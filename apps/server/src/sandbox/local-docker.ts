/**
 * LocalDockerProvider — the M2 `SandboxProvider`, talking to a local Docker
 * engine through `dockerode`.
 *
 * This is the only file in the codebase that imports `dockerode`. Nothing above
 * `SandboxProvider` may know that a container id is a 64-hex string
 * (`provider.ts`, "Identifiers"), so every Docker concept stops here.
 *
 * ============================================================================
 * WHAT THIS HOST ACTUALLY ENFORCES
 * ============================================================================
 * The contract requires that a control we cannot apply is REPORTED, in
 * `SandboxHandle.unenforced`, rather than assumed. On Docker Desktop for
 * Windows (the machine this was built and verified on: engine 29.7.2, WSL2
 * backend) the honest accounting is:
 *
 *   ENFORCED, by the kernel, verified at runtime:
 *     non-root user            `User: "10001:10001"`, asserted with `id` in the
 *                              scratch verification, and refused at validation
 *                              if it resolves to uid 0
 *     cap-drop=ALL             confirmed by re-inspecting the created container
 *     no-new-privileges        ditto
 *     default seccomp          by never passing `seccomp=`; presence of the
 *                              profile is read back from `docker info`
 *     read-only root fs        confirmed by re-inspecting; a write outside the
 *                              declared tmpfs and the repo mount fails EROFS
 *     memory / cpu / pids      cgroup limits, confirmed by re-inspecting
 *     no route off-host        `NetworkMode` is "none" or the `atrium-internal`
 *                              bridge. The bridge's `Internal: true` — the flag
 *                              that stops the daemon writing a NAT masquerade
 *                              rule, i.e. the whole control — is READ BACK from
 *                              the daemon before any container joins, never
 *                              adopted from a name match, and a network with
 *                              that name that is not internal is refused rather
 *                              than used. After create, the container's own
 *                              endpoints are re-inspected: the mode must equal
 *                              what was asked for (not merely differ from
 *                              "host"), and the attachment must be that exact
 *                              network BY ID, so a delete-and-recreate under
 *                              the same name cannot substitute a routable one.
 *     no Docker socket         there is no bind at all except the repo mount
 *
 *   NOT ENFORCED, reported in `unenforced`:
 *     "disk-quota"             `--storage-opt size=` needs overlay2/overlayfs
 *                              on xfs with pquota. Docker Desktop's WSL2
 *                              backing store is ext4, so the quota is silently
 *                              ignored by the daemon if passed. Detected from
 *                              `docker info` and reported. The tmpfs caps and
 *                              the host's free space are then the only bound.
 *     "rootless-engine"        Docker Desktop's engine runs as root inside its
 *                              own VM. That VM is a real boundary — better than
 *                              a root daemon on the metal — but it is not
 *                              rootless Docker, and a container escape lands as
 *                              root in the VM that holds the bind mount.
 *     "userns-remap"           the daemon has no `userns-remap`, so container
 *                              uid 10001 is uid 10001 in the VM.
 *     "egress-allowlist"       ONLY when the spec asks for "allowlist". Docker
 *                              has no per-container egress firewall, so an
 *                              allowlist request falls back to the `--internal`
 *                              bridge (no route off-host at all) and says so.
 *                              We never create a normal bridge network and call
 *                              an allowlist enforced.
 *
 * ============================================================================
 * WHAT THIS FILE DOES NOT DO
 * ============================================================================
 *   proxyPort   M6 (preview on a separate origin, D3)
 *   hibernate   M5
 *   restore     M5
 * They throw, naming the milestone. A stub that returns a plausible-looking
 * value is worse than no stub, because the caller then ships against it.
 */

import { randomUUID } from "node:crypto";
import { Writable } from "node:stream";
import type { Duplex } from "node:stream";
import Docker from "dockerode";

import type {
  ExecOpts,
  ExecResult,
  ProxiedPort,
  PtyHandle,
  PtyOpts,
  PtySize,
  SandboxHandle,
  SandboxId,
  SandboxImageRef,
  SandboxProvider,
  SandboxSpec,
  SandboxState,
  Snapshot,
  SnapshotId,
  UnenforcedControl,
} from "./provider.ts";
import { classifyDockerError, redact, SandboxError } from "./errors.ts";
import { hardenedHostConfig } from "./harden.ts";
import { redactSpecForLabel, specSecrets, validateSpec } from "./spec.ts";

/* ==========================================================================
 * Constants
 * ========================================================================== */

export const LABEL_MANAGED = "dev.atrium.managed";
export const LABEL_WORKSPACE = "dev.atrium.workspace";
export const LABEL_SANDBOX = "dev.atrium.sandbox";
export const LABEL_ROLE = "dev.atrium.role";
export const LABEL_SPEC = "dev.atrium.spec";
export const LABEL_UNENFORCED = "dev.atrium.unenforced";
export const LABEL_CREATED_AT = "dev.atrium.created-at";

/**
 * The `--internal` bridge every non-"none" sandbox joins.
 *
 * `Internal: true` means the daemon installs no NAT masquerade rule, so packets
 * to the internet are dropped in the kernel (measured: `ENETUNREACH`).
 *
 * The brokers (D1, D2) attach to THIS network as sidecar containers and are
 * reached by name over Docker's embedded DNS. They are NOT host processes on
 * the bridge gateway: Docker Desktop runs the engine in a WSL2 VM, so the
 * gateway belongs to the VM and a Windows listener is unreachable from here
 * (measured: `ECONNREFUSED` against a live listener). See PLAN.md §4.
 */
export const INTERNAL_NETWORK_NAME = "atrium-internal";

/**
 * PID 1 for a workspace container: a shell that sleeps and exits cleanly on
 * SIGTERM. The workload arrives later as `exec`/`spawnPty`, so the container's
 * own command must do nothing and consume nothing.
 *
 * `sleep 3600 &` + `wait` rather than a bare `sleep` so the trap fires
 * immediately instead of after the current sleep.
 */
const IDLE_COMMAND: readonly string[] = [
  "/bin/sh",
  "-c",
  "trap 'exit 0' TERM INT; while :; do sleep 3600 & wait $!; done",
];

/** How long `destroy`/`hibernate` wait for a clean exit before SIGKILL. */
const STOP_TIMEOUT_SECONDS = 5;

/* ==========================================================================
 * Engine facts
 * ========================================================================== */

/**
 * Facts about the host engine that decide which controls are real.
 *
 * Read once and cached: `docker info` is not free and none of these change
 * without a daemon restart (which would also drop every container we own).
 */
interface EngineFacts {
  readonly version: string;
  readonly seccompDefault: boolean;
  readonly usernsRemap: boolean;
  readonly rootless: boolean;
  readonly diskQuotaCapable: boolean;
}

function readEngineFacts(info: unknown, version: unknown): EngineFacts {
  const i = info as {
    SecurityOptions?: unknown;
    Driver?: unknown;
    DriverStatus?: unknown;
  };
  const v = version as { Version?: unknown };

  const securityOptions: string[] = Array.isArray(i.SecurityOptions)
    ? i.SecurityOptions.filter((s): s is string => typeof s === "string")
    : [];
  const has = (needle: string): boolean => securityOptions.some((s) => s.includes(needle));

  // `--storage-opt size=` is only honoured by overlay2/overlayfs on an xfs
  // backing filesystem with pquota, or by btrfs/zfs. Docker Desktop on WSL2
  // reports "extfs" here, so this is false on the machine this was built on.
  const driver = typeof i.Driver === "string" ? i.Driver : "";
  let backingFs = "";
  if (Array.isArray(i.DriverStatus)) {
    for (const row of i.DriverStatus) {
      if (Array.isArray(row) && row[0] === "Backing Filesystem" && typeof row[1] === "string") {
        backingFs = row[1].toLowerCase();
      }
    }
  }
  const overlay = driver === "overlay2" || driver === "overlayfs";
  const diskQuotaCapable =
    (overlay && backingFs === "xfs") || driver === "btrfs" || driver === "zfs";

  return {
    version: typeof v.Version === "string" ? v.Version : "unknown",
    seccompDefault: has("name=seccomp"),
    usernsRemap: has("name=userns"),
    rootless: has("name=rootless"),
    diskQuotaCapable,
  };
}

/* ==========================================================================
 * Small helpers
 * ========================================================================== */

function defaultSocketPath(): string {
  // Docker Desktop for Windows exposes BOTH `docker_engine` (the classic pipe,
  // which on some installs points at the Windows-containers engine) and
  // `dockerDesktopLinuxEngine`. dockerode defaults to the former. We want the
  // Linux engine explicitly.
  //
  // TODO(orchestrator): this belongs in apps/server/src/config.ts alongside the
  // other environment parsing, as an optional DOCKER_SOCKET. It is read here
  // only because config.ts is owned by another agent this milestone.
  const fromEnv = process.env["DOCKER_SOCKET"];
  if (fromEnv !== undefined && fromEnv !== "") return fromEnv;
  return process.platform === "win32" ? "//./pipe/dockerDesktopLinuxEngine" : "/var/run/docker.sock";
}

function envArray(
  plain: Readonly<Record<string, string>>,
  extra?: Readonly<Record<string, string>>,
): string[] {
  const merged: Record<string, string> = { ...plain, ...(extra ?? {}) };
  return Object.entries(merged).map(([k, v]) => `${k}=${v}`);
}

function mapState(dockerState: string): SandboxState {
  // We never pause or stop a container we own, so "exited" always means
  // something killed it: the OOM killer, a host restart, an engine crash.
  switch (dockerState) {
    case "created":
    case "restarting":
      return "creating";
    case "running":
      return "running";
    case "removing":
    case "paused":
      return "stopping";
    case "exited":
    case "dead":
      return "failed";
    default:
      return "failed";
  }
}

/**
 * A `Writable` that keeps at most `limit` bytes and counts the rest as dropped.
 * `yes` and `cat /dev/urandom` are both one token away (`ExecOpts.maxOutputBytes`).
 */
function cappedSink(limit: number): {
  stream: Writable;
  take(): Uint8Array;
  truncated(): boolean;
} {
  const chunks: Buffer[] = [];
  let kept = 0;
  let overflowed = false;
  const stream = new Writable({
    write(chunk: Buffer, _encoding, callback): void {
      const remaining = limit - kept;
      if (remaining <= 0) {
        overflowed = true;
      } else if (chunk.length > remaining) {
        chunks.push(chunk.subarray(0, remaining));
        kept += remaining;
        overflowed = true;
      } else {
        chunks.push(chunk);
        kept += chunk.length;
      }
      callback();
    },
  });
  return {
    stream,
    take: (): Uint8Array => new Uint8Array(Buffer.concat(chunks, kept)),
    truncated: (): boolean => overflowed,
  };
}

/**
 * Turn a digest-pinned `SandboxImageRef` into a reference the daemon will run.
 *
 * Two shapes are accepted, both content-addressed:
 *   - a registry image, referenced `repository@sha256:…` and pulled if absent;
 *   - a locally built image, whose `Id` IS `sha256:…` (the digest of its
 *     config). A local build has no registry digest, so pinning to the image id
 *     is the only content-addressed reference available — and it is a real one:
 *     a changed Dockerfile yields a different id, which is what T12 asks for.
 *
 * A tag is never accepted, here or in `validateSpec`.
 */
export async function resolveImageReference(
  docker: Docker,
  image: SandboxImageRef,
): Promise<string> {
  const byDigest = `${image.repository}@${image.digest}`;
  try {
    await docker.getImage(byDigest).inspect();
    return byDigest;
  } catch {
    /* not present by repo digest; try the local image id */
  }
  try {
    const info = await docker.getImage(image.digest).inspect();
    if (info.Id === image.digest) return image.digest;
  } catch {
    /* not a local image id either; fall through to a pull */
  }
  const stream = await docker.pull(byDigest);
  await new Promise<void>((resolve, reject) => {
    docker.modem.followProgress(stream, (err) => (err === null ? resolve() : reject(err)));
  });
  return byDigest;
}

/* ==========================================================================
 * The pty handle
 * ========================================================================== */

interface DockerPtyInit {
  readonly id: string;
  readonly sandboxId: SandboxId;
  readonly container: Docker.Container;
  readonly exec: Docker.Exec;
  readonly stream: Duplex;
  /** Path inside the container holding the shell's pid, or null. */
  readonly pidFile: string | null;
  readonly user: string;
}

/**
 * A pty running INSIDE the container, via the Docker Exec API with `Tty: true`.
 *
 * Deliberately not `node-pty`: a host pty is a shell on the machine that holds
 * every credential (`provider.ts`, `spawnPty`). `node-pty` stays in
 * package.json as the fallback for a future provider that must wrap a
 * container-attach *client* process, and is not imported here.
 *
 * With `Tty: true` the hijacked stream is NOT the multiplexed stdout/stderr
 * frame format, so `demuxStream` must not be called on it — bytes go from the
 * pty master to `onData` unmodified, which is exactly what the binary terminal
 * protocol in `@atrium/shared` expects.
 */
class DockerPty implements PtyHandle {
  readonly id: string;
  readonly sandboxId: SandboxId;
  readonly exited: Promise<{ exitCode: number | null; signal: string | null }>;

  #container: Docker.Container;
  #exec: Docker.Exec;
  #stream: Duplex;
  #pidFile: string | null;
  #user: string;
  #listeners = new Set<(chunk: Uint8Array) => void>();
  #resizeChain: Promise<void> = Promise.resolve();
  #disposed = false;
  #settle: (value: { exitCode: number | null; signal: string | null }) => void = () => {};

  constructor(init: DockerPtyInit) {
    this.id = init.id;
    this.sandboxId = init.sandboxId;
    this.#container = init.container;
    this.#exec = init.exec;
    this.#stream = init.stream;
    this.#pidFile = init.pidFile;
    this.#user = init.user;

    this.exited = new Promise((resolve) => {
      this.#settle = resolve;
    });

    this.#stream.on("data", (chunk: Buffer) => {
      // A view, not a copy — the transport is expected to hand it straight to
      // ws.send within the tick. Retaining past that is the caller's copy.
      const view = new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength);
      for (const listener of this.#listeners) listener(view);
    });
    this.#stream.on("error", () => {
      /* the close handler settles `exited`; an error is not a separate outcome */
    });
    this.#stream.on("close", () => {
      void this.#resolveExit();
    });
    this.#stream.on("end", () => {
      void this.#resolveExit();
    });
  }

  async #resolveExit(): Promise<void> {
    let exitCode: number | null = null;
    try {
      const info = await this.#exec.inspect();
      exitCode = typeof info.ExitCode === "number" ? info.ExitCode : null;
    } catch {
      // Engine gone, container removed under us: the pty is over either way.
    }
    // Docker's exec API reports no terminating signal, only an exit code (137
    // for SIGKILL, 143 for SIGTERM). Inferring a signal name from the code
    // would be a guess, so `signal` stays null and the code carries the truth.
    this.#settle({ exitCode, signal: null });
  }

  write(data: Uint8Array): void {
    if (this.#disposed) return;
    this.#stream.write(Buffer.from(data.buffer, data.byteOffset, data.byteLength));
  }

  /**
   * `resize` is an out-of-band HTTP call while `write` goes straight down the
   * hijacked socket, so a resize issued just before a keystroke may land just
   * after it. That is inherent to the Docker exec API and harmless — SIGWINCH
   * arrives a few milliseconds late — but two resizes racing EACH OTHER is
   * not: they can land out of order and leave the pty at the wrong size for
   * good. So they are serialised through one chain, and rejections are
   * swallowed because a resize against an exiting process is normal.
   */
  resize(size: PtySize): void {
    if (this.#disposed) return;
    this.#resizeChain = this.#resizeChain
      .then(() => this.#exec.resize({ h: size.rows, w: size.cols }))
      .then(
        () => undefined,
        () => undefined,
      );
  }

  onData(listener: (chunk: Uint8Array) => void): () => void {
    this.#listeners.add(listener);
    return () => {
      this.#listeners.delete(listener);
    };
  }

  kill(signal = "SIGTERM"): void {
    void this.#signal(signal).catch(() => undefined);
  }

  /**
   * Signal the pty's process group from inside the container.
   *
   * Docker exposes no "kill this exec" API — `docker exec` processes are not
   * addressable the way a container is. The wrapper in `spawnPty` therefore
   * writes the shell's own pid into a tmpfs file, and here we exec `kill`
   * against it in the container's own PID namespace, as the same unprivileged
   * user that owns the process. Without a writable tmpfs there is no pid file
   * and this degrades to closing the stream (see `dispose`).
   *
   * Note for callers: an INTERACTIVE shell ignores SIGTERM by design, so
   * `kill("SIGTERM")` on a `bash -i` pty legitimately does nothing. That is why
   * `dispose` sends SIGKILL rather than trusting a polite signal.
   */
  async #signal(signal: string): Promise<void> {
    if (this.#pidFile === null) return;
    const name = signal.startsWith("SIG") ? signal.slice(3) : signal;
    const exec = await this.#container.exec({
      Cmd: [
        "/bin/sh",
        "-c",
        // $0 is the pid file, $1 the signal name. Neither is interpolated into
        // the script text, so neither can be parsed as shell.
        'p=$(cat "$0" 2>/dev/null) || exit 0; [ -n "$p" ] && kill -"$1" "$p" 2>/dev/null; exit 0',
        this.#pidFile,
        name,
      ],
      AttachStdout: false,
      AttachStderr: false,
      User: this.#user,
    });
    await exec.start({ Detach: true, hijack: false, stdin: false });
  }

  async dispose(): Promise<void> {
    if (this.#disposed) return;
    this.#disposed = true;
    this.#listeners.clear();
    try {
      await this.#signal("SIGKILL");
    } catch {
      /* best effort */
    }
    this.#stream.destroy();
    await this.#resolveExit();
  }
}

/* ==========================================================================
 * The provider
 * ========================================================================== */

export interface LocalDockerProviderOptions {
  /** Named pipe or unix socket. Defaults to DOCKER_SOCKET, then per-platform. */
  readonly socketPath?: string;
  /** Injected in tests. */
  readonly docker?: Docker;
}

export class LocalDockerProvider implements SandboxProvider {
  readonly name = "local-docker";

  #docker: Docker;
  #facts: EngineFacts | null = null;
  #handles = new Map<SandboxId, SandboxHandle>();
  /**
   * Resolves to the id of the `atrium-internal` network *after* its `Internal`
   * flag has been read back from the daemon. Never a bare "we asked for it".
   */
  #networkReady: Promise<string> | null = null;

  constructor(options: LocalDockerProviderOptions = {}) {
    this.#docker =
      options.docker ?? new Docker({ socketPath: options.socketPath ?? defaultSocketPath() });
  }

  /* ---------------------------------------------------------------- create */

  async create(workspaceId: string, spec: SandboxSpec): Promise<SandboxHandle> {
    validateSpec(spec);
    const secrets = specSecrets(spec);

    // Idempotent per workspace: a second call must not produce a second
    // container. Look for a live one first, including one created by a previous
    // run of this process.
    const existing = await this.#findRunningForWorkspace(workspaceId);
    if (existing !== null) return existing;

    const facts = await this.#engineFacts(secrets);
    const unenforced: UnenforcedControl[] = [];
    if (!facts.diskQuotaCapable) unenforced.push("disk-quota");
    if (!facts.usernsRemap) unenforced.push("userns-remap");
    if (!facts.rootless) unenforced.push("rootless-engine");
    if (!facts.seccompDefault) unenforced.push("seccomp");

    // Egress. "allowlist" cannot be enforced by Docker alone (no per-container
    // egress firewall), so we fall back to the strictly tighter `--internal`
    // bridge and report the gap. We never create a normal bridge and call an
    // allowlist enforced.
    let networkMode: string;
    // The id of the network the container must end up on, or null when it must
    // end up on no network at all. Carried to the post-create verification so
    // "we asked for `atrium-internal`" is checked against "this endpoint is on
    // the network whose `Internal: true` we actually read back".
    let expectedNetworkId: string | null = null;
    if (spec.egress.mode === "none") {
      networkMode = "none";
    } else {
      expectedNetworkId = await this.#ensureInternalNetwork(secrets);
      networkMode = INTERNAL_NETWORK_NAME;
      if (spec.egress.mode === "allowlist") unenforced.push("egress-allowlist");
    }

    const sandboxId = randomUUID();
    const createdAt = new Date().toISOString();
    const imageRef = await this.#resolveImage(spec.image, secrets);

    const hostConfig = hardenedHostConfig({
      limits: spec.limits,
      tmpfs: spec.tmpfs,
      networkMode,
      diskQuotaBytes: facts.diskQuotaCapable ? spec.limits.diskBytes : null,
    });
    // The repo working tree is the ONLY bind mount. There is no code path here
    // that mounts /var/run/docker.sock, and no spec field that could ask for it.
    hostConfig.Mounts = [
      {
        Type: "bind",
        Source: spec.repo.hostPath,
        Target: spec.repo.containerPath,
        ReadOnly: !spec.repo.writable,
      },
    ];

    const labels: Record<string, string> = {
      [LABEL_MANAGED]: "true",
      [LABEL_ROLE]: "workspace",
      [LABEL_WORKSPACE]: workspaceId,
      [LABEL_SANDBOX]: sandboxId,
      [LABEL_CREATED_AT]: createdAt,
      [LABEL_SPEC]: JSON.stringify(redactSpecForLabel(spec)),
      [LABEL_UNENFORCED]: JSON.stringify(unenforced),
    };
    for (const [k, v] of Object.entries(spec.labels ?? {})) labels[`dev.atrium.user.${k}`] = v;

    const env = envArray(
      spec.env.plain,
      spec.env.capabilityToken === null
        ? undefined
        : // Named so it is greppable and rotatable. It is a capability for the
          // host-side brokers, not a credential: useless anywhere else (D1).
          { ATRIUM_CAPABILITY_TOKEN: spec.env.capabilityToken },
    );

    let container: Docker.Container;
    try {
      container = await this.#docker.createContainer({
        name: `atrium-ws-${workspaceId.replace(/[^A-Za-z0-9_.-]/g, "-")}-${sandboxId.slice(0, 8)}`,
        Image: imageRef,
        User: spec.user,
        WorkingDir: spec.workdir,
        Env: env,
        Cmd: [...IDLE_COMMAND],
        Labels: labels,
        StopSignal: "SIGTERM",
        StopTimeout: STOP_TIMEOUT_SECONDS,
        AttachStdin: false,
        AttachStdout: false,
        AttachStderr: false,
        OpenStdin: false,
        Tty: false,
        NetworkDisabled: spec.egress.mode === "none",
        HostConfig: hostConfig,
      });
      await container.start();
    } catch (err) {
      throw this.#wrap(err, "failed to create sandbox container", secrets, sandboxId);
    }

    // Read the running container back and confirm the controls actually stuck.
    // A control we believe we have is worse than one we know we lack, so this
    // is an assertion, not a formality. Any failure below removes the container
    // rather than leaving an unverified one running.
    let verified = false;
    try {
      const info = await container.inspect();
      const applied = info.HostConfig as unknown as {
        ReadonlyRootfs?: boolean;
        CapDrop?: string[] | null;
        SecurityOpt?: string[] | null;
        Privileged?: boolean;
        PidsLimit?: number | null;
        Memory?: number;
        NanoCpus?: number;
        NetworkMode?: string;
      };
      if (applied.ReadonlyRootfs !== true) unenforced.push("readonly-rootfs");
      const capDrop = applied.CapDrop ?? [];
      const noNewPrivs = (applied.SecurityOpt ?? []).some((s) => s.includes("no-new-privileges"));
      if (!capDrop.includes("ALL") || applied.Privileged === true || !noNewPrivs) {
        throw new SandboxError(
          "control-unenforceable",
          "engine did not apply cap-drop=ALL / no-new-privileges; refusing to run a softer container",
          sandboxId,
        );
      }
      if (
        (applied.PidsLimit ?? 0) <= 0 ||
        (applied.Memory ?? 0) <= 0 ||
        (applied.NanoCpus ?? 0) <= 0
      ) {
        throw new SandboxError(
          "control-unenforceable",
          "engine did not apply the memory/cpu/pids limits; refusing to run an unbounded container",
          sandboxId,
        );
      }
      // --- network (D4) ------------------------------------------------
      // The network is the whole of the egress control on this host, so it is
      // read back exactly like cap-drop is, not assumed from what we passed.
      // Three separate things have to hold, because each one alone can be true
      // while the container still has a route off-host:
      //   1. the mode is not "host"/"container:" — `assertNetworkMode` refuses
      //      those before create; this is the same refusal after the fact
      //   2. the mode is EXACTLY what we asked for, so a container that landed
      //      on `bridge` (routable) is caught, not just one that landed on the
      //      host namespace
      //   3. the endpoints are exactly the intended one, matched by network ID
      //      rather than by name — `#ensureInternalNetwork` proved a specific
      //      network is `Internal`, and a delete-and-recreate under the same
      //      name between then and now would otherwise substitute an
      //      unverified, routable network silently
      const appliedMode = typeof applied.NetworkMode === "string" ? applied.NetworkMode : "";
      const loweredMode = appliedMode.toLowerCase();
      if (loweredMode === "host" || loweredMode.startsWith("container:")) {
        throw new SandboxError("control-unenforceable", "container landed on the host network", sandboxId);
      }
      if (appliedMode !== networkMode) {
        throw new SandboxError(
          "control-unenforceable",
          `container landed on network mode ${JSON.stringify(appliedMode)}, not ${JSON.stringify(networkMode)}; refusing to run it`,
          sandboxId,
        );
      }
      const attached = info.NetworkSettings.Networks ?? {};
      const attachedNames = Object.keys(attached);
      if (expectedNetworkId === null) {
        // `NetworkDisabled: true` + NetworkMode "none". Docker Desktop 29.x
        // reports no endpoint at all here; other engine versions report the
        // "none" pseudo-network. Both are "no route anywhere". Anything else
        // is a real endpoint on a real network.
        const real = attachedNames.filter((n) => n !== "none");
        if (real.length > 0) {
          throw new SandboxError(
            "control-unenforceable",
            `container asked for no network but is attached to ${real.join(", ")}; refusing to run it`,
            sandboxId,
          );
        }
      } else {
        const endpoint = attached[INTERNAL_NETWORK_NAME];
        if (attachedNames.length !== 1 || endpoint === undefined) {
          throw new SandboxError(
            "control-unenforceable",
            `container should be attached to ${INTERNAL_NETWORK_NAME} alone but is attached to ${attachedNames.join(", ") || "nothing"}; refusing to run it`,
            sandboxId,
          );
        }
        if (endpoint.NetworkID !== expectedNetworkId) {
          // Drop the memoised id so the next create re-verifies rather than
          // failing forever against a network that no longer exists.
          this.#networkReady = null;
          throw new SandboxError(
            "control-unenforceable",
            `network ${INTERNAL_NETWORK_NAME} was replaced between verification and create; the container's network is unverified, refusing to run it`,
            sandboxId,
          );
        }
      }
      verified = true;
    } catch (err) {
      if (err instanceof SandboxError) throw err;
      throw this.#wrap(err, "failed to verify sandbox hardening", secrets, sandboxId);
    } finally {
      if (!verified) await container.remove({ force: true, v: true }).catch(() => undefined);
    }

    const handle: SandboxHandle = {
      id: sandboxId,
      workspaceId,
      state: "running",
      spec,
      createdAt,
      unenforced,
      backendRef: container.id,
    };
    this.#handles.set(sandboxId, handle);
    return handle;
  }

  /* --------------------------------------------------------------- inspect */

  async inspect(id: SandboxId): Promise<SandboxHandle | null> {
    const containers = await this.#list({ [LABEL_SANDBOX]: id });
    const found = containers[0];
    if (found === undefined) return null;
    return this.#handleFromContainerInfo(found);
  }

  /* ------------------------------------------------------------------ exec */

  async exec(handle: SandboxHandle, cmd: readonly string[], opts: ExecOpts): Promise<ExecResult> {
    if (cmd.length === 0) throw new SandboxError("invalid-spec", "exec needs at least argv[0]", handle.id);
    const secrets = specSecrets(handle.spec);
    const container = await this.#requireRunning(handle);
    const started = Date.now();

    if (opts.signal?.aborted === true) {
      throw new SandboxError("aborted", "exec aborted before it started", handle.id);
    }

    const stdout = cappedSink(opts.maxOutputBytes);
    const stderr = cappedSink(opts.maxOutputBytes);
    const wantsStdin = opts.stdin !== undefined && opts.stdin.byteLength > 0;

    let exec: Docker.Exec;
    let stream: Duplex;
    try {
      exec = await container.exec({
        Cmd: [...cmd],
        AttachStdin: wantsStdin,
        AttachStdout: true,
        AttachStderr: true,
        Tty: false,
        // `user` defaults to the spec's; there is no way to ask for root, and
        // the container's uid is not 0 anyway.
        User: opts.user ?? handle.spec.user,
        WorkingDir: opts.cwd ?? handle.spec.workdir,
        Env: envArray(handle.spec.env.plain, opts.env),
      });
      stream = await exec.start({ hijack: true, stdin: wantsStdin });
    } catch (err) {
      throw this.#wrap(err, "failed to start exec", secrets, handle.id);
    }

    // Tty is false, so the stream carries Docker's 8-byte stdout/stderr frame
    // header. demuxStream splits it. (With Tty true it must NOT be called.)
    this.#docker.modem.demuxStream(stream, stdout.stream, stderr.stream);

    let timedOut = false;
    let aborted = false;

    const finished = new Promise<void>((resolve) => {
      let settled = false;
      const done = (): void => {
        if (settled) return;
        settled = true;
        resolve();
      };
      stream.on("end", done);
      stream.on("close", done);
      stream.on("error", done);
    });

    const timer = setTimeout(() => {
      timedOut = true;
      stream.destroy();
    }, opts.timeoutMs);

    const onAbort = (): void => {
      aborted = true;
      stream.destroy();
    };
    opts.signal?.addEventListener("abort", onAbort, { once: true });

    if (wantsStdin && opts.stdin !== undefined) {
      stream.write(Buffer.from(opts.stdin.buffer, opts.stdin.byteOffset, opts.stdin.byteLength));
      // STDIN EOF IS A CONNECTION CLOSE, AND THAT IS A RACE.
      //
      // The only way to signal end-of-stdin over a hijacked Docker connection
      // is to close the write side. On a Windows named pipe there is no
      // half-close: `end()` tears the whole connection down. If that lands
      // before the daemon has finished wiring the exec's stdin to the process,
      // the payload is dropped and the command sees an empty stdin — observed
      // reproducibly here as `sh -c cat` returning nothing.
      //
      // One `inspect` round-trip after `start` is a synchronisation point: the
      // daemon cannot answer it until it has processed the start, so the FIN
      // that follows cannot overtake the attach. It costs a few milliseconds
      // and only on execs that actually pass stdin.
      await exec.inspect().catch(() => undefined);
      stream.end();
    }

    try {
      await finished;
    } finally {
      clearTimeout(timer);
      opts.signal?.removeEventListener("abort", onAbort);
    }

    if (aborted) throw new SandboxError("aborted", "exec aborted by caller", handle.id);

    let exitCode: number | null = null;
    try {
      const info = await exec.inspect();
      exitCode = typeof info.ExitCode === "number" ? info.ExitCode : null;
    } catch {
      exitCode = null;
    }

    // TIMEOUT, HONESTLY: destroying the hijacked stream detaches us from the
    // process; it does NOT kill it, because the Docker API has no "kill exec".
    // A timed-out command can therefore keep running inside the container until
    // the sandbox is destroyed. Its blast radius is bounded by the container's
    // memory/cpu/pids limits, not by this timeout. A caller that needs a hard
    // in-container ceiling should ask for one explicitly, e.g.
    // `["timeout", "-s", "KILL", "30", ...]`.
    return {
      exitCode: timedOut ? null : exitCode,
      // Docker reports no terminating signal for an exec, only the exit code.
      signal: null,
      stdout: stdout.take(),
      stderr: stderr.take(),
      truncated: stdout.truncated() || stderr.truncated(),
      timedOut,
      durationMs: Date.now() - started,
    };
  }

  /* -------------------------------------------------------------- spawnPty */

  async spawnPty(handle: SandboxHandle, opts: PtyOpts): Promise<PtyHandle> {
    if (opts.command.length === 0) {
      throw new SandboxError("invalid-spec", "pty needs a command", handle.id);
    }
    const secrets = specSecrets(handle.spec);
    const container = await this.#requireRunning(handle);
    const ptyId = randomUUID();
    const user = opts.user ?? handle.spec.user;

    // A writable tmpfs is needed for the pid file that makes `kill()` work.
    // Prefer /tmp; fall back to the first declared tmpfs; if there is none,
    // spawn without one and accept that kill() degrades to closing the stream.
    const scratch =
      handle.spec.tmpfs.find((t) => t.containerPath === "/tmp") ?? handle.spec.tmpfs[0];
    const pidFile = scratch === undefined ? null : `${scratch.containerPath}/atrium-pty-${ptyId}.pid`;

    // The wrapper records the shell's own pid, then `exec`s the requested argv
    // so the pid stays valid and no extra process lingers. argv arrives as
    // positional parameters, never spliced into the script text, so nothing the
    // caller passes is parsed as shell (`PtyOpts.command` is argv, by contract).
    const cmd =
      pidFile === null
        ? [...opts.command]
        : ["/bin/sh", "-c", 'printf %s "$$" > "$0"; shift; exec "$@"', pidFile, "sh", ...opts.command];

    let exec: Docker.Exec;
    let stream: Duplex;
    try {
      exec = await container.exec({
        Cmd: cmd,
        AttachStdin: true,
        AttachStdout: true,
        AttachStderr: true,
        Tty: true,
        User: user,
        WorkingDir: opts.cwd ?? handle.spec.workdir,
        Env: envArray(handle.spec.env.plain, { ...(opts.env ?? {}), TERM: opts.term }),
      });
      // hijack + stdin gives a raw duplex. With Tty true it is NOT multiplexed,
      // so demuxStream must never touch it.
      stream = await exec.start({ hijack: true, stdin: true });
      await exec.resize({ h: opts.size.rows, w: opts.size.cols }).catch(() => undefined);
    } catch (err) {
      throw this.#wrap(err, "failed to start pty", secrets, handle.id);
    }

    return new DockerPty({
      id: ptyId,
      sandboxId: handle.id,
      container,
      exec,
      stream,
      pidFile,
      user,
    });
  }

  /* -------------------------------------------------- not implemented yet */

  async proxyPort(_handle: SandboxHandle, _port: number): Promise<ProxiedPort> {
    // M6. The hard part is not the proxy, it is D3: the preview must be served
    // from a SEPARATE ORIGIN with a server-resolved target, never a path on the
    // app origin and never a port from the request (T5). Returning a plausible
    // localhost URL here would hand the caller exactly the bug D3 exists to
    // prevent, so this throws instead.
    throw new SandboxError(
      "internal",
      "proxyPort is not implemented until M6 (preview pane on a separate origin, SECURITY.md D3)",
    );
  }

  async hibernate(_handle: SandboxHandle): Promise<Snapshot> {
    // M5. A snapshot is the whole filesystem and therefore the densest secret
    // store in the system (T9): it needs encryption at rest and a retention
    // policy before it may exist at all.
    throw new SandboxError(
      "internal",
      "hibernate is not implemented until M5 (durable sessions, PLAN.md §6)",
    );
  }

  async restore(_snapshot: Snapshot, _spec: SandboxSpec): Promise<SandboxHandle> {
    throw new SandboxError(
      "internal",
      "restore is not implemented until M5 (durable sessions, PLAN.md §6)",
    );
  }

  async deleteSnapshot(_id: SnapshotId): Promise<void> {
    // Idempotent by construction: `hibernate` cannot run, so no snapshot this
    // provider issued can exist. Deleting one that does not exist resolves.
    return;
  }

  /* --------------------------------------------------------------- destroy */

  async destroy(handle: SandboxHandle): Promise<void> {
    this.#handles.delete(handle.id);
    const container = this.#docker.getContainer(handle.backendRef);
    try {
      // force also stops it; `v: true` removes anonymous volumes. The repo bind
      // mount is untouched — it is the user's checkout, not ours to delete.
      await container.remove({ force: true, v: true });
    } catch (err) {
      const code = classifyDockerError(err);
      // Unknown or already-destroyed resolves, per the contract.
      if (code === "not-found") return;
      const statusCode = (err as { statusCode?: number }).statusCode;
      if (statusCode === 404 || statusCode === 409) return;
      throw this.#wrap(err, "failed to destroy sandbox", specSecrets(handle.spec), handle.id);
    }
  }

  /* ---------------------------------------------------------------- health */

  async health(): Promise<{ reachable: boolean; version?: string; detail?: string }> {
    try {
      const version = await this.#docker.version();
      return { reachable: true, version: version.Version };
    } catch (err) {
      // No paths, no secrets: the socket path is a host path and the raw error
      // quotes it, so the message is built from the classification only.
      const code = classifyDockerError(err);
      return {
        reachable: false,
        detail:
          code === "backend-unavailable"
            ? "docker engine unreachable at the configured socket"
            : "docker engine returned an error",
      };
    }
  }

  /* -------------------------------------------------------- operator tools */

  /** Every sandbox container this provider owns, running or not. For cleanup. */
  async listManaged(): Promise<readonly SandboxHandle[]> {
    const containers = await this.#list({ [LABEL_MANAGED]: "true", [LABEL_ROLE]: "workspace" });
    const out: SandboxHandle[] = [];
    for (const info of containers) {
      const handle = this.#handleFromContainerInfo(info);
      if (handle !== null) out.push(handle);
    }
    return out;
  }

  /* --------------------------------------------------------------- private */

  async #engineFacts(secrets: readonly string[]): Promise<EngineFacts> {
    if (this.#facts !== null) return this.#facts;
    try {
      const [info, version] = await Promise.all([this.#docker.info(), this.#docker.version()]);
      this.#facts = readEngineFacts(info, version);
      return this.#facts;
    } catch (err) {
      throw this.#wrap(err, "docker engine is unreachable", secrets);
    }
  }

  /**
   * Create-or-adopt the `--internal` bridge once per process, and PROVE it is
   * internal before any container joins it. Returns the verified network id.
   *
   * `Internal: true` is the entirety of D4 on this host: it is why the daemon
   * installs no NAT masquerade rule for the bridge and packets bound for the
   * internet die in the kernel. Crucially, a network is not internal because we
   * asked for it to be. A network named `atrium-internal` may already exist as
   * an ordinary, routable bridge — pre-created by an operator following a
   * troubleshooting note, left behind by an older build of this file, declared
   * in a compose file, or created by anyone who can reach the engine. Adopting
   * one on the strength of its NAME would hand every workspace container full
   * egress while `unenforced` stayed empty and `/api/health` still said
   * `sandbox ok`. That is the one failure mode the "verified by re-inspecting"
   * claim at the top of this file exists to rule out, so the flag is read back
   * from the daemon on every path: adopted, freshly created, or lost-the-race.
   *
   * We refuse rather than delete-and-recreate. Removing a network we did not
   * create is a destructive act on someone else's resource, and it would fail
   * anyway while containers are attached to it — a refusal an operator can fix
   * in one command beats a half-completed repair.
   */
  async #ensureInternalNetwork(secrets: readonly string[]): Promise<string> {
    if (this.#networkReady !== null) return this.#networkReady;
    this.#networkReady = (async (): Promise<string> => {
      let networkId = await this.#findInternalNetworkId(secrets);
      if (networkId === null) {
        try {
          const created = await this.#docker.createNetwork({
            Name: INTERNAL_NETWORK_NAME,
            Driver: "bridge",
            // The whole point: no NAT masquerade rule, so packets to the
            // internet are dropped in the kernel. The brokers (D1, D2) join
            // this same network as sidecar containers from M3b and are reached
            // by name — not on the gateway, which lives in the WSL2 VM.
            Internal: true,
            Attachable: false,
            EnableIPv6: false,
            Labels: { [LABEL_MANAGED]: "true" },
          });
          networkId = created.id;
        } catch (err) {
          if ((err as { statusCode?: number }).statusCode !== 409) {
            throw this.#wrap(err, "failed to create the internal network", secrets);
          }
          // A concurrent creator won the race. We did not choose its options,
          // so it earns exactly the scrutiny a pre-existing network earns.
          networkId = await this.#findInternalNetworkId(secrets);
          if (networkId === null) {
            throw new SandboxError(
              "control-unenforceable",
              `docker reported network ${INTERNAL_NETWORK_NAME} already exists but it cannot be found`,
            );
          }
        }
      }

      let info: Docker.NetworkInspectInfo;
      try {
        info = await this.#docker.getNetwork(networkId).inspect();
      } catch (err) {
        throw this.#wrap(err, "failed to verify the internal network", secrets);
      }
      if (info.Internal !== true) {
        throw new SandboxError(
          "control-unenforceable",
          `docker network ${INTERNAL_NETWORK_NAME} exists but is not --internal, so it is a routable bridge; ` +
            `refusing to give a workspace container egress. Remove it (docker network rm ${INTERNAL_NETWORK_NAME}) ` +
            "and let Atrium recreate it.",
        );
      }
      return info.Id;
    })();
    try {
      return await this.#networkReady;
    } catch (err) {
      this.#networkReady = null;
      throw err;
    }
  }

  /**
   * The id of the one network named exactly `atrium-internal`, or null.
   *
   * The daemon's `name` filter is a SUBSTRING match, so the exact-name filter
   * has to be applied here as well — `atrium-internal-oops` would otherwise
   * come back as a match. Two networks with the same name (possible across
   * scopes) is refused rather than resolved by guessing, because a container
   * asking for the name by string would join whichever one the daemon picks.
   */
  async #findInternalNetworkId(secrets: readonly string[]): Promise<string | null> {
    let networks: Docker.NetworkInspectInfo[];
    try {
      networks = await this.#docker.listNetworks({
        filters: JSON.stringify({ name: [INTERNAL_NETWORK_NAME] }),
      });
    } catch (err) {
      throw this.#wrap(err, "failed to list docker networks", secrets);
    }
    const exact = networks.filter((n) => n.Name === INTERNAL_NETWORK_NAME);
    if (exact.length > 1) {
      throw new SandboxError(
        "control-unenforceable",
        `${exact.length} docker networks are named ${INTERNAL_NETWORK_NAME}; refusing to guess which one a container would join`,
      );
    }
    return exact[0]?.Id ?? null;
  }

  async #resolveImage(image: SandboxImageRef, secrets: readonly string[]): Promise<string> {
    try {
      return await resolveImageReference(this.#docker, image);
    } catch (err) {
      throw this.#wrap(
        err,
        `image ${image.repository}@${image.digest.slice(0, 19)}… is not present locally and could not be pulled`,
        secrets,
      );
    }
  }

  async #list(labels: Record<string, string>): Promise<Docker.ContainerInfo[]> {
    const label = Object.entries(labels).map(([k, v]) => `${k}=${v}`);
    return this.#docker.listContainers({ all: true, filters: JSON.stringify({ label }) });
  }

  async #findRunningForWorkspace(workspaceId: string): Promise<SandboxHandle | null> {
    const containers = await this.#list({
      [LABEL_MANAGED]: "true",
      [LABEL_ROLE]: "workspace",
      [LABEL_WORKSPACE]: workspaceId,
    });
    for (const info of containers) {
      if (info.State !== "running") continue;
      const id = info.Labels[LABEL_SANDBOX];
      // Prefer the in-memory handle: it still carries the live capability
      // token, which the label deliberately does not.
      if (id !== undefined) {
        const remembered = this.#handles.get(id);
        if (remembered !== undefined) return { ...remembered, state: "running" };
      }
      const rebuilt = this.#handleFromContainerInfo(info);
      if (rebuilt !== null) return rebuilt;
    }
    return null;
  }

  /**
   * Rebuild a handle from container labels, for a sandbox this process did not
   * create. The spec comes back with `capabilityToken: null` — see
   * `redactSpecForLabel`.
   */
  #handleFromContainerInfo(info: Docker.ContainerInfo): SandboxHandle | null {
    const id = info.Labels[LABEL_SANDBOX];
    const workspaceId = info.Labels[LABEL_WORKSPACE];
    const specJson = info.Labels[LABEL_SPEC];
    if (id === undefined || workspaceId === undefined || specJson === undefined) return null;
    const remembered = this.#handles.get(id);
    let spec: SandboxSpec;
    if (remembered !== undefined) {
      spec = remembered.spec;
    } else {
      try {
        spec = JSON.parse(specJson) as SandboxSpec;
      } catch {
        return null;
      }
    }
    let unenforced: UnenforcedControl[] = [];
    try {
      const parsed: unknown = JSON.parse(info.Labels[LABEL_UNENFORCED] ?? "[]");
      if (Array.isArray(parsed)) unenforced = parsed as UnenforcedControl[];
    } catch {
      /* a malformed label must not hide the sandbox */
    }
    return {
      id,
      workspaceId,
      state: mapState(info.State),
      spec,
      createdAt: info.Labels[LABEL_CREATED_AT] ?? new Date(info.Created * 1000).toISOString(),
      unenforced,
      backendRef: info.Id,
    };
  }

  async #requireRunning(handle: SandboxHandle): Promise<Docker.Container> {
    const container = this.#docker.getContainer(handle.backendRef);
    let running = false;
    try {
      const info = await container.inspect();
      running = info.State.Running === true;
    } catch (err) {
      const code = classifyDockerError(err);
      if (code === "not-found") {
        throw new SandboxError("not-found", "sandbox no longer exists", handle.id);
      }
      throw this.#wrap(err, "failed to inspect sandbox", specSecrets(handle.spec), handle.id);
    }
    if (!running) throw new SandboxError("not-running", "sandbox is not running", handle.id);
    return container;
  }

  #wrap(
    err: unknown,
    context: string,
    secrets: readonly string[],
    sandboxId?: SandboxId,
  ): SandboxError {
    if (err instanceof SandboxError) return err;
    const code = classifyDockerError(err);
    const raw = err instanceof Error ? err.message : String(err);
    // Daemon errors about bind mounts quote the host path straight back, so
    // every message goes through redact() before it can reach a log (T9).
    const detail = redact(raw, secrets).split("\n")[0] ?? "";
    return new SandboxError(code, `${context}: ${detail}`, sandboxId);
  }
}
