/**
 * SandboxProvider — the seam between the orchestrator and whatever actually
 * runs a workspace's container.
 *
 * PLAN.md §4 sketches this interface; this file is the refined contract.
 * `LocalDockerProvider` (M2, dev + self-host) is the first implementation;
 * `E2BProvider` / `FlyMachinesProvider` are the reason the seam exists at all.
 * Nothing above this interface may import `dockerode` or know what a container
 * id looks like.
 *
 * ============================================================================
 * THE TRUST BOUNDARY
 * ============================================================================
 * Everything on the far side of this interface is SEMI-HOSTILE (SECURITY.md
 * §1, boundary 2). The container runs model-generated commands and arbitrary
 * `npm install` postinstall scripts over attacker-influenceable input. An
 * implementation of this interface is not a convenience wrapper around the
 * Docker API — it is the thing that keeps a compromised container from
 * becoming a compromised host.
 *
 * Non-negotiable, on every implementation (SECURITY.md T3, §4 "M2" row):
 *
 *   1. NEVER mount the Docker socket into a container, at any path, read-only
 *      or not. This is the single most common fatal mistake in this product
 *      category: the socket is root on the host, one `docker run -v /:/host`
 *      away. There is no legitimate reason for a workspace container to speak
 *      to the engine that created it.
 *   2. Non-root user, `--cap-drop=ALL`, `--security-opt=no-new-privileges`,
 *      and the DEFAULT seccomp profile (never `seccomp=unconfined`).
 *   3. Read-only root filesystem. Writable space is the repo mount plus
 *      explicitly-declared tmpfs mounts, nothing else.
 *   4. Hard limits on memory, CPU, and PIDs (fork bombs), plus a disk quota
 *      wherever the storage driver can enforce one.
 *   5. No host network, ever. Egress is deny-by-default with an allowlist (D4).
 *   6. No credentials inside the container (D1, D2). Not the model provider
 *      key, not the Git token, not now, not later. The container gets
 *      short-lived workspace-scoped capability tokens and talks to host-side
 *      brokers.
 *
 * `SandboxSpec` is shaped so that an implementation cannot quietly skip these:
 * the security-relevant knobs are required fields, not options with permissive
 * defaults. Where a control CANNOT be enforced on a given host, the
 * implementation MUST say so in `SandboxHandle.unenforced` rather than
 * pretending. See `UnenforcedControl` — that field exists because Docker
 * Desktop for Windows genuinely cannot honour parts of this list, and a
 * security control you believe you have is worse than one you know you lack.
 */

/* ==========================================================================
 * Identifiers
 * ========================================================================== */

/** Opaque, provider-assigned sandbox id. Never a container id — that leaks the backend. */
export type SandboxId = string;

/** Opaque, provider-assigned snapshot id. */
export type SnapshotId = string;

/** Opaque, provider-assigned pty id, unique within a sandbox. */
export type PtyId = string;

/* ==========================================================================
 * Spec — what to create
 * ========================================================================== */

/**
 * Base image, pinned by digest (SECURITY.md T12).
 *
 * A tag is a mutable pointer; `node:24-bookworm` today is not the bytes it was
 * last week. Implementations MUST refuse a reference whose `digest` is absent.
 */
export interface SandboxImageRef {
  /** Repository, e.g. "ghcr.io/atrium/workspace-base". No tag, no digest. */
  readonly repository: string;
  /** Human-facing tag, recorded for diagnostics only. Resolution uses `digest`. */
  readonly tag: string;
  /** Content digest, e.g. "sha256:0f2a…". Required. This is what gets pulled. */
  readonly digest: string;
}

/**
 * The repo working tree, bind-mounted from the host.
 *
 * M4 gives each agent its own overlayfs upper layer over this mount (PLAN.md
 * §5 step 4); M2 mounts it directly. `hostPath` is resolved by the
 * orchestrator from the workspace record and is never influenced by a request
 * (same rule as the preview proxy target, SECURITY.md T5).
 */
export interface RepoMount {
  /** Absolute host path to the workspace's checkout. Server-resolved only. */
  readonly hostPath: string;
  /** Absolute path inside the container, e.g. "/workspace". */
  readonly containerPath: string;
  /** false only for read-only inspection sandboxes. */
  readonly writable: boolean;
}

/**
 * A writable tmpfs. The root filesystem is read-only, so every path the
 * container legitimately writes to outside the repo must be declared here.
 * Undeclared write paths are a bug to fix, not a reason to unlock the root fs.
 */
export interface TmpfsMount {
  /** Absolute path inside the container, e.g. "/tmp". */
  readonly containerPath: string;
  /** Hard size cap in bytes. tmpfs is RAM: an uncapped one is a host OOM. */
  readonly sizeBytes: number;
  /** Default true. Set false only for a path that must hold an executable. */
  readonly noexec?: boolean;
}

/**
 * Hard resource limits (SECURITY.md T3, T10). Every field is required: a
 * missing limit is an unlimited limit, and "I forgot" must not be spellable.
 */
export interface ResourceLimits {
  /** Memory ceiling in bytes. Also sets the swap ceiling to the same value. */
  readonly memoryBytes: number;
  /** Fractional CPUs, e.g. 1.5. Maps to cpu quota/period, not cpu shares. */
  readonly cpus: number;
  /** Max processes/threads. The fork-bomb control. 512 is a sane start. */
  readonly pids: number;
  /**
   * Writable-layer quota in bytes, or null when the host cannot enforce one.
   *
   * NOT ENFORCEABLE on Docker Desktop for Windows: `--storage-opt size=` needs
   * overlay2 on xfs with pquota (or a devicemapper thin pool), and Docker
   * Desktop's WSL2 backing store is ext4. Pass null there and report
   * "disk-quota" in `SandboxHandle.unenforced`. The tmpfs caps above and the
   * host's own free space are then the only bound on disk use.
   */
  readonly diskBytes: number | null;
}

/**
 * Egress policy (D4). Deny-by-default; the allowlist is the whole policy.
 *
 * WHAT IS ENFORCED WHERE — read this before implementing:
 *
 *   "none"     `--network=none`. No interfaces but loopback. Fully enforced by
 *              the kernel on every host including Docker Desktop for Windows.
 *              Correct for exec/pty work that needs no network at all.
 *
 *   "internal" An `--internal` user-defined bridge. Docker installs no NAT
 *              masquerade rule for it, so packets to the internet are dropped
 *              in the kernel. The container can still reach the bridge gateway
 *              — which is where the host-side model broker (D1) and Git proxy
 *              (D2) listen. This is the M2/M3 default: no direct egress, but a
 *              path to the brokers that hold the credentials.
 *
 *   "allowlist" Deny-by-default plus named destinations. THE HOSTNAME
 *              ALLOWLIST IS NOT ENFORCED BY DOCKER. Docker has no
 *              per-container egress firewall; `--network` selects a topology,
 *              not a policy. Enforcing `allowHosts` requires one of:
 *                (a) an explicit-proxy sidecar on an internal network, with
 *                    HTTP(S)_PROXY set in the container and SNI/CONNECT-host
 *                    filtering in the proxy — defeated by anything that
 *                    ignores the proxy env vars, so pair it with "internal" so
 *                    the direct path is dead; or
 *                (b) iptables/nftables rules inside the Docker VM against the
 *                    bridge interface — on Docker Desktop for Windows those
 *                    rules live in a VM the product does not own, do not
 *                    survive a Docker Desktop restart, and are therefore NOT a
 *                    control we may claim.
 *              Until (a) ships, an implementation that is asked for
 *              "allowlist" MUST either fall back to "internal" and report
 *              "egress-allowlist" in `unenforced`, or refuse to create the
 *              sandbox. It MUST NOT create a normal bridge network and call
 *              the allowlist enforced.
 *
 * `--network=host` is never a legal value. There is no mode for it here.
 */
export type NetworkMode = "none" | "internal" | "allowlist";

export interface EgressPolicy {
  readonly mode: NetworkMode;
  /**
   * Destination hosts permitted in "allowlist" mode, e.g.
   * ["registry.npmjs.org", "pypi.org"]. Exact hostnames or a single leading
   * "*." label. Empty in "none" / "internal" mode.
   *
   * Never contains the model provider or GitHub: those are reached through
   * host-side brokers, not by the container (D1, D2).
   */
  readonly allowHosts: readonly string[];
  /** Ports permitted in "allowlist" mode. Typically [443]. */
  readonly allowPorts: readonly number[];
}

/**
 * Environment for the container. Deliberately NOT `Record<string, string>`
 * with a comment asking nicely: the type exists to make credential injection
 * awkward to write.
 *
 * SECURITY.md D1/D2/T2: `env`, `/proc/<pid>/environ`, and one `Bash` call are
 * the same thing. Nothing here may be a provider key, a Git token, a database URL,
 * or a cookie-signing secret. Capability tokens are short-lived,
 * workspace-scoped, and useless outside the broker that issued them.
 */
export interface SandboxEnv {
  /** Non-secret variables: PATH additions, NODE_ENV, TZ, LANG, CI. */
  readonly plain: Readonly<Record<string, string>>;
  /**
   * Short-lived capability token for the host-side brokers, or null before
   * M3b when no broker exists yet. Recorded separately so it can be rotated,
   * audited, and grepped for — not so it is more secret than `plain`.
   */
  readonly capabilityToken: string | null;
}

export interface SandboxSpec {
  readonly image: SandboxImageRef;
  readonly repo: RepoMount;
  /** At minimum /tmp. Add every path the toolchain writes to. */
  readonly tmpfs: readonly TmpfsMount[];
  readonly limits: ResourceLimits;
  readonly egress: EgressPolicy;
  readonly env: SandboxEnv;
  /**
   * Unprivileged uid:gid to run as, e.g. "10001:10001". Required — an
   * implementation must never fall through to the image's default, because the
   * default is root often enough to matter.
   */
  readonly user: string;
  /** Working directory for exec and pty. Usually `repo.containerPath`. */
  readonly workdir: string;
  /**
   * Idle timeout in seconds before the orchestrator may hibernate (PLAN.md §6,
   * M5). Advisory: the provider does not run the timer, it just carries the
   * number so hibernation policy lives with the spec.
   */
  readonly idleTimeoutSeconds: number;
  /** Free-form labels for operator tooling. Never security-relevant. */
  readonly labels?: Readonly<Record<string, string>>;
}

/* ==========================================================================
 * Handle — what you got
 * ========================================================================== */

/**
 * A control this host could not enforce. Reported, never silently dropped.
 * Ordered by consequence.
 */
export type UnenforcedControl =
  /** No per-container egress filtering; fell back to a coarser network mode. */
  | "egress-allowlist"
  /** No writable-layer quota (ext4 backing store on Docker Desktop). */
  | "disk-quota"
  /** Daemon has no userns-remap; container uid maps to a real host uid. */
  | "userns-remap"
  /** Engine runs as root (Docker Desktop's VM); not rootless Docker. */
  | "rootless-engine"
  /** Read-only root filesystem refused by the image or the host. */
  | "readonly-rootfs"
  /** Seccomp profile unavailable or overridden. */
  | "seccomp";

export type SandboxState =
  | "creating"
  | "running"
  /** Stopped with its filesystem retained; `restore` brings it back. */
  | "hibernated"
  | "stopping"
  | "destroyed"
  /** Exited unexpectedly — OOM kill, host restart, engine crash. */
  | "failed";

/**
 * A live sandbox. Values only: no methods, so a handle can be logged,
 * serialized into the event log, and handed across a future service boundary
 * without dragging the provider with it.
 */
export interface SandboxHandle {
  readonly id: SandboxId;
  readonly workspaceId: string;
  readonly state: SandboxState;
  /** Spec the sandbox was created from, for restart and for audit. */
  readonly spec: SandboxSpec;
  readonly createdAt: string;
  /**
   * Controls this host could not enforce. MUST be accurate. An empty array is
   * a claim that every control in this file is live; do not make it lightly.
   * Callers surface this in the UI — the user is entitled to know the box is
   * softer than the docs say.
   */
  readonly unenforced: readonly UnenforcedControl[];
  /**
   * Backend-specific identifier (a Docker container id, an E2B sandbox id).
   * For operator diagnostics only. Nothing above this interface may parse it,
   * pattern-match it, or pass it to a backend API.
   */
  readonly backendRef: string;
}

/* ==========================================================================
 * exec — one-shot commands
 * ========================================================================== */

export interface ExecOpts {
  /** Defaults to `spec.workdir`. Must resolve inside the repo mount. */
  readonly cwd?: string;
  /** Merged over `spec.env.plain`. Same prohibition: no secrets. */
  readonly env?: Readonly<Record<string, string>>;
  /** Defaults to `spec.user`. There is no way to ask for root. */
  readonly user?: string;
  /** Bytes written to stdin, then stdin closes. */
  readonly stdin?: Uint8Array;
  /**
   * Wall-clock ceiling. On expiry the process is killed and `timedOut` is
   * true. Required: an agent-issued command with no timeout is a hung
   * workspace waiting to happen.
   */
  readonly timeoutMs: number;
  /**
   * Per-stream output cap. Beyond it, output is dropped and `truncated` is
   * set. Required: `yes` and `cat /dev/urandom` are both one token away.
   */
  readonly maxOutputBytes: number;
  /** Cancels the exec; the process is killed and the promise rejects. */
  readonly signal?: AbortSignal;
}

export interface ExecResult {
  /** Process exit code, or null when it was terminated by a signal. */
  readonly exitCode: number | null;
  /** Signal name that terminated the process, e.g. "SIGKILL". */
  readonly signal: string | null;
  /**
   * Captured stdout/stderr as raw bytes, capped at `maxOutputBytes`.
   *
   * Bytes, not strings, for the same reason terminal output is bytes: command
   * output is not guaranteed to be valid UTF-8, and decoding at the boundary
   * corrupts it. Decode at the point of display, once.
   */
  readonly stdout: Uint8Array;
  readonly stderr: Uint8Array;
  /** True when either stream hit `maxOutputBytes`. */
  readonly truncated: boolean;
  /** True when `timeoutMs` expired. `exitCode` is then null. */
  readonly timedOut: boolean;
  readonly durationMs: number;
}

/* ==========================================================================
 * pty — interactive shells
 * ========================================================================== */

export interface PtySize {
  /** Columns. 1..1000. */
  readonly cols: number;
  /** Rows. 1..1000. */
  readonly rows: number;
}

export interface PtyOpts {
  /** argv. `["/bin/bash", "-l"]`. Never a shell string — no shell parsing here. */
  readonly command: readonly string[];
  readonly cwd?: string;
  readonly env?: Readonly<Record<string, string>>;
  readonly user?: string;
  /** Initial window size. Resize later with `PtyHandle.resize`. */
  readonly size: PtySize;
  /** $TERM inside the pty. "xterm-256color" for xterm.js. */
  readonly term: string;
}

export interface PtyExit {
  readonly exitCode: number | null;
  readonly signal: string | null;
}

/**
 * A live pty. Unlike `SandboxHandle` this one holds live resources, so it does
 * carry methods and MUST be disposed.
 *
 * Multiple viewers share one pty (M2's done-when criterion): the transport
 * layer fans `onData` out to every subscriber and funnels every subscriber's
 * keystrokes into the single `write`. The provider knows nothing about
 * viewers — fan-out is the stream hub's job, not the sandbox's.
 */
export interface PtyHandle {
  readonly id: PtyId;
  readonly sandboxId: SandboxId;

  /** Raw bytes to the pty master. Keystrokes, paste, ^C. Never newline-framed. */
  write(data: Uint8Array): void;

  /** Tell the pty its window changed. Sends SIGWINCH to the foreground group. */
  resize(size: PtySize): void;

  /**
   * Subscribe to output bytes. Returns an unsubscribe function.
   *
   * Chunks are raw pty bytes with NO transformation: not decoded, not
   * line-buffered, not stripped of escape sequences. A chunk may split a
   * UTF-8 sequence or an ANSI escape in half — that is normal, and why the
   * wire protocol (`@atrium/shared` terminal.ts) is binary end to end.
   */
  onData(listener: (chunk: Uint8Array) => void): () => void;

  /** Resolves when the pty's process exits. Never rejects. */
  readonly exited: Promise<PtyExit>;

  /** Send a signal to the process. Defaults to SIGTERM. */
  kill(signal?: string): void;

  /**
   * Kill the process if alive and release the handle's resources. Idempotent.
   * Every `spawnPty` needs a matching `dispose` on every path, including the
   * one where the websocket died mid-command.
   */
  dispose(): Promise<void>;
}

/* ==========================================================================
 * Ports, snapshots
 * ========================================================================== */

/**
 * A proxied container port.
 *
 * Returns a struct rather than PLAN.md's bare `URL` because of SECURITY.md §5
 * revision 2 and D3: the preview MUST be on a SEPARATE ORIGIN from the app.
 * A bare URL invites `app.example.com/preview/:id/*`, which hands the user's
 * dev-server JavaScript the app's cookies and localStorage. The separate
 * origin is the security property, so it is a named field.
 */
export interface ProxiedPort {
  readonly port: number;
  /**
   * Full URL on a dedicated preview origin
   * (`<opaque>.preview.example.com`), embedded in a sandboxed iframe.
   * Never a path on the app origin.
   */
  readonly url: URL;
  /**
   * The origin alone, for the app's CSP `frame-src`. Asserted by the provider
   * to differ from the app origin; callers should assert it again.
   */
  readonly origin: string;
  /** ISO 8601 expiry of the mapping, so a stale link stops working. */
  readonly expiresAt: string;
}

/**
 * A stored sandbox filesystem (PLAN.md §6, M5).
 *
 * SECURITY.md T9: a snapshot is the whole filesystem, so it is the densest
 * secret store in the system — anything the agent read into a file is in here.
 * Encrypt at rest and apply a retention policy. `restore` takes the snapshot
 * plus a fresh spec because the security posture of the ORIGINAL spec must not
 * be resurrected verbatim: image digests get revoked and egress policy
 * tightens, and a restore is the obvious place to smuggle an old, weaker one
 * back into production.
 */
export interface Snapshot {
  readonly id: SnapshotId;
  readonly workspaceId: string;
  readonly sandboxId: SandboxId;
  readonly createdAt: string;
  readonly sizeBytes: number;
  /** Digest of the stored bytes, for integrity verification on restore. */
  readonly digest: string;
  /** Backend-specific locator (image ref, blob key). Opaque above this layer. */
  readonly backendRef: string;
}

/* ==========================================================================
 * Errors
 * ========================================================================== */

/**
 * Why a sandbox operation failed. A string union, not an enum —
 * `erasableSyntaxOnly` is on and the server runs under
 * `node --experimental-strip-types`, which erases types without transforming.
 */
export type SandboxErrorCode =
  /** No sandbox with that id, or it was destroyed. */
  | "not-found"
  /** Sandbox exists but is hibernated/stopping/failed. */
  | "not-running"
  /** Backend unreachable — Docker Desktop not running, engine restarting. */
  | "backend-unavailable"
  /** Spec rejected: unpinned image, missing limit, illegal network mode. */
  | "invalid-spec"
  /**
   * The spec asked for a control this host cannot enforce, and the caller
   * required enforcement rather than a report. See `UnenforcedControl`.
   */
  | "control-unenforceable"
  /** Ran out of memory, disk, or PIDs. */
  | "resource-exhausted"
  /** Wall-clock limit expired. */
  | "timeout"
  /** Caller aborted via AbortSignal. */
  | "aborted"
  /** Anything else. Message is for operators, never rendered to the agent. */
  | "internal";

export interface SandboxErrorShape {
  readonly code: SandboxErrorCode;
  /** Operator-facing. MUST NOT contain host paths, tokens, or env values. */
  readonly message: string;
  readonly sandboxId?: SandboxId;
}

/* ==========================================================================
 * The interface
 * ========================================================================== */

export interface SandboxProvider {
  /** Identifies the implementation in logs and health output, e.g. "local-docker". */
  readonly name: string;

  /**
   * Create and start a sandbox for a workspace.
   *
   * MUST validate the spec first and reject with `invalid-spec` on: an image
   * without a digest, `user` resolving to uid 0, a missing resource limit, a
   * writable mount outside the repo path, or any attempt at host networking.
   *
   * MUST apply the full hardening set at the top of this file. Every control
   * it cannot apply on this host goes into `SandboxHandle.unenforced` — never
   * a log line nobody reads, and never silence.
   *
   * MUST NOT mount the Docker socket. There is no flag for it and no spec
   * field that could ask for it; if an implementation adds one, delete it.
   *
   * Idempotent per workspace: called with a workspace that already has a
   * running sandbox, return the existing handle rather than a second container.
   */
  create(workspaceId: string, spec: SandboxSpec): Promise<SandboxHandle>;

  /** Current state, re-read from the backend. Null when unknown to the backend. */
  inspect(id: SandboxId): Promise<SandboxHandle | null>;

  /**
   * Run one command to completion and capture its output.
   *
   * `cmd` is argv, executed WITHOUT a shell. A caller that wants a shell asks
   * for one explicitly (`["/bin/sh", "-lc", script]`) so that the decision is
   * visible in the caller, not hidden in the provider.
   *
   * Rejects with `not-running` if the sandbox is not running, `timeout` on
   * expiry (only when output was already discarded — otherwise resolve with
   * `timedOut: true`), and `aborted` when the signal fires.
   */
  exec(handle: SandboxHandle, cmd: readonly string[], opts: ExecOpts): Promise<ExecResult>;

  /**
   * Start an interactive pty inside the sandbox.
   *
   * The pty runs INSIDE the container, never on the host. See
   * `notesForBuilders` about the host-side `node-pty` fallback: if host
   * `node-pty` is used at all it may only wrap the client process that attaches
   * to the container, and must never spawn a host shell — a host pty is a
   * shell on the machine holding every credential, which is the boundary this
   * whole file exists to defend.
   */
  spawnPty(handle: SandboxHandle, opts: PtyOpts): Promise<PtyHandle>;

  /**
   * Expose a container port on a separate preview origin (D3).
   *
   * The port comes from the workspace record or an explicit user action, never
   * from an inbound request parameter — SECURITY.md T5 makes a
   * request-influenced target an open proxy into the internal network and the
   * cloud metadata endpoint. Implementations MUST allowlist the port range.
   */
  proxyPort(handle: SandboxHandle, port: number): Promise<ProxiedPort>;

  /**
   * Stop the sandbox, retaining its filesystem (PLAN.md §6).
   *
   * Live ptys are killed first; their `exited` promises resolve. The returned
   * `Snapshot` is the only way back — the handle is `hibernated` afterwards
   * and exec/pty on it reject with `not-running`.
   */
  hibernate(handle: SandboxHandle): Promise<Snapshot>;

  /**
   * Recreate a sandbox from a snapshot under a FRESH spec.
   *
   * The spec is a parameter, not a field read back off the snapshot, so that a
   * restore cannot resurrect a stale image digest or a looser egress policy.
   * Verify `snapshot.digest` before starting anything.
   */
  restore(snapshot: Snapshot, spec: SandboxSpec): Promise<SandboxHandle>;

  /**
   * Stop and remove the sandbox and its writable layer. Idempotent: destroying
   * an unknown or already-destroyed sandbox resolves, it does not reject.
   * Does not delete snapshots.
   */
  destroy(handle: SandboxHandle): Promise<void>;

  /**
   * Delete a snapshot's stored bytes. Idempotent. Separate from `destroy`
   * because snapshot retention is a policy decision (T9), not a side effect of
   * tearing down a container.
   */
  deleteSnapshot(id: SnapshotId): Promise<void>;

  /**
   * Backend reachability, for `/api/health`. Never throws: a provider that
   * cannot answer is itself the answer.
   */
  health(): Promise<{
    readonly reachable: boolean;
    /** Engine version string, when reachable. */
    readonly version?: string;
    /** Why not, when unreachable. No paths, no secrets. */
    readonly detail?: string;
  }>;
}
