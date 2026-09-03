/**
 * Cloning a repository into a workspace checkout (M2).
 *
 * ============================================================================
 * WHY THIS IS NOT A METHOD ON THE PROVIDER
 * ============================================================================
 * A workspace container has NO route to the internet: its egress mode is
 * "none" or the `--internal` bridge, by design (D4). So `git clone` cannot run
 * inside it, and making it possible would mean giving the long-lived,
 * agent-inhabited container real egress — which is precisely the channel
 * prompt injection wants (T1).
 *
 * So the clone runs in a SEPARATE, SHORT-LIVED container that exists for the
 * duration of one `git clone` and is then removed. It gets the same hardening
 * as a workspace container (`hardenedHostConfig`) with one deliberate
 * difference, stated rather than hidden:
 *
 *   THE CLONE CONTAINER HAS UNFILTERED EGRESS. It runs on Docker's default
 *   bridge, so it can reach any host on the internet, because a git remote can
 *   be any host on the internet and Docker has no per-container egress filter
 *   (see `EgressPolicy` in provider.ts). `CloneOutcome.egressUnfiltered` says
 *   so to the caller, and it is `true` by type, not by value, so nobody can
 *   read a `false` here and relax.
 *
 * What bounds it instead: no credentials of any kind (below), the container is
 * torn down within seconds, it runs `git clone` and nothing else — no shell, no
 * hooks (`git clone` does not run remote-provided hooks), no submodules — and
 * it can write to exactly one path, the destination checkout.
 *
 * ============================================================================
 * CREDENTIALS: NONE. PUBLIC HTTPS ONLY. (SECURITY.md D2, T4)
 * ============================================================================
 * No token, no SSH key, no `.netrc`, no credential helper, no `url` with
 * userinfo — `assertPublicHttpsUrl` rejects `https://user:pass@host/…` outright.
 * `GIT_TERMINAL_PROMPT=0` and `GIT_ASKPASS=/bin/false` make an authentication
 * attempt fail fast rather than hang.
 *
 * PRIVATE REPOSITORIES ARE THEREFORE NOT SUPPORTED IN M2, on purpose. They
 * arrive in M6 through the host-side Git proxy (D2), which holds a
 * repo-scoped token, enforces a branch allowlist, and requires human approval
 * for push. The proxy is the only design in which a private repo can be cloned
 * without a credential ever entering a container. Adding a token to this file
 * would be the exact mistake D2 exists to prevent.
 */

import { mkdir, readdir } from "node:fs/promises";
import { Writable } from "node:stream";
import Docker from "dockerode";

import type { ResourceLimits, SandboxImageRef } from "./provider.ts";
import { redact, SandboxError } from "./errors.ts";
import { hardenedHostConfig } from "./harden.ts";
import { LABEL_MANAGED, LABEL_ROLE, resolveImageReference } from "./local-docker.ts";
import { DEFAULT_USER } from "./spec.ts";

/** Tight box: a clone is IO-bound and should never need more than this. */
const CLONE_LIMITS: ResourceLimits = {
  memoryBytes: 1024 * 1024 * 1024,
  cpus: 2,
  pids: 256,
  diskBytes: null,
};

const CLONE_TMPFS = [
  { containerPath: "/tmp", sizeBytes: 64 * 1024 * 1024, noexec: true },
  { containerPath: "/home/atrium", sizeBytes: 16 * 1024 * 1024, noexec: true },
] as const;

const MAX_LOG_BYTES = 64 * 1024;
const DEFAULT_CLONE_TIMEOUT_MS = 180_000;

/** Hostnames a clone must never reach: the SSRF targets, in literal form (T5). */
const FORBIDDEN_HOST_RE =
  /^(localhost|.*\.local|.*\.internal|.*\.localdomain|\[?[0-9a-f:]*\]?|\d{1,3}(\.\d{1,3}){3})$/i;

const REF_RE = /^[A-Za-z0-9][A-Za-z0-9._\-/]{0,254}$/;

export interface CloneRequest {
  /** Public HTTPS git URL. No userinfo, no ssh, no git:// — see the header. */
  readonly repoUrl: string;
  /** Absolute host path for the checkout. Server-resolved, never from a request (T5). */
  readonly hostPath: string;
  /** Digest-pinned image providing git. The workspace image does. */
  readonly image: SandboxImageRef;
  /** Branch or tag. Defaults to the remote's HEAD. */
  readonly ref?: string;
  /** `--depth`. 1 by default: history is not what an agent needs to start. */
  readonly depth?: number;
  readonly timeoutMs?: number;
  readonly user?: string;
}

export interface CloneOutcome {
  readonly ok: boolean;
  readonly exitCode: number | null;
  /** Combined stdout+stderr tail, capped and redacted. Safe to show a user. */
  readonly log: string;
  readonly timedOut: boolean;
  readonly durationMs: number;
  /**
   * Always true, and typed `true` so it cannot be read as a maybe: the clone
   * container reaches the internet without a filter. See the file header.
   */
  readonly egressUnfiltered: true;
}

/**
 * Reject anything that is not a public HTTPS git URL.
 *
 * The rejections, and what each one is for:
 *   non-https        `ssh://`, `git://`, `file://` and a bare `host:path` scp
 *                    form all reach resources this container must not touch,
 *                    and `file://` reads the host filesystem through the mount
 *   userinfo         `https://token@host/…` is a credential in a URL (D2)
 *   IP literal /     an internal address or the cloud metadata endpoint
 *   localhost /      (169.254.169.254) turns the clone into an SSRF primitive
 *   .internal        (T5)
 */
export function assertPublicHttpsUrl(raw: string): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new SandboxError("invalid-spec", "repository URL is not a URL");
  }
  if (url.protocol !== "https:") {
    throw new SandboxError(
      "invalid-spec",
      "only public https:// clone URLs are supported in M2; private repos arrive with the host-side Git proxy (D2)",
    );
  }
  if (url.username !== "" || url.password !== "") {
    throw new SandboxError(
      "invalid-spec",
      "repository URL carries credentials; credentials never enter a container (D2)",
    );
  }
  if (FORBIDDEN_HOST_RE.test(url.hostname)) {
    throw new SandboxError("invalid-spec", "repository host is not a public hostname");
  }
  if (url.hostname.includes("_") || url.hostname === "") {
    throw new SandboxError("invalid-spec", "repository host is not a hostname");
  }
  return url;
}

function cappedText(limit: number): { stream: Writable; text(): string } {
  const chunks: Buffer[] = [];
  let kept = 0;
  const stream = new Writable({
    write(chunk: Buffer, _encoding, callback): void {
      const remaining = limit - kept;
      if (remaining > 0) {
        const slice = chunk.length > remaining ? chunk.subarray(0, remaining) : chunk;
        chunks.push(slice);
        kept += slice.length;
      }
      callback();
    },
  });
  return { stream, text: (): string => Buffer.concat(chunks, kept).toString("utf8") };
}

export interface CloneOptions {
  readonly docker: Docker;
}

/**
 * Clone `request.repoUrl` into `request.hostPath`.
 *
 * The destination must be empty (or absent, in which case it is created): git
 * refuses to clone into a populated directory, and silently merging into an
 * existing checkout would be a way to overwrite a workspace's work.
 */
export async function cloneRepository(
  request: CloneRequest,
  options: CloneOptions,
): Promise<CloneOutcome> {
  const url = assertPublicHttpsUrl(request.repoUrl);
  const ref = request.ref;
  if (ref !== undefined && !REF_RE.test(ref)) {
    throw new SandboxError("invalid-spec", "ref is not a valid branch or tag name");
  }
  const depth = request.depth ?? 1;
  if (!Number.isInteger(depth) || depth < 1) {
    throw new SandboxError("invalid-spec", "depth must be a positive integer");
  }

  await mkdir(request.hostPath, { recursive: true });
  const entries = await readdir(request.hostPath);
  if (entries.length > 0) {
    throw new SandboxError(
      "invalid-spec",
      "clone destination is not empty; refusing to clone over an existing checkout",
    );
  }

  const target = "/workspace";
  const cmd = [
    "git",
    "clone",
    "--depth",
    String(depth),
    "--single-branch",
    "--no-tags",
    // Submodules are NOT initialised: a submodule URL is remote-controlled
    // input that would make the allowlist-free egress above fetch an arbitrary
    // second host. If a workspace needs them it becomes a visible decision.
    ...(ref === undefined ? [] : ["--branch", ref]),
    // `--` so a URL or ref beginning with "-" cannot become an option.
    "--",
    url.toString(),
    target,
  ];

  const hostConfig = hardenedHostConfig({
    limits: CLONE_LIMITS,
    tmpfs: [...CLONE_TMPFS],
    // The one difference from a workspace container, and the reason
    // `egressUnfiltered` is in the return type. "bridge" is Docker's default
    // NAT'd network: a route to the internet, with no per-host filtering,
    // because Docker cannot do per-host filtering (see EgressPolicy).
    networkMode: "bridge",
    diskQuotaBytes: null,
  });
  hostConfig.Mounts = [
    { Type: "bind", Source: request.hostPath, Target: target, ReadOnly: false },
  ];

  const started = Date.now();
  const out = cappedText(MAX_LOG_BYTES);

  const imageRef = await resolveImageReference(options.docker, request.image);
  const container = await options.docker.createContainer({
    Image: imageRef,
    User: request.user ?? DEFAULT_USER,
    WorkingDir: "/",
    Cmd: cmd,
    Env: [
      "HOME=/home/atrium",
      // No credential can be supplied and none will be asked for: fail fast
      // instead of hanging on a prompt (D2).
      "GIT_TERMINAL_PROMPT=0",
      "GIT_ASKPASS=/bin/false",
      "GIT_CONFIG_NOSYSTEM=1",
      "GIT_ADVICE_DETACHEDHEAD=0",
    ],
    Labels: { [LABEL_MANAGED]: "true", [LABEL_ROLE]: "clone" },
    AttachStdout: true,
    AttachStderr: true,
    Tty: false,
    HostConfig: hostConfig,
  });

  let timedOut = false;
  let exitCode: number | null = null;
  try {
    const stream = await container.attach({ stream: true, stdout: true, stderr: true });
    // Tty is false, so the stream is Docker's multiplexed frame format. git
    // writes progress to stderr; both land in one log for the caller.
    options.docker.modem.demuxStream(stream, out.stream, out.stream);

    await container.start();

    const timer = setTimeout(() => {
      timedOut = true;
      void container.kill({ signal: "SIGKILL" }).catch(() => undefined);
    }, request.timeoutMs ?? DEFAULT_CLONE_TIMEOUT_MS);
    try {
      const result = (await container.wait()) as { StatusCode?: number };
      exitCode = typeof result.StatusCode === "number" ? result.StatusCode : null;
    } finally {
      clearTimeout(timer);
    }
  } finally {
    await container.remove({ force: true, v: true }).catch(() => undefined);
  }

  return {
    ok: !timedOut && exitCode === 0,
    exitCode: timedOut ? null : exitCode,
    // The host path appears in no git message we expect, but the container also
    // never learns it — redact anyway, because "we expect" is not a control.
    log: redact(out.text(), [request.hostPath]).trimEnd(),
    timedOut,
    durationMs: Date.now() - started,
    egressUnfiltered: true,
  };
}
