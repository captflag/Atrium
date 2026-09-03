/**
 * Spec validation and the default workspace spec.
 *
 * `SandboxProvider.create` "MUST validate the spec first and reject with
 * `invalid-spec`". That validation lives here rather than inside
 * `LocalDockerProvider` for two reasons: every future provider (E2B, Fly) owes
 * the caller the same rejections, and a rule you can read in one screen is a
 * rule you can audit.
 *
 * Nothing in this file imports `dockerode`. It is pure predicate logic over the
 * contract in `provider.ts`.
 */

import { SandboxError } from "./errors.ts";
import type {
  EgressPolicy,
  ResourceLimits,
  SandboxEnv,
  SandboxImageRef,
  SandboxSpec,
  TmpfsMount,
} from "./provider.ts";

/* ==========================================================================
 * Defaults
 * ========================================================================== */

/**
 * A sane starting box: enough to run a Node toolchain, not enough to hurt the
 * host. `diskBytes` is null because Docker Desktop for Windows cannot enforce a
 * writable-layer quota (see `ResourceLimits.diskBytes` and the
 * "disk-quota" entry in `UnenforcedControl`).
 */
export const DEFAULT_LIMITS: ResourceLimits = {
  memoryBytes: 2 * 1024 * 1024 * 1024,
  cpus: 2,
  pids: 512,
  diskBytes: null,
};

/**
 * The root filesystem is read-only, so every legitimate write path outside the
 * repo mount is declared here.
 *
 * `/tmp`      build scratch, pty pid files.
 * `/home/atrium` HOME. git refuses to run without a writable HOME for its
 *              config lock files; npm wants a cache directory.
 * `/run`      pid/lock files for anything that expects FHS.
 *
 * All three are `noexec`: a downloaded binary should not be runnable from
 * scratch space. If a toolchain genuinely needs to exec out of /tmp, that is a
 * per-workspace spec decision made visibly, not a default.
 */
export const DEFAULT_TMPFS: readonly TmpfsMount[] = [
  { containerPath: "/tmp", sizeBytes: 256 * 1024 * 1024, noexec: true },
  { containerPath: "/home/atrium", sizeBytes: 64 * 1024 * 1024, noexec: true },
  { containerPath: "/run", sizeBytes: 8 * 1024 * 1024, noexec: true },
];

/** uid:gid baked into docker/workspace.Dockerfile. Never 0. */
export const DEFAULT_USER = "10001:10001";

export const DEFAULT_CONTAINER_REPO_PATH = "/workspace";

/**
 * Non-secret environment for a workspace container.
 *
 * `GIT_*` entries exist to make git behave in a credential-free container
 * (SECURITY.md D2):
 *   GIT_TERMINAL_PROMPT=0  never block asking for a username/password
 *   GIT_ASKPASS=/bin/false the same, for the helper path
 *   GIT_CONFIG_NOSYSTEM=1  ignore /etc/gitconfig; the image ships none, but a
 *                          future base image might
 *   safe.directory         the bind mount is owned by a host uid that is not
 *                          10001, and git's dubious-ownership check would
 *                          otherwise refuse to touch it
 */
export function defaultPlainEnv(containerRepoPath: string): Readonly<Record<string, string>> {
  return {
    HOME: "/home/atrium",
    PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    LANG: "C.UTF-8",
    TZ: "UTC",
    CI: "1",
    GIT_TERMINAL_PROMPT: "0",
    GIT_ASKPASS: "/bin/false",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_COUNT: "1",
    GIT_CONFIG_KEY_0: "safe.directory",
    GIT_CONFIG_VALUE_0: containerRepoPath,
  };
}

export interface WorkspaceSpecParams {
  readonly image: SandboxImageRef;
  /** Absolute host path to the workspace checkout. Server-resolved (T5). */
  readonly hostRepoPath: string;
  readonly containerRepoPath?: string;
  readonly limits?: ResourceLimits;
  readonly tmpfs?: readonly TmpfsMount[];
  /** Defaults to `{ mode: "internal", ... }` — the M2/M3 posture (D4). */
  readonly egress?: EgressPolicy;
  readonly env?: SandboxEnv;
  readonly user?: string;
  readonly idleTimeoutSeconds?: number;
  readonly labels?: Readonly<Record<string, string>>;
}

/**
 * Build the standard workspace spec. Callers may override any field, but every
 * default here is the hardened one — the easy path and the safe path are the
 * same path.
 */
export function workspaceSpec(params: WorkspaceSpecParams): SandboxSpec {
  const containerPath = params.containerRepoPath ?? DEFAULT_CONTAINER_REPO_PATH;
  const spec: SandboxSpec = {
    image: params.image,
    repo: { hostPath: params.hostRepoPath, containerPath, writable: true },
    tmpfs: params.tmpfs ?? DEFAULT_TMPFS,
    limits: params.limits ?? DEFAULT_LIMITS,
    egress: params.egress ?? { mode: "internal", allowHosts: [], allowPorts: [] },
    env: params.env ?? { plain: defaultPlainEnv(containerPath), capabilityToken: null },
    user: params.user ?? DEFAULT_USER,
    workdir: containerPath,
    idleTimeoutSeconds: params.idleTimeoutSeconds ?? 900,
    ...(params.labels === undefined ? {} : { labels: params.labels }),
  };
  return spec;
}

/* ==========================================================================
 * Validation
 * ========================================================================== */

const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const UID_GID_RE = /^(\d{1,10}):(\d{1,10})$/;
const ENV_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
const HOSTNAME_RE = /^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

/**
 * Environment names that must never appear in `SandboxEnv.plain` (D1, D2, T2).
 *
 * This is a tripwire, not a classifier: a determined caller can name a secret
 * `FOO`. It exists because the realistic failure is not malice, it is someone
 * six months from now adding `GITHUB_TOKEN` to the spec because it was
 * convenient, and nothing objecting.
 */
const FORBIDDEN_ENV_RE =
  /(^|_)(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|CREDENTIALS|PAT|APIKEY|AUTH)(_|$)|DATABASE_URL|_KEY$|_TOKEN$|_SECRET$/i;

/**
 * Names that trip `FORBIDDEN_ENV_RE` but carry no secret, each justified.
 *
 * A tripwire with no escape hatch gets deleted the first time it is wrong;
 * one with a short, reviewed exception list survives. Keep this list tiny, and
 * make every entry explain itself.
 *
 *   GIT_CONFIG_KEY_<n>  git's environment form of `git -c key=value`. The
 *                       "KEY" here is a config key NAME (we set
 *                       `safe.directory`), and the matching
 *                       GIT_CONFIG_VALUE_<n> holds the value — which is a
 *                       container path, and does not trip the rule anyway.
 */
const ALLOWED_DESPITE_NAME = /^GIT_CONFIG_KEY_\d+$/;

/** Container paths a mount must never shadow. */
const FORBIDDEN_MOUNT_TARGETS = [
  "/",
  "/bin",
  "/boot",
  "/dev",
  "/etc",
  "/lib",
  "/proc",
  "/sbin",
  "/sys",
  "/usr",
  "/var",
];

function fail(message: string): never {
  throw new SandboxError("invalid-spec", message);
}

function isAbsolutePosix(p: string): boolean {
  return p.startsWith("/") && !p.includes("\\") && !p.includes("\0");
}

/** Windows (`C:\x`, `\\server\share`) or POSIX (`/x`). Host paths are host-shaped. */
function isAbsoluteHostPath(p: string): boolean {
  if (p.includes("\0")) return false;
  if (/^[A-Za-z]:[\\/]/.test(p)) return true;
  if (p.startsWith("\\\\")) return true;
  return p.startsWith("/");
}

function normalizeContainerPath(p: string): string {
  const trimmed = p.length > 1 && p.endsWith("/") ? p.slice(0, -1) : p;
  return trimmed;
}

/** True when `child` is `parent` or lies beneath it. */
function isWithin(parent: string, child: string): boolean {
  const p = normalizeContainerPath(parent);
  const c = normalizeContainerPath(child);
  if (p === "/") return true;
  return c === p || c.startsWith(`${p}/`);
}

function validateImage(image: SandboxImageRef): void {
  if (image.repository.trim() === "") fail("image.repository is empty");
  if (/[@\s]/.test(image.repository) || image.repository.includes(":")) {
    fail("image.repository must carry neither a tag nor a digest");
  }
  // T12: a tag is a mutable pointer. Refuse anything unpinned, loudly.
  if (!DIGEST_RE.test(image.digest)) {
    fail("image.digest must be a sha256 content digest; an unpinned image reference is refused");
  }
}

function validateLimits(limits: ResourceLimits): void {
  if (!Number.isFinite(limits.memoryBytes) || limits.memoryBytes < 6 * 1024 * 1024) {
    fail("limits.memoryBytes must be at least 6MiB (the Docker minimum)");
  }
  if (!Number.isFinite(limits.cpus) || limits.cpus <= 0) fail("limits.cpus must be > 0");
  if (!Number.isInteger(limits.pids) || limits.pids <= 0) {
    fail("limits.pids must be a positive integer (the fork-bomb control)");
  }
  if (limits.diskBytes !== null && (!Number.isFinite(limits.diskBytes) || limits.diskBytes <= 0)) {
    fail("limits.diskBytes must be a positive number or null");
  }
}

function validateEgress(egress: EgressPolicy): void {
  if (egress.mode !== "none" && egress.mode !== "internal" && egress.mode !== "allowlist") {
    // Reachable from untyped callers (a spec off the wire, a JSON config file).
    fail(`egress.mode must be "none" | "internal" | "allowlist"`);
  }
  if (egress.mode !== "allowlist") {
    if (egress.allowHosts.length > 0 || egress.allowPorts.length > 0) {
      fail(`egress.allowHosts/allowPorts must be empty unless mode is "allowlist"`);
    }
    return;
  }
  if (egress.allowHosts.length === 0) {
    fail(`egress.mode "allowlist" with an empty allowHosts is "none" spelled confusingly`);
  }
  for (const host of egress.allowHosts) {
    if (!HOSTNAME_RE.test(host)) fail(`egress.allowHosts entry is not a hostname: ${host}`);
  }
  for (const port of egress.allowPorts) {
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      fail(`egress.allowPorts entry is not a port: ${String(port)}`);
    }
  }
}

function validateEnv(env: SandboxEnv): void {
  for (const [name, value] of Object.entries(env.plain)) {
    if (!ENV_NAME_RE.test(name)) fail(`env.plain has an illegal variable name: ${name}`);
    if (FORBIDDEN_ENV_RE.test(name) && !ALLOWED_DESPITE_NAME.test(name)) {
      fail(
        `env.plain must not carry credentials (D1, D2): ${name}. ` +
          `Credentials stay host-side; the container gets a capability token.`,
      );
    }
    if (value.includes("\0")) fail(`env.plain value for ${name} contains a NUL byte`);
  }
  if (env.capabilityToken !== null && env.capabilityToken.trim() === "") {
    fail("env.capabilityToken must be a non-empty string or null");
  }
}

function validateMounts(spec: SandboxSpec): void {
  const repoTarget = normalizeContainerPath(spec.repo.containerPath);
  if (!isAbsoluteHostPath(spec.repo.hostPath)) {
    fail("repo.hostPath must be an absolute host path");
  }
  if (!isAbsolutePosix(repoTarget)) fail("repo.containerPath must be an absolute POSIX path");
  if (FORBIDDEN_MOUNT_TARGETS.includes(repoTarget)) {
    fail(`repo.containerPath must not shadow a system directory: ${repoTarget}`);
  }

  const seen = new Set<string>();
  for (const mount of spec.tmpfs) {
    const target = normalizeContainerPath(mount.containerPath);
    if (!isAbsolutePosix(target)) fail("tmpfs.containerPath must be an absolute POSIX path");
    if (FORBIDDEN_MOUNT_TARGETS.includes(target)) {
      fail(`tmpfs.containerPath must not shadow a system directory: ${target}`);
    }
    if (seen.has(target)) fail(`duplicate tmpfs mount at ${target}`);
    seen.add(target);
    if (!Number.isFinite(mount.sizeBytes) || mount.sizeBytes <= 0) {
      fail(`tmpfs at ${target} needs a positive sizeBytes; tmpfs is RAM and an uncapped one OOMs the host`);
    }
    // "a writable mount outside the repo path" is the rejection the contract
    // asks for. The repo mount and the declared tmpfs are the only writable
    // surfaces; a tmpfs nested in the repo would silently hide repo content,
    // and a tmpfs containing the repo would swallow the bind.
    if (isWithin(repoTarget, target) || isWithin(target, repoTarget)) {
      fail(`tmpfs at ${target} overlaps the repo mount at ${repoTarget}`);
    }
  }
}

/**
 * Reject a spec that violates the contract. Throws `SandboxError("invalid-spec")`
 * with an operator-facing reason; returns nothing on success.
 *
 * There is deliberately no option to skip this and no field that could ask for
 * a Docker socket mount, host networking, or root.
 */
export function validateSpec(spec: SandboxSpec): void {
  validateImage(spec.image);
  validateMounts(spec);
  validateLimits(spec.limits);
  validateEgress(spec.egress);

  const user = UID_GID_RE.exec(spec.user);
  if (user === null) fail(`user must be "uid:gid" with numeric ids, got ${JSON.stringify(spec.user)}`);
  const uid = Number(user[1]);
  const gid = Number(user[2]);
  if (uid === 0 || gid === 0) fail("user must not resolve to uid 0 or gid 0");

  if (!isAbsolutePosix(spec.workdir)) fail("workdir must be an absolute POSIX path");
  if (!isWithin(spec.repo.containerPath, spec.workdir) && !spec.tmpfs.some((t) => isWithin(t.containerPath, spec.workdir))) {
    fail("workdir must resolve inside the repo mount or a declared tmpfs");
  }

  if (!Number.isFinite(spec.idleTimeoutSeconds) || spec.idleTimeoutSeconds <= 0) {
    fail("idleTimeoutSeconds must be > 0");
  }

  // Last, because its failure message is the one most likely to be a false
  // positive from the name tripwire, and a caller debugging a genuinely broken
  // spec should hear about the broken part first.
  validateEnv(spec.env);
}

/** Every secret-ish string in a spec, for `redact()`. */
export function specSecrets(spec: SandboxSpec): readonly string[] {
  const out = [spec.repo.hostPath, ...Object.values(spec.env.plain)];
  if (spec.env.capabilityToken !== null) out.push(spec.env.capabilityToken);
  return out;
}

/**
 * The spec as stored in a container label, so `inspect()` can rebuild a handle
 * for a sandbox this process did not create.
 *
 * The capability token is nulled: a label is readable by anything that can
 * reach the engine, and a credential that survives a process restart in a
 * label is a credential at rest in the wrong place.
 */
export function redactSpecForLabel(spec: SandboxSpec): SandboxSpec {
  return { ...spec, env: { plain: spec.env.plain, capabilityToken: null } };
}
