/**
 * The container hardening set, in one place.
 *
 * Both the long-lived workspace container (`LocalDockerProvider.create`) and
 * the throwaway clone container (`clone.ts`) run through this function. That is
 * the point: two call sites building `HostConfig` by hand is two chances to
 * forget `no-new-privileges`, and the forgotten one is always the one that runs
 * `git clone` against attacker-authored content.
 *
 * What is applied here (SECURITY.md T3, §4 "M2" row):
 *   - `ReadonlyRootfs`            read-only root; writes go to declared tmpfs
 *                                 and the repo bind mount, nothing else
 *   - `CapDrop: ["ALL"]`          no capabilities, including CAP_NET_RAW
 *   - `no-new-privileges:true`    setuid binaries cannot raise privileges
 *   - DEFAULT seccomp             by NOT setting `seccomp=`; passing
 *                                 `seccomp=unconfined` is never legal here
 *   - `Privileged: false`         stated rather than defaulted
 *   - `Memory` + `MemorySwap`     equal, so swap is disabled rather than
 *                                 unbounded (MemorySwap is memory+swap)
 *   - `NanoCpus`                  a real quota (cpu.max), not cpu shares
 *   - `PidsLimit`                 the fork-bomb control
 *   - `Init: true`                tini as pid 1 so orphans get reaped inside
 *                                 the PID limit rather than accumulating
 *   - tmpfs, each `nosuid,nodev` and `noexec` unless the spec says otherwise
 *
 * What is NOT applied here, and why:
 *   - There is no Docker-socket bind. There is no field for one anywhere in
 *     this codebase. If a future edit adds one, that edit is the bug.
 *   - `NetworkMode` is the caller's, because it is the one setting that
 *     legitimately differs between a workspace (no egress) and a clone (needs
 *     the network). It is never "host": `assertNetworkMode` refuses.
 *   - `StorageOpt` (the disk quota) is the caller's, because whether the host
 *     can enforce one is a runtime fact — see `EngineFacts.diskQuotaCapable`.
 *   - `UsernsMode` is left alone. Per-container userns requires daemon-level
 *     `userns-remap`, which Docker Desktop for Windows does not configure;
 *     setting it here would fail the create rather than harden it. The gap is
 *     reported as `"userns-remap"` in `SandboxHandle.unenforced`.
 */

import type Docker from "dockerode";
import type { ResourceLimits, TmpfsMount } from "./provider.ts";

/** `--security-opt` values applied to every container this process creates. */
export const HARDENED_SECURITY_OPT: readonly string[] = ["no-new-privileges:true"];

/**
 * Docker mount options for one tmpfs.
 *
 * `mode=1777` is explicit because a tmpfs inherits root ownership: without a
 * world-writable mode, an unprivileged container user cannot write to its own
 * HOME. Sticky (`1`) keeps it from being a shared-deletion hazard.
 */
export function tmpfsOptions(mount: TmpfsMount): string {
  const flags = ["rw", "nosuid", "nodev"];
  if (mount.noexec !== false) flags.push("noexec");
  flags.push("mode=1777", `size=${Math.floor(mount.sizeBytes)}`);
  return flags.join(",");
}

/** `--network=host` has no spelling in `NetworkMode` and must never acquire one. */
export function assertNetworkMode(networkMode: string): void {
  const lowered = networkMode.toLowerCase();
  if (lowered === "host" || lowered.startsWith("container:")) {
    throw new Error(`refusing network mode ${networkMode}`);
  }
}

export interface HardeningInput {
  readonly limits: ResourceLimits;
  readonly tmpfs: readonly TmpfsMount[];
  /** Docker network name, `"none"`, or a user-defined network. Never `"host"`. */
  readonly networkMode: string;
  /** Writable-layer quota, or null when the host cannot enforce one. */
  readonly diskQuotaBytes: number | null;
}

export function hardenedHostConfig(input: HardeningInput): Docker.HostConfig {
  assertNetworkMode(input.networkMode);

  const tmpfs: Record<string, string> = {};
  for (const mount of input.tmpfs) tmpfs[mount.containerPath] = tmpfsOptions(mount);

  const hostConfig: Docker.HostConfig = {
    // --- isolation -------------------------------------------------------
    ReadonlyRootfs: true,
    CapDrop: ["ALL"],
    CapAdd: [],
    SecurityOpt: [...HARDENED_SECURITY_OPT],
    Privileged: false,
    // IPC and PID namespaces are left at Docker's defaults: private. Naming
    // them here would be noise; sharing them would be the bug.
    NetworkMode: input.networkMode,
    // No port publishing. A container port reaches a human through the preview
    // proxy on a separate origin (D3), never through a host port binding.
    PortBindings: {},
    PublishAllPorts: false,

    // --- resource limits (T3, T10) --------------------------------------
    Memory: Math.floor(input.limits.memoryBytes),
    // Equal to Memory => swap disabled. Omitting this gives unlimited swap,
    // which turns a memory limit into a disk-fill.
    MemorySwap: Math.floor(input.limits.memoryBytes),
    MemorySwappiness: 0,
    NanoCpus: Math.floor(input.limits.cpus * 1e9),
    PidsLimit: Math.floor(input.limits.pids),
    OomKillDisable: false,

    // --- filesystem ------------------------------------------------------
    Tmpfs: tmpfs,
    Init: true,
    // Binds is deliberately absent: bind mounts are declared as `Mounts` by the
    // caller so each one carries an explicit ReadOnly flag.
  };

  if (input.diskQuotaBytes !== null) {
    hostConfig.StorageOpt = { size: `${Math.floor(input.diskQuotaBytes)}` };
  }

  return hostConfig;
}
