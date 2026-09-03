/**
 * WorkspaceSandboxes — the orchestrator seam between a workspace and its
 * container.
 *
 * Three files needed each other and none of them could import the others:
 * `LocalDockerProvider` creates containers but is told nothing about
 * workspaces; `TerminalRegistry` needs a `SandboxLocator` and refuses to own
 * sandbox lifecycle; `cloneRepository` needs a Docker handle and an empty
 * destination. This is the piece that owns all three decisions:
 *
 *   1. WHERE A WORKSPACE'S FILES LIVE. `RepoMount.hostPath` is derived from the
 *      configured workspaces directory plus the workspace id, and from nothing
 *      else. Never a request parameter, never a path from the CRDT — that is
 *      SECURITY.md T5's rule for the preview proxy and it applies identically
 *      to a bind mount, which is strictly more dangerous.
 *   2. WHEN A CONTAINER EXISTS. `ensure()` creates one; `forWorkspace()` (the
 *      `SandboxLocator` the terminal registry sees) only ever LOOKS ONE UP. The
 *      registry therefore cannot create a container, and the wire protocol
 *      cannot reach `ensure()` — a terminal is opened by an authorized HTTP
 *      route in index.ts that re-checks membership, never by a socket message.
 *   3. WHAT IMAGE. Pinned by digest (T12). `ATRIUM_WORKSPACE_IMAGE_DIGEST` is
 *      the real pin; without it the locally built tag is resolved to its image
 *      id ONCE and that id is used for the rest of the process, with a warning
 *      in the log saying the pin came from a mutable tag.
 *
 * This file and `clone.ts` are the only places outside `local-docker.ts` that
 * touch `dockerode`, and they do it to hand ONE engine connection to both the
 * provider and the clone helper. Nothing above `SandboxProvider` gets a Docker
 * object.
 */

import { mkdir, readdir } from "node:fs/promises";
import { join } from "node:path";
import Docker from "dockerode";

import type {
  SandboxHandle,
  SandboxImageRef,
  SandboxProvider,
  SandboxSpec,
} from "./provider.ts";
import type { SandboxBinding, SandboxLocator } from "../realtime/terminal-registry.ts";
import { cloneRepository } from "./clone.ts";
import { SandboxError } from "./errors.ts";
import { LocalDockerProvider } from "./local-docker.ts";
import { workspaceSpec } from "./spec.ts";

const WORKSPACE_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

export interface OrchestratorLogger {
  info(obj: Record<string, unknown>, msg: string): void;
  warn(obj: Record<string, unknown>, msg: string): void;
}

export interface WorkspaceSandboxesOptions {
  readonly log: OrchestratorLogger;
  /** Named pipe or unix socket for the engine. From `config.dockerSocket`. */
  readonly dockerSocket: string;
  /** Host root holding one checkout per workspace. Server-resolved (T5). */
  readonly workspacesDir: string;
  readonly image: {
    readonly repository: string;
    readonly tag: string;
    /** Content pin, or null to resolve the local tag's image id once. */
    readonly digest: string | null;
  };
  /** Public HTTPS repo cloned into an empty checkout, or null for an empty dir. */
  readonly repoUrl: string | null;
}

export class WorkspaceSandboxes implements SandboxLocator {
  readonly #docker: Docker;
  readonly #provider: LocalDockerProvider;
  readonly #options: WorkspaceSandboxesOptions;
  /** Sandboxes this process created or adopted, by workspace id. */
  readonly #bindings = new Map<string, SandboxBinding>();
  /** In-flight `ensure` calls, so two panes opening at once share one container. */
  readonly #pending = new Map<string, Promise<SandboxBinding>>();
  /** Sandboxes whose leftover ptys this process has already reaped. */
  readonly #reaped = new Set<string>();
  #imageRef: SandboxImageRef | null = null;

  constructor(options: WorkspaceSandboxesOptions) {
    this.#options = options;
    this.#docker = new Docker({ socketPath: options.dockerSocket });
    this.#provider = new LocalDockerProvider({ docker: this.#docker });
    if (options.image.digest !== null) {
      this.#imageRef = {
        repository: options.image.repository,
        tag: options.image.tag,
        digest: options.image.digest,
      };
    }
  }

  get provider(): SandboxProvider {
    return this.#provider;
  }

  /** Sandboxes this process knows about. For `/api/health`, not for policy. */
  get count(): number {
    return this.#bindings.size;
  }

  /** Every `unenforced` control across live sandboxes, deduplicated (T3). */
  get unenforced(): readonly string[] {
    const out = new Set<string>();
    for (const binding of this.#bindings.values()) {
      for (const control of binding.handle.unenforced) out.add(control);
    }
    return [...out];
  }

  /**
   * `SandboxLocator`: look up, never create. Returning null is how the terminal
   * registry learns to answer `sandbox-not-running`.
   */
  async forWorkspace(workspaceId: string): Promise<SandboxBinding | null> {
    const known = this.#bindings.get(workspaceId);
    if (known === undefined) return null;
    // Re-read from the engine: the container may have been OOM-killed or
    // removed by an operator since we last looked.
    const fresh = await this.#provider.inspect(known.handle.id).catch(() => null);
    if (fresh === null) {
      this.#bindings.delete(workspaceId);
      return null;
    }
    const binding: SandboxBinding = { provider: this.#provider, handle: fresh };
    this.#bindings.set(workspaceId, binding);
    return binding;
  }

  /**
   * Create (or adopt) the workspace's container. ORCHESTRATOR ONLY: this is
   * reachable from an authorized HTTP route, never from a websocket message.
   * Idempotent per workspace, including under concurrent callers.
   */
  async ensure(workspaceId: string): Promise<SandboxBinding> {
    if (!WORKSPACE_ID_RE.test(workspaceId)) {
      throw new SandboxError("invalid-spec", "workspace id is not a safe id");
    }
    const live = await this.forWorkspace(workspaceId);
    if (live !== null && live.handle.state === "running") {
      await this.#reapOrphanedPtys(live);
      return live;
    }

    const inFlight = this.#pending.get(workspaceId);
    if (inFlight !== undefined) return inFlight;

    const pending = this.#create(workspaceId).then(async (binding) => {
      await this.#reapOrphanedPtys(binding);
      return binding;
    });
    this.#pending.set(workspaceId, pending);
    try {
      return await pending;
    } finally {
      this.#pending.delete(workspaceId);
    }
  }

  /**
   * Kill shells left behind in an ADOPTED container by a previous run.
   *
   * Docker has no "kill exec" API, so a pty only dies when the process that
   * spawned it kills the pid the wrapper recorded (see `DockerPty.#signal`). A
   * graceful shutdown does exactly that via `registry.closeAll()`, but a
   * `--watch` restart or a crash does not — and the container outlives the
   * server process by design, so those shells become unreachable: no stream can
   * ever reattach to them, and they hold PID-limit slots until the container is
   * destroyed. Two or three restarts is nothing; a day of them is a workspace
   * that cannot fork.
   *
   * Runs ONCE per sandbox per process, before this process has spawned any pty
   * of its own — so every pid file it finds is stale by construction. Assumes
   * one Atrium process per workspace, which v1 already assumes everywhere else.
   */
  async #reapOrphanedPtys(binding: SandboxBinding): Promise<void> {
    if (this.#reaped.has(binding.handle.id)) return;
    this.#reaped.add(binding.handle.id);
    const scratch = binding.handle.spec.tmpfs.find((t) => t.containerPath === "/tmp");
    if (scratch === undefined) return;

    try {
      const result = await binding.provider.exec(
        binding.handle,
        [
          "/bin/sh",
          "-c",
          // $0 is the scratch directory; nothing is spliced into the script.
          'n=0; for f in "$0"/atrium-pty-*.pid; do [ -f "$f" ] || continue; ' +
            'p=$(cat "$f" 2>/dev/null); [ -n "$p" ] && kill -KILL "$p" 2>/dev/null; ' +
            'rm -f "$f"; n=$((n+1)); done; echo "$n"',
          scratch.containerPath,
        ],
        { timeoutMs: 10_000, maxOutputBytes: 1024 },
      );
      const reaped = Number.parseInt(Buffer.from(result.stdout).toString("utf8").trim(), 10);
      if (Number.isFinite(reaped) && reaped > 0) {
        this.#options.log.info(
          { workspaceId: binding.handle.workspaceId, reaped },
          "reaped orphaned pty processes from a previous run",
        );
      }
    } catch (error: unknown) {
      this.#options.log.warn(
        {
          workspaceId: binding.handle.workspaceId,
          err: error instanceof Error ? error.message : "unknown",
        },
        "could not reap orphaned ptys; a previous run's shells may still hold PID slots",
      );
    }
  }

  async #create(workspaceId: string): Promise<SandboxBinding> {
    const image = await this.#image();
    // The one place a host path for a workspace is ever built (T5).
    const hostRepoPath = join(this.#options.workspacesDir, workspaceId);
    await mkdir(hostRepoPath, { recursive: true });

    const repoUrl = this.#options.repoUrl;
    if (repoUrl !== null && (await readdir(hostRepoPath)).length === 0) {
      // Runs in a SEPARATE throwaway container with unfiltered egress, because
      // the workspace container deliberately has no route off-host (D4). See
      // clone.ts for what bounds that.
      this.#options.log.info({ workspaceId }, "cloning workspace repository");
      const outcome = await cloneRepository(
        { repoUrl, hostPath: hostRepoPath, image },
        { docker: this.#docker },
      );
      if (!outcome.ok) {
        this.#options.log.warn(
          { workspaceId, exitCode: outcome.exitCode, timedOut: outcome.timedOut },
          "repository clone failed; starting the sandbox on an empty checkout",
        );
      }
    }

    const spec: SandboxSpec = workspaceSpec({
      image,
      hostRepoPath,
      labels: { workspace: workspaceId },
    });
    const handle: SandboxHandle = await this.#provider.create(workspaceId, spec);

    this.#options.log.info(
      {
        workspaceId,
        sandboxId: handle.id,
        state: handle.state,
        unenforced: handle.unenforced,
      },
      "workspace sandbox ready",
    );

    const binding: SandboxBinding = { provider: this.#provider, handle };
    this.#bindings.set(workspaceId, binding);
    return binding;
  }

  /**
   * Resolve the image reference once.
   *
   * With no configured digest this inspects the local tag and pins the process
   * to the image ID it finds — content-addressed, but derived from a mutable
   * tag, which is a real (if small) T12 gap and is therefore logged as one.
   */
  async #image(): Promise<SandboxImageRef> {
    if (this.#imageRef !== null) return this.#imageRef;
    const { repository, tag } = this.#options.image;
    let id: unknown;
    try {
      const info = await this.#docker.getImage(`${repository}:${tag}`).inspect();
      id = info.Id;
    } catch {
      throw new SandboxError(
        "invalid-spec",
        `workspace image ${repository}:${tag} is not present. Build it with ` +
          `\`docker build -f docker/workspace.Dockerfile -t ${repository}:${tag} .\` ` +
          `and pin it with ATRIUM_WORKSPACE_IMAGE_DIGEST.`,
      );
    }
    if (typeof id !== "string" || !/^sha256:[0-9a-f]{64}$/.test(id)) {
      throw new SandboxError("internal", "engine returned an unusable image id");
    }
    this.#options.log.warn(
      { repository, tag, digest: id },
      "workspace image pinned from a mutable tag; set ATRIUM_WORKSPACE_IMAGE_DIGEST to pin it properly (T12)",
    );
    this.#imageRef = { repository, tag, digest: id };
    return this.#imageRef;
  }

  async health(): Promise<{ reachable: boolean; version?: string; detail?: string }> {
    return this.#provider.health();
  }

  /**
   * Containers this provider owns, running or not — for operator cleanup of
   * orphans left by a crashed process.
   */
  async listManaged(): Promise<readonly SandboxHandle[]> {
    return this.#provider.listManaged();
  }
}
