/**
 * TerminalRegistry — the set of live terminals, and the only thing that may
 * create one.
 *
 * ============================================================================
 * WHY CREATION LIVES HERE AND NOT ON THE SOCKET
 * ============================================================================
 * A terminal is a shell. If the wire protocol could spawn one, then every
 * authenticated member — and anything that can drive an authenticated member's
 * browser — would have remote code execution inside the workspace container by
 * sending one JSON message. So `terminal.ts` can only ever ATTACH to a
 * terminal that already exists: `subscribe` calls `get()`, never `open()`.
 * `open()` is the orchestrator's entry point, called from an authorized
 * server-side path when a terminal pane is created (SECURITY.md T6 — a member
 * is authenticated, not trusted).
 *
 * Lookup is scoped by workspace, which is what makes the socket's
 * authorization check total: the upgrade proved membership of exactly one
 * workspace, and `get(workspaceId, terminalId)` cannot return a terminal from
 * another one. Cross-workspace access is not a check that can be forgotten
 * later; it is structurally unreachable. Where the operator log wants to
 * distinguish "no such terminal" from "not yours", `existsElsewhere()` answers
 * that — for the LOG ONLY. The wire always says `not-found`, because telling
 * an unauthorized member that a terminal exists is itself a disclosure.
 *
 * ============================================================================
 * WHAT THIS DOES NOT KNOW
 * ============================================================================
 * Nothing here imports dockerode or parses a `backendRef`. The registry is
 * handed a `SandboxLocator` and talks only to `SandboxProvider.spawnPty` — the
 * seam exists so `LocalDockerProvider` can be swapped for an E2B or Fly
 * implementation without this file changing (PLAN.md §4).
 */

import { TERMINAL_ID_RE } from "@atrium/shared";
import type { PtyOpts, PtySize, SandboxHandle, SandboxProvider } from "../sandbox/provider.ts";
import {
  TerminalSession,
  type TerminalLogger,
  type TerminalSessionOptions,
} from "./terminal-session.ts";

/* ==========================================================================
 * The sandbox seam
 * ========================================================================== */

export interface SandboxBinding {
  readonly provider: SandboxProvider;
  readonly handle: SandboxHandle;
}

/**
 * Resolves a workspace to its running sandbox.
 *
 * Implemented by the orchestrator, not here: the registry must not decide when
 * a container is created, hibernated, or restored. Returning null means "this
 * workspace has no running sandbox right now", which becomes
 * `sandbox-not-running` on the wire.
 */
export interface SandboxLocator {
  forWorkspace(workspaceId: string): Promise<SandboxBinding | null>;
}

/* ==========================================================================
 * Errors
 * ========================================================================== */

export type TerminalOpenErrorCode =
  /** The workspace has no running sandbox. */
  | "sandbox-not-running"
  /** `MAX_TERMINALS_PER_WORKSPACE` reached. */
  | "too-many-terminals"
  /** Malformed workspace or terminal id. */
  | "invalid-id"
  /** The provider refused or the pty could not be spawned. */
  | "internal";

/**
 * A string union rather than an enum: `erasableSyntaxOnly` is on and the
 * server runs under `node --experimental-strip-types`.
 */
export class TerminalOpenError extends Error {
  readonly code: TerminalOpenErrorCode;

  constructor(code: TerminalOpenErrorCode, message: string) {
    super(message);
    this.name = "TerminalOpenError";
    this.code = code;
  }
}

/* ==========================================================================
 * Registry
 * ========================================================================== */

export interface TerminalOpenOptions {
  /**
   * argv for the shell. No shell-string parsing anywhere in this stack, per
   * the SandboxProvider contract: the caller decides explicitly.
   */
  readonly command?: readonly string[];
  /** Defaults to the sandbox spec's workdir. */
  readonly cwd?: string;
  /**
   * Extra NON-SECRET environment. SECURITY.md D1/D2/T2: no provider key, no
   * Git token, no database URL, ever — `env` and one `Bash` call are the same
   * thing. This is a server-side call site by design; it is not reachable from
   * the wire protocol, and it must not be made reachable.
   */
  readonly env?: Readonly<Record<string, string>>;
  /** Initial pty size. Superseded by ATTACH_RESIZE_POLICY once viewers attach. */
  readonly size?: PtySize;
  readonly term?: string;
}

export interface TerminalSummary {
  readonly terminalId: string;
  readonly workspaceId: string;
  readonly viewers: number;
  readonly cols: number;
  readonly rows: number;
  readonly scrollbackBytes: number;
  readonly createdAt: string;
}

export interface TerminalRegistryOptions {
  readonly sandboxes: SandboxLocator;
  readonly log: TerminalLogger;
  /** Scrollback ring per session. Default 256 KiB. */
  readonly scrollbackBytes?: number;
  /** Replayed when a client does not name an amount. Default 64 KiB. */
  readonly defaultBacklogBytes?: number;
  /** Transport queue depth that detaches a viewer. Default 4 MiB. */
  readonly viewerHighWaterBytes?: number;
  /** Cap per workspace. Default 8. Bounds container PIDs and server RAM (T10). */
  readonly maxTerminalsPerWorkspace?: number;
  /** Default shell argv when `open()` does not name one. */
  readonly defaultCommand?: readonly string[];
  /**
   * Milliseconds a session may sit with ZERO viewers before it is killed, or
   * null to never reap.
   *
   * The default is null, and that default is a deliberate statement, not an
   * oversight: sessions are server-owned (PLAN.md §6) and a build must survive
   * everybody closing their laptop. The cost is equally deliberate — an
   * unreaped session holds a container process and its scrollback until the
   * orchestrator closes it. Container hibernation (M5) is the real answer;
   * this knob exists so a self-hoster who wants a cheaper policy can have one
   * without editing code.
   */
  readonly idleReapMs?: number | null;
}

const DEFAULT_SCROLLBACK_BYTES = 256 * 1024;
const DEFAULT_BACKLOG_BYTES = 64 * 1024;
const DEFAULT_VIEWER_HIGH_WATER_BYTES = 4 * 1024 * 1024;
const DEFAULT_MAX_TERMINALS_PER_WORKSPACE = 8;
/**
 * `/bin/sh` rather than `/bin/bash`: the workspace base image is still to be
 * chosen and pinned by digest, and a missing interpreter is a terminal that
 * dies the instant it opens. The orchestrator overrides this per image.
 */
const DEFAULT_COMMAND: readonly string[] = ["/bin/sh", "-l"];
const DEFAULT_SIZE: PtySize = { cols: 80, rows: 24 };
const DEFAULT_TERM = "xterm-256color";
const WORKSPACE_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

export class TerminalRegistry {
  readonly #sessions = new Map<string, TerminalSession>();
  /** In-flight opens, so two concurrent calls cannot spawn two shells. */
  readonly #opening = new Map<string, Promise<TerminalSession>>();
  readonly #idleTimers = new Map<string, NodeJS.Timeout>();

  readonly #sandboxes: SandboxLocator;
  readonly #log: TerminalLogger;
  readonly #scrollbackBytes: number;
  readonly #defaultBacklogBytes: number;
  readonly #viewerHighWaterBytes: number;
  readonly #maxPerWorkspace: number;
  readonly #defaultCommand: readonly string[];
  readonly #idleReapMs: number | null;

  constructor(options: TerminalRegistryOptions) {
    this.#sandboxes = options.sandboxes;
    this.#log = options.log;
    this.#scrollbackBytes = options.scrollbackBytes ?? DEFAULT_SCROLLBACK_BYTES;
    this.#defaultBacklogBytes = options.defaultBacklogBytes ?? DEFAULT_BACKLOG_BYTES;
    this.#viewerHighWaterBytes = options.viewerHighWaterBytes ?? DEFAULT_VIEWER_HIGH_WATER_BYTES;
    this.#maxPerWorkspace = options.maxTerminalsPerWorkspace ?? DEFAULT_MAX_TERMINALS_PER_WORKSPACE;
    this.#defaultCommand = options.defaultCommand ?? DEFAULT_COMMAND;
    this.#idleReapMs = options.idleReapMs ?? null;
  }

  get count(): number {
    return this.#sessions.size;
  }

  /**
   * Create the terminal, or return the existing one. ORCHESTRATOR ONLY — never
   * call this from a websocket message handler. Idempotent per
   * (workspace, terminal), including under concurrent calls.
   */
  async open(
    workspaceId: string,
    terminalId: string,
    options: TerminalOpenOptions = {},
  ): Promise<TerminalSession> {
    if (!WORKSPACE_ID_RE.test(workspaceId) || !TERMINAL_ID_RE.test(terminalId)) {
      throw new TerminalOpenError("invalid-id", "workspace and terminal ids must be safe ids");
    }
    const key = sessionKey(workspaceId, terminalId);

    const existing = this.#sessions.get(key);
    if (existing !== undefined && !existing.closed) return existing;

    const inFlight = this.#opening.get(key);
    if (inFlight !== undefined) return inFlight;

    if (this.#countFor(workspaceId) >= this.#maxPerWorkspace) {
      throw new TerminalOpenError(
        "too-many-terminals",
        `workspace already has ${this.#maxPerWorkspace} terminals open`,
      );
    }

    const pending = this.#spawn(workspaceId, terminalId, key, options);
    this.#opening.set(key, pending);
    try {
      return await pending;
    } finally {
      this.#opening.delete(key);
    }
  }

  async #spawn(
    workspaceId: string,
    terminalId: string,
    key: string,
    options: TerminalOpenOptions,
  ): Promise<TerminalSession> {
    const binding = await this.#sandboxes.forWorkspace(workspaceId);
    if (binding === null) {
      throw new TerminalOpenError("sandbox-not-running", "no running sandbox for this workspace");
    }
    if (binding.handle.state !== "running") {
      throw new TerminalOpenError("sandbox-not-running", `sandbox is ${binding.handle.state}`);
    }

    const size = options.size ?? DEFAULT_SIZE;
    // Built field by field because `exactOptionalPropertyTypes` is on: an
    // absent option must not become an explicit `undefined`.
    const ptyOpts: PtyOpts = {
      command: options.command ?? this.#defaultCommand,
      size,
      term: options.term ?? DEFAULT_TERM,
      ...(options.cwd === undefined ? {} : { cwd: options.cwd }),
      ...(options.env === undefined ? {} : { env: options.env }),
      // `user` is deliberately never set: PtyOpts defaults it to the sandbox
      // spec's unprivileged uid, and there is no path here that could ask for
      // root.
    };

    let session: TerminalSession;
    try {
      const pty = await binding.provider.spawnPty(binding.handle, ptyOpts);
      const sessionOptions: TerminalSessionOptions = {
        terminalId,
        workspaceId,
        pty,
        log: this.#log,
        scrollbackBytes: this.#scrollbackBytes,
        defaultBacklogBytes: this.#defaultBacklogBytes,
        viewerHighWaterBytes: this.#viewerHighWaterBytes,
        onClosed: (closed) => this.#onSessionClosed(key, closed),
      };
      session = TerminalSession.start(sessionOptions, size);
    } catch (error: unknown) {
      // The provider's message is for operators. It never reaches the client:
      // the socket layer answers `internal` with a fixed string (T9).
      this.#log.warn(
        {
          workspaceId,
          terminalId,
          err: error instanceof Error ? error.message : "unknown",
        },
        "failed to spawn terminal pty",
      );
      throw new TerminalOpenError("internal", "could not start a shell in the sandbox");
    }

    this.#sessions.set(key, session);
    this.#armIdleReaper(key, session);
    this.#log.info(
      { workspaceId, terminalId, terminals: this.#sessions.size },
      "terminal session opened",
    );
    return session;
  }

  /**
   * The only lookup the wire protocol may use. Workspace-scoped, so a member
   * of one workspace cannot name a terminal in another.
   */
  get(workspaceId: string, terminalId: string): TerminalSession | null {
    const session = this.#sessions.get(sessionKey(workspaceId, terminalId));
    if (session === undefined || session.closed) return null;
    return session;
  }

  /**
   * True when that terminal id exists under a DIFFERENT workspace.
   *
   * For the operator log only — the caller must still answer `not-found` on
   * the wire. Terminal ids are pane ids, unique per workspace but not
   * globally, so this is a genuine question and not a tautology.
   */
  existsElsewhere(workspaceId: string, terminalId: string): boolean {
    for (const session of this.#sessions.values()) {
      if (session.terminalId === terminalId && session.workspaceId !== workspaceId) return true;
    }
    return false;
  }

  list(workspaceId: string): readonly TerminalSummary[] {
    const out: TerminalSummary[] = [];
    for (const session of this.#sessions.values()) {
      if (session.workspaceId !== workspaceId) continue;
      out.push({
        terminalId: session.terminalId,
        workspaceId: session.workspaceId,
        viewers: session.viewerCount,
        cols: session.size.cols,
        rows: session.size.rows,
        scrollbackBytes: session.scrollbackBytes,
        createdAt: session.createdAt,
      });
    }
    return out;
  }

  /** Kill one terminal. Idempotent. */
  async close(workspaceId: string, terminalId: string): Promise<void> {
    const key = sessionKey(workspaceId, terminalId);
    const session = this.#sessions.get(key);
    if (session === undefined) return;
    await session.close();
  }

  /** Kill every terminal in a workspace, e.g. when its sandbox is destroyed. */
  async closeWorkspace(workspaceId: string): Promise<void> {
    const doomed = [...this.#sessions.values()].filter((s) => s.workspaceId === workspaceId);
    await Promise.all(doomed.map((s) => s.close()));
  }

  /** Shutdown. */
  async closeAll(): Promise<void> {
    const doomed = [...this.#sessions.values()];
    for (const timer of this.#idleTimers.values()) clearTimeout(timer);
    this.#idleTimers.clear();
    await Promise.all(doomed.map((s) => s.close()));
    this.#sessions.clear();
  }

  /**
   * Called by the socket layer after a viewer detaches, so the idle reaper (if
   * one is configured) can start counting. A no-op when `idleReapMs` is null,
   * which is the default.
   */
  noteViewerChange(session: TerminalSession): void {
    this.#armIdleReaper(sessionKey(session.workspaceId, session.terminalId), session);
  }

  #armIdleReaper(key: string, session: TerminalSession): void {
    const existing = this.#idleTimers.get(key);
    if (existing !== undefined) {
      clearTimeout(existing);
      this.#idleTimers.delete(key);
    }
    if (this.#idleReapMs === null || session.closed || session.viewerCount > 0) return;

    const timer = setTimeout(() => {
      this.#idleTimers.delete(key);
      if (session.closed || session.viewerCount > 0) return;
      this.#log.info(
        { workspaceId: session.workspaceId, terminalId: session.terminalId },
        "reaping idle terminal session",
      );
      void session.close();
    }, this.#idleReapMs);
    timer.unref();
    this.#idleTimers.set(key, timer);
  }

  #onSessionClosed(key: string, session: TerminalSession): void {
    if (this.#sessions.get(key) === session) this.#sessions.delete(key);
    const timer = this.#idleTimers.get(key);
    if (timer !== undefined) {
      clearTimeout(timer);
      this.#idleTimers.delete(key);
    }
  }

  #countFor(workspaceId: string): number {
    let n = 0;
    for (const session of this.#sessions.values()) {
      if (session.workspaceId === workspaceId) n += 1;
    }
    return n;
  }
}

/** NUL separator: it cannot occur in either id, so keys cannot collide. */
function sessionKey(workspaceId: string, terminalId: string): string {
  return `${workspaceId}\u0000${terminalId}`;
}
