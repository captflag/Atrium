/**
 * AgentRegistry — the set of live agent sessions, and the only thing that may
 * create one.
 *
 * ============================================================================
 * WHY CREATION LIVES HERE AND NOT ON THE SOCKET
 * ============================================================================
 * An agent session runs model-generated commands inside the workspace
 * container. Starting one is code execution (SECURITY.md T8), exactly like
 * opening a terminal, and a missing check on a path that can start one is
 * remote code execution for every member. So `agent.ts` can only ever ATTACH:
 * `subscribe` calls `get()`, never `open()`. `open()` is reached from the
 * authorized `POST /api/workspaces/:id/agents` route, which repeats
 * authenticate + membership — the same split M2 made for terminals, for the
 * same reason.
 *
 * Lookup is scoped by workspace, which is what makes the socket's authorization
 * total: the upgrade proved membership of exactly one workspace, and
 * `get(workspaceId, agentId)` cannot return a session from another one.
 * Cross-workspace access is not a check that can be forgotten later; it is
 * structurally unreachable. `existsElsewhere()` answers the distinction FOR THE
 * OPERATOR LOG ONLY — the wire always says `not-found`.
 *
 * ============================================================================
 * WHAT THIS DOES NOT KNOW
 * ============================================================================
 * Nothing here imports the Claude Agent SDK, and nothing here knows what a
 * container id is. The registry is handed an `AgentProvider` and a
 * `SandboxLocator` and talks to neither Docker nor a harness. That is the seam
 * (PLAN.md §4): swapping to a second provider is a different object passed to
 * this constructor.
 *
 * ============================================================================
 * THE CREDENTIAL BOUNDARY (SECURITY.md D1, T2)
 * ============================================================================
 * This file assembles the `AgentSpec`, so it is the file that hands over the
 * broker binding. Three rules it follows and that a reviewer should check:
 *
 *   1. The binding is minted per session by `BrokerBindingSource`, which lives
 *      outside this file. There is no field on any option here for a provider
 *      credential, and there is no way to add one without editing this comment.
 *   2. The binding is never logged, never put in a summary, never returned from
 *      an HTTP route, and never placed in an `AgentEvent` (T9).
 *   3. `repoRoot` comes from the sandbox spec's own workdir — server-resolved,
 *      never from a request parameter (T5), exactly as `WorkspaceSandboxes`
 *      already resolves a host path.
 *
 * Persists nothing: durability is M5 (PLAN.md §6). Sessions and their
 * transcripts live in this process and are lost on restart.
 */

import {
  AGENT_COLOURS,
  AGENT_ID_RE,
  AGENT_NAME_RE,
  MAX_AGENT_AVATAR_LENGTH,
  isValidAgentIdentity,
  type AgentColour,
  type AgentIdentity,
} from "@atrium/shared";
import type {
  AgentBrokerBinding,
  AgentLimits,
  AgentModelPolicy,
  AgentProvider,
  AgentSessionState,
  AgentSpec,
  AgentToolGate,
  AgentToolPolicy,
} from "../agent/provider.ts";
import { AgentSession, readErrorCode, type AgentLogger } from "./agent-session.ts";
import type { SandboxLocator } from "./terminal-registry.ts";

/* ==========================================================================
 * The broker seam
 * ========================================================================== */

/**
 * Mints the two — and only two — values that may reach the workspace container
 * (SECURITY.md D1): the broker's origin as reachable FROM THE CONTAINER, and a
 * short-lived workspace-scoped capability token.
 *
 * Implemented outside the realtime layer, because minting a capability is an
 * orchestration decision and this file must not be able to invent one. A
 * binding is handed straight to `AgentProvider.start()` and is touched by
 * nothing else on the way — in particular it is never logged, never summarised,
 * and never serialized to a client (T9).
 */
export interface BrokerBindingSource {
  mint(workspaceId: string, sessionId: string): Promise<AgentBrokerBinding>;
}

/* ==========================================================================
 * Errors
 * ========================================================================== */

export type AgentOpenErrorCode =
  /** Malformed workspace id, agent id, or name. */
  | "invalid-id"
  /** Missing or oversized task. */
  | "invalid-task"
  /** `maxAgentsPerWorkspace` reached (SECURITY.md T10). */
  | "too-many-agents"
  /** The workspace has no running sandbox. */
  | "sandbox-not-running"
  /** The harness binary is missing or would not launch inside the container. */
  | "harness-unavailable"
  /** The broker or the model provider could not be reached. */
  | "upstream-unavailable"
  /** The broker refused on budget (T10). */
  | "budget-exhausted"
  /** Anything else. The detail goes to the operator log, never to a client. */
  | "internal";

/** A class, not an enum: `erasableSyntaxOnly` is on. Mirrors `TerminalOpenError`. */
export class AgentOpenError extends Error {
  readonly code: AgentOpenErrorCode;

  constructor(code: AgentOpenErrorCode, message: string) {
    super(message);
    this.name = "AgentOpenError";
    this.code = code;
  }
}

/* ==========================================================================
 * Registry
 * ========================================================================== */

export interface AgentOpenOptions {
  /** The human's task, verbatim. Never logged (T9). */
  readonly task: string;
  /**
   * Preferred display name. Validated against `AGENT_NAME_RE` and rejected if
   * it does not match — a name reaches every teammate's presence list, so a
   * client does not get to put arbitrary text there (see `AgentIdentity`).
   * Omitted means the registry assigns one.
   */
  readonly name?: string;
  /** Overrides the registry-wide framing. Helps, is NOT a control (T1). */
  readonly systemPromptAppend?: string;
}

export interface AgentSummary {
  readonly agentId: string;
  readonly workspaceId: string;
  readonly identity: AgentIdentity;
  readonly model: string;
  readonly state: AgentSessionState;
  readonly viewers: number;
  readonly lastSeq: number;
  readonly ended: boolean;
  readonly createdAt: string;
}

export interface AgentRegistryOptions {
  /** Look up a workspace's sandbox. The registry may NOT create one. */
  readonly sandboxes: SandboxLocator;
  readonly provider: AgentProvider;
  readonly broker: BrokerBindingSource;
  readonly log: AgentLogger;
  /**
   * Model per role, resolved from workspace configuration by the caller.
   *
   * Required, and deliberately not defaulted: PLAN.md §10.0 decided coding
   * agents run the strong model and mechanical background work runs the cheap
   * one, and "never hardcode one model everywhere" is only enforceable if this
   * file has no model id in it to fall back to.
   */
  readonly models: {
    readonly coding: AgentModelPolicy;
    readonly background?: AgentModelPolicy;
  };
  /**
   * Per-session ceilings. A UX affordance and a second line of defence — the
   * authoritative token budget and spend cap are enforced at the broker,
   * outside the container (SECURITY.md T10).
   */
  readonly limits: AgentLimits;
  /** Tool preferences passed to the harness. Advisory, never a boundary (D5). */
  readonly tools: AgentToolPolicy;
  /**
   * Appended to the harness's system prompt. Helps and is NOT a control
   * (SECURITY.md T1): a prompt-injected agent is not persuaded by a paragraph.
   */
  readonly systemPromptAppend?: string;
  /**
   * Advisory claim gate (PLAN.md §5 layer 1). Absent in M3b; M4 supplies one.
   * Passed through untouched, including to a provider that reports
   * `supportsToolGate: false` — the gate is advisory, so an unsupported gate is
   * a missing affordance, not a failed start.
   */
  readonly gate?: AgentToolGate;
  /** Transcript ceiling in events per session. Default 2000. */
  readonly transcriptEvents?: number;
  /** Transcript ceiling in approximate bytes per session. Default 2 MiB. */
  readonly transcriptBytes?: number;
  /** Transport queue depth that detaches a viewer. Default 4 MiB. */
  readonly viewerHighWaterBytes?: number;
  /**
   * Concurrent RUNNING agents per workspace. Default 4. Bounds container PIDs,
   * server RAM, and the rate at which one workspace can spend (T10).
   */
  readonly maxAgentsPerWorkspace?: number;
  /**
   * How long an ENDED session is kept so a pane can still read its transcript,
   * or null to keep it until it is deleted explicitly. Default 15 minutes.
   *
   * The wire protocol says a stopped session's channel stays valid so late
   * replay still works; that is only true while something still holds the
   * transcript, and holding it forever is a leak.
   */
  readonly endedLingerMs?: number | null;
  /**
   * Milliseconds a RUNNING session may sit with zero viewers before it is
   * stopped, or null to never reap. Default null, and that default is a
   * statement: sessions are server-owned (PLAN.md §6) and an agent must keep
   * working after everyone closes their laptop. The cost is equally deliberate
   * — an unwatched agent is still spending. The knob exists so a self-hoster
   * can choose a cheaper policy without editing code.
   */
  readonly idleReapMs?: number | null;
  /**
   * Display-name roster. Names and avatars are decoration only in the sense
   * that they are not security-relevant; they are load-bearing for the product,
   * because "agent-2 is holding src/auth/**" only reads as a colleague if
   * agent-2 is a someone (PLAN.md §10 decision 3).
   */
  readonly names?: readonly string[];
}

const DEFAULT_TRANSCRIPT_EVENTS = 2000;
const DEFAULT_TRANSCRIPT_BYTES = 2 * 1024 * 1024;
const DEFAULT_VIEWER_HIGH_WATER_BYTES = 4 * 1024 * 1024;
const DEFAULT_MAX_AGENTS_PER_WORKSPACE = 4;
const DEFAULT_ENDED_LINGER_MS = 15 * 60_000;
/** Ended sessions retained per workspace before the oldest is dropped early. */
const ENDED_RETENTION_FACTOR = 2;
const WORKSPACE_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
/** Single words, letters only, so initials are always a valid avatar. */
const DEFAULT_NAMES: readonly string[] = [
  "Wren",
  "Juniper",
  "Cove",
  "Marlow",
  "Ember",
  "Sable",
  "Rowan",
  "Fable",
];

/** Task ceiling. Same bound the wire puts on a follow-up prompt. */
const MAX_TASK_CHARS = 32 * 1024;

export class AgentRegistry {
  readonly #sessions = new Map<string, AgentSession>();
  /** In-flight starts, so two concurrent calls cannot spawn two harnesses. */
  readonly #starting = new Map<string, Promise<AgentSession>>();
  readonly #lingerTimers = new Map<string, NodeJS.Timeout>();
  readonly #idleTimers = new Map<string, NodeJS.Timeout>();

  readonly #options: AgentRegistryOptions;
  readonly #transcriptEvents: number;
  readonly #transcriptBytes: number;
  readonly #viewerHighWaterBytes: number;
  readonly #maxPerWorkspace: number;
  readonly #endedLingerMs: number | null;
  readonly #idleReapMs: number | null;
  readonly #names: readonly string[];

  constructor(options: AgentRegistryOptions) {
    this.#options = options;
    this.#transcriptEvents = options.transcriptEvents ?? DEFAULT_TRANSCRIPT_EVENTS;
    this.#transcriptBytes = options.transcriptBytes ?? DEFAULT_TRANSCRIPT_BYTES;
    this.#viewerHighWaterBytes = options.viewerHighWaterBytes ?? DEFAULT_VIEWER_HIGH_WATER_BYTES;
    this.#maxPerWorkspace = options.maxAgentsPerWorkspace ?? DEFAULT_MAX_AGENTS_PER_WORKSPACE;
    this.#endedLingerMs = options.endedLingerMs === undefined ? DEFAULT_ENDED_LINGER_MS : options.endedLingerMs;
    this.#idleReapMs = options.idleReapMs ?? null;
    const names = options.names ?? DEFAULT_NAMES;
    this.#names = names.filter((n) => AGENT_NAME_RE.test(n));
    if (this.#names.length === 0) {
      throw new Error("agent registry needs at least one name matching AGENT_NAME_RE");
    }
  }

  /** Sessions tracked, running and ended. For `/api/health`, not for policy. */
  get count(): number {
    return this.#sessions.size;
  }

  /** Sessions whose harness is still alive. */
  get runningCount(): number {
    let n = 0;
    for (const session of this.#sessions.values()) if (!session.ended) n += 1;
    return n;
  }

  get providerName(): string {
    return this.#options.provider.name;
  }

  /**
   * Start the agent, or return the existing one. AUTHORIZED CALLERS ONLY —
   * never call this from a websocket message handler.
   *
   * Idempotent per (workspace, agent), including under concurrent calls and
   * including when the existing session has already ENDED: a pane reloading
   * must not silently start a second agent and spend a second task's worth of
   * tokens. Restarting is delete-then-create, which is a deliberate act.
   */
  async open(
    workspaceId: string,
    agentId: string,
    options: AgentOpenOptions,
  ): Promise<AgentSession> {
    if (!WORKSPACE_ID_RE.test(workspaceId) || !AGENT_ID_RE.test(agentId)) {
      throw new AgentOpenError("invalid-id", "workspace and agent ids must be safe ids");
    }
    if (options.name !== undefined && !AGENT_NAME_RE.test(options.name)) {
      throw new AgentOpenError("invalid-id", "agent name must match AGENT_NAME_RE");
    }
    if (typeof options.task !== "string" || options.task.trim().length === 0) {
      throw new AgentOpenError("invalid-task", "task must be a non-empty string");
    }
    if (options.task.length > MAX_TASK_CHARS) {
      throw new AgentOpenError("invalid-task", "task is too large");
    }

    const key = sessionKey(workspaceId, agentId);
    const existing = this.#sessions.get(key);
    if (existing !== undefined && !existing.disposed) return existing;

    const inFlight = this.#starting.get(key);
    if (inFlight !== undefined) return inFlight;

    if (this.#runningFor(workspaceId) >= this.#maxPerWorkspace) {
      throw new AgentOpenError(
        "too-many-agents",
        `workspace already has ${this.#maxPerWorkspace} agents running`,
      );
    }
    this.#trimEnded(workspaceId);

    const pending = this.#start(workspaceId, agentId, key, options);
    this.#starting.set(key, pending);
    try {
      return await pending;
    } finally {
      this.#starting.delete(key);
    }
  }

  async #start(
    workspaceId: string,
    agentId: string,
    key: string,
    options: AgentOpenOptions,
  ): Promise<AgentSession> {
    const binding = await this.#options.sandboxes.forWorkspace(workspaceId);
    if (binding === null) {
      throw new AgentOpenError("sandbox-not-running", "no running sandbox for this workspace");
    }
    if (binding.handle.state !== "running") {
      throw new AgentOpenError("sandbox-not-running", `sandbox is ${binding.handle.state}`);
    }

    // The ONE place a broker binding is obtained, and the last place it is
    // readable before it disappears into the provider (D1).
    let broker: AgentBrokerBinding;
    try {
      broker = await this.#options.broker.mint(workspaceId, agentId);
    } catch (error: unknown) {
      this.#options.log.warn(
        { workspaceId, agentId, err: error instanceof Error ? error.message : "unknown" },
        "could not mint a broker capability for an agent session",
      );
      throw new AgentOpenError("upstream-unavailable", "broker capability unavailable");
    }
    if (broker.expiresAt.getTime() <= Date.now()) {
      throw new AgentOpenError("internal", "broker capability expired before it was used");
    }

    const identity = this.#mintIdentity(workspaceId, agentId, options.name);
    const systemPromptAppend = options.systemPromptAppend ?? this.#options.systemPromptAppend;
    const gate = this.#options.gate;
    const background = this.#options.models.background;

    const spec: AgentSpec = {
      sessionId: agentId,
      workspaceId,
      identity,
      task: options.task,
      // Server-resolved from the sandbox spec. Never a request parameter (T5).
      repoRoot: binding.handle.spec.workdir,
      models: {
        coding: this.#options.models.coding,
        ...(background === undefined ? {} : { background }),
      },
      limits: this.#options.limits,
      tools: this.#options.tools,
      broker,
      ...(systemPromptAppend === undefined ? {} : { systemPromptAppend }),
      ...(gate === undefined ? {} : { gate }),
    };

    let session: AgentSession;
    try {
      const handle = await this.#options.provider.start(spec);
      session = AgentSession.start({
        agentId,
        workspaceId,
        provider: this.#options.provider,
        handle,
        log: this.#options.log,
        transcriptEvents: this.#transcriptEvents,
        transcriptBytes: this.#transcriptBytes,
        viewerHighWaterBytes: this.#viewerHighWaterBytes,
        onEnded: (ended) => this.#onSessionEnded(key, ended),
      });
    } catch (error: unknown) {
      // The provider's message is written for an operator and may quote a path
      // or a harness error (T9). It is logged and never returned to a client.
      this.#options.log.warn(
        { workspaceId, agentId, err: error instanceof Error ? error.message : "unknown" },
        "failed to start agent session",
      );
      throw new AgentOpenError(openCodeFor(error), "could not start an agent in the sandbox");
    }

    this.#sessions.set(key, session);
    this.#armIdleReaper(key, session);
    this.#options.log.info(
      {
        workspaceId,
        agentId,
        model: session.model,
        harness: this.#options.provider.name,
        agents: this.#sessions.size,
        // Neither the task nor the broker binding appears here (T9, D1).
      },
      "agent session started",
    );
    return session;
  }

  /**
   * The only lookup the wire protocol may use. Workspace-scoped, so a member of
   * one workspace cannot name a session in another.
   *
   * Ended sessions are returned deliberately: their channel stays valid so a
   * pane can still show a finished transcript. Disposed ones are gone.
   */
  get(workspaceId: string, agentId: string): AgentSession | null {
    const session = this.#sessions.get(sessionKey(workspaceId, agentId));
    if (session === undefined || session.disposed) return null;
    return session;
  }

  /**
   * True when that agent id exists under a DIFFERENT workspace.
   *
   * FOR THE OPERATOR LOG ONLY — the caller must still answer `not-found` on the
   * wire. Agent ids are pane-scoped, unique per workspace but not globally, so
   * this is a genuine question.
   */
  existsElsewhere(workspaceId: string, agentId: string): boolean {
    for (const session of this.#sessions.values()) {
      if (session.agentId === agentId && session.workspaceId !== workspaceId) return true;
    }
    return false;
  }

  list(workspaceId: string): readonly AgentSummary[] {
    const out: AgentSummary[] = [];
    for (const session of this.#sessions.values()) {
      if (session.workspaceId !== workspaceId || session.disposed) continue;
      out.push(summarize(session));
    }
    return out;
  }

  /** End one session and forget it. Idempotent. */
  async close(workspaceId: string, agentId: string): Promise<void> {
    const key = sessionKey(workspaceId, agentId);
    const session = this.#sessions.get(key);
    if (session === undefined) return;
    this.#clearTimers(key);
    this.#sessions.delete(key);
    await session.dispose();
  }

  /** End every session in a workspace, e.g. when its sandbox is destroyed. */
  async closeWorkspace(workspaceId: string): Promise<void> {
    const doomed = [...this.#sessions.entries()].filter(
      ([, s]) => s.workspaceId === workspaceId,
    );
    for (const [key] of doomed) {
      this.#clearTimers(key);
      this.#sessions.delete(key);
    }
    await Promise.all(doomed.map(([, s]) => s.dispose()));
  }

  /**
   * Shutdown.
   *
   * Unlike workspace CONTAINERS — which are left running and re-adopted on the
   * next boot — an agent session cannot survive this process: its provider run
   * lives here. Stopping it is what keeps a harness from being orphaned inside
   * the container with nothing able to reach it (the M2 pty lesson: Docker has
   * no "kill exec").
   */
  async closeAll(): Promise<void> {
    const doomed = [...this.#sessions.values()];
    for (const key of [...this.#sessions.keys()]) this.#clearTimers(key);
    this.#sessions.clear();
    await Promise.all(doomed.map((s) => s.dispose()));
  }

  /** Called by the transport after a viewer detaches, so the reaper can count. */
  noteViewerChange(session: AgentSession): void {
    this.#armIdleReaper(sessionKey(session.workspaceId, session.agentId), session);
  }

  // --- internals ---------------------------------------------------------

  /**
   * Assign name, colour and avatar. SERVER-SIDE, always.
   *
   * An agent that could choose its own colour could choose a CSS string, and
   * one that could choose its own name could impersonate a human in the
   * presence list (`AgentIdentity` in @atrium/shared says so at length). The
   * result is validated against the shared validator before use, so a bug in
   * this function cannot put an invalid identity on the wire.
   */
  #mintIdentity(workspaceId: string, agentId: string, preferred: string | undefined): AgentIdentity {
    const usedNames = new Set<string>();
    const usedColours = new Set<string>();
    for (const session of this.#sessions.values()) {
      if (session.workspaceId !== workspaceId || session.disposed) continue;
      usedNames.add(session.identity.name);
      usedColours.add(session.identity.colour);
    }

    const name =
      preferred !== undefined
        ? preferred
        : (this.#names.find((n) => !usedNames.has(n)) ??
          `${this.#names[0] as string} ${usedNames.size + 1}`);
    const colour: AgentColour =
      AGENT_COLOURS.find((c) => !usedColours.has(c)) ??
      (AGENT_COLOURS[usedColours.size % AGENT_COLOURS.length] as AgentColour);

    const identity: AgentIdentity = { id: agentId, name, colour, avatar: initialsOf(name) };
    if (!isValidAgentIdentity(identity)) {
      throw new AgentOpenError("invalid-id", "could not assign a valid agent identity");
    }
    return identity;
  }

  #runningFor(workspaceId: string): number {
    let n = 0;
    for (const session of this.#sessions.values()) {
      if (session.workspaceId === workspaceId && !session.ended && !session.disposed) n += 1;
    }
    return n;
  }

  /**
   * Drop the oldest ended sessions when a workspace is holding too many.
   *
   * The linger timer is the normal path; this is the bound that stops a
   * workspace whose panes churn from accumulating transcripts faster than the
   * timer retires them.
   */
  #trimEnded(workspaceId: string): void {
    const ended = [...this.#sessions.entries()]
      .filter(([, s]) => s.workspaceId === workspaceId && s.ended && !s.disposed)
      .sort((a, b) => a[1].createdAt.localeCompare(b[1].createdAt));
    const keep = this.#maxPerWorkspace * ENDED_RETENTION_FACTOR;
    for (let i = 0; i < ended.length - keep; i += 1) {
      const entry = ended[i];
      if (entry === undefined) continue;
      const [key, session] = entry;
      this.#clearTimers(key);
      this.#sessions.delete(key);
      void session.dispose();
    }
  }

  #onSessionEnded(key: string, session: AgentSession): void {
    if (this.#sessions.get(key) !== session) return;
    this.#clearTimers(key);
    if (this.#endedLingerMs === null) return;

    const timer = setTimeout(() => {
      this.#lingerTimers.delete(key);
      if (this.#sessions.get(key) !== session) return;
      this.#sessions.delete(key);
      this.#options.log.info(
        { workspaceId: session.workspaceId, agentId: session.agentId },
        "releasing ended agent session",
      );
      void session.dispose();
    }, this.#endedLingerMs);
    timer.unref();
    this.#lingerTimers.set(key, timer);
  }

  #armIdleReaper(key: string, session: AgentSession): void {
    const existing = this.#idleTimers.get(key);
    if (existing !== undefined) {
      clearTimeout(existing);
      this.#idleTimers.delete(key);
    }
    if (this.#idleReapMs === null || session.ended || session.viewerCount > 0) return;

    const timer = setTimeout(() => {
      this.#idleTimers.delete(key);
      if (session.ended || session.viewerCount > 0) return;
      this.#options.log.info(
        { workspaceId: session.workspaceId, agentId: session.agentId },
        "reaping idle agent session",
      );
      void session.stop(null).catch(() => undefined);
    }, this.#idleReapMs);
    timer.unref();
    this.#idleTimers.set(key, timer);
  }

  #clearTimers(key: string): void {
    const linger = this.#lingerTimers.get(key);
    if (linger !== undefined) {
      clearTimeout(linger);
      this.#lingerTimers.delete(key);
    }
    const idle = this.#idleTimers.get(key);
    if (idle !== undefined) {
      clearTimeout(idle);
      this.#idleTimers.delete(key);
    }
  }
}

/* ==========================================================================
 * helpers
 * ========================================================================== */

export function summarize(session: AgentSession): AgentSummary {
  return {
    agentId: session.agentId,
    workspaceId: session.workspaceId,
    identity: session.identity,
    model: session.model,
    state: session.state,
    viewers: session.viewerCount,
    lastSeq: session.lastSeq,
    ended: session.ended,
    createdAt: session.createdAt,
  };
}

/** Maps a provider rejection onto the narrower set an HTTP caller can act on. */
function openCodeFor(error: unknown): AgentOpenErrorCode {
  switch (readErrorCode(error)) {
    case "sandbox-not-running":
      return "sandbox-not-running";
    case "harness-unavailable":
      return "harness-unavailable";
    case "upstream-unavailable":
      return "upstream-unavailable";
    case "budget-exhausted":
      return "budget-exhausted";
    case "bad-message":
      return "invalid-task";
    default:
      return "internal";
  }
}

/**
 * Initials for the avatar. Never a URL, never longer than
 * `MAX_AGENT_AVATAR_LENGTH` — a URL would be an outbound request from every
 * viewer's browser to a host somebody else chose.
 */
function initialsOf(name: string): string {
  const words = name.split(" ").filter((w) => w.length > 0);
  const first = words[0] ?? "A";
  const second = words[1];
  const raw = second === undefined ? first.slice(0, 2) : `${first.slice(0, 1)}${second.slice(0, 1)}`;
  return raw.toUpperCase().slice(0, MAX_AGENT_AVATAR_LENGTH);
}

/** NUL separator: it cannot occur in either id, so keys cannot collide. */
function sessionKey(workspaceId: string, agentId: string): string {
  return `${workspaceId}\u0000${agentId}`;
}
