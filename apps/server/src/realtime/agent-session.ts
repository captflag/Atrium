/**
 * AgentSession — one `AgentProvider` run, many viewers.
 *
 * The terminal stack's `TerminalSession` is the template and the shapes match
 * on purpose: fan-out, a bounded history for late joiners, per-viewer
 * backpressure, and a lifetime that does not end when the last human looks
 * away. What differs is what flows through it — structured, sequence-numbered
 * `AgentEvent`s instead of pty bytes — and that difference decides three
 * policies below.
 *
 * This file knows nothing about websockets and nothing about the Claude Agent
 * SDK. It talks to `AgentProvider` (apps/server/src/agent/provider.ts) and to a
 * `AgentViewer` the transport implements. If an SDK type ever appears in a
 * signature here, the seam that keeps a second harness a config change rather
 * than a refactor has failed (PLAN.md §4).
 *
 * ============================================================================
 * POLICIES — stated here so they are reviewable, not discovered
 * ============================================================================
 *
 * LIFETIME. The agent keeps working when the last viewer leaves. Sessions are
 * server-owned (PLAN.md §6), and that is the product's second claim, so
 * `detach` never stops a turn. Only `stop` — from a human, from the authorized
 * DELETE route, or from process shutdown — ends a session. The cost is stated
 * rather than hidden: a session with zero viewers still holds a harness process
 * in the container and is still spending against the broker's budget until
 * somebody ends it (SECURITY.md T10). The registry's optional idle reaper is
 * off by default for the same reason the terminal's is.
 *
 * SEQUENCE NUMBERS ARE NOT RENUMBERED. `seq` is assigned by the provider,
 * monotonic and gap-free from 1, and `subscribe.fromSeq` is only a correct
 * replay cursor if every holder of a number means the same event by it. This
 * session therefore VALIDATES the ordering and refuses anything that would
 * break it — a duplicate or out-of-order event is dropped and counted, not
 * renumbered into place. A gap is counted and logged, because a gap means the
 * provider's own contract was violated and the transcript on screen is missing
 * something.
 *
 * SERVER-GENERATED PROBLEMS ARE NOT EVENTS. When the transport or this session
 * needs to tell a viewer something — a slow-consumer detach, an event stream
 * that ended without a terminal event — it sends a `ServerAgentError` frame,
 * never a synthesized `AgentEvent`. Minting an event would mean minting a `seq`
 * the provider did not issue, which is exactly the corruption the paragraph
 * above exists to prevent.
 *
 * BACKPRESSURE. Per viewer, not per session: one bad connection must not stall
 * the agent for everybody. Before each send the session asks the transport how
 * many bytes are queued and unflushed; over `viewerHighWaterBytes` the viewer
 * is DETACHED with `slow-consumer`. Unlike the terminal — where a dropped byte
 * range is silently wrong and unrecoverable — a detached agent viewer recovers
 * exactly: reconnect, `subscribe` with `fromSeq`, and the transcript buffer
 * serves the gap.
 *
 * EVERY STRING IN AN EVENT IS UNTRUSTED (SECURITY.md T1). This file moves them
 * and never interprets them: no logging of text, prompts, tool inputs or tool
 * outputs (T9), no HTML anywhere, no URL anybody is expected to follow. What is
 * logged is ids, event kinds, counts and durations.
 *
 * PERSISTS NOTHING. No Postgres, by design — durability and the append-only
 * event log are M5 (PLAN.md §6, §7). The buffer here is in memory and is lost
 * on restart; `AgentTranscript` says the same thing at its own boundary.
 */

import type { ServerAgentControl } from "@atrium/shared";
import type {
  AgentErrorCode,
  AgentEvent,
  AgentHandle,
  AgentIdentity,
  AgentProvider,
  AgentSessionState,
} from "../agent/provider.ts";
import { AgentTranscript } from "./agent-transcript.ts";

/** Same three methods the canvas room, the gateway and the terminal log through. */
export interface AgentLogger {
  info(obj: Record<string, unknown>, msg: string): void;
  warn(obj: Record<string, unknown>, msg: string): void;
  debug(obj: Record<string, unknown>, msg: string): void;
}

/** Why a viewer stopped receiving this session. Reported to the transport. */
export type AgentDetachReason =
  /** The client sent `unsubscribe`. */
  | "client"
  /** The socket closed, or the gateway is shutting down. */
  | "closed"
  /** The viewer could not keep up and was dropped (see BACKPRESSURE). */
  | "slow-consumer"
  /** The session was disposed of entirely — its transcript is gone. */
  | "disposed";

/**
 * One attached viewer, as seen by the session. Implemented by the websocket
 * layer; the session never touches a socket.
 */
export interface AgentViewer {
  /** Unique per attachment, for logs. Not a user id and not a channel. */
  readonly viewerId: string;
  /** Authenticated principal behind this viewer, for the operator log only. */
  readonly userId: string;
  /** Wire channel assigned by the transport, carried in every server message. */
  readonly channel: number;
  send(message: ServerAgentControl): void;
  /** Bytes queued in the transport and not yet flushed. Drives backpressure. */
  bufferedBytes(): number;
  /** The session is done with this viewer. Called exactly once per attachment. */
  detached(reason: AgentDetachReason): void;
}

export interface AgentAttachRequest {
  /** Echoed into `attached.id` so a client can correlate. */
  readonly requestId: string;
  /** Replay cursor: events with `seq` greater than this, before live output. */
  readonly fromSeq?: number;
}

/**
 * A control operation failed in a way the wire has a word for.
 *
 * `code` is the frozen `AgentErrorCode` union, so the gateway maps a failure to
 * a `ServerAgentError` without inventing a second taxonomy. `message` is safe
 * to render as text: no host paths, container ids, env values, or stack traces
 * (SECURITY.md T9). A class rather than an enum-ish object because
 * `erasableSyntaxOnly` is on and this must survive type stripping.
 */
export class AgentControlError extends Error {
  readonly code: AgentErrorCode;
  readonly retryable: boolean;

  constructor(code: AgentErrorCode, message: string, retryable: boolean) {
    super(message);
    this.name = "AgentControlError";
    // `forbidden` is for the operator log only and MUST NOT reach a client:
    // telling an unauthorized member that a session exists is a disclosure.
    this.code = code === "forbidden" ? "not-found" : code;
    this.retryable = retryable;
  }
}

export interface AgentSessionOptions {
  readonly agentId: string;
  readonly workspaceId: string;
  readonly provider: AgentProvider;
  readonly handle: AgentHandle;
  readonly log: AgentLogger;
  /** Transcript ceiling in events. */
  readonly transcriptEvents: number;
  /** Transcript ceiling in approximate serialized bytes. */
  readonly transcriptBytes: number;
  /** Transport queue depth at which a viewer is detached as a slow consumer. */
  readonly viewerHighWaterBytes: number;
  /** Called once, after the provider's event stream has ended. */
  readonly onEnded: (session: AgentSession) => void;
}

export class AgentSession {
  readonly agentId: string;
  readonly workspaceId: string;
  readonly createdAt: string;

  readonly #provider: AgentProvider;
  readonly #handle: AgentHandle;
  readonly #log: AgentLogger;
  readonly #transcript: AgentTranscript;
  readonly #highWaterBytes: number;
  readonly #onEnded: (session: AgentSession) => void;

  readonly #viewers = new Set<AgentViewer>();

  /** Last state broadcast, so a change is only announced once. */
  #state: AgentSessionState;
  /** Terminal state observed locally. Outranks whatever the handle reports. */
  #ended: "stopped" | "failed" | null = null;
  #sawStarted = false;
  #turnActive = false;
  #interrupting = false;
  /** True once the event stream has finished. The session is read-only after. */
  #streamDone = false;
  /** True once `dispose()` ran: viewers detached, transcript released. */
  #disposed = false;
  /** Events the provider emitted out of order or twice. Counter only (T9). */
  #rejectedEvents = 0;
  /** Missing sequence numbers observed. A non-zero value means a broken replay. */
  #missedEvents = 0;
  #stopping: Promise<void> | null = null;

  private constructor(options: AgentSessionOptions) {
    this.agentId = options.agentId;
    this.workspaceId = options.workspaceId;
    this.createdAt = new Date().toISOString();
    this.#provider = options.provider;
    this.#handle = options.handle;
    this.#log = options.log;
    this.#transcript = new AgentTranscript(options.transcriptEvents, options.transcriptBytes);
    this.#highWaterBytes = options.viewerHighWaterBytes;
    this.#onEnded = options.onEnded;
    this.#state = options.handle.state;
  }

  /**
   * Wrap a session the provider has already started and begin pumping its
   * events.
   *
   * Called in the same tick as `provider.start()` resolves, so nothing the
   * harness emits is missed: the provider's iterator replays from the beginning
   * when no cursor is given, but relying on that would make the correctness of
   * the transcript depend on how long the caller took to get here.
   */
  static start(options: AgentSessionOptions): AgentSession {
    const session = new AgentSession(options);
    void session.#pump();
    return session;
  }

  // --- read-only view ----------------------------------------------------

  get identity(): AgentIdentity {
    return this.#handle.identity;
  }

  get model(): string {
    return this.#handle.model;
  }

  get viewerCount(): number {
    return this.#viewers.size;
  }

  /** Highest `seq` this session has accepted. 0 before the first event. */
  get lastSeq(): number {
    return this.#transcript.lastSeq;
  }

  /** Oldest `seq` still replayable from this process. 0 when none is. */
  get firstSeq(): number {
    return this.#transcript.firstSeq;
  }

  /**
   * Lifecycle as a pane needs to render it.
   *
   * The provider's `AgentHandle.state` is the authority and is documented as
   * read-through rather than a cached field. Two things are layered over it,
   * and only two: a terminal state this session watched happen, and the
   * `interrupting` window between a human pressing stop and the harness
   * acknowledging it — which the event stream has no way to express.
   */
  get state(): AgentSessionState {
    return this.#computeState();
  }

  /** True once the provider's event stream has ended. No further turns. */
  get ended(): boolean {
    return this.#streamDone;
  }

  /** True once the session has been disposed of and its transcript released. */
  get disposed(): boolean {
    return this.#disposed;
  }

  /** Operator diagnostics. Counts only — never content (T9). */
  get diagnostics(): {
    readonly events: number;
    readonly transcriptBytes: number;
    readonly droppedEvents: number;
    readonly rejectedEvents: number;
    readonly missedEvents: number;
  } {
    return {
      events: this.#transcript.count,
      transcriptBytes: this.#transcript.bytes,
      droppedEvents: this.#transcript.droppedEvents,
      rejectedEvents: this.#rejectedEvents,
      missedEvents: this.#missedEvents,
    };
  }

  // --- viewers -----------------------------------------------------------

  /**
   * Attach a viewer and replay what this process still holds.
   *
   * `attached` and the replay are sent SYNCHRONOUSLY, before returning, so no
   * live event can interleave ahead of the history it is supposed to follow.
   *
   * Attaching to a session that has ENDED is allowed and is not an error: the
   * channel stays valid so a pane can still show a finished transcript
   * (`AgentSessionState` says as much). Only a disposed session refuses.
   */
  attach(viewer: AgentViewer, request: AgentAttachRequest): boolean {
    if (this.#disposed) return false;

    this.#viewers.add(viewer);

    const cursor = Math.max(0, Math.trunc(request.fromSeq ?? 0));
    const replay = this.#transcript.since(cursor);
    const firstReplayed = replay[0];

    viewer.send({
      t: "attached",
      id: request.requestId,
      channel: viewer.channel,
      agentId: this.agentId,
      identity: this.identity,
      model: this.model,
      state: this.#computeState(),
      lastSeq: this.#transcript.lastSeq,
      // 0 when nothing is being replayed. Greater than cursor + 1 means the
      // client has a hole and must say so rather than render a transcript that
      // is missing its middle.
      replayFromSeq: firstReplayed === undefined ? 0 : firstReplayed.seq,
      viewers: this.#viewers.size,
    });

    for (const event of replay) {
      viewer.send({ t: "event", channel: viewer.channel, event });
    }

    // Everyone else needs the new viewer count for the presence badge — the
    // co-presence claim is only real if you can see who else is watching.
    this.#broadcastState(viewer);

    this.#log.debug(
      {
        workspaceId: this.workspaceId,
        agentId: this.agentId,
        userId: viewer.userId,
        viewers: this.#viewers.size,
        fromSeq: cursor,
        replayed: replay.length,
      },
      "agent viewer attached",
    );
    return true;
  }

  /**
   * Detach one viewer. The agent keeps working — see LIFETIME in the header.
   * Idempotent: detaching an unknown viewer is a no-op.
   */
  detach(viewer: AgentViewer, reason: AgentDetachReason): void {
    if (!this.#viewers.delete(viewer)) return;
    viewer.detached(reason);
    if (this.#disposed) return;

    this.#broadcastState(null);
    this.#log.debug(
      {
        workspaceId: this.workspaceId,
        agentId: this.agentId,
        userId: viewer.userId,
        reason,
        viewers: this.#viewers.size,
      },
      "agent viewer detached",
    );
  }

  // --- control -----------------------------------------------------------

  /**
   * Send a follow-up turn.
   *
   * Any attached member may prompt: they are all in the same room watching the
   * same agent, which is the point (PLAN.md §1, claim 1). The `userId` goes to
   * the operator log; the text does not (T9).
   *
   * Rejected with `busy` while a turn is running. Queueing behind a running
   * turn is a product decision M3b does not need to make, and a queue is much
   * easier to add later than to remove.
   */
  async prompt(viewer: AgentViewer, text: string): Promise<void> {
    this.#assertLive();
    const state = this.#computeState();
    if (state === "running" || state === "starting" || state === "interrupting") {
      throw new AgentControlError("busy", "The agent is still working on the last turn.", true);
    }

    this.#log.info(
      {
        workspaceId: this.workspaceId,
        agentId: this.agentId,
        userId: viewer.userId,
        // The prompt itself is never logged. Its size is not a secret and is
        // the number an operator actually needs.
        promptChars: text.length,
      },
      "agent prompt accepted",
    );

    try {
      await this.#provider.send(this.#handle, text);
    } catch (error: unknown) {
      throw this.#toControlError(error, "The agent could not accept that prompt.");
    }
    this.#turnActive = true;
    this.#refreshState();
  }

  /** Stop the current turn. The session survives and returns to idle. */
  async interrupt(viewer: AgentViewer): Promise<void> {
    this.#assertLive();
    this.#log.info(
      { workspaceId: this.workspaceId, agentId: this.agentId, userId: viewer.userId },
      "agent interrupt requested",
    );

    this.#interrupting = true;
    this.#refreshState();
    try {
      await this.#provider.interrupt(this.#handle);
    } catch (error: unknown) {
      this.#interrupting = false;
      this.#refreshState();
      throw this.#toControlError(error, "The agent could not be interrupted.");
    }
  }

  /**
   * End the session from the wire. Terminal and idempotent.
   *
   * Stops the SESSION, not the sandbox: other agents and every terminal in the
   * same container are unaffected.
   */
  async stop(viewer: AgentViewer | null): Promise<void> {
    if (this.#streamDone) return;
    this.#log.info(
      {
        workspaceId: this.workspaceId,
        agentId: this.agentId,
        userId: viewer?.userId ?? "system",
      },
      "agent stop requested",
    );

    // Concurrent stops share one provider call: `stop` is idempotent by
    // contract, but two in-flight teardowns of the same harness is exactly how
    // a process gets orphaned inside a container.
    const pending = (this.#stopping ??= (async () => {
      try {
        await this.#provider.stop(this.#handle);
      } finally {
        this.#stopping = null;
      }
    })());

    try {
      await pending;
    } catch (error: unknown) {
      throw this.#toControlError(error, "The agent could not be stopped.");
    }
    // The provider emits a final done{reason:"stopped"}; the pump sees it and
    // ends the stream. Nothing is synthesized here.
  }

  /**
   * Release the session entirely: stop it if it is still running, detach every
   * viewer, drop the transcript.
   *
   * Called by the registry when the session is removed — after its linger
   * window, on DELETE, or at shutdown. Idempotent.
   */
  async dispose(): Promise<void> {
    if (this.#disposed) return;
    if (!this.#streamDone) {
      try {
        await this.stop(null);
      } catch (error: unknown) {
        this.#log.warn(
          {
            workspaceId: this.workspaceId,
            agentId: this.agentId,
            err: error instanceof Error ? error.message : "unknown",
          },
          "agent session stop failed during dispose",
        );
      }
    }
    this.#disposed = true;
    for (const viewer of [...this.#viewers]) {
      this.#viewers.delete(viewer);
      viewer.detached("disposed");
    }
    this.#transcript.clear();
  }

  // --- internals ---------------------------------------------------------

  /**
   * The single consumer of the provider's event stream.
   *
   * One iterator, not one per viewer: the provider guarantees independent
   * iterators, but fan-out is this session's job and doing it here is what
   * makes "everyone watching an agent sees the same transcript" true by
   * construction rather than by two consumers happening to agree.
   */
  async #pump(): Promise<void> {
    try {
      for await (const event of this.#provider.events(this.#handle)) {
        this.#onEvent(event);
      }
      this.#onStreamEnd(null);
    } catch (error: unknown) {
      this.#onStreamEnd(error);
    }
  }

  #onEvent(event: AgentEvent): void {
    if (this.#disposed) return;

    const expected = this.#transcript.lastSeq + 1;
    if (event.seq > expected) {
      // The provider's contract is monotonic AND gap-free. A gap means the
      // transcript on screen is missing something, so it is counted and said
      // out loud rather than papered over.
      this.#missedEvents += event.seq - expected;
      this.#log.warn(
        {
          workspaceId: this.workspaceId,
          agentId: this.agentId,
          expected,
          received: event.seq,
        },
        "gap in agent event sequence",
      );
    }
    if (!this.#transcript.push(event)) {
      this.#rejectedEvents += 1;
      this.#log.warn(
        {
          workspaceId: this.workspaceId,
          agentId: this.agentId,
          kind: event.kind,
          seq: event.seq,
          lastSeq: this.#transcript.lastSeq,
        },
        "dropped out-of-order agent event",
      );
      return;
    }

    this.#applyLifecycle(event);
    this.#broadcastEvent(event);
    this.#refreshState();
  }

  /** Event kinds that move the session's lifecycle. Nothing else is inspected. */
  #applyLifecycle(event: AgentEvent): void {
    switch (event.kind) {
      case "started":
        this.#sawStarted = true;
        this.#turnActive = true;
        return;
      case "done":
        this.#turnActive = false;
        this.#interrupting = false;
        // Only `stopped` is terminal for the SESSION. `completed`,
        // `interrupted`, `max-turns`, `budget-exhausted` and `error` end a TURN
        // — whether the session survives one of those is the provider's call,
        // read back through `handle.state`.
        if (event.reason === "stopped") this.#ended = "stopped";
        return;
      default:
        return;
    }
  }

  #onStreamEnd(error: unknown): void {
    if (this.#streamDone) return;
    this.#streamDone = true;
    this.#turnActive = false;
    this.#interrupting = false;

    if (error !== null && error !== undefined) {
      this.#ended = "failed";
      // The provider's message may quote a harness or a daemon (T9): it goes to
      // the operator log, and the client gets a fixed string.
      this.#log.warn(
        {
          workspaceId: this.workspaceId,
          agentId: this.agentId,
          err: error instanceof Error ? error.message : "unknown",
        },
        "agent event stream failed",
      );
      this.#broadcastError(
        error instanceof Error && "code" in error
          ? this.#toControlError(error, "The agent session ended unexpectedly.")
          : new AgentControlError("internal", "The agent session ended unexpectedly.", false),
      );
    } else if (this.#ended === null) {
      // The iterator is contracted to end only after a terminal done/error. It
      // did not, so the pane must not be left showing a live agent forever.
      const reported = this.#handle.state;
      this.#ended = reported === "failed" ? "failed" : "stopped";
      this.#log.warn(
        { workspaceId: this.workspaceId, agentId: this.agentId, reported },
        "agent event stream ended without a terminal event",
      );
      this.#broadcastError(
        new AgentControlError(
          "agent-not-running",
          "The agent stopped without reporting a result.",
          false,
        ),
      );
    }

    this.#refreshState();
    this.#log.info(
      {
        workspaceId: this.workspaceId,
        agentId: this.agentId,
        state: this.#computeState(),
        ...this.diagnostics,
      },
      "agent session ended",
    );
    this.#onEnded(this);
  }

  #computeState(): AgentSessionState {
    if (this.#ended !== null) return this.#ended;
    if (this.#interrupting) return "interrupting";
    const reported = this.#handle.state;
    if (reported === "stopped" || reported === "failed") return reported;
    if (this.#turnActive) return "running";
    if (this.#sawStarted) return "idle";
    return reported;
  }

  #refreshState(): void {
    const next = this.#computeState();
    if (next === this.#state) return;
    this.#state = next;
    this.#broadcastState(null);
  }

  /** Refuses control on a session that has ended. */
  #assertLive(): void {
    if (this.#disposed || this.#streamDone) {
      throw new AgentControlError("agent-not-running", "This agent session has ended.", false);
    }
  }

  #broadcastEvent(event: AgentEvent): void {
    let slow: AgentViewer[] | null = null;
    for (const viewer of this.#viewers) {
      if (viewer.bufferedBytes() > this.#highWaterBytes) {
        (slow ??= []).push(viewer);
        continue;
      }
      viewer.send({ t: "event", channel: viewer.channel, event });
    }
    if (slow === null) return;

    for (const viewer of slow) {
      this.#log.warn(
        {
          workspaceId: this.workspaceId,
          agentId: this.agentId,
          userId: viewer.userId,
          bufferedBytes: viewer.bufferedBytes(),
          highWaterBytes: this.#highWaterBytes,
        },
        "detaching slow agent viewer",
      );
      // The transport sends the `slow-consumer` error frame; the reconnecting
      // client catches up with `fromSeq` from the transcript above.
      this.detach(viewer, "slow-consumer");
    }
  }

  #broadcastState(except: AgentViewer | null): void {
    const state = this.#computeState();
    for (const viewer of this.#viewers) {
      if (viewer === except) continue;
      viewer.send({
        t: "state",
        channel: viewer.channel,
        state,
        viewers: this.#viewers.size,
      });
    }
  }

  #broadcastError(error: AgentControlError): void {
    for (const viewer of this.#viewers) {
      viewer.send({
        t: "error",
        channel: viewer.channel,
        code: error.code,
        message: error.message,
        retryable: error.retryable,
      });
    }
  }

  /**
   * Map a provider rejection onto the wire taxonomy.
   *
   * `AgentError.detail` is for the operator log only and MUST NOT be
   * serialized to a client (T9), so it is read here and never forwarded. An
   * error carrying no recognisable code becomes `internal` with a fixed
   * string: a raw exception message can quote a path, a container id, or an
   * environment value.
   */
  #toControlError(error: unknown, fallbackMessage: string): AgentControlError {
    if (error instanceof AgentControlError) return error;

    const code = readErrorCode(error);
    if (code === null) {
      this.#log.warn(
        {
          workspaceId: this.workspaceId,
          agentId: this.agentId,
          err: error instanceof Error ? error.message : "unknown",
        },
        "agent provider call failed",
      );
      return new AgentControlError("internal", fallbackMessage, false);
    }

    this.#log.warn(
      {
        workspaceId: this.workspaceId,
        agentId: this.agentId,
        code,
        detail: readErrorDetail(error),
      },
      "agent provider refused",
    );
    return new AgentControlError(code, messageFor(code, fallbackMessage), retryableFor(code));
  }
}

/* ==========================================================================
 * Error mapping helpers
 * ========================================================================== */

const AGENT_ERROR_CODES: ReadonlySet<string> = new Set<AgentErrorCode>([
  "bad-message",
  "version-mismatch",
  "not-found",
  "forbidden",
  "bad-channel",
  "payload-too-large",
  "too-many-channels",
  "sandbox-not-running",
  "agent-not-running",
  "busy",
  "budget-exhausted",
  "upstream-unavailable",
  "harness-unavailable",
  "slow-consumer",
  "internal",
]);

/** Reads an `AgentError.code` without importing anything that could be faked. */
export function readErrorCode(error: unknown): AgentErrorCode | null {
  if (typeof error !== "object" || error === null) return null;
  const code = (error as { code?: unknown }).code;
  if (typeof code !== "string" || !AGENT_ERROR_CODES.has(code)) return null;
  return code as AgentErrorCode;
}

/** Operator-log detail. Never serialized to a client (T9). */
function readErrorDetail(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null) return undefined;
  const detail = (error as { detail?: unknown }).detail;
  return typeof detail === "string" ? detail : undefined;
}

/**
 * A fixed, curated string per code.
 *
 * Never the provider's own message: it is written for an operator and may quote
 * a path, a container id, or a daemon error (T9).
 */
export function messageFor(code: AgentErrorCode, fallback: string): string {
  switch (code) {
    case "busy":
      return "The agent is still working on the last turn.";
    case "agent-not-running":
      return "This agent session has ended.";
    case "sandbox-not-running":
      return "The workspace sandbox is not running.";
    case "harness-unavailable":
      return "The agent harness could not start in the workspace.";
    case "upstream-unavailable":
      return "The model service could not be reached.";
    case "budget-exhausted":
      return "This session has reached its budget. Raise the cap to continue.";
    case "not-found":
    case "forbidden":
      return "That agent is not available.";
    case "payload-too-large":
      return "That message is too large.";
    case "too-many-channels":
      return "Too many agents open on this connection.";
    case "bad-channel":
      return "Unknown agent channel.";
    case "bad-message":
      return "Malformed agent message.";
    case "version-mismatch":
      return "This page is running an old agent client. Reload to continue.";
    case "slow-consumer":
      return "This connection fell too far behind and was detached. Re-open the agent to catch up.";
    case "internal":
      return fallback;
    default:
      return fallback;
  }
}

/** Whether the same request may be retried unchanged. */
export function retryableFor(code: AgentErrorCode): boolean {
  switch (code) {
    case "busy":
    case "upstream-unavailable":
    case "slow-consumer":
    case "internal":
      return true;
    default:
      return false;
  }
}
