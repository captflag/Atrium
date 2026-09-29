/**
 * Agent wire protocol (M3b).
 *
 * One WebSocket at `/rt/agent?workspace=<id>&v=<AGENT_PROTOCOL_VERSION>` carries
 * any number of agent sessions. Authorization happens at the HTTP upgrade,
 * before a single frame is read — the same order `gateway.ts` and `terminal.ts`
 * already use (SECURITY.md T6). Nothing in this file authorizes anything.
 *
 * ============================================================================
 * THE RULE THAT MATTERS MOST: THIS PROTOCOL CANNOT START AN AGENT
 * ============================================================================
 * An agent session runs commands inside the workspace container. Starting one
 * is therefore code execution, exactly like a terminal (SECURITY.md T8) — and a
 * missing check on a path that can start one is remote code execution for every
 * member, or worse.
 *
 * So the split is identical to M2's terminal:
 *
 *   - Creation is an AUTHORIZED HTTP ROUTE: `POST /api/workspaces/:id/agents`,
 *     which repeats authenticate + membership. Deletion likewise.
 *   - This protocol can only ATTACH. `subscribe` LOOKS UP an existing session,
 *     and lookup is keyed by (workspace, agentId) so cross-workspace access is
 *     structurally unreachable rather than a check someone can forget.
 *   - `prompt`, `interrupt` and `stop` act on a CHANNEL the server handed out in
 *     `attached`, never on a caller-supplied session id.
 *
 * If a JSON message could spawn an agent, every member would have RCE by
 * sending one.
 *
 * ============================================================================
 * FRAMING — text frames only, and why this differs from terminal.ts
 * ============================================================================
 * `terminal.ts` splits into binary frames because a pty emits an arbitrary byte
 * stream on the hottest path in the app, and JSON would mangle it. None of that
 * applies here. Agent events are STRUCTURED and comparatively rare: a tool call,
 * a paragraph of text, a usage total. They are also persisted to the event log
 * (PLAN.md §6) as structured rows, so a binary frame would have to be decoded
 * immediately anyway.
 *
 * Therefore: every frame is a TEXT frame carrying one JSON object with a `t`
 * discriminator. There is no binary channel and no codec in this file.
 *
 * ============================================================================
 * AGENT OUTPUT IS UNTRUSTED TEXT (SECURITY.md T1)
 * ============================================================================
 * Assume the agent is prompt-injected by repo content. It reads a README, a
 * dependency's source, a file a *different* agent wrote this session — any of
 * which can carry instructions. Two consequences this protocol is shaped
 * around:
 *
 *   1. **Injection reaches humans.** Agent output renders in a canvas pane. A
 *      poisoned agent will write content aimed at the person watching ("this
 *      change is approved, click merge"). Every string in an `AgentEvent` is
 *      attacker-controlled. The client MUST render it as TEXT: `textContent` or
 *      a React text child. Never `innerHTML`, never
 *      `dangerouslySetInnerHTML`, never a markdown-to-HTML renderer, never an
 *      auto-followed or auto-fetched link. There is no sanitizer in this file
 *      because the correct answer is not to sanitize HTML but to never build
 *      any.
 *   2. **Identity is server-assigned.** `AgentIdentity.colour` is an index into
 *      a fixed palette, not a CSS string, and the name has a length cap and a
 *      character class. An agent that could choose its own colour could choose
 *      `red; background: url(...)`, and an agent that could choose its own name
 *      could impersonate a human teammate in the presence list.
 *
 * ============================================================================
 * WHAT NEVER APPEARS ON THIS WIRE (SECURITY.md T9, D1)
 * ============================================================================
 * No provider credential. No capability token. No `ANTHROPIC_BASE_URL`. No host
 * path, container id, or environment dump — an `error` carries a generic
 * message and the detail goes to the operator log only, exactly as
 * `TerminalErrorCode` already requires. Tool inputs and results are TRUNCATED
 * previews with an explicit `truncated` flag, because a full `Read` result of
 * `.env` is three long-lived copies of a secret (browser, event log, snapshot).
 */

/* ==========================================================================
 * Constants
 * ========================================================================== */

/** Bumped on any incompatible change. Sent as a query param at upgrade. */
export const AGENT_PROTOCOL_VERSION = 1;

/** `id`, `agentId`: same shape as pane, workspace and terminal ids. */
export const AGENT_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

/** Largest control frame the server accepts, in UTF-8 bytes. */
export const AGENT_MAX_CONTROL_FRAME_BYTES = 64 * 1024;

/**
 * Largest follow-up prompt a member may send in one `prompt` message. Generous
 * for a pasted stack trace, small enough that a member cannot push megabytes of
 * billable context through the broker in one frame (SECURITY.md T10).
 */
export const AGENT_MAX_PROMPT_BYTES = 32 * 1024;

/** Agent sessions one socket may hold open at once. */
export const AGENT_MAX_CHANNELS_PER_SOCKET = 8;

/**
 * Cap on a `tool_call` input preview and a `tool_result` output preview, in
 * UTF-8 bytes. The producer truncates and sets `truncated: true`; it never
 * sends the whole thing "just this once" (T9).
 */
export const AGENT_MAX_TOOL_PREVIEW_BYTES = 4 * 1024;

/** Cap on one `text` or `thinking` chunk. Longer output arrives as more events. */
export const AGENT_MAX_TEXT_CHUNK_BYTES = 16 * 1024;

/**
 * Fixed identity palette. `AgentIdentity.colour` is one of these literals and
 * nothing else — see the header: a colour that reached CSS unvalidated is
 * stored XSS for every teammate (T6). Values are chosen to stay legible against
 * both pane backgrounds and to be distinguishable at cursor size.
 */
export const AGENT_COLOURS = [
  "#e8734a",
  "#3f8ae0",
  "#4caf7d",
  "#b45cd8",
  "#d9a13b",
  "#3fb6c4",
  "#e05c7e",
  "#7c86e8",
] as const;

export type AgentColour = (typeof AGENT_COLOURS)[number];

export function isAgentColour(v: unknown): v is AgentColour {
  return typeof v === "string" && (AGENT_COLOURS as readonly string[]).includes(v);
}

/** Display name bounds. Names are assigned server-side, never by the agent. */
export const MAX_AGENT_NAME_LENGTH = 32;
/** Letters, digits, space, hyphen. No combining marks, no RTL overrides, no emoji. */
export const AGENT_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 -]{0,31}$/;

/**
 * The avatar is a SHORT GRAPHEME LABEL (initials, or a single emoji), not a
 * URL. A URL would be an outbound request from every viewer's browser to a
 * host the agent chose — a tracking pixel and an exfiltration channel in one.
 */
export const MAX_AGENT_AVATAR_LENGTH = 4;

/* ==========================================================================
 * Identity
 * ========================================================================== */

/**
 * Who the agent is, for co-presence (PLAN.md §10 decision 3). This is not
 * decoration: "agent-2 is holding `src/auth/**`" only reads as a colleague if
 * agent-2 is a someone, and the M4 conflict UI is unreadable without it.
 *
 * Every field is ASSIGNED BY THE SERVER when the session is created and is
 * immutable for the session's life. The agent cannot rename or recolour itself,
 * and neither can a client: a member who could would be able to impersonate a
 * human in the presence list.
 */
export interface AgentIdentity {
  /** Stable session-scoped id. Matches AGENT_ID_RE. */
  readonly id: string;
  /** Display name, e.g. "Wren". Matches AGENT_NAME_RE. */
  readonly name: string;
  /** One of AGENT_COLOURS. Used for the cursor, the pane chrome and claim tints. */
  readonly colour: AgentColour;
  /** Initials or one emoji. Never a URL. */
  readonly avatar: string;
}

/* ==========================================================================
 * Session state
 * ========================================================================== */

/**
 * Lifecycle as the pane needs to render it. `idle` means the harness is alive
 * and has finished a turn — a follow-up `prompt` is accepted. `stopped` and
 * `failed` are terminal; the channel stays valid so late replay still works,
 * but no further `prompt` is accepted.
 */
export type AgentSessionState =
  | "starting"
  | "running"
  | "idle"
  | "interrupting"
  | "stopped"
  | "failed";

/** Why a turn (or the session) ended. */
export type AgentDoneReason =
  | "completed"
  /** A human pressed stop mid-turn; the session survives and can be prompted again. */
  | "interrupted"
  /** The session was torn down. Terminal. */
  | "stopped"
  | "max-turns"
  /** The broker refused: session token budget or spend cap reached (T10). */
  | "budget-exhausted"
  | "error";

/* ==========================================================================
 * Errors
 * ========================================================================== */

/**
 * Why an agent message or session failed.
 *
 * `not-found` and `forbidden` are DELIBERATELY DISTINCT for the operator log,
 * but the server sends `not-found` for both on the wire: telling an
 * unauthorized member that a session exists is itself a disclosure. Servers
 * MUST NOT emit `forbidden`. Same rule, same reason, as `TerminalErrorCode`.
 */
export type AgentErrorCode =
  /** Frame was not valid JSON, or failed schema validation. */
  | "bad-message"
  /** Client protocol version does not match AGENT_PROTOCOL_VERSION. */
  | "version-mismatch"
  /** No such agent session, or the caller may not see it. */
  | "not-found"
  /** Internal only — never sent. See above. */
  | "forbidden"
  /** `channel` is unknown, already ended, or belongs to another socket. */
  | "bad-channel"
  /** Control frame over AGENT_MAX_CONTROL_FRAME_BYTES, or prompt over AGENT_MAX_PROMPT_BYTES. */
  | "payload-too-large"
  /** AGENT_MAX_CHANNELS_PER_SOCKET reached. */
  | "too-many-channels"
  /** The workspace's sandbox is hibernated, stopping, or gone. */
  | "sandbox-not-running"
  /** The session exists but its harness process is not running. */
  | "agent-not-running"
  /** A `prompt` arrived while the session was mid-turn, or after it ended. */
  | "busy"
  /**
   * The broker refused on budget (T10). Distinct from `upstream-unavailable`
   * because the remedy is a human raising a cap, not a retry.
   */
  | "budget-exhausted"
  /** The broker or the model provider could not be reached, or returned 5xx. */
  | "upstream-unavailable"
  /** The harness binary is missing or would not launch inside the container. */
  | "harness-unavailable"
  /**
   * This viewer could not keep up and was detached rather than allowed to grow
   * an unbounded server-side buffer (PLAN.md §6, backpressure). Reconnect and
   * re-subscribe; `fromSeq` catches up from the event log.
   */
  | "slow-consumer"
  /** Anything else. `message` is generic; details go to the server log only. */
  | "internal";

/* ==========================================================================
 * Agent events — the payload both the wire and the event log carry
 * ========================================================================== */

/**
 * Common to every event.
 *
 * `seq` is monotonic and gap-free per session, starting at 1, and is assigned
 * SERVER-SIDE — not by the harness, which is inside the trust boundary. It is
 * what makes `subscribe.fromSeq` a correct replay cursor in M5, and it is the
 * only ordering a client may rely on: `at` comes from a clock the server does
 * not control on every host and is for display only.
 */
export interface AgentEventBase {
  readonly seq: number;
  /** The session this belongs to. Redundant on the wire, load-bearing in the log. */
  readonly agentId: string;
  /** ISO 8601, server clock, display only. Never order by this. */
  readonly at: string;
}

/** The harness came up and is bound to a session. First event, always. */
export interface AgentStartedEvent extends AgentEventBase {
  readonly kind: "started";
  /** Resolved model id, e.g. "claude-opus-5". Echoed so the pane can show it. */
  readonly model: string;
  /** Working directory inside the container, e.g. "/workspace". */
  readonly cwd: string;
  /** Tool names the harness reports as available. For the pane's affordances. */
  readonly tools: readonly string[];
  /** Implementation name, e.g. "claude-agent-sdk". Diagnostics only. */
  readonly harness: string;
}

/**
 * Assistant prose. UNTRUSTED — render as text (header, point 1).
 *
 * Long output arrives as several events; `final` marks the last chunk of one
 * assistant message so the pane can stop showing a caret. A client that
 * concatenates should key on `messageId`, not on adjacency.
 */
export interface AgentTextEvent extends AgentEventBase {
  readonly kind: "text";
  readonly text: string;
  readonly final: boolean;
  /** Groups chunks of one assistant message. Opaque. */
  readonly messageId: string;
  /** Set when this came from a subagent, naming the tool call that spawned it. */
  readonly parentToolUseId?: string;
}

/** Reasoning output, when the model emits it. Same untrusted-text rule. */
export interface AgentThinkingEvent extends AgentEventBase {
  readonly kind: "thinking";
  readonly text: string;
  readonly messageId: string;
}

/**
 * The agent is about to run a tool.
 *
 * `inputPreview` is a TRUNCATED, already-stringified rendering — not the raw
 * input object. Two reasons: a tool input can be a whole file body, and a
 * structured blob invites a client to render it as something other than text.
 */
export interface AgentToolCallEvent extends AgentEventBase {
  readonly kind: "tool_call";
  /** Correlates with the matching `tool_result`. Opaque. */
  readonly toolUseId: string;
  /** Tool name as the harness reports it, e.g. "Edit", "Bash". */
  readonly tool: string;
  /** At most AGENT_MAX_TOOL_PREVIEW_BYTES of UTF-8. Untrusted text. */
  readonly inputPreview: string;
  readonly truncated: boolean;
  /** Set when a subagent made the call. */
  readonly parentToolUseId?: string;
}

/** How a tool call ended. `denied` is a gate refusal, not a tool failure. */
export type AgentToolStatus = "ok" | "error" | "denied";

export interface AgentToolResultEvent extends AgentEventBase {
  readonly kind: "tool_result";
  readonly toolUseId: string;
  readonly tool: string;
  readonly status: AgentToolStatus;
  /** At most AGENT_MAX_TOOL_PREVIEW_BYTES of UTF-8. Untrusted text. */
  readonly outputPreview: string;
  readonly truncated: boolean;
  readonly durationMs?: number;
}

/**
 * Token and cost accounting for the session so far.
 *
 * CUMULATIVE, not per-turn: read the latest event, never sum across events.
 *
 * `cacheReadInputTokens` is here deliberately. Prompt caching is the single
 * largest cost lever (PLAN.md §8), and a persistent zero means a silent cache
 * invalidator, not an absent feature — which is only visible if the number is
 * on screen. The authoritative ceiling is still enforced at the broker, outside
 * the container (T10); this event is for the human, not for enforcement.
 */
export interface AgentUsageEvent extends AgentEventBase {
  readonly kind: "usage";
  readonly model: string;
  readonly inputTokens: number;
  readonly outputTokens: number;
  readonly cacheReadInputTokens: number;
  readonly cacheCreationInputTokens: number;
  /** Estimate, not a billing statement. Omitted when the harness reports none. */
  readonly costUsd?: number;
}

/** A turn finished. The session may still be alive — see `AgentDoneReason`. */
export interface AgentDoneEvent extends AgentEventBase {
  readonly kind: "done";
  readonly reason: AgentDoneReason;
  /** Turns in this session so far. */
  readonly turns: number;
  /** The harness's closing message, when it produced one. Untrusted text. */
  readonly summary?: string;
}

/**
 * Something failed. Terminal for the turn; `state` on the following `ServerState`
 * says whether the session survived.
 *
 * `message` is safe to render as TEXT and never contains host paths, container
 * ids, env values, credentials, or stack traces (T9).
 */
export interface AgentErrorEvent extends AgentEventBase {
  readonly kind: "error";
  readonly code: AgentErrorCode;
  readonly message: string;
  readonly retryable: boolean;
}

/**
 * A non-fatal harness notice: a retry after a 429, a compaction, a model
 * fallback. Rendered as chrome, not as agent speech, so it must be visually
 * distinguishable from `text` in the pane — otherwise it becomes a channel for
 * an injected agent to fake system messages.
 */
export interface AgentNoticeEvent extends AgentEventBase {
  readonly kind: "notice";
  readonly level: "info" | "warn";
  readonly message: string;
}

export type AgentEvent =
  | AgentStartedEvent
  | AgentTextEvent
  | AgentThinkingEvent
  | AgentToolCallEvent
  | AgentToolResultEvent
  | AgentUsageEvent
  | AgentDoneEvent
  | AgentErrorEvent
  | AgentNoticeEvent;

export type AgentEventKind = AgentEvent["kind"];

/* ==========================================================================
 * Control messages: client -> server
 * ========================================================================== */

/**
 * Attach to an EXISTING agent session. Cannot create one — see the header.
 *
 * `id` is a client-chosen request id, echoed on the matching `attached` or
 * `error` so a client with several in flight can correlate them.
 */
export interface ClientAgentSubscribe {
  readonly t: "subscribe";
  readonly id: string;
  readonly agentId: string;
  /**
   * Replay cursor: send events with `seq` strictly greater than this before
   * live output. 0 (or omitted) asks for everything the server still holds.
   * The server replays only what it has and reports the range in `attached` —
   * durable replay from Postgres is M5 (PLAN.md §6).
   *
   * The server MUST re-authorize this request rather than trusting the
   * subscription that produced the cursor (SECURITY.md T11): membership may
   * have been revoked during the disconnect, which is exactly the window
   * durability creates.
   */
  readonly fromSeq?: number;
}

/**
 * Send a follow-up turn to an idle session.
 *
 * Rejected with `busy` while a turn is running — queueing a prompt behind a
 * running turn is a product decision M3b does not need to make, and a queue is
 * much easier to add later than to remove.
 */
export interface ClientAgentPrompt {
  readonly t: "prompt";
  readonly id: string;
  readonly channel: number;
  /** At most AGENT_MAX_PROMPT_BYTES of UTF-8. */
  readonly text: string;
}

/**
 * Stop the current turn. The session stays alive and returns to `idle`, so the
 * human can redirect it — which is the whole point of watching an agent work.
 */
export interface ClientAgentInterrupt {
  readonly t: "interrupt";
  readonly id: string;
  readonly channel: number;
}

/**
 * End the session and tear down its harness process. Terminal.
 *
 * Note this is the SESSION, not the sandbox: the container and everything else
 * in it (terminals, other agents) are unaffected.
 */
export interface ClientAgentStop {
  readonly t: "stop";
  readonly id: string;
  readonly channel: number;
}

/**
 * Stop receiving this session. Detaches the viewer only — the agent keeps
 * working, because server-owned sessions are the product (PLAN.md §6).
 * Closing the socket detaches every channel implicitly.
 */
export interface ClientAgentUnsubscribe {
  readonly t: "unsubscribe";
  readonly channel: number;
}

export type ClientAgentControl =
  | ClientAgentSubscribe
  | ClientAgentPrompt
  | ClientAgentInterrupt
  | ClientAgentStop
  | ClientAgentUnsubscribe;

/* ==========================================================================
 * Control messages: server -> client
 * ========================================================================== */

/** Subscription accepted. `channel` is now valid for this socket. */
export interface ServerAgentAttached {
  readonly t: "attached";
  /** Echoes `ClientAgentSubscribe.id`. */
  readonly id: string;
  readonly channel: number;
  readonly agentId: string;
  readonly identity: AgentIdentity;
  /** Resolved model id for this session. */
  readonly model: string;
  readonly state: AgentSessionState;
  /** Highest `seq` the server holds. 0 when the session has produced nothing. */
  readonly lastSeq: number;
  /**
   * Lowest `seq` about to be replayed, or 0 when none is. When this is greater
   * than `fromSeq + 1` the server could not serve the whole gap and the client
   * has a HOLE — say so in the UI rather than rendering a plausible-looking
   * transcript that is missing the middle.
   */
  readonly replayFromSeq: number;
  /** Viewers attached to this session, including this one. For the badge. */
  readonly viewers: number;
}

/**
 * One agent event. Replayed events and live events are indistinguishable by
 * design — the same mechanism serves a fresh join, a refresh and a five-hour
 * absence (PLAN.md §6).
 */
export interface ServerAgentEvent {
  readonly t: "event";
  readonly channel: number;
  readonly event: AgentEvent;
}

/** Lifecycle changed, or a viewer joined or left. Unsolicited. */
export interface ServerAgentState {
  readonly t: "state";
  readonly channel: number;
  readonly state: AgentSessionState;
  readonly viewers: number;
}

/** A control message failed. See `AgentErrorCode` for the disclosure rule. */
export interface ServerAgentError {
  readonly t: "error";
  /** Echoes the failing request's `id`, when the failure had one. */
  readonly id?: string;
  /** The channel concerned, when the failure had one. */
  readonly channel?: number;
  readonly code: AgentErrorCode;
  /**
   * Human-readable, safe to render as TEXT in the pane. Never contains host
   * paths, container ids, env values, or stack traces (SECURITY.md T9).
   */
  readonly message: string;
  /** True when the client may retry the same request unchanged. */
  readonly retryable: boolean;
}

export type ServerAgentControl =
  | ServerAgentAttached
  | ServerAgentEvent
  | ServerAgentState
  | ServerAgentError;

/* ==========================================================================
 * Validation
 * ========================================================================== */

export type AgentControlParseResult =
  | { readonly ok: true; readonly message: ClientAgentControl }
  | { readonly ok: false; readonly code: AgentErrorCode; readonly reason: string };

function isChannel(v: unknown): v is number {
  return typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= 0xffff_ffff;
}

function isRequestId(v: unknown): v is string {
  return typeof v === "string" && AGENT_ID_RE.test(v);
}

/** UTF-8 byte length, without allocating a copy of the whole string. */
export function utf8ByteLength(s: string): number {
  return new TextEncoder().encode(s).byteLength;
}

/**
 * Parses and validates a client control frame. The server MUST route every
 * inbound frame through this and MUST NOT trust any field it did not return —
 * a workspace member is authenticated, not trusted (SECURITY.md T6).
 */
export function parseClientAgentControl(raw: string): AgentControlParseResult {
  // UTF-8 byte length is always >= UTF-16 code-unit count, so this is a sound
  // (if loose) rejection — same argument as parseClientControl in terminal.ts.
  // The exact byte check that matters is on `prompt.text` below.
  if (raw.length > AGENT_MAX_CONTROL_FRAME_BYTES) {
    return { ok: false, code: "payload-too-large", reason: "control frame too large" };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { ok: false, code: "bad-message", reason: "not valid JSON" };
  }
  if (typeof parsed !== "object" || parsed === null) {
    return { ok: false, code: "bad-message", reason: "message must be an object" };
  }
  const m = parsed as Record<string, unknown>;

  switch (m["t"]) {
    case "subscribe": {
      if (!isRequestId(m["id"])) {
        return { ok: false, code: "bad-message", reason: "id must match AGENT_ID_RE" };
      }
      if (typeof m["agentId"] !== "string" || !AGENT_ID_RE.test(m["agentId"])) {
        return { ok: false, code: "bad-message", reason: "agentId must match AGENT_ID_RE" };
      }
      const base: ClientAgentSubscribe = {
        t: "subscribe",
        id: m["id"],
        agentId: m["agentId"],
      };
      const from = m["fromSeq"];
      if (from === undefined) return { ok: true, message: base };
      if (typeof from !== "number" || !Number.isInteger(from) || from < 0) {
        return { ok: false, code: "bad-message", reason: "fromSeq must be a non-negative integer" };
      }
      // exactOptionalPropertyTypes: the key exists only when it has a value.
      return { ok: true, message: { ...base, fromSeq: from } };
    }

    case "prompt": {
      if (!isRequestId(m["id"])) {
        return { ok: false, code: "bad-message", reason: "id must match AGENT_ID_RE" };
      }
      if (!isChannel(m["channel"])) {
        return { ok: false, code: "bad-channel", reason: "channel must be a uint32" };
      }
      const text = m["text"];
      if (typeof text !== "string" || text.length === 0) {
        return { ok: false, code: "bad-message", reason: "text must be a non-empty string" };
      }
      if (utf8ByteLength(text) > AGENT_MAX_PROMPT_BYTES) {
        return { ok: false, code: "payload-too-large", reason: "prompt too large" };
      }
      return { ok: true, message: { t: "prompt", id: m["id"], channel: m["channel"], text } };
    }

    case "interrupt":
    case "stop": {
      if (!isRequestId(m["id"])) {
        return { ok: false, code: "bad-message", reason: "id must match AGENT_ID_RE" };
      }
      if (!isChannel(m["channel"])) {
        return { ok: false, code: "bad-channel", reason: "channel must be a uint32" };
      }
      return { ok: true, message: { t: m["t"], id: m["id"], channel: m["channel"] } };
    }

    case "unsubscribe": {
      if (!isChannel(m["channel"])) {
        return { ok: false, code: "bad-channel", reason: "channel must be a uint32" };
      }
      return { ok: true, message: { t: "unsubscribe", channel: m["channel"] } };
    }

    default:
      return { ok: false, code: "bad-message", reason: "unknown message type" };
  }
}

/** Serializes a server control message for a text frame. */
export function encodeServerAgentControl(message: ServerAgentControl): string {
  return JSON.stringify(message);
}

/**
 * Parses a server control frame on the client. The server is more trusted than
 * a client, but a shape check here turns protocol drift into a clean error
 * instead of an undefined property three call frames later.
 *
 * This is NOT a trust decision about the CONTENT: every string inside a
 * returned `event` is still attacker-controlled agent output and must be
 * rendered as text (see the header).
 */
export function parseServerAgentControl(raw: string): ServerAgentControl | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null) return null;
  const t = (parsed as Record<string, unknown>)["t"];
  if (t === "attached" || t === "event" || t === "state" || t === "error") {
    return parsed as ServerAgentControl;
  }
  return null;
}

/**
 * Validates a server-assigned identity. Used where an identity crosses a
 * boundary it was not minted at — the canvas `Y.Doc`, which any member can
 * write to (SECURITY.md T6), and a replayed event log row.
 */
export function isValidAgentIdentity(v: unknown): v is AgentIdentity {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return (
    typeof o["id"] === "string" &&
    AGENT_ID_RE.test(o["id"]) &&
    typeof o["name"] === "string" &&
    AGENT_NAME_RE.test(o["name"]) &&
    isAgentColour(o["colour"]) &&
    typeof o["avatar"] === "string" &&
    o["avatar"].length > 0 &&
    o["avatar"].length <= MAX_AGENT_AVATAR_LENGTH
  );
}
