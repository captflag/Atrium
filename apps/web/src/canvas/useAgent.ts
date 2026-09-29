/**
 * The M3b agent wire protocol (`@atrium/shared/agent.ts`) bound to a pane.
 *
 * Same shape as `useTerminal`, for the same reasons: the wire format is ours,
 * the reconnect behaviour has to be explicit, and the control channel carries
 * things (viewer count, replay cursor, session lifecycle) no generic client
 * knows about. Where the two differ, the difference is deliberate and noted.
 *
 * ============================================================================
 * EVERY STRING THAT ARRIVES HERE IS UNTRUSTED (SECURITY.md T1)
 * ============================================================================
 * Assume the agent is prompt-injected by repo content — a README, a
 * dependency's source, a file another agent wrote this session. Two things
 * follow, and this hook is shaped around both:
 *
 *   1. Agent output is aimed at the human watching. "This change is approved,
 *      click merge" is a realistic payload. So this hook produces PLAIN STRINGS
 *      and nothing else: no HTML, no parsed markdown, no extracted URLs, no
 *      structured objects a renderer might be tempted to interpret. There is no
 *      sanitizer here because the correct answer is never to build markup at
 *      all. `AgentPane.tsx` renders every one of these strings as a React text
 *      child.
 *   2. Control characters are stripped from anything that goes on screen. Not
 *      because a text node can be escaped by them, but because an agent that
 *      can emit U+202E or a run of nulls can make one line of a transcript
 *      display as something other than what it says. Whitespace an agent
 *      legitimately produced — newlines, tabs — is kept; the pane's `<pre>`
 *      needs it.
 *
 * ============================================================================
 * WHAT THIS HOOK CANNOT DO
 * ============================================================================
 * It cannot start an agent. `subscribe` only ever attaches to a session that
 * already exists; creation is the authorized HTTP route in `agentApi.ts`, which
 * repeats authenticate + membership. `prompt`, `interrupt` and `stop` act on
 * the `channel` the server handed back in `attached` — never on an id this
 * client chose. See the header of `agent.ts` for why that split is the whole
 * security posture of this feature.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import {
  AGENT_MAX_PROMPT_BYTES,
  AGENT_PROTOCOL_VERSION,
  isValidAgentIdentity,
  parseServerAgentControl,
  utf8ByteLength,
} from "@atrium/shared";
import type {
  AgentDoneReason,
  AgentErrorCode,
  AgentEvent,
  AgentIdentity,
  AgentSessionState,
  AgentToolStatus,
  ClientAgentControl,
} from "@atrium/shared";
import { lookupAgent, startAgent } from "./agentApi.ts";
/**
 * The websocket's identity query parameters — the same DEVELOPMENT SHIM the
 * terminal socket carries. `devIdentityQuery` in terminalApi.ts is deliberately
 * the single definition to delete once the upgrade authorizes from a session
 * cookie (SECURITY.md T6, PLAN.md §10 decision #1), so this file imports it
 * rather than minting a second copy.
 */
import { devIdentityQuery } from "./terminalApi.ts";

const RECONNECT_BASE_MS = 500;
const RECONNECT_MAX_MS = 10_000;

/**
 * Transcript entries kept in the pane. Older entries are dropped from the head
 * rather than allowed to grow a tab out of memory over a long session; the pane
 * says so instead of pretending it has the whole thing. Durable replay from the
 * event log is M5 (PLAN.md §6).
 */
const MAX_TRANSCRIPT_ITEMS = 600;

/** Cap on one merged assistant message, in UTF-16 units. Display bound only. */
const MAX_MERGED_TEXT_CHARS = 120_000;

/** How far back to look for the `tool_call` a `tool_result` belongs to. */
const TOOL_MATCH_WINDOW = 250;

/* ==========================================================================
 * Public shape
 * ========================================================================== */

export type AgentPhase =
  /** Asking the server whether this pane has a session. */
  | "connecting"
  /** No session exists. The pane shows its composer; a human starts the work. */
  | "unstarted"
  /** A human pressed Start; the authorized create call is in flight. */
  | "starting"
  /** Socket open, `subscribe` sent, waiting for `attached`. */
  | "attaching"
  /** Live. Events are arriving. */
  | "attached"
  /** Socket dropped or the server asked us to retry; backing off. */
  | "offline"
  /** Non-retryable. No further attempts without a human. */
  | "error";

/**
 * One rendered line of transcript.
 *
 * Deliberately flat and stringly-typed: this is what reaches JSX, and a field
 * that is already a string cannot be mistaken for something to interpret.
 * `key` is derived from the server's `seq`, which is monotonic and gap-free per
 * session, so React's reconciliation is stable across a replay.
 */
export type TranscriptItem =
  | {
      readonly kind: "started";
      readonly key: string;
      readonly seq: number;
      readonly model: string;
      readonly cwd: string;
      readonly tools: readonly string[];
      readonly harness: string;
    }
  | {
      readonly kind: "text";
      readonly key: string;
      readonly seq: number;
      readonly messageId: string;
      readonly text: string;
      /** False while more chunks of this message are still expected. */
      readonly final: boolean;
      /** True when a subagent produced it, not the main loop. */
      readonly subagent: boolean;
    }
  | {
      readonly kind: "thinking";
      readonly key: string;
      readonly seq: number;
      readonly messageId: string;
      readonly text: string;
    }
  | {
      readonly kind: "tool";
      readonly key: string;
      readonly seq: number;
      readonly toolUseId: string;
      readonly tool: string;
      readonly inputPreview: string;
      readonly inputTruncated: boolean;
      readonly subagent: boolean;
      /** null until the matching `tool_result` arrives. */
      readonly status: AgentToolStatus | null;
      readonly outputPreview: string;
      readonly outputTruncated: boolean;
      readonly durationMs: number | null;
    }
  | {
      readonly kind: "notice";
      readonly key: string;
      readonly seq: number;
      readonly level: "info" | "warn";
      readonly message: string;
    }
  | {
      readonly kind: "error";
      readonly key: string;
      readonly seq: number;
      readonly code: AgentErrorCode;
      readonly message: string;
      readonly retryable: boolean;
    }
  | {
      readonly kind: "done";
      readonly key: string;
      readonly seq: number;
      readonly reason: AgentDoneReason;
      readonly turns: number;
      readonly summary: string | null;
    };

/**
 * Cumulative token and cost accounting, as the latest `usage` event reported
 * it. CUMULATIVE — the pane reads this, it never sums a series (agent.ts).
 */
export interface AgentUsage {
  readonly model: string;
  readonly inputTokens: number;
  readonly outputTokens: number;
  readonly cacheReadInputTokens: number;
  readonly cacheCreationInputTokens: number;
  readonly costUsd: number | null;
}

export interface AgentSession {
  readonly phase: AgentPhase;
  /** Operator-safe status text, already stripped of control characters. */
  readonly detail: string | null;
  /** Server-reported lifecycle. null before the first `attached`. */
  readonly state: AgentSessionState | null;
  /** Server-assigned, validated. null until `attached`. */
  readonly identity: AgentIdentity | null;
  readonly model: string | null;
  /** Viewers attached to this session, including us. 0 until `attached`. */
  readonly viewers: number;
  readonly transcript: readonly TranscriptItem[];
  /** True when older entries were dropped from the head to bound memory. */
  readonly trimmed: boolean;
  /**
   * True when the server could not replay the whole gap after a reconnect, so
   * the transcript is missing its middle. Said out loud in the pane rather than
   * rendering a plausible-looking transcript that quietly lost events.
   */
  readonly hole: boolean;
  readonly usage: AgentUsage | null;
  /** A turn is in flight; `prompt` would be rejected with `busy`. */
  readonly busy: boolean;
  /** The session can accept a follow-up turn right now. */
  readonly canPrompt: boolean;
  /** A turn is running and can be cut short. */
  readonly canInterrupt: boolean;
  /** The session is alive and can be torn down. */
  readonly canStop: boolean;

  /** Create the session and give it its first task. Only valid when `unstarted`. */
  start(task: string): void;
  /** Send a follow-up turn. No-op unless `canPrompt`. */
  prompt(text: string): void;
  /** Cut the current turn short; the session survives and returns to idle. */
  interrupt(): void;
  /** End the session. Terminal. Does not touch the sandbox. */
  stop(): void;
}

export interface UseAgentOptions {
  readonly workspaceId: string;
  /** The orchestrator's agent id. Must match AGENT_ID_RE. */
  readonly agentId: string;
}

/* ==========================================================================
 * Untrusted-text handling
 * ========================================================================== */

/**
 * Makes an agent-supplied string safe to put on screen AS TEXT.
 *
 * Keeps `\n` and `\t` — the pane renders transcript bodies in a `<pre>` and
 * losing them would mangle every code snippet an agent shows. Everything else
 * below U+0020, the C1 range, and the bidirectional-override characters are
 * replaced with a space: a run of them lets an agent make a line display as
 * something other than what it says, which is the whole point of an injection
 * aimed at the human (SECURITY.md T1).
 *
 * This is NOT sanitization in the HTML sense and must never be mistaken for it.
 * The reason no escaping is needed is that the result is only ever handed to
 * React as a text child.
 */
function displayText(raw: unknown, max: number): string {
  if (typeof raw !== "string") return "";
  let out = "";
  for (const ch of raw) {
    const code = ch.codePointAt(0) ?? 0;
    const keep =
      ch === "\n" ||
      ch === "\t" ||
      !(
        code < 0x20 ||
        (code >= 0x7f && code <= 0x9f) ||
        // LRE/RLE/PDF/LRO/RLO and the isolate family: display-order overrides.
        (code >= 0x202a && code <= 0x202e) ||
        (code >= 0x2066 && code <= 0x2069)
      );
    out += keep ? ch : " ";
    if (out.length >= max) break;
  }
  return out;
}

/** Single-line variant, for chrome: badges, status lines, tool names. */
function displayLine(raw: unknown, max = 200): string {
  return displayText(raw, max).replace(/\s+/g, " ").trim();
}

/* ==========================================================================
 * Transcript reduction
 * ========================================================================== */

interface Snapshot {
  phase: AgentPhase;
  detail: string | null;
  state: AgentSessionState | null;
  identity: AgentIdentity | null;
  model: string | null;
  viewers: number;
  transcript: readonly TranscriptItem[];
  trimmed: boolean;
  hole: boolean;
  usage: AgentUsage | null;
  /** Highest seq applied. The replay cursor on the next reconnect. */
  lastSeq: number;
}

const EMPTY: Snapshot = {
  phase: "connecting",
  detail: null,
  state: null,
  identity: null,
  model: null,
  viewers: 0,
  transcript: [],
  trimmed: false,
  hole: false,
  usage: null,
  lastSeq: 0,
};

function pushItem(
  snapshot: Snapshot,
  item: TranscriptItem,
): Pick<Snapshot, "transcript" | "trimmed"> {
  const next = [...snapshot.transcript, item];
  if (next.length <= MAX_TRANSCRIPT_ITEMS) {
    return { transcript: next, trimmed: snapshot.trimmed };
  }
  return {
    transcript: next.slice(next.length - MAX_TRANSCRIPT_ITEMS),
    trimmed: true,
  };
}

/**
 * Folds one event into the snapshot.
 *
 * The only ordering relied on is `seq`, which the SERVER assigns — monotonic
 * and gap-free from 1. `at` is a display string from a clock we do not control
 * and is never used to order anything (agent.ts, `AgentEventBase`). Events at
 * or below `lastSeq` are dropped: a reconnect asks for `seq > lastSeq`, but a
 * server that re-sent one must not double it into the transcript.
 */
function applyEvent(snapshot: Snapshot, event: AgentEvent): Snapshot {
  if (typeof event.seq !== "number" || !Number.isFinite(event.seq)) return snapshot;
  if (event.seq <= snapshot.lastSeq) return snapshot;
  const seq = event.seq;
  const key = `e${seq}`;
  const base = { ...snapshot, lastSeq: seq };

  switch (event.kind) {
    case "started":
      return {
        ...base,
        model: displayLine(event.model, 64) || base.model,
        ...pushItem(snapshot, {
          kind: "started",
          key,
          seq,
          model: displayLine(event.model, 64),
          cwd: displayLine(event.cwd, 200),
          tools: (Array.isArray(event.tools) ? event.tools : [])
            .slice(0, 64)
            .map((t) => displayLine(t, 40))
            .filter((t) => t !== ""),
          harness: displayLine(event.harness, 40),
        }),
      };

    case "text": {
      const text = displayText(event.text, MAX_MERGED_TEXT_CHARS);
      const messageId = displayLine(event.messageId, 64);
      const last = snapshot.transcript[snapshot.transcript.length - 1];
      // Chunks of one assistant message are keyed by `messageId`, not by
      // adjacency — but they are only merged when they are also adjacent, so a
      // tool call landing between two chunks stays visible in the order it
      // happened.
      if (
        last !== undefined &&
        last.kind === "text" &&
        last.messageId === messageId &&
        !last.final &&
        last.text.length < MAX_MERGED_TEXT_CHARS
      ) {
        const merged: TranscriptItem = {
          ...last,
          text: (last.text + text).slice(0, MAX_MERGED_TEXT_CHARS),
          final: event.final === true,
        };
        return {
          ...base,
          transcript: [...snapshot.transcript.slice(0, -1), merged],
        };
      }
      return {
        ...base,
        ...pushItem(snapshot, {
          kind: "text",
          key,
          seq,
          messageId,
          text,
          final: event.final === true,
          subagent: typeof event.parentToolUseId === "string",
        }),
      };
    }

    case "thinking":
      return {
        ...base,
        ...pushItem(snapshot, {
          kind: "thinking",
          key,
          seq,
          messageId: displayLine(event.messageId, 64),
          text: displayText(event.text, MAX_MERGED_TEXT_CHARS),
        }),
      };

    case "tool_call":
      return {
        ...base,
        ...pushItem(snapshot, {
          kind: "tool",
          key,
          seq,
          toolUseId: displayLine(event.toolUseId, 80),
          tool: displayLine(event.tool, 40),
          inputPreview: displayText(event.inputPreview, 8_000),
          inputTruncated: event.truncated === true,
          subagent: typeof event.parentToolUseId === "string",
          status: null,
          outputPreview: "",
          outputTruncated: false,
          durationMs: null,
        }),
      };

    case "tool_result": {
      const toolUseId = displayLine(event.toolUseId, 80);
      const status: AgentToolStatus =
        event.status === "error" || event.status === "denied" ? event.status : "ok";
      const outputPreview = displayText(event.outputPreview, 8_000);
      const durationMs =
        typeof event.durationMs === "number" && Number.isFinite(event.durationMs)
          ? event.durationMs
          : null;

      const from = Math.max(0, snapshot.transcript.length - TOOL_MATCH_WINDOW);
      for (let i = snapshot.transcript.length - 1; i >= from; i -= 1) {
        const candidate = snapshot.transcript[i];
        if (
          candidate === undefined ||
          candidate.kind !== "tool" ||
          candidate.toolUseId !== toolUseId ||
          candidate.status !== null
        ) {
          continue;
        }
        const filled: TranscriptItem = {
          ...candidate,
          status,
          outputPreview,
          outputTruncated: event.truncated === true,
          durationMs,
        };
        const transcript = [...snapshot.transcript];
        transcript[i] = filled;
        return { ...base, transcript };
      }

      // No matching call — a replay hole, or a result for a call that fell off
      // the head of the buffer. Show it rather than dropping it silently.
      return {
        ...base,
        ...pushItem(snapshot, {
          kind: "tool",
          key,
          seq,
          toolUseId,
          tool: displayLine(event.tool, 40),
          inputPreview: "",
          inputTruncated: false,
          subagent: false,
          status,
          outputPreview,
          outputTruncated: event.truncated === true,
          durationMs,
        }),
      };
    }

    case "usage": {
      // CUMULATIVE: the latest event is the running total. Never summed.
      const num = (v: unknown): number =>
        typeof v === "number" && Number.isFinite(v) && v >= 0 ? v : 0;
      return {
        ...base,
        usage: {
          model: displayLine(event.model, 64),
          inputTokens: num(event.inputTokens),
          outputTokens: num(event.outputTokens),
          cacheReadInputTokens: num(event.cacheReadInputTokens),
          cacheCreationInputTokens: num(event.cacheCreationInputTokens),
          costUsd:
            typeof event.costUsd === "number" && Number.isFinite(event.costUsd)
              ? event.costUsd
              : null,
        },
      };
    }

    case "done": {
      const summary = displayText(event.summary, 4_000);
      return {
        ...base,
        ...pushItem(snapshot, {
          kind: "done",
          key,
          seq,
          reason: event.reason,
          turns:
            typeof event.turns === "number" && Number.isFinite(event.turns) ? event.turns : 0,
          summary: summary === "" ? null : summary,
        }),
      };
    }

    case "error":
      return {
        ...base,
        ...pushItem(snapshot, {
          kind: "error",
          key,
          seq,
          code: event.code,
          message: displayLine(event.message, 400) || "the agent reported an error",
          retryable: event.retryable === true,
        }),
      };

    case "notice":
      return {
        ...base,
        ...pushItem(snapshot, {
          kind: "notice",
          key,
          seq,
          level: event.level === "warn" ? "warn" : "info",
          message: displayLine(event.message, 400),
        }),
      };
  }
}

/* ==========================================================================
 * The hook
 * ========================================================================== */

/** What the effect exposes to the component, without re-running on each render. */
interface Actions {
  start(task: string): void;
  prompt(text: string): void;
  interrupt(): void;
  stop(): void;
}

const BUSY_STATES: readonly AgentSessionState[] = ["starting", "running", "interrupting"];
const TERMINAL_STATES: readonly AgentSessionState[] = ["stopped", "failed"];

export function useAgent({ workspaceId, agentId }: UseAgentOptions): AgentSession {
  const actionsRef = useRef<Actions | null>(null);
  const [snapshot, setSnapshot] = useState<Snapshot>(EMPTY);

  useEffect(() => {
    let disposed = false;
    /** Set when there is no point retrying without a human. */
    let finished = false;
    let attempt = 0;
    let reconnectTimer: number | undefined;
    let socket: WebSocket | null = null;
    let channel: number | null = null;
    let pendingRequestId: string | null = null;
    let requestSeq = 0;
    /** Mirrors `snapshot.lastSeq` for the reconnect cursor, without a re-render. */
    let cursor = 0;
    /** Mirrors `snapshot.state`, so the action guards do not close over state. */
    let sessionState: AgentSessionState | null = null;

    const setPhase = (phase: AgentPhase, detail: string | null = null): void => {
      setSnapshot((s) => ({ ...s, phase, detail }));
    };

    /* ---- sending --------------------------------------------------------- */

    /**
     * There is no `encodeClientAgentControl` in the shared package (the server
     * owns the encode side, as with the terminal), so control messages are
     * stringified here — typed as `ClientAgentControl` so a protocol change is
     * a compile error rather than a `bad-message` at runtime.
     */
    const send = (message: ClientAgentControl): void => {
      if (socket === null || socket.readyState !== WebSocket.OPEN) return;
      socket.send(JSON.stringify(message));
    };

    const nextRequestId = (): string => {
      requestSeq += 1;
      return `req-${requestSeq}`;
    };

    /* ---- control message handling ---------------------------------------- */

    const onControl = (raw: string): void => {
      const message = parseServerAgentControl(raw);
      if (message === null) return;

      switch (message.t) {
        case "attached": {
          if (message.id !== pendingRequestId) return; // stale request, ignore
          pendingRequestId = null;
          channel = message.channel;
          attempt = 0;
          const asked = cursor;
          // `replayFromSeq` greater than `asked + 1` means the server could not
          // serve the whole gap: the transcript is missing its middle, and the
          // honest thing is to say so (agent.ts, ServerAgentAttached).
          const gap = message.replayFromSeq > 0 && message.replayFromSeq > asked + 1;
          sessionState = message.state;
          // `parseServerAgentControl` checks the envelope's shape, not this.
          // `identity.colour` becomes an inline style two files from here, so
          // it goes through the palette check first — an unvalidated colour
          // reaching CSS is stored XSS for every viewer (SECURITY.md T6), and
          // an unvalidated name is impersonation in the presence chrome.
          const identity = isValidAgentIdentity(message.identity) ? message.identity : null;
          setSnapshot((s) => ({
            ...s,
            phase: "attached",
            detail: null,
            state: message.state,
            identity: identity ?? s.identity,
            model: displayLine(message.model, 64) || s.model,
            viewers: typeof message.viewers === "number" ? message.viewers : 1,
            hole: s.hole || gap,
          }));
          return;
        }

        case "event": {
          if (channel === null || message.channel !== channel) return;
          const event = message.event;
          if (typeof event !== "object" || event === null) return;
          if (typeof event.seq === "number" && event.seq > cursor) cursor = event.seq;
          setSnapshot((s) => applyEvent(s, event));
          return;
        }

        case "state": {
          if (channel === null || message.channel !== channel) return;
          sessionState = message.state;
          setSnapshot((s) => ({
            ...s,
            state: message.state,
            viewers: typeof message.viewers === "number" ? message.viewers : s.viewers,
          }));
          return;
        }

        case "error": {
          const text = displayLine(message.message, 400) || "the server rejected that";

          // `not-found` on a subscribe means the session is gone — the server
          // restarted, or someone ended it. That is not an error state to sit
          // in: it is the same "no session, give it a task" state the pane
          // starts in. Re-creating it automatically is exactly what this pane
          // must not do (see agentApi.ts).
          if (message.code === "not-found") {
            channel = null;
            sessionState = null;
            setSnapshot((s) => ({
              ...s,
              phase: "unstarted",
              detail: "this session has ended — give it a new task to start another",
              state: null,
              viewers: 0,
            }));
            closeSocket();
            return;
          }

          if (message.retryable) {
            setPhase("offline", text);
            scheduleRetry(subscribe);
            return;
          }

          // `busy` and `payload-too-large` are answers to one request, not a
          // reason to tear the socket down: the session is still fine.
          if (message.code === "busy" || message.code === "payload-too-large") {
            setPhase(channel === null ? "offline" : "attached", text);
            return;
          }

          finished = true;
          channel = null;
          setSnapshot((s) => ({ ...s, phase: "error", detail: text, viewers: 0 }));
          closeSocket();
          return;
        }
      }
    };

    /* ---- socket ---------------------------------------------------------- */

    /**
     * Closes a socket without tripping the reconnect path, and without the
     * "closed before the connection is established" warning a CONNECTING socket
     * produces. Same shape as useTerminal/useRoom — React StrictMode mounts
     * effects twice in development, so this runs on every mount.
     */
    const closeSocket = (): void => {
      const ws = socket;
      socket = null;
      if (ws === null) return;
      ws.onclose = null;
      ws.onerror = null;
      ws.onmessage = null;
      if (ws.readyState === WebSocket.CONNECTING) {
        ws.addEventListener("open", () => ws.close(), { once: true });
      } else if (ws.readyState === WebSocket.OPEN) {
        ws.close();
      }
    };

    const scheduleRetry = (run: () => void): void => {
      if (disposed || finished) return;
      const delay = Math.min(RECONNECT_BASE_MS * 2 ** attempt, RECONNECT_MAX_MS);
      attempt += 1;
      reconnectTimer = window.setTimeout(() => {
        if (disposed || finished) return;
        run();
      }, delay);
    };

    const subscribe = (): void => {
      if (disposed || finished) return;
      const id = nextRequestId();
      pendingRequestId = id;
      setPhase("attaching");
      // Replay from where this client got to. The server re-authorizes rather
      // than trusting the subscription that produced the cursor (T11), and
      // reports what it could actually serve in `replayFromSeq`.
      send({ t: "subscribe", id, agentId, fromSeq: cursor });
    };

    const openSocket = (): void => {
      if (disposed || finished) return;

      const wsScheme = window.location.protocol === "https:" ? "wss" : "ws";
      const url =
        `${wsScheme}://${window.location.host}/rt/agent` +
        `?workspace=${encodeURIComponent(workspaceId)}` +
        `&v=${AGENT_PROTOCOL_VERSION}` +
        devIdentityQuery();

      const ws = new WebSocket(url);
      socket = ws;

      ws.onopen = () => {
        attempt = 0;
        subscribe();
      };

      // Text frames only. There is no binary channel on this protocol: agent
      // events are structured and low-rate, unlike a pty's byte stream.
      ws.onmessage = (event: MessageEvent<unknown>) => {
        if (typeof event.data !== "string") return;
        onControl(event.data);
      };

      ws.onclose = () => {
        socket = null;
        channel = null;
        if (disposed || finished) return;
        setPhase("offline", "connection lost — reconnecting");
        scheduleRetry(reconnect);
      };
      ws.onerror = () => ws.close();
    };

    /**
     * One attach attempt against a session that should already exist.
     *
     * Distinct from `connect()` in that a `lookupAgent` miss here is not the
     * first-load "no session yet" case — it means the session went away — and
     * `onControl` turns the resulting `not-found` into the unstarted state.
     */
    const reconnect = (): void => {
      if (disposed || finished) return;
      channel = null;
      pendingRequestId = null;
      openSocket();
    };

    /**
     * Mount: find out whether this pane has a session, and attach if it does.
     *
     * Unlike `ensureTerminal`, this NEVER creates one. An agent session spends
     * money at the broker and writes to the repo; a tab reopening must not
     * start that on its own. See agentApi.ts.
     */
    const connect = (): void => {
      if (disposed || finished) return;
      if (attempt === 0) setPhase("connecting");

      void lookupAgent(workspaceId, agentId).then((result) => {
        if (disposed || finished) return;
        if (result.ok) {
          setSnapshot((s) => ({
            ...s,
            identity: result.session.identity ?? s.identity,
            model: result.session.model ?? s.model,
          }));
          openSocket();
          return;
        }
        if (result.reason === "absent") {
          setSnapshot((s) => ({ ...s, phase: "unstarted", detail: null, viewers: 0 }));
          return;
        }
        if (result.retryable) {
          setPhase("offline", result.message);
          scheduleRetry(connect);
          return;
        }
        finished = true;
        setSnapshot((s) => ({ ...s, phase: "error", detail: result.message, viewers: 0 }));
      });
    };

    /* ---- actions --------------------------------------------------------- */

    actionsRef.current = {
      start(task: string): void {
        const trimmed = task.trim();
        if (trimmed === "" || disposed) return;
        if (socket !== null || channel !== null) return; // already attached
        finished = false;
        attempt = 0;
        if (reconnectTimer !== undefined) window.clearTimeout(reconnectTimer);
        // A new session starts a new transcript: the one on screen belonged to
        // the session that ended, and running the two together would read as
        // one continuous history that never happened.
        cursor = 0;
        sessionState = null;
        setSnapshot({ ...EMPTY, phase: "starting" });

        void startAgent(workspaceId, agentId, trimmed).then((result) => {
          if (disposed) return;
          if (result.ok) {
            setSnapshot((s) => ({
              ...s,
              identity: result.session.identity ?? s.identity,
              model: result.session.model ?? s.model,
            }));
            openSocket();
            return;
          }
          // Failures land back in `unstarted` with the reason on screen, even
          // the retryable ones. A start spends money at the broker and writes
          // to the repo; putting that on a retry timer would run it while
          // nobody is watching. The button is the retry.
          const message =
            result.reason === "absent"
              ? "the server would not start a session for this pane"
              : result.message;
          setSnapshot((s) => ({ ...s, phase: "unstarted", detail: message }));
        });
      },

      prompt(text: string): void {
        const trimmed = text.trim();
        if (trimmed === "" || channel === null) return;
        if (sessionState !== null && BUSY_STATES.includes(sessionState)) return;
        if (utf8ByteLength(trimmed) > AGENT_MAX_PROMPT_BYTES) {
          setPhase("attached", "that prompt is too large to send");
          return;
        }
        send({ t: "prompt", id: nextRequestId(), channel, text: trimmed });
      },

      interrupt(): void {
        if (channel === null) return;
        send({ t: "interrupt", id: nextRequestId(), channel });
      },

      stop(): void {
        if (channel === null) return;
        send({ t: "stop", id: nextRequestId(), channel });
      },
    };

    connect();

    /* ---- teardown -------------------------------------------------------- */

    return () => {
      disposed = true;
      actionsRef.current = null;
      if (reconnectTimer !== undefined) window.clearTimeout(reconnectTimer);
      // Detach politely so the server drops this viewer from the count
      // immediately rather than waiting for the socket to time out. This ends
      // the SUBSCRIPTION, never the session: the agent keeps working, which is
      // the product (PLAN.md §6).
      if (channel !== null) send({ t: "unsubscribe", channel });
      closeSocket();
    };
  }, [workspaceId, agentId]);

  const start = useCallback((task: string) => actionsRef.current?.start(task), []);
  const prompt = useCallback((text: string) => actionsRef.current?.prompt(text), []);
  const interrupt = useCallback(() => actionsRef.current?.interrupt(), []);
  const stop = useCallback(() => actionsRef.current?.stop(), []);

  const state = snapshot.state;
  const busy = state !== null && BUSY_STATES.includes(state);
  const ended = state !== null && TERMINAL_STATES.includes(state);
  const live = snapshot.phase === "attached";

  return {
    phase: snapshot.phase,
    detail: snapshot.detail,
    state,
    identity: snapshot.identity,
    model: snapshot.model,
    viewers: snapshot.viewers,
    transcript: snapshot.transcript,
    trimmed: snapshot.trimmed,
    hole: snapshot.hole,
    usage: snapshot.usage,
    busy,
    canPrompt: live && !busy && !ended,
    canInterrupt: live && busy,
    canStop: live && !ended,
    start,
    prompt,
    interrupt,
    stop,
  };
}
