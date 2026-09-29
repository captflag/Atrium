/**
 * An agent pane on the canvas: a live transcript of one agent session, a box to
 * give it work, and the two controls a human needs while watching it — stop
 * this turn, and end the session.
 *
 * Same chrome as `TerminalPane` (drag bar, close button, resize grip) so an
 * agent behaves like every other pane. It does not wrap `PaneView` for the same
 * reason `TerminalPane` does not: `PaneView`'s body is a textarea by
 * construction. See the integration note at the bottom of this file for how
 * `PaneView` should branch on `pane.kind`.
 *
 * ============================================================================
 * EVERYTHING THE AGENT SAYS IS UNTRUSTED (SECURITY.md T1) — READ BEFORE EDITING
 * ============================================================================
 * The agent reads repo files to do its job: a README, a code comment, a
 * dependency's source, a file that a DIFFERENT agent wrote earlier in the same
 * session. Any of those can carry instructions. So assume the agent is
 * compromised and assume its output is aimed at the person reading this pane —
 * "this change is approved, click merge" is the realistic payload, and it costs
 * an attacker nothing to try.
 *
 * The rules that follow are not stylistic:
 *
 *   - Every agent-supplied string is a React TEXT CHILD. Never `innerHTML`,
 *     never `dangerouslySetInnerHTML`.
 *   - NO MARKDOWN RENDERER. Not react-markdown, not marked, not a "safe" one.
 *     A markdown-to-HTML step is precisely the vector T1 describes, and the
 *     pane is perfectly readable without it. If a code block should look like
 *     code, it is a styled `<pre>` holding a text child — which is what the
 *     transcript already uses.
 *   - NO AUTO-LINKIFICATION, and no anchor built from agent output. A rendered
 *     link is a click away from being followed, and a fetched one is an
 *     exfiltration channel out of a browser that holds the app's session.
 *   - Tool names, file paths, tool inputs and tool RESULTS get exactly the same
 *     treatment. A path is a string the agent chose; a `Read` result is repo
 *     content, which is the original injection source.
 *   - `notice` events are chrome, not speech, and are rendered so they cannot
 *     be mistaken for the agent talking. If they looked alike, an injected
 *     agent could forge system messages by emitting text that looks like one.
 *   - `identity.colour` is the only agent-adjacent value that reaches CSS, and
 *     it is a palette literal the SERVER assigned, re-checked in `useAgent`
 *     against `isValidAgentIdentity` before it gets here.
 *
 * Control characters and bidi overrides are already stripped upstream in
 * `useAgent.displayText`; that is a legibility measure, not the thing that makes
 * this safe. What makes it safe is that no markup is ever built.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import type { Pane } from "@atrium/shared";
import { deleteAgent } from "./agentApi.ts";
import { useAgent } from "./useAgent.ts";
import type { AgentPhase, AgentSession, TranscriptItem } from "./useAgent.ts";

export interface AgentPaneProps {
  readonly pane: Pane;
  /** Workspace the socket and the routes authorize against. */
  readonly workspaceId: string;
  /**
   * The orchestrator's agent id for this pane. Must match AGENT_ID_RE
   * (/^[A-Za-z0-9_-]{1,64}$/). Resolved by the caller, never by this component
   * — a client that could choose its own agent id could attach to someone
   * else's session by guessing.
   */
  readonly agentId: string;
  readonly selected: boolean;
  onSelect(): void;
  onStartMove(event: React.PointerEvent): void;
  onStartResize(event: React.PointerEvent): void;
  onDelete(): void;
}

const PHASE_LABEL: Readonly<Record<AgentPhase, string>> = {
  connecting: "connecting…",
  unstarted: "no session",
  starting: "starting…",
  attaching: "attaching…",
  attached: "live",
  offline: "offline — reconnecting",
  error: "error",
};

/** Which badge colour a phase earns. `live` defers to the session state below. */
const PHASE_TONE: Readonly<Record<AgentPhase, string>> = {
  connecting: "idle",
  unstarted: "idle",
  starting: "busy",
  attaching: "idle",
  attached: "ok",
  offline: "down",
  error: "down",
};

const DONE_LABEL: Readonly<Record<string, string>> = {
  completed: "finished the turn",
  interrupted: "interrupted",
  stopped: "session ended",
  "max-turns": "hit its turn limit",
  "budget-exhausted": "out of budget",
  error: "ended with an error",
};

/** 12345 -> "12.3k". Display only; never used for a decision. */
function compact(n: number): string {
  if (n < 1_000) return String(n);
  if (n < 1_000_000) return `${(n / 1_000).toFixed(n < 10_000 ? 1 : 0)}k`;
  return `${(n / 1_000_000).toFixed(1)}M`;
}

/** The first line of an already-sanitized preview, for a collapsed summary. */
function firstLine(text: string, max = 90): string {
  const line = text.split("\n", 1)[0] ?? "";
  return line.length > max ? `${line.slice(0, max)}…` : line;
}

export function AgentPane({
  pane,
  workspaceId,
  agentId,
  selected,
  onSelect,
  onStartMove,
  onStartResize,
  onDelete,
}: AgentPaneProps): React.ReactElement {
  const session = useAgent({ workspaceId, agentId });
  const scrollerRef = useRef<HTMLDivElement | null>(null);
  /** Whether the reader is at the bottom. Auto-scroll stops when they scroll up. */
  const pinnedRef = useRef(true);

  // The canvas surface listens for wheel non-passively and turns it into
  // pan/zoom. Inside the transcript, wheel means scroll — so stop it reaching
  // the surface. Ctrl/meta+wheel is still let through, because zooming the
  // canvas while the pointer happens to be over a pane is what a user means by
  // that gesture. Same rule as TerminalPane.
  useEffect(() => {
    const scroller = scrollerRef.current;
    if (scroller === null) return;
    const onWheel = (event: WheelEvent): void => {
      if (event.ctrlKey || event.metaKey) return;
      event.stopPropagation();
    };
    scroller.addEventListener("wheel", onWheel);
    return () => scroller.removeEventListener("wheel", onWheel);
  }, []);

  const transcriptLength = session.transcript.length;
  const lastItem = session.transcript[transcriptLength - 1];
  const lastKey = lastItem?.key ?? "";
  const lastLength = lastItem !== undefined && "text" in lastItem ? lastItem.text.length : 0;

  // Follow the tail while the reader is at the bottom. `lastLength` is in the
  // dependency list so a streaming message that grows in place keeps the view
  // pinned, not just a new entry appearing.
  useEffect(() => {
    if (!pinnedRef.current) return;
    const scroller = scrollerRef.current;
    if (scroller === null) return;
    scroller.scrollTop = scroller.scrollHeight;
  }, [transcriptLength, lastKey, lastLength]);

  const onScroll = useCallback(() => {
    const scroller = scrollerRef.current;
    if (scroller === null) return;
    const distance = scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight;
    pinnedRef.current = distance < 40;
  }, []);

  const close = useCallback(() => {
    // Sessions are server-owned (PLAN.md §6), so nothing else would ever end
    // this one and the harness process would keep running in the container.
    // Fired here rather than from PaneView so the pane owns its own teardown.
    void deleteAgent(workspaceId, agentId);
    onDelete();
  }, [workspaceId, agentId, onDelete]);

  const identity = session.identity;
  const tone = session.phase === "attached" ? stateTone(session) : PHASE_TONE[session.phase];

  return (
    <article
      className={`pane pane--agent${selected ? " pane--selected" : ""}`}
      style={{ left: pane.x, top: pane.y, width: pane.width, height: pane.height }}
      onPointerDown={onSelect}
    >
      <header className="pane__bar" onPointerDown={onStartMove}>
        <span className="pane__kind mono">agent</span>

        {identity !== null && (
          <span className="agent__who" title={`${identity.name} — this workspace's agent`}>
            {/*
              `colour` is one of AGENT_COLOURS, assigned by the server and
              re-validated in useAgent. It is the ONLY agent-adjacent value in
              this file that reaches CSS. The avatar and the name are text
              children: an avatar is never a URL, so no viewer's browser makes a
              request to a host the agent picked.
            */}
            <span className="agent__avatar" style={{ background: identity.colour }}>
              {identity.avatar}
            </span>
            <span className="agent__name">{identity.name}</span>
          </span>
        )}

        <span className={`agent__phase agent__phase--${tone}`}>
          {session.phase === "attached" && session.state !== null
            ? session.state
            : PHASE_LABEL[session.phase]}
        </span>

        <span className="spacer" />

        {session.model !== null && (
          <span className="agent__model mono" title="model serving this session">
            {session.model}
          </span>
        )}
        {session.viewers > 1 && (
          <span className="agent__viewers" title="people watching this agent">
            {session.viewers} watching
          </span>
        )}

        <button
          type="button"
          className="pane__close"
          onPointerDown={(e) => e.stopPropagation()}
          onClick={close}
          aria-label="Close agent pane"
        >
          ×
        </button>
      </header>

      <div
        ref={scrollerRef}
        className="agent__transcript"
        onScroll={onScroll}
        onPointerDown={(e) => e.stopPropagation()}
      >
        {session.trimmed && (
          <p className="agent__gap">
            earlier output was dropped to bound this tab's memory — the session
            still has it
          </p>
        )}
        {session.hole && (
          <p className="agent__gap agent__gap--warn">
            some events could not be replayed after reconnecting, so this
            transcript is missing part of its middle
          </p>
        )}

        {transcriptLength === 0 && session.phase !== "connecting" && (
          <p className="agent__idlehint">
            {session.phase === "unstarted"
              ? "Give this agent a task below. Nothing runs until you do."
              : "Waiting for the agent's first output…"}
          </p>
        )}

        {session.transcript.map((item) => (
          <Entry key={item.key} item={item} />
        ))}
      </div>

      <Composer session={session} />

      <footer className="agent__status">
        {session.detail !== null && <span className="agent__detail">{session.detail}</span>}
        <Usage session={session} />
      </footer>

      <span
        className="pane__resize"
        onPointerDown={(e) => {
          e.stopPropagation();
          onStartResize(e);
        }}
        aria-hidden="true"
      />
    </article>
  );
}

/** Badge tone once attached: the session's own lifecycle drives it. */
function stateTone(session: AgentSession): string {
  switch (session.state) {
    case "running":
    case "starting":
      return "busy";
    case "interrupting":
      return "warn";
    case "idle":
      return "ok";
    case "stopped":
      return "idle";
    case "failed":
      return "down";
    default:
      return "ok";
  }
}

/* ==========================================================================
 * Transcript entries
 * ========================================================================== */

/**
 * One transcript entry.
 *
 * Every `{...}` below interpolates a string as a React text child. There is no
 * markup built from agent output anywhere in this function, and adding any
 * would reopen SECURITY.md T1 — see the file header before changing it.
 */
function Entry({ item }: { readonly item: TranscriptItem }): React.ReactElement {
  switch (item.kind) {
    case "started":
      return (
        <p className="agent__chrome">
          <span className="agent__chromeTag">session</span>
          <span>
            {item.harness} · {item.model} · {item.cwd} · {item.tools.length} tools
          </span>
        </p>
      );

    case "text":
      return (
        <div className={`agent__say${item.subagent ? " agent__say--sub" : ""}`}>
          {item.subagent && <span className="agent__subtag">subagent</span>}
          {/* pre-wrap in CSS keeps the agent's own line breaks without a parser. */}
          <div className="agent__body">{item.text}</div>
          {!item.final && <span className="agent__caret" aria-hidden="true" />}
        </div>
      );

    case "thinking":
      return (
        <details className="agent__thinking">
          <summary>thinking</summary>
          <div className="agent__body">{item.text}</div>
        </details>
      );

    case "tool": {
      const target = firstLine(item.inputPreview);
      const statusLabel =
        item.status === null
          ? "running…"
          : item.durationMs === null
            ? item.status
            : `${item.status} · ${Math.round(item.durationMs)}ms`;
      return (
        <details className={`agent__tool agent__tool--${item.status ?? "pending"}`}>
          {/*
            Collapsed by default: tool results are long, and an unexpanded
            result is also one the reader has not been shown yet. The summary
            carries only the tool name, one line of the input, and the outcome.
          */}
          <summary>
            <span className="agent__toolName mono">{item.tool}</span>
            <span className="agent__toolTarget mono">{target}</span>
            {item.subagent && <span className="agent__subtag">subagent</span>}
            <span className="agent__toolStatus">{statusLabel}</span>
          </summary>
          {item.inputPreview !== "" && (
            <>
              <p className="agent__toolLabel">
                input{item.inputTruncated ? " (truncated)" : ""}
              </p>
              <pre className="agent__pre">{item.inputPreview}</pre>
            </>
          )}
          {item.status !== null && (
            <>
              <p className="agent__toolLabel">
                result{item.outputTruncated ? " (truncated)" : ""}
              </p>
              <pre className="agent__pre">{item.outputPreview}</pre>
            </>
          )}
        </details>
      );
    }

    case "notice":
      // Chrome, NOT agent speech, and visually unlike `text` on purpose: if the
      // two looked alike, an injected agent could forge system messages by
      // saying something that reads like one (agent.ts, AgentNoticeEvent).
      return (
        <p className={`agent__chrome agent__chrome--${item.level}`}>
          <span className="agent__chromeTag">harness</span>
          <span>{item.message}</span>
        </p>
      );

    case "error":
      return (
        <p className="agent__chrome agent__chrome--error">
          <span className="agent__chromeTag">{item.code}</span>
          <span>
            {item.message}
            {item.retryable ? " (retryable)" : ""}
          </span>
        </p>
      );

    case "done":
      return (
        <div className="agent__done">
          <p className="agent__chrome">
            <span className="agent__chromeTag">done</span>
            <span>
              {DONE_LABEL[item.reason] ?? item.reason} · {item.turns} turn
              {item.turns === 1 ? "" : "s"}
            </span>
          </p>
          {item.summary !== null && <div className="agent__body">{item.summary}</div>}
        </div>
      );
  }
}

/* ==========================================================================
 * Composer and controls
 * ========================================================================== */

function Composer({ session }: { readonly session: AgentSession }): React.ReactElement {
  const [draft, setDraft] = useState("");
  const unstarted = session.phase === "unstarted";
  const canSubmit = draft.trim() !== "" && (unstarted || session.canPrompt);

  const submit = useCallback(() => {
    const text = draft.trim();
    if (text === "") return;
    if (unstarted) {
      session.start(text);
    } else if (session.canPrompt) {
      session.prompt(text);
    } else {
      return;
    }
    setDraft("");
  }, [draft, session, unstarted]);

  // The placeholder is the only explanation a disabled composer gets, so it
  // names the actual reason rather than defaulting to "ended" — a pane that is
  // merely reconnecting must not read as a dead session.
  const placeholder = unstarted
    ? "Describe the task, then press Start."
    : session.canPrompt
      ? "Send a follow-up…"
      : session.busy
        ? "The agent is working — interrupt it to redirect."
        : session.phase === "attached"
          ? "This session has ended."
          : PHASE_LABEL[session.phase];

  return (
    <div className="agent__composer" onPointerDown={(e) => e.stopPropagation()}>
      <textarea
        className="agent__input"
        value={draft}
        placeholder={placeholder}
        rows={2}
        // Enter sends, shift+Enter is a newline. Canvas's global Delete/Backspace
        // handler already ignores events whose target is a TEXTAREA, so editing
        // here never deletes the pane.
        onKeyDown={(e) => {
          if (e.key === "Enter" && !e.shiftKey) {
            e.preventDefault();
            submit();
          }
        }}
        onChange={(e) => setDraft(e.target.value)}
      />
      <div className="agent__controls">
        <button
          type="button"
          className="agent__btn agent__btn--go"
          disabled={!canSubmit}
          onClick={submit}
        >
          {unstarted ? "Start" : "Send"}
        </button>
        {/*
          Interrupt and End are separate on purpose. Interrupt cuts the turn and
          leaves the session alive so a human can redirect it — which is the
          entire reason for watching an agent work. End tears the session down;
          it does not touch the sandbox, so terminals and other agents in the
          same container keep running.
        */}
        <button
          type="button"
          className="agent__btn"
          disabled={!session.canInterrupt}
          onClick={() => session.interrupt()}
          title="Stop the current turn; the session stays alive"
        >
          Interrupt
        </button>
        <button
          type="button"
          className="agent__btn agent__btn--stop"
          disabled={!session.canStop}
          onClick={() => session.stop()}
          title="End this agent session (the container is unaffected)"
        >
          End
        </button>
      </div>
    </div>
  );
}

/**
 * Cumulative accounting for the session.
 *
 * `cacheReadInputTokens` is on screen rather than folded into a total because a
 * persistent zero means a silent cache invalidator, not an absent feature —
 * and prompt caching is the single largest cost lever in PLAN.md §8. It is
 * invisible unless the number is shown, so it is shown.
 */
function Usage({ session }: { readonly session: AgentSession }): React.ReactElement | null {
  const usage = session.usage;
  if (usage === null) return null;
  const coldCache = usage.cacheReadInputTokens === 0 && usage.inputTokens > 0;
  return (
    <span className="agent__usage mono">
      <span title="input tokens (cumulative)">in {compact(usage.inputTokens)}</span>
      <span title="output tokens (cumulative)">out {compact(usage.outputTokens)}</span>
      <span
        className={coldCache ? "agent__cache agent__cache--cold" : "agent__cache"}
        title={
          coldCache
            ? "no cached prompt tokens have been read — something is invalidating the cache"
            : "cached input tokens read (cumulative)"
        }
      >
        cache {compact(usage.cacheReadInputTokens)}
      </span>
      {usage.costUsd !== null && (
        <span title="harness estimate, not a billing statement">
          ~${usage.costUsd.toFixed(3)}
        </span>
      )}
    </span>
  );
}

/*
 * INTEGRATION NOTE (PaneView.tsx owns this; this file and Canvas.tsx are not
 * where the branch goes).
 *
 * `PaneView` already branches on `pane.kind === "terminal"`. Add the sibling:
 *
 *   if (pane.kind === "agent") {
 *     return (
 *       <AgentPane
 *         pane={pane}
 *         workspaceId={workspaceId}
 *         // M3b's mapping, identical to M2's for terminals: an agent pane's id
 *         // IS its agent id. Both already satisfy /^[A-Za-z0-9_-]{1,64}$/, and
 *         // the server scopes every lookup by workspace, so a guessed id from
 *         // another workspace resolves to nothing. If the orchestrator ever
 *         // mints agent ids separately, resolve that server-side — never let
 *         // the client choose it.
 *         agentId={pane.id}
 *         selected={selected}
 *         onSelect={onSelect}
 *         onStartMove={onStartMove}
 *         onStartResize={onStartResize}
 *         onDelete={onDelete}
 *       />
 *     );
 *   }
 *
 * Note `onDelete` is passed straight through, unlike the terminal's, which
 * PaneView wraps with `closeTerminal`. AgentPane calls `deleteAgent` itself
 * before invoking `onDelete`, so wrapping it here would send the DELETE twice.
 * (Harmless — it is idempotent — but there should be one call site.)
 *
 * Canvas.tsx needs one toolbar button, next to "Add terminal":
 *
 *   <button type="button" onClick={() => addPaneInView("agent", 480, 460)}>
 *     Add agent
 *   </button>
 *
 * 480x460 is the smallest size where a transcript, the composer and the three
 * controls all fit without the composer eating the transcript.
 *
 * As with the terminal, adding the pane is ALL the button does. No session
 * exists until a human types a task and presses Start, which goes through the
 * authorized POST route — a client cannot spawn an agent by writing to the
 * shared document, and an agent pane that is merely on the canvas is not
 * spending money or touching the repo.
 */
