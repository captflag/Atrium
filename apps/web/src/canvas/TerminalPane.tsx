/**
 * A terminal pane on the canvas.
 *
 * Same chrome as PaneView (drag bar, close button, resize grip) so a terminal
 * behaves like every other pane, with an xterm.js body instead of a textarea.
 * It does not wrap PaneView because PaneView's body is a textarea by
 * construction; see the note at the bottom of this file for how Canvas should
 * branch on `pane.kind`.
 *
 * ============================================================================
 * XTERM UNDER THE CANVAS'S CSS SCALE — the pragmatic choice, stated plainly
 * ============================================================================
 * Panes live inside `.world`, which is one `transform: scale(zoom)`. The
 * decision here is to let that transform scale the terminal like any other
 * pane, and to keep the terminal's GRID independent of zoom.
 *
 * Why that works: CSS transforms do not affect layout. The fit addon measures
 * with `getComputedStyle`, and ResizeObserver reports border-box size — both
 * report untransformed layout pixels. So cols/rows are a function of the pane's
 * canvas-space size alone. Zooming never reflows the pty, which matters here
 * more than usual: the pty is SHARED, and its size is the minimum of every
 * subscriber's viewport (ATTACH_RESIZE_POLICY). Refitting on zoom would mean
 * one person's scroll wheel reflows everyone else's shell.
 *
 * Why it looks fine: xterm.js renders with its DOM renderer by default (the
 * canvas and WebGL renderers are separate addons we do not load), so glyphs are
 * real text nodes and the browser re-rasterises them crisply at any scale. A
 * canvas-backed renderer would be resampled and blurry.
 *
 * What it costs, honestly: xterm maps pointer position to a cell using
 * `getBoundingClientRect()` (transformed) against a cell size in CSS pixels
 * (untransformed). At zoom != 1 those disagree, so click-drag TEXT SELECTION
 * inside the terminal lands on the wrong cell — off by roughly the zoom factor.
 * Keyboard, output, scrollback and copy-from-selection at 100% are unaffected.
 * The fix would be to counter-scale the body by 1/zoom and inflate its layout
 * box by zoom, which restores pointer accuracy but makes cols/rows a function
 * of zoom again — i.e. it trades a selection annoyance for reflowing other
 * people's shells. Not worth it. The pane shows a hint at non-100% zoom instead.
 */

import { useEffect, useRef } from "react";
import type { Pane } from "@atrium/shared";
import { useTerminal } from "./useTerminal.ts";
import "@xterm/xterm/css/xterm.css";

export interface TerminalPaneProps {
  readonly pane: Pane;
  /** Workspace the socket authorizes against. Same id the canvas gateway uses. */
  readonly workspaceId: string;
  /**
   * The orchestrator's terminal id for this pane. Must match TERMINAL_ID_RE
   * (/^[A-Za-z0-9_-]{1,64}$/). Resolved by the caller, never by this component
   * — a client that could choose its own terminal id could attach to someone
   * else's shell by guessing.
   */
  readonly terminalId: string;
  /** Canvas zoom, for the pointer-accuracy hint described above. */
  readonly zoom: number;
  readonly selected: boolean;
  onSelect(): void;
  onStartMove(event: React.PointerEvent): void;
  onStartResize(event: React.PointerEvent): void;
  onDelete(): void;
}

const PHASE_LABEL: Readonly<Record<string, string>> = {
  connecting: "connecting…",
  attaching: "attaching…",
  attached: "live",
  offline: "offline — reconnecting",
  exited: "exited",
  error: "error",
};

export function TerminalPane({
  pane,
  workspaceId,
  terminalId,
  zoom,
  selected,
  onSelect,
  onStartMove,
  onStartResize,
  onDelete,
}: TerminalPaneProps): React.ReactElement {
  const hostRef = useRef<HTMLDivElement | null>(null);
  const session = useTerminal(hostRef, { workspaceId, terminalId });

  // A ResizeObserver inside the hook already catches every size change. This
  // makes the CRDT-driven path explicit: when a *remote* member drags this
  // pane's corner, the new width/height arrive as a re-render, and the terminal
  // refits from the same signal the layout did.
  const { refit } = session;
  useEffect(() => refit(), [pane.width, pane.height, refit]);

  // The canvas surface listens for wheel non-passively and turns it into
  // pan/zoom. Inside a terminal, wheel means scrollback — so stop it from
  // reaching the surface. Ctrl/meta+wheel is still let through, because zooming
  // the canvas while the pointer happens to be over a terminal is what a user
  // means by that gesture.
  useEffect(() => {
    const host = hostRef.current;
    if (host === null) return;
    const onWheel = (event: WheelEvent): void => {
      if (event.ctrlKey || event.metaKey) return;
      event.stopPropagation();
    };
    host.addEventListener("wheel", onWheel);
    return () => host.removeEventListener("wheel", onWheel);
  }, []);

  // Only nag about the zoom/selection caveat on the pane the user is actually
  // working in — at any zoom but 100% it would otherwise be permanent chrome.
  const zoomed = selected && Math.abs(zoom - 1) > 0.01;

  return (
    <article
      className={`pane pane--terminal${selected ? " pane--selected" : ""}`}
      style={{ left: pane.x, top: pane.y, width: pane.width, height: pane.height }}
      onPointerDown={onSelect}
    >
      <header className="pane__bar" onPointerDown={onStartMove}>
        <span className="pane__kind mono">terminal</span>
        <span className={`term__phase term__phase--${session.phase}`}>
          {PHASE_LABEL[session.phase] ?? session.phase}
        </span>
        <span className="spacer" />
        {session.cols > 0 && (
          <span className="term__dims mono" title="pty grid">
            {session.cols}×{session.rows}
          </span>
        )}
        {session.viewers > 1 && (
          <span className="term__viewers" title="viewers attached to this shell">
            {session.viewers} watching
          </span>
        )}
        <button
          type="button"
          className="pane__close"
          onPointerDown={(e) => e.stopPropagation()}
          onClick={onDelete}
          aria-label="Close terminal pane"
        >
          ×
        </button>
      </header>

      {/*
        xterm owns everything below. Output bytes are written to the emulator,
        which renders them into its own text nodes — nothing in this component
        goes near innerHTML or dangerouslySetInnerHTML, and no server-supplied
        string is interpolated into markup (SECURITY.md T6).

        Backspace inside the terminal does not delete the pane: Canvas's global
        key handler ignores events whose target is a TEXTAREA, and xterm's input
        sink is exactly that — its hidden helper textarea.
      */}
      <div ref={hostRef} className="term__host" onPointerDown={() => session.focus()} />

      {(session.detail !== null || session.clamped || zoomed) && (
        <footer className="term__status">
          {session.detail !== null && <span className="term__detail">{session.detail}</span>}
          {session.clamped && (
            <span className="term__hint" title="the pty is sized to the smallest viewer">
              sized down by another viewer
            </span>
          )}
          {zoomed && (
            <span className="term__hint" title="text selection is only cell-accurate at 100% zoom">
              selection needs 100% zoom
            </span>
          )}
        </footer>
      )}

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

/*
 * INTEGRATION NOTE (Canvas.tsx owns this; PaneView.tsx is untouched).
 *
 * Canvas currently renders `<PaneView …/>` for every pane. Branch on kind:
 *
 *   pane.kind === "terminal"
 *     ? <TerminalPane
 *         key={pane.id}
 *         pane={pane}
 *         workspaceId={workspaceId}
 *         terminalId={pane.id}
 *         zoom={viewport.zoom}
 *         selected={pane.id === selected}
 *         onSelect={() => setSelected(pane.id)}
 *         onStartMove={(e) => startMove(pane, e)}
 *         onStartResize={(e) => startResize(pane, e)}
 *         onDelete={() => { room.deletePane(pane.id); setSelected(null); }}
 *       />
 *     : <PaneView … />
 *
 * `terminalId={pane.id}` is the M2 mapping — a terminal pane's id IS its
 * terminal id, and both already satisfy /^[A-Za-z0-9_-]{1,64}$/. If the
 * orchestrator ever mints terminal ids separately from pane ids, resolve it
 * server-side and pass that instead; do NOT let the client choose it.
 */
