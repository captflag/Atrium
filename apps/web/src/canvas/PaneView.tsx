/**
 * One pane on the canvas, dispatched by `pane.kind`.
 *
 * PLAN.md §1: "everything later is a pane type". This is where that promise is
 * kept — the canvas renders `PaneView` for every pane and does not know which
 * kinds exist. A "terminal" pane hands off to `TerminalPane` (its own chrome,
 * an xterm body); everything else keeps M1's note behaviour, a plain textarea.
 *
 * Unknown kinds fall through to the note body deliberately: `PANE_KINDS`
 * already declares agent/editor/preview and a member on a newer client can put
 * one in the shared document today. A pane that renders as an empty note is a
 * pane you can move and delete, which beats an exception in the canvas.
 */

import type { Pane } from "@atrium/shared";
import { NOTE_MAX_LENGTH } from "@atrium/shared";
import { TerminalPane } from "./TerminalPane.tsx";
import { closeTerminal } from "./terminalApi.ts";

interface Props {
  readonly pane: Pane;
  /** Workspace the pane belongs to. Terminal panes authorize their socket with it. */
  readonly workspaceId: string;
  /** Canvas zoom. Terminal panes use it for the selection-accuracy hint. */
  readonly zoom: number;
  readonly selected: boolean;
  onSelect(): void;
  onStartMove(event: React.PointerEvent): void;
  onStartResize(event: React.PointerEvent): void;
  onChangeText(text: string): void;
  onDelete(): void;
}

export function PaneView({
  pane,
  workspaceId,
  zoom,
  selected,
  onSelect,
  onStartMove,
  onStartResize,
  onChangeText,
  onDelete,
}: Props): React.ReactElement {
  if (pane.kind === "terminal") {
    return (
      <TerminalPane
        pane={pane}
        workspaceId={workspaceId}
        // M2's mapping: a terminal pane's id IS its terminal id. Both already
        // satisfy /^[A-Za-z0-9_-]{1,64}$/, and the server scopes every lookup
        // by workspace, so a guessed id from another workspace resolves to
        // nothing. If the orchestrator ever mints terminal ids separately, that
        // mapping is resolved server-side — never chosen by the client.
        terminalId={pane.id}
        zoom={zoom}
        selected={selected}
        onSelect={onSelect}
        onStartMove={onStartMove}
        onStartResize={onStartResize}
        onDelete={() => {
          // Deleting the pane is the only "close this shell" gesture there is.
          // Sessions are server-owned (PLAN.md §6), so nothing else would ever
          // end it and the container would keep the process forever.
          void closeTerminal(workspaceId, pane.id);
          onDelete();
        }}
      />
    );
  }

  return (
    <article
      className={`pane${selected ? " pane--selected" : ""}`}
      style={{ left: pane.x, top: pane.y, width: pane.width, height: pane.height }}
      onPointerDown={onSelect}
    >
      <header className="pane__bar" onPointerDown={onStartMove}>
        <span className="pane__kind mono">{pane.kind}</span>
        <button
          type="button"
          className="pane__close"
          onPointerDown={(e) => e.stopPropagation()}
          onClick={onDelete}
          aria-label="Delete pane"
        >
          ×
        </button>
      </header>

      {/*
        Note bodies render into a textarea's value — text, never HTML.
        Nothing in a pane payload is ever passed to dangerouslySetInnerHTML
        (SECURITY.md T6).
      */}
      <textarea
        className="pane__text"
        value={pane.text}
        maxLength={NOTE_MAX_LENGTH}
        placeholder="Type a note…"
        onChange={(e) => onChangeText(e.target.value)}
        onPointerDown={(e) => e.stopPropagation()}
      />

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
