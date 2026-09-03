import type { Pane } from "@atrium/shared";
import { NOTE_MAX_LENGTH } from "@atrium/shared";

interface Props {
  readonly pane: Pane;
  readonly selected: boolean;
  onSelect(): void;
  onStartMove(event: React.PointerEvent): void;
  onStartResize(event: React.PointerEvent): void;
  onChangeText(text: string): void;
  onDelete(): void;
}

export function PaneView({
  pane,
  selected,
  onSelect,
  onStartMove,
  onStartResize,
  onChangeText,
  onDelete,
}: Props): React.ReactElement {
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
