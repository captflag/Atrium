/**
 * Pane schema and validation.
 *
 * The canvas document is a CRDT, so any member can write into it. That makes
 * pane payloads untrusted input even though they come from an authenticated
 * teammate (SECURITY.md T6) — a bad payload is stored XSS for everyone in the
 * workspace. Validate on write at the server and again on render.
 *
 * PLAN.md §3: the CRDT holds layout and intent only, never authoritative
 * file content, claims, or agent state.
 */

/** M1 ships notes only. The rest are declared so the union is stable. */
export const PANE_KINDS = ["note", "terminal", "agent", "editor", "preview"] as const;
export type PaneKind = (typeof PANE_KINDS)[number];

export const PANE_MIN_SIZE = 120;
export const PANE_MAX_SIZE = 4000;
/** Canvas is finite in practice; keeps a typo from flinging a pane to 1e９. */
export const CANVAS_EXTENT = 100_000;
export const NOTE_MAX_LENGTH = 20_000;

export interface Pane {
  readonly id: string;
  readonly kind: PaneKind;
  readonly x: number;
  readonly y: number;
  readonly width: number;
  readonly height: number;
  /** Note body. Plain text — never rendered as HTML. */
  readonly text: string;
  /** Client id of the last writer, for attribution in the UI. */
  readonly updatedBy: string;
  readonly updatedAt: number;
}

export type ValidationResult =
  | { readonly ok: true; readonly pane: Pane }
  | { readonly ok: false; readonly reason: string };

function isFiniteInRange(v: unknown, min: number, max: number): v is number {
  return typeof v === "number" && Number.isFinite(v) && v >= min && v <= max;
}

const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

/**
 * Validates an untrusted pane object. Returns a normalized, clamped pane or a
 * reason. Rejects rather than silently repairing anything structural; clamps
 * only numbers, where a drag can legitimately overshoot.
 */
export function validatePane(input: unknown): ValidationResult {
  if (typeof input !== "object" || input === null) {
    return { ok: false, reason: "pane must be an object" };
  }
  const p = input as Record<string, unknown>;

  if (typeof p["id"] !== "string" || !ID_RE.test(p["id"])) {
    return { ok: false, reason: "id must match /^[A-Za-z0-9_-]{1,64}$/" };
  }
  if (typeof p["kind"] !== "string" || !(PANE_KINDS as readonly string[]).includes(p["kind"])) {
    return { ok: false, reason: `kind must be one of ${PANE_KINDS.join(", ")}` };
  }
  if (
    !isFiniteInRange(p["x"], -CANVAS_EXTENT, CANVAS_EXTENT) ||
    !isFiniteInRange(p["y"], -CANVAS_EXTENT, CANVAS_EXTENT)
  ) {
    return { ok: false, reason: "x and y must be finite and within the canvas extent" };
  }
  if (
    !isFiniteInRange(p["width"], PANE_MIN_SIZE, PANE_MAX_SIZE) ||
    !isFiniteInRange(p["height"], PANE_MIN_SIZE, PANE_MAX_SIZE)
  ) {
    return { ok: false, reason: `width and height must be ${PANE_MIN_SIZE}..${PANE_MAX_SIZE}` };
  }
  if (typeof p["text"] !== "string" || p["text"].length > NOTE_MAX_LENGTH) {
    return { ok: false, reason: `text must be a string of at most ${NOTE_MAX_LENGTH} chars` };
  }
  if (typeof p["updatedBy"] !== "string" || !ID_RE.test(p["updatedBy"])) {
    return { ok: false, reason: "updatedBy must be a client id" };
  }
  if (typeof p["updatedAt"] !== "number" || !Number.isFinite(p["updatedAt"])) {
    return { ok: false, reason: "updatedAt must be a finite number" };
  }

  return {
    ok: true,
    pane: {
      id: p["id"],
      kind: p["kind"] as PaneKind,
      x: Math.round(p["x"]),
      y: Math.round(p["y"]),
      width: Math.round(p["width"]),
      height: Math.round(p["height"]),
      text: p["text"],
      updatedBy: p["updatedBy"],
      updatedAt: p["updatedAt"],
    },
  };
}

/** Cursor/viewport state broadcast over Yjs awareness. Ephemeral, never stored. */
export interface Presence {
  readonly userId: string;
  readonly name: string;
  readonly color: string;
  /** Cursor position in canvas coordinates. Absent when off-canvas. */
  readonly cursor?: { readonly x: number; readonly y: number };
}
