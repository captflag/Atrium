/**
 * Terminal wire protocol (M2).
 *
 * One WebSocket at `/rt/terminal?workspace=<id>` carries any number of
 * terminals. Authorization happens at the HTTP upgrade, before a single frame
 * is read — same rule as the canvas gateway (SECURITY.md T6). Nothing in this
 * file authorizes anything; a `subscribe` naming a terminal the caller may not
 * see is answered with an `error`, never with output.
 *
 * ============================================================================
 * FRAMING — the one decision everything else follows from
 * ============================================================================
 * The protocol is SPLIT across the two WebSocket frame types:
 *
 *   TEXT frames   control messages, JSON, UTF-8. Low rate.
 *   BINARY frames terminal bytes. High rate, hot path.
 *
 * **Terminal output is bytes, and stays bytes end to end.** A pty emits an
 * arbitrary byte stream: ANSI escapes, C1 controls, whatever a program writes
 * to a tty, and output that is not valid UTF-8 at all (`cat` a JPEG). Chunk
 * boundaries fall wherever the read did — a multi-byte UTF-8 sequence or an
 * escape sequence WILL be split across two frames under load.
 *
 * Therefore:
 *   - Never decode a chunk in isolation. There is no "the string for this
 *     frame"; there is only a stream that xterm.js reassembles.
 *   - Never JSON-encode or base64 terminal bytes. JSON forces a decode that
 *     mangles invalid UTF-8 into U+FFFD, permanently. Base64 avoids that at a
 *     33% size cost and an allocation per chunk, on the hottest path we have.
 *   - The server treats these bytes as opaque cargo: it does not parse, filter,
 *     transform, or log them. `pty.onData` bytes go on the wire unmodified,
 *     and `xterm.write(chunk)` takes the `Uint8Array` directly.
 *
 * BINARY FRAME LAYOUT — fixed 5-byte header, big-endian:
 *
 *     byte  0      opcode      (OP_INPUT | OP_OUTPUT)
 *     bytes 1..4   channel     uint32, big-endian
 *     bytes 5..    payload     raw pty bytes, unmodified
 *
 * The channel is a small integer the SERVER assigns in `attached`, not a
 * terminal id string, so the hot path carries 5 bytes of overhead instead of a
 * variable-length identifier that would have to be validated per frame.
 * Channels are scoped to one socket and are never reused after `exit`.
 *
 * ORDERING AND LOSS. WebSocket gives ordered, reliable delivery per socket, so
 * output arrives in pty order. On reconnect the client gets a fresh socket,
 * fresh channels, and whatever backlog the server still holds
 * (`attached.backlogBytes`) — the server does not attempt byte-exact resume in
 * M2. Durable replay is M5's problem (PLAN.md §6).
 *
 * MULTIPLE VIEWERS (the M2 done-when criterion). One pty, many subscribers.
 * Every subscriber's OP_INPUT is written to the same pty master; every
 * subscriber receives the same OP_OUTPUT. There is no per-viewer echo and no
 * input arbitration — it is one shared shell, exactly as if two people were at
 * one keyboard. `resize` is likewise shared: the server applies the SMALLEST
 * subscribed viewport (see `ATTACH_RESIZE_POLICY`) so no viewer sees a line
 * wrap the pty does not know about.
 */

/* ==========================================================================
 * Constants
 * ========================================================================== */

/** Bumped on any incompatible change. Sent as a query param at upgrade. */
export const TERMINAL_PROTOCOL_VERSION = 1;

/** Client -> server: keystrokes and paste. */
export const OP_INPUT = 0x01;
/** Server -> client: pty output. */
export const OP_OUTPUT = 0x02;

/** Bytes before the payload: 1 opcode + 4 channel. */
export const FRAME_HEADER_BYTES = 5;

/**
 * Largest OP_OUTPUT payload the server emits. Larger reads are split across
 * frames; the client reassembles nothing, it just writes each chunk in order.
 */
export const MAX_OUTPUT_PAYLOAD_BYTES = 64 * 1024;

/**
 * Largest OP_INPUT payload the server accepts. Generous for a paste, small
 * enough that a member cannot push megabytes into a pty in one frame. Over it,
 * the server replies `error` with `payload-too-large` and drops the frame.
 */
export const MAX_INPUT_PAYLOAD_BYTES = 8 * 1024;

/** Largest control (text) frame the server accepts, in UTF-8 bytes. */
export const MAX_CONTROL_FRAME_BYTES = 4 * 1024;

/** Terminals one socket may hold open at once. */
export const MAX_CHANNELS_PER_SOCKET = 16;

export const MIN_COLS = 1;
export const MAX_COLS = 1000;
export const MIN_ROWS = 1;
export const MAX_ROWS = 1000;

/**
 * With several viewers on one pty, the server applies the minimum of every
 * subscriber's cols and rows. Documented as a constant so the client can say
 * so in the UI when a viewport is being clamped by someone else's window.
 */
export const ATTACH_RESIZE_POLICY = "min-of-subscribers" as const;

/** `id`, `terminalId`: /^[A-Za-z0-9_-]{1,64}$/ — same shape as pane and workspace ids. */
export const TERMINAL_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

/* ==========================================================================
 * Control messages: client -> server
 * ========================================================================== */

/**
 * Attach to an existing terminal. The terminal is created by the orchestrator
 * (a terminal pane appearing on the canvas), not by this protocol — so a
 * client can never spawn a shell just by opening a socket.
 *
 * `id` is a client-chosen request id, echoed on the matching `attached` or
 * `error` so a client with several in flight can correlate them.
 */
export interface ClientSubscribe {
  readonly t: "subscribe";
  readonly id: string;
  readonly terminalId: string;
  /** This viewer's viewport. Combined with other viewers per ATTACH_RESIZE_POLICY. */
  readonly cols: number;
  readonly rows: number;
  /**
   * Bytes of scrollback to replay before live output, capped by the server.
   * 0 asks for none. Omit to accept the server default.
   */
  readonly backlogBytes?: number;
}

/** This viewer's window changed. Does not resize the pty on its own — see the policy. */
export interface ClientResize {
  readonly t: "resize";
  readonly channel: number;
  readonly cols: number;
  readonly rows: number;
}

/**
 * Stop receiving this terminal. Detaches the viewer only: the pty keeps
 * running, because server-owned sessions are the product (PLAN.md §6).
 * Closing the socket detaches every channel implicitly.
 */
export interface ClientUnsubscribe {
  readonly t: "unsubscribe";
  readonly channel: number;
}

export type ClientControl = ClientSubscribe | ClientResize | ClientUnsubscribe;

/* ==========================================================================
 * Control messages: server -> client
 * ========================================================================== */

/**
 * Subscription accepted. `channel` is now valid for OP_INPUT / OP_OUTPUT.
 * Any backlog arrives as ordinary OP_OUTPUT frames immediately after this
 * message and before live output.
 */
export interface ServerAttached {
  readonly t: "attached";
  /** Echoes `ClientSubscribe.id`. */
  readonly id: string;
  readonly channel: number;
  readonly terminalId: string;
  /** The pty's ACTUAL size after applying ATTACH_RESIZE_POLICY. May differ from the request. */
  readonly cols: number;
  readonly rows: number;
  /** Backlog bytes about to be sent. 0 when none was kept or requested. */
  readonly backlogBytes: number;
  /** Other viewers currently attached, including this one. For the presence badge. */
  readonly viewers: number;
}

/**
 * The pty's size changed because another viewer attached, detached, or
 * resized. Unsolicited — the client re-fits xterm to these dimensions.
 */
export interface ServerResized {
  readonly t: "resized";
  readonly channel: number;
  readonly cols: number;
  readonly rows: number;
  readonly viewers: number;
}

/** The pty's process exited. The channel is dead and is never reused. */
export interface ServerExit {
  readonly t: "exit";
  readonly channel: number;
  /** Exit code, or null when terminated by a signal. */
  readonly exitCode: number | null;
  /** Signal name, e.g. "SIGKILL", or null on a normal exit. */
  readonly signal: string | null;
}

/**
 * Why a terminal message failed.
 *
 * `not-found` and `forbidden` are DELIBERATELY DISTINCT for the operator log
 * but the server sends `not-found` for both to the client: telling an
 * unauthorized member that a terminal exists is itself a disclosure. Servers
 * MUST NOT emit `forbidden` on the wire.
 */
export type TerminalErrorCode =
  /** Frame was not valid JSON, or failed schema validation. */
  | "bad-message"
  /** Client protocol version does not match TERMINAL_PROTOCOL_VERSION. */
  | "version-mismatch"
  /** No such terminal, or the caller may not see it. */
  | "not-found"
  /** Internal only — never sent. See above. */
  | "forbidden"
  /** `channel` is unknown, already exited, or belongs to another socket. */
  | "bad-channel"
  /** Input payload over MAX_INPUT_PAYLOAD_BYTES, or control frame over its cap. */
  | "payload-too-large"
  /** MAX_CHANNELS_PER_SOCKET reached. */
  | "too-many-channels"
  /** The terminal's sandbox is hibernated, stopping, or gone. */
  | "sandbox-not-running"
  /**
   * This viewer could not keep up and was detached rather than allowed to grow
   * an unbounded server-side buffer (PLAN.md §6, backpressure). Reconnect and
   * re-subscribe to catch up from backlog.
   */
  | "slow-consumer"
  /** Anything else. `message` is generic; details go to the server log only. */
  | "internal";

export interface ServerError {
  readonly t: "error";
  /** Echoes the failing request's `id`, when the failure had one. */
  readonly id?: string;
  /** The channel concerned, when the failure had one. */
  readonly channel?: number;
  readonly code: TerminalErrorCode;
  /**
   * Human-readable, safe to render as TEXT in the pane. Never contains host
   * paths, container ids, env values, or stack traces (SECURITY.md T9).
   */
  readonly message: string;
  /** True when the client may retry the same request unchanged. */
  readonly retryable: boolean;
}

export type ServerControl = ServerAttached | ServerResized | ServerExit | ServerError;

/* ==========================================================================
 * Binary frame codec
 * ========================================================================== */

export interface TerminalFrame {
  readonly opcode: typeof OP_INPUT | typeof OP_OUTPUT;
  readonly channel: number;
  /**
   * A VIEW over the received buffer, not a copy — decoding is on the hot path.
   * Callers that retain the payload past the current tick must copy it.
   */
  readonly payload: Uint8Array;
}

/** Builds a binary frame. Allocates once and copies the payload in. */
export function encodeTerminalFrame(
  opcode: typeof OP_INPUT | typeof OP_OUTPUT,
  channel: number,
  payload: Uint8Array,
): Uint8Array {
  const out = new Uint8Array(FRAME_HEADER_BYTES + payload.byteLength);
  out[0] = opcode;
  new DataView(out.buffer, out.byteOffset, FRAME_HEADER_BYTES).setUint32(1, channel, false);
  out.set(payload, FRAME_HEADER_BYTES);
  return out;
}

export type FrameDecodeResult =
  | { readonly ok: true; readonly frame: TerminalFrame }
  | { readonly ok: false; readonly code: TerminalErrorCode; readonly reason: string };

/**
 * Parses a binary frame from an untrusted socket. Every member of a workspace
 * can send these, so a malformed frame is expected input, not an exception.
 *
 * `maxPayloadBytes` defaults to the inbound (client -> server) cap; a client
 * decoding server output passes MAX_OUTPUT_PAYLOAD_BYTES.
 */
export function decodeTerminalFrame(
  data: Uint8Array,
  maxPayloadBytes: number = MAX_INPUT_PAYLOAD_BYTES,
): FrameDecodeResult {
  if (data.byteLength < FRAME_HEADER_BYTES) {
    return { ok: false, code: "bad-message", reason: "frame shorter than header" };
  }
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const opcode = view.getUint8(0);
  if (opcode !== OP_INPUT && opcode !== OP_OUTPUT) {
    return { ok: false, code: "bad-message", reason: `unknown opcode ${opcode}` };
  }
  const channel = view.getUint32(1, false);
  const payloadBytes = data.byteLength - FRAME_HEADER_BYTES;
  if (payloadBytes > maxPayloadBytes) {
    return {
      ok: false,
      code: "payload-too-large",
      reason: `payload ${payloadBytes} > ${maxPayloadBytes}`,
    };
  }
  return {
    ok: true,
    frame: {
      opcode,
      channel,
      payload: data.subarray(FRAME_HEADER_BYTES),
    },
  };
}

/* ==========================================================================
 * Control message validation
 * ========================================================================== */

export type ControlParseResult =
  | { readonly ok: true; readonly message: ClientControl }
  | { readonly ok: false; readonly code: TerminalErrorCode; readonly reason: string };

function isChannel(v: unknown): v is number {
  return typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= 0xffff_ffff;
}

function isDimension(v: unknown, min: number, max: number): v is number {
  return typeof v === "number" && Number.isInteger(v) && v >= min && v <= max;
}

/**
 * Parses and validates a client control frame. The server MUST route every
 * inbound text frame through this and MUST NOT trust any field it did not
 * return — a workspace member is authenticated, not trusted (SECURITY.md T6).
 */
export function parseClientControl(raw: string): ControlParseResult {
  // UTF-8 byte length is always >= UTF-16 code-unit count, so this is a sound
  // (if loose) rejection: anything failing here would also fail a byte check.
  if (raw.length > MAX_CONTROL_FRAME_BYTES) {
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
      if (typeof m["id"] !== "string" || !TERMINAL_ID_RE.test(m["id"])) {
        return { ok: false, code: "bad-message", reason: "id must match TERMINAL_ID_RE" };
      }
      if (typeof m["terminalId"] !== "string" || !TERMINAL_ID_RE.test(m["terminalId"])) {
        return { ok: false, code: "bad-message", reason: "terminalId must match TERMINAL_ID_RE" };
      }
      if (!isDimension(m["cols"], MIN_COLS, MAX_COLS)) {
        return { ok: false, code: "bad-message", reason: `cols must be ${MIN_COLS}..${MAX_COLS}` };
      }
      if (!isDimension(m["rows"], MIN_ROWS, MAX_ROWS)) {
        return { ok: false, code: "bad-message", reason: `rows must be ${MIN_ROWS}..${MAX_ROWS}` };
      }
      const base: ClientSubscribe = {
        t: "subscribe",
        id: m["id"],
        terminalId: m["terminalId"],
        cols: m["cols"],
        rows: m["rows"],
      };
      const backlog = m["backlogBytes"];
      if (backlog === undefined) return { ok: true, message: base };
      if (typeof backlog !== "number" || !Number.isInteger(backlog) || backlog < 0) {
        return {
          ok: false,
          code: "bad-message",
          reason: "backlogBytes must be a non-negative integer",
        };
      }
      // exactOptionalPropertyTypes: the key is only present when it has a value.
      return { ok: true, message: { ...base, backlogBytes: backlog } };
    }

    case "resize": {
      if (!isChannel(m["channel"])) {
        return { ok: false, code: "bad-channel", reason: "channel must be a uint32" };
      }
      if (!isDimension(m["cols"], MIN_COLS, MAX_COLS)) {
        return { ok: false, code: "bad-message", reason: `cols must be ${MIN_COLS}..${MAX_COLS}` };
      }
      if (!isDimension(m["rows"], MIN_ROWS, MAX_ROWS)) {
        return { ok: false, code: "bad-message", reason: `rows must be ${MIN_ROWS}..${MAX_ROWS}` };
      }
      return {
        ok: true,
        message: { t: "resize", channel: m["channel"], cols: m["cols"], rows: m["rows"] },
      };
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
export function encodeServerControl(message: ServerControl): string {
  return JSON.stringify(message);
}

/**
 * Parses a server control frame on the client. The server is more trusted than
 * a client, but a shape check here turns a protocol drift into a clean error
 * instead of an undefined property three call frames later.
 */
export function parseServerControl(raw: string): ServerControl | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null) return null;
  const t = (parsed as Record<string, unknown>)["t"];
  if (t === "attached" || t === "resized" || t === "exit" || t === "error") {
    return parsed as ServerControl;
  }
  return null;
}
