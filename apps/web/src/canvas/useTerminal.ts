/**
 * xterm.js bound to the M2 terminal wire protocol (`@atrium/shared`).
 *
 * A hand-rolled socket rather than an off-the-shelf attach addon, for the same
 * reason `useRoom` hand-rolls its Yjs provider: the wire format is ours, the
 * reconnect behaviour has to be explicit, and the control channel carries
 * things (viewer count, the min-of-subscribers resize) that no generic addon
 * knows about.
 *
 * WHAT STAYS BYTES. Terminal output arrives as BINARY frames and is handed to
 * `xterm.write(Uint8Array)` unmodified — never decoded per chunk, never
 * base64'd, never JSON. Control messages are TEXT frames and go through
 * `parseServerControl`. See terminal.ts for why the split exists.
 *
 * NOTHING HERE TOUCHES innerHTML. Output goes to xterm, which renders into its
 * own DOM as text nodes; server `error` messages are stripped of control
 * characters and written either to the pty view or into a React text node
 * (SECURITY.md T6 — a workspace member is authenticated, not trusted).
 *
 * WHO OWNS THE GRID SIZE. The DOM decides what this viewer *wants* (the fit
 * addon's proposal, derived from the pane's layout box). The SERVER decides
 * what the grid *is*, because one pty may have several viewers and the applied
 * size is the minimum of all of them (ATTACH_RESIZE_POLICY). So this hook
 * deliberately never calls `FitAddon.fit()` — that would apply a local size and
 * then echo the server's clamped size back as this viewer's desired size,
 * ratcheting the shared pty permanently smaller. It calls `proposeDimensions()`
 * to measure, sends that, and resizes the terminal only from `attached` /
 * `resized`.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { Terminal, type ITheme } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import {
  MAX_COLS,
  MAX_INPUT_PAYLOAD_BYTES,
  MAX_OUTPUT_PAYLOAD_BYTES,
  MAX_ROWS,
  MIN_COLS,
  MIN_ROWS,
  OP_INPUT,
  OP_OUTPUT,
  TERMINAL_PROTOCOL_VERSION,
  decodeTerminalFrame,
  encodeTerminalFrame,
  parseServerControl,
} from "@atrium/shared";
import type { ClientControl } from "@atrium/shared";
import { devIdentityQuery, ensureTerminal } from "./terminalApi.ts";

const RECONNECT_BASE_MS = 500;
const RECONNECT_MAX_MS = 10_000;

/** Scrollback replayed on attach. The server caps this; asking is not getting. */
const BACKLOG_REQUEST_BYTES = 64 * 1024;

/** Lines of scrollback xterm keeps client-side. Memory, not durability (M5). */
const SCROLLBACK_LINES = 5_000;

/** `proposeDimensions` returns undefined until the renderer has measured a cell. */
const MEASURE_MAX_FRAMES = 90;

export type TerminalPhase =
  /** Socket opening for the first time. */
  | "connecting"
  /** Socket open, `subscribe` sent, waiting for `attached`. */
  | "attaching"
  /** Live. Keystrokes go to the pty. */
  | "attached"
  /** Socket dropped; backing off and retrying. */
  | "offline"
  /** The pty's process exited. The buffer is history now. */
  | "exited"
  /** Non-retryable server error. No further attempts. */
  | "error";

export interface TerminalSession {
  readonly phase: TerminalPhase;
  /** Operator-safe status text, already stripped of control characters. */
  readonly detail: string | null;
  /** Viewers attached to this pty, including us. 0 until `attached`. */
  readonly viewers: number;
  /** The pty's ACTUAL grid, as the server reports it. */
  readonly cols: number;
  readonly rows: number;
  /**
   * True when the pty is smaller than this pane could show, because a smaller
   * viewer is attached (ATTACH_RESIZE_POLICY). Worth saying out loud in the UI:
   * otherwise the blank margin looks like a bug.
   */
  readonly clamped: boolean;
  /** Re-measure and republish this viewer's size. Safe to call at any time. */
  refit(): void;
  /** Move keyboard focus into the terminal. */
  focus(): void;
}

export interface UseTerminalOptions {
  readonly workspaceId: string;
  /** The orchestrator's terminal id. Must match TERMINAL_ID_RE. */
  readonly terminalId: string;
}

/* ==========================================================================
 * Helpers
 * ========================================================================== */

/**
 * Strips C0/C1 controls from server-supplied text before it is displayed.
 *
 * `ServerError.message` is contractually safe to render as text, but this is
 * the one string in the pane that a server bug could turn into an escape
 * sequence aimed at the emulator, and stripping it costs nothing.
 */
function safeText(raw: string, max = 240): string {
  let out = "";
  for (const ch of raw) {
    const code = ch.codePointAt(0) ?? 0;
    out += code < 0x20 || (code >= 0x7f && code <= 0x9f) ? " " : ch;
    if (out.length >= max) break;
  }
  return out.trim();
}

function clampCols(n: number): number {
  return Math.min(MAX_COLS, Math.max(MIN_COLS, Math.floor(n)));
}

function clampRows(n: number): number {
  return Math.min(MAX_ROWS, Math.max(MIN_ROWS, Math.floor(n)));
}

/**
 * Terminal palette derived from the app's CSS variables, so light and dark
 * both work and the pane does not become a black rectangle on a paper canvas.
 * Read once per theme change — xterm wants concrete colors, not `var()`.
 */
function readTheme(): ITheme {
  const root = getComputedStyle(document.documentElement);
  const cssVar = (name: string, fallback: string): string => {
    const raw = root.getPropertyValue(name).trim();
    return raw === "" ? fallback : raw;
  };
  const dark = window.matchMedia("(prefers-color-scheme: dark)").matches;

  const base: ITheme = {
    background: cssVar("--panel", dark ? "#1e1d18" : "#ffffff"),
    foreground: cssVar("--text", dark ? "#ece9e2" : "#1a1917"),
    cursor: cssVar("--accent", dark ? "#8ea4f5" : "#3b5bdb"),
    cursorAccent: cssVar("--panel", dark ? "#1e1d18" : "#ffffff"),
    selectionBackground: dark ? "#3c4a86" : "#c9d4f7",
    selectionInactiveBackground: dark ? "#2f3455" : "#dde3f6",
  };

  return dark
    ? {
        ...base,
        black: "#3a382f",
        red: "#e57b73",
        green: "#63b98a",
        yellow: "#d2a244",
        blue: "#8ea4f5",
        magenta: "#c79ae0",
        cyan: "#63b3b9",
        white: "#ded9cf",
        brightBlack: "#6e695d",
        brightRed: "#f0968f",
        brightGreen: "#83d3a5",
        brightYellow: "#e6bd6a",
        brightBlue: "#a9bcff",
        brightMagenta: "#d7a3e8",
        brightCyan: "#8acdd3",
        brightWhite: "#f5f1e9",
      }
    : {
        ...base,
        black: "#2b2a26",
        red: "#b4362f",
        green: "#2f7d52",
        yellow: "#a4700a",
        blue: "#3b5bdb",
        magenta: "#8a3ea8",
        cyan: "#0c7a83",
        white: "#c9c5bd",
        brightBlack: "#6b6862",
        brightRed: "#cf5a52",
        brightGreen: "#3f9a67",
        brightYellow: "#c08a1c",
        brightBlue: "#5a75e6",
        brightMagenta: "#a457c2",
        brightCyan: "#1a959e",
        brightWhite: "#efece5",
      };
}

/* ==========================================================================
 * The hook
 * ========================================================================== */

/**
 * Mounts a terminal into `hostRef` and keeps it attached to `terminalId`.
 *
 * The host element must be rendered before the effect runs and must not be
 * remounted for the life of the session — it is the element xterm owns.
 */
export function useTerminal(
  hostRef: React.RefObject<HTMLDivElement | null>,
  { workspaceId, terminalId }: UseTerminalOptions,
): TerminalSession {
  const termRef = useRef<Terminal | null>(null);
  /** Set by the effect so `refit()` can republish without re-rendering. */
  const publishRef = useRef<(() => void) | null>(null);

  const [session, setSession] = useState<{
    phase: TerminalPhase;
    detail: string | null;
    viewers: number;
    cols: number;
    rows: number;
    clamped: boolean;
  }>({ phase: "connecting", detail: null, viewers: 0, cols: 0, rows: 0, clamped: false });

  useEffect(() => {
    const host = hostRef.current;
    if (host === null) return;

    /* ---- the emulator ---------------------------------------------------- */

    const term = new Terminal({
      allowProposedApi: false,
      allowTransparency: false,
      convertEol: false,
      cursorBlink: true,
      cursorStyle: "block",
      drawBoldTextInBrightColors: true,
      fontFamily: 'ui-monospace, "SF Mono", "Cascadia Mono", Menlo, monospace',
      fontSize: 12,
      lineHeight: 1.15,
      macOptionIsMeta: true,
      scrollback: SCROLLBACK_LINES,
      theme: readTheme(),
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(host);
    termRef.current = term;

    /* ---- connection state ------------------------------------------------ */

    let disposed = false;
    /** Set when there is no point retrying: the pty exited, or a hard error. */
    let finished = false;
    let attempt = 0;
    let reconnectTimer: number | undefined;
    let socket: WebSocket | null = null;
    let channel: number | null = null;
    let pendingRequestId: string | null = null;
    let requestSeq = 0;
    /** What this viewer wants, from the DOM. Never what the server clamped us to. */
    let want = { cols: 80, rows: 24 };
    const encoder = new TextEncoder();

    const setPhase = (phase: TerminalPhase, detail: string | null = null): void => {
      setSession((s) => ({ ...s, phase, detail }));
    };

    /* ---- sending --------------------------------------------------------- */

    /**
     * There is no `encodeClientControl` in the shared package (the server owns
     * the encode side), so control messages are stringified here — typed as
     * `ClientControl` so a protocol change is a compile error rather than a
     * `bad-message` at runtime.
     */
    const send = (message: ClientControl): void => {
      if (socket === null || socket.readyState !== WebSocket.OPEN) return;
      socket.send(JSON.stringify(message));
    };

    const sendInput = (bytes: Uint8Array): void => {
      if (socket === null || socket.readyState !== WebSocket.OPEN || channel === null) return;
      // A paste can exceed the per-frame cap; split rather than be rejected.
      for (let off = 0; off < bytes.byteLength; off += MAX_INPUT_PAYLOAD_BYTES) {
        socket.send(
          encodeTerminalFrame(
            OP_INPUT,
            channel,
            bytes.subarray(off, off + MAX_INPUT_PAYLOAD_BYTES),
          ),
        );
      }
    };

    const notice = (text: string): void => {
      // Our own text, dimmed. Written through xterm like any other output.
      term.write(`\r\n\x1b[2m${text}\x1b[0m\r\n`);
    };

    /* ---- sizing ---------------------------------------------------------- */

    let sizeFrame: number | undefined;
    let measureFrames = 0;

    /**
     * Measure the pane and tell the server. Coalesced to one animation frame so
     * a drag-resize does not emit a control message per pointermove.
     *
     * ZOOM: the canvas world is a single CSS `transform: scale()`. Both the fit
     * addon (`getComputedStyle` on the host) and ResizeObserver report LAYOUT
     * pixels, which a transform does not affect — so the grid is a function of
     * the pane's canvas-space size and is completely independent of zoom. That
     * is the pragmatic choice: zoom scales the glyphs, it does not reflow the
     * shared pty out from under the other viewers. See TerminalPane.tsx for the
     * one thing this costs.
     */
    const publishSize = (): void => {
      if (sizeFrame !== undefined) return;
      sizeFrame = window.requestAnimationFrame(() => {
        sizeFrame = undefined;
        if (disposed) return;

        const proposed = fit.proposeDimensions();
        if (proposed === undefined) {
          // The renderer has not measured a cell yet (the pane may still be
          // zero-height on the first frame). Try again, but not forever.
          if (measureFrames < MEASURE_MAX_FRAMES) {
            measureFrames += 1;
            publishSize();
          }
          return;
        }
        measureFrames = 0;

        const next = { cols: clampCols(proposed.cols), rows: clampRows(proposed.rows) };
        const changed = next.cols !== want.cols || next.rows !== want.rows;
        want = next;

        if (channel !== null) {
          // Only the server may change an attached grid, and only when this
          // viewer's wish actually moved — a drag emits a frame per pointermove.
          if (changed) send({ t: "resize", channel, cols: want.cols, rows: want.rows });
        } else {
          // Not attached: nobody else's viewport to respect, so the local
          // proposal is the grid. Keeps an offline pane looking right.
          const { cols, rows } = want;
          term.resize(cols, rows);
          setSession((s) =>
            s.cols === cols && s.rows === rows ? s : { ...s, cols, rows, clamped: false },
          );
        }
      });
    };

    const observer = new ResizeObserver(publishSize);
    observer.observe(host);
    publishRef.current = publishSize;

    /* ---- theme ----------------------------------------------------------- */

    const scheme = window.matchMedia("(prefers-color-scheme: dark)");
    const onSchemeChange = (): void => {
      term.options.theme = readTheme();
    };
    scheme.addEventListener("change", onSchemeChange);

    /* ---- input ----------------------------------------------------------- */

    const dataSub = term.onData((data) => sendInput(encoder.encode(data)));
    // onBinary carries a "binary string": one code unit per byte, already
    // encoded by the emulator. Encoding it as UTF-8 would corrupt it.
    const binarySub = term.onBinary((data) => {
      const bytes = new Uint8Array(data.length);
      for (let i = 0; i < data.length; i += 1) bytes[i] = data.charCodeAt(i) & 0xff;
      sendInput(bytes);
    });

    /* ---- control message handling ---------------------------------------- */

    const applyServerSize = (cols: number, rows: number, viewers: number): void => {
      term.resize(cols, rows);
      setSession((s) => ({
        ...s,
        cols,
        rows,
        viewers,
        clamped: cols < want.cols || rows < want.rows,
      }));
    };

    const subscribe = (): void => {
      requestSeq += 1;
      const id = `req-${requestSeq}`;
      pendingRequestId = id;
      setPhase("attaching");
      send({
        t: "subscribe",
        id,
        terminalId,
        cols: want.cols,
        rows: want.rows,
        backlogBytes: BACKLOG_REQUEST_BYTES,
      });
    };

    const onControl = (raw: string): void => {
      const message = parseServerControl(raw);
      if (message === null) return;

      switch (message.t) {
        case "attached": {
          if (message.id !== pendingRequestId) return; // stale request, ignore
          pendingRequestId = null;
          channel = message.channel;
          attempt = 0;
          setPhase("attached");
          applyServerSize(message.cols, message.rows, message.viewers);
          term.focus();
          return;
        }
        case "resized": {
          if (channel === null || message.channel !== channel) return;
          applyServerSize(message.cols, message.rows, message.viewers);
          return;
        }
        case "exit": {
          if (channel === null || message.channel !== channel) return;
          channel = null;
          finished = true;
          const how =
            message.signal !== null
              ? `killed by ${safeText(message.signal, 16)}`
              : `exit code ${message.exitCode ?? "unknown"}`;
          notice(`[process exited — ${how}]`);
          setSession((s) => ({ ...s, phase: "exited", detail: how, viewers: 0 }));
          closeSocket();
          return;
        }
        case "error": {
          const text = safeText(message.message);
          if (message.retryable) {
            // Keep the socket; the server told us to try the same thing again.
            setPhase("offline", text);
            scheduleRetry(subscribe);
          } else {
            finished = true;
            channel = null;
            notice(`[${message.code}: ${text}]`);
            setSession((s) => ({ ...s, phase: "error", detail: text, viewers: 0 }));
            closeSocket();
          }
          return;
        }
      }
    };

    /* ---- socket ---------------------------------------------------------- */

    /**
     * Closes a socket without tripping the reconnect path, and without the
     * "closed before the connection is established" warning a CONNECTING
     * socket produces. Same shape as useRoom.ts — React StrictMode mounts
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

    /**
     * Open the socket and subscribe. Only ever called once the server has
     * confirmed the session exists — see `connect`.
     */
    const openSocket = (): void => {
      if (disposed || finished) return;

      const wsScheme = window.location.protocol === "https:" ? "wss" : "ws";
      const url =
        `${wsScheme}://${window.location.host}/rt/terminal` +
        `?workspace=${encodeURIComponent(workspaceId)}` +
        `&v=${TERMINAL_PROTOCOL_VERSION}` +
        devIdentityQuery();

      const ws = new WebSocket(url);
      ws.binaryType = "arraybuffer";
      socket = ws;

      ws.onopen = () => {
        attempt = 0;
        subscribe();
      };

      ws.onmessage = (event: MessageEvent<string | ArrayBuffer>) => {
        if (typeof event.data === "string") {
          onControl(event.data);
          return;
        }
        const result = decodeTerminalFrame(new Uint8Array(event.data), MAX_OUTPUT_PAYLOAD_BYTES);
        if (!result.ok) return; // malformed frame from the server: drop it
        const { frame } = result;
        if (frame.opcode !== OP_OUTPUT) return;
        if (channel === null || frame.channel !== channel) return;
        // `frame.payload` is a view over this message's own ArrayBuffer, which
        // the browser never reuses, so xterm may hold it across ticks without
        // a copy. That is the whole point of the binary path — no allocation,
        // no decode, no U+FFFD.
        term.write(frame.payload);
      };

      ws.onclose = () => {
        socket = null;
        channel = null;
        if (disposed || finished) return;
        setPhase("offline", "connection lost — reconnecting");
        scheduleRetry(connect);
      };
      ws.onerror = () => ws.close();
    };

    /**
     * One attach attempt: make sure the server-side session exists, then open
     * the socket.
     *
     * The order is load-bearing. The wire protocol deliberately cannot create a
     * terminal — `subscribe` only ever attaches — so a socket opened before the
     * orchestrator has spawned the shell would get a flat `not-found`, which is
     * not retryable and would strand the pane. `ensureTerminal` is the
     * authorized, idempotent creation call: every viewer of the pane makes it,
     * and exactly one shell exists at the end of it.
     */
    const connect = (): void => {
      if (disposed || finished) return;
      channel = null;
      pendingRequestId = null;
      if (attempt === 0) setPhase("connecting");

      void ensureTerminal(workspaceId, terminalId).then((result) => {
        if (disposed || finished) return;
        if (result.ok) {
          openSocket();
          return;
        }
        if (result.retryable) {
          setPhase("offline", result.message);
          scheduleRetry(connect);
          return;
        }
        finished = true;
        notice(`[${result.message}]`);
        setSession((s) => ({ ...s, phase: "error", detail: result.message, viewers: 0 }));
      });
    };

    connect();
    publishSize();

    /* ---- teardown -------------------------------------------------------- */

    return () => {
      disposed = true;
      if (reconnectTimer !== undefined) window.clearTimeout(reconnectTimer);
      if (sizeFrame !== undefined) window.cancelAnimationFrame(sizeFrame);
      scheme.removeEventListener("change", onSchemeChange);
      observer.disconnect();
      dataSub.dispose();
      binarySub.dispose();
      // Detach politely so the server drops this viewer from the resize policy
      // immediately rather than waiting for the socket to time out.
      if (channel !== null) send({ t: "unsubscribe", channel });
      closeSocket();
      term.dispose();
      publishRef.current = null;
      termRef.current = null;
    };
  }, [workspaceId, terminalId, hostRef]);

  const refit = useCallback(() => publishRef.current?.(), []);
  const focus = useCallback(() => termRef.current?.focus(), []);

  return { ...session, refit, focus };
}

/*
 * The identity query params this socket carries live in `terminalApi.ts`
 * (`devIdentityQuery`), shared with the HTTP calls so the dev shim has exactly
 * one definition to delete when real auth lands.
 */
