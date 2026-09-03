/**
 * TerminalSession — one pty inside a workspace container, many viewers.
 *
 * This is the "stream hub" the SandboxProvider contract refers to: the
 * provider knows nothing about viewers, and this file knows nothing about
 * Docker. It owns exactly three things a `PtyHandle` does not:
 *
 *   1. FAN-OUT. Every subscriber's input goes to the same pty master and every
 *      subscriber receives the same output. Two people typing in one shell and
 *      both seeing the result is the M2 done-when criterion (PLAN.md §7), and
 *      it falls out of there being one pty rather than one per viewer.
 *   2. SCROLLBACK. A bounded ring so a late joiner sees recent history without
 *      the browser having owned any of it (PLAN.md §6).
 *   3. BACKPRESSURE. A shell can produce output faster than a browser on a bad
 *      connection consumes it. The buffer is bounded and the policy is stated
 *      below, because "design this in; retrofitting it is painful"
 *      (PLAN.md §6).
 *
 * ============================================================================
 * POLICIES — stated here so they are reviewable, not discovered
 * ============================================================================
 *
 * LIFETIME. The pty keeps running when the last viewer leaves. Sessions are
 * server-owned (PLAN.md §6: "close your laptop and the work keeps going"), so
 * detaching a viewer must not kill a build half way through. The implication
 * is real and is not hidden: a terminal with zero viewers still holds a
 * process in the container, a slot against the sandbox's PID limit, and up to
 * `scrollbackBytes` of server RAM, until the orchestrator calls `close()` or
 * the optional idle reaper in `TerminalRegistry` fires. Container hibernation
 * (M5) is what eventually makes an idle session cheap; until then, whoever
 * opens terminals is responsible for closing them.
 *
 * RESIZE. The pty size is the MINIMUM of every attached viewer's cols and rows
 * (`ATTACH_RESIZE_POLICY` = "min-of-subscribers"). Minimum, not last-writer,
 * because a pty larger than a viewer's window makes that viewer see wraps the
 * pty does not know about — unrecoverable visual corruption, versus a wasted
 * margin for the viewer with the bigger window. WITHIN one viewer, its own
 * successive `resize` messages are last-writer-wins: no debounce, no
 * hysteresis. When no viewer is attached the last effective size is retained
 * rather than reset, so a program's layout survives everyone looking away.
 *
 * BACKPRESSURE. Per viewer, not per session: one bad connection must not stall
 * the shell for everybody. Before each write the session asks the transport
 * how many bytes are already queued and not yet flushed. Over
 * `viewerHighWaterBytes` the viewer is DETACHED with `slow-consumer` — output
 * is never dropped mid-stream for an attached viewer, because a terminal
 * missing an interior byte range is silently wrong in a way a user cannot
 * detect, whereas a detached viewer is obvious and recoverable (reconnect,
 * re-subscribe, get the backlog). The pty is never throttled and other viewers
 * are unaffected.
 *
 * BYTES ARE CARGO. The session does not decode, filter, log, or transform pty
 * output. It splits it at `MAX_OUTPUT_PAYLOAD_BYTES` because the wire protocol
 * caps a frame, and that is the only thing it does to the stream. Terminal
 * output is the highest-density secret store in the system (SECURITY.md T9);
 * the only copy it makes is the bounded in-memory ring.
 */

import {
  MAX_COLS,
  MAX_OUTPUT_PAYLOAD_BYTES,
  MAX_ROWS,
  MIN_COLS,
  MIN_ROWS,
  type ServerControl,
} from "@atrium/shared";
import type { PtyExit, PtyHandle, PtySize } from "../sandbox/provider.ts";
import { ScrollbackRing } from "./scrollback.ts";

/** Same shape the canvas room and gateway log through. Fastify's logger fits. */
export interface TerminalLogger {
  info(obj: Record<string, unknown>, msg: string): void;
  warn(obj: Record<string, unknown>, msg: string): void;
  debug(obj: Record<string, unknown>, msg: string): void;
}

/** Why a viewer stopped receiving output. Reported to the transport. */
export type DetachReason =
  /** The client sent `unsubscribe`. */
  | "client"
  /** The socket closed, or the gateway is shutting down. */
  | "closed"
  /** The viewer could not keep up and was dropped (see BACKPRESSURE). */
  | "slow-consumer"
  /** The pty exited. An `exit` control message was already delivered. */
  | "exit";

/**
 * One attached viewer, as seen by the session. Implemented by the websocket
 * layer; the session never touches a socket.
 *
 * `sendOutput` receives a VIEW over the pty's chunk, valid only for the
 * current tick. Implementations frame-and-copy immediately (which
 * `encodeTerminalFrame` does) or copy explicitly.
 */
export interface TerminalViewer {
  /** Unique per attachment, for logs. Not a user id and not a channel. */
  readonly viewerId: string;
  /** Authenticated principal behind this viewer, for the operator log only. */
  readonly userId: string;
  /** Wire channel assigned by the transport, carried in every control message. */
  readonly channel: number;
  sendControl(message: ServerControl): void;
  sendOutput(chunk: Uint8Array): void;
  /** Bytes queued in the transport and not yet flushed. Drives backpressure. */
  bufferedBytes(): number;
  /** The session is done with this viewer. Called exactly once per attachment. */
  detached(reason: DetachReason): void;
}

export interface AttachRequest {
  /** Echoed into `attached.id` so a client can correlate. */
  readonly requestId: string;
  readonly cols: number;
  readonly rows: number;
  /** Bytes of scrollback to replay. Clamped to what the ring holds. */
  readonly backlogBytes?: number;
}

export interface TerminalSessionOptions {
  readonly terminalId: string;
  readonly workspaceId: string;
  readonly pty: PtyHandle;
  readonly log: TerminalLogger;
  /** Ring capacity. */
  readonly scrollbackBytes: number;
  /** Replayed when a client does not ask for a specific amount. */
  readonly defaultBacklogBytes: number;
  /** Transport queue depth at which a viewer is detached as a slow consumer. */
  readonly viewerHighWaterBytes: number;
  /** Called once, after the pty has exited and viewers have been told. */
  readonly onClosed: (session: TerminalSession) => void;
}

/**
 * How long to wait after `close()` for the pty's own `exited` promise before
 * synthesizing an exit for the viewers. A provider whose `exited` never
 * settles must not leave panes waiting forever.
 */
const EXIT_SYNTHESIS_MS = 5_000;

export class TerminalSession {
  readonly terminalId: string;
  readonly workspaceId: string;
  readonly createdAt: string;

  readonly #pty: PtyHandle;
  readonly #log: TerminalLogger;
  readonly #scrollback: ScrollbackRing;
  readonly #defaultBacklogBytes: number;
  readonly #highWaterBytes: number;
  readonly #onClosed: (session: TerminalSession) => void;

  /** Attached viewers and the viewport each one asked for. */
  readonly #viewers = new Map<TerminalViewer, PtySize>();

  #size: PtySize;
  #exit: PtyExit | null = null;
  #closed = false;
  #unsubscribePty: (() => void) | null = null;
  #exitTimer: NodeJS.Timeout | undefined;

  private constructor(options: TerminalSessionOptions, initialSize: PtySize) {
    this.terminalId = options.terminalId;
    this.workspaceId = options.workspaceId;
    this.createdAt = new Date().toISOString();
    this.#pty = options.pty;
    this.#log = options.log;
    this.#scrollback = new ScrollbackRing(options.scrollbackBytes);
    this.#defaultBacklogBytes = options.defaultBacklogBytes;
    this.#highWaterBytes = options.viewerHighWaterBytes;
    this.#onClosed = options.onClosed;
    this.#size = initialSize;
  }

  /**
   * Wraps a live pty. The pty is already running: this subscribes to it, so it
   * must be called in the same tick it was spawned or early output is lost to
   * nobody's benefit.
   */
  static start(options: TerminalSessionOptions, initialSize: PtySize): TerminalSession {
    const session = new TerminalSession(options, clampSize(initialSize));
    session.#unsubscribePty = options.pty.onData((chunk) => session.#onData(chunk));
    void options.pty.exited.then((exit) => session.#onExit(exit));
    return session;
  }

  get viewerCount(): number {
    return this.#viewers.size;
  }

  get size(): PtySize {
    return this.#size;
  }

  /** True once the pty has exited or `close()` has run. Never attachable again. */
  get closed(): boolean {
    return this.#closed;
  }

  get scrollbackBytes(): number {
    return this.#scrollback.bytes;
  }

  // --- viewers -----------------------------------------------------------

  /**
   * Attach a viewer. Sends `attached` and then the backlog SYNCHRONOUSLY,
   * before returning, so no live output can interleave ahead of the history it
   * is supposed to follow. Returns false when the session is already closed —
   * the caller answers the client with `not-found`.
   */
  attach(viewer: TerminalViewer, request: AttachRequest): boolean {
    if (this.#closed) return false;

    this.#viewers.set(viewer, clampSize({ cols: request.cols, rows: request.rows }));
    this.#applySize();

    const want = Math.min(
      request.backlogBytes ?? this.#defaultBacklogBytes,
      this.#scrollback.capacityBytes,
    );
    const backlog = this.#scrollback.tail(want);

    viewer.sendControl({
      t: "attached",
      id: request.requestId,
      channel: viewer.channel,
      terminalId: this.terminalId,
      cols: this.#size.cols,
      rows: this.#size.rows,
      backlogBytes: backlog.byteLength,
      viewers: this.#viewers.size,
    });
    if (backlog.byteLength > 0) this.#sendChunked(viewer, backlog);

    // Everyone else needs to know the pty may have moved under them, and needs
    // the new viewer count for the presence badge.
    this.#broadcastResized(viewer);

    this.#log.debug(
      {
        workspaceId: this.workspaceId,
        terminalId: this.terminalId,
        userId: viewer.userId,
        viewers: this.#viewers.size,
        cols: this.#size.cols,
        rows: this.#size.rows,
      },
      "terminal viewer attached",
    );
    return true;
  }

  /**
   * Detach one viewer. The pty keeps running — see LIFETIME in the header.
   * Idempotent: detaching an unknown viewer is a no-op.
   */
  detach(viewer: TerminalViewer, reason: DetachReason): void {
    if (!this.#viewers.delete(viewer)) return;
    viewer.detached(reason);
    if (this.#closed) return;

    this.#applySize();
    this.#broadcastResized(null);

    this.#log.debug(
      {
        workspaceId: this.workspaceId,
        terminalId: this.terminalId,
        userId: viewer.userId,
        reason,
        viewers: this.#viewers.size,
      },
      "terminal viewer detached",
    );
  }

  /**
   * A viewer's window changed. Recomputes the shared size; a viewer whose own
   * request was clamped by someone smaller is told so even when nothing else
   * changed, so its xterm re-fits instead of rendering at a size the pty has
   * never heard of.
   */
  resize(viewer: TerminalViewer, cols: number, rows: number): void {
    const current = this.#viewers.get(viewer);
    if (current === undefined) return;

    const requested = clampSize({ cols, rows });
    this.#viewers.set(viewer, requested);

    if (this.#applySize()) {
      this.#broadcastResized(null);
    } else if (requested.cols !== this.#size.cols || requested.rows !== this.#size.rows) {
      // Nothing moved, but THIS viewer asked for something it did not get.
      this.#sendResized(viewer);
    }
  }

  /**
   * Keystrokes from one viewer into the shared pty. There is no input
   * arbitration and no per-viewer echo: it is one keyboard on one shell, and
   * two people typing at once interleave exactly as they would in person.
   */
  write(data: Uint8Array): boolean {
    if (this.#closed || data.byteLength === 0) return !this.#closed;
    try {
      this.#pty.write(data);
      return true;
    } catch (error: unknown) {
      this.#log.warn(
        {
          workspaceId: this.workspaceId,
          terminalId: this.terminalId,
          err: error instanceof Error ? error.message : "unknown",
        },
        "terminal write failed",
      );
      return false;
    }
  }

  // --- teardown ----------------------------------------------------------

  /**
   * Orchestrator-initiated close: kill the shell and release the pty. Viewers
   * receive `exit` exactly as if the process had ended on its own. Idempotent.
   */
  async close(signal?: string): Promise<void> {
    if (this.#closed) return;
    try {
      this.#pty.kill(signal);
    } catch {
      // Already gone. dispose() below is the authority.
    }
    // If the provider's `exited` never settles, do not strand the panes.
    const timer = setTimeout(() => {
      this.#onExit({ exitCode: null, signal: signal ?? "SIGTERM" });
    }, EXIT_SYNTHESIS_MS);
    timer.unref();
    this.#exitTimer = timer;

    try {
      await this.#pty.dispose();
    } catch (error: unknown) {
      this.#log.warn(
        {
          workspaceId: this.workspaceId,
          terminalId: this.terminalId,
          err: error instanceof Error ? error.message : "unknown",
        },
        "pty dispose failed",
      );
    }
  }

  // --- internals ---------------------------------------------------------

  #onData(chunk: Uint8Array): void {
    if (this.#closed || chunk.byteLength === 0) return;
    this.#scrollback.push(chunk);

    // Collect first, detach after: mutating #viewers mid-iteration is legal
    // for Map but the intent is clearer, and a detach broadcasts.
    let slow: TerminalViewer[] | null = null;
    for (const viewer of this.#viewers.keys()) {
      if (viewer.bufferedBytes() > this.#highWaterBytes) {
        (slow ??= []).push(viewer);
        continue;
      }
      this.#sendChunked(viewer, chunk);
    }
    if (slow === null) return;

    for (const viewer of slow) {
      this.#log.warn(
        {
          workspaceId: this.workspaceId,
          terminalId: this.terminalId,
          userId: viewer.userId,
          bufferedBytes: viewer.bufferedBytes(),
          highWaterBytes: this.#highWaterBytes,
        },
        "detaching slow terminal viewer",
      );
      this.detach(viewer, "slow-consumer");
    }
  }

  #onExit(exit: PtyExit): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#exit = exit;
    if (this.#exitTimer !== undefined) {
      clearTimeout(this.#exitTimer);
      this.#exitTimer = undefined;
    }
    if (this.#unsubscribePty !== null) {
      this.#unsubscribePty();
      this.#unsubscribePty = null;
    }

    for (const viewer of this.#viewers.keys()) {
      viewer.sendControl({
        t: "exit",
        channel: viewer.channel,
        exitCode: exit.exitCode,
        signal: exit.signal,
      });
      viewer.detached("exit");
    }
    this.#viewers.clear();
    this.#scrollback.clear();

    this.#log.info(
      {
        workspaceId: this.workspaceId,
        terminalId: this.terminalId,
        exitCode: exit.exitCode,
        signal: exit.signal,
      },
      "terminal session ended",
    );

    // Best effort: the pty is gone, but the provider may still hold a stream.
    void Promise.resolve(this.#pty.dispose()).catch(() => undefined);
    this.#onClosed(this);
  }

  /** The exit that ended this session, or null while it is still running. */
  get exit(): PtyExit | null {
    return this.#exit;
  }

  /**
   * Recompute the shared size from every viewer's viewport and push it to the
   * pty. Returns true when the pty's size actually changed.
   */
  #applySize(): boolean {
    if (this.#viewers.size === 0) return false; // keep the last size

    let cols = MAX_COLS;
    let rows = MAX_ROWS;
    for (const want of this.#viewers.values()) {
      if (want.cols < cols) cols = want.cols;
      if (want.rows < rows) rows = want.rows;
    }
    if (cols === this.#size.cols && rows === this.#size.rows) return false;

    this.#size = { cols, rows };
    try {
      this.#pty.resize(this.#size);
    } catch (error: unknown) {
      this.#log.warn(
        {
          workspaceId: this.workspaceId,
          terminalId: this.terminalId,
          err: error instanceof Error ? error.message : "unknown",
        },
        "pty resize failed",
      );
    }
    return true;
  }

  /**
   * Tell viewers the shared state moved. `resized` carries both the pty size
   * and the viewer count, so it is also how a pane learns that someone else
   * joined or left — that is why an attach/detach broadcasts it even when the
   * size did not change. `except` is the viewer that already learned the same
   * state from its own `attached`.
   */
  #broadcastResized(except: TerminalViewer | null): void {
    for (const viewer of this.#viewers.keys()) {
      if (viewer === except) continue;
      this.#sendResized(viewer);
    }
  }

  #sendResized(viewer: TerminalViewer): void {
    viewer.sendControl({
      t: "resized",
      channel: viewer.channel,
      cols: this.#size.cols,
      rows: this.#size.rows,
      viewers: this.#viewers.size,
    });
  }

  /** Splits at the protocol's frame cap. No other transformation. */
  #sendChunked(viewer: TerminalViewer, bytes: Uint8Array): void {
    if (bytes.byteLength <= MAX_OUTPUT_PAYLOAD_BYTES) {
      viewer.sendOutput(bytes);
      return;
    }
    for (let offset = 0; offset < bytes.byteLength; offset += MAX_OUTPUT_PAYLOAD_BYTES) {
      viewer.sendOutput(bytes.subarray(offset, offset + MAX_OUTPUT_PAYLOAD_BYTES));
    }
  }
}

function clampSize(size: PtySize): PtySize {
  return {
    cols: clamp(size.cols, MIN_COLS, MAX_COLS),
    rows: clamp(size.rows, MIN_ROWS, MAX_ROWS),
  };
}

function clamp(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) return min;
  return Math.min(max, Math.max(min, Math.trunc(value)));
}
