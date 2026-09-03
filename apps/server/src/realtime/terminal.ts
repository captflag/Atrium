/**
 * Websocket gateway for terminal panes — the transport half of M2.
 *
 * ============================================================================
 * AUTHORIZATION
 * ============================================================================
 * Identical in shape and in order to the canvas gateway (`gateway.ts`), and
 * deliberately so: Origin allowlist, workspace id shape, authenticate, check
 * membership — all AT THE HTTP UPGRADE, before a single frame is read
 * (SECURITY.md T6). The canvas gateway getting this wrong would leak a
 * document. This one getting it wrong is remote code execution inside the
 * workspace container, so it also refuses in the other direction: **the wire
 * protocol cannot create a terminal.** `subscribe` can only ever attach to a
 * session the orchestrator already opened through `TerminalRegistry.open()`,
 * and lookup is scoped to the workspace the upgrade proved membership of.
 *
 * A `subscribe` for a terminal that does not exist and one for a terminal in
 * someone else's workspace get the SAME answer on the wire, `not-found`. The
 * distinction is written to the operator log only, because a distinguishable
 * error confirms that a terminal exists.
 *
 * ============================================================================
 * WIRING — read this before integrating
 * ============================================================================
 * Node emits `upgrade` to EVERY listener on the http server, and
 * `RealtimeGateway` (M1) currently answers any path that is not exactly `/rt`
 * by writing `404` and destroying the socket, synchronously. Two independent
 * listeners therefore cannot coexist: whichever one does not own the path
 * kills the other's socket. So this gateway does NOT install an `upgrade`
 * listener of its own by default. It exposes `handleUpgrade()`, which returns
 * true when it has CLAIMED the request (path matched) and false when the
 * request belongs to somebody else — the shape a single dispatcher needs. See
 * `install()` for the caveat if you attach it directly.
 *
 * ============================================================================
 * FRAMING
 * ============================================================================
 * Control messages are TEXT (JSON), terminal bytes are BINARY, and the two
 * never mix — see `@atrium/shared` terminal.ts. Every inbound text frame goes
 * through `parseClientControl` and every inbound binary frame through
 * `decodeTerminalFrame`; no field that did not come back out of those
 * functions is trusted. Output bytes are cargo: framed, never parsed, never
 * logged (SECURITY.md T9).
 */

import { randomUUID } from "node:crypto";
import type { IncomingMessage, Server } from "node:http";
import type { Duplex } from "node:stream";
import { WebSocketServer, type RawData, type WebSocket } from "ws";
import {
  decodeTerminalFrame,
  encodeServerControl,
  encodeTerminalFrame,
  MAX_CHANNELS_PER_SOCKET,
  MAX_CONTROL_FRAME_BYTES,
  OP_INPUT,
  OP_OUTPUT,
  parseClientControl,
  TERMINAL_PROTOCOL_VERSION,
  type ClientSubscribe,
  type ServerControl,
  type ServerError,
  type TerminalErrorCode,
} from "@atrium/shared";
import type { IdentityProvider, Principal } from "../identity.ts";
import type { TerminalRegistry } from "./terminal-registry.ts";
import type {
  AttachRequest,
  TerminalLogger,
  TerminalSession,
  TerminalViewer,
} from "./terminal-session.ts";

const WORKSPACE_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const DEFAULT_PATH = "/rt/terminal";
/** Ping interval; a socket that misses two is assumed dead. Matches gateway.ts. */
const HEARTBEAT_MS = 30_000;

/**
 * Inbound keystroke budget per socket. A human types tens of bytes a second
 * and pastes a few kilobytes; anything sustained above this is a program, and
 * a program writing into a shared shell as fast as the socket allows is a
 * denial of service against the pty and against the other viewers (T10).
 * Excess is DROPPED, not queued, and logged once per socket per second.
 */
const INPUT_BYTES_PER_SECOND = 128 * 1024;
const INPUT_BURST_BYTES = 256 * 1024;

export interface TerminalGatewayOptions {
  readonly identity: IdentityProvider;
  readonly registry: TerminalRegistry;
  readonly log: TerminalLogger;
  /** Origins permitted to open a websocket. Blocks cross-site socket hijacking. */
  readonly allowedOrigins: readonly string[];
  /** Defaults to "/rt/terminal". */
  readonly path?: string;
}

export class TerminalGateway {
  readonly #wss = new WebSocketServer({ noServer: true });
  readonly #sockets = new Set<WebSocket>();
  readonly #options: TerminalGatewayOptions;
  readonly #path: string;

  constructor(options: TerminalGatewayOptions) {
    this.#options = options;
    this.#path = options.path ?? DEFAULT_PATH;
  }

  get socketCount(): number {
    return this.#sockets.size;
  }

  get path(): string {
    return this.#path;
  }

  /**
   * First refusal on an http `upgrade`.
   *
   * Returns true when this gateway has taken ownership of the socket — the
   * caller must then do nothing further with it, including not rejecting it.
   * Returns false when the path is not ours and the socket is untouched.
   *
   * The claim is synchronous (it is only a path comparison); authentication
   * continues on a promise, which is why the socket must not be written to
   * after a true return.
   */
  handleUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer): boolean {
    let url: URL;
    try {
      url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
    } catch {
      return false;
    }
    if (url.pathname !== this.#path) return false;
    void this.#authorize(req, socket, head, url);
    return true;
  }

  /**
   * Convenience for a server that has no other `upgrade` listener.
   *
   * DO NOT use this alongside `RealtimeGateway` as it stands: both listeners
   * run, and the canvas one destroys any socket whose path is not `/rt`. Route
   * through one dispatcher instead — see the WIRING note at the top of the
   * file.
   */
  install(server: Server): void {
    server.on("upgrade", (req, socket, head) => {
      this.handleUpgrade(req, socket, head);
    });
  }

  async #authorize(
    req: IncomingMessage,
    socket: Duplex,
    head: Buffer,
    url: URL,
  ): Promise<void> {
    const reject = (status: string): void => {
      socket.write(`HTTP/1.1 ${status}\r\nConnection: close\r\n\r\n`);
      socket.destroy();
    };

    try {
      // Browsers always send Origin on a websocket handshake; a missing or
      // unlisted one is not a browser we invited.
      const origin = req.headers.origin;
      if (typeof origin !== "string" || !this.#options.allowedOrigins.includes(origin)) {
        this.#options.log.warn({ origin }, "rejected terminal upgrade: bad origin");
        return reject("403 Forbidden");
      }

      const workspaceId = url.searchParams.get("workspace");
      if (workspaceId === null || !WORKSPACE_ID_RE.test(workspaceId)) {
        return reject("400 Bad Request");
      }

      const principal = await this.#options.identity.authenticate(req.headers, url);
      if (principal === null) {
        this.#options.log.warn({ workspaceId }, "rejected terminal upgrade: unauthenticated");
        return reject("401 Unauthorized");
      }

      if (!(await this.#options.identity.isMember(principal, workspaceId))) {
        this.#options.log.warn(
          { workspaceId, userId: principal.userId },
          "rejected terminal upgrade: not a member",
        );
        return reject("403 Forbidden");
      }

      const requestedVersion = url.searchParams.get("v");

      this.#wss.handleUpgrade(req, socket, head, (ws) => {
        this.#attach(ws, workspaceId, principal, requestedVersion);
      });
    } catch (error: unknown) {
      this.#options.log.warn(
        { err: error instanceof Error ? error.message : "unknown" },
        "terminal upgrade failed",
      );
      reject("400 Bad Request");
    }
  }

  #attach(
    ws: WebSocket,
    workspaceId: string,
    principal: Principal,
    requestedVersion: string | null,
  ): void {
    const { log, registry } = this.#options;
    this.#sockets.add(ws);

    const sendControl = (message: ServerControl): void => {
      if (ws.readyState === ws.OPEN) ws.send(encodeServerControl(message));
    };

    // The version check happens after the upgrade, not at it, so the client
    // gets a message it can render in the pane instead of an opaque handshake
    // failure. Authorization is already done by this point; a version mismatch
    // grants nothing. An absent `v` is treated as the current version.
    if (requestedVersion !== null && requestedVersion !== String(TERMINAL_PROTOCOL_VERSION)) {
      sendControl(
        terminalError(
          "version-mismatch",
          "This page is running an old terminal client. Reload to continue.",
          false,
        ),
      );
      ws.close(1002, "version-mismatch");
      this.#sockets.delete(ws);
      return;
    }

    /** Channels this socket owns. Never reused after `exit` — see nextChannel. */
    const channels = new Map<number, { readonly session: TerminalSession; readonly viewer: TerminalViewer }>();
    let nextChannel = 1;

    let inputTokens = INPUT_BURST_BYTES;
    let lastRefill = Date.now();
    let lastRateLog = 0;

    const spendInputBudget = (bytes: number): boolean => {
      const now = Date.now();
      inputTokens = Math.min(
        INPUT_BURST_BYTES,
        inputTokens + ((now - lastRefill) / 1000) * INPUT_BYTES_PER_SECOND,
      );
      lastRefill = now;
      if (inputTokens < bytes) {
        if (now - lastRateLog > 1000) {
          lastRateLog = now;
          log.warn(
            { workspaceId, userId: principal.userId, bytes },
            "dropping terminal input over rate limit",
          );
        }
        return false;
      }
      inputTokens -= bytes;
      return true;
    };

    const onSubscribe = (message: ClientSubscribe): void => {
      if (channels.size >= MAX_CHANNELS_PER_SOCKET) {
        sendControl(
          terminalError("too-many-channels", "Too many terminals open on this connection.", false, {
            id: message.id,
          }),
        );
        return;
      }

      const session = registry.get(workspaceId, message.terminalId);
      if (session === null) {
        // Operator log distinguishes; the wire never does (see the header).
        log.warn(
          {
            workspaceId,
            userId: principal.userId,
            terminalId: message.terminalId,
            reason: registry.existsElsewhere(workspaceId, message.terminalId)
              ? "forbidden"
              : "not-found",
          },
          "terminal subscribe refused",
        );
        sendControl(
          terminalError("not-found", "That terminal is not available.", false, { id: message.id }),
        );
        return;
      }

      const channel = nextChannel;
      nextChannel += 1;

      const viewer: TerminalViewer = {
        viewerId: randomUUID(),
        userId: principal.userId,
        channel,
        sendControl,
        sendOutput: (chunk) => {
          // encodeTerminalFrame allocates and copies, so the session's view
          // over the pty buffer does not have to outlive this call.
          if (ws.readyState === ws.OPEN) ws.send(encodeTerminalFrame(OP_OUTPUT, channel, chunk));
        },
        bufferedBytes: () => ws.bufferedAmount,
        detached: (reason) => {
          channels.delete(channel);
          if (reason === "slow-consumer") {
            sendControl(
              terminalError(
                "slow-consumer",
                "This connection fell too far behind and was detached. Re-open the terminal to catch up.",
                true,
                { channel },
              ),
            );
          }
          // Lets the registry's idle reaper (off by default) start counting.
          registry.noteViewerChange(session);
        },
      };

      const request: AttachRequest =
        message.backlogBytes === undefined
          ? { requestId: message.id, cols: message.cols, rows: message.rows }
          : {
              requestId: message.id,
              cols: message.cols,
              rows: message.rows,
              backlogBytes: message.backlogBytes,
            };

      // attach() sends `attached` and the backlog synchronously, so nothing
      // can interleave ahead of them.
      if (!session.attach(viewer, request)) {
        sendControl(
          terminalError("not-found", "That terminal is not available.", false, { id: message.id }),
        );
        return;
      }
      channels.set(channel, { session, viewer });
    };

    const onText = (raw: string): void => {
      const parsed = parseClientControl(raw);
      if (!parsed.ok) {
        log.debug(
          { workspaceId, userId: principal.userId, reason: parsed.reason },
          "rejected terminal control message",
        );
        sendControl(terminalError(parsed.code, "Malformed terminal message.", false));
        return;
      }
      const message = parsed.message;

      switch (message.t) {
        case "subscribe":
          onSubscribe(message);
          return;

        case "resize": {
          const entry = channels.get(message.channel);
          if (entry === undefined) {
            sendControl(
              terminalError("bad-channel", "Unknown terminal channel.", false, {
                channel: message.channel,
              }),
            );
            return;
          }
          entry.session.resize(entry.viewer, message.cols, message.rows);
          return;
        }

        case "unsubscribe": {
          const entry = channels.get(message.channel);
          if (entry === undefined) {
            sendControl(
              terminalError("bad-channel", "Unknown terminal channel.", false, {
                channel: message.channel,
              }),
            );
            return;
          }
          // The pty keeps running: sessions are server-owned (PLAN.md §6).
          entry.session.detach(entry.viewer, "client");
          return;
        }
      }
    };

    const onBinary = (bytes: Uint8Array): void => {
      const decoded = decodeTerminalFrame(bytes);
      if (!decoded.ok) {
        sendControl(terminalError(decoded.code, "Malformed terminal frame.", false));
        return;
      }
      const frame = decoded.frame;
      if (frame.opcode !== OP_INPUT) {
        sendControl(
          terminalError("bad-message", "Only input frames are accepted.", false, {
            channel: frame.channel,
          }),
        );
        return;
      }
      const entry = channels.get(frame.channel);
      if (entry === undefined) {
        sendControl(
          terminalError("bad-channel", "Unknown terminal channel.", false, {
            channel: frame.channel,
          }),
        );
        return;
      }
      if (!spendInputBudget(frame.payload.byteLength)) return;
      entry.session.write(frame.payload);
    };

    ws.on("message", (data: RawData, isBinary: boolean) => {
      try {
        if (isBinary) {
          onBinary(toBytes(data));
          return;
        }
        const bytes = toBytes(data);
        if (bytes.byteLength > MAX_CONTROL_FRAME_BYTES) {
          sendControl(terminalError("payload-too-large", "Control message too large.", false));
          return;
        }
        onText(Buffer.from(bytes).toString("utf8"));
      } catch (error: unknown) {
        log.warn(
          {
            workspaceId,
            userId: principal.userId,
            err: error instanceof Error ? error.message : "unknown",
          },
          "failed to handle terminal message",
        );
        sendControl(terminalError("internal", "Terminal message could not be handled.", true));
      }
    });

    let alive = true;
    ws.on("pong", () => {
      alive = true;
    });
    const heartbeat = setInterval(() => {
      if (!alive) {
        ws.terminate();
        return;
      }
      alive = false;
      ws.ping();
    }, HEARTBEAT_MS);

    let cleaned = false;
    const cleanup = (): void => {
      if (cleaned) return;
      cleaned = true;
      clearInterval(heartbeat);
      this.#sockets.delete(ws);
      // Copy first: detach() mutates `channels` through viewer.detached().
      for (const entry of [...channels.values()]) {
        entry.session.detach(entry.viewer, "closed");
      }
      channels.clear();
      log.info(
        { workspaceId, userId: principal.userId, sockets: this.#sockets.size },
        "terminal client left",
      );
    };

    ws.on("close", cleanup);
    ws.on("error", cleanup);

    log.info(
      { workspaceId, userId: principal.userId, sockets: this.#sockets.size },
      "terminal client joined",
    );
  }

  /**
   * Closes every terminal socket. Does NOT close the sessions behind them —
   * those belong to `TerminalRegistry`, and killing a build because the
   * process is restarting is exactly the behaviour PLAN.md §6 rules out. A
   * shutdown that also wants the shells gone calls `registry.closeAll()`.
   */
  async close(): Promise<void> {
    for (const ws of this.#sockets) ws.close(1001, "server shutting down");
    this.#sockets.clear();
    await new Promise<void>((resolve) => {
      this.#wss.close(() => resolve());
    });
  }
}

/* ==========================================================================
 * helpers
 * ========================================================================== */

/**
 * Builds a `ServerError`. The optional fields are attached conditionally
 * because `exactOptionalPropertyTypes` is on: an absent id must be an absent
 * key, not an explicit `undefined` that JSON.stringify would drop anyway but
 * the type system would not accept.
 */
function terminalError(
  code: TerminalErrorCode,
  message: string,
  retryable: boolean,
  ctx: { readonly id?: string; readonly channel?: number } = {},
): ServerError {
  const base = { t: "error", code, message, retryable } as const;
  if (ctx.id !== undefined && ctx.channel !== undefined) {
    return { ...base, id: ctx.id, channel: ctx.channel };
  }
  if (ctx.id !== undefined) return { ...base, id: ctx.id };
  if (ctx.channel !== undefined) return { ...base, channel: ctx.channel };
  return base;
}

/** ws hands us a Buffer, an ArrayBuffer, or a list of Buffers. Normalize once. */
function toBytes(data: RawData): Uint8Array {
  if (Buffer.isBuffer(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  if (Array.isArray(data)) {
    const joined = Buffer.concat(data);
    return new Uint8Array(joined.buffer, joined.byteOffset, joined.byteLength);
  }
  return new Uint8Array(data);
}

export { TerminalRegistry, TerminalOpenError } from "./terminal-registry.ts";
export type {
  SandboxBinding,
  SandboxLocator,
  TerminalOpenErrorCode,
  TerminalOpenOptions,
  TerminalRegistryOptions,
  TerminalSummary,
} from "./terminal-registry.ts";
export { TerminalSession } from "./terminal-session.ts";
export type {
  AttachRequest,
  DetachReason,
  TerminalLogger,
  TerminalViewer,
} from "./terminal-session.ts";
