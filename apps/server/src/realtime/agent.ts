/**
 * Websocket gateway for agent panes — the transport half of M3b.
 *
 * ============================================================================
 * AUTHORIZATION
 * ============================================================================
 * Identical in shape and in ORDER to the canvas gateway (`gateway.ts`) and the
 * terminal gateway (`terminal.ts`), and deliberately so: Origin allowlist,
 * workspace id shape, authenticate, check membership — all AT THE HTTP UPGRADE,
 * before a single frame is read (SECURITY.md T6).
 *
 * An agent session runs model-generated commands inside the workspace
 * container, so this gateway also refuses in the other direction: **the wire
 * protocol cannot start an agent.** `subscribe` can only ever attach to a
 * session the orchestrator already created through `AgentRegistry.open()`, and
 * lookup is scoped to the workspace the upgrade proved membership of. Creating
 * one is `POST /api/workspaces/:id/agents` (see `agent-routes.ts`), which
 * repeats authenticate + membership. If a JSON message could spawn an agent,
 * every member would have remote code execution by sending one.
 *
 * ONE EXTRA CHECK THE TERMINAL GATEWAY DOES NOT HAVE. Membership is re-checked
 * on every `subscribe`, not only at the upgrade. The agent protocol carries a
 * replay cursor (`fromSeq`), and replay is exactly where authorization is most
 * often checked once and then trusted forever (SECURITY.md T11): membership may
 * have been revoked during the disconnect, which is the window durability
 * creates.
 *
 * A `subscribe` for a session that does not exist and one for a session in
 * someone else's workspace get the SAME answer on the wire, `not-found`. The
 * distinction is written to the operator log only, because a distinguishable
 * error confirms that a session exists. `forbidden` exists in the error union
 * for that log and is never sent.
 *
 * ============================================================================
 * WIRING — read this before integrating
 * ============================================================================
 * Node emits `upgrade` to EVERY listener on the http server, so a gateway that
 * rejects paths it does not own destroys the other gateways' sockets — the
 * defect M2 paid for once already. This gateway therefore installs NO `upgrade`
 * listener of its own: it exposes `handleUpgrade()`, which returns true when it
 * has CLAIMED the request and false when the request belongs to somebody else.
 * `index.ts` owns the single dispatcher.
 *
 * ============================================================================
 * FRAMING
 * ============================================================================
 * TEXT FRAMES ONLY, unlike `terminal.ts`. A pty emits an arbitrary byte stream
 * on the hottest path in the app; agent events are structured, low-rate, and
 * are persisted as structured rows (M5). A binary frame here is a protocol
 * error, not a fast path. Every inbound frame goes through
 * `parseClientAgentControl` and no field that did not come back out of it is
 * trusted (SECURITY.md T6).
 *
 * ============================================================================
 * EVERYTHING AN AGENT SAYS IS UNTRUSTED (SECURITY.md T1)
 * ============================================================================
 * This file moves agent strings and never interprets them. It never logs a
 * prompt, a text chunk, a tool input or a tool output (T9), and it never puts a
 * host path, a container id, an environment value or a stack trace on the wire
 * — an error is a fixed string chosen from a small set, with the detail written
 * to the operator log. Rendering is the client's problem and the client's rule
 * is text-only; see `AgentPane`.
 */

import { randomUUID } from "node:crypto";
import type { IncomingMessage, Server } from "node:http";
import type { Duplex } from "node:stream";
import { WebSocketServer, type RawData, type WebSocket } from "ws";
import {
  AGENT_MAX_CHANNELS_PER_SOCKET,
  AGENT_MAX_CONTROL_FRAME_BYTES,
  AGENT_PROTOCOL_VERSION,
  encodeServerAgentControl,
  parseClientAgentControl,
  utf8ByteLength,
  type AgentErrorCode,
  type ClientAgentSubscribe,
  type ServerAgentControl,
  type ServerAgentError,
} from "@atrium/shared";
import type { IdentityProvider, Principal } from "../identity.ts";
import type { AgentRegistry } from "./agent-registry.ts";
import {
  AgentControlError,
  messageFor,
  retryableFor,
  type AgentAttachRequest,
  type AgentLogger,
  type AgentSession,
  type AgentViewer,
} from "./agent-session.ts";

const WORKSPACE_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const DEFAULT_PATH = "/rt/agent";
/** Ping interval; a socket that misses two is assumed dead. Matches gateway.ts. */
const HEARTBEAT_MS = 30_000;

/**
 * Prompt budget per socket, as a token bucket over UTF-8 bytes.
 *
 * A prompt is the one client message that costs money: it starts a model turn
 * through the broker (SECURITY.md T10). The bucket is generous for a human —
 * two full-size pasted stack traces back to back — and hostile to a script.
 * Every prompt is charged at least `MIN_PROMPT_COST_BYTES` so a flood of
 * one-character prompts costs the same as a flood of real ones.
 *
 * Over budget, the frame is REFUSED with an error rather than dropped
 * silently: a person who pasted something and saw nothing happen will paste it
 * again. The refusal itself is rate-limited so it cannot be used to amplify.
 */
const PROMPT_BYTES_PER_SECOND = 8 * 1024;
const PROMPT_BURST_BYTES = 64 * 1024;
const MIN_PROMPT_COST_BYTES = 4 * 1024;

/**
 * Control-frame budget per socket. Subscribing eight panes at once is normal;
 * hundreds of frames a second is a program. Excess frames are dropped and the
 * refusal is sent at most once a second.
 */
const CONTROL_FRAMES_PER_SECOND = 50;
const CONTROL_FRAME_BURST = 200;

export interface AgentGatewayOptions {
  readonly identity: IdentityProvider;
  readonly registry: AgentRegistry;
  readonly log: AgentLogger;
  /** Origins permitted to open a websocket. Blocks cross-site socket hijacking. */
  readonly allowedOrigins: readonly string[];
  /** Defaults to "/rt/agent". */
  readonly path?: string;
}

export class AgentGateway {
  readonly #wss = new WebSocketServer({ noServer: true });
  readonly #sockets = new Set<WebSocket>();
  readonly #options: AgentGatewayOptions;
  readonly #path: string;

  constructor(options: AgentGatewayOptions) {
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
   * Convenience for a server with no other `upgrade` listener.
   *
   * DO NOT use this alongside the canvas or terminal gateways: Node delivers
   * `upgrade` to every listener, and the one that does not own the path
   * destroys the other's socket. Route through one dispatcher instead.
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
        this.#options.log.warn({ origin }, "rejected agent upgrade: bad origin");
        return reject("403 Forbidden");
      }

      const workspaceId = url.searchParams.get("workspace");
      if (workspaceId === null || !WORKSPACE_ID_RE.test(workspaceId)) {
        return reject("400 Bad Request");
      }

      const principal = await this.#options.identity.authenticate(req.headers, url);
      if (principal === null) {
        this.#options.log.warn({ workspaceId }, "rejected agent upgrade: unauthenticated");
        return reject("401 Unauthorized");
      }

      if (!(await this.#options.identity.isMember(principal, workspaceId))) {
        this.#options.log.warn(
          { workspaceId, userId: principal.userId },
          "rejected agent upgrade: not a member",
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
        "agent upgrade failed",
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
    const { log, registry, identity } = this.#options;
    this.#sockets.add(ws);

    const send = (message: ServerAgentControl): void => {
      if (ws.readyState === ws.OPEN) ws.send(encodeServerAgentControl(message));
    };

    // After the upgrade, not at it, so the client gets a message it can render
    // in the pane instead of an opaque handshake failure. Authorization is
    // already done by this point; a version mismatch grants nothing.
    if (requestedVersion !== null && requestedVersion !== String(AGENT_PROTOCOL_VERSION)) {
      send(agentError("version-mismatch", messageFor("version-mismatch", ""), false));
      ws.close(1002, "version-mismatch");
      this.#sockets.delete(ws);
      return;
    }

    /** Channels this socket owns. Never reused after a channel is released. */
    const channels = new Map<number, { readonly session: AgentSession; readonly viewer: AgentViewer }>();
    let nextChannel = 1;

    let promptTokens = PROMPT_BURST_BYTES;
    let promptRefilledAt = Date.now();
    let lastPromptRefusalLog = 0;

    const spendPromptBudget = (bytes: number): boolean => {
      const now = Date.now();
      promptTokens = Math.min(
        PROMPT_BURST_BYTES,
        promptTokens + ((now - promptRefilledAt) / 1000) * PROMPT_BYTES_PER_SECOND,
      );
      promptRefilledAt = now;
      const cost = Math.max(bytes, MIN_PROMPT_COST_BYTES);
      if (promptTokens < cost) {
        if (now - lastPromptRefusalLog > 1000) {
          lastPromptRefusalLog = now;
          log.warn(
            { workspaceId, userId: principal.userId, bytes },
            "refusing agent prompt over rate limit",
          );
        }
        return false;
      }
      promptTokens -= cost;
      return true;
    };

    let frameTokens = CONTROL_FRAME_BURST;
    let frameRefilledAt = Date.now();
    let lastFrameRefusal = 0;

    const spendFrameBudget = (): boolean => {
      const now = Date.now();
      frameTokens = Math.min(
        CONTROL_FRAME_BURST,
        frameTokens + ((now - frameRefilledAt) / 1000) * CONTROL_FRAMES_PER_SECOND,
      );
      frameRefilledAt = now;
      if (frameTokens < 1) {
        if (now - lastFrameRefusal > 1000) {
          lastFrameRefusal = now;
          log.warn(
            { workspaceId, userId: principal.userId },
            "dropping agent control frames over rate limit",
          );
          send(agentError("busy", "Too many messages. Slow down and try again.", true));
        }
        return false;
      }
      frameTokens -= 1;
      return true;
    };

    /** Uniform failure path for every control message. Never leaks a detail. */
    const fail = (
      error: unknown,
      ctx: { readonly id?: string; readonly channel?: number },
    ): void => {
      if (error instanceof AgentControlError) {
        send(agentError(error.code, error.message, error.retryable, ctx));
        return;
      }
      log.warn(
        {
          workspaceId,
          userId: principal.userId,
          err: error instanceof Error ? error.message : "unknown",
        },
        "agent control message failed",
      );
      send(agentError("internal", "That did not work. Try again.", true, ctx));
    };

    const notFound = (id: string, agentId: string): void => {
      // The operator log distinguishes; the wire never does (see the header).
      log.warn(
        {
          workspaceId,
          userId: principal.userId,
          agentId,
          reason: registry.existsElsewhere(workspaceId, agentId) ? "forbidden" : "not-found",
        },
        "agent subscribe refused",
      );
      send(agentError("not-found", messageFor("not-found", ""), false, { id }));
    };

    const onSubscribe = async (message: ClientAgentSubscribe): Promise<void> => {
      if (channels.size >= AGENT_MAX_CHANNELS_PER_SOCKET) {
        send(
          agentError("too-many-channels", messageFor("too-many-channels", ""), false, {
            id: message.id,
          }),
        );
        return;
      }

      // T11: re-authorize rather than trust the socket that produced the
      // cursor. Membership can be revoked while a client is away, and a replay
      // request is precisely where that matters.
      if (!(await identity.isMember(principal, workspaceId))) {
        log.warn(
          { workspaceId, userId: principal.userId, agentId: message.agentId },
          "agent subscribe refused: membership revoked",
        );
        send(agentError("not-found", messageFor("not-found", ""), false, { id: message.id }));
        return;
      }

      // Re-checked after the await: two `subscribe` frames can be in flight at
      // once, and the check above ran before either of them yielded.
      if (channels.size >= AGENT_MAX_CHANNELS_PER_SOCKET) {
        send(
          agentError("too-many-channels", messageFor("too-many-channels", ""), false, {
            id: message.id,
          }),
        );
        return;
      }

      const session = registry.get(workspaceId, message.agentId);
      if (session === null) {
        notFound(message.id, message.agentId);
        return;
      }

      const channel = nextChannel;
      nextChannel += 1;

      const viewer: AgentViewer = {
        viewerId: randomUUID(),
        userId: principal.userId,
        channel,
        send: (control) => {
          if (ws.readyState === ws.OPEN) ws.send(encodeServerAgentControl(control));
        },
        bufferedBytes: () => ws.bufferedAmount,
        detached: (reason) => {
          channels.delete(channel);
          if (reason === "slow-consumer") {
            send(
              agentError("slow-consumer", messageFor("slow-consumer", ""), true, { channel }),
            );
          }
          // Lets the registry's idle reaper (off by default) start counting.
          registry.noteViewerChange(session);
        },
      };

      const request: AgentAttachRequest =
        message.fromSeq === undefined
          ? { requestId: message.id }
          : { requestId: message.id, fromSeq: message.fromSeq };

      // attach() sends `attached` and the replay synchronously, so nothing can
      // interleave ahead of the history it is supposed to follow.
      if (!session.attach(viewer, request)) {
        notFound(message.id, message.agentId);
        return;
      }
      channels.set(channel, { session, viewer });
    };

    const entryFor = (channel: number, id?: string): { session: AgentSession; viewer: AgentViewer } | null => {
      const entry = channels.get(channel);
      if (entry === undefined) {
        const ctx = id === undefined ? { channel } : { id, channel };
        send(agentError("bad-channel", messageFor("bad-channel", ""), false, ctx));
        return null;
      }
      return entry;
    };

    const onText = (raw: string): void => {
      const parsed = parseClientAgentControl(raw);
      if (!parsed.ok) {
        log.debug(
          { workspaceId, userId: principal.userId, reason: parsed.reason },
          "rejected agent control message",
        );
        send(agentError(parsed.code, messageFor(parsed.code, "Malformed agent message."), false));
        return;
      }
      const message = parsed.message;

      switch (message.t) {
        case "subscribe":
          void onSubscribe(message).catch((error: unknown) => fail(error, { id: message.id }));
          return;

        case "prompt": {
          const entry = entryFor(message.channel, message.id);
          if (entry === null) return;
          if (!spendPromptBudget(utf8ByteLength(message.text))) {
            send(
              agentError("busy", "You are sending prompts faster than the agent can take them.", true, {
                id: message.id,
                channel: message.channel,
              }),
            );
            return;
          }
          void entry.session
            .prompt(entry.viewer, message.text)
            .catch((error: unknown) => fail(error, { id: message.id, channel: message.channel }));
          return;
        }

        case "interrupt": {
          const entry = entryFor(message.channel, message.id);
          if (entry === null) return;
          void entry.session
            .interrupt(entry.viewer)
            .catch((error: unknown) => fail(error, { id: message.id, channel: message.channel }));
          return;
        }

        case "stop": {
          const entry = entryFor(message.channel, message.id);
          if (entry === null) return;
          void entry.session
            .stop(entry.viewer)
            .catch((error: unknown) => fail(error, { id: message.id, channel: message.channel }));
          return;
        }

        case "unsubscribe": {
          const entry = entryFor(message.channel);
          if (entry === null) return;
          // The agent keeps working: sessions are server-owned (PLAN.md §6).
          entry.session.detach(entry.viewer, "client");
          return;
        }
      }
    };

    ws.on("message", (data: RawData, isBinary: boolean) => {
      try {
        if (isBinary) {
          // There is no binary channel in this protocol. See FRAMING.
          send(agentError("bad-message", "Only text frames are accepted.", false));
          return;
        }
        const bytes = toBytes(data);
        if (bytes.byteLength > AGENT_MAX_CONTROL_FRAME_BYTES) {
          send(agentError("payload-too-large", messageFor("payload-too-large", ""), false));
          return;
        }
        if (!spendFrameBudget()) return;
        onText(Buffer.from(bytes).toString("utf8"));
      } catch (error: unknown) {
        log.warn(
          {
            workspaceId,
            userId: principal.userId,
            err: error instanceof Error ? error.message : "unknown",
          },
          "failed to handle agent message",
        );
        send(agentError("internal", "That message could not be handled.", true));
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
        "agent client left",
      );
    };

    ws.on("close", cleanup);
    ws.on("error", cleanup);

    log.info(
      { workspaceId, userId: principal.userId, sockets: this.#sockets.size },
      "agent client joined",
    );
  }

  /**
   * Closes every agent socket. Does NOT end the sessions behind them — those
   * belong to `AgentRegistry`, and stopping an agent mid-task because the
   * process is restarting is exactly what PLAN.md §6 rules out. A shutdown that
   * also wants the agents gone calls `registry.closeAll()`.
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
 * Builds a `ServerAgentError`. Optional fields are attached conditionally
 * because `exactOptionalPropertyTypes` is on: an absent id must be an absent
 * key, not an explicit `undefined`.
 */
function agentError(
  code: AgentErrorCode,
  message: string,
  retryable: boolean,
  ctx: { readonly id?: string; readonly channel?: number } = {},
): ServerAgentError {
  // Defence in depth: `forbidden` is for the operator log only and must never
  // reach a client, whatever a caller passes.
  const safeCode: AgentErrorCode = code === "forbidden" ? "not-found" : code;
  const text = message.length > 0 ? message : messageFor(safeCode, "That did not work.");
  const base = {
    t: "error",
    code: safeCode,
    message: text,
    retryable: retryable || retryableFor(safeCode),
  } as const;
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

/* ==========================================================================
 * Re-exports — one import site for the whole agent transport, matching
 * terminal.ts.
 * ========================================================================== */

export { AgentOpenError, AgentRegistry } from "./agent-registry.ts";
export type {
  AgentOpenErrorCode,
  AgentOpenOptions,
  AgentRegistryOptions,
  AgentSummary,
  BrokerBindingSource,
} from "./agent-registry.ts";
export { AgentControlError, AgentSession } from "./agent-session.ts";
export type {
  AgentAttachRequest,
  AgentDetachReason,
  AgentLogger,
  AgentSessionOptions,
  AgentViewer,
} from "./agent-session.ts";
export { registerAgentRoutes } from "./agent-routes.ts";
export type { AgentAuthorize, AgentRoutesOptions, WorkspaceSandboxEnsure } from "./agent-routes.ts";
