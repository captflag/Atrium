/**
 * Websocket gateway for the canvas.
 *
 * Authorization happens at the HTTP upgrade, before any Yjs bytes are
 * exchanged (SECURITY.md T6): possession of a workspace id is not access.
 * An unauthenticated or non-member upgrade is refused with a status line and
 * the socket destroyed.
 *
 * WIRING (changed in M2). This gateway no longer installs its own `upgrade`
 * listener, and no longer answers for paths it does not own. Node emits
 * `upgrade` to EVERY listener, so two gateways each destroying the other's
 * sockets is not a coexistence strategy — `index.ts` runs ONE dispatcher that
 * offers each request to each gateway's `handleUpgrade` and owns the final
 * reject. `handleUpgrade` returns true when it has taken the socket.
 */

import type { Duplex } from "node:stream";
import { WebSocketServer, type WebSocket } from "ws";
import type { IdentityProvider, Principal } from "../identity.ts";
import type { DocStore } from "./docstore.ts";
import { Room, type RoomConnection, type RoomLogger } from "./room.ts";

const WORKSPACE_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
/** Ping interval; a socket that misses two is assumed dead. */
const HEARTBEAT_MS = 30_000;

interface GatewayOptions {
  readonly identity: IdentityProvider;
  readonly store: DocStore;
  readonly log: RoomLogger & { info(obj: Record<string, unknown>, msg: string): void };
  /** Origins permitted to open a websocket. Blocks cross-site socket hijacking. */
  readonly allowedOrigins: readonly string[];
}

export class RealtimeGateway {
  readonly #rooms = new Map<string, Room>();
  readonly #wss = new WebSocketServer({ noServer: true });

  readonly #options: GatewayOptions;

  constructor(options: GatewayOptions) {
    this.#options = options;
  }

  get roomCount(): number {
    return this.#rooms.size;
  }

  /**
   * First refusal on an http `upgrade`.
   *
   * Returns true when this gateway has CLAIMED the socket — the caller must
   * then not touch it again, not even to reject it, because authorization
   * continues on a promise. Returns false when the path is not ours and the
   * socket is untouched, which is what lets the terminal gateway and this one
   * share a server.
   */
  handleUpgrade(req: import("node:http").IncomingMessage, socket: Duplex, head: Buffer): boolean {
    let url: URL;
    try {
      url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
    } catch {
      return false;
    }
    if (url.pathname !== "/rt") return false;
    void this.#authorize(req, socket, head, url);
    return true;
  }

  async #authorize(
    req: import("node:http").IncomingMessage,
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
        this.#options.log.warn({ origin }, "rejected websocket upgrade: bad origin");
        return reject("403 Forbidden");
      }

      const workspaceId = url.searchParams.get("workspace");
      if (workspaceId === null || !WORKSPACE_ID_RE.test(workspaceId)) {
        return reject("400 Bad Request");
      }

      const principal = await this.#options.identity.authenticate(req.headers, url);
      if (principal === null) {
        this.#options.log.warn({ workspaceId }, "rejected websocket upgrade: unauthenticated");
        return reject("401 Unauthorized");
      }

      if (!(await this.#options.identity.isMember(principal, workspaceId))) {
        this.#options.log.warn(
          { workspaceId, userId: principal.userId },
          "rejected websocket upgrade: not a member",
        );
        return reject("403 Forbidden");
      }

      this.#wss.handleUpgrade(req, socket, head, (ws) => {
        void this.#attach(ws, workspaceId, principal);
      });
    } catch (error: unknown) {
      this.#options.log.warn(
        { err: error instanceof Error ? error.message : "unknown" },
        "websocket upgrade failed",
      );
      reject("400 Bad Request");
    }
  }

  async #attach(ws: WebSocket, workspaceId: string, principal: Principal): Promise<void> {
    const room = await this.#room(workspaceId);

    const conn: RoomConnection = {
      userId: principal.userId,
      send: (data) => {
        if (ws.readyState === ws.OPEN) ws.send(data);
      },
      close: () => ws.close(),
    };

    room.addConnection(conn);
    this.#options.log.info(
      { workspaceId, userId: principal.userId, connections: room.connectionCount },
      "client joined",
    );

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

    ws.on("message", (data: Buffer) => {
      room.handleMessage(conn, new Uint8Array(data));
    });

    const cleanup = (): void => {
      clearInterval(heartbeat);
      room.removeConnection(conn);
      this.#options.log.info(
        { workspaceId, userId: principal.userId, connections: room.connectionCount },
        "client left",
      );
      // Persist and release an empty room rather than holding every doc that
      // has ever been opened in memory.
      if (room.connectionCount === 0) {
        this.#rooms.delete(workspaceId);
        void room.destroy();
      }
    };

    ws.on("close", cleanup);
    ws.on("error", cleanup);
  }

  async #room(workspaceId: string): Promise<Room> {
    const existing = this.#rooms.get(workspaceId);
    if (existing) return existing;

    const room = await Room.open(workspaceId, this.#options.store, this.#options.log);
    // Re-check: another upgrade may have opened the same room while we awaited.
    const raced = this.#rooms.get(workspaceId);
    if (raced) {
      await room.destroy();
      return raced;
    }
    this.#rooms.set(workspaceId, room);
    return room;
  }

  async close(): Promise<void> {
    await Promise.all([...this.#rooms.values()].map((r) => r.destroy()));
    this.#rooms.clear();
    this.#wss.close();
  }
}
