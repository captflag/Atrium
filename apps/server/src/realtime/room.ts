/**
 * One collaborative room per workspace.
 *
 * Holds the authoritative Y.Doc, relays sync and awareness messages between
 * connections, validates pane payloads server-side, and debounces persistence.
 *
 * Wire format is the y-websocket protocol: a varUint message type followed by
 * the protocol payload. Implemented here rather than pulled from y-websocket's
 * bundled server so the connection can be authenticated at upgrade
 * (SECURITY.md T6) and pane writes can be validated.
 */

import * as Y from "yjs";
import * as syncProtocol from "y-protocols/sync";
import * as awarenessProtocol from "y-protocols/awareness";
import * as encoding from "lib0/encoding";
import * as decoding from "lib0/decoding";
import { validatePane } from "@atrium/shared";
import type { DocStore } from "./docstore.ts";

const MESSAGE_SYNC = 0;
const MESSAGE_AWARENESS = 1;

/** How long after the last edit to write the doc. Bounds work lost on crash. */
const PERSIST_DEBOUNCE_MS = 800;
/** Hard ceiling so a continuously-edited canvas still gets checkpointed. */
const PERSIST_MAX_INTERVAL_MS = 10_000;

export interface RoomConnection {
  send(data: Uint8Array): void;
  close(): void;
  readonly userId: string;
}

export interface RoomLogger {
  warn(obj: Record<string, unknown>, msg: string): void;
  debug(obj: Record<string, unknown>, msg: string): void;
}

export class Room {
  readonly doc = new Y.Doc();
  readonly awareness = new awarenessProtocol.Awareness(this.doc);
  readonly #connections = new Map<RoomConnection, Set<number>>();

  #persistTimer: NodeJS.Timeout | undefined;
  #firstDirtyAt = 0;
  #destroyed = false;

  readonly workspaceId: string;
  readonly #store: DocStore;
  readonly #log: RoomLogger;

  private constructor(workspaceId: string, store: DocStore, log: RoomLogger) {
    this.workspaceId = workspaceId;
    this.#store = store;
    this.#log = log;
  }

  static async open(workspaceId: string, store: DocStore, log: RoomLogger): Promise<Room> {
    const room = new Room(workspaceId, store, log);
    const saved = await store.load(workspaceId);
    if (saved) Y.applyUpdate(room.doc, saved, "persistence");

    room.doc.on("update", (update: Uint8Array, origin: unknown) => {
      room.#broadcastUpdate(update, origin);
      room.#schedulePersist();
    });

    // Server-side validation of an untrusted CRDT (SECURITY.md T6). The server
    // participates as an authority: an invalid pane is corrected or removed
    // rather than rejected, because a CRDT update cannot be un-received.
    room.panes.observeDeep(() => room.#enforcePaneSchema());

    room.awareness.on(
      "update",
      (
        changes: { added: number[]; updated: number[]; removed: number[] },
        origin: unknown,
      ) => room.#broadcastAwareness(changes, origin),
    );

    return room;
  }

  get panes(): Y.Map<unknown> {
    return this.doc.getMap("panes");
  }

  get connectionCount(): number {
    return this.#connections.size;
  }

  // --- connections -------------------------------------------------------

  addConnection(conn: RoomConnection): void {
    this.#connections.set(conn, new Set());

    // Step 1 of the sync handshake, then our awareness state.
    const sync = encoding.createEncoder();
    encoding.writeVarUint(sync, MESSAGE_SYNC);
    syncProtocol.writeSyncStep1(sync, this.doc);
    conn.send(encoding.toUint8Array(sync));

    const states = this.awareness.getStates();
    if (states.size > 0) {
      const aw = encoding.createEncoder();
      encoding.writeVarUint(aw, MESSAGE_AWARENESS);
      encoding.writeVarUint8Array(
        aw,
        awarenessProtocol.encodeAwarenessUpdate(this.awareness, [...states.keys()]),
      );
      conn.send(encoding.toUint8Array(aw));
    }
  }

  removeConnection(conn: RoomConnection): void {
    const controlled = this.#connections.get(conn);
    if (controlled && controlled.size > 0) {
      awarenessProtocol.removeAwarenessStates(this.awareness, [...controlled], null);
    }
    this.#connections.delete(conn);
  }

  /** Handles one inbound message. Never throws to the caller. */
  handleMessage(conn: RoomConnection, data: Uint8Array): void {
    try {
      const decoder = decoding.createDecoder(data);
      const encoder = encoding.createEncoder();
      const messageType = decoding.readVarUint(decoder);

      switch (messageType) {
        case MESSAGE_SYNC: {
          encoding.writeVarUint(encoder, MESSAGE_SYNC);
          syncProtocol.readSyncMessage(decoder, encoder, this.doc, conn);
          if (encoding.length(encoder) > 1) conn.send(encoding.toUint8Array(encoder));
          break;
        }
        case MESSAGE_AWARENESS: {
          awarenessProtocol.applyAwarenessUpdate(
            this.awareness,
            decoding.readVarUint8Array(decoder),
            conn,
          );
          break;
        }
        default:
          this.#log.warn({ workspaceId: this.workspaceId, messageType }, "unknown message type");
      }
    } catch (error: unknown) {
      this.#log.warn(
        { workspaceId: this.workspaceId, err: error instanceof Error ? error.message : "unknown" },
        "failed to handle realtime message",
      );
    }
  }

  #broadcastUpdate(update: Uint8Array, origin: unknown): void {
    const encoder = encoding.createEncoder();
    encoding.writeVarUint(encoder, MESSAGE_SYNC);
    syncProtocol.writeUpdate(encoder, update);
    const message = encoding.toUint8Array(encoder);
    for (const conn of this.#connections.keys()) {
      if (conn !== origin) conn.send(message);
    }
  }

  #broadcastAwareness(
    changes: { added: number[]; updated: number[]; removed: number[] },
    origin: unknown,
  ): void {
    const changed = [...changes.added, ...changes.updated, ...changes.removed];

    // Track which awareness clients a connection owns, so a disconnect clears
    // that user's cursor instead of leaving a ghost on everyone's canvas.
    if (origin !== null && typeof origin === "object" && this.#connections.has(origin as RoomConnection)) {
      const owned = this.#connections.get(origin as RoomConnection);
      if (owned) {
        for (const id of changes.added) owned.add(id);
        for (const id of changes.removed) owned.delete(id);
      }
    }

    const encoder = encoding.createEncoder();
    encoding.writeVarUint(encoder, MESSAGE_AWARENESS);
    encoding.writeVarUint8Array(
      encoder,
      awarenessProtocol.encodeAwarenessUpdate(this.awareness, changed),
    );
    const message = encoding.toUint8Array(encoder);
    for (const conn of this.#connections.keys()) conn.send(message);
  }

  // --- validation --------------------------------------------------------

  #enforcePaneSchema(): void {
    const panes = this.panes;
    const corrections: Array<[string, unknown]> = [];
    const removals: string[] = [];

    for (const [id, raw] of panes.entries()) {
      const result = validatePane(raw);
      if (!result.ok) {
        this.#log.warn(
          { workspaceId: this.workspaceId, paneId: id, reason: result.reason },
          "rejected invalid pane",
        );
        removals.push(id);
        continue;
      }
      // Id must match its key, else a client could shadow another pane.
      if (result.pane.id !== id) {
        removals.push(id);
        continue;
      }
      if (JSON.stringify(result.pane) !== JSON.stringify(raw)) {
        corrections.push([id, result.pane]);
      }
    }

    if (corrections.length === 0 && removals.length === 0) return;

    // Origin "server" so this does not recurse into another enforcement pass.
    this.doc.transact(() => {
      for (const id of removals) panes.delete(id);
      for (const [id, pane] of corrections) panes.set(id, pane);
    }, "server");
  }

  // --- persistence -------------------------------------------------------

  #schedulePersist(): void {
    if (this.#destroyed) return;
    if (this.#firstDirtyAt === 0) this.#firstDirtyAt = Date.now();

    if (Date.now() - this.#firstDirtyAt >= PERSIST_MAX_INTERVAL_MS) {
      void this.persistNow();
      return;
    }
    if (this.#persistTimer) clearTimeout(this.#persistTimer);
    this.#persistTimer = setTimeout(() => void this.persistNow(), PERSIST_DEBOUNCE_MS);
  }

  async persistNow(): Promise<void> {
    if (this.#persistTimer) {
      clearTimeout(this.#persistTimer);
      this.#persistTimer = undefined;
    }
    this.#firstDirtyAt = 0;
    try {
      await this.#store.save(this.workspaceId, Y.encodeStateAsUpdate(this.doc));
    } catch (error: unknown) {
      this.#log.warn(
        { workspaceId: this.workspaceId, err: error instanceof Error ? error.message : "unknown" },
        "failed to persist canvas",
      );
    }
  }

  async destroy(): Promise<void> {
    this.#destroyed = true;
    await this.persistNow();
    for (const conn of this.#connections.keys()) conn.close();
    this.#connections.clear();
    this.awareness.destroy();
    this.doc.destroy();
  }
}
