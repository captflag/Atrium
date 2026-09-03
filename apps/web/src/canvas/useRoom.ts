/**
 * Yjs room binding: connects to the gateway, exposes panes and presence.
 *
 * A hand-rolled provider rather than y-websocket's, so reconnect behaviour and
 * the identity query are explicit and the wire format matches the server
 * exactly (both speak the y-websocket message protocol).
 */

import { useCallback, useEffect, useRef, useSyncExternalStore } from "react";
import * as Y from "yjs";
import * as syncProtocol from "y-protocols/sync";
import * as awarenessProtocol from "y-protocols/awareness";
import * as encoding from "lib0/encoding";
import * as decoding from "lib0/decoding";
import type { Pane, PaneKind, Presence } from "@atrium/shared";

const MESSAGE_SYNC = 0;
const MESSAGE_AWARENESS = 1;

const RECONNECT_BASE_MS = 500;
const RECONNECT_MAX_MS = 10_000;

export type ConnectionState = "connecting" | "connected" | "offline";

/** Stable per-tab identity. sessionStorage so a second tab is a second user. */
function tabIdentity(): { userId: string; name: string; color: string } {
  const KEY = "atrium.identity";
  try {
    const saved = sessionStorage.getItem(KEY);
    if (saved !== null) return JSON.parse(saved) as ReturnType<typeof tabIdentity>;
  } catch {
    /* private mode, or storage disabled — fall through and mint a fresh one */
  }
  const id = Math.random().toString(36).slice(2, 10);
  const palette = ["#e8590c", "#2f9e44", "#1971c2", "#9c36b5", "#c2255c", "#0c8599"];
  const identity = {
    userId: id,
    name: `guest-${id.slice(0, 4)}`,
    color: palette[Math.floor(Math.random() * palette.length)] ?? "#1971c2",
  };
  try {
    sessionStorage.setItem(KEY, JSON.stringify(identity));
  } catch {
    /* not fatal — identity just won't survive a reload */
  }
  return identity;
}

export interface Room {
  readonly panes: readonly Pane[];
  readonly peers: readonly Presence[];
  readonly state: ConnectionState;
  readonly self: { userId: string; name: string; color: string };
  /** `size` defaults to a note-sized pane; a terminal asks for a bigger one. */
  addPane(
    kind: PaneKind,
    x: number,
    y: number,
    size?: { readonly width: number; readonly height: number },
  ): void;
  updatePane(id: string, patch: Partial<Omit<Pane, "id" | "kind">>): void;
  deletePane(id: string): void;
  setCursor(cursor: { x: number; y: number } | null): void;
}

export function useRoom(workspaceId: string): Room {
  const identityRef = useRef(tabIdentity());
  const docRef = useRef<Y.Doc | null>(null);
  const awarenessRef = useRef<awarenessProtocol.Awareness | null>(null);
  const socketRef = useRef<WebSocket | null>(null);

  if (docRef.current === null) {
    docRef.current = new Y.Doc();
    awarenessRef.current = new awarenessProtocol.Awareness(docRef.current);
  }
  const doc = docRef.current;
  const awareness = awarenessRef.current as awarenessProtocol.Awareness;

  // --- snapshots for useSyncExternalStore ---------------------------------

  const panesSnapshot = useRef<readonly Pane[]>([]);
  const peersSnapshot = useRef<readonly Presence[]>([]);
  const stateRef = useRef<ConnectionState>("connecting");
  const listeners = useRef(new Set<() => void>());

  const notify = useCallback(() => {
    for (const l of listeners.current) l();
  }, []);

  const subscribe = useCallback((cb: () => void) => {
    listeners.current.add(cb);
    return () => listeners.current.delete(cb);
  }, []);

  // --- connection ---------------------------------------------------------

  useEffect(() => {
    let closed = false;
    let attempt = 0;
    let reconnectTimer: number | undefined;

    const panes = doc.getMap("panes");

    const refreshPanes = (): void => {
      const next: Pane[] = [];
      for (const value of panes.values()) {
        if (value !== null && typeof value === "object") next.push(value as Pane);
      }
      next.sort((a, b) => a.updatedAt - b.updatedAt);
      panesSnapshot.current = next;
      notify();
    };

    const refreshPeers = (): void => {
      const next: Presence[] = [];
      for (const [clientId, raw] of awareness.getStates()) {
        if (clientId === doc.clientID) continue;
        const presence = (raw as { presence?: Presence } | undefined)?.presence;
        if (presence && typeof presence.userId === "string") next.push(presence);
      }
      peersSnapshot.current = next;
      notify();
    };

    panes.observeDeep(refreshPanes);
    awareness.on("change", refreshPeers);
    refreshPanes();

    const setState = (next: ConnectionState): void => {
      stateRef.current = next;
      notify();
    };

    const connect = (): void => {
      if (closed) return;
      setState(attempt === 0 ? "connecting" : stateRef.current);

      const scheme = window.location.protocol === "https:" ? "wss" : "ws";
      const { userId, name } = identityRef.current;
      const url =
        `${scheme}://${window.location.host}/rt` +
        `?workspace=${encodeURIComponent(workspaceId)}` +
        `&uid=${encodeURIComponent(userId)}&name=${encodeURIComponent(name)}`;

      const ws = new WebSocket(url);
      ws.binaryType = "arraybuffer";
      socketRef.current = ws;

      ws.onopen = () => {
        attempt = 0;
        setState("connected");

        const sync = encoding.createEncoder();
        encoding.writeVarUint(sync, MESSAGE_SYNC);
        syncProtocol.writeSyncStep1(sync, doc);
        ws.send(encoding.toUint8Array(sync));

        awareness.setLocalStateField("presence", {
          userId: identityRef.current.userId,
          name: identityRef.current.name,
          color: identityRef.current.color,
        } satisfies Presence);
      };

      ws.onmessage = (event: MessageEvent<ArrayBuffer>) => {
        const decoder = decoding.createDecoder(new Uint8Array(event.data));
        const encoder = encoding.createEncoder();
        const messageType = decoding.readVarUint(decoder);

        if (messageType === MESSAGE_SYNC) {
          encoding.writeVarUint(encoder, MESSAGE_SYNC);
          syncProtocol.readSyncMessage(decoder, encoder, doc, ws);
          if (encoding.length(encoder) > 1) ws.send(encoding.toUint8Array(encoder));
        } else if (messageType === MESSAGE_AWARENESS) {
          awarenessProtocol.applyAwarenessUpdate(
            awareness,
            decoding.readVarUint8Array(decoder),
            ws,
          );
        }
      };

      const scheduleReconnect = (): void => {
        if (closed) return;
        setState("offline");
        const delay = Math.min(RECONNECT_BASE_MS * 2 ** attempt, RECONNECT_MAX_MS);
        attempt += 1;
        reconnectTimer = window.setTimeout(connect, delay);
      };

      ws.onclose = scheduleReconnect;
      ws.onerror = () => ws.close();
    };

    /**
     * Closes a socket without tripping the reconnect path, and without the
     * "closed before the connection is established" warning a CONNECTING
     * socket produces. React StrictMode mounts effects twice in development,
     * so this runs on every mount.
     */
    const closeSocket = (ws: WebSocket): void => {
      ws.onclose = null;
      ws.onerror = null;
      if (ws.readyState === WebSocket.CONNECTING) {
        ws.addEventListener("open", () => ws.close(), { once: true });
      } else if (ws.readyState === WebSocket.OPEN) {
        ws.close();
      }
    };

    const onDocUpdate = (update: Uint8Array, origin: unknown): void => {
      const ws = socketRef.current;
      if (origin === ws || ws === null || ws.readyState !== WebSocket.OPEN) return;
      const encoder = encoding.createEncoder();
      encoding.writeVarUint(encoder, MESSAGE_SYNC);
      syncProtocol.writeUpdate(encoder, update);
      ws.send(encoding.toUint8Array(encoder));
    };

    const onAwarenessUpdate = (
      changes: { added: number[]; updated: number[]; removed: number[] },
      origin: unknown,
    ): void => {
      const ws = socketRef.current;
      if (origin === ws || ws === null || ws.readyState !== WebSocket.OPEN) return;
      const changed = [...changes.added, ...changes.updated, ...changes.removed];
      const encoder = encoding.createEncoder();
      encoding.writeVarUint(encoder, MESSAGE_AWARENESS);
      encoding.writeVarUint8Array(
        encoder,
        awarenessProtocol.encodeAwarenessUpdate(awareness, changed),
      );
      ws.send(encoding.toUint8Array(encoder));
    };

    doc.on("update", onDocUpdate);
    awareness.on("update", onAwarenessUpdate);
    connect();

    return () => {
      closed = true;
      if (reconnectTimer !== undefined) window.clearTimeout(reconnectTimer);
      doc.off("update", onDocUpdate);
      awareness.off("update", onAwarenessUpdate);
      panes.unobserveDeep(refreshPanes);
      awareness.off("change", refreshPeers);
      if (socketRef.current !== null) closeSocket(socketRef.current);
      socketRef.current = null;
    };
  }, [workspaceId, doc, awareness, notify]);

  // --- mutations ----------------------------------------------------------

  const addPane = useCallback(
    (
      kind: PaneKind,
      x: number,
      y: number,
      size?: { readonly width: number; readonly height: number },
    ) => {
      const id = Math.random().toString(36).slice(2, 12);
      doc.getMap("panes").set(id, {
        id,
        kind,
        x: Math.round(x),
        y: Math.round(y),
        width: Math.round(size?.width ?? 260),
        height: Math.round(size?.height ?? 180),
        text: "",
        updatedBy: identityRef.current.userId,
        updatedAt: Date.now(),
      } satisfies Pane);
    },
    [doc],
  );

  const updatePane = useCallback(
    (id: string, patch: Partial<Omit<Pane, "id" | "kind">>) => {
      const panes = doc.getMap("panes");
      const current = panes.get(id) as Pane | undefined;
      if (!current) return;
      panes.set(id, {
        ...current,
        ...patch,
        updatedBy: identityRef.current.userId,
        updatedAt: Date.now(),
      });
    },
    [doc],
  );

  const deletePane = useCallback((id: string) => doc.getMap("panes").delete(id), [doc]);

  const setCursor = useCallback(
    (cursor: { x: number; y: number } | null) => {
      const base = {
        userId: identityRef.current.userId,
        name: identityRef.current.name,
        color: identityRef.current.color,
      };
      awareness.setLocalStateField(
        "presence",
        cursor === null ? base : ({ ...base, cursor } satisfies Presence),
      );
    },
    [awareness],
  );

  const panes = useSyncExternalStore(subscribe, () => panesSnapshot.current);
  const peers = useSyncExternalStore(subscribe, () => peersSnapshot.current);
  const state = useSyncExternalStore(subscribe, () => stateRef.current);

  return {
    panes,
    peers,
    state,
    self: identityRef.current,
    addPane,
    updatePane,
    deletePane,
    setCursor,
  };
}
