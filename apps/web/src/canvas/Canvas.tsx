/**
 * The canvas: a single CSS-transformed surface with absolutely-positioned
 * panes (PLAN.md §4). Panes are real DOM because they will hold iframes,
 * terminals and editors — a drawing library cannot.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import type { Pane, PaneKind } from "@atrium/shared";
import { PANE_MIN_SIZE } from "@atrium/shared";
import { useRoom } from "./useRoom.ts";
import { PaneView } from "./PaneView.tsx";
import { Cursors } from "./Cursors.tsx";
import { deleteAgent } from "./agentApi.ts";
import { closeTerminal } from "./terminalApi.ts";
import "./canvas.css";

const ZOOM_MIN = 0.25;
const ZOOM_MAX = 2.5;
const ZOOM_SENSITIVITY = 0.0015;

interface Viewport {
  x: number;
  y: number;
  zoom: number;
}

type Drag =
  | { kind: "pan"; startX: number; startY: number; originX: number; originY: number }
  | { kind: "move"; paneId: string; offsetX: number; offsetY: number }
  | { kind: "resize"; paneId: string; startW: number; startH: number; startX: number; startY: number };

export function Canvas({ workspaceId }: { workspaceId: string }): React.ReactElement {
  const room = useRoom(workspaceId);
  const surfaceRef = useRef<HTMLDivElement>(null);
  const [viewport, setViewport] = useState<Viewport>({ x: 0, y: 0, zoom: 1 });
  const [drag, setDrag] = useState<Drag | null>(null);
  const [selected, setSelected] = useState<string | null>(null);

  /** Screen point to canvas coordinates. */
  const toCanvas = useCallback(
    (clientX: number, clientY: number): { x: number; y: number } => {
      const rect = surfaceRef.current?.getBoundingClientRect();
      const left = rect?.left ?? 0;
      const top = rect?.top ?? 0;
      return {
        x: (clientX - left - viewport.x) / viewport.zoom,
        y: (clientY - top - viewport.y) / viewport.zoom,
      };
    },
    [viewport],
  );

  // Wheel: ctrl/cmd zooms about the pointer, otherwise pans.
  useEffect(() => {
    const surface = surfaceRef.current;
    if (!surface) return;

    const onWheel = (event: WheelEvent): void => {
      event.preventDefault();
      setViewport((v) => {
        if (!event.ctrlKey && !event.metaKey) {
          return { ...v, x: v.x - event.deltaX, y: v.y - event.deltaY };
        }
        const rect = surface.getBoundingClientRect();
        const px = event.clientX - rect.left;
        const py = event.clientY - rect.top;
        const next = Math.min(
          ZOOM_MAX,
          Math.max(ZOOM_MIN, v.zoom * (1 - event.deltaY * ZOOM_SENSITIVITY)),
        );
        const scale = next / v.zoom;
        return { zoom: next, x: px - (px - v.x) * scale, y: py - (py - v.y) * scale };
      });
    };

    surface.addEventListener("wheel", onWheel, { passive: false });
    return () => surface.removeEventListener("wheel", onWheel);
  }, []);

  const onPointerMove = useCallback(
    (event: React.PointerEvent) => {
      const point = toCanvas(event.clientX, event.clientY);
      room.setCursor(point);

      if (drag === null) return;
      if (drag.kind === "pan") {
        setViewport((v) => ({
          ...v,
          x: drag.originX + (event.clientX - drag.startX),
          y: drag.originY + (event.clientY - drag.startY),
        }));
      } else if (drag.kind === "move") {
        room.updatePane(drag.paneId, { x: point.x - drag.offsetX, y: point.y - drag.offsetY });
      } else {
        room.updatePane(drag.paneId, {
          width: Math.max(PANE_MIN_SIZE, drag.startW + (point.x - drag.startX)),
          height: Math.max(PANE_MIN_SIZE, drag.startH + (point.y - drag.startY)),
        });
      }
    },
    [drag, room, toCanvas],
  );

  const endDrag = useCallback(() => setDrag(null), []);

  const onSurfacePointerDown = useCallback(
    (event: React.PointerEvent) => {
      if (event.target !== event.currentTarget) return;
      setSelected(null);
      setDrag({
        kind: "pan",
        startX: event.clientX,
        startY: event.clientY,
        originX: viewport.x,
        originY: viewport.y,
      });
    },
    [viewport],
  );

  const onDoubleClick = useCallback(
    (event: React.MouseEvent) => {
      if (event.target !== event.currentTarget) return;
      const point = toCanvas(event.clientX, event.clientY);
      room.addPane("note", point.x - 130, point.y - 90);
    },
    [room, toCanvas],
  );

  /** Remove a pane from the shared document. The pane component has already
   *  ended whatever it owned server-side by the time this runs. */
  const deletePane = useCallback(
    (paneId: string) => {
      room.deletePane(paneId);
      setSelected(null);
    },
    [room],
  );

  /**
   * The keyboard delete path, which has no pane component to do its cleanup.
   *
   * Sessions are SERVER-OWNED (PLAN.md §6): nothing else ever ends them. The
   * close button works because `PaneView` wraps it with `closeTerminal`, and
   * `AgentPane` calls `deleteAgent` itself — but this shortcut bypassed both
   * and left a running shell, and would now leave an agent session that keeps
   * working and keeps spending. So it repeats the same teardown here. Both
   * calls are idempotent, so a pane that somehow arrives through both paths
   * costs one redundant DELETE and nothing else.
   */
  const deletePaneWithTeardown = useCallback(
    (paneId: string) => {
      const pane = room.panes.find((p) => p.id === paneId);
      if (pane?.kind === "terminal") void closeTerminal(workspaceId, pane.id);
      if (pane?.kind === "agent") void deleteAgent(workspaceId, pane.id);
      deletePane(paneId);
    },
    [room, workspaceId, deletePane],
  );

  // Delete removes the selected pane, unless a text field has focus.
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent): void => {
      if (selected === null) return;
      const target = event.target as HTMLElement | null;
      if (target && (target.tagName === "TEXTAREA" || target.tagName === "INPUT")) return;
      if (event.key === "Delete" || event.key === "Backspace") {
        event.preventDefault();
        deletePaneWithTeardown(selected);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [selected, deletePaneWithTeardown]);

  const startMove = useCallback(
    (pane: Pane, event: React.PointerEvent) => {
      const point = toCanvas(event.clientX, event.clientY);
      setSelected(pane.id);
      setDrag({ kind: "move", paneId: pane.id, offsetX: point.x - pane.x, offsetY: point.y - pane.y });
    },
    [toCanvas],
  );

  /**
   * Drop a pane into the middle of what the user is actually looking at,
   * cascaded so repeated clicks do not stack panes on one point. A terminal
   * asks for more room than a note: 80 columns of monospace in a 260px pane is
   * a shell you cannot read.
   */
  const addPaneInView = useCallback(
    (kind: PaneKind, width: number, height: number) => {
      const rect = surfaceRef.current?.getBoundingClientRect();
      const center = toCanvas(
        (rect?.left ?? 0) + (rect?.width ?? 800) / 2,
        (rect?.top ?? 0) + (rect?.height ?? 600) / 2,
      );
      const step = (room.panes.length % 6) * 28;
      room.addPane(kind, center.x - width / 2 + step, center.y - height / 2 + step, {
        width,
        height,
      });
    },
    [room, toCanvas],
  );

  const startResize = useCallback(
    (pane: Pane, event: React.PointerEvent) => {
      const point = toCanvas(event.clientX, event.clientY);
      setDrag({
        kind: "resize",
        paneId: pane.id,
        startW: pane.width,
        startH: pane.height,
        startX: point.x,
        startY: point.y,
      });
    },
    [toCanvas],
  );

  return (
    <div className="canvas-root">
      <Toolbar
        room={room}
        zoom={viewport.zoom}
        onResetView={() => setViewport({ x: 0, y: 0, zoom: 1 })}
        onAddNote={() => addPaneInView("note", 260, 180)}
        onAddTerminal={() => addPaneInView("terminal", 560, 340)}
        // 480x460 is the smallest size where the transcript, the composer and
        // the three controls all fit without the composer eating the transcript.
        onAddAgent={() => addPaneInView("agent", 480, 460)}
      />

      <div
        ref={surfaceRef}
        className={`surface${drag?.kind === "pan" ? " surface--panning" : ""}`}
        onPointerDown={onSurfacePointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={endDrag}
        onPointerLeave={() => {
          endDrag();
          room.setCursor(null);
        }}
        onDoubleClick={onDoubleClick}
        style={{
          backgroundPosition: `${viewport.x}px ${viewport.y}px`,
          backgroundSize: `${24 * viewport.zoom}px ${24 * viewport.zoom}px`,
        }}
      >
        <div
          className="world"
          style={{
            transform: `translate(${viewport.x}px, ${viewport.y}px) scale(${viewport.zoom})`,
          }}
        >
          {room.panes.map((pane) => (
            <PaneView
              key={pane.id}
              pane={pane}
              workspaceId={workspaceId}
              zoom={viewport.zoom}
              selected={pane.id === selected}
              onSelect={() => setSelected(pane.id)}
              onStartMove={(e) => startMove(pane, e)}
              onStartResize={(e) => startResize(pane, e)}
              onChangeText={(text) => room.updatePane(pane.id, { text })}
              onDelete={() => deletePane(pane.id)}
            />
          ))}
          <Cursors peers={room.peers} zoom={viewport.zoom} />
        </div>

        {room.panes.length === 0 && (
          <p className="empty">Double-click anywhere to add a note.</p>
        )}
      </div>
    </div>
  );
}

function Toolbar({
  room,
  zoom,
  onResetView,
  onAddNote,
  onAddTerminal,
  onAddAgent,
}: {
  room: ReturnType<typeof useRoom>;
  zoom: number;
  onResetView: () => void;
  onAddNote: () => void;
  onAddTerminal: () => void;
  onAddAgent: () => void;
}): React.ReactElement {
  const label =
    room.state === "connected"
      ? `${room.peers.length + 1} here`
      : room.state === "connecting"
        ? "connecting…"
        : "offline — reconnecting";

  return (
    <header className="toolbar">
      <span className="brand">Atrium</span>
      <span className={`conn conn--${room.state}`}>{label}</span>

      <span className="peers">
        <span className="avatar" style={{ background: room.self.color }} title={`${room.self.name} (you)`}>
          {room.self.name.slice(0, 1).toUpperCase()}
        </span>
        {room.peers.map((peer) => (
          <span key={peer.userId} className="avatar" style={{ background: peer.color }} title={peer.name}>
            {peer.name.slice(0, 1).toUpperCase()}
          </span>
        ))}
      </span>

      <span className="spacer" />
      <span className="muted mono">{Math.round(zoom * 100)}%</span>
      <button type="button" onClick={onResetView}>
        Reset view
      </button>
      <button type="button" onClick={onAddNote}>
        Add note
      </button>
      {/*
        Adding the pane is all this does. The shell itself is opened by the
        server when the pane mounts and asks for it over an authorized route —
        a client cannot spawn a process by writing to the shared document.
      */}
      <button type="button" onClick={onAddTerminal}>
        Add terminal
      </button>
      {/*
        Adding the pane is ALL this does. No session exists — and no token is
        spent — until a human types a task and presses Start, which goes through
        the authorized POST route. A button that started an agent would make
        "spend money and write to the repo" a click with no sentence attached.
      */}
      <button type="button" onClick={onAddAgent}>
        Add agent
      </button>
    </header>
  );
}
