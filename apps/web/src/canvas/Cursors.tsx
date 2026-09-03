import type { Presence } from "@atrium/shared";

/**
 * Remote cursors. Rendered inside the transformed world so they track canvas
 * coordinates, then counter-scaled so the pointer stays a constant screen size
 * regardless of zoom.
 */
export function Cursors({
  peers,
  zoom,
}: {
  readonly peers: readonly Presence[];
  readonly zoom: number;
}): React.ReactElement {
  return (
    <>
      {peers.map((peer) =>
        peer.cursor === undefined ? null : (
          <div
            key={peer.userId}
            className="cursor"
            style={{
              left: peer.cursor.x,
              top: peer.cursor.y,
              transform: `scale(${1 / zoom})`,
            }}
          >
            <svg width="16" height="20" viewBox="0 0 16 20" aria-hidden="true">
              <path
                d="M1 1 L1 15.5 L4.8 12 L7.4 18 L10 16.8 L7.5 11 L12.5 11 Z"
                fill={peer.color}
                stroke="#fff"
                strokeWidth="1.1"
                strokeLinejoin="round"
              />
            </svg>
            <span className="cursor__name" style={{ background: peer.color }}>
              {peer.name}
            </span>
          </div>
        ),
      )}
    </>
  );
}
