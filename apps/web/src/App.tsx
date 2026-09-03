import { Canvas } from "./canvas/Canvas.tsx";

/**
 * One canvas per workspace for now — PLAN.md §10 decision #4 (one board vs.
 * many) is still open, so the workspace id comes from the URL and nothing
 * assumes there is only ever one.
 */
function workspaceIdFromUrl(): string {
  const fromQuery = new URLSearchParams(window.location.search).get("workspace");
  if (fromQuery !== null && /^[A-Za-z0-9_-]{1,64}$/.test(fromQuery)) return fromQuery;
  return "demo";
}

export function App(): React.ReactElement {
  return <Canvas workspaceId={workspaceIdFromUrl()} />;
}
