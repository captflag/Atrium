# Atrium

A shared cloud workspace where a team and multiple AI coding agents work on the same repository at once — an infinite canvas of live panes, with server-owned sessions that keep running after you close your laptop.

**Status: M0, M1 and M2 complete.** Next: M3 — the harness bakeoff and the first agent. See [docs/PLAN.md](docs/PLAN.md) for the roadmap and [docs/SECURITY.md](docs/SECURITY.md) for the threat model.

## Prerequisites

- **Node.js ≥ 22** (developed on 24)
- **Docker Desktop** — required for Postgres now, and for the whole sandbox layer from M2 onward. Not optional.

On Windows, Docker needs the WSL2 backend. If Docker Desktop reports "Virtualization support not detected" while your BIOS already has VT-x enabled, the Windows features are the problem, not the firmware: run `wsl --install` as Administrator, **reboot**, then `wsl --update --web-download` as Administrator (the plain `--update` goes through Windows Update and fails with `0x80246007` when "receive updates for other Microsoft products" is off). Restart Docker Desktop afterwards so it provisions its `docker-desktop` WSL distro.

## Setup

```bash
npm install
cp .env.example .env
npm run db:up      # Postgres via Docker Compose
npm run image      # workspace container image (needed for terminal panes)
npm run dev        # server on :8787, web on :5173
```

Open <http://localhost:5173>. Open it a second time in another window to see multiplayer: cursors, live pane edits, shared notes, and the same live shell in both. Add `?workspace=<name>` to use a different room.

Double-click empty canvas to add a note, or use the toolbar for a note or a terminal. Drag the title bar to move, the corner to resize, Delete to remove. Wheel pans; ctrl/cmd-wheel zooms.

`GET /api/health` reports component status. Without Docker running, `postgres` reads `down`, `canvas-persistence` reads `degraded` — canvases then survive a browser reload but not a server restart — and `sandbox` reads `degraded`, which means terminal panes cannot open.

## Terminals

A terminal pane is a shell **inside that workspace's container**, not on your machine. The first terminal in a workspace creates the container; the checkout it mounts lives in `.atrium/workspaces/<workspace>` and is resolved server-side from the workspace id alone. Set `ATRIUM_REPO_URL` to clone a public repository into an empty checkout.

Several people can watch and type in one shell. The pty is sized to the **smallest** attached viewer, and the pane says so when that is someone else. Closing a pane closes its shell; closing a browser does not — sessions are server-owned.

What the container actually enforces, and what it does not, is reported at runtime in `SandboxHandle.unenforced` and surfaced in the `sandbox` line of `/api/health`. On Docker Desktop for Windows that list is `disk-quota`, `userns-remap`, `rootless-engine`. See [docs/SECURITY.md](docs/SECURITY.md) §4.

## Scripts

| Command | What it does |
|---|---|
| `npm run dev` | Server (`:8787`) and web client (`:5173`) together |
| `npm run typecheck` | Type-checks every workspace |
| `npm run build` | Builds all workspaces |
| `npm run db:up` / `db:down` | Start / stop Postgres |
| `npm run db:logs` | Tail Postgres logs |
| `npm run image` | Build the workspace container image |

## Layout

```
apps/
  server/     Fastify API + /rt canvas gateway + /rt/terminal terminal gateway
              realtime/  Room (authoritative Y.Doc), gateway (auth at upgrade), doc store,
                         terminal gateway/registry/session, scrollback ring
              sandbox/   SandboxProvider contract, LocalDockerProvider, spec validation,
                         hardening, clone, orchestrator (workspace -> container)
              identity.ts  IdentityProvider — stubbed, auth decision still open
  web/        React + Vite client
              canvas/    Canvas, PaneView (dispatches on pane.kind), TerminalPane,
                         useRoom (Yjs binding), useTerminal (xterm + wire protocol)
packages/
  shared/     Types shared by both — panes, health, terminal wire protocol.
              No runtime dependencies.
docker/
  workspace.Dockerfile  The workspace container image, base pinned by digest
docs/
  PLAN.md     Product and engineering plan, milestones M0-M6
  SECURITY.md Threat model and the five decisions that shape the design
```

## Conventions

- **TypeScript strict**, plus `noUncheckedIndexedAccess` and `exactOptionalPropertyTypes`. Project references, not path aliases.
- **Secrets fail loudly.** `apps/server/src/config.ts` throws at boot on a missing variable rather than defaulting. No secret in `.env.example` has a working default.
- **Interfaces at the seams that will move** — `SandboxProvider`, `AgentProvider`, `IdentityProvider`, `DocStore`. The sandbox, agent harness, auth, and persistence all stay swappable (PLAN §4, §10).
- **No TS parameter properties or enums.** The server runs under `node --experimental-strip-types`, which erases types without transforming; `erasableSyntaxOnly` enforces this at compile time.
- **The CRDT is untrusted input.** Any member can write to it, so pane payloads are validated server-side and rendered as text (SECURITY.md T6).
- **A websocket message never starts a process.** Terminals are created by an authorized HTTP route that re-checks membership; the terminal protocol can only *attach* to one that already exists. Lookup is workspace-scoped, so a terminal id from another workspace resolves to nothing.
- **One `upgrade` dispatcher.** Node emits `upgrade` to every listener, so gateways claim-or-decline (`handleUpgrade` returns a boolean) and `index.ts` owns the single fallback reject.
- **The container never holds a credential**, has no route off-host, and no Docker socket. What a given host *cannot* enforce is reported in `SandboxHandle.unenforced`, never assumed.
- The agent harness and model provider are **deliberately undecided** until M3a.
