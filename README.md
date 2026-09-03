# Atrium

A shared cloud workspace where a team and multiple AI coding agents work on the same repository at once — an infinite canvas of live panes, with server-owned sessions that keep running after you close your laptop.

**Status: M0 and M1 complete.** Next: M2 — sandbox + terminal. See [docs/PLAN.md](docs/PLAN.md) for the roadmap and [docs/SECURITY.md](docs/SECURITY.md) for the threat model.

## Prerequisites

- **Node.js ≥ 22** (developed on 24)
- **Docker Desktop** — required for Postgres now, and for the whole sandbox layer from M2 onward. Not optional.

On Windows, Docker needs the WSL2 backend. If Docker Desktop reports "Virtualization support not detected" while your BIOS already has VT-x enabled, the Windows features are the problem, not the firmware: run `wsl --install` as Administrator, **reboot**, then `wsl --update --web-download` as Administrator (the plain `--update` goes through Windows Update and fails with `0x80246007` when "receive updates for other Microsoft products" is off). Restart Docker Desktop afterwards so it provisions its `docker-desktop` WSL distro.

## Setup

```bash
npm install
cp .env.example .env
npm run db:up      # Postgres via Docker Compose
npm run dev        # server on :8787, web on :5173
```

Open <http://localhost:5173>. Open it a second time in another window to see multiplayer: cursors, live pane edits, shared notes. Add `?workspace=<name>` to use a different room.

Double-click empty canvas to add a note. Drag the title bar to move, the corner to resize, Delete to remove. Wheel pans; ctrl/cmd-wheel zooms.

`GET /api/health` reports component status. Without Docker running, `postgres` reads `down` and `canvas-persistence` reads `degraded` — canvases then survive a browser reload but not a server restart.

## Scripts

| Command | What it does |
|---|---|
| `npm run dev` | Server (`:8787`) and web client (`:5173`) together |
| `npm run typecheck` | Type-checks every workspace |
| `npm run build` | Builds all workspaces |
| `npm run db:up` / `db:down` | Start / stop Postgres |
| `npm run db:logs` | Tail Postgres logs |

## Layout

```
apps/
  server/     Fastify API + /rt realtime gateway
              realtime/  Room (authoritative Y.Doc), gateway (auth at upgrade), doc store
              identity.ts  IdentityProvider — stubbed, auth decision still open
  web/        React + Vite client
              canvas/    Canvas, PaneView, Cursors, useRoom (Yjs binding)
packages/
  shared/     Types shared by both. No runtime dependencies.
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
- The agent harness and model provider are **deliberately undecided** until M3a.
