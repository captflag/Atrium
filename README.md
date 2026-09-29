# Atrium

A shared cloud workspace where a team and multiple AI coding agents work on the same repository at once — an infinite canvas of live panes, with server-owned sessions that keep running after you close your laptop.

**Status: M0–M2 complete and verified. M3 built, not yet end-to-end verified.** Next: M4 — the claim protocol.

M0–M2 and the M3a credential boundary are proven by the probes below (`probe-terminal` 18/18, `probe-broker` 14/14). `probe-agent.mjs` has not yet been observed green, so the agent layer is built and type-checked but not end-to-end verified. No live model call has ever run: development happens with no API key, so the credential boundary is proven with a fake credential against a stub upstream. See [docs/PLAN.md](docs/PLAN.md) for the roadmap and [docs/SECURITY.md](docs/SECURITY.md) for the threat model.

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

Double-click empty canvas to add a note, or use the toolbar for a note, a terminal or an agent. Drag the title bar to move, the corner to resize, Delete to remove. Wheel pans; ctrl/cmd-wheel zooms.

`GET /api/health` reports component status. Without Docker running, `postgres` reads `down`, `canvas-persistence` reads `degraded` — canvases then survive a browser reload but not a server restart — and `sandbox` reads `degraded`, which means terminal panes cannot open.

The `agents` line reports live sessions, sockets, the harness in use and the number of broker sidecars — and says `no upstream credential configured` when there is none, which is the state this repository is developed in.

## Terminals

A terminal pane is a shell **inside that workspace's container**, not on your machine. The first terminal in a workspace creates the container; the checkout it mounts lives in `.atrium/workspaces/<workspace>` and is resolved server-side from the workspace id alone. Set `ATRIUM_REPO_URL` to clone a public repository into an empty checkout.

Several people can watch and type in one shell. The pty is sized to the **smallest** attached viewer, and the pane says so when that is someone else. Closing a pane closes its shell; closing a browser does not — sessions are server-owned.

What the container actually enforces, and what it does not, is reported at runtime in `SandboxHandle.unenforced` and surfaced in the `sandbox` line of `/api/health`. On Docker Desktop for Windows that list is `disk-quota`, `userns-remap`, `rootless-engine`. See [docs/SECURITY.md](docs/SECURITY.md) §4.

## Agents

An agent pane is one Claude Agent SDK session running **inside that workspace's container**, driving the repo the terminals see. Add one from the toolbar, type a task, press Start. Several people watch one transcript; a late joiner is replayed from the beginning and told, out loud, if the server could not serve the whole gap.

Nothing starts an agent except a person pressing Start: adding a pane creates no session, and the websocket protocol can only *attach* to one. Creation is an authorized `POST /api/workspaces/:id/agents`, and a POST with no task only looks one up.

**The container never receives a provider credential** (SECURITY.md D1). A broker sidecar — one container per workspace, on the same `--internal` bridge, reached by Docker's embedded DNS — holds the key; the agent gets `ANTHROPIC_BASE_URL` pointing at it plus a short-lived, workspace-scoped capability token, over stdin rather than its environment. The broker authenticates that token, allows exactly three upstream paths, enforces the token budget, and swaps the token for the real credential on the way out. Set `ATRIUM_UPSTREAM_API_KEY` to give it one; with none it still authenticates, allowlists and budgets, and refuses to forward — which is how `scripts/probe-agent.mjs` proves the boundary on a machine holding no key.

Everything an agent says is **untrusted text**. It reads repo files to do its job, and a file can carry instructions aimed at you. The pane renders every agent string as a text child — no markdown renderer, no linkification, no anchor built from agent output — and notices and errors are drawn as chrome that agent prose cannot imitate.

Model choice is per need (PLAN §10): `claude-opus-5` for coding, `claude-haiku-4-5` for mechanical background work. Both are config, never literals in code. Agents do not commit or push in v1.

## Scripts

| Command | What it does |
|---|---|
| `npm run dev` | Server (`:8787`) and web client (`:5173`) together |
| `npm run typecheck` | Type-checks every workspace |
| `npm run build` | Builds all workspaces |
| `npm run db:up` / `db:down` | Start / stop Postgres |
| `npm run db:logs` | Tail Postgres logs |
| `npm run image` | Build the workspace container image |
| `node scripts/probe-terminal.mjs` | M2 end-to-end: two viewers on one shell, replay, isolation (server must be running) |
| `node scripts/probe-broker.mjs` | D1: the broker holds the credential and the container does not |
| `node scripts/probe-agent.mjs` | M3b end-to-end: the SDK in the container, and the wired routes + `/rt/agent` |

## Layout

```
apps/
  server/     Fastify API + /rt canvas, /rt/terminal and /rt/agent gateways
              realtime/  Room (authoritative Y.Doc), gateway (auth at upgrade), doc store,
                         terminal gateway/registry/session, scrollback ring,
                         agent gateway/registry/session/transcript + agent routes
              agent/     AgentProvider contract, ClaudeAgentProvider (drives the runner
                         over framed stdio), event stream, identity, errors
              sandbox/   SandboxProvider contract, LocalDockerProvider, spec validation,
                         hardening, clone, orchestrator (workspace -> container),
                         broker sidecar (workspace -> credential-holding container)
              identity.ts  IdentityProvider — stubbed, auth decision still open
  agent-runner/  Runs INSIDE the workspace container. The only package that may
                 import @anthropic-ai/claude-agent-sdk.
  broker/     The model broker sidecar. Holds the provider credential; no npm deps.
  web/        React + Vite client
              canvas/    Canvas, PaneView (dispatches on pane.kind), TerminalPane,
                         AgentPane, useRoom (Yjs binding), useTerminal (xterm + wire
                         protocol), useAgent (/rt/agent + transcript folding)
packages/
  shared/     Types shared by both — panes, health, terminal and agent wire protocols.
              No runtime dependencies.
docker/
  workspace.Dockerfile  The workspace container image, base pinned by digest.
                        Carries the agent runner and its musl harness binary.
  broker.Dockerfile     The broker sidecar. No dependencies, no shell tooling.
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
- **A websocket message never starts an agent either**, for the same reason and with the same split: an authorized route creates, the protocol attaches. A POST with no task is a lookup and can create nothing.
- **Agent output is untrusted text.** Rendered as React text children — never `innerHTML`, never a markdown-to-HTML renderer, never a link built from what an agent wrote.
- **The harness is the Claude Agent SDK** (PLAN §10), and exactly one file imports it: `apps/agent-runner`. Everything above `AgentProvider` is harness-agnostic, and a compile-time assertion in `claude-agent.ts` breaks the build if the runner's event union drifts from the shared one.
- **Model choice is per need**, from config: the strong model for coding, the cheap one for mechanical background work. Never one model hardcoded everywhere.
