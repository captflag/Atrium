# Atrium — Product & Engineering Plan

> Working codename: **Atrium** (the open shared room in a building). Rename freely.
> Status: Draft v1 — written 2026-09-03, before any code exists.
> Reference product: Murmell ("cloud canvas where your team and AI agents work together").
> Security: see [SECURITY.md](./SECURITY.md). It corrects three architecture decisions in this document; those corrections are already applied below and marked *(D1)*–*(D5)*.

---

## 1. What this is

A shared cloud workspace where a team and multiple AI coding agents work on the same repository at the same time. The workspace is an infinite canvas holding live panes — terminals, file editors, agent sessions, a running dev-server preview. The workspace lives on the server, not in the browser tab: closing your laptop does not stop the work, and reconnecting restores the exact state.

**One-sentence pitch:** A repo you can walk into — where your agents keep working after you leave.

### The three claims that make it a product

1. **Co-presence.** Humans and agents occupy the same space, not separate chat threads. You watch an agent work the way you watch a colleague's cursor.
2. **Durability.** Sessions are server-owned. Disconnect is not cancellation.
3. **Safe concurrency.** Multiple agents on one repo without stepping on each other, enforced by a file-claim protocol rather than hope.

Claim 3 is the technically interesting one and the hardest to fake in a demo. It is also the one most likely to become the actual reason someone uses this. Build the plan around it.

---

## 2. Honest positioning

Murmell exists, is funded, and shipped. A head-on clone is not winnable as a solo or small-team project. Three viable framings — pick one before writing code:

| Framing | What it means | Best if |
|---|---|---|
| **A. Portfolio / depth project** | Build the hard 20% extremely well (claim protocol, durable sessions, canvas). Ship a self-hostable single-tenant version. Judged on engineering depth, not market. | This is for a résumé, thesis, or to learn distributed systems properly. |
| **B. Self-hosted / BYO-key niche** | The open-source, run-it-on-your-own-box answer. Users bring their own provider key or point at their own endpoint. No inference bill for you. | You want real users without a cloud budget. |
| **C. Vertical wedge** | Same primitives, one narrow audience Murmell ignores — e.g. teaching/code-review classrooms, or on-prem regulated teams. | You want a business, not a demo. |

**Recommendation: A, with the codebase shaped so B is a rename away.** Self-hostable and BYO-key from day one removes the two things that kill hobby infra projects: cloud spend and key custody.

### Explicit non-goals (v1)

- Multi-tenant SaaS billing, org/team management, SSO.
- Supporting non-Git version control.
- Running arbitrary untrusted third-party code with hostile-tenant isolation. v1 assumes workspace members trust each other.
- Mobile.
- An agent marketplace or plugin ecosystem.
- Beating anyone on model quality. The model is a swappable dependency; the product is the room around it.

---

## 3. Core primitives

Five nouns. Everything else is built from them.

| Primitive | Definition | Lives in |
|---|---|---|
| **Workspace** | A repo + a sandbox container + a canvas document + a member list. The unit of everything. | Postgres row + container + Yjs doc |
| **Pane** | A node placed on the canvas: terminal, file editor, agent, preview, note, chat. Has position, size, and a typed payload. | Yjs doc (`panes` map) |
| **Agent session** | One agent-harness process running inside the workspace container, bound to a pane, with its own transcript and permissions. Harness undecided (§10.0). | Container process + Postgres event log |
| **Claim** | A time-bounded exclusive lease on a set of file paths, held by one agent or human. | Postgres, server-authoritative |
| **Presence** | Who is connected, where their viewport is, what they are focused on. Ephemeral. | Yjs awareness |

**Design rule:** the canvas document (CRDT) holds *layout and intent*. It never holds authoritative file content, claims, or agent state. Those are server-authoritative because they need real conflict resolution, not last-write-wins merging. Mixing the two is the most common way this class of app rots.

---

## 4. Architecture

```
Browser (React + Vite + TS)
  |- Canvas renderer (CSS transform, DOM panes)
  |- Yjs client  --ws--+
  |- Pane transports   |
       terminal --ws---+
       agent    --ws---+
       preview  --http/ws--+
                           |
+--------------------------+-----------------------------+
| Node backend (single process in v1, splittable later)  |
|                                                        |
|  Realtime gateway   Yjs sync + awareness + auth        |
|  Orchestrator API   workspaces, sessions, claims, git  |
|  Stream hub         fan-out of agent/terminal events   |
|  Preview proxy      container port -> separate origin  |  (D3)
|  Model broker       holds provider creds, budgets, redaction (D1)
|  Git proxy          holds Git token, branch allowlist  |  (D2)
|  SandboxProvider    <- interface, swappable            |
+-----------+----------------------------+---------------+
            |                            |
      Postgres            === TRUST BOUNDARY: assume compromised ===
   users, workspaces,                    |
   members, claims,            Docker container (per workspace)
   sessions, event log           |- repo checkout
                                 |- agent runners (harness TBD, §10.0)
                                 |- pty processes
                                 |- user dev server
                                 |- NO API key, NO Git token   (D1, D2)
                                 |- egress deny-by-default      (D4)
```

**Where the brokers actually run (established empirically, 2026-09-03).** The model broker (D1) and Git proxy (D2) are drawn above on the host side, and M2's code left comments saying they would listen on the `atrium-internal` bridge gateway. **That is wrong on Docker Desktop for Windows and was never tested.** Measured from a workspace container on `atrium-internal`:

| Target | Result | Meaning |
|---|---|---|
| `https://1.1.1.1` | `ENETUNREACH` | D4 holds — no route off-host, enforced in the kernel |
| bridge gateway `172.19.0.1:<port>`, live Windows listener | `ECONNREFUSED` | packets reach the gateway **inside the WSL2 VM**; a Windows host process is not there and never will be |
| another container on `atrium-internal`, by name | **reachable** | container-to-container works, with Docker's embedded DNS |

Docker Desktop runs the engine inside a WSL2 VM, so "the host" the container can see is the VM, not Windows. A broker running as a Node process on Windows is unreachable from a workspace container by design, not by misconfiguration.

**Therefore the brokers are sidecar containers, not host processes.** Each attaches to two networks: `atrium-internal`, where workspace containers reach it by name and it is the only thing they can reach; and a second egress-capable network it uses to reach the model provider or GitHub. The workspace container keeps zero route off-host.

This is *better* than the host-process design, not a concession. The credential now lives in a container the workspace container cannot exec into, cannot share a namespace with, and can only address over one TCP port — a stronger boundary than a Unix socket on a shared host. D1 and D2 are unchanged in substance: no credential ever enters the workspace container.

**The container is semi-hostile by design.** It runs model-generated commands and arbitrary `npm install` scripts over attacker-influenceable input. Every credential stays on the host side of that boundary; the container gets short-lived, workspace-scoped capability tokens instead. Rationale and threat model in [SECURITY.md](./SECURITY.md) §1.

### Component notes

**Client.** React + TypeScript + Vite. The canvas is a single `transform: translate() scale()` container with absolutely-positioned pane elements — *not* a `<canvas>` or a drawing library. Panes must be real DOM because they contain iframes (preview), xterm.js (terminal), and CodeMirror (editor). A drawing-first library (tldraw, Excalidraw) fights you the moment panes need to be live.

**Realtime.** Yjs + `y-websocket`. The canvas document is a `Y.Doc` containing a `Y.Map` of panes. Presence via Yjs awareness — free cursors and viewports. Persist the doc to Postgres on debounce, plus a periodic snapshot.

**Backend.** Node 24 + Fastify + `ws`. One process to start. The seams that matter (`SandboxProvider`, `StreamHub`, `ClaimStore`) are interfaces from day one so they can move to separate services without a rewrite.

**Sandbox.** Docker container per workspace, behind a `SandboxProvider` interface:

```ts
interface SandboxProvider {
  create(workspaceId: string, spec: SandboxSpec): Promise<SandboxHandle>
  exec(h: SandboxHandle, cmd: string[], opts: ExecOpts): Promise<ExecResult>
  spawnPty(h: SandboxHandle, opts: PtyOpts): Promise<PtyHandle>
  proxyPort(h: SandboxHandle, port: number): Promise<URL>
  hibernate(h: SandboxHandle): Promise<Snapshot>
  restore(snapshot: Snapshot): Promise<SandboxHandle>
  destroy(h: SandboxHandle): Promise<void>
}
```

Implementations: `LocalDockerProvider` (v1, dev + self-host), and later `E2BProvider` or `FlyMachinesProvider` for hosted. Writing this interface first is what keeps framing B open.

**Datastore.** Postgres. Supabase is a reasonable managed choice (auth + DB + storage in one, generous free tier), but the schema must not depend on Supabase-specific features, so self-hosting stays possible.

**Agents — Claude Agent SDK** (`@anthropic-ai/claude-agent-sdk`), decided 2026-09-03 (§10.0). It still sits behind the `AgentProvider` interface below, which is what keeps a local or alternative model viable for the self-hosted framing (§2 B).

The agent layer sits behind an interface, exactly like the sandbox:

```ts
interface AgentProvider {
  start(spec: AgentSpec): Promise<AgentHandle>     // task, repo root, model config
  events(h: AgentHandle): AsyncIterable<AgentEvent> // message | tool_call | tool_result | done | error
  interrupt(h: AgentHandle): Promise<void>
  stop(h: AgentHandle): Promise<void>
}
```

Candidate implementations, none committed: a CLI-style coding agent driven headlessly, an open-source harness (OpenHands, Aider, SWE-agent, Goose), a vendor SDK, or a hand-rolled loop over a model-routing layer (LiteLLM, OpenRouter) if none fit. Local models are viable for the self-host framing.

**The constraint this creates.** Harnesses differ enormously in whether they expose a **tool-call gate** — a callback that can veto a write before it happens. Some do; several do not. Since the harness is undecided, **the design must not require one.** Claim enforcement therefore happens at the filesystem boundary (§5), not in the harness. This is a strictly better position: [SECURITY.md](./SECURITY.md) D5 already established that a harness-level hook is bypassable via `Bash` and is not a security boundary. Deferring the provider choice removed a dependency that was load-bearing and shouldn't have been.

**What the harness must supply**, and the rubric for choosing one later:

| Requirement | Why | Hard requirement? |
|---|---|---|
| Headless / programmatic invocation | It runs in a container, not a terminal a human sits at | Yes |
| Structured event stream (not just stdout text) | Panes render tool calls, not a log tail | Yes |
| Interrupt mid-task | Users must be able to stop an agent | Yes |
| Configurable model / provider endpoint | Keeps the model decision open too | Yes |
| Works against an OpenAI-compatible or custom base URL | Enables local models and routing layers | Strongly preferred |
| Tool-call gate / permission hook | Better UX for approvals; *not* required for correctness | No — nice to have |
| Subagents, context compaction | Quality of long tasks | No |

Decide by evaluating two or three candidates against a fixed benchmark task in the M2 container, immediately before M3 starts. Do not decide now — the right answer in three months is not knowable today, and the interface costs nothing to keep.

### Tech stack summary

| Layer | Choice | Why |
|---|---|---|
| Client | React 19 + TypeScript + Vite | Fast iteration; ecosystem for xterm/CodeMirror |
| Canvas | Custom CSS-transform pan/zoom | Panes must be live DOM |
| Editor pane | CodeMirror 6 | Lighter than Monaco, better embed story |
| Terminal pane | xterm.js + node-pty | Standard |
| Realtime | Yjs + y-websocket | Mature CRDT, awareness included |
| Backend | Node 24 + Fastify + ws | Same language as client; node-pty and the Docker SDK are first-class |
| DB | Postgres (Supabase or local) | Claims need real transactions |
| Sandbox | Docker (interface-abstracted) | Runs on the dev machine; swappable for hosted |
| Claim enforcement | Per-agent overlayfs upper layer + server-side merge | Provider-agnostic; catches raw `Bash` writes (§5) |
| Agents | **Undecided** — `AgentProvider` interface | Decide before M3 against a benchmark task (§10.0) |
| Model | **Undecided** — configurable per workspace | Deferred with the harness choice (§8) |

---

## 5. The claim protocol (the differentiating mechanism)

The problem: two agents editing `src/auth.ts` at the same time produce garbage, and neither notices. Git does not help — they share one working tree.

The solution is a server-authoritative lease, enforced at the tool boundary.

### Protocol

1. **Declare.** Before writing, an agent requests a claim: `{ paths: string[] (globs), mode: "write" | "read", reason: string }`.
2. **Grant.** The orchestrator checks for overlap against live claims inside a single Postgres transaction. On success it returns `{ leaseId, paths, expiresAt }`. On conflict it returns the holder's identity and reason, plus the requester's options: `wait`, `narrow`, or `handoff`.
3. **Heartbeat.** The agent's runner refreshes the lease every 10s. TTL is 60s. A crashed agent's lease expires on its own — no manual cleanup, no zombie locks.
4. **Enforce — at the filesystem, not in the harness.** Two layers, and only the second is authoritative.

   **Layer 1 (advisory, optional).** If the chosen harness exposes a tool-call gate, use it to reject out-of-claim writes *before* they happen and tell the agent why. This is a UX affordance: fast feedback, clean error messages. It is **not** relied upon — the harness is undecided (§4), several candidates have no such hook, and one that does is bypassable via raw `Bash` (`echo ... > src/auth.ts`).

   **Layer 2 (authoritative).** Each agent gets its **own overlayfs mount** over the shared repo: `lowerdir` is the shared working tree, `upperdir` is agent-private, and the agent sees the merged view. Every write the agent makes — through a tool, through `Bash`, through a script it wrote, through anything — lands in its private upper layer and is invisible to everyone else.

   The orchestrator, running **outside** the container, merges an agent's upper layer down into the shared tree on claim release, task completion, or periodic checkpoint. **The merge is the enforcement point.** Paths not covered by a live claim are rejected, attributed to the agent, and reported back as structured feedback.

   This is provider-agnostic by construction: it does not care what harness, model, or language the agent uses, because the kernel does the interception. It also produces two things for free — a precise per-agent diff for the UI ("here is exactly what agent-2 changed"), and read-stability, since an agent's view does not shift underneath it while another agent works.

   *Cost:* agents do not see each other's in-flight edits until merge. For a claim-based system that is correct behaviour, not a limitation. *Fallback if overlayfs proves awkward:* a Git worktree per agent with the same merge gate — more familiar, heavier on disk, same guarantees.

   **Framing (D5).** Claims prevent collisions between *cooperating* agents; the merge gate maintains integrity against a *compromised* one. See [SECURITY.md](./SECURITY.md) T7.
5. **Report back.** A rejection returns to the agent as a structured tool error naming the holder, so the agent can reason about it ("`src/auth.ts` is held by agent-2 for 'refactor session handling'") instead of retrying blindly.
6. **Release.** On task completion, session end, or TTL expiry.

### Design decisions worth stating

- **Path granularity, not file locks.** Claims are globs (`src/auth/**`) because agents work on features, not single files.
- **Write-exclusive, read-shared.** Many readers, one writer. A reader is warned (not blocked) when a file it read is subsequently modified.
- **Deny-with-information over queue-forever.** A blocked agent should be able to pick different work. Blocking is a last resort.
- **Humans hold claims too.** A person editing a file in a pane takes a soft claim, visible to agents. Agents route around humans by default.
- **Visible in the UI.** Claimed paths are tinted in the file tree and shown on the agent's pane. If the user cannot see who holds what, the mechanism may as well not exist.

### Schema sketch

```sql
create table claims (
  id            uuid primary key,
  workspace_id  uuid not null references workspaces(id) on delete cascade,
  holder_id     text not null,          -- agent session id or user id
  holder_kind   text not null,          -- 'agent' | 'human'
  paths         text[] not null,        -- glob patterns
  mode          text not null,          -- 'write' | 'read'
  reason        text,
  granted_at    timestamptz not null default now(),
  expires_at    timestamptz not null,
  released_at   timestamptz
);
create index on claims (workspace_id) where released_at is null;
```

Overlap detection runs in the application layer (glob intersection) inside a `serializable` transaction. Postgres exclusion constraints are not expressive enough for glob overlap; do not fight this.

---

## 6. Durable sessions

"Close your laptop and the work keeps going" is a state-ownership decision, not a feature.

- **The browser owns nothing.** No agent state, no terminal scrollback, no pending tool calls live only in the tab.
- **Append-only event log per session.** Every agent event (message, tool call, tool result, claim change) is written to Postgres with a monotonic sequence number.
- **Reconnect = replay + subscribe.** The client sends the last sequence number it saw; the server replays the gap, then attaches to the live stream. The same mechanism serves a fresh join, a refresh, and a five-hour absence.
- **Container hibernation.** After an idle timeout, snapshot the container filesystem and stop it. Restore on the next connection. This is the difference between a demo and something you can afford to leave running.
- **Backpressure.** A long-running agent generates events faster than a slow client consumes them. The stream hub buffers per-subscriber with a bounded queue and falls back to "catch up by replay" when a subscriber lags too far. Design this in; retrofitting it is painful.

---

## 7. Milestones

Each milestone ends in something demonstrable. Estimates assume one person; adjust to your actual pace.

### M0 — Skeleton (0.5 week) — **DONE**
Monorepo, TypeScript strict, Vite client, Fastify server, Postgres via Docker Compose, one health-check route rendered in the UI.
**Done when:** `docker compose up && npm run dev` gives a working page talking to a working server.

**Status 2026-09-03.** npm workspaces (`apps/server`, `apps/web`, `packages/shared`), TypeScript project references, strict mode with `noUncheckedIndexedAccess` and `exactOptionalPropertyTypes` — `npm run typecheck` clean. Fastify server on `:8787` with `/api/health`; Vite client on `:5173` proxying `/api`, polling health every 5s and rendering per-component status. Verified end to end in a browser, no console errors, baseline CSP clean. Security M0 items done: `.env` gitignored (verified against the index), `.env.example` with no working defaults, boot-time config validation that throws on a missing variable, lockfile committed, log redaction of `authorization` and `cookie`.

**Closed 2026-09-03** once Docker Desktop was working. `docker compose up -d` brings up Postgres 17, the container reports healthy, and `/api/health` returns `status: ok` with every component green.

Getting Docker running took four steps worth recording, because M2 depends on the same stack: hardware virtualization was already enabled in firmware, but the Windows features were not — `wsl --install` staged VirtualMachinePlatform and WSL, **a reboot was required** to activate them, the WSL2 kernel then had to be fetched with `wsl --update --web-download` (plain `wsl --update` fails with `0x80246007` because this machine has Windows Update's "other Microsoft products" setting off), and finally Docker Desktop needed a restart to provision its `docker-desktop` WSL distro, which it had skipped when WSL was unavailable at install time. Docker Desktop 4.88.0 is installed per-user, so there is no `com.docker.service`; it runs on the WSL2 backend alone.

### M1 — Multiplayer canvas (1.5 weeks) — **DONE**
Pan/zoom canvas, create/move/resize/delete panes (note panes only), Yjs sync, cursor presence, workspace persists across reload.
**Done when:** two browsers show each other's cursors and pane edits in real time, and a reload restores the layout.
**This is the substrate. Everything later is a pane type.**

**Status 2026-09-03. Every criterion verified in two live browsers.** A note created in one tab appeared in the other; text typed in one appeared in the other; a full page navigation restored both panes and their text from the server; each tab rendered the other's live cursor with its name.

Built: CSS-transform canvas with absolutely-positioned DOM panes (wheel pans, ctrl/cmd-wheel zooms about the pointer, 25–250%). Drag to move, corner-drag to resize, double-click empty space or the toolbar button to add, Delete to remove. Yjs `Y.Map` of panes over a hand-rolled provider speaking the y-websocket protocol, with exponential-backoff reconnect. Presence via Yjs awareness.

Server: `/rt` gateway on the same port, one `Room` per workspace holding the authoritative `Y.Doc`, debounced persistence (800ms, 10s ceiling), rooms released when the last client leaves.

Security M1 items done: **authorization at the HTTP upgrade, before any Yjs bytes** — Origin checked against the allowlist, principal resolved, workspace membership checked, socket destroyed with a status line on failure. Pane payloads are **validated server-side on every change** and corrected or removed, because a CRDT any member can write to is untrusted input (T6). Note bodies render into a textarea's `value` — never HTML, nothing reaches `dangerouslySetInnerHTML`.

**Auth is still stubbed, deliberately.** `DevIdentityProvider` implements the `IdentityProvider` interface and refuses to construct when `NODE_ENV=production`. It supplies the *shape* the gateway needs so §10 decision #1 stays open; it is not authentication.

**Durable persistence verified 2026-09-03.** With Postgres up, `PostgresDocStore` was exercised end to end for the first time: a pane was created, the row appeared in `canvas_docs` (195 bytes), the **server process was killed and restarted**, and the pane and its text came back from the database. The memory fallback remains as designed for when Postgres is down, reported as `degraded` by the health endpoint.

Three defects found and fixed during the build: Node's `--experimental-strip-types` rejects TS parameter properties (now banned at compile time via `erasableSyntaxOnly` rather than discovered at runtime); React StrictMode's double-mount closed a still-connecting socket, producing a warning and a spurious reconnect; the toolbar's add button stacked every pane at one point.

### M2 — Sandbox + terminal (1.5 weeks) — **DONE** — **DONE**
`SandboxProvider` interface + `LocalDockerProvider`. Clone a repo into a container. Terminal pane over xterm.js + node-pty, streamed via WebSocket. Multiple viewers on one terminal.
**Done when:** two people watch and type in the same live shell inside the container.

**Status 2026-09-03. Verified by `scripts/probe-terminal.mjs` — 17/17 checks against the running server**, plus a live two-browser check on the canvas. Two viewers attach to one shell and each sees the other's output; a late joiner replays scrollback; the shell runs as non-root `atrium` in the `/workspace` mount; a member of another workspace cannot attach; the shell survives a departing viewer, because sessions are server-owned (§6). M1 does not regress — `/rt` still upgrades and sends Yjs sync step 1.

Built by a 9-agent workflow: one contract agent froze the `SandboxProvider` interface, the terminal wire protocol and all dependencies; three builders worked disjoint files in parallel; an integrator wired them; three adversarial auditors (escape, egress, authz) reviewed the container boundary and a remediator fixed what was real.

**The audit earned its place.** Its one high finding: the `--internal` flag on the egress network — the single D4 control for the workspace container — was *adopted on trust and never verified*. A pre-existing network with the right name but no `Internal` flag would have been a fully routable bridge while the code reported deny-by-default egress. Now the network is inspected by id on every path and the server refuses to start a container rather than silently grant egress. Post-create readback also asserts the container's actual `NetworkMode` and attachment, and removes the container when they do not match.

**What is enforced**, verified by reading it back off the running container: read-only rootfs, `cap-drop=ALL`, no-new-privileges, non-root uid, memory/CPU/PID limits, `nosuid,nodev,noexec` tmpfs, no port bindings, and no Docker socket bind anywhere. A container failing the readback is removed, not run.

**What is not**, reported at runtime in `SandboxHandle.unenforced` and in `/api/health` rather than claimed: `disk-quota` (Docker Desktop's WSL2 store is ext4, so `--storage-opt size=` cannot apply — a container can still fill the host disk through the repo bind mount), `userns-remap`, and `rootless-engine`. The egress allowlist falls back to an `--internal` network with no route off-host; per-host allowlisting needs the filtering proxy described in `EgressPolicy` and does not exist yet. Private repos are unsupported — public HTTPS clone only, until the host-side Git proxy (D2).

`node-pty` was removed after integration: it was in dependencies with a host install-script grant but never imported. The pty runs inside the container via the Docker exec API, which is the point — a host pty would be a shell on the machine that holds every credential.

**Status 2026-09-03. Verified in two browsers on one canvas:** a terminal pane opened a shell in the workspace container, both windows showed the same prompt, each typed a command and both saw both results, and the pane's badge read "2 watching". `whoami` is `atrium` (uid 10001), `touch /etc/nope` fails read-only, and `/sys/fs/cgroup/pids.max` reads 512 — from the browser.

**The pty runs inside the container, not on the host.** `node-pty` is deliberately not used: a host pty is a shell on the machine holding every credential. The pty is a Docker exec with `Tty: true`, and the hijacked stream's bytes go to the wire unmodified.

**Terminal creation is server-side only.** The wire protocol can only *attach*: `subscribe` looks a session up, and lookup is keyed by (workspace, terminal). A terminal is created by an authorized `POST /api/workspaces/:id/terminals` that repeats the upgrade's authenticate + membership check. If a JSON message could spawn a shell, every member would have RCE by sending one.

**Split across four seams, all of which held:** `SandboxProvider` (the contract), `LocalDockerProvider` (the only file that knows what a container id is), `TerminalRegistry`/`TerminalSession` (fan-out, scrollback, backpressure — no Docker), and a `SandboxLocator` the orchestrator implements. The orchestrator is the only place that turns a workspace id into a host path (T5) or decides a container should exist.

Three integration defects found while wiring it: both websocket gateways installed their own `upgrade` listener and Node delivers that event to *all* of them, so the canvas gateway destroyed every terminal socket — both now claim-or-decline and `index.ts` owns one dispatcher; a client that opened its socket before the orchestrator had spawned the shell got a non-retryable `not-found` and stranded the pane, so the pane now ensures the session over HTTP *then* attaches, which also makes a server restart self-healing; and a restart left the previous run's shells alive inside the container with no stream able to reach them (Docker has no "kill exec"), so adopting a container now reaps the pid files a previous run left in its tmpfs.

**Not done here:** hibernate/restore (M5) and `proxyPort` (M6) throw, naming their milestone. Private repositories are not supported — public HTTPS clone only, because no credential enters a container until the Git proxy exists (D2).

### M3 — First agent (2.5 weeks)
**M3a — harness verification (0.5 week) — BROKER DONE, live call pending a key.** The comparison is settled (§10.0): Claude Agent SDK on `claude-opus-5`. What remains is the check that mattered most in the rubric — stand up the broker sidecar, point the SDK at it with `ANTHROPIC_BASE_URL`, and prove end to end that a real task completes with **no credential anywhere in the workspace container**. Verify before wiring real work through it, not after.

**Status 2026-09-03.** The broker sidecar is built (`apps/broker`, `docker/broker.Dockerfile`) and **D1 is proven by `scripts/probe-broker.mjs` — 9/9**, using a *fake* credential so no real key is needed or at risk. Asserted, not assumed: the workspace container's environment holds no provider credential (only `ANTHROPIC_BASE_URL` and a scoped capability token); a request without the token is refused; a non-allowlisted path is refused, so the broker is not an open proxy inside the trust boundary; the broker injects the real credential upstream; and the session token budget refuses the call that crosses the ceiling.

The broker ships **zero npm dependencies** on purpose — it is the process that holds the credential, so its supply chain is the one that matters (T12). It runs non-root, read-only, `cap-drop=ALL`.

**Two bugs caught by the probe, both mine, both fixed.** The capability token was being forwarded upstream: scoped and useless to the recipient, but a credential leaving the boundary it belongs to is a leak regardless, and the probe now asserts it never happens. Separately, the broker's own guard refused to forward a credential over plaintext to a non-local host — it fired on the test harness, which is the guard working; the fixture was renamed rather than the guard weakened.

**What M3a still owes:** one live call against the real API. That needs an Anthropic key, which the project does not have. Nothing else blocks — set `ATRIUM_UPSTREAM_API_KEY` on the broker and point `ATRIUM_UPSTREAM_ORIGIN` at `https://api.anthropic.com`. Until then the boundary is proven and the model call is not.

**M3b — integration (2 weeks).** `AgentProvider` implemented for the winner, running inside the container and bound to an agent pane. Streaming transcript with tool calls rendered. Interrupt/stop. BYO credentials, held by the host-side broker and never present in the container *(D1)*.

**Done when:** you type a task into a pane and watch an agent modify the repo, with a colleague watching live — and swapping to a second `AgentProvider` implementation is a config change, not a refactor.

### M4 — Claims (2 weeks)
Claim store, grant/heartbeat/release. Per-agent overlayfs mount and the server-side merge gate (§5 step 4) — this is the authoritative enforcement and the bulk of the work. Optional advisory hook if the M3a winner supports one. Conflict UI, claimed-path tinting in the file tree, per-agent diff view.
**Done when:** two agents given deliberately overlapping tasks do not corrupt the repo, and the UI shows exactly why the second one waited.
**This is the demo that makes the project.**

### M5 — Durability (1 week)
Event log, reconnect-and-replay, container hibernate/restore, idle timeout.
**Done when:** you kill the browser mid-agent-run, reopen 20 minutes later, and see the completed work plus the full transcript.

### M6 — Preview + editor (1.5 weeks)
Preview pane proxying the container's dev-server port. CodeMirror editor pane with a soft human claim.
**Done when:** an agent edits a file and the preview pane hot-reloads in front of you.

**Total: ~10.5 weeks of focused work.** Assume 14–15 calendar weeks at a realistic solo pace alongside other commitments.

### Sequencing rationale

M1 before M3 because agents need a room to appear in. M3 before M4 because you cannot design a claim protocol against imagined agent behaviour — you need to watch a real agent decide what to write. M5 after M4 because the event log's schema depends on what claim events look like.

The harness bakeoff sits at M3a rather than at the start because it needs the M2 container to run in. Evaluating harnesses on your laptop tells you very little about how they behave in the environment they will actually inhabit.

---

## 8. Cost model

Provider is decided (§10.0), so these are real rates. Anthropic API, per million tokens:

| Model | Model ID | Input | Output | Used for |
|---|---|---|---|---|
| Claude Opus 5 | `claude-opus-5` | $5.00 | $25.00 | Coding agents |
| Claude Haiku 4.5 | `claude-haiku-4-5` | $1.00 | $5.00 | Mechanical background work |

Claude Sonnet 5 (`claude-sonnet-5`, $2/$10) sits between them and is the obvious step-down to measure if Opus proves more than a route needs. Do not assume it — measure cost per *completed task*, not per request.

### The four levers, in descending order of impact

1. **Prompt caching.** An agent session resends a large stable prefix (system prompt, tool definitions, repo context) on every turn. Caching it is the single largest saving available and costs nothing in quality. The broker sidecar is the right place to confirm it is working: watch `usage.cache_read_input_tokens`, and treat a persistent zero as a silent invalidator, not as absence of the feature.
2. **Cost per completed task, not per request.** A cheaper model that needs three attempts is not cheaper. Benchmark on the M3a task and compare total spend to green, not sticker price.
3. **Tiering.** Strong model for coding agents; a small, cheap model for mechanical background work (summarising a transcript, naming a pane). Roughly a 5× spread between tiers at most providers.
4. **Effort.** `high` or `xhigh` for coding and long-horizon agent work, `low` for background subagents. On current models this matters more than it used to — re-tune per route rather than setting one global value.

### Hosting cost

One small container per active workspace. At roughly $0.01/hr with aggressive hibernation, 50 workspaces averaging 2 active hours/day is on the order of $30/month. Self-hosting an open-weight model changes this substantially — a GPU box is a fixed monthly floor, not a per-token charge, which favours heavy users and punishes idle ones.

### The decision that actually controls exposure

**BYO credentials.** In the recommended framing (§2), users supply their own Anthropic key to the broker, and the inference bill is not yours — hosting is the only cost you carry, and hibernation controls it. The broker is also where per-session token budgets and spend caps are enforced, so a runaway agent loop cannot quietly drain someone's account (SECURITY.md T10).

**Rough hosting cost, hosted variant:** one small container per active workspace. At roughly $0.01/hr with aggressive hibernation, 50 workspaces averaging 2 active hours/day is on the order of $30/month. That is affordable; the model bill is what is not — hence BYO key.

---

## 9. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| **Scope collapse** — the canvas alone eats every week | Nothing differentiating ships | Timebox M1 to 1.5 weeks. Note panes only. No styling polish before M4. |
| **Sandbox complexity on Windows** | M2 stalls | Docker Desktop + WSL2 backend. Verify `node-pty` and volume mounts in the first two days of M2, not the last. |
| **Agents behave differently than the claim design assumed** | M4 rework | M3 ships before M4 deliberately. Log every agent write for a week before designing the protocol's edge cases. |
| **Canvas performance with live iframes and terminals** | Unusable past ~8 panes | Freeze offscreen panes: pause xterm rendering and swap iframes for a static screenshot when outside the viewport. Design for this in M1, implement when it hurts. |
| **Prompt injection via repo content** | Agent exfiltrates secrets, pushes malicious code, or poisons a second agent through a shared file | No secrets in the container *(D1, D2)*; egress deny-by-default *(D4)*; human approval for push, package installs, and CI-config writes. Blast-radius reduction, not prevention. [SECURITY.md](./SECURITY.md) T1. |
| **API key custody** *(corrected — D1)* | Key theft, drained budget | The container **never holds the key**. A host-side broker attaches it and makes the API call; the container gets a short-lived workspace-scoped token. The earlier "fetch from orchestrator over a local socket" design was wrong — that still puts the key in container memory, readable by any `Bash` call. |
| **Preview origin confusion** | User dev-server JS steals app session cookies | Preview served from a separate origin in a sandboxed iframe; proxy target resolved server-side from the workspace record only, never from the request *(D3)*. [SECURITY.md](./SECURITY.md) T5. |
| **Container escape** | Full host compromise — the host holds every credential | v1 assumes mutually-trusting workspace members and says so out loud. Rootless Docker, non-root user, `cap-drop=ALL`, no Docker socket mount, read-only root, resource limits. Do not claim hostile-tenant isolation without gVisor or microVMs. |
| **Murmell ships the same thing better** | Motivation collapse | Framing A/B makes this irrelevant — the value is the build and the self-hostable niche, not the market. Decide this in week 1, not week 10. |

### Kill criteria

Stop and reassess if, by the end of M3, an agent cannot reliably complete a two-file change inside the container. That failure means the sandbox or the SDK integration is wrong, and no amount of canvas work fixes it.

---

## 10. Open decisions

### 10.0 — Agent harness and model provider `DECIDED 2026-09-03`

**Decided: Anthropic Claude, via the Claude Agent SDK.**

| Choice | Value |
|---|---|
| Provider | Anthropic (user's decision) |
| Harness | **Claude Agent SDK** — `@anthropic-ai/claude-agent-sdk`, entry point `query()` |
| Primary coding agents | `claude-opus-5` |
| Mechanical background work | `claude-haiku-4-5` |

**Why the Agent SDK over a hand-rolled loop.** It is Claude Code as a library: the agent loop, context management, and built-in Read/Write/Edit/Bash/Glob/Grep tools already exist. Rebuilding those is not this product — the room around the agent is. It also supplies `hooks` (including `PreToolUse`) and a `canUseTool` permission callback, which is where the advisory half of the claim protocol lands (§5, layer 1).

**Model choice is per-need, not one model everywhere.** Coding agents run `claude-opus-5`: agent quality *is* the product's experience, and a cheaper model that needs three attempts is not cheaper. Genuinely mechanical work — summarising a transcript, naming a pane — runs `claude-haiku-4-5` at roughly a fifth the price. Effort stays high for coding and drops to low for background subagents. Revisit per route with measurement, never by guessing.

**D1 is satisfied, and by a documented vendor pattern rather than a workaround.** The rubric's hard requirement (SECURITY.md T2) was that the harness must be pointable at a local endpoint so the container never holds a credential. Claude Code supports exactly this: `ANTHROPIC_BASE_URL` points it at a gateway, and Anthropic's own guidance for that mode is that *"the provider key stays server-side; developers hold gateway credentials instead."* The D1 broker sidecar **is** an LLM gateway. The workspace container gets `ANTHROPIC_BASE_URL` plus a short-lived workspace-scoped credential, and never the real key.

The Agent SDK spawns a Claude Code subprocess and takes an `env` option, which is how those two values reach it. That subprocess runs *inside* the workspace container, so anything in its environment is readable by the agent — which is precisely why only the base URL and a scoped token go there.

**What stays open:** the `AgentProvider` interface (§4) is kept. Not out of indecision — it is what keeps a local or alternative model viable for the self-hosted framing (§2 B), and it is the seam a future provider swap needs. The bakeoff at M3a is now a narrow verification rather than a comparison: confirm the SDK honours the broker base URL end to end before wiring real work through it.

### Everything else — `ALL DECIDED 2026-09-03`

**1. Auth — Supabase Auth**, behind the existing `IdentityProvider` interface. Password reset, session security and MFA are solved problems and are not this project's differentiator. The interface stays so the self-hosted framing (§2 B) can swap in something local.
*Consequence:* `DevIdentityProvider` is a stub that refuses to construct under `NODE_ENV=production`, so this must land before anyone real uses the app. It is not urgent for M3–M5, which are single-operator work.

**2. Repo source — both.** Clone a public repo by URL, and mount a folder from the operator's own machine.
*Consequence:* the local-folder path is the higher-risk one. A host path that comes from a request is a directory-traversal bug and a route into any file on the machine (T5). The path must be resolved from server-side config plus the workspace id — exactly as `WorkspaceSandboxes` already does — and a user-supplied folder must be an explicit, operator-level configuration step, never a value in an API call. Local folders also unblock private code today without waiting on the Git proxy (D2, M6).

**3. Agent identity — yes, names and avatars.** Not decoration: claim 1 in §1 is co-presence, and "agent-2 is holding `src/auth/**`" only reads as a colleague if agent-2 is a *someone*. Roughly half a day, and it makes the M4 conflict UI legible.

**4. Canvas scope — one canvas per workspace.** One repo, one room, everyone in the same place — which is the pitch. Multiple boards would split presence, so people could be "in the workspace" and invisible to each other. Addable later without redesign; the workspace id already comes from the URL rather than being assumed unique.

**5. Git strategy — one shared working tree, governed by claims.** Branch-per-agent is safer and more familiar, and that is exactly why it is the wrong choice here: it reduces the problem to ordinary git, removes the differentiator (§1, claim 3), and prevents agents from seeing each other work.
*Consequence:* the M4 claim protocol and the overlayfs merge gate (§5) are now load-bearing rather than optional, and this is the milestone the project is judged on. Agents do not commit or push in v1 — pushes go through the host-side Git proxy with a branch allowlist and human approval (D2).

---

## 11. What to do next

Every open decision is now closed. M0, M1 and M2 are done; M3a's broker is built and D1 is proven.

1. **M3b** — `AgentProvider` over the Claude Agent SDK, agent panes, streaming transcripts.
2. **One live model call** to finish M3a. Needs an Anthropic key on the broker; nothing else blocks it.
3. **M4** — claims. The milestone the project is judged on (§10 decision 5).

Security work is scheduled per milestone in [SECURITY.md](./SECURITY.md) §4 rather than deferred to a hardening pass. The M2 and M3 items in particular are cheap now and expensive later — container hardening means rebuilding the sandbox provider if retrofitted, and a key that leaks once has no second chance.

Everything above is a draft. The parts most likely to be wrong are the M4 protocol details, because they depend on watching real agent behaviour in M3.
