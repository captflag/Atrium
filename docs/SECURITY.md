# Atrium — Threat Model & Security Design

> Companion to [PLAN.md](./PLAN.md). Draft v1, 2026-09-03.
> Design-stage threat model. No code exists yet, so this is not a code audit — it is the set of decisions that must be made before code exists, because three of them change the architecture.

---

## 0. Summary — five decisions that change the design

Reviewing the plan's architecture surfaced one outright error and four gaps. These are not hardening tasks to bolt on later; they alter §4 of the plan.

| # | Decision | What it corrects |
|---|---|---|
| **D1** | **The container never holds the model provider credential.** A host-side broker makes the inference calls. Provider-agnostic — it holds whatever key or endpoint config the harness chosen at M3a needs. | PLAN.md §9 said the agent runner "fetches them from the orchestrator over a local socket" — that still puts the key in container memory, where any agent `Bash` call can read it. Wrong. |
| **D2** | **The container never holds Git credentials.** A host-side Git proxy performs fetch/push with a branch allowlist. | Not addressed at all. An injected agent with a GitHub token can push to every repo that token scopes. |
| **D3** | **Preview is served from a separate origin**, never a path on the main app origin. | Not addressed. `/preview/:id/*` on the app origin gives user-controlled JavaScript the app's session cookies. |
| **D4** | **Container egress is deny-by-default with an allowlist.** | Not addressed. The primary exfiltration channel for prompt injection. |
| **D5** | **Claims are a coordination mechanism, not a security boundary.** Integrity is enforced outside the container, at the overlayfs merge gate. | PLAN.md §5 implied a harness-level tool hook was a guarantee. It guarantees against *accident*, not against a *compromised* agent — the hook runs where the agent can bypass it. Now moot as a dependency: the harness is undecided, so enforcement moved to the filesystem regardless. |

---

## 1. Assets and trust boundaries

### Assets, by value

1. **Model provider credential** — spendable money, and access to the user's account. (Whichever provider wins at M3a; if the deployment runs a local model instead, this asset shrinks to the endpoint itself.)
2. **Git credentials / GitHub OAuth token** — write access to every repo in scope. Usually the highest-consequence asset, and the one most often left in a container.
3. **Source code** — the repo itself, plus anything the agent reads (`.env` files, config, credentials committed by mistake).
4. **Host machine** — container escape.
5. **Other workspaces** — cross-tenant access.
6. **Session transcripts** — contain code, tool output, and any secret the agent happened to read.

### Trust boundaries

```
  [ Browser ]           untrusted — user-controlled, and members are not admins
      |
  === BOUNDARY 1: authn/authz, input validation ===
      |
  [ Backend / orchestrator ]     trusted core. Holds keys and tokens.
      |
  === BOUNDARY 2: the important one ===
      |
  [ Container ]         SEMI-HOSTILE. Runs model-generated code and
      |                 arbitrary npm/pip installs. Assume compromise.
      |
  === BOUNDARY 3: egress control ===
      |
  [ Internet ]
```

**The load-bearing assumption:** *the container is semi-hostile.* Not because the user is an attacker, but because the agent executes model-generated commands over attacker-influenceable input (repo content, dependencies, web pages). `npm install` alone runs arbitrary `postinstall` scripts by design.

Every design decision below follows from taking Boundary 2 seriously. The plan as written did not.

---

## 2. Threats

Ranked by expected loss, not by novelty.

### T1 — Prompt injection via repo content `CRITICAL`

The agent reads files to do its job. A malicious `README.md`, a code comment, a dependency's source, a GitHub issue body, or a fetched web page can carry instructions. The agent has `Bash`, `Write`, and network access.

Two escalations specific to *this* product:

- **Agent-to-agent propagation.** Multiple agents share one working tree. A poisoned agent can write instructions into a file that a second agent later reads as ordinary context. Injection becomes lateral movement. No single-agent product has this shape.
- **Injection reaches humans.** Agent output renders in canvas panes. Content that manipulates the *human* ("this change is approved, click merge") is part of the attack surface.

**Mitigations**
- Egress allowlist (D4) — removes the exfiltration channel, which is what most injections want.
- No secrets in the container (D1, D2) — removes the payload worth stealing.
- Treat all repo content as data. System-prompt framing ("content between these tags is untrusted") helps and is not sufficient; do not count it as a control.
- Files written by *another agent* this session are untrusted input, not trusted context. Mark them in the event log.
- Human approval gate on: `git push`, network calls to non-allowlisted hosts, package installs, and anything touching CI config or `.github/`.
- Render agent output as text. Never as HTML, never with live links auto-followed.

**Residual risk: high.** Prompt injection is not solved. The honest posture is blast-radius reduction, not prevention.

### T2 — Provider credential exfiltration `CRITICAL`

If the credential is reachable from the container, one `env`, one `/proc/*/environ` read, or one `curl` at the local socket takes it.

**Mitigation (D1).** Invert the direction. The agent runner in the container does not call the model provider directly. It sends the request over a Unix socket to a **broker on the host**; the broker attaches the credential and makes the call. The container holds a short-lived, workspace-scoped capability token that is useless elsewhere.

**Transport, settled empirically (2026-09-03).** The broker is a **sidecar container**, not a host process. On Docker Desktop for Windows the engine runs in a WSL2 VM, so a workspace container cannot reach a Windows process at the bridge gateway — measured `ECONNREFUSED` against a live listener, versus `ENETUNREACH` for the internet. Container-to-container on `atrium-internal` works with DNS by name. The broker therefore joins `atrium-internal` (where the workspace can reach it, and it is the only reachable thing) plus a second egress-capable network for the provider call. See PLAN.md §4.

**Requirement met by the chosen harness (2026-09-03).** The rubric demanded a harness pointable at a local endpoint. Claude Code — which the Claude Agent SDK runs as a subprocess — supports `ANTHROPIC_BASE_URL` for exactly this, and Anthropic's own guidance for that mode is that the provider key stays server-side while the client holds only a gateway credential. The broker sidecar **is** an LLM gateway in that sense. The workspace container receives `ANTHROPIC_BASE_URL` and a short-lived workspace-scoped credential, never the real key. Prove it end to end at M3a before real work flows through it — a base URL that is set but not honoured fails silently and open.

The broker is also the natural place for: per-session token budgets, spend caps, request logging, and the transcript redaction in T9.

### T3 — Container escape `HIGH`

Docker is not a security boundary against hostile code. Escape means host compromise, and the host holds every key.

**Mitigations**
- Rootless Docker, or gVisor / Firecracker if hosting untrusted users. Choose based on framing (PLAN §2): self-host among trusting colleagues can accept rootless Docker; anything multi-tenant cannot.
- Never mount the Docker socket into a container. This is the single most common fatal mistake in this product category.
- Non-root user, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, seccomp default profile, user namespace remapping.
- Read-only root filesystem; writable `tmpfs` plus the repo mount only.
- Hard limits: CPU, memory, PIDs (fork bombs), disk quota (fill-the-host), no host network.

### T4 — Git credential theft and unauthorized push `HIGH`

A token in the container is a token the agent can use, and an injected agent will.

**Mitigation (D2).** Host-side Git proxy. The container has no credentials and no direct network path to GitHub. It requests `fetch` / `push` through the orchestrator, which:
- Holds a token scoped to the single repo, with minimal scopes.
- Enforces a branch allowlist — agents push to `atrium/agent-*` branches, never to default or release branches.
- Requires human approval for any push, in v1 unconditionally.

Force-push and branch deletion are never permitted to agents.

### T5 — Preview proxy: SSRF, cross-workspace access, and origin confusion `HIGH`

Three distinct bugs live in one component.

- **Origin confusion.** Serving the user's dev server at `app.example.com/preview/...` means that dev server's JavaScript runs on the app origin and can read the app's cookies and `localStorage`. Mitigation (D3): serve previews from a separate origin — `<workspace-id>.preview.example.com`, or a wholly separate domain — and embed in a `sandbox`ed iframe. Session cookies must be `Secure`, `HttpOnly`, `SameSite=Lax`, and scoped so the preview origin never receives them.
- **SSRF.** If the proxy target host or port is influenced by the request, it becomes an open proxy into the internal network and cloud metadata endpoints (`169.254.169.254`). Mitigation: the target is resolved *only* from the workspace record server-side. Never from a query parameter, header, or path segment. Allowlist the port range.
- **Cross-workspace access.** `:id` must be authorized against membership on every request, including WebSocket upgrades and every subresource — not just the initial page load.

### T6 — Authorization on the realtime layer `HIGH`

Yjs sync is frequently built as "possession of the document id grants access." That is not authorization.

**Mitigations**
- Authenticate the WebSocket at upgrade time and check workspace membership before attaching the document. Re-check on reconnect (see T11).
- Validate pane payloads server-side against a schema. A member who can write arbitrary payloads into the shared `Y.Doc` can plant stored XSS for every teammate — an `iframe` `src`, a `javascript:` URL, injected HTML in a note pane.
- Render pane content as data. Sanitize on write *and* on render.
- Strict CSP on the app origin: no `unsafe-inline`, explicit `frame-src` for the preview origin only.

### T7 — Claims are not a security control `HIGH` *(correction to PLAN.md §5)*

The original plan said a harness-level tool hook made claim enforcement "a guarantee." True against *accident*, false against *compromise*: a hook runs in the agent's own process, and a prompt-injected agent does not need the `Write` tool — it has `Bash`. `echo ... > src/auth.ts` bypasses any in-process hook.

Deferring the harness choice (PLAN §10.0) makes this moot as a dependency. Several candidate harnesses expose no tool gate at all, so the design cannot require one — enforcement had to move to the filesystem anyway.

**Correct framing:**
- **Claims prevent collisions between cooperating agents.** That is their job, they do it well, keep them.
- **Integrity is enforced outside the container.** Each agent writes into a private overlayfs upper layer; the orchestrator merges it down and rejects any path not covered by a live claim (PLAN §5 step 4). The kernel performs the interception, so it holds against `Bash`, a script the agent wrote, or any harness.
- Destructive operations and non-allowlisted egress are additionally gated at the broker and the network layer, both outside the container.

This does not weaken the plan's differentiator — it strengthens it. A guarantee that survives a hostile agent is a better demo than one that survives only a polite one.

### T8 — Workspace membership is a grant of code execution `MEDIUM`

A terminal pane is a shell in the container. Anyone in the workspace has one. Inviting someone to a workspace is therefore equivalent to granting them RCE in that container and read access to the repo.

**Mitigations**
- No "anyone with the link" access. Ever.
- Explicit invitations, accepted by an authenticated account.
- Say it plainly in the invite UI. Users will not infer it.
- Roles (viewer / operator) if time allows; viewers get read-only panes and no terminal.

### T9 — Secret leakage into transcripts and snapshots `MEDIUM`

An agent that reads `.env` puts its contents into the Postgres event log, into every connected browser, and into the hibernation snapshot. Three copies, all long-lived.

**Mitigations**
- Default-deny reads of `.env*`, `*.pem`, `*.key`, `id_*`, `credentials`, `.aws/`, `.ssh/` at the tool boundary. Overridable per workspace, with a warning.
- Redact known secret patterns at the broker before events are persisted.
- Encrypt event log and snapshots at rest. Snapshots contain the entire filesystem.
- Retention policy on transcripts; they are the highest-density secret store in the system.

### T10 — Resource and cost abuse `MEDIUM`

A looping agent burns the user's API budget. A malicious dependency mines cryptocurrency in the container. Both are cheap to prevent and expensive to discover late.

**Mitigations**
- Per-session token budget and hard spend cap, enforced at the broker (D1 makes this possible).
- Max turns per task; max concurrent agents per workspace.
- Container CPU, memory, PID and disk quotas (T3).
- Idle hibernation is a cost control as much as a UX feature.
- Alert the user on anomalous spend rather than silently continuing.

### T11 — IDOR on replay and reconnect `MEDIUM`

The durability design (PLAN §6) replays events from a client-supplied sequence number. `GET /sessions/:id/events?from=0` is an obvious cross-workspace read if authorization is checked only at connect time.

**Mitigations**
- Authorize every replay request against session → workspace → membership.
- Session ids are unguessable (UUIDv4 or better), but treat that as defence in depth, never as the control.
- Re-authorize on every reconnect. Membership may have been revoked during the disconnect — which is exactly the window durability creates.

### T12 — Supply chain `MEDIUM`

Three layers: the base container image, Atrium's own dependencies, and whatever the user's repo installs. The third is unbounded by design and is why the container is semi-hostile.

**Mitigations**
- Pin the base image by digest. Rebuild and scan on a schedule.
- Lockfiles committed; automated dependency updates reviewed, not auto-merged.
- Package installs inside the container are a human-approval gate in v1 (also T1).

### T13 — Authentication of the app itself `MEDIUM`

Standard, but easy to defer past the point where it is cheap.

- Managed auth (Supabase Auth or equivalent) over hand-rolled sessions. Password handling is not this project's differentiator.
- MFA available; required for accounts that can add members.
- Rate-limit login, invite acceptance, and workspace creation.
- Rotate and revoke user API keys from the UI, with an audit trail.

---

## 3. What v1 explicitly does not defend against

Stating this is part of the design. An unstated limit gets mistaken for a guarantee.

- **A hostile workspace member.** Membership grants container RCE (T8). v1 assumes members trust each other, exactly as PLAN.md §2 assumes.
- **A determined container escape.** Rootless Docker with dropped capabilities raises the cost; it does not make escape impossible. Hostile-tenant hosting requires gVisor or microVMs, which is a different project.
- **Prompt injection in the general case.** Blast radius is reduced (D1, D2, D4). Prevention is not claimed.
- **A malicious dependency inside the repo being worked on.** It runs in the container by design. Containment, not prevention.
- **Nation-state or supply-chain attacks on the model provider, Docker, or the host OS.** Out of scope.

---

## 4. Security work by milestone

Security that is scheduled gets built. Security in a backlog does not.

| Milestone | Security work | Why here |
|---|---|---|
| **M0** | Secrets out of the repo (`.env` in `.gitignore`, `.env.example` committed). Dependency lockfiles. Baseline CSP. | Costs an hour now; costs a rewrite later. |
| **M1** | WebSocket auth at upgrade + membership check (T6). Server-side pane payload validation. Cookie flags. | The realtime layer is where authorization is most often skipped. |
| **M2** | Full container hardening (T3): rootless, cap-drop, no-new-privileges, read-only root, resource limits, no host network, **no Docker socket mount**. Egress allowlist (D4). **Done — with four gaps, listed below.** | Retrofitting container hardening means rebuilding the provider. Do it while it is 30 lines of config. |
| **M3a** | Rubric-gate the bakeoff on D1: reject any harness that cannot be pointed at the local broker's base URL (T2). | Cheaper to eliminate a candidate than to discover after integration that it cannot be secured. |
| **M3b** | **Credential broker on the host (D1).** Per-session token budget and spend cap (T10). Secret-file read denial and transcript redaction (T9). | The first moment a credential exists in the system. Get it right on day one; there is no second chance for a leaked key. |
| **M4** | Overlayfs merge gate as the authoritative enforcement (T7, D5). Human-approval gate for destructive operations. | Ship with the claim protocol so the demo's honesty holds up. |
| **M5** | Replay authorization (T11). Re-auth on reconnect. Snapshot encryption at rest (T9). | These threats do not exist until durability does. |
| **M6** | Preview on a separate origin, sandboxed iframe, server-resolved proxy target (T5, D3). **Git proxy with branch allowlist (D2).** | Preview and push are the last two components; both are high-severity. |

### M2 as built — what is enforced, and what is not

Written down because a control you believe you have is worse than one you know you lack. The four gaps below are reported at runtime in `SandboxHandle.unenforced` and surfaced in the `sandbox` line of `/api/health`; they are not a to-do list hidden in a comment.

**Enforced by the kernel, verified by re-inspecting the running container** — non-root user (uid:gid 10001, `validateSpec` refuses uid 0), `cap-drop=ALL`, `no-new-privileges`, the default seccomp profile (by never passing `seccomp=`), read-only root filesystem with writes confined to declared `noexec` tmpfs and the repo bind mount, memory/CPU/PID limits (swap disabled by setting `MemorySwap` equal to `Memory`), no port publishing, **no Docker socket bind anywhere and no spec field that could ask for one**, and no route off-host: a workspace container joins the `atrium-internal` bridge or `--network=none`, and `assertNetworkMode` refuses `host` and `container:`. A create whose hardening did not stick is removed rather than run.

The network is the one D4 control the long-lived container has, so it is verified rather than assumed at three points. `Internal: true` — the flag that stops the daemon writing a NAT masquerade rule, which *is* the control — is read back from the daemon before any container joins; a network already named `atrium-internal` that is **not** internal is an ordinary routable bridge, so it is refused (with the `docker network rm` to fix it) instead of adopted on the strength of its name, and the same scrutiny applies to a network created by a concurrent process that won the 409 race. After create, the container's own endpoints are re-inspected: `HostConfig.NetworkMode` must equal what was requested — not merely differ from `host`, since `bridge` has full egress too — and the attachment must be that one network **matched by id**, so a delete-and-recreate under the same name between verification and create cannot substitute an unverified network. Each failure removes the container rather than running it.

**Not enforced on Docker Desktop for Windows, reported every time:**

- `egress-allowlist` — Docker has no per-container egress firewall. A spec asking for `allowlist` falls back to the `--internal` bridge (strictly tighter: no egress at all) and says so. A normal bridge is never created and called an allowlist. Real hostname filtering needs the proxy sidecar described in `EgressPolicy`.
- `disk-quota` — `--storage-opt size=` needs overlay2 on xfs with pquota; the WSL2 backing store is ext4. The tmpfs caps and the host's free space are the only bound, and a container can still fill the host disk *through the repo bind mount*.
- `rootless-engine` — Docker Desktop's engine runs as root inside its own VM. That VM is a real boundary, but an escape lands as root in the VM holding the bind mount.
- `userns-remap` — the daemon has none, so container uid 10001 is uid 10001 in the VM.

**One deliberate exception to deny-by-default egress.** `git clone` cannot run in a container with no network, and giving the long-lived, agent-inhabited container real egress is exactly the channel prompt injection wants (T1). So a clone runs in a *separate throwaway* container on the default bridge — unfiltered egress, typed `egressUnfiltered: true` so it cannot be read as safe — bounded by: no credentials of any kind, a ~2s lifetime, `git clone` only, no submodules, and one writable path. Public HTTPS only; URLs with userinfo, ssh/git/file schemes, IP literals, `localhost` and `*.internal` (the metadata-endpoint SSRF, T5) are refused. Private repositories wait for the Git proxy (D2, M6).

**Terminal-specific authorization (T6, T8).** A terminal pane is code execution in the container, so: authorization happens at the websocket upgrade before a frame is read, in the same order as the canvas gateway; **the wire protocol cannot create a terminal** — `subscribe` only attaches, and creation is an authorized HTTP route that repeats authenticate + membership; lookup is keyed by (workspace, terminal), so cross-workspace access is structurally unreachable rather than a check that can be forgotten; a terminal that does not exist and one belonging to another workspace get the same `not-found` on the wire, with the distinction written only to the operator log. Inbound keystrokes are rate-limited per socket (T10) and output bytes are never decoded, transformed, or logged (T9).

**Known M2 limitations that are not gaps in the above.** Exec timeouts are host-side only — Docker has no "kill exec", so a timed-out command keeps running, bounded by the container's cgroup limits rather than by the timeout. The same API hole means a shell whose owning server process died cannot be reattached to or killed by a stream; adopting a container therefore reaps the pid files a previous run left in its tmpfs, which assumes one Atrium process per workspace. Terminal scrollback is in memory and is lost on restart (durable replay is M5). Auth is still `DevIdentityProvider`, which refuses to construct in production — with it, every principal is a member of every workspace, so none of the membership checks above are load-bearing until PLAN.md §10 decision #1 is made.

---

## 5. Revisions required to PLAN.md

1. **§4 Architecture** — add the host-side **model broker** and **Git proxy** between the orchestrator and the container. The container's outbound path to both the model provider and GitHub goes through the host.
2. **§4** — the `SandboxProvider` interface needs `proxyPort` to return a **separate-origin** URL, not an app-origin path.
3. **§5 Claim protocol** — replace "a hook is a guarantee" with the accurate framing from T7: hooks are advisory; the overlayfs merge gate enforces integrity.
4. **§9 Risks** — the credential row's mitigation is wrong as written. Replace with D1.
5. **§9 Risks** — add rows for prompt injection (T1) and preview origin confusion (T5). Both are higher-severity than several risks already listed.
6. **§2 Non-goals** — already says v1 assumes mutually-trusting members. Good. Make it prominent rather than a bullet, since it is the assumption everything else rests on.

---

## 6. What to do next

1. Accept or reject **D1–D5**. D1 and D5 change existing text; the rest are additions.
2. If the framing from PLAN §2 becomes multi-tenant hosting, reopen T3 — rootless Docker is not sufficient there, and that changes the sandbox provider.
3. Apply the §5 revisions to PLAN.md before starting M0.
