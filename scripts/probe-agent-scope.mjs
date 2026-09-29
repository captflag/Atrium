/**
 * Agent session ids are scoped BY WORKSPACE, at every layer (SECURITY.md T5, T6).
 *
 * ============================================================================
 * WHY THIS PROBE EXISTS
 * ============================================================================
 * `AgentRegistry` keys its sessions by `(workspaceId, agentId)` and says so:
 * "cross-workspace access is not a check that can be forgotten later; it is
 * structurally unreachable". `packages/shared/src/agent.ts` repeats the claim to
 * the client. Both were true of the registry and FALSE of the layer it
 * delegates to — `ClaudeAgentProvider` kept one global `Map` keyed by the bare
 * id, so every workspace shared one namespace one level down.
 *
 * The id is not server-minted. `agent-routes.ts` reads `agentId` out of the
 * POST body and checks only that it matches `AGENT_ID_RE`, and the web client
 * sends the canvas pane's id. So naming another workspace's id is a thing any
 * member can do, and it bought three things:
 *
 *   1. Denial of start   — B POSTs A's id to B's OWN workspace; the registry
 *                          sees no such key, the provider finds A's live
 *                          session, and the start fails with HTTP 400.
 *   2. An existence oracle — that 400 is returned ONLY when the id is live in
 *                          some OTHER workspace, which is exactly the
 *                          distinction every other path erases.
 *   3. Eviction          — B's POST deletes A's retained transcript and takes
 *                          the key. Separately, the retention bound was global,
 *                          so one busy workspace evicted everyone else's.
 *
 * ============================================================================
 * WHY IT NEEDS NO DOCKER
 * ============================================================================
 * The defect is map keying, not containers, so this drives the real
 * `ClaudeAgentProvider` against a fake `SandboxLocator` and a fake pty that
 * speaks the real framed runner protocol. Seconds, no images, no Postgres —
 * which is the point: the expensive probes did not catch this, and a guard that
 * is expensive to run is a guard that stops being run.
 *
 *   node scripts/probe-agent-scope.mjs
 */

import { ClaudeAgentProvider } from "../apps/server/src/agent/claude-agent.ts";
import {
  RUNNER_FRAME_MARKER,
  RUNNER_PROTOCOL_VERSION,
  RunnerLineReader,
  encodeRunnerLine,
} from "../apps/server/src/agent/runner-protocol.ts";
import { mintAgentIdentity } from "../apps/server/src/agent/identity.ts";

let pass = 0;
let fail = 0;
const ok = (n, d = "") => { pass += 1; console.log(`PASS  ${n}${d ? `  -- ${d}` : ""}`) };
const bad = (n, d = "") => { fail += 1; console.log(`FAIL  ${n}${d ? `  -- ${d}` : ""}`) };

/**
 * A pty that speaks the runner protocol without a container.
 *
 * Emits `ready` as soon as the provider subscribes, answers `start` with an
 * `event{kind:"started"}`, and answers `prompt` with a text event. Anything
 * else is ignored, exactly as a real runner would ignore a frame it does not
 * handle.
 */
function fakePty(id) {
  const listeners = new Set();
  let exitResolve;
  const exited = new Promise((r) => { exitResolve = r; });
  const reader = new RunnerLineReader();
  let alive = true;

  const emit = (message) => {
    if (!alive) return;
    const text = encodeRunnerLine(message);
    for (const l of listeners) l(Buffer.from(text, "utf8"));
  };

  /**
   * Every reply is DEFERRED, because the real runner is a separate process
   * across a pty. Replying synchronously to the host's own `write` is a thing
   * no runner can do, and modelling it that way would make this fake fail the
   * ready/started handshake for a reason production never has.
   */
  const later = (fn) => setTimeout(fn, 1);

  const handle = {
    id: `pty-${id}`,
    sandboxId: `sandbox-${id}`,
    write(data) {
      if (!alive) return;
      for (const body of reader.push(Buffer.from(data).toString("utf8"))) {
        let msg;
        try { msg = JSON.parse(body); } catch { continue; }
        if (msg.t === "start") {
          later(() => {
            emit({ t: "event", e: {
              kind: "started", harness: "fake", model: msg.spec.model,
              cwd: msg.spec.repoRoot, tools: [],
            } });
            emit({ t: "state", state: "idle" });
          });
        }
        if (msg.t === "stop") later(() => { alive = false; exitResolve({ exitCode: 0 }); });
      }
    },
    resize() {},
    onData(listener) {
      listeners.add(listener);
      // The real runner announces itself the moment its stdio is raw.
      later(() => emit({ t: "ready", v: RUNNER_PROTOCOL_VERSION }));
      return () => listeners.delete(listener);
    },
    exited,
    kill() { if (alive) { alive = false; exitResolve({ exitCode: 137 }); } },
    async dispose() { if (alive) { alive = false; exitResolve({ exitCode: 0 }); } },
  };
  return handle;
}

/** A `SandboxLocator` that hands out a fake pty for any workspace. */
function fakeSandboxes() {
  let n = 0;
  const provider = {
    async spawnPty() { n += 1; return fakePty(n); },
  };
  return {
    async forWorkspace(workspaceId) {
      return { provider, handle: { id: `sandbox-${workspaceId}`, state: "running" } };
    },
  };
}

function specFor(workspaceId, sessionId) {
  return {
    sessionId,
    workspaceId,
    identity: mintAgentIdentity(sessionId),
    task: "probe",
    repoRoot: "/workspace",
    models: { coding: { model: "claude-opus-5", effort: "high" } },
    limits: { maxTurns: 3, turnTimeoutMs: 60_000 },
    tools: { allowed: [], denied: [] },
    broker: {
      baseUrl: "http://atrium-broker:8900",
      capabilityToken: "cap-probe-scope-0123456789",
      expiresAt: new Date(Date.now() + 3_600_000),
    },
  };
}

async function main() {
  const log = { info: () => {}, warn: () => {} };
  const agents = new ClaudeAgentProvider({
    sandboxes: fakeSandboxes(),
    log,
    readyTimeoutMs: 5_000,
    startTimeoutMs: 5_000,
    stopGraceMs: 500,
  });

  // The id a pane would supply. Identical in both workspaces, which is legal:
  // ids are unique per workspace and NOT globally.
  const ID = "pane-collide";

  console.log("=== two workspaces may hold the SAME agent id ===");

  const a = await agents.start(specFor("workspace-a", ID));
  ok("workspace A started an agent", `${a.workspaceId}/${a.sessionId} state=${a.state}`);

  // THE regression assertion. Before the fix this threw `bad-message` ("an
  // agent session with that id already exists") because it found A's session
  // under the bare id — surfacing to workspace B as HTTP 400 "That task cannot
  // be run", and telling B that the id was live somewhere it could not see.
  let b = null;
  let startError = null;
  try {
    b = await agents.start(specFor("workspace-b", ID));
  } catch (error) {
    startError = error;
  }
  b !== null
    ? ok("workspace B started the SAME id without colliding", `${b.workspaceId}/${b.sessionId}`)
    : bad("workspace B started the same id without colliding",
          `${startError?.code ?? "?"}: ${startError?.message ?? startError}`);
  if (b === null) return;

  console.log("\n=== the two sessions are independent ===");

  const ia = await agents.inspect("workspace-a", ID);
  const ib = await agents.inspect("workspace-b", ID);
  ia !== null && ib !== null && ia.workspaceId === "workspace-a" && ib.workspaceId === "workspace-b"
    ? ok("inspect() is workspace-scoped and resolves each one separately",
         `${ia.workspaceId} vs ${ib.workspaceId}`)
    : bad("inspect() is workspace-scoped", `${JSON.stringify(ia)} / ${JSON.stringify(ib)}`);

  const nowhere = await agents.inspect("workspace-c", ID);
  nowhere === null
    ? ok("a third workspace resolves the same id to nothing")
    : bad("a third workspace resolves the same id to nothing", JSON.stringify(nowhere));

  // Two distinct handles, not one object resolved twice — which is what a
  // shared namespace would have produced.
  ia.sessionId === ID && ib.sessionId === ID && ia !== ib && ia.startedAt !== ib.startedAt
    ? ok("both carry the same pane id but are genuinely separate sessions",
         `startedAt ${ia.startedAt.toISOString()} vs ${ib.startedAt.toISOString()}`)
    : bad("both carry the same pane id but are genuinely separate sessions",
          `same handle object: ${ia === ib}`);

  console.log("\n=== stopping one does not touch the other ===");

  await agents.stop(b);
  const afterA = await agents.inspect("workspace-a", ID);
  const afterB = await agents.inspect("workspace-b", ID);
  afterA !== null && afterA.state !== "stopped" && afterA.state !== "failed"
    ? ok("workspace A's session is untouched by B's stop", `state=${afterA.state}`)
    : bad("workspace A's session is untouched by B's stop", afterA ? afterA.state : "gone");
  afterB !== null && (afterB.state === "stopped" || afterB.state === "failed")
    ? ok("workspace B's session is the one that stopped", `state=${afterB.state}`)
    : bad("workspace B's session is the one that stopped", afterB ? afterB.state : "gone");

  // Restart-after-stop must still work per workspace: a terminated session
  // under this key is the documented delete-then-start gesture.
  const bAgain = await agents.start(specFor("workspace-b", ID)).catch((e) => e);
  bAgain instanceof Error
    ? bad("workspace B can restart its own id after stopping it", `${bAgain.code}: ${bAgain.message}`)
    : ok("workspace B can restart its own id after stopping it", `state=${bAgain.state}`);

  // And a genuine duplicate WITHIN one workspace must still be refused: the fix
  // must not have widened the key so far that it stopped catching real ones.
  const dup = await agents.start(specFor("workspace-a", ID)).catch((e) => e);
  dup instanceof Error && dup.code === "bad-message"
    ? ok("a duplicate id within ONE workspace is still refused", dup.message)
    : bad("a duplicate id within one workspace is still refused",
          dup instanceof Error ? `${dup.code}` : "it was allowed");

  await agents.stopAll().catch(() => {});

  console.log(`\n${fail === 0 ? "ALL CHECKS PASSED" : "FAILURES PRESENT"}  (${pass} passed, ${fail} failed)`);
  process.exitCode = fail === 0 ? 0 : 1;
}

await main();
