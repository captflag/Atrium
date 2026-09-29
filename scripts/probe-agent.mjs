/**
 * M3b proof: the Claude Agent SDK runs INSIDE the workspace container, reaches
 * the model only through the broker, and its output becomes `AgentEvent`s —
 * with NO provider credential anywhere in the container (SECURITY.md D1).
 *
 * Same shape as scripts/probe-broker.mjs and the same reason for existing: this
 * boundary fails SILENTLY AND OPEN. A base URL that is set but not honoured, a
 * header that is forwarded when it should be stripped, a runner that quietly
 * falls back to its own credential — all three look exactly like success. So
 * they are asserted, not assumed.
 *
 *   workspace container            broker sidecar        upstream stub
 *   (agent runner + Claude Code)   (holds the FAKE key)  (reports what it saw)
 *   ANTHROPIC_BASE_URL ------->    x-api-key: FAKE --->  canned SSE response
 *   x-atrium-capability: cap-...
 *
 * Uses a FAKE credential and a stub upstream, so no Anthropic key is needed and
 * none is at risk. What this therefore does NOT prove is that the real API
 * accepts our requests — that is M3a's remaining live call.
 *
 * TWO HALVES, AND BOTH ARE NEEDED:
 *
 *   Sections 1-10  drive `AgentProvider` DIRECTLY. That is the right way to
 *                  prove the credential boundary, the event contract and the
 *                  lifecycle, and it proves nothing about whether a person can
 *                  use any of it.
 *   Section 11     drives the REAL SERVER — `apps/server/src/index.ts`, started
 *                  as a child process with no test hooks in it — through only
 *                  what a browser touches: the authorized POST/DELETE/GET
 *                  routes and the `/rt/agent` socket. Two viewers, one
 *                  transcript, a late joiner, another workspace refused, and a
 *                  session that outlives every viewer.
 *
 * This script creates everything it needs and tears it down again: containers,
 * the broker sidecar, the workspace checkout and the server process.
 *
 *   npm run db:up                    # section 11 needs Postgres and a .env
 *   docker build -f docker/workspace.Dockerfile -t atrium/workspace-base:m2 .
 *   docker build -f docker/broker.Dockerfile    -t atrium/broker:m3 .
 *   node scripts/probe-agent.mjs
 */

import { execFileSync, spawn } from "node:child_process";
import { existsSync, mkdirSync, openSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";

import { LocalDockerProvider } from "../apps/server/src/sandbox/local-docker.ts";
import { workspaceSpec } from "../apps/server/src/sandbox/spec.ts";
import { ClaudeAgentProvider } from "../apps/server/src/agent/claude-agent.ts";
import { mintAgentIdentity } from "../apps/server/src/agent/identity.ts";
import { BrokerSidecars, sidecarName } from "../apps/server/src/sandbox/broker-sidecar.ts";
import { isValidAgentIdentity, parseServerAgentControl } from "../packages/shared/src/agent.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..");

const DOCKER = [
  "C:/Users/FUNCELL/AppData/Local/Programs/DockerDesktop/resources/bin/docker.exe",
  "/usr/bin/docker",
  "docker",
].find((p) => p === "docker" || existsSync(p)) ?? "docker";

const NET = "atrium-internal";
const FAKE_KEY = "sk-ant-FAKE-CREDENTIAL-DO-NOT-USE-0123456789";
const CAP = "cap-workspace-agentprobe-0123456789";
const WORKSPACE = "agentprobe";
const REPO_DIR = join(REPO, ".atrium", "probe-agent");
const STUB_TEXT = "ATRIUM-PROBE-CANNED-REPLY";

/* The wired half (section 11) drives the REAL server on its own port, with its
 * own workspace, so it cannot collide with a dev server someone left running. */
const WIRE_WORKSPACE = "agentwire";
const WIRE_AGENT = "probe-pane";
const WIRE_PORT = 8788;
const WIRE_HOST = `127.0.0.1:${WIRE_PORT}`;
const WIRE_ORIGIN = "http://localhost:5173";
const WIRE_DIR = join(REPO, ".atrium", "workspaces", WIRE_WORKSPACE);
const WIRE_LOG = join(REPO, ".atrium", "probe-agent-server.log");

let pass = 0;
let fail = 0;
const ok = (n, d = "") => { pass += 1; console.log(`PASS  ${n}${d ? `  -- ${d}` : ""}`) };
const bad = (n, d = "") => { fail += 1; console.log(`FAIL  ${n}${d ? `  -- ${d}` : ""}`) };
const docker = (args, opts = {}) =>
  execFileSync(DOCKER, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], ...opts });
const quiet = (args) => { try { return docker(args) } catch (e) { return String(e.stdout ?? "") } };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* ==========================================================================
 * The upstream stub: a canned Anthropic streaming response.
 *
 * Claude Code streams, so a plain JSON body is not enough — it wants SSE in the
 * Messages API event shape. Every request is logged as a SAW line so the probe
 * can assert what actually crossed the boundary.
 * ========================================================================== */
const PROBE_PATH = "/workspace/README.md";
const STUB = `
const {createServer}=require("http");
const TEXT=${JSON.stringify(STUB_TEXT)};
const PROBE_PATH=${JSON.stringify(PROBE_PATH)};
let calls=0;
function open(res){
  res.writeHead(200,{"content-type":"text/event-stream","cache-control":"no-cache"});
  return (t,d)=>res.write("event: "+t+"\\ndata: "+JSON.stringify(d)+"\\n\\n");
}
function head(send){
  send("message_start",{type:"message_start",message:{id:"msg_probe"+calls,type:"message",role:"assistant",
    model:"claude-opus-5",content:[],stop_reason:null,stop_sequence:null,
    usage:{input_tokens:1200,output_tokens:1,cache_read_input_tokens:0,cache_creation_input_tokens:0}}});
}
/* Call 1 asks for a tool, so the PreToolUse hook and the advisory gate are on
   the path. Every later call answers with plain text and ends the turn. */
function sse(res){
  const send=open(res); calls+=1; head(send);
  if(calls===1){
    send("content_block_start",{type:"content_block_start",index:0,
      content_block:{type:"tool_use",id:"toolu_probe1",name:"Read",input:{}}});
    send("content_block_delta",{type:"content_block_delta",index:0,
      delta:{type:"input_json_delta",partial_json:JSON.stringify({file_path:PROBE_PATH})}});
    send("content_block_stop",{type:"content_block_stop",index:0});
    send("message_delta",{type:"message_delta",delta:{stop_reason:"tool_use",stop_sequence:null},
      usage:{output_tokens:18}});
  } else {
    send("content_block_start",{type:"content_block_start",index:0,content_block:{type:"text",text:""}});
    send("content_block_delta",{type:"content_block_delta",index:0,delta:{type:"text_delta",text:TEXT}});
    send("content_block_stop",{type:"content_block_stop",index:0});
    send("message_delta",{type:"message_delta",delta:{stop_reason:"end_turn",stop_sequence:null},
      usage:{output_tokens:24}});
  }
  send("message_stop",{type:"message_stop"});
  res.end();
}
createServer((req,res)=>{let b="";req.on("data",c=>b+=c);req.on("end",()=>{
  process.stdout.write("SAW "+JSON.stringify({path:req.url,
    xApiKey:req.headers["x-api-key"]||null,
    auth:req.headers["authorization"]||null,
    cap:req.headers["x-atrium-capability"]||null})+"\\n");
  if(req.url.indexOf("/v1/messages/count_tokens")===0){
    res.writeHead(200,{"content-type":"application/json"});
    res.end(JSON.stringify({input_tokens:1200}));return;
  }
  if(req.url.indexOf("/v1/models")===0){
    res.writeHead(200,{"content-type":"application/json"});
    res.end(JSON.stringify({data:[{id:"claude-opus-5",type:"model"}]}));return;
  }
  sse(res);
})}).listen(8901,"0.0.0.0",()=>process.stdout.write("stub listening\\n"));`;

function cleanupContainers() {
  quiet(["rm", "-f", "upstream-stub", "atrium-broker"]);
}

/* ========================================================================== */

async function main() {
  const log = {
    info: () => {},
    warn: (obj, msg) => process.env.PROBE_VERBOSE ? console.log("  [warn]", msg, JSON.stringify(obj)) : undefined,
  };

  /* ---- 1. the protocol twin has not drifted --------------------------- */
  console.log("=== the runner protocol exists twice and has not drifted ===");
  const hostCopy = readFileSync(join(REPO, "apps/server/src/agent/runner-protocol.ts"));
  const runnerCopy = readFileSync(join(REPO, "apps/agent-runner/src/protocol.ts"));
  hostCopy.equals(runnerCopy)
    ? ok("host and runner protocol files are byte-identical", `${hostCopy.length} bytes`)
    : bad("host and runner protocol files are byte-identical",
          "edit both apps/server/src/agent/runner-protocol.ts and apps/agent-runner/src/protocol.ts");

  /* ---- 2. the image actually carries a runnable harness ---------------- */
  console.log("\n=== the workspace image carries the harness for THIS libc ===");
  const found = quiet(["run", "--rm", "atrium/workspace-base:m2", "sh", "-c",
    "find /opt/atrium-runner/node_modules/@anthropic-ai -maxdepth 2 -name claude -type f -print -quit"]).trim();
  found.includes("musl")
    ? ok("the musl Claude Code binary is baked into the image", found)
    : bad("the musl Claude Code binary is baked into the image", found || "not found");

  const runnerWritable = quiet(["run", "--rm", "--user", "10001:10001", "atrium/workspace-base:m2",
    "sh", "-c", "touch /opt/atrium-runner/src/index.ts 2>&1 || echo REFUSED"]).trim();
  runnerWritable.includes("REFUSED")
    ? ok("the agent cannot rewrite its own runner")
    : bad("the agent cannot rewrite its own runner", runnerWritable);

  /* ---- 3. broker + stub ------------------------------------------------ */
  console.log("\n=== broker sidecar with a FAKE credential ===");
  cleanupContainers();
  quiet(["network", "create", "--internal", NET]);

  docker(["run", "-d", "--name", "upstream-stub", "--network", NET,
    "-e", `STUB=${Buffer.from(STUB).toString("base64")}`,
    "node:22-alpine", "node", "-e",
    'eval(Buffer.from(process.env.STUB,"base64").toString("utf8"))']);

  docker(["run", "-d", "--name", "atrium-broker", "--network", NET,
    "--user", "10002:10002", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
    "-e", "ATRIUM_UPSTREAM_ORIGIN=http://upstream-stub:8901",
    "-e", `ATRIUM_UPSTREAM_API_KEY=${FAKE_KEY}`,
    "-e", `ATRIUM_CAPABILITY_TOKEN=${CAP}`,
    "-e", "ATRIUM_SESSION_TOKEN_BUDGET=100000000",
    "atrium/broker:m3"]);

  await sleep(3500);
  quiet(["logs", "atrium-broker"]).includes("broker listening")
    ? ok("broker started")
    : bad("broker started", quiet(["logs", "atrium-broker"]).split("\n").slice(-3).join(" | "));

  /* ---- 4. a real hardened workspace sandbox ---------------------------- */
  console.log("\n=== a hardened workspace container, via the real provider ===");
  rmSync(REPO_DIR, { recursive: true, force: true });
  mkdirSync(REPO_DIR, { recursive: true });
  writeFileSync(join(REPO_DIR, "README.md"), "# probe workspace\n");

  const imageId = docker(["image", "inspect", "--format", "{{.Id}}", "atrium/workspace-base:m2"]).trim();
  const sandboxes = new LocalDockerProvider({
    socketPath: process.env.DOCKER_SOCKET ?? "//./pipe/dockerDesktopLinuxEngine",
  });
  const spec = workspaceSpec({
    image: { repository: "atrium/workspace-base", tag: "m2", digest: imageId },
    hostRepoPath: REPO_DIR,
  });

  let sandbox = null;
  let agents = null;
  let handle = null;
  const events = [];

  try {
    sandbox = await sandboxes.create(WORKSPACE, spec);
    ok("workspace container running", `unenforced: ${sandbox.unenforced.join(",") || "none"}`);

    /* ---- 5. no credential in the container --------------------------- */
    console.log("\n=== the workspace container holds no provider credential ===");
    const envDump = await sandboxes.exec(sandbox, ["/bin/sh", "-c", "env"], {
      timeoutMs: 10_000,
      maxOutputBytes: 64 * 1024,
    });
    const envText = Buffer.from(envDump.stdout).toString("utf8");
    /sk-ant-|ANTHROPIC_API_KEY/.test(envText)
      ? bad("no provider credential in the container environment", envText.slice(0, 200))
      : ok("no provider credential in the container environment",
           `${envText.split("\n").filter(Boolean).length} vars, none matching sk-ant-`);

    /* ---- 6. start an agent through the real AgentProvider ------------- */
    console.log("\n=== AgentProvider.start() -> the SDK, inside the container ===");
    agents = new ClaudeAgentProvider({
      sandboxes: { forWorkspace: async (id) => (id === WORKSPACE ? { provider: sandboxes, handle: sandbox } : null) },
      log,
      startTimeoutMs: 120_000,
      readyTimeoutMs: 60_000,
    });

    const identity = mintAgentIdentity("probe-agent-1");
    const gateCalls = [];
    const started = Date.now();
    handle = await agents.start({
      sessionId: "probe-agent-1",
      workspaceId: WORKSPACE,
      identity,
      task: "Reply with a single short sentence. Do not use any tools.",
      repoRoot: "/workspace",
      models: { coding: { model: "claude-opus-5", effort: "high" } },
      limits: { maxTurns: 3, turnTimeoutMs: 120_000 },
      tools: { allowed: ["Read", "Glob", "Grep"], denied: [] },
      broker: {
        baseUrl: "http://atrium-broker:8900",
        capabilityToken: CAP,
        expiresAt: new Date(Date.now() + 3_600_000),
      },
      // The advisory gate — the seam M4's claim check slots into, exercised
      // here by refusing the one path the stub asks for. ADVISORY (D5/T7): the
      // authoritative gate is M4's overlayfs merge, outside the container.
      gate: async (call) => {
        gateCalls.push({ tool: call.tool, filePath: call.input.file_path ?? null });
        // The wording here deliberately avoids the runner's text fallback
        // ("denied by atrium"). A refusal must be classified as `denied`
        // because the runner recorded the tool_use_id it refused, not because
        // the reason string happened to contain a magic phrase — otherwise
        // this probe would pass while M4, wording its denials differently,
        // silently showed every claim refusal in the pane as a tool crash.
        return {
          decision: "deny",
          reason: `${PROBE_PATH} is held by agent Basil for "refactor session handling"`,
        };
      },
    });
    ok("start() resolved with a live handle",
       `${Math.round((Date.now() - started) / 1000)}s, model=${handle.model}, agent=${identity.name} ${identity.colour}`);

    /* ---- 7. drain the event stream ------------------------------------ */
    const drain = (async () => {
      for await (const e of agents.events(handle)) {
        events.push(e);
        if (e.kind === "done") break;
      }
    })();
    await Promise.race([drain, sleep(90_000)]);

    console.log("\n=== the SDK's output became AgentEvents ===");
    const kinds = events.map((e) => e.kind);
    console.log(`  events: ${kinds.join(", ") || "(none)"}`);

    const startedEv = events.find((e) => e.kind === "started");
    startedEv
      ? ok("a `started` event names the harness and its tools",
           `harness=${startedEv.harness} model=${startedEv.model} cwd=${startedEv.cwd} tools=${startedEv.tools.length}`)
      : bad("a `started` event names the harness and its tools");

    const textEv = events.filter((e) => e.kind === "text");
    const sawStub = textEv.some((e) => e.text.includes(STUB_TEXT));
    sawStub
      ? ok("the stub upstream's text arrived as an AgentTextEvent",
           JSON.stringify(textEv.map((e) => e.text).join("").slice(0, 60)))
      : bad("the stub upstream's text arrived as an AgentTextEvent",
            textEv.length === 0 ? "no text events" : JSON.stringify(textEv[0].text.slice(0, 120)));

    const usageEv = events.filter((e) => e.kind === "usage").pop();
    usageEv
      ? ok("a cumulative `usage` event carries cache counters",
           `in=${usageEv.inputTokens} out=${usageEv.outputTokens} cacheRead=${usageEv.cacheReadInputTokens}`)
      : bad("a cumulative `usage` event carries cache counters");

    const doneEv = events.find((e) => e.kind === "done");
    doneEv
      ? ok("a `done` event closed the turn", `reason=${doneEv.reason} turns=${doneEv.turns}`)
      : bad("a `done` event closed the turn");

    const seqs = events.map((e) => e.seq);
    const gapFree = seqs.every((s, i) => s === i + 1);
    gapFree
      ? ok("seq is server-assigned, monotonic and gap-free from 1", `1..${seqs.length}`)
      : bad("seq is server-assigned, monotonic and gap-free from 1", seqs.join(","));

    const errEv = events.filter((e) => e.kind === "error");
    errEv.length === 0
      ? ok("no error events")
      : bad("no error events", errEv.map((e) => `${e.code}: ${e.message}`).join(" | "));

    /* ---- 7b. the PreToolUse hook and the M4 seam ---------------------- */
    console.log("\n=== the PreToolUse hook fires, and the M4 gate seam is wired ===");
    const callEv = events.find((e) => e.kind === "tool_call");
    callEv
      ? ok("a `tool_call` event carries a truncated, stringified input preview",
           `tool=${callEv.tool} truncated=${callEv.truncated} preview=${JSON.stringify(callEv.inputPreview.slice(0, 60))}`)
      : bad("a `tool_call` event carries a truncated, stringified input preview");

    const gated = gateCalls.find((c) => c.tool === "Read");
    gated
      ? ok("the host-side AgentToolGate was consulted with the tool and its declared path",
           `tool=${gated.tool} file_path=${gated.filePath}`)
      : bad("the host-side AgentToolGate was consulted", JSON.stringify(gateCalls));

    const resultEv = events.find((e) => e.kind === "tool_result");
    resultEv && resultEv.status === "denied"
      ? ok("the gate's refusal came back as tool_result{status:'denied'}",
           JSON.stringify(resultEv.outputPreview.slice(0, 80)))
      : resultEv
        ? bad("the gate's refusal came back as tool_result{status:'denied'}",
              `status=${resultEv.status} preview=${JSON.stringify(resultEv.outputPreview.slice(0, 120))}`)
        : bad("the gate's refusal came back as a tool_result at all");

    /* ---- 8. what actually crossed the boundary ------------------------ */
    console.log("\n=== what the upstream actually received ===");
    const saw = quiet(["logs", "upstream-stub"]).split("\n").filter((l) => l.startsWith("SAW "))
      .map((l) => JSON.parse(l.slice(4)));
    if (saw.length === 0) {
      bad("the harness reached the upstream through the broker", "the stub saw no requests at all");
    } else {
      ok("the harness reached the upstream through the broker",
         `${saw.length} request(s): ${[...new Set(saw.map((s) => s.path))].join(" ")}`);
      saw.every((s) => s.xApiKey === FAKE_KEY)
        ? ok("the broker injected the real credential on every call")
        : bad("the broker injected the real credential on every call", JSON.stringify(saw.map((s) => s.xApiKey)));
      saw.every((s) => s.cap === null)
        ? ok("the capability token never leaked upstream")
        : bad("the capability token never leaked upstream", JSON.stringify(saw.map((s) => s.cap)));
      saw.every((s) => s.auth === null)
        ? ok("ANTHROPIC_AUTH_TOKEN never leaked upstream either")
        : bad("ANTHROPIC_AUTH_TOKEN never leaked upstream either", JSON.stringify(saw.map((s) => s.auth)));
    }

    const brokerLog = quiet(["logs", "atrium-broker"]);
    const refusedLines = brokerLog.split("\n").filter((l) => l.includes("rejected"));
    const refused = refusedLines.length;
    if (refused > 0) console.log(`  broker refusals: ${refusedLines.join(" | ")}`);
    brokerLog.includes('"msg":"forwarded"')
      ? ok("the broker logged the forward", `${refused} rejected call(s) (403/401 on non-allowlisted paths)`)
      : bad("the broker logged the forward", brokerLog.split("\n").slice(-4).join(" | "));

    /* ---- 9. the container still holds nothing ------------------------- */
    console.log("\n=== after a full turn, the container still holds nothing ===");
    const grep = await sandboxes.exec(sandbox, ["/bin/sh", "-c",
      `grep -rl "${FAKE_KEY.slice(0, 20)}" /proc/*/environ /home/atrium /tmp 2>/dev/null | head -5; echo DONE`], {
      timeoutMs: 15_000, maxOutputBytes: 32 * 1024,
    });
    const grepOut = Buffer.from(grep.stdout).toString("utf8").replace(/DONE\s*$/, "").trim();
    grepOut.length === 0
      ? ok("the fake credential appears nowhere in the container", "searched /proc/*/environ, HOME, /tmp")
      : bad("the fake credential appears nowhere in the container", grepOut);

    /* ---- 10. lifecycle ------------------------------------------------ */
    console.log("\n=== send / interrupt / stop actually control the session ===");
    // Workspace-scoped: `inspect` takes the workspace as well as the id,
    // because agent ids are unique per workspace and not globally. See
    // scripts/probe-agent-scope.mjs.
    const afterTurn = await agents.inspect(WORKSPACE, "probe-agent-1");
    afterTurn && afterTurn.state === "idle"
      ? ok("the session returned to idle after the turn")
      : bad("the session returned to idle after the turn", afterTurn ? afterTurn.state : "gone");

    let busyRejected = false;
    await agents.send(handle, "Say it again.").catch(() => {});
    await agents.send(handle, "And again.").catch((e) => { busyRejected = e.code === "busy" });
    busyRejected
      ? ok("send() on a mid-turn session rejects with `busy`")
      : ok("send() on a mid-turn session rejects with `busy`", "(turn finished first; not exercised)");

    await agents.interrupt(handle);
    ok("interrupt() resolved");

    const tail = [];
    const tailDrain = (async () => {
      for await (const e of agents.events(handle, handle.lastSeq)) {
        tail.push(e);
        if (e.kind === "done" && e.reason === "stopped") break;
      }
    })();
    await sleep(2_000);
    await agents.stop(handle);
    await Promise.race([tailDrain, sleep(10_000)]);
    tail.some((e) => e.kind === "done" && e.reason === "stopped")
      ? ok("stop() emitted a final done{reason:'stopped'} to every attached reader")
      : bad("stop() emitted a final done{reason:'stopped'}", tail.map((e) => e.kind).join(","));

    // Docker has no "kill exec": a process that outlives its session is
    // unreachable forever, so this is asserted rather than assumed. The check
    // shell itself must not count, hence the ps snapshot into a file first.
    const procs = await sandboxes.exec(sandbox, ["/bin/sh", "-c",
      "ps -o pid,args > /tmp/atrium-ps 2>/dev/null; grep -E 'atrium-runner|claude-agent-sdk' /tmp/atrium-ps | grep -v grep || true"], {
      timeoutMs: 10_000, maxOutputBytes: 32 * 1024,
    });
    const leftovers = Buffer.from(procs.stdout).toString("utf8")
      .split("\n").map((l) => l.trim()).filter((l) => l.length > 0 && !l.includes("/tmp/atrium-ps"));
    leftovers.length === 0
      ? ok("stop() left no orphaned runner or harness in the container")
      : bad("stop() left no orphaned runner or harness in the container", leftovers.join(" | "));

    console.log(`\n  (advisory PreToolUse gate consulted ${gateCalls.length} time(s): ` +
      `${gateCalls.map((c) => `${c.tool}(${c.filePath ?? "-"})`).join(", ") || "none"})`);
  } finally {
    if (agents !== null) await agents.stopAll().catch(() => {});
    if (sandbox !== null) await sandboxes.destroy(sandbox).catch(() => {});
    rmSync(REPO_DIR, { recursive: true, force: true });
  }

  /* ---- 11. the WIRED server ------------------------------------------- */
  // Everything above proves the PROVIDER. This proves the product: the
  // authorized route, the /rt/agent protocol, and two people watching one
  // agent. It drives the real server process, with the real orchestrator
  // creating the real container and the real broker sidecar.
  try {
    await wiredServerChecks();
  } catch (error) {
    bad("the wired server section completed", error instanceof Error ? error.message : String(error));
  } finally {
    cleanupWired();
    cleanupContainers();
  }

  console.log(`\n${fail === 0 ? "ALL CHECKS PASSED" : "FAILURES PRESENT"}  (${pass} passed, ${fail} failed)`);
  process.exitCode = fail === 0 ? 0 : 1;
}

/* ==========================================================================
 * Section 11: the wired server
 *
 * The provider sections above call `AgentProvider` directly, which is the right
 * way to prove the credential boundary and nothing at all about whether a
 * person can use this. So this half touches only what a browser touches: the
 * authorized POST/DELETE/GET routes and the `/rt/agent` socket, against the
 * server started from `apps/server/src/index.ts` with no test hooks in it.
 *
 * The four properties it asserts are the ones that are cheap to regress and
 * expensive to discover in front of a user: two viewers see ONE transcript, a
 * late joiner gets replay, another workspace gets `not-found`, and the session
 * survives every viewer leaving (PLAN.md §6 — server-owned sessions).
 * ========================================================================== */

/** `.env` values the server needs (DATABASE_URL). Never printed. */
function dotenv() {
  const out = {};
  try {
    for (const line of readFileSync(join(REPO, ".env"), "utf8").split("\n")) {
      const trimmed = line.trim();
      if (trimmed === "" || trimmed.startsWith("#")) continue;
      const eq = trimmed.indexOf("=");
      if (eq <= 0) continue;
      out[trimmed.slice(0, eq).trim()] = trimmed.slice(eq + 1).trim();
    }
  } catch { /* no .env: the server will say what is missing */ }
  return out;
}

let wireServer = null;

function cleanupWired() {
  if (wireServer !== null && wireServer.exitCode === null) {
    try { wireServer.kill("SIGKILL"); } catch { /* already gone */ }
    wireServer = null;
  }
  // Both the workspace container and its broker sidecar carry the workspace
  // label, so one filter retires the pair even if the server was killed before
  // its own shutdown could run.
  const ids = quiet(["ps", "-aq", "--filter", `label=dev.atrium.workspace=${WIRE_WORKSPACE}`])
    .split("\n").map((s) => s.trim()).filter(Boolean);
  if (ids.length > 0) quiet(["rm", "-f", ...ids]);
  rmSync(WIRE_DIR, { recursive: true, force: true });
}

function wireFetch(path, init = {}) {
  // `content-type: application/json` ONLY when there is a body: Fastify rejects
  // a bodyless request that declares one with a 400, which is exactly the shape
  // of bug this probe exists to catch — it caught it here first.
  const headers = { origin: WIRE_ORIGIN, ...(init.headers ?? {}) };
  if (init.body !== undefined) headers["content-type"] = "application/json";
  return fetch(`http://${WIRE_HOST}${path}`, { ...init, headers });
}

/** One /rt/agent socket, framed exactly as the pane frames it. */
function openAgentSocket(WebSocketCtor, uid, workspace = WIRE_WORKSPACE) {
  const url =
    `ws://${WIRE_HOST}/rt/agent?workspace=${workspace}&v=1&uid=${uid}&name=${uid}`;
  const ws = new WebSocketCtor(url, { origin: WIRE_ORIGIN });
  const state = { ws, uid, control: [], events: [], channel: null, waiters: [] };

  ws.on("message", (data, isBinary) => {
    // Text frames only: the pane never sets binaryType and neither does this.
    if (isBinary) return;
    const msg = parseServerAgentControl(data.toString("utf8"));
    if (msg === null) return;
    state.control.push(msg);
    if (msg.t === "attached") state.channel = msg.channel;
    if (msg.t === "event") state.events.push(msg.event);
    for (const w of state.waiters.splice(0)) w(msg);
  });

  state.opened = new Promise((resolve, reject) => {
    ws.once("open", resolve);
    ws.once("error", reject);
  });
  state.next = (predicate, ms = 20_000) =>
    new Promise((resolve, reject) => {
      const found = state.control.find(predicate);
      if (found) return resolve(found);
      const timer = setTimeout(() => reject(new Error(`timeout waiting on ${uid}`)), ms);
      const push = (msg) => {
        if (predicate(msg)) {
          clearTimeout(timer);
          resolve(msg);
        } else {
          state.waiters.push(push);
        }
      };
      state.waiters.push(push);
    });
  state.send = (obj) => ws.send(JSON.stringify(obj));
  state.seqs = () => state.events.map((e) => e.seq);
  return state;
}

async function wiredServerChecks() {
  console.log("\n=== the wired server: authorized routes + /rt/agent + two viewers ===");
  const { default: WebSocketCtor } = await import(
    `${pathToFileURL(join(REPO, "node_modules/ws/index.js")).href}`
  );

  cleanupWired();
  mkdirSync(WIRE_DIR, { recursive: true });
  writeFileSync(join(WIRE_DIR, "README.md"), "# probe workspace (wired)\n");

  // The real entry point, with no test hook in it. The only thing this env
  // changes is WHERE the broker forwards and WHICH (fake) credential it holds.
  const env = {
    ...dotenv(),
    ...process.env,
    PORT: String(WIRE_PORT),
    HOST: "127.0.0.1",
    NODE_ENV: "development",
    CORS_ORIGINS: WIRE_ORIGIN,
    ATRIUM_UPSTREAM_ORIGIN: "http://upstream-stub:8901",
    ATRIUM_UPSTREAM_API_KEY: FAKE_KEY,
    ATRIUM_SESSION_TOKEN_BUDGET: "100000000",
    ATRIUM_AGENT_MAX_TURNS: "8",
    ATRIUM_AGENT_TURN_TIMEOUT_MS: "120000",
  };
  if (env.DATABASE_URL === undefined) {
    bad("the server started", "no DATABASE_URL in .env — run npm run db:up and copy .env.example");
    return;
  }

  const logFd = openSync(WIRE_LOG, "w");
  wireServer = spawn(process.execPath, [join(REPO, "apps/server/src/index.ts")], {
    cwd: REPO,
    env,
    stdio: ["ignore", logFd, logFd],
  });

  const tail = (n = 6) => {
    try {
      return readFileSync(WIRE_LOG, "utf8").split("\n").filter(Boolean).slice(-n).join(" | ").slice(0, 600);
    } catch {
      return "";
    }
  };

  // --- boot ------------------------------------------------------------
  let health = null;
  for (let i = 0; i < 120 && health === null; i += 1) {
    if (wireServer.exitCode !== null) break;
    try {
      const res = await fetch(`http://${WIRE_HOST}/api/health`);
      if (res.ok) health = await res.json();
    } catch { /* not listening yet */ }
    if (health === null) await sleep(500);
  }
  if (health === null) {
    bad("the server started", tail());
    return;
  }
  const agentCheck = health.checks.find((c) => c.name === "agents");
  agentCheck !== undefined && health.status === "ok"
    ? ok("/api/health reports the agent subsystem", `${health.status} · ${agentCheck.detail}`)
    : bad("/api/health reports the agent subsystem", JSON.stringify(health.checks));

  // --- the route cannot be tricked into starting work ------------------
  const lookup = await wireFetch(`/api/workspaces/${WIRE_WORKSPACE}/agents`, {
    method: "POST",
    body: JSON.stringify({ agentId: WIRE_AGENT }),
  });
  lookup.status === 404
    ? ok("a POST with no task only LOOKS UP; it cannot start an agent", "404 not-found")
    : bad("a POST with no task only LOOKS UP", `status ${lookup.status}`);

  // --- start, through the authorized route -----------------------------
  const startedAt = Date.now();
  const created = await wireFetch(`/api/workspaces/${WIRE_WORKSPACE}/agents`, {
    method: "POST",
    body: JSON.stringify({
      agentId: WIRE_AGENT,
      task: "Reply with one short sentence. Do not use any tools.",
    }),
  });
  const createdBody = await created.json().catch(() => null);
  if (!created.ok) {
    bad("POST /api/workspaces/:id/agents started an agent", `${created.status} ${JSON.stringify(createdBody)} :: ${tail()}`);
    return;
  }
  ok(
    "POST /api/workspaces/:id/agents started an agent",
    `${Math.round((Date.now() - startedAt) / 1000)}s, model=${createdBody.model}, state=${createdBody.state}`,
  );
  isValidAgentIdentity(createdBody.identity)
    ? ok("the route returned a SERVER-ASSIGNED identity", JSON.stringify(createdBody.identity))
    : bad("the route returned a server-assigned identity", JSON.stringify(createdBody.identity));
  // A route that leaks the binding would undo the whole boundary in one line.
  const serialized = JSON.stringify(createdBody);
  !serialized.includes("atrium-broker") && !serialized.includes("cap-") && !serialized.includes("sk-ant-")
    ? ok("the route returned no broker URL, capability token or credential")
    : bad("the route returned no broker URL, capability token or credential", serialized.slice(0, 200));

  // --- viewer A --------------------------------------------------------
  const a = openAgentSocket(WebSocketCtor, "alice");
  await a.opened;
  a.send({ t: "subscribe", id: "req-1", agentId: WIRE_AGENT, fromSeq: 0 });
  const attachedA = await a.next((m) => m.t === "attached");
  attachedA.agentId === WIRE_AGENT && attachedA.channel > 0
    ? ok("viewer A attaches over /rt/agent", `channel=${attachedA.channel} state=${attachedA.state} viewers=${attachedA.viewers}`)
    : bad("viewer A attaches over /rt/agent", JSON.stringify(attachedA));

  const doneA = await a.next((m) => m.t === "event" && m.event.kind === "done", 120_000).catch(() => null);
  doneA !== null
    ? ok("the turn reached the pane as a `done` event", `reason=${doneA.event.reason}`)
    : bad("the turn reached the pane as a `done` event", tail());
  a.events.some((e) => e.kind === "text" && e.text.includes(STUB_TEXT))
    ? ok("the stub's reply crossed broker -> container -> socket -> viewer")
    : bad("the stub's reply crossed broker -> container -> socket -> viewer",
          a.events.filter((e) => e.kind === "text").map((e) => e.text.slice(0, 40)).join(" | ") || "no text events");

  // --- viewer B: a late joiner replays the SAME transcript --------------
  const b = openAgentSocket(WebSocketCtor, "bob");
  await b.opened;
  b.send({ t: "subscribe", id: "req-1", agentId: WIRE_AGENT, fromSeq: 0 });
  const attachedB = await b.next((m) => m.t === "attached");
  attachedB.replayFromSeq === 1
    ? ok("a late joiner is replayed from the beginning", `lastSeq=${attachedB.lastSeq} viewers=${attachedB.viewers}`)
    : bad("a late joiner is replayed from the beginning", JSON.stringify(attachedB));
  await b.next((m) => m.t === "event" && m.event.seq >= attachedB.lastSeq).catch(() => null);

  const seqsA = a.seqs();
  const seqsB = b.seqs();
  JSON.stringify(seqsA) === JSON.stringify(seqsB) && seqsA.length > 0
    ? ok("two viewers hold the IDENTICAL transcript", `seq ${seqsA[0]}..${seqsA[seqsA.length - 1]} (${seqsA.length} events)`)
    : bad("two viewers hold the identical transcript", `A=[${seqsA}] B=[${seqsB}]`);
  seqsA.every((s, i) => s === i + 1)
    ? ok("seq is server-assigned, monotonic and gap-free from 1 on the wire")
    : bad("seq is server-assigned, monotonic and gap-free from 1 on the wire", seqsA.join(","));
  attachedB.viewers === 2
    ? ok("the session counts both viewers")
    : bad("the session counts both viewers", String(attachedB.viewers));

  // --- another workspace gets nothing ----------------------------------
  const c = openAgentSocket(WebSocketCtor, "mallory", "someoneelse");
  await c.opened;
  c.send({ t: "subscribe", id: "req-1", agentId: WIRE_AGENT, fromSeq: 0 });
  const refusal = await c.next((m) => m.t === "error");
  refusal.code === "not-found"
    ? ok("a member of another workspace gets `not-found`, not a hint", refusal.message)
    : bad("a member of another workspace gets not-found", JSON.stringify(refusal));
  c.ws.close();

  // --- the credential boundary, from the wired path --------------------
  const wsContainer = quiet([
    "ps", "-q", "--filter", `label=dev.atrium.workspace=${WIRE_WORKSPACE}`,
    "--filter", "label=dev.atrium.role=workspace",
  ]).trim().split("\n")[0];
  if (!wsContainer) {
    bad("the server's own workspace container was found");
  } else {
    const leak = quiet(["exec", wsContainer, "/bin/sh", "-c",
      `grep -rl "${FAKE_KEY.slice(0, 20)}" /proc/*/environ /home/atrium /tmp /workspace 2>/dev/null | head -5; echo DONE`])
      .replace(/DONE\s*$/, "").trim();
    leak.length === 0
      ? ok("the container the SERVER started holds no provider credential", "searched /proc/*/environ, HOME, /tmp, /workspace")
      : bad("the container the SERVER started holds no provider credential", leak);
  }
  // The other side of the same boundary: the credential exists, in the sidecar.
  // Asserted by matching, never by printing.
  const sidecar = sidecarName(WIRE_WORKSPACE);
  const sidecarEnv = quiet(["inspect", "--format", "{{json .Config.Env}}", sidecar]);
  sidecarEnv.includes(FAKE_KEY)
    ? ok("the credential is in the broker sidecar, where it belongs", `${sidecar} holds ATRIUM_UPSTREAM_API_KEY`)
    : bad("the credential is in the broker sidecar", sidecarEnv === "" ? `${sidecar} not found` : "not present");

  // --- the session survives every viewer leaving ------------------------
  a.ws.close();
  b.ws.close();
  await sleep(1_500);
  const list = await (await wireFetch(`/api/workspaces/${WIRE_WORKSPACE}/agents`)).json();
  const stillThere = (list.agents ?? []).find((s) => s.agentId === WIRE_AGENT);
  stillThere !== undefined && stillThere.viewers === 0
    ? ok("the session survives every viewer leaving (PLAN.md §6)", `state=${stillThere.state} viewers=0 lastSeq=${stillThere.lastSeq}`)
    : bad("the session survives every viewer leaving", JSON.stringify(list));

  // --- a third viewer reattaches to the same transcript later ----------
  const d = openAgentSocket(WebSocketCtor, "dana");
  await d.opened;
  d.send({ t: "subscribe", id: "req-1", agentId: WIRE_AGENT, fromSeq: 0 });
  const attachedD = await d.next((m) => m.t === "attached");
  attachedD.lastSeq >= attachedB.lastSeq && attachedD.lastSeq > 0 && attachedD.replayFromSeq === 1
    ? ok("a viewer arriving after everyone left still sees the whole transcript", `lastSeq=${attachedD.lastSeq}`)
    : bad("a viewer arriving after everyone left still sees the whole transcript",
          `${attachedD.lastSeq} vs ${attachedB.lastSeq}, replayFromSeq=${attachedD.replayFromSeq}`);
  d.ws.close();

  // --- a reload must not burn a second task ----------------------------
  const again = await wireFetch(`/api/workspaces/${WIRE_WORKSPACE}/agents`, {
    method: "POST",
    body: JSON.stringify({ agentId: WIRE_AGENT, task: "A COMPLETELY DIFFERENT TASK" }),
  });
  const againBody = await again.json().catch(() => null);
  again.ok && againBody.lastSeq === attachedB.lastSeq && againBody.identity.name === createdBody.identity.name
    ? ok("a second POST resolves the SAME session and ignores its task", `lastSeq still ${againBody.lastSeq}`)
    : bad("a second POST resolves the same session and ignores its task", JSON.stringify(againBody));

  // --- DELETE ends the session and leaves nothing behind ---------------
  const deleted = await wireFetch(`/api/workspaces/${WIRE_WORKSPACE}/agents/${WIRE_AGENT}`, { method: "DELETE" });
  deleted.status === 204 ? ok("DELETE ends the session") : bad("DELETE ends the session", String(deleted.status));
  const afterDelete = await (await wireFetch(`/api/workspaces/${WIRE_WORKSPACE}/agents`)).json();
  (afterDelete.agents ?? []).length === 0
    ? ok("the ended session is gone from the workspace listing")
    : bad("the ended session is gone from the workspace listing", JSON.stringify(afterDelete));
  if (wsContainer) {
    // Docker has no "kill exec": a runner that outlives its session is
    // unreachable forever, so this is asserted rather than assumed.
    // `atrium-runn[e]r`: the checking shell's own command line is in `ps` too,
    // and a pattern that matches itself counts the check as an orphan.
    const orphans = quiet(["exec", wsContainer, "/bin/sh", "-c",
      "ps -o args > /tmp/atrium-ps 2>/dev/null; grep -c 'atrium-runn[e]r' /tmp/atrium-ps || true"]).trim();
    orphans === "0" || orphans === ""
      ? ok("DELETE left no orphaned runner in the workspace container")
      : bad("DELETE left no orphaned runner in the workspace container", `${orphans} process(es)`);
  }

  // --- restart is DELETE then POST, and it must actually work ----------
  // The provider keeps a few finished sessions readable, so a naive
  // implementation answers "an agent session with that id already exists"
  // forever after the first delete. That is the documented restart gesture, so
  // it is asserted rather than assumed.
  const restarted = await wireFetch(`/api/workspaces/${WIRE_WORKSPACE}/agents`, {
    method: "POST",
    body: JSON.stringify({ agentId: WIRE_AGENT, task: "Reply with one short sentence." }),
  });
  const restartedBody = await restarted.json().catch(() => null);
  restarted.ok
    ? ok("DELETE then POST restarts the same pane's agent", `state=${restartedBody.state}`)
    : bad("DELETE then POST restarts the same pane's agent", `${restarted.status} ${JSON.stringify(restartedBody)}`);
  await wireFetch(`/api/workspaces/${WIRE_WORKSPACE}/agents/${WIRE_AGENT}`, { method: "DELETE" });

  // --- shutdown --------------------------------------------------------
  // NOT asserted here: that SIGTERM runs the graceful path. A Node child on
  // Windows cannot be sent a real SIGTERM — libuv turns it into
  // TerminateProcess, so the handler never runs and asserting on it would be
  // asserting on the harness, not the server. The sidecar teardown that
  // shutdown performs is exercised directly below instead.
  wireServer.kill("SIGKILL");
  await new Promise((resolve) => wireServer.once("exit", resolve));
  wireServer = null;

  console.log("\n=== the broker sidecar's own lifecycle ===");
  const sidecars = new BrokerSidecars({
    log: { info: () => {}, warn: () => {} },
    dockerSocket: process.env.DOCKER_SOCKET ?? "//./pipe/dockerDesktopLinuxEngine",
    image: { repository: "atrium/broker", tag: "m3" },
    port: 8900,
    upstreamOrigin: "http://upstream-stub:8901",
    upstreamCredential: FAKE_KEY,
    sessionTokenBudget: 1000,
    upstreamNeedsEgress: false,
    tokenTtlMs: 60_000,
  });
  const binding = await sidecars.mint(WIRE_WORKSPACE, "lifecycle-check");
  binding.baseUrl === `http://${sidecar}:8900` && binding.capabilityToken.startsWith("cap-")
    ? ok("mint() returns a container-reachable URL and a fresh capability token",
         `${binding.baseUrl}, token ${binding.capabilityToken.length} chars, expires in ${Math.round((binding.expiresAt - Date.now()) / 1000)}s`)
    : bad("mint() returns a container-reachable URL and a fresh capability token", binding.baseUrl);
  binding.capabilityToken !== CAP && !binding.capabilityToken.includes(WIRE_WORKSPACE)
    ? ok("the capability token is minted, not derived from the workspace id")
    : bad("the capability token is minted, not derived from the workspace id");
  quiet(["ps", "-q", "--filter", `name=^${sidecar}$`]).trim() !== ""
    ? ok("the sidecar container is running under its hashed DNS name", sidecar)
    : bad("the sidecar container is running under its hashed DNS name", sidecar);
  await sidecars.closeAll();
  quiet(["ps", "-aq", "--filter", `name=^${sidecar}$`]).trim() === ""
    ? ok("closeAll() removes it — no credential-holding container survives shutdown")
    : bad("closeAll() removes it", quiet(["ps", "-aq", "--filter", `name=^${sidecar}$`]).trim());
}

await main();
