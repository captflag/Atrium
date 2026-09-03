/**
 * D1 proof: the workspace container never holds a provider credential.
 *
 * SECURITY.md D1 is the highest-severity decision in the design, and it fails
 * silently and OPEN — a base URL that is set but not honoured, or a header that
 * is forwarded when it should be stripped, looks exactly like success. So it is
 * asserted here rather than assumed.
 *
 * Stands up three containers on the `atrium-internal` network and checks what
 * each one can actually see:
 *
 *   workspace container  ->  broker sidecar  ->  upstream stub
 *   (no credential)          (holds the key)     (reports what it received)
 *
 * Uses a FAKE credential, so no real key is needed and none is at risk.
 *
 *   docker build -f docker/broker.Dockerfile -t atrium/broker:m3 .
 *   node scripts/probe-broker.mjs
 */

import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";

const DOCKER = [
  "C:/Users/FUNCELL/AppData/Local/Programs/DockerDesktop/resources/bin/docker.exe",
  "/usr/bin/docker",
  "docker",
].find((p) => p === "docker" || existsSync(p)) ?? "docker";

const NET = "atrium-internal";
const FAKE_KEY = "sk-ant-FAKE-CREDENTIAL-DO-NOT-USE-0123456789";
const CAP = "cap-workspace-probe-0123456789";
const BUDGET = 3000; // stub reports 1540 tokens/call, so call 3 must be refused

let pass = 0;
let fail = 0;
const ok = (n, d = "") => { pass += 1; console.log(`PASS  ${n}${d ? `  -- ${d}` : ""}`) };
const bad = (n, d = "") => { fail += 1; console.log(`FAIL  ${n}${d ? `  -- ${d}` : ""}`) };
const docker = (args, opts = {}) =>
  execFileSync(DOCKER, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], ...opts });
const quiet = (args) => { try { return docker(args) } catch { return "" } };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Runs a snippet of Node inside a throwaway workspace container. */
function inWorkspace(script, env = {}) {
  const args = ["run", "--rm", "--network", NET, "--user", "10001:10001"];
  for (const [k, v] of Object.entries(env)) args.push("-e", `${k}=${v}`);
  args.push("atrium/workspace-base:m2", "node", "-e", script);
  try { return docker(args).trim() } catch (e) { return (e.stdout || e.message || "").trim() }
}

const STUB = `
const {createServer}=require("http");
createServer((req,res)=>{let b="";req.on("data",c=>b+=c);req.on("end",()=>{
  process.stdout.write("SAW "+JSON.stringify({xApiKey:req.headers["x-api-key"]||null,
    cap:req.headers["x-atrium-capability"]||null,path:req.url})+"\\n");
  res.writeHead(200,{"content-type":"application/json"});
  res.end(JSON.stringify({type:"message",usage:{input_tokens:1200,output_tokens:340}}));
})}).listen(8901,"0.0.0.0",()=>process.stdout.write("stub listening\\n"));`;

const CALL = (path, withToken) => `
const r=require("http").request({host:"atrium-broker",port:8900,path:${JSON.stringify(path)},
 method:"POST",headers:{"content-type":"application/json"${withToken ? `,"x-atrium-capability":${JSON.stringify(CAP)}` : ""}}},
 res=>{console.log(res.statusCode);res.resume();res.on("end",()=>process.exit(0))});
r.on("error",e=>{console.log("ERR "+e.code);process.exit(0)});r.end("{}");`;

function cleanup() {
  quiet(["rm", "-f", "upstream-stub", "atrium-broker"]);
}

async function main() {
  cleanup();
  process.on("exit", cleanup);

  quiet(["network", "create", "--internal", NET]);

  docker(["run", "-d", "--name", "upstream-stub", "--network", NET,
    "-e", `STUB=${Buffer.from(STUB).toString("base64")}`,
    "node:22-alpine", "node", "-e",
    'eval(Buffer.from(process.env.STUB,"base64").toString("utf8"))']);

  docker(["run", "-d", "--name", "atrium-broker", "--network", NET,
    "--user", "10002:10002", "--read-only", "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
    "-e", "ATRIUM_UPSTREAM_ORIGIN=http://upstream-stub:8901",
    "-e", `ATRIUM_UPSTREAM_API_KEY=${FAKE_KEY}`,
    "-e", `ATRIUM_CAPABILITY_TOKEN=${CAP}`,
    "-e", `ATRIUM_SESSION_TOKEN_BUDGET=${BUDGET}`,
    "atrium/broker:m3"]);

  await sleep(4000);
  if (!quiet(["logs", "atrium-broker"]).includes("broker listening")) {
    bad("broker started", quiet(["logs", "atrium-broker"]).split("\n").slice(-3).join(" | "));
    return;
  }
  ok("broker started");

  console.log("\n=== the workspace container holds no credential ===");
  const env = inWorkspace(
    'console.log(Object.keys(process.env).filter(k=>/API[_-]?KEY|SECRET|TOKEN/i.test(k)).map(k=>k+"="+process.env[k]).join(",")||"NONE")',
    { ANTHROPIC_BASE_URL: "http://atrium-broker:8900", ANTHROPIC_AUTH_TOKEN: CAP },
  );
  const leakedKey = /sk-ant-|API_KEY=sk/i.test(env);
  leakedKey ? bad("no provider credential in workspace env", env) : ok("no provider credential in workspace env", env);

  console.log("\n=== broker enforces its own gates ===");
  const noTok = inWorkspace(CALL("/v1/messages", false));
  noTok === "401" ? ok("request without capability token is refused") : bad("request without capability token is refused", noTok);

  const badPath = inWorkspace(CALL("/v1/admin/keys", true));
  badPath === "403" ? ok("non-allowlisted path is refused (not an open proxy)") : bad("non-allowlisted path is refused", badPath);

  const good = inWorkspace(CALL("/v1/messages", true));
  good === "200" ? ok("allowlisted path with a valid token is forwarded") : bad("allowlisted path forwarded", good);

  console.log("\n=== what the upstream actually received ===");
  const saw = quiet(["logs", "upstream-stub"]).split("\n").filter((l) => l.startsWith("SAW ")).pop();
  if (!saw) { bad("upstream received the forwarded request"); }
  else {
    const seen = JSON.parse(saw.slice(4));
    seen.xApiKey === FAKE_KEY
      ? ok("broker injected the real credential", "upstream saw x-api-key")
      : bad("broker injected the real credential", String(seen.xApiKey));
    // The capability token is ours. It is scoped and useless upstream, but a
    // credential that leaves its boundary is a leak regardless. This assertion
    // caught exactly that bug on first run.
    seen.cap === null
      ? ok("capability token did NOT leak upstream")
      : bad("capability token did NOT leak upstream", String(seen.cap));
  }

  console.log("\n=== session budget is a stop line, not a postmortem ===");
  const second = inWorkspace(CALL("/v1/messages", true));
  const third = inWorkspace(CALL("/v1/messages", true));
  second === "200" ? ok("second call within budget") : bad("second call within budget", second);
  third === "429" ? ok("call past the budget ceiling is refused") : bad("call past the budget ceiling is refused", third);

  console.log(`\n${fail === 0 ? "ALL CHECKS PASSED" : "FAILURES PRESENT"}  (${pass} passed, ${fail} failed)`);
  process.exitCode = fail === 0 ? 0 : 1;
}

await main();
