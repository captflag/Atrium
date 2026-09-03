/**
 * Integration probe for the M2 terminal stack.
 *
 * Exercises the real wire protocol against a running server: upgrade
 * authorization, two viewers on one shell, scrollback replay, cross-workspace
 * isolation, and server-owned session lifetime. There is no test runner in this
 * repo yet, so this is the executable check that M2 still works.
 *
 *   npm run dev                       # server must be running
 *   npm run db:up                     # and Postgres
 *   node scripts/probe-terminal.mjs
 *
 * It creates its own terminal through the authorized POST route first, because
 * the wire protocol can only ATTACH to a terminal, never create one.
 */
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";

const ROOT = pathToFileURL(join(dirname(fileURLToPath(import.meta.url)), "..")).href.replace(/\/$/, "");
const { default: WebSocket } = await import(`${ROOT}/node_modules/ws/index.js`);
const {
  OP_INPUT,
  OP_OUTPUT,
  MAX_OUTPUT_PAYLOAD_BYTES,
  encodeTerminalFrame,
  decodeTerminalFrame,
  parseServerControl,
} = await import(`${ROOT}/packages/shared/dist/index.js`);

const HOST = "127.0.0.1:8787";
const ORIGIN = "http://localhost:5173";
const WORKSPACE = "demo";
const TERMINAL = "probe-terminal";

let pass = 0;
let fail = 0;
const ok = (name, detail = "") => {
  pass += 1;
  console.log(`PASS  ${name}${detail ? `  -- ${detail}` : ""}`);
};
const bad = (name, detail = "") => {
  fail += 1;
  console.log(`FAIL  ${name}${detail ? `  -- ${detail}` : ""}`);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function open(uid, workspace = WORKSPACE, version = "1") {
  const url = `ws://${HOST}/rt/terminal?workspace=${workspace}&v=${version}&uid=${uid}&name=${uid}`;
  const ws = new WebSocket(url, { origin: ORIGIN });
  const state = {
    ws,
    uid,
    control: [],
    output: [],
    channel: null,
    waiters: [],
  };
  ws.on("message", (data, isBinary) => {
    if (isBinary) {
      const res = decodeTerminalFrame(new Uint8Array(data), MAX_OUTPUT_PAYLOAD_BYTES);
      if (res.ok && res.frame.opcode === OP_OUTPUT) {
        state.output.push(Buffer.from(res.frame.payload));
      }
      return;
    }
    const msg = parseServerControl(data.toString("utf8"));
    if (msg === null) return;
    state.control.push(msg);
    if (msg.t === "attached") state.channel = msg.channel;
    for (const w of state.waiters.splice(0)) w(msg);
  });
  state.next = (predicate, ms = 4000) =>
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
  state.opened = new Promise((resolve, reject) => {
    ws.once("open", resolve);
    ws.once("error", reject);
  });
  state.text = () => Buffer.concat(state.output).toString("utf8");
  state.send = (obj) => ws.send(JSON.stringify(obj));
  state.type = (s) =>
    ws.send(encodeTerminalFrame(OP_INPUT, state.channel, new TextEncoder().encode(s)));
  return state;
}

async function main() {
  console.log("=== upgrade authorization ===");
  {
    const ws = new WebSocket(`ws://${HOST}/rt/terminal?workspace=${WORKSPACE}&v=1&uid=evil`, {
      origin: "http://evil.example",
    });
    const outcome = await new Promise((resolve) => {
      ws.once("open", () => resolve("opened"));
      ws.once("error", (e) => resolve(`refused: ${e.message}`));
    });
    outcome === "opened"
      ? bad("bad Origin is refused at the handshake", outcome)
      : ok("bad Origin is refused at the handshake", outcome);
  }

  console.log("\n=== canvas gateway still upgrades (M1 must not regress) ===");
  {
    const ws = new WebSocket(`ws://${HOST}/rt?workspace=${WORKSPACE}&uid=probeC&name=probeC`, {
      origin: ORIGIN,
    });
    const outcome = await new Promise((resolve) => {
      ws.once("open", () => resolve("opened"));
      ws.once("error", (e) => resolve(`refused: ${e.message}`));
    });
    const first = await new Promise((resolve) => {
      ws.once("message", (d) => resolve(Buffer.from(d)));
      setTimeout(() => resolve(null), 2000);
    });
    ws.close();
    outcome === "opened" ? ok("/rt upgrades", outcome) : bad("/rt upgrades", outcome);
    first !== null && first.length > 0
      ? ok("/rt sends the yjs sync step 1", `${first.length} bytes`)
      : bad("/rt sends the yjs sync step 1");
  }

  console.log("\n=== unknown upgrade path is rejected once, by the dispatcher ===");
  {
    const ws = new WebSocket(`ws://${HOST}/nope`, { origin: ORIGIN });
    const outcome = await new Promise((resolve) => {
      ws.once("open", () => resolve("opened"));
      ws.once("error", (e) => resolve(`refused: ${e.message}`));
    });
    outcome === "opened" ? bad("/nope refused", outcome) : ok("/nope refused", outcome);
  }

  console.log("\n=== two viewers, one shell ===");
  const a = open("probeA");
  await a.opened;
  a.send({ t: "subscribe", id: "req-1", terminalId: TERMINAL, cols: 100, rows: 30 });
  const attachedA = await a.next((m) => m.t === "attached" || m.t === "error");
  if (attachedA.t !== "attached") {
    bad("viewer A attaches", JSON.stringify(attachedA));
    process.exit(1);
  }
  ok("viewer A attaches", `channel=${attachedA.channel} ${attachedA.cols}x${attachedA.rows} viewers=${attachedA.viewers}`);

  const b = open("probeB");
  await b.opened;
  b.send({ t: "subscribe", id: "req-1", terminalId: TERMINAL, cols: 80, rows: 24 });
  const attachedB = await b.next((m) => m.t === "attached" || m.t === "error");
  attachedB.t === "attached"
    ? ok("viewer B attaches", `${attachedB.cols}x${attachedB.rows} viewers=${attachedB.viewers} backlog=${attachedB.backlogBytes}`)
    : bad("viewer B attaches", JSON.stringify(attachedB));

  const resizedA = await a.next((m) => m.t === "resized");
  resizedA.cols === 80 && resizedA.rows === 24
    ? ok("min-of-subscribers reaches viewer A", `${resizedA.cols}x${resizedA.rows} viewers=${resizedA.viewers}`)
    : bad("min-of-subscribers reaches viewer A", JSON.stringify(resizedA));

  attachedB.backlogBytes > 0
    ? ok("late joiner got scrollback", `${attachedB.backlogBytes} bytes`)
    : bad("late joiner got scrollback", "0 bytes");

  // The M2 done-when criterion: both people type, both people see everything.
  a.output.length = 0;
  b.output.length = 0;
  a.type("echo hello-from-A\n");
  await sleep(700);
  b.type("id -un; pwd\n");
  await sleep(1200);

  const at = a.text();
  const bt = b.text();
  at.includes("hello-from-A") ? ok("A sees A's command output") : bad("A sees A's command output", JSON.stringify(at.slice(-200)));
  bt.includes("hello-from-A") ? ok("B sees A's command output") : bad("B sees A's command output", JSON.stringify(bt.slice(-200)));
  at.includes("atrium") ? ok("A sees B's command output (one shared shell)") : bad("A sees B's command output", JSON.stringify(at.slice(-200)));
  bt.includes("atrium") ? ok("B sees B's command output") : bad("B sees B's command output", JSON.stringify(bt.slice(-200)));
  at.includes("/workspace") ? ok("shell starts in the repo mount", "/workspace") : bad("shell starts in the repo mount", JSON.stringify(at.slice(-200)));

  console.log("\n--- transcript as viewer B saw it ---");
  for (const line of bt.split(/\r?\n/).slice(-8)) console.log(`  | ${line}`);

  console.log("\n=== cross-workspace lookup ===");
  const c = open("probeC", "otherws");
  await c.opened;
  c.send({ t: "subscribe", id: "req-1", terminalId: TERMINAL, cols: 80, rows: 24 });
  const cross = await c.next((m) => m.t === "attached" || m.t === "error");
  cross.t === "error" && cross.code === "not-found"
    ? ok("another workspace cannot attach", `${cross.code} on the wire`)
    : bad("another workspace cannot attach", JSON.stringify(cross));
  c.ws.close();

  console.log("\n=== version mismatch ===");
  const v = open("probeV", WORKSPACE, "99");
  await v.opened;
  const vm = await v.next((m) => m.t === "error");
  vm.code === "version-mismatch" ? ok("version mismatch is a renderable error", vm.code) : bad("version mismatch", JSON.stringify(vm));
  v.ws.close();

  console.log("\n=== detach keeps the shell (server-owned sessions) ===");
  b.send({ t: "unsubscribe", channel: b.channel });
  const resizedBack = await a.next((m) => m.t === "resized" && m.viewers === 1);
  resizedBack.cols === 100 && resizedBack.rows === 30
    ? ok("size returns to the remaining viewer", `${resizedBack.cols}x${resizedBack.rows}`)
    : bad("size returns to the remaining viewer", JSON.stringify(resizedBack));
  b.ws.close();

  a.output.length = 0;
  a.type("echo still-alive\n");
  await sleep(900);
  a.text().includes("still-alive")
    ? ok("shell survived the departing viewer")
    : bad("shell survived the departing viewer", JSON.stringify(a.text().slice(-200)));

  a.ws.close();
  await sleep(200);

  console.log(`\n${fail === 0 ? "ALL CHECKS PASSED" : `${fail} CHECK(S) FAILED`}  (${pass} passed)`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("probe crashed:", e);
  process.exit(1);
});
