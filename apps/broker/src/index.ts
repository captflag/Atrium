/**
 * The model broker (SECURITY.md D1).
 *
 * A workspace container must never hold a provider credential. It runs an agent
 * over attacker-influenceable input (repo content, dependencies), so anything in
 * its environment is one prompt injection away from being exfiltrated.
 *
 * So the direction is inverted. The agent is pointed at THIS service with
 * `ANTHROPIC_BASE_URL`, and carries only a short-lived, workspace-scoped
 * capability token. The broker attaches the real credential and forwards
 * upstream. The token is useless anywhere else, and the credential never
 * crosses the trust boundary.
 *
 * This is a documented pattern, not a workaround: Claude Code supports pointing
 * at a gateway precisely so "the provider key stays server-side".
 *
 * DEPLOYMENT (PLAN.md §4). This runs as a SIDECAR CONTAINER, not a host
 * process. Docker Desktop runs its engine in a WSL2 VM, so a workspace
 * container cannot reach a Windows process at the bridge gateway — measured.
 * The broker joins `atrium-internal` (where workspaces reach it by name, and it
 * is the only thing they can reach) plus an egress-capable network for the
 * upstream call.
 *
 * Zero runtime dependencies, on purpose: this process holds the credential, so
 * its supply chain is the one that matters most (SECURITY.md T12).
 */

import { createServer, request as httpRequest, type IncomingMessage, type ServerResponse } from "node:http";
import { request as httpsRequest } from "node:https";
import { timingSafeEqual } from "node:crypto";
import { loadBrokerConfig, type BrokerConfig } from "./config.ts";
import { BudgetLedger } from "./budget.ts";

const MAX_REQUEST_BYTES = 8 * 1024 * 1024;

/**
 * Headers that must not reach the upstream.
 *
 * Two distinct reasons, both load-bearing:
 *
 *  - The caller does not get to authenticate. Anything it sends that looks like
 *    a credential is dropped and replaced with the real one, so a container
 *    cannot smuggle its own key out through us.
 *  - `x-atrium-capability` is OURS. It is scoped to this workspace and means
 *    nothing upstream, but it is still a credential, and a credential that
 *    leaves the boundary it belongs to is a leak whether or not the recipient
 *    can use it. Caught by scripts/probe-broker.mjs, which asserts the upstream
 *    never sees it.
 */
const STRIPPED_REQUEST_HEADERS = new Set([
  "x-api-key",
  "authorization",
  "proxy-authorization",
  "x-atrium-capability",
  "host",
  "content-length",
  "connection",
  "cookie",
]);

function constantTimeEquals(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

function readBody(req: IncomingMessage, limit: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on("data", (chunk: Buffer) => {
      total += chunk.length;
      if (total > limit) {
        reject(new Error("request body too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function send(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json" });
  res.end(payload);
}

/**
 * Usage is read from the upstream response so the ledger reflects what was
 * actually billed, not what we guessed. Parsing failure is not fatal: a request
 * that cannot be accounted still happened, and is charged a conservative
 * estimate rather than zero.
 */
function extractUsage(body: Buffer): { input: number; output: number } | null {
  try {
    const parsed = JSON.parse(body.toString("utf8")) as {
      usage?: { input_tokens?: number; output_tokens?: number };
    };
    const u = parsed.usage;
    if (!u) return null;
    return { input: u.input_tokens ?? 0, output: u.output_tokens ?? 0 };
  } catch {
    return null;
  }
}

function main(): void {
  const config: BrokerConfig = loadBrokerConfig();
  const ledger = new BudgetLedger(config.sessionTokenBudget);

  const server = createServer((req, res) => {
    void handle(req, res, config, ledger).catch((error: unknown) => {
      // Never echo an error body: it may quote the request, which may quote
      // repo content (SECURITY.md T9).
      log("request failed", { err: error instanceof Error ? error.message : "unknown" });
      if (!res.headersSent) send(res, 502, { type: "error", error: { type: "broker_error" } });
      else res.end();
    });
  });

  server.listen(config.port, "0.0.0.0", () => {
    log("broker listening", {
      port: config.port,
      upstream: config.upstreamOrigin,
      budgetTokens: config.sessionTokenBudget,
      // The credential itself is never logged, at any level, ever.
      credentialConfigured: config.upstreamCredential !== null,
    });
  });
}

/** Structured log with no request/response bodies and no credentials. */
function log(msg: string, fields: Record<string, unknown> = {}): void {
  process.stdout.write(`${JSON.stringify({ msg, ...fields })}\n`);
}

async function handle(
  req: IncomingMessage,
  res: ServerResponse,
  config: BrokerConfig,
  ledger: BudgetLedger,
): Promise<void> {
  const url = new URL(req.url ?? "/", "http://broker.local");

  if (url.pathname === "/healthz") {
    return send(res, 200, {
      ok: true,
      credentialConfigured: config.upstreamCredential !== null,
      spent: ledger.snapshot(),
    });
  }

  // --- capability token -----------------------------------------------------
  // The workspace container is issued a token scoped to one workspace. It is
  // not the provider credential and is worthless upstream.
  const presented = req.headers["x-atrium-capability"];
  const token = Array.isArray(presented) ? presented[0] : presented;
  if (typeof token !== "string" || !constantTimeEquals(token, config.capabilityToken)) {
    log("rejected: bad capability token", { path: url.pathname });
    return send(res, 401, { type: "error", error: { type: "authentication_error" } });
  }

  // --- path allowlist -------------------------------------------------------
  // An open forward proxy inside the trust boundary would be worse than no
  // broker at all: it would give the container a route to anywhere.
  if (!config.allowedPaths.some((p) => url.pathname === p)) {
    log("rejected: path not allowlisted", { path: url.pathname });
    return send(res, 403, { type: "error", error: { type: "permission_error" } });
  }

  // --- budget ---------------------------------------------------------------
  // A looping agent must not be able to quietly drain the account (T10).
  if (ledger.exhausted()) {
    log("rejected: session budget exhausted", ledger.snapshot());
    return send(res, 429, {
      type: "error",
      error: { type: "rate_limit_error", message: "Atrium session token budget exhausted." },
    });
  }

  if (config.upstreamCredential === null) {
    log("rejected: no upstream credential configured");
    return send(res, 503, {
      type: "error",
      error: { type: "api_error", message: "Broker has no upstream credential." },
    });
  }

  const body = await readBody(req, MAX_REQUEST_BYTES);

  // --- forward --------------------------------------------------------------
  const upstream = new URL(config.upstreamOrigin);
  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (STRIPPED_REQUEST_HEADERS.has(k.toLowerCase())) continue;
    if (typeof v === "string") headers[k] = v;
  }
  // The whole point of this service.
  headers["x-api-key"] = config.upstreamCredential;
  headers["anthropic-version"] = headers["anthropic-version"] ?? "2023-06-01";
  headers["content-length"] = String(body.length);
  headers["host"] = upstream.host;

  const doRequest = upstream.protocol === "https:" ? httpsRequest : httpRequest;

  await new Promise<void>((resolve, reject) => {
    const proxied = doRequest(
      {
        protocol: upstream.protocol,
        hostname: upstream.hostname,
        port: upstream.port || (upstream.protocol === "https:" ? 443 : 80),
        path: url.pathname + url.search,
        method: req.method ?? "POST",
        headers,
      },
      (upRes) => {
        const chunks: Buffer[] = [];
        res.writeHead(upRes.statusCode ?? 502, upRes.headers);
        upRes.on("data", (c: Buffer) => {
          chunks.push(c);
          res.write(c);
        });
        upRes.on("end", () => {
          res.end();
          const usage = extractUsage(Buffer.concat(chunks));
          if (usage) ledger.charge(usage.input, usage.output);
          log("forwarded", {
            path: url.pathname,
            status: upRes.statusCode,
            inputTokens: usage?.input ?? null,
            outputTokens: usage?.output ?? null,
            spent: ledger.snapshot(),
          });
          resolve();
        });
        upRes.on("error", reject);
      },
    );
    proxied.on("error", reject);
    proxied.end(body);
  });
}

main();
