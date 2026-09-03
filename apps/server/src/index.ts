import Fastify from "fastify";
import cors from "@fastify/cors";
import { rollUp, TERMINAL_ID_RE, type HealthCheck, type HealthResponse } from "@atrium/shared";
import { loadConfig } from "./config.ts";
import { checkDatabase, createPool } from "./db.ts";
import { DevIdentityProvider, type IdentityProvider, type Principal } from "./identity.ts";
import { createDocStore } from "./realtime/docstore.ts";
import { RealtimeGateway } from "./realtime/gateway.ts";
import { TerminalGateway, TerminalOpenError, TerminalRegistry } from "./realtime/terminal.ts";
import { isSandboxError } from "./sandbox/errors.ts";
import { WorkspaceSandboxes } from "./sandbox/orchestrator.ts";

const VERSION = "0.0.0";
const startedAt = Date.now();

const WORKSPACE_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

/**
 * The shell a terminal pane opens.
 *
 * `bash` rather than the registry's `/bin/sh` default because
 * docker/workspace.Dockerfile installs it and gives uid 10001 `/bin/bash` as
 * its login shell. It is stated here, at the call site, rather than assumed
 * inside the provider: the image and the shell are one decision.
 */
const WORKSPACE_SHELL: readonly string[] = ["/bin/bash", "-l"];

async function main(): Promise<void> {
  const config = loadConfig();
  const pool = createPool(config.databaseUrl);

  const app = Fastify({
    logger: {
      level: config.nodeEnv === "production" ? "info" : "info",
      // Never log headers or bodies wholesale — they carry credentials.
      redact: ["req.headers.authorization", "req.headers.cookie"],
    },
    // Trust no proxy by default; revisit when the preview proxy lands (M6).
    trustProxy: false,
  });

  await app.register(cors, {
    origin: [...config.corsOrigins],
    credentials: true,
  });

  const store = await createDocStore(pool, {
    info: (msg) => app.log.info(msg),
    warn: (msg) => app.log.warn(msg),
  });

  const identity: IdentityProvider = new DevIdentityProvider(config.nodeEnv);

  const gateway = new RealtimeGateway({
    identity,
    store,
    log: app.log,
    allowedOrigins: config.corsOrigins,
  });

  // --- M2: sandbox + terminal --------------------------------------------

  const sandboxes = new WorkspaceSandboxes({
    log: app.log,
    dockerSocket: config.dockerSocket,
    workspacesDir: config.workspacesDir,
    image: config.workspaceImage,
    repoUrl: config.workspaceRepoUrl,
  });

  const terminals = new TerminalRegistry({
    // The registry may only LOOK UP a sandbox. Creating one is `ensure()`,
    // which is reachable from the authorized route below and from nowhere else
    // — in particular not from a websocket message.
    sandboxes,
    log: app.log,
    defaultCommand: WORKSPACE_SHELL,
  });

  const terminalGateway = new TerminalGateway({
    identity,
    registry: terminals,
    log: app.log,
    allowedOrigins: config.corsOrigins,
  });

  /**
   * ONE upgrade dispatcher.
   *
   * Node emits `upgrade` to every listener, so a gateway that rejects paths it
   * does not own destroys the other gateway's sockets. Both gateways therefore
   * claim-or-decline, and the final reject lives here, once.
   */
  app.server.on("upgrade", (req, socket, head) => {
    if (terminalGateway.handleUpgrade(req, socket, head)) return;
    if (gateway.handleUpgrade(req, socket, head)) return;
    socket.write("HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n");
    socket.destroy();
  });

  /**
   * Authorization for the HTTP routes below, in the same order and with the
   * same primitives as the websocket upgrade (SECURITY.md T6, T11): resolve a
   * principal, then check membership of the workspace named in the path. A
   * route that opens a shell in a container is not a place to trust an id.
   */
  const authorize = async (
    req: { headers: Record<string, string | string[] | undefined>; url: string },
    workspaceId: string,
  ): Promise<{ ok: true; principal: Principal } | { ok: false; status: number; error: string }> => {
    if (!WORKSPACE_ID_RE.test(workspaceId)) {
      return { ok: false, status: 400, error: "invalid-workspace" };
    }
    const url = new URL(req.url, "http://localhost");
    const principal = await identity.authenticate(req.headers, url);
    if (principal === null) return { ok: false, status: 401, error: "unauthenticated" };
    if (!(await identity.isMember(principal, workspaceId))) {
      return { ok: false, status: 403, error: "forbidden" };
    }
    return { ok: true, principal };
  };

  /**
   * Open a terminal for a pane. THE AUTHORIZED CALL SITE.
   *
   * The wire protocol can only ever attach to a terminal that already exists
   * (terminal-registry.ts); this is where one comes into being. Idempotent, so
   * every viewer of the same pane can call it and only one shell is spawned.
   */
  app.post<{ Params: { workspaceId: string }; Body: unknown }>(
    "/api/workspaces/:workspaceId/terminals",
    async (req, reply) => {
      const { workspaceId } = req.params;
      const auth = await authorize(req, workspaceId);
      if (!auth.ok) return reply.code(auth.status).send({ error: auth.error });

      const body = (req.body ?? {}) as Record<string, unknown>;
      const terminalId = body["terminalId"];
      if (typeof terminalId !== "string" || !TERMINAL_ID_RE.test(terminalId)) {
        return reply.code(400).send({ error: "invalid-terminal-id" });
      }

      try {
        const binding = await sandboxes.ensure(workspaceId);
        const session = await terminals.open(workspaceId, terminalId);
        return reply.send({
          terminalId: session.terminalId,
          workspaceId,
          cols: session.size.cols,
          rows: session.size.rows,
          viewers: session.viewerCount,
          // The user is entitled to know the box is softer than the docs say
          // (SandboxHandle.unenforced, SECURITY.md T3).
          unenforced: binding.handle.unenforced,
        });
      } catch (error: unknown) {
        return replyTerminalError(reply, error, { workspaceId, terminalId }, app.log);
      }
    },
  );

  /**
   * Close a terminal. Called when a terminal pane is deleted: sessions are
   * server-owned (PLAN.md §6), so nothing else ever ends them, and a pane
   * removed from the canvas with its shell left running is a leak.
   */
  app.delete<{ Params: { workspaceId: string; terminalId: string } }>(
    "/api/workspaces/:workspaceId/terminals/:terminalId",
    async (req, reply) => {
      const { workspaceId, terminalId } = req.params;
      const auth = await authorize(req, workspaceId);
      if (!auth.ok) return reply.code(auth.status).send({ error: auth.error });
      if (!TERMINAL_ID_RE.test(terminalId)) {
        return reply.code(400).send({ error: "invalid-terminal-id" });
      }
      // Workspace-scoped, so a member of one workspace cannot close another's.
      await terminals.close(workspaceId, terminalId);
      return reply.code(204).send();
    },
  );

  app.get("/api/health", async (): Promise<HealthResponse> => {
    const checks: HealthCheck[] = [await checkDatabase(pool)];
    checks.push({
      name: "canvas-persistence",
      status: store.durable ? "ok" : "degraded",
      detail: store.describe,
    });
    checks.push({
      name: "realtime",
      status: "ok",
      detail: `${gateway.roomCount} room(s)`,
    });

    // Sandbox reachability. Degraded rather than down when the engine is
    // unreachable: the canvas keeps working without it, and M1 must not start
    // reporting itself broken because Docker is closed.
    const docker = await sandboxes.health();
    const unenforced = sandboxes.unenforced;
    checks.push(
      docker.reachable
        ? {
            name: "sandbox",
            status: "ok",
            detail:
              `docker ${docker.version ?? "?"} · ${sandboxes.count} sandbox(es)` +
              (unenforced.length > 0 ? ` · unenforced: ${unenforced.join(", ")}` : ""),
          }
        : {
            name: "sandbox",
            status: "degraded",
            detail: docker.detail ?? "docker engine unreachable — terminals unavailable",
          },
    );
    checks.push({
      name: "terminals",
      status: "ok",
      detail: `${terminals.count} session(s), ${terminalGateway.socketCount} socket(s)`,
    });

    return {
      status: rollUp(checks),
      time: new Date().toISOString(),
      uptimeSeconds: Math.round((Date.now() - startedAt) / 1000),
      version: VERSION,
      checks,
    };
  });

  await app.listen({ port: config.port, host: config.host });
  app.log.info(`realtime gateway on ws://${config.host}:${config.port}/rt`);
  app.log.info(`terminal gateway on ws://${config.host}:${config.port}${terminalGateway.path}`);

  const shutdown = async (signal: string): Promise<void> => {
    app.log.info({ signal }, "shutting down");
    // Sockets first (the shells survive a dropped viewer by design), then the
    // shells, then the canvas rooms, then the server and the pool. Workspace
    // CONTAINERS are deliberately left running: `create()` re-adopts them by
    // label on the next boot, and killing a build because the API process
    // restarted is what PLAN.md §6 exists to prevent.
    await terminalGateway.close();
    await terminals.closeAll();
    await gateway.close();
    await app.close();
    await pool.end();
    process.exit(0);
  };
  process.on("SIGINT", () => void shutdown("SIGINT"));
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
}

/**
 * Turn an orchestrator/registry failure into a status and a SHORT, curated
 * message.
 *
 * The thrown message is operator-facing and may quote a daemon error
 * (SECURITY.md T9), so it goes to the log and never to the client; the client
 * gets a fixed string per code and, for the one case a developer will actually
 * hit — no image built — a hint that names no path.
 */
function replyTerminalError(
  reply: { code(status: number): { send(body: unknown): unknown } },
  error: unknown,
  context: { workspaceId: string; terminalId: string },
  log: { warn(obj: Record<string, unknown>, msg: string): void },
): unknown {
  const detail = error instanceof Error ? error.message : "unknown";
  log.warn({ ...context, err: detail }, "failed to open terminal");

  if (error instanceof TerminalOpenError) {
    switch (error.code) {
      case "sandbox-not-running":
        return reply.code(503).send({ error: error.code, message: "The workspace sandbox is not running." });
      case "too-many-terminals":
        return reply
          .code(429)
          .send({ error: error.code, message: "This workspace has too many terminals open." });
      case "invalid-id":
        return reply.code(400).send({ error: error.code, message: "Invalid terminal id." });
      default:
        return reply
          .code(500)
          .send({ error: "internal", message: "Could not start a shell in the sandbox." });
    }
  }

  if (isSandboxError(error)) {
    if (error.code === "backend-unavailable") {
      return reply
        .code(503)
        .send({ error: error.code, message: "Docker is not reachable. Start Docker Desktop." });
    }
    if (error.code === "invalid-spec") {
      // The only invalid-spec a caller can cause is a missing workspace image,
      // and telling them so is worth more than the nothing it discloses.
      return reply.code(503).send({
        error: error.code,
        message:
          "The workspace image is not built. Run: docker build -f docker/workspace.Dockerfile -t atrium/workspace-base:m2 .",
      });
    }
    return reply.code(503).send({ error: error.code, message: "The workspace sandbox is unavailable." });
  }

  return reply.code(500).send({ error: "internal", message: "Could not open the terminal." });
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
