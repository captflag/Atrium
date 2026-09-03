import Fastify from "fastify";
import cors from "@fastify/cors";
import { rollUp, type HealthCheck, type HealthResponse } from "@atrium/shared";
import { loadConfig } from "./config.ts";
import { checkDatabase, createPool } from "./db.ts";
import { DevIdentityProvider } from "./identity.ts";
import { createDocStore } from "./realtime/docstore.ts";
import { RealtimeGateway } from "./realtime/gateway.ts";

const VERSION = "0.0.0";
const startedAt = Date.now();

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

  const gateway = new RealtimeGateway({
    server: app.server,
    identity: new DevIdentityProvider(config.nodeEnv),
    store,
    log: app.log,
    allowedOrigins: config.corsOrigins,
  });

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

  const shutdown = async (signal: string): Promise<void> => {
    app.log.info({ signal }, "shutting down");
    await gateway.close();
    await app.close();
    await pool.end();
    process.exit(0);
  };
  process.on("SIGINT", () => void shutdown("SIGINT"));
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
