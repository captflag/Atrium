import { Pool } from "pg";
import type { HealthCheck } from "@atrium/shared";

export function createPool(databaseUrl: string): Pool {
  return new Pool({
    connectionString: databaseUrl,
    // Fail fast at boot instead of hanging a request for 30s.
    connectionTimeoutMillis: 5_000,
    idleTimeoutMillis: 30_000,
    max: 10,
  });
}

/**
 * Liveness check for Postgres.
 *
 * Never surfaces the connection string or driver internals — the health
 * endpoint is reachable by anyone who can reach the server (SECURITY.md T9).
 */
export async function checkDatabase(pool: Pool): Promise<HealthCheck> {
  const started = performance.now();
  try {
    await pool.query("select 1");
    return {
      name: "postgres",
      status: "ok",
      latencyMs: Math.round(performance.now() - started),
    };
  } catch {
    return {
      name: "postgres",
      status: "down",
      latencyMs: Math.round(performance.now() - started),
      detail: "unreachable",
    };
  }
}
