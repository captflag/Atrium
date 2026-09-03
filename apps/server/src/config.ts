/**
 * Environment parsing. Fails loudly at boot rather than at first use.
 *
 * SECURITY.md M0: no secret ever has a default value here. A missing
 * credential must stop the process, not silently fall back to a shared one.
 */

function required(name: string): string {
  const value = process.env[name];
  if (value === undefined || value === "") {
    throw new Error(
      `Missing required environment variable ${name}. Copy .env.example to .env and fill it in.`,
    );
  }
  return value;
}

function optionalInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  const parsed = Number.parseInt(raw, 10);
  if (Number.isNaN(parsed)) {
    throw new Error(`Environment variable ${name} must be an integer, got ${JSON.stringify(raw)}`);
  }
  return parsed;
}

export interface Config {
  readonly nodeEnv: "development" | "production" | "test";
  readonly port: number;
  readonly host: string;
  readonly databaseUrl: string;
  /** Origins allowed to call the API. The web dev server in development. */
  readonly corsOrigins: readonly string[];
}

export function loadConfig(): Config {
  const nodeEnv = (process.env["NODE_ENV"] ?? "development") as Config["nodeEnv"];

  return {
    nodeEnv,
    port: optionalInt("PORT", 8787),
    host: process.env["HOST"] ?? "127.0.0.1",
    databaseUrl: required("DATABASE_URL"),
    corsOrigins: (process.env["CORS_ORIGINS"] ?? "http://localhost:5173")
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0),
  };
}
