/**
 * Types shared between the server and the web client.
 *
 * Keep this package free of runtime dependencies — it is imported by both a
 * Node process and a browser bundle.
 */

export * from "./pane.ts";

export type ComponentStatus = "ok" | "degraded" | "down";

export interface HealthCheck {
  /** Component name, e.g. "postgres". */
  readonly name: string;
  readonly status: ComponentStatus;
  /** Round-trip time in milliseconds, when the check measured one. */
  readonly latencyMs?: number;
  /** Human-readable detail. Never include connection strings or secrets. */
  readonly detail?: string;
}

export interface HealthResponse {
  readonly status: ComponentStatus;
  /** Server wall-clock at response time, ISO 8601. */
  readonly time: string;
  /** Seconds since server start. */
  readonly uptimeSeconds: number;
  readonly version: string;
  readonly checks: readonly HealthCheck[];
}

/** Rolls component statuses up into one overall status. */
export function rollUp(checks: readonly HealthCheck[]): ComponentStatus {
  if (checks.some((c) => c.status === "down")) return "down";
  if (checks.some((c) => c.status === "degraded")) return "degraded";
  return "ok";
}
