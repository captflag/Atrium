/**
 * Broker configuration.
 *
 * The credential is read from the environment of THIS process only. This
 * process runs in the broker sidecar container, which the workspace container
 * cannot exec into or share a namespace with (SECURITY.md D1, T3).
 */

function required(name: string): string {
  const v = process.env[name];
  if (v === undefined || v === "") {
    throw new Error(`Missing required environment variable ${name}.`);
  }
  return v;
}

function optionalInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  const n = Number.parseInt(raw, 10);
  if (Number.isNaN(n) || n <= 0) {
    throw new Error(`Environment variable ${name} must be a positive integer.`);
  }
  return n;
}

export interface BrokerConfig {
  readonly port: number;
  /** Origin of the upstream API, e.g. https://api.anthropic.com */
  readonly upstreamOrigin: string;
  /**
   * The provider credential. Null is a valid, useful state: the broker still
   * enforces the capability token, the path allowlist and the budget, so the
   * D1 boundary can be proven without a real key.
   */
  readonly upstreamCredential: string | null;
  /** Workspace-scoped token the container presents. NOT the credential. */
  readonly capabilityToken: string;
  /** Exact paths that may be forwarded. Never a prefix match. */
  readonly allowedPaths: readonly string[];
  /** Hard ceiling on tokens for this session before requests are refused. */
  readonly sessionTokenBudget: number;
}

export function loadBrokerConfig(): BrokerConfig {
  const upstream = process.env["ATRIUM_UPSTREAM_ORIGIN"] ?? "https://api.anthropic.com";
  // Refuse a plaintext upstream unless it is explicitly a loopback/stub target:
  // forwarding a credential over http to a real host would leak it on the wire.
  const parsed = new URL(upstream);
  const isLocalStub =
    parsed.hostname === "127.0.0.1" ||
    parsed.hostname === "localhost" ||
    parsed.hostname.endsWith(".local") ||
    parsed.hostname === "upstream-stub";
  if (parsed.protocol !== "https:" && !isLocalStub) {
    throw new Error(
      `ATRIUM_UPSTREAM_ORIGIN must be https:// for a non-local host, got ${parsed.protocol}//${parsed.hostname}`,
    );
  }

  const credential = process.env["ATRIUM_UPSTREAM_API_KEY"];

  return {
    port: optionalInt("ATRIUM_BROKER_PORT", 8900),
    upstreamOrigin: upstream,
    upstreamCredential: credential !== undefined && credential !== "" ? credential : null,
    capabilityToken: required("ATRIUM_CAPABILITY_TOKEN"),
    allowedPaths: ["/v1/messages", "/v1/messages/count_tokens", "/v1/models"],
    sessionTokenBudget: optionalInt("ATRIUM_SESSION_TOKEN_BUDGET", 2_000_000),
  };
}
