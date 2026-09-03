/**
 * SandboxError — the one error type every `SandboxProvider` implementation
 * throws.
 *
 * `provider.ts` defines `SandboxErrorShape` as a value type so an error can
 * cross a future service boundary as JSON. This class is the throwable form.
 * It deliberately does NOT `implements SandboxErrorShape`: under
 * `exactOptionalPropertyTypes`, a field declared `sandboxId: string | undefined`
 * is not assignable to `sandboxId?: string`, and a class cannot express "the
 * property is absent" through an assignment. `toShape()` builds the value form
 * instead, omitting the key when there is no sandbox to name.
 *
 * SECURITY.md T9: `message` is operator-facing and is copied into logs and the
 * event log. It MUST NOT carry host paths, container ids, capability tokens, or
 * environment values. `redact()` below is the tool for that — every message
 * built from a Docker daemon error goes through it, because daemon errors about
 * bind mounts quote the host path back at you verbatim.
 */

import type { SandboxErrorCode, SandboxErrorShape, SandboxId } from "./provider.ts";

export class SandboxError extends Error {
  readonly code: SandboxErrorCode;
  /** `undefined` when the failure happened before a sandbox existed. */
  readonly sandboxId: SandboxId | undefined;

  constructor(code: SandboxErrorCode, message: string, sandboxId?: SandboxId) {
    super(message);
    this.name = "SandboxError";
    this.code = code;
    this.sandboxId = sandboxId;
  }

  /** Value form, safe to serialize into the event log. */
  toShape(): SandboxErrorShape {
    return this.sandboxId === undefined
      ? { code: this.code, message: this.message }
      : { code: this.code, message: this.message, sandboxId: this.sandboxId };
  }
}

export function isSandboxError(value: unknown): value is SandboxError {
  return value instanceof SandboxError;
}

/**
 * Strip host-specific and secret substrings out of a message before it becomes
 * a `SandboxError`.
 *
 * `secrets` are exact strings to blank: the repo's host path, every value in
 * `spec.env.plain`, the capability token. Longest first, so a token that
 * contains another secret as a substring is replaced whole.
 *
 * This is a backstop, not a licence to interpolate secrets into messages.
 */
export function redact(message: string, secrets: readonly string[]): string {
  let out = message;
  const ordered = [...new Set(secrets.filter((s) => s.length >= 4))].sort(
    (a, b) => b.length - a.length,
  );
  for (const secret of ordered) {
    out = out.split(secret).join("<redacted>");
    // Docker echoes Windows paths back with the separators it received and
    // sometimes with the ones it normalised to, so blank both spellings.
    const flipped = secret.includes("\\") ? secret.split("\\").join("/") : secret.split("/").join("\\");
    if (flipped !== secret) out = out.split(flipped).join("<redacted>");
  }
  return out;
}

/**
 * Map a thrown value from `dockerode` onto a `SandboxErrorCode`.
 *
 * dockerode surfaces daemon errors with a numeric `statusCode` and transport
 * errors with a Node `code` (`ENOENT` on a missing named pipe, `ECONNREFUSED`
 * on a stopped engine).
 */
export function classifyDockerError(err: unknown): SandboxErrorCode {
  const e = err as { statusCode?: number; code?: string } | null;
  const nodeCode = typeof e?.code === "string" ? e.code : "";
  if (
    nodeCode === "ENOENT" ||
    nodeCode === "ECONNREFUSED" ||
    nodeCode === "ECONNRESET" ||
    nodeCode === "EPIPE" ||
    nodeCode === "ETIMEDOUT"
  ) {
    return "backend-unavailable";
  }
  switch (e?.statusCode) {
    case 404:
      return "not-found";
    case 409:
      return "not-running";
    case 400:
      return "invalid-spec";
    case 507:
      return "resource-exhausted";
    default:
      return "internal";
  }
}
