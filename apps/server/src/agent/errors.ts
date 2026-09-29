/**
 * The throwable form of `AgentError` (provider.ts).
 *
 * It deliberately does NOT `implements AgentError`, for the same reason
 * `SandboxError` does not implement `SandboxErrorShape`: under
 * `exactOptionalPropertyTypes` a class field declared `detail: string |
 * undefined` is not assignable to `detail?: string`, and a class cannot express
 * "the property is absent". The structural shape is what callers match on, and
 * `toShape()` builds the value form with the key genuinely omitted.
 *
 * SECURITY.md T9 and the `AgentError` doc comment split the two strings on
 * purpose:
 *   `message` is safe to put on the wire. It carries no host path, no container
 *            id, no capability token, no environment value, no stack trace.
 *   `detail`  is for the operator log ONLY and MUST NOT be serialized to a
 *            client. It is also not logged by default — the gateway decides.
 */

import type { AgentErrorCode } from "@atrium/shared";

export class AgentSessionError extends Error {
  readonly code: AgentErrorCode;
  /** `undefined` when there is nothing an operator would want that a client may not see. */
  readonly detail: string | undefined;

  constructor(code: AgentErrorCode, message: string, detail?: string) {
    super(message);
    this.name = "AgentSessionError";
    this.code = code;
    this.detail = detail;
  }

  /** Value form. The `detail` key is absent, not undefined, when there is none. */
  toShape(): { code: AgentErrorCode; message: string; detail?: string } {
    return this.detail === undefined
      ? { code: this.code, message: this.message }
      : { code: this.code, message: this.message, detail: this.detail };
  }
}

export function isAgentSessionError(value: unknown): value is AgentSessionError {
  return value instanceof AgentSessionError;
}

/**
 * Blank secrets out of a string before it becomes an error message or a log
 * line. A backstop, not a licence to interpolate a token into a message.
 */
export function redactAgentText(text: string, secrets: readonly string[]): string {
  let out = text;
  const ordered = [...new Set(secrets.filter((s) => s.length >= 4))].sort((a, b) => b.length - a.length);
  for (const secret of ordered) out = out.split(secret).join("<redacted>");
  return out;
}
