/**
 * Usage accounting for a forwarded response (SECURITY.md T10).
 *
 * ============================================================================
 * WHY THIS IS NOT `JSON.parse(body)`
 * ============================================================================
 * The ledger is the ONE control the whole agent layer defers to. `provider.ts`
 * tells implementors "budgets are enforced at the broker, not here… an
 * implementation MUST NOT treat a limit here as the control", and
 * `packages/shared/src/agent.ts` repeats it to the client. So this has to hold
 * for the traffic an agent actually produces, which is STREAMING.
 *
 * Claude Code calls `/v1/messages` with `stream: true`, so the body is an SSE
 * event stream, not a JSON object:
 *
 *   event: message_start
 *   data: {"type":"message_start","message":{"usage":{"input_tokens":1200,…}}}
 *   event: message_delta
 *   data: {"type":"message_delta","usage":{"output_tokens":340}}
 *
 * A `JSON.parse` over that whole body throws. A parser that answers "no usage"
 * on a throw charges zero — which made the ledger a counter that never
 * incremented, `exhausted()` permanently false, and the 429 unreachable in
 * normal operation. Both shapes are handled here.
 *
 * ============================================================================
 * THE TWO RULES THAT MAKE THIS A CONTROL RATHER THAN A STATISTIC
 * ============================================================================
 *  1. Usage figures are CUMULATIVE per message — `message_start.message.usage`
 *     and the final `message_delta.usage` both report totals for the same
 *     message — so the maximum is the total. Summing them double-counts.
 *  2. A 2xx that cannot be accounted is charged a conservative ESTIMATE, never
 *     zero. Otherwise an unparseable body, a novel response shape, or a future
 *     API revision buys free tokens, and the one place the ceiling is enforced
 *     silently stops enforcing it. This is the property the old comment claimed
 *     and the old code did not have.
 *
 * Accounting happens INCREMENTALLY, as bytes stream past. The body is never
 * buffered whole: an agent turn can stream for minutes, so holding it would be
 * a leak as well as pointless — only the numbers are wanted.
 */

import { StringDecoder } from "node:string_decoder";

/**
 * Ceiling on the text held for accounting.
 *
 * In SSE mode this bounds one partial line, because complete lines are consumed
 * as they arrive. It only grows before the first `data:` line — the
 * non-streaming path, where the whole JSON body is the unit of parsing. A body
 * that exceeds it is accounted by estimate rather than buffered, so a large or
 * newline-free response cannot grow this process without bound.
 */
const MAX_ACCOUNTING_CHARS = 1024 * 1024;

/** Rough characters-per-token, used only when a response cannot be accounted. */
const ESTIMATE_CHARS_PER_TOKEN = 4;
/** Floor on an estimated charge, so an unaccountable call is never free. */
const ESTIMATE_MIN_TOKENS = 256;

/**
 * Where a charge came from.
 *
 *  - `measured`  — read from the response's own usage figures.
 *  - `estimated` — a 2xx whose usage could not be read. Charged anyway.
 *  - `unbilled`  — a non-2xx. Charged nothing; upstream did not bill it either.
 */
export type UsageSource = "measured" | "estimated" | "unbilled";

export interface AccountedUsage {
  readonly input: number;
  readonly output: number;
  readonly source: UsageSource;
}

function toCount(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) && value > 0 ? Math.ceil(value) : 0;
}

/**
 * Read one Messages API `usage` object, or null when this is not one.
 *
 * Cache reads and cache writes are charged at the full input rate. That is
 * deliberately conservative: cached tokens are cheaper upstream, so this can
 * only ever stop an agent early, never let one run long.
 */
export function readUsage(raw: unknown): { input: number; output: number } | null {
  if (typeof raw !== "object" || raw === null) return null;
  const u = raw as Record<string, unknown>;
  const known =
    "input_tokens" in u ||
    "output_tokens" in u ||
    "cache_read_input_tokens" in u ||
    "cache_creation_input_tokens" in u;
  if (!known) return null;
  return {
    input:
      toCount(u["input_tokens"]) +
      toCount(u["cache_read_input_tokens"]) +
      toCount(u["cache_creation_input_tokens"]),
    output: toCount(u["output_tokens"]),
  };
}

/** Accounts an upstream response as it streams past, holding numbers not bytes. */
export class UsageScanner {
  readonly #decoder = new StringDecoder("utf8");
  /** Unconsumed tail: one partial SSE line, or the non-streaming body so far. */
  #carry = "";
  /** Lines of a non-streaming body, reassembled. Cleared once SSE is detected. */
  #plain = "";
  /** Set by the first `data:` line. After it, non-data lines are dropped. */
  #sse = false;
  /** The body outran `MAX_ACCOUNTING_CHARS` before a `data:` line appeared. */
  #truncated = false;
  #responseChars = 0;
  #input = 0;
  #output = 0;
  #measured = false;

  push(chunk: Buffer): void {
    const text = this.#decoder.write(chunk);
    if (text.length === 0) return;
    this.#responseChars += text.length;
    if (this.#truncated) return;
    this.#carry += text;
    for (;;) {
      const nl = this.#carry.indexOf("\n");
      if (nl === -1) break;
      const line = this.#carry.slice(0, nl);
      this.#carry = this.#carry.slice(nl + 1);
      this.#onLine(line);
    }
    if (this.#carry.length > MAX_ACCOUNTING_CHARS || this.#plain.length > MAX_ACCOUNTING_CHARS) {
      this.#carry = "";
      this.#plain = "";
      this.#truncated = true;
    }
  }

  /** Flush the final line: a body need not end with a newline. */
  end(): void {
    const tail = this.#carry + this.#decoder.end();
    this.#carry = "";
    if (tail.length > 0 && !this.#truncated) this.#onLine(tail);
    // A non-streaming body is one JSON document spread over the lines seen so
    // far, so it is parsed here rather than line by line.
    if (!this.#sse && !this.#truncated && this.#plain.length > 0) this.#absorb(this.#plain);
    this.#plain = "";
  }

  #onLine(raw: string): void {
    const line = raw.endsWith("\r") ? raw.slice(0, -1) : raw;
    if (line.startsWith("data:")) {
      if (!this.#sse) {
        this.#sse = true;
        this.#plain = "";
      }
      const payload = line.slice(5).trim();
      if (payload.length > 0 && payload !== "[DONE]") this.#absorb(payload);
      return;
    }
    // `event:`, `id:`, `retry:` and blank separators carry no usage.
    if (this.#sse) return;
    this.#plain += `${line}\n`;
  }

  #absorb(text: string): void {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      return;
    }
    if (typeof parsed !== "object" || parsed === null) return;
    const o = parsed as Record<string, unknown>;
    // Non-streaming responses put usage at the top level; `message_start` nests
    // it under `message`; `message_delta` puts it back at the top.
    this.#record(readUsage(o["usage"]));
    const message = o["message"];
    if (typeof message === "object" && message !== null) {
      this.#record(readUsage((message as Record<string, unknown>)["usage"]));
    }
  }

  #record(usage: { input: number; output: number } | null): void {
    if (usage === null) return;
    this.#measured = true;
    // Cumulative, not incremental — see rule 1 at the top of this file.
    if (usage.input > this.#input) this.#input = usage.input;
    if (usage.output > this.#output) this.#output = usage.output;
  }

  /**
   * What to charge. NEVER returns zero for a 2xx.
   *
   * A non-2xx is `unbilled`: the provider did not bill it either, and charging
   * for upstream 429s and 5xx would let a transient outage burn a workspace's
   * budget through no fault of its own. The status comes from the upstream, so
   * a container cannot choose it — which is what keeps that safe.
   */
  result(status: number, requestBytes: number): AccountedUsage {
    if (this.#measured) return { input: this.#input, output: this.#output, source: "measured" };
    if (status < 200 || status > 299) return { input: 0, output: 0, source: "unbilled" };
    const input = Math.ceil(requestBytes / ESTIMATE_CHARS_PER_TOKEN);
    let output = Math.ceil(this.#responseChars / ESTIMATE_CHARS_PER_TOKEN);
    const shortfall = ESTIMATE_MIN_TOKENS - (input + output);
    if (shortfall > 0) output += shortfall;
    return { input, output, source: "estimated" };
  }
}
