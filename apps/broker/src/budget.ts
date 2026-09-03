/**
 * Per-session token accounting (SECURITY.md T10).
 *
 * A looping agent is the realistic failure mode, not a malicious one: it
 * retries, re-reads, and burns the account while looking busy. The ceiling is
 * enforced here, outside the container, because anything inside it is advisory.
 */
export class BudgetLedger {
  readonly #limit: number;
  #input = 0;
  #output = 0;

  constructor(limit: number) {
    this.#limit = limit;
  }

  charge(inputTokens: number, outputTokens: number): void {
    this.#input += Math.max(0, inputTokens);
    this.#output += Math.max(0, outputTokens);
  }

  get total(): number {
    return this.#input + this.#output;
  }

  /**
   * Checked BEFORE a request, so the ceiling is a stop line rather than a
   * postmortem. A request in flight may overshoot it; that is bounded by one
   * response and is the correct trade against refusing mid-conversation.
   */
  exhausted(): boolean {
    return this.total >= this.#limit;
  }

  snapshot(): { inputTokens: number; outputTokens: number; limit: number } {
    return { inputTokens: this.#input, outputTokens: this.#output, limit: this.#limit };
  }
}
