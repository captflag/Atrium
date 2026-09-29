/**
 * The private wire between the HOST (`ClaudeAgentProvider`, above the
 * `AgentProvider` seam) and the RUNNER (`@atrium/agent-runner`, inside the
 * workspace container).
 *
 * ============================================================================
 * THIS FILE EXISTS TWICE, BYTE FOR BYTE
 * ============================================================================
 *   apps/server/src/agent/runner-protocol.ts   (host side)
 *   apps/agent-runner/src/protocol.ts          (container side)
 *
 * `scripts/probe-agent.mjs` asserts the two files are byte-identical and fails
 * if they drift. Edit both, or edit neither.
 *
 * The duplication is deliberate and is cheaper than the alternatives. The two
 * packages cannot share a module: `apps/server` must never resolve
 * `@atrium/agent-runner` (that would put the Agent SDK in the server's
 * dependency graph and defeat the seam `provider.ts` exists to hold), and the
 * canonical home for cross-cutting types — `packages/shared` — is the WIRE
 * protocol's home, not this one. This is not the wire protocol. Nothing here
 * ever reaches a browser.
 *
 * That is also why this file imports nothing, not even `@atrium/shared`:
 * a copy that has to resolve a package is a copy that only compiles in one of
 * the two projects. `RunnerEventPayload` below restates the `AgentEvent` union
 * minus its server-assigned fields, and `claude-agent.ts` carries a
 * compile-time assertion in BOTH directions that the restatement still matches
 * `@atrium/shared`. If the shared union changes, the server stops compiling.
 *
 * ============================================================================
 * WHY STDIO, AND WHY A PTY
 * ============================================================================
 * The runner is inside the container. Egress there is deny-by-default and the
 * only reachable host is the broker sidecar (PLAN.md §4, measured) — so there
 * is no network path from the runner back to the server, by design. The only
 * bidirectional channel Docker offers into a running container is an exec's
 * stdio, and `SandboxProvider.exec` is one-shot (stdin closes, then the command
 * runs). `spawnPty` is the only streaming duplex in the sandbox contract, so
 * that is what this rides on.
 *
 * A pty has a line discipline, which would mangle a byte protocol: it echoes
 * input back onto output, translates \n to \r\n, and turns 0x03 into SIGINT.
 * The runner's launch command therefore runs `stty raw -echo` BEFORE exec'ing
 * node, and the host sends nothing until the runner's `ready` line proves that
 * has happened. See `RUNNER_LAUNCH_ARGV` in claude-agent.ts.
 *
 * ============================================================================
 * FRAMING
 * ============================================================================
 * One message per line: RS (0x1e), then JSON, then LF. Two properties matter.
 *
 *  1. A pty merges stderr into stdout. Anything the runner's own stderr emits —
 *     a Node warning, a stray write — appears on the same stream. Lines that do
 *     not start with RS are diagnostics and are ignored by the parser rather
 *     than corrupting a message.
 *  2. The JSON is ASCII-only (`encodeRunnerLine` escapes every byte outside
 *     0x20..0x7e). A pty is byte-transparent in raw mode, but a protocol that
 *     never depends on that is a protocol that cannot be broken by a locale.
 *
 * ============================================================================
 * TRUST
 * ============================================================================
 * The runner is INSIDE the trust boundary's hostile half. Every string that
 * arrives from it is untrusted (SECURITY.md T1) and every field the host reads
 * is validated by `parseRunnerLine` before use. In particular:
 *
 *  - `seq` is NOT on this wire. Sequence numbers are assigned by the host
 *    (`provider.ts`: monotonic, gap-free, from 1) precisely because a number
 *    chosen inside the container is not a replay cursor.
 *  - The agent's own tool subprocesses cannot reach this channel: the Claude
 *    Code CLI is spawned with piped stdio, so neither it nor anything it forks
 *    inherits the runner's pty. Forging a frame would require writing to the
 *    runner's own fds.
 *  - `capabilityToken` travels in `start` over STDIN, never in the runner's
 *    environment. `/proc/<pid>/environ` is world-readable to the same uid, and
 *    the agent runs as that uid; stdin is not.
 */

/** Bumped when a field changes meaning. Host and runner must agree exactly. */
export const RUNNER_PROTOCOL_VERSION = 1;

/** ASCII record separator. Starts every protocol line. */
export const RUNNER_FRAME_MARKER = "\u001e";

/** Hard ceiling on one encoded line, both directions. */
export const RUNNER_MAX_LINE_BYTES = 512 * 1024;

/** Cap on the tool input echoed back to the host's advisory gate. */
export const RUNNER_MAX_GATE_INPUT_BYTES = 8 * 1024;

/* ==========================================================================
 * Events (the `AgentEvent` union minus its server-assigned fields)
 * ========================================================================== */

export type RunnerToolStatus = "ok" | "error" | "denied";

export type RunnerDoneReason =
  | "completed"
  | "interrupted"
  | "stopped"
  | "max-turns"
  | "budget-exhausted"
  | "error";

export type RunnerErrorCode =
  | "bad-message"
  | "version-mismatch"
  | "not-found"
  | "forbidden"
  | "bad-channel"
  | "payload-too-large"
  | "too-many-channels"
  | "sandbox-not-running"
  | "agent-not-running"
  | "busy"
  | "budget-exhausted"
  | "upstream-unavailable"
  | "harness-unavailable"
  | "slow-consumer"
  | "internal";

export type RunnerEventPayload =
  | {
      readonly kind: "started";
      readonly model: string;
      readonly cwd: string;
      readonly tools: readonly string[];
      readonly harness: string;
    }
  | {
      readonly kind: "text";
      readonly text: string;
      readonly final: boolean;
      readonly messageId: string;
      readonly parentToolUseId?: string;
    }
  | { readonly kind: "thinking"; readonly text: string; readonly messageId: string }
  | {
      readonly kind: "tool_call";
      readonly toolUseId: string;
      readonly tool: string;
      readonly inputPreview: string;
      readonly truncated: boolean;
      readonly parentToolUseId?: string;
    }
  | {
      readonly kind: "tool_result";
      readonly toolUseId: string;
      readonly tool: string;
      readonly status: RunnerToolStatus;
      readonly outputPreview: string;
      readonly truncated: boolean;
      readonly durationMs?: number;
    }
  | {
      readonly kind: "usage";
      readonly model: string;
      readonly inputTokens: number;
      readonly outputTokens: number;
      readonly cacheReadInputTokens: number;
      readonly cacheCreationInputTokens: number;
      readonly costUsd?: number;
    }
  | {
      readonly kind: "done";
      readonly reason: RunnerDoneReason;
      readonly turns: number;
      readonly summary?: string;
    }
  | {
      readonly kind: "error";
      readonly code: RunnerErrorCode;
      readonly message: string;
      readonly retryable: boolean;
    }
  | { readonly kind: "notice"; readonly level: "info" | "warn"; readonly message: string };

/* ==========================================================================
 * host -> runner
 * ========================================================================== */

/**
 * What the host tells the runner at start.
 *
 * Note what is NOT here: no workspace id, no session id, no member id, no host
 * path. The runner has no authorization decisions to make and nothing to
 * re-derive; giving it identifiers it does not need is how a component starts
 * making decisions it should not (SECURITY.md T5).
 */
export interface RunnerStartSpec {
  readonly v: number;
  /** The human's task, verbatim. Never logged, on either side (T9). */
  readonly task: string;
  /** Absolute path INSIDE the container. */
  readonly repoRoot: string;
  readonly systemPromptAppend?: string;
  readonly model: string;
  readonly effort: "low" | "medium" | "high" | "xhigh";
  readonly fallbackModel?: string;
  readonly allowedTools: readonly string[];
  readonly deniedTools: readonly string[];
  readonly maxTurns: number;
  readonly maxCostUsd?: number;
  /**
   * True when the host will answer `tool` requests with a `gate` reply. False
   * makes the PreToolUse hook log-only. Either way the hook is ADVISORY and is
   * not a security boundary (SECURITY.md D5, T7).
   */
  readonly gate: boolean;
  /** Fail-open deadline for a gate reply. Advisory layers must not wedge. */
  readonly gateTimeoutMs: number;
  /**
   * The credential boundary, and the whole point of M3 (SECURITY.md D1).
   * `baseUrl` is the broker sidecar as seen from the container;
   * `capabilityToken` is short-lived and workspace-scoped. There is no field
   * here for a provider key and there must never be one.
   */
  readonly broker: { readonly baseUrl: string; readonly capabilityToken: string };
}

export type HostToRunner =
  | { readonly t: "start"; readonly spec: RunnerStartSpec }
  | { readonly t: "prompt"; readonly text: string }
  | { readonly t: "interrupt" }
  | { readonly t: "stop" }
  | { readonly t: "gate"; readonly id: string; readonly decision: "allow" }
  | { readonly t: "gate"; readonly id: string; readonly decision: "deny"; readonly reason: string };

/* ==========================================================================
 * runner -> host
 * ========================================================================== */

/** Mirrors `AgentSessionState`, minus the states only the host can be in. */
export type RunnerState = "running" | "idle";

export type RunnerToHost =
  /** Emitted after `stty raw -echo` has taken effect. The host sends nothing before it. */
  | { readonly t: "ready"; readonly v: number }
  | { readonly t: "event"; readonly e: RunnerEventPayload }
  | { readonly t: "state"; readonly state: RunnerState }
  /**
   * A PreToolUse observation. ALWAYS sent, gate or no gate: this is the M4 seam
   * and the operator-side record of what the agent touched. `paths` is the
   * declared target set the harness put in the tool input — empty for `Bash`,
   * which is exactly why layer 2 (M4's merge gate, outside the container)
   * is the authoritative one and this is not.
   */
  | {
      readonly t: "tool";
      readonly id: string;
      readonly tool: string;
      readonly paths: readonly string[];
      /** Capped at RUNNER_MAX_GATE_INPUT_BYTES; null when it did not fit. Untrusted. */
      readonly input: Readonly<Record<string, unknown>> | null;
    }
  /** The runner cannot continue. Terminal. `detail` is operator-only (T9). */
  | {
      readonly t: "fatal";
      readonly code: RunnerErrorCode;
      readonly message: string;
      readonly detail?: string;
    };

/* ==========================================================================
 * Codec
 * ========================================================================== */

/**
 * Encode one message as a framed, ASCII-only line.
 *
 * Escaping every non-printable and non-ASCII code unit costs a few bytes and
 * removes a whole class of "it worked on my locale" failure. `JSON.parse`
 * restores the original string exactly.
 */
export function encodeRunnerLine(message: unknown): string {
  const json = JSON.stringify(message) ?? "null";
  let out = "";
  for (const ch of json) {
    const code = ch.codePointAt(0) ?? 0;
    if (code >= 0x20 && code <= 0x7e) {
      out += ch;
    } else if (code <= 0xffff) {
      out += `\\u${code.toString(16).padStart(4, "0")}`;
    } else {
      // Astral plane: JSON.stringify already produced a surrogate pair, and
      // for-of walks code points, so re-split it into the two escapes.
      const v = code - 0x10000;
      const hi = 0xd800 + (v >> 10);
      const lo = 0xdc00 + (v & 0x3ff);
      out += `\\u${hi.toString(16).padStart(4, "0")}\\u${lo.toString(16).padStart(4, "0")}`;
    }
  }
  return `${RUNNER_FRAME_MARKER}${out}\n`;
}

/**
 * Split a byte stream into framed lines.
 *
 * Deliberately a class with a `push` returning completed payloads, rather than
 * an event emitter: both sides consume it in a plain loop, and a parser that
 * cannot emit is a parser that cannot reorder.
 */
export class RunnerLineReader {
  #buffer = "";
  readonly #maxLineBytes: number;
  #overlong = false;

  constructor(maxLineBytes: number = RUNNER_MAX_LINE_BYTES) {
    this.#maxLineBytes = maxLineBytes;
  }

  /**
   * Feed decoded text. Returns the JSON bodies of every complete protocol line
   * in it, in order. Non-protocol lines (diagnostics on a merged stderr) and
   * lines over the size cap are dropped.
   */
  push(text: string): string[] {
    this.#buffer += text;
    const out: string[] = [];
    for (;;) {
      const nl = this.#buffer.indexOf("\n");
      if (nl < 0) break;
      const line = this.#buffer.slice(0, nl);
      this.#buffer = this.#buffer.slice(nl + 1);
      if (this.#overlong) {
        this.#overlong = false;
        continue;
      }
      const rs = line.lastIndexOf(RUNNER_FRAME_MARKER);
      if (rs < 0) continue;
      const body = line.slice(rs + 1).replace(/\r+$/, "");
      if (body.length === 0) continue;
      out.push(body);
    }
    if (this.#buffer.length > this.#maxLineBytes) {
      // Drop the partial line and everything up to the next newline rather than
      // growing without bound on a stream that never terminates a line.
      this.#buffer = "";
      this.#overlong = true;
    }
    return out;
  }
}

/* ==========================================================================
 * Validation
 * ==========================================================================
 * Both directions are validated. The runner validates because the host could
 * be buggy; the host validates because the runner is inside the hostile half of
 * the boundary and a message it did not return must never be trusted (T6).
 */

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function str(v: unknown): string | null {
  return typeof v === "string" ? v : null;
}

function num(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

function strArray(v: unknown): string[] | null {
  if (!Array.isArray(v)) return null;
  const out: string[] = [];
  for (const item of v) {
    if (typeof item !== "string") return null;
    out.push(item);
  }
  return out;
}

const DONE_REASONS = new Set<string>([
  "completed",
  "interrupted",
  "stopped",
  "max-turns",
  "budget-exhausted",
  "error",
]);

const ERROR_CODES = new Set<string>([
  "bad-message",
  "version-mismatch",
  "not-found",
  "forbidden",
  "bad-channel",
  "payload-too-large",
  "too-many-channels",
  "sandbox-not-running",
  "agent-not-running",
  "busy",
  "budget-exhausted",
  "upstream-unavailable",
  "harness-unavailable",
  "slow-consumer",
  "internal",
]);

/** Parse a runner event payload. Returns null on anything unrecognised. */
export function parseRunnerEventPayload(v: unknown): RunnerEventPayload | null {
  if (!isRecord(v)) return null;
  const kind = str(v["kind"]);
  switch (kind) {
    case "started": {
      const model = str(v["model"]);
      const cwd = str(v["cwd"]);
      const tools = strArray(v["tools"]);
      const harness = str(v["harness"]);
      if (model === null || cwd === null || tools === null || harness === null) return null;
      return { kind: "started", model, cwd, tools, harness };
    }
    case "text": {
      const text = str(v["text"]);
      const messageId = str(v["messageId"]);
      if (text === null || messageId === null || typeof v["final"] !== "boolean") return null;
      const parent = str(v["parentToolUseId"]);
      return parent === null
        ? { kind: "text", text, final: v["final"], messageId }
        : { kind: "text", text, final: v["final"], messageId, parentToolUseId: parent };
    }
    case "thinking": {
      const text = str(v["text"]);
      const messageId = str(v["messageId"]);
      if (text === null || messageId === null) return null;
      return { kind: "thinking", text, messageId };
    }
    case "tool_call": {
      const toolUseId = str(v["toolUseId"]);
      const tool = str(v["tool"]);
      const inputPreview = str(v["inputPreview"]);
      if (toolUseId === null || tool === null || inputPreview === null) return null;
      if (typeof v["truncated"] !== "boolean") return null;
      const parent = str(v["parentToolUseId"]);
      const base = { kind: "tool_call", toolUseId, tool, inputPreview, truncated: v["truncated"] } as const;
      return parent === null ? base : { ...base, parentToolUseId: parent };
    }
    case "tool_result": {
      const toolUseId = str(v["toolUseId"]);
      const tool = str(v["tool"]);
      const outputPreview = str(v["outputPreview"]);
      const status = str(v["status"]);
      if (toolUseId === null || tool === null || outputPreview === null) return null;
      if (status !== "ok" && status !== "error" && status !== "denied") return null;
      if (typeof v["truncated"] !== "boolean") return null;
      const base = {
        kind: "tool_result",
        toolUseId,
        tool,
        status,
        outputPreview,
        truncated: v["truncated"],
      } as const;
      const durationMs = num(v["durationMs"]);
      return durationMs === null ? base : { ...base, durationMs };
    }
    case "usage": {
      const model = str(v["model"]);
      const inputTokens = num(v["inputTokens"]);
      const outputTokens = num(v["outputTokens"]);
      const cacheReadInputTokens = num(v["cacheReadInputTokens"]);
      const cacheCreationInputTokens = num(v["cacheCreationInputTokens"]);
      if (
        model === null ||
        inputTokens === null ||
        outputTokens === null ||
        cacheReadInputTokens === null ||
        cacheCreationInputTokens === null
      ) {
        return null;
      }
      const base = {
        kind: "usage",
        model,
        inputTokens,
        outputTokens,
        cacheReadInputTokens,
        cacheCreationInputTokens,
      } as const;
      const costUsd = num(v["costUsd"]);
      return costUsd === null ? base : { ...base, costUsd };
    }
    case "done": {
      const reason = str(v["reason"]);
      const turns = num(v["turns"]);
      if (reason === null || !DONE_REASONS.has(reason) || turns === null) return null;
      const summary = str(v["summary"]);
      const base = { kind: "done", reason: reason as RunnerDoneReason, turns } as const;
      return summary === null ? base : { ...base, summary };
    }
    case "error": {
      const code = str(v["code"]);
      const message = str(v["message"]);
      if (code === null || !ERROR_CODES.has(code) || message === null) return null;
      if (typeof v["retryable"] !== "boolean") return null;
      return {
        kind: "error",
        code: code as RunnerErrorCode,
        message,
        retryable: v["retryable"],
      };
    }
    case "notice": {
      const level = str(v["level"]);
      const message = str(v["message"]);
      if ((level !== "info" && level !== "warn") || message === null) return null;
      return { kind: "notice", level, message };
    }
    default:
      return null;
  }
}

/** Parse one runner -> host line body. Null means "drop it". */
export function parseRunnerToHost(body: string): RunnerToHost | null {
  let raw: unknown;
  try {
    raw = JSON.parse(body);
  } catch {
    return null;
  }
  if (!isRecord(raw)) return null;
  switch (str(raw["t"])) {
    case "ready": {
      const v = num(raw["v"]);
      return v === null ? null : { t: "ready", v };
    }
    case "event": {
      const e = parseRunnerEventPayload(raw["e"]);
      return e === null ? null : { t: "event", e };
    }
    case "state": {
      const state = str(raw["state"]);
      if (state !== "running" && state !== "idle") return null;
      return { t: "state", state };
    }
    case "tool": {
      const id = str(raw["id"]);
      const tool = str(raw["tool"]);
      const paths = strArray(raw["paths"]);
      if (id === null || tool === null || paths === null) return null;
      const input = isRecord(raw["input"]) ? raw["input"] : null;
      return { t: "tool", id, tool, paths, input };
    }
    case "fatal": {
      const code = str(raw["code"]);
      const message = str(raw["message"]);
      if (code === null || !ERROR_CODES.has(code) || message === null) return null;
      const detail = str(raw["detail"]);
      const base = { t: "fatal", code: code as RunnerErrorCode, message } as const;
      return detail === null ? base : { ...base, detail };
    }
    default:
      return null;
  }
}

/** Parse one host -> runner line body. Null means "drop it". */
export function parseHostToRunner(body: string): HostToRunner | null {
  let raw: unknown;
  try {
    raw = JSON.parse(body);
  } catch {
    return null;
  }
  if (!isRecord(raw)) return null;
  switch (str(raw["t"])) {
    case "start": {
      const spec = parseRunnerStartSpec(raw["spec"]);
      return spec === null ? null : { t: "start", spec };
    }
    case "prompt": {
      const text = str(raw["text"]);
      return text === null ? null : { t: "prompt", text };
    }
    case "interrupt":
      return { t: "interrupt" };
    case "stop":
      return { t: "stop" };
    case "gate": {
      const id = str(raw["id"]);
      const decision = str(raw["decision"]);
      if (id === null) return null;
      if (decision === "allow") return { t: "gate", id, decision: "allow" };
      if (decision === "deny") {
        const reason = str(raw["reason"]) ?? "denied";
        return { t: "gate", id, decision: "deny", reason };
      }
      return null;
    }
    default:
      return null;
  }
}

function parseRunnerStartSpec(v: unknown): RunnerStartSpec | null {
  if (!isRecord(v)) return null;
  const version = num(v["v"]);
  const task = str(v["task"]);
  const repoRoot = str(v["repoRoot"]);
  const model = str(v["model"]);
  const effort = str(v["effort"]);
  const allowedTools = strArray(v["allowedTools"]);
  const deniedTools = strArray(v["deniedTools"]);
  const maxTurns = num(v["maxTurns"]);
  const gateTimeoutMs = num(v["gateTimeoutMs"]);
  const broker = v["broker"];
  if (
    version === null ||
    task === null ||
    repoRoot === null ||
    model === null ||
    allowedTools === null ||
    deniedTools === null ||
    maxTurns === null ||
    gateTimeoutMs === null ||
    typeof v["gate"] !== "boolean" ||
    !isRecord(broker)
  ) {
    return null;
  }
  if (effort !== "low" && effort !== "medium" && effort !== "high" && effort !== "xhigh") return null;
  const baseUrl = str(broker["baseUrl"]);
  const capabilityToken = str(broker["capabilityToken"]);
  if (baseUrl === null || capabilityToken === null) return null;

  const base: RunnerStartSpec = {
    v: version,
    task,
    repoRoot,
    model,
    effort,
    allowedTools,
    deniedTools,
    maxTurns,
    gate: v["gate"],
    gateTimeoutMs,
    broker: { baseUrl, capabilityToken },
  };
  const systemPromptAppend = str(v["systemPromptAppend"]);
  const fallbackModel = str(v["fallbackModel"]);
  const maxCostUsd = num(v["maxCostUsd"]);
  return {
    ...base,
    ...(systemPromptAppend === null ? {} : { systemPromptAppend }),
    ...(fallbackModel === null ? {} : { fallbackModel }),
    ...(maxCostUsd === null ? {} : { maxCostUsd }),
  };
}
