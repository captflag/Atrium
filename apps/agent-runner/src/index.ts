/**
 * The agent runner. THIS PROCESS EXECUTES INSIDE THE WORKSPACE CONTAINER.
 *
 * It is the only file in Atrium that imports `@anthropic-ai/claude-agent-sdk`.
 * Everything it produces leaves as `RunnerEventPayload` on stdout, which the
 * host stamps into the contract's `AgentEvent` union. If an SDK type ever
 * appears in a signature outside this file, the seam in
 * `apps/server/src/agent/provider.ts` has failed.
 *
 * ============================================================================
 * THE CREDENTIAL BOUNDARY (SECURITY.md D1, T2) — THE POINT OF THIS MILESTONE
 * ============================================================================
 * There is no provider credential here and there must never be one. The SDK
 * spawns a Claude Code subprocess and takes an `env` option whose documented
 * behaviour is REPLACE, not merge — so `buildHarnessEnv` below constructs the
 * subprocess environment from nothing and lists every variable explicitly.
 * Three of them matter:
 *
 *   ANTHROPIC_BASE_URL         the broker sidecar, reachable only on
 *                              `atrium-internal`, holding the real key
 *   ANTHROPIC_CUSTOM_HEADERS   `x-atrium-capability: <token>` — the header the
 *                              broker authenticates on. The SDK's own bundle
 *                              lists this as the documented companion of a
 *                              gateway base URL.
 *   ANTHROPIC_AUTH_TOKEN       the SAME capability token. Claude Code refuses
 *                              to start without an auth env var, and this is
 *                              the one value we have that is safe to give it:
 *                              scoped to one workspace, short-lived, and
 *                              stripped by the broker before the upstream call
 *                              (asserted by scripts/probe-broker.mjs).
 *
 * The token reaches this process over STDIN, in the `start` message, and is
 * never in this process's own environment. `/proc/<pid>/environ` is readable by
 * anything running as the same uid, and the agent runs as the same uid. Stdin
 * is not readable that way. The token is unavoidably in the CLI subprocess's
 * environment — that is what it is for — but nothing wider is.
 *
 * ============================================================================
 * WHAT THE REPO IS NOT ALLOWED TO CONFIGURE (SECURITY.md T1)
 * ============================================================================
 * The repo in `/workspace` is attacker-influenceable. By default the CLI reads
 * configuration out of it. Three options below are security settings, not
 * preferences:
 *
 *   settingSources: []     without it the CLI loads the repo's CLAUDE.md and
 *                          .claude/settings.json — repo content becoming our
 *                          agent's instructions AND its permission policy.
 *   mcpServers: {}         + strictMcpConfig: true, or the repo's .mcp.json
 *                          defines servers the agent connects to: repo-
 *                          controlled config becoming agent capability.
 *   permissionMode         'acceptEdits', never 'bypassPermissions'. The
 *                          container is the boundary; the permission mode is
 *                          where the advisory claim gate lands, and turning it
 *                          off removes the layer for no gain.
 *
 * ============================================================================
 * T9 — WHAT IS NEVER LOGGED
 * ============================================================================
 * This process writes NOTHING to stdout except framed protocol lines, and
 * nothing to stderr at all in the normal path. No prompt, no transcript body,
 * no token. The CLI's stderr is captured into a bounded ring and surfaced only
 * inside a `fatal` message's `detail`, with the capability token redacted,
 * because the alternative — "the harness would not start, no idea why" — is
 * worse for the operator and the string never reaches a client.
 */

import { spawn } from "node:child_process";
import { query } from "@anthropic-ai/claude-agent-sdk";
import type {
  HookCallback,
  HookJSONOutput,
  Options,
  PreToolUseHookInput,
  Query,
  SDKAssistantMessage,
  SDKMessage,
  SDKResultMessage,
  SDKUserMessage,
  SpawnedProcess,
  SpawnOptions,
} from "@anthropic-ai/claude-agent-sdk";

import {
  RUNNER_MAX_GATE_INPUT_BYTES,
  RUNNER_PROTOCOL_VERSION,
  RunnerLineReader,
  encodeRunnerLine,
  parseHostToRunner,
  type HostToRunner,
  type RunnerEventPayload,
  type RunnerStartSpec,
  type RunnerToHost,
} from "./protocol.ts";

/* ==========================================================================
 * Caps. Mirrors of the constants in @atrium/shared, restated here because this
 * package deliberately resolves nothing at runtime except the SDK (see
 * protocol.ts's header). The host re-clamps everything anyway; these keep a
 * single oversized frame from ever leaving the container.
 * ========================================================================== */

const MAX_TEXT_CHUNK_BYTES = 16 * 1024;
const MAX_TOOL_PREVIEW_BYTES = 4 * 1024;
const STDERR_RING_BYTES = 8 * 1024;
const INTERRUPT_SETTLE_MS = 5_000;

/** The subset of `RunnerErrorCode` a harness failure can legitimately be. */
type FatalCode = "upstream-unavailable" | "harness-unavailable" | "budget-exhausted" | "internal";

/* ==========================================================================
 * stdout: framed protocol lines, nothing else
 * ========================================================================== */

function out(message: RunnerToHost): void {
  process.stdout.write(encodeRunnerLine(message));
}

function emit(payload: RunnerEventPayload): void {
  out({ t: "event", e: payload });
}

function notice(level: "info" | "warn", message: string): void {
  emit({ kind: "notice", level, message });
}

/** Cut a string to a UTF-8 byte budget without splitting a code point. */
function clampUtf8(value: string, maxBytes: number): { text: string; truncated: boolean } {
  const buf = Buffer.from(value, "utf8");
  if (buf.byteLength <= maxBytes) return { text: value, truncated: false };
  let end = maxBytes;
  // Walk back off a continuation byte so the slice ends on a boundary.
  while (end > 0 && (buf[end] !== undefined && (buf[end] as number) >= 0x80) && (buf[end] as number) < 0xc0) {
    end -= 1;
  }
  return { text: buf.subarray(0, end).toString("utf8"), truncated: true };
}

/** Split long prose into contract-sized chunks, marking only the last final. */
function emitText(
  text: string,
  messageId: string,
  parentToolUseId: string | null,
): void {
  const buf = Buffer.from(text, "utf8");
  if (buf.byteLength === 0) return;
  const parts: string[] = [];
  let rest = text;
  while (rest.length > 0) {
    const cut = clampUtf8(rest, MAX_TEXT_CHUNK_BYTES);
    if (!cut.truncated) {
      parts.push(rest);
      break;
    }
    // clampUtf8 can return an empty slice only for a single code point larger
    // than the budget, which cannot happen at 16 KiB. Guard anyway.
    const piece = cut.text.length > 0 ? cut.text : rest.slice(0, 1);
    parts.push(piece);
    rest = rest.slice(piece.length);
  }
  parts.forEach((piece, i) => {
    const final = i === parts.length - 1;
    emit(
      parentToolUseId === null
        ? { kind: "text", text: piece, final, messageId }
        : { kind: "text", text: piece, final, messageId, parentToolUseId },
    );
  });
}

/* ==========================================================================
 * The environment the harness subprocess gets — and NOTHING else
 * ========================================================================== */

/**
 * Build the Claude Code subprocess environment from scratch.
 *
 * `Options.env` REPLACES the child environment rather than merging, which is
 * exactly the behaviour this boundary wants: nothing leaks in by inheritance,
 * and every variable below had to be typed out on purpose.
 *
 * PATH/HOME/LANG are inherited values, not secrets — but they are read from
 * this process's env one key at a time rather than spread, so that adding a
 * variable is a visible edit here.
 */
function buildHarnessEnv(spec: RunnerStartSpec): Record<string, string> {
  return {
    PATH: process.env["PATH"] ?? "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    HOME: process.env["HOME"] ?? "/home/atrium",
    LANG: process.env["LANG"] ?? "C.UTF-8",
    TMPDIR: process.env["TMPDIR"] ?? "/tmp",

    // --- the credential boundary, and the only two secret-shaped values ---
    ANTHROPIC_BASE_URL: spec.broker.baseUrl,
    ANTHROPIC_CUSTOM_HEADERS: `x-atrium-capability: ${spec.broker.capabilityToken}`,
    ANTHROPIC_AUTH_TOKEN: spec.broker.capabilityToken,

    // Egress is deny-by-default and the broker allowlists three paths. Telemetry
    // and marketplace calls would not 403 cleanly, they would HANG — which reads
    // to a user as "the agent is thinking" for as long as the timeout.
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
    DISABLE_AUTOUPDATER: "1",
    DISABLE_TELEMETRY: "1",
    DISABLE_ERROR_REPORTING: "1",
    CI: "1",
    TERM: "dumb",
  };
}

/* ==========================================================================
 * The advisory tool gate + the M4 seam
 * ==========================================================================
 * READ THIS BEFORE TREATING THE HOOK BELOW AS A CONTROL.
 *
 * It is ADVISORY AND NOT A SECURITY BOUNDARY (SECURITY.md D5, T7; PLAN.md §5
 * layer 1). It runs inside the agent's own process. A prompt-injected agent
 * does not need the `Write` tool — it has `Bash`, and `echo ... > src/auth.ts`
 * goes around every in-process hook ever written. Authoritative claim
 * enforcement is M4's per-agent overlayfs upper layer, merged down by the
 * orchestrator OUTSIDE the container, where the kernel does the interception.
 *
 * What it is good for is feedback: a refusal that reaches the agent BEFORE the
 * write produces a clean error and a legible transcript instead of a merge
 * rejection three minutes later.
 *
 * >>> THE M4 SEAM IS `AgentSpec.gate` ON THE HOST. <<<
 * Every PreToolUse call is reported to the host as a `tool` message carrying
 * the tool name and its DECLARED target paths. When the host has a gate, it
 * answers `allow` or `deny`; M4 implements that host-side function against the
 * claims table and nothing in this file changes. Note the honest limit already
 * visible here: `declaredPaths` returns [] for `Bash`, because a shell command
 * has no declared paths. That gap is not a bug to fix in the hook — it is the
 * reason layer 2 exists.
 *
 * FAIL-OPEN, DELIBERATELY. If the host does not answer within
 * `gateTimeoutMs` the call is allowed. An advisory layer that can wedge the
 * agent when the transport hiccups is worse than no advisory layer, and the
 * authoritative gate is elsewhere.
 */

/** Target paths a tool DECLARES in its input. Empty is a real answer. */
function declaredPaths(tool: string, input: unknown): string[] {
  if (typeof input !== "object" || input === null) return [];
  const rec = input as Record<string, unknown>;
  const found: string[] = [];
  const take = (v: unknown): void => {
    if (typeof v === "string" && v.length > 0 && v.length <= 4096) found.push(v);
  };
  take(rec["file_path"]);
  take(rec["path"]);
  take(rec["notebook_path"]);
  const edits = rec["edits"];
  if (Array.isArray(edits)) {
    for (const edit of edits.slice(0, 64)) {
      if (typeof edit === "object" && edit !== null) take((edit as Record<string, unknown>)["file_path"]);
    }
  }
  const paths = rec["paths"];
  if (Array.isArray(paths)) for (const p of paths.slice(0, 64)) take(p);
  // Bash, WebFetch and friends declare nothing. Reported as [] on purpose; see
  // the block comment above.
  void tool;
  return [...new Set(found)];
}

/* ==========================================================================
 * The session
 * ========================================================================== */

type GateWaiter = (decision: { allow: true } | { allow: false; reason: string }) => void;

class RunnerSession {
  readonly #spec: RunnerStartSpec;
  readonly #abort = new AbortController();
  readonly #gateWaiters = new Map<string, GateWaiter>();
  readonly #stderrRing: string[] = [];
  #stderrBytes = 0;
  #gateCounter = 0;

  /** Resolves the streaming-input iterator's next prompt. */
  #pushPrompt: ((message: SDKUserMessage) => void) | null = null;
  #closePrompts: (() => void) | null = null;

  #query: Query | null = null;
  /** pid of the Claude Code CLI, captured via `spawnClaudeCodeProcess`. */
  #harnessPid: number | null = null;
  #turns = 0;
  #interruptRequested = false;
  #stopping = false;
  #ended = false;
  /** Tool name by tool_use_id, so a tool_result can name the tool it answers. */
  readonly #toolNames = new Map<string, string>();
  readonly #toolStarts = new Map<string, number>();
  /**
   * tool_use_ids the advisory gate refused, so the resulting tool_result is
   * classified as `denied` rather than `error`.
   *
   * The id is the authoritative link: `PreToolUseHookInput.tool_use_id` is the
   * same id the assistant's `tool_use` block carries, so a refusal we issued is
   * recognised by identity. The alternative — pattern-matching the harness's
   * error text for our own reason string — silently reclassifies every refusal
   * as a generic tool failure the moment M4 words a denial differently, and the
   * pane's distinction between "the claim gate refused this" and "this tool
   * broke" is exactly what a human needs to see.
   */
  readonly #deniedToolUseIds = new Set<string>();

  constructor(spec: RunnerStartSpec) {
    this.#spec = spec;
  }

  /* ---------------------------------------------------------------- input */

  prompt(text: string): void {
    const push = this.#pushPrompt;
    if (push === null) return;
    push({
      type: "user",
      message: { role: "user", content: text },
      parent_tool_use_id: null,
    });
  }

  gateReply(id: string, decision: { allow: true } | { allow: false; reason: string }): void {
    const waiter = this.#gateWaiters.get(id);
    if (waiter === undefined) return;
    this.#gateWaiters.delete(id);
    waiter(decision);
  }

  /* ------------------------------------------------------------ interrupt */

  /**
   * Stop the current turn. The session survives and returns to idle.
   *
   * `Query.interrupt()` is the SDK's own path and only exists in streaming-input
   * mode, which is why the prompt source below is an AsyncIterable rather than a
   * string. Idempotent: interrupting an idle session is a no-op that resolves.
   */
  async interrupt(): Promise<void> {
    const q = this.#query;
    if (q === null || this.#ended) return;
    this.#interruptRequested = true;
    try {
      await q.interrupt();
    } catch {
      // A turn that ended between the check and the call is not an error.
    }
    // If the SDK produces no result for the aborted turn, close the turn out
    // ourselves so the pane does not sit on a caret forever.
    setTimeout(() => {
      if (this.#interruptRequested && !this.#ended) {
        this.#interruptRequested = false;
        emit({ kind: "done", reason: "interrupted", turns: this.#turns });
        out({ t: "state", state: "idle" });
      }
    }, INTERRUPT_SETTLE_MS).unref();
  }

  /**
   * End the session and tear the harness down. Terminal and idempotent.
   *
   * Docker has no "kill exec", so an orphaned process inside the container is
   * unreachable forever. Three teardown steps, in order, because each catches
   * what the previous one misses:
   *   1. `Query.close()` — the SDK's own cleanup: stdin EOF, grace, then kill.
   *   2. `abortController.abort()` — the backstop the SDK documents.
   *   3. `kill(-pid)` on the CLI's process GROUP — the one that gets the tools
   *      the agent spawned. `spawnClaudeCodeProcess` below starts the CLI
   *      detached precisely so this group exists and is addressable.
   */
  async stop(): Promise<void> {
    if (this.#stopping) return;
    this.#stopping = true;
    const q = this.#query;
    if (q !== null) {
      try {
        await q.interrupt();
      } catch {
        /* already over */
      }
      try {
        q.close();
      } catch {
        /* already closed */
      }
    }
    this.#closePrompts?.();
    this.#abort.abort();
    this.#killHarnessGroup("SIGTERM");
    setTimeout(() => this.#killHarnessGroup("SIGKILL"), 1_500).unref();
  }

  #killHarnessGroup(signal: NodeJS.Signals): void {
    const pid = this.#harnessPid;
    if (pid === null) return;
    try {
      // Negative pid = the whole process group. `detached: true` at spawn is
      // what makes the CLI a group leader, so this reaches the tools it forked.
      process.kill(-pid, signal);
    } catch {
      /* already reaped */
    }
  }

  /* ------------------------------------------------------------------ run */

  async run(): Promise<void> {
    const options = this.#buildOptions();
    let q: Query;
    try {
      q = query({ prompt: this.#promptSource(), options });
    } catch (err) {
      this.#fatal("harness-unavailable", "the agent harness could not be started", err);
      return;
    }
    this.#query = q;

    try {
      out({ t: "state", state: "running" });
      for await (const message of q) {
        this.#onMessage(message);
      }
    } catch (err) {
      if (this.#stopping) return;
      this.#fatal(fatalCode(err), "the agent harness stopped unexpectedly", err);
      return;
    }
    if (!this.#stopping) {
      // The generator ended without a stop: the CLI exited on its own.
      this.#ended = true;
      emit({ kind: "done", reason: "completed", turns: this.#turns });
      out({ t: "state", state: "idle" });
    }
  }

  #fatal(code: FatalCode, message: string, err: unknown): void {
    this.#ended = true;
    const raw = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
    const detail = this.#redact([raw, ...this.#stderrRing].join(" | ").slice(0, 4096));
    out({ t: "fatal", code, message, detail });
  }

  /** Blank the capability token anywhere it might have been echoed back. */
  #redact(text: string): string {
    const token = this.#spec.broker.capabilityToken;
    return token.length >= 4 ? text.split(token).join("<redacted>") : text;
  }

  /* ------------------------------------------------------------- SDK glue */

  /**
   * The prompt source. An AsyncIterable, not a string, because STREAMING INPUT
   * MODE is the only mode where `Query.interrupt()` and follow-up turns work —
   * and a pane a human types into twice is the ordinary case, not the edge one.
   */
  async *#promptSource(): AsyncGenerator<SDKUserMessage> {
    const queue: SDKUserMessage[] = [
      {
        type: "user",
        message: { role: "user", content: this.#spec.task },
        parent_tool_use_id: null,
      },
    ];
    let wake: (() => void) | null = null;
    let closed = false;
    this.#pushPrompt = (m) => {
      queue.push(m);
      wake?.();
    };
    this.#closePrompts = () => {
      closed = true;
      wake?.();
    };
    for (;;) {
      const next = queue.shift();
      if (next !== undefined) {
        yield next;
        continue;
      }
      if (closed) return;
      await new Promise<void>((resolve) => {
        wake = () => {
          wake = null;
          resolve();
        };
      });
    }
  }

  #buildOptions(): Options {
    const spec = this.#spec;
    const options: Options = {
      model: spec.model,
      effort: spec.effort,
      cwd: spec.repoRoot,
      env: buildHarnessEnv(spec),
      allowedTools: [...spec.allowedTools],
      disallowedTools: [...spec.deniedTools],

      // --- the three settings that are security, not preference (T1) ---
      settingSources: [],
      mcpServers: {},
      strictMcpConfig: true,
      permissionMode: "acceptEdits",

      maxTurns: spec.maxTurns,
      abortController: this.#abort,
      includePartialMessages: false,
      // HOME is a tmpfs; a session JSONL written there dies with the container
      // and is not the durable transcript. Durable replay is M5, from Postgres.
      persistSession: false,
      stderr: (data: string) => this.#captureStderr(data),
      hooks: { PreToolUse: [{ hooks: [this.#preToolUse] }] },
      spawnClaudeCodeProcess: (o: SpawnOptions) => this.#spawnHarness(o),
    };
    // exactOptionalPropertyTypes: an absent option and an option set to
    // undefined are different things to the SDK, so add these only when real.
    if (spec.fallbackModel !== undefined) options.fallbackModel = spec.fallbackModel;
    if (spec.maxCostUsd !== undefined) options.maxBudgetUsd = spec.maxCostUsd;
    options.systemPrompt =
      spec.systemPromptAppend === undefined
        ? { type: "preset", preset: "claude_code" }
        : { type: "preset", preset: "claude_code", append: spec.systemPromptAppend };
    return options;
  }

  /**
   * Spawn the Claude Code CLI ourselves.
   *
   * Two reasons this is not left to the SDK's default:
   *   1. `detached: true` makes the CLI a process-group leader, so `stop()` can
   *      kill the GROUP. Killing only the CLI leaves the `Bash` tool's children
   *      running inside a container that has no way to address them.
   *   2. Explicit `stdio: ["pipe","pipe","pipe"]` guarantees the CLI — and
   *      therefore every tool it forks — never inherits this process's pty. The
   *      protocol channel is not reachable from inside the agent, so the agent
   *      cannot forge a frame.
   */
  #spawnHarness(o: SpawnOptions): SpawnedProcess {
    const child = spawn(o.command, o.args, {
      cwd: o.cwd ?? this.#spec.repoRoot,
      env: o.env,
      stdio: ["pipe", "pipe", "pipe"],
      detached: true,
      windowsHide: true,
    });
    this.#harnessPid = child.pid ?? null;
    child.stderr?.setEncoding("utf8");
    child.stderr?.on("data", (chunk: string) => this.#captureStderr(chunk));
    o.signal.addEventListener(
      "abort",
      () => {
        try {
          child.kill("SIGTERM");
        } catch {
          /* already gone */
        }
      },
      { once: true },
    );
    // ChildProcess already satisfies SpawnedProcess; the cast is the SDK's own
    // documented contract ("ChildProcess already satisfies this interface")
    // rather than a shortcut around a mismatch.
    return child as unknown as SpawnedProcess;
  }

  /** Bounded ring. Never emitted as an event; `fatal.detail` only, redacted. */
  #captureStderr(data: string): void {
    this.#stderrRing.push(data);
    this.#stderrBytes += data.length;
    while (this.#stderrBytes > STDERR_RING_BYTES && this.#stderrRing.length > 1) {
      const dropped = this.#stderrRing.shift();
      this.#stderrBytes -= dropped?.length ?? 0;
    }
  }

  /* -------------------------------------------------------- the tool hook */

  readonly #preToolUse: HookCallback = async (input, _toolUseId, opts): Promise<HookJSONOutput> => {
    if (input.hook_event_name !== "PreToolUse") return {};
    const pre = input as PreToolUseHookInput;
    const id = `g${(this.#gateCounter += 1)}`;
    const paths = declaredPaths(pre.tool_name, pre.tool_input);

    // ALWAYS reported, gate or no gate. This is the operator-side record of
    // what the agent touched and the seam M4's claim check slots into.
    const serialized = JSON.stringify(pre.tool_input ?? {});
    const small =
      typeof serialized === "string" && Buffer.byteLength(serialized, "utf8") <= RUNNER_MAX_GATE_INPUT_BYTES;
    out({
      t: "tool",
      id,
      tool: pre.tool_name,
      paths,
      input: small && typeof pre.tool_input === "object" && pre.tool_input !== null
        ? (pre.tool_input as Record<string, unknown>)
        : null,
    });

    if (!this.#spec.gate) return {};

    const decision = await this.#awaitGate(id, opts.signal);
    if (decision.allow) return {};
    // Remember the refusal by tool_use_id so #onUser can label the result
    // `denied` without reading the harness's error prose. Bounded: a denial
    // whose tool_result never arrives would otherwise accumulate for the life
    // of the session.
    this.#deniedToolUseIds.add(pre.tool_use_id);
    while (this.#deniedToolUseIds.size > 256) {
      const oldest = this.#deniedToolUseIds.values().next();
      if (oldest.done === true) break;
      this.#deniedToolUseIds.delete(oldest.value);
    }
    return {
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason: decision.reason,
      },
    };
  };

  #awaitGate(
    id: string,
    signal: AbortSignal,
  ): Promise<{ allow: true } | { allow: false; reason: string }> {
    return new Promise((resolve) => {
      let settled = false;
      const finish = (d: { allow: true } | { allow: false; reason: string }): void => {
        if (settled) return;
        settled = true;
        this.#gateWaiters.delete(id);
        clearTimeout(timer);
        resolve(d);
      };
      // FAIL-OPEN. See the block comment above `declaredPaths`.
      const timer = setTimeout(() => finish({ allow: true }), this.#spec.gateTimeoutMs);
      timer.unref();
      signal.addEventListener("abort", () => finish({ allow: true }), { once: true });
      this.#gateWaiters.set(id, finish);
    });
  }

  /* ------------------------------------------------------ message mapping */

  #onMessage(message: SDKMessage): void {
    switch (message.type) {
      case "system":
        this.#onSystem(message);
        return;
      case "assistant":
        this.#onAssistant(message);
        return;
      case "user":
        this.#onUser(message);
        return;
      case "result":
        this.#onResult(message);
        return;
      default:
        // The SDKMessage union has 40 members and grows. Everything not mapped
        // above is chrome we deliberately do not surface; silently ignoring it
        // is correct, and inventing an event for it would put unmapped harness
        // internals on a human's screen.
        return;
    }
  }

  #onSystem(message: Extract<SDKMessage, { type: "system" }>): void {
    if (message.subtype === "init") {
      emit({
        kind: "started",
        model: message.model,
        cwd: message.cwd,
        tools: message.tools,
        harness: "claude-agent-sdk",
      });
      // apiKeySource tells us how the CLI decided to authenticate. Anything
      // other than a bearer/none path would mean an API key got in somehow, so
      // it is worth one line of chrome in the pane.
      if (message.apiKeySource === "ANTHROPIC_API_KEY") {
        notice("warn", "harness authenticated with an API key environment variable");
      }
      return;
    }
    if (message.subtype === "session_state_changed") {
      // The .d.ts calls 'idle' the authoritative turn-over signal, so drive
      // state from it rather than inferring from result messages.
      if (message.state === "idle") out({ t: "state", state: "idle" });
      else if (message.state === "running") out({ t: "state", state: "running" });
      return;
    }
  }

  #onAssistant(message: SDKAssistantMessage): void {
    const parent = message.parent_tool_use_id;
    const messageId = message.message.id;
    const content = message.message.content;
    if (!Array.isArray(content)) return;
    for (const block of content) {
      if (block.type === "text") {
        emitText(block.text, messageId, parent);
      } else if (block.type === "thinking") {
        emit({ kind: "thinking", text: block.thinking, messageId });
      } else if (block.type === "tool_use") {
        this.#toolNames.set(block.id, block.name);
        this.#toolStarts.set(block.id, Date.now());
        const preview = clampUtf8(safeJson(block.input), MAX_TOOL_PREVIEW_BYTES);
        emit(
          parent === null
            ? {
                kind: "tool_call",
                toolUseId: block.id,
                tool: block.name,
                inputPreview: preview.text,
                truncated: preview.truncated,
              }
            : {
                kind: "tool_call",
                toolUseId: block.id,
                tool: block.name,
                inputPreview: preview.text,
                truncated: preview.truncated,
                parentToolUseId: parent,
              },
        );
      }
    }
    if (message.aborted === true) {
      notice("info", "the current turn was interrupted");
    }
  }

  #onUser(message: SDKUserMessage): void {
    const content = message.message.content;
    if (!Array.isArray(content)) return;
    for (const block of content) {
      if (typeof block !== "object" || block === null) continue;
      const rec = block as unknown as Record<string, unknown>;
      if (rec["type"] !== "tool_result") continue;
      const toolUseId = typeof rec["tool_use_id"] === "string" ? rec["tool_use_id"] : "";
      if (toolUseId === "") continue;
      const tool = this.#toolNames.get(toolUseId) ?? "tool";
      const isError = rec["is_error"] === true;
      const started = this.#toolStarts.get(toolUseId);
      this.#toolStarts.delete(toolUseId);
      const preview = clampUtf8(toolResultText(rec["content"]), MAX_TOOL_PREVIEW_BYTES);
      // A gate refusal is not a tool failure, and the contract has a separate
      // status for it. `#deniedToolUseIds` is the authoritative answer: this
      // process issued that refusal and recorded the id it issued it against.
      // The text match is a fallback only, for a harness that surfaces a denial
      // under an id we never saw — it must never be the primary signal, because
      // it would classify by the wording of a message rather than by what
      // happened.
      const denied = this.#deniedToolUseIds.delete(toolUseId)
        ? true
        : isError && /denied by atrium/i.test(preview.text);
      const base = {
        kind: "tool_result",
        toolUseId,
        tool,
        status: denied ? ("denied" as const) : isError ? ("error" as const) : ("ok" as const),
        outputPreview: preview.text,
        truncated: preview.truncated,
      } as const;
      emit(started === undefined ? base : { ...base, durationMs: Date.now() - started });
    }
  }

  #onResult(message: SDKResultMessage): void {
    this.#turns = message.num_turns;

    // CUMULATIVE, per the .d.ts: each result carries the running total, so the
    // host reads the latest and never sums. modelUsage is the field to account
    // from — `usage` is main-loop only and excludes subagents.
    for (const [model, usage] of Object.entries(message.modelUsage)) {
      const base = {
        kind: "usage",
        model,
        inputTokens: usage.inputTokens,
        outputTokens: usage.outputTokens,
        cacheReadInputTokens: usage.cacheReadInputTokens,
        cacheCreationInputTokens: usage.cacheCreationInputTokens,
      } as const;
      emit(typeof usage.costUSD === "number" ? { ...base, costUsd: usage.costUSD } : base);
    }

    const interrupted = this.#interruptRequested;
    this.#interruptRequested = false;

    if (message.subtype === "success") {
      if (message.is_error) {
        emit({
          kind: "error",
          code: "upstream-unavailable",
          message: "the model call failed",
          retryable: true,
        });
      } else {
        const summary = clampUtf8(message.result, MAX_TEXT_CHUNK_BYTES).text;
        const reason = interrupted ? ("interrupted" as const) : ("completed" as const);
        emit(
          summary.length === 0
            ? { kind: "done", reason, turns: message.num_turns }
            : { kind: "done", reason, turns: message.num_turns, summary },
        );
      }
    } else if (message.subtype === "error_max_turns") {
      emit({ kind: "done", reason: "max-turns", turns: message.num_turns });
    } else if (message.subtype === "error_max_budget_usd") {
      emit({ kind: "done", reason: "budget-exhausted", turns: message.num_turns });
    } else {
      emit({
        kind: "done",
        reason: interrupted ? "interrupted" : "error",
        turns: message.num_turns,
      });
      if (!interrupted) {
        emit({
          kind: "error",
          code: "internal",
          message: "the agent turn ended with an error",
          retryable: true,
        });
      }
    }
    out({ t: "state", state: "idle" });
  }
}

/* ==========================================================================
 * Helpers
 * ========================================================================== */

/**
 * Map a thrown harness failure onto a code the pane can act on.
 *
 * The broker allowlists exactly three upstream paths and refuses everything
 * else with a 403; egress off `atrium-internal` does not exist. Both of those
 * must read as a legible `upstream-unavailable` rather than a hang or a generic
 * `internal`, which is the whole reason this function pattern-matches instead
 * of returning "internal" for everything.
 */
function fatalCode(err: unknown): FatalCode {
  const text = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
  if (/ECONNREFUSED|ENOTFOUND|EAI_AGAIN|ENETUNREACH|fetch failed|socket hang up/i.test(text)) {
    return "upstream-unavailable";
  }
  if (/\b(401|403)\b|authentication_error|permission_error/i.test(text)) return "upstream-unavailable";
  if (/\b429\b|rate_limit|budget/i.test(text)) return "budget-exhausted";
  if (/ENOENT|failed to launch|libc|spawn|ELF|exec format/i.test(text)) return "harness-unavailable";
  return "internal";
}

function safeJson(value: unknown): string {
  try {
    return JSON.stringify(value) ?? "";
  } catch {
    return "";
  }
}

/** Flatten a tool_result `content` (string or block array) to display text. */
function toolResultText(content: unknown): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  const parts: string[] = [];
  for (const block of content) {
    if (typeof block === "string") {
      parts.push(block);
    } else if (typeof block === "object" && block !== null) {
      const rec = block as Record<string, unknown>;
      if (typeof rec["text"] === "string") parts.push(rec["text"]);
      else if (typeof rec["type"] === "string") parts.push(`[${rec["type"]}]`);
    }
  }
  return parts.join("\n");
}

/* ==========================================================================
 * Entry point
 * ========================================================================== */

function main(): void {
  let session: RunnerSession | null = null;
  const reader = new RunnerLineReader();

  const dispatch = (message: HostToRunner): void => {
    switch (message.t) {
      case "start": {
        if (session !== null) return;
        if (message.spec.v !== RUNNER_PROTOCOL_VERSION) {
          out({
            t: "fatal",
            code: "version-mismatch",
            message: "the agent runner speaks a different protocol version",
          });
          process.exitCode = 2;
          return;
        }
        session = new RunnerSession(message.spec);
        void session.run().then(
          () => finish(0),
          () => finish(1),
        );
        return;
      }
      case "prompt":
        session?.prompt(message.text);
        return;
      case "interrupt":
        void session?.interrupt();
        return;
      case "stop":
        void shutdown();
        return;
      case "gate":
        session?.gateReply(
          message.id,
          message.decision === "allow" ? { allow: true } : { allow: false, reason: message.reason },
        );
        return;
      default:
        return;
    }
  };

  let finishing = false;
  const finish = (code: number): void => {
    if (finishing) return;
    finishing = true;
    process.exitCode = code;
    // Give the pty a tick to flush the last frames before the fd closes.
    setTimeout(() => process.exit(code), 50).unref();
  };

  const shutdown = async (): Promise<void> => {
    await session?.stop();
    finish(0);
  };

  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk: string) => {
    for (const body of reader.push(chunk)) {
      const parsed = parseHostToRunner(body);
      // A frame this parser did not return is never acted on (T6). The host is
      // the trusted end here, but a malformed frame is still a bug, not input.
      if (parsed !== null) dispatch(parsed);
    }
  });
  process.stdin.on("end", () => void shutdown());
  process.on("SIGTERM", () => void shutdown());
  process.on("SIGINT", () => void shutdown());

  // `ready` is the handshake. The launch command runs `stty raw -echo` before
  // exec'ing node, so by the time this line is written the pty no longer echoes
  // the host's frames back at it. The host sends nothing until it arrives.
  out({ t: "ready", v: RUNNER_PROTOCOL_VERSION });
}

main();
