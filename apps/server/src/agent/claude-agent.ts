/**
 * `ClaudeAgentProvider` — `AgentProvider` (provider.ts) over the Claude Agent
 * SDK, with the SDK itself running INSIDE the workspace container.
 *
 * ============================================================================
 * WHERE THE SDK IS, AND WHY IT IS NOT HERE
 * ============================================================================
 * This file imports nothing from `@anthropic-ai/claude-agent-sdk` and must not
 * start. The harness lives in `apps/agent-runner`, baked into the workspace
 * image; this file drives it over a framed stdio protocol
 * (`./runner-protocol.ts`) and translates what comes back into `AgentEvent`.
 *
 * Three reasons, in descending order of how expensive they would be to undo:
 *
 *  1. **The seam.** `provider.ts` exists so a local model or a second vendor is
 *     a config change rather than a refactor. That only holds if exactly one
 *     module knows what an `SDKMessage` is. That module is the runner.
 *  2. **The credential boundary (D1).** The agent must be pointed at the broker
 *     with a capability token and nothing else. Running the harness on the host
 *     would put the model call on the side of the boundary where the real key
 *     lives, which is the failure this whole milestone exists to prevent.
 *  3. **The binary.** The SDK's CLI is a ~210 MB per-platform native binary.
 *     The host here is Windows and the container is musl Linux; a host
 *     `node_modules` bind-mounted in would fail at spawn every time. It is
 *     installed into the image (docker/workspace.Dockerfile), outside
 *     `/workspace` so the agent cannot rewrite its own runner.
 *
 * ============================================================================
 * WHAT THIS FILE DOES NOT DO
 * ============================================================================
 * It does not authorize anything. Starting an agent is code execution inside a
 * container (SECURITY.md T8); authorization happens at the authorized HTTP
 * route and at the websocket upgrade, in the order `gateway.ts` and
 * `terminal.ts` already use (T6), BEFORE a call reaches `start()`. Nothing here
 * re-derives a workspace from a request parameter (T5) — `spec.workspaceId` and
 * `spec.repoRoot` arrive already resolved, exactly as `WorkspaceSandboxes`
 * hands them out.
 *
 * It does not enforce a budget. `AgentLimits` is a UX affordance; the
 * authoritative ceiling is the broker's ledger, outside the container (T10).
 *
 * It does not log prompts, transcript bodies, or credentials (T9). It logs ids,
 * event kinds, counts, durations, and — for the M4 seam — tool names with their
 * declared target paths.
 */

import { StringDecoder } from "node:string_decoder";

import type { AgentEvent, AgentIdentity, AgentSessionState } from "@atrium/shared";

import type { SandboxBinding, SandboxLocator } from "../realtime/terminal-registry.ts";
import type { PtyHandle } from "../sandbox/provider.ts";
import { AgentSessionError, redactAgentText } from "./errors.ts";
import { AgentEventStream, type AgentEventDraft, type DistributiveOmit } from "./event-stream.ts";
import type {
  AgentGateDecision,
  AgentHandle,
  AgentProvider,
  AgentSessionId,
  AgentSpec,
  AgentToolGate,
} from "./provider.ts";
import {
  RUNNER_PROTOCOL_VERSION,
  RunnerLineReader,
  encodeRunnerLine,
  parseRunnerToHost,
  type HostToRunner,
  type RunnerEventPayload,
  type RunnerStartSpec,
  type RunnerToHost,
} from "./runner-protocol.ts";

/* ==========================================================================
 * The seam's compile-time proof
 * ==========================================================================
 * `runner-protocol.ts` restates the `AgentEvent` union minus the three fields
 * the server owns, because it must compile in a package that resolves nothing
 * but the SDK. That restatement is only safe if it cannot silently drift, so it
 * is asserted in BOTH directions here. Add a field to `AgentEvent` in
 * @atrium/shared and this file stops compiling until the runner protocol
 * matches — which is the point.
 */
type SharedEventDraft = DistributiveOmit<AgentEvent, "seq" | "agentId" | "at">;
type RunnerCoversShared = RunnerEventPayload extends SharedEventDraft ? true : never;
type SharedCoversRunner = SharedEventDraft extends RunnerEventPayload ? true : never;
export const RUNNER_EVENT_CONFORMANCE: readonly [RunnerCoversShared, SharedCoversRunner] = [true, true];

/* ==========================================================================
 * Launching the runner
 * ========================================================================== */

/** Where the image puts the runner. Outside /workspace: the agent cannot edit it. */
export const RUNNER_ENTRY_PATH = "/opt/atrium-runner/src/index.ts";

/**
 * The pty command that starts the runner.
 *
 * `stty raw -echo` FIRST, and it is load-bearing rather than tidy. A pty in its
 * default line discipline echoes every byte the host writes straight back onto
 * the output stream, translates \n to \r\n, and turns 0x03 into SIGINT — so a
 * JSON control channel over a cooked pty reads its own frames back as input and
 * dies on the first prompt containing a control character. `exec` replaces the
 * shell rather than forking, so the pid that `LocalDockerProvider` recorded for
 * `kill()` is the runner's own.
 *
 * Type stripping (`--experimental-strip-types`) rather than a build step: the
 * runner is TypeScript with `erasableSyntaxOnly` on, the same way `apps/server`
 * runs in dev, so the image ships source and no compiler.
 */
export const RUNNER_LAUNCH_ARGV: readonly string[] = [
  "/bin/sh",
  "-c",
  `stty raw -echo 2>/dev/null; exec node --no-warnings --experimental-strip-types ${RUNNER_ENTRY_PATH}`,
];

/**
 * Model policy defaults (PLAN.md §10.0), exported as CONFIG rather than used as
 * a fallback.
 *
 * `AgentModelPolicy.model` is documented "never defaulted in code", and this
 * provider honours that: it reads `spec.models.coding.model` and rejects an
 * empty one. These constants exist so the one place that builds a spec — the
 * authorized POST route — has a named source for them instead of a string
 * literal, and so a self-hosted deployment pointing at a local endpoint changes
 * a config value rather than a code path.
 *
 * Coding runs the strong model because agent quality *is* the product's
 * experience and a cheap model that needs three attempts is not cheap.
 * Background is for genuinely mechanical work — summarising a transcript,
 * naming a pane — at roughly a fifth the price. THIS PROVIDER MAKES NO
 * BACKGROUND CALL in M3b: there is no summariser yet, so `spec.models.background`
 * is carried and unused. When M5's transcript summariser lands it must read
 * that field, not a literal.
 */
export const AGENT_MODEL_DEFAULTS = {
  coding: { model: "claude-opus-5", effort: "high" },
  background: { model: "claude-haiku-4-5", effort: "low" },
} as const;

/* ==========================================================================
 * Options
 * ========================================================================== */

export interface AgentLogger {
  info(obj: Record<string, unknown>, msg: string): void;
  warn(obj: Record<string, unknown>, msg: string): void;
}

export interface ClaudeAgentProviderOptions {
  /** Looks a workspace up. Never creates one — that is the orchestrator's job. */
  readonly sandboxes: SandboxLocator;
  readonly log: AgentLogger;
  /** Ceiling on concurrent sessions per workspace. Bounds container PIDs (T10). */
  readonly maxSessionsPerWorkspace?: number;
  /** How long to wait for the runner's `ready` line. Node boot, not the CLI. */
  readonly readyTimeoutMs?: number;
  /** How long to wait for the harness's first `started` event after `ready`. */
  readonly startTimeoutMs?: number;
  /** Grace given to a `stop` before the runner is killed. */
  readonly stopGraceMs?: number;
  /** Advisory gate reply deadline handed to the runner. Fail-open, by design. */
  readonly gateTimeoutMs?: number;
  /** Replay ring depth per session. */
  readonly ringEvents?: number;
}

const DEFAULT_MAX_SESSIONS = 4;
const DEFAULT_READY_TIMEOUT_MS = 30_000;
const DEFAULT_START_TIMEOUT_MS = 90_000;
const DEFAULT_STOP_GRACE_MS = 4_000;
const DEFAULT_GATE_TIMEOUT_MS = 2_000;
/** Finished sessions kept readable for a reattaching pane. Durable replay is M5. */
const RETAINED_TERMINATED = 8;

/* ==========================================================================
 * One session
 * ========================================================================== */

type TerminalState = "stopped" | "failed";

class ClaudeAgentSession {
  readonly sessionId: AgentSessionId;
  readonly workspaceId: string;
  readonly identity: AgentIdentity;
  readonly model: string;
  readonly startedAt = new Date();
  readonly stream: AgentEventStream;

  readonly #spec: AgentSpec;
  readonly #log: AgentLogger;
  readonly #pty: PtyHandle;
  readonly #decoder = new StringDecoder("utf8");
  readonly #reader = new RunnerLineReader();
  readonly #options: Required<
    Pick<ClaudeAgentProviderOptions, "stopGraceMs" | "gateTimeoutMs" | "startTimeoutMs">
  >;
  /** Every secret this session could accidentally echo. For `redactAgentText`. */
  readonly #secrets: readonly string[];

  #state: AgentSessionState = "starting";
  #turns = 0;
  #turnTimer: NodeJS.Timeout | null = null;
  #stopPromise: Promise<void> | null = null;
  #onReady: (() => void) | null = null;
  #onStarted: (() => void) | null = null;
  #onFatal: ((err: AgentSessionError) => void) | null = null;
  #abortGates: AbortController = new AbortController();

  constructor(init: {
    spec: AgentSpec;
    pty: PtyHandle;
    log: AgentLogger;
    ringEvents: number | undefined;
    stopGraceMs: number;
    gateTimeoutMs: number;
    startTimeoutMs: number;
  }) {
    this.#spec = init.spec;
    this.#pty = init.pty;
    this.#log = init.log;
    this.sessionId = init.spec.sessionId;
    this.workspaceId = init.spec.workspaceId;
    this.identity = init.spec.identity;
    this.model = init.spec.models.coding.model;
    this.#secrets = [init.spec.broker.capabilityToken];
    this.#options = {
      stopGraceMs: init.stopGraceMs,
      gateTimeoutMs: init.gateTimeoutMs,
      startTimeoutMs: init.startTimeoutMs,
    };
    this.stream = new AgentEventStream(
      init.ringEvents === undefined
        ? { agentId: init.spec.sessionId }
        : { agentId: init.spec.sessionId, ringEvents: init.ringEvents },
    );

    this.#pty.onData((chunk) => this.#onChunk(chunk));
    void this.#pty.exited.then(() => this.#onPtyExit());
  }

  get state(): AgentSessionState {
    return this.#state;
  }

  /**
   * READ-THROUGH, as `AgentHandle` requires: `state` and `lastSeq` are
   * accessors, not values captured when the handle was minted.
   *
   * This is load-bearing rather than pedantic. The transport keeps ONE handle
   * for the whole life of a session (`realtime/agent-session.ts` stores what
   * `start()` returned), so a snapshot would pin `handle.state` to "starting"
   * forever and every state the transport cannot re-derive from the event
   * stream — a session that failed, say — would read wrong in every pane.
   */
  get handle(): AgentHandle {
    // Captured because `this` inside the getters below is the returned object.
    const session = this;
    return {
      sessionId: this.sessionId,
      workspaceId: this.workspaceId,
      identity: this.identity,
      model: this.model,
      startedAt: this.startedAt,
      get state(): AgentSessionState {
        return session.#state;
      },
      get lastSeq(): number {
        return session.stream.lastSeq;
      },
    };
  }

  get terminated(): boolean {
    return this.#state === "stopped" || this.#state === "failed";
  }

  /* ------------------------------------------------------------ handshake */

  /** Resolves when the runner has raw-mode stdio and is listening. */
  waitForReady(timeoutMs: number): Promise<void> {
    return this.#await("the agent runner did not start inside the workspace", timeoutMs, (resolve) => {
      this.#onReady = resolve;
    });
  }

  /** Resolves when the harness itself came up and emitted `started`. */
  waitForStarted(): Promise<void> {
    return this.#await(
      "the agent harness did not start inside the workspace",
      this.#options.startTimeoutMs,
      (resolve) => {
        this.#onStarted = resolve;
      },
    );
  }

  #await(
    timeoutMessage: string,
    timeoutMs: number,
    register: (resolve: () => void) => void,
  ): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      let settled = false;
      const done = (err?: AgentSessionError): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.#onFatal = null;
        if (err === undefined) resolve();
        else reject(err);
      };
      const timer = setTimeout(
        () => done(new AgentSessionError("harness-unavailable", timeoutMessage)),
        timeoutMs,
      );
      this.#onFatal = (err) => done(err);
      register(() => done());
    });
  }

  /* --------------------------------------------------------------- output */

  #onChunk(chunk: Uint8Array): void {
    const text = this.#decoder.write(Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength));
    if (text.length === 0) return;
    for (const body of this.#reader.push(text)) {
      const message = parseRunnerToHost(body);
      // A frame the parser did not return is dropped, not guessed at. The
      // runner is inside the hostile half of the boundary (T6).
      if (message === null) continue;
      this.#onRunnerMessage(message);
    }
  }

  #onRunnerMessage(message: RunnerToHost): void {
    switch (message.t) {
      case "ready": {
        if (message.v !== RUNNER_PROTOCOL_VERSION) {
          this.#fail(
            new AgentSessionError(
              "version-mismatch",
              "the agent runner in this workspace image speaks a different protocol version",
            ),
          );
          return;
        }
        this.#onReady?.();
        this.#onReady = null;
        return;
      }
      case "event": {
        this.#onEvent(message.e);
        return;
      }
      case "state": {
        this.#setState(message.state === "running" ? "running" : "idle");
        return;
      }
      case "tool": {
        this.#onToolCall(message.id, message.tool, message.paths, message.input);
        return;
      }
      case "fatal": {
        this.#fail(new AgentSessionError(message.code, message.message, message.detail));
        return;
      }
      default:
        return;
    }
  }

  #onEvent(payload: RunnerEventPayload): void {
    if (payload.kind === "started") {
      const waiter = this.#onStarted;
      this.#onStarted = null;
      waiter?.();
    }
    if (payload.kind === "done") this.#turns = payload.turns;
    // The runner's payload is the contract's event minus the three fields the
    // server owns. `RUNNER_EVENT_CONFORMANCE` above is what makes this cast a
    // proof rather than a hope.
    this.stream.publish(payload as AgentEventDraft);
  }

  /* ------------------------------------------- the advisory gate + M4 seam */

  /**
   * A PreToolUse observation from the runner.
   *
   * TWO THINGS HAPPEN HERE AND ONLY ONE OF THEM IS A CONTROL.
   *
   * The log line is the durable one: tool name plus the paths the tool
   * DECLARED, which is what M4's claims table will be reconciled against. No
   * tool input body is logged (T9) — the input is passed to the gate in memory
   * and dropped.
   *
   * The gate reply is ADVISORY (SECURITY.md D5, T7; PLAN.md §5 layer 1). It runs
   * in the agent's own process on the far side of the boundary and is bypassable
   * with one `Bash` call, so nothing may depend on it. It exists for feedback:
   * a refusal that reaches the agent before the write produces a legible
   * transcript instead of a merge rejection three minutes later.
   *
   * >>> M4 SLOTS IN AT `AgentSpec.gate`. <<<
   * No change to this file, the runner, or the wire protocol is needed: M4
   * supplies an `AgentToolGate` closed over the claims table, and `paths` below
   * is the argument it wants. `paths` is EMPTY for `Bash` — a shell command
   * declares nothing — which is precisely why layer 2 (the overlayfs merge gate,
   * outside the container) is the authoritative half and this is not.
   */
  #onToolCall(
    id: string,
    tool: string,
    paths: readonly string[],
    input: Readonly<Record<string, unknown>> | null,
  ): void {
    this.#log.info(
      {
        agentId: this.sessionId,
        workspaceId: this.workspaceId,
        tool,
        paths,
        pathCount: paths.length,
      },
      "agent tool call",
    );

    const gate: AgentToolGate | undefined = this.#spec.gate;
    if (gate === undefined) {
      this.#write({ t: "gate", id, decision: "allow" });
      return;
    }
    void gate({
      sessionId: this.sessionId,
      tool,
      input: input ?? {},
      signal: this.#abortGates.signal,
    }).then(
      (decision: AgentGateDecision) => {
        this.#write(
          decision.decision === "allow"
            ? { t: "gate", id, decision: "allow" }
            : { t: "gate", id, decision: "deny", reason: decision.reason },
        );
      },
      () => {
        // A gate that throws is a broken advisory layer, not a denial. Fail
        // open and say so in the pane's chrome rather than wedging the agent.
        this.#write({ t: "gate", id, decision: "allow" });
        this.stream.publish({
          kind: "notice",
          level: "warn",
          message: "the advisory claim check failed and the tool call was allowed",
        });
      },
    );
  }

  /* ---------------------------------------------------------------- input */

  #write(message: HostToRunner): void {
    if (this.terminated) return;
    this.#pty.write(Buffer.from(encodeRunnerLine(message), "utf8"));
  }

  sendStart(): void {
    const spec = this.#spec;
    const runnerSpec: RunnerStartSpec = {
      v: RUNNER_PROTOCOL_VERSION,
      task: spec.task,
      repoRoot: spec.repoRoot,
      model: spec.models.coding.model,
      effort: spec.models.coding.effort,
      allowedTools: [...spec.tools.allowed],
      deniedTools: [...spec.tools.denied],
      maxTurns: spec.limits.maxTurns,
      gate: spec.gate !== undefined,
      gateTimeoutMs: this.#options.gateTimeoutMs,
      // The two values that cross the boundary, over stdin rather than in the
      // runner's environment. See runner-protocol.ts's TRUST section.
      broker: { baseUrl: spec.broker.baseUrl, capabilityToken: spec.broker.capabilityToken },
      ...(spec.systemPromptAppend === undefined ? {} : { systemPromptAppend: spec.systemPromptAppend }),
      ...(spec.models.coding.fallbackModel === undefined
        ? {}
        : { fallbackModel: spec.models.coding.fallbackModel }),
      ...(spec.limits.maxCostUsd === undefined ? {} : { maxCostUsd: spec.limits.maxCostUsd }),
    };
    this.#write({ t: "start", spec: runnerSpec });
  }

  prompt(text: string): void {
    this.#write({ t: "prompt", text });
    this.#setState("running");
  }

  async interrupt(): Promise<void> {
    if (this.terminated) return;
    if (this.#state === "idle" || this.#state === "starting") return;
    this.#setState("interrupting");
    this.#write({ t: "interrupt" });
  }

  /* ----------------------------------------------------------------- stop */

  /**
   * Terminal and idempotent, and safe to call while `events()` is iterating.
   *
   * The final `done{reason:"stopped"}` is emitted HERE, by the host, rather
   * than being waited for from the runner. A runner that has already crashed,
   * been OOM-killed, or been SIGKILLed cannot emit it, and every attached pane
   * and the event log still need the same ending.
   */
  stop(): Promise<void> {
    if (this.#stopPromise !== null) return this.#stopPromise;
    this.#stopPromise = this.#doStop("stopped");
    return this.#stopPromise;
  }

  async #doStop(final: TerminalState): Promise<void> {
    this.#clearTurnTimer();
    this.#abortGates.abort();
    if (!this.terminated) this.#write({ t: "stop" });
    this.#state = final;

    // Give the runner its graceful path: it interrupts the turn, closes the
    // SDK query (stdin EOF + grace + kill), and kills the CLI's process GROUP.
    // Docker has no "kill exec", so an orphan here is unreachable forever.
    const exited = await Promise.race([
      this.#pty.exited.then(() => true),
      new Promise<boolean>((resolve) => setTimeout(() => resolve(false), this.#options.stopGraceMs)),
    ]);
    if (!exited) {
      this.#log.warn(
        { agentId: this.sessionId, workspaceId: this.workspaceId },
        "agent runner did not exit on stop; killing it",
      );
      this.#pty.kill("SIGKILL");
    }
    await this.#pty.dispose().catch(() => undefined);

    if (!this.stream.closed) {
      this.stream.close({ kind: "done", reason: "stopped", turns: this.#turns });
    }
  }

  /** The runner died on its own, or could not start. */
  #onPtyExit(): void {
    if (this.terminated || this.#stopPromise !== null) return;
    this.#fail(
      new AgentSessionError("harness-unavailable", "the agent runner exited unexpectedly"),
    );
  }

  #fail(error: AgentSessionError): void {
    if (this.terminated) return;
    this.#state = "failed";
    this.#clearTurnTimer();
    this.#abortGates.abort();
    // `detail` is operator-only and never reaches a client. It is redacted
    // before it reaches even the log, because the runner builds it from the
    // harness's stderr and stderr quotes whatever it was handed.
    this.#log.warn(
      {
        agentId: this.sessionId,
        workspaceId: this.workspaceId,
        code: error.code,
        detail: error.detail === undefined ? undefined : redactAgentText(error.detail, this.#secrets),
      },
      "agent session failed",
    );
    const waiter = this.#onFatal;
    this.#onFatal = null;
    if (!this.stream.closed) {
      this.stream.publish({
        kind: "error",
        code: error.code,
        message: error.message,
        retryable: error.code === "upstream-unavailable",
      });
      this.stream.close({ kind: "done", reason: "error", turns: this.#turns });
    }
    void this.#pty.dispose().catch(() => undefined);
    waiter?.(error);
  }

  /* ---------------------------------------------------------------- state */

  #setState(next: AgentSessionState): void {
    if (this.terminated) return;
    if (this.#state === next) return;
    this.#state = next;
    if (next === "running") this.#armTurnTimer();
    else this.#clearTurnTimer();
  }

  /**
   * `AgentLimits.turnTimeoutMs`: exceeding it is an ERROR, not a `done`.
   *
   * A UX affordance, not a control — the authoritative ceiling is the broker's
   * ledger (T10). This exists so a wedged turn ends with something legible in
   * the pane instead of a spinner that never resolves.
   */
  #armTurnTimer(): void {
    this.#clearTurnTimer();
    const ms = this.#spec.limits.turnTimeoutMs;
    if (!Number.isFinite(ms) || ms <= 0) return;
    this.#turnTimer = setTimeout(() => {
      this.#turnTimer = null;
      if (this.terminated) return;
      this.stream.publish({
        kind: "error",
        code: "internal",
        message: "this turn exceeded its time limit and was interrupted",
        retryable: true,
      });
      void this.interrupt();
    }, ms);
    this.#turnTimer.unref();
  }

  #clearTurnTimer(): void {
    if (this.#turnTimer === null) return;
    clearTimeout(this.#turnTimer);
    this.#turnTimer = null;
  }
}

/* ==========================================================================
 * The provider
 * ========================================================================== */

export class ClaudeAgentProvider implements AgentProvider {
  readonly name = "claude-agent-sdk";
  /**
   * Reported, not assumed. The SDK exposes `hooks.PreToolUse` and the runner
   * wires it to `AgentSpec.gate`, so this is honestly true — and it stays
   * ADVISORY regardless (D5). A provider that returns `true` is promising the
   * gate is CALLED, never that it is a boundary.
   */
  readonly supportsToolGate = true;

  readonly #sandboxes: SandboxLocator;
  readonly #log: AgentLogger;
  /**
   * Live sessions, keyed by (workspace, session) — NEVER by the session id
   * alone.
   *
   * The id is chosen by the client: `agent-routes.ts` reads `agentId` out of
   * the POST body and validates only its shape, and the web client passes the
   * pane id. So agent ids are unique per workspace and NOT globally, exactly as
   * `AgentRegistry.existsElsewhere` already documents.
   *
   * Keying this map by the bare id put every workspace in one namespace one
   * layer below the registry, which is correctly scoped. That gave a member of
   * workspace B three things against workspace A purely by naming A's id in a
   * POST to B's OWN workspace: a denial of start (A's live session was found
   * here and rejected as a duplicate), a cross-workspace existence oracle (that
   * rejection is returned only when the id is live SOMEWHERE ELSE, which is the
   * distinction every other path erases), and eviction of A's retained
   * transcript. Scoping the key is what makes the "structurally unreachable"
   * claim in `agent-registry.ts` and `@atrium/shared` true of this layer too.
   */
  readonly #sessions = new Map<string, ClaudeAgentSession>();
  readonly #opts: Required<Omit<ClaudeAgentProviderOptions, "sandboxes" | "log" | "ringEvents">> & {
    ringEvents: number | undefined;
  };

  constructor(options: ClaudeAgentProviderOptions) {
    this.#sandboxes = options.sandboxes;
    this.#log = options.log;
    this.#opts = {
      maxSessionsPerWorkspace: options.maxSessionsPerWorkspace ?? DEFAULT_MAX_SESSIONS,
      readyTimeoutMs: options.readyTimeoutMs ?? DEFAULT_READY_TIMEOUT_MS,
      startTimeoutMs: options.startTimeoutMs ?? DEFAULT_START_TIMEOUT_MS,
      stopGraceMs: options.stopGraceMs ?? DEFAULT_STOP_GRACE_MS,
      gateTimeoutMs: options.gateTimeoutMs ?? DEFAULT_GATE_TIMEOUT_MS,
      ringEvents: options.ringEvents,
    };
  }

  /** Live sessions in a workspace. For the POST route's cap and for /api/health. */
  countForWorkspace(workspaceId: string): number {
    let n = 0;
    for (const session of this.#sessions.values()) {
      if (session.workspaceId === workspaceId && !session.terminated) n += 1;
    }
    return n;
  }

  /** Names already in use in a workspace, so `mintAgentIdentity` avoids them. */
  namesInWorkspace(workspaceId: string): ReadonlySet<string> {
    const names = new Set<string>();
    for (const session of this.#sessions.values()) {
      if (session.workspaceId === workspaceId && !session.terminated) names.add(session.identity.name);
    }
    return names;
  }

  /* ---------------------------------------------------------------- start */

  async start(spec: AgentSpec): Promise<AgentHandle> {
    validateSpec(spec);
    const key = sessionKey(spec.workspaceId, spec.sessionId);
    const previous = this.#sessions.get(key);
    if (previous !== undefined) {
      if (!previous.terminated) {
        throw new AgentSessionError("bad-message", "an agent session with that id already exists");
      }
      // A TERMINATED session under this id is the documented restart: a human
      // pressed delete and then start on the same pane (agent-routes.ts). The
      // finished session is retained here only so a reattaching pane can still
      // read its transcript, and by the time this is reached the caller has
      // already disposed of the transport-side one — so keeping it would turn
      // "restart this agent" into a permanent `bad-message`, which is what it
      // did before this branch existed.
      this.#sessions.delete(key);
    }
    if (this.countForWorkspace(spec.workspaceId) >= this.#opts.maxSessionsPerWorkspace) {
      throw new AgentSessionError(
        "too-many-channels",
        "this workspace already has the maximum number of running agents",
      );
    }

    const binding: SandboxBinding | null = await this.#sandboxes.forWorkspace(spec.workspaceId);
    if (binding === null) {
      throw new AgentSessionError("sandbox-not-running", "this workspace has no running sandbox");
    }

    let pty: PtyHandle;
    try {
      pty = await binding.provider.spawnPty(binding.handle, {
        command: RUNNER_LAUNCH_ARGV,
        cwd: spec.repoRoot,
        // A pty needs a size; nothing here renders, so it is only a SIGWINCH
        // value. Wide enough that a stray un-raw write is not re-wrapped.
        size: { cols: 400, rows: 100 },
        term: "dumb",
        // NOT the place for the broker binding. Anything in the runner's
        // environment is one `/proc/<pid>/environ` read away from the agent;
        // the token travels over stdin instead (runner-protocol.ts, TRUST).
        env: { ATRIUM_AGENT_RUNNER: "1" },
      });
    } catch (err) {
      throw new AgentSessionError(
        "harness-unavailable",
        "the agent runner could not be launched in this workspace",
        err instanceof Error ? err.message : String(err),
      );
    }

    const session = new ClaudeAgentSession({
      spec,
      pty,
      log: this.#log,
      ringEvents: this.#opts.ringEvents,
      stopGraceMs: this.#opts.stopGraceMs,
      gateTimeoutMs: this.#opts.gateTimeoutMs,
      startTimeoutMs: this.#opts.startTimeoutMs,
    });
    this.#sessions.set(key, session);

    try {
      await session.waitForReady(this.#opts.readyTimeoutMs);
      session.sendStart();
      await session.waitForStarted();
    } catch (err) {
      await session.stop().catch(() => undefined);
      this.#sessions.delete(key);
      throw err instanceof AgentSessionError
        ? err
        : new AgentSessionError("harness-unavailable", "the agent harness did not start");
    }

    this.#log.info(
      {
        agentId: spec.sessionId,
        workspaceId: spec.workspaceId,
        model: spec.models.coding.model,
        harness: this.name,
      },
      "agent session started",
    );
    return session.handle;
  }

  /* -------------------------------------------------------------- inspect */

  async inspect(workspaceId: string, sessionId: AgentSessionId): Promise<AgentHandle | null> {
    const session = this.#sessions.get(sessionKey(workspaceId, sessionId));
    return session === undefined ? null : session.handle;
  }

  /* --------------------------------------------------------------- events */

  events(handle: AgentHandle, fromSeq?: number): AsyncIterable<AgentEvent> {
    const session = this.#lookup(handle);
    if (session === undefined) return emptyStream();
    return session.stream.subscribe(fromSeq ?? 0);
  }

  /* ----------------------------------------------------------------- send */

  async send(handle: AgentHandle, text: string): Promise<void> {
    const session = this.#require(handle);
    if (session.terminated) {
      throw new AgentSessionError("agent-not-running", "this agent session has ended");
    }
    if (session.state === "running" || session.state === "interrupting") {
      throw new AgentSessionError("busy", "this agent is mid-turn; interrupt it or wait");
    }
    session.prompt(text);
  }

  /* ------------------------------------------------------------ interrupt */

  async interrupt(handle: AgentHandle): Promise<void> {
    const session = this.#lookup(handle);
    // Idempotent, including for a session that is already gone: a human
    // pressing stop twice is the ordinary case.
    if (session === undefined) return;
    await session.interrupt();
  }

  /* ----------------------------------------------------------------- stop */

  async stop(handle: AgentHandle): Promise<void> {
    const session = this.#lookup(handle);
    if (session === undefined) return;
    await session.stop();
    this.#log.info(
      { agentId: handle.sessionId, workspaceId: session.workspaceId },
      "agent session stopped",
    );
    // The session is NOT deleted here. A pane whose human pressed stop still
    // wants to read the transcript, and a reattach that answers `not-found`
    // makes a finished session look like a lost one. The container process is
    // gone either way; what is retained is a bounded ring of events.
    this.#pruneTerminated(session.workspaceId);
  }

  /**
   * Keep a few finished sessions readable, then let them go.
   *
   * Durable replay is M5, from Postgres. Until then an unbounded map of
   * finished sessions is a slow leak in a long-lived process, so the oldest
   * terminated ones are dropped once there are more than `RETAINED_TERMINATED`.
   *
   * PER WORKSPACE, not globally. A global bound would let one busy workspace
   * evict every other workspace's retained transcripts just by churning panes —
   * a cross-tenant effect from a retention policy, which is the same class of
   * bug as sharing the session namespace.
   */
  #pruneTerminated(workspaceId: string): void {
    const finished = [...this.#sessions.entries()]
      .filter(([, s]) => s.terminated && s.workspaceId === workspaceId)
      .sort((a, b) => a[1].startedAt.getTime() - b[1].startedAt.getTime());
    for (const [key] of finished.slice(0, Math.max(0, finished.length - RETAINED_TERMINATED))) {
      this.#sessions.delete(key);
    }
  }

  /** Stop every session. For process shutdown, so no runner is orphaned. */
  async stopAll(): Promise<void> {
    await Promise.all([...this.#sessions.values()].map((s) => s.stop().catch(() => undefined)));
    this.#sessions.clear();
  }

  /**
   * The ONLY way a handle is turned back into a session.
   *
   * `AgentHandle.workspaceId` is minted by this provider from the spec the
   * orchestrator resolved, so it is server-side data throughout — a caller
   * cannot widen its own scope by handing back an edited handle.
   */
  #lookup(handle: AgentHandle): ClaudeAgentSession | undefined {
    return this.#sessions.get(sessionKey(handle.workspaceId, handle.sessionId));
  }

  #require(handle: AgentHandle): ClaudeAgentSession {
    const session = this.#lookup(handle);
    if (session === undefined) {
      throw new AgentSessionError("not-found", "no such agent session");
    }
    return session;
  }
}

/**
 * Composite key, mirroring `sessionKey` in `realtime/agent-registry.ts`.
 *
 * NUL separator: it cannot occur in a workspace id or an agent id (both match
 * `[A-Za-z0-9_-]{1,64}`), so two different pairs cannot produce one key.
 */
function sessionKey(workspaceId: string, sessionId: AgentSessionId): string {
  return `${workspaceId}\u0000${sessionId}`;
}

/* ==========================================================================
 * Spec validation
 * ========================================================================== */

/**
 * Everything `provider.ts` says `start()` MUST reject with `bad-message`.
 *
 * Note what is NOT validated: membership, ownership, or whether the caller may
 * touch this workspace. That is not this file's job and re-deriving it here
 * would reintroduce T5.
 */
function validateSpec(spec: AgentSpec): void {
  const bad = (message: string): never => {
    throw new AgentSessionError("bad-message", message);
  };
  if (!spec.repoRoot.startsWith("/")) bad("repoRoot must be an absolute path inside the container");
  if (spec.repoRoot.includes("..")) bad("repoRoot must not contain a relative segment");
  if (spec.models.coding.model.trim().length === 0) bad("no coding model was configured");
  if (spec.limits.maxTurns < 1) bad("maxTurns must be at least 1");
  if (spec.broker.capabilityToken.length === 0) bad("no broker capability token was supplied");
  if (spec.broker.expiresAt.getTime() <= Date.now()) bad("the broker capability token has already expired");
  let origin: URL;
  try {
    origin = new URL(spec.broker.baseUrl);
  } catch {
    return bad("the broker base URL is not a URL");
  }
  if (origin.protocol !== "http:" && origin.protocol !== "https:") {
    bad("the broker base URL must be http or https");
  }
}

async function* emptyStream(): AsyncGenerator<AgentEvent> {
  // A handle for a session this provider does not know is not an error path
  // worth throwing on: the caller is a transport that already answered
  // `not-found` at attach time. An empty, immediately-ended stream is the
  // honest answer.
  return;
}
