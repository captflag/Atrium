/**
 * The two HTTP calls behind an agent pane.
 *
 * An agent session runs commands inside the workspace container, so starting
 * one is code execution (SECURITY.md T8) — exactly like a terminal, and treated
 * exactly the same way. The wire protocol in `@atrium/shared/agent.ts` can only
 * ATTACH to a session that already exists; a session comes into being only
 * through the authorized route called here, which repeats authenticate +
 * membership. If a JSON frame could spawn an agent, every member would have RCE
 * by sending one.
 *
 * ============================================================================
 * WHY THIS IS NOT `ensureTerminal` WITH THE NOUN CHANGED
 * ============================================================================
 * A terminal pane ensures its shell on every mount, from every viewer, and a
 * server restart silently re-opens it. That is right for a shell: an empty
 * `sh` costs nothing and does nothing.
 *
 * An agent session is not free and is not idempotent in the way that matters.
 * Re-creating one automatically after a restart would re-run a task — spending
 * money at the broker and modifying the repo — because a pane happened to be
 * open in a tab nobody was looking at. So creation here is explicit:
 *
 *   - `lookupAgent()` (POST with no task) only ever RESOLVES an existing
 *     session. `absent` is a legible UI state ("no session — give it a task"),
 *     not an error and not something to retry into existence.
 *   - `startAgent()` (POST with a task) is the create call, and it happens only
 *     when a human pressed Start. That is the one moment a human asked for the
 *     work, which is the only authority a spend-and-write action should have.
 *
 * Both are idempotent against an EXISTING session — a second viewer of the same
 * pane, or a double-click on Start, resolves the one session rather than
 * spawning a second agent.
 */

import { isValidAgentIdentity } from "@atrium/shared";
import type { AgentIdentity, AgentSessionState } from "@atrium/shared";
import { devIdentityQuery } from "./terminalApi.ts";

/**
 * The development identity shim is shared with the terminal calls on purpose:
 * `devIdentityQuery` has exactly one definition to delete when the upgrade is
 * authorized from a session cookie (SECURITY.md T6, PLAN.md §10 decision #1).
 */

/** Every string here crosses the boundary as text and is rendered as text. */
const AGENT_SESSION_STATES: readonly string[] = [
  "starting",
  "running",
  "idle",
  "interrupting",
  "stopped",
  "failed",
];

export interface AgentSessionSummary {
  readonly agentId: string;
  /** Server-assigned. Validated here because it is about to reach CSS. */
  readonly identity: AgentIdentity | null;
  readonly model: string | null;
  readonly state: AgentSessionState | null;
}

export type AgentRouteResult =
  | { readonly ok: true; readonly session: AgentSessionSummary }
  /** No session exists for this pane. Expected, not a failure. */
  | { readonly ok: false; readonly reason: "absent" }
  | {
      readonly ok: false;
      readonly reason: "failed";
      readonly retryable: boolean;
      readonly message: string;
    };

/**
 * Strips C0/C1 controls and caps the length of a server-supplied string before
 * it is displayed. Contractually these are already safe text, but this is the
 * cheapest possible defence against a server bug turning a status line into an
 * escape sequence, and it costs one pass over a short string.
 */
function safeMessage(raw: unknown, fallback: string): string {
  if (typeof raw !== "string" || raw.trim() === "") return fallback;
  let out = "";
  for (const ch of raw) {
    const code = ch.codePointAt(0) ?? 0;
    out += code < 0x20 || (code >= 0x7f && code <= 0x9f) ? " " : ch;
    if (out.length >= 200) break;
  }
  const trimmed = out.trim();
  return trimmed === "" ? fallback : trimmed;
}

/** `devIdentityQuery` is "&"-prefixed for the socket URLs; this makes it a query. */
function withIdentity(path: string): string {
  const params = devIdentityQuery();
  return params === "" ? path : `${path}?${params.slice(1)}`;
}

/**
 * Reads the session fields off a route response.
 *
 * `identity` goes through `isValidAgentIdentity` rather than being cast: its
 * `colour` is about to become an inline style, and a colour that reached CSS
 * unvalidated would be stored XSS for every teammate (SECURITY.md T6). An
 * identity that does not validate is dropped, not repaired — the pane renders
 * without a name until `attached` supplies one that does.
 */
function readSession(body: unknown, fallbackId: string): AgentSessionSummary {
  const o = (body ?? {}) as Record<string, unknown>;
  const agentId = typeof o["agentId"] === "string" ? o["agentId"] : fallbackId;
  const identity = isValidAgentIdentity(o["identity"]) ? o["identity"] : null;
  const model = typeof o["model"] === "string" ? safeMessage(o["model"], "") : null;
  const state =
    typeof o["state"] === "string" && AGENT_SESSION_STATES.includes(o["state"])
      ? (o["state"] as AgentSessionState)
      : null;
  return { agentId, identity, model: model === "" ? null : model, state };
}

async function postAgents(
  workspaceId: string,
  body: Record<string, unknown>,
  fallbackId: string,
): Promise<AgentRouteResult> {
  let response: Response;
  try {
    response = await fetch(withIdentity(`/api/workspaces/${encodeURIComponent(workspaceId)}/agents`), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch {
    return { ok: false, reason: "failed", retryable: true, message: "server unreachable" };
  }

  let parsed: unknown = null;
  try {
    parsed = await response.json();
  } catch {
    /* an error page rather than JSON, or a 204; the status carries the meaning */
  }

  if (response.ok) return { ok: true, session: readSession(parsed, fallbackId) };

  // 404 is the ordinary "this pane has no session" answer to a lookup, and the
  // same answer an unauthorized caller gets for someone else's session — the
  // server must not distinguish those on the wire (agent.ts, AgentErrorCode).
  if (response.status === 404) return { ok: false, reason: "absent" };

  const message = safeMessage(
    (parsed as { message?: unknown } | null)?.message,
    `could not reach the agent (${response.status})`,
  );
  // 5xx is the sandbox being slow, absent, or Docker being closed — all of
  // which a user fixes without reloading the page. 4xx is a decision.
  return { ok: false, reason: "failed", retryable: response.status >= 500, message };
}

/**
 * Resolve this pane's session WITHOUT creating one.
 *
 * Called on every mount by every viewer. `absent` means the pane is waiting for
 * a task — after a fresh canvas load, or after a server restart took the
 * session with it. Both are the same honest state, and neither silently starts
 * an agent.
 */
export function lookupAgent(workspaceId: string, agentId: string): Promise<AgentRouteResult> {
  return postAgents(workspaceId, { agentId }, agentId);
}

/**
 * Create and start this pane's session. THE AUTHORIZED CALL SITE.
 *
 * `task` is the human's own words and is never logged by this client. It is
 * sent once, at creation; every later turn is a `prompt` on the websocket
 * channel the server hands back, so a follow-up cannot be mistaken for a
 * request to start a second agent.
 */
export function startAgent(
  workspaceId: string,
  agentId: string,
  task: string,
): Promise<AgentRouteResult> {
  return postAgents(workspaceId, { agentId, task }, agentId);
}

/**
 * End a session, because its pane was deleted.
 *
 * Best effort, like `closeTerminal`: a failure leaves a session running
 * server-side, which is the safe direction to fail in (sessions are
 * server-owned, PLAN.md §6) and is visible in `/api/health` as an agent count
 * that does not go down.
 *
 * This stops the SESSION, not the sandbox — terminals and other agents in the
 * same container are unaffected.
 */
export async function deleteAgent(workspaceId: string, agentId: string): Promise<void> {
  try {
    await fetch(
      withIdentity(
        `/api/workspaces/${encodeURIComponent(workspaceId)}/agents/${encodeURIComponent(agentId)}`,
      ),
      { method: "DELETE" },
    );
  } catch {
    /* see above */
  }
}
