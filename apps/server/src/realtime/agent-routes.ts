/**
 * The authorized HTTP surface for agent sessions.
 *
 * ============================================================================
 * WHY THESE ARE ROUTES AND NOT WEBSOCKET MESSAGES
 * ============================================================================
 * Starting an agent is code execution inside the workspace container
 * (SECURITY.md T8). The wire protocol therefore cannot do it: `subscribe` only
 * ever attaches to a session that already exists. Creation and deletion live
 * here, behind the same `authenticate` + `isMember` pair the websocket upgrade
 * uses, in the same order (T6) — exactly the split M2 made for terminals.
 *
 * `POST` is IDEMPOTENT per (workspace, agent), for two reasons. Every viewer of
 * an agent pane calls it, and only one harness may start. And a pane that
 * reloads must not silently start a second agent and spend a second task's
 * worth of tokens (T10) — so a POST naming a session that has already ENDED
 * returns that session and its transcript rather than restarting it. Restarting
 * is DELETE then POST, which is a deliberate act by a human.
 *
 * A POST WITHOUT A TASK IS A LOOKUP and can create nothing: no session, and no
 * container. It answers 404 when the pane has no session, which is how a freshly
 * mounted pane learns to show its composer instead of quietly starting work.
 * See the route below.
 *
 * ============================================================================
 * WHAT THESE ROUTES NEVER RETURN (SECURITY.md T9, D1)
 * ============================================================================
 * No broker base URL, no capability token, no container id, no host path, no
 * environment. Not the task text either: the caller sent it, and echoing it
 * would put it in one more log and one more browser cache for no gain. Failures
 * return a fixed string per code; the operator-facing detail goes to the log.
 *
 * This file is deliberately separate from `index.ts` so the three M3b builders
 * do not collide in one file. `index.ts` calls `registerAgentRoutes(app, …)`
 * once — see the signature at the bottom.
 */

import { AGENT_ID_RE, AGENT_MAX_PROMPT_BYTES, AGENT_NAME_RE, utf8ByteLength } from "@atrium/shared";
import type { FastifyInstance } from "fastify";
import type { Principal } from "../identity.ts";
import { isSandboxError } from "../sandbox/errors.ts";
import { AgentOpenError, summarize, type AgentRegistry } from "./agent-registry.ts";
import type { AgentLogger } from "./agent-session.ts";
import type { SandboxBinding } from "./terminal-registry.ts";

/**
 * The workspace-scoped authorization used by every route in `index.ts`.
 *
 * Structurally identical to the `authorize` closure that already exists there,
 * so wiring is `registerAgentRoutes(app, { …, authorize })` with no adapter.
 * Authorization is NOT re-implemented here on purpose: two implementations of
 * one check is how they drift.
 */
export type AgentAuthorize = (
  req: { headers: Record<string, string | string[] | undefined>; url: string },
  workspaceId: string,
) => Promise<{ ok: true; principal: Principal } | { ok: false; status: number; error: string }>;

/**
 * The orchestrator's create-or-adopt entry point (`WorkspaceSandboxes.ensure`).
 *
 * Narrowed to the one method these routes may call. The registry itself only
 * gets a `SandboxLocator`, which cannot create a container — deciding that a
 * container should exist is an orchestrator decision reachable from an
 * authorized route and from nowhere else.
 */
export interface WorkspaceSandboxEnsure {
  ensure(workspaceId: string): Promise<SandboxBinding>;
}

export interface AgentRoutesOptions {
  readonly registry: AgentRegistry;
  readonly sandboxes: WorkspaceSandboxEnsure;
  readonly authorize: AgentAuthorize;
  readonly log: AgentLogger;
}

const WORKSPACE_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

/**
 * Registers `POST`, `DELETE` and `GET /api/workspaces/:workspaceId/agents`.
 *
 * Call once, from `index.ts`, after the registry exists.
 */
export function registerAgentRoutes(app: FastifyInstance, options: AgentRoutesOptions): void {
  const { registry, sandboxes, authorize, log } = options;

  /**
   * Start an agent for a pane, or resolve the one it already has. THE
   * AUTHORIZED CALL SITE.
   *
   * The wire protocol can only ever attach to a session that already exists
   * (agent-registry.ts); this is where one comes into being.
   *
   * TWO SHAPES, AND THE DIFFERENCE IS LOAD-BEARING:
   *
   *   { agentId }         LOOK UP ONLY. Returns the session if this pane has
   *                       one, and 404 `not-found` if it does not. Never
   *                       creates anything — not a session, and not a
   *                       container. This is what every viewer calls on mount,
   *                       and 404 is a legible UI state ("give me a task"),
   *                       not an error.
   *   { agentId, task }   CREATE-OR-RESOLVE. The only path that may start an
   *                       agent, and it exists because a human pressed Start.
   *
   * A pane that mounted must not be able to spend money or write to the repo
   * on its own: a terminal re-opens a free, idle shell after a restart, but
   * re-running a TASK because a tab was left open is a different act. When a
   * session already exists, `task` is ignored rather than queued — the second
   * viewer of a pane, and a double-clicked Start, both resolve the one session.
   */
  app.post<{ Params: { workspaceId: string }; Body: unknown }>(
    "/api/workspaces/:workspaceId/agents",
    async (req, reply) => {
      const { workspaceId } = req.params;
      const auth = await authorize(req, workspaceId);
      if (!auth.ok) return reply.code(auth.status).send({ error: auth.error });

      const body = (req.body ?? {}) as Record<string, unknown>;
      const agentId = body["agentId"];
      if (typeof agentId !== "string" || !AGENT_ID_RE.test(agentId)) {
        return reply.code(400).send({ error: "invalid-agent-id" });
      }
      const task = body["task"];
      if (task !== undefined && typeof task !== "string") {
        return reply.code(400).send({ error: "invalid-task", message: "A task must be text." });
      }
      if (task === undefined || task.trim().length === 0) {
        // Workspace-scoped lookup: a member of one workspace cannot resolve
        // another's session, and "no such session" and "not yours" are the
        // same answer on the wire (agent.ts, AgentErrorCode).
        const existing = registry.get(workspaceId, agentId);
        if (existing === null) return reply.code(404).send({ error: "not-found" });
        return reply.send(summarize(existing));
      }
      if (utf8ByteLength(task) > AGENT_MAX_PROMPT_BYTES) {
        return reply.code(413).send({ error: "invalid-task", message: "That task is too long." });
      }
      const name = body["name"];
      if (name !== undefined && (typeof name !== "string" || !AGENT_NAME_RE.test(name))) {
        // A name reaches every teammate's presence list, so it is validated
        // rather than trusted — see AgentIdentity in @atrium/shared.
        return reply.code(400).send({ error: "invalid-agent-name" });
      }

      try {
        const binding = await sandboxes.ensure(workspaceId);
        const session = await registry.open(workspaceId, agentId, {
          task,
          ...(name === undefined ? {} : { name }),
        });
        return reply.send({
          ...summarize(session),
          // The user is entitled to know the box is softer than the docs say
          // (SandboxHandle.unenforced, SECURITY.md T3).
          unenforced: binding.handle.unenforced,
        });
      } catch (error: unknown) {
        return replyAgentError(reply, error, { workspaceId, agentId }, log);
      }
    },
  );

  /**
   * End an agent session. Called when an agent pane is deleted, and when a
   * human wants to restart one.
   *
   * Sessions are server-owned (PLAN.md §6), so nothing else ever ends them: a
   * pane removed from the canvas with its harness left running is a leak that
   * keeps spending.
   */
  app.delete<{ Params: { workspaceId: string; agentId: string } }>(
    "/api/workspaces/:workspaceId/agents/:agentId",
    async (req, reply) => {
      const { workspaceId, agentId } = req.params;
      const auth = await authorize(req, workspaceId);
      if (!auth.ok) return reply.code(auth.status).send({ error: auth.error });
      if (!AGENT_ID_RE.test(agentId)) {
        return reply.code(400).send({ error: "invalid-agent-id" });
      }
      // Workspace-scoped, so a member of one workspace cannot end another's.
      await registry.close(workspaceId, agentId);
      return reply.code(204).send();
    },
  );

  /**
   * List this workspace's agent sessions.
   *
   * How a canvas rehydrates after a reload without POSTing (and therefore
   * without risking a start). Workspace-scoped and authorized identically;
   * summaries carry identity, model and state, never a transcript.
   */
  app.get<{ Params: { workspaceId: string } }>(
    "/api/workspaces/:workspaceId/agents",
    async (req, reply) => {
      const { workspaceId } = req.params;
      const auth = await authorize(req, workspaceId);
      if (!auth.ok) return reply.code(auth.status).send({ error: auth.error });
      if (!WORKSPACE_ID_RE.test(workspaceId)) {
        return reply.code(400).send({ error: "invalid-workspace" });
      }
      return reply.send({ agents: registry.list(workspaceId) });
    },
  );
}

/**
 * Turn a registry or orchestrator failure into a status and a SHORT, curated
 * message.
 *
 * The thrown message is operator-facing and may quote a harness or a daemon
 * error (SECURITY.md T9), so it goes to the log and never to the client. Shaped
 * to match `replyTerminalError` in index.ts, including the one hint a developer
 * will actually need.
 */
function replyAgentError(
  reply: { code(status: number): { send(body: unknown): unknown } },
  error: unknown,
  context: { workspaceId: string; agentId: string },
  log: AgentLogger,
): unknown {
  const detail = error instanceof Error ? error.message : "unknown";
  log.warn({ ...context, err: detail }, "failed to start agent");

  if (error instanceof AgentOpenError) {
    switch (error.code) {
      case "sandbox-not-running":
        return reply
          .code(503)
          .send({ error: error.code, message: "The workspace sandbox is not running." });
      case "too-many-agents":
        return reply
          .code(429)
          .send({ error: error.code, message: "This workspace has too many agents running." });
      case "invalid-id":
        return reply.code(400).send({ error: error.code, message: "Invalid agent id or name." });
      case "invalid-task":
        return reply.code(400).send({ error: error.code, message: "That task cannot be run." });
      case "harness-unavailable":
        return reply
          .code(503)
          .send({ error: error.code, message: "The agent harness is not available in this workspace." });
      case "upstream-unavailable":
        return reply
          .code(503)
          .send({ error: error.code, message: "The model service could not be reached." });
      case "budget-exhausted":
        return reply.code(429).send({
          error: error.code,
          message: "This workspace has reached its model budget. Raise the cap to continue.",
        });
      default:
        return reply
          .code(500)
          .send({ error: "internal", message: "Could not start an agent in the sandbox." });
    }
  }

  if (isSandboxError(error)) {
    if (error.code === "backend-unavailable") {
      return reply
        .code(503)
        .send({ error: error.code, message: "Docker is not reachable. Start Docker Desktop." });
    }
    if (error.code === "invalid-spec") {
      return reply.code(503).send({
        error: error.code,
        message:
          "The workspace image is not built. Run: docker build -f docker/workspace.Dockerfile -t atrium/workspace-base:m2 .",
      });
    }
    return reply
      .code(503)
      .send({ error: error.code, message: "The workspace sandbox is unavailable." });
  }

  return reply.code(500).send({ error: "internal", message: "Could not start the agent." });
}
