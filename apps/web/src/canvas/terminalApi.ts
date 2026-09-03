/**
 * The two HTTP calls behind a terminal pane.
 *
 * A terminal is CREATED by the server, never by the wire protocol: `subscribe`
 * can only attach to a session that already exists (see the server's
 * terminal-registry.ts — if a socket message could spawn a shell, every member
 * would have remote code execution by JSON). So a pane asks the orchestrator to
 * open one over an authorized route first, and only then connects its socket.
 *
 * Both calls are idempotent, which is what makes them safe to fire from every
 * viewer of the same pane: the server returns the one existing session.
 */

/**
 * Identity query parameters, mirroring the websocket gateways'.
 *
 * DEVELOPMENT SHIM. `DevIdentityProvider` reads `uid`/`name` off the URL, so
 * every authorized call has to carry them. This reads the identity `useRoom`
 * minted for the tab and never mints one itself. When the upgrade is authorized
 * from a session cookie (SECURITY.md T6, PLAN.md §10 decision #1) this function
 * and both of its call sites go away, and a client-supplied user id stops being
 * something the server would ever believe.
 */
export function devIdentityQuery(): string {
  try {
    const saved = sessionStorage.getItem("atrium.identity");
    if (saved === null) return "";
    const parsed = JSON.parse(saved) as { userId?: unknown; name?: unknown };
    if (typeof parsed.userId !== "string" || typeof parsed.name !== "string") return "";
    return `&uid=${encodeURIComponent(parsed.userId)}&name=${encodeURIComponent(parsed.name)}`;
  } catch {
    return "";
  }
}

export type EnsureTerminalResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly retryable: boolean; readonly message: string };

/** Server messages are contractually text, but they still go through this. */
function safeMessage(raw: unknown, fallback: string): string {
  if (typeof raw !== "string" || raw.trim() === "") return fallback;
  let out = "";
  for (const ch of raw) {
    const code = ch.codePointAt(0) ?? 0;
    out += code < 0x20 || (code >= 0x7f && code <= 0x9f) ? " " : ch;
    if (out.length >= 200) break;
  }
  return out.trim();
}

/** `devIdentityQuery` is "&"-prefixed for the socket URLs; this makes it a query. */
function withIdentity(path: string): string {
  const params = devIdentityQuery();
  return params === "" ? path : `${path}?${params.slice(1)}`;
}

/**
 * Ask the orchestrator to open this pane's shell. Resolves `ok` when a session
 * exists — whether this call created it or found it.
 *
 * `retryable` is the server's transport-level truth: a sandbox that is not
 * running yet, or a Docker daemon that is not up, is worth retrying on the
 * pane's existing backoff; a rejected id or a full workspace is not.
 */
export async function ensureTerminal(
  workspaceId: string,
  terminalId: string,
): Promise<EnsureTerminalResult> {
  let response: Response;
  try {
    response = await fetch(withIdentity(`/api/workspaces/${encodeURIComponent(workspaceId)}/terminals`), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ terminalId }),
    });
  } catch {
    return { ok: false, retryable: true, message: "server unreachable" };
  }

  if (response.ok) return { ok: true };

  let body: unknown = null;
  try {
    body = await response.json();
  } catch {
    /* an error page rather than JSON; the status is enough */
  }
  const message = safeMessage(
    (body as { message?: unknown } | null)?.message,
    `could not open the terminal (${response.status})`,
  );
  // 5xx is the sandbox being slow, absent, or Docker being closed — all of
  // which a user fixes without reloading the page. 4xx is a decision.
  return { ok: false, retryable: response.status >= 500, message };
}

/**
 * Close a terminal, because its pane was deleted.
 *
 * Best effort: a failure leaves a shell running server-side, which is the safe
 * direction to fail in (sessions are server-owned) and is visible in
 * `/api/health` as a terminal count that does not go down.
 */
export async function closeTerminal(workspaceId: string, terminalId: string): Promise<void> {
  try {
    await fetch(
      withIdentity(
        `/api/workspaces/${encodeURIComponent(workspaceId)}/terminals/${encodeURIComponent(terminalId)}`,
      ),
      { method: "DELETE" },
    );
  } catch {
    /* see above */
  }
}
