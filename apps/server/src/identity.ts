/**
 * Identity — deliberately a stub behind an interface.
 *
 * PLAN.md §10 decision #1 (Supabase Auth vs. self-rolled) is still open, so
 * this does NOT choose. It supplies the *shape* the realtime gateway needs —
 * authenticate at upgrade, then check workspace membership (SECURITY.md T6) —
 * so the real provider slots in without touching the gateway.
 *
 * DevIdentityProvider is development-only and refuses to load outside it.
 */

import { randomUUID } from "node:crypto";

export interface Principal {
  readonly userId: string;
  readonly name: string;
}

export interface IdentityProvider {
  /**
   * Resolve a principal from a websocket upgrade request.
   * Returns null when the request is unauthenticated — the caller must reject.
   */
  authenticate(headers: Readonly<Record<string, string | string[] | undefined>>, url: URL):
    | Promise<Principal | null>
    | (Principal | null);

  /** Whether the principal may join the workspace. */
  isMember(principal: Principal, workspaceId: string): Promise<boolean> | boolean;
}

/**
 * Development identity: trusts a client-supplied name and mints a stable id
 * from the `uid` query parameter so two browser tabs are distinct users.
 *
 * This is NOT authentication. It exists so M1 can be built and demonstrated
 * while the auth decision stays open. It must never run in production.
 */
export class DevIdentityProvider implements IdentityProvider {
  constructor(nodeEnv: string) {
    if (nodeEnv === "production") {
      throw new Error(
        "DevIdentityProvider must not be used in production. Resolve PLAN.md §10 decision #1 first.",
      );
    }
  }

  authenticate(
    _headers: Readonly<Record<string, string | string[] | undefined>>,
    url: URL,
  ): Principal | null {
    const uid = url.searchParams.get("uid");
    const name = url.searchParams.get("name");
    // Ids are constrained because they end up in pane.updatedBy, which is
    // validated against the same character class.
    const safeId = uid !== null && /^[A-Za-z0-9_-]{1,64}$/.test(uid) ? uid : randomUUID();
    const safeName =
      name !== null && name.length > 0 && name.length <= 40 ? name : `guest-${safeId.slice(0, 4)}`;
    return { userId: safeId, name: safeName };
  }

  /** Every dev principal is a member of every workspace. */
  isMember(): boolean {
    return true;
  }
}
