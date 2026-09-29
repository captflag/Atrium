/**
 * Agent identity — names, colours and avatars (PLAN.md §10, decision 3).
 *
 * Not decoration. Claim 1 of the product is CO-PRESENCE, and "agent-2 is
 * holding src/auth/**" only reads as a colleague if agent-2 is a *someone*.
 * The M4 conflict UI is the place this pays for itself: a conflict between
 * "Juniper" and "Basil" is a sentence a human parses instantly; a conflict
 * between two uuids is a support ticket.
 *
 * SERVER-ASSIGNED AND IMMUTABLE, per `AgentIdentity` in @atrium/shared. Never
 * chosen by the agent (a prompt-injected agent naming itself "Atrium System" is
 * a spoofing primitive) and never chosen by a client (a member renaming another
 * member's agent mid-session is the same bug with a nicer origin story).
 *
 * `colour` is a PALETTE LITERAL, not a CSS string — the pane never receives a
 * colour it has to trust. `avatar` is initials or one emoji and is NEVER a URL:
 * an identity field the browser fetches is an identity field that can phone
 * home, and it would be attacker-chosen the moment identities stop being
 * server-minted.
 */

import {
  AGENT_COLOURS,
  AGENT_NAME_RE,
  MAX_AGENT_AVATAR_LENGTH,
  MAX_AGENT_NAME_LENGTH,
  type AgentColour,
  type AgentIdentity,
} from "@atrium/shared";

/**
 * Botanical, short, and easy to say out loud in a standup. Every entry
 * satisfies `AGENT_NAME_RE` and fits `MAX_AGENT_NAME_LENGTH`; the assertion at
 * the bottom of this file proves it at module load rather than at the first
 * unlucky hash.
 *
 * THE ONE ROSTER. Exported because `AgentRegistry` mints the identities the
 * product actually shows — it also has to avoid colour collisions within a
 * workspace and honour a caller's preferred name, which this function does not
 * — and two tables of names would drift into two populations of agents. The
 * registry is handed this list as its `names` option in `index.ts`.
 */
export const AGENT_NAMES = [
  "Juniper",
  "Basil",
  "Rowan",
  "Hazel",
  "Cedar",
  "Willow",
  "Fennel",
  "Sorrel",
  "Aspen",
  "Clover",
  "Bramble",
  "Marigold",
  "Tamarind",
  "Yarrow",
  "Linden",
  "Saffron",
] as const;

/** FNV-1a. Not a security primitive — a deterministic spread over the tables. */
function hash32(value: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < value.length; i += 1) {
    h ^= value.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

/** First two letters of the name, e.g. "Juniper" -> "Ju". Never a URL. */
function initials(name: string): string {
  return name.slice(0, 2);
}

/**
 * Mint an identity for a new session.
 *
 * `seed` is the server-assigned session id, so the identity is stable across a
 * reconnect and a replay without being stored anywhere yet. `taken` is the set
 * of names already live in the workspace — two agents called Basil in one room
 * defeats the whole point, so collisions walk the table rather than reusing.
 */
export function mintAgentIdentity(
  sessionId: string,
  taken: ReadonlySet<string> = new Set(),
): AgentIdentity {
  const h = hash32(sessionId);
  let name = AGENT_NAMES[h % AGENT_NAMES.length] as string;
  for (let i = 1; taken.has(name) && i < AGENT_NAMES.length; i += 1) {
    name = AGENT_NAMES[(h + i) % AGENT_NAMES.length] as string;
  }
  // A workspace with more live agents than names gets a numeric suffix rather
  // than a duplicate. Still inside AGENT_NAME_RE and the length cap.
  if (taken.has(name)) {
    const suffix = ` ${(h % 89) + 10}`;
    name = `${name.slice(0, MAX_AGENT_NAME_LENGTH - suffix.length)}${suffix}`;
  }
  const colour = AGENT_COLOURS[(h >>> 8) % AGENT_COLOURS.length] as AgentColour;
  return {
    id: sessionId,
    name,
    colour,
    avatar: initials(name),
  };
}

// Fail at load, not at the first unlucky hash: a name that violates the shared
// regex would be rejected by `isValidAgentIdentity` at a boundary far from here.
for (const name of AGENT_NAMES) {
  if (!AGENT_NAME_RE.test(name) || name.length > MAX_AGENT_NAME_LENGTH) {
    throw new Error(`agent name table entry is not a valid AgentIdentity name: ${name}`);
  }
  if (initials(name).length > MAX_AGENT_AVATAR_LENGTH) {
    throw new Error(`agent avatar derived from ${name} exceeds MAX_AGENT_AVATAR_LENGTH`);
  }
}
