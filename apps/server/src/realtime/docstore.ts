/**
 * Persistence for canvas documents.
 *
 * An interface with two implementations, for the same reason SandboxProvider
 * is an interface (PLAN.md §4): the durable one is Postgres, but the project
 * must stay runnable when Postgres is not up. MemoryDocStore keeps a workspace
 * alive across browser reloads (the M1 criterion) but not across a server
 * restart, and says so at boot rather than silently losing work.
 */

import type { Pool } from "pg";

export interface DocStore {
  /** Encoded Y.Doc state, or null when the workspace has never been saved. */
  load(workspaceId: string): Promise<Uint8Array | null>;
  save(workspaceId: string, state: Uint8Array): Promise<void>;
  readonly durable: boolean;
  readonly describe: string;
}

export class MemoryDocStore implements DocStore {
  readonly durable = false;
  readonly describe = "in-memory (lost on server restart)";
  readonly #docs = new Map<string, Uint8Array>();

  load(workspaceId: string): Promise<Uint8Array | null> {
    return Promise.resolve(this.#docs.get(workspaceId) ?? null);
  }

  save(workspaceId: string, state: Uint8Array): Promise<void> {
    this.#docs.set(workspaceId, state);
    return Promise.resolve();
  }
}

export class PostgresDocStore implements DocStore {
  readonly durable = true;
  readonly describe = "postgres";

  readonly #pool: Pool;

  constructor(pool: Pool) {
    this.#pool = pool;
  }

  static async migrate(pool: Pool): Promise<void> {
    await pool.query(`
      create table if not exists canvas_docs (
        workspace_id text primary key,
        state        bytea       not null,
        updated_at   timestamptz not null default now()
      )
    `);
  }

  async load(workspaceId: string): Promise<Uint8Array | null> {
    const result = await this.#pool.query<{ state: Buffer }>(
      "select state from canvas_docs where workspace_id = $1",
      [workspaceId],
    );
    const row = result.rows[0];
    return row ? new Uint8Array(row.state) : null;
  }

  async save(workspaceId: string, state: Uint8Array): Promise<void> {
    await this.#pool.query(
      `insert into canvas_docs (workspace_id, state, updated_at)
       values ($1, $2, now())
       on conflict (workspace_id)
       do update set state = excluded.state, updated_at = now()`,
      [workspaceId, Buffer.from(state)],
    );
  }
}

/**
 * Prefers Postgres, falls back to memory when it is unreachable.
 * The fallback is loud: a workspace that cannot be persisted is a fact the
 * operator needs at boot, not a surprise after a restart.
 */
export async function createDocStore(
  pool: Pool,
  log: { warn: (msg: string) => void; info: (msg: string) => void },
): Promise<DocStore> {
  try {
    await PostgresDocStore.migrate(pool);
    log.info("canvas persistence: postgres");
    return new PostgresDocStore(pool);
  } catch {
    log.warn(
      "canvas persistence: postgres unreachable, falling back to memory. " +
        "Canvases survive browser reloads but NOT a server restart. Run `npm run db:up`.",
    );
    return new MemoryDocStore();
  }
}
