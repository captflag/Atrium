/**
 * Bounded transcript buffer for one agent session.
 *
 * The terminal's `ScrollbackRing` solves the same problem one layer down and
 * this file borrows its discipline — a fixed ceiling, eviction from the front,
 * amortized O(1) — but NOT its semantics. A pty produces an undifferentiated
 * byte stream, so the ring there is allowed to cut a chunk in half. An agent
 * produces STRUCTURED events with server-assigned sequence numbers, and half an
 * event is not a smear of mojibake, it is a malformed frame. So the unit of
 * storage and of eviction here is the whole event.
 *
 * WHY IT EXISTS. A late joiner must see the transcript immediately, and the
 * browser must not be the thing that owned it (PLAN.md §6: the tab that
 * happened to be open first is not a storage tier). A second viewer opening an
 * agent pane ten minutes into a task sees what the first viewer sees.
 *
 * WHY IT IS BOUNDED. An agent in a loop emits events as fast as the model
 * streams. Unbounded retention turns one runaway session into a denial of
 * service against every other workspace in the process (SECURITY.md T10). Two
 * ceilings, because either alone is escapable: `capacityEvents` bounds a flood
 * of tiny events, `capacityBytes` bounds a handful of enormous ones.
 *
 * WHAT THIS IS NOT — durability. The buffer is in memory and is lost when the
 * server restarts. Durable, sequence-numbered replay from Postgres is M5
 * (PLAN.md §6); nothing here writes to a database, deliberately. Until then
 * `ServerAgentAttached.replayFromSeq` is how a client learns it has a HOLE:
 * when the oldest event still held is newer than the cursor the client asked
 * from, the pane must say so rather than render a plausible transcript that is
 * quietly missing its middle.
 *
 * SEQUENCE NUMBERS ARE THE PROVIDER'S. This buffer assumes pushes arrive in
 * strictly increasing `seq` order and does not renumber: a replay cursor is
 * only correct if the numbering is stable across everyone who holds it. The
 * session validates that assumption before pushing (see `agent-session.ts`);
 * this file just refuses to store an event that would break the ordering.
 */

import type { AgentEvent } from "@atrium/shared";

interface Entry {
  readonly event: AgentEvent;
  /** Approximate serialized size. See `sizeOf`. */
  readonly bytes: number;
}

/** Head-pointer compaction threshold, same reasoning as `ScrollbackRing`. */
const COMPACT_AFTER_SLOTS = 256;

const NO_EVENTS: readonly AgentEvent[] = [];

export class AgentTranscript {
  readonly capacityEvents: number;
  readonly capacityBytes: number;

  #entries: (Entry | null)[] = [];
  /** Index of the oldest live entry. Slots before it are dead. */
  #head = 0;
  #bytes = 0;
  #count = 0;
  #lastSeq = 0;
  #droppedEvents = 0;

  constructor(capacityEvents: number, capacityBytes: number) {
    if (!Number.isInteger(capacityEvents) || capacityEvents <= 0) {
      throw new Error("transcript capacityEvents must be a positive integer");
    }
    if (!Number.isInteger(capacityBytes) || capacityBytes <= 0) {
      throw new Error("transcript capacityBytes must be a positive integer");
    }
    this.capacityEvents = capacityEvents;
    this.capacityBytes = capacityBytes;
  }

  /** Highest `seq` ever pushed, retained or not. 0 before the first event. */
  get lastSeq(): number {
    return this.#lastSeq;
  }

  /**
   * Lowest `seq` still retained, or 0 when nothing is.
   *
   * This is what makes a hole detectable: a client asking from a cursor below
   * this number cannot be served the gap by this process.
   */
  get firstSeq(): number {
    const oldest = this.#entries[this.#head];
    return oldest == null ? 0 : oldest.event.seq;
  }

  get count(): number {
    return this.#count;
  }

  get bytes(): number {
    return this.#bytes;
  }

  /** Events pushed and later evicted. Diagnostics and the hole warning. */
  get droppedEvents(): number {
    return this.#droppedEvents;
  }

  /**
   * Append one event. Returns false when the event is out of order or a
   * duplicate — the caller logs that; storing it would corrupt every replay
   * cursor handed out afterwards.
   */
  push(event: AgentEvent): boolean {
    if (!Number.isInteger(event.seq) || event.seq <= this.#lastSeq) return false;

    this.#entries.push({ event, bytes: sizeOf(event) });
    this.#bytes += sizeOf(event);
    this.#count += 1;
    this.#lastSeq = event.seq;
    this.#evict();
    return true;
  }

  #evict(): void {
    while (this.#count > this.capacityEvents || this.#bytes > this.capacityBytes) {
      const oldest = this.#entries[this.#head];
      if (oldest == null) break; // unreachable while #count > 0
      // One event always stays: a transcript that evicted itself to empty
      // would report firstSeq 0 and claim it can serve any cursor.
      if (this.#count <= 1) break;
      this.#entries[this.#head] = null;
      this.#head += 1;
      this.#count -= 1;
      this.#bytes -= oldest.bytes;
      this.#droppedEvents += 1;
    }
    if (this.#head >= COMPACT_AFTER_SLOTS) {
      this.#entries = this.#entries.slice(this.#head);
      this.#head = 0;
    }
  }

  /**
   * Retained events with `seq` strictly greater than `fromSeq`, oldest first.
   *
   * A fresh array every call; the caller may keep it. `fromSeq` 0 means "as far
   * back as you still have".
   */
  since(fromSeq: number): readonly AgentEvent[] {
    if (this.#count === 0) return NO_EVENTS;
    const cursor = Number.isFinite(fromSeq) ? Math.max(0, Math.trunc(fromSeq)) : 0;
    if (cursor >= this.#lastSeq) return NO_EVENTS;

    const out: AgentEvent[] = [];
    for (let i = this.#head; i < this.#entries.length; i += 1) {
      const entry = this.#entries[i];
      if (entry == null) continue;
      if (entry.event.seq > cursor) out.push(entry.event);
    }
    return out;
  }

  clear(): void {
    this.#entries = [];
    this.#head = 0;
    this.#bytes = 0;
    this.#count = 0;
    // #lastSeq is deliberately NOT reset: it is the session's high-water mark
    // and a client's cursor is compared against it after a clear.
  }
}

/**
 * Approximate serialized size, in UTF-16 code units.
 *
 * Deliberately an estimate. The exact figure would be the UTF-8 length of the
 * frame this event ends up in, which differs per viewer (each carries its own
 * `channel`), so computing it precisely would mean serializing once per viewer
 * to answer a question that only bounds memory. `JSON.stringify().length` is
 * within a small constant factor and never under-counts the string payloads,
 * which are the parts that can actually be large.
 */
function sizeOf(event: AgentEvent): number {
  try {
    return JSON.stringify(event).length;
  } catch {
    // A cyclic or unserializable event cannot reach the wire either; charge it
    // a nominal cost so it still counts against the ceiling.
    return 256;
  }
}
