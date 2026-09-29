/**
 * `AgentEventStream` — sequence assignment, the replay ring, and fan-out.
 *
 * This is the half of `AgentProvider.events()` that has nothing to do with the
 * harness, kept separate so it can be reasoned about (and swapped for a
 * Postgres-backed one in M5) without touching the SDK glue.
 *
 * Three contract obligations live here, all from `provider.ts`:
 *
 *  1. **`seq` is monotonic and gap-free per session, starting at 1, and is
 *     assigned HERE.** Not by the runner. The runner is inside the container;
 *     a sequence number chosen there is not a replay cursor, it is an
 *     attacker-influenceable integer that `subscribe.fromSeq` would then trust.
 *
 *  2. **Each `events()` call returns an INDEPENDENT iterator, and one slow
 *     consumer must not stall the others.** A pane, the event-log writer and a
 *     summariser all read the same session. So each consumer owns a bounded
 *     queue; the producer never awaits a consumer.
 *
 *  3. **A consumer that falls too far behind is DROPPED with a `slow-consumer`
 *     error event**, not allowed to grow an unbounded buffer (PLAN.md §6,
 *     backpressure). An unbounded queue behind a stalled websocket is how a
 *     single wedged browser tab OOMs the server for everyone.
 *
 * The ring is in-memory and bounded. `ServerAgentAttached.replayFromSeq` exists
 * because of that: when a client asks for events after seq 5 and the ring only
 * still holds seq 900 onward, the UI must SAY there is a hole rather than
 * render a plausible transcript that is quietly missing its middle. The
 * gateway reads that from the first replayed event's `seq`; `oldestSeq` below
 * is the same number when the ring is non-empty.
 */

import type { AgentEvent } from "@atrium/shared";

/** Events retained for replay. ~2k events is a long session's worth of pane. */
const DEFAULT_RING_EVENTS = 2_000;

/** Queue depth per consumer before it is dropped as a slow consumer. */
const DEFAULT_CONSUMER_QUEUE = 512;

export interface AgentEventStreamOptions {
  readonly agentId: string;
  readonly ringEvents?: number;
  readonly consumerQueue?: number;
  /** Injectable for tests; `at` is display-only and never an ordering key. */
  readonly now?: () => Date;
}

/** `AgentEvent` minus the three fields the server owns. */
export type AgentEventDraft = DistributiveOmit<AgentEvent, "seq" | "agentId" | "at">;

/**
 * `Omit` over a union collapses it into one object type, which would let a
 * `usage` event carry a `tool_call` field. Distributing preserves the union.
 */
export type DistributiveOmit<T, K extends keyof never> = T extends unknown ? Omit<T, K> : never;

interface Consumer {
  readonly queue: AgentEvent[];
  readonly limit: number;
  wake: (() => void) | null;
  dropped: boolean;
  closed: boolean;
}

export class AgentEventStream {
  readonly #agentId: string;
  readonly #ringLimit: number;
  readonly #consumerLimit: number;
  readonly #now: () => Date;
  readonly #ring: AgentEvent[] = [];
  readonly #consumers = new Set<Consumer>();
  #lastSeq = 0;
  #closed = false;

  constructor(options: AgentEventStreamOptions) {
    this.#agentId = options.agentId;
    this.#ringLimit = options.ringEvents ?? DEFAULT_RING_EVENTS;
    this.#consumerLimit = options.consumerQueue ?? DEFAULT_CONSUMER_QUEUE;
    this.#now = options.now ?? ((): Date => new Date());
  }

  get lastSeq(): number {
    return this.#lastSeq;
  }

  /** Lowest seq still replayable, or 0 when nothing is retained. */
  get oldestSeq(): number {
    return this.#ring[0]?.seq ?? 0;
  }

  get closed(): boolean {
    return this.#closed;
  }

  /**
   * Stamp a draft into a real `AgentEvent` and publish it.
   *
   * Returns the stamped event so a caller can react to what it just emitted
   * (the provider uses it to keep `AgentHandle.lastSeq` truthful) without
   * reaching back into the ring.
   */
  publish(draft: AgentEventDraft): AgentEvent {
    if (this.#closed) {
      // Publishing after the terminal event would break "the iterator ends
      // after done/error": a consumer that already saw the end must not see a
      // later event. Stamp it so the return type holds, but do not deliver.
      return { ...draft, seq: this.#lastSeq, agentId: this.#agentId, at: this.#now().toISOString() } as AgentEvent;
    }
    this.#lastSeq += 1;
    const event = {
      ...draft,
      seq: this.#lastSeq,
      agentId: this.#agentId,
      at: this.#now().toISOString(),
    } as AgentEvent;

    this.#ring.push(event);
    while (this.#ring.length > this.#ringLimit) this.#ring.shift();

    for (const consumer of this.#consumers) this.#deliver(consumer, event);
    return event;
  }

  /**
   * Publish the session's terminal event and end every iterator after it.
   *
   * Terminal means the SESSION ended, not that a turn finished: `done` events
   * arrive after every turn and an idle session can be prompted again.
   */
  close(final: AgentEventDraft): AgentEvent {
    const event = this.publish(final);
    this.#closed = true;
    for (const consumer of this.#consumers) {
      consumer.closed = true;
      consumer.wake?.();
    }
    return event;
  }

  #deliver(consumer: Consumer, event: AgentEvent): void {
    if (consumer.dropped || consumer.closed) return;
    if (consumer.queue.length >= consumer.limit) {
      // Drop the consumer, not the session. Its iterator gets one last
      // `slow-consumer` error so the UI can say what happened instead of the
      // stream simply going quiet. The queue is cleared: a detached viewer's
      // backlog is memory held for nobody.
      consumer.dropped = true;
      consumer.queue.length = 0;
      consumer.wake?.();
      return;
    }
    consumer.queue.push(event);
    consumer.wake?.();
  }

  /**
   * The one event this stream authors rather than relays.
   *
   * It carries the session's current `seq` rather than consuming a new one:
   * this is addressed to ONE detached viewer and must not appear in anybody
   * else's transcript, so it cannot occupy a number in the gap-free sequence.
   */
  #slowConsumerEvent(): AgentEvent {
    return {
      kind: "error",
      code: "slow-consumer",
      message: "this viewer fell too far behind and was detached from the agent stream",
      retryable: true,
      seq: this.#lastSeq,
      agentId: this.#agentId,
      at: this.#now().toISOString(),
    };
  }

  /**
   * An independent iterator over this session's events.
   *
   * Registration happens BEFORE the replay snapshot is taken, and the drain
   * loop skips anything already replayed. Doing it the other way round loses
   * every event published between the snapshot and the registration — a race
   * that only shows up under load, as a transcript missing exactly the busy
   * part.
   */
  async *subscribe(fromSeq = 0): AsyncGenerator<AgentEvent> {
    const consumer: Consumer = {
      queue: [],
      limit: this.#consumerLimit,
      wake: null,
      dropped: false,
      closed: this.#closed,
    };
    this.#consumers.add(consumer);
    try {
      let highest = fromSeq;
      for (const event of [...this.#ring]) {
        if (event.seq <= fromSeq) continue;
        highest = event.seq;
        yield event;
      }
      for (;;) {
        if (consumer.dropped) {
          yield this.#slowConsumerEvent();
          return;
        }
        const next = consumer.queue.shift();
        if (next !== undefined) {
          // Skip anything the replay above already delivered. This is the only
          // place the two paths overlap, and it is why registration precedes
          // the snapshot rather than following it.
          if (next.seq <= highest) continue;
          highest = next.seq;
          yield next;
          continue;
        }
        if (consumer.closed) return;
        await new Promise<void>((resolve) => {
          consumer.wake = () => {
            consumer.wake = null;
            resolve();
          };
        });
      }
    } finally {
      this.#consumers.delete(consumer);
    }
  }
}
