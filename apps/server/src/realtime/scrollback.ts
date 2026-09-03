/**
 * Bounded scrollback for a terminal session.
 *
 * A late joiner must see recent history immediately (PLAN.md §6: the browser
 * owns nothing, so history cannot live in the tab that happened to be open
 * first). That history has to be bounded, because a shell running `yes` will
 * otherwise turn server RAM into a denial of service for everyone else in the
 * workspace (SECURITY.md T10).
 *
 * WHAT THIS IS NOT. It is not durable replay. The ring is in memory, it is
 * lost on server restart, and it holds a fixed number of BYTES, not lines or
 * screens. Durable, sequence-numbered replay is M5 (PLAN.md §6); until then
 * `attached.backlogBytes` tells the client exactly how much it actually got.
 *
 * TWO HONEST LIMITATIONS, both inherent to replaying a byte stream from an
 * arbitrary offset:
 *
 *   1. Eviction is from the front and is byte-exact, so the oldest retained
 *      byte can be the middle of a UTF-8 sequence or the middle of an ANSI
 *      escape. xterm.js resynchronizes within a few bytes; the visible effect
 *      is at most a smear of mojibake on the first replayed line. Trimming to
 *      a "safe" boundary would require parsing the stream, and the wire
 *      protocol's whole premise is that the server does not parse pty bytes.
 *   2. The replayed bytes are the raw stream, not a rendered screen. A program
 *      that repainted with an absolute cursor address before the window we
 *      kept will look wrong until the next full repaint (^L, or a resize).
 */

const EMPTY = new Uint8Array(0);

/**
 * Compaction threshold for the head pointer: dropped-chunk slots are only
 * spliced away in batches, so eviction stays O(1) amortized instead of the
 * O(n) an `Array.shift()` per chunk would cost on a 60-byte-per-write shell.
 */
const COMPACT_AFTER_SLOTS = 512;

export class ScrollbackRing {
  readonly capacityBytes: number;

  #chunks: Uint8Array[] = [];
  /** Index of the oldest live chunk in `#chunks`. Slots before it are dead. */
  #head = 0;
  #bytes = 0;
  #evictedBytes = 0;

  constructor(capacityBytes: number) {
    if (!Number.isInteger(capacityBytes) || capacityBytes <= 0) {
      throw new Error("scrollback capacityBytes must be a positive integer");
    }
    this.capacityBytes = capacityBytes;
  }

  /** Bytes currently retained. Never exceeds `capacityBytes`. */
  get bytes(): number {
    return this.#bytes;
  }

  /** Bytes that have been pushed and then dropped. Diagnostics only. */
  get evictedBytes(): number {
    return this.#evictedBytes;
  }

  /**
   * Append pty output. The chunk is COPIED: callers hand us views over a
   * socket or stream buffer that is reused on the next read, and this ring
   * outlives the tick.
   */
  push(chunk: Uint8Array): void {
    if (chunk.byteLength === 0) return;

    // A single write larger than the whole ring: keep only its tail.
    if (chunk.byteLength >= this.capacityBytes) {
      this.#evictedBytes += this.#bytes + (chunk.byteLength - this.capacityBytes);
      this.#chunks = [chunk.slice(chunk.byteLength - this.capacityBytes)];
      this.#head = 0;
      this.#bytes = this.capacityBytes;
      return;
    }

    this.#chunks.push(chunk.slice());
    this.#bytes += chunk.byteLength;
    this.#evict();
  }

  #evict(): void {
    while (this.#bytes > this.capacityBytes) {
      const oldest = this.#chunks[this.#head];
      if (oldest === undefined) break; // unreachable while #bytes > 0
      const excess = this.#bytes - this.capacityBytes;
      if (oldest.byteLength <= excess) {
        this.#chunks[this.#head] = EMPTY;
        this.#head += 1;
        this.#bytes -= oldest.byteLength;
        this.#evictedBytes += oldest.byteLength;
      } else {
        // Partial eviction: the oldest byte kept may land mid-sequence. See
        // limitation 1 in the file header.
        this.#chunks[this.#head] = oldest.subarray(excess);
        this.#bytes -= excess;
        this.#evictedBytes += excess;
      }
    }
    if (this.#head >= COMPACT_AFTER_SLOTS) {
      this.#chunks = this.#chunks.slice(this.#head);
      this.#head = 0;
    }
  }

  /**
   * The most recent `maxBytes` bytes, concatenated into one buffer. Returns a
   * fresh array every call; the caller may keep it.
   */
  tail(maxBytes: number): Uint8Array {
    const want = Math.min(Math.max(0, Math.trunc(maxBytes)), this.#bytes);
    if (want === 0) return EMPTY;

    const out = new Uint8Array(want);
    let offset = want;
    for (let i = this.#chunks.length - 1; i >= this.#head && offset > 0; i -= 1) {
      const chunk = this.#chunks[i];
      if (chunk === undefined || chunk.byteLength === 0) continue;
      const take = Math.min(chunk.byteLength, offset);
      offset -= take;
      out.set(chunk.subarray(chunk.byteLength - take), offset);
    }
    return out;
  }

  /** Drops everything. Used when a session is torn down. */
  clear(): void {
    this.#chunks = [];
    this.#head = 0;
    this.#bytes = 0;
  }
}
