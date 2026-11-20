# seqmap

O(1) correlation map for request/reply protocols keyed by a **16-bit sequence
number**: a fixed table of **65536 slots**, handed out round-robin, mapping an
in-flight probe's sequence id to `{ target, probe, sent_ns, answered }`.

- Clean-room implementation (round-robin fixed-table approach).
- **Why:** the correlation half of any ping/probe engine — a reply carries only
  a 16-bit id, and matching it back to "which target, which probe, sent when"
  must be O(1) at 10k+ probes in flight. Generic enough for any protocol that
  correlates on a 16-bit id.
- **Platform:** any (pure logic, no OS calls). **Role:** util.
  **Concurrency:** reentrant (no shared state; don't share one instance across
  threads). **Allocation:** one table alloc at `init`; `add`/`fetch`/`release`
  never allocate.

Provenance: clean-room, no third-party source involved. An
earlier revision was written after fping's `seqmap.c`; it was replaced by a
two-stage clean-room reimplementation, so no fping attribution applies.

## API

```zig
const seqmap = @import("seqmap");

var map = try seqmap.SeqMap.init(gpa); // the single allocation (65536 slots)
defer map.deinit(gpa);

const seq = try map.add(target_id, probe_index, sent_ns); // error.Exhausted if full
const entry = map.fetch(seq);          // ?Entry — null for stale/foreign ids
map.fetchPtr(seq).?.answered = true;   // mark first reply, keep for dup detection
map.release(seq);                      // free the slot (idempotent)
map.clear();                           // start of a new probing round
```

## Semantics

- Sequence numbers are handed out **round-robin** (`next` wraps at 65536), so a
  freshly released id is not immediately reused — stale replies for it stay
  detectable as long as possible.
- `add` fails with `error.Exhausted` when the slot under the cursor is still
  occupied (all 65536 outstanding, or an old probe still holding that id after
  a wrap). The cursor does not move on failure: the next `add` retries the same
  id, and `release`ing it unblocks the call. Keep the engine's in-flight cap
  below the sequence space.
- Slots are freed **explicitly** (reply, timeout, or send error) — the map
  itself has no notion of time.

## Not provided

No expiry or timers, no anti-spoofing token, no 32-bit or composite keys: see
[`SPEC.md`](SPEC.md) under *What is deliberately not done* and *Backlog / deferred*.
