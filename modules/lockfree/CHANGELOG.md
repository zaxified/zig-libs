# lockfree — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-07** — **Fixed: `BoundedQueue.len` could report a full queue on arm64.** `tail`'s claim CAS and `head`'s store were relaxed, so a reader could see `head` past the `tail` it had just read and `t - h` wrapped (clamped to `capacity`); x86's ordered stores hid it, and the arm64 lane of tag `2026-10-06` caught it in the existing "len under a concurrent push/pop" test. Both now store with release (the `.single` `advance` moves `head` before freeing the slot), so `len` stays exact on weakly ordered CPUs. No API change; on x86 the generated code is the same.
- **2026-10-06** — Scope mvp → core. **New:** `BoundedQueue(T, capacity, .{ .consumers })` —
  a fixed-capacity, allocation-free MPMC ring (Vyukov's bounded queue, crossbeam's
  `ArrayQueue`): `push`/`pushWith` refuse and count when full (`refusedCount`), `pop`,
  and with `.consumers = .single` a CAS-free `pop` plus in-place `front`/`advance`;
  `len`/`isEmpty`/`isFull` snapshots. **New:** `Queue(T)` — the Michael-Scott queue is
  generic over its payload; `MpmcQueue` is now `Queue(u64)` and `Node`, `NodePool(Node)`
  and every existing call keep working unchanged. **Changed:** `Verdict` has a new
  variant `reordered` — `verify` now also checks that each consumer received each
  producer's items in that producer's order (FIFO); an exhaustive `switch` on
  `Verdict` outside this module needs the new arm. Mutation run over the new code:
  15 of 16 killed, 1 equivalent (SPEC §5).
- **2026-10-06** — **NO CONSUMER-VISIBLE CHANGE:** SPEC consistency: Compared with no longer says every access is `seq_cst` — only the reclamation-relevant ones are (§4a).
- **2026-10-05** — Mutation run: 28 of 30 killed, 1 equivalent, 1 not killable by
  a test (the `enterCritical` pin store's ordering — litmus territory, SPEC §5); 5
  tests and 1 checker case added (current-epoch pin, two-advance grace period,
  stale-bag drain in `retire`, lagging tail under `dequeue` and `enqueue`, checker
  pid edge). No code change.
- **2026-08-24** — `Atomic` is re-exported by the module root, so a consumer can spell
  `lockfree.Atomic` (a generic alias for `std.atomic.Value`). It was public inside
  `atomic.zig` from the start while `root.zig` published its four neighbours —
  `Backoff`, `SpinLock`, `CachePadded`, `cache_line` — and omitted this one, so it was
  reachable from nowhere outside the module. Nothing inside could notice: only an
  outside caller can tell a missing re-export from a present one, which is why the
  example is where the export is now pinned rather than a unit test. Additive; no
  existing name changes meaning.

- **2026-08-18** — Portability fix (`check-portable`): `StressConfig.per_producer` was
  `u64` while `StressConfig.producers` (its sibling field) was already `usize`; it only
  ever sizes allocations/loop bounds (`total = producers * per_producer`,
  `allocator.alloc(bool, total)`, the producer thread's item loop) — over-wide by
  accident, not a genuine 64-bit quantity — so narrowed to `usize`. `verify`'s
  post-guard `idx = pid * cfg.per_producer + seq` needed one further `@intCast` of the
  already-bounds-checked `seq` (the `pid >= cfg.producers or seq >= cfg.per_producer`
  guard just above proves it fits before the cast runs, so it can never truncate a value
  that reaches it). Pure type/cast fix, identical semantics — no new test. Verified: this
  site's `expected type 'usize', found 'u64'` error is gone from `zig build
  portable-lockfree` (the module still fails that gate for two separate, pre-existing,
  out-of-scope reasons: `[wasi-surface]` thread-spawn/libc, and the documented "64-bit
  atomic RMW unsupported at wasm32 baseline" class, neither touched here) and `zig build
  test-lockfree --summary all` (23/23) is green.
- **2026-07-19** — Security audit: three findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Modeled on crossbeam-epoch (Rust),
  Fraser epoch reclamation (2004), Michael&Scott PODC'96 (design reference, not a test
  anchor).
- **2026-07-17** — New module: Lock-free concurrency primitives for shared-memory worker
  pools (Michael & Scott MPMC queue, PODC 1996 + Fraser/crossbeam epoch reclamation).
