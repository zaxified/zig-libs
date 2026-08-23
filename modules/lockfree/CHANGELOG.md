# lockfree — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
