# loopfree-reconv — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-18** — Portability fix (`check-portable`): three sites indexed with a raw
  `u64` on a 32-bit target. Two (`self.pending[self.next_pending_id % MAX_PENDING]`,
  `self.pending[(timer_id - FIB_APPLY_BASE) % MAX_PENDING]`) take `% MAX_PENDING` (a
  `usize` constant = 256) first, which always yields a value `< 256` regardless of the
  dividend's width, so the cast can never truncate a value that reaches it — an
  unconditionally-safe `@intCast`. The third (`self.schedule[timer_id -
  CONDUCTOR_BASE]`) is NOT modulo-bounded; it was already checked against
  `self.schedule.len` before indexing, so restructured to compare on the wider (`u64`)
  side and only narrow (`@intCast`) after the bounds check proves the value fits, rather
  than casting first and hoping. `next_pending_id`/`timer_id` themselves stay `u64` — they
  are genuinely-unbounded sequence numbers/tag-bit-encoded ids, not accidentally-wide
  index counts. Compile-only for the two modulo sites (identical semantics); the third is
  a real boundary decision but the boundary was already enforced by the pre-existing
  `.len` check, just not on the correct side of the cast — no new test needed since the
  guard shape is unchanged, only which type it runs in. Verified: `zig build
  portable-loopfree-reconv` and `zig build test-loopfree-reconv --summary all` (11/11)
  both green.
- **2026-07-19** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this).
- **2026-07-15** — New module: Loop-free reconvergence transitions — two-class
  ordered-FIB schedule (provably no transient forwarding loop, TTL backstop),
  netsim-verified across fuzzed reconvergence schedules incl. overlapping.
