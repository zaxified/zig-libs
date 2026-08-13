# pping — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-13** — Test-only: `src/match.zig`'s single test — `test "match:
  file is reachable from the build"`, body `try std.testing.expect(true);` —
  was replaced by one that pins step 5a's aging sweep of the SAME-direction
  table. **Neither BREAKING nor BEHAVIOURAL** — no production code changed.
  The old test could not fail, and its stated premise had gone stale: it
  described `matchEcho` as a gated stub, but `gate.fable_core_implemented` is
  `true` and `kat.zig`/`property.zig` drive the real function. Its anchoring
  claim was redundant too — `root.zig` imports `match.zig` for the re-export
  and again in its aggregation `test`. The gap it was hiding, measured before
  the replacement was written: deleting `_ = same_dir.evictOlderThan(...)`
  from `matchEcho` left all 56 tests green, because every `kat.zig` scenario
  observes aging only through a match that no longer happens, and a direction
  whose TSvals are never echoed produces no match to observe. The new test
  feeds a stalled direction well under `capacity` and requires the entries to
  be gone once `max_age` passes, including on a call that neither matches nor
  inserts. Proven by mutation: that same deletion now fails 1 of 56, this
  test, `expected 1, found 4`.
- **2026-07-19** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Modeled on Kathleen Nichols'
  pping (Pollere LLC, C) — RFC 7323 §3 TCP Timestamps (design reference, not a test
  anchor).
- **2026-07-15** — New module: Passive RTT estimation from TCP TSval/TSecr echo matching
  (RFC 7323 / Pollere pping).
