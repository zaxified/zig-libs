# liveness-hyst — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-13** — Test-only: `src/core.zig`'s single test — `test "core: file
  is reachable from the build"`, body `try std.testing.expect(true);` — was
  replaced by one that asserts `Verdict.since` stamps the last state
  TRANSITION and not the last update. **Neither BREAKING nor BEHAVIOURAL** —
  no production code changed. The old test could not fail, and the anchoring
  it claimed was already provided twice over (`root.zig` imports `core.zig`
  for `decide` and again in its aggregation `test`). `since` is documented for
  dwell-time / anti-flap accounting by the caller and was the one `Verdict`
  field with no assertion anywhere in the module: `state` is asserted
  throughout and `metric` is what `property.zig` pins. The new test drives a
  scripted probe stream (clean, timeout burst to `.suspect`, long quiet
  recovery to `.up`) and requires `since` to move exactly on the steps where
  `state` moves, with a vacuity guard that both branches were exercised.
  Proven by mutation: `.since = now` and `.since = prev.since` each turn it
  red on their own (15/16, only this test), and it is green at 16/16 on the
  real code.
- **2026-07-19** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this).
- **2026-07-15** — New module: BFD-like link-liveness estimator with EWMA hysteresis —
  echo-probe timing + jitter/loss stats, Babel-style metric smoothing as an input
  filter: fast detection without flap-driven oscillation.
