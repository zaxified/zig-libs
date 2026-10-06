# liveness-hyst — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-06** — FIXED (review of PR #4): `Selector.update` with a `now` behind the
  challenger's start no longer traps (safe modes) or switches at once (ReleaseFast, wrapped
  subtraction); elapsed hold saturates at 0, so a clock that steps back only delays a switch.

- **2026-10-06** — ADDED, **BEHAVIOURAL, not breaking:** latency in the path cost. `pathCost()` was the smoothed loss fraction alone; it is now `ETX − 1` of that loss plus a Babel delay-metric RTT penalty (RFC 9616: 0 below `rtt_min`, linear, saturating at `rtt_max`; babeld's documented tunnel defaults 10 / 120 ms, weight 1.0), in nominal-link-cost units, with an opt-in RFC 3550 jitter term (`jitter_weight`, default 0 — it would void the monotone ordering guarantee). New `Config.path_cost: PathCostConfig` (bounds, weights, or a whole `cost_fn`), `CostInputs`, `CostFn`, `defaultCost`, `lossOnlyCost`, `rttPenalty`, `jitterPenalty`, `Estimator.costInputs()` / `smoothedRtt()`, and `Verdict.srtt` (EWMA with `metric_smoothing`; timeouts count as `rtt_max`, so the cost stays pointwise monotone). New `Selector` / `SelectorConfig`: picks among paths with Babel-style selection hysteresis — leave a `.down` path at once, switch to a cheaper one only after it has been cheaper by `margin` (0.2) for `hold` (5000 ticks). `state()` and `metric()` are unchanged and the scoring corpus is untouched. For a caller of `pathCost()`: values are no longer confined to [0, 1] and paths with equal loss now order by RTT; `.path_cost = .{ .rtt_weight = 0 }` restores the loss-only order and `.cost_fn = lossOnlyCost` the old values. No in-tree consumer calls `pathCost()`. Scope mvp -> core.
- **2026-10-06** — **NO CONSUMER-VISIBLE CHANGE:** SPEC consistency: README "Status" reworded from "complete" to the mvp scope it implements; maturity card gets the blank line between Scope and Audit.
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
