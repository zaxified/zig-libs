# liveness-hyst

A **BFD-like link-liveness estimator with hysteresis**. WireGuard has no fast
liveness signal of its own, and the paths a field fabric actually runs over —
LTE, satellite, marginal copper — flap. A naive BFD timer on top of those turns
one degraded link into fabric-wide oscillation, because every flap re-runs the
topology. This estimator combines echo-probe timing with jitter/loss statistics
([`latency-stats`](../latency-stats)) and Babel-style metric smoothing as an
**input filter** to the link-state metric: bounded detection latency without
flap-driven churn.

- **Status:** complete — core, trace corpus, scoring and property harness.
  **Platform:** any — the estimator never reads a wall clock; every `now` is
  caller-supplied.
- **Deps:** `netsim`, `latency-stats`.
- **Model after:** BFD (RFC 5880) liveness + Babel-style metric hysteresis.

## Use

```zig
const lh = @import("liveness-hyst");

var est = lh.Estimator.init(.{
    .probe_interval = 200,          // ticks; 1 tick = 1 ms by this module's convention
    .down_threshold = 1500,         // fast to distrust
    .up_threshold = 5000,           // slow to trust recovery — the asymmetry IS the hysteresis
    .metric_smoothing = 0.25,
    .degraded_loss_threshold = 0.30,
});

est.onProbeReply(now, rtt);   // a reply
est.onProbeTimeout(now);      // an unanswered probe

switch (est.state()) { .up, .suspect, .down => {} }
const cost = est.pathCost();  // ← order forwarding paths by THIS
```

## ⚠ `state()` does not order paths — `pathCost()` does

`LinkState.rank()` gives the informal up-ness order for display and tests, but
it is **not** monotone in stream quality inside `{.suspect, .down}`: a
degraded-but-usable link is deliberately harder to fail away from than a clean
one, which is the whole point of the damping. Ordering paths by `state()` would
therefore reintroduce exactly the oscillation this module exists to remove.
`pathCost()` is the monotone key; treat `state()` as the damped
transition-*timing* signal. The contract is adjudicated in `core.decide`.

## Verify

```
zig build test-liveness-hyst                          # Debug       — 15 pass
zig build test-liveness-hyst -Doptimize=ReleaseFast   # ReleaseFast — 15 pass
```

The estimator is **scored, not merely asserted**: a replayable trace corpus in
`trace.zig` runs clean, degraded, hard-failure and duty-cycle scenarios through
[`netsim`](../netsim), and `scoring.zig` measures the two quantities that trade
off against each other — detection latency after a genuine sustained failure
(target ≤ 1500 ticks) and spurious failovers over a simulated week (budget 5).
A tuning that wins on one and loses on the other fails the suite. `property.zig`
additionally pins bounded memory: the recent-probe ring is fixed-capacity, so
the footprint does not grow with the length of the probe stream.

Provenance: clean-room from RFC 5880 (BFD) and the published Babel metric
hysteresis description — both public specs, no third-party source ported or
studied, so no `NOTICE` entry is required (root [`NOTICE`](../../NOTICE) §0).

## Anchoring

**Anchor grade:** class C · oracle n/a

- **Class C** — internal algorithm or data structure — no outside exists, so correctness is defined by invariants or a brute-force reference. Not anchor debt.
- **Oracle n/a** — class C/D carries no anchor debt, so there is no oracle grade to give.

**What the tests actually contain.** local estimator "modeled after" BFD/Babel; scored via trace corpus + invariants, not wire-compat
