# netsim — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-10** — **BEHAVIOURAL, not breaking:** A1 fix campaign, netsim F1 +
  F5. F5: `generate`'s fault-kind draw no longer silently drops a disabled or
  inapplicable kind's share of the schedule — it excludes that kind from the
  weighted draw instead, so `Config.max_events` bounds the number of *emitted*
  disruptions, not the number of draws (previously up to 40% weaker with
  `enable_partition`/`enable_crash`/`enable_clock_jump` all off). The default,
  fully-enabled, linked, multi-node case is unchanged byte-for-byte; any other
  `(seed, topo, cfg)` combination now produces a different schedule — old
  seeds pinned against a non-default config are not guaranteed to reproduce
  the same trace (none of the 7 in-repo consumers were affected; verified by
  running every consumer's test lane, all green). F1: `applyFault` now rejects
  an out-of-range node id in `crash_node`/`restart_node`/`clock_jump` with a
  new `error.UnknownNode` instead of indexing unchecked (Debug panic,
  ReleaseFast out-of-bounds write reporting `outcome = .ok`) — additive, since
  `applyFault`/`replay` were already `anyerror!...`.
- **2026-08-18** — Portability fix: `Prng.below(n: usize) usize` was reused for
  `Time`-typed (`u64`) draws — `cfg.horizon` in `fault.generate` and
  `link.cfg.jitter`/`reorder_extra` in `Sim.send` — which fails to compile on a
  32-bit target (`u64` does not implicitly narrow to `usize`). `Time` is
  netsim's simulated clock and is deliberately `u64` on every host, not an
  accidentally-wide index count, so the fix is a dedicated `Prng.belowWide(n:
  u64) u64` (bound and draw both stay `u64`, no narrowing conversion, nothing
  to truncate) rather than casting `Time` down to `usize`. Fixes 4 modules:
  netsim itself plus `df-elect`, `liveness-hyst`, `raft`, all of which import
  `fault`/`sim` and failed `check-portable` for the identical reason. New test
  pins `belowWide` staying in-range and undivided-by-truncation for a bound
  past `maxInt(u32)`.
- **2026-07-19** — Security audit: three findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on TigerBeetle
  VOPR (design ref only; no throughput competitor — it is a test harness) (design
  reference, not a test anchor).
- **2026-07-15** — New module: Deterministic seeded discrete-event network simulator
  (VOPR-style: nodes/links/latency/loss/partition/clock-skew, failure-schedule fuzzer,
  byte-exact replay, ddmin counterexample minimizer).
