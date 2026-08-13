# netsim — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-19** — Security audit: three findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on TigerBeetle
  VOPR (design ref only; no throughput competitor — it is a test harness) (design
  reference, not a test anchor).
- **2026-07-15** — New module: Deterministic seeded discrete-event network simulator
  (VOPR-style: nodes/links/latency/loss/partition/clock-skew, failure-schedule fuzzer,
  byte-exact replay, ddmin counterexample minimizer).
