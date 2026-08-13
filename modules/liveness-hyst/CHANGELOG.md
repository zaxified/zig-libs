# liveness-hyst — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-19** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this).
- **2026-07-15** — New module: BFD-like link-liveness estimator with EWMA hysteresis —
  echo-probe timing + jitter/loss stats, Babel-style metric smoothing as an input
  filter: fast detection without flap-driven oscillation.
