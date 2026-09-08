# upstream — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-09** — Docs: the `NOTICE` pointer in ``src/root.zig`` resolved to `modules/NOTICE`,
  a path that has never existed in this repository. Now ``../../../NOTICE``. No code or data
  changed. `zig build check-catalog` gained a check that resolves every relative NOTICE
  link under `modules/**`, so this cannot come back silently.
- **2026-07-19** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Modeled on Envoy / HAProxy
  upstream cluster, resilience4j Bulkhead (design reference, not a test anchor).
- **2026-07-08** — New module: Load-balanced upstream pool + failover —
  round-robin/weighted/least-conn/EWMA strategies, per-upstream breaker+bulkhead,
  active+passive health.
