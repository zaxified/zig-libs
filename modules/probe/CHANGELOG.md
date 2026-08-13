# probe — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-19** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Modeled on `nmap -sT`,
  `fping` (technique only; behavioral, not code) (design reference, not a test anchor).
- **2026-07-07** — New module: TCP-connect reachability prober — up/refused/timeout +
  RTT, fan-out with bounded concurrency, latency aggregation.
