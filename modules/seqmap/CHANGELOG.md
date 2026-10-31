# seqmap — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-31** — **NO CONSUMER-VISIBLE CHANGE:** no-panic sweep (§ GZ) — every entry point is total over a u16 id into the 65536-slot table; pin tests in `src/sweep_test.zig`.
- **2026-10-04** — Tests: first mutation run (17 mutants, 17 killed by the existing tests; no test or
  source change).
- **2026-07-19** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Modeled on fping `seqmap.c`
  (design reference, not a test anchor).
- **2026-07-04** — New module: Fixed 65 536-slot 16-bit request/reply correlation map,
  O(1).
