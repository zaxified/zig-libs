# finstats — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-22** — **Fixed a memory leak in five public functions.** `xirr`, `xirrPrecise`,
  `quantile`, `riskMetrics` and `parametricRisk` each allocated scratch from the caller's
  allocator and never released it — a `std.ArrayList` of cashflows, a sorted copy, a column
  extraction. Nothing here caught it: every test in the module runs on an `ArenaAllocator`
  fixture, which bulk-frees regardless, so a function that leaked looked exactly like one
  that did not. A long-lived consumer on any other allocator leaked on every call. Found by
  writing `example/main.zig` against a `DebugAllocator`. A new test on
  `std.testing.allocator` now fails on an outstanding allocation, and was confirmed to go
  red when one of the fixes is reverted.

- **2026-07-18** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Modeled on Python `empyrical`
  / `ffn` (design reference, not a test anchor).
- **2026-07-09** — New module: Portfolio/financial statistics over `dataset` —
  XIRR/TWR/risk/beta/Monte-Carlo/correlation matrix.
