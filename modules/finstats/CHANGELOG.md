# finstats — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-23** — **BREAKING: `xirr`, `xirrPrecise` and `xirrNode` return `XirrError`, and no
  longer hand back a bracket bound as if it were an answer.** All three built their cashflow list
  as external flows plus a terminal value, with no opening balance. That is right for an
  inception-to-date series, which starts at ~0. For a series sliced out of the middle of a
  portfolio's life — anything behind a date-range selector — the opening market value appears from
  nowhere, NPV never changes sign inside `[-0.99, 10]`, and the 200-iteration bisection walked to a
  bound and returned it. `10.0` renders as a perfectly confident +1000 %, indistinguishable at the
  call site from a real result, and there was no signal of any kind that it had failed. Two
  separable changes: NPV is now checked for a sign change across the bracket before iterating and
  the answer is `error.XirrNoRoot` when there is none (`Error` is unchanged; the three functions
  return the wider `XirrError = Error || error{XirrNoRoot}`, which is source-compatible for a
  caller that already `try`s but not for one declaring `Error` itself); and the specs gained an
  `opening` mode that seeds the first row's value as a starting position. `opening` is an enum, not
  a bool, because whether `value[0]` already contains row 0's own flow is a property of the
  caller's data that is invisible in the output — a fixture pins the two readings giving opposite
  signs on identical rows. The default `.none` leaves every existing inception-to-date result
  bit-identical: the bisection loop itself is untouched.
  The bracket was deliberately not widened — a genuine +1000 % IRR exists on a small position, so
  detection is what was missing, not room. Note the sign-change check is a backstop and not a
  complete one: a windowed series whose first row happens to carry a flow DOES bracket a root, and
  converges happily on the IRR of a different question. Only `opening` fixes that, and a test says
  so.

- **2026-08-23** — **Fixed the scratch leak in the nine functions the 2026-08-22 pass missed**:
  `histogram`, `betaAlpha`, `monteCarlo` (one buffer per projected month — the largest allocation
  in the module), `correlationMatrix` (three containers plus one hash map per key), its `pearson`
  helper (two lists per MATRIX CELL), `drawdownEpisodes`, `trackingRisk`, `omegaRatioNode` and
  `rollingApply` (so `rollingMean`/`rollingVolatility`/`rollingSharpe` too). The 2026-08-22 test
  named the five functions `example/main.zig` happened to call, so naming them was itself the
  defect: it stayed green while the other nine leaked. It now calls every public function that
  takes an allocator, frees only the Dataset the caller owns, and fails on anything outstanding.
  Removing any one of the fourteen releases individually turns it red — except that
  `drawdownEpisodes` first needed a dip added to the fixture: with a monotonically rising series
  its state machine never appends, so its scratch list never allocated and the call was not
  coverage at all.

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
