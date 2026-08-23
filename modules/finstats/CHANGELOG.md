# finstats — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-23** — **BREAKING: `opening` is now a REQUIRED field**, and convergence is measured in
  the answer's units. Three things, all closing gaps left open by the change below it the same day.
  (1) `XirrSpec.opening`, `XirrPreciseSpec.opening` and `XirrNodeSpec.opening` lost their `.none`
  default. The sign-change check added below is a backstop, not a detector: a window whose first
  row happens to carry a flow DOES bracket a root, bisection converges happily, and the finite,
  plausibly-shaped answer belongs to a different question. Nothing at runtime can catch that, so
  the compiler does — omit the field and the call no longer builds. An existing correct caller adds
  `.opening = .none` and gets bit-identical numbers. (2) `rate_tol` (default `1e-9`): bisection
  must narrow the RATE below it, not merely drive `|NPV|` under `1e-2`. That threshold is absolute
  and therefore means something different at every cashflow magnitude — measured across six orders
  of magnitude, it is never bit-stable, and on a series denominated in units of ~0.01 it is met at
  the FIRST midpoint of the bracket, so `xirr` returned **4.505** for a series returning 10 %. Same
  silently-plausible shape as the bracket bound, and the sign-change check cannot see it because
  there genuinely is a root. `rate_tol = null` restores the old absolute-only test exactly, for a
  caller pinned to reproduce old numbers; switching it on moves results by under 1e-8 at 1e6 and
  above, and by as much as the entire answer below ~1. `xirrPrecise`'s Newton phase gained the same
  rate-space return, which is a WORK saving and not an answer change — deleting it leaves the suite
  green, a surviving mutation the test now states rather than hides, because the bisection fallback
  lands in the same place. (3) New `xirrPreciseNode`/`XirrPreciseNodeSpec`, the Newton-first sibling
  of `xirrNode`; the two nodes had been asymmetric since `xirrPrecise` was added.

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
  signs on identical rows.
  The bracket was deliberately not widened — a genuine +1000 % IRR exists on a small position, so
  detection is what was missing, not room.

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
