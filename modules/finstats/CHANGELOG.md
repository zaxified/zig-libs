# finstats — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-24** — **`xirr` / `xirrPrecise` returned `10.0` for a one-row window. Fixed:
  constant NPV across the bracket is now `error.XirrNoRoot`.** The sign-change check added
  on 2026-08-23 could not see this one. When every cashflow lands on the same date — which
  is what a window narrow enough to hold a single observation collapses to — every discount
  exponent is 0, so NPV is the *constant* Σcf at every rate. Under
  `opening = .value_includes_flow` that constant is exactly 0 (seed −value[0], terminal
  +value[0]), and `nv_lo == 0` read as "a bound IS the root": true, and useless. Every rate
  is a root, so none of them is the answer, and bisection walked its 200 halvings to `hi`
  and handed back **9.99999999968015** — a confident +1000 %, indistinguishable at the call
  site from a real result. Reported by a consumer that hit it against a real database over a
  one-day date range; reproduced here before the fix.
  `bracketHasRoot` now rejects `npv(lo) == npv(hi)` first. The predicate is "NPV is
  constant", not "one row", because the row count is only a proxy: unseeded, the same single
  row gives the constant +1000, a genuine no-root the sign test already rejected. The check
  gates `xirrPrecise` as well, whose Newton phase would otherwise start from a derivative
  that is identically 0. New test *"xirr: a one-row window has NO unique rate — every rate
  is a root, so none of them is the answer"* covers all four entry points.
  **No effect on any series with two or more distinct dates.**

- **2026-08-23** — Three follow-ups to the two entries below, none of which change a number.
  (1) **The measured `rate_tol = null` cost table in `XirrSpec.rate_tol` is now reproducible.**
  It published seven cells and named no construction, and an independent attempt using this
  module's own analogous test as the construction did not reproduce it — four of the seven were
  off by factors of 2–4 (`M = 30` read `0.006` against a measured `0.023`). The doc comment now
  states the construction outright (the two dates, the `flow = value = M` / `value = 1.1·M` shape,
  `opening = .none`, error = |`rate_tol = null` − `rate_tol = 1e-9`| × 100) and carries the table
  re-measured against it, plus two corrections the old prose got wrong: the crossing of a basis
  point is between `M = 100` and `M = 300`, not "around 30", and the fall is not monotone — where
  bisection stops is a chaotic function of scale, so `M = 3` and `M = 10` stop on the identical
  midpoint. New test *"xirr: the cost of `rate_tol = null` is measured here, not quoted"*
  re-derives every published cell, so a comment can no longer drift away from the code.
  (2) **New public constants `bracket_lo` / `bracket_hi` / `default_rate_tol`**, replacing four
  copies of `-0.99`/`10.0` (bisection's starting bracket, both sign-change checks and Newton's
  "stepped outside the bracket" test) and four copies of `1e-9` (the four specs that carry a
  `rate_tol`). Same thesis as unifying `buildCashflows` and `bisect` in the entry below: a
  byte-identical copy is a byte-identical gap, and Newton's bail-out is precisely *why* the four
  bracket sites have to agree. Behaviour-identical — the suite is 33/33 either side, and the table
  test above pins the exact numbers.
  (3) **New test *"xirrPrecise: the same window, against an independent oracle"***. `xirr` had its
  windowed answer checked against the time-weighted return; `xirrPrecise` had no equivalent, even
  though the case the `opening` change exists for — a window whose first row carries a flow, which
  DOES bracket a root and converges on the IRR of a different question — is exactly the one no
  runtime guard can catch. Two cashflows have a closed form, so the Newton path is now held to
  arithmetic at `1e-9` rather than to a second root-finder. Making `xirrPrecise` ignore
  `spec.opening` used to leave the suite green; it now fails that one test and nothing else.
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
