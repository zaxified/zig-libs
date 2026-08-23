# finstats — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
Portfolio/financial statistics over `dataset`: dated-flow IRR (`xirr`, plus a Newton-with-
bisection-fallback sibling `xirrPrecise`), daily time-weighted return
(`twrDaily`, Modified-Dietz), risk metrics (vol/VaR/CVaR/Sharpe/Sortino/Calmar/Ulcer/max-drawdown via
`riskMetrics`, historical/empirical), parametric VaR/CVaR at an arbitrary confidence (Gaussian via
`gaussianVaR`/`gaussianCVaR`, skew/kurtosis-adjusted Cornish-Fisher via `cornishFisherVaR`/
`cornishFisherCVaR`, bundled per-series as `parametricRisk`), beta/alpha/R² (`betaAlpha`), tracking
error + information ratio (`trackingRisk`), the Omega ratio (`omegaRatio`), a generic rolling-window
reducer (`rollingApply`, plus `rollingMean`/`rollingVolatility`/`rollingSharpe` wrappers), a seeded
Monte-Carlo net-worth projection (`monteCarlo`), a pairwise-Pearson correlation matrix
(`correlationMatrix`), a drawdown-episode state machine (`drawdownEpisodes`), and Brinson-Fachler
performance attribution (`brinsonAttribution`). Every function is a pure transform over a
caller-owned allocator (normally an arena): `Dataset → Dataset` (table/series producers) or
`Dataset → f64` (scalar reducers) — no hidden state, no I/O. Numeric conventions are exact and
deliberate (decisions, not bugs): `xirr` is 200-iteration bisection over `[-0.99, 10]`, ACT/365.25
day-count, tolerance `1e-2` (kept exactly as-is; `xirrPrecise` is an additive Newton-first sibling
that falls back to the same bracket/bisection on non-convergence). Both first check that NPV
changes sign across the bracket and return `error.XirrNoRoot` when it does not — a bracket bound is
indistinguishable from a real answer at the call site, and used to be returned as one. Both also
take an `opening` mode selecting whether the first row's `value_col` is seeded as a starting
position, which is what a series sliced to a date-range window needs; the default `.none` leaves an
inception-to-date result bit-identical. `riskMetrics`' `var95`/`cvar95`
are historical (empirical), not a parametric fit — the parametric fit lives in `parametricRisk`
instead, at a caller-chosen `confidence` (95%/99%/…), where `cornishFisherCVaR` integrates the
CF-adjusted quantile function (fixed-step trapezoidal quadrature) rather than a naive `φ(z_cf)/α`
plug-in, because that shortcut can report CVaR below VaR for negative-skew/fat-tailed inputs (see
its doc comment); `monteCarlo`
uses a fixed-seed deterministic PRNG (`std.Random.DefaultPrng`, seed `0x9E3779B97F4A7C15`) via
Box-Muller so percentile outputs are reproducible/regression-testable; `correlationMatrix` gates
pairs on `min_overlap` (default 30); `brinsonAttribution` is the Brinson-Fachler variant
(benchmark-relative allocation term `rb_i − Rb`), whose three effects sum exactly to the portfolio's
active return `Rp − Rb`, an algebraic identity (assumes weights each sum to 1) pinned by test. f64
throughout — deliberately no `decimal` dependency: risk
statistics are inherently floating-point, `decimal` is for exact ledger arithmetic, not variance/
quantile math. Platform: any (pure logic, no OS calls). Role: util. Concurrency: reentrant (no
shared state). Depends on `dataset` only. Original work of the zig-libs authors, modeled after the
Python `empyrical`/`ffn` metric set and a QuantLib subset (mirrored, not invented — behavior/
metric-set only, no code consulted or copied); the numeric behavior is exact, pinned by the tests.
See NOTICE.

## Threat model / out of scope
Not security-sensitive; the contract is numerical fidelity to the documented conventions above, not
defense against hostile input — a malformed `Dataset` (missing column) surfaces as a typed
`error.NoSuchColumn`, never a panic; allocation failure surfaces as `error.OutOfMemory`. Out of
scope / deferred (a faithful v1 lift, not a complete risk-analytics suite): arbitrary
annualization-frequency presets/bounds checking (`periods_per_year` is a free 252-defaulted knob,
same as before); confidence intervals/standard errors on the statistics. (Parametric VaR/CVaR,
tracking error/information ratio, Omega ratio, rolling-window variants, Brinson attribution, an
arbitrary VaR confidence level, and an xirr Newton-with-bisection-fallback were all backlog items
here — now implemented, see Design & invariants above.)

## Verification
Tests pin the numeric conventions above: xirr against known cash-
flow fixtures, twrDaily Modified-Dietz with warm-up trim, riskMetrics' 9-metric row incl. historical
VaR/CVaR and Sharpe/Sortino/Calmar/Ulcer, betaAlpha's cov/var/r² derivation, monteCarlo's
reproducible percentile output under the fixed seed, correlationMatrix's min_overlap gating,
drawdownEpisodes' peak→trough→recovery state machine incl. still-underwater-at-series-end (null
recovery), xirrPrecise's Newton result plus a forced-fallback case landing on the same answer,
xirr's windowed behaviour on all three `opening` modes (including one fixture where the two seeding
conventions give opposite signs, which is what pins the chosen double-count convention) and its
no-root detection, a single test calling EVERY allocating public function on
`std.testing.allocator` so scratch that is never released fails the suite,
gaussianVaR/CVaR against textbook standard-normal values (with the CVaR≥VaR invariant),
cornishFisherZ collapsing to the raw z-score at zero skew/kurtosis, skewness/excessKurtosis on a
known symmetric fixture, cornishFisherVaR/CVaR widening the tail vs the Gaussian fit for a
negative-skew/fat-tail input (a case where the *rejected* naive CVaR shortcut would have violated
CVaR≥VaR), parametricRisk's Dataset wiring against direct scalar-fn calls, trackingRisk's hand-
computed tracking-error/information-ratio plus a sign-flip control, omegaRatio's hand-computed
ratio plus a no-losses→+∞ control, rollingApply's mean/vol/sharpe wrappers plus a custom comptime
reducer and an empty-window-count edge case, and brinsonAttribution's per-segment effects plus the
TOTAL-sums-to-active-return identity. Run: `zig build test-finstats` (also
`-Doptimize=ReleaseFast`), `zig fmt --check modules/finstats`.

## Backlog / deferred
Everything from the original backlog is now implemented (see Design & invariants + Verification
above). Remaining, genuinely deferred: annualization-frequency presets/bounds checking beyond the
free `periods_per_year` knob; confidence intervals/standard errors on the statistics.

## Status
`extract · any · util · reentrant` · deps: `dataset` — canonical source is `pub const meta` in
src/root.zig.

## Anchoring

**Anchor grade:** class B · oracle MIXED

- **Class B** — published cryptographic or algorithmic construction with published vectors.
- **Oracle MIXED** — anchored for some paths, self for others — the evidence below names which.

**What the tests actually contain.** src/root.zig:1559 pins annualized vol / max drawdown / VaR95 / CVaR95 to ffn 1.1.5's own output on an 8-day return series; xirr, TWR/Modified-Dietz, beta/alpha, Brinson attribution, Omega and Cornish-Fisher remain hand-computed fixtures with no foreign oracle

**How it got there.** The anchoring work landed. DONE 1e757f4: ffn oracle on 8-return series; conventions established first
