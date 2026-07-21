# finstats

Portfolio / financial **statistics over `dataset`** — dated-flow IRR (bisection
and a Newton-with-bisection-fallback variant), daily time-weighted return,
risk metrics (vol / VaR / CVaR / Sharpe / Sortino / Calmar / Ulcer /
max-drawdown, historical), parametric VaR / CVaR at an arbitrary confidence
(Gaussian and Cornish-Fisher), beta / alpha / R², tracking error /
information ratio, the Omega ratio, a generic rolling-window reducer, a
seeded Monte-Carlo net-worth projection, a pairwise-Pearson correlation
matrix, a drawdown-episode state machine, and Brinson-Fachler performance
attribution. Every function is a pure transform: `Dataset →
Dataset` (table/series producers) or `Dataset → f64` (scalar reducers), over a
caller-owned allocator (normally an arena).

- **Model after:** the Python `empyrical` / `ffn` metric set and a QuantLib
  subset — mirrored, not invented.
- **Platform:** any (pure logic, no OS calls). **Role:** util.
  **Concurrency:** reentrant (no shared state).
- **Depends on:** [`dataset`](../dataset) only. **f64 throughout** — no
  `decimal` dependency: risk statistics are inherently floating-point;
  `decimal` is for exact ledger arithmetic, not variance/quantile math.

Provenance: original work of the zig-libs authors (MIT); modeled after the
Python `empyrical`/`ffn` metric set and a QuantLib subset (behavior/
metric-set only, no code consulted or copied) — see NOTICE. Algorithms and
constants are exact and the numeric behaviour is pinned by 11 tests.

## Numeric conventions (kept exact — these are decisions, not bugs)

- **`xirr`** — 200-iteration bisection on NPV = 0 over the bracket
  `[-0.99, 10]`, ACT/365.25 day-count, tolerance `1e-2`. External flows are
  negated (contribution = cash out of your pocket); the last row's `value_col`
  is the terminal inflow.
- **`annualize`** — CAGR `(1 + total_return)^(365.25/days) − 1`.
- **`twrDaily`** — Modified-Dietz daily return `r = (v − prev − flow) / pe`,
  skipping rows with performance-eligible base `pe ≤ 1e-6`, with an optional
  leading warm-up trim at `min_value` (skips the noisy near-zero-denominator
  early days).
- **`riskMetrics`** — `ann_vol` = sample-stdev × √periods_per_year (default
  252); `downside` = semi-deviation; **`var95` / `cvar95` are HISTORICAL
  (empirical)** — the 5th-percentile loss and the mean of the tail below it,
  not a parametric fit; `mdd` / `ulcer` from the compounded return level;
  `sharpe` / `sortino` / `calmar` off the annualized return (computed from the
  compounded level over the calendar-day span when `date_col` is given, else
  the static `ann_return`).
- **`betaAlpha`** — `beta = cov / var(bench)`, `r2 = cov² / (varp·varb)`,
  `alpha = port_ann − beta·bench_ann`.
- **`gaussianVaR`/`gaussianCVaR`** — parametric (normal-fit) VaR/CVaR at an
  arbitrary `confidence`, via Peter Acklam's inverse-normal-CDF
  approximation. **`cornishFisherZ`/`cornishFisherVaR`/`cornishFisherCVaR`**
  — skew/kurtosis-adjusted siblings; `cornishFisherCVaR` integrates the
  CF-adjusted quantile function (fixed-step trapezoidal quadrature) rather
  than plugging the CF z-score into the closed-form Gaussian ES ratio — that
  shortcut can report CVaR below VaR for negative-skew/fat-tailed inputs.
  **`parametricRisk`** bundles mean/std/skew/kurt + all four VaR/CVaR
  variants for a return column into one row.
- **`trackingRisk`** — `tracking_error = stdev(port − bench)·√ppy`,
  `information_ratio = mean(port − bench)·ppy / tracking_error` (0 when
  tracking_error is 0).
- **`omegaRatio`** — `Σ gains-above-threshold / Σ losses-below-threshold`;
  `+∞` when there are no losses and some gain, `1.0` when the series sits
  exactly at the threshold.
- **`rollingApply`** — generic sliding-window reducer (comptime `fn
  ([]const f64) f64`) over a value column, `n − window + 1` rows;
  `rollingMean`/`rollingVolatility`/`rollingSharpe` are concrete wrappers.
- **`brinsonAttribution`** — Brinson-Fachler attribution per segment:
  `allocation = (wp−wb)(rb−Rb)`, `selection = wb(rp−rb)`,
  `interaction = (wp−wb)(rp−rb)` (Rb = Σ wb·rb); the three effects sum
  exactly to the active return `Rp − Rb`.
- **`xirrPrecise`** — Newton-Raphson IRR with an automatic bisection
  fallback (same bracket as `xirr`) when Newton fails to converge.
- **`monteCarlo`** — GBM-ish monthly step `v = max(0, v·(1 + muM + sigM·Z) +
  monthly)`, `Z ~ N(0,1)` via Box-Muller, over a **fixed-seed deterministic
  PRNG** (`std.Random.DefaultPrng`, default seed `0x9E3779B97F4A7C15`) so
  percentile outputs are reproducible / regression-testable. Emits
  `{month, p10, p50, p90}`.
- **`correlationMatrix`** — long-form `(key, date, value)` grouped by key,
  aligned by date; pairwise Pearson with a `min_overlap` gate (default 30) —
  pairs with too few shared dates or no variance yield `null`.
- **`drawdownEpisodes`** — peak → trough → recovery state machine, worst
  `top_n` by depth; `recovery` / `recover_days` are `null` while still
  underwater at series end.

## API

```zig
const finstats = @import("finstats");

const Error = finstats.Error; // error{ NoSuchColumn, OutOfMemory }

// scalar reducers
fn xirr(a, d: Dataset, spec: XirrSpec) !f64;
fn xirrPrecise(a, d: Dataset, spec: XirrPreciseSpec) !f64;
fn annualize(total_return: f64, days: f64) f64;
fn quantileSorted(sorted: []const f64, q: f64) f64;
fn quantile(a, xs: []const f64, q: f64) !f64;
fn normalPdf(z: f64) f64;
fn invNormCdf(p: f64) f64;
fn gaussianVaR(mean: f64, std_dev: f64, confidence: f64) f64;
fn gaussianCVaR(mean: f64, std_dev: f64, confidence: f64) f64;
fn cornishFisherZ(z: f64, skew: f64, excess_kurt: f64) f64;
fn cornishFisherVaR(mean: f64, std_dev: f64, skew: f64, excess_kurt: f64, confidence: f64) f64;
fn cornishFisherCVaR(mean: f64, std_dev: f64, skew: f64, excess_kurt: f64, confidence: f64) f64;
fn skewness(xs: []const f64) f64;
fn excessKurtosis(xs: []const f64) f64;
fn omegaRatio(xs: []const f64, threshold: f64) f64;

// one-row / series / table producers → Dataset
fn xirrNode(a, d: Dataset, spec: XirrNodeSpec) !Dataset;       // {out}
fn annualizeNode(a, d: Dataset, spec: AnnualizeNodeSpec) !Dataset; // {out}
fn twrDaily(a, d: Dataset, spec: TwrSpec) !Dataset;            // {d, r}
fn histogram(a, d: Dataset, spec: HistogramSpec) !Dataset;     // {bin_lo, bin_hi, count}
fn riskMetrics(a, d: Dataset, spec: RiskSpec) !Dataset;        // one row, 9 metrics
fn parametricRisk(a, d: Dataset, spec: ParametricRiskSpec) !Dataset; // one row, 8 fields
fn betaAlpha(a, d: Dataset, spec: BetaSpec) !Dataset;          // {beta, alpha, r2}
fn trackingRisk(a, d: Dataset, spec: TrackingSpec) !Dataset;   // {tracking_error, information_ratio}
fn omegaRatioNode(a, d: Dataset, spec: OmegaSpec) !Dataset;    // {out}
fn rollingApply(a, d: Dataset, spec: RollingSpec, comptime reducer: fn ([]const f64) f64) !Dataset;
fn rollingMean(a, d: Dataset, spec: RollingSpec) !Dataset;
fn rollingVolatility(a, d: Dataset, spec: RollingSpec) !Dataset;
fn rollingSharpe(a, d: Dataset, spec: RollingSpec) !Dataset;
fn monteCarlo(a, spec: MonteCarloSpec) !Dataset;               // {month, p10, p50, p90}
fn correlationMatrix(a, d: Dataset, spec: CorrSpec) !Dataset;  // {key, <key>…}
fn drawdownEpisodes(a, d: Dataset, spec: DdEpisodesSpec) !Dataset;
fn brinsonAttribution(a, d: Dataset, spec: BrinsonSpec) !Dataset; // {segment, allocation, selection, interaction, total} + TOTAL row
```

See the `*Spec` structs in `src/root.zig` for the (well-documented) field set
of each function.

## Deferred (backlog, not implemented here)

The v1 backlog below is now implemented (parametric VaR/CVaR, tracking
error/information ratio, Omega ratio, rolling-window reducer, Brinson
attribution, an arbitrary VaR confidence level, and xirr's
Newton-with-bisection-fallback — see the API section above). Still
intentionally out of scope:

- **Annualization-frequency presets / validation** — `periods_per_year` is a
  free 252-defaulted knob with no daily/weekly/monthly presets or bounds check.
- **Confidence intervals / standard errors** on the statistics.

## Verify

```
zig build test-finstats
zig build test-finstats -Doptimize=ReleaseFast
zig fmt --check modules/finstats
```
