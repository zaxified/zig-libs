# finstats

Portfolio / financial **statistics over `dataset`** — dated-flow IRR, daily
time-weighted return, risk metrics (vol / VaR / CVaR / Sharpe / Sortino /
Calmar / Ulcer / max-drawdown), beta / alpha / R², a seeded Monte-Carlo
net-worth projection, a pairwise-Pearson correlation matrix, and a
drawdown-episode state machine. Every function is a pure transform: `Dataset →
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
fn annualize(total_return: f64, days: f64) f64;
fn quantileSorted(sorted: []const f64, q: f64) f64;
fn quantile(a, xs: []const f64, q: f64) !f64;

// one-row / series / table producers → Dataset
fn xirrNode(a, d: Dataset, spec: XirrNodeSpec) !Dataset;       // {out}
fn annualizeNode(a, d: Dataset, spec: AnnualizeNodeSpec) !Dataset; // {out}
fn twrDaily(a, d: Dataset, spec: TwrSpec) !Dataset;            // {d, r}
fn histogram(a, d: Dataset, spec: HistogramSpec) !Dataset;     // {bin_lo, bin_hi, count}
fn riskMetrics(a, d: Dataset, spec: RiskSpec) !Dataset;        // one row, 9 metrics
fn betaAlpha(a, d: Dataset, spec: BetaSpec) !Dataset;          // {beta, alpha, r2}
fn monteCarlo(a, spec: MonteCarloSpec) !Dataset;               // {month, p10, p50, p90}
fn correlationMatrix(a, d: Dataset, spec: CorrSpec) !Dataset;  // {key, <key>…}
fn drawdownEpisodes(a, d: Dataset, spec: DdEpisodesSpec) !Dataset;
```

See the `*Spec` structs in `src/root.zig` for the (well-documented) field set
of each function.

## Deferred (backlog, not implemented here)

Intentionally out of scope for this faithful v1 lift:

- **Parametric VaR / CVaR** (Gaussian / Cornish-Fisher) — only the historical
  (empirical) estimator exists today.
- **Tracking error + Information ratio; Omega ratio** — additional
  ratio metrics (Ulcer is already present).
- **Rolling-window variants** of the scalar metrics (rolling Sharpe / vol /
  beta over a sliding window) — everything here is whole-series.
- **Brinson (factor) attribution** — sector / asset-class weight-vs-return
  decomposition; the one genuinely involved addition (needs a weights input
  shape), not a one-liner.
- **Arbitrary VaR confidence level** — 95% is hardcoded; and
  **annualization-frequency presets / validation** — `periods_per_year` is a
  free 252-defaulted knob with no daily/weekly/monthly presets or bounds check.
- **Confidence intervals / standard errors** on the statistics, and an **xirr
  Newton-with-bisection-fallback + configurable tolerance** — the current xirr
  is pure bisection at a fixed `1e-2` tolerance.

## Verify

```
zig build test-finstats
zig build test-finstats -Doptimize=ReleaseFast
zig fmt --check modules/finstats
```
