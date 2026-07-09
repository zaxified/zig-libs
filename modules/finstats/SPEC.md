# finstats — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
Portfolio/financial statistics over `dataset`: dated-flow IRR (`xirr`), daily time-weighted return
(`twrDaily`, Modified-Dietz), risk metrics (vol/VaR/CVaR/Sharpe/Sortino/Calmar/Ulcer/max-drawdown via
`riskMetrics`), beta/alpha/R² (`betaAlpha`), a seeded Monte-Carlo net-worth projection
(`monteCarlo`), a pairwise-Pearson correlation matrix (`correlationMatrix`), and a drawdown-episode
state machine (`drawdownEpisodes`). Every function is a pure transform over a caller-owned allocator
(normally an arena): `Dataset → Dataset` (table/series producers) or `Dataset → f64` (scalar
reducers) — no hidden state, no I/O. Numeric conventions are preserved exactly from the seed
(decisions, not bugs): `xirr` is 200-iteration bisection over `[-0.99, 10]`, ACT/365.25 day-count,
tolerance `1e-2`; `var95`/`cvar95` are historical (empirical), not a parametric fit; `monteCarlo`
uses a fixed-seed deterministic PRNG (`std.Random.DefaultPrng`, seed `0x9E3779B97F4A7C15`) via
Box-Muller so percentile outputs are reproducible/regression-testable; `correlationMatrix` gates
pairs on `min_overlap` (default 30). f64 throughout — deliberately no `decimal` dependency: risk
statistics are inherently floating-point, `decimal` is for exact ledger arithmetic, not variance/
quantile math. Platform: any (pure logic, no OS calls). Role: util. Concurrency: reentrant (no
shared state). Depends on `dataset` only. Modeled after the Python `empyrical`/`ffn` metric set and
a QuantLib subset (mirrored, not invented); extracted from wgs `src/finance.zig` (same authors,
MIT), itself a faithful port of poc-wf-analytic's `reader.zig` — the numeric behavior has carried
through three code bases unchanged, pinned by the ported tests. No third-party code — see NOTICE.

## Threat model / out of scope
Not security-sensitive; the contract is numerical fidelity to the documented conventions above, not
defense against hostile input — a malformed `Dataset` (missing column) surfaces as a typed
`error.NoSuchColumn`, never a panic; allocation failure surfaces as `error.OutOfMemory`. Out of
scope / deferred (a faithful v1 lift, not a complete risk-analytics suite): parametric VaR/CVaR
(Gaussian/Cornish-Fisher — only historical exists); tracking error/information ratio; Omega ratio;
rolling-window variants of any scalar metric (everything here is whole-series); Brinson (factor)
attribution; arbitrary VaR confidence level (95% is hardcoded) and annualization-frequency presets/
bounds checking (`periods_per_year` is a free 252-defaulted knob); confidence intervals/standard
errors on the statistics; an xirr Newton-with-bisection-fallback (current is pure bisection at a
fixed tolerance).

## Verification
11 tests ported from the wgs seed, pinning the numeric conventions above: xirr against known cash-
flow fixtures, twrDaily Modified-Dietz with warm-up trim, riskMetrics' 9-metric row incl. historical
VaR/CVaR and Sharpe/Sortino/Calmar/Ulcer, betaAlpha's cov/var/r² derivation, monteCarlo's
reproducible percentile output under the fixed seed, correlationMatrix's min_overlap gating, and
drawdownEpisodes' peak→trough→recovery state machine incl. still-underwater-at-series-end (null
recovery). Run: `zig build test-finstats` (also `-Doptimize=ReleaseFast`), `zig fmt --check
modules/finstats`.

## Backlog / deferred
Per the module README's own Backlog: parametric VaR/CVaR (Gaussian/Cornish-Fisher);
tracking error + information ratio; Omega ratio; rolling-window variants of the scalar metrics;
Brinson (factor) attribution (needs a weights input shape — the one genuinely involved addition);
arbitrary VaR confidence level + annualization-frequency presets/validation; confidence intervals/
standard errors on the statistics; xirr Newton-with-bisection-fallback + configurable tolerance.

## Status
`extract · any · util · reentrant` · deps: `dataset` — canonical source is `pub const meta` in
src/root.zig.
