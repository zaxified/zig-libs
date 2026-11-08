// SPDX-License-Identifier: MIT
//! finstats: portfolio and financial statistics over plain slices: xirr, TWR,
//! risk metrics (vol/VaR/CVaR/Sharpe/Sortino/Calmar), beta/alpha, Monte-Carlo,
//! correlation, drawdown episodes, return ratios, calendar aggregation,
//! overfitting probability, factor attribution. f64 throughout (statistics, not
//! ledger).
//!
//! Pure functions over `[]const f64` (and `[]const []const u8` ISO dates). Every
//! function lives in `slice.zig` and is re-exported here by name; scalar
//! functions return the number, series functions return an owned slice and take
//! the allocator first. The numeric behaviour is exact: VaR/CVaR are historical
//! (empirical), the Monte-Carlo PRNG is fixed-seed deterministic. `slice` itself
//! stays exported as a deprecated alias namespace for one release (it used to
//! be the slice API next to the removed `Dataset` functions of this file).

const std = @import("std");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Portfolio/financial statistics over plain slices — XIRR, TWR, risk, beta, Monte-Carlo, correlation, drawdowns.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util,
    .concurrency = .reentrant,
    .model_after = "Python empyrical/ffn; QuantLib subset",
    .deps = .{},
};

/// Deprecated alias for the root namespace, kept for one release: `finstats.slice.X`
/// is `finstats.X`.
pub const slice = @import("slice.zig");

pub const max_histogram_bins = slice.max_histogram_bins;
pub const max_monte_carlo_cells = slice.max_monte_carlo_cells;
pub const max_monte_carlo_months = slice.max_monte_carlo_months;
pub const max_corr_keys = slice.max_corr_keys;
pub const max_corr_work = slice.max_corr_work;
pub const max_xirr_work = slice.max_xirr_work;
pub const max_rolling_work = slice.max_rolling_work;
pub const max_newton_iter_cap = slice.max_newton_iter_cap;
pub const annualize = slice.annualize;
pub const quantileSorted = slice.quantileSorted;
pub const quantile = slice.quantile;
pub const normalPdf = slice.normalPdf;
pub const invNormCdf = slice.invNormCdf;
pub const gaussianVaR = slice.gaussianVaR;
pub const gaussianCVaR = slice.gaussianCVaR;
pub const cornishFisherZ = slice.cornishFisherZ;
pub const cornishFisherVaR = slice.cornishFisherVaR;
pub const cornishFisherCVaR = slice.cornishFisherCVaR;
pub const skewness = slice.skewness;
pub const excessKurtosis = slice.excessKurtosis;
pub const omegaRatio = slice.omegaRatio;
pub const rollingMeanReducer = slice.rollingMeanReducer;
pub const rollingVolReducer = slice.rollingVolReducer;
pub const rollingSharpeReducer = slice.rollingSharpeReducer;
pub const winRate = slice.winRate;
pub const payoffRatio = slice.payoffRatio;
pub const profitFactor = slice.profitFactor;
pub const kellyCriterion = slice.kellyCriterion;
pub const tailRatio = slice.tailRatio;
pub const totalReturn = slice.totalReturn;
pub const cagrPeriods = slice.cagrPeriods;
pub const geometricMean = slice.geometricMean;
pub const maxDrawdown = slice.maxDrawdown;
pub const sharpeRatio = slice.sharpeRatio;
pub const sortinoRatio = slice.sortinoRatio;
pub const calmarRatio = slice.calmarRatio;
pub const gainToPain = slice.gainToPain;
pub const recoveryFactor = slice.recoveryFactor;
pub const bestReturn = slice.bestReturn;
pub const worstReturn = slice.worstReturn;
pub const avgWin = slice.avgWin;
pub const avgLoss = slice.avgLoss;
pub const maxConsecutiveWins = slice.maxConsecutiveWins;
pub const maxConsecutiveLosses = slice.maxConsecutiveLosses;
pub const stability = slice.stability;
pub const Opening = slice.Opening;
pub const Error = slice.Error;
pub const XirrError = slice.XirrError;
pub const bracket_lo = slice.bracket_lo;
pub const bracket_hi = slice.bracket_hi;
pub const default_rate_tol = slice.default_rate_tol;
pub const dayNumber = slice.dayNumber;
pub const daySpan = slice.daySpan;
pub const xirr = slice.xirr;
pub const PreciseOpts = slice.PreciseOpts;
pub const xirrPrecise = slice.xirrPrecise;
pub const Twr = slice.Twr;
pub const twrDaily = slice.twrDaily;
pub const Bin = slice.Bin;
pub const histogram = slice.histogram;
pub const volatility = slice.volatility;
pub const downsideDeviation = slice.downsideDeviation;
pub const varHistoric = slice.varHistoric;
pub const cvarHistoric = slice.cvarHistoric;
pub const ulcerIndex = slice.ulcerIndex;
pub const RiskOpts = slice.RiskOpts;
pub const RiskRow = slice.RiskRow;
pub const riskMetrics = slice.riskMetrics;
pub const ParamRow = slice.ParamRow;
pub const parametricRisk = slice.parametricRisk;
pub const beta = slice.beta;
pub const rSquared = slice.rSquared;
pub const BetaRow = slice.BetaRow;
pub const betaAlpha = slice.betaAlpha;
pub const TrackRow = slice.TrackRow;
pub const trackingRisk = slice.trackingRisk;
pub const BenchRow = slice.BenchRow;
pub const benchmarkStats = slice.benchmarkStats;
pub const informationRatio = slice.informationRatio;
pub const treynorRatio = slice.treynorRatio;
pub const Greeks = slice.Greeks;
pub const greeks = slice.greeks;
pub const BrinsonRow = slice.BrinsonRow;
pub const BrinsonResult = slice.BrinsonResult;
pub const brinsonAttribution = slice.brinsonAttribution;
pub const cumulativeReturnsInto = slice.cumulativeReturnsInto;
pub const cumulativeReturns = slice.cumulativeReturns;
pub const drawdownSeriesInto = slice.drawdownSeriesInto;
pub const drawdownSeries = slice.drawdownSeries;
pub const Episode = slice.Episode;
pub const drawdownEpisodes = slice.drawdownEpisodes;
pub const rollingApply = slice.rollingApply;
pub const rollingApplyCtx = slice.rollingApplyCtx;
pub const rollingMean = slice.rollingMean;
pub const rollingVolatility = slice.rollingVolatility;
pub const rollingSharpe = slice.rollingSharpe;
pub const BetaAlphaPoint = slice.BetaAlphaPoint;
pub const rollingBetaAlpha = slice.rollingBetaAlpha;
pub const TradeRow = slice.TradeRow;
pub const tradeStats = slice.tradeStats;
pub const PeriodRow = slice.PeriodRow;
pub const periodStats = slice.periodStats;
pub const pearson = slice.pearson;
pub const correlationMatrix = slice.correlationMatrix;
pub const MonteCarloSpec = slice.MonteCarloSpec;
pub const McRow = slice.McRow;
pub const monteCarlo = slice.monteCarlo;
pub const max_rank_work = slice.max_rank_work;
pub const avgReturn = slice.avgReturn;
pub const riskReturnRatio = slice.riskReturnRatio;
pub const ulcerPerformanceIndex = slice.ulcerPerformanceIndex;
pub const serenityIndex = slice.serenityIndex;
pub const commonSenseRatio = slice.commonSenseRatio;
pub const cpcIndex = slice.cpcIndex;
pub const profitRatio = slice.profitRatio;
pub const winLossRatio = slice.winLossRatio;
pub const exposure = slice.exposure;
pub const rar = slice.rar;
pub const outliers = slice.outliers;
pub const removeOutliers = slice.removeOutliers;
pub const outlierWinRatio = slice.outlierWinRatio;
pub const outlierLossRatio = slice.outlierLossRatio;
pub const autocorrPenalty = slice.autocorrPenalty;
pub const smartSharpe = slice.smartSharpe;
pub const smartSortino = slice.smartSortino;
pub const sortinoSqrt2 = slice.sortinoSqrt2;
pub const smartSortinoSqrt2 = slice.smartSortinoSqrt2;
pub const adjustedSortino = slice.adjustedSortino;
pub const skewSample = slice.skewSample;
pub const kurtosisSample = slice.kurtosisSample;
pub const normalCdf = slice.normalCdf;
pub const RatioBase = slice.RatioBase;
pub const probabilisticRatio = slice.probabilisticRatio;
pub const probabilisticSharpeRatio = slice.probabilisticSharpeRatio;
pub const probabilisticSortinoRatio = slice.probabilisticSortinoRatio;
pub const probabilisticAdjustedSortinoRatio = slice.probabilisticAdjustedSortinoRatio;
pub const expectedMaxSharpe = slice.expectedMaxSharpe;
pub const deflatedSharpeRatio = slice.deflatedSharpeRatio;
pub const probMom = slice.probMom;
pub const pctRank = slice.pctRank;
pub const riskOfRuin = slice.riskOfRuin;
pub const max_resample_cells = slice.max_resample_cells;
pub const max_resample_sims = slice.max_resample_sims;
pub const max_hurst_len = slice.max_hurst_len;
pub const max_gpd_work = slice.max_gpd_work;
pub const Period = slice.Period;
pub const PeriodReturn = slice.PeriodReturn;
pub const aggregateReturns = slice.aggregateReturns;
pub const monthlyReturns = slice.monthlyReturns;
pub const yearlyReturns = slice.yearlyReturns;
pub const mtdReturn = slice.mtdReturn;
pub const ytdReturn = slice.ytdReturn;
pub const winQuarter = slice.winQuarter;
pub const bestPeriod = slice.bestPeriod;
pub const worstPeriod = slice.worstPeriod;
pub const avgUpMonth = slice.avgUpMonth;
pub const avgDownMonth = slice.avgDownMonth;
pub const expectedMonthlyReturn = slice.expectedMonthlyReturn;
pub const expectedYearlyReturn = slice.expectedYearlyReturn;
pub const gainToPainMonthly = slice.gainToPainMonthly;
pub const toReturns = slice.toReturns;
pub const toReturnsInto = slice.toReturnsInto;
pub const toLogReturns = slice.toLogReturns;
pub const toLogReturnsInto = slice.toLogReturnsInto;
pub const toPriceIndex = slice.toPriceIndex;
pub const toPriceIndexInto = slice.toPriceIndexInto;
pub const rebase = slice.rebase;
pub const rebaseInto = slice.rebaseInto;
pub const deannualize = slice.deannualize;
pub const toExcessReturns = slice.toExcessReturns;
pub const toExcessReturnsInto = slice.toExcessReturnsInto;
pub const winsorize = slice.winsorize;
pub const rescale = slice.rescale;
pub const rollingSortino = slice.rollingSortino;
pub const rollingSharpeRf = slice.rollingSharpeRf;
pub const rollingCagr = slice.rollingCagr;
pub const rollingMaxDrawdown = slice.rollingMaxDrawdown;
pub const rollingWinRate = slice.rollingWinRate;
pub const rollUpCapture = slice.rollUpCapture;
pub const rollDownCapture = slice.rollDownCapture;
pub const Dist = slice.Dist;
pub const McResult = slice.McResult;
pub const montecarlo = slice.montecarlo;
pub const montecarloCagr = slice.montecarloCagr;
pub const montecarloDrawdown = slice.montecarloDrawdown;
pub const montecarloSharpe = slice.montecarloSharpe;
pub const AlphaBeta = slice.AlphaBeta;
pub const alphaBeta = slice.alphaBeta;
pub const jensenAlpha = slice.jensenAlpha;
pub const upAlphaBeta = slice.upAlphaBeta;
pub const downAlphaBeta = slice.downAlphaBeta;
pub const excessSharpe = slice.excessSharpe;
pub const Batting = slice.Batting;
pub const battingAverage = slice.battingAverage;
pub const betaFragilityHeuristic = slice.betaFragilityHeuristic;
pub const GpdRisk = slice.GpdRisk;
pub const gpdVarEs = slice.gpdVarEs;
pub const gpdRiskEstimates = slice.gpdRiskEstimates;
pub const conditionalDrawdownAtRisk = slice.conditionalDrawdownAtRisk;
pub const lambdaFromSpan = slice.lambdaFromSpan;
pub const ewmaVolatility = slice.ewmaVolatility;
pub const hurstExponent = slice.hurstExponent;
pub const evarGaussian = slice.evarGaussian;
pub const capture = slice.capture;
pub const upCapture = slice.upCapture;
pub const downCapture = slice.downCapture;
pub const upDownCapture = slice.upDownCapture;
pub const rollUpDownCapture = slice.rollUpDownCapture;
pub const rollAlphaBeta = slice.rollAlphaBeta;
pub const rollingGreeks = slice.rollingGreeks;
pub const yearFrac = slice.yearFrac;
pub const resampleReturns = slice.resampleReturns;
pub const max_combinations = slice.max_combinations;
pub const max_work = slice.max_work;
pub const max_cells = slice.max_cells;
pub const sharpePerPeriod = slice.sharpePerPeriod;
pub const OverfitDetail = slice.OverfitDetail;
pub const probBacktestOverfitting = slice.probBacktestOverfitting;
pub const probBacktestOverfittingDetail = slice.probBacktestOverfittingDetail;
pub const max_output_cells = slice.max_output_cells;
pub const Shape = slice.Shape;
pub const Attribution = slice.Attribution;
pub const computeExposures = slice.computeExposures;
pub const perfAttrib = slice.perfAttrib;

// ── tests (headless: `zig build test-finstats`) ──────────────────────────────

test {
    // The public functions on small series, hand-computed or published.
    _ = @import("api_test.zig");
    // External anchor: reference values from pyxirr, scipy, numpy, pandas and
    // empyrical-reloaded (tools/oracle.py).
    _ = @import("oracle_test.zig");
    _ = @import("sweep_test.zig");
    // Period statistics vs empyrical / ffn / quantstats; twrDaily and Brinson
    // against independent models (tools/oracle.py, tools/attrib_model.py).
    _ = @import("period_test.zig");
    // Published worked examples and ffn's calmar (tools/calmar_oracle.py).
    _ = @import("attrib_oracle_test.zig");
    // NaN, empty, zero variance, all-negative, very long series.
    _ = @import("edge_test.zig");
    // Errors, caps and degenerate input of the slice functions.
    _ = @import("slice_test.zig");
    _ = @import("ratios_test.zig");
    _ = @import("calendar_test.zig");
    _ = @import("overfit_test.zig");
    _ = @import("factor_test.zig");
    _ = @import("fuzz_test.zig");
}
