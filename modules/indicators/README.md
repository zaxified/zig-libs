# indicators

Technical-analysis indicators over plain slices, with **TA-Lib C 0.8.3** as the reference:
SMA, EMA, WMA and an `ma` dispatcher over `MaType`, MACD (plus MACDEXT and MACDFIX), RSI,
Bollinger bands, TRANGE / ATR / NATR, stochastic (slow and fast), and rolling MAX / MIN / SUM (the
seed set, wave I2), plus the Overlap Studies of wave I3: DEMA, TEMA, T3, TRIMA, KAMA, ZLEMA, RMA, VIDYA,
HMA, ALMA, MCGD, FRAMA, SWAK_BUTTER, SWAK_GAUSS (moving averages; all of them work in every `MaType` slot
except MAMA), MIDPOINT, MIDPRICE, MAVP, VWMA, the channels ACCBANDS / DONCHIAN / KC / ICHIMOKU and the
trend state machines SAR, SAREXT, SUPERTREND, CKSP, ZIGZAG, and the 50 volume / volatility / price-transform / statistic /
math-operator functions of the same wave (see below). 94 of the 237 TA-Lib functions so far.

```zig
const ind = @import("indicators");

// batch: out.len == closes.len, the lead is NaN, the lookback is returned
var out: [N]f64 = undefined;
const lb = try ind.ema(f64, &closes, &out, .{ .period = 12, .unstable = .auto4 });

// several outputs: one slice each
_ = try ind.macd(f64, &closes, &line, &signal, &hist, .{});
_ = try ind.atr(f64, &high, &low, &close, &out, .{ .period = 14 });

// streaming: the same arithmetic, bit for bit
var s = try ind.RsiStream(f64).init(.{ .period = 14 });
if (s.update(price)) |rsi| use(rsi);

// several inputs and outputs: one slice per field / output; integer outputs are integer slices
_ = try ind.supertrend(f64, &high, &low, &close, &line, &trend_i8, .{});
_ = try ind.ichimoku(f64, &high, &low, &tenkan, &kijun, &span_a, &span_b, .{});
_ = try ind.ma(f64, &closes, &out, .{ .period = 20, .kind = .hma }); // any MaType but MAMA

// streaming with history (windows) takes a caller buffer
const buf = try gpa.alloc(f64, try ind.BbandsStream(f64).bufLen(.{}));
var bb = try ind.BbandsStream(f64).init(.{}, buf);
```

- **TA-Lib parity:** parameter ranges and defaults are TA-Lib's (anything else is
  `error.BadParam`), the lookback is TA-Lib's `TA_<F>_Lookback`, the EMA numerics are TA-Lib 0.8.x's
  (`fma`, the `beta`/`k` pair that sums to exactly 1.0, period 1 as an exact copy). The unstable
  period is a per-call option (`.bars = n`, `.auto4`, `.auto8` with TA-Lib's constants), not a
  process-global setting.
- **Beyond TA-Lib:** `nan = .skip` on the recursive indicators (a NaN bar is ignored), `seed = .first`
  for EMA-based ones (pandas `ewm(adjust=False)`), no global state, no allocation on the batch path.
- **Wave I3, volume and statistics (50 more functions):** volume (AD, ADOSC, CMF, EFI, EMV, KVO, MARKETFI, NVI, OBV, PVI, PVO, PVT, RVOL, VWAP),
  volatility (ADR, BBW, CVI, MASSI, PERCENTB, ROGERSSATCHELL, RVI, RVIR), price transforms (AVGDEV, AVGPRICE, HA, MEDPRICE, TYPPRICE,
  WCLPRICE), statistics (BETA, CORREL, KURTOSIS, LINEARREG and its ANGLE / INTERCEPT / SLOPE, MEDIAN, PERCENTILE, PERCENTRANK, STDDEV, TSF,
  `variance`) and math operators (ADD, SUB, MULT, DIV, CUMSUM, MINMAX, MAXINDEX, MININDEX, MINMAXINDEX), all bitwise equal to TA-Lib
  (LINEARREG_ANGLE within 2 ULP: `atan` of the C library). Multi-input streams take a struct, e.g.
  `ind.AdStream(f64).init(.{})` then `update(.{ .high = h, .low = l, .close = c, .volume = v })`.
- **Not built yet:** MAMA (as a function and as an `MaType`, `error.Unsupported`) and the other 143 functions (momentum, cycle,
  math transform, candlesticks) come in later waves; MAVP has no streaming type. See SPEC.md.
- **Model after:** TA-Lib C 0.8.3 (`kand`, Rust, is the speed candidate for a later benchmark).
- **Platform:** any (pure logic). **Role:** util. **Concurrency:** reentrant (no shared state).
- **Depends on:** nothing. Math is f64 for both `f32` and `f64` input.

- **Evidence:** verified bit for bit against TA-Lib 0.8.3 itself: `zig build interop-indicators` (live oracle,
  see `tools/README.md`) and frozen vectors replayed by `src/oracle_test.zig`.

Provenance: formulas, constants and operation order ported from the C source of TA-Lib 0.8.3
(BSD-3-Clause, Mario Fortier); its notice and licence text are in [`NOTICE`](NOTICE). No TA-Lib
code is vendored or linked.
