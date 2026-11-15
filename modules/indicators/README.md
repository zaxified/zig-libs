# indicators

Technical-analysis indicators over plain slices, with **TA-Lib C 0.8.3** as the reference:
SMA, EMA, WMA and an `ma` dispatcher over `MaType`, MACD (plus MACDEXT and MACDFIX), RSI,
Bollinger bands, TRANGE / ATR / NATR, stochastic (slow and fast), and rolling MAX / MIN / SUM.
This is the seed set (wave I2) of the plan to cover all 240 TA-Lib functions; it establishes the
patterns the later waves copy — sliding window, recursive with an unstable period, OHLC input,
several outputs, MA-type dispatch.

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
- **Not built yet:** the moving-average types other than SMA, EMA, WMA (and the identity `.disabled`)
  answer `error.Unsupported`; the other 223 functions come in later waves. See SPEC.md.
- **Model after:** TA-Lib C 0.8.3 (`kand`, Rust, is the speed candidate for a later benchmark).
- **Platform:** any (pure logic). **Role:** util. **Concurrency:** reentrant (no shared state).
- **Depends on:** nothing. Math is f64 for both `f32` and `f64` input.

Provenance: formulas, constants and operation order ported from the C source of TA-Lib 0.8.3
(BSD-3-Clause, Mario Fortier); its notice and licence text are in [`NOTICE`](NOTICE). No TA-Lib
code is vendored or linked.
