# indicators tools

- `interop.zig` + `talib_oracle.c`: the live differential oracle against TA-Lib C 0.8.3.
  `zig build interop-indicators` (compiled by `check-interop`); header comment says what it needs.
  `-- --emit-vectors modules/indicators/src/testdata/talib_vectors.zig` regenerates the frozen
  vectors `src/oracle_test.zig` replays.
- Oracle archive: `TALIB_A` (default `~/.local/share/zig-libs/oracle-bin/ta-lib-0.8.3/libta-lib.a`) and
  headers `TALIB_INC`. Recipe, kept out of the repo build: unpack the audited `ta-lib-0.8.3` tarball
  (sha256 `28b1179b178a0db15f3dad0d846ef77f18eb06db5dfc5b5a8ca153a9ea5d84e6`), compile every
  `src/ta_func/*.c`, `src/ta_common/*.c` (and the abstract layer files the archive needs) with your
  own `cc -O2 -ffp-contract=off -fno-math-errno -I include -I src/ta_common -I src/ta_func -c`, never TA-Lib's CMake/configure, and
  `ar rcs libta-lib.a *.o`. Nothing foreign is vendored; the checkout stays outside the repository.
  ⚠ `-ffp-contract=off` is load-bearing, exactly as in TA-Lib's own CMakeLists/configure: TA-Lib marks
  its fused functions `target_clones("default","fma")`, and GCC's default `-ffp-contract=fast` would
  contract every `a*b+c` inside the fma clone, so the reference would depend on the CPU it runs on
  (2026-11-15: bitwise on one host, 7 functions off by up to 144 ULP on a CI runner). With it off,
  explicit `fma()` is the only fusion and both clones agree. `-fno-math-errno` is value-neutral.
- Inputs per function: `seriesOf` in `interop.zig` names them as letters in the order of the TA-Lib prototype: o(pen) h(igh)
  l(ow) c(lose) v(olume), and x, the generated second series of VWMA (volume) and MAVP (per-bar periods, `genAux`);
  two-series functions (BETA, CORREL, ADD, ...) read close and open. Integer outputs (SUPERTREND trend, ZIGZAG trend and pivot
  index, MAXINDEX / MININDEX / MINMAXINDEX) travel as doubles; index outputs are compared as integers. The record layout carries 8
  parameter doubles (SAREXT has eight parameters). `LINEARREG_ANGLE` has a 2 ULP bound (libm `atan`, see SPEC).
  The cycle wave adds a second allowance, `scaled_bound`: a distance as a fraction of the largest |value| of the same output of the
  same record (1e-13 for the Hilbert family and MAMA, 1e-12 for any function whose MA slot is MAMA), because a last-bit `atan`
  difference carried by their recursion reads as thousands of ULPs on an output that is near zero. `interop-indicators` prints the
  measured maximum (`max/colmax`) next to the ULP maximum. TRENDMODE's integer output travels as doubles like SUPERTREND's; the
  Hilbert functions have a 100-bar frozen vector (their first output is bar 32 / 63) and an extra 700-bar run for their AUTO warm-up.
- Wire format beyond the first six integers: the record carries `xp`, six more integers (KST and KSTEXT take up to eleven); the
  momentum wave's extra doubles of SQZMOM sit in `dp[2..3]`. One function-id space for all waves (0..236, the `Func` enum is the
  table); the momentum functions are 119..175, the candlestick patterns 176..236, and PSO has a 2 ULP bound (`tanh`, see SPEC). Header byte 3 of a record is the candle-settings preset flag (0 for every other function); when set, the 11-entry settings block follows `xp`.
- Candlestick patterns (61 functions, ids 176..236 after the momentum wave, alphabetical): four series `ohlc`, one integer output compared as a double. `tools/candle_gen.zig` generates the inputs
  (single-bar shapes and multi-bar motifs, kind 1 = 0.25 price grid for exact ties, kind 2 = scale 1e-9) and the settings presets 1..4 (`TA_SetCandleSettings` through the record's candle-settings block: 11 x
  range type, averaging period, factor; the shim resets them after each record). `interop-indicators` prints, per pattern, how many compared values had a nonzero TA-Lib answer (a pattern compared only on zeros is not
  verified; goal >= 20). The frozen vectors hold default settings only (the first records with a nonzero answer, 40 bars, f64 and f32 where found).
