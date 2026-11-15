# indicators — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-15** — Anchor: live oracle `tools/interop.zig` (TA-Lib C 0.8.3 behind a C shim, `zig build interop-indicators`, 1999 records, f64 and f32, unstable 0/3/AUTO4/AUTO8) and 114 frozen vectors (`src/testdata/talib_vectors.zig`, replayed by `src/oracle_test.zig`): every value bitwise equal. **Fixed:** `macdfix` derived its fixed 0.15/0.075 smoothing pair from untyped float literals (folded at more than double precision), so its MACD line differed from TA-Lib by up to millions of ULPs; now typed f64 constants.
- **2026-11-15** — **BEHAVIOURAL (module is new, unreleased):** `nan = .skip` now carries the previous output over a skipped bar instead of NaN (stream `update` answers the last output); MACDEXT, STOCH and STOCHF take an allocator first and keep intermediate series in f64 for `f32` input (f32 output is the f64 result rounded once). New tests pin the NaN behaviour of the windowed functions and MAX/MIN ties (0.0 vs -0.0); SPEC records the RSI NaN deviation and the in-place backlog item.
- **2026-11-15** — NO CONSUMER-VISIBLE CHANGE: the root README catalog row, module count (260), Portability and Libraries tables for this module, rendered by `gen-catalog`, `gen-portable-table` and `gen-libs-table`; the Maturity grade line in SPEC.md is generated the same way.
- **2026-11-15** — New module: technical-analysis indicators over slices with TA-Lib C 0.8.3 as the reference (formulas ported, see NOTICE). Seed set: SMA, EMA, WMA, MA, MACD, MACDEXT, MACDFIX, RSI, BBANDS, TRANGE, ATR, NATR, STOCH, STOCHF, MAX, MIN, SUM; each with a batch function over `f32`/`f64`, a `Lookback` function and a streaming type; per-call unstable period (`.bars`, `.auto4`, `.auto8`), `nan = .skip` and `seed = .first` options. Verified by hand-derived vectors and batch-equals-streaming tests only: frozen TA-Lib vectors and the live oracle are pending.
