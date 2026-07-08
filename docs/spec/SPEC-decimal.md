# SPEC — `decimal`

**Purpose** — Exact base-10 fixed-point arithmetic for money and ETL math, where `0.1 + 0.2` must
be exactly `0.3` and no binary-float noise is tolerable. Values are an `i128` scaled by `10^12`
(12 fractional digits) — like a database `DECIMAL(38,12)` — with parse, arithmetic and format all
on pure integer paths (no `f64`/`f128` anywhere). The numeric leaf primitive other modules build on.

**Model after / Seed** — Java `BigDecimal` (incl. `RoundingMode`) / IBM General Decimal Arithmetic /
Python `decimal` semantics, fixed-scale like DB `DECIMAL(38,12)`. Extracted from the authors' bxp
`bxp-core/src/decimal.zig` (where it replaced an `f80` core, proven on 40M-row ETL; Apache-2.0,
relicensed MIT). The seven rounding modes are clean-room from the published definitions/truth-tables
(BigDecimal javadoc, GDA spec, Python docs) — definitions only, no source copied. See `NOTICE`.

**Design & invariants**
- **Pure integer, no floats, never UB.** Range ±1.7e26 with step `1e-12`. `+ −` are exact; `× ÷`
  widen to **i256 intermediates** so a product of two large operands cannot overflow before the
  rescale. Any result beyond the i128 range is a typed `error.Overflow`; `÷` by zero is
  `error.DivisionByZero`; there is no Inf/NaN and no silent wrap.
- **Two rounding surfaces.** The classic ops (`mul`/`div`/`round`) round **half-away-from-zero**
  ("school"/Excel display rounding). The controlled ops (`rescale`, `roundToIntegral`, `quantize`,
  `divRound` at an explicit result scale) take an explicit `RoundingMode` —
  `half_even` (default) / `half_up` / `half_down` / `up` / `down` / `ceiling` / `floor` — with exact
  integer half-way detection (`r == d − r`), no doubling overflow.
- **Boundary policy is explicit per op.** `floor`/`ceil`/`round` return the value unchanged in the
  single unrepresentable case at the i128 extreme (rather than erroring); `rescale`/`quantize`/
  `divRound` error on overflow. `neg`/`abs` error only at the asymmetric i128 minimum.
- **Allocation-free, reentrant.** `toString` writes into a caller `[str_buf_len]u8`; a `{f}`
  formatter integrates with `std.fmt`. No shared state.
- **Parse** accepts sign, decimal point and scientific notation; fractional digits past 12 round
  half-away-from-zero into the 12th; junk/empty/double-dot/thousands-grouped input →
  `error.InvalidCharacter`, out-of-range or >60-digit mantissa → `error.Overflow`.

**Threat model / out of scope** — Not security-sensitive; the contract is numerical correctness.
The i256 scaling multiply and the parse accumulator are overflow-checked so hostile inputs (huge
mantissa × exponent) yield a clean error, never a trap. Out of scope: arbitrary/unbounded precision
(the scale is fixed at 12), locale/grouping-aware parsing (the caller strips separators), currency
semantics, and any float interchange. Deltas from the seed are failure-path hardening only
(`?Decimal` → error unions; div-quotient, parse-accumulator and `fromInt` overflow checks;
`floor`/`ceil` in i256; allocation-free `toString`) — the value semantics are preserved exactly.

**Verification** — Unit tests ported from the seed plus extraction additions: parse↔format
round-trips, exact arithmetic (`0.02+0.08=0.10`, `0.1+0.2=0.3`), mul/div half-away rounding at the
12th-digit boundary on both signs, i256-intermediate large-product correctness, clean `error.Overflow`
at the ceiling (add/sub/mul/div/fromInt), range boundaries incl. the asymmetric minimum formatting
exactly, and hostile parse (mantissa×exponent) not trapping. RoundingMode coverage is a 16-row × 7-mode
truth table hand-derived from the BigDecimal/GDA/Python definitions, plus half-way-at-2dp for every
mode on both signs, and `rescale`/`divRound`/`quantize` edges (scale-up exact, negative scale,
i128-boundary overflow).

**Status** — `extract · any · util · reentrant` · deps: none (std only).
