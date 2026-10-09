# decimal — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-09** — tests: deterministic fuzz driver `DECIMAL_FUZZ` over the existing harnesses.
- **2026-10-04** — **BEHAVIOURAL** fixes found by the mutation run: `Decimal.round(n)` with a rounding
  place beyond 10^36 now returns 0 (it returned the value unchanged; `rescale` already gave 0);
  `Decimal.parse` of a magnitude below 1e-60 now rounds half-away to the 12th place (0 below half an
  ulp) instead of `error.Overflow`; `BigDecimal.parse` no longer truncates exponent literals longer
  than 15 digits (`1e0000000000000012` is now exponent 12, was 1) and reports `error.Overflow` for
  more than 15 significant exponent digits. No signature or error-set change.
- **2026-10-04** — Tests: mutation run (117 mutants, 97 killed, 19 equivalent, 1 superseded) added
  boundary pins for i128/i32 limits, rounding-place caps, exponent/width caps, `max_align_shift`,
  `toFloat` cut-off, -0 min/max, sqrt digit budgets and exact quotients in every mode.
- **2026-09-30** — Float bridge (parity with Python `decimal`/rust_decimal): `Decimal.fromFloat`,
  `Decimal.fromFloatShortest`, `Decimal.toFloat` and `BigDecimal.fromFloat`, `fromFloatExact`,
  `fromFloatShortest`, `toFloat`. `fromFloat` refuses NaN/±Inf with `error.NotFinite`, converts the
  binary value **exactly** and rounds once with the caller's `RoundingMode` (`Decimal`: out of range
  is `error.Overflow`, never a wrap; `2.675` at 2 places half-up is `2.67`, as in Python);
  `fromFloatShortest` starts from the shortest round-trip digits instead (`2.675` → `2.68`);
  `toFloat` is the correctly rounded nearest `f64`, ties to even, and out of range is `±inf` / a
  signed zero rather than an error (Python's `float(Decimal('1e400'))` is `inf` too). The bridge
  lives only at these entry points — no arithmetic path calls it and no floating-point arithmetic
  runs inside it. Tests take their expected values from Python's `decimal` (quoted in the test
  comments) plus a seeded random-bit-pattern round trip for `BigDecimal`. Additive, no behaviour
  change to existing functions.
- **2026-09-08** — Test-only, no production change: both `fuzzParse` harnesses claim in a
  comment that their alphabet-substitution loop is inert on a corpus replay, and both
  corpus guards left that loop out — so the claim was unverified and the guard was
  measuring a different computation from the harness. A seed that grew a tail would have
  had a quarter of its literal rewritten before `parse` saw it while `digits` and `parsed`
  went on reporting the same numbers. Both guards now replay the loop and pin the
  substitution count, measured at **0** in `root.zig` and **0** in `big.zig`.


- **2026-09-07** — Both `fuzzParse` targets (`Decimal` and `BigDecimal`) had been parsing the
  empty string and nothing else. Each drew its literal with `smith.bytes(&buf)` and then took
  a length from `smith.valueRangeAtMost(…, 0, buf.len)`; a ranged `Smith` draw reads eight
  octets as a little-endian `u64` and returns the range MINIMUM when fewer remain, and `bytes`
  had already consumed them — so `len` was 0 on every input and both parsers refused at
  `error.InvalidCharacter` before reading a digit, with the literal sitting unread in `buf`.
  Now one `smith.slice(&buf)` call each, plus corpora lifted from the round-trip, rejection
  and overflow tests, and a corpus guard per parser. Measured: **`Decimal` 0 of 24 seeds
  non-empty, 0 parsed, 0 overflows, 0 octets delivered → 23/24 non-empty, 9 parsed, 5
  overflows, 294 octets; `BigDecimal` 0 of 17 non-empty, 0 parsed → 16/17, 10 parsed, 360
  octets.** ⚠ `Decimal`'s harness buffer went 80 → 128: `parse hardening: mantissa width cap
  prevents i256 accumulator overflow` needs a 90-digit input, and a seed longer than the
  buffer reads back EMPTY rather than truncated — so the one input that distinguishes "the
  cap fires early" from "the accumulator traps" could never have passed through the module's
  own harness.
- **2026-08-11** — Security audit: four findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Verified: byte-exact against the
  IBM/Cowlishaw General Decimal Arithmetic `decTest` suite v2.62.
- **2026-07-29** — The two types can finally exchange values, and `BigDecimal` covers the
  rest of the `java.math.BigDecimal` / GDA surface. `Decimal.toBigDecimal`
  is exact and total (a `Decimal` *is* `raw × 10^-12`);
  `Decimal.fromBigDecimal(allocator, b, mode)` is partial in two
  independent ways and says so in the type — excess fractional digits are
  **rounded** with the caller's mode, never truncated, and a magnitude
  past ±1.7e26 is `error.Overflow` checked *after* the rounding, so
  rounding that creates the overflow still errors. A value below half an
  ulp is a rounding decision, not an error. Both the range and
  below-half-ulp cases are decided from the coefficient's digit count
  *before* any power of ten is materialised, so `1e2000000000` returns a
  clean error in constant time. New `BigDecimal` operations: `remainder`
  (truncated-division remainder — sign of the dividend, exponent
  `min(ea, eb)`), `min`/`max` (including GDA's rule for resolving a
  numeric tie by exponent, which flips direction with the sign),
  `precision`, `signum`, `scaleByPowerOfTen`, `stripTrailingZeros` (an
  **alias of the existing `normalize`**, not a second implementation),
  `sqrt` and `pow`. `sqrt` is *correctly rounded* to a caller-given
  significant-digit count — an exact `⌊√N⌋` on a scaled radicand plus one
  exact integer comparison against the half-way point, not
  Newton-until-it-stops-changing, which is right to within an ulp and
  wrong at every rounding boundary — and reproduces GDA's ideal exponent
  for exact roots (`√1.00 = 1.0`). `pow` is integer-exponent-only (the
  `pow(int)` contract: exact, result exponent `a.exponent × n`, negative
  exponents refused rather than silently wrong); GDA's general `power`
  over non-integer exponents needs `exp`/`ln` on bignums and is
  deliberately out of scope. `sqrt`/`pow` are the only operations here
  that can make a value grow, so both check a new `max_result_digits`
  (100,000) budget **before allocating** — power.decTest really does
  contain exponent `1000000007`, and `1.1 ^ 1000000007` is a
  ~10^8-digit number. Conformance is anchored on the IBM/Cowlishaw
  decTest v2.62 suite: 279 remainder, 105 min, 105 max, 3268 square-root
  and 130 integer-power cases, extracted mechanically into
  `src/testdata/*.vec`, each asserting the result's **exponent** as well
  as its digits (the scale is part of the spec for all five ops), each
  file's header recording exactly which source cases were skipped and
  under which rule.
