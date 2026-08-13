# decimal — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
