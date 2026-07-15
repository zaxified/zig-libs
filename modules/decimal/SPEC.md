# decimal — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
Pure integer, no floats, never UB: `i128` scaled by `10^12` (12 fractional digits), range ±1.7e26
at step `1e-12`. `+ −` are exact; `× ÷` widen to **i256 intermediates** so large-operand products
cannot overflow before rescale. Any out-of-range result is a typed `error.Overflow`; `÷0` is
`error.DivisionByZero`; no Inf/NaN, no silent wrap. Two rounding surfaces: classic ops
(`mul`/`div`/`round`) are half-away-from-zero (Excel-style); controlled ops (`rescale`,
`roundToIntegral`, `quantize`, `divRound`) take an explicit `RoundingMode`
(`half_even`/`half_up`/`half_down`/`up`/`down`/`ceiling`/`floor`) with exact integer half-way
detection, no doubling overflow. Boundary policy is explicit per op: `floor`/`ceil`/`round` return
the value unchanged at the single unrepresentable i128-extreme case; `rescale`/`quantize`/
`divRound` error on overflow instead. Allocation-free and reentrant: `toString` writes into a
caller buffer, no shared state. Modeled after Java `BigDecimal`/IBM GDA/Python `decimal`; see NOTICE.

## Threat model / out of scope
Not security-sensitive — the contract is numerical correctness. The i256 scaling multiply and the
parse accumulator are overflow-checked so hostile input (huge mantissa × exponent) yields a clean
error, never a trap. Out of scope for `Decimal` specifically: arbitrary/unbounded precision (scale
fixed at 12 — see `BigDecimal` below for that), locale/grouping-aware parsing (caller strips
separators), currency semantics, float interchange.

## BigDecimal — arbitrary precision (big.zig)

`BigDecimal` (`std.math.big.int.Managed` significand × `10^exponent`) is a companion module for
values `Decimal`'s fixed `i128 @ 1e12` can't bound ahead of time. Full design rationale lives as
doc comments in `big.zig` itself (not duplicated here per the doc-ownership rule) — this section is
the auditor-altitude summary.

**std.math.big.int inventory (0.16, `lib/std/math/big/int.zig`) — what's free, so nothing below
reimplements it:** exact arbitrary-precision multiply (`Managed.mul`), exact truncating division +
remainder via Knuth Algorithm D (`Managed.divTrunc`), exact magnitude compare
(`Const.order`/`orderAgainstScalar`), exact integer powers (`Managed.pow`, used here for `10^k`),
base-10 digit-string parse (`Managed.setString`) and format (`Const.toStringAlloc`), and a base-10
digit count (`Const.log10`/`log10Alloc`). `gcd`/`sqrt`/bitops also exist but are unused here.

**Honest sizing verdict:** because std already owns the bignum core, this is *not* "implement
arbitrary-precision arithmetic" — it's "compose existing bignum primitives with exhaustive,
spec-literal correctness in the one place a rounding-mode judgment call happens." Every
rounding-*insensitive* operation (parse, format, `add`, `sub`, `mul`, `order`/`eql`, `normalize`,
and the precision-*widening* branch of `rescale`) is fully implemented and tested — arbitrary
precision makes `+ − ×` exact and widening precision is a pure multiply, so none of it needed a
stub. The one genuinely hard surface is `roundedDivMag` (big.zig): deciding how many digits a
non-terminating quotient (`1/3`) or a narrowing `rescale`/`quantize`/`roundToIntegral` should keep,
and resolving the discarded remainder for all 7 `RoundingMode`s, sign-aware, at arbitrary
precision. That is money-adjacent, correctness-critical, spec-literal work worth an exhaustive KAT
pass — but every primitive it needs (division, remainder, magnitude comparison) already exists in
std, so it is not an irreducibly novel algorithm the way the underlying bignum division itself
would have been. Closer to an Opus-tier "get every edge case exactly right" task than a true
from-scratch Fable algorithm-design task; routed to the Fable worklist anyway because of the
correctness stakes and the value of an exhaustive decTest-style pass, not because it's
algorithmically novel.

**The rounding primitive:** `roundedDivMag` in `modules/decimal/src/big.zig` (see its doc comment
for the exact composition it uses) — `Managed.divTrunc` for the exact quotient/remainder, then a
doubled-remainder compare (`2·r` vs `den`, exact, no overflow because `Managed` grows its own limbs)
to resolve the discarded remainder for all 7 `RoundingMode`s, sign-aware. It generalizes root.zig's
`i256` `divRoundMag` mode-for-mode. Everything rounding-sensitive routes through it: `div` (always),
`rescale`/`quantize`/`roundToIntegral` (only when narrowing precision — their widening branch is a
pure multiply). KAT vectors (`div_kat_vectors`/`rescale_kat_vectors` in big.zig) are a live
regression suite over divide.decTest + the rounding.decTest half-even tie block.

**Known limitations (documented, not bugs):** no scientific-notation output (plain
notation only, so a huge `exponent` produces a proportionally huge string — by design, arbitrary
precision means arbitrary length); zero always formats as `"0"`, dropping GDA's ideal-exponent/
signed-zero display (`0.00`, `-0.00`, `0E+2`); a `max_align_shift` (1,000,000) ceiling bounds how
large an exponent *difference* `add`/`sub`/widening-`rescale` will materialise as `10^k`, guarding
against a hostile/typo'd exponent forcing unbounded allocation — not a General Decimal Arithmetic
rule, a pragmatic safety cap; no GDA "context precision" (default significant-digit count) concept
— `div`'s target scale is always caller-specified, unlike `BigDecimal.divide(b)` with no scale
argument.

## Verification
Parse↔format round-trips; exact arithmetic (`0.02+0.08=0.10`, `0.1+0.2=0.3`); mul/div half-away
rounding at the 12th-digit boundary both signs; i256-intermediate large-product correctness; clean
`error.Overflow` at the ceiling (add/sub/mul/div/fromInt); range boundaries incl. asymmetric minimum
formatting exactly; hostile parse (mantissa×exponent) not trapping. RoundingMode: 16-row × 7-mode
truth table hand-derived from BigDecimal/GDA/Python definitions, plus half-way-at-2dp every mode
both signs, and `rescale`/`divRound`/`quantize` edges. `BigDecimal`: parse/format round-trip incl.
beyond-i128 magnitudes, exact add/sub/mul, normalize, compare, widening-rescale, and KAT drawn from
the IBM/Mike Cowlishaw General Decimal Arithmetic Testcases v2.62 (add.decTest/multiply.decTest/
quantize.decTest exact subsets; divide.decTest/rounding.decTest vectors exercising `roundedDivMag`
sign-aware at arbitrary precision). Run: `zig build test-decimal`.

## Backlog / deferred
None open — the rounding core (`roundedDivMag`) is implemented and KAT-covered.

## Status
`extract · any · util · reentrant` · deps: none (std only) — canonical source is `pub const meta` in
src/root.zig.
