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

**Operation surface beyond the rounding core:** `remainder` (truncated-division remainder — sign of
the *dividend*, exponent `min(ea, eb)`), `min`/`max` (GDA tie rule: equal values resolve by
exponent, and the direction flips with the sign), `precision` (exact significant-digit count via
`Const.log10Alloc`; zero is 1), `signum`, `scaleByPowerOfTen` (exponent-only, exact),
`stripTrailingZeros` (**an alias of `normalize`, not a second implementation** — same function
value, asserted in a test), `sqrt` and `pow`. All but the last two are exact and take no rounding
mode.

**`sqrt` is correctly rounded, not iterated-to-fixpoint.** GDA defines square-root as the true root
rounded to the context precision; "Newton until the digits stop changing" is right to within an ulp
and wrong at every rounding boundary, and only published vectors reveal the difference. The
implementation scales the radicand by `10^(2(prec+1))`, takes an exact `⌊√N⌋`
(`std.math.big.int.Managed.sqrt`, Brent–Zimmermann SqrtInt), then decides the rounding with one
exact integer comparison of `4N` against `((2Q+1)·10^drop)²` — no floating point, no ulp slack. An
exact root carries GDA's *ideal exponent* `⌊e/2⌋` (`√1.00 = 1.0`, `√1E+2 = 1E+1`), which is why the
vector files keep operands in their original scaled form rather than a flattened plain rendering.

**`sqrt`/`pow` have a digit budget; every other op does not need one.** `max_result_digits`
(100,000) bounds what a single operation will *produce*, checked **before** allocating — from
`precision(a) × n` for `pow` and from `prec` for `sqrt`. Like `max_align_shift` this is a pragmatic
guard, not a GDA rule. It is not optional for `pow`: power.decTest genuinely contains exponent
`1000000007`, and `1.1 ^ 1000000007` is a ~10^8-digit number that exhausts memory long before it
returns. `pow` is **integer-exponent-only** (the `java.math.BigDecimal.pow(int)` contract: exact,
result exponent `a.exponent × n`, negative `n` refused); GDA's general `power` over non-integer
exponents needs `exp`/`ln` on arbitrary-precision decimals — a transcendental-function project of
its own, deliberately out of scope. Tractable, if it is ever wanted: the same
scale-then-exact-integer-op-then-one-comparison shape used by `sqrt` generalises to an
argument-reduced `exp`/`ln` pair, but it is a separate piece of work, not an extension of `pow`.

**Bridge to the fixed-scale `Decimal` (root.zig).** `Decimal.toBigDecimal` is exact and total (a
`Decimal` *is* `raw × 10^-12`); the result carries all 12 fractional digits, trailing zeros
included, because that is the fixed type's scale. `Decimal.fromBigDecimal(allocator, b, mode)` is
partial in two independent ways and surfaces both as typed outcomes: excess fractional digits are
**rounded** with `mode` (never truncated), and a magnitude outside ±1.7e26 is `error.Overflow` —
checked *after* the rounding, so rounding that creates the overflow still errors. A value below half
an ulp is a rounding decision, not an error (`0` under `down`/`half_*`, ±1e-12 under the
away-from-zero modes). Both the range and the below-half-ulp cases are decided from the coefficient
digit count *before* any power of ten is materialised, so `1e2000000000` and `1e-2000000000` return
in constant time instead of attempting an astronomical allocation. Round-tripping
`toBigDecimal → fromBigDecimal` is the identity for every `Decimal` in every mode.

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
sign-aware at arbitrary precision).

**decTest conformance tables** (`src/testdata/*.vec`, `@embedFile`d by big.zig): remainder 279,
min 105, max 105, square-root 3268, integer power 130 cases. Extracted mechanically by script from
the v2.62 suite — never transcribed by eye — with the directives (`precision:`/`rounding:`) tracked
so each case replays under its own context. Every check asserts the **exponent** as well as the
digits, because for these five operations the result's scale is part of the specification and a
digits-only comparison would pass with all four scale rules wrong. Operands are carried through as
their raw source tokens (`1E+2`, not `100`) since square-root's ideal exponent depends on the
operand's stored scale. Each file's header records, with counts, exactly which source cases were
*not* wired and under which rule: hard condition flags with no analogue here (no `Inf`/`NaN`, no
flag register), zero results (this module prints a bare `"0"`), context-precision `Inexact`/
`Rounded` on the exact operations, non-integer/negative `power` exponents, and anything past the
stated extraction bounds (`|exponent| > 10_000` or `> 1000` coefficient digits). `remainder`
additionally diverges from GDA by design: GDA raises `Division_impossible` when the integer quotient
exceeds the context precision, and with no context precision this module simply returns the exact
answer, so those 29 cases are skipped rather than asserted.

**Mutation-tested.** 16 mutations were applied one at a time and each confirmed to turn a test red,
with the tree restored byte-identical afterwards: sqrt's half-way comparison inverted; sqrt's ideal
exponent truncated instead of floored; sqrt's exactness check removed; remainder taking the
divisor's sign (`divFloor`, i.e. modulo) and remainder using the dividend's exponent alone;
`pow` with a negative exponent silently returning zero, its digit budget added instead of
multiplied, and its result exponent unscaled; min/max comparing by magnitude and min/max failing to
mirror the negative tie rule; the shared `half_even` tie-break inverted; `precision` off by one; and
five bridge mutations (silent truncation instead of the caller's mode, widening at the wrong scale,
below-half-ulp always zero, the post-rounding range check dropped). No survivors. Run:
`zig build test-decimal`.

## Backlog / deferred
None open. The rounding core (`roundedDivMag`) is implemented and KAT-covered, and the
`java.math.BigDecimal`/GDA operation gaps (`sqrt`, `pow`, `remainder`, `min`, `max`, `precision`,
`signum`, `scaleByPowerOfTen`, `stripTrailingZeros`) plus the `Decimal` ↔ `BigDecimal` bridge are
closed. Deliberately not built: GDA's general `power` with non-integer exponents (needs `exp`/`ln`
on bignums — a separate transcendental-function project), a GDA context/flag register, and
scientific-notation output.

## Status
`extract · any · util · reentrant` · deps: none (std only) — canonical source is `pub const meta` in
src/root.zig.

## Anchoring

**Anchor grade:** class C · oracle n/a

- **Class C** — internal algorithm or data structure — no outside exists, so correctness is defined by invariants or a brute-force reference. Not anchor debt.
- **Oracle n/a** — class C/D carries no anchor debt, so there is no oracle grade to give.

**What the tests actually contain.** arbitrary-precision decimal arithmetic; no wire format, invariant-checked
