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
error, never a trap. Out of scope: arbitrary/unbounded precision (scale fixed at 12), locale/
grouping-aware parsing (caller strips separators), currency semantics, float interchange.

## Verification
Parse↔format round-trips; exact arithmetic (`0.02+0.08=0.10`, `0.1+0.2=0.3`); mul/div half-away
rounding at the 12th-digit boundary both signs; i256-intermediate large-product correctness; clean
`error.Overflow` at the ceiling (add/sub/mul/div/fromInt); range boundaries incl. asymmetric minimum
formatting exactly; hostile parse (mantissa×exponent) not trapping. RoundingMode: 16-row × 7-mode
truth table hand-derived from BigDecimal/GDA/Python definitions, plus half-way-at-2dp every mode
both signs, and `rescale`/`divRound`/`quantize` edges. Run: `zig build test-decimal`.

## Backlog / deferred
None beyond the module's own scope notes (dataset's `.decimal` Value variant
is the cross-module consumer, not a decimal-internal gap).

## Status
`extract · any · util · reentrant` · deps: none (std only) — canonical source is `pub const meta` in
src/root.zig.
