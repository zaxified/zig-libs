# SPEC — `decimal`

Exact base-10 **fixed-point decimal** (money/ETL math). Wave P1 (first extraction).
`extract · any · util · reentrant`. Model after: Java `BigDecimal` / Python `decimal` semantics,
but **fixed-scale** like a database `DECIMAL(38,12)`. **Seed: extract from
`~/workspace/bxp/bxp-core/src/decimal.zig`** (same authors' Apache-2.0 code, relicensed MIT here).
Deps: **none (std only)**. New `build.zig` entry `.{ .name = "decimal" }`.

## Why

Zig std has no decimal type; `0.1 + 0.2 != 0.3` in float. Money and ETL need exact base-10.
This is a foundational primitive that `numparse`, `finstats`, and `exprcalc` will build on. bxp
already ships a battle-tested `i128` fixed-point decimal (scale 1e12, benchmarked on 40M rows) —
this task **lifts it out** as a standalone, dependency-free library.

## Scope

1. **Extract + de-couple:** read the bxp seed and lift the `Decimal{ raw: i128 }` core out as a
   clean standalone module — drop any bxp-app coupling, keep the exact semantics. Fixed scale
   (1e12, i.e. 12 fractional digits) as in the seed; document it. Preserve behavior byte-for-byte
   where the seed has tests (this is an extraction, not a redesign).
2. **Arithmetic:** exact `add` / `sub` / `mul` (with **i256 intermediates** to avoid overflow before
   rescale), `div` and `round` with **half-away-from-zero** ("school"/Excel) rounding. **No Inf/NaN.**
   Overflow of the i128 result → a clean error (or documented saturation) — never UB.
3. **Parse / format (float-free):** `parse([]const u8) !Decimal` (sign, integer + fractional digits,
   reject junk/NaN/exponent unless the seed supports it — match the seed) and `format` to a canonical
   string (no trailing-zero noise beyond the scale; match the seed). No float anywhere in the path.
4. **Conversions + compare:** `fromInt`, `toInt`/truncation helpers, `order`/`eql`, `neg`, `abs`,
   `isZero`. Keep the API small and match the seed's surface.

## Public API sketch (final = the seed's shape; keep it small)

```zig
pub const Decimal = struct {
    raw: i128,   // value × 10^scale
    pub const scale = 12;
    pub fn fromInt(i: i128) Decimal;
    pub fn parse(text: []const u8) !Decimal;
    pub fn format(self: Decimal, buf: []u8) []const u8;   // or a std.fmt formatter
    pub fn add(a: Decimal, b: Decimal) !Decimal;
    pub fn sub(a: Decimal, b: Decimal) !Decimal;
    pub fn mul(a: Decimal, b: Decimal) !Decimal;          // i256 intermediate
    pub fn div(a: Decimal, b: Decimal) !Decimal;          // half-away-from-zero
    pub fn order(a: Decimal, b: Decimal) std.math.Order;
    // neg/abs/isZero/toInt ...
};
```

## Acceptance / verification

- **Offline unit tests (port the seed's tests + add):** exactness (`0.1 + 0.2 == 0.3`,
  `0.02 + 0.08 == 0.10`), mul/div rounding (half-away-from-zero at the boundary, negative operands),
  i256-intermediate correctness on large mul (no premature overflow), i128-overflow → clean error,
  parse round-trips (`"−123.456"` → format back, canonical), parse rejects junk / empty / too many
  fractional digits (match the seed's policy), compare/order, zero/neg/abs edge cases. Float-free
  (grep: no `f64`/`f128` in the arithmetic path).
- `zig build test-decimal` + `zig build test` (all) green, Debug + ReleaseFast; `zig fmt --check`
  clean. Registered with no deps.

## Notes for the implementer

- Use the **zig skill** for Zig 0.16 (i128/i256 math, `std.fmt` formatter, `std.math.Order`).
- This is an **EXTRACTION**: start from the bxp seed, keep its proven semantics and tests; don't
  redesign the rounding or scale. If the seed couples to bxp types, replace with std/primitive types.
- Provenance: README `Provenance:` line = "extracted from bxp `bxp-core/src/decimal.zig` (same
  authors, Apache-2.0, relicensed MIT here)". `model_after` = "Java BigDecimal / DB DECIMAL(38,12)".
  No NOTICE entry needed (it is our own code, not third-party) — SPDX MIT header as usual.
- Keep it dependency-free and portable (no OS calls) — it's a leaf primitive many modules will use.
