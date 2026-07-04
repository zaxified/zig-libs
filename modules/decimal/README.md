# decimal

Exact base-10 **fixed-point decimal** for money and ETL math. Values are an
`i128` scaled by `10^12` (12 fractional digits) — like a database
`DECIMAL(38,12)`. `0.1 + 0.2 == 0.3`, exactly; the whole parse → arithmetic →
format path is pure integer (no `f64`/`f128` anywhere).

- **Status:** `extract` — lifted from bxp `bxp-core/src/decimal.zig`, where it
  replaced an `f80` core and is proven on 40M-row ETL runs.
- **Model after:** Java `BigDecimal` / Python `decimal` semantics, but
  fixed-scale like DB `DECIMAL(38,12)`.
- **Platform:** any (pure logic, no OS calls). **Role:** util.
  **Concurrency:** reentrant (no shared state). **Allocation:** none —
  `toString` writes into a caller buffer.

Provenance: extracted from bxp `bxp-core/src/decimal.zig` (same authors,
Apache-2.0, relicensed MIT here). No third-party code.

## Semantics

- **Range:** ±170141183460469231731687303.715884105727(-8), step `1e-12`.
- **Rounding:** everything rounds **half-away-from-zero** ("school" rounding,
  what Excel/LibreOffice present): `+ −` are exact; `× ÷` widen to **i256
  intermediates** and round the 12th fractional digit; `round(n)` re-quantises
  with the same mode (`ROUND(2.5,0)=3`, `ROUND(-2.5,0)=-3`).
- **No Inf/NaN, never UB:** any result beyond the i128 range is a clean
  `error.Overflow` (`round`/`floor`/`ceil` instead return the value unchanged
  in their boundary-only unrepresentable cases); division by zero is
  `error.DivisionByZero`.
- **Parse:** optional sign, decimal point, scientific notation (`2.08e9`,
  `1e-3`). Fractional digits beyond 12 round half-away-from-zero into the
  12th. Junk/empty/double-dot/grouped (`1,234.56`) input →
  `error.InvalidCharacter`; out-of-range → `error.Overflow`.
- **Format:** canonical — integer part, up to 12 fractional digits, trailing
  zeros trimmed, dot dropped when no fraction remains.

## API

```zig
const Decimal = @import("decimal").Decimal;

pub const scale: u32 = 12;              // fractional digits
pub const scale_factor: i128 = 1e12;    // raw = value × scale_factor
pub const str_buf_len: usize = 41;      // worst-case toString length
pub const zero: Decimal;
pub const one: Decimal;

fn fromInt(n: i128) error{Overflow}!Decimal;
fn parse(s: []const u8) error{ InvalidCharacter, Overflow }!Decimal;
fn toString(self, buf: *[str_buf_len]u8) []const u8;  // infallible, canonical
fn format(self, writer: *std.Io.Writer) ...;          // "{f}" support

fn add(a, b) error{Overflow}!Decimal;   // exact
fn sub(a, b) error{Overflow}!Decimal;   // exact
fn mul(a, b) error{Overflow}!Decimal;   // i256 intermediate, half-away rounding
fn div(a, b) error{ Overflow, DivisionByZero }!Decimal;

fn round(self, n: i32) Decimal;         // re-quantise, half-away-from-zero
fn floor(self) Decimal;
fn ceil(self) Decimal;
fn trunc(self) i128;                    // integer part, toward zero
fn neg(self) error{Overflow}!Decimal;   // errors only at i128 min
fn abs(self) error{Overflow}!Decimal;
fn order(a, b) std.math.Order;
fn eql(a, b) bool;
fn isZero(self) bool;
```

## Changes vs the seed

Semantics (rounding mode, scale, parse/format policy) are preserved exactly;
the extraction made the failure paths explicit:

- `?Decimal` results became error unions (`Overflow` / `DivisionByZero` /
  `InvalidCharacter`).
- `div` now range-checks the quotient (the seed's unchecked `@intCast` could
  trap when dividing a large value by a sub-`1e-12` divisor).
- `parse` now overflow-checks the i256 scaling multiply (huge mantissa ×
  exponent combinations could overflow even the wide accumulator).
- `fromInt` is overflow-checked.
- `floor`/`ceil` compute in i256 and adopt `round`'s "unchanged if
  unrepresentable" contract at the extreme i128 boundary (seed could trap).
- `toString(alloc)` became allocation-free `toString(buf)` + a `{f}` formatter.

## Verify

```
zig build test-decimal
```
