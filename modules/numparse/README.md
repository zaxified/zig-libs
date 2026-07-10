# numparse

Locale-aware **grouped-number parsing** — thousands + decimal separators into
an exact `decimal.Decimal`, with strict structural validation.

- One function's worth of scope, generalized as a
  standalone module.
- **Model after:** ICU `NumberFormat` parse (the western 3-digit grouping
  subset).
- **Platform:** any (pure logic, no OS calls). **Role:** util.
  **Concurrency:** reentrant (no shared state). **Allocation:** none — the
  normalized digits are rewritten into a stack buffer.
- **Deps:** `decimal`.

Provenance: original work of the zig-libs authors (MIT). The expr-internal
`Value.toNumber()` glue was replaced with a direct `decimal.Decimal.parse` on
the normalized string. No third-party code.

## Semantics

```zig
const Decimal = @import("decimal").Decimal;
const numparse = @import("numparse");

// American: thousands ',' decimal '.'
numparse.parseGroupedNumber("1,234.56", ',', '.');    // → 1234.56
// European: thousands '.' decimal ','
numparse.parseGroupedNumber("-1.234.567,89", '.', ','); // → -1234567.89
```

Grammar: `[-]?d{1,3}(<thousands>d{3})+(<decimal>d+)?`

- **At least one thousands group is required.** Plain ungrouped numbers
  (`"123"`, `"1.5"`, `"1,5"`) return `null` — those are the caller's
  `Decimal.parse` responsibility.
- **Strict structural validation** (1–3 leading digits, then exact 3-digit
  groups, no trailing junk) is deliberate: it rejects date-like strings
  (`"2025,06,01"`) and American input misread under European separators
  (`"1,234.56"` with `'.'`/`','`), rather than silently mis-parsing them.
- Returns `?Decimal`: `null` on any non-match (bad shape, wrong separators,
  trailing characters) or when the normalized value is out of the `decimal`
  range.

## Implementation notes

Semantics (grammar, strictness) are preserved exactly. Two mechanical
adaptations from an earlier design iteration:

- The final re-parse targets the `decimal` module. Its `parse`
  returns an error union, so a malformed or
  out-of-range normalized string maps back to `null` via `catch null`.
- Parameters renamed `thousands`/`decimal` → `thousands_sep`/`decimal_sep`
  (avoids colliding with the `decimal` dependency name).

## Deferred (Fable-scoped follow-on, not v1)

Scientific notation, currency symbols / percent suffixes, non-3-digit
grouping (Indian lakh/crore 2-digit, CJK 4-digit myriad), and full ICU
`NumberFormat` locale coverage.

## Verify

```
zig build test-numparse
```
