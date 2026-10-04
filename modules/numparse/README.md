# numparse

Locale-aware **grouped-number parsing** — thousands + decimal separators into
an exact `decimal.Decimal`, with strict structural validation.

- One function's worth of scope, generalized as a
  standalone module.
- **Model after:** ICU `NumberFormat` parse (the western 3-digit grouping
  subset).
- **Platform:** any (pure logic, no OS calls). **Role:** util.
  **Concurrency:** reentrant (no shared state). **Allocation:** none — the
  normalized digits are rewritten into a stack buffer. **Scope:** core since 2026-10-04.
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

## `parse` — any locale's grouping, signs, percent (2026-10-04)

```zig
const cs = numparse.locale("cs").?;                     // group U+00A0, decimal ','
numparse.parse("1\u{00A0}234\u{00A0}567,89", cs);     // → 1234567.89
numparse.parse("1234,5", cs);                           // → 1234.5 (ungrouped is fine)
numparse.parse("1,23,45,678", numparse.locale("en_IN").?); // → 12345678 (lakh/crore)

var o = numparse.locale("en").?;
o.parentheses = true;                                   // accounting exports
o.percent = true;
numparse.parse("(1,234.56)", o);                        // → -1234.56
numparse.parse("12.5%", o);                             // → 0.125
```

Separators are UTF-8 slices; `lenient_spaces` accepts any space-like spelling for a space-like
separator (one spelling per number). Refused on purpose: a grouped number starting with `0`, `5.`,
an exponent after a grouped number, two signs. Checked against Babel's strict `parse_decimal` on
5 452 cases over 25 CLDR locales (`tools/babel-oracle.py`). The legacy `parseGroupedNumber` below
is unchanged.

## Implementation notes

Semantics (grammar, strictness) are preserved exactly. Two mechanical
adaptations from an earlier design iteration:

- The final re-parse targets the `decimal` module. Its `parse`
  returns an error union, so a malformed or
  out-of-range normalized string maps back to `null` via `catch null`.
- Parameters renamed `thousands`/`decimal` → `thousands_sep`/`decimal_sep`
  (avoids colliding with the `decimal` dependency name).

## Deferred

Currency symbols, CJK 4-digit myriad grouping, non-Latin digits, and full
CLDR locale coverage (25 locales are built in). See `SPEC.md`.

## Verify

```
zig build test-numparse
```
