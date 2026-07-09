# numparse — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: original work of
the zig-libs authors (MIT).

## Design & invariants
A single pure function, `parseGroupedNumber(s, thousands_sep, decimal_sep) ?Decimal`, generalized
over American (`,`/`.`) and European (`.`/`,`) grouping conventions. Grammar:
`[-]?d{1,3}(<thousands>d{3})+(<decimal>d+)?`, with strict structural validation — 1-3 leading
digits, then exact 3-digit groups, no trailing junk — and at least one thousands group required
(plain ungrouped numbers like `"123"`/`"1.5"`/`"1,5"` deliberately return `null`, left to the
caller's `decimal.Decimal.parse`). Strictness is the point: it rejects date-like strings
(`"2025,06,01"`) and American input misread under European separators, rather than silently
mis-parsing them. Implementation is a single left-to-right scan with no backtracking, normalizing
into a fixed 40-byte stack buffer (stripping the thousands separator, rewriting the decimal
separator to `.`) then re-parsing via `decimal.Decimal.parse`; the buffer size covers any value the
fixed-point range can hold (~27 integer digits + dot + 12 fractional), far beyond what `3+N*4`
digits can express, so the length guard inside the scan is a defensive bound, not a reachable
truncation path. No allocation, no shared state — reentrant. Original work of the zig-libs authors
(MIT), modeled after ICU `NumberFormat` parse's western 3-digit-grouping subset. The final re-parse
targets the extracted `decimal` module, whose `parse` returns an error union (mapped back to `null`
via `catch null`); parameters are named `thousands_sep`/`decimal_sep` to avoid colliding with the
`decimal` dependency's own name.

## Threat model / out of scope
Not security-sensitive — a pure text-classification/parse function with no I/O, no allocation, and
a bounded (40-byte) working set regardless of input length (over-long input just returns `null`
once the scan or the buffer copy fails its bound, never overflows or panics). Does not guarantee
locale correctness beyond the two documented western conventions: no scientific notation, no
currency symbols/percent suffixes, no non-3-digit grouping (Indian lakh/crore, CJK myriad), no
broader ICU `NumberFormat` locale coverage. A caller passing the wrong separator pair for their
locale gets `null` (safe failure), not a mis-parsed number silently accepted.

## Verification
2 tests (covering both grouping conventions, adapted for `decimal`'s error-union `parse`):
American-format accept cases (grouped integers/decimals, negative, exact group boundaries) and
reject cases (ungrouped, wrong group size); European-format mirror of the same, plus a
cross-locale negative (comma/dot swapped). Run: `zig build test-numparse`.

## Backlog / deferred
Per the module README's "Deferred" section (Fable-scoped follow-on, not v1): scientific notation,
currency symbols/percent suffixes, non-3-digit grouping (Indian lakh/crore 2-digit, CJK 4-digit
myriad), and full ICU `NumberFormat` locale coverage.

## Status
`extract · any · util · reentrant` + deps: `decimal` — canonical source is `pub const meta` in
src/root.zig.
