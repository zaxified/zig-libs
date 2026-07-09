# datefmt — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
Two layers: a civil core (`ymdToEpochDay`/`epochDayToYmd`/`isoWeekday`, leap-year + days-in-month,
name tables) using Howard Hinnant's days-from-civil algorithm over signed `i64` epoch-day math —
correct for dates **before 1970**, unlike a `u64`-seconds-since-epoch core which silently floors any
pre-1970 date to 1970-01-01; and a token I/O layer (`parse`/`format` over a strftime-like token
vocabulary shared by both directions). A parse→format reshuffle never round-trips through an epoch
timestamp, so it has no lower-year limit. Calendar arithmetic (`addDays`/`addMonths`/`addYears`,
`diffIn*`, `startOf*`/`endOf*`, `nthWeekdayOfMonth`) is pre-1970 safe by the same epoch-day
mechanism; `addMonths` clamps the day (Jan 31 +1mo → Feb 28/29). Platform: any (pure logic, no OS
calls, no `std.time` timestamps). Role: util. Concurrency: reentrant (no shared state). Allocation:
`format`/`formatIsoDate` take an allocator (output is an owned, variable-length string); everything
else is allocation-free. Modeled after Howard Hinnant's chrono civil algorithms; extracted from bxp
`bxp-core/src/datefmt.zig` (replaced a `sunrise`-based core there for exactly this pre-epoch
correctness reason) — user's own code, no third-party source. See NOTICE.

## Threat model / out of scope
Not security-sensitive; the contract is calendar-arithmetic correctness. Malformed format strings
or out-of-range parse input return typed `ParseError` values (`InvalidFormat`/`InvalidDate`/
`InvalidTime`/`InvalidFormatString`/`TooManyTokens`), never a panic; `firstInvalidFormatChar` gives a
diagnostic offset. Out of scope: locale-aware month/day names (English `Jan`…`Dec`/`Mon`…`Sun` only,
no i18n hook), ISO-week-date (`YYYY-Www-D` week numbering — `isoWeekday` gives weekday-in-week only),
timezone-aware formatting/conversion (no IANA tz database or DST rules — `ZZ` only carries a raw
UTC-offset literal; that's the separate `tz` module), duration/period value types (arithmetic here
takes/returns plain day/month/year counts), and named canned formats (RFC 2822/3339 — only the
generic token engine, no shortcuts).

## Verification
19 tests: civil-core round-trips (epoch-day↔ymd, incl. pre-1970 and leap-year boundaries), token
parse/format for every documented token incl. 12h AM/PM and `ZZ` offsets, calendar arithmetic
(`addMonths` day-clamping, `nthWeekdayOfMonth`), strict ISO parse/format, and malformed-format-string
error paths. Run: `zig build test-datefmt` (also `-Doptimize=ReleaseFast`), `zig fmt --check
modules/datefmt`.

## Backlog / deferred
Per PLAN.md wave-3 findings: locale-aware month/day names; ISO-week-date; duration/period types;
named canned formats (RFC 2822/3339). Timezone-aware formatting is explicitly out of scope here —
it lives in the separate `tz` module (dep on `datefmt`).

## Status
`extract · any · util · reentrant` · deps: none — canonical source is `pub const meta` in
src/root.zig.
