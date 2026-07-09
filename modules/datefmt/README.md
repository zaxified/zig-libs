# datefmt

Civil calendar + token-based date/time parse/format + calendar arithmetic.
Correct for dates **before 1970** (Howard Hinnant's days-from-civil algorithm,
signed `i64` epoch-day math) — unlike a `u64`-seconds-since-epoch core, which
silently floors any pre-1970 date to 1970-01-01.

- **Status:** `extract` — lifted from bxp `bxp-core/src/datefmt.zig`, where it
  replaced a `sunrise`-based core (bxp-core's former only external dep) for
  exactly this pre-epoch correctness reason.
- **Model after:** Howard Hinnant chrono civil algorithms
  (https://howardhinnant.github.io/date_algorithms.html); a strftime-like
  token vocabulary for parse/format.
- **Platform:** any (pure logic, no OS calls, no `std.time` timestamps).
  **Role:** util. **Concurrency:** reentrant (no shared state).
  **Allocation:** `format`/`formatIsoDate` take an allocator (output is an
  owned, variable-length string); everything else is allocation-free.

Provenance: extracted from bxp `bxp-core/src/datefmt.zig` (user's own code,
MIT). No third-party code.

## Two layers

1. **Civil core** — `ymdToEpochDay` / `epochDayToYmd` / `isoWeekday`,
   leap-year + days-in-month, name tables.
2. **Token I/O** — `parse` (string + format → `DateParts`) and `format`
   (`DateParts` + format → string). A parse→format reshuffle never round-trips
   through an epoch timestamp, so it has no lower-year limit.

## Format token vocabulary (parse and format share it)

```
YYYY  4-digit year          YY   2-digit year (00-69→2000s, 70-99→1900s)
MM/M  month (2 / 1-2 digit) MMM  short month name   MMMM full month name
DD/D  day (2 / 1-2 digit)
hh/h  hour 24h (2 / 1-2)    ii/i hour 12h (needs A/a)
mm/m  minute                ss/s second
A/a   AM/PM upper/lower     ZZ   UTC offset ±HH:MM (parses literal Z as +00:00)
EEEE  full day name         EEE/EE/E short day name
e     day-of-week 1-7 (Mon=1)
[text] literal              [*]  wildcard — skip until the next token
```

`date_tokens: [_]DateTokenDoc` carries this table as data (token/meaning/
example), for callers that want to render a reference/diagnostic UI.

## API

```zig
const datefmt = @import("datefmt");

const DateParts = struct {
    year: i32 = 1970, month: u32 = 1, day: u32 = 1,
    hour: u32 = 0, minute: u32 = 0, second: u32 = 0,
    off_min: ?i32 = null,   // set by a ZZ token; null if the format has none
};

// Civil core
fn ymdToEpochDay(year: i32, month: u32, day: u32) i64;
fn epochDayToYmd(epoch_day: i64) DateParts;
fn isoWeekday(epoch_day: i64) u32;              // Mon=1 … Sun=7
fn partsToUnix(p: DateParts) i64;
fn unixToParts(unix: i64) DateParts;
fn isLeapYear(year: i32) bool;
fn daysInMonth(year: i32, month: u32) u32;
fn validate(p: DateParts) bool;

// Token I/O
fn parse(input, fmt) ParseError!DateParts;
fn format(alloc, parts, fmt) ![]u8;              // caller frees

// Arithmetic (pre-1970 safe)
fn addDays(parts, n: i64) DateParts;
fn addMonths(parts, n: i32) DateParts;           // clamps day (Jan 31 +1mo → Feb 28/29)
fn addYears(parts, n: i32) DateParts;
fn diffInDays(a, b) i64;
fn diffInMonths(a, b) i32;
fn diffInYears(a, b) i32;
fn startOfDay/endOfDay/startOfMonth/endOfMonth/startOfYear/endOfYear(parts) DateParts;
fn nthWeekdayOfMonth(year, month, weekday, n) ?DateParts;  // DST-boundary primitive

// Strict ISO + validation helpers
fn parseIsoDate(s) ParseError!DateParts;         // strict YYYY-MM-DD
fn formatIsoDate(alloc, parts) ![]const u8;
fn firstInvalidFormatChar(fmt) ?usize;           // diagnostic: offset of first bad token
```

`ParseError = error{ InvalidFormat, InvalidDate, InvalidTime, InvalidFormatString, TooManyTokens }`.

## Verify

```
zig build test-datefmt
zig build test-datefmt -Doptimize=ReleaseFast
zig fmt --check modules/datefmt
```

## DEFER (not in this v1 — the seed doesn't need them, a spec-complete
module would want)

- **Locale-aware month/day names** — the seed hardcodes English `Jan`…`Dec` /
  `Mon`…`Sun`; no locale table or i18n hook.
- **ISO-week-date** (`YYYY-Www-D`, ISO 8601 week numbering) — not in the
  seed's token vocabulary; `isoWeekday` gives weekday-in-week only, not
  week-of-year.
- **Timezone-aware formatting/conversion** (IANA tz database, DST rules,
  offset lookup by zone name) — `ZZ` only carries a raw UTC-offset literal
  through parse/format; there is no zone database. Intentionally a **separate
  module** (`tz`), not pulled in here.
- **Duration/period types** (e.g. ISO 8601 `PnYnMnD` parsing) — arithmetic
  here takes/returns plain day/month/year counts, no duration value type.
- **RFC 2822 / RFC 3339 canned formats** — only the generic token engine;
  no named-format shortcuts (a caller composes the token string itself).
