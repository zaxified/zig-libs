# datefmt — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-24** — **NO CONSUMER-VISIBLE CHANGE:** the `strRepeat` helper (the Zig 0.17 stand-in for `**`) builds its string with one `@splat` + `@bitCast` instead of a comptime loop, which Sema evaluated in O(n²) (http's test binary: 323 s → 13 s). Same bytes, faster compile.

- **2026-10-19** — **Fix:** `unixToParts` (and so `unixNsToParts`, `toUtc`) no longer traps/UB on extreme `i64` instants: the seconds-of-day product `day * 86400` overflowed for `minInt(i64)`, and the year `@intCast` to `i32` overflowed for any instant beyond ~±6.7e16 s; the year now saturates at the `i32` range. In-range results are unchanged (S7 audit).

- **2026-10-11** — Scope core → parity (chrono 0.4, Go `time`). New: `parseRfc2822`/`bufRfc2822`/
  `formatRfc2822` (RFC 5322 `Date:`: obsolete zones, two/three-digit years per §4.3, CFWS and nested
  comments, weekday checked, trailing text refused); `parseDuration`/`bufDuration`/`formatDuration`
  (Go's duration text, bit-exact with Go 1.26 incl. its f64 fraction scaling; a sum past 2^64 is an
  error where Go wraps to 0); `partsToUnixNs`/`unixNsToParts` (i64 ns, Go's `UnixNano` range);
  `toUtc` (applies `off_min`). Evidence: `tools/go_time_oracle` (Go) and `tools/mail_date_oracle.py`
  (Python `email.utils`) write `src/go_time_vectors.zig`/`src/mail_date_vectors.zig`, replayed by
  `src/go_oracle_test.zig`; `zig build interop-datefmt [-- --check]` re-takes them.

- **2026-10-11** — Canned formats: `bufRfc3339`/`formatRfc3339`/`parseRfc3339` (RFC 3339; 0..9
  fraction digits; offset from/into `off_min`) and `bufImfFixdate`/`formatImfFixdate`/`parseImfFixdate`
  (the RFC 9110 HTTP date). The `buf*` forms write into a fixed-size array without allocating. Unlike
  `format`, all of them validate their fields (year 0..9999). Bench vs Go `time`: 0.06–0.91× (P2).
  Canned rows are paired with Go's canned RFC 3339 path; the token engine is now paired with a layout
  Go does not special-case (`fmt_rfc3339_tokens`).

- **2026-10-10** — Speed: `format` and `parse` 7–18× faster on short formats (bench vs Go `time`:
  0.23–18.95× → 0.29–1.83×; P3). The tokenizer looks tokens up by first character instead of scanning
  the token table at every position, and the token array is no longer memset on every call. `format`
  renders into a bounded stack buffer and allocates the result once. New `Layout` (`Layout.compile`,
  works at comptime) tokenizes a format once for repeated `format`/`parse`, measured 0.40–0.90× Go.
  ⚠ `format` now reports an allocation failure as `error.OutOfMemory`. Before, the growing writer
  surfaced it as `error.WriteFailed`.

- **2026-10-10** — Comparative benchmark `tools/bench.zig` (`zig build bench-datefmt`): **0.23–18.95× Go time** — over 2×, P4. Card stays `not measured` with the numbers in *Backlog* until the module is sped up (owner 2026-10-10: a consumed module must grade 3 or better). Tooling only, no code change.

- **2026-10-04** — Fix: `parse` read every numeric field with `std.fmt.parseInt`, which also
  accepts a leading `+`/`-` and `_` separators: `+1/05/2024` with `MM/DD/YYYY` parsed as January,
  and a `ZZ` offset of `+-1:30` passed the hour range check as a negative hour. Numeric fields are
  now ASCII digits only (`InvalidDate`/`InvalidTime` as before for a bad field).
- **2026-10-04** — Fix: `parseIsoDate` ("strict canonical `YYYY-MM-DD`") accepted any day up to
  31 in any month — `2023-02-30`, `2024-04-31` — which later `ymdToEpochDay` calls rolled into the
  next month; the day is now checked against the month's length (leap years included), and a sign in
  any field is refused. Inputs that named no real date are now `InvalidDate`.
- **2026-10-04** — **Tests:** mutation run (51 schemata mutants, 49 killed, 2 equivalent). New
  tests for both fixes and for the documented token edges (YY pivot, 1-2 digit fields, hour 24,
  12 AM/PM, `e`, `ZZ` range, literals, `[*]`), 12-hour formatting at noon, `MAX_TOKENS`,
  `nthWeekdayOfMonth` past the month end, and `parseIsoDate`/`parseXsdDateTime` shape.

- **2026-09-30** — Fractional seconds: `DateParts.nanosecond` (default 0), `SSS`/`SSSSSS`/`SSSSSSSSS`
  tokens in `parse`/`format`, new `parseXsdDateTimeNs` (keeps the fraction, any digit count, truncates
  beyond 9); `parseXsdDateTime` unchanged (whole seconds). ISO week date: `isoWeek`, `isoWeeksInYear`,
  `isoWeekDateToEpochDay`, tokens `GGGG`/`WW`/`W` (parse resolves the date from the week date).
  Scope raised mvp to core. ⚠ A bare `SSS`/`GGGG`/`W` outside `[...]` used to be copied as literal
  text; it is now a token. Such a format was already reported as a typo by `firstInvalidFormatChar`
  (bare letters outside the vocabulary), so a validated format cannot change meaning; an
  unvalidated one that relied on the literal must bracket it (`[W]`).
- **2026-07-18** — Security audit: no findings. Modeled on libc `strftime`/`strptime`
  (design reference, not a test anchor).
- **2026-07-09** — New module: Civil calendar + token-based date/time parse/format +
  calendar arithmetic, correct before 1970.
