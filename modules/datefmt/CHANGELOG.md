# datefmt — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
