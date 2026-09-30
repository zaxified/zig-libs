# datefmt — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
