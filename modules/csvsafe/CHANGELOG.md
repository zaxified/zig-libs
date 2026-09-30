# csvsafe — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-30** — **BEHAVIOURAL, not breaking:** a cell led by LF, `|` or `%` is now guarded too (the
  union of the ecosystem's guards: go-safe-csv-writer's LF, defusedcsv's `|` and `%`). A value that
  genuinely starts with `%` or `|` now comes out with the apostrophe in front.

- **2026-07-19** — Security audit: a CRIT/HIGH finding was fixed (part of the
  collection-wide audit; the root changelog records no further detail
  than this).
