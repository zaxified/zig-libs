# tz — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-18** — Security audit: no findings. Modeled on IANA tzdata (`zic`) / glibc
  `localtime(3)` (design reference, not a test anchor).
- **2026-07-09** — New module: IANA time-zone offset lookup — zone name → UTC offset/DST
  at a given instant (600 zones + POSIX-TZ footer).
