# tz — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-14** — `zig build check-fuzz` coverage: two `testing.fuzz` harnesses — `find`
  (the zone-name lookup that flagged the gate), and the POSIX-TZ footer grammar
  (`posixOffset`/`parseRule`/`ruleDateUnix`) reachable through the public `Zone.posix`
  field feeding public `offsetAt`, which is the module's real parsing logic and the one
  worth fuzzing: a caller building a `Zone` from an untrusted `TZ`-style footer string
  hands it bytes it did not author. Both generators are shaped toward their grammar
  (real zone names; `stdoffset[dst[offset][,start[/time],end[/time]]]` with each
  optional piece independently present) rather than pure noise. No panic, hang or leak
  found.
- **2026-07-18** — Security audit: no findings. Modeled on IANA tzdata (`zic`) / glibc
  `localtime(3)` (design reference, not a test anchor).
- **2026-07-09** — New module: IANA time-zone offset lookup — zone name → UTC offset/DST
  at a given instant (600 zones + POSIX-TZ footer).
