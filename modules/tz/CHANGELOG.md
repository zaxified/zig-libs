# tz — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-16** — The `tz-gen` generator moved into this repo at `scripts/tz-gen/`, closing the
  "tzdata refresh cadence tooling" deferral in `SPEC.md`. No code or API change here — what changes
  is that `tz_data.zig`'s pinned release can now be re-derived and bumped rather than only trusted,
  which was the one thing the extraction left unanswerable. It stays out of `modules/` deliberately:
  it reads the host's `/usr/share/zoneinfo` and is the sole user of `std.Tz`, both ruled out by this
  module's no-filesystem/no-syscalls model, and `scripts/` sits outside `build.zig.zon`'s `.paths`
  so a consumer still fetches nothing but the generated table. Arrived from the project the module
  was originally extracted from, which had kept the only copy. `tz_data.zig`'s header comment is
  edited in the same change, `DO NOT EDIT` notwithstanding: README and SPEC now delegate the
  regeneration command to that header, and it named an unlocated tool and a command that fails from
  the repo root. It is now byte-identical to what the generator emits (verified by generating against
  the host's tzdata and diffing the header with the release string normalised), so the next real
  regeneration is a no-op on those lines rather than a surprise diff.
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
