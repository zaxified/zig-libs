# tz — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-23** — Documentation: `meta.doc`, `README.md` and `SPEC.md` still
  said 600 zones after the table dropped to 598. The root README's catalog row
  is rendered from `meta.doc`, so the stale count had propagated there too. A
  test now pins `zones.len`, so a regeneration that moves the count cannot land
  without someone walking past the number.

- **2026-08-22** — **Behavioural:** two entries left the table, taking it from 600 zones to 598.
  `localtime` and `posixrules` are not IANA zones at all: on a Debian/Ubuntu host
  `/usr/share/zoneinfo/localtime` symlinks to `/etc/localtime`, so the committed table carried
  **the generator machine's own configured timezone** under that name (CET here), and
  `posixrules` symlinks to a legacy US-rules zone. Neither is in the tzdata tarball, neither is
  a name a caller should look up, and both made the output depend on who ran the generator.
  `offsetAt("localtime", ...)` now returns the same not-found result as any other unknown name.

- **2026-08-22** — `scripts/tz-gen/fetch-and-build.sh`: the pinned release is now re-derivable
  **anywhere**, not only on a machine that happens to have that release installed. The claim in
  `SPEC.md` and the 2026-08-16 entry below — that `tz_data.zig`'s pin "can be re-derived rather
  than only trusted" — was true of the tool and false in practice: the tool reads a compiled
  zoneinfo tree, the tree to hand it was `/usr/share/zoneinfo`, and that is the DISTRO's zic
  output at the DISTRO's release. This host runs 2026c against a 2026a pin, so re-deriving the
  table here produced a different one.

  The script fetches `tzdata<release>.tar.gz` from IANA against a SHA-256 pinned in
  `scripts/tz-gen/checksums.txt`, compiles it with the system `zic -b fat`, and generates from
  that tree. `--check` regenerates to a temp file and diffs the committed table, exiting non-zero
  on any difference — verified against a real mismatch, not just a clean run. A missing `zic` is a
  hard failure rather than a fall-back to the host tree, because a fall-back would emit a table
  that looks regenerated and is not.

  With the two host artifacts above removed, `modules/tz/src/tz_data.zig` now reproduces
  byte-for-byte from tzdata 2026a.

- **2026-08-22** — `tz-gen` trims the `+VERSION` fallback it reads when a zoneinfo tree has no
  `tzdata.zi`. The file ends with a newline, which landed mid-sentence in the generated header
  comment and split the line.

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
