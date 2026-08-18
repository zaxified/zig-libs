# diskusage — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-18** — Fix: `mounts.readMounts`/`mountinfo.readMountinfo` called
  `std.Io.File.read(io, &buf)`, which does not exist in Zig 0.16 (`File` only
  has `readStreaming`/`readPositional`/`reader`/`readerStreaming`) — a
  compile error a real consumer (AXP) hit on the obvious entry point. Neither
  function was called by any test in this module, so the bodies were never
  semantically analysed and every gate stayed green (the same "never
  analysed, therefore never checked" shape the repo's build-system-level
  fixes addressed the same day). Fixed both to follow `procnet.readVirtualFile`'s
  established idiom (`std.Io.File.Reader.initStreaming` +
  `.interface.allocRemaining(gpa, .limited(limit))`) instead of a hand-rolled
  read loop. Added a live test for each (`readMounts`/`readMountinfo` against
  this host's real `/proc/self/mounts`/`mountinfo`, same "run unconditionally,
  no root needed" posture as `statfs.zig`'s live `query("/")` test) so both
  entry points are now reached by `zig build test-diskusage`. Documented the
  `df` use-percentage rounding-convention split (coreutils rounds up, busybox
  rounds to nearest) in `SPEC.md`, per the same consumer's OpenWRT
  measurement (`/boot` at 36.37% prints 36 under busybox, 37 under round-up);
  this module does not compute a percentage itself, so a consumer picks the
  convention deliberately.
- **2026-08-18** — New module: `statfs(2)`/`statfs64(2)` disk-space query
  (total/free/available bytes, inodes, block size, fs type magic — `f_bfree`
  vs `f_bavail` both exposed and documented) plus `/proc/self/mounts` and
  `/proc/self/mountinfo` parsers, with octal-escape decoding for paths
  containing spaces/tabs/backslashes. Class B, oracle REDERIVED — struct
  layouts re-derived from kernel UAPI headers (cross-checked against musl's
  per-arch `bits/statfs.h`) covering four architecture families
  (`Native64`/`MipsStatfs64`/`PackedGeneric32`/`NaturalGeneric32`); mount
  parsers golden-tested against real captures from this host.
