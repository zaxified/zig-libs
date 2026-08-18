# diskusage — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-18** — Fix (post-tag audit): two findings.

  **Citation fix + stated assumption.** `SPEC.md` and `statfs.zig`'s
  `PackedGeneric32` doc comment claimed `arch/x86/include/uapi/asm/statfs.h`
  sets `ARCH_PACK_STATFS64`, "the same as ARM" — checked against this host's
  real kernel headers and false: x86's header defines only
  `ARCH_PACK_COMPAT_STATFS64`, for the separate `compat_statfs64` struct: ARM
  really does set `ARCH_PACK_STATFS64` directly, x86 never does. A native
  32-bit x86 kernel's own `statfs64` is therefore unpacked
  (`NaturalGeneric32`, 88 bytes), not the 84-byte `PackedGeneric32` `.x86`
  was already mapped to. Kept the `.x86 => .packed32` mapping rather than
  changing it: `compat_statfs64` — what a 32-bit process gets under an
  x86_64 kernel's compat syscall layer — shares `PackedGeneric32`'s exact
  layout, and that compat case, not a native i386 kernel, is the realistic
  `.x86` deployment (native 32-bit x86 kernels are essentially extinct).
  That assumption was previously unstated; now documented at the mapping
  site (`family`'s `switch` in `statfs.zig`), in `PackedGeneric32`'s and
  `NaturalGeneric32`'s doc comments, and in a new "x86 compat-layer
  assumption" note in `SPEC.md`, which also notes the severity bound: the
  kernel's own `sz`-mismatch check means a wrong assumption for a given
  target surfaces as `EINVAL`, not silent corruption.

  **Leak fixes, allocator-failure path.** Neither `mounts.parseMounts` nor
  `mountinfo.parseMountinfo` was tested under allocation failure
  (`FailingAllocator`: zero hits in the module before this). Both leaked on
  their `out.append` growth allocation: `mounts.zig` had `errdefer`s for
  `device`/`mount_point`/`fs_type` but not `options`, so a failed append
  leaked only `options`; `mountinfo.zig`'s `parseLine` returns a
  fully-owned `MountinfoEntry` whose own `errdefer`s discharge on its
  successful return, so `parseMountinfo` had no cleanup registered for any
  of its seven fields at all — a failed append there leaked the whole
  entry. Fixed by arming an `errdefer` (`gpa.free(options)` /
  `entry.free(gpa)`) immediately before each fallible `append`. Writing the
  `FailingAllocator` sweep test (every allocation-failure index from 0
  through a fully-successful run's total, `std.testing.allocator` as the
  real backing store so any leak is reported at test teardown) also
  surfaced a third, related leak in both files' existing top-of-function
  `errdefer freeAll(gpa, out.toOwnedSlice(gpa) catch &.{})`: `toOwnedSlice`
  can itself allocate (to shrink-to-fit), so on the same allocator-failure
  path this errdefer exists to guard, that call could also fail, and
  `catch &.{}` silently substituted an empty slice — leaking every
  already-collected entry. Replaced with a `free`+`deinit` errdefer that
  cannot itself allocate. Confirmed both tests fail (6 and 15 leaked
  allocations respectively, `std.testing.allocator`'s `DebugAllocator`
  reporting them at teardown) against the pre-fix source, and pass clean
  after.

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
