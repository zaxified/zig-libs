# diskfree — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-04** — **Correction to the entry below.** That entry claimed
  `mountinfo` had stopped carrying its own duplicate of `readVirtualFile` and
  now called the fixed one. **It did not: the edit never reached the file**,
  so `mountinfo.readMountinfo` was still returning an over-limit read with its
  partial final row attached, which is the exact defect the entry says was
  fixed. The duplicate is gone now and the alias is in place. The truncation
  test could not have caught it either way: every limit it used (250, 4096)
  was a multiple of the 10-byte row length, so the cut always landed on a row
  boundary and nothing was ever dropped. It now also cuts at 255 (mid-row,
  expects 250) and at 5 (no whole row at all, expects 0), and removing the
  drop turns it red.

- **2026-09-04** — **First audit.** `mounts.unescapeOctal` did its octal
  arithmetic in `u8`, so an escape above `\377` overflowed: a checked panic
  in Debug and ReleaseSafe, and in ReleaseFast a silent wrap — `\400`
  decoded to `0x00`, injecting a NUL into a returned `mount_point`, and
  `\777` to `0xff`. Out-of-range escapes are now passed through literally,
  which is the rule the doc comment already stated for every other malformed
  escape. Both fuzz harnesses derived their choices from `Smith` ranged
  draws, which return the range's **minimum** unless the input bytes already
  lie in range — so with an ASCII corpus the entire fuzz lane was
  `parse*("")`; they are byte-driven now and trip the reinstated defect in
  ~550 rounds where the old shape reached the escape decoder zero times in
  1,000,000. `readVirtualFile` now drops the partial final line on
  truncation instead of promising that the parsers skip it (they do not: a
  cut inside the last column yields a well-formed **wrong** value, measured
  as `size=10` where the truth was `size=1024k`), and `mountinfo` calls that
  one reader rather than a duplicate of it. `statfs`'s architecture mapping
  became a testable `familyFor` function, and field mapping, family
  selection and saturating multiplication gained teeth — five mutations that
  had left the suite green, `f_bavail` -> `f_bfree` among them, are now red.
  `MountinfoEntry`'s doc no longer claims option strings cannot carry
  escapes: an overlay whose `lowerdir` holds a space really does yield
  `lowerdir=/…/low\040er`. SPEC's two open layout questions are closed by
  qemu-user across eight architectures and by the real x86 compat layer
  (`sz = 84` succeeds, 88/96/120/0/4096 all `EINVAL`).

- **2026-08-23** — **`statfs.query` refuses a path with an embedded NUL
  (`StatfsError.InvalidPath`) instead of acting on half of it.** `query` is
  public API and handed its `path` bytes straight to `std.posix.toPosixPath`,
  which guards an embedded NUL only with
  `if (std.debug.runtime_safety) assert(...)` — so it is compiled out exactly
  where it matters. Measured both ways: in `ReleaseSafe`,
  `query("/\0/definitely/not/a/real/path")` aborted on that assert (exit
  134 — a caller passing bytes it did not construct is entitled to an error,
  not a crash); in `ReleaseFast` the same call returned numbers
  byte-identical to `query("/")`, a confident answer about a *different*
  path. The sibling `diskusage` module fixed exactly this in its
  `stat.lstatPath`/`scan.scanAt`, and this refusal is deliberately the same
  shape — same error name, same up-front check — so the two answer alike.
  Mutation-proven: the check removed, the new test aborts on `toPosixPath`'s
  assert; restored, green.
- **2026-08-23** — **`readMounts`/`readMountinfo` now TRUNCATE at their 1 MiB
  cap instead of returning nothing.** Both were
  `allocRemaining(gpa, .limited(limit)) catch null`, and `allocRemaining`
  returns `error.StreamTooLong` the moment the limit is reached — so an
  oversized mount table produced `null`, which is the value both functions'
  doc comments reserve for "`/proc` is not mounted". A caller cannot tell
  those two apart, and SPEC.md had already promised the bounded-prefix
  behaviour. Measured on the defect: with the cap dropped to 300 bytes,
  `diskfree-demo` printed "-- 0 filesystem(s) shown." and exited 0 on a
  63-mount host. The truncated tail's last partial row is skipped as
  malformed, like any other. Both readers' doc comments already said they
  were the same idiom as `procnet.readVirtualFile`, where this was fixed
  first; they now are. The caps are named
  (`mounts.mount_table_read_limit`, `mountinfo.mountinfo_read_limit`) rather
  than inline so the number is visible. Both copies get their own regression
  test, because both are their own function — fixing one and not the other
  is how this pair got here.
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
  compile error a real consumer hit on the obvious entry point. Neither
  function was called by any test in this module, so the bodies were never
  semantically analysed and every gate stayed green (the same "never
  analysed, therefore never checked" shape the repo's build-system-level
  fixes addressed the same day). Fixed both to follow `procnet.readVirtualFile`'s
  established idiom (`std.Io.File.Reader.initStreaming` +
  `.interface.allocRemaining(gpa, .limited(limit))`) instead of a hand-rolled
  read loop. Added a live test for each (`readMounts`/`readMountinfo` against
  this host's real `/proc/self/mounts`/`mountinfo`, same "run unconditionally,
  no root needed" posture as `statfs.zig`'s live `query("/")` test) so both
  entry points are now reached by `zig build test-diskfree`. Documented the
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
