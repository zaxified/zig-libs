# diskusage — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-23** — **`scanAt`'s NUL check was untested, and SPEC.md said the
  opposite.** No behaviour change; a correction to what was claimed about the
  coverage of the entry above. SPEC.md's "Fuzzing" paragraph said `scan.scanAt`
  "shares the same entry point" as `lstatPath` and was therefore covered by
  that harness. It does not and it was not: `scanAt` carries its own copy of
  the NUL check and its own `toPosixPath` call, then goes to `stat.lstatAt`
  directly, so no fuzz input can reach `scan.zig`'s guard. Measured before
  the new test existed: making the check in `scanAt` unreachable left
  `zig build test-diskusage` at exit 0, while the same treatment of
  `lstatPath`'s gave exit 1. The SPEC now says
  what is true, and the duplicated guard has the duplicated test it needed
  ("a path with an embedded NUL is refused, not scanned as its prefix",
  passing a NUL whose prefix is a real directory — the shape a truncating
  build answers *successfully* about). That mutation is now red.
- **2026-08-23** — New module: the `du(1)` half of the `du`/`df` pair, taking
  the name `diskfree` was renamed out of (`f35b1f9`). Two layers.

  **`stat.zig` — per-file metadata `std` does not expose.**
  `std.Io.File.Stat` carries neither `st_blocks` (real allocation, the number
  `du` reports — `st_size` is the *apparent* size and differs by the whole
  hole on a sparse file) nor `st_dev` (the `du -x` boundary, and half of the
  `(dev, ino)` identity hard links need). `std.os.linux` declares no `Stat`
  struct and no `fstatat` wrapper either — only `Statx`. So: `statx(2)`
  primary, one architecture-independent buffer; a raw `fstatat`/`fstatat64`
  fallback for kernels older than 4.11, with nine per-architecture kernel-ABI
  structs (x86_64, asm-generic 64, s390x, powerpc64, mips, asm-generic 32,
  arm, i386, powerpc32).

  ⚠ **`fstatat` has no `sz` argument**, so unlike `diskfree`'s `statfs64`
  wrapper there is no kernel-side `EINVAL` on a wrong struct — a layout
  mistake is silent. Every family is therefore pinned by `comptime` asserts on
  `@sizeOf` *and* the `@offsetOf` of all six fields read, with the numbers
  taken from a cross-compilation oracle (compile the real kernel UAPI header
  for each architecture with a compiler that knows that ABI; read
  `sizeof`/`offsetof` back out of ELF symbol sizes). That oracle established
  two things hand arithmetic gets wrong: **s390x puts `st_blocks` at offset
  112** where every other 144-byte family puts it at 64, and **ARM's and
  i386's `struct stat64` are the same C source and different structs** (104
  vs 96 bytes, five fields moved, because the two ABIs align an 8-byte scalar
  differently). Architectures the oracle cannot check, or whose
  syscall→struct pairing could not be established (sparc, sparc64, m68k,
  xtensa, x32, mips64 n32), are `statx`-only and return `error.Unsupported`
  rather than guessing. riscv32 and loongarch32 have no `fstatat` at all —
  the kernel gave the newest 32-bit architectures `statx` and nothing else.

  **`scan.zig` — the traversal.** `std.Io.Dir.walkSelectively` (its explicit
  `enter` is the seam the filesystem boundary needs; a failed `enter` leaves
  the walk in the parent, which is `du`'s complain-and-continue for free; and
  `Walker.Entry`'s open dir + basename makes every `lstat` one `fstatat`
  against an fd, with no `PATH_MAX` ceiling on depth). Hard-link
  de-duplication by `(dev, ino)` for non-directories with `nlink > 1`,
  post-order per-directory subtotals through a context-carrying `DirSink`,
  per-failure `ErrorSink`, and skip-and-carry-on partial failure.

  **Anchored against both installed `du` implementations**, byte for byte, on
  a purpose-built fixture (sparse file, hard-linked pair, valid + dangling
  symlinks, `chmod 000` directory, empty directory, FIFO, four-level nest),
  run on **tmpfs and ext4** — the two disagree on every directory's `st_size`
  and `st_blocks`, so a single-filesystem fixture would hide a
  directory-accounting error. Seven modes each, always at `-B1`: `du`'s
  default columns are 1024-byte blocks rounded up per entry and different
  implementations round differently, so comparing them would turn a display
  convention into a false failure.

  Three `du` behaviours were established by measurement, not documentation,
  and two of them broke the first implementation:

  - **A directory contributes 0 to apparent size.** `du --apparent-size -B1`
    reports `0` for an empty ext4 directory whose `st_size` is 4096; uutils
    agrees; neither documents it. Summing directories too — the obvious
    implementation — disagrees with `du` by the sum of every directory's
    `st_size` in the tree.
  - **`-x` excludes a cross-device entry entirely**, rather than merely
    declining to descend: the boundary directory's own blocks are not counted
    and no line is printed for it. Both implementations agree.
  - **On a cross-device *file* (a bind-mounted file), GNU `du -x` drops it and
    uutils keeps it** — the two oracles genuinely disagree. This module
    follows GNU. Both cross-device cases were built inside a user namespace
    (`unshare --user --map-root-user --mount`), which needs no root.

  Eight mutations were applied one at a time and reverted — including
  `X8664Stat`'s `st_blksize`/`st_blocks` swapped with the size assert kept
  satisfied, which is the mutation the missing `sz` check makes necessary, and
  which the live `statx` cross-check caught (`expected 8, found 4096`). Two did
  not behave as a plain red and both are worth recording: dropping
  `AT_SYMLINK_NOFOLLOW` does not fail a test, it **hangs** (the fixture's
  `loop.lnk -> ..` turns the walk into an unbounded descent — killed at 150 s),
  which is the strongest available argument for having no follow-symlinks
  option; and disabling the one-filesystem check **survived the first run**
  because the `/sys/fs` boundary test guarded itself with "if the scan reports
  nothing skipped, skip" — a precondition read off the mechanism under test, so
  the mutation turned the test into a skip, and a skip is a pass. The guard now
  counts boundary children with `stat.lstatAt` directly and the same mutation
  turns it red.

  The layout oracle ships as `tools/stat-layout-probe.sh` so the nine families
  can be re-derived rather than trusted; run against two different kernel-header
  versions on this host (6.8 and 7.0) it gives identical numbers.

  Class B, oracle EXTERNAL (traversal) + REDERIVED (struct layouts); details
  in `SPEC.md`.

  **Fuzzed, and it found a real one.** `lstatPath`'s `path` goes straight to
  the kernel rather than through a decoder, but a `testing.fuzz(` harness on
  it caught `std.posix.toPosixPath` doing the wrong thing on an embedded NUL:
  an `assert` (a crash in this module's safety-checked test build) that
  compiles away entirely in `ReleaseFast`, where the same input would have
  silently resolved a *shorter* path than the one the caller passed. Both
  `lstatPath` and `scanAt` now check for one first and return the new
  `error.InvalidPath` instead. Mutation-proven: the check removed, the
  harness crashed exactly as before it existed; restored, green again.
