# `diskusage` — specification

Design + threat notes for auditors. Usage: see [`./README.md`](./README.md).

## What this module is, and what it is not

The `du(1)` question: walk a directory tree, `lstat` every entry, accumulate
what it occupies. It is not a `df` tool — its sibling [`diskfree`](../diskfree)
is, and the two share no symbol; not a filesystem-space query (no `statfs`
anywhere here); not a duplicate-file finder (hard links are de-duplicated by
`(dev, ino)` identity, which is not content identity); and not a general
`stat` library — `stat.FileStat` carries the six fields `du` needs and no
timestamps, because a traversal that reads timestamps it never uses pays for
them on every file.

## Why a raw syscall layer is needed at all

`std.Io.File.Stat` (0.16) carries `size`, `mode`, `kind`, `inode` and three
timestamps. It carries neither of the two fields this module is built on:

| Field | What it decides | In `std.Io.File.Stat`? |
|---|---|---|
| `st_blocks` | allocated 512-byte blocks — the number plain `du` reports; `st_size` is the *apparent* size and differs by the whole hole on a sparse file | no |
| `st_dev` | the filesystem boundary (`du -x`), and half of the `(dev, ino)` identity hard-link de-duplication needs — `inode` alone is unique only *within* one filesystem | no |

`std.os.linux` is Linux-specific and could carry them; it does not. Grepped
against the 0.16 standard library: **no `Stat` struct and no
`fstatat`/`newfstatat` wrapper exist there at all.** What does exist is
`Statx` and `statx()`, which is what shapes the design below.

## Wire format / algorithm

### Two stat backends

**`statx(2)` is the primary backend.** It was added (Linux 4.11, 2017)
precisely to end the per-architecture `struct stat` zoo: one buffer layout on
every architecture, `stx_dev_major`/`stx_dev_minor` already split, and
`std.os.linux.Statx` already declares it. Where it exists there is no layout
to get wrong.

**A raw `fstatat`/`fstatat64` is the fallback**, because `statx` is not
everywhere this module claims to run. `.linux32` in this collection means a
big-endian soft-float MIPS router, where a 4.9-era vendor kernel is ordinary
and `statx` returns `ENOSYS`. The fallback is selected once per scan by a
single probing `statx` call and only on `ENOSYS` — any other probe failure
keeps `statx`, because "statx exists but this path is bad" is not evidence
about the syscall.

⚠ **`fstatat` has no `sz` argument, so there is no kernel-side check on the
struct layout.** This is the load-bearing difference from `diskfree`'s
`statfs64` wrapper, whose `do_statfs64` rejects a size mismatch with `EINVAL`
and therefore fails loudly. Nothing equivalent exists here: hand `fstatat64`
a wrongly-shaped buffer and the kernel fills it and you read back
silently-misaligned numbers, forever, on that architecture only. Everything in
the Anchoring section below exists because of that missing net.

### The `struct stat` families

| Family | Struct source | Size | `st_blocks` at | Architectures |
|---|---|---|---|---|
| `X8664Stat` | `arch/x86/…/stat.h`, non-`__i386__` `struct stat` | 144 | 64 | x86_64 |
| `Generic64Stat` | `include/uapi/asm-generic/stat.h`, `struct stat` | 128 | 64 | aarch64, aarch64_be, riscv64, loongarch64 |
| `S390xStat` | `arch/s390/…/stat.h` | 144 | **112** | s390x |
| `PowerPc64Stat` | `arch/powerpc/…/stat.h`, `__powerpc64__` branch | 144 | 64 | powerpc64, powerpc64le |
| `MipsStat` | `arch/mips/…/stat.h` | 104 | 96 | mips, mipsel (o32); mips64, mips64el (n64) |
| `Generic32Stat64` | `include/uapi/asm-generic/stat.h`, `struct stat64` | 104 | 64 | arc, arceb, csky, hexagon, or1k |
| `ArmStat64` | `arch/arm/…/stat.h`, `struct stat64` | **104** | 64 | arm, armeb, thumb, thumbeb |
| `X86Stat64` | `arch/x86/…/stat.h`, `__i386__` `struct stat64` | **96** | 56 | x86 (i386) |
| `PowerPc32Stat64` | `arch/powerpc/…/stat.h`, `struct stat64` | 104 | 64 | powerpc, powerpcle |

Two rows in that table are the whole argument for taking this seriously:

* **s390x puts `st_blocks` at offset 112**, where every other 144-byte family
  puts it at 64 — its `st_blksize`/`st_blocks` come *after* the three
  timestamps. A layout check that only asserted `@sizeOf` would wave a
  s390x/x86_64 mix-up straight through, which is why every family here is
  pinned by `@offsetOf` on all six fields the module reads, not by size alone.
* **`ArmStat64` and `X86Stat64` are the same C source and different structs.**
  Field for field identical in the kernel headers, 104 bytes on ARM and 96 on
  i386, because the i386 SysV ABI aligns an 8-byte scalar to 4 and ARM's EABI
  to 8. Five fields move. A layout derived from reading field names cannot see
  this; only a compiler that knows each ABI can.

That second point is also why every field 8 bytes or wider carries an explicit
`align(...)`, exactly as `diskfree/src/statfs.zig` records for its own structs:
`family`'s `switch` is comptime-pruned to the active target, but the top-level
`comptime {}` assert blocks are not — Zig evaluates them whenever the file is
analysed, on whichever target is active. With natural alignment the asserts
would measure the *active* target's ABI rather than the ABI each struct
represents.

### `st_dev` decoding

Every `struct stat` family stores `st_dev` in the kernel's `new_encode_dev`
form (`fs/stat.c` fills it with `encode_dev`/`huge_encode_dev`, and
`huge_encode_dev` is literally `return new_encode_dev(dev);`, so the 64-bit
families carry the same 32 bits as the 32-bit ones). `stat.decodeDev`
implements `new_decode_dev` from `include/linux/kdev_t.h` verbatim, including
the split of the 20-bit minor across two ranges — the historical detail that
kept old 8-bit/8-bit `dev_t` values numerically unchanged when the kernel
widened them. `statx` needs none of this: it hands major and minor over
already split, which is why `FileStat` stores them that way.

### Architectures that get no fallback

`family = .none` means `statx`-only: on a pre-4.11 kernel every call returns
`error.Unsupported` rather than a guess. Three groups, all deliberate:

* **riscv32, loongarch32** — the kernel gives them **no `fstatat` at all**.
  Verified against `std.os.linux.syscalls`: their tables contain `statx` and
  nothing else from the stat family. The newest 32-bit architectures were
  given `statx` as the only interface, which is the clearest available
  statement of where this is heading.
* **sparc, sparc64** — both a `struct stat` and a `struct stat64` exist in
  `arch/sparc/…/stat.h`, and this module could not establish which one syscall
  289 fills. Guessing has no loud-failure mode here (see the missing `sz`
  check above).
* **m68k, xtensa, x32, mips64 n32** — a per-architecture header exists but the
  layout oracle cannot compile for them (no LLVM Linux backend in this
  toolchain for m68k/xtensa), or the ABI variant is one Zig 0.16 cannot build
  at all (mips64 n32 — recorded in `diskfree`'s SPEC for the same reason), or
  nobody has checked it (x32, which `diskfree` also refuses).

### Traversal

`std.Io.Dir.walkSelectively`, not `walk` and not a hand-rolled walker.
`walkSelectively`'s explicit `enter` is the seam the one-filesystem boundary
needs (a decision made *between* seeing a directory and descending into it),
and a failed `enter` leaves the walk in the parent, which is exactly `du`'s
complain-and-continue behaviour. `Walker.Entry` also hands over the open
containing directory plus a basename, so every `lstat` is one `fstatat`
against an fd rather than a full path re-resolution — no `PATH_MAX` ceiling on
tree depth. A hand-rolled walker would have duplicated std's stack and
name-buffer bookkeeping and added none of that.

⚠ One sharp edge: `enter` refuses any entry whose `kind` is not `.directory`,
and `kind` comes from `getdents`' `d_type`, which several filesystems answer
as `.unknown`. This module classifies from the `lstat` it performs anyway and
re-labels the entry before entering, or it would silently never descend on
those filesystems.

Per-directory subtotals fall out of the traversal: a stack of frames indexed
by depth, closed when an entry at a shallower depth arrives. Children are
therefore delivered before parents and the root last — `du`'s own output
order, not a sort applied afterwards.

## The `du` compatibility decisions

Each of these decides whether this module's numbers can be compared to `du`'s
at all. All were settled by measurement against both installed
implementations, not by reading documentation.

**Apparent size versus allocated blocks: both, always, in one pass.** `du`
makes this an either/or flag; the two numbers come from two fields of the same
`lstat`, so computing one and discarding the other buys nothing, and a caller
who wants both would otherwise walk the tree twice.

⚠ **Directories contribute 0 to apparent size** — measured, and the single
easiest thing to get wrong here. `du --apparent-size -B1` reports `0` for an
empty ext4 directory whose `st_size` is 4096, and uutils' `du` agrees;
symlinks, FIFOs and regular files are all counted by their `st_size` in the
same run. Neither tool documents it. Including directories (the obvious first
implementation, and the one this module shipped for about an hour) makes every
apparent-size total disagree with `du` by the sum of every directory's
`st_size` in the tree. `allocated_bytes` does include directories: a directory
really does occupy the blocks it occupies.

**Hard links: counted once per `(dev, ino)`, per traversal.** Matching `du`'s
default; `Options.count_hard_links` is `du --count-links`. The check is
`nlink > 1 and not a directory`, so an ordinary tree never touches the hash
map at all, and a directory — which has `nlink > 1` the moment it has a
subdirectory — is never de-duplicated. Keying on `ino` alone would be wrong
across a tree spanning two filesystems, which is precisely when a de-duplicator
is exercised.

`Report.hard_link_bytes_skipped` is exposed because it is the one number `du`
cannot show you: it equals the difference between the default run and
`--count-links`, which otherwise costs a second traversal to learn.

**Symlinks: never followed.** `du`'s default. There is no option to follow
them, because following them is not `du`'s question and a followed symlink to
an ancestor makes the traversal non-terminating. The fixture carries a
`loop.lnk -> ..` for exactly that reason.

**One filesystem (`du -x`): excluded entirely, not merely not descended.**
⚠ **The two reference implementations disagree here.** Measured on a fixture
built inside a user namespace (`unshare --user --map-root-user --mount`, no
root needed):

* a cross-device *directory* — GNU and uutils both drop it completely: no
  output line, and its own 4096 bytes excluded from the parent's total. An
  implementation that only declines to descend, and still counts the mount
  point, disagrees with both. This module's first attempt did exactly that.
* a cross-device *file* (a bind-mounted file, the only way to make one) — GNU
  `du -x` drops it too (total 4096 where the plain run said 65536); uutils
  keeps it, applying the boundary to directories only.

This module follows GNU on both. The rule is applied where `fts` applies
`FTS_XDEV` — during the directory build, before `du` itself sees the entry —
so a filtered entry also never joins the hard-link set.

**Partial failure: skip and carry on.** An entry that cannot be stat'd and a
directory that cannot be opened are counted in `Report.errors`, passed to
`Options.on_error`, and stepped over; the scan still returns totals for
everything it could read, and the unreadable directory is still counted for
its own size. Only a failure on the scan *root*, and out-of-memory, are fatal.
That is `du`'s behaviour (one stderr line per failure, exit 1, totals still
printed) and it is what the rest of this collection's `/proc` and filesystem
parsers already do.

## Constant-time contract

Not applicable — no secret material is handled anywhere in this module.

## Limits and refusals

- `scanAt`'s path is bounded by `std.posix.toPosixPath`'s `PATH_MAX`-derived
  buffer (`error.NameTooLong`); paths *inside* the tree are not, because every
  entry is stat'd relative to its open parent directory rather than by full
  path.
- `lstatPath` and `scanAt`/`scanPath` reject a `path` containing an embedded
  NUL byte with `error.InvalidPath`, checked before `toPosixPath` ever sees
  it. `toPosixPath` itself only `assert`s the absence of one — a crash in a
  safety-checked build, and in `ReleaseFast`, where `assert` compiles away, a
  silent truncation to whatever precedes the NUL: a caller would be told
  about a shorter path than the one it actually gave. See the "Fuzzing"
  subsection below.
- Traversal depth is bounded only by memory: one frame plus one owned path
  copy per open directory.
- Every total saturates rather than wraps (`+|=`), and a negative `st_size` or
  `st_blocks` from a corrupt or hostile filesystem is clamped to 0 rather than
  `@bitCast` into an astronomically large unsigned value that would dominate a
  subtree total.
- The hard-link set holds one 16-byte key per multiply-linked non-directory
  encountered. A tree of nothing but hard links is the worst case, and it is
  the same worst case `du` has.
- `DirSink` failure aborts the scan with `error.SinkFailed`; the sink keeps
  the real reason in its own context. `ErrorSink` is infallible by design — a
  reporting channel that can itself fail turns one failure into two.

## Anchoring

**Anchor grade:** class B · oracle MIXED

- **Class B** — `du`'s semantics and the kernel's `struct stat` ABI are both
  real external contracts another implementation must agree with.

**Traversal — EXTERNAL, two independent oracles.** Both `du` implementations
installed on this host are diffed byte-for-byte against the example binary on
a fixture built for the purpose: a sparse file (1 MiB apparent, one block
allocated), a hard-linked pair in two different subdirectories, a valid and a
dangling symlink, a `chmod 000` directory with content inside, an empty
directory, a FIFO, a zero-length file and a four-level nest. Run on **tmpfs
and on ext4**, because the two disagree on every directory's `st_size` and
`st_blocks` and a fixture on only one of them would hide a directory-accounting
error. Seven modes each (default, `--apparent-size`, `--count-links`, `-s`,
`--max-depth=1`, `-x`, `--apparent-size --count-links`), and separately the
cross-device cases inside a user namespace.

The comparison is always against `du -B1`. ⚠ **A harness that compared `du`'s
default columns would be worse than no harness**: `du` reports in 1024-byte
blocks by default, rounds each entry up independently, and GNU and busybox
round differently (documented in `diskfree`'s SPEC for the `df` side of the
same problem). Those are display conventions. Comparing at `-B1` compares the
underlying integers, where a difference really is a defect.

**Struct layouts — REDERIVED, by a cross-compilation oracle.** Each family's
`@sizeOf` and the `@offsetOf` of all six fields read by this module were taken
from the *real* kernel UAPI header for that architecture, compiled by a
cross compiler that knows that architecture's C ABI. The harness compiles a
translation unit that includes the header and declares
`char probe_x[offsetof(struct stat, st_x) + 1];` per field, then reads the
numbers back out of the object file's ELF symbol sizes — no execution needed,
so it works for every architecture the toolchain can target:

The harness ships with the module — [`tools/stat-layout-probe.sh`](./tools/stat-layout-probe.sh)
— so the table above can be re-derived rather than trusted:

```sh
bash modules/diskusage/tools/stat-layout-probe.sh   # or pass a headers dir
```

Every number it prints must match an `assertLayout(...)` call in
`src/stat.zig`; 16 (family, target) pairs are covered. That is an oracle in the
strict sense: it fails independently of whatever this module's author believed,
and it is the thing that establishes `ArmStat64` ≠ `X86Stat64` and `st_blocks`
at 112 on s390x — both of which hand arithmetic gets wrong. Run against two
different kernel-header versions present on this host (6.8 and 7.0) it gives
identical numbers, which is what a UAPI contract is supposed to do and worth
having checked rather than assumed. Architectures the toolchain cannot target
are not guessed at; they get `family = .none` (see above).

**One family is additionally live-verified, and only one.** Where both
backends exist, `statx` *is* an independent oracle for the per-architecture
struct: its buffer has a fixed layout and cannot be misaligned in the same way
a wrong `@offsetOf` is. `stat.zig`'s "both backends agree, field for field"
test runs the same paths through both and compares all seven fields. On this
host that anchors `X8664Stat` and nothing else — the other eight families have
no kernel here to run against, and the test says so in a comment rather than
letting a green run imply more than it proves.

**Mutation-proven.** Eight mutations were applied one at a time, each observed
against the tests and then reverted and observed green again: hard-link
de-duplication disabled; apparent size including directories; allocated size
read from `st_size`; `AT_SYMLINK_NOFOLLOW` dropped; an unreadable directory
made fatal; the one-filesystem comparison disabled; `decodeDev`'s major shift
wrong by four bits; and — the one that matters most, given the missing `sz`
check — `X8664Stat`'s `st_blksize` and `st_blocks` swapped *with the size
assert kept satisfied*, so that only the `@offsetOf` half of the comptime
assert and the live `statx` cross-check stand between it and silent wrong
numbers.

Two of the eight did not behave as a plain red:

- **Dropping `AT_SYMLINK_NOFOLLOW` does not fail a test; it hangs.** The
  fixture carries `syms/loop.lnk -> ..`, so following the final symlink turns
  the traversal into an unbounded descent through the fixture root. Killed at
  150 s. That is the strongest available statement of why there is no
  follow-symlinks option: the failure mode is non-termination and unbounded
  memory growth, not a wrong number.
- ⚠ **Disabling the one-filesystem check SURVIVED the first run**, and the
  reason was a defect in the test rather than in the module. The `/sys/fs`
  boundary test guarded itself with "if the scan reports nothing skipped,
  `error.SkipZigTest`" — a precondition read off the very mechanism under
  test, so the mutation made the test *skip*, and a skip is a pass. The guard
  now counts boundary children with `stat.lstatAt` directly, independently of
  `scanAt`, and the same mutation turns it red. A precondition may never be
  read off the mechanism under test.

**Fuzzing.** `lstatPath`'s `path` is not this module's wire format — it is
handed straight to the kernel — so `stat.zig` carries a `testing.fuzz(`
harness on it with a narrower contract than a decoder's: never panic, and
never act on a different path than the bytes actually given, for arbitrary
byte content (embedded NUL, non-UTF8 bytes, a path past `PATH_MAX`, one that
is all slashes). It found `StatError.InvalidPath` above — the harness is what
turned up the `toPosixPath` assert/truncate hazard, not an audit reading the
source. `scan.scanAt` does **not** get a second harness: one would have to
walk the real filesystem on fuzzer-controlled input, exactly the
unbounded-traversal risk the symlink mutation above already demonstrates.
⚠ Nor is it covered by `lstatPath`'s — an earlier revision of this paragraph
claimed `scanAt` "shares the same entry point", and it does not: `scanAt`
carries its own copy of the NUL check and its own `toPosixPath` call, then
goes straight to `stat.lstatAt`, so no input to the harness can ever reach
`scan.zig`'s guard. Measured, *before* the test named below existed: making
the check in `scanAt` unreachable left `zig build test-diskusage` at exit 0,
while the same treatment of `stat.zig`'s `lstatPath` gave exit 1 (the fuzz
harness aborting on `toPosixPath`'s assert). What covers the duplicate
is a duplicate test — `scan.zig`'s "a path with an embedded NUL is refused,
not scanned as its prefix", which calls `scanAt` directly with a NUL whose
prefix is a real directory in the fixture (the shape a truncating build
answers *successfully* about). Both guards are mutation-proven, each against
its own test: removed, red; restored, green.

## What is deliberately not done

- **Following symlinks (`du -L`/`-D`).** Not `du`'s default, not this
  module's question, and an invitation to a non-terminating traversal.
- **`--separate-dirs`, `--threshold`, `--exclude`, `--inodes`, `--time`.**
  Reporting and filtering policy, all expressible by a caller over `DirSink`
  and `Report` without the module holding an opinion.
- **Block-size formatting and human-readable units.** The same reasoning
  `diskfree` gives for not computing a use-percentage: there is no single
  correct rounding rule to bake in, GNU and busybox pick differently, and a
  consumer that wants `du`'s columns should round deliberately. This module
  reports exact bytes.
- **A per-file sink (`du -a`).** The directory sink plus `Report` covers every
  question asked so far; adding a per-entry callback is a small symmetric
  extension when a consumer needs one.
- **`statfs`, mount tables, filesystem type.** That is `diskfree`. Neither
  module imports the other.

## Open

- Eight of the nine `fstatat` struct families have no live kernel here to
  syscall against — the cross-compilation oracle verifies their layout, and
  the `statx` cross-check verifies only x86_64's. Unlike `diskfree`'s
  `statfs64` wrapper there is **no `EINVAL` safety net**: a layout error on
  one of those architectures would be silent. The mitigation is that all nine
  are pinned by a compiler that knows each ABI, and that the fallback only
  runs at all on a kernel older than 4.11.
- `Generic32Stat64` is probe-verified through **hexagon** (and, redundantly,
  riscv32, which has no `fstatat` to use it with). It is also mapped to
  **arc, arceb, csky and or1k**, which this toolchain cannot target — those
  four have no per-architecture `asm/stat.h` in the kernel tree at all, which
  is by construction why they fall into the asm-generic bucket, but their ABI
  alignment is taken on trust rather than measured. `diskfree`'s
  `NaturalGeneric32` carries the same caveat for the same reason; unlike it,
  this one has no `EINVAL` net.
- `sparc`/`sparc64`, `m68k`, `xtensa`, `x32` and mips64 n32 have no fallback
  (`family = .none`) — see "Architectures that get no fallback". On those, a
  pre-4.11 kernel yields `error.Unsupported`. Closing any of them needs either
  a toolchain that can target it (m68k, xtensa) or a kernel syscall table to
  settle the syscall→struct pairing (sparc).
- The `-x` divergence between GNU and uutils on a cross-device *file* is
  recorded as measured behaviour of both; nothing here establishes which is
  the intended one. This module follows GNU.
- `du`'s "directories contribute 0 to apparent size" rule is likewise measured
  from two implementations, not read from either one's documentation or
  source.

## Provenance

Original work of the zig-libs authors (MIT), written from the Linux kernel's own UAPI
headers and the `statx(2)`/`fstatat(2)` manual pages — an interface specification, not a
copyrightable work (CONVENTIONS.md §5). No third-party source was read or ported.

**The committed data.** `tools/stat-layout-probe.sh` is our own tooling, and the numbers it
produces are **generated on demand from the kernel headers installed on the machine running
it** — nothing captured from a third party is checked in. The script compiles each
architecture's real UAPI `struct stat` with a cross compiler that knows that ABI and reads
the field offsets back out of ELF symbol sizes, so the layout assertions in `src/stat.zig`
can be re-derived by anyone rather than trusted. It exists precisely because `fstatat` takes
no size argument and therefore cannot fail loudly on a wrong struct the way `statfs64` does.

**The oracle for the traversal** is the two `du` implementations installed on the test
machine (GNU coreutils and uutils). They are executed as black boxes for comparison; no part
of either is read or reproduced here, and where the two disagree the difference is recorded
rather than resolved silently.
