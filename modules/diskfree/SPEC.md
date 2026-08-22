# `diskfree` — specification

Design + threat notes for auditors. Usage: see [`./README.md`](./README.md).

## What this module is, and what it is not

A `statfs(2)`/`statfs64(2)` syscall wrapper plus `/proc/self/mounts` and
`/proc/self/mountinfo` parsers — enough to answer "what is mounted and how
full is it" without spawning `df`/`mount`/`findmnt`. It is not a general
`/proc` reader (see `procnet` for that, and `README.md`'s "Why this exists,
and why it is not part of `procnet`" for why the two stay separate), not a
`libmount`-equivalent (no mount-tree traversal helpers beyond the raw
`mount_id`/`parent_id` fields `mountinfo` hands back — a caller that wants
the tree built into a data structure builds it from those), and not a
filesystem-type-name resolver (`Usage.fs_type_magic` is the raw kernel magic
number; see README's DEFER list).

## Wire format / algorithm

**`statfs`/`statfs64` struct layout.** `std.os.linux` (0.16) declares the
syscall *numbers* per architecture (`std.os.linux.syscalls.<Arch>.statfs`/
`.statfs64`) but no struct to receive the result — this module supplies that
half, transcribed from the kernel UAPI headers rather than assumed:

| Family | Syscall | Struct source | Size | Targets |
|---|---|---|---|---|
| `Native64` | `statfs` (no size arg) | `include/uapi/asm-generic/statfs.h`, `__BITS_PER_LONG == 64` branch | 120 | x86_64, aarch64, riscv64, loongarch64, and the native ABI of powerpc64/s390x/sparc64/mips64 (n64) |
| `MipsStatfs64` | `statfs64` | `arch/mips/include/uapi/asm/statfs.h` | 96 | `.mips`/`.mipsel` (o32); `.mips64`/`.mips64el` built n32 (`gnuabin32`/`muslabin32`) |
| `PackedGeneric32` | `statfs64` | asm-generic, packed (`packed,aligned(4)`) — ARM sets `ARCH_PACK_STATFS64` directly, per `arch/arm/…/statfs.h`; x86 packs only the separate `compat_statfs64` struct, via `ARCH_PACK_COMPAT_STATFS64` in `arch/x86/…/statfs.h` — see "x86 compat-layer assumption" below | 84 | arm/armeb/thumb/thumbeb, x86 (i386) |
| `NaturalGeneric32` | `statfs64` | asm-generic, no arch override (natural C alignment) | 88 | powerpc(32), m68k, sparc(32), xtensa, riscv32, loongarch32, arc, csky, hexagon, or1k |

Family selection (`statfs.zig`'s `family` comptime constant) mirrors
`std.os.linux.SYS`'s own arch/ABI switch, including the mips64 n32 special
case. `x32` (`x86_64` target, `gnux32`/`muslx32` ABI) is refused at compile
time rather than guessed at — not a target of this collection, and nobody
had a kernel header to check it against.

**x86 compat-layer assumption.** The real `arch/x86/include/uapi/asm/
statfs.h` on this host reads:

```c
#define ARCH_PACK_COMPAT_STATFS64 __attribute__((packed,aligned(4)))
#include <asm-generic/statfs.h>
```

— it defines `ARCH_PACK_COMPAT_STATFS64` and never touches
`ARCH_PACK_STATFS64` at all. (ARM's header, by contrast, really does define
`ARCH_PACK_STATFS64` directly:
`#define ARCH_PACK_STATFS64 __attribute__((packed,aligned(4)))`.) A native
32-bit x86 kernel's own `statfs64` therefore falls through to the generic
header's *unpacked* fallback (`#ifndef ARCH_PACK_STATFS64 #define
ARCH_PACK_STATFS64 #endif`) — i.e. `NaturalGeneric32` (88 bytes), the same
struct every other architecture with no per-arch override gets — not the
84-byte `PackedGeneric32` this module assigns to `.x86`.

What x86 actually packs is a *different* kernel struct, `compat_statfs64`
(also confirmed against the real header: same fields, same order, same
84-byte packed layout as `PackedGeneric32`) — the struct a 32-bit userspace
process gets when it calls `statfs64` under an x86_64 kernel's 32-bit compat
syscall table. This module keeps `.x86 => .packed32` (`family`'s `switch` in
`statfs.zig`), deliberately choosing to model that compat case rather than a
native i386 kernel, because native 32-bit x86 kernels are essentially
extinct while 32-bit x86 userspace under an x86_64 kernel (multilib/compat)
is the realistic deployment for anything this module would actually run on.
That assumption was previously unstated anywhere in this file — it is now.

It is also unverified by this repository (no i386 kernel, native or
compat-hosting, in CI) and could in principle be wrong for a genuinely
native i386 target. The severity of being wrong is bounded by the same
self-checking property documented below: `do_statfs64` rejects a caller
whose `sz` argument does not match its own struct's size, so a native i386
kernel handed this module's 84-byte `PackedGeneric32` buffer (its own
`statfs64` being 88 bytes) returns `EINVAL` rather than reading back a
silently-misaligned `Usage` — a loud failure, not silent corruption, and no
worse than the unverified-but-EINVAL-bounded status the Anchoring/Open
sections already give `NaturalGeneric32`/`MipsStatfs64`.

**Why `statfs64`, not `statfs`, wherever it exists.** The plain `statfs`
struct's counters are kernel `long` — 32 bits on a 32-bit kernel ABI, which
wraps for real filesystem sizes well within what an embedded device's
storage can be. `statfs64` is the kernel's fix (64-bit counters, at the cost
of an explicit `sz` argument). On a native 64-bit target `long` is already
64 bits, so plain `statfs` already carries full range and nothing is gained
by the `64`-suffixed syscall — mirrors musl libc's own choice
(`src/stat/statvfs.c`: `#ifdef SYS_statfs64` use it with `sizeof(*buf)`,
`#else` plain `statfs`), studied as a design reference, no source copied.

**Self-checking property.** The kernel's `do_statfs64` rejects a caller
whose `sz` argument does not exactly equal its own struct's `sizeof`
(`-EINVAL`). A wrong struct size for a given architecture therefore fails
the *live* syscall loudly rather than reading back a silently-misaligned
`Usage` — this does not substitute for reading the header correctly (an
`EINVAL` return is still a broken module for that architecture), but it does
mean a layout mistake cannot manifest as quietly-wrong numbers on the
architectures where the syscall actually runs. The `comptime` size asserts
in `statfs.zig` catch the same class of mistake earlier — at compile time,
on every architecture this collection ever targets, not only the one CI
happens to build on.

**`f_bfree` vs `f_bavail`.** Both are exposed (`Usage.blocks_free` /
`Usage.blocks_available`) rather than collapsed to one number, because they
answer different questions: `f_bfree` is raw free space, `f_bavail` is what
an *unprivileged* caller can actually use — the difference is the margin a
filesystem reserves for its superuser (`tune2fs -m` on ext-family; 0 on most
non-ext filesystems, so the two often coincide there but must not be assumed
equal). `df`(1) reports "Available" and computes its use-percentage from
`f_bavail`; a consumer replacing `df` gets different numbers if it reads the
wrong field, which is exactly the bug this module's doc comments are written
to prevent.

**Use-percentage rounding: this module does not compute one, and the two
common `df` implementations disagree on how.** `Usage` exposes the raw block
counters (`blocks_total`/`blocks_free`/`blocks_available`) and byte
convenience wrappers (`totalBytes`/`freeBytes`/`availableBytes`); it
deliberately stops short of a "percent used" number, because there is no
single correct rounding rule to bake in — a consumer replacing `df` output
has to pick one, and the two real-world implementations pick differently:

- **coreutils `df`** rounds *up* (`df.c`'s `usage_percent` in GNU coreutils
  computes `used`/`total` and takes the `ceiling`, so any nonzero remainder
  bumps the percentage to the next whole number).
- **busybox `df`** rounds to the *nearest* whole percent:
  `(used*100 + denom/2) / denom` (integer division with a pre-added half-
  denominator, the standard round-half-up-via-integer-arithmetic idiom;
  `denom` is `total`, `used` is `total - available`).

The two disagree exactly at the boundary a truncating/flooring implementation
would also get wrong, and disagree with each other by construction whenever
the true percentage has a nonzero fractional part below `.5` (round-up says
one more than round-to-nearest). This is not a hypothetical: measured on real
OpenWRT 25.12.4 hardware, `/boot` at a true 36.37% used prints **36%** under
busybox's `df` and **37%** under a round-up implementation — a one-point
difference from the identical underlying `f_blocks`/`f_bavail` numbers, pure
rounding-rule choice. A consumer computing a percentage from this module's
`Usage` fields should pick one of the two conventions above deliberately
(most OpenWRT/embedded targets — this module's `.linux32` audience — report
busybox's round-to-nearest; most desktop/server Linux reports coreutils'
round-up) rather than inventing a third (e.g. plain truncation, which matches
neither and would read low compared to both real-world tools).

**`/proc/self/mounts` and `/proc/self/mountinfo`.** Both covered — see
`README.md`'s "Why this exists" section for the choice between them (short
version: `mounts` for the common `df`-adjacent case and its stable four-
column shape going back to `mtab`(5); `mountinfo` for the mount tree, bind-
mount root, and device number, and because it is what modern tooling
actually reads). Both parsers reverse the kernel's `mangle_path`
(`fs/seq_file.c`) octal-escape encoding of space/tab/newline/backslash in
path fields (`mounts.unescapeOctal`, shared by both files) — decoded
generically as any `\` followed by three octal digits, not limited to the
four bytes the kernel happens to emit today.

## Constant-time contract

Not applicable — no secret material is handled anywhere in this module.

## Limits and refusals

- `statfs.query`'s path is bounded by `std.posix.toPosixPath`'s
  `PATH_MAX`-derived buffer; a longer path returns `error.NameTooLong`
  rather than truncating.
- `mounts.readMounts`/`mountinfo.readMountinfo` cap the read at 1MiB
  (`readVirtualFile`'s `limit` argument) — chosen as generous headroom over
  any real host's mount table (this repo's own dev host's `/proc/self/mounts`
  is ~4KiB for 63 mounts) while still bounding allocation against a
  pathological mount count, matching `procnet`'s `readVirtualFile`
  discipline (its own doc comment explains why a streaming read is required
  at all: `/proc` files report size 0 from `stat`).
- A malformed row in either parser (too few columns, non-numeric IDs, a
  missing `-` separator in `mountinfo`) is skipped, not fatal — one corrupt
  line does not sink the whole table, matching `procnet`'s parsers.

## Anchoring

**Anchor grade:** class B · oracle REDERIVED

- **Class B** — the wire formats (`statfs64` struct layout, `/proc/self/
  mounts`/`mountinfo` text shape) are real external kernel ABI/UAPI
  contracts another implementation must agree with, so an outside truth
  exists.
- **Oracle REDERIVED**: `mounts.zig`/`mountinfo.zig` tests run against text
  actually captured from this host's live `/proc/self/mounts` and
  `/proc/self/mountinfo` (`src/testdata/*_sample.txt`) plus hand-authored
  fixtures for the escaped-path case — an in-house oracle reaching the
  answer by reading the real kernel output, which catches a parsing typo but
  not a shared misreading of the escape rule. `statfs.zig`'s struct layouts
  are re-derived from the kernel UAPI header text
  (`/usr/src/linux-headers-*/arch/{x86,arm,mips}/include/uapi/asm/statfs.h`
  and `include/uapi/asm-generic/statfs.h`, cross-checked against musl's own
  per-arch `bits/statfs.h`, which independently confirmed the MIPS field
  order) rather than a live syscall on every architecture — this repository
  has no MIPS/ARM/x86(32) kernel to run against, only x86_64. The `Native64`
  path (x86_64) *is* additionally live-verified: `query("/")` runs the real
  syscall on every CI lane and asserts internally consistent, non-garbage
  numbers.

  The other three families were cross-compiled (not merely parsed) with `zig
  build-obj -target <triple>`, forcing real semantic analysis of `query` (a
  bare compile of `root.zig` with nothing calling into it analyses nothing —
  verified by deliberately breaking a struct's `comptime` size assert and
  seeing the "broken" build still exit 0, until an `export fn` that actually
  calls `query` was added to force it), across x86 (i386), arm, mips, mipsel,
  powerpc, riscv32, aarch64, riscv64, s390x, sparc64 and loongarch64. This
  caught a real bug in this module before it shipped: the four families'
  `comptime` size asserts are NOT pruned per-target (`family`'s `switch` in
  `query` is pruned, but a file's top-level `comptime {}` blocks all run
  whenever that file is analyzed at all, on whichever target is active), and
  `extern struct` fields left at "natural" alignment size differently per
  target — i386's SysV ABI aligns 8-byte scalars to 4 bytes, unlike every
  other target here — so `MipsStatfs64`/`NaturalGeneric32` computed the wrong
  size the moment i386 was the active target, even though neither struct is
  ever used on i386. Every field 8 bytes or wider now carries an explicit
  `align(8)`/`align(4)` (see the comment block above `Native64`), making each
  struct's `@sizeOf` a fixed fact about the kernel ABI it represents,
  independent of the active compilation target. Confirmed by mutating each of
  the four size asserts in turn and observing the forced-analysis build fail
  (previously silent), then reverting and observing it pass again, on the
  same target that first exposed the bug. One target does not build at all —
  `mips64-linux-muslabin32` (mips n32 ABI) — but the failure is entirely
  inside `std.Io.Threaded`'s generic Linux file-mapping code and the
  `MipsN32` syscall table (missing `.llseek`, an `arg6: u32` vs `u64`
  mismatch), not in anything this module wrote; it looks like a gap in Zig
  0.16.0's own std support for that specific ABI variant, not a `diskfree`
  defect, and n32 (as opposed to o32, `.mips`/`.mipsel`, which build and
  analyze cleanly) is not the concrete target this module's requirements
  named.

## What is deliberately not done

- Filesystem-type-magic → name mapping. The kernel's magic-number list is
  long, undocumented in one canonical machine-readable place, and grows;
  duplicating it here would drift. `Usage.fs_type_magic` is exposed raw.
- `fstatfs` (the file-descriptor-based sibling of `statfs`) — `query` takes
  a path, which covers "what does this directory's filesystem look like"
  without requiring the caller to already have an open fd. Adding `fstatfs`
  is a small, symmetric extension if a consumer needs it on an already-open
  fd; deferred until one does.
- `/proc/<pid>/mounts`/`mountinfo` for a namespace other than the caller's
  own — only `self` is covered (see README DEFER).
- A `libmount`-style mount-tree builder over `mountinfo`'s `mount_id`/
  `parent_id` — the raw fields are exposed; building and maintaining a tree
  structure from them is consumer-side until something here needs it
  internally.

## Open

- `NaturalGeneric32`/`PackedGeneric32`/`MipsStatfs64` are unverified by a
  live syscall on their actual target architectures (no such kernel is
  available in this collection's CI, x86_64 + arm64 only) — see the
  Anchoring section's REDERIVED grade for what cross-compilation *did*
  verify (real semantic analysis + target-independent `comptime` size
  asserts across eleven architectures). The kernel's own `sz`-mismatch
  `-EINVAL` check means a layout error would surface as a hard failure
  rather than silent corruption on whichever architecture eventually
  exercises this for real, but that is a safety net, not a substitute for
  the missing live test.
- `mips64-linux-muslabin32` (mips n32 ABI) does not currently build at all —
  the failure is inside Zig 0.16.0's own `std.Io.Threaded`/`std.os.linux`
  support for that target (a `.llseek` syscall missing from the `MipsN32`
  table, an `arg6` width mismatch), unrelated to this module's code. Not
  investigated further here: out of scope for a `diskfree` fix, and o32
  (`.mips`/`.mipsel`) — the concrete target this module's requirements
  named — builds and analyzes cleanly.
- `.x86`'s mapping to `PackedGeneric32` assumes a 32-bit process under an
  x86_64 kernel's compat syscall layer, not a native i386 kernel — see the
  "x86 compat-layer assumption" note above for the header text this rests
  on and the `EINVAL` bound on being wrong. Not further verified here: no
  i386 kernel, native or compat-hosting, is available in this collection's
  CI to check the assumption against a live syscall either way.
