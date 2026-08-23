// SPDX-License-Identifier: MIT
//! Raw per-file metadata: `statx(2)` where the kernel has it, a raw
//! `fstatat`/`fstatat64` syscall with a per-architecture kernel-ABI struct
//! where it does not. No libc, no `std.c`.
//!
//! **Why this file exists at all.** The portable `std.Io.File.Stat` (0.16)
//! carries `size`, `mode`, `kind`, `inode` and the three timestamps — and
//! neither of the two numbers `du` is actually built on:
//!
//!   * `st_blocks`, the *allocated* 512-byte block count. `du` reports
//!     `st_blocks * 512` by default; `st_size` (all `std` exposes) is the
//!     *apparent* size, and for a sparse file the two differ by the whole
//!     hole.
//!   * `st_dev`, the device the file lives on — the only way to stop a
//!     traversal at a filesystem boundary (`du -x`), and half of the
//!     `(dev, ino)` identity that makes hard-link de-duplication correct.
//!     `std.Io.File.Stat.inode` alone is not an identity: inode numbers are
//!     only unique *within* one filesystem.
//!
//! **Why not `std.os.linux`, which is Linux-specific and could carry them.**
//! It does not: `std.os.linux` (0.16) declares no `Stat` struct and no
//! `fstatat`/`newfstatat` wrapper at all — grepped, not assumed. What it
//! *does* declare is `Statx` and `statx()`, which is the whole reason for
//! the two-backend shape below.
//!
//! ## Two backends, and why the modern one is not enough on its own
//!
//! `statx(2)` (Linux 4.11, 2017) was introduced precisely to end the
//! per-architecture `struct stat` zoo — its buffer has ONE layout on every
//! architecture, and `std.os.linux.Statx` already declares it. Where it is
//! available it is strictly the better call: no layout to get wrong, and it
//! hands back `stx_dev_major`/`stx_dev_minor` already split rather than
//! packed into an encoded `dev_t`.
//!
//! It is not available everywhere this collection claims to run. `.linux32`
//! here means a big-endian soft-float MIPS router class of device, where a
//! 4.9-era vendor kernel is ordinary and `statx` returns `ENOSYS`. So the
//! fallback is a raw `fstatat`/`fstatat64` with the kernel's own per-arch
//! `struct stat`/`struct stat64` — the same shape `diskfree`'s `statfs.zig`
//! takes for `statfs64`, but with one important difference stated loudly:
//!
//! ⚠ **`fstatat` has no `sz` argument, so there is no kernel-side check on
//! the struct layout.** `statfs64`'s `do_statfs64` rejects a caller whose
//! size argument disagrees with the kernel's own (`EINVAL`), which makes a
//! layout mistake there fail loudly. Nothing equivalent exists here: hand
//! `fstatat64` a wrongly-shaped buffer and the kernel fills it happily and
//! you read back silently-misaligned numbers. That absence is why every
//! family below is pinned by a `comptime` assert on `@sizeOf` *and* on the
//! `@offsetOf` of every field this module actually reads, and why those
//! numbers come from a cross-compilation oracle rather than from arithmetic
//! done by hand — see `SPEC.md`'s Anchoring section for the harness.
//!
//! Architectures whose syscall→struct pairing could not be pinned down that
//! way get `family = .none` and are `statx`-only: a loud `error.Unsupported`
//! on an old kernel, never a guess.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

comptime {
    if (builtin.os.tag != .linux)
        @compileError("diskusage.stat is Linux-only (raw statx/fstatat syscalls, no portable fallback)");
}

/// Everything `du` needs about one file, normalised across both backends.
///
/// `dev_major`/`dev_minor` are split rather than left as an encoded `dev_t`
/// because that is how `statx` hands them over, because it is what
/// `/proc/self/mountinfo` prints, and because the encoded form is a kernel
/// ABI detail (`new_encode_dev`, `include/linux/kdev_t.h`) with no meaning
/// to a caller. The `fstatat` backend decodes it (`decodeDev`).
pub const FileStat = struct {
    /// `st_mode` — file type bits plus permissions.
    mode: u32,
    /// `st_nlink`. `> 1` on a non-directory is what makes hard-link
    /// de-duplication necessary; `du` checks exactly this before paying for
    /// a hash insertion.
    nlink: u64,
    /// `st_size` — the *apparent* size, what `du --apparent-size` sums. For
    /// a sparse file this is larger, often far larger, than what the file
    /// occupies; for a file with tail-packing or transparent compression it
    /// can be smaller.
    size: u64,
    /// `st_blocks` — allocated 512-byte blocks, what plain `du` sums. The
    /// 512 is fixed by POSIX and by the kernel's own field comment
    /// ("Number 512-byte blocks allocated"), NOT by the filesystem's block
    /// size, and must not be confused with `st_blksize`.
    blocks: u64,
    /// Major number of the device holding this file.
    dev_major: u32,
    /// Minor number of the device holding this file.
    dev_minor: u32,
    /// `st_ino`. Unique only within one device — pair it with
    /// `dev_major`/`dev_minor` (see `id`) before using it as an identity.
    ino: u64,

    /// `st_blocks * 512`, saturating. The default `du` measure.
    pub fn allocatedBytes(s: FileStat) u64 {
        return s.blocks *| 512;
    }

    /// The `(device, inode)` pair that identifies a file uniquely across a
    /// whole traversal. Inode alone is not unique across filesystems, which
    /// is exactly the case a hard-link de-duplicator must not get wrong.
    pub fn id(s: FileStat) Id {
        return .{ .dev = (@as(u64, s.dev_major) << 32) | s.dev_minor, .ino = s.ino };
    }

    /// Device identity only — what a one-filesystem boundary compares.
    pub fn device(s: FileStat) u64 {
        return (@as(u64, s.dev_major) << 32) | s.dev_minor;
    }

    pub fn isDir(s: FileStat) bool {
        return s.mode & linux.S.IFMT == linux.S.IFDIR;
    }
    pub fn isSymLink(s: FileStat) bool {
        return s.mode & linux.S.IFMT == linux.S.IFLNK;
    }
    pub fn isRegular(s: FileStat) bool {
        return s.mode & linux.S.IFMT == linux.S.IFREG;
    }
};

/// A file's cross-filesystem identity. Comparable and hashable.
pub const Id = struct {
    dev: u64,
    ino: u64,
};

pub const StatError = error{
    FileNotFound,
    AccessDenied,
    NotDir,
    NameTooLong,
    TooManySymlinks,
    IoError,
    /// The kernel has neither `statx` (pre-4.11) nor an `fstatat` layout
    /// this module has verified for the current architecture. Deliberately
    /// distinct from `Unexpected`: it is a fact about the host, not a bug.
    Unsupported,
    Unexpected,
};

/// Which syscall a call should use. Chosen once by `detect` and then passed
/// in explicitly rather than cached in a global — the detection costs one
/// syscall and a caller that scans a tree does it once per scan, so a
/// process-wide latch would buy nothing but shared mutable state.
pub const Backend = enum {
    /// `statx(2)`. One architecture-independent buffer layout.
    statx,
    /// `fstatat`/`fstatat64(2)` with this architecture's kernel-ABI struct.
    fstatat,
};

/// Whether this architecture has an `fstatat` struct layout verified by the
/// layout oracle (see SPEC.md). `false` means `statx` is the only backend
/// and a pre-4.11 kernel yields `error.Unsupported`.
pub const fstatat_available: bool = family != .none;

/// One probing `statx` call. Returns `.fstatat` only when `statx` is
/// genuinely absent (`ENOSYS`) *and* this architecture has a verified
/// layout; every other outcome — including a probe that fails for an
/// unrelated reason such as the probe path not existing — keeps `.statx`,
/// because "statx exists but this path is bad" is not evidence about the
/// syscall.
pub fn detect() Backend {
    if (!fstatat_available) return .statx;
    var buf: linux.Statx = undefined;
    const rc = linux.statx(linux.AT.FDCWD, "/", linux.AT.SYMLINK_NOFOLLOW, linux.STATX.BASIC_STATS, &buf);
    return if (linux.errno(rc) == .NOSYS) .fstatat else .statx;
}

/// `lstat`-equivalent relative to an open directory fd: never follows a
/// final symlink, which is `du`'s default and the only behaviour this
/// module offers (see SPEC.md's "Symlinks" decision).
///
/// Taking `(dirfd, basename)` rather than a whole path is deliberate: a
/// traversal already holds the containing directory open, so this avoids
/// re-resolving every component of a deep path on every file, and avoids
/// `PATH_MAX` entirely for trees deeper than it.
pub fn lstatAt(backend: Backend, dirfd: i32, basename: [*:0]const u8) StatError!FileStat {
    return switch (backend) {
        .statx => statxAt(dirfd, basename),
        .fstatat => fstatatAt(dirfd, basename),
    };
}

/// `lstat`-equivalent on a path resolved against the current working
/// directory (or an absolute path).
pub fn lstatPath(backend: Backend, path: []const u8) StatError!FileStat {
    const path_z = std.posix.toPosixPath(path) catch return error.NameTooLong;
    return lstatAt(backend, linux.AT.FDCWD, &path_z);
}

// ── statx backend ───────────────────────────────────────────────────────────

fn statxAt(dirfd: i32, basename: [*:0]const u8) StatError!FileStat {
    var raw: linux.Statx = undefined;
    // AT.STATX_SYNC_AS_STAT (0) — "do whatever stat() does". Explicitly NOT
    // AT.STATX_DONT_SYNC: on a network filesystem that would let the kernel
    // answer from a cache, and a `du` that reports stale block counts is
    // worse than a slow one. NO_AUTOMOUNT mirrors what `du` gets from its
    // own lstat: traversing a directory must not trigger an automount.
    const flags: u32 = linux.AT.SYMLINK_NOFOLLOW | linux.AT.NO_AUTOMOUNT | linux.AT.STATX_SYNC_AS_STAT;
    const rc = linux.statx(dirfd, basename, flags, linux.STATX.BASIC_STATS, &raw);
    const e = linux.errno(rc);
    if (e != .SUCCESS) return mapErrno(e);

    // The kernel fills `mask` with what it actually answered, and its own
    // man page tells callers to check it rather than trust the request.
    // BLOCKS is the one field this module cannot substitute for: without it
    // the default measure would silently read 0 for every file. SIZE and
    // INO are equally load-bearing. A filesystem that declines any of them
    // is reported, not papered over.
    if (!raw.mask.BLOCKS or !raw.mask.SIZE or !raw.mask.INO or !raw.mask.NLINK or !raw.mask.TYPE)
        return error.Unsupported;

    return .{
        .mode = raw.mode,
        .nlink = raw.nlink,
        .size = raw.size,
        .blocks = raw.blocks,
        .dev_major = raw.dev_major,
        .dev_minor = raw.dev_minor,
        .ino = raw.ino,
    };
}

// ── fstatat backend: per-architecture kernel-ABI structs ────────────────────
//
// Every struct below is transcribed field-for-field from a kernel UAPI
// header (cited per family), and every one carries an EXPLICIT `align(...)`
// on each field 8 bytes or wider. That is not decoration, and the reason is
// the same one `diskfree/src/statfs.zig` records: `family`'s switch is
// comptime-pruned to the active target, but the top-level `comptime {}`
// blocks below are NOT — Zig evaluates every one of them whenever this file
// is analysed, on whichever target happens to be active. `@sizeOf`/
// `@offsetOf` of an `extern struct` with natural alignment is a function of
// the CURRENT target's C ABI, and the targets here disagree: i386's SysV ABI
// aligns an 8-byte scalar to 4, ARM's EABI to 8, and the two produce
// genuinely different layouts from *identical* C source (see `X86Stat64` at
// 96 bytes versus `ArmStat64` at 104 — same fields, same order, same header
// text lineage, different ABI). Forcing the alignment makes each struct's
// byte layout a fixed fact about the kernel ABI it was transcribed from,
// independent of the compilation target that happens to be analysing it.
//
// The asserts pin `@sizeOf` and the `@offsetOf` of every field this module
// reads. Size alone is not enough: two field orders can share a size, and
// `st_blocks` in particular sits at a different offset on s390x (112) than
// on every other 144-byte family (64) — a mistake a size assert would wave
// straight through.

/// `arch/x86/include/uapi/asm/stat.h`, the `#else /* __i386__ */` branch —
/// x86_64's `struct stat`, filled by `newfstatat` (syscall 262, which Zig's
/// syscall table spells `fstatat64`).
const X8664Stat = extern struct {
    dev: u64 align(8),
    ino: u64 align(8),
    nlink: u64 align(8),
    mode: u32,
    uid: u32,
    gid: u32,
    __pad0: u32,
    rdev: u64 align(8),
    size: i64 align(8),
    blksize: i64 align(8),
    blocks: i64 align(8),
    atime: u64 align(8),
    atime_nsec: u64 align(8),
    mtime: u64 align(8),
    mtime_nsec: u64 align(8),
    ctime: u64 align(8),
    ctime_nsec: u64 align(8),
    __unused: [3]i64 align(8),
};
comptime {
    assertLayout(X8664Stat, 144, .{ .dev = 0, .ino = 8, .mode = 24, .nlink = 16, .size = 48, .blocks = 64 });
}

/// `include/uapi/asm-generic/stat.h`, the `struct stat` (64-bit) shape —
/// every 64-bit architecture with no per-arch `asm/stat.h` override in the
/// kernel tree: aarch64, riscv64, loongarch64. Reached through the generic
/// `__NR3264_fstatat` = 79.
const Generic64Stat = extern struct {
    dev: u64 align(8),
    ino: u64 align(8),
    mode: u32,
    nlink: u32,
    uid: u32,
    gid: u32,
    rdev: u64 align(8),
    __pad1: u64 align(8),
    size: i64 align(8),
    blksize: i32,
    __pad2: i32,
    blocks: i64 align(8),
    atime: i64 align(8),
    atime_nsec: u64 align(8),
    mtime: i64 align(8),
    mtime_nsec: u64 align(8),
    ctime: i64 align(8),
    ctime_nsec: u64 align(8),
    __unused4: u32,
    __unused5: u32,
};
comptime {
    assertLayout(Generic64Stat, 128, .{ .dev = 0, .ino = 8, .mode = 16, .nlink = 20, .size = 48, .blocks = 64 });
}

/// `arch/s390/include/uapi/asm/stat.h`. Same 144 bytes as x86_64's, and a
/// DIFFERENT field order: `st_blksize`/`st_blocks` come *after* the three
/// timestamps here, so `st_blocks` sits at offset 112 rather than 64. This
/// is the concrete case that makes a size-only assert insufficient.
const S390xStat = extern struct {
    dev: u64 align(8),
    ino: u64 align(8),
    nlink: u64 align(8),
    mode: u32,
    uid: u32,
    gid: u32,
    __pad1: u32,
    rdev: u64 align(8),
    size: u64 align(8),
    atime: u64 align(8),
    atime_nsec: u64 align(8),
    mtime: u64 align(8),
    mtime_nsec: u64 align(8),
    ctime: u64 align(8),
    ctime_nsec: u64 align(8),
    blksize: u64 align(8),
    blocks: i64 align(8),
    __unused: [3]u64 align(8),
};
comptime {
    assertLayout(S390xStat, 144, .{ .dev = 0, .ino = 8, .mode = 24, .nlink = 16, .size = 48, .blocks = 112 });
}

/// `arch/powerpc/include/uapi/asm/stat.h`, the `__powerpc64__` branch of
/// `struct stat` (`st_nlink` before `st_mode`, one extra `__unused6`).
const PowerPc64Stat = extern struct {
    dev: u64 align(8),
    ino: u64 align(8),
    nlink: u64 align(8),
    mode: u32,
    uid: u32,
    gid: u32,
    __pad0: u32,
    rdev: u64 align(8),
    size: i64 align(8),
    blksize: u64 align(8),
    blocks: u64 align(8),
    atime: u64 align(8),
    atime_nsec: u64 align(8),
    mtime: u64 align(8),
    mtime_nsec: u64 align(8),
    ctime: u64 align(8),
    ctime_nsec: u64 align(8),
    __unused4: u64 align(8),
    __unused5: u64 align(8),
    __unused6: u64 align(8),
};
comptime {
    assertLayout(PowerPc64Stat, 144, .{ .dev = 0, .ino = 8, .mode = 24, .nlink = 16, .size = 48, .blocks = 64 });
}

/// `arch/mips/include/uapi/asm/stat.h`. One struct covers two families,
/// because the header itself says so: MIPS's 32-bit `struct stat64` is
/// documented there as "The memory layout is the same as of struct stat of
/// the 64-bit kernel", and the layout oracle confirms it — `mips-linux-musl`
/// building `struct stat64` and `mips64-linux-musl` building `struct stat`
/// produce byte-identical offsets. So `.mips`/`.mipsel` (o32, via
/// `fstatat64` 4293) and `.mips64`/`.mips64el` (n64, via `newfstatat` 5252)
/// share this one declaration.
const MipsStat = extern struct {
    dev: u32,
    __pad0: [3]u32,
    ino: u64 align(8),
    mode: u32,
    nlink: u32,
    uid: u32,
    gid: u32,
    rdev: u32,
    __pad1: [3]u32,
    size: i64 align(8),
    atime: i32,
    atime_nsec: u32,
    mtime: i32,
    mtime_nsec: u32,
    ctime: i32,
    ctime_nsec: u32,
    blksize: u32,
    __pad2: u32,
    blocks: i64 align(8),
};
comptime {
    assertLayout(MipsStat, 104, .{ .dev = 0, .ino = 16, .mode = 24, .nlink = 28, .size = 56, .blocks = 96 });
}

/// `include/uapi/asm-generic/stat.h`, the `struct stat64` (32-bit) shape —
/// every 32-bit architecture with no per-arch override that still has an
/// `fstatat64`: arc, csky, hexagon, or1k. Reached through `__NR3264_fstatat`
/// = 79 in its 32-bit spelling.
const Generic32Stat64 = extern struct {
    dev: u64 align(8),
    ino: u64 align(8),
    mode: u32,
    nlink: u32,
    uid: u32,
    gid: u32,
    rdev: u64 align(8),
    __pad1: u64 align(8),
    size: i64 align(8),
    blksize: i32,
    __pad2: i32,
    blocks: i64 align(8),
    atime: i32,
    atime_nsec: u32,
    mtime: i32,
    mtime_nsec: u32,
    ctime: i32,
    ctime_nsec: u32,
    __unused4: u32,
    __unused5: u32,
};
comptime {
    assertLayout(Generic32Stat64, 104, .{ .dev = 0, .ino = 8, .mode = 16, .nlink = 20, .size = 48, .blocks = 64 });
}

/// `arch/arm/include/uapi/asm/stat.h`'s `struct stat64` — the glibc-2.1
/// shape with "absolutely insane amounts of padding around dev_t's", as the
/// header itself puts it. Note the two inode fields: the legacy 32-bit
/// `__st_ino` near the front (which the header flags as
/// `STAT64_HAS_BROKEN_ST_INO`) and the real 64-bit `st_ino` at the very
/// end, at offset 96. Reading the wrong one would give a truncated identity
/// and break hard-link de-duplication on a large filesystem, silently.
const ArmStat64 = extern struct {
    dev: u64 align(8),
    __pad0: [4]u8,
    __st_ino: u32,
    mode: u32,
    nlink: u32,
    uid: u32,
    gid: u32,
    rdev: u64 align(8),
    __pad3: [4]u8,
    size: i64 align(8),
    blksize: u32,
    blocks: u64 align(8),
    atime: u32,
    atime_nsec: u32,
    mtime: u32,
    mtime_nsec: u32,
    ctime: u32,
    ctime_nsec: u32,
    ino: u64 align(8),
};
comptime {
    assertLayout(ArmStat64, 104, .{ .dev = 0, .ino = 96, .mode = 16, .nlink = 20, .size = 48, .blocks = 64 });
    // The 8-byte alignment is the whole difference from X86Stat64 below.
    std.debug.assert(@alignOf(ArmStat64) == 8);
}

/// `arch/x86/include/uapi/asm/stat.h`'s `__i386__` `struct stat64`. The C
/// source is field-for-field the same as ARM's above; the i386 SysV ABI
/// aligns an 8-byte scalar to 4 rather than 8, and that alone moves five
/// fields and shrinks the struct from 104 bytes to 96. Two architectures,
/// one header lineage, two incompatible layouts — which is why this module
/// declines to derive a layout from field text alone.
const X86Stat64 = extern struct {
    dev: u64 align(4),
    __pad0: [4]u8,
    __st_ino: u32,
    mode: u32,
    nlink: u32,
    uid: u32,
    gid: u32,
    rdev: u64 align(4),
    __pad3: [4]u8,
    size: i64 align(4),
    blksize: u32,
    blocks: u64 align(4),
    atime: u32,
    atime_nsec: u32,
    mtime: u32,
    mtime_nsec: u32,
    ctime: u32,
    ctime_nsec: u32,
    ino: u64 align(4),
};
comptime {
    assertLayout(X86Stat64, 96, .{ .dev = 0, .ino = 88, .mode = 16, .nlink = 20, .size = 44, .blocks = 56 });
    std.debug.assert(@alignOf(X86Stat64) == 4);
}

/// `arch/powerpc/include/uapi/asm/stat.h`'s `struct stat64` (32-bit
/// PowerPC). Distinguished from the asm-generic 32-bit shape by the
/// `unsigned short __pad2` after `st_rdev` where the generic header has a
/// full `unsigned long long __pad1`, and by having no `__pad2` word between
/// `st_blksize` and `st_blocks` — the two end up at the same offsets anyway,
/// which is exactly the sort of coincidence a separate declaration plus its
/// own oracle row is meant to keep honest rather than assumed.
const PowerPc32Stat64 = extern struct {
    dev: u64 align(8),
    ino: u64 align(8),
    mode: u32,
    nlink: u32,
    uid: u32,
    gid: u32,
    rdev: u64 align(8),
    __pad2: u16,
    size: i64 align(8),
    blksize: i32,
    blocks: i64 align(8),
    atime: i32,
    atime_nsec: u32,
    mtime: i32,
    mtime_nsec: u32,
    ctime: i32,
    ctime_nsec: u32,
    __unused4: u32,
    __unused5: u32,
};
comptime {
    assertLayout(PowerPc32Stat64, 104, .{ .dev = 0, .ino = 8, .mode = 16, .nlink = 20, .size = 48, .blocks = 64 });
}

/// Compile-time layout pin: `@sizeOf` plus the `@offsetOf` of every field
/// this module reads. Written as one helper rather than open-coded asserts
/// so a family added later cannot ship with the size checked and the
/// offsets forgotten.
fn assertLayout(comptime T: type, comptime size: usize, comptime off: struct {
    dev: usize,
    ino: usize,
    mode: usize,
    nlink: usize,
    size: usize,
    blocks: usize,
}) void {
    std.debug.assert(@sizeOf(T) == size);
    std.debug.assert(@offsetOf(T, "dev") == off.dev);
    std.debug.assert(@offsetOf(T, "ino") == off.ino);
    std.debug.assert(@offsetOf(T, "mode") == off.mode);
    std.debug.assert(@offsetOf(T, "nlink") == off.nlink);
    std.debug.assert(@offsetOf(T, "size") == off.size);
    std.debug.assert(@offsetOf(T, "blocks") == off.blocks);
}

const Family = enum { x86_64, generic64, s390x, ppc64, mips, generic32, arm32, x86_32, ppc32, none };

const family: Family = switch (builtin.cpu.arch) {
    .x86_64 => switch (builtin.abi) {
        // x32 (ILP32 over the x86_64 syscall ABI) has its own compat stat
        // layout that nothing here has checked — `diskfree` refuses it for
        // the same reason. statx-only rather than a guess.
        .gnux32, .muslx32 => .none,
        else => .x86_64,
    },
    .aarch64, .aarch64_be, .riscv64, .loongarch64 => .generic64,
    .s390x => .s390x,
    .powerpc64, .powerpc64le => .ppc64,
    .mips, .mipsel => .mips,
    .mips64, .mips64el => switch (builtin.abi) {
        // n32's `fstatat64` (6256) routes to a compat handler whose struct
        // this module has not pinned down, and Zig 0.16 cannot build for
        // `muslabin32` at all (std's own MipsN32 syscall table is
        // incomplete — recorded in diskfree's SPEC). Not guessed at.
        .gnuabin32, .muslabin32 => .none,
        else => .mips,
    },
    .arm, .armeb, .thumb, .thumbeb => .arm32,
    .x86 => .x86_32,
    .powerpc, .powerpcle => .ppc32,
    .arc, .arceb, .csky, .hexagon, .or1k => .generic32,
    // Everything else is statx-only. Three groups, all deliberate:
    //   * riscv32 and loongarch32 have NO fstatat syscall at all — the
    //     kernel gave the newest 32-bit architectures `statx` and nothing
    //     else, which is the clearest possible statement of where this is
    //     all heading (verified against std's own syscall tables).
    //   * sparc/sparc64 have both a `struct stat` and a `struct stat64` and
    //     this module could not establish which one syscall 289 fills.
    //   * m68k and xtensa ship their own `asm/stat.h` but no LLVM Linux
    //     backend here, so the layout oracle cannot check them.
    // See SPEC.md's "Open" section.
    else => .none,
};

fn fstatatAt(dirfd: i32, basename: [*:0]const u8) StatError!FileStat {
    // AT.NO_AUTOMOUNT is deliberately NOT passed here: it is meaningful to
    // fstatat, but the whole point of this backend is a kernel old enough
    // to lack statx, and NO_AUTOMOUNT predates statx by far, so it is safe
    // — the omission would be the bug. Passed for parity with the statx
    // path above.
    const flags: u32 = linux.AT.SYMLINK_NOFOLLOW | linux.AT.NO_AUTOMOUNT;
    switch (family) {
        .none => return error.Unsupported,
        inline else => |f| {
            const T = comptime familyStruct(f);
            var raw: T = std.mem.zeroes(T);
            const rc = linux.syscall4(
                .fstatat64,
                @as(usize, @bitCast(@as(isize, dirfd))),
                @intFromPtr(basename),
                @intFromPtr(&raw),
                flags,
            );
            const e = linux.errno(rc);
            if (e != .SUCCESS) return mapErrno(e);
            const dev = decodeDev(@intCast(raw.dev));
            return .{
                .mode = raw.mode,
                .nlink = raw.nlink,
                // `st_size`/`st_blocks` are signed in several of the kernel
                // structs above and unsigned in others. Clamping a negative
                // to 0 rather than `@bitCast`ing it keeps a corrupt or
                // hostile value from becoming an astronomically large
                // unsigned one that then dominates a subtree total.
                .size = clampNonNegative(raw.size),
                .blocks = clampNonNegative(raw.blocks),
                .dev_major = dev.major,
                .dev_minor = dev.minor,
                .ino = raw.ino,
            };
        },
    }
}

/// Widen a kernel counter to `u64`, treating a negative value as 0. Written
/// generically because the same field is signed in some of the structs above
/// and unsigned in others.
fn clampNonNegative(v: anytype) u64 {
    return if (v > 0) @intCast(v) else 0;
}

fn familyStruct(comptime f: Family) type {
    return switch (f) {
        .x86_64 => X8664Stat,
        .generic64 => Generic64Stat,
        .s390x => S390xStat,
        .ppc64 => PowerPc64Stat,
        .mips => MipsStat,
        .generic32 => Generic32Stat64,
        .arm32 => ArmStat64,
        .x86_32 => X86Stat64,
        .ppc32 => PowerPc32Stat64,
        .none => unreachable,
    };
}

/// `new_decode_dev` from `include/linux/kdev_t.h`, verbatim. Every
/// `struct stat` family above stores `st_dev` in this encoding — `fs/stat.c`
/// fills it with `encode_dev`/`huge_encode_dev`, and `huge_encode_dev` is
/// literally `return new_encode_dev(dev);`, so the 64-bit families carry the
/// same 32 bits of information as the 32-bit ones and decode identically.
///
/// Splitting the 20-bit minor across two ranges (low 8 bits at the bottom,
/// the rest above bit 20) is the historical part: it kept the old
/// 8-bit-major/8-bit-minor `dev_t` values numerically unchanged when the
/// kernel widened them.
pub fn decodeDev(encoded: u64) struct { major: u32, minor: u32 } {
    const d: u32 = @truncate(encoded);
    return .{
        .major = (d & 0xfff00) >> 8,
        .minor = (d & 0xff) | ((d >> 12) & 0xfff00),
    };
}

fn mapErrno(err: linux.E) StatError {
    return switch (err) {
        .NOENT => error.FileNotFound,
        .ACCES, .PERM => error.AccessDenied,
        .NOTDIR => error.NotDir,
        .NAMETOOLONG => error.NameTooLong,
        .LOOP => error.TooManySymlinks,
        .IO => error.IoError,
        .NOSYS => error.Unsupported,
        else => error.Unexpected,
    };
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "decodeDev: round-trips the kernel's own new_encode_dev" {
    // new_encode_dev, transcribed from include/linux/kdev_t.h, used only
    // here as the inverse under test. If both directions were written from
    // the same misreading this test would pass vacuously, so the fixed
    // vectors below anchor it independently.
    const encode = struct {
        fn f(major: u32, minor: u32) u64 {
            return (minor & 0xff) | (major << 8) | ((minor & ~@as(u32, 0xff)) << 12);
        }
    }.f;

    const cases = [_][2]u32{
        .{ 0, 0 },
        .{ 8, 1 }, // /dev/sda1
        .{ 253, 0 }, // device-mapper
        .{ 0, 46 }, // typical tmpfs anonymous device
        .{ 259, 3 }, // nvme0n1p3 — major above 255, the case old_encode_dev cannot hold
        .{ 4095, 1048575 }, // widest representable major/minor
        .{ 1, 256 }, // minor just past the low 8 bits, where the split bites
    };
    for (cases) |c| {
        const got = decodeDev(encode(c[0], c[1]));
        try testing.expectEqual(c[0], got.major);
        try testing.expectEqual(c[1], got.minor);
    }
}

test "decodeDev: fixed vectors independent of the encoder above" {
    // Anchors taken from the encoding rule read off the kernel header by
    // hand, so a shared mistake in the encode/decode pair cannot hide here.
    // 0x00800001 => minor low bits 0x01, major (0x00800001 & 0xfff00) >> 8
    // = 0x000 ... use concrete numbers instead of prose:
    //   major 8, minor 1   -> (1 & 0xff) | (8 << 8) | 0 = 0x0801
    try testing.expectEqual(@as(u32, 8), decodeDev(0x0801).major);
    try testing.expectEqual(@as(u32, 1), decodeDev(0x0801).minor);
    //   major 259, minor 3 -> 3 | (259 << 8) = 0x10303
    try testing.expectEqual(@as(u32, 259), decodeDev(0x10303).major);
    try testing.expectEqual(@as(u32, 3), decodeDev(0x10303).minor);
    //   major 1, minor 256 -> (256 & ~0xff) << 12 = 0x100000, | (1<<8)
    try testing.expectEqual(@as(u32, 1), decodeDev(0x100100).major);
    try testing.expectEqual(@as(u32, 256), decodeDev(0x100100).minor);
}

test "lstatPath: a real directory reports sane, self-consistent metadata" {
    const backend = detect();
    const s = try lstatPath(backend, "/");
    try testing.expect(s.isDir());
    try testing.expect(!s.isSymLink());
    try testing.expect(s.nlink >= 1);
    // Every real filesystem gives `/` a nonzero device. A zero here is the
    // signature of a struct read at the wrong offset.
    try testing.expect(s.device() != 0);
    try testing.expect(s.ino != 0);
}

test "lstatPath: missing path is FileNotFound, not a zeroed FileStat" {
    const backend = detect();
    try testing.expectError(error.FileNotFound, lstatPath(backend, "/no/such/path/diskusage-test"));
}

test "lstatPath: does not follow the final symlink" {
    const backend = detect();
    // /proc/self is a symlink on every Linux host; following it would give
    // a directory, not following it gives the link itself.
    const s = try lstatPath(backend, "/proc/self");
    try testing.expect(s.isSymLink());
    try testing.expect(!s.isDir());
}

test "both backends agree, field for field, on the same files" {
    // The load-bearing cross-check for the fstatat layout: statx has one
    // architecture-independent buffer and cannot be misaligned, so where
    // both backends exist, statx IS an oracle for the per-architecture
    // struct — an independent one, since a wrong offset in the struct
    // cannot also be wrong in the same way in statx's fixed layout.
    //
    // ⚠ This anchors exactly ONE family: whichever the build's own
    // architecture selects. It is a real live check where it applies and no
    // evidence at all about the other eight (see SPEC.md's Anchoring
    // section for what covers those).
    if (!fstatat_available) return error.SkipZigTest;
    if (detect() != .statx) return error.SkipZigTest; // no statx here: nothing to compare against

    const paths = [_][]const u8{ "/", "/proc/self", "/proc/self/mounts", "/dev/null", "/etc" };
    var compared: usize = 0;
    for (paths) |p| {
        const a = lstatPath(.statx, p) catch continue;
        const b = try lstatPath(.fstatat, p);
        try testing.expectEqual(a.mode, b.mode);
        try testing.expectEqual(a.nlink, b.nlink);
        try testing.expectEqual(a.size, b.size);
        try testing.expectEqual(a.blocks, b.blocks);
        try testing.expectEqual(a.dev_major, b.dev_major);
        try testing.expectEqual(a.dev_minor, b.dev_minor);
        try testing.expectEqual(a.ino, b.ino);
        compared += 1;
    }
    // Guard against the test passing because every path was skipped — the
    // vacuous-green shape a `continue` in a loop invites.
    try testing.expect(compared >= 3);
}

test "FileStat.allocatedBytes: 512-byte units, saturating" {
    const s: FileStat = .{ .mode = 0, .nlink = 1, .size = 0, .blocks = 8, .dev_major = 0, .dev_minor = 0, .ino = 0 };
    try testing.expectEqual(@as(u64, 4096), s.allocatedBytes());

    const huge: FileStat = .{ .mode = 0, .nlink = 1, .size = 0, .blocks = std.math.maxInt(u64), .dev_major = 0, .dev_minor = 0, .ino = 0 };
    try testing.expectEqual(std.math.maxInt(u64), huge.allocatedBytes());
}

test "FileStat.id: same inode on different devices is a different identity" {
    const a: FileStat = .{ .mode = 0, .nlink = 2, .size = 0, .blocks = 0, .dev_major = 8, .dev_minor = 1, .ino = 42 };
    const b: FileStat = .{ .mode = 0, .nlink = 2, .size = 0, .blocks = 0, .dev_major = 8, .dev_minor = 2, .ino = 42 };
    try testing.expect(!std.meta.eql(a.id(), b.id()));
    try testing.expect(std.meta.eql(a.id(), a.id()));
}
