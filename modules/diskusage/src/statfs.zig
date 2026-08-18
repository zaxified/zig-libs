// SPDX-License-Identifier: MIT
//! Raw `statfs(2)`/`statfs64(2)` syscall wrapper — no libc, no `std.c`.
//!
//! Why not just `std.posix`: 0.16's `std.posix`/`std.os.linux` carry no
//! `statfs` struct or wrapper at all (only the raw `SYS.statfs`/`SYS.statfs64`
//! syscall NUMBERS exist, per-arch, in `std.os.linux.syscalls`). This file is
//! the missing piece: the kernel-ABI struct layout, chosen per architecture,
//! plus the syscall invocation and errno mapping.
//!
//! **Why `statfs64`, not `statfs`, on 32-bit targets.** The plain `statfs`
//! syscall's struct uses 32-bit `long` counters on a 32-bit kernel ABI, which
//! silently wrap for any filesystem bigger than ~4GB (in block units, so in
//! practice far smaller than that for `f_files`/`f_ffree`). `statfs64` is the
//! kernel's own fix: same information, 64-bit counters, at the cost of an
//! extra `size_t sz` argument the kernel uses to validate the caller's struct
//! matches its own (`do_statfs64` returns `EINVAL` on a size mismatch — a
//! wrong struct size fails loudly, not silently). On a 64-bit target the
//! plain `statfs` struct already has 64-bit counters (`__BITS_PER_LONG == 64`
//! in the kernel's own `asm-generic/statfs.h`), so there is nothing `statfs64`
//! would add — this mirrors musl libc's own choice in
//! `src/stat/statvfs.c` (`__statfs`: `#ifdef SYS_statfs64` use it with
//! `sizeof(*buf)`, `#else` fall back to plain `statfs`), studied here as a
//! design reference (see `README.md`'s `Provenance:` line) — no source
//! copied, just the syscall-selection strategy.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

comptime {
    if (builtin.os.tag != .linux)
        @compileError("diskusage.statfs is Linux-only (raw statfs/statfs64 syscalls, no portable fallback)");
}

/// Kernel `__kernel_fsid_t` — two opaque 32-bit words identifying the
/// filesystem instance; glibc/musl both just copy it through without
/// interpreting it. 8 bytes on every architecture.
pub const Fsid = extern struct { val: [2]i32 };

/// One `statfs(2)` result, already widened to 64-bit counters regardless of
/// which kernel-ABI struct family the target architecture actually uses.
pub const Usage = struct {
    /// Optimal I/O block size (`f_bsize`), bytes.
    block_size: i64,
    /// Fragment size (`f_frsize`). Some filesystems/kernels report 0 here —
    /// per musl's `statvfs` fixup (`f_frsize ? f_frsize : f_bsize`), treat
    /// `block_size` as the true unit when this is 0.
    fragment_size: i64,
    /// Total blocks, in units of `block_size` (`f_blocks`).
    blocks_total: u64,
    /// Free blocks, **including** the filesystem's superuser-reserved margin
    /// (`f_bfree`). This is *not* what `df`'s "Avail" column reports — see
    /// `blocks_available`.
    blocks_free: u64,
    /// Free blocks available to an *unprivileged* caller (`f_bavail`). This
    /// is the number `df`(1) prints as "Available" and computes its
    /// use-percentage from. `blocks_free - blocks_available` is the margin
    /// reserved for root (ext-family: `tune2fs -m`; 0 on most non-ext
    /// filesystems, so the two are often equal there).
    blocks_available: u64,
    /// Total inodes (`f_files`); 0 on filesystems with no fixed inode count
    /// (some network/FUSE filesystems) — not an error.
    inodes_total: u64,
    /// Free inodes (`f_ffree`).
    inodes_free: u64,
    /// Raw `f_type` filesystem magic — see `statfs(2)`'s table (e.g.
    /// `0xEF53` = ext2/3/4, `0x01021994` = tmpfs, `0x9fa0` = proc). Not
    /// resolved to a name here: the kernel's list is long and grows, so a
    /// caller that cares compares against the specific constant it needs.
    fs_type_magic: u32,
    /// Maximum filename length the filesystem supports (`f_namelen`).
    name_max: i64,

    /// `blocks_total * block_size`, saturating (never wraps on an
    /// adversarial/corrupt report).
    pub fn totalBytes(u: Usage) u64 {
        return u.blocks_total *| blockSizeU64(u);
    }
    /// `blocks_free * block_size` — includes the root-reserved margin; see
    /// the field doc comment.
    pub fn freeBytes(u: Usage) u64 {
        return u.blocks_free *| blockSizeU64(u);
    }
    /// `blocks_available * block_size` — matches `df`'s "Available"/use%.
    pub fn availableBytes(u: Usage) u64 {
        return u.blocks_available *| blockSizeU64(u);
    }

    fn blockSizeU64(u: Usage) u64 {
        // block_size is a kernel-reported `long`; on real filesystems this is
        // always a small positive power of two, but a hostile/corrupt report
        // is clamped to 0 rather than trusted as a negative multiplier.
        return if (u.block_size > 0) @intCast(u.block_size) else 0;
    }
};

pub const StatfsError = error{
    FileNotFound,
    AccessDenied,
    NotDir,
    NameTooLong,
    TooManySymlinks,
    IoError,
    Unexpected,
};

// ── Kernel-ABI struct families ──────────────────────────────────────────────
//
// Every family below is transcribed field-for-field from a kernel UAPI header
// (cited per family) rather than assumed from the 64-bit-native shape. The
// kernel's own `do_statfs64` rejects a caller whose `sz` argument does not
// exactly equal its own struct's `sizeof` (`EINVAL`), so a wrong layout here
// fails the live syscall loudly on the real architecture rather than reading
// back silently-misaligned values — the `comptime` size asserts below catch
// the same mistake earlier, at compile time, on every architecture the
// collection ever targets (not just the one CI happens to build on).
//
// Every field 8 bytes wide or more carries an EXPLICIT `align(8)` (or, in
// `PackedGeneric32`, `align(4)`, matching the kernel's own packing). This is
// not decoration: `family`'s comptime-pruned `switch` means only the struct
// for the CURRENT build's own architecture is ever actually used at runtime,
// but the top-level `comptime {}` size-assert blocks below are NOT similarly
// pruned — Zig evaluates every top-level `comptime` block in a file once
// that file is analyzed at all, regardless of which target is active or
// which struct that target will end up using. `@sizeOf` of an `extern
// struct` with unforced ("natural") field alignment is a function of the
// CURRENT compilation target's C ABI, and at least one target this
// collection cross-compiles to disagrees with the others in exactly the way
// that matters here: the i386 SysV ABI aligns 8-byte scalars (`long long`)
// to 4 bytes, not 8, unlike every other target here. Left unforced, cross-
// compiling this file to `x86-linux-*` alone (a 32-bit target, hit while
// verifying `MipsStatfs64`/`NaturalGeneric32`'s sizes with `zig build-obj
// -target ...` against nine architectures) would have computed a SMALLER
// `@sizeOf(MipsStatfs64)`/`@sizeOf(NaturalGeneric32)` than on every other
// target and failed their assertions — not because those structs are wrong
// for MIPS/PowerPC/etc, but because a struct meant for one architecture was
// being SIZED under a different one's alignment rules. Forcing the
// alignment explicitly makes every struct's byte layout a fixed fact about
// the kernel ABI it was transcribed from, independent of whatever target
// happens to be active when the file is analyzed — which is what a
// `comptime` assert claiming to verify "the kernel's real struct layout"
// actually needs to mean.

/// `__BITS_PER_LONG == 64` shape of `include/uapi/asm-generic/statfs.h`,
/// used natively (via the plain `statfs`/`fstatfs` syscall, no `64` suffix,
/// no `sz` argument) on every 64-bit-pointer architecture this collection
/// targets: x86_64, aarch64, riscv64, loongarch64, and the 64-bit-native ABI
/// of powerpc64/s390x/sparc64/mips64 (n64). All eleven `long`-typed fields
/// are already 64 bits wide at this word size, so nothing here can silently
/// truncate a large filesystem — this *is* the "64-bit" struct, just spelled
/// `statfs` instead of `statfs64` because the kernel never needed a wider one
/// on these targets.
const Native64 = extern struct {
    type: i64 align(8),
    bsize: i64 align(8),
    blocks: u64 align(8),
    bfree: u64 align(8),
    bavail: u64 align(8),
    files: u64 align(8),
    ffree: u64 align(8),
    fsid: Fsid,
    namelen: i64 align(8),
    frsize: i64 align(8),
    flags: i64 align(8),
    spare: [4]i64 align(8),
};
comptime {
    std.debug.assert(@sizeOf(Native64) == 120); // 11 * 8 + spare[4] * 8
}

/// MIPS's *own* `statfs64` (`arch/mips/include/uapi/asm/statfs.h`) — the
/// kernel's asm-generic header explicitly carves MIPS out ("which I'm not
/// touching with a 10' pole"), and for good reason: field order and an
/// explicit padding word both differ from every other 32-bit architecture.
/// Shared, byte-for-byte, by the o32 (`_MIPS_SIM_ABI32`) and n32
/// (`_MIPS_SIM_NABI32`) ABIs — both are 32-bit-pointer targets in Zig terms
/// (`.mips`/`.mipsel`, and `.mips64`/`.mips64el` built for the n32 ABI). n64
/// mips64 does NOT use this — it takes the `Native64` path above, since its
/// `long` is already 64 bits.
const MipsStatfs64 = extern struct {
    type: u32,
    bsize: u32,
    frsize: u32,
    _pad: u32 = 0,
    blocks: u64 align(8),
    bfree: u64 align(8),
    files: u64 align(8),
    ffree: u64 align(8),
    bavail: u64 align(8),
    fsid: Fsid,
    namelen: u32,
    flags: u32,
    spare: [5]u32,
};
comptime {
    // 4*4 (type/bsize/frsize/_pad) + 5*8 (blocks/bfree/files/ffree/bavail)
    // + 8 (fsid) + 2*4 (namelen/flags) + 5*4 (spare) = 16+40+8+8+20 = 92,
    // rounded up to the struct's own 8-byte alignment (from the u64 fields).
    std.debug.assert(@sizeOf(MipsStatfs64) == 96);
}

/// asm-generic `statfs64` (`include/uapi/asm-generic/statfs.h`) as used
/// *packed* — `packed,aligned(4)` — which is what
/// `arch/arm/include/uapi/asm/statfs.h` sets directly via
/// `ARCH_PACK_STATFS64`, citing the reason: avoid 8-byte alignment padding
/// after the two leading 32-bit words so 32-bit and 64-bit userspace agree
/// on the layout.
///
/// **x86 is different, and it matters.** `arch/x86/include/uapi/asm/
/// statfs.h` never defines `ARCH_PACK_STATFS64` — it defines only
/// `ARCH_PACK_COMPAT_STATFS64`, which packs the *separate*
/// `compat_statfs64` struct (what a 32-bit process gets calling `statfs64`
/// under an x86_64 kernel's compat syscall layer). A native i386 kernel's
/// own `statfs64` therefore falls through to the generic header's unpacked
/// default — `NaturalGeneric32` below, not this struct. What IS packed on
/// x86, `compat_statfs64`, happens to share this exact field layout (same
/// fields, same order, same 84-byte packed size) — which is why `.x86` maps
/// here rather than to `NaturalGeneric32`, but the mapping is deliberately
/// modelling the compat-layer case (32-bit process, 64-bit kernel), not a
/// native 32-bit x86 kernel. See SPEC.md's "x86 compat-layer assumption"
/// note for why that is taken as the realistic `.x86` deployment (native
/// 32-bit x86 kernels are essentially extinct) and for the `EINVAL` safety
/// net if the assumption is ever wrong for a given target.
///
/// `align(4)` on the `u64` fields below reproduces the packing — without it
/// Zig's default `extern struct` layout would insert the same trailing pad
/// `NaturalGeneric32` has, which is wrong for both ARM's native `statfs64`
/// and x86's `compat_statfs64`.
const PackedGeneric32 = extern struct {
    type: u32,
    bsize: u32,
    blocks: u64 align(4),
    bfree: u64 align(4),
    bavail: u64 align(4),
    files: u64 align(4),
    ffree: u64 align(4),
    fsid: Fsid,
    namelen: u32,
    frsize: u32,
    flags: u32,
    spare: [4]u32,
};
comptime {
    // 2*4 + 5*8 + 8 + 3*4 + 4*4 = 8+40+8+12+16 = 84, and the forced align(4)
    // means the struct's own alignment is 4, so 84 (already a multiple of 4)
    // needs no trailing pad.
    std.debug.assert(@sizeOf(PackedGeneric32) == 84);
    std.debug.assert(@alignOf(PackedGeneric32) == 4);
}

/// The same asm-generic `statfs64` layout as `PackedGeneric32`, but taken
/// *without* an `ARCH_PACK_STATFS64` override — i.e. what every 32-bit
/// architecture gets that does not ship its own `arch/*/include/uapi/asm/
/// statfs.h` (no override file exists for these in the kernel tree, so the
/// generic header's `#ifndef ARCH_PACK_STATFS64 #define ARCH_PACK_STATFS64
/// #endif` leaves it empty and natural C alignment applies): powerpc(32),
/// m68k, sparc(32), xtensa, riscv32, loongarch32, arc, csky, hexagon, or1k —
/// and, at the header level, a *native* i386 kernel's own `statfs64` too:
/// `arch/x86/include/uapi/asm/statfs.h` never defines `ARCH_PACK_STATFS64`
/// (only `ARCH_PACK_COMPAT_STATFS64`, for the different `compat_statfs64`
/// struct), so a native i386 kernel falls through to this same unpacked
/// default. `family`'s `switch` does not route `.x86` here — see
/// `PackedGeneric32`'s doc comment and SPEC.md for why the compat-layer case
/// is taken as the realistic `.x86` deployment instead.
/// The two leading `u32` fields already sum to 8 bytes, so there is no
/// *internal* padding gap either way — the only difference from
/// `PackedGeneric32` is 4 bytes of *trailing* padding, because an
/// 8-byte-aligned struct (forced by the `u64` fields) must have a size that
/// is a multiple of 8, and 84 is not.
///
/// UNVERIFIED beyond this static reading of the generic header: none of
/// these architectures has a live kernel to syscall against in this
/// collection's CI (x86_64 + arm64 only), and none has its own
/// `arch/*/include/uapi/asm/statfs.h` to double-check against either — by
/// construction, since that absence is exactly why they fall into this
/// bucket. `do_statfs64`'s `sz` check means a wrong guess here fails loudly
/// (`EINVAL`) rather than corrupting output, on whichever of these targets
/// someone eventually runs this against for real.
const NaturalGeneric32 = extern struct {
    type: u32,
    bsize: u32,
    blocks: u64 align(8),
    bfree: u64 align(8),
    bavail: u64 align(8),
    files: u64 align(8),
    ffree: u64 align(8),
    fsid: Fsid,
    namelen: u32,
    frsize: u32,
    flags: u32,
    spare: [4]u32,
};
comptime {
    std.debug.assert(@sizeOf(NaturalGeneric32) == 88); // 84 + 4 trailing pad
    std.debug.assert(@alignOf(NaturalGeneric32) == 8);
}

const Family = enum { native64, mips32, packed32, natural32 };

const family: Family = switch (builtin.cpu.arch) {
    .x86_64 => switch (builtin.abi) {
        // x32 (ILP32 pointers over the x86_64 syscall ABI) is neither
        // verified nor targeted by this collection — refuse rather than
        // guess at a struct layout nobody has checked.
        .gnux32, .muslx32 => @compileError("diskusage.statfs: x32 ABI statfs64 layout not verified — not a target of this collection"),
        else => .native64,
    },
    .aarch64,
    .aarch64_be,
    .riscv64,
    .loongarch64,
    .powerpc64,
    .powerpc64le,
    .s390x,
    .sparc64,
    => .native64,
    .mips64, .mips64el => switch (builtin.abi) {
        // Mirrors std.os.linux.SYS's own dispatch: n32 shares MIPS's 32-bit
        // ABI struct, everything else (n64) is native64.
        .gnuabin32, .muslabin32 => .mips32,
        else => .native64,
    },
    .mips, .mipsel => .mips32,
    .arm, .armeb, .thumb, .thumbeb => .packed32,
    // .x86 (i386): `.packed32` here is `compat_statfs64` (32-bit process
    // under an x86_64 kernel's compat syscall layer), NOT a native i386
    // kernel's own `statfs64` (which is unpacked — see NaturalGeneric32).
    // Stated explicitly because the two are different kernel structs that
    // happen to share this one's byte layout: this module assumes the
    // compat case is the realistic `.x86` deployment (native 32-bit x86
    // kernels are essentially extinct) — SPEC.md's "x86 compat-layer
    // assumption" note has the full reasoning and the EINVAL safety net.
    .x86 => .packed32,
    .powerpc,
    .powerpcle,
    .m68k,
    .sparc,
    .xtensa,
    .xtensaeb,
    .riscv32,
    .loongarch32,
    .arc,
    .arceb,
    .csky,
    .hexagon,
    .or1k,
    => .natural32,
    else => @compileError("diskusage.statfs: no statfs64 struct layout verified for this target architecture"),
};

fn toUsage(comptime T: type, raw: T) Usage {
    return switch (T) {
        Native64 => .{
            .block_size = raw.bsize,
            .fragment_size = raw.frsize,
            .blocks_total = raw.blocks,
            .blocks_free = raw.bfree,
            .blocks_available = raw.bavail,
            .inodes_total = raw.files,
            .inodes_free = raw.ffree,
            .fs_type_magic = @truncate(@as(u64, @bitCast(raw.type))),
            .name_max = raw.namelen,
        },
        MipsStatfs64 => .{
            .block_size = raw.bsize,
            .fragment_size = raw.frsize,
            .blocks_total = raw.blocks,
            .blocks_free = raw.bfree,
            .blocks_available = raw.bavail,
            .inodes_total = raw.files,
            .inodes_free = raw.ffree,
            .fs_type_magic = raw.type,
            .name_max = raw.namelen,
        },
        PackedGeneric32, NaturalGeneric32 => .{
            .block_size = raw.bsize,
            .fragment_size = raw.frsize,
            .blocks_total = raw.blocks,
            .blocks_free = raw.bfree,
            .blocks_available = raw.bavail,
            .inodes_total = raw.files,
            .inodes_free = raw.ffree,
            .fs_type_magic = raw.type,
            .name_max = raw.namelen,
        },
        else => @compileError("unreachable statfs struct family"),
    };
}

fn mapErrno(err: std.os.linux.E) StatfsError {
    return switch (err) {
        .NOENT => error.FileNotFound,
        .ACCES, .PERM => error.AccessDenied,
        .NOTDIR => error.NotDir,
        .NAMETOOLONG => error.NameTooLong,
        .LOOP => error.TooManySymlinks,
        .IO => error.IoError,
        else => error.Unexpected,
    };
}

/// `statfs(2)` on `path`. Follows symlinks (kernel default); the path must
/// name an existing file or directory anywhere on the target filesystem, not
/// necessarily its mount point.
pub fn query(path: []const u8) StatfsError!Usage {
    const path_z = std.posix.toPosixPath(path) catch return error.NameTooLong;
    switch (family) {
        .native64 => {
            var raw: Native64 = std.mem.zeroes(Native64);
            const rc = linux.syscall2(.statfs, @intFromPtr(&path_z), @intFromPtr(&raw));
            if (linux.errno(rc) != .SUCCESS) return mapErrno(linux.errno(rc));
            return toUsage(Native64, raw);
        },
        .mips32 => {
            var raw: MipsStatfs64 = std.mem.zeroes(MipsStatfs64);
            const rc = linux.syscall3(.statfs64, @intFromPtr(&path_z), @sizeOf(MipsStatfs64), @intFromPtr(&raw));
            if (linux.errno(rc) != .SUCCESS) return mapErrno(linux.errno(rc));
            return toUsage(MipsStatfs64, raw);
        },
        .packed32 => {
            var raw: PackedGeneric32 = std.mem.zeroes(PackedGeneric32);
            const rc = linux.syscall3(.statfs64, @intFromPtr(&path_z), @sizeOf(PackedGeneric32), @intFromPtr(&raw));
            if (linux.errno(rc) != .SUCCESS) return mapErrno(linux.errno(rc));
            return toUsage(PackedGeneric32, raw);
        },
        .natural32 => {
            var raw: NaturalGeneric32 = std.mem.zeroes(NaturalGeneric32);
            const rc = linux.syscall3(.statfs64, @intFromPtr(&path_z), @sizeOf(NaturalGeneric32), @intFromPtr(&raw));
            if (linux.errno(rc) != .SUCCESS) return mapErrno(linux.errno(rc));
            return toUsage(NaturalGeneric32, raw);
        },
    }
}

const testing = std.testing;

test "query: root filesystem gives internally consistent numbers" {
    // No machine-specific constants — `/` exists on every host this test
    // runs on, but its size/fstype does not. Assert relationships that must
    // hold for ANY real filesystem instead.
    const u = try query("/");
    try testing.expect(u.blocks_total > 0);
    try testing.expect(u.block_size > 0);
    // available <= free <= total is the invariant the task description
    // calls out explicitly: f_bavail (unprivileged) <= f_bfree (raw free)
    // <= f_blocks (total), never the reverse.
    try testing.expect(u.blocks_available <= u.blocks_free);
    try testing.expect(u.blocks_free <= u.blocks_total);
    try testing.expect(u.availableBytes() <= u.freeBytes());
    try testing.expect(u.freeBytes() <= u.totalBytes());
    // name_max is meaningless as an absolute bound across filesystems, but
    // every real one reports a positive value.
    try testing.expect(u.name_max > 0);
}

test "query: missing path returns FileNotFound, not a garbage Usage" {
    try testing.expectError(error.FileNotFound, query("/this/path/does/not/exist/diskusage-test"));
}

test "totalBytes/freeBytes/availableBytes: saturate rather than wrap on a corrupt block_size" {
    const u = Usage{
        .block_size = -1, // hostile/corrupt report — never a real value
        .fragment_size = 0,
        .blocks_total = std.math.maxInt(u64),
        .blocks_free = std.math.maxInt(u64),
        .blocks_available = std.math.maxInt(u64),
        .inodes_total = 0,
        .inodes_free = 0,
        .fs_type_magic = 0,
        .name_max = 0,
    };
    try testing.expectEqual(@as(u64, 0), u.totalBytes());
    try testing.expectEqual(@as(u64, 0), u.freeBytes());
    try testing.expectEqual(@as(u64, 0), u.availableBytes());
}

test "totalBytes: normal values multiply without saturating" {
    const u = Usage{
        .block_size = 4096,
        .fragment_size = 4096,
        .blocks_total = 1000,
        .blocks_free = 500,
        .blocks_available = 400,
        .inodes_total = 100,
        .inodes_free = 50,
        .fs_type_magic = 0xEF53,
        .name_max = 255,
    };
    try testing.expectEqual(@as(u64, 4096 * 1000), u.totalBytes());
    try testing.expectEqual(@as(u64, 4096 * 500), u.freeBytes());
    try testing.expectEqual(@as(u64, 4096 * 400), u.availableBytes());
}
