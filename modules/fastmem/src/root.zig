// SPDX-License-Identifier: MIT

//! fastmem — a vectorised `memset` and `memcpy` for binaries that link no libc.
//!
//! (The history below is `memset`'s, on Zig 0.16. `memcpy` came on 0.17,
//! where compiler_rt's copies one element at a time with no string move:
//! 1.2–2.3× glibc's, and 58 % of a 64 KiB websocket frame read.)
//!
//! Without libc, every `@memset` whose length is not known at compile time,
//! and every `std.crypto.secureZero`, ends in compiler_rt's `memset`, which in
//! Zig 0.16 stores **one byte per iteration**: measured 3.2 GB/s on an
//! i7-7920HQ, against 65–96 GB/s for compiler_rt's own `memcpy` on the same
//! core (qap audit, 2026-09-28). A 4 KiB clear costs ~1.25 µs where it should
//! cost ~50 ns, and the callers are not only ours: std's deflate clears a
//! 64 KiB hash table per gzip response, TLS libraries scrub record buffers
//! per handshake.
//!
//! compiler_rt exports `memset` with **weak** linkage, so a strong definition
//! anywhere in the binary replaces it for every caller, std included. That is
//! what `exportSymbols` does — and why nothing happens unless the executable
//! asks for it:
//!
//! ```zig
//! const fastmem = @import("fastmem");
//! comptime {
//!     fastmem.exportSymbols(); // in the executable's root file
//! }
//! ```
//!
//! Replacing a symbol for the whole binary is a decision for whoever owns the
//! binary, not for a library it imports, so a library must never call it on
//! its callers' behalf. With libc linked it is a compile error: the strong
//! symbol would interpose libc's own `memset`, which is already vectorised
//! and tuned per CPU, and replace it with this one.
//!
//! `set` and `copy` are the same code without the export, for a caller that
//! wants the speed at one site and nothing global.
//!
//! ## Why the stores are volatile
//!
//! This is a `memset`. LLVM recognises a store loop as the memset idiom (and a
//! load/store loop as the memcpy one) and turns it into a call to `memset` —
//! which, once this function IS `memset`, is itself: infinite recursion. Volatile stores are never recognised, and
//! cost nothing here, because every store is one full vector the loop was
//! going to issue anyway.

const std = @import("std");
const builtin = @import("builtin");

pub const meta = .{
    .doc = "Vectorised memset and memcpy (32-byte vectors, overlapping head/tail; rep stosq past L2 / rep movsb from 16 KiB on x86-64) that an executable without libc can export to replace compiler_rt's for every caller, std included; opt-in.",
    .platform_note = "any (portable @Vector code, plus rep-stosq / rep-movsb paths for large lengths on x86-64; the export refuses libc-linked builds)",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util,
    .concurrency = .reentrant,
    .model_after = "musl / Go runtime memclr: vector stores with overlapping unaligned ends",
    .deps = .{},
};

// ── public API ──────────────────────────────────────────────────────────────

/// Store `c` into `dest[0..len]`.
pub fn set(dest: [*]u8, c: u8, len: usize) void {
    if (len < 32) return setSmall(dest, c, len);
    const v: V = @splat(c);
    // Up to 8 vectors: the first k and the last k, overlapping in the middle,
    // no loop and no alignment arithmetic.
    inline for (.{ 1, 2, 4 }) |k| {
        if (len <= 2 * k * 32) {
            inline for (0..k) |j| {
                store(V, dest + 32 * j, v);
                store(V, dest + len - 32 * (k - j), v);
            }
            return;
        }
    }
    if (use_stos and len >= stos_min) return setLarge(dest, c, len);
    // Unaligned first and last vectors, overlapping the aligned middle; the
    // middle then starts at the first aligned address after `dest`.
    store(V, dest, v);
    store(V, dest + len - 32, v);
    const start = @intFromPtr(dest);
    const first = std.mem.alignForward(usize, start + 1, 32);
    const end = start + len - 32; // the tail store covers from here
    // Four stores per iteration: 37 against 44 ns for a 4 KiB clear with one
    // (disposable probe, 2026-10-26), level from 16 KiB up.
    var p = first;
    while (p + 128 <= end) : (p += 128) {
        storeAligned(@ptrFromInt(p), v);
        storeAligned(@ptrFromInt(p + 32), v);
        storeAligned(@ptrFromInt(p + 64), v);
        storeAligned(@ptrFromInt(p + 96), v);
    }
    while (p < end) : (p += 32) storeAligned(@ptrFromInt(p), v);
}

/// The C `memset`, over `set`.
pub fn memset(dest: ?[*]u8, c: c_int, len: usize) callconv(.c) ?[*]u8 {
    if (len != 0) set(dest.?, @truncate(@as(c_uint, @bitCast(c))), len);
    return dest;
}

/// Copy `src[0..len]` to `dest[0..len]`; the ranges must not overlap.
pub fn copy(noalias dest: [*]u8, noalias src: [*]const u8, len: usize) void {
    if (len < 32) return copySmall(dest, src, len);
    // Up to 8 vectors: the first k and the last k, overlapping in the middle,
    // no loop and no alignment arithmetic.
    inline for (.{ 1, 2, 4 }) |k| {
        if (len <= 2 * k * 32) {
            var v: [2 * k]V = undefined;
            inline for (0..k) |j| {
                v[j] = load(V, src + 32 * j);
                v[k + j] = load(V, src + len - 32 * (k - j));
            }
            inline for (0..k) |j| {
                store(V, dest + 32 * j, v[j]);
                store(V, dest + len - 32 * (k - j), v[k + j]);
            }
            return;
        }
    }
    if (use_movs and len >= movs_min) return copyLarge(dest, src, len);
    // Unaligned first and last vectors, loaded before anything is stored, and
    // 32-aligned destination stores in between, four per iteration.
    const head = load(V, src);
    const tail = load(V, src + len - 32);
    const end = len - 32; // the tail store covers from here
    var i: usize = 32 - (@intFromPtr(dest) & 31);
    while (i + 128 <= end) : (i += 128) {
        const a = load(V, src + i);
        const b = load(V, src + i + 32);
        const c = load(V, src + i + 64);
        const d = load(V, src + i + 96);
        storeAligned(dest + i, a);
        storeAligned(dest + i + 32, b);
        storeAligned(dest + i + 64, c);
        storeAligned(dest + i + 96, d);
    }
    while (i < end) : (i += 32) storeAligned(dest + i, load(V, src + i));
    store(V, dest, head);
    store(V, dest + end, tail);
}

/// The C `memcpy`, over `copy`.
pub fn memcpy(noalias dest: ?[*]u8, noalias src: ?[*]const u8, len: usize) callconv(.c) ?[*]u8 {
    if (len != 0) copy(dest.?, src.?, len);
    return dest;
}

/// Export `memset` and `memcpy` as strong symbols, replacing compiler_rt's
/// weak ones for the whole binary. Call it from a `comptime` block in the
/// EXECUTABLE's root file — never from a library (see the module doc).
pub fn exportSymbols() void {
    if (builtin.link_libc) @compileError("fastmem.exportSymbols: this build links libc, whose memset and memcpy are already vectorised; exporting would interpose them");
    @export(&memset, .{ .name = "memset", .linkage = .strong });
    @export(&memcpy, .{ .name = "memcpy", .linkage = .strong });
}

// ── implementation ──────────────────────────────────────────────────────────

const V = @Vector(32, u8);

/// Above this length the middle is stored by `rep stosq` instead of the
/// vector loop. Measured 2026-10-11 on an i7-7920HQ (256 KiB L2): the string
/// store is 0.95-1.07x the loop from 4 KiB to 192 KiB and 0.75-0.84x from
/// 256 KiB up, where the buffer leaves L2 and the loop's stores each pay a
/// read-for-ownership the fast-string protocol skips.
const stos_min = 192 * 1024;

// Not under the C backend: it would have to spell the register constraints
// in C, and nothing there is measured.
const use_stos = builtin.cpu.arch == .x86_64 and builtin.zig_backend != .stage2_c;

/// `set` for `len >= stos_min` on x86-64: the same unaligned head and tail
/// vectors, and the 32-aligned middle by `rep stosq`. The last qword ends at
/// most 7 bytes past the tail vector's start, which it covers anyway, so
/// nothing outside `[dest, dest + len)` is written. `noinline` and reached by
/// a tail call, so `set` itself stays a leaf with no frame: measured
/// 2026-10-11, a call inside it cost the 256 B and 4 KiB rows 15-40 %.
noinline fn setLarge(dest: [*]u8, c: u8, len: usize) void {
    const v: V = @splat(c);
    store(V, dest, v);
    store(V, dest + len - 32, v);
    const start = @intFromPtr(dest);
    const first = std.mem.alignForward(usize, start + 1, 32);
    var d: [*]u8 = @ptrFromInt(first);
    var n: usize = (start + len - 32 - first + 7) / 8;
    const q: u64 = @as(u64, c) * 0x0101010101010101;
    asm volatile ("rep stosq"
        : [d] "+{rdi}" (d),
          [n] "+{rcx}" (n),
        : [q] "{rax}" (q),
        : .{ .memory = true });
}

inline fn store(comptime T: type, p: [*]u8, v: T) void {
    const w: *align(1) volatile T = @ptrCast(p);
    w.* = v;
}

inline fn storeAligned(p: [*]u8, v: V) void {
    const w: *volatile V = @ptrCast(@alignCast(p));
    w.* = v;
}

inline fn load(comptime T: type, p: [*]const u8) T {
    const r: *align(1) const T = @ptrCast(p);
    return r.*;
}

/// From this length up `copy` moves the middle by `rep movsb` instead of the
/// vector loop. Measured 2026-10-26 on an i7-7920HQ (ERMS, no FSRM;
/// disposable probe, destination offsets 0/5/37, source 3× that): at 8 KiB the
/// loop is 0.60-0.88× the string move, at 16 KiB the string move is 0.79-0.88×
/// the loop and stays level with or ahead of it up to 2 MiB (0.75-0.95× from
/// 256 KiB, where the loop's stores pay a read-for-ownership per line).
const movs_min = 16 * 1024;

const use_movs = use_stos;

/// `copy` for `len >= movs_min` on x86-64: two unaligned vectors for the
/// first 64 bytes, `rep movsb` from the first 64-aligned destination address
/// after `dest` up to the tail vector, and the tail vector. Aligning the
/// destination is what makes the string move fast at every source offset
/// (unaligned, it was 1.5× slower at 16 KiB). `noinline` and reached by a tail
/// call, for the same reason as `setLarge`.
noinline fn copyLarge(noalias dest: [*]u8, noalias src: [*]const u8, len: usize) void {
    const h0 = load(V, src);
    const h1 = load(V, src + 32);
    const tail = load(V, src + len - 32);
    const skew = 64 - (@intFromPtr(dest) & 63);
    var d = dest + skew;
    var s = src + skew;
    var n = len - 32 - skew;
    asm volatile ("rep movsb"
        : [d] "+{rdi}" (d),
          [s] "+{rsi}" (s),
          [n] "+{rcx}" (n),
        :
        : .{ .memory = true });
    store(V, dest, h0);
    store(V, dest + 32, h1);
    store(V, dest + len - 32, tail);
}

/// Below one vector: the first and the last word of the widest width that
/// fits, both loaded before either is stored.
fn copySmall(d: [*]u8, s: [*]const u8, n: usize) void {
    inline for (.{ @Vector(16, u8), u64, u32, u16 }) |T| {
        if (n >= @sizeOf(T)) {
            const a = load(T, s);
            const b = load(T, s + n - @sizeOf(T));
            store(T, d, a);
            store(T, d + n - @sizeOf(T), b);
            return;
        }
    }
    if (n == 1) store(u8, d, s[0]);
}

/// Below one vector: two overlapping stores of the largest width that fits,
/// so every length is two stores (or one byte).
fn setSmall(d: [*]u8, c: u8, n: usize) void {
    if (n >= 16) {
        const v: @Vector(16, u8) = @splat(c);
        store(@Vector(16, u8), d, v);
        store(@Vector(16, u8), d + n - 16, v);
    } else if (n >= 8) {
        const v: u64 = @as(u64, c) * 0x0101010101010101;
        store(u64, d, v);
        store(u64, d + n - 8, v);
    } else if (n >= 4) {
        const v: u32 = @as(u32, c) * 0x01010101;
        store(u32, d, v);
        store(u32, d + n - 4, v);
    } else if (n >= 2) {
        const v: u16 = @as(u16, c) * 0x0101;
        store(u16, d, v);
        store(u16, d + n - 2, v);
    } else if (n == 1) {
        store(u8, d, c);
    }
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "set: every length 0..300 at every offset 0..63 writes exactly its range" {
    var canvas: [512]u8 align(64) = undefined;
    for ([_]u8{ 0x00, 0xA5, 0xFF }) |c| {
        for (0..64) |off| {
            for (0..301) |len| {
                for (&canvas, 0..) |*b, i| b.* = @truncate(i *% 7 +% 1);
                set(canvas[off..].ptr, c, len);
                for (canvas, 0..) |b, i| {
                    const want: u8 = if (i >= off and i < off + len) c else @truncate(i *% 7 +% 1);
                    if (b != want) {
                        std.debug.print("c={x} off={d} len={d} i={d}: got {x}, want {x}\n", .{ c, off, len, i, b, want });
                        return error.TestUnexpectedResult;
                    }
                }
            }
        }
    }
}

test "set: large lengths across page-sized buffers" {
    const buf = try testing.allocator.alloc(u8, 3 * 4096 + 64);
    defer testing.allocator.free(buf);
    for ([_]usize{ 4095, 4096, 4097, 8191, 12289 }) |len| {
        for ([_]usize{ 0, 1, 31, 33 }) |off| {
            for (buf) |*b| b.* = 0x11;
            set(buf[off..].ptr, 0xEE, len);
            for (buf, 0..) |b, i| {
                const inside = i >= off and i < off + len;
                try testing.expectEqual(@as(u8, if (inside) 0xEE else 0x11), b);
            }
        }
    }
}

test "set: the rep-stosq path writes exactly its range" {
    // Lengths at and around `stos_min`, at offsets that put `first` at every
    // distance from `end` mod 8 -- the qword count's rounding is the edge.
    const buf = try testing.allocator.alignedAlloc(u8, .@"64", stos_min + 4096);
    defer testing.allocator.free(buf);
    for ([_]usize{ stos_min - 1, stos_min, stos_min + 1, stos_min + 7, stos_min + 33, stos_min + 2000 }) |len| {
        for ([_]usize{ 0, 1, 5, 8, 31, 32, 63 }) |off| {
            for (buf, 0..) |*b, i| b.* = @truncate(i *% 13 +% 3);
            set(buf[off..].ptr, 0x5A, len);
            for (buf, 0..) |b, i| {
                const want: u8 = if (i >= off and i < off + len) 0x5A else @truncate(i *% 13 +% 3);
                if (b != want) {
                    std.debug.print("off={d} len={d} i={d}: got {x}, want {x}\n", .{ off, len, i, b, want });
                    return error.TestUnexpectedResult;
                }
            }
        }
    }
}

/// Copy `len` bytes between two fresh canvases at the given offsets and check
/// every byte of the destination canvas: the range equals the source, the
/// rest is untouched, and the source is unchanged.
fn expectCopy(dst: []u8, src: []u8, d_off: usize, s_off: usize, len: usize) !void {
    for (src, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);
    for (dst, 0..) |*b, i| b.* = @truncate(i *% 13 +% 3);
    copy(dst[d_off..].ptr, src[s_off..].ptr, len);
    for (dst, 0..) |b, i| {
        const want: u8 = if (i >= d_off and i < d_off + len) src[i - d_off + s_off] else @truncate(i *% 13 +% 3);
        if (b != want) {
            std.debug.print("d_off={d} s_off={d} len={d} i={d}: got {x}, want {x}\n", .{ d_off, s_off, len, i, b, want });
            return error.TestUnexpectedResult;
        }
    }
    for (src, 0..) |b, i| try testing.expectEqual(@as(u8, @truncate(i *% 31 +% 7)), b);
}

test "copy: every length 0..300 at every destination offset 0..63 writes exactly its range" {
    var dst: [512]u8 align(64) = undefined;
    var src: [512]u8 align(64) = undefined;
    for ([_]usize{ 0, 1, 5, 17, 32, 63 }) |s_off| {
        for (0..64) |d_off| {
            for (0..301) |len| try expectCopy(&dst, &src, d_off, s_off, len);
        }
    }
}

test "copy: page-scale lengths, the unrolled vector loop and its remainder" {
    const dst = try testing.allocator.alignedAlloc(u8, .@"64", 3 * 4096 + 128);
    defer testing.allocator.free(dst);
    const src = try testing.allocator.alignedAlloc(u8, .@"64", 3 * 4096 + 128);
    defer testing.allocator.free(src);
    for ([_]usize{ 4095, 4096, 4097, 4127, 4159, 8191, 12289 }) |len| {
        for ([_]usize{ 0, 1, 31, 33 }) |d_off| {
            for ([_]usize{ 0, 7, 64 }) |s_off| try expectCopy(dst, src, d_off, s_off, len);
        }
    }
}

test "copy: the rep-movsb path writes exactly its range" {
    // Lengths at and around `movs_min` and well past it, at destination
    // offsets that put the 64-byte skew at both ends of its range (1 and 64).
    const dst = try testing.allocator.alignedAlloc(u8, .@"64", 3 * movs_min + 256);
    defer testing.allocator.free(dst);
    const src = try testing.allocator.alignedAlloc(u8, .@"64", 3 * movs_min + 256);
    defer testing.allocator.free(src);
    for ([_]usize{ movs_min - 1, movs_min, movs_min + 1, movs_min + 63, movs_min + 2000, 3 * movs_min }) |len| {
        for ([_]usize{ 0, 1, 5, 32, 63, 64 }) |d_off| {
            for ([_]usize{ 0, 3, 70 }) |s_off| try expectCopy(dst, src, d_off, s_off, len);
        }
    }
}

test "memcpy: C semantics -- returns dest, len 0 accepts null and touches nothing" {
    var a: [40]u8 = @splat(1);
    const b: [40]u8 = @splat(2);
    try testing.expectEqual(@as(?[*]u8, &a), memcpy(&a, &b, 40));
    for (a) |x| try testing.expectEqual(@as(u8, 2), x);
    try testing.expectEqual(@as(?[*]u8, null), memcpy(null, null, 0));
}

test "memset: C semantics -- returns dest, takes the low byte of c, len 0 touches nothing" {
    var a: [40]u8 = @splat(1);
    try testing.expectEqual(@as(?[*]u8, &a), memset(&a, 0x1FF, 40)); // low byte 0xFF
    for (a) |b| try testing.expectEqual(@as(u8, 0xFF), b);
    try testing.expectEqual(@as(?[*]u8, &a), memset(&a, 0, 0));
    for (a) |b| try testing.expectEqual(@as(u8, 0xFF), b);
}

test "memset: len 0 accepts a null dest and dereferences nothing" {
    // C callers (and LLVM-emitted calls on empty slices) may pass a null or
    // dangling pointer with length 0; only a non-zero length may touch `dest`.
    try testing.expectEqual(@as(?[*]u8, null), memset(null, 0xAB, 0));
}

test "the export took effect: the linked `memset` is this module's" {
    if (builtin.link_libc) return error.SkipZigTest;
    // Exported HERE rather than from a file-level `comptime` block: the export
    // is global either way (every `@memset` in the test binary, std's runner and
    // allocator included, then runs through `set`), but a file-level block also
    // fires in any build that merely imports this file under `zig test` --
    // `check-pubfn-reach` does, and analysing `exportSymbols`' body there is a
    // second `@export` of the same name: "exported symbol collision"
    // (CI run 36443590540, 2026-09-28).
    comptime exportSymbols();
    const linked = @extern(*const fn (?[*]u8, c_int, usize) callconv(.c) ?[*]u8, .{ .name = "memset" });
    try testing.expectEqual(@intFromPtr(&memset), @intFromPtr(linked));
    const linked_cpy = @extern(*const fn (?[*]u8, ?[*]const u8, usize) callconv(.c) ?[*]u8, .{ .name = "memcpy" });
    try testing.expectEqual(@intFromPtr(&memcpy), @intFromPtr(linked_cpy));
    // And a runtime-length @memset / @memcpy goes through them with the right result.
    var buf: [100]u8 = @splat(3);
    var n: usize = 77;
    _ = &n;
    @memset(buf[5..][0..n], 9);
    for (buf, 0..) |b, i| try testing.expectEqual(@as(u8, if (i >= 5 and i < 82) 9 else 3), b);
    var dst: [100]u8 = @splat(1);
    @memcpy(dst[2..][0..n], buf[4..][0..n]);
    for (dst, 0..) |b, i| try testing.expectEqual(if (i >= 2 and i < 79) buf[i + 2] else 1, b);
}
