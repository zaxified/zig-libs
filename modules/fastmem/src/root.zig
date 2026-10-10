// SPDX-License-Identifier: MIT

//! fastmem — a vectorised `memset` for binaries that link no libc.
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
//! `set` is the same code without the export, for a caller that wants the
//! speed at one site and nothing global.
//!
//! ## Why the stores are volatile
//!
//! This is a `memset`. LLVM recognises a store loop as the memset idiom and
//! turns it into a call to `memset` — which, once this function IS `memset`,
//! is itself: infinite recursion. Volatile stores are never recognised, and
//! cost nothing here, because every store is one full vector the loop was
//! going to issue anyway.

const std = @import("std");
const builtin = @import("builtin");

pub const meta = .{
    .doc = "Vectorised memset (32-byte stores, overlapping head/tail; rep stosq past L2 on x86-64) that an executable without libc can export to replace compiler_rt's byte-at-a-time one for every caller, std included; opt-in.",
    .platform_note = "any (portable @Vector code, plus a rep-stosq path for large lengths on x86-64; the export refuses libc-linked builds)",
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
    if (use_stos and len >= stos_min) return setLarge(dest, c, len);
    const v: V = @splat(c);
    // Unaligned first and last vectors, overlapping the aligned middle; the
    // middle then starts at the first aligned address after `dest`.
    store(V, dest, v);
    store(V, dest + len - 32, v);
    const start = @intFromPtr(dest);
    const first = std.mem.alignForward(usize, start + 1, 32);
    const end = start + len - 32; // the tail store covers from here
    var p = first;
    while (p < end) : (p += 32) {
        const w: *volatile V = @ptrFromInt(p);
        w.* = v;
    }
}

/// The C `memset`, over `set`.
pub fn memset(dest: ?[*]u8, c: c_int, len: usize) callconv(.c) ?[*]u8 {
    if (len != 0) set(dest.?, @truncate(@as(c_uint, @bitCast(c))), len);
    return dest;
}

/// Export `memset` as a strong symbol, replacing compiler_rt's weak one for
/// the whole binary. Call it from a `comptime` block in the EXECUTABLE's root
/// file — never from a library (see the module doc).
pub fn exportSymbols() void {
    if (builtin.link_libc) @compileError("fastmem.exportSymbols: this build links libc, whose memset is already vectorised; exporting would interpose it");
    @export(&memset, .{ .name = "memset", .linkage = .strong });
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
    // And a runtime-length @memset goes through it with the right result.
    var buf: [100]u8 = @splat(3);
    var n: usize = 77;
    _ = &n;
    @memset(buf[5..][0..n], 9);
    for (buf, 0..) |b, i| try testing.expectEqual(@as(u8, if (i >= 5 and i < 82) 9 else 3), b);
}
