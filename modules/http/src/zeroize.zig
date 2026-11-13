// SPDX-License-Identifier: MIT

//! This module's `secureZero`: zero memory that must not survive a `free`
//! in ReleaseFast (request bodies, header blocks, credentials) without
//! paying for `std.crypto.secureZero`'s byte-at-a-time store.
//!
//! `std.crypto.secureZero(T, s)` is `@memset(s, zero)` over a `[]volatile
//! T` (`lib/std/crypto.zig`). `@memset` cannot lower a volatile destination
//! to the ordinary `memset` intrinsic -- doing so would let the optimizer
//! treat the write as droppable or reorderable, which is exactly what
//! `volatile` forbids -- so every build, including ReleaseFast, emits a
//! scalar loop that stores one `T` at a time. Measured (qap perf audit
//! 2026-09-21, finding F1): zeroing 4096 B this way costs 5657
//! instructions, 2048 B costs 2841. `h2_server.zig`'s per-stream
//! `body_scratch` zeroing (added in 60a08442) runs on *every* h2 stream,
//! GET included, and regressed a downstream server's h2 GET path by +13%
//! total instructions (+35% of the user-space part) for a request that has
//! no body to protect.
//!
//! `zeroize` instead does volatile stores of 32-byte vectors over the
//! aligned middle of the buffer, falling back to volatile byte stores only
//! for the unaligned head (up to 31 bytes) and tail (up to 31 bytes).
//! Measured: 169 instructions for the same 4096 B -- each store instruction
//! now moves 32 bytes instead of 1, and there are proportionally fewer of
//! them, but every one is still volatile: nothing here can be folded into a
//! call to the byte-at-a-time `compiler_rt.memset`, and nothing can be
//! dropped as dead because the buffer is never read again.
//!
//! Every `std.crypto.secureZero` call in `modules/http/src/` should be
//! `zeroize` instead; this is the module's only sanctioned way to scrub a
//! buffer before it goes back to an allocator.
const std = @import("std");
const testing = std.testing;

/// `list.appendSlice(gpa, bytes)` that never hands a block holding data back
/// to the allocator unzeroed: when `list` must grow, the new block is
/// allocated and filled first, then the old one is zeroed and freed. Plain
/// `appendSlice` may `realloc`, and a moving realloc frees the old block
/// with the request bytes still in it (mutation run wave 3, F2/F4).
pub fn appendSliceWiped(gpa: std.mem.Allocator, list: *std.ArrayList(u8), bytes: []const u8) std.mem.Allocator.Error!void {
    try ensureUnusedCapacityWiped(gpa, list, bytes.len);
    list.appendSliceAssumeCapacity(bytes);
}

/// `list.ensureUnusedCapacity(gpa, n)` that never hands a block holding data
/// back to the allocator unzeroed: a growth allocates the new block, copies,
/// then zeroes and frees the old one. On failure `list` is unchanged.
pub fn ensureUnusedCapacityWiped(gpa: std.mem.Allocator, list: *std.ArrayList(u8), n: usize) std.mem.Allocator.Error!void {
    if (list.unusedCapacitySlice().len >= n) return;
    const need = std.math.add(usize, list.items.len, n) catch return error.OutOfMemory;
    var new_cap: usize = @max(list.capacity, 64);
    while (new_cap < need) new_cap = std.math.mul(usize, new_cap, 2) catch need;
    const new_mem = try gpa.alloc(u8, new_cap);
    const len = list.items.len;
    @memcpy(new_mem[0..len], list.items);
    const old = list.allocatedSlice();
    zeroize(old);
    gpa.free(old);
    list.items = new_mem[0..len];
    list.capacity = new_cap;
}

/// `list.toOwnedSlice(gpa)` that never frees a block holding data unzeroed:
/// the unused tail is zeroed (it may hold bytes of an earlier, longer use), then
/// the block is shrunk in place when the allocator can, otherwise a block of exactly `items.len` is allocated,
/// filled, and the old one zeroed and freed. On failure `list` is unchanged;
/// on success it is empty.
pub fn toOwnedSliceWiped(gpa: std.mem.Allocator, list: *std.ArrayList(u8)) std.mem.Allocator.Error![]u8 {
    const old = list.allocatedSlice();
    const len = list.items.len;
    if (len == old.len) {
        list.* = .empty;
        return old;
    }
    if (len != 0) zeroize(old[len..]);
    if (len != 0 and gpa.resize(old, len)) {
        list.* = .empty;
        return old.ptr[0..len];
    }
    const out: []u8 = if (len == 0) &.{} else try gpa.alloc(u8, len);
    @memcpy(out, list.items);
    zeroize(old);
    gpa.free(old);
    list.* = .empty;
    return out;
}

/// Zero every byte of `buf` in place. Handles `buf.len == 0`, lengths
/// below 32, and any starting alignment -- `buf.ptr` need not be aligned
/// to anything in particular.
pub fn zeroize(buf: []u8) void {
    const Vec32 = @Vector(32, u8);
    const zero_vec: Vec32 = @splat(0);

    // Bytes needed to bring `buf.ptr + i` up to a 32-byte-aligned address,
    // clamped to `buf.len` -- a short buffer never reaches alignment and
    // is handled entirely by the tail loop below.
    const addr = @intFromPtr(buf.ptr);
    const head_len = @min(buf.len, std.mem.alignForward(usize, addr, 32) - addr);

    var i: usize = 0;
    while (i < head_len) : (i += 1) {
        const p: *volatile u8 = &buf[i];
        p.* = 0;
    }
    while (i + 32 <= buf.len) : (i += 32) {
        const p: *volatile Vec32 = @ptrCast(@alignCast(buf[i..][0..32].ptr));
        p.* = zero_vec;
    }
    while (i < buf.len) : (i += 1) {
        const p: *volatile u8 = &buf[i];
        p.* = 0;
    }
}

fn expectAllZero(buf: []const u8) !void {
    for (buf, 0..) |b, idx| {
        if (b != 0) {
            std.debug.print("byte {d} of {d} was 0x{x}, not zero\n", .{ idx, buf.len, b });
            return error.TestExpectedZero;
        }
    }
}

test "zeroize: every byte is zero for lengths 0..100" {
    var len: usize = 0;
    while (len <= 100) : (len += 1) {
        var buf: [100]u8 = undefined;
        for (buf[0..len], 0..) |*b, idx| b.* = @truncate(0xaa +% idx);
        zeroize(buf[0..len]);
        try expectAllZero(buf[0..len]);
    }
}

test "zeroize: large buffers (2048, 4096, 65536 bytes)" {
    const sizes = [_]usize{ 2048, 4096, 65536 };
    for (sizes) |size| {
        const buf = try testing.allocator.alloc(u8, size);
        defer testing.allocator.free(buf);
        @memset(buf, 0xff);
        zeroize(buf);
        try expectAllZero(buf);
    }
}

test "zeroize: misaligned starts, offsets 0..33 into a bigger buffer" {
    // A slice starting at an arbitrary byte offset into a larger
    // allocation -- `buf.ptr` is then not necessarily aligned to
    // anything, which is the case this helper's head loop exists for.
    var big: [4096]u8 = undefined;
    var offset: usize = 0;
    while (offset <= 33) : (offset += 1) {
        @memset(&big, 0x5a);
        const slice = big[offset..];
        for (slice, 0..) |*b, idx| b.* = @truncate(0x5a +% idx);
        zeroize(slice);
        try expectAllZero(slice);
        // Bytes before the offset are untouched.
        for (big[0..offset]) |b| try testing.expectEqual(@as(u8, 0x5a), b);
    }
}

test "zeroize: len 0 is a no-op, not a crash" {
    var buf: [1]u8 = .{0x42};
    zeroize(buf[0..0]);
    try testing.expectEqual(@as(u8, 0x42), buf[0]);
}

test "zeroize: single byte and sub-vector lengths at various misalignments" {
    var big: [64]u8 = undefined;
    var offset: usize = 0;
    while (offset < 32) : (offset += 1) {
        var len: usize = 1;
        while (len <= 31) : (len += 1) {
            if (offset + len > big.len) break;
            @memset(&big, 0x77);
            const slice = big[offset..][0..len];
            zeroize(slice);
            try expectAllZero(slice);
        }
    }
}

test "appendSliceWiped: grows like appendSlice and keeps the bytes in order" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    var expect: std.ArrayList(u8) = .empty;
    defer expect.deinit(gpa);
    var i: usize = 0;
    while (i < 300) : (i += 1) {
        const piece = [_]u8{ @truncate(i), @truncate(i *% 7), @truncate(i *% 13) };
        try appendSliceWiped(gpa, &list, piece[0 .. i % 3 + 1]);
        try expect.appendSlice(gpa, piece[0 .. i % 3 + 1]);
    }
    try testing.expectEqualSlices(u8, expect.items, list.items);
    try appendSliceWiped(gpa, &list, &.{});
    try testing.expectEqual(expect.items.len, list.items.len);
}

test "ensureUnusedCapacityWiped / toOwnedSliceWiped: contents survive, capacity is exact" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    try appendSliceWiped(gpa, &list, "hello");
    try ensureUnusedCapacityWiped(gpa, &list, 1000);
    try testing.expect(list.unusedCapacitySlice().len >= 1000);
    try testing.expectEqualStrings("hello", list.items);
    const owned = try toOwnedSliceWiped(gpa, &list);
    defer gpa.free(owned);
    try testing.expectEqualStrings("hello", owned);
    try testing.expectEqual(@as(usize, 0), list.capacity);
    var empty: std.ArrayList(u8) = .empty;
    try ensureUnusedCapacityWiped(gpa, &empty, 10);
    const none = try toOwnedSliceWiped(gpa, &empty);
    try testing.expectEqual(@as(usize, 0), none.len);
}

/// Counts frees of blocks that still hold `marker`; `can_resize` says whether
/// `resize` (an in-place shrink) succeeds. Never remaps, so a move shows up as
/// alloc + free. Meaningful in ReleaseFast only: a safe build's `free`
/// poisons the block itself, hiding a missing wipe.
pub const ScrubAlloc = struct {
    marker: []const u8,
    can_resize: bool,
    dirty_frees: usize = 0,
    /// The nth `alloc` call (1-based) fails; 0 = never.
    fail_alloc_at: usize = 0,
    allocs: usize = 0,

    pub fn allocator(w: *ScrubAlloc) std.mem.Allocator {
        return .{ .ptr = w, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(ctx: *anyopaque, len: usize, a: std.mem.Alignment, ra: usize) ?[*]u8 {
        const w: *ScrubAlloc = @ptrCast(@alignCast(ctx));
        w.allocs += 1;
        if (w.allocs == w.fail_alloc_at) return null;
        return testing.allocator.rawAlloc(len, a, ra);
    }
    fn resize(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, n: usize, ra: usize) bool {
        const w: *ScrubAlloc = @ptrCast(@alignCast(ctx));
        if (!w.can_resize) return false;
        return testing.allocator.rawResize(m, a, n, ra);
    }
    fn remap(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
        return null;
    }
    fn free(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, ra: usize) void {
        const w: *ScrubAlloc = @ptrCast(@alignCast(ctx));
        if (std.mem.find(u8, m, w.marker) != null) w.dirty_frees += 1;
        testing.allocator.rawFree(m, a, ra);
    }
};

test "ensureUnusedCapacityWiped: the block a growth frees holds no data" {
    var w: ScrubAlloc = .{ .marker = "SECRET-MARKER-1", .can_resize = false };
    const gpa = w.allocator();
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try appendSliceWiped(gpa, &list, w.marker);
    try ensureUnusedCapacityWiped(gpa, &list, 4096); // moves
    try testing.expectEqualStrings(w.marker, list.items);
    try testing.expectEqual(@as(usize, 0), w.dirty_frees);
}

test "toOwnedSliceWiped: a shrink that moves frees a clean block" {
    var w: ScrubAlloc = .{ .marker = "SECRET-MARKER-2", .can_resize = false };
    const gpa = w.allocator();
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    try appendSliceWiped(gpa, &list, w.marker);
    const owned = try toOwnedSliceWiped(gpa, &list);
    defer gpa.free(owned);
    try testing.expectEqualStrings(w.marker, owned);
    try testing.expectEqual(@as(usize, 0), w.dirty_frees);
}

test "toOwnedSliceWiped: an in-place shrink zeroes the released tail" {
    const marker = "SECRET-MARKER-3";
    var buf: [128]u8 align(32) = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&buf);
    const gpa = fba.allocator();
    var list: std.ArrayList(u8) = try .initCapacity(gpa, 64);
    list.appendSliceAssumeCapacity(marker ++ marker ++ marker);
    list.shrinkRetainingCapacity(4); // the tail still holds the marker
    const base = list.items.ptr;
    const owned = try toOwnedSliceWiped(gpa, &list);
    try testing.expectEqual(base, owned.ptr); // shrunk in place, not moved
    try testing.expectEqual(@as(usize, 4), owned.len);
    try expectAllZero(buf[@intFromPtr(base) - @intFromPtr(&buf) + 4 ..][0..60]);
}

test "toOwnedSliceWiped: an empty result still zeroes the block it gives back" {
    // `Allocator.resize(block, 0)` frees the block: the shrink to nothing must
    // not be left to it.
    for ([_]bool{ false, true }) |can_resize| {
        var w: ScrubAlloc = .{ .marker = "SECRET-MARKER-4", .can_resize = can_resize };
        const gpa = w.allocator();
        var list: std.ArrayList(u8) = .empty;
        try appendSliceWiped(gpa, &list, w.marker);
        list.shrinkRetainingCapacity(0); // the block still holds the marker
        const owned = try toOwnedSliceWiped(gpa, &list);
        try testing.expectEqual(@as(usize, 0), owned.len);
        try testing.expectEqual(@as(usize, 0), w.dirty_frees);
    }
}
