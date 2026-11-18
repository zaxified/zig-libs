// SPDX-License-Identifier: MIT

//! wipealloc — an allocator adapter that zeroes every block before it goes back.
//!
//! `WipingAllocator` forwards `alloc` to its child and, on `free`, overwrites
//! the whole block with `std.crypto.secureZero` before handing it to the
//! child. `resize` and `remap` are refused, so a buffer never grows, shrinks
//! or moves without passing through `free`: `Allocator.realloc` then falls back
//! to alloc + copy + free, and the old block is wiped.
//!
//! Why refuse instead of forwarding: a shrink in place hands a tail back to
//! the child without a `free` (a page allocator unmaps it), and a moving
//! remap releases the old location the same way, so there is no hook left to
//! scrub it. Wiping a tail first would destroy data the caller still owns if
//! the child then refused.
//!
//! Which build mode this is for: `Allocator.free` memsets the block to
//! `undefined` before reaching the vtable, so in Debug and ReleaseSafe the
//! block is already scrubbed to `0xaa`. In ReleaseFast that memset compiles
//! away and this wipe is the only thing between a freed block and unrelated
//! code. Use it behind containers that hold secrets and grow (`ArrayList`,
//! `ArenaAllocator` chunks, a parser's tree).
//!
//! Not covered: stack copies, and memory the child never receives back
//! (a leak is a leak). The wipe is a volatile byte store loop (`secureZero`),
//! so it costs about one store per byte; an arena that holds no secrets does
//! not need it.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;

pub const meta = .{
    .doc = "Allocator adapter that zeroes every block before it is freed and refuses resize/remap, so a growing secret-holding buffer never leaves an unwiped copy in the child allocator.",
    .platform_note = "any (portable)",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util,
    .concurrency = .reentrant, // as thread-safe as the child allocator; the adapter holds no state of its own
    .model_after = "OpenSSL OPENSSL_clear_free / libsodium sodium_free: wipe on every give-back",
    .deps = .{},
};

pub const WipingAllocator = struct {
    child: Allocator,

    pub fn init(child: Allocator) WipingAllocator {
        return .{ .child = child };
    }

    /// The wiping allocator. The returned value points at `self`, which must
    /// outlive every block allocated through it and must not move.
    pub fn allocator(self: *WipingAllocator) Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Allocator.VTable = .{
        .alloc = alloc,
        .resize = resize,
        .remap = remap,
        .free = free,
    };

    fn alloc(ctx: *anyopaque, len: usize, alignment: Alignment, ret_addr: usize) ?[*]u8 {
        const self: *WipingAllocator = @ptrCast(@alignCast(ctx));
        return self.child.rawAlloc(len, alignment, ret_addr);
    }

    fn resize(_: *anyopaque, _: []u8, _: Alignment, _: usize, _: usize) bool {
        return false;
    }

    fn remap(_: *anyopaque, _: []u8, _: Alignment, _: usize, _: usize) ?[*]u8 {
        return null;
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: Alignment, ret_addr: usize) void {
        const self: *WipingAllocator = @ptrCast(@alignCast(ctx));
        std.crypto.secureZero(u8, memory);
        self.child.rawFree(memory, alignment, ret_addr);
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// The CHILD of the adapter under test: passes through to `child` and, on
/// `free`, records whether the block the adapter handed back was all zero.
/// (`Allocator.free` poisons the block with 0xaa in Debug/ReleaseSafe before the
/// adapter sees it, so zeros here prove the adapter's own wipe in every mode.)
const Spy = struct {
    child: Allocator,
    frees: usize = 0,
    zero_frees: usize = 0,
    last_len: usize = 0,

    fn allocator(self: *Spy) Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = sAlloc, .resize = sResize, .remap = sRemap, .free = sFree } };
    }
    fn sAlloc(ctx: *anyopaque, len: usize, a: Alignment, ra: usize) ?[*]u8 {
        const self: *Spy = @ptrCast(@alignCast(ctx));
        return self.child.rawAlloc(len, a, ra);
    }
    fn sResize(_: *anyopaque, _: []u8, _: Alignment, _: usize, _: usize) bool {
        return false;
    }
    fn sRemap(_: *anyopaque, _: []u8, _: Alignment, _: usize, _: usize) ?[*]u8 {
        return null;
    }
    fn sFree(ctx: *anyopaque, m: []u8, a: Alignment, ra: usize) void {
        const self: *Spy = @ptrCast(@alignCast(ctx));
        self.frees += 1;
        self.last_len = m.len;
        if (std.mem.allEqual(u8, m, 0)) self.zero_frees += 1;
        self.child.rawFree(m, a, ra);
    }
};

test "free hands the child an all-zero block" {
    var spy: Spy = .{ .child = testing.allocator };
    var wa = WipingAllocator.init(spy.allocator());
    const a = wa.allocator();
    const buf = try a.alloc(u8, 100);
    @memset(buf, 0x5a);
    a.free(buf);
    try testing.expectEqual(@as(usize, 1), spy.frees);
    try testing.expectEqual(@as(usize, 1), spy.zero_frees);
    try testing.expectEqual(@as(usize, 100), spy.last_len);
}

test "resize and remap are refused for growth, shrink and same size" {
    var wa = WipingAllocator.init(testing.allocator);
    const a = wa.allocator();
    const buf = try a.alloc(u8, 64);
    defer a.free(buf);
    try testing.expect(!a.resize(buf, 32));
    try testing.expect(!a.resize(buf, 64));
    try testing.expect(!a.resize(buf, 128));
    try testing.expect(a.remap(buf, 32) == null);
    try testing.expect(a.remap(buf, 128) == null);
}

test "realloc moves through alloc + copy + free: the old block is wiped, the data survives" {
    var spy: Spy = .{ .child = testing.allocator };
    var wa = WipingAllocator.init(spy.allocator());
    const a = wa.allocator();
    var buf = try a.alloc(u8, 16);
    for (buf, 0..) |*b, i| b.* = @intCast(i + 1);
    buf = try a.realloc(buf, 4096); // growth
    try testing.expectEqual(@as(usize, 1), spy.frees);
    try testing.expectEqual(@as(usize, 1), spy.zero_frees);
    for (buf[0..16], 0..) |b, i| try testing.expectEqual(@as(u8, @intCast(i + 1)), b);
    buf = try a.realloc(buf, 8); // shrink
    try testing.expectEqual(@as(usize, 2), spy.frees);
    try testing.expectEqual(@as(usize, 2), spy.zero_frees);
    for (buf, 0..) |b, i| try testing.expectEqual(@as(u8, @intCast(i + 1)), b);
    a.free(buf);
    try testing.expectEqual(@as(usize, 3), spy.zero_frees);
}

test "the wipe covers the whole block, every alignment, and a zero-length free is harmless" {
    var spy: Spy = .{ .child = testing.allocator };
    var wa = WipingAllocator.init(spy.allocator());
    const a = wa.allocator();
    const wide = try a.alignedAlloc(u8, .@"64", 129);
    @memset(wide, 0xff);
    a.free(wide);
    try testing.expectEqual(@as(usize, 129), spy.last_len);
    try testing.expectEqual(@as(usize, 1), spy.zero_frees);
    const empty = try a.alloc(u8, 0);
    a.free(empty); // never reaches the child: nothing to wipe, nothing to count
    try testing.expectEqual(@as(usize, 1), spy.frees);
}

test "an ArrayList that grows behind it leaves no secret in the child's freed blocks" {
    var backing: [4096]u8 = @splat(0);
    var fba = std.heap.FixedBufferAllocator.init(&backing);
    var wa = WipingAllocator.init(fba.allocator());
    const a = wa.allocator();
    var list: std.ArrayList(u8) = .empty;
    const secret = "correct horse battery staple";
    for (0..8) |_| try list.appendSlice(a, secret); // several reallocations
    list.deinit(a);
    try testing.expect(std.mem.indexOf(u8, &backing, secret) == null);
}

test "init and the struct literal are the same adapter; an allocation failure passes through" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var a1 = WipingAllocator.init(failing.allocator());
    var a2: WipingAllocator = .{ .child = failing.allocator() };
    try testing.expectError(error.OutOfMemory, a1.allocator().alloc(u8, 8));
    try testing.expectError(error.OutOfMemory, a2.allocator().alloc(u8, 8));
}
