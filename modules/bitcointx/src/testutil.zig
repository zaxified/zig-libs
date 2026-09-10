// SPDX-License-Identifier: MIT
//! Tiny hex-decode helpers shared by the `*_kat_test.zig` files. Test-only
//! (not part of the public API).

const std = @import("std");
const Allocator = std.mem.Allocator;

pub fn hexToBytesAlloc(allocator: Allocator, hex: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(out);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

pub fn hexToArray(comptime n: usize, hex: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

/// Wraps a backing allocator and counts `alloc`/successful-`resize`/
/// successful-`remap` calls -- used to measure "did adding
/// `ensureTotalCapacity` actually cut allocator round-trips", the way
/// `A1/bitcointx.md` finding B2 was measured (see
/// `A1/repro/bitcointx/allocs.zig`). `free` is passed through uncounted:
/// the finding is about growth, not cleanup.
pub const CountingAllocator = struct {
    backing: Allocator,
    allocs: usize = 0,
    resizes: usize = 0,
    remaps: usize = 0,

    pub fn allocator(self: *CountingAllocator) Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = alloc,
            .resize = resize,
            .remap = remap,
            .free = free,
        } };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        const p = Allocator.rawAlloc(self.backing, len, alignment, ret_addr);
        if (p != null) self.allocs += 1;
        return p;
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        const ok = Allocator.rawResize(self.backing, memory, alignment, new_len, ret_addr);
        if (ok) self.resizes += 1;
        return ok;
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        const p = Allocator.rawRemap(self.backing, memory, alignment, new_len, ret_addr);
        if (p != null) self.remaps += 1;
        return p;
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        Allocator.rawFree(self.backing, memory, alignment, ret_addr);
    }
};
