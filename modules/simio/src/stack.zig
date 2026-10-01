// SPDX-License-Identifier: MIT

//! Fiber stacks: an anonymous private mapping with a `PROT_NONE` guard page at
//! its low end, so a task that overflows its stack faults on the guard instead
//! of silently writing into whatever the allocator placed below it. The mapping
//! is `MAP_NORESERVE`, so the virtual size is cheap: pages are committed only
//! when a task actually touches them.
//!
//! Stacks never come from the caller's allocator: a `std.testing.allocator`
//! would have to hand out megabytes per task, and an overflow would land in the
//! allocator's own bookkeeping.

const std = @import("std");
const linux = std.os.linux;

pub const Error = error{OutOfMemory};

pub const Stack = struct {
    /// The whole mapping, guard page included.
    mapping: []align(std.heap.page_size_min) u8,

    /// One past the highest usable byte; stacks grow down from here.
    pub fn top(s: Stack) usize {
        return @intFromPtr(s.mapping.ptr) + s.mapping.len;
    }

    /// Lowest usable byte, just above the guard page.
    pub fn bottom(s: Stack) usize {
        return @intFromPtr(s.mapping.ptr) + std.heap.pageSize();
    }
};

/// Maps a stack of at least `usable` bytes plus one guard page.
pub fn map(usable: usize) Error!Stack {
    const page = std.heap.pageSize();
    const len = std.mem.alignForward(usize, usable, page) + page;
    const rc = linux.mmap(null, len, .{ .READ = true, .WRITE = true }, .{
        .TYPE = .PRIVATE,
        .ANONYMOUS = true,
        .NORESERVE = true,
    }, -1, 0);
    if (linux.errno(rc) != .SUCCESS) return error.OutOfMemory;
    const ptr: [*]align(std.heap.page_size_min) u8 = @ptrFromInt(rc);
    const stack: Stack = .{ .mapping = ptr[0..len] };
    if (linux.errno(linux.mprotect(ptr, page, .{})) != .SUCCESS) {
        unmap(stack);
        return error.OutOfMemory;
    }
    return stack;
}

pub fn unmap(s: Stack) void {
    _ = linux.munmap(s.mapping.ptr, s.mapping.len);
}

test "the guard page is below the usable range and the range is page aligned" {
    const s = try map(64 * 1024);
    defer unmap(s);
    const page = std.heap.pageSize();
    try std.testing.expectEqual(@as(usize, 0), s.top() % page);
    try std.testing.expectEqual(s.bottom(), @intFromPtr(s.mapping.ptr) + page);
    try std.testing.expect(s.top() - s.bottom() >= 64 * 1024);
    // The usable range is writable end to end.
    const usable: [*]u8 = @ptrFromInt(s.bottom());
    usable[0] = 0xaa;
    usable[s.top() - s.bottom() - 1] = 0x55;
    try std.testing.expectEqual(@as(u8, 0xaa), usable[0]);
}
