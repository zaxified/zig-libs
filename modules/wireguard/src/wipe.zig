// SPDX-License-Identifier: MIT

//! An allocator adapter that zeroes every byte it gives back: `free` wipes,
//! and `resize`/`remap` are refused, so a growing or shrinking buffer goes
//! through the caller's `alloc` + copy + `free` path and the old block is
//! wiped by `free`. Used for the control-plane buffers that carry the interface
//! private key and the peers' pre-shared keys (`buildSetRequests`): an
//! `std.ArrayList` that grows or shrinks to fit would otherwise leave
//! earlier copies of the key in freed heap blocks.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;

pub const WipingAllocator = struct {
    child: Allocator,

    pub fn init(child: Allocator) WipingAllocator {
        return .{ .child = child };
    }

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

    // Every resize and remap is refused, so the caller allocates, copies and
    // frees (which wipes). Shrinking in place and zeroing the tail afterwards
    // would touch memory the child may already have released (a page
    // allocator unmaps it); zeroing it first would destroy data the caller
    // still owns if the child then refused. Same shape as `xmldsig`'s and
    // `bbs`'s adapters.
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
