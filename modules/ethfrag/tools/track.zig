// SPDX-License-Identifier: MIT
//
// WHY THIS EXISTS: a peak-LIVE-bytes tracking allocator, shared by every probe
// in this directory that makes a claim about memory.
//
// ⚠ It records the HIGH-WATER MARK, not a cumulative total. A cumulative
// counter cannot see simultaneity: it answers "how many bytes passed through"
// when the question a resource bound asks is "how many were held at once".
// Audit F4 and F5 are both statements about `peak`; audit F8 is a statement
// about `total_alloc`. Keeping both, separately named, is what lets one probe
// answer both without either number being mistaken for the other.

const std = @import("std");
const Alignment = std.mem.Alignment;

pub const Track = struct {
    child: std.mem.Allocator,
    live: usize = 0,
    peak: usize = 0,
    total_alloc: usize = 0,
    n_alloc: usize = 0,
    n_free: usize = 0,
    n_resize: usize = 0,
    n_remap: usize = 0,

    pub fn allocator(self: *Track) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = alloc,
            .resize = resize,
            .remap = remap,
            .free = free,
        } };
    }

    fn bump(self: *Track, n: usize) void {
        self.live += n;
        if (self.live > self.peak) self.peak = self.live;
    }

    fn alloc(ctx: *anyopaque, len: usize, a: Alignment, ra: usize) ?[*]u8 {
        const self: *Track = @ptrCast(@alignCast(ctx));
        const p = self.child.rawAlloc(len, a, ra) orelse return null;
        self.n_alloc += 1;
        self.total_alloc += len;
        self.bump(len);
        return p;
    }

    fn resize(ctx: *anyopaque, m: []u8, a: Alignment, new_len: usize, ra: usize) bool {
        const self: *Track = @ptrCast(@alignCast(ctx));
        if (!self.child.rawResize(m, a, new_len, ra)) return false;
        self.n_resize += 1;
        if (new_len > m.len) {
            self.total_alloc += new_len - m.len;
            self.bump(new_len - m.len);
        } else self.live -= m.len - new_len;
        return true;
    }

    fn remap(ctx: *anyopaque, m: []u8, a: Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const self: *Track = @ptrCast(@alignCast(ctx));
        const p = self.child.rawRemap(m, a, new_len, ra) orelse return null;
        self.n_remap += 1;
        if (new_len > m.len) {
            self.total_alloc += new_len - m.len;
            self.bump(new_len - m.len);
        } else self.live -= m.len - new_len;
        return p;
    }

    fn free(ctx: *anyopaque, m: []u8, a: Alignment, ra: usize) void {
        const self: *Track = @ptrCast(@alignCast(ctx));
        self.child.rawFree(m, a, ra);
        self.n_free += 1;
        self.live -= m.len;
    }
};
