// SPDX-License-Identifier: MIT
//! Column-name lookups for the verbs that resolve many names against one frame.
//! `Frame.columnIndex` scans the columns, so resolving every name of a wide spec (or one
//! name in every frame of an output) is width x width string compares: a hostile width
//! made that minutes (sweep S2-6). A `NameMap` is built in one pass; the first of a
//! repeated name wins, as `columnIndex` does.

const std = @import("std");
const Column = @import("value.zig").Column;

pub const NameMap = struct {
    map: std.StringHashMapUnmanaged(usize) = .empty,

    pub fn init(a: std.mem.Allocator, columns: []const Column) std.mem.Allocator.Error!NameMap {
        var m: NameMap = .{};
        const n = std.math.cast(u32, columns.len) orelse return error.OutOfMemory;
        try m.map.ensureTotalCapacity(a, n);
        for (columns, 0..) |c, i| {
            const gop = m.map.getOrPutAssumeCapacity(c.name);
            if (!gop.found_existing) gop.value_ptr.* = i;
        }
        return m;
    }

    pub fn get(m: *const NameMap, name: []const u8) ?usize {
        return m.map.get(name);
    }

    pub fn must(m: *const NameMap, name: []const u8) error{NoSuchColumn}!usize {
        return m.map.get(name) orelse error.NoSuchColumn;
    }
};
