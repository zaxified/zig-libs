// SPDX-License-Identifier: MIT

//! **External anchor for the JSON <-> blobmsg codec: libubox's own.**
//!
//! `testdata/libubox_oracle.zig` (made by `tools/libubox_oracle.py`) holds,
//! for each JSON object, the blobmsg children OpenWRT libubox's
//! `blobmsg_add_json_from_string` built from it -- the bytes `ubus call`
//! sends -- and what `blobmsg_format_json` printed back from them -- what
//! `ubus` shows. Here:
//!
//! - `encodeArgs` of the same JSON must be those bytes, exactly;
//! - `decodeToJson` of libubox's bytes must mean what libubox printed
//!   (compared as JSON values: libubox prints doubles with 17 digits) --
//!   except an empty member name, which libubox prints as invalid JSON and
//!   this codec refuses (listed below).

const std = @import("std");
const testing = std.testing;
const codec = @import("codec.zig");
const rec = @import("testdata/libubox_oracle.zig");

fn unhex(a: std.mem.Allocator, h: []const u8) ![]u8 {
    const out = try a.alloc(u8, h.len / 2);
    _ = try std.fmt.hexToBytes(out, h);
    return out;
}

/// Structural JSON equality; numbers compare by value (int 2 == float 2.0).
fn same(x: std.json.Value, y: std.json.Value) bool {
    const fx: ?f64 = switch (x) {
        .integer => |i| @floatFromInt(i),
        .float => |f| f,
        else => null,
    };
    const fy: ?f64 = switch (y) {
        .integer => |i| @floatFromInt(i),
        .float => |f| f,
        else => null,
    };
    if (fx != null and fy != null) {
        if (x == .integer and y == .integer) return x.integer == y.integer;
        return fx.? == fy.?;
    }
    return switch (x) {
        .null => y == .null,
        .bool => |b| y == .bool and y.bool == b,
        .string => |s| y == .string and std.mem.eql(u8, s, y.string),
        .array => |arr| blk: {
            if (y != .array or y.array.items.len != arr.items.len) break :blk false;
            for (arr.items, y.array.items) |p, q| if (!same(p, q)) break :blk false;
            break :blk true;
        },
        .object => |o| blk: {
            if (y != .object or y.object.count() != o.count()) break :blk false;
            var it = o.iterator();
            var jt = y.object.iterator();
            while (it.next()) |e| {
                const f = jt.next().?; // libubox keeps member order; so must we
                if (!std.mem.eql(u8, e.key_ptr.*, f.key_ptr.*) or !same(e.value_ptr.*, f.value_ptr.*)) break :blk false;
            }
            break :blk true;
        },
        else => false,
    };
}

test "libubox oracle: encodeArgs builds the bytes libubox builds" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for (rec.cases) |c| {
        errdefer std.debug.print("case {s}\n", .{c.json});
        const v = try std.json.parseFromSliceLeaky(std.json.Value, a, c.json, .{ .duplicate_field_behavior = .use_last });
        const ours = codec.encodeArgs(a, v) catch |e| {
            if (c.bytes == null) continue;
            return e;
        };
        try testing.expectEqualSlices(u8, try unhex(a, c.bytes orelse return error.TestUnexpectedResult), ours);
    }
}

test "libubox oracle: decodeToJson reads libubox's bytes as libubox does" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for (rec.cases) |c| {
        errdefer std.debug.print("case {s}\n", .{c.json});
        const bytes = try unhex(a, c.bytes orelse continue);
        if (std.mem.startsWith(u8, c.json, "{\"\":")) {
            // Listed divergence: libubox's encoder accepts an empty member
            // name, and its formatter then prints `{"empty key",...}` --
            // not JSON. This codec refuses an unnamed TABLE field, as
            // upstream `blobmsg_check_attr` does (audit F5).
            try testing.expectError(error.BadLength, codec.decodeToJsonAlloc(a, bytes));
            continue;
        }
        const ours = try codec.decodeToJsonAlloc(a, bytes);
        const want = try std.json.parseFromSliceLeaky(std.json.Value, a, c.formatted, .{});
        const got = try std.json.parseFromSliceLeaky(std.json.Value, a, ours, .{});
        if (!same(want, got)) {
            std.debug.print("libubox printed {s}\nours            {s}\n", .{ c.formatted, ours });
            return error.TestUnexpectedResult;
        }
    }
}
