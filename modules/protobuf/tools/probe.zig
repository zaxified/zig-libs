// SPDX-License-Identifier: MIT
//! The module side of the differential rig: a line protocol over `protobuf` so
//! a Python reference process can be diffed against it decision-for-decision.
//!
//! stdin lines:  <op> <schema> <hexbytes>
//!   op = "d"  decode, print canonical dump or the error name
//!   op = "r"  decode then re-encode, print the resulting hex (or error)
//! stdout lines: "OK <dump>" | "ERR <name>"
//!
//! WHY THIS IS A PROGRAM AND NOT A TEST. A test binary answers one fixed set of
//! inputs and has to be rebuilt to answer another. The campaigns feed this
//! hundreds of thousands of byte strings from a generator and a mutator, so the
//! thing that decodes them has to be a process that reads stdin. It is also why
//! it lives in `tools/` and not in `src/`: it is driven by Python.
//!
//! WHAT IT NEEDS. Only this module. Build it beside this file:
//!
//!     zig build-exe probe.zig --dep protobuf -Mroot=probe.zig \
//!         -Mprotobuf=../src/root.zig -O ReleaseSafe
//!
//! WHAT IT PRODUCES. One answer line per input line, in order, so a comparison
//! with the reference is a string comparison — nothing is parsed twice and no
//! interpretation sits between the two implementations.
//!
//! ⚠ THE SCHEMAS BELOW MUST MATCH `oracle.py`'s FIELD FOR FIELD. They are the
//! contract of the comparison, not an implementation detail: add a field on one
//! side only and the rig keeps running while quietly comparing different things.
//! The dump format is mirrored there too — ordered by field number, `<unset>`
//! for an absent optional, floats as raw bits so NaN payloads survive.

const std = @import("std");
const pb = @import("protobuf");
const Field = pb.Field;

pub const Color = enum(i32) { unspecified = 0, red = 1, green = 2, _ };

pub const Inner = struct {
    v: i32 = 0,
    note: []const u8 = "",
    pub const pb_fields = .{
        .v = Field{ .number = 1, .kind = .int32 },
        .note = Field{ .number = 2, .kind = .string },
    };
};

pub const Wide = struct {
    i32_: i32 = 0,
    i64_: i64 = 0,
    u32_: u32 = 0,
    u64_: u64 = 0,
    s32: i32 = 0,
    s64: i64 = 0,
    b: bool = false,
    color: Color = .unspecified,
    f64_: u64 = 0,
    sf64: i64 = 0,
    d: f64 = 0,
    f32_: u32 = 0,
    sf32: i32 = 0,
    f: f32 = 0,
    s: []const u8 = "",
    raw: []const u8 = "",
    inner: ?Inner = null,
    unknown: pb.Unknown = .empty,

    pub const pb_fields = .{
        .i32_ = Field{ .number = 1, .kind = .int32 },
        .i64_ = Field{ .number = 2, .kind = .int64 },
        .u32_ = Field{ .number = 3, .kind = .uint32 },
        .u64_ = Field{ .number = 4, .kind = .uint64 },
        .s32 = Field{ .number = 5, .kind = .sint32 },
        .s64 = Field{ .number = 6, .kind = .sint64 },
        .b = Field{ .number = 7, .kind = .bool },
        .color = Field{ .number = 8, .kind = .@"enum" },
        .f64_ = Field{ .number = 9, .kind = .fixed64 },
        .sf64 = Field{ .number = 10, .kind = .sfixed64 },
        .d = Field{ .number = 11, .kind = .double },
        .f32_ = Field{ .number = 12, .kind = .fixed32 },
        .sf32 = Field{ .number = 13, .kind = .sfixed32 },
        .f = Field{ .number = 14, .kind = .float },
        .s = Field{ .number = 15, .kind = .string },
        .raw = Field{ .number = 16, .kind = .bytes },
        .inner = Field{ .number = 17, .kind = .message },
    };
};

pub const Repeated = struct {
    nums: []const i32 = &.{},
    unpacked: []const i32 = &.{},
    zz: []const i64 = &.{},
    fixed: []const u32 = &.{},
    flags: []const bool = &.{},
    colors: []const Color = &.{},
    names: []const []const u8 = &.{},
    inners: []const Inner = &.{},
    unknown: pb.Unknown = .empty,

    pub const pb_fields = .{
        .nums = Field{ .number = 1, .kind = .int32 },
        .unpacked = Field{ .number = 2, .kind = .int32, .packed_encoding = false },
        .zz = Field{ .number = 3, .kind = .sint64 },
        .fixed = Field{ .number = 4, .kind = .fixed32 },
        .flags = Field{ .number = 5, .kind = .bool },
        .colors = Field{ .number = 6, .kind = .@"enum" },
        .names = Field{ .number = 7, .kind = .string },
        .inners = Field{ .number = 8, .kind = .message },
    };
};

pub const Presence = struct {
    implicit: i32 = 0,
    explicit: ?i32 = null,
    implicit_str: []const u8 = "",
    explicit_str: ?[]const u8 = null,
    unknown: pb.Unknown = .empty,

    pub const pb_fields = .{
        .implicit = Field{ .number = 1, .kind = .int32 },
        .explicit = Field{ .number = 2, .kind = .int32 },
        .implicit_str = Field{ .number = 3, .kind = .string },
        .explicit_str = Field{ .number = 4, .kind = .string },
    };
};

pub const Chain = struct {
    depth: i32 = 0,
    next: ?*const Chain = null,
    unknown: pb.Unknown = .empty,
    pub const pb_fields = .{
        .depth = Field{ .number = 1, .kind = .int32 },
        .next = Field{ .number = 2, .kind = .message },
    };
};

// ── canonical dump, mirrored by oracle.py ───────────────────────────────────

fn dumpValue(comptime kind: pb.Kind, comptime E: type, v: E, w: *std.ArrayList(u8), gpa: std.mem.Allocator) std.mem.Allocator.Error!void {
    switch (kind) {
        .bool => try w.appendSlice(gpa, if (v) "1" else "0"),
        .float => {
            const bits: u32 = @bitCast(v);
            try w.print(gpa, "f32:{x:0>8}", .{bits});
        },
        .double => {
            const bits: u64 = @bitCast(v);
            try w.print(gpa, "f64:{x:0>16}", .{bits});
        },
        .string, .bytes => {
            try w.append(gpa, 'h');
            for (v) |b| try w.print(gpa, "{x:0>2}", .{b});
        },
        .@"enum" => try w.print(gpa, "{d}", .{@intFromEnum(v)}),
        .message => {
            try w.append(gpa, '{');
            try dumpMessage(E, v, w, gpa);
            try w.append(gpa, '}');
        },
        else => try w.print(gpa, "{d}", .{v}),
    }
}

fn dumpMessage(comptime T: type, value: T, w: *std.ArrayList(u8), gpa: std.mem.Allocator) std.mem.Allocator.Error!void {
    var first = true;
    inline for (comptime pb.infos(T)) |info| {
        if (!first) try w.append(gpa, ';');
        first = false;
        try w.appendSlice(gpa, info.name);
        try w.append(gpa, '=');
        const f = @field(value, info.name);
        switch (info.card) {
            .singular => try dumpValue(info.kind, info.Elem, f, w, gpa),
            .optional => {
                if (f) |present| {
                    if (comptime info.boxed)
                        try dumpValue(info.kind, info.Elem, present.*, w, gpa)
                    else
                        try dumpValue(info.kind, info.Elem, present, w, gpa);
                } else try w.appendSlice(gpa, "<unset>");
            },
            .repeated => {
                try w.append(gpa, '[');
                for (f, 0..) |elem, i| {
                    if (i != 0) try w.append(gpa, ',');
                    try dumpValue(info.kind, info.Elem, elem, w, gpa);
                }
                try w.append(gpa, ']');
            },
        }
    }
}

fn hexDecode(gpa: std.mem.Allocator, hex: []const u8) ![]u8 {
    const out = try gpa.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

fn handle(comptime T: type, gpa: std.mem.Allocator, op: u8, bytes: []const u8, out: *std.ArrayList(u8), opts: pb.DecodeOptions) !void {
    var d = pb.decode(T, gpa, bytes, opts) catch |e| {
        try out.print(gpa, "ERR {s}", .{@errorName(e)});
        return;
    };
    defer d.deinit();
    if (op == 'd') {
        try out.appendSlice(gpa, "OK ");
        try dumpMessage(T, d.value, out, gpa);
    } else {
        const re = pb.encodeAlloc(gpa, d.value, .{}) catch |e| {
            try out.print(gpa, "ERR {s}", .{@errorName(e)});
            return;
        };
        defer gpa.free(re);
        try out.appendSlice(gpa, "OK ");
        for (re) |b| try out.print(gpa, "{x:0>2}", .{b});
    }
}

fn readAll(gpa: std.mem.Allocator) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    var tmp: [1 << 16]u8 = undefined;
    while (true) {
        const n = try std.posix.read(0, &tmp);
        if (n == 0) break;
        try buf.appendSlice(gpa, tmp[0..n]);
    }
    return buf.toOwnedSlice(gpa);
}

pub fn main() !void {
    var dbg = std.heap.DebugAllocator(.{}){};
    const gpa = dbg.allocator();

    const input = try readAll(gpa);
    defer gpa.free(input);

    var result: std.ArrayList(u8) = .empty;
    defer result.deinit(gpa);

    var lines = std.mem.splitScalar(u8, input, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var it = std.mem.tokenizeScalar(u8, line, ' ');
        const op_s = it.next() orelse continue;
        const schema = it.next() orelse continue;
        const hex = it.next() orelse "";

        const bytes = try hexDecode(gpa, hex);
        defer gpa.free(bytes);

        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);

        const op = op_s[0];
        if (std.mem.eql(u8, schema, "Wide")) {
            try handle(Wide, gpa, op, bytes, &out, .{});
        } else if (std.mem.eql(u8, schema, "Repeated")) {
            try handle(Repeated, gpa, op, bytes, &out, .{});
        } else if (std.mem.eql(u8, schema, "Presence")) {
            try handle(Presence, gpa, op, bytes, &out, .{});
        } else if (std.mem.eql(u8, schema, "Chain")) {
            try handle(Chain, gpa, op, bytes, &out, .{});
        } else if (std.mem.eql(u8, schema, "Inner")) {
            try handle(Inner, gpa, op, bytes, &out, .{});
        } else {
            // An unknown schema name is answered, not skipped: a silently
            // dropped line would shift every later answer by one and the
            // campaigns compare by position.
            try out.appendSlice(gpa, "ERR NoSuchSchema");
        }
        try result.appendSlice(gpa, out.items);
        try result.append(gpa, '\n');
    }
    var off: usize = 0;
    while (off < result.items.len) {
        const n = std.os.linux.write(1, result.items[off..].ptr, result.items.len - off);
        if (@as(isize, @bitCast(n)) <= 0) break;
        off += n;
    }
}
