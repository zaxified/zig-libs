// SPDX-License-Identifier: MIT

//! Golden-byte and round-trip tests for the message codec.
//!
//! The byte vectors here are hand-derived from the published encoding spec,
//! not from our own encoder, so they stay meaningful even if encoder and
//! decoder drift together. The live reference implementation checks the same
//! ground independently in `reference_interop.zig` — see SPEC.md for why
//! both exist.

const std = @import("std");
const testing = std.testing;
const pb = @import("root.zig");

const Field = pb.Field;

// ── shared fixtures ─────────────────────────────────────────────────────────

pub const Color = enum(i32) {
    unspecified = 0,
    red = 1,
    green = 2,
    _, // open, as proto3 enums are
};

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

    pub const pb_fields = .{
        .implicit = Field{ .number = 1, .kind = .int32 },
        .explicit = Field{ .number = 2, .kind = .int32 },
        .implicit_str = Field{ .number = 3, .kind = .string },
        .explicit_str = Field{ .number = 4, .kind = .string },
    };
};

/// A message that keeps what it does not understand.
pub const Keeps = struct {
    known: i32 = 0,
    unknown: pb.Unknown = .empty,
    pub const pb_fields = .{
        .known = Field{ .number = 1, .kind = .int32 },
    };
};

/// The same field numbers, minus the fields a newer peer knows about.
pub const Drops = struct {
    known: i32 = 0,
    pub const pb_fields = .{
        .known = Field{ .number = 1, .kind = .int32 },
    };
};

/// Self-recursive via a boxed optional — the shape a linked structure needs.
pub const Chain = struct {
    depth: i32 = 0,
    next: ?*const Chain = null,
    pub const pb_fields = .{
        .depth = Field{ .number = 1, .kind = .int32 },
        .next = Field{ .number = 2, .kind = .message },
    };
};

// ── helpers ─────────────────────────────────────────────────────────────────

fn expectEncodes(value: anytype, expected: []const u8) !void {
    const got = try pb.encodeAlloc(testing.allocator, value, .{});
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, expected, got);
    // encodedSize must agree with what was actually written.
    try testing.expectEqual(got.len, try pb.encodedSize(value, .{}));
}

// ── golden bytes ────────────────────────────────────────────────────────────

test "golden: the canonical spec example (field 1 varint 150)" {
    const M = struct {
        a: i32 = 0,
        pub const pb_fields = .{ .a = Field{ .number = 1, .kind = .int32 } };
    };
    // 08 96 01 — the example from the encoding spec's opening section.
    try expectEncodes(M{ .a = 150 }, &.{ 0x08, 0x96, 0x01 });
}

test "golden: negative int32 sign-extends to ten bytes" {
    const M = struct {
        a: i32 = 0,
        pub const pb_fields = .{ .a = Field{ .number = 1, .kind = .int32 } };
    };
    // The failure mode this catches: casting i32 -> u32 gives `08 ff ff ff ff 0f`,
    // which round-trips against itself and is wrong everywhere else.
    try expectEncodes(M{ .a = -1 }, &.{ 0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01 });
    try expectEncodes(M{ .a = -2 }, &.{ 0x08, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01 });
    try expectEncodes(M{ .a = std.math.minInt(i32) }, &.{ 0x08, 0x80, 0x80, 0x80, 0x80, 0xf8, 0xff, 0xff, 0xff, 0xff, 0x01 });
}

test "golden: sint32/sint64 zigzag, not two's complement" {
    const M = struct {
        a: i32 = 0,
        b: i64 = 0,
        pub const pb_fields = .{
            .a = Field{ .number = 1, .kind = .sint32 },
            .b = Field{ .number = 2, .kind = .sint64 },
        };
    };
    // -1 zigzags to 1; +1 zigzags to 2. Dropping the transform gives the
    // ten-byte int32 form instead — a single byte here versus ten.
    try expectEncodes(M{ .a = -1 }, &.{ 0x08, 0x01 });
    try expectEncodes(M{ .a = 1 }, &.{ 0x08, 0x02 });
    try expectEncodes(M{ .a = -2 }, &.{ 0x08, 0x03 });
    try expectEncodes(M{ .b = std.math.minInt(i64) }, &.{ 0x10, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01 });
}

test "golden: string, bytes and embedded message are length-delimited" {
    const bytes = try pb.encodeAlloc(testing.allocator, Wide{
        .s = "testing",
        .inner = .{ .v = 7 },
    }, .{});
    defer testing.allocator.free(bytes);
    try testing.expectEqualSlices(u8, &.{
        0x7a, 0x07, 't', 'e', 's', 't', 'i', 'n', 'g', // field 15, LEN, 7 bytes
        0x8a, 0x01, 0x02, 0x08, 0x07, // field 17, LEN, 2 bytes: {field 1 = 7}
    }, bytes);
}

test "golden: fixed-width fields are little-endian" {
    const M = struct {
        a: u32 = 0,
        b: u64 = 0,
        f: f32 = 0,
        pub const pb_fields = .{
            .a = Field{ .number = 1, .kind = .fixed32 },
            .b = Field{ .number = 2, .kind = .fixed64 },
            .f = Field{ .number = 3, .kind = .float },
        };
    };
    try expectEncodes(M{ .a = 1 }, &.{ 0x0d, 0x01, 0x00, 0x00, 0x00 });
    try expectEncodes(M{ .b = 1 }, &.{ 0x11, 0x01, 0, 0, 0, 0, 0, 0, 0 });
    try expectEncodes(M{ .f = 1.0 }, &.{ 0x1d, 0x00, 0x00, 0x80, 0x3f });
}

test "golden: proto3 packs repeated scalars by default" {
    // field 1, wire 2, 3 bytes of payload: 1, 2, 150 -> 01 02 96 01 is 4 bytes.
    try expectEncodes(
        Repeated{ .nums = &.{ 1, 2, 150 } },
        &.{ 0x0a, 0x04, 0x01, 0x02, 0x96, 0x01 },
    );
    // Same values, packing turned off: one tag per element.
    try expectEncodes(
        Repeated{ .unpacked = &.{ 1, 2, 150 } },
        &.{ 0x10, 0x01, 0x10, 0x02, 0x10, 0x96, 0x01 },
    );
    // Length-delimited element types are never packed, whatever the default.
    try expectEncodes(
        Repeated{ .names = &.{ "a", "bb" } },
        &.{ 0x3a, 0x01, 'a', 0x3a, 0x02, 'b', 'b' },
    );
}

test "golden: empty repeated and default scalars are absent from the wire" {
    try expectEncodes(Repeated{}, &.{});
    try expectEncodes(Wide{}, &.{});
    // Not even a zero-length packed payload for an empty repeated field.
    try expectEncodes(Repeated{ .nums = &.{} }, &.{});
}

// ── presence ────────────────────────────────────────────────────────────────

test "presence: implicit omits the default, explicit transmits it" {
    // Implicit-presence scalar equal to the default: nothing on the wire.
    try expectEncodes(Presence{ .implicit = 0 }, &.{});
    // Non-default: present. (Omitting THIS is the mutation that a
    // default-only test would miss.)
    try expectEncodes(Presence{ .implicit = 1 }, &.{ 0x08, 0x01 });
    // Explicit presence: a zero that was explicitly set IS transmitted.
    try expectEncodes(Presence{ .explicit = 0 }, &.{ 0x10, 0x00 });
    try expectEncodes(Presence{ .explicit = 5 }, &.{ 0x10, 0x05 });
    // Same for strings.
    try expectEncodes(Presence{ .implicit_str = "" }, &.{});
    try expectEncodes(Presence{ .explicit_str = "" }, &.{ 0x22, 0x00 });
}

test "presence: an absent explicit field decodes back to null, a present zero to 0" {
    const gpa = testing.allocator;
    {
        var d = try pb.decode(Presence, gpa, &.{}, .{});
        defer d.deinit();
        try testing.expect(d.value.explicit == null);
        try testing.expect(d.value.explicit_str == null);
        try testing.expectEqual(@as(i32, 0), d.value.implicit);
    }
    {
        var d = try pb.decode(Presence, gpa, &.{ 0x10, 0x00 }, .{});
        defer d.deinit();
        try testing.expectEqual(@as(?i32, 0), d.value.explicit);
    }
}

// ── round trips over every kind ─────────────────────────────────────────────

test "round trip: every scalar kind at its extremes" {
    const gpa = testing.allocator;
    const cases = [_]Wide{
        .{},
        .{ .i32_ = std.math.maxInt(i32), .i64_ = std.math.maxInt(i64) },
        .{ .i32_ = std.math.minInt(i32), .i64_ = std.math.minInt(i64) },
        .{ .u32_ = std.math.maxInt(u32), .u64_ = std.math.maxInt(u64) },
        .{ .s32 = std.math.minInt(i32), .s64 = std.math.minInt(i64) },
        .{ .s32 = std.math.maxInt(i32), .s64 = std.math.maxInt(i64) },
        .{ .b = true, .color = .green },
        .{ .color = @enumFromInt(9999) }, // open enum: a value we never declared
        .{ .color = @enumFromInt(-3) },
        .{ .f64_ = std.math.maxInt(u64), .sf64 = std.math.minInt(i64) },
        .{ .f32_ = std.math.maxInt(u32), .sf32 = std.math.minInt(i32) },
        .{ .d = -1.5e300, .f = 3.5 },
        .{ .s = "unicode: ěščřž 🎉", .raw = &.{ 0x00, 0xff, 0x7f, 0x80 } },
        .{ .inner = .{ .v = -9, .note = "n" } },
    };
    for (cases) |c| {
        const bytes = try pb.encodeAlloc(gpa, c, .{});
        defer gpa.free(bytes);
        var d = try pb.decode(Wide, gpa, bytes, .{});
        defer d.deinit();

        try testing.expectEqual(c.i32_, d.value.i32_);
        try testing.expectEqual(c.i64_, d.value.i64_);
        try testing.expectEqual(c.u32_, d.value.u32_);
        try testing.expectEqual(c.u64_, d.value.u64_);
        try testing.expectEqual(c.s32, d.value.s32);
        try testing.expectEqual(c.s64, d.value.s64);
        try testing.expectEqual(c.b, d.value.b);
        try testing.expectEqual(c.color, d.value.color);
        try testing.expectEqual(c.f64_, d.value.f64_);
        try testing.expectEqual(c.sf64, d.value.sf64);
        try testing.expectEqual(c.d, d.value.d);
        try testing.expectEqual(c.f32_, d.value.f32_);
        try testing.expectEqual(c.sf32, d.value.sf32);
        try testing.expectEqual(c.f, d.value.f);
        try testing.expectEqualStrings(c.s, d.value.s);
        try testing.expectEqualStrings(c.raw, d.value.raw);
        if (c.inner) |want| {
            try testing.expectEqual(want.v, d.value.inner.?.v);
            try testing.expectEqualStrings(want.note, d.value.inner.?.note);
        } else try testing.expect(d.value.inner == null);
    }
}

test "round trip: repeated fields of every shape" {
    const gpa = testing.allocator;
    const v = Repeated{
        .nums = &.{ -1, 0, 1, 150, std.math.maxInt(i32) },
        .unpacked = &.{ 7, 8 },
        .zz = &.{ -1, 1, std.math.minInt(i64) },
        .fixed = &.{ 0, 0xdeadbeef },
        .flags = &.{ true, false, true },
        .colors = &.{ .red, .green, @enumFromInt(77) },
        .names = &.{ "", "a", "long-ish string" },
        .inners = &.{ .{ .v = 1 }, .{ .v = 2, .note = "x" } },
    };
    const bytes = try pb.encodeAlloc(gpa, v, .{});
    defer gpa.free(bytes);
    var d = try pb.decode(Repeated, gpa, bytes, .{});
    defer d.deinit();

    try testing.expectEqualSlices(i32, v.nums, d.value.nums);
    try testing.expectEqualSlices(i32, v.unpacked, d.value.unpacked);
    try testing.expectEqualSlices(i64, v.zz, d.value.zz);
    try testing.expectEqualSlices(u32, v.fixed, d.value.fixed);
    try testing.expectEqualSlices(bool, v.flags, d.value.flags);
    try testing.expectEqualSlices(Color, v.colors, d.value.colors);
    try testing.expectEqual(v.names.len, d.value.names.len);
    for (v.names, d.value.names) |a, b| try testing.expectEqualStrings(a, b);
    try testing.expectEqual(v.inners.len, d.value.inners.len);
    for (v.inners, d.value.inners) |a, b| {
        try testing.expectEqual(a.v, b.v);
        try testing.expectEqualStrings(a.note, b.note);
    }
}

test "decoder accepts both packed and unpacked forms of the same field" {
    const gpa = testing.allocator;
    // Field 1 is packed by default; a peer sent it unpacked. Must still parse.
    {
        var d = try pb.decode(Repeated, gpa, &.{ 0x08, 0x01, 0x08, 0x02, 0x08, 0x96, 0x01 }, .{});
        defer d.deinit();
        try testing.expectEqualSlices(i32, &.{ 1, 2, 150 }, d.value.nums);
    }
    // Field 2 is declared unpacked; a peer sent it packed. Must still parse.
    {
        var d = try pb.decode(Repeated, gpa, &.{ 0x12, 0x04, 0x01, 0x02, 0x96, 0x01 }, .{});
        defer d.deinit();
        try testing.expectEqualSlices(i32, &.{ 1, 2, 150 }, d.value.unpacked);
    }
    // And the two forms interleaved for one field concatenate, per the spec.
    {
        var d = try pb.decode(Repeated, gpa, &.{ 0x0a, 0x02, 0x01, 0x02, 0x08, 0x03 }, .{});
        defer d.deinit();
        try testing.expectEqualSlices(i32, &.{ 1, 2, 3 }, d.value.nums);
    }
}

test "decoder: last occurrence of a singular field wins" {
    const gpa = testing.allocator;
    var d = try pb.decode(Wide, gpa, &.{ 0x08, 0x01, 0x08, 0x02 }, .{});
    defer d.deinit();
    try testing.expectEqual(@as(i32, 2), d.value.i32_);
}

// ── unknown fields ──────────────────────────────────────────────────────────

test "unknown fields survive a decode/encode round trip byte for byte" {
    const gpa = testing.allocator;
    // A newer peer's message: known field 1, plus fields 2 (varint),
    // 3 (LEN) and 4 (fixed32) that this build has never heard of.
    const from_peer = [_]u8{
        0x08, 0x2a, // 1: varint 42            (known)
        0x10, 0x07, // 2: varint 7             (unknown)
        0x1a, 0x03, 'a', 'b', 'c', // 3: LEN   (unknown)
        0x25, 0x04, 0x03, 0x02, 0x01, // 4: I32 (unknown)
    };
    var d = try pb.decode(Keeps, gpa, &from_peer, .{});
    defer d.deinit();
    try testing.expectEqual(@as(i32, 42), d.value.known);
    try testing.expectEqualSlices(u8, from_peer[2..], d.value.unknown.raw);

    const again = try pb.encodeAlloc(gpa, d.value, .{});
    defer gpa.free(again);
    try testing.expectEqualSlices(u8, &from_peer, again);
}

test "unknown fields are dropped by a message with no sink" {
    const gpa = testing.allocator;
    const from_peer = [_]u8{ 0x08, 0x2a, 0x10, 0x07 };
    var d = try pb.decode(Drops, gpa, &from_peer, .{});
    defer d.deinit();
    try testing.expectEqual(@as(i32, 42), d.value.known);

    const again = try pb.encodeAlloc(gpa, d.value, .{});
    defer gpa.free(again);
    try testing.expectEqualSlices(u8, &.{ 0x08, 0x2a }, again); // field 2 gone
}

test "unknown fields inside a submessage are preserved too" {
    const Outer = struct {
        inner: ?Keeps = null,
        unknown: pb.Unknown = .empty,
        pub const pb_fields = .{ .inner = Field{ .number = 1, .kind = .message } };
    };
    const gpa = testing.allocator;
    // 0a 04 { 08 2a 10 07 }: submessage with a known and an unknown field.
    const from_peer = [_]u8{ 0x0a, 0x04, 0x08, 0x2a, 0x10, 0x07 };
    var d = try pb.decode(Outer, gpa, &from_peer, .{});
    defer d.deinit();
    try testing.expectEqualSlices(u8, &.{ 0x10, 0x07 }, d.value.inner.?.unknown.raw);

    const again = try pb.encodeAlloc(gpa, d.value, .{});
    defer gpa.free(again);
    try testing.expectEqualSlices(u8, &from_peer, again);
}

test "reject_unknown_fields refuses instead of preserving" {
    const gpa = testing.allocator;
    try testing.expectError(error.UnknownField, pb.decode(
        Keeps,
        gpa,
        &.{ 0x08, 0x2a, 0x10, 0x07 },
        .{ .reject_unknown_fields = true },
    ));
    // The known-only message still parses.
    var d = try pb.decode(Keeps, gpa, &.{ 0x08, 0x2a }, .{ .reject_unknown_fields = true });
    defer d.deinit();
    try testing.expectEqual(@as(i32, 42), d.value.known);
}

test "a wire-type mismatch is treated as an unknown field, not a parse failure" {
    const gpa = testing.allocator;
    // Field 1 of Keeps is a varint; the peer sent it length-delimited.
    // Protobuf's rule is to treat that as an unknown field.
    const input = [_]u8{ 0x0a, 0x01, 0x63 };
    var d = try pb.decode(Keeps, gpa, &input, .{});
    defer d.deinit();
    try testing.expectEqual(@as(i32, 0), d.value.known);
    try testing.expectEqualSlices(u8, &input, d.value.unknown.raw);
}

// ── nesting ─────────────────────────────────────────────────────────────────

test "nesting: a boxed self-recursive chain round trips" {
    const gpa = testing.allocator;
    const c3 = Chain{ .depth = 3 };
    const c2 = Chain{ .depth = 2, .next = &c3 };
    const c1 = Chain{ .depth = 1, .next = &c2 };

    const bytes = try pb.encodeAlloc(gpa, c1, .{});
    defer gpa.free(bytes);
    var d = try pb.decode(Chain, gpa, bytes, .{});
    defer d.deinit();

    try testing.expectEqual(@as(i32, 1), d.value.depth);
    try testing.expectEqual(@as(i32, 2), d.value.next.?.depth);
    try testing.expectEqual(@as(i32, 3), d.value.next.?.next.?.depth);
    try testing.expect(d.value.next.?.next.?.next == null);
}

// ── zero-copy option ────────────────────────────────────────────────────────

test "copy_strings=false aliases the input buffer" {
    const gpa = testing.allocator;
    const input = [_]u8{ 0x7a, 0x03, 'a', 'b', 'c' };
    var d = try pb.decode(Wide, gpa, &input, .{ .copy_strings = false });
    defer d.deinit();
    try testing.expectEqualStrings("abc", d.value.s);
    try testing.expectEqual(@intFromPtr(&input[2]), @intFromPtr(d.value.s.ptr));

    var d2 = try pb.decode(Wide, gpa, &input, .{ .copy_strings = true });
    defer d2.deinit();
    try testing.expectEqualStrings("abc", d2.value.s);
    try testing.expect(@intFromPtr(&input[2]) != @intFromPtr(d2.value.s.ptr));
}

// ── the no-allocation encode path ───────────────────────────────────────────

test "encodeInto writes into a caller buffer and refuses a short one" {
    var buf: [64]u8 = undefined;
    const v = Wide{ .s = "hello", .i32_ = 150 };
    const n = try pb.encodeInto(&buf, v, .{});
    try testing.expectEqual(n, try pb.encodedSize(v, .{}));

    var tiny: [3]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, pb.encodeInto(&tiny, v, .{}));
}
