// SPDX-License-Identifier: MIT

//! Golden-byte and round-trip tests for the message codec.
//!
//! The byte vectors here are hand-derived from the published encoding spec,
//! not from our own encoder, so they stay meaningful even if encoder and
//! decoder drift together. The live reference implementation checks the same
//! ground independently in `tools/interop.zig` — see SPEC.md for why both
//! exist.

const std = @import("std");
const testing = std.testing;
const pb = @import("root.zig");

const Field = pb.Field;

// ── shared fixtures ─────────────────────────────────────────────────────────
//
// The message types themselves live in `conformance.zig`, which the
// out-of-tree interop program (`tools/interop.zig`) also imports — one table,
// so the live run against the reference and the frozen replay here judge the
// same schemas. Re-exported under their old names so every existing reference
// (`ct.Wide`, `ct.Chain`, …) keeps working.

const conformance = @import("conformance.zig");

pub const Color = conformance.Color;
pub const Inner = conformance.Inner;
pub const Wide = conformance.Wide;
pub const Repeated = conformance.Repeated;
pub const Presence = conformance.Presence;
pub const Keeps = conformance.Keeps;
pub const Drops = conformance.Drops;
pub const Chain = conformance.Chain;

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

// A1/protobuf.md F12: the case list above stops at `-1.5e300` / `3.5` — no
// NaN, no +-Inf, no denormal anywhere in the suite. Compared bit-for-bit,
// not by value: NaN != NaN under `==`, so `testing.expectEqual` on the
// float itself (as the block above does) cannot even express this case.
// `-0.0` is deliberately excluded: `isDefault` treats it as the type
// default (`-0.0 == 0` is true in IEEE 754), so proto3 implicit presence
// never puts it on the wire at all — that is a documented, intentional
// elision (A1/protobuf.md F12's own writeup), not something a round trip
// through an implicit-presence field can observe either way.
test "F12: float pathology (NaN payload, +-Inf, denormal) round-trips bit-exact" {
    const gpa = testing.allocator;
    const f64_cases = [_]u64{
        0x7ff8000000000000, // qNaN, canonical payload
        0x7ff0000000000001, // sNaN, minimal payload
        0xfff8000000000001, // negative NaN, nonzero payload
        0x7ff0000000000000, // +Inf
        0xfff0000000000000, // -Inf
        0x0000000000000001, // smallest positive denormal
        0x8000000000000001, // smallest negative denormal
    };
    const f32_cases = [_]u32{
        0x7fc00000, // qNaN
        0x7f800001, // sNaN
        0xffc00001, // negative NaN, nonzero payload
        0x7f800000, // +Inf
        0xff800000, // -Inf
        0x00000001, // smallest positive denormal
        0x80000001, // smallest negative denormal
    };
    for (f64_cases) |bits| {
        const c = Wide{ .d = @bitCast(bits) };
        const bytes = try pb.encodeAlloc(gpa, c, .{});
        defer gpa.free(bytes);
        var d = try pb.decode(Wide, gpa, bytes, .{});
        defer d.deinit();
        try testing.expectEqual(bits, @as(u64, @bitCast(d.value.d)));
    }
    for (f32_cases) |bits| {
        const c = Wide{ .f = @bitCast(bits) };
        const bytes = try pb.encodeAlloc(gpa, c, .{});
        defer gpa.free(bytes);
        var d = try pb.decode(Wide, gpa, bytes, .{});
        defer d.deinit();
        try testing.expectEqual(bits, @as(u32, @bitCast(d.value.f)));
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

// ── F7: a message with dozens of fields still compiles ─────────────────────

test "a 40-field message compiles and round-trips (28 was the old ceiling)" {
    // `schema.infos`' comptime derivation hit `@setEvalBranchQuota`'s old
    // budget (20_000) at exactly 29 fields — `evaluation exceeded 20000
    // backwards branches`, pointing into schema.zig's own duplicate-number
    // check rather than at anything the caller wrote (wave-3 audit finding
    // `protobuf` F7). 40 fields is comfortably past that ceiling and not an
    // unusual schema size in real protobuf use.
    const Wide40 = struct {
        f0: i32 = 0,
        f1: i32 = 0,
        f2: i32 = 0,
        f3: i32 = 0,
        f4: i32 = 0,
        f5: i32 = 0,
        f6: i32 = 0,
        f7: i32 = 0,
        f8: i32 = 0,
        f9: i32 = 0,
        f10: i32 = 0,
        f11: i32 = 0,
        f12: i32 = 0,
        f13: i32 = 0,
        f14: i32 = 0,
        f15: i32 = 0,
        f16: i32 = 0,
        f17: i32 = 0,
        f18: i32 = 0,
        f19: i32 = 0,
        f20: i32 = 0,
        f21: i32 = 0,
        f22: i32 = 0,
        f23: i32 = 0,
        f24: i32 = 0,
        f25: i32 = 0,
        f26: i32 = 0,
        f27: i32 = 0,
        f28: i32 = 0,
        f29: i32 = 0,
        f30: i32 = 0,
        f31: i32 = 0,
        f32: i32 = 0,
        f33: i32 = 0,
        f34: i32 = 0,
        f35: i32 = 0,
        f36: i32 = 0,
        f37: i32 = 0,
        f38: i32 = 0,
        f39: i32 = 0,

        pub const pb_fields = .{
            .f0 = Field{ .number = 1, .kind = .int32 },
            .f1 = Field{ .number = 2, .kind = .int32 },
            .f2 = Field{ .number = 3, .kind = .int32 },
            .f3 = Field{ .number = 4, .kind = .int32 },
            .f4 = Field{ .number = 5, .kind = .int32 },
            .f5 = Field{ .number = 6, .kind = .int32 },
            .f6 = Field{ .number = 7, .kind = .int32 },
            .f7 = Field{ .number = 8, .kind = .int32 },
            .f8 = Field{ .number = 9, .kind = .int32 },
            .f9 = Field{ .number = 10, .kind = .int32 },
            .f10 = Field{ .number = 11, .kind = .int32 },
            .f11 = Field{ .number = 12, .kind = .int32 },
            .f12 = Field{ .number = 13, .kind = .int32 },
            .f13 = Field{ .number = 14, .kind = .int32 },
            .f14 = Field{ .number = 15, .kind = .int32 },
            .f15 = Field{ .number = 16, .kind = .int32 },
            .f16 = Field{ .number = 17, .kind = .int32 },
            .f17 = Field{ .number = 18, .kind = .int32 },
            .f18 = Field{ .number = 19, .kind = .int32 },
            .f19 = Field{ .number = 20, .kind = .int32 },
            .f20 = Field{ .number = 21, .kind = .int32 },
            .f21 = Field{ .number = 22, .kind = .int32 },
            .f22 = Field{ .number = 23, .kind = .int32 },
            .f23 = Field{ .number = 24, .kind = .int32 },
            .f24 = Field{ .number = 25, .kind = .int32 },
            .f25 = Field{ .number = 26, .kind = .int32 },
            .f26 = Field{ .number = 27, .kind = .int32 },
            .f27 = Field{ .number = 28, .kind = .int32 },
            .f28 = Field{ .number = 29, .kind = .int32 },
            .f29 = Field{ .number = 30, .kind = .int32 },
            .f30 = Field{ .number = 31, .kind = .int32 },
            .f31 = Field{ .number = 32, .kind = .int32 },
            .f32 = Field{ .number = 33, .kind = .int32 },
            .f33 = Field{ .number = 34, .kind = .int32 },
            .f34 = Field{ .number = 35, .kind = .int32 },
            .f35 = Field{ .number = 36, .kind = .int32 },
            .f36 = Field{ .number = 37, .kind = .int32 },
            .f37 = Field{ .number = 38, .kind = .int32 },
            .f38 = Field{ .number = 39, .kind = .int32 },
            .f39 = Field{ .number = 40, .kind = .int32 },
        };
    };

    const gpa = testing.allocator;
    var v: Wide40 = .{};
    v.f0 = 1;
    v.f28 = 29; // the field number that used to be the ceiling
    v.f39 = 40;

    const bytes = try pb.encodeAlloc(gpa, v, .{});
    defer gpa.free(bytes);
    var d = try pb.decode(Wide40, gpa, bytes, .{});
    defer d.deinit();
    try testing.expectEqual(@as(i32, 1), d.value.f0);
    try testing.expectEqual(@as(i32, 29), d.value.f28);
    try testing.expectEqual(@as(i32, 40), d.value.f39);
}

// ── F6: encodeAlloc's size cache agrees with encodeInto's recompute ────────
//
// A1/protobuf.md F6: `encodeAlloc` now sizes every submessage exactly once
// (a `SizeTree` built alongside the sizing pass) instead of recomputing a
// nested size on every level it is under. `encodeInto` still recomputes —
// it has no allocator to cache with, and that is its whole point (see
// encode.zig's module doc comment) — so the two functions are two
// INDEPENDENT implementations of "how big is this submessage" that must
// still agree byte-for-byte. That is the differential test below, not a
// reimplementation of either (see
// [[feedback_a_test_that_reimplements_the_code_cannot_fail]]).

fn buildChain(nodes: []Chain, depth: usize) ?*const Chain {
    if (depth == 0) return null;
    var i: usize = depth;
    while (i > 0) : (i -= 1) {
        nodes[i - 1] = .{
            .depth = @intCast(i),
            .next = if (i < depth) &nodes[i] else null,
        };
    }
    return &nodes[0];
}

fn expectEncodeIntoAgreesWithEncodeAlloc(gpa: std.mem.Allocator, value: anytype, options: pb.EncodeOptions) !void {
    const size = try pb.encodedSize(value, options);
    const into_buf = try gpa.alloc(u8, size);
    defer gpa.free(into_buf);
    const into_len = try pb.encodeInto(into_buf, value, options);
    try testing.expectEqual(size, into_len);

    const alloc_buf = try pb.encodeAlloc(gpa, value, options);
    defer gpa.free(alloc_buf);

    try testing.expectEqualSlices(u8, into_buf[0..into_len], alloc_buf);
}

test "F6: encodeInto and encodeAlloc agree bit-for-bit on a chain, across depths" {
    const gpa = testing.allocator;
    const depths = [_]usize{ 0, 1, 2, 3, 5, 8, 16, 32, 63, 64, 100, 150, 200, 254 };
    var nodes: [254]Chain = undefined;
    const options: pb.EncodeOptions = .{ .max_depth = 255 };
    for (depths) |d| {
        const root = buildChain(&nodes, d);
        const value: Chain = if (root) |r| r.* else .{};
        try expectEncodeIntoAgreesWithEncodeAlloc(gpa, value, options);
    }
}

/// Deliberately NOT a chain: `a` is a leaf sibling that comes BEFORE `c`, a
/// nested sibling, in field order — the shape that broke the first attempt
/// at F6's cache (a flat, single-cursor list gives the wrong size to `a`
/// once `c`'s own subtree has entries of its own; see encode.zig's module
/// doc comment for why a real per-node child list is needed instead).
const SiblingNest = struct {
    a: ?Inner = null,
    c: ?*const SiblingNest = null,

    pub const pb_fields = .{
        .a = Field{ .number = 1, .kind = .message },
        .c = Field{ .number = 2, .kind = .message },
    };
};

test "F6: encodeInto and encodeAlloc agree when a leaf sibling precedes a nested one" {
    const gpa = testing.allocator;
    const leaf3: SiblingNest = .{ .a = .{ .v = 3, .note = "d" } };
    const leaf2: SiblingNest = .{ .a = .{ .v = 2, .note = "c" }, .c = &leaf3 };
    const root: SiblingNest = .{ .a = .{ .v = 1, .note = "a" }, .c = &leaf2 };
    try expectEncodeIntoAgreesWithEncodeAlloc(gpa, root, .{});

    // A wider version: three levels, each with TWO leaf siblings ahead of
    // the nested one, and the deepest level a repeated (array) sibling too
    // -- exercises `.optional` and `.repeated` message-typed fields sharing
    // one node's child list, in schema field order.
    const Level = struct {
        first: ?Inner = null,
        second: ?Inner = null,
        many: []const Inner = &.{},
        deeper: ?*const @This() = null,

        pub const pb_fields = .{
            .first = Field{ .number = 1, .kind = .message },
            .second = Field{ .number = 2, .kind = .message },
            .many = Field{ .number = 3, .kind = .message },
            .deeper = Field{ .number = 4, .kind = .message },
        };
    };
    const many3 = [_]Inner{ .{ .v = 30 }, .{ .v = 31 }, .{ .v = 32 } };
    const l3: Level = .{ .first = .{ .v = 300 }, .second = .{ .v = 301 }, .many = &many3 };
    const many2 = [_]Inner{.{ .v = 20 }};
    const l2: Level = .{ .first = .{ .v = 200 }, .many = &many2, .deeper = &l3 };
    const l1: Level = .{ .second = .{ .v = 100 }, .deeper = &l2 };
    try expectEncodeIntoAgreesWithEncodeAlloc(gpa, l1, .{});
}

fn fuzzEncodeIntoAgreesWithEncodeAlloc(_: void, smith: *std.testing.Smith) !void {
    const gpa = testing.allocator;

    var inners_buf: [6]Inner = undefined;
    const n_inners = smith.index(inners_buf.len + 1);
    for (inners_buf[0..n_inners]) |*it| {
        it.* = .{ .v = smith.value(i32), .note = if (smith.value(bool)) "x" else "" };
    }

    const value: Repeated = .{
        .nums = &.{ smith.value(i32), smith.value(i32) },
        .unpacked = &.{smith.value(i32)},
        .zz = &.{smith.value(i64)},
        .fixed = &.{smith.value(u32)},
        .flags = &.{ smith.value(bool), smith.value(bool) },
        .colors = &.{@enumFromInt(smith.valueRangeAtMost(u2, 0, 2))},
        .names = &.{if (smith.value(bool)) "abc" else ""},
        .inners = inners_buf[0..n_inners],
    };
    try expectEncodeIntoAgreesWithEncodeAlloc(gpa, value, .{});
}

test "fuzz: encodeInto and encodeAlloc agree bit-for-bit on randomized Repeated values" {
    try std.testing.fuzz({}, fuzzEncodeIntoAgreesWithEncodeAlloc, .{});
}
