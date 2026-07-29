// SPDX-License-Identifier: MIT

//! Hostile-input tests: the parts of the decoder an attacker controls.
//!
//! Two defects dominate this format's history and both are shaped the same
//! way — *a number read from the input used to size an allocation or bound a
//! loop before the buffer was checked*. Here they are exercised on purpose:
//!
//!  - a tiny message declaring an enormous length;
//!  - a deeply nested chain of embedded messages, which is unbounded
//!    recursion unless something stops it.
//!
//! Plus the smaller ones a fuzzer would find: truncation at every offset,
//! over-long varints, reserved wire types, lengths that overrun by one.

const std = @import("std");
const testing = std.testing;
const pb = @import("root.zig");
const ct = @import("codec_test.zig");

const Field = pb.Field;

// ── the headline case: a length that is a lie ───────────────────────────────

test "hostile: a 5-byte message claiming a 4 GiB string allocates nothing" {
    const gpa = testing.allocator;
    // Tag for field 15 (string), then the varint 0xffff_ffff, then nothing.
    // A decoder that trusts the length allocates 4 GiB (or overflows).
    const attack = [_]u8{ 0x7a, 0xff, 0xff, 0xff, 0xff, 0x0f };
    try testing.expectError(error.Truncated, pb.decode(ct.Wide, gpa, &attack, .{}));
    // testing.allocator would report a leak or a huge live allocation on
    // failure; reaching here means nothing was allocated on the way out.
}

test "hostile: a submessage length beyond the buffer is refused" {
    const gpa = testing.allocator;
    // Field 17 (message), declared length 0x7fff_ffff, one byte present.
    const attack = [_]u8{ 0x8a, 0x01, 0xff, 0xff, 0xff, 0xff, 0x07, 0x08 };
    try testing.expectError(error.Truncated, pb.decode(ct.Wide, gpa, &attack, .{}));
}

test "hostile: a packed payload length beyond the buffer is refused" {
    const gpa = testing.allocator;
    // Field 1 of Repeated is packed int32; declare 1 MiB of payload, send 2 bytes.
    const attack = [_]u8{ 0x0a, 0x80, 0x80, 0x40, 0x01, 0x02 };
    try testing.expectError(error.Truncated, pb.decode(ct.Repeated, gpa, &attack, .{}));
}

test "hostile: off-by-one — a length exactly one past the end still fails" {
    const gpa = testing.allocator;
    // "abc" declared as 4 bytes.
    try testing.expectError(error.Truncated, pb.decode(ct.Wide, gpa, &.{ 0x7a, 0x04, 'a', 'b', 'c' }, .{}));
    // Declared as exactly 3: fine. The boundary is where it should be.
    var ok = try pb.decode(ct.Wide, gpa, &.{ 0x7a, 0x03, 'a', 'b', 'c' }, .{});
    defer ok.deinit();
    try testing.expectEqualStrings("abc", ok.value.s);
}

test "hostile: the same lie inside an unknown field is caught too" {
    const gpa = testing.allocator;
    // Field 99 (not in the schema), LEN, claiming 0xffff_ffff bytes. The
    // skip path must bound-check exactly like the parse path.
    const attack = [_]u8{ 0x9a, 0x06, 0xff, 0xff, 0xff, 0xff, 0x0f };
    try testing.expectError(error.Truncated, pb.decode(ct.Keeps, gpa, &attack, .{}));
}

// ── the second headline case: unbounded nesting ─────────────────────────────

/// A chain of `n` nested submessages of field 2 (`Chain.next`), built from
/// the inside out: each level prepends `0x12` plus the varint length of
/// everything so far.
fn nestedChain(gpa: std.mem.Allocator, n: usize) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(gpa);
    // Innermost payload: field 1 varint 1 -> `08 01`.
    try buf.appendSlice(gpa, &.{ 0x08, 0x01 });
    for (0..n) |_| {
        var hdr: [11]u8 = undefined;
        var e = pb.wire.Emitter.init(&hdr);
        e.tag(2, .len);
        e.varint(buf.items.len);
        try buf.insertSlice(gpa, 0, hdr[0..e.pos]);
    }
    return buf.toOwnedSlice(gpa);
}

test "hostile: deep nesting stops at max_depth instead of exhausting the stack" {
    const gpa = testing.allocator;
    // 40 levels: fine at the default cap of 64.
    {
        const deep = try nestedChain(gpa, 40);
        defer gpa.free(deep);
        var d = try pb.decode(ct.Chain, gpa, deep, .{});
        defer d.deinit();
    }
    // The same input with a cap of 8: refused, not crashed.
    {
        const deep = try nestedChain(gpa, 40);
        defer gpa.free(deep);
        try testing.expectError(error.DepthExceeded, pb.decode(ct.Chain, gpa, deep, .{ .max_depth = 8 }));
    }
    // And at the default cap, a chain past it is refused rather than
    // recursing until the stack runs out.
    {
        const deep = try nestedChain(gpa, 60);
        defer gpa.free(deep);
        try testing.expectError(error.DepthExceeded, pb.decode(ct.Chain, gpa, deep, .{ .max_depth = 32 }));
    }
}

test "hostile: the classic nesting bomb — a few KiB, thousands of levels" {
    const gpa = testing.allocator;
    // ~3 bytes of input buy one stack frame. Without a cap, 2000 levels of
    // this is a recursive descent the input picked the depth of; the whole
    // bomb is under 7 KiB.
    const bomb = try nestedChain(gpa, 2000);
    defer gpa.free(bomb);
    try testing.expect(bomb.len < 8192);
    try testing.expectError(error.DepthExceeded, pb.decode(ct.Chain, gpa, bomb, .{}));
    // Raising the cap to its maximum does not make it safe: the input can
    // always name a deeper chain, so the cap is a bound, not a threshold to
    // tune past.
    try testing.expectError(error.DepthExceeded, pb.decode(ct.Chain, gpa, bomb, .{ .max_depth = 255 }));
}

test "hostile: encoding a value deeper than max_depth is refused, not overflowed" {
    // The encoder recurses too, and a boxed chain built at runtime can be
    // arbitrarily deep. Build 12 levels and cap at 4.
    var nodes: [12]ct.Chain = undefined;
    nodes[11] = .{ .depth = 11 };
    var i: usize = 11;
    while (i > 0) : (i -= 1) nodes[i - 1] = .{ .depth = @intCast(i - 1), .next = &nodes[i] };

    try testing.expectError(error.DepthExceeded, pb.encodedSize(nodes[0], .{ .max_depth = 4 }));
    var buf: [256]u8 = undefined;
    try testing.expectError(error.DepthExceeded, pb.encodeInto(&buf, nodes[0], .{ .max_depth = 4 }));
}

// ── malformed framing ───────────────────────────────────────────────────────

test "hostile: truncation at every offset of a valid message never panics" {
    const gpa = testing.allocator;
    const good = try pb.encodeAlloc(gpa, ct.Wide{
        .i32_ = -5,
        .s = "some string",
        .d = 1.25,
        .inner = .{ .v = 3, .note = "nn" },
    }, .{});
    defer gpa.free(good);

    for (0..good.len) |cut| {
        // Any prefix is either a valid shorter message or a clean error.
        if (pb.decode(ct.Wide, gpa, good[0..cut], .{})) |*d| {
            var m = d.*;
            m.deinit();
        } else |err| switch (err) {
            error.Truncated, error.VarintOverflow, error.FieldNumberZero, error.UnsupportedWireType => {},
            else => return err,
        }
    }
}

test "hostile: byte-flip sweep never panics" {
    const gpa = testing.allocator;
    const good = try pb.encodeAlloc(gpa, ct.Repeated{
        .nums = &.{ 1, -2, 300 },
        .names = &.{ "a", "bcd" },
        .inners = &.{.{ .v = 9, .note = "z" }},
    }, .{});
    defer gpa.free(good);

    const scratch = try gpa.dupe(u8, good);
    defer gpa.free(scratch);

    for (0..good.len) |i| {
        for ([_]u8{ 0x00, 0x01, 0x7f, 0x80, 0xff }) |patch| {
            @memcpy(scratch, good);
            scratch[i] = patch;
            if (pb.decode(ct.Repeated, gpa, scratch, .{})) |*d| {
                var m = d.*;
                m.deinit();
            } else |err| switch (err) {
                error.Truncated,
                error.VarintOverflow,
                error.FieldNumberZero,
                error.UnsupportedWireType,
                error.DepthExceeded,
                => {},
                else => return err,
            }
        }
    }
}

test "hostile: group wire types and field 0 are rejected by name" {
    const gpa = testing.allocator;
    // Field 1, wire type 3 (start group) — removed in proto3.
    try testing.expectError(error.UnsupportedWireType, pb.decode(ct.Keeps, gpa, &.{ 0x0b, 0x00 }, .{}));
    // Field 0 is reserved and no encoder emits it.
    try testing.expectError(error.FieldNumberZero, pb.decode(ct.Keeps, gpa, &.{ 0x00, 0x00 }, .{}));
}

test "hostile: an over-long varint is refused rather than silently truncated" {
    const gpa = testing.allocator;
    // Eleven bytes of continuation for one field value.
    const attack = [_]u8{ 0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01 };
    try testing.expectError(error.VarintOverflow, pb.decode(ct.Keeps, gpa, &attack, .{}));
}

test "hostile: an exhaustive enum rejects a value it cannot represent" {
    const Closed = enum(i32) { a = 0, b = 1 };
    const M = struct {
        e: Closed = .a,
        pub const pb_fields = .{ .e = Field{ .number = 1, .kind = .@"enum" } };
    };
    const gpa = testing.allocator;
    try testing.expectError(error.InvalidEnumValue, pb.decode(M, gpa, &.{ 0x08, 0x7b }, .{}));
    // The open form in codec_test.zig accepts the same byte — that is the
    // proto3-recommended shape, and why the compile-time hint says `_`.
    var d = try pb.decode(struct {
        e: ct.Color = .unspecified,
        pub const pb_fields = .{ .e = Field{ .number = 1, .kind = .@"enum" } };
    }, gpa, &.{ 0x08, 0x7b }, .{});
    defer d.deinit();
    try testing.expectEqual(@as(i32, 123), @intFromEnum(d.value.e));
}

test "hostile: an empty input is a valid all-defaults message" {
    const gpa = testing.allocator;
    var d = try pb.decode(ct.Wide, gpa, &.{}, .{});
    defer d.deinit();
    try testing.expectEqual(@as(i32, 0), d.value.i32_);
    try testing.expect(d.value.inner == null);
}
