// SPDX-License-Identifier: MIT

//! Hostile-input tests for the parts of this module an attacker controls: the
//! five bytes in front of every message, and the header/trailer field values.
//!
//! The headline defect for a length-prefixed protocol is always the same
//! shape — *a number read from the input used to size an allocation before
//! anything has been verified*. Five bytes here can claim a 4 GiB message, so
//! that claim is exercised on purpose, from several directions: at the
//! default limit, with the limit raised to its maximum (where "check the
//! limit" is no defence at all and only the no-allocation invariant is left),
//! split across pushes so the check cannot be a one-shot, and repeated so a
//! per-message failure cannot leak.
//!
//! Then the smaller ones a fuzzer would find, and the fuzzers themselves.

const std = @import("std");
const testing = std.testing;
const frame = @import("frame.zig");
const status = @import("status.zig");
const metadata = @import("metadata.zig");
const call = @import("call.zig");

// ── the headline case: a length that is a lie ───────────────────────────────

test "hostile: five bytes claiming 4 GiB allocate nothing and fail cleanly" {
    const gpa = testing.allocator;
    var d: frame.Deframer = .{};
    defer d.deinit(gpa);
    try testing.expectError(
        error.MessageTooLarge,
        d.push(gpa, &.{ 0x00, 0xff, 0xff, 0xff, 0xff }),
    );
    try testing.expectEqual(@as(usize, 5), d.buf.items.len);
}

test "hostile: with the limit at its maximum, the lie STILL allocates nothing" {
    const gpa = testing.allocator;
    // The limit is the first line of defence; this test removes it entirely,
    // so what remains is the real invariant: the declared length never sizes
    // an allocation. A deframer that pre-reserved `length` would try for
    // 4 GiB right here, and the testing allocator would say so.
    var d: frame.Deframer = .{ .max_recv_message_size = std.math.maxInt(u32) };
    defer d.deinit(gpa);
    try d.push(gpa, &.{ 0x00, 0xff, 0xff, 0xff, 0xff });
    try d.push(gpa, "ten bytes!");
    try testing.expectEqual(@as(usize, 15), d.buf.items.len);
    try testing.expect(d.buf.capacity < 1024);
    // …and it is still not a message, because 4 GiB of it never arrived.
    try testing.expectEqual(@as(?[]const u8, null), try d.next());
    try testing.expectError(error.TruncatedMessage, d.endOfStream());
}

test "hostile: the check is not one-shot — a lie split across pushes still fails" {
    const gpa = testing.allocator;
    // No single push ever contains a whole header.
    var d: frame.Deframer = .{ .max_recv_message_size = 1024 };
    defer d.deinit(gpa);
    try d.push(gpa, &.{ 0x00, 0x7f, 0xff, 0xff });
    try testing.expectError(error.MessageTooLarge, d.push(gpa, &.{0xff}));
}

test "hostile: a run of oversized headers fails every time, not just the first" {
    const gpa = testing.allocator;
    for (0..64) |_| {
        var d: frame.Deframer = .{ .max_recv_message_size = 8 };
        defer d.deinit(gpa);
        try testing.expectError(
            error.MessageTooLarge,
            d.push(gpa, &.{ 0x00, 0x00, 0x00, 0x00, 0x09 }),
        );
    }
}

test "hostile: a valid message followed by a lying one fails at the second" {
    const gpa = testing.allocator;
    var d: frame.Deframer = .{ .max_recv_message_size = 8 };
    defer d.deinit(gpa);
    try d.push(gpa, &.{ 0x00, 0x00, 0x00, 0x00, 0x02, 'o', 'k' });
    try testing.expectEqualStrings("ok", (try d.next()).?);
    try testing.expectError(
        error.MessageTooLarge,
        d.push(gpa, &.{ 0x00, 0xff, 0xff, 0xff, 0xff }),
    );
}

test "hostile: a flood of zero-length messages does not grow the buffer" {
    const gpa = testing.allocator;
    var d: frame.Deframer = .{};
    defer d.deinit(gpa);
    for (0..100_000) |_| {
        try d.push(gpa, &.{ 0, 0, 0, 0, 0 });
        try testing.expectEqualStrings("", (try d.next()).?);
    }
    try testing.expect(d.buf.capacity < 1024);
}

test "hostile: off-by-one — one byte short is not a message" {
    const gpa = testing.allocator;
    var d: frame.Deframer = .{};
    defer d.deinit(gpa);
    try d.push(gpa, &.{ 0x00, 0x00, 0x00, 0x00, 0x04, 'a', 'b', 'c' });
    try testing.expectEqual(@as(?[]const u8, null), try d.next());
    try d.push(gpa, &.{'d'});
    try testing.expectEqualStrings("abcd", (try d.next()).?);
}

test "hostile: every nonzero value of the flag byte means compressed" {
    const gpa = testing.allocator;
    // Not just 0x01 — a peer (or an attacker) may set any bit, and treating
    // anything but 0x01 as "not compressed" would hand a compressed payload
    // to the protobuf decoder as if it were plaintext.
    var v: u8 = 1;
    while (v != 0) : (v +%= 1) {
        var d: frame.Deframer = .{};
        defer d.deinit(gpa);
        try testing.expectError(
            error.CompressedUnsupported,
            d.push(gpa, &.{ v, 0x00, 0x00, 0x00, 0x01, 0x00 }),
        );
    }
}

// ── field values ───────────────────────────────────────────────────────────

test "hostile: a grpc-status that is not a bare decimal never reads as OK" {
    const bad = [_][]const u8{
        "",           " ",   "0x0", "99999999999999999999",
        "4294967296", "+1",  "-1",  "1.0",
        "1 ",         " 1",  "\t0", "0\n",
        "٠",
        "０",
        "1e3",        "0;0",
    };
    for (bad) |b| try testing.expectEqual(@as(?status.Status, null), status.parse(b));
    // Leading zeros ARE a bare decimal, and must not be rejected.
    try testing.expectEqual(status.Status.ok, status.parse("00").?);
    try testing.expectEqual(status.Status.not_found, status.parse("005").?);
}

test "hostile: grpc-message decoding survives every truncation of an escape" {
    const value = "a%E2%98%83b%0A%";
    var buf: [64]u8 = undefined;
    for (0..value.len + 1) |n| {
        const out = status.decodeMessage(value[0..n], &buf);
        try testing.expect(out.len <= n);
    }
}

test "hostile: a -bin value of arbitrary junk is an error, never partial garbage" {
    const gpa = testing.allocator;
    const junk = [_][]const u8{
        "!!!!", "A", "AB=C", "====", "\x00\x01\x02\x03", "AAAAA",
    };
    for (junk) |j| {
        const r = metadata.decodeValue(gpa, "x-bin", j) catch |e| {
            try testing.expectEqual(error.InvalidBinaryValue, e);
            continue;
        };
        // If it did decode, it must round trip — a decoder that silently
        // accepted a broken value would be worse than one that rejected it.
        defer r.deinit(gpa);
        var enc: [64]u8 = undefined;
        const back = metadata.encodeValue(.{ .name = "x-bin", .value = r.bytes }, &enc);
        try testing.expectEqualStrings(std.mem.trimEnd(u8, j, "="), back);
    }
}

test "hostile: a grpc-timeout value outside the grammar is rejected" {
    const bad = [_][]const u8{
        "", "S", "1", "1X",
        "999999999S", // nine digits: one more than the grammar allows
        "-1S",
        "1.5S",
        " 1S",
        "1S ",
        "1s", // lowercase 's' is not a unit; 'S' is
        "0000000001S",
        "١S",
    };
    for (bad) |b| try testing.expectEqual(@as(?call.Timeout, null), call.Timeout.parse(b));
}

// ── fuzz ───────────────────────────────────────────────────────────────────

fn fuzzDeframerNeverPanics(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len = smith.valueRangeAtMost(u16, 0, buf.len);
    const chunk = smith.valueRangeAtMost(u16, 1, 64);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var d: frame.Deframer = .{ .max_recv_message_size = 4096 };
    var i: usize = 0;
    while (i < len) {
        const end = @min(len, i + chunk);
        d.push(a, buf[i..end]) catch return;
        while (d.next() catch return) |_| {}
        i = end;
    }
    d.endOfStream() catch return;
}
test "fuzz: the deframer never panics on arbitrary bytes, however they are chopped" {
    try std.testing.fuzz({}, fuzzDeframerNeverPanics, .{});
}

fn fuzzFieldValuesNeverPanic(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len = smith.valueRangeAtMost(u16, 0, buf.len);
    const value = buf[0..len];

    _ = status.parse(value);
    _ = call.Timeout.parse(value);

    var out: [256]u8 = undefined;
    const decoded = status.decodeMessage(value, &out);
    // Re-encoding what came out must always fit the encoder's own estimate.
    var enc: [768]u8 = undefined;
    if (status.encodedMessageLen(decoded) <= enc.len) {
        _ = status.encodeMessage(decoded, &enc);
    }

    const r = metadata.decodeValue(std.testing.allocator, "x-bin", value) catch return;
    r.deinit(std.testing.allocator);
}
test "fuzz: status, timeout and metadata field parsing never panic" {
    try std.testing.fuzz({}, fuzzFieldValuesNeverPanic, .{});
}
