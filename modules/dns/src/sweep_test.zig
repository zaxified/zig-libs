// SPDX-License-Identifier: MIT
//! No-panic sweep tests for dns, wave GV. Findings DN-1 .. DN-4, see
//! ~/CML/20261029-panic-sweep/dns-sweep.report.md.
const std = @import("std");
const testing = std.testing;
const netaddr = @import("netaddr");
const Resolver = @import("Resolver.zig");
const tsig = @import("tsig.zig");

const loopback: netaddr.Ip = .{ .v4 = .{ 127, 0, 0, 1 } };

test "exchange: a packet over 65535 bytes is refused before anything is sent (sweep DN-1)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var r = Resolver.init(threaded.io(), testing.allocator, .{ .transport = .tcp, .port = 1, .attempts = 1, .timeout_ms = 1000 });
    defer r.deinit();

    const packet = try testing.allocator.alloc(u8, 65_536);
    defer testing.allocator.free(packet);
    @memset(packet, 0);
    // 65 536 bytes cannot be announced by the 2-byte TCP length prefix; the
    // plain `@intCast` of the length trapped.
    try testing.expectError(error.RequestTooLarge, r.exchange(loopback, packet));
    try testing.expectError(error.MalformedResponse, r.exchange(loopback, packet[0 .. message_header_len - 1]));
    // The exact limit is accepted by the check: the attempt then fails on the
    // network (nothing listens on port 1), not as a malformed packet.
    if (r.exchange(loopback, packet[0..65_535])) |raw| {
        testing.allocator.free(raw);
        return error.TestUnexpectedResult;
    } else |err| try testing.expect(err != error.MalformedResponse and err != error.RequestTooLarge);
}

const message_header_len = 12;

fn testKey() tsig.Key {
    return .{ .name = "k.example.", .algorithm = .hmac_sha256, .secret = "0123456789abcdef0123456789abcdef" };
}

fn header(buf: []u8) void {
    @memset(buf[0..12], 0);
    buf[1] = 7; // id
}

test "tsig.sign: `other` that pushes RDLENGTH past 65535 is Malformed, the exact limit signs and verifies (sweep DN-2)" {
    const key = testKey();
    const buf = try testing.allocator.alloc(u8, 70_000);
    defer testing.allocator.free(buf);
    const other = try testing.allocator.alloc(u8, 65_535);
    defer testing.allocator.free(other);
    @memset(other, 0xAB);

    // hmac-sha256: alg name 13 wire bytes + 6+2+2+32+2+2+2 = 61 fixed bytes, so
    // 65 474 bytes of `other` make RDLENGTH exactly 65 535.
    var mac: tsig.Mac = .{};
    for ([_]usize{ 65_475, 65_535 }) |n| {
        header(buf);
        try testing.expectError(error.Malformed, tsig.sign(buf, 12, &key, .{ .time = 1_000, .other = other[0..n] }, &mac));
        try testing.expectEqual(@as(u8, 0), mac.len);
        // The header is untouched: ARCOUNT still 0.
        try testing.expectEqual(@as(u8, 0), buf[11]);
    }
    header(buf);
    const signed = try tsig.sign(buf, 12, &key, .{ .time = 1_000, .other = other[0..65_474] }, &mac);
    var seen: tsig.Mac = .{};
    try tsig.verify(signed, &key, .{ .now = 1_000 }, &seen);
    try testing.expectEqualSlices(u8, mac.slice(), seen.slice());
}

test "tsig.verify: a request_mac over 65535 bytes is Malformed, not a trap (sweep DN-3)" {
    const key = testKey();
    var buf: [512]u8 = undefined;
    header(&buf);
    var mac: tsig.Mac = .{};
    const signed = try tsig.sign(&buf, 12, &key, .{ .time = 1_000 }, &mac);

    const big = try testing.allocator.alloc(u8, 65_536);
    defer testing.allocator.free(big);
    @memset(big, 0);
    var seen: tsig.Mac = .{};
    try testing.expectError(error.Malformed, tsig.verify(signed, &key, .{ .now = 1_000, .request_mac = big }, &seen));
    try testing.expectEqual(@as(u8, 0), seen.len);
    // 65 535 is the largest the wire can carry: it gets as far as the MAC
    // comparison (which cannot match the signature made without it).
    try testing.expectError(error.BadSig, tsig.verify(signed, &key, .{ .now = 1_000, .request_mac = big[0..65_535] }, &seen));
}

const message = @import("message.zig");

/// A 65 533-byte reply: one record owned by a 127-label name, then 5 438
/// 12-byte records whose owner is a compression pointer to it.
fn pointerFlood(buf: []u8) []u8 {
    var n: usize = 0;
    const records = 5438;
    @memcpy(buf[0..12], &[_]u8{ 0, 1, 0x81, 0x80, 0, 0, 0x15, 0x3f, 0, 0, 0, 0 }); // ancount 5439
    n = 12;
    for (0..127) |_| {
        buf[n] = 1;
        buf[n + 1] = 'a';
        n += 2;
    }
    buf[n] = 0;
    n += 1;
    const tail = [_]u8{ 0, 99, 0, 1, 0, 0, 0, 0, 0, 0 }; // type 99, class IN, ttl 0, rdlength 0
    @memcpy(buf[n..][0..10], &tail);
    n += 10;
    for (0..records) |_| {
        buf[n] = 0xc0;
        buf[n + 1] = 12;
        @memcpy(buf[n + 2 ..][0..10], &tail);
        n += 12;
    }
    return buf[0..n];
}

test "decode: records sharing one owner name share its decoded copy (sweep REV-dns-1)" {
    var buf: [65_535]u8 = undefined;
    const wire = pointerFlood(&buf);
    try testing.expect(wire.len > 65_000);
    var counting = testing.FailingAllocator.init(testing.allocator, .{});
    var msg = try message.decode(counting.allocator(), wire);
    defer msg.deinit();
    try testing.expectEqual(@as(usize, 5439), msg.answers.len);
    try testing.expectEqual(@as(usize, 127), msg.answers[5438].labels.len);
    try testing.expectEqualStrings(msg.answers[0].name, msg.answers[5438].name);
    // Measured 2026-10-31: 848 588 bytes with sharing; without it every one of
    // the 5 439 records paid for its own name copy and 127-slot labels array
    // (~13 MB). One MiB leaves room for allocator slack, not for per-record copies.
    try testing.expect(counting.allocated_bytes <= 1 << 20);
}
