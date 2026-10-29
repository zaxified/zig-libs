// SPDX-License-Identifier: MIT
//! No-panic sweep pins for the wire layer (wave GM, packet / topic / acl).
//! The sweep found no crash in these files; these tests pin the hostile
//! inputs the report lists as "clean", so a later edit that breaks one fails.
const std = @import("std");
const packet = @import("packet.zig");
const topic = @import("topic.zig");
const acl = @import("acl.zig");
const broker = @import("broker.zig");
const testing = std.testing;

test "remaining length: 5 bytes, an unfinished varint and the maximum with a short body (sweep MW-clean)" {
    try testing.expectError(error.MalformedRemainingLength, packet.decodePacket(&.{ 0x30, 0x80, 0x80, 0x80, 0x80, 0x01 }, .v5));
    try testing.expectError(error.MalformedRemainingLength, packet.decodePacket(&.{ 0x30, 0xFF, 0xFF, 0xFF, 0xFF }, .v5));
    try testing.expectEqual(null, try packet.decodePacket(&.{ 0x30, 0xFF, 0xFF }, .v5));
    // the largest announced body: needs more bytes, no allocation, no panic
    try testing.expectEqual(null, try packet.decodePacket(&.{ 0x30, 0xFF, 0xFF, 0xFF, 0x7F, 1, 2, 3 }, .v5));
    try testing.expectEqual(null, try packet.decodePacket(&.{}, .v5));
}

test "every prefix and every single-byte flip of a rich v5 PUBLISH decodes or errors (sweep MW-clean)" {
    var buf: [256]u8 = undefined;
    const props: packet.Properties = .{
        .message_expiry_interval = 5,
        .content_type = "text/x",
        .user_properties = .{ .items = &.{ .{ .name = "k", .value = "v" }, .{ .name = "k2", .value = "v2" } } },
        .subscription_ids = .{ .items = &.{ 1, 300 } },
    };
    const enc = try packet.encodePacket(&buf, .v5, .{ .publish = .{ .topic = "a/b", .payload = "xyz", .qos = .at_least_once, .packet_id = 7, .properties = props } });
    var work: [256]u8 = undefined;
    for (0..enc.len) |n| _ = packet.decodePacket(enc[0..n], .v5) catch {};
    for (0..enc.len) |i| for (0..256) |v| {
        @memcpy(work[0..enc.len], enc);
        work[i] = @intCast(v);
        _ = packet.decodePacket(work[0..enc.len], .v5) catch {};
        _ = packet.decodePacket(work[0..enc.len], .v3_1_1) catch {};
    };
}

test "hostile property blocks are typed errors (sweep MW-clean)" {
    // property length larger than the packet
    try testing.expectError(error.MalformedPacket, packet.decodePacket(&.{ 0x30, 0x06, 0x00, 0x01, 'a', 0xFF, 0xFF, 0x7F }, .v5));
    // duplicate Message Expiry Interval
    const dup = [_]u8{ 0x02, 0, 0, 0, 1, 0x02, 0, 0, 0, 2 };
    try testing.expectError(error.ProtocolViolation, packet.decodePropertyEntries(&dup, .publish));
    // Topic Alias 0, Subscription Identifier 0, Receive Maximum 0
    try testing.expectError(error.ProtocolViolation, packet.decodePropertyEntries(&.{ 0x23, 0, 0 }, .publish));
    try testing.expectError(error.ProtocolViolation, packet.decodePropertyEntries(&.{ 0x0B, 0 }, .publish));
    try testing.expectError(error.ProtocolViolation, packet.decodePropertyEntries(&.{ 0x21, 0, 0 }, .connect));
    // Subscription Identifier varint of 5 bytes, unknown id, id not allowed for the packet
    try testing.expectError(error.MalformedPacket, packet.decodePropertyEntries(&.{ 0x0B, 0x80, 0x80, 0x80, 0x80, 0x01 }, .publish));
    try testing.expectError(error.MalformedPacket, packet.decodePropertyEntries(&.{ 0x7F, 0 }, .publish));
    try testing.expectError(error.MalformedPacket, packet.decodePropertyEntries(&.{ 0x0B, 1 }, .puback));
    // a string running past the block, a U+0000 in a string
    try testing.expectError(error.MalformedPacket, packet.decodePropertyEntries(&.{ 0x03, 0xFF, 0xFF, 'a' }, .publish));
    try testing.expectError(error.InvalidUtf8, packet.decodePropertyEntries(&.{ 0x03, 0, 1, 0 }, .publish));
}

test "SUBSCRIBE / QoS 3 / reserved flags are typed errors (sweep MW-clean)" {
    try testing.expectError(error.InvalidQos, packet.decodePacket(&.{ 0x36, 0x03, 0, 1, 'a' }, .v3_1_1)); // PUBLISH QoS 3
    try testing.expectError(error.InvalidQos, packet.decodePacket(&.{ 0x82, 0x06, 0, 1, 0, 1, 'a', 3 }, .v3_1_1));
    try testing.expectError(error.ProtocolViolation, packet.decodePacket(&.{ 0x82, 0x07, 0, 1, 0, 0, 1, 'a', 3 }, .v5));
    try testing.expectError(error.ProtocolViolation, packet.decodePacket(&.{ 0x82, 0x07, 0, 1, 0, 0, 1, 'a', 0x30 }, .v5));
    try testing.expectError(error.InvalidFlags, packet.decodePacket(&.{ 0x80, 0x00 }, .v3_1_1));
    try testing.expectError(error.UnknownPacketType, packet.decodePacket(&.{ 0xF0, 0x00 }, .v3_1_1));
    try testing.expectError(error.UnknownPacketType, packet.decodePacket(&.{ 0x00, 0x00 }, .v5));
}

test "hand-built Subscribe / Unsubscribe payloads and property raw blocks end iteration (sweep MW-clean)" {
    const junk = [_][]const u8{ &.{}, &.{0}, &.{ 0xFF, 0xFF, 1 }, &.{ 0, 5, 'a' }, &.{ 0, 1, 'a', 0xFF }, &.{ 0, 1, 'a', 3 }, &.{ 0, 1, 'a', 0x30 } };
    for (junk) |p| {
        var s = (packet.Subscribe{ .packet_id = 1, .payload = p }).iterator();
        while (s.next()) |_| {}
        var u = (packet.Unsubscribe{ .packet_id = 1, .payload = p }).iterator();
        while (u.next()) |_| {}
        const props: packet.Properties = .{ .user_properties = .{ .raw = p }, .subscription_ids = .{ .raw = p } };
        _ = props.user_properties.count();
        _ = props.subscription_ids.count();
        _ = props.isEmpty();
    }
}

test "a 200 KB block of empty user properties decodes and counts in one pass (sweep MW-clean)" {
    const gpa = testing.allocator;
    const n = 40_000;
    const block = try gpa.alloc(u8, n * 5);
    defer gpa.free(block);
    for (0..n) |i| @memcpy(block[i * 5 ..][0..5], &[_]u8{ 0x26, 0, 0, 0, 0 });
    const p = try packet.decodePropertyEntries(block, .publish);
    try testing.expectEqual(@as(usize, n), p.user_properties.count());
}

test "topic matching and acl checks on a 64 KiB topic of empty levels (sweep MW-clean)" {
    const gpa = testing.allocator;
    const t = try gpa.alloc(u8, 65_535);
    defer gpa.free(t);
    @memset(t, '/');
    try testing.expect(topic.matches("#", t));
    try testing.expect(!topic.matches("+/+", t));
    try topic.validateName(t);
    const rules = [_]acl.Rule{
        .{ .scope = .pattern, .access = .deny, .topic = "%u/%c/#" },
        .{ .scope = .pattern, .access = .readwrite, .topic = "dev/%c/#" },
        .{ .scope = .anonymous, .access = .read, .topic = "+/+/+/+/#" },
    };
    const a = acl.Acl.init(&rules);
    _ = a.check(.{ .client_id = "c", .username = "u", .topic = t, .operation = .subscribe });
    _ = a.check(.{ .client_id = t[0..1000], .username = null, .topic = t, .operation = .publish });
    // a substituted identity that holds '/' never matches a pattern (fails closed on a deny)
    try testing.expect(!a.check(.{ .client_id = "a/b", .username = "u", .topic = "dev/a/b/x", .operation = .publish }));
    try testing.expect(a.check(.{ .client_id = "ok", .username = null, .topic = "dev/ok/x", .operation = .publish }));
}
