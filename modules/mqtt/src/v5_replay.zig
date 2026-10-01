// SPDX-License-Identifier: MIT

//! **External anchor for MQTT 5.0: real mosquitto and paho bytes, replayed.**
//!
//! `testdata/v5_transcript.txt` was taken live by `tools/interop.zig`
//! (`zig build interop-mqtt -- --capture`): this module's `Client` against
//! Eclipse Mosquitto 2.1.2, and paho-mqtt 2.1.0 clients against this module's
//! `Broker` — every step checked against what the real peer did or reported
//! before the bytes were written down. Here, with no peer and no socket:
//!
//! - **client**: every packet our `Client` sent decodes as 5.0 and re-encodes
//!   to the very bytes mosquitto accepted (an encoder that drifts from what a
//!   real broker took fails here); every packet mosquitto sent decodes — its
//!   CONNACK properties, reason codes, forwarded properties, topic aliases,
//!   DISCONNECT 0x8E — and carries what the live run saw.
//! - **broker**: paho's chunks go into a fresh `Broker` in the recorded order
//!   at the recorded clock, and every connection's output must equal, byte for
//!   byte, what paho received live. The live run serialized processing across
//!   connections, so this replay is deterministic.
//!
//! What it cannot do is accept a byte the peers never sent: that takes the
//! live program again (after any wire-visible change, before a release).

const std = @import("std");
const testing = std.testing;
const packet = @import("packet.zig");
const broker_mod = @import("broker.zig");

const transcript = @embedFile("testdata/v5_transcript.txt");

fn unhex(gpa: std.mem.Allocator, h: []const u8) ![]u8 {
    const out = try gpa.alloc(u8, h.len / 2);
    _ = try std.fmt.hexToBytes(out, h);
    return out;
}

/// The packets of one direction of one recorded connection.
fn packets(gpa: std.mem.Allocator, bytes: []const u8) ![]packet.Packet {
    var list: std.ArrayList(packet.Packet) = .empty;
    errdefer list.deinit(gpa);
    var off: usize = 0;
    while (off < bytes.len) {
        const d = (try packet.decodePacket(bytes[off..], .v5)) orelse return error.TruncatedRecording;
        try list.append(gpa, d.packet);
        off += d.consumed;
    }
    return list.toOwnedSlice(gpa);
}

fn userProps(gpa: std.mem.Allocator, p: packet.Properties) ![]u8 {
    var s: std.ArrayList(u8) = .empty;
    var it = p.user_properties.iterator();
    while (it.next()) |u| try s.print(gpa, "{s}={s};", .{ u.name, u.value });
    return s.toOwnedSlice(gpa);
}

test "v5 replay, client: our bytes re-encode to what mosquitto accepted; its bytes say what it said" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var c2s: [3][]const u8 = .{ &.{}, &.{}, &.{} };
    var s2c: [3][]const u8 = .{ &.{}, &.{}, &.{} };
    var in_case = false;
    var lines = std.mem.tokenizeScalar(u8, transcript, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "case ")) in_case = std.mem.eql(u8, line, "case client");
        if (!in_case or !std.mem.startsWith(u8, line, "conn ")) continue;
        var f = std.mem.tokenizeScalar(u8, line, ' ');
        _ = f.next();
        const conn = try std.fmt.parseInt(usize, f.next().?, 10);
        const dir = f.next().?;
        const bytes = try unhex(arena, f.next() orelse "");
        if (std.mem.eql(u8, dir, "c2s")) c2s[conn] = bytes else s2c[conn] = bytes;
    }

    // Ours: decode, re-encode, same bytes.
    var ours: usize = 0;
    for (c2s) |stream| {
        var off: usize = 0;
        while (off < stream.len) {
            const d = (try packet.decodePacket(stream[off..], .v5)).?;
            var buf: [1024]u8 = undefined;
            try testing.expectEqualSlices(u8, stream[off..][0..d.consumed], try packet.encodePacket(&buf, .v5, d.packet));
            off += d.consumed;
            ours += 1;
        }
    }
    try testing.expect(ours >= 20);

    // Theirs, connection 0: the whole session.
    const in0 = try packets(arena, s2c[0]);
    try testing.expectEqual(packet.ReasonCode.success, in0[0].connack.reason_code);
    try testing.expect(in0[0].connack.properties.topic_alias_maximum.? >= 1);
    var subacks: usize = 0;
    var forwarded: usize = 0;
    var aliased: usize = 0;
    var unsuback_ok = false;
    var will_ok = false;
    for (in0) |p| switch (p) {
        .suback => subacks += 1,
        .publish => |m| {
            if (m.properties.topic_alias != null) aliased += 1;
            const ups = try userProps(arena, m.properties);
            if (std.mem.eql(u8, ups, "a=1;b=2;")) {
                // Forwarded unaltered (3.3.2-4/15/16/17/20), with our
                // Subscription Identifier and the expiry counted down.
                try testing.expectEqualStrings("zl5/reply", m.properties.response_topic.?);
                try testing.expectEqualSlices(u8, "\x00\x2a", m.properties.correlation_data.?);
                try testing.expectEqualStrings("text/plain", m.properties.content_type.?);
                try testing.expectEqual(@as(?packet.PayloadFormat, .utf8), m.properties.payload_format);
                try testing.expect(m.properties.message_expiry_interval.? <= 300);
                try testing.expectEqual(@as(?u32, 7), m.properties.subscription_ids.first());
                forwarded += 1;
            }
            if (std.mem.eql(u8, ups, "why=lost;")) will_ok = std.mem.eql(u8, m.payload, "gone");
        },
        .unsuback => |u| unsuback_ok = std.mem.eql(u8, u.codes, &.{ 0x00, 0x11 }),
        else => {},
    };
    try testing.expect(subacks >= 4);
    try testing.expectEqual(@as(usize, 3), forwarded); // QoS 0, 1 and 2
    try testing.expect(unsuback_ok);
    try testing.expect(will_ok);
    // mosquitto aliases its deliveries to us (we announced 4 slots): five
    // PUBLISHes in this capture carry a Topic Alias, the empty-topic ones
    // included, and the live run resolved each to its topic — the external
    // anchor for the client's inbound alias handling. Pinned, so a different
    // capture says so.
    try testing.expectEqual(@as(usize, 5), aliased);

    // Connection 1 was taken over: CONNACK, then DISCONNECT 0x8E.
    const in1 = try packets(arena, s2c[1]);
    try testing.expectEqual(@as(usize, 2), in1.len);
    try testing.expectEqual(packet.ReasonCode.session_taken_over, in1[1].disconnect.reason_code);
}

/// A growable recording transport for the broker replay.
const Sink = struct {
    gpa: std.mem.Allocator,
    out: std.ArrayList(u8) = .empty,
    closed: bool = false,

    fn transport(s: *Sink) broker_mod.Transport {
        return .{ .ctx = s, .writeFn = writeFn, .closeFn = closeFn };
    }

    fn writeFn(ctx: *anyopaque, bytes: []const u8) broker_mod.TransportError!void {
        const s: *Sink = @ptrCast(@alignCast(ctx));
        s.out.appendSlice(s.gpa, bytes) catch return error.TransportFailed;
    }

    fn closeFn(ctx: *anyopaque) void {
        const s: *Sink = @ptrCast(@alignCast(ctx));
        s.closed = true;
    }
};

test "v5 replay, broker: paho's recorded chunks reproduce every byte paho received" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var b = broker_mod.Broker.init(testing.allocator, .{});
    defer b.deinit();
    const max_conns = 16;
    var sinks: [max_conns]Sink = undefined;
    for (&sinks) |*s| s.* = .{ .gpa = arena };
    var conns: [max_conns]?*broker_mod.Connection = @splat(null);
    var done: [max_conns]bool = @splat(false);
    var expected: [max_conns]?[]const u8 = @splat(null);
    var n_conns: usize = 0;

    var in_case = false;
    var lines = std.mem.tokenizeScalar(u8, transcript, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "case ")) in_case = std.mem.eql(u8, line, "case broker");
        if (!in_case) continue;
        var f = std.mem.tokenizeScalar(u8, line, ' ');
        const head = f.next().?;
        if (std.mem.eql(u8, head, "out")) {
            const i = try std.fmt.parseInt(usize, f.next().?, 10);
            expected[i] = try unhex(arena, f.next() orelse "");
            continue;
        }
        if (!std.mem.eql(u8, head, "at")) continue;
        const now = try std.fmt.parseInt(i64, f.next().?, 10);
        _ = f.next(); // "conn"
        const i = try std.fmt.parseInt(usize, f.next().?, 10);
        n_conns = @max(n_conns, i + 1);
        const what = f.next().?;
        if (conns[i] == null and !done[i]) conns[i] = try b.accept(sinks[i].transport());
        const conn = conns[i].?;
        if (std.mem.eql(u8, what, "close")) {
            b.remove(conn);
            conns[i] = null;
            done[i] = true;
            continue;
        }
        const bytes = try unhex(arena, f.next() orelse "");
        try b.feed(conn, bytes);
        _ = b.process(conn, now) catch {}; // a violation closes; its "close" line follows
    }
    try testing.expect(n_conns >= 8);
    for (0..n_conns) |i| {
        try testing.expectEqualSlices(u8, expected[i].?, sinks[i].out.items);
    }
}
