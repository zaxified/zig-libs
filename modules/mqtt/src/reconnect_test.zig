// SPDX-License-Identifier: MIT

//! Tests for `reconnect.zig` (backoff, subscription replay) and for the
//! client's in-flight resume outbox (`Client.Buffers.outbox`), driven from
//! in-memory buffers; the last one against the in-repo `Broker`.

const std = @import("std");
const testing = std.testing;
const packet = @import("packet.zig");
const client_mod = @import("client.zig");
const broker_mod = @import("broker.zig");
const reconnect = @import("reconnect.zig");

const Client = client_mod.Client;
const Reconnect = reconnect.Reconnect;
const SubscriptionSet = reconnect.SubscriptionSet;

// ── backoff ─────────────────────────────────────────────────────────────────

test "backoff: exact schedule, cap, reset" {
    var r = Reconnect.init(.{ .jitter = .none });
    try testing.expect(r.due(0)); // nothing scheduled: the first attempt is now
    try testing.expectEqual(@as(?u64, null), r.nextAttemptAt());
    const want = [_]u64{ 1000, 2000, 4000, 8000, 16000, 32000, 60000, 60000, 60000 };
    for (want, 1..) |w, n| {
        try testing.expectEqual(5000 + w, r.failed(5000, null));
        try testing.expectEqual(@as(u32, @intCast(n)), r.attempts());
        try testing.expectEqual(@as(?u64, 5000 + w), r.nextAttemptAt());
    }
    try testing.expect(!r.due(5000 + 59_999));
    try testing.expect(r.due(5000 + 60_000));
    r.connected();
    try testing.expectEqual(@as(u32, 0), r.attempts());
    try testing.expectEqual(@as(?u64, null), r.nextAttemptAt());
    try testing.expectEqual(@as(u64, 1000), r.failed(0, null));
}

test "backoff: multiplier 3, constant multipliers, initial above the cap, zero initial" {
    var r = Reconnect.init(.{ .initial_ms = 100, .max_ms = 1000, .multiplier = 3, .jitter = .none });
    for ([_]u64{ 100, 300, 900, 1000, 1000 }) |w| try testing.expectEqual(w, r.failed(0, null));
    var k = Reconnect.init(.{ .initial_ms = 250, .multiplier = 1, .jitter = .none });
    for (0..5) |_| try testing.expectEqual(@as(u64, 250), k.failed(0, null));
    var z = Reconnect.init(.{ .initial_ms = 250, .multiplier = 0, .jitter = .none });
    for (0..3) |_| try testing.expectEqual(@as(u64, 250), z.failed(0, null));
    var big = Reconnect.init(.{ .initial_ms = 5000, .max_ms = 100, .jitter = .none });
    try testing.expectEqual(@as(u64, 100), big.failed(0, null));
    var zero = Reconnect.init(.{ .initial_ms = 0, .jitter = .none });
    zero.failures = std.math.maxInt(u32) - 1; // would loop for ever without the zero guard
    try testing.expectEqual(@as(u64, 7), zero.failed(7, null));
}

test "backoff: saturating arithmetic never overflows" {
    const max = std.math.maxInt(u64);
    var r = Reconnect.init(.{ .initial_ms = max / 2 + 1, .max_ms = max, .multiplier = std.math.maxInt(u32), .jitter = .none });
    try testing.expectEqual(@as(u64, max), r.failed(max - 5, null)); // now + delay saturates
    r.failures = std.math.maxInt(u32);
    try testing.expectEqual(@as(u64, max), r.failed(1, null));
    try testing.expectEqual(std.math.maxInt(u32), r.attempts()); // the counter saturates too
    var j = Reconnect.init(.{ .initial_ms = max, .max_ms = max });
    // delay + 1 = 2^64: the high 32 bits scale it to 0xFFFFFFFF * 2^32, no overflow
    try testing.expectEqual(@as(u64, 0xFFFF_FFFF_0000_0000), j.failed(0, std.math.maxInt(u64)));
}

test "backoff: full jitter stays inside [0, delay]; null bits mean none" {
    var r = Reconnect.init(.{});
    try testing.expectEqual(@as(u64, 100), r.failed(100, 0)); // lowest bits: no wait
    // second failure: delay 2000
    try testing.expectEqual(@as(u64, 100 + 2000), r.failed(100, std.math.maxInt(u64))); // highest: the full delay
    // third failure: delay 4000; half of the range
    try testing.expectEqual(@as(u64, 100 + 2000), r.failed(100, 0x8000_0000_0000_0000));
    // the low half of the bits is ignored
    var a = Reconnect.init(.{});
    var b = Reconnect.init(.{});
    try testing.expectEqual(a.failed(0, 0x1234_5678_0000_0000), b.failed(0, 0x1234_5678_FFFF_FFFF));
    // null bits: the whole delay even with .full
    var n = Reconnect.init(.{});
    try testing.expectEqual(@as(u64, 1000), n.failed(0, null));
    // a sweep: always within bounds
    var prng = std.Random.DefaultPrng.init(0x5eed);
    var s = Reconnect.init(.{ .initial_ms = 10, .max_ms = 500 });
    for (0..200) |i| {
        s.failures = @intCast(i % 12);
        const at = s.failed(1000, prng.random().int(u64));
        try testing.expect(at >= 1000 and at <= 1500);
    }
}

// ── in-memory transport ─────────────────────────────────────────────────────

/// Captures every write whole, so a test can see packet boundaries.
const Wire = struct {
    buf: [4096]u8 = undefined,
    ends: [64]usize = undefined,
    n: usize = 0,
    fail: bool = false,

    fn transport(w: *Wire) client_mod.Transport {
        return .{ .ctx = w, .writeFn = writeFn };
    }

    fn writeFn(ctx: *anyopaque, bytes: []const u8) client_mod.TransportError!void {
        const w: *Wire = @ptrCast(@alignCast(ctx));
        if (w.fail) return error.TransportFailed;
        const start = if (w.n == 0) 0 else w.ends[w.n - 1];
        @memcpy(w.buf[start..][0..bytes.len], bytes);
        w.ends[w.n] = start + bytes.len;
        w.n += 1;
    }

    fn reset(w: *Wire) void {
        w.n = 0;
    }

    fn at(w: *const Wire, i: usize) []const u8 {
        const start = if (i == 0) 0 else w.ends[i - 1];
        return w.buf[start..w.ends[i]];
    }
};

test "SubscriptionSet: add, replace, remove, bounds" {
    var storage: [24]u8 = undefined;
    var slots: [3]SubscriptionSet.Entry = undefined;
    var s = SubscriptionSet.init(&storage, &slots);
    try s.add(.{ .filter = "a/b", .qos = .at_least_once });
    try s.add(.{ .filter = "c/#", .qos = .exactly_once, .no_local = true });
    try s.add(.{ .filter = "d/+", .qos = .at_most_once });
    try testing.expectEqual(@as(usize, 3), s.len());
    try testing.expectError(error.SubscriptionSetFull, s.add(.{ .filter = "e" })); // slots
    try testing.expectError(error.InvalidTopicFilter, s.add(.{ .filter = "a/#/b" }));
    // an equal filter replaces the options, keeps the place, takes no room
    try s.add(.{ .filter = "c/#", .qos = .at_least_once });
    try testing.expectEqual(@as(usize, 3), s.len());
    try testing.expectEqual(packet.QoS.at_least_once, s.slots[1].qos);
    try testing.expect(!s.slots[1].no_local);
    try testing.expect(!s.remove("zzz"));
    try testing.expect(s.remove("a/b"));
    try testing.expectEqual(@as(usize, 2), s.len());
    try testing.expectEqualStrings("c/#", s.storage[s.slots[0].offset..][0..s.slots[0].len]);
    try testing.expectEqualStrings("d/+", s.storage[s.slots[1].offset..][0..s.slots[1].len]);
    try s.add(.{ .filter = "x/y/z" });
    try testing.expectEqualStrings("x/y/z", s.storage[s.slots[2].offset..][0..s.slots[2].len]);
    // storage bound: 3 + 3 + 5 = 11 used, 24 total
    var small_storage: [4]u8 = undefined;
    var small_slots: [4]SubscriptionSet.Entry = undefined;
    var t = SubscriptionSet.init(&small_storage, &small_slots);
    try t.add(.{ .filter = "abc" });
    try testing.expectError(error.SubscriptionSetFull, t.add(.{ .filter = "de" }));
    try testing.expectEqual(@as(usize, 1), t.len());
}

fn makeConnected(w: *Wire, rx: []u8, tx: []u8, outbox: []u8, clean: bool) !Client {
    var c = Client.init(w.transport(), .{ .rx = rx, .tx = tx, .outbox = outbox });
    try connectAndAck(&c, w, 0, clean, false);
    return c;
}

fn connectAndAck(c: *Client, w: *Wire, now: u64, clean: bool, session_present: bool) !void {
    try c.connect(now, .{ .client_id = "cli", .clean_session = clean, .keep_alive_s = 60 });
    w.reset();
    var buf: [4]u8 = undefined;
    try c.feed(try packet.encodeConnack(&buf, .{ .session_present = session_present, .return_code = .accepted }));
    const ev = (try c.poll(now)).?;
    try testing.expect(ev == .connack);
}

test "SubscriptionSet.resubscribe: chunks of 32, options and order kept" {
    var wire = Wire{};
    var rx: [256]u8 = undefined;
    var tx: [1024]u8 = undefined;
    var c = try makeConnected(&wire, &rx, &tx, &.{}, true);
    wire.reset();

    var storage: [1024]u8 = undefined;
    var slots: [80]SubscriptionSet.Entry = undefined;
    var s = SubscriptionSet.init(&storage, &slots);
    try testing.expectEqual(@as(usize, 0), try s.resubscribe(&c, 1)); // empty set: nothing sent
    try testing.expectEqual(@as(usize, 0), wire.n);
    var name: [8]u8 = undefined;
    for (0..70) |i| {
        const f = try std.fmt.bufPrint(&name, "t/{d}", .{i});
        try s.add(.{ .filter = f, .qos = if (i == 40) .exactly_once else .at_least_once });
    }
    try testing.expectEqual(@as(usize, 3), try s.resubscribe(&c, 2));
    try testing.expectEqual(@as(usize, 3), wire.n);
    var seen: usize = 0;
    for (0..3) |p| {
        const sub = (try packet.decode(wire.at(p))).?.packet.subscribe;
        var it = sub.iterator();
        var in_packet: usize = 0;
        while (it.next()) |f| : (in_packet += 1) {
            const want = try std.fmt.bufPrint(&name, "t/{d}", .{seen});
            try testing.expectEqualStrings(want, f.filter);
            try testing.expectEqual(if (seen == 40) packet.QoS.exactly_once else packet.QoS.at_least_once, f.qos);
            seen += 1;
        }
        try testing.expectEqual(@as(usize, if (p < 2) 32 else 6), in_packet);
    }
    try testing.expectEqual(@as(usize, 70), seen);
}

// ── outbox ──────────────────────────────────────────────────────────────────

fn ack(buf: *[4]u8, comptime kind: enum { puback, pubrec, pubcomp }, id: u16) ![]const u8 {
    return switch (kind) {
        .puback => packet.encodePuback(buf, id),
        .pubrec => packet.encodePubrec(buf, id),
        .pubcomp => packet.encodePubcomp(buf, id),
    };
}

test "outbox: QoS 1 survives a lost connection and is resent with DUP, same id and bytes" {
    var wire = Wire{};
    var rx: [256]u8 = undefined;
    var tx: [256]u8 = undefined;
    var arena: [256]u8 = undefined;
    var c = try makeConnected(&wire, &rx, &tx, &arena, false);

    wire.reset();
    const id = (try c.publish(1, "a/b", "hi", .{ .qos = .at_least_once, .retain = true })).?;
    var orig: [64]u8 = undefined;
    const first = wire.at(0);
    @memcpy(orig[0..first.len], first);
    try testing.expectEqual(@as(usize, 1), c.outboxLen());
    try testing.expectEqual(first.len, c.outboxBytes());

    c.connectionLost();
    try testing.expectEqual(client_mod.ConnectionState.disconnected, c.state);
    try testing.expectEqual(@as(usize, 1), c.outboxLen());
    try testing.expectEqual(@as(usize, 1), c.pending_len);
    try testing.expectError(error.NotConnected, c.publish(2, "a/b", "x", .{ .qos = .at_least_once }));

    try connectAndAck(&c, &wire, 10, false, true);
    try testing.expectEqual(@as(usize, 1), wire.n);
    var want: [64]u8 = undefined;
    @memcpy(want[0..first.len], orig[0..first.len]);
    want[0] |= 0x08;
    try testing.expectEqualSlices(u8, want[0..first.len], wire.at(0));
    const p = (try packet.decode(wire.at(0))).?.packet.publish;
    try testing.expect(p.dup);
    try testing.expect(p.retain);
    try testing.expectEqual(id, p.packet_id);
    try testing.expectEqual(@as(usize, 0), c.outboxDropped());

    var buf: [4]u8 = undefined;
    try c.feed(try ack(&buf, .puback, id));
    try testing.expectEqual(id, (try c.poll(11)).?.puback.packet_id);
    try testing.expectEqual(@as(usize, 0), c.outboxLen());
    try testing.expectEqual(@as(usize, 0), c.outboxBytes());
    try testing.expectEqual(@as(usize, 0), c.pending_len);
}

test "outbox: Session Present resends in the original order, PUBREL for a PUBRECed QoS 2" {
    var wire = Wire{};
    var rx: [256]u8 = undefined;
    var tx: [256]u8 = undefined;
    var arena: [256]u8 = undefined;
    var c = try makeConnected(&wire, &rx, &tx, &arena, false);
    wire.reset();
    const a = (try c.publish(1, "t/a", "A", .{ .qos = .at_least_once })).?;
    const b = (try c.publish(1, "t/b", "B", .{ .qos = .exactly_once })).?;
    const d = (try c.publish(1, "t/c", "C", .{ .qos = .at_least_once })).?;
    var buf: [4]u8 = undefined;
    try c.feed(try ack(&buf, .pubrec, b)); // b: PUBREL goes out, its bytes are freed
    try testing.expectEqual(null, try c.poll(2));
    try testing.expectEqual(@as(usize, 3), c.outboxLen());
    try testing.expectEqual(wire.at(0).len + wire.at(2).len, c.outboxBytes());

    c.connectionLost();
    try connectAndAck(&c, &wire, 10, false, true);
    try testing.expectEqual(@as(usize, 3), wire.n);
    const pa = (try packet.decode(wire.at(0))).?.packet.publish;
    try testing.expect(pa.dup);
    try testing.expectEqual(a, pa.packet_id);
    try testing.expectEqualStrings("A", pa.payload);
    try testing.expectEqualSlices(u8, &.{ 0x62, 0x02, 0x00, @intCast(b) }, wire.at(1));
    const pc = (try packet.decode(wire.at(2))).?.packet.publish;
    try testing.expect(pc.dup);
    try testing.expectEqual(d, pc.packet_id);
    try testing.expectEqualStrings("t/c", pc.topic);

    // the handshake finishes normally afterwards
    try c.feed(try ack(&buf, .pubcomp, b));
    try testing.expectEqual(b, (try c.poll(11)).?.pubcomp.packet_id);
    try testing.expectEqual(@as(usize, 2), c.outboxLen());
}

test "outbox: Session Present = 0 resends PUBLISH with DUP=0 and drops the PUBRECed QoS 2" {
    var wire = Wire{};
    var rx: [256]u8 = undefined;
    var tx: [256]u8 = undefined;
    var arena: [256]u8 = undefined;
    var c = try makeConnected(&wire, &rx, &tx, &arena, false);
    wire.reset();
    const q2 = (try c.publish(1, "t/2", "two", .{ .qos = .exactly_once })).?;
    const q1 = (try c.publish(1, "t/1", "one", .{ .qos = .at_least_once })).?;
    var orig: [64]u8 = undefined;
    const q1_bytes = wire.at(1);
    @memcpy(orig[0..q1_bytes.len], q1_bytes);
    var buf: [4]u8 = undefined;
    try c.feed(try ack(&buf, .pubrec, q2));
    _ = try c.poll(2);

    c.connectionLost();
    try connectAndAck(&c, &wire, 10, false, false);
    try testing.expectEqual(@as(usize, 1), wire.n);
    try testing.expectEqualSlices(u8, orig[0..q1_bytes.len], wire.at(0)); // identical, DUP clear
    try testing.expectEqual(q1, (try packet.decode(wire.at(0))).?.packet.publish.packet_id);
    try testing.expectEqual(@as(usize, 1), c.outboxDropped());
    try testing.expectEqual(@as(usize, 1), c.outboxLen());
    try testing.expectEqual(@as(usize, 1), c.pending_len);
    // the dropped message's id is free again; a stray PUBCOMP for it is a violation
    try c.feed(try ack(&buf, .pubcomp, q2));
    try testing.expectError(error.ProtocolViolation, c.poll(11));
}

test "outbox: a clean connect empties it; disabled outbox behaves as before" {
    var wire = Wire{};
    var rx: [256]u8 = undefined;
    var tx: [256]u8 = undefined;
    var arena: [256]u8 = undefined;
    var c = try makeConnected(&wire, &rx, &tx, &arena, false);
    _ = try c.publish(1, "t", "x", .{ .qos = .at_least_once });
    c.connectionLost();
    try connectAndAck(&c, &wire, 10, true, false);
    try testing.expectEqual(@as(usize, 0), c.outboxLen());
    try testing.expectEqual(@as(usize, 0), c.outboxBytes());
    try testing.expectEqual(@as(usize, 0), c.pending_len);
    try testing.expectEqual(@as(usize, 0), wire.n);

    // no outbox configured: even clean_session = false resets and resends nothing
    var wire2 = Wire{};
    var c2 = try makeConnected(&wire2, &rx, &tx, &.{}, false);
    _ = try c2.publish(1, "t", "x", .{ .qos = .at_least_once });
    try testing.expectEqual(@as(usize, 1), c2.pending_len);
    try testing.expectEqual(@as(usize, 0), c2.outboxLen());
    c2.connectionLost();
    try connectAndAck(&c2, &wire2, 10, false, true);
    try testing.expectEqual(@as(usize, 0), wire2.n);
    try testing.expectEqual(@as(usize, 0), c2.pending_len);
}

test "outbox: OutboxFull sends nothing and releases the id; acks make room" {
    var wire = Wire{};
    var rx: [256]u8 = undefined;
    var tx: [256]u8 = undefined;
    var arena: [20]u8 = undefined;
    var c = try makeConnected(&wire, &rx, &tx, &arena, false);
    wire.reset();
    const big = "0123456789012345678901234567890";
    try testing.expectError(error.OutboxFull, c.publish(1, "t", big, .{ .qos = .at_least_once }));
    try testing.expectEqual(@as(usize, 0), wire.n);
    try testing.expectEqual(@as(usize, 0), c.pending_len);
    try testing.expectEqual(@as(usize, 0), c.outboxLen());
    // QoS 0 never touches the outbox
    try testing.expectEqual(@as(?u16, null), try c.publish(1, "t", big, .{}));
    const id = (try c.publish(1, "t", "x", .{ .qos = .at_least_once })).?;
    // fill: each small publish is 8 bytes; two fit in 20, the third does not
    _ = try c.publish(1, "t", "y", .{ .qos = .at_least_once });
    try testing.expectError(error.OutboxFull, c.publish(1, "t", "z", .{ .qos = .at_least_once }));
    var buf: [4]u8 = undefined;
    try c.feed(try ack(&buf, .puback, id));
    _ = try c.poll(2);
    _ = try c.publish(3, "t", "z", .{ .qos = .at_least_once });
    try testing.expectEqual(@as(usize, 2), c.outboxLen());
    try testing.expectEqual(@as(usize, 16), c.outboxBytes());
}

test "outbox: a failed write leaves no entry behind" {
    var wire = Wire{};
    var rx: [256]u8 = undefined;
    var tx: [256]u8 = undefined;
    var arena: [64]u8 = undefined;
    var c = try makeConnected(&wire, &rx, &tx, &arena, false);
    wire.fail = true;
    try testing.expectError(error.TransportFailed, c.publish(1, "t", "x", .{ .qos = .at_least_once }));
    try testing.expectEqual(@as(usize, 0), c.outboxLen());
    try testing.expectEqual(@as(usize, 0), c.pending_len);
}

fn connack5(buf: []u8, session_present: bool, props: packet.Properties) ![]const u8 {
    return packet.encodePacket(buf, .v5, .{ .connack = .{ .session_present = session_present, .reason_code = .success, .properties = props } });
}

fn connect5(c: *Client, w: *Wire, now: u64, session_present: bool, props: packet.Properties) !void {
    try c.connect(now, .{ .client_id = "cli", .clean_session = false, .version = .v5 });
    w.reset();
    var buf: [64]u8 = undefined;
    try c.feed(try connack5(&buf, session_present, props));
    try testing.expect((try c.poll(now)).? == .connack);
}

test "outbox (5.0): a smaller Receive Maximum holds the rest back until acks free the quota" {
    var wire = Wire{};
    var rx: [256]u8 = undefined;
    var tx: [256]u8 = undefined;
    var arena: [256]u8 = undefined;
    var c = Client.init(wire.transport(), .{ .rx = &rx, .tx = &tx, .outbox = &arena });
    try connect5(&c, &wire, 0, false, .{});
    var ids: [3]u16 = undefined;
    for (&ids) |*id| id.* = (try c.publish(1, "t", "p", .{ .qos = .at_least_once })).?;
    c.connectionLost();
    try connect5(&c, &wire, 10, true, .{ .receive_maximum = 1 });
    try testing.expectEqual(@as(usize, 1), wire.n);
    try testing.expectEqual(ids[0], (try packet.decodePacket(wire.at(0), .v5)).?.packet.publish.packet_id);
    try testing.expectError(error.ReceiveMaximumReached, c.publish(11, "t", "n", .{ .qos = .at_least_once }));

    var buf: [8]u8 = undefined;
    for (1..3) |i| {
        try c.feed(try packet.encodePacket(&buf, .v5, .{ .puback = .{ .packet_id = ids[i - 1] } }));
        try testing.expect((try c.poll(12)).? == .puback);
        try testing.expectEqual(i + 1, wire.n);
        const p = (try packet.decodePacket(wire.at(i), .v5)).?.packet.publish;
        try testing.expectEqual(ids[i], p.packet_id);
        try testing.expect(p.dup);
    }
}

test "outbox (5.0): entries over the new Maximum Packet Size or QoS are dropped; alias-only publishes refused" {
    var wire = Wire{};
    var rx: [256]u8 = undefined;
    var tx: [256]u8 = undefined;
    var arena: [256]u8 = undefined;
    var c = Client.init(wire.transport(), .{ .rx = &rx, .tx = &tx, .outbox = &arena });
    try connect5(&c, &wire, 0, false, .{ .topic_alias_maximum = 4 });
    _ = try c.publish(1, "t", "short", .{ .qos = .at_least_once });
    _ = try c.publish(1, "t", "a much longer payload than the other one", .{ .qos = .at_least_once });
    _ = try c.publish(1, "q", "two", .{ .qos = .exactly_once });
    // an alias set with a topic is self-contained; one without a topic is not resendable
    try testing.expectEqual(@as(?u16, null), try c.publish(1, "", "x", .{ .properties = .{ .topic_alias = 1 } })); // QoS 0: fine
    try testing.expectError(error.TopicAliasInvalid, c.publish(1, "", "x", .{ .qos = .at_least_once, .properties = .{ .topic_alias = 1 } }));
    try testing.expectEqual(@as(usize, 3), c.outboxLen());

    c.connectionLost();
    try connect5(&c, &wire, 10, true, .{ .maximum_packet_size = 20, .maximum_qos = .at_least_once });
    try testing.expectEqual(@as(usize, 1), wire.n); // only the short QoS 1 one
    try testing.expectEqual(@as(usize, 2), c.outboxDropped());
    try testing.expectEqual(@as(usize, 1), c.outboxLen());
    try testing.expectEqual(@as(usize, 1), c.pending_len);
}

// ── against the in-repo broker ──────────────────────────────────────────────

/// The broker's view of a client connection: captures what it writes.
const BrokerSink = struct {
    buf: [1024]u8 = undefined,
    len: usize = 0,

    fn transport(s: *BrokerSink) broker_mod.Transport {
        return .{ .ctx = s, .writeFn = writeFn };
    }

    fn writeFn(ctx: *anyopaque, bytes: []const u8) broker_mod.TransportError!void {
        const s: *BrokerSink = @ptrCast(@alignCast(ctx));
        @memcpy(s.buf[s.len..][0..bytes.len], bytes);
        s.len += bytes.len;
    }

    /// Hand everything the broker wrote to the client and clear.
    fn deliver(s: *BrokerSink, c: *Client) !void {
        try c.feed(s.buf[0..s.len]);
        s.len = 0;
    }
};

/// Hand the client's captured writes to the broker connection.
fn pump(b: *broker_mod.Broker, conn: *broker_mod.Connection, w: *Wire, now: i64) !void {
    for (0..w.n) |i| try b.feed(conn, w.at(i));
    w.reset();
    try testing.expectEqual(broker_mod.Disposition.keep, try b.process(conn, now));
}

test "outbox end to end: a QoS 1 publish whose PUBACK was lost is resent to a persistent session" {
    var b = broker_mod.Broker.init(testing.allocator, .{});
    defer b.deinit();
    var wire = Wire{};
    var rx: [256]u8 = undefined;
    var tx: [256]u8 = undefined;
    var arena: [256]u8 = undefined;
    var c = Client.init(wire.transport(), .{ .rx = &rx, .tx = &tx, .outbox = &arena });

    // First connection: session created, publish reaches the broker, its PUBACK is lost.
    var sink1 = BrokerSink{};
    const conn1 = try b.accept(sink1.transport());
    try c.connect(0, .{ .client_id = "egw", .clean_session = false });
    try pump(&b, conn1, &wire, 0);
    try sink1.deliver(&c);
    var ev = (try c.poll(0)).?;
    try testing.expect(!ev.connack.session_present);
    const id = (try c.publish(1, "egw/1/t", "20.5", .{ .qos = .at_least_once })).?;
    try pump(&b, conn1, &wire, 1);
    sink1.len = 0; // the PUBACK never arrives
    try testing.expectEqual(@as(usize, 1), c.outboxLen());
    c.connectionLost();
    b.remove(conn1);

    // Second connection: the broker still has the session; the client resends on its own.
    var sink2 = BrokerSink{};
    const conn2 = try b.accept(sink2.transport());
    try c.connect(10, .{ .client_id = "egw", .clean_session = false });
    try pump(&b, conn2, &wire, 10);
    try sink2.deliver(&c);
    ev = (try c.poll(10)).?; // CONNACK: the resend goes out here
    try testing.expect(ev.connack.session_present);
    try testing.expectEqual(@as(usize, 1), wire.n);
    const resent = (try packet.decode(wire.at(0))).?.packet.publish;
    try testing.expect(resent.dup);
    try testing.expectEqual(id, resent.packet_id);
    try pump(&b, conn2, &wire, 11);
    try sink2.deliver(&c);
    ev = (try c.poll(11)).?;
    try testing.expectEqual(id, ev.puback.packet_id);
    try testing.expectEqual(@as(usize, 0), c.outboxLen());
    b.remove(conn2);
}
