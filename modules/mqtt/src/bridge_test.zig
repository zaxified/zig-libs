// SPDX-License-Identifier: MIT

//! Tests for `bridge.zig`: two in-process brokers (local and remote) joined
//! by a `Bridge` over byte pipes, no sockets.

const std = @import("std");
const testing = std.testing;
const packet = @import("packet.zig");
const broker_mod = @import("broker.zig");
const client_mod = @import("client.zig");
const bridge_mod = @import("bridge.zig");
const reconnect_mod = @import("reconnect.zig");

const Broker = broker_mod.Broker;
const Connection = broker_mod.Connection;
const Bridge = bridge_mod.Bridge;

/// What a broker wrote to one connection; `next` decodes it in order.
const Sink = struct {
    buf: [4096]u8 = undefined,
    len: usize = 0,
    read: usize = 0,
    fed: usize = 0,

    fn transport(s: *Sink) broker_mod.Transport {
        return .{ .ctx = s, .writeFn = writeFn };
    }

    fn writeFn(ctx: *anyopaque, bytes: []const u8) broker_mod.TransportError!void {
        const s: *Sink = @ptrCast(@alignCast(ctx));
        if (s.len + bytes.len > s.buf.len) return error.TransportFailed;
        @memcpy(s.buf[s.len..][0..bytes.len], bytes);
        s.len += bytes.len;
    }

    fn next(s: *Sink) !?packet.Packet {
        if (s.read >= s.len) return null;
        const dec = (try packet.decode(s.buf[s.read..s.len])) orelse return null;
        s.read += dec.consumed;
        return dec.packet;
    }

    /// The next PUBLISH, skipping nothing: any other packet is a failure.
    fn nextPublish(s: *Sink) !packet.Publish {
        const p = (try s.next()) orelse return error.NoPacket;
        return switch (p) {
            .publish => |x| x,
            else => error.NotAPublish,
        };
    }
};

/// A plain 3.1.1 client of one of the brokers.
const Peer = struct {
    b: *Broker,
    conn: *Connection,
    sink: *Sink,

    fn open(b: *Broker, sink: *Sink, id: []const u8) !Peer {
        const conn = try b.accept(sink.transport());
        var buf: [128]u8 = undefined;
        try b.feed(conn, try packet.encodeConnect(&buf, .{ .client_id = id }));
        try testing.expectEqual(broker_mod.Disposition.keep, try b.process(conn, 0));
        try testing.expect((try sink.next()).? == .connack);
        return .{ .b = b, .conn = conn, .sink = sink };
    }

    fn subscribe(p: Peer, filter: []const u8, qos: packet.QoS) !void {
        var buf: [256]u8 = undefined;
        try p.b.feed(p.conn, try packet.encodeSubscribe(&buf, 1, &.{.{ .filter = filter, .qos = qos }}));
        _ = try p.b.process(p.conn, 0);
        try testing.expect((try p.sink.next()).? == .suback);
    }

    fn publish(p: Peer, topic_name: []const u8, payload: []const u8, qos: packet.QoS, retain: bool) !void {
        var buf: [512]u8 = undefined;
        const id: u16 = if (qos == .at_most_once) 0 else 7;
        try p.b.feed(p.conn, try packet.encodePublish(&buf, .{ .topic = topic_name, .payload = payload, .qos = qos, .retain = retain, .packet_id = id }));
        _ = try p.b.process(p.conn, 0);
        if (qos != .at_most_once) try testing.expect((try p.sink.next()).? == .puback);
    }
};

/// Everything the bridge sends toward the remote broker.
const Wire = struct {
    buf: [4096]u8 = undefined,
    len: usize = 0,

    fn transport(w: *Wire) client_mod.Transport {
        return .{ .ctx = w, .writeFn = writeFn };
    }

    fn writeFn(ctx: *anyopaque, bytes: []const u8) client_mod.TransportError!void {
        const w: *Wire = @ptrCast(@alignCast(ctx));
        if (w.len + bytes.len > w.buf.len) return error.TransportFailed;
        @memcpy(w.buf[w.len..][0..bytes.len], bytes);
        w.len += bytes.len;
    }
};

const Harness = struct {
    local: Broker,
    remote: Broker,
    bridge: Bridge,
    wire: Wire = .{},
    rsink: Sink = .{},
    rconn: ?*Connection = null,
    local_rx: [2048]u8 = undefined,
    local_tx: [2048]u8 = undefined,
    pipe_up: [4096]u8 = undefined,
    pipe_down: [4096]u8 = undefined,
    remote_rx: [2048]u8 = undefined,
    remote_tx: [2048]u8 = undefined,
    outbox: [2048]u8 = undefined,
    sub_storage: [512]u8 = undefined,
    sub_slots: [8]reconnect_mod.SubscriptionSet.Entry = undefined,

    fn create(config: bridge_mod.Config) !*Harness {
        const h = try testing.allocator.create(Harness);
        h.* = .{ .local = Broker.init(testing.allocator, .{}), .remote = Broker.init(testing.allocator, .{}), .bridge = undefined };
        try h.bridge.init(&h.local, config, .{
            .local_rx = &h.local_rx,
            .local_tx = &h.local_tx,
            .pipe_up = &h.pipe_up,
            .pipe_down = &h.pipe_down,
            .remote_rx = &h.remote_rx,
            .remote_tx = &h.remote_tx,
            .remote_outbox = &h.outbox,
            .sub_storage = &h.sub_storage,
            .sub_slots = &h.sub_slots,
        }, h.wire.transport());
        try h.bridge.start(0);
        return h;
    }

    fn destroy(h: *Harness) void {
        h.bridge.deinit();
        h.local.deinit();
        h.remote.deinit();
        testing.allocator.destroy(h);
    }

    fn dial(h: *Harness, now: u64) !void {
        try testing.expect(h.bridge.wantConnect(now));
        h.rsink = .{};
        h.wire.len = 0;
        h.rconn = try h.remote.accept(h.rsink.transport());
        try h.bridge.remoteOpened(now);
    }

    /// Run bytes between the bridge and the remote broker until quiet.
    fn step(h: *Harness, now: u64) !void {
        var i: usize = 0;
        while (i < 12) : (i += 1) {
            var moved = false;
            if (h.rconn) |c| {
                if (h.wire.len > 0) {
                    try h.remote.feed(c, h.wire.buf[0..h.wire.len]);
                    h.wire.len = 0;
                    moved = true;
                    _ = try h.remote.process(c, @intCast(now));
                }
                if (h.rsink.len > h.rsink.fed) {
                    try h.bridge.remoteBytes(h.rsink.buf[h.rsink.fed..h.rsink.len]);
                    h.rsink.fed = h.rsink.len;
                    moved = true;
                }
            }
            if (try h.bridge.poll(now) == .remote_lost) return error.RemoteLost;
            if (h.wire.len > 0) moved = true;
            if (!moved) break;
        }
    }

    /// The link dies: whatever was in flight is gone.
    fn drop(h: *Harness, now: u64) u64 {
        h.wire.len = 0;
        if (h.rconn) |c| h.remote.remove(c);
        h.rconn = null;
        return h.bridge.connectionLost(now, null);
    }
};

fn rules1(r: []const bridge_mod.Rule) bridge_mod.Config {
    return .{ .rules = r, .remote_client_id = "bridge" };
}

test "bridge: an out rule forwards local messages with the prefix rewritten" {
    const rules = [_]bridge_mod.Rule{.{ .pattern = "sensors/#", .direction = .out, .qos = .at_least_once, .remote_prefix = "site1/" }};
    const h = try Harness.create(rules1(&rules));
    defer h.destroy();
    try h.dial(0);
    try h.step(0);
    try testing.expect(h.bridge.remoteUp());

    var rs = Sink{};
    const rpeer = try Peer.open(&h.remote, &rs, "r1");
    try rpeer.subscribe("#", .at_least_once);
    var ls = Sink{};
    const lpeer = try Peer.open(&h.local, &ls, "l1");

    try lpeer.publish("sensors/room/t", "21.5", .at_least_once, false);
    try lpeer.publish("other/x", "no", .at_most_once, false);
    try h.step(1);
    const got = try rs.nextPublish();
    try testing.expectEqualStrings("site1/sensors/room/t", got.topic);
    try testing.expectEqualStrings("21.5", got.payload);
    try testing.expectEqual(packet.QoS.at_least_once, got.qos);
    try testing.expect((try rs.next()) == null); // other/x stayed home
    try testing.expectEqual(@as(u64, 1), h.bridge.stats().forwarded_out);

    // a message the broker itself publishes is forwarded too
    try h.local.publish("sensors/srv", "up", .at_most_once, false);
    try h.step(2);
    try testing.expectEqualStrings("site1/sensors/srv", (try rs.nextPublish()).topic);
}

test "bridge: an in rule re-publishes remote messages locally, retain kept" {
    const rules = [_]bridge_mod.Rule{.{ .pattern = "cmd/#", .direction = .in, .qos = .at_least_once, .local_prefix = "from-remote/" }};
    var cfg = rules1(&rules);
    cfg.version = .v5; // Retain As Published: a 3.1.1 remote clears RETAIN on live deliveries
    const h = try Harness.create(cfg);
    defer h.destroy();
    try h.dial(0);
    try h.step(0);

    var ls = Sink{};
    const lpeer = try Peer.open(&h.local, &ls, "l1");
    try lpeer.subscribe("from-remote/#", .at_least_once);
    var rs = Sink{};
    const rpeer = try Peer.open(&h.remote, &rs, "r1");
    try rpeer.publish("cmd/a/b", "go", .at_least_once, true);
    try rpeer.publish("elsewhere", "no", .at_most_once, false);
    try h.step(1);
    const got = try ls.nextPublish();
    try testing.expectEqualStrings("from-remote/cmd/a/b", got.topic);
    try testing.expectEqualStrings("go", got.payload);
    try testing.expect((try ls.next()) == null);
    try testing.expectEqual(@as(u64, 1), h.bridge.stats().forwarded_in);

    // the retained flag was kept: a later local subscriber receives it as retained
    var ls2 = Sink{};
    const late = try Peer.open(&h.local, &ls2, "l2");
    try late.subscribe("from-remote/#", .at_least_once);
    const ret = try ls2.nextPublish();
    try testing.expect(ret.retain);
    try testing.expectEqualStrings("go", ret.payload);
}

test "bridge: both directions do not loop, with a 3.1.1 and a 5.0 remote" {
    for ([_]packet.Version{ .v3_1_1, .v5 }) |version| {
        const rules = [_]bridge_mod.Rule{.{ .pattern = "shared/#", .direction = .both, .remote_prefix = "far/", .local_prefix = "near/" }};
        var cfg = rules1(&rules);
        cfg.version = version;
        const h = try Harness.create(cfg);
        defer h.destroy();
        try h.dial(0);
        try h.step(0);

        var ls = Sink{};
        const lpeer = try Peer.open(&h.local, &ls, "l1");
        try lpeer.subscribe("near/#", .at_most_once);
        var ls2 = Sink{};
        const lpub = try Peer.open(&h.local, &ls2, "l2");
        var rs = Sink{};
        const rpeer = try Peer.open(&h.remote, &rs, "r1");
        try rpeer.subscribe("far/#", .at_most_once);
        var rs2 = Sink{};
        const rpub = try Peer.open(&h.remote, &rs2, "r2");

        try lpub.publish("near/shared/x", "A", .at_most_once, false);
        try h.step(1);
        try testing.expectEqualStrings("far/shared/x", (try rs.nextPublish()).topic);
        try testing.expect((try rs.next()) == null); // exactly once on the remote
        try testing.expectEqualStrings("near/shared/x", (try ls.nextPublish()).topic); // the local subscriber's own copy
        try testing.expect((try ls.next()) == null); // and no echo from the remote

        try rpub.publish("far/shared/y", "B", .at_most_once, false);
        try h.step(2);
        try testing.expectEqualStrings("near/shared/y", (try ls.nextPublish()).topic);
        try testing.expect((try ls.next()) == null);
        try testing.expectEqualStrings("far/shared/y", (try rs.nextPublish()).topic); // remote's own subscriber
        try testing.expect((try rs.next()) == null);

        const st = h.bridge.stats();
        try testing.expectEqual(@as(u64, 1), st.forwarded_out);
        try testing.expectEqual(@as(u64, 1), st.forwarded_in);
        // 5.0: the remote broker never echoed (No Local); 3.1.1: the bridge dropped the echo
        try testing.expectEqual(@as(u64, if (version == .v5) 0 else 1), st.echoes_suppressed);
    }
}

test "bridge: a QoS 1 message in flight when the link drops is resent after the reconnect" {
    const rules = [_]bridge_mod.Rule{.{ .pattern = "up/#", .direction = .out, .qos = .at_least_once }};
    const h = try Harness.create(rules1(&rules));
    defer h.destroy();
    try h.dial(0);
    try h.step(0);
    var rs = Sink{};
    const rpeer = try Peer.open(&h.remote, &rs, "r1");
    try rpeer.subscribe("up/#", .at_least_once);
    var ls = Sink{};
    const lpeer = try Peer.open(&h.local, &ls, "l1");

    // the PUBLISH leaves the bridge but never reaches the remote
    try lpeer.publish("up/m", "payload", .at_least_once, false);
    _ = try h.bridge.poll(10);
    try testing.expect(h.wire.len > 0);
    try testing.expectEqual(@as(usize, 1), h.bridge.remote_client.outboxLen());
    const next_at = h.drop(10);
    try testing.expectEqual(@as(u64, 10 + 1000), next_at);
    try testing.expect(!h.bridge.remoteUp());
    try testing.expect(!h.bridge.wantConnect(500)); // backoff not elapsed
    try testing.expectEqual(@as(usize, 1), h.bridge.remote_client.outboxLen()); // kept

    // while down, further local messages are dropped and counted
    try lpeer.publish("up/lost", "x", .at_most_once, false);
    _ = try h.bridge.poll(600);
    try testing.expectEqual(@as(u64, 1), h.bridge.stats().dropped);

    try testing.expect(h.bridge.wantConnect(1010));
    try h.dial(1010);
    try h.step(1010);
    try testing.expect(h.bridge.remoteUp());
    const got = try rs.nextPublish();
    try testing.expectEqualStrings("up/m", got.topic);
    try testing.expectEqualStrings("payload", got.payload);
    try testing.expect((try rs.next()) == null);
    try testing.expectEqual(@as(usize, 0), h.bridge.remote_client.outboxLen()); // PUBACKed
    try testing.expectEqual(@as(u32, 0), h.bridge.schedule.attempts()); // reset by the CONNACK
}

test "bridge: the notification topic is 1 when up, 0 when the link is lost" {
    const rules = [_]bridge_mod.Rule{.{ .pattern = "none/#", .direction = .out }};
    var cfg = rules1(&rules);
    cfg.notification_topic = "bridges/b1/state";
    const h = try Harness.create(cfg);
    defer h.destroy();

    var ls = Sink{};
    const lpeer = try Peer.open(&h.local, &ls, "l1");
    try lpeer.subscribe("bridges/#", .at_least_once);
    const initial = try ls.nextPublish();
    try testing.expectEqualStrings("0", initial.payload);
    try testing.expect(initial.retain);

    try h.dial(0);
    var rs = Sink{};
    const rpeer = try Peer.open(&h.remote, &rs, "r1");
    try rpeer.subscribe("bridges/#", .at_least_once);
    try h.step(0);
    try testing.expectEqualStrings("1", (try ls.nextPublish()).payload);
    const remote_up = try rs.nextPublish();
    try testing.expectEqualStrings("bridges/b1/state", remote_up.topic);
    try testing.expectEqualStrings("1", remote_up.payload);

    _ = h.drop(5);
    try testing.expectEqualStrings("0", (try ls.nextPublish()).payload); // local, from connectionLost
    const will = try rs.nextPublish(); // remote, the Will
    try testing.expectEqualStrings("0", will.payload);
}

test "bridge: wildcard rule patterns pick the right messages" {
    const rules = [_]bridge_mod.Rule{
        .{ .pattern = "+/temp", .direction = .out },
        .{ .pattern = "dev/+/#", .direction = .in, .local_prefix = "r/" },
    };
    const h = try Harness.create(rules1(&rules));
    defer h.destroy();
    try h.dial(0);
    try h.step(0);

    var rs = Sink{};
    const rpeer = try Peer.open(&h.remote, &rs, "r1");
    try rpeer.subscribe("#", .at_most_once);
    var ls = Sink{};
    const lpeer = try Peer.open(&h.local, &ls, "l1");
    try lpeer.subscribe("r/#", .at_most_once);

    try lpeer.publish("room1/temp", "1", .at_most_once, false);
    try lpeer.publish("room1/hum", "2", .at_most_once, false);
    try lpeer.publish("room1/x/temp", "3", .at_most_once, false);
    try h.step(1);
    try testing.expectEqualStrings("room1/temp", (try rs.nextPublish()).topic);
    try testing.expect((try rs.next()) == null);

    try rpeer.publish("dev/7", "yes", .at_most_once, false); // `#` also matches the parent level
    try rpeer.publish("dev/7/a/b", "yes", .at_most_once, false);
    try rpeer.publish("other/7/a", "no", .at_most_once, false);
    _ = try rs.next(); // the broker echoes the remote peer's own publishes to itself
    _ = try rs.next();
    _ = try rs.next();
    try h.step(2);
    var seen: usize = 0;
    while (try ls.next()) |p| {
        seen += 1;
        try testing.expect(std.mem.startsWith(u8, p.publish.topic, "r/dev/7"));
    }
    try testing.expectEqual(@as(usize, 2), seen); // dev/7 and dev/7/a/b
}
