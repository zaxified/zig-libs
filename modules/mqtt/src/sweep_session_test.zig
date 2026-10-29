// SPDX-License-Identifier: MIT

//! Tests for the no-panic sweep of the mqtt session layer (wave GM, gm-b):
//! broker, client, bridge. One test per finding, named `(sweep MS-n)`.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const packet = @import("packet.zig");
const broker_mod = @import("broker.zig");
const client_mod = @import("client.zig");
const bridge_mod = @import("bridge.zig");
const reconnect_mod = @import("reconnect.zig");

const Broker = broker_mod.Broker;
const Bridge = bridge_mod.Bridge;
const Client = client_mod.Client;

/// Counts what a broker writes to one connection.
const Counting = struct {
    bytes: usize = 0,
    packets: usize = 0,

    fn transport(m: *Counting) broker_mod.Transport {
        return .{ .ctx = m, .writeFn = writeFn };
    }
    fn writeFn(ctx: *anyopaque, bytes: []const u8) broker_mod.TransportError!void {
        const m: *Counting = @ptrCast(@alignCast(ctx));
        m.bytes += bytes.len;
        m.packets += 1;
    }
};

const Discard = struct {
    fn transport(d: *Discard) client_mod.Transport {
        return .{ .ctx = d, .writeFn = writeFn };
    }
    fn writeFn(_: *anyopaque, _: []const u8) client_mod.TransportError!void {}
};

/// A bridge over a local broker with caller-sized buffers.
const BridgeRig = struct {
    local: Broker,
    bridge: Bridge = undefined,
    discard: Discard = .{},
    local_rx: [1024]u8 = undefined,
    local_tx: [1024]u8 = undefined,
    pipe_up: [4096]u8 = undefined,
    pipe_down: [4096]u8 = undefined,
    remote_rx: [4096]u8 = undefined,
    remote_tx: [1024]u8 = undefined,
    sub_storage: [256]u8 = undefined,
    sub_slots: [4]reconnect_mod.SubscriptionSet.Entry = undefined,

    fn init(r: *BridgeRig, broker_cfg: broker_mod.Config, config: bridge_mod.Config) !void {
        r.local = Broker.init(testing.allocator, broker_cfg);
        errdefer r.local.deinit();
        try r.bridge.init(&r.local, config, .{
            .local_rx = &r.local_rx,
            .local_tx = &r.local_tx,
            .pipe_up = &r.pipe_up,
            .pipe_down = &r.pipe_down,
            .remote_rx = &r.remote_rx,
            .remote_tx = &r.remote_tx,
            .sub_storage = &r.sub_storage,
            .sub_slots = &r.sub_slots,
        }, r.discard.transport());
    }

    fn deinit(r: *BridgeRig) void {
        r.bridge.deinit();
        r.local.deinit();
    }
};

test "an empty Response Topic does not index past it when a prefix starts with '$' (sweep MS-1)" {
    const rig = try testing.allocator.create(BridgeRig);
    defer testing.allocator.destroy(rig);
    try rig.init(.{}, .{
        .rules = &.{.{ .pattern = "$X/#", .direction = .out, .remote_prefix = "$r/" }},
        .remote_client_id = "r",
        .version = .v5,
    });
    defer rig.deinit();
    try rig.bridge.start(0);
    // Remote down: the message is dropped, but its properties are mapped first.
    try rig.local.publishWith("$X/a", "p", .{ .properties = .{ .response_topic = "" } });
    try testing.expectEqual(bridge_mod.Status.ok, try rig.bridge.poll(0));
    try testing.expectEqual(@as(u64, 1), rig.bridge.stats().dropped);
}

test "a clock above maxInt(i64) is clamped, not cast (sweep MS-2)" {
    const rig = try testing.allocator.create(BridgeRig);
    defer testing.allocator.destroy(rig);
    try rig.init(.{}, .{
        .rules = &.{.{ .pattern = "#", .direction = .out }},
        .remote_client_id = "r",
    });
    defer rig.deinit();
    try rig.bridge.start(std.math.maxInt(u64));
    try testing.expectEqual(bridge_mod.Status.ok, try rig.bridge.poll(std.math.maxInt(u64)));
}

test "Client.tick near the end of the u64 clock saturates (sweep MS-3)" {
    var rx: [64]u8 = undefined;
    var tx: [64]u8 = undefined;
    var d: Discard = .{};
    var c = Client.init(d.transport(), .{ .rx = &rx, .tx = &tx });
    const late = std.math.maxInt(u64) - 1;
    try c.connect(late, .{ .client_id = "c", .keep_alive_s = 10 });
    try c.feed(&.{ 0x20, 0x02, 0x00, 0x00 });
    try testing.expect((try c.poll(late)).? == .connack);
    try c.tick(std.math.maxInt(u64)); // last_tx + keep-alive would overflow
    try testing.expect(c.awaiting_pingresp);
    try testing.expectError(error.KeepAliveTimeout, c.tick(std.math.maxInt(u64))); // ping_sent + keep-alive likewise
}

test "broker clock arithmetic saturates at the ends of the i64 clock (sweep MS-4)" {
    var b = Broker.init(testing.allocator, .{ .session_expiry_ms = 1000 });
    defer b.deinit();

    // Message Expiry: now + 5000 ms.
    try b.publishWith("a/b", "x", .{ .message_expiry_s = 5, .now = std.math.maxInt(i64) });

    // Keep-alive deadline: last_packet_ms + 1.5 * keep-alive.
    var c1: Counting = .{};
    const conn = try b.accept(c1.transport());
    var buf: [64]u8 = undefined;
    try b.feed(conn, try packet.encodeConnect(&buf, .{ .client_id = "k", .keep_alive_s = 10 }));
    try testing.expectEqual(broker_mod.Disposition.keep, try b.process(conn, std.math.maxInt(i64)));
    try testing.expect(!b.keepAliveExpired(conn, std.math.maxInt(i64)));

    // Session age: now - offline_since_ms.
    var c2: Counting = .{};
    const pc = try b.accept(c2.transport());
    try b.feed(pc, try packet.encodeConnect(&buf, .{ .client_id = "persist", .clean_session = false }));
    _ = try b.process(pc, 5);
    b.remove(pc);
    try testing.expectEqual(@as(usize, 0), b.expireSessions(std.math.minInt(i64)));
    try testing.expectEqual(@as(usize, 1), b.sessionCount());
    b.remove(conn);

    // Retained store: now - age, now + expiry, expiry left, age.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try b.restoreRetained(&.{.{ .topic = "r/t", .payload = "x", .qos = .at_most_once, .expires_in_ms = 5, .age_ms = 5 }}, std.math.maxInt(i64));
    const items = try b.retainedMessages(arena, std.math.minInt(i64));
    try testing.expectEqual(@as(usize, 1), items.len);
}

fn monoNs() u64 {
    return @intCast(std.Io.Timestamp.now(testing.io, .awake).nanoseconds);
}

/// Runs `run(n)` and `run(4 n)` three times each and asserts the best times
/// grow like linear work (4x), not quadratic (16x): ratio < 9. A ratio, not an
/// absolute bound: it holds under CI load and in any optimize mode.
fn expectLinear(comptime run: fn (usize) anyerror!u64, n: usize) !void {
    var t1: u64 = std.math.maxInt(u64);
    var t4: u64 = std.math.maxInt(u64);
    for (0..3) |_| {
        t1 = @min(t1, try run(n));
        t4 = @min(t4, try run(4 * n));
    }
    if (t4 >= 9 * @max(t1, 1)) {
        std.debug.print("\nnot linear: n={d} {d} ns, 4n {d} ns (x{d:.1})\n", .{ n, t1, t4, @as(f64, @floatFromInt(t4)) / @as(f64, @floatFromInt(@max(t1, 1))) });
        return error.NotLinear;
    }
}

/// Time for the broker to process `packets` pipelined PINGREQs in one buffer.
fn pipelinedNs(packets: usize) anyerror!u64 {
    var b = Broker.init(testing.allocator, .{ .max_packet_size = 1 << 18 });
    defer b.deinit();
    var ct: Counting = .{};
    const conn = try b.accept(ct.transport());
    var buf: [64]u8 = undefined;
    try b.feed(conn, try packet.encodeConnect(&buf, .{ .client_id = "p", .keep_alive_s = 0 }));
    _ = try b.process(conn, 0);
    const sent = ct.packets;

    const chunk = try testing.allocator.alloc(u8, packets * 2);
    defer testing.allocator.free(chunk);
    var i: usize = 0;
    while (i < chunk.len) : (i += 2) {
        chunk[i] = 0xC0;
        chunk[i + 1] = 0x00;
    }
    try b.feed(conn, chunk);
    const t0 = monoNs();
    try testing.expectEqual(broker_mod.Disposition.keep, try b.process(conn, 1));
    const took = monoNs() - t0;
    try testing.expectEqual(packets, ct.packets - sent);
    return took;
}

test "N pipelined tiny packets are not a memmove each (sweep MS-5)" {
    // Compacting the rest of the buffer after every packet is quadratic in
    // the packets of one buffer.
    try expectLinear(pipelinedNs, 16384);
}

/// Time for a client to poll `packets` pipelined PINGRESPs from one buffer.
fn clientPollNs(packets: usize) anyerror!u64 {
    const rx = try testing.allocator.alloc(u8, 1 << 18);
    defer testing.allocator.free(rx);
    var tx: [64]u8 = undefined;
    var d: Discard = .{};
    var c = Client.init(d.transport(), .{ .rx = rx, .tx = &tx });
    try c.connect(0, .{ .client_id = "c" });
    try c.feed(&.{ 0x20, 0x02, 0x00, 0x00 });
    try testing.expect((try c.poll(0)).? == .connack);
    const chunk = try testing.allocator.alloc(u8, packets * 2);
    defer testing.allocator.free(chunk);
    var n: usize = 0;
    while (n < chunk.len) : (n += 2) {
        chunk[n] = 0xD0; // PINGRESP
        chunk[n + 1] = 0x00;
    }
    try c.feed(chunk);
    const t0 = monoNs();
    var events: usize = 0;
    while (try c.poll(1)) |_| events += 1;
    const took = monoNs() - t0;
    try testing.expectEqual(packets, events);
    return took;
}

test "Client.poll over a full buffer of tiny packets is not quadratic (sweep MS-6)" {
    try expectLinear(clientPollNs, 16384);
}

test "a burst larger than the local broker's receive buffer does not wedge the bridge (sweep MS-7)" {
    const rig = try testing.allocator.create(BridgeRig);
    defer testing.allocator.destroy(rig);
    try rig.init(.{ .max_packet_size = 512 }, .{
        .rules = &.{.{ .pattern = "#", .direction = .in }},
        .remote_client_id = "r",
    });
    defer rig.deinit();
    try rig.bridge.start(0);

    // A local subscriber that counts what arrives.
    var sub: Counting = .{};
    const sc = try rig.local.accept(sub.transport());
    var buf: [128]u8 = undefined;
    try rig.local.feed(sc, try packet.encodeConnect(&buf, .{ .client_id = "sub" }));
    _ = try rig.local.process(sc, 0);
    try rig.local.feed(sc, try packet.encodeSubscribe(&buf, 1, &.{.{ .filter = "#" }}));
    _ = try rig.local.process(sc, 0);
    const before = sub.packets;

    try rig.bridge.remoteOpened(0);
    // CONNACK, then 30 QoS 0 messages (~50 bytes each) in ONE read: the local
    // client's PUBLISHes (1.5 KB) exceed the 512-byte receive buffer.
    var wire: [2048]u8 = undefined;
    var len: usize = 0;
    @memcpy(wire[0..4], &[_]u8{ 0x20, 0x02, 0x00, 0x00 });
    len = 4;
    for (0..30) |_| {
        const p = try packet.encodePublish(wire[len..], .{ .topic = "r/x", .payload = "0123456789012345678901234567890123456789" });
        len += p.len;
    }
    try rig.bridge.remoteBytes(wire[0..len]);
    var polls: usize = 0;
    while (polls < 8 and rig.bridge.stats().forwarded_in < 30) : (polls += 1) {
        try testing.expectEqual(bridge_mod.Status.ok, try rig.bridge.poll(1));
    }
    try testing.expectEqual(@as(u64, 30), rig.bridge.stats().forwarded_in);
    _ = try rig.bridge.poll(2);
    _ = try rig.bridge.poll(3);
    try testing.expectEqual(@as(usize, 30), sub.packets - before);
}

fn serveTask(srv: *broker_mod.TcpServer) void {
    srv.serve() catch {};
}

test "TcpServer takes pipelined packets that straddle its read size (sweep MS-8)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var b = Broker.init(testing.allocator, .{});
    defer b.deinit();
    var srv = broker_mod.TcpServer.init(io, &b);
    srv.bind("127.0.0.1", 0) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    defer srv.deinit();
    var serving = try io.concurrent(serveTask, .{&srv});
    const stream = srv.boundAddress().connect(io, .{ .mode = .stream }) catch |err| {
        srv.shutdown();
        serving.await(io);
        return testkit.loopbackSkip("loopback connect failed ({t})", .{err});
    };

    // 7000 + 8000 + 3000 bytes in one write: with 4096-byte reads the second
    // packet is incomplete (5288 buffered) when a full read of the third's
    // head arrives, 9384 > the 8192-byte receive buffer.
    const total = 7000 + 8000 + 3000;
    const all = try testing.allocator.alloc(u8, total + 64);
    defer testing.allocator.free(all);
    var cbuf: [64]u8 = undefined;
    var len: usize = 0;
    const conn_bytes = try packet.encodeConnect(&cbuf, .{ .client_id = "pipe", .keep_alive_s = 30 });
    @memcpy(all[0..conn_bytes.len], conn_bytes);
    len = conn_bytes.len;
    for ([_]usize{ 7000, 8000, 3000 }) |plen| {
        const payload = try testing.allocator.alloc(u8, plen - 16);
        defer testing.allocator.free(payload);
        @memset(payload, 'x');
        const p = try packet.encodePublish(all[len..], .{ .topic = "t/big", .payload = payload });
        len += p.len;
    }
    all[len] = 0xC0; // PINGREQ
    all[len + 1] = 0x00;
    len += 2;

    var wbuf: [64]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    var rbuf: [64]u8 = undefined;
    var r = stream.reader(io, &rbuf);
    var ok = true;
    w.interface.writeAll(all[0..len]) catch {
        ok = false;
    };
    w.interface.flush() catch {
        ok = false;
    };
    // CONNACK, then PINGRESP: the connection survived every packet.
    if (ok) {
        const ack: ?u8 = if (r.interface.takeArray(4)) |a| a[0] else |_| null;
        const pong: ?u8 = if (r.interface.takeArray(2)) |a| a[0] else |_| null;
        ok = ack == 0x20 and pong == 0xD0;
    }
    stream.close(io);
    srv.shutdown();
    serving.await(io);
    try testing.expect(ok);
}

test "an announced body above the receive buffer is never buffered past it, either side (sweep MS-9)" {
    // PUBLISH QoS 0, remaining length 100 000 (3 varint bytes), body not sent.
    var head: [64]u8 = undefined;
    const hdr = [_]u8{ 0x30, 0xA0, 0x8D, 0x06, 0x00, 0x01, 't' };
    @memcpy(head[0..hdr.len], &hdr);

    var b = Broker.init(testing.allocator, .{ .max_packet_size = 256 });
    defer b.deinit();
    var ct: Counting = .{};
    const conn = try b.accept(ct.transport());
    var cb: [64]u8 = undefined;
    try b.feed(conn, try packet.encodeConnect(&cb, .{ .client_id = "big" }));
    _ = try b.process(conn, 0);
    var junk: [256]u8 = @splat('x');
    try b.feed(conn, head[0..hdr.len]);
    try b.feed(conn, junk[0 .. 256 - hdr.len]);
    try testing.expectEqual(broker_mod.Disposition.keep, try b.process(conn, 1));
    try testing.expectEqual(@as(usize, 0), b.rxRoom(conn)); // full: the caller drops the connection
    try testing.expectError(error.RxBufferFull, b.feed(conn, junk[0..1]));

    var rx: [128]u8 = undefined;
    var tx: [64]u8 = undefined;
    var d: Discard = .{};
    var c = Client.init(d.transport(), .{ .rx = &rx, .tx = &tx });
    try c.connect(0, .{ .client_id = "c" });
    try c.feed(&.{ 0x20, 0x02, 0x00, 0x00 });
    _ = try c.poll(0);
    try c.feed(head[0..hdr.len]);
    try c.feed(junk[0 .. 128 - hdr.len]);
    try testing.expectEqual(@as(?client_mod.Event, null), try c.poll(1));
    try testing.expectEqual(@as(usize, 0), c.rxRoom());
    try testing.expectError(error.RxBufferFull, c.feed(junk[0..1]));
}

/// Keeps the last thing the broker wrote to one connection, and counts them.
const Capture = struct {
    last: [64]u8 = undefined,
    len: usize = 0,
    packets: usize = 0,

    fn transport(m: *Capture) broker_mod.Transport {
        return .{ .ctx = m, .writeFn = writeFn };
    }
    fn writeFn(ctx: *anyopaque, bytes: []const u8) broker_mod.TransportError!void {
        const m: *Capture = @ptrCast(@alignCast(ctx));
        m.len = @min(bytes.len, m.last.len);
        @memcpy(m.last[0..m.len], bytes[0..m.len]);
        m.packets += 1;
    }
};

/// A 3.1.1 SUBSCRIBE of one filter; the SUBACK's return code.
fn subscribeCode(b: *Broker, conn: *broker_mod.Connection, cap: *Capture, filter: []const u8) !u8 {
    var buf: [256]u8 = undefined;
    try b.feed(conn, try packet.encodeSubscribe(&buf, 1, &.{.{ .filter = filter }}));
    _ = try b.process(conn, 0);
    try testing.expectEqual(@as(u8, 0x90), cap.last[0]); // SUBACK
    return cap.last[cap.len - 1];
}

test "trie nodes are counted against max_subscription_nodes (sweep R-MQ-5)" {
    var b = Broker.init(testing.allocator, .{ .max_subscription_nodes = 10 });
    defer b.deinit();
    var cap: Capture = .{};
    const conn = try b.accept(cap.transport());
    var buf: [64]u8 = undefined;
    try b.feed(conn, try packet.encodeConnect(&buf, .{ .client_id = "deep" }));
    _ = try b.process(conn, 0);

    try testing.expectEqual(@as(u8, 0), try subscribeCode(&b, conn, &cap, "a/b/c/d/e/f/g/h")); // 8 nodes
    try testing.expectEqual(@as(u8, 0x80), try subscribeCode(&b, conn, &cap, "x/y/z/w")); // 12 > 10
    try testing.expectEqual(@as(u8, 0x80), try subscribeCode(&b, conn, &cap, "a/b/c/d/e/f/g/h/i/j/k")); // 11 > 10
    try testing.expectEqual(@as(u8, 0), try subscribeCode(&b, conn, &cap, "a/b/c/d/e/f/g/h/i")); // 9
    try testing.expectEqual(@as(u8, 0), try subscribeCode(&b, conn, &cap, "a/b/c/#")); // shares nodes: 0 new
    // The refused filters changed nothing: the old subscription still delivers.
    const before = cap.packets;
    try b.publishWith("a/b/c/d/e/f/g/h", "x", .{});
    try testing.expectEqual(before + 1, cap.packets);

    // Nodes freed by UNSUBSCRIBE are uncounted: room for a new filter.
    var ub: [256]u8 = undefined;
    for ([_][]const u8{ "a/b/c/d/e/f/g/h/i", "a/b/c/#" }) |f| {
        try b.feed(conn, try packet.encodeUnsubscribe(&ub, 2, &.{f}));
        _ = try b.process(conn, 0);
    }
    try testing.expectEqual(@as(u8, 0x80), try subscribeCode(&b, conn, &cap, "x/y/z/w")); // 8 + 4 > 10
    try b.feed(conn, try packet.encodeUnsubscribe(&ub, 3, &.{"a/b/c/d/e/f/g/h"}));
    _ = try b.process(conn, 0);
    try testing.expectEqual(@as(u8, 0), try subscribeCode(&b, conn, &cap, "x/y/z/w"));
}

/// `n` connections each subscribed to the same 8 filters, all matching a/b:
/// time of one PUBLISH to a/b, which must reach each of them once.
fn fanoutNs(n: usize) anyerror!u64 {
    var b = Broker.init(testing.allocator, .{ .max_connections = 4096 });
    defer b.deinit();
    const sinks = try testing.allocator.alloc(Counting, n);
    defer testing.allocator.free(sinks);
    @memset(sinks, .{});
    const filters = [_]packet.Subscription{
        .{ .filter = "a/b" }, .{ .filter = "a/+" }, .{ .filter = "+/b" }, .{ .filter = "+/+" },
        .{ .filter = "a/#" }, .{ .filter = "+/#" }, .{ .filter = "#" },   .{ .filter = "a/b/#" },
    };
    var buf: [256]u8 = undefined;
    var id: [16]u8 = undefined;
    for (sinks, 0..) |*sink, i| {
        const conn = try b.accept(sink.transport());
        const cid = try std.fmt.bufPrint(&id, "c{d}", .{i});
        try b.feed(conn, try packet.encodeConnect(&buf, .{ .client_id = cid }));
        _ = try b.process(conn, 0);
        try b.feed(conn, try packet.encodeSubscribe(&buf, 1, &filters));
        _ = try b.process(conn, 0);
    }
    const t0 = monoNs();
    try b.publishWith("a/b", "x", .{});
    const took = monoNs() - t0;
    for (sinks) |s| try testing.expectEqual(@as(usize, 3), s.packets); // CONNACK, SUBACK, one PUBLISH
    return took;
}

test "a PUBLISH to many owners with overlapping filters is linear in the matches (sweep R-MQ-2)" {
    try expectLinear(fanoutNs, 256);
}

/// `n` live retained messages, then `n` that all expire together: time of the
/// sweep. (Expiring ones alone would hide a rescan: each is found at the
/// front of the list; the live prefix is what a rescan has to walk past.)
fn sweepNs(n: usize) anyerror!u64 {
    var b = Broker.init(testing.allocator, .{});
    defer b.deinit();
    const items = try testing.allocator.alloc(Broker.RetainedState, 2 * n);
    defer testing.allocator.free(items);
    const names = try testing.allocator.alloc([12]u8, 2 * n);
    defer testing.allocator.free(names);
    for (items, names, 0..) |*it, *name, i| {
        const t = try std.fmt.bufPrint(name, "r/{d:0>8}", .{i});
        it.* = .{ .topic = t, .payload = "x", .qos = .at_most_once, .expires_in_ms = if (i < n) null else 5 };
    }
    try b.restoreRetained(items, 0);
    const t0 = monoNs();
    _ = b.expireSessions(1000);
    const took = monoNs() - t0;
    try testing.expectEqual(@as(u64, n), b.messagesExpired());
    return took;
}

test "expiring many retained messages at once is a single pass (sweep R-MQ-10)" {
    try expectLinear(sweepNs, 768);
}

fn floodTask(io: std.Io, stream: std.Io.net.Stream) void {
    var wbuf: [64]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    var msg: [8192]u8 = undefined;
    var payload: [8000]u8 = undefined;
    @memset(&payload, 'x');
    const p = packet.encodePublish(&msg, .{ .topic = "t/x", .payload = &payload }) catch return;
    for (0..3000) |_| w.interface.writeAll(p) catch return;
    w.interface.writeAll(&.{ 0xC0, 0x00 }) catch return; // PINGREQ
    w.interface.flush() catch return;
}

test "a subscriber that never reads does not stall publishers (sweep R-MQ-1)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var b = Broker.init(testing.allocator, .{});
    defer b.deinit();
    var srv = broker_mod.TcpServer.init(io, &b);
    srv.write_timeout_ms = 300;
    srv.bind("127.0.0.1", 0) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    defer srv.deinit();
    var serving = try io.concurrent(serveTask, .{&srv});
    const sub = srv.boundAddress().connect(io, .{ .mode = .stream }) catch |err| {
        srv.shutdown();
        serving.await(io);
        return testkit.loopbackSkip("loopback connect failed ({t})", .{err});
    };
    const pubs = srv.boundAddress().connect(io, .{ .mode = .stream }) catch {
        sub.close(io);
        srv.shutdown();
        serving.await(io);
        return error.SkipZigTest;
    };
    const small = std.mem.toBytes(@as(c_int, 2048));
    std.posix.setsockopt(sub.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVBUF, &small) catch {};

    var ok = true;
    var flood: ?std.Io.Future(void) = null;
    run: {
        var buf: [128]u8 = undefined;
        // The subscriber: keep-alive 0 (no watchdog deadline), `#`, then never reads again.
        var sw = sub.writer(io, &buf);
        var sr_buf: [16]u8 = undefined;
        var sr = sub.reader(io, &sr_buf);
        var pk: [64]u8 = undefined;
        sw.interface.writeAll(packet.encodeConnect(&pk, .{ .client_id = "mute", .keep_alive_s = 0 }) catch break :run) catch break :run;
        sw.interface.writeAll(packet.encodeSubscribe(&pk, 1, &.{.{ .filter = "#" }}) catch break :run) catch break :run;
        sw.interface.flush() catch break :run;
        _ = sr.interface.takeArray(4) catch break :run; // CONNACK
        _ = sr.interface.takeArray(5) catch break :run; // SUBACK

        var pw = pubs.writer(io, &buf);
        var pr_buf: [16]u8 = undefined;
        var pr = pubs.reader(io, &pr_buf);
        pw.interface.writeAll(packet.encodeConnect(&pk, .{ .client_id = "pub", .keep_alive_s = 0 }) catch break :run) catch break :run;
        pw.interface.flush() catch break :run;
        _ = pr.interface.takeArray(4) catch break :run; // CONNACK

        flood = io.concurrent(floodTask, .{ io, pubs }) catch break :run;
        // PINGRESP = the publisher's connection got through all 3000 publishes.
        var fds = [_]std.posix.pollfd{.{ .fd = pubs.socket.handle, .events = std.posix.POLL.IN, .revents = 0 }};
        const ready = std.posix.poll(&fds, 10_000) catch 0;
        if (ready == 0) {
            ok = false;
            break :run;
        }
        const pong = pr.interface.takeArray(2) catch break :run;
        ok = pong[0] == 0xD0;
        break :run;
    }
    // Unblock everything whatever happened, then close.
    pubs.shutdown(io, .both) catch {};
    sub.shutdown(io, .both) catch {};
    if (flood) |*f| f.await(io);
    pubs.close(io);
    sub.close(io);
    srv.shutdown();
    serving.await(io);
    try testing.expect(ok);
}
