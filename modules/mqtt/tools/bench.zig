// SPDX-License-Identifier: MIT

//! Comparative benchmark: the `mqtt` broker against Eclipse Mosquitto 2.1.2
//! (the card's reference), the program behind the `**Performance:**` line of
//! the maturity card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-mqtt` runs it (always
//! ReleaseFast). Needs podman and the image `docker.io/library/eclipse-mosquitto:2`
//! (2.1.2 when measured; `podman pull` it first — this program never pulls).
//! Run from the repository root.
//!
//! Both brokers are loaded by the SAME driver below — raw TCP over loopback,
//! packets built and parsed with this module's codec, MQTT 3.1.1, so whatever
//! the driver costs, it costs both sides. Ours runs in this process
//! (`TcpServer`, thread per connection, default `Config`); Mosquitto runs as
//! `mosquitto -c` with `listener <port> 127.0.0.1`, `allow_anonymous true` and
//! `set_tcp_nodelay true`, `max_queued_messages 0` (otherwise defaults; ours:
//! `TcpServer.tcp_nodelay`, unbounded `max_queued_*` — see `ours`)
//! in a host-network container, from a copy of its binary exactly as
//! `tools/interop.zig` does (an AppArmor profile attaches by path).
//!
//! Workloads (64-byte payloads unless named; one unit = the per-op figure):
//! - `qos0_1to1` — 200 000 QoS 0 messages, 1 publisher → 1 subscriber; per message.
//! - `qos1_1to1` — 100 000 QoS 1, publisher window 64, subscriber at QoS 1; per message.
//! - `qos2_1to1` — 20 000 QoS 2, window 10, subscriber at QoS 2; per message.
//!   (At window 32 Mosquitto 2.1.2 stops answering: past ~20 unreleased inbound
//!   QoS 2 publishes at its defaults it sends no PUBREC, measured 2026-10-17.)
//! - `qos0_fanout100` — 10 000 QoS 0 messages to 100 subscribers; per delivery.
//! - `qos0_fanin32` — 32 publishers × 5 000 → 1 subscriber; per message.
//! - `rtt_1k` — 5 000 round trips of a 1 KiB QoS 0 message to a client's own
//!   subscription, one at a time; per round trip (latency).
//! - `connect` — 500 sequential CONNECT → CONNACK → DISCONNECT; per connection.
//!
//! Timing: from the first publish to the last message counted by the
//! subscriber(s). Each side runs `BENCH_ROUNDS` (default 3) times, the sides
//! alternating, each keeping its best. A row in which a side delivered fewer
//! messages than were sent is marked LOST and fails the run (Mosquitto drops
//! QoS 0 for a subscriber whose queue is full; a ratio over different work
//! means nothing). A watchdog ends the program — container removed — if a row
//! takes over 120 s.

const std = @import("std");
const mqtt = @import("mqtt");
const packet = mqtt.packet;
const net = std.Io.net;

const image = "docker.io/library/eclipse-mosquitto:2";
const payload_len = 64;

const Row = enum { qos0_1to1, qos1_1to1, qos2_1to1, qos0_fanout100, qos0_fanin32, rtt_1k, connect };

var io_g: std.Io = undefined;
var container_id_buf: [80]u8 = undefined;
var container_id_len: std.atomic.Value(usize) = .init(0);
var deadline_ns: std.atomic.Value(i64) = .init(std.math.maxInt(i64));
/// Which broker the running row is loading, for the watchdog's message.
var side: std.atomic.Value(u8) = .init(0);

fn nowNs() i64 {
    return @intCast(std.Io.Clock.Timestamp.now(io_g, .awake).raw.nanoseconds);
}

// ── one raw client connection ──────────────────────────────────────────────

const Raw = struct {
    t: mqtt.TcpTransport,
    rx: []u8,
    len: usize = 0,
    start: usize = 0,
    tx: std.ArrayList(u8) = .empty,
    gpa: std.mem.Allocator,

    fn open(gpa: std.mem.Allocator, addr: net.IpAddress, client_id: []const u8) !Raw {
        var r: Raw = .{ .t = try mqtt.TcpTransport.connect(io_g, addr), .rx = try gpa.alloc(u8, 1 << 18), .gpa = gpa };
        // The driver's own Nagle + the peer's delayed ACK would stall every
        // window (40 ms each) and measure the kernel, not the broker.
        const one: c_int = 1;
        std.posix.setsockopt(r.t.stream.socket.handle, std.posix.IPPROTO.TCP, std.posix.TCP.NODELAY, std.mem.asBytes(&one)) catch {};
        var buf: [256]u8 = undefined;
        try r.send(try packet.encodeConnect(&buf, .{ .client_id = client_id, .keep_alive_s = 0 }));
        const p = try r.next();
        if (p != .connack or p.connack.return_code != .accepted) return error.ConnectRefused;
        return r;
    }

    fn close(r: *Raw) void {
        var buf: [8]u8 = undefined;
        if (packet.encodePacket(&buf, .v3_1_1, .{ .disconnect = .{} })) |b| r.send(b) catch {} else |_| {}
        r.t.close();
        r.tx.deinit(r.gpa);
        r.gpa.free(r.rx);
    }

    fn send(r: *Raw, bytes: []const u8) !void {
        try r.t.transport().write(bytes);
    }

    /// Queue bytes; `flush` writes them in one go.
    fn queue(r: *Raw, comptime f: anytype, args: anytype) !void {
        var buf: [1200]u8 = undefined;
        try r.tx.appendSlice(r.gpa, try @call(.auto, f, .{&buf} ++ args));
    }

    fn flush(r: *Raw) !void {
        if (r.tx.items.len == 0) return;
        try r.send(r.tx.items);
        r.tx.clearRetainingCapacity();
    }

    fn hasBuffered(r: *Raw) bool {
        return (packet.decodePacket(r.rx[r.start..r.len], .v3_1_1) catch return true) != null;
    }

    /// The next packet; blocks (after flushing queued acks) when none is buffered.
    fn next(r: *Raw) !packet.Packet {
        while (true) {
            if (try packet.decodePacket(r.rx[r.start..r.len], .v3_1_1)) |d| {
                r.start += d.consumed;
                return d.packet;
            }
            try r.flush();
            if (r.start > 0) {
                std.mem.copyForwards(u8, r.rx, r.rx[r.start..r.len]);
                r.len -= r.start;
                r.start = 0;
            }
            const n = try r.t.readSome(r.rx[r.len..]);
            if (n == 0) return error.EndOfStream;
            r.len += n;
        }
    }

    fn subscribe(r: *Raw, filter: []const u8, qos: packet.QoS) !void {
        var buf: [300]u8 = undefined;
        try r.send(try packet.encodePacket(&buf, .v3_1_1, .{ .subscribe = .{ .packet_id = 1, .filters = &.{.{ .filter = filter, .qos = qos }} } }));
        while (true) if ((try r.next()) == .suback) return;
    }
};

fn encPublish(buf: []u8, topic: []const u8, payload: []const u8, qos: packet.QoS, id: u16) packet.EncodeError![]const u8 {
    return packet.encodePublish(buf, .{ .topic = topic, .payload = payload, .qos = qos, .packet_id = id });
}

fn encAck(buf: []u8, comptime kind: std.meta.Tag(packet.Packet), id: u16) packet.EncodeError![]const u8 {
    return packet.encodePacket(buf, .v3_1_1, @unionInit(packet.Packet, @tagName(kind), .{ .packet_id = id }));
}

// ── workload pieces ────────────────────────────────────────────────────────

const Sub = struct {
    raw: Raw,
    want: usize,
    got: usize = 0,
    end_ns: i64 = 0,
    err: ?anyerror = null,

    fn run(s: *Sub) void {
        s.loop() catch |e| {
            s.err = e;
        };
        s.end_ns = nowNs();
    }

    fn loop(s: *Sub) !void {
        while (s.got < s.want) {
            switch (try s.raw.next()) {
                .publish => |p| {
                    switch (p.qos) {
                        .at_most_once => {},
                        .at_least_once => try s.raw.queue(encAck, .{ .puback, p.packet_id }),
                        .exactly_once => try s.raw.queue(encAck, .{ .pubrec, p.packet_id }),
                    }
                    s.got += 1;
                },
                .pubrel => |a| try s.raw.queue(encAck, .{ .pubcomp, a.packet_id }),
                else => {},
            }
            if (!s.raw.hasBuffered()) try s.raw.flush();
        }
        // Answer what is still owed (QoS 2 PUBRELs of the last messages).
        try s.raw.flush();
    }
};

fn publishMany(raw: *Raw, topic: []const u8, count: usize, qos: packet.QoS, window: usize) !void {
    const payload: [payload_len]u8 = @splat('x');
    var sent: usize = 0;
    while (sent < count) {
        const n = @min(if (qos == .at_most_once) 512 else window, count - sent);
        for (0..n) |i| try raw.queue(encPublish, .{ topic, &payload, qos, @as(u16, @intCast(i + 1)) });
        try raw.flush();
        sent += n;
        if (qos == .at_most_once) continue;
        var done: usize = 0;
        while (done < n) switch (try raw.next()) {
            .puback => done += 1,
            .pubrec => |a| {
                try raw.queue(encAck, .{ .pubrel, a.packet_id });
                if (!raw.hasBuffered()) try raw.flush();
            },
            .pubcomp => done += 1,
            else => {},
        };
    }
}

const Pub = struct {
    raw: Raw,
    topic: []const u8,
    count: usize,
    err: ?anyerror = null,
    fn run(p: *Pub) void {
        publishMany(&p.raw, p.topic, p.count, .at_most_once, 0) catch |e| {
            p.err = e;
        };
    }
};

/// One measurement of `row` against the broker at `addr`: ns per unit.
fn measure(gpa: std.mem.Allocator, addr: net.IpAddress, row: Row) !f64 {
    deadline_ns.store(nowNs() + 120 * std.time.ns_per_s, .release);
    defer deadline_ns.store(std.math.maxInt(i64), .release);
    switch (row) {
        .qos0_1to1, .qos1_1to1, .qos2_1to1 => {
            const qos: packet.QoS, const count: usize, const window: usize = switch (row) {
                .qos0_1to1 => .{ .at_most_once, 200_000, 0 },
                .qos1_1to1 => .{ .at_least_once, 100_000, 64 },
                else => .{ .exactly_once, 20_000, 10 },
            };
            var sub: Sub = .{ .raw = try Raw.open(gpa, addr, "bench-sub"), .want = count };
            defer sub.raw.close();
            try sub.raw.subscribe("bench/1to1", qos);
            var publisher = try Raw.open(gpa, addr, "bench-pub");
            defer publisher.close();
            const th = try std.Thread.spawn(.{}, Sub.run, .{&sub});
            const t0 = nowNs();
            try publishMany(&publisher, "bench/1to1", count, qos, window);
            th.join();
            if (sub.err) |e| return e;
            if (sub.got != count) return error.Lost;
            return @as(f64, @floatFromInt(sub.end_ns - t0)) / @as(f64, @floatFromInt(count));
        },
        .qos0_fanout100 => {
            const n_subs = 100;
            const count = 10_000;
            const subs = try gpa.alloc(Sub, n_subs);
            defer gpa.free(subs);
            var opened: usize = 0;
            defer for (subs[0..opened]) |*s| s.raw.close();
            for (subs, 0..) |*s, i| {
                var id_buf: [32]u8 = undefined;
                s.* = .{ .raw = try Raw.open(gpa, addr, try std.mem.print(&id_buf, "bench-fan-{d}", .{i})), .want = count };
                opened += 1;
                try s.raw.subscribe("bench/fan", .at_most_once);
            }
            var publisher = try Raw.open(gpa, addr, "bench-pub");
            defer publisher.close();
            const ths = try gpa.alloc(std.Thread, n_subs);
            defer gpa.free(ths);
            for (subs, ths) |*s, *t| t.* = try std.Thread.spawn(.{}, Sub.run, .{s});
            const t0 = nowNs();
            try publishMany(&publisher, "bench/fan", count, .at_most_once, 0);
            var end: i64 = 0;
            for (subs, ths) |*s, t| {
                t.join();
                if (s.err) |e| return e;
                if (s.got != count) return error.Lost;
                end = @max(end, s.end_ns);
            }
            return @as(f64, @floatFromInt(end - t0)) / @as(f64, @floatFromInt(count * n_subs));
        },
        .qos0_fanin32 => {
            const n_pubs = 32;
            const per = 5_000;
            var sub: Sub = .{ .raw = try Raw.open(gpa, addr, "bench-sub"), .want = n_pubs * per };
            defer sub.raw.close();
            try sub.raw.subscribe("bench/in/+", .at_most_once);
            const pubs = try gpa.alloc(Pub, n_pubs);
            defer gpa.free(pubs);
            var opened: usize = 0;
            defer for (pubs[0..opened]) |*p| p.raw.close();
            var topics: [n_pubs][16]u8 = undefined;
            for (pubs, 0..) |*p, i| {
                var id_buf: [32]u8 = undefined;
                p.* = .{ .raw = try Raw.open(gpa, addr, try std.mem.print(&id_buf, "bench-in-{d}", .{i})), .topic = try std.mem.print(&topics[i], "bench/in/{d}", .{i}), .count = per };
                opened += 1;
            }
            const sth = try std.Thread.spawn(.{}, Sub.run, .{&sub});
            const ths = try gpa.alloc(std.Thread, n_pubs);
            defer gpa.free(ths);
            const t0 = nowNs();
            for (pubs, ths) |*p, *t| t.* = try std.Thread.spawn(.{}, Pub.run, .{p});
            for (pubs, ths) |*p, t| {
                t.join();
                if (p.err) |e| return e;
            }
            sth.join();
            if (sub.err) |e| return e;
            if (sub.got != n_pubs * per) return error.Lost;
            return @as(f64, @floatFromInt(sub.end_ns - t0)) / @as(f64, @floatFromInt(n_pubs * per));
        },
        .rtt_1k => {
            const trips = 5_000;
            var raw = try Raw.open(gpa, addr, "bench-rtt");
            defer raw.close();
            try raw.subscribe("bench/rtt", .at_most_once);
            const payload: [1024]u8 = @splat('r');
            const t0 = nowNs();
            for (0..trips) |_| {
                try raw.queue(encPublish, .{ "bench/rtt", &payload, packet.QoS.at_most_once, @as(u16, 0) });
                try raw.flush();
                while ((try raw.next()) != .publish) {}
            }
            return @as(f64, @floatFromInt(nowNs() - t0)) / trips;
        },
        .connect => {
            const n = 500;
            const t0 = nowNs();
            for (0..n) |_| {
                var raw = try Raw.open(gpa, addr, "bench-conn");
                raw.close();
            }
            return @as(f64, @floatFromInt(nowNs() - t0)) / n;
        },
    }
}

// ── the two brokers ────────────────────────────────────────────────────────

fn ours(gpa: std.mem.Allocator, b: *mqtt.Broker, server: *mqtt.broker.TcpServer) !net.IpAddress {
    // Queues unbounded on both sides (Mosquitto: `max_queued_messages 0`):
    // MQTT has no end-to-end flow control, so a publisher outrunning a QoS 1/2
    // subscriber fills the broker's queue for it, and at the default caps
    // (1000 messages on both) each broker DROPS the rest — then the row
    // would compare drop policies, not throughput.
    b.* = .init(gpa, .{ .max_packet_size = 64 * 1024, .max_queued_messages = 1 << 30, .max_queued_bytes = 1 << 40 });
    server.* = .init(io_g, b);
    server.tcp_nodelay = true; // Mosquitto gets `set_tcp_nodelay true` too
    try server.bind("127.0.0.1", 0);
    _ = try std.Thread.spawn(.{}, serveThread, .{server});
    return server.boundAddress();
}

fn serveThread(s: *mqtt.broker.TcpServer) void {
    s.serve() catch {};
}

fn freePort() !u16 {
    const ip = try net.IpAddress.parse("127.0.0.1", 0);
    var l = try ip.listen(io_g, .{ .reuse_address = true });
    defer l.deinit(io_g);
    return l.socket.address.getPort();
}

fn removeContainer() void {
    const n = container_id_len.load(.acquire);
    if (n == 0) return;
    const r = std.process.run(std.heap.page_allocator, io_g, .{ .argv = &.{ "podman", "rm", "-f", "-t", "0", container_id_buf[0..n] } }) catch return;
    _ = r;
    container_id_len.store(0, .release);
}

fn startMosquitto(arena: std.mem.Allocator) !struct { addr: net.IpAddress, version: []const u8 } {
    const port = try freePort();
    // Self-limiting: the container ends itself after 30 minutes whatever
    // happens to this program.
    // A config file only for `set_tcp_nodelay` (ours sets it as well); the
    // listener and anonymous access are what `-p` alone would give.
    const cmd = try arena.print("cp /usr/sbin/mosquitto /tmp/mosquitto && printf 'listener {d} 127.0.0.1\nallow_anonymous true\nset_tcp_nodelay true\nmax_queued_messages 0\n' > /tmp/m.conf && exec timeout 1800 /tmp/mosquitto -c /tmp/m.conf", .{port});
    const r = try std.process.run(arena, io_g, .{ .argv = &.{ "podman", "run", "-d", "--rm", "--network", "host", image, "sh", "-c", cmd } });
    if (r.term != .exited or r.term.exited != 0) {
        std.debug.print("bench-mqtt: podman run failed (is {s} pulled?):\n{s}\n", .{ image, r.stderr });
        return error.MosquittoStart;
    }
    const id = std.mem.trim(u8, r.stdout, " \n");
    @memcpy(container_id_buf[0..id.len], id);
    container_id_len.store(id.len, .release);
    const addr = try net.IpAddress.parse("127.0.0.1", port);
    // Ready when it accepts a CONNECT.
    var tries: usize = 0;
    while (true) : (tries += 1) {
        if (Raw.open(arena, addr, "bench-probe")) |raw| {
            var rr = raw;
            rr.close();
            break;
        } else |_| {
            if (tries > 100) return error.MosquittoNotReady;
            try io_g.sleep(.fromMilliseconds(50), .awake);
        }
    }
    const h = try std.process.run(arena, io_g, .{ .argv = &.{ "podman", "exec", id, "/tmp/mosquitto", "-h" } });
    return .{ .addr = addr, .version = std.mem.sliceTo(h.stdout, '\n') };
}

fn watchdog() void {
    while (true) {
        io_g.sleep(.fromSeconds(1), .awake) catch {};
        if (nowNs() > deadline_ns.load(.acquire)) {
            std.debug.print("bench-mqtt: HANG — a row against {s} took over 120 s; removing the container and exiting\n", .{if (side.load(.acquire) == 1) "ours" else "mosquitto"});
            removeContainer();
            std.process.exit(2);
        }
    }
}

pub fn main(init: std.process.Init) !u8 {
    io_g = init.io;
    const arena = init.arena.allocator();
    const gpa = std.heap.smp_allocator;
    const args = try init.minimal.args.toSlice(arena);
    const filters = if (args.len > 1) args[1..] else &[_][:0]const u8{};
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 3;

    _ = try std.Thread.spawn(.{}, watchdog, .{});
    var broker: mqtt.Broker = undefined;
    var server: mqtt.broker.TcpServer = undefined;
    const ours_addr = try ours(gpa, &broker, &server);
    const mosq = try startMosquitto(arena);
    defer removeContainer();

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io_g, &buf);
    const w = &stdout.interface;
    try w.print("{s:<16} {s:>12} {s:>12} {s:>7} {s:>6} {s:>6}\n", .{ "workload", "ours ns", "mosq ns", "/ref", "spr us", "spr rf" });
    try w.flush();
    var worst: f64 = 0;
    var best_r: f64 = std.math.inf(f64);
    var max_spread: f64 = 0;
    inline for (@typeInfo(Row).@"enum".field_names, @typeInfo(Row).@"enum".field_values) |f_name, f_value| {
        const f = .{ .name = f_name };
        const row: Row = @fromBackingInt(@intCast(f_value));
        var hit = filters.len == 0;
        for (filters) |x| hit = hit or std.mem.find(u8, f.name, x) != null;
        if (hit) {
            var o_best: f64 = std.math.inf(f64);
            var o_worst: f64 = 0;
            var m_best: f64 = std.math.inf(f64);
            var m_worst: f64 = 0;
            for (0..rounds) |_| {
                side.store(0, .release);
                const m = measure(gpa, mosq.addr, row) catch |e| {
                    std.debug.print("bench-mqtt: {s} against mosquitto: {t}\n", .{ f.name, e });
                    return 1;
                };
                side.store(1, .release);
                const o = measure(gpa, ours_addr, row) catch |e| {
                    std.debug.print("bench-mqtt: {s} against ours: {t}\n", .{ f.name, e });
                    return 1;
                };
                o_best = @min(o_best, o);
                o_worst = @max(o_worst, o);
                m_best = @min(m_best, m);
                m_worst = @max(m_worst, m);
            }
            const ratio = o_best / m_best;
            worst = @max(worst, ratio);
            best_r = @min(best_r, ratio);
            const so = o_worst / o_best - 1;
            const sm = m_worst / m_best - 1;
            max_spread = @max(max_spread, @max(so, sm));
            try w.print("{s:<16} {d:>12.0} {d:>12.0} {d:>7.3} {d:>5.1}% {d:>5.1}%\n", .{ f.name, o_best, m_best, ratio, 100 * so, 100 * sm });
            try w.flush();
        }
    }
    try w.print("rounds: {d}; wall time; largest spread {d:.1}%{s}\nreference: {s}\nworst ours/mosquitto = {d:.3} (best {d:.3})\n", .{
        rounds, 100 * max_spread, if (max_spread > 0.05) " (OVER 5 %: noisy run, repeat)" else "", mosq.version, worst, best_r,
    });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× {s} · fastest ? (measured <today>)\n", .{ best_r, worst, mosq.version });
    try w.flush();
    server.shutdown();
    return 0;
}
