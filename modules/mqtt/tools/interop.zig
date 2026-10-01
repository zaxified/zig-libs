// SPDX-License-Identifier: MIT

//! LIVE third-party-peer interop for `mqtt`'s MQTT 5.0: this module's `Client`
//! against a real **Eclipse Mosquitto 2.x** broker, and real **paho-mqtt**
//! clients against this module's `Broker` — and the recorder that turns both
//! exchanges into `src/testdata/v5_transcript.txt`, which `src/v5_replay.zig`
//! replays with no mosquitto, no Python and no socket.
//!
//! ## Why this is a PROGRAM and not a test
//!
//! The peers are foreign: a container image and a Python package. A module is
//! standalone Zig (CONVENTIONS §9), so the TAKING of the anchor lives here and
//! its VALUE — the frozen bytes — runs in the module's own lane, everywhere.
//! What only this program can do: find a NEW divergence. The transcript proves
//! we still answer the recorded bytes the way the real peers accepted; it can
//! never prove a peer accepts bytes it has not seen. Run it after any
//! wire-visible change, and before a release.
//!
//! ## Usage
//!
//!     zig build interop-mqtt                 # run both directions, check them
//!     zig build interop-mqtt -- --capture    # ...and rewrite the transcript
//!
//! The peers (installed once, into the droppable `.zig-cache/mqtt-interop/`):
//!
//!     podman pull docker.io/library/eclipse-mosquitto:2
//!     python3 -m venv .zig-cache/mqtt-interop/venv
//!     .zig-cache/mqtt-interop/venv/bin/pip install paho-mqtt==2.1.0
//!
//! Mosquitto runs rootless in podman on an ephemeral loopback port; the paho
//! scenario is `tools/paho_v5.py`, read from its own path at run time. Both
//! are black-box peers — EPL-2.0 OR EDL-1.0, neither source read nor copied
//! (root NOTICE §0).
//!
//! ## What is recorded
//!
//! - `case client`: every byte our `Client` wrote to mosquitto and read back,
//!   per connection. The replay decodes every packet both ways, re-encodes
//!   ours and requires the very bytes mosquitto accepted.
//! - `case broker`: every chunk a paho client sent, with the broker's clock
//!   and the order across connections, and everything the broker wrote to
//!   each. The broker processes one connection's chunk at a time here (a
//!   process lock spans log, feed and process), so the replay — the same
//!   chunks, in the same order, at the same `now` — must reproduce every
//!   connection's output byte for byte.

const std = @import("std");
const mqtt = @import("mqtt");
const packet = mqtt.packet;
const net = std.Io.net;

const transcript_path = "modules/mqtt/src/testdata/v5_transcript.txt";
const python = ".zig-cache/mqtt-interop/venv/bin/python";
const paho_script = "modules/mqtt/tools/paho_v5.py";
const image = "docker.io/library/eclipse-mosquitto:2";

var t0_ns: i96 = 0;

fn nowMs(io: std.Io) i64 {
    const ns = std.Io.Timestamp.now(io, .real).nanoseconds - t0_ns;
    return @intCast(@divFloor(ns, std.time.ns_per_ms));
}

fn fail(comptime fmt: []const u8, args: anytype) error{Mismatch} {
    std.debug.print("FAIL: " ++ fmt ++ "\n", args);
    return error.Mismatch;
}

fn want(ok: bool, comptime what: []const u8) error{Mismatch}!void {
    if (!ok) return fail("{s}", .{what});
}

fn appendHex(gpa: std.mem.Allocator, out: *std.ArrayList(u8), bytes: []const u8) !void {
    const digits = "0123456789abcdef";
    for (bytes) |b| try out.appendSlice(gpa, &.{ digits[b >> 4], digits[b & 15] });
}

fn watchdog(io: std.Io) void {
    io.sleep(.fromSeconds(120), .awake) catch return;
    std.debug.print("FAIL: interop-mqtt took over 120 s — a peer stopped answering\n", .{});
    std.process.exit(3);
}

pub fn main(init: std.process.Init.Minimal) !u8 {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer _ = da.deinit();
    const gpa = da.allocator();
    // The environment goes to the children: podman finds its network helper
    // (pasta) through PATH, and an empty environment has none.
    var threaded: std.Io.Threaded = .init(gpa, .{ .environ = init.environ });
    defer threaded.deinit();
    const io = threaded.io();
    t0_ns = std.Io.Timestamp.now(io, .real).nanoseconds;

    var capture = false;
    var args = init.args.iterate();
    _ = args.skip();
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--capture")) capture = true else {
            std.debug.print("usage: interop-mqtt [--capture]\n", .{});
            return 2;
        }
    }
    var dog = try io.concurrent(watchdog, .{io});
    defer dog.cancel(io);

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try out.appendSlice(gpa, "# MQTT 5.0 interop transcript, written by `zig build interop-mqtt -- --capture`\n" ++
        "# (modules/mqtt/tools/interop.zig); replayed by src/v5_replay.zig. Do not edit.\n");

    clientVsMosquitto(gpa, io, &out) catch |e| {
        std.debug.print("client vs mosquitto: {s}\n", .{@errorName(e)});
        return 1;
    };
    pahoVsBroker(gpa, io, &out) catch |e| {
        std.debug.print("paho vs broker: {s}\n", .{@errorName(e)});
        return 1;
    };
    if (capture) {
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = transcript_path, .data = out.items });
        std.debug.print("interop-mqtt: transcript written to {s}\n", .{transcript_path});
    }
    std.debug.print("interop-mqtt: both directions agree with the real peers\n", .{});
    return 0;
}

// ── our Client against a real mosquitto ────────────────────────────────────

fn run(gpa: std.mem.Allocator, io: std.Io, argv: []const []const u8) ![]u8 {
    const r = try std.process.run(gpa, io, .{ .argv = argv });
    defer gpa.free(r.stderr);
    switch (r.term) {
        .exited => |code| if (code == 0) return r.stdout,
        else => {},
    }
    std.debug.print("`{s}` failed: {s}\n", .{ argv[0], r.stderr });
    gpa.free(r.stdout);
    return error.PeerCommandFailed;
}

const Mosquitto = struct {
    id: []u8,
    port: u16,
    version: []u8,

    fn start(gpa: std.mem.Allocator, io: std.Io) !Mosquitto {
        // Host networking and mosquitto's no-config mode — loopback only,
        // anonymous allowed — on a port free a moment ago.
        //
        // ⛔ The binary runs from a COPY. A host whose AppArmor ships a
        // `mosquitto` profile attaches it by path to `/usr/sbin/mosquitto` —
        // inside the container too. Confined that way it could open no `-c`
        // file but the host's `/etc/mosquitto/...`, and it accepts no signal
        // from anyone (no `signal (receive)` rule): `podman kill`/`rm -f`
        // fail, and every container left behind is unkillable without root.
        const port = try freePort(io);
        var port_buf: [8]u8 = undefined;
        const port_str = try std.fmt.bufPrint(&port_buf, "{d}", .{port});
        const cmd = try std.fmt.allocPrint(gpa, "cp /usr/sbin/mosquitto /tmp/mosquitto && exec /tmp/mosquitto -p {s}", .{port_str});
        defer gpa.free(cmd);
        const raw_id = try run(gpa, io, &.{ "podman", "run", "-d", "--rm", "--network", "host", image, "sh", "-c", cmd });
        defer gpa.free(raw_id);
        const id = try gpa.dupe(u8, std.mem.trim(u8, raw_id, " \n"));
        errdefer {
            kill(gpa, io, id);
            gpa.free(id);
        }
        const help = run(gpa, io, &.{ "podman", "exec", id, "/tmp/mosquitto", "-h" }) catch try gpa.dupe(u8, "mosquitto version ?\n");
        defer gpa.free(help);
        const first = std.mem.sliceTo(help, '\n');
        const version = try gpa.dupe(u8, first);
        errdefer gpa.free(version);
        const m = Mosquitto{ .id = id, .port = port, .version = version };
        try m.waitReady(io);
        return m;
    }

    fn freePort(io: std.Io) !u16 {
        const ip = try net.IpAddress.parse("127.0.0.1", 0);
        var l = try ip.listen(io, .{ .reuse_address = true });
        defer l.deinit(io);
        return l.socket.address.getPort();
    }

    /// A 3.1.1 CONNECT answered by a CONNACK, retried: the port forwarder
    /// accepts before mosquitto listens. Not recorded.
    fn waitReady(m: Mosquitto, io: std.Io) !void {
        var buf: [64]u8 = undefined;
        const hello = try packet.encodeConnect(&buf, .{ .client_id = "ready" });
        for (0..100) |_| {
            if (tryHello(io, m.port, hello)) return;
            try io.sleep(.fromMilliseconds(100), .awake);
        }
        return error.MosquittoNotReady;
    }

    fn tryHello(io: std.Io, port: u16, hello: []const u8) bool {
        const addr = net.IpAddress.parse("127.0.0.1", port) catch return false;
        const stream = addr.connect(io, .{ .mode = .stream }) catch return false;
        defer stream.close(io);
        var wbuf: [64]u8 = undefined;
        var w = stream.writer(io, &wbuf);
        w.interface.writeAll(hello) catch return false;
        w.interface.flush() catch return false;
        var rbuf: [8]u8 = undefined;
        var r = stream.reader(io, &rbuf);
        const ack = r.interface.takeArray(4) catch return false;
        return ack[0] == 0x20;
    }

    fn stop(m: *Mosquitto, gpa: std.mem.Allocator, io: std.Io) void {
        kill(gpa, io, m.id);
        gpa.free(m.id);
        gpa.free(m.version);
    }

    /// Removed outright: mosquitto ignores SIGTERM for a while, and `--rm`
    /// would leave the removal to conmon, which `hw run` reaps with the job.
    fn kill(gpa: std.mem.Allocator, io: std.Io, id: []const u8) void {
        const r = std.process.run(gpa, io, .{ .argv = &.{ "podman", "rm", "-f", "-t", "0", id } }) catch return;
        gpa.free(r.stdout);
        gpa.free(r.stderr);
    }
};

/// One recorded connection of our `Client` to mosquitto.
const Link = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    tcp: mqtt.TcpTransport,
    c2s: std.ArrayList(u8) = .empty,
    s2c: std.ArrayList(u8) = .empty,
    rx: [8192]u8 = undefined,
    tx: [8192]u8 = undefined,
    read_buf: [4096]u8 = undefined,
    slots: [4]mqtt.AliasSlot = .{ .{}, .{}, .{}, .{} },
    client: mqtt.Client = undefined,

    fn open(l: *Link, gpa: std.mem.Allocator, io: std.Io, port: u16) !void {
        const addr = try net.IpAddress.parse("127.0.0.1", port);
        l.* = .{ .io = io, .gpa = gpa, .tcp = try mqtt.TcpTransport.connect(io, addr) };
        l.client = mqtt.Client.init(.{ .ctx = l, .writeFn = writeFn }, .{ .rx = &l.rx, .tx = &l.tx, .topic_aliases = &l.slots });
    }

    fn close(l: *Link) void {
        l.tcp.close();
        l.c2s.deinit(l.gpa);
        l.s2c.deinit(l.gpa);
    }

    fn writeFn(ctx: *anyopaque, bytes: []const u8) mqtt.TransportError!void {
        const l: *Link = @ptrCast(@alignCast(ctx));
        l.c2s.appendSlice(l.gpa, bytes) catch return error.TransportFailed;
        return l.tcp.transport().write(bytes);
    }

    /// The next event; reads from the socket as needed. `error.Closed` when
    /// the broker ended the connection.
    fn next(l: *Link) !mqtt.Event {
        while (true) {
            if (try l.client.poll(@intCast(nowMs(l.io)))) |ev| return ev;
            const n = try l.tcp.readSome(l.read_buf[0..@min(l.read_buf.len, l.client.rxRoom())]);
            if (n == 0) return error.Closed;
            try l.s2c.appendSlice(l.gpa, l.read_buf[0..n]);
            try l.client.feed(l.read_buf[0..n]);
        }
    }

    fn now(l: *Link) u64 {
        return @intCast(nowMs(l.io));
    }

    /// PINGREQ, then take events until its PINGRESP: whatever the broker
    /// sent before is consumed.
    fn drainToPong(l: *Link) !void {
        try l.client.pingreq(l.now());
        while (try l.next() != .pingresp) {}
    }

    fn record(l: *Link, out: *std.ArrayList(u8), conn: usize) !void {
        try out.print(l.gpa, "conn {d} c2s ", .{conn});
        try appendHex(l.gpa, out, l.c2s.items);
        try out.print(l.gpa, "\nconn {d} s2c ", .{conn});
        try appendHex(l.gpa, out, l.s2c.items);
        try out.append(l.gpa, '\n');
    }
};

fn userProps(p: packet.Properties, gpa: std.mem.Allocator) ![]u8 {
    var s: std.ArrayList(u8) = .empty;
    var it = p.user_properties.iterator();
    while (it.next()) |u| try s.print(gpa, "{s}={s};", .{ u.name, u.value });
    return s.toOwnedSlice(gpa);
}

fn expectMessageProps(gpa: std.mem.Allocator, m: mqtt.Message, topic: []const u8) !void {
    if (!std.mem.eql(u8, m.topic, topic)) return fail("echo topic {s}, wanted {s}", .{ m.topic, topic });
    const p = m.properties;
    const ups = try userProps(p, gpa);
    defer gpa.free(ups);
    try want(std.mem.eql(u8, ups, "a=1;b=2;"), "user properties forwarded unaltered, in order");
    try want(std.mem.eql(u8, p.response_topic orelse "", "zl5/reply"), "response topic forwarded");
    try want(std.mem.eql(u8, p.correlation_data orelse "", "\x00\x2a"), "correlation data forwarded");
    try want(std.mem.eql(u8, p.content_type orelse "", "text/plain"), "content type forwarded");
    try want(p.payload_format == .utf8, "payload format forwarded");
    try want(if (p.message_expiry_interval) |e| e <= 300 and e >= 299 else false, "message expiry counted down from 300");
    try want(p.subscription_ids.first() == 7 and p.subscription_ids.count() == 1, "subscription identifier 7");
}

fn clientVsMosquitto(gpa: std.mem.Allocator, io: std.Io, out: *std.ArrayList(u8)) !void {
    var mq = try Mosquitto.start(gpa, io);
    defer mq.stop(gpa, io);
    std.debug.print("interop-mqtt: our Client vs {s} on port {d}\n", .{ mq.version, mq.port });
    try out.print(gpa, "peer {s}\ncase client\n", .{mq.version});

    const fwd = packet.Properties{
        .user_properties = .{ .items = &.{ .{ .name = "a", .value = "1" }, .{ .name = "b", .value = "2" } } },
        .response_topic = "zl5/reply",
        .correlation_data = "\x00\x2a",
        .content_type = "text/plain",
        .payload_format = .utf8,
        .message_expiry_interval = 300,
    };

    var l0: Link = undefined;
    try l0.open(gpa, io, mq.port);
    defer l0.close();
    // 1. CONNECT with properties.
    try l0.client.connect(l0.now(), .{
        .client_id = "zl5",
        .keep_alive_s = 30,
        .version = .v5,
        .properties = .{ .session_expiry_interval = 120, .user_properties = .{ .items = &.{.{ .name = "who", .value = "zig" }} } },
    });
    const ca = (try l0.next()).connack;
    try want(ca.reason_code == .success, "mosquitto accepts our 5.0 CONNECT");
    const limits = l0.client.serverLimits();
    std.debug.print("  CONNACK: topic alias max {d}, receive max {d}, max packet {d}\n", .{ limits.topic_alias_maximum, limits.receive_maximum, limits.maximum_packet_size });

    // 2. SUBSCRIBE with a Subscription Identifier.
    _ = try l0.client.subscribeWith(l0.now(), &.{.{ .filter = "zl5/#", .qos = .exactly_once }}, .{ .subscription_ids = .{ .items = &.{7} } });
    const sa = (try l0.next()).suback;
    try want(std.mem.eql(u8, sa.codes, &.{2}), "SUBACK grants QoS 2");

    // 3. QoS 0/1/2 with every forwardable property, each echoed back.
    inline for (.{ packet.QoS.at_most_once, packet.QoS.at_least_once, packet.QoS.exactly_once }, 0..) |q, i| {
        const topic = std.fmt.comptimePrint("zl5/q{d}", .{i});
        _ = try l0.client.publish(l0.now(), topic, "m", .{ .qos = q, .properties = fwd });
        var echoed = false;
        var acked = q == .at_most_once;
        while (!(echoed and acked)) switch (try l0.next()) {
            .message => |m| {
                try expectMessageProps(gpa, m, topic);
                try want(m.qos == q, "echo at the published QoS");
                echoed = true;
            },
            .puback => |a| {
                try want(a.reason_code == .success, "PUBACK success");
                acked = true;
            },
            .pubcomp => |a| {
                try want(a.reason_code == .success, "PUBCOMP success");
                acked = true;
            },
            else => return fail("unexpected event after a publish", .{}),
        };
    }

    // 4. No Local: our own publish does not come back; a PINGRESP fences it.
    _ = try l0.client.subscribe(l0.now(), &.{.{ .filter = "zl5nl", .no_local = true }});
    _ = (try l0.next()).suback;
    _ = try l0.client.publish(l0.now(), "zl5nl", "local", .{});
    try l0.client.pingreq(l0.now());
    try want((try l0.next()) == .pingresp, "No Local: nothing before the PINGRESP");

    // 5. Outbound Topic Alias, set then used alone; mosquitto may alias its
    //    deliveries to us in turn (we announced 4 slots).
    try want(limits.topic_alias_maximum >= 1, "mosquitto takes topic aliases");
    _ = try l0.client.publish(l0.now(), "zl5/alias", "first", .{ .properties = .{ .topic_alias = 1 } });
    _ = try l0.client.publish(l0.now(), "", "second", .{ .properties = .{ .topic_alias = 1 } });
    for ([_][]const u8{ "first", "second" }) |want_payload| {
        const m = (try l0.next()).message;
        if (!std.mem.eql(u8, m.topic, "zl5/alias") or !std.mem.eql(u8, m.payload, want_payload)) {
            return fail("alias echo {s} {s}", .{ m.topic, m.payload });
        }
    }

    // 6. A retained message with a Message Expiry, then a subscriber that
    //    gets it with RETAIN set.
    _ = try l0.client.publish(l0.now(), "zl5/ret", "kept", .{ .qos = .at_least_once, .retain = true, .properties = .{ .message_expiry_interval = 60 } });
    var got_ack = false;
    var got_echo = false;
    while (!(got_ack and got_echo)) switch (try l0.next()) {
        .puback => got_ack = true,
        .message => |m| {
            try want(!m.retain, "a live delivery has RETAIN 0 without Retain As Published");
            got_echo = true;
        },
        else => return fail("unexpected event after a retained publish", .{}),
    };
    _ = try l0.client.subscribe(l0.now(), &.{.{ .filter = "zl5r/+", .qos = .at_least_once }});
    _ = (try l0.next()).suback;
    _ = try l0.client.publish(l0.now(), "zl5r/x", "r", .{ .retain = true });
    _ = (try l0.next()).message; // its live copy
    _ = try l0.client.subscribe(l0.now(), &.{.{ .filter = "zl5r/x" }});
    _ = (try l0.next()).suback;
    const rm = (try l0.next()).message;
    try want(rm.retain and std.mem.eql(u8, rm.payload, "r"), "retained message at subscribe, RETAIN 1");
    _ = try l0.client.publish(l0.now(), "zl5r/x", "", .{ .retain = true }); // clear it
    try l0.drainToPong(); // one copy or one per overlapping subscription: mosquitto's choice

    // 7. UNSUBACK reason codes per filter.
    _ = try l0.client.unsubscribe(l0.now(), &.{ "zl5nl", "never" });
    try want(std.mem.eql(u8, (try l0.next()).unsuback.codes, &.{ 0x00, 0x11 }), "UNSUBACK Success, No subscription existed");

    // 8. Take-over: the first connection is told 0x8E. Then the second, with
    //    a Will carrying properties, ends without DISCONNECT.
    var l1: Link = undefined;
    try l1.open(gpa, io, mq.port);
    defer l1.close();
    try l1.client.connect(l1.now(), .{ .client_id = "zl5w", .version = .v5 });
    _ = (try l1.next()).connack;
    var l2: Link = undefined;
    try l2.open(gpa, io, mq.port);
    defer l2.close();
    try l2.client.connect(l2.now(), .{ .client_id = "zl5w", .version = .v5, .will = .{
        .topic = "zl5/will",
        .message = "gone",
        .properties = .{ .content_type = "text/plain", .user_properties = .{ .items = &.{.{ .name = "why", .value = "lost" }} } },
    } });
    _ = (try l2.next()).connack;
    const told = (try l1.next()).disconnect;
    try want(told.reason_code == .session_taken_over, "the superseded connection gets 0x8E");
    l2.tcp.stream.shutdown(io, .both) catch {};
    const will = (try l0.next()).message;
    try want(std.mem.eql(u8, will.topic, "zl5/will") and std.mem.eql(u8, will.payload, "gone"), "the Will is published");
    const wups = try userProps(will.properties, gpa);
    defer gpa.free(wups);
    try want(std.mem.eql(u8, wups, "why=lost;") and std.mem.eql(u8, will.properties.content_type orelse "", "text/plain"), "Will properties forwarded");

    try l0.client.disconnectWith(l0.now(), .{});
    try l0.record(out, 0);
    try l1.record(out, 1);
    try l2.record(out, 2);
}

// ── real paho clients against our Broker ───────────────────────────────────

const Recorder = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    broker: *mqtt.Broker,
    /// Spans log + feed + process (and remove), so the recorded order is the
    /// order the broker processed in — what makes the replay deterministic.
    lock: std.Io.Mutex = .init,
    log: std.ArrayList(u8) = .empty,
    outs: std.ArrayList(std.ArrayList(u8)) = .empty,
    next_conn: usize = 0,
    group: std.Io.Group = .init,

    fn deinit(r: *Recorder) void {
        for (r.outs.items) |*o| o.deinit(r.gpa);
        r.outs.deinit(r.gpa);
        r.log.deinit(r.gpa);
    }

    fn serve(r: *Recorder, listener: *net.Server) void {
        while (true) {
            const stream = listener.accept(r.io) catch return;
            r.lock.lockUncancelable(r.io);
            const id = r.next_conn;
            r.next_conn += 1;
            r.outs.append(r.gpa, .empty) catch {
                r.lock.unlock(r.io);
                stream.close(r.io);
                continue;
            };
            r.lock.unlock(r.io);
            r.group.concurrent(r.io, connMain, .{ r, stream, id }) catch stream.close(r.io);
        }
    }

    const Wire = struct {
        r: *Recorder,
        stream: net.Stream,
        id: usize,

        fn writeFn(ctx: *anyopaque, bytes: []const u8) mqtt.BrokerTransportError!void {
            const w: *Wire = @ptrCast(@alignCast(ctx));
            // Called with the recorder's lock held (every write happens inside
            // some connection's process or remove).
            w.r.outs.items[w.id].appendSlice(w.r.gpa, bytes) catch return error.TransportFailed;
            var wbuf: [512]u8 = undefined;
            var sw = w.stream.writer(w.r.io, &wbuf);
            sw.interface.writeAll(bytes) catch return error.TransportFailed;
            sw.interface.flush() catch return error.TransportFailed;
        }

        fn closeFn(ctx: *anyopaque) void {
            const w: *Wire = @ptrCast(@alignCast(ctx));
            w.stream.shutdown(w.r.io, .both) catch {};
        }
    };

    fn connMain(r: *Recorder, stream: net.Stream, id: usize) void {
        defer stream.close(r.io);
        var wire = Wire{ .r = r, .stream = stream, .id = id };
        const conn = r.broker.accept(.{ .ctx = &wire, .writeFn = Wire.writeFn, .closeFn = Wire.closeFn }) catch return;
        var buf: [4096]u8 = undefined;
        while (true) {
            var sr = stream.reader(r.io, &buf);
            sr.interface.fillMore() catch break;
            const bytes = buf[0..sr.interface.bufferedLen()];
            r.lock.lockUncancelable(r.io);
            const now = nowMs(r.io);
            r.log.print(r.gpa, "at {d} conn {d} c2s ", .{ now, id }) catch {};
            appendHex(r.gpa, &r.log, bytes) catch {};
            r.log.append(r.gpa, '\n') catch {};
            const disp: mqtt.broker.Disposition = blk: {
                r.broker.feed(conn, bytes) catch break :blk .close;
                break :blk r.broker.process(conn, now) catch .close;
            };
            r.lock.unlock(r.io);
            if (disp == .close) break;
        }
        r.lock.lockUncancelable(r.io);
        r.log.print(r.gpa, "at {d} conn {d} close\n", .{ nowMs(r.io), id }) catch {};
        r.broker.remove(conn);
        r.lock.unlock(r.io);
    }
};

fn pahoVsBroker(gpa: std.mem.Allocator, io: std.Io, out: *std.ArrayList(u8)) !void {
    var broker = mqtt.Broker.init(gpa, .{});
    defer broker.deinit();
    var rec = Recorder{ .gpa = gpa, .io = io, .broker = &broker };
    defer rec.deinit();
    const ip = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = try ip.listen(io, .{ .reuse_address = true });
    const port = listener.socket.address.getPort();
    var serving = try io.concurrent(Recorder.serve, .{ &rec, &listener });

    var port_buf: [8]u8 = undefined;
    const port_str = try std.fmt.bufPrint(&port_buf, "{d}", .{port});
    std.debug.print("interop-mqtt: paho-mqtt vs our Broker on port {d}\n", .{port});
    const r = try std.process.run(gpa, io, .{ .argv = &.{ python, paho_script, "127.0.0.1", port_str } });
    defer gpa.free(r.stdout);
    defer gpa.free(r.stderr);

    // Stop accepting; let the connection tasks finish.
    listener.deinit(io);
    serving.cancel(io);
    rec.group.cancel(io);

    const ok = switch (r.term) {
        .exited => |code| code == 0,
        else => false,
    };
    if (!ok) {
        std.debug.print("paho scenario failed:\n{s}\n{s}\n", .{ r.stdout, r.stderr });
        return error.PahoFailed;
    }
    checkPaho(gpa, r.stdout) catch |e| {
        std.debug.print("paho reported:\n{s}\n", .{r.stdout});
        return e;
    };

    // Exactly one connection — the superseded one — ended on DISCONNECT 0x8E.
    var told: usize = 0;
    for (rec.outs.items) |o| {
        if (std.mem.endsWith(u8, o.items, &.{ 0xE0, 0x01, 0x8E })) told += 1;
    }
    try want(told == 1, "the superseded paho connection got DISCONNECT 0x8E on the wire");

    try out.appendSlice(gpa, "peer paho-mqtt 2.1.0\ncase broker\n");
    try out.appendSlice(gpa, rec.log.items);
    for (rec.outs.items, 0..) |o, i| {
        try out.print(gpa, "out {d} ", .{i});
        try appendHex(gpa, out, o.items);
        try out.append(gpa, '\n');
    }
}

/// What paho observed, step by step (`tools/paho_v5.py`).
fn checkPaho(gpa: std.mem.Allocator, stdout: []const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var steps = std.StringHashMap(std.json.Value).init(arena);
    var lines = std.mem.tokenizeScalar(u8, stdout, '\n');
    while (lines.next()) |line| {
        const v = try std.json.parseFromSliceLeaky(std.json.Value, arena, line, .{});
        try steps.put(v.object.get("step").?.string, v);
    }
    const S = struct {
        steps: *std.StringHashMap(std.json.Value),
        fn get(s: @This(), name: []const u8) !std.json.ObjectMap {
            const v = s.steps.get(name) orelse return fail("paho never reported step {s}", .{name});
            return v.object;
        }
    };
    const s = S{ .steps = &steps };
    const int = struct {
        fn of(o: std.json.ObjectMap, k: []const u8) i64 {
            const v = o.get(k) orelse return -1;
            return if (v == .integer) v.integer else -1;
        }
        fn str(o: std.json.ObjectMap, k: []const u8) []const u8 {
            const v = o.get(k) orelse return "";
            return if (v == .string) v.string else "";
        }
        fn flag(o: std.json.ObjectMap, k: []const u8) bool {
            const v = o.get(k) orelse return false;
            return v == .bool and v.bool;
        }
        fn list(o: std.json.ObjectMap, k: []const u8) []const std.json.Value {
            const v = o.get(k) orelse return &.{};
            return if (v == .array) v.array.items else &.{};
        }
    };

    const ca = try s.get("connack");
    try want(int.of(ca, "reason") == 0 and !int.flag(ca, "present"), "paho: CONNACK success, no session");
    const cp = ca.get("props").?.object;
    try want(int.of(cp, "ReceiveMaximum") == mqtt.max_in_flight, "paho: Receive Maximum 64");
    try want(int.of(cp, "MaximumPacketSize") == 8192, "paho: Maximum Packet Size 8192");
    try want(int.of(cp, "TopicAliasMaximum") == 16, "paho: Topic Alias Maximum 16");
    try want(std.mem.startsWith(u8, int.str(cp, "AssignedClientIdentifier"), "auto-"), "paho: an assigned client id");

    try want(int.list(try s.get("suback"), "codes").len == 1 and int.list(try s.get("suback"), "codes")[0].integer == 2, "paho: SUBACK QoS 2");
    try want(int.of(try s.get("ack-q1"), "reason") == 0, "paho: PUBACK success");
    try want(int.of(try s.get("ack-q2"), "reason") == 0, "paho: QoS 2 completes");
    for ([_][]const u8{ "echo-q0", "echo-q1", "echo-q2" }, 0..) |name, q| {
        const e = try s.get(name);
        try want(int.of(e, "qos") == @as(i64, @intCast(q)), "paho: echo at the published QoS");
        const p = e.get("props").?.object;
        const ups = int.list(p, "UserProperty");
        try want(ups.len == 2 and std.mem.eql(u8, ups[0].array.items[0].string, "a") and std.mem.eql(u8, ups[1].array.items[0].string, "b"), "paho: user properties forwarded in order");
        try want(std.mem.eql(u8, int.str(p, "ResponseTopic"), "zp/reply"), "paho: response topic forwarded");
        try want(std.mem.eql(u8, int.str(p, "CorrelationData"), "002a"), "paho: correlation data forwarded");
        try want(std.mem.eql(u8, int.str(p, "ContentType"), "text/plain"), "paho: content type forwarded");
        try want(int.of(p, "PayloadFormatIndicator") == 1, "paho: payload format forwarded");
        try want(int.of(p, "MessageExpiryInterval") == 120, "paho: message expiry forwarded");
        const sids = int.list(p, "SubscriptionIdentifier");
        try want(sids.len == 1 and sids[0].integer == 5, "paho: subscription identifier 5");
        try want(p.get("TopicAlias") == null, "paho: no topic alias forwarded");
    }
    try want(int.of(try s.get("nosub"), "reason") == 0x10, "paho: PUBACK 0x10 without subscribers");
    const al = int.list(try s.get("alias"), "topics");
    try want(al.len == 2 and std.mem.eql(u8, al[0].string, "zp/alias") and std.mem.eql(u8, al[1].string, "zp/alias"), "paho: topic alias resolved");
    const sh = try s.get("shared");
    try want(int.list(sh, "p2").len == 2 and int.list(sh, "p3").len == 2 and int.flag(sh, "extra2") and int.flag(sh, "extra3"), "paho: shared subscription splits 2 + 2");
    const nl = try s.get("nolocal");
    try want(std.mem.eql(u8, int.str(nl, "p2"), "local") and int.flag(nl, "p1_quiet"), "paho: No Local");
    const rt = try s.get("retain");
    try want(int.flag(rt, "retained") and std.mem.eql(u8, int.str(rt, "payload"), "kept") and int.flag(rt, "rh2_quiet"), "paho: retained at subscribe, Retain Handling 2 quiet");
    try want(int.flag(try s.get("rap"), "retain"), "paho: Retain As Published keeps RETAIN");
    const wl = try s.get("will");
    const wp = wl.get("props").?.object;
    try want(std.mem.eql(u8, int.str(wl, "payload"), "gone") and std.mem.eql(u8, int.str(wp, "ContentType"), "text/plain") and int.list(wp, "UserProperty").len == 1, "paho: Will with properties");
    const rs = try s.get("resume");
    const q = int.list(rs, "queued");
    try want(int.flag(rs, "present") and q.len == 2 and std.mem.eql(u8, q[0].string, "q1") and std.mem.eql(u8, q[1].string, "q2"), "paho: session resumed with its queue");
    // paho 2.1.0 reports 0 for a server's DISCONNECT 0x8E (measured against
    // mosquitto too, whose 0x8E our own Client sees); the take-over is checked
    // on the wire instead, in `pahoVsBroker`.
    _ = try s.get("takeover");
    const ua = int.list(try s.get("unsuback"), "codes");
    try want(ua.len == 2 and ua[0].integer == 0 and ua[1].integer == 0x11, "paho: UNSUBACK codes");
    _ = try s.get("done");
}
