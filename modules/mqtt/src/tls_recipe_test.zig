// SPDX-License-Identifier: MIT

//! Recipe, tested: a TLS listener for `TcpServer` (Mosquitto's `listener 8883`
//! with a `certfile` / `keyfile`) with this collection's `tlsserver`.
//!
//! `TcpServer.secure` is the seam: `Secure.openFn` runs the handshake on the
//! connection's own task and returns a `SecureStream` whose `readFn` /
//! `writeFn` carry plaintext. The module has no dependency on a TLS engine (it
//! builds for 32-bit targets, `tlsserver` does not); the glue below is all
//! there is to it. The client is `tlsclient` (std's TLS client with RFC 5280
//! chain checks), over the same recipe `tools/interop.zig` runs against
//! Mosquitto.
//!
//! Test-only dependencies (`test_deps`): `tlsserver`, `tlsclient`.

const std = @import("std");
const testing = std.testing;
const net = std.Io.net;
const mqtt = @import("root.zig");
const testkit = @import("testkit");
const tlsserver = @import("tlsserver");
const tlsclient = @import("tlsclient");

/// What `Secure.ctx` points at: one TLS configuration for every connection.
const TlsListener = struct {
    gpa: std.mem.Allocator,
    /// Its `random` is replaced per connection by a CSPRNG seeded from the OS.
    config: *const tlsserver.Config,
    out_len: usize,

    fn secure(l: *TlsListener) mqtt.broker.Secure {
        return .{ .ctx = l, .openFn = open };
    }

    fn open(ctx: *anyopaque, io: std.Io, stream: net.Stream) mqtt.BrokerTransportError!mqtt.broker.SecureStream {
        const l: *TlsListener = @ptrCast(@alignCast(ctx));
        const s = Session.create(l, io, stream) catch return error.TransportFailed;
        s.conn.handshake() catch {
            s.destroy();
            return error.TransportFailed;
        };
        return .{ .ctx = s, .readFn = Session.readFn, .writeFn = Session.writeFn, .closeFn = Session.closeFn };
    }
};

/// One connection's TLS state, on the heap: the connection must not move.
const Session = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    cfg: tlsserver.Config,
    csprng: std.Random.DefaultCsprng,
    in_buf: []u8,
    out_buf: []u8,
    joiner: []u8,
    sr: net.Stream.Reader,
    sw: net.Stream.Writer,
    conn: tlsserver.Connection,
    /// Parks the reader's and the writers' sends against each other
    /// (`Connection.Guard`): the broker's fan-out writes from another
    /// thread while this connection's task reads.
    mutex: std.Io.Mutex = .init,
    /// What `read` returned beyond the caller's buffer.
    pending: []const u8 = &.{},

    fn create(l: *TlsListener, io: std.Io, stream: net.Stream) !*Session {
        const gpa = l.gpa;
        const s = try gpa.create(Session);
        errdefer gpa.destroy(s);
        var seed: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
        try io.randomSecure(&seed);
        defer std.crypto.secureZero(u8, &seed);
        const in_buf = try gpa.alloc(u8, tlsserver.record.max_record_len);
        errdefer gpa.free(in_buf);
        const out_buf = try gpa.alloc(u8, l.out_len);
        errdefer gpa.free(out_buf);
        const joiner = try gpa.alloc(u8, tlsserver.inbound.Joiner.bufferLen(tlsserver.inbound.default_max_message));
        errdefer gpa.free(joiner);
        s.* = .{
            .gpa = gpa,
            .io = io,
            .cfg = l.config.*,
            .csprng = std.Random.DefaultCsprng.init(seed),
            .in_buf = in_buf,
            .out_buf = out_buf,
            .joiner = joiner,
            .sr = stream.reader(io, in_buf),
            .sw = stream.writer(io, out_buf),
            .conn = undefined,
        };
        s.cfg.random = s.csprng.random();
        s.conn = tlsserver.Connection.init(&s.cfg, &s.sr.interface, &s.sw.interface, joiner);
        s.conn.guard = .{ .ctx = s, .lock = lock, .unlock = unlock };
        return s;
    }

    fn destroy(s: *Session) void {
        s.conn.deinit();
        std.crypto.secureZero(u8, s.joiner);
        const gpa = s.gpa;
        gpa.free(s.joiner);
        gpa.free(s.in_buf);
        gpa.free(s.out_buf);
        gpa.destroy(s);
    }

    fn lock(ctx: *anyopaque) void {
        const s: *Session = @ptrCast(@alignCast(ctx));
        s.mutex.lockUncancelable(s.io);
    }

    fn unlock(ctx: *anyopaque) void {
        const s: *Session = @ptrCast(@alignCast(ctx));
        s.mutex.unlock(s.io);
    }

    fn readFn(ctx: *anyopaque, buf: []u8) mqtt.BrokerTransportError!usize {
        const s: *Session = @ptrCast(@alignCast(ctx));
        if (s.pending.len == 0) {
            s.pending = (s.conn.read() catch return error.TransportFailed) orelse return 0;
        }
        const n = @min(buf.len, s.pending.len);
        @memcpy(buf[0..n], s.pending[0..n]);
        s.pending = s.pending[n..];
        return n;
    }

    fn writeFn(ctx: *anyopaque, bytes: []const u8) mqtt.BrokerTransportError!void {
        const s: *Session = @ptrCast(@alignCast(ctx));
        s.conn.writeAll(bytes) catch return error.TransportFailed;
    }

    fn closeFn(ctx: *anyopaque) void {
        const s: *Session = @ptrCast(@alignCast(ctx));
        s.conn.close() catch {}; // close_notify, best effort
        s.destroy();
    }
};

fn serveTask(srv: *mqtt.TcpServer) void {
    srv.serve() catch {};
}

/// The client half: `Transport.write` seals into the TLS client's writer,
/// reads pull plaintext into `Client.feed`.
const TlsLink = struct {
    tc: tlsclient.Client,
    sw: *net.Stream.Writer,

    fn transport(l: *TlsLink) mqtt.Transport {
        return .{ .ctx = l, .writeFn = writeFn };
    }

    fn writeFn(ctx: *anyopaque, bytes: []const u8) mqtt.TransportError!void {
        const l: *TlsLink = @ptrCast(@alignCast(ctx));
        l.tc.writer.writeAll(bytes) catch return error.TransportFailed;
        l.tc.writer.flush() catch return error.TransportFailed;
        l.sw.interface.flush() catch return error.TransportFailed;
    }

    fn next(l: *TlsLink, c: *mqtt.Client) !mqtt.Event {
        while (true) {
            if (try c.poll(0)) |ev| return ev;
            const r = &l.tc.reader;
            try r.fillMore();
            const got = r.buffered();
            try c.feed(got);
            r.toss(got.len);
        }
    }
};

test "TcpServer.secure: an MQTT 5.0 session over TLS 1.3 through tlsserver" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const kv = comptime tlsserver.testKeyVector("p256-pkcs8");
    var pair: tlsserver.keys.CertKeyPair = undefined;
    try tlsserver.keys.CertKeyPair.fromPem(&pair, gpa, kv.cert_pem, kv.key_pem);
    defer pair.deinit(gpa);
    const ck = pair.certifiedKey();
    var prng = std.Random.DefaultPrng.init(1); // replaced per connection
    const config: tlsserver.Config = .{ .certificate = .{ .fixed = &ck }, .random = prng.random() };
    var listener: TlsListener = .{
        .gpa = gpa,
        .config = &config,
        .out_len = @max(tlsserver.server.full_record_output_len, tlsserver.server.minOutputLen(&config, &ck)),
    };

    var b = mqtt.Broker.init(gpa, .{});
    defer b.deinit();
    var srv = mqtt.TcpServer.init(io, &b);
    srv.secure = listener.secure();
    srv.bind("127.0.0.1", 0) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    defer srv.deinit();
    var serving = try io.concurrent(serveTask, .{&srv});

    const stream = srv.boundAddress().connect(io, .{ .mode = .stream }) catch |err| {
        srv.shutdown();
        serving.await(io);
        return testkit.loopbackSkip("loopback connect failed ({t})", .{err});
    };
    var net_in: [tlsclient.Client.min_buffer_len]u8 = undefined;
    var net_out: [tlsclient.Client.min_buffer_len]u8 = undefined;
    var tls_in: [tlsclient.Client.min_buffer_len]u8 = undefined;
    var tls_out: [tlsclient.Client.min_buffer_len]u8 = undefined;
    var sr = stream.reader(io, &net_in);
    var sw = stream.writer(io, &net_out);
    var entropy: [tlsclient.Client.Options.entropy_len]u8 = undefined;
    io.random(&entropy);
    var link: TlsLink = .{ .sw = &sw, .tc = undefined };
    // The fixture certificate is only valid around 2030: the client's clock.
    const now: std.Io.Timestamp = .fromNanoseconds(@as(i96, 1_900_000_000) * std.time.ns_per_s);
    tlsclient.Client.initInto(&link.tc, &sr.interface, &sw.interface, .{
        .host = .{ .explicit = "localhost" },
        .ca = .self_signed,
        .read_buffer = &tls_in,
        .write_buffer = &tls_out,
        .entropy = &entropy,
        .realtime_now = now,
        .min_version = .tls_1_3,
    }) catch |err| {
        stream.close(io);
        srv.shutdown();
        serving.await(io);
        return err;
    };

    var rx: [4096]u8 = undefined;
    var tx: [4096]u8 = undefined;
    var c = mqtt.Client.init(link.transport(), .{ .rx = &rx, .tx = &tx });
    errdefer {
        stream.close(io);
        srv.shutdown();
        serving.await(io);
    }
    try c.connect(0, .{ .client_id = "tls-listener", .version = .v5 });
    const ack = try link.next(&c);
    try testing.expect(ack == .connack and ack.connack.reason_code == .success);
    _ = try c.subscribe(0, &.{.{ .filter = "tls/#", .qos = .at_least_once }});
    try testing.expect((try link.next(&c)) == .suback);
    _ = try c.publish(0, "tls/listener", "encrypted", .{ .qos = .at_least_once });
    var got_msg = false;
    var got_ack = false;
    while (!(got_msg and got_ack)) switch (try link.next(&c)) {
        .message => |m| {
            try testing.expectEqualStrings("encrypted", m.payload);
            got_msg = true;
        },
        .puback => got_ack = true,
        else => {},
    };
    try c.disconnect(0);

    // The client goes before the server (see the plain loopback test).
    stream.close(io);
    srv.shutdown();
    serving.await(io);
}
