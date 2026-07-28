// SPDX-License-Identifier: MIT

//! **Live BACnet/SC interop over a real WebSocket.**
//!
//! Gated on `BACNET_SC_TEST_HUB=host:port` (our node dials out) and
//! `BACNET_SC_TEST_LISTEN=host:port` (our hub listens). With neither set —
//! the normal case, and what CI does — each test prints `SKIPPED: ...` and
//! passes. A peer that is configured but silent is a **failure**, never a
//! skip.
//!
//! **What the peer is, exactly.** Annex AB's *codec* has two independent
//! third-party implementations that this module is byte-compared against (see
//! `sc_goldens.zig`). Its *connection state machine* does not: bacpypes3
//! 0.0.106 ships `bacpypes3.sc.bvll` but its `bacpypes3.sc.service` hands
//! every BVLC message straight up to the application without answering a
//! Connect-Request at all, and bacnet-stack's hub needs libwebsockets, which
//! could not be built here. So the peer these tests were developed against is
//! a **hybrid**, and it is labelled as one:
//!
//! * every BVLC-SC frame it sends is encoded by **bacpypes3's** encoders and
//!   every frame it receives is decoded by **bacpypes3's** decoders — that
//!   part is genuinely third party, over a real socket;
//! * the *hub policy* on top (admit, resolve, forward) is harness code, so it
//!   is **not** an independent check of our state machine, only of our wire
//!   format, our WebSocket binding and our framing.
//!
//! SPEC.md says the same thing in the same words. Do not read these tests as
//! a certified interop result; read them as "our octets go into a foreign
//! decoder over a real TLS-shaped socket and come back out intact".
//!
//! The transport is plaintext `ws://` on loopback. That is deliberate and is
//! the one thing that is *not* conforming BACnet/SC: this collection does not
//! implement TLS, `sc_ws.TlsAssertion.none` says so, and the node therefore
//! declines to claim a secure path. See `sc_ws.zig` for the seam.

const std = @import("std");
const websocket = @import("websocket");
const sc = @import("sc.zig");
const sc_ws = @import("sc_ws.zig");
const sc_node = @import("sc_node.zig");
const sc_hub = @import("sc_hub.zig");

// Skip diagnostics are opt-in: `zig build test` must be silent on
// success (any stderr triggers the build runner's `failed command:`
// line even when the step succeeded), while the skip *count* still
// shows up in the summary regardless. Set ZIG_LIBS_VERBOSE_SKIP to any
// non-empty value to see the reasons. (std.posix.getenv doesn't exist
// in 0.16 — std.testing.environ + Environ.getPosix is the repo's
// existing env-read pattern for tests, see netconf's `envVar`.)
fn verboseSkip() bool {
    const v = std.process.Environ.getPosix(std.testing.environ, "ZIG_LIBS_VERBOSE_SKIP") orelse return false;
    return v.len > 0;
}

const testing = std.testing;

fn envVar(name: []const u8) ?[]const u8 {
    return std.process.Environ.getPosix(std.testing.environ, name);
}

fn address(spec: []const u8) ?std.Io.net.IpAddress {
    const colon = std.mem.lastIndexOfScalar(u8, spec, ':') orelse return null;
    const port = std.fmt.parseInt(u16, spec[colon + 1 ..], 10) catch return null;
    var octets: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, spec[0..colon], '.');
    for (&octets) |*o| {
        const part = it.next() orelse return null;
        o.* = std.fmt.parseInt(u8, part, 10) catch return null;
    }
    if (it.next() != null) return null;
    return .{ .ip4 = .{ .bytes = octets, .port = port } };
}

fn skip(comptime what: []const u8, comptime which: []const u8) void {
    if (verboseSkip()) std.debug.print("SKIPPED: {s} (set {s}=host:port to run)\n", .{ what, which });
}

// ── minimal HTTP-head scanning, for this file only ─────────────────────────
//
// `websocket.handshake` validates a parsed `http.h1` head, and `bacnet` does
// not depend on `http`. Rather than widen the module's dependency graph for a
// gated test, these two helpers do the bare minimum on the raw bytes: find the
// end of the head, pull one header out, and let `websocket.handshake` compute
// and check the accept key. They are test scaffolding, not a parser.

fn headEnd(buf: []const u8) ?usize {
    return if (std.mem.indexOf(u8, buf, "\r\n\r\n")) |i| i + 4 else null;
}

fn headerValue(head: []const u8, name: []const u8) ?[]const u8 {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.next(); // start line
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, line[0..colon], " \t"), name)) continue;
        return std.mem.trim(u8, line[colon + 1 ..], " \t");
    }
    return null;
}

// ── a live WebSocket connection, driven by hand ────────────────────────────

const Link = struct {
    io: std.Io,
    stream: std.Io.net.Stream,
    wbuf: [4096]u8 = undefined,
    /// Bytes read but not yet consumed by the frame parser.
    pending: [8192]u8 = undefined,
    pending_len: usize = 0,
    conn: websocket.connection.Connection = undefined,
    /// The `Connection`'s fragment-reassembly space.
    msg_buf: [4096]u8 = undefined,
    /// Where a completed message is copied to, so the caller can keep it while
    /// the receive buffers shift underneath.
    out_buf: [4096]u8 = undefined,

    fn writeRaw(self: *Link, bytes: []const u8) !void {
        var sw = self.stream.writer(self.io, &self.wbuf);
        sw.interface.writeAll(bytes) catch return error.WriteFailed;
        sw.interface.flush() catch return error.WriteFailed;
    }

    fn readable(self: *Link, ms: u32) bool {
        var fds = [_]std.posix.pollfd{.{
            .fd = self.stream.socket.handle,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        const n = std.posix.poll(&fds, @intCast(ms)) catch return false;
        return n != 0;
    }

    /// Reads whatever is available into `pending`. Returns false on timeout.
    ///
    /// Deliberately `std.posix.read` rather than a `std.Io.net.Stream.Reader`:
    /// creating a Reader on this socket was observed to stop subsequent writes
    /// through the paired `Stream.Writer` from reaching the wire under
    /// `std.Io.Threaded`. Reading the raw descriptor sidesteps it, and this is
    /// gated test scaffolding, not library code.
    fn fill(self: *Link, ms: u32) !bool {
        if (!self.readable(ms)) return false;
        const got = std.posix.read(
            self.stream.socket.handle,
            self.pending[self.pending_len..],
        ) catch return error.ReadFailed;
        if (got == 0) return error.PeerClosed;
        self.pending_len += got;
        return true;
    }

    /// Reads the HTTP head (up to `\r\n\r\n`) and leaves anything after it in
    /// `pending`.
    fn readHead(self: *Link, out: []u8, ms: u32) ![]u8 {
        var deadline: usize = 0;
        while (deadline < 50) : (deadline += 1) {
            if (headEnd(self.pending[0..self.pending_len])) |end| {
                @memcpy(out[0..end], self.pending[0..end]);
                std.mem.copyForwards(
                    u8,
                    self.pending[0 .. self.pending_len - end],
                    self.pending[end..self.pending_len],
                );
                self.pending_len -= end;
                return out[0..end];
            }
            if (!try self.fill(ms)) return error.HandshakeTimeout;
        }
        return error.HandshakeTimeout;
    }

    /// One BVLC-SC message, or null on timeout. Borrows until the next call.
    fn recv(self: *Link, ms: u32) !?[]const u8 {
        var rounds: usize = 0;
        while (rounds < 100) : (rounds += 1) {
            const r = try sc_ws.receive(&self.conn, self.pending[0..self.pending_len]);
            switch (r.event) {
                .need_more => {
                    if (!try self.fill(ms)) return null;
                    continue;
                },
                .message => |m| {
                    // Copy out before the buffer shifts under us. It goes to a
                    // buffer of its own: `m` may already point *into*
                    // `msg_buf` when the peer fragmented the message.
                    const len = m.len;
                    @memcpy(self.out_buf[0..len], m);
                    self.consume(r.consumed);
                    return self.out_buf[0..len];
                },
                .ping, .pong, .partial => {
                    self.consume(r.consumed);
                    continue;
                },
                .close => |c| {
                    std.debug.print("live SC: peer closed code={?d} reason={s}\n", .{ c.code, c.reason });
                    return error.PeerClosed;
                },
            }
        }
        return null;
    }

    fn consume(self: *Link, n: usize) void {
        std.mem.copyForwards(
            u8,
            self.pending[0 .. self.pending_len - n],
            self.pending[n..self.pending_len],
        );
        self.pending_len -= n;
    }

    fn send(self: *Link, bvlc: []const u8, mask: ?[4]u8) !void {
        var frame: [4200]u8 = undefined;
        var w = std.Io.Writer.fixed(&frame);
        try sc_ws.writeMessage(&w, bvlc, mask);
        try self.writeRaw(w.buffered());
    }
};

// ── our node against a live hub ────────────────────────────────────────────

test "live BACnet/SC: our node connects to a hub and exchanges NPDUs" {
    const spec = envVar("BACNET_SC_TEST_HUB") orelse {
        skip("live BACnet/SC node", "BACNET_SC_TEST_HUB");
        return;
    };
    const addr = address(spec) orelse return error.BadHubAddress;

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var link: Link = .{ .io = io, .stream = try addr.connect(io, .{ .mode = .stream }) };
    defer link.stream.close(io);
    link.conn = websocket.connection.Connection.init(.client, &link.msg_buf, 8192);

    var prng = std.Random.DefaultPrng.init(0xBAC0_5C);
    const rand = prng.random();

    // ── the opening handshake ──────────────────────────────────────────────
    const key = websocket.handshake.generateKey(rand);
    var host_buf: [64]u8 = undefined;
    const host = try std.fmt.bufPrint(&host_buf, "{s}", .{spec});
    var req: [512]u8 = undefined;
    var rw = std.Io.Writer.fixed(&req);
    try websocket.handshake.writeRequest(&rw, sc_ws.clientRequest(.hub, host, "/", &key));
    try link.writeRaw(rw.buffered());

    var head_buf: [2048]u8 = undefined;
    const head = try link.readHead(&head_buf, 3000);
    try testing.expect(std.mem.startsWith(u8, head, "HTTP/1.1 101"));
    const accept = headerValue(head, "sec-websocket-accept") orelse return error.NoAcceptHeader;
    const expected = websocket.handshake.computeAcceptKey(&key);
    try testing.expectEqualStrings(&expected, accept);
    // The registered subprotocol must be negotiated, or the peer is not a
    // BACnet/SC hub at all.
    try sc_ws.verifyNegotiated(headerValue(head, "sec-websocket-protocol"), .hub);

    // ── the BACnet/SC connection ───────────────────────────────────────────
    var node = sc_node.Node.init(.{
        .vmac = sc.Vmac.random(rand),
        .uuid = sc.Uuid.random(rand),
        .primary_uri = spec,
        .tls = .none, // plaintext loopback; see the file comment
    }, rand);

    var now: u64 = 0;
    _ = node.start(now);
    _ = try node.onWebSocketOpen(now);
    try pump(&link, &node, rand);

    // The hub must answer the Connect-Request.
    const accept_frame = (try link.recv(3000)) orelse return error.HubSilent;
    const ev = try node.onMessage(now, accept_frame);
    try testing.expectEqual(sc_node.State.connected, node.state);
    std.debug.print(
        "live SC: connected, hub vmac {f}, max bvlc {d}, max npdu {d}\n",
        .{ ev.connected.peer.vmac, ev.connected.max_bvlc_length, ev.connected.max_npdu_length },
    );

    // ── a heartbeat round trip ─────────────────────────────────────────────
    now += 150_000;
    _ = try node.poll(now);
    try pump(&link, &node, rand);
    const hb = (try link.recv(3000)) orelse return error.NoHeartbeatAck;
    const hb_msg = try sc.decode(hb);
    try testing.expectEqual(sc.Function.heartbeat_ack, hb_msg.function());
    _ = try node.onMessage(now, hb);
    std.debug.print("live SC: heartbeat acknowledged (id {d})\n", .{hb_msg.header.message_id});

    // ── an Encapsulated-NPDU, broadcast, echoed back by the harness ────────
    const who_is = [_]u8{ 0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF, 0x10, 0x08 };
    try node.sendNpdu(sc.Vmac.broadcast, &who_is);
    try pump(&link, &node, rand);
    if (try link.recv(3000)) |echo| {
        const back = try sc.decode(echo);
        try testing.expectEqual(sc.Function.encapsulated_npdu, back.function());
        const got = back.payload.encapsulated_npdu;
        if (std.mem.eql(u8, got, &who_is)) {
            std.debug.print("live SC: NPDU echoed back intact ({d} octets)\n", .{who_is.len});
        } else {
            // bacpypes3 0.0.106's `sc.bvll` **decoder** consumes one octet too
            // many whenever a VMAC is present and no header options are: it
            // reads a header-option marker the control octet never announced.
            // (With no VMAC at all it is correct, and its *encoder* is correct
            // in every case — which is why the goldens come from the encoder.)
            // So what a bacpypes3-decoding peer echoes is our NPDU minus its
            // first octet. Assert exactly that rather than pretending.
            try testing.expectEqualSlices(u8, who_is[1..], got);
            std.debug.print(
                "live SC: NPDU echoed back minus its first octet — bacpypes3 0.0.106 " ++
                    "decoder defect (over-reads the header option list), not ours\n",
                .{},
            );
        }
        _ = try node.onMessage(now, echo);
    } else return error.NoNpduEcho;

    // ── a graceful disconnect ──────────────────────────────────────────────
    _ = try node.stop(now);
    try pump(&link, &node, rand);
    const bye = (try link.recv(3000)) orelse return error.NoDisconnectAck;
    try testing.expectEqual(sc.Function.disconnect_ack, (try sc.decode(bye)).function());
    _ = try node.onMessage(now, bye);
    try testing.expectEqual(sc_node.State.stopped, node.state);
    std.debug.print("live SC: disconnected cleanly\n", .{});
}

/// Transmits everything the node has queued.
fn pump(link: *Link, node: *sc_node.Node, rand: std.Random) !void {
    while (node.nextOutgoing()) |frame| {
        var mask: [4]u8 = undefined;
        rand.bytes(&mask);
        try link.send(frame, mask);
    }
}

// ── our hub against a live node ────────────────────────────────────────────

test "live BACnet/SC: our hub admits a third-party node" {
    const spec = envVar("BACNET_SC_TEST_LISTEN") orelse {
        skip("live BACnet/SC hub", "BACNET_SC_TEST_LISTEN");
        return;
    };
    const addr = address(spec) orelse return error.BadListenAddress;

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    std.debug.print("live SC hub: listening on {s}\n", .{spec});

    var prng = std.Random.DefaultPrng.init(0x5C_BAC0);
    const rand = prng.random();
    var hub = sc_hub.Hub.init(.{
        .vmac = sc.Vmac.random(rand),
        .uuid = sc.Uuid.random(rand),
        .websocket_uris = "",
    }, rand);

    const accepted = try server.accept(io);
    var link: Link = .{ .io = io, .stream = accepted };
    defer link.stream.close(io);
    link.conn = websocket.connection.Connection.init(.server, &link.msg_buf, 8192);

    // ── the opening handshake, server side ─────────────────────────────────
    var head_buf: [2048]u8 = undefined;
    const head = try link.readHead(&head_buf, 5000);
    try testing.expect(std.mem.startsWith(u8, head, "GET "));
    const key = headerValue(head, "sec-websocket-key") orelse return error.NoKeyHeader;
    const offered = headerValue(head, "sec-websocket-protocol") orelse return error.NoSubprotocol;
    try testing.expect(std.mem.indexOf(u8, offered, sc.subprotocol_hub) != null);

    const accept_key = websocket.handshake.computeAcceptKey(key);
    var res: [256]u8 = undefined;
    var rw = std.Io.Writer.fixed(&res);
    try rw.print(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ++
            "Sec-WebSocket-Accept: {s}\r\nSec-WebSocket-Protocol: {s}\r\n\r\n",
        .{ accept_key, sc.subprotocol_hub },
    );
    try link.writeRaw(rw.buffered());

    // ── admit the node ─────────────────────────────────────────────────────
    var now: u64 = 0;
    const conn = try hub.accept(now);
    var served: usize = 0;
    var rounds: usize = 0;
    while (rounds < 40) : (rounds += 1) {
        const maybe = link.recv(500) catch |e| switch (e) {
            // The node hung up; that is how this test ends when the peer is
            // done rather than a failure.
            error.PeerClosed => break,
            else => return e,
        };
        const frame = maybe orelse continue;
        const ev = hub.onMessage(now, conn, frame) catch |e| {
            std.debug.print("live SC hub: refused a frame: {t}\n", .{e});
            continue;
        };
        served += 1;
        switch (ev) {
            .node_connected => |n| std.debug.print(
                "live SC hub: admitted vmac {f}\n",
                .{n.vmac},
            ),
            .node_disconnected => |n| std.debug.print(
                "live SC hub: node left ({t})\n",
                .{n.reason},
            ),
            else => {},
        }
        while (hub.nextOutgoing()) |o| try link.send(o.bytes, null);
        now += 10;
        if (hub.nodeCount() == 0 and served > 1) break;
    }
    std.debug.print("live SC hub: served {d} frames, admitted {d}\n", .{ served, hub.admitted });
    try testing.expect(hub.admitted >= 1);
}
