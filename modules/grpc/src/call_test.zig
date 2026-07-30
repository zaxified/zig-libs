// SPDX-License-Identifier: MIT

//! Offline call tests: the client driven over fixed buffers, with the server
//! half **fabricated frame by frame** from an `http.h2.Connection` in server
//! role. Nothing here needs a socket, a python interpreter or a network.
//!
//! What this file can prove, and what it deliberately cannot: it can script
//! response shapes a real server would be hard-pressed to produce on demand
//! (a status with no body, a message split at an awkward offset, a length
//! that lies), and it can pin the exact bytes the client puts on the wire.
//! It cannot prove that those bytes are the *right* bytes — a framing defect
//! that is consistent between our writer and our reader survives every test
//! here by construction. That is what `reference_interop.zig` is for, and the
//! two files are complementary rather than redundant.

const std = @import("std");
const http = @import("http");
const pb = @import("protobuf");
const grpc = @import("root.zig");

const testing = std.testing;
const h2 = http.h2;
const h2c = http.h2_client;
const hpack = http.hpack;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;
const Allocator = std.mem.Allocator;

// ── a tiny schema ───────────────────────────────────────────────────────────

const Msg = struct {
    text: []const u8 = "",
    n: i32 = 0,
    pub const pb_fields = .{
        .text = pb.Field{ .number = 1, .kind = .string },
        .n = pb.Field{ .number = 2, .kind = .int32 },
    };
};

const MsgStream = grpc.Stream(Msg, Msg);

// ── fixture ─────────────────────────────────────────────────────────────────

/// Heap-allocated: the session holds pointers to `in`/`out`, so nothing here
/// may move after `init`.
const Fx = struct {
    gpa: Allocator,
    in: Reader,
    out_buf: [32 * 1024]u8,
    out: Writer,
    session: h2c.Session,
    ch: grpc.Channel,

    fn init(gpa: Allocator, options: grpc.Options) !*Fx {
        const fx = try gpa.create(Fx);
        errdefer gpa.destroy(fx);
        fx.gpa = gpa;
        fx.in = .fixed("");
        fx.out = .fixed(&fx.out_buf);
        fx.session = try h2c.Session.init(gpa, &fx.in, &fx.out, .{});
        fx.ch = grpc.Channel.init(gpa, &fx.session, options);
        return fx;
    }

    fn deinit(fx: *Fx) void {
        const gpa = fx.gpa;
        fx.session.deinit();
        gpa.destroy(fx);
    }

    /// Everything the client has written so far.
    fn clientBytes(fx: *const Fx) []const u8 {
        return fx.out.buffered();
    }

    /// Point the client at scripted server bytes.
    fn reply(fx: *Fx, bytes: []const u8) void {
        fx.in = .fixed(bytes);
    }
};

/// The scripted peer: a real h2 server-role connection whose handshake with
/// the client's staged bytes is already done, ready to emit exact frames.
const Peer = struct {
    conn: h2.Connection,
    wire: std.ArrayList(u8) = .empty,
    events: std.ArrayList(h2.Event) = .empty,

    fn init(client_bytes: []const u8) !Peer {
        const gpa = testing.allocator;
        var p: Peer = .{ .conn = .init(gpa, .server, .{}) };
        errdefer p.deinit();
        try p.conn.sendPreface(&p.wire);
        try p.conn.recv(client_bytes, &p.wire, &p.events);
        return p;
    }

    fn deinit(p: *Peer) void {
        const gpa = testing.allocator;
        for (p.events.items) |*ev| ev.deinit(gpa);
        p.events.deinit(gpa);
        p.wire.deinit(gpa);
        p.conn.deinit();
    }

    /// The decoded request header block for `sid`, or null.
    fn requestHeaders(p: *const Peer, sid: u31) ?hpack.HeaderList {
        for (p.events.items) |ev| {
            switch (ev) {
                .headers => |hd| if (hd.stream_id == sid) return hd.headers,
                else => {},
            }
        }
        return null;
    }

    /// Every DATA octet the client sent on `sid`, concatenated.
    fn requestBody(p: *const Peer, gpa: Allocator, sid: u31) ![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(gpa);
        for (p.events.items) |ev| {
            switch (ev) {
                .data => |d| if (d.stream_id == sid) try out.appendSlice(gpa, d.data),
                else => {},
            }
        }
        return out.toOwnedSlice(gpa);
    }

    fn okHeaders(p: *Peer, sid: u31, end: bool) !void {
        try p.conn.sendHeaders(&p.wire, sid, &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-type", .value = "application/grpc+proto" },
        }, end);
    }

    fn trailers(p: *Peer, sid: u31, fields: []const hpack.Field) !void {
        try p.conn.sendHeaders(&p.wire, sid, fields, true);
    }

    fn okTrailers(p: *Peer, sid: u31) !void {
        try p.trailers(sid, &.{.{ .name = "grpc-status", .value = "0" }});
    }

    fn data(p: *Peer, sid: u31, bytes: []const u8, end: bool) !void {
        try p.conn.sendData(&p.wire, sid, bytes, end);
    }
};

fn framed(gpa: Allocator, value: Msg) ![]u8 {
    const body = try pb.encodeAlloc(gpa, value, .{});
    defer gpa.free(body);
    return grpc.frame.encodeAlloc(gpa, body);
}

/// Build a complete server byte stream for stream 1 **ahead of time**, so a
/// call that sends and reads in one go (`grpc.unary`) can be tested: a
/// throwaway client produces a representative request for the peer to
/// handshake against, and the resulting frames are handed back.
fn stagedResponse(gpa: Allocator, script: *const fn (*Peer) anyerror!void) ![]u8 {
    const fx = try Fx.init(gpa, .{});
    defer fx.deinit();
    var call = try fx.ch.start("/s/m", .{});
    defer call.deinit();
    try call.sendMessage("", true);

    var peer = try Peer.init(fx.clientBytes());
    defer peer.deinit();
    try script(&peer);
    return gpa.dupe(u8, peer.wire.items);
}

// ── the request the client puts on the wire ────────────────────────────────

test "request: pseudo-headers, te/content-type, timeout, metadata and the LPM body" {
    const gpa = testing.allocator;
    const fx = try Fx.init(gpa, .{});
    defer fx.deinit();

    var call = try fx.ch.start("/pkg.Svc/Method", .{
        .timeout = .{ .value = 250, .unit = .milliseconds },
        .metadata = &.{
            .{ .name = "x-token", .value = "abc" },
            .{ .name = "x-trace-bin", .value = &.{ 0x00, 0xff, 0x10 } },
        },
    });
    defer call.deinit();
    try call.sendMessage("hi", true);

    var peer = try Peer.init(fx.clientBytes());
    defer peer.deinit();
    const hl = peer.requestHeaders(1).?;

    try testing.expectEqualStrings("POST", fieldValue(hl, ":method").?);
    try testing.expectEqualStrings("/pkg.Svc/Method", fieldValue(hl, ":path").?);
    try testing.expectEqualStrings("http", fieldValue(hl, ":scheme").?);
    try testing.expectEqualStrings("trailers", fieldValue(hl, "te").?);
    try testing.expectEqualStrings("application/grpc+proto", fieldValue(hl, "content-type").?);
    try testing.expectEqualStrings("250m", fieldValue(hl, "grpc-timeout").?);
    try testing.expectEqualStrings("identity", fieldValue(hl, "grpc-accept-encoding").?);
    try testing.expectEqualStrings("abc", fieldValue(hl, "x-token").?);
    // The -bin key travels base64-encoded, unpadded, and the caller never saw
    // the encoding.
    try testing.expectEqualStrings("AP8Q", fieldValue(hl, "x-trace-bin").?);

    // …and the body is exactly one length-prefixed message: flag 0, then the
    // length big-endian, then the payload. Literal bytes on purpose — any
    // mutation to the prefix layout has to break this line.
    const body = try peer.requestBody(gpa, 1);
    defer gpa.free(body);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x00, 0x00, 0x00, 0x02, 'h', 'i' }, body);
}

test "request: a metadata key this layer owns is refused, not duplicated" {
    const gpa = testing.allocator;
    const fx = try Fx.init(gpa, .{});
    defer fx.deinit();
    try testing.expectError(error.ReservedMetadata, fx.ch.start("/s/m", .{
        .metadata = &.{.{ .name = "grpc-timeout", .value = "1S" }},
    }));
    try testing.expectError(error.ReservedMetadata, fx.ch.start("/s/m", .{
        .metadata = &.{.{ .name = "Content-Type", .value = "text/plain" }},
    }));
}

test "request: several messages are several prefixes on one stream" {
    const gpa = testing.allocator;
    const fx = try Fx.init(gpa, .{});
    defer fx.deinit();

    var call = try fx.ch.start("/s/m", .{});
    defer call.deinit();
    try call.sendMessage("a", false);
    try call.sendMessage("bcd", false);
    try call.sendMessage("", false);
    try call.closeSend();

    var peer = try Peer.init(fx.clientBytes());
    defer peer.deinit();
    const body = try peer.requestBody(gpa, 1);
    defer gpa.free(body);
    try testing.expectEqualSlices(u8, &.{
        0x00, 0x00, 0x00, 0x00, 0x01, 'a',
        0x00, 0x00, 0x00, 0x00, 0x03, 'b',
        'c',  'd',  0x00, 0x00, 0x00, 0x00,
        0x00,
    }, body);
}

test "request: an empty body still gets its END_STREAM" {
    const gpa = testing.allocator;
    const fx = try Fx.init(gpa, .{});
    defer fx.deinit();

    var call = try fx.ch.start("/s/m", .{});
    defer call.deinit();
    try call.closeSend();
    try testing.expect(fx.session.sendEnded(1));
    // Idempotent: a second close is not a `SendClosed` error at this layer.
    try call.closeSend();
}

// ── the response, in its two shapes ────────────────────────────────────────

test "response: HEADERS, DATA, TRAILERS — the ordinary shape" {
    const gpa = testing.allocator;
    const fx = try Fx.init(gpa, .{});
    defer fx.deinit();

    var s = try MsgStream.start(&fx.ch, "/s/m", .{});
    defer s.deinit();
    try s.sendEnd(.{ .text = "ping" });

    var peer = try Peer.init(fx.clientBytes());
    defer peer.deinit();
    const reply = try framed(gpa, .{ .text = "pong", .n = 3 });
    defer gpa.free(reply);
    try peer.okHeaders(1, false);
    try peer.data(1, reply, false);
    try peer.okTrailers(1);
    fx.reply(peer.wire.items);

    var got = (try s.receive()).?;
    defer got.deinit();
    try testing.expectEqualStrings("pong", got.value.text);
    try testing.expectEqual(@as(i32, 3), got.value.n);
    try testing.expectEqual(@as(?pb.Decoded(Msg), null), try s.receive());
    try s.finish();
    try testing.expectEqual(grpc.Status.ok, s.call.status.?);
}

test "response: Trailers-Only — a status with no body, and no trailer section" {
    const gpa = testing.allocator;
    const fx = try Fx.init(gpa, .{});
    defer fx.deinit();

    var s = try MsgStream.start(&fx.ch, "/s/m", .{});
    defer s.deinit();
    try s.sendEnd(.{});

    var peer = try Peer.init(fx.clientBytes());
    defer peer.deinit();
    // ONE frame, END_STREAM, status inside it. A client that only looks for
    // trailers after a body blocks here forever.
    try peer.conn.sendHeaders(&peer.wire, 1, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "application/grpc+proto" },
        .{ .name = "grpc-status", .value = "7" },
        .{ .name = "grpc-message", .value = "no%20entry%0Ahere" },
    }, true);
    fx.reply(peer.wire.items);

    try testing.expectEqual(@as(?pb.Decoded(Msg), null), try s.receive());
    try testing.expect(s.call.trailers_only);
    try testing.expect(s.call.trailingMetadata() == null);
    try testing.expectError(error.PermissionDenied, s.finish());
    try testing.expectEqual(grpc.Status.permission_denied, s.call.status.?);
    // Percent-decoded, not passed through raw.
    try testing.expectEqualStrings("no entry\nhere", s.call.statusMessage());
}

test "response: an empty successful body is NOT how a Trailers-Only error reads" {
    const gpa = testing.allocator;
    const fx = try Fx.init(gpa, .{});
    defer fx.deinit();

    var s = try MsgStream.start(&fx.ch, "/s/m", .{});
    defer s.deinit();
    try s.sendEnd(.{});

    var peer = try Peer.init(fx.clientBytes());
    defer peer.deinit();
    // The genuinely-empty-but-successful response: HEADERS without a status,
    // then trailers saying OK. It must stay distinguishable from the case
    // above, and the distinguishing fact is the status, not the emptiness.
    try peer.okHeaders(1, false);
    try peer.okTrailers(1);
    fx.reply(peer.wire.items);

    try testing.expectEqual(@as(?pb.Decoded(Msg), null), try s.receive());
    try testing.expect(!s.call.trailers_only);
    try s.finish(); // no error: this one really did succeed
    try testing.expectEqual(grpc.Status.ok, s.call.status.?);
}

test "response: a non-OK status after a body is still raised, not swallowed" {
    const gpa = testing.allocator;
    const fx = try Fx.init(gpa, .{});
    defer fx.deinit();

    var s = try MsgStream.start(&fx.ch, "/s/m", .{});
    defer s.deinit();
    try s.sendEnd(.{});

    var peer = try Peer.init(fx.clientBytes());
    defer peer.deinit();
    const one = try framed(gpa, .{ .text = "partial" });
    defer gpa.free(one);
    try peer.okHeaders(1, false);
    try peer.data(1, one, false);
    try peer.trailers(1, &.{
        .{ .name = "grpc-status", .value = "8" },
        .{ .name = "grpc-message", .value = "over budget" },
    });
    fx.reply(peer.wire.items);

    var got = (try s.receive()).?;
    got.deinit();
    try testing.expectEqual(@as(?pb.Decoded(Msg), null), try s.receive());
    try testing.expectError(error.ResourceExhausted, s.finish());
    try testing.expectEqualStrings("over budget", s.call.statusMessage());
}

test "response: grpc-status in the initial HEADERS ends the call there" {
    const gpa = testing.allocator;
    const fx = try Fx.init(gpa, .{});
    defer fx.deinit();

    var s = try MsgStream.start(&fx.ch, "/s/m", .{});
    defer s.deinit();
    try s.sendEnd(.{});

    // A HEADERS frame carrying `grpc-status` is a Trailers-Only response by
    // the spec's own definition (the status is in the initial metadata), even
    // without END_STREAM. This pins the decision rather than leaving it to
    // whichever branch happens to run first.
    var peer = try Peer.init(fx.clientBytes());
    defer peer.deinit();
    try peer.conn.sendHeaders(&peer.wire, 1, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "application/grpc+proto" },
        .{ .name = "grpc-status", .value = "0" },
    }, false);
    const one = try framed(gpa, .{ .text = "late" });
    defer gpa.free(one);
    try peer.data(1, one, true);
    fx.reply(peer.wire.items);

    try testing.expectEqual(@as(?pb.Decoded(Msg), null), try s.receive());
    try s.finish();
    try testing.expectEqual(grpc.Status.ok, s.call.status.?);
}

test "response: metadata stays readable after finish, in both sections" {
    const gpa = testing.allocator;
    const fx = try Fx.init(gpa, .{});
    defer fx.deinit();

    var call = try fx.ch.start("/s/m", .{});
    defer call.deinit();
    try call.sendMessage("", true);

    var peer = try Peer.init(fx.clientBytes());
    defer peer.deinit();
    try peer.conn.sendHeaders(&peer.wire, 1, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "application/grpc+proto" },
        .{ .name = "x-head", .value = "H" },
        .{ .name = "x-head-bin", .value = "AP8Q" },
    }, false);
    try peer.trailers(1, &.{
        .{ .name = "grpc-status", .value = "0" },
        .{ .name = "x-tail", .value = "T" },
    });
    fx.reply(peer.wire.items);

    try testing.expectEqual(@as(?[]const u8, null), try call.receive());
    try call.finish();

    // Checking the status first and reading metadata afterwards is the
    // natural order, so both lists must outlive `finish` — they are borrowed
    // from the session, and the stream is only released by `deinit`.
    try testing.expectEqualStrings("H", call.metadataValue("x-head").?);
    try testing.expectEqualStrings("T", call.metadataValue("x-tail").?);
    const bin = (try call.metadataValueDecoded("x-head-bin")).?;
    defer bin.deinit(gpa);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0xff, 0x10 }, bin.bytes);
}

// ── framing across DATA-frame boundaries ───────────────────────────────────

test "response: three messages inside ONE DATA frame" {
    const gpa = testing.allocator;
    const fx = try Fx.init(gpa, .{});
    defer fx.deinit();

    var s = try MsgStream.start(&fx.ch, "/s/m", .{});
    defer s.deinit();
    try s.sendEnd(.{});

    var blob: std.ArrayList(u8) = .empty;
    defer blob.deinit(gpa);
    for ([_][]const u8{ "a", "bb", "ccc" }) |t| {
        const f = try framed(gpa, .{ .text = t });
        defer gpa.free(f);
        try blob.appendSlice(gpa, f);
    }

    var peer = try Peer.init(fx.clientBytes());
    defer peer.deinit();
    try peer.okHeaders(1, false);
    try peer.data(1, blob.items, false);
    try peer.okTrailers(1);
    fx.reply(peer.wire.items);

    for ([_][]const u8{ "a", "bb", "ccc" }) |want| {
        var got = (try s.receive()).?;
        defer got.deinit();
        try testing.expectEqualStrings(want, got.value.text);
    }
    try testing.expectEqual(@as(?pb.Decoded(Msg), null), try s.receive());
    try s.finish();
}

test "response: one message split across DATA frames, at every split point" {
    const gpa = testing.allocator;
    const payload = "a message long enough to be worth cutting up";
    const whole = try framed(gpa, .{ .text = payload, .n = 42 });
    defer gpa.free(whole);

    var cut: usize = 1;
    while (cut < whole.len) : (cut += 1) {
        const fx = try Fx.init(gpa, .{});
        defer fx.deinit();
        var s = try MsgStream.start(&fx.ch, "/s/m", .{});
        defer s.deinit();
        try s.sendEnd(.{});

        var peer = try Peer.init(fx.clientBytes());
        defer peer.deinit();
        try peer.okHeaders(1, false);
        // Two DATA frames, split at `cut` — including splits inside the
        // 5-byte prefix itself.
        try peer.data(1, whole[0..cut], false);
        try peer.data(1, whole[cut..], false);
        try peer.okTrailers(1);
        fx.reply(peer.wire.items);

        var got = (try s.receive()).?;
        defer got.deinit();
        try testing.expectEqualStrings(payload, got.value.text);
        try testing.expectEqual(@as(i32, 42), got.value.n);
        try testing.expectEqual(@as(?pb.Decoded(Msg), null), try s.receive());
        try s.finish();
    }
}

test "response: a message that stops mid-stream is INTERNAL, not a short read" {
    const gpa = testing.allocator;
    const fx = try Fx.init(gpa, .{});
    defer fx.deinit();

    var s = try MsgStream.start(&fx.ch, "/s/m", .{});
    defer s.deinit();
    try s.sendEnd(.{});

    const whole = try framed(gpa, .{ .text = "truncated" });
    defer gpa.free(whole);

    var peer = try Peer.init(fx.clientBytes());
    defer peer.deinit();
    try peer.okHeaders(1, false);
    try peer.data(1, whole[0 .. whole.len - 3], false); // three bytes short
    try peer.okTrailers(1);
    fx.reply(peer.wire.items);

    try testing.expectError(error.Internal, s.receive());
    try testing.expectEqual(grpc.Status.internal, s.call.status.?);
}

// ── the receive limit, over a real stream ──────────────────────────────────

test "limit: a 5-byte frame claiming 4 GiB fails RESOURCE_EXHAUSTED" {
    const gpa = testing.allocator;
    const fx = try Fx.init(gpa, .{});
    defer fx.deinit();

    var s = try MsgStream.start(&fx.ch, "/s/m", .{});
    defer s.deinit();
    try s.sendEnd(.{});

    var peer = try Peer.init(fx.clientBytes());
    defer peer.deinit();
    try peer.okHeaders(1, false);
    try peer.data(1, &.{ 0x00, 0xff, 0xff, 0xff, 0xff }, false);
    try peer.okTrailers(1);
    fx.reply(peer.wire.items);

    try testing.expectError(error.ResourceExhausted, s.receive());
    try testing.expectEqual(grpc.Status.resource_exhausted, s.call.status.?);
}

test "limit: the boundary is exactly max_recv_message_size" {
    const gpa = testing.allocator;
    const body = "0123456789abcdef"; // 16 bytes

    { // at the limit: accepted
        const fx = try Fx.init(gpa, .{ .max_recv_message_size = body.len });
        defer fx.deinit();
        var call = try fx.ch.start("/s/m", .{});
        defer call.deinit();
        try call.sendMessage("", true);

        var peer = try Peer.init(fx.clientBytes());
        defer peer.deinit();
        const f = try grpc.frame.encodeAlloc(gpa, body);
        defer gpa.free(f);
        try peer.okHeaders(1, false);
        try peer.data(1, f, false);
        try peer.okTrailers(1);
        fx.reply(peer.wire.items);
        try testing.expectEqualStrings(body, (try call.receive()).?);
    }
    { // one byte over: refused
        const fx = try Fx.init(gpa, .{ .max_recv_message_size = body.len - 1 });
        defer fx.deinit();
        var call = try fx.ch.start("/s/m", .{});
        defer call.deinit();
        try call.sendMessage("", true);

        var peer = try Peer.init(fx.clientBytes());
        defer peer.deinit();
        const f = try grpc.frame.encodeAlloc(gpa, body);
        defer gpa.free(f);
        try peer.okHeaders(1, false);
        try peer.data(1, f, false);
        try peer.okTrailers(1);
        fx.reply(peer.wire.items);
        try testing.expectError(error.ResourceExhausted, call.receive());
    }
}

test "limit: an oversized declaration split across DATA frames still fails at the header" {
    const gpa = testing.allocator;
    const fx = try Fx.init(gpa, .{ .max_recv_message_size = 32 });
    defer fx.deinit();

    var call = try fx.ch.start("/s/m", .{});
    defer call.deinit();
    try call.sendMessage("", true);

    var peer = try Peer.init(fx.clientBytes());
    defer peer.deinit();
    try peer.okHeaders(1, false);
    // The prefix itself arrives in two pieces, then a trickle of payload
    // that must never be accumulated.
    try peer.data(1, &.{ 0x00, 0x00, 0x0f }, false);
    try peer.data(1, &.{ 0x42, 0x40 }, false); // → declares 0x000f4240 = 1 000 000
    try peer.data(1, "x" ** 64, false);
    try peer.okTrailers(1);
    fx.reply(peer.wire.items);

    try testing.expectError(error.ResourceExhausted, call.receive());
}

test "limit: a compressed frame is refused instead of decoded as plaintext" {
    const gpa = testing.allocator;
    const fx = try Fx.init(gpa, .{});
    defer fx.deinit();

    var call = try fx.ch.start("/s/m", .{});
    defer call.deinit();
    try call.sendMessage("", true);

    var peer = try Peer.init(fx.clientBytes());
    defer peer.deinit();
    try peer.okHeaders(1, false);
    try peer.data(1, &.{ 0x01, 0x00, 0x00, 0x00, 0x03, 'x', 'y', 'z' }, false);
    try peer.okTrailers(1);
    fx.reply(peer.wire.items);

    try testing.expectError(error.Internal, call.receive());
}

// ── malformed responses ────────────────────────────────────────────────────

test "response: no grpc-status anywhere is MissingStatus, never a quiet OK" {
    const gpa = testing.allocator;
    const fx = try Fx.init(gpa, .{});
    defer fx.deinit();

    var call = try fx.ch.start("/s/m", .{});
    defer call.deinit();
    try call.sendMessage("", true);

    var peer = try Peer.init(fx.clientBytes());
    defer peer.deinit();
    try peer.okHeaders(1, false);
    try peer.data(1, "", true); // END_STREAM on DATA: no trailer section at all
    fx.reply(peer.wire.items);

    try testing.expectError(error.MissingStatus, call.receive());
}

test "response: a non-numeric grpc-status is MalformedStatus, not zero" {
    const gpa = testing.allocator;
    for ([_][]const u8{ "", " 0", "0 ", "ok", "+0", "-1" }) |bad| {
        const fx = try Fx.init(gpa, .{});
        defer fx.deinit();
        var call = try fx.ch.start("/s/m", .{});
        defer call.deinit();
        try call.sendMessage("", true);

        var peer = try Peer.init(fx.clientBytes());
        defer peer.deinit();
        try peer.okHeaders(1, false);
        try peer.trailers(1, &.{.{ .name = "grpc-status", .value = bad }});
        fx.reply(peer.wire.items);

        try testing.expectError(error.MalformedStatus, call.receive());
    }
}

test "response: a non-200 HTTP status maps through the spec's table" {
    const gpa = testing.allocator;
    const cases = [_]struct { []const u8, anyerror }{
        .{ "404", error.Unimplemented },
        .{ "401", error.Unauthenticated },
        .{ "403", error.PermissionDenied },
        .{ "429", error.Unavailable },
        .{ "503", error.Unavailable },
        .{ "418", error.Unknown },
    };
    for (cases) |case| {
        const code, const want = case;
        const fx = try Fx.init(gpa, .{});
        defer fx.deinit();
        var call = try fx.ch.start("/s/m", .{});
        defer call.deinit();
        try call.sendMessage("", true);

        var peer = try Peer.init(fx.clientBytes());
        defer peer.deinit();
        try peer.conn.sendHeaders(&peer.wire, 1, &.{
            .{ .name = ":status", .value = code },
            .{ .name = "content-type", .value = "text/html" },
        }, true);
        fx.reply(peer.wire.items);

        try testing.expectError(want, call.readHead());
    }
}

test "response: a 200 that is not application/grpc is refused before deframing" {
    const gpa = testing.allocator;
    const fx = try Fx.init(gpa, .{});
    defer fx.deinit();

    var call = try fx.ch.start("/s/m", .{});
    defer call.deinit();
    try call.sendMessage("", true);

    var peer = try Peer.init(fx.clientBytes());
    defer peer.deinit();
    try peer.conn.sendHeaders(&peer.wire, 1, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/html" },
    }, false);
    try peer.data(1, "<html>not gRPC at all</html>", false);
    try peer.okTrailers(1);
    fx.reply(peer.wire.items);

    try testing.expectError(error.Internal, call.receive());
}

test "response: a message encoding we never accepted is refused" {
    const gpa = testing.allocator;
    const fx = try Fx.init(gpa, .{});
    defer fx.deinit();

    var call = try fx.ch.start("/s/m", .{});
    defer call.deinit();
    try call.sendMessage("", true);

    var peer = try Peer.init(fx.clientBytes());
    defer peer.deinit();
    try peer.conn.sendHeaders(&peer.wire, 1, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "application/grpc+proto" },
        .{ .name = "grpc-encoding", .value = "gzip" },
    }, false);
    try peer.data(1, &.{ 0x01, 0x00, 0x00, 0x00, 0x01, 0x00 }, false);
    try peer.okTrailers(1);
    fx.reply(peer.wire.items);

    try testing.expectError(error.Internal, call.readHead());
}

// ── the unary contract ─────────────────────────────────────────────────────

fn scriptNoMessage(p: *Peer) anyerror!void {
    try p.okHeaders(1, false);
    try p.okTrailers(1);
}

test "unary: an OK response with no message is MissingMessage" {
    const gpa = testing.allocator;
    const bytes = try stagedResponse(gpa, &scriptNoMessage);
    defer gpa.free(bytes);

    const fx = try Fx.init(gpa, .{});
    defer fx.deinit();
    fx.reply(bytes);
    try testing.expectError(
        error.MissingMessage,
        grpc.unary(Msg, Msg, &fx.ch, "/s/m", .{}, .{}),
    );
}

fn scriptTwoMessages(p: *Peer) anyerror!void {
    const gpa = testing.allocator;
    const one = try framed(gpa, .{ .text = "first" });
    defer gpa.free(one);
    const two = try framed(gpa, .{ .text = "second" });
    defer gpa.free(two);
    try p.okHeaders(1, false);
    try p.data(1, one, false);
    try p.data(1, two, false);
    try p.okTrailers(1);
}

test "unary: a second reply where the contract allows one is UnexpectedMessage" {
    const gpa = testing.allocator;
    const bytes = try stagedResponse(gpa, &scriptTwoMessages);
    defer gpa.free(bytes);

    const fx = try Fx.init(gpa, .{});
    defer fx.deinit();
    fx.reply(bytes);
    try testing.expectError(
        error.UnexpectedMessage,
        grpc.unary(Msg, Msg, &fx.ch, "/s/m", .{}, .{}),
    );
}

fn scriptTrailersOnlyFailure(p: *Peer) anyerror!void {
    try p.conn.sendHeaders(&p.wire, 1, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "application/grpc+proto" },
        .{ .name = "grpc-status", .value = "5" },
        .{ .name = "grpc-message", .value = "gone%20%E2%98%83" },
    }, true);
}

test "unary: a Trailers-Only failure surfaces the status, not MissingMessage" {
    const gpa = testing.allocator;
    const bytes = try stagedResponse(gpa, &scriptTrailersOnlyFailure);
    defer gpa.free(bytes);

    const fx = try Fx.init(gpa, .{});
    defer fx.deinit();
    fx.reply(bytes);

    var failure: grpc.Failure = .{};
    defer failure.deinit(gpa);
    try testing.expectError(
        error.NotFound,
        grpc.unary(Msg, Msg, &fx.ch, "/s/m", .{}, .{ .failure = &failure }),
    );
    try testing.expectEqual(grpc.Status.not_found, failure.status);
    try testing.expectEqualStrings("gone \xe2\x98\x83", failure.message);
}

fn scriptUnaryOk(p: *Peer) anyerror!void {
    const gpa = testing.allocator;
    const one = try framed(gpa, .{ .text = "only", .n = 9 });
    defer gpa.free(one);
    try p.okHeaders(1, false);
    try p.data(1, one, false);
    try p.okTrailers(1);
}

test "unary: the happy path yields exactly one decoded reply" {
    const gpa = testing.allocator;
    const bytes = try stagedResponse(gpa, &scriptUnaryOk);
    defer gpa.free(bytes);

    const fx = try Fx.init(gpa, .{});
    defer fx.deinit();
    fx.reply(bytes);

    var reply = try grpc.unary(Msg, Msg, &fx.ch, "/s/m", .{ .text = "q" }, .{});
    defer reply.deinit();
    try testing.expectEqualStrings("only", reply.value.text);
    try testing.expectEqual(@as(i32, 9), reply.value.n);
}

// ── send-side limit ────────────────────────────────────────────────────────

test "send: max_send_message_size is enforced locally" {
    const gpa = testing.allocator;
    const fx = try Fx.init(gpa, .{ .max_send_message_size = 4 });
    defer fx.deinit();
    var call = try fx.ch.start("/s/m", .{});
    defer call.deinit();
    try call.sendMessage("1234", false);
    try testing.expectError(error.SendMessageTooLarge, call.sendMessage("12345", false));
}

// ── helpers ────────────────────────────────────────────────────────────────

fn fieldValue(hl: hpack.HeaderList, name: []const u8) ?[]const u8 {
    for (hl.fields) |f| {
        if (std.ascii.eqlIgnoreCase(f.name, name)) return f.value;
    }
    return null;
}
