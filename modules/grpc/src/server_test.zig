// SPDX-License-Identifier: MIT

//! Offline tests for the gRPC server, driven at the **HTTP/2 frame level**.
//!
//! The client's self-tests could only ever check "our framer and our deframer
//! agree", which is invisible to any mutation that stays consistent between
//! the two. The server has a stronger offline oracle available, and this file
//! uses it: an `h2.Connection` in client role sits on the other end of
//! `h2_server.serve`, so every assertion here is about *frames actually
//! produced* — how many HEADERS blocks, which one carried END_STREAM, whether
//! a DATA frame exists at all.
//!
//! That is what makes the Trailers-Only tests real. "Is `grpc-status` in the
//! headers or the trailers?" is not a question about field values — both
//! spellings use the same field name — it is a question about how many field
//! blocks the response has and where END_STREAM sits. Only a frame-level peer
//! can see it, and every mutation of the two response paths dies here.

const std = @import("std");
const http = @import("http");
const pb = @import("protobuf");

const server = @import("server.zig");
const frame = @import("frame.zig");
const status_mod = @import("status.zig");

const h2 = http.h2;
const hpack = http.hpack;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

// ── the schema under test ───────────────────────────────────────────────────

const EchoRequest = struct {
    text: []const u8 = "",
    count: i32 = 0,
    blob: []const u8 = "",
    pub const pb_fields = .{
        .text = pb.Field{ .number = 1, .kind = .string },
        .count = pb.Field{ .number = 2, .kind = .int32 },
        .blob = pb.Field{ .number = 3, .kind = .bytes },
    };
};

const EchoReply = struct {
    text: []const u8 = "",
    index: i32 = 0,
    blob: []const u8 = "",
    pub const pb_fields = .{
        .text = pb.Field{ .number = 1, .kind = .string },
        .index = pb.Field{ .number = 2, .kind = .int32 },
        .blob = pb.Field{ .number = 3, .kind = .bytes },
    };
};

const M = server.Methods(EchoRequest, EchoReply);

// ── the service under test ──────────────────────────────────────────────────

fn unaryImpl(c: *server.Call, req: EchoRequest) anyerror!EchoReply {
    return .{
        .text = try std.fmt.allocPrint(c.arena, "echo:{s}", .{req.text}),
        .index = req.count,
        .blob = req.blob,
    };
}

fn serverStreamImpl(s: *M.Stream, req: EchoRequest) anyerror!void {
    var i: i32 = 0;
    while (i < req.count) : (i += 1) {
        try s.send(.{
            .text = try std.fmt.allocPrint(s.call.arena, "{s}-{d}", .{ req.text, i }),
            .index = i,
        });
    }
}

fn clientStreamImpl(s: *M.Stream) anyerror!EchoReply {
    var parts: std.ArrayList([]const u8) = .empty;
    var n: i32 = 0;
    while (try s.receive()) |*r| {
        defer @constCast(r).deinit();
        try parts.append(s.call.arena, try s.call.arena.dupe(u8, r.value.text));
        n += 1;
    }
    return .{
        .text = try std.mem.join(s.call.arena, "|", parts.items),
        .index = n,
    };
}

fn bidiImpl(s: *M.Stream) anyerror!void {
    var i: i32 = 0;
    while (try s.receive()) |*r| {
        defer @constCast(r).deinit();
        try s.send(.{
            .text = try std.fmt.allocPrint(s.call.arena, "re:{s}", .{r.value.text}),
            .index = i,
        });
        i += 1;
    }
}

/// Fails before anything has gone out → a Trailers-Only response.
fn failImpl(c: *server.Call, req: EchoRequest) anyerror!EchoReply {
    return c.fail(@enumFromInt(@as(u32, @intCast(req.count))), req.text);
}

/// Sends `count` messages and THEN fails → the status lands in a real
/// trailer section, which is the other half of the contract.
fn streamFailImpl(s: *M.Stream, req: EchoRequest) anyerror!void {
    var i: i32 = 0;
    while (i < req.count) : (i += 1) {
        try s.send(.{ .text = "partial", .index = i });
    }
    return s.call.failFmt(.data_loss, "gave up after {d}", .{req.count});
}

/// A *successful* call that produces no message at all. The reference
/// implementation answers Trailers-Only here too — "nothing has been sent
/// yet" is the whole rule, and it does not care whether the status is OK.
fn emptyImpl(s: *M.Stream, req: EchoRequest) anyerror!void {
    _ = s;
    _ = req;
}

fn metaImpl(c: *server.Call, req: EchoRequest) anyerror!EchoReply {
    _ = req;
    const probe = c.metadataValue("x-probe") orelse "-";
    const bin_copy: []const u8 = if (try c.metadataValueDecoded("x-probe-bin")) |d| blk: {
        defer d.deinit(c.gpa);
        break :blk try c.arena.dupe(u8, d.bytes);
    } else "";

    try c.addInitialMetadata(.{ .name = "x-echo", .value = probe });
    try c.addInitialMetadata(.{ .name = "x-echo-bin", .value = bin_copy });
    try c.declareTrailingMetadata(&.{ "x-tail", "x-tail-bin" });
    try c.setTrailingMetadata(.{ .name = "x-tail", .value = probe });
    try c.setTrailingMetadata(.{ .name = "x-tail-bin", .value = bin_copy });
    return .{ .text = probe, .index = @intCast(bin_copy.len), .blob = bin_copy };
}

/// Reports the deadline the client asked for, in milliseconds remaining
/// (−1 when there is none). The clock is injected, so this is exact.
fn deadlineImpl(c: *server.Call, req: EchoRequest) anyerror!EchoReply {
    _ = req;
    const left = c.remaining();
    return .{
        .text = "deadline",
        .index = if (left) |ns| @intCast(ns / std.time.ns_per_ms) else -1,
    };
}

fn bigImpl(c: *server.Call, req: EchoRequest) anyerror!EchoReply {
    const n: usize = @intCast(@max(0, req.count));
    const blob = try c.arena.alloc(u8, n);
    @memset(blob, 0x5a);
    return .{ .text = "big", .index = req.count, .blob = blob };
}

/// The untyped escape hatch: bytes in, bytes out, no protobuf.
fn rawImpl(c: *server.Call) anyerror!void {
    while (try c.receive()) |msg| {
        const copy = try c.arena.dupe(u8, msg);
        try c.send(copy);
    }
}

const echo_service: server.Service = .{
    .name = "echo.Echo",
    .methods = &.{
        M.unary("Unary", unaryImpl),
        M.serverStreaming("ServerStream", serverStreamImpl),
        M.clientStreaming("ClientStream", clientStreamImpl),
        M.bidiStreaming("Bidi", bidiImpl),
        M.unary("Fail", failImpl),
        M.serverStreaming("StreamFail", streamFailImpl),
        M.serverStreaming("Empty", emptyImpl),
        M.unary("Meta", metaImpl),
        M.unary("Deadline", deadlineImpl),
        M.unary("Big", bigImpl),
        server.Method.raw("Raw", rawImpl),
    },
};

const other_service: server.Service = .{ .name = "other.Svc", .methods = &.{} };

// ── a frozen clock, so deadline tests are exact rather than flaky ───────────

const FakeClock = struct {
    ns: u64 = 1_000_000_000,
    /// Advance by this much on every reading. Zero = a frozen clock, so a
    /// "how much time is left?" assertion is exact rather than approximate;
    /// non-zero makes time pass *between* the engine's own two readings,
    /// which is the only way to expire a deadline the server itself computed
    /// (`now + grpc-timeout`) without sleeping.
    step: u64 = 0,
    fn nowFn(ctx: ?*anyopaque) u64 {
        const f: *FakeClock = @ptrCast(@alignCast(ctx.?));
        const v = f.ns;
        f.ns += f.step;
        return v;
    }
    fn clock(f: *FakeClock) server.Clock {
        return .{ .ctx = f, .nowFn = nowFn };
    }
};

// ── the frame-level peer ────────────────────────────────────────────────────

/// One response stream as the peer saw it — **frame counts and END_STREAM
/// placement**, not just field values. This is the part that can tell
/// Trailers-Only from a trailer section.
const Collected = struct {
    status: u16 = 0,
    headers: ?hpack.HeaderList = null,
    /// A SECOND HEADERS frame on the stream = the trailer section (§8.1).
    trailers: ?hpack.HeaderList = null,
    body: std.ArrayList(u8) = .empty,
    data_frames: u32 = 0,
    headers_end_stream: bool = false,
    data_end_stream: bool = false,
    trailers_end_stream: bool = false,
    end: bool = false,
    rst: ?h2.ErrorCode = null,

    fn header(c: *const Collected, name: []const u8) ?[]const u8 {
        const hl = c.headers orelse return null;
        for (hl.fields) |f| {
            if (std.mem.eql(u8, f.name, name)) return f.value;
        }
        return null;
    }

    fn trailer(c: *const Collected, name: []const u8) ?[]const u8 {
        const hl = c.trailers orelse return null;
        for (hl.fields) |f| {
            if (std.mem.eql(u8, f.name, name)) return f.value;
        }
        return null;
    }

    /// Whether the response is **Trailers-Only**: one field block carrying
    /// END_STREAM, no DATA frame, no second field block. Every clause is
    /// load-bearing — a response with the right fields in the wrong number
    /// of frames is a different response.
    fn isTrailersOnly(c: *const Collected) bool {
        return c.headers_end_stream and c.data_frames == 0 and c.trailers == null;
    }

    /// The length-prefixed messages in the body.
    fn messages(c: *const Collected, gpa: Allocator, out: *std.ArrayList([]const u8)) !void {
        var d: frame.Deframer = .{ .max_recv_message_size = 8 * 1024 * 1024 };
        defer d.deinit(gpa);
        try d.push(gpa, c.body.items);
        while (try d.next()) |m| try out.append(gpa, try gpa.dupe(u8, m));
        try d.endOfStream();
    }

    fn deinit(c: *Collected, gpa: Allocator) void {
        if (c.headers) |*hl| hl.deinit(gpa);
        if (c.trailers) |*hl| hl.deinit(gpa);
        c.body.deinit(gpa);
    }
};

const TestPeer = struct {
    gpa: Allocator,
    conn: h2.Connection,
    wire: std.ArrayList(u8) = .empty,
    events: std.ArrayList(h2.Event) = .empty,
    resps: std.AutoArrayHashMapUnmanaged(u31, Collected) = .empty,
    goaway: ?h2.ErrorCode = null,

    fn init(gpa: Allocator) TestPeer {
        return .{ .gpa = gpa, .conn = .init(gpa, .client, .{ .settings = .{} }) };
    }

    fn deinit(p: *TestPeer) void {
        for (p.resps.values()) |*c| c.deinit(p.gpa);
        p.resps.deinit(p.gpa);
        p.events.deinit(p.gpa);
        p.wire.deinit(p.gpa);
        p.conn.deinit();
    }

    fn feed(p: *TestPeer, bytes: []const u8) !void {
        try p.conn.recv(bytes, &p.wire, &p.events);
        for (p.events.items) |*ev| switch (ev.*) {
            .headers => |*hd| {
                const g = try p.resps.getOrPut(p.gpa, hd.stream_id);
                if (!g.found_existing) g.value_ptr.* = .{};
                if (g.value_ptr.headers == null) {
                    g.value_ptr.headers = hd.headers;
                    g.value_ptr.headers_end_stream = hd.end_stream;
                    if (g.value_ptr.header(":status")) |v|
                        g.value_ptr.status = std.fmt.parseInt(u16, v, 10) catch 0;
                } else if (g.value_ptr.trailers == null) {
                    g.value_ptr.trailers = hd.headers;
                    g.value_ptr.trailers_end_stream = hd.end_stream;
                } else hd.headers.deinit(p.gpa);
                if (hd.end_stream) g.value_ptr.end = true;
            },
            .data => |d| {
                const g = try p.resps.getOrPut(p.gpa, d.stream_id);
                if (!g.found_existing) g.value_ptr.* = .{};
                try g.value_ptr.body.appendSlice(p.gpa, d.data);
                g.value_ptr.data_frames += 1;
                if (d.end_stream) {
                    g.value_ptr.data_end_stream = true;
                    g.value_ptr.end = true;
                }
            },
            .stream_reset => |r| {
                const g = try p.resps.getOrPut(p.gpa, r.stream_id);
                if (!g.found_existing) g.value_ptr.* = .{};
                g.value_ptr.rst = r.code;
                g.value_ptr.end = true;
            },
            .goaway => |g| p.goaway = g.code,
            else => {},
        };
        p.events.clearRetainingCapacity();
    }

    fn resp(p: *TestPeer, sid: u31) *Collected {
        return p.resps.getPtr(sid).?;
    }
};

fn grpcFields(path: []const u8) [6]hpack.Field {
    return .{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = path },
        .{ .name = ":authority", .value = "t" },
        .{ .name = "te", .value = "trailers" },
        .{ .name = "content-type", .value = "application/grpc+proto" },
    };
}

var out_buf: [512 * 1024]u8 = undefined;

/// Run the gRPC router offline over the bytes the peer has staged.
fn runOffline(peer: *TestPeer, router: *server.Router) !void {
    var in: Reader = .fixed(peer.wire.items);
    var out: Writer = .fixed(&out_buf);
    http.h2_server.serve(testing.allocator, router.h2ServerOptions(.{
        .handler = server.handleHttp,
        .max_body_bytes = 8 * 1024 * 1024,
    }), &in, &out);
    peer.wire.clearRetainingCapacity();
    try peer.feed(out.buffered());
}

/// Stage a whole request (head + one framed message + END_STREAM).
fn startCall(peer: *TestPeer, path: []const u8, msgs: []const []const u8) !u31 {
    const fields = grpcFields(path);
    const sid = try peer.conn.startStream(&peer.wire, &fields, msgs.len == 0);
    for (msgs, 0..) |m, i| {
        const framed = try frame.encodeAlloc(testing.allocator, m);
        defer testing.allocator.free(framed);
        try peer.conn.sendData(&peer.wire, sid, framed, i + 1 == msgs.len);
    }
    return sid;
}

fn encodeReq(gpa: Allocator, req: EchoRequest) ![]u8 {
    return pb.encodeAlloc(gpa, req, .{});
}

fn defaultRouter() server.Router {
    return .{ .gpa = testing.allocator, .services = &.{ echo_service, other_service } };
}

// ── the happy path, and where the status lives on it ────────────────────────

test "server: a unary call answers HEADERS, DATA, then a TRAILER section" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa);
    defer peer.deinit();
    var router = defaultRouter();

    try peer.conn.sendPreface(&peer.wire);
    const req = try encodeReq(gpa, .{ .text = "hi", .count = 7, .blob = "\x00\xff" });
    defer gpa.free(req);
    const sid = try startCall(&peer, "/echo.Echo/Unary", &.{req});
    try runOffline(&peer, &router);

    const r = peer.resp(sid);
    try testing.expectEqual(@as(u16, 200), r.status);
    try testing.expectEqualStrings("application/grpc+proto", r.header("content-type").?);

    // ── the framing, which is the actual claim ──
    // Three things must all hold, and each one dies to a different mutation:
    try testing.expect(!r.headers_end_stream); // the head is not the end…
    try testing.expect(r.data_frames > 0); // …a body followed…
    try testing.expect(!r.data_end_stream); // …END_STREAM did NOT ride it…
    try testing.expect(r.trailers_end_stream); // …it rode the trailer section.
    try testing.expect(!r.isTrailersOnly());

    // `grpc-status` is a TRAILER here, and must not also be a header —
    // putting it in the head is the mutation this pair exists for.
    try testing.expectEqualStrings("0", r.trailer("grpc-status").?);
    try testing.expectEqual(@as(?[]const u8, null), r.header("grpc-status"));

    var msgs: std.ArrayList([]const u8) = .empty;
    defer {
        for (msgs.items) |m| gpa.free(m);
        msgs.deinit(gpa);
    }
    try r.messages(gpa, &msgs);
    try testing.expectEqual(@as(usize, 1), msgs.items.len);
    var decoded = try pb.decode(EchoReply, gpa, msgs.items[0], .{});
    defer decoded.deinit();
    try testing.expectEqualStrings("echo:hi", decoded.value.text);
    try testing.expectEqual(@as(i32, 7), decoded.value.index);
    try testing.expectEqualSlices(u8, "\x00\xff", decoded.value.blob);
}

test "server: the length prefix is big-endian on the wire, byte for byte" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa);
    defer peer.deinit();
    var router = defaultRouter();

    try peer.conn.sendPreface(&peer.wire);
    // The untyped method echoes bytes, so the response body is exactly a
    // 5-byte prefix plus the payload and can be asserted literally. A
    // little-endian length is consistent between our framer and our
    // deframer and therefore invisible to a round trip — but not to this.
    const sid = try startCall(&peer, "/echo.Echo/Raw", &.{"ABC"});
    try runOffline(&peer, &router);

    const r = peer.resp(sid);
    try testing.expectEqualSlices(
        u8,
        &.{ 0x00, 0x00, 0x00, 0x00, 0x03, 'A', 'B', 'C' },
        r.body.items,
    );
}

test "server: server-streaming sends N messages, then one trailer section" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa);
    defer peer.deinit();
    var router = defaultRouter();

    try peer.conn.sendPreface(&peer.wire);
    const req = try encodeReq(gpa, .{ .text = "tick", .count = 5 });
    defer gpa.free(req);
    const sid = try startCall(&peer, "/echo.Echo/ServerStream", &.{req});
    try runOffline(&peer, &router);

    const r = peer.resp(sid);
    try testing.expect(!r.isTrailersOnly());
    try testing.expectEqualStrings("0", r.trailer("grpc-status").?);
    // Each reply was pushed out on its own: a server-streaming response
    // that arrives as one frame at the end is not a stream.
    try testing.expect(r.data_frames >= 5);

    var msgs: std.ArrayList([]const u8) = .empty;
    defer {
        for (msgs.items) |m| gpa.free(m);
        msgs.deinit(gpa);
    }
    try r.messages(gpa, &msgs);
    try testing.expectEqual(@as(usize, 5), msgs.items.len);
    for (msgs.items, 0..) |m, i| {
        var d = try pb.decode(EchoReply, gpa, m, .{});
        defer d.deinit();
        var name: [16]u8 = undefined;
        try testing.expectEqualStrings(
            try std.fmt.bufPrint(&name, "tick-{d}", .{i}),
            d.value.text,
        );
    }
}

test "server: client-streaming folds every request message into one reply" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa);
    defer peer.deinit();
    var router = defaultRouter();

    try peer.conn.sendPreface(&peer.wire);
    const a = try encodeReq(gpa, .{ .text = "a" });
    defer gpa.free(a);
    const b = try encodeReq(gpa, .{ .text = "bb" });
    defer gpa.free(b);
    const c = try encodeReq(gpa, .{ .text = "ccc" });
    defer gpa.free(c);
    const sid = try startCall(&peer, "/echo.Echo/ClientStream", &.{ a, b, c });
    try runOffline(&peer, &router);

    const r = peer.resp(sid);
    try testing.expectEqualStrings("0", r.trailer("grpc-status").?);
    var msgs: std.ArrayList([]const u8) = .empty;
    defer {
        for (msgs.items) |m| gpa.free(m);
        msgs.deinit(gpa);
    }
    try r.messages(gpa, &msgs);
    try testing.expectEqual(@as(usize, 1), msgs.items.len);
    var d = try pb.decode(EchoReply, gpa, msgs.items[0], .{});
    defer d.deinit();
    try testing.expectEqualStrings("a|bb|ccc", d.value.text);
    try testing.expectEqual(@as(i32, 3), d.value.index);
}

test "server: bidirectional answers every request message" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa);
    defer peer.deinit();
    var router = defaultRouter();

    try peer.conn.sendPreface(&peer.wire);
    const one = try encodeReq(gpa, .{ .text = "one" });
    defer gpa.free(one);
    const two = try encodeReq(gpa, .{ .text = "two" });
    defer gpa.free(two);
    const sid = try startCall(&peer, "/echo.Echo/Bidi", &.{ one, two });
    try runOffline(&peer, &router);

    const r = peer.resp(sid);
    try testing.expectEqualStrings("0", r.trailer("grpc-status").?);
    var msgs: std.ArrayList([]const u8) = .empty;
    defer {
        for (msgs.items) |m| gpa.free(m);
        msgs.deinit(gpa);
    }
    try r.messages(gpa, &msgs);
    try testing.expectEqual(@as(usize, 2), msgs.items.len);
    var d0 = try pb.decode(EchoReply, gpa, msgs.items[0], .{});
    defer d0.deinit();
    try testing.expectEqualStrings("re:one", d0.value.text);
    var d1 = try pb.decode(EchoReply, gpa, msgs.items[1], .{});
    defer d1.deinit();
    try testing.expectEqualStrings("re:two", d1.value.text);
}

// ── Trailers-Only: the subtle one ───────────────────────────────────────────

test "server: an error before any message is a Trailers-Only response" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa);
    defer peer.deinit();
    var router = defaultRouter();

    try peer.conn.sendPreface(&peer.wire);
    const detail = "boom\nline two \xe2\x98\x83 100% done";
    const req = try encodeReq(gpa, .{
        .text = detail,
        .count = @intFromEnum(status_mod.Status.permission_denied),
    });
    defer gpa.free(req);
    const sid = try startCall(&peer, "/echo.Echo/Fail", &.{req});
    try runOffline(&peer, &router);

    const r = peer.resp(sid);
    try testing.expectEqual(@as(u16, 200), r.status);

    // ── the whole point ──
    // ONE field block, END_STREAM on it, and nothing else on the stream.
    // Emitting an empty DATA frame, or a second (trailer) field block with
    // the same fields in it, would leave every field value below unchanged
    // and would still be the wrong response.
    try testing.expect(r.isTrailersOnly());
    try testing.expect(r.headers_end_stream);
    try testing.expectEqual(@as(u32, 0), r.data_frames);
    try testing.expect(r.trailers == null);
    try testing.expect(!r.data_end_stream);
    try testing.expectEqual(@as(usize, 0), r.body.items.len);

    // The status is a HEADER here — the same field name, a different place.
    try testing.expectEqualStrings("7", r.header("grpc-status").?);
    try testing.expectEqualStrings("application/grpc+proto", r.header("content-type").?);
    // …and it must not ALSO be advertised as a trailer: `Trailer:` in the
    // head is what `declareTrailers` emits, and reaching that call is
    // exactly the mutation that turns this into the wrong shape.
    try testing.expectEqual(@as(?[]const u8, null), r.header("trailer"));

    // The message is percent-encoded per the ABNF: the raw bytes above are
    // not legal in a field value.
    const raw = r.header("grpc-message").?;
    try testing.expect(std.mem.indexOfScalar(u8, raw, '\n') == null);
    var dec: [128]u8 = undefined;
    try testing.expectEqualStrings(detail, status_mod.decodeMessage(raw, &dec));
}

test "server: a SUCCESSFUL call with no message is Trailers-Only too" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa);
    defer peer.deinit();
    var router = defaultRouter();

    try peer.conn.sendPreface(&peer.wire);
    // A server-streaming method that yields nothing. The rule is "nothing
    // has been sent yet", not "the call failed" — a server that reserved
    // Trailers-Only for errors would send an empty DATA frame plus a
    // trailer section here, which no field-value assertion would notice.
    const req = try encodeReq(gpa, .{ .count = 0 });
    defer gpa.free(req);
    const sid = try startCall(&peer, "/echo.Echo/Empty", &.{req});
    try runOffline(&peer, &router);

    const r = peer.resp(sid);
    try testing.expect(r.isTrailersOnly());
    try testing.expectEqualStrings("0", r.header("grpc-status").?);
    try testing.expectEqual(@as(?[]const u8, null), r.header("grpc-message"));
}

test "server: messages then an error puts the status in a real trailer section" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa);
    defer peer.deinit();
    var router = defaultRouter();

    try peer.conn.sendPreface(&peer.wire);
    const req = try encodeReq(gpa, .{ .count = 3 });
    defer gpa.free(req);
    const sid = try startCall(&peer, "/echo.Echo/StreamFail", &.{req});
    try runOffline(&peer, &router);

    const r = peer.resp(sid);
    // Not Trailers-Only: three messages already went out, so the status has
    // nowhere to live but the trailer section.
    try testing.expect(!r.isTrailersOnly());
    try testing.expect(r.trailers != null);
    try testing.expect(r.trailers_end_stream);
    try testing.expect(!r.data_end_stream);
    try testing.expectEqualStrings("15", r.trailer("grpc-status").?); // DATA_LOSS
    var dec: [64]u8 = undefined;
    try testing.expectEqualStrings(
        "gave up after 3",
        status_mod.decodeMessage(r.trailer("grpc-message").?, &dec),
    );

    var msgs: std.ArrayList([]const u8) = .empty;
    defer {
        for (msgs.items) |m| gpa.free(m);
        msgs.deinit(gpa);
    }
    try r.messages(gpa, &msgs);
    try testing.expectEqual(@as(usize, 3), msgs.items.len);
}

// ── request validation ──────────────────────────────────────────────────────

test "server: a non-POST request is 405, not a gRPC status" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa);
    defer peer.deinit();
    var router = defaultRouter();

    try peer.conn.sendPreface(&peer.wire);
    const fields = [_]hpack.Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/echo.Echo/Unary" },
        .{ .name = ":authority", .value = "t" },
        .{ .name = "content-type", .value = "application/grpc" },
    };
    const sid = try peer.conn.startStream(&peer.wire, &fields, true);
    try runOffline(&peer, &router);

    const r = peer.resp(sid);
    try testing.expectEqual(@as(u16, 405), r.status);
    try testing.expectEqualStrings("POST", r.header("allow").?);
    // A gRPC error is HTTP 200; answering one here would let a non-gRPC
    // HTTP/2 client read the failure as a success.
    try testing.expectEqual(@as(?[]const u8, null), r.header("grpc-status"));
}

test "server: a non-gRPC content-type is 415" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa);
    defer peer.deinit();
    var router = defaultRouter();

    try peer.conn.sendPreface(&peer.wire);
    const fields = [_]hpack.Field{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/echo.Echo/Unary" },
        .{ .name = ":authority", .value = "t" },
        .{ .name = "content-type", .value = "application/json" },
    };
    const sid = try peer.conn.startStream(&peer.wire, &fields, true);
    try runOffline(&peer, &router);

    const r = peer.resp(sid);
    try testing.expectEqual(@as(u16, 415), r.status);
    try testing.expectEqual(@as(?[]const u8, null), r.header("grpc-status"));
}

test "server: an unknown service or method is UNIMPLEMENTED, Trailers-Only" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa);
    defer peer.deinit();
    var router = defaultRouter();

    try peer.conn.sendPreface(&peer.wire);
    const no_svc = try startCall(&peer, "/nope.Nope/Unary", &.{""});
    const no_mth = try startCall(&peer, "/echo.Echo/Missing", &.{""});
    const malformed = try startCall(&peer, "/justonesegment", &.{""});
    const empty_method = try startCall(&peer, "/echo.Echo/", &.{""});
    try runOffline(&peer, &router);

    for ([_]u31{ no_svc, no_mth, malformed, empty_method }) |sid| {
        const r = peer.resp(sid);
        try testing.expectEqual(@as(u16, 200), r.status);
        try testing.expect(r.isTrailersOnly());
        try testing.expectEqualStrings("12", r.header("grpc-status").?);
    }
    // The messages distinguish the three reasons.
    var dec: [128]u8 = undefined;
    try testing.expectEqualStrings(
        "unknown service nope.Nope",
        status_mod.decodeMessage(peer.resp(no_svc).header("grpc-message").?, &dec),
    );
    try testing.expectEqualStrings(
        "unknown method Missing for service echo.Echo",
        status_mod.decodeMessage(peer.resp(no_mth).header("grpc-message").?, &dec),
    );
}

test "server: a request compressed with an unknown encoding is UNIMPLEMENTED + accept-encoding" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa);
    defer peer.deinit();
    var router = defaultRouter();

    try peer.conn.sendPreface(&peer.wire);
    const fields = [_]hpack.Field{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/echo.Echo/Unary" },
        .{ .name = ":authority", .value = "t" },
        .{ .name = "content-type", .value = "application/grpc" },
        .{ .name = "grpc-encoding", .value = "gzip" },
    };
    const sid = try peer.conn.startStream(&peer.wire, &fields, true);
    try runOffline(&peer, &router);

    const r = peer.resp(sid);
    try testing.expect(r.isTrailersOnly());
    try testing.expectEqualStrings("12", r.header("grpc-status").?);
    // The compression spec: the answer has to say what WOULD work.
    try testing.expectEqualStrings("identity", r.header("grpc-accept-encoding").?);
}

test "server: a message carrying the compressed flag is refused, not decoded" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa);
    defer peer.deinit();
    var router = defaultRouter();

    try peer.conn.sendPreface(&peer.wire);
    const fields = grpcFields("/echo.Echo/Unary");
    const sid = try peer.conn.startStream(&peer.wire, &fields, false);
    // Compressed flag set, but no `grpc-encoding` was negotiated: the bytes
    // must not reach the protobuf decoder as if they were plain.
    try peer.conn.sendData(&peer.wire, sid, &.{ 1, 0, 0, 0, 3, 'x', 'y', 'z' }, true);
    try runOffline(&peer, &router);

    const r = peer.resp(sid);
    try testing.expect(r.isTrailersOnly());
    try testing.expectEqualStrings("12", r.header("grpc-status").?); // UNIMPLEMENTED
}

// ── the receive limit, adversarially ────────────────────────────────────────

test "server: a request frame claiming 4 GiB fails RESOURCE_EXHAUSTED, buffering nothing" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa);
    defer peer.deinit();
    var router = defaultRouter();
    router.options.max_recv_message_size = 64 * 1024;

    try peer.conn.sendPreface(&peer.wire);
    const fields = grpcFields("/echo.Echo/Unary");
    const sid = try peer.conn.startStream(&peer.wire, &fields, false);
    // Five bytes. The claim is 4 GiB; the testing allocator would notice an
    // implementation that believed it.
    try peer.conn.sendData(&peer.wire, sid, &.{ 0, 0xff, 0xff, 0xff, 0xff }, true);
    try runOffline(&peer, &router);

    const r = peer.resp(sid);
    try testing.expect(r.isTrailersOnly());
    try testing.expectEqualStrings("8", r.header("grpc-status").?); // RESOURCE_EXHAUSTED
}

test "server: one byte over the receive limit is over the limit" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa);
    defer peer.deinit();
    var router = defaultRouter();
    router.options.max_recv_message_size = 1024;

    try peer.conn.sendPreface(&peer.wire);

    // Exactly at the limit: accepted. The `Raw` method echoes it back.
    const at = try gpa.alloc(u8, 1024);
    defer gpa.free(at);
    @memset(at, 'a');
    const ok_sid = try startCall(&peer, "/echo.Echo/Raw", &.{at});

    // One byte more: refused, and the refusal happens at the 5-byte header,
    // before the payload it promises has any chance to be buffered.
    const over = try gpa.alloc(u8, 1025);
    defer gpa.free(over);
    @memset(over, 'b');
    const bad_sid = try startCall(&peer, "/echo.Echo/Raw", &.{over});

    try runOffline(&peer, &router);

    try testing.expectEqualStrings("0", peer.resp(ok_sid).trailer("grpc-status").?);
    const bad = peer.resp(bad_sid);
    try testing.expect(bad.isTrailersOnly());
    try testing.expectEqualStrings("8", bad.header("grpc-status").?);
}

test "server: the limit is a MESSAGE bound, not a per-read one" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa);
    defer peer.deinit();
    var router = defaultRouter();
    router.options.max_recv_message_size = 4096;
    router.options.read_chunk = 64; // far smaller than one message

    try peer.conn.sendPreface(&peer.wire);
    const body = try gpa.alloc(u8, 4000);
    defer gpa.free(body);
    @memset(body, 'z');
    const sid = try startCall(&peer, "/echo.Echo/Raw", &.{body});
    try runOffline(&peer, &router);

    const r = peer.resp(sid);
    try testing.expectEqualStrings("0", r.trailer("grpc-status").?);
    var msgs: std.ArrayList([]const u8) = .empty;
    defer {
        for (msgs.items) |m| gpa.free(m);
        msgs.deinit(gpa);
    }
    try r.messages(gpa, &msgs);
    try testing.expectEqual(@as(usize, 1), msgs.items.len);
    try testing.expectEqualSlices(u8, body, msgs.items[0]);
}

test "server: a request that stops mid-message is truncated, not short" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa);
    defer peer.deinit();
    var router = defaultRouter();

    try peer.conn.sendPreface(&peer.wire);
    const fields = grpcFields("/echo.Echo/Raw");
    const sid = try peer.conn.startStream(&peer.wire, &fields, false);
    // A header promising six bytes, followed by five and END_STREAM.
    try peer.conn.sendData(&peer.wire, sid, &.{ 0, 0, 0, 0, 6, 'a', 'b', 'c', 'd', 'e' }, true);
    try runOffline(&peer, &router);

    const r = peer.resp(sid);
    // The five bytes must not surface as a message; the call fails.
    try testing.expectEqualStrings("13", r.header("grpc-status").?); // INTERNAL
}

// ── metadata ────────────────────────────────────────────────────────────────

test "server: initial and trailing metadata land in their own sections" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa);
    defer peer.deinit();
    var router = defaultRouter();

    try peer.conn.sendPreface(&peer.wire);
    const raw = [_]u8{ 0x00, 0x01, 0xfe, 0xff, 0x0a, 0x25 };
    var fields: [8]hpack.Field = undefined;
    @memcpy(fields[0..6], &grpcFields("/echo.Echo/Meta"));
    fields[6] = .{ .name = "x-probe", .value = "probe-value" };
    fields[7] = .{ .name = "x-probe-bin", .value = "AAH+/wol" }; // base64 of `raw`
    const sid = try peer.conn.startStream(&peer.wire, &fields, false);
    const req = try encodeReq(gpa, .{});
    defer gpa.free(req);
    const framed = try frame.encodeAlloc(gpa, req);
    defer gpa.free(framed);
    try peer.conn.sendData(&peer.wire, sid, framed, true);
    try runOffline(&peer, &router);

    const r = peer.resp(sid);
    try testing.expectEqualStrings("probe-value", r.header("x-echo").?);
    try testing.expectEqualStrings("AAH+/wol", r.header("x-echo-bin").?);
    // Trailing metadata is in the TRAILER section, not the head — that is
    // what "trailing" means, and the distinction is invisible to a lookup
    // that searches both.
    try testing.expectEqualStrings("probe-value", r.trailer("x-tail").?);
    try testing.expectEqualStrings("AAH+/wol", r.trailer("x-tail-bin").?);
    try testing.expectEqual(@as(?[]const u8, null), r.header("x-tail"));

    var msgs: std.ArrayList([]const u8) = .empty;
    defer {
        for (msgs.items) |m| gpa.free(m);
        msgs.deinit(gpa);
    }
    try r.messages(gpa, &msgs);
    var d = try pb.decode(EchoReply, gpa, msgs.items[0], .{});
    defer d.deinit();
    try testing.expectEqualSlices(u8, &raw, d.value.blob);
}

test "server: a handler cannot forge a reserved field" {
    // The gate `addInitialMetadata` / `setTrailingMetadata` apply. Its
    // wire-level consequence is that no handler can put a second
    // `grpc-status` next to the real one, however it spells the name.
    const md = @import("metadata.zig");
    try testing.expect(md.isReserved("grpc-status"));
    try testing.expect(md.isReserved("GRPC-Status"));
    try testing.expect(md.isReserved("content-type"));
    try testing.expect(!md.isReserved("x-tail"));
}

// ── deadlines ───────────────────────────────────────────────────────────────

test "server: grpc-timeout is parsed and surfaced to the handler" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa);
    defer peer.deinit();
    var fake: FakeClock = .{};
    var router = defaultRouter();
    router.options.clock = fake.clock();

    try peer.conn.sendPreface(&peer.wire);
    const req = try encodeReq(gpa, .{});
    defer gpa.free(req);
    const framed = try frame.encodeAlloc(gpa, req);
    defer gpa.free(framed);

    var with: [7]hpack.Field = undefined;
    @memcpy(with[0..6], &grpcFields("/echo.Echo/Deadline"));
    with[6] = .{ .name = "grpc-timeout", .value = "30S" };
    const sid_with = try peer.conn.startStream(&peer.wire, &with, false);
    try peer.conn.sendData(&peer.wire, sid_with, framed, true);

    const sid_without = try startCall(&peer, "/echo.Echo/Deadline", &.{req});
    try runOffline(&peer, &router);

    // The clock never moved, so the remaining time is exactly the timeout.
    try testing.expectEqual(@as(i32, 30_000), try replyIndex(gpa, peer.resp(sid_with)));
    try testing.expectEqual(@as(i32, -1), try replyIndex(gpa, peer.resp(sid_without)));
}

test "server: a deadline already in the past fails DEADLINE_EXCEEDED before the handler runs" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa);
    defer peer.deinit();
    // A second passes between every reading of the clock. The server
    // computes the deadline as `now + grpc-timeout` when it decodes the
    // head, so nothing a test does *before* the server runs can expire it —
    // time has to move between the engine's own two readings. Deterministic,
    // and no test sleeps for a second.
    var fake: FakeClock = .{ .step = std.time.ns_per_s };
    var router = defaultRouter();
    router.options.clock = fake.clock();

    try peer.conn.sendPreface(&peer.wire);
    const req = try encodeReq(gpa, .{});
    defer gpa.free(req);
    const framed = try frame.encodeAlloc(gpa, req);
    defer gpa.free(framed);
    var f: [7]hpack.Field = undefined;
    @memcpy(f[0..6], &grpcFields("/echo.Echo/Deadline"));
    f[6] = .{ .name = "grpc-timeout", .value = "1n" };
    const sid = try peer.conn.startStream(&peer.wire, &f, false);
    try peer.conn.sendData(&peer.wire, sid, framed, true);
    try runOffline(&peer, &router);

    const r = peer.resp(sid);
    try testing.expect(r.isTrailersOnly());
    try testing.expectEqualStrings("4", r.header("grpc-status").?); // DEADLINE_EXCEEDED
}

test "server: a malformed grpc-timeout is refused, not ignored" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa);
    defer peer.deinit();
    var router = defaultRouter();

    try peer.conn.sendPreface(&peer.wire);
    var f: [7]hpack.Field = undefined;
    @memcpy(f[0..6], &grpcFields("/echo.Echo/Deadline"));
    // Nine digits: the spec allows at most eight.
    f[6] = .{ .name = "grpc-timeout", .value = "123456789S" };
    const sid = try peer.conn.startStream(&peer.wire, &f, true);
    try runOffline(&peer, &router);

    const r = peer.resp(sid);
    try testing.expect(r.isTrailersOnly());
    // Silently dropping it would run a call the client believes is bounded.
    try testing.expectEqualStrings("13", r.header("grpc-status").?); // INTERNAL
}

fn replyIndex(gpa: Allocator, r: *Collected) !i32 {
    var msgs: std.ArrayList([]const u8) = .empty;
    defer {
        for (msgs.items) |m| gpa.free(m);
        msgs.deinit(gpa);
    }
    try r.messages(gpa, &msgs);
    try testing.expectEqual(@as(usize, 1), msgs.items.len);
    var d = try pb.decode(EchoReply, gpa, msgs.items[0], .{});
    defer d.deinit();
    return d.value.index;
}

// ── a big reply, split across DATA frames by flow control ───────────────────

test "server: a large reply is split across DATA frames and reassembles exactly" {
    const gpa = testing.allocator;
    var peer: TestPeer = .init(gpa);
    defer peer.deinit();
    var router = defaultRouter();

    try peer.conn.sendPreface(&peer.wire);
    // 48 KiB is several times the peer's 16 KiB default max frame size, so
    // the one message provably arrives in pieces.
    const want: i32 = 48 * 1024;
    const req = try encodeReq(gpa, .{ .count = want });
    defer gpa.free(req);
    const sid = try startCall(&peer, "/echo.Echo/Big", &.{req});
    try runOffline(&peer, &router);

    const r = peer.resp(sid);
    try testing.expectEqualStrings("0", r.trailer("grpc-status").?);
    try testing.expect(r.data_frames > 1);
    var msgs: std.ArrayList([]const u8) = .empty;
    defer {
        for (msgs.items) |m| gpa.free(m);
        msgs.deinit(gpa);
    }
    try r.messages(gpa, &msgs);
    try testing.expectEqual(@as(usize, 1), msgs.items.len);
    var d = try pb.decode(EchoReply, gpa, msgs.items[0], .{});
    defer d.deinit();
    try testing.expectEqual(@as(usize, @intCast(want)), d.value.blob.len);
    for (d.value.blob) |b| try testing.expectEqual(@as(u8, 0x5a), b);
}

// ── unit tests for the small decisions ──────────────────────────────────────

test "server: path splitting is exactly /{Service}/{Method}" {
    const s = server.splitPath("/echo.Echo/Unary").?;
    try testing.expectEqualStrings("echo.Echo", s.service);
    try testing.expectEqualStrings("Unary", s.method);
    try testing.expectEqual(@as(?server.PathSplit, null), server.splitPath(""));
    try testing.expectEqual(@as(?server.PathSplit, null), server.splitPath("/"));
    try testing.expectEqual(@as(?server.PathSplit, null), server.splitPath("/onlyone"));
    try testing.expectEqual(@as(?server.PathSplit, null), server.splitPath("/svc/"));
    try testing.expectEqual(@as(?server.PathSplit, null), server.splitPath("//m"));
    try testing.expectEqual(@as(?server.PathSplit, null), server.splitPath("echo.Echo/Unary"));
    try testing.expectEqual(@as(?server.PathSplit, null), server.splitPath("/a/b/c"));
}

test "server: the response content-type echoes the request's grpc flavour" {
    try testing.expectEqualStrings("application/grpc", server.grpcContentType("application/grpc").?);
    try testing.expectEqualStrings(
        "application/grpc+proto",
        server.grpcContentType("application/grpc+proto").?,
    );
    try testing.expectEqualStrings(
        "application/grpc+json",
        server.grpcContentType("application/grpc+json").?,
    );
    // Parameters are dropped from the echo, not carried back.
    try testing.expectEqualStrings(
        "application/grpc",
        server.grpcContentType("application/grpc; charset=utf-8").?,
    );
    try testing.expectEqual(@as(?[]const u8, null), server.grpcContentType("application/grpcweb"));
    try testing.expectEqual(@as(?[]const u8, null), server.grpcContentType("text/plain"));
    try testing.expectEqual(@as(?[]const u8, null), server.grpcContentType(""));
}

test "server: grpc-timeout converts to nanoseconds without losing the unit" {
    try testing.expectEqual(@as(u64, 30 * std.time.ns_per_s), server.timeoutNanos(.{ .value = 30, .unit = .seconds }));
    try testing.expectEqual(@as(u64, 30 * std.time.ns_per_s), server.timeoutNanos(.{ .value = 30_000, .unit = .milliseconds }));
    try testing.expectEqual(@as(u64, std.time.ns_per_hour), server.timeoutNanos(.{ .value = 1, .unit = .hours }));
    try testing.expectEqual(@as(u64, 1), server.timeoutNanos(.{ .value = 1, .unit = .nanoseconds }));
}

test "server: every StatusError keeps its own code on the way out" {
    inline for (@typeInfo(status_mod.StatusError).error_set.?) |e| {
        const se: status_mod.StatusError = @field(status_mod.StatusError, e.name);
        try testing.expectEqual(status_mod.fromError(se), server.statusForError(se));
    }
    // An error that is not a status is UNKNOWN — the code that exists for
    // exactly this — never a silent OK.
    try testing.expectEqual(status_mod.Status.unknown, server.statusForError(error.SomethingElse));
    try testing.expectEqual(status_mod.Status.resource_exhausted, server.statusForError(error.OutOfMemory));
    try testing.expectEqual(status_mod.Status.resource_exhausted, server.statusForError(error.MessageTooLarge));
}
