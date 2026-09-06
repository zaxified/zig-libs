// SPDX-License-Identifier: MIT

//! **The external anchor, replayed offline.** Pure Zig: no child process, no
//! socket, no foreign source, no `python3` and no `go` anywhere.
//!
//! ## Why this file exists
//!
//! Every other self-contained gRPC test in this module is a conversation with
//! ourselves. Our framer writes the length prefix and our deframer reads it;
//! flip both to little-endian and every round trip in `call_test.zig` still
//! passes while nothing on the network can read a byte we send. Only an
//! outside implementation sees that class of defect.
//!
//! Until 2026-09-06 the outside implementation was reached by spawning
//! Python `grpcio` from inside `test-grpc`, with the reference scripts
//! `@embedFile`d into module source. That put foreign code in a library that
//! promises to be standalone Zig, and — worse — it "skipped loudly" when the
//! interpreter was missing. A skip is a pass, so on any host without grpcio
//! the module's strongest evidence quietly evaporated.
//!
//! Now the taking lives in `tools/interop.zig` (`zig build interop-grpc`) and
//! what it records lives here. `testdata/grpcio_capture.zig` is a
//! byte-for-byte recording of one real conversation with grpcio, in **both
//! directions**; this file replays it. The header of that generated file says
//! which grpcio, on which day, by which command, and exactly what was pinned
//! to make replay deterministic.
//!
//! ## What each half proves
//!
//! **Forward** — the reference *server*'s bytes, parsed by our client. This
//! is complete offline: grpcio produced those bytes and reading them
//! correctly is the whole test. HPACK, DATA framing across many frames, the
//! Trailers-Only field block, the percent-encoded `grpc-message`, `-bin`
//! base64 and grpcio's own protobuf wire output are all under our decoder
//! here, exactly as they were live.
//!
//! **Reverse** — the reference *client*'s bytes, fed to our server. Two
//! things are asserted, and they are different things:
//!
//!   1. our server understands what grpcio SENT — its HPACK, its `-bin`
//!      base64, its `grpc-timeout` rendering, its protobuf encoding;
//!   2. what our server ANSWERS matches, field by field, what grpcio itself
//!      read off the wire at capture time (`reverse_report`). Those
//!      expectations are the reference's own readings rather than numbers
//!      someone typed here — a server change that grpcio would have read
//!      differently breaks them.
//!
//! What no recording can carry is grpcio's *parser* running on freshly
//! produced bytes, so a genuinely NEW divergence in the reverse direction is
//! still only findable by `zig build interop-grpc`. That is a pre-release
//! check, and it is the honest boundary of this file.

const std = @import("std");
const http = @import("http");
const pb = @import("protobuf");

const grpc = @import("root.zig");
const frame = @import("frame.zig");
const server = @import("server.zig");
const status_mod = @import("status.zig");
const capture = @import("testdata/grpcio_capture.zig");

const h2 = http.h2;
const h2c = http.h2_client;
const hpack = http.hpack;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

// ── the schema, mirroring tools/reference_server.py ────────────────────────

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

const Echo = grpc.Stream(EchoRequest, EchoReply);

// ── a Reader that hands the recording over the way a socket would ──────────

/// How many bytes one read of the recording yields.
///
/// ⚠ This is not a performance knob, it is what makes replay *legal*.
/// `Reader.fixed` hands its whole slice over in one go, and the h2 engines
/// take everything `buffered()` offers in a single `recv`. A 256 KiB reply
/// therefore arrived as one 256 KiB burst, and the connection-level receive
/// window (65535 octets, fixed by RFC 9113 §6.9.2 and raised only by
/// WINDOW_UPDATEs we emit as the application consumes) was blown before the
/// application had seen a byte — `error.FlowControlError`, connection-scoped.
///
/// Live, the peer paced itself against exactly those WINDOW_UPDATEs. A
/// recording cannot pace itself, so the reader does it: bounded reads put
/// the consume→WINDOW_UPDATE→read-more loop back, which is the loop the
/// capture was made under. Nothing is compared less; the same bytes arrive
/// in the same order, in the sized pieces a socket would have delivered.
const chunk_len = 8 * 1024;

const Chunked = struct {
    src: []const u8,
    pos: usize = 0,
    buf: [chunk_len]u8 = undefined,
    reader: Reader,

    fn init(src: []const u8) Chunked {
        return .{
            .src = src,
            .reader = .{
                .vtable = &.{ .stream = Chunked.streamFn },
                .buffer = &.{},
                .end = 0,
                .seek = 0,
            },
        };
    }

    /// Must run after the struct reaches its final address: `reader.buffer`
    /// points into `buf`.
    fn arm(c: *Chunked) void {
        c.reader.buffer = &c.buf;
    }

    fn streamFn(r: *Reader, w: *Writer, limit: std.Io.Limit) Reader.StreamError!usize {
        const c: *Chunked = @alignCast(@fieldParentPtr("reader", r));
        if (c.pos == c.src.len) return error.EndOfStream;
        const want = @min(@min(chunk_len, c.src.len - c.pos), @intFromEnum(limit));
        const dest = limit.slice(try w.writableSliceGreedy(1));
        const n = @min(want, dest.len);
        @memcpy(dest[0..n], c.src[c.pos..][0..n]);
        c.pos += n;
        w.advance(n);
        return n;
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// FORWARD: the reference SERVER's recorded bytes, parsed by our client.
// ═══════════════════════════════════════════════════════════════════════════

/// Heap-allocated: the h2 session holds pointers to `in`/`out`, so nothing
/// here may move after `init`.
///
/// The same shape `call_test.zig`'s `Fx` uses — a client session over fixed
/// buffers — with one difference that is the entire point: the bytes in `in`
/// were produced by grpcio's C-core, not fabricated here.
const Fx = struct {
    gpa: Allocator,
    in: Chunked,
    out_buf: [128 * 1024]u8,
    out: Writer,
    session: h2c.Session,
    ch: grpc.Channel,

    fn start(gpa: Allocator, name: []const u8, options: grpc.Options) !*Fx {
        // A missing case is a FAILING test, never a skip: the whole reason
        // this file exists is that a skip is a pass.
        const c = capture.find(name) orelse {
            std.debug.print("\nthe capture has no case `{s}` — regenerate it with " ++
                "`zig build interop-grpc -- --capture`\n", .{name});
            return error.MissingCaptureCase;
        };
        const fx = try gpa.create(Fx);
        errdefer gpa.destroy(fx);
        fx.gpa = gpa;
        fx.in = Chunked.init(c.bytes);
        fx.in.arm();
        fx.out = .fixed(&fx.out_buf);
        fx.session = try h2c.Session.init(gpa, &fx.in.reader, &fx.out, .{});
        fx.ch = grpc.Channel.init(gpa, &fx.session, options);
        return fx;
    }

    fn deinit(fx: *Fx) void {
        const gpa = fx.gpa;
        fx.session.deinit();
        gpa.destroy(fx);
    }
};

test "replay grpcio: unary — one request, one reply, real grpc-status OK in the trailers" {
    const gpa = testing.allocator;
    const fx = try Fx.start(gpa, "unary", .{});
    defer fx.deinit();

    var reply = try grpc.unary(EchoRequest, EchoReply, &fx.ch, "/echo.Echo/Unary", .{
        .text = "hello reference",
        .count = 7,
        .blob = &.{ 0x00, 0xff, 0x10 },
    }, .{});
    defer reply.deinit();

    try testing.expectEqualStrings("echo:hello reference", reply.value.text);
    try testing.expectEqual(@as(i32, 7), reply.value.index);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0xff, 0x10 }, reply.value.blob);
}

test "replay grpcio: server-streaming — many replies on one stream, then trailers" {
    const gpa = testing.allocator;
    const fx = try Fx.start(gpa, "server_stream", .{});
    defer fx.deinit();

    var s = try Echo.start(&fx.ch, "/echo.Echo/ServerStream", .{});
    defer s.deinit();
    try s.sendEnd(.{ .text = "tick", .count = 5 });

    var seen: i32 = 0;
    while (try s.receive()) |*r| {
        defer @constCast(r).deinit();
        var name_buf: [32]u8 = undefined;
        const want = try std.fmt.bufPrint(&name_buf, "tick-{d}", .{seen});
        try testing.expectEqualStrings(want, r.value.text);
        try testing.expectEqual(seen, r.value.index);
        seen += 1;
    }
    try testing.expectEqual(@as(i32, 5), seen);
    try s.finish();
}

test "replay grpcio: client-streaming — many requests, one reply after closeSend" {
    const gpa = testing.allocator;
    const fx = try Fx.start(gpa, "client_stream", .{});
    defer fx.deinit();

    var s = try Echo.start(&fx.ch, "/echo.Echo/ClientStream", .{});
    defer s.deinit();
    try s.send(.{ .text = "a" });
    try s.send(.{ .text = "bb" });
    try s.send(.{ .text = "ccc" });
    try s.closeSend();

    var reply = (try s.receive()).?;
    defer reply.deinit();
    try testing.expectEqualStrings("a|bb|ccc", reply.value.text);
    try testing.expectEqual(@as(i32, 3), reply.value.index);
    try testing.expectEqual(@as(?pb.Decoded(EchoReply), null), try s.receive());
    try s.finish();
}

test "replay grpcio: bidirectional — send and receive interleaved on one stream" {
    const gpa = testing.allocator;
    const fx = try Fx.start(gpa, "bidi", .{});
    defer fx.deinit();

    var s = try Echo.start(&fx.ch, "/echo.Echo/Bidi", .{});
    defer s.deinit();

    const words = [_][]const u8{ "one", "two", "three" };
    for (words, 0..) |w, i| {
        try s.send(.{ .text = w });
        var r = (try s.receive()).?;
        defer r.deinit();
        var buf: [32]u8 = undefined;
        try testing.expectEqualStrings(try std.fmt.bufPrint(&buf, "re:{s}", .{w}), r.value.text);
        try testing.expectEqual(@as(i32, @intCast(i)), r.value.index);
    }
    try s.closeSend();
    try testing.expectEqual(@as(?pb.Decoded(EchoReply), null), try s.receive());
    try s.finish();
}

test "replay grpcio: a failing call arrives as a real Trailers-Only response" {
    const gpa = testing.allocator;
    const fx = try Fx.start(gpa, "fail", .{});
    defer fx.deinit();

    // A message full of bytes the grpc-message ABNF forbids, so the
    // percent-decoding is exercised against the reference's ENCODER — the
    // convention (`\n` → `%0A`, each byte of the multi-byte UTF-8 snowman
    // escaped separately, a literal `%` → `%25`) comes from grpcio's C-core,
    // which `status.zig` has never seen. A test that only checked our own
    // `encodeMessage`/`decodeMessage` agree with each other cannot catch a
    // decoder that silently agrees with the *wrong* convention.
    const detail = "boom\nline two \xe2\x98\x83 100% done";

    var failure: grpc.Failure = .{};
    defer failure.deinit(gpa);
    const err = grpc.unary(EchoRequest, EchoReply, &fx.ch, "/echo.Echo/Fail", .{
        .text = detail,
        .count = @intFromEnum(grpc.Status.permission_denied),
    }, .{ .failure = &failure });

    try testing.expectError(error.PermissionDenied, err);
    try testing.expectEqual(grpc.Status.permission_denied, failure.status);
    try testing.expectEqualStrings(detail, failure.message);
}

test "replay grpcio: a Trailers-Only response has no trailer section at all" {
    const gpa = testing.allocator;
    const fx = try Fx.start(gpa, "trailers_only", .{});
    defer fx.deinit();

    var call = try fx.ch.start("/echo.Echo/Fail", .{});
    defer call.deinit();
    const req = try pb.encodeAlloc(gpa, EchoRequest{
        .text = "nope",
        .count = @intFromEnum(grpc.Status.not_found),
    }, .{});
    defer gpa.free(req);
    try call.sendMessage(req, true);

    // The whole response is one HEADERS frame: no body, and `grpc-status` is
    // in the INITIAL metadata. A client that only ever looks in the trailer
    // section finds nothing here and waits forever.
    try testing.expectEqual(@as(?[]const u8, null), try call.receive());
    try testing.expect(call.trailers_only);
    try testing.expect(call.trailingMetadata() == null);
    try testing.expect(call.initialMetadata().?.fields.len != 0);
    try testing.expectError(error.NotFound, call.finish());
    try testing.expectEqual(grpc.Status.not_found, call.status.?);
    try testing.expectEqualStrings("nope", call.statusMessage());
}

test "replay grpcio: messages then a non-OK status in a real trailer section" {
    const gpa = testing.allocator;
    const fx = try Fx.start(gpa, "stream_fail", .{});
    defer fx.deinit();

    var s = try Echo.start(&fx.ch, "/echo.Echo/StreamFail", .{});
    defer s.deinit();
    try s.sendEnd(.{ .text = "x", .count = 3 });

    var seen: usize = 0;
    while (try s.receive()) |*r| {
        @constCast(r).deinit();
        seen += 1;
    }
    try testing.expectEqual(@as(usize, 3), seen);
    // Not Trailers-Only this time: the status came in the TRAILERS frame
    // after three DATA frames, which is the other half of the contract.
    try testing.expect(!s.call.trailers_only);
    try testing.expect(s.call.trailingMetadata() != null);
    try testing.expectError(error.DataLoss, s.finish());
    try testing.expectEqualStrings("gave up after 3", s.call.statusMessage());
}

test "replay grpcio: a large reply under the limit is reassembled across DATA frames" {
    const gpa = testing.allocator;
    const fx = try Fx.start(gpa, "big", .{ .max_recv_message_size = 1024 * 1024 });
    defer fx.deinit();

    // 256 KiB of payload is many times the peer's 16 KiB default HTTP/2 frame
    // size and far past the 64 KiB initial flow-control window, so this one
    // message provably arrived split across a long run of DATA frames — and
    // the deframer has to put it back together to the byte.
    const want: i32 = 256 * 1024;
    var reply = try grpc.unary(EchoRequest, EchoReply, &fx.ch, "/echo.Echo/Big", .{
        .count = want,
    }, .{});
    defer reply.deinit();

    try testing.expectEqualStrings("big", reply.value.text);
    try testing.expectEqual(want, reply.value.index);
    try testing.expectEqual(@as(usize, @intCast(want)), reply.value.blob.len);
    for (reply.value.blob) |b| try testing.expectEqual(@as(u8, 0x5a), b);
}

test "replay grpcio: a reply larger than max_recv_message_size fails RESOURCE_EXHAUSTED" {
    const gpa = testing.allocator;
    // The SAME recording as the test above, read by a client with a 64 KiB
    // limit. That is not a shortcut: the reference's output does not depend
    // on our receive limit — the refusal is purely local — so recording this
    // arm separately would only have recorded a stream truncated at the point
    // our client stopped reading, which proves less, not more.
    const fx = try Fx.start(gpa, "big", .{ .max_recv_message_size = 64 * 1024 });
    defer fx.deinit();

    var failure: grpc.Failure = .{};
    defer failure.deinit(gpa);
    const err = grpc.unary(EchoRequest, EchoReply, &fx.ch, "/echo.Echo/Big", .{
        .count = 256 * 1024,
    }, .{ .failure = &failure });

    try testing.expectError(error.ResourceExhausted, err);
    try testing.expectEqual(grpc.Status.resource_exhausted, failure.status);
}

test "replay grpcio: ASCII and -bin metadata survive both directions" {
    const gpa = testing.allocator;
    const fx = try Fx.start(gpa, "metadata", .{});
    defer fx.deinit();

    // Bytes that no ASCII header could carry — that is the whole reason
    // `-bin` exists, so the probe has to actually contain them. What is being
    // read back here is grpcio's own base64.
    const raw = [_]u8{ 0x00, 0x01, 0xfe, 0xff, 0x0a, 0x25 };

    var call = try fx.ch.start("/echo.Echo/Meta", .{ .metadata = &.{
        .{ .name = "x-probe", .value = "probe-value" },
        .{ .name = "x-probe-bin", .value = &raw },
    } });
    defer call.deinit();
    const req = try pb.encodeAlloc(gpa, EchoRequest{}, .{});
    defer gpa.free(req);
    try call.sendMessage(req, true);

    const msg = (try call.receive()).?;
    var decoded = try pb.decode(EchoReply, gpa, msg, .{});
    defer decoded.deinit();
    // The reference read our ASCII header and our base64 -bin header, and
    // handed both back inside the message body.
    try testing.expectEqualStrings("probe-value", decoded.value.text);
    try testing.expectEqualSlices(u8, &raw, decoded.value.blob);

    // …and in its own metadata, in both sections.
    try testing.expectEqualStrings("probe-value", call.metadataValue("x-echo").?);
    const echoed = (try call.metadataValueDecoded("x-echo-bin")).?;
    defer echoed.deinit(gpa);
    try testing.expectEqualSlices(u8, &raw, echoed.bytes);

    try testing.expectEqual(@as(?[]const u8, null), try call.receive());
    try testing.expectEqualStrings("probe-value", call.metadataValue("x-tail").?);
    const tail = (try call.metadataValueDecoded("x-tail-bin")).?;
    defer tail.deinit(gpa);
    try testing.expectEqualSlices(u8, &raw, tail.bytes);
    try call.finish();
}

test "replay grpcio: grpc-timeout was understood by the reference server" {
    const gpa = testing.allocator;

    // Three calls, three recordings, one connection each — see
    // `tools/interop.zig`'s note: a recording of sequential calls on ONE
    // connection cannot be replayed against a client that opens its streams
    // one at a time, because the recording already holds the answers to
    // streams the replaying client has not opened yet.
    {
        // No deadline: the reference reported -1.
        const fx = try Fx.start(gpa, "deadline_none", .{});
        defer fx.deinit();
        var none = try grpc.unary(EchoRequest, EchoReply, &fx.ch, "/echo.Echo/Deadline", .{}, .{});
        defer none.deinit();
        try testing.expectEqual(@as(i32, -1), none.value.index);
    }
    {
        // 30 s: the reference saw a deadline in the 29–30 s band, which only
        // happens if it parsed our `grpc-timeout` value AND our unit.
        const fx = try Fx.start(gpa, "deadline_seconds", .{});
        defer fx.deinit();
        var some = try grpc.unary(EchoRequest, EchoReply, &fx.ch, "/echo.Echo/Deadline", .{}, .{
            .timeout = .{ .value = 30, .unit = .seconds },
        });
        defer some.deinit();
        try testing.expect(some.value.index >= 29_000 and some.value.index <= 30_000);
    }
    {
        // The same duration expressed in milliseconds must land in the same
        // band — a unit we render but the peer reads differently shows here.
        const fx = try Fx.start(gpa, "deadline_millis", .{});
        defer fx.deinit();
        var ms = try grpc.unary(EchoRequest, EchoReply, &fx.ch, "/echo.Echo/Deadline", .{}, .{
            .timeout = grpc.Timeout.fromMillis(30_000),
        });
        defer ms.deinit();
        try testing.expect(ms.value.index >= 29_000 and ms.value.index <= 30_000);
    }
}

test "replay grpcio: several calls multiplexed on one HTTP/2 connection" {
    const gpa = testing.allocator;
    const fx = try Fx.start(gpa, "multiplex", .{});
    defer fx.deinit();

    // Three streams open at once on one connection, collected out of order —
    // the demultiplexing underneath is the h2 client's, exercised here
    // against a third-party server's frame interleaving.
    var a = try Echo.start(&fx.ch, "/echo.Echo/Unary", .{});
    defer a.deinit();
    var b = try Echo.start(&fx.ch, "/echo.Echo/ServerStream", .{});
    defer b.deinit();
    var c = try Echo.start(&fx.ch, "/echo.Echo/Unary", .{});
    defer c.deinit();

    try a.sendEnd(.{ .text = "A" });
    try b.sendEnd(.{ .text = "B", .count = 2 });
    try c.sendEnd(.{ .text = "C" });

    var rc = (try c.receive()).?;
    defer rc.deinit();
    try testing.expectEqualStrings("echo:C", rc.value.text);

    var seen: usize = 0;
    while (try b.receive()) |*r| {
        @constCast(r).deinit();
        seen += 1;
    }
    try testing.expectEqual(@as(usize, 2), seen);

    var ra = (try a.receive()).?;
    defer ra.deinit();
    try testing.expectEqualStrings("echo:A", ra.value.text);

    try a.finish();
    try b.finish();
    try c.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// The frozen constants that predate the capture (F5, 2026-08-08). Kept
// because they assert the SAME grpcio bytes at a different seam — a hand-
// readable one — and because they are cheap.
// ═══════════════════════════════════════════════════════════════════════════

/// `grpc-status`/`grpc-message`, byte-for-byte as the reference **C-core**
/// server's Trailers-Only response carried them (`/echo.Echo/Fail`,
/// `req.count = permission_denied`).
const live_grpcio_status_value = "7"; // permission_denied
const live_grpcio_message_wire = "boom%0Aline two %E2%98%83 100%25 done";
const live_grpcio_message_decoded = "boom\nline two \xe2\x98\x83 100% done";

test "external anchor: grpcio's real Trailers-Only grpc-status/grpc-message wire bytes decode correctly (frozen 2026-08-08)" {
    try testing.expectEqual(grpc.Status.permission_denied, status_mod.parse(live_grpcio_status_value).?);

    var buf: [live_grpcio_message_wire.len]u8 = undefined;
    const decoded = status_mod.decodeMessage(live_grpcio_message_wire, &buf);
    try testing.expectEqualStrings(live_grpcio_message_decoded, decoded);
}

/// The exact bytes the C-core reference server's protobuf library put on the
/// wire for one `EchoReply` (`/echo.Echo/Unary`, `text = "hello reference"`,
/// `count = 7`, `blob = {0x00, 0xff, 0x10}`) — the 5-byte gRPC length prefix
/// already stripped by `Call.receive`'s deframer. Field 1 (`0x0a`,
/// length-delimited, 20 bytes) is `text`, field 2 (`0x10`, varint) is
/// `count`/`index`, field 3 (`0x1a`, length-delimited, 3 bytes) is `blob` —
/// real protobuf-library wire output, not this repo's own `pb.encode`.
const live_grpcio_echo_reply_bytes = [_]u8{
    0x0a, 0x14, 'e',  'c',  'h',  'o',  ':',  'h', 'e', 'l', 'l', 'o', ' ', 'r', 'e', 'f', 'e', 'r', 'e', 'n', 'c', 'e',
    0x10, 0x07, 0x1a, 0x03, 0x00, 0xff, 0x10,
};

test "external anchor: grpcio's real EchoReply wire bytes decode through frame + pb (frozen 2026-08-08)" {
    const gpa = testing.allocator;

    // Re-frame with this module's own LPM header — its byte layout is already
    // anchored independently in `frame.zig`'s spec-derived tests — purely so
    // the exact `Deframer` code path `Call.receive` uses is the one under
    // test here too, not a shortcut around it.
    const framed = try frame.encodeAlloc(gpa, &live_grpcio_echo_reply_bytes);
    defer gpa.free(framed);

    var d: frame.Deframer = .{};
    defer d.deinit(gpa);
    try d.push(gpa, framed);
    const payload = (try d.next()).?;
    try testing.expectEqualSlices(u8, &live_grpcio_echo_reply_bytes, payload);
    try testing.expectEqual(@as(?[]const u8, null), try d.next());

    var decoded = try pb.decode(EchoReply, gpa, payload, .{});
    defer decoded.deinit();
    try testing.expectEqualStrings("echo:hello reference", decoded.value.text);
    try testing.expectEqual(@as(i32, 7), decoded.value.index);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0xff, 0x10 }, decoded.value.blob);
}

// ═══════════════════════════════════════════════════════════════════════════
// REVERSE: the reference CLIENT's recorded bytes, fed to OUR server.
// ═══════════════════════════════════════════════════════════════════════════

// The service must be identical to the one `tools/interop.zig` served at
// capture time — the manifest's `reverse_service` records the method list so
// a one-sided edit is visible. It is duplicated rather than imported: a
// module's tests must not reach into `tools/`.

const M = server.Methods(EchoRequest, EchoReply);

fn srvUnary(c: *server.Call, req: EchoRequest) anyerror!EchoReply {
    return .{
        .text = try std.fmt.allocPrint(c.arena, "echo:{s}", .{req.text}),
        .index = req.count,
        .blob = req.blob,
    };
}

fn srvServerStream(s: *M.Stream, req: EchoRequest) anyerror!void {
    var i: i32 = 0;
    while (i < req.count) : (i += 1) {
        try s.send(.{
            .text = try std.fmt.allocPrint(s.call.arena, "{s}-{d}", .{ req.text, i }),
            .index = i,
        });
    }
}

fn srvClientStream(s: *M.Stream) anyerror!EchoReply {
    var parts: std.ArrayList([]const u8) = .empty;
    var n: i32 = 0;
    while (try s.receive()) |*r| {
        defer @constCast(r).deinit();
        try parts.append(s.call.arena, try s.call.arena.dupe(u8, r.value.text));
        n += 1;
    }
    return .{ .text = try std.mem.join(s.call.arena, "|", parts.items), .index = n };
}

fn srvBidi(s: *M.Stream) anyerror!void {
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

fn srvFail(c: *server.Call, req: EchoRequest) anyerror!EchoReply {
    try c.setTrailingMetadata(.{ .name = "x-why", .value = "because" });
    return c.fail(@enumFromInt(@as(u32, @intCast(req.count))), req.text);
}

fn srvStreamFail(s: *M.Stream, req: EchoRequest) anyerror!void {
    var i: i32 = 0;
    while (i < req.count) : (i += 1) {
        try s.send(.{ .text = "partial", .index = i });
    }
    return s.call.failFmt(.data_loss, "gave up after {d}", .{req.count});
}

fn srvEmpty(s: *M.Stream, req: EchoRequest) anyerror!void {
    _ = s;
    _ = req;
}

fn srvBig(c: *server.Call, req: EchoRequest) anyerror!EchoReply {
    const n: usize = @intCast(@max(0, req.count));
    const blob = try c.arena.alloc(u8, n);
    @memset(blob, 0x5a);
    return .{ .text = "big", .index = req.count, .blob = blob };
}

fn srvMeta(c: *server.Call, req: EchoRequest) anyerror!EchoReply {
    _ = req;
    const probe = c.metadataValue("x-probe") orelse "-";
    const bin: []const u8 = if (try c.metadataValueDecoded("x-probe-bin")) |d| blk: {
        defer d.deinit(c.gpa);
        break :blk try c.arena.dupe(u8, d.bytes);
    } else "";
    try c.addInitialMetadata(.{ .name = "x-echo", .value = probe });
    try c.addInitialMetadata(.{ .name = "x-echo-bin", .value = bin });
    try c.declareTrailingMetadata(&.{ "x-tail", "x-tail-bin" });
    try c.setTrailingMetadata(.{ .name = "x-tail", .value = probe });
    try c.setTrailingMetadata(.{ .name = "x-tail-bin", .value = bin });
    return .{ .text = probe, .index = @intCast(bin.len), .blob = bin };
}

/// −1 = no deadline, 1 = a deadline in (29 s, 31 s], 2 = anything else. The
/// band is what proves the **unit**: reading `m` as minutes instead of
/// milliseconds turns grpcio's `30100m` into three weeks.
///
/// The clock is the real one here, exactly as at capture: the server computes
/// `now + grpc-timeout` when it decodes the recorded request, so the band is
/// stable no matter when the replay runs.
fn srvDeadline(c: *server.Call, req: EchoRequest) anyerror!EchoReply {
    _ = req;
    const raw = c.metadataValue("grpc-timeout") orelse "none";
    const ns = c.remaining() orelse return .{ .text = raw, .index = -1 };
    const in_band = ns > 29 * std.time.ns_per_s and ns <= 31 * std.time.ns_per_s;
    return .{ .text = raw, .index = if (in_band) 1 else 2 };
}

const interop_service: server.Service = .{
    .name = "echo.Echo",
    .methods = &.{
        M.unary("Unary", srvUnary),
        M.serverStreaming("ServerStream", srvServerStream),
        M.clientStreaming("ClientStream", srvClientStream),
        M.bidiStreaming("Bidi", srvBidi),
        M.unary("Fail", srvFail),
        M.serverStreaming("StreamFail", srvStreamFail),
        M.serverStreaming("Empty", srvEmpty),
        M.unary("Big", srvBig),
        M.unary("Meta", srvMeta),
        M.unary("Deadline", srvDeadline),
    },
};

/// One response stream as a client-role peer saw it — **frame counts and
/// END_STREAM placement**, not just field values. That is the part that can
/// tell Trailers-Only from a trailer section: both spellings use the same
/// field name, and only the number of field blocks distinguishes them.
const Collected = struct {
    path: []const u8 = "",
    status: u16 = 0,
    headers: ?hpack.HeaderList = null,
    trailers: ?hpack.HeaderList = null,
    body: std.ArrayList(u8) = .empty,
    data_frames: u32 = 0,
    headers_end_stream: bool = false,

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

    /// `grpc-status` wherever it legitimately lives — the trailer section, or
    /// the single field block of a Trailers-Only response.
    fn grpcStatus(c: *const Collected) ?grpc.Status {
        const v = c.trailer("grpc-status") orelse c.header("grpc-status") orelse return null;
        return status_mod.parse(v);
    }

    fn grpcMessage(c: *const Collected) []const u8 {
        return c.trailer("grpc-message") orelse c.header("grpc-message") orelse "";
    }

    fn isTrailersOnly(c: *const Collected) bool {
        return c.headers_end_stream and c.data_frames == 0 and c.trailers == null;
    }

    /// The length-prefixed messages in the body.
    fn messages(c: *const Collected, gpa: Allocator, out: *std.ArrayList([]const u8)) !void {
        var d: frame.Deframer = .{ .max_recv_message_size = 8 * 1024 * 1024 };
        defer d.deinit(gpa);
        try d.push(gpa, c.body.items);
        while (try d.next()) |m| try out.append(gpa, try gpa.dupe(u8, m));
    }

    fn deinit(c: *Collected, gpa: Allocator) void {
        if (c.headers) |*hl| hl.deinit(gpa);
        if (c.trailers) |*hl| hl.deinit(gpa);
        c.body.deinit(gpa);
    }
};

/// Everything one replay of the reverse direction produced.
const Reverse = struct {
    gpa: Allocator,
    /// Per response stream, in the order the reference opened them.
    streams: std.ArrayList(Collected) = .empty,
    /// The reference client's own report, parsed on demand.
    report: []const u8 = capture.reverse_report,

    fn deinit(rv: *Reverse) void {
        for (rv.streams.items) |*c| {
            rv.gpa.free(c.path);
            c.deinit(rv.gpa);
        }
        rv.streams.deinit(rv.gpa);
    }

    /// The `n`-th response stream whose request had this `:path`.
    fn call(rv: *const Reverse, path: []const u8, n: usize) !*const Collected {
        var seen: usize = 0;
        for (rv.streams.items) |*c| {
            if (!std.mem.eql(u8, c.path, path)) continue;
            if (seen == n) return c;
            seen += 1;
        }
        std.debug.print("\nthe capture has no call #{d} to `{s}`\n", .{ n, path });
        return error.MissingCaptureCall;
    }

    /// What grpcio itself read for this observation, at capture time.
    fn reported(rv: *const Reverse, key: []const u8) ![]const u8 {
        var it = std.mem.splitScalar(u8, rv.report, '\n');
        while (it.next()) |line| {
            const tab = std.mem.indexOfScalar(u8, line, '\t') orelse continue;
            if (std.mem.eql(u8, line[0..tab], key)) return line[tab + 1 ..];
        }
        std.debug.print("\nthe reference client's report has no `{s}`\n", .{key});
        return error.MissingCaptureObservation;
    }

    /// Assert an observation against the reference's own reading of it.
    fn expectReported(rv: *const Reverse, key: []const u8, got: []const u8) !void {
        try testing.expectEqualStrings(try rv.reported(key), got);
    }

    fn expectReportedInt(rv: *const Reverse, key: []const u8, got: anytype) !void {
        var buf: [32]u8 = undefined;
        try rv.expectReported(key, try std.fmt.bufPrint(&buf, "{d}", .{got}));
    }

    /// grpcio names statuses in SCREAMING_SNAKE (`PERMISSION_DENIED`); our
    /// enum tags are the same words in lower case. Comparing them upper-cased
    /// keeps the expectation anchored to what the reference read, instead of
    /// to a number typed here.
    fn expectReportedStatus(rv: *const Reverse, key: []const u8, c: *const Collected) !void {
        const st = c.grpcStatus() orelse {
            std.debug.print("\nno grpc-status on the `{s}` response at all\n", .{c.path});
            return error.NoStatus;
        };
        var buf: [64]u8 = undefined;
        const tag = @tagName(st);
        try testing.expect(tag.len <= buf.len);
        for (tag, 0..) |ch, i| buf[i] = std.ascii.toUpper(ch);
        try rv.expectReported(key, buf[0..tag.len]);
    }
};

/// Our server's response bytes must fit somewhere; a 48 KiB reply plus twelve
/// other calls needs room. File-scope so the test binary's stack stays small.
var reverse_out_buf: [1024 * 1024]u8 = undefined;

/// The SETTINGS the recorded peer advertised, read straight out of the
/// recording: the 24-octet client connection preface (§3.4) is followed
/// immediately by a SETTINGS frame, and §6.5 requires it. Reading them back
/// rather than transcribing them is what keeps the decoders in `replayReverse`
/// honest when the fixture is regenerated against a different grpcio.
fn peerSettings(recording: []const u8) h2.Settings {
    var out: h2.Settings = .{ .enable_push = false };
    const preface_len = 24;
    if (recording.len < preface_len + 9) return out;
    const head = recording[preface_len..][0..9];
    const len: usize = (@as(usize, head[0]) << 16) | (@as(usize, head[1]) << 8) | head[2];
    if (head[3] != 0x4) return out; // not SETTINGS — leave the defaults
    if (len % 6 != 0 or recording.len < preface_len + 9 + len) return out;
    var it: h2.SettingsIterator = .{ .payload = recording[preface_len + 9 ..][0..len] };
    while (it.next()) |e| switch (e.id) {
        .header_table_size => out.header_table_size = e.value,
        .initial_window_size => out.initial_window_size = e.value,
        .max_frame_size => out.max_frame_size = e.value,
        .max_header_list_size => out.max_header_list_size = e.value,
        else => {},
    };
    return out;
}

/// Replay the reference client's recorded bytes into our server.
///
/// Three passes, because they answer three different questions:
///
///   1. a **server-role** `h2.Connection` decodes the recording on its own,
///      to recover which stream id carried which `:path` (and to prove the
///      recording is well-formed HTTP/2 independently of our server);
///   2. `h2_server.serve` — the exact entry point the capture ran on, with
///      the socket swapped for a fixed reader — turns those bytes into our
///      server's response bytes;
///   3. a **client-role** `h2.Connection`, primed with the stream ids pass 1
///      found, decodes the response bytes into `Collected` per stream.
fn replayReverse(gpa: Allocator) !Reverse {
    var rv: Reverse = .{ .gpa = gpa };
    errdefer rv.deinit();

    // ── pass 1: what did the reference ASK for? ─────────────────────────────
    var ids: std.ArrayList(u31) = .empty;
    defer ids.deinit(gpa);
    {
        // A passive decoder: it never runs handlers, so it never consumes and
        // never emits WINDOW_UPDATEs of its own. The recording, however, holds
        // a 64 KiB request (the over-limit case) that a live server paid for
        // with exactly those updates. Both windows are therefore opened wide
        // up front — legal, and precisely what a server that acks instantly
        // would do. Enforcement is not this pass's job; pass 2 runs the real
        // server with the real defaults.
        var req_conn: h2.Connection = .init(gpa, .server, .{
            .settings = .{ .initial_window_size = 1 << 28 },
        });
        defer req_conn.deinit();
        var wire: std.ArrayList(u8) = .empty;
        defer wire.deinit(gpa);
        var events: std.ArrayList(h2.Event) = .empty;
        defer {
            for (events.items) |*ev| ev.deinit(gpa);
            events.deinit(gpa);
        }
        try req_conn.sendWindowUpdate(&wire, 0, 1 << 28);
        try req_conn.recv(capture.reverse_client, &wire, &events);
        for (events.items) |*ev| switch (ev.*) {
            .headers => |*hd| {
                var path: []const u8 = "";
                for (hd.headers.fields) |f| {
                    if (std.mem.eql(u8, f.name, ":path")) path = f.value;
                }
                // The duped path is freed by `freeReverse`.
                try rv.streams.append(gpa, .{
                    .path = try gpa.dupe(u8, path),
                    .body = .empty,
                });
                try ids.append(gpa, hd.stream_id);
            },
            else => {},
        };
    }
    try testing.expect(rv.streams.items.len != 0);

    // ── pass 2: OUR server, over the recorded request bytes ─────────────────
    var router: server.Router = .{
        .gpa = gpa,
        .services = &.{interop_service},
        // Deliberately below the oversized request the reference sends, and
        // above everything else it sends — identical to the capture run.
        .options = .{ .max_recv_message_size = 64 * 1024 },
    };
    var in = Chunked.init(capture.reverse_client);
    in.arm();
    var out: Writer = .fixed(&reverse_out_buf);
    http.h2_server.serve(gpa, router.h2ServerOptions(.{
        .handler = server.handleHttp,
        .max_body_bytes = 8 << 20,
    }), &in.reader, &out);
    const response_bytes = out.buffered();
    try testing.expect(response_bytes.len != 0);

    // ── pass 3: decode what our server answered ─────────────────────────────
    // The response decoder must be configured the way the RECORDED peer was,
    // not the way `h2.Settings`'s defaults are: grpcio advertises a 4 MiB
    // `SETTINGS_MAX_FRAME_SIZE` and a 4 MiB initial window, and our server
    // sized its DATA frames to exactly that. A decoder holding the 16 KiB
    // default rejects them with FRAME_SIZE_ERROR — which would be a fault in
    // the instrument, not in the module. The values are read back OUT of the
    // recording rather than typed here, so they cannot drift from it.
    var resp_conn: h2.Connection = .init(gpa, .client, .{ .settings = peerSettings(capture.reverse_client) });
    defer resp_conn.deinit();
    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(gpa);
    var events: std.ArrayList(h2.Event) = .empty;
    defer events.deinit(gpa);

    // Like pass 1 this decoder never consumes, so it never earns its window
    // back; open it wide instead of enforcing accounting the real server
    // (pass 2) already enforced with the real defaults.
    try resp_conn.sendWindowUpdate(&wire, 0, 1 << 28);

    // Prime the client-role connection with the same stream ids the reference
    // opened, so the responses land on streams it considers open. The fields
    // are the real `:path`s from pass 1 and the bytes go nowhere.
    try resp_conn.sendPreface(&wire);
    for (rv.streams.items, ids.items) |*c, want_id| {
        const fields = [_]hpack.Field{
            .{ .name = ":method", .value = "POST" },
            .{ .name = ":scheme", .value = "http" },
            .{ .name = ":path", .value = c.path },
            .{ .name = ":authority", .value = "t" },
            .{ .name = "te", .value = "trailers" },
            .{ .name = "content-type", .value = "application/grpc+proto" },
        };
        const sid = try resp_conn.startStream(&wire, &fields, true);
        // grpcio allocates client stream ids 1, 3, 5, … in order, and so do
        // we — if that ever stops holding, the mapping below is wrong and the
        // whole reverse replay would be quietly asserting the wrong streams.
        try testing.expectEqual(want_id, sid);
    }
    wire.clearRetainingCapacity();

    try resp_conn.recv(response_bytes, &wire, &events);
    for (events.items) |*ev| switch (ev.*) {
        .headers => |*hd| {
            const idx = std.mem.indexOfScalar(u31, ids.items, hd.stream_id) orelse {
                hd.headers.deinit(gpa);
                continue;
            };
            const c = &rv.streams.items[idx];
            if (c.headers == null) {
                c.headers = hd.headers;
                c.headers_end_stream = hd.end_stream;
                if (c.header(":status")) |v| c.status = std.fmt.parseInt(u16, v, 10) catch 0;
            } else if (c.trailers == null) {
                c.trailers = hd.headers;
            } else hd.headers.deinit(gpa);
        },
        .data => |d| {
            const idx = std.mem.indexOfScalar(u31, ids.items, d.stream_id) orelse continue;
            const c = &rv.streams.items[idx];
            try c.body.appendSlice(gpa, d.data);
            c.data_frames += 1;
        },
        else => {},
    };
    return rv;
}

test "replay grpcio AS CLIENT: our server answers all four call shapes the way the reference read them" {
    const gpa = testing.allocator;
    var rv = try replayReverse(gpa);
    defer rv.deinit();

    // The recording is of a run that reached the end; nothing timed out.
    try rv.expectReported("DONE", "1");

    // ── unary ──
    {
        const c = try rv.call("/echo.Echo/Unary", 0);
        var msgs: std.ArrayList([]const u8) = .empty;
        defer {
            for (msgs.items) |m| gpa.free(m);
            msgs.deinit(gpa);
        }
        try c.messages(gpa, &msgs);
        try testing.expectEqual(@as(usize, 1), msgs.items.len);
        var d = try pb.decode(EchoReply, gpa, msgs.items[0], .{});
        defer d.deinit();
        try rv.expectReported("unary.text", d.value.text);
        try rv.expectReportedInt("unary.index", d.value.index);
        var hex_buf: [64]u8 = undefined;
        try rv.expectReported("unary.blob", try std.fmt.bufPrint(&hex_buf, "{x}", .{d.value.blob}));
        try rv.expectReportedStatus("unary.code", c);
        // HEADERS, DATA, then a real trailer section — three frames, not one.
        try testing.expect(!c.isTrailersOnly());
        try testing.expect(c.trailers != null);
        try testing.expectEqual(@as(u16, 200), c.status);
    }

    // ── server-streaming: five separate messages ──
    {
        const c = try rv.call("/echo.Echo/ServerStream", 0);
        var msgs: std.ArrayList([]const u8) = .empty;
        defer {
            for (msgs.items) |m| gpa.free(m);
            msgs.deinit(gpa);
        }
        try c.messages(gpa, &msgs);
        var joined: std.ArrayList(u8) = .empty;
        defer joined.deinit(gpa);
        for (msgs.items, 0..) |m, i| {
            var d = try pb.decode(EchoReply, gpa, m, .{});
            defer d.deinit();
            if (i != 0) try joined.append(gpa, ',');
            try joined.appendSlice(gpa, d.value.text);
        }
        try rv.expectReported("serverstream.texts", joined.items);
        try rv.expectReportedStatus("serverstream.code", c);
    }

    // ── client-streaming ──
    {
        const c = try rv.call("/echo.Echo/ClientStream", 0);
        var msgs: std.ArrayList([]const u8) = .empty;
        defer {
            for (msgs.items) |m| gpa.free(m);
            msgs.deinit(gpa);
        }
        try c.messages(gpa, &msgs);
        try testing.expectEqual(@as(usize, 1), msgs.items.len);
        var d = try pb.decode(EchoReply, gpa, msgs.items[0], .{});
        defer d.deinit();
        try rv.expectReported("clientstream.text", d.value.text);
        try rv.expectReportedInt("clientstream.index", d.value.index);
        try rv.expectReportedStatus("clientstream.code", c);
    }

    // ── bidirectional ──
    {
        const c = try rv.call("/echo.Echo/Bidi", 0);
        var msgs: std.ArrayList([]const u8) = .empty;
        defer {
            for (msgs.items) |m| gpa.free(m);
            msgs.deinit(gpa);
        }
        try c.messages(gpa, &msgs);
        var joined: std.ArrayList(u8) = .empty;
        defer joined.deinit(gpa);
        for (msgs.items, 0..) |m, i| {
            var d = try pb.decode(EchoReply, gpa, m, .{});
            defer d.deinit();
            if (i != 0) try joined.append(gpa, ',');
            try joined.appendSlice(gpa, d.value.text);
        }
        try rv.expectReported("bidi.texts", joined.items);
    }
}

test "replay grpcio AS CLIENT: both ways a status reaches the reference" {
    const gpa = testing.allocator;
    var rv = try replayReverse(gpa);
    defer rv.deinit();

    // ── an error before any message → Trailers-Only ──
    {
        const c = try rv.call("/echo.Echo/Fail", 0);
        try rv.expectReportedStatus("fail.code", c);
        // ONE field block, no DATA, no second block. A response with the
        // right fields in the wrong number of frames is a different response,
        // and only a frame-level peer can see the difference.
        try testing.expect(c.isTrailersOnly());

        // The detail contained a newline, a multi-byte UTF-8 sequence and a
        // literal '%' — every class of byte the grpc-message ABNF forbids.
        // grpcio's percent-DEcoder reproduced it exactly at capture time
        // (`fail.details_match` = 1), which is what says our ENcoder is
        // right; here we check our encoder still emits the same wire form.
        try rv.expectReported("fail.details_match", "1");
        var buf: [256]u8 = undefined;
        const decoded = status_mod.decodeMessage(c.grpcMessage(), &buf);
        try testing.expectEqualStrings("boom\nline two \xe2\x98\x83 100% done", decoded);
        // …and the trailing metadata that rode in the SAME single field block.
        try rv.expectReported("fail.x_why", c.header("x-why") orelse "-");
    }

    // ── messages, then a status in a real trailer section ──
    {
        const c = try rv.call("/echo.Echo/StreamFail", 0);
        var msgs: std.ArrayList([]const u8) = .empty;
        defer {
            for (msgs.items) |m| gpa.free(m);
            msgs.deinit(gpa);
        }
        try c.messages(gpa, &msgs);
        try rv.expectReportedInt("streamfail.count", msgs.items.len);
        try rv.expectReportedStatus("streamfail.code", c);
        try testing.expect(!c.isTrailersOnly());
        try testing.expect(c.trailers != null);
        var buf: [256]u8 = undefined;
        try rv.expectReported("streamfail.details", status_mod.decodeMessage(c.grpcMessage(), &buf));
    }

    // ── routing: a method that does not exist ──
    {
        const c = try rv.call("/echo.Echo/NoSuchMethod", 0);
        try rv.expectReportedStatus("unknown.code", c);
        var buf: [256]u8 = undefined;
        try rv.expectReported("unknown.details", status_mod.decodeMessage(c.grpcMessage(), &buf));
    }

    // ── a REQUEST over the server's receive limit ──
    {
        // The oversized one is the SECOND call to /echo.Echo/Unary: the
        // reference sends 128 KiB of blob against a 64 KiB limit.
        const c = try rv.call("/echo.Echo/Unary", 1);
        try rv.expectReportedStatus("toolarge.code", c);
    }

    // ── a successful call that produces no message at all ──
    {
        const c = try rv.call("/echo.Echo/Empty", 0);
        var msgs: std.ArrayList([]const u8) = .empty;
        defer {
            for (msgs.items) |m| gpa.free(m);
            msgs.deinit(gpa);
        }
        try c.messages(gpa, &msgs);
        try rv.expectReportedInt("empty.count", msgs.items.len);
        try rv.expectReportedStatus("empty.code", c);
    }
}

test "replay grpcio AS CLIENT: metadata, deadlines and a many-frame reply" {
    const gpa = testing.allocator;
    var rv = try replayReverse(gpa);
    defer rv.deinit();

    // ── metadata, both sections, ASCII and -bin ──
    {
        const c = try rv.call("/echo.Echo/Meta", 0);
        var msgs: std.ArrayList([]const u8) = .empty;
        defer {
            for (msgs.items) |m| gpa.free(m);
            msgs.deinit(gpa);
        }
        try c.messages(gpa, &msgs);
        try testing.expectEqual(@as(usize, 1), msgs.items.len);
        var d = try pb.decode(EchoReply, gpa, msgs.items[0], .{});
        defer d.deinit();
        // Our server decoded grpcio's OWN base64 `-bin` header to get this.
        try rv.expectReported("meta.body_text", d.value.text);
        var hex_buf: [64]u8 = undefined;
        try rv.expectReported("meta.body_blob", try std.fmt.bufPrint(&hex_buf, "{x}", .{d.value.blob}));

        try rv.expectReported("meta.initial_ascii", c.header("x-echo").?);
        try rv.expectReported("meta.trailing_ascii", c.trailer("x-tail").?);
        // Decisive: a field the reference reported as TRAILING must not also
        // appear in the initial block. If our server put the trailer fields
        // in the head, this flips.
        try rv.expectReported("meta.tail_not_initial", if (c.header("x-tail") == null) "1" else "0");

        // The `-bin` values our server emitted, decoded the way grpcio did.
        const raw = [_]u8{ 0x00, 0x01, 0xfe, 0xff, 0x0a, 0x25 };
        var bin_buf: [64]u8 = undefined;
        var dec = std.base64.standard_no_pad.Decoder;
        const ib = c.header("x-echo-bin").?;
        const ib_len = try dec.calcSizeForSlice(ib);
        try dec.decode(bin_buf[0..ib_len], ib);
        try testing.expectEqualSlices(u8, &raw, bin_buf[0..ib_len]);
        try rv.expectReported("meta.initial_bin", try std.fmt.bufPrint(&hex_buf, "{x}", .{bin_buf[0..ib_len]}));

        const tb = c.trailer("x-tail-bin").?;
        const tb_len = try dec.calcSizeForSlice(tb);
        try dec.decode(bin_buf[0..tb_len], tb);
        try rv.expectReported("meta.trailing_bin", try std.fmt.bufPrint(&hex_buf, "{x}", .{bin_buf[0..tb_len]}));
    }

    // ── grpc-timeout, as the reference rendered it ──
    {
        // Two calls: the first carries a 30 s deadline, the second none.
        const with = try rv.call("/echo.Echo/Deadline", 0);
        var msgs: std.ArrayList([]const u8) = .empty;
        defer {
            for (msgs.items) |m| gpa.free(m);
            msgs.deinit(gpa);
        }
        try with.messages(gpa, &msgs);
        var d = try pb.decode(EchoReply, gpa, msgs.items[0], .{});
        defer d.deinit();
        // Band 1 = our server, parsing grpcio's own `grpc-timeout` literal,
        // computed a deadline in (29 s, 31 s]. Reading `m` as minutes instead
        // of milliseconds turns grpcio's `30100m` into three weeks and lands
        // in band 2 — this single digit is the whole unit check.
        try rv.expectReportedInt("deadline.band", d.value.index);
        // `text` is grpcio's literal, echoed back. Its exact form (`30100m`
        // vs `30S`) is grpcio's own timing artifact — the recording pins one,
        // and only its SHAPE is a contract.
        try rv.expectReported("deadline.raw", d.value.text);
        const raw = d.value.text;
        try testing.expect(raw.len >= 2);
        try testing.expect(switch (raw[raw.len - 1]) {
            'H', 'M', 'S', 'm', 'u', 'n' => std.mem.indexOfNone(u8, raw[0 .. raw.len - 1], "0123456789") == null,
            else => false,
        });

        const without = try rv.call("/echo.Echo/Deadline", 1);
        var msgs2: std.ArrayList([]const u8) = .empty;
        defer {
            for (msgs2.items) |m| gpa.free(m);
            msgs2.deinit(gpa);
        }
        try without.messages(gpa, &msgs2);
        var d2 = try pb.decode(EchoReply, gpa, msgs2.items[0], .{});
        defer d2.deinit();
        try rv.expectReportedInt("deadline.none", d2.value.index);
    }

    // ── a reply spanning many DATA frames ──
    {
        const c = try rv.call("/echo.Echo/Big", 0);
        var msgs: std.ArrayList([]const u8) = .empty;
        defer {
            for (msgs.items) |m| gpa.free(m);
            msgs.deinit(gpa);
        }
        try c.messages(gpa, &msgs);
        var d = try pb.decode(EchoReply, gpa, msgs.items[0], .{});
        defer d.deinit();
        try rv.expectReportedInt("big.len", d.value.blob.len);
        var all_5a = true;
        for (d.value.blob) |b| {
            if (b != 0x5a) all_5a = false;
        }
        try rv.expectReported("big.all_5a", if (all_5a) "1" else "0");
        // 48 KiB against the peer's frame size: this provably left in several
        // DATA frames rather than one.
        try testing.expect(c.data_frames > 1);
    }
}

test "the capture's provenance is recorded" {
    // A fixture whose origin is not written down is a fixture nobody can
    // re-derive — and this one is the module's only external evidence on a
    // machine with no grpcio. These four lines are what a reader needs.
    try testing.expect(std.mem.startsWith(u8, capture.reference, "Python grpcio "));
    try testing.expectEqual(@as(usize, 10), capture.captured_on.len);
    try testing.expect(std.mem.indexOf(u8, capture.command, "--capture") != null);
    try testing.expect(std.mem.indexOf(u8, capture.reverse_service, "echo.Echo") != null);
    // Every forward case the tests above look up must exist.
    for ([_][]const u8{
        "unary",         "server_stream",    "client_stream",
        "bidi",          "fail",             "trailers_only",
        "stream_fail",   "big",              "metadata",
        "deadline_none", "deadline_seconds", "deadline_millis",
        "multiplex",
    }) |name| {
        if (capture.find(name) == null) {
            std.debug.print("\ncapture case `{s}` is missing\n", .{name});
            return error.MissingCaptureCase;
        }
    }
}
