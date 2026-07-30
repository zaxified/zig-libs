// SPDX-License-Identifier: MIT

//! Live interop against the **reference** gRPC implementation — Python
//! `grpcio`, the stack the gRPC project itself ships.
//!
//! ## Why this file is the module's real evidence
//!
//! Every self-contained gRPC test in this repository is a conversation with
//! ourselves. Our framer writes the length prefix and our deframer reads it;
//! flip both to little-endian, or put the compressed flag after the length
//! instead of before it, and every round trip in `call_test.zig` still passes
//! while nothing on the network can read a byte we send. The mutations that
//! matter most are exactly the ones that stay *consistent* between the two
//! halves — they are invisible to a self round trip by construction, and only
//! an outside implementation sees them.
//!
//! So the reference server here is not a nicety. It is the only place where
//! "our framing is correct" is actually tested rather than assumed.
//!
//! It is also, incidentally, the first **third-party HTTP/2 peer** the
//! `http` module's h2 client has ever talked to: grpcio serves real HTTP/2
//! (c-core), so the preface, SETTINGS, HPACK, flow control, DATA framing and
//! trailer sections underneath these calls are all being validated against a
//! stack that has never seen our code.
//!
//! ## What is driven
//!
//! All four call shapes (unary, server-streaming, client-streaming,
//! bidirectional), plus: a call that fails with a real `grpc-status` in a
//! real **Trailers-Only** response; a call that streams messages and *then*
//! fails, so the status arrives in a trailer section instead; metadata in
//! both directions including `-bin` keys; `grpc-timeout` read back by the
//! reference; a reply large enough to be split across many DATA frames; and
//! the receive limit refusing an oversized one.
//!
//! Tests **skip loudly** (never silently, never as a failure) when the
//! interpreter or `grpcio` is missing. Set `GRPC_PYTHON` to point at a
//! specific interpreter (a virtualenv with grpcio installed);
//! `~/.cache/zig-libs-grpc/bin/python` is tried before a bare `python3`.
//! Set `ZIG_LIBS_VERBOSE_SKIP` to see skip reasons.

const builtin = @import("builtin");
const std = @import("std");
const http = @import("http");
const pb = @import("protobuf");
const grpc = @import("root.zig");

const testing = std.testing;

// ── the schema, mirroring testdata/reference_server.py ──────────────────────

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

// ── skip plumbing ───────────────────────────────────────────────────────────

fn verboseSkip() bool {
    const v = std.process.Environ.getPosix(std.testing.environ, "ZIG_LIBS_VERBOSE_SKIP") orelse return false;
    return v.len > 0;
}

fn skip(reason: []const u8) error{SkipZigTest} {
    if (verboseSkip()) std.debug.print("\nSKIPPED: {s}\n", .{reason});
    return error.SkipZigTest;
}

/// `$GRPC_PYTHON` if set, else the interpreter this repository's grpcio
/// virtualenv lives in, else a bare `python3`. `buf` backs the middle case.
fn interpreter(buf: []u8) []const u8 {
    if (std.process.Environ.getPosix(std.testing.environ, "GRPC_PYTHON")) |p| {
        if (p.len != 0) return p;
    }
    if (std.process.Environ.getPosix(std.testing.environ, "HOME")) |home| {
        const path = std.fmt.bufPrint(buf, "{s}/.cache/zig-libs-grpc/bin/python", .{home}) catch return "python3";
        std.Io.Dir.cwd().access(testing.io, path, .{}) catch return "python3";
        return path;
    }
    return "python3";
}

fn requireGrpcio(io: std.Io, python: []const u8) error{SkipZigTest}!void {
    var child = std.process.spawn(io, .{
        .argv = &.{ python, "-c", "import grpc" },
        .stdin = .close,
        .stdout = .ignore,
        .stderr = .ignore,
    }) catch return skip("no python interpreter — grpc reference-interop tests need one");
    const term = child.wait(io) catch return skip("python could not be waited on");
    switch (term) {
        .exited => |code| if (code != 0)
            return skip("python has no `grpcio` module (pip install grpcio)"),
        else => return skip("python terminated abnormally"),
    }
}

// ── fixture: a live grpcio server plus a channel pointed at it ─────────────

const script = @embedFile("testdata/reference_server.py");

/// Heap-allocated because `http.Client` and the h2 session hold pointers into
/// each other — none of this may move once connected.
const Fixture = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    child: std.process.Child,
    client: http.Client,
    hs: *http.Client.H2Session,
    ch: grpc.Channel,
    /// Backs `interpreter`'s constructed path for the child's lifetime.
    path_buf: [512]u8 = undefined,

    fn start(gpa: std.mem.Allocator, options: grpc.Options) !*Fixture {
        if (builtin.os.tag != .linux) return skip("grpc reference interop is exercised on Linux");
        const io = testing.io;
        const f = try gpa.create(Fixture);
        errdefer gpa.destroy(f);
        f.gpa = gpa;
        f.io = io;

        const python = interpreter(&f.path_buf);
        try requireGrpcio(io, python);

        f.child = std.process.spawn(io, .{
            .argv = &.{ python, "-c", script },
            .stdin = .close,
            .stdout = .pipe,
            .stderr = .ignore,
        }) catch return skip("could not spawn the grpcio reference server");
        errdefer f.child.kill(io);

        // The server prints `PORT <n>` after bind()+start(), so anything we
        // connect afterwards is guaranteed to find a listening socket.
        var line_buf: [128]u8 = undefined;
        var stdout_reader = f.child.stdout.?.reader(io, &line_buf);
        const raw = stdout_reader.interface.takeDelimiterInclusive('\n') catch
            return skip("the grpcio reference server never printed its port");
        const line = std.mem.trimEnd(u8, raw, "\n");
        if (!std.mem.startsWith(u8, line, "PORT ")) return skip("unexpected greeting from the reference server");
        const port = std.fmt.parseInt(u16, line["PORT ".len..], 10) catch
            return skip("unparseable port from the reference server");

        f.client = http.Client.init(io, gpa, .{});
        errdefer f.client.deinit();
        f.hs = f.client.connectH2c("127.0.0.1", port, .{}) catch
            return skip("could not open h2c to the reference server");
        f.ch = grpc.Channel.overH2Session(f.hs, options);
        return f;
    }

    fn deinit(f: *Fixture) void {
        f.hs.close();
        f.client.deinit();
        f.child.kill(f.io);
        const gpa = f.gpa;
        gpa.destroy(f);
    }
};

// ── the four call shapes ────────────────────────────────────────────────────

test "LIVE grpcio: unary — one request, one reply, real grpc-status OK in the trailers" {
    const gpa = testing.allocator;
    const f = try Fixture.start(gpa, .{});
    defer f.deinit();

    var reply = try grpc.unary(EchoRequest, EchoReply, &f.ch, "/echo.Echo/Unary", .{
        .text = "hello reference",
        .count = 7,
        .blob = &.{ 0x00, 0xff, 0x10 },
    }, .{});
    defer reply.deinit();

    try testing.expectEqualStrings("echo:hello reference", reply.value.text);
    try testing.expectEqual(@as(i32, 7), reply.value.index);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0xff, 0x10 }, reply.value.blob);
}

test "LIVE grpcio: server-streaming — many replies on one stream, then trailers" {
    const gpa = testing.allocator;
    const f = try Fixture.start(gpa, .{});
    defer f.deinit();

    var s = try Echo.start(&f.ch, "/echo.Echo/ServerStream", .{});
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

test "LIVE grpcio: client-streaming — many requests, one reply after closeSend" {
    const gpa = testing.allocator;
    const f = try Fixture.start(gpa, .{});
    defer f.deinit();

    var s = try Echo.start(&f.ch, "/echo.Echo/ClientStream", .{});
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

test "LIVE grpcio: bidirectional — send and receive interleaved on one stream" {
    const gpa = testing.allocator;
    const f = try Fixture.start(gpa, .{});
    defer f.deinit();

    var s = try Echo.start(&f.ch, "/echo.Echo/Bidi", .{});
    defer s.deinit();

    // Genuinely interleaved: each reply is read before the next request is
    // written, so the request half is still open while the response half is
    // producing — the thing only a bidirectional stream can do.
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

// ── errors: the two ways a status arrives ──────────────────────────────────

test "LIVE grpcio: a failing call arrives as a real Trailers-Only response" {
    const gpa = testing.allocator;
    const f = try Fixture.start(gpa, .{});
    defer f.deinit();

    // A message full of bytes the grpc-message ABNF forbids, so the
    // percent-decoding is exercised against the reference's encoder rather
    // than against our own.
    const detail = "boom\nline two \xe2\x98\x83 100% done";

    var failure: grpc.Failure = .{};
    defer failure.deinit(gpa);
    const err = grpc.unary(EchoRequest, EchoReply, &f.ch, "/echo.Echo/Fail", .{
        .text = detail,
        .count = @intFromEnum(grpc.Status.permission_denied),
    }, .{ .failure = &failure });

    try testing.expectError(error.PermissionDenied, err);
    try testing.expectEqual(grpc.Status.permission_denied, failure.status);
    try testing.expectEqualStrings(detail, failure.message);
}

test "LIVE grpcio: a Trailers-Only response has no trailer section at all" {
    const gpa = testing.allocator;
    const f = try Fixture.start(gpa, .{});
    defer f.deinit();

    var call = try f.ch.start("/echo.Echo/Fail", .{});
    defer call.deinit();
    const req = try pb.encodeAlloc(gpa, EchoRequest{
        .text = "nope",
        .count = @intFromEnum(grpc.Status.not_found),
    }, .{});
    defer gpa.free(req);
    try call.sendMessage(req, true);

    // The whole response is one HEADERS frame: no body, and `grpc-status`
    // is in the INITIAL metadata. A client that only ever looks in the
    // trailer section finds nothing here and waits forever.
    try testing.expectEqual(@as(?[]const u8, null), try call.receive());
    try testing.expect(call.trailers_only);
    try testing.expect(call.trailingMetadata() == null);
    try testing.expect(call.initialMetadata().?.fields.len != 0);
    try testing.expectError(error.NotFound, call.finish());
    try testing.expectEqual(grpc.Status.not_found, call.status.?);
    try testing.expectEqualStrings("nope", call.statusMessage());
}

test "LIVE grpcio: messages then a non-OK status in a real trailer section" {
    const gpa = testing.allocator;
    const f = try Fixture.start(gpa, .{});
    defer f.deinit();

    var s = try Echo.start(&f.ch, "/echo.Echo/StreamFail", .{});
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

// ── the receive limit, against a real producer ─────────────────────────────

test "LIVE grpcio: a reply larger than max_recv_message_size fails RESOURCE_EXHAUSTED" {
    const gpa = testing.allocator;
    // 64 KiB limit, and we ask the reference for a ~256 KiB reply.
    const f = try Fixture.start(gpa, .{ .max_recv_message_size = 64 * 1024 });
    defer f.deinit();

    var failure: grpc.Failure = .{};
    defer failure.deinit(gpa);
    const err = grpc.unary(EchoRequest, EchoReply, &f.ch, "/echo.Echo/Big", .{
        .count = 256 * 1024,
    }, .{ .failure = &failure });

    try testing.expectError(error.ResourceExhausted, err);
    try testing.expectEqual(grpc.Status.resource_exhausted, failure.status);
}

test "LIVE grpcio: a large reply under the limit is reassembled across DATA frames" {
    const gpa = testing.allocator;
    const f = try Fixture.start(gpa, .{ .max_recv_message_size = 1024 * 1024 });
    defer f.deinit();

    // 256 KiB of payload is many times the peer's 16 KiB default HTTP/2 frame
    // size and far past the 64 KiB initial flow-control window, so this one
    // message provably arrives split across a long run of DATA frames — and
    // the deframer has to put it back together to the byte.
    const want: i32 = 256 * 1024;
    var reply = try grpc.unary(EchoRequest, EchoReply, &f.ch, "/echo.Echo/Big", .{
        .count = want,
    }, .{});
    defer reply.deinit();

    try testing.expectEqualStrings("big", reply.value.text);
    try testing.expectEqual(want, reply.value.index);
    try testing.expectEqual(@as(usize, @intCast(want)), reply.value.blob.len);
    for (reply.value.blob) |b| try testing.expectEqual(@as(u8, 0x5a), b);
}

// ── metadata and deadlines ─────────────────────────────────────────────────

test "LIVE grpcio: ASCII and -bin metadata survive both directions" {
    const gpa = testing.allocator;
    const f = try Fixture.start(gpa, .{});
    defer f.deinit();

    // Bytes that no ASCII header could carry — that is the whole reason
    // `-bin` exists, so the probe has to actually contain them.
    const raw = [_]u8{ 0x00, 0x01, 0xfe, 0xff, 0x0a, 0x25 };

    var call = try f.ch.start("/echo.Echo/Meta", .{ .metadata = &.{
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

test "LIVE grpcio: grpc-timeout is understood by the reference server" {
    const gpa = testing.allocator;
    const f = try Fixture.start(gpa, .{});
    defer f.deinit();

    // No deadline: the reference reports -1.
    var none = try grpc.unary(EchoRequest, EchoReply, &f.ch, "/echo.Echo/Deadline", .{}, .{});
    defer none.deinit();
    try testing.expectEqual(@as(i32, -1), none.value.index);

    // 30 s: the reference sees a deadline in the 29–30 s band, which only
    // happens if it parsed our `grpc-timeout` value AND our unit.
    var some = try grpc.unary(EchoRequest, EchoReply, &f.ch, "/echo.Echo/Deadline", .{}, .{
        .timeout = .{ .value = 30, .unit = .seconds },
    });
    defer some.deinit();
    try testing.expect(some.value.index >= 29_000 and some.value.index <= 30_000);

    // The same duration expressed in milliseconds must land in the same band
    // — a unit we render but the peer reads differently would show up here.
    var ms = try grpc.unary(EchoRequest, EchoReply, &f.ch, "/echo.Echo/Deadline", .{}, .{
        .timeout = grpc.Timeout.fromMillis(30_000),
    });
    defer ms.deinit();
    try testing.expect(ms.value.index >= 29_000 and ms.value.index <= 30_000);
}

test "LIVE grpcio: several calls multiplexed on one HTTP/2 connection" {
    const gpa = testing.allocator;
    const f = try Fixture.start(gpa, .{});
    defer f.deinit();

    // Three streams open at once on one connection, collected out of order —
    // the demultiplexing underneath is the h2 client's, exercised here
    // against a third-party server for the first time.
    var a = try Echo.start(&f.ch, "/echo.Echo/Unary", .{});
    defer a.deinit();
    var b = try Echo.start(&f.ch, "/echo.Echo/ServerStream", .{});
    defer b.deinit();
    var c = try Echo.start(&f.ch, "/echo.Echo/Unary", .{});
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
