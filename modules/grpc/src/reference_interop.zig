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
//! ## Both directions, and why the second one is the stronger test
//!
//! The first half of this file points **our client** at the reference
//! server. The second half turns it round: the reference `grpcio` **client**
//! calls **our server** (`testdata/reference_client.py`).
//!
//! That direction is worth more. A client that frames wrongly can still be
//! understood by a lenient peer — a length prefix that is one byte off is
//! usually recoverable at the far end — but a server that frames wrongly
//! fails visibly, because the peer has to find every message boundary, the
//! trailer section and the status without help. Everything our server
//! *produces* is under a real parser here: the 5-byte prefixes, the choice
//! between a Trailers-Only field block and a trailer section, the
//! percent-encoded `grpc-message`, and the `-bin` metadata base64.
//!
//! ## What is driven
//!
//! In both directions: all four call shapes (unary, server-streaming,
//! client-streaming, bidirectional), plus a call that fails with a real
//! `grpc-status` in a real **Trailers-Only** response; a call that streams
//! messages and *then* fails, so the status arrives in a trailer section
//! instead; metadata in both sections including `-bin` keys; `grpc-timeout`
//! read back by the far side; a message large enough to be split across many
//! DATA frames; and the receive limit refusing an oversized one.
//!
//! Every call the Python client makes carries a deadline, and the script
//! carries a watchdog that exits the process regardless. Mis-framing against
//! a real peer does not fail, it **hangs** — the peer believes a bogus length
//! and waits — so a framing bug has to surface as a timeout rather than as a
//! stuck suite.
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

const testkit = @import("testkit");
const verboseSkip = testkit.verboseSkip;

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

/// F1: how long a single `Fixture`'s lifetime (`start` → `deinit`) may run
/// before the watchdog below assumes the forward direction has hung and
/// kills the whole test process. The reverse direction already has this —
/// `testdata/reference_client.py` carries a per-call deadline plus its own
/// 90 s `threading.Timer` backstop — but `Fixture` opened an h2c session
/// with no read deadline at all, so a framing regression here didn't fail,
/// it hung: the fault-injected little-endian length-prefix flip (this
/// file's own doc comment, and F1's evidence) ran **10 minutes** before an
/// external `timeout` had to SIGTERM the suite. 20 s is generous headroom
/// over the whole live suite's *normal* runtime (a few seconds, subprocess
/// spawn included) and two orders of magnitude below that hang.
const fixture_watchdog_ms: u64 = 20_000;

/// Distinct `exit()` code the watchdog uses, so a hang is unmistakably this
/// mechanism firing and not an unrelated process death — mirrors
/// `reference_client.py`'s own `os._exit(7)` backstop for the reverse
/// direction, which is why they don't share a number.
const watchdog_exit_code: u8 = 94;

/// Polls `stop` on a short interval until it is set or `fixture_watchdog_ms`
/// elapses, then exits the whole process with `watchdog_exit_code`. Runs on
/// its own thread, started by `Fixture.start` and stopped by `Fixture.deinit`
/// — so it brackets exactly the span in which a hang can happen: opening the
/// h2c session and every RPC the test makes on it.
fn watchdogFn(stop: *std.atomic.Value(bool)) void {
    const poll_ms: u64 = 50;
    var waited_ms: u64 = 0;
    while (waited_ms < fixture_watchdog_ms) : (waited_ms += poll_ms) {
        if (stop.load(.acquire)) return;
        var ts: std.posix.timespec = .{
            .sec = @intCast(poll_ms / 1000),
            .nsec = @intCast((poll_ms % 1000) * 1_000_000),
        };
        _ = std.os.linux.nanosleep(&ts, null);
    }
    if (stop.load(.acquire)) return;
    std.debug.print(
        "\nGRPC FORWARD-DIRECTION WATCHDOG FIRED: a live Fixture ran past {d} ms " ++
            "without reaching deinit — framing regression or a hung read (F1). " ++
            "Exiting {d} instead of hanging the suite.\n",
        .{ fixture_watchdog_ms, watchdog_exit_code },
    );
    std.process.exit(watchdog_exit_code);
}

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
    /// F1: set just before `deinit` tears anything down, so the watchdog
    /// thread below stops polling instead of firing on a fixture that
    /// finished normally.
    watchdog_stop: std.atomic.Value(bool) = .init(false),
    /// Null only if the watchdog thread itself failed to spawn (never
    /// observed, but `deinit` must not crash if it happens) — a fixture with
    /// no watchdog is worse than the pre-fix world, so this is not silently
    /// tolerated by `start`: see the `orelse` there.
    watchdog_thread: ?std.Thread = null,

    fn start(gpa: std.mem.Allocator, options: grpc.Options) !*Fixture {
        if (builtin.os.tag != .linux) return skip("grpc reference interop is exercised on Linux");
        const io = testing.io;
        const f = try gpa.create(Fixture);
        errdefer gpa.destroy(f);
        f.gpa = gpa;
        f.io = io;
        f.watchdog_stop = .init(false);
        f.watchdog_thread = null;

        const python = interpreter(&f.path_buf);
        try requireGrpcio(io, python);

        f.child = std.process.spawn(io, .{
            .argv = &.{ python, "-c", script },
            .stdin = .close,
            .stdout = .pipe,
            .stderr = .ignore,
        }) catch return skip("could not spawn the grpcio reference server");
        errdefer f.child.kill(io);

        // Arm the watchdog before anything that can block: the port line can
        // hang just as easily as the h2c session that follows it.
        f.watchdog_thread = std.Thread.spawn(.{}, watchdogFn, .{&f.watchdog_stop}) catch
            return skip("could not start the F1 watchdog thread — refusing to run a live fixture unguarded");
        errdefer {
            f.watchdog_stop.store(true, .release);
            if (f.watchdog_thread) |t| t.join();
        }

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
        // Stop the watchdog FIRST: teardown itself must not race a firing
        // watchdog, and a fixture that reached deinit at all is by
        // definition not the hang the watchdog exists to catch.
        f.watchdog_stop.store(true, .release);
        if (f.watchdog_thread) |t| t.join();
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

// ═══════════════════════════════════════════════════════════════════════════
// Frozen reference bytes (F5, 2026-08-08): the same problem `netconf` solved
// for its own live oracle — these two live tests establish that grpcio is a
// real, independent peer, but that proof evaporates on a host with no
// `grpcio` (every one of the 13 live tests above degrades to
// `error.SkipZigTest`, and a skip is a pass). So the concrete bytes grpcio
// put on the wire in one session are captured *once* here and asserted
// **offline**, with no `Fixture`, no subprocess and no `requireGrpcio` gate,
// exactly the way `netconf/src/reply.zig`'s `live_netconf_2_1_0_*` constants
// keep working without the `netconf` Python package installed.
//
// Captured by temporarily instrumenting this file to print the undecoded
// wire values (`std.fmt` hex dumps of `call.initialMetadata()` fields and of
// the raw bytes `Call.receive()` returned before protobuf-decoding them),
// running `scripts/capped zig build test-grpc -Dtest-filter="..."` once
// against the reference server, and transcribing the output below; the
// instrumentation itself was removed afterwards. The live tests above are
// what refreshes these constants if the module's wire contract ever
// deliberately changes.

/// `grpc-status`/`grpc-message`, byte-for-byte as the reference **C-core**
/// server's Trailers-Only response carried them (`/echo.Echo/Fail`,
/// `req.count = permission_denied`, `req.text` = the detail string below).
/// This is genuinely external: the percent-encoding convention this proves —
/// `\n` → `%0A`, each byte of the multi-byte UTF-8 snowman individually
/// escaped, a literal `%` → `%25` — comes from grpcio's own encoder, which
/// this module's `status.zig` never saw. A test that only checked
/// `encodeMessage` and `decodeMessage` agree with each other (as
/// `status.zig`'s existing round-trip tests do) cannot catch a decoder that
/// silently agrees with the *wrong* convention; this one can.
const live_grpcio_status_value = "7"; // permission_denied
const live_grpcio_message_wire = "boom%0Aline two %E2%98%83 100%25 done";
const live_grpcio_message_decoded = "boom\nline two \xe2\x98\x83 100% done";

test "external anchor: grpcio's real Trailers-Only grpc-status/grpc-message wire bytes decode correctly (frozen 2026-08-08)" {
    const status_mod = @import("status.zig");
    try testing.expectEqual(grpc.Status.permission_denied, status_mod.parse(live_grpcio_status_value).?);

    var buf: [live_grpcio_message_wire.len]u8 = undefined;
    const decoded = status_mod.decodeMessage(live_grpcio_message_wire, &buf);
    try testing.expectEqualStrings(live_grpcio_message_decoded, decoded);
}

/// The exact bytes the C-core reference server's protobuf library put on the
/// wire for one `EchoReply` (`/echo.Echo/Unary`, `text = "hello reference"`,
/// `count = 7`, `blob = {0x00, 0xff, 0x10}`) — the 5-byte gRPC length prefix
/// already stripped by `Call.receive`'s deframer the same way it was when
/// captured, so this is the payload exactly as `frame.Deframer.next` handed
/// it to `pb.decode` in the live session. Field 1 (`0x0a`, length-delimited,
/// 20 bytes) is `text`, field 2 (`0x10`, varint) is `count`/`index`, field 3
/// (`0x1a`, length-delimited, 3 bytes) is `blob` — real protobuf-library
/// wire output, not this repo's own `pb.encode`, so decoding it offline is
/// an external anchor on `protobuf`'s wire-format compatibility the same way
/// the message above is one on the percent-encoding.
const live_grpcio_echo_reply_bytes = [_]u8{
    0x0a, 0x14, 'e',  'c',  'h',  'o',  ':',  'h', 'e', 'l', 'l', 'o', ' ', 'r', 'e', 'f', 'e', 'r', 'e', 'n', 'c', 'e',
    0x10, 0x07, 0x1a, 0x03, 0x00, 0xff, 0x10,
};

test "external anchor: grpcio's real EchoReply wire bytes decode through frame + pb (frozen 2026-08-08)" {
    const gpa = testing.allocator;

    // Re-frame with this module's own LPM header — its byte layout is
    // already anchored independently in `frame.zig`'s spec-derived tests —
    // purely so the exact `Deframer` code path `Call.receive` uses is the
    // one under test here too, not a shortcut around it.
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
// The other direction: the reference grpcio CLIENT calling OUR server.
// ═══════════════════════════════════════════════════════════════════════════

const server = @import("server.zig");
const frame = @import("frame.zig");
const Writer = std.Io.Writer;

const M = server.Methods(EchoRequest, EchoReply);

/// The same `echo.Echo` contract `reference_server.py` implements, served by
/// us this time — so the reference client's expectations are unchanged and
/// only the producer of the bytes has swapped sides.
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

/// Fails before anything has gone out → a Trailers-Only response, with a
/// trailing-metadata field alongside the status so the reference has to find
/// that in the same field block.
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

/// Reports a *band* rather than a number, so the assertion on the far side is
/// exact against a real clock: −1 = no deadline, 1 = a deadline in
/// (29 s, 31 s], 2 = a deadline somewhere else.
///
/// The band is narrow enough to be evidence and wide enough to be stable. For
/// a 30 s call the reference usually pads the deadline by around 100 ms when
/// it renders `grpc-timeout` (typically `30100m`, though the exact literal
/// varies with scheduling — sometimes it lands on an exact `30S` instead), so
/// the upper edge has to be above 30 s regardless. It is 31 s and not 31
/// *minutes*, which is what makes the band prove the **unit** too: reading
/// `m` as minutes instead of milliseconds turns 30100 into three weeks, and a
/// wider band would have accepted that silently.
fn srvDeadline(c: *server.Call, req: EchoRequest) anyerror!EchoReply {
    _ = req;
    // `text` carries the reference's own `grpc-timeout` rendering back, so a
    // band that comes out wrong says *why* rather than just failing.
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

const client_script = @embedFile("testdata/reference_client.py");

/// Every `KEY\tVALUE` line the reference client printed.
const Report = struct {
    gpa: std.mem.Allocator,
    text: []u8,

    fn get(r: Report, key: []const u8) ?[]const u8 {
        var it = std.mem.splitScalar(u8, r.text, '\n');
        while (it.next()) |line| {
            const tab = std.mem.indexOfScalar(u8, line, '\t') orelse continue;
            if (std.mem.eql(u8, line[0..tab], key)) return line[tab + 1 ..];
        }
        return null;
    }

    fn expect(r: Report, key: []const u8, want: []const u8) !void {
        const got = r.get(key) orelse {
            std.debug.print("\nreference client never reported `{s}`; full report:\n{s}\n", .{ key, r.text });
            return error.MissingObservation;
        };
        if (!std.mem.eql(u8, got, want)) {
            std.debug.print(
                "\n`{s}`: reference client reported `{s}`, expected `{s}`\nfull report:\n{s}\n",
                .{ key, got, want, r.text },
            );
            return error.WrongObservation;
        }
    }

    /// Like `expect`, but for a raw `grpc-timeout` header rendering: checks
    /// the *shape* (decimal digits followed by one of grpc's timeout unit
    /// letters) rather than one exact literal.
    ///
    /// grpcio's C-core chooses both the quantization and the unit from the
    /// wall-clock gap between "the deadline was set" and "the request was
    /// actually framed onto the wire", so the same 30 s call can legitimately
    /// render as `30100m` on one run and `30S` on another depending on
    /// scheduling — confirmed by running this suite repeatedly. Pinning the
    /// literal string makes the test flaky for a reason that has nothing to
    /// do with this module's correctness. What must never vary is that a
    /// well-formed value arrived at all; whether it was parsed correctly is
    /// `deadline.band`'s job, not this one's.
    fn expectTimeoutShape(r: Report, key: []const u8) !void {
        const got = r.get(key) orelse {
            std.debug.print("\nreference client never reported `{s}`; full report:\n{s}\n", .{ key, r.text });
            return error.MissingObservation;
        };
        const valid = got.len >= 2 and switch (got[got.len - 1]) {
            'H', 'M', 'S', 'm', 'u', 'n' => std.mem.indexOfNone(u8, got[0 .. got.len - 1], "0123456789") == null,
            else => false,
        };
        if (!valid) {
            std.debug.print(
                "\n`{s}`: reference client reported `{s}`, which is not a well-formed grpc-timeout value\nfull report:\n{s}\n",
                .{ key, got, r.text },
            );
            return error.WrongObservation;
        }
    }

    fn deinit(r: Report) void {
        r.gpa.free(r.text);
    }
};

fn serveWrap(s: *http.Server) void {
    s.serve() catch {};
}

/// Stand our gRPC server up on a loopback port, run the reference client
/// against it once, and collect everything it reported.
fn driveReferenceClient(gpa: std.mem.Allocator) !Report {
    if (builtin.os.tag != .linux) return skip("grpc reference interop is exercised on Linux");
    var path_buf: [512]u8 = undefined;
    const python = interpreter(&path_buf);
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    try requireGrpcio(io, python);

    var router: grpc.Router = .{
        .gpa = gpa,
        .services = &.{interop_service},
        // Deliberately below the oversized request the client sends, and
        // above everything else it sends.
        .options = .{ .max_recv_message_size = 64 * 1024 },
    };
    var srv = http.Server.init(io, gpa, router.httpOptions(.{
        .handler = grpc.handleHttp,
        .addr = "127.0.0.1",
        .max_body_bytes = 8 << 20,
    }));
    srv.bind() catch return skip("could not bind a loopback port for the gRPC server");
    const port = srv.boundAddress().getPort();
    const th = std.Thread.spawn(.{}, serveWrap, .{&srv}) catch {
        srv.deinit();
        return skip("could not spawn the serving thread");
    };
    defer {
        srv.shutdown();
        th.join();
        srv.deinit();
    }

    var port_buf: [16]u8 = undefined;
    const port_str = try std.fmt.bufPrint(&port_buf, "{d}", .{port});

    var child = std.process.spawn(io, .{
        .argv = &.{ python, "-c", client_script, port_str },
        .stdin = .close,
        .stdout = .pipe,
        .stderr = .pipe,
    }) catch return skip("could not spawn the grpcio reference client");

    // Read stdout to EOF. The child cannot outlive its own watchdog, so this
    // read terminates even if our framing wedges the RPC — which is the
    // point: a framing bug against a real peer HANGS rather than failing.
    var collected: std.ArrayList(u8) = .empty;
    errdefer collected.deinit(gpa);
    var read_buf: [4096]u8 = undefined;
    var out_reader = child.stdout.?.reader(io, &read_buf);
    while (true) {
        var w: Writer = .fixed(&read_buf);
        const n = out_reader.interface.stream(&w, .limited(read_buf.len)) catch |err| switch (err) {
            error.EndOfStream => break,
            else => break,
        };
        if (n == 0) continue;
        try collected.appendSlice(gpa, w.buffered());
    }

    var err_buf: [8192]u8 = undefined;
    var err_reader = child.stderr.?.reader(io, &err_buf);
    var stderr_text: std.ArrayList(u8) = .empty;
    defer stderr_text.deinit(gpa);
    while (true) {
        var w: Writer = .fixed(&err_buf);
        const n = err_reader.interface.stream(&w, .limited(err_buf.len)) catch break;
        if (n == 0) continue;
        stderr_text.appendSlice(gpa, w.buffered()) catch break;
    }

    const term = child.wait(io) catch return skip("the reference client could not be waited on");
    const text = try collected.toOwnedSlice(gpa);
    errdefer gpa.free(text);
    switch (term) {
        .exited => |code| if (code != 0) {
            std.debug.print(
                "\nreference client exited {d}\nstdout:\n{s}\nstderr:\n{s}\n",
                .{ code, text, stderr_text.items },
            );
            return error.ReferenceClientFailed;
        },
        else => {
            std.debug.print("\nreference client terminated abnormally\nstderr:\n{s}\n", .{stderr_text.items});
            return error.ReferenceClientFailed;
        },
    }
    return .{ .gpa = gpa, .text = text };
}

// One server, one run of the reference client, every observation asserted.
//
// Deliberately a single test: standing the server up and starting a Python
// interpreter with grpcio costs about a second, and splitting this into
// twelve tests would pay that twelve times for no extra evidence — the
// observations are independent of each other, and a failing one names itself.
test "LIVE grpcio (as CLIENT): the reference drives all four shapes against OUR server" {
    const gpa = testing.allocator;
    const report = try driveReferenceClient(gpa);
    defer report.deinit();

    // The script ran to the end; nothing timed out.
    try report.expect("DONE", "1");

    // ── unary ──
    try report.expect("unary.text", "echo:hello reference");
    try report.expect("unary.index", "7");
    try report.expect("unary.blob", "00ff10");
    try report.expect("unary.code", "OK");

    // ── server-streaming: five separate messages, deframed by the reference ──
    try report.expect("serverstream.texts", "tick-0,tick-1,tick-2,tick-3,tick-4");
    try report.expect("serverstream.code", "OK");

    // ── client-streaming ──
    try report.expect("clientstream.text", "a|bb|ccc");
    try report.expect("clientstream.index", "3");
    try report.expect("clientstream.code", "OK");

    // ── bidirectional ──
    try report.expect("bidi.texts", "re:one,re:two,re:three");

    // ── an error before any message ──
    try report.expect("fail.code", "PERMISSION_DENIED");
    // The message contained a newline, a multi-byte UTF-8 sequence and a
    // literal '%' — every class of byte the grpc-message ABNF forbids. The
    // reference's percent-decoder reproduced it exactly, which is what says
    // our ENcoder is right.
    try report.expect("fail.details_match", "1");
    // …and the trailing metadata that rode in the same single field block.
    try report.expect("fail.x_why", "because");

    // ── messages, then a status in a real trailer section ──
    try report.expect("streamfail.count", "3");
    try report.expect("streamfail.code", "DATA_LOSS");
    try report.expect("streamfail.details", "gave up after 3");

    // ── routing ──
    try report.expect("unknown.code", "UNIMPLEMENTED");
    try report.expect("unknown.details", "unknown method NoSuchMethod for service echo.Echo");

    // ── metadata, both sections ──
    try report.expect("meta.body_text", "probe-value");
    try report.expect("meta.body_blob", "0001feff0a25");
    try report.expect("meta.initial_ascii", "probe-value");
    try report.expect("meta.initial_bin", "0001feff0a25");
    try report.expect("meta.trailing_ascii", "probe-value");
    try report.expect("meta.trailing_bin", "0001feff0a25");
    // The reference reports the tail fields as TRAILING and not as initial:
    // the two sections are really two field blocks on the wire, not one.
    try report.expect("meta.tail_not_initial", "1");

    // ── grpc-timeout ──
    // Band 1 = the server saw a deadline in (29 s, 31 s] for a 30 s call,
    // which needs both the value and the unit read correctly (see
    // `srvDeadline`). `deadline.raw` is the reference's own rendering of the
    // header it sent — evidence for *why* the band came out as it did — but
    // its exact literal form (e.g. `30100m` vs `30S`) is grpcio's own timing
    // artifact, not ours, so only its shape is asserted; `deadline.band` is
    // what actually proves our parsing.
    try report.expectTimeoutShape("deadline.raw");
    try report.expect("deadline.band", "1");
    try report.expect("deadline.none", "-1");

    // ── a reply spanning many DATA frames ──
    try report.expect("big.len", "49152");
    try report.expect("big.all_5a", "1");

    // ── the receive limit, against a real producer ──
    try report.expect("toolarge.code", "RESOURCE_EXHAUSTED");

    // ── a successful call with no message at all (Trailers-Only) ──
    try report.expect("empty.count", "0");
    try report.expect("empty.code", "OK");
}
