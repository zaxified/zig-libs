// SPDX-License-Identifier: MIT

//! Live interop against the **reference** gRPC implementation — Python
//! `grpcio`, the stack the gRPC project itself ships.
//!
//! ## Why this is a PROGRAM and not a test
//!
//! `zig-libs` modules are standalone Zig with no external dependency. An
//! anchor against a foreign implementation is a different thing: it needs a
//! Python interpreter with `grpcio` and `protobuf` installed. Until
//! 2026-09-06 this file lived at `src/reference_interop.zig`, `@embedFile`d
//! two Python scripts into module source and shelled out from inside
//! `test-grpc` — so every consumer of the library carried foreign source, and
//! the module's own test lane could not run without a toolchain it had no
//! business needing. It "skipped loudly" instead, and a skip is a pass, so on
//! a host without grpcio the module's strongest evidence silently evaporated.
//!
//! The split:
//!
//!   * this program does the **taking** — spawns `reference_server.py` /
//!     `reference_client.py` (next to this file, run from their own path),
//!     talks to them over real sockets, and compares live. It is built by
//!     `zig build interop-grpc` and by `zig build check-interop`; it is never
//!     compiled into `test-grpc` and never into `zig build`.
//!
//!   * `zig build interop-grpc -- --capture` additionally **records every
//!     byte the reference put on the wire** into `src/testdata/grpcio/*.bin`
//!     and regenerates the manifest `src/testdata/grpcio_capture.zig`.
//!
//!   * `src/reference_replay.zig` — inside the module, in the ordinary test
//!     lane — replays those bytes with no child process, no socket and no
//!     foreign source. That is where the anchor's VALUE runs.
//!
//! So: this program is the only thing that can discover a NEW divergence, and
//! is a pre-release check. The replay is what keeps a KNOWN divergence caught
//! on every machine.
//!
//! ## Why the anchor is the module's real evidence
//!
//! Every self-contained gRPC test in this repository is a conversation with
//! ourselves. Our framer writes the length prefix and our deframer reads it;
//! flip both to little-endian, or put the compressed flag after the length
//! instead of before it, and every round trip in `call_test.zig` still passes
//! while nothing on the network can read a byte we send. The mutations that
//! matter most are exactly the ones that stay *consistent* between the two
//! halves — invisible to a self round trip by construction, visible only to
//! an outside implementation.
//!
//! It is also the first **third-party HTTP/2 peer** the `http` module's h2
//! client and server have ever talked to: grpcio serves real HTTP/2 (c-core),
//! so the preface, SETTINGS, HPACK, flow control, DATA framing and trailer
//! sections underneath these calls are all validated against a stack that has
//! never seen our code.
//!
//! ## Both directions, and why the second one is the stronger test
//!
//! The forward half points **our client** at the reference server. The
//! reverse half turns it round: the reference `grpcio` **client** calls **our
//! server**.
//!
//! That direction is worth more. A client that frames wrongly can still be
//! understood by a lenient peer — a length prefix one byte off is usually
//! recoverable at the far end — but a server that frames wrongly fails
//! visibly, because the peer has to find every message boundary, the trailer
//! section and the status without help.
//!
//! ## Usage
//!
//!     zig build interop-grpc                  # live comparison, both directions
//!     zig build interop-grpc -- --capture     # …and rewrite the replay fixture
//!     zig build interop-grpc -- --forward     # forward direction only
//!     zig build interop-grpc -- --reverse     # reverse direction only
//!
//! `$GRPC_PYTHON` selects the interpreter (a virtualenv with grpcio
//! installed); `~/.cache/zig-libs-grpc/bin/python` is tried before a bare
//! `python3`. `$GRPC_TOOLS_DIR` / `$GRPC_TESTDATA_DIR` override where the
//! reference scripts are read from and where the capture is written; both
//! default to this module's own paths relative to the build root, which is
//! the cwd `zig build` runs the program in.
//!
//! Exit codes: 0 = everything compared equal. 1 = a comparison failed (a real
//! divergence, or a bug here). 2 = the reference peer is not installed — said
//! plainly, never as a silent pass.

const builtin = @import("builtin");
const std = @import("std");
const http = @import("http");
const pb = @import("protobuf");
const grpc = @import("grpc");

const net = std.Io.net;
const Allocator = std.mem.Allocator;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

// ── the schema, mirroring reference_server.py / reference_client.py ─────────

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

// ── failure reporting ───────────────────────────────────────────────────────

var failures: u32 = 0;
var comparisons: u32 = 0;

fn note(comptime fmt: []const u8, args: anytype) void {
    std.debug.print(fmt ++ "\n", args);
}

/// The reference peer is missing. Loud, and exit 2 — never a silent pass.
fn peerMissing(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("\nREFERENCE PEER NOT AVAILABLE: " ++ fmt ++ "\n", args);
    std.debug.print(
        \\
        \\  This program is the *taking* half of the grpc anchor and needs a
        \\  Python interpreter with `grpcio` and `protobuf`:
        \\
        \\      python3 -m venv ~/.cache/zig-libs-grpc
        \\      ~/.cache/zig-libs-grpc/bin/pip install grpcio protobuf
        \\
        \\  The module's own hermetic replay (`zig build test-grpc`) needs
        \\  none of this and is unaffected.
        \\
    , .{});
    std.process.exit(2);
}

fn expectStr(case: []const u8, key: []const u8, got: []const u8, want: []const u8) void {
    comparisons += 1;
    if (!std.mem.eql(u8, got, want)) {
        failures += 1;
        note("DIVERGENCE {s}.{s}: got `{s}`, expected `{s}`", .{ case, key, got, want });
    }
}

fn expectInt(case: []const u8, key: []const u8, got: anytype, want: @TypeOf(got)) void {
    comparisons += 1;
    if (got != want) {
        failures += 1;
        note("DIVERGENCE {s}.{s}: got {d}, expected {d}", .{ case, key, got, want });
    }
}

fn expectTrue(case: []const u8, key: []const u8, ok: bool) void {
    comparisons += 1;
    if (!ok) {
        failures += 1;
        note("DIVERGENCE {s}.{s}: expected true", .{ case, key });
    }
}

// ── a Reader that copies everything it yields into a log ───────────────────

/// Modelled on `std.Io.Reader.Hashed` — same three vtable entries, with
/// `hasher.update` replaced by an append into `log`. Wrapping the socket's
/// reader (rather than tapping inside `http`) is what makes the recording
/// exactly the byte stream our own client/server saw, in the order it saw it:
/// a fixture recorded anywhere else would be a fixture of something else.
const Tap = struct {
    in: *Reader,
    gpa: Allocator,
    log: *std.ArrayList(u8),
    reader: Reader,

    fn init(in: *Reader, gpa: Allocator, log: *std.ArrayList(u8), buffer: []u8) Tap {
        return .{
            .in = in,
            .gpa = gpa,
            .log = log,
            .reader = .{
                .vtable = &.{
                    .stream = Tap.streamFn,
                    .readVec = Tap.readVecFn,
                    .discard = Tap.discardFn,
                },
                .buffer = buffer,
                .end = 0,
                .seek = 0,
            },
        };
    }

    fn record(t: *Tap, bytes: []const u8) void {
        t.log.appendSlice(t.gpa, bytes) catch @panic("OOM recording the interop capture");
    }

    fn streamFn(r: *Reader, w: *Writer, limit: std.Io.Limit) Reader.StreamError!usize {
        const t: *Tap = @alignCast(@fieldParentPtr("reader", r));
        const data = limit.slice(try w.writableSliceGreedy(1));
        var vec: [1][]u8 = .{data};
        const n = try t.in.readVec(&vec);
        t.record(data[0..n]);
        w.advance(n);
        return n;
    }

    fn readVecFn(r: *Reader, data: [][]u8) Reader.Error!usize {
        const t: *Tap = @alignCast(@fieldParentPtr("reader", r));
        var vecs: [8][]u8 = undefined;
        const dest_n, const data_size = try r.writableVector(&vecs, data);
        const dest = vecs[0..dest_n];
        const n = try t.in.readVec(dest);
        var remaining: usize = n;
        for (dest) |slice| {
            if (remaining < slice.len) {
                t.record(slice[0..remaining]);
                remaining = 0;
                break;
            } else {
                remaining -= slice.len;
                t.record(slice);
            }
        }
        std.debug.assert(remaining == 0);
        if (n > data_size) {
            r.end += n - data_size;
            return data_size;
        }
        return n;
    }

    fn discardFn(r: *Reader, limit: std.Io.Limit) Reader.Error!usize {
        const t: *Tap = @alignCast(@fieldParentPtr("reader", r));
        const peeked = limit.slice(try t.in.peekGreedy(1));
        t.record(peeked);
        t.in.toss(peeked.len);
        return peeked.len;
    }
};

// ── watchdog ────────────────────────────────────────────────────────────────

/// Mis-framing against a real peer does not fail, it **hangs** — the peer
/// believes a bogus length and waits. The forward direction's own history:
/// a fault-injected little-endian length-prefix flip ran 10 minutes before an
/// external `timeout` had to SIGTERM the suite. Every live span here is
/// bracketed by this.
const watchdog_ms: u64 = 60_000;
const watchdog_exit_code: u8 = 94;

const Watchdog = struct {
    stop: std.atomic.Value(bool) = .init(false),
    thread: ?std.Thread = null,
    what: []const u8 = "",

    fn arm(w: *Watchdog, what: []const u8) void {
        w.stop = .init(false);
        w.what = what;
        w.thread = std.Thread.spawn(.{}, run, .{w}) catch |err| {
            note("could not arm the interop watchdog ({t}) — refusing to run unguarded", .{err});
            std.process.exit(1);
        };
    }

    fn disarm(w: *Watchdog) void {
        w.stop.store(true, .release);
        if (w.thread) |t| t.join();
        w.thread = null;
    }

    fn run(w: *Watchdog) void {
        const poll_ms: u64 = 50;
        var waited: u64 = 0;
        while (waited < watchdog_ms) : (waited += poll_ms) {
            if (w.stop.load(.acquire)) return;
            var ts: std.posix.timespec = .{
                .sec = @intCast(poll_ms / 1000),
                .nsec = @intCast((poll_ms % 1000) * 1_000_000),
            };
            _ = std.os.linux.nanosleep(&ts, null);
        }
        if (w.stop.load(.acquire)) return;
        std.debug.print(
            "\nINTEROP WATCHDOG FIRED during `{s}`: ran past {d} ms without finishing — " ++
                "a framing regression HANGS rather than failing. Exiting {d}.\n",
            .{ w.what, watchdog_ms, watchdog_exit_code },
        );
        std.process.exit(watchdog_exit_code);
    }
};

// ── environment ─────────────────────────────────────────────────────────────

var environ: std.process.Environ = .empty;

fn getEnv(name: []const u8) ?[]const u8 {
    return std.process.Environ.getPosix(environ, name);
}

/// `$GRPC_PYTHON` if set, else this repository's grpcio virtualenv, else a
/// bare `python3`. `buf` backs the middle case.
fn interpreter(io: std.Io, buf: []u8) []const u8 {
    if (getEnv("GRPC_PYTHON")) |p| {
        if (p.len != 0) return p;
    }
    if (getEnv("HOME")) |home| {
        const path = std.fmt.bufPrint(buf, "{s}/.cache/zig-libs-grpc/bin/python", .{home}) catch return "python3";
        std.Io.Dir.cwd().access(io, path, .{}) catch return "python3";
        return path;
    }
    return "python3";
}

/// ⚠ THIS MUST NAME EVERYTHING THE REFERENCE SCRIPTS IMPORT, not just the one
/// the module is named after. It checked `grpc` alone until 2026-08-15, and
/// both scripts also import `google.protobuf` — so on an interpreter carrying
/// grpcio without protobuf the gate said "peer available" and the run died on
/// `ModuleNotFoundError: No module named 'google'`.
fn requireGrpcio(io: std.Io, python: []const u8) void {
    var child = std.process.spawn(io, .{
        .argv = &.{ python, "-c", "import grpc, google.protobuf" },
        .stdin = .close,
        .stdout = .ignore,
        .stderr = .ignore,
    }) catch peerMissing("no python interpreter at `{s}`", .{python});
    const term = child.wait(io) catch peerMissing("`{s}` could not be waited on", .{python});
    switch (term) {
        .exited => |code| if (code != 0)
            peerMissing("`{s}` lacks `grpcio` or `protobuf` — both scripts import both", .{python}),
        else => peerMissing("`{s}` terminated abnormally", .{python}),
    }
}

/// grpcio's own version string, for the fixture header. A capture whose
/// provenance is not written down is a capture nobody can re-derive.
fn grpcioVersion(gpa: Allocator, io: std.Io, python: []const u8) ![]u8 {
    var child = try std.process.spawn(io, .{
        .argv = &.{ python, "-c", "import grpc,sys,google.protobuf as p;sys.stdout.write(grpc.__version__+' / protobuf '+p.__version__)" },
        .stdin = .close,
        .stdout = .pipe,
        .stderr = .ignore,
    });
    var buf: [256]u8 = undefined;
    var r = child.stdout.?.reader(io, &buf);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    r.interface.appendRemaining(gpa, &out, .limited(1024)) catch {};
    _ = child.wait(io) catch {};
    return out.toOwnedSlice(gpa);
}

// ── the forward direction: our client against the reference server ─────────

/// One live conversation: a fresh grpcio server on its own port, a fresh h2c
/// connection to it, and a tap recording every byte that came back.
///
/// Each case gets its own `Session` on purpose. Stream ids restart at 1 and
/// the response HPACK dynamic table starts empty, so what the tap records is
/// replayable from byte zero — a shared connection would make every case
/// after the first depend on the exact order the others ran in.
const Session = struct {
    gpa: Allocator,
    io: std.Io,
    child: std.process.Child,
    stream: net.Stream,
    sr: net.Stream.Reader,
    sw: net.Stream.Writer,
    tap: Tap,
    hs: *http.Client.H2Session,
    ch: grpc.Channel,
    log: std.ArrayList(u8),
    wd: Watchdog,
    path_buf: [512]u8 = undefined,
    read_buf: [64 * 1024]u8 = undefined,
    write_buf: [64 * 1024]u8 = undefined,
    tap_buf: [64 * 1024]u8 = undefined,

    fn start(cfg: Config, name: []const u8, options: grpc.Options) !*Session {
        const gpa = cfg.gpa;
        const io = cfg.io;
        const s = try gpa.create(Session);
        errdefer gpa.destroy(s);
        s.gpa = gpa;
        s.io = io;
        s.log = .empty;
        s.wd = .{};

        var script_buf: [1024]u8 = undefined;
        const script = try std.fmt.bufPrint(&script_buf, "{s}/reference_server.py", .{cfg.tools_dir});
        std.Io.Dir.cwd().access(io, script, .{}) catch
            peerMissing("cannot find `{s}` — set $GRPC_TOOLS_DIR", .{script});

        const python = interpreter(io, &s.path_buf);
        s.child = std.process.spawn(io, .{
            .argv = &.{ python, script },
            .stdin = .close,
            .stdout = .pipe,
            .stderr = .ignore,
        }) catch peerMissing("could not spawn the grpcio reference server", .{});
        errdefer s.child.kill(io);

        s.wd.arm(name);
        errdefer s.wd.disarm();

        // The server prints `PORT <n>` after bind()+start(), so anything we
        // connect afterwards is guaranteed to find a listening socket.
        var line_buf: [128]u8 = undefined;
        var stdout_reader = s.child.stdout.?.reader(io, &line_buf);
        const raw = stdout_reader.interface.takeDelimiterInclusive('\n') catch
            peerMissing("the grpcio reference server never printed its port", .{});
        const line = std.mem.trimEnd(u8, raw, "\n");
        if (!std.mem.startsWith(u8, line, "PORT "))
            peerMissing("unexpected greeting from the reference server: `{s}`", .{line});
        const port = try std.fmt.parseInt(u16, line["PORT ".len..], 10);

        const addr: net.IpAddress = try .parse("127.0.0.1", port);
        s.stream = try addr.connect(io, .{ .mode = .stream });
        errdefer s.stream.close(io);

        s.sr = s.stream.reader(io, &s.read_buf);
        s.sw = s.stream.writer(io, &s.write_buf);
        s.tap = Tap.init(&s.sr.interface, gpa, &s.log, &s.tap_buf);
        s.hs = try http.Client.connectH2Over(gpa, &s.tap.reader, &s.sw.interface, "127.0.0.1", .{});
        s.ch = grpc.Channel.overH2Session(s.hs, options);
        return s;
    }

    fn deinit(s: *Session) void {
        s.hs.close();
        s.stream.close(s.io);
        s.wd.disarm();
        s.child.kill(s.io);
        s.log.deinit(s.gpa);
        const gpa = s.gpa;
        gpa.destroy(s);
    }

    /// Hand the recording over; the session no longer owns it.
    fn takeLog(s: *Session) []u8 {
        return s.log.toOwnedSlice(s.gpa) catch @panic("OOM");
    }
};

const Config = struct {
    gpa: Allocator,
    io: std.Io,
    tools_dir: []const u8,
    testdata_dir: []const u8,
    capture: bool,
};

const Capture = struct { name: []const u8, bytes: []u8 };

var captures: std.ArrayList(Capture) = .empty;

fn keep(cfg: Config, name: []const u8, bytes: []u8) void {
    if (!cfg.capture) {
        cfg.gpa.free(bytes);
        return;
    }
    captures.append(cfg.gpa, .{ .name = name, .bytes = bytes }) catch @panic("OOM");
}

fn forward(cfg: Config) !void {
    const gpa = cfg.gpa;

    // ── 1. unary ────────────────────────────────────────────────────────────
    {
        const s = try Session.start(cfg, "unary", .{});
        defer s.deinit();
        var reply = try grpc.unary(EchoRequest, EchoReply, &s.ch, "/echo.Echo/Unary", .{
            .text = "hello reference",
            .count = 7,
            .blob = &.{ 0x00, 0xff, 0x10 },
        }, .{});
        defer reply.deinit();
        expectStr("unary", "text", reply.value.text, "echo:hello reference");
        expectInt("unary", "index", reply.value.index, 7);
        expectStr("unary", "blob", reply.value.blob, &.{ 0x00, 0xff, 0x10 });
        keep(cfg, "unary", s.takeLog());
    }

    // ── 2. server-streaming ─────────────────────────────────────────────────
    {
        const s = try Session.start(cfg, "server_stream", .{});
        defer s.deinit();
        var st = try Echo.start(&s.ch, "/echo.Echo/ServerStream", .{});
        defer st.deinit();
        try st.sendEnd(.{ .text = "tick", .count = 5 });
        var seen: i32 = 0;
        while (try st.receive()) |*r| {
            defer @constCast(r).deinit();
            var name_buf: [32]u8 = undefined;
            const want = try std.fmt.bufPrint(&name_buf, "tick-{d}", .{seen});
            expectStr("server_stream", "text", r.value.text, want);
            expectInt("server_stream", "index", r.value.index, seen);
            seen += 1;
        }
        expectInt("server_stream", "count", seen, 5);
        try st.finish();
        keep(cfg, "server_stream", s.takeLog());
    }

    // ── 3. client-streaming ─────────────────────────────────────────────────
    {
        const s = try Session.start(cfg, "client_stream", .{});
        defer s.deinit();
        var st = try Echo.start(&s.ch, "/echo.Echo/ClientStream", .{});
        defer st.deinit();
        try st.send(.{ .text = "a" });
        try st.send(.{ .text = "bb" });
        try st.send(.{ .text = "ccc" });
        try st.closeSend();
        var reply = (try st.receive()).?;
        defer reply.deinit();
        expectStr("client_stream", "text", reply.value.text, "a|bb|ccc");
        expectInt("client_stream", "index", reply.value.index, 3);
        expectTrue("client_stream", "eos", (try st.receive()) == null);
        try st.finish();
        keep(cfg, "client_stream", s.takeLog());
    }

    // ── 4. bidirectional, genuinely interleaved ─────────────────────────────
    {
        const s = try Session.start(cfg, "bidi", .{});
        defer s.deinit();
        var st = try Echo.start(&s.ch, "/echo.Echo/Bidi", .{});
        defer st.deinit();
        // Each reply is read before the next request is written, so the
        // request half is still open while the response half is producing —
        // the thing only a bidirectional stream can do.
        const words = [_][]const u8{ "one", "two", "three" };
        for (words, 0..) |w, i| {
            try st.send(.{ .text = w });
            var r = (try st.receive()).?;
            defer r.deinit();
            var buf: [32]u8 = undefined;
            expectStr("bidi", "text", r.value.text, try std.fmt.bufPrint(&buf, "re:{s}", .{w}));
            expectInt("bidi", "index", r.value.index, @as(i32, @intCast(i)));
        }
        try st.closeSend();
        expectTrue("bidi", "eos", (try st.receive()) == null);
        try st.finish();
        keep(cfg, "bidi", s.takeLog());
    }

    // ── 5. an error before any message: a real Trailers-Only response ───────
    {
        const s = try Session.start(cfg, "fail", .{});
        defer s.deinit();
        // Bytes the grpc-message ABNF forbids, so the percent-decoding is
        // exercised against the reference's encoder rather than our own.
        const detail = "boom\nline two \xe2\x98\x83 100% done";
        var failure: grpc.Failure = .{};
        defer failure.deinit(gpa);
        const err = grpc.unary(EchoRequest, EchoReply, &s.ch, "/echo.Echo/Fail", .{
            .text = detail,
            .count = @intFromEnum(grpc.Status.permission_denied),
        }, .{ .failure = &failure });
        expectTrue("fail", "error", err == error.PermissionDenied);
        expectTrue("fail", "status", failure.status == .permission_denied);
        expectStr("fail", "message", failure.message, detail);
        keep(cfg, "fail", s.takeLog());
    }

    // ── 6. …and that response has no trailer section at all ─────────────────
    {
        const s = try Session.start(cfg, "trailers_only", .{});
        defer s.deinit();
        var call = try s.ch.start("/echo.Echo/Fail", .{});
        defer call.deinit();
        const req = try pb.encodeAlloc(gpa, EchoRequest{
            .text = "nope",
            .count = @intFromEnum(grpc.Status.not_found),
        }, .{});
        defer gpa.free(req);
        try call.sendMessage(req, true);
        expectTrue("trailers_only", "no_body", (try call.receive()) == null);
        expectTrue("trailers_only", "flag", call.trailers_only);
        expectTrue("trailers_only", "no_trailers", call.trailingMetadata() == null);
        expectTrue("trailers_only", "has_initial", call.initialMetadata().?.fields.len != 0);
        expectTrue("trailers_only", "error", call.finish() == error.NotFound);
        expectTrue("trailers_only", "status", call.status.? == .not_found);
        expectStr("trailers_only", "message", call.statusMessage(), "nope");
        keep(cfg, "trailers_only", s.takeLog());
    }

    // ── 7. messages, then a non-OK status in a real trailer section ─────────
    {
        const s = try Session.start(cfg, "stream_fail", .{});
        defer s.deinit();
        var st = try Echo.start(&s.ch, "/echo.Echo/StreamFail", .{});
        defer st.deinit();
        try st.sendEnd(.{ .text = "x", .count = 3 });
        var seen: usize = 0;
        while (try st.receive()) |*r| {
            @constCast(r).deinit();
            seen += 1;
        }
        expectInt("stream_fail", "count", seen, 3);
        expectTrue("stream_fail", "not_trailers_only", !st.call.trailers_only);
        expectTrue("stream_fail", "has_trailers", st.call.trailingMetadata() != null);
        expectTrue("stream_fail", "error", st.finish() == error.DataLoss);
        expectStr("stream_fail", "message", st.call.statusMessage(), "gave up after 3");
        keep(cfg, "stream_fail", s.takeLog());
    }

    // ── 8/9. a large reply, under and over the receive limit ────────────────
    //
    // ONE recording serves both arms. The reference's output does not depend
    // on our client's `max_recv_message_size` — that is a purely local
    // refusal — so the honest capture is the *complete* 256 KiB reply, which
    // the replay then feeds to a 1 MiB client (reassembly) and to a 64 KiB
    // client (RESOURCE_EXHAUSTED). Recording the over-limit arm separately
    // would record a truncated stream, because that client stops reading.
    {
        const s = try Session.start(cfg, "big", .{ .max_recv_message_size = 1024 * 1024 });
        defer s.deinit();
        // 256 KiB is many times the peer's 16 KiB default frame size and far
        // past the 64 KiB initial flow-control window, so this one message
        // provably arrives split across a long run of DATA frames — and the
        // deframer has to put it back together to the byte.
        const want: i32 = 256 * 1024;
        var reply = try grpc.unary(EchoRequest, EchoReply, &s.ch, "/echo.Echo/Big", .{
            .count = want,
        }, .{});
        defer reply.deinit();
        expectStr("big", "text", reply.value.text, "big");
        expectInt("big", "index", reply.value.index, want);
        expectInt("big", "blob_len", reply.value.blob.len, @as(usize, @intCast(want)));
        var all_5a = true;
        for (reply.value.blob) |b| {
            if (b != 0x5a) all_5a = false;
        }
        expectTrue("big", "all_5a", all_5a);
        keep(cfg, "big", s.takeLog());
    }
    {
        // The over-limit arm, live. (The replay runs it off the `big`
        // recording above.)
        const s = try Session.start(cfg, "big_over_limit", .{ .max_recv_message_size = 64 * 1024 });
        defer s.deinit();
        var failure: grpc.Failure = .{};
        defer failure.deinit(gpa);
        const err = grpc.unary(EchoRequest, EchoReply, &s.ch, "/echo.Echo/Big", .{
            .count = 256 * 1024,
        }, .{ .failure = &failure });
        expectTrue("big_over_limit", "error", err == error.ResourceExhausted);
        expectTrue("big_over_limit", "status", failure.status == .resource_exhausted);
        gpa.free(s.takeLog()); // not part of the fixture — see above
    }

    // ── 10. metadata, both sections, ASCII and -bin ─────────────────────────
    {
        const s = try Session.start(cfg, "metadata", .{});
        defer s.deinit();
        // Bytes no ASCII header could carry — that is the whole reason `-bin`
        // exists, so the probe has to actually contain them.
        const raw = [_]u8{ 0x00, 0x01, 0xfe, 0xff, 0x0a, 0x25 };
        var call = try s.ch.start("/echo.Echo/Meta", .{ .metadata = &.{
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
        expectStr("metadata", "body_text", decoded.value.text, "probe-value");
        expectStr("metadata", "body_blob", decoded.value.blob, &raw);
        expectStr("metadata", "initial_ascii", call.metadataValue("x-echo").?, "probe-value");
        const echoed = (try call.metadataValueDecoded("x-echo-bin")).?;
        defer echoed.deinit(gpa);
        expectStr("metadata", "initial_bin", echoed.bytes, &raw);
        expectTrue("metadata", "eos", (try call.receive()) == null);
        expectStr("metadata", "trailing_ascii", call.metadataValue("x-tail").?, "probe-value");
        const tail = (try call.metadataValueDecoded("x-tail-bin")).?;
        defer tail.deinit(gpa);
        expectStr("metadata", "trailing_bin", tail.bytes, &raw);
        try call.finish();
        keep(cfg, "metadata", s.takeLog());
    }

    // ── 11. grpc-timeout is understood by the reference server ──────────────
    //
    // Three calls, and deliberately three CONNECTIONS. A recording of several
    // sequential calls on one connection cannot be replayed against a client
    // that opens its streams one at a time: the recording holds the answers to
    // streams 3 and 5 already, and a replaying client reading ahead sees
    // HEADERS for a stream it has not opened yet — a connection PROTOCOL_ERROR
    // (§5.1.1), correctly raised, about an artefact of replay rather than
    // about grpcio. Several calls sharing one connection keep their coverage
    // in `multiplex`, where they are opened before any is read.
    {
        const s = try Session.start(cfg, "deadline_none", .{});
        defer s.deinit();
        // No deadline: the reference reports -1.
        var none = try grpc.unary(EchoRequest, EchoReply, &s.ch, "/echo.Echo/Deadline", .{}, .{});
        defer none.deinit();
        expectInt("deadline_none", "index", none.value.index, -1);
        keep(cfg, "deadline_none", s.takeLog());
    }
    {
        // 30 s: the reference sees a deadline in the 29–30 s band, which only
        // happens if it parsed our `grpc-timeout` value AND our unit.
        const s = try Session.start(cfg, "deadline_seconds", .{});
        defer s.deinit();
        var some = try grpc.unary(EchoRequest, EchoReply, &s.ch, "/echo.Echo/Deadline", .{}, .{
            .timeout = .{ .value = 30, .unit = .seconds },
        });
        defer some.deinit();
        expectTrue("deadline_seconds", "band", some.value.index >= 29_000 and some.value.index <= 30_000);
        keep(cfg, "deadline_seconds", s.takeLog());
    }
    {
        // The same duration in milliseconds must land in the same band — a
        // unit we render but the peer reads differently shows up here.
        const s = try Session.start(cfg, "deadline_millis", .{});
        defer s.deinit();
        var ms = try grpc.unary(EchoRequest, EchoReply, &s.ch, "/echo.Echo/Deadline", .{}, .{
            .timeout = grpc.Timeout.fromMillis(30_000),
        });
        defer ms.deinit();
        expectTrue("deadline_millis", "band", ms.value.index >= 29_000 and ms.value.index <= 30_000);
        keep(cfg, "deadline_millis", s.takeLog());
    }

    // ── 12. several calls multiplexed on one HTTP/2 connection ──────────────
    {
        const s = try Session.start(cfg, "multiplex", .{});
        defer s.deinit();
        var a = try Echo.start(&s.ch, "/echo.Echo/Unary", .{});
        defer a.deinit();
        var b = try Echo.start(&s.ch, "/echo.Echo/ServerStream", .{});
        defer b.deinit();
        var c = try Echo.start(&s.ch, "/echo.Echo/Unary", .{});
        defer c.deinit();

        try a.sendEnd(.{ .text = "A" });
        try b.sendEnd(.{ .text = "B", .count = 2 });
        try c.sendEnd(.{ .text = "C" });

        // Collected out of order — the demultiplexing underneath is the h2
        // client's, exercised here against a third-party server.
        var rc = (try c.receive()).?;
        defer rc.deinit();
        expectStr("multiplex", "c", rc.value.text, "echo:C");

        var seen: usize = 0;
        while (try b.receive()) |*r| {
            @constCast(r).deinit();
            seen += 1;
        }
        expectInt("multiplex", "b_count", seen, 2);

        var ra = (try a.receive()).?;
        defer ra.deinit();
        expectStr("multiplex", "a", ra.value.text, "echo:A");

        try a.finish();
        try b.finish();
        try c.finish();
        keep(cfg, "multiplex", s.takeLog());
    }
}

// ── the reverse direction: the reference client against our server ─────────

/// The same `echo.Echo` contract `reference_server.py` implements, served by
/// us this time — so the reference client's expectations are unchanged and
/// only the producer of the bytes has swapped sides.
fn srvUnary(c: *grpc.ServerCall, req: EchoRequest) anyerror!EchoReply {
    return .{
        .text = try std.fmt.allocPrint(c.arena, "echo:{s}", .{req.text}),
        .index = req.count,
        .blob = req.blob,
    };
}

const M = grpc.Methods(EchoRequest, EchoReply);

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
fn srvFail(c: *grpc.ServerCall, req: EchoRequest) anyerror!EchoReply {
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

fn srvBig(c: *grpc.ServerCall, req: EchoRequest) anyerror!EchoReply {
    const n: usize = @intCast(@max(0, req.count));
    const blob = try c.arena.alloc(u8, n);
    @memset(blob, 0x5a);
    return .{ .text = "big", .index = req.count, .blob = blob };
}

fn srvMeta(c: *grpc.ServerCall, req: EchoRequest) anyerror!EchoReply {
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
fn srvDeadline(c: *grpc.ServerCall, req: EchoRequest) anyerror!EchoReply {
    _ = req;
    // `text` carries the reference's own `grpc-timeout` rendering back, so a
    // band that comes out wrong says *why* rather than just failing.
    const raw = c.metadataValue("grpc-timeout") orelse "none";
    const ns = c.remaining() orelse return .{ .text = raw, .index = -1 };
    const in_band = ns > 29 * std.time.ns_per_s and ns <= 31 * std.time.ns_per_s;
    return .{ .text = raw, .index = if (in_band) 1 else 2 };
}

/// Shared with `src/reference_replay.zig` through duplication, deliberately:
/// the module's replay must not import anything from `tools/`, and this list
/// changing on one side without the other is exactly what the reverse-capture
/// header's `service` line records.
pub const interop_service: grpc.Service = .{
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

/// Every `KEY\tVALUE` line the reference client printed.
const Report = struct {
    gpa: Allocator,
    text: []u8,

    fn get(r: Report, key: []const u8) ?[]const u8 {
        var it = std.mem.splitScalar(u8, r.text, '\n');
        while (it.next()) |line| {
            const tab = std.mem.indexOfScalar(u8, line, '\t') orelse continue;
            if (std.mem.eql(u8, line[0..tab], key)) return line[tab + 1 ..];
        }
        return null;
    }

    fn expect(r: Report, key: []const u8, want: []const u8) void {
        comparisons += 1;
        const got = r.get(key) orelse {
            failures += 1;
            note("reverse: reference client never reported `{s}`", .{key});
            return;
        };
        if (!std.mem.eql(u8, got, want)) {
            failures += 1;
            note("DIVERGENCE reverse.{s}: reference read `{s}`, expected `{s}`", .{ key, got, want });
        }
    }

    /// Like `expect`, but for a raw `grpc-timeout` header rendering: checks
    /// the *shape* (decimal digits followed by one of grpc's timeout unit
    /// letters) rather than one exact literal.
    ///
    /// grpcio's C-core chooses both the quantization and the unit from the
    /// wall-clock gap between "the deadline was set" and "the request was
    /// actually framed onto the wire", so the same 30 s call can legitimately
    /// render as `30100m` on one run and `30S` on another. Pinning the
    /// literal makes the check flaky for a reason that has nothing to do with
    /// this module. What must never vary is that a well-formed value arrived;
    /// whether it was parsed correctly is `deadline.band`'s job.
    fn expectTimeoutShape(r: Report, key: []const u8) void {
        comparisons += 1;
        const got = r.get(key) orelse {
            failures += 1;
            note("reverse: reference client never reported `{s}`", .{key});
            return;
        };
        const valid = got.len >= 2 and switch (got[got.len - 1]) {
            'H', 'M', 'S', 'm', 'u', 'n' => std.mem.indexOfNone(u8, got[0 .. got.len - 1], "0123456789") == null,
            else => false,
        };
        if (!valid) {
            failures += 1;
            note("DIVERGENCE reverse.{s}: `{s}` is not a well-formed grpc-timeout value", .{ key, got });
        }
    }

    fn deinit(r: Report) void {
        r.gpa.free(r.text);
    }
};

/// State the serving thread needs; the h2 codec runs on it, the main thread
/// waits for the child.
const ServeCtx = struct {
    gpa: Allocator,
    io: std.Io,
    listener: *net.Server,
    log: *std.ArrayList(u8),
    /// Set once the connection is done, so the main thread knows the
    /// recording is complete.
    done: std.atomic.Value(bool) = .init(false),
    read_buf: [64 * 1024]u8 = undefined,
    write_buf: [64 * 1024]u8 = undefined,
    tap_buf: [64 * 1024]u8 = undefined,
};

/// Accept exactly one connection and serve HTTP/2 on it, taping every byte
/// the reference client sent.
///
/// Deliberately `h2_server.serve` over the raw socket rather than
/// `http.Server`: `serve` is the SAME entry point `src/reference_replay.zig`
/// drives over a fixed reader, so the capture and the replay differ in one
/// thing only — where the bytes come from.
fn serveOnce(ctx: *ServeCtx) void {
    const io = ctx.io;
    const stream = ctx.listener.accept(io) catch |err| {
        note("reverse: accept failed: {t}", .{err});
        ctx.done.store(true, .release);
        return;
    };
    defer stream.close(io);
    var sr = stream.reader(io, &ctx.read_buf);
    var sw = stream.writer(io, &ctx.write_buf);
    var tap = Tap.init(&sr.interface, ctx.gpa, ctx.log, &ctx.tap_buf);

    var router: grpc.Router = .{
        .gpa = ctx.gpa,
        .services = &.{interop_service},
        // Deliberately below the oversized request the client sends, and
        // above everything else it sends.
        .options = .{ .max_recv_message_size = 64 * 1024 },
    };
    http.h2_server.serve(ctx.gpa, router.h2ServerOptions(.{
        .handler = grpc.handleHttp,
        .max_body_bytes = 8 << 20,
    }), &tap.reader, &sw.interface);
    ctx.done.store(true, .release);
}

fn reverse(cfg: Config) !void {
    const gpa = cfg.gpa;
    const io = cfg.io;

    var script_buf: [1024]u8 = undefined;
    const script = try std.fmt.bufPrint(&script_buf, "{s}/reference_client.py", .{cfg.tools_dir});
    std.Io.Dir.cwd().access(io, script, .{}) catch
        peerMissing("cannot find `{s}` — set $GRPC_TOOLS_DIR", .{script});

    var path_buf: [512]u8 = undefined;
    const python = interpreter(io, &path_buf);

    const bind_addr: net.IpAddress = try .parse("127.0.0.1", 0);
    var listener = try bind_addr.listen(io, .{});
    defer listener.deinit(io);
    const port = listener.socket.address.getPort();

    var log: std.ArrayList(u8) = .empty;
    errdefer log.deinit(gpa);

    const ctx = try gpa.create(ServeCtx);
    defer gpa.destroy(ctx);
    ctx.* = .{ .gpa = gpa, .io = io, .listener = &listener, .log = &log };

    var wd: Watchdog = .{};
    wd.arm("reverse direction");
    defer wd.disarm();

    const th = try std.Thread.spawn(.{}, serveOnce, .{ctx});

    var port_buf: [16]u8 = undefined;
    const port_str = try std.fmt.bufPrint(&port_buf, "{d}", .{port});

    var child = std.process.spawn(io, .{
        .argv = &.{ python, script, port_str },
        .stdin = .close,
        .stdout = .pipe,
        .stderr = .pipe,
    }) catch peerMissing("could not spawn the grpcio reference client", .{});

    // Read stdout to EOF. The child cannot outlive its own watchdog, so this
    // read terminates even if our framing wedges the RPC — which is the
    // point: a framing bug against a real peer HANGS rather than failing.
    var out_buf: [4096]u8 = undefined;
    var out_reader = child.stdout.?.reader(io, &out_buf);
    var collected: std.ArrayList(u8) = .empty;
    errdefer collected.deinit(gpa);
    out_reader.interface.appendRemaining(gpa, &collected, .unlimited) catch {};

    var err_buf: [8192]u8 = undefined;
    var err_reader = child.stderr.?.reader(io, &err_buf);
    var stderr_text: std.ArrayList(u8) = .empty;
    defer stderr_text.deinit(gpa);
    err_reader.interface.appendRemaining(gpa, &stderr_text, .limited(256 * 1024)) catch {};

    const term = child.wait(io) catch peerMissing("the reference client could not be waited on", .{});
    th.join();

    const text = try collected.toOwnedSlice(gpa);
    const report: Report = .{ .gpa = gpa, .text = text };
    defer report.deinit();

    switch (term) {
        .exited => |code| if (code != 0) {
            failures += 1;
            note("reference client exited {d}\nstdout:\n{s}\nstderr:\n{s}", .{ code, text, stderr_text.items });
            return;
        },
        else => {
            failures += 1;
            note("reference client terminated abnormally\nstderr:\n{s}", .{stderr_text.items});
            return;
        },
    }

    // The script ran to the end; nothing timed out.
    report.expect("DONE", "1");

    report.expect("unary.text", "echo:hello reference");
    report.expect("unary.index", "7");
    report.expect("unary.blob", "00ff10");
    report.expect("unary.code", "OK");

    report.expect("serverstream.texts", "tick-0,tick-1,tick-2,tick-3,tick-4");
    report.expect("serverstream.code", "OK");

    report.expect("clientstream.text", "a|bb|ccc");
    report.expect("clientstream.index", "3");
    report.expect("clientstream.code", "OK");

    report.expect("bidi.texts", "re:one,re:two,re:three");

    report.expect("fail.code", "PERMISSION_DENIED");
    // The message contained a newline, a multi-byte UTF-8 sequence and a
    // literal '%' — every class of byte the grpc-message ABNF forbids. The
    // reference's percent-decoder reproduced it exactly, which is what says
    // our ENcoder is right.
    report.expect("fail.details_match", "1");
    // …and the trailing metadata that rode in the same single field block.
    report.expect("fail.x_why", "because");

    report.expect("streamfail.count", "3");
    report.expect("streamfail.code", "DATA_LOSS");
    report.expect("streamfail.details", "gave up after 3");

    report.expect("unknown.code", "UNIMPLEMENTED");
    report.expect("unknown.details", "unknown method NoSuchMethod for service echo.Echo");

    report.expect("meta.body_text", "probe-value");
    report.expect("meta.body_blob", "0001feff0a25");
    report.expect("meta.initial_ascii", "probe-value");
    report.expect("meta.initial_bin", "0001feff0a25");
    report.expect("meta.trailing_ascii", "probe-value");
    report.expect("meta.trailing_bin", "0001feff0a25");
    // The reference reports the tail fields as TRAILING and not as initial:
    // the two sections are really two field blocks on the wire, not one.
    report.expect("meta.tail_not_initial", "1");

    report.expectTimeoutShape("deadline.raw");
    report.expect("deadline.band", "1");
    report.expect("deadline.none", "-1");

    report.expect("big.len", "49152");
    report.expect("big.all_5a", "1");

    report.expect("toolarge.code", "RESOURCE_EXHAUSTED");

    report.expect("empty.count", "0");
    report.expect("empty.code", "OK");

    if (cfg.capture) {
        keep(cfg, "reverse_client", try log.toOwnedSlice(gpa));
        // The report is part of the fixture: the replay asserts our server's
        // decoded output against what the REFERENCE read off the wire, so the
        // hermetic expectations keep grpcio as their provenance instead of
        // becoming numbers someone typed.
        keep(cfg, "reverse_report", try gpa.dupe(u8, text));
    } else {
        log.deinit(gpa);
    }
}

// ── writing the fixture ─────────────────────────────────────────────────────

/// `YYYY-MM-DD` from the realtime clock (`std.time`'s timestamp helpers are
/// gone in 0.16). Days→civil is Howard Hinnant's algorithm.
fn today(io: std.Io, buf: []u8) []const u8 {
    const ts = std.Io.Timestamp.now(io, .real);
    const secs: i64 = @intCast(@divFloor(ts.nanoseconds, 1_000_000_000));
    var days: i64 = @divFloor(secs, 86400);
    days += 719468;
    const era = @divFloor(days, 146097);
    const doe = days - era * 146097;
    const yoe = @divFloor(doe - @divFloor(doe, 1460) + @divFloor(doe, 36524) - @divFloor(doe, 146096), 365);
    const y = yoe + era * 400;
    const doy = doe - (365 * yoe + @divFloor(yoe, 4) - @divFloor(yoe, 100));
    const mp = @divFloor(5 * doy + 2, 153);
    const d = doy - @divFloor(153 * mp + 2, 5) + 1;
    const m = if (mp < 10) mp + 3 else mp - 9;
    const year: u16 = @intCast(if (m <= 2) y + 1 else y);
    const month: u8 = @intCast(m);
    const day: u8 = @intCast(d);
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}", .{ year, month, day }) catch "unknown";
}

const manifest_prologue =
    \\// SPDX-License-Identifier: MIT
    \\
    \\//! GENERATED — do not hand-edit. Rewritten by
    \\//! `zig build interop-grpc -- --capture` (see `../../tools/interop.zig`).
    \\//!
    \\//! ## What this is
    \\//!
    \\//! A byte-for-byte recording of a conversation with the **reference** gRPC
    \\//! implementation, Python `grpcio` (the stack the gRPC project ships).
    \\//! `../reference_replay.zig` replays it with no child process, no socket
    \\//! and no foreign source, so the anchor's evidence runs on every machine —
    \\//! including one with no `python3` and no `go` anywhere.
    \\//!
    \\//! ## What each recording contains
    \\//!
    \\//! `forward` entries are the bytes the reference **server** put on the wire,
    \\//! taped at the socket by this module's own h2 client. One entry per case,
    \\//! each from its own fresh connection.
    \\//!
    \\//! `reverse_client` is the bytes the reference **client** put on the wire
    \\//! against our server, taped the same way; `reverse_report` is the
    \\//! `KEY\tVALUE` report that same client printed after reading our replies.
    \\//! A server reference and a client reference test opposite directions and
    \\//! both are here.
    \\//!
    \\//! ## What is pinned, and how replay is made deterministic
    \\//!
    \\//! gRPC over HTTP/2 carries several things that differ run to run. None of
    \\//! them is reached by comparing less:
    \\//!
    \\//!   * **Stream ids** — every forward case records its OWN connection, so
    \\//!     ids restart at 1 and the client that replays them opens streams in
    \\//!     the identical order. A shared connection would have made each case
    \\//!     depend on which others ran first.
    \\//!   * **HPACK dynamic-table state** — self-contained in each recording for
    \\//!     the same reason: the field blocks are replayed from the byte the
    \\//!     table was empty at, so every indexed reference resolves.
    \\//!   * **Flow control** — the recording holds the peer's whole side up
    \\//!     front. Our own WINDOW_UPDATEs still go out during replay (into a
    \\//!     discarded writer); the peer's accounting was settled at capture.
    \\//!   * **`grpc-timeout`** — the value grpcio renders is chosen from the
    \\//!     wall-clock gap between "deadline set" and "request framed", so the
    \\//!     same 30 s call is `30100m` on one run and `30S` on another. The
    \\//!     recording pins ONE such rendering and the replay asserts the band it
    \\//!     produced, exactly as the live run does — the literal itself is
    \\//!     grpcio's timing artifact, not this module's behaviour.
    \\//!   * **Timestamps** — gRPC responses carry no `date` header (grpcio does
    \\//!     not send one, and our server's `now` hook is left null), so nothing
    \\//!     in these bytes moves with the clock.
    \\//!
    \\//! ## What replay CANNOT carry, and where that still runs
    \\//!
    \\//! In the forward direction the replay is complete: the reference produced
    \\//! those bytes and our client parses them, which is the whole test.
    \\//!
    \\//! In the reverse direction the replay covers the half that is recordable —
    \\//! grpcio's requests, decoded by our server. Whether grpcio can READ our
    \\//! server's replies cannot be replayed at all (it needs grpcio). What
    \\//! bridges the gap is `reverse_report`: the replay asserts our server's
    \\//! decoded output against the values the reference itself read off the
    \\//! wire, so those expectations keep grpcio as their provenance rather than
    \\//! becoming numbers someone typed. A NEW divergence there is still only
    \\//! findable by `zig build interop-grpc`.
    \\
    \\pub const Case = struct {
    \\    name: []const u8,
    \\    /// The peer's side of one conversation, from byte zero.
    \\    bytes: []const u8,
    \\};
    \\
    \\/// Look one up by name; `null` if the fixture was regenerated without it,
    \\/// which the replay turns into a failing test rather than a silent skip.
    \\pub fn find(name: []const u8) ?Case {
    \\    for (forward) |c| {
    \\        if (@import("std").mem.eql(u8, c.name, name)) return c;
    \\    }
    \\    return null;
    \\}
    \\
    \\
;

fn writeManifest(cfg: Config, version: []const u8, date: []const u8) !void {
    const gpa = cfg.gpa;
    const io = cfg.io;

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    const w = &buf;

    try w.appendSlice(gpa, manifest_prologue);
    try w.print(gpa,
        \\/// The reference implementation this fixture was taken from.
        \\pub const reference = "Python grpcio {s}";
        \\
        \\/// The day it was taken.
        \\pub const captured_on = "{s}";
        \\
        \\/// The exact command that produced it, run from the repository root.
        \\pub const command = "zig build interop-grpc -- --capture";
        \\
        \\/// The service the reverse direction was recorded against. Changing
        \\/// the method set on one side without the other is what this records.
        \\pub const reverse_service = "echo.Echo: Unary ServerStream ClientStream Bidi Fail StreamFail Empty Big Meta Deadline";
        \\
        \\
    , .{ version, date });

    try w.appendSlice(gpa, "/// The reference SERVER's side, one entry per case.\npub const forward = [_]Case{\n");
    for (captures.items) |c| {
        if (std.mem.startsWith(u8, c.name, "reverse")) continue;
        try w.print(gpa, "    .{{ .name = \"{s}\", .bytes = @embedFile(\"grpcio/{s}.bin\") }},\n", .{ c.name, c.name });
    }
    try w.appendSlice(gpa, "};\n\n");

    try w.appendSlice(gpa,
        \\/// The reference CLIENT's side, driving our server: one connection
        \\/// carrying all twelve of its calls.
        \\pub const reverse_client: []const u8 = @embedFile("grpcio/reverse_client.bin");
        \\
        \\/// What that same client printed after reading our server's replies —
        \\/// `KEY\tVALUE` per observation. The replay checks our server's decoded
        \\/// output against these, so the expectations are the reference's
        \\/// readings and not hand-typed constants.
        \\pub const reverse_report: []const u8 = @embedFile("grpcio/reverse_report.txt");
        \\
    );

    var path_buf: [1024]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/grpcio_capture.zig", .{cfg.testdata_dir});
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = buf.items });
    note("wrote {s} ({d} bytes)", .{ path, buf.items.len });
}

fn writeCaptures(cfg: Config) !void {
    const io = cfg.io;
    var dir_buf: [1024]u8 = undefined;
    const dir = try std.fmt.bufPrint(&dir_buf, "{s}/grpcio", .{cfg.testdata_dir});
    try std.Io.Dir.cwd().createDirPath(io, dir);

    for (captures.items) |c| {
        var path_buf: [1024]u8 = undefined;
        const ext = if (std.mem.eql(u8, c.name, "reverse_report")) "txt" else "bin";
        const path = try std.fmt.bufPrint(&path_buf, "{s}/{s}.{s}", .{ dir, c.name, ext });
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = c.bytes });
        note("  {s}  {d} bytes", .{ path, c.bytes.len });
    }
}

// ── main ────────────────────────────────────────────────────────────────────

pub fn main(init: std.process.Init.Minimal) !u8 {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    environ = init.environ;

    var do_forward = true;
    var do_reverse = true;
    var capture = false;
    var args = init.args.iterate();
    _ = args.next(); // argv[0]
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--capture")) {
            capture = true;
        } else if (std.mem.eql(u8, a, "--forward")) {
            do_reverse = false;
        } else if (std.mem.eql(u8, a, "--reverse")) {
            do_forward = false;
        } else if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-h")) {
            note("usage: interop-grpc [--capture] [--forward] [--reverse]", .{});
            return 0;
        } else {
            note("unknown argument `{s}` (try --help)", .{a});
            return 1;
        }
    }
    if (capture and !(do_forward and do_reverse)) {
        note("--capture rewrites the WHOLE fixture, so it needs both directions", .{});
        return 1;
    }

    if (builtin.os.tag != .linux) {
        note("grpc reference interop is exercised on Linux", .{});
        return 2;
    }

    const cfg: Config = .{
        .gpa = gpa,
        .io = io,
        .tools_dir = getEnv("GRPC_TOOLS_DIR") orelse "modules/grpc/tools",
        .testdata_dir = getEnv("GRPC_TESTDATA_DIR") orelse "modules/grpc/src/testdata",
        .capture = capture,
    };
    defer {
        for (captures.items) |c| gpa.free(c.bytes);
        captures.deinit(gpa);
    }

    var path_buf: [512]u8 = undefined;
    const python = interpreter(io, &path_buf);
    requireGrpcio(io, python);
    const version = try grpcioVersion(gpa, io, python);
    defer gpa.free(version);
    note("reference: Python grpcio {s}  (interpreter: {s})", .{ version, python });

    if (do_forward) try forward(cfg);
    if (do_reverse) try reverse(cfg);

    if (capture and failures == 0) {
        var date_buf: [16]u8 = undefined;
        const date = today(io, &date_buf);
        try writeCaptures(cfg);
        try writeManifest(cfg, version, date);
    } else if (capture) {
        note("NOT writing the fixture: the live comparison diverged first", .{});
    }

    note("\n{d} comparisons, {d} divergences", .{ comparisons, failures });
    return if (failures != 0) 1 else 0;
}
