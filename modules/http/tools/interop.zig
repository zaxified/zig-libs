// SPDX-License-Identifier: MIT

//! Live HTTP/2 server conformance against **h2spec** (summerwind/h2spec, MIT):
//! an independent conformance suite that drives a server with crafted frames,
//! one connection per case, and judges its answers against RFC 9113 / RFC 7541.
//!
//! THIS IS A PROGRAM, NOT A TEST. Built and run by `zig build interop-http`,
//! compiled (never run) by `zig build check-interop`, never part of `test-http`.
//!
//! Two phases, each the full suite: the real `Server` with h1 and h2c prior
//! knowledge on one loopback port, then `h2_server.serveStream` alone (the
//! entry point of an ALPN "h2" connection). Exit 0 only when neither phase has
//! a failure outside `shared_port_expected`. It does not skip:
//! a missing h2spec is a failure, because running this program IS the request
//! to consult the suite. Install: `go install github.com/summerwind/h2spec/cmd/h2spec@latest`.
//!
//! A third phase re-takes the Go standard-library oracle (`tools/go_oracle`,
//! replayed by `src/go_oracle.zig`): it runs the generator again and fails
//! when its output differs from the committed `src/go_oracle_vectors.zig` --
//! a newer Go answering differently, or a case table edited without
//! regenerating. Needs `go` on PATH, no network.
//!
//!   zig build interop-http                      # every phase
//!   zig build interop-http -- --h2spec PATH     # a non-default binary
//!   zig build interop-http -- --only http2/6.5  # one section (h2spec's spec ids)
//!   zig build interop-http -- --phase go        # only the Go oracle (or `h2spec`)
//!   zig build interop-http -- --phase problem   # CPython on problem+json (or `sse`:
//!                                               # sseclient-py + httpx-sse); see oracles.zig
//!   zig build interop-http -- --phase sse --write   # re-take the frozen vectors

const std = @import("std");
const http = @import("http");
const oracles = @import("oracles.zig");

const Server = http.Server;
const Writer = std.Io.Writer;

const scratch = ".zig-cache/interop-http";

var body_sink: [64 * 1024]u8 = undefined;

/// What h2spec asks of the server: a 200 with a body for GET, and a POST whose
/// body is read to the end (several cases send DATA and wait for the answer).
fn handler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
    const r = req.reader();
    while (true) {
        var sink: Writer = .fixed(&body_sink);
        _ = r.stream(&sink, .limited(body_sink.len)) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
    }
    try rw.setHeader("Content-Type", "text/plain");
    try rw.writeAll("hello h2spec\n");
}

fn serveWrap(s: *Server) void {
    s.serve() catch |err| std.debug.print("serve ended: {t}\n", .{err});
}

/// The h2-only listener: every connection straight into `h2_server.serveStream`,
/// the entry point an ALPN-negotiated "h2" connection takes, each on its own
/// thread (h2spec may leave a connection open while it starts the next case).
fn h2OnlyLoop(io: std.Io, gpa: std.mem.Allocator, listener: *std.Io.net.Server) void {
    while (true) {
        const stream = listener.accept(io) catch return; // shut down
        const t = std.Thread.spawn(.{}, h2OnlyConn, .{ io, gpa, stream }) catch {
            stream.close(io);
            continue;
        };
        t.detach();
    }
}

fn h2OnlyConn(io: std.Io, gpa: std.mem.Allocator, stream: std.Io.net.Stream) void {
    defer stream.close(io);
    var rbuf: [16 * 1024]u8 = undefined;
    var wbuf: [16 * 1024]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);
    http.h2_server.serveStream(gpa, &sr.interface, &sw.interface, stream.socket.address, .{ .handler = handler });
    sw.interface.flush() catch {};
    // The caller's half of the close (see `Server.lingerClose`): a
    // BYO-transport caller owns it. Bounded like the server's.
    stream.shutdown(io, .send) catch return;
    _ = sr.interface.discard(.limited(64 * 1024)) catch {};
}

const Verdict = struct { tests: usize = 0, failed: std.ArrayList([]const u8) = .empty };

/// Run h2spec against `port`; read its JUnit report back.
fn runH2spec(io: std.Io, gpa: std.mem.Allocator, h2spec: []const u8, port: u16, only: ?[]const u8, report_path: []const u8, arena: std.mem.Allocator) !Verdict {
    var port_buf: [8]u8 = undefined;
    const port_s = try std.fmt.bufPrint(&port_buf, "{d}", .{port});
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(gpa);
    try argv.appendSlice(gpa, &.{ h2spec, "-h", "127.0.0.1", "-p", port_s, "-o", "2", "-j", report_path });
    if (only) |o| try argv.append(gpa, o);
    var child = std.process.spawn(io, .{
        .argv = argv.items,
        .stdin = .close,
        .stdout = .ignore,
        .stderr = .inherit,
    }) catch |e| {
        std.debug.print("could not spawn {s} ({t}) -- the suite is required, not optional\n", .{ h2spec, e });
        return error.NoSuite;
    };
    _ = try child.wait(io); // nonzero on any failure; the report says which

    const xml = try std.Io.Dir.cwd().readFileAlloc(io, report_path, arena, .limited(16 << 20));
    var v: Verdict = .{};
    var it = std.mem.splitSequence(u8, xml, "<testcase ");
    _ = it.next();
    while (it.next()) |case| {
        v.tests += 1;
        const end = std.mem.indexOf(u8, case, "</testcase>") orelse case.len;
        if (std.mem.indexOf(u8, case[0..end], "<failure") == null) continue;
        try v.failed.append(arena, try std.fmt.allocPrint(arena, "{s} {s}", .{ attr(case, "package"), attr(case, "classname") }));
    }
    if (v.tests == 0) return error.EmptyReport;
    return v;
}

fn attr(tag: []const u8, name: []const u8) []const u8 {
    var key_buf: [32]u8 = undefined;
    const key = std.fmt.bufPrint(&key_buf, "{s}=\"", .{name}) catch return "?";
    const at = std.mem.indexOf(u8, tag, key) orelse return "?";
    const rest = tag[at + key.len ..];
    return rest[0 .. std.mem.indexOfScalar(u8, rest, '"') orelse rest.len];
}

/// The one case a shared h1/h2c port cannot pass by design: h2spec's
/// "invalid preface" bytes are a malformed HTTP/1.1 request there, answered
/// 400 like Go's h2c handler does. The h2-only phase holds the h2 engine to it.
const shared_port_expected = "http2/3.5 Sends invalid connection preface";

fn report(phase: []const u8, v: Verdict, allowed: []const []const u8) bool {
    var ok = true;
    for (v.failed.items) |f| {
        const known = for (allowed) |a| {
            if (std.mem.eql(u8, a, f)) break true;
        } else false;
        std.debug.print("  {s} FAIL {s}{s}\n", .{ phase, f, if (known) " (expected on this phase)" else "" });
        if (!known) ok = false;
    }
    std.debug.print("{s}: {d} cases, {d} failed -- {s}\n", .{ phase, v.tests, v.failed.items.len, if (ok) "OK" else "NOT OK" });
    return ok;
}

fn usage() u8 {
    std.debug.print("usage: interop-http [--h2spec PATH] [--only SPEC] [--phase h2spec|go|problem|sse] [--write]\n", .{});
    return 2;
}

const go_oracle_dir = "modules/http/tools/go_oracle";
const go_vectors = "modules/http/src/go_oracle_vectors.zig";

/// Re-take the Go oracle into scratch and compare it with the committed
/// vectors byte for byte.
/// `env` is passed on explicitly: a child spawned without a map gets an
/// empty environment, and `go` needs HOME (or GOCACHE) for its build cache.
fn checkGoOracle(io: std.Io, arena: std.mem.Allocator, env: *const std.process.Environ.Map) !bool {
    const fresh = scratch ++ "/go_oracle_vectors.zig";
    var child = std.process.spawn(io, .{
        // `-out` is relative to the generator's directory, four levels down.
        .argv = &.{ "go", "run", ".", "-out", "../../../../" ++ fresh },
        .cwd = .{ .path = go_oracle_dir },
        .environ_map = env,
        .stdin = .close,
        .stdout = .inherit,
        .stderr = .inherit,
    }) catch |e| {
        std.debug.print("could not spawn go ({t}) -- the oracle is required, not optional\n", .{e});
        return error.NoGo;
    };
    switch (try child.wait(io)) {
        .exited => |code| if (code != 0) {
            std.debug.print("go oracle: generator exited {d}\n", .{code});
            return false;
        },
        else => {
            std.debug.print("go oracle: generator did not exit normally\n", .{});
            return false;
        },
    }
    const cwd = std.Io.Dir.cwd();
    const want = try cwd.readFileAlloc(io, go_vectors, arena, .limited(16 << 20));
    const got = try cwd.readFileAlloc(io, fresh, arena, .limited(16 << 20));
    if (std.mem.eql(u8, want, got)) {
        std.debug.print("go oracle: {s} matches a fresh run -- OK\n", .{go_vectors});
        return true;
    }
    std.debug.print("go oracle: a fresh run differs from {s} -- NOT OK\n" ++
        "  diff {s} {s}; if Go changed, review every changed verdict before copying it over\n", .{ go_vectors, go_vectors, fresh });
    return false;
}

pub fn main(init: std.process.Init.Minimal) !u8 {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var h2spec: []const u8 = "h2spec";
    var only: ?[]const u8 = null;
    var phase: enum { all, h2spec, go, problem, sse } = .all;
    var write = false;
    var args = init.args.iterate();
    _ = args.skip();
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--h2spec")) {
            h2spec = args.next() orelse return usage();
        } else if (std.mem.eql(u8, a, "--only")) {
            only = args.next() orelse return usage();
        } else if (std.mem.eql(u8, a, "--write")) {
            write = true;
        } else if (std.mem.eql(u8, a, "--phase")) {
            const p = args.next() orelse return usage();
            phase = std.meta.stringToEnum(@TypeOf(phase), p) orelse return usage();
        } else {
            std.debug.print("unknown argument '{s}'\n", .{a});
            return usage();
        }
    }
    std.Io.Dir.cwd().createDirPath(io, scratch) catch {};

    const env = try init.environ.createMap(arena);
    if (phase == .problem) return if (try oracles.problemPhase(io, gpa, arena, &env, write)) 0 else 1;
    if (phase == .sse) return if (try oracles.ssePhase(io, gpa, arena, &env, write)) 0 else 1;
    const go_ok = phase == .h2spec or try checkGoOracle(io, arena, &env);
    if (phase == .go) return if (go_ok) 0 else 1;
    const py_ok = phase == .h2spec or (try oracles.problemPhase(io, gpa, arena, &env, false) and
        try oracles.ssePhase(io, gpa, arena, &env, false));

    // Phase 1: the real `Server`, h1 and h2c prior knowledge on one port.
    const shared = blk: {
        var server = Server.init(io, gpa, .{
            .handler = handler,
            .enable_h2c = true,
            .max_body_bytes = 1 << 20,
        });
        defer server.deinit();
        try server.bind();
        const thread = try std.Thread.spawn(.{}, serveWrap, .{&server});
        defer {
            server.shutdown();
            thread.join();
        }
        break :blk try runH2spec(io, gpa, h2spec, server.boundAddress().getPort(), only, scratch ++ "/h2spec-shared.xml", arena);
    };

    // Phase 2: `h2_server.serveStream` alone, as behind TLS + ALPN "h2".
    const h2only = blk: {
        const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
        var listener = try addr.listen(io, .{ .reuse_address = true });
        defer listener.deinit(io);
        const thread = try std.Thread.spawn(.{}, h2OnlyLoop, .{ io, gpa, &listener });
        defer {
            const s: std.Io.net.Stream = .{ .socket = listener.socket };
            s.shutdown(io, .both) catch {};
            thread.join();
        }
        break :blk try runH2spec(io, gpa, h2spec, listener.socket.address.getPort(), only, scratch ++ "/h2spec-h2only.xml", arena);
    };

    const a = report("shared h1/h2c port", shared, &.{shared_port_expected});
    const b = report("h2 only (serveStream)", h2only, &.{});
    return if (a and b and go_ok and py_ok) 0 else 1;
}
