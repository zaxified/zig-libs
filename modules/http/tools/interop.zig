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
//!   zig build interop-http -- --phase alpn      # Client over TLS + ALPN vs Go
//!
//! The `alpn` phase (in every full run) puts `Client` with `Options.http2`
//! against Go's net/http over real TLS (`go_oracle -h2tls`, needs `go`): ALPN
//! must pick h2 where the server offers it and HTTP/1.1 where it does not,
//! and Go's server must see our request exactly as it sees Go's own
//! Transport's, `User-Agent` aside.

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
    std.debug.print("usage: interop-http [--h2spec PATH] [--only SPEC] [--phase h2spec|go|problem|sse|alpn] [--write]\n", .{});
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
    var phase: enum { all, h2spec, go, problem, sse, alpn } = .all;
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

    var env = try init.environ.createMap(arena);
    // The Go oracle is compared byte for byte, so its version is part of the
    // claim: the committed vectors were taken with go1.26.0 and a runner's own
    // Go drifts (tar/zipstream, interop lane 2026-10-07). `go` fetches the
    // pinned toolchain when the installed one differs.
    try env.put("GOTOOLCHAIN", "go1.26.0");
    if (phase == .problem) return if (try oracles.problemPhase(io, gpa, arena, &env, write)) 0 else 1;
    if (phase == .sse) return if (try oracles.ssePhase(io, gpa, arena, &env, write)) 0 else 1;
    if (phase == .alpn) return if (try alpnPhase(io, gpa, arena, &env)) 0 else 1;
    const go_ok = phase == .h2spec or try checkGoOracle(io, arena, &env);
    if (phase == .go) return if (go_ok) 0 else 1;
    const alpn_ok = phase == .h2spec or try alpnPhase(io, gpa, arena, &env);
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
    return if (a and b and go_ok and py_ok and alpn_ok) 0 else 1;
}

// ── phase alpn: Client + Options.http2 against Go over TLS ──────────────────

const Client = http.Client;

fn alpnPhase(io: std.Io, gpa: std.mem.Allocator, arena: std.mem.Allocator, env: *const std.process.Environ.Map) !bool {
    const port_file = scratch ++ "/h2tls-ports";
    const cwd = std.Io.Dir.cwd();
    cwd.deleteFile(io, port_file) catch {};
    var child = std.process.spawn(io, .{
        // `-h2tls` is relative to the generator's directory, four levels down.
        .argv = &.{ "go", "run", ".", "-h2tls", "../../../../" ++ port_file },
        .cwd = .{ .path = go_oracle_dir },
        .environ_map = env,
        .stdin = .pipe,
        .stdout = .inherit,
        .stderr = .inherit,
    }) catch |e| {
        std.debug.print("could not spawn go ({t}) -- the peer is required, not optional\n", .{e});
        return error.NoGo;
    };
    defer {
        // EOF on its stdin ends the peer (and with it `go run`).
        if (child.stdin) |f| f.close(io);
        child.stdin = null;
        _ = child.wait(io) catch {};
    }
    // `go run` builds first: allow two minutes.
    const ports = for (0..1200) |_| {
        if (cwd.readFileAlloc(io, port_file, arena, .limited(64))) |t| {
            if (std.mem.endsWith(u8, t, "\n")) break t;
        } else |_| {}
        try io.sleep(.fromMilliseconds(100), .awake);
    } else {
        std.debug.print("alpn: the Go peer never wrote {s} -- NOT OK\n", .{port_file});
        return false;
    };
    var it = std.mem.tokenizeAny(u8, ports, " =\n");
    _ = it.next(); // "h2"
    const h2_port = it.next() orelse return error.BadPortFile;
    _ = it.next(); // "h1"
    const h1_port = it.next() orelse return error.BadPortFile;

    var client = Client.init(io, gpa, .{
        .http2 = .alpn(),
        .decompress = .gzip(1 << 20),
        .tls = .{ .verify = .insecure_no_verify }, // httptest's self-signed certificate
        .total_timeout_ms = 10_000,
    });
    defer client.deinit();
    var ok = true;
    const custom: []const http.Header = &.{.{ .name = "X-Custom", .value = "v" }};

    // ALPN picks h2: the request Go's server saw, beside Go's own.
    const ours = try fetch(&client, arena, h2_port, "/fields", custom, .http2, &ok);
    const go = try fetch(&client, arena, h2_port, "/go", &.{}, .http2, &ok);
    ok = sameFields("h2", ours, go, "proto: HTTP/2.0") and ok;
    {
        const url = try std.fmt.allocPrint(arena, "https://127.0.0.1:{s}/trailers", .{h2_port});
        var res = try client.request(.get, url, .{});
        defer res.deinit();
        const body = try res.readAllAlloc(arena, 1 << 16);
        ok = check("h2 trailers", std.mem.eql(u8, body, "body before trailers") and
            std.mem.eql(u8, res.trailer("X-Checksum") orelse "", "c0ffee")) and ok;
    }
    {
        const url = try std.fmt.allocPrint(arena, "https://127.0.0.1:{s}/gz", .{h2_port});
        var res = try client.request(.get, url, .{});
        defer res.deinit();
        const body = try res.readAllAlloc(arena, 1 << 16);
        ok = check("h2 gzip", res.uncompressed and std.mem.eql(u8, body, "gzip over h2, decoded by the client\n")) and ok;
    }
    const redirected = try fetch(&client, arena, h2_port, "/redirect", &.{}, .http2, &ok);
    ok = check("h2 redirect", std.mem.startsWith(u8, redirected, "proto: HTTP/2.0\n")) and ok;
    {
        const url = try std.fmt.allocPrint(arena, "https://127.0.0.1:{s}/echo", .{h2_port});
        var up = try client.requestStreaming(.post, url, .{}, null);
        for (0..64) |_| try up.writer().writeAll(strRepeat("0123456789abcdef", 64));
        var res = try up.finish();
        defer res.deinit();
        const body = try res.readAllAlloc(arena, 1 << 20);
        ok = check("h2 streamed upload", res.proto() == .http2 and body.len == 64 * 1024) and ok;
    }
    ok = check("h2: one connection for all of it", client.dialCount() == 1) and ok;

    // A request that asks to upgrade stays on HTTP/1.1, even here.
    _ = try fetch(&client, arena, h2_port, "/fields", &.{
        .{ .name = "Connection", .value = "Upgrade" },
        .{ .name = "Upgrade", .value = "websocket" },
    }, .http1_1, &ok);

    // No h2 on offer: HTTP/1.1, the same request for both clients.
    const ours1 = try fetch(&client, arena, h1_port, "/fields", custom, .http1_1, &ok);
    const go1 = try fetch(&client, arena, h1_port, "/go", &.{}, .http1_1, &ok);
    ok = sameFields("h1", ours1, go1, "proto: HTTP/1.1") and ok;

    std.debug.print("alpn: Client over TLS against Go net/http -- {s}\n", .{if (ok) "OK" else "NOT OK"});
    return ok;
}

fn fetch(client: *Client, arena: std.mem.Allocator, port: []const u8, path: []const u8, headers: []const http.Header, want: Client.Proto, ok: *bool) ![]const u8 {
    const url = try std.fmt.allocPrint(arena, "https://127.0.0.1:{s}{s}", .{ port, path });
    var res = try client.request(.get, url, .{ .headers = headers });
    defer res.deinit();
    const body = try res.readAllAlloc(arena, 1 << 16);
    if (res.proto() != want or res.status != 200) {
        std.debug.print("  alpn FAIL {s}: {d} over {s}, want 200 over {s}\n", .{ url, res.status, res.proto().text(), want.text() });
        ok.* = false;
    }
    return body;
}

fn check(what: []const u8, good: bool) bool {
    if (!good) std.debug.print("  alpn FAIL {s}\n", .{what});
    return good;
}

/// Go's server's view of our request and of Go's: the same lines, `User-Agent`
/// aside, and the protocol line `proto`.
fn sameFields(label: []const u8, ours: []const u8, go: []const u8, proto: []const u8) bool {
    var good = std.mem.startsWith(u8, ours, proto) and std.mem.startsWith(u8, go, proto);
    var a = std.mem.splitScalar(u8, ours, '\n');
    var b = std.mem.splitScalar(u8, go, '\n');
    while (true) {
        var la = a.next();
        var lb = b.next();
        while (la != null and std.mem.startsWith(u8, la.?, "user-agent: ")) la = a.next();
        while (lb != null and std.mem.startsWith(u8, lb.?, "user-agent: ")) lb = b.next();
        if (la == null and lb == null) break;
        if (la == null or lb == null or !std.mem.eql(u8, la.?, lb.?)) {
            good = false;
            break;
        }
    }
    if (!good) std.debug.print("  alpn FAIL {s}: Go's server saw\n--- ours\n{s}--- Go's\n{s}", .{ label, ours, go });
    return good;
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    const rep_result = comptime blk: {
        @setEvalBranchQuota(n * (s.len + 4) + 1000);
        var buf: [s.len * n:0]u8 = undefined;
        for (0..n) |i| @memcpy(buf[i * s.len ..][0..s.len], s);
        const rep_final = buf;
        break :blk rep_final;
    };
    return &rep_result;
}
