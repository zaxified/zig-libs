// SPDX-License-Identifier: MIT

//! LIVE third-party-client interop for **response trailers**: this module's
//! server answered by real `curl` (libcurl + nghttp2), over a real loopback
//! TCP socket, on HTTP/1.1 and HTTP/2.
//!
//! Why this file exists at all: every other trailer test in this module has
//! our writer on one side and our reader on the other. That arrangement
//! cannot catch a shared misreading of the framing rules — put the trailer
//! block before the last chunk instead of after it, or leave END_STREAM on
//! the final DATA frame, and a reader written from the same misunderstanding
//! agrees with the writer and stays green. The same failure mode has already
//! cost this collection real defects (see `dtls`'s wolfSSL interop: six bugs
//! surfaced only once a live third-party peer looked at our bytes, with
//! every self-interop test passing throughout).
//!
//! curl is a genuine oracle for both directions here:
//!   * HTTP/1.1 — its chunked decoder hard-fails a trailer section that is
//!     not exactly where RFC 9112 §7.1.2 puts it (exit 56), and it passes
//!     the parsed trailer fields to the header callback, so `-D` shows them
//!     *after* the body. That is a parse-level observation, not a byte echo.
//!   * HTTP/2 — nghttp2 decodes the trailing HEADERS frame as a trailer
//!     section and curl hands those fields to the same header callback, so
//!     `-D` shows them after the head here too.
//!
//! One measured caveat, because it decides which assertion carries the
//! weight on h2: curl 8.18 / nghttp2 1.68 do NOT fail a transfer whose
//! trailer HEADERS arrives after a DATA frame that already carried
//! END_STREAM — they silently DISCARD the late frame and still exit 0
//! (verified by mutation, twice: once with our own send-side state guard in
//! place, once with it removed so the bad frame really went out). So on h2
//! the oracle is "curl surfaced the trailer fields", not the exit code. On
//! h1 it is both: a misplaced trailer section fails the transfer outright.
//!
//! Every test **skips loudly** (`SKIPPED: …` + `error.SkipZigTest`) when
//! curl is missing or was built without HTTP/2 — never silently.
//!
//! Child-process hygiene: curl writes its output to files in a temp dir
//! (`-D`/`-o`/`--trace-ascii`) and its own stdio is discarded, so no test
//! ever reads a live child's pipe to EOF — the classic way this kind of
//! test wedges the suite instead of failing it.

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;

const Server = @import("Server.zig");

const Writer = std.Io.Writer;

fn verboseSkip() bool {
    const v = std.process.Environ.getPosix(std.testing.environ, "ZIG_LIBS_VERBOSE_SKIP") orelse return false;
    return v.len > 0;
}

/// The handler the live tests are served by: one route per framing shape,
/// each ending in a trailer section a client can check.
fn trailerHandler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
    if (std.mem.eql(u8, req.path, "/outtrailers")) {
        // Body fits the response buffer, so an exact Content-Length was
        // available: the chunked framing here comes purely from declaring
        // trailers.
        try rw.setHeader("Content-Type", "text/plain");
        try rw.declareTrailers(&.{ "X-Checksum", "X-Rows" });
        try rw.writeAll("hello");
        try rw.setTrailer("X-Checksum", "deadbeef");
        try rw.setTrailer("X-Rows", "3");
    } else if (std.mem.eql(u8, req.path, "/outtrailers-stream")) {
        // Body outgrows the buffer and is flushed mid-handler: the head is
        // long gone by the time the trailer value is computed.
        try rw.setHeader("Content-Type", "text/plain");
        try rw.declareTrailer("X-Checksum");
        try rw.writeAll(streamed_body);
        try rw.flush();
        try rw.setTrailer("X-Checksum", "deadbeef");
    } else {
        rw.setStatus(404);
        try rw.writeAll("not found\n");
    }
}

const streamed_body = "abcdefgh" ** 512; // 4 KiB: several chunks / DATA frames

fn serveWrap(s: *Server) void {
    s.serve() catch {};
}

/// One curl invocation against `url`, writing its header dump, body and
/// protocol trace into `dir`. Returns curl's exit code (0 = the transfer
/// completed and every framing rule curl enforces held).
fn runCurl(io: std.Io, dir: std.Io.Dir, extra: []const []const u8, url: []const u8) !u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(testing.allocator);
    try argv.appendSlice(testing.allocator, &.{
        "curl",          "-sS",
        "--max-time",    "20",
        "-o",            "body.txt",
        "-D",            "head.txt",
        "--trace-ascii", "trace.txt",
    });
    try argv.appendSlice(testing.allocator, extra);
    try argv.append(testing.allocator, url);

    var child = std.process.spawn(io, .{
        .argv = argv.items,
        .cwd = .{ .dir = dir },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    }) catch {
        if (verboseSkip()) std.debug.print(
            "\nSKIPPED: LIVE http curl interop: no `curl` on PATH.\n  fix: sudo apt install curl\n",
            .{},
        );
        return error.SkipZigTest;
    };
    return switch (try child.wait(io)) {
        .exited => |code| code,
        else => 255,
    };
}

/// True when the installed curl was built with HTTP/2 support.
fn curlHasHttp2(io: std.Io, gpa: std.mem.Allocator, dir: std.Io.Dir) !bool {
    var child = std.process.spawn(io, .{
        .argv = &.{ "curl", "--version" },
        .cwd = .{ .dir = dir },
        .stdin = .ignore,
        .stdout = .{ .file = try dir.createFile(io, "version.txt", .{}) },
        .stderr = .ignore,
    }) catch {
        if (verboseSkip()) std.debug.print("\nSKIPPED: LIVE http curl interop: no `curl` on PATH.\n", .{});
        return error.SkipZigTest;
    };
    _ = try child.wait(io);
    const text = try dir.readFileAlloc(io, "version.txt", gpa, .limited(64 * 1024));
    defer gpa.free(text);
    return std.mem.indexOf(u8, text, "HTTP2") != null;
}

/// A server on a loopback port, plus the URL prefix to reach it.
const LiveServer = struct {
    server: Server,
    thread: std.Thread,
    url_buf: [64]u8 = undefined,
    url_len: usize = 0,

    fn url(l: *const LiveServer) []const u8 {
        return l.url_buf[0..l.url_len];
    }

    fn stop(l: *LiveServer) void {
        l.server.shutdown();
        l.thread.join();
        l.server.deinit();
    }
};

fn startServer(io: std.Io, gpa: std.mem.Allocator, l: *LiveServer, enable_h2c: bool) !void {
    l.server = Server.init(io, gpa, .{ .handler = trailerHandler, .enable_h2c = enable_h2c });
    l.server.bind() catch |err| {
        l.server.deinit();
        std.debug.print("loopback bind failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    var w: Writer = .fixed(&l.url_buf);
    try w.print("http://127.0.0.1:{d}", .{l.server.boundAddress().getPort()});
    l.url_len = w.buffered().len;
    l.thread = try std.Thread.spawn(.{}, serveWrap, .{&l.server});
}

/// `head.txt` from curl, split at the end of the response head. Returns the
/// head (status line + header fields) and everything curl's header callback
/// emitted *after* it — which for a trailered response is the trailer
/// section, and nothing else.
const HeaderDump = struct {
    head: []const u8,
    after_head: []const u8,
};

fn splitHeaderDump(text: []const u8) !HeaderDump {
    // curl separates the head from anything that follows with the blank
    // line it received; find the first one.
    const sep = std.mem.indexOf(u8, text, "\r\n\r\n") orelse return error.NoHeadTerminator;
    return .{ .head = text[0 .. sep + 2], .after_head = text[sep + 4 ..] };
}

// ── HTTP/1.1 ────────────────────────────────────────────────────────────────

test "LIVE curl: HTTP/1.1 response trailers are accepted and surfaced" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var live: LiveServer = undefined;
    try startServer(io, gpa, &live, false);
    defer live.stop();

    var url_buf: [96]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "{s}/outtrailers", .{live.url()});
    const code = try runCurl(io, tmp.dir, &.{"--http1.1"}, url);

    const trace = try tmp.dir.readFileAlloc(io, "trace.txt", gpa, .limited(256 * 1024));
    defer gpa.free(trace);
    // Exit 0 is the load-bearing assertion: curl's chunked decoder ran to
    // completion. A trailer section emitted anywhere but after the `0`
    // last-chunk line is read as a chunk-size line and fails the transfer
    // with exit 56 — verified by mutation, not assumed.
    if (code != 0) {
        std.debug.print("\ncurl exited {d}; trace:\n{s}\n", .{ code, trace });
        return error.CurlRejectedTheResponse;
    }

    const body = try tmp.dir.readFileAlloc(io, "body.txt", gpa, .limited(64 * 1024));
    defer gpa.free(body);
    // The trailer bytes are framing, not payload: curl must not have
    // counted a single one of them as body.
    try testing.expectEqualStrings("hello", body);

    const dump = try tmp.dir.readFileAlloc(io, "head.txt", gpa, .limited(64 * 1024));
    defer gpa.free(dump);
    const split = try splitHeaderDump(dump);
    // The advert rode in the head (RFC 9110 §6.6.2)…
    try testing.expect(std.mem.indexOf(u8, split.head, "Trailer: X-Checksum, X-Rows\r\n") != null);
    // …and curl delivered the trailer fields to its header callback only
    // AFTER the head was complete. This is what distinguishes "curl parsed
    // a trailer section" from "our bytes happened to contain those
    // strings": had we emitted them as ordinary head fields, they would be
    // on the other side of this split.
    try testing.expect(std.mem.indexOf(u8, split.after_head, "X-Checksum: deadbeef") != null);
    try testing.expect(std.mem.indexOf(u8, split.after_head, "X-Rows: 3") != null);
    try testing.expect(std.mem.indexOf(u8, split.head, "X-Checksum: deadbeef") == null);
    // Framing sanity: chunked, and no Content-Length anywhere.
    try testing.expect(std.mem.indexOf(u8, split.head, "Transfer-Encoding: chunked\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, dump, "Content-Length") == null);
}

test "LIVE curl: HTTP/1.1 trailers survive a multi-chunk streamed body" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var live: LiveServer = undefined;
    try startServer(io, gpa, &live, false);
    defer live.stop();

    var url_buf: [96]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "{s}/outtrailers-stream", .{live.url()});
    const code = try runCurl(io, tmp.dir, &.{"--http1.1"}, url);
    if (code != 0) {
        const trace = try tmp.dir.readFileAlloc(io, "trace.txt", gpa, .limited(256 * 1024));
        defer gpa.free(trace);
        std.debug.print("\ncurl exited {d}; trace:\n{s}\n", .{ code, trace });
        return error.CurlRejectedTheResponse;
    }
    const body = try tmp.dir.readFileAlloc(io, "body.txt", gpa, .limited(64 * 1024));
    defer gpa.free(body);
    try testing.expectEqualStrings(streamed_body, body);

    const dump = try tmp.dir.readFileAlloc(io, "head.txt", gpa, .limited(64 * 1024));
    defer gpa.free(dump);
    const split = try splitHeaderDump(dump);
    try testing.expect(std.mem.indexOf(u8, split.head, "Trailer: X-Checksum\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, split.after_head, "X-Checksum: deadbeef") != null);
}

// ── HTTP/2 ──────────────────────────────────────────────────────────────────

test "LIVE curl: HTTP/2 response trailers are accepted by nghttp2 and surfaced" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    if (!try curlHasHttp2(io, gpa, tmp.dir)) {
        if (verboseSkip()) std.debug.print(
            "\nSKIPPED: LIVE http curl interop: curl was built without HTTP/2 (no nghttp2).\n",
            .{},
        );
        return error.SkipZigTest;
    }

    var live: LiveServer = undefined;
    try startServer(io, gpa, &live, true);
    defer live.stop();

    var url_buf: [96]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "{s}/outtrailers", .{live.url()});
    const code = try runCurl(io, tmp.dir, &.{"--http2-prior-knowledge"}, url);

    const trace = try tmp.dir.readFileAlloc(io, "trace.txt", gpa, .limited(256 * 1024));
    defer gpa.free(trace);
    // Exit 0 only means curl completed the transfer; on h2 that alone does
    // NOT prove the framing (see the caveat in this file's doc comment —
    // curl discards a post-END_STREAM HEADERS and still exits 0). The
    // load-bearing h2 assertion is the trailer surfacing below.
    if (code != 0) {
        std.debug.print("\ncurl exited {d}; trace:\n{s}\n", .{ code, trace });
        return error.CurlRejectedTheResponse;
    }

    const body = try tmp.dir.readFileAlloc(io, "body.txt", gpa, .limited(64 * 1024));
    defer gpa.free(body);
    try testing.expectEqualStrings("hello", body);

    const dump = try tmp.dir.readFileAlloc(io, "head.txt", gpa, .limited(64 * 1024));
    defer gpa.free(dump);
    const split = try splitHeaderDump(dump);
    try testing.expect(std.mem.indexOf(u8, split.head, "HTTP/2 200") != null);
    try testing.expect(std.mem.indexOf(u8, split.head, "trailer: X-Checksum, X-Rows\r\n") != null);
    // Same parse-level observation as on h1: the trailer HEADERS frame
    // reached curl's header callback after the response head, i.e. it was
    // decoded as a trailer section rather than as more response headers.
    try testing.expect(std.mem.indexOf(u8, split.after_head, "x-checksum: deadbeef") != null);
    try testing.expect(std.mem.indexOf(u8, split.after_head, "x-rows: 3") != null);
    try testing.expect(std.mem.indexOf(u8, split.head, "x-checksum: deadbeef") == null);
    // h1 framing must not have leaked into h2 (§8.2.2).
    try testing.expect(std.mem.indexOf(u8, dump, "chunked") == null);
}

test "LIVE curl: HTTP/2 trailers survive a multi-DATA-frame streamed body" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    if (!try curlHasHttp2(io, gpa, tmp.dir)) return error.SkipZigTest;

    var live: LiveServer = undefined;
    try startServer(io, gpa, &live, true);
    defer live.stop();

    var url_buf: [96]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "{s}/outtrailers-stream", .{live.url()});
    const code = try runCurl(io, tmp.dir, &.{"--http2-prior-knowledge"}, url);
    if (code != 0) {
        const trace = try tmp.dir.readFileAlloc(io, "trace.txt", gpa, .limited(256 * 1024));
        defer gpa.free(trace);
        std.debug.print("\ncurl exited {d}; trace:\n{s}\n", .{ code, trace });
        return error.CurlRejectedTheResponse;
    }
    const body = try tmp.dir.readFileAlloc(io, "body.txt", gpa, .limited(256 * 1024));
    defer gpa.free(body);
    try testing.expectEqualStrings(streamed_body, body);

    const dump = try tmp.dir.readFileAlloc(io, "head.txt", gpa, .limited(64 * 1024));
    defer gpa.free(dump);
    const split = try splitHeaderDump(dump);
    try testing.expect(std.mem.indexOf(u8, split.after_head, "x-checksum: deadbeef") != null);
}
