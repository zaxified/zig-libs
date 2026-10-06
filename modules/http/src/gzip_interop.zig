// SPDX-License-Identifier: MIT

//! LIVE third-party decoders for **gzip response compression**: this module's
//! server compresses (`Options.compression`), and two independent gzip
//! implementations decode what went over a real loopback socket:
//!
//!   * curl `--compressed` (libcurl's content decoding over zlib's
//!     `inflate`, which checks the RFC 1952 trailer: CRC-32 and ISIZE);
//!   * `gzip -dc` (GNU gzip's own inflate; refuses a bad CRC or length).
//!
//! (CPython's `gzip.decompress` was a third until 2026-10-06: a module may
//! not spawn a foreign toolchain, CONVENTIONS §9, and both of these are
//! peers, not toolchains.)
//!
//! Before this file the encoder was checked only against std's own
//! `flate.Decompress` — a decoder from the same family as the encoder it
//! judged. Here the header, the deflate stream (one call, many sync flushes,
//! stored blocks for incompressible data), and the trailer are each judged by
//! code we did not write, at levels 1, 6 and 9, on HTTP/1.1 and HTTP/2.
//!
//! The decoders are proven to have teeth on every run: the raw body is also
//! fed to gzip(1) with its CRC-32 and then its ISIZE flipped, and it must
//! refuse it. A decoder that accepted those would make the positive results
//! meaningless.
//!
//! Every test **skips loudly** (`SKIPPED: …` + `error.SkipZigTest`) when
//! curl or gzip is missing — never silently. Children write to files
//! in a temp dir; no child's pipe is ever read to EOF.

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;

const Server = @import("Server.zig");
const Writer = std.Io.Writer;

const testkit = @import("testkit");

/// Plain bodies, one per route. Every one is over `Compression.min_size`
/// and served as `text/plain`, so every one is compressed.
const Route = struct { path: []const u8, kind: enum { whole, stream, noise } };

const routes = [_]Route{
    // Fits the response buffer: compressed in one piece, Content-Length known.
    .{ .path = "/gz-whole", .kind = .whole },
    // 64 × 4 KiB, flushed after each: 64 sync flushes inside one member.
    .{ .path = "/gz-stream", .kind = .stream },
    // 192 KiB of PRNG output: deflate falls back to stored blocks.
    .{ .path = "/gz-noise", .kind = .noise },
};

const whole_body = "The quick brown fox jumps over the lazy dog. " ** 64; // ~2.8 KiB
const stream_piece = "abcdefgh0123456789" ** 228; // ~4 KiB, not a power of two
const stream_pieces = 64;
const noise_len = 192 * 1024;

fn noiseBody(buf: []u8) void {
    var prng = std.Random.DefaultPrng.init(0x67_7a_69_70);
    prng.random().bytes(buf);
}

var noise_buf: [noise_len]u8 = undefined;

fn expectedBody(kind: @TypeOf(routes[0].kind), gpa: std.mem.Allocator) ![]u8 {
    return switch (kind) {
        .whole => gpa.dupe(u8, whole_body),
        .stream => blk: {
            const out = try gpa.alloc(u8, stream_piece.len * stream_pieces);
            for (0..stream_pieces) |i| @memcpy(out[i * stream_piece.len ..][0..stream_piece.len], stream_piece);
            break :blk out;
        },
        .noise => blk: {
            noiseBody(&noise_buf);
            break :blk gpa.dupe(u8, &noise_buf);
        },
    };
}

fn gzHandler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
    try rw.setHeader("Content-Type", "text/plain");
    for (routes) |r| {
        if (!std.mem.eql(u8, req.path, r.path)) continue;
        switch (r.kind) {
            .whole => try rw.writeAll(whole_body),
            .stream => for (0..stream_pieces) |_| {
                try rw.writeAll(stream_piece);
                try rw.flush();
            },
            .noise => {
                var buf: [noise_len]u8 = undefined;
                noiseBody(&buf);
                try rw.writeAll(&buf);
            },
        }
        return;
    }
    rw.setStatus(404);
    try rw.writeAll("not found\n");
}

fn serveWrap(s: *Server) void {
    s.serve() catch {};
}

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

fn startServer(io: std.Io, gpa: std.mem.Allocator, l: *LiveServer, level: u4) !void {
    l.server = Server.init(io, gpa, .{
        .handler = gzHandler,
        .enable_h2c = true,
        .compression = .{ .level = level },
    });
    l.server.bind() catch |err| {
        l.server.deinit();
        return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    };
    var w: Writer = .fixed(&l.url_buf);
    try w.print("http://127.0.0.1:{d}", .{l.server.boundAddress().getPort()});
    l.url_len = w.buffered().len;
    l.thread = try std.Thread.spawn(.{}, serveWrap, .{&l.server});
}

/// Run `argv` in `dir`, stdout into `stdout_name` (or discarded). Returns the
/// exit code; a missing program is a loud skip.
fn run(io: std.Io, dir: std.Io.Dir, argv: []const []const u8, stdout_name: ?[]const u8) !u8 {
    const out_file: ?std.Io.File = if (stdout_name) |n| try dir.createFile(io, n, .{}) else null;
    defer if (out_file) |f| f.close(io);
    var child = std.process.spawn(io, .{
        .argv = argv,
        .cwd = .{ .dir = dir },
        .stdin = .ignore,
        .stdout = if (out_file) |f| .{ .file = f } else .ignore,
        .stderr = .ignore,
    }) catch return testkit.skip("LIVE http gzip interop: no `{s}` on PATH", .{argv[0]});
    return switch (try child.wait(io)) {
        .exited => |code| code,
        else => 255,
    };
}

fn readFile(io: std.Io, dir: std.Io.Dir, gpa: std.mem.Allocator, name: []const u8) ![]u8 {
    return dir.readFileAlloc(io, name, gpa, .limited(4 << 20));
}

/// Fetch `path` twice — decoded by curl, and raw — then decode the raw body
/// with gzip(1); both must give `expected`.
fn checkRoute(
    io: std.Io,
    gpa: std.mem.Allocator,
    dir: std.Io.Dir,
    base: []const u8,
    proto: []const u8,
    r: Route,
) !void {
    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "{s}{s}", .{ base, r.path });
    const expected = try expectedBody(r.kind, gpa);
    defer gpa.free(expected);

    // curl decodes (its zlib checks the trailer); the head proves it was gzip.
    const c1 = try run(io, dir, &.{ "curl", "-sS", "--max-time", "20", proto, "--compressed", "-o", "curl.out", "-D", "head.txt", url }, null);
    try testing.expectEqual(@as(u8, 0), c1);
    const head = try readFile(io, dir, gpa, "head.txt");
    defer gpa.free(head);
    if (std.ascii.indexOfIgnoreCase(head, "content-encoding: gzip") == null) {
        std.debug.print("\n{s} {s}: not gzip-encoded; head:\n{s}\n", .{ proto, r.path, head });
        return error.NotCompressed;
    }
    const by_curl = try readFile(io, dir, gpa, "curl.out");
    defer gpa.free(by_curl);
    try testing.expectEqualSlices(u8, expected, by_curl);

    // The raw member, as it crossed the wire.
    const c2 = try run(io, dir, &.{ "curl", "-sS", "--max-time", "20", proto, "-H", "Accept-Encoding: gzip", "-o", "raw.gz", url }, null);
    try testing.expectEqual(@as(u8, 0), c2);

    try testing.expectEqual(@as(u8, 0), try run(io, dir, &.{ "gzip", "-dc", "raw.gz" }, "gzip.out"));
    const by_gzip = try readFile(io, dir, gpa, "gzip.out");
    defer gpa.free(by_gzip);
    try testing.expectEqualSlices(u8, expected, by_gzip);

    // Teeth: the same member with its CRC-32, then its ISIZE, corrupted must
    // be refused by gzip(1).
    const raw = try readFile(io, dir, gpa, "raw.gz");
    defer gpa.free(raw);
    for ([_]usize{ 8, 4 }) |from_end| {
        const bad = try gpa.dupe(u8, raw);
        defer gpa.free(bad);
        bad[bad.len - from_end] ^= 0x01;
        try dir.writeFile(io, .{ .sub_path = "bad.gz", .data = bad });
        try testing.expect(try run(io, dir, &.{ "gzip", "-dc", "bad.gz" }, null) != 0);
    }
}

fn checkAll(level: u4, protos: []const []const u8) !void {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var live: LiveServer = undefined;
    try startServer(io, gpa, &live, level);
    defer live.stop();

    for (protos) |proto| for (routes) |r| try checkRoute(io, gpa, tmp.dir, live.url(), proto, r);
}

test "LIVE gzip: curl and gzip(1) decode our level-6 members on HTTP/1.1 and h2c" {
    try checkAll(6, &.{ "--http1.1", "--http2-prior-knowledge" });
}

test "LIVE gzip: levels 1 and 9 decode the same way" {
    try checkAll(1, &.{"--http1.1"});
    try checkAll(9, &.{"--http1.1"});
}
