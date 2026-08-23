// SPDX-License-Identifier: MIT

//! What a production HTTP server does with `staticfiles`: mount a root
//! directory, serve a real file over the socket-free `http` codec, resolve a
//! byte range (RFC 7233 via RFC 9110 §14), see an unsatisfiable range
//! rejected, see a conditional `If-None-Match` short-circuit to 304, and see
//! a path-traversal attempt rejected by a NAMED error before it ever touches
//! the filesystem. `Handler.serve` takes `*http.Server.Request`/
//! `*http.Server.ResponseWriter` directly — an http-layer handler, not a
//! `router` middleware.
//!
//! External judges:
//!
//! 1. RFC 9110 (HTTP Semantics) §14 "Range Requests" and §13 "Conditional
//!    Requests" — the status codes and header shapes asserted below
//!    (`206`/`Content-Range: bytes <start>-<end>/<len>`, `416`/
//!    `Content-Range: bytes */<len>`, `304` with no body) are exactly what
//!    those sections specify, not this module's own invention.
//! 2. A real independent server, `python3 -m http.server`, run against the
//!    same `hello.txt` on this machine — but MEASURED, not assumed, to
//!    support only part of what's being tested here:
//!
//!      cd /tmp/httpd_test && python3 -m http.server 8199 &
//!      curl -sD- -o/dev/null http://127.0.0.1:8199/hello.txt        # 200, Content-Length: 11
//!      curl -sD- -o/dev/null -H 'Range: bytes=0-4' .../hello.txt    # STILL 200 — Range ignored
//!      curl -sD- -o/dev/null -H 'If-None-Match: "bogus"' .../hello.txt  # STILL 200 — no ETag at all
//!      curl -sD- -o/dev/null -H "If-Modified-Since: <its own Last-Modified>" .../hello.txt
//!                                                                     # 304 Not Modified
//!
//!    So `python3 -m http.server` is a genuine external confirmation for
//!    `If-Modified-Since` → 304 (the mechanism this example's `If-None-Match`
//!    check is the ETag-based sibling of, RFC 9110 §13.1.1 vs §13.1.2), but
//!    it does **not** implement `Range` or `If-None-Match` at all (every such
//!    request measured above still came back a plain 200) — it cannot serve
//!    as the oracle for those two, so RFC 9110 §14 and §13.1.2's own text are
//!    the judge there instead.
//!
//! Built by `zig build check-examples` against the PUBLISHED module — no
//! access to anything `staticfiles` (or `http`) does not export.

const std = @import("std");
const http = @import("http");
const staticfiles = @import("staticfiles");

fn runRequest(handler: *staticfiles.Handler, wire: []const u8, out_buf: []u8) []const u8 {
    var in: std.Io.Reader = .fixed(wire);
    var out: std.Io.Writer = .fixed(out_buf);
    var head_buf: [4096]u8 = undefined;
    var request_body_buf: [256]u8 = undefined;
    var response_body_buf: [256]u8 = undefined;
    var chunk_buf: [512]u8 = undefined;
    http.Server.serveStream(.{
        .handler = staticfiles.httpHandler,
        .context = handler,
        .server_name = "example",
    }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    return out.buffered();
}

fn getWithHeader(handler: *staticfiles.Handler, path: []const u8, extra: []const u8, out_buf: []u8) []const u8 {
    var wire_buf: [512]u8 = undefined;
    const wire = std.fmt.bufPrint(&wire_buf, "GET {s} HTTP/1.1\r\nHost: t\r\n{s}Connection: close\r\n\r\n", .{ path, extra }) catch unreachable;
    return runRequest(handler, wire, out_buf);
}

fn statusOf(resp: []const u8) u16 {
    if (resp.len < 12) return 0;
    return std.fmt.parseInt(u16, resp[9..12], 10) catch 0;
}

fn headerValue(got: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitSequence(u8, got, "\r\n");
    while (it.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, line[0..colon], " "), name))
            return std.mem.trim(u8, line[colon + 1 ..], " ");
    }
    return null;
}

fn bodyOf(resp: []const u8) []const u8 {
    const i = std.mem.indexOf(u8, resp, "\r\n\r\n") orelse return "";
    return resp[i + 4 ..];
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // A real root under the build's own cache dir, cleaned up at the end.
    const base = ".zig-cache/tmp/example-staticfiles";
    defer std.Io.Dir.cwd().deleteTree(io, base) catch {};
    var root = try std.Io.Dir.cwd().createDirPathOpen(io, base, .{ .open_options = .{ .iterate = true } });
    defer root.close(io);

    try root.writeFile(io, .{ .sub_path = "hello.txt", .data = "hello world" }); // 11 bytes
    try root.writeFile(io, .{ .sub_path = "index.html", .data = "<h1>home</h1>" });

    var handler = staticfiles.Handler.init(io, root, .{});

    // ── plain GET ────────────────────────────────────────────────────────
    var buf1: [1024]u8 = undefined;
    const resp1 = getWithHeader(&handler, "/hello.txt", "", &buf1);
    if (statusOf(resp1) != 200) return error.ExpectedOk;
    if (!std.mem.eql(u8, bodyOf(resp1), "hello world")) return error.WrongBody;
    const etag = headerValue(resp1, "ETag") orelse return error.MissingETag;
    std.debug.print("GET /hello.txt: 200, ETag={s}\n", .{etag});

    // ── RFC 9110 §14: a satisfiable byte range → 206 + exact Content-Range ─
    var range_hdr_buf: [64]u8 = undefined;
    const range_hdr = std.fmt.bufPrint(&range_hdr_buf, "Range: bytes=0-4\r\n", .{}) catch unreachable;
    var buf2: [1024]u8 = undefined;
    const resp2 = getWithHeader(&handler, "/hello.txt", range_hdr, &buf2);
    if (statusOf(resp2) != 206) return error.ExpectedPartial;
    const content_range = headerValue(resp2, "Content-Range") orelse return error.MissingContentRange;
    // RFC 9110 §14.4: "Content-Range: bytes 0-4/11" for the first 5 bytes of
    // an 11-byte resource.
    if (!std.mem.eql(u8, content_range, "bytes 0-4/11")) return error.WrongContentRange;
    if (!std.mem.eql(u8, bodyOf(resp2), "hello")) return error.WrongRangeBody;
    std.debug.print("Range bytes=0-4: 206, Content-Range={s}, body={s}\n", .{ content_range, bodyOf(resp2) });

    // ── RFC 9110 §14.1.2: an unsatisfiable range → 416 + `bytes */<len>` ───
    var bad_range_buf: [64]u8 = undefined;
    const bad_range_hdr = std.fmt.bufPrint(&bad_range_buf, "Range: bytes=100-200\r\n", .{}) catch unreachable;
    var buf3: [1024]u8 = undefined;
    const resp3 = getWithHeader(&handler, "/hello.txt", bad_range_hdr, &buf3);
    if (statusOf(resp3) != 416) return error.ExpectedRangeNotSatisfiable;
    const unsat_range = headerValue(resp3, "Content-Range") orelse return error.MissingContentRange;
    if (!std.mem.eql(u8, unsat_range, "bytes */11")) return error.WrongUnsatisfiedRange;
    std.debug.print("Range bytes=100-200 (past EOF): 416, Content-Range={s}\n", .{unsat_range});

    // ── RFC 9110 §13.1.2: If-None-Match with the resource's real ETag → 304,
    // no body ───────────────────────────────────────────────────────────
    var inm_buf: [96]u8 = undefined;
    const inm_hdr = std.fmt.bufPrint(&inm_buf, "If-None-Match: {s}\r\n", .{etag}) catch unreachable;
    var buf4: [1024]u8 = undefined;
    const resp4 = getWithHeader(&handler, "/hello.txt", inm_hdr, &buf4);
    if (statusOf(resp4) != 304) return error.ExpectedNotModified;
    if (bodyOf(resp4).len != 0) return error.UnexpectedBodyOn304;
    std.debug.print("If-None-Match: {s}: 304, empty body\n", .{etag});

    // ── path traversal: rejected by a NAMED error, before any filesystem
    // access — sanitizePath is layer 1 of the module's own two-layer defense
    var san_buf: [staticfiles.max_path_bytes]u8 = undefined;
    if (staticfiles.sanitizePath("/../../etc/passwd", &san_buf, .{})) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.Traversal => std.debug.print("sanitizePath(\"/../../etc/passwd\"): Traversal (expected)\n", .{}),
        else => return err,
    }

    // The same attempt through the full HTTP path answers 403, never 404
    // (which would leak whether the target exists) and never touches the
    // filesystem outside root.
    var buf5: [1024]u8 = undefined;
    const resp5 = getWithHeader(&handler, "/..%2f..%2fetc%2fpasswd", "", &buf5);
    if (statusOf(resp5) != 403) return error.ExpectedForbidden;
    std.debug.print("GET /..%2f..%2fetc%2fpasswd over the wire: 403\n", .{});
}
