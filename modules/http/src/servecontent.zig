// SPDX-License-Identifier: MIT

//! `serveContent` — Go's `http.ServeContent` for a representation held in
//! memory: `Last-Modified`, the preconditions (`If-Match`, `If-None-Match`,
//! `If-Modified-Since`, `If-Unmodified-Since` → 412/304), `If-Range`, byte
//! ranges (one → 206 + `Content-Range`, several → `multipart/byteranges`,
//! none satisfiable → 416), `Content-Type` (given, already set, or sniffed),
//! `Accept-Ranges` and an exact `Content-Length`, HEAD without a body. The
//! pieces are `conditional`, `range` and `sniff`; this file composes them in
//! Go's order, and `go_oracle.zig` (area serve) replays Go's answers through
//! it. A file server with descriptors, symlink policy and precompressed
//! variants is the sibling module `staticfiles`.

const std = @import("std");
const Server = @import("Server.zig");
const conditional = @import("conditional.zig");
const range = @import("range.zig");
const sniff = @import("sniff.zig");

pub const Options = struct {
    /// The `Content-Type`. Null: keep one the handler already set, else
    /// sniff the first 512 bytes (`sniff.detectContentType`), as Go does
    /// when the name has no known extension.
    content_type: ?[]const u8 = null,
    /// The representation's entity tag, quoted (`"v1"`, `W/"v1"`), sent as
    /// `ETag` and compared by the preconditions. Go reads it from the
    /// handler's `ETag` header; here it is passed.
    etag: ?[]const u8 = null,
    /// Last modification, epoch seconds. Sent as `Last-Modified` and used by
    /// the date preconditions; null or 0 = none (Go's zero time and Unix 0).
    last_modified: ?i64 = null,
};

pub const Error = Server.ResponseWriter.SetHeaderError || std.Io.Writer.Error;

/// Answer `req` with `content`, Go `ServeContent`'s way. Call it before
/// anything is written; it writes the whole response (status, headers and
/// body, or no body for HEAD/304/412). A Range set whose parts add up to more
/// than the representation is served whole (200), as Go does — the
/// amplification bound `range.applyBounded` exists for.
pub fn serveContent(req: *const Server.Request, rw: *Server.ResponseWriter, content: []const u8, opts: Options) Error!void {
    const last_modified: ?i64 = if (opts.last_modified) |t| (if (t == 0) null else t) else null;
    var date_buf: [Server.http_date_len]u8 = undefined;
    if (last_modified) |t| try rw.setHeader("Last-Modified", Server.formatHttpDate(t, &date_buf));

    const v: conditional.Validators = .{ .etag = opts.etag, .last_modified = last_modified, .exists = true };
    if (try conditional.apply(req, rw, v)) {
        // A 304 carries the validators, not the representation's metadata
        // (RFC 9110 §15.4.5): Go drops Content-Type/-Length/-Encoding, and
        // Last-Modified when an ETag is there to identify it.
        if (rw.status == 304) {
            try rw.delHeader("Content-Type");
            try rw.delHeader("Content-Encoding");
            if (opts.etag != null) try rw.delHeader("Last-Modified");
        }
        return;
    }

    const ct: []const u8 = opts.content_type orelse rw.getHeader("Content-Type") orelse sniff.detectContentType(content);
    try rw.setHeader("Content-Type", ct);

    var ranges: [range.default_max_ranges]range.ResolvedRange = undefined;
    const applied: range.Applied = if (conditional.ifRangeAllows(req, v))
        try range.applyBounded(req, rw, content.len, &ranges, content.len)
    else
        .{ .outcome = .no_range, .ranges = &.{} };

    const body = req.method != .head;
    var len_buf: [20]u8 = undefined;
    switch (applied.outcome) {
        .no_range => {
            try rw.setHeader("Accept-Ranges", "bytes");
            try setLength(rw, &len_buf, content.len);
            if (body) try rw.writeAll(content);
        },
        .single => {
            const r = applied.ranges[0];
            try setLength(rw, &len_buf, r.len());
            if (body) try rw.writeAll(content[@intCast(r.start)..@intCast(r.end + 1)]);
        },
        .not_satisfiable => {
            // `range.apply` staged 416 + `Content-Range: bytes */N`; Go's body.
            try rw.writeError(416, "invalid range: failed to overlap");
        },
        .multiple => {
            var boundary_buf: [boundary_len]u8 = undefined;
            const mp: range.MultipartRanges = .{ .boundary = boundary(content, opts.etag, &boundary_buf), .content_type = ct };
            mp.setContentType(rw) catch |err| switch (err) {
                error.BoundaryTooLong => unreachable, // boundary_len < 70
                else => |e| return e,
            };
            try setLength(rw, &len_buf, mp.bodyLen(applied.ranges));
            if (body) mp.writeBody(rw.writer(), applied.ranges, content) catch |err| switch (err) {
                error.RangeOutOfBounds => unreachable, // resolved against content.len
                else => |e| return e,
            };
        },
    }
}

fn setLength(rw: *Server.ResponseWriter, buf: *[20]u8, n: u64) Server.ResponseWriter.SetHeaderError!void {
    // A body the handler marked as encoded is not `content`'s length (Go
    // leaves the length out then too).
    if (rw.getHeader("Content-Encoding") != null) return;
    try rw.setHeader("Content-Length", std.fmt.bufPrint(buf, "{d}", .{n}) catch unreachable);
}

const boundary_len = 32;

/// A multipart boundary that does not occur in `content` (RFC 2046 §5.1.1):
/// hex of a hash over the representation, re-drawn on the (adversarial-only)
/// chance it appears inside it. Deterministic, so a cache sees the same
/// bytes for the same answer; Go draws a random one instead.
fn boundary(content: []const u8, etag: ?[]const u8, buf: *[boundary_len]u8) []const u8 {
    var salt: u64 = 0;
    while (true) : (salt += 1) {
        var h = std.hash.Wyhash.init(salt);
        h.update(content);
        if (etag) |e| h.update(e);
        const a = h.final();
        const b = std.hash.Wyhash.hash(a, content);
        _ = std.fmt.bufPrint(buf, "{x:0>16}{x:0>16}", .{ a, b }) catch unreachable;
        if (std.mem.indexOf(u8, content, buf) == null) return buf;
    }
}

const testing = std.testing;

const Fixture = struct {
    var content: []const u8 = "";
    var opts: Options = .{};

    fn handler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
        try serveContent(req, rw, content, opts);
    }
};

fn run(wire: []const u8, out: []u8) ![]const u8 {
    var in: std.Io.Reader = .fixed(wire);
    var w: std.Io.Writer = .fixed(out);
    var head: [2048]u8 = undefined;
    var req_body: [64]u8 = undefined;
    var resp_body: [256]u8 = undefined;
    var chunk: [64]u8 = undefined;
    Server.serveStream(.{ .handler = Fixture.handler, .server_name = null }, &in, &w, .{
        .head = &head,
        .request_body = &req_body,
        .response_body = &resp_body,
        .chunk = &chunk,
    });
    return w.buffered();
}

test "serveContent: 200 with sniffed type, length, Last-Modified and Accept-Ranges" {
    Fixture.content = "<html><p>hi</p></html>";
    Fixture.opts = .{ .etag = "\"v1\"", .last_modified = 784111777 };
    var out: [1024]u8 = undefined;
    const resp = try run("GET /x HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &out);
    try testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 200 "));
    for ([_][]const u8{
        "\r\nContent-Type: text/html; charset=utf-8\r\n",
        "\r\nLast-Modified: Sun, 06 Nov 1994 08:49:37 GMT\r\n",
        "\r\nETag: \"v1\"\r\n",
        "\r\nAccept-Ranges: bytes\r\n",
        "\r\nContent-Length: 22\r\n",
    }) |line| try testing.expect(std.mem.indexOf(u8, resp, line) != null);
    try testing.expect(std.mem.endsWith(u8, resp, "\r\n\r\n<html><p>hi</p></html>"));
}

test "serveContent: HEAD has the GET head and no body; 304 drops the metadata" {
    Fixture.content = "0123456789";
    Fixture.opts = .{ .etag = "\"v1\"", .last_modified = 784111777, .content_type = "text/plain" };
    var out: [1024]u8 = undefined;
    const head = try run("HEAD /x HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &out);
    try testing.expect(std.mem.indexOf(u8, head, "\r\nContent-Length: 10\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, head, "\r\n\r\n"));

    var out2: [1024]u8 = undefined;
    const nm = try run("GET /x HTTP/1.1\r\nHost: t\r\nIf-None-Match: \"v1\"\r\nConnection: close\r\n\r\n", &out2);
    try testing.expect(std.mem.startsWith(u8, nm, "HTTP/1.1 304 "));
    try testing.expect(std.mem.indexOf(u8, nm, "\r\nETag: \"v1\"\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, nm, "Content-Type") == null);
    try testing.expect(std.mem.indexOf(u8, nm, "Last-Modified") == null);
}

test "serveContent: one range, several ranges, an unsatisfiable range, an oversized set" {
    Fixture.content = "0123456789" ** 10;
    Fixture.opts = .{ .content_type = "text/plain" };
    var out: [2048]u8 = undefined;
    const one = try run("GET /x HTTP/1.1\r\nHost: t\r\nRange: bytes=10-14\r\nConnection: close\r\n\r\n", &out);
    try testing.expect(std.mem.startsWith(u8, one, "HTTP/1.1 206 "));
    try testing.expect(std.mem.indexOf(u8, one, "\r\nContent-Range: bytes 10-14/100\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, one, "\r\n\r\n01234"));

    var out2: [2048]u8 = undefined;
    const many = try run("GET /x HTTP/1.1\r\nHost: t\r\nRange: bytes=0-1,98-\r\nConnection: close\r\n\r\n", &out2);
    try testing.expect(std.mem.startsWith(u8, many, "HTTP/1.1 206 "));
    const ct = responseHeader(many, "Content-Type").?;
    try testing.expect(std.mem.startsWith(u8, ct, "multipart/byteranges; boundary="));
    const b = ct["multipart/byteranges; boundary=".len..];
    const body = many[std.mem.indexOf(u8, many, "\r\n\r\n").? + 4 ..];
    try testing.expectEqual(try std.fmt.parseInt(usize, responseHeader(many, "Content-Length").?, 10), body.len);
    try testing.expect(std.mem.indexOf(u8, body, "Content-Range: bytes 0-1/100\r\n\r\n01\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, body, "Content-Range: bytes 98-99/100\r\n\r\n89\r\n") != null);
    var close_buf: [64]u8 = undefined;
    try testing.expect(std.mem.endsWith(u8, body, try std.fmt.bufPrint(&close_buf, "--{s}--\r\n", .{b})));

    var out3: [2048]u8 = undefined;
    const none = try run("GET /x HTTP/1.1\r\nHost: t\r\nRange: bytes=200-\r\nConnection: close\r\n\r\n", &out3);
    try testing.expect(std.mem.startsWith(u8, none, "HTTP/1.1 416 "));
    try testing.expectEqualStrings("bytes */100", responseHeader(none, "Content-Range").?);

    var out4: [2048]u8 = undefined;
    const big = try run("GET /x HTTP/1.1\r\nHost: t\r\nRange: bytes=0-,0-\r\nConnection: close\r\n\r\n", &out4);
    try testing.expect(std.mem.startsWith(u8, big, "HTTP/1.1 200 "));
}

test "serveContent: the boundary is deterministic and absent from the content" {
    var buf: [boundary_len]u8 = undefined;
    var again: [boundary_len]u8 = undefined;
    const content = "--0123456789abcdef--" ** 8;
    const b = boundary(content, "\"v1\"", &buf);
    try testing.expectEqualStrings(b, boundary(content, "\"v1\"", &again));
    try testing.expect(std.mem.indexOf(u8, content, b) == null);
    try testing.expect(!std.mem.eql(u8, b, boundary(content, "\"v2\"", &again)));
}

fn responseHeader(resp: []const u8, name: []const u8) ?[]const u8 {
    const head_end = std.mem.indexOf(u8, resp, "\r\n\r\n") orelse resp.len;
    var lines = std.mem.splitSequence(u8, resp[0..head_end], "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (std.ascii.eqlIgnoreCase(line[0..colon], name)) return std.mem.trim(u8, line[colon + 1 ..], " ");
    }
    return null;
}
