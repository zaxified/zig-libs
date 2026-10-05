// SPDX-License-Identifier: MIT

//! OFFLINE differential anchor: Go's standard library net/http
//! (`http.FileServer` over `http.Dir`, `http.ServeContent`; go1.26,
//! BSD-3-Clause) as an independent implementation of this module. The file
//! tree and the requests are ours (`tools/go_oracle/main.go`); Go's answers,
//! taken over a real loopback socket from the very request bytes used here,
//! are in `go_oracle_vectors.zig`. This file builds the same tree, sends the
//! same bytes through `http.Server.serveStream` into a `Handler`, and
//! compares. No Go at test time. Only Go's observable answers were recorded;
//! no Go source was read or ported.
//!
//! Compared: the status; for a redirect, where it points (resolved against
//! the request path, since Go answers with relative Locations); for a 2xx,
//! the body; for `cond`, `Content-Range` and `Content-Length` too.
//!
//! Go is an oracle, not an authority: every case answered differently is
//! listed in `divergences` with the judgement; a differing case without an
//! entry fails, and so does an entry whose case has started to agree.

const std = @import("std");
const testing = std.testing;
const mem = std.mem;
const http = @import("http");
const staticfiles = @import("root.zig");
const vectors = @import("go_oracle_vectors.zig");

const Divergence = struct { id: []const u8, why: []const u8 };

/// Path-area cases this module answers differently from Go's FileServer.
/// Most are Go serving what this module refuses on purpose (SPEC threat
/// model); the rest are where Go canonicalizes with a redirect and we serve
/// or refuse the RFC 3986-normalized path directly.
const divergences = [_]Divergence{
    .{ .id = "p05", .why = "/a.txt/ names a directory: Go redirects to the file, we answer 404 like POSIX ENOTDIR, nginx and Apache (we served the file until 2026-10-05: an exact-path rule in front was bypassed by one slash)" },
    .{ .id = "p66", .why = "/a.txt%2f: as p05, the slash percent-encoded" },
    .{ .id = "p68", .why = "/dir/b.txt/. is /dir/b.txt/ after RFC 3986 dot-segment removal (http normalizes it): as p05. Go's path.Clean drops the slash and serves the file" },
    .{ .id = "p07", .why = "a NUL in the path: Go looks for the file (404), we refuse the request (400)" },
    .{ .id = "p79", .why = "as p07" },
    .{ .id = "p80", .why = "as p07" },
    .{ .id = "p13", .why = "/dir/index.html: Go redirects to the directory URL, we serve the index file at its own name (as nginx does); both are the same bytes" },
    .{ .id = "p14", .why = "as p13 for the root index" },
    .{ .id = "p22", .why = "an encoded dot-segment (..%2f): Go decodes then cleans and serves a.txt, we refuse a decoded '..' (403) -- literal ones are already removed by http's RFC 3986 normalization" },
    .{ .id = "p23", .why = "as p22, %2e%2e" },
    .{ .id = "p24", .why = "as p22; both refuse, Go with 404" },
    .{ .id = "p82", .why = "as p22, .%2e" },
    .{ .id = "p84", .why = "as p22, inside a directory" },
    .{ .id = "p29", .why = "a backslash: Go looks for a file named 'dir\\b.txt' (404), we refuse the byte (403) so no Windows-style separator ever reaches the OS" },
    .{ .id = "p30", .why = "as p29, %5c" },
    .{ .id = "p81", .why = "as p29" },
    .{ .id = "p32", .why = "a directory without an index: Go lists it, our listing is opt-in (Options.directory_listing) and off answers 403" },
    .{ .id = "p34", .why = "a dotfile: Go serves it, we refuse dotfiles unless Options.serve_dotfiles" },
    .{ .id = "p35", .why = "as p34: .env" },
    .{ .id = "p36", .why = "as p34, %2e-encoded" },
    .{ .id = "p37", .why = "as p34: .git/config" },
    .{ .id = "p38", .why = "as p34 and p32: .git/ listed by Go" },
    .{ .id = "p43", .why = "raw UTF-8 bytes in the request-target: RFC 9112 allows only ASCII there, http refuses the request line (400); the percent-encoded form (p41, p42) is served by both" },
    .{ .id = "p58", .why = "an in-root symlink: Go follows it, we refuse symlinks unless Options.follow_symlinks" },
    .{ .id = "p59", .why = "a symlink OUT of root: Go serves the file outside root, we refuse it (403)" },
    .{ .id = "p60", .why = "as p59, through a symlinked directory" },
    .{ .id = "p61", .why = "as p59: Go lists the directory outside root" },
    .{ .id = "p65", .why = "/%2f: Go cleans it to / and serves the index; we decode it to a directory route without a literal trailing slash and redirect to /%2f/, which then serves the index" },
    .{ .id = "p67", .why = "/dir/b.txt/.. is /dir/ after RFC 3986 dot-segment removal (http): we serve its index, Go redirects to it" },
    .{ .id = "p69", .why = "/. is / after dot-segment removal: we serve the index, Go redirects" },
    .{ .id = "p70", .why = "as p69 for /.." },
    .{ .id = "p71", .why = "as p67 for /dir/.." },
    .{ .id = "p72", .why = "as p67 for /dir/." },
    .{ .id = "p75", .why = "a 300-byte name: Go answers 500 (ENAMETOOLONG), we 404 -- no such file can exist (A1 F13)" },
    .{ .id = "p76", .why = "as p75 for a directory component (a Debug build of ours PANICKED here until 2026-10-05, see isSymlinkComponent)" },
    .{ .id = "m1", .why = "POST: Go's FileServer serves the file for any method, we answer 405 with Allow (RFC 9110 §15.5.6)" },
    .{ .id = "m2", .why = "as m1, PUT" },
    .{ .id = "m3", .why = "as m1, DELETE" },
    .{ .id = "m4", .why = "as m1, OPTIONS" },
    .{ .id = "m5", .why = "as m1, PATCH" },
};

/// Range shapes answered differently, whatever the preconditions (each
/// pinned to both statuses, so a third outcome still fails). RFC 9110 §14
/// decides each.
const RangeDivergence = struct { range: []const u8, go: u16, ours: u16, why: []const u8 };
const range_divergences = [_]RangeDivergence{
    .{ .range = "bytes=-0", .go = 206, .ours = 416, .why = "a zero suffix-length is unsatisfiable (RFC 9110 §14.1.1); Go answers 206 with the invalid Content-Range 'bytes 100-99/100'" },
    .{ .range = "items=0-9", .go = 416, .ours = 200, .why = "an unknown range unit MUST be ignored (RFC 9110 §14.2); Go answers 416" },
    .{ .range = "BYTES=0-9", .go = 416, .ours = 206, .why = "range units are case-insensitive (RFC 9110 §14.1); Go only knows 'bytes'" },
    .{ .range = "bytes=50-10", .go = 416, .ours = 200, .why = "an invalid range-spec (last < first): a server MAY ignore or reject it (RFC 9110 §14.2); we ignore, Go rejects" },
    .{ .range = "bytes=abc", .go = 416, .ours = 200, .why = "as bytes=50-10" },
    .{ .range = "bytes=-", .go = 416, .ours = 200, .why = "as bytes=50-10" },
    .{ .range = "bytes=0-9,20-29", .go = 206, .ours = 200, .why = "several ranges: Go answers multipart/byteranges, this module serves the whole representation (documented; a server MAY ignore Range)" },
    .{ .range = "bytes=0-9,5-14", .go = 206, .ours = 200, .why = "as bytes=0-9,20-29 (overlapping)" },
};

fn rangeOf(c: vectors.Case) ?[]const u8 {
    for (c.headers) |h| if (mem.startsWith(u8, h, "Range: ")) return h["Range: ".len..];
    return null;
}

const Tree = struct {
    tmp: testing.TmpDir,
    root: std.Io.Dir,

    fn init() !Tree {
        const io = testing.io;
        var tmp = testing.tmpDir(.{});
        errdefer tmp.cleanup();
        try tmp.dir.writeFile(io, .{ .sub_path = "secret.txt", .data = vectors.secret });
        var root = try tmp.dir.createDirPathOpen(io, "root", .{ .open_options = .{ .iterate = true } });
        errdefer root.close(io);
        for (vectors.files) |f| {
            if (mem.endsWith(u8, f.path, "/")) {
                var d = try root.createDirPathOpen(io, f.path[0 .. f.path.len - 1], .{});
                d.close(io);
            } else {
                try root.writeFile(io, .{ .sub_path = f.path, .data = f.data });
            }
        }
        for (vectors.links) |l| try root.symLink(io, l.target, l.path, .{});
        const ts: std.Io.Timestamp = .{ .nanoseconds = @as(i96, vectors.mtime_s) * std.time.ns_per_s };
        var i = vectors.files.len;
        while (i > 0) { // files before their directories
            i -= 1;
            const p = vectors.files[i].path;
            const sub = if (mem.endsWith(u8, p, "/")) p[0 .. p.len - 1] else p;
            try root.setTimestamps(io, sub, .{ .access_timestamp = .{ .new = ts }, .modify_timestamp = .{ .new = ts } });
        }
        return .{ .tmp = tmp, .root = root };
    }

    fn deinit(t: *Tree) void {
        t.root.close(testing.io);
        t.tmp.cleanup();
    }
};

fn runRequest(handler: *staticfiles.Handler, wire: []const u8, out_buf: []u8) []const u8 {
    var in: std.Io.Reader = .fixed(wire);
    var out: std.Io.Writer = .fixed(out_buf);
    var head_buf: [4096]u8 = undefined;
    var request_body_buf: [256]u8 = undefined;
    var response_body_buf: [512]u8 = undefined;
    var chunk_buf: [512]u8 = undefined;
    http.Server.serveStream(.{
        .handler = staticfiles.httpHandler,
        .context = handler,
        .server_name = "test",
    }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    return out.buffered();
}

const Response = struct {
    status: u16,
    location: ?[]const u8 = null,
    content_range: ?[]const u8 = null,
    content_length: ?[]const u8 = null,
    chunked: bool = false,
    body: []const u8 = "",
};

fn parseResponse(raw: []const u8, body_buf: []u8) !Response {
    if (raw.len < 12) return error.ShortResponse;
    var r: Response = .{ .status = try std.fmt.parseInt(u16, raw[9..12], 10) };
    const end = mem.indexOf(u8, raw, "\r\n\r\n") orelse return error.NoHeadEnd;
    var lines = mem.splitSequence(u8, raw[0..end], "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        const colon = mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = line[0..colon];
        const value = mem.trim(u8, line[colon + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(name, "Location")) r.location = value;
        if (std.ascii.eqlIgnoreCase(name, "Content-Range")) r.content_range = value;
        if (std.ascii.eqlIgnoreCase(name, "Content-Length")) r.content_length = value;
        if (std.ascii.eqlIgnoreCase(name, "Transfer-Encoding") and std.ascii.indexOfIgnoreCase(value, "chunked") != null) r.chunked = true;
    }
    const rest = raw[end + 4 ..];
    if (!r.chunked) {
        r.body = rest;
        return r;
    }
    var n: usize = 0;
    var p: usize = 0;
    while (true) {
        const eol = mem.indexOfPos(u8, rest, p, "\r\n") orelse return error.BadChunk;
        const size_text = rest[p..eol];
        const semi = mem.indexOfScalar(u8, size_text, ';') orelse size_text.len;
        const size = try std.fmt.parseInt(usize, size_text[0..semi], 16);
        p = eol + 2;
        if (size == 0) break;
        @memcpy(body_buf[n..][0..size], rest[p..][0..size]);
        n += size;
        p += size + 2;
    }
    r.body = body_buf[0..n];
    return r;
}

/// Resolve a Location against the request path, the way a browser would --
/// enough for the absolute-path and dot-relative forms both sides use.
fn resolve(buf: []u8, req_path: []const u8, loc: []const u8) []const u8 {
    if (loc.len > 0 and loc[0] == '/') return loc;
    const q = mem.indexOfAny(u8, req_path, "?#") orelse req_path.len;
    const dir_end = (mem.lastIndexOfScalar(u8, req_path[0..q], '/') orelse 0) + 1;
    var w: std.Io.Writer = .fixed(buf);
    w.writeAll(req_path[0..dir_end]) catch unreachable;
    const rel = if (mem.startsWith(u8, loc, "./")) loc[2..] else loc;
    w.writeAll(rel) catch unreachable;
    return w.buffered();
}

fn eqlOpt(a: ?[]const u8, b: ?[]const u8) bool {
    if (a == null or b == null) return a == null and b == null;
    return mem.eql(u8, a.?, b.?);
}

fn agrees(c: vectors.Case, r: Response) bool {
    if (r.status != c.status) return false;
    if (c.status >= 300 and c.status < 400) {
        var b1: [1024]u8 = undefined;
        var b2: [1024]u8 = undefined;
        if (c.location == null or r.location == null) return eqlOpt(c.location, r.location);
        return mem.eql(u8, resolve(&b1, c.target, c.location.?), resolve(&b2, c.target, r.location.?));
    }
    if (c.area == .cond) {
        if (!eqlOpt(c.content_range, r.content_range)) return false;
        if (c.status == 200 or c.status == 206) {
            if (!eqlOpt(c.content_length, r.content_length)) return false;
        }
    }
    if (c.status >= 200 and c.status < 300) return mem.eql(u8, c.body, r.body);
    return true;
}

test "go oracle: FileServer paths and ServeContent preconditions/ranges answer as Go's net/http" {
    const io = testing.io;
    var tree = try Tree.init();
    defer tree.deinit();
    var plain = staticfiles.Handler.init(io, tree.root, .{});
    var strong = staticfiles.Handler.init(io, tree.root, .{ .strong_etag = true });

    var seen = [_]bool{false} ** divergences.len;
    var range_seen = [_]bool{false} ** range_divergences.len;
    var bad: usize = 0;
    for (vectors.cases) |c| {
        var wire_buf: [4096]u8 = undefined;
        var ww: std.Io.Writer = .fixed(&wire_buf);
        try ww.print("{s} {s} HTTP/1.1\r\nHost: t\r\n", .{ c.method, c.target });
        for (c.headers) |h| try ww.print("{s}\r\n", .{h});
        try ww.writeAll("Connection: close\r\n\r\n");
        var out: [16384]u8 = undefined;
        const h = if (c.area == .cond and c.strong) &strong else &plain;
        const raw = runRequest(h, ww.buffered(), &out);
        var body_buf: [16384]u8 = undefined;
        const r = parseResponse(raw, &body_buf) catch |e| {
            std.debug.print("{s}: unparseable response ({t}): {s}\n", .{ c.id, e, raw });
            bad += 1;
            continue;
        };
        if (agrees(c, r)) continue;
        if (rangeOf(c)) |rg| {
            var hit = false;
            for (range_divergences, 0..) |d, i| if (mem.eql(u8, d.range, rg) and c.status == d.go and r.status == d.ours) {
                range_seen[i] = true;
                hit = true;
            };
            if (hit) continue;
        }
        var listed = false;
        for (divergences, 0..) |d, i| if (mem.eql(u8, d.id, c.id)) {
            seen[i] = true;
            listed = true;
        };
        if (listed) continue;
        bad += 1;
        std.debug.print("{s} {s} {s} {any}: go {d} loc={?s} cr={?s} cl={?s} body={d}B | ours {d} loc={?s} cr={?s} cl={?s} body={d}B\n", .{
            c.id,             c.method,   c.target,        c.headers,
            c.status,         c.location, c.content_range, c.content_length,
            c.body.len,       r.status,   r.location,      r.content_range,
            r.content_length, r.body.len,
        });
    }
    for (divergences, seen) |d, s| if (!s) {
        std.debug.print("divergence {s} agrees now: delete it\n", .{d.id});
        bad += 1;
    };
    for (range_divergences, range_seen) |d, s| if (!s) {
        std.debug.print("range divergence {s} agrees now: delete it\n", .{d.range});
        bad += 1;
    };
    try testing.expectEqual(@as(usize, 0), bad);
}
