// SPDX-License-Identifier: MIT

//! Replays `chi_vectors.zig`: go-chi/chi v5.3.2's answers (`tools/go_chi_oracle`)
//! to this module's own seeded route tables and requests, against `Router`
//! with chi's trailing-slash posture (`.strict`). Per request: the status,
//! and on a 200 the matched pattern and every capture; on a 405, chi's
//! `Allow` methods must be a subset of ours (ours is the union over every
//! candidate the path reaches, RFC 9110 §15.5.6 — chi lists one node's).
//! No Go at test time.
//!
//! The generated requests stay where the two semantics coincide (no empty
//! capture, each delimiter at most once per segment — see the oracle's
//! `values`), and there every answer must agree. One normalization: chi's
//! `RoutePattern()` drops a pattern's trailing slash (`/users/` reports as
//! `/users`), this module reports the pattern as registered.
//!
//! The documented divergences (README "Patterns inside a segment") are a
//! crafted table of their own, each with this module's answer pinned here:
//!  - EMPTY: chi matches with an empty capture (`{name}.{ext}` on `.b`); here
//!    no capture is ever empty.
//!  - SPLIT: chi ends a capture at the first BYTE of the literal after it;
//!    here at the first occurrence of the whole literal, and the last capture
//!    at the literal suffix (`{id}suf` takes `asufsuf`; `{a}.json` wins
//!    `a.b.json` with `a.b`).

const std = @import("std");
const testing = std.testing;
const http = @import("http");
const router = @import("root.zig");
const v = @import("chi_vectors.zig");

fn echo(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll(ctx.matchedPattern().?);
    for (ctx.params.entries[0..ctx.params.len]) |e| {
        try ctx.res.writeAll("\x00");
        try ctx.res.writeAll(e.name);
        try ctx.res.writeAll("\x00");
        try ctx.res.writeAll(e.value);
    }
}

const Got = struct { status: u16, body: []const u8, allow: []const u8 };

fn ask(r: *router.Router, method: []const u8, path: []const u8, out_buf: []u8) !Got {
    var req_buf: [512]u8 = undefined;
    const wire = try std.fmt.bufPrint(&req_buf, "{s} {s} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", .{ method, path });
    var in: std.Io.Reader = .fixed(wire);
    var out: std.Io.Writer = .fixed(out_buf);
    var head_buf: [2048]u8 = undefined;
    var request_body_buf: [64]u8 = undefined;
    var response_body_buf: [1024]u8 = undefined;
    var chunk_buf: [128]u8 = undefined;
    http.Server.serveStream(.{ .handler = r.handler(), .context = r, .server_name = null }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    const resp = out.buffered();
    const status = try std.fmt.parseInt(u16, resp[9..12], 10);
    const head_end = std.mem.indexOf(u8, resp, "\r\n\r\n").?;
    var allow: []const u8 = "";
    if (std.mem.indexOf(u8, resp[0..head_end], "\r\nAllow: ")) |i| {
        const start = i + "\r\nAllow: ".len;
        allow = resp[start..std.mem.indexOfPos(u8, resp, start, "\r\n").?];
    }
    return .{ .status = status, .body = resp[head_end + 4 ..], .allow = allow };
}

/// The body `echo` would write for chi's answer.
fn chiBody(c: v.Case, buf: []u8) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    w.writeAll(c.pattern) catch unreachable;
    for (c.params) |p| w.print("\x00{s}\x00{s}", .{ p.name, p.value }) catch unreachable;
    return w.buffered();
}

fn methodOf(text: []const u8) http.Method {
    var lower: [16]u8 = undefined;
    return std.meta.stringToEnum(http.Method, std.ascii.lowerString(&lower, text)).?;
}

/// `got` (ours) is chi's answer, up to chi dropping a trailing slash from the
/// pattern it reports.
fn agrees(c: v.Case, got: Got) bool {
    if (got.status != c.status) return false;
    if (c.status != 200) return true;
    var want_buf: [1024]u8 = undefined;
    const want = chiBody(c, &want_buf);
    if (std.mem.eql(u8, got.body, want)) return true;
    // `/users/` registered, chi says `/users`.
    const pat_end = std.mem.indexOfScalar(u8, got.body, 0) orelse got.body.len;
    const ours_pat = got.body[0..pat_end];
    return ours_pat.len == c.pattern.len + 1 and ours_pat[ours_pat.len - 1] == '/' and
        std.mem.startsWith(u8, ours_pat, c.pattern) and
        std.mem.eql(u8, got.body[pat_end..], want[c.pattern.len..]);
}

test "chi oracle: every generated request answers as go-chi/chi does" {
    var bad: usize = 0;
    var cases: usize = 0;
    var by_status = [_]usize{ 0, 0, 0 };
    for (v.tables, 0..) |t, ti| {
        var r = router.Router.init(testing.allocator);
        defer r.deinit();
        r.trailing_slash = .strict;
        for (t.routes) |rt| r.add(methodOf(rt.method), rt.pattern, echo) catch |e| {
            bad += 1;
            std.debug.print("table {d}: chi registers {s} {s}, this router refuses it: {t}\n", .{ ti, rt.method, rt.pattern, e });
        };
        for (t.cases) |c| {
            cases += 1;
            var out_buf: [4096]u8 = undefined;
            const got = try ask(&r, c.method, c.path, &out_buf);
            if (!agrees(c, got)) {
                bad += 1;
                var want_buf: [1024]u8 = undefined;
                std.debug.print("table {d}: {s} {s}: chi {d} {s}, ours {d} {s}\n", .{ ti, c.method, c.path, c.status, chiBody(c, &want_buf), got.status, got.body });
                continue;
            }
            by_status[
                switch (c.status) {
                    200 => 0,
                    404 => 1,
                    else => 2,
                }
            ] += 1;
            // chi lists one node's methods; ours is the union over every
            // candidate, so it holds chi's.
            for (c.allow) |m| if (std.mem.indexOf(u8, got.allow, m) == null) {
                bad += 1;
                std.debug.print("table {d}: {s} {s}: chi's Allow has {s}, ours is \"{s}\"\n", .{ ti, c.method, c.path, m, got.allow });
            };
        }
    }
    try testing.expectEqual(@as(usize, 0), bad);
    // Teeth: the tables reach every outcome, mostly matches.
    try testing.expect(cases >= 3000 and by_status[0] >= 1000 and by_status[1] >= 500 and by_status[2] >= 300);
}

test "chi oracle: the documented divergences answer as this module documents, not as chi" {
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.trailing_slash = .strict;
    for (v.divergence_routes) |rt| try r.add(methodOf(rt.method), rt.pattern, echo);
    // Ours, in `v.divergences` order: status and `echo`'s body.
    const ours = [_]struct { u16, []const u8 }{
        .{ 404, "" }, // EMPTY: name would be ""
        .{ 404, "" }, // EMPTY: id would be ""
        .{ 404, "" }, // EMPTY: n would be ""
        .{ 404, "" }, // EMPTY, in the 405 domain: no candidate reaches the path
        .{ 200, "/x/{id}suf\x00id\x00asuf" }, // SPLIT: the last capture runs to the suffix
        .{ 200, "/w/{a}.json\x00a\x00a.b" }, // SPLIT: the whole literal, not its first byte
        .{ 200, "/q/a{x}b{y}c\x00x\x001\x00y\x002c" }, // SPLIT
    };
    comptime std.debug.assert(ours.len == v.divergences.len);
    for (v.divergences, ours) |c, want| {
        var out_buf: [4096]u8 = undefined;
        const got = try ask(&r, c.method, c.path, &out_buf);
        errdefer std.debug.print("divergence {s} {s}: ours {d} {s}\n", .{ c.method, c.path, got.status, got.body });
        try testing.expectEqual(want[0], got.status);
        if (want[0] == 200) try testing.expectEqualStrings(want[1], got.body);
        // Still a divergence: chi has not come round to this answer.
        try testing.expect(!agrees(c, got));
    }
}
