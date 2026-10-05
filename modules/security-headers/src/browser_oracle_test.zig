// SPDX-License-Identifier: MIT

//! OFFLINE replay of the browser oracle (`tools/interop.zig`,
//! `tools/browser_oracle.js`; frozen in `browser_oracle_vectors.zig`).
//! Headless Chrome loaded a page and its subresources from this middleware
//! under seven configurations (the defaults, both CSP postures, report-only,
//! a relaxed set, SAMEORIGIN, and a malformed negative control) and, from
//! another origin, framed it, embedded its image and opened it.
//!
//! Held here, with no Chrome: what Chrome observed is what the headers are
//! specified to cause (scripts, inline style, data: image, Referer, framing,
//! CORP, COOP), Chrome had no complaint about any real configuration's
//! header and did complain about the control's -- and the middleware still
//! sets exactly the header set Chrome judged.

const std = @import("std");
const testing = std.testing;
const http = @import("http");
const router = @import("router");
const sh = @import("root.zig");
const vectors = @import("browser_oracle_vectors.zig");

fn hOk(ctx: *router.Ctx) anyerror!void {
    try ctx.res.setHeader("Content-Type", "text/html; charset=utf-8");
    try ctx.res.writeAll("<!doctype html>");
}

fn managed(name: []const u8) bool {
    const names = [_][]const u8{
        "Strict-Transport-Security",    "Content-Security-Policy",    "Content-Security-Policy-Report-Only",
        "X-Content-Type-Options",       "X-Frame-Options",            "Referrer-Policy",
        "Permissions-Policy",           "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy",
        "Cross-Origin-Embedder-Policy", "Server",
    };
    for (names) |n| if (std.ascii.eqlIgnoreCase(n, name)) return true;
    return false;
}

fn seenEql(a: vectors.Seen, b: vectors.Seen) bool {
    return a.inline_script == b.inline_script and a.ext_script == b.ext_script and a.plain_script == b.plain_script and
        a.inline_style == b.inline_style and a.data_img == b.data_img and std.mem.eql(u8, a.referer, b.referer) and
        a.framed == b.framed and a.corp_img == b.corp_img and a.opener_severed == b.opener_severed;
}

test "browser oracle: Chrome did what the headers specify, and complained only about the control" {
    var bad: usize = 0;
    var controls: usize = 0;
    for (vectors.cases) |c| {
        if (!seenEql(c.seen, c.want)) {
            bad += 1;
            std.debug.print("{s}: chrome {any}\n  want {any}\n", .{ c.name, c.seen, c.want });
        }
        if (c.complaint_expected) controls += 1;
        if ((c.seen.complaints.len > 0) != c.complaint_expected) {
            bad += 1;
            std.debug.print("{s}: {d} complaints, expected {s}\n", .{ c.name, c.seen.complaints.len, if (c.complaint_expected) "some" else "none" });
        }
    }
    try testing.expectEqual(@as(usize, 0), bad);
    try testing.expect(controls == 1);
}

test "browser oracle: the middleware sets the header set Chrome judged" {
    var bad: usize = 0;
    for (vectors.cases) |c| {
        var set = try sh.SecurityHeaders.init(c.options);
        var r = router.Router.init(testing.allocator);
        defer r.deinit();
        try r.use(set.middleware());
        try r.get("/*path", hOk);

        var in: std.Io.Reader = .fixed("GET /c/page HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
        var buf: [8192]u8 = undefined;
        var out: std.Io.Writer = .fixed(&buf);
        var head_buf: [4096]u8 = undefined;
        var request_body_buf: [256]u8 = undefined;
        var response_body_buf: [512]u8 = undefined;
        var chunk_buf: [128]u8 = undefined;
        http.Server.serveStream(.{ .handler = r.handler(), .context = &r, .server_name = null }, &in, &out, .{
            .head = &head_buf,
            .request_body = &request_body_buf,
            .response_body = &response_body_buf,
            .chunk = &chunk_buf,
        });
        const got = out.buffered();
        const end = std.mem.indexOf(u8, got, "\r\n\r\n") orelse got.len;
        var lines = std.mem.splitSequence(u8, got[0..end], "\r\n");
        _ = lines.next();
        var i: usize = 0;
        var same = true;
        while (lines.next()) |line| {
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
            const name = line[0..colon];
            if (!managed(name)) continue;
            const value = std.mem.trim(u8, line[colon + 1 ..], " ");
            if (i >= c.head.len or !std.mem.eql(u8, c.head[i][0], name) or !std.mem.eql(u8, c.head[i][1], value)) same = false;
            i += 1;
        }
        if (i != c.head.len) same = false;
        if (!same) {
            bad += 1;
            std.debug.print("{s}: answered\n{s}\n", .{ c.name, got[0..end] });
        }
    }
    try testing.expectEqual(@as(usize, 0), bad);
}
