// SPDX-License-Identifier: MIT

//! OFFLINE replay of the browser oracle (`tools/interop.zig`,
//! `tools/browser_oracle.js`; answers frozen in `browser_oracle_vectors.zig`).
//! Headless Chrome ran `fetch()` from two origins against this module's
//! middleware under 16 gated configurations and 2 of the static posture;
//! no Chrome, no bun at test time.
//!
//! Two things are held:
//!   - Chrome's verdict -- did the script get the response, could it read
//!     `X-Total` / `X-Secret` -- is what the configured policy says (the
//!     Fetch Standard's CORS checks applied to the configuration, in the
//!     driver), case by case;
//!   - the middleware still answers every request Chrome sent with the head
//!     Chrome judged: same status, same `Access-Control-*` and `Vary`
//!     fields in the same order. A changed answer is a verdict nobody has
//!     taken -- re-run `zig build interop-cors`.

const std = @import("std");
const testing = std.testing;
const http = @import("http");
const router = @import("router");
const cors = @import("root.zig");
const vectors = @import("browser_oracle_vectors.zig");

fn hOk(ctx: *router.Ctx) anyerror!void {
    try ctx.res.setHeader("X-Total", "7");
    try ctx.res.setHeader("X-Secret", "s");
    try ctx.res.setHeader("Content-Type", "text/plain");
    try ctx.res.writeAll("ok");
}

/// tools/interop.zig's `statics`, the same two (a drift shows as a replay mismatch).
const statics = [_]cors.StaticOptions{
    .{},
    .{ .allow_origin = "http://127.0.0.1:18601", .allow_methods = "GET, PUT", .allow_headers = "X-A", .max_age_s = 0, .expose_headers = "X-Total" },
};

fn StaticMw(comptime o: cors.StaticOptions) type {
    return struct {
        fn run(_: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
            if (cors.isPreflight(ctx.req)) return cors.applyPreflightStatic(o, ctx.req, ctx.res);
            try cors.applyActualStatic(o, ctx.res);
            return next.run(ctx);
        }
    };
}

fn serveOne(r: *router.Router, bytes: []const u8, out_buf: []u8) []const u8 {
    var in: std.Io.Reader = .fixed(bytes);
    var out: std.Io.Writer = .fixed(out_buf);
    var head_buf: [4096]u8 = undefined;
    var request_body_buf: [256]u8 = undefined;
    var response_body_buf: [512]u8 = undefined;
    var chunk_buf: [128]u8 = undefined;
    http.Server.serveStream(.{ .handler = r.handler(), .context = r, .server_name = null }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    return out.buffered();
}

test "browser oracle: Chrome's verdict is the configured policy" {
    var bad: usize = 0;
    for (vectors.cases) |c| {
        if (c.ok != c.want_ok or c.total != c.want_total or c.secret != c.want_secret) {
            bad += 1;
            std.debug.print("config {d} origin {d} {s}: chrome ok={} total={} secret={}, policy ok={} total={} secret={}\n", .{
                c.config, c.origin, c.name, c.ok, c.total, c.secret, c.want_ok, c.want_total, c.want_secret,
            });
        }
    }
    try testing.expectEqual(@as(usize, 0), bad);
}

test "browser oracle: the middleware answers what Chrome judged" {
    comptime std.debug.assert(statics.len == vectors.statics_len);
    const n = vectors.configs.len + statics.len;
    var corses: [vectors.configs.len]cors.Cors = undefined;
    var routers: [n]router.Router = undefined;
    for (&routers, 0..) |*r, i| {
        r.* = router.Router.init(testing.allocator);
        if (i < vectors.configs.len) {
            corses[i] = try .init(testing.allocator, vectors.configs[i]);
            try r.use(corses[i].middleware());
        } else switch (i - vectors.configs.len) {
            inline 0...statics.len - 1 => |j| try r.use(.{ .state = null, .run = StaticMw(statics[j]).run }),
            else => unreachable,
        }
        for ([_]http.Method{ .get, .head, .post, .put, .delete, .patch, .options }) |m| try r.add(m, "/*path", hOk);
    }
    defer {
        for (&routers) |*r| r.deinit();
        for (&corses) |*c| c.deinit();
    }

    var bad: usize = 0;
    var exchanges: usize = 0;
    var buf: [4096]u8 = undefined;
    for (vectors.cases) |c| for (c.exchanges) |e| {
        exchanges += 1;
        const got = serveOne(&routers[c.config], e.request, &buf);
        const end = std.mem.indexOf(u8, got, "\r\n\r\n") orelse got.len;
        var lines = std.mem.splitSequence(u8, got[0..end], "\r\n");
        const status_line = lines.next() orelse "";
        const status = if (status_line.len >= 12) std.fmt.parseInt(u16, status_line[9..12], 10) catch 0 else 0;
        var i: usize = 0;
        var same = status == e.status;
        while (lines.next()) |line| {
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
            const name = line[0..colon];
            const value = std.mem.trim(u8, line[colon + 1 ..], " ");
            const cors_field = std.ascii.startsWithIgnoreCase(name, "access-control-") or std.ascii.eqlIgnoreCase(name, "vary");
            if (!cors_field) continue;
            if (i >= e.head.len or !std.mem.eql(u8, e.head[i][0], name) or
                !std.mem.eql(u8, std.mem.trim(u8, e.head[i][1], " "), value)) same = false;
            i += 1;
        }
        if (i != e.head.len) same = false;
        if (!same) {
            bad += 1;
            if (bad <= 10) std.debug.print("config {d} {s}:\n--- request\n{s}--- frozen status {d}, {d} fields; got\n{s}\n", .{
                c.config, c.name, e.request, e.status, e.head.len, got[0..end],
            });
        }
    };
    try testing.expectEqual(@as(usize, 0), bad);
    // Measured 2026-10-05: 448 fetches, every one reaching the middleware at least once.
    try testing.expect(exchanges >= vectors.cases.len);
}
