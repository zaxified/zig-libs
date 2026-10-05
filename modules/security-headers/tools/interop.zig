// SPDX-License-Identifier: MIT

//! The header set against a real browser: headless Google Chrome, driven by
//! `tools/browser_oracle.js` (bun), loads a page and its subresources from
//! this module's middleware under several configurations, frames it, embeds
//! its image and opens it from another origin, and reports what ran, what
//! loaded, what was sent and what it complained about. The heads this
//! module answered and Chrome's observations are frozen in
//! `src/browser_oracle_vectors.zig`, replayed by `src/browser_oracle_test.zig`
//! in `test-security-headers`.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-security-headers` runs
//! it and `zig build check-interop` compiles it. No network: everything is on
//! 127.0.0.1. It needs `bun` and `google-chrome`; a missing one is a failure.
//!
//!   zig build interop-security-headers               # re-take, write the vectors
//!   zig build interop-security-headers -- --check    # re-take, compare
//!
//! `serve CONFIGS.json LOG.jsonl BASE_PORT` is the mode the driver starts:
//! one `http.Server` + `router` + this middleware per configuration on port
//! BASE_PORT + its index, every response head appended to LOG.

const std = @import("std");
const http = @import("http");
const router = @import("router");
const sh = @import("security-headers");

/// One configuration, as the driver describes it: `null` leaves the field
/// at its default, `""` disables an optional header, `"@api"`/`"@helmet"`
/// name this module's own CSP postures.
const Config = struct {
    hsts: ?bool = null,
    csp: ?[]const u8 = null,
    csp_report_only: ?[]const u8 = null,
    nosniff: ?bool = null,
    x_frame_options: ?[]const u8 = null,
    referrer_policy: ?[]const u8 = null,
    permissions_policy: ?[]const u8 = null,
    coop: ?[]const u8 = null,
    corp: ?[]const u8 = null,
    coep: ?[]const u8 = null,
};

fn str(v: []const u8) ?[]const u8 {
    if (v.len == 0) return null;
    if (std.mem.eql(u8, v, "@api")) return sh.csp_api;
    if (std.mem.eql(u8, v, "@helmet")) return sh.csp_helmet_default;
    return v;
}

fn options(c: Config) sh.Options {
    var o: sh.Options = .{};
    if (c.hsts) |b| if (!b) {
        o.hsts = null;
    };
    if (c.csp) |v| o.content_security_policy = str(v);
    if (c.csp_report_only) |v| o.content_security_policy_report_only = str(v);
    if (c.nosniff) |b| o.x_content_type_options = b;
    if (c.x_frame_options) |v| o.x_frame_options = str(v);
    if (c.referrer_policy) |v| o.referrer_policy = str(v);
    if (c.permissions_policy) |v| o.permissions_policy = str(v);
    if (c.coop) |v| o.cross_origin_opener_policy = str(v);
    if (c.corp) |v| o.cross_origin_resource_policy = str(v);
    if (c.coep) |v| o.cross_origin_embedder_policy = str(v);
    return o;
}

const Log = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    file: std.Io.File,
    mutex: std.Io.Mutex = .init,
};

const Tap = struct { index: usize, log: *Log };

fn tapRun(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    const tap: *Tap = @ptrCast(@alignCast(state.?));
    try next.run(ctx);
    var line: std.Io.Writer.Allocating = .init(tap.log.gpa);
    defer line.deinit();
    var s: std.json.Stringify = .{ .writer = &line.writer };
    try s.beginObject();
    try s.objectField("cfg");
    try s.write(tap.index);
    try s.objectField("target");
    try s.write(ctx.req.target);
    try s.objectField("status");
    try s.write(ctx.res.status);
    try s.objectField("resp");
    try s.beginArray();
    for (ctx.res.headers[0..ctx.res.headers_len]) |h| try s.write([2][]const u8{ h.name, h.value });
    try s.endArray();
    try s.endObject();
    try line.writer.writeByte('\n');
    const log = tap.log;
    try log.mutex.lock(log.io);
    defer log.mutex.unlock(log.io);
    var buf: [256]u8 = undefined;
    var w = log.file.writerStreaming(log.io, &buf);
    try w.interface.writeAll(line.written());
    try w.interface.flush();
}

/// The page the browser loads: an inline script, a same-origin script, a
/// same-origin script served as text/plain, an inline style, a data: image.
pub const page =
    \\<!doctype html><html><head><title>sh</title>
    \\<style>#s{color:rgb(1, 2, 3)}</style>
    \\<script>window.inlineRan=1</script>
    \\<script src="s.js"></script>
    \\<script src="plain.js"></script>
    \\</head><body><div id="s">x</div>
    \\<img id="d" src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==">
    \\</body></html>
;
/// A 1x1 GIF, the image another origin embeds.
pub const gif = "GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;";

/// Every route's body. Shared with `src/browser_oracle_test.zig` in spirit:
/// the replay serves the same paths with the same content types.
fn hAny(ctx: *router.Ctx) anyerror!void {
    const path = ctx.req.path;
    const name = path[(std.mem.lastIndexOfScalar(u8, path, '/') orelse 0) + 1 ..];
    if (std.mem.eql(u8, name, "page")) {
        try ctx.res.setHeader("Content-Type", "text/html; charset=utf-8");
        try ctx.res.writeAll(page);
    } else if (std.mem.eql(u8, name, "s.js")) {
        try ctx.res.setHeader("Content-Type", "application/javascript");
        try ctx.res.writeAll("window.extRan=1;");
    } else if (std.mem.eql(u8, name, "plain.js")) {
        try ctx.res.setHeader("Content-Type", "text/plain");
        try ctx.res.writeAll("window.plainRan=1;");
    } else if (std.mem.eql(u8, name, "img.gif")) {
        try ctx.res.setHeader("Content-Type", "image/gif");
        try ctx.res.writeAll(gif);
    } else if (std.mem.eql(u8, name, "ref")) {
        try ctx.res.setHeader("Content-Type", "text/plain");
        try ctx.res.writeAll(ctx.req.header("Referer") orelse "-");
    } else {
        ctx.res.setStatus(404);
    }
}

fn serveThread(server: *http.Server) void {
    server.serve() catch {};
}

fn serve(io: std.Io, gpa: std.mem.Allocator, arena: std.mem.Allocator, configs_path: []const u8, log_path: []const u8, base_port: u16) !u8 {
    const cwd = std.Io.Dir.cwd();
    const text = try cwd.readFileAlloc(io, configs_path, arena, .limited(1 << 20));
    const configs = try std.json.parseFromSliceLeaky([]const Config, arena, text, .{});
    var log: Log = .{ .io = io, .gpa = gpa, .file = try cwd.createFile(io, log_path, .{}) };
    defer log.file.close(io);
    const n = configs.len;
    const sets = try arena.alloc(sh.SecurityHeaders, n);
    const taps = try arena.alloc(Tap, n);
    const routers = try arena.alloc(router.Router, n);
    const servers = try arena.alloc(http.Server, n);
    const threads = try arena.alloc(std.Thread, n);
    for (configs, 0..) |c, i| {
        sets[i] = try .init(options(c));
        taps[i] = .{ .index = i, .log = &log };
        routers[i] = router.Router.init(gpa);
        try routers[i].use(.{ .state = &taps[i], .run = tapRun });
        try routers[i].use(sets[i].middleware());
        try routers[i].get("/*path", hAny);
        servers[i] = .init(io, gpa, .{
            .handler = routers[i].handler(),
            .context = &routers[i],
            .addr = "127.0.0.1",
            .port = base_port + @as(u16, @intCast(i)),
            .server_name = null,
            .reuse_address = true,
        });
        servers[i].bind() catch |e| {
            std.debug.print("bind 127.0.0.1:{d}: {t}\n", .{ base_port + i, e });
            return e;
        };
        threads[i] = try std.Thread.spawn(.{}, serveThread, .{&servers[i]});
    }
    var obuf: [64]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &obuf);
    try stdout.interface.writeAll("ready\n");
    try stdout.interface.flush();
    var ibuf: [64]u8 = undefined;
    var stdin = std.Io.File.stdin().readerStreaming(io, &ibuf);
    _ = stdin.interface.discardRemaining() catch {};
    for (servers, threads, routers) |*s, t, *r| {
        s.shutdown();
        t.join();
        s.deinit();
        r.deinit();
    }
    return 0;
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

    var args = init.args.iterate();
    _ = args.skip();
    var check = false;
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "serve")) {
            const configs = args.next() orelse return 2;
            const log = args.next() orelse return 2;
            const base = std.fmt.parseInt(u16, args.next() orelse return 2, 10) catch return 2;
            return serve(io, gpa, arena, configs, log, base);
        } else if (std.mem.eql(u8, a, "--check")) {
            check = true;
        } else {
            std.debug.print("usage: interop-security-headers [--check] | serve CONFIGS.json LOG.jsonl BASE_PORT\n", .{});
            return 2;
        }
    }

    const self = try std.process.executablePathAlloc(io, arena);
    const env = try init.environ.createMap(arena);
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(arena, &.{ "bun", "modules/security-headers/tools/browser_oracle.js", "--server", self });
    if (check) try argv.append(arena, "--check");
    const home_bun = if (env.get("HOME")) |h| try std.fmt.allocPrint(arena, "{s}/.bun/bin/bun", .{h}) else "bun";
    var child = std.process.spawn(io, .{ .argv = argv.items, .environ_map = &env, .stdin = .close }) catch retry: {
        argv.items[0] = home_bun;
        break :retry std.process.spawn(io, .{ .argv = argv.items, .environ_map = &env, .stdin = .close }) catch |e| {
            std.debug.print("could not spawn bun ({t}) -- the browser oracle needs it\n", .{e});
            return 1;
        };
    };
    const term = try child.wait(io);
    return switch (term) {
        .exited => |code| code,
        else => 1,
    };
}
