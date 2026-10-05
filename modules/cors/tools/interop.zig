// SPDX-License-Identifier: MIT

//! The CORS policy against a real browser: headless Google Chrome, driven
//! over the DevTools protocol by `tools/browser_oracle.js` (bun), runs
//! `fetch()` from pages on several origins against this module's
//! middleware, and its verdict -- did the script get the response, which
//! response headers could it read -- must be what the configured policy
//! says. The requests Chrome actually sent and the heads this module
//! answered are frozen in `src/browser_oracle_vectors.zig`, which
//! `src/browser_oracle_test.zig` replays offline in `test-cors`.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-cors` runs it and
//! `zig build check-interop` compiles it. No network: everything is on
//! 127.0.0.1. It needs `bun` and `google-chrome`; a missing one is a
//! failure, not a skip.
//!
//!   zig build interop-cors                 # re-take, write src/browser_oracle_vectors.zig
//!   zig build interop-cors -- --check      # re-take, compare with the committed file
//!
//! `serve CONFIGS.json LOG.jsonl BASE_PORT` is the mode the driver starts:
//! one `http.Server` + `router` + `cors` per configuration on loopback port
//! BASE_PORT + its index (printed as one JSON line), every request and the
//! head answered to it appended to LOG, until stdin closes.

const std = @import("std");
const http = @import("http");
const router = @import("router");
const cors = @import("cors");

const Config = struct {
    /// "none", "any", or a list of origins.
    origins: std.json.Value,
    methods: []const []const u8,
    /// "reflect", or a list of header names.
    headers: std.json.Value,
    expose: []const []const u8 = &.{},
    credentials: bool = false,
    max_age: ?u32 = null,
    unconditional: bool = false,
};

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
    try s.objectField("method");
    try s.write(ctx.req.method.token());
    try s.objectField("target");
    try s.write(ctx.req.target);
    try s.objectField("headers");
    try s.beginArray();
    var it = ctx.req.iterateHeaders();
    while (it.next()) |h| try s.write([2][]const u8{ h.name, h.value });
    try s.endArray();
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

/// The response every route answers: two headers a script may or may not
/// be allowed to read, and a body.
fn hOk(ctx: *router.Ctx) anyerror!void {
    try ctx.res.setHeader("X-Total", "7");
    try ctx.res.setHeader("X-Secret", "s");
    try ctx.res.setHeader("Content-Type", "text/plain");
    try ctx.res.writeAll("ok");
}

/// The static posture's configurations, served after the gated ones (ports
/// BASE_PORT + configs.len + j). Comptime data, so they live here and not in
/// CONFIGS.json; `src/browser_oracle_test.zig` holds the same two, and the
/// driver's `STATICS` describes them to its policy model.
pub const statics = [_]cors.StaticOptions{
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

fn options(arena: std.mem.Allocator, c: Config) !cors.Options {
    var o: cors.Options = .{};
    switch (c.origins) {
        .string => |s| o.allowed_origins = if (std.mem.eql(u8, s, "any")) .any else .none,
        .array => |a| {
            const list = try arena.alloc([]const u8, a.items.len);
            for (a.items, list) |v, *d| d.* = v.string;
            o.allowed_origins = .{ .list = list };
        },
        else => return error.BadConfig,
    }
    const methods = try arena.alloc(http.Method, c.methods.len);
    for (c.methods, methods) |name, *m| {
        const lower = try std.ascii.allocLowerString(arena, name);
        m.* = std.meta.stringToEnum(http.Method, lower) orelse return error.BadConfig;
    }
    o.allowed_methods = methods;
    switch (c.headers) {
        .string => o.allowed_headers = .reflect,
        .array => |a| {
            const list = try arena.alloc([]const u8, a.items.len);
            for (a.items, list) |v, *d| d.* = v.string;
            o.allowed_headers = .{ .list = list };
        },
        else => return error.BadConfig,
    }
    o.exposed_headers = c.expose;
    o.allow_credentials = c.credentials;
    o.max_age_s = c.max_age;
    o.allow_unconditional_wildcard = c.unconditional;
    return o;
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

    const gated = configs.len;
    const n = gated + statics.len;
    const corses = try arena.alloc(cors.Cors, gated);
    const taps = try arena.alloc(Tap, n);
    const routers = try arena.alloc(router.Router, n);
    const servers = try arena.alloc(http.Server, n);
    const threads = try arena.alloc(std.Thread, n);
    var out: std.Io.Writer.Allocating = .init(arena);
    try out.writer.writeAll("{\"ports\":[");
    for (0..n) |i| {
        taps[i] = .{ .index = i, .log = &log };
        routers[i] = router.Router.init(gpa);
        try routers[i].use(.{ .state = &taps[i], .run = tapRun });
        if (i < gated) {
            corses[i] = try .init(gpa, try options(arena, configs[i]));
            try routers[i].use(corses[i].middleware());
        } else switch (i - gated) {
            inline 0...statics.len - 1 => |j| try routers[i].use(.{ .state = null, .run = StaticMw(statics[j]).run }),
            else => unreachable,
        }
        for ([_]http.Method{ .get, .head, .post, .put, .delete, .patch, .options }) |m|
            try routers[i].add(m, "/*path", hOk);
        servers[i] = .init(io, gpa, .{
            .handler = routers[i].handler(),
            .context = &routers[i],
            .addr = "127.0.0.1",
            .port = base_port + @as(u16, @intCast(i)),
            .server_name = null,
            // Fixed ports, re-taken run after run: the last run's TIME-WAIT.
            .reuse_address = true,
        });
        servers[i].bind() catch |e| {
            std.debug.print("bind 127.0.0.1:{d}: {t} ({s})\n", .{ base_port + i, e, servers[i].bindErrorName() orelse "?" });
            return e;
        };
        if (i != 0) try out.writer.writeByte(',');
        try out.writer.print("{d}", .{servers[i].boundAddress().getPort()});
        threads[i] = try std.Thread.spawn(.{}, serveThread, .{&servers[i]});
    }
    try out.writer.writeAll("]}\n");
    var obuf: [64]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &obuf);
    try stdout.interface.writeAll(out.written());
    try stdout.interface.flush();

    // Until the driver closes our stdin.
    var ibuf: [64]u8 = undefined;
    var stdin = std.Io.File.stdin().readerStreaming(io, &ibuf);
    _ = stdin.interface.discardRemaining() catch {};

    for (servers, threads, routers) |*s, t, *r| {
        s.shutdown();
        t.join();
        s.deinit();
        r.deinit();
    }
    for (corses) |*c| c.deinit();
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
            std.debug.print("usage: interop-cors [--check] | serve CONFIGS.json LOG.jsonl BASE_PORT\n", .{});
            return 2;
        }
    }

    // The driver: bun runs Chrome and starts this binary again in `serve` mode.
    const self = try std.process.executablePathAlloc(io, arena);
    const env = try init.environ.createMap(arena);
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(arena, &.{ "bun", "modules/cors/tools/browser_oracle.js", "--server", self });
    if (check) try argv.append(arena, "--check");
    // `bun` on PATH, else where its installer puts it (a PATH set up by a
    // login shell is not always the one a build step inherits).
    const home_bun = if (env.get("HOME")) |h| try std.fmt.allocPrint(arena, "{s}/.bun/bin/bun", .{h}) else "bun";
    var child = std.process.spawn(io, .{
        .argv = argv.items,
        .environ_map = &env,
        .stdin = .close,
        .stdout = .inherit,
        .stderr = .inherit,
    }) catch retry: {
        argv.items[0] = home_bun;
        break :retry std.process.spawn(io, .{
            .argv = argv.items,
            .environ_map = &env,
            .stdin = .close,
            .stdout = .inherit,
            .stderr = .inherit,
        }) catch |e| {
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
