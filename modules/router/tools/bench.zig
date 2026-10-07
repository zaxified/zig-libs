// SPDX-License-Identifier: MIT

//! Comparative benchmark: `router` against go-chi/chi v5.3.2 (the reference),
//! the program behind the `**Performance:**` line of the maturity card
//! (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-router` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26.0 and
//! github.com/go-chi/chi/v5 in the module cache (pinned by
//! `tools/go_bench/go.mod`/`go.sum`, the same version the chi oracle pins;
//! `GOPROXY=off`). Run from the repository root.
//!
//! Two workloads over one API-shaped table (25 routes: static, `{param}`,
//! in-segment captures, regexp constraints, a trailing `*`) and 32 requests
//! (hits, 404s, 405s):
//!   lookup   -- route lookup alone: our `Static(routes).match` (the same
//!               matcher `Router` runs, built at compile time) against chi's
//!               `Mux.Match` with a reset route context;
//!   serve    -- request bytes in, response bytes out: `http.Server.serveStream`
//!               over `Router` against Go's `http.ReadRequest` + chi
//!               `ServeHTTP` writing into a buffer. This one measures the http
//!               stacks as much as the routers, and says so in the output.
//! One op = all 32 requests. Both sides time the same way (double the batch
//! until it takes over 100 ms, best of five) and report a result count (matched
//! routes, or the sum of the status codes); a count that differs fails the run.
//! The verdict is the WORST ratio, ours/chi.

const std = @import("std");
const http = @import("http");
const router = @import("router");

const R = struct { m: http.Method, p: []const u8 };
const routes = [_]R{
    .{ .m = .get, .p = "/" },
    .{ .m = .get, .p = "/health" },
    .{ .m = .get, .p = "/users" },
    .{ .m = .post, .p = "/users" },
    .{ .m = .get, .p = "/users/{id}" },
    .{ .m = .put, .p = "/users/{id}" },
    .{ .m = .delete, .p = "/users/{id}" },
    .{ .m = .get, .p = "/users/{id}/repos" },
    .{ .m = .get, .p = "/users/{id}/repos/{repo}" },
    .{ .m = .get, .p = "/repos/{owner}/{repo}" },
    .{ .m = .get, .p = "/repos/{owner}/{repo}/issues" },
    .{ .m = .get, .p = "/repos/{owner}/{repo}/issues/{number:[0-9]+}" },
    .{ .m = .post, .p = "/repos/{owner}/{repo}/issues" },
    .{ .m = .get, .p = "/repos/{owner}/{repo}/pulls/{number:[0-9]+}/files" },
    .{ .m = .get, .p = "/orgs/{org}/members" },
    .{ .m = .get, .p = "/orgs/{org}/teams/{team}" },
    .{ .m = .get, .p = "/search/code" },
    .{ .m = .get, .p = "/search/issues" },
    .{ .m = .get, .p = "/api/v1/things" },
    .{ .m = .get, .p = "/api/v1/things/{id}" },
    .{ .m = .get, .p = "/api/v1/things/{id}/parts/{part}" },
    .{ .m = .get, .p = "/api/v2/things/{id}.{format}" },
    .{ .m = .get, .p = "/files/{name}.{ext}" },
    .{ .m = .get, .p = "/static/*" },
    .{ .m = .get, .p = "/v{version:[0-9]+}/status" },
};

const requests = [_]R{
    .{ .m = .get, .p = "/" },                              .{ .m = .get, .p = "/health" },
    .{ .m = .get, .p = "/users" },                         .{ .m = .post, .p = "/users" },
    .{ .m = .get, .p = "/users/42" },                      .{ .m = .put, .p = "/users/42" },
    .{ .m = .delete, .p = "/users/42" },                   .{ .m = .patch, .p = "/users/42" },
    .{ .m = .get, .p = "/users/42/repos" },                .{ .m = .get, .p = "/users/42/repos/zig" },
    .{ .m = .get, .p = "/repos/ziglang/zig" },             .{ .m = .get, .p = "/repos/ziglang/zig/issues" },
    .{ .m = .get, .p = "/repos/ziglang/zig/issues/1234" }, .{ .m = .get, .p = "/repos/ziglang/zig/issues/abc" },
    .{ .m = .post, .p = "/repos/ziglang/zig/issues" },     .{ .m = .get, .p = "/repos/ziglang/zig/pulls/77/files" },
    .{ .m = .get, .p = "/orgs/acme/members" },             .{ .m = .get, .p = "/orgs/acme/teams/core" },
    .{ .m = .get, .p = "/search/code" },                   .{ .m = .get, .p = "/search/issues" },
    .{ .m = .get, .p = "/search/users" },                  .{ .m = .get, .p = "/api/v1/things" },
    .{ .m = .get, .p = "/api/v1/things/7" },               .{ .m = .get, .p = "/api/v1/things/7/parts/9" },
    .{ .m = .get, .p = "/api/v2/things/7.json" },          .{ .m = .get, .p = "/files/report.pdf" },
    .{ .m = .get, .p = "/static/css/site.css" },           .{ .m = .get, .p = "/static/js/app/main.js" },
    .{ .m = .get, .p = "/v3/status" },                     .{ .m = .get, .p = "/vx/status" },
    .{ .m = .get, .p = "/nope" },                          .{ .m = .delete, .p = "/health" },
};

const static_routes: [routes.len]router.StaticRoute = blk: {
    var t: [routes.len]router.StaticRoute = undefined;
    for (routes, 0..) |r, i| t[i] = .{ .method = r.m, .pattern = r.p };
    const frozen = t;
    break :blk frozen;
};
const Table = router.Static(&static_routes, .{});

const work_dir = ".zig-cache/bench-router";

fn ok(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll("ok");
}

fn lookupAll() usize {
    var params: router.Params = .{};
    var found: usize = 0;
    for (requests) |q| {
        switch (Table.match(q.m, q.p, &params)) {
            .found => found += 1,
            else => {},
        }
    }
    return found;
}

const Wires = [requests.len][]const u8;

fn serveAll(r: *router.Router, wires: *const Wires) usize {
    var sum: usize = 0;
    var out_buf: [1024]u8 = undefined;
    var head_buf: [2048]u8 = undefined;
    var request_body_buf: [64]u8 = undefined;
    var response_body_buf: [1024]u8 = undefined;
    var chunk_buf: [128]u8 = undefined;
    for (wires) |wire| {
        var in: std.Io.Reader = .fixed(wire);
        var out: std.Io.Writer = .fixed(&out_buf);
        http.Server.serveStream(.{ .handler = r.handler(), .context = r, .server_name = null }, &in, &out, .{
            .head = &head_buf,
            .request_body = &request_body_buf,
            .response_body = &response_body_buf,
            .chunk = &chunk_buf,
        });
        const resp = out.buffered();
        sum += std.fmt.parseInt(u16, resp[9..12], 10) catch 0;
    }
    return sum;
}

fn timeIt(io: std.Io, ctx: anytype, comptime f: anytype) struct { ns: f64, count: usize } {
    var n: usize = 1;
    while (true) {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| std.mem.doNotOptimizeAway(@call(.auto, f, ctx));
        if (t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds > 100_000_000) break;
        n *= 2;
    }
    var best: i96 = std.math.maxInt(i96);
    var count: usize = 0;
    for (0..5) |_| {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| count = @call(.auto, f, ctx);
        best = @min(best, t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds);
    }
    return .{ .ns = @as(f64, @floatFromInt(best)) / @as(f64, @floatFromInt(n)), .count = count };
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();

    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    var dir = try cwd.openDir(io, work_dir, .{});
    defer dir.close(io);

    // The table and the requests the Go side reads: method TAB pattern/path.
    var list: std.Io.Writer.Allocating = .init(arena);
    for (routes) |r| try list.writer.print("{s}\t{s}\n", .{ r.m.token(), r.p });
    try dir.writeFile(io, .{ .sub_path = "routes.tsv", .data = list.written() });
    list.clearRetainingCapacity();
    for (requests) |q| try list.writer.print("{s}\t{s}\n", .{ q.m.token(), q.p });
    try dir.writeFile(io, .{ .sub_path = "requests.tsv", .data = list.written() });

    var env = try init.environ_map.clone(arena);
    try env.put("GOTOOLCHAIN", "go1.26.0");
    try env.put("GOPROXY", "off");
    try env.put("GOFLAGS", "-mod=readonly");
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);
    std.debug.print("bench-router: go-chi/chi ...\n", .{});
    const go = std.process.run(arena, io, .{
        .argv = &.{ "go", "run", ".", abs },
        .environ_map = &env,
        .cwd = .{ .path = "modules/router/tools/go_bench" },
    }) catch |e| {
        std.debug.print("bench-router: could not run go ({t}) -- the benchmark needs it\n", .{e});
        return 1;
    };
    if (go.term != .exited or go.term.exited != 0) {
        std.debug.print("bench-router: go_bench failed:\n{s}\n", .{go.stderr});
        return 1;
    }
    const GoRow = struct { ns: f64, count: usize };
    var go_rows: std.StringHashMapUnmanaged(GoRow) = .empty;
    var lines = std.mem.tokenizeScalar(u8, go.stdout, '\n');
    while (lines.next()) |line| {
        var f = std.mem.tokenizeScalar(u8, line, '\t');
        const name = f.next() orelse continue;
        const ns = try std.fmt.parseFloat(f64, f.next() orelse return error.BadGoOutput);
        const count = try std.fmt.parseInt(usize, f.next() orelse return error.BadGoOutput, 10);
        try go_rows.put(arena, name, .{ .ns = ns, .count = count });
    }

    // Our runtime Router, chi's trailing-slash posture.
    var r = router.Router.init(std.heap.smp_allocator);
    defer r.deinit();
    r.trailing_slash = .strict;
    for (routes) |rt| try r.add(rt.m, rt.p, ok);
    var wires: Wires = undefined;
    for (requests, 0..) |q, i| wires[i] = try std.fmt.allocPrint(arena, "{s} {s} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", .{ q.m.token(), q.p });

    const lookup = timeIt(io, .{}, lookupAll);
    const serve = timeIt(io, .{ &r, &wires }, serveAll);

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.print("{s:<8} {s:>14} {s:>14} {s:>8}  count (one op = {d} requests)\n", .{ "workload", "ours ns/op", "chi ns/op", "ours/chi", requests.len });
    var worst: f64 = 0;
    var best: f64 = std.math.inf(f64);
    var mismatch = false;
    for ([_]struct { []const u8, @TypeOf(lookup) }{ .{ "lookup", lookup }, .{ "serve", serve } }) |row| {
        const theirs = go_rows.get(row[0]) orelse {
            std.debug.print("bench-router: chi reported nothing for {s}\n", .{row[0]});
            return 1;
        };
        const ratio = row[1].ns / theirs.ns;
        worst = @max(worst, ratio);
        best = @min(best, ratio);
        const same = row[1].count == theirs.count;
        if (!same) mismatch = true;
        try w.print("{s:<8} {d:>14.1} {d:>14.1} {d:>8.2}  {d}{s}\n", .{ row[0], row[1].ns, theirs.ns, ratio, row[1].count, if (same) "" else " ≠ chi" });
    }
    if (mismatch) {
        try w.writeAll("bench-router: FAILED -- a result count differs from chi's; the timing means nothing until it agrees\n");
        try w.flush();
        return 1;
    }
    try w.writeAll("(serve includes each side's HTTP/1.1 parser and response writer, not only the router)\n");
    try w.print("\nworst ours/chi = {d:.2} (best {d:.2})\n", .{ worst, best });
    try w.print("card: **Performance:** ref {d:.2}–{d:.2}× go-chi/chi v5.3.2 · fastest ? (measured <today>)\n", .{ best, worst });
    try w.flush();
    return 0;
}
