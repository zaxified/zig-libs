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
//!
//! A second part answers "how far from the fastest in the field": the same
//! `lookup` over the PLAIN subset of the table (static segments, whole-segment
//! `{name}` captures, a trailing `*`; no regexp constraint, no capture inside a
//! segment -- what every colon-syntax router can express) against
//! julienschmidt/httprouter, labstack/echo and uptrace/bunrouter
//! (tools/go_fast_bench) and ibraheemdev/matchit (tools/rust_fast_bench). A
//! contender that cannot express a plain route exits 3 and is reported as
//! unsupported, never silently run on a different table. BENCH_FAST=0 skips it.

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
const fast_dir = "modules/router/tools/go_fast_bench";
const rust_manifest = "modules/router/tools/rust_fast_bench/Cargo.toml";
const rust_target = ".zig-cache/bench-router/rust-target";
const rust_exe = rust_target ++ "/release/rust_fast_bench";

const Contender = struct { name: []const u8, label: []const u8, rust: bool = false };
const contenders = [_]Contender{
    .{ .name = "httprouter", .label = "httprouter v1.3.0" },
    .{ .name = "echo", .label = "echo v4.16.2" },
    .{ .name = "bunrouter", .label = "bunrouter v1.0.23" },
    .{ .name = "matchit", .label = "matchit 0.9.2", .rust = true },
};

/// True when every segment is a literal, a whole-segment `{name}` or a final `*`.
fn isPlain(pattern: []const u8) bool {
    const specials = "{}:*";
    var it = std.mem.splitScalar(u8, pattern, '/');
    while (it.next()) |seg| {
        if (std.mem.findAny(u8, seg, specials) == null) continue;
        if (std.mem.eql(u8, seg, "*")) continue;
        if (seg.len > 2 and seg[0] == '{' and seg[seg.len - 1] == '}' and
            std.mem.findAny(u8, seg[1 .. seg.len - 1], specials) == null) continue;
        return false;
    }
    return true;
}

const plain_count = blk: {
    @setEvalBranchQuota(100_000);
    var n: usize = 0;
    for (routes) |r| {
        if (isPlain(r.p)) n += 1;
    }
    break :blk n;
};
const plain_routes: [plain_count]R = blk: {
    @setEvalBranchQuota(100_000);
    var t: [plain_count]R = undefined;
    var i: usize = 0;
    for (routes) |r| {
        if (isPlain(r.p)) {
            t[i] = r;
            i += 1;
        }
    }
    const frozen = t;
    break :blk frozen;
};
const plain_static: [plain_count]router.StaticRoute = blk: {
    var t: [plain_count]router.StaticRoute = undefined;
    for (plain_routes, 0..) |r, i| t[i] = .{ .method = r.m, .pattern = r.p };
    const frozen = t;
    break :blk frozen;
};
const PlainTable = router.Static(&plain_static, .{});

/// The requests the plain table is timed on, set once in main(): those on which
/// the full table and the plain table agree whether a route matches, so a
/// request is dropped exactly when it needed a route the plain subset lacks.
var plain_requests: []const R = &.{};

fn lookupPlain() usize {
    var params: router.Params = .{};
    var found: usize = 0;
    for (plain_requests) |q| {
        switch (PlainTable.match(q.m, q.p, &params)) {
            .found => found += 1,
            else => {},
        }
    }
    return found;
}

fn isFound(comptime T: type, q: R) bool {
    var params: router.Params = .{};
    return switch (T.match(q.m, q.p, &params)) {
        .found => true,
        else => false,
    };
}

const GoRow = struct { ns: f64, count: usize };

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
    // The plain subset, for the fastest-in-the-field contenders.
    var plain_buf: [requests.len]R = undefined;
    var n_plain: usize = 0;
    for (requests) |q| {
        if (isFound(Table, q) == isFound(PlainTable, q)) {
            plain_buf[n_plain] = q;
            n_plain += 1;
        }
    }
    plain_requests = plain_buf[0..n_plain];
    // `--plain-only [seconds]`: our plain-subset lookup alone, no foreign
    // side -- the loop to put under `perf` (default 3 s).
    const args = try init.minimal.args.toSlice(arena);
    if (args.len > 1 and std.mem.eql(u8, args[1], "--plain-only")) {
        const secs = if (args.len > 2) try std.fmt.parseFloat(f64, args[2]) else 3.0;
        const row = timeIt(io, .{}, lookupPlain);
        const reps: usize = @intFromFloat(secs * 1e9 / row.ns);
        var found: usize = 0;
        for (0..reps) |_| found +%= lookupPlain();
        std.mem.doNotOptimizeAway(found);
        std.debug.print("ours (plain) {d:.1} ns/op, count {d}\n", .{ row.ns, row.count });
        return 0;
    }
    list.clearRetainingCapacity();
    for (plain_routes) |r| try list.writer.print("{s}\t{s}\n", .{ r.m.token(), r.p });
    try dir.writeFile(io, .{ .sub_path = "routes_plain.tsv", .data = list.written() });
    list.clearRetainingCapacity();
    for (plain_requests) |q| try list.writer.print("{s}\t{s}\n", .{ q.m.token(), q.p });
    try dir.writeFile(io, .{ .sub_path = "requests_plain.tsv", .data = list.written() });

    var env = try init.environ_map.clone(arena);
    try env.put("GOTOOLCHAIN", "local");
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
    for (requests, 0..) |q, i| wires[i] = try arena.print("{s} {s} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", .{ q.m.token(), q.p });

    const lookup = timeIt(io, .{}, lookupAll);
    const serve = timeIt(io, .{ &r, &wires }, serveAll);
    const use_fast = if (init.environ_map.get("BENCH_FAST")) |v| !std.mem.eql(u8, v, "0") else true;
    const lookup_plain = timeIt(io, .{}, lookupPlain);
    var fast: [contenders.len]?GoRow = @splat(null);
    if (use_fast) {
        std.debug.print("bench-router: building the Rust side ...\n", .{});
        try rustBuild(arena, io, &env);
        for (contenders, 0..) |c, i| {
            std.debug.print("bench-router: {s} ...\n", .{c.label});
            fast[i] = try fastRun(arena, io, &env, abs, c);
        }
    }

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
    if (!use_fast) {
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× go-chi/chi v5.3.2 · fastest ? (measured <today>)\n", .{ best, worst });
        try w.flush();
        return 0;
    }

    // ---- fastest in the field: lookup over the plain subset ----
    try w.print("\nfastest in the field -- lookup, plain subset ({d} routes, one op = {d} requests)\n", .{ plain_count, plain_requests.len });
    try w.print("{s:<20} {s:>12} {s:>9}  count\n", .{ "contender", "ns/op", "ours/it" });
    try w.print("{s:<20} {d:>12.1} {s:>9}  {d}\n", .{ "ours (plain)", lookup_plain.ns, "-", lookup_plain.count });
    var fastest_ns = std.math.inf(f64);
    var fastest_who: []const u8 = "";
    var fast_mismatch = false;
    for (contenders, 0..) |c, i| {
        const row = fast[i] orelse {
            try w.print("{s:<20} {s:>12} {s:>9}  unsupported on the plain table\n", .{ c.label, "-", "-" });
            continue;
        };
        const same = row.count == lookup_plain.count;
        if (!same) fast_mismatch = true;
        try w.print("{s:<20} {d:>12.1} {d:>9.2}  {d}{s}\n", .{ c.label, row.ns, lookup_plain.ns / row.ns, row.count, if (same) "" else " != ours" });
        if (row.ns < fastest_ns) {
            fastest_ns = row.ns;
            fastest_who = c.label;
        }
    }
    if (fast_mismatch) {
        try w.writeAll("bench-router: FAILED -- a contender's match count differs from ours on the plain subset; the timing means nothing until it agrees\n");
        try w.flush();
        return 1;
    }
    if (fastest_who.len == 0) {
        try w.writeAll("bench-router: FAILED -- no contender could run the plain table\n");
        try w.flush();
        return 1;
    }
    // One workload (lookup), so the worst row is that row.
    const worst_fast = lookup_plain.ns / fastest_ns;
    try w.print("\nworst vs fastest = {d:.2} (row lookup, {s})\n", .{ worst_fast, fastest_who });
    try w.print("card: **Performance:** ref {d:.2}–{d:.2}× go-chi/chi v5.3.2 · fastest {d:.2}× {s} (measured <today>)\n", .{ best, worst, worst_fast, fastest_who });
    try w.flush();
    return 0;
}

/// Build the Rust side once (no network: the crate is in the cargo registry
/// after `cargo fetch`; Cargo.lock is committed).
fn rustBuild(arena: std.mem.Allocator, io: std.Io, env: *std.process.Environ.Map) !void {
    try env.put("CARGO_NET_OFFLINE", "true");
    const res = std.process.run(arena, io, .{
        .argv = &.{ "cargo", "build", "--release", "--offline", "--locked", "--manifest-path", rust_manifest, "--target-dir", rust_target },
        .environ_map = env,
    }) catch |e| {
        std.debug.print("bench-router: could not run cargo ({t}) -- BENCH_FAST=0 skips the contenders\n", .{e});
        return error.RustBuildFailed;
    };
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("bench-router: cargo build failed:\n{s}\n", .{res.stderr});
        return error.RustBuildFailed;
    }
}

/// One contender on the plain subset: null when it exits 3 (`unsupported`),
/// else its `lookup<TAB>ns<TAB>count` line.
fn fastRun(arena: std.mem.Allocator, io: std.Io, env: *std.process.Environ.Map, abs: []const u8, c: Contender) !?GoRow {
    const res = (if (c.rust)
        std.process.run(arena, io, .{ .argv = &.{ rust_exe, abs }, .environ_map = env })
    else
        std.process.run(arena, io, .{
            .argv = &.{ "go", "run", ".", c.name, abs },
            .environ_map = env,
            .cwd = .{ .path = fast_dir },
        })) catch |e| {
        std.debug.print("bench-router: could not run {s} ({t})\n", .{ c.name, e });
        return error.ForeignFailed;
    };
    if (res.term == .exited and res.term.exited == 3) return null;
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("bench-router: {s} failed:\n{s}\n", .{ c.name, res.stderr });
        return error.ForeignFailed;
    }
    var f = std.mem.tokenizeScalar(u8, std.mem.trimEnd(u8, res.stdout, "\n"), '\t');
    if (!std.mem.eql(u8, f.next() orelse return error.BadForeignOutput, "lookup")) return error.BadForeignOutput;
    const ns = try std.fmt.parseFloat(f64, f.next() orelse return error.BadForeignOutput);
    const count = try std.fmt.parseInt(usize, f.next() orelse return error.BadForeignOutput, 10);
    return .{ .ns = ns, .count = count };
}
