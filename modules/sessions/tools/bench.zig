// SPDX-License-Identifier: MIT

//! Comparative benchmark: `sessions` against alexedwards/scs v2.9.0 with its
//! in-memory `memstore` (the reference), the program behind the
//! `**Performance:**` line of the maturity card (CONVENTIONS.md §9, kept
//! instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-sessions` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26.0 and
//! github.com/alexedwards/scs/v2 v2.9.0 in the module cache (pinned by
//! `tools/go_bench/go.mod`/`go.sum`; `GOPROXY=off`). Run from the repository
//! root.
//!
//! Every workload is a batch of 16 requests in, responses out. Ours:
//! `http.Server.serveStream` over `Router` + `Manager.middleware()` on a
//! `RamcacheStore` (bounded: 4096 entries, so the new-session row evicts like a
//! server under load would); scs's: `LoadAndSave` over `memstore`
//! (`NewWithCleanupInterval(0)`, no cleanup goroutine) driven with
//! `httptest.NewRecorder` + `httptest.NewRequest`. The HTTP stacks are in the
//! number on both sides, so `passthrough` (a route with no session work / a bare
//! handler) is measured too, is EXCLUDED from the verdict, and the verdict is
//! the "net" ratio: (workload - passthrough) per side, the cost of the session
//! work itself. The gross ratio (stacks included) is printed beside it.
//!   new_session  no cookie; the handler stores one value -> Set-Cookie
//!   load_read    a valid cookie; the handler reads the value, writes nothing
//!   load_write   a valid cookie; the handler overwrites the value
//!   destroy      8 x (a request that creates a session, then one that destroys it)
//! `destroy` is a pair because a destroyed session cannot be destroyed again
//! per repeated batch. scs's IdleTimeout is set to ours (30 min): with it,
//! scs commits and re-stamps the cookie on every load (data.go:78-83), as the
//! rolling window here does. The session ids differ in length and encoding
//! (ours 64 hex, scs 43 base64url); the result count is built from status
//! codes, Set-Cookie presence and body lengths only, so it does not depend on
//! them. Each side times the same way (double the batch until it takes over
//! 100 ms, best of five); the sides alternate for BENCH_ROUNDS (default 3)
//! rounds, each keeping its best. Ratios are ours/scs by wall time; the verdict
//! is the WORST net ratio. Arguments filter workloads.

const std = @import("std");
const bench = @import("testkit").bench;
const http = @import("http");
const router = @import("router");
const ramcache = @import("ramcache");
const sessions = @import("sessions");

const bench_name = "bench-sessions";
const work_dir = ".zig-cache/bench-sessions";
const go_dir = "modules/sessions/tools/go_bench";
const ref_short = "scs";
const ref_card = "alexedwards/scs v2.9.0 + memstore";

const net_base: ?[]const u8 = "passthrough";
const info_only = [_][]const u8{"passthrough"};
const names = [_][]const u8{ "passthrough", "new_session", "load_read", "load_write", "destroy" };
const n_req = 16;

const Row = struct {
    cache: ramcache.Cache,
    store: sessions.RamcacheStore,
    mgr: sessions.Manager,
    router: router.Router,
    /// The requests of one batch (all but `destroy`, which builds them).
    wires: [n_req][]const u8 = undefined,
};

const Data = struct {
    rows: [names.len]*Row,
};

fn hPlain(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll("<none>");
}

fn hNew(ctx: *router.Ctx) anyerror!void {
    try sessions.sessionOf(ctx).?.putValue("uid", "42");
    try ctx.res.writeAll("created");
}

fn hRead(ctx: *router.Ctx) anyerror!void {
    const v = (try sessions.sessionOf(ctx).?.getValue("uid")) orelse "<none>";
    try ctx.res.writeAll(v);
}

fn hWrite(ctx: *router.Ctx) anyerror!void {
    try sessions.sessionOf(ctx).?.putValue("uid", "43");
    try ctx.res.writeAll("updated");
}

fn hLogout(ctx: *router.Ctx) anyerror!void {
    sessions.sessionOf(ctx).?.revoke();
    try ctx.res.writeAll("bye");
}

/// One request through the row's router, response bytes in `out_buf`.
fn serve(row: *Row, wire: []const u8, out_buf: []u8) []const u8 {
    var head_buf: [2048]u8 = undefined;
    var request_body_buf: [64]u8 = undefined;
    var response_body_buf: [1024]u8 = undefined;
    var chunk_buf: [128]u8 = undefined;
    var in: std.Io.Reader = .fixed(wire);
    var out: std.Io.Writer = .fixed(out_buf);
    http.Server.serveStream(.{ .handler = row.router.handler(), .context = &row.router, .server_name = null }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    return out.buffered();
}

/// status + one per response carrying a Set-Cookie header + the body length.
fn tally(resp: []const u8) u64 {
    var sum: u64 = std.fmt.parseInt(u16, resp[9..12], 10) catch 0;
    if (std.ascii.indexOfIgnoreCase(resp, "\r\nset-cookie:") != null) sum += 1;
    if (std.mem.indexOf(u8, resp, "\r\n\r\n")) |i| sum += resp.len - (i + 4);
    return sum;
}

/// The session id in the response's `Set-Cookie: session=<id>; ...`.
fn cookieOf(resp: []const u8) []const u8 {
    const at = std.ascii.indexOfIgnoreCase(resp, "set-cookie: session=") orelse return "";
    const rest = resp[at + "set-cookie: session=".len ..];
    return rest[0 .. std.mem.indexOfScalar(u8, rest, ';') orelse rest.len];
}

const no_cookie = "GET {s} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n";
const with_cookie = "GET {s} HTTP/1.1\r\nHost: t\r\nCookie: session={s}\r\nConnection: close\r\n\r\n";

fn once(d: *const Data, w: usize) u64 {
    const row = d.rows[w];
    var sum: u64 = 0;
    var out_buf: [1024]u8 = undefined;
    if (w == destroy_row) {
        var req_buf: [256]u8 = undefined;
        for (0..n_req / 2) |_| {
            const created = serve(row, row.wires[0], &out_buf);
            sum += tally(created);
            const req = std.fmt.bufPrint(&req_buf, with_cookie, .{ "/logout", cookieOf(created) }) catch unreachable;
            sum += tally(serve(row, req, &out_buf));
        }
        return sum;
    }
    for (row.wires) |wire| sum += tally(serve(row, wire, &out_buf));
    return sum;
}

const destroy_row = 4;

fn setupRow(arena: std.mem.Allocator, io: std.Io, wi: usize) !*Row {
    const gpa = std.heap.smp_allocator;
    const row = try arena.create(Row);
    row.cache = ramcache.Cache.init(gpa, .{ .max_bytes = 8 << 20, .max_entries = 4096 });
    row.store = .{ .cache = &row.cache };
    row.mgr = try sessions.Manager.init(gpa, row.store.store(), .{ .io = io });
    row.router = router.Router.init(gpa);
    if (wi == 0) {
        try row.router.get("/", hPlain);
    } else {
        try row.router.use(row.mgr.middleware());
        try row.router.get("/new", hNew);
        try row.router.get("/read", hRead);
        try row.router.get("/write", hWrite);
        try row.router.get("/logout", hLogout);
    }
    var out_buf: [1024]u8 = undefined;
    switch (wi) {
        0 => for (&row.wires) |*wire| {
            wire.* = try std.fmt.allocPrint(arena, no_cookie, .{"/"});
        },
        1, destroy_row => for (&row.wires) |*wire| {
            wire.* = try std.fmt.allocPrint(arena, no_cookie, .{"/new"});
        },
        else => for (&row.wires) |*wire| {
            // A session per slot, made through the real middleware.
            const made = serve(row, try std.fmt.allocPrint(arena, no_cookie, .{"/new"}), &out_buf);
            const id = cookieOf(made);
            if (id.len == 0) return error.NoSessionCookie;
            wire.* = try std.fmt.allocPrint(arena, with_cookie, .{ if (wi == 2) "/read" else "/write", id });
        },
    }
    return row;
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);
    const args = try init.minimal.args.toSlice(arena);
    const filters = if (args.len > 1) args[1..] else &[_][:0]const u8{};
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 3;

    var d: Data = .{ .rows = undefined };
    for (&d.rows, 0..) |*row, wi| row.* = try setupRow(arena, io, wi);

    const exe = try bench.goBuild(arena, io, bench_name, init.environ_map, .{ .exe = "go", .dir = go_dir, .abs = abs, .toolchain = "go1.26.0" });
    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.print("{s:<22} {s:>11} {s:>11} {s:>8} {s:>8} {s:>7} {s:>7}  count\n", .{ "workload", "ours ns", ref_short ++ " ns", "gross", "net", "spr us", "spr ref" });
    try w.flush();
    var worst: f64 = 0;
    var best: f64 = std.math.inf(f64);
    var max_spread: f64 = 0;
    var mismatch = false;
    var base_ours: f64 = 0;
    var base_ref: f64 = 0;
    for (names, 0..) |name, wi| {
        if (filters.len > 0) {
            var hit = false;
            for (filters) |f| hit = hit or std.mem.indexOf(u8, name, f) != null;
            if (!hit) continue;
        }
        var ours: bench.Side = .{};
        var go: bench.Side = .{};
        for (0..rounds) |_| {
            go.add(try bench.foreign(arena, io, bench_name, exe, abs, name, null));
            ours.add(bench.timeIt(io, .{ .fd = null }, once, .{ &d, wi }, true));
        }
        const gross = ours.best_ns / go.best_ns;
        // `net_base` (a workload name): the cost of the HTTP stacks both sides
        // carry is that workload; the module's own ratio is what is left over.
        var net: f64 = std.math.nan(f64);
        if (net_base) |nb| {
            if (std.mem.eql(u8, nb, name)) {
                base_ours = ours.best_ns;
                base_ref = go.best_ns;
            } else if (base_ref != 0 and go.best_ns > base_ref) {
                net = (ours.best_ns - base_ours) / (go.best_ns - base_ref);
            }
        }
        const ratio = if (net_base != null and !std.math.isNan(net)) net else gross;
        const info = for (info_only) |n| {
            if (std.mem.eql(u8, n, name)) break true;
        } else false;
        if (!info) {
            worst = @max(worst, ratio);
            best = @min(best, ratio);
        }
        max_spread = @max(max_spread, @max(ours.spread(false), go.spread(false)));
        const same = ours.count == go.count;
        mismatch = mismatch or !same;
        try w.print("{s:<22} {d:>11.0} {d:>11.0} {d:>8.3} {d:>8.3} {d:>6.1}% {d:>6.1}%  {d}{s}\n", .{ name, ours.best_ns, go.best_ns, gross, net, 100 * ours.spread(false), 100 * go.spread(false), ours.count, if (same and !info) "" else if (same) "  (info only, not in the verdict)" else " ≠ " ++ ref_short });
        try w.flush();
    }
    try w.print("rounds: {d}; ratios by wall time{s}; largest spread {d:.1}%{s}\n", .{ rounds, if (net_base != null) " (verdict = net of the " ++ net_base.? ++ " workload)" else "", 100 * max_spread, if (max_spread > 0.05) " (OVER 5 %: noisy run, repeat)" else "" });
    if (mismatch) {
        try w.writeAll(bench_name ++ ": FAILED -- a result count differs from the reference's; the timing means nothing until it agrees\n");
        try w.flush();
        return 1;
    }
    try w.print("\nworst ours/{s} = {d:.2} (best {d:.2})\n", .{ ref_short, worst, best });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× {s} · fastest ? (measured <today>)\n", .{ best, worst, ref_card });
    try w.flush();
    return 0;
}
