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
//!
//! "Fastest in the field": `tools/go_fast_bench` (the `middleware/session` of
//! gofiber/fiber v3.6.1 with its built-in in-memory storage, on fasthttp
//! v1.75.0, driven in-process: one `fasthttp.RequestCtx`, the app's
//! `Handler()`) is timed the same way over the same five workloads, with its
//! own `passthrough` baseline so the verdict stays NET of the HTTP stack. Like
//! scs it builds its own requests (the cookies come from its own sessions), so
//! no `.wire` files are written. Not byte-identical work: gob-encoded session
//! data, a base64url id, an extra absolute-deadline value; the source header
//! says where. The count (status codes + Set-Cookie presence + body lengths)
//! still agrees. A workload it cannot do (exit 3) drops the row. `BENCH_FAST=0`
//! skips it. The card's fastest figure is ours / the cheaper net cost of
//! {reference, fiber} per row, worst over the rows.

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

const fast_go_dir = "modules/sessions/tools/go_fast_bench";
const fast_name = "fiber";
const fast_card = "gofiber/fiber v3.6.1 session + memory storage";

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
    if (std.ascii.findIgnoreCase(resp, "\r\nset-cookie:") != null) sum += 1;
    if (std.mem.find(u8, resp, "\r\n\r\n")) |i| sum += resp.len - (i + 4);
    return sum;
}

/// The session id in the response's `Set-Cookie: session=<id>; ...`.
fn cookieOf(resp: []const u8) []const u8 {
    const at = std.ascii.findIgnoreCase(resp, "set-cookie: session=") orelse return "";
    const rest = resp[at + "set-cookie: session=".len ..];
    return rest[0 .. std.mem.findScalar(u8, rest, ';') orelse rest.len];
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
            const req = std.mem.print(&req_buf, with_cookie, .{ "/logout", cookieOf(created) }) catch unreachable;
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
            wire.* = try arena.print(no_cookie, .{"/"});
        },
        1, destroy_row => for (&row.wires) |*wire| {
            wire.* = try arena.print(no_cookie, .{"/new"});
        },
        else => for (&row.wires) |*wire| {
            // A session per slot, made through the real middleware.
            const made = serve(row, try arena.print(no_cookie, .{"/new"}), &out_buf);
            const id = cookieOf(made);
            if (id.len == 0) return error.NoSessionCookie;
            wire.* = try arena.print(with_cookie, .{ if (wi == 2) "/read" else "/write", id });
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

    const exe = try bench.goBuild(arena, io, bench_name, init.environ_map, .{ .exe = "go", .dir = go_dir, .abs = abs });
    const use_fast = if (init.environ_map.get("BENCH_FAST")) |v| !std.mem.eql(u8, v, "0") else true;
    const fast_exe = if (use_fast) try fastGoBuild(arena, io, init.environ_map, abs) else "";
    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.print("{s:<22} {s:>11} {s:>11} {s:>8} {s:>8} {s:>7} {s:>7}  count\n", .{ "workload", "ours ns", ref_short ++ " ns", "gross", "net", "spr us", "spr ref" });
    if (use_fast) try w.print("{s:<22} {s:>11} {s:>9}  net, vs cheapest (who)\n", .{ "", fast_name ++ " ns", "ours/best" });
    try w.flush();
    var worst: f64 = 0;
    var worst_fast: f64 = 0;
    var worst_fast_row: []const u8 = "";
    var worst_fast_who: []const u8 = "";
    var base_fast: f64 = 0;
    var best: f64 = std.math.inf(f64);
    var max_spread: f64 = 0;
    var mismatch = false;
    var base_ours: f64 = 0;
    var base_ref: f64 = 0;
    for (names, 0..) |name, wi| {
        if (filters.len > 0) {
            var hit = false;
            for (filters) |f| hit = hit or std.mem.find(u8, name, f) != null;
            if (!hit) continue;
        }
        var ours: bench.Side = .{};
        var go: bench.Side = .{};
        var fast: bench.Side = .{};
        // false once the contender answers "unsupported" for this workload
        var fast_ok = use_fast;
        for (0..rounds) |_| {
            go.add(try bench.foreign(arena, io, bench_name, exe, abs, name, null));
            if (fast_ok) {
                if (try fastRun(arena, io, fast_exe, abs, name)) |r| fast.add(r) else fast_ok = false;
            }
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
        if (fast_ok) {
            // net cost of each side = workload - its own `passthrough`; the
            // cheaper of the reference and the contender is the yardstick
            const is_base = std.mem.eql(u8, net_base.?, name);
            const ours_cost = ours.best_ns - base_ours;
            var fastest_cost: f64 = if (go.best_ns > base_ref) go.best_ns - base_ref else std.math.inf(f64);
            var fastest_who: []const u8 = ref_short;
            try w.print("{s:<22} {d:>11.0}", .{ "", fast.best_ns });
            max_spread = @max(max_spread, fast.spread(false));
            if (fast.count != ours.count) {
                mismatch = true;
                try w.print(" ({s}: {d} != ours {d})", .{ fast_name, fast.count, ours.count });
            }
            if (is_base) {
                base_fast = fast.best_ns;
            } else if (fast.best_ns > base_fast and fast.best_ns - base_fast < fastest_cost) {
                fastest_cost = fast.best_ns - base_fast;
                fastest_who = fast_card;
            }
            if (!is_base and std.math.isFinite(fastest_cost)) {
                const ratio_fast = if (ours_cost > 0) ours_cost / fastest_cost else 0;
                if (!info and ratio_fast > worst_fast) {
                    worst_fast = ratio_fast;
                    worst_fast_row = name;
                    worst_fast_who = fastest_who;
                }
                try w.print(" {d:>9.3}  ({s})\n", .{ ratio_fast, fastest_who });
            } else try w.writeAll("\n");
        } else if (use_fast) {
            try w.print("{s:<22} {s} unsupported: row dropped for it\n", .{ "", fast_name });
        }
        try w.flush();
    }
    try w.print("rounds: {d}; ratios by wall time{s}; largest spread {d:.1}%{s}\n", .{ rounds, if (net_base != null) " (verdict = net of the " ++ net_base.? ++ " workload)" else "", 100 * max_spread, if (max_spread > 0.05) " (OVER 5 %: noisy run, repeat)" else "" });
    if (mismatch) {
        try w.writeAll(bench_name ++ ": FAILED -- a result count differs from the reference's; the timing means nothing until it agrees\n");
        try w.flush();
        return 1;
    }
    try w.print("\nworst ours/{s} = {d:.2} (best {d:.2})\n", .{ ref_short, worst, best });
    if (use_fast) try w.print("worst vs fastest = {d:.2} (row {s}, {s})\n", .{ worst_fast, worst_fast_row, worst_fast_who });
    if (filters.len == 0) {
        if (use_fast)
            try w.print("card: **Performance:** ref {d:.2}–{d:.2}× {s} · fastest {d:.2}× {s} (measured <today>)\n", .{ best, worst, ref_card, worst_fast, worst_fast_who })
        else
            try w.print("card: **Performance:** ref {d:.2}–{d:.2}× {s} · fastest ? (measured <today>)\n", .{ best, worst, ref_card });
    }
    try w.flush();
    return 0;
}

// ---- the "fastest in the field" side ----

/// Build tools/go_fast_bench (same environment as `bench.goBuild`: local
/// toolchain, `GOPROXY=off`, read-only modules) into `<abs>/go_fast_bench`.
fn fastGoBuild(arena: std.mem.Allocator, io: std.Io, environ: *const std.process.Environ.Map, abs: []const u8) ![]const u8 {
    var env = try environ.clone(arena);
    try env.put("GOTOOLCHAIN", "local");
    try env.put("GOPROXY", "off");
    try env.put("GOFLAGS", "-mod=readonly");
    const exe = try arena.print("{s}/go_fast_bench", .{abs});
    std.debug.print("{s}: building the Go fastest-in-the-field side ...\n", .{bench_name});
    const res = std.process.run(arena, io, .{
        .argv = &.{ "go", "build", "-o", exe, "." },
        .environ_map = &env,
        .cwd = .{ .path = fast_go_dir },
    }) catch |e| {
        std.debug.print("{s}: could not run go ({t}) -- BENCH_FAST=0 skips this side\n", .{ bench_name, e });
        return error.GoBuildFailed;
    };
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: go build (go_fast_bench) failed:\n{s}\n", .{ bench_name, res.stderr });
        return error.GoBuildFailed;
    }
    return exe;
}

/// `<exe> <work dir> <workload> <contender>` prints `name \t ns/op \t count`.
/// Null when the contender cannot do the workload (exit 3).
fn fastRun(arena: std.mem.Allocator, io: std.Io, exe: []const u8, abs: []const u8, name: []const u8) !?bench.Row {
    const res = try std.process.run(arena, io, .{ .argv = &.{ exe, abs, name, fast_name } });
    if (res.term == .exited and res.term.exited == 3) return null;
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: {s} failed on {s}:\n{s}\n", .{ bench_name, fast_name, name, res.stderr });
        return error.ForeignFailed;
    }
    var f = std.mem.tokenizeScalar(u8, std.mem.trimEnd(u8, res.stdout, "\n"), '\t');
    if (!std.mem.eql(u8, f.next() orelse return error.BadForeignOutput, name)) return error.BadForeignOutput;
    const ns = try std.fmt.parseFloat(f64, f.next() orelse return error.BadForeignOutput);
    const count = try std.fmt.parseInt(u64, f.next() orelse return error.BadForeignOutput, 10);
    return .{ .ns = ns, .count = count };
}
