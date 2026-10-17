// SPDX-License-Identifier: MIT

//! Comparative benchmark: `security-headers` against unrolled/secure v1.17.0
//! (Go, MIT; the reference), the program behind the `**Performance:**` line of
//! the maturity card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-security-headers` runs it
//! (always ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26.0
//! and github.com/unrolled/secure v1.17.0 in the module cache (pinned by
//! `tools/go_bench/go.mod`/`go.sum`; `GOPROXY=off`). Run from the repository
//! root.
//!
//! The header work is isolated on both sides, with no HTTP stack, no handler,
//! no parsing and no serialisation. One op = 64 responses:
//!   ours  a persistent `http.Server.ResponseWriter` (over a fixed buffer),
//!         reset between responses (`headers_len`, `header_buf_len` = 0), and
//!         the module's own entry point called on it.
//!   Go    `Secure.Process(w, r)` with a minimal ResponseWriter that holds one
//!         `http.Header` map, cleared between responses, and a request built
//!         once. (`httptest.ResponseRecorder` would add a header snapshot and
//!         a body buffer per response.) Go's `Process` builds its own header
//!         map and copies it into `w.Header()`; that is what Go's header work
//!         is, and it is in the number.
//!   apply_default  the default header set, 9 headers: Strict-Transport-
//!         Security, X-Content-Type-Options, X-Frame-Options DENY, Referrer-
//!         Policy no-referrer, COOP/CORP same-origin, X-XSS-Protection 0,
//!         X-DNS-Prefetch-Control off, X-Permitted-Cross-Domain-Policies none.
//!         Ours: `SecurityHeaders.apply` of `.{ .origin_agent_cluster = false,
//!         .x_download_options = false }` (the two further default headers of
//!         ours, Origin-Agent-Cluster and X-Download-Options, have no option in
//!         unrolled/secure; left off so both sides emit the same set). Go: the
//!         equivalent Options (ForceSTSHeader, since its request is plain HTTP).
//!   apply_static   the same set, ours `SecurityHeaders.applyStatic` (comptime
//!         options, `setHeaderStatic`); Go has no comptime path and runs the
//!         same code as apply_default, so this row shows our lead.
//!   csp_nonce      only Content-Security-Policy: helmet's default policy with
//!         a fresh nonce appended to script-src and style-src. Ours:
//!         `applyCspNonce` (renders the `csp.Spec`, `io.randomSecure`, base64,
//!         `setHeader`). Go: ContentSecurityPolicy with `$NONCE` in the same two
//!         places (its `processRequest` draws 16 bytes from crypto/rand, base64
//!         without padding, and `fmt.Sprintf`s the template).
//! Result count = per response (headers + name bytes + value bytes), summed;
//! the nonce is 22 bytes on both sides, so a policy that diverges shows up as a
//! count mismatch before any timing is read.
//! Each side times the same way (double the batch until it takes over 100 ms,
//! best of five); the sides alternate for BENCH_ROUNDS (default 3) rounds, each
//! keeping its best. Ratios are ours/Go by wall time; the verdict is the WORST
//! ratio over the three workloads. Arguments filter workloads.

const std = @import("std");
const http = @import("http");
const sh = @import("security-headers");

const bench_name = "bench-security-headers";
const work_dir = ".zig-cache/bench-security-headers";
const go_dir = "modules/security-headers/tools/go_bench";
const ref_short = "Go";
const ref_card = "unrolled/secure v1.17.0";

const net_base: ?[]const u8 = null;
const info_only = [_][]const u8{};
const names = [_][]const u8{ "apply_default", "apply_static", "csp_nonce" };
const n_resp = 64;

const Data = struct {
    io: std.Io,
    rw: *http.Server.ResponseWriter,
    policy: sh.SecurityHeaders,
};

const opts: sh.Options = .{ .origin_agent_cluster = false, .x_download_options = false };

/// helmet's default policy with `$NONCE` where ours appends the nonce.
const go_policy = "default-src 'self';base-uri 'self';font-src 'self' https: data:;" ++
    "form-action 'self';frame-ancestors 'self';img-src 'self' data:;" ++
    "object-src 'none';script-src 'self' $NONCE;script-src-attr 'none';" ++
    "style-src 'self' https: 'unsafe-inline' $NONCE;upgrade-insecure-requests";

const csp_spec: sh.csp.Spec = .{};
const nonce_in = [_]sh.csp.Name{ .script_src, .style_src };

fn tally(rw: *const http.Server.ResponseWriter) u64 {
    var sum: u64 = 0;
    for (rw.headers[0..rw.headers_len]) |h| sum += 1 + h.name.len + h.value.len;
    return sum;
}

fn once(d: *const Data, w: usize) u64 {
    const rw = d.rw;
    var scratch: [1024]u8 = undefined;
    var sum: u64 = 0;
    for (0..n_resp) |_| {
        rw.headers_len = 0;
        rw.header_buf_len = 0;
        switch (w) {
            0 => d.policy.apply(rw) catch unreachable,
            1 => sh.SecurityHeaders.applyStatic(opts, rw) catch unreachable,
            else => _ = sh.applyCspNonce(rw, d.io, csp_spec, &nonce_in, false, &scratch) catch unreachable,
        }
        sum += tally(rw);
    }
    return sum;
}

fn setup(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) !Data {
    var d: Data = undefined;
    d.io = io;
    d.policy = try sh.SecurityHeaders.init(opts);
    const out = try arena.create(std.Io.Writer);
    out.* = .fixed(try arena.alloc(u8, 256));
    d.rw = try arena.create(http.Server.ResponseWriter);
    d.rw.* = .init(out, try arena.alloc(u8, 64), try arena.alloc(u8, 32), .{});
    try dir.writeFile(io, .{ .sub_path = "csp_nonce.policy", .data = go_policy });
    return d;
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    var dir = try cwd.openDir(io, work_dir, .{});
    defer dir.close(io);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);
    const args = try init.minimal.args.toSlice(arena);
    const filters = if (args.len > 1) args[1..] else &[_][:0]const u8{};
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 3;

    var d: Data = try setup(arena, io, dir);

    const exe = try goBuild(arena, io, init.environ_map, abs);
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
        var ours: Side = .{};
        var go: Side = .{};
        for (0..rounds) |_| {
            go.add(try goRun(arena, io, exe, abs, name));
            ours.add(timeIt(io, &d, wi));
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
        max_spread = @max(max_spread, @max(ours.spread(), go.spread()));
        const same = ours.count == go.count;
        mismatch = mismatch or !same;
        try w.print("{s:<22} {d:>11.0} {d:>11.0} {d:>8.3} {d:>8.3} {d:>6.1}% {d:>6.1}%  {d}{s}\n", .{ name, ours.best_ns, go.best_ns, gross, net, 100 * ours.spread(), 100 * go.spread(), ours.count, if (same and !info) "" else if (same) "  (info only, not in the verdict)" else " ≠ " ++ ref_short });
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
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× {s} · fastest ? (measured 2026-10-17)\n", .{ best, worst, ref_card });
    try w.flush();
    return 0;
}

// ---- comparison driver (the same in every stdlib-Go-referenced bench) ----

const Row = struct { ns: f64, count: u64 };

const Side = struct {
    best_ns: f64 = std.math.inf(f64),
    worst_ns: f64 = 0,
    count: u64 = 0,
    fn add(s: *Side, r: Row) void {
        s.best_ns = @min(s.best_ns, r.ns);
        s.worst_ns = @max(s.worst_ns, r.ns);
        s.count = r.count;
    }
    fn spread(s: Side) f64 {
        return s.worst_ns / s.best_ns - 1;
    }
};

fn timeIt(io: std.Io, d: *const Data, w: usize) Row {
    var n: usize = 1;
    while (true) {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| std.mem.doNotOptimizeAway(once(d, w));
        if (t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds > 100_000_000) break;
        n *= 2;
    }
    var best: i96 = std.math.maxInt(i96);
    var count: u64 = 0;
    for (0..5) |_| {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| count = once(d, w);
        best = @min(best, t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds);
    }
    return .{ .ns = @as(f64, @floatFromInt(best)) / @as(f64, @floatFromInt(n)), .count = count };
}

/// Build the Go side once (`go build`), so the timed runs do not pay for it.
fn goBuild(arena: std.mem.Allocator, io: std.Io, environ: *const std.process.Environ.Map, abs: []const u8) ![]const u8 {
    var env = try environ.clone(arena);
    try env.put("GOTOOLCHAIN", "local");
    try env.put("GOPROXY", "off");
    try env.put("GOFLAGS", "-mod=readonly");
    const exe = try std.fmt.allocPrint(arena, "{s}/go_bench", .{abs});
    std.debug.print("{s}: building the Go side ...\n", .{bench_name});
    const res = std.process.run(arena, io, .{
        .argv = &.{ "go", "build", "-o", exe, "." },
        .environ_map = &env,
        .cwd = .{ .path = go_dir },
    }) catch |e| {
        std.debug.print("{s}: could not run go ({t}) -- the benchmark needs it\n", .{ bench_name, e });
        return error.GoBuildFailed;
    };
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: go build failed:\n{s}\n", .{ bench_name, res.stderr });
        return error.GoBuildFailed;
    }
    return exe;
}

/// Run the Go side for one workload: `<exe> <work dir> <name>` prints
/// `name \t ns/op \t count`.
fn goRun(arena: std.mem.Allocator, io: std.Io, exe: []const u8, abs: []const u8, name: []const u8) !Row {
    const res = try std.process.run(arena, io, .{ .argv = &.{ exe, abs, name } });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: Go side failed on {s}:\n{s}\n", .{ bench_name, name, res.stderr });
        return error.ForeignFailed;
    }
    var f = std.mem.tokenizeScalar(u8, std.mem.trimEnd(u8, res.stdout, "\n"), '\t');
    if (!std.mem.eql(u8, f.next() orelse return error.BadForeignOutput, name)) return error.BadForeignOutput;
    const ns = try std.fmt.parseFloat(f64, f.next() orelse return error.BadForeignOutput);
    const count = try std.fmt.parseInt(u64, f.next() orelse return error.BadForeignOutput, 10);
    return .{ .ns = ns, .count = count };
}
