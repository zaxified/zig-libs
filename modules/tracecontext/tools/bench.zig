// SPDX-License-Identifier: MIT

//! Comparative benchmark: `tracecontext` against OpenTelemetry Go's W3C
//! `propagation.TraceContext` (go.opentelemetry.io/otel v1.46.0, the
//! reference), the program behind the `**Performance:**` line of the maturity
//! card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-tracecontext` runs it
//! (always ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26.0
//! and otel v1.46.0 (+ otel/trace) in the module cache (pinned by
//! `tools/go_bench/go.mod`/`go.sum`, the same versions the otel oracle pins;
//! `GOPROXY=off`). Run from the repository root.
//!
//! The module's job is a middleware, so every workload is request bytes in,
//! response bytes out (16 requests to one route "/"): ours
//! `http.Server.serveStream` over `Router` + `TraceContext.middleware`, Go's
//! `http.ReadRequest` + a handler doing Extract / child span / Inject into a
//! buffer. The HTTP stacks are in the number on both sides, so `plain` (no
//! tracing) is measured too, is EXCLUDED from the verdict, and the verdict is
//! the "net" ratio: (workload - plain) per side, the cost of the propagation
//! itself. The gross ratio (stacks included) is printed beside it.
//!   propagate  valid incoming `traceparent`: parse, child span id, echo
//!   state      the same plus a `tracestate` carried through
//!   fresh      no incoming header: a new sampled trace
//! The OTel SDK's id generator is not among the pinned modules; the Go side
//! draws ids from math/rand/v2 (what the SDK's default generator uses), ours
//! uses its own clock/counter mix. Result count = sum of status codes + per
//! response: 1 for a 55-byte traceparent, 1 for a tracestate header and (for
//! propagate/state) the byte sums of the echoed trace id and flags. Each side
//! times the same way (double the batch until it takes over 100 ms, best of
//! five); the sides alternate for BENCH_ROUNDS (default 3) rounds, each keeping
//! its best. Ratios are ours/Go by wall time; the verdict is the WORST net
//! ratio. Arguments filter workloads.
//!
//! "Fastest in the field": `tools/rust_fast_bench` (OpenTelemetry Rust 0.33.1,
//! opentelemetry_sdk's `TraceContextPropagator`, the same Extract / child span /
//! Inject steps as the Go side) is timed the same way over the same request
//! bytes, with its own `plain` baseline so the verdict stays NET of the HTTP
//! stack. It is not like-for-like work (the Rust request side is httparse +
//! `http::Request`; ids from a small xorshift, as Go draws from math/rand/v2;
//! the propagator formats a String per injected field and always calls `set`
//! for tracestate; the source header says where). `BENCH_FAST=0` skips it
//! (needs cargo and the pinned crates in ~/.cargo/registry). The card's fastest
//! figure is ours / the cheaper net cost of {otel Go, otel Rust} per row, worst
//! over the rows.

const std = @import("std");
const bench = @import("testkit").bench;
const http = @import("http");
const router = @import("router");
const tracecontext = @import("tracecontext");

const bench_name = "bench-tracecontext";
const work_dir = ".zig-cache/bench-tracecontext";
const go_dir = "modules/tracecontext/tools/go_bench";
const ref_short = "otel";
const ref_card = "OpenTelemetry Go v1.46.0 TraceContext";

const fast_rs_manifest = "modules/tracecontext/tools/rust_fast_bench/Cargo.toml";
const fast_rs_exe = "modules/tracecontext/tools/rust_fast_bench/target/release/tracecontext_fast_bench";
const fast_name = "otel-rust";
const fast_card = "OpenTelemetry Rust 0.33.1 TraceContextPropagator";

const net_base: ?[]const u8 = "plain";
const info_only = [_][]const u8{"plain"};
const names = [_][]const u8{ "plain", "propagate", "state", "fresh" };
const n_req = 16;

const Data = struct {
    plain: *router.Router,
    mw: *router.Router,
    wires: [names.len][n_req][]const u8,
};

fn hOk(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll("ok");
}

const tc: tracecontext.TraceContext = .{};

fn sumBytes(s: []const u8) u64 {
    var t: u64 = 0;
    for (s) |c| t += c;
    return t;
}

/// The value of response header `name` (case-insensitive), or null.
fn headerValue(resp: []const u8, comptime name: []const u8) ?[]const u8 {
    const at = std.ascii.findIgnoreCase(resp, "\r\n" ++ name ++ ":") orelse return null;
    const rest = resp[at + 2 + name.len + 1 ..];
    const end = std.mem.find(u8, rest, "\r\n") orelse rest.len;
    return std.mem.trim(u8, rest[0..end], " ");
}

fn once(d: *const Data, w: usize) u64 {
    const r = if (w == 0) d.plain else d.mw;
    var sum: u64 = 0;
    var out_buf: [1024]u8 = undefined;
    var head_buf: [2048]u8 = undefined;
    var request_body_buf: [64]u8 = undefined;
    var response_body_buf: [1024]u8 = undefined;
    var chunk_buf: [128]u8 = undefined;
    for (d.wires[w]) |wire| {
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
        if (headerValue(resp, "traceparent")) |tp| {
            if (tp.len == 55) {
                sum += 1;
                if (w == 1 or w == 2) sum += sumBytes(tp[3..35]) + sumBytes(tp[53..55]);
            }
        }
        if (headerValue(resp, "tracestate") != null) sum += 1;
    }
    return sum;
}

fn setup(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) !Data {
    var d: Data = undefined;
    d.plain = try arena.create(router.Router);
    d.plain.* = router.Router.init(std.heap.smp_allocator);
    try d.plain.get("/", hOk);
    d.mw = try arena.create(router.Router);
    d.mw.* = router.Router.init(std.heap.smp_allocator);
    try d.mw.use(tc.middleware());
    try d.mw.get("/", hOk);
    var prng = std.Random.DefaultPrng.init(0x7ace_c0de);
    const r = prng.random();
    for (names, 0..) |name, wi| {
        var all: std.Io.Writer.Allocating = .init(arena);
        for (0..n_req) |i| {
            var tid: [16]u8 = undefined;
            var sid: [8]u8 = undefined;
            r.bytes(&tid);
            r.bytes(&sid);
            tid[0] |= 1;
            sid[0] |= 1;
            const wire = switch (wi) {
                1 => try arena.print("GET / HTTP/1.1\r\nHost: t\r\ntraceparent: 00-{x}-{x}-01\r\nConnection: close\r\n\r\n", .{ tid, sid }),
                2 => try arena.print("GET / HTTP/1.1\r\nHost: t\r\ntraceparent: 00-{x}-{x}-01\r\ntracestate: congo=t61rcWkgMzE,rojo=00f067aa0ba902b7\r\nConnection: close\r\n\r\n", .{ tid, sid }),
                else => try arena.dupe(u8, "GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n"),
            };
            d.wires[wi][i] = wire;
            if (i != 0) try all.writer.writeByte(0);
            try all.writer.writeAll(wire);
        }
        try dir.writeFile(io, .{ .sub_path = try arena.print("{s}.wire", .{name}), .data = all.written() });
    }
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

    const exe = try bench.goBuild(arena, io, bench_name, init.environ_map, .{ .exe = "go", .dir = go_dir, .abs = abs });
    const use_fast = if (init.environ_map.get("BENCH_FAST")) |v| !std.mem.eql(u8, v, "0") else true;
    if (use_fast) try rustBuild(arena, io);
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
        for (0..rounds) |_| {
            go.add(try bench.foreign(arena, io, bench_name, exe, abs, name, null));
            if (use_fast) fast.add(try fastRun(arena, io, abs, name));
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
        if (use_fast) {
            // net cost of each side = workload - its own `plain`; the cheaper of
            // the reference and the contender is the yardstick
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

/// `cargo build --release --offline` of tools/rust_fast_bench.
fn rustBuild(arena: std.mem.Allocator, io: std.Io) !void {
    std.debug.print("{s}: building the Rust side ...\n", .{bench_name});
    const res = std.process.run(arena, io, .{
        .argv = &.{ "cargo", "build", "--release", "--offline", "--quiet", "--manifest-path", fast_rs_manifest },
    }) catch |e| {
        std.debug.print("{s}: could not run cargo ({t}) -- BENCH_FAST=0 skips this side\n", .{ bench_name, e });
        return error.CargoBuildFailed;
    };
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: cargo build failed:\n{s}\n", .{ bench_name, res.stderr });
        return error.CargoBuildFailed;
    }
}

/// `<exe> <work dir> <workload> <contender>` prints `name \t ns/op \t count`.
fn fastRun(arena: std.mem.Allocator, io: std.Io, abs: []const u8, name: []const u8) !bench.Row {
    const res = try std.process.run(arena, io, .{ .argv = &.{ fast_rs_exe, abs, name, fast_name } });
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
