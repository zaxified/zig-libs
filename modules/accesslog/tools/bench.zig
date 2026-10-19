// SPDX-License-Identifier: MIT

//! Comparative benchmark: `accesslog` against what Go offers for writing an
//! access-log line (go 1.26.0 `encoding/json`, `log/slog`, and go-logfmt
//! v0.6.1), the program behind the `**Performance:**` line of the maturity
//! card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-accesslog` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26.0 and
//! github.com/go-logfmt/logfmt v0.6.1 in the module cache (pinned by
//! `tools/go_bench/go.mod`/`go.sum`, the same version the logfmt judge pins;
//! `GOPROXY=off`). Run from the repository root.
//!
//! The card's own reference (Apache httpd `mod_log_config`, C) is a server
//! directive, not a callable library, so it cannot be timed through an API;
//! this bench compares the two formats that HAVE a library-grade Go
//! counterpart and says so. The Combined (CLF) writer has NO reference here
//! and is not measured.
//!   json_encoding  `writeJsonLines` vs `encoding/json` Encoder
//!                  (SetEscapeHTML(false)) over a struct, absent = null
//!   json_slog      `writeJsonLines` vs `slog.JSONHandler.Handle` (one record
//!                  per entry, built-in time/level/msg dropped by ReplaceAttr)
//!   logfmt         `writeLogfmt` vs go-logfmt `Encoder.EncodeKeyval` per field
//! One op = 16 entries (GET/POST/PUT/DELETE, 200..500, query strings with `&`
//! `=` `,`, a browser User-Agent, half with referer / trace ids) written to a
//! reused buffer; neither side allocates per op beyond what its API does.
//! Result count = bytes written, which must agree between the sides (the key
//! order, names and number formats are the same on both). Each side times the
//! same way (double the batch until it takes over 100 ms, best of five); the
//! sides alternate for BENCH_ROUNDS (default 3) rounds, each keeping its best.
//! Ratios are ours/Go by wall time; the verdict is the WORST ratio. Arguments
//! filter workloads.

const std = @import("std");
const bench = @import("testkit").bench;
const accesslog = @import("accesslog");

const bench_name = "bench-accesslog";
const work_dir = ".zig-cache/bench-accesslog";
const go_dir = "modules/accesslog/tools/go_bench";
const ref_short = "Go";
const ref_card = "Go 1.26.0 encoding/json + log/slog + go-logfmt v0.6.1";

const net_base: ?[]const u8 = null;
const info_only = [_][]const u8{};
const names = [_][]const u8{ "json_encoding", "json_slog", "logfmt" };
const n_entries = 16;

const Data = struct {
    entries: [n_entries]accesslog.Entry,
    out: []u8,
};

fn once(d: *const Data, w: usize) u64 {
    var out: std.Io.Writer = .fixed(d.out);
    for (d.entries) |e| {
        if (w == 2) accesslog.writeLogfmt(e, &out) catch unreachable else accesslog.writeJsonLines(e, &out) catch unreachable;
    }
    return out.buffered().len;
}

fn setup(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) !Data {
    var prng = std.Random.DefaultPrng.init(0xacce_5510);
    const r = prng.random();
    const methods = [_][]const u8{ "GET", "POST", "PUT", "DELETE" };
    const statuses = [_]u16{ 200, 200, 200, 201, 404, 500 };
    var d: Data = undefined;
    d.out = try arena.alloc(u8, 64 * 1024);
    var tsv: std.Io.Writer.Allocating = .init(arena);
    const w = &tsv.writer;
    for (&d.entries, 0..) |*e, i| {
        const rid = try arena.print("{x:0>16}{x:0>16}", .{ r.int(u64), r.int(u64) });
        e.* = .{
            .timestamp_ns = 1_760_000_000_000_000_000 + @as(i64, @intCast(i)) * 1_234_567,
            .remote_addr = try arena.print("203.0.113.{d}", .{r.intRangeAtMost(u8, 1, 254)}),
            .method = methods[r.uintLessThan(usize, methods.len)],
            .target = try arena.print("/api/v1/items/{d}?expand=owner&fields=id,name", .{r.uintLessThan(u32, 100000)}),
            .protocol = "HTTP/1.1",
            .status = statuses[r.uintLessThan(usize, statuses.len)],
            .request_bytes = r.uintLessThan(u64, 4096),
            .response_bytes = r.uintLessThan(u64, 100000),
            .latency_ns = r.uintLessThan(u64, 50_000_000),
            .user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
            .referer = if (i % 2 == 0) "https://example.com/dashboard" else null,
            .request_id = rid,
            .trace_id = if (i % 2 == 0) "4bf92f3577b34da6a3ce929d0e0e4736" else null,
            .span_id = if (i % 2 == 0) "00f067aa0ba902b7" else null,
        };
        const x = "\x01";
        try w.print("{d}\t{s}\t{s}\t{s}\t{s}\t{d}\t{d}\t{d}\t{d}\t{s}\t{s}\t{s}\t{s}\t{s}\n", .{
            e.timestamp_ns,      e.remote_addr.?,    e.method,           e.target,
            e.protocol,          e.status,           e.request_bytes.?,  e.response_bytes.?,
            e.latency_ns.?,      e.user_agent.?,     e.referer orelse x, e.request_id.?,
            e.trace_id orelse x, e.span_id orelse x,
        });
    }
    try dir.writeFile(io, .{ .sub_path = "entries.tsv", .data = tsv.written() });
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
            for (filters) |f| hit = hit or std.mem.find(u8, name, f) != null;
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
        const in_net = std.mem.startsWith(u8, name, if (@hasDecl(@This(), "net_prefix")) @field(@This(), "net_prefix") else "");
        if (net_base) |nb| {
            if (std.mem.eql(u8, nb, name)) {
                base_ours = ours.best_ns;
                base_ref = go.best_ns;
            } else if (in_net and base_ref != 0 and go.best_ns > base_ref) {
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
