// SPDX-License-Identifier: MIT

//! Comparative benchmark: `datefmt` against Go's standard `time` package
//! (go 1.26.0; the reference), the program behind the `**Performance:**` line
//! of the maturity card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-datefmt` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26.0 (stdlib
//! only, `GOPROXY=off`). Run from the repository root.
//!
//! Workloads -- what an HTTP server does with dates, over 64 fixed-seed
//! timestamps (1990..2060); one op = all 64:
//!   fmt_imf             Unix seconds -> `Date:` header text (IMF-fixdate);
//!                       ours `unixToParts` + `format`, Go `Format(http.TimeFormat)`
//!   fmt_rfc3339         Unix seconds -> `YYYY-MM-DDThh:mm:ssZ`: ours
//!                       `formatRfc3339`, Go `Format(time.RFC3339)` -- both
//!                       sides' canned path (Go special-cases that layout)
//!   parse_imf           `If-Modified-Since` text -> Unix seconds;
//!                       ours `parse` + `partsToUnix`, Go `time.Parse(http.TimeFormat)`
//!   parse_rfc3339       RFC 3339 `...Z` -> Unix seconds, ours `parseXsdDateTime`
//!   parse_rfc3339_frac  RFC 3339 with 9 fraction digits and a +02:00 offset,
//!                       ours `parseXsdDateTimeNs`, Go `time.Parse(time.RFC3339)`
//!   fmt_rfc3339_tokens  the same text through the token engine, ours
//!                       `format("YYYY-MM-DD[T]hh:mm:ss[Z]")`, Go
//!                       `Format("2006-01-02T15:04:05Z")` -- a layout Go does
//!                       NOT special-case, so generic path against generic path
//!   *_layout            fmt_imf, fmt_rfc3339_tokens, parse_imf through a
//!                       `datefmt.Layout` compiled once (comptime); Go runs the
//!                       same code as the row without the suffix (it has no
//!                       compiled layout -- its layout string is the constant)
//!   fmt_imf_canned      `formatImfFixdate`, Go as fmt_imf
//!   parse_imf_canned    `parseImfFixdate` + `partsToUnix`, Go as parse_imf
//!   parse_rfc3339_parts `parseRfc3339` (offset kept, applied after), on the
//!                       parse_rfc3339_frac inputs, Go as that row
//! Each side times the same way (double the batch until it takes over 100 ms,
//! best of five); per workload the sides alternate for BENCH_ROUNDS (default 3)
//! rounds, each keeping its best. The result count (sum of output bytes, or of
//! the parsed instants) must agree or the run fails. Ratios are ours/Go by
//! wall time; the verdict is the WORST ratio. Arguments filter workloads.
//! Both sides allocate their output string (ours via `smp_allocator`, Go's GC).

const std = @import("std");
const bench = @import("testkit").bench;
const datefmt = @import("datefmt");

const ref_short = "Go";
const ref_card = "Go 1.26.0 time";
const bench_name = "bench-datefmt";
const work_dir = ".zig-cache/bench-datefmt";
const go_dir = "modules/datefmt/tools/go_bench";
const N = 64;
const imf_fmt = "EEE, DD MMM YYYY hh:mm:ss [GMT]";
const rfc_fmt = "YYYY-MM-DD[T]hh:mm:ss[Z]";

const net_base: ?[]const u8 = null;
const info_only = [_][]const u8{};
const names = [_][]const u8{ "fmt_imf", "fmt_rfc3339", "parse_imf", "parse_rfc3339", "parse_rfc3339_frac", "fmt_imf_layout", "fmt_rfc3339_layout", "parse_imf_layout", "fmt_rfc3339_tokens", "fmt_imf_canned", "parse_imf_canned", "parse_rfc3339_parts" };
const imf_layout = datefmt.Layout.compile(imf_fmt) catch unreachable;
const rfc_layout = datefmt.Layout.compile(rfc_fmt) catch unreachable;

const Data = struct {
    unix: [N]i64,
    imf: [N][]const u8,
    rfc: [N][]const u8,
    rfcns: [N][]const u8,
};

fn sumBytes(s: []const u8) u64 {
    var t: u64 = 0;
    for (s) |c| t += c;
    return t;
}

fn once(d: *const Data, w: usize) u64 {
    const a = std.heap.smp_allocator;
    var t: u64 = 0;
    switch (w) {
        0, 8 => for (d.unix) |u| {
            const s = datefmt.format(a, datefmt.unixToParts(u), if (w == 0) imf_fmt else rfc_fmt) catch unreachable;
            t += sumBytes(s);
            a.free(s);
        },
        2 => for (d.imf) |s| {
            const p = datefmt.parse(s, imf_fmt) catch unreachable;
            t +%= @bitCast(datefmt.partsToUnix(p));
        },
        5, 6 => for (d.unix) |u| {
            const l = if (w == 5) &imf_layout else &rfc_layout;
            const s = l.format(a, datefmt.unixToParts(u)) catch unreachable;
            t += sumBytes(s);
            a.free(s);
        },
        7 => for (d.imf) |s| {
            const p = imf_layout.parse(s) catch unreachable;
            t +%= @bitCast(datefmt.partsToUnix(p));
        },
        1, 9 => for (d.unix) |u| {
            const p = datefmt.unixToParts(u);
            const s = (if (w == 1) datefmt.formatRfc3339(a, p, 0) else datefmt.formatImfFixdate(a, p)) catch unreachable;
            t += sumBytes(s);
            a.free(s);
        },
        10 => for (d.imf) |s| {
            const p = datefmt.parseImfFixdate(s) catch unreachable;
            t +%= @bitCast(datefmt.partsToUnix(p));
        },
        11 => for (d.rfcns) |s| {
            const p = datefmt.parseRfc3339(s) catch unreachable;
            t +%= @bitCast(datefmt.partsToUnix(p) - @as(i64, p.off_min.?) * 60);
            t += p.nanosecond;
        },
        3 => for (d.rfc) |s| {
            t +%= @bitCast(datefmt.parseXsdDateTime(s) catch unreachable);
        },
        4 => for (d.rfcns) |s| {
            const r = datefmt.parseXsdDateTimeNs(s) catch unreachable;
            t +%= @bitCast(r.unix);
            t += r.nanosecond;
        },
        else => unreachable,
    }
    return t;
}

fn setup(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) !Data {
    // Inputs: fixed seed; the strings are rendered by our own `format`, so a
    // Go `Format` that disagrees shows up as a count mismatch in fmt_*.
    var prng = std.Random.DefaultPrng.init(0xda7e_f317);
    const r = prng.random();
    var d: Data = undefined;
    var f_unix: std.Io.Writer.Allocating = .init(arena);
    var f_imf: std.Io.Writer.Allocating = .init(arena);
    var f_rfc: std.Io.Writer.Allocating = .init(arena);
    var f_ns: std.Io.Writer.Allocating = .init(arena);
    for (0..N) |i| {
        d.unix[i] = r.intRangeAtMost(i64, 631_152_000, 2_840_140_800);
        const p = datefmt.unixToParts(d.unix[i]);
        d.imf[i] = try datefmt.format(arena, p, imf_fmt);
        d.rfc[i] = try datefmt.format(arena, p, rfc_fmt);
        const base = try datefmt.format(arena, p, "YYYY-MM-DD[T]hh:mm:ss");
        d.rfcns[i] = try arena.print("{s}.{d:0>9}+02:00", .{ base, r.uintLessThan(u32, 1_000_000_000) });
        try f_unix.writer.print("{d}\n", .{d.unix[i]});
        try f_imf.writer.print("{s}\n", .{d.imf[i]});
        try f_rfc.writer.print("{s}\n", .{d.rfc[i]});
        try f_ns.writer.print("{s}\n", .{d.rfcns[i]});
    }
    try dir.writeFile(io, .{ .sub_path = "unix.txt", .data = f_unix.written() });
    try dir.writeFile(io, .{ .sub_path = "imf.txt", .data = f_imf.written() });
    try dir.writeFile(io, .{ .sub_path = "rfc.txt", .data = f_rfc.written() });
    try dir.writeFile(io, .{ .sub_path = "rfcns.txt", .data = f_ns.written() });
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
