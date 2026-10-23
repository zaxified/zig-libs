// SPDX-License-Identifier: MIT

//! Comparative benchmark: `numparse` against Babel 2.17 `numbers.parse_decimal(s,
//! locale, strict=True)` (system python3) -- the program behind the
//! `**Performance:**` line of the maturity card (CONVENTIONS.md §9, kept
//! instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-numparse` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `python3` with
//! Babel on PATH. Run from the repository root.
//!
//! The reference side is `tools/bench_ref.py` (`python3 -I`), one process per
//! workload and round; it times itself as this side does (double the batch until
//! it takes over 100 ms, best of five) and prints `name \t ns \t count`.
//!
//! One op = every line of the workload's input once (1000 lines):
//!
//!   en_US_grouped  `1,234,567.89` style, some negative
//!   de_grouped     `1.234.567,89`
//!   cs_nbsp        `1 234 567,89` with U+00A0 groups
//!   en_IN_indian   `12,34,567.89`
//!   fr_mixed       half valid (U+202F groups or ungrouped), half refused
//!   ar_EG_native   Arabic-Indic digits and U+066B, ungrouped
//!
//! Ours is `numparse.parse(s, opts)` with the Options looked up once per
//! workload (Babel gets a resolved `Locale` object likewise). `count` packs
//! the number of accepted lines (low 32 bits) and the sum of the parsed values'
//! raw Decimal representation, mod 2^32 (high 32 bits): a parser that accepts
//! but mis-parses cannot agree. The sides alternate for BENCH_ROUNDS (default 3)
//! rounds, each keeping its best; ratios are ours/reference by wall time; the
//! verdict is the worst. Arguments filter workloads.
//!
//! The fastest in the field is timed beside it: ICU4C's `DecimalFormat::parse`
//! (strict, the system libicu via `tools/icu_bench/build.sh`; needs g++ and
//! libicu-dev, `BENCH_ICU=0` skips it), over the same files and with the same
//! `count`, so it must agree with Babel too. The card's `fastest` figure is
//! ours / min(Babel, ICU) per workload, worst over the workloads.

const std = @import("std");
const bench = @import("testkit").bench;
const numparse = @import("numparse");

const bench_name = "bench-numparse";
const work_dir = ".zig-cache/bench-numparse";
const ref_script = "modules/numparse/tools/bench_ref.py";
const icu_build = "modules/numparse/tools/icu_bench/build.sh";
const icu_exe = "modules/numparse/tools/icu_bench/target/icu_bench";
const lines_per_op = 1000;

const Work = struct { name: []const u8, locale: []const u8, native: bool = false };
const works = [_]Work{
    .{ .name = "en_US_grouped", .locale = "en_US" },
    .{ .name = "de_grouped", .locale = "de" },
    .{ .name = "cs_nbsp", .locale = "cs" },
    .{ .name = "en_IN_indian", .locale = "en_IN" },
    .{ .name = "fr_mixed", .locale = "fr" },
    .{ .name = "ar_EG_native", .locale = "ar_EG", .native = true },
};

// ── input generation ─────────────────────────────────────────────────────────

/// `v` in decimal with a group separator every `first` digits from the right,
/// then every `rest` (western 3/3, indian 3/2).
fn grouped(w: *std.Io.Writer, v: u64, sep: []const u8, rest: usize) !void {
    var digits: [24]u8 = undefined;
    const s = std.fmt.bufPrint(&digits, "{d}", .{v}) catch unreachable;
    for (s, 0..) |c, i| {
        const left = s.len - i; // digits remaining including this one
        if (i != 0 and ((left == 3) or (left > 3 and (left - 3) % rest == 0))) try w.writeAll(sep);
        try w.writeByte(c);
    }
}

fn nativeDigits(w: *std.Io.Writer, v: u64, frac: []const u8) !void {
    var digits: [24]u8 = undefined;
    const s = std.fmt.bufPrint(&digits, "{d}", .{v}) catch unreachable;
    for (s) |c| try w.print("{u}", .{@as(u21, 0x660) + (c - '0')});
    try w.writeAll("\u{066B}");
    for (frac) |c| try w.print("{u}", .{@as(u21, 0x660) + (c - '0')});
}

fn fracDigits(r: std.Random, buf: *[2]u8) []const u8 {
    buf[0] = '0' + r.uintLessThan(u8, 10);
    buf[1] = '0' + r.uintLessThan(u8, 10);
    return buf[0..2];
}

fn generate(arena: std.mem.Allocator, wk: Work, wi: usize) ![]const u8 {
    var out: std.Io.Writer.Allocating = .init(arena);
    const w = &out.writer;
    var prng: std.Random.DefaultPrng = .init(0x6e756d70 + wi);
    const r = prng.random();
    for (0..lines_per_op) |i| {
        var fb: [2]u8 = undefined;
        const frac = fracDigits(r, &fb);
        // 4..9 integer digits, so that every grouping has several groups.
        const mag = std.math.pow(u64, 10, r.intRangeAtMost(u6, 3, 8));
        const v = mag + r.uintLessThan(u64, mag * 9);
        const neg = i % 7 == 3;
        if (neg and !wk.native) try w.writeByte('-');
        switch (wi) {
            0 => {
                try grouped(w, v, ",", 3);
                try w.print(".{s}", .{frac});
            },
            1 => {
                try grouped(w, v, ".", 3);
                try w.print(",{s}", .{frac});
            },
            2 => {
                try grouped(w, v, "\u{00A0}", 3);
                try w.print(",{s}", .{frac});
            },
            3 => {
                try grouped(w, v, ",", 2);
                try w.print(".{s}", .{frac});
            },
            4 => {
                // half valid, half refused (five refusal shapes, rotating)
                if (i % 2 == 0) {
                    if (i % 4 == 0) try grouped(w, v, "\u{202F}", 3) else try w.print("{d}", .{v});
                    try w.print(",{s}", .{frac});
                } else switch (i / 2 % 5) {
                    0 => try w.print("{d}x{s}", .{ v, frac }), // junk inside
                    1 => { // wrong group width
                        try grouped(w, v, "\u{202F}", 3);
                        try w.print("\u{202F}12,{s}", .{frac});
                    },
                    2 => try w.print("{d},{s},{s}", .{ v, frac, frac }), // two decimal separators
                    3 => try w.print("abc{d}", .{v}), // junk before
                    else => { // wrong separator for the locale
                        try grouped(w, v, ",", 3);
                        try w.print(".{s}", .{frac});
                    },
                }
            },
            else => try nativeDigits(w, v, frac),
        }
        try w.writeByte('\n');
    }
    return out.written();
}

// ── our side ─────────────────────────────────────────────────────────────────

const Prepared = struct { lines: [][]const u8, opts: numparse.Options };

fn once(ps: *const [works.len]Prepared, wi: usize) u64 {
    const p = ps[wi];
    var accepted: u32 = 0;
    var digest: u32 = 0;
    for (p.lines) |s| {
        const d = numparse.parse(s, p.opts) orelse continue;
        accepted += 1;
        digest +%= @truncate(@as(u128, @bitCast(d.raw)));
    }
    return (@as(u64, digest) << 32) | accepted;
}

fn selected(name: []const u8, filters: []const [:0]const u8) bool {
    if (filters.len == 0) return true;
    for (filters) |f| if (std.mem.find(u8, name, f) != null) return true;
    return false;
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

    var ps: [works.len]Prepared = undefined;
    for (works, 0..) |wk, wi| {
        const text = try generate(arena, wk, wi);
        const file = try std.fmt.allocPrint(arena, "{s}.txt", .{wk.name});
        try dir.writeFile(io, .{ .sub_path = file, .data = text });
        var list: std.ArrayList([]const u8) = .empty;
        var it = std.mem.splitScalar(u8, std.mem.trimEnd(u8, text, "\n"), '\n');
        while (it.next()) |l| try list.append(arena, l);
        ps[wi] = .{
            .lines = list.items,
            .opts = (if (wk.native) numparse.localeNative(wk.locale) else numparse.locale(wk.locale)) orelse @panic("unknown locale"),
        };
    }

    const py_ver = blk: {
        const r = std.process.run(arena, io, .{ .argv = &.{ "python3", "-I", "-c", "import babel;print(babel.__version__)" } }) catch |e| {
            std.debug.print("{s}: could not run python3 ({t}) -- the benchmark needs it\n", .{ bench_name, e });
            return 1;
        };
        break :blk std.mem.trim(u8, r.stdout, " \n");
    };

    const use_icu = if (init.environ_map.get("BENCH_ICU")) |v| !std.mem.eql(u8, v, "0") else true;
    if (use_icu) {
        const r = std.process.run(arena, io, .{ .argv = &.{ "bash", icu_build } }) catch |e| {
            std.debug.print("{s}: could not run {s} ({t}) -- BENCH_ICU=0 skips the ICU side\n", .{ bench_name, icu_build, e });
            return 1;
        };
        if (r.term != .exited or r.term.exited != 0) {
            std.debug.print("{s}: ICU side build failed:\n{s}\n", .{ bench_name, r.stderr });
            return 1;
        }
    }

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.print("{d} lines per op\n", .{lines_per_op});
    try w.print("{s:<16} {s:>13} {s:>13} {s:>8} {s:>7} {s:>7}  count\n", .{ "workload", "ours ns", "ref ns", "/ref", "spr us", "spr ref" });
    try w.flush();
    var worst: f64 = 0;
    var worst_fast: f64 = 0;
    var best: f64 = std.math.inf(f64);
    var max_spread: f64 = 0;
    var mismatch = false;
    var banner: []const u8 = "";
    var icu_banner: []const u8 = "";
    for (works, 0..) |wk, wi| {
        if (!selected(wk.name, filters)) continue;
        var ours: bench.Side = .{};
        var ref: bench.Side = .{};
        var icu: bench.Side = .{};
        for (0..rounds) |_| {
            ref.add(try bench.foreignArgv(arena, io, bench_name, &.{ "python3", "-I", ref_script, abs, wk.name }, wk.name, &banner));
            if (use_icu) icu.add(try bench.foreignArgv(arena, io, bench_name, &.{ icu_exe, abs, wk.name }, wk.name, &icu_banner));
            ours.add(bench.timeIt(io, .{ .fd = null }, once, .{ &ps, wi }, true));
        }
        const ratio = ours.best_ns / ref.best_ns;
        worst = @max(worst, ratio);
        best = @min(best, ratio);
        max_spread = @max(max_spread, @max(ours.spread(false), ref.spread(false)));
        const same = ours.count == ref.count;
        mismatch = mismatch or !same;
        try w.print("{s:<16} {d:>13.0} {d:>13.0} {d:>8.4} {d:>6.1}% {d:>6.1}%  accepted {d}, digest {d}{s}\n", .{ wk.name, ours.best_ns, ref.best_ns, ratio, 100 * ours.spread(false), 100 * ref.spread(false), ours.count & 0xFFFFFFFF, ours.count >> 32, if (same) "" else " ≠ ref" });
        if (!same) try w.print("  ref accepted {d}, digest {d}\n", .{ ref.count & 0xFFFFFFFF, ref.count >> 32 });
        if (use_icu) {
            const fastest = @min(ref.best_ns, icu.best_ns);
            const rf = ours.best_ns / fastest;
            worst_fast = @max(worst_fast, rf);
            max_spread = @max(max_spread, icu.spread(false));
            const icu_same = icu.count == ref.count;
            mismatch = mismatch or !icu_same;
            try w.print("{s:<16} {s:>13} {d:>13.0} {d:>8.4} {s:>7} {d:>6.1}%  ICU{s}\n", .{ "", "", icu.best_ns, rf, "", 100 * icu.spread(false), if (icu_same) "" else " ≠ ref" });
        }
        try w.flush();
    }
    try w.print("rounds: {d}; ratios by wall time; largest spread {d:.1}%{s}\n", .{ rounds, 100 * max_spread, if (max_spread > 0.05) " (OVER 5 %: noisy run, repeat)" else "" });
    if (banner.len > 0) try w.print("reference: {s}\n", .{std.mem.trim(u8, banner, " \n")});
    if (icu_banner.len > 0) try w.print("fastest side: {s}\n", .{std.mem.trim(u8, icu_banner, " \n")});
    if (mismatch) {
        try w.writeAll(bench_name ++ ": FAILED -- a result count differs from the reference's; the timing means nothing until it agrees\n");
        try w.flush();
        return 1;
    }
    try w.print("\nworst ours/ref = {d:.4} (best {d:.4})\n", .{ worst, best });
    if (use_icu) try w.print("worst ours/fastest = {d:.4}\n", .{worst_fast});
    if (filters.len == 0) {
        if (use_icu)
            try w.print("card: **Performance:** ref {d:.4}–{d:.4}× Babel {s} parse_decimal(strict) · fastest {d:.3}× ICU4C DecimalFormat::parse (measured <today>)\n", .{ best, worst, py_ver, worst_fast })
        else
            try w.print("card: **Performance:** ref {d:.4}–{d:.4}× Babel {s} parse_decimal(strict) · fastest ? (measured <today>)\n", .{ best, worst, py_ver });
    }
    try w.flush();
    return 0;
}
