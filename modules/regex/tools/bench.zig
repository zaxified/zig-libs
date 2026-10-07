// SPDX-License-Identifier: MIT

//! Comparative benchmark: `regex` against Go's `regexp` (the reference), the
//! program behind the `**Performance:**` line of the maturity card
//! (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-regex` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26.0
//! (standard library only, `GOPROXY=off`) on PATH. Run from the repository root.
//!
//!   zig build bench-regex               # every workload
//!   zig build bench-regex -- cz_        # workloads whose name contains `cz_`
//!
//! How it measures. The workloads are defined here once. This program writes
//! the texts (generated from fixed seeds, so every run sees the same bytes) and
//! the workload list into `.zig-cache/bench-regex/`, runs `tools/go_bench` over
//! the same files, then runs its own side. Both sides time the same way: double
//! the iteration count until one batch takes over 100 ms, then keep the best of
//! five batches. Both report a result count per workload (matches found, or the
//! submatch slots); a count that differs fails the run, because a faster wrong
//! answer is not a speed-up. The verdict is the WORST ratio, ours/Go — the card
//! records the loss, never an average that hides it.

const std = @import("std");
const regex = @import("regex");

const Mode = enum { match, findall, findallsub, submatch, compile_submatch };

const Workload = struct {
    name: []const u8,
    mode: Mode,
    pattern: []const u8,
    /// A generated text (`rnd`, `inv`, `cz`) or a short literal string.
    text: Text,
};

const Text = union(enum) { file: []const u8, literal: []const u8 };

const workloads = [_]Workload{
    // Go's regexp benchmark shapes: no match in 1 MiB of printable noise.
    .{ .name = "easy0", .mode = .match, .pattern = "ABCDEFGHIJKLMNOPQRSTUVWXYZ$", .text = .{ .file = "rnd" } },
    .{ .name = "easy1", .mode = .match, .pattern = "A[AB]B[BC]C[CD]D[DE]E[EF]F[FG]G[GH]H[HI]I[IJ]J$", .text = .{ .file = "rnd" } },
    .{ .name = "medium", .mode = .match, .pattern = "[XYZ]ABCDEFGHIJKLMNOPQRSTUVWXYZ$", .text = .{ .file = "rnd" } },
    .{ .name = "hard", .mode = .match, .pattern = "[ -~]*ABCDEFGHIJKLMNOPQRSTUVWXYZ$", .text = .{ .file = "rnd" } },
    .{ .name = "hard1", .mode = .match, .pattern = "ABCD|CDEF|EFGH|GHIJ|IJKL|KLMN|MNOP|OPQR|QRST|STUV|UVWX|WXYZ", .text = .{ .file = "rnd" } },
    .{ .name = "icase", .mode = .match, .pattern = "(?i)abcdefghijklmnopqrstuvwxyz$", .text = .{ .file = "rnd" } },
    // Searches with positions.
    .{ .name = "inv_sub", .mode = .findallsub, .pattern = "INV-([0-9]{4}-[0-9]{4})", .text = .{ .file = "inv" } },
    .{ .name = "inv_all", .mode = .findall, .pattern = "INV-[0-9]{4}-[0-9]{4}", .text = .{ .file = "inv" } },
    .{ .name = "dense_AZ", .mode = .findall, .pattern = "[A-Z]+", .text = .{ .file = "rnd" } },
    .{ .name = "lit_all", .mode = .findall, .pattern = "ABC", .text = .{ .file = "rnd" } },
    // Unicode text (Czech, Greek, Cyrillic).
    .{ .name = "cz_letters", .mode = .findall, .pattern = "\\p{L}+", .text = .{ .file = "cz" } },
    .{ .name = "cz_words", .mode = .findall, .pattern = "\\b\\w+\\b", .text = .{ .file = "cz" } },
    .{ .name = "cz_icase", .mode = .findall, .pattern = "(?i)žluť\\w*", .text = .{ .file = "cz" } },
    .{ .name = "cz_digits", .mode = .findall, .pattern = "[0-9]+", .text = .{ .file = "cz" } },
    // Short strings: per-call overhead.
    .{ .name = "anch_all", .mode = .findall, .pattern = "^[a-z]+", .text = .{ .literal = "hello world 123" } },
    .{ .name = "sub_short", .mode = .submatch, .pattern = "(\\d+)-(\\d+)", .text = .{ .literal = "abc 123-456 def" } },
    .{ .name = "sub_email", .mode = .submatch, .pattern = "^([a-z0-9._]+)@([a-z0-9.-]+)\\.([a-z]{2,})$", .text = .{ .literal = "john.doe@example.com" } },
    .{ .name = "compile_sub", .mode = .compile_submatch, .pattern = "INV-([0-9]+)-([0-9]+)", .text = .{ .literal = "Invoice INV-2024-0042 for customer 17" } },
};

const work_dir = ".zig-cache/bench-regex";

// ── generated texts ─────────────────────────────────────────────────────────

/// 1 MiB of printable ASCII with a newline about every 31 bytes.
fn genRnd(gpa: std.mem.Allocator) ![]u8 {
    const t = try gpa.alloc(u8, 1 << 20);
    var prng = std.Random.DefaultPrng.init(0x0b5e_55ed_0001);
    const r = prng.random();
    for (t) |*c| c.* = if (r.uintLessThan(u8, 31) == 0) '\n' else ' ' + r.uintLessThan(u8, '~' - ' ' + 1);
    return t;
}

/// ~85 KiB of invoice-like lines, two in three carrying an `INV-dddd-dddd` id.
fn genInv(gpa: std.mem.Allocator) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(gpa);
    var prng = std.Random.DefaultPrng.init(0x0b5e_55ed_0002);
    const r = prng.random();
    const customers = [_][]const u8{ "Novák", "Dvořák", "Svoboda", "Acme s.r.o.", "Kovář", "Beta a.s." };
    while (out.written().len < 85 * 1024) {
        const c = customers[r.uintLessThan(usize, customers.len)];
        if (r.uintLessThan(u8, 3) != 0) {
            try out.writer.print("Order {d} ref INV-{d:0>4}-{d:0>4} for {s}, total {d}.{d:0>2} CZK\n", .{
                r.uintLessThan(u32, 100000), r.uintLessThan(u32, 10000), r.uintLessThan(u32, 10000), c, r.uintLessThan(u32, 100000), r.uintLessThan(u32, 100),
            });
        } else {
            try out.writer.print("Note {d}: call {s} about the delivery on day {d}\n", .{ r.uintLessThan(u32, 1000), c, r.uintLessThan(u32, 31) + 1 });
        }
    }
    return out.toOwnedSlice();
}

/// 1 MiB of Czech, Greek and Cyrillic words with numbers and punctuation.
fn genCz(gpa: std.mem.Allocator) ![]u8 {
    const words = [_][]const u8{
        "žluťoučký",
        "kůň",
        "úpěl",
        "ďábelské",
        "ódy",
        "Příliš",
        "Žluťásek",
        "čeština",
        "řeřicha",
        "šťovík",
        "ŽLUŤOUČKÝ",
        "město",
        "dům",
        "který",
        "proto",
        "και",
        "λόγος",
        "Αθήνα",
        "θάλασσα",
        "привет",
        "Москва",
        "язык",
        "город",
        "the",
        "of",
        "data",
        "žluť",
    };
    var out: std.Io.Writer.Allocating = .init(gpa);
    var prng = std.Random.DefaultPrng.init(0x0b5e_55ed_0003);
    const r = prng.random();
    while (out.written().len < (1 << 20) - 32) {
        switch (r.uintLessThan(u8, 12)) {
            0 => try out.writer.print("{d} ", .{r.uintLessThan(u32, 100000)}),
            1 => try out.writer.writeAll(", "),
            2 => try out.writer.writeAll(".\n"),
            else => {
                try out.writer.writeAll(words[r.uintLessThan(usize, words.len)]);
                try out.writer.writeByte(' ');
            },
        }
    }
    return out.toOwnedSlice();
}

// ── our side ────────────────────────────────────────────────────────────────

const gpa_fast = std.heap.smp_allocator;

const Ctx = struct { re: *const regex.Regex, m: *regex.Matcher, s: []const u8, pattern: []const u8, mode: Mode };

fn runOnce(c: Ctx) usize {
    switch (c.mode) {
        .match => return @intFromBool(c.re.isMatch(c.s)),
        .findall => {
            var it = c.m.iterator(c.s);
            var k: usize = 0;
            while (it.next()) |_| k += 1;
            return k;
        },
        .findallsub => {
            var it = c.m.iterator(c.s);
            var g: [8]?regex.Span = undefined;
            var k: usize = 0;
            while (it.nextCaptures(&g)) |_| k += 1;
            return k;
        },
        .submatch => {
            var g: [8]?regex.Span = undefined;
            if (!c.m.captures(c.s, 0, &g)) return 0;
            return 2 * c.re.groupCount() + 2;
        },
        .compile_submatch => {
            var re = regex.Regex.compile(gpa_fast, c.pattern) catch unreachable;
            defer re.deinit(gpa_fast);
            var m = regex.Matcher.init(gpa_fast, &re) catch unreachable;
            defer m.deinit();
            var g: [8]?regex.Span = undefined;
            return if (m.captures(c.s, 0, &g)) 2 * re.groupCount() + 2 else 0;
        },
    }
}

fn timeIt(io: std.Io, c: Ctx) struct { ns: f64, count: usize } {
    var n: usize = 1;
    while (true) {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| std.mem.doNotOptimizeAway(runOnce(c));
        if (t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds > 100_000_000) break;
        n *= 2;
    }
    var best: i96 = std.math.maxInt(i96);
    var count: usize = 0;
    for (0..5) |_| {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| count = runOnce(c);
        best = @min(best, t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds);
    }
    return .{ .ns = @as(f64, @floatFromInt(best)) / @as(f64, @floatFromInt(n)), .count = count };
}

// ── driver ──────────────────────────────────────────────────────────────────

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    const only: ?[]const u8 = if (args.len > 1) args[1] else null;

    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    var dir = try cwd.openDir(io, work_dir, .{});
    defer dir.close(io);

    const texts = .{ .rnd = try genRnd(arena), .inv = try genInv(arena), .cz = try genCz(arena) };
    try dir.writeFile(io, .{ .sub_path = "rnd.txt", .data = texts.rnd });
    try dir.writeFile(io, .{ .sub_path = "inv.txt", .data = texts.inv });
    try dir.writeFile(io, .{ .sub_path = "cz.txt", .data = texts.cz });

    // The list the Go side reads: name, mode, pattern, text file -- tab-separated
    // (no pattern here contains a tab). Literal strings get a file each.
    var list: std.Io.Writer.Allocating = .init(arena);
    for (workloads) |w| {
        if (only) |o| if (std.mem.indexOf(u8, w.name, o) == null) continue;
        const file = switch (w.text) {
            .file => |f| try std.fmt.allocPrint(arena, "{s}.txt", .{f}),
            .literal => |l| blk: {
                const f = try std.fmt.allocPrint(arena, "lit-{s}.txt", .{w.name});
                try dir.writeFile(io, .{ .sub_path = f, .data = l });
                break :blk f;
            },
        };
        try list.writer.print("{s}\t{t}\t{s}\t{s}\n", .{ w.name, w.mode, w.pattern, file });
    }
    try dir.writeFile(io, .{ .sub_path = "workloads.tsv", .data = list.written() });

    // Go first, so its numbers are not taken right after ours warmed the caches
    // for a different program.
    var env = try init.environ_map.clone(arena);
    try env.put("GOTOOLCHAIN", "go1.26.0");
    try env.put("GOPROXY", "off");
    try env.put("GOFLAGS", "-mod=readonly");
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);
    std.debug.print("bench-regex: Go regexp ...\n", .{});
    const go = std.process.run(arena, io, .{
        .argv = &.{ "go", "run", ".", abs },
        .environ_map = &env,
        .cwd = .{ .path = "modules/regex/tools/go_bench" },
    }) catch |e| {
        std.debug.print("bench-regex: could not run go ({t}) -- the benchmark needs it\n", .{e});
        return 1;
    };
    if (go.term != .exited or go.term.exited != 0) {
        std.debug.print("bench-regex: go_bench failed:\n{s}\n", .{go.stderr});
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

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.print("{s:<12} {s:>14} {s:>14} {s:>7}  count\n", .{ "workload", "ours ns/op", "go ns/op", "ours/go" });
    try w.flush();

    var worst: f64 = 0;
    var best: f64 = std.math.inf(f64);
    var mismatch = false;
    for (workloads) |wl| {
        if (only) |o| if (std.mem.indexOf(u8, wl.name, o) == null) continue;
        const s: []const u8 = switch (wl.text) {
            .file => |f| if (std.mem.eql(u8, f, "rnd")) texts.rnd else if (std.mem.eql(u8, f, "inv")) texts.inv else texts.cz,
            .literal => |l| l,
        };
        var re = try regex.Regex.compile(gpa_fast, wl.pattern);
        defer re.deinit(gpa_fast);
        var m = try regex.Matcher.init(gpa_fast, &re);
        defer m.deinit();
        const ours = timeIt(io, .{ .re = &re, .m = &m, .s = s, .pattern = wl.pattern, .mode = wl.mode });
        const theirs = go_rows.get(wl.name) orelse {
            std.debug.print("bench-regex: Go reported nothing for {s}\n", .{wl.name});
            return 1;
        };
        const ratio = ours.ns / theirs.ns;
        worst = @max(worst, ratio);
        best = @min(best, ratio);
        const same = ours.count == theirs.count;
        if (!same) mismatch = true;
        try w.print("{s:<12} {d:>14.1} {d:>14.1} {d:>7.2}  {d}{s}\n", .{ wl.name, ours.ns, theirs.ns, ratio, ours.count, if (same) "" else " ≠ Go" });
        try w.flush();
    }
    if (mismatch) {
        try w.writeAll("bench-regex: FAILED -- a result count differs from Go's; the timing means nothing until it agrees\n");
        try w.flush();
        return 1;
    }
    try w.print("\nworst ours/go = {d:.2} (best {d:.2})\n", .{ worst, best });
    try w.print("card: **Performance:** ref {d:.2}–{d:.2}× Go regexp go1.26 · fastest ? (measured <today>)\n", .{ best, worst });
    try w.flush();
    return 0;
}
