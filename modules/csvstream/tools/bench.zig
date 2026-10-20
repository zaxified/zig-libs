// SPDX-License-Identifier: MIT

//! Comparative benchmark: `csvstream` against Go `encoding/csv` (the reference)
//! -- the program behind the `**Performance:**` line of the maturity card
//! (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-csvstream` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `go` (standard
//! library only; `tools/go_bench`, built offline). Run from the repository root.
//!
//! The data is generated once (seeded PRNG, `tools` generator below) into
//! `.zig-cache/bench-csvstream/*-v1.csv` and read by both sides from the same
//! files; an existing file is reused (bump the `-v1` suffix in both this file
//! and `go_bench/main.go` if a generator changes).
//!
//!   narrow       10 numeric columns x 1 000 000 rows, no quotes           file-backed
//!   wide         100 text columns x 100 000 rows (10 % empty), no quotes  file-backed
//!   quoted       10 columns x 400 000 rows, EVERY field quoted, 10 % of
//!                the fields hold a doubled quote                          file-backed
//!   multiline    6 columns x 300 000 rows, one quoted field per row with
//!                1-3 line breaks (ours `.span`, Go spans natively)        file-backed
//!   mem_narrow   the narrow file already in RAM: `LineIterator` +
//!                `splitFields` vs Go over a `bytes.Reader` (no file I/O)
//!   write        1 000 000 records (a 1000-record pool of plain, comma,
//!                quote, line-break and empty fields, cycled) through
//!                `writeRecord` vs `csv.Writer`, both into a pre-sized
//!                in-memory buffer, LF terminator
//!
//! File-backed = `StreamReader.nextFields` over a `std.Io.File` (default 10 MiB
//! chunk) vs `csv.NewReader(*os.File)` (its own 4 KiB bufio); the file is
//! opened per op on both sides and sits in the page cache. Go reads with
//! `ReuseRecord = true`, `LazyQuotes = true` (our reading), `FieldsPerRecord =
//! -1`, every record to the end. OUR escaped-quote copies (`splitFields`
//! allocates only for fields holding `""`) come from a `FixedBufferAllocator`
//! (1 MiB) reset per record -- no allocator call per field, no free; the field
//! slice buffer is a stack array of 128.
//!
//! "Touching" every field: per field h = (h ^ len) * P, then (h ^ first byte) *
//! P and (h ^ last byte) * P if it is not empty; per record h = (h ^ field
//! count) * P (FNV-1a offset and prime, same on both sides). Unescaping shows in
//! `len`. The reader workloads' count is h.
//!
//! BEFORE ANYTHING IS TIMED the Go side runs in `check` mode and its record
//! count, field count and checksum (for `write`: record count, output length
//! and FNV-1a of the whole output) must equal ours on every selected row, or
//! the bench fails. The sides then alternate for BENCH_ROUNDS (default 3)
//! rounds, each keeping its best of five batches; ratio = ours/Go by wall time;
//! the verdict is the worst row. MB/s is the file size (the output size for
//! `write`) over the best time. Arguments filter workloads (substring).

const std = @import("std");
const bench = @import("testkit").bench;
const csvstream = @import("csvstream");

const bench_name = "bench-csvstream";
const work_dir = ".zig-cache/bench-csvstream";
const go_dir = "modules/csvstream/tools/go_bench";
const write_records = 1_000_000;
const pool_len = 1000;

const fnv_off: u64 = 0xcbf29ce484222325;
const fnv_prime: u64 = 0x100000001b3;

const Kind = enum { file, file_span, mem, write };
const Work = struct { name: []const u8, file: []const u8, kind: Kind };
const works = [_]Work{
    .{ .name = "narrow", .file = "narrow-v1.csv", .kind = .file },
    .{ .name = "wide", .file = "wide-v1.csv", .kind = .file },
    .{ .name = "quoted", .file = "quoted-v1.csv", .kind = .file },
    .{ .name = "multiline", .file = "multiline-v1.csv", .kind = .file_span },
    .{ .name = "mem_narrow", .file = "narrow-v1.csv", .kind = .mem },
    .{ .name = "write", .file = "pool-v1.csv", .kind = .write },
};

const Res = struct { records: u64 = 0, fields: u64 = 0, h: u64 = fnv_off };

inline fn touch(res: *Res, rec: []const []const u8) void {
    var h = res.h;
    for (rec) |f| {
        h = (h ^ f.len) *% fnv_prime;
        if (f.len > 0) {
            h = (h ^ f[0]) *% fnv_prime;
            h = (h ^ f[f.len - 1]) *% fnv_prime;
        }
    }
    res.h = (h ^ rec.len) *% fnv_prime;
    res.records += 1;
    res.fields += rec.len;
}

const Ctx = struct {
    io: std.Io,
    alloc: std.mem.Allocator,
    op: usize = 0,
    scratch: []u8,
    /// The narrow file in RAM (mem_narrow).
    mem: []const u8 = &.{},
    pool: []const []const []const u8 = &.{},
    out: []u8 = &.{},
};

fn openWork(c: *Ctx, name: []const u8) std.Io.File {
    var b: [128]u8 = undefined;
    const p = std.fmt.bufPrint(&b, work_dir ++ "/{s}", .{name}) catch unreachable;
    return std.Io.Dir.cwd().openFile(c.io, p, .{}) catch |e| std.debug.panic("open {s}: {t}", .{ p, e });
}

fn scanFile(c: *Ctx, wk: Work) Res {
    const f = openWork(c, wk.file);
    defer f.close(c.io);
    var sr = csvstream.StreamReader.init(c.io, c.alloc, f, .{
        .quoted_newlines = if (wk.kind == .file_span) .span else .end_record,
    }) catch |e| std.debug.panic("StreamReader.init: {t}", .{e});
    defer sr.deinit();
    var fba: std.heap.FixedBufferAllocator = .init(c.scratch);
    const a = fba.allocator();
    var buf: [128][]const u8 = undefined;
    var res: Res = .{};
    while (true) {
        fba.reset();
        const rec = (sr.nextFields(&buf, a) catch |e| std.debug.panic("nextFields: {t}", .{e})) orelse break;
        touch(&res, rec);
    }
    return res;
}

fn scanMem(c: *Ctx) Res {
    var it = csvstream.LineIterator.init(c.mem, '"', 0);
    var fba: std.heap.FixedBufferAllocator = .init(c.scratch);
    const a = fba.allocator();
    var buf: [128][]const u8 = undefined;
    var res: Res = .{};
    while (it.next()) |rec| {
        fba.reset();
        const fields = csvstream.splitFields(rec.bytes, &buf, ',', '"', a) catch |e| std.debug.panic("splitFields: {t}", .{e});
        touch(&res, fields);
    }
    return res;
}

fn writeAll(c: *Ctx, w: *std.Io.Writer) void {
    for (0..write_records) |i| {
        csvstream.writeRecord(w, c.pool[i % c.pool.len], .{ .line_terminator = .lf }) catch |e| std.debug.panic("writeRecord: {t}", .{e});
    }
}

fn once(c: *Ctx) u64 {
    const wk = works[c.op];
    switch (wk.kind) {
        .file, .file_span => return scanFile(c, wk).h,
        .mem => return scanMem(c).h,
        .write => {
            var w: std.Io.Writer = .fixed(c.out);
            writeAll(c, &w);
            return w.end;
        },
    }
}

// ── data generator ───────────────────────────────────────────────────────────

fn exists(io: std.Io, dir: std.Io.Dir, name: []const u8) bool {
    const f = dir.openFile(io, name, .{}) catch return false;
    f.close(io);
    return true;
}

fn letters(r: std.Random, out: []u8, lo: usize, hi: usize) []u8 {
    const n = r.intRangeAtMost(usize, lo, hi);
    for (out[0..n]) |*ch| ch.* = 'a' + r.uintLessThan(u8, 26);
    return out[0..n];
}

fn genNarrow(r: std.Random, w: *std.Io.Writer) !void {
    for (0..1_000_000) |i| {
        try w.print("{d}", .{i});
        for (1..10) |col| {
            switch (col % 3) {
                0 => try w.print(",{d}", .{r.int(u32)}),
                1 => try w.print(",{d}", .{r.intRangeAtMost(i32, -99999, 99999)}),
                else => try w.print(",{d}.{d:0>3}", .{ r.uintLessThan(u32, 100000), r.uintLessThan(u32, 1000) }),
            }
        }
        try w.writeByte('\n');
    }
}

fn genWide(r: std.Random, w: *std.Io.Writer) !void {
    var b: [16]u8 = undefined;
    for (0..100_000) |_| {
        for (0..100) |col| {
            if (col != 0) try w.writeByte(',');
            if (r.uintLessThan(u8, 10) != 0) try w.writeAll(letters(r, &b, 1, 12));
        }
        try w.writeByte('\n');
    }
}

fn genQuoted(r: std.Random, w: *std.Io.Writer) !void {
    var b: [16]u8 = undefined;
    for (0..400_000) |_| {
        for (0..10) |col| {
            if (col != 0) try w.writeByte(',');
            const s = letters(r, &b, 2, 12);
            try w.writeByte('"');
            if (r.uintLessThan(u8, 10) == 0) {
                const at = r.intRangeAtMost(usize, 1, s.len - 1);
                try w.writeAll(s[0..at]);
                try w.writeAll("\"\"");
                try w.writeAll(s[at..]);
            } else try w.writeAll(s);
            try w.writeByte('"');
        }
        try w.writeByte('\n');
    }
}

fn genMultiline(r: std.Random, w: *std.Io.Writer) !void {
    var b: [16]u8 = undefined;
    for (0..300_000) |i| {
        try w.print("{d},", .{i});
        try w.writeAll(letters(r, &b, 3, 10));
        try w.writeByte(',');
        try w.writeAll(letters(r, &b, 3, 10));
        try w.writeAll(",\"");
        const lines = r.intRangeAtMost(u8, 2, 4);
        for (0..lines) |k| {
            if (k != 0) try w.writeByte('\n');
            try w.writeAll(letters(r, &b, 4, 14));
            try w.writeByte(' ');
            try w.writeAll(letters(r, &b, 4, 14));
        }
        try w.print("\",{d},", .{r.uintLessThan(u32, 100000)});
        // A second quoted field (comma inside), no line break.
        try w.writeByte('"');
        try w.writeAll(letters(r, &b, 3, 8));
        try w.writeAll(", ");
        try w.writeAll(letters(r, &b, 3, 8));
        try w.writeAll("\"\n");
    }
}

/// 1000 records x 10 fields for the writer: plain, empty, comma, quote and line
/// break fields. Quoted here by hand (not by the code under test); no field
/// starts with a space or is `\.` (Go's extra quoting triggers), no record is a
/// single empty field.
fn genPool(r: std.Random, w: *std.Io.Writer) !void {
    var b: [16]u8 = undefined;
    for (0..pool_len) |_| {
        for (0..10) |col| {
            if (col != 0) try w.writeByte(',');
            const s = letters(r, &b, 2, 12);
            switch (r.uintLessThan(u8, 8)) {
                0 => {},
                1, 2, 3 => try w.writeAll(s),
                4 => try w.print("\"{s},{s}\"", .{ s, s }),
                5 => try w.print("\"{s}\"\"{s}\"", .{ s[0..1], s[1..] }),
                6 => try w.print("\"{s}\n{s}\"", .{ s[0..1], s[1..] }),
                else => try w.print("\"{s},\"\"{s}\"\"\n\"", .{ s[0..1], s[1..] }),
            }
        }
        try w.writeByte('\n');
    }
}

fn generate(io: std.Io, dir: std.Io.Dir, name: []const u8, seed: u64, genfn: *const fn (std.Random, *std.Io.Writer) anyerror!void) !void {
    if (exists(io, dir, name)) return;
    std.debug.print("{s}: generating {s} ...\n", .{ bench_name, name });
    var prng = std.Random.DefaultPrng.init(seed);
    const f = try dir.createFile(io, name, .{});
    defer f.close(io);
    var buf: [64 * 1024]u8 = undefined;
    var fw = f.writer(io, &buf);
    try genfn(prng.random(), &fw.interface);
    try fw.interface.flush();
}

// ── check mode ───────────────────────────────────────────────────────────────

const Check = struct { a: u64, b: u64, c: u64 };

fn goCheck(arena: std.mem.Allocator, io: std.Io, exe: []const u8, abs: []const u8, name: []const u8) !Check {
    const res = try std.process.run(arena, io, .{ .argv = &.{ exe, abs, name, "check" } });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: go check of {s} failed:\n{s}\n", .{ bench_name, name, res.stderr });
        return error.ForeignFailed;
    }
    var it = std.mem.tokenizeAny(u8, res.stdout, " \n");
    const a = try std.fmt.parseInt(u64, it.next() orelse return error.BadForeignOutput, 10);
    const b = try std.fmt.parseInt(u64, it.next() orelse return error.BadForeignOutput, 10);
    const c = try std.fmt.parseInt(u64, it.next() orelse return error.BadForeignOutput, 10);
    return .{ .a = a, .b = b, .c = c };
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

    try generate(io, dir, "narrow-v1.csv", 0x6373_7601, genNarrow);
    try generate(io, dir, "wide-v1.csv", 0x6373_7602, genWide);
    try generate(io, dir, "quoted-v1.csv", 0x6373_7603, genQuoted);
    try generate(io, dir, "multiline-v1.csv", 0x6373_7604, genMultiline);
    try generate(io, dir, "pool-v1.csv", 0x6373_7605, genPool);

    const gexe = try bench.goBuild(arena, io, bench_name, init.environ_map, .{ .exe = "go", .dir = go_dir, .abs = abs });

    var ctx: Ctx = .{ .io = io, .alloc = std.heap.page_allocator, .scratch = try arena.alloc(u8, 1 << 20) };

    var sizes: [works.len]u64 = undefined;
    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;

    // ── pre-check: Go's answer against ours, per selected row ────────────────
    for (works, 0..) |wk, wi| {
        if (!bench.selected(wk.name, filters)) continue;
        const f = openWork(&ctx, wk.file);
        sizes[wi] = try f.length(io);
        f.close(io);
        const g = try goCheck(arena, io, gexe, abs, wk.name);
        var ok: bool = undefined;
        var ours: Check = undefined;
        switch (wk.kind) {
            .file, .file_span, .mem => {
                if (wk.kind == .mem and ctx.mem.len == 0) ctx.mem = try cwd.readFileAlloc(io, work_dir ++ "/narrow-v1.csv", arena, .limited(1 << 30));
                const r = if (wk.kind == .mem) scanMem(&ctx) else scanFile(&ctx, wk);
                ours = .{ .a = r.records, .b = r.fields, .c = r.h };
            },
            .write => {
                if (ctx.pool.len == 0) ctx.pool = try loadPool(&ctx, arena);
                var aw: std.Io.Writer.Allocating = .init(arena);
                writeAll(&ctx, &aw.writer);
                const out = aw.written();
                ours = .{ .a = write_records, .b = out.len, .c = std.hash.Fnv1a_64.hash(out) };
                ctx.out = try arena.alloc(u8, out.len);
                sizes[wi] = out.len;
            },
        }
        ok = ours.a == g.a and ours.b == g.b and ours.c == g.c;
        try w.print("pre-check {s}: ours {d} {d} {x}; go {d} {d} {x}; {d} bytes -- {s}\n", .{ wk.name, ours.a, ours.b, ours.c, g.a, g.b, g.c, sizes[wi], if (ok) "agree" else "DISAGREE" });
        try w.flush();
        if (!ok) {
            try w.print("{s}: FAILED -- {s} disagrees with Go encoding/csv\n", .{ bench_name, wk.name });
            try w.flush();
            return 1;
        }
    }

    // ── timing ───────────────────────────────────────────────────────────────
    const cyc: bench.Cycles = .open();
    var s: bench.Summary = .{};
    try w.print("{s:<12} {s:>13} {s:>13} {s:>8} {s:>10} {s:>10} {s:>6} {s:>6}  count\n", .{ "workload", "ours ns", "go ns", "ours/go", "ours MB/s", "go MB/s", "spr us", "spr go" });
    try w.flush();
    for (works, 0..) |wk, wi| {
        if (!bench.selected(wk.name, filters)) continue;
        ctx.op = wi;
        var ours: bench.Side = .{};
        var ref: bench.Side = .{};
        for (0..rounds) |_| {
            ref.add(try bench.foreign(arena, io, bench_name, gexe, abs, wk.name, &s.banner));
            ours.add(bench.timeIt(io, cyc, once, .{&ctx}, true));
        }
        const l = bench.score(ours, ref, null, false);
        s.add(l);
        const mb: f64 = @floatFromInt(sizes[wi]);
        try w.print("{s:<12} {d:>13.0} {d:>13.0} {d:>8.3} {d:>10.1} {d:>10.1} {d:>5.1}% {d:>5.1}%  {d}{s}\n", .{
            wk.name,                  ours.best_ns,             ref.best_ns,
            l.ref,                    mb * 1000 / ours.best_ns, mb * 1000 / ref.best_ns,
            100 * ours.spread(false), 100 * ref.spread(false),  ours.count,
            if (!l.same_count) " ≠" else "",
        });
        try w.flush();
    }
    try w.print("rounds: {d}; ratios by wall time; largest spread {d:.1}%{s}\n", .{ rounds, 100 * s.max_spread, if (s.max_spread > 0.05) " (OVER 5 %: noisy run, repeat)" else "" });
    if (s.mismatch) {
        try w.print("{s}: FAILED -- an output count differs between the sides\n", .{bench_name});
        try w.flush();
        return 1;
    }
    try w.print("reference: {s}\nworst ours/go = {d:.3} (best {d:.3}) -> {s}\n", .{ std.mem.trimEnd(u8, s.banner, "\n"), s.worst_ref, s.best_ref, if (s.worst_ref <= 1.1) "P2 met (every row <= 1.1x)" else "P2 NOT met" });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× Go encoding/csv (ReuseRecord, LazyQuotes; 6 rows, wall time)\n", .{ s.best_ref, s.worst_ref });
    try w.flush();
    return 0;
}

/// The writer's 1000-record pool, read with OUR reader (span mode: the pool has
/// line breaks inside quoted fields) into the arena.
fn loadPool(c: *Ctx, arena: std.mem.Allocator) ![]const []const []const u8 {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(c.io, work_dir ++ "/pool-v1.csv", arena, .limited(1 << 24));
    var it = csvstream.LineIterator.initSpan(bytes, '"', 0, .{});
    var recs: std.ArrayList([]const []const u8) = .empty;
    var buf: [16][]const u8 = undefined;
    while (it.next()) |rec| {
        const fields = try csvstream.splitFields(rec.bytes, &buf, ',', '"', arena);
        try recs.append(arena, try arena.dupe([]const u8, fields));
    }
    if (recs.items.len != pool_len) return error.BadPool;
    return recs.items;
}
