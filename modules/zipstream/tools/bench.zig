// SPDX-License-Identifier: MIT

//! Comparative benchmark: `zipstream` against Go `archive/zip` (the reference)
//! -- the program behind the `**Performance:**` line of the maturity card
//! (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-zipstream` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `go` (standard
//! library only; `tools/go_bench`, built offline). Run from the repository root.
//!
//! The data is generated once (seeded PRNG) into `.zig-cache/bench-zipstream/`:
//! `data-v1.xml` (512 MiB of xlsx-shaped sheet XML, written here) and, from it by
//! the Go side (`go_bench <dir> gen`), the four fixture archives. Both sides
//! read the same files; bump the `-v1` suffix here and in `go_bench/main.go`
//! when a generator changes.
//!
//!   xlsx      xlsx-v1.zip: a ~200 MiB Deflate sheet + small parts; every entry
//!             stream-extracted (inflate + CRC), output discarded
//!   store     store-v1.zip: one 512 MiB Stored entry (CRC + copy bound)
//!   cdopen    many-v1.zip: open the central directory of 100 000 tiny entries
//!             and find the last name (ours `Archive.find`, Go a linear walk of
//!             `Reader.File`; no entry data read)
//!   small     small-v1.zip: 10 000 small Deflate entries, opened and read one
//!             by one
//!   wdeflate  writer: the first 256 MiB of data-v1.xml as one entry, Deflate
//!             level 6 (ours `addEntry`, Go `CreateHeader` + one `Write`)
//!   wstore    the same, Stored
//!   sdeflate  streamed writer, Deflate level 6 (ours `beginEntry`/`endEntry`,
//!             Go `CreateHeader`; both in 64 KiB writes)
//!   sstore    the same, Stored
//!
//! Our side reads through `Archive.init` (a file) with an `EntryReader` into a
//! reused discarding writer; Go through `zip.OpenReader` + `io.Copy(io.Discard,
//! ...)`. Writers go into a counting discard writer on both sides. The
//! compression ratio of the writer rows is printed beside the MB/s.
//!
//! BEFORE ANYTHING IS TIMED the sides are cross-checked on every selected
//! row. Readers: entry count, bytes read and the sum of the entries' CRC-32
//! must equal Go's. Writers: each side writes its archive to a file; the
//! other side reads it (Go `readcheck`, ours `Archive`) and must find one
//! entry of the right size whose CRC-32 is the data's. Then the sides
//! alternate for BENCH_ROUNDS (default 3) rounds, each side keeping its best
//! of BENCH_REPS (default 1: the rounds are the repetitions) runs (every run takes seconds; testkit's
//! doubling batch would not fit the time budget); ratio = ours/Go by wall
//! time; the verdict is the worst row. Arguments filter workloads (substring).

const std = @import("std");
const bench = @import("testkit").bench;
const zipstream = @import("zipstream");

const bench_name = "bench-zipstream";
const work_dir = ".zig-cache/bench-zipstream";
const go_dir = "modules/zipstream/tools/go_bench";

const data_len: u64 = 512 << 20;
const write_len = 256 << 20;
const chunk = 64 << 10;
const entry_name = "xl/worksheets/sheet1.xml";
const many_last = "xl/worksheets/rows/r099999.xml";

const Kind = enum { read_data, read_cd, write_buffered, write_streamed };
const Work = struct { name: []const u8, file: []const u8, kind: Kind, method: zipstream.WriteMethod = .deflate };
const works = [_]Work{
    .{ .name = "xlsx", .file = "xlsx-v1.zip", .kind = .read_data },
    .{ .name = "store", .file = "store-v1.zip", .kind = .read_data },
    .{ .name = "cdopen", .file = "many-v1.zip", .kind = .read_cd },
    .{ .name = "small", .file = "small-v1.zip", .kind = .read_data },
    .{ .name = "wdeflate", .file = "", .kind = .write_buffered },
    .{ .name = "wstore", .file = "", .kind = .write_buffered, .method = .store },
    .{ .name = "sdeflate", .file = "", .kind = .write_streamed },
    .{ .name = "sstore", .file = "", .kind = .write_streamed, .method = .store },
};

const Res = struct { entries: u64 = 0, bytes: u64 = 0, crc: u64 = 0 };

const Ctx = struct {
    io: std.Io,
    alloc: std.mem.Allocator,
    op: usize = 0,
    window: []u8,
    er: *zipstream.EntryReader,
    sink_buf: []u8,
    /// The first 256 MiB of data-v1.xml (writer rows).
    data: []const u8 = &.{},
    /// Compressed size of the last write op.
    comp: u64 = 0,
};

fn openWork(c: *Ctx, name: []const u8) std.Io.File {
    var b: [128]u8 = undefined;
    const p = std.fmt.bufPrint(&b, work_dir ++ "/{s}", .{name}) catch unreachable;
    return std.Io.Dir.cwd().openFile(c.io, p, .{}) catch |e| std.debug.panic("open {s}: {t}", .{ p, e });
}

/// Read an archive with this module: every entry's data into a discarding
/// writer (`data`), or only the directory plus `Archive.find(find)`.
fn readArchive(c: *Ctx, file: std.Io.File, data: bool, find: []const u8) Res {
    var a: zipstream.Archive = undefined;
    a.init(c.io, c.alloc, file) catch |e| std.debug.panic("Archive.init: {t}", .{e});
    defer a.deinit();
    var res: Res = .{};
    for (a.entries.items) |*e| {
        res.entries += 1;
        res.crc += e.crc32;
        if (!data) continue;
        c.er.init(&a, e, c.window) catch |err| std.debug.panic("EntryReader.init {s}: {t}", .{ e.name, err });
        var dw: std.Io.Writer.Discarding = .init(c.sink_buf);
        const n = c.er.reader().streamRemaining(&dw.writer) catch |err| std.debug.panic("read {s}: {t} (crc mismatch {})", .{ e.name, err, c.er.crcMismatch() });
        res.bytes += n;
    }
    if (!data) {
        const e = a.find(find) orelse std.debug.panic("find: {s} missing", .{find});
        res.bytes = (@intFromPtr(e) - @intFromPtr(a.entries.items.ptr)) / @sizeOf(zipstream.Entry) + 1;
    }
    return res;
}

fn count(r: Res) u64 {
    return r.bytes +% r.crc +% r.entries;
}

fn writeArchive(c: *Ctx, wk: Work, out: *std.Io.Writer) void {
    var w = zipstream.ArchiveWriter.init(c.alloc, out);
    defer w.deinit();
    switch (wk.kind) {
        .write_buffered => w.addEntry(entry_name, c.data, .{ .method = wk.method }) catch |e| std.debug.panic("addEntry: {t}", .{e}),
        .write_streamed => {
            const sw = w.beginEntry(entry_name, .{ .method = wk.method }) catch |e| std.debug.panic("beginEntry: {t}", .{e});
            var off: usize = 0;
            while (off < c.data.len) : (off += chunk) sw.writeAll(c.data[off..@min(off + chunk, c.data.len)]) catch |e| std.debug.panic("write: {t}", .{e});
            w.endEntry() catch |e| std.debug.panic("endEntry: {t}", .{e});
        },
        else => unreachable,
    }
    w.finish() catch |e| std.debug.panic("finish: {t}", .{e});
    out.flush() catch |e| std.debug.panic("flush: {t}", .{e});
}

fn once(c: *Ctx) u64 {
    const wk = works[c.op];
    switch (wk.kind) {
        .read_data, .read_cd => {
            const f = openWork(c, wk.file);
            defer f.close(c.io);
            return count(readArchive(c, f, wk.kind == .read_data, many_last));
        },
        .write_buffered, .write_streamed => {
            var dw: std.Io.Writer.Discarding = .init(c.sink_buf);
            writeArchive(c, wk, &dw.writer);
            c.comp = dw.fullCount();
            return c.data.len;
        },
    }
}

/// Wall time per op, best of BENCH_REPS runs (the pilot run counts).
fn timeIt(io: std.Io, c: *Ctx, reps: usize) bench.Row {
    var best: i96 = std.math.maxInt(i96);
    var cnt: u64 = 0;
    for (0..reps) |_| {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        cnt = once(c);
        best = @min(best, t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds);
    }
    return .{ .ns = @floatFromInt(best), .count = cnt };
}

// ── data generator ───────────────────────────────────────────────────────────

fn generate(io: std.Io, dir: std.Io.Dir) !void {
    const name = "data-v1.xml";
    if (dir.openFile(io, name, .{})) |f| {
        defer f.close(io);
        if ((try f.length(io)) == data_len) return;
    } else |_| {}
    std.debug.print("{s}: generating {s} ...\n", .{ bench_name, name });
    var prng = std.Random.DefaultPrng.init(0x7a69_7001);
    const r = prng.random();
    const f = try dir.createFile(io, name, .{});
    defer f.close(io);
    var buf: [1 << 20]u8 = undefined;
    var fw = f.writer(io, &buf);
    const w = &fw.interface;
    var total: u64 = 0;
    var i: u64 = 1;
    var row: [512]u8 = undefined;
    while (total < data_len) : (i += 1) {
        var rw: std.Io.Writer = .fixed(&row);
        try rw.print("<row r=\"{d}\" spans=\"1:8\" x14ac:dyDescent=\"0.25\">", .{i});
        try rw.print("<c r=\"A{d}\" s=\"1\" t=\"s\"><v>{d}</v></c>", .{ i, r.uintLessThan(u32, 20000) });
        try rw.print("<c r=\"B{d}\" s=\"2\"><v>{d}.{d:0>2}</v></c>", .{ i, r.uintLessThan(u32, 100000), r.uintLessThan(u32, 100) });
        try rw.print("<c r=\"C{d}\"><v>{d}</v></c>", .{ i, r.uintLessThan(u32, 1000) });
        try rw.print("<c r=\"D{d}\" s=\"3\"><v>{d}</v></c>", .{ i, 43000 + r.uintLessThan(u32, 900) });
        try rw.print("<c r=\"E{d}\" t=\"s\"><v>{d}</v></c>", .{ i, r.uintLessThan(u32, 300) });
        try rw.print("<c r=\"F{d}\" s=\"2\"><v>{d}.{d:0>4}</v></c>", .{ i, r.uintLessThan(u32, 10), r.uintLessThan(u32, 10000) });
        try rw.print("<c r=\"G{d}\"><f>B{d}*C{d}</f><v>{d}</v></c>", .{ i, i, i, r.uintLessThan(u32, 1 << 24) });
        try rw.writeAll("<c r=\"H");
        try rw.print("{d}\" s=\"1\"/></row>\n", .{i});
        const s = rw.buffered();
        const n: usize = @intCast(@min(s.len, data_len - total));
        try w.writeAll(s[0..n]);
        total += n;
    }
    try w.flush();
}

// ── check mode ───────────────────────────────────────────────────────────────

const Check = struct { v: [4]u64 = @splat(0), n: usize = 0 };

fn goRun(arena: std.mem.Allocator, io: std.Io, argv: []const []const u8) !Check {
    const res = try std.process.run(arena, io, .{ .argv = argv });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: go {s} failed:\n{s}\n", .{ bench_name, argv[2], res.stderr });
        return error.ForeignFailed;
    }
    var out: Check = .{};
    var it = std.mem.tokenizeAny(u8, res.stdout, " \n");
    while (it.next()) |t| : (out.n += 1) {
        if (out.n == out.v.len) return error.BadForeignOutput;
        out.v[out.n] = try std.fmt.parseInt(u64, t, 10);
    }
    return out;
}

fn ensureFixtures(arena: std.mem.Allocator, io: std.Io, gexe: []const u8, abs: []const u8) !void {
    _ = try goRun(arena, io, &.{ gexe, abs, "gen" });
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
    const reps: usize = if (init.environ_map.get("BENCH_REPS")) |r| try std.fmt.parseInt(usize, r, 10) else 1;

    try generate(io, dir);
    const gexe = try bench.goBuild(arena, io, bench_name, init.environ_map, .{ .exe = "go", .dir = go_dir, .abs = abs });
    try ensureFixtures(arena, io, gexe, abs);

    const alloc = std.heap.smp_allocator;
    var ctx: Ctx = .{
        .io = io,
        .alloc = alloc,
        .window = try alloc.alloc(u8, std.compress.flate.max_window_len),
        .er = try alloc.create(zipstream.EntryReader),
        .sink_buf = try alloc.alloc(u8, 64 << 10),
    };

    var mbytes: [works.len]u64 = undefined;
    var comp_go: [works.len]u64 = @splat(0);
    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;

    const any_write = for (works) |wk| {
        if (bench.selected(wk.name, filters) and wk.kind != .read_data and wk.kind != .read_cd) break true;
    } else false;
    if (any_write) {
        const f = try dir.openFile(io, "data-v1.xml", .{});
        defer f.close(io);
        const d = try alloc.alloc(u8, write_len);
        if (try f.readPositionalAll(io, d, 0) != d.len) return error.ShortRead;
        ctx.data = d;
    }
    const want_crc: u64 = std.hash.Crc32.hash(ctx.data);

    // ── pre-check: Go's answer against ours, per selected row ────────────────
    for (works, 0..) |wk, wi| {
        if (!bench.selected(wk.name, filters)) continue;
        var ok: bool = undefined;
        switch (wk.kind) {
            .read_data, .read_cd => {
                const g = try goRun(arena, io, &.{ gexe, abs, wk.name, "check" });
                const f = openWork(&ctx, wk.file);
                defer f.close(io);
                const r = readArchive(&ctx, f, wk.kind == .read_data, many_last);
                ok = r.entries == g.v[0] and r.bytes == g.v[1] and r.crc == g.v[2];
                mbytes[wi] = if (wk.kind == .read_data) r.bytes else try f.length(io);
                try w.print("pre-check {s}: ours {d} entries {d} bytes crc-sum {d}; go {d} {d} {d} -- {s}\n", .{ wk.name, r.entries, r.bytes, r.crc, g.v[0], g.v[1], g.v[2], if (ok) "agree" else "DISAGREE" });
            },
            .write_buffered, .write_streamed => {
                // Go writes (check mode) and prints "1 size crc compressed"; its archive is read by us.
                const g = try goRun(arena, io, &.{ gexe, abs, wk.name, "check" });
                comp_go[wi] = g.v[3];
                var gname: [64]u8 = undefined;
                const gf = try dir.openFile(io, try std.fmt.bufPrint(&gname, "out-go-{s}.zip", .{wk.name}), .{});
                defer gf.close(io);
                var a: zipstream.Archive = undefined;
                try a.init(io, alloc, gf);
                defer a.deinit();
                const ours_reads_go = a.entries.items.len == 1 and a.entries.items[0].uncompressed_size == write_len and a.entries.items[0].crc32 == want_crc;
                // Read it through to the end: the entry reader checks the CRC-32.
                var dw: std.Io.Writer.Discarding = .init(ctx.sink_buf);
                ctx.er.init(&a, &a.entries.items[0], ctx.window) catch return error.BadGoArchive;
                const n = try ctx.er.reader().streamRemaining(&dw.writer);
                // Our archive, written to a file, read by Go.
                var oname: [64]u8 = undefined;
                const opath = try std.fmt.bufPrint(&oname, "out-ours-{s}.zip", .{wk.name});
                {
                    const of = try dir.createFile(io, opath, .{});
                    defer of.close(io);
                    var fbuf: [1 << 16]u8 = undefined;
                    var fw = of.writer(io, &fbuf);
                    writeArchive(&ctx, wk, &fw.interface);
                }
                var full: [256]u8 = undefined;
                const gr = try goRun(arena, io, &.{ gexe, abs, "readcheck", try std.fmt.bufPrint(&full, "{s}/{s}", .{ abs, opath }) });
                const of2 = try dir.openFile(io, opath, .{});
                defer of2.close(io);
                const osize = try of2.length(io);
                ok = ours_reads_go and n == write_len and gr.v[0] == 1 and gr.v[1] == write_len and gr.v[2] == want_crc;
                mbytes[wi] = write_len;
                try w.print("pre-check {s}: ours reads Go's archive ({d} B): {s}; Go reads ours ({d} B): 1 entry, {d} bytes, crc {s} -- {s}\n", .{
                    wk.name,                         g.v[3],  if (ours_reads_go and n == write_len) "ok" else "BAD",
                    osize,                           gr.v[1], if (gr.v[2] == want_crc) "ok" else "BAD",
                    if (ok) "agree" else "DISAGREE",
                });
            },
        }
        try w.flush();
        if (!ok) {
            try w.print("{s}: FAILED -- {s} disagrees with Go archive/zip\n", .{ bench_name, wk.name });
            try w.flush();
            return 1;
        }
    }

    // ── timing ───────────────────────────────────────────────────────────────
    var s: bench.Summary = .{};
    try w.print("{s:<10} {s:>14} {s:>14} {s:>8} {s:>10} {s:>10} {s:>6} {s:>6}  {s:<22} count\n", .{ "workload", "ours ns", "go ns", "ours/go", "ours MB/s", "go MB/s", "spr us", "spr go", "compressed ours/go" });
    try w.flush();
    for (works, 0..) |wk, wi| {
        if (!bench.selected(wk.name, filters)) continue;
        ctx.op = wi;
        var ours: bench.Side = .{};
        var ref: bench.Side = .{};
        var env = try init.environ_map.clone(arena);
        try env.put("BENCH_REPS", try std.fmt.allocPrint(arena, "{d}", .{reps}));
        for (0..rounds) |_| {
            const res = try std.process.run(arena, io, .{ .argv = &.{ gexe, abs, wk.name }, .environ_map = &env });
            if (res.term != .exited or res.term.exited != 0) {
                std.debug.print("{s}: foreign side failed on {s}:\n{s}\n", .{ bench_name, wk.name, res.stderr });
                return error.ForeignFailed;
            }
            s.banner = res.stderr;
            ref.add(try bench.parseForeign(res.stdout, wk.name));
            ours.add(timeIt(io, &ctx, reps));
        }
        const l = bench.score(ours, ref, null, false);
        s.add(l);
        const mb: f64 = @floatFromInt(mbytes[wi]);
        var cbuf: [48]u8 = undefined;
        const ctext = if (wk.kind == .write_buffered or wk.kind == .write_streamed) try std.fmt.bufPrint(&cbuf, "{d}/{d} ({d:.2}x)", .{ ctx.comp, comp_go[wi], @as(f64, @floatFromInt(ctx.comp)) / @as(f64, @floatFromInt(comp_go[wi])) }) else "";
        try w.print("{s:<10} {d:>14.0} {d:>14.0} {d:>8.3} {d:>10.1} {d:>10.1} {d:>5.1}% {d:>5.1}%  {s:<22} {d}{s}\n", .{
            wk.name,                  ours.best_ns,             ref.best_ns,
            l.ref,                    mb * 1000 / ours.best_ns, mb * 1000 / ref.best_ns,
            100 * ours.spread(false), 100 * ref.spread(false),  ctext,
            ours.count,
            if (!l.same_count) " ≠" else "",
        });
        try w.flush();
    }
    try w.print("rounds: {d} (best of {d} runs each); ratios by wall time; largest spread {d:.1}%{s}\n", .{ rounds, reps, 100 * s.max_spread, if (s.max_spread > 0.05) " (OVER 5 %: noisy run, repeat)" else "" });
    if (s.mismatch) {
        try w.print("{s}: FAILED -- an output count differs between the sides\n", .{bench_name});
        try w.flush();
        return 1;
    }
    try w.print("reference: {s}\nworst ours/go = {d:.3} (best {d:.3}) -> {s}\n", .{ std.mem.trimEnd(u8, s.banner, "\n"), s.worst_ref, s.best_ref, if (s.worst_ref <= 1.1) "P2 met (every row <= 1.1x)" else "P2 NOT met" });
    try w.flush();
    return 0;
}
