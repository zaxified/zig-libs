// SPDX-License-Identifier: MIT

//! Comparative benchmark: `bzip2` against libbzip2 1.0.8 (the reference), the
//! program behind the `**Performance:**` line of the maturity card
//! (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-bzip2` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `zig` on PATH
//! (it builds `tools/c_bench/foreign_bench.c` together with the seven library
//! sources of the pinned clone with `zig cc -O3 -march=native`) and the clone
//! (`tools/build-oracle.sh` fetches it into `.zig-cache/survey/bzip2`; or
//! `BZIP2_SRC=<dir>`). Run from the repository root.
//!
//! Payloads, written into `.zig-cache/bench-bzip2/` from a fixed seed, `n` MiB
//! each (`BZIP2_BENCH_MIB`, default 8): `text` (Zipf-distributed words of a
//! random 30 000-word vocabulary) and `binary` (records, random, zero-padded
//! and opcode-like sections). Workloads: `enc9_*`, `enc1_*` compress at level
//! 9 / 1 into a buffer allocated once (ours: `compressInto`; theirs:
//! `BZ2_bzBuffToBuffCompress`, work factor 30), `dec9_*`, `dec1_*` decompress
//! the stream the reference made into a buffer allocated once (ours:
//! `decompressStream` into a fixed writer; theirs: `BZ2_bzBuffToBuffDecompress`).
//! `decA9_*` is ours allocating its output (`decompress`), printed for
//! information only. The count is the compressed size (encode) or the plain
//! size (decode); the encoder's must equal the reference's to the byte count
//! (it emits the reference's bytes), and before timing our decoder must
//! reproduce each payload from the reference's stream and our encoder must
//! reproduce its bytes.
//!
//! Method (`testkit.bench`): each side doubles its batch until it takes over
//! 100 ms and keeps the best of five; per workload the sides alternate for
//! `BENCH_ROUNDS` (default 3) rounds, each keeping its best. Ratios are ours /
//! theirs by wall time (the C side counts no cycles). Arguments filter
//! workloads by substring (no card line then).

const std = @import("std");
const bench = @import("testkit").bench;
const Work = bench.Work(Op);
const bzip2 = @import("bzip2");

const bench_name = "bench-bzip2";
const work_dir = ".zig-cache/bench-bzip2";
const kinds = [_][]const u8{ "text", "binary" };

const Op = struct { decompress: bool = false, level: u4 = 9, kind: usize = 0, alloc: bool = false };

const Ctx = struct {
    gpa: std.mem.Allocator,
    op: Op,
    plain: [2][]u8,
    /// Reference streams at level 1 and 9.
    ref: [2][2][]u8,
    out: [2][]u8,
};

fn once(c: *Ctx) u64 {
    const o = c.op;
    if (o.decompress) {
        const stream = c.ref[o.kind][if (o.level == 1) 0 else 1];
        if (o.alloc) {
            const r = bzip2.decompress(c.gpa, stream, .{}) catch unreachable;
            defer c.gpa.free(r);
            return r.len;
        }
        var in: std.Io.Reader = .fixed(stream);
        var w: std.Io.Writer = .fixed(c.out[o.kind]);
        return bzip2.decompressStream(c.gpa, &in, &w, .{}) catch unreachable;
    }
    return bzip2.compressInto(c.gpa, c.out[o.kind], c.plain[o.kind], .{ .level = o.level }) catch unreachable;
}

fn genText(arena: std.mem.Allocator, n: usize, r: std.Random) ![]u8 {
    const letters = "etaoinshrdlcumwfgypbvkjxqz";
    const vocab = try arena.alloc([]u8, 30_000);
    for (vocab) |*w| {
        const len = 2 + r.uintLessThan(usize, 8);
        w.* = try arena.alloc(u8, len);
        for (w.*) |*c| {
            c.* = letters[@min(r.uintLessThan(usize, 26), r.uintLessThan(usize, 26))];
        }
    }
    const out = try arena.alloc(u8, n);
    var i: usize = 0;
    while (i < n) {
        const u = r.float(f64);
        const idx: usize = @intFromFloat(@exp(u * @log(@as(f64, @floatFromInt(vocab.len)))));
        const w = vocab[@min(idx, vocab.len - 1) % vocab.len];
        const sep: []const u8 = switch (r.uintLessThan(u8, 24)) {
            0 => ", ",
            1 => ".\n",
            else => " ",
        };
        for ([_][]const u8{ w, sep }) |piece| {
            const k = @min(piece.len, n - i);
            @memcpy(out[i..][0..k], piece[0..k]);
            i += k;
        }
    }
    return out;
}

fn genBinary(arena: std.mem.Allocator, n: usize, r: std.Random) ![]u8 {
    const out = try arena.alloc(u8, n);
    var ops: [64][8]u8 = undefined;
    for (&ops) |*o| r.bytes(o);
    var i: usize = 0;
    var id: u32 = 0;
    while (i < n) {
        const room = n - i;
        switch (r.uintLessThan(u8, 4)) {
            0 => {
                const recs = @min(room / 16, 256 + r.uintLessThan(usize, 2048));
                for (0..recs) |_| {
                    std.mem.writeInt(u32, out[i..][0..4], id, .little);
                    std.mem.writeInt(u32, out[i + 4 ..][0..4], r.uintLessThan(u32, 1000), .little);
                    std.mem.writeInt(u64, out[i + 8 ..][0..8], 0x7f00_0000_0000 + @as(u64, r.uintLessThan(u32, 1 << 20)) * 8, .little);
                    id += 1;
                    i += 16;
                }
                if (recs == 0) {
                    @memset(out[i..], 0);
                    i = n;
                }
            },
            1 => {
                const k = @min(room, 4096 + r.uintLessThan(usize, 60_000));
                r.bytes(out[i..][0..k]);
                i += k;
            },
            2 => {
                const k = @min(room, 256 + r.uintLessThan(usize, 8000));
                @memset(out[i..][0..k], 0);
                i += k;
            },
            else => {
                const k = @min(room, 1024 + r.uintLessThan(usize, 30_000));
                var j: usize = 0;
                while (j < k) {
                    const o = ops[r.uintLessThan(usize, ops.len)];
                    const m = @min(4 + r.uintLessThan(usize, 5), k - j);
                    @memcpy(out[i + j ..][0..m], o[0..m]);
                    j += m;
                }
                i += k;
            },
        }
    }
    return out;
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
    const mib: usize = if (init.environ_map.get("BZIP2_BENCH_MIB")) |r| try std.fmt.parseInt(usize, r, 10) else 8;
    const src = init.environ_map.get("BZIP2_SRC") orelse ".zig-cache/survey/bzip2";

    // The pinned clone (and, as a side effect, the differential oracle).
    if (cwd.access(io, src, .{})) {} else |_| {
        const r = try std.process.run(arena, io, .{ .argv = &.{ "bash", "modules/bzip2/tools/build-oracle.sh" } });
        if (r.term != .exited or r.term.exited != 0) {
            std.debug.print("{s}: could not fetch libbzip2:\n{s}\n", .{ bench_name, r.stderr });
            return 1;
        }
    }

    var prng = std.Random.DefaultPrng.init(0xb7b2_2026);
    const r = prng.random();
    var ctx: Ctx = undefined;
    ctx.gpa = std.heap.smp_allocator;
    ctx.plain[0] = try genText(arena, mib << 20, r);
    ctx.plain[1] = try genBinary(arena, mib << 20, r);
    for (kinds, 0..) |k, i| {
        try dir.writeFile(io, .{ .sub_path = try arena.print("{s}.bin", .{k}), .data = ctx.plain[i] });
        ctx.out[i] = try arena.alloc(u8, bzip2.compressBound(ctx.plain[i].len));
    }

    const srcs = [_][]const u8{ "blocksort", "huffman", "crctable", "randtable", "compress", "decompress", "bzlib" };
    var libs: [srcs.len][]const u8 = undefined;
    for (srcs, &libs) |s, *l| l.* = try arena.print("{s}/{s}.c", .{ src, s });
    const exe = try bench.buildForeign(arena, io, bench_name, &.{ "zig", "cc", "-I", src, "-D_FILE_OFFSET_BITS=64" }, abs, "modules/bzip2/tools/c_bench/foreign_bench.c", &libs);

    const prep = try std.process.run(arena, io, .{ .argv = &.{ exe, abs, "prep" } });
    if (prep.term != .exited or prep.term.exited != 0) {
        std.debug.print("{s}: foreign prep failed:\n{s}\n", .{ bench_name, prep.stderr });
        return 1;
    }
    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.print("payloads: {d} MiB each; reference compressed sizes:\n{s}", .{ mib, prep.stdout });

    // Correctness gate before any timing.
    for (kinds, 0..) |k, i| {
        for ([_]u4{ 1, 9 }, 0..) |level, li| {
            const rb = try dir.readFileAlloc(io, try arena.print("{s}.{d}.ref.bz2", .{ k, level }), arena, .limited(1 << 28));
            ctx.ref[i][li] = rb;
            const back = try bzip2.decompress(arena, rb, .{});
            if (!std.mem.eql(u8, back, ctx.plain[i])) {
                std.debug.print("{s}: FAILED -- our decoder does not reproduce {s} from the level {d} reference stream\n", .{ bench_name, k, level });
                return 1;
            }
            const mine = try bzip2.compress(arena, ctx.plain[i], .{ .level = level });
            if (!std.mem.eql(u8, mine, rb)) {
                std.debug.print("{s}: FAILED -- our level {d} stream of {s} differs from the reference's\n", .{ bench_name, level, k });
                return 1;
            }
        }
    }
    try w.writeAll("correctness: our decoder reads the reference streams, our encoder reproduces them byte for byte\n");
    try w.flush();

    var ws: std.ArrayList(Work) = .empty;
    for (kinds, 0..) |k, i| {
        for ([_]u4{ 9, 1 }) |level| {
            const en = try arena.print("enc{d}_{s}", .{ level, k });
            try ws.append(arena, .{ .name = en, .op = .{ .level = level, .kind = i }, .ref = en });
            const dn = try arena.print("dec{d}_{s}", .{ level, k });
            try ws.append(arena, .{ .name = dn, .op = .{ .decompress = true, .level = level, .kind = i }, .ref = dn });
        }
        const an = try arena.print("decA9_{s}", .{k});
        try ws.append(arena, .{ .name = an, .op = .{ .decompress = true, .level = 9, .kind = i, .alloc = true }, .ref = try arena.print("dec9_{s}", .{k}), .info = true });
    }

    const s = try bench.drive(io, arena, .{ .name = bench_name, .exes = &.{exe}, .abs = abs, .filters = filters, .rounds = rounds }, &ctx, once, ws.items, w);
    try w.print("reference: {s}\nworst ours/libbzip2 = {d:.3} (best {d:.3})\n", .{ std.mem.trimEnd(u8, s.banner, "\n"), s.worst_ref, s.best_ref });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× libbzip2 1.0.8 (C, one-shot) · fastest ? (measured <today>)\n", .{ s.best_ref, s.worst_ref });
    try w.flush();
    return 0;
}
