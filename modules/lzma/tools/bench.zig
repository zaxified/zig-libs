// SPDX-License-Identifier: MIT

//! Comparative benchmark: `lzma` against liblzma 5.8.1 (the reference), the
//! program behind the `**Performance:**` line of the maturity card
//! (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-lzma` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `zig` on PATH
//! (it builds `tools/c_oracle/lzbench.c` together with the library sources of
//! the pinned XZ Utils clone with `zig cc -O3 -march=native`) and the clone
//! (`tools/build-oracle.sh` fetches it into `.zig-cache/survey/lzma/xz`; or
//! `LZMA_SRC=<dir>`). Run from the repository root.
//!
//! Payloads, written into `.zig-cache/bench-lzma/` from a fixed seed, `n` MiB
//! each (`LZMA_BENCH_MIB`, default 2: presets 6 and 9 compress at about 3 MB/s
//! and the method times each side 5 batches x `BENCH_ROUNDS` rounds): `text`
//! (Zipf-distributed words of a random 30 000-word vocabulary) and `binary`
//! (records, random, zero-padded and opcode-like sections). Workloads:
//! `enc<P>_*` compress as `.xz` (CRC-64, one block) at preset P in 1, 6, 9
//! into a buffer allocated once (ours: `compressInto`; theirs: a
//! `lzma_stream_encoder` fed the whole buffer), `dec<P>_*` decompress the
//! stream the reference made into a buffer allocated once (ours:
//! `decompressStream` into a fixed writer; theirs: `lzma_stream_decoder`).
//! `decA6_*` is ours allocating its output (`decompress`), printed for
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
const lzma = @import("lzma");

const bench_name = "bench-lzma";
const work_dir = ".zig-cache/bench-lzma";
const kinds = [_][]const u8{ "text", "binary" };
const presets = [_]u4{ 1, 6, 9 };

const Op = struct { decompress: bool = false, preset: usize = 1, kind: usize = 0, alloc: bool = false };

const Ctx = struct {
    gpa: std.mem.Allocator,
    op: Op,
    plain: [2][]u8,
    /// Reference streams at presets 1, 6, 9.
    ref: [2][3][]u8,
    out: [2][]u8,
};

fn once(c: *Ctx) u64 {
    const o = c.op;
    if (o.decompress) {
        const stream = c.ref[o.kind][o.preset];
        if (o.alloc) {
            const r = lzma.decompress(c.gpa, stream, .xz, .{}) catch unreachable;
            defer c.gpa.free(r);
            return r.len;
        }
        var in: std.Io.Reader = .fixed(stream);
        var w: std.Io.Writer = .fixed(c.out[o.kind]);
        return lzma.decompressStream(c.gpa, &in, &w, .xz, .{}) catch unreachable;
    }
    return lzma.compressInto(c.gpa, c.out[o.kind], c.plain[o.kind], .xz, .{ .lzma = lzma.preset(presets[o.preset], false) }) catch unreachable;
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
    const mib: usize = if (init.environ_map.get("LZMA_BENCH_MIB")) |r| try std.fmt.parseInt(usize, r, 10) else 2;
    const src = init.environ_map.get("LZMA_SRC") orelse ".zig-cache/survey/lzma/xz";

    // The pinned clone (and, as a side effect, the differential oracle).
    if (cwd.access(io, src, .{})) {} else |_| {
        const r = try std.process.run(arena, io, .{ .argv = &.{ "bash", "modules/lzma/tools/build-oracle.sh" } });
        if (r.term != .exited or r.term.exited != 0) {
            std.debug.print("{s}: could not fetch liblzma:\n{s}\n", .{ bench_name, r.stderr });
            return 1;
        }
    }

    var prng = std.Random.DefaultPrng.init(0x1a2b_2026);
    const r = prng.random();
    var ctx: Ctx = undefined;
    ctx.gpa = std.heap.smp_allocator;
    ctx.plain[0] = try genText(arena, mib << 20, r);
    ctx.plain[1] = try genBinary(arena, mib << 20, r);
    for (kinds, 0..) |k, i| {
        try dir.writeFile(io, .{ .sub_path = try arena.print("{s}.bin", .{k}), .data = ctx.plain[i] });
        ctx.out[i] = try arena.alloc(u8, lzma.compressBound(ctx.plain[i].len));
    }

    // liblzma's library sources, compiled with the macros its CMake defines.
    const L = try arena.print("{s}/src/liblzma", .{src});
    const dirs_c = [_][]const u8{
        "common/alone_decoder.c",           "common/alone_encoder.c",             "common/auto_decoder.c",          "common/block_buffer_decoder.c",
        "common/block_buffer_encoder.c",    "common/block_decoder.c",             "common/block_encoder.c",         "common/block_header_decoder.c",
        "common/block_header_encoder.c",    "common/block_util.c",                "common/common.c",                "common/easy_buffer_encoder.c",
        "common/easy_decoder_memusage.c",   "common/easy_encoder.c",              "common/easy_encoder_memusage.c", "common/easy_preset.c",
        "common/filter_buffer_decoder.c",   "common/filter_buffer_encoder.c",     "common/filter_common.c",         "common/filter_decoder.c",
        "common/filter_encoder.c",          "common/filter_flags_decoder.c",      "common/filter_flags_encoder.c",  "common/index.c",
        "common/index_decoder.c",           "common/index_encoder.c",             "common/index_hash.c",            "common/microlzma_decoder.c",
        "common/microlzma_encoder.c",       "common/stream_buffer_decoder.c",     "common/stream_buffer_encoder.c", "common/stream_decoder.c",
        "common/stream_encoder.c",          "common/stream_flags_common.c",       "common/stream_flags_decoder.c",  "common/stream_flags_encoder.c",
        "common/vli_decoder.c",             "common/vli_encoder.c",               "common/vli_size.c",              "check/check.c",
        "check/crc32_fast.c",               "check/crc64_fast.c",                 "check/sha256.c",                 "lz/lz_encoder.c",
        "lz/lz_encoder_mf.c",               "lz/lz_decoder.c",                    "lzma/lzma_encoder.c",            "lzma/lzma_encoder_presets.c",
        "lzma/lzma_encoder_optimum_fast.c", "lzma/lzma_encoder_optimum_normal.c", "lzma/lzma_decoder.c",            "lzma/lzma2_encoder.c",
        "lzma/lzma2_decoder.c",             "lzma/fastpos_table.c",               "rangecoder/price_table.c",
    };
    var cc: std.ArrayList([]const u8) = .empty;
    try cc.appendSlice(arena, &.{ "zig", "cc", "-w" });
    for ([_][]const u8{
        "HAVE_ENCODERS",    "HAVE_DECODERS",    "HAVE_ENCODER_LZMA1",         "HAVE_ENCODER_LZMA2", "HAVE_DECODER_LZMA1", "HAVE_DECODER_LZMA2",
        "HAVE_CHECK_CRC32", "HAVE_CHECK_CRC64", "HAVE_CHECK_SHA256",          "HAVE_MF_HC3",        "HAVE_MF_HC4",        "HAVE_MF_BT2",
        "HAVE_MF_BT3",      "HAVE_MF_BT4",      "TUKLIB_SYMBOL_PREFIX=lzma_", "NDEBUG",             "HAVE_STDBOOL_H",     "HAVE_STDINT_H",
        "HAVE_INTTYPES_H",  "HAVE__BOOL",
    }) |d| try cc.append(arena, try arena.print("-D{s}", .{d}));
    for ([_][]const u8{ "api", "common", "check", "lz", "lzma", "rangecoder", "simple", "delta" }) |d|
        try cc.appendSlice(arena, &.{ "-I", try arena.print("{s}/{s}", .{ L, d }) });
    try cc.appendSlice(arena, &.{ "-I", try arena.print("{s}/src/common", .{src}), "-lpthread" });
    var libs: [dirs_c.len][]const u8 = undefined;
    for (dirs_c, &libs) |s, *l| l.* = try arena.print("{s}/{s}", .{ L, s });
    const exe = try bench.buildForeign(arena, io, bench_name, cc.items, abs, "modules/lzma/tools/c_oracle/lzbench.c", &libs);

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
        for (presets, 0..) |preset, pi| {
            const rb = try dir.readFileAlloc(io, try arena.print("{s}.{d}.ref.xz", .{ k, preset }), arena, .limited(1 << 28));
            ctx.ref[i][pi] = rb;
            const back = try lzma.decompress(arena, rb, .xz, .{});
            if (!std.mem.eql(u8, back, ctx.plain[i])) {
                std.debug.print("{s}: FAILED -- our decoder does not reproduce {s} from the preset {d} reference stream\n", .{ bench_name, k, preset });
                return 1;
            }
            // (A filtered run is for profiling one side: it skips the encoder gate.)
            if (filters.len != 0) continue;
            const mine = try lzma.compress(arena, ctx.plain[i], .xz, .{ .lzma = lzma.preset(preset, false) });
            if (!std.mem.eql(u8, mine, rb)) {
                std.debug.print("{s}: FAILED -- our preset {d} stream of {s} differs from the reference's\n", .{ bench_name, preset, k });
                return 1;
            }
        }
    }
    try w.writeAll("correctness: our decoder reads the reference streams, our encoder reproduces them byte for byte\n");
    try w.flush();

    var ws: std.ArrayList(Work) = .empty;
    for (kinds, 0..) |k, i| {
        for (presets, 0..) |preset, pi| {
            const en = try arena.print("enc{d}_{s}", .{ preset, k });
            try ws.append(arena, .{ .name = en, .op = .{ .preset = pi, .kind = i }, .ref = en });
            const dn = try arena.print("dec{d}_{s}", .{ preset, k });
            try ws.append(arena, .{ .name = dn, .op = .{ .decompress = true, .preset = pi, .kind = i }, .ref = dn });
        }
        const an = try arena.print("decA6_{s}", .{k});
        try ws.append(arena, .{ .name = an, .op = .{ .decompress = true, .preset = 1, .kind = i, .alloc = true }, .ref = try arena.print("dec6_{s}", .{k}), .info = true });
    }

    const s = try bench.drive(io, arena, .{ .name = bench_name, .exes = &.{exe}, .abs = abs, .filters = filters, .rounds = rounds }, &ctx, once, ws.items, w);
    try w.print("reference: {s}\nworst ours/liblzma = {d:.3} (best {d:.3})\n", .{ std.mem.trimEnd(u8, s.banner, "\n"), s.worst_ref, s.best_ref });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× liblzma 5.8.1 (C, one-shot) · fastest ? (measured <today>)\n", .{ s.best_ref, s.worst_ref });
    try w.flush();
    return 0;
}
