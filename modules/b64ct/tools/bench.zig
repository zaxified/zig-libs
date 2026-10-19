// SPDX-License-Identifier: MIT

//! Comparative benchmark: `b64ct` against libsodium 1.0.22's
//! `sodium_bin2base64` / `sodium_base642bin` (the reference of the maturity
//! card; its constant-time codec, compiled from its own `codecs.c`), the
//! program behind the `**Performance:**` line (CONVENTIONS.md §9, kept
//! instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-b64ct` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `zig` on PATH
//! (it builds `tools/c_bench/sodium_bench.c` + libsodium's `codecs.c` with
//! `zig cc -O3 -march=native`) and the same pinned `codecs.c` as
//! `interop.zig` (its header has the recipe). Run from the repository root.
//!
//! Workloads (padded standard alphabet, fixed seed, written into
//! `.zig-cache/bench-b64ct/`): encode 32 B / 1 KiB / 64 KiB, decode their
//! encodings, and decode a 4 KiB PEM body wrapped at 64 with `\n` ignored
//! (`decodeIgnoring`). Outputs are compared before anything is timed. The
//! sides alternate: five rounds, each timing ours (best of 3, batch doubled
//! until it takes over 50 ms) and then the libsodium program (same), and each
//! side keeps its best over the rounds.

const std = @import("std");
const b64ct = @import("b64ct");
const interop = @import("interop.zig");

const work_dir = ".zig-cache/bench-b64ct";
const rounds = 5;
const C = b64ct.standard;

const Op = enum { enc, dec, dec_ign };
const W = struct { name: []const u8, file: []const u8, op: Op, input: []const u8 = &.{} };

fn runOnce(w: W, out: []u8) usize {
    return switch (w.op) {
        .enc => C.encode(out, w.input).len,
        .dec => (C.decode(out, w.input) catch unreachable).len,
        .dec_ign => (C.decodeIgnoring(out, w.input, "\n") catch unreachable).len,
    };
}

fn timeIt(io: std.Io, w: W, out: []u8) f64 {
    var n: usize = 1;
    while (true) {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| {
            std.mem.doNotOptimizeAway(runOnce(w, out));
            std.mem.doNotOptimizeAway(out.ptr);
        }
        if (t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds > 50_000_000) break;
        n *= 2;
    }
    var best: i96 = std.math.maxInt(i96);
    for (0..3) |_| {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| {
            std.mem.doNotOptimizeAway(runOnce(w, out));
            std.mem.doNotOptimizeAway(out.ptr);
        }
        best = @min(best, t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds);
    }
    return @as(f64, @floatFromInt(best)) / @as(f64, @floatFromInt(n));
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const cwd = std.Io.Dir.cwd();

    const codecs = try interop.codecsPath(arena, io, init.environ_map) orelse return 2;
    try cwd.createDirPath(io, work_dir);
    var dir = try cwd.openDir(io, work_dir, .{});
    defer dir.close(io);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);

    var prng = std.Random.DefaultPrng.init(0x6236_3463_745f_6265);
    const r = prng.random();
    var ws = [_]W{
        .{ .name = "enc_32", .file = "bin32", .op = .enc },
        .{ .name = "enc_1k", .file = "bin1k", .op = .enc },
        .{ .name = "enc_64k", .file = "bin64k", .op = .enc },
        .{ .name = "dec_32", .file = "b64_32", .op = .dec },
        .{ .name = "dec_1k", .file = "b64_1k", .op = .dec },
        .{ .name = "dec_64k", .file = "b64_64k", .op = .dec },
        .{ .name = "dec_pem_4k", .file = "pem_4k", .op = .dec_ign },
    };
    for ([_]usize{ 32, 1024, 65536 }, 0..) |n, i| {
        const bin = try arena.alloc(u8, n);
        r.bytes(bin);
        ws[i].input = bin;
        ws[i + 3].input = try C.encodeAlloc(arena, bin);
    }
    const pem_bin = try arena.alloc(u8, 4096);
    r.bytes(pem_bin);
    const pem = try arena.alloc(u8, C.encodedWrappedLen(pem_bin.len, 64, .lf));
    ws[6].input = C.encodeWrapped(pem, pem_bin, 64, .lf);
    for (ws) |w| try dir.writeFile(io, .{ .sub_path = w.file, .data = w.input });

    const exe = try arena.print("{s}/sodium_bench", .{abs});
    std.debug.print("bench-b64ct: building the libsodium side from {s} ...\n", .{codecs});
    const cc = try std.process.run(arena, io, .{ .argv = &.{ "zig", "cc", "-O3", "-march=native", "-Imodules/b64ct/tools/sodium_shim", "modules/b64ct/tools/c_bench/sodium_bench.c", codecs, "-o", exe } });
    if (cc.term != .exited or cc.term.exited != 0) {
        std.debug.print("bench-b64ct: zig cc failed:\n{s}\n", .{cc.stderr});
        return 1;
    }

    const out = try arena.alloc(u8, 1 << 18);
    var ours_best: [ws.len]f64 = @splat(std.math.inf(f64));
    var theirs_best: [ws.len]f64 = @splat(std.math.inf(f64));
    for (0..rounds) |round| {
        for (ws, 0..) |w, i| ours_best[i] = @min(ours_best[i], timeIt(io, w, out));
        const res = try std.process.run(arena, io, .{ .argv = &.{ exe, abs, "3" } });
        if (res.term != .exited or res.term.exited != 0) {
            std.debug.print("bench-b64ct: libsodium side failed:\n{s}\n", .{res.stderr});
            return 1;
        }
        var lines = std.mem.tokenizeScalar(u8, res.stdout, '\n');
        while (lines.next()) |line| {
            var f = std.mem.tokenizeScalar(u8, line, '\t');
            const name = f.next() orelse continue;
            const ns = try std.fmt.parseFloat(f64, f.next() orelse return error.BadForeignOutput);
            for (ws, 0..) |w, i| if (std.mem.eql(u8, w.name, name)) {
                theirs_best[i] = @min(theirs_best[i], ns);
            };
        }
        if (round == 0) {
            // Interop before believing any number: same output, byte for byte.
            for (ws) |w| {
                const file = try arena.print("{s}.out", .{w.name});
                const theirs = try dir.readFileAlloc(io, file, arena, .limited(1 << 20));
                const n = runOnce(w, out);
                if (!std.mem.eql(u8, out[0..n], theirs)) {
                    std.debug.print("bench-b64ct: FAILED -- {s}: output differs from libsodium's\n", .{w.name});
                    return 1;
                }
            }
        }
    }

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const wr = &stdout.interface;
    try wr.print("interop: outputs equal (ours, {s}) for all workloads\n", .{interop.codecs_version});
    try wr.print("{s:<11} {s:>11} {s:>13} {s:>13}  MB/s ours\n", .{ "workload", "ours ns", "libsodium ns", "ours/sodium" });
    var worst: f64 = 0;
    var best: f64 = std.math.inf(f64);
    for (ws, 0..) |w, i| {
        const ratio = ours_best[i] / theirs_best[i];
        worst = @max(worst, ratio);
        best = @min(best, ratio);
        const mbs = @as(f64, @floatFromInt(w.input.len)) / ours_best[i] * 1e3;
        try wr.print("{s:<11} {d:>11.1} {d:>13.1} {d:>13.3}  {d:.0}\n", .{ w.name, ours_best[i], theirs_best[i], ratio, mbs });
    }
    try wr.print("\nours/libsodium: worst {d:.2}, best {d:.2} ({d} alternating rounds)\n", .{ worst, best, rounds });
    try wr.print("card: **Performance:** ref {d:.2}–{d:.2}× libsodium 1.0.22 · fastest ?\n", .{ best, worst });
    try wr.flush();
    return 0;
}
