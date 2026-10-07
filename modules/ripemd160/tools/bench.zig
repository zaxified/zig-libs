// SPDX-License-Identifier: MIT

//! Comparative benchmark: `ripemd160` against Bitcoin Core v29.0's `CRIPEMD160`
//! (the reference of the maturity card) and, as a second row set, OpenSSL
//! libcrypto's one-shot `RIPEMD160()`; the program behind the `**Performance:**`
//! line of the maturity card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-ripemd160` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `zig` on PATH
//! (it builds `tools/c_bench/openssl_bench.c` with `zig cc` and
//! `tools/c_bench/bitcoin_bench.cpp` with `zig c++`), the system libcrypto
//! (`libcrypto.so.3`, path below or `CRYPTO_SO`; no headers needed) and the
//! Bitcoin Core v29.0 sources `ripemd160.cpp`, `crypto/{ripemd160.h,common.h}`,
//! `compat/{endian.h,byteswap.h}` (dir below or `BITCOIN_RIPEMD_SRC`; if it is
//! missing the program prints the fetch recipe and exits 2).
//! Run from the repository root.
//!
//! Workloads: the one-shot digest of a 64-byte, a 64 KiB and a 1 MiB message,
//! all written into `.zig-cache/bench-ripemd160/` from a fixed seed. Both sides
//! double the batch until it takes over 100 ms and keep the best of five.
//! Before timing anything, all three digests must be equal -- a benchmark of two
//! things that disagree measures nothing.

const std = @import("std");
const ripemd160 = @import("ripemd160");

const work_dir = ".zig-cache/bench-ripemd160";
const default_so = "/usr/lib/x86_64-linux-gnu/libcrypto.so.3";

const default_btc_src = ".zig-cache/foreign/bitcoin-ripemd";
const btc_recipe =
    \\bench-ripemd160: Bitcoin Core v29.0 sources not found at {s}
    \\  fetch (and review before compiling) these 5 files into one directory, same layout:
    \\    base=https://raw.githubusercontent.com/bitcoin/bitcoin/v29.0/src
    \\    ripemd160.cpp  crypto/ripemd160.h  crypto/common.h  compat/endian.h  compat/byteswap.h
    \\  expected sha256 of ripemd160.cpp: 126156e7107e8636be1b92869c1b7c3aa2b8067d6cdaf143595b23a2d26c66a3
    \\  then: BITCOIN_RIPEMD_SRC=<dir> zig build bench-ripemd160
    \\
;

const Row = struct { ns: f64, count: u64 };

const Ctx = struct { msg: []const u8 };

fn doHash(c: Ctx) usize {
    var out: [ripemd160.Ripemd160.digest_length]u8 = undefined;
    ripemd160.Ripemd160.hash(c.msg, &out, .{});
    std.mem.doNotOptimizeAway(&out);
    return c.msg.len;
}

fn timeIt(io: std.Io, c: Ctx, comptime f: fn (Ctx) usize) Row {
    var n: usize = 1;
    while (true) {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| std.mem.doNotOptimizeAway(f(c));
        if (t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds > 100_000_000) break;
        n *= 2;
    }
    var best: i96 = std.math.maxInt(i96);
    var count: usize = 0;
    for (0..5) |_| {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| count = f(c);
        best = @min(best, t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds);
    }
    return .{ .ns = @as(f64, @floatFromInt(best)) / @as(f64, @floatFromInt(n)), .count = count };
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();

    const cwd = std.Io.Dir.cwd();
    const btc_src = init.environ_map.get("BITCOIN_RIPEMD_SRC") orelse default_btc_src;
    cwd.access(io, btc_src, .{}) catch {
        std.debug.print(btc_recipe, .{btc_src});
        return 2;
    };
    const btc_abs = try cwd.realPathFileAlloc(io, btc_src, arena);
    try cwd.createDirPath(io, work_dir);
    var dir = try cwd.openDir(io, work_dir, .{});
    defer dir.close(io);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);

    var prng = std.Random.DefaultPrng.init(0x0b5e_55ed_71b1);
    const r = prng.random();
    const m64 = try arena.alloc(u8, 64);
    const m64k = try arena.alloc(u8, 65536);
    const m1m = try arena.alloc(u8, 1 << 20);
    r.bytes(m64);
    r.bytes(m64k);
    r.bytes(m1m);
    try dir.writeFile(io, .{ .sub_path = "msg64.bin", .data = m64 });
    try dir.writeFile(io, .{ .sub_path = "msg64k.bin", .data = m64k });
    try dir.writeFile(io, .{ .sub_path = "msg1m.bin", .data = m1m });

    const so = init.environ_map.get("CRYPTO_SO") orelse default_so;
    const exe = try std.fmt.allocPrint(arena, "{s}/openssl_bench", .{abs});
    std.debug.print("bench-ripemd160: building the OpenSSL side against {s} ...\n", .{so});
    const cc = try std.process.run(arena, io, .{ .argv = &.{ "zig", "cc", "-O3", "-march=native", "modules/ripemd160/tools/c_bench/openssl_bench.c", so, "-o", exe } });
    if (cc.term != .exited or cc.term.exited != 0) {
        std.debug.print("bench-ripemd160: zig cc failed:\n{s}\n", .{cc.stderr});
        return 1;
    }
    const res = try std.process.run(arena, io, .{ .argv = &.{ exe, abs } });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("bench-ripemd160: OpenSSL side failed:\n{s}\n", .{res.stderr});
        return 1;
    }
    var rows: std.StringHashMapUnmanaged(Row) = .empty;
    var lines = std.mem.tokenizeScalar(u8, res.stdout, '\n');
    while (lines.next()) |line| {
        var f = std.mem.tokenizeScalar(u8, line, '\t');
        const name = f.next() orelse continue;
        const ns = try std.fmt.parseFloat(f64, f.next() orelse return error.BadForeignOutput);
        const count = try std.fmt.parseInt(u64, f.next() orelse return error.BadForeignOutput, 10);
        try rows.put(arena, name, .{ .ns = ns, .count = count });
    }

    const btc_exe = try std.fmt.allocPrint(arena, "{s}/bitcoin_bench", .{abs});
    const btc_inc = try std.fmt.allocPrint(arena, "-I{s}", .{btc_abs});
    const btc_cpp = try std.fmt.allocPrint(arena, "{s}/ripemd160.cpp", .{btc_abs});
    std.debug.print("bench-ripemd160: building the Bitcoin Core side from {s} ...\n", .{btc_src});
    const cxx = try std.process.run(arena, io, .{ .argv = &.{ "zig", "c++", "-O3", "-march=native", "-std=c++20", btc_inc, "modules/ripemd160/tools/c_bench/bitcoin_bench.cpp", btc_cpp, "-o", btc_exe } });
    if (cxx.term != .exited or cxx.term.exited != 0) {
        std.debug.print("bench-ripemd160: zig c++ failed:\n{s}\n", .{cxx.stderr});
        return 1;
    }
    const bres = try std.process.run(arena, io, .{ .argv = &.{ btc_exe, abs } });
    if (bres.term != .exited or bres.term.exited != 0) {
        std.debug.print("bench-ripemd160: Bitcoin Core side failed:\n{s}\n", .{bres.stderr});
        return 1;
    }
    var brows: std.StringHashMapUnmanaged(Row) = .empty;
    var blines = std.mem.tokenizeScalar(u8, bres.stdout, '\n');
    while (blines.next()) |line| {
        var f = std.mem.tokenizeScalar(u8, line, '\t');
        const name = f.next() orelse continue;
        const ns = try std.fmt.parseFloat(f64, f.next() orelse return error.BadForeignOutput);
        const count = try std.fmt.parseInt(u64, f.next() orelse return error.BadForeignOutput, 10);
        try brows.put(arena, name, .{ .ns = ns, .count = count });
    }

    const W = struct { name: []const u8, msg: []const u8 };
    const ws = [_]W{
        .{ .name = "hash_64", .msg = m64 },
        .{ .name = "hash_64k", .msg = m64k },
        .{ .name = "hash_1m", .msg = m1m },
    };

    // Interop before timing: the digests must be equal.
    for (ws) |x| {
        const file = try std.fmt.allocPrint(arena, "{s}.digest", .{x.name});
        const theirs = try dir.readFileAlloc(io, file, arena, .limited(64));
        var ours: [ripemd160.Ripemd160.digest_length]u8 = undefined;
        ripemd160.Ripemd160.hash(x.msg, &ours, .{});
        if (!std.mem.eql(u8, &ours, theirs)) {
            std.debug.print("bench-ripemd160: FAILED -- {s}: the digest differs from OpenSSL's\n", .{x.name});
            return 1;
        }
        const bfile = try std.fmt.allocPrint(arena, "btc_{s}.digest", .{x.name});
        const btheirs = try dir.readFileAlloc(io, bfile, arena, .limited(64));
        if (!std.mem.eql(u8, &ours, btheirs)) {
            std.debug.print("bench-ripemd160: FAILED -- {s}: the digest differs from Bitcoin Core's\n", .{x.name});
            return 1;
        }
    }

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.print("interop: digests equal (ours, Bitcoin Core, OpenSSL) for all workloads\n", .{});
    try w.print("{s:<9} {s:>11} {s:>11} {s:>11} {s:>12} {s:>12}  bytes\n", .{ "workload", "ours ns", "bitcoin ns", "openssl ns", "ours/bitcoin", "ours/openssl" });
    var worst: f64 = 0;
    var best: f64 = std.math.inf(f64);
    var worst_o: f64 = 0;
    var best_o: f64 = std.math.inf(f64);
    var mismatch = false;
    for (ws) |x| {
        const ours = timeIt(io, .{ .msg = x.msg }, doHash);
        const t = rows.get(x.name) orelse return error.MissingRow;
        const b = brows.get(x.name) orelse return error.MissingRow;
        const ratio = ours.ns / b.ns;
        const ratio_o = ours.ns / t.ns;
        worst = @max(worst, ratio);
        best = @min(best, ratio);
        worst_o = @max(worst_o, ratio_o);
        best_o = @min(best_o, ratio_o);
        const same = ours.count == t.count and ours.count == b.count;
        if (!same) mismatch = true;
        try w.print("{s:<9} {d:>11.1} {d:>11.1} {d:>11.1} {d:>12.2} {d:>12.2}  {d}{s}\n", .{ x.name, ours.ns, b.ns, t.ns, ratio, ratio_o, ours.count, if (same) "" else " ≠" });
        try w.flush();
    }
    if (mismatch) return 1;
    try w.print("\nours/bitcoin: worst {d:.2}, best {d:.2}; ours/openssl: worst {d:.2}, best {d:.2}\n", .{ worst, best, worst_o, best_o });
    try w.print("card: **Performance:** ref {d:.2}–{d:.2}× Bitcoin Core v29.0 CRIPEMD160 · fastest ? (measured 2026-10-07)\n", .{ best, worst });
    try w.flush();
    return 0;
}
