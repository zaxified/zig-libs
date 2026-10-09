// SPDX-License-Identifier: MIT

//! Comparative benchmark: `sealedbox` against libsodium's `crypto_box_seal`
//! (the reference), the program behind the `**Performance:**` line of the
//! maturity card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-sealedbox` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `zig` on PATH
//! (it builds `tools/c_bench/sodium_bench.c` with `zig cc`) and the system
//! libsodium (`libsodium.so.23`, path below or `SODIUM_SO`; no headers needed).
//! Run from the repository root.
//!
//! Workloads: seal and open of a 64-byte and a 64 KiB message under one key
//! pair, both written into `.zig-cache/bench-sealedbox/` from fixed seeds.
//! Both sides double the batch until it takes over 100 ms and keep the best of
//! five, and report the output length. Before timing anything, a box libsodium
//! sealed for our key pair must open here to the same message — a benchmark of
//! two things that do not interoperate measures nothing.

const std = @import("std");
const sealedbox = @import("sealedbox");

const work_dir = ".zig-cache/bench-sealedbox";
const default_so = "/usr/lib/x86_64-linux-gnu/libsodium.so.23";

const Row = struct { ns: f64, count: u64 };

const Ctx = struct { io: std.Io, kp: sealedbox.KeyPair, msg: []const u8, sealed: []const u8, out: []u8 };

fn doSeal(c: Ctx) usize {
    sealedbox.seal(c.io, c.out[0 .. c.msg.len + sealedbox.overhead], c.msg, c.kp.public_key) catch unreachable;
    return c.msg.len + sealedbox.overhead;
}
fn doOpen(c: Ctx) usize {
    sealedbox.open(c.out[0..c.msg.len], c.sealed, &c.kp) catch unreachable;
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
    try cwd.createDirPath(io, work_dir);
    var dir = try cwd.openDir(io, work_dir, .{});
    defer dir.close(io);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);

    var prng = std.Random.DefaultPrng.init(0x0b5e_55ed_5ea1);
    const r = prng.random();
    var sk: [sealedbox.secret_length]u8 = undefined;
    r.bytes(&sk);
    var kp: sealedbox.KeyPair = undefined;
    try sealedbox.keyPairFromSecretKey(&kp, &sk);
    const m64 = try arena.alloc(u8, 64);
    const m64k = try arena.alloc(u8, 65536);
    r.bytes(m64);
    r.bytes(m64k);
    try dir.writeFile(io, .{ .sub_path = "pk.bin", .data = &kp.public_key });
    try dir.writeFile(io, .{ .sub_path = "sk.bin", .data = &kp.secret_key });
    try dir.writeFile(io, .{ .sub_path = "msg64.bin", .data = m64 });
    try dir.writeFile(io, .{ .sub_path = "msg64k.bin", .data = m64k });

    const so = init.environ_map.get("SODIUM_SO") orelse default_so;
    const exe = try std.fmt.allocPrint(arena, "{s}/sodium_bench", .{abs});
    std.debug.print("bench-sealedbox: building the libsodium side against {s} ...\n", .{so});
    const cc = try std.process.run(arena, io, .{ .argv = &.{ "zig", "cc", "-O3", "-march=native", "modules/sealedbox/tools/c_bench/sodium_bench.c", so, "-o", exe } });
    if (cc.term != .exited or cc.term.exited != 0) {
        std.debug.print("bench-sealedbox: zig cc failed:\n{s}\n", .{cc.stderr});
        return 1;
    }
    const res = try std.process.run(arena, io, .{ .argv = &.{ exe, abs } });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("bench-sealedbox: libsodium side failed:\n{s}\n", .{res.stderr});
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

    // Interop before timing.
    const theirs = try dir.readFileAlloc(io, "sodium_sealed64.bin", arena, .limited(4096));
    var opened: [64]u8 = undefined;
    sealedbox.open(&opened, theirs, &kp) catch {
        std.debug.print("bench-sealedbox: FAILED -- a box libsodium sealed does not open here\n", .{});
        return 1;
    };
    if (!std.mem.eql(u8, &opened, m64)) {
        std.debug.print("bench-sealedbox: FAILED -- a box libsodium sealed opens to a different message\n", .{});
        return 1;
    }

    const out = try arena.alloc(u8, 65536 + sealedbox.overhead);
    const s64 = try arena.alloc(u8, 64 + sealedbox.overhead);
    const s64k = try arena.alloc(u8, 65536 + sealedbox.overhead);
    try sealedbox.seal(io, s64, m64, kp.public_key);
    try sealedbox.seal(io, s64k, m64k, kp.public_key);

    const W = struct { name: []const u8, ctx: Ctx, open: bool };
    const ws = [_]W{
        .{ .name = "seal_64", .ctx = .{ .io = io, .kp = kp, .msg = m64, .sealed = s64, .out = out }, .open = false },
        .{ .name = "seal_64k", .ctx = .{ .io = io, .kp = kp, .msg = m64k, .sealed = s64k, .out = out }, .open = false },
        .{ .name = "open_64", .ctx = .{ .io = io, .kp = kp, .msg = m64, .sealed = s64, .out = out }, .open = true },
        .{ .name = "open_64k", .ctx = .{ .io = io, .kp = kp, .msg = m64k, .sealed = s64k, .out = out }, .open = true },
    };

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.print("reference: {s}", .{res.stderr});
    try w.print("{s:<9} {s:>12} {s:>14} {s:>12}  bytes\n", .{ "workload", "ours ns/op", "sodium ns/op", "ours/sodium" });
    var worst: f64 = 0;
    var best: f64 = std.math.inf(f64);
    var mismatch = false;
    for (ws) |x| {
        const ours = if (x.open) timeIt(io, x.ctx, doOpen) else timeIt(io, x.ctx, doSeal);
        const t = rows.get(x.name) orelse return error.MissingRow;
        const ratio = ours.ns / t.ns;
        worst = @max(worst, ratio);
        best = @min(best, ratio);
        const same = ours.count == t.count;
        if (!same) mismatch = true;
        try w.print("{s:<9} {d:>12.0} {d:>14.0} {d:>12.2}  {d}{s}\n", .{ x.name, ours.ns, t.ns, ratio, ours.count, if (same) "" else " ≠" });
        try w.flush();
    }
    if (mismatch) return 1;
    try w.print("\nworst ours/sodium = {d:.2} (best {d:.2})\n", .{ worst, best });
    try w.print("card: **Performance:** ref {d:.2}–{d:.2}× libsodium <version> crypto_box_seal · fastest ? (measured <today>)\n", .{ best, worst });
    try w.flush();
    return 0;
}
