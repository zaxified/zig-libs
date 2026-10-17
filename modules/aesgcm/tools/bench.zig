// SPDX-License-Identifier: MIT

//! Comparative benchmark: `aesgcm` against OpenSSL's EVP AES-GCM (the
//! reference), the program behind the `**Performance:**` line of the maturity
//! card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-aesgcm` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `zig` on PATH (it
//! builds `tools/c_bench/foreign_bench.c` with `zig cc -O3 -march=native`) and
//! the system OpenSSL 3 (`libcrypto.so.3`, path below or `LIBCRYPTO_SO`; no
//! headers needed). Run from the repository root.
//!
//! Workloads: AES-128-GCM and AES-256-GCM, encrypt and decrypt, of a 64-byte,
//! a 1420-byte (one WireGuard/QUIC-sized packet) and a 16 KiB (one TLS record)
//! message with 13 bytes of associated data, under a key set up once (ours:
//! `Context`, theirs: an `EVP_CIPHER_CTX` keyed once, the nonce set per op).
//! Inputs are written into `.zig-cache/bench-aesgcm/` from fixed seeds.
//!
//! Method (`testkit.bench`): each side doubles its batch until it
//! takes over 100 ms and keeps the best of five; per workload the sides
//! alternate for `BENCH_ROUNDS` (default 3) rounds, each keeping its best; the
//! spread printed is (worst round − best round) / best round per side. Ratios
//! are ours/theirs by user-mode cycles when both sides count them (they do not
//! move with the clock), else by wall time. Before timing anything OpenSSL's
//! AES-256-GCM ciphertext and tag of the 16 KiB message must equal ours byte
//! for byte. Arguments filter workloads by substring (no card line then).

const std = @import("std");
const bench = @import("testkit").bench;
const Work = bench.Work(Op);
const aesgcm = @import("aesgcm");

const bench_name = "bench-aesgcm";
const work_dir = ".zig-cache/bench-aesgcm";
const default_so = "/usr/lib/x86_64-linux-gnu/libcrypto.so.3";
const sizes = [_]usize{ 64, 1420, 16384 };

const Op = struct { bits: u16, decrypt: bool, size: usize };

const Ctx = struct {
    c128: aesgcm.Aes128Gcm.Context,
    c256: aesgcm.Aes256Gcm.Context,
    nonce: [12]u8,
    ad: [13]u8,
    msgs: [sizes.len][]u8,
    cts: [2][sizes.len][]u8,
    tags: [2][sizes.len][16]u8,
    out: []u8,
    op: Op = undefined,
};

fn sizeIndex(n: usize) usize {
    return std.mem.indexOfScalar(usize, &sizes, n).?;
}

fn once(x: *Ctx) usize {
    var tag: [16]u8 = undefined;
    const i = sizeIndex(x.op.size);
    const n = x.op.size;
    const b: usize = if (x.op.bits == 128) 0 else 1;
    if (x.op.decrypt) {
        if (b == 0)
            x.c128.decrypt(x.out[0..n], x.cts[b][i], x.tags[b][i], &x.ad, x.nonce) catch unreachable
        else
            x.c256.decrypt(x.out[0..n], x.cts[b][i], x.tags[b][i], &x.ad, x.nonce) catch unreachable;
        return n;
    }
    if (b == 0) x.c128.encrypt(x.out[0..n], &tag, x.msgs[i], &x.ad, x.nonce) else x.c256.encrypt(x.out[0..n], &tag, x.msgs[i], &x.ad, x.nonce);
    std.mem.doNotOptimizeAway(&tag);
    return n + 16;
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

    var prng = std.Random.DefaultPrng.init(0xae5_6c3_b3c4);
    const r = prng.random();
    var key: [32]u8 = undefined;
    var ctx: Ctx = undefined;
    r.bytes(&key);
    r.bytes(&ctx.nonce);
    r.bytes(&ctx.ad);
    ctx.c128 = aesgcm.Aes128Gcm.Context.init(key[0..16].*);
    ctx.c256 = aesgcm.Aes256Gcm.Context.init(key);
    ctx.out = try arena.alloc(u8, 16384 + 16);
    try dir.writeFile(io, .{ .sub_path = "key32.bin", .data = &key });
    try dir.writeFile(io, .{ .sub_path = "nonce.bin", .data = &ctx.nonce });
    try dir.writeFile(io, .{ .sub_path = "ad.bin", .data = &ctx.ad });
    for (sizes, 0..) |n, i| {
        ctx.msgs[i] = try arena.alloc(u8, n);
        r.bytes(ctx.msgs[i]);
        try dir.writeFile(io, .{ .sub_path = try std.fmt.allocPrint(arena, "msg{d}.bin", .{n}), .data = ctx.msgs[i] });
        for (0..2) |b| ctx.cts[b][i] = try arena.alloc(u8, n);
        ctx.c128.encrypt(ctx.cts[0][i], &ctx.tags[0][i], ctx.msgs[i], &ctx.ad, ctx.nonce);
        ctx.c256.encrypt(ctx.cts[1][i], &ctx.tags[1][i], ctx.msgs[i], &ctx.ad, ctx.nonce);
    }

    const so = init.environ_map.get("LIBCRYPTO_SO") orelse default_so;
    const exe = try bench.buildForeign(arena, io, bench_name, &.{ "zig", "cc" }, abs, "modules/aesgcm/tools/c_bench/foreign_bench.c", &.{so});

    // Interop before timing.
    try bench.foreignOnce(arena, io, bench_name, exe, abs, "interop");
    const theirs = try dir.readFileAlloc(io, "ossl_ct.bin", arena, .limited(1 << 20));
    const i16k = sizeIndex(16384);
    if (theirs.len != 16384 + 16 or !std.mem.eql(u8, theirs[0..16384], ctx.cts[1][i16k]) or !std.mem.eql(u8, theirs[16384..], &ctx.tags[1][i16k])) {
        std.debug.print("bench-aesgcm: FAILED -- OpenSSL's AES-256-GCM output differs from ours\n", .{});
        return 1;
    }

    var ws: std.ArrayList(Work) = .empty;
    for ([_]u16{ 128, 256 }) |bits| for ([_]bool{ false, true }) |decrypt| for (sizes) |n| {
        const name = try std.fmt.allocPrint(arena, "aes{d}_{s}_{d}", .{ bits, if (decrypt) "dec" else "enc", n });
        try ws.append(arena, .{ .name = name, .op = .{ .bits = bits, .decrypt = decrypt, .size = n }, .ref = name });
    };

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = try bench.drive(io, arena, .{ .name = bench_name, .exes = &.{exe}, .abs = abs, .filters = filters, .rounds = rounds }, &ctx, once, ws.items, w);
    try w.print("reference: {s}\nworst ours/OpenSSL = {d:.3} (best {d:.3})\n", .{ std.mem.trimEnd(u8, s.banner, "\n"), s.worst_ref, s.best_ref });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× OpenSSL <version> EVP AES-GCM · fastest ? (measured <today>)\n", .{ s.best_ref, s.worst_ref });
    try w.flush();
    return 0;
}
