// SPDX-License-Identifier: MIT

//! Comparative benchmark: `chachapoly` against OpenSSL's EVP
//! `chacha20-poly1305` (the reference the module's scope was surveyed
//! against) and libsodium's `crypto_aead_chacha20poly1305_ietf` (the other
//! implementation in the field measured here),
//! the program behind the `**Performance:**` line of the maturity card
//! (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-chachapoly` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `zig` on PATH (it
//! builds `tools/c_bench/foreign_bench.c` with `zig cc -O3 -march=native`), the
//! system libsodium (`libsodium.so.23`, or `SODIUM_SO`) and OpenSSL 3
//! (`libcrypto.so.3`, or `LIBCRYPTO_SO`); no headers needed. Run from the
//! repository root.
//!
//! Workloads: ChaCha20-Poly1305 (RFC 8439) encrypt and decrypt of a 64-byte, a
//! 1420-byte (one WireGuard packet) and a 16 KiB (one TLS record) message with
//! 13 bytes of associated data (ours: `ChaCha20Poly1305.encryptInto` /
//! `decryptInto`). Inputs are written into `.zig-cache/bench-chachapoly/`
//! from fixed seeds.
//!
//! Method (`testkit.bench`): each side doubles its batch until it
//! takes over 100 ms and keeps the best of five; per workload the sides
//! alternate for `BENCH_ROUNDS` (default 3) rounds, each keeping its best; the
//! spread printed is (worst round − best round) / best round per side. Ratios
//! are ours/theirs by user-mode cycles when all sides count them, else by wall
//! time; `/fast` is ours over the faster of OpenSSL and libsodium. Before
//! timing anything both libraries' ciphertext and tag of the 1420-byte message
//! must equal ours byte for byte. Arguments filter workloads by substring.

const std = @import("std");
const bench = @import("testkit").bench;
const Work = bench.Work(Op);
const chachapoly = @import("chachapoly");
const Aead = chachapoly.ChaCha20Poly1305;

const bench_name = "bench-chachapoly";
const work_dir = ".zig-cache/bench-chachapoly";
const default_sodium = "/usr/lib/x86_64-linux-gnu/libsodium.so.23";
const default_crypto = "/usr/lib/x86_64-linux-gnu/libcrypto.so.3";
const sizes = [_]usize{ 64, 1420, 16384 };

const Op = struct { decrypt: bool, size: usize };

const Ctx = struct {
    key: [32]u8,
    nonce: [12]u8,
    ad: [13]u8,
    msgs: [sizes.len][]u8,
    cts: [sizes.len][]u8,
    tags: [sizes.len][16]u8,
    out: []u8,
    op: Op = undefined,
};

fn sizeIndex(n: usize) usize {
    return std.mem.findScalar(usize, &sizes, n).?;
}

fn once(x: *Ctx) usize {
    const i = sizeIndex(x.op.size);
    const n = x.op.size;
    if (x.op.decrypt) {
        Aead.decryptInto(x.out[0..n], x.cts[i], x.tags[i], &x.ad, x.nonce, &x.key) catch unreachable;
        return n;
    }
    var tag: [16]u8 = undefined;
    Aead.encryptInto(x.out[0..n], &tag, x.msgs[i], &x.ad, x.nonce, &x.key);
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

    var prng = std.Random.DefaultPrng.init(0xc4a_c4a_1305);
    const r = prng.random();
    var ctx: Ctx = undefined;
    r.bytes(&ctx.key);
    r.bytes(&ctx.nonce);
    r.bytes(&ctx.ad);
    ctx.out = try arena.alloc(u8, 16384 + 16);
    try dir.writeFile(io, .{ .sub_path = "key32.bin", .data = &ctx.key });
    try dir.writeFile(io, .{ .sub_path = "nonce.bin", .data = &ctx.nonce });
    try dir.writeFile(io, .{ .sub_path = "ad.bin", .data = &ctx.ad });
    for (sizes, 0..) |n, i| {
        ctx.msgs[i] = try arena.alloc(u8, n);
        r.bytes(ctx.msgs[i]);
        try dir.writeFile(io, .{ .sub_path = try arena.print("msg{d}.bin", .{n}), .data = ctx.msgs[i] });
        ctx.cts[i] = try arena.alloc(u8, n);
        Aead.encryptInto(ctx.cts[i], &ctx.tags[i], ctx.msgs[i], &ctx.ad, ctx.nonce, &ctx.key);
    }

    const so_s = init.environ_map.get("SODIUM_SO") orelse default_sodium;
    const so_c = init.environ_map.get("LIBCRYPTO_SO") orelse default_crypto;
    const exe = try bench.buildForeign(arena, io, bench_name, &.{ "zig", "cc" }, abs, "modules/chachapoly/tools/c_bench/foreign_bench.c", &.{ so_s, so_c });

    // Interop before timing.
    try bench.foreignOnce(arena, io, bench_name, exe, abs, "interop");
    const idx_1420 = sizeIndex(1420);
    for ([_][]const u8{ "sodium_ct.bin", "ossl_ct.bin" }) |f| {
        const theirs = try dir.readFileAlloc(io, f, arena, .limited(1 << 20));
        if (theirs.len != 1420 + 16 or !std.mem.eql(u8, theirs[0..1420], ctx.cts[idx_1420]) or !std.mem.eql(u8, theirs[1420..], &ctx.tags[idx_1420])) {
            std.debug.print("bench-chachapoly: FAILED -- {s} differs from ours\n", .{f});
            return 1;
        }
    }

    var ws: std.ArrayList(Work) = .empty;
    for ([_]bool{ false, true }) |decrypt| for (sizes) |n| {
        const op = if (decrypt) "dec" else "enc";
        try ws.append(arena, .{
            .name = try arena.print("{s}_{d}", .{ op, n }),
            .op = .{ .decrypt = decrypt, .size = n },
            .ref = try arena.print("ossl.{s}_{d}", .{ op, n }),
            .alt = try arena.print("sodium.{s}_{d}", .{ op, n }),
        });
    };

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = try bench.drive(io, arena, .{ .name = bench_name, .exes = &.{exe}, .abs = abs, .filters = filters, .rounds = rounds }, &ctx, once, ws.items, w);
    try w.print("reference: {s}; other: libsodium {s}\nworst ours/OpenSSL = {d:.3} (best {d:.3}); worst ours/fastest = {d:.3}\n", .{ std.mem.trimEnd(u8, s.banner, "\n"), std.mem.trimEnd(u8, s.alt_banner, "\n"), s.worst_ref, s.best_ref, s.worst_fast orelse 0 });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× OpenSSL <version> EVP ChaCha20-Poly1305 · fastest {d:.2}× (OpenSSL or libsodium per row) (measured <today>)\n", .{ s.best_ref, s.worst_ref, s.worst_fast orelse 0 });
    try w.flush();
    return 0;
}
