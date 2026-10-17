// SPDX-License-Identifier: MIT

//! Comparative benchmark: `ct25519` against libsodium (the reference) and,
//! for X25519, OpenSSL (the other implementation in the field measured here),
//! the program behind the `**Performance:**` line of the maturity card
//! (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-ct25519` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `zig` on PATH (it
//! builds `tools/c_bench/foreign_bench.c` with `zig cc -O3 -march=native`), the
//! system libsodium (`libsodium.so.23`, or `SODIUM_SO`) and OpenSSL 3
//! (`libcrypto.so.3`, or `LIBCRYPTO_SO`); no headers needed. Run from the
//! repository root.
//!
//! Workloads (each one operation, encoded output included on both sides):
//!   x25519      `X25519.scalarmultInto` vs `crypto_scalarmult` (and OpenSSL
//!               `EVP_PKEY_derive`, peer set once)
//!   x25519_pub  `X25519.recoverPublicKeyInto` vs `crypto_scalarmult_base` (and
//!               OpenSSL's raw-key import + `get_raw_public_key`)
//!   ed_base     `mulBase(s).toBytes()` vs `crypto_scalarmult_ed25519_base_noclamp`
//!   rist_base   `mulRistrettoBase(s).toBytes()` vs `crypto_scalarmult_ristretto255_base`
//! Not compared: the variable-base Edwards/Ristretto `mul` -- libsodium's
//! `crypto_scalarmult_ed25519_noclamp` adds a prime-order-subgroup check (a
//! second scalar multiplication) that `mul` does not do, so the ratio would
//! measure the API, not the arithmetic. Inputs are written into
//! `.zig-cache/bench-ct25519/` from fixed seeds; `s` is below 2^252 (< L).
//!
//! Method (`testkit.bench`): each side doubles its batch until it
//! takes over 100 ms and keeps the best of five; per workload the sides
//! alternate for `BENCH_ROUNDS` (default 3) rounds, each keeping its best; the
//! spread printed is (worst round − best round) / best round per side. Ratios
//! are ours/theirs by user-mode cycles when all sides count them, else by wall
//! time; `/fast` is ours over the faster of libsodium and OpenSSL. Before
//! timing anything every foreign output must equal ours byte for byte.
//! Arguments filter workloads by substring.

const std = @import("std");
const bench = @import("testkit").bench;
const Work = bench.Work(Op);
const ct25519 = @import("ct25519");

const bench_name = "bench-ct25519";
const work_dir = ".zig-cache/bench-ct25519";
const default_sodium = "/usr/lib/x86_64-linux-gnu/libsodium.so.23";
const default_crypto = "/usr/lib/x86_64-linux-gnu/libcrypto.so.3";

const Op = enum { x25519, x25519_pub, ed_base, rist_base };

const Ctx = struct {
    sk: [32]u8,
    peer: [32]u8,
    s: [32]u8,
    op: Op = undefined,
};

fn compute(x: *const Ctx, op: Op) [32]u8 {
    var out: [32]u8 = undefined;
    switch (op) {
        .x25519 => ct25519.X25519.scalarmultInto(&out, &x.sk, x.peer) catch unreachable,
        .x25519_pub => ct25519.X25519.recoverPublicKeyInto(&out, &x.sk) catch unreachable,
        .ed_base => out = ct25519.mulBase(x.s).toBytes(),
        .rist_base => out = ct25519.mulRistrettoBase(x.s).toBytes(),
    }
    return out;
}

fn once(x: *Ctx) usize {
    const out = compute(x, x.op);
    std.mem.doNotOptimizeAway(&out);
    return out.len;
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

    var prng = std.Random.DefaultPrng.init(0x25519_c7);
    const r = prng.random();
    var ctx: Ctx = undefined;
    r.bytes(&ctx.sk);
    var peer_sk: [32]u8 = undefined;
    r.bytes(&peer_sk);
    ctx.peer = try ct25519.X25519.recoverPublicKey(peer_sk);
    r.bytes(&ctx.s);
    ctx.s[31] &= 0x0f;
    try dir.writeFile(io, .{ .sub_path = "sk.bin", .data = &ctx.sk });
    try dir.writeFile(io, .{ .sub_path = "peer.bin", .data = &ctx.peer });
    try dir.writeFile(io, .{ .sub_path = "scalar.bin", .data = &ctx.s });

    const so_s = init.environ_map.get("SODIUM_SO") orelse default_sodium;
    const so_c = init.environ_map.get("LIBCRYPTO_SO") orelse default_crypto;
    const exe = try bench.buildForeign(arena, io, bench_name, &.{ "zig", "cc" }, abs, "modules/ct25519/tools/c_bench/foreign_bench.c", &.{ so_s, so_c });

    // Interop before timing.
    try bench.foreignOnce(arena, io, bench_name, exe, abs, "interop");
    const checks = [_]struct { f: []const u8, op: Op }{
        .{ .f = "sodium.x25519.bin", .op = .x25519 },   .{ .f = "sodium.x25519_pub.bin", .op = .x25519_pub },
        .{ .f = "sodium.ed_base.bin", .op = .ed_base }, .{ .f = "sodium.rist_base.bin", .op = .rist_base },
        .{ .f = "ossl.x25519.bin", .op = .x25519 },     .{ .f = "ossl.x25519_pub.bin", .op = .x25519_pub },
    };
    for (checks) |c| {
        const theirs = try dir.readFileAlloc(io, c.f, arena, .limited(64));
        if (!std.mem.eql(u8, theirs, &compute(&ctx, c.op))) {
            std.debug.print("bench-ct25519: FAILED -- {s} differs from ours\n", .{c.f});
            return 1;
        }
    }

    const ws = [_]Work{
        .{ .name = "x25519", .op = .x25519, .ref = "sodium.x25519", .alt = "ossl.x25519" },
        .{ .name = "x25519_pub", .op = .x25519_pub, .ref = "sodium.x25519_pub", .alt = "ossl.x25519_pub" },
        .{ .name = "ed_base", .op = .ed_base, .ref = "sodium.ed_base" },
        .{ .name = "rist_base", .op = .rist_base, .ref = "sodium.rist_base" },
    };

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = try bench.drive(io, arena, .{ .name = bench_name, .exes = &.{exe}, .abs = abs, .filters = filters, .rounds = rounds }, &ctx, once, &ws, w);
    try w.print("reference: libsodium {s}\nworst ours/libsodium = {d:.3} (best {d:.3}); worst ours/fastest (X25519 rows) = {d:.3}\n", .{ std.mem.trimEnd(u8, s.banner, "\n"), s.worst_ref, s.best_ref, s.worst_fast orelse 0 });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× libsodium <version> · fastest {d:.2}× OpenSSL <version> (X25519 rows) (measured <today>)\n", .{ s.best_ref, s.worst_ref, s.worst_fast orelse 0 });
    try w.flush();
    return 0;
}
