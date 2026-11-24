// SPDX-License-Identifier: MIT

//! Comparative benchmark for `poseidon` (the program behind the card's
//! `**Performance:**` line). THIS IS A PROGRAM, NOT A TEST: `zig build
//! bench-poseidon` runs it (ReleaseFast); run it under `hw run`.
//!
//! Foreign sides: light-poseidon 0.4.0 (Apache-2.0; circom-compatible Poseidon
//! over BN254, the reference for `poseidon.bn254`) and neptune 14.0.0 (git
//! b06f03c5; Filecoin's Poseidon over BLS12-381, built on blst's C and assembly,
//! the reference for `poseidon.neptune`). Both are built from source by
//! `cargo build --release --offline --locked` in tools/oracle after the crate
//! sources were fetched and reviewed (SPEC.md, Performance); `Cargo.lock` pins
//! every transitive crate and the build is the crate's own `target/`.
//!
//! One op = a chain of 16 hashes, `acc = H(acc, c_1 .. c_{k-1})` with the fixed
//! small constants `c = 1, 2, 3, ...` (`k` = number of inputs), so a hash waits
//! for the one before it and nothing overlaps. Per op both sides do the same
//! work and must end on the same digest (count = its low 64 bits):
//!   bn254_t3 / bn254_t5   2 / 4 inputs, circom parameters (t = 3 / 5)
//!   neptune_a2 / _a4 / _a8   2 / 4 / 8 inputs, Merkle tag, standard strength
//! Not the same: the reference's per-hash setup differs (neptune re-fills a
//! `Poseidon` buffer and runs its preprocessed sparse-matrix schedule;
//! light-poseidon allocates a result vector); ours runs the optimised partial-round schedule
//! of `permute`, as neptune does. Instance construction (the Grain derivation) is not timed on any
//! side. Wall time only (the foreign side counts no cycles). Ratios are
//! ours/reference.

const std = @import("std");
const bench = @import("benchkit");
const poseidon = @import("poseidon");

const bench_name = "bench-poseidon";
const work_dir = ".zig-cache/bench-poseidon";
const oracle = "modules/poseidon/tools/oracle/target/release/poseidon-oracle";
const chain = 16;

const Op = enum { bn254_t3, bn254_t5, neptune_a2, neptune_a4, neptune_a8 };

const Bn = poseidon.bn254;
const Np = poseidon.neptune;

const Ctx = struct {
    op: Op = .bn254_t3,
    b3: Bn.Perm(3) = undefined,
    b5: Bn.Perm(5) = undefined,
    n2: Np.Hasher(2, .standard) = undefined,
    n4: Np.Hasher(4, .standard) = undefined,
    n8: Np.Hasher(8, .standard) = undefined,
};

fn low64(be: [32]u8) u64 {
    return std.mem.readInt(u64, be[24..32], .big);
}

fn bnChain(comptime k: usize, p: anytype) u64 {
    var acc = Bn.fromU64(0);
    for (0..chain) |i| {
        var pre: [k]Bn.Fr = undefined;
        pre[0] = acc;
        for (1..k) |j| pre[j] = Bn.fromU64(i * k + j + 1);
        acc = p.hash(pre);
    }
    return low64(acc.toBytes());
}

fn npChain(comptime k: usize, h: anytype) u64 {
    var acc = Np.Fr.zero;
    for (0..chain) |i| {
        var pre: [k]Np.Fr = undefined;
        pre[0] = acc;
        for (1..k) |j| pre[j] = fromU64(i * k + j + 1);
        acc = h.merkle(pre);
    }
    return low64(acc.toBytes());
}

fn fromU64(v: u64) Np.Fr {
    var be: [32]u8 = @splat(0);
    std.mem.writeInt(u64, be[24..32], v, .big);
    return Np.Fr.fromBytes(be) catch unreachable;
}

fn once(c: *Ctx) u64 {
    return switch (c.op) {
        .bn254_t3 => bnChain(2, &c.b3),
        .bn254_t5 => bnChain(4, &c.b5),
        .neptune_a2 => npChain(2, &c.n2),
        .neptune_a4 => npChain(4, &c.n4),
        .neptune_a8 => npChain(8, &c.n8),
    };
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);
    const args = try init.minimal.args.toSlice(arena);
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 5;

    const ctx = try arena.create(Ctx);
    ctx.* = .{};
    ctx.b3 = Bn.Perm(3).init();
    ctx.b5 = Bn.Perm(5).init();
    ctx.n2 = Np.Hasher(2, .standard).init();
    ctx.n4 = Np.Hasher(4, .standard).init();
    ctx.n8 = Np.Hasher(8, .standard).init();
    const exe = try cwd.realPathFileAlloc(io, oracle, arena);

    const W = bench.Work(Op);
    const ws = [_]W{
        .{ .name = "bn254_t3", .op = .bn254_t3, .ref = "bn254_t3", .wall_only = true },
        .{ .name = "bn254_t5", .op = .bn254_t5, .ref = "bn254_t5", .wall_only = true },
        .{ .name = "neptune_a2", .op = .neptune_a2, .ref = "neptune_a2", .wall_only = true },
        .{ .name = "neptune_a4", .op = .neptune_a4, .ref = "neptune_a4", .wall_only = true },
        .{ .name = "neptune_a8", .op = .neptune_a8, .ref = "neptune_a8", .wall_only = true },
    };
    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = bench.drive(io, arena, .{
        .name = bench_name,
        .exes = &.{exe},
        .abs = abs,
        .filters = if (args.len > 1) args[1..] else &.{},
        .rounds = rounds,
    }, ctx, once, ws, w) catch |e| switch (e) {
        error.CountMismatch => return 1,
        else => return e,
    };
    try w.print("\nworst ours/reference = {d:.2} (best {d:.2})\n", .{ s.worst_ref, s.best_ref });
    try w.flush();
    return 0;
}
