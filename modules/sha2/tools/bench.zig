// SPDX-License-Identifier: MIT

//! Comparative benchmark: `sha2` against OpenSSL's EVP digests (the
//! reference), the program behind the `**Performance:**` line of the maturity
//! card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-sha2` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `zig` on PATH (it
//! builds `tools/c_bench/foreign_bench.c` with `zig cc -O3 -march=native`) and
//! the system OpenSSL 3 (`libcrypto.so.3`, path below or `LIBCRYPTO_SO`; no
//! headers needed). Run from the repository root.
//!
//! Workloads, one-shot per op: `sha256_N`, `sha384_N`, `sha512_N` over N = 64,
//! 256, 1024, 16384, 1048576 bytes, plus `sha224_1024` and `sha512t256_1024` (SHA-512/256)
//! (ours: `H.hash`, theirs: `EVP_Digest` with the `EVP_MD` looked up once, so
//! an op costs the hash and OpenSSL's context handling, not a lookup). HMAC,
//! the JWT HS256 shape: `hmac_sha256_256`, `hmac_sha384_256`,
//! `hmac_sha512_256` -- a 256-byte message under a 32 / 48 / 64-byte key, the
//! key set up on every op on both sides (ours:
//! `std.crypto.auth.hmac.Hmac(sha2.H).create`, theirs: the one-shot `HMAC()`).
//! Inputs are written into `.zig-cache/bench-sha2/` from a fixed seed.
//! `sha2.Sha256T192` and the `Sha512T*` truncations have no OpenSSL twin and
//! are not timed. `std.crypto.hash.sha2` is not timed either: `testkit.bench`
//! has no third in-process side, and adding one is not this program's job.
//!
//! Method (`testkit.bench`): each side doubles its batch until it
//! takes over 100 ms and keeps the best of five; per workload the sides
//! alternate for `BENCH_ROUNDS` (default 3) rounds, each keeping its best; the
//! spread printed is (worst round − best round) / best round per side. Ratios
//! are ours/theirs by user-mode cycles when both sides count them (they do not
//! move with the clock), else by wall time. Before timing anything OpenSSL's
//! digest and HMAC of every workload must equal ours byte for byte. Arguments
//! filter workloads by substring (no card line then).
//!
//! The card's numbers come from a JCC-mitigated build (the Kaby Lake erratum,
//! `modules/sort/tools/README.md`), two-stage because Zig has no `-mllvm`
//! passthrough. sha2's module assembly leaves AT&T syntax in force (see
//! `src/root.zig`), so Intel is restated after its end marker:
//!
//!     OPT=$(ls .zig-cache/o/*/options.zig | head -1)
//!     zig build-exe -OReleaseFast -fllvm --dep sha2 --dep testkit -Mroot=modules/sha2/tools/bench.zig \
//!       -OReleaseFast -Msha2=modules/sha2/src/root.zig \
//!       -OReleaseFast --dep zl_options -Mtestkit=modules/testkit/src/root.zig -Mzl_options=$OPT \
//!       --cache-dir .zig-cache -fno-emit-bin -femit-asm=.zig-cache/jcc/bench-sha2.s --name bench-sha2-jcc
//!     sed -i '/# end of zl_sha2 assembly/a .intel_syntax noprefix' .zig-cache/jcc/bench-sha2.s
//!     zig build-exe -OReleaseFast -cflags -mbranches-within-32B-boundaries -- .zig-cache/jcc/bench-sha2.s \
//!       --cache-dir .zig-cache -femit-bin=.zig-cache/jcc/bench-sha2-jcc
//!     BENCH_ROUNDS=5 .zig-cache/jcc/bench-sha2-jcc

const std = @import("std");
const bench = @import("testkit").bench;
const Work = bench.Work(Op);
const sha2 = @import("sha2");
const Hmac = std.crypto.auth.hmac.Hmac;

const bench_name = "bench-sha2";
const work_dir = ".zig-cache/bench-sha2";
const default_so = "/usr/lib/x86_64-linux-gnu/libcrypto.so.3";
const max_len = 1 << 20;
const hmac_len = 256;

const Alg = enum { sha224, sha256, sha384, sha512, sha512t256 };

const Op = struct { alg: Alg = .sha256, hmac: bool = false, len: usize = 0 };

const Ctx = struct {
    msg: *[max_len]u8,
    key: [64]u8,
    out: [64]u8 = undefined,
    op: Op = .{},
};

fn digestLen(alg: Alg) usize {
    return switch (alg) {
        inline else => |a| hashType(a).digest_length,
    };
}

fn hashType(comptime alg: Alg) type {
    return switch (alg) {
        .sha224 => sha2.Sha224,
        .sha256 => sha2.Sha256,
        .sha384 => sha2.Sha384,
        .sha512 => sha2.Sha512,
        .sha512t256 => sha2.Sha512_256,
    };
}

fn once(x: *Ctx) usize {
    const op = x.op;
    switch (op.alg) {
        inline else => |a| {
            const H = hashType(a);
            if (op.hmac) {
                const M = Hmac(H);
                M.create(x.out[0..M.mac_length], x.msg[0..op.len], x.key[0..H.digest_length]);
            } else {
                H.hash(x.msg[0..op.len], x.out[0..H.digest_length], .{});
            }
        },
    }
    std.mem.doNotOptimizeAway(&x.out);
    return digestLen(op.alg);
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

    var prng = std.Random.DefaultPrng.init(0x5a2_256_c0de);
    const r = prng.random();
    var ctx: Ctx = .{ .msg = try arena.create([max_len]u8), .key = undefined };
    r.bytes(&ctx.key);
    r.bytes(ctx.msg);
    try dir.writeFile(io, .{ .sub_path = "key64.bin", .data = &ctx.key });
    try dir.writeFile(io, .{ .sub_path = "msg.bin", .data = ctx.msg });

    var ws: std.ArrayList(Work) = .empty;
    for ([_]Alg{ .sha256, .sha384, .sha512 }) |alg| {
        for ([_]usize{ 64, 256, 1024, 16384, 1048576 }) |n|
            try ws.append(arena, try work(arena, @tagName(alg), .{ .alg = alg, .len = n }, n));
    }
    try ws.append(arena, try work(arena, "sha224", .{ .alg = .sha224, .len = 1024 }, 1024));
    try ws.append(arena, try work(arena, "sha512t256", .{ .alg = .sha512t256, .len = 1024 }, 1024));
    for ([_]Alg{ .sha256, .sha384, .sha512 }) |alg|
        try ws.append(arena, try work(arena, try arena.print("hmac_{s}", .{@tagName(alg)}), .{ .alg = alg, .hmac = true, .len = hmac_len }, hmac_len));

    const so = init.environ_map.get("LIBCRYPTO_SO") orelse default_so;
    const exe = try bench.buildForeign(arena, io, bench_name, &.{ "zig", "cc" }, abs, "modules/sha2/tools/c_bench/foreign_bench.c", &.{so});

    // Interop before timing: every workload's output, OpenSSL against ours.
    try bench.foreignOnce(arena, io, bench_name, exe, abs, "interop");
    for (ws.items) |wk| {
        const file = try arena.print("ossl_{s}.bin", .{wk.name});
        const theirs = try dir.readFileAlloc(io, file, arena, .limited(1 << 10));
        ctx.op = wk.op;
        const n = once(&ctx);
        if (!std.mem.eql(u8, theirs, ctx.out[0..n])) {
            std.debug.print("bench-sha2: FAILED -- OpenSSL's {s} differs from ours\n", .{wk.name});
            return 1;
        }
    }

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = try bench.drive(io, arena, .{ .name = bench_name, .exes = &.{exe}, .abs = abs, .filters = filters, .rounds = rounds }, &ctx, once, ws.items, w);
    try w.print("reference: {s}\nworst ours/OpenSSL = {d:.3} (best {d:.3})\n", .{ std.mem.trimEnd(u8, s.banner, "\n"), s.worst_ref, s.best_ref });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× OpenSSL <version> EVP SHA-2 · fastest ? (measured <today>)\n", .{ s.best_ref, s.worst_ref });
    try w.flush();
    return 0;
}

/// A workload `<base>` (`sha256` -> `sha256_64`; an `hmac_*` base gets its
/// message length too), named the same in the C program.
fn work(arena: std.mem.Allocator, base: []const u8, op: Op, n: usize) !Work {
    const name = try arena.print("{s}_{d}", .{ base, n });
    return .{ .name = name, .op = op, .ref = name };
}
