// SPDX-License-Identifier: MIT

//! Comparative benchmark: `montint` against OpenSSL's BN Montgomery
//! arithmetic (the reference; the maturity card names OpenSSL BN as the speed
//! yardstick), the program behind the `**Performance:**` line of the card
//! (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-montint` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `zig` on PATH (it
//! builds `tools/c_bench/foreign_bench.c` with `zig cc -O3 -march=native`) and
//! the system OpenSSL 3 (`libcrypto.so.3`, path below or `LIBCRYPTO_SO`; no
//! headers needed). Run from the repository root.
//!
//! Workloads, per modulus size (a random odd modulus with its top bit set;
//! operands `a`, `b` below it; `e` a full-width exponent; all from fixed
//! seeds, written to `.zig-cache/bench-montint/`):
//!   mul_N      one Montgomery multiply with operands already in the Montgomery
//!              domain: ours `Modint(N).montMul`, theirs `BN_mod_mul_montgomery`
//!              (sizes 2048, 3072, 4096)
//!   exp_N      constant-time full-width modular exponentiation (RSA private
//!              key / Paillier shape): ours `Modint(N).powMont`, theirs
//!              `BN_mod_exp_mont_consttime` (1024 ... 4096)
//!   dynexp_N   the same with the run-time-sized `DynModint(N).pow`, the type
//!              `rsa`/`paillier` actually run their secrets on (same reference)
//!   pub_N      public-exponent 65537 power (RSA verify): ours
//!              `DynModint(N).powPublic`, theirs `BN_mod_exp_mont`
//!              (2048, 3072, 4096)
//! 1024 and 1536 are the CRT halves of 2048- and 3072-bit RSA keys, so the
//! exp rows cover an RSA-CRT private operation as well. Both sides build
//! their modulus context once (ours: the `Modint`/`DynModint` value, theirs:
//! the `BN_MONT_CTX`); the result is `N / 8` bytes on both sides.
//!
//! Method (`testkit.bench`): each side doubles its batch until it
//! takes over 100 ms and keeps the best of five; per workload the sides
//! alternate for `BENCH_ROUNDS` (default 3) rounds, each keeping its best; the
//! spread printed is (worst round − best round) / best round per side. Ratios
//! are ours/theirs by user-mode cycles when both sides count them (they do not
//! move with the clock), else by wall time. Before timing anything OpenSSL's
//! result of every operation and size must equal ours byte for byte. Arguments
//! filter workloads by substring (no card line then).

const std = @import("std");
const bench = @import("testkit").bench;
const Work = bench.Work(Op);
const montint = @import("montint");

const bench_name = "bench-montint";
const work_dir = ".zig-cache/bench-montint";
const default_so = "/usr/lib/x86_64-linux-gnu/libcrypto.so.3";
const sizes = [_]comptime_int{ 1024, 1536, 2048, 3072, 4096 };

const Kind = enum { mul, exp, dynexp, pub_exp };
const Op = struct { kind: Kind, size: usize };

fn Case(comptime bits: comptime_int) type {
    return struct {
        const M = montint.Modint(bits);
        const D = montint.DynModint(bits);
        m: M,
        d: D,
        a: M.Elem,
        b: M.Elem,
        e: M.Elem,
        da: D.Elem,
        de: D.Elem,
        out: [bits / 8]u8 = undefined,
        const e65537 = [_]u8{ 1, 0, 1 };

        fn init(modulus: *const [bits / 8]u8, a: *const [bits / 8]u8, b: *const [bits / 8]u8, e: *const [bits / 8]u8) !@This() {
            const m = try M.fromBytesBE(modulus);
            const d = try D.fromBytesBE(modulus);
            return .{
                .m = m,
                .d = d,
                .a = try m.elementFromBytesBE(a),
                .b = try m.elementFromBytesBE(b),
                // the exponent is only required to fit the limbs, not to be < m
                .e = std.mem.zeroes(M.Elem),
                .da = try d.elemFromBytesBE(a),
                .de = try D.loadBE(e),
            };
        }

        fn run(c: *@This(), kind: Kind) usize {
            switch (kind) {
                .mul => {
                    const r = c.m.montMul(&c.a, &c.b);
                    c.m.toBytesBE(&r, &c.out);
                },
                .exp => {
                    const r = c.m.powMont(&c.a, &c.e);
                    c.m.toBytesBE(&r, &c.out);
                },
                .dynexp => {
                    const r = c.d.pow(&c.da, &c.de);
                    c.d.toBytesBE(&r, &c.out);
                },
                .pub_exp => {
                    const r = c.d.powPublic(&c.da, &e65537);
                    c.d.toBytesBE(&r, &c.out);
                },
            }
            std.mem.doNotOptimizeAway(&c.out);
            return bits / 8;
        }
    };
}

const Ctx = struct {
    cases: @Tuple(&blk: {
        var t: [sizes.len]type = undefined;
        for (sizes, 0..) |b, i| t[i] = Case(b);
        break :blk t;
    }),
    op: Op = undefined,
};

fn once(x: *Ctx) usize {
    inline for (sizes, 0..) |b, i| {
        if (x.op.size == b) return x.cases[i].run(x.op.kind);
    }
    unreachable;
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

    var prng = std.Random.DefaultPrng.init(0x30d_17b3_ac01);
    const r = prng.random();
    const ctx = try arena.create(Ctx);
    ctx.op = undefined;
    inline for (sizes, 0..) |bits, i| {
        const n = bits / 8;
        var mb: [n]u8 = undefined;
        var ab: [n]u8 = undefined;
        var bb: [n]u8 = undefined;
        var eb: [n]u8 = undefined;
        r.bytes(&mb);
        r.bytes(&ab);
        r.bytes(&bb);
        r.bytes(&eb);
        mb[0] |= 0x80; // full width
        mb[n - 1] |= 1; // odd
        ab[0] &= 0x7f; // below the modulus
        bb[0] &= 0x7f;
        eb[0] |= 0x80; // full-width exponent
        try dir.writeFile(io, .{ .sub_path = try arena.print("m{d}.bin", .{bits}), .data = &mb });
        try dir.writeFile(io, .{ .sub_path = try arena.print("a{d}.bin", .{bits}), .data = &ab });
        try dir.writeFile(io, .{ .sub_path = try arena.print("b{d}.bin", .{bits}), .data = &bb });
        try dir.writeFile(io, .{ .sub_path = try arena.print("e{d}.bin", .{bits}), .data = &eb });
        ctx.cases[i] = try @TypeOf(ctx.cases[i]).init(&mb, &ab, &bb, &eb);
        // powMont takes an exponent of exactly L limbs (not required < m)
        ctx.cases[i].e = std.mem.zeroes(@TypeOf(ctx.cases[i]).M.Elem);
        for (0..n) |k| ctx.cases[i].e[k / 8] |= @as(u64, eb[n - 1 - k]) << @intCast(8 * (k % 8));
    }

    const so = init.environ_map.get("LIBCRYPTO_SO") orelse default_so;
    const exe = try bench.buildForeign(arena, io, bench_name, &.{ "zig", "cc" }, abs, "modules/montint/tools/c_bench/foreign_bench.c", &.{so});

    // Interop before timing: every operation at every size, byte for byte.
    try bench.foreignOnce(arena, io, bench_name, exe, abs, "interop");
    inline for (sizes, 0..) |bits, i| {
        inline for (.{ .{ "mul", Kind.mul }, .{ "exp", Kind.exp }, .{ "exp", Kind.dynexp }, .{ "pub", Kind.pub_exp } }) |t| {
            const theirs = try dir.readFileAlloc(io, try arena.print("ossl_{s}_{d}.bin", .{ t[0], bits }), arena, .limited(1 << 16));
            _ = ctx.cases[i].run(t[1]);
            if (!std.mem.eql(u8, theirs, &ctx.cases[i].out)) {
                std.debug.print("{s}: FAILED -- OpenSSL's {s} at {d} bits differs from ours ({s})\n", .{ bench_name, t[0], bits, @tagName(t[1]) });
                return 1;
            }
        }
    }

    var ws: std.ArrayList(Work) = .empty;
    inline for (sizes) |bits| {
        const spec = [_]struct { k: Kind, p: []const u8, r: []const u8, on: bool }{
            .{ .k = .mul, .p = "mul", .r = "mul", .on = bits >= 2048 },
            .{ .k = .exp, .p = "exp", .r = "exp", .on = true },
            .{ .k = .dynexp, .p = "dynexp", .r = "exp", .on = true },
            .{ .k = .pub_exp, .p = "pub", .r = "pub", .on = bits >= 2048 },
        };
        for (spec) |s| if (s.on) {
            try ws.append(arena, .{
                .name = try arena.print("{s}_{d}", .{ s.p, bits }),
                .op = .{ .kind = s.k, .size = bits },
                .ref = try arena.print("{s}_{d}", .{ s.r, bits }),
            });
        };
    }

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = try bench.drive(io, arena, .{ .name = bench_name, .exes = &.{exe}, .abs = abs, .filters = filters, .rounds = rounds }, ctx, once, ws.items, w);
    try w.print("reference: {s}\nworst ours/OpenSSL = {d:.3} (best {d:.3})\n", .{ std.mem.trimEnd(u8, s.banner, "\n"), s.worst_ref, s.best_ref });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× OpenSSL <version> BN (Montgomery mul, constant-time and public-exponent modexp) · fastest ? (measured <today>)\n", .{ s.best_ref, s.worst_ref });
    try w.flush();
    return 0;
}
