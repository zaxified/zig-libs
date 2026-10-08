// SPDX-License-Identifier: MIT

//! Comparative benchmark: `hqc` against the HQC v5.0.0 authors' code in two
//! lanes, the program behind the `**Performance:**` line of the maturity card
//! (CONVENTIONS.md §9, kept instrument kind 3):
//!   * `ref`    -- `src/ref`, the portable reference (the card's "ref" column);
//!   * `avx256` -- `src/x86_64/avx256` built with `-mavx -mavx2 -mbmi -mpclmul`,
//!     the authors' fastest lane (the card's "fastest" column).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-hqc` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `zig` on PATH
//! (it compiles `tools/c_bench/hqc_bench.c` plus the reference's `.c` files
//! with `zig cc -O3`, once per parameter set and lane; the reference's cmake is
//! never run) and the HQC v5.0.0 source tree (dir below or `HQC_SRC`; if it is
//! missing the program prints the fetch recipe and exits 2). Run from the
//! repository root.
//!
//! Workloads: keygen, encaps and decaps for hqc-1/3/5 (= Hqc128/192/256). The
//! reference PRNG and ours are seeded from one fixed 48-byte seed written to
//! `.zig-cache/bench-hqc/`. Both sides double the batch until it takes over
//! 100 ms and keep the best of five. Before timing anything, the pk/sk/ct/ss the
//! reference produced from that seed (both lanes) must equal ours byte for byte,
//! and ours must decapsulate the reference's ciphertext to the same secret.

const std = @import("std");
const hqc = @import("hqc");

const work_dir = ".zig-cache/bench-hqc";
const default_src = ".zig-cache/foreign/hqc/hqc-v5.0.0";
const recipe =
    \\bench-hqc: HQC v5.0.0 sources not found at {s}
    \\  fetch (and review before compiling) into one directory:
    \\    https://gitlab.com/pqc-hqc/hqc/-/archive/v5.0.0/hqc-v5.0.0.tar.gz
    \\  expected sha256 of the tarball:
    \\    f5b1653fcbb0c15801573b059aa421255679b865b8c6c8dc464d8388bedfc3df
    \\  extract it, then: HQC_SRC=<dir>/hqc-v5.0.0 zig build bench-hqc
    \\
;

const seed_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";

const Row = struct { ns: f64, count: u64 };

fn timeIt(io: std.Io, ctx: anytype, comptime f: fn (@TypeOf(ctx)) usize) Row {
    var n: usize = 1;
    while (true) {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| std.mem.doNotOptimizeAway(f(ctx));
        if (t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds > 100_000_000) break;
        n *= 2;
    }
    var best: i96 = std.math.maxInt(i96);
    var count: usize = 0;
    for (0..5) |_| {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| count = f(ctx);
        best = @min(best, t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds);
    }
    return .{ .ns = @as(f64, @floatFromInt(best)) / @as(f64, @floatFromInt(n)), .count = count };
}

fn Ours(comptime Kem: type) type {
    return struct {
        const Ctx = struct { seed: *const [32]u8, coins: *const [Kem.coins_bytes]u8, kp: *const Kem.KeyPair, ct: *const Kem.Ciphertext };
        fn keygen(c: Ctx) usize {
            const r = keypairV(Kem, c.seed);
            std.mem.doNotOptimizeAway(&r);
            return r.ek.len;
        }
        fn encaps(c: Ctx) usize {
            const r = encapsV(Kem, c.kp.ek, c.coins);
            std.mem.doNotOptimizeAway(&r);
            return r.ct.len;
        }
        fn decaps(c: Ctx) usize {
            const r = decapsV(Kem, c.kp.dk, c.ct.*);
            std.mem.doNotOptimizeAway(&r);
            return r.len;
        }
    };
}

const Lane = struct { name: []const u8, avx: bool };
const lanes = [_]Lane{ .{ .name = "ref", .avx = false }, .{ .name = "avx256", .avx = true } };

const sources_common = [_][]const u8{ "src/common/code.c", "src/common/crypto_memset.c", "src/common/fft.c", "src/common/kem.c", "src/common/symmetric.c", "lib/fips202/fips202.c" };
const sources_ref = [_][]const u8{ "src/ref/gf.c", "src/ref/gf2x.c", "src/ref/hqc.c", "src/ref/parsing.c", "src/ref/reed_muller.c", "src/ref/reed_solomon.c", "src/ref/vector.c" };
const sources_avx = [_][]const u8{ "src/x86_64/common/hqc.c", "src/x86_64/common/parsing.c", "src/x86_64/avx256/gf.c", "src/x86_64/avx256/reed_muller.c", "src/x86_64/avx256/vector.c" };

/// Builds the C side for one (variant, lane), runs it and stores its timing rows
/// under `<tag>_<workload>`.
fn buildAndRun(arena: std.mem.Allocator, io: std.Io, src: []const u8, abs: []const u8, v: u8, lane: Lane, tag: []const u8, rows: *std.StringHashMapUnmanaged(Row)) !void {
    const exe = try std.fmt.allocPrint(arena, "{s}/hqc_bench_{s}", .{ abs, tag });
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(arena, &.{ "zig", "cc", "-std=c99", "-O3", "-funroll-loops", "-w" });
    if (lane.avx) {
        try argv.appendSlice(arena, &.{ "-mavx", "-mavx2", "-mbmi", "-mpclmul", "-DHQC_ARCH_X86_64=1", "-DHQC_ARCH_X86_64_AVX256=1" });
    } else {
        try argv.append(arena, "-DHQC_ARCH_REF=1");
    }
    const var_dirs = if (lane.avx)
        [_][]const u8{ "src/common", "src/common/hqc-{d}", "src/x86_64/common", "src/x86_64/common/hqc-{d}", "src/x86_64/avx256", "src/x86_64/avx256/hqc-{d}", "lib/fips202" }
    else
        [_][]const u8{ "src/common", "src/common/hqc-{d}", "src/ref", "src/ref/hqc-{d}", "lib/fips202", "", "" };
    for (var_dirs) |d| {
        if (d.len == 0) continue;
        const rel = try std.mem.replaceOwned(u8, arena, d, "{d}", &.{'0' + v});
        try argv.append(arena, try std.fmt.allocPrint(arena, "-I{s}/{s}", .{ src, rel }));
    }
    try argv.append(arena, "modules/hqc/tools/c_bench/hqc_bench.c");
    for (sources_common) |s| try argv.append(arena, try std.fmt.allocPrint(arena, "{s}/{s}", .{ src, s }));
    for (if (lane.avx) &sources_avx else &sources_ref) |s| try argv.append(arena, try std.fmt.allocPrint(arena, "{s}/{s}", .{ src, s }));
    // Variant-specific sources (only the avx lane has any: reed_solomon.c, gf2x.c).
    if (lane.avx) {
        try argv.append(arena, try std.fmt.allocPrint(arena, "{s}/src/x86_64/avx256/hqc-{d}/reed_solomon.c", .{ src, v }));
        try argv.append(arena, try std.fmt.allocPrint(arena, "{s}/src/x86_64/common/hqc-{d}/gf2x.c", .{ src, v }));
    }
    try argv.appendSlice(arena, &.{ "-o", exe });
    const cc = try std.process.run(arena, io, .{ .argv = argv.items });
    if (cc.term != .exited or cc.term.exited != 0) {
        std.debug.print("bench-hqc: zig cc failed for {s}:\n{s}\n", .{ tag, cc.stderr });
        return error.CcFailed;
    }
    const res = try std.process.run(arena, io, .{ .argv = &.{ exe, abs, seed_hex, tag } });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("bench-hqc: reference side {s} failed:\n{s}\n", .{ tag, res.stderr });
        return error.RefFailed;
    }
    var lines = std.mem.tokenizeScalar(u8, res.stdout, '\n');
    while (lines.next()) |line| {
        var f = std.mem.tokenizeScalar(u8, line, '\t');
        const name = f.next() orelse continue;
        const ns = try std.fmt.parseFloat(f64, f.next() orelse return error.BadForeignOutput);
        const count = try std.fmt.parseInt(u64, f.next() orelse return error.BadForeignOutput, 10);
        try rows.put(arena, try std.fmt.allocPrint(arena, "{s}_{s}", .{ tag, name }), .{ .ns = ns, .count = count });
    }
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();

    const cwd = std.Io.Dir.cwd();
    const src = init.environ_map.get("HQC_SRC") orelse default_src;
    cwd.access(io, src, .{}) catch {
        std.debug.print(recipe, .{src});
        return 2;
    };
    const src_abs = try cwd.realPathFileAlloc(io, src, arena);
    try cwd.createDirPath(io, work_dir);
    var dir = try cwd.openDir(io, work_dir, .{});
    defer dir.close(io);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);

    var seed: [48]u8 = undefined;
    _ = try std.fmt.hexToBytes(&seed, seed_hex);

    var rows: std.StringHashMapUnmanaged(Row) = .empty;
    const variants = [_]struct { v: u8, label: []const u8, Kem: type }{
        .{ .v = 1, .label = "hqc-1", .Kem = hqc.Hqc128 },
        .{ .v = 3, .label = "hqc-3", .Kem = hqc.Hqc192 },
        .{ .v = 5, .label = "hqc-5", .Kem = hqc.Hqc256 },
    };
    std.debug.print("bench-hqc: building the reference side (3 parameter sets x 2 lanes) from {s} ...\n", .{src});
    inline for (variants) |vr| {
        inline for (lanes) |lane| {
            const tag = vr.label ++ "_" ++ lane.name;
            try buildAndRun(arena, io, src_abs, abs, vr.v, lane, tag, &rows);
        }
    }

    // Interop before timing: same seed -> identical pk/sk/ct/ss, both lanes.
    inline for (variants) |vr| {
        const Kem = vr.Kem;
        var prng = hqc.prng.Prng.init(&seed, &.{});
        var seed_kem: [32]u8 = undefined;
        prng.getBytes(&seed_kem);
        const kp = keypairV(Kem, &seed_kem);
        var coins: [Kem.coins_bytes]u8 = undefined;
        prng.getBytes(&coins);
        const enc = encapsV(Kem, kp.ek, &coins);
        inline for (lanes) |lane| {
            const tag = vr.label ++ "_" ++ lane.name;
            const pk = try dir.readFileAlloc(io, tag ++ ".pk", arena, .limited(1 << 16));
            const sk = try dir.readFileAlloc(io, tag ++ ".sk", arena, .limited(1 << 16));
            const ct = try dir.readFileAlloc(io, tag ++ ".ct", arena, .limited(1 << 16));
            const ss = try dir.readFileAlloc(io, tag ++ ".ss", arena, .limited(1 << 16));
            const ok = std.mem.eql(u8, pk, &kp.ek) and std.mem.eql(u8, sk, &kp.dk) and
                std.mem.eql(u8, ct, &enc.ct) and std.mem.eql(u8, ss, &enc.ss);
            if (!ok) {
                std.debug.print("bench-hqc: FAILED -- {s}: pk/sk/ct/ss from the reference differ from ours\n", .{tag});
                return 1;
            }
            if (ct.len != Kem.ct_bytes) return 1;
            const dec = decapsV(Kem, kp.dk, ct[0..Kem.ct_bytes].*);
            if (!std.mem.eql(u8, &dec, ss)) {
                std.debug.print("bench-hqc: FAILED -- {s}: we decapsulate the reference's ciphertext to a different secret\n", .{tag});
                return 1;
            }
        }
    }

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.print("interop: pk/sk/ct/ss equal (ours, ref lane, avx256 lane) for hqc-1/3/5; ours decapsulates the reference ct\n", .{});
    try w.print("{s:<13} {s:>12} {s:>12} {s:>12} {s:>9} {s:>9}  bytes\n", .{ "workload", "ours ns", "ref ns", "avx256 ns", "ours/ref", "ours/avx" });
    var worst: f64 = 0;
    var best: f64 = std.math.inf(f64);
    var worst_a: f64 = 0;
    var best_a: f64 = std.math.inf(f64);
    var mismatch = false;
    inline for (variants) |vr| {
        const Kem = vr.Kem;
        var prng = hqc.prng.Prng.init(&seed, &.{});
        var seed_kem: [32]u8 = undefined;
        prng.getBytes(&seed_kem);
        const kp = keypairV(Kem, &seed_kem);
        var coins: [Kem.coins_bytes]u8 = undefined;
        prng.getBytes(&coins);
        const enc = encapsV(Kem, kp.ek, &coins);
        const O = Ours(Kem);
        const ctx: O.Ctx = .{ .seed = &seed_kem, .coins = &coins, .kp = &kp, .ct = &enc.ct };
        inline for (.{ "keygen", "encaps", "decaps" }) |wl| {
            const ours = switch (comptime std.meta.stringToEnum(enum { keygen, encaps, decaps }, wl).?) {
                .keygen => timeIt(io, ctx, O.keygen),
                .encaps => timeIt(io, ctx, O.encaps),
                .decaps => timeIt(io, ctx, O.decaps),
            };
            const r = rows.get(vr.label ++ "_ref_" ++ wl) orelse return error.MissingRow;
            const a = rows.get(vr.label ++ "_avx256_" ++ wl) orelse return error.MissingRow;
            const ratio = ours.ns / r.ns;
            const ratio_a = ours.ns / a.ns;
            worst = @max(worst, ratio);
            best = @min(best, ratio);
            worst_a = @max(worst_a, ratio_a);
            best_a = @min(best_a, ratio_a);
            const same = ours.count == r.count and ours.count == a.count;
            if (!same) mismatch = true;
            try w.print("{s:<13} {d:>12.0} {d:>12.0} {d:>12.0} {d:>9.2} {d:>9.2}  {d}{s}\n", .{ vr.label ++ "_" ++ wl, ours.ns, r.ns, a.ns, ratio, ratio_a, ours.count, if (same) "" else " ≠" });
            try w.flush();
        }
    }
    if (mismatch) return 1;
    try w.print("\nours/ref: worst {d:.2}, best {d:.2}; ours/avx256: worst {d:.2}, best {d:.2}\n", .{ worst, best, worst_a, best_a });
    try w.print("card: **Performance:** ref {d:.2}–{d:.2}× HQC v5.0.0 `ref` lane · fastest {d:.2}–{d:.2}× HQC v5.0.0 `x86_64/avx256` lane (measured 2026-10-07)\n", .{ best, worst, best_a, worst_a });
    try w.flush();
    return 0;
}

// Value-returning wrappers over the pointer/out-param KEM API, for tests and
// benchmarks that compare values; library callers use the real API.
fn keypairV(comptime K: type, seed: *const [32]u8) K.KeyPair {
    var kp: K.KeyPair = undefined;
    K.keypair(&kp, seed);
    return kp;
}
fn encapsV(comptime K: type, ek: K.EncapsKey, coins: *const [K.coins_bytes]u8) struct { ct: K.Ciphertext, ss: K.SharedSecret } {
    var r: struct { ct: K.Ciphertext, ss: K.SharedSecret } = undefined;
    K.encaps(&r.ct, &r.ss, &ek, coins);
    return .{ .ct = r.ct, .ss = r.ss };
}
fn decapsV(comptime K: type, dk: K.DecapsKey, ct: K.Ciphertext) K.SharedSecret {
    var ss: K.SharedSecret = undefined;
    K.decaps(&ss, &dk, &ct);
    return ss;
}
