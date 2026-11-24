// SPDX-License-Identifier: MIT

//! Comparative benchmark: `bn254`'s pairing against gnark-crypto v0.19.2
//! `ecc/bn254` (Go; the toolkit the SPEC's *Compared with* names, with
//! amd64 assembly field arithmetic), the program behind the `**Performance:**`
//! line of the maturity card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-bn254` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `zig` and `go`
//! (1.26.x) on PATH and gnark-crypto v0.19.2, bits-and-blooms/bitset v1.24.4
//! and golang.org/x/sys v0.50.0 in the Go module cache (`GOPROXY=off`:
//! nothing is downloaded; if they are missing the program prints the recipe
//! and exits 1). Run from the repository root.
//!
//! Inputs, both sides: P = [a]G1, Q = [b]G2 from the standard generators,
//! a and b fixed below (passed to Go in decimal), and R = −[ab]G1.
//! Workloads:
//!   pairing_1  e(P, Q), final exponentiation included
//!   check_2    the ecPairing shape: e(P, Q)·e(R, G2) == 1 (true)
//!   miller_2   the two-pair Miller loop alone (no final exponentiation)
//! Before timing, the sides must agree on the check's verdict. The reduced
//! pairing values are NOT compared: gnark's final exponentiation returns a
//! fixed power of the canonical pairing (the Fuentes-Castañeda et al. hard
//! part, per its own doc comment), this module the canonical value (py_ecc's,
//! pinned by its KATs). Both double the batch until it takes over 100 ms and
//! keep the best of five.

const std = @import("std");
const bn254 = @import("bn254");

const a_scalar: u64 = 0x1234_5678_90ab_cdef;
const b_scalar: u64 = 0x0fed_cba9_8765_4321;

const recipe =
    \\bench-bn254: Go or gnark-crypto v0.19.2 not usable (see the error above)
    \\  needs go 1.26.x and github.com/consensys/gnark-crypto@v0.19.2 (+ bitset v1.24.4, x/sys v0.50.0) in
    \\  the Go module cache (offline, GOPROXY=off). Fetch (and review) them once with a network:
    \\    (cd modules/bn254/tools/go_bench && GOFLAGS=-mod=mod go mod download)
    \\  expected go.sum lines are committed in modules/bn254/tools/go_bench/go.sum.
    \\
;

const Row = struct { ns: f64, check: u64 };

fn be32(v: u128) [32]u8 {
    var out: [32]u8 = @splat(0);
    std.mem.writeInt(u128, out[16..32], v, .big);
    return out;
}

const Inputs = struct {
    p: bn254.g1.Affine,
    q: bn254.g2.Affine,
    r: bn254.g1.Affine,
    g2: bn254.g2.Affine,
};

fn timeIt(io: std.Io, in: *const Inputs, comptime f: fn (*const Inputs) void) f64 {
    var n: usize = 1;
    while (true) {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| f(in);
        if (t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds > 100_000_000) break;
        n *= 2;
    }
    var best: i96 = std.math.maxInt(i96);
    for (0..5) |_| {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| f(in);
        best = @min(best, t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds);
    }
    return @as(f64, @floatFromInt(best)) / @as(f64, @floatFromInt(n));
}

const W = struct {
    fn pairing1(in: *const Inputs) void {
        std.mem.doNotOptimizeAway(bn254.pairing.pairing(in.p, in.q));
    }
    fn check2(in: *const Inputs) void {
        std.mem.doNotOptimizeAway(bn254.pairing.pairingCheck(&.{ .{ .p = in.p, .q = in.q }, .{ .p = in.r, .q = in.g2 } }));
    }
    fn miller2(in: *const Inputs) void {
        std.mem.doNotOptimizeAway(bn254.pairing.multiMillerLoop(&.{ .{ .p = in.p, .q = in.q }, .{ .p = in.r, .q = in.g2 } }));
    }
};

fn foreign(arena: std.mem.Allocator, io: std.Io, env: *const std.process.Environ.Map, argv: []const []const u8, cwd: []const u8) !std.StringHashMapUnmanaged(Row) {
    const res = try std.process.run(arena, io, .{ .argv = argv, .environ_map = env, .cwd = .{ .path = cwd } });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("bench-bn254: {s} failed:\n{s}\n", .{ argv[0], res.stderr });
        return error.ForeignSideFailed;
    }
    var rows: std.StringHashMapUnmanaged(Row) = .empty;
    var lines = std.mem.tokenizeScalar(u8, res.stdout, '\n');
    while (lines.next()) |line| {
        var f = std.mem.tokenizeScalar(u8, line, '\t');
        const name = f.next() orelse continue;
        const ns = try std.fmt.parseFloat(f64, f.next() orelse return error.BadForeignOutput);
        const check = try std.fmt.parseInt(u64, f.next() orelse return error.BadForeignOutput, 10);
        try rows.put(arena, name, .{ .ns = ns, .check = check });
    }
    return rows;
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();

    const g1gen = bn254.g1.Jacobian.fromAffine(bn254.g1.Affine.generator);
    const g2gen = bn254.g2.Jacobian.fromAffine(bn254.g2.Affine.generator);
    const ab = @as(u128, a_scalar) * b_scalar;
    const in: Inputs = .{
        .p = g1gen.scalarMulBytes(&be32(a_scalar)).toAffine(),
        .q = g2gen.scalarMulBytes(&be32(b_scalar)).toAffine(),
        .r = g1gen.scalarMulBytes(&be32(ab)).negate().toAffine(),
        .g2 = bn254.g2.Affine.generator,
    };
    const ours_check: u64 = @intFromBool(bn254.pairing.pairingCheck(&.{ .{ .p = in.p, .q = in.q }, .{ .p = in.r, .q = in.g2 } }));

    var env = try init.environ_map.clone(arena);
    try env.put("GOTOOLCHAIN", "local");
    try env.put("GOPROXY", "off");
    try env.put("GOFLAGS", "-mod=readonly");
    std.debug.print("bench-bn254: gnark-crypto v0.19.2 ...\n", .{});
    const a_dec = try std.fmt.allocPrint(arena, "{d}", .{a_scalar});
    const b_dec = try std.fmt.allocPrint(arena, "{d}", .{b_scalar});
    const go = foreign(arena, io, &env, &.{ "go", "run", ".", a_dec, b_dec }, "modules/bn254/tools/go_bench") catch {
        std.debug.print("{s}", .{recipe});
        return 1;
    };

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const names = [_][]const u8{ "pairing_1", "check_2", "miller_2" };
    const fns = .{ W.pairing1, W.check2, W.miller2 };
    const ours_checks = [_]?u64{ null, ours_check, null };
    try w.print("{s:<10} {s:>12} {s:>12} {s:>8}\n", .{ "workload", "ours ns/op", "gnark ns/op", "ours/ref" });
    var worst: f64 = 0;
    var best: f64 = std.math.inf(f64);
    var mismatch = false;
    inline for (names, fns, ours_checks) |name, f, oc| {
        const g = go.get(name) orelse return error.MissingRow;
        if (oc) |c| {
            if (c != g.check) mismatch = true;
        }
        const ns = timeIt(io, &in, f);
        const r = ns / g.ns;
        worst = @max(worst, r);
        best = @min(best, r);
        try w.print("{s:<10} {d:>12.1} {d:>12.1} {d:>8.2}{s}\n", .{ name, ns, g.ns, r, if (oc != null and oc.? != g.check) "  ≠ check" else "" });
        try w.flush();
    }
    if (mismatch) {
        try w.writeAll("bench-bn254: FAILED -- the sides disagree on a check value\n");
        try w.flush();
        return 1;
    }
    try w.print("\nworst ours/gnark = {d:.2} (best {d:.2})\n", .{ worst, best });
    try w.print("card: **Performance:** ref {d:.2}–{d:.2}× gnark-crypto v0.19.2 · fastest ? (measured <today>)\n", .{ best, worst });
    try w.flush();
    return 0;
}
