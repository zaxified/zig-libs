// SPDX-License-Identifier: MIT

//! Cross-check of the MDS subspace-trail checks against an **independent
//! second port** of the same sage source — `testdata/subspace_trail.py`, built
//! on sympy's `DomainMatrix` over `GF(p)`.
//!
//! ## What this is worth, stated up front
//!
//! **Tier 2, not an external anchor.** sage is not installed here, so the
//! oracle is a Python transcription of the *same* `reference_params.sage` text
//! the Zig side was written from. It catches transcription slips — an index
//! off by one, a wrong sub-code, a rejection that fails to advance the stream
//! — and it categorically does **not** catch a shared misreading of the
//! specification: misunderstand `generate_vectorspace` and both ports
//! misunderstand it the same way, and every comparison here still passes. This
//! repository has that distinction written down; see `SPEC.md` §"Anchoring".
//!
//! The grade-1 anchor for this module remains circomlib's and the authors'
//! published constants, which `constants_test.zig` pins.
//!
//! ## Where it IS strong
//!
//! Two things make this more than a rubber stamp:
//!
//!   1. **The inputs are chosen so the checks fail.** Over BN254 a random
//!      matrix passes with probability `1 - 2^-236`, so an oracle fed only
//!      Poseidon-sized inputs would agree with `return true`. Most cases here
//!      are over `p = 101` and `p = 251`, where 19 of the 168 random matrices
//!      in these batches are rejected, and the comparison covers each of them.
//!   2. **It compares the sub-code, not a boolean.** `algorithm_1` returns
//!      `[False, 1|2|3]` plus the round `i` it failed at; all three fields are
//!      compared. Agreeing on "insecure" is weak; agreeing on "insecure,
//!      code 3, at i = 2" is not.
//!
//! The Python side also deliberately takes different routes to the same
//! quantities (canonical RREF bases vs rank-plus-containment, double
//! orthogonal complement vs stacked kernels, sympy's factorisation vs a
//! hand-written Cantor-Zassenhaus, the minimal polynomial by definition vs the
//! charpoly-irreducibility shortcut), so an agreement is not two copies of one
//! routine agreeing with itself.
//!
//! Every test **skips loudly** when python3 or sympy is missing — never
//! silently, and never as a failure. Set `ZIG_LIBS_VERBOSE_SKIP` to see why.

const std = @import("std");
const testing = std.testing;
const mds_security = @import("mds_security.zig");
const grain = @import("grain.zig");
const small_field = @import("small_field.zig");
const bn254 = @import("bn254");

const testkit = @import("testkit");
const verboseSkip = testkit.verboseSkip;

fn skip(comptime reason: []const u8) error{SkipZigTest} {
    if (verboseSkip()) std.debug.print("SKIPPED: " ++ reason ++ "\n", .{});
    return error.SkipZigTest;
}

/// One line of `out.txt` — the reference's verdicts for one matrix.
const Verdict = struct {
    alg1_secure: bool,
    alg1_code: u8,
    alg1_round: usize,
    alg2: bool,
    alg3: bool,
    minpoly: bool,
};

const Ref = struct {
    tmp: testing.TmpDir,
    io: std.Io,
    gpa: std.mem.Allocator,

    const driver = @embedFile("testdata/subspace_trail.py");

    fn init(gpa: std.mem.Allocator, io: std.Io) error{SkipZigTest}!Ref {
        var child = std.process.spawn(io, .{
            .argv = &.{ "python3", "-c", "import sympy" },
            .stdin = .close,
            .stdout = .ignore,
            .stderr = .ignore,
        }) catch return skip("python3 not found — subspace-trail interop needs it");
        const term = child.wait(io) catch return skip("python3 could not be waited on");
        switch (term) {
            .exited => |code| if (code != 0)
                return skip("python3 has no `sympy` module (pip install sympy)"),
            else => return skip("python3 terminated abnormally"),
        }
        return .{ .tmp = testing.tmpDir(.{}), .io = io, .gpa = gpa };
    }

    fn deinit(self: *Ref) void {
        self.tmp.cleanup();
    }

    /// Runs the oracle over `input` (the `in.txt` payload) and parses its
    /// verdicts. Caller frees the returned slice.
    fn run(self: *Ref, input: []const u8) ![]Verdict {
        try self.tmp.dir.writeFile(self.io, .{ .sub_path = "in.txt", .data = input });
        self.tmp.dir.deleteFile(self.io, "out.txt") catch {};
        var child = try std.process.spawn(self.io, .{
            .argv = &.{ "python3", "-c", driver },
            .cwd = .{ .dir = self.tmp.dir },
            .stdin = .close,
            .stdout = .ignore,
            .stderr = .ignore,
        });
        switch (try child.wait(self.io)) {
            .exited => |code| if (code != 0) return error.ReferenceFailed,
            else => return error.ReferenceCrashed,
        }
        const text = try self.tmp.dir.readFileAlloc(self.io, "out.txt", self.gpa, .limited(1 << 20));
        defer self.gpa.free(text);

        var out: std.ArrayList(Verdict) = .empty;
        errdefer out.deinit(self.gpa);
        var lines = std.mem.tokenizeScalar(u8, text, '\n');
        while (lines.next()) |line| {
            var f = std.mem.tokenizeScalar(u8, line, ' ');
            const v = Verdict{
                .alg1_secure = (try std.fmt.parseInt(u8, f.next().?, 10)) == 1,
                .alg1_code = try std.fmt.parseInt(u8, f.next().?, 10),
                .alg1_round = try std.fmt.parseInt(usize, f.next().?, 10),
                .alg2 = (try std.fmt.parseInt(u8, f.next().?, 10)) == 1,
                .alg3 = (try std.fmt.parseInt(u8, f.next().?, 10)) == 1,
                .minpoly = (try std.fmt.parseInt(u8, f.next().?, 10)) == 1,
            };
            try out.append(self.gpa, v);
        }
        return out.toOwnedSlice(self.gpa);
    }
};

/// A field element as the decimal integer the oracle reads.
fn asInt(comptime Fr: type, v: Fr) u256 {
    const be = v.toBytes();
    return std.mem.readInt(u256, &be, .big);
}

/// Compares our verdicts with the oracle's for a batch of matrices.
fn compare(
    comptime Fr: type,
    comptime p_be: []const u8,
    comptime n_max: usize,
    ref: *Ref,
    t: usize,
    matrices: []const [n_max][n_max]Fr,
    want_minpoly: bool,
) !void {
    const C = mds_security.Checks(Fr, p_be, n_max);

    var buf: std.Io.Writer.Allocating = .init(ref.gpa);
    defer buf.deinit();
    const w = &buf.writer;
    try w.print("{d}\n{d}\n{d}\n{d}\n", .{
        std.mem.readInt(u256, p_be[0..32], .big),
        t,
        matrices.len,
        @intFromBool(want_minpoly),
    });
    for (matrices) |m| {
        for (0..t) |i| {
            for (0..t) |j| try w.print("{d} ", .{asInt(Fr, m[i][j])});
            try w.print("\n", .{});
        }
    }

    const verdicts = try ref.run(buf.written());
    defer ref.gpa.free(verdicts);
    try testing.expectEqual(matrices.len, verdicts.len);

    var rejected: usize = 0;
    var codes: [4]usize = @splat(0);
    for (matrices, verdicts, 0..) |m, want, idx| {
        codes[want.alg1_code] += 1;
        const got1 = try C.algorithm1(&m, t);
        testing.expectEqual(want.alg1_secure, got1.secure) catch |e| {
            std.debug.print("algorithm_1 verdict differs at case {d}\n", .{idx});
            return e;
        };
        testing.expectEqual(want.alg1_code, got1.code) catch |e| {
            std.debug.print("algorithm_1 SUB-CODE differs at case {d}: ref {d}, ours {d}\n", .{ idx, want.alg1_code, got1.code });
            return e;
        };
        testing.expectEqual(want.alg1_round, got1.round) catch |e| {
            std.debug.print("algorithm_1 round differs at case {d}\n", .{idx});
            return e;
        };
        testing.expectEqual(want.alg2, C.algorithm2(&m, t)) catch |e| {
            std.debug.print("algorithm_2 differs at case {d}\n", .{idx});
            return e;
        };
        testing.expectEqual(want.alg3, C.algorithm3(&m, t)) catch |e| {
            std.debug.print("algorithm_3 differs at case {d}\n", .{idx});
            return e;
        };
        // The literal transcription must agree with the fast path too.
        try testing.expectEqual(want.alg3, C.algorithm3Literal(&m, t));
        const slow1 = try C.algorithm1Literal(&m, t);
        try testing.expectEqual(want.alg1_code, slow1.code);
        if (want_minpoly) {
            testing.expectEqual(want.minpoly, C.checkMinpolyCondition(&m, t)) catch |e| {
                std.debug.print("check_minpoly_condition differs at case {d}\n", .{idx});
                return e;
            };
        }
        if (!want.alg1_secure or !want.alg2 or !want.alg3) rejected += 1;
    }
    if (verboseSkip()) std.debug.print(
        "batch of {d} at t={d}: {d} rejected by the reference (alg1 codes seen: {d}/{d}/{d})\n",
        .{ matrices.len, t, rejected, codes[1], codes[2], codes[3] },
    );
}

const F101 = small_field.SmallField(101);
const F251 = small_field.SmallField(251);

/// Deterministic pseudo-random matrices — a plain LCG, so the cases are
/// reproducible without an RNG dependency and can be quoted in a bug report.
fn samples(comptime Fr: type, comptime n_max: usize, comptime count: usize, t: usize, seed: u64) [count][n_max][n_max]Fr {
    var state = seed;
    var out: [count][n_max][n_max]Fr = undefined;
    for (&out) |*m| {
        m.* = @splat(@as([n_max]Fr, @splat(Fr.zero)));
        for (0..t) |i| {
            for (0..t) |j| {
                state = state *% 6364136223846793005 +% 1442695040888963407;
                var be: [32]u8 = @splat(0);
                std.mem.writeInt(u64, be[24..32], state >> 11, .big);
                m[i][j] = Fr.reduceWide(&be);
            }
        }
    }
    return out;
}

test "reference: random matrices over GF(101), all four checks incl. sub-codes" {
    var ref = try Ref.init(testing.allocator, testing.io);
    defer ref.deinit();
    inline for (.{ 3, 4, 5, 6 }) |t| {
        const batch = samples(F101, 6, 26, t, 0xC0FFEE + t);
        try compare(F101, &F101.modulus_be, 6, &ref, t, &batch, true);
    }
}

test "reference: random matrices over GF(251), all four checks incl. sub-codes" {
    var ref = try Ref.init(testing.allocator, testing.io);
    defer ref.deinit();
    inline for (.{ 3, 4, 5, 6 }) |t| {
        const batch = samples(F251, 6, 16, t, 0xBEEF + t);
        try compare(F251, &F251.modulus_be, 6, &ref, t, &batch, true);
    }
}

/// A small matrix from a row-major list of small integers.
fn build(comptime n_max: usize, t: usize, vals: []const u64) [n_max][n_max]F101 {
    var m: [n_max][n_max]F101 = @splat(@as([n_max]F101, @splat(F101.zero)));
    for (0..t) |i| {
        for (0..t) |j| m[i][j] = .{ .v = @intCast(vals[i * t + j]) };
    }
    return m;
}

test "reference: constructed algorithm_1 failures — every sub-code, not just the verdict" {
    // Random matrices over GF(101) never fail `algorithm_1` (measured: 0 of
    // 168 — its failures need a rank-deficient observability matrix, which is
    // a ~1/p event). Without this batch the sub-code comparison, which is the
    // whole reason the oracle is worth running, would be vacuous.
    var ref = try Ref.init(testing.allocator, testing.io);
    defer ref.deinit();

    const t3 = [_][6][6]F101{
        // Scalar at i = 1: the identity.
        build(6, 3, &.{ 1, 0, 0, 0, 1, 0, 0, 0, 1 }),
        // Scalar at i = 2 but not at i = 1: M^2 = 4I.
        build(6, 3, &.{ 0, 4, 0, 1, 0, 0, 0, 0, 2 }),
        // Diagonal: e_1 and e_2 are eigenvectors with eigenvalues in F and
        // both lie in S_1 = {x[0] = 0}.
        build(6, 3, &.{ 2, 0, 0, 0, 3, 0, 0, 0, 5 }),
        // Block triangular with a rational eigenvalue on the trailing block.
        build(6, 3, &.{ 2, 5, 0, 0, 3, 0, 0, 0, 3 }),
        // A 3-cycle: p = 101 is 2 mod 3, so only lambda = 1 is rational and
        // its eigenvector (1,1,1) is NOT in S_1.
        build(6, 3, &.{ 0, 0, 1, 1, 0, 0, 0, 1, 0 }),
        // e_0 is fixed, so the row sequence stalls immediately.
        build(6, 3, &.{ 7, 0, 0, 3, 2, 5, 11, 13, 4 }),
    };
    try compare(F101, &F101.modulus_be, 6, &ref, 3, &t3, true);

    const t4 = [_][6][6]F101{
        // Block diagonal: e_0^T M^k never leaves span(e_0, e_1).
        build(6, 4, &.{ 2, 3, 0, 0, 5, 7, 0, 0, 0, 0, 11, 0, 0, 0, 0, 13 }),
        // Same shape, non-diagonal trailing block.
        build(6, 4, &.{ 2, 3, 0, 0, 5, 7, 0, 0, 9, 1, 11, 2, 4, 6, 8, 13 }),
        // Scalar at i = 3 = t - 1: a 4-cycle has M^4 = I, so M^3 is not
        // scalar; use a doubled 2-cycle instead, M^2 = I.
        build(6, 4, &.{ 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0 }),
        build(6, 4, &.{ 3, 0, 0, 0, 0, 3, 0, 0, 0, 0, 3, 0, 0, 0, 0, 3 }),
    };
    try compare(F101, &F101.modulus_be, 6, &ref, 4, &t4, true);
}

test "reference: the Cauchy candidates derive actually draws over GF(101)" {
    // Not random matrices — the exact `create_mds_p` outputs the rejection
    // loop sees, accepted and rejected alike. This is the input distribution
    // that matters, and the one an argument about `derive` is really about.
    var ref = try Ref.init(testing.allocator, testing.io);
    defer ref.deinit();

    const t = 5;
    const cfg = grain.Config{
        .Fr = F101,
        .modulus_be = F101.modulus_be,
        .n = 7,
        .t = t,
        .r_f = 8,
        .r_p = 21, // three candidates: two rejected, one accepted
    };
    var lfsr: grain.Lfsr = .init(cfg.n, cfg.t, cfg.r_f, cfg.r_p);
    const p = std.mem.readInt(u256, &cfg.modulus_be, .big);
    for (0..cfg.numConstants()) |_| {
        var v = lfsr.nextNum(cfg.n);
        while (v >= p) v = lfsr.nextNum(cfg.n);
    }

    var batch: [3][6][6]F101 = @splat(@splat(@as([6]F101, @splat(F101.zero))));
    var drawn: usize = 0;
    while (drawn < batch.len) {
        var rand_list: [2 * t]F101 = undefined;
        while (true) {
            for (&rand_list) |*e| {
                var be: [32]u8 = undefined;
                std.mem.writeInt(u256, &be, lfsr.nextNum(cfg.n), .big);
                e.* = F101.reduceWide(&be);
            }
            var dup = false;
            for (0..2 * t) |i| {
                for (i + 1..2 * t) |j| {
                    if (rand_list[i].eql(rand_list[j])) dup = true;
                }
            }
            if (!dup) break;
        }
        var singular = false;
        var m: [6][6]F101 = @splat(@as([6]F101, @splat(F101.zero)));
        for (0..t) |i| {
            for (0..t) |j| {
                const s = rand_list[i].add(rand_list[t + j]);
                if (s.isZero()) singular = true else m[i][j] = s.inv() catch unreachable;
            }
        }
        if (singular) continue;
        batch[drawn] = m;
        drawn += 1;
    }

    try compare(F101, &F101.modulus_be, 6, &ref, t, &batch, false);

    // And the verdicts must be exactly "reject, reject, accept" — which is
    // what `mds_candidates == 3` in `rejection_test.zig` claims.
    const C = mds_security.Checks(F101, &F101.modulus_be, 6);
    try testing.expect(!try C.isSecure(&batch[0], t));
    try testing.expect(!try C.isSecure(&batch[1], t));
    try testing.expect(try C.isSecure(&batch[2], t));
    try testing.expectEqual(@as(usize, 3), (try grain.derive(cfg)).mds_candidates);
}

test "reference: the shipped BN254 MDS matrices, at the real field size" {
    // Small batch: sympy over a 254-bit prime is slow, and this direction adds
    // little — every one of these passes, which is exactly why the small-field
    // batches above exist. What it does prove is that nothing in either port
    // depends on the modulus being small.
    var ref = try Ref.init(testing.allocator, testing.io);
    defer ref.deinit();

    const bn = @import("bn254_poseidon.zig");
    const t = 3;
    const P = bn.Perm(t).init();
    var batch: [1][3][3]bn254.Fr = undefined;
    batch[0] = P.mds;
    try compare(bn254.Fr, &bn254.scalar.r_bytes, 3, &ref, t, &batch, false);
}
