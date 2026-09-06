// SPDX-License-Identifier: MIT

//! The MDS subspace-trail checks against a **committed transcript** of what an
//! independent sympy port of the same sage source said — replayed here with no
//! child process, no Python and no foreign source anywhere in the module.
//!
//! ## Where the transcript comes from
//!
//! `tools/interop.zig` drives `tools/subspace_trail.py` and captures its
//! verdicts into `testdata/mds_subspace_trail.txt`:
//!
//! ```sh
//! zig build interop-poseidon -- --capture   # re-take it (needs python3+sympy)
//! zig build interop-poseidon                # re-run the peer, diff, no rewrite
//! ```
//!
//! Until 2026-09-06 that comparison ran here, spawning `python3` from inside
//! `zig build test-poseidon` and skipping loudly without it. A skip is not an
//! assertion: on every host without sympy — CI included, where the peer install
//! is `continue-on-error` — the four algorithms had no oracle at all, while
//! every consumer of the library still carried an embedded 285-line Python
//! driver. Splitting it puts the anchor's *taking* in `tools/` and its *value*
//! here, in the lane that runs everywhere.
//!
//! ## What this is worth, stated up front
//!
//! **Tier 2, not an external anchor.** sage is not installed here, so the peer
//! is a Python transcription of the *same* `reference_params.sage` text the Zig
//! side was written from. It catches transcription slips — an index off by one,
//! a wrong sub-code, a rejection that fails to advance the stream — and it
//! categorically does **not** catch a shared misreading of the specification:
//! misunderstand `generate_vectorspace` and both ports misunderstand it the same
//! way, and every comparison here still passes. The grade-1 anchor for this
//! module remains circomlib's and the authors' published constants, which
//! `constants_test.zig` pins. See `SPEC.md` §"Anchoring".
//!
//! ## Where it IS strong
//!
//!   1. **The inputs are chosen so the checks fail.** Over BN254 a random matrix
//!      passes with probability `1 - 2^-236`, so an oracle fed only
//!      Poseidon-sized inputs would agree with `return true`. Most batches here
//!      are over `p = 101` and `p = 251`, where **19 of the 168** random
//!      matrices are rejected, and the comparison covers each of them.
//!   2. **It compares the sub-code, not a boolean.** `algorithm_1` returns
//!      `[False, 1|2|3]` plus the round `i` it failed at; all three fields are
//!      compared. Agreeing on "insecure" is weak; agreeing on "insecure, code 3,
//!      at i = 2" is not.
//!
//! ## The transcript cannot go stale silently
//!
//! Every matrix is regenerated here from this module's own code and required to
//! equal the one the transcript records, so a transcript that pins inputs nobody
//! produces any more fails instead of passing quietly. `mds_batch_coverage`
//! additionally pins the batch list and the total, so a replay cannot pass by
//! having stopped looking.

const std = @import("std");
const testing = std.testing;
const mds_security = @import("mds_security.zig");
const grain = @import("grain.zig");
const small_field = @import("small_field.zig");
const bn254 = @import("bn254");

const testkit = @import("testkit");
const verboseSkip = testkit.verboseSkip;

/// What `tools/interop.zig` captured. Committed, and the only thing between
/// this module and the oracle.
const transcript = @embedFile("testdata/mds_subspace_trail.txt");

/// The widest state any batch uses, and the bound `Checks` is instantiated at.
const max_t = 6;

/// One line of `v` — the reference's verdicts for one matrix.
const Verdict = struct {
    alg1_secure: bool,
    alg1_code: u8,
    alg1_round: usize,
    alg2: bool,
    alg3: bool,
    minpoly: bool,
};

/// One `m`/`v` pair: the matrix as decimals, row-major, and its verdicts.
const Entry = struct {
    vals: [max_t * max_t]u256,
    verdict: Verdict,
};

/// A cursor over one named batch of the transcript.
const Batch = struct {
    lines: std.mem.SplitIterator(u8, .scalar),
    p: u256,
    t: usize,
    want_minpoly: bool,
    count: usize,

    fn open(id: []const u8) !Batch {
        var lines = std.mem.splitScalar(u8, transcript, '\n');
        while (lines.next()) |line| {
            if (!std.mem.startsWith(u8, line, "batch ")) continue;
            var f = std.mem.tokenizeAny(u8, line[6..], " \r");
            if (!std.mem.eql(u8, f.next() orelse "", id)) continue;
            return .{
                .lines = lines,
                .p = try field(u256, f.next(), "p="),
                .t = try field(usize, f.next(), "t="),
                .want_minpoly = try field(u1, f.next(), "minpoly=") == 1,
                .count = try field(usize, f.next(), "count="),
            };
        }
        std.debug.print("\ntranscript has no batch '{s}' — re-capture it\n", .{id});
        return error.NoSuchBatch;
    }

    fn field(comptime T: type, tok: ?[]const u8, comptime prefix: []const u8) !T {
        const s = tok orelse return error.MalformedBatchHeader;
        if (!std.mem.startsWith(u8, s, prefix)) return error.MalformedBatchHeader;
        return std.fmt.parseInt(T, s[prefix.len..], 10);
    }

    /// The next `m`/`v` pair, or null at the end of this batch.
    fn next(self: *Batch) !?Entry {
        const m_line = self.lines.next() orelse return null;
        if (!std.mem.startsWith(u8, m_line, "m ")) return null;
        var e: Entry = .{ .vals = @splat(0), .verdict = undefined };
        var f = std.mem.tokenizeAny(u8, m_line[2..], " \r");
        for (0..self.t * self.t) |i| {
            e.vals[i] = try std.fmt.parseInt(u256, f.next() orelse return error.ShortMatrix, 10);
        }
        if (f.next() != null) return error.LongMatrix;

        const v_line = self.lines.next() orelse return error.MissingVerdict;
        if (!std.mem.startsWith(u8, v_line, "v ")) return error.MissingVerdict;
        var g = std.mem.tokenizeAny(u8, v_line[2..], " \r");
        e.verdict = .{
            .alg1_secure = try num(u1, &g) == 1,
            .alg1_code = try num(u8, &g),
            .alg1_round = try num(usize, &g),
            .alg2 = try num(u1, &g) == 1,
            .alg3 = try num(u1, &g) == 1,
            .minpoly = try num(u1, &g) == 1,
        };
        return e;
    }

    fn num(comptime T: type, it: *std.mem.TokenIterator(u8, .any)) !T {
        return std.fmt.parseInt(T, it.next() orelse return error.ShortVerdict, 10);
    }
};

/// A field element as the decimal integer the transcript records.
fn asInt(comptime Fr: type, v: Fr) u256 {
    const be = v.toBytes();
    return std.mem.readInt(u256, &be, .big);
}

/// Replays one batch: the transcript's matrices must be the ones this module
/// generates, and its verdicts must be the ones these checks reach.
fn replay(
    comptime Fr: type,
    comptime p_be: []const u8,
    comptime n_max: usize,
    id: []const u8,
    t: usize,
    matrices: []const [n_max][n_max]Fr,
) !void {
    const C = mds_security.Checks(Fr, p_be, n_max);

    var batch = try Batch.open(id);
    try testing.expectEqual(t, batch.t);
    try testing.expectEqual(std.mem.readInt(u256, p_be[0..32], .big), batch.p);
    try testing.expectEqual(matrices.len, batch.count);

    var rejected: usize = 0;
    var codes: [4]usize = @splat(0);
    var seen: usize = 0;
    for (matrices, 0..) |m, idx| {
        const e = (try batch.next()) orelse {
            std.debug.print("\n{s}: transcript ran out at case {d}\n", .{ id, idx });
            return error.TranscriptTooShort;
        };
        seen += 1;

        // The input half: what the oracle was actually asked about must be what
        // this module produces today, or the verdicts below are about matrices
        // nobody generates any more.
        for (0..t) |i| {
            for (0..t) |j| {
                testing.expectEqual(e.vals[i * t + j], asInt(Fr, m[i][j])) catch |err| {
                    std.debug.print(
                        "\n{s} case {d}: transcript input differs at [{d}][{d}] — re-capture\n",
                        .{ id, idx, i, j },
                    );
                    return err;
                };
            }
        }

        const want = e.verdict;
        codes[want.alg1_code] += 1;
        const got1 = try C.algorithm1(&m, t);
        testing.expectEqual(want.alg1_secure, got1.secure) catch |err| {
            std.debug.print("{s}: algorithm_1 verdict differs at case {d}\n", .{ id, idx });
            return err;
        };
        testing.expectEqual(want.alg1_code, got1.code) catch |err| {
            std.debug.print(
                "{s}: algorithm_1 SUB-CODE differs at case {d}: reference {d}, ours {d}\n",
                .{ id, idx, want.alg1_code, got1.code },
            );
            return err;
        };
        testing.expectEqual(want.alg1_round, got1.round) catch |err| {
            std.debug.print("{s}: algorithm_1 round differs at case {d}\n", .{ id, idx });
            return err;
        };
        testing.expectEqual(want.alg2, C.algorithm2(&m, t)) catch |err| {
            std.debug.print("{s}: algorithm_2 differs at case {d}\n", .{ id, idx });
            return err;
        };
        testing.expectEqual(want.alg3, C.algorithm3(&m, t)) catch |err| {
            std.debug.print("{s}: algorithm_3 differs at case {d}\n", .{ id, idx });
            return err;
        };
        // The literal transcriptions must agree with the fast paths too.
        try testing.expectEqual(want.alg3, C.algorithm3Literal(&m, t));
        const slow1 = try C.algorithm1Literal(&m, t);
        try testing.expectEqual(want.alg1_code, slow1.code);
        if (batch.want_minpoly) {
            testing.expectEqual(want.minpoly, C.checkMinpolyCondition(&m, t)) catch |err| {
                std.debug.print("{s}: check_minpoly_condition differs at case {d}\n", .{ id, idx });
                return err;
            };
        }
        if (!want.alg1_secure or !want.alg2 or !want.alg3) rejected += 1;
    }
    if (try batch.next() != null) {
        std.debug.print("\n{s}: transcript has more matrices than this module generates\n", .{id});
        return error.TranscriptTooLong;
    }
    if (verboseSkip()) std.debug.print(
        "{s}: {d} matrices, {d} rejected by the reference (alg1 codes seen: {d}/{d}/{d})\n",
        .{ id, seen, rejected, codes[1], codes[2], codes[3] },
    );
}

const F101 = small_field.SmallField(101);
const F251 = small_field.SmallField(251);

/// Deterministic pseudo-random matrices — a plain LCG, so the cases are
/// reproducible without an RNG dependency and can be quoted in a bug report.
/// `tools/interop.zig` reproduces this stream in plain integers; the input
/// check in `replay` is what proves the two agree.
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

test "replay: random matrices over GF(101), all four checks incl. sub-codes" {
    inline for (.{ 3, 4, 5, 6 }) |t| {
        const batch = samples(F101, 6, 26, t, 0xC0FFEE + t);
        try replay(F101, &F101.modulus_be, 6, std.fmt.comptimePrint("gf101_random_t{d}", .{t}), t, &batch);
    }
}

test "replay: random matrices over GF(251), all four checks incl. sub-codes" {
    inline for (.{ 3, 4, 5, 6 }) |t| {
        const batch = samples(F251, 6, 16, t, 0xBEEF + t);
        try replay(F251, &F251.modulus_be, 6, std.fmt.comptimePrint("gf251_random_t{d}", .{t}), t, &batch);
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

test "replay: constructed algorithm_1 failures — every sub-code, not just the verdict" {
    // Random matrices over GF(101) never fail `algorithm_1` (measured: 0 of
    // 168 — its failures need a rank-deficient observability matrix, which is
    // a ~1/p event). Without this batch the sub-code comparison, which is the
    // whole reason the oracle is worth running, would be vacuous.
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
    try replay(F101, &F101.modulus_be, 6, "gf101_constructed_t3", 3, &t3);

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
    try replay(F101, &F101.modulus_be, 6, "gf101_constructed_t4", 4, &t4);
}

test "replay: the Cauchy candidates derive actually draws over GF(101)" {
    // Not random matrices — the exact `create_mds_p` outputs the rejection
    // loop sees, accepted and rejected alike. This is the input distribution
    // that matters, and the one an argument about `derive` is really about.
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

    try replay(F101, &F101.modulus_be, 6, "gf101_cauchy_t5", t, &batch);

    // And the verdicts must be exactly "reject, reject, accept" — which is
    // what `mds_candidates == 3` in `rejection_test.zig` claims.
    const C = mds_security.Checks(F101, &F101.modulus_be, 6);
    try testing.expect(!try C.isSecure(&batch[0], t));
    try testing.expect(!try C.isSecure(&batch[1], t));
    try testing.expect(try C.isSecure(&batch[2], t));
    try testing.expectEqual(@as(usize, 3), (try grain.derive(cfg)).mds_candidates);
}

test "replay: the shipped BN254 MDS matrices, at the real field size" {
    // Small batch: sympy over a 254-bit prime is slow, and this direction adds
    // little — every one of these passes, which is exactly why the small-field
    // batches above exist. What it does prove is that nothing in either port
    // depends on the modulus being small.
    const bn = @import("bn254_poseidon.zig");
    const t = 3;
    const P = bn.Perm(t).init();
    var batch: [1][3][3]bn254.Fr = undefined;
    batch[0] = P.mds;
    try replay(bn254.Fr, &bn254.scalar.r_bytes, 3, "bn254_mds_t3", t, &batch);
}

test "replay: the transcript still covers every batch, at full size" {
    // A replay that passes because it stopped looking is worse than no replay.
    // These are the batches and the totals the oracle was actually run on; a
    // transcript that shrinks fails here rather than passing quietly.
    const expected = [_]struct { id: []const u8, count: usize }{
        .{ .id = "gf101_random_t3", .count = 26 },
        .{ .id = "gf101_random_t4", .count = 26 },
        .{ .id = "gf101_random_t5", .count = 26 },
        .{ .id = "gf101_random_t6", .count = 26 },
        .{ .id = "gf251_random_t3", .count = 16 },
        .{ .id = "gf251_random_t4", .count = 16 },
        .{ .id = "gf251_random_t5", .count = 16 },
        .{ .id = "gf251_random_t6", .count = 16 },
        .{ .id = "gf101_constructed_t3", .count = 6 },
        .{ .id = "gf101_constructed_t4", .count = 4 },
        .{ .id = "gf101_cauchy_t5", .count = 3 },
        .{ .id = "bn254_mds_t3", .count = 1 },
    };
    var total: usize = 0;
    for (expected) |want| {
        var b = try Batch.open(want.id);
        try testing.expectEqual(want.count, b.count);
        var n: usize = 0;
        while (try b.next()) |_| n += 1;
        try testing.expectEqual(want.count, n);
        total += n;
    }
    try testing.expectEqual(@as(usize, 182), total);

    // And nothing else: a batch the tests above do not replay would be dead
    // weight that looks like coverage.
    var declared: usize = 0;
    var lines = std.mem.splitScalar(u8, transcript, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "batch ")) declared += 1;
    }
    try testing.expectEqual(expected.len, declared);
}

test "replay: the transcript records which reference produced it" {
    // Provenance is part of the artifact, not of a comment that can drift from
    // it: which driver, which sympy, when, and by which command.
    for ([_][]const u8{ "# reference : ", "# python    : ", "# sympy     : ", "# captured  : ", "# command   : " }) |key| {
        const at = std.mem.indexOf(u8, transcript, key) orelse {
            std.debug.print("\ntranscript header is missing '{s}'\n", .{key});
            return error.MissingProvenance;
        };
        const rest = transcript[at + key.len ..];
        const end = std.mem.indexOfScalar(u8, rest, '\n') orelse rest.len;
        try testing.expect(std.mem.trim(u8, rest[0..end], " \r").len > 0);
    }
}
