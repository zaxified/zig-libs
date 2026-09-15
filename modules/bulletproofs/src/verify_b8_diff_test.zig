// SPDX-License-Identifier: MIT

//! verify_b8_diff_test — the pre-B8 verifier, kept as a reference, and the
//! differential that holds the B8 verifier to it.
//!
//! Audit finding B8: `rangeproof.verify` used to materialise
//! `h'_i = y^{-i}*H_i` with `n` constant-time ladders (63 % of its time at
//! n=64) and hand `h'` to `ipa.verifyIpa`. It now folds `y^{-i}` into the MSM
//! coefficients instead (`rangeproof.verifyTraced`'s `h_scalars` and
//! `ipa.equationSides`'s `h_scale`). A mistake there does not make a slower
//! verifier, it makes one that accepts forgeries — so "the suite stayed
//! green" is not the evidence. This file is:
//!
//! - `refVerify` / `refIpaSides`: the pre-B8 `rangeproof.verify` and
//!   `ipa.verifyIpa`, copied from `git show
//!   646d54a5:modules/bulletproofs/src/{rangeproof,ipa}.zig`. The only
//!   deviations: they report a `VerifyTrace` / the two equation sides
//!   alongside the verdict, and their scratch comes from
//!   `std.testing.allocator`. They share no code with the path under test
//!   except primitives B8 did not touch (`scalarvec.mulCt`,
//!   `scalarvec.multiScalarMulVartime`, `rangeproof.deltaYZ`, `Transcript`).
//!   ⛔ Deliberately NOT `ipa.verifyIpa`: that now routes through the new
//!   `equationSides`, so a mutant there would move both arms of the
//!   comparison at once.
//! - A comparison on BYTES of the group elements each verifier computed — the
//!   IPA statement point `P` and both sides of the IPA's final equation — on
//!   every input, forged ones included. Two broken verifiers can agree on
//!   `false`; they do not agree on three 32-byte encodings by accident.
//! - Forgery classes: a single-bit flip at every byte of every wire field;
//!   byte-position ladders on every scalar field; point perturbations; L/R
//!   swaps, reorders, dropped and extra rounds; wrong commitment; wrong
//!   width; a cheating prover whose `t_hat` is forced so it PASSES check 1
//!   and is caught only by the IPA; the same points in a different internal
//!   (E[4]-shifted) representation, which must still be ACCEPTED; randomized
//!   forgeries; and a randomized IPA-level differential over arbitrary
//!   `h_scale` vectors, zeros included (`invert(0) == 0` makes `y == 0` the
//!   one place a "simplified" coefficient would diverge).
//!
//! Only single-value (`m = 1`) proofs exist in this module, so there is no
//! aggregated case to cover (see SPEC.md "Out of scope").
//!
//! Debug runs a reduced but non-empty version of every class; the full
//! sweeps run in optimized builds (the module lane runs both).

const std = @import("std");
const builtin = @import("builtin");
const Ristretto255 = std.crypto.ecc.Ristretto255;
const Edwards25519 = std.crypto.ecc.Edwards25519;
const scalar = Ristretto255.scalar;
const Generators = @import("generators.zig").Generators;
const Transcript = @import("transcript.zig").Transcript;
const scalarvec = @import("scalarvec.zig");
const ipa = @import("ipa.zig");
const InnerProductProof = ipa.InnerProductProof;
const rangeproof = @import("rangeproof.zig");
const RangeProof = rangeproof.RangeProof;
const VerifyTrace = rangeproof.VerifyTrace;

const talloc = std.testing.allocator;
const heavy = builtin.mode != .Debug;

// ── the pre-B8 reference ─────────────────────────────────────────────────────

fn refInvertScalar(s: [32]u8) [32]u8 {
    const inv = scalar.Scalar.fromBytes(s).invert();
    return inv.toBytes();
}

/// Pre-B8 `ipa.verifyIpa`, returning both sides instead of comparing them.
fn refIpaSides(
    transcript: *Transcript,
    g_vec: []const Ristretto255,
    h_vec: []const Ristretto255,
    q: Ristretto255,
    p: Ristretto255,
    proof: InnerProductProof,
) ?ipa.EquationSides {
    const n = g_vec.len;
    if (h_vec.len != n or n == 0 or !std.math.isPowerOfTwo(n)) return null;
    const rounds: usize = std.math.log2_int(usize, n);
    if (proof.l_vec.len != rounds or proof.r_vec.len != rounds) return null;

    var u: [64][32]u8 = undefined;
    var u_inv: [64][32]u8 = undefined;
    for (0..rounds) |j| {
        transcript.appendPoint("L", proof.l_vec[j]);
        transcript.appendPoint("R", proof.r_vec[j]);
        u[j] = transcript.challengeScalar("u");
        u_inv[j] = refInvertScalar(u[j]);
    }

    const alloc = talloc;

    var allinv = scalarvec.one;
    for (0..rounds) |j| allinv = scalar.mul(allinv, u_inv[j]);

    const s = alloc.alloc([32]u8, n) catch return null;
    defer alloc.free(s);
    s[0] = allinv;
    for (1..n) |i| {
        const lg = std.math.log2_int(usize, i);
        const k = @as(usize, 1) << @intCast(lg);
        const jj = rounds - 1 - lg;
        const u_sq = scalar.mul(u[jj], u[jj]);
        s[i] = scalar.mul(s[i - k], u_sq);
    }

    const terms = 2 * n + 1;
    const msm_scalars = alloc.alloc([32]u8, terms) catch return null;
    defer alloc.free(msm_scalars);
    const msm_points = alloc.alloc(Ristretto255, terms) catch return null;
    defer alloc.free(msm_points);
    for (0..n) |i| {
        msm_scalars[i] = scalar.mul(proof.a, s[i]);
        msm_points[i] = g_vec[i];
        msm_scalars[n + i] = scalar.mul(proof.b, s[n - 1 - i]);
        msm_points[n + i] = h_vec[i];
    }
    msm_scalars[2 * n] = scalar.mul(proof.a, proof.b);
    msm_points[2 * n] = q;
    const lhs = scalarvec.multiScalarMulVartime(msm_scalars, msm_points) catch return null;

    var rhs = p;
    for (0..rounds) |j| {
        rhs = rhs.add(scalarvec.mulCt(proof.l_vec[j], scalar.mul(u[j], u[j])));
        rhs = rhs.add(scalarvec.mulCt(proof.r_vec[j], scalar.mul(u_inv[j], u_inv[j])));
    }

    return .{ .lhs = lhs, .rhs = rhs };
}

/// Pre-B8 `rangeproof.verify` — materialises `h'` — writing the same trace
/// the new `verifyTraced` writes.
fn refVerify(
    gens: Generators,
    transcript: *Transcript,
    v: Ristretto255,
    proof: RangeProof,
    trace: *VerifyTrace,
) bool {
    const n = gens.n;
    if (n == 0 or !std.math.isPowerOfTwo(n)) return false;
    if (gens.g_vec.len != n or gens.h_vec.len != n) return false;
    const rounds: usize = std.math.log2_int(usize, n);
    if (proof.ipa.l_vec.len != rounds or proof.ipa.r_vec.len != rounds) return false;

    const scratch = talloc;

    transcript.appendU64("n", n);
    transcript.appendPoint("V", v);
    transcript.appendPoint("A", proof.a);
    transcript.appendPoint("S", proof.s);
    const y = transcript.challengeScalar("y");
    const z = transcript.challengeScalar("z");
    transcript.appendPoint("T1", proof.t1);
    transcript.appendPoint("T2", proof.t2);
    const x = transcript.challengeScalar("x");
    const z2 = scalar.mul(z, z);
    const x2 = scalar.mul(x, x);

    const delta = rangeproof.deltaYZ(scratch, y, z, n) catch return false;
    const lhs = scalarvec.mulCt(gens.g, proof.t_hat).add(scalarvec.mulCt(gens.h, proof.tau_x));
    const rhs = scalarvec.mulCt(v, z2)
        .add(scalarvec.mulCt(gens.g, delta))
        .add(scalarvec.mulCt(proof.t1, x))
        .add(scalarvec.mulCt(proof.t2, x2));
    if (!lhs.equivalent(rhs)) return false;

    transcript.appendScalar("t_hat", proof.t_hat);
    transcript.appendScalar("tau_x", proof.tau_x);
    transcript.appendScalar("mu", proof.mu);
    const w = transcript.challengeScalar("w");
    const q = scalarvec.mulCt(gens.g, w);

    const y_inv = refInvertScalar(y);
    const h_prime = scratch.alloc(Ristretto255, n) catch return false;
    defer scratch.free(h_prime);
    const h_scalars = scratch.alloc([32]u8, n) catch return false;
    defer scratch.free(h_scalars);

    var sum_g = scalarvec.identity_point;
    {
        var y_inv_pow = scalarvec.one;
        var y_pow = scalarvec.one;
        var two_pow = scalarvec.one;
        for (h_prime, h_scalars, gens.h_vec, gens.g_vec) |*o, *c_out, hp, gp| {
            o.* = scalarvec.mulCt(hp, y_inv_pow);
            c_out.* = scalar.mulAdd(z2, two_pow, scalar.mul(z, y_pow));
            sum_g = sum_g.add(gp);
            y_inv_pow = scalar.mul(y_inv_pow, y_inv);
            y_pow = scalar.mul(y_pow, y);
            two_pow = scalar.add(two_pow, two_pow);
        }
    }
    const h_term = scalarvec.multiScalarMulVartime(h_scalars, h_prime) catch return false;

    const p = proof.a
        .add(scalarvec.mulCt(proof.s, x))
        .sub(scalarvec.mulCt(sum_g, z))
        .sub(scalarvec.mulCt(gens.h, proof.mu))
        .add(h_term)
        .add(scalarvec.mulCt(q, proof.t_hat));

    const sides = refIpaSides(transcript, gens.g_vec, h_prime, q, p, proof.ipa) orelse return false;
    trace.reached_ipa = true;
    trace.p = p.toBytes();
    trace.ipa_lhs = sides.lhs.toBytes();
    trace.ipa_rhs = sides.rhs.toBytes();
    return sides.lhs.equivalent(sides.rhs);
}

// ── the differential ─────────────────────────────────────────────────────────

const Outcome = struct { verdict: bool, reached_ipa: bool };

const Tally = struct {
    cases: usize = 0,
    accepted: usize = 0,
    reached_ipa: usize = 0,

    fn add(self: *Tally, got: Outcome) void {
        self.cases += 1;
        if (got.verdict) self.accepted += 1;
        if (got.reached_ipa) self.reached_ipa += 1;
    }
};

/// Both verifiers, fresh transcripts, one input. They must agree on the
/// verdict, on whether the IPA ran, and byte-for-byte on `P` and both IPA
/// equation sides.
fn diffOne(gens: Generators, v: Ristretto255, proof: RangeProof) !Outcome {
    var new_trace: VerifyTrace = .{};
    var old_trace: VerifyTrace = .{};
    var t_new = Transcript.init(rangeproof.transcript_domain);
    var t_old = Transcript.init(rangeproof.transcript_domain);
    const new_verdict = rangeproof.verifyTraced(gens, &t_new, v, proof, &new_trace);
    const old_verdict = refVerify(gens, &t_old, v, proof, &old_trace);
    try std.testing.expectEqual(old_verdict, new_verdict);
    try std.testing.expectEqual(old_trace.reached_ipa, new_trace.reached_ipa);
    try std.testing.expectEqualSlices(u8, &old_trace.p, &new_trace.p);
    try std.testing.expectEqualSlices(u8, &old_trace.ipa_lhs, &new_trace.ipa_lhs);
    try std.testing.expectEqualSlices(u8, &old_trace.ipa_rhs, &new_trace.ipa_rhs);
    return .{ .verdict = new_verdict, .reached_ipa = new_trace.reached_ipa };
}

fn rejectSame(tally: *Tally, gens: Generators, v: Ristretto255, forged: RangeProof) !void {
    const got = try diffOne(gens, v, forged);
    try std.testing.expect(!got.verdict);
    tally.add(got);
}

fn randomScalar(random: std.Random) [32]u8 {
    var wide: [64]u8 = @splat(0);
    random.bytes(&wide);
    return scalar.reduce64(wide);
}

fn randomPoint(random: std.Random) Ristretto255 {
    return scalarvec.mulCt(Ristretto255.basePoint, randomScalar(random));
}

fn u64Scalar(v: u64) [32]u8 {
    var out = scalarvec.zero;
    std.mem.writeInt(u64, out[0..8], v, .little);
    return out;
}

const Fixture = struct {
    gens: Generators,
    v_point: Ristretto255,
    proof: RangeProof,

    /// An honest proof from the real `rangeproof.prove`.
    fn honest(n: usize, v_in: u64, gamma: [32]u8) !Fixture {
        const gens = try Generators.init(talloc, n);
        errdefer gens.deinit(talloc);
        const v: u64 = if (n < 64) v_in & ((@as(u64, 1) << @intCast(n)) - 1) else v_in;
        var t = Transcript.init(rangeproof.transcript_domain);
        const proof = try rangeproof.prove(talloc, gens, &t, &v, gamma);
        return .{ .gens = gens, .v_point = rangeproof.commit(gens, u64Scalar(v), gamma), .proof = proof };
    }

    fn deinit(self: Fixture) void {
        self.proof.deinit(talloc);
        self.gens.deinit(talloc);
    }
};

/// A CHEATING prover — the adversary, not the subject. It runs the §4.1
/// construction on the low `n` bits of `v` (so an out-of-range `v` gives bit
/// vectors that do not add up to it) and, with `force_t_hat`, sends
/// `t_hat = z^2*v + delta + t1*x + t2*x^2` instead of `<l(x), r(x)>`. That
/// makes check 1 hold by construction, so the forgery lands in the IPA — the
/// half of the verifier B8 changed — carrying an honestly-folded IPA proof of
/// the WRONG inner product. With an in-range `v` the forced value equals the
/// honest one, which is the forger's own positive control.
fn forge(
    gens: Generators,
    v: u64,
    gamma: [32]u8,
    force_t_hat: bool,
    random: std.Random,
) !struct { v_point: Ristretto255, proof: RangeProof } {
    const n = gens.n;
    var arena_state = std.heap.ArenaAllocator.init(talloc);
    defer arena_state.deinit();
    const ar = arena_state.allocator();

    const a_l = try ar.alloc([32]u8, n);
    const a_r = try ar.alloc([32]u8, n);
    for (a_l, a_r, 0..) |*al, *arr, i| {
        al.* = scalarvec.zero;
        al.*[0] = if (i < 64) @truncate((v >> @intCast(i)) & 1) else 0;
        arr.* = scalar.sub(al.*, scalarvec.one);
    }
    const alpha = randomScalar(random);
    const a_commit = scalarvec.mulCt(gens.h, alpha)
        .add(try scalarvec.multiScalarMul(a_l, gens.g_vec))
        .add(try scalarvec.multiScalarMul(a_r, gens.h_vec));
    const s_l = try ar.alloc([32]u8, n);
    const s_r = try ar.alloc([32]u8, n);
    for (s_l, s_r) |*sl, *sr| {
        sl.* = randomScalar(random);
        sr.* = randomScalar(random);
    }
    const rho = randomScalar(random);
    const s_commit = scalarvec.mulCt(gens.h, rho)
        .add(try scalarvec.multiScalarMul(s_l, gens.g_vec))
        .add(try scalarvec.multiScalarMul(s_r, gens.h_vec));

    var t = Transcript.init(rangeproof.transcript_domain);
    t.appendU64("n", n);
    const v_scalar = u64Scalar(v);
    const v_point = rangeproof.commit(gens, v_scalar, gamma);
    t.appendPoint("V", v_point);
    t.appendPoint("A", a_commit);
    t.appendPoint("S", s_commit);
    const y = t.challengeScalar("y");
    const z = t.challengeScalar("z");

    const y_pows = try scalarvec.powers(ar, y, n);
    const two_pows = try scalarvec.powers(ar, scalarvec.two, n);
    const z2 = scalar.mul(z, z);
    const l0 = try ar.alloc([32]u8, n);
    const r0 = try ar.alloc([32]u8, n);
    const r1 = try ar.alloc([32]u8, n);
    for (l0, r0, r1, a_l, a_r, y_pows, two_pows, s_r) |*o_l0, *o_r0, *o_r1, al, arr, yp, tp, sr| {
        o_l0.* = scalar.sub(al, z);
        o_r0.* = scalar.mulAdd(z2, tp, scalar.mul(yp, scalar.add(arr, z)));
        o_r1.* = scalar.mul(yp, sr);
    }
    const t1 = scalar.add(try scalarvec.innerProduct(l0, r1), try scalarvec.innerProduct(s_l, r0));
    const t2 = try scalarvec.innerProduct(s_l, r1);
    const tau1 = randomScalar(random);
    const tau2 = randomScalar(random);
    const t1_commit = scalarvec.mulCt(gens.g, t1).add(scalarvec.mulCt(gens.h, tau1));
    const t2_commit = scalarvec.mulCt(gens.g, t2).add(scalarvec.mulCt(gens.h, tau2));
    t.appendPoint("T1", t1_commit);
    t.appendPoint("T2", t2_commit);
    const x = t.challengeScalar("x");
    const x2 = scalar.mul(x, x);

    const l_x = try ar.alloc([32]u8, n);
    const r_x = try ar.alloc([32]u8, n);
    for (l_x, r_x, l0, s_l, r0, r1) |*ol, *orr, c0, c1, d0, d1| {
        ol.* = scalar.mulAdd(c1, x, c0);
        orr.* = scalar.mulAdd(d1, x, d0);
    }
    const delta = try rangeproof.deltaYZ(ar, y, z, n);
    const t_hat = if (force_t_hat)
        scalar.add(scalar.add(scalar.mul(z2, v_scalar), delta), scalar.add(scalar.mul(t1, x), scalar.mul(t2, x2)))
    else
        try scalarvec.innerProduct(l_x, r_x);
    const tau_x = scalar.add(scalar.mulAdd(tau2, x2, scalar.mul(tau1, x)), scalar.mul(z2, gamma));
    const mu = scalar.mulAdd(rho, x, alpha);

    t.appendScalar("t_hat", t_hat);
    t.appendScalar("tau_x", tau_x);
    t.appendScalar("mu", mu);
    const w = t.challengeScalar("w");
    const q = scalarvec.mulCt(gens.g, w);
    const y_inv = refInvertScalar(y);
    const h_prime = try ar.alloc(Ristretto255, n);
    var y_inv_pow = scalarvec.one;
    for (h_prime, gens.h_vec) |*o, hp| {
        o.* = scalarvec.mulCt(hp, y_inv_pow);
        y_inv_pow = scalar.mul(y_inv_pow, y_inv);
    }
    const ipa_proof = try ipa.proveIpa(talloc, &t, gens.g_vec, h_prime, q, l_x, r_x);
    return .{
        .v_point = v_point,
        .proof = .{ .a = a_commit, .s = s_commit, .t1 = t1_commit, .t2 = t2_commit, .tau_x = tau_x, .mu = mu, .t_hat = t_hat, .ipa = ipa_proof },
    };
}

/// The order-2 Edwards point (0, -1). Adding it to a Ristretto255 element's
/// internal representation leaves the element — and its encoding — unchanged.
fn order2() Edwards25519 {
    return Edwards25519.fromBytes([_]u8{0xec} ++ [_]u8{0xff} ** 30 ++ [_]u8{0x7f}) catch unreachable;
}

fn shifted(p: Ristretto255) Ristretto255 {
    return .{ .p = p.p.add(order2()) };
}

// ── tests ────────────────────────────────────────────────────────────────────

test "B8 diff: honest proofs at every width verify identically, bytes of P and both IPA sides" {
    const widths: []const usize = if (heavy) &.{ 1, 2, 4, 8, 16, 32, 64 } else &.{ 1, 2, 4, 8, 16 };
    var prng = std.Random.DefaultPrng.init(0xB8_0001);
    const random = prng.random();
    var tally: Tally = .{};
    for (widths) |n| {
        for ([_]u64{ 0, std.math.maxInt(u64), random.int(u64) }) |v| {
            const fx = try Fixture.honest(n, v, randomScalar(random));
            defer fx.deinit();
            const got = try diffOne(fx.gens, fx.v_point, fx.proof);
            tally.add(got);
            // The public entry point is the traced body without a trace.
            var t = Transcript.init(rangeproof.transcript_domain);
            try std.testing.expectEqual(got.verdict, rangeproof.verify(fx.gens, &t, fx.v_point, fx.proof));
        }
    }
    try std.testing.expectEqual(widths.len * 3, tally.cases);
    try std.testing.expectEqual(tally.cases, tally.accepted);
    try std.testing.expectEqual(tally.cases, tally.reached_ipa);
}

const WireField = enum(u8) { A, S, T1, T2, tau_x, mu, t_hat, rounds, L, R, a, b };

fn wireField(off: usize, len: usize) WireField {
    if (off < 224) return @enumFromInt(off / 32);
    if (off < 228) return .rounds;
    if (off >= len - 32) return .b;
    if (off >= len - 64) return .a;
    return if ((off - 228) % 64 < 32) .L else .R;
}

test "B8 diff: a single-bit flip at every byte of every wire field is rejected identically" {
    const widths: []const usize = if (heavy) &.{ 2, 8, 64 } else &.{2};
    const masks = [_]u8{ 0x01, 0x80 };
    const field_count = @typeInfo(WireField).@"enum".fields.len;
    var prng = std.Random.DefaultPrng.init(0xB8_0002);
    const random = prng.random();
    for (widths) |n| {
        const fx = try Fixture.honest(n, random.int(u64), randomScalar(random));
        defer fx.deinit();
        const bytes = try fx.proof.toBytesAlloc(talloc);
        defer talloc.free(bytes);
        const work = try talloc.dupe(u8, bytes);
        defer talloc.free(work);

        // Positive control: the untouched encoding decodes and is accepted.
        {
            const back = try RangeProof.fromBytesAlloc(talloc, work);
            defer back.deinit(talloc);
            try std.testing.expect((try diffOne(fx.gens, fx.v_point, back)).verdict);
        }

        var decoded: [field_count]usize = @splat(0);
        var reached: [field_count]usize = @splat(0);
        for (0..bytes.len) |off| {
            for (masks) |m| {
                @memcpy(work, bytes);
                work[off] ^= m;
                const forged = RangeProof.fromBytesAlloc(talloc, work) catch continue;
                defer forged.deinit(talloc);
                const f = @intFromEnum(wireField(off, bytes.len));
                decoded[f] += 1;
                const got = try diffOne(fx.gens, fx.v_point, forged);
                try std.testing.expect(!got.verdict);
                if (got.reached_ipa) reached[f] += 1;
            }
        }
        // Not blind: every field but the rounds header put flips past the
        // codec (a header flip changes the implied length, which the codec
        // always refuses), and every field bound after check 1 — mu, the IPA
        // points, the IPA scalars — put forgeries into the IPA.
        for (std.enums.values(WireField)) |f| {
            if (f == .rounds and n > 1) {
                try std.testing.expectEqual(@as(usize, 0), decoded[@intFromEnum(f)]);
            } else {
                try std.testing.expect(decoded[@intFromEnum(f)] > 0);
            }
        }
        for ([_]WireField{ .mu, .L, .R, .a, .b }) |f| try std.testing.expect(reached[@intFromEnum(f)] > 0);
    }
}

test "B8 diff: structured forgeries are rejected identically (field ladders, L/R swaps, rounds, wrong V, wrong width)" {
    const widths: []const usize = if (heavy) &.{ 2, 8, 64 } else &.{4};
    var prng = std.Random.DefaultPrng.init(0xB8_0003);
    const random = prng.random();
    for (widths) |n| {
        const v: u64 = if (n < 64) (@as(u64, 1) << @intCast(n - 1)) + 1 else 0x0123_4567_89ab_cdef;
        const gamma = randomScalar(random);
        const fx = try Fixture.honest(n, v, gamma);
        defer fx.deinit();
        const gens = fx.gens;
        const base = fx.proof;
        var tally: Tally = .{};

        try std.testing.expect((try diffOne(gens, fx.v_point, base)).verdict);

        // (a) Point fields shifted by a public generator, one at a time.
        const bumps = [_]Ristretto255{ Ristretto255.basePoint, gens.h_vec[n - 1], gens.g_vec[0], gens.h };
        for (bumps) |d| {
            for (0..4) |which| {
                var f = base;
                switch (which) {
                    0 => f.a = f.a.add(d),
                    1 => f.s = f.s.add(d),
                    2 => f.t1 = f.t1.add(d),
                    else => f.t2 = f.t2.add(d),
                }
                try rejectSame(&tally, gens, fx.v_point, f);
            }
        }

        // (b) Every scalar field + 2^(8k), a ladder over byte positions
        // (2^248 < L, so every rung stays canonical).
        const all_k = [_]usize{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
        const ks: []const usize = if (heavy) &all_k else &.{ 0, 15, 31 };
        for (ks) |k| {
            var e = scalarvec.zero;
            e[k] = 1;
            for (0..5) |which| {
                var f = base;
                switch (which) {
                    0 => f.tau_x = scalar.add(f.tau_x, e),
                    1 => f.mu = scalar.add(f.mu, e),
                    2 => f.t_hat = scalar.add(f.t_hat, e),
                    3 => f.ipa.a = scalar.add(f.ipa.a, e),
                    else => f.ipa.b = scalar.add(f.ipa.b, e),
                }
                try rejectSame(&tally, gens, fx.v_point, f);
            }
        }
        {
            var f = base;
            f.ipa.a = base.ipa.b;
            f.ipa.b = base.ipa.a;
            try rejectSame(&tally, gens, fx.v_point, f);
        }

        // (c) The IPA vectors.
        const rounds = base.ipa.l_vec.len;
        const l = try talloc.dupe(Ristretto255, base.ipa.l_vec);
        defer talloc.free(l);
        const r = try talloc.dupe(Ristretto255, base.ipa.r_vec);
        defer talloc.free(r);
        var f_ipa = base;
        f_ipa.ipa.l_vec = l;
        f_ipa.ipa.r_vec = r;
        for (0..rounds) |i| {
            l[i] = base.ipa.l_vec[i].add(Ristretto255.basePoint);
            try rejectSame(&tally, gens, fx.v_point, f_ipa);
            l[i] = base.ipa.l_vec[i];

            r[i] = base.ipa.r_vec[i].add(gens.h_vec[0]);
            try rejectSame(&tally, gens, fx.v_point, f_ipa);
            r[i] = base.ipa.r_vec[i];

            // L_i <-> R_i
            l[i] = base.ipa.r_vec[i];
            r[i] = base.ipa.l_vec[i];
            try rejectSame(&tally, gens, fx.v_point, f_ipa);
            l[i] = base.ipa.l_vec[i];
            r[i] = base.ipa.r_vec[i];

            if (i + 1 < rounds) {
                // Rounds i and i+1 reordered.
                l[i] = base.ipa.l_vec[i + 1];
                l[i + 1] = base.ipa.l_vec[i];
                r[i] = base.ipa.r_vec[i + 1];
                r[i + 1] = base.ipa.r_vec[i];
                try rejectSame(&tally, gens, fx.v_point, f_ipa);
                @memcpy(l, base.ipa.l_vec);
                @memcpy(r, base.ipa.r_vec);
            }
        }
        if (rounds > 0) {
            // Whole L and R vectors exchanged.
            var f = base;
            f.ipa.l_vec = r;
            f.ipa.r_vec = l;
            try rejectSame(&tally, gens, fx.v_point, f);
            // Last round dropped.
            f = base;
            f.ipa.l_vec = l[0 .. rounds - 1];
            f.ipa.r_vec = r[0 .. rounds - 1];
            try rejectSame(&tally, gens, fx.v_point, f);
        }
        {
            // One extra round appended.
            const l_long = try talloc.alloc(Ristretto255, rounds + 1);
            defer talloc.free(l_long);
            const r_long = try talloc.alloc(Ristretto255, rounds + 1);
            defer talloc.free(r_long);
            @memcpy(l_long[0..rounds], base.ipa.l_vec);
            @memcpy(r_long[0..rounds], base.ipa.r_vec);
            l_long[rounds] = Ristretto255.basePoint;
            r_long[rounds] = gens.h;
            var f = base;
            f.ipa.l_vec = l_long;
            f.ipa.r_vec = r_long;
            try rejectSame(&tally, gens, fx.v_point, f);
        }

        // (d) The right proof against the wrong commitment.
        const wrong_v = [_]Ristretto255{
            fx.v_point.add(Ristretto255.basePoint),
            fx.v_point.add(gens.h),
            fx.v_point.add(gens.g),
            rangeproof.commit(gens, u64Scalar(v +% 1), gamma),
            rangeproof.commit(gens, u64Scalar(v), scalar.add(gamma, scalarvec.one)),
            scalarvec.identity_point,
            scalarvec.identity_point.sub(fx.v_point),
        };
        for (wrong_v) |wv| try rejectSame(&tally, gens, wv, base);

        // (e) The right proof against a generator set of the wrong width.
        for ([_]usize{ n * 2, n / 2 }) |other| {
            if (other == 0) continue;
            const g_other = try Generators.init(talloc, other);
            defer g_other.deinit(talloc);
            try rejectSame(&tally, g_other, fx.v_point, base);
        }

        // (f) Everything the identity, correct shape.
        {
            const zl = try talloc.alloc(Ristretto255, rounds);
            defer talloc.free(zl);
            for (zl) |*p| p.* = scalarvec.identity_point;
            const f = RangeProof{
                .a = scalarvec.identity_point,
                .s = scalarvec.identity_point,
                .t1 = scalarvec.identity_point,
                .t2 = scalarvec.identity_point,
                .tau_x = scalarvec.zero,
                .mu = scalarvec.zero,
                .t_hat = scalarvec.zero,
                .ipa = .{ .l_vec = zl, .r_vec = zl, .a = scalarvec.zero, .b = scalarvec.zero },
            };
            try rejectSame(&tally, gens, fx.v_point, f);
        }

        try std.testing.expectEqual(@as(usize, 0), tally.accepted);
        try std.testing.expect(tally.reached_ipa > 0);
        try std.testing.expect(tally.cases >= 40);
    }
}

test "B8 diff: the same points in an E[4]-shifted internal representation are accepted identically" {
    const widths: []const usize = if (heavy) &.{ 8, 64 } else &.{8};
    var prng = std.Random.DefaultPrng.init(0xB8_0004);
    const random = prng.random();
    for (widths) |n| {
        const fx = try Fixture.honest(n, random.int(u64), randomScalar(random));
        defer fx.deinit();
        const base = fx.proof;

        // The shift is invisible in the Ristretto encoding, visible in the
        // underlying Edwards one — i.e. it really is a different representation.
        try std.testing.expectEqualSlices(u8, &base.a.toBytes(), &shifted(base.a).toBytes());
        try std.testing.expect(!std.mem.eql(u8, &base.a.p.toBytes(), &shifted(base.a).p.toBytes()));

        var accepted: usize = 0;
        for (0..6) |which| {
            var f = base;
            const l = try talloc.dupe(Ristretto255, base.ipa.l_vec);
            defer talloc.free(l);
            const r = try talloc.dupe(Ristretto255, base.ipa.r_vec);
            defer talloc.free(r);
            f.ipa.l_vec = l;
            f.ipa.r_vec = r;
            var v_point = fx.v_point;
            switch (which) {
                0 => f.a = shifted(f.a),
                1 => f.s = shifted(f.s),
                2 => f.t1 = shifted(f.t1),
                3 => f.t2 = shifted(f.t2),
                4 => {
                    l[0] = shifted(l[0]);
                    r[r.len - 1] = shifted(r[r.len - 1]);
                },
                else => v_point = shifted(v_point),
            }
            if ((try diffOne(fx.gens, v_point, f)).verdict) accepted += 1;
        }
        try std.testing.expectEqual(@as(usize, 6), accepted);

        // Every generator shifted: this is where h_vec enters the new MSM
        // directly, unscaled.
        {
            const g_vec = try talloc.alloc(Ristretto255, n);
            defer talloc.free(g_vec);
            const h_vec = try talloc.alloc(Ristretto255, n);
            defer talloc.free(h_vec);
            for (g_vec, h_vec, fx.gens.g_vec, fx.gens.h_vec) |*go, *ho, gi, hi| {
                go.* = shifted(gi);
                ho.* = shifted(hi);
            }
            const gens_shifted = Generators{ .g = shifted(fx.gens.g), .h = shifted(fx.gens.h), .g_vec = g_vec, .h_vec = h_vec, .n = n };
            try std.testing.expect((try diffOne(gens_shifted, fx.v_point, base)).verdict);
            // ...and a forgery under them is still refused identically.
            var f = base;
            f.mu = scalar.add(f.mu, scalarvec.one);
            try std.testing.expect(!(try diffOne(gens_shifted, fx.v_point, f)).verdict);
        }
    }
}

test "B8 diff: a cheating prover with a forced t_hat passes check 1, reaches the IPA, and is rejected identically" {
    const widths: []const usize = if (heavy) &.{ 2, 8, 32 } else &.{ 2, 8 };
    var prng = std.Random.DefaultPrng.init(0xB8_0005);
    const random = prng.random();
    for (widths) |n| {
        const gens = try Generators.init(talloc, n);
        defer gens.deinit(talloc);
        const gamma = randomScalar(random);
        const top = @as(u64, 1) << @intCast(n);

        // Positive control: in range, the forced t_hat IS the honest one.
        {
            const fp = try forge(gens, top - 1, gamma, true, random);
            defer fp.proof.deinit(talloc);
            const got = try diffOne(gens, fp.v_point, fp.proof);
            try std.testing.expect(got.verdict and got.reached_ipa);
        }
        for ([_]u64{ top, top + 3, std.math.maxInt(u64) }) |v| {
            {
                const fp = try forge(gens, v, gamma, true, random);
                defer fp.proof.deinit(talloc);
                const got = try diffOne(gens, fp.v_point, fp.proof);
                try std.testing.expect(!got.verdict);
                try std.testing.expect(got.reached_ipa);
            }
            {
                // Unforced: the lie is caught by check 1, before the IPA.
                const fp = try forge(gens, v, gamma, false, random);
                defer fp.proof.deinit(talloc);
                const got = try diffOne(gens, fp.v_point, fp.proof);
                try std.testing.expect(!got.verdict);
                try std.testing.expect(!got.reached_ipa);
            }
        }
    }
}

test "B8 diff: randomized forgeries (wire flips, point and scalar perturbations, point swaps) agree in verdict and bytes" {
    const widths: []const usize = if (heavy) &.{ 2, 8, 32, 64 } else &.{4};
    const iterations: usize = if (heavy) 200 else 30;
    var prng = std.Random.DefaultPrng.init(0xB8_0006);
    const random = prng.random();
    for (widths) |n| {
        const fx = try Fixture.honest(n, random.int(u64), randomScalar(random));
        defer fx.deinit();
        // Second base: a forced-t_hat forgery (already in the IPA) for n < 64.
        const forged_base = if (n < 64) try forge(fx.gens, (@as(u64, 1) << @intCast(n)) + 1, randomScalar(random), true, random) else null;
        defer if (forged_base) |fb| fb.proof.deinit(talloc);

        var tally: Tally = .{};
        var codec_rejects: usize = 0;
        for (0..iterations) |_| {
            const use_forged = forged_base != null and random.boolean();
            const base = if (use_forged) forged_base.?.proof else fx.proof;
            const v_point = if (use_forged) forged_base.?.v_point else fx.v_point;
            const rounds = base.ipa.l_vec.len;

            const l = try talloc.dupe(Ristretto255, base.ipa.l_vec);
            defer talloc.free(l);
            const r = try talloc.dupe(Ristretto255, base.ipa.r_vec);
            defer talloc.free(r);
            var f = base;
            f.ipa.l_vec = l;
            f.ipa.r_vec = r;

            switch (random.uintLessThan(u8, 4)) {
                0 => {
                    const bytes = try base.toBytesAlloc(talloc);
                    defer talloc.free(bytes);
                    const flips = 1 + random.uintLessThan(usize, 3);
                    for (0..flips) |_| bytes[random.uintLessThan(usize, bytes.len)] ^= 1 + random.uintLessThan(u8, 255);
                    const decoded = RangeProof.fromBytesAlloc(talloc, bytes) catch {
                        codec_rejects += 1;
                        continue;
                    };
                    defer decoded.deinit(talloc);
                    try rejectSame(&tally, fx.gens, v_point, decoded);
                    continue;
                },
                1 => {
                    const d = randomPoint(random);
                    const slot = random.uintLessThan(usize, 4 + 2 * rounds);
                    switch (slot) {
                        0 => f.a = f.a.add(d),
                        1 => f.s = f.s.add(d),
                        2 => f.t1 = f.t1.add(d),
                        3 => f.t2 = f.t2.add(d),
                        else => {
                            const j = slot - 4;
                            if (j < rounds) l[j] = l[j].add(d) else r[j - rounds] = r[j - rounds].add(d);
                        },
                    }
                },
                2 => {
                    const d = randomScalar(random);
                    switch (random.uintLessThan(u8, 5)) {
                        0 => f.tau_x = scalar.add(f.tau_x, d),
                        1 => f.mu = scalar.add(f.mu, d),
                        2 => f.t_hat = scalar.add(f.t_hat, d),
                        3 => f.ipa.a = scalar.add(f.ipa.a, d),
                        else => f.ipa.b = scalar.add(f.ipa.b, d),
                    }
                },
                else => {
                    if (rounds == 0) {
                        f.ipa.b = scalar.add(f.ipa.b, scalarvec.one);
                    } else {
                        // Two distinct slots among the 2*rounds L/R points.
                        const total = 2 * rounds;
                        const s1 = random.uintLessThan(usize, total);
                        const s2 = (s1 + 1 + random.uintLessThan(usize, total - 1)) % total;
                        const p1 = if (s1 < rounds) &l[s1] else &r[s1 - rounds];
                        const p2 = if (s2 < rounds) &l[s2] else &r[s2 - rounds];
                        const tmp = p1.*;
                        p1.* = p2.*;
                        p2.* = tmp;
                    }
                },
            }
            try rejectSame(&tally, fx.gens, v_point, f);
        }
        try std.testing.expectEqual(iterations, tally.cases + codec_rejects);
        try std.testing.expect(tally.reached_ipa > 0);
        try std.testing.expectEqual(@as(usize, 0), tally.accepted);
    }
}

test "B8 diff: ipa.equationSides with h_scale equals the pre-B8 IPA verifier over materialised h', for arbitrary scales" {
    const widths: []const usize = if (heavy) &.{ 1, 2, 4, 8, 16, 32, 64 } else &.{ 1, 2, 4, 8 };
    const iterations: usize = if (heavy) 40 else 6;
    var prng = std.Random.DefaultPrng.init(0xB8_0007);
    const random = prng.random();
    for (widths) |n| {
        const gens = try Generators.init(talloc, n);
        defer gens.deinit(talloc);
        const rounds: usize = std.math.log2_int(usize, n);
        const scale = try talloc.alloc([32]u8, n);
        defer talloc.free(scale);
        const h_prime = try talloc.alloc(Ristretto255, n);
        defer talloc.free(h_prime);
        const l = try talloc.alloc(Ristretto255, rounds);
        defer talloc.free(l);
        const r = try talloc.alloc(Ristretto255, rounds);
        defer talloc.free(r);

        var accepted: usize = 0;
        for (0..iterations) |it| {
            // Scale kinds: y^{-i} for a random y; y = 0 (so [1, 0, 0, ...]);
            // fully random; random with about half the entries zero.
            const y_inv = refInvertScalar(if (it % 4 == 1) scalarvec.zero else randomScalar(random));
            var pow = scalarvec.one;
            for (scale) |*s| {
                s.* = switch (it % 4) {
                    0, 1 => pow,
                    2 => randomScalar(random),
                    else => if (random.boolean()) scalarvec.zero else randomScalar(random),
                };
                pow = scalar.mul(pow, y_inv);
            }
            for (h_prime, gens.h_vec, scale) |*o, hi, s| o.* = scalarvec.mulCt(hi, s);

            // Half the iterations: an honest IPA proof over h' (must accept).
            // The other half: random L/R/a/b/P (must reject).
            const honest = it % 2 == 0;
            var p: Ristretto255 = undefined;
            const q = randomPoint(random);
            var proof: InnerProductProof = undefined;
            var owned = false;
            if (honest) {
                const a_vec = try talloc.alloc([32]u8, n);
                defer talloc.free(a_vec);
                const b_vec = try talloc.alloc([32]u8, n);
                defer talloc.free(b_vec);
                for (a_vec, b_vec) |*ai, *bi| {
                    ai.* = randomScalar(random);
                    bi.* = randomScalar(random);
                }
                p = (try scalarvec.multiScalarMul(a_vec, gens.g_vec))
                    .add(try scalarvec.multiScalarMul(b_vec, h_prime))
                    .add(scalarvec.mulCt(q, try scalarvec.innerProduct(a_vec, b_vec)));
                var tp = Transcript.init(ipa.transcript_domain);
                proof = try ipa.proveIpa(talloc, &tp, gens.g_vec, h_prime, q, a_vec, b_vec);
                owned = true;
            } else {
                p = randomPoint(random);
                for (l, r) |*li, *ri| {
                    li.* = randomPoint(random);
                    ri.* = randomPoint(random);
                }
                proof = .{ .l_vec = l, .r_vec = r, .a = randomScalar(random), .b = randomScalar(random) };
            }
            defer if (owned) proof.deinit(talloc);

            var t_new = Transcript.init(ipa.transcript_domain);
            var t_old = Transcript.init(ipa.transcript_domain);
            const new_sides = ipa.equationSides(&t_new, gens.g_vec, gens.h_vec, scale, q, p, proof).?;
            const old_sides = refIpaSides(&t_old, gens.g_vec, h_prime, q, p, proof).?;
            try std.testing.expectEqualSlices(u8, &old_sides.lhs.toBytes(), &new_sides.lhs.toBytes());
            try std.testing.expectEqualSlices(u8, &old_sides.rhs.toBytes(), &new_sides.rhs.toBytes());
            const verdict = new_sides.lhs.equivalent(new_sides.rhs);
            try std.testing.expectEqual(old_sides.lhs.equivalent(old_sides.rhs), verdict);
            try std.testing.expectEqual(honest, verdict);
            if (verdict) accepted += 1;

            // The unscaled public verifyIpa is unchanged: an honest proof
            // over h' is accepted with h' passed directly, like before.
            var t_pub = Transcript.init(ipa.transcript_domain);
            try std.testing.expectEqual(honest, ipa.verifyIpa(&t_pub, gens.g_vec, h_prime, q, p, proof));
        }
        try std.testing.expectEqual((iterations + 1) / 2, accepted);

        // A scale of the wrong length is a structural rejection.
        var t_bad = Transcript.init(ipa.transcript_domain);
        const empty = InnerProductProof{ .l_vec = l, .r_vec = r, .a = scalarvec.zero, .b = scalarvec.zero };
        try std.testing.expect(ipa.equationSides(&t_bad, gens.g_vec, gens.h_vec, scale[0 .. n - 1], scalarvec.identity_point, scalarvec.identity_point, empty) == null);
    }
}
