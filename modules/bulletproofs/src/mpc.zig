// SPDX-License-Identifier: MIT
//! Multi-party aggregated range proofs: dalek's `range_proof::{dealer,
//! party}` protocol (Bulletproofs paper §4.5). `m` parties, each holding one
//! value and its blinding, build ONE aggregated proof — the proof
//! `proveMultiple` makes and `verifyMultiple` checks — without any party
//! revealing its witness to the others or to the dealer.
//!
//! Rounds, as dalek's state machines (each party at its position `j`):
//!
//! 1. `Party.init` → `BitCommitment { V_j, A_j, S_j }`;
//!    `Dealer.receiveBitCommitments` → `BitChallenge { y, z }`.
//! 2. `Party.applyBitChallenge` → `PolyCommitment { T1_j, T2_j }`;
//!    `Dealer.receivePolyCommitments` → `PolyChallenge { x }`.
//! 3. `Party.applyPolyChallenge` → `ProofShare` (`t_x`, `t_x_blinding`,
//!    `e_blinding`, the party's `l(x)`/`r(x)` slices);
//!    `Dealer.receiveShares` sums the shares, runs the inner-product proof
//!    over the concatenated vectors and checks the result with
//!    `verifyMultiple`. A proof that does not verify is not returned: every
//!    share is audited (dalek's `audit_share`: `t_x = <l, r>`, the `t_x`
//!    commitment equation, the `l`/`r` vector equation over the party's
//!    generators) and `error.MalformedProofShares` reports the culprits in
//!    `bad` (dalek's `MPCError::MalformedProofShares { bad_shares }`).
//!
//! The dealer is a role, not a trusted party: it learns only public values.
//! What it must not do is reuse a challenge; the dealer here derives every
//! challenge from the transcript, as dalek's.

const std = @import("std");
const rp = @import("rangeproof.zig");
const scalarvec = @import("scalarvec.zig");
const ipa = @import("ipa.zig");
const Generators = @import("generators.zig").Generators;
const Transcript = @import("transcript.zig").Transcript;
const Ristretto255 = std.crypto.ecc.Ristretto255;
const scalar = Ristretto255.scalar;

pub const MpcError = error{
    /// `m` is not a power of two, is zero, or exceeds `gens.parties`; or a
    /// round got a different number of messages than `m`.
    InvalidAggregation,
    /// A party's position is outside `[0, gens.parties)`.
    InvalidPosition,
    /// The value does not fit in `gens.n` bits.
    ValueOutOfRange,
    /// The dealer's assembled proof did not verify; `bad` names the shares
    /// that fail the audit.
    MalformedProofShares,
    /// A share's vectors are not `gens.n` long.
    MalformedShare,
    OutOfMemory,
    EntropyUnavailable,
    Canceled,
};

pub const BitCommitment = struct { v: Ristretto255, a: Ristretto255, s: Ristretto255 };
pub const BitChallenge = struct { y: [32]u8, z: [32]u8 };
pub const PolyCommitment = struct { t1: Ristretto255, t2: Ristretto255 };
pub const PolyChallenge = struct { x: [32]u8 };

/// A party's round-3 message. `l_vec`/`r_vec` are allocated by
/// `applyPolyChallenge`; free with `deinit`.
pub const ProofShare = struct {
    t_x: [32]u8,
    t_x_blinding: [32]u8,
    e_blinding: [32]u8,
    l_vec: [][32]u8,
    r_vec: [][32]u8,

    pub fn deinit(self: ProofShare, allocator: std.mem.Allocator) void {
        allocator.free(self.l_vec);
        allocator.free(self.r_vec);
    }
};

/// One party's secret state across the three rounds. Holds the witness and
/// the blinding scalars: `deinit` wipes and frees them.
pub const Party = struct {
    allocator: std.mem.Allocator,
    gens: Generators,
    j: usize,
    gamma: [32]u8,
    alpha: [32]u8,
    rho: [32]u8,
    tau1: [32]u8 = scalarvec.zero,
    tau2: [32]u8 = scalarvec.zero,
    z: [32]u8 = scalarvec.zero,
    a_l: [][32]u8,
    a_r: [][32]u8,
    s_l: [][32]u8,
    s_r: [][32]u8,
    /// l0 and r0, r1 after the bit challenge (l1 is `s_l`).
    l0: [][32]u8,
    r0: [][32]u8,
    r1: [][32]u8,

    /// Round 1 for value `v` with blinding `gamma` at position `j`.
    ///
    /// Every round runs its body one frame down and then zeroes the stack
    /// that body used (`rangeproof.burnStack`, as `prove`): without it the
    /// dead stack kept `gamma` and the blinding scalars after each round
    /// (`stackprobe2_test.zig`, 2026-11-23). `gamma` by pointer for the same
    /// reason (no by-value copy in this frame).
    pub fn init(out: *Party, allocator: std.mem.Allocator, io: std.Io, gens: Generators, j: usize, v: u64, gamma: *const [32]u8) MpcError!BitCommitment {
        const r = initBody(out, allocator, io, gens, j, v, gamma);
        rp.burnStack();
        return r;
    }

    noinline fn initBody(out: *Party, allocator: std.mem.Allocator, io: std.Io, gens: Generators, j: usize, v: u64, gamma: *const [32]u8) MpcError!BitCommitment {
        const n = gens.n;
        if (j >= gens.parties) return error.InvalidPosition;
        if (n < 64 and v >= (@as(u64, 1) << @intCast(n))) return error.ValueOutOfRange;
        var bufs: [7][][32]u8 = undefined;
        var made: usize = 0;
        errdefer for (bufs[0..made]) |b| {
            std.crypto.secureZero(u8, std.mem.sliceAsBytes(b));
            allocator.free(b);
        };
        for (&bufs) |*b| {
            b.* = try allocator.alloc([32]u8, n);
            made += 1;
        }
        out.* = .{
            .allocator = allocator,
            .gens = gens,
            .j = j,
            .gamma = gamma.*,
            .alpha = undefined,
            .rho = undefined,
            .a_l = bufs[0],
            .a_r = bufs[1],
            .s_l = bufs[2],
            .s_r = bufs[3],
            .l0 = bufs[4],
            .r0 = bufs[5],
            .r1 = bufs[6],
        };
        for (out.a_l, out.a_r, 0..) |*al, *ar, i| {
            const bit: u8 = if (i < 64) @truncate((v >> @intCast(i)) & 1) else 0;
            al.* = scalarvec.zero;
            al.*[0] = bit;
            ar.* = scalar.sub(al.*, scalarvec.one);
        }
        for (out.s_l, out.s_r) |*sl, *sr| {
            sl.* = try rp.randomScalar(io);
            sr.* = try rp.randomScalar(io);
        }
        out.alpha = try rp.randomScalar(io);
        out.rho = try rp.randomScalar(io);
        out.tau1 = try rp.randomScalar(io);
        out.tau2 = try rp.randomScalar(io);
        const g_j = gens.g_vec[j * n ..][0..n];
        const h_j = gens.h_vec[j * n ..][0..n];
        var v_bytes = scalarvec.zero;
        defer std.crypto.secureZero(u8, &v_bytes);
        std.mem.writeInt(u64, v_bytes[0..8], v, .little);
        return .{
            .v = rp.commit(gens, v_bytes, gamma.*),
            .a = scalarvec.mulCt(gens.h, out.alpha)
                .add(scalarvec.multiScalarMul(out.a_l, g_j) catch unreachable)
                .add(scalarvec.multiScalarMul(out.a_r, h_j) catch unreachable),
            .s = scalarvec.mulCt(gens.h, out.rho)
                .add(scalarvec.multiScalarMul(out.s_l, g_j) catch unreachable)
                .add(scalarvec.multiScalarMul(out.s_r, h_j) catch unreachable),
        };
    }

    /// Round 2: the party's slice of `l(X)`, `r(X)` (offset `y^{jn}`,
    /// weight `z^{2+j}`), `T1_j = t1_j G + tau1_j H`, `T2_j` likewise.
    pub fn applyBitChallenge(self: *Party, c: BitChallenge) PolyCommitment {
        const r = applyBitChallengeBody(self, c);
        rp.burnStack();
        return r;
    }

    noinline fn applyBitChallengeBody(self: *Party, c: BitChallenge) PolyCommitment {
        const n = self.gens.n;
        self.z = c.z;
        const zz = zPow(c.z, 2 + self.j);
        var yk = powUsize(c.y, self.j * n);
        var two_i = scalarvec.one;
        for (self.l0, self.r0, self.r1, self.a_l, self.a_r, self.s_r) |*l0, *r0, *r1, al, ar, sr| {
            l0.* = scalar.sub(al, c.z);
            r0.* = scalar.mulAdd(zz, two_i, scalar.mul(yk, scalar.add(ar, c.z)));
            r1.* = scalar.mul(yk, sr);
            yk = scalar.mul(yk, c.y);
            two_i = scalar.add(two_i, two_i);
        }
        var t1 = scalar.add(
            scalarvec.innerProduct(self.l0, self.r1) catch unreachable,
            scalarvec.innerProduct(self.s_l, self.r0) catch unreachable,
        );
        defer std.crypto.secureZero(u8, &t1);
        var t2 = scalarvec.innerProduct(self.s_l, self.r1) catch unreachable;
        defer std.crypto.secureZero(u8, &t2);
        return .{
            .t1 = scalarvec.mulCt(self.gens.g, t1).add(scalarvec.mulCt(self.gens.h, self.tau1)),
            .t2 = scalarvec.mulCt(self.gens.g, t2).add(scalarvec.mulCt(self.gens.h, self.tau2)),
        };
    }

    /// Round 3: the share. The party's secrets are no longer needed after
    /// it; `deinit` wipes them.
    pub fn applyPolyChallenge(self: *Party, c: PolyChallenge, out: *ProofShare) error{OutOfMemory}!void {
        const r = applyPolyChallengeBody(self, c, out);
        rp.burnStack();
        return r;
    }

    noinline fn applyPolyChallengeBody(self: *Party, c: PolyChallenge, out: *ProofShare) error{OutOfMemory}!void {
        const n = self.gens.n;
        const l = try self.allocator.alloc([32]u8, n);
        errdefer self.allocator.free(l);
        const r = try self.allocator.alloc([32]u8, n);
        for (l, r, self.l0, self.s_l, self.r0, self.r1) |*lo, *ro, l0, l1, r0, r1| {
            lo.* = scalar.mulAdd(l1, c.x, l0);
            ro.* = scalar.mulAdd(r1, c.x, r0);
        }
        const x2 = scalar.mul(c.x, c.x);
        var zg = scalar.mul(zPow(self.z, 2 + self.j), self.gamma);
        defer std.crypto.secureZero(u8, &zg);
        out.* = .{
            .t_x = scalarvec.innerProduct(l, r) catch unreachable,
            .t_x_blinding = scalar.add(scalar.mulAdd(self.tau2, x2, scalar.mul(self.tau1, c.x)), zg),
            .e_blinding = scalar.mulAdd(self.rho, c.x, self.alpha),
            .l_vec = l,
            .r_vec = r,
        };
    }

    pub fn deinit(self: *Party) void {
        for ([_][][32]u8{ self.a_l, self.a_r, self.s_l, self.s_r, self.l0, self.r0, self.r1 }) |b| {
            std.crypto.secureZero(u8, std.mem.sliceAsBytes(b));
            self.allocator.free(b);
        }
        std.crypto.secureZero(u8, &self.gamma);
        std.crypto.secureZero(u8, &self.alpha);
        std.crypto.secureZero(u8, &self.rho);
        std.crypto.secureZero(u8, &self.tau1);
        std.crypto.secureZero(u8, &self.tau2);
    }
};

fn zPow(z: [32]u8, e: usize) [32]u8 {
    return powUsize(z, e);
}

fn powUsize(b: [32]u8, e: usize) [32]u8 {
    var r = scalarvec.one;
    var base = b;
    var k = e;
    while (k != 0) : (k >>= 1) {
        if (k & 1 == 1) r = scalar.mul(r, base);
        base = scalar.mul(base, base);
    }
    return r;
}

/// The dealer of one aggregated proof over `m` parties. Public state only.
/// `transcript` is the one the verifier will use (in the state the verifier
/// starts from); the dealer advances it.
pub const Dealer = struct {
    gens: Generators,
    transcript: *Transcript,
    initial: Transcript,
    m: usize,
    bcs: []const BitCommitment = &.{},
    pcs: []const PolyCommitment = &.{},
    y: [32]u8 = scalarvec.zero,
    z: [32]u8 = scalarvec.zero,
    x: [32]u8 = scalarvec.zero,

    pub fn init(gens: Generators, transcript: *Transcript, m: usize) MpcError!Dealer {
        if (m == 0 or !std.math.isPowerOfTwo(m) or m > gens.parties) return error.InvalidAggregation;
        return .{ .gens = gens, .transcript = transcript, .initial = transcript.*, .m = m };
    }

    /// Round 1 → the bit challenge. `bcs[j]` is party `j`'s; the slice must
    /// stay alive until `receiveShares` returns.
    pub fn receiveBitCommitments(self: *Dealer, bcs: []const BitCommitment) MpcError!BitChallenge {
        if (bcs.len != self.m) return error.InvalidAggregation;
        self.bcs = bcs;
        rp.appendDomainSepMultiple(self.transcript, self.gens.n, self.m);
        var a = bcs[0].a;
        var s = bcs[0].s;
        for (bcs) |bc| self.transcript.appendPoint("V", bc.v);
        for (bcs[1..]) |bc| {
            a = a.add(bc.a);
            s = s.add(bc.s);
        }
        self.transcript.appendPoint("A", a);
        self.transcript.appendPoint("S", s);
        self.y = self.transcript.challengeScalar("y");
        self.z = self.transcript.challengeScalar("z");
        return .{ .y = self.y, .z = self.z };
    }

    /// Round 2 → the polynomial challenge (same lifetime rule as above).
    pub fn receivePolyCommitments(self: *Dealer, pcs: []const PolyCommitment) MpcError!PolyChallenge {
        if (pcs.len != self.m) return error.InvalidAggregation;
        self.pcs = pcs;
        var t1 = pcs[0].t1;
        var t2 = pcs[0].t2;
        for (pcs[1..]) |pc| {
            t1 = t1.add(pc.t1);
            t2 = t2.add(pc.t2);
        }
        self.transcript.appendPoint("T_1", t1);
        self.transcript.appendPoint("T_2", t2);
        self.x = self.transcript.challengeScalar("x");
        return .{ .x = self.x };
    }

    /// Round 3 → the aggregated proof, checked with `verifyMultiple`
    /// against the commitments. On failure every share is audited and
    /// `bad[j]` (`bad.len == m`) set for each one that fails.
    pub fn receiveShares(self: *Dealer, allocator: std.mem.Allocator, shares: []const ProofShare, bad: []bool) MpcError!rp.RangeProof {
        const n = self.gens.n;
        const m = self.m;
        if (shares.len != m or bad.len != m) return error.InvalidAggregation;
        for (shares) |sh| if (sh.l_vec.len != n or sh.r_vec.len != n) return error.MalformedShare;
        var t_x = scalarvec.zero;
        var t_x_blinding = scalarvec.zero;
        var e_blinding = scalarvec.zero;
        for (shares) |sh| {
            t_x = scalar.add(t_x, sh.t_x);
            t_x_blinding = scalar.add(t_x_blinding, sh.t_x_blinding);
            e_blinding = scalar.add(e_blinding, sh.e_blinding);
        }
        self.transcript.appendScalar("t_x", t_x);
        self.transcript.appendScalar("t_x_blinding", t_x_blinding);
        self.transcript.appendScalar("e_blinding", e_blinding);
        const w = self.transcript.challengeScalar("w");
        const q = scalarvec.mulCt(self.gens.g, w);

        const nm = n * m;
        var arena_state = std.heap.ArenaAllocator.init(allocator);
        defer arena_state.deinit();
        const scratch = arena_state.allocator();
        const l = try scratch.alloc([32]u8, nm);
        const r = try scratch.alloc([32]u8, nm);
        for (shares, 0..) |sh, j| {
            @memcpy(l[j * n ..][0..n], sh.l_vec);
            @memcpy(r[j * n ..][0..n], sh.r_vec);
        }
        const h_prime = try scratch.alloc(Ristretto255, nm);
        const y_inv = scalar.Scalar.fromBytes(self.y).invert().toBytes();
        {
            var p = scalarvec.one;
            for (h_prime, self.gens.h_vec[0..nm]) |*o, h| {
                o.* = scalarvec.mulCt(h, p);
                p = scalar.mul(p, y_inv);
            }
        }
        const ipa_proof = ipa.proveIpa(allocator, self.transcript, self.gens.g_vec[0..nm], h_prime, q, l, r) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.LengthMismatch, error.NotPowerOfTwo => unreachable,
        };
        var t1 = self.pcs[0].t1;
        var t2 = self.pcs[0].t2;
        var a = self.bcs[0].a;
        var s = self.bcs[0].s;
        for (self.pcs[1..], self.bcs[1..]) |pc, bc| {
            t1 = t1.add(pc.t1);
            t2 = t2.add(pc.t2);
            a = a.add(bc.a);
            s = s.add(bc.s);
        }
        const proof: rp.RangeProof = .{ .a = a, .s = s, .t1 = t1, .t2 = t2, .tau_x = t_x_blinding, .mu = e_blinding, .t_hat = t_x, .ipa = ipa_proof };

        const vs = try scratch.alloc(Ristretto255, m);
        for (vs, self.bcs) |*v, bc| v.* = bc.v;
        var vt = self.initial;
        if (rp.verifyMultiple(self.gens, &vt, vs, proof)) {
            @memset(bad, false);
            return proof;
        }
        proof.deinit(allocator);
        var any = false;
        for (shares, 0..) |sh, j| {
            bad[j] = !self.auditShare(j, sh);
            any = any or bad[j];
        }
        if (!any) @memset(bad, true); // every share audits but the sum fails: blame cannot be placed
        return error.MalformedProofShares;
    }

    /// dalek's `ProofShare::audit_share` for party `j` (public values only).
    pub fn auditShare(self: *const Dealer, j: usize, sh: ProofShare) bool {
        const n = self.gens.n;
        if (sh.l_vec.len != n or sh.r_vec.len != n) return false;
        const bc = self.bcs[j];
        const pc = self.pcs[j];
        const z = self.z;
        const x = self.x;
        // t_x = <l, r>
        const ip = scalarvec.innerProduct(sh.l_vec, sh.r_vec) catch return false;
        if (!std.mem.eql(u8, &ip, &sh.t_x)) return false;
        // t_x G + t_x_blinding H == z^{2+j} V_j + delta_j G + x T1_j + x^2 T2_j
        const zz = zPow(z, 2 + j);
        var sum_y = scalarvec.zero;
        var yk = powUsize(self.y, j * n);
        for (0..n) |_| {
            sum_y = scalar.add(sum_y, yk);
            yk = scalar.mul(yk, self.y);
        }
        var two_n = scalarvec.one;
        for (0..n) |_| two_n = scalar.add(two_n, two_n);
        const sum_2n = scalar.sub(two_n, scalarvec.one);
        const delta = scalar.sub(scalar.mul(scalar.sub(z, scalar.mul(z, z)), sum_y), scalar.mul(scalar.mul(zz, z), sum_2n));
        const g = self.gens.g;
        const h = self.gens.h;
        const lhs = scalarvec.mulCt(g, sh.t_x);
        const lhs2 = lhs.add(scalarvec.mulCt(h, sh.t_x_blinding));
        const rhs = (scalarvec.mulCt(bc.v, zz))
            .add(scalarvec.mulCt(g, delta))
            .add(scalarvec.mulCt(pc.t1, x))
            .add(scalarvec.mulCt(pc.t2, scalar.mul(x, x)));
        if (!std.mem.eql(u8, &lhs2.toBytes(), &rhs.toBytes())) return false;
        // <l, G_j> + <r y^{-k}, H_j> + e H == A_j + x S_j - z <1, G_j> + <z + z^{2+j} 2^i y^{-k}, H_j>
        const g_j = self.gens.g_vec[j * n ..][0..n];
        const h_j = self.gens.h_vec[j * n ..][0..n];
        const y_inv = scalar.Scalar.fromBytes(self.y).invert().toBytes();
        var yinv_k = powUsize(y_inv, j * n);
        var two_i = scalarvec.one;
        var left = scalarvec.mulCt(h, sh.e_blinding);
        var right = bc.a.add(scalarvec.mulCt(bc.s, x));
        const neg_z = scalar.neg(z);
        for (0..n) |i| {
            left = left.add(scalarvec.mulCt(g_j[i], sh.l_vec[i]))
                .add(scalarvec.mulCt(h_j[i], scalar.mul(sh.r_vec[i], yinv_k)));
            right = right.add(scalarvec.mulCt(g_j[i], neg_z))
                .add(scalarvec.mulCt(h_j[i], scalar.add(z, scalar.mul(scalar.mul(zz, two_i), yinv_k))));
            yinv_k = scalar.mul(yinv_k, y_inv);
            two_i = scalar.add(two_i, two_i);
        }
        return std.mem.eql(u8, &left.toBytes(), &right.toBytes());
    }
};

// ── tests ──────────────────────────────────────────────────────────────

const testing = std.testing;
const talloc = testing.allocator;

const Run = struct {
    proof: rp.RangeProof,
    vs: [8]Ristretto255,
};

fn gammaFor(j: usize) [32]u8 {
    var g: [32]u8 = @splat(0);
    std.mem.writeInt(u64, g[0..8], 0x9e37_79b9_7f4a_7c15 *% (@as(u64, j) + 1), .little);
    return scalar.reduce(g);
}

/// The whole protocol for `values`; `corrupt` (party index) flips one
/// byte of that party's `l_vec` before the dealer sees it.
fn runMpc(gens: Generators, values: []const u64, corrupt: ?usize, bad: []bool) MpcError!Run {
    const m = values.len;
    var t = Transcript.init("mpc test");
    var dealer = try Dealer.init(gens, &t, m);
    var parties: [8]Party = undefined;
    var bcs: [8]BitCommitment = undefined;
    var made: usize = 0;
    defer for (parties[0..made]) |*p| p.deinit();
    for (values, 0..) |v, j| {
        bcs[j] = try Party.init(&parties[j], talloc, testing.io, gens, j, v, &gammaFor(j));
        made += 1;
    }
    const bit_c = try dealer.receiveBitCommitments(bcs[0..m]);
    var pcs: [8]PolyCommitment = undefined;
    for (parties[0..m], 0..) |*p, j| pcs[j] = p.applyBitChallenge(bit_c);
    const poly_c = try dealer.receivePolyCommitments(pcs[0..m]);
    var shares: [8]ProofShare = undefined;
    var nshares: usize = 0;
    defer for (shares[0..nshares]) |sh| sh.deinit(talloc);
    for (parties[0..m], 0..) |*p, j| {
        try p.applyPolyChallenge(poly_c, &shares[j]);
        nshares += 1;
    }
    if (corrupt) |c| shares[c].l_vec[0][0] ^= 1;
    var run: Run = .{ .proof = try dealer.receiveShares(talloc, shares[0..m], bad), .vs = undefined };
    for (bcs[0..m], 0..) |bc, j| run.vs[j] = bc.v;
    return run;
}

test "mpc: m = 1, 2, 4 parties build one aggregated proof that verifyMultiple accepts" {
    const gens = try Generators.initParties(talloc, 16, 4);
    defer gens.deinit(talloc);
    const sets = [_][]const u64{ &.{7}, &.{ 0, 65535 }, &.{ 1, 2, 3, 40000 } };
    for (sets) |values| {
        var bad: [4]bool = undefined;
        const run = try runMpc(gens, values, null, bad[0..values.len]);
        defer run.proof.deinit(talloc);
        var t = Transcript.init("mpc test");
        try testing.expect(rp.verifyMultiple(gens, &t, run.vs[0..values.len], run.proof));
        // Another transcript label does not verify; nor do reordered commitments.
        var t2 = Transcript.init("other");
        try testing.expect(!rp.verifyMultiple(gens, &t2, run.vs[0..values.len], run.proof));
        if (values.len > 1) {
            var swapped = run.vs;
            std.mem.swap(Ristretto255, &swapped[0], &swapped[1]);
            var t3 = Transcript.init("mpc test");
            try testing.expect(!rp.verifyMultiple(gens, &t3, swapped[0..values.len], run.proof));
        }
    }
}

test "mpc: a corrupted share is MalformedProofShares and blamed on its party only" {
    const gens = try Generators.initParties(talloc, 8, 4);
    defer gens.deinit(talloc);
    for (0..4) |c| {
        var bad: [4]bool = undefined;
        try testing.expectError(error.MalformedProofShares, runMpc(gens, &.{ 5, 6, 7, 8 }, c, &bad));
        for (bad, 0..) |b, j| try testing.expectEqual(j == c, b);
    }
}

test "mpc: honest shares pass the audit" {
    const gens = try Generators.initParties(talloc, 8, 2);
    defer gens.deinit(talloc);
    var t = Transcript.init("mpc audit");
    var dealer = try Dealer.init(gens, &t, 2);
    var parties: [2]Party = undefined;
    var bcs: [2]BitCommitment = undefined;
    for (&parties, 0..) |*p, j| bcs[j] = try Party.init(p, talloc, testing.io, gens, j, 100 + j, &gammaFor(j));
    defer for (&parties) |*p| p.deinit();
    const bit_c = try dealer.receiveBitCommitments(&bcs);
    var pcs: [2]PolyCommitment = undefined;
    for (&parties, 0..) |*p, j| pcs[j] = p.applyBitChallenge(bit_c);
    const poly_c = try dealer.receivePolyCommitments(&pcs);
    var shares: [2]ProofShare = undefined;
    for (&parties, 0..) |*p, j| try p.applyPolyChallenge(poly_c, &shares[j]);
    defer for (shares) |sh| sh.deinit(talloc);
    for (shares, 0..) |sh, j| try testing.expect(dealer.auditShare(j, sh));
    // A share at the wrong position fails.
    try testing.expect(!dealer.auditShare(1, shares[0]));
}

test "mpc: malformed setups are refused" {
    const gens = try Generators.initParties(talloc, 8, 2);
    defer gens.deinit(talloc);
    var t = Transcript.init("x");
    try testing.expectError(error.InvalidAggregation, Dealer.init(gens, &t, 0));
    try testing.expectError(error.InvalidAggregation, Dealer.init(gens, &t, 3));
    try testing.expectError(error.InvalidAggregation, Dealer.init(gens, &t, 4));
    var p: Party = undefined;
    try testing.expectError(error.InvalidPosition, Party.init(&p, talloc, testing.io, gens, 2, 1, &gammaFor(0)));
    try testing.expectError(error.ValueOutOfRange, Party.init(&p, talloc, testing.io, gens, 0, 256, &gammaFor(0)));
    var dealer = try Dealer.init(gens, &t, 2);
    const one: [1]BitCommitment = undefined;
    try testing.expectError(error.InvalidAggregation, dealer.receiveBitCommitments(&one));
}
