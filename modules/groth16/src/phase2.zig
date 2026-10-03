// SPDX-License-Identifier: MIT
//! The circuit-specific half of a Groth16 trusted setup ("phase 2"), over a
//! phase-1 powers-of-tau file — the real replacement for `prover.setup`'s
//! plaintext toxic waste:
//!
//!   - `newZkey(r1cs, ptau)`: the initial proving key (δ = 1). Every secret
//!     comes from the ceremony behind the `.ptau`; nothing secret exists here.
//!   - `contribute(zkey, x)`: one MPC contribution — multiplies δ by a secret
//!     `x` the contributor draws and then forgets. As long as ONE contributor
//!     forgot theirs, no one knows δ.
//!   - `verify(r1cs, ptau, zkey)`: whether a key someone hands you is a
//!     well-formed Groth16 key for this circuit over this ceremony, for SOME δ.
//!
//! ## Compatibility with snarkjs (measured, `snarkjs_files_test.zig`)
//!
//! `newZkey` reproduces `snarkjs groth16 setup` byte for byte in every
//! section except the 64-byte circuit hash of section 10. snarkjs derives
//! that hash in a way 29 340 candidate constructions (orders × encodings ×
//! subsets of the point sections, blake2b-512) did not reproduce, and its
//! source is GPL, so it is not read to find out. Here the hash is
//! `blake2b-512` over sections 3, 5, 6, 7, 8, 9 as written; snarkjs's own
//! `zkey verify` therefore rejects a key made here ("Circuit does not
//! match"), while `groth16 prove` accepts it. Likewise `contribute` writes a
//! proof of knowledge of its own construction (below), which snarkjs's
//! `zkey verify` cannot check. SPEC.md backlog.
//!
//! ## The contribution record: a consistency proof, NOT a proof of knowledge
//!
//! `g1_s = [s]₁`, `g1_sx = [s·x]₁`, `g2_sp = [h]₂` with `h` a hash of the
//! record's transcript, `g2_spx = [x]·g2_sp`. `verifyContribution` checks
//! `e(g1_s, g2_spx) = e(g1_sx, g2_sp)` and `e(δ_before, g2_spx) =
//! e(δ_after, g2_sp)`: δ moved by the same `x` in G1 and G2, and the record
//! (name included) is the one its transcript names.
//!
//! ⛔ It does NOT show that the contributor KNEW `x`. `h` is public, so
//! anyone reads `[x]₂ = h⁻¹·g2_spx` off a published record, and can then
//! write a valid record for `x' = k·x_prev` without knowing `x'` (review
//! 2026-10-02). What still holds: making the final δ a value you know needs
//! `[x]₂` for `x = known/δ_before`, i.e. `[1/δ_before]₂`, which no record
//! reveals — so a ceremony with one honest contributor still ends at a δ
//! nobody knows. A real proof of knowledge needs a `g2_sp` of unknown
//! discrete log (hash-to-G2) — SPEC.md backlog.

const std = @import("std");
const bn254 = @import("bn254");
const bin = @import("snarkjs_bin.zig");
const zkey_mod = @import("zkey.zig");
const circom = @import("circom.zig");
const ptau_mod = @import("ptau.zig");
const msm = @import("msm.zig");

const Fr = bn254.Fr;
const G1 = bn254.G1;
const G2 = bn254.G2;
const ZKey = zkey_mod.ZKey;
const Coef = zkey_mod.Coef;
const Ptau = ptau_mod.Ptau;
const Allocator = std.mem.Allocator;
const Blake2b512 = std.crypto.hash.blake2.Blake2b512;

pub const Error = error{
    /// The ceremony's power is too small for this circuit's domain.
    PtauTooSmall,
    /// More than 2²⁷ rows (constraints + public signals + 1): the prover's
    /// coset needs a root of unity of twice the domain, and `Fr` has 2²⁸.
    CircuitTooLarge,
} || bin.ParseError || Allocator.Error;

/// The initial phase-2 key for `r` over `p` (δ = γ = 1).
pub fn newZkey(allocator: Allocator, r: circom.R1cs, p: Ptau) Error!ZKey {
    const n_public = r.nPublic();
    const n_vars = r.n_wires;
    const rows = @as(u64, r.constraints.len) + n_public + 1;
    const log_n: u5 = blk: {
        var l: u6 = 1;
        while ((@as(u64, 1) << l) < rows) : (l += 1) if (l == 28) return error.CircuitTooLarge;
        break :blk @intCast(l);
    };
    if (log_n > p.power) return error.PtauTooSmall;
    const n: usize = @as(usize, 1) << log_n;

    // Coefficients: A then B of every constraint, then A[m + i][i] = 1.
    var coefs: std.ArrayList(Coef) = .empty;
    defer coefs.deinit(allocator);
    for (r.constraints, 0..) |con, i| {
        for (con.a) |t| try coefs.append(allocator, .{ .matrix = .a, .constraint = @intCast(i), .signal = @intCast(t.index), .value = t.coeff });
        for (con.b) |t| try coefs.append(allocator, .{ .matrix = .b, .constraint = @intCast(i), .signal = @intCast(t.index), .value = t.coeff });
    }
    for (0..n_public + 1) |i| try coefs.append(allocator, .{
        .matrix = .a,
        .constraint = @intCast(r.constraints.len + i),
        .signal = @intCast(i),
        .value = Fr.one,
    });

    // The Lagrange bases this domain needs, decoded once.
    const l_tau = try decodeG1(allocator, try p.lagrangeBytes(.tau_g1, log_n));
    defer allocator.free(l_tau);
    const l_alpha = try decodeG1(allocator, try p.lagrangeBytes(.alpha_tau_g1, log_n));
    defer allocator.free(l_alpha);
    const l_beta = try decodeG1(allocator, try p.lagrangeBytes(.beta_tau_g1, log_n));
    defer allocator.free(l_beta);
    const l_tau2 = try allocator.alloc(G2.Affine, n);
    defer allocator.free(l_tau2);
    try bin.g2SliceUnchecked(try p.lagrangeBytes(.tau_g2, log_n), l_tau2);

    // Per-signal term lists, built once: A and B from the coefficient list
    // (which has the public rows), C straight from the r1cs.
    var ga = try SignalTerms.fromCoefs(allocator, coefs.items, .a, n_vars);
    defer ga.deinit(allocator);
    var gb = try SignalTerms.fromCoefs(allocator, coefs.items, .b, n_vars);
    defer gb.deinit(allocator);
    var gc = try SignalTerms.fromR1csC(allocator, r);
    defer gc.deinit(allocator);
    var scratch: Scratch = .{};
    defer scratch.deinit(allocator);

    var z: ZKey = .{
        .n_vars = n_vars,
        .n_public = n_public,
        .domain_size = @intCast(n),
        .alpha_g1 = try p.alphaG1(),
        .beta_g1 = try p.betaG1(),
        .beta_g2 = try p.betaG2(),
        .gamma_g2 = G2.Affine.generator,
        .delta_g1 = G1.Affine.generator,
        .delta_g2 = G2.Affine.generator,
        .ic = &.{},
        .coefs = &.{},
        .a = &.{},
        .b_g1 = &.{},
        .b_g2 = &.{},
        .c = &.{},
        .h = &.{},
        .circuit_hash = undefined,
        .contributions = &.{},
    };
    errdefer z.deinit(allocator);
    z.a = try allocator.alloc(G1.Affine, n_vars);
    z.b_g1 = try allocator.alloc(G1.Affine, n_vars);
    z.b_g2 = try allocator.alloc(G2.Affine, n_vars);
    z.ic = try allocator.alloc(G1.Affine, n_public + 1);
    z.c = try allocator.alloc(G1.Affine, n_vars - n_public - 1);
    z.h = try allocator.alloc(G1.Affine, n);

    // [A_j(τ)]₁, [B_j(τ)]₁,₂, and [(β·A_j + α·B_j + C_j)(τ)]₁ — IC for the
    // public signals, C (÷δ = 1) for the private ones.
    for (0..n_vars) |j| {
        z.a[j] = (try scratch.msmG1(allocator, ga, j, l_tau)).toAffine();
        z.b_g1[j] = (try scratch.msmG1(allocator, gb, j, l_tau)).toAffine();
        z.b_g2[j] = (try scratch.msmG2(allocator, gb, j, l_tau2)).toAffine();
        var acc = try scratch.msmG1(allocator, ga, j, l_beta);
        acc = acc.add(try scratch.msmG1(allocator, gb, j, l_alpha));
        acc = acc.add(try scratch.msmG1(allocator, gc, j, l_tau));
        if (j <= n_public) z.ic[j] = acc.toAffine() else z.c[j - n_public - 1] = acc.toAffine();
    }

    // H_i = [L^{2n}_{2i+1}(τ)]₁ (zkprove.zig derives why).
    const l2 = try p.lagrangeBytes(.tau_g1, log_n + 1);
    for (z.h, 0..) |*out, i| out.* = try bin.g1FromBytes(l2[(2 * i + 1) * bin.g1_bytes ..][0..bin.g1_bytes]);

    z.coefs = try coefs.toOwnedSlice(allocator);
    z.circuit_hash = circuitHash(z);
    return z;
}

fn decodeG1(allocator: Allocator, bytes: []const u8) Error![]G1.Affine {
    const out = try allocator.alloc(G1.Affine, bytes.len / bin.g1_bytes);
    errdefer allocator.free(out);
    try bin.g1Slice(bytes, out);
    return out;
}

/// The (constraint, value) terms of one matrix, grouped by signal (CSR):
/// signal `j`'s terms are `rows[start[j]..start[j + 1]]`, in file order.
const SignalTerms = struct {
    rows: []u32,
    vals: []Fr,
    start: []usize,

    fn deinit(self: *SignalTerms, allocator: Allocator) void {
        allocator.free(self.rows);
        allocator.free(self.vals);
        allocator.free(self.start);
    }

    fn alloc(allocator: Allocator, n_vars: usize, total: usize) Allocator.Error!SignalTerms {
        const start = try allocator.alloc(usize, n_vars + 1);
        errdefer allocator.free(start);
        @memset(start, 0);
        const rows = try allocator.alloc(u32, total);
        errdefer allocator.free(rows);
        return .{ .rows = rows, .vals = try allocator.alloc(Fr, total), .start = start };
    }

    /// Turns per-signal counts in `start[j + 1]` into offsets, and returns a
    /// cursor array (owned by the caller) positioned at each signal's start.
    fn offsets(self: *SignalTerms, allocator: Allocator) Allocator.Error![]usize {
        for (1..self.start.len) |k| self.start[k] += self.start[k - 1];
        return allocator.dupe(usize, self.start[0 .. self.start.len - 1]);
    }

    fn fromCoefs(allocator: Allocator, coefs: []const Coef, which: Coef.Matrix, n_vars: usize) Allocator.Error!SignalTerms {
        var total: usize = 0;
        for (coefs) |co| total += @intFromBool(co.matrix == which);
        var self = try alloc(allocator, n_vars, total);
        errdefer self.deinit(allocator);
        for (coefs) |co| if (co.matrix == which) {
            self.start[co.signal + 1] += 1;
        };
        const cursor = try self.offsets(allocator);
        defer allocator.free(cursor);
        for (coefs) |co| if (co.matrix == which) {
            self.rows[cursor[co.signal]] = co.constraint;
            self.vals[cursor[co.signal]] = co.value;
            cursor[co.signal] += 1;
        };
        return self;
    }

    fn fromR1csC(allocator: Allocator, r: circom.R1cs) Allocator.Error!SignalTerms {
        var total: usize = 0;
        for (r.constraints) |con| total += con.c.len;
        var self = try alloc(allocator, r.n_wires, total);
        errdefer self.deinit(allocator);
        for (r.constraints) |con| for (con.c) |t| {
            self.start[t.index + 1] += 1;
        };
        const cursor = try self.offsets(allocator);
        defer allocator.free(cursor);
        for (r.constraints, 0..) |con, i| for (con.c) |t| {
            self.rows[cursor[t.index]] = @intCast(i);
            self.vals[cursor[t.index]] = t.coeff;
            cursor[t.index] += 1;
        };
        return self;
    }
};

/// Gather buffers for one signal's bases, reused across signals.
const Scratch = struct {
    g1: std.ArrayList(G1.Affine) = .empty,
    g2: std.ArrayList(G2.Affine) = .empty,

    fn deinit(self: *Scratch, allocator: Allocator) void {
        self.g1.deinit(allocator);
        self.g2.deinit(allocator);
    }

    fn msmG1(self: *Scratch, allocator: Allocator, t: SignalTerms, j: usize, basis: []const G1.Affine) Allocator.Error!G1.Jacobian {
        const lo = t.start[j];
        const hi = t.start[j + 1];
        try self.g1.resize(allocator, hi - lo);
        for (t.rows[lo..hi], self.g1.items) |row, *b| b.* = basis[row];
        return msm.pippengerG1(allocator, self.g1.items, t.vals[lo..hi]);
    }

    fn msmG2(self: *Scratch, allocator: Allocator, t: SignalTerms, j: usize, basis: []const G2.Affine) Allocator.Error!G2.Jacobian {
        const lo = t.start[j];
        const hi = t.start[j + 1];
        try self.g2.resize(allocator, hi - lo);
        for (t.rows[lo..hi], self.g2.items) |row, *b| b.* = basis[row];
        return msm.pippengerG2(allocator, self.g2.items, t.vals[lo..hi]);
    }
};

/// This module's circuit hash (NOT snarkjs's — see the module doc):
/// blake2b-512 over sections 3, 5, 6, 7, 8, 9 as `zkey.write` encodes them,
/// computed on the initial key (δ = 1) so it names the circuit, not a
/// contribution.
pub fn circuitHash(z: ZKey) [64]u8 {
    var h = Blake2b512.init(.{});
    for (z.ic) |p| h.update(&bin.g1ToBytes(p));
    for (z.a) |p| h.update(&bin.g1ToBytes(p));
    for (z.b_g1) |p| h.update(&bin.g1ToBytes(p));
    for (z.b_g2) |p| h.update(&bin.g2ToBytes(p));
    for (z.c) |p| h.update(&bin.g1ToBytes(p));
    for (z.h) |p| h.update(&bin.g1ToBytes(p));
    var out: [64]u8 = undefined;
    h.final(&out);
    return out;
}

// ── contribution ────────────────────────────────────────────────────────────

/// Applies one contribution to `z` in place: δ ← x·δ, C and H ← x⁻¹·(C, H),
/// and appends a record carrying a proof of knowledge of `x`. `x` and `s`
/// must be fresh uniform secrets (`Fr.random(io)`) that the caller destroys
/// afterwards — the ceremony's security is that SOME contributor's `x` is
/// gone. `name` is stored in the record (≤ 255 bytes). This function's own
/// copies of `x` are wiped; the caller wipes theirs.
pub fn contribute(allocator: Allocator, z: *ZKey, x: Fr, s: Fr, name: []const u8) (error{ TrivialSecret, NameTooLong } || Allocator.Error)!void {
    // x = 1 would add a record that moved nothing.
    if (x.isZero() or x.eql(Fr.one) or s.isZero()) return error.TrivialSecret;
    if (name.len > 255) return error.NameTooLong;
    var x_inv = x.inv() catch unreachable;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&x_inv));

    const params = try allocator.alloc(u8, 2 + name.len);
    errdefer allocator.free(params);
    params[0] = 1;
    params[1] = @intCast(name.len);
    @memcpy(params[2..], name);
    const list = try allocator.alloc(zkey_mod.Contribution, z.contributions.len + 1);
    // Nothing below can fail: `z` is updated completely or not at all.
    @memcpy(list[0..z.contributions.len], z.contributions);

    const delta_before = z.delta_g1;
    const prev_transcript: [64]u8 = if (z.contributions.len == 0) z.circuit_hash else z.contributions[z.contributions.len - 1].transcript;
    z.delta_g1 = G1.Jacobian.fromAffine(z.delta_g1).scalarMul(x).toAffine();
    z.delta_g2 = G2.Jacobian.fromAffine(z.delta_g2).scalarMul(x).toAffine();
    for (z.c) |*p| p.* = G1.Jacobian.fromAffine(p.*).scalarMul(x_inv).toAffine();
    for (z.h) |*p| p.* = G1.Jacobian.fromAffine(p.*).scalarMul(x_inv).toAffine();

    var rec: zkey_mod.Contribution = .{
        .delta_after = z.delta_g1,
        .g1_s = mulG1(s),
        .g1_sx = mulG1(s.mul(x)),
        .g2_spx = undefined,
        .transcript = undefined,
        .type = 0,
        .params = params,
    };
    rec.transcript = transcriptOf(prev_transcript, delta_before, rec);
    rec.g2_spx = G2.Jacobian.fromAffine(g2Sp(rec.transcript)).scalarMul(x).toAffine();
    list[list.len - 1] = rec;
    allocator.free(z.contributions);
    z.contributions = list;
}

fn mulG1(k: Fr) G1.Affine {
    return G1.Jacobian.fromAffine(G1.Affine.generator).scalarMul(k).toAffine();
}

/// The record's transcript: what the proof of knowledge is bound to.
fn transcriptOf(prev: [64]u8, delta_before: G1.Affine, rec: zkey_mod.Contribution) [64]u8 {
    var h = Blake2b512.init(.{});
    h.update("zig-libs groth16 phase2 contribution v1");
    h.update(&prev);
    h.update(&bin.g1ToBytes(delta_before));
    h.update(&bin.g1ToBytes(rec.delta_after));
    h.update(&bin.g1ToBytes(rec.g1_s));
    h.update(&bin.g1ToBytes(rec.g1_sx));
    h.update(rec.params);
    var out: [64]u8 = undefined;
    h.final(&out);
    return out;
}

fn g2Sp(transcript: [64]u8) G2.Affine {
    return G2.Jacobian.fromAffine(G2.Affine.generator).scalarMul(Fr.reduceWide(&transcript)).toAffine();
}

/// `e(a1, b2) == e(a2, b1)`: the G1 pair and the G2 pair have the same ratio.
fn ratioMatches(a1: G1.Affine, a2: G1.Affine, b1: G2.Affine, b2: G2.Affine) bool {
    const neg_a2 = G1.Jacobian.fromAffine(a2).negate().toAffine();
    return bn254.pairing.pairingCheck(&.{ .{ .p = a1, .q = b2 }, .{ .p = neg_a2, .q = b1 } });
}

/// Checks the proof of knowledge of contribution `k` of `z` — one made by
/// `contribute`. A snarkjs record fails here (its `g2_sp` is not derived
/// the way `g2Sp` derives ours); `verify` does not need it.
pub fn verifyContribution(z: ZKey, k: usize) bool {
    if (k >= z.contributions.len) return false;
    const rec = z.contributions[k];
    const delta_before = if (k == 0) G1.Affine.generator else z.contributions[k - 1].delta_after;
    const prev: [64]u8 = if (k == 0) z.circuit_hash else z.contributions[k - 1].transcript;
    if (!std.mem.eql(u8, &transcriptOf(prev, delta_before, rec), &rec.transcript)) return false;
    if (rec.g1_s.infinity or rec.delta_after.infinity) return false;
    const sp = g2Sp(rec.transcript);
    return ratioMatches(rec.g1_s, rec.g1_sx, sp, rec.g2_spx) and
        ratioMatches(delta_before, rec.delta_after, sp, rec.g2_spx);
}

// ── verification ────────────────────────────────────────────────────────────

pub const Verdict = enum {
    ok,
    /// Size, coefficients, IC, A, B or the α/β/γ points differ from what the
    /// r1cs and ptau give.
    circuit_mismatch,
    /// δ₁ and δ₂ are not the same scalar, δ is zero, or δ₂ is not in G2.
    bad_delta,
    /// C or H are not the initial values divided by δ.
    not_divided_by_delta,
    /// The last contribution record does not end at the key's δ₁.
    chain_mismatch,
};

/// Whether `z` is a well-formed Groth16 key for `r` over `p`, for SOME δ:
/// every δ-independent part equals a fresh `newZkey`, `[δ]₁`/`[δ]₂` agree,
/// and C and H equal the fresh values divided by δ (checked as one random
/// linear combination, `io` supplying the coefficients).
///
/// What it does NOT check: the circuit hash (snarkjs's differs from this
/// module's, so comparing would refuse every snarkjs key) and the
/// contribution records beyond "the last one ends at δ₁" —
/// `verifyContribution` checks records made here. The `.ptau` is trusted: its
/// G2 points are not subgroup-checked and its ceremony is not verified.
pub fn verify(allocator: Allocator, io: std.Io, r: circom.R1cs, p: Ptau, z: ZKey) Error!Verdict {
    var fresh = try newZkey(allocator, r, p);
    defer fresh.deinit(allocator);

    if (z.n_vars != fresh.n_vars or z.n_public != fresh.n_public or z.domain_size != fresh.domain_size or
        z.coefs.len != fresh.coefs.len or z.c.len != fresh.c.len or z.h.len != fresh.h.len or
        z.ic.len != fresh.ic.len or z.a.len != fresh.a.len or z.b_g1.len != fresh.b_g1.len or
        z.b_g2.len != fresh.b_g2.len) return .circuit_mismatch;
    for (z.coefs, fresh.coefs) |a, b| {
        if (a.matrix != b.matrix or a.constraint != b.constraint or a.signal != b.signal or !a.value.eql(b.value)) return .circuit_mismatch;
    }
    if (!eqG1(z.alpha_g1, fresh.alpha_g1) or !eqG1(z.beta_g1, fresh.beta_g1) or
        !eqG2(z.beta_g2, fresh.beta_g2) or !eqG2(z.gamma_g2, fresh.gamma_g2)) return .circuit_mismatch;
    if (!allEqG1(z.ic, fresh.ic) or !allEqG1(z.a, fresh.a) or !allEqG1(z.b_g1, fresh.b_g1)) return .circuit_mismatch;
    for (z.b_g2, fresh.b_g2) |a, b| if (!eqG2(a, b)) return .circuit_mismatch;

    if (z.delta_g1.infinity or z.delta_g2.infinity) return .bad_delta;
    if (!G2.Jacobian.fromAffine(z.delta_g2).subgroupCheck()) return .bad_delta;
    if (!ratioMatches(G1.Affine.generator, z.delta_g1, G2.Affine.generator, z.delta_g2)) return .bad_delta;

    // Σ ρᵢ·(C ‖ H)ᵢ · δ == Σ ρᵢ·(C⁰ ‖ H⁰)ᵢ.
    const total = z.c.len + z.h.len;
    const rho = try allocator.alloc(Fr, total);
    defer allocator.free(rho);
    for (rho) |*v| v.* = Fr.random(io);
    const lhs = (try msm.pippengerG1(allocator, z.c, rho[0..z.c.len])).add(try msm.pippengerG1(allocator, z.h, rho[z.c.len..]));
    const rhs = (try msm.pippengerG1(allocator, fresh.c, rho[0..z.c.len])).add(try msm.pippengerG1(allocator, fresh.h, rho[z.c.len..]));
    // e(Σρ·X, δ₂) == e(Σρ·X⁰, [1]₂).
    if (!ratioMatches(lhs.toAffine(), rhs.toAffine(), G2.Affine.generator, z.delta_g2)) return .not_divided_by_delta;
    if (z.contributions.len == 0) {
        if (!eqG1(z.delta_g1, G1.Affine.generator)) return .chain_mismatch;
    } else if (!eqG1(z.contributions[z.contributions.len - 1].delta_after, z.delta_g1)) return .chain_mismatch;
    return .ok;
}

fn eqG1(a: G1.Affine, b: G1.Affine) bool {
    if (a.infinity or b.infinity) return a.infinity == b.infinity;
    return a.x.eql(b.x) and a.y.eql(b.y);
}

fn eqG2(a: G2.Affine, b: G2.Affine) bool {
    if (a.infinity or b.infinity) return a.infinity == b.infinity;
    return a.x.eql(b.x) and a.y.eql(b.y);
}

fn allEqG1(a: []const G1.Affine, b: []const G1.Affine) bool {
    for (a, b) |x, y| if (!eqG1(x, y)) return false;
    return true;
}

// ── tests (internals) ───────────────────────────────────────────────────────

test "verifyContribution: a δ that the proof of knowledge does not account for" {
    // A contributor who knows their own x can build a record whose proof is
    // valid for x and still set δ_after to something else (e.g. a value that
    // cancels earlier contributions). Only the second same-ratio check, δ
    // against the G2 pair, sees it.
    const testing = std.testing;
    var z = try zkey_mod.parse(testing.allocator, @embedFile("testdata/snarkjs/t0.zkey"));
    defer z.deinit(testing.allocator);
    const x = Fr.reduceWide(&[_]u8{7} ** 32);
    const s = Fr.reduceWide(&[_]u8{9} ** 32);
    try contribute(testing.allocator, &z, x, s, "mallory");
    try testing.expect(verifyContribution(z, 0));

    var rec = &z.contributions[0];
    rec.delta_after = mulG1(Fr.reduceWide(&[_]u8{5} ** 32));
    rec.transcript = transcriptOf(z.circuit_hash, G1.Affine.generator, rec.*);
    rec.g2_spx = G2.Jacobian.fromAffine(g2Sp(rec.transcript)).scalarMul(x).toAffine();
    // The first check (g1_s, g1_sx) still holds — the forgery is consistent there.
    try testing.expect(ratioMatches(rec.g1_s, rec.g1_sx, g2Sp(rec.transcript), rec.g2_spx));
    try testing.expect(!verifyContribution(z, 0));
}
