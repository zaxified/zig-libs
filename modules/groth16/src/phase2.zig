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
//! ## The contribution record: a proof of knowledge of `x`
//!
//! `g1_s = [s]₁`, `g1_sx = [s·x]₁`, `g2_sp = hashToG2(transcript)`,
//! `g2_spx = [x]·g2_sp`. `verifyContribution` checks
//! `e(g1_s, g2_spx) = e(g1_sx, g2_sp)` and `e(δ_before, g2_spx) =
//! e(δ_after, g2_sp)`: δ moved by the same `x` in G1 and G2, and the record
//! (name included) is the one its transcript names. `g2_sp` is hashed to the
//! curve (RFC 9380 SVDW, `hash_to_g2.zig`), so its discrete log is unknown
//! and `g2_spx` cannot be written without `x` — the knowledge-of-exponent
//! argument of the Bowe–Gabizon–Miers MPC (IACR ePrint 2017/1050). The tag
//! is this module's own (snarkjs derives its `g2_sp` differently), so a
//! record written by an earlier version (`[h]₂`, then try-and-increment)
//! fails here.

const std = @import("std");
const bn254 = @import("bn254");
const bin = @import("snarkjs_bin.zig");
const burn = @import("burn.zig");
const zkey_mod = @import("zkey.zig");
const circom = @import("circom.zig");
const ptau_mod = @import("ptau.zig");
const msm = @import("msm.zig");
const hash_to_g2 = @import("hash_to_g2.zig");

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
/// gone. `name` is stored in the record (≤ 255 bytes). `x` and `s` are taken by
/// pointer and never copied out of this call's burned frames (`x`, `x⁻¹`,
/// `s·x` and the multiplication frames are zeroed on return); the caller
/// wipes theirs.
pub fn contribute(allocator: Allocator, z: *ZKey, x: *const Fr, s: *const Fr, name: []const u8) (error{ TrivialSecret, NameTooLong } || Allocator.Error)!void {
    return burn.run(burn.contribute_burn, (error{ TrivialSecret, NameTooLong } || Allocator.Error)!void, contributeBody, .{ allocator, z, x, s, name });
}

fn contributeBody(allocator: Allocator, z: *ZKey, x_ptr: *const Fr, s_ptr: *const Fr, name: []const u8) (error{ TrivialSecret, NameTooLong } || Allocator.Error)!void {
    const x = x_ptr.*;
    const s = s_ptr.*;
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
    errdefer allocator.free(list);
    const scratch = try allocator.create(ScaleScratch);
    defer {
        std.crypto.secureZero(u8, std.mem.asBytes(scratch));
        allocator.destroy(scratch);
    }
    // Nothing below can fail: `z` is updated completely or not at all.
    @memcpy(list[0..z.contributions.len], z.contributions);

    const delta_before = z.delta_g1;
    const prev_transcript: [64]u8 = if (z.contributions.len == 0) z.circuit_hash else z.contributions[z.contributions.len - 1].transcript;
    z.delta_g1 = G1.Jacobian.fromAffine(z.delta_g1).scalarMul(x).toAffine();
    z.delta_g2 = G2.Jacobian.fromAffine(z.delta_g2).scalarMul(x).toAffine();
    var k_be = x_inv.toBytes();
    defer std.crypto.secureZero(u8, &k_be);
    scaleAll(scratch, z.c, &k_be);
    scaleAll(scratch, z.h, &k_be);

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
    return hashToG2(&transcript);
}

// ── hash-to-G2 ──────────────────────────────────────────────────────────────
//
// `g2_sp` must be a G2 point whose discrete log nobody knows, or `[x]₂` can be
// read off a record (§ 5b item 6). RFC 9380 `hash_to_curve` with the SVDW map
// (`hash_to_g2.zig`: gnark-crypto's `BN254G2_XMD:SHA-256_SVDW_RO_` suite) under
// this module's own domain separation tag.

/// The domain separation tag of `hashToG2` (RFC 9380 §3.1 shape).
pub const hash_to_g2_dst = "ZIG-LIBS-GROTH16-PHASE2-V2-CS01-with-BN254G2_XMD:SHA-256_SVDW_RO_";

/// A point of the order-r subgroup of G2 determined by `msg`, with a discrete
/// log nobody knows (in the random-oracle model): `hash_to_g2.hashToG2(msg,
/// hash_to_g2_dst)`.
pub fn hashToG2(msg: []const u8) G2.Affine {
    return hash_to_g2.hashToG2(msg, hash_to_g2_dst);
}

// ── rescaling C and H by 1/x ────────────────────────────────────────────────
//
// Every C/H point is multiplied by the same secret `1/x`, so the scalar's
// digits are read once and each point gets a 4-bit fixed window (16-entry
// table of public multiples of P, a constant-time scan to pick the entry, a
// complete add per window: 256 doublings + 64 adds instead of 256 + 256), then
// `scale_batch` results share one field inversion (Montgomery's trick) on the
// way back to affine. The Jacobian results and prefix products are wiped
// with the scratch (projective coordinates can leak about the scalar).

/// Points per shared inversion.
pub const scale_batch = 256;

/// Heap scratch for `scaleAll` (32 KiB: kept off the burned stack).
pub const ScaleScratch = struct {
    jac: [scale_batch]G1.Jacobian,
    pre: [scale_batch]bn254.Fp,
};

/// `pts[i] ← [k]·pts[i]` for the big-endian scalar `k_be`, constant-time in
/// `k_be` (the timing depends on `pts.len` and on which inputs are the point
/// at infinity, both public).
pub fn scaleAll(scratch: *ScaleScratch, pts: []G1.Affine, k_be: *const [32]u8) void {
    var i: usize = 0;
    while (i < pts.len) {
        const n = @min(scale_batch, pts.len - i);
        for (pts[i..][0..n], scratch.jac[0..n]) |pt, *j| j.* = mulWindowed(G1.Jacobian.fromAffine(pt), k_be);
        normalizeBatch(scratch, pts[i..][0..n]);
        i += n;
    }
}

fn ctSelectJ(cond: bool, a: G1.Jacobian, b: G1.Jacobian) G1.Jacobian {
    const Fp = bn254.Fp;
    return .{ .x = Fp.ctSelect(cond, a.x, b.x), .y = Fp.ctSelect(cond, a.y, b.y), .z = Fp.ctSelect(cond, a.z, b.z) };
}

/// `[k]P`, 4-bit fixed window, every table entry read on every window.
fn mulWindowed(p: G1.Jacobian, k_be: *const [32]u8) G1.Jacobian {
    var table: [16]G1.Jacobian = undefined;
    table[0] = G1.Jacobian.identity;
    table[1] = p;
    for (2..16) |t| table[t] = table[t - 1].add(p);
    var acc = G1.Jacobian.identity;
    for (k_be) |byte| {
        inline for (.{ 4, 0 }) |shift| {
            acc = acc.double().double().double().double();
            const digit: u8 = (byte >> shift) & 0xf;
            var sel = table[0];
            for (table[1..], 1..) |e, t| sel = ctSelectJ(t == digit, e, sel);
            acc = acc.add(sel);
        }
    }
    return acc;
}

/// `scratch.jac[0..out.len]` to affine with one inversion.
fn normalizeBatch(scratch: *ScaleScratch, out: []G1.Affine) void {
    const Fp = bn254.Fp;
    var acc = Fp.one;
    for (scratch.jac[0..out.len], scratch.pre[0..out.len]) |j, *pre| {
        pre.* = acc;
        if (!j.z.isZero()) acc = acc.mul(j.z);
    }
    var inv = acc.inv() catch unreachable; // a product of nonzero z
    var i = out.len;
    while (i > 0) {
        i -= 1;
        const j = scratch.jac[i];
        if (j.z.isZero()) {
            out[i] = G1.Affine.identity;
            continue;
        }
        const zi = inv.mul(scratch.pre[i]);
        inv = inv.mul(j.z);
        const zi2 = zi.square();
        out[i] = .{ .x = j.x.mul(zi2), .y = j.y.mul(zi2).mul(zi) };
    }
    std.crypto.secureZero(u8, std.mem.asBytes(&inv));
}

/// The plain form `scaleAll` replaced: one double-and-add-always `scalarMul`
/// and one inversion per point. Kept as the reference the tests and the
/// opt-in bench (`src/bench.zig`) compare against.
pub fn scaleAllRef(pts: []G1.Affine, k: Fr) void {
    for (pts) |*p| p.* = G1.Jacobian.fromAffine(p.*).scalarMul(k).toAffine();
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
    const x = Fr.reduceWide(&@as([32]u8, @splat(7)));
    const s = Fr.reduceWide(&@as([32]u8, @splat(9)));
    try contribute(testing.allocator, &z, &x, &s, "mallory");
    try testing.expect(verifyContribution(z, 0));

    var rec = &z.contributions[0];
    rec.delta_after = mulG1(Fr.reduceWide(&@as([32]u8, @splat(5))));
    rec.transcript = transcriptOf(z.circuit_hash, G1.Affine.generator, rec.*);
    rec.g2_spx = G2.Jacobian.fromAffine(g2Sp(rec.transcript)).scalarMul(x).toAffine();
    // The first check (g1_s, g1_sx) still holds — the forgery is consistent there.
    try testing.expect(ratioMatches(rec.g1_s, rec.g1_sx, g2Sp(rec.transcript), rec.g2_spx));
    try testing.expect(!verifyContribution(z, 0));
}

fn forgeBase(z: *ZKey, x: Fr, s: Fr) !*zkey_mod.Contribution {
    try contribute(std.testing.allocator, z, &x, &s, "forge");
    return &z.contributions[0];
}

test "verifyContribution: records that only a single guard or check rejects" {
    // Each forgery passes every check but one (the mutation audit found each
    // of these checks could be removed without a test noticing):
    //  - g1_s = g1_sx = infinity makes the proof of knowledge trivially true
    //    (e(inf, .) = 1) — only the `g1_s.infinity` guard refuses it;
    //  - delta_after = g1_sx = g2_spx = infinity satisfies both ratios — only
    //    the `delta_after.infinity` guard refuses it;
    //  - a g1_sx that is not s·x breaks only the first ratio.
    const testing = std.testing;
    const x = Fr.reduceWide(&@as([32]u8, @splat(7)));
    const s = Fr.reduceWide(&@as([32]u8, @splat(9)));
    const t0 = @embedFile("testdata/snarkjs/t0.zkey");

    var z = try zkey_mod.parse(testing.allocator, t0);
    defer z.deinit(testing.allocator);
    const rec = try forgeBase(&z, x, s);
    try testing.expect(verifyContribution(z, 0));
    const good = rec.*;
    const prev = z.circuit_hash;
    const gen = G1.Affine.generator;

    rec.g1_s = G1.Affine.identity;
    rec.g1_sx = G1.Affine.identity;
    rec.transcript = transcriptOf(prev, gen, rec.*);
    rec.g2_spx = G2.Jacobian.fromAffine(g2Sp(rec.transcript)).scalarMul(x).toAffine();
    try testing.expect(ratioMatches(rec.g1_s, rec.g1_sx, g2Sp(rec.transcript), rec.g2_spx));
    try testing.expect(ratioMatches(gen, rec.delta_after, g2Sp(rec.transcript), rec.g2_spx));
    try testing.expect(!verifyContribution(z, 0));

    rec.* = good;
    rec.delta_after = G1.Affine.identity;
    rec.g1_sx = G1.Affine.identity;
    rec.g2_spx = G2.Affine.identity;
    rec.transcript = transcriptOf(prev, gen, rec.*);
    try testing.expect(ratioMatches(rec.g1_s, rec.g1_sx, g2Sp(rec.transcript), rec.g2_spx));
    try testing.expect(ratioMatches(gen, rec.delta_after, g2Sp(rec.transcript), rec.g2_spx));
    try testing.expect(!verifyContribution(z, 0));

    rec.* = good;
    rec.g1_sx = mulG1(Fr.reduceWide(&@as([32]u8, @splat(5))));
    rec.transcript = transcriptOf(prev, gen, rec.*);
    rec.g2_spx = G2.Jacobian.fromAffine(g2Sp(rec.transcript)).scalarMul(x).toAffine();
    try testing.expect(ratioMatches(gen, rec.delta_after, g2Sp(rec.transcript), rec.g2_spx));
    try testing.expect(!verifyContribution(z, 0));
}

test "contribute: the record's transcript is the documented hash (independent derivation), type, name bounds" {
    // The transcript was derived outside this module (Python, 20 lines of
    // affine arithmetic over the base field plus blake2b):
    //   blake2b-512("zig-libs groth16 phase2 contribution v1" || prev || G1(delta_before)
    //   || G1(delta_after) || G1(s*G) || G1(s*x*G) || params), points as the
    // 64 Montgomery little-endian bytes of the zkey format, params = [1, len, name],
    // prev = the circuit hash of the key (a first contribution), delta_before = G.
    // That pins every input of the hash (mutants: each `h.update` dropped, the domain tag included).
    const testing = std.testing;
    const t0 = @embedFile("testdata/snarkjs/t0.zkey");
    const t1 = @embedFile("testdata/snarkjs/t1.zkey");
    var xb: [32]u8 = undefined;
    var sb: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&xb, "000000000000000000000000000000001234567890abcdef1234567890abcdef");
    _ = try std.fmt.hexToBytes(&sb, "00000000000000000000000000000000fedcba0987654321fedcba0987654321");
    const x = try Fr.fromBytes(xb);
    const s = try Fr.fromBytes(sb);

    var z = try zkey_mod.parse(testing.allocator, t0);
    defer z.deinit(testing.allocator);
    try contribute(testing.allocator, &z, &x, &s, "kat");
    var want: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, "8f78aeadcd14c662fb5b6952b5bb6fb23c373ddea5f5456878531e79b6b3ca5eeb94116465d79aae49d6e86d7d29a2e23efc18c8d436bafdce1fc0e90ef0f631");
    try testing.expectEqualSlices(u8, &want, &z.contributions[0].transcript);

    // snarkjs's own record in t1.zkey has the same `type` field value as ours.
    var t1z = try zkey_mod.parse(testing.allocator, t1);
    defer t1z.deinit(testing.allocator);
    try testing.expectEqual(t1z.contributions[0].type, z.contributions[0].type);

    // A name of 255 bytes fits the one-byte length; 256 does not.
    const long: [256]u8 = @splat('n');
    var z2 = try zkey_mod.parse(testing.allocator, t0);
    defer z2.deinit(testing.allocator);
    try testing.expectError(error.NameTooLong, contribute(testing.allocator, &z2, &x, &s, &long));
    try testing.expectEqual(@as(usize, 0), z2.contributions.len);
    try contribute(testing.allocator, &z2, &x, &s, long[0..255]);
    try testing.expectEqual(@as(usize, 255), z2.contributions[0].name().?.len);
}

test "hashToG2: on the curve, in the order-r subgroup, never the identity, deterministic, input-separated" {
    const testing = std.testing;
    var seen: [8]G2.Affine = undefined;
    for (&seen, 0..) |*pt, i| {
        const msg = [_]u8{ 'm', @intCast(i) };
        pt.* = hashToG2(&msg);
        try testing.expect(!pt.infinity);
        const j = G2.Jacobian.fromAffine(pt.*);
        try testing.expect(j.isOnCurve());
        try testing.expect(j.subgroupCheck());
        const again = hashToG2(&msg);
        try testing.expect(again.x.eql(pt.x) and again.y.eql(pt.y));
        for (seen[0..i]) |q| try testing.expect(!q.x.eql(pt.x));
    }
}

test "hashToG2: pinned under this module's tag (independent RFC 9380 model in Python)" {
    const testing = std.testing;
    var t: [64]u8 = undefined;
    for (&t, 0..) |*b, i| b.* = @truncate(i * 7 + 1);
    const got = bn254.g2.toBytes(hashToG2(&t));
    var want: [128]u8 = undefined;
    // EIP-197 order: x.c1 ‖ x.c0 ‖ y.c1 ‖ y.c0.
    _ = try std.fmt.hexToBytes(&want, "0883b96e1ab5bb828fcf893949740758f6145ba2735fb87263c90717c84c9257" ++
        "11bd384f53dc134b3b5869b1bbba412e498dff04bc39d01e6965a0336b19dbcf" ++
        "2f87fad00505331f5474f6667b88a2a39738aeaf80b1d057619a1a02043733ea" ++
        "1cb813966970251042fd7c6d9ab6c2b6e8ae3cd5f36de41ce6fac818863ec640");
    try testing.expectEqualSlices(u8, &want, &got);
}

test "a contribution record's g2_sp is the hashed point, not [h]₂ (the old, knowable construction fails)" {
    const testing = std.testing;
    var t: [64]u8 = undefined;
    for (&t, 0..) |*b, i| b.* = @truncate(i * 7 + 1);
    const sp = g2Sp(t);
    const old = G2.Jacobian.fromAffine(G2.Affine.generator).scalarMul(Fr.reduceWide(&t)).toAffine();
    try testing.expect(!sp.x.eql(old.x));
    const h = hashToG2(&t);
    try testing.expect(sp.x.eql(h.x) and sp.y.eql(h.y));
}

test "scaleAll equals scalarMul per point, across batch edges, with points at infinity" {
    const testing = std.testing;
    const gpa = testing.allocator;
    const n = scale_batch + 37;
    const a = try gpa.alloc(G1.Affine, n);
    defer gpa.free(a);
    const b = try gpa.alloc(G1.Affine, n);
    defer gpa.free(b);
    var acc = G1.Jacobian.fromAffine(G1.Affine.generator);
    const step = G1.Jacobian.fromAffine(G1.Affine.generator).scalarMul(Fr.reduceWide(&@as([64]u8, @splat(0x5a))));
    for (a, 0..) |*p, i| {
        p.* = if (i % 97 == 3) G1.Affine.identity else acc.toAffine();
        acc = acc.add(step);
    }
    const scratch = try gpa.create(ScaleScratch);
    defer gpa.destroy(scratch);
    var wide: [64]u8 = undefined;
    for (0..3) |round| {
        for (&wide, 0..) |*w, i| w.* = @truncate(i * 31 + round * 101 + 7);
        var k = Fr.reduceWide(&wide);
        if (round == 2) k = Fr.one.neg(); // r - 1, the largest scalar
        @memcpy(b, a);
        scaleAllRef(b, k);
        const got = try gpa.dupe(G1.Affine, a);
        defer gpa.free(got);
        const k_be = k.toBytes();
        scaleAll(scratch, got, &k_be);
        for (got, b) |g, w| {
            try testing.expectEqual(w.infinity, g.infinity);
            if (!w.infinity) try testing.expect(g.x.eql(w.x) and g.y.eql(w.y));
        }
    }
}
