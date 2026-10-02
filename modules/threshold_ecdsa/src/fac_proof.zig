// SPDX-License-Identifier: MIT
//! Πfac — "no small factor" proof, CGGMP21 (ePrint 2021/060) **Fig.28**.
//!
//! The prover knows `N0 = p·q` (its own Paillier modulus) and convinces a
//! verifier that neither factor is small. Without it a party that generates
//! its own Paillier key can pick `N0` with tiny prime factors; the GG18/GG20
//! MtA responses then leak an honest peer's share modulo each of them, and a
//! handful of sessions reconstruct it — the BitForge class (Fireblocks,
//! 2023). `aux_proofs.Pimod.provePaillier` proves `N0` is a Paillier-Blum
//! modulus; this proves its factors are large. Dealer-free keygen needs both
//! for every party's `N0`; under `keygenTrustedDealer` neither arises (the
//! dealer generates every key).
//!
//! The commitments live in the VERIFIER's ring-Pedersen group `(N̂, s, t)` —
//! its `AuxParams` (`s = h1`, `t = h2`) — so one proof is made per verifier.
//!
//! ```text
//! ℓ = 256 (|q|), ε = 2ℓ, S = ⌈bits(N0)/2⌉ (2^S ≥ √N0, and p, q < 2^S).
//! Prover:
//!   α, β ← [0, 2^{ℓ+ε+S})        μ, ν ← [0, 2^ℓ·N̂)
//!   σ ← [0, 2^ℓ·N0·N̂)            r ← [0, 2^{ℓ+ε}·N0·N̂)
//!   x, y ← [0, 2^{ℓ+ε}·N̂)
//!   P = s^p t^μ   Q = s^q t^ν   A = s^α t^x   B = s^β t^y   T = Q^α t^r   (mod N̂)
//!   e = H(context, N0, N̂, s, t, P, Q, A, B, T, σ) ∈ Zq
//!   z1 = α + e·p   z2 = β + e·q   w1 = x + e·μ   w2 = y + e·ν
//!   v  = r + e·(σ − ν·p)
//! Verifier, with R = s^{N0} t^σ:
//!   z1, z2 < 2^{ℓ+ε+S+1}
//!   s^{z1} t^{w1} = A·P^e    s^{z2} t^{w2} = B·Q^e    Q^{z1} t^v = T·R^e
//! ```
//!
//! **Non-negative variant.** The paper samples from symmetric ranges `±X`;
//! here every mask is drawn from `[0, X)`, the challenge from `[0, q)`, and
//! every response is a non-negative integer, as the GG18 proofs in
//! `zkproofs.zig` do. Hiding is unchanged (each mask still dominates the
//! secret term it hides by `2^ε` or `2^ℓ`). The one signed quantity is
//! `σ − ν·p`; `v` is negative only when `r + e·σ < e·ν·p`, probability
//! below `2^-ℓ`, and the prover then draws a fresh proof. Extraction from
//! two accepting transcripts gives `p ≤ |Δz1|`, so a factor of an accepted
//! `N0` is at least `√N0 / 2^{ℓ+ε+2}` — about `2^253` for a 2048-bit `N0`.
//!
//! Fiat-Shamir and encoding are this module's own (no cross-implementation
//! format exists; tss-lib's `facproof` hashes differently). Secrets (`p`,
//! `q`, the masks) meet only `zkproofs.powSecret` (montint's constant-time
//! windowed pow, chunked) with fixed-width exponents and the fixed-trip-count
//! byte arithmetic below — not `std.crypto.ff`'s pow, whose table select
//! LLVM compiles to a branch (ctgrind, 2026-10-02). The verifier is
//! variable-time over public values.

const std = @import("std");
const root = @import("root.zig");
const zkproofs = @import("zkproofs.zig");

const AuxFe = root.AuxFe;
const AuxModulus = root.AuxModulus;

pub const domain = "threshold_ecdsa/fac-proof/v1";

/// `ℓ` in bits: the secp256k1 group order's length.
pub const ell_bits = 256;
/// `ε = 2ℓ` in bits (CGGMP21's choice).
pub const epsilon_bits = 2 * ell_bits;

const ell_bytes = ell_bits / 8;
const ell_eps_bytes = (ell_bits + epsilon_bits) / 8;
const mod_bytes = root.aux_modulus_bytes;

// Widest value of each kind, for `N0` and `N̂` up to `aux_modulus_bits`.
const ab_cap = ell_eps_bytes + mod_bytes / 2; // α, β
const mu_cap = mod_bytes + ell_bytes; // μ, ν
const n0nh_cap = 2 * mod_bytes; // N0·N̂
const sigma_cap = n0nh_cap + ell_bytes;
const r_cap = n0nh_cap + ell_eps_bytes;
const xy_cap = mod_bytes + ell_eps_bytes;
/// Wide enough for `e·q` with a factor as wide as `N0` itself — what a
/// small-factor `N0` forces — so such a proof parses and is then refused by
/// the range check, not by the codec.
const z_cap = @max(ab_cap, 32 + mod_bytes) + 1;
const w_cap = xy_cap + 1;
const v_cap = r_cap + 2;

/// A non-negative integer in a fixed-capacity big-endian buffer, kept in its
/// minimal encoding. The capacity is the parse bound: an attacker cannot hand
/// the verifier an exponent wider than an honest one.
fn Int(comptime cap: usize) type {
    return struct {
        const Self = @This();
        pub const capacity = cap;

        buf: [cap]u8 = [_]u8{0} ** cap,
        len: usize = 0,

        pub fn bytes(self: *const Self) []const u8 {
            return self.buf[0..self.len];
        }

        fn fromBytes(in: []const u8) error{InvalidEncoding}!Self {
            const v = stripLeadingZeros(in);
            if (v.len > cap) return error.InvalidEncoding;
            var out: Self = .{};
            @memcpy(out.buf[0..v.len], v);
            out.len = v.len;
            return out;
        }
    };
}

pub const FacProof = struct {
    /// `P`, `Q`, `A`, `B`, `T`: canonical mod the verifier's `N̂`.
    p_commit: AuxFe,
    q_commit: AuxFe,
    a: AuxFe,
    b: AuxFe,
    t: AuxFe,
    sigma: Int(sigma_cap),
    z1: Int(z_cap),
    z2: Int(z_cap),
    w1: Int(w_cap),
    w2: Int(w_cap),
    v: Int(v_cap),

    pub const ByteError = std.crypto.ff.OverflowError || std.crypto.ff.RepresentationError;
    pub const AllocError = std.mem.Allocator.Error || ByteError;

    /// `len-prefixed` each of `P, Q, A, B, T` (fixed `aux_modulus_bytes`)
    /// then `σ, z1, z2, w1, w2, v` (minimal big-endian).
    pub fn toBytesAlloc(self: FacProof, allocator: std.mem.Allocator) AllocError![]u8 {
        var list: std.ArrayList(u8) = .empty;
        errdefer list.deinit(allocator);
        for ([_]AuxFe{ self.p_commit, self.q_commit, self.a, self.b, self.t }) |fe| {
            var buf: [mod_bytes]u8 = undefined;
            try fe.toBytes(&buf, .big);
            try appendLenPrefixed(&list, allocator, &buf);
        }
        try appendLenPrefixed(&list, allocator, self.sigma.bytes());
        try appendLenPrefixed(&list, allocator, self.z1.bytes());
        try appendLenPrefixed(&list, allocator, self.z2.bytes());
        try appendLenPrefixed(&list, allocator, self.w1.bytes());
        try appendLenPrefixed(&list, allocator, self.w2.bytes());
        try appendLenPrefixed(&list, allocator, self.v.bytes());
        return list.toOwnedSlice(allocator);
    }

    pub const FromBytesError = error{InvalidEncoding};

    /// Inverse of `toBytesAlloc`; `n_hat` is the verifier's `N̂`. Rejects
    /// trailing bytes and any integer wider than an honest one.
    pub fn fromBytes(n_hat: AuxModulus, in: []const u8) FromBytesError!FacProof {
        var off: usize = 0;
        var fes: [5]AuxFe = undefined;
        for (&fes) |*fe| {
            const raw = try readLenPrefixed(in, &off);
            fe.* = AuxFe.fromBytes(n_hat, stripLeadingZeros(raw), .big) catch return error.InvalidEncoding;
        }
        const out: FacProof = .{
            .p_commit = fes[0],
            .q_commit = fes[1],
            .a = fes[2],
            .b = fes[3],
            .t = fes[4],
            .sigma = try Int(sigma_cap).fromBytes(try readLenPrefixed(in, &off)),
            .z1 = try Int(z_cap).fromBytes(try readLenPrefixed(in, &off)),
            .z2 = try Int(z_cap).fromBytes(try readLenPrefixed(in, &off)),
            .w1 = try Int(w_cap).fromBytes(try readLenPrefixed(in, &off)),
            .w2 = try Int(w_cap).fromBytes(try readLenPrefixed(in, &off)),
            .v = try Int(v_cap).fromBytes(try readLenPrefixed(in, &off)),
        };
        if (off != in.len) return error.InvalidEncoding;
        return out;
    }
};

/// `InvalidAuxParams`: the verifier's tuple failed `AuxParams.validate`
/// (the prover commits `p`/`q` under it, so a malformed one is refused
/// before any secret is touched). `InvalidStatement`: `N0` or the factors
/// do not fit (`p·q` wider than `aux_modulus_bits`, a factor wider than
/// `2^S`).
pub const ProveError = root.AuxParams.ValidateError || error{InvalidStatement};

/// Prove that `n0 = p·q` has no small factor, for the verifier whose aux
/// tuple is `verifier_aux`, bound to `context` (`session id || prover
/// index`). `p`, `q` are big-endian and SECRET; the caller vouches that
/// `p·q == n0` (a mismatch yields a proof that does not verify).
pub fn prove(
    n0: AuxModulus,
    p: []const u8,
    q: []const u8,
    verifier_aux: root.AuxParams,
    context: []const u8,
    random: std.Random,
) ProveError!FacProof {
    try verifier_aux.validate(random);
    return proveUnchecked(n0, p, q, verifier_aux, context, random, false);
}

/// `prove` without the verifier-tuple validation — for tests over tuples
/// below `validate`'s floor, and for the small-factor reject test, whose
/// statement is false on purpose.
fn proveUnchecked(
    n0: AuxModulus,
    p_in: []const u8,
    q_in: []const u8,
    aux: root.AuxParams,
    context: []const u8,
    random: std.Random,
    comptime wide_factors: bool,
) error{InvalidStatement}!FacProof {
    const nh = aux.n_tilde;
    var n0_buf: [mod_bytes]u8 = undefined;
    n0.toBytes(&n0_buf, .big) catch unreachable;
    const n0_bytes = stripLeadingZeros(&n0_buf);
    var nh_buf: [mod_bytes]u8 = undefined;
    nh.toBytes(&nh_buf, .big) catch unreachable;
    const nh_bytes = stripLeadingZeros(&nh_buf);
    const s_bits = sqrtBits(n0);

    // Factors in fixed-width buffers of the public width ⌈S/8⌉, so every
    // exponentiation and product sees a value-independent length. (The
    // small-factor test widens it: its false statement has a factor far
    // wider than `2^S`.)
    // No leading-zero strip of the secret factors: `fitRight` branches only
    // on the public lengths and on whether the value fits at all.
    const f_len = if (wide_factors) @max(p_in.len, q_in.len) else (s_bits + 7) / 8;
    var p_buf: [mod_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &p_buf);
    var q_buf: [mod_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &q_buf);
    if (f_len > p_buf.len) return error.InvalidStatement;
    const p = p_buf[0..f_len];
    const q = q_buf[0..f_len];
    if (!fitRight(p, p_in) or !fitRight(q, q_in)) return error.InvalidStatement;

    // Public sampling bounds.
    var n0nh_buf: [n0nh_cap + 1]u8 = undefined;
    const n0nh = stripLeadingZeros(mulAddBytes(n0_bytes, nh_bytes, &.{}, n0nh_buf[0 .. n0_bytes.len + nh_bytes.len + 1]));
    var mu_bound_buf: [mu_cap]u8 = undefined;
    const mu_bound = shiftBytes(&mu_bound_buf, nh_bytes, ell_bytes);
    var sigma_bound_buf: [sigma_cap]u8 = undefined;
    const sigma_bound = shiftBytes(&sigma_bound_buf, n0nh, ell_bytes);
    var r_bound_buf: [r_cap]u8 = undefined;
    const r_bound = shiftBytes(&r_bound_buf, n0nh, ell_eps_bytes);
    var xy_bound_buf: [xy_cap]u8 = undefined;
    const xy_bound = shiftBytes(&xy_bound_buf, nh_bytes, ell_eps_bytes);
    const ab_bits = ell_bits + epsilon_bits + s_bits;

    const s = aux.h1;
    const t = aux.h2;

    while (true) {
        // 1. Masks (SECRET).
        var alpha_buf: [ab_cap]u8 = undefined;
        defer std.crypto.secureZero(u8, &alpha_buf);
        const alpha = sampleBits(random, ab_bits, &alpha_buf);
        var beta_buf: [ab_cap]u8 = undefined;
        defer std.crypto.secureZero(u8, &beta_buf);
        const beta = sampleBits(random, ab_bits, &beta_buf);
        var mu_buf: [mu_cap]u8 = undefined;
        defer std.crypto.secureZero(u8, &mu_buf);
        const mu = sampleBelow(random, mu_bound, &mu_buf);
        var nu_buf: [mu_cap]u8 = undefined;
        defer std.crypto.secureZero(u8, &nu_buf);
        const nu = sampleBelow(random, mu_bound, &nu_buf);
        var sigma_buf: [sigma_cap]u8 = undefined;
        const sigma = sampleBelow(random, sigma_bound, &sigma_buf); // public once sent
        var r_buf: [r_cap]u8 = undefined;
        defer std.crypto.secureZero(u8, &r_buf);
        const r = sampleBelow(random, r_bound, &r_buf);
        var x_buf: [xy_cap]u8 = undefined;
        defer std.crypto.secureZero(u8, &x_buf);
        const x = sampleBelow(random, xy_bound, &x_buf);
        var y_buf: [xy_cap]u8 = undefined;
        defer std.crypto.secureZero(u8, &y_buf);
        const y = sampleBelow(random, xy_bound, &y_buf);

        // 2. Commitments in the verifier's group.
        const p_commit = zkproofs.pedersenCt(nh, s, p, t, mu);
        const q_commit = zkproofs.pedersenCt(nh, s, q, t, nu);
        const a = zkproofs.pedersenCt(nh, s, alpha, t, x);
        const b = zkproofs.pedersenCt(nh, s, beta, t, y);
        const t_commit = zkproofs.pedersenCt(nh, q_commit, alpha, t, r);

        // 3. Challenge.
        const e = challenge(context, n0, aux, p_commit, q_commit, a, b, t_commit, stripLeadingZeros(sigma));
        const e_bytes = e.toBytes(.big);
        if (stripLeadingZeros(&e_bytes).len == 0) continue; // probability 1/q

        // 4. Responses — plain non-negative integers.
        var out: FacProof = .{
            .p_commit = p_commit,
            .q_commit = q_commit,
            .a = a,
            .b = b,
            .t = t_commit,
            .sigma = Int(sigma_cap).fromBytes(sigma) catch unreachable,
            .z1 = undefined,
            .z2 = undefined,
            .w1 = undefined,
            .w2 = undefined,
            .v = undefined,
        };
        var z_buf: [z_cap + 32]u8 = undefined;
        out.z1 = Int(z_cap).fromBytes(mulAddBytes(&e_bytes, p, alpha, z_buf[0 .. @max(32 + f_len, alpha.len) + 1])) catch return error.InvalidStatement;
        out.z2 = Int(z_cap).fromBytes(mulAddBytes(&e_bytes, q, beta, z_buf[0 .. @max(32 + f_len, beta.len) + 1])) catch return error.InvalidStatement;
        var w_buf: [w_cap + 32]u8 = undefined;
        out.w1 = Int(w_cap).fromBytes(mulAddBytes(&e_bytes, mu, x, w_buf[0 .. @max(32 + mu.len, x.len) + 1])) catch unreachable;
        out.w2 = Int(w_cap).fromBytes(mulAddBytes(&e_bytes, nu, y, w_buf[0 .. @max(32 + nu.len, y.len) + 1])) catch unreachable;

        // v = (r + e·σ) − (e·ν)·p, computed at one fixed width.
        const v_len = @max(32 + sigma.len, r.len) + 1;
        var pos_buf: [v_cap + 32]u8 = undefined;
        defer std.crypto.secureZero(u8, &pos_buf);
        const pos = mulAddBytes(&e_bytes, sigma, r, pos_buf[0..v_len]);
        var enu_buf: [mu_cap + 33]u8 = undefined;
        defer std.crypto.secureZero(u8, &enu_buf);
        const enu = mulAddBytes(&e_bytes, nu, &.{}, enu_buf[0 .. 32 + nu.len + 1]);
        var neg_buf: [mu_cap + 33 + mod_bytes + 1]u8 = undefined;
        defer std.crypto.secureZero(u8, &neg_buf);
        const neg = mulAddBytes(enu, p, &.{}, neg_buf[0 .. enu.len + p.len + 1]);
        var v_buf: [v_cap + 32]u8 = undefined;
        defer std.crypto.secureZero(u8, &v_buf);
        const borrow = subBytes(pos, neg, v_buf[0..v_len]);
        if (borrow != 0) continue; // v < 0: probability < 2^-ℓ, draw again
        out.v = Int(v_cap).fromBytes(v_buf[0..v_len]) catch unreachable;
        return out;
    }
}

/// Check a proof that `n0` has no small factor, made for THIS verifier
/// (`own_aux` is the verifier's own tuple, the one the prover committed
/// under) and bound to the prover's `context`. Variable-time; all inputs
/// public.
pub fn verify(n0: AuxModulus, own_aux: root.AuxParams, context: []const u8, proof: FacProof) bool {
    return verifyInner(n0, own_aux, context, proof, true);
}

/// `check_range = false` exists for one test: it shows the three equations
/// accept a small-factor proof, so the range check is what refuses it.
fn verifyInner(n0: AuxModulus, own_aux: root.AuxParams, context: []const u8, proof: FacProof, comptime check_range: bool) bool {
    const nh = own_aux.n_tilde;
    const s = own_aux.h1;
    const t = own_aux.h2;

    // Zero is never an honest commitment (they are products of units).
    for ([_]AuxFe{ proof.p_commit, proof.q_commit, proof.a, proof.b, proof.t }) |fe| {
        if (fe.isZero()) return false;
    }

    // The range check — the whole point: a small factor forces the OTHER
    // factor's response past this bound.
    const z_max_bits = ell_bits + epsilon_bits + sqrtBits(n0) + 1;
    if (check_range and (bitLen(proof.z1.bytes()) > z_max_bits or bitLen(proof.z2.bytes()) > z_max_bits)) return false;

    const e = challenge(context, n0, own_aux, proof.p_commit, proof.q_commit, proof.a, proof.b, proof.t, proof.sigma.bytes());
    const e_bytes = e.toBytes(.big);
    if (stripLeadingZeros(&e_bytes).len == 0) return false;

    // s^{z1} t^{w1} = A·P^e
    if (!feEql(nh.mul(powPub(nh, s, proof.z1.bytes()), powPub(nh, t, proof.w1.bytes())), nh.mul(proof.a, powPub(nh, proof.p_commit, &e_bytes)))) return false;
    // s^{z2} t^{w2} = B·Q^e
    if (!feEql(nh.mul(powPub(nh, s, proof.z2.bytes()), powPub(nh, t, proof.w2.bytes())), nh.mul(proof.b, powPub(nh, proof.q_commit, &e_bytes)))) return false;
    // Q^{z1} t^v = T·R^e, R = s^{N0} t^σ
    var n0_buf: [mod_bytes]u8 = undefined;
    n0.toBytes(&n0_buf, .big) catch return false;
    const r_pt = nh.mul(powPub(nh, s, &n0_buf), powPub(nh, t, proof.sigma.bytes()));
    return feEql(nh.mul(powPub(nh, proof.q_commit, proof.z1.bytes()), powPub(nh, t, proof.v.bytes())), nh.mul(proof.t, powPub(nh, r_pt, &e_bytes)));
}

fn challenge(
    context: []const u8,
    n0: AuxModulus,
    aux: root.AuxParams,
    p_commit: AuxFe,
    q_commit: AuxFe,
    a: AuxFe,
    b: AuxFe,
    t_commit: AuxFe,
    sigma: []const u8,
) root.Scalar {
    var tr = zkproofs.Transcript.init(domain);
    tr.appendContext(context);
    var n0_buf: [mod_bytes]u8 = undefined;
    n0.toBytes(&n0_buf, .big) catch unreachable;
    tr.appendContext(&n0_buf);
    tr.appendAuxParams(aux);
    tr.appendAuxFe(p_commit);
    tr.appendAuxFe(q_commit);
    tr.appendAuxFe(a);
    tr.appendAuxFe(b);
    tr.appendAuxFe(t_commit);
    tr.appendContext(sigma);
    return tr.finalize();
}

/// `S = ⌈bits(N0)/2⌉`.
fn sqrtBits(n0: AuxModulus) usize {
    return (n0.bits() + 1) / 2;
}

// ── byte-string integer helpers (copied per file, as `zkproofs.zig`'s are) ─

fn stripLeadingZeros(bytes: []const u8) []const u8 {
    var i: usize = 0;
    while (i < bytes.len and bytes[i] == 0) : (i += 1) {}
    return bytes[i..];
}

fn bitLen(bytes_in: []const u8) usize {
    const b = stripLeadingZeros(bytes_in);
    if (b.len == 0) return 0;
    return 8 * b.len - @clz(b[0]);
}

fn intCompare(a_in: []const u8, b_in: []const u8) std.math.Order {
    const a = stripLeadingZeros(a_in);
    const b = stripLeadingZeros(b_in);
    if (a.len != b.len) return if (a.len < b.len) .lt else .gt;
    return std.mem.order(u8, a, b);
}

/// `in` right-aligned into `out`; false when `in` has a nonzero byte above
/// `out`'s width. Branches on the two lengths (public) and on the OR of the
/// excess bytes (a fits / does-not-fit answer), never on where the value's
/// leading zeros end.
fn fitRight(out: []u8, in: []const u8) bool {
    @memset(out, 0);
    if (in.len <= out.len) {
        @memcpy(out[out.len - in.len ..], in);
        return true;
    }
    const excess = in.len - out.len;
    var acc: u8 = 0;
    for (in[0..excess]) |b| acc |= b;
    @memcpy(out, in[excess..]);
    return acc == 0;
}

/// `value · 2^(8·zero_bytes)`.
fn shiftBytes(out_buf: []u8, value: []const u8, zero_bytes: usize) []u8 {
    const out = out_buf[0 .. value.len + zero_bytes];
    @memcpy(out[0..value.len], value);
    @memset(out[value.len..], 0);
    return out;
}

/// `out = e·x + addend`, big-endian, `out.len >= max(e.len + x.len,
/// addend.len) + 1`. Fixed trip counts — the carry chain always runs to
/// `out[0]` — so secret operands of public length leak nothing through
/// timing (copied from `zkproofs.zig`, where the early-exit version was a
/// measured ctgrind finding).
fn mulAddBytes(e: []const u8, x: []const u8, addend: []const u8, out: []u8) []u8 {
    std.debug.assert(out.len >= e.len + x.len + 1 and out.len >= addend.len + 1);
    @memset(out, 0);
    @memcpy(out[out.len - addend.len ..], addend);
    var i: usize = e.len;
    while (i > 0) {
        i -= 1;
        var carry: u32 = 0;
        var j: usize = x.len;
        while (j > 0) {
            j -= 1;
            const pos = out.len - 1 - (e.len - 1 - i) - (x.len - 1 - j);
            const cur = @as(u32, out[pos]) + @as(u32, e[i]) * @as(u32, x[j]) + carry;
            out[pos] = @truncate(cur);
            carry = cur >> 8;
        }
        var pos = out.len - 1 - (e.len - 1 - i) - x.len;
        while (true) {
            const cur = @as(u32, out[pos]) + carry;
            out[pos] = @truncate(cur);
            carry = cur >> 8;
            if (pos == 0) break;
            pos -= 1;
        }
    }
    return out;
}

/// `out = a − b` over `out.len` bytes (`a`, `b` right-aligned, each at most
/// `out.len` long); returns the final borrow (1 when `a < b`). Every byte
/// position is visited, whatever the values.
fn subBytes(a: []const u8, b: []const u8, out: []u8) u8 {
    std.debug.assert(a.len <= out.len and b.len <= out.len);
    var borrow: u16 = 0;
    var k: usize = 0;
    while (k < out.len) : (k += 1) {
        const ai: u16 = if (k < a.len) a[a.len - 1 - k] else 0;
        const bi: u16 = if (k < b.len) b[b.len - 1 - k] else 0;
        const d = ai -% bi -% borrow;
        out[out.len - 1 - k] = @truncate(d);
        borrow = (d >> 8) & 1;
    }
    return @intCast(borrow);
}

/// Uniform in `[0, bound)` by rejection; returns the `bound.len`-wide slice
/// (fixed width per bound). The comparison only decides a discarded draw.
fn sampleBelow(random: std.Random, bound_in: []const u8, out_buf: []u8) []u8 {
    const bound = stripLeadingZeros(bound_in);
    std.debug.assert(bound.len >= 1 and out_buf.len >= bound.len);
    const mask: u8 = @as(u8, 0xff) >> @intCast(@clz(bound[0]));
    const out = out_buf[0..bound.len];
    while (true) {
        random.bytes(out);
        out[0] &= mask;
        if (intCompare(out, bound) == .lt) return out;
    }
}

/// Uniform in `[0, 2^bits)`, in a fixed `⌈bits/8⌉`-wide slice.
fn sampleBits(random: std.Random, bits: usize, out_buf: []u8) []u8 {
    const len = (bits + 7) / 8;
    const out = out_buf[0..len];
    random.bytes(out);
    out[0] &= @as(u8, 0xff) >> @intCast(8 * len - bits);
    return out;
}

/// `base^e mod m`, constant-time in `e`'s value (montint, chunked —
/// `zkproofs.powSecret`; the length of `e` is public). `e = 0` gives 1.
fn powCt(m: AuxModulus, base: AuxFe, e: []const u8) AuxFe {
    return zkproofs.powSecret(m, base, e);
}

/// `base^e mod m` for a public exponent. `e = 0` gives 1.
fn powPub(m: AuxModulus, base: AuxFe, e: []const u8) AuxFe {
    const eb = stripLeadingZeros(e);
    if (eb.len == 0) return m.one();
    return m.powWithEncodedPublicExponent(base, eb, .big) catch m.one();
}

fn feEql(a: AuxFe, b: AuxFe) bool {
    var ab: [mod_bytes]u8 = undefined;
    a.toBytes(&ab, .big) catch return false;
    var bb: [mod_bytes]u8 = undefined;
    b.toBytes(&bb, .big) catch return false;
    return std.mem.eql(u8, &ab, &bb);
}

fn appendLenPrefixed(list: *std.ArrayList(u8), allocator: std.mem.Allocator, data: []const u8) std.mem.Allocator.Error!void {
    var len_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &len_buf, @intCast(data.len), .big);
    try list.appendSlice(allocator, &len_buf);
    try list.appendSlice(allocator, data);
}

fn readLenPrefixed(bytes: []const u8, offset: *usize) error{InvalidEncoding}![]const u8 {
    if (bytes.len - offset.* < 4) return error.InvalidEncoding;
    const len = std.mem.readInt(u32, bytes[offset.*..][0..4], .big);
    offset.* += 4;
    if (bytes.len - offset.* < len) return error.InvalidEncoding;
    const out = bytes[offset.*..][0..len];
    offset.* += len;
    return out;
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;
const vectors = @import("tsslib_vectors.zig");

/// A real 2048-bit statement: tss-lib party `prover`'s Paillier factors
/// (1024-bit safe primes, so also Blum) and party `verifier`'s aux tuple.
const Real = struct {
    n0: AuxModulus,
    p: [128]u8,
    q: [128]u8,
    aux: root.AuxParams,
};

fn hexFe(nt: AuxModulus, hex: []const u8) !AuxFe {
    var buf: [mod_bytes]u8 = undefined;
    const b = try unhexInto(&buf, hex);
    return AuxFe.fromBytes(nt, b, .big);
}

fn unhexInto(buf: []u8, hex: []const u8) ![]u8 {
    const len = (hex.len + 1) / 2;
    const out = buf[0..len];
    if (hex.len % 2 == 1) {
        out[0] = try std.fmt.parseInt(u8, hex[0..1], 16);
        _ = try std.fmt.hexToBytes(out[1..], hex[1..]);
    } else {
        _ = try std.fmt.hexToBytes(out, hex);
    }
    return out;
}

fn realStatement(prover: usize, verifier: usize) !Real {
    const pp = vectors.tsslib_keygen.parties[prover];
    const vp = vectors.tsslib_keygen.parties[verifier];
    var out: Real = undefined;
    _ = try std.fmt.hexToBytes(&out.p, pp.paillier_p);
    _ = try std.fmt.hexToBytes(&out.q, pp.paillier_q);
    var n_buf: [2 * 128 + 1]u8 = undefined;
    const n = mulAddBytes(&out.p, &out.q, &.{}, &n_buf);
    out.n0 = try AuxModulus.fromBytes(stripLeadingZeros(n), .big);
    var nt_buf: [mod_bytes]u8 = undefined;
    const nt = try AuxModulus.fromBytes(try unhexInto(&nt_buf, vp.n_tilde), .big);
    out.aux = .{ .n_tilde = nt, .h1 = try hexFe(nt, vp.h1), .h2 = try hexFe(nt, vp.h2) };
    return out;
}

const ctx_a = "session-0001" ++ [_]u8{ 0, 0, 0, 1 };
const ctx_b = "session-0001" ++ [_]u8{ 0, 0, 0, 2 };

test "Πfac: an honest 2048-bit proof verifies, and survives the codec" {
    var prng = std.Random.DefaultPrng.init(0x6661_6331);
    const st = try realStatement(0, 1);
    const proof = try prove(st.n0, &st.p, &st.q, st.aux, ctx_a, prng.random());
    try testing.expect(verify(st.n0, st.aux, ctx_a, proof));

    const bytes = try proof.toBytesAlloc(testing.allocator);
    defer testing.allocator.free(bytes);
    const back = try FacProof.fromBytes(st.aux.n_tilde, bytes);
    try testing.expect(verify(st.n0, st.aux, ctx_a, back));

    // Trailing garbage and a truncated encoding are refused.
    const longer = try std.mem.concat(testing.allocator, u8, &.{ bytes, &[_]u8{0} });
    defer testing.allocator.free(longer);
    try testing.expectError(error.InvalidEncoding, FacProof.fromBytes(st.aux.n_tilde, longer));
    try testing.expectError(error.InvalidEncoding, FacProof.fromBytes(st.aux.n_tilde, bytes[0 .. bytes.len - 1]));
}

test "Πfac: bound to the prover's context and to the verifier it was made for" {
    var prng = std.Random.DefaultPrng.init(0x6661_6332);
    const st = try realStatement(0, 1);
    const proof = try prove(st.n0, &st.p, &st.q, st.aux, ctx_a, prng.random());
    // Another party (or session) cannot claim it.
    try testing.expect(!verify(st.n0, st.aux, ctx_b, proof));
    // A different verifier's tuple: the commitments mean nothing there (as
    // that verifier receives it — through the codec, under its own N̂).
    const other = try realStatement(0, 2);
    const bytes = try proof.toBytesAlloc(testing.allocator);
    defer testing.allocator.free(bytes);
    if (FacProof.fromBytes(other.aux.n_tilde, bytes)) |as_other| {
        try testing.expect(!verify(other.n0, other.aux, ctx_a, as_other));
    } else |_| {}
    // Another party's N0 under the same verifier.
    const st2 = try realStatement(2, 1);
    try testing.expect(!verify(st2.n0, st.aux, ctx_a, proof));
}

test "Πfac: every field is load-bearing (tamper one, verification fails)" {
    var prng = std.Random.DefaultPrng.init(0x6661_6333);
    const st = try realStatement(1, 0);
    const proof = try prove(st.n0, &st.p, &st.q, st.aux, ctx_a, prng.random());
    const nh = st.aux.n_tilde;
    const two = try AuxFe.fromBytes(nh, &[_]u8{2}, .big);

    inline for (.{ "p_commit", "q_commit", "a", "b", "t" }) |f| {
        var bad = proof;
        @field(bad, f) = nh.mul(@field(bad, f), two);
        try testing.expect(!verify(st.n0, st.aux, ctx_a, bad));
    }
    inline for (.{ "sigma", "z1", "z2", "w1", "w2", "v" }) |f| {
        var bad = proof;
        const fld = &@field(bad, f);
        fld.buf[fld.len - 1] ^= 1;
        try testing.expect(!verify(st.n0, st.aux, ctx_a, bad));
    }
}

test "Πfac TEETH: N0 = 3·X — the equations accept, the range check refuses" {
    // The BitForge shape: a Paillier modulus with a tiny prime factor. The
    // statement is false, but the prover's algorithm still runs with
    // (p, q) = (3, X): every equation closes, and z2 = β + e·X is ~2^2300,
    // far past 2^{ℓ+ε+S+1} = 2^1793. Primality of X is irrelevant to Πfac.
    var prng = std.Random.DefaultPrng.init(0x6661_6334);
    const random = prng.random();
    const st = try realStatement(0, 1);

    var x: [mod_bytes]u8 = undefined;
    random.bytes(&x);
    x[0] = 0x40 | (x[0] & 0x0f); // 3·X stays below 2^2048
    x[x.len - 1] |= 1;
    var n_buf: [mod_bytes + 2]u8 = undefined;
    const n = mulAddBytes(&[_]u8{3}, &x, &.{}, &n_buf);
    const n0 = try AuxModulus.fromBytes(stripLeadingZeros(n), .big);
    try testing.expectEqual(@as(usize, 2048), n0.bits());

    // The public `prove` refuses the statement outright (X is wider than 2^S).
    try testing.expectError(error.InvalidStatement, prove(n0, &[_]u8{3}, &x, st.aux, ctx_a, random));

    const proof = try proveUnchecked(n0, &[_]u8{3}, &x, st.aux, ctx_a, random, true);
    try testing.expect(verifyInner(n0, st.aux, ctx_a, proof, false));
    try testing.expect(!verify(n0, st.aux, ctx_a, proof));
    try testing.expect(bitLen(proof.z2.bytes()) > ell_bits + epsilon_bits + 1024 + 1);
}

test "FacProof.fromBytes refuses an integer wider than an honest one" {
    var prng = std.Random.DefaultPrng.init(0x6661_6336);
    const st = try realStatement(0, 1);
    const proof = try prove(st.n0, &st.p, &st.q, st.aux, ctx_a, prng.random());
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    for ([_]AuxFe{ proof.p_commit, proof.q_commit, proof.a, proof.b, proof.t }) |fe| {
        var buf: [mod_bytes]u8 = undefined;
        try fe.toBytes(&buf, .big);
        try appendLenPrefixed(&list, testing.allocator, &buf);
    }
    const wide = [_]u8{1} ** (sigma_cap + 1);
    try appendLenPrefixed(&list, testing.allocator, &wide); // σ one byte past its cap
    for ([_][]const u8{ proof.z1.bytes(), proof.z2.bytes(), proof.w1.bytes(), proof.w2.bytes(), proof.v.bytes() }) |f|
        try appendLenPrefixed(&list, testing.allocator, f);
    try testing.expectError(error.InvalidEncoding, FacProof.fromBytes(st.aux.n_tilde, list.items));
}

test "Πfac: prove refuses a verifier tuple that fails validate" {
    var prng = std.Random.DefaultPrng.init(0x6661_6335);
    const st = try realStatement(0, 1);
    var bad = st.aux;
    bad.h2 = bad.n_tilde.one(); // h2 = 1: no binding commitment at all
    try testing.expectError(error.InvalidAuxParams, prove(st.n0, &st.p, &st.q, bad, ctx_a, prng.random()));
}

test "subBytes: borrow and value at the edges" {
    var out: [3]u8 = undefined;
    try testing.expectEqual(@as(u8, 0), subBytes(&[_]u8{ 1, 0, 0 }, &[_]u8{1}, &out));
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 0xff, 0xff }, &out);
    try testing.expectEqual(@as(u8, 1), subBytes(&[_]u8{1}, &[_]u8{2}, &out));
    try testing.expectEqual(@as(u8, 0), subBytes(&[_]u8{5}, &[_]u8{5}, &out));
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0 }, &out);
}
