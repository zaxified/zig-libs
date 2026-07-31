// SPDX-License-Identifier: MIT
//! paillier — pure-Zig Paillier additively-homomorphic public-key cryptosystem
//! (Paillier 1999). `std.crypto.ff` carries every value (the same fixed-width
//! constant-time modular-arithmetic primitive this repo's `rsa` module builds
//! on) and does keygen, the L-function, the CRT/Garner recombination, and all
//! serialization; the modular-exponentiation HOT PATHS — encrypt's `r^n mod n²`
//! and decrypt's `c^λ mod n²` — are routed through the sibling `montint` module
//! (full-radix-2^64 Montgomery modexp, ~3–4× faster than `ff` on the portable
//! path). Decrypt additionally uses **Paillier-CRT** (compute `c^(λ mod p(p-1))
//! mod p²` and `c^(λ mod q(q-1)) mod q²`, Garner-recombine) for a further ~3.4×.
//! Measured net on a 2048-bit key (ReleaseFast, this host): encrypt 59→16 ms
//! (~3.7×), decrypt 118→7.8 ms (~15×). The montint moduli + Montgomery
//! constants are precomputed ONCE per key (`MontParams`, carried on the key).
//!
//! **Status: IMPLEMENTED.** Keygen (`generate`/`fromPrimes`), `encrypt`/
//! `decrypt`, and the homomorphic ops (`addCiphertexts`/`addPlaintext`/
//! `mulPlaintext`) are all real: cross-checked value-exact against `phe`
//! (python-paillier) 1.5.0 toy-key vectors (p=11, q=17 — see "Tests" below
//! and NOTICE), plus self-checking round-trip/homomorphic-property tests and
//! a full-size `generate` round trip.
//!
//! This is Phase 1 of the I2 threshold-ECDSA arc: Paillier is the additively-
//! homomorphic sub-primitive GG20/CMP threshold-ECDSA's MtA (multiplicative-
//! to-additive) protocol builds on. The zero-knowledge proofs that protocol
//! actually needs (proof of correct Paillier encryption, range proofs, MtA
//! itself) are Phase 2, deliberately OUT OF SCOPE here — see "Phase-2
//! boundary" below and the `// TODO(phase2)` markers.
//!
//! ## Fe construction contract — READ BEFORE CALLING `encrypt`/the homomorphic ops
//!
//! Every value below is represented as `Fe` (`std.crypto.ff.Modulus(max_bits).Fe`),
//! but "canonical" is relative to WHICH modulus instance shrunk it (`Modulus.shrink`
//! only ever narrows a value's limb width, it never widens one back). Concretely:
//!
//!   - Plaintexts (`m`) and randomness (`r`) passed to `encrypt`, and the plaintext
//!     operands (`m`/`k`) passed to `addPlaintext`/`mulPlaintext`, are used as a
//!     base/exponent in a `pk.n_sq`-modulus operation (`pow`/`mul`). They MUST be
//!     constructed canonical mod `pk.n_sq` — e.g. `Fe.fromBytes(pk.n_sq, bytes, .big)`
//!     or `Fe.fromPrimitive(T, pk.n_sq, x)` — NOT mod `pk.n`. Every value < n is
//!     automatically < n² too, so constructing directly against `n_sq` is always
//!     safe and free; the trap is constructing against `pk.n` first (which shrinks
//!     the `Fe`'s internal limb count down to `n`'s width) and then reusing that
//!     same value as a base/exponent under `n_sq` — `Modulus.shrink`/`toMontgomery`
//!     will fail with `error.Overflow` because they only narrow, never widen.
//!   - `SecretKey.lambda` is canonical mod `sk.n_sq` (it is the exponent in
//!     `c^lambda mod n²`); `SecretKey.mu` is canonical mod `sk.n` (it is used in
//!     the final `L(...) * mu mod n` step, which is entirely inside `n`'s domain).
//!   - `decrypt`'s returned plaintext `Fe` is canonical mod `sk.n` (the natural
//!     domain of a plaintext) — comparing it against a value built mod `pk.n_sq`
//!     (e.g. the `m` you fed to `encrypt`) with `.eql()` still works correctly
//!     (`Fe.eql` compares the full fixed-size limb buffer, not just the active
//!     `limbs_len` prefix, and unused high limbs are always zero by construction);
//!     `.toPrimitive()` is likewise unaffected by which modulus a value was shrunk
//!     against.

const std = @import("std");

/// Fast constant-time Montgomery modexp backend for the Paillier hot paths
/// (encrypt `r^n mod n²`, decrypt `c^λ mod n²` and its CRT halves `mod p²/q²`).
/// See `montint`'s SPEC.md; same MontParams-per-key + limb-dispatch pattern the
/// `rsa` module uses. `std.crypto.ff` is retained for keygen, the L-function,
/// the CRT/Garner recombination arithmetic, and all serialization — only the
/// exponentiation primitive moved.
const montint = @import("montint");

pub const meta = .{
    .platform = .any,
    .role = .util, // pure computation (no I/O of its own)
    // PublicKey/SecretKey/Ciphertext are plain value types, no shared/global
    // state — safe to use from multiple threads as long as they aren't
    // mutated concurrently (they never are; every op returns a new value).
    .concurrency = .reentrant,
    .model_after = "P. Paillier, \"Public-Key Cryptosystems Based on Composite Degree Residuosity Classes\", EUROCRYPT 1999; std.crypto.ff carrier + montint modexp hot path (this repo's `rsa` module builds on the same pairing)",
    .deps = .{"montint"}, // std.crypto.ff carrier + montint modexp hot path
};

// ── parameter sizes ──────────────────────────────────────────────────────────

/// Bit-size of `n` this module is sized for. Paillier security is governed by
/// the difficulty of factoring `n = p*q`, exactly like RSA — 2048-bit `n`
/// (two 1024-bit primes) matches this repo's `rsa` module's default modulus
/// size / comparable real-world security margin. `generate`/`fromPrimes`
/// accept any `p`,`q` that fit within `max_bits/2` (including much smaller
/// ones, e.g. for KATs); this constant is only the size this module is
/// *designed and sized* for.
pub const modulus_bits = 2048;

/// Ciphertexts and all `n²`-modulus arithmetic need double `modulus_bits` of
/// headroom (`n² < 2^(2*modulus_bits)`) — this is the ceiling the fixed-width
/// `Uint`/`Modulus`/`Fe` types below are sized to.
pub const max_bits = modulus_bits * 2;

/// Fixed-capacity big-unsigned-integer type sized to `max_bits` (i.e. to `n²`
/// at the canonical `modulus_bits` size). `n`-modulus values (which need only
/// `modulus_bits`) use the *same* type, just holding a smaller actual value —
/// mirrors how `rsa` sizes `p`/`q`/`n` all as one `Modulus` type at
/// `max_modulus_bits`.
pub const Uint = std.crypto.ff.Uint(max_bits);

/// Constant-time finite-field modulus type sized to `max_bits`. Every
/// `PublicKey`/`SecretKey` field of "modulus" kind (`n`, `n_sq`) is this
/// type; see `std.crypto.ff` doc comments for the underlying Montgomery-
/// ladder details.
pub const Modulus = std.crypto.ff.Modulus(max_bits);

/// Field element type for `Modulus` — every Paillier integer (plaintexts,
/// randomness, ciphertexts, `lambda`/`mu`) is carried as this type. See the
/// "Fe construction contract" note above the module doc comment for which
/// modulus instance a given value must be canonical against.
pub const Fe = Modulus.Fe;

/// Byte length of a canonical `n`-sized value at `modulus_bits`.
pub const modulus_bytes = modulus_bits / 8;

/// Byte length of a canonical `n²`-sized value (ciphertexts, `n_sq`) at
/// `modulus_bits`.
pub const modulus_sq_bytes = max_bits / 8;

/// Byte length needed to serialize a value of `bit_count` bits.
fn byteLen(bit_count: usize) usize {
    return (bit_count + 7) / 8;
}

/// `Modulus.fromBytes`/`Fe.fromBytes` reject inputs longer than the backing
/// `Uint`; externally-supplied big-endian values may carry leading zero
/// octets (e.g. from a fixed-width wire format), so strip them first.
fn stripLeadingZeros(bytes: []const u8) []const u8 {
    var i: usize = 0;
    while (i < bytes.len and bytes[i] == 0) : (i += 1) {}
    return bytes[i..];
}

// ── montint modexp backend (the hot-path arithmetic) ────────────────────────
//
// `montint.Modint(bits)` fixes its limb count `L` at comptime, whereas a
// Paillier operation's width is only known at runtime: `n²` is `max_bits` wide
// (L=64 at the canonical size) while the CRT halves work over `p²`/`q²`, each
// ~half that (L=32). We bridge the two exactly as `rsa` does — a runtime-
// dispatched set of comptime `Modint` instantiations, keyed on the operand's
// limb count rounded up to a multiple of `mont_step`. Rounding keeps the
// number of monomorphized modexp instantiations small (16). The canonical
// sizes land on exact multiple-of-4 limb counts with ZERO padding: a 2048-bit
// key's `n²` is L=64 and each `p²`/`q²` is L=32 — precisely the Montgomery-
// resident portable win the audit targeted (both < montint's `asm_min_limbs`
// =32… note `p²` sits right at the cutoff; the asm core is gated off repo-wide
// so every size takes the portable CIOS path regardless). Padding, when a
// non-round width forces it, only adds leading zero limbs, which `montint`
// handles correctly (just slightly slower).

const mont_step: usize = 4;
const mont_min_limbs: usize = 4;
const mont_max_limbs: usize = (max_bits + 63) / 64; // 64

/// A modulus plus its precomputed Montgomery constants, stored in a max-width
/// buffer with only the low `L` limbs live. Computed ONCE per key so no
/// per-operation Montgomery setup is paid — the `Modint` view is reconstructed
/// field-by-field at op time, skipping the `computeConstants` doubling loop.
const MontParams = struct {
    /// Live limb count (multiple of `mont_step`); selects the comptime `Modint`.
    L: usize = 0,
    /// `-m[0]⁻¹ mod 2^64` (montint's CIOS reduction constant).
    n0inv: u64 = 0,
    /// The odd modulus, little-endian, low `L` limbs live.
    m: [mont_max_limbs]u64 = [_]u64{0} ** mont_max_limbs,
    /// `R² mod m` (montint's `toMontgomery` constant).
    r2: [mont_max_limbs]u64 = [_]u64{0} ** mont_max_limbs,
    /// `R mod m` — the value `1` in the Montgomery domain.
    one: [mont_max_limbs]u64 = [_]u64{0} ** mont_max_limbs,
};

/// Round a runtime limb count up to the modeled `Modint` slot: the smallest
/// multiple of `mont_step` that is ≥ `l` and ≥ `mont_min_limbs`.
fn montSlot(l: usize) usize {
    var s: usize = mont_min_limbs;
    while (s < l) s += mont_step;
    return s;
}

/// Load a big-endian byte string into an `slot`-limb little-endian value with
/// NO value-dependent branch (the only branch is on the PUBLIC bit position vs
/// the limb count) — safe on a secret exponent. The caller guarantees the
/// value fits in `slot` limbs (every base/exponent here is `< m`).
fn beToLimbs(comptime slot: usize, be: []const u8) [slot]u64 {
    var v = [_]u64{0} ** slot;
    var idx: usize = 0;
    var i: usize = be.len;
    while (i > 0) : (idx += 8) {
        i -= 1;
        const limb = idx >> 6;
        if (limb >= slot) break; // branch on public position, not on any value
        v[limb] |= @as(u64, be[i]) << @intCast(idx & 63);
    }
    return v;
}

/// Precompute the montint modulus + Montgomery constants for an `ff` modulus.
/// One-time (key construction) — walks the doubling-based `computeConstants`.
fn montParamsFromModulus(mod: Modulus) MontParams {
    var be: [modulus_sq_bytes]u8 = undefined;
    mod.toBytes(&be, .big) catch unreachable; // n²-width buffer never overflows
    const slot = montSlot((mod.bits() + 63) / 64);
    var mp: MontParams = .{ .L = slot };
    comptime var s: usize = mont_min_limbs;
    inline while (s <= mont_max_limbs) : (s += mont_step) {
        if (s == slot) {
            const M = montint.Modint(s * 64);
            // Build via the branchless `beToLimbs` + `fromElem` (NOT montint's
            // `fromBytesBE`, whose zero-byte skip is value-dependent) so the
            // path stays uniform; the modulus is public here regardless.
            const mm = M.fromElem(beToLimbs(s, &be)) catch unreachable; // odd, ≥3, fits
            mp.n0inv = mm.n0inv;
            @memcpy(mp.m[0..s], &mm.m);
            @memcpy(mp.r2[0..s], &mm.r2);
            @memcpy(mp.one[0..s], &mm.one_mont);
            return mp;
        }
    }
    unreachable;
}

/// Reconstruct the comptime `Modint` view for slot `s` from precomputed params.
fn montView(comptime s: usize, mp: *const MontParams) montint.Modint(s * 64) {
    const M = montint.Modint(s * 64);
    return M{
        .m = mp.m[0..s].*,
        .n0inv = mp.n0inv,
        .r2 = mp.r2[0..s].*,
        .one_mont = mp.one[0..s].*,
    };
}

/// Constant-time (in the exponent VALUE) modexp `base^exp mod m` over the
/// precomputed modulus `mp`. `base_be`/`exp_be` are big-endian, both `< m`.
/// Writes the big-endian result (slot-width) into `out_buf` and returns that
/// slice. Used for the secret decrypt paths (`c^λ mod n²`, `c^dp mod p²`,
/// `c^dq mod q²`).
fn montPowSecret(mp: *const MontParams, base_be: []const u8, exp_be: []const u8, out_buf: *[modulus_sq_bytes]u8) []const u8 {
    comptime var s: usize = mont_min_limbs;
    inline while (s <= mont_max_limbs) : (s += mont_step) {
        if (s == mp.L) {
            const M = montint.Modint(s * 64);
            const mod = montView(s, mp);
            const b = beToLimbs(s, base_be);
            const e = beToLimbs(s, exp_be);
            const r = mod.powMont(&b, &e);
            mod.toBytesBE(&r, out_buf[0..M.encoded_bytes]);
            return out_buf[0..M.encoded_bytes];
        }
    }
    unreachable;
}

/// Variable-time modexp `base^e mod m` for a PUBLIC exponent (the `r^n mod n²`
/// term of `encrypt` — `n` is the public modulus). Left-to-right square-and-
/// multiply over `e`'s actual bit length; variable-time is fine because `e` is
/// public, and the base `r` is still processed through montint's Montgomery
/// multiply. `base_be` is big-endian, `< m`.
fn montPowPublic(mp: *const MontParams, base_be: []const u8, e_be: []const u8, out_buf: *[modulus_sq_bytes]u8) []const u8 {
    comptime var s: usize = mont_min_limbs;
    inline while (s <= mont_max_limbs) : (s += mont_step) {
        if (s == mp.L) {
            const M = montint.Modint(s * 64);
            const mod = montView(s, mp);
            const b = beToLimbs(s, base_be);
            const b_mont = mod.toMontgomery(&b);
            var acc: M.Elem = mod.one_mont;
            var seen = false;
            const eb = stripLeadingZeros(e_be);
            for (eb) |byte| {
                var mask: u8 = 0x80;
                while (mask != 0) : (mask >>= 1) {
                    if (seen) acc = mod.montSqr(&acc);
                    if (byte & mask != 0) {
                        if (seen) {
                            acc = mod.montMul(&acc, &b_mont);
                        } else {
                            acc = b_mont; // first set bit: acc = base^1
                            seen = true;
                        }
                    }
                }
            }
            const r = mod.fromMontgomery(&acc);
            mod.toBytesBE(&r, out_buf[0..M.encoded_bytes]);
            return out_buf[0..M.encoded_bytes];
        }
    }
    unreachable;
}

/// Parse a montint big-endian result (slot-width, value `< m`) back into an
/// `Fe` canonical mod `m`. Leading zero octets are stripped first.
fn feFromMontBytes(m: Modulus, res: []const u8) Fe {
    return Fe.fromBytes(m, stripLeadingZeros(res), .big) catch unreachable; // value < m
}

/// `base^exp mod m` (secret exponent, constant-time), returning an `Fe`
/// canonical mod `m`. `base` must serialize to a value `< m`.
fn montModexpSecret(mp: *const MontParams, m: Modulus, base: Fe, exp_be: []const u8) Fe {
    var base_be: [modulus_sq_bytes]u8 = undefined;
    base.toBytes(&base_be, .big) catch unreachable;
    var out: [modulus_sq_bytes]u8 = undefined;
    const res = montPowSecret(mp, &base_be, exp_be, &out);
    return feFromMontBytes(m, res);
}

/// `base^exp mod m` (public exponent, variable-time in `exp`), returning an
/// `Fe` canonical mod `m`.
fn montModexpPublic(mp: *const MontParams, m: Modulus, base: Fe, exp_be: []const u8) Fe {
    var base_be: [modulus_sq_bytes]u8 = undefined;
    base.toBytes(&base_be, .big) catch unreachable;
    var out: [modulus_sq_bytes]u8 = undefined;
    const res = montPowPublic(mp, &base_be, exp_be, &out);
    return feFromMontBytes(m, res);
}

/// `ff.Modulus.reduce` assumes the input spans at least as many limbs as the
/// modulus; zero-extend the active limbs first so it is safe for narrow inputs
/// (e.g. reducing a mod-`p²` value into the mod-`q²` or mod-`n²` domain during
/// CRT recombination). Mirrors `rsa`'s `reduceWide`.
fn reduceWide(m: Modulus, x: Uint) Fe {
    var xx = x;
    if (xx.limbs_len < m.v.limbs_len) {
        @memset(xx.limbs_buffer[xx.limbs_len..m.v.limbs_len], 0);
        xx.limbs_len = m.v.limbs_len;
    }
    return m.reduce(xx);
}

// ── big-int scratch helpers (mechanical n² / n+1 derivation only — NO
//    keygen number theory: no primality, no gcd/lcm, no modular inverse) ────

const BigInt = std.math.big.int.Managed;

/// Limb capacity covering a `max_bits`-wide product plus headroom.
const big_capacity = (2 * max_bits) / @bitSizeOf(std.math.big.Limb) + 4;

/// Scratch arena size for the one-time, mechanical n²/n+1 derivations below.
/// Not on any per-ciphertext hot path. Matches `rsa`'s scratch sizing for
/// the same class of one-time big.int derivation.
const scratch_bytes = 128 * 1024;

fn newBig(gpa: std.mem.Allocator) !BigInt {
    return BigInt.initCapacity(gpa, big_capacity);
}

fn bigFromBytes(gpa: std.mem.Allocator, bytes: []const u8) !BigInt {
    var x = try newBig(gpa);
    if (bytes.len == 0) {
        try x.set(0);
        return x;
    }
    try x.ensureCapacity(bytes.len / @sizeOf(std.math.big.Limb) + 2);
    var m = x.toMutable();
    m.readTwosComplement(bytes, bytes.len * 8, .big, .unsigned);
    x.setMetadata(m.positive, m.len);
    return x;
}

/// `n_sq = n * n` — plain multiplication. Mechanical (no primality testing,
/// no modular inverse, no lambda/mu derivation happens here); used by
/// `PublicKey.fromBytes` / `SecretKey.fromBytes` to derive `n_sq` from a
/// serialized `n` without re-deriving the secret key material.
fn squareModulus(n_bytes: []const u8) !Modulus {
    var scratch: [scratch_bytes]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    const gpa = fba.allocator();

    var bn = try bigFromBytes(gpa, n_bytes);
    var bn_sq = try newBig(gpa);
    try bn_sq.mul(&bn, &bn);
    if (bn_sq.bitCountAbs() > max_bits) return error.Overflow;
    var buf: [modulus_sq_bytes]u8 = undefined;
    bn_sq.toConst().writeTwosComplement(&buf, .big);
    return try Modulus.fromBytes(&buf, .big);
}

/// `g = n + 1` (the standard-variant generator; Paillier 1999 §3, the choice
/// this module's `encrypt`/`decrypt` formulas assume) as an `Fe` canonical
/// mod `n_sq`. Plain addition — mechanical.
fn standardGenerator(n_bytes: []const u8, n_sq: Modulus) !Fe {
    var scratch: [scratch_bytes]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    const gpa = fba.allocator();

    var bn = try bigFromBytes(gpa, n_bytes);
    var bg = try newBig(gpa);
    try bg.addScalar(&bn, 1);
    var buf: [modulus_sq_bytes]u8 = undefined;
    bg.toConst().writeTwosComplement(&buf, .big);
    return try Fe.fromBytes(n_sq, &buf, .big);
}

// ── PublicKey ─────────────────────────────────────────────────────────────

/// Paillier public key: `n` (the RSA-like composite modulus), `n_sq` (= n²,
/// precomputed since every ciphertext operation needs it), and `g` (the
/// generator; the standard variant `g = n+1` unless the key was built with an
/// explicit `g`).
pub const PublicKey = struct {
    n: Modulus,
    n_sq: Modulus,
    /// Canonical mod `n_sq` (see the "Fe construction contract" note above).
    g: Fe,
    /// Precomputed montint modulus + Montgomery constants for `n²` (the
    /// `r^n mod n²` public op of `encrypt`).
    n_sq_mont: MontParams,

    pub const FromBytesError = error{InvalidPublicKey};

    /// Build a `PublicKey` from a raw big-endian `n` and (optionally) an
    /// explicit `g`; `n_sq` is always re-derived here (mechanical squaring),
    /// never trusted from an external source. If `g_bytes` is `null`, the
    /// standard variant `g = n+1` is used. This is pure parsing/derivation of
    /// an *already-chosen* `n` — it does NOT generate or validate that `n` is
    /// a product of two primes (that is `generate`/`fromPrimes`'s job).
    pub fn fromBytes(n_bytes: []const u8, g_bytes: ?[]const u8) FromBytesError!PublicKey {
        return fromBytesImpl(n_bytes, g_bytes) catch error.InvalidPublicKey;
    }

    fn fromBytesImpl(n_bytes_in: []const u8, g_bytes: ?[]const u8) !PublicKey {
        const n_bytes = stripLeadingZeros(n_bytes_in);
        if (n_bytes.len == 0 or n_bytes.len > modulus_bytes) return error.InvalidPublicKey;
        const n = Modulus.fromBytes(n_bytes, .big) catch return error.InvalidPublicKey;

        const n_sq = squareModulus(n_bytes) catch return error.InvalidPublicKey;

        const g: Fe = if (g_bytes) |gb| blk: {
            const gs = stripLeadingZeros(gb);
            break :blk Fe.fromBytes(n_sq, gs, .big) catch return error.InvalidPublicKey;
        } else standardGenerator(n_bytes, n_sq) catch return error.InvalidPublicKey;

        return .{ .n = n, .n_sq = n_sq, .g = g, .n_sq_mont = montParamsFromModulus(n_sq) };
    }

    /// `n` is a `Modulus` (`Modulus.toBytes` only fails with `Overflow`);
    /// `g` is an `Fe` (`Fe.toBytes` can additionally fail with
    /// `UnexpectedRepresentation` if it were ever left in Montgomery form —
    /// never true for values this module hands back to a caller).
    pub const ByteError = std.crypto.ff.OverflowError || std.crypto.ff.RepresentationError;

    /// Minimum buffer length (bytes) `nToBytes` needs.
    pub fn nByteLen(self: PublicKey) usize {
        return byteLen(self.n.bits());
    }

    /// Encodes `n` as big-endian bytes into `out` (`out.len` must be >=
    /// `nByteLen()`; shorter values are zero-padded from the left).
    pub fn nToBytes(self: PublicKey, out: []u8) ByteError!void {
        return self.n.toBytes(out, .big);
    }

    /// Encodes `g` (canonical mod `n_sq`) as big-endian bytes into `out`
    /// (`out.len` must be >= `modulus_sq_bytes`, or exactly big enough to
    /// hold the actual value — see `Fe.toBytes`).
    pub fn gToBytes(self: PublicKey, out: []u8) ByteError!void {
        return self.g.toBytes(out, .big);
    }
};

// ── SecretKey ─────────────────────────────────────────────────────────────

/// CRT decryption parameters (Paillier-CRT / Hazay-Lindell). Rather than one
/// full-width `c^λ mod n²`, decrypt computes the two half-width exponentiations
/// `c^(λ mod p(p-1)) mod p²` and `c^(λ mod q(q-1)) mod q²` — each over a
/// half-size modulus (L=32 vs L=64: montint's O(L²) modmul is ~4× cheaper) and
/// a half-size exponent — then Garner-recombines them into `x = c^λ mod n²`.
/// The reduced exponents are valid because a well-formed ciphertext is a unit
/// mod `p²`/`q²`, so `c^λ ≡ c^(λ mod |(Z/p²)*|)` with `|(Z/p²)*| = p(p-1)`
/// (Lagrange). The recombined `x` is byte-identical to the single-modulus
/// result, so the downstream `L(x)·µ mod n` step (and the phe cross-check) is
/// unchanged. Net ~4× on decrypt on top of the montint constant-factor win.
///
/// All fields are factorization-equivalent secrets (or derived from them).
const CrtParams = struct {
    /// montint constants for `p²` (the `c^dp mod p²` CRT half).
    p_sq_mont: MontParams,
    /// montint constants for `q²` (the `c^dq mod q²` CRT half).
    q_sq_mont: MontParams,
    /// `λ mod p(p-1)`, the reduced CRT exponent, big-endian, `< 2^modulus_bits`.
    dp: [modulus_bytes]u8,
    /// `λ mod q(q-1)`, the reduced CRT exponent, big-endian.
    dq: [modulus_bytes]u8,
    /// `p²` as an `ff` modulus — used to reduce `c` into the mod-`p²` domain.
    p_sq: Modulus,
    /// `q²` as an `ff` modulus — the domain of the Garner recombination step
    /// (and to reduce `c` into the mod-`q²` domain).
    q_sq: Modulus,
    /// `p²` as an `Fe` canonical mod `n_sq` — the `x = x_p + p²·u` multiplier.
    p_sq_fe: Fe,
    /// `(p²)⁻¹ mod q²`, canonical mod `q_sq` — the Garner coefficient.
    p_sq_inv: Fe,
};

/// Paillier secret key: `lambda` = Carmichael function λ(n) = lcm(p-1, q-1)
/// (canonical mod `n_sq` — it is used as the exponent in `c^lambda mod n²`),
/// `mu` = L(g^lambda mod n²)⁻¹ mod n (canonical mod `n`), plus `n`/`n_sq` for
/// convenience so `decrypt` doesn't need a separate `PublicKey`, and an
/// optional `crt` block (the factors + derived CRT material) enabling the ~4×
/// CRT decrypt path.
pub const SecretKey = struct {
    n: Modulus,
    n_sq: Modulus,
    /// Canonical mod `n_sq` (see the "Fe construction contract" note above).
    lambda: Fe,
    /// Canonical mod `n`.
    mu: Fe,
    /// Precomputed montint constants for `n²` — the non-CRT decrypt path
    /// (`c^λ mod n²`), used when `crt` is `null` (e.g. keys loaded via
    /// `fromBytes`, which carries no factors).
    n_sq_mont: MontParams,
    /// CRT decryption parameters (the factors `p`,`q` and everything derived
    /// from them). Present for keys built by `fromPrimes`/`generate`; `null`
    /// for keys parsed from `n`/`lambda`/`mu` alone (`fromBytes`), which then
    /// fall back to the single-modulus `c^λ mod n²` path. The factors are
    /// already-secret material, so retaining them changes no exposure.
    crt: ?CrtParams,

    pub const FromBytesError = error{InvalidPrivateKey};

    /// Parse an already-derived `SecretKey` from raw big-endian `n`/`lambda`/
    /// `mu` bytes (e.g. round-tripping a key this module itself produced, or
    /// loading one from storage). This does NOT derive `lambda`/`mu` from
    /// primes — that is `fromPrimes`'s job; this is pure mechanical parsing
    /// plus the same mechanical `n_sq = n*n` re-derivation
    /// `PublicKey.fromBytes` does.
    pub fn fromBytes(n_bytes: []const u8, lambda_bytes: []const u8, mu_bytes: []const u8) FromBytesError!SecretKey {
        return fromBytesImpl(n_bytes, lambda_bytes, mu_bytes) catch error.InvalidPrivateKey;
    }

    fn fromBytesImpl(n_bytes_in: []const u8, lambda_bytes_in: []const u8, mu_bytes_in: []const u8) !SecretKey {
        const n_bytes = stripLeadingZeros(n_bytes_in);
        if (n_bytes.len == 0 or n_bytes.len > modulus_bytes) return error.InvalidPrivateKey;
        const n = Modulus.fromBytes(n_bytes, .big) catch return error.InvalidPrivateKey;
        const n_sq = squareModulus(n_bytes) catch return error.InvalidPrivateKey;

        const lambda_bytes = stripLeadingZeros(lambda_bytes_in);
        const lambda = Fe.fromBytes(n_sq, lambda_bytes, .big) catch return error.InvalidPrivateKey;

        const mu_bytes = stripLeadingZeros(mu_bytes_in);
        const mu = Fe.fromBytes(n, mu_bytes, .big) catch return error.InvalidPrivateKey;

        // No factors available from a serialized n/λ/µ key → no CRT block;
        // decrypt falls back to the single-modulus `c^λ mod n²` montint path.
        return .{
            .n = n,
            .n_sq = n_sq,
            .lambda = lambda,
            .mu = mu,
            .n_sq_mont = montParamsFromModulus(n_sq),
            .crt = null,
        };
    }

    pub const ByteError = std.crypto.ff.OverflowError || std.crypto.ff.RepresentationError;

    pub fn nByteLen(self: SecretKey) usize {
        return byteLen(self.n.bits());
    }

    pub fn nToBytes(self: SecretKey, out: []u8) ByteError!void {
        return self.n.toBytes(out, .big);
    }

    /// `lambda` is canonical mod `n_sq`; `out.len` should be sized
    /// accordingly (see the "Fe construction contract" note above).
    pub fn lambdaToBytes(self: SecretKey, out: []u8) ByteError!void {
        return self.lambda.toBytes(out, .big);
    }

    /// `mu` is canonical mod `n`.
    pub fn muToBytes(self: SecretKey, out: []u8) ByteError!void {
        return self.mu.toBytes(out, .big);
    }

    /// Zero this key's SECRET material: `lambda`/`mu`, and (when present)
    /// the entire `crt` block. `crt.p_sq`/`crt.q_sq` are `p²`/`q²` — from
    /// which the factorization `p`,`q` is directly recoverable (a square
    /// root over the integers) — so every field derived from them
    /// (`p_sq_mont`/`q_sq_mont`/`dp`/`dq`/`p_sq_fe`/`p_sq_inv`) is
    /// factorization-equivalent secret material too (see `CrtParams`'s doc
    /// comment). `n`/`n_sq`/`n_sq_mont` are PUBLIC — the same values the
    /// `PublicKey` carries — and are left untouched. Idempotent; the key
    /// must not be used again after calling this.
    pub fn deinit(sk: *SecretKey) void {
        std.crypto.secureZero(u8, std.mem.asBytes(&sk.lambda));
        std.crypto.secureZero(u8, std.mem.asBytes(&sk.mu));
        if (sk.crt) |*crt| std.crypto.secureZero(u8, std.mem.asBytes(crt));
    }
};

// ── Ciphertext ────────────────────────────────────────────────────────────

/// A Paillier ciphertext: a single `Fe`, canonical mod the `PublicKey`'s
/// `n_sq`.
pub const Ciphertext = struct {
    c: Fe,

    pub const FromBytesError = error{InvalidCiphertext};

    /// Parse a ciphertext from raw big-endian bytes, canonical mod `pk.n_sq`.
    pub fn fromBytes(pk: PublicKey, bytes: []const u8) FromBytesError!Ciphertext {
        const b = stripLeadingZeros(bytes);
        const c = Fe.fromBytes(pk.n_sq, b, .big) catch return error.InvalidCiphertext;
        return .{ .c = c };
    }

    pub const ByteError = std.crypto.ff.OverflowError || std.crypto.ff.RepresentationError;

    /// Encodes the ciphertext as big-endian bytes into `out` (`out.len` must
    /// be >= `modulus_sq_bytes`, or exactly big enough for the actual value).
    pub fn toBytes(self: Ciphertext, out: []u8) ByteError!void {
        return self.c.toBytes(out, .big);
    }
};

// ── keygen ────────────────────────────────────────────────────────────────

pub const KeyPair = struct {
    public: PublicKey,
    secret: SecretKey,
};

pub const FromPrimesError = error{ InvalidPrimes, Overflow };
pub const GenerateError = FromPrimesError || error{InvalidBits};

/// x⁻¹ (mod m) via the extended Euclidean algorithm; fails unless
/// gcd(x, m) = 1. Variable-time — used only inside the one-time `fromPrimes`
/// key derivation (see SPEC.md's timing note). Same shape as `rsa`'s
/// `bigModInverse`.
fn bigModInverse(gpa: std.mem.Allocator, x: *const BigInt, m: *const BigInt) !BigInt {
    // Invariants: t0*x ≡ r0, t1*x ≡ r1 (mod m).
    var r0 = try newBig(gpa);
    try r0.copy(m.toConst());
    var r1 = try newBig(gpa);
    try r1.copy(x.toConst());
    var t0 = try newBig(gpa);
    try t0.set(0);
    var t1 = try newBig(gpa);
    try t1.set(1);
    var quot = try newBig(gpa);
    var rem = try newBig(gpa);
    var tmp = try newBig(gpa);
    var new_t = try newBig(gpa);

    while (!r1.eqlZero()) {
        try quot.divFloor(&rem, &r0, &r1);
        // (r0, r1) <- (r1, r0 mod r1)
        r0.swap(&r1);
        r1.swap(&rem);
        // (t0, t1) <- (t1, t0 - quot*t1)
        try tmp.mul(&quot, &t1);
        try new_t.sub(&t0, &tmp);
        t0.swap(&t1);
        t1.swap(&new_t);
    }
    // r0 = gcd(x, m); must be 1 for x to be invertible.
    if (r0.toConst().orderAgainstScalar(1) != .eq) return error.NotInvertible;
    // t0*x ≡ 1 (mod m); normalize t0 (possibly negative) into [0, m).
    try quot.divFloor(&rem, &t0, m);
    return rem;
}

/// Derive a `KeyPair` from two prime factors `p`, `q` (raw big-endian
/// bytes), for deterministic/reproducible construction (KATs, testing) —
/// mirrors `rsa.SecretKey.fromPrimes`. `p`/`q` are trusted to be prime (no
/// primality test here; that is `generate`'s job) — the derivation's own
/// self-checks (L-exactness, mu invertibility) catch many composites, but
/// NOT all: a key derived from composite factors decrypts garbage.
///
/// Construction (Paillier 1999 §3, standard `g = n+1` variant):
///   1. `n = p * q`; reject `p == q` and products over `modulus_bits`
///      (`error.Overflow`).
///   2. `lambda = lcm(p-1, q-1) = (p-1)*(q-1) / gcd(p-1, q-1)` (big-int
///      gcd, exactly like `rsa.fromPrimesImpl`'s λ(n) step).
///   3. `g = n + 1`.
///   4. `mu = L(g^lambda mod n²)⁻¹ mod n`, where `L(x) = (x-1)/n` (exact
///      integer division — `g^lambda ≡ 1 (mod n)` is guaranteed for prime
///      p, q, Paillier 1999 Theorem 2) and `⁻¹` is `bigModInverse`.
///      `g^lambda mod n²` uses constant-time `pow`, never `powPublic` —
///      `lambda` is factorization-equivalent secret material.
pub fn fromPrimes(p_bytes: []const u8, q_bytes: []const u8) FromPrimesError!KeyPair {
    return fromPrimesImpl(p_bytes, q_bytes) catch |err| switch (err) {
        error.Overflow => error.Overflow,
        else => error.InvalidPrimes,
    };
}

fn fromPrimesImpl(p_bytes_in: []const u8, q_bytes_in: []const u8) !KeyPair {
    const pb = stripLeadingZeros(p_bytes_in);
    const qb = stripLeadingZeros(q_bytes_in);
    if (pb.len == 0 or qb.len == 0) return error.InvalidPrimes;
    if (pb.len > modulus_bytes or qb.len > modulus_bytes) return error.InvalidPrimes;

    // All big.int scratch lives in a stack arena; individual deinit is
    // pointless (fixed buffer), the whole arena dies with this frame — same
    // idiom as `rsa.fromPrimesImpl`. Doubled vs `scratch_bytes` because the
    // CRT-parameter derivation below adds a second modular inversion plus
    // several full-width products, all in this one arena.
    var scratch: [2 * scratch_bytes]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    const gpa = fba.allocator();

    var bp = try bigFromBytes(gpa, pb);
    var bq = try bigFromBytes(gpa, qb);
    if (bp.order(bq) == .eq) return error.InvalidPrimes; // p == q
    // p, q >= 3: p = 2 would make n even (Montgomery needs odd) and p <= 1
    // breaks p-1; reject explicitly rather than let later steps fail.
    if (bp.toConst().orderAgainstScalar(3) == .lt) return error.InvalidPrimes;
    if (bq.toConst().orderAgainstScalar(3) == .lt) return error.InvalidPrimes;

    // 1. n = p*q, capped at modulus_bits.
    var bn = try newBig(gpa);
    try bn.mul(&bp, &bq);
    if (bn.bitCountAbs() > modulus_bits) return error.Overflow;
    var n_buf: [modulus_bytes]u8 = undefined;
    bn.toConst().writeTwosComplement(&n_buf, .big);
    const n = Modulus.fromBytes(&n_buf, .big) catch return error.InvalidPrimes; // rejects even n

    // n² (the same mechanical squaring `squareModulus` performs, kept in
    // this arena to avoid a second scratch buffer) and 3. g = n + 1.
    var bn_sq = try newBig(gpa);
    try bn_sq.mul(&bn, &bn);
    var nsq_buf: [modulus_sq_bytes]u8 = undefined;
    bn_sq.toConst().writeTwosComplement(&nsq_buf, .big);
    const n_sq = Modulus.fromBytes(&nsq_buf, .big) catch return error.InvalidPrimes;

    var bg = try newBig(gpa);
    try bg.addScalar(&bn, 1);
    var g_buf: [modulus_sq_bytes]u8 = undefined;
    bg.toConst().writeTwosComplement(&g_buf, .big);
    // Canonical mod n_sq per the Fe construction contract (n+1 < n² always).
    const g = Fe.fromBytes(n_sq, &g_buf, .big) catch return error.InvalidPrimes;

    // 2. lambda = lcm(p-1, q-1) = (p-1)(q-1) / gcd(p-1, q-1).
    var p1 = try newBig(gpa);
    try p1.addScalar(&bp, -1);
    var q1 = try newBig(gpa);
    try q1.addScalar(&bq, -1);
    var gg = try newBig(gpa);
    try gg.gcd(&p1, &q1);
    var phi = try newBig(gpa);
    try phi.mul(&p1, &q1);
    var lambda_big = try newBig(gpa);
    var rem = try newBig(gpa);
    try lambda_big.divFloor(&rem, &phi, &gg); // exact: gcd | (p-1)(q-1)

    var lambda_buf: [modulus_sq_bytes]u8 = undefined;
    lambda_big.toConst().writeTwosComplement(&lambda_buf, .big);
    // Canonical mod n_sq — lambda is the exponent of c^lambda mod n², and
    // lambda <= (p-1)(q-1) < n < n² always.
    const lambda = Fe.fromBytes(n_sq, &lambda_buf, .big) catch return error.InvalidPrimes;
    if (lambda.isZero()) return error.InvalidPrimes; // impossible for p, q >= 3

    // 4. mu = L(g^lambda mod n²)⁻¹ mod n, L(x) = (x-1)/n (exact division).
    const x = n_sq.pow(g, lambda) catch return error.InvalidPrimes; // constant-time
    var x_buf: [modulus_sq_bytes]u8 = undefined;
    x.toBytes(&x_buf, .big) catch return error.InvalidPrimes;
    var bx = try bigFromBytes(gpa, &x_buf);
    var bx1 = try newBig(gpa);
    try bx1.addScalar(&bx, -1);
    var bl = try newBig(gpa);
    try bl.divFloor(&rem, &bx1, &bn);
    // Paillier 1999 Theorem 2: g^lambda ≡ 1 (mod n) for prime p, q — a
    // nonzero remainder means the supplied factors weren't prime.
    if (!rem.eqlZero()) return error.InvalidPrimes;
    // bigModInverse also proves gcd(L, n) = 1 (and rejects L = 0).
    var bmu = try bigModInverse(gpa, &bl, &bn);
    var mu_buf: [modulus_bytes]u8 = undefined;
    bmu.toConst().writeTwosComplement(&mu_buf, .big);
    const mu = Fe.fromBytes(n, &mu_buf, .big) catch return error.InvalidPrimes; // canonical mod n

    // ── CRT decryption parameters (Paillier-CRT / Hazay-Lindell) ──────────
    // p², q² as ff moduli (odd; p,q ≥ 3 ⇒ p²,q² ≥ 9). Both < 2^modulus_bits.
    var bp_sq = try newBig(gpa);
    try bp_sq.mul(&bp, &bp);
    var bq_sq = try newBig(gpa);
    try bq_sq.mul(&bq, &bq);
    var psq_buf: [modulus_sq_bytes]u8 = undefined;
    bp_sq.toConst().writeTwosComplement(&psq_buf, .big);
    const p_sq = Modulus.fromBytes(&psq_buf, .big) catch return error.InvalidPrimes;
    var qsq_buf: [modulus_sq_bytes]u8 = undefined;
    bq_sq.toConst().writeTwosComplement(&qsq_buf, .big);
    const q_sq = Modulus.fromBytes(&qsq_buf, .big) catch return error.InvalidPrimes;

    // Reduced CRT exponents: dp = λ mod p(p-1), dq = λ mod q(q-1). Valid to
    // reduce because a well-formed ciphertext is a unit mod p²/q² and
    // |(Z/p²)*| = p(p-1) (Lagrange), so c^λ ≡ c^(λ mod p(p-1)) (mod p²).
    var p_ord = try newBig(gpa);
    try p_ord.mul(&bp, &p1); // p·(p-1)
    var q_ord = try newBig(gpa);
    try q_ord.mul(&bq, &q1); // q·(q-1)
    var quo = try newBig(gpa);
    var dp_big = try newBig(gpa);
    try quo.divFloor(&dp_big, &lambda_big, &p_ord); // remainder = λ mod p(p-1)
    var dq_big = try newBig(gpa);
    try quo.divFloor(&dq_big, &lambda_big, &q_ord);
    var dp_buf = [_]u8{0} ** modulus_bytes;
    dp_big.toConst().writeTwosComplement(&dp_buf, .big); // < p(p-1) < 2^modulus_bits
    var dq_buf = [_]u8{0} ** modulus_bytes;
    dq_big.toConst().writeTwosComplement(&dq_buf, .big);

    // Garner coefficient (p²)⁻¹ mod q² (gcd(p²,q²)=1 for distinct primes),
    // and p² as an Fe canonical mod n² (the x = x_p + p²·u multiplier).
    var pinv_big = try bigModInverse(gpa, &bp_sq, &bq_sq);
    var pinv_buf: [modulus_sq_bytes]u8 = undefined;
    pinv_big.toConst().writeTwosComplement(&pinv_buf, .big);
    const p_sq_inv = Fe.fromBytes(q_sq, stripLeadingZeros(&pinv_buf), .big) catch return error.InvalidPrimes;
    const p_sq_fe = Fe.fromBytes(n_sq, stripLeadingZeros(&psq_buf), .big) catch return error.InvalidPrimes;

    const n_sq_mont = montParamsFromModulus(n_sq);

    return .{
        .public = .{ .n = n, .n_sq = n_sq, .g = g, .n_sq_mont = n_sq_mont },
        .secret = .{
            .n = n,
            .n_sq = n_sq,
            .lambda = lambda,
            .mu = mu,
            .n_sq_mont = n_sq_mont,
            .crt = .{
                .p_sq_mont = montParamsFromModulus(p_sq),
                .q_sq_mont = montParamsFromModulus(q_sq),
                .dp = dp_buf,
                .dq = dq_buf,
                .p_sq = p_sq,
                .q_sq = q_sq,
                .p_sq_fe = p_sq_fe,
                .p_sq_inv = p_sq_inv,
            },
        },
    };
}

// ── prime generation (mirrors `rsa`'s probable-prime search) ──────────────
//
// Same construction as this repo's `rsa` module: draw random odd candidates
// of exactly `prime_bits` bits with the two top bits set (so n = p·q always
// lands on exactly 2·prime_bits bits), trial-divide against a comptime
// sieve, then Miller-Rabin with 64 random witnesses (FIPS 186-5 Table B.1's
// largest requirement is 44 rounds; 64 dominates every entry and gives a
// worst-case 4^-64 = 2^-128 error bound per accepted candidate). Unlike
// `rsa` there is no public exponent `e` to keep coprime, so that filter is
// dropped. gcd(n, φ(n)) = 1 — which the g = n+1 decryption relies on —
// holds by construction for two same-length primes: p | q-1 would need
// q-1 >= p, impossible when both lie in [2^(b-1)+2^(b-2), 2^b) with p ≠ q.
//
// Timing: the prime search loop is inherently variable-time (every
// implementation's is); the modexps inside Miller-Rabin still use `ff`'s
// constant-time path, and all candidate buffers are secureZero'ed. What
// remains observable is how long the search took, which reveals nothing
// useful about the primes that were kept.

/// Miller-Rabin rounds per candidate — see the section comment above.
const mr_rounds = 64;

/// Odd primes below 1024 for the trial-division pre-sieve, generated at
/// comptime (sieve of Eratosthenes). Filters ~84% of random odd candidates
/// with cheap byte-wise remainders before any Miller-Rabin modexp runs.
const sieve_primes = blk: {
    @setEvalBranchQuota(20_000);
    const limit = 1024;
    var composite = [_]bool{false} ** limit;
    var count: usize = 0;
    var i: usize = 3;
    while (i < limit) : (i += 2) {
        if (composite[i]) continue;
        count += 1;
        var j = i * i;
        while (j < limit) : (j += 2 * i) composite[j] = true;
    }
    var list: [count]u16 = undefined;
    var idx: usize = 0;
    i = 3;
    while (i < limit) : (i += 2) {
        if (composite[i]) continue;
        list[idx] = i;
        idx += 1;
    }
    break :blk list;
};

/// Big-endian unsigned `bytes` mod `divisor` (u128 intermediate: safe for
/// any u64 divisor). Pre-sieve only — variable-time, never touches a kept
/// secret in a data-dependent way beyond the reject/accept decision itself.
fn bytesMod(bytes: []const u8, divisor: u64) u64 {
    std.debug.assert(divisor != 0);
    var r: u64 = 0;
    for (bytes) |b| {
        r = @intCast(((@as(u128, r) << 8) | b) % divisor);
    }
    return r;
}

/// In-place big-endian right shift by `s` bits (zero-fill from the left).
fn shrBytesBe(buf: []u8, s: usize) void {
    const byte_sh = s / 8;
    const bit_sh: u4 = @intCast(s % 8);
    var i: usize = buf.len;
    while (i > 0) {
        i -= 1;
        const lo: u16 = if (i >= byte_sh) buf[i - byte_sh] else 0;
        const hi: u16 = if (i >= byte_sh + 1) buf[i - byte_sh - 1] else 0;
        buf[i] = @truncate(((hi << 8) | lo) >> bit_sh);
    }
}

/// Set bit `bit` (LSB = 0) of a big-endian byte string.
fn setBitBe(buf: []u8, bit: usize) void {
    buf[buf.len - 1 - bit / 8] |= @as(u8, 1) << @intCast(bit % 8);
}

/// Uniform random Miller-Rabin witness in [2, m-2] by rejection sampling
/// (mask to m's bit length, retry on out-of-range — expected < 2 draws).
fn randomWitness(m: Modulus, random: std.Random) Fe {
    const n_bits = m.bits();
    const n_len = byteLen(n_bits);
    const n_minus_1 = m.sub(m.zero, m.one());
    var buf: [modulus_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, buf[0..n_len]);
    while (true) {
        random.bytes(buf[0..n_len]);
        buf[0] &= @as(u8, 0xff) >> @intCast(8 * n_len - n_bits);
        const a = Fe.fromBytes(m, buf[0..n_len], .big) catch continue; // >= m: redraw
        if (a.isZero() or a.eql(m.one()) or a.eql(n_minus_1)) continue; // outside [2, m-2]
        return a;
    }
}

/// Miller-Rabin probable-prime test with `mr_rounds` random witnesses from
/// `random`. `m` must be an odd integer >= 5 (every `Modulus` is odd by
/// construction; callers here only ever pass >= 2^255). Returns false iff a
/// witness proves `m` composite.
fn isProbablePrime(m: Modulus, random: std.Random) bool {
    const n_len = byteLen(m.bits());

    // m - 1 = d * 2^s with d odd: m is odd, so m-1 is just m with the low
    // bit cleared, s = ctz(m-1) >= 1, d = (m-1) >> s.
    var d_buf: [modulus_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, d_buf[0..n_len]);
    m.toBytes(d_buf[0..n_len], .big) catch unreachable; // buffer is exactly byteLen(bits)
    d_buf[n_len - 1] &= 0xfe;
    var s: usize = 0;
    var i: usize = n_len;
    while (i > 0) {
        i -= 1;
        if (d_buf[i] == 0) {
            s += 8;
        } else {
            s += @ctz(d_buf[i]);
            break;
        }
    }
    shrBytesBe(d_buf[0..n_len], s);
    const d_bytes = stripLeadingZeros(d_buf[0..n_len]);

    const one = m.one();
    const n_minus_1 = m.sub(m.zero, one);

    var round: usize = 0;
    rounds: while (round < mr_rounds) : (round += 1) {
        const a = randomWitness(m, random);
        // a^d mod m — constant-time modexp (the exponent d is m-derived).
        var x = m.powWithEncodedExponent(a, d_bytes, .big) catch unreachable; // d is odd, never 0
        if (x.eql(one) or x.eql(n_minus_1)) continue :rounds;
        var j: usize = 1;
        while (j < s) : (j += 1) {
            x = m.sq(x);
            if (x.eql(n_minus_1)) continue :rounds;
            // A nontrivial square root of 1: composite for sure — stop early.
            if (x.eql(one)) return false;
        }
        return false; // never hit m-1: `a` witnesses compositeness
    }
    return true;
}

/// Draw random odd candidates of exactly `prime_bits` bits with the top two
/// bits set (so p·q of two such primes always reaches 2·`prime_bits` bits),
/// pre-sieve by trial division, and Miller-Rabin test until a probable
/// prime lands in `out` (`out.len == byteLen(prime_bits)`).
fn generatePrime(random: std.Random, prime_bits: usize, out: []u8) void {
    std.debug.assert(out.len == byteLen(prime_bits));
    std.debug.assert(prime_bits >= 128); // callers: >= 256 (bits >= 512)
    const top_mask = @as(u8, 0xff) >> @intCast(8 * out.len - prime_bits);
    candidates: while (true) {
        random.bytes(out);
        out[0] &= top_mask;
        setBitBe(out, prime_bits - 1); // exact bit length…
        setBitBe(out, prime_bits - 2); // …and p·q >= 2^(2·prime_bits - 1)
        out[out.len - 1] |= 1; // odd

        // Trial-division pre-sieve. Candidates are >= 2^127, so a zero
        // remainder always means a proper factor, never candidate == prime.
        for (sieve_primes) |sp| {
            if (bytesMod(out, sp) == 0) continue :candidates;
        }

        // Odd, >= 3, <= modulus_bytes bytes: Modulus.fromBytes can't fail.
        const m = Modulus.fromBytes(out, .big) catch unreachable;
        if (isProbablePrime(m, random)) return;
    }
}

/// FIPS 186-5 §A.1.3 closeness guard: reject q when the top 100 bits of p
/// and q coincide (a sufficient condition for |p − q| <= 2^(plen − 100),
/// which would expose n to Fermat factorization). Also subsumes p == q.
fn topBitsMatch(p: []const u8, q: []const u8) bool {
    std.debug.assert(p.len == q.len and p.len >= 13);
    if (!std.mem.eql(u8, p[0..12], q[0..12])) return false; // 96 bits
    return (p[12] ^ q[12]) & 0xf0 == 0; // + 4 more = 100 bits
}

/// Floor `generate` enforces on `bits` — mirrors `rsa`'s 512-bit minimum
/// (any real deployment uses `modulus_bits`; the floor only guards against
/// sizes the prime search above cannot honor).
pub const min_generate_bits = 512;

/// Generate a random `KeyPair` with an `n` of exactly `bits` bits (two
/// random `bits/2`-bit probable primes p, q, both with their top two bits
/// set), then derive the key material via `fromPrimes`. `random` MUST be a
/// cryptographically secure generator for real keys (the primes are drawn
/// straight from it); a seeded deterministic generator is acceptable only
/// for tests. `bits` must be even and in [`min_generate_bits`,
/// `modulus_bits`]; expect a slow search as `bits` grows (2048 is
/// noticeably slow in Debug builds).
pub fn generate(random: std.Random, bits: usize) GenerateError!KeyPair {
    if (bits < min_generate_bits or bits > modulus_bits or bits % 2 != 0) return error.InvalidBits;
    const half = bits / 2;
    const half_len = byteLen(half);

    var p_buf: [modulus_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, p_buf[0..half_len]);
    var q_buf: [modulus_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, q_buf[0..half_len]);
    const p_bytes = p_buf[0..half_len];
    const q_bytes = q_buf[0..half_len];

    while (true) {
        generatePrime(random, half, p_bytes);
        while (true) {
            generatePrime(random, half, q_bytes);
            if (!topBitsMatch(p_bytes, q_bytes)) break;
        }
        // p ≠ q and both (probable) primes: `fromPrimes` can only fail here
        // if a Miller-Rabin false positive slipped through (<= 2^-128 per
        // prime) and tripped its L-exactness/invertibility self-checks —
        // restart the search instead of surfacing an error for an input the
        // caller never chose (mirrors `rsa.generate`).
        return fromPrimes(p_bytes, q_bytes) catch continue;
    }
}

// ── encrypt / decrypt ─────────────────────────────────────────────────────

pub const EncryptError = std.crypto.ff.NullExponentError || std.crypto.ff.RepresentationError;

/// `n`'s value as an `Fe` canonical mod `n_sq` — the one "widening"
/// direction the Fe construction contract requires a fresh byte-level
/// construction for (`Modulus.shrink` never widens).
fn nAsFeModNsq(n: Modulus, n_sq: Modulus) Fe {
    var buf: [modulus_bytes]u8 = undefined;
    const n_len = byteLen(n.bits());
    n.toBytes(buf[0..n_len], .big) catch unreachable; // exact-size buffer
    return Fe.fromBytes(n_sq, buf[0..n_len], .big) catch unreachable; // n < n² always
}

/// `g^m mod n²` with the two special cases `encrypt`/`addPlaintext` need:
///
///   - **Standard generator `g = n+1` (the only kind this module ever
///     derives):** the binomial theorem collapses `(1+n)^m = Σ C(m,k)·n^k ≡
///     1 + m·n (mod n²)` — every k >= 2 term carries an n² factor — so one
///     constant-time `mul` + `add` replaces a full modexp. This also handles
///     `m = 0` for free (1 + 0·n = 1) with no data-dependent branch, and a
///     possibly-secret `m` never enters a bit-scanned exponent path at all.
///   - **`m = 0` under a caller-supplied non-standard `g`
///     (`PublicKey.fromBytes` with explicit `g_bytes`):** `ff`'s `pow`
///     rejects zero exponents (`NullExponent`), but `E(0)` is a valid
///     plaintext — `g^0 = 1`. Otherwise fall back to the general
///     constant-time `pow`.
fn gPow(pk: PublicKey, m: Fe) HomomorphicError!Fe {
    const one = pk.n_sq.one();
    const n_fe = nAsFeModNsq(pk.n, pk.n_sq);
    const g_std = pk.n_sq.add(n_fe, one); // the standard generator, n+1
    if (pk.g.eql(g_std)) return pk.n_sq.add(pk.n_sq.mul(m, n_fe), one);
    if (m.isZero()) return one;
    return pk.n_sq.pow(pk.g, m);
}

/// Paillier encryption: `c = g^m * r^n mod n²` (Paillier 1999 §3). `m` must
/// be canonical mod `pk.n_sq` and `< pk.n` (see the "Fe construction
/// contract" note above the module doc comment — construct it via
/// `Fe.fromBytes(pk.n_sq, ...)`/`Fe.fromPrimitive(T, pk.n_sq, ...)`, NOT
/// `pk.n`). `r` (the blinding randomness) must likewise be canonical mod
/// `pk.n_sq`, `0 < r < pk.n`, and coprime to `pk.n` (gcd(r, n) = 1 — for a
/// random `r` drawn from a large `n`'s factors this holds with overwhelming
/// probability and is not checked by most reference implementations,
/// including phe/python-paillier; see `encryptRandom`, which samples `r`
/// this way). Caller-supplied `r` here is for deterministic/KAT-reproducible
/// encryption; use `encryptRandom` to have `r` sampled automatically.
///
/// The `g^m` term goes through `gPow` (see there): for the standard
/// `g = n+1` it is the binomial shortcut `1 + m·n mod n²` (no modexp, and
/// `m = 0` needs no special case); for a caller-supplied `g` it is a
/// constant-time `pow` with `g^0 = 1` special-cased around `ff`'s
/// `NullExponent` guard. The `r^n` term uses `powPublic` — the exponent `n`
/// is the public modulus (the *base* `r` is still processed in constant
/// time), and `r` is never legitimately zero (gcd(0,n) = n != 1), so no
/// zero-exponent case can arise there.
pub fn encrypt(pk: PublicKey, m: Fe, r: Fe) EncryptError!Ciphertext {
    const gm = try gPow(pk, m);
    // r^n mod n² — the modexp hot path, routed through montint. `n` is the
    // PUBLIC modulus (variable-time in the exponent is fine); the base `r`
    // still goes through montint's constant-time Montgomery multiply.
    var n_be: [modulus_bytes]u8 = undefined;
    const n_len = byteLen(pk.n.bits());
    pk.n.toBytes(n_be[0..n_len], .big) catch unreachable; // exact-size buffer
    const rn = montModexpPublic(&pk.n_sq_mont, pk.n_sq, r, n_be[0..n_len]);
    return .{ .c = pk.n_sq.mul(gm, rn) };
}

/// `encrypt` with `r` sampled uniformly from `[1, pk.n)` by rejection
/// sampling (mirrors `rsa`'s `randomWitness` pattern: mask to `n`'s bit
/// length, redraw on out-of-range or zero). Production callers MUST use
/// this (or equivalent care drawing `r`) for every real encryption —
/// Paillier's IND-CPA security lives entirely in the fresh uniform `r`;
/// see SPEC.md.
pub fn encryptRandom(pk: PublicKey, m: Fe, random: std.Random) EncryptError!Ciphertext {
    return encrypt(pk, m, sampleNonzeroLtN(pk, random));
}

fn sampleNonzeroLtN(pk: PublicKey, random: std.Random) Fe {
    const n_bits = pk.n.bits();
    const n_len = byteLen(n_bits);
    var buf: [modulus_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, buf[0..n_len]);
    while (true) {
        random.bytes(buf[0..n_len]);
        buf[0] &= @as(u8, 0xff) >> @intCast(8 * n_len - n_bits);
        // Constructed against n_sq (not n) per the Fe construction contract
        // — encrypt() uses this value as the base of r^n mod n^2.
        const r = Fe.fromBytes(pk.n_sq, buf[0..n_len], .big) catch continue; // >= n_sq: redraw (won't happen, n_len bytes < n_sq)
        if (r.isZero()) continue;
        return r;
    }
}

pub const DecryptError = std.crypto.ff.NullExponentError || std.crypto.ff.RepresentationError || error{InvalidCiphertext};

/// Paillier decryption: `m = L(c^lambda mod n²) * mu mod n`, where
/// `L(x) = (x-1)/n` (exact integer division: Paillier 1999 Theorem 2
/// guarantees `c^lambda ≡ 1 (mod n)` for a well-formed ciphertext, so `x - 1`
/// is always an exact multiple of `n`).
///
/// `c^lambda mod n²` is a constant-time `Modulus.pow` (`sk.lambda` is
/// secret-key material — never `powPublic`). `L(x)` drops to
/// `std.math.big.int` exact division (`std.crypto.ff` has no native
/// L-function/exact-division primitive — mirrors how `rsa.fromPrimesImpl`
/// drops to `big.int` for its own lcm/modinv steps); that division is
/// variable-time in `x`, a plaintext-derived value — see SPEC.md's timing
/// note. A `c` that is 0, shares a factor with `n`, or otherwise fails the
/// `x ≡ 1 (mod n)` exactness guarantee is rejected as
/// `error.InvalidCiphertext` rather than silently decrypting garbage.
/// `x = c^λ mod n²` via the single-modulus montint path (constant-time in the
/// secret `λ`). Returns `null` iff `λ = 0` (a malformed key — not a real
/// Paillier secret), preserving the old `NullExponent → InvalidCiphertext`
/// behavior. Used when no CRT block is available (`fromBytes` keys).
fn decryptNonCrtX(sk: SecretKey, c: Fe) ?Fe {
    if (sk.lambda.isZero()) return null;
    var lam_be: [modulus_sq_bytes]u8 = undefined;
    sk.lambda.toBytes(&lam_be, .big) catch unreachable; // canonical mod n², full-width
    return montModexpSecret(&sk.n_sq_mont, sk.n_sq, c, &lam_be);
}

/// `x = c^λ mod n²` via Paillier-CRT: two half-width constant-time modexps
/// `c^dp mod p²` and `c^dq mod q²`, Garner-recombined into `x` mod `n²`. Byte-
/// identical to `decryptNonCrtX` for a well-formed ciphertext, but ~4× cheaper.
/// Constant-time in the secret exponents; the recombination is all `ff` field
/// arithmetic with no secret-dependent branch.
fn decryptCrtX(sk: SecretKey, crt: *const CrtParams, c: Fe) Fe {
    // Reduce c into the mod-p² and mod-q² domains (both constant-time).
    const cp = reduceWide(crt.p_sq, c.v);
    const cq = reduceWide(crt.q_sq, c.v);
    // x_p = c^dp mod p², x_q = c^dq mod q² (constant-time secret exponents).
    const xp = montModexpSecret(&crt.p_sq_mont, crt.p_sq, cp, &crt.dp);
    const xq = montModexpSecret(&crt.q_sq_mont, crt.q_sq, cq, &crt.dq);
    // Garner: u = (x_q − x_p)·(p²)⁻¹ mod q²;  x = x_p + p²·u   (0 ≤ x < n²).
    const xp_q = reduceWide(crt.q_sq, xp.v);
    const u = crt.q_sq.mul(crt.q_sq.sub(xq, xp_q), crt.p_sq_inv);
    const xp_n = reduceWide(sk.n_sq, xp.v);
    const u_n = reduceWide(sk.n_sq, u.v);
    return sk.n_sq.add(xp_n, sk.n_sq.mul(crt.p_sq_fe, u_n));
}

pub fn decrypt(sk: SecretKey, c: Ciphertext) DecryptError!Fe {
    // c must be a unit mod n² for L to be defined; c = 0 never is.
    if (c.c.isZero()) return error.InvalidCiphertext;

    // x = c^lambda mod n² — constant-time. CRT path (~4×) when the key carries
    // its factors, else the single-modulus montint fallback.
    const x = if (sk.crt) |*crt|
        decryptCrtX(sk, crt, c.c)
    else
        (decryptNonCrtX(sk, c.c) orelse return error.InvalidCiphertext);
    if (x.isZero()) return error.InvalidCiphertext; // gcd(c, n) != 1

    // L(x) = (x - 1)/n via big.int exact division. Exact for well-formed
    // ciphertexts (x ≡ 1 mod n, Paillier 1999 Theorem 2); a nonzero
    // remainder means c was not a valid ciphertext under this key. The
    // arena is amply sized for the handful of fixed-capacity big ints
    // below, so allocation failures are impossible (`catch unreachable`).
    var scratch: [scratch_bytes]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    const gpa = fba.allocator();

    var x_buf: [modulus_sq_bytes]u8 = undefined;
    x.toBytes(&x_buf, .big) catch unreachable; // canonical value, full-width buffer
    var bx = bigFromBytes(gpa, &x_buf) catch unreachable;
    var bx1 = newBig(gpa) catch unreachable;
    bx1.addScalar(&bx, -1) catch unreachable;

    const n_len = byteLen(sk.n.bits());
    var n_buf: [modulus_bytes]u8 = undefined;
    sk.n.toBytes(n_buf[0..n_len], .big) catch unreachable; // exact-size buffer
    var bn = bigFromBytes(gpa, n_buf[0..n_len]) catch unreachable;

    var bl = newBig(gpa) catch unreachable;
    var brem = newBig(gpa) catch unreachable;
    bl.divFloor(&brem, &bx1, &bn) catch unreachable;
    if (!brem.eqlZero()) return error.InvalidCiphertext;

    var l_buf: [modulus_sq_bytes]u8 = undefined;
    bl.toConst().writeTwosComplement(&l_buf, .big);
    // L(x) < n always (x < n²), so this is canonical mod n by construction
    // — fresh construction against sk.n per the Fe construction contract.
    const l_fe = Fe.fromBytes(sk.n, &l_buf, .big) catch return error.InvalidCiphertext;

    // m = L(x) * mu mod n.
    return sk.n.mul(l_fe, sk.mu);
}

// ── homomorphic ops (the whole point of this module) ─────────────────────
//
// TODO(phase2): the zero-knowledge proofs GG20/CMP threshold-ECDSA actually
// needs around these operations (proof of correct Paillier encryption,
// range proofs bounding the plaintext/randomness, and the MtA protocol that
// composes addPlaintext+mulPlaintext+addCiphertexts into a secure share
// conversion) are OUT OF SCOPE for this module. This module provides only
// the core additively-homomorphic PKE; MtA/range-proofs are a separate,
// later module (I2 Phase 2) that will depend on this one.

pub const HomomorphicError = std.crypto.ff.NullExponentError || std.crypto.ff.RepresentationError;

/// Ciphertext addition: `E(m1 + m2 mod n) = E(m1) * E(m2) mod n²` — the core
/// additively-homomorphic property this module exists for (Paillier 1999
/// §3.1). Construction: `pk.n_sq.mul(c1.c, c2.c)` — a single field
/// multiplication, no modular exponentiation needed at all (unlike
/// `addPlaintext`/`mulPlaintext` below). Cannot fail (`Modulus.mul` has no
/// error cases).
pub fn addCiphertexts(pk: PublicKey, c1: Ciphertext, c2: Ciphertext) Ciphertext {
    return .{ .c = pk.n_sq.mul(c1.c, c2.c) };
}

/// Plaintext addition: `E(m1 + m2 mod n) = E(m1) * g^m2 mod n²`. `m` must be
/// canonical mod `pk.n_sq` (Fe construction contract, see module doc
/// comment). The `g^m` term goes through `gPow` (binomial shortcut for the
/// standard `g = n+1`, `m = 0` handled — see there).
pub fn addPlaintext(pk: PublicKey, c: Ciphertext, m: Fe) HomomorphicError!Ciphertext {
    return .{ .c = pk.n_sq.mul(c.c, try gPow(pk, m)) };
}

/// Plaintext (scalar) multiplication: `E(k*m mod n) = E(m)^k mod n²`. `k`
/// must be canonical mod `pk.n_sq` (Fe construction contract). `k = 0`
/// returns the deterministic, unblinded encryption of 0 (`c^0 = 1`, and
/// `L(1^lambda) = 0` decrypts to 0) — exactly what `phe`'s `raw_mul` (python
/// `pow(c, 0, n²) = 1`) produces; `ff`'s `pow` would reject the zero
/// exponent, so it is special-cased. The exponentiation is the constant-time
/// `pow`: `k` may be a secret scalar (e.g. in a future MtA context).
pub fn mulPlaintext(pk: PublicKey, c: Ciphertext, k: Fe) HomomorphicError!Ciphertext {
    if (k.isZero()) return .{ .c = pk.n_sq.one() };
    return .{ .c = try pk.n_sq.pow(c.c, k) };
}

// ── tests ────────────────────────────────────────────────────────────────
//
// Paillier has no official RFC/standard KAT vectors. Two groups below:
//
//   1. Mechanical serialization tests (PublicKey/SecretKey/Ciphertext
//      fromBytes/toBytes, n_sq/standard-g derivation).
//   2. Round-trip + homomorphic-property + cross-check tests exercising
//      `fromPrimes`/`generate`/`encrypt`/`decrypt`/the homomorphic ops —
//      the concrete (m, r) -> c values are cross-checked against phe
//      (python-paillier) 1.5.0 (see NOTICE); the property tests are
//      self-checking and need no external oracle.

const testing = std.testing;

// Toy fixed key used by every test below: p=11, q=17 (NOT secure — chosen
// only because it's small enough to hand-verify and hex-dump). n = 187,
// n² = 34969, lambda = lcm(10,16) = 80, g = n+1 = 188,
// mu = L(g^lambda mod n²)^-1 mod n = 180. All five derived values, plus
// every ciphertext below, were independently verified against phe
// (python-paillier) 1.5.0's `PaillierPublicKey`/`PaillierPrivateKey`
// (`raw_encrypt`/`raw_decrypt` with an explicit `r_value`, same `g = n+1`
// standard variant) — see NOTICE for the recomputation this was checked
// against.
const kat_p = [_]u8{11};
const kat_q = [_]u8{17};
const kat_n = [_]u8{187};
const kat_lambda = [_]u8{80};
const kat_g = [_]u8{188};
const kat_mu = [_]u8{180};

test "PublicKey.fromBytes derives n_sq and the standard generator g=n+1" {
    const pk = try PublicKey.fromBytes(&kat_n, null);
    try testing.expectEqual(@as(u32, 187), try pk.n.v.toPrimitive(u32));
    try testing.expectEqual(@as(u32, 34969), try pk.n_sq.v.toPrimitive(u32));
    try testing.expectEqual(@as(u32, 188), try pk.g.toPrimitive(u32));

    var n_out: [1]u8 = undefined;
    try pk.nToBytes(&n_out);
    try testing.expectEqualSlices(u8, &kat_n, &n_out);

    var g_out: [1]u8 = undefined;
    try pk.gToBytes(&g_out);
    try testing.expectEqualSlices(u8, &kat_g, &g_out);
}

test "PublicKey.fromBytes accepts an explicit g" {
    // g need not be n+1 in general (a caller-supplied generator is
    // permitted by the API even though this module only ever *derives*
    // the standard variant); use g=2 here just to exercise the branch.
    const pk = try PublicKey.fromBytes(&kat_n, &[_]u8{2});
    try testing.expectEqual(@as(u32, 2), try pk.g.toPrimitive(u32));
}

test "SecretKey.fromBytes round-trips n/lambda/mu" {
    const sk = try SecretKey.fromBytes(&kat_n, &kat_lambda, &kat_mu);
    try testing.expectEqual(@as(u32, 187), try sk.n.v.toPrimitive(u32));
    try testing.expectEqual(@as(u32, 34969), try sk.n_sq.v.toPrimitive(u32));
    try testing.expectEqual(@as(u32, 80), try sk.lambda.toPrimitive(u32));
    try testing.expectEqual(@as(u32, 180), try sk.mu.toPrimitive(u32));

    var lambda_out: [1]u8 = undefined;
    try sk.lambdaToBytes(&lambda_out);
    try testing.expectEqualSlices(u8, &kat_lambda, &lambda_out);

    var mu_out: [1]u8 = undefined;
    try sk.muToBytes(&mu_out);
    try testing.expectEqualSlices(u8, &kat_mu, &mu_out);
}

test "SecretKey.deinit zeroes lambda/mu (no-crt key, e.g. loaded via fromBytes)" {
    var sk = try SecretKey.fromBytes(&kat_n, &kat_lambda, &kat_mu);
    try testing.expect(sk.crt == null);
    try testing.expect(!std.mem.allEqual(u8, std.mem.asBytes(&sk.lambda), 0)); // present before wipe
    try testing.expect(!std.mem.allEqual(u8, std.mem.asBytes(&sk.mu), 0));

    sk.deinit();

    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&sk.lambda), 0)); // wiped after
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&sk.mu), 0));
    // Public fields untouched by deinit — still usable to build a PublicKey view.
    try testing.expectEqual(@as(u32, 187), try sk.n.v.toPrimitive(u32));
}

test "SecretKey.deinit zeroes lambda/mu/crt (fromPrimes key, factorization-bearing block present)" {
    var kp = try fromPrimes(&.{61}, &.{53});
    try testing.expect(kp.secret.crt != null);
    try testing.expect(!std.mem.allEqual(u8, std.mem.asBytes(&kp.secret.lambda), 0));
    try testing.expect(!std.mem.allEqual(u8, std.mem.asBytes(&kp.secret.mu), 0));
    try testing.expect(!std.mem.allEqual(u8, std.mem.asBytes(&kp.secret.crt.?), 0));

    kp.secret.deinit();

    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&kp.secret.lambda), 0));
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&kp.secret.mu), 0));
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&kp.secret.crt.?), 0));
    // Public fields (n/n_sq, and the PublicKey half) untouched.
    try testing.expectEqual(@as(u32, 61 * 53), try kp.secret.n.v.toPrimitive(u32));
    try testing.expectEqual(@as(u32, 61 * 53), try kp.public.n.v.toPrimitive(u32));
}

test "Ciphertext bytes round-trip" {
    const pk = try PublicKey.fromBytes(&kat_n, null);
    // c=28686 = E(0, r=3) under this key (see the round-trip test below
    // for the full vector table + phe cross-check).
    const c_bytes = [_]u8{ 0x70, 0x0e }; // 28686
    const c = try Ciphertext.fromBytes(pk, &c_bytes);
    try testing.expectEqual(@as(u32, 28686), try c.c.toPrimitive(u32));

    var out: [2]u8 = undefined;
    try c.toBytes(&out);
    try testing.expectEqualSlices(u8, &c_bytes, &out);
}

test "n_sq derivation matches a from-scratch big.int square (sanity, no phe needed)" {
    // Cross-check squareModulus/PublicKey.fromBytes's mechanical n^2
    // derivation against a second, independently-written computation.
    var n: u64 = 187;
    var acc: u64 = 1;
    var i: u64 = 0;
    while (i < 2) : (i += 1) acc *= n;
    _ = &n;
    try testing.expectEqual(@as(u64, 34969), acc);
    const pk = try PublicKey.fromBytes(&kat_n, null);
    try testing.expectEqual(acc, try pk.n_sq.v.toPrimitive(u64));
}

// ── crypto-core tests ─────────────────────────────────────────────────────

test "fromPrimes derives the phe-cross-checked toy key exactly (p=11, q=17)" {
    const kp = try fromPrimes(&kat_p, &kat_q);
    try testing.expectEqual(@as(u32, 187), try kp.public.n.v.toPrimitive(u32));
    try testing.expectEqual(@as(u32, 34969), try kp.public.n_sq.v.toPrimitive(u32));
    try testing.expectEqual(@as(u32, 188), try kp.public.g.toPrimitive(u32));
    try testing.expectEqual(@as(u32, 187), try kp.secret.n.v.toPrimitive(u32));
    try testing.expectEqual(@as(u32, 34969), try kp.secret.n_sq.v.toPrimitive(u32));
    try testing.expectEqual(@as(u32, 80), try kp.secret.lambda.toPrimitive(u32)); // lcm(10, 16)
    try testing.expectEqual(@as(u32, 180), try kp.secret.mu.toPrimitive(u32)); // 80^-1 mod 187
}

test "fromPrimes rejects p == q, degenerate factors, and oversized products" {
    try testing.expectError(error.InvalidPrimes, fromPrimes(&kat_p, &kat_p)); // p == q
    try testing.expectError(error.InvalidPrimes, fromPrimes(&[_]u8{0}, &kat_q));
    try testing.expectError(error.InvalidPrimes, fromPrimes(&[_]u8{1}, &kat_q));
    try testing.expectError(error.InvalidPrimes, fromPrimes(&[_]u8{2}, &kat_q)); // n even
    try testing.expectError(error.InvalidPrimes, fromPrimes(&[_]u8{}, &kat_q));

    // Two full-width odd values: product needs 2*modulus_bits > modulus_bits.
    var big1: [modulus_bytes]u8 = undefined;
    @memset(&big1, 0xff);
    var big2 = big1;
    big2[modulus_bytes - 1] = 0xfd; // differ from big1, still odd
    try testing.expectError(error.Overflow, fromPrimes(&big1, &big2));
}

test "round-trip: decrypt(encrypt(m, r)) == m, fixed small p,q,r (phe-cross-checked)" {
    // Vectors verified against phe (python-paillier) 1.5.0 for the p=11,
    // q=17 key above -- see NOTICE.
    const kp = try fromPrimes(&kat_p, &kat_q);
    const pk = kp.public;
    const sk = kp.secret;

    const Vector = struct { m: u32, r: u32, c: u32 };
    const vectors = [_]Vector{
        .{ .m = 0, .r = 3, .c = 28686 },
        .{ .m = 1, .r = 5, .c = 7219 },
        .{ .m = 42, .r = 7, .c = 25922 },
        .{ .m = 186, .r = 13, .c = 4781 }, // m = n-1
    };
    for (vectors) |v| {
        // m/r constructed mod pk.n_sq per the Fe construction contract.
        const m_fe = try Fe.fromPrimitive(u32, pk.n_sq, v.m);
        const r_fe = try Fe.fromPrimitive(u32, pk.n_sq, v.r);
        const c = try encrypt(pk, m_fe, r_fe);
        try testing.expectEqual(@as(u32, v.c), try c.c.toPrimitive(u32));
        const m2 = try decrypt(sk, c);
        try testing.expectEqual(@as(u32, v.m), try m2.toPrimitive(u32));
    }
}

test "homomorphic properties: add(E(m1),E(m2)), addPlaintext, mulPlaintext" {
    // m1=5,r1=3 -> c1=28873; m2=9,r2=7 -> c2=9466 (phe-cross-checked, see
    // NOTICE). n=187.
    const kp = try fromPrimes(&kat_p, &kat_q);
    const pk = kp.public;
    const sk = kp.secret;

    const m1 = try Fe.fromPrimitive(u32, pk.n_sq, 5);
    const r1 = try Fe.fromPrimitive(u32, pk.n_sq, 3);
    const c1 = try encrypt(pk, m1, r1);
    try testing.expectEqual(@as(u32, 28873), try c1.c.toPrimitive(u32));

    const m2 = try Fe.fromPrimitive(u32, pk.n_sq, 9);
    const r2 = try Fe.fromPrimitive(u32, pk.n_sq, 7);
    const c2 = try encrypt(pk, m2, r2);
    try testing.expectEqual(@as(u32, 9466), try c2.c.toPrimitive(u32));

    // decrypt(add(E(m1),E(m2))) == m1+m2 mod n
    const c_add = addCiphertexts(pk, c1, c2);
    try testing.expectEqual(@as(u32, 29083), try c_add.c.toPrimitive(u32));
    try testing.expectEqual(@as(u32, (5 + 9) % 187), try (try decrypt(sk, c_add)).toPrimitive(u32));

    // decrypt(mulPlaintext(E(m1),k)) == k*m1 mod n
    const k = try Fe.fromPrimitive(u32, pk.n_sq, 4);
    const c_mul = try mulPlaintext(pk, c1, k);
    try testing.expectEqual(@as(u32, 24535), try c_mul.c.toPrimitive(u32));
    try testing.expectEqual(@as(u32, (5 * 4) % 187), try (try decrypt(sk, c_mul)).toPrimitive(u32));

    // decrypt(addPlaintext(E(m1),m2plain)) == m1+m2plain mod n
    const m2plain = try Fe.fromPrimitive(u32, pk.n_sq, 6);
    const c_addpt = try addPlaintext(pk, c1, m2plain);
    try testing.expectEqual(@as(u32, 8116), try c_addpt.c.toPrimitive(u32));
    try testing.expectEqual(@as(u32, (5 + 6) % 187), try (try decrypt(sk, c_addpt)).toPrimitive(u32));
}

test "homomorphic edge cases: m=0 operands, k=0/k=1 scaling, wrap-around mod n" {
    const kp = try fromPrimes(&kat_p, &kat_q);
    const pk = kp.public;
    const sk = kp.secret;
    var prng = std.Random.DefaultPrng.init(42);
    const random = prng.random();

    // Wrap-around: m1 + m2 >= n (100 + 150 = 250 ≡ 63 mod 187).
    const m1 = try Fe.fromPrimitive(u32, pk.n_sq, 100);
    const m2 = try Fe.fromPrimitive(u32, pk.n_sq, 150);
    const c1 = try encryptRandom(pk, m1, random);
    const c2 = try encryptRandom(pk, m2, random);
    try testing.expectEqual(@as(u32, (100 + 150) % 187), try (try decrypt(sk, addCiphertexts(pk, c1, c2))).toPrimitive(u32));

    // E(n-1) + E(1) wraps to exactly 0.
    const m_max = try Fe.fromPrimitive(u32, pk.n_sq, 186);
    const m_one = try Fe.fromPrimitive(u32, pk.n_sq, 1);
    const c_max = try encryptRandom(pk, m_max, random);
    const c_one = try encryptRandom(pk, m_one, random);
    try testing.expectEqual(@as(u32, 0), try (try decrypt(sk, addCiphertexts(pk, c_max, c_one))).toPrimitive(u32));

    // addPlaintext: m = 0 is the identity; wrap-around matches mod-n sum.
    const zero = try Fe.fromPrimitive(u32, pk.n_sq, 0);
    try testing.expectEqual(@as(u32, 100), try (try decrypt(sk, try addPlaintext(pk, c1, zero))).toPrimitive(u32));
    try testing.expectEqual(@as(u32, (100 + 150) % 187), try (try decrypt(sk, try addPlaintext(pk, c1, m2))).toPrimitive(u32));

    // mulPlaintext: k = 0 is the deterministic unblinded E(0) (c^0 = 1,
    // matching phe's pow(c, 0, n²) = 1) and decrypts to 0.
    const c_k0 = try mulPlaintext(pk, c1, zero);
    try testing.expectEqual(@as(u32, 1), try c_k0.c.toPrimitive(u32));
    try testing.expectEqual(@as(u32, 0), try (try decrypt(sk, c_k0)).toPrimitive(u32));
    // k = 1 is the identity; k = 5 wraps: 100*5 = 500 ≡ 126 mod 187.
    try testing.expectEqual(@as(u32, 100), try (try decrypt(sk, try mulPlaintext(pk, c1, m_one))).toPrimitive(u32));
    const k5 = try Fe.fromPrimitive(u32, pk.n_sq, 5);
    try testing.expectEqual(@as(u32, (100 * 5) % 187), try (try decrypt(sk, try mulPlaintext(pk, c1, k5))).toPrimitive(u32));

    // m = 0 as an *encrypted* value composes homomorphically too.
    const c_zero = try encryptRandom(pk, zero, random);
    try testing.expectEqual(@as(u32, 0), try (try decrypt(sk, c_zero)).toPrimitive(u32));
    try testing.expectEqual(@as(u32, 100), try (try decrypt(sk, addCiphertexts(pk, c1, c_zero))).toPrimitive(u32));
}

test "encrypt/decrypt round-trips every residue of the toy key (exhaustive m in [0, n))" {
    // Cycles r through a fixed pool of units mod 187 rather than
    // encryptRandom: with a toy 8-bit n the chance a uniform r shares a
    // factor with n is ~1/p + 1/q ≈ 15% per draw (negligible only for real
    // key sizes — see SPEC.md), and decrypt correctly *rejects* such
    // non-unit ciphertexts as error.InvalidCiphertext.
    const kp = try fromPrimes(&kat_p, &kat_q);
    const r_pool = [_]u32{ 3, 5, 7, 13, 19, 23, 29, 31 }; // all coprime to 187 = 11*17
    var m: u32 = 0;
    while (m < 187) : (m += 1) {
        const m_fe = try Fe.fromPrimitive(u32, kp.public.n_sq, m);
        const r_fe = try Fe.fromPrimitive(u32, kp.public.n_sq, r_pool[m % r_pool.len]);
        const c = try encrypt(kp.public, m_fe, r_fe);
        try testing.expectEqual(m, try (try decrypt(kp.secret, c)).toPrimitive(u32));
    }
}

test "decrypt rejects invalid ciphertexts (zero and non-units mod n)" {
    const kp = try fromPrimes(&kat_p, &kat_q);
    const sk = kp.secret;
    const zero_c = Ciphertext{ .c = try Fe.fromPrimitive(u32, sk.n_sq, 0) };
    try testing.expectError(error.InvalidCiphertext, decrypt(sk, zero_c));
    // c = n: c^lambda ≡ 0 (mod n²) — L is undefined.
    const n_c = Ciphertext{ .c = try Fe.fromPrimitive(u32, sk.n_sq, 187) };
    try testing.expectError(error.InvalidCiphertext, decrypt(sk, n_c));
    // c = p (shares the factor 11 with n): x ≢ 1 (mod n), exactness check fires.
    const p_c = Ciphertext{ .c = try Fe.fromPrimitive(u32, sk.n_sq, 11) };
    try testing.expectError(error.InvalidCiphertext, decrypt(sk, p_c));
}

test "decrypt via non-CRT fallback (fromBytes key, no factors) matches phe vectors" {
    // A key loaded from n/λ/µ alone carries no factors, so `decrypt` takes the
    // single-modulus `c^λ mod n²` montint path instead of CRT. The same phe-
    // cross-checked toy vectors as the CRT round-trip above must still decrypt,
    // anchoring the non-CRT montint modexp externally.
    const pk = try PublicKey.fromBytes(&kat_n, null);
    const sk = try SecretKey.fromBytes(&kat_n, &kat_lambda, &kat_mu);
    try testing.expect(sk.crt == null); // fallback path is what's under test
    const Vector = struct { m: u32, r: u32 };
    const vectors = [_]Vector{ .{ .m = 0, .r = 3 }, .{ .m = 1, .r = 5 }, .{ .m = 42, .r = 7 }, .{ .m = 186, .r = 13 } };
    for (vectors) |v| {
        const m_fe = try Fe.fromPrimitive(u32, pk.n_sq, v.m);
        const r_fe = try Fe.fromPrimitive(u32, pk.n_sq, v.r);
        const c = try encrypt(pk, m_fe, r_fe);
        try testing.expectEqual(v.m, try (try decrypt(sk, c)).toPrimitive(u32));
    }
}

test "CRT and non-CRT decrypt agree at a real 512-bit key size" {
    // The toy key is too small to exercise the multi-limb CRT recombination
    // meaningfully; at 512 bits `n²` spans several limbs and p²/q² take the
    // half-width path. Decrypt the same ciphertext both ways (CRT via the
    // generated key, non-CRT via a factor-less rebuild) and require identity —
    // a differential check that the Garner recombination equals the full
    // single-modulus modexp.
    var prng = std.Random.DefaultPrng.init(0x1d0c7e51);
    const random = prng.random();
    const kp = try generate(random, 512);
    try testing.expect(kp.secret.crt != null);

    // Rebuild the same secret key from n/λ/µ only → no CRT block.
    var n_b: [modulus_bytes]u8 = undefined;
    var lam_b: [modulus_sq_bytes]u8 = undefined;
    var mu_b: [modulus_bytes]u8 = undefined;
    try kp.secret.nToBytes(&n_b);
    try kp.secret.lambdaToBytes(&lam_b);
    try kp.secret.muToBytes(&mu_b);
    const sk_nocrt = try SecretKey.fromBytes(&n_b, &lam_b, &mu_b);
    try testing.expect(sk_nocrt.crt == null);

    const m = try Fe.fromPrimitive(u64, kp.public.n_sq, 0x00C0FFEE_1234_5678);
    const c = try encryptRandom(kp.public, m, random);
    const via_crt = try decrypt(kp.secret, c);
    const via_full = try decrypt(sk_nocrt, c);
    try testing.expectEqual(@as(u64, 0x00C0FFEE_1234_5678), try via_crt.toPrimitive(u64));
    try testing.expect(via_crt.eql(via_full));
}

test "topBitsMatch: FIPS 186-5 closeness guard fires exactly at the 100-bit boundary" {
    // Gap found by mutation testing: `generate`'s random prime search almost
    // never actually exercises this guard's true-branch (matching the top
    // 100 bits of two independently-drawn primes has probability ~2^-100),
    // so nothing in the round-trip/keygen tests above can ever discriminate
    // a broken guard from a working one. Exercise it directly instead.
    var p: [16]u8 = [_]u8{0} ** 16;
    var q: [16]u8 = [_]u8{0} ** 16;
    for (0..12) |i| {
        p[i] = @intCast(i + 1);
        q[i] = @intCast(i + 1);
    }

    // Bytes 0..11 (96 bits) equal, high nibble of byte 12 (bits 96-99) equal
    // too (low nibble differs, irrelevant to the 100-bit window) -> matches.
    p[12] = 0xF3;
    q[12] = 0xF7;
    try testing.expect(topBitsMatch(&p, &q));

    // Same first 96 bits, but the high nibble of byte 12 now differs ->
    // exactly 96 bits match, not 100 -> must NOT match.
    p[12] = 0x0F;
    q[12] = 0xF0;
    try testing.expect(!topBitsMatch(&p, &q));

    // Differ well before the 96-bit mark -> never matches.
    p[12] = 0xF3;
    q[12] = 0xF3;
    q[0] = 0xFF;
    try testing.expect(!topBitsMatch(&p, &q));

    // p == q (every real bit matches) is of course caught too.
    q[0] = p[0];
    try testing.expect(topBitsMatch(&p, &q));
}

test "generate rejects invalid bit sizes" {
    var prng = std.Random.DefaultPrng.init(1);
    const random = prng.random();
    try testing.expectError(error.InvalidBits, generate(random, 0));
    try testing.expectError(error.InvalidBits, generate(random, min_generate_bits - 2));
    try testing.expectError(error.InvalidBits, generate(random, min_generate_bits + 1)); // odd
    try testing.expectError(error.InvalidBits, generate(random, modulus_bits + 2));
}

test "generate: 512-bit keygen round-trips encrypt/decrypt + homomorphic add" {
    // Small-but-real keygen kept fast enough for every-run testing; the
    // full modulus_bits path is exercised by the (slow) test below.
    var prng = std.Random.DefaultPrng.init(0x5041494c);
    const random = prng.random();
    const kp = try generate(random, 512);
    try testing.expectEqual(@as(usize, 512), kp.public.n.bits());

    const m = try Fe.fromPrimitive(u64, kp.public.n_sq, 0xdeadbeef12345678);
    const c = try encryptRandom(kp.public, m, random);
    const m_back = try decrypt(kp.secret, c);
    try testing.expectEqual(@as(u64, 0xdeadbeef12345678), try m_back.toPrimitive(u64));

    // E(m) + E(m) decrypts to 2m (fits well below a 512-bit n).
    const two_m = try decrypt(kp.secret, addCiphertexts(kp.public, c, c));
    try testing.expectEqual(@as(u128, 2 * @as(u128, 0xdeadbeef12345678)), try two_m.toPrimitive(u128));
}

test "generate: full 2048-bit keygen round-trips (slow; the size this module is designed for)" {
    var prng = std.Random.DefaultPrng.init(0x70616c6c);
    const random = prng.random();
    const kp = try generate(random, modulus_bits);
    try testing.expectEqual(@as(usize, modulus_bits), kp.public.n.bits());

    const m = try Fe.fromPrimitive(u64, kp.public.n_sq, 0x123456789abcdef);
    const c = try encryptRandom(kp.public, m, random);
    try testing.expectEqual(@as(u64, 0x123456789abcdef), try (try decrypt(kp.secret, c)).toPrimitive(u64));

    const k = try Fe.fromPrimitive(u32, kp.public.n_sq, 3);
    const c3 = try mulPlaintext(kp.public, c, k);
    try testing.expectEqual(@as(u128, 3 * @as(u128, 0x123456789abcdef)), try (try decrypt(kp.secret, c3)).toPrimitive(u128));
}

test "smoke: module compiles and constants are sane" {
    try testing.expect(max_bits == modulus_bits * 2);
    try testing.expect(modulus_sq_bytes == 2 * modulus_bytes);
}

// ── fuzz: byte-loaders never panic on arbitrary attacker-supplied bytes ──
//
// `PublicKey.fromBytes`/`SecretKey.fromBytes`/`Ciphertext.fromBytes` are
// this module's only untrusted-input boundary: raw big-endian `n`/`g`/
// `lambda`/`mu`/ciphertext bytes loaded from storage or a wire message,
// turned into `std.crypto.ff` values via a hand-rolled `stripLeadingZeros`
// + length-bound check (`n_bytes.len == 0 or n_bytes.len > modulus_bytes`)
// BEFORE `Modulus.fromBytes`/`Fe.fromBytes` ever run -- unlike the
// sibling k256/p256/bls12_381 group modules' fixed-size-array `fromBytes`,
// these take variable-length `[]const u8` directly, so the length-bound
// check itself is in-scope here. `smith.bytes` biased toward lengths at/
// over the `modulus_bytes`/`modulus_sq_bytes` boundary, mixed with leading
// zero runs (exercises `stripLeadingZeros`) and fully random content.
test "fuzz: PublicKey.fromBytes never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzPublicKeyFromBytes, .{});
}

// ⚠ This helper is the HARNESS, and it was the thing that crashed -- twice --
// the first time this module was ever really fuzzed. Both were u8 arithmetic
// on values that do not fit in a u8:
//
//   - `modulus_bytes - 4 + valueRangeAtMost(u8, 0, 8)` took its result type
//     from the u8, so `modulus_bytes - 4` (252 at 2048 bits) plus up to 8
//     overflowed. `@min` was applied AFTER the overflow, so it could not help.
//   - `@intCast(buf.len)` to the u8/u16 range bound aborted outright for the
//     `modulus_sq_bytes + 16` buffers, which are far larger than 255.
//
// A harness that aborts before calling the parser leaves the parser with ZERO
// fuzz coverage while the sweep records a FINDING -- worse than a red test,
// because it looks like the library was exercised and found wanting.
fn fuzzedFieldBytes(smith: *std.testing.Smith, buf: []u8) []const u8 {
    smith.bytes(buf);
    // Occasionally force a run of leading zeros (stripLeadingZeros path).
    if (smith.value(bool)) {
        const n_zeros: usize = @min(buf.len, smith.valueRangeAtMost(u16, 0, 512));
        @memset(buf[0..n_zeros], 0);
    }
    // Bias length toward at/over the modulus_bytes boundary as well as
    // fully random.
    const len: usize = if (smith.value(bool))
        boundaryLen(buf.len, smith.valueRangeAtMost(u8, 0, 8))
    else
        @min(buf.len, smith.valueRangeAtMost(u16, 0, 65535));
    return buf[0..len];
}

/// The boundary-biased length, as a pure function of its inputs.
///
/// Split out because the bug lived here and a Smith-driven test could not
/// reliably reach it: restoring the overflow left the harness test green,
/// which made it a toothless test rather than a redundant fix. Exhaustive over
/// `r` below instead -- eight values, no randomness, no ambiguity.
fn boundaryLen(buf_len: usize, r: u8) usize {
    // `modulus_bytes - 4` is 252 at 2048 bits, so `+ r` overflowed when this
    // was u8 arithmetic. Widen BEFORE adding; `@min` afterwards cannot undo an
    // overflow that already trapped.
    return @min(buf_len, modulus_bytes - 4 + @as(usize, r));
}

test "boundaryLen does not overflow for any value the harness can draw" {
    // Every `r` in the drawn range, not a sample: the overflow starts at r=4
    // and a one-value test would pass against a fix covering only that value.
    for (0..9) |r| {
        const n = boundaryLen(modulus_sq_bytes + 16, @intCast(r));
        try testing.expectEqual(modulus_bytes - 4 + r, n);
        try testing.expect(n <= modulus_sq_bytes + 16);
    }
    // And the clamp still binds when the buffer is the smaller of the two.
    try testing.expectEqual(@as(usize, 8), boundaryLen(8, 8));
}

test "fuzzedFieldBytes stays in bounds for the largest buffer it is given" {
    // The harness's own regression test. `modulus_sq_bytes + 16` is the widest
    // buffer any caller passes, and it is precisely the size that broke both
    // range bounds -- so a harness helper needs a test like any other code.
    //
    // `Smith{ .in = null }` only works under `builtin.fuzz`; outside it the
    // byte source must be supplied, or `smith.bytes` hits `unreachable`. That
    // cost a red test before this comment existed.
    var seed: [4096]u8 = undefined;
    for (&seed, 0..) |*b, k| b.* = @truncate(k *% 131 +% 7);

    var buf: [modulus_sq_bytes + 16]u8 = undefined;
    for (0..64) |k| {
        var smith: std.testing.Smith = .{ .in = seed[k * 8 ..] };
        const out = fuzzedFieldBytes(&smith, &buf);
        try testing.expect(out.len <= buf.len);
    }
}

fn fuzzPublicKeyFromBytes(_: void, smith: *std.testing.Smith) !void {
    var n_buf: [modulus_bytes + 16]u8 = undefined;
    const n_bytes = fuzzedFieldBytes(smith, &n_buf);

    var g_buf: [modulus_sq_bytes + 16]u8 = undefined;
    const g_bytes: ?[]const u8 = if (smith.value(bool)) fuzzedFieldBytes(smith, &g_buf) else null;

    _ = PublicKey.fromBytes(n_bytes, g_bytes) catch return;
}

test "fuzz: SecretKey.fromBytes never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzSecretKeyFromBytes, .{});
}

fn fuzzSecretKeyFromBytes(_: void, smith: *std.testing.Smith) !void {
    var n_buf: [modulus_bytes + 16]u8 = undefined;
    const n_bytes = fuzzedFieldBytes(smith, &n_buf);
    var lambda_buf: [modulus_sq_bytes + 16]u8 = undefined;
    const lambda_bytes = fuzzedFieldBytes(smith, &lambda_buf);
    var mu_buf: [modulus_bytes + 16]u8 = undefined;
    const mu_bytes = fuzzedFieldBytes(smith, &mu_buf);

    var sk = SecretKey.fromBytes(n_bytes, lambda_bytes, mu_bytes) catch return;
    sk.deinit();
}

test "fuzz: Ciphertext.fromBytes never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzCiphertextFromBytes, .{});
}

fn fuzzCiphertextFromBytes(_: void, smith: *std.testing.Smith) !void {
    // A real (small, toy) key so `pk.n_sq` is a valid modulus context --
    // the point here is fuzzing the ciphertext bytes, not the key parse
    // (already covered by `fuzzPublicKeyFromBytes` above).
    const pk = PublicKey.fromBytes(&kat_n, null) catch unreachable;

    var buf: [modulus_sq_bytes + 16]u8 = undefined;
    const bytes = fuzzedFieldBytes(smith, &buf);
    _ = Ciphertext.fromBytes(pk, bytes) catch return;
}
