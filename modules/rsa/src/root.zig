// SPDX-License-Identifier: MIT
//! rsa — pure-Zig RSA (PKCS#1 v2.2 / RFC 8017), built on `std.crypto.ff`.
//!
//! **P1+P2+P3 IMPLEMENTED, P4–P6 still stubs.** The RFC 8017 §5 primitives
//! (RSAEP/RSADP/RSASP1/RSAVP1, incl. the CRT fast path), `PublicKey.fromBytes`,
//! `SecretKey.fromPrimes`, the RSASSA-PKCS1-v1_5 scheme
//! (`signPkcs1v15`/`verifyPkcs1v15`, SHA-1/224/256/384/512), the
//! RSAES-OAEP scheme (`encryptOaep`/`decryptOaep`, MGF1, constant-time
//! decode), and the RSASSA-PSS scheme (`signPss`/`verifyPss`, branch-clean
//! verify) are real and tested against OpenSSL-generated known-answer
//! vectors. Every P4+ function body is still `@panic("TODO(agent): ...")`.
//! Phase plan:
//!   P1 — EMSA-PKCS1-v1_5 sign/verify (`signPkcs1v15`/`verifyPkcs1v15`) — DONE.
//!   P2 — RSAES-OAEP encrypt/decrypt (`encryptOaep`/`decryptOaep`) — DONE.
//!   P3 — RSASSA-PSS sign/verify (`signPss`/`verifyPss`) — DONE.
//!   P4 — key parsing (`fromPkcs8`/`fromOpenSSH`).
//!   P5 — keypair generation (`generate`).
//!   P6 — self-signed certificate generation (`selfSignedCert`).
//!
//! Modular exponentiation is not reimplemented: this module builds on
//! `std.crypto.ff` (`Uint`/`Modulus`/`Fe`), the same constant-time finite-field
//! primitive Zig std's own internal RSA verifier
//! (`std.crypto.Certificate.rsa`, not public) is built on. This module exposes
//! a clean, PUBLIC, sign-capable superset of that shape (std's internal `rsa`
//! only verifies; it has no `SecretKey`/CRT/signing support at all).
//!
//! Provenance: clean-room implementation from RFC 8017 (PKCS#1 v2.2); design
//! reference = Zig std's internal `std.crypto.Certificate.rsa` (MIT) for the
//! `Modulus`/`Fe`/`PublicKey` shape and the RSAEP/RSAVP1 primitive — shape
//! only, no source copied (std's `rsa` struct is not `pub`, so nothing here is
//! a re-export of it). See README.md "Provenance" for the full statement and
//! `NOTICE` for the design-reference entry.

const std = @import("std");

pub const meta = .{
    // NOTE: CONVENTIONS.md's `meta` tag vocabulary (platform/role/concurrency/
    // model_after/deps) has no dedicated "status" tag; module maturity lives
    // in each SPEC.md's closing "Status" line instead, using the catalog's
    // `extract` (built) / `gap` (not yet built) vocabulary. This module's
    // SPEC.md uses `gap` — the closest existing term for "skeleton, not yet
    // implemented" — until phase P1 lands.
    .platform = .any,
    .role = .util, // pure computation (no I/O, no wire framing of its own) -> util, not .codec
    .concurrency = .reentrant, // no shared/global state; PublicKey/SecretKey are plain value types
    .model_after = "RFC 8017 (PKCS#1 v2.2); std.crypto internal RSA (Certificate/rsa)",
    .deps = .{}, // std only (std.crypto.ff)
};

/// Largest RSA modulus this module supports, in bits. Matches the ceiling
/// std's own internal RSA verifier uses (`std.crypto.Certificate.rsa`).
pub const max_modulus_bits = 4096;

/// Fixed-capacity big-unsigned-integer type sized to `max_modulus_bits`.
pub const Uint = std.crypto.ff.Uint(max_modulus_bits);

/// Constant-time finite-field modulus type sized to `max_modulus_bits`; all
/// modular exponentiation (`pow`/`powPublic`) goes through this — see
/// `std.crypto.ff` doc comments for the underlying Montgomery-ladder details.
pub const Modulus = std.crypto.ff.Modulus(max_modulus_bits);

/// Field element type for `Modulus` (`Modulus.Fe`) — every RSA integer
/// (modulus components, exponents, message/signature representatives) is
/// carried as this type.
pub const Fe = Modulus.Fe;

/// Largest supported modulus length in bytes (`k` in RFC 8017 terms).
pub const max_modulus_len = max_modulus_bits / 8;

/// Smallest modulus accepted by `PublicKey.fromBytes`, in bits. Matches the
/// floor used by std's internal RSA verifier: 512-bit RSA was factored in
/// 1999, this only ratchets in an obvious lower bound for untrusted keys.
const min_modulus_bits = 512;

/// Modulus length in bytes for a modulus of `bit_count` bits.
fn byteLen(bit_count: usize) usize {
    return (bit_count + 7) / 8;
}

/// DER integers and externally supplied big-endian values may carry leading
/// zero octets; the `ff` codecs reject inputs longer than the backing `Uint`,
/// so strip them first (I2OSP/OS2IP length tolerance).
fn stripLeadingZeros(bytes: []const u8) []const u8 {
    var i: usize = 0;
    while (i < bytes.len and bytes[i] == 0) : (i += 1) {}
    return bytes[i..];
}

/// RSA public key: modulus `n` and public exponent `e` (RFC 8017 §3.1).
pub const PublicKey = struct {
    n: Modulus,
    e: Fe,

    pub const FromBytesError = error{InvalidPublicKey};

    /// Parse a public key from raw big-endian modulus + exponent byte
    /// strings (as extracted from a DER `RSAPublicKey` SEQUENCE, or supplied
    /// directly). Modeled after `std.crypto.Certificate.rsa.PublicKey.fromBytes`
    /// (which is not `pub`), generalized to be usable stand-alone.
    pub fn fromBytes(modulus_bytes: []const u8, exponent_bytes: []const u8) FromBytesError!PublicKey {
        // Leading-zero tolerant (DER integers are sign-prefixed).
        const n_bytes = stripLeadingZeros(modulus_bytes);
        if (n_bytes.len > max_modulus_len) return error.InvalidPublicKey;
        // `Modulus.fromBytes` also rejects even moduli (n = p*q is always odd).
        const n = Modulus.fromBytes(n_bytes, .big) catch return error.InvalidPublicKey;
        if (n.bits() < min_modulus_bits) return error.InvalidPublicKey;

        // Public exponent: odd, >= 3, and < 2^32. The 32-bit cap mitigates
        // DoS via attacker-supplied huge exponents and matches what other
        // widespread implementations accept.
        const e_bytes = stripLeadingZeros(exponent_bytes);
        if (e_bytes.len == 0 or e_bytes.len > 4) return error.InvalidPublicKey;
        const e = Fe.fromBytes(n, e_bytes, .big) catch return error.InvalidPublicKey;
        if (!e.isOdd()) return error.InvalidPublicKey;
        const e_v = e.toPrimitive(u32) catch return error.InvalidPublicKey;
        if (e_v < 3) return error.InvalidPublicKey;

        return .{ .n = n, .e = e };
    }

    pub const FromDerError = error{InvalidDer};

    /// Parse a public key from a DER-encoded `RSAPublicKey` (PKCS#1 Appendix
    /// A.1.1) or an X.509 `SubjectPublicKeyInfo` wrapping one.
    pub fn fromDer(bytes: []const u8) FromDerError!PublicKey {
        _ = bytes;
        @panic("TODO(agent): DER/ASN.1 parse RSAPublicKey per RFC 8017 Appendix A.1.1, or SubjectPublicKeyInfo per RFC 5280, then delegate to fromBytes");
    }
};

/// RSA private key in CRT form (RFC 8017 §3.2): the two prime factors plus
/// the precomputed CRT exponents/coefficient, so `rsadpCrt`/`rsasp1` can use
/// the fast (~4x) two-prime CRT path. `d` (the plain, non-CRT private
/// exponent) is kept too for the straightforward `rsadp` form and as a
/// fallback / cross-check.
pub const SecretKey = struct {
    /// Modulus n = p * q.
    n: Modulus,
    /// Private exponent d ≡ e⁻¹ (mod λ(n)) — non-CRT form (RFC 8017 §3.2, form (1)).
    d: Fe,
    /// First prime factor p.
    p: Modulus,
    /// Second prime factor q.
    q: Modulus,
    /// dP = d mod (p - 1) — first CRT exponent.
    dp: Fe,
    /// dQ = d mod (q - 1) — second CRT exponent.
    dq: Fe,
    /// qInv = q⁻¹ mod p — CRT coefficient.
    qinv: Fe,

    pub const FromPrimesError = error{InvalidPrivateKey};

    /// Build a `SecretKey` (deriving `n`, `d`, and the CRT params) from the
    /// two prime factors and the public exponent, all big-endian byte strings
    /// (leading zeros tolerated), per RFC 8017 §3.2:
    ///   n = p*q, d = e⁻¹ mod λ(n) with λ(n) = lcm(p-1, q-1),
    ///   dP = d mod (p-1), dQ = d mod (q-1), qInv = q⁻¹ mod p.
    ///
    /// `p` and `q` are trusted to be prime (this constructor validates
    /// structure — oddness, p ≠ q, gcd(e, λ(n)) = 1, qInv·q ≡ 1 (mod p) —
    /// but performs no primality test; that is P5 territory).
    ///
    /// Timing note: the runtime primitives are constant-time via
    /// `std.crypto.ff`, and qInv is derived with a constant-time Fermat
    /// inversion (q^(p-2) mod p). The n/λ/d/dP/dQ derivation, however, uses
    /// `std.math.big.int` (extended Euclid), which is variable-time — `ff`
    /// cannot express it since λ(n) and p-1/q-1 are even. This is a one-time
    /// key-import cost, not a per-operation leak.
    pub fn fromPrimes(p_bytes: []const u8, q_bytes: []const u8, e_bytes: []const u8) FromPrimesError!SecretKey {
        return fromPrimesImpl(p_bytes, q_bytes, e_bytes) catch error.InvalidPrivateKey;
    }
};

// ── fromPrimes internals (big.int-backed key derivation) ────────────────────

const BigInt = std.math.big.int.Managed;

/// Limb capacity covering 2×`max_modulus_bits` products plus headroom; every
/// scratch `BigInt` is pre-sized to this so the derivation below performs no
/// reallocation-driven growth inside the fixed-buffer arena.
const big_capacity = (2 * max_modulus_bits) / @bitSizeOf(std.math.big.Limb) + 4;

fn newBig(gpa: std.mem.Allocator) !BigInt {
    return BigInt.initCapacity(gpa, big_capacity);
}

/// Big-endian unsigned bytes -> `BigInt`.
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

/// Non-negative `BigInt` -> canonical `Fe` of `m` (fails if out of range).
fn feFromBig(m: Modulus, x: *const BigInt) !Fe {
    if (!x.isPositive() and !x.eqlZero()) return error.InvalidPrivateKey;
    if (x.bitCountAbs() > max_modulus_bits) return error.InvalidPrivateKey;
    var buf: [max_modulus_len]u8 = undefined;
    x.toConst().writeTwosComplement(&buf, .big);
    return Fe.fromBytes(m, &buf, .big);
}

/// d = e⁻¹ (mod m) via the extended Euclidean algorithm; fails unless
/// gcd(e, m) = 1. Variable-time (see the `fromPrimes` timing note).
fn bigModInverse(gpa: std.mem.Allocator, e: *const BigInt, m: *const BigInt) !BigInt {
    // Invariants: t0*e ≡ r0, t1*e ≡ r1 (mod m).
    var r0 = try newBig(gpa);
    try r0.copy(m.toConst());
    var r1 = try newBig(gpa);
    try r1.copy(e.toConst());
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
    // r0 = gcd(e, m); must be 1 for e to be invertible.
    if (r0.toConst().orderAgainstScalar(1) != .eq) return error.InvalidPrivateKey;
    // t0*e ≡ 1 (mod m); normalize t0 (possibly negative) into [0, m).
    try quot.divFloor(&rem, &t0, m);
    return rem;
}

fn fromPrimesImpl(p_bytes: []const u8, q_bytes: []const u8, e_bytes: []const u8) !SecretKey {
    const pb = stripLeadingZeros(p_bytes);
    const qb = stripLeadingZeros(q_bytes);
    const eb = stripLeadingZeros(e_bytes);
    if (pb.len > max_modulus_len or qb.len > max_modulus_len) return error.InvalidPrivateKey;
    // e must be odd and >= 3 (RFC 8017 §3.1); evenness would also fail the
    // gcd check below, but reject early and explicitly.
    if (eb.len == 0 or eb[eb.len - 1] & 1 == 0) return error.InvalidPrivateKey;
    if (eb.len == 1 and eb[0] < 3) return error.InvalidPrivateKey;

    // `Modulus.fromBytes` rejects even and < 3 values, covering p, q oddness.
    const p = Modulus.fromBytes(pb, .big) catch return error.InvalidPrivateKey;
    const q = Modulus.fromBytes(qb, .big) catch return error.InvalidPrivateKey;

    // All big.int scratch lives in a stack arena; individual deinit is
    // pointless (fixed buffer), the whole arena dies with this frame.
    var scratch: [128 * 1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    const gpa = fba.allocator();

    var bp = try bigFromBytes(gpa, pb);
    var bq = try bigFromBytes(gpa, qb);
    var be = try bigFromBytes(gpa, eb);
    if (bp.order(bq) == .eq) return error.InvalidPrivateKey; // p == q

    // n = p*q, capped at max_modulus_bits.
    var bn = try newBig(gpa);
    try bn.mul(&bp, &bq);
    if (bn.bitCountAbs() > max_modulus_bits) return error.InvalidPrivateKey;
    var n_buf: [max_modulus_len]u8 = undefined;
    bn.toConst().writeTwosComplement(&n_buf, .big);
    const n = Modulus.fromBytes(&n_buf, .big) catch return error.InvalidPrivateKey;

    // λ(n) = lcm(p-1, q-1) = (p-1)(q-1) / gcd(p-1, q-1).
    var p1 = try newBig(gpa);
    try p1.addScalar(&bp, -1);
    var q1 = try newBig(gpa);
    try q1.addScalar(&bq, -1);
    var g = try newBig(gpa);
    try g.gcd(&p1, &q1);
    var phi = try newBig(gpa);
    try phi.mul(&p1, &q1);
    var lambda = try newBig(gpa);
    var rem = try newBig(gpa);
    try lambda.divFloor(&rem, &phi, &g); // exact: g | (p-1)(q-1)

    // d = e⁻¹ mod λ(n); also proves gcd(e, λ(n)) = 1.
    var bd = try bigModInverse(gpa, &be, &lambda);
    if (bd.eqlZero()) return error.InvalidPrivateKey;

    // dP = d mod (p-1), dQ = d mod (q-1).
    var quot = try newBig(gpa);
    var bdp = try newBig(gpa);
    try quot.divFloor(&bdp, &bd, &p1);
    var bdq = try newBig(gpa);
    try quot.divFloor(&bdq, &bd, &q1);

    const d = try feFromBig(n, &bd);
    const dp = try feFromBig(p, &bdp);
    const dq = try feFromBig(q, &bdq);
    // Zero CRT exponents are impossible for prime p, q (e·dP ≡ 1 mod p-1);
    // reject rather than trip `ff`'s NullExponent later on garbage input.
    if (d.isZero() or dp.isZero() or dq.isZero()) return error.InvalidPrivateKey;

    // qInv = q⁻¹ mod p = (q mod p)^(p-2) mod p — Fermat inversion, valid for
    // prime p, constant-time via `ff` (the exponent p-2 is secret).
    const q_mod_p = reduceWide(p, q.v);
    if (q_mod_p.isZero()) return error.InvalidPrivateKey;
    const two = Fe.fromPrimitive(u8, p, 2) catch return error.InvalidPrivateKey;
    const p_minus_2 = p.sub(p.zero, two); // (0 - 2) mod p = p - 2
    const qinv = p.pow(q_mod_p, p_minus_2) catch return error.InvalidPrivateKey;
    // Self-check qInv·q ≡ 1 (mod p): catches a non-prime p sneaking past.
    if (!p.mul(qinv, q_mod_p).eql(p.one())) return error.InvalidPrivateKey;

    return .{
        .n = n,
        .d = d,
        .p = p,
        .q = q,
        .dp = dp,
        .dq = dq,
        .qinv = qinv,
    };
}

// ── low-level primitives (RFC 8017 §5) ───────────────────────────────────────
//
// Named after the RFC's own primitive names so the mapping to the spec is
// unambiguous: RSAEP/RSADP are the encrypt/decrypt primitives (§5.1), RSASP1/
// RSAVP1 are the sign/verify primitives (§5.2). RSAEP and RSAVP1 share the
// same math (public-key modexp); RSADP and RSASP1 share the same math
// (private-key modexp) — mirrors how std's internal `rsa.encrypt` collapses
// RSAEP/RSAVP1 into one function.

pub const PrimitiveError = error{MessageRepresentativeOutOfRange};

// Runtime-length (slice) cores. The `out` buffer must be exactly the modulus
// length in bytes (I2OSP target length, `k` in the RFC); each caller in this
// file guarantees that, so the final I2OSP `toBytes` cannot overflow. The
// input is OS2IP'd and range-checked (must be in [0, n-1]) as the RFC
// requires.

/// `ff.Modulus.reduce` assumes the input spans at least as many limbs as the
/// modulus (its initial copy loop underflows `usize` otherwise — std only
/// ever feeds it wider-than-modulus values). Zero-extend the active limbs
/// first so it is safe for narrow inputs (e.g. m2 < q reduced mod n).
fn reduceWide(m: Modulus, x: Uint) Fe {
    var xx = x;
    if (xx.limbs_len < m.v.limbs_len) {
        @memset(xx.limbs_buffer[xx.limbs_len..m.v.limbs_len], 0);
        xx.limbs_len = m.v.limbs_len;
    }
    return m.reduce(xx);
}

fn publicOp(pk: PublicKey, in: []const u8, out: []u8) PrimitiveError!void {
    const m = Fe.fromBytes(pk.n, in, .big) catch return error.MessageRepresentativeOutOfRange;
    // Public exponent -> variable-time powPublic is fine; e is validated
    // non-zero at key construction time.
    const c = pk.n.powPublic(m, pk.e) catch unreachable;
    c.toBytes(out, .big) catch unreachable; // c < n and out.len == byteLen(n)
}

fn privateOp(sk: SecretKey, in: []const u8, out: []u8) PrimitiveError!void {
    const c = Fe.fromBytes(sk.n, in, .big) catch return error.MessageRepresentativeOutOfRange;
    // Secret exponent -> constant-time pow; d is validated non-zero by
    // `fromPrimes`.
    const m = sk.n.pow(c, sk.d) catch unreachable;
    m.toBytes(out, .big) catch unreachable;
}

fn privateOpCrt(sk: SecretKey, in: []const u8, out: []u8) PrimitiveError!void {
    const c = Fe.fromBytes(sk.n, in, .big) catch return error.MessageRepresentativeOutOfRange;
    // RFC 8017 §5.1.2 form (2), two-prime case:
    //   m1 = c^dP mod p, m2 = c^dQ mod q
    const m1 = sk.p.pow(reduceWide(sk.p, c.v), sk.dp) catch unreachable;
    const m2 = sk.q.pow(reduceWide(sk.q, c.v), sk.dq) catch unreachable;
    //   h = (m1 - m2) * qInv mod p    (m2 reduced into mod-p domain first)
    const h = sk.p.mul(sk.qinv, sk.p.sub(m1, reduceWide(sk.p, m2.v)));
    //   m = m2 + q*h — the true integer value is < n (m2 < q, h <= p-1), so
    //   computing it mod n is exact.
    const m2_n = reduceWide(sk.n, m2.v);
    const q_n = reduceWide(sk.n, sk.q.v);
    const h_n = reduceWide(sk.n, h.v);
    const m = sk.n.add(m2_n, sk.n.mul(q_n, h_n));
    m.toBytes(out, .big) catch unreachable;
}

/// RSAEP: c = m^e mod n (RFC 8017 §5.1.1), the encryption primitive.
/// `modulus_len` must be the modulus length in bytes (`k` = ceil(bits(n)/8)).
pub fn rsaep(comptime modulus_len: usize, m: [modulus_len]u8, pk: PublicKey) PrimitiveError![modulus_len]u8 {
    comptime std.debug.assert(modulus_len <= max_modulus_len);
    var out: [modulus_len]u8 = undefined;
    try publicOp(pk, &m, &out);
    return out;
}

/// RSAVP1: identical math to `rsaep` (RFC 8017 §5.2.2), the verification
/// primitive. Kept as a separate name for spec-fidelity / call-site clarity.
pub fn rsavp1(comptime modulus_len: usize, s: [modulus_len]u8, pk: PublicKey) PrimitiveError![modulus_len]u8 {
    return rsaep(modulus_len, s, pk);
}

/// RSADP: m = c^d mod n (RFC 8017 §5.1.2, form (1) — non-CRT), the decryption
/// primitive.
pub fn rsadp(comptime modulus_len: usize, c: [modulus_len]u8, sk: SecretKey) PrimitiveError![modulus_len]u8 {
    comptime std.debug.assert(modulus_len <= max_modulus_len);
    var out: [modulus_len]u8 = undefined;
    try privateOp(sk, &c, &out);
    return out;
}

/// RSADP via CRT (RFC 8017 §5.1.2, form (2), steps 2.a-2.d) — the fast path
/// using p, q, dP, dQ, qInv instead of a single full-width modexp.
pub fn rsadpCrt(comptime modulus_len: usize, c: [modulus_len]u8, sk: SecretKey) PrimitiveError![modulus_len]u8 {
    comptime std.debug.assert(modulus_len <= max_modulus_len);
    var out: [modulus_len]u8 = undefined;
    try privateOpCrt(sk, &c, &out);
    return out;
}

/// RSASP1: signature primitive, same math as `rsadp` (RFC 8017 §5.2.1).
/// The real implementation should route through `rsadpCrt` for performance.
pub fn rsasp1(comptime modulus_len: usize, m: [modulus_len]u8, sk: SecretKey) PrimitiveError![modulus_len]u8 {
    return rsadpCrt(modulus_len, m, sk);
}

// ── P1: EMSA-PKCS1-v1_5 sign / verify (RFC 8017 §8.2, §9.2) ─────────────────
//
// This is the first phase a follow-up crypto-implementation agent should
// build: the classic PKCS#1 v1.5 signature scheme (still the most widely
// deployed RSA signature format — TLS, JWT `RS256`, code signing).

/// DER-encoded DigestInfo prefix `T` minus the trailing digest, per RFC 8017
/// §9.2 Note 1 (fixed byte strings straight out of the RFC).
fn digestInfoPrefix(comptime Hash: type) []const u8 {
    const hash = std.crypto.hash;
    return switch (Hash) {
        hash.Sha1 => &.{
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
            0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
        },
        hash.sha2.Sha224 => &.{
            0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
            0x00, 0x04, 0x1c,
        },
        hash.sha2.Sha256 => &.{
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
            0x00, 0x04, 0x20,
        },
        hash.sha2.Sha384 => &.{
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
            0x00, 0x04, 0x30,
        },
        hash.sha2.Sha512 => &.{
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
            0x00, 0x04, 0x40,
        },
        else => @compileError("unsupported hash for EMSA-PKCS1-v1_5 DigestInfo: " ++ @typeName(Hash)),
    };
}

pub const EmsaEncodeError = error{EncodedMessageTooShort};

/// EMSA-PKCS1-v1_5 encoding (RFC 8017 §9.2):
/// EM = 0x00 || 0x01 || PS(0xff…) || 0x00 || DigestInfo(Hash, Hash(msg)),
/// written into all of `em` (`em.len` = intended encoded message length).
fn emsaPkcs1v15Encode(comptime Hash: type, msg: []const u8, em: []u8) EmsaEncodeError!void {
    const prefix = digestInfoPrefix(Hash);
    const t_len = prefix.len + Hash.digest_length;
    // §9.2 step 3: emLen >= tLen + 11 guarantees PS >= 8 octets.
    if (em.len < t_len + 11) return error.EncodedMessageTooShort;
    em[0] = 0x00;
    em[1] = 0x01;
    const ps_end = em.len - t_len - 1;
    @memset(em[2..ps_end], 0xff);
    em[ps_end] = 0x00;
    @memcpy(em[ps_end + 1 ..][0..prefix.len], prefix);
    Hash.hash(msg, em[em.len - Hash.digest_length ..][0..Hash.digest_length], .{});
}

pub const SignPkcs1v15Error = EmsaEncodeError || error{BufferTooSmall};

/// Sign `msg` with EMSA-PKCS1-v1_5 encoding (RFC 8017 §9.2) + the RSASP1
/// signature primitive (§8.2.1). `out` must be at least as long as the
/// modulus (`sk.n` byte length); returns the written subslice.
pub fn signPkcs1v15(sk: SecretKey, comptime Hash: type, msg: []const u8, out: []u8) SignPkcs1v15Error![]u8 {
    const k = byteLen(sk.n.bits());
    if (out.len < k) return error.BufferTooSmall;
    var em_buf: [max_modulus_len]u8 = undefined;
    const em = em_buf[0..k];
    try emsaPkcs1v15Encode(Hash, msg, em);
    // EM starts with 0x00 0x01, so its integer value is < n by construction;
    // the range check inside the primitive cannot fail.
    privateOpCrt(sk, em, out[0..k]) catch unreachable;
    return out[0..k];
}

pub const VerifyPkcs1v15Error = error{SignatureVerificationFailed};

/// Verify an EMSA-PKCS1-v1_5 signature (RFC 8017 §8.2.2): RSAVP1 recovers the
/// encoded message, which must byte-for-byte equal the re-derived
/// EMSA-PKCS1-v1_5 encoding of `msg` (full encoding comparison — no parsing
/// of the recovered padding, so no Bleichenbacher'06-style laxity), compared
/// in constant time.
pub fn verifyPkcs1v15(pk: PublicKey, comptime Hash: type, msg: []const u8, sig: []const u8) VerifyPkcs1v15Error!void {
    const k = byteLen(pk.n.bits());
    // §8.2.2 step 1: the signature must be exactly k octets.
    if (sig.len != k) return error.SignatureVerificationFailed;
    var em_dec = std.mem.zeroes([max_modulus_len]u8);
    publicOp(pk, sig, em_dec[0..k]) catch return error.SignatureVerificationFailed;
    var em_exp = std.mem.zeroes([max_modulus_len]u8);
    emsaPkcs1v15Encode(Hash, msg, em_exp[0..k]) catch return error.SignatureVerificationFailed;
    if (!std.crypto.timing_safe.eql([max_modulus_len]u8, em_dec, em_exp)) {
        return error.SignatureVerificationFailed;
    }
}

// ── P2: RSAES-OAEP (RFC 8017 §7.1) ───────────────────────────────────────────

/// MGF1 mask generation function (RFC 8017 §B.2.1), XORed directly into
/// `data` (`data ^= MGF1(seed, data.len)`). The XOR-in-place form serves both
/// masking and unmasking (they are the same operation) without a second
/// full-width mask buffer.
fn mgf1Xor(comptime Hash: type, seed: []const u8, data: []u8) void {
    var counter: u32 = 0;
    var off: usize = 0;
    while (off < data.len) : (counter += 1) {
        // §B.2.1 step 3: Hash(seed || C) with C = I2OSP(counter, 4).
        var c: [4]u8 = undefined;
        std.mem.writeInt(u32, &c, counter, .big);
        var st = Hash.init(.{});
        st.update(seed);
        st.update(&c);
        var digest: [Hash.digest_length]u8 = undefined;
        st.final(&digest);
        const n = @min(digest.len, data.len - off);
        for (data[off..][0..n], digest[0..n]) |*d, m| d.* ^= m;
        off += n;
    }
}

// Constant-time byte helpers for the OAEP decode (no data-dependent
// branches; standard masking arithmetic, same shape as
// `std.crypto.timing_safe.eql`'s accumulator).

/// 1 if `x == y`, else 0 — branchless.
fn ctEqByte(x: u8, y: u8) u8 {
    const diff: u16 = x ^ y;
    return @truncate(((diff -% 1) >> 8) & 1);
}

/// `if (v == 1) a else b` for v in {0, 1} — branchless.
fn ctSelect(v: u8, a: usize, b: usize) usize {
    const mask = @as(usize, 0) -% v; // all-ones iff v == 1
    return (a & mask) | (b & ~mask);
}

pub const EncryptOaepError = error{ MessageTooLong, BufferTooSmall };

/// Encrypt `msg` under RSAES-OAEP (RFC 8017 §7.1.1). `label` is the optional
/// OAEP label (`L` in the RFC; pass `""` for the common no-label case).
/// `random` supplies the mandatory fresh seed and MUST be cryptographically
/// secure — OAEP's security proof assumes an unpredictable seed (a
/// deterministic or low-entropy source voids CCA security). `out` must be at
/// least as long as the modulus; returns the written (modulus-length)
/// ciphertext subslice. `msg` is bounded by `k - 2*Hash.digest_length - 2`
/// (§7.1.1 step 1.b).
pub fn encryptOaep(pk: PublicKey, comptime Hash: type, random: std.Random, msg: []const u8, label: []const u8, out: []u8) EncryptOaepError![]u8 {
    const h_len = Hash.digest_length;
    const k = byteLen(pk.n.bits());
    if (out.len < k) return error.BufferTooSmall;
    // §7.1.1 step 1.b: mLen <= k - 2 hLen - 2 (also covers k too small for
    // the hash at all).
    if (k < 2 * h_len + 2 or msg.len > k - 2 * h_len - 2) return error.MessageTooLong;

    // EM = 0x00 || maskedSeed (hLen) || maskedDB (k - hLen - 1), built in
    // place (§7.1.1 step 2).
    var em_buf: [max_modulus_len]u8 = undefined;
    defer std.crypto.secureZero(u8, em_buf[0..k]); // seed/DB are secret
    const em = em_buf[0..k];
    em[0] = 0x00;
    const seed = em[1..][0..h_len];
    const db = em[1 + h_len .. k];

    // DB = lHash || PS (zeros) || 0x01 || M   (step 2.a-2.c)
    Hash.hash(label, db[0..h_len], .{});
    @memset(db[h_len .. db.len - msg.len - 1], 0x00);
    db[db.len - msg.len - 1] = 0x01;
    @memcpy(db[db.len - msg.len ..], msg);

    // step 2.d-2.h: random seed, then the two MGF1 maskings. Order matters
    // for the in-place XOR: DB is masked with the *raw* seed first, then the
    // seed is masked with the already-masked DB.
    random.bytes(seed);
    mgf1Xor(Hash, seed, db); // maskedDB   = DB   ^ MGF1(seed)
    mgf1Xor(Hash, db, seed); // maskedSeed = seed ^ MGF1(maskedDB)

    // step 3: RSAEP. EM starts with 0x00, so OS2IP(EM) < n by construction
    // (k = byteLen(n) and n's top byte is nonzero) — the range check cannot
    // fire.
    publicOp(pk, em, out[0..k]) catch unreachable;
    return out[0..k];
}

pub const DecryptOaepError = error{ DecryptionError, BufferTooSmall };

/// Decrypt an RSAES-OAEP ciphertext (RFC 8017 §7.1.2). `out` must be at
/// least `k - 2*Hash.digest_length - 2` bytes (the maximum recoverable
/// message length — checked up front so the buffer test never depends on the
/// secret plaintext length); returns the written (plaintext-length) subslice.
///
/// All padding-decode failures (leading byte != 0x00, label-hash mismatch,
/// missing/malformed 0x01 separator) are accumulated branch-free into one
/// validity flag and reported as the single generic `error.DecryptionError` —
/// per §7.1.2 "care must be taken to ensure that an opponent cannot
/// distinguish the different error conditions" (Manger's CCA2 attack). The
/// only length checks that branch early (`ct.len != k`, undersized `out`,
/// RSADP range) depend purely on public values.
pub fn decryptOaep(sk: SecretKey, comptime Hash: type, ct: []const u8, label: []const u8, out: []u8) DecryptOaepError![]u8 {
    const h_len = Hash.digest_length;
    const k = byteLen(sk.n.bits());
    // §7.1.2 step 1: ciphertext must be exactly k octets and k >= 2 hLen + 2.
    if (ct.len != k or k < 2 * h_len + 2) return error.DecryptionError;
    const max_msg_len = k - 2 * h_len - 2;
    if (out.len < max_msg_len) return error.BufferTooSmall;

    // step 2: RSADP (CRT fast path). c >= n is public information (the
    // ciphertext is public), so this early error is not an oracle.
    var em_buf: [max_modulus_len]u8 = undefined;
    defer std.crypto.secureZero(u8, em_buf[0..k]);
    const em = em_buf[0..k];
    privateOpCrt(sk, ct, em) catch return error.DecryptionError;

    // step 3: EME-OAEP decode, branch-free. EM = Y || maskedSeed || maskedDB.
    const seed = em[1..][0..h_len];
    const db = em[1 + h_len .. k];
    mgf1Xor(Hash, db, seed); // seed = maskedSeed ^ MGF1(maskedDB)
    mgf1Xor(Hash, seed, db); // DB   = maskedDB   ^ MGF1(seed)

    var lhash: [h_len]u8 = undefined;
    Hash.hash(label, &lhash, .{});
    const y_ok = ctEqByte(em[0], 0x00);
    const lhash_ok: u8 = @intFromBool(std.crypto.timing_safe.eql([h_len]u8, lhash, db[0..h_len].*));

    // Scan DB[hLen..] = PS || 0x01 || M for the separator without revealing
    // its position: `looking` stays 1 until the first 0x01; any nonzero,
    // non-separator byte seen while still looking marks the padding invalid.
    var looking: u8 = 1;
    var invalid: u8 = 0;
    var sep_idx: usize = 0; // index of the 0x01 separator within db
    var i: usize = h_len;
    while (i < db.len) : (i += 1) {
        const is_one = ctEqByte(db[i], 0x01);
        const is_zero = ctEqByte(db[i], 0x00);
        sep_idx = ctSelect(looking & is_one, i, sep_idx);
        looking &= is_one ^ 1;
        invalid |= looking & (is_zero ^ 1);
    }

    // Single decision point: every failure mode collapses into one flag and
    // one generic error. (`looking` still 1 = no separator found at all.)
    const valid = y_ok & lhash_ok & (invalid ^ 1) & (looking ^ 1);
    if (valid != 1) return error.DecryptionError;

    // step 4: M = DB[sep_idx+1..]. Its length is part of the function's
    // regular output (the returned slice), i.e. public on success — only
    // failures must be indistinguishable, and none of them reach this point.
    const msg_len = db.len - sep_idx - 1;
    @memcpy(out[0..msg_len], db[sep_idx + 1 ..]);
    return out[0..msg_len];
}

// ── P3: RSASSA-PSS (RFC 8017 §8.1) ───────────────────────────────────────────
//
// PSS operates on emBits = modBits - 1 bits (§8.1.1 step 2), so the encoded
// message can be one byte shorter than the modulus (when modBits ≡ 1 mod 8)
// and its leftmost 8·emLen - emBits bits are always forced to zero — that is
// what keeps EM < 2^emBits <= n/2 < n, so RSASP1's range check can never fire
// on a well-formed encoding. MGF1 is reused from P2 (`mgf1Xor`); this module
// follows the ubiquitous MGF-hash = message-hash convention (same as
// `openssl dgst -sigopt rsa_padding_mode:pss` defaults).

/// EMSA-PSS-ENCODE (RFC 8017 §9.1.1) with a caller-supplied salt, written
/// into all of `em` (`em.len` must equal ceil(em_bits/8)):
///   H = Hash((0x00 × 8) || Hash(msg) || salt)
///   EM = (DB ^ MGF1(H)) || H || 0xbc, DB = PS(0x00…) || 0x01 || salt,
/// with the leftmost 8·emLen - emBits bits of maskedDB cleared (step 11).
fn emsaPssEncode(comptime Hash: type, msg: []const u8, salt: []const u8, em_bits: usize, em: []u8) EmsaEncodeError!void {
    const h_len = Hash.digest_length;
    const em_len = em.len;
    std.debug.assert(em_len == byteLen(em_bits));
    // §9.1.1 step 3: emLen >= hLen + sLen + 2.
    if (em_len < h_len + 2 or salt.len > em_len - h_len - 2) return error.EncodedMessageTooShort;

    const db = em[0 .. em_len - h_len - 1];
    const h = em[em_len - h_len - 1 ..][0..h_len];

    // steps 2, 5-6: mHash = Hash(M); H = Hash(M'),
    // M' = (0x00 × 8) || mHash || salt.
    var m_hash: [h_len]u8 = undefined;
    Hash.hash(msg, &m_hash, .{});
    var st = Hash.init(.{});
    st.update(&[_]u8{0} ** 8);
    st.update(&m_hash);
    st.update(salt);
    st.final(h);

    // steps 7-8: DB = PS (zeros) || 0x01 || salt.
    @memset(db[0 .. db.len - salt.len - 1], 0x00);
    db[db.len - salt.len - 1] = 0x01;
    @memcpy(db[db.len - salt.len ..], salt);

    // steps 9-10: maskedDB = DB ^ MGF1(H, emLen - hLen - 1).
    mgf1Xor(Hash, h, db);

    // step 11: clear the leftmost 8·emLen - emBits bits of maskedDB so that
    // OS2IP(EM) < 2^emBits.
    em[0] &= @as(u8, 0xff) >> @intCast(8 * em_len - em_bits);

    em[em_len - 1] = 0xbc; // step 12: trailer field.
}

pub const SignPssError = EmsaEncodeError || error{BufferTooSmall};

/// Sign `msg` with RSASSA-PSS (RFC 8017 §8.1.1): EMSA-PSS-ENCODE (§9.1.1)
/// over emBits = modBits - 1, then the RSASP1 signature primitive (CRT fast
/// path). `salt_len` is the PSS salt length in bytes (`sLen`): `0` yields
/// deterministic signatures (and `random` is never drawn from),
/// `Hash.digest_length` is the conventional default (what OpenSSL calls
/// `rsa_pss_saltlen:digest`). `random` supplies the fresh salt and MUST be
/// cryptographically secure for `salt_len > 0`. `out` must be at least as
/// long as the modulus (`sk.n` byte length); returns the written
/// (modulus-length) signature subslice.
pub fn signPss(sk: SecretKey, comptime Hash: type, random: std.Random, msg: []const u8, salt_len: usize, out: []u8) SignPssError![]u8 {
    const k = byteLen(sk.n.bits());
    if (out.len < k) return error.BufferTooSmall;
    const em_bits = sk.n.bits() - 1;
    const em_len = byteLen(em_bits);
    // Early salt bound so the fixed salt buffer below cannot overflow on an
    // absurd salt_len; the precise §9.1.1 step 3 bound is re-checked inside
    // emsaPssEncode.
    if (salt_len >= em_len) return error.EncodedMessageTooShort;

    var salt_buf: [max_modulus_len]u8 = undefined;
    const salt = salt_buf[0..salt_len];
    defer std.crypto.secureZero(u8, salt);
    random.bytes(salt);

    // EM is placed at the right edge of the k-byte representative; the
    // leading pad byte (present only when modBits ≡ 1 mod 8) stays zero.
    var em_buf: [max_modulus_len]u8 = undefined;
    defer std.crypto.secureZero(u8, em_buf[0..k]);
    @memset(em_buf[0 .. k - em_len], 0x00);
    try emsaPssEncode(Hash, msg, salt, em_bits, em_buf[k - em_len .. k]);

    // §8.1.1 step 2: RSASP1. EM < 2^emBits < n by construction (step 11
    // cleared the top bits), so the primitive's range check cannot fail.
    privateOpCrt(sk, em_buf[0..k], out[0..k]) catch unreachable;
    return out[0..k];
}

pub const VerifyPssError = error{SignatureVerificationFailed};

/// Verify an RSASSA-PSS signature (RFC 8017 §8.1.2): RSAVP1 recovers the
/// encoded message, which is checked per EMSA-PSS-VERIFY (§9.1.2) against
/// `msg` for the given `salt_len` (must equal the signer's `sLen`; this
/// implementation does not auto-detect salt length). All checks over the
/// recovered encoding are accumulated branch-free into one validity flag
/// (H comparison via `std.crypto.timing_safe.eql`) and every failure mode
/// reports the single generic `error.SignatureVerificationFailed`.
pub fn verifyPss(pk: PublicKey, comptime Hash: type, msg: []const u8, sig: []const u8, salt_len: usize) VerifyPssError!void {
    const h_len = Hash.digest_length;
    const k = byteLen(pk.n.bits());
    // §8.1.2 step 1: the signature must be exactly k octets.
    if (sig.len != k) return error.SignatureVerificationFailed;
    const em_bits = pk.n.bits() - 1;
    const em_len = byteLen(em_bits);
    // §9.1.2 step 3: emLen >= hLen + sLen + 2. Public parameters only
    // (modulus size, hash, expected salt length), so branching is harmless.
    if (em_len < h_len + 2 or salt_len > em_len - h_len - 2) return error.SignatureVerificationFailed;

    // §8.1.2 step 2: RSAVP1 (public-key operation; s >= n is public info).
    var em_buf: [max_modulus_len]u8 = undefined;
    publicOp(pk, sig, em_buf[0..k]) catch return error.SignatureVerificationFailed;

    var ok: u8 = 1;
    // When emLen < k the representative carries leading pad octets that a
    // well-formed signature leaves zero.
    for (em_buf[0 .. k - em_len]) |b| ok &= ctEqByte(b, 0x00);
    const em = em_buf[k - em_len .. k];
    const db = em[0 .. em_len - h_len - 1];
    const h = em[em_len - h_len - 1 ..][0..h_len];

    // §9.1.2 step 4: rightmost octet must be the 0xbc trailer.
    ok &= ctEqByte(em[em_len - 1], 0xbc);

    // step 6: the leftmost 8·emLen - emBits bits of maskedDB must be zero.
    const top_mask = @as(u8, 0xff) >> @intCast(8 * em_len - em_bits);
    ok &= ctEqByte(em[0] & ~top_mask, 0x00);

    // steps 7-9: DB = maskedDB ^ MGF1(H), then clear the leftmost bits.
    mgf1Xor(Hash, h, db);
    db[0] &= top_mask;

    // step 10: DB = PS (zeros) || 0x01 || salt.
    const ps_len = em_len - h_len - salt_len - 2;
    for (db[0..ps_len]) |b| ok &= ctEqByte(b, 0x00);
    ok &= ctEqByte(db[ps_len], 0x01);
    const salt = db[db.len - salt_len ..];

    // steps 2, 12-13: H' = Hash((0x00 × 8) || Hash(msg) || salt).
    var m_hash: [h_len]u8 = undefined;
    Hash.hash(msg, &m_hash, .{});
    var h_prime: [h_len]u8 = undefined;
    var st = Hash.init(.{});
    st.update(&[_]u8{0} ** 8);
    st.update(&m_hash);
    st.update(salt);
    st.final(&h_prime);

    // step 14: H == H', folded into the single decision point.
    ok &= @intFromBool(std.crypto.timing_safe.eql([h_len]u8, h.*, h_prime));
    if (ok != 1) return error.SignatureVerificationFailed;
}

// ── P4: key parsing — reserved, not yet implemented ─────────────────────────

/// Parse a private key from a DER-encoded PKCS#8 `PrivateKeyInfo` wrapping an
/// RFC 8017 Appendix A.1.2 `RSAPrivateKey`.
pub fn fromPkcs8(bytes: []const u8) !SecretKey {
    _ = bytes;
    @panic("TODO(agent): P4 parse PKCS#8 PrivateKeyInfo (RFC 5958) wrapping RSAPrivateKey per RFC 8017 Appendix A.1.2");
}

/// Parse a private key from the OpenSSH `PROTOCOL.key` private-key text
/// format (`-----BEGIN OPENSSH PRIVATE KEY-----`), including bcrypt-pbkdf
/// decryption for passphrase-protected keys.
pub fn fromOpenSSH(gpa: std.mem.Allocator, text: []const u8) !SecretKey {
    _ = gpa;
    _ = text;
    @panic("TODO(agent): P4 parse OpenSSH PROTOCOL.key format (base64 blob + bcrypt-pbkdf if encrypted; see OpenBSD PROTOCOL.key + bcrypt_pbkdf.c as design refs only)");
}

// ── P5: key generation — reserved, not yet implemented ──────────────────────

/// Generate a fresh RSA keypair of `bits` modulus size (probable-prime search
/// + CRT parameter derivation).
pub fn generate(io: std.Io, bits: usize) !SecretKey {
    _ = io;
    _ = bits;
    @panic("TODO(agent): P5 RSA keypair generation per RFC 8017 §3.2 (two probable primes, e.g. Miller-Rabin per NIST FIPS 186-5 Appendix B/C) + CRT param derivation");
}

// ── P6: self-signed certificate generation — reserved, not yet implemented ──

/// Generate a self-signed X.509 certificate for `sk`, DER-encoded.
pub fn selfSignedCert(gpa: std.mem.Allocator, sk: SecretKey, subject: []const u8) ![]u8 {
    _ = gpa;
    _ = sk;
    _ = subject;
    @panic("TODO(agent): P6 self-signed X.509 cert generation: build TBSCertificate DER (RFC 5280) + RSASSA-PKCS1-v1_5-sign it (via signPkcs1v15)");
}

// ── tests ────────────────────────────────────────────────────────────────────
//
// Single-file module (no submodules), so the CONVENTIONS.md "dark-tests" rule
// (aggregate every submodule's tests into root.zig's `test { _ = ...; }`) does
// not apply here — nothing to aggregate. None of these tests touch the
// remaining P2–P6 @panic stubs.
//
// Test-vector provenance:
// * Textbook vector (p=61, q=53, e=17): the classic worked RSA example —
//   n=3233, λ(n)=780, d=413, 65^17 mod 3233 = 2790 — verifiable by hand.
// * 2048-bit and 512-bit KATs: keypairs generated locally with
//   `openssl genpkey -algorithm RSA` (OpenSSL 3.5.5, 2026-07-10), components
//   dumped via `openssl pkey -text`, signatures produced with
//   `openssl dgst -shaN -sign` (RSASSA-PKCS1-v1_5 is deterministic, so these
//   are stable known answers). OpenSSL derives d = e⁻¹ mod λ(n), same as
//   `fromPrimes`, so d/dP/dQ/qInv are compared verbatim.
// * OAEP decrypt KATs: ciphertexts produced against the same 2048-bit key
//   with `openssl pkeyutl -encrypt -pkeyopt rsa_padding_mode:oaep`
//   (OpenSSL 3.5.5, 2026-07-10; `rsa_oaep_md`/`rsa_mgf1_md` = sha256 or
//   sha1, `rsa_oaep_label` for the labeled vector). OAEP *encryption* is
//   randomized, so only decrypt KATs can be static — round-trip tests cover
//   the encrypt direction.
// * MGF1 vectors: computed with Python 3.14 hashlib per RFC 8017 §B.2.1
//   (seed || I2OSP(counter, 4), concatenated digests).
// * PSS KATs: signatures produced against the same 2048-bit key with
//   `openssl dgst -shaN -sigopt rsa_padding_mode:pss
//   -sigopt rsa_pss_saltlen:<n> -sign` (OpenSSL 3.5.5, 2026-07-10; MGF1 hash
//   = message hash, OpenSSL's default). PSS signing is randomized for
//   sLen > 0, so those are verify-only KATs; the sLen = 0 vector is
//   deterministic and doubles as a byte-exact sign KAT.

const testing = std.testing;

fn hexLit(comptime hex: []const u8) [hex.len / 2]u8 {
    comptime {
        @setEvalBranchQuota(100_000);
        var out: [hex.len / 2]u8 = undefined;
        _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
        return out;
    }
}

// 2048-bit OpenSSL KAT key + signatures (see provenance note above).
const kat2048 = struct {
    const msg = "zig-libs rsa: PKCS#1 v1.5 known-answer test";
    const e = [_]u8{ 0x01, 0x00, 0x01 }; // 65537
    const p = hexLit("cd91a6496cfb79576c073ddea09edc423deebdaa3b103017d00572ebb61b1a05b9e7340239fd8019790b76ec74233842f786d620f80362ca455e6c0b26859db9e5c50d71c551759ffd2ef2facc98c10d6c2e8e0662a5d25a0d847c4fc54a062fc4bb75c552ae1cdef197916cd81c4dd102f314a8a4eb8c73c5c6b3e85c40a11d");
    const q = hexLit("c9c4dbb594569066caaaadbf5be98990357e0ea3d3619601b2155bac8ed96b28d6eec9578163dd3b08e0132a0f91a99c98a139b3e7b016f7e83dfe6e18d97b4448dccab617a3ac3aa6aa1359c3f5396473f4b0b20038252ae1d77e8cdf1fce2a9f4ea3208269f79d516e7b9a22e2fe4b4dad87621173348f896e2303cae5b59f");
    const n = hexLit("a2056f805f21fbf8815681fc5f7bb07bb8c7cba3be6e10ef3c3905981d666aa60adde3a7ebd258efae4e0d120e109c42cde35c6c322287135644e25eb79640aa91bc69a63b96fc3a72d85641cf567f4d4775c70c11d3c319989e764bc94c68002eb159d8fb05b73cafe489fb33b99e8f58ada35d59577e657f5097bb0e7a3f53e74b3592dbb31772092b96ab5aac70cef3b2afb54d1a35da41e895222c898f0306f9cd9ecb5b4e3bee111dcd5bfc44b976e7620b0e01b3072d0d3f5e995dcf20aa78d6633ef658bc1468f311ac4e6e005b2cf37d18f82cdc661f7d8cbd93709a4c122dd732bd243632b4a9d51da2f1d3c677a54d0f36c8f8458165d2fefe9203");
    const d = hexLit("181979e1323002643a37780f3b7ea647738fedbceb42eb96ecdcc875bcb872ad99ae86972acf22211df55dcc028be59fa988a398890934bbf8c2e1ef027216d2a83f1fc734fee62bfad02e086242f49d8b3f11693caf99ca1161a4a9423070c4722d8ecbe50eba6ce1a190afecf233b66668dc2f5d98d38eb2562108ec5987ae02819c97d0a2f60afa32d471766acdb8358b9a61cd8d4d4e1cd98aaa1193217558fb466be20ea48eda646929332e19c887f78ba423d573d44d05e74ce9757c79a59fb0377cace9e65f915b93dcc5b95fdc9cf026ab0ae69b48beed0e0238266b250ed55aa4e4bbf19ac8076a96a16e86b04058e565af55d8fc82726668d3062d");
    const dp = hexLit("01cceac5eddc6dfda406943624f5ff3bdd4b000243ae2a9daac6c170eb1165b2f323e142bbbb4aa9ee7379412ceb3a0cec1a143a09b20de573a216142aec34ab7225bdae676a053bb77df7c6d68fe7f0f4279c3ad61659b74c3302dbb800a3f93b21e1302f3f332588bc291be8f0a685d41ec8e989383eecaca8c6de9c203cc9");
    const dq = hexLit("1fe07c1db9ebdb30824068e6dcac8ed13bc248a9d5518b9385011ed4aa54eb3b2e89d7417dedbb1c0290f43626f38a6a752ab3a51aab95556159ba02c6e645354a95a769115f086cd3bbf706ad90e69a5a3f8452faf9e3d55c8ce12f7c68d7f79fe79a9a1e4083a05527315beebb1215ef95c4d7d78dedf5e76e8115ae4e905d");
    const qinv = hexLit("99437ab1bf00d96eccd75400da8411fdc353abcf7ff206668e056bd3dff642233cd0b6758daa0f6a651fcc2f6a160e0e5daa37393627627667a3e4391633e46c2a6dec7b1f3cca7647d7294f34a3fe104ac106ee34045c0ad1c97ed23b17fe1f7bce97b1cbd633f86912a17055e96ae4c6c565975b38def64419f645db7b14d2");
    const sig_sha256 = hexLit("13a8d24ca5403975e798dba5175fb593222e324590d4c893502e7b1523004537e45f43b249db254286cff0ac9620b086e64e022f17839f6a506c91823b5f598a295d5fc6cb71ea052f1763e8c72a83ff56abaf316d64480af1ce6e659a17cbec0121bfbc2e85fc0a4d0257d1cc3b9ba631330f27822294a2485553123be06190b0674873cde82c047aec88ff7f80408fc7b83c2e6aa60b4f145bda7a41ef039c3f296a89153e2e955b468e2183487dda64b7caff1058241a104703728512bb00b64daf033d52238f8dff1c50ffcf7f4c8428c76f170c0a8595c3480f61b0035f5aceaf037919752bd983d49f81a7966ad8c9729da9961b1231ea3c3568cc7871");
    const sig_sha384 = hexLit("0cb2f889b418a10bcc5d76741c88e6220ddeafc94e83c3c1bff4ab72eb8dbef5081aed59f6f31b532fd739e233e06d16382e130d6b6246e69a136df64d7fd6a19827c7d06056f5488273c29382f4bd864165ab853c36688cf1c820e1274d7143306161dae48336cc5a544dcf3616fa97f56491f9f8194ad0bab72e0e806384335622ad8ee6ea7af920e039672d1553f8025d2d900087942100e917e8f12eefcb32afdbe94c920db724742ebff5748d424e2fef815bd733cb8ec53e818dbb44ae3a19e6036ab224abf0e9ef0cac7df10c9ac080430473f409fea8720448b4c7380e91a08c740138da34b87f44ad0a9009ffc7741d9d761026a36fee09b29239b7");
    const sig_sha512 = hexLit("96157c8091612c24c99acc6f1cc0d91146e91c6a65940c6657bde957c600b23ec232eeda4f9a5e837770c430b1d8b372a0f093f5375983eb8655c5ca63f5229b981af95fea37c9d35e9400eb91d501adb877fad6ddf4f4dbd8576a137cd97c445a3602a1c8238e1f3ca43bfb65a5acb33c506befc6f6927135c130cc1f618bf9be056b6dd0e8a8c7fb8988fcee35ed11107ed85a462f71d7b12c94caf820e2189f770f5e6b8a2b160e0929ee753cfa1a3c4072603ca79803a571257d8ed72eba50a96c38bf4ed5f3d30bd703502a1c3915029fb35a2dcf8ffd1b78945a5bfa7de8bfc057578fd569487ba97d73c248ac5f9511e0a924556720d9db99915d79a4");

    fn secretKey() !SecretKey {
        return SecretKey.fromPrimes(&p, &q, &e);
    }

    fn publicKey() !PublicKey {
        return PublicKey.fromBytes(&n, &e);
    }
};

// 512-bit OpenSSL KAT key (minimum accepted modulus; exercises the
// encoded-message-too-short path for wide hashes).
const kat512 = struct {
    const e = [_]u8{ 0x01, 0x00, 0x01 };
    const p = hexLit("ddffc02bcb723444977ae03951c3e049051839daceea9745140e707abe762573");
    const q = hexLit("da7a6a07c0d4a626817597e6836e227f5689fb34184c39ca2b6a19fb2c1ee293");
    const n = hexLit("bd75f1797ee6d06063238fbe5109dd1f3845a4d1cbc138eb5d535c3391447fab5ff634bf7566df51327286a370bae5d4dcefcf914573cf4ba4d285a8d2610709");
};

test "rsa module compiles" {
    try testing.expect(true);
}

test "fromPrimes derives textbook parameters (p=61, q=53, e=17)" {
    const sk = try SecretKey.fromPrimes(&.{61}, &.{53}, &.{17});
    try testing.expectEqual(3233, try sk.n.v.toPrimitive(u32));
    try testing.expectEqual(413, try sk.d.toPrimitive(u32)); // e⁻¹ mod λ = e⁻¹ mod 780
    try testing.expectEqual(53, try sk.dp.toPrimitive(u32)); // 413 mod 60
    try testing.expectEqual(49, try sk.dq.toPrimitive(u32)); // 413 mod 52
    try testing.expectEqual(38, try sk.qinv.toPrimitive(u32)); // 53⁻¹ mod 61
    try testing.expectEqual(61, try sk.p.v.toPrimitive(u32));
    try testing.expectEqual(53, try sk.q.v.toPrimitive(u32));
}

test "fromPrimes rejects invalid inputs" {
    // p == q
    try testing.expectError(error.InvalidPrivateKey, SecretKey.fromPrimes(&.{61}, &.{61}, &.{17}));
    // even e / e < 3
    try testing.expectError(error.InvalidPrivateKey, SecretKey.fromPrimes(&.{61}, &.{53}, &.{16}));
    try testing.expectError(error.InvalidPrivateKey, SecretKey.fromPrimes(&.{61}, &.{53}, &.{1}));
    // gcd(e, λ) != 1: λ(61·53) = 780 = 2²·3·5·13 -> e = 13 shares a factor
    try testing.expectError(error.InvalidPrivateKey, SecretKey.fromPrimes(&.{61}, &.{53}, &.{13}));
    // even "prime"
    try testing.expectError(error.InvalidPrivateKey, SecretKey.fromPrimes(&.{62}, &.{53}, &.{17}));
}

test "rsaep/rsadp/rsadpCrt textbook KAT and round-trip" {
    const sk = try SecretKey.fromPrimes(&.{61}, &.{53}, &.{17});
    const pk = PublicKey{ .n = sk.n, .e = try Fe.fromPrimitive(u32, sk.n, 17) };

    // 65^17 mod 3233 = 2790 (0x0ae6)
    const c = try rsaep(2, .{ 0x00, 0x41 }, pk);
    try testing.expectEqualSlices(u8, &.{ 0x0a, 0xe6 }, &c);

    const m_plain = try rsadp(2, c, sk);
    const m_crt = try rsadpCrt(2, c, sk);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x41 }, &m_plain);
    try testing.expectEqualSlices(u8, &m_plain, &m_crt);

    // rsavp1/rsasp1 are the same math with the RFC's signature naming.
    const s = try rsasp1(2, .{ 0x00, 0x41 }, sk);
    const v = try rsavp1(2, s, pk);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x41 }, &v);
}

test "primitives reject representative >= n" {
    const sk = try SecretKey.fromPrimes(&.{61}, &.{53}, &.{17});
    const pk = PublicKey{ .n = sk.n, .e = try Fe.fromPrimitive(u32, sk.n, 17) };
    // n = 3233 = 0x0ca1
    try testing.expectError(error.MessageRepresentativeOutOfRange, rsaep(2, .{ 0x0c, 0xa1 }, pk));
    try testing.expectError(error.MessageRepresentativeOutOfRange, rsadp(2, .{ 0xff, 0xff }, sk));
    try testing.expectError(error.MessageRepresentativeOutOfRange, rsadpCrt(2, .{ 0x0c, 0xa1 }, sk));
}

test "fromPrimes reproduces the OpenSSL 2048-bit key exactly" {
    const sk = try kat2048.secretKey();

    var n_buf: [256]u8 = undefined;
    try sk.n.toBytes(&n_buf, .big);
    try testing.expectEqualSlices(u8, &kat2048.n, &n_buf);

    var d_buf: [256]u8 = undefined;
    try sk.d.toBytes(&d_buf, .big);
    try testing.expectEqualSlices(u8, &kat2048.d, &d_buf);

    var half_buf: [128]u8 = undefined;
    try sk.dp.toBytes(&half_buf, .big);
    try testing.expectEqualSlices(u8, &kat2048.dp, &half_buf);
    try sk.dq.toBytes(&half_buf, .big);
    try testing.expectEqualSlices(u8, &kat2048.dq, &half_buf);
    try sk.qinv.toBytes(&half_buf, .big);
    try testing.expectEqualSlices(u8, &kat2048.qinv, &half_buf);
}

test "signPkcs1v15 matches OpenSSL known answers (SHA-256/384/512)" {
    const sk = try kat2048.secretKey();
    const sha2 = std.crypto.hash.sha2;
    var out: [max_modulus_len]u8 = undefined;

    const s256 = try signPkcs1v15(sk, sha2.Sha256, kat2048.msg, &out);
    try testing.expectEqualSlices(u8, &kat2048.sig_sha256, s256);

    const s384 = try signPkcs1v15(sk, sha2.Sha384, kat2048.msg, &out);
    try testing.expectEqualSlices(u8, &kat2048.sig_sha384, s384);

    const s512 = try signPkcs1v15(sk, sha2.Sha512, kat2048.msg, &out);
    try testing.expectEqualSlices(u8, &kat2048.sig_sha512, s512);
}

test "verifyPkcs1v15 accepts the OpenSSL known answers" {
    const pk = try kat2048.publicKey();
    const sha2 = std.crypto.hash.sha2;
    try verifyPkcs1v15(pk, sha2.Sha256, kat2048.msg, &kat2048.sig_sha256);
    try verifyPkcs1v15(pk, sha2.Sha384, kat2048.msg, &kat2048.sig_sha384);
    try verifyPkcs1v15(pk, sha2.Sha512, kat2048.msg, &kat2048.sig_sha512);
}

test "verifyPkcs1v15 rejects tampering, wrong message, wrong hash, wrong length" {
    const pk = try kat2048.publicKey();
    const sha2 = std.crypto.hash.sha2;

    // Bit-flip anywhere in the signature.
    var tampered = kat2048.sig_sha256;
    tampered[0] ^= 0x01;
    try testing.expectError(error.SignatureVerificationFailed, verifyPkcs1v15(pk, sha2.Sha256, kat2048.msg, &tampered));
    tampered = kat2048.sig_sha256;
    tampered[255] ^= 0x80;
    try testing.expectError(error.SignatureVerificationFailed, verifyPkcs1v15(pk, sha2.Sha256, kat2048.msg, &tampered));

    // Wrong message.
    try testing.expectError(error.SignatureVerificationFailed, verifyPkcs1v15(pk, sha2.Sha256, "not the signed message", &kat2048.sig_sha256));

    // Wrong hash function.
    try testing.expectError(error.SignatureVerificationFailed, verifyPkcs1v15(pk, sha2.Sha384, kat2048.msg, &kat2048.sig_sha256));

    // Wrong signature length (RFC 8017 §8.2.2 step 1).
    try testing.expectError(error.SignatureVerificationFailed, verifyPkcs1v15(pk, sha2.Sha256, kat2048.msg, kat2048.sig_sha256[0..255]));
    const long_sig = kat2048.sig_sha256 ++ [_]u8{0};
    try testing.expectError(error.SignatureVerificationFailed, verifyPkcs1v15(pk, sha2.Sha256, kat2048.msg, &long_sig));
}

test "sign/verify round-trip on fresh messages, incl. SHA-1/SHA-224" {
    const sk = try kat2048.secretKey();
    const pk = try kat2048.publicKey();
    var out: [max_modulus_len]u8 = undefined;

    inline for (.{
        std.crypto.hash.Sha1,
        std.crypto.hash.sha2.Sha224,
        std.crypto.hash.sha2.Sha256,
        std.crypto.hash.sha2.Sha512,
    }) |Hash| {
        const sig = try signPkcs1v15(sk, Hash, "fresh round-trip message", &out);
        try verifyPkcs1v15(pk, Hash, "fresh round-trip message", sig);
        try testing.expectError(error.SignatureVerificationFailed, verifyPkcs1v15(pk, Hash, "some other message", sig));
    }

    var small: [64]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, signPkcs1v15(sk, std.crypto.hash.sha2.Sha256, "m", &small));
}

test "std.crypto.Certificate.rsa verifies our signature (oracle cross-check)" {
    const sk = try kat2048.secretKey();
    var out: [max_modulus_len]u8 = undefined;
    const sig = try signPkcs1v15(sk, std.crypto.hash.sha2.Sha256, kat2048.msg, &out);

    const std_rsa = std.crypto.Certificate.rsa;
    const std_pk = try std_rsa.PublicKey.fromBytes(&kat2048.e, &kat2048.n);
    try std_rsa.PKCS1v1_5Signature.verify(256, sig[0..256].*, kat2048.msg, std_pk, std.crypto.hash.sha2.Sha256);
}

test "rsadpCrt equals rsadp on the 2048-bit key" {
    const sk = try kat2048.secretKey();
    const pk = try kat2048.publicKey();

    var m: [256]u8 = undefined;
    for (&m, 0..) |*b, i| b.* = @truncate(i *% 37 +% 11);
    m[0] = 0; // keep the representative < n

    const c = try rsaep(256, m, pk);
    const via_plain = try rsadp(256, c, sk);
    const via_crt = try rsadpCrt(256, c, sk);
    try testing.expectEqualSlices(u8, &m, &via_plain);
    try testing.expectEqualSlices(u8, &via_plain, &via_crt);
}

test "512-bit key: SHA-256 round-trips, SHA-512 encoding is too short" {
    const sk = try SecretKey.fromPrimes(&kat512.p, &kat512.q, &kat512.e);
    const pk = try PublicKey.fromBytes(&kat512.n, &kat512.e);
    var out: [max_modulus_len]u8 = undefined;

    const sig = try signPkcs1v15(sk, std.crypto.hash.sha2.Sha256, "small key", &out);
    try testing.expectEqual(64, sig.len);
    try verifyPkcs1v15(pk, std.crypto.hash.sha2.Sha256, "small key", sig);

    // k = 64 < tLen(SHA-512) + 11 = 94 -> RFC 8017 §9.2 step 3.
    try testing.expectError(error.EncodedMessageTooShort, signPkcs1v15(sk, std.crypto.hash.sha2.Sha512, "small key", &out));
}

// ── P2 (OAEP) tests ──────────────────────────────────────────────────────────

// OAEP known-answer ciphertexts for the kat2048 key (see the OAEP bullet in
// the provenance note above).
const kat2048_oaep = struct {
    const msg = "zig-libs rsa: OAEP known-answer test";
    const label = "kat-label";
    // rsa_oaep_md:sha256, rsa_mgf1_md:sha256, no label.
    const ct_sha256 = hexLit("4da891fbebd835a537f462ee715d5820a3a5302a483a14bb0d34032acf0c3cf203a5c6eaad7eac42ec95822c1543f7056af1f20bafdcc505527880644b26dd6669f26d344c2e2081015db887b102248cdb83868f11a0199f5706177d5009b3e659fac64c780f18aa1f3ad349eb8779fec62d19190dc30cedf11c2c86b18787eac71613714ea5fea145ba607fa5ece466763c01603fb719a4901903a9c24c66603bcdfdee9aa3f4b25c5905507c9918dc19c556ed69edbea28d42aee4a013cfd5f55afe9633742297261afc74768e180e582c3124566854ec4394fe0228cff01d37c44163d41d16b6fe5c49a4e032d08d38aae631ac3f41ba3df5686530f7f9f9");
    // rsa_oaep_md:sha1, rsa_mgf1_md:sha1, no label.
    const ct_sha1 = hexLit("27c096515a140dae55fb4cfa72f5704be78439582a59f416ea173779fc8b60a6f2714fa012077bd693fe692552c50264191d4bd1e28ba3ae40332c1eb316dcc734558e90ff9c5537bad762b8772836a42c97a318cdcf3f4f916ce6e1363a72171e34be7821316053eb8a270ed9e47d2f90480c61a92dab549efc20af7f1b7d135bff327ba875719f762faed2cae8fdff49819ebeb0a95645ecd96078b48ae8b58128992b7870b49e5f19f72f2fb6d0dde1ebe1eaecb06f7629c6b3e18e06cc94d6251ed207736488ae1d911300aeb1a722810fece0231e4f227b12c95e1501784d6079708cc99a286672c2b67f17633f2bbf113356f87b1c72b57650ac7f7d93");
    // rsa_oaep_md:sha256, rsa_mgf1_md:sha256, rsa_oaep_label:"kat-label".
    const ct_sha256_label = hexLit("8187ffa66e94587003200c430a804fb8e1f1794411ebb97910b2ae78b54186da71b9eec18ee8f34db87c3108ba2ad6bec093066a402782d1cf3bb4247652282c69a0dbbd978df771cb983289de68106fe7d5224c156ed6d1729367785a64a781b2b9c9c3577c0ba72cd044dbcd9f715ee41f8dae60eabd6ab59d46b46a9e01edcaffc41d4a8a6c93b00cb34b125108c253c24a48c061be5687da32354a7a35074ab6382edbaa5e52dcdd2df8b1adce52d2c637d0165ccdb8fe8cbc4f0f2be64011c7fc72e66993f6d8f2bfc73dbdf953b0dfd7d9492a2a0105ec9714b67257321fe14e250da5233d23b2f015efcfd06a9667019ffc88e30776809210ab3655f6");
};

test "mgf1Xor matches Python hashlib cross-check vectors" {
    // seed = "zig-libs mgf1 seed", mask length 41 (crosses a digest boundary
    // for both hashes, exercising the counter increment).
    const seed = "zig-libs mgf1 seed";

    const want256 = comptime hexLit("35f1fc1965a11812ab455ff88faef9b68b9c3ab13edc4912b29fce6b9e5a280c6fe4e63efc05602280");
    const want1 = comptime hexLit("b9b6810cbb2db3b1679dec9c8bedbe6c60e3178372f2d2a0d670720ab424e450a5ad46abf4f57aaf6c");

    var mask256 = std.mem.zeroes([41]u8);
    mgf1Xor(std.crypto.hash.sha2.Sha256, seed, &mask256);
    try testing.expectEqualSlices(u8, &want256, &mask256);
    // XOR-in-place involution: masking twice with the same seed restores zeros.
    mgf1Xor(std.crypto.hash.sha2.Sha256, seed, &mask256);
    try testing.expectEqualSlices(u8, &std.mem.zeroes([41]u8), &mask256);

    var mask1 = std.mem.zeroes([41]u8);
    mgf1Xor(std.crypto.hash.Sha1, seed, &mask1);
    try testing.expectEqualSlices(u8, &want1, &mask1);
}

test "decryptOaep matches OpenSSL known answers (SHA-256, SHA-1, labeled)" {
    const sk = try kat2048.secretKey();
    const sha2 = std.crypto.hash.sha2;
    var out: [max_modulus_len]u8 = undefined;

    const m256 = try decryptOaep(sk, sha2.Sha256, &kat2048_oaep.ct_sha256, "", &out);
    try testing.expectEqualStrings(kat2048_oaep.msg, m256);

    const m1 = try decryptOaep(sk, std.crypto.hash.Sha1, &kat2048_oaep.ct_sha1, "", &out);
    try testing.expectEqualStrings(kat2048_oaep.msg, m1);

    const mlab = try decryptOaep(sk, sha2.Sha256, &kat2048_oaep.ct_sha256_label, kat2048_oaep.label, &out);
    try testing.expectEqualStrings(kat2048_oaep.msg, mlab);
}

test "encryptOaep/decryptOaep round-trip (hashes x labels x message lengths)" {
    const sk = try kat2048.secretKey();
    const pk = try kat2048.publicKey();
    // Deterministic PRNG is fine for tests (production callers must supply a
    // CSPRNG — see the encryptOaep doc comment).
    var prng = std.Random.DefaultPrng.init(0x6f6165705f726e67);
    const random = prng.random();
    var ct: [max_modulus_len]u8 = undefined;
    var pt: [max_modulus_len]u8 = undefined;

    var big_msg: [214]u8 = undefined; // 214 = max mLen for k=256 with SHA-1
    random.bytes(&big_msg);

    inline for (.{ std.crypto.hash.Sha1, std.crypto.hash.sha2.Sha256 }) |Hash| {
        const max_len = 256 - 2 * Hash.digest_length - 2;
        inline for (.{ "", "a label" }) |label| {
            for ([_]usize{ 0, 1, 17, max_len }) |msg_len| {
                const msg = big_msg[0..msg_len];
                const c = try encryptOaep(pk, Hash, random, msg, label, &ct);
                try testing.expectEqual(256, c.len);
                const m = try decryptOaep(sk, Hash, c, label, &pt);
                try testing.expectEqualSlices(u8, msg, m);
            }
        }
    }

    // OAEP is randomized: the same message never encrypts to the same
    // ciphertext twice (fresh seed each call).
    var ct2: [max_modulus_len]u8 = undefined;
    const c1 = try encryptOaep(pk, std.crypto.hash.sha2.Sha256, random, "same message", "", &ct);
    const c2 = try encryptOaep(pk, std.crypto.hash.sha2.Sha256, random, "same message", "", &ct2);
    try testing.expect(!std.mem.eql(u8, c1, c2));
}

test "decryptOaep rejects corruption, wrong label/hash, wrong length (one generic error)" {
    const sk = try kat2048.secretKey();
    const Sha256 = std.crypto.hash.sha2.Sha256;
    var out: [max_modulus_len]u8 = undefined;

    // Bit-flip anywhere in the ciphertext.
    var bad = kat2048_oaep.ct_sha256;
    bad[0] ^= 0x01;
    try testing.expectError(error.DecryptionError, decryptOaep(sk, Sha256, &bad, "", &out));
    bad = kat2048_oaep.ct_sha256;
    bad[255] ^= 0x80;
    try testing.expectError(error.DecryptionError, decryptOaep(sk, Sha256, &bad, "", &out));

    // Label mismatch in both directions — while the same ciphertexts decrypt
    // fine under the correct label (previous test).
    try testing.expectError(error.DecryptionError, decryptOaep(sk, Sha256, &kat2048_oaep.ct_sha256, kat2048_oaep.label, &out));
    try testing.expectError(error.DecryptionError, decryptOaep(sk, Sha256, &kat2048_oaep.ct_sha256_label, "", &out));

    // Wrong hash function.
    try testing.expectError(error.DecryptionError, decryptOaep(sk, Sha256, &kat2048_oaep.ct_sha1, "", &out));

    // Wrong ciphertext length (RFC 8017 §7.1.2 step 1.b).
    try testing.expectError(error.DecryptionError, decryptOaep(sk, Sha256, kat2048_oaep.ct_sha256[0..255], "", &out));
    const long_ct = kat2048_oaep.ct_sha256 ++ [_]u8{0};
    try testing.expectError(error.DecryptionError, decryptOaep(sk, Sha256, &long_ct, "", &out));

    // Undersized output buffer (public-length check, distinct error is fine).
    var small: [189]u8 = undefined; // max mLen for k=256/SHA-256 is 190
    try testing.expectError(error.BufferTooSmall, decryptOaep(sk, Sha256, &kat2048_oaep.ct_sha256, "", &small));
}

test "decryptOaep rejects EM with nonzero leading byte (Y != 0x00)" {
    const sk = try kat2048.secretKey();
    const pk = try kat2048.publicKey();
    const Sha256 = std.crypto.hash.sha2.Sha256;

    // Hand-build an otherwise perfectly valid EM but with Y = 0x01 (still
    // < n, since n's top byte is 0xa2) and run it through the raw RSAEP
    // primitive — only the Y check can catch it.
    var em: [256]u8 = undefined;
    em[0] = 0x01;
    const seed = em[1..33];
    const db = em[33..256];
    Sha256.hash("", db[0..32], .{});
    @memset(db[32 .. db.len - 4], 0x00);
    db[db.len - 4] = 0x01;
    @memcpy(db[db.len - 3 ..], "msg");
    var prng = std.Random.DefaultPrng.init(42);
    prng.random().bytes(seed);
    mgf1Xor(Sha256, seed, db);
    mgf1Xor(Sha256, db, seed);

    var out: [max_modulus_len]u8 = undefined;
    const ct_bad_y = try rsaep(256, em, pk);
    try testing.expectError(error.DecryptionError, decryptOaep(sk, Sha256, &ct_bad_y, "", &out));

    // Control: the identical EM with Y = 0x00 decrypts — proving the
    // rejection above was the Y check and nothing else.
    em[0] = 0x00;
    const ct_ok = try rsaep(256, em, pk);
    try testing.expectEqualStrings("msg", try decryptOaep(sk, Sha256, &ct_ok, "", &out));
}

test "encryptOaep rejects oversize messages and undersized buffers/keys" {
    const pk = try kat2048.publicKey();
    const Sha256 = std.crypto.hash.sha2.Sha256;
    var prng = std.Random.DefaultPrng.init(1);
    const random = prng.random();
    var ct: [max_modulus_len]u8 = undefined;

    // Max mLen for k=256/SHA-256 is 190: 191 is rejected, 190 encrypts.
    const big = [_]u8{0xaa} ** 191;
    try testing.expectError(error.MessageTooLong, encryptOaep(pk, Sha256, random, &big, "", &ct));
    _ = try encryptOaep(pk, Sha256, random, big[0..190], "", &ct);

    // Output buffer shorter than the modulus.
    var small_out: [255]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, encryptOaep(pk, Sha256, random, "m", "", &small_out));

    // 512-bit key: k = 64 < 2*32 + 2 = 66 -> SHA-256 OAEP can never fit.
    const pk512 = try PublicKey.fromBytes(&kat512.n, &kat512.e);
    try testing.expectError(error.MessageTooLong, encryptOaep(pk512, Sha256, random, "", "", &ct));

    // SHA-1 on the 512-bit key fits up to 64 - 2*20 - 2 = 22 bytes.
    const sk512 = try SecretKey.fromPrimes(&kat512.p, &kat512.q, &kat512.e);
    var pt: [max_modulus_len]u8 = undefined;
    const c = try encryptOaep(pk512, std.crypto.hash.Sha1, random, "22-byte msg for sha1..", "", &ct);
    try testing.expectEqual(64, c.len);
    try testing.expectEqualStrings("22-byte msg for sha1..", try decryptOaep(sk512, std.crypto.hash.Sha1, c, "", &pt));
    try testing.expectError(error.MessageTooLong, encryptOaep(pk512, std.crypto.hash.Sha1, random, "23-byte msg for sha-1..", "", &ct));
}

test "PublicKey.fromBytes accepts/rejects per RFC 8017 §3.1 sanity rules" {
    // Leading zeros tolerated on both components.
    const padded_n = [_]u8{ 0, 0, 0 } ++ kat2048.n;
    const padded_e = [_]u8{0} ++ kat2048.e;
    const pk = try PublicKey.fromBytes(&padded_n, &padded_e);
    try testing.expectEqual(2048, pk.n.bits());
    try testing.expectEqual(65537, try pk.e.toPrimitive(u32));

    // Even exponent.
    try testing.expectError(error.InvalidPublicKey, PublicKey.fromBytes(&kat2048.n, &.{0x10}));
    // e < 3.
    try testing.expectError(error.InvalidPublicKey, PublicKey.fromBytes(&kat2048.n, &.{0x01}));
    // Exponent wider than 32 bits (DoS guard).
    try testing.expectError(error.InvalidPublicKey, PublicKey.fromBytes(&kat2048.n, &.{ 0x01, 0x00, 0x00, 0x00, 0x01 }));
    // Even modulus.
    var even_n = kat2048.n;
    even_n[255] &= 0xfe;
    try testing.expectError(error.InvalidPublicKey, PublicKey.fromBytes(&even_n, &kat2048.e));
    // Modulus below the 512-bit floor.
    const tiny_n = [_]u8{0xff} ** 32;
    try testing.expectError(error.InvalidPublicKey, PublicKey.fromBytes(&tiny_n, &kat2048.e));
    // Modulus above max_modulus_bits.
    const huge_n = [_]u8{0xff} ** (max_modulus_len + 1);
    try testing.expectError(error.InvalidPublicKey, PublicKey.fromBytes(&huge_n, &kat2048.e));
}

// ── P3 (PSS) tests ───────────────────────────────────────────────────────────

// PSS known-answer signatures for the kat2048 key (see the PSS bullet in the
// provenance note above).
const kat2048_pss = struct {
    const msg = "zig-libs rsa: PSS known-answer test";
    // -sha256 -sigopt rsa_pss_saltlen:32 (randomized -> verify-only KAT).
    const sig_sha256_s32 = hexLit("21de593a077463eae5e5bf33955fc9603bac17cb9f6fdf978152a2dec9d0a5ac832947fc0eb466b6661ecd00a9a36e49bb1842037a889601863fa3280a30dd00367b93f63b8e6137e29d07689881036dc6bef12b76ac8738299f91423aa102835370954ae61a91e161c10c32bff3e22f1f6c8f95bc2ee3f2f0ab916a2382cab91c585360ed0ec1350e85dcc3328ad79a189210a714669b7a4a0a33da28c5bc72156880516fde01db01f6925781d7df01d8aa20ca1c32ebc036f2af5dacdacd0a04dc5a911dcf45d382e4d80af85834d0f33611721341e9f0713d0f6bcce6a192c960831cb9ac218db7a12383b6b26239d1d5383f00b8cf76b4a2a2bdcfe3538f");
    // -sha256 -sigopt rsa_pss_saltlen:0 (deterministic -> byte-exact sign KAT).
    const sig_sha256_s0 = hexLit("0232ff64e3172b8d9a4953f97f6a415054574f6f18e4a2690c3703662fda3ded6fc3ea916fdae81af5ad1b2b2873ff5684a15d0b101736f3f2ca95d0334aaf840ce8ea0225302f7e53747c93cfa3080d8895e21cc66f16cd7d2248ef5495364ce68913c164d0f1e9ca14d8bc9fa30bf7af6e7d5a34d60e64bbf5d22258d781458982cb48c6304d3d861c699f9268fcb8ba3a36489fd68b174b21cd831427e6ad8bb80bebd4b691be935db60f8ff1b24922b133a670d72e882697bf8e9582092498009fe5f348cd607cb0ace3ad36c346b366e441801aefa4bd13162625e99afed10fe6b0f07c77b2fe0db84bc9a7fe75fdbe877a638c33c949ca784d48183349");
    // -sha512 -sigopt rsa_pss_saltlen:20 (randomized -> verify-only KAT).
    const sig_sha512_s20 = hexLit("2010462129b3ebafdb3b2db227062c359bf78068229def1553477a12865b2f21293ed68434cefcfd48a1e506384f641a4e987bffab742044e208ea448d5cd5f212f875ba506f70d1c7737f4e50f4732884a2b6d35db38d0081f8887bf89ed7561134fb6e8f73292e435c1d93e21bbbee55dd7f3a22d099304e95e48520c562cb8c91eb889695618c2a795638d089cef37e9807cf229aa2d3696ad152e15857837add16114b3c922fb5e38f4af0321a7ba3ca406091a9308be84b68b25c5c096dd3096b7d545fce118eec4b9e99070ca52d2e0d7a94d6a75d762cdd28650c5be567a53cbc509e00720a32d43f02312253d4d9bbad722c4fa99a4bf3be79a84fac");
};

test "verifyPss accepts the OpenSSL known answers" {
    const pk = try kat2048.publicKey();
    const sha2 = std.crypto.hash.sha2;
    try verifyPss(pk, sha2.Sha256, kat2048_pss.msg, &kat2048_pss.sig_sha256_s32, 32);
    try verifyPss(pk, sha2.Sha256, kat2048_pss.msg, &kat2048_pss.sig_sha256_s0, 0);
    try verifyPss(pk, sha2.Sha512, kat2048_pss.msg, &kat2048_pss.sig_sha512_s20, 20);
}

test "signPss with salt_len = 0 matches the deterministic OpenSSL answer" {
    const sk = try kat2048.secretKey();
    // sLen = 0 -> the signature is fully deterministic; the byte-exact match
    // against OpenSSL's answer proves the PRNG below is never material.
    var prng = std.Random.DefaultPrng.init(0);
    var out: [max_modulus_len]u8 = undefined;
    const sig = try signPss(sk, std.crypto.hash.sha2.Sha256, prng.random(), kat2048_pss.msg, 0, &out);
    try testing.expectEqualSlices(u8, &kat2048_pss.sig_sha256_s0, sig);
}

test "signPss/verifyPss round-trip (hashes x salt lengths), 2048-bit key" {
    const sk = try kat2048.secretKey();
    const pk = try kat2048.publicKey();
    var prng = std.Random.DefaultPrng.init(0x7073735f726e6421);
    const random = prng.random();
    var out: [max_modulus_len]u8 = undefined;

    inline for (.{
        std.crypto.hash.sha2.Sha256,
        std.crypto.hash.sha2.Sha384,
        std.crypto.hash.sha2.Sha512,
    }) |Hash| {
        for ([_]usize{ 0, Hash.digest_length, 20 }) |s_len| {
            const sig = try signPss(sk, Hash, random, "fresh PSS round-trip message", s_len, &out);
            try testing.expectEqual(256, sig.len);
            try verifyPss(pk, Hash, "fresh PSS round-trip message", sig, s_len);
            try testing.expectError(error.SignatureVerificationFailed, verifyPss(pk, Hash, "some other message", sig, s_len));
        }
    }

    // PSS with sLen > 0 is randomized: two signatures over the same message
    // differ (fresh salt each call) yet both verify.
    var out2: [max_modulus_len]u8 = undefined;
    const s1 = try signPss(sk, std.crypto.hash.sha2.Sha256, random, "same message", 32, &out);
    const s2 = try signPss(sk, std.crypto.hash.sha2.Sha256, random, "same message", 32, &out2);
    try testing.expect(!std.mem.eql(u8, s1, s2));
    try verifyPss(pk, std.crypto.hash.sha2.Sha256, "same message", s1, 32);
    try verifyPss(pk, std.crypto.hash.sha2.Sha256, "same message", s2, 32);
}

test "signPss/verifyPss round-trip on the 512-bit key (top-bit clearing path)" {
    // modBits = 512 -> emBits = 511: emLen == k and exactly one leading bit
    // of maskedDB is cleared/checked, exercising §9.1.1 step 11 / §9.1.2
    // step 6 with a nontrivial mask.
    const sk = try SecretKey.fromPrimes(&kat512.p, &kat512.q, &kat512.e);
    const pk = try PublicKey.fromBytes(&kat512.n, &kat512.e);
    var prng = std.Random.DefaultPrng.init(0x353132626974);
    const random = prng.random();
    var out: [max_modulus_len]u8 = undefined;

    // Max sLen for k=64/SHA-256: emLen - hLen - 2 = 64 - 32 - 2 = 30.
    for ([_]usize{ 0, 20, 30 }) |s_len| {
        const sig = try signPss(sk, std.crypto.hash.sha2.Sha256, random, "small key", s_len, &out);
        try testing.expectEqual(64, sig.len);
        try verifyPss(pk, std.crypto.hash.sha2.Sha256, "small key", sig, s_len);
    }

    // sLen = 31 exceeds the §9.1.1 step 3 bound.
    try testing.expectError(error.EncodedMessageTooShort, signPss(sk, std.crypto.hash.sha2.Sha256, random, "small key", 31, &out));
    // SHA-512 cannot fit at all: emLen = 64 < hLen + 2 = 66.
    try testing.expectError(error.EncodedMessageTooShort, signPss(sk, std.crypto.hash.sha2.Sha512, random, "small key", 0, &out));
}

test "verifyPss rejects tampering, wrong message/hash/salt_len/length" {
    const pk = try kat2048.publicKey();
    const sha2 = std.crypto.hash.sha2;

    // Bit-flip anywhere in the signature.
    var tampered = kat2048_pss.sig_sha256_s32;
    tampered[0] ^= 0x01;
    try testing.expectError(error.SignatureVerificationFailed, verifyPss(pk, sha2.Sha256, kat2048_pss.msg, &tampered, 32));
    tampered = kat2048_pss.sig_sha256_s32;
    tampered[255] ^= 0x80;
    try testing.expectError(error.SignatureVerificationFailed, verifyPss(pk, sha2.Sha256, kat2048_pss.msg, &tampered, 32));

    // Wrong message.
    try testing.expectError(error.SignatureVerificationFailed, verifyPss(pk, sha2.Sha256, "not the signed message", &kat2048_pss.sig_sha256_s32, 32));

    // Wrong hash function.
    try testing.expectError(error.SignatureVerificationFailed, verifyPss(pk, sha2.Sha384, kat2048_pss.msg, &kat2048_pss.sig_sha256_s32, 32));

    // Wrong salt_len at verify (both directions).
    try testing.expectError(error.SignatureVerificationFailed, verifyPss(pk, sha2.Sha256, kat2048_pss.msg, &kat2048_pss.sig_sha256_s32, 20));
    try testing.expectError(error.SignatureVerificationFailed, verifyPss(pk, sha2.Sha256, kat2048_pss.msg, &kat2048_pss.sig_sha256_s0, 32));

    // Wrong signature length (RFC 8017 §8.1.2 step 1).
    try testing.expectError(error.SignatureVerificationFailed, verifyPss(pk, sha2.Sha256, kat2048_pss.msg, kat2048_pss.sig_sha256_s32[0..255], 32));
    const long_sig = kat2048_pss.sig_sha256_s32 ++ [_]u8{0};
    try testing.expectError(error.SignatureVerificationFailed, verifyPss(pk, sha2.Sha256, kat2048_pss.msg, &long_sig, 32));

    // salt_len over the §9.1.2 step 3 bound (emLen - hLen - 2 = 222).
    try testing.expectError(error.SignatureVerificationFailed, verifyPss(pk, sha2.Sha256, kat2048_pss.msg, &kat2048_pss.sig_sha256_s32, 223));
}

test "verifyPss rejects a wrong trailer byte and nonzero top bits" {
    const sk = try kat2048.secretKey();
    const pk = try kat2048.publicKey();
    const Sha256 = std.crypto.hash.sha2.Sha256;
    const msg = "trailer/top-bit negative test";

    // Hand-build a fully valid EM (emBits = 2047, emLen = 256), then break
    // exactly one property per case and push it through the raw RSASP1
    // primitive — only the targeted check can catch it. The salt is searched
    // so that em[0] | 0x80 stays below n's top byte (0xa2): the top-bit
    // corruption below must keep the representative < n, or RSASP1's range
    // check would reject it before verifyPss ever sees it.
    var salt = [_]u8{0} ** 32;
    var em: [256]u8 = undefined;
    var found = false;
    var s: usize = 0;
    while (s < 256) : (s += 1) {
        @memset(&salt, @intCast(s));
        try emsaPssEncode(Sha256, msg, &salt, 2047, &em);
        if (em[0] < 0x22) {
            found = true;
            break;
        }
    }
    try testing.expect(found);

    // Control: the untouched EM signs and verifies — proving the rejections
    // below are the trailer/top-bit checks and nothing else.
    const sig_ok = try rsasp1(256, em, sk);
    try verifyPss(pk, Sha256, msg, &sig_ok, 32);

    // Trailer != 0xbc (§9.1.2 step 4).
    var em_bad = em;
    em_bad[255] = 0xcc;
    const sig_bad_trailer = try rsasp1(256, em_bad, sk);
    try testing.expectError(error.SignatureVerificationFailed, verifyPss(pk, Sha256, msg, &sig_bad_trailer, 32));

    // Nonzero leftmost bit of maskedDB (§9.1.2 step 6). Still < n (n's top
    // byte is 0xa2), so only the top-bit check can reject it.
    em_bad = em;
    em_bad[0] |= 0x80;
    const sig_bad_top = try rsasp1(256, em_bad, sk);
    try testing.expectError(error.SignatureVerificationFailed, verifyPss(pk, Sha256, msg, &sig_bad_top, 32));
}

test "signPss rejects an undersized output buffer" {
    const sk = try kat2048.secretKey();
    var prng = std.Random.DefaultPrng.init(7);
    var small: [255]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, signPss(sk, std.crypto.hash.sha2.Sha256, prng.random(), "m", 32, &small));
}
