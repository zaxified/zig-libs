// SPDX-License-Identifier: MIT
//! rsa — pure-Zig RSA (PKCS#1 v2.2 / RFC 8017), built on `std.crypto.ff`.
//!
//! **ALL PHASES (P1–P6) IMPLEMENTED.** The RFC 8017 §5
//! primitives (RSAEP/RSADP/RSASP1/RSAVP1, incl. the CRT fast path),
//! `PublicKey.fromBytes`, `SecretKey.fromPrimes`, the RSASSA-PKCS1-v1_5
//! scheme (`signPkcs1v15`/`verifyPkcs1v15`, SHA-1/224/256/384/512), the
//! RSAES-OAEP scheme (`encryptOaep`/`decryptOaep`, MGF1, constant-time
//! decode — plus `encryptOaepH`/`decryptOaepH`, a decoupled-hash variant whose
//! label/digest hash and MGF1 hash may differ per RFC 8017 §7.1, e.g. XML-Enc
//! `rsa-oaep` with digest=SHA-256, MGF1=SHA-1; the coupled forms delegate to it
//! with both hashes equal), the RSASSA-PSS scheme (`signPss`/`verifyPss`, branch-clean
//! verify), DER/PEM key parsing (`PublicKey.fromDer`/`fromPem`,
//! `SecretKey.fromDer`/`fromPkcs8`/`fromPem`, cleartext PEM only), OpenSSH
//! `PROTOCOL.key` private-key parsing (`fromOpenSSH`: unencrypted and
//! bcrypt/aes256-ctr/aes256-cbc encrypted, with a from-scratch Blowfish +
//! bcrypt-pbkdf in `openssh.zig`), keypair
//! generation (`generate`: probable primes via sieve + Miller-Rabin,
//! FIPS 186-5-style constraints), and X.509 v3 self-signed certificate
//! generation (`selfSignedCert`, RFC 5280) are real and tested against
//! OpenSSL/ssh-keygen-generated known-answer vectors and (for
//! `selfSignedCert`, `generate`, and the bcrypt-pbkdf) against
//! `std.crypto.Certificate` / `std.crypto.pwhash.bcrypt.opensshKdf` as
//! independent oracles.
//! Phase plan:
//!   P1  — EMSA-PKCS1-v1_5 sign/verify (`signPkcs1v15`/`verifyPkcs1v15`) — DONE.
//!   P2  — RSAES-OAEP encrypt/decrypt (`encryptOaep`/`decryptOaep`; decoupled
//!         label/MGF1 hash via `encryptOaepH`/`decryptOaepH`) — DONE.
//!   P3  — RSASSA-PSS sign/verify (`signPss`/`verifyPss`) — DONE.
//!   P4a — DER/PEM key parsing (PKCS#1/PKCS#8/SPKI, cleartext only) — DONE.
//!   P4b — OpenSSH `PROTOCOL.key` parsing incl. bcrypt-pbkdf (`fromOpenSSH`) — DONE.
//!   P5  — keypair generation (`generate`) — DONE.
//!   P6  — self-signed certificate generation (`selfSignedCert`) — DONE.
//!
//! The `std.crypto.ff` (`Uint`/`Modulus`/`Fe`) types remain the canonical
//! big-integer carrier for every RSA value (modulus components, exponents,
//! message/signature representatives) and provide the constant-time finite-
//! field shape Zig std's own internal RSA verifier
//! (`std.crypto.Certificate.rsa`, not public) is built on. This module exposes
//! a clean, PUBLIC, sign-capable superset of that shape (std's internal `rsa`
//! only verifies; it has no `SecretKey`/CRT/signing support at all).
//!
//! Speed: the modular-exponentiation HOT PATH (the CRT private op mod p / mod q,
//! the non-CRT private op mod n, and the public op mod n) is routed through the
//! sibling `montint` module — a full-radix-2^64, Montgomery-resident,
//! constant-time modexp that is ~3× faster than `std.crypto.ff` on the portable
//! path (the deep audit measured `ff` at ~29× OpenSSL for the CRT sign; see
//! `~/CML/audit/modules/rsa.md`). `ff` is retained for key derivation, the CRT
//! recombination arithmetic (Garner), reductions, and all serialization; only
//! the exponentiation primitive moved. The `montint` moduli + Montgomery
//! constants are precomputed ONCE per key at construction and carried on the
//! key (`MontParams`), so no per-operation setup cost is paid.
//!
//! SECURITY (audit F2/F3, see `~/CML/audit/modules/rsa.md`): the CRT private op
//! (`privateOpCrt`) now carries both fault- and side-channel countermeasures.
//! F3 (Bellcore/BDL): every CRT private op re-encrypts the recovered `m` and
//! checks `m^e ≡ c (mod n)`, returning `error.FaultDetected` on mismatch rather
//! than a faulty value an attacker could use to factor `n`. F2 (base blinding):
//! with a `Blinding.csprng` the op runs on `c·r^e mod n` for a fresh random
//! unit `r` and unblinds by `r⁻¹ mod n`, masking any residual
//! (compiler-defeated) timing/power signal on the secret exponent. Both add
//! roughly one extra public-modexp (plus, when blinding, an inverse) per
//! private op — the expected cost.
//!
//! `signPss` blinds always (it holds a CSPRNG for the salt anyway). The
//! deterministic entry points — `signPkcs1v15`, `decryptOaep`/`decryptOaepH`,
//! `rsadpCrt` — default to `Blinding.none`, since std 0.16 removed
//! `std.crypto.random` and they take no generator; each has a `…Blinded` twin
//! that accepts one, so a consumer running an OAEP decryption oracle on
//! attacker-chosen ciphertext can turn masking on without editing this module
//! (B6 seam audit, 2026-08-12). The F3 check runs on every path regardless.
//! See `Blinding` for the full argument.
//!
//! Provenance: clean-room implementation from RFC 8017 (PKCS#1 v2.2); design
//! reference = Zig std's internal `std.crypto.Certificate.rsa` (MIT) for the
//! `Modulus`/`Fe`/`PublicKey` shape and the RSAEP/RSAVP1 primitive — shape
//! only, no source copied (std's `rsa` struct is not `pub`, so nothing here is
//! a re-export of it). See README.md "Provenance" for the full statement and
//! `NOTICE` for the design-reference entry.

const std = @import("std");

/// Fast constant-time Montgomery modexp backend for the RSA hot path
/// (private CRT op, non-CRT private op, public op). See `montint`'s SPEC.md.
const montint = @import("montint");

/// Blowfish + OpenBSD bcrypt_pbkdf (P4b support primitives), re-exported
/// for callers that need the KDF stand-alone.
pub const openssh = @import("openssh.zig");

pub const meta = .{
    // NOTE: CONVENTIONS.md's `meta` tag vocabulary (platform/role/concurrency/
    // model_after/deps) has no dedicated "status" tag; module maturity lives
    // in each SPEC.md's closing "Status" line instead, using the catalog's
    // `extract` (built) / `gap` (not yet built) vocabulary. All phases P1-P6
    // have landed, so SPEC.md's Status line uses `extract`.
    .platform = .any,
    .role = .util, // pure computation (no I/O, no wire framing of its own) -> util, not .codec
    .concurrency = .reentrant, // no shared/global state; PublicKey/SecretKey are plain value types
    .model_after = "RFC 8017 (PKCS#1 v2.2); std.crypto internal RSA (Certificate/rsa)",
    .deps = .{"montint"}, // std.crypto.ff carrier + montint modexp hot path
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

// ── montint modexp backend (the hot-path arithmetic) ────────────────────────
//
// `montint.Modint(bits)` fixes its limb count `L` at comptime, whereas an RSA
// key's size is only known at runtime (512…4096-bit moduli, and CRT operates on
// the ~half-width primes). We bridge the two with a runtime-dispatched set of
// comptime `Modint` instantiations, keyed on the operand's limb count rounded
// up to a multiple of `mont_step`. Rounding keeps the number of monomorphized
// modexp instantiations small (16) while the common RSA sizes (2048/3072/4096
// moduli, their 1024/1536/2048-bit primes) land on an exact multiple-of-4 limb
// count with ZERO padding — a 2048-bit CRT sign runs mod-p at L=16, exactly the
// Montgomery-resident portable win the audit targeted (L=16 < montint's
// `asm_min_limbs`=32, so it takes the portable CIOS path). Padding, when it
// happens (a non-round modulus width), only adds leading zero limbs, which
// `montint` handles and which stays correct — just slightly slower.

const mont_step: usize = 4;
const mont_min_limbs: usize = 4;
const mont_max_limbs: usize = (max_modulus_bits + 63) / 64; // 64

/// A modulus plus its precomputed Montgomery constants, stored in a max-width
/// (`mont_max_limbs`) buffer with only the low `L` limbs live. Computed ONCE
/// per key (at construction) so no per-operation Montgomery setup is paid — the
/// `Modint` view is reconstructed field-by-field at op time, skipping the
/// (relatively expensive) `computeConstants` doubling loop.
const MontParams = struct {
    /// Live limb count (a multiple of `mont_step`, in `[mont_min_limbs,
    /// mont_max_limbs]`); selects the comptime `Modint` at op time.
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
/// multiple of `mont_step` that is ≥ `L` and ≥ `mont_min_limbs`. `L ≤
/// mont_max_limbs` always (a value ≤ `max_modulus_bits` wide), so the result is
/// in the instantiated set `{4, 8, …, 64}`.
fn montSlot(l: usize) usize {
    var s: usize = mont_min_limbs;
    while (s < l) s += mont_step;
    return s;
}

/// Load a big-endian byte string into an `L`-limb little-endian value with NO
/// value-dependent branch (the only branch is on the PUBLIC bit position vs the
/// limb count) — so it is safe to use on the secret exponent. The caller
/// guarantees the value fits in `slot` limbs (RSA operands always do: a
/// reduced base is `< m`, and every exponent here is `< m`).
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
    var be: [max_modulus_len]u8 = undefined;
    mod.toBytes(&be, .big) catch unreachable; // 512-byte buffer never overflows
    const slot = montSlot((mod.bits() + 63) / 64);
    var mp: MontParams = .{ .L = slot };
    comptime var s: usize = mont_min_limbs;
    inline while (s <= mont_max_limbs) : (s += mont_step) {
        if (s == slot) {
            const M = montint.Modint(s * 64);
            // NB: build via `fromElem` from a branchless-loaded limb array
            // rather than montint's `fromBytesBE` — that loader skips zero
            // bytes, so its work depends on the input's byte VALUES (montint
            // SPEC.md § "Constant-time contract" states this as an explicit
            // exclusion). This function is called on the SECRET CRT primes
            // `p` and `q`, not only on the public `n`, so the branchless load
            // is load-bearing here and not a style preference.
            //
            // (The older reason given here — that the loaders were "currently
            // broken", referencing a `Self.Error` that `Modint` did not
            // expose — has been stale since before 2026-07-21: the alias is
            // present, pinned by montint's own regression test, and routing
            // this call through `M.fromBytesBE` compiles and leaves all 76
            // `test-rsa` tests green. Verified 2026-08-13, then reverted.)
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

/// Reconstruct the comptime `Modint` view for slot `s` from precomputed params
/// (no `computeConstants` — just copies the stored constants into the fields).
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
/// slice. This is the analogue of `ff.Modulus.pow` (secret path) — used for the
/// private CRT halves (`c^dP mod p`, `c^dQ mod q`) and the non-CRT `c^d mod n`.
fn montPowSecret(mp: *const MontParams, base_be: []const u8, exp_be: []const u8, out_buf: *[max_modulus_len]u8) []const u8 {
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

/// Variable-time modexp `base^e mod m` for a PUBLIC exponent (RSA verify /
/// encrypt) — a left-to-right square-and-multiply over `e`'s actual bit length,
/// so the tiny public exponent (typically 65537) costs ~17 squarings + 2
/// multiplies rather than the full-width `L·64` squarings a constant-time
/// modexp would spend. Variable-time is fine: `e` is public. Uses montint's
/// fast Montgomery multiply throughout. `base_be` is big-endian, `< m`.
fn montPowPublic(mp: *const MontParams, base_be: []const u8, e_be: []const u8, out_buf: *[max_modulus_len]u8) []const u8 {
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

/// Copy a montint big-endian result (`res`, a Montgomery slot-width byte
/// string) into an `out` buffer of caller-chosen width, big-endian-aligned.
/// The value is always `< n`, so it fits in either direction:
///   - `res.len >= out.len` (narrow): the leading `res.len − out.len` bytes of
///     `res` are provably zero (the montint slot is ≥ the modulus byte length),
///     so drop them and keep the low `out.len` bytes.
///   - `out.len > res.len` (widen): the caller requested a fixed max-width
///     output (e.g. blindrsa's `max_modulus_len` path) larger than this key's
///     slot. Right-align `res` in `out` and zero the leading `out.len − res.len`
///     high bytes — a smaller big-endian value in a wider fixed-width field is
///     just left-zero-padded (most-significant zeros on the left).
fn writeMontResult(out: []u8, res: []const u8) void {
    if (res.len >= out.len) {
        @memcpy(out, res[res.len - out.len ..]);
    } else {
        const pad = out.len - res.len;
        @memset(out[0..pad], 0);
        @memcpy(out[pad..], res);
    }
}

/// RSA public key: modulus `n` and public exponent `e` (RFC 8017 §3.1).
pub const PublicKey = struct {
    n: Modulus,
    e: Fe,
    /// Precomputed montint modulus + Montgomery constants for `n` (public op).
    n_mont: MontParams,

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

        return .{ .n = n, .e = e, .n_mont = montParamsFromModulus(n) };
    }

    pub const FromDerError = error{InvalidDer};

    /// Parse a public key from a DER-encoded `RSAPublicKey` (PKCS#1 Appendix
    /// A.1.1) or an X.509 `SubjectPublicKeyInfo` wrapping one.
    pub fn fromDer(bytes: []const u8) FromDerError!PublicKey {
        return publicKeyFromDerImpl(bytes) catch error.InvalidDer;
    }

    /// Parse a public key from a PEM text block: `PUBLIC KEY` (X.509
    /// `SubjectPublicKeyInfo`) or `RSA PUBLIC KEY` (bare PKCS#1
    /// `RSAPublicKey`). The first matching block in `text` is used; other
    /// labels (including OpenSSH `authorized_keys`-style or unrecognized
    /// blocks) are rejected with `error.UnsupportedPemLabel`.
    pub fn fromPem(text: []const u8) PemError!PublicKey {
        const block = try pemDecodeBody(text);
        if (!std.mem.eql(u8, block.label, "PUBLIC KEY") and
            !std.mem.eql(u8, block.label, "RSA PUBLIC KEY"))
        {
            return error.UnsupportedPemLabel;
        }
        return try PublicKey.fromDer(block.der());
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
    /// Public exponent e (kept so the private CRT op can re-encrypt `m^e mod n`
    /// for the Bellcore/BDL fault check — audit F3). Public value, carried as
    /// an `Fe` of `n` for symmetry with `PublicKey.e`.
    e: Fe,
    /// Precomputed montint constants for `n` (non-CRT private op `c^d mod n`).
    n_mont: MontParams,
    /// Precomputed montint constants for `p` (CRT half `c^dP mod p`).
    p_mont: MontParams,
    /// Precomputed montint constants for `q` (CRT half `c^dQ mod q`).
    q_mont: MontParams,

    /// Securely wipe all key material. Every field is fixed-size plain data
    /// (ff `Fe`/`Modulus` limbs + `MontParams` arrays, no heap), so zeroing the
    /// struct's bytes erases the secret exponents/primes (`d,p,q,dp,dq,qinv`
    /// and the p/q Montgomery constants). Call when the key is no longer needed;
    /// the struct is left zeroed and must not be reused.
    pub fn deinit(sk: *SecretKey) void {
        std.crypto.secureZero(u8, std.mem.asBytes(sk));
    }

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

    pub const FromDerError = error{ InvalidDer, InvalidPrivateKey };

    /// Parse a private key from a DER-encoded bare PKCS#1 `RSAPrivateKey`
    /// (RFC 8017 Appendix A.1.2) — the format `openssl rsa -traditional`
    /// writes (as opposed to `fromPkcs8`'s `PrivateKeyInfo` wrapper). Only
    /// the two-prime form (version 0) is supported; multi-prime keys
    /// (version 1, `otherPrimeInfos`) are rejected. `p`/`q`/`e` are extracted
    /// and routed through `fromPrimes`, which re-derives `n`/`d`/the CRT
    /// parameters itself rather than trusting the on-disk ones (see
    /// `fromPrimes`'s doc comment).
    pub fn fromDer(bytes: []const u8) FromDerError!SecretKey {
        return secretKeyFromPkcs1Impl(bytes) catch |err| switch (err) {
            error.InvalidPrivateKey => error.InvalidPrivateKey,
            else => error.InvalidDer,
        };
    }

    /// Parse a private key from a PEM text block: `PRIVATE KEY` (PKCS#8
    /// `PrivateKeyInfo`, via `fromPkcs8`) or `RSA PRIVATE KEY` (bare PKCS#1
    /// `RSAPrivateKey`, via `fromDer`). The first matching block in `text` is
    /// used. `ENCRYPTED PRIVATE KEY` (PKCS#8 `EncryptedPrivateKeyInfo`) is
    /// out of scope and OpenSSH (`OPENSSH PRIVATE KEY`) blocks belong to
    /// the module-level `fromOpenSSH`; both report
    /// `error.UnsupportedPemLabel` here, never silently misparsed.
    pub fn fromPem(text: []const u8) PemError!SecretKey {
        const block = try pemDecodeBody(text);
        if (std.mem.eql(u8, block.label, "PRIVATE KEY")) {
            return try fromPkcs8(block.der());
        }
        if (std.mem.eql(u8, block.label, "RSA PRIVATE KEY")) {
            return try SecretKey.fromDer(block.der());
        }
        return error.UnsupportedPemLabel;
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

/// `e⁻¹ (mod m)` via the extended Euclidean algorithm over a (possibly
/// composite) `m`; fails with `error.InvalidPrivateKey` unless gcd(e, m) = 1.
/// VARIABLE-TIME in both operands (division-based Euclid — `std.crypto.ff`
/// has no `invert`, and Fermat inversion needs a *prime* modulus, which a
/// composite-modulus caller may not even know the factorization of). Used
/// internally for `d = e⁻¹ mod λ(n)` key derivation (`fromPrimes`, offline,
/// operates on already-known primes) and per-op CRT base-blinding
/// (`invModN`, called on a fresh public random `r`, never on secret key
/// material) — both call sites only ever feed it a *non-secret* operand.
///
/// `pub` so sibling modules needing a generic composite-modulus inverse
/// (currently `blindrsa`, for its RFC 9474 blinding-factor inversion) can
/// reuse this instead of carrying their own copy. It is a bare arithmetic
/// primitive with NO masking of its own — a caller with a secret operand
/// MUST mask it (multiply by a fresh independent random unit) before
/// calling, the same way `invModN` above and `blindrsa`'s `maskedInvert`
/// do; passing a secret directly leaks it through the run's data-dependent
/// branch count. The returned `BigInt` is a fresh, caller-owned value (the
/// caller's allocator is used for it, same as every other scratch value
/// here); this module always draws `gpa` from a `FixedBufferAllocator`
/// arena and lets the whole arena die together, never calling `.deinit()`
/// individually — a caller using a real allocator must deinit the result.
pub fn bigModInverse(gpa: std.mem.Allocator, e: *const BigInt, m: *const BigInt) !BigInt {
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

    // Public exponent as an `Fe` of `n` (used by the CRT fault check to
    // re-encrypt `m^e mod n`). e < 2³² < n, so this never overflows.
    const e_fe = Fe.fromBytes(n, eb, .big) catch return error.InvalidPrivateKey;

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
        .e = e_fe,
        .n_mont = montParamsFromModulus(n),
        .p_mont = montParamsFromModulus(p),
        .q_mont = montParamsFromModulus(q),
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

pub const PrimitiveError = error{
    /// OS2IP of the input is >= n (RFC 8017 range check).
    MessageRepresentativeOutOfRange,
    /// The CRT private op's Bellcore/BDL fault check failed: the recomputed
    /// `m^e mod n` did not equal the input `c`, so at least one CRT half was
    /// faulted. The (potentially secret-leaking) result is withheld — audit F3.
    FaultDetected,
};

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
    // Public exponent -> variable-time square-and-multiply on montint's fast
    // Montgomery multiply (e is public, small — see `montPowPublic`). `e` is
    // validated non-zero, odd, >= 3 at key construction time.
    var mb: [max_modulus_len]u8 = undefined;
    m.toBytes(&mb, .big) catch unreachable;
    var eb: [max_modulus_len]u8 = undefined;
    pk.e.toBytes(&eb, .big) catch unreachable;
    var ob: [max_modulus_len]u8 = undefined;
    const res = montPowPublic(&pk.n_mont, &mb, &eb, &ob);
    writeMontResult(out, res); // out.len == byteLen(n); res is < n
}

fn privateOp(sk: SecretKey, in: []const u8, out: []u8) PrimitiveError!void {
    const c = Fe.fromBytes(sk.n, in, .big) catch return error.MessageRepresentativeOutOfRange;
    // Secret exponent -> constant-time montint modexp; d is validated non-zero
    // by `fromPrimes`. (Non-CRT form; `rsadpCrt` is the fast default path.)
    var cb: [max_modulus_len]u8 = undefined;
    c.toBytes(&cb, .big) catch unreachable;
    var db: [max_modulus_len]u8 = undefined;
    sk.d.toBytes(&db, .big) catch unreachable;
    var ob: [max_modulus_len]u8 = undefined;
    const res = montPowSecret(&sk.n_mont, &cb, &db, &ob);
    writeMontResult(out, res);
}

/// Whether a CRT private op masks its input with F2 base blinding, and with
/// what.
///
/// **Why this is a type and not a `?std.Random`.** Blinding is the one
/// countermeasure on the secret path that this module cannot supply for
/// itself: std 0.16 removed `std.crypto.random`, so entropy has to arrive as
/// an argument, and the deterministic entry points (`decryptOaep`,
/// `signPkcs1v15`, `rsadpCrt`) have no argument to arrive in. Until the B6
/// seam audit that meant those three ran unblinded with *no way for a
/// consumer to change it* — an internal comment was the only trace. A `null`
/// in a `?std.Random` slot says nothing about what was given up; `.none`
/// names it, and `.csprng` names the assertion the caller is making about
/// their generator (`std.Random` is a vtable, so nothing here can check it).
///
/// Blinding is **defence in depth, not the primary defence**: both CRT
/// exponentiations run through `montPowSecret`, which is constant-time in the
/// secret exponent, and the F3 Bellcore fault check runs on every path
/// regardless of this value. What blinding buys is that a residual leak in
/// that constant-time claim — a compiler that defeats it, a microarchitectural
/// channel it does not model — is not correlated with an attacker-chosen
/// base, which is what turns a leak into a key recovery.
pub const Blinding = union(enum) {
    /// Base blinding ON, using this generator for the masking factor `r`.
    /// It MUST be cryptographically secure: a predictable `r` voids the
    /// masking entirely (the attacker just divides it back out).
    csprng: std.Random,

    /// Base blinding OFF — the operation runs directly on the caller's input.
    /// This is what every deterministic entry point does by default, and it
    /// is the right choice when the base is not attacker-chosen or when no
    /// CSPRNG is in hand. It is NOT the right choice for an OAEP decryption
    /// oracle exposed to the network.
    none,

    /// Deliberately NOT `pub`: the point of the type is that the choice is
    /// visible at the call site, and a public accessor would hand callers
    /// back the flat `?std.Random` this replaced.
    fn rng(self: Blinding) ?std.Random {
        return switch (self) {
            .csprng => |r| r,
            .none => null,
        };
    }
};

/// F2 base-blinding factors for one CRT private op: `c_blinded = c·r^e mod n`
/// for a fresh random unit `r`, plus `r_inv = r⁻¹ mod n` to undo it afterwards
/// (`m·r_inv = (c·r^e)^d·r⁻¹ = c^d·r·r⁻¹ = c^d mod n`).
const BlindingFactors = struct { c_blinded: Fe, r_inv: Fe };

/// Draw a fresh blinding pair. All arithmetic here is on the PUBLIC modulus n
/// and on `r` (a secret-independent random value), so the variable-time inverse
/// and the `r^e` public modexp leak nothing about the private exponent. `rng`
/// MUST be cryptographically secure — a predictable `r` voids the masking.
fn makeBlinding(sk: SecretKey, c: Fe, rng: std.Random) BlindingFactors {
    const n_len = byteLen(sk.n.bits());
    var n_be: [max_modulus_len]u8 = undefined;
    sk.n.toBytes(n_be[0..n_len], .big) catch unreachable;
    var e_be: [max_modulus_len]u8 = undefined;
    sk.e.toBytes(&e_be, .big) catch unreachable;

    while (true) {
        // Uniform r in [1, n-1] by rejection sampling (>= n redraws).
        var r_raw: [max_modulus_len]u8 = undefined;
        rng.bytes(r_raw[0..n_len]);
        const r = Fe.fromBytes(sk.n, r_raw[0..n_len], .big) catch continue;
        if (r.isZero()) continue;
        var r_be: [max_modulus_len]u8 = undefined;
        r.toBytes(r_be[0..n_len], .big) catch unreachable; // canonical, < n

        // r_inv = r⁻¹ mod n (fails only if gcd(r, n) != 1 — r shares p or q,
        // astronomically unlikely; redraw if so).
        var rinv_be: [max_modulus_len]u8 = undefined;
        const rinv = invModN(n_be[0..n_len], r_be[0..n_len], &rinv_be) orelse continue;
        const r_inv = Fe.fromBytes(sk.n, rinv, .big) catch continue;

        // re = r^e mod n (public modexp), then c_blinded = c·re mod n.
        var re_out: [max_modulus_len]u8 = undefined;
        const re_be = montPowPublic(&sk.n_mont, r_be[0..n_len], &e_be, &re_out);
        const re = Fe.fromBytes(sk.n, re_be, .big) catch continue;
        return .{ .c_blinded = sk.n.mul(c, re), .r_inv = r_inv };
    }
}

/// `r⁻¹ mod n` as big-endian bytes into `out` (returns the written slice), or
/// `null` if `r` is not a unit mod n. Extended-Euclid via `std.math.big.int` on
/// a stack arena — variable-time, but only ever on the public modulus and a
/// random `r`, never on secret key material.
fn invModN(n_be: []const u8, r_be: []const u8, out: *[max_modulus_len]u8) ?[]const u8 {
    var scratch: [96 * 1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    const gpa = fba.allocator();
    var r_big = bigFromBytes(gpa, r_be) catch return null;
    var n_big = bigFromBytes(gpa, n_be) catch return null;
    var inv = bigModInverse(gpa, &r_big, &n_big) catch return null; // gcd != 1 -> null
    if (inv.bitCountAbs() > max_modulus_bits) return null;
    inv.toConst().writeTwosComplement(out, .big); // left-zero-padded to out.len
    return out[0..];
}

fn privateOpCrt(sk: SecretKey, in: []const u8, out: []u8, blinding: Blinding) PrimitiveError!void {
    const c = Fe.fromBytes(sk.n, in, .big) catch return error.MessageRepresentativeOutOfRange;

    // F2 (base blinding): with `.csprng`, run the CRT op on c' = c·r^e mod n
    // and unblind the result by r⁻¹ mod n below. This randomizes every secret-
    // dependent intermediate so any residual (compiler-defeated) timing/power
    // signal is masked. With `.none` the op runs unblinded but the F3 fault
    // check still applies.
    var r_inv: ?Fe = null;
    var c_eff = c;
    if (blinding.rng()) |g| {
        const b = makeBlinding(sk, c, g);
        c_eff = b.c_blinded;
        r_inv = b.r_inv;
    }

    // RFC 8017 §5.1.2 form (2), two-prime case:
    //   m1 = c^dP mod p, m2 = c^dQ mod q   (on the possibly-blinded c_eff)
    // The two half-width modexps are the hot path — routed through montint
    // (constant-time in the secret exponent). Reduction of `c_eff` into the
    // mod-p / mod-q domains stays in `ff` (constant-time), as does the Garner
    // recombination below; only the exponentiation moved.
    const cp = reduceWide(sk.p, c_eff.v);
    var cpb: [max_modulus_len]u8 = undefined;
    cp.toBytes(&cpb, .big) catch unreachable;
    var dpb: [max_modulus_len]u8 = undefined;
    sk.dp.toBytes(&dpb, .big) catch unreachable;
    var m1_buf: [max_modulus_len]u8 = undefined;
    const m1_be = montPowSecret(&sk.p_mont, &cpb, &dpb, &m1_buf);
    const m1 = Fe.fromBytes(sk.p, m1_be, .big) catch unreachable; // m1 < p

    const cq = reduceWide(sk.q, c_eff.v);
    var cqb: [max_modulus_len]u8 = undefined;
    cq.toBytes(&cqb, .big) catch unreachable;
    var dqb: [max_modulus_len]u8 = undefined;
    sk.dq.toBytes(&dqb, .big) catch unreachable;
    var m2_buf: [max_modulus_len]u8 = undefined;
    const m2_be = montPowSecret(&sk.q_mont, &cqb, &dqb, &m2_buf);
    const m2 = Fe.fromBytes(sk.q, m2_be, .big) catch unreachable; // m2 < q

    //   h = (m1 - m2) * qInv mod p    (m2 reduced into mod-p domain first)
    const h = sk.p.mul(sk.qinv, sk.p.sub(m1, reduceWide(sk.p, m2.v)));
    //   m = m2 + q*h — the true integer value is < n (m2 < q, h <= p-1), so
    //   computing it mod n is exact.
    const m2_n = reduceWide(sk.n, m2.v);
    const q_n = reduceWide(sk.n, sk.q.v);
    const h_n = reduceWide(sk.n, h.v);
    var m = sk.n.add(m2_n, sk.n.mul(q_n, h_n));

    // F2 unblind: m <- m·r⁻¹ mod n, recovering the true representative.
    if (r_inv) |ri| m = sk.n.mul(m, ri);

    // F3 (Bellcore / BDL fault check): re-encrypt the UNBLINDED m and compare
    // to the ORIGINAL c. A fault in either CRT half makes m ≢ c^d, so m^e ≢ c
    // and we refuse to emit m — denying the attacker the faulty value from
    // which p = gcd(c − m^e mod n, n) would otherwise factor the modulus.
    var m_be: [max_modulus_len]u8 = undefined;
    m.toBytes(&m_be, .big) catch unreachable;
    var e_be: [max_modulus_len]u8 = undefined;
    sk.e.toBytes(&e_be, .big) catch unreachable;
    var chk_buf: [max_modulus_len]u8 = undefined;
    const chk_be = montPowPublic(&sk.n_mont, &m_be, &e_be, &chk_buf);
    const chk = Fe.fromBytes(sk.n, chk_be, .big) catch unreachable;
    if (!chk.eql(c)) return error.FaultDetected;

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
///
/// Runs with F2 base blinding **OFF** (`Blinding.none`) — see `Blinding` for
/// what that costs and why the default is this way. Use `rsadpCrtBlinded` to
/// supply a CSPRNG when `c` is attacker-chosen.
pub fn rsadpCrt(comptime modulus_len: usize, c: [modulus_len]u8, sk: SecretKey) PrimitiveError![modulus_len]u8 {
    return rsadpCrtBlinded(modulus_len, c, sk, .none);
}

/// `rsadpCrt` with an explicit F2 base-blinding choice.
pub fn rsadpCrtBlinded(comptime modulus_len: usize, c: [modulus_len]u8, sk: SecretKey, blinding: Blinding) PrimitiveError![modulus_len]u8 {
    comptime std.debug.assert(modulus_len <= max_modulus_len);
    var out: [modulus_len]u8 = undefined;
    try privateOpCrt(sk, &c, &out, blinding);
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

pub const SignPkcs1v15Error = EmsaEncodeError || error{ BufferTooSmall, FaultDetected };

/// Sign `msg` with EMSA-PKCS1-v1_5 encoding (RFC 8017 §9.2) + the RSASP1
/// signature primitive (§8.2.1). `out` must be at least as long as the
/// modulus (`sk.n` byte length); returns the written subslice.
///
/// PKCS#1 v1.5 signing is deterministic by definition, so this entry point
/// takes no generator and runs the private op with F2 base blinding **OFF**
/// (`Blinding.none`). The signature itself does not depend on the blinding
/// factor, so a caller who signs attacker-supplied messages with a long-lived
/// key can pass a CSPRNG through `signPkcs1v15Blinded` and get byte-identical
/// signatures with the masking on — see `Blinding`.
pub fn signPkcs1v15(sk: SecretKey, comptime Hash: type, msg: []const u8, out: []u8) SignPkcs1v15Error![]u8 {
    return signPkcs1v15Blinded(sk, Hash, .none, msg, out);
}

/// `signPkcs1v15` with an explicit F2 base-blinding choice. The emitted
/// signature is identical either way (blinding is undone before output);
/// only the side-channel posture of the private op differs.
pub fn signPkcs1v15Blinded(sk: SecretKey, comptime Hash: type, blinding: Blinding, msg: []const u8, out: []u8) SignPkcs1v15Error![]u8 {
    const k = byteLen(sk.n.bits());
    if (out.len < k) return error.BufferTooSmall;
    var em_buf: [max_modulus_len]u8 = undefined;
    const em = em_buf[0..k];
    try emsaPkcs1v15Encode(Hash, msg, em);
    // EM starts with 0x00 0x01, so its integer value is < n by construction;
    // the range check inside the primitive cannot fail. A Bellcore fault (F3)
    // is surfaced on either blinding setting, never signed over.
    privateOpCrt(sk, em, out[0..k], blinding) catch |err| switch (err) {
        error.MessageRepresentativeOutOfRange => unreachable,
        error.FaultDetected => return error.FaultDetected,
    };
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
///
/// Uses a single `Hash` for both the label digest (`lHash`) and MGF1; a thin
/// wrapper over `encryptOaepH` with `LabelHash == MgfHash == Hash`.
pub fn encryptOaep(pk: PublicKey, comptime Hash: type, random: std.Random, msg: []const u8, label: []const u8, out: []u8) EncryptOaepError![]u8 {
    return encryptOaepH(pk, Hash, Hash, random, msg, label, out);
}

/// Decoupled-hash RSAES-OAEP encrypt (RFC 8017 §7.1.1). `LabelHash` is the
/// digest used for `lHash = LabelHash(label)` and fixes the structural sizes
/// (seed length = `LabelHash.digest_length` = `hLen`, and the message bound
/// `k - 2*hLen - 2`); `MgfHash` is the hash driving MGF1 (§B.2.1). RFC 8017
/// permits the two to differ (the digest and the mask-generation hash are
/// independent parameters); real-world XML-Encryption `rsa-oaep` configs use
/// e.g. digest=SHA-256 with MGF1=SHA-1. See `encryptOaep` for the argument
/// contract; identical apart from the split hash parameters.
///
/// `random` supplies the mandatory fresh OAEP seed and MUST be cryptographically
/// secure — OAEP's security proof assumes an unpredictable
/// seed, and a deterministic or low-entropy source makes the ciphertext a
/// function of the plaintext alone, so anyone holding the public key confirms
/// a guessed plaintext by re-encrypting it. (Stated here because it is stated
/// on `encryptOaep`: the two entry points carry the same requirement, and
/// only one of them used to say so.)
pub fn encryptOaepH(pk: PublicKey, comptime LabelHash: type, comptime MgfHash: type, random: std.Random, msg: []const u8, label: []const u8, out: []u8) EncryptOaepError![]u8 {
    const h_len = LabelHash.digest_length;
    const k = byteLen(pk.n.bits());
    if (out.len < k) return error.BufferTooSmall;
    // §7.1.1 step 1.b: mLen <= k - 2 hLen - 2 (also covers k too small for
    // the hash at all). hLen is the *label* hash's length (it sizes lHash and
    // the seed); the MGF hash only affects mask generation, not the layout.
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
    LabelHash.hash(label, db[0..h_len], .{});
    @memset(db[h_len .. db.len - msg.len - 1], 0x00);
    db[db.len - msg.len - 1] = 0x01;
    @memcpy(db[db.len - msg.len ..], msg);

    // step 2.d-2.h: random seed, then the two MGF1 maskings. Order matters
    // for the in-place XOR: DB is masked with the *raw* seed first, then the
    // seed is masked with the already-masked DB. MGF1 uses `MgfHash`.
    random.bytes(seed);
    mgf1Xor(MgfHash, seed, db); // maskedDB   = DB   ^ MGF1(seed)
    mgf1Xor(MgfHash, db, seed); // maskedSeed = seed ^ MGF1(maskedDB)

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
///
/// Runs the private op with F2 base blinding **OFF** (`Blinding.none`). This
/// is the entry point most likely to be sitting behind a network-facing
/// decryption oracle, where the base `ct` is entirely attacker-chosen — use
/// `decryptOaepBlinded` with a CSPRNG there. See `Blinding` for exactly what
/// blinding does and does not buy, and why the default stayed off.
///
/// Uses a single `Hash` for both the label digest (`lHash`) and MGF1; a thin
/// wrapper over `decryptOaepH` with `LabelHash == MgfHash == Hash`.
pub fn decryptOaep(sk: SecretKey, comptime Hash: type, ct: []const u8, label: []const u8, out: []u8) DecryptOaepError![]u8 {
    return decryptOaepHBlinded(sk, Hash, Hash, .none, ct, label, out);
}

/// `decryptOaep` with an explicit F2 base-blinding choice. The recovered
/// plaintext and every error are identical either way.
pub fn decryptOaepBlinded(sk: SecretKey, comptime Hash: type, blinding: Blinding, ct: []const u8, label: []const u8, out: []u8) DecryptOaepError![]u8 {
    return decryptOaepHBlinded(sk, Hash, Hash, blinding, ct, label, out);
}

/// Decoupled-hash RSAES-OAEP decrypt (RFC 8017 §7.1.2). `LabelHash` is the
/// digest used for `lHash = LabelHash(label)` and fixes `hLen` (seed length
/// and the layout); `MgfHash` drives MGF1. Mirrors `encryptOaepH`; use it to
/// decrypt ciphertext produced with a digest hash that differs from the MGF1
/// hash (e.g. XML-Encryption `rsa-oaep` with digest=SHA-256, MGF1=SHA-1). The
/// same constant-time / single-generic-error posture as `decryptOaep` applies
/// (all padding-decode failures collapse to `error.DecryptionError`), F2 base
/// blinding **OFF** included — `decryptOaepHBlinded` is the opt-in.
pub fn decryptOaepH(sk: SecretKey, comptime LabelHash: type, comptime MgfHash: type, ct: []const u8, label: []const u8, out: []u8) DecryptOaepError![]u8 {
    return decryptOaepHBlinded(sk, LabelHash, MgfHash, .none, ct, label, out);
}

/// `decryptOaepH` with an explicit F2 base-blinding choice — the one entry
/// point through which every other OAEP-decrypt path reaches the private op.
pub fn decryptOaepHBlinded(sk: SecretKey, comptime LabelHash: type, comptime MgfHash: type, blinding: Blinding, ct: []const u8, label: []const u8, out: []u8) DecryptOaepError![]u8 {
    const h_len = LabelHash.digest_length;
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
    // `blinding` is the caller's F2 choice — `.none` on the deterministic
    // entry points, `.csprng` when they opted in. The F3 fault check runs
    // either way, and a fault maps to the same generic DecryptionError (no
    // oracle), as does a blinded run.
    privateOpCrt(sk, ct, em, blinding) catch return error.DecryptionError;

    // step 3: EME-OAEP decode, branch-free. EM = Y || maskedSeed || maskedDB.
    // hLen is the label hash length; MGF1 uses `MgfHash`.
    const seed = em[1..][0..h_len];
    const db = em[1 + h_len .. k];
    mgf1Xor(MgfHash, db, seed); // seed = maskedSeed ^ MGF1(maskedDB)
    mgf1Xor(MgfHash, seed, db); // DB   = maskedDB   ^ MGF1(seed)

    var lhash: [h_len]u8 = undefined;
    LabelHash.hash(label, &lhash, .{});
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
///
/// `pub` so a caller needing EMSA-PSS-ENCODE as a standalone step — decoupled
/// from RSASP1 — can reuse it instead of carrying an independent copy.
/// `blindrsa`'s RFC 9474 Blind is exactly this: it encodes, then blinds the
/// encoded integer, and only signs (via `rsasp1`) later, server-side, over
/// the blinded value — it never calls `signPss` here. `blindrsa.pssEncode`
/// is now a thin wrapper delegating straight to this function.
pub fn emsaPssEncode(comptime Hash: type, msg: []const u8, salt: []const u8, em_bits: usize, em: []u8) EmsaEncodeError!void {
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

pub const SignPssError = EmsaEncodeError || error{ BufferTooSmall, FaultDetected };

/// Sign `msg` with RSASSA-PSS (RFC 8017 §8.1.1): EMSA-PSS-ENCODE (§9.1.1)
/// over emBits = modBits - 1, then the RSASP1 signature primitive (CRT fast
/// path). `salt_len` is the PSS salt length in bytes (`sLen`): `0` yields
/// deterministic signatures (the emitted signature is salt-free), while any
/// `salt_len`, the conventional default `Hash.digest_length` included (what
/// OpenSSL calls `rsa_pss_saltlen:digest`), draws that many salt octets.
/// `random` supplies the fresh salt AND the F2 base-blinding factor for the
/// CRT private op, so it is drawn from even when `salt_len == 0` (blinding is
/// unblinded before output — the signature stays deterministic for
/// `salt_len == 0`). `random` MUST be cryptographically secure. `out` must be at least as
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
    // `random` also drives F2 base blinding inside the CRT op; a Bellcore
    // fault (F3) is surfaced, never signed over.
    privateOpCrt(sk, em_buf[0..k], out[0..k], .{ .csprng = random }) catch |err| switch (err) {
        error.MessageRepresentativeOutOfRange => unreachable,
        error.FaultDetected => return error.FaultDetected,
    };
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

// ── P4a: DER/ASN.1 + PEM key parsing ─────────────────────────────────────────
//
// Low-level TLV reads go through `std.crypto.codecs.asn1.Element.decode`
// (added in Zig 0.16) rather than the older `std.crypto.Certificate.der`
// (also inspected: its `Element.parse` computes slice bounds from the
// length octets without ever checking them against the input buffer, so a
// truncated/malformed element can yield a slice that runs past `bytes.len` —
// fine for std's own use where the caller pre-validates well-formedness, but
// exactly the kind of thing that becomes a wild slice — undefined behavior
// once actually indexed in `ReleaseFast` — when handed attacker- or
// corruption-controlled key files). `codecs.asn1.Element.decode`'s own doc
// comment guarantees it "does NOT read memory outside bytes" and "does NOT
// return elements with slices outside bytes" (`error.EndOfStream` instead),
// which is the property this module needs. `derChild` below adds the one
// thing that primitive cannot: bounding a child element to its *logical*
// parent's content range (a SEQUENCE's `[start, end)`), since
// `Element.decode` only ever validates against the overall buffer.
//
// The higher-level `codecs.asn1.der.Decoder`/`der.decode(T, ...)` struct
// reflection (also new in 0.16) is not used: PKCS#1/PKCS#8 have a small,
// fixed number of shapes, each with only one wrinkle (RSAPrivateKey's
// version-gated `otherPrimeInfos`, PrivateKeyInfo's optional `attributes`
// context tag) that is simpler to reject/ignore by hand than to teach the
// reflection layer's optional/implicit-tag machinery.

const Asn1 = std.crypto.codecs.asn1;

/// `rsaEncryption` algorithm OID (RFC 8017 Appendix C / RFC 3279 §2.3.1):
/// 1.2.840.113549.1.1.1, DER content octets (tag/length excluded).
const oid_rsa_encryption = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };

const DerError = error{InvalidDer};

/// Decode the element at `index`, requiring an exact universal-class
/// tag/constructed-bit match. Thin wrapper over `Asn1.Element.decode` (see
/// the section doc comment for why that primitive and not
/// `std.crypto.Certificate.der`).
fn derElem(bytes: []const u8, index: u32, number: Asn1.Tag.Number, constructed: bool) DerError!Asn1.Element {
    const e = Asn1.Element.decode(bytes, index) catch return error.InvalidDer;
    if (e.tag.number != number or e.tag.constructed != constructed or e.tag.class != .universal) {
        return error.InvalidDer;
    }
    return e;
}

/// Like `derElem`, but the whole point of this module's DER walking: `index`
/// must be strictly before `container_end`, and the decoded element must fit
/// entirely within `[index, container_end)`. `Element.decode` alone cannot
/// enforce this — it only knows about `bytes` as a whole, not any logical
/// parent SEQUENCE's content range — so without this check a crafted
/// sibling-length field could make one element's content "spill" into (or
/// past) its parent's supposed end while still passing `Element.decode`.
fn derChild(bytes: []const u8, index: u32, container_end: u32, number: Asn1.Tag.Number, constructed: bool) DerError!Asn1.Element {
    if (index >= container_end) return error.InvalidDer;
    const e = try derElem(bytes, index, number, constructed);
    if (e.slice.end > container_end) return error.InvalidDer;
    return e;
}

/// The outermost `SEQUENCE`, required to span the entire input — rejects
/// trailing garbage after the structure DER is supposed to end at.
fn derTopSequence(bytes: []const u8) DerError!Asn1.Element {
    if (bytes.len > std.math.maxInt(u32)) return error.InvalidDer;
    const top = try derElem(bytes, 0, .sequence, true);
    if (top.slice.end != bytes.len) return error.InvalidDer;
    return top;
}

fn derView(bytes: []const u8, e: Asn1.Element) []const u8 {
    return e.slice.view(bytes);
}

/// `RSAPublicKey` (PKCS#1 Appendix A.1.1) or `SubjectPublicKeyInfo`
/// (RFC 5280) — distinguished by the top SEQUENCE's first child: a bare
/// INTEGER means PKCS#1, a nested SEQUENCE (AlgorithmIdentifier) means SPKI.
fn publicKeyFromDerImpl(bytes: []const u8) !PublicKey {
    const top = try derTopSequence(bytes);
    if (top.slice.start >= top.slice.end) return error.InvalidDer; // empty SEQUENCE
    const first = Asn1.Element.decode(bytes, top.slice.start) catch return error.InvalidDer;
    if (first.slice.end > top.slice.end) return error.InvalidDer;

    if (first.tag.class == .universal and !first.tag.constructed and first.tag.number == .integer) {
        // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
        const n = first;
        const e = try derChild(bytes, n.slice.end, top.slice.end, .integer, false);
        if (e.slice.end != top.slice.end) return error.InvalidDer; // exactly two fields
        return PublicKey.fromBytes(derView(bytes, n), derView(bytes, e)) catch error.InvalidDer;
    }

    if (first.tag.class == .universal and first.tag.constructed and first.tag.number == .sequence) {
        // SubjectPublicKeyInfo ::= SEQUENCE { AlgorithmIdentifier, subjectPublicKey BIT STRING }
        const alg_id = first;
        const oid_elem = try derChild(bytes, alg_id.slice.start, alg_id.slice.end, .oid, false);
        if (!std.mem.eql(u8, derView(bytes, oid_elem), &oid_rsa_encryption)) return error.InvalidDer;
        // AlgorithmIdentifier.parameters (conventionally a NULL for RSA) is
        // not inspected further — `alg_id.slice.end` is where it ends either way.

        const bit_str = try derChild(bytes, alg_id.slice.end, top.slice.end, .bitstring, false);
        if (bit_str.slice.end != top.slice.end) return error.InvalidDer; // exactly two fields

        const raw = derView(bytes, bit_str);
        // The embedded RSAPublicKey DER must be byte-aligned: zero unused bits.
        if (raw.len < 1 or raw[0] != 0) return error.InvalidDer;
        return publicKeyFromDerImpl(raw[1..]);
    }

    return error.InvalidDer;
}

/// `RSAPrivateKey` (PKCS#1 Appendix A.1.2), two-prime form only (`version`
/// 0): extracts `p`, `q`, `e` and routes them through `SecretKey.fromPrimes`
/// (see that function's doc comment for why `n`/`d`/the CRT fields on the
/// wire are not trusted). Multi-prime keys (`version` 1, `otherPrimeInfos`)
/// are rejected rather than silently truncated.
fn secretKeyFromPkcs1Impl(bytes: []const u8) !SecretKey {
    const top = try derTopSequence(bytes);

    const version = try derChild(bytes, top.slice.start, top.slice.end, .integer, false);
    const version_bytes = derView(bytes, version);
    if (!(version_bytes.len == 1 and version_bytes[0] == 0)) return error.InvalidDer;

    const n = try derChild(bytes, version.slice.end, top.slice.end, .integer, false);
    const e = try derChild(bytes, n.slice.end, top.slice.end, .integer, false);
    const d = try derChild(bytes, e.slice.end, top.slice.end, .integer, false);
    const p = try derChild(bytes, d.slice.end, top.slice.end, .integer, false);
    const q = try derChild(bytes, p.slice.end, top.slice.end, .integer, false);
    const dp = try derChild(bytes, q.slice.end, top.slice.end, .integer, false);
    const dq = try derChild(bytes, dp.slice.end, top.slice.end, .integer, false);
    const qinv = try derChild(bytes, dq.slice.end, top.slice.end, .integer, false);
    if (qinv.slice.end != top.slice.end) return error.InvalidDer; // no otherPrimeInfos

    // n/d/dP/dQ/qInv are on-the-wire CRT bookkeeping `fromPrimes` re-derives
    // and cross-checks itself (see its doc comment) — only p, q, e feed it.
    return SecretKey.fromPrimes(derView(bytes, p), derView(bytes, q), derView(bytes, e)) catch error.InvalidPrivateKey;
}

pub const FromPkcs8Error = error{ InvalidDer, InvalidPrivateKey };

/// Parse a private key from a DER-encoded PKCS#8 `PrivateKeyInfo` (RFC 5958)
/// wrapping an RFC 8017 Appendix A.1.2 `RSAPrivateKey`. Only the plain
/// (unencrypted) `PrivateKeyInfo` shape is handled — `EncryptedPrivateKeyInfo`
/// (`ENCRYPTED PRIVATE KEY` in PEM) is a distinct ASN.1 structure entirely
/// and out of scope (passphrase-protected keys are supported in the OpenSSH
/// format instead, via `fromOpenSSH`).
pub fn fromPkcs8(bytes: []const u8) FromPkcs8Error!SecretKey {
    return fromPkcs8Impl(bytes) catch |err| switch (err) {
        error.InvalidPrivateKey => error.InvalidPrivateKey,
        else => error.InvalidDer,
    };
}

fn fromPkcs8Impl(bytes: []const u8) !SecretKey {
    const top = try derTopSequence(bytes);

    // PrivateKeyInfo ::= SEQUENCE { version INTEGER, algorithm AlgorithmIdentifier,
    //                               privateKey OCTET STRING, attributes [0] OPTIONAL }
    const version = try derChild(bytes, top.slice.start, top.slice.end, .integer, false);
    const version_bytes = derView(bytes, version);
    // v1 (RFC 5208): version MUST be 0. v2 (RFC 5958, adds an OPTIONAL
    // public key [1] field, version 1) is not produced by `openssl pkey`
    // for plain RSA keys and is not accepted here.
    if (!(version_bytes.len == 1 and version_bytes[0] == 0)) return error.InvalidDer;

    const alg_id = try derChild(bytes, version.slice.end, top.slice.end, .sequence, true);
    const oid_elem = try derChild(bytes, alg_id.slice.start, alg_id.slice.end, .oid, false);
    if (!std.mem.eql(u8, derView(bytes, oid_elem), &oid_rsa_encryption)) return error.InvalidDer;

    const priv_key = try derChild(bytes, alg_id.slice.end, top.slice.end, .octetstring, false);
    // An OPTIONAL `attributes [0]` field may follow `priv_key`; it is not
    // needed for RSA and is left unexamined (it can only ever occupy
    // `(priv_key.slice.end, top.slice.end]`, already bounds-checked above).

    return secretKeyFromPkcs1Impl(derView(bytes, priv_key));
}

// ── PEM (RFC 7468) ───────────────────────────────────────────────────────────

pub const PemError = error{
    MissingPemBlock,
    InvalidPem,
    UnsupportedPemLabel,
    InvalidDer,
    InvalidPrivateKey,
};

const max_pem_label_len = 32; // longest in use: "ENCRYPTED PRIVATE KEY" (21)
const max_end_marker_len = "-----END -----".len + max_pem_label_len;

/// Largest DER payload `pemDecodeBody` will produce: a PKCS#8-wrapped,
/// `max_modulus_bits`-sized two-prime `RSAPrivateKey` is ~2.4 KiB in the
/// worst case (8 big INTEGERs plus headers); this leaves comfortable
/// headroom without needing an allocator.
const max_pem_der_len = 8 * max_modulus_len;

const PemBlock = struct {
    label: []const u8,
    der_buf: [max_pem_der_len]u8,
    der_len: usize,

    fn der(self: *const PemBlock) []const u8 {
        return self.der_buf[0..self.der_len];
    }
};

/// Decode the FIRST `-----BEGIN <label>-----`/`-----END <label>-----` block
/// in `text` (surrounding/other-labeled text is ignored, matching common
/// OpenSSL PEM-bundle tolerance) into its label and base64-decoded DER body.
/// Callers (`PublicKey.fromPem`/`SecretKey.fromPem`) dispatch on the label —
/// including recognizing but rejecting encrypted/unsupported ones
/// (`ENCRYPTED PRIVATE KEY`, `OPENSSH PRIVATE KEY`) with a clear error
/// instead of misparsing their DER/blob as if it were a cleartext key.
fn pemDecodeBody(text: []const u8) PemError!PemBlock {
    const begin_marker = "-----BEGIN ";
    const dashes = "-----";

    const bi = std.mem.indexOf(u8, text, begin_marker) orelse return error.MissingPemBlock;
    const label_start = bi + begin_marker.len;
    const label_end = std.mem.indexOfPos(u8, text, label_start, dashes) orelse return error.InvalidPem;
    const label = text[label_start..label_end];
    if (label.len > max_pem_label_len) return error.InvalidPem;

    const body_start = label_end + dashes.len;
    var end_marker_buf: [max_end_marker_len]u8 = undefined;
    const end_marker = std.fmt.bufPrint(&end_marker_buf, "-----END {s}-----", .{label}) catch unreachable;
    const ei = std.mem.indexOfPos(u8, text, body_start, end_marker) orelse return error.InvalidPem;
    const body = text[body_start..ei];

    const dec = std.base64.standard.decoderWithIgnore(" \t\r\n");
    var block: PemBlock = .{ .label = label, .der_buf = undefined, .der_len = 0 };
    const n = dec.decode(&block.der_buf, body) catch return error.InvalidPem;
    if (n == 0) return error.InvalidPem;
    block.der_len = n;
    return block;
}

// ── P4b: OpenSSH PROTOCOL.key private-key parsing ────────────────────────────
//
// Design references (specs only, no source copied): OpenSSH's PROTOCOL.key
// document (the openssh-key-v1 container layout), RFC 4251 §5 (the SSH
// `string`/`mpint` wire encodings), and the OpenBSD bcrypt_pbkdf(3)
// algorithm — the latter implemented from scratch in openssh.zig together
// with Blowfish (Schneier's spec); see that file's provenance note.

pub const FromOpenSSHError = error{
    MissingPemBlock,
    InvalidPem,
    UnsupportedPemLabel,
    /// Structural failure: bad magic, truncated field, nkeys != 1,
    /// trailing garbage, malformed kdf options, or bad padding.
    InvalidOpenSSH,
    /// The key parsed but is not `ssh-rsa` (e.g. ssh-ed25519, ecdsa-*).
    UnsupportedKeyType,
    /// A ciphername other than none/aes256-ctr/aes256-cbc.
    UnsupportedCipher,
    /// A kdfname other than none/bcrypt.
    UnsupportedKdf,
    /// The decrypted check-int pair does not match (wrong passphrase; also
    /// reported for an empty passphrase against an encrypted key).
    IncorrectPassphrase,
    InvalidPrivateKey,
};

/// Minimal reader for the SSH wire primitives (RFC 4251 §5): u32
/// length-prefixed `string`s (and `mpint`s, which share the outer shape)
/// over a fixed buffer. Every read is bounds-checked; truncation is a
/// structural error, never a panic.
const SshReader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn readU32(r: *SshReader) error{InvalidOpenSSH}!u32 {
        if (r.buf.len - r.pos < 4) return error.InvalidOpenSSH;
        const v = std.mem.readInt(u32, r.buf[r.pos..][0..4], .big);
        r.pos += 4;
        return v;
    }

    fn readString(r: *SshReader) error{InvalidOpenSSH}![]const u8 {
        const n = try r.readU32();
        if (r.buf.len - r.pos < n) return error.InvalidOpenSSH;
        const s = r.buf[r.pos..][0..n];
        r.pos += n;
        return s;
    }

    /// `mpint` (big-endian two's complement, leading 0x00 when the high
    /// bit is set) — same length-prefixed wire shape as `string`; the RSA
    /// consumers below strip the sign octet via `stripLeadingZeros`.
    fn readMpint(r: *SshReader) error{InvalidOpenSSH}![]const u8 {
        return r.readString();
    }

    fn rest(r: *const SshReader) []const u8 {
        return r.buf[r.pos..];
    }
};

/// Ciphers an openssh-key-v1 container may protect the private section
/// with. OpenSSH's default is aes256-ctr; aes256-cbc is the legacy `-Z`
/// choice. Both take a 32-byte key + 16-byte IV from bcrypt-pbkdf.
const OpensshCipher = enum {
    none,
    aes256_ctr,
    aes256_cbc,

    fn fromName(name: []const u8) FromOpenSSHError!OpensshCipher {
        if (std.mem.eql(u8, name, "none")) return .none;
        if (std.mem.eql(u8, name, "aes256-ctr")) return .aes256_ctr;
        if (std.mem.eql(u8, name, "aes256-cbc")) return .aes256_cbc;
        return error.UnsupportedCipher;
    }

    fn blockLen(self: OpensshCipher) usize {
        return switch (self) {
            .none => 8, // "none" still pads the section to 8-byte blocks
            .aes256_ctr, .aes256_cbc => 16,
        };
    }
};

/// Parse a private key from the OpenSSH `PROTOCOL.key` private-key text
/// format (`-----BEGIN OPENSSH PRIVATE KEY-----`), including bcrypt-pbkdf +
/// AES decryption for passphrase-protected keys (aes256-ctr and aes256-cbc;
/// pass `""` for unencrypted keys). Only single-key files (`nkeys == 1`)
/// holding an `ssh-rsa` key are accepted. As everywhere in this module,
/// only `p`, `q`, `e` are taken from the file — `n`/`d`/CRT values are
/// re-derived by `SecretKey.fromPrimes` (the on-disk `n` is then required
/// to match the derived one as an integrity cross-check).
pub fn fromOpenSSH(text: []const u8, passphrase: []const u8) FromOpenSSHError!SecretKey {
    const block = pemDecodeBody(text) catch |err| return switch (err) {
        error.MissingPemBlock => error.MissingPemBlock,
        else => error.InvalidPem,
    };
    if (!std.mem.eql(u8, block.label, "OPENSSH PRIVATE KEY")) return error.UnsupportedPemLabel;
    return fromOpensshBinary(block.der(), passphrase);
}

/// The decoded openssh-key-v1 container: magic, cipher/kdf negotiation,
/// public-key blob, and the (possibly encrypted) private section.
fn fromOpensshBinary(bin: []const u8, passphrase: []const u8) FromOpenSSHError!SecretKey {
    const magic = "openssh-key-v1\x00";
    if (bin.len < magic.len or !std.mem.eql(u8, bin[0..magic.len], magic)) {
        return error.InvalidOpenSSH;
    }
    var r = SshReader{ .buf = bin, .pos = magic.len };
    const ciphername = try r.readString();
    const kdfname = try r.readString();
    const kdfoptions = try r.readString();
    const nkeys = try r.readU32();
    if (nkeys != 1) return error.InvalidOpenSSH;
    // The public-key blob duplicates key type + n + e; the private section
    // is authoritative (and covered by the checkint test), so skip it.
    _ = try r.readString();
    const private_section = try r.readString();
    if (r.rest().len != 0) return error.InvalidOpenSSH;

    const cipher = try OpensshCipher.fromName(ciphername);
    const kdf_none = std.mem.eql(u8, kdfname, "none");
    const kdf_bcrypt = std.mem.eql(u8, kdfname, "bcrypt");
    if (!kdf_none and !kdf_bcrypt) return error.UnsupportedKdf;

    if (cipher == .none) {
        // Unencrypted: kdf must be none with empty options.
        if (!kdf_none or kdfoptions.len != 0) return error.InvalidOpenSSH;
        return parsePrivateSection(private_section, cipher, false);
    }

    // Encrypted: kdf must be bcrypt; kdfoptions = string salt + u32 rounds.
    if (!kdf_bcrypt) return error.InvalidOpenSSH;
    var kr = SshReader{ .buf = kdfoptions };
    const salt = try kr.readString();
    const rounds = try kr.readU32();
    if (kr.rest().len != 0 or salt.len == 0 or rounds == 0) return error.InvalidOpenSSH;
    if (private_section.len == 0 or private_section.len % cipher.blockLen() != 0) {
        return error.InvalidOpenSSH;
    }

    // Derive key (32) || IV (16). An empty passphrase is rejected by the
    // KDF itself — report it like any other wrong passphrase.
    var key_iv: [48]u8 = undefined;
    defer std.crypto.secureZero(u8, &key_iv);
    openssh.bcryptPbkdf(passphrase, salt, rounds, &key_iv) catch return error.IncorrectPassphrase;
    const aes_key = key_iv[0..32];
    const iv = key_iv[32..48];

    var dec_buf: [max_pem_der_len]u8 = undefined;
    const dec = dec_buf[0..private_section.len]; // <= bin.len <= max_pem_der_len
    defer std.crypto.secureZero(u8, dec);
    const aes = std.crypto.core.aes;
    switch (cipher) {
        .none => unreachable,
        .aes256_ctr => {
            const ctx = aes.Aes256.initEnc(aes_key.*);
            std.crypto.core.modes.ctr(
                aes.AesEncryptCtx(aes.Aes256),
                ctx,
                dec,
                private_section,
                iv.*,
                .big,
            );
        },
        .aes256_cbc => {
            const ctx = aes.Aes256.initDec(aes_key.*);
            var prev: [16]u8 = iv.*;
            var off: usize = 0;
            while (off < private_section.len) : (off += 16) {
                const ct_block = private_section[off..][0..16];
                var pt: [16]u8 = undefined;
                ctx.decrypt(&pt, ct_block);
                for (&pt, prev) |*b, x| b.* ^= x;
                @memcpy(dec[off..][0..16], &pt);
                prev = ct_block.*;
            }
        },
    }
    return parsePrivateSection(dec, cipher, true);
}

/// The (decrypted) private section: checkint pair, key type, the RSA
/// mpints in OpenSSH order (n, e, d, iqmp, p, q), comment, then 1..n
/// incrementing padding bytes filling up to the cipher block size.
fn parsePrivateSection(section: []const u8, cipher: OpensshCipher, encrypted: bool) FromOpenSSHError!SecretKey {
    var r = SshReader{ .buf = section };
    const check1 = try r.readU32();
    const check2 = try r.readU32();
    if (check1 != check2) {
        // Matching checkints are how OpenSSH detects a good passphrase; on
        // an unencrypted key a mismatch can only mean corruption.
        return if (encrypted) error.IncorrectPassphrase else error.InvalidOpenSSH;
    }
    const keytype = try r.readString();
    if (!std.mem.eql(u8, keytype, "ssh-rsa")) return error.UnsupportedKeyType;

    const n_wire = try r.readMpint();
    const e_wire = try r.readMpint();
    _ = try r.readMpint(); // d — re-derived by fromPrimes, never trusted
    _ = try r.readMpint(); // iqmp — likewise
    const p_wire = try r.readMpint();
    const q_wire = try r.readMpint();
    _ = try r.readString(); // comment — not needed for key material

    // Deterministic padding: bytes 0x01, 0x02, ... up to (but excluding) a
    // full cipher block. A wrong sequence means a parse misalignment or a
    // corrupt/forged section.
    const pad = r.rest();
    if (pad.len >= cipher.blockLen()) return error.InvalidOpenSSH;
    for (pad, 0..) |b, i| {
        if (b != i + 1) return error.InvalidOpenSSH;
    }

    const sk = SecretKey.fromPrimes(
        stripLeadingZeros(p_wire),
        stripLeadingZeros(q_wire),
        stripLeadingZeros(e_wire),
    ) catch return error.InvalidPrivateKey;

    // Integrity cross-check: the on-disk modulus must equal p*q.
    const n_file = stripLeadingZeros(n_wire);
    const k = byteLen(sk.n.bits());
    var n_buf: [max_modulus_len]u8 = undefined;
    sk.n.toBytes(n_buf[0..k], .big) catch return error.InvalidPrivateKey;
    if (!std.mem.eql(u8, n_file, n_buf[0..k])) return error.InvalidPrivateKey;

    return sk;
}

// ── P5: key generation (RFC 8017 §3.2, FIPS 186-5 A.1.3-style checks) ───────
//
// `generate` draws two random probable primes p, q of `bits`/2 bits each
// (top two bits forced so n = p·q lands on exactly `bits` bits), tests them
// with a small-prime trial-division pre-sieve + Miller-Rabin, enforces the
// FIPS 186-5 §A.1.3 structural constraints (p ≠ q with |p − q| large,
// gcd(e, p−1) = gcd(e, q−1) = 1), and then routes the primes through the
// existing `SecretKey.fromPrimes` (P1) for the n/d/dP/dQ/qInv derivation —
// key assembly is *not* re-implemented here.
//
// Miller-Rabin round count: a uniform `mr_rounds = 64` for every candidate
// at every size. FIPS 186-5 Table B.1's largest requirement (no companion
// Lucas test) is 44 rounds (1024-bit primes, 2^-100 target); 64 rounds
// dominates every table entry for all sizes this module supports and gives
// a worst-case (adversarial-composite) error bound of 4^-64 = 2^-128 per
// accepted candidate — for self-generated random candidates the
// average-case error (Damgård-Landrock-Pomerance) is far smaller still.
// Witnesses are drawn from the caller's `random`, uniformly in [2, n-2].
//
// Timing: prime generation is inherently variable-time (the search loop
// itself is data-dependent — every implementation's is). The modexps inside
// Miller-Rabin still use `ff`'s constant-time `powWithEncodedExponent`
// path, and all candidate/intermediate buffers are `secureZero`ed; what
// unavoidably remains observable is how *long* the search took, which
// reveals nothing useful about the primes that were kept.

/// Miller-Rabin rounds per candidate — see the section comment above for the
/// FIPS 186-5 Table B.1 rationale.
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

/// Big-endian unsigned `bytes` mod `divisor` (u128 intermediate: safe for any
/// u64 divisor). Used for the pre-sieve and the p mod e reduction only —
/// variable-time, never touches a kept secret in a data-dependent way beyond
/// the (public-fate) reject/accept decision itself.
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

/// Uniform random Miller-Rabin witness in [2, n-2] by rejection sampling
/// (mask to n's bit length, retry on out-of-range — expected < 2 draws).
fn randomWitness(m: Modulus, random: std.Random) Fe {
    const n_bits = m.bits();
    const n_len = byteLen(n_bits);
    const n_minus_1 = m.sub(m.zero, m.one());
    var buf: [max_modulus_len]u8 = undefined;
    defer std.crypto.secureZero(u8, buf[0..n_len]);
    while (true) {
        random.bytes(buf[0..n_len]);
        buf[0] &= @as(u8, 0xff) >> @intCast(8 * n_len - n_bits);
        const a = Fe.fromBytes(m, buf[0..n_len], .big) catch continue; // >= n: redraw
        if (a.isZero() or a.eql(m.one()) or a.eql(n_minus_1)) continue; // outside [2, n-2]
        return a;
    }
}

/// Miller-Rabin probable-prime test with `mr_rounds` random witnesses from
/// `random`. `m` must be an odd integer >= 5 (every `Modulus` is odd by
/// construction; callers here only ever pass >= 2^255). Returns false iff a
/// witness proves `m` composite.
fn isProbablePrime(m: Modulus, random: std.Random) bool {
    const n_len = byteLen(m.bits());

    // n - 1 = d * 2^s with d odd: n is odd, so n-1 is just n with the low
    // bit cleared, s = ctz(n-1) >= 1, d = (n-1) >> s.
    var d_buf: [max_modulus_len]u8 = undefined;
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
        // a^d mod n — constant-time modexp (the exponent d is n-derived).
        var x = m.powWithEncodedExponent(a, d_bytes, .big) catch unreachable; // d is odd, never 0
        if (x.eql(one) or x.eql(n_minus_1)) continue :rounds;
        var j: usize = 1;
        while (j < s) : (j += 1) {
            x = m.sq(x);
            if (x.eql(n_minus_1)) continue :rounds;
            // A nontrivial square root of 1: composite for sure — stop early.
            if (x.eql(one)) return false;
        }
        return false; // never hit n-1: `a` witnesses compositeness
    }
    return true;
}

/// Draw random odd candidates of exactly `prime_bits` bits with the top two
/// bits set (so p·q of two such primes always reaches 2·`prime_bits` bits),
/// pre-sieve by trial division, enforce gcd(e, candidate-1) = 1, and
/// Miller-Rabin test until a probable prime lands in `out`
/// (`out.len == byteLen(prime_bits)`).
fn generatePrime(random: std.Random, prime_bits: usize, e: u64, out: []u8) void {
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

        // gcd(e, p-1) = 1, via (p-1) mod e: e | p-1 (rem 0) or a shared
        // factor both make e non-invertible mod λ(n) — reject either way.
        const p_mod_e = bytesMod(out, e);
        const p1_mod_e = (p_mod_e + e - 1) % e; // no overflow: e < 2^32
        if (p1_mod_e == 0 or std.math.gcd(e, p1_mod_e) != 1) continue :candidates;

        // Odd, >= 3, <= max_modulus_len bytes: Modulus.fromBytes can't fail.
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

/// A freshly generated RSA keypair (`generate`'s result). The two halves are
/// returned together because a `SecretKey` alone cannot reproduce its
/// `PublicKey` — it does not store `e` (see `selfSignedCert`'s doc comment).
pub const KeyPair = struct {
    public_key: PublicKey,
    secret_key: SecretKey,
};

pub const GenerateError = error{
    /// `bits` is below 512, above `max_modulus_bits`, or odd.
    InvalidBits,
    /// `e` is even, < 3, or >= 2^32 (the same public-exponent cap
    /// `PublicKey.fromBytes` enforces — a key this module's own parsers
    /// would reject is never generated).
    InvalidExponent,
};

/// Generate a fresh RSA keypair with a modulus of exactly `bits` bits
/// (probable-prime search per the P5 section comment above + CRT parameter
/// derivation via `SecretKey.fromPrimes`). `e` is the public exponent —
/// pass the conventional 65537 unless there is a specific reason not to.
/// `random` MUST be a cryptographically secure generator for real keys
/// (the two primes are drawn straight from it); a seeded deterministic
/// generator is acceptable only for tests. `bits` must be even, between 512
/// and `max_modulus_bits`; expect roughly quadratic slowdown as `bits`
/// grows (2048+ is noticeably slow in Debug builds).
pub fn generate(random: std.Random, bits: usize, e: u64) GenerateError!KeyPair {
    if (bits < min_modulus_bits or bits > max_modulus_bits or bits % 2 != 0) return error.InvalidBits;
    if (e < 3 or e & 1 == 0 or e > std.math.maxInt(u32)) return error.InvalidExponent;

    const half = bits / 2;
    const half_len = byteLen(half);

    var e_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &e_bytes, e, .big);

    var p_buf: [max_modulus_len]u8 = undefined;
    defer std.crypto.secureZero(u8, p_buf[0..half_len]);
    var q_buf: [max_modulus_len]u8 = undefined;
    defer std.crypto.secureZero(u8, q_buf[0..half_len]);
    const p_bytes = p_buf[0..half_len];
    const q_bytes = q_buf[0..half_len];

    while (true) {
        generatePrime(random, half, e, p_bytes);
        while (true) {
            generatePrime(random, half, e, q_bytes);
            if (!topBitsMatch(p_bytes, q_bytes)) break;
        }

        // p ≠ q, gcd(e, p-1) = gcd(e, q-1) = 1 and both (probable) primes:
        // `fromPrimes` (P1) can only fail here if a Miller-Rabin false
        // positive slipped through (probability <= 2^-128 per prime) and
        // tripped its qInv self-check — restart the search instead of
        // surfacing an error for an input the caller never chose.
        const sk = SecretKey.fromPrimes(p_bytes, q_bytes, &e_bytes) catch continue;

        // Both primes have their top two bits set, so
        // n >= (3·2^(half-2))^2 = 9·2^(bits-4) > 2^(bits-1): exactly `bits`
        // bits, and `PublicKey.fromBytes`'s n/e validation (n odd and wide
        // enough, e odd, 3 <= e < 2^32) is satisfied by construction.
        var n_buf: [max_modulus_len]u8 = undefined;
        const n_len = byteLen(sk.n.bits());
        sk.n.toBytes(n_buf[0..n_len], .big) catch unreachable;
        const pk = PublicKey.fromBytes(n_buf[0..n_len], &e_bytes) catch unreachable;
        return .{ .public_key = pk, .secret_key = sk };
    }
}

// ── P6: X.509 v3 self-signed certificate generation (RFC 5280) ──────────────
//
// `selfSignedCert` builds `Certificate ::= SEQUENCE { tbsCertificate,
// signatureAlgorithm, signatureValue BIT STRING }` and signs it with
// `signPkcs1v15` (P1). The DER-encoding idiom below (`DerBuild`: an
// arena-backed bottom-up TLV builder — every helper returns a complete
// tag+length+value slice) is copied from `modules/acme/src/x509.zig`'s `Der`
// helper (which builds a PKCS#10 CSR, a structurally similar problem), not
// reimplemented from scratch; it is extended here with the extra primitive
// shapes a full certificate needs beyond a bare CSR: INTEGER (serial number,
// version), OCTET STRING + BOOLEAN (extension values), UTCTime (validity),
// UTF8String (commonName), and the `[n] EXPLICIT`/`[n] IMPLICIT`
// context-specific tags RFC 5280 uses for `version`/`extensions` and for
// `GeneralName` SAN choices. `zero-dep` still holds — nothing here is `pub
// use`d or `@import`ed from `acme`; the shape is copied by hand into this
// module, same as this file's own provenance note requires for its
// `std.crypto.ff`-derived shapes.
//
// `std.crypto.Certificate` (std's independent X.509 *parser*) is the primary
// test oracle: the tests below parse a generated certificate back with it
// and confirm `Parsed.verify` (issuer==subject, validity window, RSA
// signature) succeeds — proving the DER structure and the signature are
// both correct end-to-end, not just "well-formed enough to not crash." A
// second test walks the same DER with this module's own P4a-style bounds
// checked `Asn1.Element.decode` primitive (bypassing the `derElem`/`derChild`
// wrappers, which enforce a universal tag class that the certificate's
// context-specific `[0]`/`[3]` tags don't have) to independently recover the
// embedded SPKI (fed back through `PublicKey.fromDer`) and the signature
// (fed back through `verifyPkcs1v15`), so both directions of this module's
// own code are cross-checked, not only std's.

const DerCertError = error{ OutOfMemory, ValueTooLarge };

/// Arena-backed DER TLV builder (see the section doc comment above for
/// provenance: the idiom, not the source, is copied from
/// `modules/acme/src/x509.zig`'s `Der`). Every helper returns a complete TLV
/// slice allocated from `a`; use an arena and free it all at once.
const DerBuild = struct {
    a: std.mem.Allocator,

    fn encodeHeader(buf: *[4]u8, tag: u8, len: usize) DerCertError!usize {
        buf[0] = tag;
        if (len < 0x80) {
            buf[1] = @intCast(len);
            return 2;
        }
        if (len < 0x100) {
            buf[1] = 0x81;
            buf[2] = @intCast(len);
            return 3;
        }
        if (len < 0x10000) {
            buf[1] = 0x82;
            buf[2] = @intCast(len >> 8);
            buf[3] = @intCast(len & 0xff);
            return 4;
        }
        return error.ValueTooLarge; // nothing built in this module gets remotely this large
    }

    fn tlv(d: DerBuild, tag: u8, content: []const u8) DerCertError![]const u8 {
        var head: [4]u8 = undefined;
        const head_len = try encodeHeader(&head, tag, content.len);
        const out = try d.a.alloc(u8, head_len + content.len);
        @memcpy(out[0..head_len], head[0..head_len]);
        @memcpy(out[head_len..], content);
        return out;
    }

    fn cat(d: DerBuild, parts: []const []const u8) DerCertError![]const u8 {
        return std.mem.concat(d.a, u8, parts);
    }

    fn seq(d: DerBuild, parts: []const []const u8) DerCertError![]const u8 {
        return d.tlv(0x30, try d.cat(parts));
    }

    fn oid(d: DerBuild, encoded: []const u8) DerCertError![]const u8 {
        return d.tlv(0x06, encoded);
    }

    /// BIT STRING with zero unused bits.
    fn bitString(d: DerBuild, bytes: []const u8) DerCertError![]const u8 {
        return d.tlv(0x03, try d.cat(&.{ "\x00", bytes }));
    }

    fn octetString(d: DerBuild, bytes: []const u8) DerCertError![]const u8 {
        return d.tlv(0x04, bytes);
    }

    fn boolean(d: DerBuild, value: bool) DerCertError![]const u8 {
        return d.tlv(0x01, if (value) "\xff" else "\x00");
    }

    /// INTEGER from a big-endian magnitude (leading zeros tolerated and
    /// stripped first; a single 0x00 pad byte is (re)inserted whenever the
    /// top bit is set, since DER INTEGER is signed two's-complement and
    /// every value this module encodes — serials, version, modulus,
    /// exponent — is non-negative).
    fn integer(d: DerBuild, magnitude: []const u8) DerCertError![]const u8 {
        const m = stripLeadingZeros(magnitude);
        if (m.len == 0) return d.tlv(0x02, "\x00");
        if (m[0] & 0x80 != 0) return d.tlv(0x02, try d.cat(&.{ "\x00", m }));
        return d.tlv(0x02, m);
    }

    fn integerU64(d: DerBuild, value: u64) DerCertError![]const u8 {
        var buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf, value, .big);
        return d.integer(&buf);
    }

    /// UTCTime (RFC 5280 §4.1.2.5.1: two-digit year, `YYMMDDHHMMSSZ`).
    /// `text` must be exactly 13 bytes ending in 'Z' — enforced by the only
    /// caller (`selfSignedCert`, via `validUtcTime`) before this is reached.
    fn utcTime(d: DerBuild, text: []const u8) DerCertError![]const u8 {
        std.debug.assert(text.len == 13);
        return d.tlv(0x17, text);
    }

    fn utf8String(d: DerBuild, text: []const u8) DerCertError![]const u8 {
        return d.tlv(0x0c, text);
    }

    /// `[n] EXPLICIT ...`: a context-specific *constructed* tag wrapping a
    /// complete inner TLV (used for `version [0]` and `extensions [3]`).
    fn explicit(d: DerBuild, tag_num: u5, content: []const u8) DerCertError![]const u8 {
        return d.tlv(0xa0 | @as(u8, tag_num), content);
    }

    /// `[n] IMPLICIT ...`: a context-specific *primitive* tag carrying raw
    /// content directly (used for the `GeneralName` CHOICE alternatives:
    /// `dNSName [2]`, `uniformResourceIdentifier [6]`).
    fn implicitPrimitive(d: DerBuild, tag_num: u5, content: []const u8) DerCertError![]const u8 {
        return d.tlv(0x80 | @as(u8, tag_num), content);
    }
};

const der_null = "\x05\x00"; // NULL — AlgorithmIdentifier.parameters for rsaEncryption/sha*WithRSAEncryption

// sha*WithRSAEncryption OIDs (RFC 8017 Appendix C / RFC 4055 §5): the same
// 1.2.840.113549.1.1.* arc as `oid_rsa_encryption` above, differing only in
// the final arc (11/12/13). `std.crypto.Certificate.Algorithm.map` (see
// P4a's provenance note on that struct) recognizes exactly these three plus
// sha1/sha224/md2/md5 — only sha256/384/512 are offered here since RFC 8017
// (this module's whole provenance) has no opinion on MD2/MD5/SHA-1 being
// appropriate for *new* signatures, and P1's `signPkcs1v15` already restricts
// `Hash` at compile time via `digestInfoPrefix`'s exhaustive switch.
const oid_sha256_with_rsa_encryption = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b };
const oid_sha384_with_rsa_encryption = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c };
const oid_sha512_with_rsa_encryption = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d };

const oid_common_name = [_]u8{ 0x55, 0x04, 0x03 }; // 2.5.4.3
const oid_basic_constraints = [_]u8{ 0x55, 0x1d, 0x13 }; // 2.5.29.19
const oid_key_usage = [_]u8{ 0x55, 0x1d, 0x0f }; // 2.5.29.15
const oid_subject_alt_name = [_]u8{ 0x55, 0x1d, 0x11 }; // 2.5.29.17

/// sha256/384/512WithRSAEncryption OID content bytes for `Hash` (RFC 8017
/// Appendix C). X.509 signature-algorithm OIDs are a small fixed set, not a
/// per-call runtime choice, so an unsupported `Hash` is a compile error.
fn sigAlgOid(comptime Hash: type) []const u8 {
    const sha2 = std.crypto.hash.sha2;
    return switch (Hash) {
        sha2.Sha256 => &oid_sha256_with_rsa_encryption,
        sha2.Sha384 => &oid_sha384_with_rsa_encryption,
        sha2.Sha512 => &oid_sha512_with_rsa_encryption,
        else => @compileError("selfSignedCert: unsupported Hash (need sha256/384/512WithRSAEncryption): " ++ @typeName(Hash)),
    };
}

/// One `GeneralName` SAN entry this module can emit (RFC 5280 §4.2.1.6):
/// `dns_name` is `dNSName [2]`, `uri` is `uniformResourceIdentifier [6]`
/// (both IA5String/ASCII content) — the two alternatives `CertOptions` needs
/// today; an OPC-UA `applicationUri` is exactly a `.uri` value. Extending to
/// other `GeneralName` choices (`otherName`, `iPAddress`, ...) is a matter of
/// adding more `DerBuild.implicitPrimitive` calls in `buildSanExtnValue`
/// below — the extension hook the module-level doc asked for.
pub const SubjectAltName = union(enum) {
    dns_name: []const u8,
    uri: []const u8,
};

/// Parameters for `selfSignedCert`. `not_before`/`not_after` are
/// caller-supplied UTCTime strings rather than a clock read: Zig 0.16 has no
/// `std.time` timestamp API, and a certificate-generation library should
/// never silently assume a clock source anyway.
pub const CertOptions = struct {
    /// Subject/issuer commonName. The certificate is self-signed (issuer ==
    /// subject byte-for-byte), encoded as a single RDN, UTF8String-valued.
    common_name: []const u8,
    /// X.509 `serialNumber` (RFC 5280 §4.1.2.2: a positive integer, unique
    /// per issuer — uniqueness is the caller's responsibility, this module
    /// tracks no state). `u64` rather than an arbitrary byte string: every
    /// value fits in 8 bytes, and P6 is a self-signed-cert generator, not a
    /// general bignum-serial API.
    serial: u64 = 1,
    /// `notBefore`, UTCTime `"YYMMDDHHMMSSZ"` (RFC 5280 §4.1.2.5.1: exactly
    /// 13 bytes, two-digit year, trailing 'Z').
    not_before: []const u8,
    /// `notAfter`, same UTCTime shape as `not_before`.
    not_after: []const u8,
    /// basicConstraints `cA` (RFC 5280 §4.2.1.9). Also gates whether
    /// `keyCertSign`/`cRLSign` are set in the `keyUsage` extension.
    is_ca: bool = false,
    /// `subjectAltName` entries (RFC 5280 §4.2.1.6); the extension is
    /// omitted entirely when empty.
    subject_alt_names: []const SubjectAltName = &.{},
};

pub const SelfSignedCertError = error{
    /// `common_name` is empty, or `not_before`/`not_after` is not a
    /// 13-byte `"YYMMDDHHMMSSZ"` string.
    InvalidCertOptions,
} || DerCertError || SignPkcs1v15Error;

/// RFC 5280 §4.1.2.5.1 UTCTime shape: exactly `YYMMDDHHMMSSZ` (13 bytes, all
/// ASCII digits except the trailing 'Z'). Calendar validity (day-of-month
/// bounds etc.) is not checked here — a garbage-but-shaped string still
/// yields a syntactically valid, if semantically wrong, certificate;
/// `std.crypto.Certificate`'s own `parseTimeDigits` bounds-checks the digits
/// again on the parse side (see the P6 tests).
fn validUtcTime(text: []const u8) bool {
    if (text.len != 13 or text[12] != 'Z') return false;
    for (text[0..12]) |c| {
        if (c < '0' or c > '9') return false;
    }
    return true;
}

/// `Name ::= RDNSequence` with a single RDN carrying one
/// `AttributeTypeAndValue { commonName, UTF8String }` — used for both
/// `issuer` and `subject` (self-signed: identical bytes, reused verbatim).
fn buildNameCn(d: DerBuild, common_name: []const u8) DerCertError![]const u8 {
    const atv = try d.seq(&.{ try d.oid(&oid_common_name), try d.utf8String(common_name) });
    const rdn = try d.tlv(0x31, atv); // RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
    return d.seq(&.{rdn}); // RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
}

/// `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`
/// (PKCS#1 Appendix A.1.1) — the same shape P4a's `publicKeyFromDerImpl`
/// parses, built here instead of parsed.
fn buildRsaPublicKeyDer(d: DerBuild, pk: PublicKey) DerCertError![]const u8 {
    var n_buf: [max_modulus_len]u8 = undefined;
    pk.n.toBytes(&n_buf, .big) catch unreachable; // n is its own modulus: always fits its own byte length
    var e_buf: [max_modulus_len]u8 = undefined;
    pk.e.toBytes(&e_buf, .big) catch unreachable; // e < n, so it fits n's byte length too

    return d.seq(&.{
        try d.integer(&n_buf),
        try d.integer(&e_buf),
    });
}

/// `SubjectPublicKeyInfo ::= SEQUENCE { AlgorithmIdentifier, BIT STRING }`
/// wrapping a `buildRsaPublicKeyDer` value under the `rsaEncryption` OID
/// (RFC 8017 Appendix C) — the SPKI shape P4a's `publicKeyFromDerImpl` also
/// parses (and what `PublicKey.fromDer` on the extracted bytes round-trips
/// through in the tests below).
fn buildSpki(d: DerBuild, pk: PublicKey) DerCertError![]const u8 {
    const rsa_pub_key_der = try buildRsaPublicKeyDer(d, pk);
    return d.seq(&.{
        try d.seq(&.{ try d.oid(&oid_rsa_encryption), der_null }),
        try d.bitString(rsa_pub_key_der),
    });
}

/// `GeneralNames ::= SEQUENCE OF GeneralName` — the `subjectAltName`
/// extension's `extnValue` payload (RFC 5280 §4.2.1.6).
fn buildSanExtnValue(d: DerBuild, sans: []const SubjectAltName) DerCertError![]const u8 {
    const names = try d.a.alloc([]const u8, sans.len);
    for (names, sans) |*slot, san| slot.* = switch (san) {
        .dns_name => |name| try d.implicitPrimitive(2, name),
        .uri => |uri| try d.implicitPrimitive(6, uri),
    };
    return d.seq(names);
}

/// `KeyUsage ::= BIT STRING` (RFC 5280 §4.2.1.3) with `digitalSignature`
/// (bit 0) always set, plus `keyCertSign` (bit 5) and `cRLSign` (bit 6) for
/// a CA certificate. DER's minimal BIT STRING encoding drops trailing
/// zero *bits* by recording how many of the last content byte's low bits
/// are unused (X.690 §11.2.7); `@ctz` of the single content byte is exactly
/// that count for a one-byte KeyUsage value.
fn keyUsageBitString(d: DerBuild, is_ca: bool) DerCertError![]const u8 {
    const byte: u8 = if (is_ca) 0x86 else 0x80; // digitalSignature | (keyCertSign | cRLSign if CA)
    const unused: u8 = @ctz(byte);
    return d.tlv(0x03, try d.cat(&.{ &.{unused}, &.{byte} }));
}

/// `extensions [3] EXPLICIT Extensions` (RFC 5280 §4.1.2.9): always
/// `basicConstraints` (critical, `cA` per `opts.is_ca`) and `keyUsage`
/// (critical); `subjectAltName` (not critical) if `opts.subject_alt_names`
/// is non-empty.
fn buildExtensions(d: DerBuild, opts: CertOptions) DerCertError![]const u8 {
    var list: std.ArrayList([]const u8) = .empty;

    const basic_constraints_value = if (opts.is_ca)
        try d.seq(&.{try d.boolean(true)}) // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, ... }
    else
        try d.seq(&.{}); // cA defaults to FALSE: an empty SEQUENCE says exactly that
    try list.append(d.a, try d.seq(&.{
        try d.oid(&oid_basic_constraints),
        try d.boolean(true), // critical
        try d.octetString(basic_constraints_value),
    }));

    try list.append(d.a, try d.seq(&.{
        try d.oid(&oid_key_usage),
        try d.boolean(true), // critical
        try d.octetString(try keyUsageBitString(d, opts.is_ca)),
    }));

    if (opts.subject_alt_names.len > 0) {
        try list.append(d.a, try d.seq(&.{
            try d.oid(&oid_subject_alt_name),
            try d.octetString(try buildSanExtnValue(d, opts.subject_alt_names)),
        }));
    }

    return d.explicit(3, try d.seq(list.items));
}

/// Generate a self-signed X.509 v3 certificate (RFC 5280) for `sk`/`pk`
/// (the caller-supplied `pk` must be the public key matching `sk` — this is
/// not re-derived from `sk`, since `SecretKey` carries no cached `e`),
/// signed with RSASSA-PKCS1-v1_5 over `Hash` (`signPkcs1v15`, P1). Returns
/// `gpa`-owned DER bytes (`Certificate ::= SEQUENCE { tbsCertificate,
/// signatureAlgorithm, signatureValue BIT STRING }`); an owned-slice return
/// (mirroring `modules/acme/src/x509.zig`'s `csrDer`) is the natural shape
/// here rather than a fixed `out` buffer, since the encoded length varies
/// with `common_name`/SAN content and the caller has no simple formula to
/// pre-size a buffer for that.
pub fn selfSignedCert(
    gpa: std.mem.Allocator,
    sk: SecretKey,
    pk: PublicKey,
    comptime Hash: type,
    opts: CertOptions,
) SelfSignedCertError![]u8 {
    if (opts.common_name.len == 0) return error.InvalidCertOptions;
    if (!validUtcTime(opts.not_before) or !validUtcTime(opts.not_after)) return error.InvalidCertOptions;

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const d: DerBuild = .{ .a = arena.allocator() };

    const name = try buildNameCn(d, opts.common_name); // issuer == subject: built once, reused twice below
    const version = try d.explicit(0, try d.integerU64(2)); // v3
    const serial = try d.integerU64(opts.serial);
    const sig_alg_id = try d.seq(&.{ try d.oid(sigAlgOid(Hash)), der_null });
    const validity = try d.seq(&.{ try d.utcTime(opts.not_before), try d.utcTime(opts.not_after) });
    const spki = try buildSpki(d, pk);
    const extensions = try buildExtensions(d, opts);

    const tbs_certificate = try d.seq(&.{
        version,
        serial,
        sig_alg_id,
        name, // issuer
        validity,
        name, // subject
        spki,
        extensions,
    });

    // `signPkcs1v15`'s `out` must be at least the modulus length; `sk.n` is
    // bounded by `max_modulus_bits` by construction (every `SecretKey`
    // constructor routes through `Modulus.fromBytes`/`fromPrimitive`, which
    // reject wider moduli), so a `max_modulus_len` stack buffer always
    // suffices — `signPkcs1v15`'s own `BufferTooSmall` is therefore
    // unreachable in practice but stays in `SelfSignedCertError` for type
    // honesty (it is `signPkcs1v15`'s real error set).
    var sig_buf: [max_modulus_len]u8 = undefined;
    const sig = try signPkcs1v15(sk, Hash, tbs_certificate, &sig_buf);

    const cert = try d.seq(&.{
        tbs_certificate,
        sig_alg_id, // RFC 5280 §4.1.1.2: MUST repeat tbsCertificate.signature verbatim
        try d.bitString(sig),
    });
    return gpa.dupe(u8, cert);
}

// ── tests ────────────────────────────────────────────────────────────────────
//
// CONVENTIONS.md "dark-tests" rule: openssh.zig's tests only run if the file
// is referenced from a `test { _ = ...; }` block here.
test {
    _ = openssh;
}

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
// * OpenSSH fixtures: one locally generated 2048-bit keypair stored three
//   ways by ssh-keygen (OpenSSH_10.2p1 Ubuntu-2ubuntu3.2, OpenSSL 3.5.5,
//   2026-07-10): unencrypted, aes256-ctr + bcrypt, aes256-cbc + bcrypt —
//   see the fixture comment below for the exact commands. Blowfish and
//   bcrypt-pbkdf vector provenance lives in openssh.zig.

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

test "SecretKey.deinit zeroes all key material (audit F4)" {
    var sk = try SecretKey.fromPrimes(&.{61}, &.{53}, &.{17});
    const bytes = std.mem.asBytes(&sk);
    var any_nonzero = false;
    for (bytes) |b| {
        if (b != 0) any_nonzero = true;
    }
    try testing.expect(any_nonzero); // key material present before wipe
    sk.deinit();
    for (bytes) |b| try testing.expectEqual(@as(u8, 0), b); // fully zeroed after
}

test "rsaep/rsadp/rsadpCrt textbook KAT and round-trip" {
    const sk = try SecretKey.fromPrimes(&.{61}, &.{53}, &.{17});
    const pk = PublicKey{ .n = sk.n, .e = try Fe.fromPrimitive(u32, sk.n, 17), .n_mont = sk.n_mont };

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
    const pk = PublicKey{ .n = sk.n, .e = try Fe.fromPrimitive(u32, sk.n, 17), .n_mont = sk.n_mont };
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

// audit F3 — Bellcore/BDL fault-injection countermeasure. A persistent fault
// in one CRT exponent (`dP`) makes the recovered `m` fail the `m^e ≡ c` re-
// encryption check, so the op must return `error.FaultDetected` instead of the
// factoring-oracle value. RED if the F3 check is removed from `privateOpCrt`.
test "privateOpCrt Bellcore check rejects a faulted CRT half (audit F3)" {
    var sk = try SecretKey.fromPrimes(&kat512.p, &kat512.q, &kat512.e);
    const k = byteLen(sk.n.bits());

    // A representative safely < n (top byte zero).
    var msg: [max_modulus_len]u8 = undefined;
    @memset(msg[0..k], 0);
    msg[k - 1] = 0x2a;

    var out: [max_modulus_len]u8 = undefined;
    // Baseline: the intact key produces a value and passes the check.
    try privateOpCrt(sk, msg[0..k], out[0..k], .none);

    // Inject a persistent single-half fault: dP <- dP + 1 (mod p). Now
    // m1 = c^(dP+1) mod p is wrong, so the recombined m ≢ c^d and m^e ≢ c.
    sk.dp = sk.p.add(sk.dp, sk.p.one());
    try testing.expectError(error.FaultDetected, privateOpCrt(sk, msg[0..k], out[0..k], .none));

    // Same rejection on the blinded path (blinding must not mask a real fault).
    var prng = std.Random.DefaultPrng.init(0xfa17_1717_c0de_0003);
    try testing.expectError(error.FaultDetected, privateOpCrt(sk, msg[0..k], out[0..k], .{ .csprng = prng.random() }));
}

// A faulted key also fails at the public sign entry points (fault propagates as
// error.FaultDetected, never a silent bad signature).
test "signPkcs1v15 surfaces a CRT fault as error.FaultDetected (audit F3)" {
    var sk = try kat2048.secretKey();
    sk.dq = sk.q.add(sk.dq, sk.q.one()); // fault the other CRT half this time
    var out: [max_modulus_len]u8 = undefined;
    try testing.expectError(error.FaultDetected, signPkcs1v15(sk, std.crypto.hash.sha2.Sha256, "faulted", &out));
}

// audit F2 — CRT base blinding. The blinded op (rng supplied) must round-trip to
// exactly the unblinded result across key sizes, and repeated blinded runs must
// agree (masking is unblinded before output). Also cross-checks m^e ≡ c via the
// public key. Uses the internal `privateOpCrt` since the public primitives are
// deterministic (null rng).
test "CRT base blinding round-trips and matches the unblinded result (audit F2)" {
    var prng = std.Random.DefaultPrng.init(0xb11d_0000_5eed_0002);
    const random = prng.random();

    const sk512 = try SecretKey.fromPrimes(&kat512.p, &kat512.q, &kat512.e);
    const sk2048 = try kat2048.secretKey();
    for ([_]SecretKey{ sk512, sk2048 }) |sk| {
        const k = byteLen(sk.n.bits());
        var msg: [max_modulus_len]u8 = undefined;
        random.bytes(msg[0..k]);
        msg[0] = 0; // representative < n (n's top byte is nonzero)

        var out_plain: [max_modulus_len]u8 = undefined;
        var out_blind1: [max_modulus_len]u8 = undefined;
        var out_blind2: [max_modulus_len]u8 = undefined;
        try privateOpCrt(sk, msg[0..k], out_plain[0..k], .none);
        try privateOpCrt(sk, msg[0..k], out_blind1[0..k], .{ .csprng = random });
        try privateOpCrt(sk, msg[0..k], out_blind2[0..k], .{ .csprng = random });
        // Blinding with two independent random r's yields the same plaintext.
        try testing.expectEqualSlices(u8, out_plain[0..k], out_blind1[0..k]);
        try testing.expectEqualSlices(u8, out_plain[0..k], out_blind2[0..k]);

        // Cross-check: re-encrypting the blinded output recovers the input.
        const pk = PublicKey{ .n = sk.n, .e = sk.e, .n_mont = sk.n_mont };
        var recovered: [max_modulus_len]u8 = undefined;
        try publicOp(pk, out_blind1[0..k], recovered[0..k]);
        try testing.expectEqualSlices(u8, msg[0..k], recovered[0..k]);
    }
}

// ── B6 RNG-seam pins (2026-08-12) ─────────────────────────────────────
//
// R1 was: F2 base blinding existed (`makeBlinding`) but the three private-key
// entry points that run over ATTACKER-CHOSEN input — `decryptOaep`,
// `decryptOaepH`, `signPkcs1v15` (and the `rsadpCrt` primitive) — hard-coded
// `privateOpCrt(…, null)`, and the public API had no parameter through which a
// consumer could turn it on. The default is unchanged (see `Blinding`); what
// changed is that there is now a way to ask, and the choice has a name.

test "Blinding: exactly two arms, and the unblinded one is a name rather than a null" {
    const info = @typeInfo(Blinding).@"union";
    try testing.expectEqual(@as(usize, 2), info.fields.len);
    try testing.expectEqualStrings("csprng", info.fields[0].name);
    try testing.expectEqualStrings("none", info.fields[1].name);
    // `.none` carries no payload — it is a decision, not an absent argument.
    try testing.expectEqual(void, info.fields[1].type);

    var prng = std.Random.DefaultPrng.init(0xb11d_0000_5eed_0009);
    const on: Blinding = .{ .csprng = prng.random() };
    const off: Blinding = .none;
    try testing.expect(on.rng() != null);
    try testing.expect(off.rng() == null);
}

test "the blinded twins reach makeBlinding from the PUBLIC API, and produce identical output (audit R1)" {
    const sk = try kat2048.secretKey();
    const pk = try kat2048.publicKey();
    const k = byteLen(sk.n.bits());
    const Sha256 = std.crypto.hash.sha2.Sha256;

    // Two generators in the same state. Every case below drives one of them
    // through a `…Blinded` entry point and leaves the other untouched: if the
    // generator never reaches `makeBlinding`, the two states stay equal and
    // the assertion fails. That is what pins "the knob is wired", as opposed
    // to "the knob exists".
    const seed = 0xb11d_0000_5eed_000a;
    var used = std.Random.DefaultPrng.init(seed);
    var untouched = std.Random.DefaultPrng.init(seed);
    const drawnFrom = struct {
        fn check(a: *std.Random.DefaultPrng, b: *std.Random.DefaultPrng) !void {
            try testing.expect(!std.mem.eql(u8, std.mem.asBytes(a), std.mem.asBytes(b)));
        }
    }.check;

    // (1) OAEP decrypt — the network-facing oracle this finding is about.
    var seed_rng = std.Random.DefaultPrng.init(0x0ae9_5eed_0001);
    const secret = "attacker cannot choose this, but they choose the ciphertext";
    var ct: [max_modulus_len]u8 = undefined;
    const ct_slice = try encryptOaep(pk, Sha256, seed_rng.random(), secret, "", ct[0..k]);

    var plain_unblinded: [max_modulus_len]u8 = undefined;
    var plain_blinded: [max_modulus_len]u8 = undefined;
    const got_unblinded = try decryptOaep(sk, Sha256, ct_slice, "", &plain_unblinded);
    const got_blinded = try decryptOaepBlinded(sk, Sha256, .{ .csprng = used.random() }, ct_slice, "", &plain_blinded);
    try testing.expectEqualSlices(u8, secret, got_unblinded);
    try testing.expectEqualSlices(u8, secret, got_blinded);
    try drawnFrom(&used, &untouched);

    // The decoupled-hash twin is the one every other OAEP path funnels
    // through, so it gets its own case rather than riding on the wrapper.
    used = std.Random.DefaultPrng.init(seed);
    const got_h = try decryptOaepHBlinded(sk, Sha256, Sha256, .{ .csprng = used.random() }, ct_slice, "", &plain_blinded);
    try testing.expectEqualSlices(u8, secret, got_h);
    try drawnFrom(&used, &untouched);

    // A blinded decrypt of a CORRUPTED ciphertext must still fail closed with
    // the same generic error — blinding must not become an oracle of its own.
    var bad: [max_modulus_len]u8 = undefined;
    @memcpy(bad[0..k], ct_slice);
    bad[k - 1] ^= 0x01;
    try testing.expectError(error.DecryptionError, decryptOaepBlinded(sk, Sha256, .{ .csprng = used.random() }, bad[0..k], "", &plain_blinded));

    // (2) PKCS#1 v1.5 signing — deterministic by definition, so the emitted
    // signature must be byte-identical with the masking on. It is also the
    // published KAT value, so this doubles as an anchor check.
    used = std.Random.DefaultPrng.init(seed);
    var sig_plain: [max_modulus_len]u8 = undefined;
    var sig_blind: [max_modulus_len]u8 = undefined;
    const s_plain = try signPkcs1v15(sk, Sha256, kat2048.msg, &sig_plain);
    const s_blind = try signPkcs1v15Blinded(sk, Sha256, .{ .csprng = used.random() }, kat2048.msg, &sig_blind);
    try testing.expectEqualSlices(u8, &kat2048.sig_sha256, s_plain);
    try testing.expectEqualSlices(u8, s_plain, s_blind);
    try drawnFrom(&used, &untouched);

    // (3) The raw CRT primitive.
    used = std.Random.DefaultPrng.init(seed);
    var c_fixed: [256]u8 = @splat(0);
    c_fixed[255] = 0x2a;
    const m_plain = try rsadpCrt(256, c_fixed, sk);
    const m_blind = try rsadpCrtBlinded(256, c_fixed, sk, .{ .csprng = used.random() });
    try testing.expectEqualSlices(u8, &m_plain, &m_blind);
    try drawnFrom(&used, &untouched);
}

// The doc half of the finding: `encryptOaep` stated the CSPRNG requirement and
// its decoupled-hash twin `encryptOaepH` did not, even though the seed it
// draws is the same seed with the same consequence. Pinned against the source
// text so the two cannot drift apart again silently. The needle is assembled
// from fragments so this test cannot match its own source.
test "doc: both OAEP encrypt entry points state the CSPRNG requirement" {
    const src = @embedFile("root.zig");
    // Both needles are assembled from fragments so this test cannot match its
    // own source text.
    const decl = "pub fn " ++ "encryptOaep";
    const needle = "MUST be " ++ "cryptographically";

    const at0 = std.mem.indexOf(u8, src, decl).?;
    const at1 = std.mem.indexOfPos(u8, src, at0 + decl.len, decl).?;
    try testing.expect(std.mem.indexOfPos(u8, src, at1 + decl.len, decl) == null); // exactly two

    // The requirement must sit in the doc block immediately BEFORE each
    // declaration. The second window starts at the END of the first
    // declaration, so `encryptOaep`'s own doc cannot satisfy `encryptOaepH`.
    try testing.expect(std.mem.indexOf(u8, src[at0 -| 1600..at0], needle) != null);
    try testing.expect(std.mem.indexOf(u8, src[at0 + decl.len .. at1], needle) != null);
}

// Regression for the montint-rewire CRIT: a sub-max key driven through the
// max-width primitive path (`modulus_len == max_modulus_len`, the way blindrsa
// calls rsavp1/rsasp1) must LEFT-ZERO-PAD the narrower montint result into the
// wider output instead of asserting `res.len >= out.len`. Before the fix,
// `writeMontResult` hit `reached unreachable` here for every key < 4096 bits.
test "widening path: 2048-bit key through max_modulus_len primitives (writeMontResult zero-pad)" {
    const sk = try kat2048.secretKey();
    const pk = try kat2048.publicKey();
    const k = 256; // 2048-bit modulus byte length
    comptime std.debug.assert(max_modulus_len > k); // the widening case must be real

    // A representative < n, presented left-zero-padded to the full max width
    // (exactly what OS2IP of a sub-max value into a max-width buffer yields).
    var m_wide = [_]u8{0} ** max_modulus_len;
    for (m_wide[max_modulus_len - k ..], 0..) |*b, i| b.* = @truncate(i *% 37 +% 11);
    m_wide[max_modulus_len - k] = 0; // keep the representative < n

    // Sign at max width (rsasp1 -> CRT private op) then verify at max width
    // (rsavp1 -> publicOp -> writeMontResult, the exact crash site): the
    // round-trip m -> s^d -> s^e must recover the original representative.
    const s_wide = try rsasp1(max_modulus_len, m_wide, sk);
    // High bytes above the modulus width must be zero (big-endian left pad).
    try testing.expect(std.mem.allEqual(u8, s_wide[0 .. max_modulus_len - k], 0));
    const back = try rsavp1(max_modulus_len, s_wide, pk);
    try testing.expect(std.mem.allEqual(u8, back[0 .. max_modulus_len - k], 0));
    try testing.expectEqualSlices(u8, &m_wide, &back);

    // Cross-check: signing at the key's NATURAL width yields the identical
    // low-k bytes — the max-width path only prepends leading zeros.
    const s_narrow = try rsasp1(k, m_wide[max_modulus_len - k ..].*, sk);
    try testing.expectEqualSlices(u8, s_wide[max_modulus_len - k ..], &s_narrow);
    // And rsaep at max width round-trips through rsadp (public/private widen).
    const c_wide = try rsaep(max_modulus_len, m_wide, pk);
    const dec = try rsadp(max_modulus_len, c_wide, sk);
    try testing.expectEqualSlices(u8, &m_wide, &dec);
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

test "encryptOaepH/decryptOaepH decoupled hash (LabelHash != MgfHash)" {
    // CONSTRUCTED round-trip, NOT an external byte-exact KAT. Config: OAEP
    // digest/label hash = SHA-256, MGF1 hash = SHA-1 — the digest≠MGF pairing
    // that real-world XML-Encryption `rsa-oaep` sometimes specifies. RFC 8017
    // §7.1 treats the label/digest hash and the MGF1 hash as independent
    // parameters; `encryptOaepH`/`decryptOaepH` expose that split. The bundled
    // OpenSSL OAEP KATs above are all equal-hash (rsa_oaep_md == rsa_mgf1_md),
    // so no external mismatched-hash vector is shipped here; this proves the
    // round-trip and that the resulting padding is genuinely distinct from the
    // coupled (equal-hash) construction.
    const sk = try kat2048.secretKey();
    const pk = try kat2048.publicKey();
    const Sha256 = std.crypto.hash.sha2.Sha256;
    const Sha1 = std.crypto.hash.Sha1;
    var prng = std.Random.DefaultPrng.init(0x6f6165705f68); // deterministic: tests only
    const random = prng.random();
    var ct: [max_modulus_len]u8 = undefined;
    var pt: [max_modulus_len]u8 = undefined;

    inline for (.{ "", "xmlenc-label" }) |label| {
        for ([_][]const u8{ "", "digest != mgf oaep", "x" }) |msg| {
            const c = try encryptOaepH(pk, Sha256, Sha1, random, msg, label, &ct);
            try testing.expectEqual(256, c.len);
            const m = try decryptOaepH(sk, Sha256, Sha1, c, label, &pt);
            try testing.expectEqualSlices(u8, msg, m);

            // The mismatched-hash ciphertext is a genuinely different padding:
            // the coupled (equal-hash) decrypt cannot decode it under either
            // the digest hash or the MGF hash.
            try testing.expectError(error.DecryptionError, decryptOaep(sk, Sha256, c, label, &pt));
            try testing.expectError(error.DecryptionError, decryptOaep(sk, Sha1, c, label, &pt));
        }
    }

    // Constant-time posture preserved: a wrong label or a corrupted ciphertext
    // still collapses to the single generic error (never a distinct one).
    const secret = try encryptOaepH(pk, Sha256, Sha1, random, "top secret", "right", &ct);
    try testing.expectError(error.DecryptionError, decryptOaepH(sk, Sha256, Sha1, secret, "wrong", &pt));
    var corrupt: [256]u8 = undefined;
    @memcpy(&corrupt, secret);
    corrupt[100] ^= 0x40;
    try testing.expectError(error.DecryptionError, decryptOaepH(sk, Sha256, Sha1, &corrupt, "right", &pt));

    // Wrapper equivalence: with LabelHash == MgfHash and the SAME seed,
    // encryptOaepH is byte-identical to the coupled encryptOaep — the coupled
    // path adds nothing over delegating to the decoupled form.
    var pa = std.Random.DefaultPrng.init(7);
    var pb = std.Random.DefaultPrng.init(7);
    var ca: [max_modulus_len]u8 = undefined;
    var cb: [max_modulus_len]u8 = undefined;
    const c_coupled = try encryptOaep(pk, Sha256, pa.random(), "wrapper-equiv", "L", &ca);
    const c_decoupled = try encryptOaepH(pk, Sha256, Sha256, pb.random(), "wrapper-equiv", "L", &cb);
    try testing.expectEqualSlices(u8, c_coupled, c_decoupled);
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

// ── P4a (DER/PEM key parsing) tests ──────────────────────────────────────────
//
// Fixture provenance: the SAME 2048-bit key as `kat2048` above (identical
// p/q/e/d/dP/dQ/qInv) re-serialized to DER/PEM with OpenSSL 3.5.5
// (2026-07-10):
//   1. `kat2048`'s components were hand-encoded into a PKCS#1 `RSAPrivateKey`
//      DER (plain ASN.1 SEQUENCE-of-INTEGER TLV encoding; no ASN.1 library
//      involved in that one step) and round-tripped through
//      `openssl rsa -inform der -check -text` to confirm OpenSSL reconstructs
//      the exact same key (n/d/dP/dQ/qInv all matched `kat2048` byte-for-byte)
//      — this is the `priv_pkcs1`/`priv_pkcs1` fixture below.
//   2. `openssl pkcs8 -topk8 -nocrypt -inform der -in <1> -outform der|pem`
//      -> the PKCS#8 (`priv_pkcs8`) fixtures.
//   3. `openssl rsa -inform der -in <1> -pubout -outform der|pem`
//      -> the X.509 SubjectPublicKeyInfo (`pub_spki`) fixtures.
//   4. `openssl rsa -inform der -in <1> -RSAPublicKey_out -outform der|pem`
//      -> the PKCS#1 `RSAPublicKey` (`pub_pkcs1`) fixtures.
// Every fixture below therefore decodes to the exact `kat2048` n/e/p/q/d, and
// `signPkcs1v15`/`verifyPkcs1v15` KATs from the `kat2048` block above are
// reused as round-trip oracles.

const kat2048_der = struct {
    // openssl rsa -in kat2048.der -inform der -traditional -outform der
    const priv_pkcs1 = hexLit("308204a30201000282010100a2056f805f21fbf8815681fc5f7bb07bb8c7cba3be6e10ef3c3905981d666aa60adde3a7ebd258efae4e0d120e109c42cde35c6c322287135644e25eb79640aa91bc69a63b96fc3a72d85641cf567f4d4775c70c11d3c319989e764bc94c68002eb159d8fb05b73cafe489fb33b99e8f58ada35d59577e657f5097bb0e7a3f53e74b3592dbb31772092b96ab5aac70cef3b2afb54d1a35da41e895222c898f0306f9cd9ecb5b4e3bee111dcd5bfc44b976e7620b0e01b3072d0d3f5e995dcf20aa78d6633ef658bc1468f311ac4e6e005b2cf37d18f82cdc661f7d8cbd93709a4c122dd732bd243632b4a9d51da2f1d3c677a54d0f36c8f8458165d2fefe9203020301000102820100181979e1323002643a37780f3b7ea647738fedbceb42eb96ecdcc875bcb872ad99ae86972acf22211df55dcc028be59fa988a398890934bbf8c2e1ef027216d2a83f1fc734fee62bfad02e086242f49d8b3f11693caf99ca1161a4a9423070c4722d8ecbe50eba6ce1a190afecf233b66668dc2f5d98d38eb2562108ec5987ae02819c97d0a2f60afa32d471766acdb8358b9a61cd8d4d4e1cd98aaa1193217558fb466be20ea48eda646929332e19c887f78ba423d573d44d05e74ce9757c79a59fb0377cace9e65f915b93dcc5b95fdc9cf026ab0ae69b48beed0e0238266b250ed55aa4e4bbf19ac8076a96a16e86b04058e565af55d8fc82726668d3062d02818100cd91a6496cfb79576c073ddea09edc423deebdaa3b103017d00572ebb61b1a05b9e7340239fd8019790b76ec74233842f786d620f80362ca455e6c0b26859db9e5c50d71c551759ffd2ef2facc98c10d6c2e8e0662a5d25a0d847c4fc54a062fc4bb75c552ae1cdef197916cd81c4dd102f314a8a4eb8c73c5c6b3e85c40a11d02818100c9c4dbb594569066caaaadbf5be98990357e0ea3d3619601b2155bac8ed96b28d6eec9578163dd3b08e0132a0f91a99c98a139b3e7b016f7e83dfe6e18d97b4448dccab617a3ac3aa6aa1359c3f5396473f4b0b20038252ae1d77e8cdf1fce2a9f4ea3208269f79d516e7b9a22e2fe4b4dad87621173348f896e2303cae5b59f02818001cceac5eddc6dfda406943624f5ff3bdd4b000243ae2a9daac6c170eb1165b2f323e142bbbb4aa9ee7379412ceb3a0cec1a143a09b20de573a216142aec34ab7225bdae676a053bb77df7c6d68fe7f0f4279c3ad61659b74c3302dbb800a3f93b21e1302f3f332588bc291be8f0a685d41ec8e989383eecaca8c6de9c203cc90281801fe07c1db9ebdb30824068e6dcac8ed13bc248a9d5518b9385011ed4aa54eb3b2e89d7417dedbb1c0290f43626f38a6a752ab3a51aab95556159ba02c6e645354a95a769115f086cd3bbf706ad90e69a5a3f8452faf9e3d55c8ce12f7c68d7f79fe79a9a1e4083a05527315beebb1215ef95c4d7d78dedf5e76e8115ae4e905d0281810099437ab1bf00d96eccd75400da8411fdc353abcf7ff206668e056bd3dff642233cd0b6758daa0f6a651fcc2f6a160e0e5daa37393627627667a3e4391633e46c2a6dec7b1f3cca7647d7294f34a3fe104ac106ee34045c0ad1c97ed23b17fe1f7bce97b1cbd633f86912a17055e96ae4c6c565975b38def64419f645db7b14d2");
    // openssl pkcs8 -topk8 -nocrypt -in kat2048.der -inform der -outform der
    const priv_pkcs8 = hexLit("308204bd020100300d06092a864886f70d0101010500048204a7308204a30201000282010100a2056f805f21fbf8815681fc5f7bb07bb8c7cba3be6e10ef3c3905981d666aa60adde3a7ebd258efae4e0d120e109c42cde35c6c322287135644e25eb79640aa91bc69a63b96fc3a72d85641cf567f4d4775c70c11d3c319989e764bc94c68002eb159d8fb05b73cafe489fb33b99e8f58ada35d59577e657f5097bb0e7a3f53e74b3592dbb31772092b96ab5aac70cef3b2afb54d1a35da41e895222c898f0306f9cd9ecb5b4e3bee111dcd5bfc44b976e7620b0e01b3072d0d3f5e995dcf20aa78d6633ef658bc1468f311ac4e6e005b2cf37d18f82cdc661f7d8cbd93709a4c122dd732bd243632b4a9d51da2f1d3c677a54d0f36c8f8458165d2fefe9203020301000102820100181979e1323002643a37780f3b7ea647738fedbceb42eb96ecdcc875bcb872ad99ae86972acf22211df55dcc028be59fa988a398890934bbf8c2e1ef027216d2a83f1fc734fee62bfad02e086242f49d8b3f11693caf99ca1161a4a9423070c4722d8ecbe50eba6ce1a190afecf233b66668dc2f5d98d38eb2562108ec5987ae02819c97d0a2f60afa32d471766acdb8358b9a61cd8d4d4e1cd98aaa1193217558fb466be20ea48eda646929332e19c887f78ba423d573d44d05e74ce9757c79a59fb0377cace9e65f915b93dcc5b95fdc9cf026ab0ae69b48beed0e0238266b250ed55aa4e4bbf19ac8076a96a16e86b04058e565af55d8fc82726668d3062d02818100cd91a6496cfb79576c073ddea09edc423deebdaa3b103017d00572ebb61b1a05b9e7340239fd8019790b76ec74233842f786d620f80362ca455e6c0b26859db9e5c50d71c551759ffd2ef2facc98c10d6c2e8e0662a5d25a0d847c4fc54a062fc4bb75c552ae1cdef197916cd81c4dd102f314a8a4eb8c73c5c6b3e85c40a11d02818100c9c4dbb594569066caaaadbf5be98990357e0ea3d3619601b2155bac8ed96b28d6eec9578163dd3b08e0132a0f91a99c98a139b3e7b016f7e83dfe6e18d97b4448dccab617a3ac3aa6aa1359c3f5396473f4b0b20038252ae1d77e8cdf1fce2a9f4ea3208269f79d516e7b9a22e2fe4b4dad87621173348f896e2303cae5b59f02818001cceac5eddc6dfda406943624f5ff3bdd4b000243ae2a9daac6c170eb1165b2f323e142bbbb4aa9ee7379412ceb3a0cec1a143a09b20de573a216142aec34ab7225bdae676a053bb77df7c6d68fe7f0f4279c3ad61659b74c3302dbb800a3f93b21e1302f3f332588bc291be8f0a685d41ec8e989383eecaca8c6de9c203cc90281801fe07c1db9ebdb30824068e6dcac8ed13bc248a9d5518b9385011ed4aa54eb3b2e89d7417dedbb1c0290f43626f38a6a752ab3a51aab95556159ba02c6e645354a95a769115f086cd3bbf706ad90e69a5a3f8452faf9e3d55c8ce12f7c68d7f79fe79a9a1e4083a05527315beebb1215ef95c4d7d78dedf5e76e8115ae4e905d0281810099437ab1bf00d96eccd75400da8411fdc353abcf7ff206668e056bd3dff642233cd0b6758daa0f6a651fcc2f6a160e0e5daa37393627627667a3e4391633e46c2a6dec7b1f3cca7647d7294f34a3fe104ac106ee34045c0ad1c97ed23b17fe1f7bce97b1cbd633f86912a17055e96ae4c6c565975b38def64419f645db7b14d2");
    // openssl rsa -in kat2048.der -inform der -pubout -outform der
    const pub_spki = hexLit("30820122300d06092a864886f70d01010105000382010f003082010a0282010100a2056f805f21fbf8815681fc5f7bb07bb8c7cba3be6e10ef3c3905981d666aa60adde3a7ebd258efae4e0d120e109c42cde35c6c322287135644e25eb79640aa91bc69a63b96fc3a72d85641cf567f4d4775c70c11d3c319989e764bc94c68002eb159d8fb05b73cafe489fb33b99e8f58ada35d59577e657f5097bb0e7a3f53e74b3592dbb31772092b96ab5aac70cef3b2afb54d1a35da41e895222c898f0306f9cd9ecb5b4e3bee111dcd5bfc44b976e7620b0e01b3072d0d3f5e995dcf20aa78d6633ef658bc1468f311ac4e6e005b2cf37d18f82cdc661f7d8cbd93709a4c122dd732bd243632b4a9d51da2f1d3c677a54d0f36c8f8458165d2fefe92030203010001");
    // openssl rsa -in kat2048.der -inform der -RSAPublicKey_out -outform der
    const pub_pkcs1 = hexLit("3082010a0282010100a2056f805f21fbf8815681fc5f7bb07bb8c7cba3be6e10ef3c3905981d666aa60adde3a7ebd258efae4e0d120e109c42cde35c6c322287135644e25eb79640aa91bc69a63b96fc3a72d85641cf567f4d4775c70c11d3c319989e764bc94c68002eb159d8fb05b73cafe489fb33b99e8f58ada35d59577e657f5097bb0e7a3f53e74b3592dbb31772092b96ab5aac70cef3b2afb54d1a35da41e895222c898f0306f9cd9ecb5b4e3bee111dcd5bfc44b976e7620b0e01b3072d0d3f5e995dcf20aa78d6633ef658bc1468f311ac4e6e005b2cf37d18f82cdc661f7d8cbd93709a4c122dd732bd243632b4a9d51da2f1d3c677a54d0f36c8f8458165d2fefe92030203010001");
};

const kat2048_pem = struct {
    // openssl rsa -in kat2048.der -inform der -traditional -outform pem
    const priv_pkcs1 =
        \\-----BEGIN RSA PRIVATE KEY-----
        \\MIIEowIBAAKCAQEAogVvgF8h+/iBVoH8X3uwe7jHy6O+bhDvPDkFmB1maqYK3eOn
        \\69JY765ODRIOEJxCzeNcbDIihxNWROJet5ZAqpG8aaY7lvw6cthWQc9Wf01HdccM
        \\EdPDGZiedkvJTGgALrFZ2PsFtzyv5In7M7mej1ito11ZV35lf1CXuw56P1PnSzWS
        \\27MXcgkrlqtarHDO87KvtU0aNdpB6JUiLImPAwb5zZ7LW0477hEdzVv8RLl252IL
        \\DgGzBy0NP16ZXc8gqnjWYz72WLwUaPMRrE5uAFss830Y+CzcZh99jL2TcJpMEi3X
        \\Mr0kNjK0qdUdovHTxnelTQ82yPhFgWXS/v6SAwIDAQABAoIBABgZeeEyMAJkOjd4
        \\Dzt+pkdzj+2860LrluzcyHW8uHKtma6GlyrPIiEd9V3MAovln6mIo5iJCTS7+MLh
        \\7wJyFtKoPx/HNP7mK/rQLghiQvSdiz8RaTyvmcoRYaSpQjBwxHItjsvlDrps4aGQ
        \\r+zyM7ZmaNwvXZjTjrJWIQjsWYeuAoGcl9Ci9gr6MtRxdmrNuDWLmmHNjU1OHNmK
        \\qhGTIXVY+0Zr4g6kjtpkaSkzLhnIh/eLpCPVc9RNBedM6XV8eaWfsDd8rOnmX5Fb
        \\k9zFuV/cnPAmqwrmm0i+7Q4COCZrJQ7VWqTku/GayAdqlqFuhrBAWOVlr1XY/IJy
        \\ZmjTBi0CgYEAzZGmSWz7eVdsBz3eoJ7cQj3uvao7EDAX0AVy67YbGgW55zQCOf2A
        \\GXkLdux0IzhC94bWIPgDYspFXmwLJoWdueXFDXHFUXWf/S7y+syYwQ1sLo4GYqXS
        \\Wg2EfE/FSgYvxLt1xVKuHN7xl5Fs2BxN0QLzFKik64xzxcaz6FxAoR0CgYEAycTb
        \\tZRWkGbKqq2/W+mJkDV+DqPTYZYBshVbrI7ZayjW7slXgWPdOwjgEyoPkamcmKE5
        \\s+ewFvfoPf5uGNl7REjcyrYXo6w6pqoTWcP1OWRz9LCyADglKuHXfozfH84qn06j
        \\IIJp951RbnuaIuL+S02th2IRczSPiW4jA8rltZ8CgYABzOrF7dxt/aQGlDYk9f87
        \\3UsAAkOuKp2qxsFw6xFlsvMj4UK7u0qp7nN5QSzrOgzsGhQ6CbIN5XOiFhQq7DSr
        \\ciW9rmdqBTu3fffG1o/n8PQnnDrWFlm3TDMC27gAo/k7IeEwLz8zJYi8KRvo8KaF
        \\1B7I6Yk4PuysqMbenCA8yQKBgB/gfB2569swgkBo5tysjtE7wkip1VGLk4UBHtSq
        \\VOs7LonXQX3tuxwCkPQ2JvOKanUqs6Uaq5VVYVm6AsbmRTVKladpEV8IbNO79wat
        \\kOaaWj+EUvr549VcjOEvfGjX95/nmpoeQIOgVScxW+67EhXvlcTX143t9edugRWu
        \\TpBdAoGBAJlDerG/ANluzNdUANqEEf3DU6vPf/IGZo4Fa9Pf9kIjPNC2dY2qD2pl
        \\H8wvahYODl2qNzk2J2J2Z6PkORYz5Gwqbex7HzzKdkfXKU80o/4QSsEG7jQEXArR
        \\yX7SOxf+H3vOl7HL1jP4aRKhcFXpauTGxWWXWzje9kQZ9kXbexTS
        \\-----END RSA PRIVATE KEY-----
        \\
    ;
    // openssl pkcs8 -topk8 -nocrypt -in kat2048.der -inform der -outform pem
    const priv_pkcs8 =
        \\-----BEGIN PRIVATE KEY-----
        \\MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCiBW+AXyH7+IFW
        \\gfxfe7B7uMfLo75uEO88OQWYHWZqpgrd46fr0ljvrk4NEg4QnELN41xsMiKHE1ZE
        \\4l63lkCqkbxppjuW/Dpy2FZBz1Z/TUd1xwwR08MZmJ52S8lMaAAusVnY+wW3PK/k
        \\ifszuZ6PWK2jXVlXfmV/UJe7Dno/U+dLNZLbsxdyCSuWq1qscM7zsq+1TRo12kHo
        \\lSIsiY8DBvnNnstbTjvuER3NW/xEuXbnYgsOAbMHLQ0/XpldzyCqeNZjPvZYvBRo
        \\8xGsTm4AWyzzfRj4LNxmH32MvZNwmkwSLdcyvSQ2MrSp1R2i8dPGd6VNDzbI+EWB
        \\ZdL+/pIDAgMBAAECggEAGBl54TIwAmQ6N3gPO36mR3OP7bzrQuuW7NzIdby4cq2Z
        \\roaXKs8iIR31XcwCi+WfqYijmIkJNLv4wuHvAnIW0qg/H8c0/uYr+tAuCGJC9J2L
        \\PxFpPK+ZyhFhpKlCMHDEci2Oy+UOumzhoZCv7PIztmZo3C9dmNOOslYhCOxZh64C
        \\gZyX0KL2Cvoy1HF2as24NYuaYc2NTU4c2YqqEZMhdVj7RmviDqSO2mRpKTMuGciH
        \\94ukI9Vz1E0F50zpdXx5pZ+wN3ys6eZfkVuT3MW5X9yc8CarCuabSL7tDgI4Jmsl
        \\DtVapOS78ZrIB2qWoW6GsEBY5WWvVdj8gnJmaNMGLQKBgQDNkaZJbPt5V2wHPd6g
        \\ntxCPe69qjsQMBfQBXLrthsaBbnnNAI5/YAZeQt27HQjOEL3htYg+ANiykVebAsm
        \\hZ255cUNccVRdZ/9LvL6zJjBDWwujgZipdJaDYR8T8VKBi/Eu3XFUq4c3vGXkWzY
        \\HE3RAvMUqKTrjHPFxrPoXEChHQKBgQDJxNu1lFaQZsqqrb9b6YmQNX4Oo9NhlgGy
        \\FVusjtlrKNbuyVeBY907COATKg+RqZyYoTmz57AW9+g9/m4Y2XtESNzKthejrDqm
        \\qhNZw/U5ZHP0sLIAOCUq4dd+jN8fziqfTqMggmn3nVFue5oi4v5LTa2HYhFzNI+J
        \\biMDyuW1nwKBgAHM6sXt3G39pAaUNiT1/zvdSwACQ64qnarGwXDrEWWy8yPhQru7
        \\Sqnuc3lBLOs6DOwaFDoJsg3lc6IWFCrsNKtyJb2uZ2oFO7d998bWj+fw9CecOtYW
        \\WbdMMwLbuACj+Tsh4TAvPzMliLwpG+jwpoXUHsjpiTg+7Kyoxt6cIDzJAoGAH+B8
        \\Hbnr2zCCQGjm3KyO0TvCSKnVUYuThQEe1KpU6zsuiddBfe27HAKQ9DYm84pqdSqz
        \\pRqrlVVhWboCxuZFNUqVp2kRXwhs07v3Bq2Q5ppaP4RS+vnj1VyM4S98aNf3n+ea
        \\mh5Ag6BVJzFb7rsSFe+VxNfXje31526BFa5OkF0CgYEAmUN6sb8A2W7M11QA2oQR
        \\/cNTq89/8gZmjgVr09/2QiM80LZ1jaoPamUfzC9qFg4OXao3OTYnYnZno+Q5FjPk
        \\bCpt7HsfPMp2R9cpTzSj/hBKwQbuNARcCtHJftI7F/4fe86XscvWM/hpEqFwVelq
        \\5MbFZZdbON72RBn2Rdt7FNI=
        \\-----END PRIVATE KEY-----
        \\
    ;
    // openssl rsa -in kat2048.der -inform der -pubout -outform pem
    const pub_spki =
        \\-----BEGIN PUBLIC KEY-----
        \\MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAogVvgF8h+/iBVoH8X3uw
        \\e7jHy6O+bhDvPDkFmB1maqYK3eOn69JY765ODRIOEJxCzeNcbDIihxNWROJet5ZA
        \\qpG8aaY7lvw6cthWQc9Wf01HdccMEdPDGZiedkvJTGgALrFZ2PsFtzyv5In7M7me
        \\j1ito11ZV35lf1CXuw56P1PnSzWS27MXcgkrlqtarHDO87KvtU0aNdpB6JUiLImP
        \\Awb5zZ7LW0477hEdzVv8RLl252ILDgGzBy0NP16ZXc8gqnjWYz72WLwUaPMRrE5u
        \\AFss830Y+CzcZh99jL2TcJpMEi3XMr0kNjK0qdUdovHTxnelTQ82yPhFgWXS/v6S
        \\AwIDAQAB
        \\-----END PUBLIC KEY-----
        \\
    ;
    // openssl rsa -in kat2048.der -inform der -RSAPublicKey_out -outform pem
    const pub_pkcs1 =
        \\-----BEGIN RSA PUBLIC KEY-----
        \\MIIBCgKCAQEAogVvgF8h+/iBVoH8X3uwe7jHy6O+bhDvPDkFmB1maqYK3eOn69JY
        \\765ODRIOEJxCzeNcbDIihxNWROJet5ZAqpG8aaY7lvw6cthWQc9Wf01HdccMEdPD
        \\GZiedkvJTGgALrFZ2PsFtzyv5In7M7mej1ito11ZV35lf1CXuw56P1PnSzWS27MX
        \\cgkrlqtarHDO87KvtU0aNdpB6JUiLImPAwb5zZ7LW0477hEdzVv8RLl252ILDgGz
        \\By0NP16ZXc8gqnjWYz72WLwUaPMRrE5uAFss830Y+CzcZh99jL2TcJpMEi3XMr0k
        \\NjK0qdUdovHTxnelTQ82yPhFgWXS/v6SAwIDAQAB
        \\-----END RSA PUBLIC KEY-----
        \\
    ;
};

fn expectMatchesKat2048PublicKey(pk: PublicKey) !void {
    var n_buf: [256]u8 = undefined;
    try pk.n.toBytes(&n_buf, .big);
    try testing.expectEqualSlices(u8, &kat2048.n, &n_buf);
    try testing.expectEqual(65537, try pk.e.toPrimitive(u32));
}

fn expectMatchesKat2048SecretKey(sk: SecretKey) !void {
    var n_buf: [256]u8 = undefined;
    try sk.n.toBytes(&n_buf, .big);
    try testing.expectEqualSlices(u8, &kat2048.n, &n_buf);
    var d_buf: [256]u8 = undefined;
    try sk.d.toBytes(&d_buf, .big);
    try testing.expectEqualSlices(u8, &kat2048.d, &d_buf);
}

test "PublicKey.fromDer parses SPKI and PKCS#1 DER, matches kat2048" {
    const from_spki = try PublicKey.fromDer(&kat2048_der.pub_spki);
    try expectMatchesKat2048PublicKey(from_spki);
    try verifyPkcs1v15(from_spki, std.crypto.hash.sha2.Sha256, kat2048.msg, &kat2048.sig_sha256);

    const from_pkcs1 = try PublicKey.fromDer(&kat2048_der.pub_pkcs1);
    try expectMatchesKat2048PublicKey(from_pkcs1);
    try verifyPkcs1v15(from_pkcs1, std.crypto.hash.sha2.Sha256, kat2048.msg, &kat2048.sig_sha256);
}

test "PublicKey.fromPem parses PUBLIC KEY and RSA PUBLIC KEY PEM, matches kat2048" {
    const from_spki = try PublicKey.fromPem(kat2048_pem.pub_spki);
    try expectMatchesKat2048PublicKey(from_spki);

    const from_pkcs1 = try PublicKey.fromPem(kat2048_pem.pub_pkcs1);
    try expectMatchesKat2048PublicKey(from_pkcs1);
    try verifyPkcs1v15(from_pkcs1, std.crypto.hash.sha2.Sha256, kat2048.msg, &kat2048.sig_sha256);
}

test "SecretKey.fromDer parses bare PKCS#1 RSAPrivateKey DER, matches kat2048 and signs" {
    const sk = try SecretKey.fromDer(&kat2048_der.priv_pkcs1);
    try expectMatchesKat2048SecretKey(sk);

    var out: [max_modulus_len]u8 = undefined;
    const sig = try signPkcs1v15(sk, std.crypto.hash.sha2.Sha256, kat2048.msg, &out);
    try testing.expectEqualSlices(u8, &kat2048.sig_sha256, sig); // deterministic -> byte-exact
}

test "fromPkcs8 parses PKCS#8 PrivateKeyInfo DER, matches kat2048 and signs" {
    const sk = try fromPkcs8(&kat2048_der.priv_pkcs8);
    try expectMatchesKat2048SecretKey(sk);

    var out: [max_modulus_len]u8 = undefined;
    const sig = try signPkcs1v15(sk, std.crypto.hash.sha2.Sha256, kat2048.msg, &out);
    try testing.expectEqualSlices(u8, &kat2048.sig_sha256, sig);
}

test "SecretKey.fromPem parses RSA PRIVATE KEY and PRIVATE KEY PEM, matches kat2048" {
    const from_pkcs1 = try SecretKey.fromPem(kat2048_pem.priv_pkcs1);
    try expectMatchesKat2048SecretKey(from_pkcs1);

    const from_pkcs8 = try SecretKey.fromPem(kat2048_pem.priv_pkcs8);
    try expectMatchesKat2048SecretKey(from_pkcs8);

    var out: [max_modulus_len]u8 = undefined;
    const sig = try signPkcs1v15(from_pkcs1, std.crypto.hash.sha2.Sha256, kat2048.msg, &out);
    try verifyPkcs1v15(try PublicKey.fromPem(kat2048_pem.pub_spki), std.crypto.hash.sha2.Sha256, kat2048.msg, sig);
}

test "PublicKey.fromDer/SecretKey.fromDer/fromPkcs8 reject truncated DER" {
    inline for (.{ &kat2048_der.pub_spki, &kat2048_der.pub_pkcs1 }) |der_bytes| {
        var l: usize = 0;
        while (l < der_bytes.len) : (l += 7) {
            try testing.expectError(error.InvalidDer, PublicKey.fromDer(der_bytes[0..l]));
        }
    }
    {
        var l: usize = 0;
        while (l < kat2048_der.priv_pkcs1.len) : (l += 11) {
            try testing.expectError(error.InvalidDer, SecretKey.fromDer(kat2048_der.priv_pkcs1[0..l]));
        }
    }
    {
        var l: usize = 0;
        while (l < kat2048_der.priv_pkcs8.len) : (l += 11) {
            try testing.expectError(error.InvalidDer, fromPkcs8(kat2048_der.priv_pkcs8[0..l]));
        }
    }
}

test "PublicKey.fromDer rejects a wrong leading tag (never panics)" {
    var corrupt = kat2048_der.pub_spki;
    corrupt[0] ^= 0xff; // SEQUENCE tag (0x30) mangled
    try testing.expectError(error.InvalidDer, PublicKey.fromDer(&corrupt));

    var corrupt1 = kat2048_der.pub_pkcs1;
    corrupt1[0] ^= 0xff;
    try testing.expectError(error.InvalidDer, PublicKey.fromDer(&corrupt1));
}

test "PublicKey.fromDer/fromPkcs8 reject a wrong AlgorithmIdentifier OID" {
    var corrupt = kat2048_der.pub_spki;
    const idx = std.mem.indexOf(u8, &corrupt, &oid_rsa_encryption).?;
    corrupt[idx] ^= 0xff;
    try testing.expectError(error.InvalidDer, PublicKey.fromDer(&corrupt));

    var corrupt8 = kat2048_der.priv_pkcs8;
    const idx8 = std.mem.indexOf(u8, &corrupt8, &oid_rsa_encryption).?;
    corrupt8[idx8] ^= 0xff;
    try testing.expectError(error.InvalidDer, fromPkcs8(&corrupt8));
}

test "SecretKey.fromDer rejects a corrupted version field" {
    var corrupt = kat2048_der.priv_pkcs1;
    // version INTEGER is `02 01 00` right after the outer SEQUENCE header;
    // its content byte (must be 0x00) sits at offset 6.
    try testing.expectEqual(@as(u8, 0x00), corrupt[6]);
    corrupt[6] = 0x01; // multi-prime (version 1): rejected, not supported
    try testing.expectError(error.InvalidDer, SecretKey.fromDer(&corrupt));
}

test "PublicKey.fromPem/SecretKey.fromPem: missing block, corrupted base64, encrypted/OpenSSH labels" {
    try testing.expectError(error.MissingPemBlock, PublicKey.fromPem("no pem here"));
    try testing.expectError(error.MissingPemBlock, SecretKey.fromPem("no pem here"));

    try testing.expectError(error.InvalidPem, PublicKey.fromPem(
        "-----BEGIN PUBLIC KEY-----\n!!!!not base64!!!!\n-----END PUBLIC KEY-----\n",
    ));
    try testing.expectError(error.InvalidPem, PublicKey.fromPem(
        "-----BEGIN PUBLIC KEY-----\nAAAA", // no END marker
    ));

    // Encrypted PKCS#8 and OpenSSH private keys are recognized by label and
    // rejected with a specific error (P4b territory) rather than being
    // misparsed as cleartext DER or panicking on the OpenSSH blob shape.
    try testing.expectError(error.UnsupportedPemLabel, SecretKey.fromPem(
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n",
    ));
    try testing.expectError(error.UnsupportedPemLabel, SecretKey.fromPem(
        "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
    ));
    // Right key material, wrong accessor (a public PEM handed to fromPem for
    // secret keys, and vice versa) is also a label mismatch, not a crash.
    try testing.expectError(error.UnsupportedPemLabel, SecretKey.fromPem(kat2048_pem.pub_spki));
    try testing.expectError(error.UnsupportedPemLabel, PublicKey.fromPem(kat2048_pem.priv_pkcs1));
}

// ── P6 (self-signed X.509 certificate) tests ────────────────────────────────
//
// Fixture: the same `kat2048` key as every other section. Validity window
// mirrors `modules/acme/src/x509.zig`'s own test fixtures (notBefore
// 2025-01-01, notAfter 2030-12-31) so `verify_now` below (an arbitrary
// instant inside that window) needs no clock and no epoch-math helper.

fn testCertOptions(is_ca: bool) CertOptions {
    return .{
        .common_name = "zig-libs rsa self-signed test",
        .serial = 7,
        .not_before = "250101000000Z", // 2025-01-01T00:00:00Z
        .not_after = "301231235959Z", // 2030-12-31T23:59:59Z
        .is_ca = is_ca,
    };
}

// Epoch seconds for 2027-06-15T00:00:00Z: comfortably inside the fixture's
// validity window (computed once with Python: `int(datetime(2027,6,15,
// tzinfo=timezone.utc).timestamp())`), used as `now_sec` for
// `std.crypto.Certificate.Parsed.verify` below — never a clock read.
const verify_now: i64 = 1813363200;

test "selfSignedCert: std.crypto.Certificate parses + fully verifies it (self-signed oracle)" {
    const sk = try kat2048.secretKey();
    const pk = try kat2048.publicKey();

    const cert_der = try selfSignedCert(testing.allocator, sk, pk, std.crypto.hash.sha2.Sha256, testCertOptions(true));
    defer testing.allocator.free(cert_der);

    const cert: std.crypto.Certificate = .{ .buffer = cert_der, .index = 0 };
    const parsed = try cert.parse();

    try testing.expectEqual(.v3, parsed.version);
    try testing.expectEqual(.sha256WithRSAEncryption, parsed.signature_algorithm);
    try testing.expect(parsed.pub_key_algo == .rsaEncryption);

    // Self-signed: issuer and subject are byte-identical (the same `Name`
    // DER, built once and reused for both fields).
    try testing.expectEqualSlices(u8, parsed.issuer(), parsed.subject());
    try testing.expectEqualStrings("zig-libs rsa self-signed test", parsed.commonName());

    // Embedded public key round-trips to the exact kat2048 n/e.
    const pk_components = try std.crypto.Certificate.rsa.PublicKey.parseDer(parsed.pubKey());
    try testing.expectEqualSlices(u8, &kat2048.n, pk_components.modulus);
    try testing.expectEqualSlices(u8, &kat2048.e, pk_components.exponent);

    // The strongest oracle: std's full self-verify path (issuer==subject
    // name match, validity window, RSA signature over the TBS bytes) all
    // pass through `Parsed.verify` against itself.
    try parsed.verify(parsed, verify_now);

    // Outside the validity window, `verify` must reject — proving the
    // notBefore/notAfter checks are real and not merely parsed-and-ignored.
    try testing.expectError(error.CertificateNotYetValid, parsed.verify(parsed, 1_735_689_599)); // 1s before notBefore
    try testing.expectError(error.CertificateExpired, parsed.verify(parsed, 1_924_992_000)); // 1s after notAfter

    // A bit flip in the signature bytes (the certificate's last byte, deep
    // inside the trailing signatureValue BIT STRING) must break the
    // signature check without touching issuer/subject/validity — proving
    // the RSA signature is actually checked, not just parsed and ignored.
    // (A flip inside the commonName is not used here: issuer and subject
    // both embed that same text as two separate copies, so corrupting the
    // first occurrence trips the issuer/subject *name* mismatch check
    // first, before the signature is ever verified.)
    var tampered = try testing.allocator.dupe(u8, cert_der);
    defer testing.allocator.free(tampered);
    tampered[tampered.len - 1] ^= 0x01;
    const tampered_cert: std.crypto.Certificate = .{ .buffer = tampered, .index = 0 };
    const tampered_parsed = try tampered_cert.parse();
    try testing.expectError(error.CertificateSignatureInvalid, tampered_parsed.verify(tampered_parsed, verify_now));
}

test "selfSignedCert: basicConstraints reflects is_ca (CA vs leaf)" {
    const sk = try kat2048.secretKey();
    const pk = try kat2048.publicKey();
    const Sha256 = std.crypto.hash.sha2.Sha256;

    // Both are self-consistency checks against this module's own
    // deterministic encoding (`buildExtensions`): `cA TRUE` only appears
    // for a CA cert, `cA`-absent (empty inner SEQUENCE, DEFAULT FALSE) only
    // for a leaf — proving `is_ca` actually reaches the DER, not just that
    // the OID is present in both.
    const ca_der = try selfSignedCert(testing.allocator, sk, pk, Sha256, testCertOptions(true));
    defer testing.allocator.free(ca_der);
    const leaf_der = try selfSignedCert(testing.allocator, sk, pk, Sha256, testCertOptions(false));
    defer testing.allocator.free(leaf_der);

    const ca_true_seq = [_]u8{ 0x30, 0x03, 0x01, 0x01, 0xff }; // SEQUENCE { BOOLEAN TRUE }
    const ca_empty_seq = [_]u8{ 0x30, 0x00 }; // SEQUENCE {} (cA DEFAULT FALSE)

    try testing.expect(std.mem.indexOf(u8, ca_der, &ca_true_seq) != null);
    try testing.expect(std.mem.indexOf(u8, leaf_der, &ca_true_seq) == null);
    try testing.expect(std.mem.indexOf(u8, leaf_der, &ca_empty_seq) != null);

    // keyUsage differs too: CA sets keyCertSign+cRLSign (content byte 0x86,
    // 1 unused bit), leaf sets only digitalSignature (0x80, 7 unused bits).
    const ku_ca = [_]u8{ 0x03, 0x02, 0x01, 0x86 };
    const ku_leaf = [_]u8{ 0x03, 0x02, 0x07, 0x80 };
    try testing.expect(std.mem.indexOf(u8, ca_der, &ku_ca) != null);
    try testing.expect(std.mem.indexOf(u8, leaf_der, &ku_leaf) != null);

    // Both are still valid, verifiable certificates regardless of is_ca.
    inline for (.{ ca_der, leaf_der }) |der_bytes| {
        const cert: std.crypto.Certificate = .{ .buffer = der_bytes, .index = 0 };
        const parsed = try cert.parse();
        try parsed.verify(parsed, verify_now);
    }
}

test "selfSignedCert: subjectAltName (dNSName + URI) round-trips through std's verifyHostName" {
    const sk = try kat2048.secretKey();
    const pk = try kat2048.publicKey();
    var opts = testCertOptions(false);
    opts.subject_alt_names = &.{
        .{ .dns_name = "example.com" },
        .{ .dns_name = "*.example.com" },
        .{ .uri = "urn:zig-libs:rsa:test" },
    };

    const cert_der = try selfSignedCert(testing.allocator, sk, pk, std.crypto.hash.sha2.Sha256, opts);
    defer testing.allocator.free(cert_der);
    const cert: std.crypto.Certificate = .{ .buffer = cert_der, .index = 0 };
    const parsed = try cert.parse();

    try parsed.verifyHostName("example.com");
    try parsed.verifyHostName("foo.example.com"); // matches the wildcard SAN
    try testing.expectError(error.CertificateHostMismatch, parsed.verifyHostName("other.org"));

    // The URI SAN is present in the raw subjectAltName bytes too (std has no
    // dedicated URI accessor, so check the extnValue bytes directly).
    try testing.expect(std.mem.indexOf(u8, parsed.subjectAltName(), "urn:zig-libs:rsa:test") != null);
}

test "selfSignedCert: rejects invalid CertOptions (empty CN, malformed UTCTime)" {
    const sk = try kat2048.secretKey();
    const pk = try kat2048.publicKey();
    const Sha256 = std.crypto.hash.sha2.Sha256;

    var opts = testCertOptions(false);
    opts.common_name = "";
    try testing.expectError(error.InvalidCertOptions, selfSignedCert(testing.allocator, sk, pk, Sha256, opts));

    opts = testCertOptions(false);
    opts.not_before = "2025-01-01"; // wrong shape entirely
    try testing.expectError(error.InvalidCertOptions, selfSignedCert(testing.allocator, sk, pk, Sha256, opts));

    opts = testCertOptions(false);
    opts.not_after = "301231235959"; // missing trailing 'Z'
    try testing.expectError(error.InvalidCertOptions, selfSignedCert(testing.allocator, sk, pk, Sha256, opts));

    opts = testCertOptions(false);
    opts.not_before = "25010100000AZ"; // non-digit in the date portion
    try testing.expectError(error.InvalidCertOptions, selfSignedCert(testing.allocator, sk, pk, Sha256, opts));
}

test "selfSignedCert: allocator exhaustion is reported, not panicked (BufferTooSmall analogue)" {
    // selfSignedCert returns a gpa-owned slice sized to the (variable-length)
    // encoded certificate rather than writing into a caller-fixed `out`
    // buffer (see its doc comment for why); the equivalent "not enough room"
    // negative for an allocator-returning API is allocator exhaustion, not a
    // fixed-buffer-too-small error code.
    const sk = try kat2048.secretKey();
    const pk = try kat2048.publicKey();

    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    try testing.expectError(
        error.OutOfMemory,
        selfSignedCert(failing.allocator(), sk, pk, std.crypto.hash.sha2.Sha256, testCertOptions(false)),
    );
}

test "selfSignedCert: this module's own P4a parser round-trips the embedded SPKI and signature" {
    // Independent of std.crypto.Certificate: walk the Certificate DER by
    // hand with the same bounds-checked `Asn1.Element.decode` primitive
    // P4a's `derElem`/`derChild` are built on (used directly here, not
    // through those wrappers, since they require a universal tag class and
    // `version [0]`/context-specific fields are not universal-class), then
    // feed the extracted SPKI back through `PublicKey.fromDer` and the
    // extracted signature back through `verifyPkcs1v15` — both P4a and P1
    // cross-checked against this module's own P6 encoder, not just std's.
    const sk = try kat2048.secretKey();
    const pk = try kat2048.publicKey();
    const Sha256 = std.crypto.hash.sha2.Sha256;

    const cert_der = try selfSignedCert(testing.allocator, sk, pk, Sha256, testCertOptions(false));
    defer testing.allocator.free(cert_der);

    const cert_elem = try Asn1.Element.decode(cert_der, 0);
    const tbs_elem = try Asn1.Element.decode(cert_der, cert_elem.slice.start);

    const version_elem = try Asn1.Element.decode(cert_der, tbs_elem.slice.start);
    const serial_elem = try Asn1.Element.decode(cert_der, version_elem.slice.end);
    const tbs_sig_alg_elem = try Asn1.Element.decode(cert_der, serial_elem.slice.end);
    const issuer_elem = try Asn1.Element.decode(cert_der, tbs_sig_alg_elem.slice.end);
    const validity_elem = try Asn1.Element.decode(cert_der, issuer_elem.slice.end);
    const subject_elem = try Asn1.Element.decode(cert_der, validity_elem.slice.end);
    const spki_elem = try Asn1.Element.decode(cert_der, subject_elem.slice.end);

    // Issuer and subject are the exact same bytes (self-signed).
    try testing.expectEqualSlices(
        u8,
        cert_der[issuer_elem.slice.start..issuer_elem.slice.end],
        cert_der[subject_elem.slice.start..subject_elem.slice.end],
    );

    // `PublicKey.fromDer` expects a *complete* top-level SEQUENCE (header
    // included); the SPKI's header starts exactly where `subject` ends.
    const spki_full = cert_der[subject_elem.slice.end..spki_elem.slice.end];
    const parsed_pk = try PublicKey.fromDer(spki_full);
    try expectMatchesKat2048PublicKey(parsed_pk);

    // signatureAlgorithm + signatureValue follow tbsCertificate in the outer
    // Certificate SEQUENCE (siblings of `tbs_elem`, not children of it).
    const outer_sig_alg_elem = try Asn1.Element.decode(cert_der, tbs_elem.slice.end);
    const outer_sig_bits_elem = try Asn1.Element.decode(cert_der, outer_sig_alg_elem.slice.end);
    const sig_bitstring_content = cert_der[outer_sig_bits_elem.slice.start..outer_sig_bits_elem.slice.end];
    try testing.expect(sig_bitstring_content.len >= 1 and sig_bitstring_content[0] == 0); // 0 unused bits
    const sig_bytes = sig_bitstring_content[1..];

    // The signed message is the complete tbsCertificate TLV (header
    // included) — `cert_elem.slice.start` is exactly where it begins.
    const tbs_full = cert_der[cert_elem.slice.start..tbs_elem.slice.end];
    try verifyPkcs1v15(pk, Sha256, tbs_full, sig_bytes);

    // And the reverse-direction cross-check: corrupting one byte inside the
    // signed TBS content must make our own verifier reject it too.
    var tampered_tbs = try testing.allocator.dupe(u8, tbs_full);
    defer testing.allocator.free(tampered_tbs);
    tampered_tbs[tampered_tbs.len - 1] ^= 0x01;
    try testing.expectError(error.SignatureVerificationFailed, verifyPkcs1v15(pk, Sha256, tampered_tbs, sig_bytes));
}

// ── P5 (key generation) tests ───────────────────────────────────────────────
//
// All generation tests use a fixed-seed `std.Random.DefaultPrng` so CI is
// reproducible (and CHACHA-free/fast); `generate`'s doc comment is explicit
// that a deterministic generator is a test-only arrangement. Key sizes stay
// at 512/1024 bits to keep the Debug-mode suite fast — the machinery is
// size-independent (same code path up to `max_modulus_bits`).

test "generate: rejects invalid bits and exponents" {
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    // Too small, too large, odd — all before any prime search starts.
    try testing.expectError(error.InvalidBits, generate(random, 0, 65537));
    try testing.expectError(error.InvalidBits, generate(random, 256, 65537));
    try testing.expectError(error.InvalidBits, generate(random, 511, 65537));
    try testing.expectError(error.InvalidBits, generate(random, 513, 65537));
    try testing.expectError(error.InvalidBits, generate(random, max_modulus_bits + 2, 65537));

    // e must be odd, >= 3, and < 2^32 (the module-wide public-exponent cap).
    try testing.expectError(error.InvalidExponent, generate(random, 512, 0));
    try testing.expectError(error.InvalidExponent, generate(random, 512, 1));
    try testing.expectError(error.InvalidExponent, generate(random, 512, 2));
    try testing.expectError(error.InvalidExponent, generate(random, 512, 65536));
    try testing.expectError(error.InvalidExponent, generate(random, 512, 1 << 33));
}

/// n == p·q cross-check via `std.math.big.int` (an arithmetic path fully
/// independent of the `ff` code that produced the key).
fn expectNisPQ(sk: SecretKey) !void {
    var scratch: [128 * 1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    const gpa = fba.allocator();

    var p_bytes: [max_modulus_len]u8 = undefined;
    const p_len = byteLen(sk.p.bits());
    try sk.p.toBytes(p_bytes[0..p_len], .big);
    var q_bytes: [max_modulus_len]u8 = undefined;
    const q_len = byteLen(sk.q.bits());
    try sk.q.toBytes(q_bytes[0..q_len], .big);

    var bp = try bigFromBytes(gpa, p_bytes[0..p_len]);
    var bq = try bigFromBytes(gpa, q_bytes[0..q_len]);
    var product = try newBig(gpa);
    try product.mul(&bp, &bq);

    var n_bytes: [max_modulus_len]u8 = undefined;
    const n_len = byteLen(sk.n.bits());
    try sk.n.toBytes(n_bytes[0..n_len], .big);
    const bn = try bigFromBytes(gpa, n_bytes[0..n_len]);

    try testing.expect(product.order(bn) == .eq);
}

test "generate: 512-bit key structure (n exactly 512 bits, p/q prime, p != q, n = p*q, e)" {
    var prng = std.Random.DefaultPrng.init(0x7273615f67656e35); // "rsa_gen5"
    const random = prng.random();

    const kp = try generate(random, 512, 65537);
    const sk = kp.secret_key;
    const pk = kp.public_key;

    // Exact bit length, requested exponent, matching halves.
    try testing.expectEqual(@as(usize, 512), sk.n.bits());
    try testing.expectEqual(@as(usize, 512), pk.n.bits());
    try testing.expect(pk.n.v.eql(sk.n.v));
    try testing.expectEqual(@as(u32, 65537), try pk.e.toPrimitive(u32));

    // p and q: exactly half-size, distinct, and each re-confirmed prime with
    // 64 fresh Miller-Rabin rounds (independent witnesses — the PRNG has
    // advanced past the generation draws).
    try testing.expectEqual(@as(usize, 256), sk.p.bits());
    try testing.expectEqual(@as(usize, 256), sk.q.bits());
    try testing.expect(!sk.p.v.eql(sk.q.v));
    try testing.expect(isProbablePrime(sk.p, random));
    try testing.expect(isProbablePrime(sk.q, random));

    // n == p·q via an independent bignum path.
    try expectNisPQ(sk);
}

test "generate: honors a non-default exponent (e = 3)" {
    var prng = std.Random.DefaultPrng.init(0x655f6571735f33); // "e_eqs_3"
    const random = prng.random();

    const kp = try generate(random, 512, 3);
    try testing.expectEqual(@as(u32, 3), try kp.public_key.e.toPrimitive(u32));
    try testing.expectEqual(@as(usize, 512), kp.secret_key.n.bits());
    try testing.expect(isProbablePrime(kp.secret_key.p, random));
    try testing.expect(isProbablePrime(kp.secret_key.q, random));
}

test "generate: 1024-bit key round-trips P1 sign/verify, P2 OAEP, and P6 selfSignedCert" {
    var prng = std.Random.DefaultPrng.init(0x67656e5f65326531); // "gen_e2e1"
    const random = prng.random();
    const Sha256 = std.crypto.hash.sha2.Sha256;

    // 1024 bits: the smallest size std.crypto.Certificate's RSA verifier
    // accepts (its modulus-length switch starts at 128 bytes), so the P6
    // oracle below exercises the generated key end-to-end.
    const kp = try generate(random, 1024, 65537);
    const sk = kp.secret_key;
    const pk = kp.public_key;
    try testing.expectEqual(@as(usize, 1024), sk.n.bits());
    try expectNisPQ(sk);

    // P1: sign/verify round-trip, and the verifier still rejects a wrong
    // message under this fresh key.
    const msg = "generated-key end-to-end message";
    var sig_buf: [max_modulus_len]u8 = undefined;
    const sig = try signPkcs1v15(sk, Sha256, msg, &sig_buf);
    try verifyPkcs1v15(pk, Sha256, msg, sig);
    try testing.expectError(error.SignatureVerificationFailed, verifyPkcs1v15(pk, Sha256, "another message", sig));

    // P2: OAEP encrypt/decrypt round-trip.
    const secret = "oaep plaintext under a generated key";
    var ct_buf: [max_modulus_len]u8 = undefined;
    const ct = try encryptOaep(pk, Sha256, random, secret, "", &ct_buf);
    var pt_buf: [max_modulus_len]u8 = undefined;
    const pt = try decryptOaep(sk, Sha256, ct, "", &pt_buf);
    try testing.expectEqualStrings(secret, pt);

    // P6: a self-signed certificate for the generated key must fully verify
    // under std.crypto.Certificate (parse + issuer/subject + validity +
    // RSA signature over the TBS bytes).
    const cert_der = try selfSignedCert(testing.allocator, sk, pk, Sha256, testCertOptions(false));
    defer testing.allocator.free(cert_der);
    const cert: std.crypto.Certificate = .{ .buffer = cert_der, .index = 0 };
    const parsed = try cert.parse();
    try parsed.verify(parsed, verify_now);
}

test "isProbablePrime: known primes pass, known composites fail" {
    var prng = std.Random.DefaultPrng.init(0x6d725f6b6174); // "mr_kat"
    const random = prng.random();

    // 2^255 - 19 (Curve25519's prime) and 2^127 - 1 (Mersenne prime M127).
    const p25519_bytes = comptime hexLit("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed");
    const p25519 = try Modulus.fromBytes(&p25519_bytes, .big);
    try testing.expect(isProbablePrime(p25519, random));
    const m127 = try Modulus.fromPrimitive(u128, (1 << 127) - 1);
    try testing.expect(isProbablePrime(m127, random));

    // Composites, including pseudoprime bait: 1729 = 7·13·19 (a Carmichael
    // number — Fermat-fools every coprime base, Miller-Rabin must not),
    // 3215031751 = 151·751·28351 (the smallest strong pseudoprime to bases
    // 2, 3, 5 and 7 simultaneously), and an odd perfect square.
    try testing.expect(!isProbablePrime(try Modulus.fromPrimitive(u32, 1729), random));
    try testing.expect(!isProbablePrime(try Modulus.fromPrimitive(u64, 3215031751), random));
    try testing.expect(!isProbablePrime(try Modulus.fromPrimitive(u64, 1000003 * 1000003), random));
}

// ── P4b: OpenSSH fixtures + tests ────────────────────────────────────────────

// One 2048-bit RSA keypair stored three ways by ssh-keygen (OpenSSH_10.2p1
// Ubuntu-2ubuntu3.2, OpenSSL 3.5.5, 2026-07-10), temp files deleted after
// embedding:
//   ssh-keygen -t rsa -b 2048 -N ""        -C "zig-libs-rsa-p4b" -f k1
//   cp k1 k2 && ssh-keygen -p -N "hunter2" -Z aes256-ctr -a 4 -f k2
//   cp k1 k3 && ssh-keygen -p -N "hunter2" -Z aes256-cbc -a 4 -f k3
// Same underlying key, so all three must parse to the same modulus.
const openssh_fixture_plain =
    \\-----BEGIN OPENSSH PRIVATE KEY-----
    \\b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
    \\NhAAAAAwEAAQAAAQEAjVsqQO9FbSWVx8o1ILSU2Y5ELsxlrmD+XzDh6zUQnNaYiWz4YPyd
    \\9q93+Hj8krgxtWMJGDTu0Cqn5klvOAOfRBd83EGM40fwrlahtBmRV2tu2iyslUL6PTUbij
    \\GNXexUiw0fVDVb3trjpVhISouCyuffxbDjQWe39lH/myxjCDgbnKpfs7acb/a6RV/XRb+8
    \\fOrks8jVZnp9xqt3rVJ8Wf8eSu9AV/yfKNyvz4YRs7PeyjzYkm4h6fY41dMxcAIGJslR4t
    \\PX1XfVsKTNyIoE22Dk0kZq38IhU5bVOorzA7RIvAfTRCwzD26WKcnSUw5SW8DJz6pFaSNR
    \\Ed+EkqqbLQAAA8hUMuQjVDLkIwAAAAdzc2gtcnNhAAABAQCNWypA70VtJZXHyjUgtJTZjk
    \\QuzGWuYP5fMOHrNRCc1piJbPhg/J32r3f4ePySuDG1YwkYNO7QKqfmSW84A59EF3zcQYzj
    \\R/CuVqG0GZFXa27aLKyVQvo9NRuKMY1d7FSLDR9UNVve2uOlWEhKi4LK59/FsONBZ7f2Uf
    \\+bLGMIOBucql+ztpxv9rpFX9dFv7x86uSzyNVmen3Gq3etUnxZ/x5K70BX/J8o3K/PhhGz
    \\s97KPNiSbiHp9jjV0zFwAgYmyVHi09fVd9WwpM3IigTbYOTSRmrfwiFTltU6ivMDtEi8B9
    \\NELDMPbpYpydJTDlJbwMnPqkVpI1ER34SSqpstAAAAAwEAAQAAAQAH/yXLSZ3wWEV6aXaK
    \\9JxNGG7EBP0lmcgaI35MW5KmhL9ZWuhMOE5JY9DSJioHtNLfE4yyqV/vN9KKxRG9JftPE1
    \\MVdMHfI7U6b50zPpUJ0IKTZh6XTRQx/TyjGz2HmDSKL0Jb9a7OUyy4sF9alDzgdLCkkuaw
    \\TwlJrobaxO6PSuPB/gQWK3ETvts+Ft8OFkHqOXgHYoBSAMvGlellTzZhV8X3GU0b/66BU7
    \\+qBFKbwHYJETbog9GT+DzKUfXYh5hAuhNWMaF4lWktZiDqT9k1J9MwGzg5Jm6Wisdyo5JF
    \\CsawtvWcMZUCxa9M9fH6KQzmxeTy5kd+gxZ1XETI3GLjAAAAgD8zhug8WyogyBAOwh/k9t
    \\QtC91FJqlF9Nr2Il566huilk9+095QvCXkYJOnbO6yVOq59Ss6ZC4GtjS4edXP0YeZdCZV
    \\jYU53FolfMexdhl14w9LsPvaSq0fPAoD2zqXnrbvdHv6tvFC6LL37r5HUXgDauni7RREdI
    \\vw156xOXX5AAAAgQDB+OU0hvB7sj2Bo6SPjmSydUmR1a59yn49dxtCpSnV+Ol8QZeGTKOE
    \\+Bqa7hh3UcVYOoDUv+NQp2wjvFBLP6kJsclhzkVXNRCTC8TzVhImV1Y98EjseZ/JSGWwJG
    \\0TzId1EkCKhrVOUJhx0zpRYHGLW4s4XGkWCX5/O7rzbcQEEwAAAIEAuo73rDcPcO3JT32l
    \\PlQTZoXBsLcxC5X4VKdqXpWQavVkQj1Rf3hJoo/j82hrl4vf1TTiBzl6nnRNVe7SVC9Zue
    \\fo1iI7C4nvnVGdTXy9BUlhzYVDc88UCMbpVZlgwJ5vX8yae7jtrbkpNACTyf6XLhp/H/KQ
    \\zl+1DFv6pOIeS78AAAAQemlnLWxpYnMtcnNhLXA0YgECAw==
    \\-----END OPENSSH PRIVATE KEY-----
    \\
;
const openssh_fixture_ctr =
    \\-----BEGIN OPENSSH PRIVATE KEY-----
    \\b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDm8zGt/d
    \\qoG0Uzfsy5X7kfAAAABAAAAAEAAAEXAAAAB3NzaC1yc2EAAAADAQABAAABAQCNWypA70Vt
    \\JZXHyjUgtJTZjkQuzGWuYP5fMOHrNRCc1piJbPhg/J32r3f4ePySuDG1YwkYNO7QKqfmSW
    \\84A59EF3zcQYzjR/CuVqG0GZFXa27aLKyVQvo9NRuKMY1d7FSLDR9UNVve2uOlWEhKi4LK
    \\59/FsONBZ7f2Uf+bLGMIOBucql+ztpxv9rpFX9dFv7x86uSzyNVmen3Gq3etUnxZ/x5K70
    \\BX/J8o3K/PhhGzs97KPNiSbiHp9jjV0zFwAgYmyVHi09fVd9WwpM3IigTbYOTSRmrfwiFT
    \\ltU6ivMDtEi8B9NELDMPbpYpydJTDlJbwMnPqkVpI1ER34SSqpstAAAD0CmpVFbQVaaZsN
    \\2uZUcAh6MxbUjh+3MWKDIe5nIJ3R4aN5vK0uVNT7aeWZ0PQpw0qNW+KIBrE7SELnRtutLb
    \\zkgR2rLM5A6oCx61GBq1XwXhwVrQXI4fhxpoU7PGUe8/KKLtKAGu+Z8fzCzJI8NwDr/JO2
    \\58cUvbDcTLGEWTh9GrHcJ2k2KQOlCB1n/HEajyzGnvxcpeCT/MVbV8/yWIgS/MfTjiuogm
    \\YcVY2fjcoOMOML7q7jV39kMclGSSc+G+mkqjmHsH85eKIEVzYz6OVj5VURPIUNFsOymWtD
    \\TmZhueYcHnleh3JIasmtJdvzQ8O0cRbrqPYcGxhTJAFALK31iu9H3yG2wEVsPAiXfPzSc+
    \\iN5vplq/5By6WX9cQ4jBYf4ieHAwnHLEQCy8qx7036ozBbeJtcxigct/FhKLoXdaupZH7v
    \\XO9a7dfzr+x1P+SlnU7UWv4VgY3Hg+c4Iy6QNQglc5Lbyxsxxmi6e2k4LsyPWvQMHfH7Vq
    \\aVh1esr+jMA01KYZZvfsYwS2/brGnbSme+kxuNlqXOCLYznMyv7SV6WkPNdSmHefWVo46V
    \\MOr11Lha2yUG3L7IuYSylHdiMDseBwnyAxUhFWD0YYDx/Aqqco//ewEtrp1EhF9pvwoK6w
    \\7qZNjIiLafyT9Bf7Ti1k4ikLA2MkkgVmerxhOgYhEtXHsYfYF+dap0Fc7qpxdM+paPxL+4
    \\wkpdpPRO+BZhj8+F3Pc4tZJQa9rrcRCH1SX0fmo3brWE6UzPKl54CVKXZTEOR+lyWv9bf/
    \\MpRBRy7Q1TvV1GyygpPxBWfG3emN4BS9x/sFZy7Mpcj5F03XVGQmr3eqdGrYkX8gftSgvh
    \\+0vALh1lSeLzyCgQmsqfg8lZ9haO0Vo/w8RFNCPLoDx+UwKe/n6jYdInk3u81dcT1Zas9N
    \\x4lmavzmTwC6x7sydj4u2t3li0hNImpKnZS13hPec89MOGrXYdMhTGiFGzcmimVQCTNmM0
    \\VW1pZ3/ESKqG8h6L15clCafuzGMHj2vEtgOdvB/1SlcdlkTwio/3vf/ZNQ3VAAL+DPQtZC
    \\XDrijDX4FUN4UZYXn6Q+S7vv6fqhpyFG9Ofy9xDxwR3V+wsXg+GJZ/NtWX3B/iCtbwIJXA
    \\wKUXqQ1EDCMMxbj3ac/C6IMnUfmoG0YuBhaGY97I361V2FfbeoTjg6JhN/dEh/k2KcSZmY
    \\Q3cVR9e2Q64UdazIThMVyVVAqIh4FC+ft6mi614n+g/lIHWzjxMsgczh0MSr/hE8BJica/
    \\HT4Bon1zwpE+gPk84nq+V52nWDl+M=
    \\-----END OPENSSH PRIVATE KEY-----
    \\
;
const openssh_fixture_cbc =
    \\-----BEGIN OPENSSH PRIVATE KEY-----
    \\b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jYmMAAAAGYmNyeXB0AAAAGAAAABCeFkEsJ1
    \\imSchpU7c7O/5AAAAABAAAAAEAAAEXAAAAB3NzaC1yc2EAAAADAQABAAABAQCNWypA70Vt
    \\JZXHyjUgtJTZjkQuzGWuYP5fMOHrNRCc1piJbPhg/J32r3f4ePySuDG1YwkYNO7QKqfmSW
    \\84A59EF3zcQYzjR/CuVqG0GZFXa27aLKyVQvo9NRuKMY1d7FSLDR9UNVve2uOlWEhKi4LK
    \\59/FsONBZ7f2Uf+bLGMIOBucql+ztpxv9rpFX9dFv7x86uSzyNVmen3Gq3etUnxZ/x5K70
    \\BX/J8o3K/PhhGzs97KPNiSbiHp9jjV0zFwAgYmyVHi09fVd9WwpM3IigTbYOTSRmrfwiFT
    \\ltU6ivMDtEi8B9NELDMPbpYpydJTDlJbwMnPqkVpI1ER34SSqpstAAAD0MtoRWM3d6mFTg
    \\5loJrhltibguJCznq66OF7aYd+WOJxOegituf8hj1udal1z4LkiC8pNj/S7Y5OsmJMuIYo
    \\vu0SuGq6jU0fahyVA3i+Fm9VA0vLkNWcxspIdyf3JQQTz60okTymYUZPkbhYSQW4PziMP6
    \\FQ5zDk/bHRzmb1hNBh1HxIFhmQRojxz0XZwh3AXb4TjmGDRKuZdbJxSCVWufa5BJWWycQ8
    \\fA7dgdhQEwIGrlM8OJg4JMjjcqPZcSPv1Yq64adD6Nmf9Ae/w9myeB18QUU4ClKqbTXVD6
    \\CIWZ3NwmpVRMdS6xjwJBTcC4IxXwm8cn0XNh9W9VKqRgFH9UzhQSnslkVq1RzOBJvWpRuv
    \\+JG5HRh5X9gCJr5pHwevmSRGCryZfQljjzUGcb+VNJvd3z0N/fDLWOusVCxvSbPaKyv8tp
    \\hYhFIAZ9B2hAr5Kqk1dK/IX/YA+933Rdw+INV+9vOzhUfesNnYv+U6LjLk3EYtZusvoQb1
    \\ebLP4qb2tHIUwBACmFIdMMMAVRQg53YCV1WNoIVqiwaIw3q6HAFQYcZijkFEkJLL8EN0l7
    \\XjCigjHHQfw/CQyYTDCrW7Wy12pLATodWm3Zx/JRn4i7fBB9pKhQgGecJZtU+5NwZ2EvPB
    \\n+ERL9ozQdd2WMdvhrJ0Va44xFCmtypX9+lY4n7Bxsz34NGgB9J4SU47/QRje66qoDQvYs
    \\6lqPhMQHrz/mlBBT8uJZyBOn4AqARrd20fSqxfdTDrUKwaYHtLnSUDUZEmWvM9vzvhmCq2
    \\v2JvzQTA45KYtNysZFu1w9kq8ATkpkCAwz3stqaU6y7CW2ykBCpnshLMOUK6bVcpa3d4mB
    \\LKRo2bTr6Y9bZYtGEPKPtZFFY9nzUBvi+sCVORKNQ3JaavBcxPdNTelBcwJqLyWd0x9A/z
    \\KCsYB47fbh6R4AFcH6p6z2I6fvmukrFzhfL8dv3JnRXCctq/ISPF6R0165Q4P0m9ufX9uh
    \\H3lZPqpU74nSf/8UhgEoVJ47wxEowuDLLdZ01jReZqr93knazhN8O1f9tvyTDYNl/f/IMJ
    \\GlWQd0/VZUAjZujeQBDe43Rmxx8xvtkcDfY6tvnJHNIQxBxuDlnJXXXt+YQ8Kf68KDqJ9P
    \\+CrA5Ck21BWiyHxAqbsiZ9+13HffLTEnIBDq/A4eU+PJqPwPFtrN3/gb9ZHk6zsLQBSh4c
    \\g36pMfM1CrZaoaWR4l/mNFqCqEZOR8jhH8Rgr34QH3Wn9VDo/m1SzCZ4DliXi6roZ1Tl8S
    \\lmCiSOw5F5C5NkKKSGwjGiuE+V9g4=
    \\-----END OPENSSH PRIVATE KEY-----
    \\
;

test "fromOpenSSH: unencrypted key parses, signs and verifies (P1 round-trip)" {
    const sk = try fromOpenSSH(openssh_fixture_plain, "");
    const pk = PublicKey{ .n = sk.n, .e = try Fe.fromPrimitive(u32, sk.n, 65537), .n_mont = sk.n_mont };
    const msg = "zig-libs rsa: P4b openssh fixture";
    var sig_buf: [max_modulus_len]u8 = undefined;
    const sig = try signPkcs1v15(sk, std.crypto.hash.sha2.Sha256, msg, &sig_buf);
    try verifyPkcs1v15(pk, std.crypto.hash.sha2.Sha256, msg, sig);
}

test "fromOpenSSH: bcrypt/aes256-ctr and aes256-cbc decrypt to the unencrypted sibling" {
    const sk_plain = try fromOpenSSH(openssh_fixture_plain, "");
    const k = byteLen(sk_plain.n.bits());
    var n_plain: [max_modulus_len]u8 = undefined;
    try sk_plain.n.toBytes(n_plain[0..k], .big);

    inline for (.{ openssh_fixture_ctr, openssh_fixture_cbc }) |fixture| {
        const sk = try fromOpenSSH(fixture, "hunter2");
        try testing.expectEqual(sk_plain.n.bits(), sk.n.bits());
        var n_enc: [max_modulus_len]u8 = undefined;
        try sk.n.toBytes(n_enc[0..k], .big);
        try testing.expectEqualSlices(u8, n_plain[0..k], n_enc[0..k]);
    }
}

test "fromOpenSSH: wrong or empty passphrase is IncorrectPassphrase" {
    try testing.expectError(error.IncorrectPassphrase, fromOpenSSH(openssh_fixture_ctr, "hunter3"));
    try testing.expectError(error.IncorrectPassphrase, fromOpenSSH(openssh_fixture_ctr, ""));
    try testing.expectError(error.IncorrectPassphrase, fromOpenSSH(openssh_fixture_cbc, "HUNTER2"));
}

/// Test helper: assemble a synthetic openssh-key-v1 binary image from SSH
/// wire pieces, then armor it as an `OPENSSH PRIVATE KEY` PEM block.
const OpensshTestBuilder = struct {
    buf: [1024]u8 = undefined,
    len: usize = 0,

    fn raw(w: *OpensshTestBuilder, bytes: []const u8) *OpensshTestBuilder {
        @memcpy(w.buf[w.len..][0..bytes.len], bytes);
        w.len += bytes.len;
        return w;
    }

    fn int(w: *OpensshTestBuilder, v: u32) *OpensshTestBuilder {
        std.mem.writeInt(u32, w.buf[w.len..][0..4], v, .big);
        w.len += 4;
        return w;
    }

    fn str(w: *OpensshTestBuilder, s: []const u8) *OpensshTestBuilder {
        return w.int(@intCast(s.len)).raw(s);
    }

    fn pem(w: *const OpensshTestBuilder, out: []u8) []const u8 {
        const prefix = "-----BEGIN OPENSSH PRIVATE KEY-----\n";
        const suffix = "\n-----END OPENSSH PRIVATE KEY-----\n";
        @memcpy(out[0..prefix.len], prefix);
        const b64 = std.base64.standard.Encoder.encode(out[prefix.len..], w.buf[0..w.len]);
        @memcpy(out[prefix.len + b64.len ..][0..suffix.len], suffix);
        return out[0 .. prefix.len + b64.len + suffix.len];
    }
};

test "fromOpenSSH: rejects bad magic, truncation, nkeys != 1, trailing garbage" {
    var pem_buf: [2048]u8 = undefined;

    { // wrong magic
        var b = OpensshTestBuilder{};
        _ = b.raw("openssh-key-v2\x00").str("none").str("none").str("").int(1).str("").str("");
        try testing.expectError(error.InvalidOpenSSH, fromOpenSSH(b.pem(&pem_buf), ""));
    }
    { // truncated container: stops after kdfname
        var b = OpensshTestBuilder{};
        _ = b.raw("openssh-key-v1\x00").str("none").str("none");
        try testing.expectError(error.InvalidOpenSSH, fromOpenSSH(b.pem(&pem_buf), ""));
    }
    { // truncated string: private section claims more bytes than exist
        var b = OpensshTestBuilder{};
        _ = b.raw("openssh-key-v1\x00").str("none").str("none").str("").int(1).str("").int(64);
        try testing.expectError(error.InvalidOpenSSH, fromOpenSSH(b.pem(&pem_buf), ""));
    }
    { // nkeys != 1
        var b = OpensshTestBuilder{};
        _ = b.raw("openssh-key-v1\x00").str("none").str("none").str("").int(2).str("").str("");
        try testing.expectError(error.InvalidOpenSSH, fromOpenSSH(b.pem(&pem_buf), ""));
    }
    { // trailing garbage after the private section
        var b = OpensshTestBuilder{};
        _ = b.raw("openssh-key-v1\x00").str("none").str("none").str("").int(1).str("").str("").raw("x");
        try testing.expectError(error.InvalidOpenSSH, fromOpenSSH(b.pem(&pem_buf), ""));
    }
}

test "fromOpenSSH: rejects unsupported cipher/kdf and foreign PEM labels" {
    var pem_buf: [2048]u8 = undefined;

    { // cipher this module does not speak
        var b = OpensshTestBuilder{};
        _ = b.raw("openssh-key-v1\x00").str("chacha20-poly1305@openssh.com").str("bcrypt").str("").int(1).str("").str("");
        try testing.expectError(error.UnsupportedCipher, fromOpenSSH(b.pem(&pem_buf), "pw"));
    }
    { // unknown kdf
        var b = OpensshTestBuilder{};
        _ = b.raw("openssh-key-v1\x00").str("aes256-ctr").str("argon2id").str("").int(1).str("").str("");
        try testing.expectError(error.UnsupportedKdf, fromOpenSSH(b.pem(&pem_buf), "pw"));
    }
    { // inconsistent: encryption without a kdf
        var b = OpensshTestBuilder{};
        _ = b.raw("openssh-key-v1\x00").str("aes256-ctr").str("none").str("").int(1).str("").str("");
        try testing.expectError(error.InvalidOpenSSH, fromOpenSSH(b.pem(&pem_buf), "pw"));
    }

    try testing.expectError(error.MissingPemBlock, fromOpenSSH("no pem block here", ""));
    try testing.expectError(error.UnsupportedPemLabel, fromOpenSSH(
        "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n",
        "",
    ));
}

test "fromOpenSSH: rejects checkint mismatch and non-RSA key types" {
    var pem_buf: [2048]u8 = undefined;

    { // checkint mismatch on an unencrypted key = corruption
        var priv = OpensshTestBuilder{};
        _ = priv.int(0xdeadbeef).int(0xdeadbee0);
        var b = OpensshTestBuilder{};
        _ = b.raw("openssh-key-v1\x00").str("none").str("none").str("").int(1).str("").str(priv.buf[0..priv.len]);
        try testing.expectError(error.InvalidOpenSSH, fromOpenSSH(b.pem(&pem_buf), ""));
    }
    { // well-formed container holding an ssh-ed25519 key
        var priv = OpensshTestBuilder{};
        _ = priv.int(7).int(7).str("ssh-ed25519");
        var b = OpensshTestBuilder{};
        _ = b.raw("openssh-key-v1\x00").str("none").str("none").str("").int(1).str("").str(priv.buf[0..priv.len]);
        try testing.expectError(error.UnsupportedKeyType, fromOpenSSH(b.pem(&pem_buf), ""));
    }
}

// ── opt-in micro-benchmark: montint vs the old std.crypto.ff modexp path ─────
//
// The pilot deliverable of the montint rewire (see the module doc comment).
// Off by default; opt in with:
//
//   RSA_BENCH=1 zig build test-rsa -Doptimize=ReleaseFast
//
// For rsa-2048 and rsa-4096 it times, on the SAME freshly generated key and
// host: CRT sign and public verify on BOTH the NEW montint path (the shipped
// `rsasp1`/`rsavp1`) and the OLD `std.crypto.ff` path (the exact pre-rewire
// arithmetic, replicated inline here from git history) — so the before/after is
// a same-session, same-key A/B on nothing but the arithmetic backend. The
// OpenSSL reference column is produced separately (`openssl speed rsaNNNN`).
// Numbers are noisy on a mobile CPU (turbo/thermal); read them as ratios.

fn benchNowNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

// The OLD ff CRT private op (pre-rewire `privateOpCrt`), kept here verbatim as
// the "before" reference. Constant-time via ff, identical math to the new path.
fn ffPrivateOpCrt(sk: SecretKey, in: []const u8, out: []u8) void {
    const c = Fe.fromBytes(sk.n, in, .big) catch unreachable;
    const m1 = sk.p.pow(reduceWide(sk.p, c.v), sk.dp) catch unreachable;
    const m2 = sk.q.pow(reduceWide(sk.q, c.v), sk.dq) catch unreachable;
    const h = sk.p.mul(sk.qinv, sk.p.sub(m1, reduceWide(sk.p, m2.v)));
    const m2_n = reduceWide(sk.n, m2.v);
    const q_n = reduceWide(sk.n, sk.q.v);
    const h_n = reduceWide(sk.n, h.v);
    const m = sk.n.add(m2_n, sk.n.mul(q_n, h_n));
    m.toBytes(out, .big) catch unreachable;
}

fn benchRsa(comptime bits: usize, random: std.Random) void {
    const klen = bits / 8;
    const kp = generate(random, bits, 65537) catch {
        std.debug.print("rsa-{d}: keygen failed\n", .{bits});
        return;
    };
    const sk = kp.secret_key;
    const pk = kp.public_key;

    // A message representative < n: top byte 0 guarantees it (generated n has
    // its top bit set, so value < 2^(bits-8) < n).
    var msg: [klen]u8 = undefined;
    for (&msg) |*b| b.* = random.int(u8);
    msg[0] = 0;

    const sign_iters: usize = if (bits >= 4096) 40 else 200;
    const verify_iters: usize = if (bits >= 4096) 1_000 else 3_000;
    var sink: u64 = 0;

    // sign — NEW (montint)
    var sig: [klen]u8 = undefined;
    {
        const t0 = benchNowNs();
        var i: usize = 0;
        while (i < sign_iters) : (i += 1) {
            sig = rsasp1(klen, msg, sk) catch unreachable;
            sink ^= sig[klen - 1];
        }
        const dt = benchNowNs() - t0;
        std.debug.print("rsa-{d} sign   montint : {d:>10} ns/op\n", .{ bits, dt / sign_iters });
    }
    // sign — OLD (ff)
    {
        var out: [klen]u8 = undefined;
        const t0 = benchNowNs();
        var i: usize = 0;
        while (i < sign_iters) : (i += 1) {
            ffPrivateOpCrt(sk, &msg, &out);
            sink ^= out[klen - 1];
        }
        const dt = benchNowNs() - t0;
        std.debug.print("rsa-{d} sign   ff      : {d:>10} ns/op\n", .{ bits, dt / sign_iters });
    }
    // verify — NEW (montint)
    {
        const t0 = benchNowNs();
        var i: usize = 0;
        while (i < verify_iters) : (i += 1) {
            const v = rsavp1(klen, sig, pk) catch unreachable;
            sink ^= v[klen - 1];
        }
        const dt = benchNowNs() - t0;
        std.debug.print("rsa-{d} verify montint : {d:>10} ns/op\n", .{ bits, dt / verify_iters });
    }
    // verify — OLD (ff)
    {
        const t0 = benchNowNs();
        var i: usize = 0;
        while (i < verify_iters) : (i += 1) {
            const m = Fe.fromBytes(pk.n, &sig, .big) catch unreachable;
            const c = pk.n.powPublic(m, pk.e) catch unreachable;
            var vb: [klen]u8 = undefined;
            c.toBytes(&vb, .big) catch unreachable;
            sink ^= vb[klen - 1];
        }
        const dt = benchNowNs() - t0;
        std.debug.print("rsa-{d} verify ff      : {d:>10} ns/op\n", .{ bits, dt / verify_iters });
    }
    std.mem.doNotOptimizeAway(sink);
    std.debug.print("\n", .{});
}

test "bench: montint vs ff (opt-in via RSA_BENCH)" {
    if (@import("builtin").target.os.tag == .windows or std.testing.environ.getPosix("RSA_BENCH") == null) return error.SkipZigTest;
    var prng = std.Random.DefaultPrng.init(0x5A17_C0DE_F00D);
    const random = prng.random();
    std.debug.print("\n=== rsa modexp bench: montint vs std.crypto.ff (same key/host) ===\n", .{});
    benchRsa(2048, random);
    benchRsa(4096, random);
}

// ── fuzz: every untrusted-wire key parser must reject, never panic ─────────

fn fuzzPublicKeyFromDer(_: void, smith: *std.testing.Smith) !void {
    var buf: [1024]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const pk = PublicKey.fromDer(buf[0..len]) catch return;
    _ = pk;
}

test "fuzz: PublicKey.fromDer never panics" {
    try testing.fuzz({}, fuzzPublicKeyFromDer, .{});
}

fn fuzzSecretKeyFromDer(_: void, smith: *std.testing.Smith) !void {
    var buf: [1024]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const sk = SecretKey.fromDer(buf[0..len]) catch return;
    _ = sk;
}

test "fuzz: SecretKey.fromDer never panics" {
    try testing.fuzz({}, fuzzSecretKeyFromDer, .{});
}

fn fuzzFromPkcs8(_: void, smith: *std.testing.Smith) !void {
    var buf: [1024]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const sk = fromPkcs8(buf[0..len]) catch return;
    _ = sk;
}

test "fuzz: fromPkcs8 never panics" {
    try testing.fuzz({}, fuzzFromPkcs8, .{});
}

fn fuzzPublicKeyFromPem(_: void, smith: *std.testing.Smith) !void {
    var buf: [1024]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const pk = PublicKey.fromPem(buf[0..len]) catch return;
    _ = pk;
}

test "fuzz: PublicKey.fromPem never panics" {
    try testing.fuzz({}, fuzzPublicKeyFromPem, .{});
}

fn fuzzSecretKeyFromPem(_: void, smith: *std.testing.Smith) !void {
    var buf: [1024]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const sk = SecretKey.fromPem(buf[0..len]) catch return;
    _ = sk;
}

test "fuzz: SecretKey.fromPem never panics" {
    try testing.fuzz({}, fuzzSecretKeyFromPem, .{});
}

fn fuzzFromOpenSSH(_: void, smith: *std.testing.Smith) !void {
    var buf: [1024]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const sk = fromOpenSSH(buf[0..len], "") catch return;
    _ = sk;
}

test "fuzz: fromOpenSSH never panics" {
    try testing.fuzz({}, fuzzFromOpenSSH, .{});
}
