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
//! path (the internal deep audit measured `ff` at ~29× OpenSSL for the CRT
//! sign). `ff` is retained for key derivation, the CRT
//! recombination arithmetic (Garner), reductions, and all serialization; only
//! the exponentiation primitive moved. The `montint` moduli + Montgomery
//! constants are precomputed ONCE per key at construction and carried on the
//! key (`MontParams`), so no per-operation setup cost is paid.
//!
//! ⚠ That last clause is a claim about the CALLER, and it is worth reading as
//! one. It holds for a consumer that builds a key and reuses it — `qap` builds
//! its `SecretKey` when its certificate store loads and then only signs;
//! `iec62351`'s GOOSE verifier carries a built `PublicKey` and verifies per
//! frame. It does NOT hold for certificate path validation, which builds a
//! fresh key per chain link: there the setup IS the per-operation cost, and it
//! dwarfs the operation (measured 2026-09-08: ~500 us to build a 2048-bit
//! public key, 36 us to verify with it). `SPEC.md` § "Performance posture" has
//! the split, the two ways to shrink it, and why neither was taken.
//!
//! SECURITY (internal audit F2/F3): the CRT private op
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
const b64ct = @import("b64ct");

/// Fast constant-time Montgomery modexp backend for the RSA hot path
/// (private CRT op, non-CRT private op, public op). See `montint`'s SPEC.md.
const montint = @import("montint");
const aescbc = @import("aescbc");
/// Batched constant-time inversion (moved from here into montint 2026-10-14).
const safegcd = montint.safegcd;
const burn = @import("burn.zig");

/// Blowfish + OpenBSD bcrypt_pbkdf (P4b support primitives), re-exported
/// for callers that need the KDF stand-alone.
pub const openssh = @import("openssh.zig");

/// Test-only (`build.zig`'s `test_deps`, never `deps`): the fuzz corpus seed
/// helpers, in the format `std.testing.Smith` actually reads.
const testkit = @import("testkit");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Pure-Zig RSA (PKCS#1 v2.2, RFC 8017) — keygen, PKCS1-v1.5/PSS sign+verify, OAEP/PKCS1 encrypt+decrypt, DER/PEM/OpenSSH key parsing.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    // NOTE: CONVENTIONS.md's `meta` tag vocabulary (platform/role/concurrency/
    // model_after/deps) has no dedicated "status" tag; module maturity lives
    // in each SPEC.md's closing "Status" line instead, using the catalog's
    // `extract` (built) / `gap` (not yet built) vocabulary. All phases P1-P6
    // have landed, so SPEC.md's Status line uses `extract`.
    .targets = .{.linux64},
    .platform = .any,
    .role = .util, // pure computation (no I/O, no wire framing of its own) -> util, not .codec
    .concurrency = .reentrant, // no shared/global state; PublicKey/SecretKey are plain value types
    .model_after = "RFC 8017 (PKCS#1 v2.2); std.crypto internal RSA (Certificate/rsa)",
    .deps = .{ "montint", "aescbc", "aes192", "b64ct" }, // b64ct: PEM base64 of private keys, constant time; std.crypto.ff carrier + montint modexp hot path; aescbc/aes192: PBES2 encrypted PKCS#8
};

/// Largest RSA modulus this module supports, in bits: 8192 since 2026-10-14
/// (was std's own verifier ceiling, 4096). 8192-bit keys exist in the wild
/// (`ssh-keygen -b 8192`, some CA and test keys) and are the first thing an
/// OpenSSL user would find refused; OpenSSL's own cap of 16384 is not
/// followed (no deployed use; a key generation of minutes, and a `SecretKey`
/// of twice today's size again). Sizes up to 4096 run exactly as before
/// (the montint slot follows the key); the cost is stack: a `SecretKey` and
/// every `max_modulus_len` buffer doubled.
///
/// **Consumer build option** (the first one in zig-libs, 2026-10-17): the
/// application may lower the cap with `-Drsa-max-modulus-bits=N` (4096..8192,
/// a multiple of 64), or get 4096 from `-Dprofile=small`. Not below 4096:
/// public CA roots with 4096-bit keys are common, so a lower cap would make an
/// HTTPS client refuse ordinary chains. Code size is what it
/// buys: montint instantiates one slot per key size up to the cap (10 at 8192,
/// 8 at 4096, since 2026-10-18; one per 256 bits before), and on an ADX/BMI2
/// CPU each slot is straight-line asm — the rsa sizeprobe (ReleaseSmall,
/// native) is 427 536 B at 8192 and 319 128 B at 4096.
/// A key above the cap is refused the way any oversized key is
/// (`error.InvalidPublicKey` / `InvalidPrivateKey` / `InvalidBits`, or
/// `InvalidDer` when the DER wrapper alone is already too long), never
/// truncated. The default stays 8192: the grade is measured on it.
pub const max_modulus_bits: comptime_int = blk: {
    const bits: comptime_int = zl_options.rsa_max_modulus_bits orelse switch (zl_options.profile) {
        .default => 8192,
        .small => 4096,
    };
    if (bits < 4096 or bits > 8192 or bits % 64 != 0)
        @compileError(std.fmt.comptimePrint("rsa-max-modulus-bits={d}: must be 4096..8192 and a multiple of 64", .{bits}));
    break :blk bits;
};
const zl_options = @import("zl_options");

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
    return bit_count / 8 + @intFromBool(bit_count % 8 != 0); // sweep REV-RS-3: no `+ 7` overflow
}

/// DER integers and externally supplied big-endian values may carry leading
/// zero octets; the `ff` codecs reject inputs longer than the backing `Uint`,
/// so strip them first (I2OSP/OS2IP length tolerance).
fn stripLeadingZeros(bytes: []const u8) []const u8 {
    var i: usize = 0;
    while (i < bytes.len and bytes[i] == 0) : (i += 1) {}
    return bytes[i..];
}

// ── montint backend (every secret-touching operation) ──────────────────────
//
// `montint.DynModint` carries a modulus chosen at run time — a 512…8192-bit
// `n`, or one of its ~half-width CRT primes — on the smallest comptime
// `Modint` slot (a multiple of 4 limbs) that holds it, so a 2048-bit CRT sign
// runs mod-p at L=16 with no padding. Its constants are computed once per key.
//
// Until 2026-10-02 only the two CRT modexps ran here; the reduction of `c`
// into the mod-p/mod-q domains, the Garner recombination and the unblinding
// stayed in `std.crypto.ff`, whose `reduce`/`montgomeryMul`/`toBytes` branch
// on the secret values in ReleaseFast (ctgrind `rsa/crt`: 213 in-file
// contexts, nearly all in `ff.zig`). The whole private path now runs on
// `DynModint`; `std.crypto.ff` stays the public carrier type (`Modulus`,
// `Fe`) and the key-import arithmetic.

/// A modulus plus its Montgomery constants (run-time size).
const MontParams = montint.DynModint(max_modulus_bits);
/// A normal-domain element of a `MontParams`, see `montint.DynModint`.
const MontElem = MontParams.Elem;

/// Precompute the montint modulus for an `ff` modulus. Branchless in the
/// value (`DynModint.fromFf`): this runs on the SECRET CRT primes `p` and
/// `q`, not only on the public `n`.
fn montParamsFromModulus(mod: Modulus) MontParams {
    return MontParams.fromFf(mod) catch unreachable; // odd, ≥ 512 bits
}

/// `fe` as a montint element — a positional limb repack, no branch on the
/// value (`DynModint.elemFromFf`). The secret CRT exponents and `qInv` come
/// through here on every private op: they stay `ff` fields so the existing
/// fault-injection tests and the ctgrind harness still reach the op through
/// them. Every `Fe` this module stores is in the normal domain.
fn feToElem(fe: *const Fe) MontElem {
    return MontParams.elemFromFf(&fe.v);
}

/// Constant-time (in the exponent VALUE) modexp `base^exp mod m` over the
/// precomputed modulus `mp`. `base_be`/`exp_be` are big-endian, both `< m`.
/// Writes the big-endian result (slot-width) into `out_buf` and returns that
/// slice. Used for the non-CRT `c^d mod n`.
fn montPowSecret(mp: *const MontParams, base_be: []const u8, exp_be: []const u8, out_buf: *[max_modulus_len]u8) []const u8 {
    var b = MontParams.loadBE(base_be) catch unreachable; // < m
    defer std.crypto.secureZero(u64, &b);
    var e = MontParams.loadBE(exp_be) catch unreachable; // < m
    defer std.crypto.secureZero(u64, &e);
    const r = mp.pow(&b, &e);
    const out = out_buf[0 .. mp.L * 8];
    mp.toBytesBE(&r, out);
    return out;
}

/// Variable-time modexp `base^e mod m` for a PUBLIC exponent (RSA verify /
/// encrypt) — square-and-multiply over `e`'s actual bit length, so the tiny
/// public exponent (typically 65537) costs ~17 squarings + 1 multiply rather
/// than the full-width `L·64` squarings a constant-time modexp would spend.
/// `base_be` is big-endian, `< m`. Slot-width result, as `montPowSecret`.
fn montPowPublic(mp: *const MontParams, base_be: []const u8, e_be: []const u8, out_buf: *[max_modulus_len]u8) []const u8 {
    const b = MontParams.loadBE(base_be) catch unreachable; // < m
    const r = mp.powPublic(&b, stripLeadingZeros(e_be));
    const out = out_buf[0 .. mp.L * 8];
    mp.toBytesBE(&r, out);
    return out;
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

        return .{ .n = n, .e = e, .n_mont = MontParams.fromLimbsPublic(&MontParams.elemFromFf(&n.v)) catch unreachable }; // odd, ≥ 512 bits
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

    /// The verify-only form of this key: same modulus, same exponent, no
    /// `ff` constants (see `VerifyKey`). For a holder of a `KeyPair` that
    /// hands its public half to a verifier that takes a `VerifyKey`.
    pub fn verifyKey(pk: *const PublicKey) VerifyKey {
        return .{ .mp = pk.n_mont, .e = pk.publicExponent() };
    }

    /// `e` as the `u32` every constructor validated it to fit.
    fn publicExponent(pk: PublicKey) u32 {
        return pk.e.toPrimitive(u32) catch unreachable; // < 2^32 since fromBytes
    }

    /// Same modulus and exponent (Go `PublicKey.Equal`). Public values.
    pub fn equal(a: *const PublicKey, b: *const PublicKey) bool {
        return MontParams.eql(&a.n_mont.m, &b.n_mont.m) and a.publicExponent() == b.publicExponent();
    }

    /// Modulus length in bits.
    pub fn bits(pk: *const PublicKey) usize {
        return pk.n_mont.bits();
    }

    /// Modulus length in bytes — the signature and ciphertext size
    /// (`k` in RFC 8017; Go `PublicKey.Size`).
    pub fn size(pk: *const PublicKey) usize {
        return pk.n_mont.byteLen();
    }

    /// DER `RSAPublicKey` (PKCS#1 A.1.1) — `i2d_RSAPublicKey`, Go
    /// `x509.MarshalPKCS1PublicKey`. `out.len ≥ max_pkcs1_public_der_len`
    /// always suffices; the result is a prefix of `out`.
    pub fn toPkcs1Der(pk: *const PublicKey, out: []u8) MarshalError![]u8 {
        return marshal.publicDer(&pk.n_mont, pk.publicExponent(), .pkcs1, out);
    }

    /// DER X.509 `SubjectPublicKeyInfo` (rsaEncryption, NULL parameters) —
    /// `i2d_PUBKEY`, Go `x509.MarshalPKIXPublicKey`. `out.len ≥
    /// max_spki_der_len` always suffices.
    pub fn toSpkiDer(pk: *const PublicKey, out: []u8) MarshalError![]u8 {
        return marshal.publicDer(&pk.n_mont, pk.publicExponent(), .spki, out);
    }

    /// PEM: `PUBLIC KEY` (SPKI, what `openssl pkey -pubout` writes) or
    /// `RSA PUBLIC KEY` (PKCS#1). `out.len ≥ max_public_pem_len` always
    /// suffices.
    pub fn toPem(pk: *const PublicKey, form: PublicKeyForm, out: []u8) MarshalError![]u8 {
        return marshal.publicPem(&pk.n_mont, pk.publicExponent(), form, out);
    }
};

/// Key serialisation (`toPkcs1Der`, `toSpkiDer`, `toPkcs8Der`, `toPem`).
const marshal = @import("marshal.zig");
pub const MarshalError = marshal.MarshalError;
/// Public-key encodings: `.spki` = X.509 `SubjectPublicKeyInfo` (PEM `PUBLIC
/// KEY`), `.pkcs1` = bare `RSAPublicKey` (PEM `RSA PUBLIC KEY`).
pub const PublicKeyForm = marshal.PublicDer;
/// Private-key encodings: `.pkcs8` = `PrivateKeyInfo` (PEM `PRIVATE KEY`,
/// the OpenSSL 3 default), `.pkcs1` = bare `RSAPrivateKey` (PEM `RSA PRIVATE
/// KEY`, `openssl rsa -traditional`).
pub const PrivateKeyForm = marshal.PrivateDer;
/// Output buffer sizes that fit any key of up to `max_modulus_bits`.
pub const max_pkcs1_public_der_len = marshal.max_pkcs1_public_der_len;
pub const max_spki_der_len = marshal.max_spki_der_len;
pub const max_pkcs1_private_der_len = marshal.max_pkcs1_private_der_len;
pub const max_pkcs8_der_len = marshal.max_pkcs8_der_len;
pub const max_public_pem_len = marshal.max_public_pem_len;
pub const max_private_pem_len = marshal.max_private_pem_len;

/// A public key that can only verify (PKCS#1 v1.5, PSS), built for a key
/// that is used once: certificate path validation, a handshake, a token.
///
/// `PublicKey` also carries `n` and `e` as `std.crypto.ff` values, and
/// `ff.Modulus.fromBytes` computes Montgomery constants of its own that the
/// verify path never reads — for a 2048-bit key that construction cost
/// several times the verification itself. This type keeps only the montint
/// modulus and the exponent, with exactly `PublicKey.fromBytes`'s checks
/// (size 512…8192 bits, odd `n`, odd `3 ≤ e < 2^32`), and verifies
/// identically. Hold a `PublicKey` when the key is kept and used for
/// anything else; build this when it is parsed, used and dropped.
pub const VerifyKey = struct {
    mp: MontParams,
    e: u32,

    pub const FromBytesError = PublicKey.FromBytesError;
    pub const FromDerError = PublicKey.FromDerError;

    /// From raw big-endian modulus and exponent (leading zeros allowed), as
    /// `PublicKey.fromBytes`.
    pub fn fromBytes(modulus_bytes: []const u8, exponent_bytes: []const u8) FromBytesError!VerifyKey {
        const n_bytes = stripLeadingZeros(modulus_bytes);
        if (n_bytes.len > max_modulus_len) return error.InvalidPublicKey;
        // Rejects an even modulus and one below 3; the length is public.
        const mp = MontParams.fromBytesBEPublic(n_bytes) catch return error.InvalidPublicKey;
        if (mp.bits() < min_modulus_bits) return error.InvalidPublicKey;

        const e_bytes = stripLeadingZeros(exponent_bytes);
        if (e_bytes.len == 0 or e_bytes.len > 4) return error.InvalidPublicKey;
        var e: u32 = 0;
        for (e_bytes) |b| e = e << 8 | b;
        if (e & 1 == 0 or e < 3) return error.InvalidPublicKey;
        // `PublicKey.fromBytes` takes `e` as an element of Z_n, so it refuses
        // `e ≥ n`; with `n` ≥ 512 bits and `e` < 2^32 that never triggers.
        return .{ .mp = mp, .e = e };
    }

    /// From a DER `RSAPublicKey` or an X.509 `SubjectPublicKeyInfo`
    /// wrapping one, as `PublicKey.fromDer`.
    pub fn fromDer(bytes: []const u8) FromDerError!VerifyKey {
        const parts = publicKeyPartsFromDer(bytes) catch return error.InvalidDer;
        return fromBytes(parts.n, parts.e) catch error.InvalidDer;
    }

    /// Modulus length in bits.
    pub fn bits(vk: *const VerifyKey) usize {
        return vk.mp.bits();
    }

    /// As `PublicKey.toPkcs1Der`.
    pub fn toPkcs1Der(vk: *const VerifyKey, out: []u8) MarshalError![]u8 {
        return marshal.publicDer(&vk.mp, vk.e, .pkcs1, out);
    }

    /// As `PublicKey.toSpkiDer`.
    pub fn toSpkiDer(vk: *const VerifyKey, out: []u8) MarshalError![]u8 {
        return marshal.publicDer(&vk.mp, vk.e, .spki, out);
    }

    /// As `PublicKey.toPem`.
    pub fn toPem(vk: *const VerifyKey, form: PublicKeyForm, out: []u8) MarshalError![]u8 {
        return marshal.publicPem(&vk.mp, vk.e, form, out);
    }

    /// As `verifyPkcs1v15`.
    pub fn verifyPkcs1v15(vk: *const VerifyKey, comptime Hash: type, msg: []const u8, sig: []const u8) VerifyPkcs1v15Error!void {
        return verifyPkcs1v15Mont(&vk.mp, vk.e, Hash, msg, sig);
    }

    /// As `verifyPss`.
    pub fn verifyPss(vk: *const VerifyKey, comptime Hash: type, msg: []const u8, sig: []const u8, salt_len: usize) VerifyPssError!void {
        return verifyPssMont(&vk.mp, vk.e, Hash, msg, sig, salt_len);
    }

    /// As `verifyPkcs1v15Prehashed`.
    pub fn verifyPkcs1v15Prehashed(vk: *const VerifyKey, comptime Hash: type, digest: *const [Hash.digest_length]u8, sig: []const u8) VerifyPkcs1v15Error!void {
        return verifyPkcs1v15DigestMont(&vk.mp, vk.e, Hash, digest, sig);
    }

    /// As `verifyPssPrehashed`.
    pub fn verifyPssPrehashed(vk: *const VerifyKey, comptime Hash: type, digest: *const [Hash.digest_length]u8, sig: []const u8, salt_len: usize) VerifyPssError!void {
        _ = try verifyPssDigestMont(&vk.mp, vk.e, Hash, Hash, digest, sig, salt_len);
    }

    /// As `verifyPkcs1v15Digest`.
    pub fn verifyPkcs1v15Digest(vk: *const VerifyKey, id: HashId, digest: []const u8, sig: []const u8) (VerifyPkcs1v15Error || DigestError)!void {
        return verifyPkcs1v15DigestAny(&vk.mp, vk.e, id, digest, sig);
    }

    /// As `verifyPssDigest`.
    pub fn verifyPssDigest(vk: *const VerifyKey, id: HashId, digest: []const u8, sig: []const u8, salt_len: ?usize) (VerifyPssError || DigestError)!usize {
        return verifyPssDigestAny(&vk.mp, vk.e, id, digest, sig, salt_len);
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
    /// Timing note (2026-10-03): the derivation is montint limb arithmetic,
    /// constant-time in the primes — `n` a limb product, `λ` from
    /// `montint.nt.lcm`, `d`/`dP`/`dQ` from `inverseOfModulus` (inverses
    /// modulo the even `λ`, `p−1`, `q−1`), `qInv` by Fermat on montint. The
    /// one step still variable-time on `p`, `q` is building their
    /// `std.crypto.ff` `Modulus` carriers (`sk.p`, `sk.q`); SPEC Backlog.
    /// Cost: a few milliseconds at 8192-bit width (the gcd and lcm run at the
    /// full `max_modulus_bits` capacity, whatever the key size).
    pub fn fromPrimes(out: *SecretKey, p_bytes: []const u8, q_bytes: []const u8, e_bytes: []const u8) FromPrimesError!void {
        const r = fromPrimesUnburned(out, p_bytes, q_bytes, e_bytes);
        burn.stack(burn.key_burn);
        return r;
    }

    noinline fn fromPrimesUnburned(out: *SecretKey, p_bytes: []const u8, q_bytes: []const u8, e_bytes: []const u8) FromPrimesError!void {
        out.* = fromPrimesValue(p_bytes, q_bytes, e_bytes) catch |err| {
            std.crypto.secureZero(u8, std.mem.asBytes(out));
            return err;
        };
    }

    fn fromPrimesValue(p_bytes: []const u8, q_bytes: []const u8, e_bytes: []const u8) FromPrimesError!SecretKey {
        return fromPrimesImpl(p_bytes, q_bytes, e_bytes) catch error.InvalidPrivateKey;
    }

    pub const FromDerError = error{ InvalidDer, InvalidPrivateKey };

    /// Parse a private key from a DER-encoded bare PKCS#1 `RSAPrivateKey`
    /// (RFC 8017 Appendix A.1.2) — the format `openssl rsa -traditional`
    /// writes (as opposed to `fromPkcs8`'s `PrivateKeyInfo` wrapper). Only
    /// the two-prime form (version 0) is supported; multi-prime keys
    /// (version 1, `otherPrimeInfos`) are rejected. The key is derived from
    /// `p`/`q`/`e` by `fromPrimes`; the on-disk `n`, `dP`, `dQ`, `qInv` must
    /// equal the derived values and `d` must be a valid private exponent
    /// (λ- or φ-reduced, both occur in the wild; it is kept as given), else
    /// `error.InvalidPrivateKey` — what `openssl rsa -check` and Go's
    /// `PrivateKey.Validate` refuse.
    pub fn fromDer(out: *SecretKey, bytes: []const u8) FromDerError!void {
        const r = fromDerUnburned(out, bytes);
        burn.stack(burn.key_burn);
        return r;
    }

    noinline fn fromDerUnburned(out: *SecretKey, bytes: []const u8) FromDerError!void {
        out.* = fromDerValue(bytes) catch |err| {
            std.crypto.secureZero(u8, std.mem.asBytes(out));
            return err;
        };
    }

    fn fromDerValue(bytes: []const u8) FromDerError!SecretKey {
        return secretKeyFromPkcs1Impl(bytes) catch |err| switch (err) {
            error.InvalidPrivateKey => error.InvalidPrivateKey,
            else => error.InvalidDer,
        };
    }

    /// Parse a private key from a PEM text block: `PRIVATE KEY` (PKCS#8
    /// `PrivateKeyInfo`, via `fromPkcs8`) or `RSA PRIVATE KEY` (bare PKCS#1
    /// `RSAPrivateKey`, via `fromDer`). The first matching block in `text` is
    /// used. `ENCRYPTED PRIVATE KEY` (PKCS#8 `EncryptedPrivateKeyInfo`)
    /// needs a password and goes to `fromPemEncrypted`; OpenSSH (`OPENSSH
    /// PRIVATE KEY`) blocks belong to the module-level `fromOpenSSH`; both report
    /// `error.UnsupportedPemLabel` here, never silently misparsed.
    pub fn fromPem(out: *SecretKey, text: []const u8) PemError!void {
        const r = fromPemUnburned(out, text);
        burn.stack(burn.key_burn);
        return r;
    }

    noinline fn fromPemUnburned(out: *SecretKey, text: []const u8) PemError!void {
        out.* = fromPemValue(text) catch |err| {
            std.crypto.secureZero(u8, std.mem.asBytes(out));
            return err;
        };
    }

    fn fromPemValue(text: []const u8) PemError!SecretKey {
        const block = try pemDecodeBody(text);
        if (std.mem.eql(u8, block.label, "PRIVATE KEY")) {
            return try fromPkcs8Value(block.der());
        }
        if (std.mem.eql(u8, block.label, "RSA PRIVATE KEY")) {
            return try SecretKey.fromDerValue(block.der());
        }
        return error.UnsupportedPemLabel;
    }

    /// `e` as the `u32` every constructor validated it to fit.
    fn publicExponent(sk: *const SecretKey) u32 {
        return sk.e.toPrimitive(u32) catch unreachable; // < 2^32 since fromPrimes
    }

    /// The public half (Go `PrivateKey.Public`): `n`, `e` and the public-op
    /// constants are all stored.
    pub fn publicKey(sk: *const SecretKey) PublicKey {
        return .{ .n = sk.n, .e = sk.e, .n_mont = sk.n_mont };
    }

    /// DER `RSAPrivateKey`, version 0 (PKCS#1 A.1.2) — `openssl rsa
    /// -traditional -outform DER`, Go `x509.MarshalPKCS1PrivateKey`. Written
    /// straight into `out` (no staging copy of the secrets); `out` is zeroed
    /// on error. `out.len ≥ max_pkcs1_private_der_len` always suffices.
    /// The byte lengths of the secret INTEGERs are part of DER and so of the
    /// output's timing, as they are of every encoder's and parser's.
    pub fn toPkcs1Der(sk: *const SecretKey, out: []u8) MarshalError![]u8 {
        return marshal.privateDer(sk, .pkcs1, out);
    }

    /// DER PKCS#8 `PrivateKeyInfo` (RFC 5958 v1) — `openssl pkey -outform
    /// DER`, Go `x509.MarshalPKCS8PrivateKey`. As `toPkcs1Der`;
    /// `out.len ≥ max_pkcs8_der_len` always suffices.
    pub fn toPkcs8Der(sk: *const SecretKey, out: []u8) MarshalError![]u8 {
        return marshal.privateDer(sk, .pkcs8, out);
    }

    /// PEM `PRIVATE KEY` (`.pkcs8`) or `RSA PRIVATE KEY` (`.pkcs1`), the
    /// unencrypted forms `fromPem` reads. As `toPkcs1Der`;
    /// `out.len ≥ max_private_pem_len` always suffices.
    pub fn toPem(sk: *const SecretKey, form: PrivateKeyForm, out: []u8) MarshalError![]u8 {
        return marshal.privatePem(sk, form, out);
    }

    /// PEM `ENCRYPTED PRIVATE KEY` (PBES2, see `fromPkcs8Encrypted`) — and,
    /// so one call serves input of unknown kind, every label `fromPem`
    /// reads (the password is then unused).
    pub fn fromPemEncrypted(out: *SecretKey, text: []const u8, password: []const u8) (PemError || FromEncryptedError)!void {
        const r = fromPemEncryptedUnburned(out, text, password);
        burn.stack(burn.key_burn);
        return r;
    }

    noinline fn fromPemEncryptedUnburned(out: *SecretKey, text: []const u8, password: []const u8) (PemError || FromEncryptedError)!void {
        out.* = fromPemEncryptedValue(text, password) catch |err| {
            std.crypto.secureZero(u8, std.mem.asBytes(out));
            return err;
        };
    }

    fn fromPemEncryptedValue(text: []const u8, password: []const u8) (PemError || FromEncryptedError)!SecretKey {
        const block = try pemDecodeBody(text);
        if (std.mem.eql(u8, block.label, "ENCRYPTED PRIVATE KEY")) return fromPkcs8EncryptedValue(block.der(), password);
        return fromPemValue(text);
    }

    /// DER PKCS#8 `EncryptedPrivateKeyInfo`: PBES2, PBKDF2, AES-CBC
    /// (`openssl pkcs8 -topk8`; the default `opts` are OpenSSL 3's exact
    /// parameter shape). Salt and IV come from `random`, which MUST be a
    /// CSPRNG. `out.len ≥ max_encrypted_pkcs8_der_len` always suffices;
    /// `out` is zeroed on error.
    pub fn toPkcs8Encrypted(sk: *const SecretKey, password: []const u8, random: std.Random, opts: Pbes2Options, out: []u8) EncryptError![]u8 {
        const r = marshal.encryptedDer(sk, password, random, opts, out);
        burn.stack(burn.key_burn);
        return r;
    }

    /// As `toPkcs8Encrypted`, PEM `ENCRYPTED PRIVATE KEY`;
    /// `out.len ≥ max_encrypted_pem_len` always suffices.
    pub fn toPemEncrypted(sk: *const SecretKey, password: []const u8, random: std.Random, opts: Pbes2Options, out: []u8) EncryptError![]u8 {
        const r = marshal.encryptedPem(sk, password, random, opts, out);
        burn.stack(burn.key_burn);
        return r;
    }
};

// ── big.int helpers (the public-operand inverse only) ───────────────────────
//
// `fromPrimes` stopped using these on 2026-10-03 (montint limb arithmetic,
// constant-time) and the per-op blinding inverse on 2026-10-10 (`montint.safegcd`);
// what remains is `bigModInverse` for `blindrsa`.

const BigInt = std.math.big.int.Managed;

/// Limb capacity covering 2×`max_modulus_bits` products plus headroom; every
/// scratch `BigInt` is pre-sized to this so no reallocation-driven growth
/// happens inside the fixed-buffer arena.
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

/// `e⁻¹ (mod m)` via the extended Euclidean algorithm over a (possibly
/// composite) `m`; fails with `error.InvalidPrivateKey` unless gcd(e, m) = 1.
/// VARIABLE-TIME in both operands (division-based Euclid — `std.crypto.ff`
/// has no `invert`, and Fermat inversion needs a *prime* modulus, which a
/// composite-modulus caller may not even know the factorization of). No
/// longer used inside this module: per-op CRT base-blinding moved to the
/// constant-time `montint.safegcd` on 2026-10-10, key derivation to montint's
/// `inverseOfModulus` on 2026-10-03.
///
/// `pub` so sibling modules needing a generic composite-modulus inverse
/// (currently `blindrsa`, for its RFC 9474 blinding-factor inversion) can
/// reuse this instead of carrying their own copy. It is a bare arithmetic
/// primitive with NO masking of its own — a caller with a secret operand
/// MUST mask it (multiply by a fresh independent random unit) before
/// calling, the same way `blindrsa`'s `maskedInvert` does; passing a secret directly leaks it through the run's data-dependent
/// branch count. The returned `BigInt` is a fresh, caller-owned value (the
/// caller's allocator is used for it, same as every other scratch value
/// here); this module always draws `gpa` from a `FixedBufferAllocator`
/// arena and lets the whole arena die together, never calling `.deinit()`
/// individually — a caller using a real allocator must deinit the result.
pub fn bigModInverse(gpa: std.mem.Allocator, e: *const BigInt, m: *const BigInt) !BigInt {
    // Sweep RS-4: a zero modulus reached `divFloor` below with a zero divisor
    // (std asserts); there is no inverse modulo 0 (`e = 1, m = 0` got that far).
    if (m.eqlZero()) return error.InvalidPrivateKey;
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
    // invertibility verdict below, but reject early and explicitly. e is
    // public, so are these branches.
    if (eb.len == 0 or eb[eb.len - 1] & 1 == 0) return error.InvalidPrivateKey;
    if (eb.len == 1 and eb[0] < 3) return error.InvalidPrivateKey;
    // Sweep REV-RS-1: e < 2^32, as `PublicKey.fromBytes` and `generate` require; every
    // later `publicExponent()` (`toPrimitive(u32) catch unreachable`) relies on it.
    if (eb.len > 4) return error.InvalidPrivateKey;

    // `Modulus.fromBytes` rejects even and < 3 values, covering p, q oddness.
    // ⚠ These two `std.crypto.ff` constructions are the derivation's one
    // remaining variable-time step on the secret primes (ff's Montgomery
    // setup branches on the value) — they are the key's public carrier
    // type (`sk.p`, `sk.q`); SPEC Backlog.
    const p = Modulus.fromBytes(pb, .big) catch return error.InvalidPrivateKey;
    const q = Modulus.fromBytes(qb, .big) catch return error.InvalidPrivateKey;

    // Everything else is montint limb arithmetic, constant-time in the
    // primes' values (2026-10-03; until then std.math.big.int — `gcd`,
    // `divFloor` and an extended Euclid on λ, the binary-GCD class of
    // single-trace keygen attack, Aldaya et al. 2019).
    var pv = MontParams.loadBE(pb) catch return error.InvalidPrivateKey;
    defer std.crypto.secureZero(u64, &pv);
    var qv = MontParams.loadBE(qb) catch return error.InvalidPrivateKey;
    defer std.crypto.secureZero(u64, &qv);
    if (MontParams.eql(&pv, &qv)) return error.InvalidPrivateKey; // p == q

    // n = p·q, capped at max_modulus_bits (n is public: its size may branch).
    var nprod: [2 * MontParams.max_limbs]u64 = undefined;
    defer std.crypto.secureZero(u64, &nprod);
    montint.limbs.mulSchoolbook(&nprod, &pv, &qv);
    for (nprod[MontParams.max_limbs..]) |w| if (w != 0) return error.InvalidPrivateKey;
    var n_buf: [max_modulus_len]u8 = undefined;
    limbsToBe(nprod[0..MontParams.max_limbs], &n_buf);
    const n = Modulus.fromBytes(&n_buf, .big) catch return error.InvalidPrivateKey;

    // λ(n) = lcm(p−1, q−1) (p, q odd: p − 1 is p with bit 0 cleared).
    var p1 = pv;
    p1[0] &= ~@as(u64, 1);
    defer std.crypto.secureZero(u64, &p1);
    var q1 = qv;
    q1[0] &= ~@as(u64, 1);
    defer std.crypto.secureZero(u64, &q1);
    var lam_wide = montint.nt.lcm(MontParams.max_limbs, &p1, &q1);
    defer std.crypto.secureZero(u64, &lam_wide);
    var lam: MontElem = lam_wide[0..MontParams.max_limbs].*; // λ ≤ φ < n: fits

    // d = e⁻¹ mod λ(n), dP = e⁻¹ mod (p−1), dQ = e⁻¹ mod (q−1) — the
    // inverses of the odd public modulus e modulo three EVEN secrets
    // (`inverseOfModulus`). dP equals d mod (p−1): (p−1) | λ. The verdicts
    // prove gcd(e, λ) = 1 (the key is valid) and are the only branches.
    const ev = MontParams.loadBE(eb) catch return error.InvalidPrivateKey;
    const e_mod = MontParams.fromLimbs(&ev) catch return error.InvalidPrivateKey; // odd, ≥ 3
    var d_el: MontElem = undefined;
    defer std.crypto.secureZero(u64, &d_el);
    var dp_el: MontElem = undefined;
    defer std.crypto.secureZero(u64, &dp_el);
    var dq_el: MontElem = undefined;
    defer std.crypto.secureZero(u64, &dq_el);
    const ok_d = e_mod.inverseOfModulus(&lam, &d_el);
    const ok_p = e_mod.inverseOfModulus(&p1, &dp_el);
    const ok_q = e_mod.inverseOfModulus(&q1, &dq_el);
    std.crypto.secureZero(u64, &lam);
    if (!(ok_d and ok_p and ok_q)) return error.InvalidPrivateKey;
    // Zero CRT exponents are impossible for prime p, q (e·dP ≡ 1 mod p−1);
    // reject rather than trip a NullExponent later on garbage input.
    if (MontParams.isZero(&d_el) or MontParams.isZero(&dp_el) or MontParams.isZero(&dq_el)) return error.InvalidPrivateKey;

    // Public exponent as an `Fe` of `n` (used by the CRT fault check to
    // re-encrypt `m^e mod n`). e < 2³² < n, so this never overflows.
    const e_fe = Fe.fromBytes(n, eb, .big) catch return error.InvalidPrivateKey;

    // qInv = q⁻¹ mod p = (q mod p)^(p−2) mod p — Fermat inversion on montint
    // (constant-time in p, q); the self-check qInv·q ≡ 1 (mod p) also
    // catches a non-prime p sneaking past (Fermat's answer is then wrong).
    // From the limbs with the length the byte strings already give (the key
    // size, public) — `montParamsFromModulus` would scan the secret value
    // for it.
    const p_mont = MontParams.fromLimbsBits(&pv, bitLenBe(pb)) catch return error.InvalidPrivateKey;
    const q_mont = MontParams.fromLimbsBits(&qv, bitLenBe(qb)) catch return error.InvalidPrivateKey;
    var q_mod_p = p_mont.reduceLimbs(&qv);
    defer std.crypto.secureZero(u64, &q_mod_p);
    var pm2 = pv;
    defer std.crypto.secureZero(u64, &pm2);
    var two = MontParams.zero;
    two[0] = 2;
    _ = montint.limbs.subInto(&pm2, &two);
    var qinv_el = p_mont.pow(&q_mod_p, &pm2);
    defer std.crypto.secureZero(u64, &qinv_el);
    var one = MontParams.zero;
    one[0] = 1;
    if (!MontParams.eql(&p_mont.mul(&qinv_el, &q_mod_p), &one)) return error.InvalidPrivateKey;

    // Into the `ff` carrier fields by a positional repack (ff's own
    // `fromBytes` branches on the value): d < λ < n, dP < p, dQ < q,
    // qInv < p.
    return .{
        .n = n,
        .d = MontParams.elemToFf(Fe, n, &d_el),
        .p = p,
        .q = q,
        .dp = MontParams.elemToFf(Fe, p, &dp_el),
        .dq = MontParams.elemToFf(Fe, q, &dq_el),
        .qinv = MontParams.elemToFf(Fe, p, &qinv_el),
        .e = e_fe,
        .n_mont = montParamsFromModulus(n),
        .p_mont = p_mont,
        .q_mont = q_mont,
    };
}

/// Bit length of a stripped big-endian byte string (`be[0] != 0`): its
/// length, which for a key component is the public key size.
fn bitLenBe(be: []const u8) usize {
    return 8 * be.len - @clz(be[0]);
}

/// Little-endian limbs → big-endian bytes filling `out` (positions only).
fn limbsToBe(v: []const u64, out: []u8) void {
    for (out, 0..) |*o, i| {
        const pos = out.len - 1 - i;
        o.* = if (pos / 8 < v.len) @truncate(v[pos / 8] >> @intCast(8 * (pos % 8))) else 0;
    }
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

/// RSAVP1 / RSAEP straight on the montint modulus: `in` must be `< n`
/// (`elemFromBytesBE` refuses it otherwise — the same verdict `Fe.fromBytes`
/// gives `publicOp`), then a variable-time `in^e mod n`. Everything here is
/// public. `out.len == byteLen(n)`.
fn publicOpMont(mp: *const MontParams, e: u32, in: []const u8, out: []u8) PrimitiveError!void {
    const c = mp.elemFromBytesBE(in) catch return error.MessageRepresentativeOutOfRange;
    var eb: [4]u8 = undefined;
    std.mem.writeInt(u32, &eb, e, .big);
    const r = mp.powPublic(&c, stripLeadingZeros(&eb));
    var ob: [max_modulus_len]u8 = undefined;
    const res = ob[0 .. mp.L * 8];
    mp.toBytesBE(&r, res);
    writeMontResult(out, res); // res is < n
}

fn privateOpPtr(sk: *const SecretKey, in: []const u8, out: []u8) PrimitiveError!void {
    const c = sk.n_mont.elemFromBytesBE(in) catch return error.MessageRepresentativeOutOfRange;
    // Secret exponent -> constant-time montint modexp; d is validated non-zero
    // by `fromPrimes`. (Non-CRT form; `rsadpCrt` is the fast default path.)
    var d = feToElem(&sk.d);
    defer std.crypto.secureZero(u64, &d);
    var m = sk.n_mont.pow(&c, &d);
    defer std.crypto.secureZero(u64, &m);
    sk.n_mont.toBytesBE(&m, out);
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

    /// Base blinding ON from a pair the caller keeps between operations
    /// (`BlindingCache`, the OpenSSL/BoringSSL `BN_BLINDING` scheme): each op
    /// squares the cached pair instead of drawing and inverting a fresh `r`,
    /// and a fresh `r` comes from the cache's CSPRNG every
    /// `BlindingCache.refresh_every` ops. Same masking guarantee as
    /// `.csprng` for a base the attacker chooses; ~5 % faster at 2048 bits
    /// (the inverse and `r^e` were most of the blinding cost). The cache is
    /// mutable and holds secrets — see `BlindingCache`.
    cached: *BlindingCache,
};

/// The state behind `Blinding.cached`: a blinding pair for ONE key, in the
/// CRT domain — `r^e` and `r⁻¹` modulo `p` and modulo `q` for a random unit
/// `r` mod n — and the count of ops it may still serve.
///
/// Use: `var cache = BlindingCache.init(csprng); defer cache.deinit();` then
/// pass `.{ .cached = &cache }` to any `…Blinded` entry point. One cache per
/// thread: it is mutated by every op and has no lock. A cache follows the
/// key it last served (its modulus and public exponent, and which prime it
/// lists first); handed a different key, it draws a fresh pair for that one,
/// so sharing a cache between keys is correct, only slower.
///
/// **It holds key material.** `r^e mod p` and `r⁻¹ mod p` together give `p`
/// (`gcd(r^e·(r⁻¹)^e − 1 mod n, n)`), so the cache needs the care of the
/// `SecretKey` itself: keep it out of logs and swap like the key, and call
/// `deinit` when done. The stack burn of a private op does not reach it.
///
/// Update rule (`r ← r²` between fresh draws): `(r²)^e = (r^e)²` and
/// `(r²)⁻¹ = (r⁻¹)²`, four half-size squarings per op instead of two
/// half-size inverses and two `r^e`. Consecutive blinding values are
/// related (known squares of each other) — the property OpenSSL accepts
/// with its 32-op refresh; an attacker sees neither, both stay secret like
/// the fresh `r` of `.csprng`.
pub const BlindingCache = struct {
    /// Fresh `r` after this many ops on one pair (OpenSSL's
    /// `BN_BLINDING_COUNTER`).
    pub const refresh_every: u32 = 32;

    rng: std.Random,
    /// Ops left on `pair`; 0 = draw a fresh pair on the next op.
    left: u32,
    /// The key `pair` belongs to: its public modulus (low `n_limbs` limbs)
    /// and exponent.
    n: MontElem,
    n_limbs: usize,
    e: u32,
    /// The first CRT prime of that key (`sk.p_mont.m`; SECRET, wiped by
    /// `deinit`). `n` and `e` do not identify the pair: `SecretKey` keeps
    /// `p` and `q` in the order it was given, and the pair is reduced mod
    /// `p` and mod `q` separately, so a key with the same `n`, `e` and the
    /// primes swapped (`fromPrimes(q, p, e)`, a PKCS#1 file written the
    /// other way round) needs a pair of its own.
    p: MontElem,
    pair: BlindingPair,

    /// `rng` MUST be cryptographically secure (see `Blinding.csprng`).
    pub fn init(rng: std.Random) BlindingCache {
        return .{ .rng = rng, .left = 0, .n = undefined, .n_limbs = 0, .e = 0, .p = MontParams.zero, .pair = undefined };
    }

    /// Wipe the pair (key material, see above); the cache stays usable and
    /// draws afresh on its next op.
    pub fn deinit(self: *BlindingCache) void {
        std.crypto.secureZero(u8, std.mem.asBytes(&self.pair));
        std.crypto.secureZero(u64, &self.p);
        self.left = 0;
        self.n_limbs = 0;
    }

    fn serves(self: *const BlindingCache, sk: *const SecretKey) bool {
        const L = sk.n_mont.L;
        const same_public = self.left != 0 and self.n_limbs == L and self.e == sk.publicExponent() and
            std.mem.eql(u64, self.n[0..L], sk.n_mont.m[0..L]); // public values
        // `p` is secret: compared without a branch of its own and folded into
        // the one verdict below. With `n` and `e` already equal, that verdict
        // says only whether this key object lists the same prime first as
        // the one the pair was drawn for — nothing about the primes' values.
        var diff: u64 = 0;
        for (self.p, sk.p_mont.m) |a, b| diff |= a ^ b;
        const same_p: u1 = @intFromBool(diff == 0);
        return (@intFromBool(same_public) & same_p) == 1;
    }

    /// The pair for this op: the cached one squared, or a fresh draw.
    fn next(self: *BlindingCache, sk: *const SecretKey) void {
        if (self.serves(sk)) {
            const P = &self.pair;
            P.rpe = sk.p_mont.sq(&P.rpe);
            P.rp_inv = sk.p_mont.sq(&P.rp_inv);
            P.rqe = sk.q_mont.sq(&P.rqe);
            P.rq_inv = sk.q_mont.sq(&P.rq_inv);
        } else {
            self.pair = drawBlindingPair(sk, self.rng);
            const L = sk.n_mont.L;
            @memcpy(self.n[0..L], sk.n_mont.m[0..L]);
            self.n_limbs = L;
            self.e = sk.publicExponent();
            self.p = sk.p_mont.m;
            self.left = refresh_every;
        }
        self.left -= 1;
    }
};

/// An F2 base-blinding pair in the CRT domain: for a random unit `r` mod n,
/// `r^e` and `r⁻¹` modulo `p` and modulo `q`. The op blinds the halves of
/// its input, `cp = (c mod p)·r^e` (likewise mod q), and unblinds the
/// results by `r⁻¹` (`cp^dP = m1·r` mod p since `e·dP ≡ 1 (mod p − 1)`).
/// Every field is a montint result, zero above its prime's slot.
const BlindingPair = struct { rpe: MontElem, rqe: MontElem, rp_inv: MontElem, rq_inv: MontElem };

/// Draw a fresh blinding pair. `r` is drawn uniformly mod the PUBLIC modulus
/// `n` (rejection on `n` only — nothing here samples against a secret prime);
/// `rng` MUST be cryptographically secure — a predictable `r` voids the
/// masking.
///
/// Since 2026-10-14 the pair lives in the CRT domain: `r mod p` and
/// `r mod q` are inverted together by `safegcd.Inverter.invert2` (two
/// half-size inversions, interleaved, ~½ the cost of one inverse mod n), and
/// `r^e`, the blind and the unblind are half-size operations. Before, the
/// 2048-bit inverse mod n alone was ~7 % of a blinded RSA-2048 op (perf on
/// `bench-rsa`). Each inverse is checked (`r·r⁻¹ ≡ 1`) before use, so neither
/// a non-unit `r` (shares `p` or `q`: probability ~2^-1023) nor a divstep-
/// bound shortfall can produce a wrong unblinding; both just redraw — a
/// decision about the random `r`, not about a secret. Still ~5 % of a
/// 2048-bit op (2026-10-18), which `Blinding.cached` amortizes.
fn drawBlindingPair(sk: *const SecretKey, rng: std.Random) BlindingPair {
    const n_len = sk.n_mont.byteLen();
    var e_be: [4]u8 = undefined;
    std.mem.writeInt(u32, &e_be, sk.publicExponent(), .big);
    const e_s = stripLeadingZeros(&e_be);
    var one: MontElem = MontParams.zero;
    one[0] = 1;
    const half_bits = @max(sk.p_mont.nbits, sk.q_mont.nbits);

    while (true) {
        // Uniform r in [1, n−1] by rejection sampling (>= n and 0 redraw).
        var r_raw: [max_modulus_len]u8 = undefined;
        defer std.crypto.secureZero(u8, r_raw[0..n_len]);
        rng.bytes(r_raw[0..n_len]);
        var r_el = sk.n_mont.elemFromBytesBE(r_raw[0..n_len]) catch continue;
        defer std.crypto.secureZero(u64, &r_el);
        if (MontParams.isZero(&r_el)) continue;

        var rp = sk.p_mont.reduceLimbs(r_el[0..sk.n_mont.L]);
        defer std.crypto.secureZero(u64, &rp);
        var rq = sk.q_mont.reduceLimbs(r_el[0..sk.n_mont.L]);
        defer std.crypto.secureZero(u64, &rq);
        var out: BlindingPair = undefined; // invert2 writes both inverses whole
        const units = BlindInverter.invert2(&rp, &sk.p_mont.m, &rq, &sk.q_mont.m, half_bits, &out.rp_inv, &out.rq_inv);
        // One verdict, read once: the four checks run mod the SECRET primes,
        // so each would otherwise be its own branch on p/q (ctgrind). It is
        // false only for r ≡ 0 mod p or q (~2^-1023) or a divstep-bound
        // shortfall, and only ever causes a redraw.
        const ok = @intFromBool(units[0]) & @intFromBool(units[1]) &
            @intFromBool(MontParams.eql(&sk.p_mont.mul(&rp, &out.rp_inv), &one)) &
            @intFromBool(MontParams.eql(&sk.q_mont.mul(&rq, &out.rq_inv), &one));
        if (ok == 0) continue;

        // r^e mod p, r^e mod q (public exponent).
        out.rpe = sk.p_mont.powPublic(&rp, e_s);
        out.rqe = sk.q_mont.powPublic(&rq, e_s);
        return out;
    }
}

/// The blinding inverse's limb width matches montint's element exactly.
const BlindInverter = safegcd.Inverter(@typeInfo(MontElem).array.len * 64);

fn privateOpCrtPtr(sk: *const SecretKey, in: []const u8, out: []u8, blinding: Blinding) PrimitiveError!void {
    // OS2IP + range check on the PUBLIC input; from here on every value is
    // a montint element (see "montint backend" above for why not `ff`).
    const c = sk.n_mont.elemFromBytesBE(in) catch return error.MessageRepresentativeOutOfRange;

    // F2 (base blinding): with `.csprng`, run the CRT op on c' = c·r^e mod n
    // and unblind the result by r⁻¹ mod n below. This randomizes every secret-
    // dependent intermediate so any residual (compiler-defeated) timing/power
    // signal is masked. With `.none` the op runs unblinded but the F3 fault
    // check still applies.
    var cp: MontElem = undefined;
    defer std.crypto.secureZero(u64, &cp);
    var cq: MontElem = undefined;
    defer std.crypto.secureZero(u64, &cq);
    var r_inv: ?struct { p: MontElem, q: MontElem } = null;
    defer if (r_inv) |*ri| {
        std.crypto.secureZero(u64, ri.p[0..sk.p_mont.L]);
        std.crypto.secureZero(u64, ri.q[0..sk.q_mont.L]);
    };
    cp = sk.p_mont.reduceLimbs(c[0..sk.n_mont.L]);
    cq = sk.q_mont.reduceLimbs(c[0..sk.n_mont.L]);
    switch (blinding) {
        .none => {},
        .csprng => |g| {
            var b = drawBlindingPair(sk, g);
            // Every field is a montint result: zero above its slot, so only
            // the slot limbs can hold a secret (wiping the 4 KiB struct byte
            // by byte cost ~1 µs at the 8192-bit capacity).
            defer for ([_]*MontElem{ &b.rpe, &b.rp_inv }) |x| std.crypto.secureZero(u64, x[0..sk.p_mont.L]);
            defer for ([_]*MontElem{ &b.rqe, &b.rq_inv }) |x| std.crypto.secureZero(u64, x[0..sk.q_mont.L]);
            cp = sk.p_mont.mul(&cp, &b.rpe);
            cq = sk.q_mont.mul(&cq, &b.rqe);
            r_inv = .{ .p = b.rp_inv, .q = b.rq_inv };
        },
        .cached => |cache| {
            cache.next(sk);
            cp = sk.p_mont.mul(&cp, &cache.pair.rpe);
            cq = sk.q_mont.mul(&cq, &cache.pair.rqe);
            r_inv = .{ .p = cache.pair.rp_inv, .q = cache.pair.rq_inv };
        },
    }

    // The secret CRT parameters as montint elements, wiped on return.
    var dp = feToElem(&sk.dp);
    defer std.crypto.secureZero(u64, &dp);
    var dq = feToElem(&sk.dq);
    defer std.crypto.secureZero(u64, &dq);
    var qinv = feToElem(&sk.qinv);
    defer std.crypto.secureZero(u64, &qinv);

    // RFC 8017 §5.1.2 form (2), two-prime case:
    //   m1 = c^dP mod p, m2 = c^dQ mod q   (on the possibly-blinded halves)
    var m1 = sk.p_mont.pow(&cp, &dp);
    defer std.crypto.secureZero(u64, &m1);
    var m2 = sk.q_mont.pow(&cq, &dq);
    defer std.crypto.secureZero(u64, &m2);
    // F2 unblind, per half: m1·(r mod p)⁻¹, m2·(r mod q)⁻¹.
    if (r_inv) |*ri| {
        m1 = sk.p_mont.mul(&m1, &ri.p);
        m2 = sk.q_mont.mul(&m2, &ri.q);
    }

    //   h = (m1 - m2) * qInv mod p    (m2 reduced into the mod-p domain first)
    var h = sk.p_mont.mul(&qinv, &sk.p_mont.sub(&m1, &sk.p_mont.reduceLimbs(m2[0..sk.q_mont.L])));
    defer std.crypto.secureZero(u64, &h);
    //   m = m2 + q*h — the true integer value is < n (m2 < q, h <= p-1), so
    //   computing it mod n is exact. q, h and m2 are all < n, so each is
    //   already a canonical element of n.
    var m = sk.n_mont.add(&m2, &sk.n_mont.mul(&sk.q_mont.m, &h));
    defer std.crypto.secureZero(u64, &m);

    // F3 (Bellcore / BDL fault check): re-encrypt the UNBLINDED m and compare
    // to the ORIGINAL c. A fault in either CRT half makes m ≢ c^d, so m^e ≢ c
    // and we refuse to emit m — denying the attacker the faulty value from
    // which p = gcd(c − m^e mod n, n) would otherwise factor the modulus.
    var e_be: [4]u8 = undefined;
    std.mem.writeInt(u32, &e_be, sk.publicExponent(), .big);
    const chk = sk.n_mont.powPublic(&m, stripLeadingZeros(&e_be));
    if (!MontParams.eql(&chk, &c)) return error.FaultDetected;

    sk.n_mont.toBytesBE(&m, out);
}

/// RSAEP: c = m^e mod n (RFC 8017 §5.1.1), the encryption primitive.
/// `modulus_len` must be the modulus length in bytes (`k` = ceil(bits(n)/8));
/// a value below `k` (here and in `rsavp1`, `rsadp`, `rsadpCrt`,
/// `rsadpCrtBlinded`, `rsasp1`) is `error.MessageRepresentativeOutOfRange`,
/// a larger one left-pads.
pub fn rsaep(comptime modulus_len: usize, m: [modulus_len]u8, pk: PublicKey) PrimitiveError![modulus_len]u8 {
    comptime std.debug.assert(modulus_len <= max_modulus_len);
    // Sweep RS-2: a result buffer shorter than the modulus cannot hold the value.
    if (modulus_len < pk.n_mont.byteLen()) return error.MessageRepresentativeOutOfRange;
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
pub fn rsadp(comptime modulus_len: usize, c: [modulus_len]u8, sk: *const SecretKey) PrimitiveError![modulus_len]u8 {
    const r = rsadpUnburned(modulus_len, c, sk);
    burn.stack(burn.private_op_burn);
    return r;
}

noinline fn rsadpUnburned(comptime modulus_len: usize, c: [modulus_len]u8, sk: *const SecretKey) PrimitiveError![modulus_len]u8 {
    comptime std.debug.assert(modulus_len <= max_modulus_len);
    if (modulus_len < sk.n_mont.byteLen()) return error.MessageRepresentativeOutOfRange; // sweep RS-2
    var out: [modulus_len]u8 = undefined;
    try privateOpPtr(sk, &c, &out);
    return out;
}

/// RSADP via CRT (RFC 8017 §5.1.2, form (2), steps 2.a-2.d) — the fast path
/// using p, q, dP, dQ, qInv instead of a single full-width modexp.
///
/// Runs with F2 base blinding **OFF** (`Blinding.none`) — see `Blinding` for
/// what that costs and why the default is this way. Use `rsadpCrtBlinded` to
/// supply a CSPRNG when `c` is attacker-chosen.
pub fn rsadpCrt(comptime modulus_len: usize, c: [modulus_len]u8, sk: *const SecretKey) PrimitiveError![modulus_len]u8 {
    const r = rsadpCrtUnburned(modulus_len, c, sk);
    burn.stack(burn.private_op_burn);
    return r;
}

noinline fn rsadpCrtUnburned(comptime modulus_len: usize, c: [modulus_len]u8, sk: *const SecretKey) PrimitiveError![modulus_len]u8 {
    return rsadpCrtBlindedUnburned(modulus_len, c, sk, .none);
}

/// `rsadpCrt` with an explicit F2 base-blinding choice.
pub fn rsadpCrtBlinded(comptime modulus_len: usize, c: [modulus_len]u8, sk: *const SecretKey, blinding: Blinding) PrimitiveError![modulus_len]u8 {
    const r = rsadpCrtBlindedUnburned(modulus_len, c, sk, blinding);
    burn.stack(burn.private_op_burn);
    return r;
}

noinline fn rsadpCrtBlindedUnburned(comptime modulus_len: usize, c: [modulus_len]u8, sk: *const SecretKey, blinding: Blinding) PrimitiveError![modulus_len]u8 {
    comptime std.debug.assert(modulus_len <= max_modulus_len);
    if (modulus_len < sk.n_mont.byteLen()) return error.MessageRepresentativeOutOfRange; // sweep RS-2
    var out: [modulus_len]u8 = undefined;
    try privateOpCrtPtr(sk, &c, &out, blinding);
    return out;
}

/// RSASP1: signature primitive, same math as `rsadp` (RFC 8017 §5.2.1).
/// The real implementation should route through `rsadpCrt` for performance.
pub fn rsasp1(comptime modulus_len: usize, m: [modulus_len]u8, sk: *const SecretKey) PrimitiveError![modulus_len]u8 {
    const r = rsasp1Unburned(modulus_len, m, sk);
    burn.stack(burn.private_op_burn);
    return r;
}

noinline fn rsasp1Unburned(comptime modulus_len: usize, m: [modulus_len]u8, sk: *const SecretKey) PrimitiveError![modulus_len]u8 {
    return rsadpCrtBlindedUnburned(modulus_len, m, sk, .none);
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
        // The rest of the NIST hash arc (2.16.840.1.101.3.4.2.x, 2026-10-14):
        // same shape, checked byte for byte against DigestInfo recovered from
        // OpenSSL 3 signatures (test "HashId: ...").
        hash.sha2.Sha512_224 => comptime nistDigestInfoPrefix(5, 28),
        hash.sha2.Sha512_256 => comptime nistDigestInfoPrefix(6, 32),
        hash.sha3.Sha3_224 => comptime nistDigestInfoPrefix(7, 28),
        hash.sha3.Sha3_256 => comptime nistDigestInfoPrefix(8, 32),
        hash.sha3.Sha3_384 => comptime nistDigestInfoPrefix(9, 48),
        hash.sha3.Sha3_512 => comptime nistDigestInfoPrefix(10, 64),
        else => @compileError("unsupported hash for EMSA-PKCS1-v1_5 DigestInfo: " ++ @typeName(Hash)),
    };
}

/// `DigestInfo ::= SEQUENCE { SEQUENCE { OID 2.16.840.1.101.3.4.2.<arc>,
/// NULL }, OCTET STRING <digest_len> }` without the digest.
fn nistDigestInfoPrefix(comptime arc: u8, comptime digest_len: u8) []const u8 {
    const t = [_]u8{
        0x30, 0x11 + digest_len, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,       0x01,
        0x65, 0x03,              0x04, 0x02, arc,  0x05, 0x00, 0x04, digest_len,
    };
    return &t;
}

/// A hash chosen at run time — Go's `crypto.Hash`, OpenSSL's digest name —
/// for the `*Digest` entry points (a caller holding a digest and an algorithm
/// identifier, as X.509, CMS and TLS do). Every member has a PKCS#1 v1.5
/// DigestInfo and works for PSS. MD5, RIPEMD-160 and MD5+SHA-1 are not
/// offered: broken or without a std type.
pub const HashId = enum {
    sha1,
    sha224,
    sha256,
    sha384,
    sha512,
    sha512_224,
    sha512_256,
    sha3_224,
    sha3_256,
    sha3_384,
    sha3_512,

    /// The std hash type.
    pub fn Type(comptime id: HashId) type {
        const h = std.crypto.hash;
        return switch (id) {
            .sha1 => h.Sha1,
            .sha224 => h.sha2.Sha224,
            .sha256 => h.sha2.Sha256,
            .sha384 => h.sha2.Sha384,
            .sha512 => h.sha2.Sha512,
            .sha512_224 => h.sha2.Sha512_224,
            .sha512_256 => h.sha2.Sha512_256,
            .sha3_224 => h.sha3.Sha3_224,
            .sha3_256 => h.sha3.Sha3_256,
            .sha3_384 => h.sha3.Sha3_384,
            .sha3_512 => h.sha3.Sha3_512,
        };
    }

    pub fn digestLen(id: HashId) usize {
        return switch (id) {
            inline else => |c| c.Type().digest_length,
        };
    }
};

/// The longest digest a `HashId` produces.
pub const max_digest_len = 64;

pub const DigestError = error{
    /// `digest.len` is not the selected hash's digest length.
    InvalidDigestLength,
};

/// `id`'s digest of `msg` into `out`; returns the digest (a prefix of `out`).
pub fn hashMessage(id: HashId, msg: []const u8, out: *[max_digest_len]u8) []u8 {
    switch (id) {
        inline else => |c| {
            const H = c.Type();
            H.hash(msg, out[0..H.digest_length], .{});
            return out[0..H.digest_length];
        },
    }
}

pub const EmsaEncodeError = error{EncodedMessageTooShort};

/// EMSA-PKCS1-v1_5 encoding (RFC 8017 §9.2):
/// EM = 0x00 || 0x01 || PS(0xff…) || 0x00 || DigestInfo(Hash, Hash(msg)),
/// written into all of `em` (`em.len` = intended encoded message length).
fn emsaPkcs1v15Encode(comptime Hash: type, msg: []const u8, em: []u8) EmsaEncodeError!void {
    var digest: [Hash.digest_length]u8 = undefined;
    Hash.hash(msg, &digest, .{});
    return emsaPkcs1v15EncodeDigest(Hash, &digest, em);
}

/// §9.2 from step 2 on: `digest` is H = Hash(M).
fn emsaPkcs1v15EncodeDigest(comptime Hash: type, digest: *const [Hash.digest_length]u8, em: []u8) EmsaEncodeError!void {
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
    em[em.len - Hash.digest_length ..][0..Hash.digest_length].* = digest.*;
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
pub fn signPkcs1v15(sk: *const SecretKey, comptime Hash: type, msg: []const u8, out: []u8) SignPkcs1v15Error![]u8 {
    const r = signPkcs1v15Unburned(sk, Hash, msg, out);
    burn.stack(burn.private_op_burn);
    return r;
}

noinline fn signPkcs1v15Unburned(sk: *const SecretKey, comptime Hash: type, msg: []const u8, out: []u8) SignPkcs1v15Error![]u8 {
    return signPkcs1v15BlindedUnburned(sk, Hash, .none, msg, out);
}

/// `signPkcs1v15` with an explicit F2 base-blinding choice. The emitted
/// signature is identical either way (blinding is undone before output);
/// only the side-channel posture of the private op differs.
pub fn signPkcs1v15Blinded(sk: *const SecretKey, comptime Hash: type, blinding: Blinding, msg: []const u8, out: []u8) SignPkcs1v15Error![]u8 {
    const r = signPkcs1v15BlindedUnburned(sk, Hash, blinding, msg, out);
    burn.stack(burn.private_op_burn);
    return r;
}

noinline fn signPkcs1v15BlindedUnburned(sk: *const SecretKey, comptime Hash: type, blinding: Blinding, msg: []const u8, out: []u8) SignPkcs1v15Error![]u8 {
    var digest: [Hash.digest_length]u8 = undefined;
    Hash.hash(msg, &digest, .{});
    return signPkcs1v15DigestUnburned(sk, Hash, blinding, &digest, out);
}

/// `signPkcs1v15` over a digest the caller already has (`digest` =
/// Hash(M)) -- for protocols that sign a running hash, such as a TLS 1.2
/// CertificateVerify. Same signature as `signPkcs1v15(M)`; F2 blinding off,
/// as there.
pub fn signPkcs1v15Prehashed(sk: *const SecretKey, comptime Hash: type, digest: *const [Hash.digest_length]u8, out: []u8) SignPkcs1v15Error![]u8 {
    const r = signPkcs1v15DigestUnburned(sk, Hash, .none, digest, out);
    burn.stack(burn.private_op_burn);
    return r;
}

noinline fn signPkcs1v15DigestUnburned(sk: *const SecretKey, comptime Hash: type, blinding: Blinding, digest: *const [Hash.digest_length]u8, out: []u8) SignPkcs1v15Error![]u8 {
    const k = byteLen(sk.n.bits());
    if (out.len < k) return error.BufferTooSmall;
    var em_buf: [max_modulus_len]u8 = undefined;
    const em = em_buf[0..k];
    try emsaPkcs1v15EncodeDigest(Hash, digest, em);
    // EM starts with 0x00 0x01, so its integer value is < n by construction;
    // the range check inside the primitive cannot fail. A Bellcore fault (F3)
    // is surfaced on either blinding setting, never signed over.
    privateOpCrtPtr(sk, em, out[0..k], blinding) catch |err| switch (err) {
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
    return verifyPkcs1v15Mont(&pk.n_mont, pk.publicExponent(), Hash, msg, sig);
}

/// `verifyPkcs1v15` over the montint modulus and the validated exponent —
/// the body both `PublicKey` and `VerifyKey` share.
fn verifyPkcs1v15Mont(mp: *const MontParams, e: u32, comptime Hash: type, msg: []const u8, sig: []const u8) VerifyPkcs1v15Error!void {
    var digest: [Hash.digest_length]u8 = undefined;
    Hash.hash(msg, &digest, .{});
    return verifyPkcs1v15DigestMont(mp, e, Hash, &digest, sig);
}

fn verifyPkcs1v15DigestMont(mp: *const MontParams, e: u32, comptime Hash: type, digest: *const [Hash.digest_length]u8, sig: []const u8) VerifyPkcs1v15Error!void {
    const k = mp.byteLen();
    // §8.2.2 step 1: the signature must be exactly k octets.
    if (sig.len != k) return error.SignatureVerificationFailed;
    // Exactly k octets each (both writers fill all of it); not zeroed or
    // compared at the 1 KiB capacity — that was ~10 % of a 2048-bit verify
    // once the cap went to 8192 bits (2026-10-14).
    var em_dec: [max_modulus_len]u8 = undefined;
    publicOpMont(mp, e, sig, em_dec[0..k]) catch return error.SignatureVerificationFailed;
    var em_exp: [max_modulus_len]u8 = undefined;
    emsaPkcs1v15EncodeDigest(Hash, digest, em_exp[0..k]) catch return error.SignatureVerificationFailed;
    // Constant-time over the k octets (a public signature, but the full
    // comparison keeps "no Bleichenbacher'06-style laxity" independent of
    // where the first difference is).
    var diff: u8 = 0;
    for (em_dec[0..k], em_exp[0..k]) |a, b| diff |= a ^ b;
    if (diff != 0) return error.SignatureVerificationFailed;
}

/// `verifyPkcs1v15` against a digest the caller already has (`digest` =
/// Hash(M)) — the verify twin of `signPkcs1v15Prehashed`.
pub fn verifyPkcs1v15Prehashed(pk: PublicKey, comptime Hash: type, digest: *const [Hash.digest_length]u8, sig: []const u8) VerifyPkcs1v15Error!void {
    return verifyPkcs1v15DigestMont(&pk.n_mont, pk.publicExponent(), Hash, digest, sig);
}

/// `signPkcs1v15Prehashed` with the hash chosen at run time (Go
/// `SignPKCS1v15(rand, priv, hash, digest)`). `digest.len` must be
/// `id.digestLen()`.
pub fn signPkcs1v15Digest(sk: *const SecretKey, id: HashId, digest: []const u8, out: []u8) (SignPkcs1v15Error || DigestError)![]u8 {
    switch (id) {
        inline else => |c| {
            const H = c.Type();
            if (digest.len != H.digest_length) return error.InvalidDigestLength;
            return signPkcs1v15Prehashed(sk, H, digest[0..H.digest_length], out);
        },
    }
}

/// `verifyPkcs1v15Prehashed` with the hash chosen at run time (Go
/// `VerifyPKCS1v15(pub, hash, digest, sig)`).
pub fn verifyPkcs1v15Digest(pk: PublicKey, id: HashId, digest: []const u8, sig: []const u8) (VerifyPkcs1v15Error || DigestError)!void {
    return verifyPkcs1v15DigestAny(&pk.n_mont, pk.publicExponent(), id, digest, sig);
}

fn verifyPkcs1v15DigestAny(mp: *const MontParams, e: u32, id: HashId, digest: []const u8, sig: []const u8) (VerifyPkcs1v15Error || DigestError)!void {
    switch (id) {
        inline else => |c| {
            const H = c.Type();
            if (digest.len != H.digest_length) return error.InvalidDigestLength;
            return verifyPkcs1v15DigestMont(mp, e, H, digest[0..H.digest_length], sig);
        },
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
pub fn decryptOaep(sk: *const SecretKey, comptime Hash: type, ct: []const u8, label: []const u8, out: []u8) DecryptOaepError![]u8 {
    const r = decryptOaepUnburned(sk, Hash, ct, label, out);
    burn.stack(burn.private_op_burn);
    return r;
}

noinline fn decryptOaepUnburned(sk: *const SecretKey, comptime Hash: type, ct: []const u8, label: []const u8, out: []u8) DecryptOaepError![]u8 {
    return decryptOaepHBlindedUnburned(sk, Hash, Hash, .none, ct, label, out);
}

/// `decryptOaep` with an explicit F2 base-blinding choice. The recovered
/// plaintext and every error are identical either way.
pub fn decryptOaepBlinded(sk: *const SecretKey, comptime Hash: type, blinding: Blinding, ct: []const u8, label: []const u8, out: []u8) DecryptOaepError![]u8 {
    const r = decryptOaepBlindedUnburned(sk, Hash, blinding, ct, label, out);
    burn.stack(burn.private_op_burn);
    return r;
}

noinline fn decryptOaepBlindedUnburned(sk: *const SecretKey, comptime Hash: type, blinding: Blinding, ct: []const u8, label: []const u8, out: []u8) DecryptOaepError![]u8 {
    return decryptOaepHBlindedUnburned(sk, Hash, Hash, blinding, ct, label, out);
}

/// Decoupled-hash RSAES-OAEP decrypt (RFC 8017 §7.1.2). `LabelHash` is the
/// digest used for `lHash = LabelHash(label)` and fixes `hLen` (seed length
/// and the layout); `MgfHash` drives MGF1. Mirrors `encryptOaepH`; use it to
/// decrypt ciphertext produced with a digest hash that differs from the MGF1
/// hash (e.g. XML-Encryption `rsa-oaep` with digest=SHA-256, MGF1=SHA-1). The
/// same constant-time / single-generic-error posture as `decryptOaep` applies
/// (all padding-decode failures collapse to `error.DecryptionError`), F2 base
/// blinding **OFF** included — `decryptOaepHBlinded` is the opt-in.
pub fn decryptOaepH(sk: *const SecretKey, comptime LabelHash: type, comptime MgfHash: type, ct: []const u8, label: []const u8, out: []u8) DecryptOaepError![]u8 {
    const r = decryptOaepHUnburned(sk, LabelHash, MgfHash, ct, label, out);
    burn.stack(burn.private_op_burn);
    return r;
}

noinline fn decryptOaepHUnburned(sk: *const SecretKey, comptime LabelHash: type, comptime MgfHash: type, ct: []const u8, label: []const u8, out: []u8) DecryptOaepError![]u8 {
    return decryptOaepHBlindedUnburned(sk, LabelHash, MgfHash, .none, ct, label, out);
}

/// `decryptOaepH` with an explicit F2 base-blinding choice — the one entry
/// point through which every other OAEP-decrypt path reaches the private op.
pub fn decryptOaepHBlinded(sk: *const SecretKey, comptime LabelHash: type, comptime MgfHash: type, blinding: Blinding, ct: []const u8, label: []const u8, out: []u8) DecryptOaepError![]u8 {
    const r = decryptOaepHBlindedUnburned(sk, LabelHash, MgfHash, blinding, ct, label, out);
    burn.stack(burn.private_op_burn);
    return r;
}

noinline fn decryptOaepHBlindedUnburned(sk: *const SecretKey, comptime LabelHash: type, comptime MgfHash: type, blinding: Blinding, ct: []const u8, label: []const u8, out: []u8) DecryptOaepError![]u8 {
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
    privateOpCrtPtr(sk, ct, em, blinding) catch return error.DecryptionError;

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

/// All-ones iff `a == b`, all-zeros otherwise. Branch-free — same bit trick
/// as `ctEqByte` above, widened to `usize` so a data-dependent LENGTH (not
/// just a data-dependent byte) can be compared without branching on it.
fn ctEqMaskUsize(a: usize, b: usize) usize {
    const bits = @bitSizeOf(usize);
    const d = a ^ b;
    const nonzero = (d | (0 -% d)) >> (bits - 1);
    return nonzero -% 1;
}

/// Result of `decryptOaepHNoFail`. Unlike `decryptOaepH`/`decryptOaepHBlinded`,
/// a padding failure is not an `error` — see that function's doc comment for
/// why, and `xmlenc`'s `rsaOaepUnwrap` for the caller that needs this shape.
pub const OaepUnwrapResult = struct {
    /// The recovered `want`-byte OAEP message when `ok` — otherwise
    /// unspecified content (NOT a decoy; `msg.len` is 0). A caller that
    /// needs an unpredictable-to-the-peer decoy on `!ok` derives its own
    /// from `raw`, the same division of labor the RSAES-PKCS1-v1.5 path
    /// already has between `rsa.rsadpCrt` (raw block) and the caller's own
    /// decoy derivation.
    msg: []const u8,
    /// The raw RSADP output, `c^d mod n`, always `k` bytes (`k` = the
    /// modulus byte length) regardless of `ok` — secret material the peer
    /// cannot compute, suitable as decoy-derivation input.
    raw: []const u8,
    ok: bool,
};

/// Decoupled-hash RSAES-OAEP decrypt that reports a padding failure as data,
/// not as an early `error` return — the constant-time counterpart to
/// `decryptOaepHBlinded` for callers that must not let OAEP-unwrap success or
/// failure become an externally observable TIMING signal on its own.
///
/// `decryptOaepHBlinded`'s `if (valid != 1) return error.DecryptionError`
/// is exactly right for a caller that has nothing further to do either way
/// (13 in-repo consumers do; this function changes nothing about their
/// behavior). It is exactly WRONG for a caller like XML-Encryption's
/// `rsa-oaep` key transport, which RFC 8017 §7.2.2's classic countermeasure
/// (originally stated for PKCS#1 v1.5, and applied here to OAEP for the same
/// reason) requires to run the SAME amount of downstream work — decrypting
/// the symmetric content — whether or not the key unwrap actually succeeded,
/// so that "the RSA step failed" and "the RSA step succeeded but the AEAD
/// tag didn't verify" are indistinguishable from outside. An early `error`
/// return defeats that at the call site: the caller either duplicates this
/// function's OAEP-decode cryptography to build its own non-erroring
/// variant (a second, drifting copy of decoding logic no one wants), or it
/// cannot implement the countermeasure at all. This function is the
/// alternative: additive to the module's public surface, and every existing
/// entry point (`decryptOaep`, `decryptOaepBlinded`, `decryptOaepH`,
/// `decryptOaepHBlinded`) keeps its exact current signature and behavior.
///
/// `want` (the expected message length, e.g. a content-encryption key's
/// byte length) is folded into the SAME branch-free validity determination
/// as the padding itself — checking it separately, one call frame up, would
/// reopen exactly the oracle this function exists to close (measured for
/// the analogous PKCS#1 v1.5 case: 97% classifier accuracy when the length
/// check was one frame removed from the padding check). `raw_out` must be
/// at least `k` bytes (the modulus byte length); `out` at least `want`
/// bytes.
pub fn decryptOaepHNoFail(
    sk: *const SecretKey,
    comptime LabelHash: type,
    comptime MgfHash: type,
    blinding: Blinding,
    ct: []const u8,
    label: []const u8,
    want: usize,
    out: []u8,
    raw_out: []u8,
) DecryptOaepError!OaepUnwrapResult {
    const r = decryptOaepHNoFailUnburned(sk, LabelHash, MgfHash, blinding, ct, label, want, out, raw_out);
    burn.stack(burn.private_op_burn);
    return r;
}

noinline fn decryptOaepHNoFailUnburned(
    sk: *const SecretKey,
    comptime LabelHash: type,
    comptime MgfHash: type,
    blinding: Blinding,
    ct: []const u8,
    label: []const u8,
    want: usize,
    out: []u8,
    raw_out: []u8,
) DecryptOaepError!OaepUnwrapResult {
    const h_len = LabelHash.digest_length;
    const k = byteLen(sk.n.bits());
    // §7.1.2 step 1 and this function's own buffer preconditions are all
    // PUBLIC data (ciphertext length, modulus size, `want` from a public
    // algorithm URI, caller-supplied buffer sizes) — an early return here
    // discloses nothing an observer could not already compute themselves.
    if (ct.len != k or k < 2 * h_len + 2) return error.DecryptionError;
    if (raw_out.len < k) return error.BufferTooSmall;
    const max_msg_len = k - 2 * h_len - 2;
    if (want > max_msg_len or out.len < want) return error.BufferTooSmall;

    var em_buf: [max_modulus_len]u8 = undefined;
    defer std.crypto.secureZero(u8, em_buf[0..k]);
    const em = em_buf[0..k];
    // c >= n is public (the ciphertext is public), same reasoning as
    // `decryptOaepHBlinded`'s identical early return.
    privateOpCrtPtr(sk, ct, em, blinding) catch return error.DecryptionError;
    // Preserve the raw block past this function's own `defer`-scheduled
    // zeroing, for the caller's decoy derivation.
    @memcpy(raw_out[0..k], em);

    const seed = em[1..][0..h_len];
    const db = em[1 + h_len .. k];
    mgf1Xor(MgfHash, db, seed);
    mgf1Xor(MgfHash, seed, db);

    var lhash: [h_len]u8 = undefined;
    LabelHash.hash(label, &lhash, .{});
    const y_ok = ctEqByte(em[0], 0x00);
    const lhash_ok: u8 = @intFromBool(std.crypto.timing_safe.eql([h_len]u8, lhash, db[0..h_len].*));

    var looking: u8 = 1;
    var invalid: u8 = 0;
    var sep_idx: usize = 0;
    var i: usize = h_len;
    while (i < db.len) : (i += 1) {
        const is_one = ctEqByte(db[i], 0x01);
        const is_zero = ctEqByte(db[i], 0x00);
        sep_idx = ctSelect(looking & is_one, i, sep_idx);
        looking &= is_one ^ 1;
        invalid |= looking & (is_zero ^ 1);
    }
    const found_sep = looking ^ 1;
    // When no separator was found `sep_idx` stayed 0 and this is a bogus
    // value — never read unless `found_sep` (folded into `valid` below).
    const msg_len = db.len - sep_idx - 1;
    const len_ok: u8 = @truncate(ctEqMaskUsize(msg_len, want) & 1);
    const valid: u8 = y_ok & lhash_ok & (invalid ^ 1) & found_sep & len_ok;

    if (valid == 1) {
        @memcpy(out[0..msg_len], db[sep_idx + 1 ..][0..msg_len]);
        return .{ .msg = out[0..msg_len], .raw = raw_out[0..k], .ok = true };
    }
    return .{ .msg = out[0..0], .raw = raw_out[0..k], .ok = false };
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
/// `em.len != ceil(em_bits/8)` is `error.EncodedMessageTooShort`, like a too-small `em`.
///
/// `pub` so a caller needing EMSA-PSS-ENCODE as a standalone step — decoupled
/// from RSASP1 — can reuse it instead of carrying an independent copy.
/// `blindrsa`'s RFC 9474 Blind is exactly this: it encodes, then blinds the
/// encoded integer, and only signs (via `rsasp1`) later, server-side, over
/// the blinded value — it never calls `signPss` here. `blindrsa.pssEncode`
/// is now a thin wrapper delegating straight to this function.
pub fn emsaPssEncode(comptime Hash: type, msg: []const u8, salt: []const u8, em_bits: usize, em: []u8) EmsaEncodeError!void {
    var m_hash: [Hash.digest_length]u8 = undefined;
    Hash.hash(msg, &m_hash, .{});
    return emsaPssEncodeDigest(Hash, Hash, &m_hash, salt, em_bits, em);
}

/// §9.1.1 from step 3 on: `m_hash` is mHash = Hash(M); the mask is
/// MGF1 over `MgfHash` (= `Hash` everywhere except `signPssH`).
fn emsaPssEncodeDigest(comptime Hash: type, comptime MgfHash: type, m_hash: *const [Hash.digest_length]u8, salt: []const u8, em_bits: usize, em: []u8) EmsaEncodeError!void {
    const h_len = Hash.digest_length;
    const em_len = em.len;
    // Sweep RS-3: `em.len` must be ceil(em_bits/8) (an assert, i.e. UB in
    // ReleaseFast, on a value `pub emsaPssEncode` takes from its caller).
    if (em_len != byteLen(em_bits)) return error.EncodedMessageTooShort;
    // §9.1.1 step 3: emLen >= hLen + sLen + 2.
    if (em_len < h_len + 2 or salt.len > em_len - h_len - 2) return error.EncodedMessageTooShort;

    const db = em[0 .. em_len - h_len - 1];
    const h = em[em_len - h_len - 1 ..][0..h_len];

    // steps 5-6: H = Hash(M'), M' = (0x00 × 8) || mHash || salt.
    var st = Hash.init(.{});
    st.update(&@as([8]u8, @splat(0)));
    st.update(m_hash);
    st.update(salt);
    st.final(h);

    // steps 7-8: DB = PS (zeros) || 0x01 || salt.
    @memset(db[0 .. db.len - salt.len - 1], 0x00);
    db[db.len - salt.len - 1] = 0x01;
    @memcpy(db[db.len - salt.len ..], salt);

    // steps 9-10: maskedDB = DB ^ MGF1(H, emLen - hLen - 1).
    mgf1Xor(MgfHash, h, db);

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
pub fn signPss(sk: *const SecretKey, comptime Hash: type, random: std.Random, msg: []const u8, salt_len: usize, out: []u8) SignPssError![]u8 {
    const r = signPssUnburned(sk, Hash, random, msg, salt_len, out);
    burn.stack(burn.private_op_burn);
    return r;
}

noinline fn signPssUnburned(sk: *const SecretKey, comptime Hash: type, random: std.Random, msg: []const u8, salt_len: usize, out: []u8) SignPssError![]u8 {
    var m_hash: [Hash.digest_length]u8 = undefined;
    Hash.hash(msg, &m_hash, .{});
    return signPssDigestUnburned(sk, Hash, Hash, random, &m_hash, salt_len, out);
}

/// `signPss` over a digest the caller already has (`digest` = Hash(M)) --
/// e.g. a TLS CertificateVerify over a running transcript hash. Same
/// signature as `signPss(M)` for the same salt.
pub fn signPssPrehashed(sk: *const SecretKey, comptime Hash: type, random: std.Random, digest: *const [Hash.digest_length]u8, salt_len: usize, out: []u8) SignPssError![]u8 {
    const r = signPssDigestUnburned(sk, Hash, Hash, random, digest, salt_len, out);
    burn.stack(burn.private_op_burn);
    return r;
}

noinline fn signPssDigestUnburned(sk: *const SecretKey, comptime Hash: type, comptime MgfHash: type, random: std.Random, digest: *const [Hash.digest_length]u8, salt_len: usize, out: []u8) SignPssError![]u8 {
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
    try emsaPssEncodeDigest(Hash, MgfHash, digest, salt, em_bits, em_buf[k - em_len .. k]);

    // §8.1.1 step 2: RSASP1. EM < 2^emBits < n by construction (step 11
    // cleared the top bits), so the primitive's range check cannot fail.
    // `random` also drives F2 base blinding inside the CRT op; a Bellcore
    // fault (F3) is surfaced, never signed over.
    privateOpCrtPtr(sk, em_buf[0..k], out[0..k], .{ .csprng = random }) catch |err| switch (err) {
        error.MessageRepresentativeOutOfRange => unreachable,
        error.FaultDetected => return error.FaultDetected,
    };
    return out[0..k];
}

/// `signPss` with the MGF1 hash decoupled from the message hash (OpenSSL
/// `rsa_mgf1_md`, X.509 `RSASSA-PSS-params` with a different
/// `maskGenAlgorithm`) — the PSS twin of `encryptOaepH`.
pub fn signPssH(sk: *const SecretKey, comptime Hash: type, comptime MgfHash: type, random: std.Random, msg: []const u8, salt_len: usize, out: []u8) SignPssError![]u8 {
    const r = signPssHUnburned(sk, Hash, MgfHash, random, msg, salt_len, out);
    burn.stack(burn.private_op_burn);
    return r;
}

noinline fn signPssHUnburned(sk: *const SecretKey, comptime Hash: type, comptime MgfHash: type, random: std.Random, msg: []const u8, salt_len: usize, out: []u8) SignPssError![]u8 {
    var m_hash: [Hash.digest_length]u8 = undefined;
    Hash.hash(msg, &m_hash, .{});
    return signPssDigestUnburned(sk, Hash, MgfHash, random, &m_hash, salt_len, out);
}

/// `signPssPrehashed` with the hash chosen at run time (Go
/// `SignPSS(rand, priv, hash, digest, opts)`). `digest.len` must be
/// `id.digestLen()`.
pub fn signPssDigest(sk: *const SecretKey, id: HashId, random: std.Random, digest: []const u8, salt_len: usize, out: []u8) (SignPssError || DigestError)![]u8 {
    switch (id) {
        inline else => |c| {
            const H = c.Type();
            if (digest.len != H.digest_length) return error.InvalidDigestLength;
            return signPssPrehashed(sk, H, random, digest[0..H.digest_length], salt_len, out);
        },
    }
}

/// The largest PSS salt for a `modulus_bits`-bit key and `Hash`:
/// emLen − hLen − 2 (RFC 8017 §9.1.1 step 3) — what Go's
/// `PSSSaltLengthAuto` signs with and OpenSSL calls `rsa_pss_saltlen:max`.
/// `null` if the key is too small for the hash at all.
/// (`PSSSaltLengthEqualsHash` / `saltlen:digest` is `Hash.digest_length`.)
pub fn maxPssSaltLen(modulus_bits: usize, comptime Hash: type) ?usize {
    if (modulus_bits < 2) return null;
    const em_len = byteLen(modulus_bits - 1);
    if (em_len < Hash.digest_length + 2) return null;
    return em_len - Hash.digest_length - 2;
}

pub const VerifyPssError = error{SignatureVerificationFailed};

/// Verify an RSASSA-PSS signature (RFC 8017 §8.1.2): RSAVP1 recovers the
/// encoded message, which is checked per EMSA-PSS-VERIFY (§9.1.2) against
/// `msg` for the given `salt_len` (must equal the signer's `sLen`;
/// `verifyPssAuto` recovers it instead). All checks over the
/// recovered encoding are accumulated branch-free into one validity flag
/// (H comparison via `std.crypto.timing_safe.eql`) and every failure mode
/// reports the single generic `error.SignatureVerificationFailed`.
pub fn verifyPss(pk: PublicKey, comptime Hash: type, msg: []const u8, sig: []const u8, salt_len: usize) VerifyPssError!void {
    return verifyPssMont(&pk.n_mont, pk.publicExponent(), Hash, msg, sig, salt_len);
}

/// `verifyPss` over the montint modulus and the validated exponent — the
/// body both `PublicKey` and `VerifyKey` share.
fn verifyPssMont(mp: *const MontParams, e: u32, comptime Hash: type, msg: []const u8, sig: []const u8, salt_len: usize) VerifyPssError!void {
    var m_hash: [Hash.digest_length]u8 = undefined;
    Hash.hash(msg, &m_hash, .{});
    _ = try verifyPssDigestMont(mp, e, Hash, Hash, &m_hash, sig, salt_len);
}

/// EMSA-PSS-VERIFY from mHash on. `salt_len` null = recover it from the
/// encoding (Go `PSSSaltLengthAuto`, OpenSSL `rsa_pss_saltlen:auto`): the
/// first non-zero octet of the unmasked DB must be the 0x01 separator and
/// what follows it is the salt (§9.1.2 step 10 read the other way round).
/// Everything here is public (signature, key, message digest), so the scan
/// may branch; the explicit-length path keeps its accumulate-then-decide
/// shape. Returns the salt length.
fn verifyPssDigestMont(mp: *const MontParams, e: u32, comptime Hash: type, comptime MgfHash: type, m_hash: *const [Hash.digest_length]u8, sig: []const u8, salt_len: ?usize) VerifyPssError!usize {
    const h_len = Hash.digest_length;
    const k = mp.byteLen();
    // §8.1.2 step 1: the signature must be exactly k octets.
    if (sig.len != k) return error.SignatureVerificationFailed;
    const em_bits = mp.bits() - 1;
    const em_len = byteLen(em_bits);
    // §9.1.2 step 3: emLen >= hLen + sLen + 2. Public parameters only
    // (modulus size, hash, expected salt length), so branching is harmless.
    if (em_len < h_len + 2) return error.SignatureVerificationFailed;
    if (salt_len) |sl| if (sl > em_len - h_len - 2) return error.SignatureVerificationFailed;

    // §8.1.2 step 2: RSAVP1 (public-key operation; s >= n is public info).
    var em_buf: [max_modulus_len]u8 = undefined;
    publicOpMont(mp, e, sig, em_buf[0..k]) catch return error.SignatureVerificationFailed;

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
    mgf1Xor(MgfHash, h, db);
    db[0] &= top_mask;

    // step 10: DB = PS (zeros) || 0x01 || salt.
    const sl: usize = salt_len orelse blk: {
        const sep = std.mem.findNone(u8, db, &.{0}) orelse break :blk 0; // all zero: the 0x01 check fails
        break :blk db.len - sep - 1;
    };
    const ps_len = em_len - h_len - sl - 2;
    for (db[0..ps_len]) |b| ok &= ctEqByte(b, 0x00);
    ok &= ctEqByte(db[ps_len], 0x01);
    const salt = db[db.len - sl ..];

    // steps 12-13: H' = Hash((0x00 × 8) || mHash || salt).
    var h_prime: [h_len]u8 = undefined;
    var st = Hash.init(.{});
    st.update(&@as([8]u8, @splat(0)));
    st.update(m_hash);
    st.update(salt);
    st.final(&h_prime);

    // step 14: H == H', folded into the single decision point.
    ok &= @intFromBool(std.crypto.timing_safe.eql([h_len]u8, h.*, h_prime));
    if (ok != 1) return error.SignatureVerificationFailed;
    return sl;
}

/// `verifyPss` against a digest the caller already has (`digest` =
/// Hash(M)) — the verify twin of `signPssPrehashed`.
pub fn verifyPssPrehashed(pk: PublicKey, comptime Hash: type, digest: *const [Hash.digest_length]u8, sig: []const u8, salt_len: usize) VerifyPssError!void {
    _ = try verifyPssDigestMont(&pk.n_mont, pk.publicExponent(), Hash, Hash, digest, sig, salt_len);
}

/// `verifyPss` without knowing the salt length (Go `PSSSaltLengthAuto`,
/// OpenSSL `rsa_pss_saltlen:auto`): any salt length the encoding carries is
/// accepted, and returned. Prefer `verifyPss` with the expected length when
/// the protocol fixes one (X.509 `RSASSA-PSS-params`, TLS 1.3: hLen).
pub fn verifyPssAuto(pk: PublicKey, comptime Hash: type, msg: []const u8, sig: []const u8) VerifyPssError!usize {
    var m_hash: [Hash.digest_length]u8 = undefined;
    Hash.hash(msg, &m_hash, .{});
    return verifyPssDigestMont(&pk.n_mont, pk.publicExponent(), Hash, Hash, &m_hash, sig, null);
}

/// `verifyPssAuto` against a digest the caller already has.
pub fn verifyPssAutoPrehashed(pk: PublicKey, comptime Hash: type, digest: *const [Hash.digest_length]u8, sig: []const u8) VerifyPssError!usize {
    return verifyPssDigestMont(&pk.n_mont, pk.publicExponent(), Hash, Hash, digest, sig, null);
}

/// `verifyPss` with the MGF1 hash decoupled from the message hash (the
/// verify twin of `signPssH`). `salt_len` null recovers it, as `verifyPssAuto`.
pub fn verifyPssH(pk: PublicKey, comptime Hash: type, comptime MgfHash: type, msg: []const u8, sig: []const u8, salt_len: ?usize) VerifyPssError!usize {
    var m_hash: [Hash.digest_length]u8 = undefined;
    Hash.hash(msg, &m_hash, .{});
    return verifyPssDigestMont(&pk.n_mont, pk.publicExponent(), Hash, MgfHash, &m_hash, sig, salt_len);
}

/// `verifyPssPrehashed` with the hash chosen at run time (Go
/// `VerifyPSS(pub, hash, digest, sig, opts)`); `salt_len` null recovers it.
/// Returns the salt length.
pub fn verifyPssDigest(pk: PublicKey, id: HashId, digest: []const u8, sig: []const u8, salt_len: ?usize) (VerifyPssError || DigestError)!usize {
    return verifyPssDigestAny(&pk.n_mont, pk.publicExponent(), id, digest, sig, salt_len);
}

fn verifyPssDigestAny(mp: *const MontParams, e: u32, id: HashId, digest: []const u8, sig: []const u8, salt_len: ?usize) (VerifyPssError || DigestError)!usize {
    switch (id) {
        inline else => |c| {
            const H = c.Type();
            if (digest.len != H.digest_length) return error.InvalidDigestLength;
            return verifyPssDigestMont(mp, e, H, H, digest[0..H.digest_length], sig, salt_len);
        },
    }
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
    const parts = try publicKeyPartsFromDer(bytes);
    return PublicKey.fromBytes(parts.n, parts.e) catch error.InvalidDer;
}

/// The modulus and exponent INTEGER contents of a DER `RSAPublicKey`, or of
/// the one an X.509 `SubjectPublicKeyInfo` wraps — the structure walk shared
/// by `PublicKey.fromDer` and `VerifyKey.fromDer`.
const PublicKeyParts = struct { n: []const u8, e: []const u8 };

fn publicKeyPartsFromDer(bytes: []const u8) !PublicKeyParts {
    const top = try derTopSequence(bytes);
    if (top.slice.start >= top.slice.end) return error.InvalidDer; // empty SEQUENCE
    const first = Asn1.Element.decode(bytes, top.slice.start) catch return error.InvalidDer;
    if (first.slice.end > top.slice.end) return error.InvalidDer;

    if (first.tag.class == .universal and !first.tag.constructed and first.tag.number == .integer) {
        return pkcs1PublicParts(bytes, top);
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
        // Sweep RS-1: the BIT STRING holds a bare PKCS#1 `RSAPublicKey` and
        // nothing else. It used to be parsed by this function again, so an SPKI
        // wrapped in an SPKI wrapped in ... recursed to a depth set by the input
        // (stack overflow on a large DER).
        const inner = raw[1..];
        const inner_top = try derTopSequence(inner);
        if (inner_top.slice.start >= inner_top.slice.end) return error.InvalidDer;
        return pkcs1PublicParts(inner, inner_top);
    }

    return error.InvalidDer;
}

/// `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`:
/// `top` is the outer SEQUENCE of `bytes`; exactly two INTEGERs.
fn pkcs1PublicParts(bytes: []const u8, top: Asn1.Element) !PublicKeyParts {
    const n = try derChild(bytes, top.slice.start, top.slice.end, .integer, false);
    const e = try derChild(bytes, n.slice.end, top.slice.end, .integer, false);
    if (e.slice.end != top.slice.end) return error.InvalidDer; // exactly two fields
    return .{ .n = derView(bytes, n), .e = derView(bytes, e) };
}

/// `RSAPrivateKey` (PKCS#1 Appendix A.1.2), two-prime form only (`version`
/// 0): derives the key from `p`, `q`, `e` through `SecretKey.fromPrimes`,
/// then checks the wire `n`/`d`/CRT fields against it (`checkWireFields`).
/// Multi-prime keys (`version` 1, `otherPrimeInfos`)
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

    // The key is derived from p, q, e alone; the wire n, d, dP, dQ, qInv must
    // then agree with it (audit F1, 2026-10-14: until then they were never
    // read, so a file with a wrong `n` or `d` loaded silently).
    var sk = SecretKey.fromPrimesValue(derView(bytes, p), derView(bytes, q), derView(bytes, e)) catch return error.InvalidPrivateKey;
    errdefer sk.deinit();
    try checkWireFields(&sk, derView(bytes, n), derView(bytes, d), derView(bytes, dp), derView(bytes, dq), derView(bytes, qinv));
    return sk;
}

/// The F1 check, and the adoption of the wire `d`. `n`, `dP`, `dQ`, `qInv`
/// are unique given p, q, e and must equal the derived values. `d` is not:
/// any `d ≡ e⁻¹ (mod λ(n))` below `n` is valid — OpenSSL derives it mod λ,
/// older tools mod φ = (p−1)(q−1) — so it is accepted iff
/// `d ≡ dP (mod p−1)` and `d ≡ dQ (mod q−1)` (with dP, dQ derived), and is
/// then KEPT, so that parse → `toPkcs1Der` gives the input back. The secret
/// comparisons are constant-time up to the single accept/reject verdict.
fn checkWireFields(sk: *SecretKey, n_be: []const u8, d_be: []const u8, dp_be: []const u8, dq_be: []const u8, qinv_be: []const u8) error{InvalidPrivateKey}!void {
    // n is public.
    const n_wire = MontParams.loadBE(n_be) catch return error.InvalidPrivateKey;
    if (!MontParams.eql(&n_wire, &sk.n_mont.m)) return error.InvalidPrivateKey;

    var bad: u1 = 0;
    var w: [4]MontElem = undefined; // d, dP, dQ, qInv off the wire
    defer std.crypto.secureZero(u8, std.mem.asBytes(&w));
    for ([_][]const u8{ d_be, dp_be, dq_be, qinv_be }, 0..) |be, i| {
        w[i] = MontParams.loadBE(be) catch blk: {
            bad = 1; // longer than any key (public length)
            break :blk MontParams.zero;
        };
    }
    var t: [3]MontElem = .{ feToElem(&sk.dp), feToElem(&sk.dq), feToElem(&sk.qinv) };
    defer std.crypto.secureZero(u8, std.mem.asBytes(&t));
    bad |= @intFromBool(!MontParams.eql(&w[1], &t[0]));
    bad |= @intFromBool(!MontParams.eql(&w[2], &t[1]));
    bad |= @intFromBool(!MontParams.eql(&w[3], &t[2]));

    // 0 < d < n.
    var s = w[0];
    defer std.crypto.secureZero(u64, &s);
    bad |= ~montint.limbs.subInto(&s, &sk.n_mont.m); // no borrow ⟺ d ≥ n
    bad |= @intFromBool(MontParams.isZero(&w[0]));
    // d − dP ≡ 0 (mod p−1) and d − dQ ≡ 0 (mod q−1); a borrow means d < dP,
    // impossible for a valid d since dP is the least residue.
    for ([_]*const MontParams{ &sk.p_mont, &sk.q_mont }, [_]*const MontElem{ &t[0], &t[1] }) |pm, dx| {
        s = w[0];
        bad |= montint.limbs.subInto(&s, dx);
        var m1 = pm.m;
        m1[0] &= ~@as(u64, 1);
        defer std.crypto.secureZero(u64, &m1);
        var quot = montint.nt.divExact(MontParams.max_limbs, &s, &m1) catch blk: {
            bad = 1;
            break :blk MontParams.zero;
        };
        std.crypto.secureZero(u64, &quot);
    }
    if (bad != 0) return error.InvalidPrivateKey;
    sk.d = MontParams.elemToFf(Fe, sk.n, &w[0]);
}

pub const FromPkcs8Error = error{ InvalidDer, InvalidPrivateKey };

/// Parse a private key from a DER-encoded PKCS#8 `PrivateKeyInfo` (RFC 5958)
/// wrapping an RFC 8017 Appendix A.1.2 `RSAPrivateKey`. Only the plain
/// (unencrypted) `PrivateKeyInfo` shape is handled here; the password-
/// protected `EncryptedPrivateKeyInfo` (`ENCRYPTED PRIVATE KEY` in PEM) is
/// `fromPkcs8Encrypted`.
pub fn fromPkcs8(out: *SecretKey, bytes: []const u8) FromPkcs8Error!void {
    const r = fromPkcs8Unburned(out, bytes);
    burn.stack(burn.key_burn);
    return r;
}

noinline fn fromPkcs8Unburned(out: *SecretKey, bytes: []const u8) FromPkcs8Error!void {
    out.* = fromPkcs8Value(bytes) catch |err| {
        std.crypto.secureZero(u8, std.mem.asBytes(out));
        return err;
    };
}

fn fromPkcs8Value(bytes: []const u8) FromPkcs8Error!SecretKey {
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

// ── R5 (2026-10-14): encrypted PKCS#8 — PBES2 + PBKDF2 (RFC 8018, RFC 5958 §3) ─
//
// What `openssl genpkey -aes256` and `openssl pkcs8 -topk8` write: PBES2 with
// PBKDF2 (HMAC-SHA-1/224/256/384/512) and AES-128/192/256-CBC. Owner decision
// 2026-10-14: scrypt (needs an allocator; OpenSSL writes it only on `-scrypt`),
// PBES1 and the legacy `Proc-Type: 4,ENCRYPTED` / `DEK-Info` PEM (MD5 KDF,
// DES-EDE3, cannot detect a wrong password) are refused with
// `error.UnsupportedEncryption`.

pub const Pbes2Prf = marshal.Pbes2Prf;
pub const Pbes2Cipher = marshal.Pbes2Cipher;
pub const Pbes2Options = marshal.Pbes2Options;
pub const max_pbkdf2_iterations = marshal.max_pbkdf2_iterations;
pub const max_pbes2_salt_len = marshal.max_pbes2_salt_len;
pub const max_encrypted_pkcs8_der_len = marshal.max_encrypted_pkcs8_der_len;
pub const max_encrypted_pem_len = marshal.max_encrypted_pem_len;
pub const EncryptError = marshal.EncryptError;

pub const FromEncryptedError = error{
    InvalidDer,
    /// Not PBES2-with-PBKDF2-and-AES-CBC (scrypt, PBES1, another cipher).
    UnsupportedEncryption,
    /// The file names more than `max_pbkdf2_iterations` PBKDF2 iterations.
    KdfIterationsTooLarge,
    /// Wrong password, or a corrupted ciphertext: the two cannot be told
    /// apart (CBC padding and the inner key's DER are the only check), so
    /// they are one error.
    IncorrectPasswordOrCorrupt,
};

/// Parse a DER PKCS#8 `EncryptedPrivateKeyInfo` (PBES2) holding an RSA key.
/// `out` is zeroed on error; the derived key and the decrypted PKCS#8 are
/// wiped before return.
pub fn fromPkcs8Encrypted(out: *SecretKey, der: []const u8, password: []const u8) FromEncryptedError!void {
    const r = fromPkcs8EncryptedUnburned(out, der, password);
    burn.stack(burn.key_burn);
    return r;
}

noinline fn fromPkcs8EncryptedUnburned(out: *SecretKey, der: []const u8, password: []const u8) FromEncryptedError!void {
    out.* = fromPkcs8EncryptedValue(der, password) catch |err| {
        std.crypto.secureZero(u8, std.mem.asBytes(out));
        return err;
    };
}

fn fromPkcs8EncryptedValue(der: []const u8, password: []const u8) FromEncryptedError!SecretKey {
    const pp = try pbes2Params(der);
    var key: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &key);
    switch (pp.prf) {
        inline else => |p| std.crypto.pwhash.pbkdf2(key[0..pp.cipher.keyLen()], password, pp.salt, pp.iterations, p.Type()) catch unreachable, // rounds ≥ 1, dk ≤ 32
    }
    var plain: [max_pkcs8_der_len + 16]u8 = undefined;
    const pt = plain[0..pp.data.len];
    defer std.crypto.secureZero(u8, pt);
    switch (pp.cipher) {
        inline else => |c| {
            const A = c.Aes();
            _ = aescbc.decrypt(A, key[0 .. A.key_bits / 8], pp.iv.*, pp.data, pt) catch unreachable; // aligned, sized
        },
    }
    const n = aescbc.unpadPkcs7(pt) catch return error.IncorrectPasswordOrCorrupt;
    return fromPkcs8Value(pt[0..n]) catch error.IncorrectPasswordOrCorrupt;
}

const Pbes2Params = struct {
    prf: Pbes2Prf,
    cipher: Pbes2Cipher,
    salt: []const u8,
    iterations: u32,
    iv: *const [16]u8,
    data: []const u8,
};

/// The `EncryptedPrivateKeyInfo` walk (all public data):
///   SEQUENCE { SEQUENCE { pbes2, SEQUENCE {
///       SEQUENCE { pbkdf2, SEQUENCE { salt OCTET STRING, iterationCount,
///                                     keyLength OPTIONAL, prf DEFAULT sha1 } },
///       SEQUENCE { aes-CBC OID, iv OCTET STRING(16) } } },
///     encryptedData OCTET STRING }
fn pbes2Params(der: []const u8) FromEncryptedError!Pbes2Params {
    const bad = error.InvalidDer;
    const top = derTopSequence(der) catch return bad;
    const alg = derChild(der, top.slice.start, top.slice.end, .sequence, true) catch return bad;
    const data = derChild(der, alg.slice.end, top.slice.end, .octetstring, false) catch return bad;
    if (data.slice.end != top.slice.end) return bad;
    const oid = derChild(der, alg.slice.start, alg.slice.end, .oid, false) catch return bad;
    if (!std.mem.eql(u8, derView(der, oid), &marshal.oid_pbes2)) return error.UnsupportedEncryption;
    const params = derChild(der, oid.slice.end, alg.slice.end, .sequence, true) catch return bad;
    if (params.slice.end != alg.slice.end) return bad;
    const kdf = derChild(der, params.slice.start, params.slice.end, .sequence, true) catch return bad;
    const enc = derChild(der, kdf.slice.end, params.slice.end, .sequence, true) catch return bad;
    if (enc.slice.end != params.slice.end) return bad;

    const kdf_oid = derChild(der, kdf.slice.start, kdf.slice.end, .oid, false) catch return bad;
    if (!std.mem.eql(u8, derView(der, kdf_oid), &marshal.oid_pbkdf2)) return error.UnsupportedEncryption;
    const kp = derChild(der, kdf_oid.slice.end, kdf.slice.end, .sequence, true) catch return bad;
    if (kp.slice.end != kdf.slice.end) return bad;
    const salt = derChild(der, kp.slice.start, kp.slice.end, .octetstring, false) catch return bad;
    const iter = derChild(der, salt.slice.end, kp.slice.end, .integer, false) catch return bad;
    var at = iter.slice.end;
    var key_len: ?u64 = null;
    if (at < kp.slice.end) {
        const e = Asn1.Element.decode(der, at) catch return bad;
        if (e.slice.end > kp.slice.end) return bad;
        if (e.tag.class == .universal and !e.tag.constructed and e.tag.number == .integer) {
            key_len = derUint(derView(der, e)) orelse return bad;
            at = e.slice.end;
        }
    }
    var prf: Pbes2Prf = .hmac_sha1;
    if (at < kp.slice.end) {
        const p = derChild(der, at, kp.slice.end, .sequence, true) catch return bad;
        if (p.slice.end != kp.slice.end) return bad;
        const p_oid = derChild(der, p.slice.start, p.slice.end, .oid, false) catch return bad;
        prf = oidUnderArc(derView(der, p_oid), &marshal.oid_hmac_arc, Pbes2Prf) orelse return error.UnsupportedEncryption;
        if (p_oid.slice.end != p.slice.end) { // parameters: absent or NULL
            const nul = derChild(der, p_oid.slice.end, p.slice.end, .null, false) catch return bad;
            if (nul.slice.end != p.slice.end or nul.slice.start != nul.slice.end) return bad;
        }
    }

    const enc_oid = derChild(der, enc.slice.start, enc.slice.end, .oid, false) catch return bad;
    const cipher = oidUnderArc(derView(der, enc_oid), &marshal.oid_aes_arc, Pbes2Cipher) orelse return error.UnsupportedEncryption;
    const iv = derChild(der, enc_oid.slice.end, enc.slice.end, .octetstring, false) catch return bad;
    if (iv.slice.end != enc.slice.end) return bad;
    const iv_bytes = derView(der, iv);
    if (iv_bytes.len != 16) return bad;
    if (key_len) |kl| if (kl != cipher.keyLen()) return bad;

    const salt_bytes = derView(der, salt);
    if (salt_bytes.len == 0 or salt_bytes.len > max_pbes2_salt_len) return bad;
    const iterations = derUint(derView(der, iter)) orelse return bad;
    if (iterations == 0) return bad;
    if (iterations > max_pbkdf2_iterations) return error.KdfIterationsTooLarge;
    const ct = derView(der, data);
    if (ct.len == 0 or ct.len % 16 != 0 or ct.len > max_pkcs8_der_len + 16) return bad;
    return .{
        .prf = prf,
        .cipher = cipher,
        .salt = salt_bytes,
        .iterations = @intCast(iterations),
        .iv = iv_bytes[0..16],
        .data = ct,
    };
}

/// A non-negative minimal DER INTEGER as a u64; values wider than 64 bits
/// saturate (every caller compares against a much smaller cap).
fn derUint(b: []const u8) ?u64 {
    if (b.len == 0 or b[0] & 0x80 != 0) return null; // empty or negative
    if (b.len > 1 and b[0] == 0 and b[1] & 0x80 == 0) return null; // not minimal
    const s = stripLeadingZeros(b);
    if (s.len > 8) return std.math.maxInt(u64);
    var v: u64 = 0;
    for (s) |x| v = v << 8 | x;
    return v;
}

/// `E.fromOidLast` of the last OID component if `oid` is `arc` plus one
/// single-byte component.
fn oidUnderArc(oid: []const u8, arc: []const u8, comptime E: type) ?E {
    if (oid.len != arc.len + 1 or !std.mem.eql(u8, oid[0..arc.len], arc)) return null;
    return E.fromOidLast(oid[arc.len]);
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

    const bi = std.mem.find(u8, text, begin_marker) orelse return error.MissingPemBlock;
    const label_start = bi + begin_marker.len;
    const label_end = std.mem.findPos(u8, text, label_start, dashes) orelse return error.InvalidPem;
    const label = text[label_start..label_end];
    if (label.len > max_pem_label_len) return error.InvalidPem;

    const body_start = label_end + dashes.len;
    var end_marker_buf: [max_end_marker_len]u8 = undefined;
    const end_marker = std.mem.print(&end_marker_buf, "-----END {s}-----", .{label}) catch unreachable;
    // The END line starts at the first '-' after the body: base64 has none, so
    // this scan's compare is false on every key character and it stops at the
    // body's (public) length. Not std.mem.findPos: Boyer-Moore-Horspool
    // indexes its skip table by, and skips by an amount that depends on, the
    // key's characters (acme ctgrind 2026-10-18). The first block of the label
    // is used, as documented.
    const ei = std.mem.findScalarPos(u8, text, body_start, '-') orelse return error.InvalidPem;
    if (!std.mem.startsWith(u8, text[ei..], end_marker)) return error.InvalidPem;
    const body = text[body_start..ei];

    // Constant time in the body's characters (a private key's DER), not
    // std's table decoder: the alphabet lookup is indexed by the key.
    var block: PemBlock = .{ .label = label, .der_buf = undefined, .der_len = 0 };
    const n = (b64ct.standard.decodeIgnoring(&block.der_buf, body, b64ct.pem_whitespace) catch return error.InvalidPem).len;
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

/// The largest bcrypt round count `fromOpenSSH` accepts from a key file:
/// 2048, 128x ssh-keygen's default of 16 and a few seconds of CPU. OpenSSH
/// itself sets no bound (ssh-keygen -a takes anything up to INT_MAX); the cap
/// and its value follow Go's x/crypto/ssh (`maxRounds = 1 << 11`). Found by
/// RSA_FUZZ (`rsa-openssh` HANG, 2026-10-09): `rounds = 2^32-1` in the
/// kdfoptions ran for over 120 s before the watchdog.
pub const max_openssh_kdf_rounds: u32 = 1 << 11;

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
    /// The bcrypt round count stored in the key file is above
    /// `max_openssh_kdf_rounds`. bcrypt_pbkdf's cost is linear in it and the
    /// file sets it, so an uncapped value pins the caller's CPU for months.
    KdfRoundsTooLarge,
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
pub const OpensshCipher = enum {
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
pub fn fromOpenSSH(out: *SecretKey, text: []const u8, passphrase: []const u8) FromOpenSSHError!void {
    const r = fromOpenSSHUnburned(out, text, passphrase);
    burn.stack(burn.key_burn);
    return r;
}

noinline fn fromOpenSSHUnburned(out: *SecretKey, text: []const u8, passphrase: []const u8) FromOpenSSHError!void {
    out.* = fromOpenSSHValue(text, passphrase) catch |err| {
        std.crypto.secureZero(u8, std.mem.asBytes(out));
        return err;
    };
}

fn fromOpenSSHValue(text: []const u8, passphrase: []const u8) FromOpenSSHError!SecretKey {
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

    var dec_buf: [max_pem_der_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &dec_buf);
    const sec = try opensshDecryptSection(&dec_buf, ciphername, kdfname, kdfoptions, private_section, passphrase);
    return parsePrivateSection(sec.plain, sec.cipher, sec.encrypted);
}

/// An openssh-key-v1 private-keys section after `opensshDecryptSection`.
pub const OpensshSection = struct {
    /// The plaintext section: the container's own bytes when it is not
    /// encrypted, else the decryption in the caller's `dst`.
    plain: []const u8,
    /// Whether a passphrase was involved: a checkint mismatch then means a
    /// wrong passphrase (`error.IncorrectPassphrase`), not corruption.
    encrypted: bool,
    /// The block size the section is padded to (8 for `none`, 16 for AES):
    /// the `1, 2, 3, ...` padding after the last key is shorter than this.
    block_len: usize,
    cipher: OpensshCipher,
};

/// The cipher/KDF half of OpenSSH `PROTOCOL.key`, shared by every key type
/// (the `ssh` module uses it for ed25519 and ECDSA containers): validates the
/// ciphername/kdfname/kdfoptions combination, caps the bcrypt round count
/// (`max_openssh_kdf_rounds`), derives key || IV with bcrypt_pbkdf and
/// decrypts `section` (aes256-ctr / aes256-cbc, the two ciphers OpenSSH and
/// Go's x/crypto/ssh read) into `dst` (`dst.len >= section.len`). For an
/// unencrypted container (`none`/`none`, empty options) `dst` is untouched
/// and `plain` is `section`. The caller owns wiping `dst` and burning the
/// stack (bcrypt and AES key schedules live in this frame's callees).
pub fn opensshDecryptSection(
    dst: []u8,
    ciphername: []const u8,
    kdfname: []const u8,
    kdfoptions: []const u8,
    section: []const u8,
    passphrase: []const u8,
) FromOpenSSHError!OpensshSection {
    const cipher = try OpensshCipher.fromName(ciphername);
    const kdf_none = std.mem.eql(u8, kdfname, "none");
    const kdf_bcrypt = std.mem.eql(u8, kdfname, "bcrypt");
    if (!kdf_none and !kdf_bcrypt) return error.UnsupportedKdf;

    if (cipher == .none) {
        // Unencrypted: kdf must be none with empty options.
        if (!kdf_none or kdfoptions.len != 0) return error.InvalidOpenSSH;
        return .{ .plain = section, .encrypted = false, .block_len = cipher.blockLen(), .cipher = cipher };
    }

    // Encrypted: kdf must be bcrypt; kdfoptions = string salt + u32 rounds.
    if (!kdf_bcrypt) return error.InvalidOpenSSH;
    var kr = SshReader{ .buf = kdfoptions };
    const salt = try kr.readString();
    const rounds = try kr.readU32();
    if (kr.rest().len != 0 or salt.len == 0 or rounds == 0) return error.InvalidOpenSSH;
    if (rounds > max_openssh_kdf_rounds) return error.KdfRoundsTooLarge;
    if (section.len == 0 or section.len % cipher.blockLen() != 0) {
        return error.InvalidOpenSSH;
    }
    if (dst.len < section.len) return error.InvalidOpenSSH;

    // Derive key (32) || IV (16). An empty passphrase is rejected by the
    // KDF itself — report it like any other wrong passphrase.
    var key_iv: [48]u8 = undefined;
    defer std.crypto.secureZero(u8, &key_iv);
    openssh.bcryptPbkdf(passphrase, salt, rounds, &key_iv) catch return error.IncorrectPassphrase;
    const aes_key = key_iv[0..32];
    const iv = key_iv[32..48];

    const dec = dst[0..section.len];
    const aes = std.crypto.core.aes;
    switch (cipher) {
        .none => unreachable,
        .aes256_ctr => {
            const ctx = aes.Aes256.initEnc(aes_key.*);
            std.crypto.core.modes.ctr(
                aes.AesEncryptCtx(aes.Aes256),
                ctx,
                dec,
                section,
                iv.*,
                .big,
            );
        },
        .aes256_cbc => {
            const ctx = aes.Aes256.initDec(aes_key.*);
            var prev: [16]u8 = iv.*;
            var off: usize = 0;
            while (off < section.len) : (off += 16) {
                const ct_block = section[off..][0..16];
                var pt: [16]u8 = undefined;
                ctx.decrypt(&pt, ct_block);
                for (&pt, prev) |*b, x| b.* ^= x;
                @memcpy(dec[off..][0..16], &pt);
                prev = ct_block.*;
                std.crypto.secureZero(u8, &pt);
            }
        },
    }
    return .{ .plain = dec, .encrypted = true, .block_len = cipher.blockLen(), .cipher = cipher };
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

    var sk: SecretKey = undefined;
    SecretKey.fromPrimes(
        &sk,
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
// Witnesses are drawn from the caller's `random`, uniformly in
// [2, 2^(bits−1)) — below every candidate by its length, so no draw is
// compared against the secret.
//
// Timing: the search loop is data-dependent (every implementation's is),
// but what it reveals is about REJECTED candidates. Along the path a kept
// prime takes, Miller-Rabin is constant-time in its value since 2026-10-03
// (`montint.DynModint.isProbablePrime`: montint ladder, `p − 1 = d·2^s` by
// masked shifts, round verdicts OR-ed before the one branch) — `ff`'s pow,
// used until then, branches on its exponent windows in ReleaseFast. Still
// observable: `s` (the 2-adic valuation of `p − 1`, via the squaring count)
// and the trial-division sieve's `%` on the candidate (`bytesMod`).

/// Miller-Rabin rounds per candidate — see the section comment above for the
/// FIPS 186-5 Table B.1 rationale.
const mr_rounds = 64;

/// Odd primes below 1024 for the trial-division pre-sieve, generated at
/// comptime (sieve of Eratosthenes). Filters ~84% of random odd candidates
/// with cheap byte-wise remainders before any Miller-Rabin modexp runs.
const sieve_primes = blk: {
    @setEvalBranchQuota(20_000);
    const limit = 1024;
    var composite = @as([limit]bool, @splat(false));
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

/// Set bit `bit` (LSB = 0) of a big-endian byte string.
fn setBitBe(buf: []u8, bit: usize) void {
    buf[buf.len - 1 - bit / 8] |= @as(u8, 1) << @intCast(bit % 8);
}

/// Miller-Rabin with `mr_rounds` witnesses on an `ff` modulus — the
/// tests' entry point (their known primes and composites); the search
/// itself calls `DynModint.isProbablePrime` on the candidate directly.
fn isProbablePrime(m: Modulus, random: std.Random) bool {
    var v = MontParams.elemFromFf(&m.v);
    defer std.crypto.secureZero(u64, &v);
    const mc = MontParams.fromLimbsBits(&v, m.bits()) catch return false;
    return mc.isProbablePrime(random, mr_rounds);
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

        // Odd, exactly prime_bits bits (both set above): the candidate as a
        // montint modulus of known length, Miller-Rabin on it constant-time
        // in its value along a prime's path (`DynModint.isProbablePrime`).
        var v = MontParams.loadBE(out) catch unreachable; // <= max_modulus_len bytes
        defer std.crypto.secureZero(u64, &v);
        var m = MontParams.fromLimbsBits(&v, prime_bits) catch unreachable;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&m));
        if (m.isProbablePrime(random, mr_rounds)) return;
    }
}

/// FIPS 186-5 §A.1.3 closeness guard: reject q when the top 100 bits of p
/// and q coincide (a sufficient condition for |p − q| <= 2^(plen − 100),
/// which would expose n to Fermat factorization). Also subsumes p == q.
/// `d > 2^half`, constant-time in `d` up to the verdict: `d − (2^half + 1)`
/// does not borrow.
fn privateExponentAboveHalf(sk: *const SecretKey, half: usize) bool {
    var t = feToElem(&sk.d);
    defer std.crypto.secureZero(u64, &t);
    var bound = MontParams.zero;
    bound[half / 64] = @as(u64, 1) << @intCast(half % 64);
    bound[0] |= 1;
    return montint.limbs.subInto(&t, &bound) == 0;
}

fn topBitsMatch(p: []const u8, q: []const u8) bool {
    std.debug.assert(p.len == q.len and p.len >= 13);
    if (!std.mem.eql(u8, p[0..12], q[0..12])) return false; // 96 bits
    return (p[12] ^ q[12]) & 0xf0 == 0; // + 4 more = 100 bits
}

/// A freshly generated RSA keypair (`generate`'s result). `public_key`
/// equals `secret_key.publicKey()`; it is returned too for convenience.
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
pub fn generate(out: *KeyPair, random: std.Random, bits: usize, e: u64) GenerateError!void {
    const r = generateUnburned(out, random, bits, e);
    burn.stack(burn.key_burn);
    return r;
}

noinline fn generateUnburned(out: *KeyPair, random: std.Random, bits: usize, e: u64) GenerateError!void {
    out.* = generateValue(random, bits, e) catch |err| {
        std.crypto.secureZero(u8, std.mem.asBytes(out));
        return err;
    };
}

fn generateValue(random: std.Random, bits: usize, e: u64) GenerateError!KeyPair {
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
        var sk: SecretKey = undefined;
        SecretKey.fromPrimes(&sk, p_bytes, q_bytes, &e_bytes) catch continue;
        // FIPS 186-5 A.1.1 step 4.c (survey F2, 2026-10-14): d > 2^(nlen/2),
        // else start over with fresh primes. Practically never taken for a
        // random key; the verdict is the only branch on d.
        if (!privateExponentAboveHalf(&sk, half)) {
            sk.deinit();
            continue;
        }

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
// `signPkcs1v15` (P1). The DER is built with `der_writer.Builder` (`src/der_writer.zig`:
// an arena-backed bottom-up TLV builder — every helper returns a complete
// tag+length+value slice), the encoder `acme` and `ocsp` share too. Its
// idiom started as a hand copy of `acme`'s CSR builder, extended with the
// shapes a full certificate needs (INTEGER, OCTET STRING, BOOLEAN, UTCTime,
// UTF8String, `[n] EXPLICIT`/`[n] IMPLICIT`); since 2026-10-17 the copy is
// the one shared implementation and `acme` imports it from here.
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

/// `ValueTooLarge` stays for the public `SelfSignedCertError`'s stability; the
/// shared `der_writer.Builder` encodes any length, so it is no longer returned.
const DerCertError = error{ OutOfMemory, ValueTooLarge };

/// The DER encoder (`src/der_writer.zig`), public for `acme` and `ocsp`.
pub const der_writer = @import("der_writer.zig");

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
/// adding more `der_writer.Builder.implicitPrimitive` calls in `buildSanExtnValue`
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
fn buildNameCn(d: der_writer.Builder, common_name: []const u8) DerCertError![]const u8 {
    const atv = try d.seq(&.{ try d.oid(&oid_common_name), try d.utf8String(common_name) });
    const rdn = try d.tlv(0x31, atv); // RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
    return d.seq(&.{rdn}); // RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
}

/// `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`
/// (PKCS#1 Appendix A.1.1) — the same shape P4a's `publicKeyFromDerImpl`
/// parses, built here instead of parsed.
fn buildRsaPublicKeyDer(d: der_writer.Builder, pk: PublicKey) DerCertError![]const u8 {
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
fn buildSpki(d: der_writer.Builder, pk: PublicKey) DerCertError![]const u8 {
    const rsa_pub_key_der = try buildRsaPublicKeyDer(d, pk);
    return d.seq(&.{
        try d.seq(&.{ try d.oid(&oid_rsa_encryption), der_null }),
        try d.bitString(rsa_pub_key_der),
    });
}

/// `GeneralNames ::= SEQUENCE OF GeneralName` — the `subjectAltName`
/// extension's `extnValue` payload (RFC 5280 §4.2.1.6).
fn buildSanExtnValue(d: der_writer.Builder, sans: []const SubjectAltName) DerCertError![]const u8 {
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
fn keyUsageBitString(d: der_writer.Builder, is_ca: bool) DerCertError![]const u8 {
    const byte: u8 = if (is_ca) 0x86 else 0x80; // digitalSignature | (keyCertSign | cRLSign if CA)
    const unused: u8 = @ctz(byte);
    return d.tlv(0x03, try d.cat(&.{ &.{unused}, &.{byte} }));
}

/// `extensions [3] EXPLICIT Extensions` (RFC 5280 §4.1.2.9): always
/// `basicConstraints` (critical, `cA` per `opts.is_ca`) and `keyUsage`
/// (critical); `subjectAltName` (not critical) if `opts.subject_alt_names`
/// is non-empty.
fn buildExtensions(d: der_writer.Builder, opts: CertOptions) DerCertError![]const u8 {
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
/// (the caller-supplied `pk` must be the public key matching `sk`, e.g.
/// `sk.publicKey()`; it is not compared),
/// signed with RSASSA-PKCS1-v1_5 over `Hash` (`signPkcs1v15`, P1). Returns
/// `gpa`-owned DER bytes (`Certificate ::= SEQUENCE { tbsCertificate,
/// signatureAlgorithm, signatureValue BIT STRING }`); an owned-slice return
/// (mirroring `modules/acme/src/x509.zig`'s `csrDer`) is the natural shape
/// here rather than a fixed `out` buffer, since the encoded length varies
/// with `common_name`/SAN content and the caller has no simple formula to
/// pre-size a buffer for that.
pub fn selfSignedCert(
    gpa: std.mem.Allocator,
    sk: *const SecretKey,
    pk: PublicKey,
    comptime Hash: type,
    opts: CertOptions,
) SelfSignedCertError![]u8 {
    if (opts.common_name.len == 0) return error.InvalidCertOptions;
    if (!validUtcTime(opts.not_before) or !validUtcTime(opts.not_after)) return error.InvalidCertOptions;

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const d: der_writer.Builder = .{ .a = arena.allocator() };

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
    _ = der_writer;
    _ = @import("sweep_test.zig");
    _ = @import("stackprobe_test.zig");
    _ = @import("stackprobe2_test.zig");
    _ = @import("wycheproof_test.zig");
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

/// Destination for the error-path tests of the out-param constructors.
var test_sk_out: SecretKey = undefined;
var test_kp_out: KeyPair = undefined;

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
        return SecretKey.fromPrimesValue(&p, &q, &e);
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
    var sk: SecretKey = undefined;
    try SecretKey.fromPrimes(&sk, &.{61}, &.{53}, &.{17});
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
    try testing.expectError(error.InvalidPrivateKey, SecretKey.fromPrimes(&test_sk_out, &.{61}, &.{61}, &.{17}));
    // even e / e < 3
    try testing.expectError(error.InvalidPrivateKey, SecretKey.fromPrimes(&test_sk_out, &.{61}, &.{53}, &.{16}));
    try testing.expectError(error.InvalidPrivateKey, SecretKey.fromPrimes(&test_sk_out, &.{61}, &.{53}, &.{1}));
    // gcd(e, λ) != 1: λ(61·53) = 780 = 2²·3·5·13 -> e = 13 shares a factor
    try testing.expectError(error.InvalidPrivateKey, SecretKey.fromPrimes(&test_sk_out, &.{61}, &.{53}, &.{13}));
    // even "prime"
    try testing.expectError(error.InvalidPrivateKey, SecretKey.fromPrimes(&test_sk_out, &.{62}, &.{53}, &.{17}));
}

test "SecretKey.deinit zeroes all key material (audit F4)" {
    var sk: SecretKey = undefined;
    try SecretKey.fromPrimes(&sk, &.{61}, &.{53}, &.{17});
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
    var sk: SecretKey = undefined;
    try SecretKey.fromPrimes(&sk, &.{61}, &.{53}, &.{17});
    const pk = PublicKey{ .n = sk.n, .e = try Fe.fromPrimitive(u32, sk.n, 17), .n_mont = sk.n_mont };

    // 65^17 mod 3233 = 2790 (0x0ae6)
    const c = try rsaep(2, .{ 0x00, 0x41 }, pk);
    try testing.expectEqualSlices(u8, &.{ 0x0a, 0xe6 }, &c);

    const m_plain = try rsadp(2, c, &sk);
    const m_crt = try rsadpCrt(2, c, &sk);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x41 }, &m_plain);
    try testing.expectEqualSlices(u8, &m_plain, &m_crt);

    // rsavp1/rsasp1 are the same math with the RFC's signature naming.
    const s = try rsasp1(2, .{ 0x00, 0x41 }, &sk);
    const v = try rsavp1(2, s, pk);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x41 }, &v);
}

test "primitives reject representative >= n" {
    var sk: SecretKey = undefined;
    try SecretKey.fromPrimes(&sk, &.{61}, &.{53}, &.{17});
    const pk = PublicKey{ .n = sk.n, .e = try Fe.fromPrimitive(u32, sk.n, 17), .n_mont = sk.n_mont };
    // n = 3233 = 0x0ca1
    try testing.expectError(error.MessageRepresentativeOutOfRange, rsaep(2, .{ 0x0c, 0xa1 }, pk));
    try testing.expectError(error.MessageRepresentativeOutOfRange, rsadp(2, .{ 0xff, 0xff }, &sk));
    try testing.expectError(error.MessageRepresentativeOutOfRange, rsadpCrt(2, .{ 0x0c, 0xa1 }, &sk));
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

    const s256 = try signPkcs1v15(&sk, sha2.Sha256, kat2048.msg, &out);
    try testing.expectEqualSlices(u8, &kat2048.sig_sha256, s256);

    const s384 = try signPkcs1v15(&sk, sha2.Sha384, kat2048.msg, &out);
    try testing.expectEqualSlices(u8, &kat2048.sig_sha384, s384);

    const s512 = try signPkcs1v15(&sk, sha2.Sha512, kat2048.msg, &out);
    try testing.expectEqualSlices(u8, &kat2048.sig_sha512, s512);
}

test "signPkcs1v15Prehashed / signPssPrehashed: the OpenSSL known answers from the digest; PSS verifies" {
    const sk = try kat2048.secretKey();
    const sha2 = std.crypto.hash.sha2;
    var out: [max_modulus_len]u8 = undefined;
    inline for (.{ .{ sha2.Sha256, &kat2048.sig_sha256 }, .{ sha2.Sha384, &kat2048.sig_sha384 }, .{ sha2.Sha512, &kat2048.sig_sha512 } }) |c| {
        var d: [c[0].digest_length]u8 = undefined;
        c[0].hash(kat2048.msg, &d, .{});
        try testing.expectEqualSlices(u8, c[1], try signPkcs1v15Prehashed(&sk, c[0], &d, &out));
    }
    // PSS: salt 0 is deterministic, so the two entry points must agree; a
    // salted prehashed signature verifies against the message.
    var csprng = std.Random.DefaultCsprng.init(@splat(9));
    var d: [32]u8 = undefined;
    sha2.Sha256.hash(kat2048.msg, &d, .{});
    var a: [max_modulus_len]u8 = undefined;
    const from_msg = try signPss(&sk, sha2.Sha256, csprng.random(), kat2048.msg, 0, &a);
    try testing.expectEqualSlices(u8, from_msg, try signPssPrehashed(&sk, sha2.Sha256, csprng.random(), &d, 0, &out));
    const salted = try signPssPrehashed(&sk, sha2.Sha256, csprng.random(), &d, 32, &out);
    try verifyPss(try kat2048.publicKey(), sha2.Sha256, kat2048.msg, salted, 32);
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
        const sig = try signPkcs1v15(&sk, Hash, "fresh round-trip message", &out);
        try verifyPkcs1v15(pk, Hash, "fresh round-trip message", sig);
        try testing.expectError(error.SignatureVerificationFailed, verifyPkcs1v15(pk, Hash, "some other message", sig));
    }

    var small: [64]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, signPkcs1v15(&sk, std.crypto.hash.sha2.Sha256, "m", &small));
}

test "std.crypto.Certificate.rsa verifies our signature (oracle cross-check)" {
    const sk = try kat2048.secretKey();
    var out: [max_modulus_len]u8 = undefined;
    const sig = try signPkcs1v15(&sk, std.crypto.hash.sha2.Sha256, kat2048.msg, &out);

    const std_rsa = std.crypto.Certificate.rsa;
    const std_pk = try std_rsa.PublicKey.fromBytes(&kat2048.e, &kat2048.n);
    try std_rsa.PKCS1v1_5Signature.verify(256, sig[0..256], kat2048.msg, std_pk, std.crypto.hash.sha2.Sha256);
}

test "rsadpCrt equals rsadp on the 2048-bit key" {
    const sk = try kat2048.secretKey();
    const pk = try kat2048.publicKey();

    var m: [256]u8 = undefined;
    for (&m, 0..) |*b, i| b.* = @truncate(i *% 37 +% 11);
    m[0] = 0; // keep the representative < n

    const c = try rsaep(256, m, pk);
    const via_plain = try rsadp(256, c, &sk);
    const via_crt = try rsadpCrt(256, c, &sk);
    try testing.expectEqualSlices(u8, &m, &via_plain);
    try testing.expectEqualSlices(u8, &via_plain, &via_crt);
}

// audit F3 — Bellcore/BDL fault-injection countermeasure. A persistent fault
// in one CRT exponent (`dP`) makes the recovered `m` fail the `m^e ≡ c` re-
// encryption check, so the op must return `error.FaultDetected` instead of the
// factoring-oracle value. RED if the F3 check is removed from `privateOpCrt`.
test "privateOpCrt Bellcore check rejects a faulted CRT half (audit F3)" {
    var sk: SecretKey = undefined;
    try SecretKey.fromPrimes(&sk, &kat512.p, &kat512.q, &kat512.e);
    const k = byteLen(sk.n.bits());

    // A representative safely < n (top byte zero).
    var msg: [max_modulus_len]u8 = undefined;
    @memset(msg[0..k], 0);
    msg[k - 1] = 0x2a;

    var out: [max_modulus_len]u8 = undefined;
    // Baseline: the intact key produces a value and passes the check.
    try privateOpCrtPtr(&sk, msg[0..k], out[0..k], .none);

    // Inject a persistent single-half fault: dP <- dP + 1 (mod p). Now
    // m1 = c^(dP+1) mod p is wrong, so the recombined m ≢ c^d and m^e ≢ c.
    sk.dp = sk.p.add(sk.dp, sk.p.one());
    try testing.expectError(error.FaultDetected, privateOpCrtPtr(&sk, msg[0..k], out[0..k], .none));

    // Same rejection on the blinded path (blinding must not mask a real fault).
    var prng = std.Random.DefaultPrng.init(0xfa17_1717_c0de_0003);
    try testing.expectError(error.FaultDetected, privateOpCrtPtr(&sk, msg[0..k], out[0..k], .{ .csprng = prng.random() }));
}

// A faulted key also fails at the public sign entry points (fault propagates as
// error.FaultDetected, never a silent bad signature).
test "signPkcs1v15 surfaces a CRT fault as error.FaultDetected (audit F3)" {
    var sk = try kat2048.secretKey();
    sk.dq = sk.q.add(sk.dq, sk.q.one()); // fault the other CRT half this time
    var out: [max_modulus_len]u8 = undefined;
    try testing.expectError(error.FaultDetected, signPkcs1v15(&sk, std.crypto.hash.sha2.Sha256, "faulted", &out));
}

// audit F2 — CRT base blinding. The blinded op (rng supplied) must round-trip to
// exactly the unblinded result across key sizes, and repeated blinded runs must
// agree (masking is unblinded before output). Also cross-checks m^e ≡ c via the
// public key. Uses the internal `privateOpCrt` since the public primitives are
// deterministic (null rng).
test "CRT base blinding round-trips and matches the unblinded result (audit F2)" {
    var prng = std.Random.DefaultPrng.init(0xb11d_0000_5eed_0002);
    const random = prng.random();

    var sk512: SecretKey = undefined;
    try SecretKey.fromPrimes(&sk512, &kat512.p, &kat512.q, &kat512.e);
    const sk2048 = try kat2048.secretKey();
    for ([_]SecretKey{ sk512, sk2048 }) |sk| {
        const k = byteLen(sk.n.bits());
        var msg: [max_modulus_len]u8 = undefined;
        random.bytes(msg[0..k]);
        msg[0] = 0; // representative < n (n's top byte is nonzero)

        var out_plain: [max_modulus_len]u8 = undefined;
        var out_blind1: [max_modulus_len]u8 = undefined;
        var out_blind2: [max_modulus_len]u8 = undefined;
        try privateOpCrtPtr(&sk, msg[0..k], out_plain[0..k], .none);
        try privateOpCrtPtr(&sk, msg[0..k], out_blind1[0..k], .{ .csprng = random });
        try privateOpCrtPtr(&sk, msg[0..k], out_blind2[0..k], .{ .csprng = random });
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
// R1 was: F2 base blinding existed (`makeBlinding`, now `drawBlindingPair`) but the three private-key
// entry points that run over ATTACKER-CHOSEN input — `decryptOaep`,
// `decryptOaepH`, `signPkcs1v15` (and the `rsadpCrt` primitive) — hard-coded
// `privateOpCrt(…, null)`, and the public API had no parameter through which a
// consumer could turn it on. The default is unchanged (see `Blinding`); what
// changed is that there is now a way to ask, and the choice has a name.

test "Blinding: three arms, and the unblinded one is a name rather than a null" {
    const info = @typeInfo(Blinding).@"union";
    try testing.expectEqual(@as(usize, 3), info.field_names.len);
    try testing.expectEqualStrings("csprng", info.field_names[0]);
    try testing.expectEqualStrings("none", info.field_names[1]);
    try testing.expectEqualStrings("cached", info.field_names[2]);
    // `.none` carries no payload — it is a decision, not an absent argument.
    try testing.expectEqual(void, info.field_types[1]);
    try testing.expectEqual(*BlindingCache, info.field_types[2]);
}

// `Blinding.cached` (2026-10-18): the cached pair is squared per op and
// redrawn every `refresh_every` ops or on a key change. Each case compares
// against the unblinded op, so a wrong pair — one not satisfying
// `r^e·(r⁻¹)^e ≡ 1` — fails as a different output or `error.FaultDetected`.
test "Blinding.cached: equals the unblinded op across refreshes and key changes; draws only on refresh" {
    var sk512: SecretKey = undefined;
    try SecretKey.fromPrimes(&sk512, &kat512.p, &kat512.q, &kat512.e);
    const sk2048 = try kat2048.secretKey();
    var msg_rng = std.Random.DefaultPrng.init(0xb11d_cace_0001);
    var prng = std.Random.DefaultPrng.init(0xb11d_cace_0002);
    var cache = BlindingCache.init(prng.random());
    defer cache.deinit();

    const n_ops = 2 * BlindingCache.refresh_every + 5;
    for ([_]*const SecretKey{ &sk512, &sk2048 }) |sk| {
        const k = byteLen(sk.n.bits());
        for (0..n_ops) |i| {
            var msg: [max_modulus_len]u8 = undefined;
            msg_rng.random().bytes(msg[0..k]);
            msg[0] = 0; // < n
            var plain: [max_modulus_len]u8 = undefined;
            var got: [max_modulus_len]u8 = undefined;
            try privateOpCrtPtr(sk, msg[0..k], plain[0..k], .none);
            const before = prng;
            const prev = cache.pair;
            try privateOpCrtPtr(sk, msg[0..k], got[0..k], .{ .cached = &cache });
            try testing.expectEqualSlices(u8, plain[0..k], got[0..k]);
            // The generator is read on the first op for this key and then
            // every `refresh_every` ops, never in between.
            const drew = !std.mem.eql(u8, std.mem.asBytes(&before), std.mem.asBytes(&prng));
            try testing.expectEqual(i % BlindingCache.refresh_every == 0, drew);
            // Between draws the pair is the previous one squared. Reusing
            // the same `r` unchanged passes every other check here (mutation
            // 2026-10-18), so the update itself is pinned.
            if (!drew) {
                try testing.expect(MontParams.eql(&cache.pair.rpe, &sk.p_mont.sq(&prev.rpe)));
                try testing.expect(MontParams.eql(&cache.pair.rp_inv, &sk.p_mont.sq(&prev.rp_inv)));
                try testing.expect(MontParams.eql(&cache.pair.rqe, &sk.q_mont.sq(&prev.rqe)));
                try testing.expect(MontParams.eql(&cache.pair.rq_inv, &sk.q_mont.sq(&prev.rq_inv)));
            }
            // The squared pair still blinds and unblinds: r^e·(r⁻¹)^e ≡ 1.
            var e_be: [4]u8 = undefined;
            std.mem.writeInt(u32, &e_be, sk.publicExponent(), .big);
            var one: MontElem = MontParams.zero;
            one[0] = 1;
            const P = &cache.pair;
            try testing.expect(MontParams.eql(&sk.p_mont.mul(&P.rpe, &sk.p_mont.powPublic(&P.rp_inv, stripLeadingZeros(&e_be))), &one));
            try testing.expect(MontParams.eql(&sk.q_mont.mul(&P.rqe, &sk.q_mont.powPublic(&P.rq_inv, stripLeadingZeros(&e_be))), &one));
        }
    }

    // Alternating keys: every op is a key change, so every op draws.
    for (0..4) |i| {
        const sk: *const SecretKey = if (i % 2 == 0) &sk512 else &sk2048;
        const k = byteLen(sk.n.bits());
        var msg: [max_modulus_len]u8 = @splat(0);
        msg[k - 1] = @intCast(i + 2);
        var plain: [max_modulus_len]u8 = undefined;
        var got: [max_modulus_len]u8 = undefined;
        try privateOpCrtPtr(sk, msg[0..k], plain[0..k], .none);
        const before = prng;
        try privateOpCrtPtr(sk, msg[0..k], got[0..k], .{ .cached = &cache });
        try testing.expectEqualSlices(u8, plain[0..k], got[0..k]);
        try testing.expect(!std.mem.eql(u8, std.mem.asBytes(&before), std.mem.asBytes(&prng)));
    }

    // deinit wipes the pair and forgets the key: the next op draws afresh.
    cache.deinit();
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&cache.pair), 0));
    const before_deinit = prng;
    var sig: [max_modulus_len]u8 = undefined;
    var sig_plain: [max_modulus_len]u8 = undefined;
    const Sha256 = std.crypto.hash.sha2.Sha256;
    const a = try signPkcs1v15Blinded(&sk2048, Sha256, .{ .cached = &cache }, "cached", &sig);
    const b = try signPkcs1v15(&sk2048, Sha256, "cached", &sig_plain);
    try testing.expectEqualSlices(u8, b, a);
    try testing.expect(!std.mem.eql(u8, std.mem.asBytes(&before_deinit), std.mem.asBytes(&prng)));
}

// The cache's key check compares the modulus AND the exponent. The test
// above alternates keys of different widths, which a limb-count check alone
// tells apart; here the other key differs only in `e` (same primes), or only
// in `n` (same width) — a pair kept for the old key would blind with the
// wrong `r^e` and fail as `error.FaultDetected` (mutation 2026-10-18).
test "Blinding.cached: another exponent on the same modulus, or another modulus of the same width, draws afresh" {
    var sk_a: SecretKey = undefined;
    try SecretKey.fromPrimes(&sk_a, &kat512.p, &kat512.q, &kat512.e);
    // Same primes, a different valid exponent (the first one coprime to λ).
    var sk_e: SecretKey = undefined;
    for ([_]u8{ 3, 5, 7, 11, 13, 17 }) |e| {
        SecretKey.fromPrimes(&sk_e, &kat512.p, &kat512.q, &.{e}) catch continue;
        break;
    } else return error.NoSecondExponent;
    // A different 512-bit modulus: same limb count as `sk_a`.
    var key_rng = std.Random.DefaultPrng.init(0xb11d_cace_0003);
    var kp: KeyPair = undefined;
    try generate(&kp, key_rng.random(), 512, 65537);
    try testing.expectEqual(sk_a.n_mont.L, kp.secret_key.n_mont.L);

    var prng = std.Random.DefaultPrng.init(0xb11d_cace_0004);
    var cache = BlindingCache.init(prng.random());
    defer cache.deinit();
    const keys = [_]*const SecretKey{ &sk_a, &sk_e, &sk_a, &kp.secret_key, &sk_a };
    for (keys, 0..) |sk, i| {
        const k = byteLen(sk.n.bits());
        var msg: [max_modulus_len]u8 = @splat(0);
        msg[k - 1] = @intCast(i + 2);
        var plain: [max_modulus_len]u8 = undefined;
        var got: [max_modulus_len]u8 = undefined;
        try privateOpCrtPtr(sk, msg[0..k], plain[0..k], .none);
        const before = prng;
        try privateOpCrtPtr(sk, msg[0..k], got[0..k], .{ .cached = &cache });
        try testing.expectEqualSlices(u8, plain[0..k], got[0..k]);
        try testing.expect(!std.mem.eql(u8, std.mem.asBytes(&before), std.mem.asBytes(&prng)));
    }
}

// Audit 2026-10-19 (O3-1): `SecretKey` keeps `p`, `q` in the order given, so
// `fromPrimes(p, q)` and `fromPrimes(q, p)` are the same public key with the
// CRT halves swapped. Until the cache compared `p` too, the second key was
// "served" the first one's pair (reduced mod the other prime) and every op
// failed the F3 check with `error.FaultDetected` until the 32-op refresh.
test "Blinding.cached: the same key with p and q swapped draws its own pair" {
    var sk_pq: SecretKey = undefined;
    try SecretKey.fromPrimes(&sk_pq, &kat2048.p, &kat2048.q, &kat2048.e);
    var sk_qp: SecretKey = undefined;
    try SecretKey.fromPrimes(&sk_qp, &kat2048.q, &kat2048.p, &kat2048.e);
    try testing.expect(MontParams.eql(&sk_pq.n_mont.m, &sk_qp.n_mont.m));

    var prng = std.Random.DefaultPrng.init(0xb11d_cace_0005);
    var cache = BlindingCache.init(prng.random());
    defer cache.deinit();
    const Sha256 = std.crypto.hash.sha2.Sha256;
    for (0..6) |i| {
        // pq, qp, qp, pq, pq, qp: every switch and every repeat.
        const sk: *const SecretKey = if ((i + 1) % 4 < 2) &sk_pq else &sk_qp;
        var sig: [max_modulus_len]u8 = undefined;
        const got = try signPkcs1v15Blinded(sk, Sha256, .{ .cached = &cache }, kat2048.msg, &sig);
        try testing.expectEqualSlices(u8, &kat2048.sig_sha256, got);
    }
    try testing.expect(MontParams.eql(&cache.p, &sk_qp.p_mont.m));
    cache.deinit();
    try testing.expect(std.mem.allEqual(u64, &cache.p, 0));
}

test "the blinded twins reach drawBlindingPair from the PUBLIC API, and produce identical output (audit R1)" {
    const sk = try kat2048.secretKey();
    const pk = try kat2048.publicKey();
    const k = byteLen(sk.n.bits());
    const Sha256 = std.crypto.hash.sha2.Sha256;

    // Two generators in the same state. Every case below drives one of them
    // through a `…Blinded` entry point and leaves the other untouched: if the
    // generator never reaches `drawBlindingPair`, the two states stay equal and
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
    const got_unblinded = try decryptOaep(&sk, Sha256, ct_slice, "", &plain_unblinded);
    const got_blinded = try decryptOaepBlinded(&sk, Sha256, .{ .csprng = used.random() }, ct_slice, "", &plain_blinded);
    try testing.expectEqualSlices(u8, secret, got_unblinded);
    try testing.expectEqualSlices(u8, secret, got_blinded);
    try drawnFrom(&used, &untouched);

    // The decoupled-hash twin is the one every other OAEP path funnels
    // through, so it gets its own case rather than riding on the wrapper.
    used = std.Random.DefaultPrng.init(seed);
    const got_h = try decryptOaepHBlinded(&sk, Sha256, Sha256, .{ .csprng = used.random() }, ct_slice, "", &plain_blinded);
    try testing.expectEqualSlices(u8, secret, got_h);
    try drawnFrom(&used, &untouched);

    // A blinded decrypt of a CORRUPTED ciphertext must still fail closed with
    // the same generic error — blinding must not become an oracle of its own.
    var bad: [max_modulus_len]u8 = undefined;
    @memcpy(bad[0..k], ct_slice);
    bad[k - 1] ^= 0x01;
    try testing.expectError(error.DecryptionError, decryptOaepBlinded(&sk, Sha256, .{ .csprng = used.random() }, bad[0..k], "", &plain_blinded));

    // (2) PKCS#1 v1.5 signing — deterministic by definition, so the emitted
    // signature must be byte-identical with the masking on. It is also the
    // published KAT value, so this doubles as an anchor check.
    used = std.Random.DefaultPrng.init(seed);
    var sig_plain: [max_modulus_len]u8 = undefined;
    var sig_blind: [max_modulus_len]u8 = undefined;
    const s_plain = try signPkcs1v15(&sk, Sha256, kat2048.msg, &sig_plain);
    const s_blind = try signPkcs1v15Blinded(&sk, Sha256, .{ .csprng = used.random() }, kat2048.msg, &sig_blind);
    try testing.expectEqualSlices(u8, &kat2048.sig_sha256, s_plain);
    try testing.expectEqualSlices(u8, s_plain, s_blind);
    try drawnFrom(&used, &untouched);

    // (3) The raw CRT primitive.
    used = std.Random.DefaultPrng.init(seed);
    var c_fixed: [256]u8 = @splat(0);
    c_fixed[255] = 0x2a;
    const m_plain = try rsadpCrt(256, c_fixed, &sk);
    const m_blind = try rsadpCrtBlinded(256, c_fixed, &sk, .{ .csprng = used.random() });
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

    const at0 = std.mem.find(u8, src, decl).?;
    const at1 = std.mem.findPos(u8, src, at0 + decl.len, decl).?;
    try testing.expect(std.mem.findPos(u8, src, at1 + decl.len, decl) == null); // exactly two

    // The requirement must sit in the doc block immediately BEFORE each
    // declaration. The second window starts at the END of the first
    // declaration, so `encryptOaep`'s own doc cannot satisfy `encryptOaepH`.
    try testing.expect(std.mem.find(u8, src[at0 -| 1600..at0], needle) != null);
    try testing.expect(std.mem.find(u8, src[at0 + decl.len .. at1], needle) != null);
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
    var m_wide = @as([max_modulus_len]u8, @splat(0));
    for (m_wide[max_modulus_len - k ..], 0..) |*b, i| b.* = @truncate(i *% 37 +% 11);
    m_wide[max_modulus_len - k] = 0; // keep the representative < n

    // Sign at max width (rsasp1 -> CRT private op) then verify at max width
    // (rsavp1 -> publicOp -> writeMontResult, the exact crash site): the
    // round-trip m -> s^d -> s^e must recover the original representative.
    const s_wide = try rsasp1(max_modulus_len, m_wide, &sk);
    // High bytes above the modulus width must be zero (big-endian left pad).
    try testing.expect(std.mem.allEqual(u8, s_wide[0 .. max_modulus_len - k], 0));
    const back = try rsavp1(max_modulus_len, s_wide, pk);
    try testing.expect(std.mem.allEqual(u8, back[0 .. max_modulus_len - k], 0));
    try testing.expectEqualSlices(u8, &m_wide, &back);

    // Cross-check: signing at the key's NATURAL width yields the identical
    // low-k bytes — the max-width path only prepends leading zeros.
    const s_narrow = try rsasp1(k, m_wide[max_modulus_len - k ..].*, &sk);
    try testing.expectEqualSlices(u8, s_wide[max_modulus_len - k ..], &s_narrow);
    // And rsaep at max width round-trips through rsadp (public/private widen).
    const c_wide = try rsaep(max_modulus_len, m_wide, pk);
    const dec = try rsadp(max_modulus_len, c_wide, &sk);
    try testing.expectEqualSlices(u8, &m_wide, &dec);
}

test "512-bit key: SHA-256 round-trips, SHA-512 encoding is too short" {
    var sk: SecretKey = undefined;
    try SecretKey.fromPrimes(&sk, &kat512.p, &kat512.q, &kat512.e);
    const pk = try PublicKey.fromBytes(&kat512.n, &kat512.e);
    var out: [max_modulus_len]u8 = undefined;

    const sig = try signPkcs1v15(&sk, std.crypto.hash.sha2.Sha256, "small key", &out);
    try testing.expectEqual(64, sig.len);
    try verifyPkcs1v15(pk, std.crypto.hash.sha2.Sha256, "small key", sig);

    // k = 64 < tLen(SHA-512) + 11 = 94 -> RFC 8017 §9.2 step 3.
    try testing.expectError(error.EncodedMessageTooShort, signPkcs1v15(&sk, std.crypto.hash.sha2.Sha512, "small key", &out));
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

    const m256 = try decryptOaep(&sk, sha2.Sha256, &kat2048_oaep.ct_sha256, "", &out);
    try testing.expectEqualStrings(kat2048_oaep.msg, m256);

    const m1 = try decryptOaep(&sk, std.crypto.hash.Sha1, &kat2048_oaep.ct_sha1, "", &out);
    try testing.expectEqualStrings(kat2048_oaep.msg, m1);

    const mlab = try decryptOaep(&sk, sha2.Sha256, &kat2048_oaep.ct_sha256_label, kat2048_oaep.label, &out);
    try testing.expectEqualStrings(kat2048_oaep.msg, mlab);
}

test "decryptOaepHNoFail: valid ciphertext -> ok=true, matches decryptOaep's KAT" {
    const sk = try kat2048.secretKey();
    const sha2 = std.crypto.hash.sha2;
    var out: [max_modulus_len]u8 = undefined;
    var raw: [max_modulus_len]u8 = undefined;

    const want = kat2048_oaep.msg.len;
    const r = try decryptOaepHNoFail(&sk, sha2.Sha256, sha2.Sha256, .none, &kat2048_oaep.ct_sha256, "", want, &out, &raw);
    try testing.expect(r.ok);
    try testing.expectEqualStrings(kat2048_oaep.msg, r.msg);
    try testing.expectEqual(@as(usize, 256), r.raw.len); // k for the 2048-bit key
}

test "decryptOaepHNoFail: padding failure -> ok=false, no error, raw still populated" {
    const sk = try kat2048.secretKey();
    const sha2 = std.crypto.hash.sha2;
    var out: [max_modulus_len]u8 = undefined;
    var raw: [max_modulus_len]u8 = undefined;

    // A single flipped byte in a valid ciphertext corrupts the RSA private
    // op's output enough that OAEP padding cannot validate -- exactly the
    // "attacker-crafted garbage" shape rsaOaepUnwrap must tolerate without
    // erroring.
    var corrupt = kat2048_oaep.ct_sha256;
    corrupt[100] ^= 0x01;
    const r = try decryptOaepHNoFail(&sk, sha2.Sha256, sha2.Sha256, .none, &corrupt, "", kat2048_oaep.msg.len, &out, &raw);
    try testing.expect(!r.ok);
    try testing.expectEqual(@as(usize, 0), r.msg.len);
    // `raw` is populated either way -- it is the caller's decoy-derivation
    // input, not conditional on validity.
    try testing.expect(!std.mem.allEqual(u8, r.raw, 0));

    // Wrong label: same padding-failure shape, same non-error contract.
    const r2 = try decryptOaepHNoFail(&sk, sha2.Sha256, sha2.Sha256, .none, &kat2048_oaep.ct_sha256, "wrong-label", kat2048_oaep.msg.len, &out, &raw);
    try testing.expect(!r2.ok);
}

test "decryptOaepHNoFail: want-length mismatch is folded into validity, not a separate check" {
    // A perfectly valid ciphertext whose recovered message length does NOT
    // equal the caller's `want` must report ok=false, exactly like a
    // corrupted padding -- see the doc comment on why this is folded into
    // the SAME branch-free decision rather than compared by the caller
    // after the fact (the 97%-accuracy PKCS#1 v1.5 precedent this mirrors).
    const sk = try kat2048.secretKey();
    const sha2 = std.crypto.hash.sha2;
    var out: [max_modulus_len]u8 = undefined;
    var raw: [max_modulus_len]u8 = undefined;

    const r = try decryptOaepHNoFail(&sk, sha2.Sha256, sha2.Sha256, .none, &kat2048_oaep.ct_sha256, "", kat2048_oaep.msg.len + 1, &out, &raw);
    try testing.expect(!r.ok);

    const r2 = try decryptOaepHNoFail(&sk, sha2.Sha256, sha2.Sha256, .none, &kat2048_oaep.ct_sha256, "", kat2048_oaep.msg.len - 1, &out, &raw);
    try testing.expect(!r2.ok);

    // The exact length still succeeds (sanity: this isn't just "always false").
    const r3 = try decryptOaepHNoFail(&sk, sha2.Sha256, sha2.Sha256, .none, &kat2048_oaep.ct_sha256, "", kat2048_oaep.msg.len, &out, &raw);
    try testing.expect(r3.ok);
}

test "decryptOaepHNoFail: decoupled hash (LabelHash != MgfHash) round-trips too" {
    const sk = try kat2048.secretKey();
    const pk = try kat2048.publicKey();
    const Sha256 = std.crypto.hash.sha2.Sha256;
    const Sha1 = std.crypto.hash.Sha1;
    var prng = std.Random.DefaultPrng.init(0x6f6165705f68e); // deterministic: tests only
    const random = prng.random();
    var ct: [max_modulus_len]u8 = undefined;
    var out: [max_modulus_len]u8 = undefined;
    var raw: [max_modulus_len]u8 = undefined;

    const msg = "decoupled hash, no-fail variant";
    const c = try encryptOaepH(pk, Sha256, Sha1, random, msg, "xmlenc-label", &ct);
    const r = try decryptOaepHNoFail(&sk, Sha256, Sha1, .none, c, "xmlenc-label", msg.len, &out, &raw);
    try testing.expect(r.ok);
    try testing.expectEqualStrings(msg, r.msg);
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
                const m = try decryptOaep(&sk, Hash, c, label, &pt);
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
            const m = try decryptOaepH(&sk, Sha256, Sha1, c, label, &pt);
            try testing.expectEqualSlices(u8, msg, m);

            // The mismatched-hash ciphertext is a genuinely different padding:
            // the coupled (equal-hash) decrypt cannot decode it under either
            // the digest hash or the MGF hash.
            try testing.expectError(error.DecryptionError, decryptOaep(&sk, Sha256, c, label, &pt));
            try testing.expectError(error.DecryptionError, decryptOaep(&sk, Sha1, c, label, &pt));
        }
    }

    // Constant-time posture preserved: a wrong label or a corrupted ciphertext
    // still collapses to the single generic error (never a distinct one).
    const secret = try encryptOaepH(pk, Sha256, Sha1, random, "top secret", "right", &ct);
    try testing.expectError(error.DecryptionError, decryptOaepH(&sk, Sha256, Sha1, secret, "wrong", &pt));
    var corrupt: [256]u8 = undefined;
    @memcpy(&corrupt, secret);
    corrupt[100] ^= 0x40;
    try testing.expectError(error.DecryptionError, decryptOaepH(&sk, Sha256, Sha1, &corrupt, "right", &pt));

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
    try testing.expectError(error.DecryptionError, decryptOaep(&sk, Sha256, &bad, "", &out));
    bad = kat2048_oaep.ct_sha256;
    bad[255] ^= 0x80;
    try testing.expectError(error.DecryptionError, decryptOaep(&sk, Sha256, &bad, "", &out));

    // Label mismatch in both directions — while the same ciphertexts decrypt
    // fine under the correct label (previous test).
    try testing.expectError(error.DecryptionError, decryptOaep(&sk, Sha256, &kat2048_oaep.ct_sha256, kat2048_oaep.label, &out));
    try testing.expectError(error.DecryptionError, decryptOaep(&sk, Sha256, &kat2048_oaep.ct_sha256_label, "", &out));

    // Wrong hash function.
    try testing.expectError(error.DecryptionError, decryptOaep(&sk, Sha256, &kat2048_oaep.ct_sha1, "", &out));

    // Wrong ciphertext length (RFC 8017 §7.1.2 step 1.b).
    try testing.expectError(error.DecryptionError, decryptOaep(&sk, Sha256, kat2048_oaep.ct_sha256[0..255], "", &out));
    const long_ct = kat2048_oaep.ct_sha256 ++ [_]u8{0};
    try testing.expectError(error.DecryptionError, decryptOaep(&sk, Sha256, &long_ct, "", &out));

    // Undersized output buffer (public-length check, distinct error is fine).
    var small: [189]u8 = undefined; // max mLen for k=256/SHA-256 is 190
    try testing.expectError(error.BufferTooSmall, decryptOaep(&sk, Sha256, &kat2048_oaep.ct_sha256, "", &small));
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
    try testing.expectError(error.DecryptionError, decryptOaep(&sk, Sha256, &ct_bad_y, "", &out));

    // Control: the identical EM with Y = 0x00 decrypts — proving the
    // rejection above was the Y check and nothing else.
    em[0] = 0x00;
    const ct_ok = try rsaep(256, em, pk);
    try testing.expectEqualStrings("msg", try decryptOaep(&sk, Sha256, &ct_ok, "", &out));
}

test "encryptOaep rejects oversize messages and undersized buffers/keys" {
    const pk = try kat2048.publicKey();
    const Sha256 = std.crypto.hash.sha2.Sha256;
    var prng = std.Random.DefaultPrng.init(1);
    const random = prng.random();
    var ct: [max_modulus_len]u8 = undefined;

    // Max mLen for k=256/SHA-256 is 190: 191 is rejected, 190 encrypts.
    const big = @as([191]u8, @splat(0xaa));
    try testing.expectError(error.MessageTooLong, encryptOaep(pk, Sha256, random, &big, "", &ct));
    _ = try encryptOaep(pk, Sha256, random, big[0..190], "", &ct);

    // Output buffer shorter than the modulus.
    var small_out: [255]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, encryptOaep(pk, Sha256, random, "m", "", &small_out));

    // 512-bit key: k = 64 < 2*32 + 2 = 66 -> SHA-256 OAEP can never fit.
    const pk512 = try PublicKey.fromBytes(&kat512.n, &kat512.e);
    try testing.expectError(error.MessageTooLong, encryptOaep(pk512, Sha256, random, "", "", &ct));

    // SHA-1 on the 512-bit key fits up to 64 - 2*20 - 2 = 22 bytes.
    var sk512: SecretKey = undefined;
    try SecretKey.fromPrimes(&sk512, &kat512.p, &kat512.q, &kat512.e);
    var pt: [max_modulus_len]u8 = undefined;
    const c = try encryptOaep(pk512, std.crypto.hash.Sha1, random, "22-byte msg for sha1..", "", &ct);
    try testing.expectEqual(64, c.len);
    try testing.expectEqualStrings("22-byte msg for sha1..", try decryptOaep(&sk512, std.crypto.hash.Sha1, c, "", &pt));
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
    const tiny_n = @as([32]u8, @splat(0xff));
    try testing.expectError(error.InvalidPublicKey, PublicKey.fromBytes(&tiny_n, &kat2048.e));
    // Modulus above max_modulus_bits.
    const huge_n = @as([max_modulus_len + 1]u8, @splat(0xff));
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
    const sig = try signPss(&sk, std.crypto.hash.sha2.Sha256, prng.random(), kat2048_pss.msg, 0, &out);
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
            const sig = try signPss(&sk, Hash, random, "fresh PSS round-trip message", s_len, &out);
            try testing.expectEqual(256, sig.len);
            try verifyPss(pk, Hash, "fresh PSS round-trip message", sig, s_len);
            try testing.expectError(error.SignatureVerificationFailed, verifyPss(pk, Hash, "some other message", sig, s_len));
        }
    }

    // PSS with sLen > 0 is randomized: two signatures over the same message
    // differ (fresh salt each call) yet both verify.
    var out2: [max_modulus_len]u8 = undefined;
    const s1 = try signPss(&sk, std.crypto.hash.sha2.Sha256, random, "same message", 32, &out);
    const s2 = try signPss(&sk, std.crypto.hash.sha2.Sha256, random, "same message", 32, &out2);
    try testing.expect(!std.mem.eql(u8, s1, s2));
    try verifyPss(pk, std.crypto.hash.sha2.Sha256, "same message", s1, 32);
    try verifyPss(pk, std.crypto.hash.sha2.Sha256, "same message", s2, 32);
}

test "signPss/verifyPss round-trip on the 512-bit key (top-bit clearing path)" {
    // modBits = 512 -> emBits = 511: emLen == k and exactly one leading bit
    // of maskedDB is cleared/checked, exercising §9.1.1 step 11 / §9.1.2
    // step 6 with a nontrivial mask.
    var sk: SecretKey = undefined;
    try SecretKey.fromPrimes(&sk, &kat512.p, &kat512.q, &kat512.e);
    const pk = try PublicKey.fromBytes(&kat512.n, &kat512.e);
    var prng = std.Random.DefaultPrng.init(0x353132626974);
    const random = prng.random();
    var out: [max_modulus_len]u8 = undefined;

    // Max sLen for k=64/SHA-256: emLen - hLen - 2 = 64 - 32 - 2 = 30.
    for ([_]usize{ 0, 20, 30 }) |s_len| {
        const sig = try signPss(&sk, std.crypto.hash.sha2.Sha256, random, "small key", s_len, &out);
        try testing.expectEqual(64, sig.len);
        try verifyPss(pk, std.crypto.hash.sha2.Sha256, "small key", sig, s_len);
    }

    // sLen = 31 exceeds the §9.1.1 step 3 bound.
    try testing.expectError(error.EncodedMessageTooShort, signPss(&sk, std.crypto.hash.sha2.Sha256, random, "small key", 31, &out));
    // SHA-512 cannot fit at all: emLen = 64 < hLen + 2 = 66.
    try testing.expectError(error.EncodedMessageTooShort, signPss(&sk, std.crypto.hash.sha2.Sha512, random, "small key", 0, &out));
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
    var salt = @as([32]u8, @splat(0));
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
    const sig_ok = try rsasp1(256, em, &sk);
    try verifyPss(pk, Sha256, msg, &sig_ok, 32);

    // Trailer != 0xbc (§9.1.2 step 4).
    var em_bad = em;
    em_bad[255] = 0xcc;
    const sig_bad_trailer = try rsasp1(256, em_bad, &sk);
    try testing.expectError(error.SignatureVerificationFailed, verifyPss(pk, Sha256, msg, &sig_bad_trailer, 32));

    // Nonzero leftmost bit of maskedDB (§9.1.2 step 6). Still < n (n's top
    // byte is 0xa2), so only the top-bit check can reject it.
    em_bad = em;
    em_bad[0] |= 0x80;
    const sig_bad_top = try rsasp1(256, em_bad, &sk);
    try testing.expectError(error.SignatureVerificationFailed, verifyPss(pk, Sha256, msg, &sig_bad_top, 32));
}

test "signPss rejects an undersized output buffer" {
    const sk = try kat2048.secretKey();
    var prng = std.Random.DefaultPrng.init(7);
    var small: [255]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, signPss(&sk, std.crypto.hash.sha2.Sha256, prng.random(), "m", 32, &small));
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

test "VerifyKey: same accept/reject as PublicKey on the KATs, from bytes and from DER" {
    const sha2 = std.crypto.hash.sha2;
    const pk = try kat2048.publicKey();
    for ([_]VerifyKey{
        try VerifyKey.fromBytes(&kat2048.n, &kat2048.e),
        try VerifyKey.fromDer(&kat2048_der.pub_spki),
        try VerifyKey.fromDer(&kat2048_der.pub_pkcs1),
    }) |vk| {
        try testing.expectEqual(@as(usize, 2048), vk.bits());
        try testing.expectEqualSlices(u64, &pk.n_mont.m, &vk.mp.m);
        try testing.expectEqualSlices(u64, &pk.n_mont.r2, &vk.mp.r2);
        try vk.verifyPkcs1v15(sha2.Sha256, kat2048.msg, &kat2048.sig_sha256);
        try vk.verifyPkcs1v15(sha2.Sha384, kat2048.msg, &kat2048.sig_sha384);
        try vk.verifyPkcs1v15(sha2.Sha512, kat2048.msg, &kat2048.sig_sha512);
        try testing.expectError(error.SignatureVerificationFailed, vk.verifyPkcs1v15(sha2.Sha384, kat2048.msg, &kat2048.sig_sha256));
        var bad = kat2048.sig_sha256;
        bad[100] ^= 4;
        try testing.expectError(error.SignatureVerificationFailed, vk.verifyPkcs1v15(sha2.Sha256, kat2048.msg, &bad));
    }
    // PSS through both, on a fresh signature.
    const sk = try kat2048.secretKey();
    var prng = std.Random.DefaultPrng.init(0x7E41);
    var buf: [256]u8 = undefined;
    const sig = try signPss(&sk, sha2.Sha256, prng.random(), "verify key pss", 32, &buf);
    const vk = try VerifyKey.fromDer(&kat2048_der.pub_spki);
    try verifyPss(pk, sha2.Sha256, "verify key pss", sig, 32);
    try vk.verifyPss(sha2.Sha256, "verify key pss", sig, 32);
    try testing.expectError(error.SignatureVerificationFailed, vk.verifyPss(sha2.Sha256, "verify key pss", sig, 31));
    try testing.expectError(error.SignatureVerificationFailed, vk.verifyPss(sha2.Sha256, "verify key PSS", sig, 32));
}

test "VerifyKey: a representative s ≥ n is refused, s = n − 1 reaches the padding check" {
    // `publicOpMont` takes the range check from montint where `publicOp`
    // took it from `ff`; the boundary is where the two could disagree.
    const Sha256 = std.crypto.hash.sha2.Sha256;
    const pk = try kat2048.publicKey();
    const vk = try VerifyKey.fromBytes(&kat2048.n, &kat2048.e);
    var out: [256]u8 = undefined;
    var s = kat2048.n;
    try testing.expectError(error.MessageRepresentativeOutOfRange, publicOp(pk, &s, &out));
    try testing.expectError(error.MessageRepresentativeOutOfRange, publicOpMont(&vk.mp, vk.e, &s, &out));
    s[255] +%= 2; // n + 2 (n is odd, so no carry out of the last byte)
    try testing.expectError(error.MessageRepresentativeOutOfRange, publicOpMont(&vk.mp, vk.e, &s, &out));
    s = kat2048.n;
    s[255] -= 1; // n − 1 ≡ −1: (−1)^e = −1 = n − 1
    try publicOpMont(&vk.mp, vk.e, &s, &out);
    try testing.expectEqualSlices(u8, &s, &out);
    var out_ff: [256]u8 = undefined;
    try publicOp(pk, &s, &out_ff);
    try testing.expectEqualSlices(u8, &out_ff, &out);
    try testing.expectError(error.SignatureVerificationFailed, vk.verifyPkcs1v15(Sha256, kat2048.msg, &s));
}

test "VerifyKey.fromBytes accepts and refuses exactly what PublicKey.fromBytes does" {
    // A seeded differential over the shapes the checks are about: modulus
    // length around 512 and 4096 bits, even moduli, leading zeros; exponent
    // 0…5 bytes, even, 1, leading zeros. `PublicKey.fromBytes` validates
    // through `std.crypto.ff`, `VerifyKey.fromBytes` through montint.
    var prng = std.Random.DefaultPrng.init(0xD1FF_2026);
    const rnd = prng.random();
    var n_buf: [max_modulus_len + 3]u8 = undefined;
    var e_buf: [6]u8 = undefined;
    var accepted: usize = 0;
    var refused: usize = 0;
    const n_lens = [_]usize{ 0, 1, 62, 63, 64, 65, 256, 511, 512, 513, 514 };
    for (0..1500) |i| {
        const n_len = n_lens[i % n_lens.len];
        const n = n_buf[0..n_len];
        rnd.bytes(n);
        const lead = rnd.uintLessThan(usize, 4);
        if (n_len > 0) {
            for (n[0..@min(lead, n_len)]) |*b| b.* = 0;
            if (rnd.boolean()) n[n_len - 1] |= 1 else if (rnd.uintLessThan(u8, 4) == 0) n[n_len - 1] &= 0xfe;
            if (n_len > lead and rnd.boolean()) n[lead] |= 0x80;
        }
        const e_len = rnd.uintLessThan(usize, 6);
        const e = e_buf[0..e_len];
        rnd.bytes(e);
        switch (rnd.uintLessThan(u8, 6)) {
            0 => if (e_len > 0) {
                @memset(e, 0);
                e[e_len - 1] = rnd.uintLessThan(u8, 4); // 0, 1, 2, 3
            },
            1 => if (e_len > 0) {
                e[0] = 0; // leading zero
            },
            2 => if (e_len > 0) {
                e[e_len - 1] &= 0xfe; // even
            },
            else => if (e_len > 0) {
                e[e_len - 1] |= 1;
            },
        }
        const want = PublicKey.fromBytes(n, e);
        const got = VerifyKey.fromBytes(n, e);
        if (want) |w| {
            const g = got catch |err| {
                std.debug.print("case {d}: PublicKey accepts, VerifyKey says {t}\n", .{ i, err });
                return error.TestUnexpectedResult;
            };
            try testing.expectEqualSlices(u64, &w.n_mont.m, &g.mp.m);
            try testing.expectEqual(w.publicExponent(), g.e);
            accepted += 1;
        } else |_| {
            if (got) |_| {
                std.debug.print("case {d}: PublicKey refuses, VerifyKey accepts\n", .{i});
                return error.TestUnexpectedResult;
            } else |_| {}
            refused += 1;
        }
    }
    // Both verdicts must actually occur, or the differential proves nothing.
    try testing.expect(accepted >= 100);
    try testing.expect(refused >= 100);
}

test "PublicKey.fromPem parses PUBLIC KEY and RSA PUBLIC KEY PEM, matches kat2048" {
    const from_spki = try PublicKey.fromPem(kat2048_pem.pub_spki);
    try expectMatchesKat2048PublicKey(from_spki);

    const from_pkcs1 = try PublicKey.fromPem(kat2048_pem.pub_pkcs1);
    try expectMatchesKat2048PublicKey(from_pkcs1);
    try verifyPkcs1v15(from_pkcs1, std.crypto.hash.sha2.Sha256, kat2048.msg, &kat2048.sig_sha256);
}

test "SecretKey.fromDer parses bare PKCS#1 RSAPrivateKey DER, matches kat2048 and signs" {
    var sk: SecretKey = undefined;
    try SecretKey.fromDer(&sk, &kat2048_der.priv_pkcs1);
    try expectMatchesKat2048SecretKey(sk);

    var out: [max_modulus_len]u8 = undefined;
    const sig = try signPkcs1v15(&sk, std.crypto.hash.sha2.Sha256, kat2048.msg, &out);
    try testing.expectEqualSlices(u8, &kat2048.sig_sha256, sig); // deterministic -> byte-exact
}

test "fromPkcs8 parses PKCS#8 PrivateKeyInfo DER, matches kat2048 and signs" {
    var sk: SecretKey = undefined;
    try fromPkcs8(&sk, &kat2048_der.priv_pkcs8);
    try expectMatchesKat2048SecretKey(sk);

    var out: [max_modulus_len]u8 = undefined;
    const sig = try signPkcs1v15(&sk, std.crypto.hash.sha2.Sha256, kat2048.msg, &out);
    try testing.expectEqualSlices(u8, &kat2048.sig_sha256, sig);
}

test "SecretKey.fromPem parses RSA PRIVATE KEY and PRIVATE KEY PEM, matches kat2048" {
    var from_pkcs1: SecretKey = undefined;
    try SecretKey.fromPem(&from_pkcs1, kat2048_pem.priv_pkcs1);
    try expectMatchesKat2048SecretKey(from_pkcs1);

    var from_pkcs8: SecretKey = undefined;
    try SecretKey.fromPem(&from_pkcs8, kat2048_pem.priv_pkcs8);
    try expectMatchesKat2048SecretKey(from_pkcs8);

    var out: [max_modulus_len]u8 = undefined;
    const sig = try signPkcs1v15(&from_pkcs1, std.crypto.hash.sha2.Sha256, kat2048.msg, &out);
    try verifyPkcs1v15(try PublicKey.fromPem(kat2048_pem.pub_spki), std.crypto.hash.sha2.Sha256, kat2048.msg, sig);
}

// ── R1 (2026-10-14): key serialisation, byte-exact against OpenSSL ──────────
//
// The kat2048 fixtures above are OpenSSL 3 output (`openssl rsa -traditional`,
// `pkcs8 -topk8 -nocrypt`, `-pubout`, `-RSAPublicKey_out`, DER and PEM): a
// parsed fixture written back must give exactly those bytes.

test "marshal: parse -> write reproduces the OpenSSL DER and PEM fixtures byte for byte" {
    var sk: SecretKey = undefined;
    try SecretKey.fromDer(&sk, &kat2048_der.priv_pkcs1);
    defer sk.deinit();
    const pk = sk.publicKey();
    const vk = pk.verifyKey();
    var buf: [max_private_pem_len]u8 = undefined;

    try testing.expectEqualSlices(u8, &kat2048_der.priv_pkcs1, try sk.toPkcs1Der(&buf));
    try testing.expectEqualSlices(u8, &kat2048_der.priv_pkcs8, try sk.toPkcs8Der(&buf));
    try testing.expectEqualSlices(u8, kat2048_pem.priv_pkcs1, try sk.toPem(.pkcs1, &buf));
    try testing.expectEqualSlices(u8, kat2048_pem.priv_pkcs8, try sk.toPem(.pkcs8, &buf));
    for ([_]PublicKey{ pk, try PublicKey.fromDer(&kat2048_der.pub_pkcs1) }) |p| {
        try testing.expectEqualSlices(u8, &kat2048_der.pub_pkcs1, try p.toPkcs1Der(&buf));
        try testing.expectEqualSlices(u8, &kat2048_der.pub_spki, try p.toSpkiDer(&buf));
        try testing.expectEqualSlices(u8, kat2048_pem.pub_pkcs1, try p.toPem(.pkcs1, &buf));
        try testing.expectEqualSlices(u8, kat2048_pem.pub_spki, try p.toPem(.spki, &buf));
    }
    try testing.expectEqualSlices(u8, &kat2048_der.pub_pkcs1, try vk.toPkcs1Der(&buf));
    try testing.expectEqualSlices(u8, &kat2048_der.pub_spki, try vk.toSpkiDer(&buf));
    try testing.expectEqualSlices(u8, kat2048_pem.pub_spki, try vk.toPem(.spki, &buf));

    try testing.expect(pk.equal(&try PublicKey.fromPem(kat2048_pem.pub_spki)));
    try testing.expectEqual(2048, pk.bits());
    try testing.expectEqual(256, pk.size());
}

test "marshal: an exact-size buffer fits, one byte less is BufferTooSmall with out zeroed" {
    var sk: SecretKey = undefined;
    try SecretKey.fromDer(&sk, &kat2048_der.priv_pkcs1);
    defer sk.deinit();
    const pk = sk.publicKey();
    var buf: [max_private_pem_len]u8 = undefined;
    const Case = struct { want: usize, run: *const fn (*const SecretKey, *const PublicKey, []u8) MarshalError![]u8 };
    const cases = [_]Case{
        .{ .want = kat2048_der.priv_pkcs1.len, .run = struct {
            fn f(s: *const SecretKey, _: *const PublicKey, o: []u8) MarshalError![]u8 {
                return s.toPkcs1Der(o);
            }
        }.f },
        .{ .want = kat2048_der.priv_pkcs8.len, .run = struct {
            fn f(s: *const SecretKey, _: *const PublicKey, o: []u8) MarshalError![]u8 {
                return s.toPkcs8Der(o);
            }
        }.f },
        .{ .want = kat2048_pem.priv_pkcs8.len, .run = struct {
            fn f(s: *const SecretKey, _: *const PublicKey, o: []u8) MarshalError![]u8 {
                return s.toPem(.pkcs8, o);
            }
        }.f },
        .{ .want = kat2048_der.pub_spki.len, .run = struct {
            fn f(_: *const SecretKey, p: *const PublicKey, o: []u8) MarshalError![]u8 {
                return p.toSpkiDer(o);
            }
        }.f },
        .{ .want = kat2048_pem.pub_pkcs1.len, .run = struct {
            fn f(_: *const SecretKey, p: *const PublicKey, o: []u8) MarshalError![]u8 {
                return p.toPem(.pkcs1, o);
            }
        }.f },
    };
    for (cases) |c| {
        try testing.expectEqual(c.want, (try c.run(&sk, &pk, buf[0..c.want])).len);
        @memset(&buf, 0xaa);
        try testing.expectError(error.BufferTooSmall, c.run(&sk, &pk, buf[0 .. c.want - 1]));
        for (buf[0 .. c.want - 1]) |b| try testing.expectEqual(0, b);
    }
    // The advertised maxima hold for the largest keys the module takes.
    try testing.expect(max_pkcs1_private_der_len >= kat2048_der.priv_pkcs1.len);
    try testing.expect(max_public_pem_len >= kat2048_pem.pub_pkcs1.len);
}

/// The nine INTEGER fields of a PKCS#1 `RSAPrivateKey` DER (version, n, e,
/// d, p, q, dP, dQ, qInv) as content ranges.
fn pkcs1Fields(der: []const u8) ![9]Asn1.Element {
    const top = try derTopSequence(der);
    var f: [9]Asn1.Element = undefined;
    var at = top.slice.start;
    for (&f) |*e| {
        e.* = try derChild(der, at, top.slice.end, .integer, false);
        at = e.slice.end;
    }
    return f;
}

test "F1: a wrong on-disk n, d, dP, dQ or qInv is InvalidPrivateKey (was loaded silently)" {
    for ([_]usize{ 1, 3, 6, 7, 8 }) |field| { // n, d, dP, dQ, qInv
        var der = kat2048_der.priv_pkcs1;
        const f = try pkcs1Fields(&der);
        der[f[field].slice.end - 1] ^= 0x02; // a low bit: length and sign unchanged
        try testing.expectError(error.InvalidPrivateKey, SecretKey.fromDer(&test_sk_out, &der));
        var pkcs8: [kat2048_der.priv_pkcs8.len]u8 = kat2048_der.priv_pkcs8;
        @memcpy(pkcs8[pkcs8.len - der.len ..], &der);
        try testing.expectError(error.InvalidPrivateKey, fromPkcs8(&test_sk_out, &pkcs8));
    }
}

test "F1: a φ-reduced (or any other valid) d is accepted and kept, so it round-trips" {
    // d' = d + λ(n) is another valid private exponent (< 2λ ≤ φ < n); keys
    // written by tools that reduce mod φ carry such a d.
    var sk: SecretKey = undefined;
    try SecretKey.fromDer(&sk, &kat2048_der.priv_pkcs1);
    defer sk.deinit();
    var mem: [64 * 1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&mem);
    const gpa = fba.allocator();
    var p1 = try bigFromBytes(gpa, &kat2048.p);
    try p1.addScalar(&p1, -1);
    var q1 = try bigFromBytes(gpa, &kat2048.q);
    try q1.addScalar(&q1, -1);
    var g = try newBig(gpa);
    try g.gcd(&p1, &q1);
    var pq1 = try newBig(gpa);
    try pq1.mul(&p1, &q1);
    var lam = try newBig(gpa);
    var rem = try newBig(gpa);
    try lam.divFloor(&rem, &pq1, &g);
    var d2 = try bigFromBytes(gpa, &kat2048.d);
    try d2.add(&d2, &lam);
    var d2_bytes: [256]u8 = undefined;
    d2.toConst().writeTwosComplement(&d2_bytes, .big);
    sk.d = try Fe.fromBytes(sk.n, &d2_bytes, .big);

    var buf: [max_pkcs1_private_der_len]u8 = undefined;
    const der = try sk.toPkcs1Der(&buf);
    var back: SecretKey = undefined;
    try SecretKey.fromDer(&back, der);
    defer back.deinit();
    var got: [256]u8 = undefined;
    try back.d.toBytes(&got, .big);
    try testing.expectEqualSlices(u8, &d2_bytes, &got);
    var buf2: [max_pkcs1_private_der_len]u8 = undefined;
    try testing.expectEqualSlices(u8, der, try back.toPkcs1Der(&buf2));
    // The non-CRT path uses d: still the right key.
    const m = @as([255]u8, @splat(0)) ++ [_]u8{42};
    try testing.expectEqualSlices(u8, &try rsadp(256, m, &sk), &try rsadp(256, m, &back));
}

const kat2048_pbes2 = struct {
    const password = "zig-libs-pw";
    // openssl pkcs8 -topk8 -in kat2048.pem -v2 aes-256-cbc -v2prf hmacWithSHA256 -iter 2048 -passout pass:zig-libs-pw -outform DER
    const aes256_sha256 = hexLit("30820535305f06092a864886f70d01050d3052303106092a864886f70d01050c30240410015751a57cfbdf7110334c0a5e87a4c602020800300c06082a864886f70d02090500301d060960864801650304012a04103e32dee7e1f40b670ddd313123517ed7048204d02ce9ac185e8ffbf2f01aea59cbab4dbd27b525f7f85cf9f2a220cd8d6e4d4cf207ccad9b8d022b575f87187b803b6967cb0ab82595d1315ae095e2d0867347b16ea74f0c00c0532852d63facee250d523a17879072881481d83727681860743d7094f70d981c391b4bf4fa0a34e59710e87bf34325a43a8072918d45af1a0297e675820a1878a160e2614ff9db6bc1109ebbeb3a73f68407d3a5d59d80587044b4d6494bc5d3eb6132b086a6ca85ca8d6f96cdfc78e9c3df9e3d2b66febfab38f81f485abf1528b9e7f27a481a191f97c1773108f03c5792cd07d1c84a399ad1d9943e7881b24b5249575ea9d26d5e16be05a99c1ad6f418bd337d6deac9b45a5a58795974ec5c0f039bd647f75d0b197876b2cdff8191adbb496db8bec0ebfe23af4fece8ec07071fbac208eff46e0688f1491d397955b92ca247372659bdcef093e9462f2149df208a24652d274d7c35a9c3e9590dd90850ec71ecff8d884cb8896603e544e5a6b800b3897fd712a3a8bf9fc846cd9816095127c2670c07094e50366f2d702f6cd38ce6cda5425812cd3fd891b6a55454247830390c7cc8fb69677a67412a3f76d21b8b6106b1c857ffd4bbabe2530116f3d35949e04f2ba320ade576e2bd0273cca2eb109ab72a9e9a8fcfcbe81ff7dcc78de347ffd6fb1c379d2a8a7c8abad07eb2b35add731011ab3d453b350a3dc5f55442415bedd4666347a6f4438d6fc9e4b44db56c656dfb029deeb7d0b097641fd8b475f0f6051f13b310addcc2664c10c2ecd352d64a1358044297ab82306ecec7c75dc8f40025b8387b80d44aaaa502342f67fce6c0ba3ae8656178eb938e90dab64d951893afb6441eb55dcb88cd86ab7a2fa5459ae952780e0e7bd5d1ac324fba518af013e45fc4360c39fd5a8b3e9dcb11211fdad89df71174e01ccbfe8c4f64a0036ceb7c09383fac225a05e9fd95a5d34c863ed5bdc58399b8be5114915ad08414ffa2d54d9df32950463d934ed66fc4069d56a16b24916baea8d946513c650507d5f0945899f7182138e4c2e863f5b52ac41cb1acc424ffc09b41ecb266a921797039cb9180ee67485d70bfc220f60fb2ffcaeaacf4e18dca6f67aa7f2d6fe2897b3ffbe034a66420482e586d04b9bf68a3863f599c2548a73eb725253bce7f5ad4f0bff402b5579b31c5077f277f352c8ad6234615798bfd3b84d570dec16cb9dcbd563d8468fef4bea77d7762057c22b97d44348d7db09891a61414ed26b2d6eddab743051243ccb5fd39fcca7da83038a4f9eed9a31623624856933ac0261855c09d42d81094e33c124576fad874731e769b800540c6fb6a7da1557af6a6289898ed18d8c17b1bbe3b2d705266cc431bb32ef85038e5e312b77b3553b106c44fdbd18a94d1d0df7452e73fb0b3e6a5780ffa1b9e1e81c7a5b3f5a8949267301d8d72b77613e16d7d1adbed6b21e1c31134cf954126cea7c3844ab5569ac1300bb3f2eddc4dd837ac6efb60f14d8185bb30494c5fe42d97d7a26faf2b3806d66d174c1062673179320707cd8e420913757bd0953c10903d45f3faff034e5a589f2d5ed9dda03e49d7c14a48d636c293d81cbc12c2b9cc3dd406b938377c92d9ea9b86a894b8d5a4f396cdc318063e68de75e3536e355946de76efe594527e59dde98ef12560f7966fd6e95eba02565755da64c88e8a9499f5899ce3f6f77951275cfeffe699bdb250d077799138a033b296af");
    // ... -v2 aes-128-cbc -v2prf hmacWithSHA1 -iter 1000 (PRF omitted: DER DEFAULT)
    const aes128_sha1 = hexLit("30820527305106092a864886f70d01050d3044302306092a864886f70d01050c301604107a6f931b7eed66e632527dc88d01e965020203e8301d0609608648016503040102041047f0a15f93d380ad0568a014743ccbde048204d096d95f225d456078cb1fb48e456fa195c4453fcf6f816614302f1cf44e13d9599ab51e4ccabdcf3262458abc6b4e64ab9490cc60de2933afa3eba85f638235bbcb76dcb5c83cc95a0ab82594ae226b438e25b0b0795e98dbfd59e014eeaa08aeb061baa51a9fe3e9799b8ff914fd9d50b2085821efd63039479f5c37e2ee07b4362bb654a12a23edcf5fae74a92e9e10bf4af6f55ae71b5f440ce11113d762061c7f7acbbfcb4fcbb4abbce6d422b1dd06bc476f9065e4e043eea203e116dac60fb9aaf7305bbea592533d3c6afc49ed068ceeabe0f7e7bf4e79fdb42021abc692e112f4eb3e187ebd989f99c887d34530faee70eccddf6ecf01ebacab297f29c07f8b8ea32be3f074c62b458e2a90d1c3304af55b8091c53b67cc03735a2b0029f7c86439bdb8ceb7b3a5f9ce4422ac7453ff265cfd1152543db64da9f7e8ea4f767473628ce12d308ac336c1ab28627ff88952123392ecc632fae627c92ad805c1554f7a41b10799093373e0b1df8ee90c1a5a70f04d49a85117ba5defb392b653dfd059a6ad2f60eb5b4236f83aced6254f187259c1f5df1f3ceb7f5a436bb23ea9ecb27b8848bf14f50af5b0b1c32e865999b9a9c3a86e3ca0c21ccea72b538075f0f6465146d9bbe9838d7abfcb57be805c1f0fee0a64940199bb594ea33ae0c90b7ee4109f21c6fa608304780ff34a4aeac5fa20ca796d837c98a3efde169679f6c809b46dac7160e7771a49ebb81df0a2bd6ae868151853158e867b30083831ae479e7f0aa50093b26a265188723803a87ea3bc08a18c646f69d5a65de5af1d0dfa7d4fd0a624c93aebe15d4b427b9128f929edbb50be2c8a6001d96ad626bdafa17291c74c8cc13d50c5939525c6722a59c8d5d1895b9787fb035e8231c5555a594b18709d3520725ca890209d1505529690df80b72eef69b3b23614f1846460bda2b50716ff670a8515bf8a5c4fd5f0a90e6b34a58d0fb2259c4ded644dc8fe4fc234ab7cb84cc4f9e5fe3b00d923711823ce5c243b5309a2d24a8652ffe49334a7380ac0c84f7fe21477a6d2e47d7485c9b002f64cbeac6eb9d3bb0748e121a66c0d86c4ce1ede1943eb597e5044db3113fd6d5ee8dd4a44948f80f1cd3ed4df899fdde62b2fde2dc2bac3392f4a7f1f51e2946007de0981aadfc4919f208a7ce626a3324334f5a939624d3e38c3716074946d229498af929547008326320270d1c1fa96a6d49e613fceb1c1f18820272178f70636afaf6d751c76ac5377d96f60415d36080801f7f9991934cc5e007f2dddedf59c811d8a6edaa824d3acea6c2972ad73fe44b36bcd5efc691154fc10b277e21d70daef2e724764a080d48e26056dcc377fa75be0e9d5f654b8ec1aaee309f672e393c66607b43e5d09504893e28bf34ba86bea7880729d18f665437accc426d81eaf0435b469304b208dfc627ec40400a7ba5c0584d73947c3fc2f36f401611994946850e7159cdf2fb034ce00a5a8d7498044e6aefd963301b9d741ba72e8e9c9eb40b7f503a8d652a067d730592d7dc4c4b8d2d7362cd3d070f1319a01bb62c4c665eb245e1fd9cd1c365180e222d99614696168518a7053ea46c0cae94c3f1b2861995a4e9caa847f166f4967577a16227e6e9e07bb159c26c650708d96ab7854025a44b1f77ef02b8db2563149676e5f753bd2dc97949bd53b0dfeb5edb7b35dfb4404bc04a3dd8428fa14a8214b124415493b2658");
    // ... -v2 aes-192-cbc -v2prf hmacWithSHA512 -iter 1000
    const aes192_sha512 = hexLit("30820535305f06092a864886f70d01050d3052303106092a864886f70d01050c30240410f65e757964a034d94dfb9f1c15a78b36020203e8300c06082a864886f70d020b0500301d06096086480165030401160410234e08ce466704c6a9a6e7298ca2b6e4048204d02d12feede633826e3f3f88640afc6fc210b0f346f1322f8f5dc88043e9b182ade98859f25c90438c740e4410e5e910974fb910a2a263e6caf2f6dbd89db4fdea547f87d5ca487e956debc48e49bd723052aabfebfbefbd10e70c60b2003d417a941770e008105d4ca432b196538c12d74fe6735574d533510d648da6f9165bd761a7c2b7710da603122752adb2407b6346b346d20e007e24f770c0fe99a9e57d54b6859175a3d9c0f28ecd0e4c8c0bea30a029e75d0b933dc0c4243b413d1ec983371575c479495dce84941c9c9f938a739c27bb87cd89c7d5e9230898d7668ea79b1c268744e3b8685c7184930d4961b5701b27ec719ef61c5871b11362e82177fe885010c3ecfce983730a8741efa96a9ebeefdabbf5a9030498095cdd73600ab66237d5ea1fa944dc5cb5d21536343ab6c05d8e7ffbfff0fe8f76193c6d4f62b67542151330bb9f8e640e3ccf99a417b8f38a2545d05d2773628e99395ac81141abcf8ed9a5c5005cca30783c244912a6de18386ea46f1e197739d7fabaa1799a169e98197e4e22db564b9e0801878c9bf92d6a680ebfe0fd2e15711966e888cbb0719abc28598096aa468c57e06d876036bd290ce166db1a01e4495c11fafe2137c8cc996947d891751db6c332eb7eccbb80833713e3f4a907cdc0584909b6e7775ffbe91ec2038485c8b792a7db868a6d9bc01fe15e1d7615397c76143ef14f029c3d27ca09e18d3fcf14a7d9afe7cae4d874c565e65f67763d3057b988bf8346ddffbd3710f74a794b5a3e1d35213866d69059f00087e83eb3c79013e2c4399f114e9155fc6027925e090ef55861bc4b808dccbcbba22c642d516a12fd62beb87e69b683f4945e251d8014eb8aa90de15669bef7a59f94bc906440c8a3fc519e62dfcc27cb2986b3e1ed32ca4b02be4f1214c6d4cc4303cc981b154969358362dfecafdeb72646c3036990dc1077c4d958024557b660edbb100583f2faeef674f3209b36f6a45514f71f669a366b2b04b59b286e8f3c5c6f0f78109d3706a0264c3ac9ddc05607e335403cbf30db8f17fa4ae0616035a557f497b15c32cc15f0c649fb5618834f6f758e29070329aeffcfed07138c0efc69fddf70edb937771e9a3be85901ee551c6dea86fba0726c6df5f2ce068c46375c1e2b0e8cd68d7c825f49f8326009d85193bc5cac181572274a5d40244041f5f2e64d74df34a71223ceb4f0f9bfe443c1b85c2c65c1ae80337efd86392fe641c2afa9b040a1b8a3b0ffdbf38989b2d34767a81eacf9e82aba29855eba0deb82df48ae5365ebfcbb37097576e9cbec99670cbc2426d6ed6d0c7332941112cb55e910dc92a67de39e693992efbe8d8e957cab1ed9e2b42dcbbdbc0f4e61c32db47bae868610eb4adce752cf7c9c8d4daec7de831eca22cd18c6cf75167051419dad5b387e9d87202d1f99512c841b87a8ce749726f50d96fde2ec245e15db41ed2795a70ea26923973fd2790460db03ee73e150a0c1a02925f694cb6389fa1d47059c2446240147ab8f7a29592f79c2218c8fe56f7c4db39ad7669be4f6042747f0e2d072326e07eb1997fd5a3f8453a88b5d75ccc6f0572b3590d5ca792c3657d228896ed763997a2a2bc0b17ebaaa4fa899e424fded16bfc127b40629125ab75ca9f8896cb23028e2165fcebd5a45d85f7f1e8d77fb3a7ee88a8563fb98933c601b73def2a37e9821a8fffc44fe7a1ab1992de24c1b");
    // ... -scrypt -scrypt_N 1024 -scrypt_r 8 -scrypt_p 1 (scrypt: not supported)
    const scrypt = hexLit("3082052d305706092a864886f70d01050d304a302906092b06010401da47040b301c0410e52636f1015b2471f036d1f98e7d0cc202020400020108020101301d060960864801650304012a04106b467a0afbac6a5fa86723858d61e06b048204d021f2691a8ad740650124cf8d86e3c9f5d52083c170f0da913169ba8d77b3de10409b0f02ff72070b6f7288371887525e8a196cd04f7fb937ea9458aa37e924bb3c358804d5519f24a6c61f97f778d1bb15f6102986b15e3a112d7e8acf33f54b6fdf421ee73db174a7bb92740e763a05401b41b3cec51835c20426a4084c05bb28edaecc328f3bbe28bdf996e4ec47d937bf65ae1119ba9143c145354f141b36510dc11e786eea5860336f12974ed8ada6d0acdf61f81b4dc249aa6e8ad41b473d47c1d07298a0de3d95ac74ac0c3dfc626833a76c108b71bc3de8a85292968d50c5e0e74db62a33fe165e5c373a452b905f33b5d8c970c8a841dcfd6557ec5177604eec227ee87af4752b5258fd6c157c0b26d9b36b9f216aa89c11ddd3b5a77eefb8a13223ffa23c79375463ca5622dcb71daf8cf9fee9dddd195809c31fa0319f081b56db3d22f61b2b224c7d2916202694835f135a808d0bb20e03a6a320b2ea0741fe3039d00a4fdfdee9af172d466b5dd831a2a41280ac60c52dc34548c64b639cfdcf3253a48795650bbb786e50574dfbc6316be1bc32e648638d2e3533a7dae2cdf92dac06b133ca170459dd01fcb5ed57dfc06ea1f47d716f1dc26fbfcfb5139a2ab2b105660664c01117497695e0e515db4834c2711faecfda1600100bd9e4b9175b92ee7772687ed99e0f29178a28f6ce715800035de04ed7242df7a3236a45d256b8d4c5f5df7ca45a21b5194f79fb43ebbe0186a387f6d92948d6c6e4c8be0fe544e30443899304da0525bf48d3cbae34039b2dc5504d944d6c27eec905191062578697d01bbea41d38ec6e20939a738450edbefb8d909b0be9d04e4b950a39b2fe3af7516756aa0c15c474e59affccec43d5ceaf4aa828cfa8fb331860e3dc23c816870cb6102776df25d202af181af201879cdaa96cd47692ba4429cd59abe2ae00871d4a49d56af8275719ea14961bbdd133892d504086b93ad8e7ac3098276226a69365534565d22c63fde162b859d62fafff147036a3599c267c520433d81bc2ebe4ef35b874580c0ac75f69249102e5da6a9f13c2f73d00fd8c4ddd913eda9428bbd41494fba38b94c6e5f0ceb40a43f74a1e427f15269d9a12bfb6b11a586f47a8b0d1c2763184cc71a204570c22886d9764b57c5d904943671f13ea5c9eea5f6aa92988e50b3b41e4c4850d3e1ff16286206c50b348180b0bd7fd56c78339ae94fdec6ff22954567d5d4bfc03874a342140d221b1b6f93a79989d1551d7ea979774320f0f97fba1ada6726679db283579d331200e2c3952a3b924c19d500e04358875ccc71e10ba1684f7104298a3ed132a7fe7bc7af2916495907c5f90cb5a549e722854fb1340a749f5b94d84624604f948f3ece1eb1cb0ee4c207bef98fbde4a7b8769840e79097fb52ba6d2bcbf23a5fcdb68e4c877a87da28d55a1b7430307dfe9ca1ba8a5571dd9ee3be5d7eb2bdd6057d87fa6173ec6ebf0392852d56d274d71bad8d572a7db1a443fb14431c6ec4df71aec1e13b841bcef889026e68065cd280dca33aa1361864715b318a075b25c2176b2260477d265b4bd8253ee731704f4b789cff45a12f81f42e5d6dbb51789ab8ee54a870d982d9e4a9ce3f1fab75a9766130f13752a5ad896ab9612041e93baafe475d54b7e40456f1aeda2ce8c45b2ae9ec8c3f431e01604f2d84d6092249cf23bb0560b427b6e8ca7ebb3638313c3558b");
    // ... -v1 PBE-SHA1-3DES (PBES1: not supported)
    const pbes1 = hexLit("308204ea301c060a2a864886f70d010c0103300e0408de7d4b492da13a2c02020800048204c8a53465fb796af5660d43d3e6fc98428317364ab9a5c2a85d4331e384f4e77419ed72b90a1da504ef1c586714c6067a07ff66de5c9026dd666b5857dd9621dcb1ee1e974ed4af05048126cc7a7511233fb0a4ab1d42b2832693d2e889f5b455fc1929a466259d0cea81b16675c8bef1ae98f7bde8f8a971a0b53add5f58eff16fac41138fe3611bee1420c024c78f0d56ac0f72d30f10a9e7e589eddb2ff9e35ec0909a3f518ba266210b7feca64f3d633b758874476225dc4f04f4619b9a8e61be4eba06528d1f67b236c1c94539bb1e6c84f3faf5e2cd83ce8cf8e22a4e66bf701c9a5d1a42d291785d0640cbd44772d4473aa31f414dbc7cda5a20f3ddd773c5b048639efbee9610f4cf7cdfd83d1a518809a0f235a96859c5eafe43bac049a31414b90a468851ee81adef75cb5e8bf2c441d8e730f1c61852fab3ce3f44dbf5ad410cbd8f6b2f9b5f6dde36273c0c9b663863159bbd070ebe0b7e85c388ec11049f1045ded6e48b6b570da13d704914e037df6e45c6f168970416534a2b4da9a67e520ace6da4ceda97c6b0ac494b3771728156dac8513e1af732ad3b201471f8c7ed9f6fdf83f3cd3cb70e857bc3b3b45da4bdedffe09f5b8260756e316e9e06f8e61c0aa34cf7a4e8484f82c0638a82af91416e63b98ecc72a19bc98181777fb887753ff7abe377a0196a01255fb1a9d7ad6b4dba147c22b1dd0b25a88195be2e3263ab8fac45efbc1ad164944bce7162699db8db51701311abbf3c3d1f6baae9efa75cea78714c6036421a41428d0e0994522062382bdb675cace05612be07743ce0a1c803098ed82f285026112f8f654fbd7b12720bc150786a1213dd90d79c85cd08607bc796eebc79a1f0ce2b25025c681d0a227dcf4c3d4ef10a8fb85f8208cb2e2a1ed7533c326d6e39ff5e0771525f352c67dc897f843beca137e298e0d90673f58d79a80b627b3eb5f3f719fe87225c98c99dac31bc00e351a8222c87fe604d71ef41215fe628e505bebd61ca5015607eb91ce5ddccd6e82b6352b8144ad4435e468aaf71324c4db523e3ac116a3ea55cd0775da51b3e2bede6582eb07d7632d959e04a18c98a4584a262c4354b2fce8a28e5474ab09863556d5507c9121af4b8b1b94047e6def80954c73ae0c85596ae24a22189af15b6611f960db0b512ab9b33d767c8a011695d75b5e7242a2e4aa6acd953e8a88e7d36ecc2f2fbca839e77ea163b297cb2db7f31b9f4e64ca2b61024741e4579359a0dc0f68c3d1fe424de96d74c87221f0603af736c81b59bc1180b9e536369edd7a34f8634d53739fa4ef9152108deec4cae79f84bc566030464d7753ee88a9573adf9436a54b54a154a6c3ea2daa33ee13c54099076aeee8af8495ade11dfb87fab1e3379d62c4b75f4f74f29fac5c36934e411760c6e28e7ad1169819581103a0b9bcdc00c1f70711d7031c096cf22d4acb9827e44c6364f8bd26a4b99436c9952a87c199011658fc21351757e6863e9a7d8714cf64555c0f91fb1c25461626d624343ea92e1518725ea727e53b02e7662139f6e04151aa6a9e28db215b974a886d5f3d7afbe5b13ab66f0f6698dc83719fbf6281ce6f970fcaf76dc55d362e08643f02c574e39d0c674d50f36a976042c7186203aa4eefac5041a133f4b284d64b10e8e4d2c6766234ad2feafa101b7da61c77237e71d49ef3d58d4ca59cc609a39a8223432fd2af8f8");
    // the same as aes256_sha256 key, PEM (fresh salt/IV; OpenSSL 3 default shape)
    const pem =
        \\-----BEGIN ENCRYPTED PRIVATE KEY-----
        \\MIIFNTBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQy+zOX4+SbBFhR9yQ
        \\yukJdQICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEJemfRmbyIRdlQOC
        \\rxCHT7QEggTQ+wkRWytQx1T3J8ozWbgzqSpn6U8ke6dxScB29Ko/0l2pzSZ7OK2w
        \\N8rJxJNrLTvjbw0/0i4ti9VAG/tW1+Qygqi6m9asUixH55F57XoaQaeccAPfuEtG
        \\dUSM2ZOQsIPQMPqPvXIwhPUnNgzjewm5fPjA/5VIUjt1bA9TR5mOaS3H6qUQaYca
        \\BGOhknqRoi+m7ls46PxX12i1HiOc0+dYxTG8y6C9K/LO2fhI+2RJoPqWLvNWY6G/
        \\YcvGEdcvdFBhfiNPwlqJL7BvFHJ85UTkCbc+TsytCXj4UhpRoVMT4m6IFAnWruFR
        \\I1GaWz56m7ZFko7RYJs4zwS6VGUgMneG1hgY3pgVIm2MqjgkwPZfVjjY2v3YiFdB
        \\4y1nHO2y8vG21Nh0qQcbTDB8DfHupse3EttcVV/bWjYqoVNUfakeLWpteQS23fXM
        \\ct7Gi1vbVNnONWDEd58h31TcifJzyUusMgNT/g4ebtZiA05WPC14bs5qDwZdWGW8
        \\6xXd/0Qes47kVW2fEXlW5e9fRFTMUGadUpfA3PLrRYOhHZ1Vodx7j5ZBssgkKaDv
        \\730Kkvc1W9HZNPididdVgrLaO7KmlsaFrr767Skc6J+trKcJaAdJ+SCu6Am/y7yd
        \\BIkCAGRjJr1pIrTKW8Tn6MCQN++X/GP31ClcZMpWUbo6JTwHzXl2QV+Zlxs/FZso
        \\WBRepQWVEqvfGGWSc5yZqwaRO1ty8e+Q4CjgU7gThbDulCp5KGe2f0pUZPUCUR2C
        \\0B3m7QtS4MWZFb3P5GZ01f+eJGzrrU5uEOl3iaFVHy1gdJJ+UIEBrimDGYgJ97WU
        \\vNZMGBfj974el4N03XhYajHrVR08XamyKLvSleDzvDpgVvyyFYE4PIpIoKBDbKVt
        \\Bpr8+QxEA3SOLlhyqZmlTwkazBsL/qI3fmJ9CANE3EMCPSrs105gH5McZcHqGwRO
        \\NuPIe5TBcvSmginPnSWomRppAu3/DpNyNIKW6+RWBe6+xtui//kF4nglmhrayV4z
        \\pHOgFhJeUGWvvTvS2dHQeq/VyKYrKz9HZYdKEygWYbpyaHwb0BXR8IrfnsVSx9zq
        \\a2yPyHAYHhz1Dv1dj2w+hpTadCECxkC7JwGIAu21Y6iG91zEf4fG9tHz3iYGApPl
        \\pZCbJQyfwWscxrREj2xZqzchlPFdwGJ6knED29kZ+c52rp67wKA94WZ1ln3faN4X
        \\JXIivgv4V70YiSSLQbUGtgOk8NYpgCF6dXt5wkwUDrBtRv73PFR903Sv84qkEDvA
        \\91Wg79mWp7tvgwhh/qOawvkWOxq52aqX9a7C0+wXsVkauRap3CnQsEzWhrcELn/M
        \\5vROMbJ80k69NLZabuti6Uf6GNsujkZXasHC2EqhOigl6ORfhOjxfUqJIdn+LVBM
        \\M6N4jiyShsGKG0HmPbslWCm3rDwWDTiAOR56GP3bwXIuFGJIEYB9tutEzV7c9EcM
        \\BbV/oS/kSAk6+75OknpVpzu17pPK4kSqTCr1JgPaCNVZ/YkP9PgluJwESQLkToos
        \\FH52fRV3qBxjLzTJDNrBTIHEimKL01ZKSEAKk2EdcU4EC+5tWyXANi+Su1nY76vh
        \\7WnNOHRASpfgeXtqxbtrGplyUtu2iqvXPVGunW6i4niN9qTmLG1ltis=
        \\-----END ENCRYPTED PRIVATE KEY-----
        \\
    ;
};

// ── R5 (2026-10-14): encrypted PKCS#8 against OpenSSL 3 files ───────────────

test "PBES2: OpenSSL's encrypted PKCS#8 (AES-128/192/256-CBC, HMAC-SHA1/256/512) decrypts to kat2048" {
    var buf: [max_pkcs1_private_der_len]u8 = undefined;
    for ([_][]const u8{ &kat2048_pbes2.aes256_sha256, &kat2048_pbes2.aes128_sha1, &kat2048_pbes2.aes192_sha512 }) |der| {
        var sk: SecretKey = undefined;
        try fromPkcs8Encrypted(&sk, der, kat2048_pbes2.password);
        defer sk.deinit();
        try testing.expectEqualSlices(u8, &kat2048_der.priv_pkcs1, try sk.toPkcs1Der(&buf));
        try testing.expectError(error.IncorrectPasswordOrCorrupt, fromPkcs8Encrypted(&test_sk_out, der, "wrong password"));
        // A flipped ciphertext octet in the last block: padding or DER breaks.
        var bad: [1400]u8 = undefined;
        @memcpy(bad[0..der.len], der);
        bad[der.len - 20] ^= 0x01;
        try testing.expectError(error.IncorrectPasswordOrCorrupt, fromPkcs8Encrypted(&test_sk_out, bad[0..der.len], kat2048_pbes2.password));
    }
    var sk: SecretKey = undefined;
    try SecretKey.fromPemEncrypted(&sk, kat2048_pbes2.pem, kat2048_pbes2.password);
    defer sk.deinit();
    try testing.expectEqualSlices(u8, &kat2048_der.priv_pkcs1, try sk.toPkcs1Der(&buf));
    // The cleartext labels go through the same call.
    var sk2: SecretKey = undefined;
    try SecretKey.fromPemEncrypted(&sk2, kat2048_pem.priv_pkcs8, "ignored");
    defer sk2.deinit();
    try testing.expectEqualSlices(u8, &kat2048_der.priv_pkcs1, try sk2.toPkcs1Der(&buf));
    // Encrypted input to the cleartext entry points is still refused by label.
    try testing.expectError(error.UnsupportedPemLabel, SecretKey.fromPem(&test_sk_out, kat2048_pbes2.pem));
}

test "PBES2: scrypt and PBES1 are UnsupportedEncryption; truncations are InvalidDer" {
    try testing.expectError(error.UnsupportedEncryption, fromPkcs8Encrypted(&test_sk_out, &kat2048_pbes2.scrypt, kat2048_pbes2.password));
    try testing.expectError(error.UnsupportedEncryption, fromPkcs8Encrypted(&test_sk_out, &kat2048_pbes2.pbes1, kat2048_pbes2.password));
    const der = &kat2048_pbes2.aes256_sha256;
    var l: usize = 0;
    while (l < der.len) : (l += 13) {
        try testing.expectError(error.InvalidDer, fromPkcs8Encrypted(&test_sk_out, der[0..l], kat2048_pbes2.password));
    }
}

/// `der` with the salt, IV and ciphertext contents zeroed — the parts that
/// differ between two encryptions of the same key under the same options.
fn pbes2Masked(der: []const u8, out: []u8) ![]u8 {
    @memcpy(out[0..der.len], der);
    const pp = try pbes2Params(der);
    for ([_][]const u8{ pp.salt, pp.iv, pp.data }) |part| {
        const at = @intFromPtr(part.ptr) - @intFromPtr(der.ptr);
        @memset(out[at..][0..part.len], 0);
    }
    return out[0..der.len];
}

test "PBES2: our encryption has OpenSSL's exact shape (salt, IV, ciphertext aside) and decrypts back" {
    var sk = try kat2048.secretKey();
    defer sk.deinit();
    var prng = std.Random.DefaultPrng.init(0x9be5_2014);
    const Case = struct { opts: Pbes2Options, openssl: []const u8 };
    var ours: [max_encrypted_pem_len]u8 = undefined;
    var m1: [max_encrypted_pkcs8_der_len]u8 = undefined;
    var m2: [max_encrypted_pkcs8_der_len]u8 = undefined;
    var buf: [max_pkcs1_private_der_len]u8 = undefined;
    for ([_]Case{
        .{ .opts = .{}, .openssl = &kat2048_pbes2.aes256_sha256 }, // the defaults = OpenSSL's
        .{ .opts = .{ .cipher = .aes128_cbc, .prf = .hmac_sha1, .iterations = 1000 }, .openssl = &kat2048_pbes2.aes128_sha1 },
        .{ .opts = .{ .cipher = .aes192_cbc, .prf = .hmac_sha512, .iterations = 1000 }, .openssl = &kat2048_pbes2.aes192_sha512 },
    }) |c| {
        const der = try sk.toPkcs8Encrypted("zig-libs-pw", prng.random(), c.opts, &ours);
        try testing.expectEqualSlices(u8, try pbes2Masked(c.openssl, &m1), try pbes2Masked(der, &m2));
        var back: SecretKey = undefined;
        try fromPkcs8Encrypted(&back, der, "zig-libs-pw");
        defer back.deinit();
        try testing.expectEqualSlices(u8, &kat2048_der.priv_pkcs1, try back.toPkcs1Der(&buf));
    }
    // PEM, and fresh salt + IV per call.
    const pem = try sk.toPemEncrypted("pw", prng.random(), .{ .iterations = 16 }, &ours);
    var back: SecretKey = undefined;
    try SecretKey.fromPemEncrypted(&back, pem, "pw");
    defer back.deinit();
    var other: [max_encrypted_pem_len]u8 = undefined;
    try testing.expect(!std.mem.eql(u8, pem, try sk.toPemEncrypted("pw", prng.random(), .{ .iterations = 16 }, &other)));
    // Options outside the caps.
    for ([_]Pbes2Options{ .{ .iterations = 0 }, .{ .iterations = max_pbkdf2_iterations + 1 }, .{ .salt_len = 0 }, .{ .salt_len = max_pbes2_salt_len + 1 } }) |o| {
        try testing.expectError(error.InvalidOptions, sk.toPkcs8Encrypted("pw", prng.random(), o, &ours));
    }
}

test "PBES2: an iteration count over max_pbkdf2_iterations is refused before any KDF work" {
    var sk = try kat2048.secretKey();
    defer sk.deinit();
    var prng = std.Random.DefaultPrng.init(7);
    var buf: [max_encrypted_pkcs8_der_len]u8 = undefined;
    // 0x010000 iterations, then the INTEGER patched to 0x110000 (> 2^20).
    const der = try sk.toPkcs8Encrypted("pw", prng.random(), .{ .iterations = 0x010000 }, &buf);
    const at = std.mem.find(u8, der, &.{ 0x02, 0x03, 0x01, 0x00, 0x00 }).?;
    der[at + 2] = 0x11;
    try testing.expectError(error.KdfIterationsTooLarge, fromPkcs8Encrypted(&test_sk_out, der, "pw"));
}

// ── audit 2026-10-18: mutation survivors of the 2026-10 additions ───────────
//
// Each test below breaks ONE property of an otherwise valid input (or checks
// one boundary) that a mutant of the new serialisation / PBES2 / F1 code could
// not be told apart by before; see SPEC.md "Mutation (2026-10-18".

/// An `EncryptedPrivateKeyInfo` (RFC 5958 §3, PBES2-params RFC 8018 A.4) with
/// optional faults. The defaults are a valid AES-256-CBC / PBKDF2 file shape
/// (the ciphertext is filler: only `pbes2Params`, the structure walk, reads it).
const Epki = struct {
    salt: []const u8 = "0123456789abcdef",
    iter: []const u8 = &.{ 0x08, 0x00 },
    key_len: ?[]const u8 = null,
    prf_last: ?u8 = null,
    prf_oid_extra: []const u8 = "",
    prf_params: []const u8 = &.{ 0x05, 0x00 },
    cipher_last: u8 = 0x2a,
    cipher_extra: []const u8 = "",
    iv: []const u8 = "ivivivivivivivi!",
    data_len: usize = 32,
    kp_tail: []const u8 = "",
    kdf_tail: []const u8 = "",
    enc_tail: []const u8 = "",
    params_tail: []const u8 = "",
    alg_tail: []const u8 = "",
    top_tail: []const u8 = "",

    fn build(o: Epki, a: std.mem.Allocator) ![]const u8 {
        const d: der_writer.Builder = .{ .a = a };
        const kl: []const u8 = if (o.key_len) |k| try d.integerRaw(k) else "";
        const prf: []const u8 = if (o.prf_last) |l| try d.seq(&.{
            try d.oid(try d.cat(&[_][]const u8{ &marshal.oid_hmac_arc, &[_]u8{l}, o.prf_oid_extra })),
            o.prf_params,
        }) else "";
        const kp = try d.seq(&.{ try d.octetString(o.salt), try d.integerRaw(o.iter), kl, prf, o.kp_tail });
        const kdf = try d.seq(&.{ try d.oid(&marshal.oid_pbkdf2), kp, o.kdf_tail });
        const enc = try d.seq(&.{
            try d.oid(try d.cat(&[_][]const u8{ &marshal.oid_aes_arc, &[_]u8{o.cipher_last}, o.cipher_extra })),
            try d.octetString(o.iv),
            o.enc_tail,
        });
        const params = try d.seq(&.{ kdf, enc, o.params_tail });
        const alg = try d.seq(&.{ try d.oid(&marshal.oid_pbes2), params, o.alg_tail });
        const data = try a.alloc(u8, o.data_len);
        @memset(data, 0x5a);
        return d.seq(&.{ alg, try d.octetString(data), o.top_tail });
    }

    fn expect(o: Epki, a: std.mem.Allocator, want: ?FromEncryptedError) !void {
        const der = try o.build(a);
        if (want) |e| {
            try testing.expectError(e, pbes2Params(der));
        } else {
            _ = try pbes2Params(der);
        }
    }
};

test "PBES2 structure walk: every container must end where its last child ends" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const extra = [_]u8{ 0x05, 0x00 }; // a NULL where the container should have ended
    try (Epki{}).expect(a, null);
    try (Epki{ .prf_last = 9 }).expect(a, null);
    try (Epki{ .top_tail = &extra }).expect(a, error.InvalidDer);
    try (Epki{ .alg_tail = &extra }).expect(a, error.InvalidDer);
    try (Epki{ .params_tail = &extra }).expect(a, error.InvalidDer);
    try (Epki{ .kdf_tail = &extra }).expect(a, error.InvalidDer);
    try (Epki{ .enc_tail = &extra }).expect(a, error.InvalidDer);
    try (Epki{ .prf_last = 9, .kp_tail = &extra }).expect(a, error.InvalidDer);
    try (Epki{ .kp_tail = &extra }).expect(a, error.InvalidDer); // after iterations: not a keyLength, not a PRF
}

test "PBES2 parameters: keyLength, PRF parameters, IV, salt, iteration and ciphertext limits" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // keyLength present: must be the cipher's.
    try (Epki{ .key_len = &.{0x20} }).expect(a, null);
    try (Epki{ .key_len = &.{0x18} }).expect(a, error.InvalidDer);
    // PRF parameters: absent or a real (empty) NULL, nothing else.
    try (Epki{ .prf_last = 9, .prf_params = "" }).expect(a, null);
    try (Epki{ .prf_last = 9, .prf_params = &.{ 0x05, 0x01, 0x00 } }).expect(a, error.InvalidDer);
    // The IV is exactly one block.
    try (Epki{ .iv = "ivivivivivivivi" }).expect(a, error.InvalidDer);
    try (Epki{ .iv = "ivivivivivivivi!!" }).expect(a, error.InvalidDer);
    // Salt: 1 .. max_pbes2_salt_len octets.
    const salt64 = @as([max_pbes2_salt_len]u8, @splat(0x11));
    try (Epki{ .salt = &salt64 }).expect(a, null);
    try (Epki{ .salt = &(salt64 ++ [_]u8{0x11}) }).expect(a, error.InvalidDer);
    try (Epki{ .salt = "" }).expect(a, error.InvalidDer);
    // Iterations: 1 .. 2^20; a non-minimal or negative INTEGER is no count.
    try (Epki{ .iter = &.{0x01} }).expect(a, null);
    try (Epki{ .iter = &.{0x00} }).expect(a, error.InvalidDer);
    try (Epki{ .iter = &.{ 0x10, 0x00, 0x00 } }).expect(a, null);
    try (Epki{ .iter = &.{ 0x10, 0x00, 0x01 } }).expect(a, error.KdfIterationsTooLarge);
    try (Epki{ .iter = &.{ 0x00, 0x08, 0x00 } }).expect(a, error.InvalidDer);
    try (Epki{ .iter = &.{ 0x88, 0x00 } }).expect(a, error.InvalidDer);
    // Ciphertext: whole blocks, 1 .. max_pkcs8_der_len + 16 octets.
    const top = (max_pkcs8_der_len + 16) / 16 * 16;
    try (Epki{ .data_len = 16 }).expect(a, null);
    try (Epki{ .data_len = top }).expect(a, null);
    try (Epki{ .data_len = top + 16 }).expect(a, error.InvalidDer);
    try (Epki{ .data_len = 0 }).expect(a, error.InvalidDer);
    try (Epki{ .data_len = 17 }).expect(a, error.InvalidDer);
}

test "PBES2 OIDs: PRF and cipher are single arc octets under their arc, nothing else" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const prfs = [_]Pbes2Prf{ .hmac_sha1, .hmac_sha224, .hmac_sha256, .hmac_sha384, .hmac_sha512 };
    for (prfs, 7..) |want, last| {
        const pp = try pbes2Params(try (Epki{ .prf_last = @intCast(last) }).build(a));
        try testing.expectEqual(want, pp.prf);
    }
    const ciphers = [_]struct { Pbes2Cipher, u8 }{ .{ .aes128_cbc, 0x02 }, .{ .aes192_cbc, 0x16 }, .{ .aes256_cbc, 0x2a } };
    for (ciphers) |c| {
        const pp = try pbes2Params(try (Epki{ .cipher_last = c[1] }).build(a));
        try testing.expectEqual(c[0], pp.cipher);
    }
    // Neighbours of the HMAC range (2.6 and 2.12 are other algorithms) and of the AES ones.
    for ([_]u8{ 6, 12 }) |last| try (Epki{ .prf_last = last }).expect(a, error.UnsupportedEncryption);
    for ([_]u8{ 0x01, 0x03, 0x15, 0x17, 0x29, 0x2b }) |last| try (Epki{ .cipher_last = last }).expect(a, error.UnsupportedEncryption);
    // A longer OID under the arc is not the algorithm.
    try (Epki{ .prf_last = 9, .prf_oid_extra = &.{0x01} }).expect(a, error.UnsupportedEncryption);
    try (Epki{ .cipher_extra = &.{0x01} }).expect(a, error.UnsupportedEncryption);
}

/// The nine INTEGER contents of a PKCS#1 `RSAPrivateKey`, as DER again with
/// `d` replaced.
fn pkcs1WithD(a: std.mem.Allocator, der: []const u8, d_be: []const u8) ![]const u8 {
    const f = try pkcs1Fields(der);
    const b: der_writer.Builder = .{ .a = a };
    var parts: [9][]const u8 = undefined;
    for (f, 0..) |e, i| parts[i] = try b.integer(if (i == 3) d_be else derView(der, e));
    return b.seq(&parts);
}

test "F1: a wire d at or above n is refused although it satisfies both congruences" {
    // d' = d + φ(n) ≡ d (mod p−1) and (mod q−1), but d' > n.
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var mem: [64 * 1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&mem);
    const gpa = fba.allocator();
    var p1 = try bigFromBytes(gpa, &kat2048.p);
    try p1.addScalar(&p1, -1);
    var q1 = try bigFromBytes(gpa, &kat2048.q);
    try q1.addScalar(&q1, -1);
    var phi = try newBig(gpa);
    try phi.mul(&p1, &q1);
    var d2 = try bigFromBytes(gpa, &kat2048.d);
    try d2.add(&d2, &phi);
    var d2_bytes: [257]u8 = undefined;
    d2.toConst().writeTwosComplement(&d2_bytes, .big);
    const der = try pkcs1WithD(a, &kat2048_der.priv_pkcs1, &d2_bytes);
    try testing.expectError(error.InvalidPrivateKey, SecretKey.fromDer(&test_sk_out, der));
    // The same rewrite with the original d is the original key (the helper is faithful).
    const same = try pkcs1WithD(a, &kat2048_der.priv_pkcs1, &kat2048.d);
    try testing.expectEqualSlices(u8, &kat2048_der.priv_pkcs1, same);
}

/// Every INTEGER of a `RSAPrivateKey` DER is in minimal two's complement form.
fn expectMinimalIntegers(der: []const u8) !bool {
    var top40 = false;
    for (try pkcs1Fields(der)) |e| {
        const c = derView(der, e);
        try testing.expect(c.len > 0 and c[0] & 0x80 == 0); // non-negative
        if (c.len > 1 and c[0] == 0) try testing.expect(c[1] & 0x80 != 0); // no redundant sign octet
        if (c[0] >= 0x40 and c[0] < 0x80) top40 = true;
    }
    return top40;
}

test "marshal: INTEGERs are minimal for many exponents; a block-aligned PKCS#8 encrypts and decrypts" {
    var prng = std.Random.DefaultPrng.init(0x1018);
    var saw_top40 = false;
    var aligned: usize = 0;
    var keys: usize = 0;
    var e: u32 = 3;
    while (e < 301) : (e += 2) {
        var e_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &e_bytes, e, .big);
        var sk: SecretKey = undefined;
        SecretKey.fromPrimes(&sk, &kat2048.p, &kat2048.q, std.mem.trimStart(u8, &e_bytes, &.{0})) catch continue;
        defer sk.deinit();
        keys += 1;
        var buf: [max_pkcs1_private_der_len]u8 = undefined;
        const der = try sk.toPkcs1Der(&buf);
        if (try expectMinimalIntegers(der)) saw_top40 = true;
        var back: SecretKey = undefined;
        try SecretKey.fromDer(&back, der);
        defer back.deinit();
        var buf2: [max_pkcs1_private_der_len]u8 = undefined;
        try testing.expectEqualSlices(u8, der, try back.toPkcs1Der(&buf2));

        var p8: [max_pkcs8_der_len]u8 = undefined;
        const p8_len = (try sk.toPkcs8Der(&p8)).len;
        if (p8_len % 16 != 0) continue;
        aligned += 1; // PKCS#7 then adds a whole block of 16 × 0x10
        var enc: [max_encrypted_pkcs8_der_len]u8 = undefined;
        const ed = try sk.toPkcs8Encrypted("pw", prng.random(), .{ .cipher = .aes128_cbc, .iterations = 1 }, &enc);
        try testing.expectEqual(p8_len + 16, (try pbes2Params(ed)).data.len);
        var dec: SecretKey = undefined;
        try fromPkcs8Encrypted(&dec, ed, "pw");
        defer dec.deinit();
        try testing.expectEqualSlices(u8, der, try dec.toPkcs1Der(&buf2));
    }
    try testing.expect(keys >= 20);
    try testing.expect(saw_top40);
    try testing.expect(aligned >= 1);
}

test "marshal: success zeroes what the DER moved out of; a short buffer still gets the whole result" {
    var sk = try kat2048.secretKey();
    defer sk.deinit();
    const pk = sk.publicKey();
    var prng = std.Random.DefaultPrng.init(0x2018);
    var buf: [max_encrypted_pem_len]u8 = undefined;
    const n = kat2048_der.priv_pkcs1.len;
    // DER: the copy left at the end of `out` is wiped (here pos ≥ n) ...
    @memset(&buf, 0xaa);
    try testing.expectEqualSlices(u8, &kat2048_der.priv_pkcs1, try sk.toPkcs1Der(&buf));
    for (buf[buf.len - n ..]) |b| try testing.expectEqual(0, b);
    // ... and with only one spare byte (pos < n) the result is intact.
    @memset(&buf, 0xaa);
    try testing.expectEqualSlices(u8, &kat2048_der.priv_pkcs1, try sk.toPkcs1Der(buf[0 .. n + 1]));
    @memset(&buf, 0xaa);
    try testing.expectEqualSlices(u8, &kat2048_der.pub_spki, try pk.toSpkiDer(buf[0 .. kat2048_der.pub_spki.len + 1]));
    // PEM (plain and encrypted): nothing of the DER stays behind the text.
    @memset(&buf, 0xaa);
    var pem = try sk.toPem(.pkcs8, &buf);
    for (buf[pem.len..]) |b| try testing.expectEqual(0, b);
    @memset(&buf, 0xaa);
    pem = try sk.toPemEncrypted("pw", prng.random(), .{ .iterations = 1 }, &buf);
    for (buf[pem.len..]) |b| try testing.expectEqual(0, b);
    @memset(&buf, 0xaa);
    pem = try pk.toPem(.spki, &buf);
    for (buf[pem.len..]) |b| try testing.expectEqual(0, b);
}

test "marshal: a buffer too small for the DER itself fails with out zeroed, in every writer" {
    var sk = try kat2048.secretKey();
    defer sk.deinit();
    const pk = sk.publicKey();
    var prng = std.Random.DefaultPrng.init(0x3018);
    var buf: [100]u8 = undefined;
    @memset(&buf, 0xaa);
    try testing.expectError(error.BufferTooSmall, pk.toPem(.spki, &buf));
    for (buf) |b| try testing.expectEqual(0, b);
    @memset(&buf, 0xaa);
    try testing.expectError(error.BufferTooSmall, sk.toPem(.pkcs1, &buf));
    for (buf) |b| try testing.expectEqual(0, b);
    @memset(&buf, 0xaa);
    try testing.expectError(error.BufferTooSmall, sk.toPkcs8Encrypted("pw", prng.random(), .{ .iterations = 1 }, &buf));
    for (buf) |b| try testing.expectEqual(0, b);
    @memset(&buf, 0xaa);
    try testing.expectError(error.BufferTooSmall, sk.toPemEncrypted("pw", prng.random(), .{ .iterations = 1 }, &buf));
    for (buf) |b| try testing.expectEqual(0, b);
    // A buffer that holds the plaintext but not the ciphertext + parameters.
    var mid: [kat2048_der.priv_pkcs8.len + 16]u8 = undefined;
    @memset(&mid, 0xaa);
    try testing.expectError(error.BufferTooSmall, sk.toPkcs8Encrypted("pw", prng.random(), .{ .iterations = 1 }, &mid));
    for (mid) |b| try testing.expectEqual(0, b);
}

test "PBES2 writer: the option limits are inclusive (2^20 iterations, 64 salt octets)" {
    var sk = try kat2048.secretKey();
    defer sk.deinit();
    var prng = std.Random.DefaultPrng.init(0x4018);
    var buf: [max_encrypted_pkcs8_der_len]u8 = undefined;
    const der = try sk.toPkcs8Encrypted("pw", prng.random(), .{ .cipher = .aes128_cbc, .prf = .hmac_sha1, .iterations = max_pbkdf2_iterations, .salt_len = max_pbes2_salt_len }, &buf);
    const pp = try pbes2Params(der);
    try testing.expectEqual(max_pbkdf2_iterations, pp.iterations);
    try testing.expectEqual(max_pbes2_salt_len, pp.salt.len);
    // Our default shape names hmacWithSHA256 and says so; SHA-1 is the omitted DEFAULT.
    const d256 = try sk.toPkcs8Encrypted("pw", prng.random(), .{ .iterations = 1 }, &buf);
    try testing.expectEqual(Pbes2Prf.hmac_sha256, (try pbes2Params(d256)).prf);
    const d1 = try sk.toPkcs8Encrypted("pw", prng.random(), .{ .prf = .hmac_sha1, .iterations = 1 }, &buf);
    try testing.expect(std.mem.find(u8, d1, &marshal.oid_hmac_arc) == null);
    try testing.expectEqual(Pbes2Prf.hmac_sha1, (try pbes2Params(d1)).prf);
}

test "digest entry points: a digest of the wrong length is refused by all four, long or short" {
    var sk = try kat2048.secretKey();
    defer sk.deinit();
    const pk = sk.publicKey();
    var prng = std.Random.DefaultPrng.init(0x5018);
    var out: [256]u8 = undefined;
    const digest = @as([65]u8, @splat(0x42));
    for ([_]usize{ 31, 33 }) |len| {
        const dg = digest[0..len];
        try testing.expectError(error.InvalidDigestLength, signPkcs1v15Digest(&sk, .sha256, dg, &out));
        try testing.expectError(error.InvalidDigestLength, verifyPkcs1v15Digest(pk, .sha256, dg, &kat2048.sig_sha256));
        try testing.expectError(error.InvalidDigestLength, signPssDigest(&sk, .sha256, prng.random(), dg, 32, &out));
        try testing.expectError(error.InvalidDigestLength, verifyPssDigest(pk, .sha256, dg, &kat2048.sig_sha256, null));
        try testing.expectError(error.InvalidDigestLength, pk.verifyKey().verifyPkcs1v15Digest(.sha256, dg, &kat2048.sig_sha256));
    }
}

test "PSS: the smallest key a hash fits (emLen = hLen + 2) signs and verifies with salt 0" {
    const Sha256 = std.crypto.hash.sha2.Sha256;
    try testing.expectEqual(0, maxPssSaltLen(272, Sha256).?); // emLen 34 = 32 + 2
    try testing.expectEqual(null, maxPssSaltLen(264, Sha256)); // emLen 33
    try testing.expectEqual(0, maxPssSaltLen(273, Sha256).?); // emBits 272: still 34 octets
    try testing.expectEqual(1, maxPssSaltLen(280, Sha256).?);
    // 172-bit modulus: emLen = 22 = SHA-1's 20 + 2.
    const p = comptime hexLit("3bed8e60ed84e75dfc365b");
    const q = comptime hexLit("33f4814871f502d278fec1");
    var sk: SecretKey = undefined;
    try SecretKey.fromPrimes(&sk, &p, &q, &.{ 0x01, 0x00, 0x01 });
    defer sk.deinit();
    const pk = sk.publicKey();
    try testing.expectEqual(172, pk.bits());
    var prng = std.Random.DefaultPrng.init(0x6018);
    var sig: [22]u8 = undefined;
    const s = try signPss(&sk, std.crypto.hash.Sha1, prng.random(), "tiny", 0, &sig);
    try verifyPss(pk, std.crypto.hash.Sha1, "tiny", s, 0);
    try testing.expectEqual(0, try verifyPssAuto(pk, std.crypto.hash.Sha1, "tiny", s));
    try testing.expectError(error.SignatureVerificationFailed, verifyPss(pk, std.crypto.hash.Sha1, "tiny", s, 1));
}

test "PEM: two blocks of one label load the first; a '-' inside the body is no END line" {
    const k1 = kat2048_pem.pub_spki;
    const first = try PublicKey.fromPem(k1);
    // Two different keys, same label: the first one.
    const pk3 = try PublicKey.fromBytes(&kat2048.n, &.{0x03}); // same n, e = 3: another key
    var buf: [max_public_pem_len]u8 = undefined;
    const other = try pk3.toPem(.spki, &buf);
    var two: [2 * max_public_pem_len]u8 = undefined;
    const text = try std.mem.print(&two, "{s}{s}", .{ k1, other });
    try testing.expect(first.equal(&try PublicKey.fromPem(text)));
    try testing.expect(!first.equal(&pk3));
    // The reverse order loads the other key.
    const text2 = try std.mem.print(&two, "{s}{s}", .{ other, k1 });
    try testing.expect(pk3.equal(&try PublicKey.fromPem(text2)));
    // A '-' that does not start the END line ends the body there: invalid.
    var junk: [max_public_pem_len + 16]u8 = undefined;
    const body_end = std.mem.find(u8, k1, "-----END").?;
    const bad = try std.mem.print(&junk, "{s}-{s}", .{ k1[0..body_end], k1[body_end..] });
    try testing.expectError(error.InvalidPem, PublicKey.fromPem(bad));
    // END line of another label: invalid.
    const wrong = try std.mem.print(&junk, "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END RSA PUBLIC KEY-----\n", .{});
    try testing.expectError(error.InvalidPem, PublicKey.fromPem(wrong));
}

test "PEM: a label of exactly 32 octets is a label, 33 is not; an END line before the BEGIN is no block" {
    const a32 = strRepeat("A", 32);
    const ok = "-----BEGIN " ++ a32 ++ "-----\nAAAA\n-----END " ++ a32 ++ "-----\n";
    try testing.expectError(error.UnsupportedPemLabel, PublicKey.fromPem(ok));
    try testing.expectError(error.UnsupportedPemLabel, SecretKey.fromPem(&test_sk_out, ok));
    const a33 = strRepeat("A", 33);
    const long = "-----BEGIN " ++ a33 ++ "-----\nAAAA\n-----END " ++ a33 ++ "-----\n";
    try testing.expectError(error.InvalidPem, PublicKey.fromPem(long));
    const swapped = "-----END PUBLIC KEY-----\n-----BEGIN PUBLIC KEY-----\nAAAA\n";
    try testing.expectError(error.InvalidPem, PublicKey.fromPem(swapped));
    // Text around the block, including a block of another label after it, is ignored.
    const around = "junk\n" ++ kat2048_pem.pub_spki ++ "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    _ = try PublicKey.fromPem(around);
}

// ── R7 (2026-10-14): 8192-bit keys ──────────────────────────────────────────
//
// openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:8192 (OpenSSL 3.5.5),
// then `rsa -traditional -outform DER`, `pkey -pubout -outform DER`,
// `dgst -sha256 -sign` over `msg`, `pkeyutl -encrypt` OAEP-SHA256 of "oaep-8192".
const kat8192 = struct {
    const msg = "zig-libs rsa: 8192-bit known-answer test";
    const priv_pkcs1 = hexLit("308212280201000282040100e9e618c8364f6d569497698c1977f389dbba4f2ba08feb9854966b1c41a7b6da26e44ddac235a7b32413dc52a31d2c4f77d7df396be9b84fe056c9780b1a492d4e04962496d98fbd7bb3ca5833c0754850f4a04e702314993e587529aafa5ca5c850c2a9f692d6343033a041f93b83a436c8665cc9e93b01f7696e419156deff549f141c1296783ee846640d110f55b08f9c82c04c154dd46a95a187d9b8d0ae761166ca9db06d4d1e0cd420f59ff6d8871c3b3e389947a554046547eff5351e6f16790054acbf1f9fd302581827c0b8b1236648c75d943d15ee6eb3be7c22aee47ea32fd3008172afe6293daa31e2c6e040b5361b0c2fbc1deacd128032607e8ec7bfb8efbed08b474142a60f1d59d4dd7a27d58b2cbf9d865b27262f829b8ca608016630375f9b18816b5413432a4c785ba52bee753ab1a2b845a1b081d0ea93e467b4453fb25b1b3204912dbf937cf5bb1db6bf6ba7947989dadda9321b9ebd3bfda1b526b052e5e4690f1e1de84bd45c7dfc6e86ed60cb626f940998af74ee7e5039fc2d45ac928c1b5ec4698972d200b26269929bd0ce4870299d208242478df32486bf5a50a8b43a825befb37547c4fd4ca7cc22faeae148bf607a15ae61421beb7eee08119290502085ad6d1ce33c7c89be3c3f54a39c9ff3055132f15390972d20033fb2f00f080a952b62ca81f37cfe9de4fa515690e5cfe8918f13b59b507ed5291ec008e27c140623cce2573cbb8f238bf601c82f1e423533ef96c9ed86a9a681273b5b2f91ff9c831bf1be098e37f4e8bf3baab836f51729a82e2f115544c7a09529d46a54987ecdac0843f7195a0d03117a99624bb3d9c957690d834024778fda194e90e0e2742df82f7dd1cd377aa663b3d305ac13a5bf6df38c203670b457da43a91530958277e28fbb018601f9c891afae2ffd8887887c2d4b4c61755f0fa589426d9e0585b3fafd0d1f5268a173ecf5829fb59174547d41b63a865b7a30e233c7fe206b4f47c512038f218a228cc7ad014818d26f732a1e1db4f6eb2a00f90fd6a800675f86d15eb1260d98b4ca474bd0121df5c20cfc98659bdee1336d8c707bc436033db3e0203ff0689b7a863458669f1a310dfbd9fd8fd96579887cf056c6b6fc316adb8a01f3b729c1465f68cea05e24723cbae8f26a749194cbed436c0b3cbd757c78f17abd6b37294175859a904e60cd65f3a9e6141c208ee92c5fff76ae4065d2120f4d0dc5790b153027e1c2855eb635d29f74fadaa7911c97d8a37529311bd13cc1bb7cedc0eb1f470943d9c2c7a065437df075343c0ca2f0e872ff5197677f7614ec16c74cb2233ba654b0d39323b6b3777e77f25d6d2faf00ab9a127275a0e77fd939122a07282b770deb59910b6aa14e89788e97260672dae85ce2a7c8a70b93f4199b372122ba5cef984e8e3de9efbcbb02030100010282040019b7c925ca82f53cbddde0271d6dc903717b8cd4f93499ed07effa1b0345139fed02d164aa5207fc748d127eab9cbb908956dd1e8d3507a510bfba2b4edd370a9a377ae2cf0b60f8aeaf5822569e64c6eccfd90886dff495dcfb10f6e1ebe16001249022ec0fbd29c3db0955f7b78983f6da161741c4394ec00b81aa07f70b51fbd5f9fa14392343977a95e9b1e483c18428eb5f857e1a2eaf0180df551b3326dba8922ad927dafccdbf0f5c0865ec586692be18db544f4268788b425baa148b221fd0722edd47ae8c7e4115baa234589a718fff949c3f7e6ff8e58731fca83b9eb825ed4e4011fbb0479865455f72d5f73666366ac6ee40baf16457126d779ab2cc57d257da1d48132fa3ca6a8309ab9426a8569c94f104bb0f2ec0ce1c8849f0bf9497cdd968d3bee00c1314832015846e5f3cf35d4474dfb56f42960bd012daec1453080236f4398b4861462c78651707d9fe8c11a43d7917a54f1619825bf3e6b2bea3127bf4c17e59e6e5a2d835ee45b53c9a528fab42f1b1df0f2710b3c4bd72c8cd6794efa2b57114fc77b63b3fc7ffd53e52767b811309f2296ab7a7de0247a7ce811fc71aa5a6814ae6924ee4f34dfeadbc8e64148b6cda4e1b5e62ec22bebb281bb81b668823a74fcb7fe1db427d570fe9c3f4e480863dcc69df3615c0223f3df3dd7f29521dca3c18a726291fc2b0a45fd6fe368c7c185e34130d1bec99bd07cb0aa581a2df5590ca587494f538fccc9bef55cd845d67a7285ef7e5676948e9590709223d713134f47fd82accca4977915cbb04ecbeea9d085593ee8bfdfecfd4c85e184590d1d2ad959c0b773e3e0c63dc9385da3995d7fd11868a28ce5336054baaea994e1cdc3941e8ca5b02feaca2181d5b3d5b398f5e99f9aa33edd85fec03753a28b69f832598dabee426efa6aae6e317ec19701f498bd7fd84d4011c0589e1bc9122b5e082bab0c2d8ad73817db3c4c83c582f64bbde6373ef766f70c251f4af4cd3e56cc7eda7ff7436b0df5043a67db240845d9a30d04d1ab2d6546c2db9f3c2d7681618d8ac25ffbf266e76b499a0dd7efccec52dcb03c2f755474442c6c970662f64e4950238dc22f83fa73f1347872d95b2c0af7d5c7f87dee0274bea4970a0ddc69e6c96b89e07879101e2a12aefda1e6d0ea70e041280af3a6d3612bab6623e8cd9680784ab8219cb3e642d292c33d419041a271ff741db8fc7eaff43b0cc9bb9b930f1c51a42bf0f4ee8c640c8681cec5f0b405fbe26d474cc90fa3b19d3cc9a23342b1c0dec5e10392ba562a8160b1b9e753c696db915a410e51550dc6db9fea9c4e01d80d14d1164602ebb22e90e75fe96c0e612b5e4e8850348fa4027e9723ae017555a388cb1b2b5367c53ab071c1dd6e3fc90226868c493f3ccc770d04773b1fac335d2d9843cd4d65856edbd6eeffd910282020100f68bc4dffcd5549bbb39a783d63e20d9e1094b114958551e0958731ee2270a13c9eb46edbadc451f13e715e308b3d3ad8a7ee69e172fa79ca173d47a5313df6fb264d00369fdf1d03377ae1612039a264ace8d5abb4765eb2375b6ba655e5083c2a067c4f830d4a5ff7be2e13acb707c2bb4bfb8dcd4f8838cb7f03240f2789da05823ac161fb1f7aceba7570e605755b7e32f51adbb9d762a7054b3313d5879600b5313eacb9df25bcf817dc9a6ca1b93441e0972b1096eb51813b1e15bcf84cba229f2b6228848359382096285fe71b102056ef02d83ab3b28daab9108f999b6bc6f5e231d6663232ca0c6ef6d2bf16d0d88025f6a0962c176273f65c0a1353df5eb2cbf35811b97221c5464f2a3de4af051192762660fcf4fc2c29d49ab4004ec780bcbfbe0771f65fdbad7a95f677d00848559a67b4afce1258f39f3b6b642d399f63805eb07db5f85aed160710bd58b553b32434f7c2e9898baeff74a526bab776e0694ecfb92990ac0248eb71afc98a3d28e3aab22db4f480179d20ee854c66d61325f49c5ab934af168176d95ae075e7a37037962fa1c2a4d5fac00d798ca3eefe372ad6abd3941462ac6f94b0bba629d78bb3423a3d6b601fc6155228a1da944c5510d72a4af4e7b5716ba6828d38990c4805d5cb0a2e332ae2dbd13bfcfcf97493209a6e8974d554ae3e521a9580452557a3dd3f9b2d094341658150282020100f2de2d227325971b696d657e5940a52ddb1a01393b04f308f2462feef06df2ee58a296b0abfbd64f63f7b80e6ecd55e27b69818211a1eb334340fad66cba882601549c2d317496e285e39ea4f959de621cda0b7d57c693ec06aa73dc9f717059c1fe0a76ca501c88e633971da20a476594a006422a1e453200b7f0a3b318155ede030b705bd7d5439d4f610543ceedc36f83067a61fc6a2bc5db0986f0ea0ad9e221624b91bab0939dd459871f6e7d479812c1b00199b47916f51bbc957c03858e31f6468c258f50c6ba5e125298e7cf63f38fbd7aa99f6c845f65232b7c8191e7ae6ca81fbd331aebba1225ad86e58d24fa917252eb773cc6739c8964aed09db7abcf75b19fc74c3794669188f6e21070433def39a671c15b9c2e1e7eadfb5e4333d2fba04a597f8b1385f1de4a6c5b53a8803afb60e84a3e7cbeb78e6d865630d8dbb4a2aab862742d30361c240d4bda32344dca208a4291fa190f848b5bfb08c5dbb035ab75516256fe35430b74cb9bcbda37f4f2c8cd0ee7e657ec63c4398dc2b5ddef28821ea7b11479eb886f6ba4f14fc13ef975a3f8ae0cd557d071212684304ad1e0622ca3842c1f9c98d063a4102779403a553bf224933065f1e7431a408fcaf7b128a763c2fbd8f5bfeba90046173a8e095a9761fff4def2b38cd90025e9927697b033ffde04d7d1643d43cb8b19d22c7299ea3259df7884b3a58f0282020100ba74e223f3f6f2d2043a8a31eea975f6d17651cb7508d4f6ae62b24dbd03815f8de9ddee94cf5987336a24e75b0185294e00c330f4a019c71f6396621cca7ec4dec9d7777d858c87c524d207e6ffca6903524b1d3f5db3faad0aad73328ead9db867cf92eb91228198427d47914ba27a8623608bd2974e8b4eb51d77241f3c91195f0f3b6a4ff62c361ed2a3c83f9c4d3b91198c5033ffd60a2a8224332d0de85d76b311f114a51351d4113eac6ef392ff4118e6545307ab2e525332c818c34ccf24894d01ea03df78856266ee981fe2a3d7bf7c333078cfdb21fe9e9a458b5f710ff9b9dc1cb3fe6defa6784d42e764e2f0c4d7e6892f27fcdffab6bba17f49e0de4749c42216ce62f26d327655fb1076e460b101542d93ef598715e01682e91bd02ac9e12f508746bbbfb4babd6165c6e7c9518087a3df0678d00b0decff55c01c7fe7f25ea76d7dbf343f0e223ddc91579ad1f62569cba501cb2035b37405f95fe826d1db778e9b441b194d8c91765b6aa51aec6dfa57963cd35c2a616edccea072c07b740d3aed93abadfee718fd866c144ba1a782fa13e591288b1e6e549f3cf5743f33cf6b564822d18a308900f491b55b1a9f99c30a79ab94bce66f987b940b1bf38e64f93b0b49f385ddae846fbbebe20c7a78214d852306852c1a3f01658cbe01a1522364ec689404db6dc2936bf978bb2483f5f875ffc0d5d3c03102820200332a8999bb668cfa3270e0b408bbacd1075ae82d15790a76b50c02673572047f205f489df9edb98dca42d31cff4cf52e1ccff27fe3951847198124176e9ab1ba48077a4baf229ff3233ffc19478b1e65cf2c44c5686ba698502332fba4ffb22ac6caed8b6f3e0774f402a47092c5d59ada0008b181cc14c9df0ae180ab6784811306d32f1dba4fecc9c4826d2886fce272a8c901998923190bbb04bbd01f8e9fae9b57e911cfa209c7738855065331c3968f450cfe9952433c89f108fef93c88b397650a21d67be609a813cf8a653a591ff69d2ecf1bd3417a75da89d94c86c3a56ac2eb7c9c509af854a0241df5d080b6ecaf1dc5c863bb8317b23fe3dd4c881dbced9d1f09c9640e458e8254b7a692ce03ec956cb0db40603b7c1fe29266e5ca04ae0b630ea6e24efb92f98cda630fae854e569ec520cb1b750e7cff5da5b29ce1e30fa041954cf0aae08055d76691b76b62478d30e3cff88f171e84cf1356c4d7625c32426819f83cd99b80ff75e0bb76ec0763ec8e4f5d378ff8b00da8b6735e351087a5221cb1398655d5404e310073f258851aeb24db6c57b9cea1546426882ce0666cfe61e7251e629e8c3742f6ba8c8667f8a22259f648a826a21b15b0ff2f0c14b8d716c4d6bc564e17dbdf23f6a0482eca5bb28eebecbbd7a7ea21817d7b42e70738110c73cad36902d441672d6c0832630678279975921f6af5930282020074b83f9fe126b962683439ae02eb606e636fe25e0bf180f31fc472eeae230f2af56374b7b179455680e5dd9a0b241737120bbd86b7ca5d9c16103a921ddec7417abfb32385f88bc769e9d92bd32c711406fb2089a3b035355333e7f4bfebbfd1d50200add5f830bdab0252ee3614e47bc8867b22c3c57184ab0d6fbbf5f9b51721b68ff39eff427dbf8e7815dfbe8eb6c47912db39d6e865995214f773040b53274156e650d8e29cdda72fe8c9c5c4e82c6867272414e912caaaae34611c0ede73706540211904ffff416c726af94c7c35fcb66944c36a06d6c40bd7d9c0b96be801c4f8843cf24af2f5c2bd4744aceaecf80c30bbe1309c84cbbf7e07b40cc83e88de020d09693a340bf7d26db3cc834d7c91739a568affe87b6e71e7827882fcc3bd147f9c32a03ac7bdacd8c69029018892f6f8f1c3ed1428a9dabc7da018aa078ebf953f8fa91a34c7a8f6ecc8f8abcd750b5ccf190e405ad2a4f222efa2354e1e4034667517c8b79af958a72ce5f21020bb5af9bae4c954e128ded572756c48103d3736af1f4ff04cfe4434e5b5600b7013361aaaf1d1831d5c885a8a9b14c52885aad7144f7d8ed1dcbc8b7f6b80f38dddfc6c92de75d517e1ddee177440dba50e553d4d2165dcadf9a7c042febc494b116341164fded202e9dbe5f1638f0456f002324052e6916cf9da075deaaf59560ddc0d01ff5e2042d244f7e711");
    const pub_spki = hexLit("30820422300d06092a864886f70d01010105000382040f003082040a0282040100e9e618c8364f6d569497698c1977f389dbba4f2ba08feb9854966b1c41a7b6da26e44ddac235a7b32413dc52a31d2c4f77d7df396be9b84fe056c9780b1a492d4e04962496d98fbd7bb3ca5833c0754850f4a04e702314993e587529aafa5ca5c850c2a9f692d6343033a041f93b83a436c8665cc9e93b01f7696e419156deff549f141c1296783ee846640d110f55b08f9c82c04c154dd46a95a187d9b8d0ae761166ca9db06d4d1e0cd420f59ff6d8871c3b3e389947a554046547eff5351e6f16790054acbf1f9fd302581827c0b8b1236648c75d943d15ee6eb3be7c22aee47ea32fd3008172afe6293daa31e2c6e040b5361b0c2fbc1deacd128032607e8ec7bfb8efbed08b474142a60f1d59d4dd7a27d58b2cbf9d865b27262f829b8ca608016630375f9b18816b5413432a4c785ba52bee753ab1a2b845a1b081d0ea93e467b4453fb25b1b3204912dbf937cf5bb1db6bf6ba7947989dadda9321b9ebd3bfda1b526b052e5e4690f1e1de84bd45c7dfc6e86ed60cb626f940998af74ee7e5039fc2d45ac928c1b5ec4698972d200b26269929bd0ce4870299d208242478df32486bf5a50a8b43a825befb37547c4fd4ca7cc22faeae148bf607a15ae61421beb7eee08119290502085ad6d1ce33c7c89be3c3f54a39c9ff3055132f15390972d20033fb2f00f080a952b62ca81f37cfe9de4fa515690e5cfe8918f13b59b507ed5291ec008e27c140623cce2573cbb8f238bf601c82f1e423533ef96c9ed86a9a681273b5b2f91ff9c831bf1be098e37f4e8bf3baab836f51729a82e2f115544c7a09529d46a54987ecdac0843f7195a0d03117a99624bb3d9c957690d834024778fda194e90e0e2742df82f7dd1cd377aa663b3d305ac13a5bf6df38c203670b457da43a91530958277e28fbb018601f9c891afae2ffd8887887c2d4b4c61755f0fa589426d9e0585b3fafd0d1f5268a173ecf5829fb59174547d41b63a865b7a30e233c7fe206b4f47c512038f218a228cc7ad014818d26f732a1e1db4f6eb2a00f90fd6a800675f86d15eb1260d98b4ca474bd0121df5c20cfc98659bdee1336d8c707bc436033db3e0203ff0689b7a863458669f1a310dfbd9fd8fd96579887cf056c6b6fc316adb8a01f3b729c1465f68cea05e24723cbae8f26a749194cbed436c0b3cbd757c78f17abd6b37294175859a904e60cd65f3a9e6141c208ee92c5fff76ae4065d2120f4d0dc5790b153027e1c2855eb635d29f74fadaa7911c97d8a37529311bd13cc1bb7cedc0eb1f470943d9c2c7a065437df075343c0ca2f0e872ff5197677f7614ec16c74cb2233ba654b0d39323b6b3777e77f25d6d2faf00ab9a127275a0e77fd939122a07282b770deb59910b6aa14e89788e97260672dae85ce2a7c8a70b93f4199b372122ba5cef984e8e3de9efbcbb0203010001");
    const sig_sha256 = hexLit("5deb9438222fbf380e1a1747b289323f1156016977c4fbe378499add23f51f486589b3c575d1e799ca7886ad4f6a89251457fa2ba79f02f5ba3be6c1b0a77906e2b86c5fae70a6cdffc9f4c3363dd686cbd92205f835cee0ea4b180b92a7a4d89640a7ee85b485c5220c1c880c0aee686fd9b343ec97b57a79bccc2c4af1d64d1374400fe0dab49b6030a0de1f937c81e8804b2c67ac7978f78e365981ab57342a5b40ee548a7446965d3126d6d5d1eb999d8e1effcbe47b6bf8c59dddc05ffb7d04a0dd03912931ffb14e8703e8ba095f227189ee39d8d01bfb7ef717056f7a5cffb41eea3e666891ece24c7d3acaf7225a92a41066b7754e087fbc3a4709800556acd173b0f012bf10bf224980c93d60b7a789a34581c65b8bb9f6a01e1963ddd044d25f0a39d34332934d3e124a06ffe0edb42d03b171685491f96c25f7ee98db6fd5b86653764a9aafa972ebf35899cab1db0cf62a42278e904332820308e73c9e84913b22346342f72eed30c0e2cd32740b7fd2b7ad258d242188281a295ff20a1909def2e6f5c92642736c0fa9ce8c37e4a4a334d7d2bc0818a0c15a809f69e1de114cb8cffedc4b32531e6a5c73865f95b15ab517d1f1511e848e2aaf2dfa59d2cb99e633976c492d9dc0c2a894d0b71718be61066c856eeb4a6bcff6b71abab904acb0953d48d3558a58dbf95d83bb19767fe593945bd7b45a122643b7620d50dcfd835ff860075d70917851a09ff68ea1d25ee753e72c3120ff71b0d462b275a6b46cccd9b0918ee1937308e020288865ff31bcda5479bc74117680f7dcea3c2e17c544cc2d136910bd13523524fa77df02a65c3e300f8aa1ff1822d245addc00ca547d18853c69bc0eb213ba3f910e47652f3f7c13f18978a36e68aa4e0d11a9e00ab29047f9c6f875a33825c11d81029d55676f70723e46e54f96208db1f802033bf3c1607585fe3cd2ae29c87320e0242b1e561e31a69005bd86ac91aa7a83efc9061c5c4d773173cfd322eb060d938c193fd2bf08f5fa175ffe80fb7cda5663b6b2cc4b94ee30d8d22e94412447d71839141ccc017712927bcea532ac03822473477dc6693bf2203e3f1f3d6f21ca6b08d342e209de943a14505670eed6f82b39562fce8d36c487c18eccd2427c5f5cdd3aff08464f2afe1294880fe325c77eb7302fe7b7e3e298570d47f1062580cd370a594611e1da00dd96c7641dfe47ce0576f7cc9088efed8194f4a04e6d3a1e7bae2adb1d814f74f45a558108b22344ae372e61a79a86f15246810cdcb6e6dcac21ce10e7d5585e20ae7c38ae55cb93fcc87e5e4516ef1a7f35d04b70b2e4b2bcfeda85e1449ce4eb028648b9abebfe4bd7efc1920bc0099199398b9f51413d0ea0a0bf931dd3a39977ac275ede72ac810ed4c7c665670e5d4e3d16bda3d6315507d0683b7a80d202b2");
    const oaep_sha256 = hexLit("1fce955e23cfd5d4fdac7f15d866188c2cb73244e654b44a44564a902e1a3d9c4f5724f45843bc72e90279193ac9657e75926bd43c514a0c87617dfffa1a945e6e00393c5c671bc5ba2996d162521a6191d0774b1af4b276c4643ef7829a5e5a046f541f014a263f81bdc34f2bffd7c0e26a24d79a7a1a886ce9e49e91183b13aa666e9a4abec734715d50b8219503b1b4992949097673eba28a358c72c989595d59d82d7bd22b28dfa82884d29bab5bf4ee520b3c46461a1f6ec2781057764fc151ba7ca828d0e2f26235c998f1d01a49f1225602b9ed02a964d6057965d2f83cd92d7d79b1ed1df8fb1b341e0bc07330e1cc653bead053fbf181827c22d0094a13122e20c3489fedc87aa69c31db460388a30772e5802bda8c04809b1d7019230371161677499e3afc3a309bc87b0a693ac32d946ee23ad239649a223092156923d0eef55f7b78b6723d39db992ecf1a5ebb582d5db9db07d3989bfc8a8ac20ab19b5a7767c97d5cabbf52ec9034f2602ecb48610939f0b7b8208009789d7ee60e6ddb1a55b53ede02d07040162cdd89466c835160c5e5053ad142a0dd79e1e80b60234af649655904c9f5bc96f1b647c5f0688aa8a4fa17438f814e468d6c8f4759bb8e77fe6e8fbda1f295648a88efdc0921b619d94c425eb3ee67ff75f47e07e4cae75f15632582a5f9f90400fff4d7bfbb6962e3bbf056d912484662c460952e41a3fbda63c2f1d7732a76cf4781b38b66f2981dc601108bddeda3804086793c1bb5bf98940377edcc479ff9fce978779066bb7072c66b481eaa9d09f30fecb57ccd34d682e67693dc1e1f31bcbdeed77b38cdbe5c3d27e75c0bd205e3d88447df66bce95111fa9d67b31121323e32b1861b751e9363ba14298c39cf0b0610e4cc45ed2578cbe15be110f42682cae272de82d92f4280361209f7dd6108a7be0df173165f469f716ae21646bc8671463bd50279ebcc4d05eb08f0f20e36b06b442f6be1306c1414465dacdfd3ff38f75dfa5fcd01d6586990ef7c4358506af9be98578305905d6e0a3185261819a2f1b059a8b07e8603784e7cbc7287b7783b7d5e60cb878f163ffd35c0c713d4b79a96b17fdb483c373ed82fbb13b7eb2422ce2baf7fc1083cb6e0ba828bac6b09c4fbaa9b553b2713348d00a0004ee9e56add85235b540fbcc487fa0f0d8e36a4c4c0857385300c4655b7f9c1911fd93ac93cfcde1ac46452b0dbdef4eac30f847ba5cc7a7e50b675ba451c63b1b53f81dbbf2e1be9dfad2be195c48ddd146f2d03c1b3ae65bcd7e6c8ddf1e77d8681d3c46fdef6d286ab72addd986012fade6916bb6acb8bc76bb6cff27d70ccb804ff050e4fb1ca8e05e282e0519b737b97c9754e676d5f6e278a118b4f6badf45770a2195f308cda1a48a83c50f029aa2e117d4ae96f2ae513e5e6ec6fd9b1e973");
};

test "8192-bit keys (R7): OpenSSL's key parses and round-trips; v1.5 sign byte-exact, OAEP decrypts, PSS both ways" {
    const Sha256 = std.crypto.hash.sha2.Sha256;
    var sk: SecretKey = undefined;
    if (max_modulus_bits < 8192) {
        // A consumer lowered the cap (`-Drsa-max-modulus-bits`, `-Dprofile=small`):
        // the same key must be REFUSED by every entry point, never truncated.
        // (Which error depends on where the size first shows -- the DER
        // wrapper or the modulus -- so only "refused" is asserted.)
        if (SecretKey.fromDer(&sk, &kat8192.priv_pkcs1)) |_| {
            sk.deinit();
            return error.TestUnexpectedResult;
        } else |_| {}
        if (PublicKey.fromDer(&kat8192.pub_spki)) |_| return error.TestUnexpectedResult else |_| {}
        if (VerifyKey.fromDer(&kat8192.pub_spki)) |_| return error.TestUnexpectedResult else |_| {}
        return;
    }
    try SecretKey.fromDer(&sk, &kat8192.priv_pkcs1);
    defer sk.deinit();
    const pk = sk.publicKey();
    try testing.expectEqual(8192, pk.bits());
    var buf: [max_private_pem_len]u8 = undefined;
    try testing.expectEqualSlices(u8, &kat8192.priv_pkcs1, try sk.toPkcs1Der(&buf));
    try testing.expectEqualSlices(u8, &kat8192.pub_spki, try pk.toSpkiDer(&buf));
    try testing.expect(pk.equal(&try PublicKey.fromDer(&kat8192.pub_spki)));
    const vk = try VerifyKey.fromDer(&kat8192.pub_spki);

    var out: [max_modulus_len]u8 = undefined;
    try testing.expectEqualSlices(u8, &kat8192.sig_sha256, try signPkcs1v15(&sk, Sha256, kat8192.msg, &out));
    try verifyPkcs1v15(pk, Sha256, kat8192.msg, &kat8192.sig_sha256);
    try vk.verifyPkcs1v15(Sha256, kat8192.msg, &kat8192.sig_sha256);

    var pt: [max_modulus_len]u8 = undefined;
    try testing.expectEqualSlices(u8, "oaep-8192", try decryptOaep(&sk, Sha256, &kat8192.oaep_sha256, "", &pt));

    var prng = std.Random.DefaultPrng.init(8192);
    const sig = try signPss(&sk, Sha256, prng.random(), kat8192.msg, 32, &out);
    try testing.expectEqual(32, try verifyPssAuto(pk, Sha256, kat8192.msg, sig));
    try vk.verifyPss(Sha256, kat8192.msg, sig, 32);
    // Blinded CRT and the non-CRT path agree at this size too.
    var out2: [max_modulus_len]u8 = undefined;
    try testing.expectEqualSlices(u8, &kat8192.sig_sha256, try signPkcs1v15Blinded(&sk, Sha256, .{ .csprng = prng.random() }, kat8192.msg, &out2));
}

test "modulus cap: a modulus one byte wider is refused, one at the cap is not" {
    var n = @as([max_modulus_len + 1]u8, @splat(0xff));
    n[n.len - 1] = 0xfd; // odd
    try testing.expectError(error.InvalidPublicKey, PublicKey.fromBytes(&n, &.{ 1, 0, 1 }));
    try testing.expectError(error.InvalidPublicKey, VerifyKey.fromBytes(&n, &.{ 1, 0, 1 }));
    _ = try PublicKey.fromBytes(n[1..], &.{ 1, 0, 1 });
    _ = try VerifyKey.fromBytes(n[1..], &.{ 1, 0, 1 });
    // The cap the build asked for (`zl_options`), and the grade's default.
    try testing.expectEqual(max_modulus_bits / 8, max_modulus_len);
    if (zl_options.rsa_max_modulus_bits == null and zl_options.profile == .default)
        try testing.expectEqual(1024, max_modulus_len);
    if (zl_options.rsa_max_modulus_bits == null and zl_options.profile == .small)
        try testing.expectEqual(512, max_modulus_len);
}

test "generate: FIPS 186-5 d > 2^(nlen/2) bound (F2)" {
    var sk = try kat2048.secretKey();
    defer sk.deinit();
    try testing.expect(privateExponentAboveHalf(&sk, 1024));
    // A d at and just above the bound (not valid keys; the check alone).
    var d = @as([256]u8, @splat(0));
    d[256 - 129] = 1; // 2^1024
    sk.d = try Fe.fromBytes(sk.n, &d, .big);
    try testing.expect(!privateExponentAboveHalf(&sk, 1024));
    d[255] = 1; // 2^1024 + 1
    sk.d = try Fe.fromBytes(sk.n, &d, .big);
    try testing.expect(privateExponentAboveHalf(&sk, 1024));
    d = @as([256]u8, @splat(0));
    d[255] = 3;
    sk.d = try Fe.fromBytes(sk.n, &d, .big);
    try testing.expect(!privateExponentAboveHalf(&sk, 1024));
}

test "marshal: generated keys round-trip through every form" {
    var prng = std.Random.DefaultPrng.init(0x5eed_0014);
    for ([_]usize{ 512, 1024 }) |bits| {
        var kp: KeyPair = undefined;
        try generate(&kp, prng.random(), bits, 65537);
        defer kp.secret_key.deinit();
        try testing.expect(kp.public_key.equal(&kp.secret_key.publicKey()));
        var a: [max_private_pem_len]u8 = undefined;
        var b: [max_private_pem_len]u8 = undefined;
        for ([_]PrivateKeyForm{ .pkcs1, .pkcs8 }) |form| {
            var back: SecretKey = undefined;
            const pem = try kp.secret_key.toPem(form, &a);
            try SecretKey.fromPem(&back, pem);
            defer back.deinit();
            try testing.expectEqualSlices(u8, try kp.secret_key.toPkcs8Der(&a), try back.toPkcs8Der(&b));
        }
        for ([_]PublicKeyForm{ .pkcs1, .spki }) |form| {
            const back = try PublicKey.fromPem(try kp.public_key.toPem(form, &a));
            try testing.expect(back.equal(&kp.public_key));
        }
    }
}

// ── R3/R4 (2026-10-14): run-time hash, prehashed verify, PSS salt/MGF ───────
//
// Oracle: OpenSSL 3.5.5 over the kat2048 key and `kat2048.msg` (commands in
// the comments); PKCS#1 v1.5 and salt-0 PSS are deterministic, so those are
// byte-exact sign KATs too.

const kat2048_hashid = struct {
    // openssl dgst -<hash> -sign kat2048.pem msg (OpenSSL 3.5.5, PKCS#1 v1.5, deterministic)
    const sha512_224 = hexLit("99155048b2f8c9e46f59d10c82103912bce2ba0c08564d4f8db6484b98d8ff1c9211fa771f6cff0448a247495ba97c5dbaaad0d48b98d0b69fff72f57bc63f7e85bf4bf242601f55961fcabdc773ecddf7d68a1229da97d7303095d6cd78d26266834464a8fa3bc7ba1534c8b453d424f5ec326b6d52655dc4a041cb7a07624e913fb08311947be767bf11a48f3cb50e50c763a2b51f2991ae3785e6c412d73e33d661809b90999c5bd1f9e11476d90ae55fb7eb55804045c1488f02247256b1c091f2bdb3755a95bc63ff3edcdd4bd647b8a05634e0c426333460b2bf8cf7f4e4dada1e019daae5922d87bd56545359ed01931e8ea734df89d64725ea1e44a2");
    const sha512_256 = hexLit("0ab166545ee254efc88963f88b87d893370144210917f45a832a5d78d260f422f0fba89337e8deb0a50e61ffc1912d46481ea0a8f258942d9bb6399e4ec0b73012ff3685125ff02acff8ab2df5dac1d7a3ec300f7c2269ee7213a6c558cf2b9346272b4f315645852e30d7e8466e30e675abd389a9c02ee6f5966c767bbb41cda8ae604f472dd19071eaaa8a1519162d94cba8517ff5aaaf3b044dede4c33b9742f73a96086f6a61bca9e0c595caf808d03db6ebf747251bc6d258e31b38a3623f5fc2efa9ca593abdd1fb4930cf6fc20f9c928ae82aa3ea494a09687d8c6c109060db25bf17e94afc4445cf0eb3d925fd531efa2b8f598956519585cb5378bf");
    const sha3_224 = hexLit("89844722208bd264f4247bfe8586de7718342d89a6807f5232765bda843c7bbf31cfd65f407f0d03bc8d05b1dcc9bea6c89da645d9f0a7b17a4c299576930d9dd161c3fcf834679955459f19ef44ae796ccf80e13c8d9a1df83cd6ff526796c8df2610346f14939edbe1fb7ce49fab639066b218db37562373981e4204bfac48071bf60ca94182706ef2b8db8321a253ee836255b614b120662e424048cda81e103599aee9e88ea9b80f5e663f605a2d5192ee399d2eb00b323f3ce855e0752ded4d97548b9806d1cd4ff5a99dcf2609a9adddc5194afe691b27a40400c6c5bce30585dfe05913ab3d38b556f8c189a2757fc5069cc0e0a6311ed4ef368137fd");
    const sha3_256 = hexLit("4fcf92294adcf57bc9ed4b4f4d1e98613c59864cf2f6df38d7805939b68f66e6bd1e694229d25d10cfb749aa9b1b3517561eb09df32265c02bbc8fa6617f8e59f2363a64bc0de103901ddc923d2b0728996989b3d2d4b689affa37a077ed9b8f5f71089f77242b10270a1a4cc1ba9aa0a78fac2027159364ac82fc4078e1ed50f45af2b7c3819991d38b540f601271dc6de7e3648914d96c272f471863c3017e7efdf8d90f8cd996648e5a1c774e797f1bad0b46cf94b04b920c61dbcfaa0cad5431a6d7fe4fa304ac34abfcb4599b322b9322fb2b9f93e01c765c7fa4ff46861c75295becd885bdff03cbaec2241599b40f243ba2ca4a56487c070e046fbd08");
    const sha3_384 = hexLit("994a0bb5887a0a8beacb6b0918780521da3df1db6e630215944ba30ea82ad91f2033d0bff6c6b98b97bd4b0bffd0060f206db770aadb96869d6e129cb4d4e53f12143d0bcce5b812acab0624e7721fb015b44d6b9c451940a1b5492672bb4456838e9523630db36ea51689ca877e572e430e3f20e726a89ac37100bb63ce2c5903764405a33d44c34fc6500a63a8a01274636083559c44c9af967e120ee96297f44bf62e642a10556b2ff6547a681ff51232ffb187ef11b6d32844eeee54acd3818cf172fbd7cd40d6f8bbfe023555a12e7462d4a9e9c24efb486ad853084d41c9ee625dac771e5c3d2094eb257f0e649250c8d07203dfbcd39ba4f272e89ee8");
    const sha3_512 = hexLit("62abfde99917a476e6ff8311aba9ee433a415ab360aa925df4b8e9b9c1ae4e1b1d86ca5d46d1db077e821ad8a59a149dcc5745b665a85b89d185f53e110f218f47a7866c7bbc6e305ca6f9ee5bbe0d8267bcab734b6cefaf96fa04d23024be00e05b749eb16f31222e8a4f67eb5c3b90b21b9219d6ac051b0cab031e5b4b31c83749dd6b5003a215e960851ff59861d9675cd65d49d89ddeb3c6160a2b791b7c5ca83da61cfa46b2b4f1c5fcebe46bef92f7723cd6483f137036739a313b7aa3a0460d15f47733d516b6a09253fa1283cf4cf363c35a9bad6a164de089df1cb476b9169504e3c372efbf668cc8f5a478fa7e8f0c572ff233d8f2e4eafaa42ad8");
    // openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:<n> [-sigopt rsa_mgf1_md:sha1] -sign kat2048.pem msg
    const pss_salt_0 = hexLit("2e6f8537447e18455f1bc67a5dda7c1308a7ff36ca58b0bd016ce9a74b7bc54d7a0c269b65e8625fddc55f3dbed76b2a6d4a20b7dd532f2084a9a8ebb86c0f588b01ed0c56c8cfe15e2ed83cbb051068743b665d5935df37d95aefdf3bbcbd61e1db1d8adbc05162c9bef2672b705030194e86b2f2da64fc4948948e98c760335904bbf1501a7aa2f79a01eefdab7a53506e89f7a17904f575586cdc46ed7d8b211a80685b13eff8e5ab62c7171c094a3603d90da0d33f4aef0316af828568a9a8780e315b52fa602f4ebd134b1ed0f9218d399473c4ee4970e00429a5225de7c43096a3523e66233f9b5810b6ce8f02cabdf77d989b95ec94a38b606709dda2");
    const pss_salt_20 = hexLit("3a8cae4e6ff61fda10ff1787fe15ddb5305f5696132404f9a0b6c7d5a1f8bd14b3c84291a29a5964970dd22e99738acc120e9a34c1017e3d47de9f8c1f068bfdd379173e5dac7040df0bc735fc2af180b8cc87d09be92d02d8a3bc23e68cb60c64d3ad42a0c37079e5429674155b3e6cc2a2f8fb17b15b9928acfae0e32bfc57f7982ddb578e214d648cd84f08a8c79e617d8bd9e3d954121eb40aca9e1a0edb1fa1f3df19e3c0c85bf0710e54e0e8a2383f5a054403558d0a2ee7d2d88c93de882edaf0c6a3cd211ab352b3a3662673ab5b5a08d61cc083d1bf8783ed2cba551fc4e50be1332f4b223ea30e32b0b13ef3f7653ca004326e7a1e9015d16a4148");
    const pss_salt_32 = hexLit("80dd4e1c84b179db37a68e4c74c5a43528aed76d25eba959eb36d598179579435445cd7777e5572b25b4dbdb600a2bf77152871304caccbe2538141a3f702ee2bfdafe4e32078245157fa3cb05f0bb1541d2cd105da5e3e32429ec61b0739b9d008755c2d5f413a0e794da54923e20cbb17d6ad342568888d73df5911b617b6be84abdff212afcf17708f1a81160924aecc2a1fa9a0e9c11df08933237fcb4e82b880cfbe30861b654fb4f11ae44d5875a903c1b1c34f13fa135baa2c5192e0f3f0c0aec0ec49db74abe27218126e34f7ff19689c4a919d3024c281e12fe80551c12b067d80a32fd089a1abc7e18463bb5af1f858af80530552196548e5b81df");
    const pss_salt_max = hexLit("7641d3535db9ac03705b1c812268d2857be11aa43b6255ab934713afde1c38c3f0357a2ed0bfd80f518949d29be3e6ae729bd4ac47136982fc1a6b2b3c914095258e10ea1d8c210fbfd9e058649f74a718cd6683f628f1889e6b293136fb292df1d5f1e56559f483f1c1ae58ed1bb0da74806ede009c34cc9dc27bae12ef4bf5116430689114c65db97226e7e621a9d29ff43dba8c92db95eb4fb9da655e74b20d89466efd6ee93df80452b9c053b4e4454da4f3534a649487351ca26ef94d0716d8a7b7d2a7e31a29cfd551bba50282c8580230b8152b7ebc575cc84e9fd093b9038592510e68b7df76044fc4bdaaad11d70b71fa0225f68d0c5d9a84a34929");
    const pss_mgf1sha1_salt_32 = hexLit("48f94a67c4e70dbbe1be0abd4af8fecdd5da5c7b751f842b74a4348a9371376c3ef423e1744cdb886217097d925f1c23e9eef02ca10c76c2fb473632cee52cb521a4098156a6731ec9d20146be44826dde5ae555c4cab9a7fa6a26fc6f675ae521c643c5832770254822528ec795cdf167f67b2f65a60450c0559b8684e18da29c39bfcb1149e4d4741e9e5faccb83389c6a5d32c2bf268a7c43b0b8313f9ea2d213eb646587858be53f9c134b7c81962ad27b37f647ab6e0d4df4168cffb227a54ab1b7ad509a8c5a87e569747ad266b281e031dc97de9b84f6f544a2655f5014ece18c148a696b1c31e68fae4ae06c7d81f3f3bd2f5d8b89c7530484c5d1db");
    const pss_mgf1sha1_salt_0 = hexLit("967955c00a6138ba3a4414990f4ef9ecbd491ff06787084c3c9eb4c1518630b21efa53b6dc06def4895e8719f0d364db7d79d3ee9f6e668b928625f3d5c41fe93f393706f872e8d2285379b8919f4013e8e7cafe61b01ad22bd32fa3ed0c3259cffb3b4cd098bfce599ff8a21e736e0874c81e05853e85667aceaee9ae0f60cb7b5c1210c707fd470169fea8ea409f2e4a0d3c2793333b251253c85afb3ccfb75e1fe96afa13d1aeadd1b59514102133a72355295ddb0497d8bfd2591e7ff0f1137ca9bb48fd77cdf63872669aadedc267e39a12a4049501928b7aa566e3f6816f3b8d6881758cb1c0f2db9fc6f6778c0515db462c0ab81f239a4e39366b691e");
    // openssl dgst -sha3-256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest -sign kat2048.pem msg
    const pss_sha3_256_salt_32 = hexLit("394eb24c7df16c6304c361cbc095bb8bdf049bf32b3e9a33f66f7a5922ca167c301d60bd1c9cf668a53a50adb67855564b39407d5062bc68f49122a1219aa2eea84759e5d59fdf6b693fd08d6073bfdf15bbacf611e3ca7fb79a4ab39f59d51eb28ba1b90e4d1bd041d2073724d0a84d6bc310a37333de1548e82538263732063ffd1d15e770a66b35c8176b0a225e11e5df65556c03b142df633e4b43d51ab0380f491ceac0cb58e4bd5653ef2db7dec7ed618b08fe111cc34375cfccb237615c87f2cea485573b9d39d2b76528a1e63c42d6cfbb35332235a9466129acc788a60736f68fe4e04ed01506fd36f4ce08ce32b8848209709f7b82494aa01625eb");
};

test "HashId: NIST-arc DigestInfo prefixes equal the RFC literals; new hashes sign byte-exact vs OpenSSL" {
    const h = std.crypto.hash;
    try testing.expectEqualSlices(u8, digestInfoPrefix(h.sha2.Sha256), comptime nistDigestInfoPrefix(1, 32));
    try testing.expectEqualSlices(u8, digestInfoPrefix(h.sha2.Sha384), comptime nistDigestInfoPrefix(2, 48));
    try testing.expectEqualSlices(u8, digestInfoPrefix(h.sha2.Sha512), comptime nistDigestInfoPrefix(3, 64));
    try testing.expectEqualSlices(u8, digestInfoPrefix(h.sha2.Sha224), comptime nistDigestInfoPrefix(4, 28));

    const sk = try kat2048.secretKey();
    const pk = try kat2048.publicKey();
    const vk = pk.verifyKey();
    const Kat = struct { id: HashId, sig: []const u8 };
    const kats = [_]Kat{
        .{ .id = .sha512_224, .sig = &kat2048_hashid.sha512_224 },
        .{ .id = .sha512_256, .sig = &kat2048_hashid.sha512_256 },
        .{ .id = .sha3_224, .sig = &kat2048_hashid.sha3_224 },
        .{ .id = .sha3_256, .sig = &kat2048_hashid.sha3_256 },
        .{ .id = .sha3_384, .sig = &kat2048_hashid.sha3_384 },
        .{ .id = .sha3_512, .sig = &kat2048_hashid.sha3_512 },
        .{ .id = .sha256, .sig = &kat2048.sig_sha256 },
        .{ .id = .sha384, .sig = &kat2048.sig_sha384 },
        .{ .id = .sha512, .sig = &kat2048.sig_sha512 },
    };
    var out: [max_modulus_len]u8 = undefined;
    var dbuf: [max_digest_len]u8 = undefined;
    inline for (kats) |c| {
        const H = comptime c.id.Type();
        try testing.expectEqualSlices(u8, c.sig, try signPkcs1v15(&sk, H, kat2048.msg, &out));
        const digest = hashMessage(c.id, kat2048.msg, &dbuf);
        try testing.expectEqual(c.id.digestLen(), digest.len);
        try testing.expectEqualSlices(u8, c.sig, try signPkcs1v15Digest(&sk, c.id, digest, &out));
        try verifyPkcs1v15(pk, H, kat2048.msg, c.sig);
        try verifyPkcs1v15Prehashed(pk, H, digest[0..H.digest_length], c.sig);
        try verifyPkcs1v15Digest(pk, c.id, digest, c.sig);
        try vk.verifyPkcs1v15Prehashed(H, digest[0..H.digest_length], c.sig);
        try vk.verifyPkcs1v15Digest(c.id, digest, c.sig);
        // A wrong digest, a wrong hash, a wrong digest length.
        var bad = digest[0..H.digest_length].*;
        bad[0] ^= 1;
        try testing.expectError(error.SignatureVerificationFailed, verifyPkcs1v15Digest(pk, c.id, &bad, c.sig));
        try testing.expectError(error.InvalidDigestLength, verifyPkcs1v15Digest(pk, c.id, digest[1..], c.sig));
        try testing.expectError(error.InvalidDigestLength, signPkcs1v15Digest(&sk, c.id, digest[1..], &out));
    }
    try testing.expectError(error.SignatureVerificationFailed, verifyPkcs1v15Digest(pk, .sha3_256, hashMessage(.sha3_256, kat2048.msg, &dbuf), &kat2048_hashid.sha512_256));
}

test "PSS: auto salt recovers OpenSSL's salt lengths (0, 20, 32, max); explicit lengths agree" {
    const Sha256 = std.crypto.hash.sha2.Sha256;
    const pk = try kat2048.publicKey();
    const vk = pk.verifyKey();
    const max = maxPssSaltLen(2048, Sha256).?;
    try testing.expectEqual(256 - 32 - 2, max);
    const Kat = struct { salt: usize, sig: []const u8 };
    var dbuf: [max_digest_len]u8 = undefined;
    const digest = hashMessage(.sha256, kat2048.msg, &dbuf);
    for ([_]Kat{
        .{ .salt = 0, .sig = &kat2048_hashid.pss_salt_0 },
        .{ .salt = 20, .sig = &kat2048_hashid.pss_salt_20 },
        .{ .salt = 32, .sig = &kat2048_hashid.pss_salt_32 },
        .{ .salt = max, .sig = &kat2048_hashid.pss_salt_max },
    }) |c| {
        try testing.expectEqual(c.salt, try verifyPssAuto(pk, Sha256, kat2048.msg, c.sig));
        try testing.expectEqual(c.salt, try verifyPssAutoPrehashed(pk, Sha256, digest[0..32], c.sig));
        try testing.expectEqual(c.salt, try verifyPssDigest(pk, .sha256, digest, c.sig, null));
        try testing.expectEqual(c.salt, try vk.verifyPssDigest(.sha256, digest, c.sig, null));
        try verifyPss(pk, Sha256, kat2048.msg, c.sig, c.salt);
        try verifyPssPrehashed(pk, Sha256, digest[0..32], c.sig, c.salt);
        try vk.verifyPssPrehashed(Sha256, digest[0..32], c.sig, c.salt);
        // The wrong explicit length is refused (salt 0's neighbour is 1).
        try testing.expectError(error.SignatureVerificationFailed, verifyPss(pk, Sha256, kat2048.msg, c.sig, if (c.salt == 0) 1 else c.salt - 1));
        // Another message is refused in auto mode too.
        try testing.expectError(error.SignatureVerificationFailed, verifyPssAuto(pk, Sha256, "another message", c.sig));
    }
    // A PKCS#1 v1.5 signature is no PSS encoding under auto either.
    try testing.expectError(error.SignatureVerificationFailed, verifyPssAuto(pk, Sha256, kat2048.msg, &kat2048.sig_sha256));
    // SHA3-256 PSS through the run-time selector.
    try testing.expectEqual(32, try verifyPssDigest(pk, .sha3_256, hashMessage(.sha3_256, kat2048.msg, &dbuf), &kat2048_hashid.pss_sha3_256_salt_32, null));
}

test "PSS: decoupled MGF1 hash — OpenSSL rsa_mgf1_md:sha1 verifies, salt-0 sign is byte-exact" {
    const sha2 = std.crypto.hash.sha2;
    const Sha1 = std.crypto.hash.Sha1;
    const sk = try kat2048.secretKey();
    const pk = try kat2048.publicKey();
    try testing.expectEqual(32, try verifyPssH(pk, sha2.Sha256, Sha1, kat2048.msg, &kat2048_hashid.pss_mgf1sha1_salt_32, null));
    try testing.expectEqual(32, try verifyPssH(pk, sha2.Sha256, Sha1, kat2048.msg, &kat2048_hashid.pss_mgf1sha1_salt_32, 32));
    // The same signature under MGF1-SHA256 (the default pairing) is refused.
    try testing.expectError(error.SignatureVerificationFailed, verifyPssAuto(pk, sha2.Sha256, kat2048.msg, &kat2048_hashid.pss_mgf1sha1_salt_32));

    var prng = std.Random.DefaultPrng.init(0x14_10_2026);
    var out: [max_modulus_len]u8 = undefined;
    try testing.expectEqualSlices(u8, &kat2048_hashid.pss_mgf1sha1_salt_0, try signPssH(&sk, sha2.Sha256, Sha1, prng.random(), kat2048.msg, 0, &out));
    try testing.expectEqualSlices(u8, &kat2048_hashid.pss_salt_0, try signPssH(&sk, sha2.Sha256, sha2.Sha256, prng.random(), kat2048.msg, 0, &out));
    // Max salt through the run-time selector round-trips with auto recovery.
    var dbuf: [max_digest_len]u8 = undefined;
    const d512 = hashMessage(.sha512, kat2048.msg, &dbuf);
    const max512 = maxPssSaltLen(2048, sha2.Sha512).?;
    const sig = try signPssDigest(&sk, .sha512, prng.random(), d512, max512, &out);
    try testing.expectEqual(max512, try verifyPssDigest(pk, .sha512, d512, sig, null));
    try testing.expectError(error.EncodedMessageTooShort, signPssDigest(&sk, .sha512, prng.random(), d512, max512 + 1, &out));
    try testing.expectEqual(null, maxPssSaltLen(512, sha2.Sha512)); // 63-byte EM < 64 + 2
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
            try testing.expectError(error.InvalidDer, SecretKey.fromDer(&test_sk_out, kat2048_der.priv_pkcs1[0..l]));
        }
    }
    {
        var l: usize = 0;
        while (l < kat2048_der.priv_pkcs8.len) : (l += 11) {
            try testing.expectError(error.InvalidDer, fromPkcs8(&test_sk_out, kat2048_der.priv_pkcs8[0..l]));
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
    const idx = std.mem.find(u8, &corrupt, &oid_rsa_encryption).?;
    corrupt[idx] ^= 0xff;
    try testing.expectError(error.InvalidDer, PublicKey.fromDer(&corrupt));

    var corrupt8 = kat2048_der.priv_pkcs8;
    const idx8 = std.mem.find(u8, &corrupt8, &oid_rsa_encryption).?;
    corrupt8[idx8] ^= 0xff;
    try testing.expectError(error.InvalidDer, fromPkcs8(&test_sk_out, &corrupt8));
}

test "SecretKey.fromDer rejects a corrupted version field" {
    var corrupt = kat2048_der.priv_pkcs1;
    // version INTEGER is `02 01 00` right after the outer SEQUENCE header;
    // its content byte (must be 0x00) sits at offset 6.
    try testing.expectEqual(@as(u8, 0x00), corrupt[6]);
    corrupt[6] = 0x01; // multi-prime (version 1): rejected, not supported
    try testing.expectError(error.InvalidDer, SecretKey.fromDer(&test_sk_out, &corrupt));
}

test "PublicKey.fromPem/SecretKey.fromPem: missing block, corrupted base64, encrypted/OpenSSH labels" {
    try testing.expectError(error.MissingPemBlock, PublicKey.fromPem("no pem here"));
    try testing.expectError(error.MissingPemBlock, SecretKey.fromPem(&test_sk_out, "no pem here"));

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
        &test_sk_out,
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n",
    ));
    try testing.expectError(error.UnsupportedPemLabel, SecretKey.fromPem(
        &test_sk_out,
        "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
    ));
    // Right key material, wrong accessor (a public PEM handed to fromPem for
    // secret keys, and vice versa) is also a label mismatch, not a crash.
    try testing.expectError(error.UnsupportedPemLabel, SecretKey.fromPem(&test_sk_out, kat2048_pem.pub_spki));
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

    const cert_der = try selfSignedCert(testing.allocator, &sk, pk, std.crypto.hash.sha2.Sha256, testCertOptions(true));
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
    const ca_der = try selfSignedCert(testing.allocator, &sk, pk, Sha256, testCertOptions(true));
    defer testing.allocator.free(ca_der);
    const leaf_der = try selfSignedCert(testing.allocator, &sk, pk, Sha256, testCertOptions(false));
    defer testing.allocator.free(leaf_der);

    const ca_true_seq = [_]u8{ 0x30, 0x03, 0x01, 0x01, 0xff }; // SEQUENCE { BOOLEAN TRUE }
    const ca_empty_seq = [_]u8{ 0x30, 0x00 }; // SEQUENCE {} (cA DEFAULT FALSE)

    try testing.expect(std.mem.find(u8, ca_der, &ca_true_seq) != null);
    try testing.expect(std.mem.find(u8, leaf_der, &ca_true_seq) == null);
    try testing.expect(std.mem.find(u8, leaf_der, &ca_empty_seq) != null);

    // keyUsage differs too: CA sets keyCertSign+cRLSign (content byte 0x86,
    // 1 unused bit), leaf sets only digitalSignature (0x80, 7 unused bits).
    const ku_ca = [_]u8{ 0x03, 0x02, 0x01, 0x86 };
    const ku_leaf = [_]u8{ 0x03, 0x02, 0x07, 0x80 };
    try testing.expect(std.mem.find(u8, ca_der, &ku_ca) != null);
    try testing.expect(std.mem.find(u8, leaf_der, &ku_leaf) != null);

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

    const cert_der = try selfSignedCert(testing.allocator, &sk, pk, std.crypto.hash.sha2.Sha256, opts);
    defer testing.allocator.free(cert_der);
    const cert: std.crypto.Certificate = .{ .buffer = cert_der, .index = 0 };
    const parsed = try cert.parse();

    try parsed.verifyHostName("example.com");
    try parsed.verifyHostName("foo.example.com"); // matches the wildcard SAN
    try testing.expectError(error.CertificateHostMismatch, parsed.verifyHostName("other.org"));

    // The URI SAN is present in the raw subjectAltName bytes too (std has no
    // dedicated URI accessor, so check the extnValue bytes directly).
    try testing.expect(std.mem.find(u8, parsed.subjectAltName(), "urn:zig-libs:rsa:test") != null);
}

test "selfSignedCert: rejects invalid CertOptions (empty CN, malformed UTCTime)" {
    const sk = try kat2048.secretKey();
    const pk = try kat2048.publicKey();
    const Sha256 = std.crypto.hash.sha2.Sha256;

    var opts = testCertOptions(false);
    opts.common_name = "";
    try testing.expectError(error.InvalidCertOptions, selfSignedCert(testing.allocator, &sk, pk, Sha256, opts));

    opts = testCertOptions(false);
    opts.not_before = "2025-01-01"; // wrong shape entirely
    try testing.expectError(error.InvalidCertOptions, selfSignedCert(testing.allocator, &sk, pk, Sha256, opts));

    opts = testCertOptions(false);
    opts.not_after = "301231235959"; // missing trailing 'Z'
    try testing.expectError(error.InvalidCertOptions, selfSignedCert(testing.allocator, &sk, pk, Sha256, opts));

    opts = testCertOptions(false);
    opts.not_before = "25010100000AZ"; // non-digit in the date portion
    try testing.expectError(error.InvalidCertOptions, selfSignedCert(testing.allocator, &sk, pk, Sha256, opts));
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
        selfSignedCert(failing.allocator(), &sk, pk, std.crypto.hash.sha2.Sha256, testCertOptions(false)),
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

    const cert_der = try selfSignedCert(testing.allocator, &sk, pk, Sha256, testCertOptions(false));
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
    try testing.expectError(error.InvalidBits, generate(&test_kp_out, random, 0, 65537));
    try testing.expectError(error.InvalidBits, generate(&test_kp_out, random, 256, 65537));
    try testing.expectError(error.InvalidBits, generate(&test_kp_out, random, 511, 65537));
    try testing.expectError(error.InvalidBits, generate(&test_kp_out, random, 513, 65537));
    try testing.expectError(error.InvalidBits, generate(&test_kp_out, random, max_modulus_bits + 2, 65537));

    // e must be odd, >= 3, and < 2^32 (the module-wide public-exponent cap).
    try testing.expectError(error.InvalidExponent, generate(&test_kp_out, random, 512, 0));
    try testing.expectError(error.InvalidExponent, generate(&test_kp_out, random, 512, 1));
    try testing.expectError(error.InvalidExponent, generate(&test_kp_out, random, 512, 2));
    try testing.expectError(error.InvalidExponent, generate(&test_kp_out, random, 512, 65536));
    try testing.expectError(error.InvalidExponent, generate(&test_kp_out, random, 512, 1 << 33));
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

    var kp: KeyPair = undefined;
    try generate(&kp, random, 512, 65537);
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

    var kp: KeyPair = undefined;
    try generate(&kp, random, 512, 3);
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
    var kp: KeyPair = undefined;
    try generate(&kp, random, 1024, 65537);
    const sk = kp.secret_key;
    const pk = kp.public_key;
    try testing.expectEqual(@as(usize, 1024), sk.n.bits());
    try expectNisPQ(sk);

    // P1: sign/verify round-trip, and the verifier still rejects a wrong
    // message under this fresh key.
    const msg = "generated-key end-to-end message";
    var sig_buf: [max_modulus_len]u8 = undefined;
    const sig = try signPkcs1v15(&sk, Sha256, msg, &sig_buf);
    try verifyPkcs1v15(pk, Sha256, msg, sig);
    try testing.expectError(error.SignatureVerificationFailed, verifyPkcs1v15(pk, Sha256, "another message", sig));

    // P2: OAEP encrypt/decrypt round-trip.
    const secret = "oaep plaintext under a generated key";
    var ct_buf: [max_modulus_len]u8 = undefined;
    const ct = try encryptOaep(pk, Sha256, random, secret, "", &ct_buf);
    var pt_buf: [max_modulus_len]u8 = undefined;
    const pt = try decryptOaep(&sk, Sha256, ct, "", &pt_buf);
    try testing.expectEqualStrings(secret, pt);

    // P6: a self-signed certificate for the generated key must fully verify
    // under std.crypto.Certificate (parse + issuer/subject + validity +
    // RSA signature over the TBS bytes).
    const cert_der = try selfSignedCert(testing.allocator, &sk, pk, Sha256, testCertOptions(false));
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
    var sk: SecretKey = undefined;
    try fromOpenSSH(&sk, openssh_fixture_plain, "");
    const pk = PublicKey{ .n = sk.n, .e = try Fe.fromPrimitive(u32, sk.n, 65537), .n_mont = sk.n_mont };
    const msg = "zig-libs rsa: P4b openssh fixture";
    var sig_buf: [max_modulus_len]u8 = undefined;
    const sig = try signPkcs1v15(&sk, std.crypto.hash.sha2.Sha256, msg, &sig_buf);
    try verifyPkcs1v15(pk, std.crypto.hash.sha2.Sha256, msg, sig);
}

test "fromOpenSSH: bcrypt/aes256-ctr and aes256-cbc decrypt to the unencrypted sibling" {
    var sk_plain: SecretKey = undefined;
    try fromOpenSSH(&sk_plain, openssh_fixture_plain, "");
    const k = byteLen(sk_plain.n.bits());
    var n_plain: [max_modulus_len]u8 = undefined;
    try sk_plain.n.toBytes(n_plain[0..k], .big);

    inline for (.{ openssh_fixture_ctr, openssh_fixture_cbc }) |fixture| {
        var sk: SecretKey = undefined;
        try fromOpenSSH(&sk, fixture, "hunter2");
        try testing.expectEqual(sk_plain.n.bits(), sk.n.bits());
        var n_enc: [max_modulus_len]u8 = undefined;
        try sk.n.toBytes(n_enc[0..k], .big);
        try testing.expectEqualSlices(u8, n_plain[0..k], n_enc[0..k]);
    }
}

test "fromOpenSSH: wrong or empty passphrase is IncorrectPassphrase" {
    try testing.expectError(error.IncorrectPassphrase, fromOpenSSH(&test_sk_out, openssh_fixture_ctr, "hunter3"));
    try testing.expectError(error.IncorrectPassphrase, fromOpenSSH(&test_sk_out, openssh_fixture_ctr, ""));
    try testing.expectError(error.IncorrectPassphrase, fromOpenSSH(&test_sk_out, openssh_fixture_cbc, "HUNTER2"));
}

/// Test helper: assemble a synthetic openssh-key-v1 binary image from SSH
/// wire pieces, then armor it as an `OPENSSH PRIVATE KEY` PEM block.
const OpensshTestBuilder = struct {
    buf: [2048]u8 = undefined,
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
        try testing.expectError(error.InvalidOpenSSH, fromOpenSSH(&test_sk_out, b.pem(&pem_buf), ""));
    }
    { // truncated container: stops after kdfname
        var b = OpensshTestBuilder{};
        _ = b.raw("openssh-key-v1\x00").str("none").str("none");
        try testing.expectError(error.InvalidOpenSSH, fromOpenSSH(&test_sk_out, b.pem(&pem_buf), ""));
    }
    { // truncated string: private section claims more bytes than exist
        var b = OpensshTestBuilder{};
        _ = b.raw("openssh-key-v1\x00").str("none").str("none").str("").int(1).str("").int(64);
        try testing.expectError(error.InvalidOpenSSH, fromOpenSSH(&test_sk_out, b.pem(&pem_buf), ""));
    }
    { // nkeys != 1
        var b = OpensshTestBuilder{};
        _ = b.raw("openssh-key-v1\x00").str("none").str("none").str("").int(2).str("").str("");
        try testing.expectError(error.InvalidOpenSSH, fromOpenSSH(&test_sk_out, b.pem(&pem_buf), ""));
    }
    { // trailing garbage after the private section
        var b = OpensshTestBuilder{};
        _ = b.raw("openssh-key-v1\x00").str("none").str("none").str("").int(1).str("").str("").raw("x");
        try testing.expectError(error.InvalidOpenSSH, fromOpenSSH(&test_sk_out, b.pem(&pem_buf), ""));
    }
}

test "fromOpenSSH: rejects unsupported cipher/kdf and foreign PEM labels" {
    var pem_buf: [2048]u8 = undefined;

    { // cipher this module does not speak
        var b = OpensshTestBuilder{};
        _ = b.raw("openssh-key-v1\x00").str("chacha20-poly1305@openssh.com").str("bcrypt").str("").int(1).str("").str("");
        try testing.expectError(error.UnsupportedCipher, fromOpenSSH(&test_sk_out, b.pem(&pem_buf), "pw"));
    }
    { // bcrypt rounds above the cap (RSA_FUZZ HANG, 2026-10-09): refused
        // before any KDF work, at the first value over it and at the maximum.
        for ([_]u32{ max_openssh_kdf_rounds + 1, 0xffff_ffff }) |rounds| {
            var opts: [4 + 16 + 4]u8 = undefined;
            std.mem.writeInt(u32, opts[0..4], 16, .big);
            @memset(opts[4..20], 0x5a);
            std.mem.writeInt(u32, opts[20..24], rounds, .big);
            var b = OpensshTestBuilder{};
            _ = b.raw("openssh-key-v1\x00").str("aes256-ctr").str("bcrypt").str(&opts).int(1).str("").str(&(@as([16]u8, @splat(0))));
            try testing.expectError(error.KdfRoundsTooLarge, fromOpenSSH(&test_sk_out, b.pem(&pem_buf), "pw"));
        }
    }
    { // unknown kdf
        var b = OpensshTestBuilder{};
        _ = b.raw("openssh-key-v1\x00").str("aes256-ctr").str("argon2id").str("").int(1).str("").str("");
        try testing.expectError(error.UnsupportedKdf, fromOpenSSH(&test_sk_out, b.pem(&pem_buf), "pw"));
    }
    { // inconsistent: encryption without a kdf
        var b = OpensshTestBuilder{};
        _ = b.raw("openssh-key-v1\x00").str("aes256-ctr").str("none").str("").int(1).str("").str("");
        try testing.expectError(error.InvalidOpenSSH, fromOpenSSH(&test_sk_out, b.pem(&pem_buf), "pw"));
    }

    try testing.expectError(error.MissingPemBlock, fromOpenSSH(&test_sk_out, "no pem block here", ""));
    try testing.expectError(error.UnsupportedPemLabel, fromOpenSSH(
        &test_sk_out,
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
        try testing.expectError(error.InvalidOpenSSH, fromOpenSSH(&test_sk_out, b.pem(&pem_buf), ""));
    }
    { // well-formed container holding an ssh-ed25519 key
        var priv = OpensshTestBuilder{};
        _ = priv.int(7).int(7).str("ssh-ed25519");
        var b = OpensshTestBuilder{};
        _ = b.raw("openssh-key-v1\x00").str("none").str("none").str("").int(1).str("").str(priv.buf[0..priv.len]);
        try testing.expectError(error.UnsupportedKeyType, fromOpenSSH(&test_sk_out, b.pem(&pem_buf), ""));
    }
}

// ── audit 2026-10-04: tests asked for by mutation survivors ──────────────────
//
// Each test below breaks exactly ONE property of an otherwise valid input, so
// only the check under test can refuse it (the older negative tests often
// failed for an earlier, unrelated reason — e.g. an empty OpenSSH private
// section is refused by the first `readU32`, whatever the container says).

test "ctEqByte is equality on every byte pair" {
    // Definition: 1 iff x == y. The OAEP and PSS decoders fold every byte
    // check through it, so a wrong answer for any pair is a padding oracle.
    var x: u16 = 0;
    while (x < 256) : (x += 1) {
        var y: u16 = 0;
        while (y < 256) : (y += 1) {
            try testing.expectEqual(@as(u8, @intFromBool(x == y)), ctEqByte(@intCast(x), @intCast(y)));
        }
    }
}

test "EMSA-PKCS1-v1_5 refuses an encoding with fewer than 8 PS octets" {
    // RFC 8017 §9.2 step 3: emLen < tLen + 11 → "intended encoded message
    // length too short". SHA-256's T is 19 + 32 = 51 octets, so 62 is the
    // shortest legal emLen (PS = exactly 8 × 0xff) and 61 must be refused.
    const Sha256 = std.crypto.hash.sha2.Sha256;
    var em: [62]u8 = undefined;
    try testing.expectError(error.EncodedMessageTooShort, emsaPkcs1v15Encode(Sha256, "m", em[0..61]));
    try emsaPkcs1v15Encode(Sha256, "m", &em);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x01 }, em[0..2]);
    try testing.expectEqualSlices(u8, &(@as([8]u8, @splat(0xff))), em[2..10]);
    try testing.expectEqual(@as(u8, 0x00), em[10]);
}

test "verify refuses a signature that is not exactly k octets, even one equal in value" {
    // RFC 8017 §8.2.2 step 1 and §8.1.2 step 1: "If the length of the
    // signature S is not k octets, output 'invalid signature'". A leading
    // 0x00 keeps the integer value — only the length check can refuse it.
    const Sha256 = std.crypto.hash.sha2.Sha256;
    const sk = try kat2048.secretKey();
    const pk = try kat2048.publicKey();
    var long: [257]u8 = undefined;
    long[0] = 0;
    long[1..].* = kat2048.sig_sha256;
    try verifyPkcs1v15(pk, Sha256, kat2048.msg, &kat2048.sig_sha256); // control
    try testing.expectError(error.SignatureVerificationFailed, verifyPkcs1v15(pk, Sha256, kat2048.msg, &long));

    var prng = std.Random.DefaultPrng.init(3);
    var sig_buf: [256]u8 = undefined;
    const sig = try signPss(&sk, Sha256, prng.random(), "pss length", 32, &sig_buf);
    try verifyPss(pk, Sha256, "pss length", sig, 32); // control
    long[1..].* = sig[0..256].*;
    try testing.expectError(error.SignatureVerificationFailed, verifyPss(pk, Sha256, "pss length", &long, 32));
}

/// Re-mask a PSS encoding after the caller edited its unmasked DB: the steps
/// a signer runs (§9.1.1 steps 9-11), so the result differs from a genuine
/// encoding only in the edited DB octets.
fn pssEditDb(comptime Hash: type, em: []u8, em_bits: usize, edit: *const fn (db: []u8) void) void {
    const h_len = Hash.digest_length;
    const db = em[0 .. em.len - h_len - 1];
    const h = em[em.len - h_len - 1 ..][0..h_len];
    const top_mask = @as(u8, 0xff) >> @intCast(8 * em.len - em_bits);
    mgf1Xor(Hash, h, db); // unmask
    db[0] &= top_mask;
    edit(db);
    mgf1Xor(Hash, h, db); // mask again
    db[0] &= top_mask;
}

test "verifyPss refuses a nonzero PS octet and a wrong separator octet" {
    // RFC 8017 §9.1.2 step 10: the emLen − hLen − sLen − 2 leftmost octets
    // of DB must be zero and the next one 0x01, else "inconsistent". H covers
    // only M' (mHash ‖ salt), not DB, so these edits keep H valid — only the
    // step-10 checks can refuse them.
    const Sha256 = std.crypto.hash.sha2.Sha256;
    const sk = try kat2048.secretKey();
    const pk = try kat2048.publicKey();
    const msg = "pss db edits";
    const salt = @as([32]u8, @splat(0x5a));
    var em: [256]u8 = undefined;
    try emsaPssEncode(Sha256, msg, &salt, 2047, &em);
    const good = try rsasp1(256, em, &sk);
    try verifyPss(pk, Sha256, msg, &good, 32); // control

    // ps_len = 256 − 32 − 32 − 2 = 190; DB[190] is the 0x01 separator.
    const edits = [_]*const fn (db: []u8) void{
        struct {
            fn f(db: []u8) void {
                db[5] = 0x01; // a PS octet
            }
        }.f,
        struct {
            fn f(db: []u8) void {
                db[190] = 0x02; // the separator
            }
        }.f,
    };
    for (edits) |edit| {
        var bad = em;
        pssEditDb(Sha256, &bad, 2047, edit);
        const sig = try rsasp1(256, bad, &sk);
        try testing.expectError(error.SignatureVerificationFailed, verifyPss(pk, Sha256, msg, &sig, 32));
    }
}

/// A 521-bit key (modBits ≡ 1 mod 8, so emLen = k − 1 for PSS): two primes
/// found by a Miller–Rabin (40 rounds) search from 2^260 + 2^259 + 12345 and
/// 2^260 + 2^258 + 67891, with gcd(65537, p − 1) = gcd(65537, q − 1) = 1.
/// `fromPrimes` re-checks qInv·q ≡ 1 (mod p).
const kat521 = struct {
    const e = [_]u8{ 0x01, 0x00, 0x01 };
    const p = hexLit("18000000000000000000000000000000000000000000000000000000000000314f");
    const q = hexLit("14000000000000000000000000000000000000000000000000000000000001096d");
    const n = hexLit("01e000000000000000000000000000000000000000000000000000000000001cbc6400000000000000000000000000000000000000000000000000000000331fc5a3");
};

test "verifyPss refuses a representative wider than emLen when modBits ≡ 1 mod 8" {
    // RFC 8017 §8.1.2 step 2c: EM = I2OSP(m, emLen) with emLen = k − 1 here;
    // a representative m ≥ 256^emLen is "integer too large" → invalid
    // signature. So the octet in front of EM must be zero — even when the
    // rest is a perfectly valid encoding, as built here.
    const Sha256 = std.crypto.hash.sha2.Sha256;
    var sk: SecretKey = undefined;
    try SecretKey.fromPrimes(&sk, &kat521.p, &kat521.q, &kat521.e);
    const pk = try PublicKey.fromBytes(&kat521.n, &kat521.e);
    try testing.expectEqual(@as(usize, 521), pk.n.bits());
    const msg = "emLen = k - 1";
    var x: [66]u8 = undefined;
    var salt = @as([16]u8, @splat(0));
    var s: u8 = 0;
    // 0x01 ‖ EM must stay below n (= 0x01e0…): pick a salt whose EM[0] < 0xe0.
    while (true) : (s += 1) {
        @memset(&salt, s);
        try emsaPssEncode(Sha256, msg, &salt, 520, x[1..]);
        if (x[1] < 0xe0) break;
    }
    x[0] = 0x00;
    const good = try rsasp1(66, x, &sk);
    try verifyPss(pk, Sha256, msg, &good, 16); // control
    x[0] = 0x01;
    const bad = try rsasp1(66, x, &sk);
    try testing.expectError(error.SignatureVerificationFailed, verifyPss(pk, Sha256, msg, &bad, 16));
}

/// RSAEP of an OAEP encoding with a caller-chosen leading octet Y and DB
/// (masked as §7.1.1 steps 2.d–2.i do), under `kat2048`: a ciphertext that
/// differs from a genuine one only where the caller says.
fn oaepCraft(y: u8, db_in: *const [223]u8) ![256]u8 {
    const Sha256 = std.crypto.hash.sha2.Sha256;
    var em: [256]u8 = undefined;
    em[0] = y;
    const seed = em[1..33];
    const db = em[33..256];
    db.* = db_in.*;
    var prng = std.Random.DefaultPrng.init(42);
    prng.random().bytes(seed);
    mgf1Xor(Sha256, seed, db);
    mgf1Xor(Sha256, db, seed);
    return rsaep(256, em, try kat2048.publicKey());
}

test "OAEP decryption refuses a stray PS octet and a missing separator (both entry points)" {
    // RFC 8017 §7.1.2 step 3g: DB = lHash' ‖ PS ‖ 0x01 ‖ M where PS is zero
    // octets; "if there is no octet with hexadecimal value 0x01 to separate
    // PS from M, ... output 'decryption error'". A nonzero non-0x01 octet
    // before the separator is therefore not PS and the block is invalid.
    const Sha256 = std.crypto.hash.sha2.Sha256;
    const sk = try kat2048.secretKey();
    var out: [max_modulus_len]u8 = undefined;
    var raw: [max_modulus_len]u8 = undefined;

    var db: [223]u8 = @splat(0);
    Sha256.hash("", db[0..32], .{});
    db[db.len - 4] = 0x01;
    @memcpy(db[db.len - 3 ..], "msg");
    const ok_ct = try oaepCraft(0x00, &db); // control
    try testing.expectEqualStrings("msg", try decryptOaep(&sk, Sha256, &ok_ct, "", &out));
    const r_ok = try decryptOaepHNoFail(&sk, Sha256, Sha256, .none, &ok_ct, "", 3, &out, &raw);
    try testing.expect(r_ok.ok);

    var stray = db;
    stray[40] = 0x02;
    const stray_ct = try oaepCraft(0x00, &stray);
    try testing.expectError(error.DecryptionError, decryptOaep(&sk, Sha256, &stray_ct, "", &out));
    try testing.expect(!(try decryptOaepHNoFail(&sk, Sha256, Sha256, .none, &stray_ct, "", 3, &out, &raw)).ok);

    var no_sep = db;
    @memset(no_sep[32..], 0);
    const no_sep_ct = try oaepCraft(0x00, &no_sep);
    try testing.expectError(error.DecryptionError, decryptOaep(&sk, Sha256, &no_sep_ct, "", &out));

    // Y ≠ 0 (§7.1.2 step 3g, "if Y is nonzero") through the no-fail entry
    // point (the erroring one has its own test above).
    const y_ct = try oaepCraft(0x01, &db);
    try testing.expect(!(try decryptOaepHNoFail(&sk, Sha256, Sha256, .none, &y_ct, "", 3, &out, &raw)).ok);
}

test "OAEP decryption checks its output buffers up front, from public sizes only" {
    // `decryptOaep*`'s contract: `out` ≥ k − 2hLen − 2 (the largest message
    // the key can carry), checked BEFORE the private op so the answer never
    // depends on the secret plaintext length; `decryptOaepHNoFail`'s `want`
    // above that bound is the same kind of public precondition failure.
    const Sha256 = std.crypto.hash.sha2.Sha256;
    const sk = try kat2048.secretKey();
    var prng = std.Random.DefaultPrng.init(5);
    var ct_buf: [256]u8 = undefined;
    const ct = try encryptOaep(try kat2048.publicKey(), Sha256, prng.random(), "short", "", &ct_buf);
    const max_msg = 256 - 2 * 32 - 2;
    var out: [max_modulus_len]u8 = undefined;
    var raw: [max_modulus_len]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, decryptOaep(&sk, Sha256, ct, "", out[0 .. max_msg - 1]));
    try testing.expectEqualStrings("short", try decryptOaep(&sk, Sha256, ct, "", out[0..max_msg]));
    try testing.expectError(error.BufferTooSmall, decryptOaepHNoFail(&sk, Sha256, Sha256, .none, ct, "", max_msg + 1, &out, &raw));
}

/// `der` with `extra` appended INSIDE its outer SEQUENCE. Every fixture here
/// has a two-octet long-form outer length (`30 82 hi lo`).
fn derAppendInTop(der: []const u8, extra: []const u8, out: []u8) []const u8 {
    std.debug.assert(der[0] == 0x30 and der[1] == 0x82);
    @memcpy(out[0..der.len], der);
    @memcpy(out[der.len..][0..extra.len], extra);
    const len = std.mem.readInt(u16, der[2..4], .big) + extra.len;
    std.mem.writeInt(u16, out[2..4], @intCast(len), .big);
    return out[0 .. der.len + extra.len];
}

test "DER keys: trailing bytes, extra fields, unused bits and a v2 PKCS#8 are refused" {
    var buf: [2048]u8 = undefined;
    // Controls: the fixtures themselves parse.
    _ = try PublicKey.fromDer(&kat2048_der.pub_pkcs1);
    _ = try PublicKey.fromDer(&kat2048_der.pub_spki);

    // A DER key is exactly one SEQUENCE TLV (X.690 §8.1.1); anything after it
    // is not part of the key — refused rather than ignored.
    inline for (.{ &kat2048_der.pub_pkcs1, &kat2048_der.pub_spki }) |der| {
        @memcpy(buf[0..der.len], der);
        buf[der.len] = 0x00;
        try testing.expectError(error.InvalidDer, PublicKey.fromDer(buf[0 .. der.len + 1]));
    }
    @memcpy(buf[0..kat2048_der.priv_pkcs1.len], &kat2048_der.priv_pkcs1);
    buf[kat2048_der.priv_pkcs1.len] = 0x00;
    try testing.expectError(error.InvalidDer, SecretKey.fromDer(&test_sk_out, buf[0 .. kat2048_der.priv_pkcs1.len + 1]));

    // RSAPublicKey is SEQUENCE { modulus, publicExponent } (RFC 8017 A.1.1)
    // and SubjectPublicKeyInfo SEQUENCE { algorithm, subjectPublicKey }
    // (RFC 5280 §4.1): a third field is not that structure.
    try testing.expectError(error.InvalidDer, PublicKey.fromDer(derAppendInTop(&kat2048_der.pub_pkcs1, &.{ 0x02, 0x01, 0x00 }, &buf)));
    try testing.expectError(error.InvalidDer, PublicKey.fromDer(derAppendInTop(&kat2048_der.pub_spki, &.{ 0x05, 0x00 }, &buf)));
    // RSAPrivateKey version 0 has no otherPrimeInfos (RFC 8017 A.1.2: "version
    // SHALL be 0 if there are only two primes").
    try testing.expectError(error.InvalidDer, SecretKey.fromDer(&test_sk_out, derAppendInTop(&kat2048_der.priv_pkcs1, &.{ 0x30, 0x00 }, &buf)));

    // The BIT STRING wrapping RSAPublicKey carries whole octets: its
    // unused-bits octet (X.690 §8.6.2.2) must be 0. Offset 23 = outer header
    // (4) + AlgorithmIdentifier (15) + BIT STRING header `03 82 01 0f` (4).
    var spki = kat2048_der.pub_spki;
    try testing.expectEqualSlices(u8, &.{ 0x03, 0x82, 0x01, 0x0f, 0x00 }, spki[19..24]);
    spki[23] = 0x01;
    try testing.expectError(error.InvalidDer, PublicKey.fromDer(&spki));

    // PKCS#8 version: only v1 (0, RFC 5208) is accepted — SPEC scope, v2
    // `OneAsymmetricKey` (RFC 5958) is refused. Offset 6 = `30 82 04 bd 02 01 [00]`.
    var p8 = kat2048_der.priv_pkcs8;
    try testing.expectEqualSlices(u8, &.{ 0x02, 0x01, 0x00 }, p8[4..7]);
    p8[6] = 0x01;
    try testing.expectError(error.InvalidDer, fromPkcs8(&test_sk_out, &p8));
}

test "PEM: a block with no base64 payload is a PEM error, not a DER one" {
    // RFC 7468 §3: a textual encoding carries base64 data between the
    // boundaries. An empty body is malformed PEM — reported as InvalidPem
    // before any DER parser sees zero bytes.
    try testing.expectError(error.InvalidPem, PublicKey.fromPem("-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n"));
}

/// The fields of a decoded openssh-key-v1 fixture, so a test can rebuild it
/// with exactly one field changed.
const OpensshParts = struct {
    cipher: []const u8,
    kdf: []const u8,
    kdfopts: []const u8,
    pubkey: []const u8,
    private: []const u8,

    fn of(bin: []const u8) !OpensshParts {
        var r = SshReader{ .buf = bin, .pos = "openssh-key-v1\x00".len };
        const cipher = try r.readString();
        const kdf = try r.readString();
        const kdfopts = try r.readString();
        try testing.expectEqual(@as(u32, 1), try r.readU32());
        const pubkey = try r.readString();
        const private = try r.readString();
        try testing.expectEqual(@as(usize, 0), r.rest().len);
        return .{ .cipher = cipher, .kdf = kdf, .kdfopts = kdfopts, .pubkey = pubkey, .private = private };
    }

    fn build(p: OpensshParts, b: *OpensshTestBuilder, nkeys: u32, trailing: []const u8) void {
        _ = b.raw("openssh-key-v1\x00").str(p.cipher).str(p.kdf).str(p.kdfopts).int(nkeys).str(p.pubkey).str(p.private).raw(trailing);
    }
};

test "fromOpenSSH: one bad field in an otherwise valid container is refused" {
    // PROTOCOL.key: one key per file here (nkeys = 1, SPEC), no bytes after
    // the private section, `none` cipher ⇔ `none` kdf with empty options,
    // bcrypt options = string salt ‖ uint32 rounds and nothing more, the
    // encrypted section a whole number of cipher blocks, and the private
    // section padded with 1, 2, 3, … up to (never including) a full block.
    var pem_buf: [4096]u8 = undefined;
    const plain_block = try pemDecodeBody(openssh_fixture_plain);
    const plain = try OpensshParts.of(plain_block.der());
    { // control: the rebuilt container parses
        var b = OpensshTestBuilder{};
        plain.build(&b, 1, "");
        try fromOpenSSH(&test_sk_out, b.pem(&pem_buf), "");
    }
    { // nkeys = 2 with the single key's fields intact
        var b = OpensshTestBuilder{};
        plain.build(&b, 2, "");
        try testing.expectError(error.InvalidOpenSSH, fromOpenSSH(&test_sk_out, b.pem(&pem_buf), ""));
    }
    { // a byte after a valid private section
        var b = OpensshTestBuilder{};
        plain.build(&b, 1, "x");
        try testing.expectError(error.InvalidOpenSSH, fromOpenSSH(&test_sk_out, b.pem(&pem_buf), ""));
    }
    { // cipher none with a bcrypt kdf
        var p = plain;
        p.kdf = "bcrypt";
        var b = OpensshTestBuilder{};
        p.build(&b, 1, "");
        try testing.expectError(error.InvalidOpenSSH, fromOpenSSH(&test_sk_out, b.pem(&pem_buf), ""));
    }
    // The fixture's section ends `… 'b' 01 02 03` (comment, then padding).
    const sec = plain.private;
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03 }, sec[sec.len - 3 ..]);
    var sec_buf: [2048]u8 = undefined;
    { // wrong padding value
        @memcpy(sec_buf[0..sec.len], sec);
        sec_buf[sec.len - 1] = 0x04;
        var p = plain;
        p.private = sec_buf[0..sec.len];
        var b = OpensshTestBuilder{};
        p.build(&b, 1, "");
        try testing.expectError(error.InvalidOpenSSH, fromOpenSSH(&test_sk_out, b.pem(&pem_buf), ""));
    }
    { // padding 1…11: a correct sequence, but a full block (8) or more of it
        @memcpy(sec_buf[0..sec.len], sec);
        for (0..8) |i| sec_buf[sec.len + i] = @intCast(4 + i);
        var p = plain;
        p.private = sec_buf[0 .. sec.len + 8];
        var b = OpensshTestBuilder{};
        p.build(&b, 1, "");
        try testing.expectError(error.InvalidOpenSSH, fromOpenSSH(&test_sk_out, b.pem(&pem_buf), ""));
    }

    const cbc_block = try pemDecodeBody(openssh_fixture_cbc);
    const cbc = try OpensshParts.of(cbc_block.der());
    { // control
        var b = OpensshTestBuilder{};
        cbc.build(&b, 1, "");
        try fromOpenSSH(&test_sk_out, b.pem(&pem_buf), "hunter2");
    }
    { // bcrypt options with a byte after `rounds`
        var opts: [64]u8 = undefined;
        @memcpy(opts[0..cbc.kdfopts.len], cbc.kdfopts);
        opts[cbc.kdfopts.len] = 0;
        var p = cbc;
        p.kdfopts = opts[0 .. cbc.kdfopts.len + 1];
        var b = OpensshTestBuilder{};
        p.build(&b, 1, "");
        try testing.expectError(error.InvalidOpenSSH, fromOpenSSH(&test_sk_out, b.pem(&pem_buf), "hunter2"));
    }
    { // an encrypted section one byte past a whole number of AES blocks
        @memcpy(sec_buf[0..cbc.private.len], cbc.private);
        sec_buf[cbc.private.len] = 0;
        var p = cbc;
        p.private = sec_buf[0 .. cbc.private.len + 1];
        var b = OpensshTestBuilder{};
        p.build(&b, 1, "");
        try testing.expectError(error.InvalidOpenSSH, fromOpenSSH(&test_sk_out, b.pem(&pem_buf), "hunter2"));
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
    var kp: KeyPair = undefined;
    generate(&kp, random, bits, 65537) catch {
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
            sig = rsasp1(klen, msg, &sk) catch unreachable;
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
//
// ⚠ Every harness below used to open with
//
//     smith.bytes(&buf);
//     const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
//
// which is the collapsing idiom: `bytes` consumes `@min(buf.len, in.len)`
// octets and the ranged draw then finds fewer than the eight it reads as a
// little-endian u64, so it returns the range MINIMUM — zero. The seed reached
// `buf` and was thrown away, and with no corpus at all the six targets ran
// exactly one input each, for ever: `fromDer("")`, `fromPem("")`,
// `fromOpenSSH("", "")`. Six parsers of externally supplied key material, and
// not one octet of a key had ever gone through any of them here.
//
// ⛔ Arbitrary bytes cannot fix that on their own. A DER `RSAPrivateKey` is a
// nine-INTEGER SEQUENCE whose primes have to multiply back to the modulus and
// whose `e` has to be invertible mod λ(n); the chance of drawing one is nil.
// The interesting frames are therefore PERTURBATIONS of a real encoding, and
// the real encodings this module owns are the `kat2048_der`/`kat2048_pem`/
// `openssh_fixture_*` fixtures above. Roughly half of every corpus below is a
// fixture one octet off — the shape that reaches past the outer TLV and into
// the arithmetic.

/// `frame` with one octet XORed. The corpus building block: a real encoding
/// with a single byte changed still parses as ASN.1, so it reaches the key
/// arithmetic instead of dying at the first tag the way random bytes do.
fn perturbed(comptime frame: []const u8, comptime at: usize, comptime mask: u8) []const u8 {
    return &struct {
        const bytes = blk: {
            var out = frame[0..frame.len].*;
            out[at] ^= mask;
            break :blk out;
        };
    }.bytes;
}

/// A running record of which moduli actually came back out of a corpus.
///
/// ⛔ The reason the guards below pin this and not just an "accepted" count:
/// `accepted` says a frame was legal, not that the SEED decided which one. Two
/// seeds carrying the same fixture score the same as ten, and a corpus that
/// silently collapsed to one frame — a seed grown past the harness's buffer
/// reads back EMPTY, without a word — keeps whatever count the remaining seeds
/// happen to make. `n` is the number the collapse cannot hold up: it only
/// moves when a seed's own OCTETS reach the modulus.
const ModuliSeen = struct {
    seen: [8][max_modulus_len]u8 = undefined,
    lens: [8]usize = undefined,
    n: usize = 0,

    fn add(self: *ModuliSeen, m: Modulus) !void {
        const k = byteLen(m.bits());
        var buf: [max_modulus_len]u8 = undefined;
        try m.toBytes(buf[0..k], .big);
        for (self.seen[0..self.n], self.lens[0..self.n]) |*prev, plen| {
            if (plen == k and std.mem.eql(u8, prev[0..k], buf[0..k])) return;
        }
        if (self.n == self.seen.len) return error.TooManyModuli;
        @memcpy(self.seen[self.n][0..k], buf[0..k]);
        self.lens[self.n] = k;
        self.n += 1;
    }
};

// ── deterministic driver: harness bodies generic over the source ───────────

const fuzz_driver = testkit.fuzz.driver;
const FuzzLabel = enum { raw_rejected, raw_accepted, pristine_accepted, damaged_rejected, damaged_accepted };
var fuzz_reach: [@typeInfo(FuzzLabel).@"enum".field_names.len]usize = @splat(0);

fn mark(comptime l: FuzzLabel) void {
    fuzz_reach[@backingInt(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

fn parsePubDer(in: []const u8) ?usize {
    const pk = PublicKey.fromDer(in) catch return null;
    publicRoundTrip(&pk);
    return pk.n.bits();
}
fn parsePubPem(in: []const u8) ?usize {
    const pk = PublicKey.fromPem(in) catch return null;
    publicRoundTrip(&pk);
    return pk.n.bits();
}
fn parseSecDer(in: []const u8) ?usize {
    var sk: SecretKey = undefined;
    SecretKey.fromDer(&sk, in) catch return null;
    defer sk.deinit();
    secretRoundTrip(&sk);
    return sk.n.bits();
}
fn parsePkcs8(in: []const u8) ?usize {
    var sk: SecretKey = undefined;
    fromPkcs8(&sk, in) catch return null;
    defer sk.deinit();
    secretRoundTrip(&sk);
    return sk.n.bits();
}
fn parseSecPem(in: []const u8) ?usize {
    var sk: SecretKey = undefined;
    SecretKey.fromPem(&sk, in) catch return null;
    defer sk.deinit();
    secretRoundTrip(&sk);
    return sk.n.bits();
}

/// The writer's property on every key a parser accepted (R1, 2026-10-14):
/// each encoding parses back, and writing the re-parsed key gives the same
/// bytes — the parser and the writer agree on every key the harnesses reach.
fn publicRoundTrip(pk: *const PublicKey) void {
    var a: [max_public_pem_len]u8 = undefined;
    var b: [max_public_pem_len]u8 = undefined;
    for ([_]PublicKeyForm{ .pkcs1, .spki }) |form| {
        const der = (switch (form) {
            .pkcs1 => pk.toPkcs1Der(&a),
            .spki => pk.toSpkiDer(&a),
        }) catch @panic("max_*_der_len too small");
        const back = PublicKey.fromDer(der) catch @panic("written public DER does not parse");
        if (!back.equal(pk)) @panic("public DER round trip changed the key");
    }
    const pem = pk.toPem(.spki, &a) catch @panic("toPem: max_public_pem_len too small");
    const back = PublicKey.fromPem(pem) catch @panic("written public PEM does not parse");
    const again = back.toPem(.spki, &b) catch unreachable;
    if (!std.mem.eql(u8, pem, again)) @panic("public PEM is not a fixed point");
}

fn secretRoundTrip(sk: *const SecretKey) void {
    var a: [max_private_pem_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &a);
    var b: [max_private_pem_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &b);
    for ([_]PrivateKeyForm{ .pkcs1, .pkcs8 }) |form| {
        const pem = sk.toPem(form, &a) catch @panic("toPem: max_private_pem_len too small");
        var back: SecretKey = undefined;
        SecretKey.fromPem(&back, pem) catch @panic("written private PEM does not parse");
        defer back.deinit();
        const again = back.toPem(form, &b) catch unreachable;
        if (!std.mem.eql(u8, pem, again)) @panic("private PEM is not a fixed point");
    }
}
fn parseSsh(in: []const u8) ?usize {
    var sk: SecretKey = undefined;
    fromOpenSSH(&sk, in, "hunter2") catch return null;
    defer sk.deinit();
    return sk.n.bits();
}

fn scriptByte(script: []const u8, i: usize) u8 {
    return if (i < script.len) script[i] else 0;
}

/// The "mutated" overlay: a genuine fixture (chosen by the script), damaged in
/// 0..3 octets and maybe truncated, all read from the drawn octets `script`
/// (missing octets read as zero). An undamaged fixture is a genuine input and
/// MUST be accepted as the 2048-bit key; a damaged one may go either way but
/// must not panic.
fn overlay(comptime parse: fn ([]const u8) ?usize, fixtures: []const []const u8, script: []const u8) !void {
    const fx = fixtures[scriptByte(script, 13) % fixtures.len];
    var out: [2560]u8 = undefined;
    @memcpy(out[0..fx.len], fx);
    var len = fx.len;
    const nd = scriptByte(script, 0) % 4;
    for (0..nd) |i| {
        const pos = ((@as(usize, scriptByte(script, 1 + 3 * i)) << 8) | scriptByte(script, 2 + 3 * i)) % len;
        out[pos] ^= scriptByte(script, 3 + 3 * i);
    }
    if (scriptByte(script, 10) & 0x80 != 0)
        len = ((@as(usize, scriptByte(script, 11)) << 8) | scriptByte(script, 12)) % (len + 1);
    const pristine = std.mem.eql(u8, out[0..len], fx);
    if (parse(out[0..len])) |bits| {
        if (pristine) {
            if (bits != 2048) return error.GenuineKeyMismatch;
            mark(.pristine_accepted);
        } else mark(.damaged_accepted);
    } else {
        if (pristine) return error.GenuineKeyRejected;
        mark(.damaged_rejected);
    }
}

// ── PublicKey.fromDer ────────────────────────────────────────────────────────

// `pub_pkcs1` is `30 82 01 0a | 02 82 01 01 | 00 <256 octets of n> |
// 02 03 01 00 01`, so n occupies indices 9..264 and `pub_spki` carries the
// same blob 24 octets in (SEQUENCE header 4 + AlgorithmIdentifier 15 +
// BIT STRING header 5).
const pubder_seeds = [_][]const u8{
    testkit.fuzz.seed(&kat2048_der.pub_spki), // X.509 SubjectPublicKeyInfo
    testkit.fuzz.seed(&kat2048_der.pub_pkcs1), // bare PKCS#1 RSAPublicKey
    // n with one octet changed in the middle: still odd, still 2048 bits, so
    // this is a DIFFERENT key that parses — the seed's own content decides
    // what comes out, which is what the distinct-moduli count is counting.
    testkit.fuzz.seed(perturbed(&kat2048_der.pub_spki, 124, 0x55)),
    // n's LOW octet flipped: n is now even, which `Modulus.fromBytes` refuses.
    testkit.fuzz.seed(perturbed(&kat2048_der.pub_pkcs1, 264, 0x01)),
    // e's low octet cleared: e = 65536, even, refused by `fromBytes`.
    testkit.fuzz.seed(perturbed(&kat2048_der.pub_pkcs1, 269, 0x01)),
    // The outer SEQUENCE length claims one octet more than the frame has.
    testkit.fuzz.seed(perturbed(&kat2048_der.pub_pkcs1, 3, 0x01)),
    // A truncated SPKI: header intact, key material cut off mid-modulus.
    testkit.fuzz.seed(kat2048_der.pub_spki[0..64]),
    // Not DER at all, and the input the target used to run for ever.
    testkit.fuzz.seed("\x30\x82\xff\xff"),
    testkit.fuzz.seed(""),
};

fn fuzzPublicKeyFromDer(_: void, smith: *std.testing.Smith) !void {
    return pubDerHarness(std.testing.Smith, smith, testing.allocator);
}

fn pubDerHarness(comptime S: type, smith: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    // 1024 against a 294-octet SPKI, the largest public encoding a 2048-bit
    // key makes; a 4096-bit SPKI is still only ~550.
    var buf: [1024]u8 = undefined;
    const len: usize = smith.slice(&buf);
    if (parsePubDer(buf[0..len])) |bits| {
        std.mem.doNotOptimizeAway(bits);
        mark(.raw_accepted);
    } else mark(.raw_rejected);
    try overlay(parsePubDer, &.{ &kat2048_der.pub_spki, &kat2048_der.pub_pkcs1 }, buf[0..len]);
}

test "fuzz: PublicKey.fromDer never panics" {
    try testing.fuzz({}, fuzzPublicKeyFromDer, .{ .corpus = &pubder_seeds });
}

test "corpus: PublicKey.fromDer seeds reach the parser, counts pinned" {
    var nonempty: usize = 0;
    var accepted: usize = 0;
    var moduli: ModuliSeen = .{};
    for (pubder_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [1024]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        const pk = PublicKey.fromDer(buf[0..len]) catch continue;
        accepted += 1;
        try moduli.add(pk.n);
    }
    try testing.expectEqual(pubder_seeds.len - 1, nonempty); // the empty seed
    try testing.expectEqual(@as(usize, 3), accepted);
    try testing.expectEqual(@as(usize, 2), moduli.n);
}

// ── SecretKey.fromDer (bare PKCS#1 RSAPrivateKey) ────────────────────────────

// `priv_pkcs1` is a nine-INTEGER SEQUENCE; the offsets below were read off the
// fixture itself: version 6, n 11..267, e 270..272, d 277..532, p 536..664,
// q 668..796, dP 800..927, dQ 931..1058, qInv 1062..1190.
const secder_seeds = [_][]const u8{
    testkit.fuzz.seed(&kat2048_der.priv_pkcs1), // the real 2048-bit key
    // version 1 = multi-prime (`otherPrimeInfos`), which this parser refuses
    // rather than misreading as a two-prime key.
    testkit.fuzz.seed(perturbed(&kat2048_der.priv_pkcs1, 6, 0x01)),
    // ⭐ One octet changed inside p, and one inside q. Both are refused, for
    // different reasons:
    //   - a corrupted **p** fails the `qInv·q ≡ 1 (mod p)` self-check: qInv
    //     is derived by Fermat inversion q^(p-2) mod p, an inverse only when
    //     p is prime ("catches a non-prime p sneaking past"; before this
    //     corpus nothing ever handed that branch a non-prime p);
    //   - a corrupted **q** derives soundly (p is still prime) to a different
    //     modulus, which until 2026-10-14 was ACCEPTED as that other key; the
    //     wire-`n` check (audit F1) now refuses it.
    testkit.fuzz.seed(perturbed(&kat2048_der.priv_pkcs1, 600, 0x03)),
    testkit.fuzz.seed(perturbed(&kat2048_der.priv_pkcs1, 700, 0x03)),
    // ⭐ One octet changed inside dP. Until 2026-10-14 it came out as the SAME
    // key (the on-disk CRT fields were never read); F1 now refuses it.
    testkit.fuzz.seed(perturbed(&kat2048_der.priv_pkcs1, 900, 0x03)),
    // Outer length one octet too long.
    testkit.fuzz.seed(perturbed(&kat2048_der.priv_pkcs1, 3, 0x01)),
    // Truncated mid-modulus.
    testkit.fuzz.seed(kat2048_der.priv_pkcs1[0..300]),
    // A PKCS#8 wrapper handed to the bare-PKCS#1 parser: the confusion this
    // function exists to refuse.
    testkit.fuzz.seed(&kat2048_der.priv_pkcs8),
    testkit.fuzz.seed(""),
};

fn fuzzSecretKeyFromDer(_: void, smith: *std.testing.Smith) !void {
    return secDerHarness(std.testing.Smith, smith, testing.allocator);
}

fn secDerHarness(comptime S: type, smith: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    // ⛔ 2048 because the module's own 2048-bit PKCS#1 private key is 1191
    // octets. With the old 1024-octet buffer no real private key could ever
    // have passed through this harness: `Smith.slice` checks the declared
    // length against `rangeAtMost(0, buf.len)` and falls back to the range
    // minimum, so an over-long seed reads back as the EMPTY one.
    var buf: [2048]u8 = undefined;
    const len: usize = smith.slice(&buf);
    if (parseSecDer(buf[0..len])) |bits| {
        std.mem.doNotOptimizeAway(bits);
        mark(.raw_accepted);
    } else mark(.raw_rejected);
    try overlay(parseSecDer, &.{&kat2048_der.priv_pkcs1}, buf[0..len]);
}

test "fuzz: SecretKey.fromDer never panics" {
    try testing.fuzz({}, fuzzSecretKeyFromDer, .{ .corpus = &secder_seeds });
}

test "corpus: SecretKey.fromDer seeds reach the parser, counts pinned" {
    var nonempty: usize = 0;
    var accepted: usize = 0;
    var moduli: ModuliSeen = .{};
    for (secder_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [2048]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        var sk: SecretKey = undefined;
        SecretKey.fromDer(&sk, buf[0..len]) catch continue;
        defer sk.deinit();
        accepted += 1;
        try moduli.add(sk.n);
    }
    // Measured 2026-09-07: 0 non-empty / 0 accepted / 0 distinct before,
    // 8 / 3 / 2 after (the q- and dP-perturbations accepted). 2026-10-14,
    // audit F1 (wire fields checked): 8 / 1 / 1 — only the genuine key.
    try testing.expectEqual(secder_seeds.len - 1, nonempty);
    try testing.expectEqual(@as(usize, 1), accepted);
    try testing.expectEqual(@as(usize, 1), moduli.n);
}

// ── fromPkcs8 (PrivateKeyInfo wrapper) ───────────────────────────────────────

// `priv_pkcs8` is `30 82 04 bd | 02 01 00 | 30 0d <rsaEncryption AlgId> |
// 04 82 04 a7 <the priv_pkcs1 blob>`, so the inner key starts at index 26 and
// the algorithm OID's last octet is index 24.
const pkcs8_seeds = [_][]const u8{
    testkit.fuzz.seed(&kat2048_der.priv_pkcs8), // the real PKCS#8 key
    // The algorithm OID's final octet changed: a well-formed PrivateKeyInfo
    // for something that is not rsaEncryption, which must be refused before
    // the inner blob is looked at.
    testkit.fuzz.seed(perturbed(&kat2048_der.priv_pkcs8, 24, 0x02)),
    // One octet inside the wrapped q (726 − 26 = 700, `secder_seeds`' q
    // offset): accepted as another key until audit F1 (2026-10-14).
    testkit.fuzz.seed(perturbed(&kat2048_der.priv_pkcs8, 726, 0x03)),
    // The OCTET STRING length one octet short of its content.
    testkit.fuzz.seed(perturbed(&kat2048_der.priv_pkcs8, 25, 0x01)),
    // Truncated inside the wrapper.
    testkit.fuzz.seed(kat2048_der.priv_pkcs8[0..40]),
    // A bare PKCS#1 key with no wrapper: the confusion this function refuses.
    testkit.fuzz.seed(&kat2048_der.priv_pkcs1),
    testkit.fuzz.seed(""),
};

fn fuzzFromPkcs8(_: void, smith: *std.testing.Smith) !void {
    return pkcs8Harness(std.testing.Smith, smith, testing.allocator);
}

fn pkcs8Harness(comptime S: type, smith: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    // ⛔ 2048: the PKCS#8 form of the module's own 2048-bit key is 1217
    // octets, so 1024 could not carry it (see `fuzzSecretKeyFromDer`).
    var buf: [2048]u8 = undefined;
    const len: usize = smith.slice(&buf);
    if (parsePkcs8(buf[0..len])) |bits| {
        std.mem.doNotOptimizeAway(bits);
        mark(.raw_accepted);
    } else mark(.raw_rejected);
    try overlay(parsePkcs8, &.{&kat2048_der.priv_pkcs8}, buf[0..len]);
}

test "fuzz: fromPkcs8 never panics" {
    try testing.fuzz({}, fuzzFromPkcs8, .{ .corpus = &pkcs8_seeds });
}

test "corpus: fromPkcs8 seeds reach the parser, counts pinned" {
    var nonempty: usize = 0;
    var accepted: usize = 0;
    var moduli: ModuliSeen = .{};
    for (pkcs8_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [2048]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        var sk: SecretKey = undefined;
        fromPkcs8(&sk, buf[0..len]) catch continue;
        defer sk.deinit();
        accepted += 1;
        try moduli.add(sk.n);
    }
    // 2 / 2 until 2026-10-14 (the q-perturbation); F1: the genuine key only.
    try testing.expectEqual(pkcs8_seeds.len - 1, nonempty);
    try testing.expectEqual(@as(usize, 1), accepted);
    try testing.expectEqual(@as(usize, 1), moduli.n);
}

// ── PublicKey.fromPem ────────────────────────────────────────────────────────

const pubpem_seeds = [_][]const u8{
    testkit.fuzz.seed(kat2048_pem.pub_spki), // -----BEGIN PUBLIC KEY-----
    testkit.fuzz.seed(kat2048_pem.pub_pkcs1), // -----BEGIN RSA PUBLIC KEY-----
    // A base64 octet changed inside the body: the block still decodes, so this
    // lands in `fromDer` with a modulus one bit-group off.
    testkit.fuzz.seed(perturbed(kat2048_pem.pub_spki, 120, 0x04)),
    // A private-key label, which `fromPem` must refuse rather than route.
    // ⚠ Deliberately a stub and not the real `kat2048_pem.priv_pkcs8`: that
    // one is 1705 octets against this harness's 1024-octet buffer, so it would
    // read back EMPTY and quietly become a second copy of the empty seed. The
    // guard's `nonempty` count is what caught it.
    testkit.fuzz.seed("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"),
    // Base64 with a character outside the alphabet.
    testkit.fuzz.seed("-----BEGIN PUBLIC KEY-----\n!!!!not base64!!!!\n-----END PUBLIC KEY-----\n"),
    // A BEGIN with no END.
    testkit.fuzz.seed("-----BEGIN PUBLIC KEY-----\nAAAA"),
    // A label longer than `max_pem_label_len`.
    testkit.fuzz.seed("-----BEGIN AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-----\nAAAA\n-----END\n"),
    testkit.fuzz.seed(""),
};

fn fuzzPublicKeyFromPem(_: void, smith: *std.testing.Smith) !void {
    return pubPemHarness(std.testing.Smith, smith, testing.allocator);
}

fn pubPemHarness(comptime S: type, smith: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    // 1024 against a 452-octet PEM public key; the PRIVATE forms are ~1700 and
    // belong to `fuzzSecretKeyFromPem`, which sizes its buffer for them.
    var buf: [1024]u8 = undefined;
    const len: usize = smith.slice(&buf);
    if (parsePubPem(buf[0..len])) |bits| {
        std.mem.doNotOptimizeAway(bits);
        mark(.raw_accepted);
    } else mark(.raw_rejected);
    try overlay(parsePubPem, &.{ kat2048_pem.pub_spki, kat2048_pem.pub_pkcs1 }, buf[0..len]);
}

test "fuzz: PublicKey.fromPem never panics" {
    try testing.fuzz({}, fuzzPublicKeyFromPem, .{ .corpus = &pubpem_seeds });
}

test "corpus: PublicKey.fromPem seeds reach the parser, counts pinned" {
    var nonempty: usize = 0;
    var accepted: usize = 0;
    var moduli: ModuliSeen = .{};
    for (pubpem_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [1024]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        const pk = PublicKey.fromPem(buf[0..len]) catch continue;
        accepted += 1;
        try moduli.add(pk.n);
    }
    try testing.expectEqual(pubpem_seeds.len - 1, nonempty);
    try testing.expectEqual(@as(usize, 3), accepted);
    try testing.expectEqual(@as(usize, 2), moduli.n);
}

// ── SecretKey.fromPem ────────────────────────────────────────────────────────

const secpem_seeds = [_][]const u8{
    testkit.fuzz.seed(kat2048_pem.priv_pkcs1), // -----BEGIN RSA PRIVATE KEY-----
    testkit.fuzz.seed(kat2048_pem.priv_pkcs8), // -----BEGIN PRIVATE KEY-----
    // A base64 octet changed inside the PKCS#1 body, at the text offset that
    // lands in **p** (DER octet ~567), so it reaches the non-prime-p refusal
    // through the PEM route as well. ⚠ The obvious offset 700 lands in `d`,
    // which `fromDer` re-derives and therefore ignores, so that seed parsed to
    // the very same key — a perturbation has to be aimed at a field the parser
    // actually consumes or it is just a second copy of the fixture.
    testkit.fuzz.seed(perturbed(kat2048_pem.priv_pkcs1, 800, 0x04)),
    // The two labels this function refuses by name rather than by content:
    // PKCS#8 encryption is out of scope and OpenSSH belongs to `fromOpenSSH`.
    testkit.fuzz.seed("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n"),
    testkit.fuzz.seed(openssh_fixture_plain),
    // A public-key block where a private one is expected.
    testkit.fuzz.seed(kat2048_pem.pub_spki),
    // Truncated: BEGIN line and part of the body, no END.
    testkit.fuzz.seed(kat2048_pem.priv_pkcs8[0..200]),
    testkit.fuzz.seed(""),
};

fn fuzzSecretKeyFromPem(_: void, smith: *std.testing.Smith) !void {
    return secPemHarness(std.testing.Smith, smith, testing.allocator);
}

fn secPemHarness(comptime S: type, smith: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    // ⛔ 2048: the module's own PKCS#8 PEM private key is 1705 octets and the
    // PKCS#1 one 1676. With the old 1024-octet buffer neither could pass — a
    // seed longer than the buffer reads back EMPTY, silently.
    var buf: [2048]u8 = undefined;
    const len: usize = smith.slice(&buf);
    if (parseSecPem(buf[0..len])) |bits| {
        std.mem.doNotOptimizeAway(bits);
        mark(.raw_accepted);
    } else mark(.raw_rejected);
    try overlay(parseSecPem, &.{ kat2048_pem.priv_pkcs1, kat2048_pem.priv_pkcs8 }, buf[0..len]);
}

test "fuzz: SecretKey.fromPem never panics" {
    try testing.fuzz({}, fuzzSecretKeyFromPem, .{ .corpus = &secpem_seeds });
}

test "corpus: SecretKey.fromPem seeds reach the parser, counts pinned" {
    var nonempty: usize = 0;
    var accepted: usize = 0;
    var moduli: ModuliSeen = .{};
    for (secpem_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [2048]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        var sk: SecretKey = undefined;
        SecretKey.fromPem(&sk, buf[0..len]) catch continue;
        defer sk.deinit();
        accepted += 1;
        try moduli.add(sk.n);
    }
    try testing.expectEqual(secpem_seeds.len - 1, nonempty);
    try testing.expectEqual(@as(usize, 2), accepted);
    try testing.expectEqual(@as(usize, 1), moduli.n);
}

// ── fromOpenSSH ──────────────────────────────────────────────────────────────

/// An OpenSSH corpus entry: the armoured text, then a SECOND length-prefixed
/// field carrying the passphrase.
///
/// ⛔ The passphrase is not decoration and it cannot be a knob drawn after the
/// bytes. `fromOpenSSH(text, "")` — what this harness used to hardcode — stops
/// at the `bcrypt` KDF for every encrypted key, so the aes256-ctr/aes256-cbc
/// halves of the parser, which are the part with a from-scratch Blowfish under
/// them, were unreachable from the harness by construction. Carrying it in the
/// seed keeps the draw byte-first (the gate's requirement) AND leaves the
/// fuzzer driving it.
fn opensshSeed(store: []u8, text: []const u8, passphrase: []const u8) []const u8 {
    const head = testkit.fuzz.seedInto(store, text);
    const tail = testkit.fuzz.seedInto(store[head.len..], passphrase);
    return store[0 .. head.len + tail.len];
}

const OpensshCorpus = struct {
    store: [16384]u8 = undefined,
    used: usize = 0,
    entries: [9][]const u8 = undefined,
    n: usize = 0,

    fn push(self: *OpensshCorpus, text: []const u8, passphrase: []const u8) void {
        const sd = opensshSeed(self.store[self.used..], text, passphrase);
        self.entries[self.n] = self.store[self.used..][0..sd.len];
        self.used += sd.len;
        self.n += 1;
    }

    fn build(self: *OpensshCorpus) []const []const u8 {
        // The unencrypted key, which needs no passphrase.
        self.push(openssh_fixture_plain, "");
        // aes256-ctr and aes256-cbc with the passphrase ssh-keygen was given:
        // bcrypt-pbkdf, then the cipher, then the decrypted private section.
        self.push(openssh_fixture_ctr, "hunter2");
        self.push(openssh_fixture_cbc, "hunter2");
        // The same key with the WRONG passphrase: the KDF and the cipher still
        // run, and the check-int mismatch is what has to catch it.
        self.push(openssh_fixture_ctr, "hunter3");
        // ⭐ Three one-octet perturbations aimed at three different fields of
        // the decoded container, which is how this corpus says what the parser
        // trusts. Offsets read off the fixture: the public blob spans binary
        // octets 43..321 and the private section 326..1293, with n at 349..605,
        // d at 617..872 and p at 1009..1137.
        //   - inside the PUBLIC copy of the modulus (~269): must still parse,
        //     to the same key — the blob is documented as skipped;
        self.push(perturbed(openssh_fixture_plain, 400, 0x04), "");
        //   - inside the private `d` (~861): must still parse, to the same
        //     key — `d` is re-derived from p/q/e and never trusted;
        self.push(perturbed(openssh_fixture_plain, 1200, 0x04), "");
        //   - inside the private `n` (~500): must be REFUSED, by the one
        //     cross-check `parsePrivateSection` performs (n on disk == p*q).
        self.push(perturbed(openssh_fixture_plain, 711, 0x04), "");
        // A PKCS#8 PEM block, i.e. the right armour and the wrong label.
        self.push(kat2048_pem.priv_pkcs8, "");
        // The input this target ran, and only ran, before it had a corpus.
        self.push("", "");
        return self.entries[0..self.n];
    }
};

fn fuzzFromOpenSSH(_: void, smith: *std.testing.Smith) !void {
    return sshHarness(std.testing.Smith, smith, testing.allocator);
}

fn sshHarness(comptime S: type, smith: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    // ⛔ 2560: the module's own OpenSSH fixtures are 1824–1877 octets, so the
    // old 1024-octet buffer could not carry one — an over-long seed reads back
    // as the EMPTY one and says nothing about it.
    var buf: [2560]u8 = undefined;
    const len: usize = smith.slice(&buf);
    var pass: [64]u8 = undefined;
    const plen: usize = smith.slice(&pass);
    var sk: SecretKey = undefined;
    if (fromOpenSSH(&sk, buf[0..len], pass[0..plen])) {
        defer sk.deinit();
        std.mem.doNotOptimizeAway(sk.n.bits());
        mark(.raw_accepted);
    } else |_| mark(.raw_rejected);
    try overlay(parseSsh, &.{ openssh_fixture_plain, openssh_fixture_ctr, openssh_fixture_cbc }, buf[0..len]);
}

test "fuzz: fromOpenSSH never panics" {
    var corpus: OpensshCorpus = .{};
    try testing.fuzz({}, fuzzFromOpenSSH, .{ .corpus = corpus.build() });
}

test "corpus: fromOpenSSH seeds reach the parser, counts pinned" {
    // ⭐ Built from the SAME place the harness builds it; a guard measuring a
    // different corpus is not a guard.
    var corpus: OpensshCorpus = .{};
    const entries = corpus.build();
    var nonempty: usize = 0;
    var with_pass: usize = 0;
    var accepted: usize = 0;
    var moduli: ModuliSeen = .{};
    for (entries) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [2560]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        var pass: [64]u8 = undefined;
        const plen: usize = smith.slice(&pass);
        if (plen != 0) with_pass += 1;
        var sk: SecretKey = undefined;
        fromOpenSSH(&sk, buf[0..len], pass[0..plen]) catch continue;
        defer sk.deinit();
        accepted += 1;
        try moduli.add(sk.n);
    }
    // `with_pass` is the second number the collapse cannot produce: it counts
    // the seeds that carry a passphrase at all, and before this the harness
    // passed `""` on every round, so the bcrypt/AES half of `fromOpenSSH` was
    // structurally out of reach.
    //
    // Measured 2026-09-07: 0 non-empty / 0 with a passphrase / 0 accepted
    // before — the target's only ever input was `fromOpenSSH("", "")` — and
    // 8 / 3 / 5 after. `distinct` stays 1 on purpose: every perturbation that
    // WOULD change the modulus is caught by the `n == p*q` cross-check, so the
    // five accepted seeds are five routes to the same key (plain, aes256-ctr,
    // aes256-cbc, and the two fields the format lets the file lie about).
    try testing.expectEqual(entries.len - 1, nonempty);
    try testing.expectEqual(@as(usize, 3), with_pass);
    try testing.expectEqual(@as(usize, 5), accepted);
    try testing.expectEqual(@as(usize, 1), moduli.n);
}

// ── fromPkcs8Encrypted (PBES2) ───────────────────────────────────────────────

fn parsePbes2(in: []const u8) ?usize {
    var sk: SecretKey = undefined;
    fromPkcs8Encrypted(&sk, in, kat2048_pbes2.password) catch return null;
    defer sk.deinit();
    secretRoundTrip(&sk);
    return sk.n.bits();
}

const pbes2_seeds = [_][]const u8{
    testkit.fuzz.seed(&kat2048_pbes2.aes256_sha256),
    testkit.fuzz.seed(&kat2048_pbes2.aes128_sha1), // PRF omitted (DEFAULT)
    testkit.fuzz.seed(&kat2048_pbes2.aes192_sha512),
    testkit.fuzz.seed(&kat2048_pbes2.scrypt), // UnsupportedEncryption
    testkit.fuzz.seed(&kat2048_pbes2.pbes1), // UnsupportedEncryption
    // The iteration count's low octet changed: the KDF runs, the key is wrong.
    testkit.fuzz.seed(perturbed(&kat2048_pbes2.aes256_sha256, 55, 0x01)),
    // A ciphertext octet in the last block: padding or inner DER breaks.
    testkit.fuzz.seed(perturbed(&kat2048_pbes2.aes256_sha256, kat2048_pbes2.aes256_sha256.len - 20, 0x01)),
    // Plaintext PKCS#8 handed to the encrypted parser.
    testkit.fuzz.seed(&kat2048_der.priv_pkcs8),
    testkit.fuzz.seed(""),
};

fn fuzzFromPkcs8Encrypted(_: void, smith: *std.testing.Smith) !void {
    return pbes2Harness(std.testing.Smith, smith, testing.allocator);
}

fn pbes2Harness(comptime S: type, smith: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var buf: [2048]u8 = undefined; // the fixtures are 1323–1337 octets
    const len: usize = smith.slice(&buf);
    if (parsePbes2(buf[0..len])) |bits| {
        std.mem.doNotOptimizeAway(bits);
        mark(.raw_accepted);
    } else mark(.raw_rejected);
    try overlay(parsePbes2, &.{ &kat2048_pbes2.aes256_sha256, &kat2048_pbes2.aes128_sha1, &kat2048_pbes2.aes192_sha512 }, buf[0..len]);
}

test "fuzz: fromPkcs8Encrypted never panics" {
    try testing.fuzz({}, fuzzFromPkcs8Encrypted, .{ .corpus = &pbes2_seeds });
}

test "corpus: fromPkcs8Encrypted seeds reach the parser, counts pinned" {
    var nonempty: usize = 0;
    var accepted: usize = 0;
    for (pbes2_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [2048]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        if (parsePbes2(buf[0..len]) != null) accepted += 1;
    }
    // The three genuine files; everything else refused (2026-10-14).
    try testing.expectEqual(pbes2_seeds.len - 1, nonempty);
    try testing.expectEqual(@as(usize, 3), accepted);
}

// ── deterministic driver tests ───────────────────────────────────────────────

test "fuzz driver: RSA_FUZZ (rsa-pubder)" {
    try fuzz_driver.run(pubDerHarness, .{ .prefix = "RSA_FUZZ", .name = "rsa-pubder" });
}
test "fuzz driver: RSA_FUZZ (rsa-secder)" {
    try fuzz_driver.run(secDerHarness, .{ .prefix = "RSA_FUZZ", .name = "rsa-secder" });
}
test "fuzz driver: RSA_FUZZ (rsa-pkcs8)" {
    try fuzz_driver.run(pkcs8Harness, .{ .prefix = "RSA_FUZZ", .name = "rsa-pkcs8" });
}
test "fuzz driver: RSA_FUZZ (rsa-pubpem)" {
    try fuzz_driver.run(pubPemHarness, .{ .prefix = "RSA_FUZZ", .name = "rsa-pubpem" });
}
test "fuzz driver: RSA_FUZZ (rsa-secpem)" {
    try fuzz_driver.run(secPemHarness, .{ .prefix = "RSA_FUZZ", .name = "rsa-secpem" });
}
test "fuzz driver: RSA_FUZZ (rsa-pbes2)" {
    try fuzz_driver.run(pbes2Harness, .{ .prefix = "RSA_FUZZ", .name = "rsa-pbes2" });
}
test "fuzz driver: RSA_FUZZ (rsa-openssh)" {
    try fuzz_driver.run(sshHarness, .{ .prefix = "RSA_FUZZ", .name = "rsa-openssh", .scale = 10 });
}

fn reachCheck(comptime harness: anytype, name: []const u8, seeds: usize, optional: ?FuzzLabel) !void {
    fuzz_reach = @splat(0);
    for (0..seeds) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        harness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("{s} seed {d}: {t}\n", .{ name, seed, err });
            return err;
        };
    }
    for (fuzz_reach, 0..) |n, i| {
        const l: FuzzLabel = @fromBackingInt(@intCast(i));
        // Random octets are never a valid key encoding: `raw_accepted` is
        // reached only through the corpus, not by the driver.
        if (l == .raw_accepted) continue;
        if (optional) |o| if (l == o) continue;
        if (n == 0) {
            std.debug.print("reach: {s}: label {t} never hit in {d} seeds\n", .{ name, l, seeds });
            return error.HarnessDoesNotReach;
        }
    }
}

test "fuzz harness: seeds in every test run, and they get everywhere" {
    try reachCheck(pubDerHarness, "rsa-pubder", 300, null);
    try reachCheck(pubPemHarness, "rsa-pubpem", 300, null);
    // Since audit F1 (2026-10-14) every octet of a PKCS#1 private key is bound
    // to the derived key, so a damaged one is never accepted: not demanded.
    // PKCS#8 adds only the 2-octet AlgorithmIdentifier parameters, which are
    // not inspected — too small a target for 100 seeds.
    try reachCheck(secDerHarness, "rsa-secder", 100, .damaged_accepted);
    try reachCheck(pkcs8Harness, "rsa-pkcs8", 100, .damaged_accepted);
    // A damaged base64/armoured body is accepted only by luck (a XOR that lands
    // in padding or whitespace); not demanded for the private PEM and OpenSSH
    // forms, whose seeds are too expensive to run by the thousand.
    try reachCheck(secPemHarness, "rsa-secpem", 100, .damaged_accepted);
    try reachCheck(sshHarness, "rsa-openssh", 30, .damaged_accepted);
    // PBES2: every damaged octet lands in a checked field, the KDF input, or
    // the ciphertext; acceptance is luck (a pad-free change in an ignored
    // NULL), so not demanded.
    try reachCheck(pbes2Harness, "rsa-pbes2", 60, .damaged_accepted);
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    // One @splat + @bitCast, not a loop: a comptime loop writing into an
    // array var costs O(n^2) in Sema (40 000 bytes: 8.7 s; http's test
    // binary spent ~5 min in Sema on these, 2026-10-24).
    const rep_result = comptime blk: {
        const unit: [s.len]u8 = s[0..s.len].*;
        const grid: [n][s.len]u8 = @splat(unit);
        const flat: [s.len * n]u8 = @bitCast(grid);
        break :blk (flat ++ [_:0]u8{})[0 .. s.len * n :0].*;
    };
    return &rep_result;
}
