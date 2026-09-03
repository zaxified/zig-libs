// SPDX-License-Identifier: MIT
//! xmlenc — W3C XML-Encryption (xmlenc-core-1) DECRYPTION for the SAML cluster.
//!
//! Purpose: close the SAML cluster's last gap. `saml` detects a
//! `<saml:EncryptedAssertion>` and refuses it with
//! `error.EncryptedAssertionUnsupported`; eIDAS requires encrypted assertions.
//! This module lets the relying party (the SP, which holds the RSA private
//! key) recover the plaintext `<saml:Assertion>` octets from an
//! `<xenc:EncryptedData>` so the existing parse -> signature-verify -> XSW
//! path can run over the decrypted assertion.
//!
//! **DECRYPTION ONLY.** We are the receiving party with the private key;
//! encryption / ciphertext generation is out of scope, as are CipherReference
//! (external URI dereference — SSRF/XXE surface) and any ds:Transforms on the
//! ciphertext.
//!
//! Threat model: the ciphertext is attacker-influenced. See SPEC.md. In one
//! line: strict algorithm allow-list; GCM (AEAD, fail-closed) and RSA-OAEP are
//! the safe defaults; RSA-1_5 (Bleichenbacher / Jager-Somorovsky) is gated
//! behind an explicit opt-in; AES-CBC unpadding is written to avoid distinct
//! padding-error signals; every failure collapses to a generic
//! `error.DecryptionError`; never panics; the recovered CEK is zeroized.
//!
//! Reference: W3C "XML Encryption Syntax and Processing Version 1.1"
//! (xmlenc-core-1) + RFC 8017 (RSAES-OAEP / RSAES-PKCS1-v1_5) + RFC 3394
//! (AES key wrap) + NIST SP800-38A (CBC) + NIST SP800-38D (GCM).

const std = @import("std");
const xml = @import("xml");
const rsa = @import("rsa");
const aescbc = @import("aescbc");
const aeskw = @import("aeskw");

const Sha1 = std.crypto.hash.Sha1;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Aes128 = std.crypto.core.aes.Aes128;
const Aes256 = std.crypto.core.aes.Aes256;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "XML-Encryption (xmlenc-core-1) **decryption only** — recovers `EncryptedAssertion` plaintext (RSA-OAEP/AES-KW key transport + AES-GCM/CBC content), decrypt-then-verify",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "W3C XML Encryption 1.1 (xmlenc-core-1), decryption side; RFC 8017 / RFC 3394 / NIST SP800-38A/D",
    .deps = .{ "xml", "rsa", "aescbc", "aeskw" },
};

// ── namespace URIs ──────────────────────────────────────────────────────────

/// XML-Encryption core namespace (2001/04).
pub const xenc_ns = "http://www.w3.org/2001/04/xmlenc#";
/// XML-Encryption 1.1 namespace (2009) — carries GCM, xenc11 rsa-oaep, MGF.
pub const xenc11_ns = "http://www.w3.org/2009/xmlenc11#";
/// XML-Signature namespace (2000/09) — KeyInfo, DigestMethod.
pub const ds_ns = "http://www.w3.org/2000/09/xmldsig#";
/// SAML 2.0 assertion namespace (for the EncryptedAssertion wrapper).
pub const saml_ns = "urn:oasis:names:tc:SAML:2.0:assertion";

// ── algorithm identifiers ───────────────────────────────────────────────────

// Content (data) encryption.
const alg_aes128_cbc = xenc_ns ++ "aes128-cbc";
const alg_aes192_cbc = xenc_ns ++ "aes192-cbc";
const alg_aes256_cbc = xenc_ns ++ "aes256-cbc";
const alg_aes128_gcm = xenc11_ns ++ "aes128-gcm";
const alg_aes192_gcm = xenc11_ns ++ "aes192-gcm";
const alg_aes256_gcm = xenc11_ns ++ "aes256-gcm";

// Key transport / key wrap.
const alg_rsa_15 = xenc_ns ++ "rsa-1_5";
const alg_rsa_oaep_mgf1p = xenc_ns ++ "rsa-oaep-mgf1p";
const alg_rsa_oaep = xenc11_ns ++ "rsa-oaep";
const alg_kw_aes128 = xenc_ns ++ "kw-aes128";
const alg_kw_aes256 = xenc_ns ++ "kw-aes256";

// Digest methods (for OAEP).
const alg_sha1 = ds_ns ++ "sha1";
const alg_sha256 = xenc_ns ++ "sha256";

// MGF (xenc11 rsa-oaep).
const alg_mgf1sha1 = xenc11_ns ++ "mgf1sha1";
const alg_mgf1sha256 = xenc11_ns ++ "mgf1sha256";

// ── options & errors ────────────────────────────────────────────────────────

pub const Options = struct {
    /// Opt-in for RSAES-PKCS#1 v1.5 key transport (`rsa-1_5`). OFF by default:
    /// v1.5 is Bleichenbacher-vulnerable and, composed with XML-Enc, enables
    /// the Jager-Somorovsky "How to Break XML Encryption" attack. Only enable
    /// for an IdP that offers nothing else, and prefer to migrate the IdP.
    allow_weak_rsa15: bool = false,

    /// Symmetric key-encryption key for `kw-aes128` / `kw-aes256` key wrap
    /// (RFC 3394). Only consulted when the EncryptedKey uses a kw-aes*
    /// algorithm; `null` (the default) means "no symmetric KEK available", so a
    /// kw-aes* EncryptedKey then fails with `error.KekNotProvided`. Must be 16
    /// bytes (kw-aes128) or 32 bytes (kw-aes256).
    kek: ?[]const u8 = null,

    /// Upper bound on the decoded content ciphertext, in bytes (DoS guard on an
    /// attacker-sized CipherValue). Default 4 MiB — far above any real SAML
    /// assertion.
    max_ciphertext_len: usize = 4 << 20,
};

pub const Error = error{
    /// Structure present but not an algorithm on the allow-list (includes
    /// AES-192 — std 0.16 ships no AES-192 block cipher — and any OAEP
    /// digest/MGF pairing this module cannot express).
    UnsupportedAlgorithm,
    /// Required element/attribute missing, malformed nesting, or a CipherValue
    /// that is not valid base64.
    MalformedStructure,
    /// The CEK could not be unwrapped, or the content did not decrypt/
    /// authenticate. Deliberately GENERIC: every cryptographic failure mode
    /// (wrong key, bad RSA/CBC padding, GCM tag mismatch, RSADP range) maps
    /// here (Bleichenbacher / Manger / padding-oracle).
    ///
    /// ⚠ Collapsing the error VALUE is only half of it, and for a long time it
    /// was the only half here. A failed key unwrap used to return before the
    /// content was touched, so a whole AES pass over an attacker-sized
    /// ciphertext happened on exactly one side of the conformance decision —
    /// measured at 97% classifier accuracy (min-of-8 queries) over a 3 MiB CBC
    /// content ciphertext, with this value fully collapsed throughout. The
    /// content is now decrypted with a decoy CEK on failure so both outcomes do
    /// the same work; see `Unwrapped`, and SPEC.md for the OAEP arm that is
    /// still open.
    DecryptionError,
    /// `rsa-1_5` key transport was used but `Options.allow_weak_rsa15` is false.
    WeakRsa15NotAllowed,
    /// A `<xenc:CipherReference>` (external ciphertext URI) was found. Rejected
    /// unconditionally — dereferencing it is an SSRF/XXE surface.
    CipherReferenceUnsupported,
    /// A kw-aes* EncryptedKey needs a symmetric KEK but `Options.kek` is null.
    KekNotProvided,
    /// Decoded ciphertext exceeds `Options.max_ciphertext_len`.
    CiphertextTooLarge,
} || std.mem.Allocator.Error;

// ── public entry points ─────────────────────────────────────────────────────

/// Decrypt an `<xenc:EncryptedData>` element and return the recovered plaintext
/// octets (owned by `alloc`; caller frees). `sk` is the relying party's RSA
/// private key (used only for rsa-oaep* / rsa-1_5 key transport — for kw-aes*
/// the CEK comes from `options.kek`, and `sk` is ignored).
///
/// For a SAML `Type="...#Element"` EncryptedData the returned bytes are the
/// serialized decrypted element (e.g. `<saml:Assertion ...>...</saml:Assertion>`),
/// ready to feed back into `xml.parse` + signature verification.
///
/// **The returned plaintext is the caller's to destroy** (CONVENTIONS §2.1 Z2).
/// It is recovered sensitive content — for the SAML path, a subject identity
/// and every attribute asserted about it — and this module cannot know when the
/// caller is finished with it. `std.crypto.secureZero` it before `alloc.free`.
/// Every buffer *this* module frees on the way there (the CEK, the CBC
/// plaintext-plus-padding scratch) is wiped here.
pub fn decryptData(
    alloc: std.mem.Allocator,
    encrypted_data: *const xml.Element,
    sk: rsa.SecretKey,
    options: Options,
) Error![]u8 {
    if (!isEl(encrypted_data, xenc_ns, "EncryptedData")) return error.MalformedStructure;

    // 1. Content encryption algorithm.
    const content_method = childEl(encrypted_data, xenc_ns, "EncryptionMethod") orelse
        return error.MalformedStructure;
    const content_alg = content_method.attr("", "Algorithm") orelse return error.MalformedStructure;
    const content = try classifyContent(content_alg);

    // 2. Read the content ciphertext FIRST — this rejects a CipherReference and
    // malformed CipherData structurally, before the private key ever runs.
    const cipher = try readCipherValue(alloc, encrypted_data, options.max_ciphertext_len);
    defer alloc.free(cipher);

    // 3. Locate the EncryptedKey (SAML nests it in ds:KeyInfo) and unwrap the CEK.
    const key_info = childEl(encrypted_data, ds_ns, "KeyInfo") orelse return error.MalformedStructure;
    const enc_key = childEl(key_info, xenc_ns, "EncryptedKey") orelse return error.MalformedStructure;

    var cek_buf: [64]u8 = undefined; // >= any AES key length
    // CONVENTIONS §2.1 Z1: the `defer` is registered BEFORE the fallible
    // `unwrapCek`, not after it. Registered after, an early return from
    // `unwrapCek` skipped the wipe entirely and left whatever the unwrap had
    // already written into the buffer — no current unwrap path copies before
    // it succeeds, but that is an accident of two callees, not a guarantee.
    defer std.crypto.secureZero(u8, cek_buf[0..]);
    const un = try unwrapCek(alloc, enc_key, sk, options, &cek_buf, content.key_len);

    // 4. Decrypt the content with the CEK — INCLUDING when the unwrap failed,
    //    in which case `un.cek` is a decoy of the right length and this pass is
    //    what makes the two outcomes cost the same. See `Unwrapped`. The result
    //    is thrown away below; only the work is wanted.
    const plain = switch (content.mode) {
        .gcm => aesGcmDecrypt(alloc, un.cek, cipher),
        .cbc => aesCbcDecrypt(alloc, un.cek, cipher),
    };
    if (!un.ok) {
        // A decoy cannot authenticate a GCM tag and all but never satisfies CBC
        // padding, so this is nearly always already an error — but "nearly" is
        // not a guarantee, and handing back garbage as plaintext would be a
        // worse bug than the one being fixed. The answer is decided by the
        // mask, not by what the content decryption happened to do.
        if (plain) |p| {
            std.crypto.secureZero(u8, p);
            alloc.free(p);
        } else |_| {}
        return error.DecryptionError;
    }
    return try plain;
}

/// Convenience for the SAML path: take a `<saml:EncryptedAssertion>` wrapper,
/// find its single `<xenc:EncryptedData>` child, and decrypt it. Returns the
/// plaintext `<saml:Assertion>` octets (owned by `alloc`).
pub fn decryptAssertion(
    alloc: std.mem.Allocator,
    encrypted_assertion: *const xml.Element,
    sk: rsa.SecretKey,
    options: Options,
) Error![]u8 {
    if (!isEl(encrypted_assertion, saml_ns, "EncryptedAssertion")) return error.MalformedStructure;
    const ed = childEl(encrypted_assertion, xenc_ns, "EncryptedData") orelse return error.MalformedStructure;
    return decryptData(alloc, ed, sk, options);
}

/// Like `decryptData`, but parse the recovered octets and return the root
/// element inside an owned `xml.Document` (caller `deinit`s). Handy when the
/// caller wants the tree directly; SAML prefers `decryptAssertion` (bytes) so
/// it can re-parse with its own ID-attribute options.
pub fn decryptDataToDocument(
    alloc: std.mem.Allocator,
    encrypted_data: *const xml.Element,
    sk: rsa.SecretKey,
    options: Options,
) (Error || xml.ParseError)!xml.Document {
    const plain = try decryptData(alloc, encrypted_data, sk, options);
    // CONVENTIONS §2.1 Z1: this function ALLOCATES and FREES the plaintext
    // itself and never hands it out, so wiping it is not the caller's job —
    // it is this function's. `decryptData`'s doc comment three lines up says
    // exactly that about its own return value, and the repo-wide zeroization
    // pass that added the wipes inside `decryptData` walked past this sibling.
    // Measured before the fix with a free-scanning allocator in ReleaseFast:
    // 1 of 12 released blocks still held the whole recovered SAML assertion.
    defer {
        std.crypto.secureZero(u8, plain);
        alloc.free(plain);
    }
    return xml.parse(alloc, plain, .{ .id_attr_names = &.{"ID"} });
}

// ── content algorithm classification ────────────────────────────────────────

const ContentMode = enum { cbc, gcm };
const ContentAlg = struct { mode: ContentMode, key_len: usize };

fn classifyContent(alg: []const u8) Error!ContentAlg {
    if (eq(alg, alg_aes128_cbc)) return .{ .mode = .cbc, .key_len = 16 };
    if (eq(alg, alg_aes256_cbc)) return .{ .mode = .cbc, .key_len = 32 };
    if (eq(alg, alg_aes128_gcm)) return .{ .mode = .gcm, .key_len = 16 };
    if (eq(alg, alg_aes256_gcm)) return .{ .mode = .gcm, .key_len = 32 };
    // AES-192 (cbc/gcm) is a real xmlenc algorithm but std 0.16 has no AES-192
    // block cipher — surface it as unsupported, never a silent wrong result.
    if (eq(alg, alg_aes192_cbc) or eq(alg, alg_aes192_gcm)) return error.UnsupportedAlgorithm;
    return error.UnsupportedAlgorithm;
}

// ── CEK unwrap (key transport / key wrap) ───────────────────────────────────

const OaepHash = enum { sha1, sha256 };

/// Unwrap the content-encryption key from an `<xenc:EncryptedKey>`. Returns a
/// subslice of `out` holding the CEK. Never trusts any KeyInfo inside the
/// EncryptedKey — the private key / KEK come from the caller.
/// The largest EncryptedKey ciphertext accepted, in decoded bytes. An RSA block
/// is at most `rsa.max_modulus_len` (512 for RSA-4096) and an AES-KW blob is
/// 40; 1024 is generous for both and is the ceiling on the base64 source too.
const max_wrapped_key_len: usize = 1024;

/// The outcome of a key unwrap.
///
/// `ok = false` means the unwrap failed **cryptographically** — a non-conforming
/// PKCS#1 block, a failed AES-KW integrity check, or a recovered key of the
/// wrong length for the content algorithm. `cek` is then a DECOY of exactly the
/// requested length, so the caller decrypts the content anyway and reports the
/// same `error.DecryptionError` afterwards, having done the same work.
///
/// This is the RFC 8017 §7.2.2 / TLS countermeasure, and it is here because the
/// alternative is a Bleichenbacher oracle at *caller* scope: returning early on
/// a bad block skips an entire AES pass over an attacker-sized ciphertext, which
/// is orders of magnitude louder than anything `rsaPkcs1v15Unwrap`'s mask
/// arithmetic was written to suppress. Collapsing the error VALUE is not the
/// same as collapsing the WORK.
///
/// The decoy must be unpredictable to the peer, or they could craft a content
/// ciphertext that verifies under a decoy they computed themselves and read the
/// bit back out of the success/failure answer. Each path derives it from secret
/// material it already holds — the raw RSA block for PKCS#1 v1.5, the KEK for
/// AES-KW.
///
/// ⛔ Structural failures (a missing element, an unsupported algorithm URI, a
/// refused `rsa-1_5`) still return early. Those decisions are made on PUBLIC
/// data — the document's shape and the caller's `Options` — so an early return
/// discloses nothing the peer did not already choose.
const Unwrapped = struct {
    cek: []const u8,
    ok: bool,
};

/// Derive a decoy CEK of `want` bytes from secret material the peer cannot
/// compute. Domain-separated so a decoy can never collide with any other use of
/// the same secret.
fn decoyCek(secret: []const u8, want: usize, out: *[64]u8) []const u8 {
    var h = Sha256.init(.{});
    h.update("zig-libs/xmlenc decoy CEK v1");
    h.update(secret);
    var digest: [Sha256.digest_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &digest);
    h.final(&digest);
    const n = @min(want, digest.len);
    @memcpy(out[0..n], digest[0..n]);
    // A content algorithm wanting more than one digest is not reachable today
    // (AES-256 is 32 bytes), but zero-filling beats returning a short slice.
    if (want > n) @memset(out[n..want], 0);
    return out[0..want];
}

fn unwrapCek(
    alloc: std.mem.Allocator,
    enc_key: *const xml.Element,
    sk: rsa.SecretKey,
    options: Options,
    out: *[64]u8,
    want: usize,
) Error!Unwrapped {
    const method = childEl(enc_key, xenc_ns, "EncryptionMethod") orelse return error.MalformedStructure;
    const alg = method.attr("", "Algorithm") orelse return error.MalformedStructure;

    // An RSA block or a KW blob is small, and this bound now bounds the WORK
    // as well as the output — see `decodeBase64FromElement`. It used to bound
    // only the decoded size, which let a 1024-byte ceiling admit 191 MB.
    const wrapped = try readCipherValue(alloc, enc_key, max_wrapped_key_len);
    defer alloc.free(wrapped);

    if (eq(alg, alg_rsa_oaep_mgf1p)) {
        // ⛔ OAEP still returns early on a decode failure — see SPEC.md
        // §"Constant-time posture". The decoy needs secret material, and the
        // only secret this path holds is inside `rsa.decryptOaepH`, which
        // reports failure as an error and keeps its intermediate block; giving
        // OAEP the same treatment means either a second modular exponentiation
        // (a louder difference than the one being closed) or a change to the
        // `rsa` module's surface. Recorded, not fixed.
        return .{ .cek = try rsaOaepUnwrap(sk, .{ .digest = .sha1, .mgf = .sha1 }, enc_key, wrapped, out), .ok = true };
    } else if (eq(alg, alg_rsa_oaep)) {
        const h = try oaepHashFromMethod(method);
        return .{ .cek = try rsaOaepUnwrap(sk, h, enc_key, wrapped, out), .ok = true };
    } else if (eq(alg, alg_rsa_15)) {
        if (!options.allow_weak_rsa15) return error.WeakRsa15NotAllowed;
        return try rsaPkcs1v15Unwrap(sk, wrapped, out, want);
    } else if (eq(alg, alg_kw_aes128) or eq(alg, alg_kw_aes256)) {
        const kek = options.kek orelse return error.KekNotProvided;
        const kek_want: usize = if (eq(alg, alg_kw_aes128)) 16 else 32;
        if (kek.len != kek_want) return error.UnsupportedAlgorithm;
        return try aesKwUnwrap(kek, wrapped, out, want);
    }
    return error.UnsupportedAlgorithm;
}

/// Digest hash (DigestMethod) and MGF1 hash for an OAEP EncryptedKey. The two
/// may differ — RFC 8017 treats them as independent parameters, and real-world
/// xenc11 `rsa-oaep` configs use e.g. DigestMethod=SHA-256 with MGF1=SHA-1.
/// `rsa.decryptOaepH` is decoupled-hash, so any of the four combinations below
/// is expressible; see SPEC.md.
const OaepHashes = struct { digest: OaepHash, mgf: OaepHash };

/// Resolve the OAEP digest + MGF1 hash for an xenc11 `rsa-oaep`
/// EncryptionMethod.
fn oaepHashFromMethod(method: *const xml.Element) Error!OaepHashes {
    // DigestMethod defaults to SHA-256 for xenc11 rsa-oaep when absent.
    var digest: OaepHash = .sha256;
    if (childEl(method, ds_ns, "DigestMethod")) |dm| {
        const da = dm.attr("", "Algorithm") orelse return error.MalformedStructure;
        if (eq(da, alg_sha1)) {
            digest = .sha1;
        } else if (eq(da, alg_sha256)) {
            digest = .sha256;
        } else return error.UnsupportedAlgorithm;
    }
    // MGF defaults to mgf1sha1 (the xenc11 spec default) when absent.
    var mgf: OaepHash = .sha1;
    if (childEl(method, xenc11_ns, "MGF")) |mg| {
        const ma = mg.attr("", "Algorithm") orelse return error.MalformedStructure;
        if (eq(ma, alg_mgf1sha1)) {
            mgf = .sha1;
        } else if (eq(ma, alg_mgf1sha256)) {
            mgf = .sha256;
        } else return error.UnsupportedAlgorithm;
    }
    return .{ .digest = digest, .mgf = mgf };
}

fn rsaOaepUnwrap(
    sk: rsa.SecretKey,
    hashes: OaepHashes,
    enc_key: *const xml.Element,
    wrapped: []const u8,
    out: *[64]u8,
) Error![]const u8 {
    // OAEPparams (the OAEP label L) is optional; empty when absent.
    var label_buf: [256]u8 = undefined;
    var label: []const u8 = "";
    if (childEl(childEl(enc_key, xenc_ns, "EncryptionMethod").?, xenc_ns, "OAEPparams")) |op| {
        label = try readBase64Text(op, &label_buf);
    }
    // The CEK is at most 32 bytes; the OAEP max-message bound depends on k and
    // the hash, so give decryptOaepH a generous buffer and copy the result out.
    var msg_buf: [rsa.max_modulus_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &msg_buf);
    const msg = switch (hashes.digest) {
        .sha1 => switch (hashes.mgf) {
            .sha1 => rsa.decryptOaepH(sk, Sha1, Sha1, wrapped, label, &msg_buf),
            .sha256 => rsa.decryptOaepH(sk, Sha1, Sha256, wrapped, label, &msg_buf),
        },
        .sha256 => switch (hashes.mgf) {
            .sha1 => rsa.decryptOaepH(sk, Sha256, Sha1, wrapped, label, &msg_buf),
            .sha256 => rsa.decryptOaepH(sk, Sha256, Sha256, wrapped, label, &msg_buf),
        },
    } catch return error.DecryptionError;
    if (msg.len == 0 or msg.len > out.len) return error.DecryptionError;
    @memcpy(out[0..msg.len], msg);
    return out[0..msg.len];
}

/// RSAES-PKCS#1 v1.5 decryption (RFC 8017 §7.2.2). Gated behind
/// `allow_weak_rsa15`.
///
/// Bleichenbacher hardening, stated precisely (see `SPEC.md` §"Constant-time
/// posture" for what is and is not verified):
///
///   * Every validity check accumulates into one all-ones/all-zeros mask built
///     from `ctEqByteMask` / `ctGeMaskUsize`, which are pure integer arithmetic.
///     No `if`, no `while` condition and no array index anywhere in this
///     function depends on the *contents* of `em`.
///   * The separator search always walks the whole block; the message copy
///     always performs the same fixed number of byte operations, over indices
///     derived only from the (public) modulus length.
///   * `out` is written with a fixed-length masked copy, so a rejected block
///     leaves it all-zero rather than skipping the write.
///   * Exactly one branch on secret-derived data remains — the final
///     accept/reject — and it is the outcome itself, with nothing but the
///     return after it. Both outcomes collapse to one `error.DecryptionError`
///     at every caller.
///
/// `em.len`, the loop bounds and `wrapped.len` are all functions of the public
/// modulus length. (std does not let us hide the RSADP range check, which is on
/// the public ciphertext anyway.)
fn rsaPkcs1v15Unwrap(sk: rsa.SecretKey, wrapped: []const u8, out: *[64]u8, want: usize) Error!Unwrapped {
    // `want` is the content algorithm's key length, decided by a public
    // algorithm URI, so refusing an impossible one here leaks nothing — and the
    // decoy is written into `out`, which this bounds.
    if (want == 0 or want > out.len) return error.DecryptionError;
    var em_buf: [rsa.max_modulus_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &em_buf);
    const em = try rsaRawPrivate(sk, wrapped, &em_buf);
    // EM = 0x00 || 0x02 || PS || 0x00 || M, PS >= 8 nonzero octets (RFC 8017
    // §7.2.2). `em.len` is the modulus byte length: public.
    if (em.len < 11) return error.DecryptionError;
    const all_ones = ~@as(usize, 0);
    var good: usize = all_ones;
    good &= ctEqByteMask(em[0], 0x00);
    good &= ctEqByteMask(em[1], 0x02);
    // Locate the first 0x00 at index >= 2; PS is everything before it and must
    // be all-nonzero and >= 8 bytes.
    var seen_sep: usize = 0;
    var sep_idx: usize = 0;
    var i: usize = 2;
    while (i < em.len) : (i += 1) {
        const is_zero = ctEqByteMask(em[i], 0x00);
        // Record the first separator position without branching on it.
        const first = ~seen_sep & is_zero;
        sep_idx = ctSelectUsize(first, i, sep_idx);
        seen_sep |= is_zero;
    }
    good &= seen_sep; // a 0x00 terminator must exist
    // PS length = sep_idx - 2 must be >= 8, i.e. sep_idx >= 10.
    good &= ctGeMaskUsize(sep_idx, 10);
    // `sep_idx <= em.len - 1` always holds (it is either an in-range index or
    // the 0 initialiser), so this cannot underflow and needs no guard.
    const msg_len = em.len - sep_idx - 1;
    good &= ~ctEqMaskUsize(msg_len, 0); // a zero-length message is not a CEK
    good &= ctGeMaskUsize(out.len, msg_len); // and it must fit the CEK buffer
    // The content algorithm's key length is folded in HERE rather than checked
    // by the caller. A conforming block carrying a differently-sized key is one
    // of the three arms a Bleichenbacher search separates, and checking it one
    // frame up put it back on the fast path — measured at 97% classifier
    // accuracy over a 3 MiB content ciphertext.
    good &= ctEqMaskUsize(msg_len, want);

    // Fixed-shape message extraction. Rather than reading `em` at the
    // secret-derived offset `sep_idx + 1` (a data-dependent memory access), try
    // every *public* separator position and keep the one that matches. The work
    // done is a function of `em.len` alone.
    var msg_buf: [64]u8 = @splat(0);
    defer std.crypto.secureZero(u8, &msg_buf);
    var s: usize = 2;
    while (s + 1 < em.len) : (s += 1) {
        const m: u8 = @truncate(ctEqMaskUsize(s, sep_idx));
        const take = @min(em.len - s - 1, msg_buf.len);
        for (msg_buf[0..take], em[s + 1 ..][0..take]) |*o, v| o.* |= v & m;
    }
    // Publish under the validity mask: on rejection `out` becomes all-zero
    // rather than being left untouched, so the write is unconditional and no
    // recovered plaintext survives in the caller's buffer.
    const pub_mask: u8 = @truncate(good);
    for (out, &msg_buf) |*o, v| o.* = v & pub_mask;

    if (good == 0) {
        // Not an error: a decoy of the right length, so the caller decrypts the
        // content either way. `em` is c^d mod n — the peer cannot compute it,
        // which is what stops them crafting content that verifies under a decoy
        // they predicted. See `Unwrapped`.
        return .{ .cek = decoyCek(em, want, out), .ok = false };
    }
    return .{ .cek = out[0..want], .ok = true };
}

/// Raw RSADP over the module's CRT primitive. `rsadpCrt` needs a comptime
/// modulus length, so dispatch on the (public) modulus byte length across the
/// realistic RSA key sizes. `wrapped.len` must equal k.
fn rsaRawPrivate(sk: rsa.SecretKey, wrapped: []const u8, out: *[rsa.max_modulus_len]u8) Error![]const u8 {
    const k = (sk.n.bits() + 7) / 8;
    if (wrapped.len != k) return error.DecryptionError;
    inline for (.{ 64, 128, 192, 256, 384, 512 }) |L| {
        if (k == L) {
            var c: [L]u8 = undefined;
            @memcpy(&c, wrapped[0..L]);
            const m = rsa.rsadpCrt(L, c, sk) catch return error.DecryptionError;
            @memcpy(out[0..L], &m);
            return out[0..L];
        }
    }
    return error.DecryptionError; // non-standard modulus size
}

fn aesKwUnwrap(kek: []const u8, wrapped: []const u8, out: *[64]u8, want: usize) Error!Unwrapped {
    // RFC 3394 unwrap (delegated to the shared `aeskw` module): recovered
    // length = wrapped.len - 8. Any failure (bad length, unsupported KEK
    // length, integrity-check mismatch) collapses to the generic
    // `DecryptionError` — see the module doc comment on error posture.
    // Both length checks are on PUBLIC data (the ciphertext's own length), so
    // returning early here discloses nothing the peer did not choose. ⚠ Without
    // the first one, `wrapped.len - 8` wraps around on a `usize` for any blob
    // under 8 bytes and `out[0..plain_len]` slices a 64-byte array to ~2^64.
    if (wrapped.len < 24) return error.DecryptionError;
    const plain_len = wrapped.len - 8;
    if (plain_len > out.len) return error.DecryptionError;
    if (aeskw.unwrap(kek, wrapped, out[0..plain_len])) |_| {
        // The integrity check passed. A key of the wrong length for the content
        // algorithm is still a failure, but it takes the same route as any
        // other so the work stays identical.
        if (plain_len == want) return .{ .cek = out[0..want], .ok = true };
    } else |_| {}
    // The KEK is secret and the peer cannot compute it, so a decoy keyed on it
    // is unpredictable — see `Unwrapped`. Bound to the wrapped bytes as well, so
    // two different blobs do not decoy to the same key.
    var secret: [64 + 1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &secret);
    const n = @min(kek.len, 64);
    @memcpy(secret[0..n], kek[0..n]);
    const m = @min(wrapped.len, secret.len - n);
    @memcpy(secret[n..][0..m], wrapped[0..m]);
    return .{ .cek = decoyCek(secret[0 .. n + m], want, out), .ok = false };
}

// ── content decryption ──────────────────────────────────────────────────────

/// AES-GCM (SP800-38D). XML-Enc layout: IV(12) || ciphertext || tag(16); AAD is
/// empty. Fails closed on tag mismatch.
fn aesGcmDecrypt(alloc: std.mem.Allocator, key: []const u8, data: []const u8) Error![]u8 {
    const iv_len = 12;
    const tag_len = 16;
    if (data.len < iv_len + tag_len) return error.DecryptionError;
    const npub = data[0..iv_len].*;
    const ct = data[iv_len .. data.len - tag_len];
    const tag: [tag_len]u8 = data[data.len - tag_len ..][0..tag_len].*;

    const out = try alloc.alloc(u8, ct.len);
    errdefer alloc.free(out);
    switch (key.len) {
        16 => Aes128Gcm.decrypt(out, ct, tag, "", npub, key[0..16].*) catch return error.DecryptionError,
        32 => Aes256Gcm.decrypt(out, ct, tag, "", npub, key[0..32].*) catch return error.DecryptionError,
        else => return error.UnsupportedAlgorithm,
    }
    return out;
}

/// AES-CBC (SP800-38A, via the shared `aescbc` module) with XML-Enc padding
/// (`aescbc.unpadXmlEnc`). Layout: IV(16) || ciphertext (16-byte multiple).
/// Padding: the final byte N (1..16) is the pad length; the preceding N-1 pad
/// bytes are arbitrary (only the length byte is meaningful). Any failure
/// (misaligned ciphertext, `aescbc`'s own `NotBlockAligned`/`BufferTooSmall`,
/// or an invalid pad) collapses to the generic `DecryptionError` — padding-
/// oracle hardening; the safe composition is still decrypt-then-signature-
/// verify; see SPEC.md.
fn aesCbcDecrypt(alloc: std.mem.Allocator, key: []const u8, data: []const u8) Error![]u8 {
    const bs = aescbc.block_len;
    if (data.len < 2 * bs or (data.len - bs) % bs != 0) return error.DecryptionError;
    const iv = data[0..bs].*;
    const ct = data[bs..];

    const buf = try alloc.alloc(u8, ct.len);
    // CONVENTIONS §2.1 Z1: `buf` is the recovered plaintext (plus padding) in
    // heap storage this function owns and frees, so it goes back to the
    // allocator — and on to unrelated code — unless it is wiped first. One
    // `defer` covers the success path and the padding-failure path alike; the
    // old `errdefer` + explicit `free` pair wiped neither.
    defer {
        std.crypto.secureZero(u8, buf);
        alloc.free(buf);
    }

    const n = switch (key.len) {
        16 => aescbc.decrypt(Aes128, key[0..16].*, iv, ct, buf),
        32 => aescbc.decrypt(Aes256, key[0..32].*, iv, ct, buf),
        else => return error.UnsupportedAlgorithm, // errdefer frees buf
    } catch return error.DecryptionError;

    const plain_len = aescbc.unpadXmlEnc(buf[0..n]) catch return error.DecryptionError;
    // Shrink into a right-sized allocation (never hand back a slice whose
    // backing capacity leaks the pad); free the scratch buffer on success.
    const out = try alloc.alloc(u8, plain_len);
    @memcpy(out, buf[0..plain_len]);
    return out;
}

// ── XML helpers ─────────────────────────────────────────────────────────────

fn isEl(el: *const xml.Element, uri: []const u8, local: []const u8) bool {
    return eq(el.uri, uri) and eq(el.local, local);
}

fn childEl(parent: *const xml.Element, uri: []const u8, local: []const u8) ?*const xml.Element {
    for (parent.children) |c| switch (c.content) {
        .element => |e| if (isEl(e, uri, local)) return e,
        else => {},
    };
    return null;
}

/// Read the base64 CipherData/CipherValue under `parent` and return the decoded
/// bytes (owned by `alloc`). Rejects a CipherReference (external URI).
///
/// **Exactly one** `CipherData`, and exactly one `CipherValue` inside it. The
/// xenc schema says so (`CipherData` is `minOccurs=1 maxOccurs=1`, its body a
/// choice of one `CipherValue` or one `CipherReference`) and `xmlsec1` enforces
/// it — measured: `xmlsec1 --decrypt` refuses a document with two `CipherData`
/// or two `CipherValue` children, while a first-match search here happily
/// decrypted the first one. That is signature wrapping's shape one layer down:
/// two implementations looking at the same document disagreeing about whether
/// it is even valid, and — if a third resolves duplicates last-match — about
/// which ciphertext IS the message.
fn readCipherValue(alloc: std.mem.Allocator, parent: *const xml.Element, max_len: usize) Error![]u8 {
    const cipher_data = try onlyChild(parent, xenc_ns, "CipherData");
    if (childEl(cipher_data, xenc_ns, "CipherReference") != null) return error.CipherReferenceUnsupported;
    const cipher_value = try onlyChild(cipher_data, xenc_ns, "CipherValue");

    return decodeBase64FromElement(alloc, cipher_value, max_len);
}

/// `childEl`, but a second match is `error.MalformedStructure` rather than
/// silently the first one. See `readCipherValue`.
fn onlyChild(parent: *const xml.Element, uri: []const u8, local: []const u8) Error!*const xml.Element {
    var found: ?*const xml.Element = null;
    for (parent.children) |c| switch (c.content) {
        .element => |e| if (isEl(e, uri, local)) {
            if (found != null) return error.MalformedStructure;
            found = e;
        },
        else => {},
    };
    return found orelse error.MalformedStructure;
}

/// Whitespace-strip and base64-decode an element's text content, bounding the
/// SOURCE before any of it is copied.
///
/// The previous route was `textContent(alloc)` — one full copy of the attacker's
/// text — then an `ArrayList` grown byte by byte — a second — and only then
/// `if (n > max_len) return error.CiphertextTooLarge`. So `max_len` bounded the
/// OUTPUT while the work was unbounded: the EncryptedKey's hard-coded 1024-byte
/// ceiling, justified in its own comment as "an RSA block / KW blob is small",
/// admitted **191 MB of peak live allocation and 474 ms** from one
/// unauthenticated document — 186,000x the stated bound, all of it spent before
/// the private key is touched, and `saml`'s `EncryptedAssertion` path reaches
/// here pre-authentication. A real, enforced cap that bounds the wrong quantity.
///
/// Now: walk the text nodes without copying, refuse as soon as the significant
/// (non-whitespace) character count cannot possibly decode within `max_len`, and
/// only then allocate — once, at the exact size. The document's own bytes are
/// already resident (the caller parsed it), so the walk adds nothing.
fn decodeBase64FromElement(alloc: std.mem.Allocator, el: *const xml.Element, max_len: usize) Error![]u8 {
    // base64 spends 4 characters per 3 bytes; +4 covers the padding group.
    const max_chars = (std.math.divCeil(usize, max_len, 3) catch return error.CiphertextTooLarge) * 4 + 4;

    var n_sig: usize = 0;
    try countSignificant(el, max_chars, &n_sig);

    const compact = try alloc.alloc(u8, n_sig);
    defer alloc.free(compact);
    var w: usize = 0;
    gatherSignificant(el, compact, &w);
    std.debug.assert(w == n_sig);

    const dec = std.base64.standard.Decoder;
    const n = dec.calcSizeForSlice(compact) catch return error.MalformedStructure;
    if (n > max_len) return error.CiphertextTooLarge;
    const out = try alloc.alloc(u8, n);
    errdefer alloc.free(out);
    dec.decode(out, compact) catch return error.MalformedStructure;
    return out;
}

fn isB64Space(c: u8) bool {
    return c == ' ' or c == '\t' or c == '\r' or c == '\n';
}

fn countSignificant(el: *const xml.Element, cap: usize, n: *usize) Error!void {
    for (el.children) |c| switch (c.content) {
        .text, .cdata => |t| {
            for (t) |ch| {
                if (isB64Space(ch)) continue;
                n.* += 1;
                if (n.* > cap) return error.CiphertextTooLarge;
            }
        },
        // `textContent` descends into child elements and `xmlsec1` accepts a
        // nested element inside CipherValue too, so the traversal matches both
        // — this is a bound on the work, not a change of shape.
        .element => |e| try countSignificant(e, cap, n),
        .comment, .pi => {},
    };
}

fn gatherSignificant(el: *const xml.Element, out: []u8, w: *usize) void {
    for (el.children) |c| switch (c.content) {
        .text, .cdata => |t| {
            for (t) |ch| {
                if (isB64Space(ch)) continue;
                out[w.*] = ch;
                w.* += 1;
            }
        },
        .element => |e| gatherSignificant(e, out, w),
        .comment, .pi => {},
    };
}

/// Decode a base64 element's text into `out` (small, fixed buffers only — for
/// the OAEP label). Returns a subslice of `out`.
fn readBase64Text(el: *const xml.Element, out: []u8) Error![]const u8 {
    var buf: [512]u8 = undefined;
    const raw = if (el.children.len == 0) "" else blk: {
        // textContent needs an allocator; the label is tiny, so gather inline.
        var fbs = std.heap.FixedBufferAllocator.init(&buf);
        break :blk el.textContent(fbs.allocator()) catch return error.MalformedStructure;
    };
    return decodeBase64Fixed(raw, out);
}

/// Whitespace-strip + base64-decode into a fixed buffer (for the tiny OAEP
/// label). Returns a subslice of `out`.
fn decodeBase64Fixed(text: []const u8, out: []u8) Error![]const u8 {
    var compact_buf: [512]u8 = undefined;
    var w: usize = 0;
    for (text) |c| {
        if (c == ' ' or c == '\t' or c == '\r' or c == '\n') continue;
        if (w >= compact_buf.len) return error.MalformedStructure;
        compact_buf[w] = c;
        w += 1;
    }
    const dec = std.base64.standard.Decoder;
    const n = dec.calcSizeForSlice(compact_buf[0..w]) catch return error.MalformedStructure;
    if (n > out.len) return error.MalformedStructure;
    dec.decode(out[0..n], compact_buf[0..w]) catch return error.MalformedStructure;
    return out[0..n];
}

// ── constant-time byte helpers ──────────────────────────────────────────────

fn eq(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

// These return an all-ones / all-zeros *mask*, not a 0/1 flag, and are written
// as pure integer arithmetic so that no comparison operator (which lowers to a
// branch or a conditional move at the compiler's discretion) sits on a secret.
// `std.crypto.timing_safe` offers no scalar select or equality mask — only
// `eql`/`compare` over slices and the valgrind `classify`/`declassify`
// annotations — so these are the minimum that has to be hand-rolled.
//
// The mask width is `usize` throughout so that masks can be combined with
// index arithmetic without a widening step.

const usize_bits = @bitSizeOf(usize);

/// All-ones iff `a == b`, all-zeros otherwise. Branch-free.
fn ctEqByteMask(a: u8, b: u8) usize {
    // `d | -d` has its top bit set for every d != 0, and is 0 for d == 0.
    const d: usize = a ^ b;
    const nonzero = (d | (0 -% d)) >> (usize_bits - 1);
    return nonzero -% 1;
}

/// All-ones iff `a == b`, all-zeros otherwise. Branch-free.
fn ctEqMaskUsize(a: usize, b: usize) usize {
    const d = a ^ b;
    const nonzero = (d | (0 -% d)) >> (usize_bits - 1);
    return nonzero -% 1;
}

/// All-ones iff `a >= b` (unsigned), all-zeros otherwise. Branch-free.
fn ctGeMaskUsize(a: usize, b: usize) usize {
    // Hacker's Delight §2-12: the borrow out of `a - b` — which is exactly the
    // predicate `a < b` for unsigned operands — is the top bit of
    // `(~a & b) | (~(a ^ b) & (a - b))`.
    const lt = ((~a & b) | (~(a ^ b) & (a -% b))) >> (usize_bits - 1);
    return lt -% 1;
}

/// `a` when `mask` is all-ones, `b` when it is all-zeros. Branch-free.
fn ctSelectUsize(mask: usize, a: usize, b: usize) usize {
    return (a & mask) | (b & ~mask);
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test {
    testing.refAllDecls(@This());
    _ = @import("test_roundtrip.zig");
    _ = @import("test_external.zig");
}

test "classifyContent allow-list" {
    try testing.expectEqual(ContentMode.cbc, (try classifyContent(alg_aes256_cbc)).mode);
    try testing.expectEqual(@as(usize, 16), (try classifyContent(alg_aes128_gcm)).key_len);
    try testing.expectError(error.UnsupportedAlgorithm, classifyContent(alg_aes192_cbc));
    try testing.expectError(error.UnsupportedAlgorithm, classifyContent("http://example.com/bogus"));
}

// NOTE: the byte-exact NIST SP800-38A F.2.5 (AES-256-CBC) core KAT this
// module used to carry directly now lives in `aescbc`'s own tests (single
// source of truth — `modules/aescbc/src/root.zig`). This module's own
// `aesCbcDecrypt` (the full IV-prefixed layout + XML-Enc unpad) is exercised
// byte-exact-on-recovered-plaintext by the CBC round-trip tests in
// `test_roundtrip.zig` ("OAEP-mgf1p (SHA1) + AES-256-CBC" / "+ AES-128-CBC").

test "RFC 3394 §4.1 AES key unwrap (byte-exact)" {
    const kek = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const key_data = [_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    const ciphertext = [_]u8{
        0x1f, 0xa6, 0x8b, 0x0a, 0x81, 0x12, 0xb4, 0x47,
        0xae, 0xf3, 0x4b, 0xd8, 0xfb, 0x5a, 0x7b, 0x82,
        0x9d, 0x3e, 0x86, 0x23, 0x71, 0xd2, 0xcf, 0xe5,
    };
    var out: [64]u8 = undefined;
    const un = try aesKwUnwrap(&kek, &ciphertext, &out, key_data.len);
    try testing.expect(un.ok);
    try testing.expectEqualSlices(u8, &key_data, un.cek);
}

// ── RFC 8017 §7.2.2 unpadding teeth ─────────────────────────────────────────
//
// This replaces a placeholder that asserted `testing.expect(true)` and said so
// in its own comment ("feeding a fake modexp is out of scope"). It is not out
// of scope: RSA is a bijection, so a chosen EM block can be handed to the
// *production* `rsaPkcs1v15Unwrap` by raw-encrypting it with the matching
// public key (`rsa.rsaep`) — RSADP then hands the unpadding exactly the block
// we built. No refactor, no fake key, no test-only entry point.
//
// This matters because the module's own threat model names Bleichenbacher and
// Jager–Somorovsky as the reason `rsa-1_5` is gated behind `allow_weak_rsa15`:
// the unpadding IS the check that stands between a deployment that flips that
// opt-in and those attacks. Before this table, deleting the block-type check
// (`em[1] == 0x02`) or the PS ≥ 8 minimum left the whole suite green.
//
// Key size: a 512-bit modulus (k = 64) is used deliberately. The PS-length
// boundary is only reachable at all when `k - sep_idx - 1` still fits the
// 64-byte CEK buffer; with k = 128 a 7-octet PS implies a 118-byte "message"
// and would be rejected by the length arm instead, so the PS test would pass
// for the wrong reason. The over-long-message arm gets its own 1024-bit case.

/// Deterministic test keys (test-only use of a seeded PRNG, as elsewhere here).
fn v15TestKey(comptime bits: usize) !rsa.KeyPair {
    var prng = std.Random.DefaultPrng.init(0x15_C0_DE_15);
    return rsa.generate(prng.random(), bits, 65537);
}

/// Build an EM block of exactly `k` bytes: `b0 || b1 || PS || sep || M`, where
/// PS is `ps_len` nonzero octets and `sep` is 0x00 unless `terminate` is false
/// (in which case the whole tail after the prefix is nonzero — no terminator).
fn buildEm(comptime k: usize, b0: u8, b1: u8, ps_len: usize, msg_len: usize, terminate: bool) [k]u8 {
    var em: [k]u8 = undefined;
    @memset(&em, 0xBB); // nonzero filler
    em[0] = b0;
    em[1] = b1;
    if (terminate) {
        std.debug.assert(2 + ps_len + 1 + msg_len == k);
        em[2 + ps_len] = 0x00;
        // A recognisable message body so the recovered bytes can be compared.
        for (em[2 + ps_len + 1 ..], 0..) |*p, i| p.* = @intCast((i % 251) + 1);
    }
    return em;
}

/// Hand `em` to the production unpadding by raw-encrypting it under `pk`, and
/// turn its masked result back into the accept/reject answer these tests are
/// about. `want` is the content algorithm's key length, which the unpadding
/// folds into its validity mask — each case below passes its OWN message
/// length, so the only thing that can reject a case is the check it names.
fn unpadEm(comptime k: usize, em: [k]u8, kp: rsa.KeyPair, out: *[64]u8, want: usize) Error![]const u8 {
    const ct = rsa.rsaep(k, em, kp.public_key) catch return error.DecryptionError;
    const un = try rsaPkcs1v15Unwrap(kp.secret_key, &ct, out, want);
    if (!un.ok) return error.DecryptionError;
    return un.cek;
}

test "TEETH: PKCS#1 v1.5 unpadding accepts a valid EM and the PS=8 boundary" {
    const k = 64;
    var kp = try v15TestKey(512);
    defer kp.secret_key.deinit();
    var out: [64]u8 = undefined;

    // Ordinary CEK-sized message: EM = 00 02 PS(29) 00 M(32).
    const good = buildEm(k, 0x00, 0x02, 29, 32, true);
    const rec = try unpadEm(k, good, kp, &out, 32);
    try testing.expectEqualSlices(u8, good[k - 32 ..], rec);

    // PS of exactly 8 octets is the RFC 8017 §7.2.2 minimum — must be ACCEPTED.
    // (This is the positive half of the boundary; the negative half is PS = 7
    // in the rejection table below. Without both, `sep_idx >= 10` can be moved
    // in either direction unnoticed.)
    const ps8 = buildEm(k, 0x00, 0x02, 8, 53, true);
    const rec8 = try unpadEm(k, ps8, kp, &out, 53);
    try testing.expectEqualSlices(u8, ps8[k - 53 ..], rec8);
}

test "TEETH: PKCS#1 v1.5 unpadding rejects every malformed EM (RFC 8017 §7.2.2)" {
    const k = 64;
    var kp = try v15TestKey(512);
    defer kp.secret_key.deinit();
    var out: [64]u8 = undefined;

    const Case = struct {
        name: []const u8,
        em: [k]u8,
        /// The message length this case's EM claims — passed as `want` so the
        /// key-length fold can never be the reason a case is rejected.
        want: usize,
    };
    const cases = [_]Case{
        // EM[0] must be 0x00.
        .{ .name = "leading octet 0x01", .em = buildEm(k, 0x01, 0x02, 29, 32, true), .want = 32 },
        // EM[1] must be 0x02. 0x01 is block type 1 (the *signature* padding
        // type) — accepting it is the classic v1.5 confusion, and dropping this
        // single check is what previously survived the whole suite.
        .{ .name = "block type 1 (signature padding)", .em = buildEm(k, 0x00, 0x01, 29, 32, true), .want = 32 },
        .{ .name = "block type 0", .em = buildEm(k, 0x00, 0x00, 29, 32, true), .want = 32 },
        .{ .name = "block type 3", .em = buildEm(k, 0x00, 0x03, 29, 32, true), .want = 32 },
        // PS must be at least 8 octets. 7 is one below the bound; everything
        // else about this block is valid, so the PS minimum is the only check
        // that can reject it.
        .{ .name = "PS of 7 octets (one below the minimum)", .em = buildEm(k, 0x00, 0x02, 7, 54, true), .want = 54 },
        .{ .name = "PS of 1 octet", .em = buildEm(k, 0x00, 0x02, 1, 60, true), .want = 60 },
        .{ .name = "PS of 0 octets (0x00 immediately after the prefix)", .em = buildEm(k, 0x00, 0x02, 0, 61, true), .want = 61 },
        // A 0x00 terminator must exist.
        .{ .name = "no 0x00 terminator anywhere", .em = buildEm(k, 0x00, 0x02, 0, 0, false), .want = 0 },
        // A zero-length message (terminator is the final octet) is not a CEK.
        .{ .name = "zero-length message", .em = buildEm(k, 0x00, 0x02, k - 3, 0, true), .want = 0 },
    };

    for (cases) |c| {
        const r = unpadEm(k, c.em, kp, &out, c.want);
        testing.expectError(error.DecryptionError, r) catch |e| {
            std.debug.print("v1.5 unpadding ACCEPTED a malformed EM: {s}\n", .{c.name});
            return e;
        };
    }
}

test "TEETH: PKCS#1 v1.5 unpadding rejects a message longer than the CEK buffer" {
    // The `msg_len > out.len` arm needs a modulus large enough that a valid
    // PS still leaves more than 64 message octets: k = 128, PS = 8 ⇒ 117.
    const k = 128;
    var kp = try v15TestKey(1024);
    defer kp.secret_key.deinit();
    var out: [64]u8 = undefined;

    // No content algorithm asks for a 117-byte key, so `want` is refused before
    // any secret-dependent work — a public bound on a public value.
    const long = buildEm(k, 0x00, 0x02, 8, 117, true);
    try testing.expectError(error.DecryptionError, unpadEm(k, long, kp, &out, 117));
    // And with a realistic `want`, the same over-long message is rejected by the
    // mask rather than by that bound.
    try testing.expectError(error.DecryptionError, unpadEm(k, long, kp, &out, 32));

    // Control on the same key: a 32-byte CEK with a full-length PS decodes.
    const ok = buildEm(k, 0x00, 0x02, 93, 32, true);
    const rec = try unpadEm(k, ok, kp, &out, 32);
    try testing.expectEqualSlices(u8, ok[k - 32 ..], rec);
}

// ── constant-time shape of the v1.5 unpadding (F3) ──────────────────────────
//
// WHAT THESE TESTS PROVE, AND WHAT THEY DO NOT.
//
// They prove the *structural* half of the constant-time claim: that the write
// into the caller's CEK buffer has a fixed length and happens on every path,
// accept and reject alike, rather than being a `@memcpy` of `msg_len` bytes
// read from the secret-derived offset `sep_idx + 1` and skipped entirely by an
// early `return error`. That is observable from Zig, and it is what the two
// tests below assert.
//
// They do NOT prove that the compiled code is branch-free, and they cannot:
// a unit test cannot measure timing, cannot see a conditional move, and cannot
// stop a future compiler from lowering the mask arithmetic into a branch. The
// tools that could — valgrind/ctgrind via `std.crypto.timing_safe.classify`,
// or a dudect-style statistical harness — are not wired into this repo, and a
// green test that measures none of that would be worse than saying so. The
// remaining assurance for the arithmetic itself is that the mask helpers are
// exhaustively tested below and are load-bearing: get a mask wrong and the
// RFC 8017 §7.2.2 teeth tests above go red.
//
// See `SPEC.md` §"Constant-time posture" for the same statement in prose.

test "TEETH (F3): the v1.5 message copy has a fixed length, not msg_len" {
    const k = 64;
    var kp = try v15TestKey(512);
    defer kp.secret_key.deinit();

    // A short (16-byte) CEK. A `@memcpy(out[0..msg_len], …)` touches 16 bytes
    // and leaves the other 48 as the caller left them; the constant-time copy
    // writes all 64.
    var out: [64]u8 = @splat(0xAA);
    const em = buildEm(k, 0x00, 0x02, 45, 16, true);
    const rec = try unpadEm(k, em, kp, &out, 16);
    try testing.expectEqualSlices(u8, em[k - 16 ..], rec);
    for (out[16..], 16..) |b, idx| {
        if (b != 0) {
            std.debug.print(
                "v1.5 copy is msg_len-sized: out[{d}] still holds the caller's 0x{X:0>2}\n",
                .{ idx, b },
            );
            return error.MessageCopyLengthLeaksMsgLen;
        }
    }
}

test "TEETH (F3): a rejected v1.5 block still WRITES the CEK buffer, and never with plaintext" {
    const k = 64;
    var kp = try v15TestKey(512);
    defer kp.secret_key.deinit();

    // PS = 7 is one octet below the RFC 8017 minimum: rejected, but every
    // other part of the block is well formed, so a `msg_len`-sized copy placed
    // before the validity branch would deposit 54 bytes of recovered plaintext
    // here and an early `return error` would deposit none. Both are visible.
    //
    // Since the anti-oracle work landed, a rejected block leaves a DECOY in the
    // first `want` bytes rather than zeros — that is the whole point, the caller
    // decrypts the content with it. So the property asserted here is the one
    // that actually matters and always did: whatever is in the buffer, it is not
    // the recovered message, and nothing past the decoy is left over.
    const want = 54;
    var out: [64]u8 = @splat(0xAA);
    const bad = buildEm(k, 0x00, 0x02, 7, want, true);
    try testing.expectError(error.DecryptionError, unpadEm(k, bad, kp, &out, want));

    const recovered = bad[k - want ..];
    if (std.mem.eql(u8, out[0..want], recovered)) {
        std.debug.print("rejected v1.5 block published the recovered plaintext\n", .{});
        return error.RejectedBlockLeakedPlaintext;
    }
    // The write happened at all — an early `return error` would have left the
    // caller's 0xAA fill in place.
    var untouched = true;
    for (out) |b| {
        if (b != 0xAA) {
            untouched = false;
            break;
        }
    }
    if (untouched) {
        std.debug.print("rejected v1.5 block skipped the CEK-buffer write entirely\n", .{});
        return error.RejectedBlockSkippedWrite;
    }
    // And nothing beyond the decoy: no tail of the recovered message survives.
    for (out[want..], want..) |b, idx| {
        if (b != 0) {
            std.debug.print("rejected v1.5 block left out[{d}] = 0x{X:0>2} past the decoy\n", .{ idx, b });
            return error.RejectedBlockLeftResidue;
        }
    }
}

test "TEETH (F3): a failed key unwrap still decrypts the content, so both outcomes cost the same" {
    // The oracle this closes is at CALLER scope, not inside the unpadding: a
    // non-conforming block used to return before `decryptData` touched the
    // content at all, so a whole AES pass over an attacker-sized ciphertext
    // happened on exactly one side of the decision. Measured at 97% classifier
    // accuracy (min-of-8 queries) over a 3 MiB CBC content ciphertext, with the
    // error VALUE fully collapsed the whole time.
    //
    // Asserted here as the mechanism rather than as a timing ratio, because a
    // wall-clock assertion is exactly the kind that reads the same with and
    // without the fix. `Unwrapped.ok` false with a `want`-length decoy IS the
    // fix; a decoy of the wrong length would put the caller back on the fast
    // path.
    const k = 64;
    var kp = try v15TestKey(512);
    defer kp.secret_key.deinit();
    var out: [64]u8 = @splat(0xAA);

    for ([_]usize{ 16, 32 }) |want| {
        // Block type 1 — the classic v1.5 confusion, and non-conforming.
        const bad = buildEm(k, 0x00, 0x01, 29, 32, true);
        const ct = try rsa.rsaep(k, bad, kp.public_key);
        const un = try rsaPkcs1v15Unwrap(kp.secret_key, &ct, &out, want);
        try testing.expect(!un.ok);
        // The decoy is exactly the content algorithm's key length, so the
        // caller's AES pass runs on it.
        try testing.expectEqual(want, un.cek.len);

        // A CONFORMING block whose message is the wrong length for the content
        // algorithm is the third arm of the same oracle, and it takes the same
        // route rather than being checked one frame up.
        const other: usize = if (want == 32) 16 else 32;
        const wrong_len = buildEm(k, 0x00, 0x02, k - 3 - other, other, true);
        const ct2 = try rsa.rsaep(k, wrong_len, kp.public_key);
        const un2 = try rsaPkcs1v15Unwrap(kp.secret_key, &ct2, &out, want);
        try testing.expect(!un2.ok);
        try testing.expectEqual(want, un2.cek.len);

        // Control: the right length, conforming, still succeeds.
        const good = buildEm(k, 0x00, 0x02, 29, 32, true);
        const ct3 = try rsa.rsaep(k, good, kp.public_key);
        const un3 = try rsaPkcs1v15Unwrap(kp.secret_key, &ct3, &out, 32);
        try testing.expect(un3.ok);
        try testing.expectEqualSlices(u8, good[k - 32 ..], un3.cek);
    }
}

test "TEETH (F3): the decoy is unpredictable and input-bound, not a constant" {
    // If the decoy were public — a constant, or a function of the ciphertext
    // alone — the peer could craft a content ciphertext that authenticates
    // under the decoy they computed themselves, and read the unwrap result back
    // out of the success/failure answer. It is derived from the raw RSA block,
    // which needs the private key.
    const k = 64;
    var kp = try v15TestKey(512);
    defer kp.secret_key.deinit();
    var out_a: [64]u8 = undefined;
    var out_b: [64]u8 = undefined;

    const bad_a = buildEm(k, 0x00, 0x01, 29, 32, true);
    var bad_b = bad_a;
    bad_b[40] ^= 0x01; // one bit of the rejected block

    const un_a = try rsaPkcs1v15Unwrap(kp.secret_key, &(try rsa.rsaep(k, bad_a, kp.public_key)), &out_a, 32);
    const un_b = try rsaPkcs1v15Unwrap(kp.secret_key, &(try rsa.rsaep(k, bad_b, kp.public_key)), &out_b, 32);
    try testing.expect(!un_a.ok and !un_b.ok);

    var zero: [32]u8 = @splat(0);
    try testing.expect(!std.mem.eql(u8, un_a.cek, &zero));
    // Two different rejected blocks must not decoy to the same key.
    try testing.expect(!std.mem.eql(u8, un_a.cek, un_b.cek));
}

test "constant-time mask helpers (exhaustive over u8, table over usize)" {
    const ones = ~@as(usize, 0);

    // ctEqByteMask: all 65536 byte pairs.
    var a: usize = 0;
    while (a < 256) : (a += 1) {
        var b: usize = 0;
        while (b < 256) : (b += 1) {
            const want: usize = if (a == b) ones else 0;
            try testing.expectEqual(want, ctEqByteMask(@intCast(a), @intCast(b)));
        }
    }

    const vals = [_]usize{ 0, 1, 2, 8, 9, 10, 11, 63, 64, 65, 255, 512, ones >> 1, ones - 1, ones };
    for (vals) |x| {
        for (vals) |y| {
            try testing.expectEqual(@as(usize, if (x == y) ones else 0), ctEqMaskUsize(x, y));
            try testing.expectEqual(@as(usize, if (x >= y) ones else 0), ctGeMaskUsize(x, y));
            try testing.expectEqual(x, ctSelectUsize(ones, x, y));
            try testing.expectEqual(y, ctSelectUsize(0, x, y));
        }
    }
}
