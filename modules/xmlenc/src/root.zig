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
    /// here so no padding/oracle signal leaks (Bleichenbacher / Manger /
    /// padding-oracle).
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
    const cek = try unwrapCek(alloc, enc_key, sk, options, &cek_buf);
    defer std.crypto.secureZero(u8, cek_buf[0..]);
    if (cek.len != content.key_len) return error.DecryptionError;

    // 4. Decrypt the content with the CEK.

    return switch (content.mode) {
        .gcm => try aesGcmDecrypt(alloc, cek, cipher),
        .cbc => try aesCbcDecrypt(alloc, cek, cipher),
    };
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
    defer alloc.free(plain);
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
fn unwrapCek(
    alloc: std.mem.Allocator,
    enc_key: *const xml.Element,
    sk: rsa.SecretKey,
    options: Options,
    out: *[64]u8,
) Error![]const u8 {
    const method = childEl(enc_key, xenc_ns, "EncryptionMethod") orelse return error.MalformedStructure;
    const alg = method.attr("", "Algorithm") orelse return error.MalformedStructure;

    const wrapped = try readCipherValue(alloc, enc_key, 1024); // an RSA block / KW blob is small
    defer alloc.free(wrapped);

    if (eq(alg, alg_rsa_oaep_mgf1p)) {
        return try rsaOaepUnwrap(sk, .{ .digest = .sha1, .mgf = .sha1 }, enc_key, wrapped, out);
    } else if (eq(alg, alg_rsa_oaep)) {
        const h = try oaepHashFromMethod(method);
        return try rsaOaepUnwrap(sk, h, enc_key, wrapped, out);
    } else if (eq(alg, alg_rsa_15)) {
        if (!options.allow_weak_rsa15) return error.WeakRsa15NotAllowed;
        return try rsaPkcs1v15Unwrap(sk, wrapped, out);
    } else if (eq(alg, alg_kw_aes128) or eq(alg, alg_kw_aes256)) {
        const kek = options.kek orelse return error.KekNotProvided;
        const want: usize = if (eq(alg, alg_kw_aes128)) 16 else 32;
        if (kek.len != want) return error.UnsupportedAlgorithm;
        return try aesKwUnwrap(kek, wrapped, out);
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
/// `allow_weak_rsa15`. The unpadding accumulates every check into one validity
/// flag and returns a single generic `error.DecryptionError`, so it does not
/// branch on padding validity (a Bleichenbacher oracle-hardening measure; note
/// std does not let us fully hide the RSADP range check, which is on the
/// public ciphertext anyway).
fn rsaPkcs1v15Unwrap(sk: rsa.SecretKey, wrapped: []const u8, out: *[64]u8) Error![]const u8 {
    var em_buf: [rsa.max_modulus_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &em_buf);
    const em = try rsaRawPrivate(sk, wrapped, &em_buf);
    // EM = 0x00 || 0x02 || PS || 0x00 || M, PS >= 8 nonzero octets (RFC 8017
    // §7.2.2). Scan branch-light; collapse to one flag.
    if (em.len < 11) return error.DecryptionError;
    var good: u8 = 1;
    good &= ctEq(em[0], 0x00);
    good &= ctEq(em[1], 0x02);
    // Locate the first 0x00 at index >= 2; PS is everything before it and must
    // be all-nonzero and >= 8 bytes.
    var seen_sep: u8 = 0;
    var sep_idx: usize = 0;
    var i: usize = 2;
    while (i < em.len) : (i += 1) {
        const is_zero = ctEq(em[i], 0x00);
        // record first separator position
        const first = (seen_sep ^ 1) & is_zero;
        sep_idx = ctSelectUsize(first, i, sep_idx);
        seen_sep |= is_zero;
    }
    good &= seen_sep; // a 0x00 terminator must exist
    // PS length = sep_idx - 2 must be >= 8.
    const ps_ok: u8 = if (sep_idx >= 10) 1 else 0;
    good &= ps_ok;
    const msg_len = if (sep_idx + 1 <= em.len) em.len - sep_idx - 1 else 0;
    if (msg_len == 0 or msg_len > out.len) good = 0;
    if (good != 1) return error.DecryptionError;
    @memcpy(out[0..msg_len], em[sep_idx + 1 ..]);
    return out[0..msg_len];
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

fn aesKwUnwrap(kek: []const u8, wrapped: []const u8, out: *[64]u8) Error![]const u8 {
    // RFC 3394 unwrap (delegated to the shared `aeskw` module): recovered
    // length = wrapped.len - 8. Any failure (bad length, unsupported KEK
    // length, integrity-check mismatch) collapses to the generic
    // `DecryptionError` — see the module doc comment on error posture.
    if (wrapped.len < 24) return error.DecryptionError; // bound the out-slice below
    const plain_len = wrapped.len - 8;
    if (plain_len > out.len) return error.DecryptionError;
    _ = aeskw.unwrap(kek, wrapped, out[0..plain_len]) catch return error.DecryptionError;
    return out[0..plain_len];
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
    errdefer alloc.free(buf);

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
    alloc.free(buf);
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
fn readCipherValue(alloc: std.mem.Allocator, parent: *const xml.Element, max_len: usize) Error![]u8 {
    const cipher_data = childEl(parent, xenc_ns, "CipherData") orelse return error.MalformedStructure;
    if (childEl(cipher_data, xenc_ns, "CipherReference") != null) return error.CipherReferenceUnsupported;
    const cipher_value = childEl(cipher_data, xenc_ns, "CipherValue") orelse return error.MalformedStructure;

    const raw = cipher_value.textContent(alloc) catch return error.OutOfMemory;
    defer alloc.free(raw);
    return decodeBase64Alloc(alloc, raw, max_len);
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

/// Strip ASCII whitespace and standard-base64-decode into a fresh allocation.
fn decodeBase64Alloc(alloc: std.mem.Allocator, text: []const u8, max_len: usize) Error![]u8 {
    var compact: std.ArrayList(u8) = .empty;
    defer compact.deinit(alloc);
    for (text) |c| {
        if (c == ' ' or c == '\t' or c == '\r' or c == '\n') continue;
        try compact.append(alloc, c);
    }
    const dec = std.base64.standard.Decoder;
    const n = dec.calcSizeForSlice(compact.items) catch return error.MalformedStructure;
    if (n > max_len) return error.CiphertextTooLarge;
    const out = try alloc.alloc(u8, n);
    errdefer alloc.free(out);
    dec.decode(out, compact.items) catch return error.MalformedStructure;
    return out;
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

fn ctEq(a: u8, b: u8) u8 {
    return @intFromBool(a == b);
}

fn ctSelectUsize(cond: u8, a: usize, b: usize) usize {
    return if (cond == 1) a else b;
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
    const rec = try aesKwUnwrap(&kek, &ciphertext, &out);
    try testing.expectEqualSlices(u8, &key_data, rec);
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

/// Hand `em` to the production unpadding by raw-encrypting it under `pk`.
fn unpadEm(comptime k: usize, em: [k]u8, kp: rsa.KeyPair, out: *[64]u8) Error![]const u8 {
    const ct = rsa.rsaep(k, em, kp.public_key) catch return error.DecryptionError;
    return rsaPkcs1v15Unwrap(kp.secret_key, &ct, out);
}

test "TEETH: PKCS#1 v1.5 unpadding accepts a valid EM and the PS=8 boundary" {
    const k = 64;
    var kp = try v15TestKey(512);
    defer kp.secret_key.deinit();
    var out: [64]u8 = undefined;

    // Ordinary CEK-sized message: EM = 00 02 PS(29) 00 M(32).
    const good = buildEm(k, 0x00, 0x02, 29, 32, true);
    const rec = try unpadEm(k, good, kp, &out);
    try testing.expectEqualSlices(u8, good[k - 32 ..], rec);

    // PS of exactly 8 octets is the RFC 8017 §7.2.2 minimum — must be ACCEPTED.
    // (This is the positive half of the boundary; the negative half is PS = 7
    // in the rejection table below. Without both, `sep_idx >= 10` can be moved
    // in either direction unnoticed.)
    const ps8 = buildEm(k, 0x00, 0x02, 8, 53, true);
    const rec8 = try unpadEm(k, ps8, kp, &out);
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
    };
    const cases = [_]Case{
        // EM[0] must be 0x00.
        .{ .name = "leading octet 0x01", .em = buildEm(k, 0x01, 0x02, 29, 32, true) },
        // EM[1] must be 0x02. 0x01 is block type 1 (the *signature* padding
        // type) — accepting it is the classic v1.5 confusion, and dropping this
        // single check is what previously survived the whole suite.
        .{ .name = "block type 1 (signature padding)", .em = buildEm(k, 0x00, 0x01, 29, 32, true) },
        .{ .name = "block type 0", .em = buildEm(k, 0x00, 0x00, 29, 32, true) },
        .{ .name = "block type 3", .em = buildEm(k, 0x00, 0x03, 29, 32, true) },
        // PS must be at least 8 octets. 7 is one below the bound; everything
        // else about this block is valid, so the PS minimum is the only check
        // that can reject it.
        .{ .name = "PS of 7 octets (one below the minimum)", .em = buildEm(k, 0x00, 0x02, 7, 54, true) },
        .{ .name = "PS of 1 octet", .em = buildEm(k, 0x00, 0x02, 1, 60, true) },
        .{ .name = "PS of 0 octets (0x00 immediately after the prefix)", .em = buildEm(k, 0x00, 0x02, 0, 61, true) },
        // A 0x00 terminator must exist.
        .{ .name = "no 0x00 terminator anywhere", .em = buildEm(k, 0x00, 0x02, 0, 0, false) },
        // A zero-length message (terminator is the final octet) is not a CEK.
        .{ .name = "zero-length message", .em = buildEm(k, 0x00, 0x02, k - 3, 0, true) },
    };

    for (cases) |c| {
        const r = unpadEm(k, c.em, kp, &out);
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

    const long = buildEm(k, 0x00, 0x02, 8, 117, true);
    try testing.expectError(error.DecryptionError, unpadEm(k, long, kp, &out));

    // Control on the same key: a 32-byte CEK with a full-length PS decodes.
    const ok = buildEm(k, 0x00, 0x02, 93, 32, true);
    const rec = try unpadEm(k, ok, kp, &out);
    try testing.expectEqualSlices(u8, ok[k - 32 ..], rec);
}
