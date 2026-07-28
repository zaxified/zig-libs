// SPDX-License-Identifier: MIT
//! xmldsig — XML Canonicalization (C14N) + XML-Signature **verification**
//! (W3C xmldsig-core 1.1) over the `xml` infoset tree.
//!
//! This is layer 2 of a SAML cluster: it sits on `xml` (layer 1, the hardened
//! parser) and is consumed by `saml` (layer 3, the SP). Its job is to answer,
//! for untrusted IdP input, exactly one question: **is this `ds:Signature`
//! cryptographically valid, and does it actually cover the element I care
//! about?**
//!
//! ## Scope
//! - VERIFICATION only. Signing / signature *generation* is deliberately out of
//!   scope — we are the relying party (service provider) checking an IdP's
//!   signature, never producing one. (The test suite uses the sibling `rsa` /
//!   `p256` signers to build round-trip fixtures, but no signing API is
//!   exported.)
//! - Canonicalization: see `c14n.zig` — Exclusive C14N 1.0 (+WithComments,
//!   +InclusiveNamespaces PrefixList) and Canonical XML 1.0 (+WithComments).
//!
//! ## Trust model (READ THIS)
//! Signatures are verified against a **caller-supplied key** (`Options.key`) —
//! the SP is configured out-of-band with the IdP's certificate / public key.
//! `<KeyInfo>` is **NEVER trusted to supply the verification key**: doing so
//! would let an attacker sign with their own key and attach their own cert. We
//! *do* parse `<KeyInfo><X509Data><X509Certificate>` and hand the caller the
//! raw DER (`Result.x509_cert_der`) so they can pin / compare it against their
//! configured cert — but that comparison, and the decision to trust, belong to
//! the caller.
//!
//! ## Algorithm allow-list (everything else is rejected)
//! - C14N / transforms: exclusive & inclusive C14N (both comment variants), the
//!   enveloped-signature transform. XPath / XSLT / XPath-filter / base64 and any
//!   other transform are **rejected** (`error.UnsupportedTransform`) — they are
//!   an attack surface, not implemented at all.
//! - Digest: SHA-256 (primary), SHA-384, SHA-512; SHA-1 only when
//!   `Options.allow_weak_sha1` is set (flagged weak).
//! - Signature: RSA-SHA256 (primary), RSA-SHA384, RSA-SHA512, ECDSA-P256-SHA256;
//!   RSA-SHA1 only when `Options.allow_weak_sha1`.
//!
//! Never panics on malformed signature XML: every failure is a typed error.

const std = @import("std");
const xml = @import("xml");
const rsa = @import("rsa");
const p256 = @import("p256");

pub const c14n = @import("c14n.zig");

pub const meta = .{
    .platform = .any,
    .role = .util, // pure verification logic over a parsed tree — no I/O, no wire framing
    .concurrency = .reentrant,
    .model_after = "W3C XML Signature Syntax and Processing (xmldsig-core 1.1) + Exclusive/Canonical XML 1.0",
    .deps = .{ "xml", "rsa", "p256" },
};

// ── namespace + algorithm identifiers ───────────────────────────────────────

/// The XML-Signature namespace.
pub const ds_ns = "http://www.w3.org/2000/09/xmldsig#";
/// The Exclusive C14N namespace (also the `ec:` transform-parameter namespace).
pub const exc_c14n_ns = "http://www.w3.org/2001/10/xml-exc-c14n#";

// Canonicalization / transform algorithm URIs.
const alg_exc_c14n = "http://www.w3.org/2001/10/xml-exc-c14n#";
const alg_exc_c14n_wc = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
const alg_c14n = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
const alg_c14n_wc = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
const alg_enveloped = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

// Digest algorithm URIs.
const dig_sha1 = "http://www.w3.org/2000/09/xmldsig#sha1";
const dig_sha256 = "http://www.w3.org/2001/04/xmlenc#sha256";
const dig_sha384 = "http://www.w3.org/2001/04/xmldsig-more#sha384";
const dig_sha512 = "http://www.w3.org/2001/04/xmlenc#sha512";

// Signature algorithm URIs.
const sig_rsa_sha1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
const sig_rsa_sha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const sig_rsa_sha384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
const sig_rsa_sha512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
const sig_ecdsa_sha256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";

// ── public types ────────────────────────────────────────────────────────────

/// The configured verification key. This — never `<KeyInfo>` — is what
/// signatures are checked against.
pub const VerifyKey = union(enum) {
    /// An RSA public key (from the IdP metadata / pinned cert).
    rsa: rsa.PublicKey,
    /// A P-256 public key as a SEC1-encoded point (33-byte compressed or
    /// 65-byte uncompressed).
    ecdsa_p256_sec1: []const u8,
};

pub const Options = struct {
    /// The configured trust anchor. Signatures are verified against THIS key.
    key: VerifyKey,
    /// Permit the legacy, cryptographically weak SHA-1 digest and RSA-SHA1
    /// signature algorithms. Off by default; enable only for legacy interop.
    allow_weak_sha1: bool = false,
    /// If set, `URI="#value"` references are resolved by matching this
    /// unqualified attribute's local name (via `Document.findByAttr`) instead of
    /// the parser's ID heuristic (`getElementById`). SAML profiles that use a
    /// non-standard ID attribute name pass it here.
    id_attr: ?[]const u8 = null,
};

/// Per-reference outcome.
pub const RefResult = struct {
    /// The reference's `URI` attribute, verbatim (borrowed from the document).
    uri: []const u8,
    /// Whether the recomputed digest matched `<DigestValue>`.
    digest_valid: bool,
};

/// The structured verification verdict. Owns `references` and (optionally)
/// `x509_cert_der`; free with `deinit`.
pub const Result = struct {
    /// Overall verdict: every reference digest matched AND the SignatureValue
    /// verified against the configured key.
    valid: bool,
    /// One entry per `<Reference>`, in document order.
    references: []RefResult,
    /// The `<SignatureMethod>` algorithm URI (borrowed from the document).
    signature_method_uri: []const u8,
    /// The `<CanonicalizationMethod>` (for `<SignedInfo>`) algorithm URI.
    canonicalization_method_uri: []const u8,
    /// Raw DER of the first `<KeyInfo><X509Data><X509Certificate>`, base64
    /// -decoded, or null if none was present. **Untrusted** — provided only so
    /// the caller can compare it against their pinned certificate. Owned.
    x509_cert_der: ?[]u8,

    pub fn deinit(self: *Result, alloc: std.mem.Allocator) void {
        alloc.free(self.references);
        if (self.x509_cert_der) |d| alloc.free(d);
        self.* = undefined;
    }
};

pub const VerifyError = error{
    /// The element is not a well-formed `ds:Signature` (missing SignedInfo,
    /// SignatureValue, Reference, DigestValue, required attributes, …).
    MalformedSignature,
    /// A named C14N / digest / signature / transform algorithm is not on the
    /// allow-list (or SHA-1 used without `allow_weak_sha1`).
    UnsupportedAlgorithm,
    /// A transform other than enveloped-signature / exclusive / inclusive C14N
    /// was requested (XPath, XSLT, base64, …). Rejected by policy.
    UnsupportedTransform,
    /// A `Reference URI` did not resolve to exactly one in-document element
    /// (missing, external, or — defensively — not found).
    UriNotResolved,
    /// A recomputed reference digest did not match `<DigestValue>`.
    DigestMismatch,
    /// The `<SignatureValue>` did not verify against the configured key.
    SignatureMismatch,
    /// The configured key's type does not match the `<SignatureMethod>` (e.g.
    /// an RSA method with an ECDSA key).
    KeyAlgorithmMismatch,
} || std.mem.Allocator.Error;

// ── internal algorithm enums ────────────────────────────────────────────────

const DigestAlg = enum { sha1, sha256, sha384, sha512 };
const SigAlg = enum { rsa_sha1, rsa_sha256, rsa_sha384, rsa_sha512, ecdsa_sha256 };

fn mapC14n(uri: []const u8) ?c14n.Mode {
    if (std.mem.eql(u8, uri, alg_exc_c14n)) return .exclusive;
    if (std.mem.eql(u8, uri, alg_exc_c14n_wc)) return .exclusive_with_comments;
    if (std.mem.eql(u8, uri, alg_c14n)) return .inclusive;
    if (std.mem.eql(u8, uri, alg_c14n_wc)) return .inclusive_with_comments;
    return null;
}

fn mapDigest(uri: []const u8) ?DigestAlg {
    if (std.mem.eql(u8, uri, dig_sha256)) return .sha256;
    if (std.mem.eql(u8, uri, dig_sha384)) return .sha384;
    if (std.mem.eql(u8, uri, dig_sha512)) return .sha512;
    if (std.mem.eql(u8, uri, dig_sha1)) return .sha1;
    return null;
}

fn mapSig(uri: []const u8) ?SigAlg {
    if (std.mem.eql(u8, uri, sig_rsa_sha256)) return .rsa_sha256;
    if (std.mem.eql(u8, uri, sig_rsa_sha384)) return .rsa_sha384;
    if (std.mem.eql(u8, uri, sig_rsa_sha512)) return .rsa_sha512;
    if (std.mem.eql(u8, uri, sig_ecdsa_sha256)) return .ecdsa_sha256;
    if (std.mem.eql(u8, uri, sig_rsa_sha1)) return .rsa_sha1;
    return null;
}

// ── entry point ─────────────────────────────────────────────────────────────

/// Verify the `ds:Signature` element `signature` within `doc`.
///
/// `signature` must be the `ds:Signature` element (namespace `ds_ns`). `saml`
/// locates it (e.g. the child of the assertion / response it wants to trust)
/// and passes it here together with the configured IdP key in `options.key`.
///
/// Returns a `Result` describing which references validated, the overall
/// verdict, and the certificate seen in `<KeyInfo>` (for pinning). A `false`
/// `Result.valid` is only returned for a *structurally* valid signature that
/// simply did not verify; structural / algorithm / resolution problems return a
/// typed `VerifyError`. Never panics on malformed input.
pub fn verify(
    alloc: std.mem.Allocator,
    doc: *const xml.Document,
    signature: *const xml.Element,
    options: Options,
) VerifyError!Result {
    var arena_state = std.heap.ArenaAllocator.init(alloc);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    if (!isDs(signature, "Signature")) return error.MalformedSignature;

    const signed_info = childByName(signature, "SignedInfo") orelse return error.MalformedSignature;
    const signature_value_el = childByName(signature, "SignatureValue") orelse return error.MalformedSignature;

    // CanonicalizationMethod (for SignedInfo) + SignatureMethod.
    const cm = childByName(signed_info, "CanonicalizationMethod") orelse return error.MalformedSignature;
    const cm_uri = cm.attr("", "Algorithm") orelse return error.MalformedSignature;
    const si_mode = mapC14n(cm_uri) orelse return error.UnsupportedAlgorithm;

    const sm = childByName(signed_info, "SignatureMethod") orelse return error.MalformedSignature;
    const sm_uri = sm.attr("", "Algorithm") orelse return error.MalformedSignature;
    const sig_alg = mapSig(sm_uri) orelse return error.UnsupportedAlgorithm;
    if (sig_alg == .rsa_sha1 and !options.allow_weak_sha1) return error.UnsupportedAlgorithm;

    // ── Reference validation ────────────────────────────────────────────────
    var refs: std.ArrayList(RefResult) = .empty;
    // Result-owned; allocate from the caller allocator so it survives the arena.
    errdefer refs.deinit(alloc);

    var all_refs_valid = true;
    var saw_reference = false;
    for (signed_info.children) |child| switch (child.content) {
        .element => |ref_el| {
            if (!isDs(ref_el, "Reference")) continue;
            saw_reference = true;
            const rr = try validateReference(arena, doc, signature, ref_el, options);
            if (!rr.digest_valid) all_refs_valid = false;
            try refs.append(alloc, rr);
        },
        else => {},
    };
    if (!saw_reference) return error.MalformedSignature;

    // ── Signature validation over canonicalized SignedInfo ───────────────────
    const si_c14n = c14n.canonicalize(arena, signed_info, .{ .mode = si_mode }) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
    };
    const sig_bytes = try decodeBase64(arena, try textOf(arena, signature_value_el));
    const sig_ok = try verifySignature(sig_alg, options.key, si_c14n, sig_bytes);

    // ── KeyInfo (untrusted, for pinning only) ────────────────────────────────
    var cert_der: ?[]u8 = null;
    errdefer if (cert_der) |d| alloc.free(d);
    if (childByName(signature, "KeyInfo")) |ki| {
        if (findX509Cert(ki)) |cert_el| {
            const der = try decodeBase64(alloc, try textOf(arena, cert_el));
            cert_der = der;
        }
    }

    return .{
        .valid = all_refs_valid and sig_ok,
        .references = try refs.toOwnedSlice(alloc),
        .signature_method_uri = sm_uri,
        .canonicalization_method_uri = cm_uri,
        .x509_cert_der = cert_der,
    };
}

fn validateReference(
    arena: std.mem.Allocator,
    doc: *const xml.Document,
    signature: *const xml.Element,
    ref_el: *const xml.Element,
    options: Options,
) VerifyError!RefResult {
    const uri = ref_el.attr("", "URI") orelse return error.MalformedSignature;

    // Resolve the reference to exactly one in-document element.
    const target = try resolveReference(doc, uri, options);

    // Walk the transform chain in order.
    var mode: c14n.Mode = .inclusive; // XML-DSig default when a node-set needs serializing
    var omit: ?*const xml.Element = null;
    var inclusive_prefixes: []const []const u8 = &.{};

    if (childByName(ref_el, "Transforms")) |transforms| {
        for (transforms.children) |tc| switch (tc.content) {
            .element => |t| {
                if (!isDs(t, "Transform")) continue;
                const talg = t.attr("", "Algorithm") orelse return error.MalformedSignature;
                if (std.mem.eql(u8, talg, alg_enveloped)) {
                    omit = signature;
                } else if (mapC14n(talg)) |m| {
                    mode = m;
                    inclusive_prefixes = try parseInclusiveNamespaces(arena, t);
                } else {
                    // XPath, XSLT, XPath-filter, base64, … — rejected by policy.
                    return error.UnsupportedTransform;
                }
            },
            else => {},
        };
    }
    // DigestMethod + DigestValue.
    const dm = childByName(ref_el, "DigestMethod") orelse return error.MalformedSignature;
    const dm_uri = dm.attr("", "Algorithm") orelse return error.MalformedSignature;
    const dig_alg = mapDigest(dm_uri) orelse return error.UnsupportedAlgorithm;
    if (dig_alg == .sha1 and !options.allow_weak_sha1) return error.UnsupportedAlgorithm;

    const dv_el = childByName(ref_el, "DigestValue") orelse return error.MalformedSignature;
    const expected_digest = try decodeBase64(arena, try textOf(arena, dv_el));

    // Canonicalize the (transformed) referenced subtree and digest it.
    const canon = c14n.canonicalize(arena, target, .{
        .mode = mode,
        .inclusive_prefixes = inclusive_prefixes,
        .omit = omit,
    }) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
    };
    const got_digest = try computeDigest(arena, dig_alg, canon);

    return .{
        .uri = uri,
        .digest_valid = constantTimeEql(expected_digest, got_digest),
    };
}

fn resolveReference(doc: *const xml.Document, uri: []const u8, options: Options) VerifyError!*xml.Element {
    if (uri.len == 0) return doc.root; // same-document, whole document
    if (uri[0] != '#') return error.UriNotResolved; // external references unsupported
    const id = uri[1..];
    if (id.len == 0) return error.UriNotResolved;
    if (options.id_attr) |name| {
        return doc.findByAttr("", name, id) orelse error.UriNotResolved;
    }
    // The parser guarantees ID uniqueness (DuplicateId is a parse error), so a
    // hit here is unambiguous — the DSig-layer half of the wrapping defense.
    return doc.getElementById(id) orelse error.UriNotResolved;
}

/// Parse an `<ec:InclusiveNamespaces PrefixList="...">` child of an exc-c14n
/// transform, returning the space-separated tokens (borrowing the value bytes).
fn parseInclusiveNamespaces(arena: std.mem.Allocator, transform: *const xml.Element) VerifyError![]const []const u8 {
    for (transform.children) |c| switch (c.content) {
        .element => |el| {
            if (!std.mem.eql(u8, el.uri, exc_c14n_ns)) continue;
            if (!std.mem.eql(u8, el.local, "InclusiveNamespaces")) continue;
            const list = el.attr("", "PrefixList") orelse return &.{};
            var toks: std.ArrayList([]const u8) = .empty;
            var it = std.mem.tokenizeScalar(u8, list, ' ');
            while (it.next()) |tok| try toks.append(arena, tok);
            return try toks.toOwnedSlice(arena);
        },
        else => {},
    };
    return &.{};
}

// ── crypto dispatch ─────────────────────────────────────────────────────────

fn computeDigest(arena: std.mem.Allocator, alg: DigestAlg, msg: []const u8) VerifyError![]u8 {
    return switch (alg) {
        .sha1 => try hashInto(arena, std.crypto.hash.Sha1, msg),
        .sha256 => try hashInto(arena, std.crypto.hash.sha2.Sha256, msg),
        .sha384 => try hashInto(arena, std.crypto.hash.sha2.Sha384, msg),
        .sha512 => try hashInto(arena, std.crypto.hash.sha2.Sha512, msg),
    };
}

fn hashInto(arena: std.mem.Allocator, comptime Hash: type, msg: []const u8) ![]u8 {
    var out = try arena.alloc(u8, Hash.digest_length);
    Hash.hash(msg, out[0..Hash.digest_length], .{});
    return out;
}

fn verifySignature(alg: SigAlg, key: VerifyKey, signed_info_canon: []const u8, sig: []const u8) VerifyError!bool {
    switch (alg) {
        .rsa_sha1, .rsa_sha256, .rsa_sha384, .rsa_sha512 => {
            const pk = switch (key) {
                .rsa => |p| p,
                else => return error.KeyAlgorithmMismatch,
            };
            const res = switch (alg) {
                .rsa_sha1 => rsa.verifyPkcs1v15(pk, std.crypto.hash.Sha1, signed_info_canon, sig),
                .rsa_sha256 => rsa.verifyPkcs1v15(pk, std.crypto.hash.sha2.Sha256, signed_info_canon, sig),
                .rsa_sha384 => rsa.verifyPkcs1v15(pk, std.crypto.hash.sha2.Sha384, signed_info_canon, sig),
                .rsa_sha512 => rsa.verifyPkcs1v15(pk, std.crypto.hash.sha2.Sha512, signed_info_canon, sig),
                else => unreachable,
            };
            res catch return false;
            return true;
        },
        .ecdsa_sha256 => {
            const sec1 = switch (key) {
                .ecdsa_p256_sec1 => |s| s,
                else => return error.KeyAlgorithmMismatch,
            };
            // XML-DSig ECDSA signatures are raw r‖s (IEEE P1363), NOT DER.
            if (sig.len != 64) return error.MalformedSignature;
            var rs: [64]u8 = undefined;
            @memcpy(&rs, sig[0..64]);
            return p256.sign.ecdsaVerify(sec1, signed_info_canon, rs);
        },
    }
}

// ── small helpers ────────────────────────────────────────────────────────────

/// Length-then-constant-time byte compare (digests are public, but this keeps
/// the comparison branch-free once lengths match).
fn constantTimeEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| diff |= x ^ y;
    return diff == 0;
}

fn isDs(el: *const xml.Element, local: []const u8) bool {
    return std.mem.eql(u8, el.uri, ds_ns) and std.mem.eql(u8, el.local, local);
}

/// First child element in the ds namespace with the given local name.
fn childByName(parent: *const xml.Element, local: []const u8) ?*xml.Element {
    for (parent.children) |c| switch (c.content) {
        .element => |el| if (isDs(el, local)) return el,
        else => {},
    };
    return null;
}

/// Concatenated text content of an element (for base64 leaf values).
fn textOf(arena: std.mem.Allocator, el: *const xml.Element) ![]u8 {
    return el.textContent(arena);
}

/// Depth-first: the first `X509Certificate` element anywhere under a KeyInfo.
fn findX509Cert(el: *const xml.Element) ?*xml.Element {
    for (el.children) |c| switch (c.content) {
        .element => |child| {
            if (isDs(child, "X509Certificate")) return child;
            if (findX509Cert(child)) |f| return f;
        },
        else => {},
    };
    return null;
}

/// Decode standard base64, tolerating embedded ASCII whitespace/newlines (which
/// XML routinely wraps long base64 fields with).
fn decodeBase64(arena: std.mem.Allocator, text: []const u8) VerifyError![]u8 {
    var clean: std.ArrayList(u8) = .empty;
    defer clean.deinit(arena);
    for (text) |c| {
        if (!std.ascii.isWhitespace(c)) try clean.append(arena, c);
    }
    const dec = std.base64.standard.Decoder;
    const n = dec.calcSizeForSlice(clean.items) catch return error.MalformedSignature;
    const buf = try arena.alloc(u8, n);
    dec.decode(buf, clean.items) catch return error.MalformedSignature;
    return buf;
}

// ── tests ────────────────────────────────────────────────────────────────────
// Pull in the canonicalization test suite (byte-exact W3C vectors).
test {
    _ = c14n;
}

const testing = std.testing;

// A fixed RSA test keypair (PKCS#8 / SPKI PEM). TEST MATERIAL ONLY — generated
// with `openssl genrsa 2048`; never used outside this test suite.
const test_rsa_priv_pem =
    \\-----BEGIN PRIVATE KEY-----
    \\MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDpraSRCJ3brZRP
    \\ZOjK9UqPjr/SZlV3/lfuqEazKuknYGNsZadxoXj4eZ1QBL2iznYjDRZMEj3D+FhA
    \\6abpTy3kReBuEx+2/Dn5av2PE8nbkqd1wrOa/3pUrJ68YbnsVUjf02cLbsZg4HAs
    \\gMwQDsmJueVusc9QG/WQ8Mbf3i8lFDS+HV8v2eaHjCbaRAAbZyG6dOoiZD46QsXI
    \\01PtDtiQ7xbf2PGXRoRNeNyTwPKD7OhkBzBXReAyUtbsY4CcG8ce0KShUx2usPXW
    \\BxFjbJbX99/KYkstSxzrO8plF1gt6bhp9BovzkWZibKOQ1q6EdM10XxNsspNI+Tn
    \\kNu3cxPNAgMBAAECggEAALPR69Gvz8o8yORPwtRr7fSK5RIDrcGo+AGvfLhjTQgA
    \\JIJFt5S5rV2IOIZbH5MpTb+rUn03jFBBy6goJUlkpOwE2a/bB4zIi9RjgLuZfrx5
    \\HmSAb7XW40xFieFtUqWK+4lCJQmnNQFXtPqKIn444t4ZL3T/X4lF+rKOlnuvfpgI
    \\e+OemQazaFK8NyxkzgxrPvb6Ei7u89+gjZDSs05Sj5FkBciqkefyTRKZy2ucKLaK
    \\yL1ra2v6h/6MzxqXb7QsrpXNL0ZPV+DiBe8nPTDFDNvEZSPQnYv/LwiDcKOcbdrw
    \\XVljYUPy2tlQLxKCAyeS2htHnm97XsmN8HVc5VSmoQKBgQD9W6caoN3RfCkxboxk
    \\cHw9ubLmA9Tr9tGwNsrxomIDguPSv0/Mo1nFkhYqW8NYVSC5bXtBQw5TIilkWPge
    \\w8vxQuCApkphX9iuX/IoqyM8Nxa+XzHWkRKkzrZRt16OwvYlWtCyeLjyQ8REjdyZ
    \\q0xpxCfpdQqGbLeUM2Wi5ttPyQKBgQDsHXRV6Y+pJ8o30Ekt73/zGSihJlndj1u8
    \\9E418Pr5lUET0avFWJ009f2CHCzuOuGg867QGOW+ep1bon4sLpWBtFMzeb3cjO0y
    \\6DUr2MMxhyB556rs/i+5DAWBk6pnWZRs/92VpcNNGcavxlMm21RY91bDTC5dhEHJ
    \\ijFCTzuN5QKBgQClQyysPPSUGfZQzTh8p7cTGFdunF8+EADVfdhBZ9ehTLbJGIu4
    \\A3GiY1lcBgFVVCoFajm050WnyqfPUg1/G96jICmLIW1xOPEBRYqTJpbUR2bphPTg
    \\bj8IC+J3STI/00J2OVfaos6ZEMUsppCYGFm+v/n82aCk8LOK0z/f09CIqQKBgQCd
    \\xdDG15q3XW8yfGtp1m+Y8WbEx+uksPaL/HOGd9A8lg82PxSYee4SRY1wM4OSbKX3
    \\9t0JEJnz/drIMHw+6aHdWbF+5AqKJWEacy+UbPOBVNnOm48LbY5WCEJlo1ZqWOFl
    \\NFPMe0dVbbPmII/Plx91k1DWj0EsHAQZt83SkT8qQQKBgBuU+xylwVOIVWKEP8jx
    \\9BjBe8NkmL2fuO6cdDYKwOALgsYEVfN65BNIGg+Kiibl1mkrl54PXPsA8TPZbHtA
    \\8PHrKACN3MvwaTcYZ3PnlocUNVnnkDlnhK0xleYAn681G7W+WYnRoXobDprtTOy6
    \\ImWPn10DdQwbmUHhjTumzyIT
    \\-----END PRIVATE KEY-----
;
const test_rsa_pub_pem =
    \\-----BEGIN PUBLIC KEY-----
    \\MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6a2kkQid262UT2ToyvVK
    \\j46/0mZVd/5X7qhGsyrpJ2BjbGWncaF4+HmdUAS9os52Iw0WTBI9w/hYQOmm6U8t
    \\5EXgbhMftvw5+Wr9jxPJ25KndcKzmv96VKyevGG57FVI39NnC27GYOBwLIDMEA7J
    \\ibnlbrHPUBv1kPDG394vJRQ0vh1fL9nmh4wm2kQAG2chunTqImQ+OkLFyNNT7Q7Y
    \\kO8W39jxl0aETXjck8Dyg+zoZAcwV0XgMlLW7GOAnBvHHtCkoVMdrrD11gcRY2yW
    \\1/ffymJLLUsc6zvKZRdYLem4afQaL85FmYmyjkNauhHTNdF8TbLKTSPk55Dbt3MT
    \\zQIDAQAB
    \\-----END PUBLIC KEY-----
;

// Build a signed document by (test-only) signing SignedInfo with the sibling
// `rsa` signer, so we can drive the whole verify() path end to end. This is a
// CONSTRUCTED round-trip fixture (the byte-exact interop guarantee lives in the
// C14N vector tests); it proves reference-digest + SignedInfo-signature +
// enveloped-transform verification agree with a real signer.
const SignedDoc = struct {
    xml: []u8,
    fn deinit(self: *SignedDoc, a: std.mem.Allocator) void {
        a.free(self.xml);
    }
};

fn buildSignedRsaDoc(a: std.mem.Allocator, tamper_content: bool, tamper_sig: bool) !SignedDoc {
    var sk = try rsa.SecretKey.fromPem(test_rsa_priv_pem);
    defer sk.deinit();

    // The signer always signs the ORIGINAL content; tampering happens only in
    // the finally-emitted document, so the recomputed digest must mismatch.
    const content = "Hello World";

    // 1. Assemble the payload with an empty DigestValue/SignatureValue, parse it
    //    so we can canonicalize precisely the way verify() will.
    // The Reference covers the whole document (URI="") with an enveloped
    // transform + exclusive C14N.
    const digest_placeholder = "";
    const doc_template =
        "<Envelope ID=\"obj-1\" xmlns=\"urn:demo\">" ++
        "<Data>{s}</Data>" ++
        "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">" ++
        "<ds:SignedInfo>" ++
        "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" ++
        "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>" ++
        "<ds:Reference URI=\"\">" ++
        "<ds:Transforms>" ++
        "<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>" ++
        "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" ++
        "</ds:Transforms>" ++
        "<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>" ++
        "<ds:DigestValue>{s}</ds:DigestValue>" ++
        "</ds:Reference>" ++
        "</ds:SignedInfo>" ++
        "<ds:SignatureValue>{s}</ds:SignatureValue>" ++
        "</ds:Signature>" ++
        "</Envelope>";

    // Pass 1: compute the reference digest (canonicalize whole doc minus the
    // Signature, exclusive C14N).
    const with_empty = try std.fmt.allocPrint(a, doc_template, .{ content, digest_placeholder, "" });
    defer a.free(with_empty);
    var doc1 = try xml.parse(a, with_empty, .{});
    defer doc1.deinit();
    const sig1 = childByName(doc1.root, "Signature").?;
    const ref_canon = try c14n.canonicalize(a, doc1.root, .{ .mode = .exclusive, .omit = sig1 });
    defer a.free(ref_canon);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(ref_canon, &digest, .{});
    var digest_b64_buf: [64]u8 = undefined;
    const digest_b64 = std.base64.standard.Encoder.encode(&digest_b64_buf, &digest);

    // Pass 2: with the real digest in place, canonicalize SignedInfo and sign.
    const with_digest = try std.fmt.allocPrint(a, doc_template, .{ content, digest_b64, "" });
    defer a.free(with_digest);
    var doc2 = try xml.parse(a, with_digest, .{});
    defer doc2.deinit();
    const sig2 = childByName(doc2.root, "Signature").?;
    const si2 = childByName(sig2, "SignedInfo").?;
    const si_canon = try c14n.canonicalize(a, si2, .{ .mode = .exclusive });
    defer a.free(si_canon);

    var sig_buf: [256]u8 = undefined;
    const sig_slice = try rsa.signPkcs1v15(sk, std.crypto.hash.sha2.Sha256, si_canon, &sig_buf);
    if (tamper_sig) sig_slice[0] ^= 0x01;
    var sig_b64_buf: [512]u8 = undefined;
    const sig_b64 = std.base64.standard.Encoder.encode(&sig_b64_buf, sig_slice);

    const emit_content = if (tamper_content) "Hello EVIL" else content;
    const final = try std.fmt.allocPrint(a, doc_template, .{ emit_content, digest_b64, sig_b64 });
    return .{ .xml = final };
}

test "verify: valid RSA-SHA256 enveloped signature round-trips" {
    var sd = try buildSignedRsaDoc(testing.allocator, false, false);
    defer sd.deinit(testing.allocator);

    var doc = try xml.parse(testing.allocator, sd.xml, .{});
    defer doc.deinit();
    const sig = childByName(doc.root, "Signature").?;

    const pk = try rsa.PublicKey.fromPem(test_rsa_pub_pem);
    var res = try verify(testing.allocator, &doc, sig, .{ .key = .{ .rsa = pk } });
    defer res.deinit(testing.allocator);

    try testing.expect(res.valid);
    try testing.expectEqual(@as(usize, 1), res.references.len);
    try testing.expect(res.references[0].digest_valid);
}

test "verify: tampered signed content fails the reference digest" {
    var sd = try buildSignedRsaDoc(testing.allocator, true, false);
    defer sd.deinit(testing.allocator);
    var doc = try xml.parse(testing.allocator, sd.xml, .{});
    defer doc.deinit();
    const sig = childByName(doc.root, "Signature").?;
    const pk = try rsa.PublicKey.fromPem(test_rsa_pub_pem);
    var res = try verify(testing.allocator, &doc, sig, .{ .key = .{ .rsa = pk } });
    defer res.deinit(testing.allocator);
    // Digest was computed over the ORIGINAL content; tampered content ⇒ mismatch.
    try testing.expect(!res.valid);
    try testing.expect(!res.references[0].digest_valid);
}

test "verify: flipped SignatureValue fails signature check" {
    var sd = try buildSignedRsaDoc(testing.allocator, false, true);
    defer sd.deinit(testing.allocator);
    var doc = try xml.parse(testing.allocator, sd.xml, .{});
    defer doc.deinit();
    const sig = childByName(doc.root, "Signature").?;
    const pk = try rsa.PublicKey.fromPem(test_rsa_pub_pem);
    var res = try verify(testing.allocator, &doc, sig, .{ .key = .{ .rsa = pk } });
    defer res.deinit(testing.allocator);
    // Reference digest is fine, but SignedInfo signature does not verify.
    try testing.expect(!res.valid);
    try testing.expect(res.references[0].digest_valid);
}

test "verify: wrong key fails" {
    var sd = try buildSignedRsaDoc(testing.allocator, false, false);
    defer sd.deinit(testing.allocator);
    var doc = try xml.parse(testing.allocator, sd.xml, .{});
    defer doc.deinit();
    const sig = childByName(doc.root, "Signature").?;
    // A different modulus (same exponent) — valid RSA key, wrong signer.
    const wrong = try rsa.PublicKey.fromBytes(&([_]u8{0xC5} ** 256), &[_]u8{ 0x01, 0x00, 0x01 });
    var res = try verify(testing.allocator, &doc, sig, .{ .key = .{ .rsa = wrong } });
    defer res.deinit(testing.allocator);
    try testing.expect(!res.valid);
}

test "verify: ECDSA-P256-SHA256 enveloped signature round-trips" {
    const a = testing.allocator;
    const sk = [_]u8{0x11} ** 32;
    const pub_sec1 = (try p256.P256.combMulBase(sk, .big)).toUncompressedSec1();

    const doc_template =
        "<Envelope ID=\"obj-1\" xmlns=\"urn:demo\">" ++
        "<Data>ec-content</Data>" ++
        "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">" ++
        "<ds:SignedInfo>" ++
        "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" ++
        "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256\"/>" ++
        "<ds:Reference URI=\"\">" ++
        "<ds:Transforms>" ++
        "<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>" ++
        "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" ++
        "</ds:Transforms>" ++
        "<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>" ++
        "<ds:DigestValue>{s}</ds:DigestValue>" ++
        "</ds:Reference>" ++
        "</ds:SignedInfo>" ++
        "<ds:SignatureValue>{s}</ds:SignatureValue>" ++
        "</ds:Signature>" ++
        "</Envelope>";

    const with_empty = try std.fmt.allocPrint(a, doc_template, .{ "", "" });
    defer a.free(with_empty);
    var doc1 = try xml.parse(a, with_empty, .{});
    defer doc1.deinit();
    const s1 = childByName(doc1.root, "Signature").?;
    const ref_canon = try c14n.canonicalize(a, doc1.root, .{ .mode = .exclusive, .omit = s1 });
    defer a.free(ref_canon);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(ref_canon, &digest, .{});
    var db64: [64]u8 = undefined;
    const digest_b64 = std.base64.standard.Encoder.encode(&db64, &digest);

    const with_digest = try std.fmt.allocPrint(a, doc_template, .{ digest_b64, "" });
    defer a.free(with_digest);
    var doc2 = try xml.parse(a, with_digest, .{});
    defer doc2.deinit();
    const si2 = childByName(childByName(doc2.root, "Signature").?, "SignedInfo").?;
    const si_canon = try c14n.canonicalize(a, si2, .{ .mode = .exclusive });
    defer a.free(si_canon);

    const nonce = [_]u8{0x42} ** 32;
    const rs = try p256.sign.ecdsaSign(sk, si_canon, nonce);
    var sb64: [128]u8 = undefined;
    const sig_b64 = std.base64.standard.Encoder.encode(&sb64, &rs);

    const final = try std.fmt.allocPrint(a, doc_template, .{ digest_b64, sig_b64 });
    defer a.free(final);
    var doc = try xml.parse(a, final, .{});
    defer doc.deinit();
    const sig = childByName(doc.root, "Signature").?;

    var res = try verify(a, &doc, sig, .{ .key = .{ .ecdsa_p256_sec1 = &pub_sec1 } });
    defer res.deinit(a);
    try testing.expect(res.valid);

    // Teeth for the ECDSA branch specifically. The round-trip above passes
    // unchanged against a `verifySignature` whose `.ecdsa_sha256` arm just
    // returns true — the negative signature tests elsewhere in this file all go
    // through the RSA arm, so nothing else can catch that (verified by
    // mutation). Both checks below leave the document, its transforms and its
    // reference digest intact, so only the ECDSA verify can flip the verdict.

    // (a) Right document, a different (valid) P-256 key.
    const other_pub = (try p256.P256.combMulBase([_]u8{0x22} ** 32, .big)).toUncompressedSec1();
    var wrong_key_res = try verify(a, &doc, sig, .{ .key = .{ .ecdsa_p256_sec1 = &other_pub } });
    defer wrong_key_res.deinit(a);
    try testing.expect(!wrong_key_res.valid);
    try testing.expect(wrong_key_res.references[0].digest_valid); // the digest still matches

    // (b) Right key, one flipped bit in the raw r‖s SignatureValue.
    var bad_rs = rs;
    bad_rs[0] ^= 0x01;
    var bad_b64: [128]u8 = undefined;
    const bad_sig_b64 = std.base64.standard.Encoder.encode(&bad_b64, &bad_rs);
    const flipped = try std.fmt.allocPrint(a, doc_template, .{ digest_b64, bad_sig_b64 });
    defer a.free(flipped);
    var doc_f = try xml.parse(a, flipped, .{});
    defer doc_f.deinit();
    const sig_f = childByName(doc_f.root, "Signature").?;
    var flipped_res = try verify(a, &doc_f, sig_f, .{ .key = .{ .ecdsa_p256_sec1 = &pub_sec1 } });
    defer flipped_res.deinit(a);
    try testing.expect(!flipped_res.valid);
    try testing.expect(flipped_res.references[0].digest_valid);
}

test "verify: unsupported transform (XPath) is rejected" {
    const a = testing.allocator;
    const src =
        "<Envelope xmlns=\"urn:demo\">" ++
        "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">" ++
        "<ds:SignedInfo>" ++
        "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" ++
        "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>" ++
        "<ds:Reference URI=\"\">" ++
        "<ds:Transforms>" ++
        "<ds:Transform Algorithm=\"http://www.w3.org/TR/1999/REC-xpath-19991116\"/>" ++
        "</ds:Transforms>" ++
        "<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>" ++
        "<ds:DigestValue>AAAA</ds:DigestValue>" ++
        "</ds:Reference>" ++
        "</ds:SignedInfo>" ++
        "<ds:SignatureValue>AAAA</ds:SignatureValue>" ++
        "</ds:Signature>" ++
        "</Envelope>";
    var doc = try xml.parse(a, src, .{});
    defer doc.deinit();
    const sig = childByName(doc.root, "Signature").?;
    const pk = try rsa.PublicKey.fromPem(test_rsa_pub_pem);
    try testing.expectError(error.UnsupportedTransform, verify(a, &doc, sig, .{ .key = .{ .rsa = pk } }));
}

test "verify: SHA-1 digest rejected unless explicitly allowed" {
    const a = testing.allocator;
    const src =
        "<Envelope xmlns=\"urn:demo\">" ++
        "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">" ++
        "<ds:SignedInfo>" ++
        "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" ++
        "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>" ++
        "<ds:Reference URI=\"\">" ++
        "<ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>" ++
        "<ds:DigestValue>AAAA</ds:DigestValue>" ++
        "</ds:Reference>" ++
        "</ds:SignedInfo>" ++
        "<ds:SignatureValue>AAAA</ds:SignatureValue>" ++
        "</ds:Signature>" ++
        "</Envelope>";
    var doc = try xml.parse(a, src, .{});
    defer doc.deinit();
    const sig = childByName(doc.root, "Signature").?;
    const pk = try rsa.PublicKey.fromPem(test_rsa_pub_pem);
    try testing.expectError(error.UnsupportedAlgorithm, verify(a, &doc, sig, .{ .key = .{ .rsa = pk } }));
}

test "verify: unresolved reference URI fails" {
    const a = testing.allocator;
    const src =
        "<Envelope xmlns=\"urn:demo\">" ++
        "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">" ++
        "<ds:SignedInfo>" ++
        "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" ++
        "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>" ++
        "<ds:Reference URI=\"#does-not-exist\">" ++
        "<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>" ++
        "<ds:DigestValue>AAAA</ds:DigestValue>" ++
        "</ds:Reference>" ++
        "</ds:SignedInfo>" ++
        "<ds:SignatureValue>AAAA</ds:SignatureValue>" ++
        "</ds:Signature>" ++
        "</Envelope>";
    var doc = try xml.parse(a, src, .{});
    defer doc.deinit();
    const sig = childByName(doc.root, "Signature").?;
    const pk = try rsa.PublicKey.fromPem(test_rsa_pub_pem);
    try testing.expectError(error.UriNotResolved, verify(a, &doc, sig, .{ .key = .{ .rsa = pk } }));
}

test "verify: KeyInfo X509Certificate is exposed but not trusted" {
    // The cert DER is surfaced for pinning; verification still uses the
    // configured key. Here we supply the RIGHT key AND a KeyInfo cert blob.
    const a = testing.allocator;
    var sk = try rsa.SecretKey.fromPem(test_rsa_priv_pem);
    defer sk.deinit();

    const doc_template =
        "<Envelope xmlns=\"urn:demo\">" ++
        "<Data>content</Data>" ++
        "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">" ++
        "<ds:SignedInfo>" ++
        "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" ++
        "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>" ++
        "<ds:Reference URI=\"\">" ++
        "<ds:Transforms>" ++
        "<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>" ++
        "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" ++
        "</ds:Transforms>" ++
        "<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>" ++
        "<ds:DigestValue>{s}</ds:DigestValue>" ++
        "</ds:Reference>" ++
        "</ds:SignedInfo>" ++
        "<ds:SignatureValue>{s}</ds:SignatureValue>" ++
        "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>SGVsbG8=</ds:X509Certificate></ds:X509Data></ds:KeyInfo>" ++
        "</ds:Signature>" ++
        "</Envelope>";

    const with_empty = try std.fmt.allocPrint(a, doc_template, .{ "", "" });
    defer a.free(with_empty);
    var doc1 = try xml.parse(a, with_empty, .{});
    defer doc1.deinit();
    const s1 = childByName(doc1.root, "Signature").?;
    const ref_canon = try c14n.canonicalize(a, doc1.root, .{ .mode = .exclusive, .omit = s1 });
    defer a.free(ref_canon);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(ref_canon, &digest, .{});
    var db64: [64]u8 = undefined;
    const digest_b64 = std.base64.standard.Encoder.encode(&db64, &digest);

    const with_digest = try std.fmt.allocPrint(a, doc_template, .{ digest_b64, "" });
    defer a.free(with_digest);
    var doc2 = try xml.parse(a, with_digest, .{});
    defer doc2.deinit();
    const si2 = childByName(childByName(doc2.root, "Signature").?, "SignedInfo").?;
    const si_canon = try c14n.canonicalize(a, si2, .{ .mode = .exclusive });
    defer a.free(si_canon);
    var sig_buf: [256]u8 = undefined;
    const sig_slice = try rsa.signPkcs1v15(sk, std.crypto.hash.sha2.Sha256, si_canon, &sig_buf);
    var sb64: [512]u8 = undefined;
    const sig_b64 = std.base64.standard.Encoder.encode(&sb64, sig_slice);

    const final = try std.fmt.allocPrint(a, doc_template, .{ digest_b64, sig_b64 });
    defer a.free(final);
    var doc = try xml.parse(a, final, .{});
    defer doc.deinit();
    const sig = childByName(doc.root, "Signature").?;
    const pk = try rsa.PublicKey.fromPem(test_rsa_pub_pem);

    var res = try verify(a, &doc, sig, .{ .key = .{ .rsa = pk } });
    defer res.deinit(a);
    try testing.expect(res.valid);
    // "SGVsbG8=" is base64("Hello") — exposed verbatim for the caller to pin.
    try testing.expect(res.x509_cert_der != null);
    try testing.expectEqualStrings("Hello", res.x509_cert_der.?);
}

test "verify: not a Signature element is a typed error, never a panic" {
    const a = testing.allocator;
    var doc = try xml.parse(a, "<root><child/></root>", .{});
    defer doc.deinit();
    const pk = try rsa.PublicKey.fromPem(test_rsa_pub_pem);
    try testing.expectError(error.MalformedSignature, verify(a, &doc, doc.root, .{ .key = .{ .rsa = pk } }));
}
