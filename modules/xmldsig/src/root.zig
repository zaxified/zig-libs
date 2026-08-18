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
    .targets = .{.linux64},
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
    /// unqualified attribute's local name instead of the parser's ID heuristic
    /// (`getElementById`). SAML profiles that use a non-standard ID attribute
    /// name pass it here.
    ///
    /// Uniqueness on this branch is enforced by `resolveReference` itself, NOT
    /// by the parser: `Document.findByAttr` is first-match-in-document-order,
    /// and the name given here need not be one of the `xml.Options.id_attr_names`
    /// the document was parsed with, so `error.DuplicateId` may never have looked
    /// at it. A document carrying this attribute with the same value on two
    /// elements is rejected (`error.UriNotResolved`) rather than silently
    /// resolved to the first — see that error's documentation.
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
    /// W2-A8/xmldsig-F4: the enveloped-signature transform appeared after a
    /// C14N transform in `<Transforms>` — semantically backwards (canonicalize
    /// first, then try to strip an element from already-serialized octets) and
    /// not what any real signer emits. Not independently exploitable (the
    /// digest is still bound to whatever `omit`/`mode` the chain nets out to,
    /// and a mismatch is still caught), but accepting it silently as if it
    /// were the correct order is unnecessary laxness on an untrusted chain.
    TransformOrderInvalid,
    /// A `Reference URI` did not resolve to exactly one in-document element:
    /// missing, external, not found — or **ambiguous**, i.e. two or more
    /// elements carry `Options.id_attr` with that value. Ambiguity is a refusal
    /// and not a first-match, because the caller resolves the same id
    /// independently when deciding what the signature covers, and a resolution
    /// the two sides can disagree about is signature wrapping.
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

// ── secret-scrubbing allocator (CONVENTIONS §2.1 Z1) ────────────────────────

/// An allocator wrapper that `secureZero`s every block before handing it back to
/// `child`. `verify()` backs its scratch arena with this, because the arena's
/// blocks hold the canonical form of the very octets under verification — which,
/// on `saml`'s encrypted-assertion path, is a decrypted SAML assertion.
///
/// `resize`/`remap` are deliberately refused rather than forwarded: both can end
/// up releasing storage inside `child` (a shrink's tail, a moving remap's old
/// block) without ever reaching `free`, so there is no hook left to scrub it.
/// Refusing makes `Allocator.realloc` fall back to alloc + copy + free, and that
/// `free` is ours. The arena only ever calls `alloc` and `free` on its child
/// anyway, so this costs nothing today and stays correct if the arena goes away.
///
/// Note which build mode this is for: `Allocator.free` memsets the block to
/// `undefined` before reaching the vtable, so in Debug/ReleaseSafe the block is
/// already scrubbed to `0xaa`. In ReleaseFast that memset compiles away and this
/// wipe is the only thing standing between a freed block and unrelated code.
const WipingAllocator = struct {
    child: std.mem.Allocator,

    fn allocator(self: *WipingAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = allocFn,
            .resize = resizeFn,
            .remap = remapFn,
            .free = freeFn,
        } };
    }

    fn allocFn(ctx: *anyopaque, len: usize, a: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *WipingAllocator = @ptrCast(@alignCast(ctx));
        return self.child.rawAlloc(len, a, ra);
    }
    fn resizeFn(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) bool {
        return false;
    }
    fn remapFn(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
        return null;
    }
    fn freeFn(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, ra: usize) void {
        const self: *WipingAllocator = @ptrCast(@alignCast(ctx));
        std.crypto.secureZero(u8, m);
        self.child.rawFree(m, a, ra);
    }
};

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
    // CONVENTIONS §2.1 Z1 — everything this arena holds is a copy of the bytes
    // under verification, and for `saml`'s encrypted-assertion path those bytes
    // are a DECRYPTED `<saml:Assertion>`: the subject NameID and every attribute
    // asserted about them. `saml` wipes its own plaintext buffer, but we
    // canonicalize that plaintext into arena storage we own and free, so the
    // long-lived copy is ours. Wiping only the final canonical slices would miss
    // the intermediate `ArrayList` growth copies the arena keeps, so the wipe
    // goes on the arena's own release path — every block, once.
    var wiping: WipingAllocator = .{ .child = alloc };
    var arena_state = std.heap.ArenaAllocator.init(wiping.allocator());
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
    // W2-A8/xmldsig-F4: tracks whether a C14N transform has already been
    // consumed, so an enveloped-signature transform arriving after one (the
    // nonsense order — canonicalize, then try to strip an element from the
    // resulting octets) is refused rather than silently accepted and treated
    // as if it were the correct order.
    var seen_c14n = false;

    if (childByName(ref_el, "Transforms")) |transforms| {
        for (transforms.children) |tc| switch (tc.content) {
            .element => |t| {
                if (!isDs(t, "Transform")) continue;
                const talg = t.attr("", "Algorithm") orelse return error.MalformedSignature;
                if (std.mem.eql(u8, talg, alg_enveloped)) {
                    if (seen_c14n) return error.TransformOrderInvalid;
                    omit = signature;
                } else if (mapC14n(talg)) |m| {
                    mode = m;
                    inclusive_prefixes = try parseInclusiveNamespaces(arena, t);
                    seen_c14n = true;
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
        // `Document.findByAttr` is first-match-in-document-order and guarantees
        // nothing about uniqueness — and `name` need not be one of the names the
        // parser's `DuplicateId` guard was configured with, so on this branch the
        // parse-time ID index proves nothing at all. That gap is the whole of
        // XML Signature Wrapping in one step: a caller reads
        // `Result.references[i].uri` and resolves it their own way, and if two
        // elements may carry the same id, "the element we digested" and "the
        // element they read" are free to be different elements. Enforce here what
        // `UriNotResolved` already promises — *exactly one*.
        const hit = doc.findByAttr("", name, id) orelse return error.UriNotResolved;
        if (countByAttr(doc.root, name, id) != 1) return error.UriNotResolved;
        return hit;
    }
    // Fall-through ONLY: this branch reads the parse-time ID index, which is
    // deduplicated (a repeated value is `error.DuplicateId` at parse time), so a
    // hit here is unambiguous — the DSig-layer half of the wrapping defense.
    return doc.getElementById(id) orelse error.UriNotResolved;
}

/// How many elements in `el`'s subtree carry the unprefixed attribute `name`
/// with value `value`, saturating at 2 — the only question asked is
/// "exactly one?", and stopping early keeps a wide document cheap.
fn countByAttr(el: *const xml.Element, name: []const u8, value: []const u8) usize {
    var n: usize = 0;
    if (el.attr("", name)) |v| {
        if (std.mem.eql(u8, v, value)) n += 1;
    }
    for (el.children) |c| switch (c.content) {
        .element => |child| {
            n += countByAttr(child, name, value);
            if (n >= 2) return 2;
        },
        else => {},
    };
    return n;
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
            // W2-A8/xmldsig-F5: a wrong-length `SignatureValue` is "did not
            // verify" (`false`), not a structural error — matching the RSA
            // arm above, where `rsa.verifyPkcs1v15` rejecting a malformed
            // (including wrong-length) signature is caught and folded into
            // `false` rather than propagated. Before this fix the two arms
            // disagreed: RSA's `Result.valid = false` vs. ECDSA's hard
            // `error.MalformedSignature`, for the same underlying shape of
            // input defect. Callers that only inspect `Result.valid` still
            // fail closed either way (`saml` maps any `verify` error to
            // `SignatureInvalid`), so this is API-consistency, not a
            // fail-open risk either direction.
            if (sig.len != 64) return false;
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

pub const Base64Error = error{ MalformedBase64, OutOfMemory };

/// Decode standard base64, tolerating embedded ASCII whitespace/newlines.
///
/// XML routinely wraps long base64 fields (`SignatureValue`, `X509Certificate`,
/// `CipherValue`, a SAML POST binding's `SAMLResponse`) across lines, and HTML
/// forms inject their own, so a strict decoder rejects perfectly ordinary
/// documents. Public because `saml` — which already depends on this module —
/// needs exactly the same leniency for the same reason; it is XML-DSig's
/// problem, not two modules' problem.
///
/// Leniency stops at whitespace: padding, alphabet and length are still
/// std's strict standard decoder, so this does not widen what counts as a
/// valid signature value. Caller owns the result.
pub fn base64DecodeLenient(alloc: std.mem.Allocator, text: []const u8) Base64Error![]u8 {
    var clean: std.ArrayList(u8) = .empty;
    defer clean.deinit(alloc);
    for (text) |c| {
        if (!std.ascii.isWhitespace(c)) try clean.append(alloc, c);
    }
    const dec = std.base64.standard.Decoder;
    const n = dec.calcSizeForSlice(clean.items) catch return error.MalformedBase64;
    const buf = try alloc.alloc(u8, n);
    errdefer alloc.free(buf);
    dec.decode(buf, clean.items) catch return error.MalformedBase64;
    return buf;
}

fn decodeBase64(arena: std.mem.Allocator, text: []const u8) VerifyError![]u8 {
    return base64DecodeLenient(arena, text) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.MalformedBase64 => error.MalformedSignature,
    };
}

// ── tests ────────────────────────────────────────────────────────────────────
// Pull in the canonicalization test suite (byte-exact W3C vectors).
test {
    _ = c14n;
    _ = @import("test_external.zig");
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

/// Build a document whose signature references `#dup-1` through a CUSTOM id
/// attribute (`AID`, deliberately not one of `xml.Options.id_attr_names`, so the
/// parser's `DuplicateId` guard never looks at it). The reference covers the
/// `<Target>` subtree with plain exclusive C14N — no enveloped transform — so
/// appending `<Decoy AID="dup-1">` as a later sibling leaves both the reference
/// digest and the `SignedInfo` signature bit-for-bit valid while making the id
/// ambiguous. That is the attack shape: an untouched, genuinely valid signature
/// over a reference that no longer names one element.
fn buildDupIdDoc(a: std.mem.Allocator, with_decoy: bool) ![]u8 {
    var sk = try rsa.SecretKey.fromPem(test_rsa_priv_pem);
    defer sk.deinit();

    const tmpl =
        "<Root xmlns=\"urn:demo\">" ++
        "<Target AID=\"dup-1\">genuine</Target>" ++
        "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">" ++
        "<ds:SignedInfo>" ++
        "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" ++
        "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>" ++
        "<ds:Reference URI=\"#dup-1\">" ++
        "<ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms>" ++
        "<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>" ++
        "<ds:DigestValue>{s}</ds:DigestValue>" ++
        "</ds:Reference></ds:SignedInfo>" ++
        "<ds:SignatureValue>{s}</ds:SignatureValue>" ++
        "</ds:Signature>{s}</Root>";

    // Pass 1: digest the `<Target>` subtree.
    const p1 = try std.fmt.allocPrint(a, tmpl, .{ "", "", "" });
    defer a.free(p1);
    var d1 = try xml.parse(a, p1, .{});
    defer d1.deinit();
    const target = firstLocal(d1.root, "Target").?;
    const ref_canon = try c14n.canonicalize(a, target, .{ .mode = .exclusive });
    defer a.free(ref_canon);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(ref_canon, &digest, .{});
    var digest_b64_buf: [64]u8 = undefined;
    const digest_b64 = std.base64.standard.Encoder.encode(&digest_b64_buf, &digest);

    // Pass 2: sign the real `<SignedInfo>`.
    const p2 = try std.fmt.allocPrint(a, tmpl, .{ digest_b64, "", "" });
    defer a.free(p2);
    var d2 = try xml.parse(a, p2, .{});
    defer d2.deinit();
    const si = firstLocal(d2.root, "SignedInfo").?;
    const si_canon = try c14n.canonicalize(a, si, .{ .mode = .exclusive });
    defer a.free(si_canon);
    var sig_buf: [256]u8 = undefined;
    const sig_slice = try rsa.signPkcs1v15(sk, std.crypto.hash.sha2.Sha256, si_canon, &sig_buf);
    var sig_b64_buf: [512]u8 = undefined;
    const sig_b64 = std.base64.standard.Encoder.encode(&sig_b64_buf, sig_slice);

    const decoy = if (with_decoy) "<Decoy AID=\"dup-1\">forged</Decoy>" else "";
    return std.fmt.allocPrint(a, tmpl, .{ digest_b64, sig_b64, decoy });
}

/// First element with this local name anywhere in the subtree (namespace-blind).
fn firstLocal(el: *xml.Element, local: []const u8) ?*xml.Element {
    if (std.mem.eql(u8, el.local, local)) return el;
    for (el.children) |c| switch (c.content) {
        .element => |child| {
            if (firstLocal(child, local)) |f| return f;
        },
        else => {},
    };
    return null;
}

test "verify: an id_attr reference matching two elements is refused, not resolved to the first" {
    const a = testing.allocator;
    const pk = try rsa.PublicKey.fromPem(test_rsa_pub_pem);
    const opts: Options = .{ .key = .{ .rsa = pk }, .id_attr = "AID" };

    // Control: exactly one carrier of AID="dup-1" — a genuine, valid signature.
    const one = try buildDupIdDoc(a, false);
    defer a.free(one);
    var doc1 = try xml.parse(a, one, .{});
    defer doc1.deinit();
    var res = try verify(a, &doc1, firstLocal(doc1.root, "Signature").?, opts);
    defer res.deinit(a);
    try testing.expect(res.valid);

    // The attack shape: the SAME signature, plus a second element carrying the
    // same AID. Nothing the signature covers has changed, so the digest and the
    // SignatureValue both still check out — the only thing that changed is that
    // `#dup-1` no longer names one element. `AID` is not one of `xml`'s default
    // `id_attr_names`, so the parser's `DuplicateId` guard never sees it: this
    // document parses without complaint (asserted below).
    const two = try buildDupIdDoc(a, true);
    defer a.free(two);
    var doc2 = try xml.parse(a, two, .{});
    defer doc2.deinit();
    try testing.expect(firstLocal(doc2.root, "Decoy") != null);

    // Resolution must fail closed. Reporting "#dup-1 is validly signed" when a
    // caller resolving #dup-1 their own way could land on <Decoy> is exactly the
    // signature-wrapping split this module exists to prevent.
    try testing.expectError(error.UriNotResolved, verify(a, &doc2, firstLocal(doc2.root, "Signature").?, opts));
}

/// Test-only allocator that inspects every block on its way back to `child` and
/// records whether `needle` survived in it — the only way to observe a Z1 heap
/// wipe, since after `free` the bytes belong to the allocator again.
const FreeScanner = struct {
    child: std.mem.Allocator,
    needle: []const u8,
    /// A block still containing `needle` was released.
    leaked: bool = false,
    /// Blocks big enough to hold `needle` that were released at all — the
    /// positive control that the scanner is watching something.
    frees_seen: usize = 0,

    fn allocator(self: *FreeScanner) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = allocFn,
            .resize = resizeFn,
            .remap = remapFn,
            .free = freeFn,
        } };
    }
    fn allocFn(ctx: *anyopaque, len: usize, a: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *FreeScanner = @ptrCast(@alignCast(ctx));
        return self.child.rawAlloc(len, a, ra);
    }
    fn resizeFn(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, n: usize, ra: usize) bool {
        const self: *FreeScanner = @ptrCast(@alignCast(ctx));
        return self.child.rawResize(m, a, n, ra);
    }
    fn remapFn(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, n: usize, ra: usize) ?[*]u8 {
        const self: *FreeScanner = @ptrCast(@alignCast(ctx));
        return self.child.rawRemap(m, a, n, ra);
    }
    fn freeFn(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, ra: usize) void {
        const self: *FreeScanner = @ptrCast(@alignCast(ctx));
        if (m.len >= self.needle.len) {
            self.frees_seen += 1;
            if (std.mem.indexOf(u8, m, self.needle) != null) self.leaked = true;
        }
        self.child.rawFree(m, a, ra);
    }
};

test "Z1: verify() scrubs the canonicalized plaintext before its arena goes back to the caller's allocator" {
    // ReleaseFast ONLY, and the reason is the point of the test:
    // `std.mem.Allocator.free` memsets the block to `undefined` before it
    // reaches the vtable, so in Debug/ReleaseSafe every freed block is already
    // 0xaa and a scanner sees nothing whatever this module does. ReleaseFast is
    // the mode where our own `secureZero` is load-bearing — and the mode an
    // integrator ships (CONVENTIONS §2.1). A visible skip beats a silent pass.
    if (@import("builtin").mode != .ReleaseFast) return error.SkipZigTest;

    const a = testing.allocator;
    var sd = try buildSignedRsaDoc(a, false, false);
    defer sd.deinit(a);

    var doc = try xml.parse(a, sd.xml, .{});
    defer doc.deinit();
    const sig = childByName(doc.root, "Signature").?;
    const pk = try rsa.PublicKey.fromPem(test_rsa_pub_pem);

    // This byte sequence exists ONLY in the canonical form: in the source
    // document the `<ds:Signature>` sits between `</Data>` and `</Envelope>`,
    // and the enveloped-signature transform is what splices them together. A hit
    // therefore cannot come from the source buffer or from the parsed tree
    // (whose slices borrow from that buffer) — only from a C14N buffer inside
    // verify()'s own arena.
    const needle = "<Data>Hello World</Data></Envelope>";
    try testing.expect(std.mem.indexOf(u8, sd.xml, needle) == null);

    var scan = FreeScanner{ .child = a, .needle = needle };
    const sa = scan.allocator();

    var res = try verify(sa, &doc, sig, .{ .key = .{ .rsa = pk } });
    defer res.deinit(sa);
    // The canonicalization really happened (and agreed with the signature).
    try testing.expect(res.valid);
    // The scanner really watched something.
    try testing.expect(scan.frees_seen > 0);
    try testing.expect(!scan.leaked);
}

test "EXTERNAL anchor: our own signer's output is byte-identical to openssl's over the same canonical bytes" {
    // RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) is DETERMINISTIC — no salt, no nonce —
    // so for a FIXED key and FIXED message there is exactly one valid
    // signature, and any correct implementation must produce it. That lets us
    // cross-check `buildSignedRsaDoc`'s own signer (used by every OTHER test in
    // this file) against `openssl dgst -sha256 -sign` run OFFLINE over the
    // identical canonical `<SignedInfo>` bytes, computed with `xmllint
    // --exc-c14n` (independent of this module's own C14N). Reproduction
    // commands (not run by the test suite):
    //   xmllint --exc-c14n ref_input.xml | openssl dgst -sha256 -binary | base64
    //   xmllint --exc-c14n si_input.xml | openssl dgst -sha256 -sign priv.pem -binary | base64
    //   xmlsec1 --verify --lax-key-search --pubkey-pem pub.pem final_doc.xml   # => OK
    // `ref_input.xml`/`si_input.xml` are the exact `with_empty`/`with_digest`
    // documents `buildSignedRsaDoc` constructs for content="Hello World" under
    // the SAME `test_rsa_priv_pem` embedded above. This is the same "EXTERNAL
    // anchor" pattern `saml`'s `test_redirect_binding.zig` already uses for its
    // Redirect-signing primitive.
    const external_digest_b64 = "qp5qp7UvMAZZZNnPy5biqRM83FVVRSmnkEymMrZATJE=";
    const external_signature_b64 =
        "hN3vrcjhR4T8Qa4i9XYStjFbbKWaNi26+ekfD8wxiFk1b+FkKEkgkRCk34000nnLqV2PVy9jVYFhw8ApaW9gTH/O/+rkOXys1u7Ye1vUBQFx+tuP0icIesNPp1BrD9h7cQGo3RSvjJXG67x+XdXHRjYGehHhVhicffTsA1ji0T40dUK05Crny68WwJD4Jq626ZCTvUMZwRToNbxoLUmHyBClymP/34Jrzln9bSQTgABBwZ1MxMFE5KuW/qcbCbcT5OhJ0eXGx4Zo5kmce1iW8EDBsVpZ3xg9QMbr9vzQQN7Puw3lWZK7OnQsX+sFU+QoIHxwZBB+4S/+aerQ9+Shqw==";

    var sd = try buildSignedRsaDoc(testing.allocator, false, false);
    defer sd.deinit(testing.allocator);
    var doc = try xml.parse(testing.allocator, sd.xml, .{});
    defer doc.deinit();
    const sig = childByName(doc.root, "Signature").?;
    const digest_el = childByName(childByName(childByName(sig, "SignedInfo").?, "Reference").?, "DigestValue").?;
    const sig_val_el = childByName(sig, "SignatureValue").?;
    const got_digest = try digest_el.textContent(testing.allocator);
    defer testing.allocator.free(got_digest);
    const got_sig = try sig_val_el.textContent(testing.allocator);
    defer testing.allocator.free(got_sig);

    try testing.expectEqualStrings(external_digest_b64, got_digest);
    try testing.expectEqualStrings(external_signature_b64, got_sig);

    // And, as belt-and-suspenders, our own verifier accepts the reconstructed
    // externally-signed document too (xmlsec1 --verify already confirmed OK
    // offline against this exact digest+signature pair).
    const pk = try rsa.PublicKey.fromPem(test_rsa_pub_pem);
    var res = try verify(testing.allocator, &doc, sig, .{ .key = .{ .rsa = pk } });
    defer res.deinit(testing.allocator);
    try testing.expect(res.valid);
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

    // (c) W2-A8/xmldsig-F5: a wrong-LENGTH raw r‖s `SignatureValue` — before
    // this fix the ECDSA arm raised `error.MalformedSignature` here (a hard
    // structural error, no `Result` at all) where the RSA arm folds the same
    // shape of defect into `Result.valid = false`. `verify` itself must
    // still succeed and report a normal (unverified) `Result`, exactly like
    // (a) and (b) above — not propagate an error.
    var short_rs: [63]u8 = undefined;
    @memcpy(&short_rs, rs[0..63]);
    var short_b64: [128]u8 = undefined;
    const short_sig_b64 = std.base64.standard.Encoder.encode(&short_b64, &short_rs);
    const shortened = try std.fmt.allocPrint(a, doc_template, .{ digest_b64, short_sig_b64 });
    defer a.free(shortened);
    var doc_s = try xml.parse(a, shortened, .{});
    defer doc_s.deinit();
    const sig_s = childByName(doc_s.root, "Signature").?;
    var short_res = try verify(a, &doc_s, sig_s, .{ .key = .{ .ecdsa_p256_sec1 = &pub_sec1 } });
    defer short_res.deinit(a);
    try testing.expect(!short_res.valid);
    try testing.expect(short_res.references[0].digest_valid); // structurally fine up to the signature
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

// W2-A8/xmldsig-F4: the transform-order check must fire before any digest or
// signature bytes matter — both `DigestValue` and `SignatureValue` below are
// garbage, and the reference-loop's order check runs before `DigestMethod`
// is even parsed, so this is not exploitable through those fields.
test "verify: enveloped-signature transform after C14N is rejected (wrong order)" {
    const a = testing.allocator;
    const src =
        "<Envelope xmlns=\"urn:demo\">" ++
        "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">" ++
        "<ds:SignedInfo>" ++
        "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" ++
        "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>" ++
        "<ds:Reference URI=\"\">" ++
        "<ds:Transforms>" ++
        // WRONG ORDER: canonicalize first, then (nonsensically) try to strip
        // the Signature element from the resulting octets. The correct order
        // (exercised by every other test in this file) is the reverse.
        "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" ++
        "<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>" ++
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
    try testing.expectError(error.TransformOrderInvalid, verify(a, &doc, sig, .{ .key = .{ .rsa = pk } }));
}

// The correct order (enveloped-signature, THEN C14N) must keep working — a
// real signed document exercises this already (`buildSignedRsaDoc`), but
// this pins the *acceptance* boundary right next to the rejection above.
test "verify: enveloped-signature transform before C14N is still accepted (right order)" {
    const a = testing.allocator;
    var doc = try buildSignedRsaDoc(a, false, false);
    defer doc.deinit(a);
    var parsed = try xml.parse(a, doc.xml, .{});
    defer parsed.deinit();
    const sig = childByName(parsed.root, "Signature").?;
    const pk = try rsa.PublicKey.fromPem(test_rsa_pub_pem);
    var res = try verify(a, &parsed, sig, .{ .key = .{ .rsa = pk } });
    defer res.deinit(a);
    try testing.expect(res.valid);
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

// ════════════════════════════════════════════════════════════════════════════
// fuzz: the `ds:Signature` surface
// ════════════════════════════════════════════════════════════════════════════
//
// `verify()` IS this module's attack surface: it runs on a fully
// attacker-controlled `ds:Signature` element before any trust decision has
// been made (`saml` calls it on an unauthenticated Response). Until this
// harness existed the module had no `testing.fuzz` target at all, so
// `scripts/fuzz-sweep.sh` — whose module list is derived from that grep — had
// never covered it, and `xml`'s own harness stops at the parse layer: it never
// builds a `ds:Signature`, so `validateReference`, `c14n.canonicalize`,
// `decodeBase64` and `verifySignature` were unreached by any fuzzer.
//
// Raw entropy cannot get past `xml.parse`, let alone assemble a SignedInfo, so
// the fuzzed bytes are placed INSIDE real signature structure: algorithm URIs
// drawn from the module's own allow-lists (plus off-list ones), base64 fields
// of signature length, and — the deepest mode — byte mutations of a genuinely
// valid signed document, which reach the digest and RSA comparisons with
// everything else intact.

/// One valid signed document, built once (two RSA signatures) and reused as
/// the mutation base; `buildSignedRsaDoc` is deterministic, so caching changes
/// nothing but the budget. Held in the page allocator on purpose: it outlives
/// individual tests, and `std.testing.allocator` is torn down between them.
var fuzz_signed_doc: ?[]u8 = null;

fn fuzzSignedDoc() ![]const u8 {
    if (fuzz_signed_doc) |d| return d;
    const sd = try buildSignedRsaDoc(std.heap.page_allocator, false, false); // global-alloc-ok: test/fuzz fixture cache outliving testing.allocator's per-test teardown (see doc comment above)
    fuzz_signed_doc = sd.xml;
    return sd.xml;
}

const fuzz_c14n_algs = [_][]const u8{
    alg_exc_c14n, alg_exc_c14n_wc, alg_c14n, alg_c14n_wc, "urn:not-a-c14n",
};
const fuzz_sig_algs = [_][]const u8{
    sig_rsa_sha256, sig_rsa_sha384, sig_rsa_sha512, sig_rsa_sha1, sig_ecdsa_sha256, "urn:not-a-sig",
};
const fuzz_digest_algs = [_][]const u8{
    dig_sha256, dig_sha384, dig_sha512, dig_sha1, "urn:not-a-digest",
};
const fuzz_transform_algs = [_][]const u8{
    alg_enveloped, alg_exc_c14n, alg_c14n, "http://www.w3.org/TR/1999/REC-xpath-19991116", "urn:not-a-transform",
};
const fuzz_ref_uris = [_][]const u8{ "", "#obj-1", "#nope", "#", "http://evil.example/x" };

/// The parts of a `ds:Signature` document a hostile peer controls.
const SigShape = struct {
    c14n_alg: []const u8,
    sig_alg: []const u8,
    digest_alg: []const u8,
    transform1: ?[]const u8,
    transform2: ?[]const u8,
    ref_uri: []const u8,
    digest_value: []const u8,
    signature_value: []const u8,
    content: []const u8,
    key_info_cert: ?[]const u8,
    /// Emit a second `ds:Reference` (the multi-reference shape).
    second_reference: bool,
};

fn buildFuzzSignature(alloc: std.mem.Allocator, s: SigShape) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    try out.print(alloc, "<Envelope ID=\"obj-1\" xmlns=\"urn:demo\"><Data>{s}</Data>", .{s.content});
    try out.print(alloc, "<ds:Signature xmlns:ds=\"{s}\"><ds:SignedInfo>", .{ds_ns});
    try out.print(alloc, "<ds:CanonicalizationMethod Algorithm=\"{s}\"/>", .{s.c14n_alg});
    try out.print(alloc, "<ds:SignatureMethod Algorithm=\"{s}\"/>", .{s.sig_alg});
    for (0..(if (s.second_reference) @as(usize, 2) else 1)) |_| {
        try out.print(alloc, "<ds:Reference URI=\"{s}\">", .{s.ref_uri});
        if (s.transform1 != null or s.transform2 != null) {
            try out.appendSlice(alloc, "<ds:Transforms>");
            if (s.transform1) |t| try out.print(alloc, "<ds:Transform Algorithm=\"{s}\"/>", .{t});
            if (s.transform2) |t| try out.print(alloc, "<ds:Transform Algorithm=\"{s}\"/>", .{t});
            try out.appendSlice(alloc, "</ds:Transforms>");
        }
        try out.print(alloc, "<ds:DigestMethod Algorithm=\"{s}\"/>", .{s.digest_alg});
        try out.print(alloc, "<ds:DigestValue>{s}</ds:DigestValue></ds:Reference>", .{s.digest_value});
    }
    try out.appendSlice(alloc, "</ds:SignedInfo>");
    try out.print(alloc, "<ds:SignatureValue>{s}</ds:SignatureValue>", .{s.signature_value});
    if (s.key_info_cert) |c| {
        try out.print(
            alloc,
            "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{s}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>",
            .{c},
        );
    }
    try out.appendSlice(alloc, "</ds:Signature></Envelope>");
    return out.toOwnedSlice(alloc);
}

/// Parse a candidate document and run `verify()` on the `ds:Signature` it
/// contains (the element itself when it is the root — the enveloping shape).
/// Split out so the reachability test drives exactly what the fuzzer drives.
fn fuzzVerifyDoc(alloc: std.mem.Allocator, src: []const u8, options: Options) !void {
    var doc = xml.parse(alloc, src, .{ .id_attr_names = &.{"ID"} }) catch return;
    defer doc.deinit();
    const sig = if (isDs(doc.root, "Signature")) doc.root else childByName(doc.root, "Signature") orelse return;
    var res = verify(alloc, &doc, sig, options) catch return;
    res.deinit(alloc);
}

/// XML-text-safe alphabet (no `<`/`&`), biased to base64 so a fuzzed
/// DigestValue/SignatureValue frequently decodes instead of dying at the
/// first character.
const ds_b64ish = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/= \n\t!*";

fn toDsB64ish(buf: []u8) void {
    for (buf) |*c| c.* = ds_b64ish[c.* % ds_b64ish.len];
}

fn fuzzVerifySignature(_: void, smith: *std.testing.Smith) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const pk = try rsa.PublicKey.fromPem(test_rsa_pub_pem);
    const options: Options = .{
        .key = .{ .rsa = pk },
        .allow_weak_sha1 = smith.value(bool),
        .id_attr = if (smith.value(bool)) "ID" else null,
    };

    var raw: [512]u8 = undefined;
    smith.bytes(&raw);
    const raw_len: usize = smith.valueRangeAtMost(u16, 0, raw.len);

    // Mode 1 — a signature assembled around the fuzzed bytes.
    {
        var digest_buf: [64]u8 = undefined;
        smith.bytes(&digest_buf);
        var sig_buf: [256]u8 = undefined; // exactly one RSA-2048 signature
        smith.bytes(&sig_buf);
        var text_buf: [64]u8 = undefined;
        smith.bytes(&text_buf);
        toDsB64ish(&text_buf);

        const digest_value: []const u8 = switch (smith.valueRangeAtMost(u8, 0, 2)) {
            0 => try b64Encode(a, digest_buf[0..32]),
            1 => blk: {
                const t = try a.dupe(u8, digest_buf[0..]);
                toDsB64ish(t);
                break :blk t;
            },
            else => "",
        };
        const signature_value: []const u8 = switch (smith.valueRangeAtMost(u8, 0, 2)) {
            0 => try b64Encode(a, sig_buf[0..]), // right length: reaches the RSA op
            1 => blk: {
                const t = try a.dupe(u8, sig_buf[0..64]);
                toDsB64ish(t);
                break :blk t;
            },
            else => "",
        };

        const src = try buildFuzzSignature(a, .{
            .c14n_alg = fuzz_c14n_algs[smith.index(fuzz_c14n_algs.len)],
            .sig_alg = fuzz_sig_algs[smith.index(fuzz_sig_algs.len)],
            .digest_alg = fuzz_digest_algs[smith.index(fuzz_digest_algs.len)],
            .transform1 = if (smith.value(bool)) fuzz_transform_algs[smith.index(fuzz_transform_algs.len)] else null,
            .transform2 = if (smith.value(bool)) fuzz_transform_algs[smith.index(fuzz_transform_algs.len)] else null,
            .ref_uri = fuzz_ref_uris[smith.index(fuzz_ref_uris.len)],
            .digest_value = digest_value,
            .signature_value = signature_value,
            .content = &text_buf,
            .key_info_cert = if (smith.value(bool)) digest_value else null,
            .second_reference = smith.value(bool),
        });
        try fuzzVerifyDoc(a, src, options);
    }

    // Mode 2 — a genuinely VALID signed document with a fuzzer-chosen byte
    // range overwritten. Everything the mutation does not touch stays
    // consistent, so these inputs reach the digest and signature comparisons
    // that a from-scratch document rarely survives to.
    {
        const base = try fuzzSignedDoc();
        const mutant = try a.dupe(u8, base);
        const off = smith.index(mutant.len);
        const n = @min(smith.valueRangeAtMost(u8, 0, 32), mutant.len - off);
        var patch: [32]u8 = undefined;
        smith.bytes(&patch);
        toDsB64ish(patch[0..n]);
        @memcpy(mutant[off..][0..n], patch[0..n]);
        try fuzzVerifyDoc(a, mutant, options);
    }

    // Mode 3 — unstructured, so the XML framing itself is fuzzed.
    try fuzzVerifyDoc(a, raw[0..raw_len], options);
}

fn b64Encode(alloc: std.mem.Allocator, data: []const u8) ![]u8 {
    const enc = std.base64.standard.Encoder;
    const out = try alloc.alloc(u8, enc.calcSize(data.len));
    _ = enc.encode(out, data);
    return out;
}

test "fuzz: verify never panics on a hostile ds:Signature" {
    try std.testing.fuzz({}, fuzzVerifySignature, .{});
}

test "the xmldsig fuzz harness reaches verify's digest and signature checks (reachability)" {
    // Guards the class-B defect: a harness that never reaches what it covers.
    const a = testing.allocator;
    const pk = try rsa.PublicKey.fromPem(test_rsa_pub_pem);
    const options: Options = .{ .key = .{ .rsa = pk } };

    // 1. The mutation base is a document that verifies — so mode 2 starts from
    //    an input that traverses `verify()` in full, digest comparison and RSA
    //    verification included.
    {
        const base = try fuzzSignedDoc();
        var doc = try xml.parse(a, base, .{ .id_attr_names = &.{"ID"} });
        defer doc.deinit();
        const sig = childByName(doc.root, "Signature").?;
        var res = try verify(a, &doc, sig, options);
        defer res.deinit(a);
        try testing.expect(res.valid);
        try testing.expect(res.references[0].digest_valid);
    }

    // 2. A document from the harness's own builder, with on-allow-list
    //    algorithms and a signature-length base64 SignatureValue, runs all the
    //    way to a verdict: `verify` RETURNING a Result (rather than a
    //    structural error) means C14N, the reference digest and
    //    `verifySignature` all executed.
    {
        const digest_b64 = try b64Encode(a, &[_]u8{0xAB} ** 32);
        defer a.free(digest_b64);
        const sig_b64 = try b64Encode(a, &[_]u8{0xCD} ** 256);
        defer a.free(sig_b64);
        const src = try buildFuzzSignature(a, .{
            .c14n_alg = alg_exc_c14n,
            .sig_alg = sig_rsa_sha256,
            .digest_alg = dig_sha256,
            .transform1 = alg_enveloped,
            .transform2 = alg_exc_c14n,
            .ref_uri = "",
            .digest_value = digest_b64,
            .signature_value = sig_b64,
            .content = "Hello World",
            .key_info_cert = null,
            .second_reference = false,
        });
        defer a.free(src);
        var doc = try xml.parse(a, src, .{ .id_attr_names = &.{"ID"} });
        defer doc.deinit();
        const sig = childByName(doc.root, "Signature").?;
        var res = try verify(a, &doc, sig, options);
        defer res.deinit(a);
        // Both comparisons ran and both said no — which is the point: they ran.
        try testing.expect(!res.valid);
        try testing.expectEqual(@as(usize, 1), res.references.len);
        try testing.expect(!res.references[0].digest_valid);
    }

    // 3. And the harness body itself runs to completion on fixed input.
    var smith: std.testing.Smith = .{ .in = &([_]u8{0x01} ** 64 ++ [_]u8{0x00} ** 2048) };
    try fuzzVerifySignature({}, &smith);
}
