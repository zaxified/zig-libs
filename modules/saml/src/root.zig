// SPDX-License-Identifier: MIT
//! saml — SAML 2.0 Web Browser SSO, **Service-Provider (relying-party) side**.
//!
//! This is layer 3 (the top) of a SAML cluster: `xml` (hardened parser) →
//! `xmldsig` (C14N + XML-Signature *verify*) → `saml` (this module: consume an
//! IdP's `<samlp:Response>`, defend against XML-Signature-Wrapping, validate
//! conditions / subject confirmation, and hand the caller a trusted
//! `AuthnResult`).
//!
//! ## What it does
//! Given the base64 `SAMLResponse` form field from the HTTP-POST binding (or the
//! already-decoded XML), `consumeResponse` performs, in order:
//!   1. base64-decode + hardened parse (`xml`, which is XXE / entity-bomb proof);
//!   2. structural location of the single `<saml:Assertion>` (direct child of
//!      `<samlp:Response>`) — *more than one assertion is rejected*;
//!   3. signature verification via `xmldsig.verify` against the **caller-
//!      configured IdP key** (never `<KeyInfo>`), accepting a signed Assertion
//!      and/or a signed Response;
//!   4. the **XML-Signature-Wrapping defense** (see below);
//!   5. `<Conditions>` (NotBefore / NotOnOrAfter / AudienceRestriction /
//!      OneTimeUse), Bearer `<SubjectConfirmationData>` (Recipient /
//!      NotOnOrAfter / InResponseTo), and Response-level `<Status>` / `<Issuer>`
//!      / `<Destination>` checks, all against a **caller-supplied clock**;
//!   6. extraction of NameID, SessionIndex, AuthnContextClassRef and the
//!      `<AttributeStatement>` into an owned `AuthnResult`.
//!
//! ## XML-Signature-Wrapping (XSW) defense — the headline security property
//! `xmldsig` proves only "signature S cryptographically covers the element whose
//! ID = X". It deliberately does NOT decide which element the SP may trust. That
//! decision lives here. The mechanism (`signedTargetMatches`):
//!   - the verified signature must carry exactly ONE `<Reference>`;
//!   - its `URI` must be a non-empty same-document `#id` (empty / external /
//!     ambiguous references are refused);
//!   - resolving that id (via the SAML `ID` attribute) yields a node **pointer**
//!     that must be *identical* to the assertion the SP is about to consume (or,
//!     for a Response-level signature, to the Response element that directly
//!     contains that assertion).
//! Because `xml` rejects duplicate IDs at parse time and both `xmldsig` and this
//! module resolve the reference through the very same unique-ID index, pointer
//! identity is a sound proof that the signed octets ARE the assertion whose
//! NameID / attributes we read — an injected or wrapped sibling assertion the
//! signature does not cover can never become the consumed one. A signature that
//! is valid but points elsewhere is reported as `error.SignatureWrappingDetected`
//! rather than silently ignored.
//!
//! A Response/Assertion with no signature covering the consumed assertion is
//! rejected (`error.SignatureMissing`) — there is no "optional signature"
//! downgrade.
//!
//! ## Trust model
//! The IdP signing key is configured out-of-band (`Config.idp_key`). `<KeyInfo>`
//! is never trusted to supply it; the certificate seen there is surfaced
//! (`AuthnResult.x509_cert_der`, UNTRUSTED) only so the caller may pin it.
//!
//! ## `<saml:EncryptedAssertion>` — the eIDAS encrypt profile
//! When the SP configures its RSA decryption key (`Config.sp_decrypt_key`), an
//! `<saml:EncryptedAssertion>` is transparently decrypted via the sibling
//! `xmlenc` module and the recovered `<saml:Assertion>` runs through the SAME
//! signature-verify + XSW + validation path a cleartext assertion does. The
//! order is **decrypt → then signature-verify**: the IdP signs the assertion
//! before encrypting it, so verification happens on the plaintext, and a
//! padding/oracle probe that yields a well-formed-but-wrong plaintext still
//! fails the signature check. With no key configured the old refuse-behavior
//! (`error.EncryptedAssertionUnsupported`) is preserved. The decrypted
//! assertion is the root of its own standalone document; the XSW pointer-pin
//! holds within that inner document (see `verifyCoveringDecrypted`).
//!
//! ## `<saml:EncryptedID>` / `<saml:EncryptedAttribute>` + Holder-of-Key
//! With `Config.sp_decrypt_key` set, an encrypted `<saml:EncryptedID>` in the
//! Subject and any `<saml:EncryptedAttribute>` in the AttributeStatement are
//! decrypted (via `xmlenc.decryptData`) on the ALREADY-signature-verified
//! assertion — the recovered `<NameID>` / `<Attribute>` splice into the normal
//! extraction path, and decryption failures collapse to generic
//! `error.IdDecryptionFailed` / `error.AttributeDecryptionFailed`. Subject
//! confirmation is selected via `Config.subject_confirmation` (`.bearer` |
//! `.holder_of_key` | `.sender_vouches` | `.either`): Holder-of-Key matches the
//! presenter's key structurally — SAME-FORM (X.509-DER byte-equality vs
//! `presented_holder_cert_der`, or a bare `<ds:KeyValue>` RSA modulus+exponent /
//! EC SEC1 point vs `presented_holder_key`) and CROSS-FORM (certificate ↔
//! `<ds:KeyValue>`, via the certificate's `SubjectPublicKeyInfo` extracted with
//! `x509.spkiOf`, a defensive walk that never calls
//! `std.crypto.Certificate.parse`, then compared by key PARAMETERS — RSA
//! modulus+exponent, or the P-256 affine point — never by encoding);
//! sender-vouches trusts the verified signature alone (no key/recipient
//! binding). An optional `Config.required_loa` enforces a minimum eIDAS
//! `<AuthnContextClassRef>`. See SPEC.md for the HoK matching matrix and the
//! sender-vouches trust model.
//!
//! ## Out of scope (see SPEC.md)
//!   - Single Logout, artifact binding, the IdP side.
//!
//! Never reads the system clock. Never panics on malformed / adversarial input:
//! every failure is a typed error.

const std = @import("std");
const xml = @import("xml");
const xmldsig = @import("xmldsig");
const xmlenc = @import("xmlenc");
const rsa = @import("rsa");
const x509 = @import("x509");

/// P-256 public keys, the one EC form `xmldsig.VerifyKey` (and therefore this
/// module's Holder-of-Key matching) supports.
const P256PublicKey = std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey;

pub const meta = .{
    .platform = .any,
    .role = .codec, // consumes an untrusted wire document into a trusted result
    .concurrency = .reentrant,
    .model_after = "OASIS SAML 2.0 (SAMLCore / SAMLProf) Web Browser SSO, SP side; XSW-hardened per 'On Breaking SAML'",
    .deps = .{ "xmldsig", "xml", "xmlenc", "rsa", "x509" }, // x509: the panic-safe SubjectPublicKeyInfo extractor behind HoK cross-form matching
};

// ── namespaces ───────────────────────────────────────────────────────────────

pub const samlp_ns = "urn:oasis:names:tc:SAML:2.0:protocol";
pub const saml_ns = "urn:oasis:names:tc:SAML:2.0:assertion";
pub const md_ns = "urn:oasis:names:tc:SAML:2.0:metadata";

const status_success = "urn:oasis:names:tc:SAML:2.0:status:Success";
const cm_bearer = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
const cm_holder_of_key = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key";
const cm_sender_vouches = "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches";

// The eIDAS Level-of-Assurance class references, in ascending order.
const eidas_loa_low = "http://eidas.europa.eu/LoA/low";
const eidas_loa_substantial = "http://eidas.europa.eu/LoA/substantial";
const eidas_loa_high = "http://eidas.europa.eu/LoA/high";

// The single P-256 (secp256r1 / prime256v1) NamedCurve identifier accepted for
// an `<ECKeyValue>` match. Mirrors `xmldsig.VerifyKey`, which is P-256-only.
const named_curve_p256 = "urn:oid:1.2.840.10045.3.1.7";

/// A decompression-bomb cap for the HTTP-Redirect (DEFLATE) binding.
pub const max_redirect_inflated = 1 << 20;

// ── configuration ────────────────────────────────────────────────────────────

/// Which element(s) the SP will accept a valid signature on. `.either` (the
/// default) accepts a signed Assertion OR a signed enclosing Response; both are
/// pinned to the consumed assertion by the XSW defense regardless.
pub const SignaturePolicy = enum { assertion, response, either };

/// Which `<saml:SubjectConfirmation>` method(s) the SP will accept.
///   - `.bearer` (the default) — the Web-SSO default; only Bearer confirmations
///     are considered, matching all prior behavior.
///   - `.holder_of_key` — only Holder-of-Key confirmations are considered; the
///     caller MUST supply `presented_holder_cert_der` and/or
///     `presented_holder_key` (the key the presenter authenticated the transport
///     with).
///   - `.sender_vouches` — only sender-vouches confirmations are considered. This
///     method imposes NO key/recipient binding on the subject: trust derives
///     entirely from the already-verified assertion signature. The caller MUST
///     ensure the configured `idp_key` is the trusted attesting authority (see
///     SPEC.md "Sender-vouches").
///   - `.either` — a Bearer, Holder-of-Key OR sender-vouches confirmation may
///     satisfy the subject; HoK still requires the presented key when a HoK
///     confirmation is the one being validated.
pub const SubjectConfirmationPolicy = enum { bearer, holder_of_key, sender_vouches, either };

/// A public key the presenter authenticated the transport with, for matching a
/// bare `<ds:KeyValue>` in a Holder-of-Key `<SubjectConfirmation>` (no
/// certificate). Mirrors `xmldsig.VerifyKey`.
///   - `.rsa` — an `rsa.PublicKey`; matched against an `<RSAKeyValue>`'s
///     `<Modulus>`+`<Exponent>` by big-endian integer equality.
///   - `.ec_sec1` — a SEC1-encoded P-256 point (33-byte compressed or 65-byte
///     uncompressed); matched against an `<ECKeyValue>`'s `<PublicKey>` point by
///     byte equality (the `<NamedCurve>` must identify P-256).
pub const PresentedKey = union(enum) {
    rsa: rsa.PublicKey,
    ec_sec1: []const u8,
};

/// Everything the SP is configured with out-of-band. `now_unix` is supplied by
/// the caller — the module never reads the system clock (testability + no
/// hidden ambient authority).
pub const Config = struct {
    /// Expected `<Issuer>` (IdP entityID). Compared verbatim.
    idp_entity_id: []const u8,
    /// The IdP's configured signing key. Signatures are verified against THIS —
    /// never `<KeyInfo>`.
    idp_key: xmldsig.VerifyKey,

    /// This SP's entityID; MUST appear in every `<AudienceRestriction>`.
    sp_entity_id: []const u8,
    /// This SP's Assertion Consumer Service URL; MUST equal the Bearer
    /// `<SubjectConfirmationData Recipient>` (and `<Response Destination>` when
    /// that attribute is present).
    acs_url: []const u8,

    /// The caller's current time, seconds since the Unix epoch.
    now_unix: i64,
    /// Allowed clock skew (seconds) applied to every time-window comparison.
    clock_skew_secs: i64 = 60,

    /// The `ID` of the AuthnRequest this SP sent (solicited SSO). A Bearer
    /// `SubjectConfirmationData InResponseTo` MUST equal it. Leave null only
    /// together with `allow_idp_initiated`.
    expected_in_response_to: ?[]const u8 = null,
    /// Permit an unsolicited (IdP-initiated) assertion, i.e. one whose Bearer
    /// confirmation carries no `InResponseTo`. Off by default.
    allow_idp_initiated: bool = false,

    /// Permit the legacy SHA-1 digest / RSA-SHA1 signature algorithms.
    allow_weak_sha1: bool = false,
    /// Which element the signature must be on. Default `.either`.
    signature_policy: SignaturePolicy = .either,

    /// Which `<SubjectConfirmation>` method(s) are acceptable. Default `.bearer`
    /// (the Web-SSO default; unchanged for existing callers).
    subject_confirmation: SubjectConfirmationPolicy = .bearer,
    /// For Holder-of-Key confirmation: the DER of the certificate the presenter
    /// authenticated the transport with (e.g. the TLS client certificate). It
    /// matches an `<ds:X509Certificate>` in the HoK `<ds:KeyInfo>` by DER
    /// byte-equality (same form), and a bare `<ds:KeyValue>` by comparing this
    /// certificate's extracted public key with the one the `<ds:KeyValue>`
    /// names (cross-form). Null (the default) ⇒ no certificate is presented;
    /// irrelevant to the Bearer path. A HoK confirmation with NEITHER
    /// `presented_holder_cert_der` NOR `presented_holder_key` configured cannot
    /// be satisfied (`error.PresentedKeyMissing`). See SPEC.md "Holder-of-Key".
    presented_holder_cert_der: ?[]const u8 = null,
    /// For Holder-of-Key confirmation: the public key the presenter
    /// authenticated the transport with. It matches an `<RSAKeyValue>` by
    /// big-endian modulus+exponent equality and an `<ECKeyValue>` by NamedCurve
    /// (P-256) + point-byte equality (same form), and an `<ds:X509Certificate>`
    /// by comparing it with that certificate's extracted public key
    /// (cross-form). May be set together with (or instead of)
    /// `presented_holder_cert_der`; ANY of the four pairings matching confirms
    /// the subject. See SPEC.md "Holder-of-Key".
    presented_holder_key: ?PresentedKey = null,

    /// eIDAS Level-of-Assurance minimum. When set, the returned
    /// `<AuthnContextClassRef>` MUST meet this level or the Response is rejected
    /// (`error.LevelOfAssuranceInsufficient`). For the eIDAS URIs
    /// (`http://eidas.europa.eu/LoA/{low,substantial,high}`) the natural ordering
    /// low < substantial < high is used; for any other (non-eIDAS) class ref an
    /// EXACT string match is required. An absent `<AuthnContextClassRef>` never
    /// meets a requirement. Null (the default) ⇒ no LoA check (unchanged
    /// behavior). See SPEC.md "Level of Assurance".
    required_loa: ?[]const u8 = null,

    /// The unqualified attribute name that carries assertion / response IDs.
    /// SAML uses `ID`; both this module and `xmldsig` resolve references through
    /// it, which is what makes the XSW pointer-pin sound.
    id_attr: []const u8 = "ID",

    // ── EncryptedAssertion (eIDAS encrypt profile) ───────────────────────────
    // All optional: when `sp_decrypt_key` is null the module behaves exactly as
    // before and refuses any `<saml:EncryptedAssertion>` with
    // `error.EncryptedAssertionUnsupported`.

    /// This SP's RSA private key, used ONLY to decrypt a
    /// `<saml:EncryptedAssertion>` (RSA-OAEP / — gated — RSA-1_5 key transport)
    /// via the `xmlenc` module. Null (the default) ⇒ encrypted assertions are
    /// refused (`error.EncryptedAssertionUnsupported`), i.e. opt-in.
    sp_decrypt_key: ?rsa.SecretKey = null,
    /// Permit RSAES-PKCS#1 v1.5 key transport when decrypting (Bleichenbacher /
    /// Jager–Somorovsky). OFF by default; only enable for an IdP that offers
    /// nothing else. Passed straight through to `xmlenc`.
    allow_weak_rsa15: bool = false,
    /// Optional symmetric key-encryption key for `kw-aes128` / `kw-aes256` key
    /// wrap inside the EncryptedKey (16 or 32 bytes). Null ⇒ none available.
    /// Passed straight through to `xmlenc`.
    decrypt_kek: ?[]const u8 = null,
};

// ── result ───────────────────────────────────────────────────────────────────

/// One `<saml:Attribute>` collapsed to name → values. `values` may be empty
/// (an attribute present with no `<AttributeValue>`) or multi-valued.
pub const Attribute = struct {
    name: []const u8,
    friendly_name: ?[]const u8,
    values: []const []const u8,
};

/// The trusted outcome of consuming a Response. All strings are owned by an
/// internal arena — free the whole thing with `deinit`. Nothing here borrows
/// from the input bytes.
pub const AuthnResult = struct {
    arena: std.heap.ArenaAllocator,

    /// The authenticated subject identifier (`<NameID>` text).
    name_id: []const u8,
    /// `<NameID Format>` if present.
    name_id_format: ?[]const u8,
    /// `<NameID SPNameQualifier>` if present.
    name_id_sp_qualifier: ?[]const u8,
    /// `<AuthnStatement SessionIndex>` if present (for Single-Logout / session).
    session_index: ?[]const u8,
    /// `<AuthnContextClassRef>` text if present.
    authn_context_class_ref: ?[]const u8,
    /// Attributes in document order.
    attributes: []const Attribute,

    /// The assertion's `<Conditions NotOnOrAfter>` as Unix seconds, if present —
    /// a sensible upper bound for the local session lifetime.
    session_not_on_or_after: ?i64,
    /// `<Conditions><OneTimeUse>` was present — the caller SHOULD enforce
    /// single use (e.g. cache the assertion ID until expiry).
    one_time_use: bool,
    /// The assertion's `ID` (for OneTimeUse replay caches / audit).
    assertion_id: []const u8,

    /// Raw DER of the `<KeyInfo><X509Certificate>` seen on the verifying
    /// signature, if any. **UNTRUSTED** — present only for pinning. Owned.
    x509_cert_der: ?[]const u8,

    pub fn deinit(self: *AuthnResult) void {
        self.arena.deinit();
        self.* = undefined;
    }

    /// Convenience: the values of the first attribute named `name`, or null.
    pub fn attribute(self: *const AuthnResult, name: []const u8) ?[]const []const u8 {
        for (self.attributes) |a| {
            if (std.mem.eql(u8, a.name, name)) return a.values;
        }
        return null;
    }
};

// ── errors ───────────────────────────────────────────────────────────────────

pub const DecodeError = error{
    /// Not valid base64 (POST binding) or the inflate stream was malformed /
    /// exceeded the decompression cap (Redirect binding).
    InvalidEncoding,
} || std.mem.Allocator.Error;

pub const ConsumeError = error{
    /// base64 / inflate decoding of the SAMLResponse field failed.
    InvalidEncoding,
    /// The XML was not well-formed, violated a hardening bound, or was otherwise
    /// unparseable (XXE / entity bombs surface here — nothing was fetched).
    MalformedResponse,
    /// The document root is not `{samlp}Response`.
    NotSamlResponse,
    /// `<samlp:Status>` was not `…:status:Success`.
    StatusNotSuccess,
    /// `<Issuer>` did not equal `Config.idp_entity_id`.
    IssuerMismatch,
    /// `<Response Destination>` was present and did not equal `Config.acs_url`.
    DestinationMismatch,
    /// No `<Assertion>` (and no EncryptedAssertion) — nothing to consume.
    NoAssertion,
    /// More than one `<Assertion>` — refused (XSW hardening: exactly one).
    MultipleAssertions,
    /// A `<saml:EncryptedAssertion>` was present but no `Config.sp_decrypt_key`
    /// was configured — the SP did not opt in to decryption, so it cannot be
    /// consumed. (With a key configured it is decrypted transparently.)
    EncryptedAssertionUnsupported,
    /// A `<saml:EncryptedAssertion>` could not be decrypted: wrong SP key, an
    /// unsupported/disallowed algorithm, malformed ciphertext, or a GCM/CBC/RSA
    /// failure. Deliberately GENERIC (mirrors `xmlenc`'s oracle-safe error
    /// collapse); the safe composition is decrypt-then-signature-verify.
    AssertionDecryptionFailed,
    /// No valid signature covers the consumed assertion.
    SignatureMissing,
    /// A signature was present but did not cryptographically verify against the
    /// configured key (bad signature, bad digest, disallowed algorithm, …).
    SignatureInvalid,
    /// A valid signature was found, but it covers an element OTHER than the
    /// assertion (or Response) being consumed — a signature-wrapping attempt.
    SignatureWrappingDetected,
    /// `now` is at/after the assertion's `Conditions NotOnOrAfter` (+skew).
    AssertionExpired,
    /// `now` is before the assertion's `Conditions NotBefore` (−skew).
    AssertionNotYetValid,
    /// `Config.sp_entity_id` is not in an `<AudienceRestriction>` (or none
    /// present — fail closed).
    AudienceMismatch,
    /// The assertion has no `<Subject>`/`<NameID>` to authenticate.
    SubjectMissing,
    /// No acceptable `<SubjectConfirmation>` (see the more specific Recipient /
    /// InResponseTo / expiry / HoK errors first).
    SubjectConfirmationFailed,
    /// The only `<SubjectConfirmation>` methods present are not permitted by
    /// `Config.subject_confirmation` (e.g. a Holder-of-Key confirmation under the
    /// default `.bearer` policy, or a Bearer confirmation under `.holder_of_key`).
    SubjectConfirmationMethodNotAllowed,
    /// A Holder-of-Key `<SubjectConfirmation>` is being validated but neither
    /// `Config.presented_holder_cert_der` nor `Config.presented_holder_key` is
    /// configured — the SP cannot prove the presenter holds the key.
    PresentedKeyMissing,
    /// A Holder-of-Key `<SubjectConfirmation>`'s `<ds:KeyInfo>` named key
    /// material that WAS compared — same-form or cross-form — against what the
    /// caller supplied, and none of it was the presenter's key. This is the
    /// real "you do not hold this key" verdict.
    HolderOfKeyMismatch,
    /// A Holder-of-Key `<SubjectConfirmation>` named key material, but NONE of
    /// it could be reduced to a public key to compare at all, so nothing was
    /// proved either way and the confirmation fails closed. Reached when a
    /// cross-form pairing is the only one available and the certificate in
    /// question is malformed DER, or carries a public-key algorithm outside
    /// RSA and EC P-256 (the two forms `PresentedKey` can express). Same-form
    /// pairings never produce this. See SPEC.md.
    HolderOfKeyCrossFormUnsupported,
    /// A `<saml:EncryptedID>` was present in the Subject but no
    /// `Config.sp_decrypt_key` was configured — the SP did not opt in to
    /// decryption. (With a key configured it is decrypted transparently.)
    EncryptedIdUnsupported,
    /// A `<saml:EncryptedAttribute>` was present but no `Config.sp_decrypt_key`
    /// was configured — opt-in decryption is required to consume it.
    EncryptedAttributeUnsupported,
    /// A `<saml:EncryptedID>` could not be decrypted or did not recover a
    /// `<saml:NameID>`. GENERIC (mirrors `AssertionDecryptionFailed`): every
    /// crypto/structure failure collapses here, so no oracle signal leaks. Safe
    /// because the enclosing assertion is already signature-verified.
    IdDecryptionFailed,
    /// A `<saml:EncryptedAttribute>` could not be decrypted or did not recover a
    /// `<saml:Attribute>`. GENERIC, same rationale as `IdDecryptionFailed`.
    AttributeDecryptionFailed,
    /// Bearer `Recipient` did not equal `Config.acs_url`.
    RecipientMismatch,
    /// Bearer `InResponseTo` did not match `Config.expected_in_response_to`
    /// (or was absent while `allow_idp_initiated` is false, or present while no
    /// request was pending).
    InResponseToMismatch,
    /// An xsd:dateTime attribute could not be parsed.
    InvalidDateTime,
    /// `Config.required_loa` was set but the assertion's
    /// `<AuthnContextClassRef>` was absent or below the required Level of
    /// Assurance (eIDAS ordering low < substantial < high; exact match for any
    /// non-eIDAS class ref).
    LevelOfAssuranceInsufficient,
} || std.mem.Allocator.Error;

// ── decoding helpers ─────────────────────────────────────────────────────────

/// Decode a POST-binding `SAMLResponse` field: standard base64 (tolerating the
/// ASCII whitespace HTML forms sometimes inject). Caller owns the result.
pub fn decodePostField(alloc: std.mem.Allocator, field: []const u8) DecodeError![]u8 {
    return decodeBase64(alloc, field) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidEncoding,
    };
}

/// Decode a Redirect-binding `SAMLResponse` field: base64 then raw DEFLATE
/// (RFC 1951, no zlib header — the SAML DEFLATE encoding). The caller has
/// already performed URL-decoding. Output is capped at `max_redirect_inflated`.
pub fn decodeRedirectField(alloc: std.mem.Allocator, field: []const u8) DecodeError![]u8 {
    const deflated = try decodePostField(alloc, field);
    defer alloc.free(deflated);
    var in = std.Io.Reader.fixed(deflated);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var dc = std.compress.flate.Decompress.init(&in, .raw, &window);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    dc.reader.appendRemaining(alloc, &out, .limited(max_redirect_inflated)) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidEncoding,
    };
    return out.toOwnedSlice(alloc);
}

// ── entry points ─────────────────────────────────────────────────────────────

/// Consume a POST-binding SAMLResponse form field (base64). Decodes, parses and
/// fully validates it, returning the trusted `AuthnResult` or a typed error.
pub fn consumeResponse(alloc: std.mem.Allocator, saml_response_field: []const u8, config: Config) ConsumeError!AuthnResult {
    const xml_bytes = decodePostField(alloc, saml_response_field) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidEncoding,
    };
    defer alloc.free(xml_bytes);
    return consumeResponseXml(alloc, xml_bytes, config);
}

/// Consume an already-base64-decoded `<samlp:Response>` XML document.
pub fn consumeResponseXml(alloc: std.mem.Allocator, xml_bytes: []const u8, config: Config) ConsumeError!AuthnResult {
    var doc = xml.parse(alloc, xml_bytes, .{
        .id_attr_names = &.{"ID"},
    }) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedResponse,
    };
    defer doc.deinit();
    return processResponse(alloc, &doc, config);
}

// ── core processing ──────────────────────────────────────────────────────────

fn processResponse(alloc: std.mem.Allocator, doc: *const xml.Document, config: Config) ConsumeError!AuthnResult {
    const root = doc.root;
    if (!isEl(root, samlp_ns, "Response")) return error.NotSamlResponse;

    // Status must be Success.
    const status = childEl(root, samlp_ns, "Status") orelse return error.MalformedResponse;
    const status_code = childEl(status, samlp_ns, "StatusCode") orelse return error.MalformedResponse;
    const code = status_code.attr("", "Value") orelse return error.MalformedResponse;
    if (!std.mem.eql(u8, code, status_success)) return error.StatusNotSuccess;

    // Response Issuer (optional element; when present it MUST match).
    if (childEl(root, saml_ns, "Issuer")) |iss| {
        const t = try textAlloc(alloc, iss);
        defer alloc.free(t);
        if (!std.mem.eql(u8, trim(t), config.idp_entity_id)) return error.IssuerMismatch;
    }

    // Response Destination (optional attribute; when present it MUST match ACS).
    if (root.attr("", "Destination")) |dest| {
        if (!std.mem.eql(u8, dest, config.acs_url)) return error.DestinationMismatch;
    }

    // Locate the single assertion, cleartext or encrypted, as a DIRECT child of
    // Response (XSW hardening: the exactly-one discipline spans BOTH kinds — a
    // cleartext + an encrypted assertion, or two encrypted ones, are refused).
    var assertion: ?*const xml.Element = null;
    var enc_assertion: ?*const xml.Element = null;
    var count: usize = 0;
    for (root.children) |c| switch (c.content) {
        .element => |el| {
            if (isEl(el, saml_ns, "Assertion")) {
                count += 1;
                assertion = el;
            } else if (isEl(el, saml_ns, "EncryptedAssertion")) {
                count += 1;
                enc_assertion = el;
            }
        },
        else => {},
    };
    if (count == 0) return error.NoAssertion;
    if (count > 1) return error.MultipleAssertions;

    // The encrypted profile: decrypt, then run the recovered assertion through
    // the identical verify + validate path (decrypt-then-verify).
    if (enc_assertion) |enc| return processEncryptedAssertion(alloc, doc, root, enc, config);

    const asrt = assertion.?;

    // ── signature + XSW defense ──────────────────────────────────────────────
    var cert_der: ?[]u8 = null;
    errdefer if (cert_der) |d| alloc.free(d);
    const signed = try verifyCovering(alloc, doc, root, asrt, config, &cert_der);
    if (!signed) return error.SignatureMissing;

    // ── the assertion is now trusted: validate + extract ─────────────────────
    return buildResult(alloc, asrt, config, &cert_der);
}

/// Try to establish that `asrt` is covered by a signature valid under the
/// configured key, honoring `Config.signature_policy`. On the first valid,
/// correctly-pinned signature this returns true (and moves any KeyInfo cert into
/// `cert_out`). A structurally-present-but-invalid signature, or a valid one
/// that points elsewhere, is a hard error (never a silent downgrade to unsigned).
fn verifyCovering(
    alloc: std.mem.Allocator,
    doc: *const xml.Document,
    root: *const xml.Element,
    asrt: *const xml.Element,
    config: Config,
    cert_out: *?[]u8,
) ConsumeError!bool {
    const opts = sigOpts(config);

    // 1. A signature that is a direct child of the Assertion (assertion-signed).
    if (config.signature_policy != .response) {
        if (childEl(asrt, xmldsig.ds_ns, "Signature")) |sig| {
            var res = xmldsig.verify(alloc, doc, sig, opts) catch return error.SignatureInvalid;
            defer res.deinit(alloc);
            if (!res.valid) return error.SignatureInvalid;
            if (!signedTargetMatches(doc, &res, asrt, config.id_attr)) return error.SignatureWrappingDetected;
            moveCert(alloc, &res, cert_out);
            return true;
        }
    }

    // 2. A signature that is a direct child of the Response (response-signed).
    //    It must cover the Response element that directly contains our assertion.
    if (config.signature_policy != .assertion) {
        if (childEl(root, xmldsig.ds_ns, "Signature")) |sig| {
            var res = xmldsig.verify(alloc, doc, sig, opts) catch return error.SignatureInvalid;
            defer res.deinit(alloc);
            if (!res.valid) return error.SignatureInvalid;
            if (!signedTargetMatches(doc, &res, root, config.id_attr)) return error.SignatureWrappingDetected;
            if (asrt.parent != root) return error.SignatureWrappingDetected;
            moveCert(alloc, &res, cert_out);
            return true;
        }
    }

    return false;
}

fn sigOpts(config: Config) xmldsig.Options {
    return .{
        .key = config.idp_key,
        .allow_weak_sha1 = config.allow_weak_sha1,
        .id_attr = config.id_attr,
    };
}

/// The eIDAS encrypt profile. `enc` is the `<saml:EncryptedAssertion>` (a direct
/// child of `outer_root`, already confirmed the *only* assertion). We decrypt it
/// with the SP's key, re-parse the plaintext into its OWN standalone document,
/// then run the recovered assertion through the same signature-verify + XSW +
/// validation path a cleartext assertion uses. Decrypt happens BEFORE verify:
/// the IdP signs the assertion prior to encryption, so a manipulated ciphertext
/// yields a plaintext that fails the signature check (padding-oracle safe).
fn processEncryptedAssertion(
    alloc: std.mem.Allocator,
    outer_doc: *const xml.Document,
    outer_root: *const xml.Element,
    enc: *const xml.Element,
    config: Config,
) ConsumeError!AuthnResult {
    // No key configured ⇒ the SP did not opt in: preserve the old refusal.
    const sk = config.sp_decrypt_key orelse return error.EncryptedAssertionUnsupported;

    const plaintext = xmlenc.decryptAssertion(alloc, enc, sk, .{
        .allow_weak_rsa15 = config.allow_weak_rsa15,
        .kek = config.decrypt_kek,
    }) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        // Everything else (DecryptionError, UnsupportedAlgorithm,
        // MalformedStructure, WeakRsa15NotAllowed, CipherReferenceUnsupported,
        // KekNotProvided, CiphertextTooLarge) collapses to one generic error —
        // no oracle signal, mirroring xmlenc's own posture.
        else => return error.AssertionDecryptionFailed,
    };
    defer alloc.free(plaintext);

    // Parse the recovered octets with the SAME id-attribute options `saml` uses
    // for the Response, so the XSW pointer-pin (which resolves the signature's
    // #id Reference through the SAML `ID` index) is sound inside the inner doc.
    var inner = xml.parse(alloc, plaintext, .{
        .id_attr_names = &.{"ID"},
    }) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedResponse,
    };
    defer inner.deinit();

    const asrt = inner.root;
    if (!isEl(asrt, saml_ns, "Assertion")) return error.NoAssertion;

    // ── signature + XSW defense on the DECRYPTED assertion ────────────────────
    var cert_der: ?[]u8 = null;
    errdefer if (cert_der) |d| alloc.free(d);
    const signed = try verifyCoveringDecrypted(alloc, &inner, outer_doc, outer_root, enc, config, &cert_der);
    if (!signed) return error.SignatureMissing;

    // buildResult dupes everything it keeps into its OWN arena (backed by
    // `alloc`), so the returned AuthnResult never borrows from `inner`, which we
    // deinit on return.
    return buildResult(alloc, asrt, config, &cert_der);
}

/// Establish that the decrypted assertion is covered by a valid signature,
/// honoring `signature_policy`. The decrypted assertion is the ROOT of its own
/// standalone `inner_doc` (NOT a direct child of the Response), so:
///   - `.assertion` / `.either`: the assertion-level signature lives inside the
///     decrypted assertion; it is pinned by pointer identity to `inner_doc.root`
///     within that inner document — the "assertion must be a direct child of
///     Response" structural rule does not (and cannot) apply here.
///   - `.response`: the enclosing (outer) Response may itself be signed over the
///     `<EncryptedAssertion>` ciphertext; that signature is verified against the
///     OUTER document and pinned to the outer Response, plus `enc` must be a
///     direct child of it. This does NOT weaken the wrapping defense — each
///     branch resolves its single `#id` Reference to a pointer it controls.
fn verifyCoveringDecrypted(
    alloc: std.mem.Allocator,
    inner_doc: *const xml.Document,
    outer_doc: *const xml.Document,
    outer_root: *const xml.Element,
    enc: *const xml.Element,
    config: Config,
    cert_out: *?[]u8,
) ConsumeError!bool {
    const opts = sigOpts(config);
    const inner_root = inner_doc.root;

    // 1. Assertion-level signature, INSIDE the decrypted assertion.
    if (config.signature_policy != .response) {
        if (childEl(inner_root, xmldsig.ds_ns, "Signature")) |sig| {
            var res = xmldsig.verify(alloc, inner_doc, sig, opts) catch return error.SignatureInvalid;
            defer res.deinit(alloc);
            if (!res.valid) return error.SignatureInvalid;
            if (!signedTargetMatches(inner_doc, &res, inner_root, config.id_attr)) return error.SignatureWrappingDetected;
            moveCert(alloc, &res, cert_out);
            return true;
        }
    }

    // 2. Response-level signature, in the OUTER document, over the Response that
    //    directly contains the EncryptedAssertion ciphertext.
    if (config.signature_policy != .assertion) {
        if (childEl(outer_root, xmldsig.ds_ns, "Signature")) |sig| {
            var res = xmldsig.verify(alloc, outer_doc, sig, opts) catch return error.SignatureInvalid;
            defer res.deinit(alloc);
            if (!res.valid) return error.SignatureInvalid;
            if (!signedTargetMatches(outer_doc, &res, outer_root, config.id_attr)) return error.SignatureWrappingDetected;
            if (enc.parent != outer_root) return error.SignatureWrappingDetected;
            moveCert(alloc, &res, cert_out);
            return true;
        }
    }

    return false;
}

fn moveCert(alloc: std.mem.Allocator, res: *xmldsig.Result, cert_out: *?[]u8) void {
    if (res.x509_cert_der) |d| {
        // Take ownership away from res (whose deinit would otherwise free it).
        cert_out.* = d;
        res.x509_cert_der = null;
    }
    _ = alloc;
}

/// A decrypted-and-parsed wrapper element. `xml.parse` BORROWS its element/attr
/// slices from the source octets, so the plaintext buffer must live exactly as
/// long as `doc`; this struct owns both and frees them together.
const Decrypted = struct {
    doc: xml.Document,
    src: []u8,
    fn deinit(self: *Decrypted, alloc: std.mem.Allocator) void {
        self.doc.deinit();
        alloc.free(self.src);
        self.* = undefined;
    }
};

/// Decrypt a `<saml:EncryptedID>` / `<saml:EncryptedAttribute>` wrapper (each
/// carries a single `<xenc:EncryptedData>` exactly like `<EncryptedAssertion>`)
/// and re-parse the recovered octets into their own standalone document (caller
/// `deinit`s the returned `Decrypted`). `config.sp_decrypt_key` MUST be non-null
/// (the caller checks and raises the wrapper-specific `…Unsupported` error
/// otherwise). Every crypto/structure failure collapses to `fail_err` — a single
/// generic outcome, no oracle signal (`xmlenc`'s own posture). This runs ONLY on
/// the already-signature-verified assertion, so the ciphertext is authenticated
/// by enclosure before the private key ever touches it.
fn decryptWrappedElement(
    alloc: std.mem.Allocator,
    wrapper: *const xml.Element,
    config: Config,
    fail_err: ConsumeError,
) ConsumeError!Decrypted {
    const sk = config.sp_decrypt_key orelse return error.EncryptedIdUnsupported; // unreachable in practice
    const ed = childEl(wrapper, xmlenc.xenc_ns, "EncryptedData") orelse return fail_err;
    const plaintext = xmlenc.decryptData(alloc, ed, sk, .{
        .allow_weak_rsa15 = config.allow_weak_rsa15,
        .kek = config.decrypt_kek,
    }) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return fail_err,
    };
    errdefer alloc.free(plaintext);
    const doc = xml.parse(alloc, plaintext, .{ .id_attr_names = &.{"ID"} }) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return fail_err,
    };
    return .{ .doc = doc, .src = plaintext };
}

/// The XSW pointer-pin. A verified signature covers `target` iff it has exactly
/// one same-document `#id` Reference whose id resolves (through the SAML ID
/// index) to `target` by pointer identity. Empty / external / multi-reference
/// signatures fail closed.
fn signedTargetMatches(doc: *const xml.Document, res: *const xmldsig.Result, target: *const xml.Element, id_attr: []const u8) bool {
    if (res.references.len != 1) return false;
    const uri = res.references[0].uri;
    if (uri.len == 0 or uri[0] != '#') return false;
    const id = uri[1..];
    if (id.len == 0) return false;
    const resolved = doc.findByAttr("", id_attr, id) orelse return false;
    return resolved == target;
}

/// Validate conditions + subject confirmation on the trusted assertion, then
/// extract everything into an owned `AuthnResult`.
fn buildResult(alloc: std.mem.Allocator, asrt: *const xml.Element, config: Config, cert_in: *?[]u8) ConsumeError!AuthnResult {
    const now = config.now_unix;
    const skew = config.clock_skew_secs;

    var one_time_use = false;
    var session_noa: ?i64 = null;

    // ── Conditions ───────────────────────────────────────────────────────────
    var audience_ok = false;
    if (childEl(asrt, saml_ns, "Conditions")) |cond| {
        if (cond.attr("", "NotBefore")) |nb| {
            const t = try parseDateTime(nb);
            if (now + skew < t) return error.AssertionNotYetValid;
        }
        if (cond.attr("", "NotOnOrAfter")) |noa| {
            const t = try parseDateTime(noa);
            if (now - skew >= t) return error.AssertionExpired;
            session_noa = t;
        }
        one_time_use = childEl(cond, saml_ns, "OneTimeUse") != null;

        // Multiple <AudienceRestriction> are ANDed; SP must be in EVERY one.
        var saw_restriction = false;
        for (cond.children) |c| switch (c.content) {
            .element => |el| if (isEl(el, saml_ns, "AudienceRestriction")) {
                saw_restriction = true;
                if (!audienceContains(el, config.sp_entity_id, alloc)) return error.AudienceMismatch;
            },
            else => {},
        };
        audience_ok = saw_restriction;
    }
    if (!audience_ok) return error.AudienceMismatch; // fail closed: require the SP be named

    // ── Subject + SubjectConfirmation ────────────────────────────────────────
    const subject = childEl(asrt, saml_ns, "Subject") orelse return error.SubjectMissing;

    // The NameID may be cleartext (`<saml:NameID>`) or, in the eIDAS encrypt
    // profile, a `<saml:EncryptedID>` wrapping a `<xenc:EncryptedData>`. Decrypt
    // the latter (opt-in) into its own standalone document, which must outlive
    // extraction below — a function-scoped defer frees it. The enclosing
    // assertion is already signature-verified, so this ciphertext is
    // authenticated by enclosure.
    var enc_id_dec: ?Decrypted = null;
    defer if (enc_id_dec) |*d| d.deinit(alloc);
    const name_id = nid: {
        if (childEl(subject, saml_ns, "NameID")) |nid| break :nid nid;
        if (childEl(subject, saml_ns, "EncryptedID")) |enc_id| {
            if (config.sp_decrypt_key == null) return error.EncryptedIdUnsupported;
            var dec = try decryptWrappedElement(alloc, enc_id, config, error.IdDecryptionFailed);
            if (!isEl(dec.doc.root, saml_ns, "NameID")) {
                dec.deinit(alloc);
                return error.IdDecryptionFailed;
            }
            enc_id_dec = dec;
            break :nid enc_id_dec.?.doc.root;
        }
        return error.SubjectMissing;
    };

    try validateSubjectConfirmation(alloc, subject, config, now, skew);

    // ── extraction (into the result arena) ───────────────────────────────────
    var arena = std.heap.ArenaAllocator.init(alloc);
    errdefer arena.deinit();
    const a = arena.allocator();

    const nid_text = try dupTrimmedText(a, name_id);
    const nid_format = try dupAttr(a, name_id, "Format");
    const nid_spq = try dupAttr(a, name_id, "SPNameQualifier");
    const asrt_id = if (asrt.attr("", config.id_attr)) |v| try a.dupe(u8, v) else "";

    var session_index: ?[]const u8 = null;
    var acr: ?[]const u8 = null;
    if (childEl(asrt, saml_ns, "AuthnStatement")) |authn| {
        session_index = try dupAttr(a, authn, "SessionIndex");
        if (childEl(authn, saml_ns, "AuthnContext")) |actx| {
            if (childEl(actx, saml_ns, "AuthnContextClassRef")) |cref| {
                acr = try dupTrimmedText(a, cref);
            }
        }
    }

    // eIDAS Level-of-Assurance minimum (opt-in): the returned class ref must meet
    // `required_loa`. Absent LoA never meets a requirement.
    if (config.required_loa) |req| {
        if (!loaMeets(req, acr)) return error.LevelOfAssuranceInsufficient;
    }

    const attrs = try extractAttributes(a, alloc, asrt, config);

    // Move the (owned, caller-alloc) cert DER into the arena and release it.
    var cert_der_owned: ?[]const u8 = null;
    if (cert_in.*) |d| {
        cert_der_owned = try a.dupe(u8, d);
        alloc.free(d);
        cert_in.* = null;
    }

    return .{
        .arena = arena,
        .name_id = nid_text,
        .name_id_format = nid_format,
        .name_id_sp_qualifier = nid_spq,
        .session_index = session_index,
        .authn_context_class_ref = acr,
        .attributes = attrs,
        .session_not_on_or_after = session_noa,
        .one_time_use = one_time_use,
        .assertion_id = asrt_id,
        .x509_cert_der = cert_der_owned,
    };
}

/// Confirm the subject via one acceptable `<SubjectConfirmation>`, honoring
/// `Config.subject_confirmation`. Returns on the FIRST fully-valid confirmation
/// of a permitted method; otherwise the first recorded rejection reason (each
/// method's own validator picks the most specific one). A method disallowed by
/// policy is remembered as `SubjectConfirmationMethodNotAllowed` but never masks
/// a more specific failure of a permitted method.
fn validateSubjectConfirmation(alloc: std.mem.Allocator, subject: *const xml.Element, config: Config, now: i64, skew: i64) ConsumeError!void {
    const policy = config.subject_confirmation;
    var best_err: ?ConsumeError = null;
    for (subject.children) |c| switch (c.content) {
        .element => |sc| {
            if (!isEl(sc, saml_ns, "SubjectConfirmation")) continue;
            const method = sc.attr("", "Method") orelse continue;
            if (std.mem.eql(u8, method, cm_bearer)) {
                if (policy != .bearer and policy != .either) {
                    best_err = best_err orelse error.SubjectConfirmationMethodNotAllowed;
                    continue;
                }
                validateBearerData(sc, config, now, skew) catch |e| {
                    best_err = best_err orelse e;
                    continue;
                };
                return; // a fully-valid Bearer confirmation
            } else if (std.mem.eql(u8, method, cm_holder_of_key)) {
                if (policy != .holder_of_key and policy != .either) {
                    best_err = best_err orelse error.SubjectConfirmationMethodNotAllowed;
                    continue;
                }
                validateHolderOfKeyData(alloc, sc, config, now, skew) catch |e| {
                    best_err = best_err orelse e;
                    continue;
                };
                return; // a fully-valid Holder-of-Key confirmation
            } else if (std.mem.eql(u8, method, cm_sender_vouches)) {
                if (policy != .sender_vouches and policy != .either) {
                    best_err = best_err orelse error.SubjectConfirmationMethodNotAllowed;
                    continue;
                }
                // Sender-vouches imposes NO key/recipient binding on the subject:
                // the assertion's trust derives entirely from its already-verified
                // signature (the attesting authority == the configured `idp_key`)
                // plus the assertion `<Conditions>` (NotBefore/NotOnOrAfter/
                // Audience), both enforced before this point. The Bearer
                // Recipient/InResponseTo and the HoK key check are therefore NOT
                // applied. The caller MUST ensure `idp_key` is the trusted
                // attesting authority (see SPEC.md "Sender-vouches").
                return; // a permitted sender-vouches confirmation
            }
            // Unknown / unsupported method: skip.
        },
        else => {},
    };
    return best_err orelse error.SubjectConfirmationFailed;
}

/// Validate a single Bearer `<SubjectConfirmationData>` (Web-SSO default):
/// `Recipient` == ACS, `NotOnOrAfter` present and in the future, `InResponseTo`
/// correlates (or absent only when `allow_idp_initiated`). Returns the most
/// specific rejection; void on success.
fn validateBearerData(sc: *const xml.Element, config: Config, now: i64, skew: i64) ConsumeError!void {
    const scd = childEl(sc, saml_ns, "SubjectConfirmationData") orelse return error.SubjectConfirmationFailed;
    // Recipient must equal the ACS URL.
    const recip = scd.attr("", "Recipient") orelse return error.RecipientMismatch;
    if (!std.mem.eql(u8, recip, config.acs_url)) return error.RecipientMismatch;
    // NotOnOrAfter is required for a Bearer confirmation.
    const noa = scd.attr("", "NotOnOrAfter") orelse return error.SubjectConfirmationFailed;
    const t = try parseDateTime(noa);
    if (now - skew >= t) return error.AssertionExpired;
    // InResponseTo correlation.
    if (scd.attr("", "InResponseTo")) |irt| {
        const expected = config.expected_in_response_to orelse return error.InResponseToMismatch;
        if (!std.mem.eql(u8, irt, expected)) return error.InResponseToMismatch;
    } else if (!config.allow_idp_initiated) {
        return error.InResponseToMismatch;
    }
}

/// Validate a single Holder-of-Key `<SubjectConfirmationData>` (SAML V2.0 HoK
/// Web-SSO profile). The HoK KEY check replaces the Bearer `Recipient` check:
/// the presenter must actually hold the key named in `<ds:KeyInfo>`, which the
/// caller proves by supplying `presented_holder_cert_der` (the transport client
/// certificate). `Recipient` / `InResponseTo` MAY be omitted for HoK; when
/// present they are still honored. `NotBefore` / `NotOnOrAfter`, when present,
/// are enforced.
///
/// SAME-FORM matches (no DER parsing at all):
///   - `<ds:X509Certificate>` DER byte-equality vs `presented_holder_cert_der`;
///   - `<ds:KeyValue><ds:RSAKeyValue>` modulus+exponent integer-equality vs a
///     `presented_holder_key` `.rsa`;
///   - `<ds:KeyValue><ds:ECKeyValue>` NamedCurve(P-256)+point byte-equality vs a
///     `presented_holder_key` `.ec_sec1`.
///
/// CROSS-FORM matches (the confirmation names the key in the other form from
/// the one the caller supplied): the certificate's `SubjectPublicKeyInfo` is
/// extracted with `x509.spkiOf` — a defensive raw-DER walk that never touches
/// `std.crypto.Certificate.parse`, the Zig 0.16 panic hazard — reduced to a
/// canonical public key, and compared with the *other* side's key by
/// PARAMETERS, never by encoding: RSA by big-endian modulus+exponent integers,
/// P-256 by the affine point recovered through `fromSec1` (which also proves
/// the point is on the curve). Two encodings of one key therefore compare
/// equal, and two different keys cannot compare equal regardless of encoding.
///
/// Order: same-form first (cheapest, and unchanged for existing callers), then
/// cross-form. ANY match confirms — the confirmation may legitimately name the
/// same key several ways. Everything that cannot be reduced to a comparable
/// key fails closed. See SPEC.md.
fn validateHolderOfKeyData(alloc: std.mem.Allocator, sc: *const xml.Element, config: Config, now: i64, skew: i64) ConsumeError!void {
    const scd = childEl(sc, saml_ns, "SubjectConfirmationData") orelse return error.SubjectConfirmationFailed;
    // NotBefore / NotOnOrAfter are optional for HoK; enforce them if present.
    if (scd.attr("", "NotBefore")) |nb| {
        const t = try parseDateTime(nb);
        if (now + skew < t) return error.AssertionNotYetValid;
    }
    if (scd.attr("", "NotOnOrAfter")) |noa| {
        const t = try parseDateTime(noa);
        if (now - skew >= t) return error.AssertionExpired;
    }
    // Recipient is optional for HoK; when present it must still match the ACS.
    if (scd.attr("", "Recipient")) |recip| {
        if (!std.mem.eql(u8, recip, config.acs_url)) return error.RecipientMismatch;
    }
    // InResponseTo is optional for HoK; when present and a request is pending it
    // must correlate.
    if (scd.attr("", "InResponseTo")) |irt| {
        if (config.expected_in_response_to) |expected| {
            if (!std.mem.eql(u8, irt, expected)) return error.InResponseToMismatch;
        }
    }
    // The HoK key check: the presenter must hold the confirmation key. The
    // confirmation may name it as an `<X509Certificate>` and/or as a bare
    // `<ds:KeyValue>`; the caller may have supplied either form (or both).
    // All four pairings are tried — see this function's doc comment.
    const have_cert = config.presented_holder_cert_der != null;
    const have_key = config.presented_holder_key != null;
    if (!have_cert and !have_key) return error.PresentedKeyMissing;

    // `decided` = at least one comparison ran all the way to a verdict, so a
    // failure really means "the presenter does not hold this key".
    // `incomparable` = key material was named but could not be reduced to a
    // key at all (malformed DER, an unsupported algorithm/curve) — a rejection
    // either way, but a distinguishable one for the operator.
    var decided = false;
    var incomparable = false;

    // X.509 same-form: presented cert DER vs an `<X509Certificate>`.
    if (config.presented_holder_cert_der) |cert_der| {
        if (anyX509Present(scd)) {
            decided = true;
            if (anyX509Matches(alloc, scd, cert_der)) return; // confirmed
        }
    }
    // KeyValue same-form: presented public key vs an `<RSAKeyValue>`/`<ECKeyValue>`.
    if (config.presented_holder_key) |pk| {
        if (anyKeyValuePresent(scd)) {
            decided = true;
            if (anyKeyValueMatches(alloc, scd, pk)) return; // confirmed
        }
    }
    // Cross-form: an `<X509Certificate>` in the confirmation vs the caller's
    // bare presented key.
    if (config.presented_holder_key) |pk| {
        if (anyX509Present(scd)) switch (anyX509MatchesKey(alloc, scd, pk)) {
            .match => return, // confirmed
            .mismatch => decided = true,
            .incomparable => incomparable = true,
        };
    }
    // Cross-form: a bare `<ds:KeyValue>` in the confirmation vs the caller's
    // presented certificate.
    if (config.presented_holder_cert_der) |cert_der| {
        if (anyKeyValuePresent(scd)) switch (anyKeyValueMatchesCert(alloc, scd, cert_der)) {
            .match => return, // confirmed
            .mismatch => decided = true,
            .incomparable => incomparable = true,
        };
    }

    // A comparison ran and nothing matched: the presenter does not hold the key.
    if (decided) return error.HolderOfKeyMismatch;
    // Nothing could be compared, because nothing could be reduced to a key.
    if (incomparable) return error.HolderOfKeyCrossFormUnsupported;
    // The confirmation carried no recognizable key material at all.
    return error.HolderOfKeyMismatch;
}

// ── Holder-of-Key cross-form matching (certificate ↔ `<ds:KeyValue>`) ────────

/// The verdict of one cross-form comparison. `.incomparable` is NOT a match and
/// NOT a mismatch: the key material was present but could not be reduced to a
/// public key at all, so nothing was actually proved either way. It never
/// confirms a subject.
const CrossMatch = enum { match, mismatch, incomparable };

/// A public key recovered from a certificate's `SubjectPublicKeyInfo`, reduced
/// to a canonical form — the whole point of the cross-form path is to compare
/// key PARAMETERS, so neither variant stores anything encoding-specific.
const CertKey = union(enum) {
    /// Compared by big-endian modulus + exponent integer equality (the same
    /// comparison the same-form `<RSAKeyValue>` path uses).
    rsa: rsa.PublicKey,
    /// The P-256 point in its canonical uncompressed SEC1 form. `fromSec1`
    /// already proved it is a point on the curve, so equality of these 65 bytes
    /// is equality of the affine (x, y) coordinates — key identity, not
    /// encoding identity. A compressed and an uncompressed encoding of one key
    /// both reduce to this, and two distinct keys cannot reduce to the same
    /// value.
    ec_p256: [65]u8,
};

/// Recover the public key named by a certificate, or `null` when it cannot be
/// reduced to one this module can compare (malformed/hostile DER, or an
/// algorithm outside RSA and EC P-256).
///
/// `x509.spkiOf` is a defensive raw-DER walk: it validates the whole TLV
/// structure first and never routes the bytes through
/// `std.crypto.Certificate.parse`, which is not panic-safe on adversarial DER
/// in Zig 0.16. `rsa.PublicKey.fromDer` and `fromSec1` are both total on
/// arbitrary bytes. So this is safe on a certificate lifted straight out of an
/// attacker-supplied assertion.
fn certPublicKey(cert_der: []const u8) ?CertKey {
    const spki = x509.spkiOf(cert_der) catch return null;
    if (spki.algorithmIs(&x509.safe.oid_rsa_encryption)) {
        return .{ .rsa = rsa.PublicKey.fromDer(spki.der) catch return null };
    }
    if (spki.algorithmIs(&x509.safe.oid_ec_public_key)) {
        // RFC 5480 §2.1.1: the parameters must name the curve. An absent /
        // implicit / explicitly-specified curve is not comparable — fail closed
        // rather than assume P-256.
        const curve_oid = spki.namedCurveOid() orelse return null;
        if (!std.mem.eql(u8, curve_oid, &x509.safe.oid_prime256v1)) return null;
        const pk = P256PublicKey.fromSec1(spki.key_bits) catch return null;
        return .{ .ec_p256 = pk.toUncompressedSec1() };
    }
    return null;
}

/// Whether two `rsa.PublicKey`s are the same key: big-endian modulus and
/// exponent integers, leading-zero-insensitive. Never a signature op, and
/// never a comparison of encodings.
fn rsaPublicKeysEqual(a: rsa.PublicKey, b: rsa.PublicKey) bool {
    var a_n: [rsa.max_modulus_len]u8 = undefined;
    var b_n: [rsa.max_modulus_len]u8 = undefined;
    const a_len = (a.n.bits() + 7) / 8;
    const b_len = (b.n.bits() + 7) / 8;
    if (a_len > a_n.len or b_len > b_n.len) return false;
    a.n.toBytes(a_n[0..a_len], .big) catch return false;
    b.n.toBytes(b_n[0..b_len], .big) catch return false;

    var a_e: [rsa.max_modulus_len]u8 = undefined;
    var b_e: [rsa.max_modulus_len]u8 = undefined;
    a.e.toBytes(&a_e, .big) catch return false;
    b.e.toBytes(&b_e, .big) catch return false;

    return std.mem.eql(u8, stripLeadingZeros(a_n[0..a_len]), stripLeadingZeros(b_n[0..b_len])) and
        std.mem.eql(u8, stripLeadingZeros(&a_e), stripLeadingZeros(&b_e));
}

/// Whether a key recovered from a certificate is the same key the presenter
/// authenticated the transport with. Different algorithms never match (an RSA
/// key is not an EC key, whatever their bytes look like).
fn certKeyMatchesPresented(ck: CertKey, presented: PresentedKey) bool {
    return switch (ck) {
        .rsa => |cert_pk| switch (presented) {
            .rsa => |pres_pk| rsaPublicKeysEqual(cert_pk, pres_pk),
            .ec_sec1 => false,
        },
        .ec_p256 => |cert_point| switch (presented) {
            .rsa => false,
            // The presented point is canonicalized the same way, so a caller
            // holding the compressed form of the certificate's key still matches.
            .ec_sec1 => |sec1| blk: {
                const pres = P256PublicKey.fromSec1(sec1) catch break :blk false;
                break :blk std.mem.eql(u8, &cert_point, &pres.toUncompressedSec1());
            },
        },
    };
}

/// Cross-form, direction 1: an `<ds:X509Certificate>` anywhere under `el` whose
/// public key is the caller's `presented` bare key. Walks the whole subtree,
/// like `anyX509Matches`. A certificate that does not decode to a comparable
/// key contributes `.incomparable`, never a match.
fn anyX509MatchesKey(alloc: std.mem.Allocator, el: *const xml.Element, presented: PresentedKey) CrossMatch {
    var decided = false;
    for (el.children) |c| switch (c.content) {
        .element => |child| {
            const verdict = if (isEl(child, xmldsig.ds_ns, "X509Certificate"))
                x509CertMatchesKey(alloc, child, presented)
            else
                anyX509MatchesKey(alloc, child, presented);
            switch (verdict) {
                .match => return .match,
                .mismatch => decided = true,
                .incomparable => {},
            }
        },
        else => {},
    };
    return if (decided) .mismatch else .incomparable;
}

fn x509CertMatchesKey(alloc: std.mem.Allocator, cert_el: *const xml.Element, presented: PresentedKey) CrossMatch {
    const txt = textAlloc(alloc, cert_el) catch return .incomparable;
    defer alloc.free(txt);
    const cert_der = decodeBase64(alloc, trim(txt)) catch return .incomparable;
    defer alloc.free(cert_der);
    const ck = certPublicKey(cert_der) orelse return .incomparable;
    return if (certKeyMatchesPresented(ck, presented)) .match else .mismatch;
}

/// Cross-form, direction 2: a bare `<RSAKeyValue>`/`<ECKeyValue>` anywhere under
/// `el` that names the public key of the caller's `presented_holder_cert_der`.
/// The certificate is reduced to a key ONCE, up front: if that fails, nothing
/// under `el` is comparable at all.
fn anyKeyValueMatchesCert(alloc: std.mem.Allocator, el: *const xml.Element, cert_der: []const u8) CrossMatch {
    const ck = certPublicKey(cert_der) orelse return .incomparable;
    return anyKeyValueMatchesCertKey(alloc, el, ck);
}

fn anyKeyValueMatchesCertKey(alloc: std.mem.Allocator, el: *const xml.Element, ck: CertKey) CrossMatch {
    var decided = false;
    for (el.children) |c| switch (c.content) {
        .element => |child| {
            if (std.mem.eql(u8, child.local, "RSAKeyValue")) {
                switch (ck) {
                    // Reuses the SAME-FORM comparison verbatim: once the
                    // certificate is reduced to an `rsa.PublicKey`, matching it
                    // against an `<RSAKeyValue>` is exactly the same problem the
                    // same-form path already solves.
                    .rsa => |pk| {
                        decided = true;
                        if (rsaKeyValueMatches(alloc, child, pk)) return .match;
                    },
                    .ec_p256 => {},
                }
            } else if (std.mem.eql(u8, child.local, "ECKeyValue")) {
                switch (ck) {
                    .ec_p256 => |point| {
                        decided = true;
                        if (ecKeyValueMatchesPoint(alloc, child, point)) return .match;
                    },
                    .rsa => {},
                }
            } else switch (anyKeyValueMatchesCertKey(alloc, child, ck)) {
                .match => return .match,
                .mismatch => decided = true,
                .incomparable => {},
            }
        },
        else => {},
    };
    return if (decided) .mismatch else .incomparable;
}

/// Match an `<ECKeyValue>` against a canonical uncompressed P-256 point. Unlike
/// the same-form `ecKeyValueMatches` — which byte-compares an opaque presented
/// blob because the caller supplied no curve context — both sides here are
/// known-good curve points, so they are compared as POINTS: the XML point is
/// put through `fromSec1` (rejecting off-curve and malformed encodings) and its
/// canonical uncompressed form compared. A compressed `<PublicKey>` naming the
/// certificate's key therefore matches, and no non-key byte string can.
fn ecKeyValueMatchesPoint(alloc: std.mem.Allocator, ekv: *const xml.Element, canonical: [65]u8) bool {
    const nc = childByLocal(ekv, "NamedCurve") orelse return false;
    const uri = nc.attr("", "URI") orelse return false;
    if (!std.mem.eql(u8, trim(uri), named_curve_p256)) return false;
    const pk_el = childByLocal(ekv, "PublicKey") orelse return false;
    const pk_txt = textAlloc(alloc, pk_el) catch return false;
    defer alloc.free(pk_txt);
    const point = decodeBase64(alloc, trim(pk_txt)) catch return false;
    defer alloc.free(point);
    const parsed = P256PublicKey.fromSec1(point) catch return false;
    return std.mem.eql(u8, &canonical, &parsed.toUncompressedSec1());
}

/// True iff any `<ds:X509Certificate>` anywhere under `el` decodes to DER that is
/// byte-identical to `presented`. Walks the whole subtree so a `<ds:KeyInfo>`
/// nested under `<SubjectConfirmationData>` (or a chain of certificates) is
/// covered. Never parses the DER (panic-safe on hostile input).
fn anyX509Matches(alloc: std.mem.Allocator, el: *const xml.Element, presented: []const u8) bool {
    for (el.children) |c| switch (c.content) {
        .element => |child| {
            if (isEl(child, xmldsig.ds_ns, "X509Certificate")) {
                if (x509CertMatches(alloc, child, presented)) return true;
            } else if (anyX509Matches(alloc, child, presented)) {
                return true;
            }
        },
        else => {},
    };
    return false;
}

fn x509CertMatches(alloc: std.mem.Allocator, cert_el: *const xml.Element, presented: []const u8) bool {
    const txt = textAlloc(alloc, cert_el) catch return false;
    defer alloc.free(txt);
    const der = decodeBase64(alloc, trim(txt)) catch return false;
    defer alloc.free(der);
    return std.mem.eql(u8, der, presented);
}

/// True iff any `<ds:X509Certificate>` is present anywhere under `el` (a cheap
/// structural probe used to distinguish a same-form mismatch from a cross-form
/// pairing — the match itself is `anyX509Matches`).
fn anyX509Present(el: *const xml.Element) bool {
    for (el.children) |c| switch (c.content) {
        .element => |child| {
            if (isEl(child, xmldsig.ds_ns, "X509Certificate")) return true;
            if (anyX509Present(child)) return true;
        },
        else => {},
    };
    return false;
}

/// True iff any `<RSAKeyValue>` or `<ECKeyValue>` is present anywhere under `el`
/// (local-name match, namespace-lenient: the EC form lives in the `dsig11`
/// namespace, the RSA form in `ds`). Structural probe only.
fn anyKeyValuePresent(el: *const xml.Element) bool {
    for (el.children) |c| switch (c.content) {
        .element => |child| {
            if (std.mem.eql(u8, child.local, "RSAKeyValue") or
                std.mem.eql(u8, child.local, "ECKeyValue")) return true;
            if (anyKeyValuePresent(child)) return true;
        },
        else => {},
    };
    return false;
}

/// True iff any bare `<ds:KeyValue>` public key anywhere under `el` matches the
/// caller-presented key. An `<RSAKeyValue>` matches a `.rsa` key; an
/// `<ECKeyValue>` matches an `.ec_sec1` key. Purely structural (base64 + integer
/// comparison); no signature op and no DER parsing. Namespace-lenient on the
/// KeyValue element local names.
fn anyKeyValueMatches(alloc: std.mem.Allocator, el: *const xml.Element, presented: PresentedKey) bool {
    for (el.children) |c| switch (c.content) {
        .element => |child| {
            if (std.mem.eql(u8, child.local, "RSAKeyValue")) {
                switch (presented) {
                    .rsa => |pk| if (rsaKeyValueMatches(alloc, child, pk)) return true,
                    else => {},
                }
            } else if (std.mem.eql(u8, child.local, "ECKeyValue")) {
                switch (presented) {
                    .ec_sec1 => |sec1| if (ecKeyValueMatches(alloc, child, sec1)) return true,
                    else => {},
                }
            } else if (anyKeyValueMatches(alloc, child, presented)) {
                return true;
            }
        },
        else => {},
    };
    return false;
}

/// Strip leading zero octets (I2OSP/OS2IP length tolerance) — DER integers and
/// XML `<Modulus>`/`<Exponent>` values may carry a sign-guard leading zero.
fn stripLeadingZeros(bytes: []const u8) []const u8 {
    var i: usize = 0;
    while (i < bytes.len and bytes[i] == 0) : (i += 1) {}
    return bytes[i..];
}

/// Match an `<RSAKeyValue>` (base64 `<Modulus>` + `<Exponent>`, big-endian) to an
/// `rsa.PublicKey` by comparing the (leading-zero-stripped) modulus and exponent
/// integers. Never a signature op.
fn rsaKeyValueMatches(alloc: std.mem.Allocator, rkv: *const xml.Element, pk: rsa.PublicKey) bool {
    const mod_el = childByLocal(rkv, "Modulus") orelse return false;
    const exp_el = childByLocal(rkv, "Exponent") orelse return false;

    const mod_txt = textAlloc(alloc, mod_el) catch return false;
    defer alloc.free(mod_txt);
    const mod_bytes = decodeBase64(alloc, trim(mod_txt)) catch return false;
    defer alloc.free(mod_bytes);
    const exp_txt = textAlloc(alloc, exp_el) catch return false;
    defer alloc.free(exp_txt);
    const exp_bytes = decodeBase64(alloc, trim(exp_txt)) catch return false;
    defer alloc.free(exp_bytes);

    // Serialize the presented key's n and e big-endian.
    var n_buf: [rsa.max_modulus_len]u8 = undefined;
    const n_len = (pk.n.bits() + 7) / 8;
    if (n_len > n_buf.len) return false;
    pk.n.toBytes(n_buf[0..n_len], .big) catch return false;
    var e_buf: [rsa.max_modulus_len]u8 = undefined;
    pk.e.toBytes(&e_buf, .big) catch return false;

    return std.mem.eql(u8, stripLeadingZeros(mod_bytes), stripLeadingZeros(n_buf[0..n_len])) and
        std.mem.eql(u8, stripLeadingZeros(exp_bytes), stripLeadingZeros(&e_buf));
}

/// Match an `<ECKeyValue>` (`<NamedCurve URI=…>` + base64 `<PublicKey>` point) to
/// a presented SEC1 point. Requires the NamedCurve to identify P-256 (the only
/// EC curve `xmldsig.VerifyKey` supports) and the point bytes to be identical.
/// Byte-exact (a differently-encoded — compressed vs uncompressed — point will
/// not match, the same trade as the certificate-DER path).
fn ecKeyValueMatches(alloc: std.mem.Allocator, ekv: *const xml.Element, presented_sec1: []const u8) bool {
    const nc = childByLocal(ekv, "NamedCurve") orelse return false;
    const uri = nc.attr("", "URI") orelse return false;
    if (!std.mem.eql(u8, trim(uri), named_curve_p256)) return false;
    const pk_el = childByLocal(ekv, "PublicKey") orelse return false;
    const pk_txt = textAlloc(alloc, pk_el) catch return false;
    defer alloc.free(pk_txt);
    const point = decodeBase64(alloc, trim(pk_txt)) catch return false;
    defer alloc.free(point);
    return std.mem.eql(u8, point, presented_sec1);
}

/// First direct child element with the given local name (any namespace).
fn childByLocal(parent: *const xml.Element, local: []const u8) ?*xml.Element {
    for (parent.children) |c| switch (c.content) {
        .element => |el| if (std.mem.eql(u8, el.local, local)) return el,
        else => {},
    };
    return null;
}

/// The eIDAS-aware Level-of-Assurance comparison. `required` meets when:
///   - both `required` and `presented` are eIDAS URIs and
///     rank(presented) >= rank(required) (low < substantial < high); or
///   - `required` is non-eIDAS and equals `presented` exactly.
/// An absent `presented`, or an eIDAS `required` against a non-eIDAS
/// `presented`, never meets.
fn loaMeets(required: []const u8, presented: ?[]const u8) bool {
    const p = presented orelse return false;
    if (eidasLoaRank(required)) |req_rank| {
        const p_rank = eidasLoaRank(p) orelse return false;
        return p_rank >= req_rank;
    }
    return std.mem.eql(u8, required, p);
}

fn eidasLoaRank(uri: []const u8) ?u8 {
    if (std.mem.eql(u8, uri, eidas_loa_low)) return 1;
    if (std.mem.eql(u8, uri, eidas_loa_substantial)) return 2;
    if (std.mem.eql(u8, uri, eidas_loa_high)) return 3;
    return null;
}

fn audienceContains(restriction: *const xml.Element, sp: []const u8, alloc: std.mem.Allocator) bool {
    for (restriction.children) |c| switch (c.content) {
        .element => |el| if (isEl(el, saml_ns, "Audience")) {
            const t = textAlloc(alloc, el) catch return false;
            defer alloc.free(t);
            if (std.mem.eql(u8, trim(t), sp)) return true;
        },
        else => {},
    };
    return false;
}

/// Extract every `<saml:Attribute>` from the (trusted) assertion's
/// `<AttributeStatement>` into the result arena `a`. A `<saml:EncryptedAttribute>`
/// is decrypted (opt-in, using the caller allocator `alloc` for scratch) to a
/// `<saml:Attribute>` and merged alongside the cleartext ones. Decryption runs on
/// the already-signature-verified assertion, so the ciphertext is authenticated
/// by enclosure.
fn extractAttributes(a: std.mem.Allocator, alloc: std.mem.Allocator, asrt: *const xml.Element, config: Config) ConsumeError![]const Attribute {
    var out: std.ArrayList(Attribute) = .empty;
    const stmt = childEl(asrt, saml_ns, "AttributeStatement") orelse return out.toOwnedSlice(a);
    for (stmt.children) |c| switch (c.content) {
        .element => |attr_el| {
            if (isEl(attr_el, saml_ns, "Attribute")) {
                try appendAttribute(a, &out, attr_el);
            } else if (isEl(attr_el, saml_ns, "EncryptedAttribute")) {
                if (config.sp_decrypt_key == null) return error.EncryptedAttributeUnsupported;
                var dec = try decryptWrappedElement(alloc, attr_el, config, error.AttributeDecryptionFailed);
                defer dec.deinit(alloc);
                if (!isEl(dec.doc.root, saml_ns, "Attribute")) return error.AttributeDecryptionFailed;
                try appendAttribute(a, &out, dec.doc.root);
            }
        },
        else => {},
    };
    return out.toOwnedSlice(a);
}

/// Append one `<saml:Attribute>` element to `out`, duping into arena `a`. A
/// nameless Attribute is skipped (no append), matching the cleartext behavior.
fn appendAttribute(a: std.mem.Allocator, out: *std.ArrayList(Attribute), attr_el: *const xml.Element) ConsumeError!void {
    const name = if (attr_el.attr("", "Name")) |n| try a.dupe(u8, n) else return;
    const friendly = try dupAttr(a, attr_el, "FriendlyName");
    var vals: std.ArrayList([]const u8) = .empty;
    for (attr_el.children) |vc| switch (vc.content) {
        .element => |ve| if (isEl(ve, saml_ns, "AttributeValue")) {
            try vals.append(a, try dupTrimmedText(a, ve));
        },
        else => {},
    };
    try out.append(a, .{
        .name = name,
        .friendly_name = friendly,
        .values = try vals.toOwnedSlice(a),
    });
}

// ── AuthnRequest generation (SP-initiated SSO) ───────────────────────────────

pub const AuthnRequestOptions = struct {
    /// A caller-generated unique request ID (no RNG in the module). Becomes the
    /// AuthnRequest `ID` and the value you set as `expected_in_response_to` when
    /// the Response comes back.
    id: []const u8,
    /// xsd:dateTime the caller formats (e.g. "2024-06-01T12:00:00Z"). Not
    /// generated here — the module never reads the clock.
    issue_instant: []const u8,
    /// This SP's entityID (becomes `<Issuer>`).
    issuer: []const u8,
    /// This SP's ACS URL (`AssertionConsumerServiceURL`).
    acs_url: []const u8,
    /// The IdP SSO endpoint (`Destination`); optional.
    destination: ?[]const u8 = null,
    /// `<NameIDPolicy Format>`; optional.
    name_id_format: ?[]const u8 = null,
    /// Emit `AllowCreate="true"` on the NameIDPolicy.
    allow_create: bool = true,
};

/// Build a `<samlp:AuthnRequest>` document (the caller applies the binding —
/// deflate+base64+URL-encode for Redirect, or base64 for POST). Owned by caller.
pub fn buildAuthnRequest(alloc: std.mem.Allocator, opts: AuthnRequestOptions) std.mem.Allocator.Error![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(alloc);
    const w = &buf;
    try w.appendSlice(alloc, "<samlp:AuthnRequest xmlns:samlp=\"");
    try w.appendSlice(alloc, samlp_ns);
    try w.appendSlice(alloc, "\" xmlns:saml=\"");
    try w.appendSlice(alloc, saml_ns);
    try w.appendSlice(alloc, "\" ID=\"");
    try appendAttrEscaped(alloc, w, opts.id);
    try w.appendSlice(alloc, "\" Version=\"2.0\" IssueInstant=\"");
    try appendAttrEscaped(alloc, w, opts.issue_instant);
    try w.appendSlice(alloc, "\"");
    if (opts.destination) |d| {
        try w.appendSlice(alloc, " Destination=\"");
        try appendAttrEscaped(alloc, w, d);
        try w.appendSlice(alloc, "\"");
    }
    try w.appendSlice(alloc, " AssertionConsumerServiceURL=\"");
    try appendAttrEscaped(alloc, w, opts.acs_url);
    try w.appendSlice(alloc, "\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\">");
    try w.appendSlice(alloc, "<saml:Issuer>");
    try appendTextEscaped(alloc, w, opts.issuer);
    try w.appendSlice(alloc, "</saml:Issuer>");
    if (opts.name_id_format) |f| {
        try w.appendSlice(alloc, "<samlp:NameIDPolicy Format=\"");
        try appendAttrEscaped(alloc, w, f);
        try w.appendSlice(alloc, if (opts.allow_create) "\" AllowCreate=\"true\"/>" else "\"/>");
    } else if (opts.allow_create) {
        try w.appendSlice(alloc, "<samlp:NameIDPolicy AllowCreate=\"true\"/>");
    }
    try w.appendSlice(alloc, "</samlp:AuthnRequest>");
    return buf.toOwnedSlice(alloc);
}

// ── IdP metadata parsing ─────────────────────────────────────────────────────

pub const SsoEndpoint = struct {
    binding: []const u8,
    location: []const u8,
};

/// Parsed `<md:IDPSSODescriptor>` essentials. All slices owned by `arena`.
pub const IdpMetadata = struct {
    arena: std.heap.ArenaAllocator,
    entity_id: []const u8,
    /// `<md:SingleSignOnService>` endpoints.
    sso_endpoints: []const SsoEndpoint,
    /// Raw DER of each `<md:KeyDescriptor use="signing">` certificate (base64
    /// -decoded). **UNTRUSTED bytes** — the caller parses/pins them (we never
    /// feed adversarial DER to std.crypto.Certificate). A descriptor with no
    /// `use` is treated as usable for signing (SAML default = both).
    signing_certs_der: []const []const u8,

    pub fn deinit(self: *IdpMetadata) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

pub const MetadataError = error{
    MalformedMetadata,
    NoIdpDescriptor,
} || std.mem.Allocator.Error;

/// Parse a SAML metadata document (`<md:EntityDescriptor>`), extracting the IdP
/// SSO endpoints and signing certificates so the caller can build a `Config`.
/// Certificates are returned as raw DER only — never parsed here.
pub fn parseIdpMetadata(alloc: std.mem.Allocator, metadata_xml: []const u8) MetadataError!IdpMetadata {
    var doc = xml.parse(alloc, metadata_xml, .{}) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedMetadata,
    };
    defer doc.deinit();

    const ed = doc.root;
    if (!isEl(ed, md_ns, "EntityDescriptor")) return error.MalformedMetadata;
    const entity_id_src = ed.attr("", "entityID") orelse return error.MalformedMetadata;
    const idp = childEl(ed, md_ns, "IDPSSODescriptor") orelse return error.NoIdpDescriptor;

    var arena = std.heap.ArenaAllocator.init(alloc);
    errdefer arena.deinit();
    const a = arena.allocator();

    const entity_id = try a.dupe(u8, entity_id_src);

    var endpoints: std.ArrayList(SsoEndpoint) = .empty;
    var certs: std.ArrayList([]const u8) = .empty;
    for (idp.children) |c| switch (c.content) {
        .element => |el| {
            if (isEl(el, md_ns, "SingleSignOnService")) {
                const binding = el.attr("", "Binding") orelse continue;
                const location = el.attr("", "Location") orelse continue;
                try endpoints.append(a, .{
                    .binding = try a.dupe(u8, binding),
                    .location = try a.dupe(u8, location),
                });
            } else if (isEl(el, md_ns, "KeyDescriptor")) {
                if (el.attr("", "use")) |use| {
                    if (!std.mem.eql(u8, use, "signing")) continue;
                }
                if (findX509(el)) |cert_el| {
                    const text = textAlloc(a, cert_el) catch continue;
                    const der = decodeBase64(a, text) catch continue;
                    try certs.append(a, der);
                }
            }
        },
        else => {},
    };

    return .{
        .arena = arena,
        .entity_id = entity_id,
        .sso_endpoints = try endpoints.toOwnedSlice(a),
        .signing_certs_der = try certs.toOwnedSlice(a),
    };
}

fn findX509(el: *const xml.Element) ?*xml.Element {
    for (el.children) |c| switch (c.content) {
        .element => |child| {
            if (isEl(child, xmldsig.ds_ns, "X509Certificate")) return child;
            if (findX509(child)) |f| return f;
        },
        else => {},
    };
    return null;
}

// ── small helpers ────────────────────────────────────────────────────────────

fn isEl(el: *const xml.Element, uri: []const u8, local: []const u8) bool {
    return std.mem.eql(u8, el.uri, uri) and std.mem.eql(u8, el.local, local);
}

/// First direct child element with the given (uri, local).
fn childEl(parent: *const xml.Element, uri: []const u8, local: []const u8) ?*xml.Element {
    for (parent.children) |c| switch (c.content) {
        .element => |el| if (isEl(el, uri, local)) return el,
        else => {},
    };
    return null;
}

fn textAlloc(alloc: std.mem.Allocator, el: *const xml.Element) std.mem.Allocator.Error![]u8 {
    return el.textContent(alloc);
}

fn trim(s: []const u8) []const u8 {
    return std.mem.trim(u8, s, " \t\r\n");
}

fn dupTrimmedText(a: std.mem.Allocator, el: *const xml.Element) std.mem.Allocator.Error![]const u8 {
    const t = try el.textContent(a);
    defer a.free(t);
    return a.dupe(u8, trim(t));
}

fn dupAttr(a: std.mem.Allocator, el: *const xml.Element, name: []const u8) std.mem.Allocator.Error!?[]const u8 {
    if (el.attr("", name)) |v| return try a.dupe(u8, v);
    return null;
}

/// Decode standard base64, tolerating embedded ASCII whitespace/newlines.
fn decodeBase64(alloc: std.mem.Allocator, text: []const u8) ![]u8 {
    var clean: std.ArrayList(u8) = .empty;
    defer clean.deinit(alloc);
    for (text) |c| {
        if (!std.ascii.isWhitespace(c)) try clean.append(alloc, c);
    }
    const dec = std.base64.standard.Decoder;
    const n = try dec.calcSizeForSlice(clean.items);
    const buf = try alloc.alloc(u8, n);
    errdefer alloc.free(buf);
    try dec.decode(buf, clean.items);
    return buf;
}

fn appendAttrEscaped(alloc: std.mem.Allocator, w: *std.ArrayList(u8), s: []const u8) std.mem.Allocator.Error!void {
    for (s) |c| switch (c) {
        '&' => try w.appendSlice(alloc, "&amp;"),
        '<' => try w.appendSlice(alloc, "&lt;"),
        '>' => try w.appendSlice(alloc, "&gt;"),
        '"' => try w.appendSlice(alloc, "&quot;"),
        else => try w.append(alloc, c),
    };
}

fn appendTextEscaped(alloc: std.mem.Allocator, w: *std.ArrayList(u8), s: []const u8) std.mem.Allocator.Error!void {
    for (s) |c| switch (c) {
        '&' => try w.appendSlice(alloc, "&amp;"),
        '<' => try w.appendSlice(alloc, "&lt;"),
        '>' => try w.appendSlice(alloc, "&gt;"),
        else => try w.append(alloc, c),
    };
}

// ── xsd:dateTime → Unix seconds ──────────────────────────────────────────────
//
// Parses the SAML/xsd forms: `YYYY-MM-DDThh:mm:ss(.frac)?(Z|±hh:mm)?`. Fractional
// seconds are truncated (second granularity is sufficient for validity windows).
// A missing timezone is treated as UTC (SAML timestamps are UTC in practice).
//
// DRY note: `datefmt.partsToUnix` does the civil→epoch arithmetic, but `saml`
// depends only on `xmldsig`+`xml`; the calendar math is reproduced here rather
// than pulling in `datefmt`. A future `datetime`/`iso8601` helper would let all
// three (saml, xmldsig-conditions, jwt exp/nbf) share one parser.
fn parseDateTime(s: []const u8) ConsumeError!i64 {
    // Minimum: "YYYY-MM-DDThh:mm:ss" = 19 chars.
    if (s.len < 19) return error.InvalidDateTime;
    if (s[4] != '-' or s[7] != '-' or (s[10] != 'T' and s[10] != 't') or s[13] != ':' or s[16] != ':') {
        return error.InvalidDateTime;
    }
    const year = try parseIntField(i64, s[0..4]);
    const month = try parseIntField(i64, s[5..7]);
    const day = try parseIntField(i64, s[8..10]);
    const hour = try parseIntField(i64, s[11..13]);
    const min = try parseIntField(i64, s[14..16]);
    const sec = try parseIntField(i64, s[17..19]);
    if (month < 1 or month > 12 or day < 1 or day > 31) return error.InvalidDateTime;
    if (hour > 23 or min > 59 or sec > 60) return error.InvalidDateTime;

    var i: usize = 19;
    // Optional fractional seconds (ignored).
    if (i < s.len and s[i] == '.') {
        i += 1;
        const frac_start = i;
        while (i < s.len and s[i] >= '0' and s[i] <= '9') i += 1;
        if (i == frac_start) return error.InvalidDateTime;
    }
    // Optional timezone.
    var tz_offset: i64 = 0;
    if (i < s.len) {
        const c = s[i];
        if (c == 'Z' or c == 'z') {
            i += 1;
        } else if (c == '+' or c == '-') {
            if (i + 6 > s.len or s[i + 3] != ':') return error.InvalidDateTime;
            const oh = try parseIntField(i64, s[i + 1 .. i + 3]);
            const om = try parseIntField(i64, s[i + 4 .. i + 6]);
            if (oh > 23 or om > 59) return error.InvalidDateTime;
            tz_offset = (oh * 60 + om) * 60;
            if (c == '-') tz_offset = -tz_offset;
            i += 6;
        } else return error.InvalidDateTime;
    }
    if (i != s.len) return error.InvalidDateTime;

    const days = daysFromCivil(year, @intCast(month), @intCast(day));
    const secs = days * 86400 + hour * 3600 + min * 60 + sec;
    return secs - tz_offset;
}

fn parseIntField(comptime T: type, s: []const u8) ConsumeError!T {
    var v: T = 0;
    if (s.len == 0) return error.InvalidDateTime;
    for (s) |c| {
        if (c < '0' or c > '9') return error.InvalidDateTime;
        v = v * 10 + @as(T, c - '0');
    }
    return v;
}

/// Days since 1970-01-01 for a proleptic-Gregorian date (Howard Hinnant's
/// algorithm). Valid for the full range SAML timestamps use.
fn daysFromCivil(y_in: i64, m: u32, d: u32) i64 {
    var y = y_in;
    if (m <= 2) y -= 1;
    const era = @divFloor(if (y >= 0) y else y - 399, 400);
    const yoe: i64 = y - era * 400;
    const mp: i64 = @intCast((m + 9) % 12);
    const doy: i64 = @divTrunc(153 * mp + 2, 5) + @as(i64, @intCast(d)) - 1;
    const doe: i64 = yoe * 365 + @divTrunc(yoe, 4) - @divTrunc(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

// ── tests ────────────────────────────────────────────────────────────────────

test {
    _ = @import("test_xsw.zig");
    _ = @import("test_fixture.zig");
    _ = @import("test_encrypted.zig");
    _ = @import("test_sign.zig");
    _ = @import("test_encrypted_id_attr.zig");
    _ = @import("test_hok.zig");
    _ = @import("test_hok_keyvalue.zig");
    _ = @import("test_hok_crossform.zig");
    _ = @import("test_eidas.zig");
}

const testing = std.testing;

test "parseDateTime: UTC Z form" {
    // 2024-06-01T12:00:00Z == 1717243200.
    try testing.expectEqual(@as(i64, 1717243200), try parseDateTime("2024-06-01T12:00:00Z"));
}

test "parseDateTime: fractional seconds truncated, lowercase t/z tolerated" {
    try testing.expectEqual(@as(i64, 1717243200), try parseDateTime("2024-06-01t12:00:00.123456z"));
}

test "parseDateTime: numeric timezone offset applied" {
    // 12:00:00+02:00 is 10:00:00Z == 1717236000.
    try testing.expectEqual(@as(i64, 1717236000), try parseDateTime("2024-06-01T12:00:00+02:00"));
    // 12:00:00-02:00 is 14:00:00Z == 1717250400.
    try testing.expectEqual(@as(i64, 1717250400), try parseDateTime("2024-06-01T12:00:00-02:00"));
}

test "parseDateTime: epoch and a pre-epoch date" {
    try testing.expectEqual(@as(i64, 0), try parseDateTime("1970-01-01T00:00:00Z"));
    // 1969-12-31T00:00:00Z == -86400.
    try testing.expectEqual(@as(i64, -86400), try parseDateTime("1969-12-31T00:00:00Z"));
}

test "parseDateTime: malformed inputs are typed errors, never panics" {
    try testing.expectError(error.InvalidDateTime, parseDateTime("2024-06-01"));
    try testing.expectError(error.InvalidDateTime, parseDateTime("2024/06/01T12:00:00Z"));
    try testing.expectError(error.InvalidDateTime, parseDateTime("2024-13-01T12:00:00Z"));
    try testing.expectError(error.InvalidDateTime, parseDateTime("2024-06-01T25:00:00Z"));
    try testing.expectError(error.InvalidDateTime, parseDateTime("2024-06-01T12:00:00Q"));
    try testing.expectError(error.InvalidDateTime, parseDateTime("2024-06-01T12:00:00+0200"));
    try testing.expectError(error.InvalidDateTime, parseDateTime(""));
}

test "daysFromCivil matches known epochs" {
    try testing.expectEqual(@as(i64, 0), daysFromCivil(1970, 1, 1));
    try testing.expectEqual(@as(i64, 19875), daysFromCivil(2024, 6, 1));
}

test "buildAuthnRequest: well-formed, parses back, carries the fields" {
    const req = try buildAuthnRequest(testing.allocator, .{
        .id = "_req123",
        .issue_instant = "2024-06-01T12:00:00Z",
        .issuer = "https://sp.example.org/metadata",
        .acs_url = "https://sp.example.org/acs",
        .destination = "https://idp.example.org/sso",
        .name_id_format = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    });
    defer testing.allocator.free(req);

    var doc = try xml.parse(testing.allocator, req, .{});
    defer doc.deinit();
    try testing.expect(isEl(doc.root, samlp_ns, "AuthnRequest"));
    try testing.expectEqualStrings("_req123", doc.root.attr("", "ID").?);
    try testing.expectEqualStrings("https://sp.example.org/acs", doc.root.attr("", "AssertionConsumerServiceURL").?);
    try testing.expectEqualStrings("https://idp.example.org/sso", doc.root.attr("", "Destination").?);
    const issuer = childEl(doc.root, saml_ns, "Issuer").?;
    const it = try issuer.textContent(testing.allocator);
    defer testing.allocator.free(it);
    try testing.expectEqualStrings("https://sp.example.org/metadata", it);
    const nidp = childEl(doc.root, samlp_ns, "NameIDPolicy").?;
    try testing.expectEqualStrings("true", nidp.attr("", "AllowCreate").?);
}

test "decodeRedirectField: raw-DEFLATE + base64 round-trips" {
    const alloc = testing.allocator;
    const msg = "<samlp:AuthnRequest ID=\"_x\"/>";
    // Produce the Redirect encoding: raw DEFLATE then base64.
    var aw = try std.Io.Writer.Allocating.initCapacity(alloc, 256);
    defer aw.deinit();
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var comp = try std.compress.flate.Compress.init(&aw.writer, &window, .raw, .default);
    try comp.writer.writeAll(msg);
    try comp.finish();
    const deflated = aw.writer.buffered();

    const enc = std.base64.standard.Encoder;
    const b64 = try alloc.alloc(u8, enc.calcSize(deflated.len));
    defer alloc.free(b64);
    const field = enc.encode(b64, deflated);

    const decoded = try decodeRedirectField(alloc, field);
    defer alloc.free(decoded);
    try testing.expectEqualStrings(msg, decoded);
}

test "decodeRedirectField: malformed base64/inflate is a typed error" {
    try testing.expectError(error.InvalidEncoding, decodeRedirectField(testing.allocator, "!!!not-base64!!!"));
}

test "parseIdpMetadata: endpoints + signing cert DER (untrusted)" {
    const md =
        "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\"" ++
        " xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" entityID=\"https://idp.example.org/saml\">" ++
        "<md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">" ++
        "<md:KeyDescriptor use=\"signing\"><ds:KeyInfo><ds:X509Data>" ++
        "<ds:X509Certificate>SGVsbG8=</ds:X509Certificate>" ++ // base64("Hello")
        "</ds:X509Data></ds:KeyInfo></md:KeyDescriptor>" ++
        "<md:KeyDescriptor use=\"encryption\"><ds:KeyInfo><ds:X509Data>" ++
        "<ds:X509Certificate>d29ybGQ=</ds:X509Certificate>" ++ // must be skipped
        "</ds:X509Data></ds:KeyInfo></md:KeyDescriptor>" ++
        "<md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://idp.example.org/sso\"/>" ++
        "</md:IDPSSODescriptor></md:EntityDescriptor>";
    var m = try parseIdpMetadata(testing.allocator, md);
    defer m.deinit();
    try testing.expectEqualStrings("https://idp.example.org/saml", m.entity_id);
    try testing.expectEqual(@as(usize, 1), m.sso_endpoints.len);
    try testing.expectEqualStrings("https://idp.example.org/sso", m.sso_endpoints[0].location);
    // Only the signing descriptor's cert is returned, as raw DER bytes.
    try testing.expectEqual(@as(usize, 1), m.signing_certs_der.len);
    try testing.expectEqualStrings("Hello", m.signing_certs_der[0]);
}

// ── fuzz: HTTP-binding field decode + IdP metadata parse, never panics ─────
//
// `decodePostField`/`decodeRedirectField` run on the `SAMLResponse` query/
// form field of an inbound HTTP request — base64 (POST binding) or
// base64+raw-DEFLATE (Redirect binding), both fully attacker-controlled
// before any XML signature has been checked. `parseIdpMetadata` runs on a
// metadata document fetched from (or forwarded by) an IdP, which this
// module's own doc calls out as untrusted (certs come back as raw DER,
// "never parsed here" — this file just has to survive hostile XML shape).

test "fuzz: decodePostField/decodeRedirectField never panic on arbitrary bytes" {
    try testing.fuzz({}, fuzzDecodeFields, .{});
}

fn fuzzDecodeFields(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const field = buf[0..len];

    if (decodePostField(testing.allocator, field)) |d| testing.allocator.free(d) else |_| {}
    if (decodeRedirectField(testing.allocator, field)) |d| testing.allocator.free(d) else |_| {}
}

test "fuzz: parseIdpMetadata never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzParseIdpMetadata, .{});
}

fn fuzzParseIdpMetadata(_: void, smith: *std.testing.Smith) !void {
    const alphabet = "<>/=\"'&;! ?abcmdsEntityDescriptorIDPSSOKeyInfoX509CertificateSingleSignOnServiceBinding0123\n\t";
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    for (buf[0..len]) |*c| {
        if (smith.boolWeighted(1, 3)) c.* = alphabet[c.* % alphabet.len];
    }

    var m = parseIdpMetadata(testing.allocator, buf[0..len]) catch return;
    m.deinit();
}
