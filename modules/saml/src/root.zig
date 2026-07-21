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
//! ## Out of scope (see SPEC.md)
//!   - `<saml:EncryptedAssertion>` / XML-Encryption — detected and refused with
//!     `error.EncryptedAssertionUnsupported` (top follow-up: eIDAS needs it).
//!   - Single Logout, artifact binding, the IdP side.
//!
//! Never reads the system clock. Never panics on malformed / adversarial input:
//! every failure is a typed error.

const std = @import("std");
const xml = @import("xml");
const xmldsig = @import("xmldsig");

pub const meta = .{
    .platform = .any,
    .role = .codec, // consumes an untrusted wire document into a trusted result
    .concurrency = .reentrant,
    .model_after = "OASIS SAML 2.0 (SAMLCore / SAMLProf) Web Browser SSO, SP side; XSW-hardened per 'On Breaking SAML'",
    .deps = .{ "xmldsig", "xml" },
};

// ── namespaces ───────────────────────────────────────────────────────────────

pub const samlp_ns = "urn:oasis:names:tc:SAML:2.0:protocol";
pub const saml_ns = "urn:oasis:names:tc:SAML:2.0:assertion";
pub const md_ns = "urn:oasis:names:tc:SAML:2.0:metadata";

const status_success = "urn:oasis:names:tc:SAML:2.0:status:Success";
const cm_bearer = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

/// A decompression-bomb cap for the HTTP-Redirect (DEFLATE) binding.
pub const max_redirect_inflated = 1 << 20;

// ── configuration ────────────────────────────────────────────────────────────

/// Which element(s) the SP will accept a valid signature on. `.either` (the
/// default) accepts a signed Assertion OR a signed enclosing Response; both are
/// pinned to the consumed assertion by the XSW defense regardless.
pub const SignaturePolicy = enum { assertion, response, either };

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

    /// The unqualified attribute name that carries assertion / response IDs.
    /// SAML uses `ID`; both this module and `xmldsig` resolve references through
    /// it, which is what makes the XSW pointer-pin sound.
    id_attr: []const u8 = "ID",
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
    /// A `<saml:EncryptedAssertion>` was present. XML-Encryption is unsupported.
    EncryptedAssertionUnsupported,
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
    /// No acceptable Bearer `<SubjectConfirmation>` (see the more specific
    /// Recipient / InResponseTo / expiry errors first).
    SubjectConfirmationFailed,
    /// Bearer `Recipient` did not equal `Config.acs_url`.
    RecipientMismatch,
    /// Bearer `InResponseTo` did not match `Config.expected_in_response_to`
    /// (or was absent while `allow_idp_initiated` is false, or present while no
    /// request was pending).
    InResponseToMismatch,
    /// An xsd:dateTime attribute could not be parsed.
    InvalidDateTime,
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

    // Encrypted assertions are unsupported (detect before anything else fails).
    if (childEl(root, saml_ns, "EncryptedAssertion") != null) return error.EncryptedAssertionUnsupported;

    // Exactly one Assertion, as a DIRECT child of Response (XSW hardening).
    var assertion: ?*const xml.Element = null;
    var count: usize = 0;
    for (root.children) |c| switch (c.content) {
        .element => |el| if (isEl(el, saml_ns, "Assertion")) {
            count += 1;
            assertion = el;
        },
        else => {},
    };
    if (count == 0) return error.NoAssertion;
    if (count > 1) return error.MultipleAssertions;
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
    const opts: xmldsig.Options = .{
        .key = config.idp_key,
        .allow_weak_sha1 = config.allow_weak_sha1,
        .id_attr = config.id_attr,
    };

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

fn moveCert(alloc: std.mem.Allocator, res: *xmldsig.Result, cert_out: *?[]u8) void {
    if (res.x509_cert_der) |d| {
        // Take ownership away from res (whose deinit would otherwise free it).
        cert_out.* = d;
        res.x509_cert_der = null;
    }
    _ = alloc;
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

    // ── Subject + Bearer SubjectConfirmation ─────────────────────────────────
    const subject = childEl(asrt, saml_ns, "Subject") orelse return error.SubjectMissing;
    const name_id = childEl(subject, saml_ns, "NameID") orelse return error.SubjectMissing;

    try validateBearerConfirmation(alloc, subject, config, now, skew);

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

    const attrs = try extractAttributes(a, asrt);

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

fn validateBearerConfirmation(alloc: std.mem.Allocator, subject: *const xml.Element, config: Config, now: i64, skew: i64) ConsumeError!void {
    var best_err: ?ConsumeError = null;
    var saw_bearer = false;
    for (subject.children) |c| switch (c.content) {
        .element => |sc| {
            if (!isEl(sc, saml_ns, "SubjectConfirmation")) continue;
            const method = sc.attr("", "Method") orelse continue;
            if (!std.mem.eql(u8, method, cm_bearer)) continue;
            saw_bearer = true;
            const scd = childEl(sc, saml_ns, "SubjectConfirmationData") orelse {
                best_err = best_err orelse error.SubjectConfirmationFailed;
                continue;
            };
            // Recipient must equal the ACS URL.
            const recip = scd.attr("", "Recipient") orelse {
                best_err = error.RecipientMismatch;
                continue;
            };
            if (!std.mem.eql(u8, recip, config.acs_url)) {
                best_err = error.RecipientMismatch;
                continue;
            }
            // NotOnOrAfter is required for a Bearer confirmation.
            const noa = scd.attr("", "NotOnOrAfter") orelse {
                best_err = best_err orelse error.SubjectConfirmationFailed;
                continue;
            };
            const t = try parseDateTime(noa);
            if (now - skew >= t) {
                best_err = best_err orelse error.AssertionExpired;
                continue;
            }
            // InResponseTo correlation.
            if (scd.attr("", "InResponseTo")) |irt| {
                const expected = config.expected_in_response_to orelse {
                    best_err = error.InResponseToMismatch;
                    continue;
                };
                if (!std.mem.eql(u8, irt, expected)) {
                    best_err = error.InResponseToMismatch;
                    continue;
                }
            } else if (!config.allow_idp_initiated) {
                best_err = error.InResponseToMismatch;
                continue;
            }
            return; // a fully-valid Bearer confirmation
        },
        else => {},
    };
    _ = alloc;
    return best_err orelse error.SubjectConfirmationFailed;
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

fn extractAttributes(a: std.mem.Allocator, asrt: *const xml.Element) ConsumeError![]const Attribute {
    var out: std.ArrayList(Attribute) = .empty;
    const stmt = childEl(asrt, saml_ns, "AttributeStatement") orelse return out.toOwnedSlice(a);
    for (stmt.children) |c| switch (c.content) {
        .element => |attr_el| {
            if (!isEl(attr_el, saml_ns, "Attribute")) continue;
            const name = if (attr_el.attr("", "Name")) |n| try a.dupe(u8, n) else continue;
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
        },
        else => {},
    };
    return out.toOwnedSlice(a);
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
