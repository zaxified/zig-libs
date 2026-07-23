// SPDX-License-Identifier: MIT

//! IEC 62351-3 — the TLS profile, as a checkable policy object.
//!
//! ## Why this is a policy and not a protocol
//!
//! IEC 62351-3 does not define a protocol. It *constrains* TLS: which
//! versions, which cipher suites, what a certificate must look like, whether
//! revocation must be checked, how often a session must be renegotiated, when
//! resumption is allowed. Every one of those is a sentence in a document that
//! somebody is supposed to read and honour.
//!
//! This file turns those sentences into a value: a `Profile` with named
//! knobs, and a `check` that returns a **typed set of the specific rules that
//! were violated**. That makes conformance something a test can assert and a
//! runtime can log, and — importantly — it is useful even when the TLS
//! handshake happens somewhere else entirely. `zig-libs` deliberately ships
//! no TLS server (see `CONVENTIONS.md` §2: TLS is proxy-terminated or
//! bring-your-own), so an operator whose TLS terminates in a proxy, in
//! `std.crypto.tls`, or in a vendor stack can still hand this module the
//! negotiated parameters and the peer certificate and get a verdict.
//!
//! ## What it checks and what it cannot
//!
//! Everything here is a check on **already-negotiated** parameters plus a
//! **static** look at one certificate. Specifically:
//!
//! - It does **not** perform path validation. That is `x509.verifyChain`'s
//!   job and the caller must run it; `Violation.chain_not_validated` exists so
//!   a caller can record that it did.
//! - It does **not** fetch a CRL or speak OCSP. `revocation_checked` is an
//!   assertion the caller makes; the modules that can actually do the work
//!   are `ocsp`/`ocspcache`.
//! - It does **not** verify the certificate's signature. A certificate that
//!   is structurally fine but forged fails path validation, not this policy.
//!
//! Saying so matters more than the checks themselves: a policy object that
//! silently implied it had validated a chain would be worse than none.
//!
//! ## Provenance of the default values
//!
//! `Profile.iec62351_3` encodes the requirements that are consistently
//! reported for IEC 62351-3:2018 and the cipher-suite lists IEC 62351-4:2018
//! carries for MMS: TLS 1.2 as the floor, `TLS_RSA_WITH_AES_128_CBC_SHA256`
//! as the mandatory-to-implement suite for the native mode, AES-GCM suites
//! preferred, RC4 and 3DES removed as obsolete, RSA keys of at least 2048
//! bits, mandatory revocation checking, and a bounded session lifetime with
//! renegotiation. The standard is paywalled; the numeric bounds it fixes
//! (exact renegotiation interval, exact resumption lifetime) vary by edition
//! and by the profile a deployment claims, so they are **knobs with
//! documented defaults**, not constants baked into the checks. A deployment
//! that must match a specific clause sets them. Cipher-suite code points are
//! from the IANA TLS registry and are not in doubt.

const std = @import("std");
const x509 = @import("x509");
const rsa = @import("rsa");

const Certificate = std.crypto.Certificate;

// ── negotiated-session vocabulary ───────────────────────────────────────────

pub const TlsVersion = enum(u16) {
    ssl30 = 0x0300,
    tls10 = 0x0301,
    tls11 = 0x0302,
    tls12 = 0x0303,
    tls13 = 0x0304,
    _,

    pub fn atLeast(v: TlsVersion, floor: TlsVersion) bool {
        return @intFromEnum(v) >= @intFromEnum(floor);
    }
};

/// TLS cipher suites this module can name. Code points are IANA registry
/// values. Anything else is representable as an unnamed enum value, so an
/// unknown suite is checkable (it simply is not on the allow-list) rather
/// than unrepresentable.
pub const CipherSuite = enum(u16) {
    // Obsolete — present so a profile can reject them by name.
    tls_rsa_with_rc4_128_sha = 0x0005,
    tls_rsa_with_3des_ede_cbc_sha = 0x000a,
    tls_dhe_rsa_with_3des_ede_cbc_sha = 0x0016,
    tls_rsa_with_aes_128_cbc_sha = 0x002f,
    tls_dh_dss_with_aes_256_cbc_sha = 0x0038,
    tls_rsa_with_aes_256_cbc_sha = 0x0035,

    // TLS 1.2 SHA-256/384 suites.
    tls_rsa_with_aes_128_cbc_sha256 = 0x003c,
    tls_rsa_with_aes_256_cbc_sha256 = 0x003d,
    tls_dhe_rsa_with_aes_128_cbc_sha256 = 0x0067,
    tls_dhe_rsa_with_aes_256_cbc_sha256 = 0x006b,
    tls_rsa_with_aes_128_gcm_sha256 = 0x009c,
    tls_rsa_with_aes_256_gcm_sha384 = 0x009d,
    tls_dhe_rsa_with_aes_128_gcm_sha256 = 0x009e,
    tls_dhe_rsa_with_aes_256_gcm_sha384 = 0x009f,
    tls_dh_rsa_with_aes_128_gcm_sha256 = 0x00a0,
    tls_dh_rsa_with_aes_256_gcm_sha384 = 0x00a1,
    tls_ecdhe_ecdsa_with_aes_128_gcm_sha256 = 0xc02b,
    tls_ecdhe_ecdsa_with_aes_256_gcm_sha384 = 0xc02c,
    tls_ecdhe_rsa_with_aes_128_gcm_sha256 = 0xc02f,
    tls_ecdhe_rsa_with_aes_256_gcm_sha384 = 0xc030,

    // TLS 1.3.
    tls_aes_128_gcm_sha256 = 0x1301,
    tls_aes_256_gcm_sha384 = 0x1302,
    tls_chacha20_poly1305_sha256 = 0x1303,
    _,
};

/// The negotiated parameters of a session, as observed by whoever terminated
/// it. Every field is something a TLS stack can report; none of it is
/// derived here.
pub const SessionDescription = struct {
    version: TlsVersion,
    cipher_suite: CipherSuite,
    /// RFC 5746 secure-renegotiation indication was negotiated.
    secure_renegotiation: bool = true,
    /// TLS-level compression was negotiated (CRIME).
    compression: bool = false,
    /// The peer presented a certificate and it was required.
    mutual_authentication: bool = true,
    /// The caller ran `x509.verifyChain` (or equivalent) on the peer chain.
    chain_validated: bool = true,
    /// The caller checked revocation (CRL or OCSP) for the peer chain.
    revocation_checked: bool = true,
    /// How long this session has been open, in seconds.
    age_s: u64 = 0,
    /// Octets transferred over the session so far.
    bytes_transferred: u64 = 0,
    /// The session was resumed rather than fully negotiated.
    resumed: bool = false,
    /// Age of the resumption ticket/session used, in seconds.
    resumption_age_s: u64 = 0,
};

// ── certificate facts ───────────────────────────────────────────────────────

pub const KeyKind = enum { rsa, ecdsa, ed25519, other };

/// Everything the policy looks at in a certificate, extracted once so the
/// policy itself is pure and testable without DER.
pub const CertificateFacts = struct {
    not_before_s: u64,
    not_after_s: u64,
    key_kind: KeyKind,
    /// RSA modulus size, or the curve's field size for ECDSA; 0 when unknown.
    key_bits: usize,
    named_curve: ?Certificate.NamedCurve = null,
    signature_algorithm: ?Certificate.Algorithm = null,
    key_usage: ?x509.extensions.KeyUsage = null,
    key_usage_critical: bool = false,
    ext_key_usage_present: bool = false,
    /// The certificate lists the purpose the profile asked for (or
    /// `anyExtendedKeyUsage`).
    has_required_purpose: bool = false,
    basic_constraints: ?x509.extensions.BasicConstraints = null,
    version: Certificate.Version = .v3,
};

// The pre-flight guard that used to live here (`structurallySafe` /
// `derTilesExactly`, found necessary by fuzzing) has moved to the shared
// `x509.safe` helper — `std.crypto.Certificate`'s DER reader is unchecked and
// panics / reads out of bounds on a malformed, attacker-supplied certificate,
// and three modules independently guarded against it. `inspectCertificate`
// below now parses the certificate through `x509.safe.safeCertificate`, which
// validates well-formedness and returns a zero-padded copy that is safe to
// hand to std's parser. See `x509/src/safe.zig` and this module's `SPEC.md`.

pub const InspectError = error{
    /// The DER did not parse as an X.509 certificate at all.
    MalformedCertificate,
    /// The certificate's extensions block is malformed.
    MalformedExtensions,
};

/// Extract `CertificateFacts` from DER. Uses `std.crypto.Certificate` for the
/// base fields and the sibling `x509` module for the extensions std does not
/// expose (keyUsage, extKeyUsage, basicConstraints).
pub fn inspectCertificate(der_bytes: []const u8, want: x509.extensions.Purpose) InspectError!CertificateFacts {
    // Guard `std.crypto.Certificate.parse` against its unchecked DER reader via
    // the shared `x509.safe` helper: validate well-formedness and parse a
    // zero-padded copy so a hostile certificate is a typed error, never a crash.
    var scratch: [x509.safe.max_certificate_len + x509.safe.parse_slack]u8 = undefined;
    const cert = x509.safe.safeCertificate(der_bytes, &scratch) catch return error.MalformedCertificate;
    const parsed = cert.parse() catch return error.MalformedCertificate;

    var facts: CertificateFacts = .{
        .not_before_s = parsed.validity.not_before,
        .not_after_s = parsed.validity.not_after,
        .key_kind = switch (parsed.pub_key_algo) {
            .rsaEncryption, .rsassa_pss => .rsa,
            .X9_62_id_ecPublicKey => .ecdsa,
            .curveEd25519 => .ed25519,
        },
        .key_bits = 0,
        .signature_algorithm = parsed.signature_algorithm,
        .version = parsed.version,
    };

    switch (parsed.pub_key_algo) {
        .rsaEncryption, .rsassa_pss => {
            const pk = rsa.PublicKey.fromDer(parsed.pubKey()) catch
                return error.MalformedCertificate;
            facts.key_bits = pk.n.bits();
        },
        .X9_62_id_ecPublicKey => |curve| {
            facts.named_curve = curve;
            facts.key_bits = switch (curve) {
                .X9_62_prime256v1 => 256,
                .secp384r1 => 384,
                .secp521r1 => 521,
            };
        },
        .curveEd25519 => facts.key_bits = 255,
    }

    const slice = x509.extensions.findExtensions(cert) catch
        return error.MalformedExtensions;
    if (slice) |s| {
        var it = x509.extensions.iterate(s, cert);
        while (it.next() catch return error.MalformedExtensions) |entry| {
            switch (entry.id orelse continue) {
                .key_usage => {
                    facts.key_usage = x509.extensions.parseKeyUsage(entry.value) catch
                        return error.MalformedExtensions;
                    facts.key_usage_critical = entry.critical;
                },
                .basic_constraints => facts.basic_constraints =
                    x509.extensions.parseBasicConstraints(entry.value) catch
                        return error.MalformedExtensions,
                .ext_key_usage => {
                    facts.ext_key_usage_present = true;
                    facts.has_required_purpose = x509.extensions.hasPurpose(entry.value, want) catch
                        return error.MalformedExtensions;
                },
                else => {},
            }
        }
    }
    return facts;
}

// ── violations ──────────────────────────────────────────────────────────────

/// Every rule this policy can fail, named after the requirement rather than
/// after the code that checks it. A caller logs the first one, or the whole
/// set.
pub const Violation = enum {
    // Session.
    tls_version_below_minimum,
    cipher_suite_not_permitted,
    cipher_suite_forbidden,
    compression_enabled,
    secure_renegotiation_missing,
    mutual_authentication_missing,
    session_lifetime_exceeded,
    session_data_volume_exceeded,
    resumption_not_permitted,
    resumption_ticket_too_old,
    chain_not_validated,
    revocation_not_checked,

    // Certificate.
    certificate_expired,
    certificate_not_yet_valid,
    certificate_validity_too_long,
    certificate_version_below_v3,
    certificate_key_too_short,
    certificate_key_algorithm_not_permitted,
    certificate_curve_not_permitted,
    certificate_signature_algorithm_weak,
    certificate_key_usage_missing,
    certificate_key_usage_not_digital_signature,
    certificate_key_usage_not_critical,
    certificate_is_a_ca,
    certificate_ext_key_usage_missing,
    certificate_purpose_not_permitted,
};

/// The outcome of a check: the set of rules that failed, in a fixed order so
/// `first` is deterministic.
pub const Report = struct {
    violations: std.EnumSet(Violation) = .initEmpty(),

    pub fn ok(r: Report) bool {
        return r.violations.count() == 0;
    }

    pub fn count(r: Report) usize {
        return r.violations.count();
    }

    pub fn has(r: Report, v: Violation) bool {
        return r.violations.contains(v);
    }

    /// The lowest-numbered violation, i.e. the first rule in declaration
    /// order that failed. Deterministic, so it can be asserted in a test.
    pub fn first(r: Report) ?Violation {
        var it = r.violations.iterator();
        return it.next();
    }

    fn add(r: *Report, v: Violation) void {
        r.violations.insert(v);
    }
};

// ── the profile ─────────────────────────────────────────────────────────────

pub const Profile = struct {
    /// Lowest acceptable negotiated version.
    min_version: TlsVersion = .tls12,
    /// Suites the profile permits. Empty means "any suite not on
    /// `forbidden_cipher_suites`", which is how a deployment relaxes to a
    /// stack whose suite list it does not fully control.
    allowed_cipher_suites: []const CipherSuite = &default_allowed_suites,
    /// Suites rejected outright even if `allowed_cipher_suites` is empty.
    forbidden_cipher_suites: []const CipherSuite = &default_forbidden_suites,
    /// TLS-level compression must be off.
    forbid_compression: bool = true,
    /// RFC 5746 secure renegotiation must have been negotiated.
    require_secure_renegotiation: bool = true,
    /// The peer must have presented a certificate.
    require_mutual_authentication: bool = true,
    /// The caller must have run path validation.
    require_chain_validation: bool = true,
    /// The caller must have checked revocation.
    require_revocation_check: bool = true,
    /// Longest a session may run before it must be renegotiated or closed.
    /// Default: 24 hours. 0 disables the check.
    max_session_age_s: u64 = 24 * 60 * 60,
    /// Most data a session may carry before renegotiation. 0 disables.
    max_session_bytes: u64 = 0,
    /// Whether session resumption may be used at all.
    allow_resumption: bool = true,
    /// Longest a resumption ticket/session may be reused. Default: 24 hours.
    /// 0 disables the check.
    max_resumption_age_s: u64 = 24 * 60 * 60,

    /// Minimum RSA modulus size, in bits.
    min_rsa_bits: usize = 2048,
    /// Minimum EC field size, in bits.
    min_ec_bits: usize = 256,
    /// Key algorithms the profile permits.
    allowed_key_kinds: []const KeyKind = &.{ .rsa, .ecdsa },
    /// Named curves the profile permits. Empty means "any".
    allowed_curves: []const Certificate.NamedCurve = &.{ .X9_62_prime256v1, .secp384r1 },
    /// Certificate signature algorithms the profile rejects as weak.
    weak_signature_algorithms: []const Certificate.Algorithm = &default_weak_signature_algorithms,
    /// The certificate's `keyUsage` must be present, must assert
    /// `digitalSignature`, and must be marked critical.
    require_digital_signature_key_usage: bool = true,
    require_key_usage_critical: bool = true,
    /// An end-entity TLS certificate must not be a CA certificate.
    forbid_ca_certificate: bool = true,
    /// `extKeyUsage` must be present and must list `required_purpose`.
    require_ext_key_usage: bool = true,
    required_purpose: x509.extensions.Purpose = .client_auth,
    /// Longest certificate validity period accepted, in seconds. Default:
    /// three years, the ceiling utility PKI practice converged on. 0 disables.
    max_certificate_validity_s: u64 = 3 * 365 * 24 * 60 * 60,

    pub const default_allowed_suites = [_]CipherSuite{
        // The suite IEC 62351-4:2018 names as mandatory-to-implement for the
        // native mode, plus the AEAD suites the same tables recommend.
        .tls_rsa_with_aes_128_cbc_sha256,
        .tls_rsa_with_aes_256_cbc_sha256,
        .tls_dhe_rsa_with_aes_128_cbc_sha256,
        .tls_dhe_rsa_with_aes_256_cbc_sha256,
        .tls_dhe_rsa_with_aes_128_gcm_sha256,
        .tls_dhe_rsa_with_aes_256_gcm_sha384,
        .tls_dh_rsa_with_aes_128_gcm_sha256,
        .tls_dh_rsa_with_aes_256_gcm_sha384,
        .tls_ecdhe_rsa_with_aes_128_gcm_sha256,
        .tls_ecdhe_rsa_with_aes_256_gcm_sha384,
        .tls_ecdhe_ecdsa_with_aes_128_gcm_sha256,
        .tls_ecdhe_ecdsa_with_aes_256_gcm_sha384,
        // TLS 1.3.
        .tls_aes_128_gcm_sha256,
        .tls_aes_256_gcm_sha384,
        .tls_chacha20_poly1305_sha256,
    };

    pub const default_forbidden_suites = [_]CipherSuite{
        .tls_rsa_with_rc4_128_sha,
        .tls_rsa_with_3des_ede_cbc_sha,
        .tls_dhe_rsa_with_3des_ede_cbc_sha,
    };

    pub const default_weak_signature_algorithms = [_]Certificate.Algorithm{
        .md2WithRSAEncryption,
        .md5WithRSAEncryption,
        .sha1WithRSAEncryption,
    };

    /// The profile as this module models IEC 62351-3:2018 — every default
    /// above, unchanged. Named so a caller's intent is visible at the call
    /// site and a deviation is a visible override.
    pub const iec62351_3: Profile = .{};

    /// A TLS-1.3-only tightening: no CBC suites, no resumption, shorter
    /// session lifetime. Offered because "the profile's floor" and "what a
    /// greenfield deployment should actually do" are not the same thing.
    pub const strict_tls13: Profile = .{
        .min_version = .tls13,
        .allowed_cipher_suites = &.{
            .tls_aes_128_gcm_sha256,
            .tls_aes_256_gcm_sha384,
            .tls_chacha20_poly1305_sha256,
        },
        .allow_resumption = false,
        .max_session_age_s = 8 * 60 * 60,
    };

    /// Check the negotiated session parameters alone.
    pub fn checkSession(p: Profile, s: SessionDescription) Report {
        var r: Report = .{};
        if (!s.version.atLeast(p.min_version)) r.add(.tls_version_below_minimum);

        for (p.forbidden_cipher_suites) |c| {
            if (c == s.cipher_suite) r.add(.cipher_suite_forbidden);
        }
        if (p.allowed_cipher_suites.len != 0) {
            var permitted = false;
            for (p.allowed_cipher_suites) |c| {
                if (c == s.cipher_suite) permitted = true;
            }
            if (!permitted) r.add(.cipher_suite_not_permitted);
        }

        if (p.forbid_compression and s.compression) r.add(.compression_enabled);
        if (p.require_secure_renegotiation and !s.secure_renegotiation) r.add(.secure_renegotiation_missing);
        if (p.require_mutual_authentication and !s.mutual_authentication) r.add(.mutual_authentication_missing);
        if (p.max_session_age_s != 0 and s.age_s > p.max_session_age_s) r.add(.session_lifetime_exceeded);
        if (p.max_session_bytes != 0 and s.bytes_transferred > p.max_session_bytes) r.add(.session_data_volume_exceeded);
        if (s.resumed) {
            if (!p.allow_resumption) r.add(.resumption_not_permitted);
            if (p.max_resumption_age_s != 0 and s.resumption_age_s > p.max_resumption_age_s) {
                r.add(.resumption_ticket_too_old);
            }
        }
        if (p.require_chain_validation and !s.chain_validated) r.add(.chain_not_validated);
        if (p.require_revocation_check and !s.revocation_checked) r.add(.revocation_not_checked);
        return r;
    }

    /// Check a certificate's facts against the profile at time `now_s`
    /// (seconds since the UTC epoch — injected, never read from a clock).
    pub fn checkCertificateFacts(p: Profile, f: CertificateFacts, now_s: u64) Report {
        var r: Report = .{};

        if (now_s > f.not_after_s) r.add(.certificate_expired);
        if (now_s < f.not_before_s) r.add(.certificate_not_yet_valid);
        if (p.max_certificate_validity_s != 0 and f.not_after_s > f.not_before_s and
            f.not_after_s - f.not_before_s > p.max_certificate_validity_s)
        {
            r.add(.certificate_validity_too_long);
        }
        if (f.version != .v3) r.add(.certificate_version_below_v3);

        var kind_ok = p.allowed_key_kinds.len == 0;
        for (p.allowed_key_kinds) |k| {
            if (k == f.key_kind) kind_ok = true;
        }
        if (!kind_ok) r.add(.certificate_key_algorithm_not_permitted);

        switch (f.key_kind) {
            .rsa => if (f.key_bits < p.min_rsa_bits) r.add(.certificate_key_too_short),
            .ecdsa => {
                if (f.key_bits < p.min_ec_bits) r.add(.certificate_key_too_short);
                if (p.allowed_curves.len != 0) {
                    var curve_ok = false;
                    for (p.allowed_curves) |c| {
                        if (f.named_curve == c) curve_ok = true;
                    }
                    if (!curve_ok) r.add(.certificate_curve_not_permitted);
                }
            },
            else => {},
        }

        if (f.signature_algorithm) |alg| {
            for (p.weak_signature_algorithms) |weak| {
                if (weak == alg) r.add(.certificate_signature_algorithm_weak);
            }
        }

        if (p.require_digital_signature_key_usage) {
            if (f.key_usage) |ku| {
                if (!ku.digital_signature) r.add(.certificate_key_usage_not_digital_signature);
            } else {
                r.add(.certificate_key_usage_missing);
            }
            if (p.require_key_usage_critical and f.key_usage != null and !f.key_usage_critical) {
                r.add(.certificate_key_usage_not_critical);
            }
        }
        if (p.forbid_ca_certificate) {
            if (f.basic_constraints) |bc| {
                if (bc.is_ca) r.add(.certificate_is_a_ca);
            }
            if (f.key_usage) |ku| {
                if (ku.key_cert_sign) r.add(.certificate_is_a_ca);
            }
        }
        if (p.require_ext_key_usage) {
            if (!f.ext_key_usage_present) {
                r.add(.certificate_ext_key_usage_missing);
            } else if (!f.has_required_purpose) {
                r.add(.certificate_purpose_not_permitted);
            }
        }
        return r;
    }

    /// `checkCertificateFacts` straight from DER.
    pub fn checkCertificate(p: Profile, der_bytes: []const u8, now_s: u64) InspectError!Report {
        const facts = try inspectCertificate(der_bytes, p.required_purpose);
        return p.checkCertificateFacts(facts, now_s);
    }

    /// The whole conformance question in one call: session parameters plus
    /// peer certificate. The two reports are merged, so a caller sees every
    /// rule that failed rather than only the first layer's.
    pub fn check(
        p: Profile,
        der_bytes: []const u8,
        s: SessionDescription,
        now_s: u64,
    ) InspectError!Report {
        var r = p.checkSession(s);
        const cert = try p.checkCertificate(der_bytes, now_s);
        r.violations.setUnion(cert.violations);
        return r;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

const conforming_session: SessionDescription = .{
    .version = .tls12,
    .cipher_suite = .tls_ecdhe_rsa_with_aes_128_gcm_sha256,
};

test "a conforming session passes with no violations" {
    const r = Profile.iec62351_3.checkSession(conforming_session);
    try testing.expect(r.ok());
    try testing.expect(r.first() == null);
}

test "the mandatory-to-implement suite is on the allow-list" {
    var s = conforming_session;
    s.cipher_suite = .tls_rsa_with_aes_128_cbc_sha256;
    try testing.expect(Profile.iec62351_3.checkSession(s).ok());
}

test "TLS below the floor is a named violation" {
    var s = conforming_session;
    s.version = .tls11;
    const r = Profile.iec62351_3.checkSession(s);
    try testing.expect(r.has(.tls_version_below_minimum));
    try testing.expectEqual(Violation.tls_version_below_minimum, r.first().?);

    s.version = .tls13;
    try testing.expect(Profile.iec62351_3.checkSession(s).ok());
    // ...but the strict profile still rejects a TLS 1.2 session.
    var s12 = conforming_session;
    try testing.expect(Profile.strict_tls13.checkSession(s12).has(.tls_version_below_minimum));
    s12.version = .tls13;
    s12.cipher_suite = .tls_aes_128_gcm_sha256;
    try testing.expect(Profile.strict_tls13.checkSession(s12).ok());
}

test "obsolete suites are rejected twice over: forbidden and not permitted" {
    var s = conforming_session;
    s.cipher_suite = .tls_rsa_with_rc4_128_sha;
    const r = Profile.iec62351_3.checkSession(s);
    try testing.expect(r.has(.cipher_suite_forbidden));
    try testing.expect(r.has(.cipher_suite_not_permitted));

    s.cipher_suite = .tls_rsa_with_3des_ede_cbc_sha;
    try testing.expect(Profile.iec62351_3.checkSession(s).has(.cipher_suite_forbidden));
}

test "an unknown cipher-suite code point is not permitted, and does not crash" {
    var s = conforming_session;
    s.cipher_suite = @enumFromInt(0xdead);
    const r = Profile.iec62351_3.checkSession(s);
    try testing.expect(r.has(.cipher_suite_not_permitted));
    try testing.expect(!r.has(.cipher_suite_forbidden));
}

test "compression, renegotiation and mutual authentication are each checked" {
    {
        var s = conforming_session;
        s.compression = true;
        try testing.expect(Profile.iec62351_3.checkSession(s).has(.compression_enabled));
    }
    {
        var s = conforming_session;
        s.secure_renegotiation = false;
        try testing.expect(Profile.iec62351_3.checkSession(s).has(.secure_renegotiation_missing));
    }
    {
        var s = conforming_session;
        s.mutual_authentication = false;
        try testing.expect(Profile.iec62351_3.checkSession(s).has(.mutual_authentication_missing));
    }
}

test "session lifetime, data volume and resumption bounds" {
    {
        var s = conforming_session;
        s.age_s = 25 * 60 * 60;
        try testing.expect(Profile.iec62351_3.checkSession(s).has(.session_lifetime_exceeded));
    }
    {
        var p = Profile.iec62351_3;
        p.max_session_bytes = 1 << 30;
        var s = conforming_session;
        s.bytes_transferred = (1 << 30) + 1;
        try testing.expect(p.checkSession(s).has(.session_data_volume_exceeded));
    }
    {
        var s = conforming_session;
        s.resumed = true;
        s.resumption_age_s = 48 * 60 * 60;
        const r = Profile.iec62351_3.checkSession(s);
        try testing.expect(r.has(.resumption_ticket_too_old));
        try testing.expect(!r.has(.resumption_not_permitted));
        // The strict profile forbids resumption outright.
        var s13 = s;
        s13.version = .tls13;
        s13.cipher_suite = .tls_aes_128_gcm_sha256;
        try testing.expect(Profile.strict_tls13.checkSession(s13).has(.resumption_not_permitted));
    }
    {
        // A non-resumed session never trips the resumption rules.
        var s = conforming_session;
        s.resumption_age_s = 1 << 40;
        try testing.expect(Profile.iec62351_3.checkSession(s).ok());
    }
}

test "the caller's own assertions about chain validation and revocation are checked" {
    {
        var s = conforming_session;
        s.chain_validated = false;
        try testing.expect(Profile.iec62351_3.checkSession(s).has(.chain_not_validated));
    }
    {
        var s = conforming_session;
        s.revocation_checked = false;
        try testing.expect(Profile.iec62351_3.checkSession(s).has(.revocation_not_checked));
    }
}

test "several violations at once are all reported, and first() is deterministic" {
    var s = conforming_session;
    s.version = .tls10;
    s.cipher_suite = .tls_rsa_with_rc4_128_sha;
    s.compression = true;
    const r = Profile.iec62351_3.checkSession(s);
    try testing.expectEqual(@as(usize, 4), r.count());
    try testing.expectEqual(Violation.tls_version_below_minimum, r.first().?);
}

// ── certificate checks against real DER ─────────────────────────────────────

const rsa_mod = @import("rsa");
const keys = @import("test_keys.zig");

const year_s: u64 = 365 * 24 * 60 * 60;

/// Build a self-signed certificate with this repository's `rsa` module.
/// Synthetic test material — no key or certificate here comes from any real
/// system.
fn makeCert(
    gpa: std.mem.Allocator,
    bits: enum { rsa2048, rsa1024 },
    not_before: []const u8,
    not_after: []const u8,
    is_ca: bool,
) ![]u8 {
    var sk = switch (bits) {
        .rsa2048 => try keys.rsa2048SecretKey(),
        .rsa1024 => try keys.rsa1024SecretKey(),
    };
    defer sk.deinit();
    const pk = switch (bits) {
        .rsa2048 => try keys.rsa2048PublicKey(),
        .rsa1024 => try keys.rsa1024PublicKey(),
    };
    return rsa_mod.selfSignedCert(gpa, sk, pk, std.crypto.hash.sha2.Sha256, .{
        .common_name = "iec62351-test",
        .serial = 1,
        .not_before = not_before,
        .not_after = not_after,
        .is_ca = is_ca,
        .subject_alt_names = &.{.{ .dns_name = "ied.example.invalid" }},
    });
}

/// 2020-01-01T00:00:00Z .. 2021-01-01T00:00:00Z, and a "now" inside it.
const nb = "200101000000Z";
const na = "210101000000Z";
const inside_s: u64 = 1_593_561_600; // 2020-07-01

test "inspectCertificate reads the facts the policy needs out of real DER" {
    const gpa = testing.allocator;
    const der = try makeCert(gpa, .rsa2048, nb, na, false);
    defer gpa.free(der);

    const f = try inspectCertificate(der, .client_auth);
    try testing.expectEqual(KeyKind.rsa, f.key_kind);
    try testing.expectEqual(@as(usize, 2048), f.key_bits);
    try testing.expectEqual(Certificate.Version.v3, f.version);
    try testing.expectEqual(Certificate.Algorithm.sha256WithRSAEncryption, f.signature_algorithm.?);
    try testing.expect(f.key_usage.?.digital_signature);
    try testing.expect(f.key_usage_critical);
    try testing.expect(!f.basic_constraints.?.is_ca);
    // `rsa.selfSignedCert` emits no extKeyUsage.
    try testing.expect(!f.ext_key_usage_present);
}

test "a real certificate passes once the profile's extKeyUsage rule is relaxed" {
    const gpa = testing.allocator;
    const der = try makeCert(gpa, .rsa2048, nb, na, false);
    defer gpa.free(der);

    var p = Profile.iec62351_3;
    // The generator emits no extKeyUsage; the rest of the profile stands.
    p.require_ext_key_usage = false;
    const r = try p.checkCertificate(der, inside_s);
    try testing.expect(r.ok());

    // With the rule on, the missing extension is the named violation.
    const strict = try Profile.iec62351_3.checkCertificate(der, inside_s);
    try testing.expectEqual(@as(usize, 1), strict.count());
    try testing.expect(strict.has(.certificate_ext_key_usage_missing));
}

test "an expired certificate fails, and a not-yet-valid one fails differently" {
    const gpa = testing.allocator;
    const der = try makeCert(gpa, .rsa2048, nb, na, false);
    defer gpa.free(der);
    var p = Profile.iec62351_3;
    p.require_ext_key_usage = false;

    const after: u64 = 1_700_000_000; // 2023
    const expired = try p.checkCertificate(der, after);
    try testing.expect(expired.has(.certificate_expired));
    try testing.expect(!expired.has(.certificate_not_yet_valid));

    const before: u64 = 1_500_000_000; // 2017
    const early = try p.checkCertificate(der, before);
    try testing.expect(early.has(.certificate_not_yet_valid));
    try testing.expect(!early.has(.certificate_expired));
}

test "a short RSA key fails the minimum-key-size rule" {
    const gpa = testing.allocator;
    const der = try makeCert(gpa, .rsa1024, nb, na, false);
    defer gpa.free(der);
    var p = Profile.iec62351_3;
    p.require_ext_key_usage = false;

    const r = try p.checkCertificate(der, inside_s);
    try testing.expect(r.has(.certificate_key_too_short));

    // A deployment that has to accept 1024 bits says so explicitly.
    p.min_rsa_bits = 1024;
    try testing.expect((try p.checkCertificate(der, inside_s)).ok());
}

test "a CA certificate is refused as a TLS end-entity certificate" {
    const gpa = testing.allocator;
    const der = try makeCert(gpa, .rsa2048, nb, na, true);
    defer gpa.free(der);
    var p = Profile.iec62351_3;
    p.require_ext_key_usage = false;

    const r = try p.checkCertificate(der, inside_s);
    try testing.expect(r.has(.certificate_is_a_ca));
}

test "wrong key usage: a real certificate patched to drop digitalSignature fails" {
    const gpa = testing.allocator;
    const der = try makeCert(gpa, .rsa2048, nb, na, false);
    defer gpa.free(der);

    // Locate the keyUsage extension (OID 2.5.29.15 = 55 1d 0f) and rewrite
    // its BIT STRING from `digitalSignature` (0x80) to `keyEncipherment`
    // (0x20). The signature is deliberately NOT recomputed: this policy does
    // not verify signatures — that is `x509.verifyChain`'s job — so patching
    // in place is the honest way to get a certificate with the wrong usage
    // without inventing a second certificate builder.
    const oid = [_]u8{ 0x06, 0x03, 0x55, 0x1d, 0x0f };
    const at = std.mem.indexOf(u8, der, &oid).?;
    // ... 06 03 55 1d 0f 01 01 ff 04 04 03 02 <unused> <bits>
    const bits_at = at + oid.len + 3 + 2 + 2 + 1;
    try testing.expectEqual(@as(u8, 0x80), der[bits_at]);
    der[bits_at - 1] = 0x05; // unused bits for a single 0x20 bit
    der[bits_at] = 0x20; // keyEncipherment only

    var p = Profile.iec62351_3;
    p.require_ext_key_usage = false;
    const f = try inspectCertificate(der, .client_auth);
    try testing.expect(!f.key_usage.?.digital_signature);
    try testing.expect(f.key_usage.?.key_encipherment);

    const r = try p.checkCertificate(der, inside_s);
    try testing.expect(r.has(.certificate_key_usage_not_digital_signature));
}

test "a malformed certificate is a typed error, not a crash" {
    try testing.expectError(error.MalformedCertificate, inspectCertificate(&.{}, .client_auth));
    try testing.expectError(error.MalformedCertificate, inspectCertificate(
        &.{ 0x30, 0x03, 0x02, 0x01, 0x00 },
        .client_auth,
    ));
}

test "check() merges the session and certificate reports" {
    const gpa = testing.allocator;
    const der = try makeCert(gpa, .rsa1024, nb, na, false);
    defer gpa.free(der);

    var p = Profile.iec62351_3;
    p.require_ext_key_usage = false;
    var s = conforming_session;
    s.version = .tls10;

    const r = try p.check(der, s, inside_s);
    try testing.expect(r.has(.tls_version_below_minimum));
    try testing.expect(r.has(.certificate_key_too_short));
    try testing.expectEqual(@as(usize, 2), r.count());
}

// ── facts-level checks (no DER needed) ──────────────────────────────────────

const good_facts: CertificateFacts = .{
    .not_before_s = 0,
    .not_after_s = year_s,
    .key_kind = .ecdsa,
    .key_bits = 256,
    .named_curve = .X9_62_prime256v1,
    .signature_algorithm = .ecdsa_with_SHA256,
    .key_usage = .{ .digital_signature = true },
    .key_usage_critical = true,
    .ext_key_usage_present = true,
    .has_required_purpose = true,
    .basic_constraints = .{ .is_ca = false },
    .version = .v3,
};

test "facts: a conforming ECDSA end-entity certificate passes" {
    try testing.expect(Profile.iec62351_3.checkCertificateFacts(good_facts, year_s / 2).ok());
}

test "facts: each certificate rule fires on its own" {
    const p = Profile.iec62351_3;
    const half = year_s / 2;

    {
        var f = good_facts;
        f.version = .v1;
        try testing.expect(p.checkCertificateFacts(f, half).has(.certificate_version_below_v3));
    }
    {
        var f = good_facts;
        f.named_curve = .secp521r1;
        f.key_bits = 521;
        try testing.expect(p.checkCertificateFacts(f, half).has(.certificate_curve_not_permitted));
    }
    {
        var f = good_facts;
        f.key_kind = .ed25519;
        f.key_bits = 255;
        try testing.expect(p.checkCertificateFacts(f, half).has(.certificate_key_algorithm_not_permitted));
    }
    {
        var f = good_facts;
        f.signature_algorithm = .sha1WithRSAEncryption;
        try testing.expect(p.checkCertificateFacts(f, half).has(.certificate_signature_algorithm_weak));
    }
    {
        var f = good_facts;
        f.key_usage = null;
        try testing.expect(p.checkCertificateFacts(f, half).has(.certificate_key_usage_missing));
    }
    {
        var f = good_facts;
        f.key_usage_critical = false;
        try testing.expect(p.checkCertificateFacts(f, half).has(.certificate_key_usage_not_critical));
    }
    {
        var f = good_facts;
        f.key_usage = .{ .digital_signature = true, .key_cert_sign = true };
        try testing.expect(p.checkCertificateFacts(f, half).has(.certificate_is_a_ca));
    }
    {
        var f = good_facts;
        f.has_required_purpose = false;
        try testing.expect(p.checkCertificateFacts(f, half).has(.certificate_purpose_not_permitted));
    }
    {
        var f = good_facts;
        f.not_after_s = 10 * year_s;
        try testing.expect(p.checkCertificateFacts(f, half).has(.certificate_validity_too_long));
    }
}

test "facts: a certificate valid for exactly the maximum is accepted" {
    var f = good_facts;
    f.not_before_s = 0;
    f.not_after_s = Profile.iec62351_3.max_certificate_validity_s;
    try testing.expect(!Profile.iec62351_3.checkCertificateFacts(f, 1).has(.certificate_validity_too_long));
    f.not_after_s += 1;
    try testing.expect(Profile.iec62351_3.checkCertificateFacts(f, 1).has(.certificate_validity_too_long));
}

test "fuzz: certificate inspection never panics on arbitrary DER" {
    try testing.fuzz({}, fuzzInspect, .{});
}

fn fuzzInspect(_: void, smith: *std.testing.Smith) !void {
    var buf: [200]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u8, 0, buf.len);
    const facts = inspectCertificate(buf[0..len], .client_auth) catch return;
    // Whatever came back must survive the policy without trapping.
    _ = Profile.iec62351_3.checkCertificateFacts(facts, 1_600_000_000);
}

test "fuzz: a real certificate with one octet corrupted never panics" {
    try testing.fuzz({}, fuzzCorrupt, .{});
}

fn fuzzCorrupt(_: void, smith: *std.testing.Smith) !void {
    const gpa = testing.allocator;
    const der = try makeCert(gpa, .rsa2048, nb, na, false);
    defer gpa.free(der);
    const idx = smith.index(der.len);
    der[idx] ^= smith.value(u8);
    const facts = inspectCertificate(der, .client_auth) catch return;
    _ = Profile.iec62351_3.checkCertificateFacts(facts, inside_s);
}
