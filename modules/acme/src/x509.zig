// SPDX-License-Identifier: MIT

//! Minimal X.509/PKCS building blocks for ACME: a small DER encoder, the
//! PKCS#10 certification request (RFC 2986) with a subjectAltName extension
//! request — the one ASN.1 structure an ACME client must *produce* — plus
//! PEM encode/decode and RFC 5915 EC private-key serialization. Reading a
//! CA-supplied certificate (`notAfter`, the ARI CertID, the issuer CN) is the
//! `x509` module's — an independent parser from the encoder here.
//!
//! Scope is deliberately tiny: P-256, P-384 and P-521 keys (ES256 / ES384 /
//! ES512 signatures) and RSA 2048..4096 keys (RS256: sha256WithRSAEncryption;
//! keys are the `rsa` module's), dNSName SANs, RFC 5915, PKCS#1 and PKCS#8
//! key PEM, the RFC 9773 CertID.
//! The CSR uses an **empty subject** — RFC 8555 §7.4 requires the SAN
//! extension to carry the identifiers and Let's Encrypt ignores (and is
//! phasing out) the CN; skipping CN also avoids its 64-byte limit.
//! Everything decodes back: `parseCsr` is the bounds-checked structural
//! parser used by tests and by the mock CA to validate what we emit.

const std = @import("std");
const b64ct = @import("b64ct").standard;
const Allocator = std.mem.Allocator;
const burn = @import("burn.zig");
const rsa = @import("rsa");
/// The `x509` module (named apart from this file, which `root.zig` exports
/// as `acme.x509`): every READ of a CA-supplied certificate goes through it.
const pkix = @import("x509");
const Sha256 = std.crypto.hash.sha2.Sha256;

/// Test-only: the corpus format `Smith.slice` actually reads. A corpus entry is
/// not the frame — the length draw reads a little-endian `u32` first, so a raw
/// CSR would arrive minus its own first four octets, which for DER means minus
/// its outer tag. `testkit/src/fuzz.zig` carries the other two hazards.
const testkit = @import("testkit");
const seedHex = testkit.fuzz.seedHex;

/// p256's burned wrapper, not std's: std's signer leaves the private key and
/// the nonce on the dead stack after every signature (measured 2026-10-08,
/// `stackprobe_test.zig`).
pub const Es256 = @import("p256").EcdsaP256Sha256;
/// ES384 over the `p384` module (same reason).
pub const Es384 = jws.Es384;
/// ES512 over the `p521` module (same reason).
pub const Es512 = jws.Es512;

const jws = @import("jws.zig");
const netaddr = @import("netaddr");
const Alg = jws.Alg;

// ── DER encoding (bottom-up, arena-backed) ──────────────────────────────────

/// `ValueTooLarge` is kept for the public error sets' stability; the shared
/// encoder (`rsa.der_writer`) encodes any length, so it is no longer returned.
pub const DerEncodeError = error{ OutOfMemory, ValueTooLarge };

/// The shared arena-backed DER builder (every helper returns a complete TLV
/// allocated from `a`; use an arena and free everything at once).
const Der = rsa.der_writer.Builder;

// Pre-encoded OID content bytes.
const oid_ec_public_key = "\x2a\x86\x48\xce\x3d\x02\x01"; // 1.2.840.10045.2.1
const oid_p256 = "\x2a\x86\x48\xce\x3d\x03\x01\x07"; // 1.2.840.10045.3.1.7
const oid_ecdsa_sha256 = "\x2a\x86\x48\xce\x3d\x04\x03\x02"; // 1.2.840.10045.4.3.2
const oid_p384 = "\x2b\x81\x04\x00\x22"; // 1.3.132.0.34 (secp384r1)
const oid_ecdsa_sha384 = "\x2a\x86\x48\xce\x3d\x04\x03\x03"; // 1.2.840.10045.4.3.3
const oid_p521 = "\x2b\x81\x04\x00\x23"; // 1.3.132.0.35 (secp521r1)
const oid_ecdsa_sha512 = "\x2a\x86\x48\xce\x3d\x04\x03\x04"; // 1.2.840.10045.4.3.4
const oid_rsa_encryption = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"; // 1.2.840.113549.1.1.1
const oid_sha256_with_rsa = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b"; // 1.2.840.113549.1.1.11

/// The named-curve OID of an EC algorithm. An RSA key has none (`unreachable`:
/// every caller is already on the EC side of an `alg == .rs256` branch).
fn curveOid(alg: Alg) []const u8 {
    return switch (alg) {
        .es256 => oid_p256,
        .es384 => oid_p384,
        .es512 => oid_p521,
        .rs256 => unreachable,
    };
}

/// The signature-algorithm OID of `alg`.
fn sigAlgOid(alg: Alg) []const u8 {
    return switch (alg) {
        .es256 => oid_ecdsa_sha256,
        .es384 => oid_ecdsa_sha384,
        .es512 => oid_ecdsa_sha512,
        .rs256 => oid_sha256_with_rsa,
    };
}

/// AlgorithmIdentifier of the signature algorithm. ecdsa-with-SHA2 omits the
/// parameters (RFC 5758 §3.2); sha256WithRSAEncryption carries an explicit
/// NULL (RFC 4055 §5).
fn sigAlgId(d: Der, alg: Alg) DerEncodeError![]const u8 {
    if (alg == .rs256) return d.seq(&.{ try d.oid(sigAlgOid(alg)), try d.tlv(0x05, "") });
    return d.seq(&.{try d.oid(sigAlgOid(alg))});
}

fn algFromCurveOid(oid: []const u8) ?Alg {
    if (std.mem.eql(u8, oid, oid_p256)) return .es256;
    if (std.mem.eql(u8, oid, oid_p384)) return .es384;
    if (std.mem.eql(u8, oid, oid_p521)) return .es512;
    return null;
}
const oid_extension_request = "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x0e"; // 1.2.840.113549.1.9.14
const oid_subject_alt_name = "\x55\x1d\x11"; // 2.5.29.17
const oid_acme_identifier = "\x2b\x06\x01\x05\x05\x07\x01\x1f"; // 1.3.6.1.5.5.7.1.31 (id-pe-acmeIdentifier)

// ── domain validation ───────────────────────────────────────────────────────

/// LDH hostname check (letters/digits/hyphen labels, 1–63 chars each, ≤253
/// total). Deliberately rejects wildcards — RFC 8555 §7.1.3 allows them
/// only for the dns-01 challenge, which this module does not implement.
pub fn isValidDomain(name: []const u8) bool {
    if (name.len == 0 or name.len > 253) return false;
    var it = std.mem.splitScalar(u8, name, '.');
    while (it.next()) |label| {
        if (label.len == 0 or label.len > 63) return false;
        if (label[0] == '-' or label[label.len - 1] == '-') return false;
        for (label) |c| switch (c) {
            'a'...'z', 'A'...'Z', '0'...'9', '-' => {},
            else => return false,
        };
    }
    return true;
}

/// A wildcard dNSName, `*.` followed by a valid LDH name (RFC 8555 §7.1.3:
/// the asterisk is the whole leftmost label). Only DNS-01 can validate one.
pub fn isValidWildcardDomain(name: []const u8) bool {
    return std.mem.startsWith(u8, name, "*.") and isValidDomain(name[2..]);
}

// ── PKCS#10 CSR ─────────────────────────────────────────────────────────────

pub const CsrError = error{ OutOfMemory, ValueTooLarge, InvalidDomain, SigningFailed, DuplicateExtension };

/// One extra X.509 extension for the CSR's extensionRequest (`csrDerWith`),
/// e.g. `must_staple`. The CA decides which it copies into the certificate.
pub const Extension = struct {
    /// The OID's content octets (no tag/length), e.g. "\x2b\x06\x01\x05\x05\x07\x01\x18".
    oid: []const u8,
    critical: bool = false,
    /// The DER the extnValue OCTET STRING wraps.
    value: []const u8,
};

/// TLS Feature `status_request` (RFC 7633, OCSP Must-Staple): OID
/// 1.3.6.1.5.5.7.1.24, value `SEQUENCE { INTEGER 5 }`.
pub const must_staple: Extension = .{
    .oid = "\x2b\x06\x01\x05\x05\x07\x01\x18",
    .value = "\x30\x03\x02\x01\x05",
};

/// Build a DER-encoded PKCS#10 CSR for `domains`, signed with `key_pair` (a
/// pointer to an `Es256.KeyPair`, an `Es384.KeyPair`, an `Es512.KeyPair`, an
/// `rsa.KeyPair` or a `jws.AnyKeyPair`; ecdsa-with-SHA256 / -SHA384 / -SHA512
/// by curve, sha256WithRSAEncryption for RSA — the SPKI is rsaEncryption with
/// NULL parameters over the PKCS#1 `RSAPublicKey`, the signature algorithm
/// carries a NULL parameter and the signature is the raw PKCS#1 v1.5 value).
/// Structure: version 0, empty subject,
/// the key's SPKI, one extensionRequest attribute carrying subjectAltName =
/// dNSName list. A wildcard (`*.example.org`) is a valid dNSName here; whether
/// it can be validated is the order flow's business. Caller owns the returned
/// bytes.
pub fn csrDer(gpa: Allocator, key_pair: anytype, domains: []const []const u8) CsrError![]u8 {
    return csrDerWith(gpa, key_pair, domains, &.{});
}

/// `csrDer` with `extra` extensions after the subjectAltName in the
/// extensionRequest (autocert `ExtraExtensions`, certbot `--must-staple`).
/// An OID given twice, or the subjectAltName itself, is `DuplicateExtension`.
pub fn csrDerWith(gpa: Allocator, key_pair: anytype, domains: []const []const u8, extra: []const Extension) CsrError![]u8 {
    if (comptime @TypeOf(key_pair.*) == jws.AnyKeyPair) {
        return switch (key_pair.*) {
            inline .es256, .es384, .es512 => |*kp| csrDerTyped(gpa, kp, domains, extra),
            .rs256 => |kp| csrDerTyped(gpa, kp, domains, extra),
        };
    } else {
        return csrDerTyped(gpa, key_pair, domains, extra);
    }
}

fn csrDerTyped(gpa: Allocator, key_pair: anytype, domains: []const []const u8, extra: []const Extension) CsrError![]u8 {
    return burn.run(burn.sign_burn, CsrError![]u8, CsrBody(@TypeOf(key_pair.*)).run, .{ gpa, key_pair, domains, extra });
}

fn CsrBody(comptime KP: type) type {
    return struct {
        fn run(gpa: Allocator, key_pair: *const KP, domains: []const []const u8, extra: []const Extension) CsrError![]u8 {
            return csrDerBody(KP, gpa, key_pair, domains, extra);
        }
    };
}

fn csrDerBody(comptime KP: type, gpa: Allocator, key_pair: *const KP, domains: []const []const u8, extra: []const Extension) CsrError![]u8 {
    const alg = comptime jws.algOf(KP);
    if (domains.len == 0) return error.InvalidDomain;
    for (domains) |name| {
        if (!isValidSanName(name)) return error.InvalidDomain;
    }
    for (extra, 0..) |ext, i| {
        if (std.mem.eql(u8, ext.oid, oid_subject_alt_name)) return error.DuplicateExtension;
        for (extra[0..i]) |prev| if (std.mem.eql(u8, prev.oid, ext.oid)) return error.DuplicateExtension;
    }

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const d: Der = .{ .a = arena.allocator() };

    // SubjectPublicKeyInfo: { { id-ecPublicKey, namedCurve }, BIT STRING key },
    // or for RSA { { rsaEncryption, NULL }, BIT STRING { RSAPublicKey } } —
    // which `rsa` already emits as a finished DER element.
    const spki = if (comptime alg == .rs256) blk: {
        var spki_buf: [rsa.max_spki_der_len]u8 = undefined;
        const spki_der = key_pair.public_key.toSpkiDer(&spki_buf) catch unreachable; // sized for the largest key
        break :blk try d.a.dupe(u8, spki_der);
    } else blk: {
        const pub_sec1 = key_pair.public_key.toUncompressedSec1();
        break :blk try d.seq(&.{
            try d.seq(&.{ try d.oid(oid_ec_public_key), try d.oid(curveOid(alg)) }),
            try d.bitString(&pub_sec1),
        });
    };

    // subjectAltName GeneralNames: dNSName is [2] IMPLICIT IA5String,
    // iPAddress [7] IMPLICIT OCTET STRING of 4 or 16 octets (RFC 5280
    // §4.2.1.6; an IP identifier, RFC 8738 §3).
    const names = try d.a.alloc([]const u8, domains.len);
    for (names, domains) |*slot, name| slot.* = try sanEntry(d, name);
    const san_value = try d.seq(names);
    const san_ext = try d.seq(&.{
        try d.oid(oid_subject_alt_name),
        // criticality omitted (DEFAULT FALSE), then extnValue OCTET STRING.
        try d.tlv(0x04, san_value),
    });
    const ext_list = try d.a.alloc([]const u8, 1 + extra.len);
    ext_list[0] = san_ext;
    for (ext_list[1..], extra) |*slot, ext| {
        slot.* = if (ext.critical)
            try d.seq(&.{ try d.oid(ext.oid), try d.tlv(0x01, "\xff"), try d.tlv(0x04, ext.value) })
        else
            try d.seq(&.{ try d.oid(ext.oid), try d.tlv(0x04, ext.value) });
    }
    const extensions = try d.seq(ext_list);

    // Attributes [0]: one extensionRequest attribute (OID + SET { Extensions }).
    const attribute = try d.seq(&.{
        try d.oid(oid_extension_request),
        try d.tlv(0x31, extensions),
    });
    const attributes = try d.tlv(0xa0, attribute);

    const info = try d.seq(&.{
        try d.tlv(0x02, "\x00"), // version 0
        try d.seq(&.{}), // empty subject — see the module doc
        spki,
        attributes,
    });

    // The signature covers the full DER encoding of certificationRequestInfo.
    const sig_bits = if (comptime alg == .rs256) blk: {
        var rsa_sig: [rsa.max_modulus_len]u8 = undefined;
        const raw = rsa.signPkcs1v15(&key_pair.secret_key, Sha256, info, &rsa_sig) catch return error.SigningFailed;
        break :blk try d.bitString(raw);
    } else blk: {
        const sig = key_pair.sign(info, null) catch return error.SigningFailed;
        var sig_buf: [@TypeOf(sig).der_encoded_length_max]u8 = undefined;
        const sig_der = sig.toDer(&sig_buf);
        break :blk try d.bitString(sig_der);
    };

    const csr = try d.seq(&.{
        info,
        try sigAlgId(d, alg), // ecdsa-with-SHA256/384/512 (params absent) or sha256WithRSAEncryption (NULL)
        sig_bits,
    });
    return gpa.dupe(u8, csr);
}

// ── RFC 8737 TLS-ALPN-01 validation certificate ─────────────────────────────

pub const TlsAlpnError = error{ OutOfMemory, ValueTooLarge, InvalidDomain, SigningFailed };

/// A fixed, wide validity window for the ephemeral validation certificate.
/// The CA connects over TLS immediately to read the `acmeIdentifier`
/// extension and does not path-validate a self-signed leaf, so a constant
/// window avoids needing a system clock. ASN.1 UTCTime (`YYMMDDHHMMSSZ`,
/// `YY` 00–49 ⇒ 20YY): 2000-01-01 … 2049-12-31.
pub const tls_alpn_not_before = "000101000000Z";
pub const tls_alpn_not_after = "491231235959Z";

/// The ALPN protocol the validation certificate is served under (RFC 8737 §3).
pub const tls_alpn_protocol = "acme-tls/1";

/// The self-signed TLS-ALPN-01 validation certificate (RFC 8737): a freshly
/// generated leaf key plus the DER certificate carrying the critical
/// `id-pe-acmeIdentifier` extension and a dNSName SAN for the domain. The
/// caller serves `cert_der` + `key_pem` from a TLS listener under ALPN
/// `acme-tls/1`; running that listener is app-side (out of scope here).
pub const TlsAlpnCert = struct {
    /// The validation certificate, DER.
    cert_der: []u8,
    /// The matching leaf key as an `EC PRIVATE KEY` PEM (RFC 5915).
    key_pem: []u8,

    pub fn deinit(self: *TlsAlpnCert, gpa: Allocator) void {
        gpa.free(self.cert_der);
        gpa.free(self.key_pem);
        self.* = undefined;
    }
};

/// Build the DER of the RFC 8737 self-signed validation certificate for
/// `domain`. Deterministic (same inputs → same bytes) — the keyed core the
/// tests pin. Structure (X.509 v3, `ecdsa-with-SHA256`, empty issuer/subject):
///
///   - `subjectAltName` (critical — empty subject, RFC 5280 §4.2.1.6) with a
///     single dNSName = `domain`.
///   - `id-pe-acmeIdentifier` (1.3.6.1.5.5.7.1.31), **critical**, whose
///     extnValue is `OCTET STRING( OCTET STRING(acme_identifier) )` — the
///     double wrap: extnValue is itself an OCTET STRING wrapping the DER of
///     `Authorization ::= OCTET STRING (SIZE (32))` (RFC 8737 §3).
///
/// `acme_identifier` is `SHA-256(keyAuthorization)` (see `jws.acmeIdentifier`).
/// `serial` is the (positive, minimal, ≤20-byte) INTEGER content. `not_before`
/// / `not_after` are ASN.1 UTCTime strings. Caller owns the returned bytes.
pub fn tlsAlpnCertDer(
    gpa: Allocator,
    key_pair: anytype,
    domain: []const u8,
    acme_identifier: [32]u8,
    serial: []const u8,
    not_before: []const u8,
    not_after: []const u8,
) TlsAlpnError![]u8 {
    if (comptime @TypeOf(key_pair.*) == jws.AnyKeyPair) {
        return switch (key_pair.*) {
            inline .es256, .es384, .es512 => |*kp| tlsAlpnCertDerTyped(gpa, kp, domain, acme_identifier, serial, not_before, not_after),
            // The validation certificate's key is EC by design (it is minted
            // fresh, `tlsAlpnCert`, and never an account key); an RSA pair is refused.
            .rs256 => error.SigningFailed,
        };
    } else {
        return tlsAlpnCertDerTyped(gpa, key_pair, domain, acme_identifier, serial, not_before, not_after);
    }
}

fn tlsAlpnCertDerTyped(
    gpa: Allocator,
    key_pair: anytype,
    domain: []const u8,
    acme_identifier: [32]u8,
    serial: []const u8,
    not_before: []const u8,
    not_after: []const u8,
) TlsAlpnError![]u8 {
    const KP = @TypeOf(key_pair.*);
    const Body = struct {
        fn run(
            g: Allocator,
            kp: *const KP,
            dom: []const u8,
            id: [32]u8,
            ser: []const u8,
            nb: []const u8,
            na: []const u8,
        ) TlsAlpnError![]u8 {
            return tlsAlpnCertDerBody(KP, g, kp, dom, id, ser, nb, na);
        }
    };
    return burn.run(burn.sign_burn, TlsAlpnError![]u8, Body.run, .{ gpa, key_pair, domain, acme_identifier, serial, not_before, not_after });
}

fn tlsAlpnCertDerBody(
    comptime KP: type,
    gpa: Allocator,
    key_pair: *const KP,
    domain: []const u8,
    acme_identifier: [32]u8,
    serial: []const u8,
    not_before: []const u8,
    not_after: []const u8,
) TlsAlpnError![]u8 {
    const alg = comptime jws.algOf(KP);
    if (comptime alg == .rs256) @compileError("the TLS-ALPN-01 validation certificate key is EC (P-256, tlsAlpnCert)");
    if (!isValidDomain(domain) and netaddr.parseIp(domain) == null) return error.InvalidDomain;

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const d: Der = .{ .a = arena.allocator() };

    // SubjectPublicKeyInfo — identical shape to the CSR's.
    const pub_sec1 = key_pair.public_key.toUncompressedSec1();
    const spki = try d.seq(&.{
        try d.seq(&.{ try d.oid(oid_ec_public_key), try d.oid(curveOid(alg)) }),
        try d.bitString(&pub_sec1),
    });

    // AlgorithmIdentifier ecdsa-with-SHA256/384/512 (params absent) — shared by
    // the inner `signature` field and the outer `signatureAlgorithm`.
    const alg_id = try sigAlgId(d, alg);

    // Validity ::= SEQUENCE { notBefore UTCTime, notAfter UTCTime }.
    const validity = try d.seq(&.{
        try d.tlv(0x17, not_before),
        try d.tlv(0x17, not_after),
    });

    // subjectAltName: GeneralNames { [2] dNSName }, marked critical because
    // the subject is empty (RFC 5280 §4.2.1.6).
    const san_names = try d.seq(&.{try sanEntry(d, domain)}); // RFC 8738 §6: an IP as iPAddress
    const san_ext = try d.seq(&.{
        try d.oid(oid_subject_alt_name),
        try d.tlv(0x01, "\xff"), // critical TRUE
        try d.tlv(0x04, san_names), // extnValue OCTET STRING
    });

    // id-pe-acmeIdentifier: critical, extnValue = OCTET STRING wrapping the
    // DER OCTET STRING of the 32-byte identifier (RFC 8737 §3 double wrap).
    const inner_octet = try d.tlv(0x04, &acme_identifier); // Authorization
    const acme_ext = try d.seq(&.{
        try d.oid(oid_acme_identifier),
        try d.tlv(0x01, "\xff"), // critical TRUE (RFC 8737 MUST)
        try d.tlv(0x04, inner_octet), // extnValue OCTET STRING( OCTET STRING(hash) )
    });

    const extensions = try d.tlv(0xa3, try d.seq(&.{ san_ext, acme_ext })); // [3] EXPLICIT

    const name = try d.seq(&.{}); // empty Name — reused for issuer and subject
    const tbs = try d.seq(&.{
        try d.tlv(0xa0, try d.tlv(0x02, "\x02")), // version [0] EXPLICIT INTEGER 2 (v3)
        try d.tlv(0x02, serial), // serialNumber
        alg_id, // signature (must match signatureAlgorithm)
        name, // issuer
        validity,
        name, // subject
        spki,
        extensions,
    });

    // Self-sign the TBSCertificate.
    const sig = key_pair.sign(tbs, null) catch return error.SigningFailed;
    var sig_buf: [@TypeOf(sig).der_encoded_length_max]u8 = undefined;
    const sig_der = sig.toDer(&sig_buf);

    const cert = try d.seq(&.{
        tbs,
        alg_id,
        try d.bitString(sig_der),
    });
    return gpa.dupe(u8, cert);
}

/// Convenience: generate a fresh P-256 leaf key and build the RFC 8737
/// validation certificate for `domain`. `random` supplies the key seed and
/// the serial number (no `std.crypto.random` dependency — pass a CSPRNG such
/// as `std.crypto.random` shims or a seeded PRNG in tests). Uses the fixed
/// `tls_alpn_not_before`/`tls_alpn_not_after` window. Caller owns the result
/// (`TlsAlpnCert.deinit`).
pub fn tlsAlpnCert(
    gpa: Allocator,
    domain: []const u8,
    acme_identifier: [32]u8,
    random: std.Random,
) TlsAlpnError!TlsAlpnCert {
    var seed: [32]u8 = undefined;
    random.bytes(&seed);
    defer std.crypto.secureZero(u8, &seed);
    var key_pair: Es256.KeyPair = undefined;
    Es256.KeyPair.generateDeterministicInto(&key_pair, &seed) catch return error.SigningFailed;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&key_pair));

    // 16-byte positive, minimal serial: force the top byte to 0x01..0x7f so
    // it is nonzero and has no leading-zero / high-bit ambiguity.
    var serial: [16]u8 = undefined;
    random.bytes(&serial);
    serial[0] = (serial[0] & 0x7f) | 0x01;

    const cert_der = try tlsAlpnCertDer(
        gpa,
        &key_pair,
        domain,
        acme_identifier,
        &serial,
        tls_alpn_not_before,
        tls_alpn_not_after,
    );
    errdefer gpa.free(cert_der);
    const key_pem = try ecPrivateKeyToPem(gpa, &key_pair);
    return .{ .cert_der = cert_der, .key_pem = key_pem };
}

// ── bounds-checked DER reading (the decode half) ────────────────────────────

/// One decoded TLV. `start..end` is the content; `hdr` is where the tag
/// byte sits (so `bytes[hdr..end]` is the full element, what signatures
/// cover).
const Elem = struct {
    tag: u8,
    hdr: usize,
    start: usize,
    end: usize,

    fn content(e: Elem, bytes: []const u8) []const u8 {
        return bytes[e.start..e.end];
    }
};

const ReadError = error{Malformed};

/// Fully bounds-checked DER TLV read at `index` (unlike
/// `std.crypto.Certificate.der.Element.parse`, malformed input can never
/// index out of bounds here — malformed CA output must not panic).
fn readElem(bytes: []const u8, index: usize) ReadError!Elem {
    if (index + 2 > bytes.len) return error.Malformed;
    const tag = bytes[index];
    const first = bytes[index + 1];
    var start = index + 2;
    var len: usize = 0;
    if (first < 0x80) {
        len = first;
    } else {
        const len_size: usize = first & 0x7f;
        if (len_size == 0 or len_size > 4) return error.Malformed;
        if (start + len_size > bytes.len) return error.Malformed;
        for (bytes[start..][0..len_size]) |b| len = (len << 8) | b;
        start += len_size;
    }
    if (len > bytes.len or start > bytes.len - len) return error.Malformed;
    return .{ .tag = tag, .hdr = index, .start = start, .end = start + len };
}

fn expectElem(bytes: []const u8, index: usize, tag: u8) ReadError!Elem {
    const e = try readElem(bytes, index);
    if (e.tag != tag) return error.Malformed;
    return e;
}

/// One GeneralName for `name`: iPAddress for an IP literal, else dNSName.
fn sanEntry(d: Der, name: []const u8) DerEncodeError![]const u8 {
    return if (netaddr.parseIp(name)) |ip| switch (ip) {
        .v4 => |q| try d.tlv(0x87, &q),
        .v6 => |b| try d.tlv(0x87, &b),
    } else try d.tlv(0x82, name);
}

/// A SAN value `csrDer` and `tlsAlpnCertDer` accept: an LDH name, a
/// wildcard name, or an IPv4/IPv6 literal (RFC 8738).
fn isValidSanName(name: []const u8) bool {
    return isValidDomain(name) or isValidWildcardDomain(name) or netaddr.parseIp(name) != null;
}

// ── CSR parse-back (test / mock-CA oracle) ──────────────────────────────────

pub const ParseCsrError = error{ OutOfMemory, MalformedCsr, UnsupportedCsr, BadCsrSignature };

/// A structurally validated, signature-checked P-256 CSR.
pub const ParsedCsr = struct {
    gpa: Allocator,
    /// dNSName SAN values, slices into the DER passed to `parseCsr`.
    sans: []const []const u8,
    public_key: Es256.PublicKey,

    pub fn deinit(p: *ParsedCsr) void {
        p.gpa.free(p.sans);
        p.* = undefined;
    }
};

/// `ParsedCsr` for any supported key.
pub const ParsedCsrAny = struct {
    gpa: Allocator,
    /// dNSName SAN values, slices into the DER.
    sans: []const []const u8,
    /// iPAddress SAN values (4 or 16 octets each), slices into the DER.
    ip_sans: []const []const u8 = &.{},
    public_key: jws.AnyPublicKey,

    pub fn deinit(p: *ParsedCsrAny) void {
        p.gpa.free(p.sans);
        p.gpa.free(p.ip_sans);
        p.* = undefined;
    }
};

/// Decode + verify a CSR of the exact shape `csrDer` produces with a P-256
/// key (ES256 / SAN extension request): checks version, algorithms, extracts
/// the dNSName SANs and verifies the self-signature. The oracle half of the
/// encoder — also what the mock CA runs against the client's finalize. A
/// P-384 or P-521 CSR is `UnsupportedCsr` here (see `parseCsrAny`).
pub fn parseCsr(gpa: Allocator, der_bytes: []const u8) ParseCsrError!ParsedCsr {
    var any = try parseCsrAny(gpa, der_bytes);
    switch (any.public_key) {
        .es256 => |k| {
            gpa.free(any.ip_sans);
            return .{ .gpa = gpa, .sans = any.sans, .public_key = k };
        },
        .es384, .es512, .rs256 => {
            any.deinit();
            return error.UnsupportedCsr;
        },
    }
}

/// `parseCsr` for P-256, P-384 and P-521 (ecdsa-with-SHA256 / -SHA384 / -SHA512; the
/// signature algorithm must match the key's curve) and for RSA keys of
/// `jws.rsa_min_bits` .. `jws.rsa_max_bits` bits (rsaEncryption SPKI,
/// sha256WithRSAEncryption — any other RSA signature OID is `UnsupportedCsr`).
pub fn parseCsrAny(gpa: Allocator, der_bytes: []const u8) ParseCsrError!ParsedCsrAny {
    return parseCsrInner(gpa, der_bytes) catch |err| switch (err) {
        error.Malformed => error.MalformedCsr,
        error.OutOfMemory => error.OutOfMemory,
        error.UnsupportedCsr => error.UnsupportedCsr,
        error.BadCsrSignature => error.BadCsrSignature,
    };
}

fn parseCsrInner(
    gpa: Allocator,
    bytes: []const u8,
) (ReadError || error{ OutOfMemory, UnsupportedCsr, BadCsrSignature })!ParsedCsrAny {
    const csr = try expectElem(bytes, 0, 0x30);
    if (csr.end != bytes.len) return error.Malformed; // no trailing garbage

    const info = try expectElem(bytes, csr.start, 0x30);
    const info_full = bytes[info.hdr..info.end]; // signed bytes (header included)

    // version INTEGER 0
    const version = try expectElem(bytes, info.start, 0x02);
    if (!std.mem.eql(u8, version.content(bytes), "\x00")) return error.UnsupportedCsr;
    // subject (content not interpreted)
    const subject = try expectElem(bytes, version.end, 0x30);

    // SPKI: alg = { id-ecPublicKey, prime256v1 }, key = BIT STRING; or
    // { rsaEncryption, NULL } over a PKCS#1 RSAPublicKey.
    const spki = try expectElem(bytes, subject.end, 0x30);
    const spki_alg = try expectElem(bytes, spki.start, 0x30);
    const alg_oid = try expectElem(bytes, spki_alg.start, 0x06);
    const public_key: jws.AnyPublicKey = if (std.mem.eql(u8, alg_oid.content(bytes), oid_rsa_encryption)) blk: {
        const params = try expectElem(bytes, alg_oid.end, 0x05); // NULL, required (RFC 3279 §2.3.1)
        if (params.end != params.start or params.end != spki_alg.end) return error.UnsupportedCsr;
        const rsa_bits = try expectElem(bytes, spki_alg.end, 0x03);
        if (rsa_bits.end != spki.end) return error.Malformed;
        const vk = rsa.VerifyKey.fromDer(bytes[spki.hdr..spki.end]) catch return error.UnsupportedCsr;
        if (vk.bits() < jws.rsa_min_bits or vk.bits() > jws.rsa_max_bits) return error.UnsupportedCsr;
        break :blk .{ .rs256 = vk };
    } else blk: {
        if (!std.mem.eql(u8, alg_oid.content(bytes), oid_ec_public_key)) return error.UnsupportedCsr;
        const curve_oid = try expectElem(bytes, alg_oid.end, 0x06);
        const curve = algFromCurveOid(curve_oid.content(bytes)) orelse return error.UnsupportedCsr;
        const key_bits = try expectElem(bytes, spki_alg.end, 0x03);
        const key_content = key_bits.content(bytes);
        if (key_content.len != 2 + 2 * curve.coordLen() or key_content[0] != 0) return error.UnsupportedCsr;
        break :blk switch (curve) {
            .es256 => .{ .es256 = Es256.PublicKey.fromSec1(key_content[1..]) catch return error.UnsupportedCsr },
            .es384 => .{ .es384 = Es384.PublicKey.fromSec1(key_content[1..]) catch return error.UnsupportedCsr },
            .es512 => .{ .es512 = Es512.PublicKey.fromSec1(key_content[1..]) catch return error.UnsupportedCsr },
            .rs256 => unreachable, // `algFromCurveOid` names curves only
        };
    };
    const alg = public_key.alg();

    // Attributes [0] → extensionRequest → Extensions → subjectAltName.
    const attributes = try expectElem(bytes, spki.end, 0xa0);
    const found = try findSans(gpa, bytes, attributes);
    errdefer {
        gpa.free(found.dns);
        gpa.free(found.ip);
    }

    // signatureAlgorithm must be the ecdsa-with-SHA2 of the key's curve, or
    // sha256WithRSAEncryption for an RSA key (parameters NULL or absent);
    // signature a BIT STRING.
    const sig_alg = try expectElem(bytes, info.end, 0x30);
    const sig_oid = try expectElem(bytes, sig_alg.start, 0x06);
    if (!std.mem.eql(u8, sig_oid.content(bytes), sigAlgOid(alg))) return error.UnsupportedCsr;
    if (alg == .rs256 and sig_oid.end != sig_alg.end) {
        const params = try expectElem(bytes, sig_oid.end, 0x05);
        if (params.end != params.start or params.end != sig_alg.end) return error.Malformed;
    }
    const sig_bits = try expectElem(bytes, sig_alg.end, 0x03);
    const sig_content = sig_bits.content(bytes);
    if (sig_content.len < 1 or sig_content[0] != 0) return error.Malformed;

    switch (public_key) {
        .es256 => |k| {
            const sig = Es256.Signature.fromDer(sig_content[1..]) catch return error.BadCsrSignature;
            sig.verify(info_full, k) catch return error.BadCsrSignature;
        },
        .es384 => |k| {
            const sig = Es384.Signature.fromDer(sig_content[1..]) catch return error.BadCsrSignature;
            sig.verify(info_full, k) catch return error.BadCsrSignature;
        },
        .es512 => |k| {
            const sig = Es512.Signature.fromDer(sig_content[1..]) catch return error.BadCsrSignature;
            sig.verify(info_full, k) catch return error.BadCsrSignature;
        },
        .rs256 => |*k| k.verifyPkcs1v15(Sha256, info_full, sig_content[1..]) catch return error.BadCsrSignature,
    }

    return .{ .gpa = gpa, .sans = found.dns, .ip_sans = found.ip, .public_key = public_key };
}

fn findSans(
    gpa: Allocator,
    bytes: []const u8,
    attributes: Elem,
) (ReadError || error{ OutOfMemory, UnsupportedCsr })!SanLists {
    var attr_at = attributes.start;
    while (attr_at < attributes.end) {
        const attribute = try expectElem(bytes, attr_at, 0x30);
        attr_at = attribute.end;
        const attr_oid = try expectElem(bytes, attribute.start, 0x06);
        if (!std.mem.eql(u8, attr_oid.content(bytes), oid_extension_request)) continue;

        const values = try expectElem(bytes, attr_oid.end, 0x31); // SET
        const extensions = try expectElem(bytes, values.start, 0x30);
        var ext_at = extensions.start;
        while (ext_at < extensions.end) {
            const ext = try expectElem(bytes, ext_at, 0x30);
            ext_at = ext.end;
            const ext_oid = try expectElem(bytes, ext.start, 0x06);
            if (!std.mem.eql(u8, ext_oid.content(bytes), oid_subject_alt_name)) continue;
            var next = try readElem(bytes, ext_oid.end);
            if (next.tag == 0x01) next = try readElem(bytes, next.end); // optional critical BOOLEAN
            if (next.tag != 0x04) return error.Malformed; // extnValue OCTET STRING
            return collectSans(gpa, bytes, next);
        }
    }
    return error.UnsupportedCsr; // no SAN — not a CSR this module produced
}

const SanLists = struct { dns: []const []const u8, ip: []const []const u8 };

fn collectSans(
    gpa: Allocator,
    bytes: []const u8,
    extn_value: Elem,
) (ReadError || error{OutOfMemory})!SanLists {
    const general_names = try expectElem(bytes, extn_value.start, 0x30);
    var dns: std.ArrayList([]const u8) = .empty;
    errdefer dns.deinit(gpa);
    var ip: std.ArrayList([]const u8) = .empty;
    errdefer ip.deinit(gpa);
    var at = general_names.start;
    while (at < general_names.end) {
        const name = try readElem(bytes, at);
        at = name.end;
        switch (name.tag) {
            0x82 => try dns.append(gpa, name.content(bytes)), // dNSName
            0x87 => { // iPAddress
                const octets = name.content(bytes);
                if (octets.len != 4 and octets.len != 16) return error.Malformed;
                try ip.append(gpa, octets);
            },
            else => {},
        }
    }
    const dns_owned = try dns.toOwnedSlice(gpa);
    errdefer gpa.free(dns_owned);
    return .{ .dns = dns_owned, .ip = try ip.toOwnedSlice(gpa) };
}

// ── PEM ─────────────────────────────────────────────────────────────────────

pub const PemDecodeError = error{ OutOfMemory, MissingPemBlock, InvalidPem, LabelTooLong };

const max_pem_label_len = 48;

/// Encode DER as one PEM block (RFC 7468 shape: 64-char base64 lines).
/// Caller owns the result.
pub fn pemEncode(gpa: Allocator, label: []const u8, der_bytes: []const u8) error{OutOfMemory}![]u8 {
    const enc = std.base64.standard.Encoder;
    const b64_text = try gpa.alloc(u8, enc.calcSize(der_bytes.len));
    defer gpa.free(b64_text);
    _ = enc.encode(b64_text, der_bytes);

    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    const w = &out.writer;
    writePem(w, label, b64_text) catch return error.OutOfMemory; // Allocating fails on OOM only
    return out.toOwnedSlice();
}

fn writePem(w: *std.Io.Writer, label: []const u8, b64_text: []const u8) std.Io.Writer.Error!void {
    try w.print("-----BEGIN {s}-----\n", .{label});
    var rest = b64_text;
    while (rest.len > 64) {
        try w.print("{s}\n", .{rest[0..64]});
        rest = rest[64..];
    }
    if (rest.len > 0) try w.print("{s}\n", .{rest});
    try w.print("-----END {s}-----\n", .{label});
}

/// Decode the FIRST `-----BEGIN <label>-----` block in `text` (other labels
/// are skipped). Caller owns the returned DER bytes.
pub fn pemDecode(gpa: Allocator, label: []const u8, text: []const u8) PemDecodeError![]u8 {
    // Not an assert: the label is caller-supplied and both `bufPrint`s below
    // end in `catch unreachable`. An assert compiles out in ReleaseFast and
    // ReleaseSmall, so an over-long label would reach that `unreachable`.
    if (label.len > max_pem_label_len) return error.LabelTooLong;
    var begin_buf: [max_pem_label_len + 16]u8 = undefined;
    var end_buf: [max_pem_label_len + 16]u8 = undefined;
    const begin = std.fmt.bufPrint(&begin_buf, "-----BEGIN {s}-----", .{label}) catch unreachable;
    const end = std.fmt.bufPrint(&end_buf, "-----END {s}-----", .{label}) catch unreachable;

    const bi = std.mem.indexOf(u8, text, begin) orelse return error.MissingPemBlock;
    const body_start = bi + begin.len;
    const ei = std.mem.indexOfPos(u8, text, body_start, end) orelse return error.InvalidPem;
    const body = text[body_start..ei];

    const dec = std.base64.standard.decoderWithIgnore(" \t\r\n");
    const buf = try gpa.alloc(u8, dec.calcSizeUpperBound(body.len));
    errdefer gpa.free(buf);
    const n = dec.decode(buf, body) catch return error.InvalidPem;
    if (n == 0) return error.InvalidPem;
    return gpa.realloc(buf, n) catch |err| switch (err) {
        error.OutOfMemory => buf[0..n], // shrink failing is not fatal
    };
}

/// The longest private-key DER the secret PEM paths handle (a P-256
/// `EC PRIVATE KEY` is 121 bytes, a P-521 one 223).
const max_secret_der = 1024;

/// `pemEncode` for a SECRET DER: constant-time base64 (the `b64ct` module), and the
/// base64 text exists only in a wiped stack buffer and in the one returned
/// allocation — `pemEncode` leaves it in a freed heap block and in the
/// `Allocating` writer's discarded growth buffers.
fn pemEncodeSecret(gpa: Allocator, label: []const u8, der_bytes: []const u8) error{OutOfMemory}![]u8 {
    std.debug.assert(der_bytes.len <= max_secret_der);
    var b64_buf: [b64ct.encodedLen(max_secret_der)]u8 = undefined;
    defer std.crypto.secureZero(u8, &b64_buf);
    const b64_text = b64ct.encode(&b64_buf, der_bytes);

    const lines = (b64_text.len + 63) / 64;
    const begin_len = "-----BEGIN -----\n".len + label.len;
    const end_len = "-----END -----\n".len + label.len;
    const out = try gpa.alloc(u8, begin_len + b64_text.len + lines + end_len);
    var w: std.Io.Writer = .fixed(out);
    writePem(&w, label, b64_text) catch unreachable; // sized exactly above
    std.debug.assert(w.end == out.len);
    return out;
}

/// `pemDecode` for a SECRET DER, into `out` (no allocation): the base64 body
/// is decoded in constant time by `b64ct.decodeIgnoring`, which skips the
/// whitespace itself. Locating the BEGIN/END lines still branches on the
/// text: that decision comes out the same for every key character (a base64
/// character is never `-`), so it reveals the PEM's layout, not the key — the
/// `pem` row of `scripts/checks/ctgrind-expected.tsv` itemises it.
fn pemDecodeSecret(label: []const u8, text: []const u8, out: []u8) PemDecodeError![]u8 {
    if (label.len > max_pem_label_len) return error.LabelTooLong;
    var begin_buf: [max_pem_label_len + 16]u8 = undefined;
    var end_buf: [max_pem_label_len + 16]u8 = undefined;
    const begin = std.fmt.bufPrint(&begin_buf, "-----BEGIN {s}-----", .{label}) catch unreachable;
    const end = std.fmt.bufPrint(&end_buf, "-----END {s}-----", .{label}) catch unreachable;

    const bi = pemBlockStart(text, label) orelse return error.MissingPemBlock;
    const body_start = bi + begin.len;
    // The END line starts at the first '-' after the body: base64 has none,
    // so this scan's compare is false on every key character and it stops at
    // the body's (public) length. Not std.mem.indexOfPos: Boyer-Moore-Horspool
    // indexes its skip table by, and skips by an amount that depends on, the
    // key's base64 characters (ctgrind 2026-10-18, mem.zig findPos). The
    // first block of the label is used.
    const ei = std.mem.indexOfScalarPos(u8, text, body_start, '-') orelse return error.InvalidPem;
    if (!std.mem.startsWith(u8, text[ei..], end)) return error.InvalidPem;
    const body = text[body_start..ei];

    const der_bytes = b64ct.decodeIgnoring(out, body, @import("b64ct").pem_whitespace) catch {
        std.crypto.secureZero(u8, out);
        return error.InvalidPem;
    };
    if (der_bytes.len == 0) return error.InvalidPem;
    return der_bytes;
}

/// Where the first `-----BEGIN <label>-----` block of `text` starts, or null.
/// Safe over text that also holds SECRET blocks of other labels (a key file
/// searched for a label it does not have, a key stored before its chain):
/// a plain `std.mem.indexOf` for the header is Boyer-Moore-Horspool, which
/// would run over every body before the match — or over all of them when the
/// label is absent — indexing its skip table by the key's base64 characters
/// (2026-10-18). This walks the blocks instead: the searches for
/// `-----BEGIN ` and for the end of the header line read only text between
/// blocks and the header lines, and a non-matching block's body is skipped by
/// a scan for its END line's first '-', a compare that is false on every
/// base64 character, so it depends on the body's (public) length only.
pub fn pemBlockStart(text: []const u8, label: []const u8) ?usize {
    const begin = "-----BEGIN ";
    const dashes = "-----";
    var pos: usize = 0;
    while (std.mem.indexOfPos(u8, text, pos, begin)) |bi| {
        const label_start = bi + begin.len;
        const after = text[label_start..];
        if (std.mem.startsWith(u8, after, label) and std.mem.startsWith(u8, after[label.len..], dashes)) return bi;
        // Skip this block: past its header line, then to its END line.
        const line_end = std.mem.indexOfScalarPos(u8, text, label_start, '\n') orelse return null;
        pos = std.mem.indexOfScalarPos(u8, text, line_end, '-') orelse return null;
    }
    return null;
}

/// Number of `-----BEGIN <label>-----` blocks in `text` (`std.mem.count`:
/// for public text, see `pemBlockStart`).
pub fn pemBlockCount(label: []const u8, text: []const u8) error{LabelTooLong}!usize {
    if (label.len > max_pem_label_len) return error.LabelTooLong;
    var begin_buf: [max_pem_label_len + 16]u8 = undefined;
    const begin = std.fmt.bufPrint(&begin_buf, "-----BEGIN {s}-----", .{label}) catch unreachable;
    return std.mem.count(u8, text, begin);
}

// ── EC private key (RFC 5915) ───────────────────────────────────────────────

pub const KeyPemError = error{ OutOfMemory, MissingPemBlock, InvalidPem, MalformedKey, LabelTooLong };

/// Serialize a key pair (a pointer to an `Es256.KeyPair`, an `Es384.KeyPair`,
/// an `Es512.KeyPair` or a `jws.AnyKeyPair`) as an openssl-compatible `EC PRIVATE KEY` PEM
/// (RFC 5915: version 1, private scalar, curve OID, public point).
/// An `rsa.KeyPair` (or a `jws.AnyKeyPair` holding one) is written as the
/// PKCS#1 `RSA PRIVATE KEY` PEM instead — see `rsaPrivateKeyToPem`.
pub fn ecPrivateKeyToPem(gpa: Allocator, key_pair: anytype) error{OutOfMemory}![]u8 {
    const r = privateKeyToPemUnburned(.sec1, gpa, key_pair);
    burn.stack(burn.key_burn);
    return r;
}

/// Serialize a key pair as a PKCS#8 `PRIVATE KEY` PEM (RFC 5958 over RFC
/// 5915, the shape `openssl genpkey` writes: the curve rides in the
/// AlgorithmIdentifier, the inner ECPrivateKey omits the parameters).
pub fn pkcs8PrivateKeyToPem(gpa: Allocator, key_pair: anytype) error{OutOfMemory}![]u8 {
    const r = privateKeyToPemUnburned(.pkcs8, gpa, key_pair);
    burn.stack(burn.key_burn);
    return r;
}

const KeyForm = enum { sec1, pkcs8 };

noinline fn privateKeyToPemUnburned(comptime form: KeyForm, gpa: Allocator, key_pair: anytype) error{OutOfMemory}![]u8 {
    if (comptime @TypeOf(key_pair.*) == jws.AnyKeyPair) {
        return switch (key_pair.*) {
            inline .es256, .es384, .es512 => |*kp| privateKeyToPemTyped(form, gpa, kp),
            .rs256 => |kp| rsaKeyToPem(form, gpa, kp),
        };
    } else if (comptime @TypeOf(key_pair.*) == rsa.KeyPair) {
        return rsaKeyToPem(form, gpa, key_pair);
    } else {
        return privateKeyToPemTyped(form, gpa, key_pair);
    }
}

/// An RSA pair as PKCS#1 `RSA PRIVATE KEY` (`.sec1`, what `openssl rsa
/// -traditional` and autocert write) or PKCS#8 `PRIVATE KEY` (`.pkcs8`),
/// through `rsa`'s own encoder. The PEM is assembled in a wiped stack buffer
/// and only the returned allocation keeps a copy. `rsa`'s base64 is the
/// same constant-time `b64ct` the EC paths use (since 2026-10-17).
fn rsaKeyToPem(comptime form: KeyForm, gpa: Allocator, key_pair: *const rsa.KeyPair) error{OutOfMemory}![]u8 {
    var buf: [rsa.max_private_pem_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &buf);
    const pem = key_pair.secret_key.toPem(switch (form) {
        .sec1 => .pkcs1,
        .pkcs8 => .pkcs8,
    }, &buf) catch unreachable; // max_private_pem_len fits any key rsa accepts
    return gpa.dupe(u8, pem);
}

/// Serialize an RSA key pair as a PKCS#1 `RSA PRIVATE KEY` PEM (RFC 8017
/// A.1.2 — `openssl rsa -traditional`, what autocert writes). `ecPrivateKeyToPem`
/// and `pkcs8PrivateKeyToPem` of a `jws.AnyKeyPair` holding an RSA pair write
/// the same PKCS#1 / the PKCS#8 form, so `Client` needs no case of its own.
/// Caller owns (and should wipe) the returned text.
pub fn rsaPrivateKeyToPem(gpa: Allocator, key_pair: *const rsa.KeyPair) error{OutOfMemory}![]u8 {
    const r = privateKeyToPemUnburned(.sec1, gpa, key_pair);
    burn.stack(burn.key_burn);
    return r;
}

/// Load an RSA key pair from a PEM holding a PKCS#1 `RSA PRIVATE KEY` or a
/// PKCS#8 `PRIVATE KEY` with rsaEncryption (the first such block; other blocks
/// before it are skipped). The public half is derived from the secret key.
/// The key must be `jws.rsa_min_bits` .. `jws.rsa_max_bits` bits, else
/// `MalformedKey`; multi-prime keys and keys `rsa.SecretKey.fromPem` finds
/// inconsistent (`openssl rsa -check` fails) are `MalformedKey` too. The pair
/// goes into `out` (zeroed on error). `rsa`'s PEM decoder is std's base64
/// (not constant-time) into a stack block that `rsa` burns afterwards.
pub fn rsaPrivateKeyFromPem(out: *rsa.KeyPair, text: []const u8) KeyPemError!void {
    const r = rsaKeyFromPemUnburned(out, text);
    burn.stack(burn.key_burn);
    return r;
}

noinline fn rsaKeyFromPemUnburned(out: *rsa.KeyPair, text: []const u8) KeyPemError!void {
    errdefer std.crypto.secureZero(u8, std.mem.asBytes(out));
    const pkcs1 = pemBlockStart(text, "RSA PRIVATE KEY");
    const pkcs8 = pemBlockStart(text, "PRIVATE KEY");
    const start = if (pkcs1 != null and pkcs8 != null) @min(pkcs1.?, pkcs8.?) else (pkcs1 orelse pkcs8 orelse return error.MissingPemBlock);
    rsa.SecretKey.fromPem(&out.secret_key, text[start..]) catch |err| switch (err) {
        error.MissingPemBlock => return error.MissingPemBlock,
        error.InvalidPem => return error.InvalidPem,
        error.UnsupportedPemLabel, error.InvalidDer, error.InvalidPrivateKey => return error.MalformedKey,
    };
    out.public_key = out.secret_key.publicKey();
    const bits = out.public_key.bits();
    if (bits < jws.rsa_min_bits or bits > jws.rsa_max_bits) return error.MalformedKey;
}

fn privateKeyToPemTyped(comptime form: KeyForm, gpa: Allocator, key_pair: anytype) error{OutOfMemory}![]u8 {
    const alg = comptime jws.algOf(@TypeOf(key_pair.*));
    // The DER holds the private scalar: build it in a stack buffer and wipe
    // that, not in an arena whose freed pages would keep it.
    var der_buf: [2048]u8 = undefined;
    defer std.crypto.secureZero(u8, &der_buf);
    var fba = std.heap.FixedBufferAllocator.init(&der_buf);
    const d: Der = .{ .a = fba.allocator() };

    var sk = key_pair.secret_key.toBytes();
    defer std.crypto.secureZero(u8, &sk);
    const pub_sec1 = key_pair.public_key.toUncompressedSec1();
    const der = (switch (form) {
        .sec1 => ecKeyDer(d, alg, true, &sk, &pub_sec1),
        .pkcs8 => pkcs8Der(d, alg, &sk, &pub_sec1),
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ValueTooLarge => unreachable, // fixed-size structure
    };
    return pemEncodeSecret(gpa, switch (form) {
        .sec1 => "EC PRIVATE KEY",
        .pkcs8 => "PRIVATE KEY",
    }, der);
}

/// RFC 5915 ECPrivateKey; `with_params` writes the `[0]` curve OID (top-level
/// `EC PRIVATE KEY` yes, inside PKCS#8 no).
fn ecKeyDer(d: Der, alg: Alg, with_params: bool, sk: []const u8, pub_sec1: []const u8) DerEncodeError![]const u8 {
    const version = try d.tlv(0x02, "\x01"); // ecPrivkeyVer1
    const priv = try d.tlv(0x04, sk);
    const public = try d.tlv(0xa1, try d.bitString(pub_sec1)); // publicKey [1]
    if (!with_params) return d.seq(&.{ version, priv, public });
    const params = try d.tlv(0xa0, try d.oid(curveOid(alg))); // parameters [0]
    return d.seq(&.{ version, priv, params, public });
}

/// RFC 5958 PrivateKeyInfo { version 0, { id-ecPublicKey, curve }, OCTET STRING { ECPrivateKey } }.
fn pkcs8Der(d: Der, alg: Alg, sk: []const u8, pub_sec1: []const u8) DerEncodeError![]const u8 {
    const inner = try ecKeyDer(d, alg, false, sk, pub_sec1);
    return d.seq(&.{
        try d.tlv(0x02, "\x00"),
        try d.seq(&.{ try d.oid(oid_ec_public_key), try d.oid(curveOid(alg)) }),
        try d.tlv(0x04, inner),
    });
}

/// Load a key pair from an `EC PRIVATE KEY` PEM (RFC 5915 — the format
/// `ecPrivateKeyToPem` and `openssl ecparam -genkey` write). `out` is a
/// pointer to an `Es256.KeyPair`, an `Es384.KeyPair`, an `Es512.KeyPair` (the
/// PEM's curve must be that one, else `MalformedKey`) or a `jws.AnyKeyPair` (the PEM's curve
/// picks the variant; the `[0]` parameters are then required). The pair goes
/// into `out` (zeroed on error), never through a return value: a returned
/// pair would sit in the caller's error-union temporary. `gpa` is no longer
/// used (since 2026-10-13 the DER is decoded into a wiped stack buffer, in
/// constant time; a `realloc`ed heap copy could not be wiped) and stays for
/// the signature.
pub fn ecPrivateKeyFromPem(out: anytype, gpa: Allocator, text: []const u8) KeyPemError!void {
    _ = gpa;
    return keyFromPem("EC PRIVATE KEY", .sec1, out, text);
}

/// `ecPrivateKeyFromPem` for a PKCS#8 `PRIVATE KEY` PEM (RFC 5958, what
/// `openssl genpkey` writes and `openssl pkcs8` converts to): an EC key on
/// P-256, P-384 or P-521, the curve taken from the AlgorithmIdentifier.
pub fn pkcs8PrivateKeyFromPem(out: anytype, gpa: Allocator, text: []const u8) KeyPemError!void {
    _ = gpa;
    return keyFromPem("PRIVATE KEY", .pkcs8, out, text);
}

/// Load either PEM form into an `AnyKeyPair`: `EC PRIVATE KEY` first, else
/// `PRIVATE KEY`. EC keys only: an `AnyKeyPair` holds an RSA pair by pointer
/// (`jws.AnyKeyPair.rs256`) and has no storage to load one into, so an RSA
/// PEM is refused (an error, never a key: `InvalidPem` or `MalformedKey` for PKCS#8, `MissingPemBlock` for PKCS#1) —
/// load it with `rsaPrivateKeyFromPem` into a pair of your own and point an
/// `AnyKeyPair` at that.
pub fn privateKeyFromPem(out: *jws.AnyKeyPair, gpa: Allocator, text: []const u8) KeyPemError!void {
    ecPrivateKeyFromPem(out, gpa, text) catch |err| switch (err) {
        error.MissingPemBlock => return pkcs8PrivateKeyFromPem(out, gpa, text),
        else => return err,
    };
}

fn keyFromPem(comptime label: []const u8, comptime form: KeyForm, out: anytype, text: []const u8) KeyPemError!void {
    if (comptime @TypeOf(out.*) == rsa.KeyPair) @compileError("use rsaPrivateKeyFromPem for an RSA key");
    var der_buf: [max_secret_der]u8 = undefined;
    defer std.crypto.secureZero(u8, &der_buf);
    const der_bytes = try pemDecodeSecret(label, text, &der_buf);
    const r = keyFromDerBurned(form, out, der_bytes);
    return r catch error.MalformedKey;
}

fn keyFromDerBurned(comptime form: KeyForm, out: anytype, bytes: []const u8) (ReadError || error{MalformedKey})!void {
    const r = keyFromDer(form, out, bytes);
    burn.stack(burn.key_burn);
    return r;
}

/// Where a decoded key of curve `E` goes: `out` itself when it is that
/// curve's pair, the matching variant of an `AnyKeyPair`, else null.
fn pairDest(comptime E: type, out: anytype) ?*E.KeyPair {
    const Out = @TypeOf(out.*);
    if (Out == E.KeyPair) return out;
    if (Out == jws.AnyKeyPair) {
        if (E == Es256) {
            out.* = .{ .es256 = undefined };
            return &out.es256;
        }
        if (E == Es384) {
            out.* = .{ .es384 = undefined };
            return &out.es384;
        }
        out.* = .{ .es512 = undefined };
        return &out.es512;
    }
    return null;
}

noinline fn keyFromDer(comptime form: KeyForm, out: anytype, bytes: []const u8) (ReadError || error{MalformedKey})!void {
    errdefer std.crypto.secureZero(u8, std.mem.asBytes(out));
    const Out = @TypeOf(out.*);
    // A typed `out` fixes the curve; an `AnyKeyPair` takes it from the key.
    var curve: ?Alg = if (Out == jws.AnyKeyPair) null else jws.algOf(Out);

    var inner = bytes;
    if (form == .pkcs8) {
        // PrivateKeyInfo ::= SEQUENCE { version 0|1, { id-ecPublicKey, curve },
        // OCTET STRING { ECPrivateKey }, ... } — trailing attributes/publicKey ignored.
        const info = try expectElem(bytes, 0, 0x30);
        const version = try expectElem(bytes, info.start, 0x02);
        const v = version.content(bytes);
        if (!std.mem.eql(u8, v, "\x00") and !std.mem.eql(u8, v, "\x01")) return error.MalformedKey;
        const alg_id = try expectElem(bytes, version.end, 0x30);
        const key_oid = try expectElem(bytes, alg_id.start, 0x06);
        if (!std.mem.eql(u8, key_oid.content(bytes), oid_ec_public_key)) return error.MalformedKey;
        const curve_oid = try expectElem(bytes, key_oid.end, 0x06);
        const a = algFromCurveOid(curve_oid.content(bytes)) orelse return error.MalformedKey;
        if (curve) |c| if (c != a) return error.MalformedKey;
        curve = a;
        const octets = try expectElem(bytes, alg_id.end, 0x04);
        inner = octets.content(bytes);
    }

    const seq = try expectElem(inner, 0, 0x30);
    const version = try expectElem(inner, seq.start, 0x02);
    if (!std.mem.eql(u8, version.content(inner), "\x01")) return error.MalformedKey;
    const priv = try expectElem(inner, version.end, 0x04);
    const raw = priv.content(inner);
    if (priv.end < seq.end) {
        const next = try readElem(inner, priv.end);
        if (next.tag == 0xa0) { // [0] parameters: the curve OID, which must agree
            const oid = try expectElem(inner, next.start, 0x06);
            const a = algFromCurveOid(oid.content(inner)) orelse return error.MalformedKey;
            if (curve) |c| if (c != a) return error.MalformedKey;
            curve = a;
        }
    }
    const alg = curve orelse return error.MalformedKey;
    if (raw.len == 0 or raw.len > alg.coordLen()) return error.MalformedKey;
    switch (alg) {
        .es256 => try fillPair(Es256, out, raw),
        .es384 => try fillPair(Es384, out, raw),
        .es512 => try fillPair(Es512, out, raw),
        .rs256 => unreachable, // `curve` only ever holds a curve (`algFromCurveOid`)
    }
}

fn fillPair(comptime E: type, out: anytype, raw: []const u8) error{MalformedKey}!void {
    const dst = pairDest(E, out) orelse return error.MalformedKey;
    var sk: E.SecretKey = .{ .bytes = @splat(0) };
    defer std.crypto.secureZero(u8, std.mem.asBytes(&sk));
    @memcpy(sk.bytes[sk.bytes.len - raw.len ..], raw); // RFC 5915 fixes the length; tolerate short
    E.KeyPair.fromSecretKeyInto(dst, &sk) catch return error.MalformedKey;
}

// ── certificate readers (the `x509` module) ────────────────────────────────

pub const CertError = error{ OutOfMemory, MissingPemBlock, InvalidPem, MalformedCertificate, LabelTooLong };

/// `notAfter` (epoch seconds, UTC) of the FIRST certificate in a PEM chain,
/// read by the `x509` module's bounded walk (an independent parser from the
/// encoder here; CA-supplied DER errors instead of tripping safety checks).
pub fn certNotAfter(gpa: Allocator, cert_pem: []const u8) CertError!u64 {
    const der_bytes = try pemDecode(gpa, "CERTIFICATE", cert_pem);
    defer gpa.free(der_bytes);
    const validity = pkix.chain.certValidity(der_bytes) catch return error.MalformedCertificate;
    return validity.not_after;
}

// ── ARI CertID (RFC 9773 §4.1) ──────────────────────────────────────────────

pub const AriCertIdError = error{ OutOfMemory, MalformedCertificate, NoAuthorityKeyIdentifier };

/// The ARI CertID of a certificate (RFC 9773 §4.1):
/// `base64url(AKI keyIdentifier) "." base64url(serial)`, no padding, where
/// the serial is the content octets of the DER INTEGER (tag and length
/// stripped, a leading 0x00 kept). The certificate needs an
/// authorityKeyIdentifier extension with a keyIdentifier, as every publicly
/// trusted one has. Caller owns the result.
pub fn ariCertId(gpa: Allocator, cert_der: []const u8) AriCertIdError![]u8 {
    const serial = (pkix.chain.certSerialAndIssuer(cert_der) catch return error.MalformedCertificate).serial;
    if (serial.len == 0) return error.MalformedCertificate;
    const key_id = (pkix.chain.certAuthorityKeyId(cert_der) catch return error.MalformedCertificate) orelse
        return error.NoAuthorityKeyIdentifier;
    const out = try gpa.alloc(u8, jws.base64UrlLen(key_id.len) + 1 + jws.base64UrlLen(serial.len));
    const n = jws.base64UrlEncode(out, key_id).len;
    out[n] = '.';
    _ = jws.base64UrlEncode(out[n + 1 ..], serial);
    return out;
}

/// `ariCertId` of the first certificate in a PEM chain.
pub fn ariCertIdFromPem(gpa: Allocator, cert_pem: []const u8) (AriCertIdError || PemDecodeError)![]u8 {
    const der_bytes = try pemDecode(gpa, "CERTIFICATE", cert_pem);
    defer gpa.free(der_bytes);
    return ariCertId(gpa, der_bytes);
}

/// The first commonName (2.5.4.3) value in a certificate's issuer Name, or
/// null (no CN, or the DER does not walk). Used by `Client` to pick an
/// alternate chain by its topmost issuer.
pub fn issuerCommonName(cert_der: []const u8) ?[]const u8 {
    const issuer = (pkix.chain.certSerialAndIssuer(cert_der) catch return null).issuer;
    return pkix.names.nameAttribute(issuer, &pkix.names.oid_common_name) catch null;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// A fixed, non-secret test key pair per seed byte, in static storage (one
/// derivation per seed), so tests pass it by pointer like production code.
fn testKeyPair(comptime seed_byte: u8) *const Es256.KeyPair {
    const S = struct {
        var kp: Es256.KeyPair = undefined;
        var ready = false;
    };
    if (!S.ready) {
        const seed: [Es256.KeyPair.seed_length]u8 = @splat(seed_byte);
        Es256.KeyPair.generateDeterministicInto(&S.kp, &seed) catch unreachable;
        S.ready = true;
    }
    return &S.kp;
}

test "DER: header length forms (short, 0x81, 0x82)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const d: Der = .{ .a = arena.allocator() };

    const short = try d.tlv(0x04, "abc");
    try testing.expectEqualSlices(u8, "\x04\x03abc", short);

    const mid = try d.tlv(0x04, strRepeat("x", 200));
    try testing.expectEqualSlices(u8, "\x04\x81\xc8", mid[0..3]);
    try testing.expectEqual(@as(usize, 203), mid.len);

    const long = try d.tlv(0x04, strRepeat("y", 300));
    try testing.expectEqualSlices(u8, "\x04\x82\x01\x2c", long[0..4]);
    try testing.expectEqual(@as(usize, 304), long.len);

    // Golden: SEQUENCE { INTEGER 0, OCTET STRING "hi" }.
    const seq = try d.seq(&.{ try d.tlv(0x02, "\x00"), try d.tlv(0x04, "hi") });
    try testing.expectEqualSlices(u8, "\x30\x07\x02\x01\x00\x04\x02hi", seq);

    // readElem round-trips the encodings and rejects truncation.
    const e = try readElem(long, 0);
    try testing.expectEqual(@as(usize, 4), e.start);
    try testing.expectEqual(@as(usize, 304), e.end);
    try testing.expectError(error.Malformed, readElem(long[0 .. long.len - 1], 0));
    try testing.expectError(error.Malformed, readElem("\x30", 0));
    try testing.expectError(error.Malformed, readElem("\x30\x85\x01\x01\x01\x01\x01", 0)); // 5-byte length
}

test "CSR: build, parse back, SANs + signature verify" {
    const kp = testKeyPair(42);
    const domains = [_][]const u8{ "example.com", "www.example.com" };
    const der_bytes = try csrDer(testing.allocator, kp, &domains);
    defer testing.allocator.free(der_bytes);

    var parsed = try parseCsr(testing.allocator, der_bytes);
    defer parsed.deinit();
    try testing.expectEqual(@as(usize, 2), parsed.sans.len);
    try testing.expectEqualStrings("example.com", parsed.sans[0]);
    try testing.expectEqualStrings("www.example.com", parsed.sans[1]);
    try testing.expectEqualSlices(
        u8,
        &kp.public_key.toUncompressedSec1(),
        &parsed.public_key.toUncompressedSec1(),
    );

    // Deterministic signing → identical CSR bytes on rebuild.
    const again = try csrDer(testing.allocator, kp, &domains);
    defer testing.allocator.free(again);
    try testing.expectEqualSlices(u8, der_bytes, again);
}

test "CSR: any tampered byte breaks the signature (or the structure)" {
    const kp = testKeyPair(43);
    const der_bytes = try csrDer(testing.allocator, kp, &.{"tamper.example"});
    defer testing.allocator.free(der_bytes);

    // Flip one byte inside the SAN name (deep in certificationRequestInfo).
    const at = std.mem.indexOf(u8, der_bytes, "tamper").?;
    const mutated = try testing.allocator.dupe(u8, der_bytes);
    defer testing.allocator.free(mutated);
    mutated[at] ^= 0x01;
    try testing.expectError(error.BadCsrSignature, parseCsr(testing.allocator, mutated));

    // Truncation errors out (never panics).
    var l: usize = 0;
    while (l < der_bytes.len) : (l += 7) {
        try testing.expect(if (parseCsr(testing.allocator, der_bytes[0..l])) |_| false else |_| true);
    }
}

test "CSR: domain validation" {
    const kp = testKeyPair(44);
    const cases = [_][]const u8{
        "",                  ".",               "example..com", "-bad.example",   "bad-.example",
        "exa mple.com",
        "chybí.diakritika",
        strRepeat("x", 254),
        // A wildcard is only the whole leftmost label (RFC 8555 §7.1.3).
        "*",               "*.",           "**.example.com", "*example.com",
        "a.*.example.com",   "*.*.example.com",
    };
    for (cases) |bad| {
        try testing.expectError(error.InvalidDomain, csrDer(testing.allocator, kp, &.{bad}));
        try testing.expect(!isValidDomain(bad));
        try testing.expect(!isValidWildcardDomain(bad));
    }
    try testing.expectError(error.InvalidDomain, csrDer(testing.allocator, kp, &.{}));
    try testing.expect(isValidDomain("a.example"));
    try testing.expect(isValidDomain("xn--hkyrky-ptac70bc.example"));
    try testing.expect(isValidDomain("127.0.0.1")); // IP-shaped names pass the LDH check (mock/test use)

    // A wildcard is a valid dNSName for the CSR (since 2026-09-30, with
    // DNS-01); it is still not a plain LDH name.
    try testing.expect(isValidWildcardDomain("*.example.com"));
    try testing.expect(!isValidDomain("*.example.com"));
    const der = try csrDer(testing.allocator, kp, &.{ "*.example.com", "example.com" });
    defer testing.allocator.free(der);
    var parsed = try parseCsr(testing.allocator, der);
    defer parsed.deinit();
    try testing.expectEqual(@as(usize, 2), parsed.sans.len);
    try testing.expectEqualStrings("*.example.com", parsed.sans[0]);
}

/// Navigate a self-signed cert and verify its ECDSA signature over the exact
/// TBSCertificate bytes with the embedded public key (test oracle, reusing
/// the file's bounds-checked DER reader).
fn verifySelfSigned(bytes: []const u8) !void {
    const cert = try expectElem(bytes, 0, 0x30);
    const tbs = try expectElem(bytes, cert.start, 0x30);
    const tbs_full = bytes[tbs.hdr..tbs.end];

    const version = try expectElem(bytes, tbs.start, 0xa0);
    const serial = try expectElem(bytes, version.end, 0x02);
    const sig_alg_in = try expectElem(bytes, serial.end, 0x30);
    const issuer = try expectElem(bytes, sig_alg_in.end, 0x30);
    const validity = try expectElem(bytes, issuer.end, 0x30);
    const subject = try expectElem(bytes, validity.end, 0x30);
    const spki = try expectElem(bytes, subject.end, 0x30);
    const spki_alg = try expectElem(bytes, spki.start, 0x30);
    const key_bits = try expectElem(bytes, spki_alg.end, 0x03);
    const key_content = key_bits.content(bytes);
    if (key_content.len != 66 or key_content[0] != 0) return error.Malformed;
    const public_key = try Es256.PublicKey.fromSec1(key_content[1..]);

    const sig_alg = try expectElem(bytes, tbs.end, 0x30);
    const sig_bits = try expectElem(bytes, sig_alg.end, 0x03);
    const sig_content = sig_bits.content(bytes);
    const sig = try Es256.Signature.fromDer(sig_content[1..]);
    try sig.verify(tbs_full, public_key);
}

test "TLS-ALPN-01 cert: RFC 8737 extension encoding + SAN + self-signature" {
    const kp = testKeyPair(70);
    // Oracle acmeIdentifier (cross-referenced in jws.zig's acmeIdentifier test).
    const acme_id = [_]u8{
        0x54, 0x88, 0x65, 0x39, 0xb5, 0x35, 0xe1, 0x2b, 0x33, 0xb8, 0x68, 0x89, 0x8d, 0x81, 0x24, 0x48,
        0x25, 0xb3, 0x6b, 0xdf, 0x97, 0xf9, 0x41, 0x54, 0xbb, 0x31, 0xa1, 0xd5, 0x0b, 0x22, 0x61, 0xc5,
    };
    const der_bytes = try tlsAlpnCertDer(
        testing.allocator,
        kp,
        "example.org",
        acme_id,
        "\x01",
        tls_alpn_not_before,
        tls_alpn_not_after,
    );
    defer testing.allocator.free(der_bytes);

    // RFC 8737 §3, byte-exact: SEQUENCE { OID 1.3.6.1.5.5.7.1.31, critical
    // TRUE, extnValue OCTET STRING( OCTET STRING(32-byte identifier) ) }.
    const acme_ext =
        "\x30\x31" ++ // SEQUENCE, len 0x31 = 49
        "\x06\x08\x2b\x06\x01\x05\x05\x07\x01\x1f" ++ // OID id-pe-acmeIdentifier
        "\x01\x01\xff" ++ // critical BOOLEAN TRUE
        "\x04\x22\x04\x20" ++ // OCTET STRING(len 34) { OCTET STRING(len 32) ... }
        acme_id;
    try testing.expect(std.mem.indexOf(u8, der_bytes, acme_ext) != null);

    // subjectAltName dNSName = the domain ([2] IMPLICIT IA5String).
    try testing.expect(std.mem.indexOf(u8, der_bytes, "\x82\x0b" ++ "example.org") != null);
    // The SAN extension is marked critical (empty subject).
    try testing.expect(std.mem.indexOf(u8, der_bytes, "\x06\x03\x55\x1d\x11\x01\x01\xff") != null);

    // Self-signed: the signature verifies over the TBSCertificate.
    try verifySelfSigned(der_bytes);

    // Deterministic: identical inputs rebuild byte-for-byte.
    const again = try tlsAlpnCertDer(
        testing.allocator,
        kp,
        "example.org",
        acme_id,
        "\x01",
        tls_alpn_not_before,
        tls_alpn_not_after,
    );
    defer testing.allocator.free(again);
    try testing.expectEqualSlices(u8, der_bytes, again);

    // Wildcards / bad domains are rejected (dNSName must be a real host).
    try testing.expectError(error.InvalidDomain, tlsAlpnCertDer(
        testing.allocator,
        kp,
        "*.example.org",
        acme_id,
        "\x01",
        tls_alpn_not_before,
        tls_alpn_not_after,
    ));
}

test "TLS-ALPN-01 cert: tlsAlpnCert convenience generates a usable key + cert" {
    var prng = std.Random.DefaultPrng.init(0x8737);
    const acme_id: [32]u8 = @splat(0xAB);
    var cert = try tlsAlpnCert(testing.allocator, "example.com", acme_id, prng.random());
    defer cert.deinit(testing.allocator);

    // The certificate self-verifies and carries the identifier + SAN.
    try verifySelfSigned(cert.cert_der);
    try testing.expect(std.mem.indexOf(u8, cert.cert_der, "\x04\x22\x04\x20" ++ &acme_id) != null);
    try testing.expect(std.mem.indexOf(u8, cert.cert_der, "\x82\x0b" ++ "example.com") != null);

    // The emitted key PEM parses back and matches the cert's SPKI point.
    var kp: Es256.KeyPair = undefined;
    try ecPrivateKeyFromPem(&kp, testing.allocator, cert.key_pem);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&kp));
    const point = kp.public_key.toUncompressedSec1();
    try testing.expect(std.mem.indexOf(u8, cert.cert_der, &point) != null);
}

// openssl-built fixture for the `id-pe-acmeIdentifier` extension (RFC 8737
// §3): the double-wrap encoding above (extnValue OCTET STRING wrapping the
// DER of `Authorization ::= OCTET STRING (SIZE (32))`) is this module's own
// construction, so it needed a real, independent oracle. openssl has no
// built-in name for this OID, but its generic-extension syntax (`DER:<hex>`)
// accepts caller-supplied extnValue content, builds a real self-signed
// certificate around it, and `openssl x509 -text` / `openssl asn1parse`
// re-parse that certificate back into the SEQUENCE/OID/BOOLEAN/OCTET STRING
// shown below — a genuine build-and-reparse round trip, not a self-check.
// Reproduced with (P-256 key in `key.pem`, hash = the same 32-byte
// `acme_id` used by the test above and by jws.zig's `acmeIdentifier` test):
//
//   openssl req -x509 -new -key key.pem -subj "/" -days 3650 -sha256 \
//     -out cert.pem \
//     -addext "subjectAltName=critical,DNS:example.org" \
//     -addext "1.3.6.1.5.5.7.1.31=critical,DER:0420548865...61c5"
//
//   $ openssl x509 -in cert.pem -noout -text
//     1.3.6.1.5.5.7.1.31: critical
//         . T.e9.5.+3.h...$H%.k...AT.1..."a.
//   $ openssl asn1parse -in cert.der -inform DER | grep -A2 1.3.6.1.5.5.7.1.31
//     288:d=4  hl=2 l=  49 cons: SEQUENCE
//     290:d=5  hl=2 l=   8 prim: OBJECT   :1.3.6.1.5.5.7.1.31
//     300:d=5  hl=2 l=   1 prim: BOOLEAN  :255
//     303:d=5  hl=2 l=  34 prim: OCTET STRING [HEX DUMP]:0420548865...61c5
//
// (openssl also default-adds subjectKeyIdentifier/authorityKeyIdentifier/
// basicConstraints, harmless noise around the extension under test.)
const test_tls_alpn_openssl_cert_pem =
    \\-----BEGIN CERTIFICATE-----
    \\MIIBpTCCAUugAwIBAgIULccuKbyy5iea5LEYnXfYRWUz124wCgYIKoZIzj0EAwIw
    \\ADAeFw0yNjA4MDExNDI2NTJaFw0zNjA3MjkxNDI2NTJaMAAwWTATBgcqhkjOPQIB
    \\BggqhkjOPQMBBwNCAAROuQlU2wcguLnwZh1LmNttftSuMXTH3TNzFOTo6mOle2Nz
    \\LdA9225cMBJe/GrszwZyyRcO7sUX8OOeVr7Zot6Wo4GiMIGfMB0GA1UdDgQWBBS2
    \\Z7RCabPsFuzW/TJZyzg/bloYFTAfBgNVHSMEGDAWgBS2Z7RCabPsFuzW/TJZyzg/
    \\bloYFTAPBgNVHRMBAf8EBTADAQH/MBkGA1UdEQEB/wQPMA2CC2V4YW1wbGUub3Jn
    \\MDEGCCsGAQUFBwEfAQH/BCIEIFSIZTm1NeErM7hoiY2BJEgls2vfl/lBVLsxodUL
    \\ImHFMAoGCCqGSM49BAMCA0gAMEUCIQCorf12038TiYhtWhmaAEdFxHzI3/lcCe+Z
    \\4lzoneFx9wIgeyMQEPrYYNsD9cC2RPbAEa45gZU0GNuAOQUwXs07lF8=
    \\-----END CERTIFICATE-----
    \\
;

test "TLS-ALPN-01 extension: openssl builds + re-parses the same bytes we do" {
    const acme_id = [_]u8{
        0x54, 0x88, 0x65, 0x39, 0xb5, 0x35, 0xe1, 0x2b, 0x33, 0xb8, 0x68, 0x89, 0x8d, 0x81, 0x24, 0x48,
        0x25, 0xb3, 0x6b, 0xdf, 0x97, 0xf9, 0x41, 0x54, 0xbb, 0x31, 0xa1, 0xd5, 0x0b, 0x22, 0x61, 0xc5,
    };
    // Byte-exact, frozen from the `openssl asn1parse` dump above: SEQUENCE {
    // OID id-pe-acmeIdentifier, critical TRUE, extnValue OCTET STRING(34) {
    // OCTET STRING(32) acme_id } } — the real oracle's answer, not derived
    // from this module's own encoder.
    const acme_ext_oracle =
        "\x30\x31" ++
        "\x06\x08\x2b\x06\x01\x05\x05\x07\x01\x1f" ++
        "\x01\x01\xff" ++
        "\x04\x22\x04\x20" ++
        acme_id;
    try testing.expectEqual(@as(usize, 51), acme_ext_oracle.len); // count canary

    const oracle_der = try pemDecode(testing.allocator, "CERTIFICATE", test_tls_alpn_openssl_cert_pem);
    defer testing.allocator.free(oracle_der);
    try testing.expect(std.mem.indexOf(u8, oracle_der, acme_ext_oracle) != null);
    // The oracle certificate is itself a well-formed, self-signed P-256 cert
    // (extra confidence the fixture is real, not truncated/garbled).
    try verifySelfSigned(oracle_der);

    // Our own encoder, fed the identical acme_id, produces the identical
    // extension bytes — the cross-check the governing rule requires: an
    // external answer, compared byte-for-byte against our own output.
    const kp = testKeyPair(70);
    const ours_der = try tlsAlpnCertDer(
        testing.allocator,
        kp,
        "example.org",
        acme_id,
        "\x01",
        tls_alpn_not_before,
        tls_alpn_not_after,
    );
    defer testing.allocator.free(ours_der);
    try testing.expect(std.mem.indexOf(u8, ours_der, acme_ext_oracle) != null);
}

test "PEM: encode/decode round-trip, wrapping, labels, garbage" {
    const payload = "\x01\x02\x03" ++ (strRepeat("D", 100)); // forces a 2-line body
    const pem = try pemEncode(testing.allocator, "CERTIFICATE", payload);
    defer testing.allocator.free(pem);
    try testing.expect(std.mem.startsWith(u8, pem, "-----BEGIN CERTIFICATE-----\n"));
    try testing.expect(std.mem.endsWith(u8, pem, "-----END CERTIFICATE-----\n"));
    // 64-char body lines.
    var lines = std.mem.splitScalar(u8, pem, '\n');
    _ = lines.next(); // BEGIN
    try testing.expectEqual(@as(usize, 64), lines.next().?.len);

    const back = try pemDecode(testing.allocator, "CERTIFICATE", pem);
    defer testing.allocator.free(back);
    try testing.expectEqualSlices(u8, payload, back);

    // Surrounding garbage + a preceding block with another label.
    const noisy = try std.mem.concat(testing.allocator, u8, &.{
        "leading junk\n-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n",
        pem,
        "trailing junk",
    });
    defer testing.allocator.free(noisy);
    const picked = try pemDecode(testing.allocator, "CERTIFICATE", noisy);
    defer testing.allocator.free(picked);
    try testing.expectEqualSlices(u8, payload, picked);
    try testing.expectEqual(@as(usize, 1), try pemBlockCount("CERTIFICATE", noisy));
    try testing.expectEqual(@as(usize, 1), try pemBlockCount("EC PRIVATE KEY", noisy));

    // The length guard used to be an `std.debug.assert`, which compiles out of
    // ReleaseFast/ReleaseSmall — the over-long label then reached the
    // `bufPrint(...) catch unreachable` below it.
    const too_long = strRepeat("A", max_pem_label_len + 1);
    try testing.expectError(error.LabelTooLong, pemBlockCount(too_long, noisy));

    try testing.expectError(error.MissingPemBlock, pemDecode(testing.allocator, "CERTIFICATE REQUEST", noisy));
    try testing.expectError(error.InvalidPem, pemDecode(
        testing.allocator,
        "CERTIFICATE",
        "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n",
    ));
    try testing.expectError(error.InvalidPem, pemDecode(
        testing.allocator,
        "CERTIFICATE",
        "-----BEGIN CERTIFICATE-----\nAAAA", // END marker missing
    ));
}

test "EC private key PEM: round-trip ours, parse openssl's" {
    const kp = testKeyPair(45);
    const pem = try ecPrivateKeyToPem(testing.allocator, kp);
    defer testing.allocator.free(pem);
    var back: Es256.KeyPair = undefined;
    try ecPrivateKeyFromPem(&back, testing.allocator, pem);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&back));
    try testing.expectEqualSlices(u8, &kp.secret_key.toBytes(), &back.secret_key.toBytes());
    try testing.expectEqualSlices(
        u8,
        &kp.public_key.toUncompressedSec1(),
        &back.public_key.toUncompressedSec1(),
    );

    // openssl-generated fixture (openssl ecparam -name prime256v1 -genkey).
    const openssl_key =
        \\-----BEGIN EC PRIVATE KEY-----
        \\MHcCAQEEIPmjCX1tDF32kw9U4M23KMOZT1+KMVELotqIPeVfB6s6oAoGCCqGSM49
        \\AwEHoUQDQgAEb+JvbKV4Cc0ewU3MD9T3q0w0ToXqcJraSE4q5yfZg1FgnKx49uo7
        \\oBZrKpL5YPo7lUbIVH6MSrPk9JrltTXSPg==
        \\-----END EC PRIVATE KEY-----
        \\
    ;
    var parsed: Es256.KeyPair = undefined;
    try ecPrivateKeyFromPem(&parsed, testing.allocator, openssl_key);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&parsed));
    // The [1] public-key BIT STRING in the fixture must match the point we
    // re-derive from the private scalar (cross-checks scalar-mult too).
    const der_bytes = try pemDecode(testing.allocator, "EC PRIVATE KEY", openssl_key);
    defer testing.allocator.free(der_bytes);
    const derived = parsed.public_key.toUncompressedSec1();
    try testing.expect(std.mem.indexOf(u8, der_bytes, &derived) != null);

    var scratch: Es256.KeyPair = undefined;
    try testing.expectError(error.MissingPemBlock, ecPrivateKeyFromPem(&scratch, testing.allocator, "no pem here"));
    try testing.expectError(error.MalformedKey, ecPrivateKeyFromPem(
        &scratch,
        testing.allocator,
        "-----BEGIN EC PRIVATE KEY-----\nMAA=\n-----END EC PRIVATE KEY-----\n",
    ));
}

// openssl req -x509 (P-256): notBefore 2025-01-01T00:00:00Z (1735689600),
// notAfter 2030-12-31T23:59:59Z (1924991999). Shared with root.zig's
// needsRenewal tests and the mock CA.
pub const test_cert_not_after: u64 = 1924991999;
pub const test_cert_pem =
    \\-----BEGIN CERTIFICATE-----
    \\MIIBqjCCAU+gAwIBAgIUVrv8ibqbXrZOhdcCjfShaw5SMFIwCgYIKoZIzj0EAwIw
    \\HDEaMBgGA1UEAwwRYWNtZS10ZXN0LWZpeHR1cmUwHhcNMjUwMTAxMDAwMDAwWhcN
    \\MzAxMjMxMjM1OTU5WjAcMRowGAYDVQQDDBFhY21lLXRlc3QtZml4dHVyZTBZMBMG
    \\ByqGSM49AgEGCCqGSM49AwEHA0IABG/ib2yleAnNHsFNzA/U96tMNE6F6nCa2khO
    \\Kucn2YNRYJysePbqO6AWayqS+WD6O5VGyFR+jEqz5PSa5bU10j6jbzBtMB0GA1Ud
    \\DgQWBBTV5giKKPpSYzcftjnA/sM6fEW6HzAfBgNVHSMEGDAWgBTV5giKKPpSYzcf
    \\tjnA/sM6fEW6HzAPBgNVHRMBAf8EBTADAQH/MBoGA1UdEQQTMBGCD2ZpeHR1cmUu
    \\ZXhhbXBsZTAKBggqhkjOPQQDAgNJADBGAiEAtFqnJ4bJ1VdhYQJ5UJwbdUmI1VUs
    \\I1XJd1xSCaaY3DECIQCQe0e6QlftFHSkNxXMHi2WBAfZGp7+XwODJf9Kkhtvrg==
    \\-----END CERTIFICATE-----
    \\
;

/// A second (independent) fixture: plays the issuer in mock chains.
pub const test_root_cert_pem =
    \\-----BEGIN CERTIFICATE-----
    \\MIIBhjCCAS2gAwIBAgIUSP8yPGtPtcduRGbdIMjNtjPY2VkwCgYIKoZIzj0EAwIw
    \\GTEXMBUGA1UEAwwOYWNtZS10ZXN0LXJvb3QwHhcNMjUwMTAxMDAwMDAwWhcNMzUx
    \\MjMxMjM1OTU5WjAZMRcwFQYDVQQDDA5hY21lLXRlc3Qtcm9vdDBZMBMGByqGSM49
    \\AgEGCCqGSM49AwEHA0IABEWWjTC+x0pS8fXJ7/vMkrU8zVigaQrZR8ltTXdoHeza
    \\LkAYE/juoYp/Jc4WiQSyO/KNYntLiUmn8JV1qPri7hujUzBRMB0GA1UdDgQWBBTT
    \\yzuCh1F+kLGkAf1zg1uhwyWw7zAfBgNVHSMEGDAWgBTTyzuCh1F+kLGkAf1zg1uh
    \\wyWw7zAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIEinz8NQpsHF
    \\1MTYFbqBqfarZnf2knqOq3/9XVj6uFz+AiAxut3Jdge1TKRIk+pCET6YJqRIFCgG
    \\T52E7TLdhp3fJA==
    \\-----END CERTIFICATE-----
    \\
;

test "certNotAfter: openssl fixture parses to the known epoch" {
    try testing.expectEqual(
        test_cert_not_after,
        try certNotAfter(testing.allocator, test_cert_pem),
    );

    // First-of-chain semantics: leaf ++ root reports the leaf's notAfter.
    const chain = test_cert_pem ++ test_root_cert_pem;
    try testing.expectEqual(test_cert_not_after, try certNotAfter(testing.allocator, chain));

    try testing.expectError(error.MissingPemBlock, certNotAfter(testing.allocator, "nothing"));
    try testing.expectError(error.MalformedCertificate, certNotAfter(
        testing.allocator,
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
    ));
    // Truncated DER inside valid PEM must error, not panic.
    const der_bytes = try pemDecode(testing.allocator, "CERTIFICATE", test_cert_pem);
    defer testing.allocator.free(der_bytes);
    const cut = try pemEncode(testing.allocator, "CERTIFICATE", der_bytes[0 .. der_bytes.len / 2]);
    defer testing.allocator.free(cut);
    try testing.expectError(error.MalformedCertificate, certNotAfter(testing.allocator, cut));
}

// ── fuzz: the CSR DER decoder ──────────────────────────────────────────
//
// ⚠ This harness used to open with `smith.bytes(&buf)` followed by
// `smith.valueRangeAtMost(u16, 0, buf.len)`. `bytes` copies `min(buf.len,
// in.len)` octets and the ranged draw then reads EIGHT more as a little-endian
// u64, returning the range minimum when fewer remain -- so `len` was 0 for
// every input a corpus can carry and `parseCsr` was handed an EMPTY slice while
// the DER sat unread in `buf`. One `slice` draw reads the corpus entry's own
// length header and hands the bytes over intact.

/// The DER shapes `parseCsr` must refuse, in the format the length draw reads.
/// Hand-written because they are structural: a CSR that stops being a
/// SEQUENCE, one with trailing garbage, one whose version is not 0. Everything
/// `parseCsr` ACCEPTS is built by `csrDer` below instead -- there is no
/// captured CSR in this module and a pasted one would freeze a copy of the
/// encoder rather than track it.
const csr_reject_seeds = [_][]const u8{
    seedHex("3000"), // an empty SEQUENCE: nothing inside to read
    seedHex("300602010030008000"), // version 0, empty subject, then a wrong tag
    seedHex("3006020101300000"), // version 1: UnsupportedCsr, not Malformed
    seedHex("31060201003000"), // a SET where the outer SEQUENCE belongs
    seedHex("30"), // a bare tag with no length
    seedHex("308501010101"), // a 5-octet length: refused by readElem
    seedHex("0500"), // ASN.1 NULL: the wrong type entirely
    seedHex("00"), // one octet
};

/// The whole corpus: the refusals above, plus the CSRs this decoder ACCEPTS,
/// which only `csrDer` can produce. Built at run time so the corpus follows the
/// encoder.
///
/// ⭐ The fuzz harness and the corpus guard below both build it from HERE. A
/// guard measuring a different corpus from the one the harness gets is not a
/// guard.
const CsrCorpus = struct {
    one_store: [4 + 1024]u8 = undefined,
    two_store: [4 + 1024]u8 = undefined,
    tampered_store: [4 + 1024]u8 = undefined,
    truncated_store: [4 + 1024]u8 = undefined,
    entries: [csr_reject_seeds.len + 4][]const u8 = undefined,

    fn build(self: *CsrCorpus, gpa: Allocator) ![]const []const u8 {
        @memcpy(self.entries[0..csr_reject_seeds.len], &csr_reject_seeds);

        const one = try csrDer(gpa, testKeyPair(42), &.{"example.com"});
        defer gpa.free(one);
        const two = try csrDer(gpa, testKeyPair(43), &.{ "example.com", "www.example.com" });
        defer gpa.free(two);

        self.entries[csr_reject_seeds.len + 0] = testkit.fuzz.seedInto(&self.one_store, one);
        self.entries[csr_reject_seeds.len + 1] = testkit.fuzz.seedInto(&self.two_store, two);

        // A structurally perfect CSR whose SAN was edited: the one shape that
        // reaches the signature check and fails it. No hand-written literal can
        // stand in for this -- it has to be a real CSR to get that far.
        var tampered: [1024]u8 = undefined;
        @memcpy(tampered[0..one.len], one);
        const at = std.mem.indexOf(u8, tampered[0..one.len], "example").?;
        tampered[at] ^= 0x01;
        self.entries[csr_reject_seeds.len + 2] =
            testkit.fuzz.seedInto(&self.tampered_store, tampered[0..one.len]);

        // Truncated mid-signature: structure walks, then runs off the end.
        self.entries[csr_reject_seeds.len + 3] =
            testkit.fuzz.seedInto(&self.truncated_store, one[0 .. one.len - 9]);

        return &self.entries;
    }
};

test "fuzz: parseCsr never panics on arbitrary bytes" {
    var corpus: CsrCorpus = .{};
    try testing.fuzz({}, fuzzParseCsr, .{ .corpus = try corpus.build(testing.allocator) });
}

fn fuzzParseCsr(_: void, smith: *std.testing.Smith) !void {
    return csrHarness(std.testing.Smith, smith, testing.allocator);
}

const fuzz_driver = testkit.fuzz.driver;
const CsrLabel = enum { raw_rejected, raw_accepted, genuine_parsed, truncated_rejected, trailing_rejected, flipped_rejected };
var csr_reach: [@typeInfo(CsrLabel).@"enum".field_names.len]usize = @splat(0);

fn markCsr(comptime l: CsrLabel) void {
    csr_reach[@backingInt(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

/// Generic over its source (`Smith` under `--fuzz`, `fuzz_driver.Rng` under the
/// driver). The drawn octets are parsed raw (any outcome, no panic, success
/// freed); then they seed a PRNG that names 1..3 domains and has `csrDer` sign
/// a genuine CSR, which must parse back to those names. Every truncation, one
/// trailing octet and any single flipped bit must be REFUSED: the CSR is
/// self-signed over every octet of its body, so an accepted flip is a forgery.
fn csrHarness(comptime S: type, smith: *S, gpa: Allocator) anyerror!void {
    var buf: [1024]u8 = undefined;
    const len: usize = smith.slice(&buf);
    if (parseCsr(gpa, buf[0..len])) |parsed| {
        var p = parsed;
        p.deinit();
        markCsr(.raw_accepted);
    } else |_| markCsr(.raw_rejected);

    var prng = std.Random.DefaultPrng.init(std.hash.Wyhash.hash(0, buf[0..len]));
    const rnd = prng.random();
    var names_store: [3][24]u8 = undefined;
    var names: [3][]const u8 = undefined;
    const n_names = 1 + rnd.uintLessThan(usize, 3);
    for (names[0..n_names], names_store[0..n_names]) |*nm, *st| {
        const label_len = 1 + rnd.uintLessThan(usize, 8);
        for (st[0..label_len]) |*c| c.* = 'a' + rnd.uintLessThan(u8, 26);
        const suffix = ".example.com";
        @memcpy(st[label_len..][0..suffix.len], suffix);
        nm.* = st[0 .. label_len + suffix.len];
    }
    const der = csrDer(gpa, testKeyPair(42), names[0..n_names]) catch return error.CsrDerFailed;
    defer gpa.free(der);
    {
        var parsed = parseCsr(gpa, der) catch return error.GenuineCsrRejected;
        defer parsed.deinit();
        if (parsed.sans.len != n_names) return error.RoundTripMismatch;
        for (parsed.sans, names[0..n_names]) |g, want| {
            if (!std.mem.eql(u8, g, want)) return error.RoundTripMismatch;
        }
    }
    markCsr(.genuine_parsed);

    const cut = rnd.uintLessThan(usize, der.len);
    if (parseCsr(gpa, der[0..cut])) |p| {
        var pp = p;
        pp.deinit();
        return error.TruncatedCsrAccepted;
    } else |_| {}
    markCsr(.truncated_rejected);

    var ext: [1024]u8 = undefined;
    @memcpy(ext[0..der.len], der);
    ext[der.len] = rnd.int(u8);
    if (parseCsr(gpa, ext[0 .. der.len + 1])) |p| {
        var pp = p;
        pp.deinit();
        return error.TrailingOctetAccepted;
    } else |_| {}
    markCsr(.trailing_rejected);

    ext[rnd.uintLessThan(usize, der.len)] ^= @as(u8, 1) << rnd.int(u3);
    if (parseCsr(gpa, ext[0..der.len])) |p| {
        var pp = p;
        pp.deinit();
        return error.ForgedCsrAccepted;
    } else |_| {}
    markCsr(.flipped_rejected);
}

test "fuzz driver: ACME_FUZZ (acme-csr)" {
    try fuzz_driver.run(csrHarness, .{ .prefix = "ACME_FUZZ", .name = "acme-csr" });
}

test "fuzz harness: 200 CSR seeds in every test run, and they get everywhere" {
    csr_reach = @splat(0);
    for (0..200) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        csrHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("acme-csr seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    for (csr_reach, 0..) |n, i| {
        const l: CsrLabel = @fromBackingInt(@intCast(i));
        // Random octets are never a self-signed CSR: `raw_accepted` is reached
        // through the corpus only.
        if (l == .raw_accepted) continue;
        if (n == 0) {
            std.debug.print("reach: label {t} never hit in 200 seeds\n", .{l});
            return error.HarnessDoesNotReach;
        }
    }
}

test "corpus: every CSR seed reaches parseCsr, and the SANs recovered are pinned" {
    // ⭐ The measurement, executable rather than written in a comment. The
    // buffer went 512 → 1024 with it: the two CSRs here measure 232 and 248
    // octets, so 512 held them, but the margin was about four more domain
    // names wide and a seed over the buffer reads back EMPTY rather than
    // large — silently, which is how three harnesses elsewhere in this tree
    // ended up unable to pass their own module's largest fixture.
    //
    // `sans_recovered` is the second number, and it is the one that matters:
    // `parseCsr` refuses the empty input, so acceptance alone looks
    // discriminating -- but a corpus of version-0/empty-subject stubs could
    // still be "accepted" by a future, laxer decoder while recovering no name
    // at all, and the SAN list is the entire product of this parser.
    var nonempty: usize = 0;
    var accepted: usize = 0;
    var sans_recovered: usize = 0;
    var corpus: CsrCorpus = .{};
    const entries = try corpus.build(testing.allocator);
    for (entries) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [1024]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        var parsed = parseCsr(testing.allocator, buf[0..len]) catch continue;
        defer parsed.deinit();
        accepted += 1;
        sans_recovered += parsed.sans.len;
    }
    try testing.expectEqual(entries.len, nonempty);
    // Measured 2026-09-07: 0 of 12 seeds non-empty, 0 accepted and 0 SANs
    // recovered before the draw was fixed.
    try testing.expectEqual(@as(usize, 2), accepted);
    try testing.expectEqual(@as(usize, 3), sans_recovered);
}

// ── audit 2026-10-04: tests asked for by mutation survivors ──────────────────

test "isValidDomain: the RFC 1035 limits and the LDH alphabet" {
    // RFC 1035 §2.3.4: labels ≤ 63 octets, names ≤ 255 octets on the wire
    // (≤ 253 as text without the trailing dot); RFC 952/1123 LDH: letters,
    // digits, hyphen — no underscore in a hostname.
    const l63 = strRepeat("a", 63);
    try testing.expect(isValidDomain(l63 ++ ".example"));
    try testing.expect(!isValidDomain(strRepeat("a", 64) ++ ".example"));
    const n253 = l63 ++ "." ++ l63 ++ "." ++ l63 ++ "." ++ strRepeat("a", 61); // 253
    try testing.expect(isValidDomain(n253));
    try testing.expect(!isValidDomain(n253 ++ "a"));
    try testing.expect(!isValidDomain("under_score.example"));
}

test "readElem: indefinite length and a truncated long-form length are malformed" {
    // X.690 §10.1 (DER): definite length only — 0x80 is BER's indefinite
    // form; and a long-form length whose octets are missing cannot be read.
    try testing.expectError(error.Malformed, readElem("\x04\x80\x00\x00", 0));
    try testing.expectError(error.Malformed, readElem("\x04\x82\x01", 0));
}

test "parseCsr: trailing bytes, a foreign version or algorithm, and a nonzero unused-bits octet are refused by name" {
    // `parseCsr` checks version 0 and the P-256/ES256 algorithms (RFC 2986
    // §4.1, RFC 5480, RFC 5758 §3.2) before the signature and reports them
    // as `UnsupportedCsr`; bytes after the CSR are not part of it.
    const kp = testKeyPair(5);
    const good = try csrDer(testing.allocator, kp, &.{"example.org"});
    defer testing.allocator.free(good);
    var p = try parseCsr(testing.allocator, good); // control
    p.deinit();

    var buf: [1024]u8 = undefined;
    @memcpy(buf[0..good.len], good);
    buf[good.len] = 0;
    try testing.expectError(error.MalformedCsr, parseCsr(testing.allocator, buf[0 .. good.len + 1]));

    const Case = struct { pattern: []const u8, delta: usize, last: bool };
    const cases = [_]Case{
        .{ .pattern = "\x02\x01\x00", .delta = 2, .last = false }, // version 0 -> 1
        .{ .pattern = oid_ec_public_key, .delta = 0, .last = false },
        .{ .pattern = oid_p256, .delta = 0, .last = false },
        .{ .pattern = "\x03\x42\x00\x04", .delta = 2, .last = false }, // BIT STRING unused bits
        .{ .pattern = oid_ecdsa_sha256, .delta = 0, .last = true }, // signatureAlgorithm (unsigned)
    };
    for (cases) |c| {
        @memcpy(buf[0..good.len], good);
        const at = (if (c.last) std.mem.lastIndexOf(u8, good, c.pattern) else std.mem.indexOf(u8, good, c.pattern)).? + c.delta;
        buf[at] ^= 1;
        try testing.expectError(error.UnsupportedCsr, parseCsr(testing.allocator, buf[0..good.len]));
    }
}

/// `csrDer`'s structure with two knobs it never sets: an explicit
/// `critical` flag on the SAN extension, and an extra iPAddress GeneralName.
fn csrVariant(gpa: Allocator, key_pair: *const Es256.KeyPair, critical: bool, ip: bool) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const d: Der = .{ .a = arena.allocator() };
    const pub_sec1 = key_pair.public_key.toUncompressedSec1();
    const spki = try d.seq(&.{
        try d.seq(&.{ try d.oid(oid_ec_public_key), try d.oid(oid_p256) }),
        try d.bitString(&pub_sec1),
    });
    const names = if (ip)
        try d.seq(&.{ try d.tlv(0x87, "\x7f\x00\x00\x01"), try d.tlv(0x82, "example.org") })
    else
        try d.seq(&.{try d.tlv(0x82, "example.org")});
    const san_ext = if (critical)
        try d.seq(&.{ try d.oid(oid_subject_alt_name), try d.tlv(0x01, "\xff"), try d.tlv(0x04, names) })
    else
        try d.seq(&.{ try d.oid(oid_subject_alt_name), try d.tlv(0x04, names) });
    const attributes = try d.tlv(0xa0, try d.seq(&.{ try d.oid(oid_extension_request), try d.tlv(0x31, try d.seq(&.{san_ext})) }));
    const info = try d.seq(&.{ try d.tlv(0x02, "\x00"), try d.seq(&.{}), spki, attributes });
    const sig = try key_pair.sign(info, null);
    var sig_buf: [Es256.Signature.der_encoded_length_max]u8 = undefined;
    const csr = try d.seq(&.{ info, try d.seq(&.{try d.oid(oid_ecdsa_sha256)}), try d.bitString(sig.toDer(&sig_buf)) });
    return gpa.dupe(u8, csr);
}

test "parseCsr: a critical SAN extension is read, and only dNSName entries are returned" {
    // RFC 5280 §4.1: Extension ::= SEQUENCE { extnID, critical BOOLEAN
    // DEFAULT FALSE, extnValue } — the flag may be present. §4.2.1.6: a
    // GeneralName is one of several choices; dNSName is [2], iPAddress [7],
    // and an IP address is not a DNS name.
    const kp = testKeyPair(6);
    const crit = try csrVariant(testing.allocator, kp, true, false);
    defer testing.allocator.free(crit);
    var p1 = try parseCsr(testing.allocator, crit);
    defer p1.deinit();
    try testing.expectEqual(@as(usize, 1), p1.sans.len);
    try testing.expectEqualStrings("example.org", p1.sans[0]);
    const with_ip = try csrVariant(testing.allocator, kp, false, true);
    defer testing.allocator.free(with_ip);
    var p2 = try parseCsr(testing.allocator, with_ip);
    defer p2.deinit();
    try testing.expectEqual(@as(usize, 1), p2.sans.len);
    try testing.expectEqualStrings("example.org", p2.sans[0]);
}

test "EC private key PEM: found among other blocks; the first key block is used" {
    // pemDecodeSecret finds the END line by the first '-' after the body
    // (2026-10-18: std's Boyer-Moore-Horspool ran over the key's base64). A
    // key between certificate blocks — the Manager stores key, then chain —
    // loads; of two key blocks the first is used; a '-' in the body that does
    // not start the END line is refused.
    const kp = testKeyPair(46);
    const key_pem = try ecPrivateKeyToPem(testing.allocator, kp);
    defer testing.allocator.free(key_pem);
    const cert = "-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\n";
    const text = try std.mem.concat(testing.allocator, u8, &.{ cert, key_pem, cert, cert });
    defer testing.allocator.free(text);
    var back: Es256.KeyPair = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&back));
    try ecPrivateKeyFromPem(&back, testing.allocator, text);
    try testing.expectEqualSlices(u8, &kp.secret_key.toBytes(), &back.secret_key.toBytes());
    const other = try ecPrivateKeyToPem(testing.allocator, testKeyPair(47));
    defer testing.allocator.free(other);
    const two = try std.mem.concat(testing.allocator, u8, &.{ key_pem, other });
    defer testing.allocator.free(two);
    try ecPrivateKeyFromPem(&back, testing.allocator, two);
    try testing.expectEqualSlices(u8, &kp.secret_key.toBytes(), &back.secret_key.toBytes());
    try testing.expectError(error.InvalidPem, ecPrivateKeyFromPem(
        &back,
        testing.allocator,
        "-----BEGIN EC PRIVATE KEY-----\nMAA-=\n-----END EC PRIVATE KEY-----\n",
    ));
    // The END line before the BEGIN line is no block.
    try testing.expectError(error.InvalidPem, ecPrivateKeyFromPem(
        &back,
        testing.allocator,
        "-----END EC PRIVATE KEY-----\n-----BEGIN EC PRIVATE KEY-----\nMAA=\n",
    ));
}

test "pemDecode: an over-long label and an empty body are typed errors" {
    // The label is caller-supplied and formatted into fixed buffers (see
    // `pemDecode`'s comment); RFC 7468 §3: a block carries base64 data.
    try testing.expectError(error.LabelTooLong, pemDecode(testing.allocator, strRepeat("L", max_pem_label_len + 1), "x"));
    try testing.expectError(error.InvalidPem, pemDecode(testing.allocator, "CERTIFICATE", "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"));
}

test "ecPrivateKeyFromPem: version must be 1 and the private octets at most 32" {
    // RFC 5915 §3: ECPrivateKey version is ecPrivkeyVer1 (1); privateKey is
    // ceiling(log2(n)/8) = 32 octets for P-256.
    const kp = testKeyPair(7);
    const pem = try ecPrivateKeyToPem(testing.allocator, kp);
    defer testing.allocator.free(pem);
    const der_bytes = try pemDecode(testing.allocator, "EC PRIVATE KEY", pem);
    defer testing.allocator.free(der_bytes);
    const v_at = std.mem.indexOf(u8, der_bytes, "\x02\x01\x01").? + 2;
    der_bytes[v_at] = 2;
    const pem_v2 = try pemEncode(testing.allocator, "EC PRIVATE KEY", der_bytes);
    defer testing.allocator.free(pem_v2);
    var scratch: Es256.KeyPair = undefined;
    try testing.expectError(error.MalformedKey, ecPrivateKeyFromPem(&scratch, testing.allocator, pem_v2));

    const long_priv = "\x30\x26\x02\x01\x01\x04\x21" ++ strRepeat("\x01", 33);
    const pem_long = try pemEncode(testing.allocator, "EC PRIVATE KEY", long_priv);
    defer testing.allocator.free(pem_long);
    try testing.expectError(error.MalformedKey, ecPrivateKeyFromPem(&scratch, testing.allocator, pem_long));
}

// `pemBlockStart` (2026-10-18) replaced `std.mem.indexOf` for the header in
// every search over text that may hold a key: it must find what the plain
// search found, in order, across blocks of other labels.
test "pemBlockStart: first block of the label, past blocks of other labels; labels match whole" {
    const key = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIBEND+PRIVATE/KEY\n-----END EC PRIVATE KEY-----\n";
    const cert = "-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\n";
    const crlf = "-----BEGIN CERTIFICATE-----\r\nMAE=\r\n-----END CERTIFICATE-----\r\n";
    const text = "junk\n" ++ key ++ cert ++ crlf;
    try testing.expectEqual(@as(?usize, 5), pemBlockStart(text, "EC PRIVATE KEY"));
    try testing.expectEqual(@as(?usize, 5 + key.len), pemBlockStart(text, "CERTIFICATE"));
    try testing.expectEqual(@as(?usize, 0), pemBlockStart(crlf ++ cert, "CERTIFICATE"));
    try testing.expectEqual(@as(?usize, key.len), pemBlockStart(key ++ crlf, "CERTIFICATE"));
    // A label is matched whole: neither a prefix nor a suffix of another.
    try testing.expectEqual(@as(?usize, null), pemBlockStart(text, "PRIVATE KEY"));
    try testing.expectEqual(@as(?usize, null), pemBlockStart(text, "EC PRIVATE"));
    try testing.expectEqual(@as(?usize, null), pemBlockStart(text, "CERTIFICATE REQUEST"));
    try testing.expectEqual(@as(?usize, null), pemBlockStart("", "CERTIFICATE"));
    // A block with no END line hides everything after it (no '-' to stop at).
    try testing.expectEqual(@as(?usize, null), pemBlockStart("-----BEGIN X-----\nAAAA", "CERTIFICATE"));

    // The callers: a PKCS#8 text through `privateKeyFromPem` (its EC search
    // misses), and the RSA loader over a text whose first block is a cert.
    const kp = testKeyPair384(0x5a);
    const pk8 = try pkcs8PrivateKeyToPem(testing.allocator, kp);
    defer testing.allocator.free(pk8);
    var any: jws.AnyKeyPair = undefined;
    try privateKeyFromPem(&any, testing.allocator, pk8);
    try testing.expectEqualSlices(u8, &kp.secret_key.bytes, &any.es384.secret_key.bytes);
    const both = try std.mem.concat(testing.allocator, u8, &.{ cert, pk8 });
    defer testing.allocator.free(both);
    try privateKeyFromPem(&any, testing.allocator, both);
    try testing.expectEqualSlices(u8, &kp.secret_key.bytes, &any.es384.secret_key.bytes);
}

// ── ES384 / PKCS#8 / ARI (2026-10-13) ───────────────────────────────────────

fn testKeyPair384(comptime seed_byte: u8) *const Es384.KeyPair {
    const S = struct {
        var kp: Es384.KeyPair = undefined;
        var ready = false;
    };
    if (!S.ready) {
        const seed: [Es384.KeyPair.seed_length]u8 = @splat(seed_byte);
        Es384.KeyPair.generateDeterministicInto(&S.kp, &seed) catch unreachable;
        S.ready = true;
    }
    return &S.kp;
}

// openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 (a throwaway
// key, published here as a fixture), and `openssl ec -in` of the same key.
const openssl_p384_pkcs8 =
    \\-----BEGIN PRIVATE KEY-----
    \\MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCE0QplzHY7BC1IafxZ
    \\4JBjKxOAtmJiuqr7HbZNwl5gR7oRR9Er2iRTLts739glAxOhZANiAASLZ6+pBa5E
    \\woUvL3usqhUrTPAU5uQko58suo+aYRKPhw2gcJ3LigSH3IDM3Mxq36T3aCXdvFHy
    \\Q9GC3el14cUCesuVLW7yYaid1BWgCHqCf4pL7HjKgAs/DKyQdGXfjZM=
    \\-----END PRIVATE KEY-----
    \\
;
const openssl_p384_sec1 =
    \\-----BEGIN EC PRIVATE KEY-----
    \\MIGkAgEBBDCE0QplzHY7BC1IafxZ4JBjKxOAtmJiuqr7HbZNwl5gR7oRR9Er2iRT
    \\Lts739glAxOgBwYFK4EEACKhZANiAASLZ6+pBa5EwoUvL3usqhUrTPAU5uQko58s
    \\uo+aYRKPhw2gcJ3LigSH3IDM3Mxq36T3aCXdvFHyQ9GC3el14cUCesuVLW7yYaid
    \\1BWgCHqCf4pL7HjKgAs/DKyQdGXfjZM=
    \\-----END EC PRIVATE KEY-----
    \\
;
// openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256
const openssl_p256_pkcs8 =
    \\-----BEGIN PRIVATE KEY-----
    \\MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgSgsW16H9kHCpshJG
    \\NehQcK4Aeuct6AWEyLfuwelCWKehRANCAAQXEOm3ln0/R5mvfwdk4lV9eN1YLL07
    \\JsH2FbaDsZV6IrhIon9lwTWaP5BJeTveQCGv4Ke7d7tNkV73ghq3vSXs
    \\-----END PRIVATE KEY-----
    \\
;
// openssl req -new -key <the P-384 key> -subj / -sha384 -addext subjectAltName=DNS:example.org,DNS:*.example.org
const openssl_p384_csr =
    \\-----BEGIN CERTIFICATE REQUEST-----
    \\MIIBMTCBtwIBADAAMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEi2evqQWuRMKFLy97
    \\rKoVK0zwFObkJKOfLLqPmmESj4cNoHCdy4oEh9yAzNzMat+k92gl3bxR8kPRgt3p
    \\deHFAnrLlS1u8mGondQVoAh6gn+KS+x4yoALPwyskHRl342ToDgwNgYJKoZIhvcN
    \\AQkOMSkwJzAlBgNVHREEHjAcggtleGFtcGxlLm9yZ4INKi5leGFtcGxlLm9yZzAK
    \\BggqhkjOPQQDAwNpADBmAjEA8cZ0EN2IpYc4vRTU7vRn4GN/QpZzp8KUtiS1DfoT
    \\vFf8uRwG084HYNvB04E6CHB6AjEAnC/y58faanKq/eRMQgWS7oaZO3INCdZ9kStW
    \\u58Hgz6Lm5OftsLWgDoJs+O6nuL4
    \\-----END CERTIFICATE REQUEST-----
    \\
;

test "ES384 CSR: openssl's CSR verifies, ours round-trips, and the P-256-only parser refuses it" {
    // External oracle: a CSR openssl built and `openssl req -verify` accepted.
    const ossl_der = try pemDecode(testing.allocator, "CERTIFICATE REQUEST", openssl_p384_csr);
    defer testing.allocator.free(ossl_der);
    var theirs = try parseCsrAny(testing.allocator, ossl_der);
    defer theirs.deinit();
    try testing.expectEqual(@as(usize, 2), theirs.sans.len);
    try testing.expectEqualStrings("example.org", theirs.sans[0]);
    try testing.expectEqualStrings("*.example.org", theirs.sans[1]);
    try testing.expectEqual(Alg.es384, theirs.public_key.alg());
    try testing.expectError(error.UnsupportedCsr, parseCsr(testing.allocator, ossl_der));
    // One flipped bit in the signed part must break the signature.
    const bad = try testing.allocator.dupe(u8, ossl_der);
    defer testing.allocator.free(bad);
    bad[40] ^= 1;
    try testing.expect(std.meta.isError(parseCsrAny(testing.allocator, bad)));

    // Ours: build with a P-384 key, parse back, same key and SANs.
    const kp = testKeyPair384(46);
    const der_bytes = try csrDer(testing.allocator, kp, &.{ "example.org", "www.example.org" });
    defer testing.allocator.free(der_bytes);
    try testing.expect(std.mem.indexOf(u8, der_bytes, oid_ecdsa_sha384) != null);
    try testing.expect(std.mem.indexOf(u8, der_bytes, oid_ecdsa_sha256) == null);
    var back = try parseCsrAny(testing.allocator, der_bytes);
    defer back.deinit();
    try testing.expectEqual(@as(usize, 2), back.sans.len);
    try testing.expect(back.public_key.eql(.{ .es384 = kp.public_key }));
    // The same bytes through an AnyKeyPair.
    var any: jws.AnyKeyPair = .{ .es384 = kp.* };
    defer std.crypto.secureZero(u8, std.mem.asBytes(&any));
    const via_any = try csrDer(testing.allocator, &any, &.{ "example.org", "www.example.org" });
    defer testing.allocator.free(via_any);
    try testing.expectEqualSlices(u8, der_bytes, via_any);

    // A signature algorithm that disagrees with the key's curve is refused by name.
    const mismatched = try testing.allocator.dupe(u8, der_bytes);
    defer testing.allocator.free(mismatched);
    const at = std.mem.lastIndexOf(u8, mismatched, oid_ecdsa_sha384).? + oid_ecdsa_sha384.len - 1;
    mismatched[at] = 0x02; // ecdsa-with-SHA256
    try testing.expectError(error.UnsupportedCsr, parseCsrAny(testing.allocator, mismatched));
}

test "ES384 TLS-ALPN-01 validation certificate: independent parser reads it, carries the P-384 OIDs" {
    const kp = testKeyPair384(71);
    const id: [32]u8 = @splat(0x5a);
    const cert_der = try tlsAlpnCertDer(testing.allocator, kp, "example.org", id, "\x01\x02", tls_alpn_not_before, tls_alpn_not_after);
    defer testing.allocator.free(cert_der);
    try pkix.safe.validateForStdParse(cert_der);
    const cert: std.crypto.Certificate = .{ .buffer = cert_der, .index = 0 };
    const parsed = try cert.parse();
    try testing.expectEqual(std.crypto.Certificate.NamedCurve.secp384r1, parsed.pub_key_algo.X9_62_id_ecPublicKey);
    try testing.expectEqual(std.crypto.Certificate.Algorithm.ecdsa_with_SHA384, parsed.signature_algorithm);
    try testing.expect(std.mem.indexOf(u8, cert_der, oid_p384) != null);
    // The self-signature verifies over the TBSCertificate with the P-384 key.
    const tbs = try expectElem(cert_der, (try expectElem(cert_der, 0, 0x30)).start, 0x30);
    const cert_elem = try expectElem(cert_der, 0, 0x30);
    const sig_alg = try expectElem(cert_der, tbs.end, 0x30);
    const sig_bits = try expectElem(cert_der, sig_alg.end, 0x03);
    try testing.expectEqual(cert_elem.end, sig_bits.end);
    const sig = try Es384.Signature.fromDer(sig_bits.content(cert_der)[1..]);
    try sig.verify(cert_der[tbs.hdr..tbs.end], kp.public_key);
}

test "PKCS#8 and SEC1 PEM: openssl's P-384 and P-256 keys load, ours reproduce openssl's bytes" {
    // P-384: PKCS#8 and SEC1 of the same key.
    var any: jws.AnyKeyPair = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&any));
    try privateKeyFromPem(&any, testing.allocator, openssl_p384_pkcs8);
    try testing.expectEqual(Alg.es384, any.alg());
    const out8 = try pkcs8PrivateKeyToPem(testing.allocator, &any);
    defer testing.allocator.free(out8);
    try testing.expectEqualStrings(openssl_p384_pkcs8, out8);
    const out1 = try ecPrivateKeyToPem(testing.allocator, &any);
    defer testing.allocator.free(out1);
    try testing.expectEqualStrings(openssl_p384_sec1, out1);

    var sec1_any: jws.AnyKeyPair = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&sec1_any));
    try privateKeyFromPem(&sec1_any, testing.allocator, openssl_p384_sec1);
    try testing.expectEqualSlices(u8, &any.es384.secret_key.toBytes(), &sec1_any.es384.secret_key.toBytes());

    // Typed targets: the right curve loads, the wrong one is refused.
    var typed: Es384.KeyPair = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&typed));
    try pkcs8PrivateKeyFromPem(&typed, testing.allocator, openssl_p384_pkcs8);
    try testing.expectEqualSlices(u8, &any.es384.secret_key.toBytes(), &typed.secret_key.toBytes());
    var wrong: Es256.KeyPair = undefined;
    try testing.expectError(error.MalformedKey, pkcs8PrivateKeyFromPem(&wrong, testing.allocator, openssl_p384_pkcs8));
    try testing.expectError(error.MalformedKey, ecPrivateKeyFromPem(&wrong, testing.allocator, openssl_p384_sec1));
    var wrong384: Es384.KeyPair = undefined;
    try testing.expectError(error.MalformedKey, pkcs8PrivateKeyFromPem(&wrong384, testing.allocator, openssl_p256_pkcs8));
    // The EC PRIVATE KEY reader does not take a PRIVATE KEY block, and vice versa.
    try testing.expectError(error.MissingPemBlock, ecPrivateKeyFromPem(&typed, testing.allocator, openssl_p384_pkcs8));
    try testing.expectError(error.MissingPemBlock, pkcs8PrivateKeyFromPem(&typed, testing.allocator, openssl_p384_sec1));

    // P-256 PKCS#8, byte-exact both ways.
    var p256: jws.AnyKeyPair = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&p256));
    try privateKeyFromPem(&p256, testing.allocator, openssl_p256_pkcs8);
    try testing.expectEqual(Alg.es256, p256.alg());
    const p256_out = try pkcs8PrivateKeyToPem(testing.allocator, &p256.es256);
    defer testing.allocator.free(p256_out);
    try testing.expectEqualStrings(openssl_p256_pkcs8, p256_out);
    var p256_typed: Es256.KeyPair = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&p256_typed));
    try pkcs8PrivateKeyFromPem(&p256_typed, testing.allocator, p256_out);
    try testing.expectEqualSlices(u8, &p256.es256.secret_key.toBytes(), &p256_typed.secret_key.toBytes());

    // Our own keys round-trip through both forms, on both curves.
    const kp = testKeyPair384(47);
    const pem = try pkcs8PrivateKeyToPem(testing.allocator, kp);
    defer testing.allocator.free(pem);
    var rt: Es384.KeyPair = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&rt));
    try pkcs8PrivateKeyFromPem(&rt, testing.allocator, pem);
    try testing.expectEqualSlices(u8, &kp.secret_key.toBytes(), &rt.secret_key.toBytes());
    try testing.expectEqualSlices(u8, &kp.public_key.toUncompressedSec1(), &rt.public_key.toUncompressedSec1());

    // Damage: a PKCS#8 whose inner key is a different curve than its AlgorithmIdentifier says.
    const der_bytes = try pemDecode(testing.allocator, "PRIVATE KEY", openssl_p384_pkcs8);
    defer testing.allocator.free(der_bytes);
    const curve_at = std.mem.indexOf(u8, der_bytes, oid_p384).? + oid_p384.len - 1;
    der_bytes[curve_at] = 0x21; // secp224r1 — not supported
    const bad_pem = try pemEncode(testing.allocator, "PRIVATE KEY", der_bytes);
    defer testing.allocator.free(bad_pem);
    try testing.expectError(error.MalformedKey, privateKeyFromPem(&any, testing.allocator, bad_pem));
}

// ── ES512 (2026-10-16) ──────────────────────────────────────────────────────

fn testKeyPair521(comptime seed_byte: u8) *const Es512.KeyPair {
    const S = struct {
        var kp: Es512.KeyPair = undefined;
        var ready = false;
    };
    if (!S.ready) {
        const seed: [Es512.KeyPair.seed_length]u8 = @splat(seed_byte);
        Es512.KeyPair.generateDeterministicInto(&S.kp, &seed) catch unreachable;
        S.ready = true;
    }
    return &S.kp;
}

// openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-521 -out k.pkcs8.pem (a throwaway
// key, published here as a fixture); `openssl pkcs8 -topk8 -nocrypt` of the SEC1 form below
// gives the same bytes.
const openssl_p521_pkcs8 =
    \\-----BEGIN PRIVATE KEY-----
    \\MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIAg5E++wD4V6KAYY76
    \\DM8S8SOaqHPs0rzYug8sEVEVDFVtu5+aWBixPcynqpkG2Y9oXSwhYvp3gP7CfvYh
    \\Q5UhInmhgYkDgYYABADp1kMjY64eqTo2tF6E0OfCwtK4oFP0m8dMpcSaT0T6Z/p/
    \\caX6QWUM5jtpWfazsfD+eargrs4irCEPta5dTMJocgAfLe430ZFgyVqspyzSGeCI
    \\iumKf0t00QbX394B0CGiC8x9g5xqnHE3AMfYE1ULbcEbZmN313bTS1rL5vOArJzc
    \\vQ==
    \\-----END PRIVATE KEY-----
    \\
;
// openssl ec -in k.pkcs8.pem -out k.sec1.pem (the same key, RFC 5915)
const openssl_p521_sec1 =
    \\-----BEGIN EC PRIVATE KEY-----
    \\MIHcAgEBBEIAg5E++wD4V6KAYY76DM8S8SOaqHPs0rzYug8sEVEVDFVtu5+aWBix
    \\PcynqpkG2Y9oXSwhYvp3gP7CfvYhQ5UhInmgBwYFK4EEACOhgYkDgYYABADp1kMj
    \\Y64eqTo2tF6E0OfCwtK4oFP0m8dMpcSaT0T6Z/p/caX6QWUM5jtpWfazsfD+earg
    \\rs4irCEPta5dTMJocgAfLe430ZFgyVqspyzSGeCIiumKf0t00QbX394B0CGiC8x9
    \\g5xqnHE3AMfYE1ULbcEbZmN313bTS1rL5vOArJzcvQ==
    \\-----END EC PRIVATE KEY-----
    \\
;
// openssl req -new -key k.pkcs8.pem -subj / -sha512 -addext subjectAltName=DNS:example.org,DNS:*.example.org -out k.csr.pem
// openssl req -in k.csr.pem -verify -noout   ->  "Certificate request self-signature verify OK"
const openssl_p521_csr =
    \\-----BEGIN CERTIFICATE REQUEST-----
    \\MIIBezCB3QIBADAAMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQA6dZDI2OuHqk6
    \\NrRehNDnwsLSuKBT9JvHTKXEmk9E+mf6f3Gl+kFlDOY7aVn2s7Hw/nmq4K7OIqwh
    \\D7WuXUzCaHIAHy3uN9GRYMlarKcs0hngiIrpin9LdNEG19/eAdAhogvMfYOcapxx
    \\NwDH2BNVC23BG2Zjd9d200tay+bzgKyc3L2gODA2BgkqhkiG9w0BCQ4xKTAnMCUG
    \\A1UdEQQeMByCC2V4YW1wbGUub3Jngg0qLmV4YW1wbGUub3JnMAoGCCqGSM49BAME
    \\A4GMADCBiAJCAcRVdVAAZt5fc9bLRUJgNAatN74vlgaLE4M5EByh+cELgIvLS6Dm
    \\XGUu9MHDwGJDkNHxEaLPgMAXUViUnPG3Yz53AkIAwsaZS3Ua07gSCIM9Ue/ns+hr
    \\k7Lz2PEGsQrWfXrTW8sJXRFi+3sLIjW9D8JQTXhatHIQJwNHz1hD35nGJdONXUY=
    \\-----END CERTIFICATE REQUEST-----
    \\
;

test "ES512 CSR: openssl's CSR verifies, ours round-trips, and the P-256-only parser refuses it" {
    // External oracle: a CSR openssl built and `openssl req -verify` accepted.
    const ossl_der = try pemDecode(testing.allocator, "CERTIFICATE REQUEST", openssl_p521_csr);
    defer testing.allocator.free(ossl_der);
    var theirs = try parseCsrAny(testing.allocator, ossl_der);
    defer theirs.deinit();
    try testing.expectEqual(@as(usize, 2), theirs.sans.len);
    try testing.expectEqualStrings("example.org", theirs.sans[0]);
    try testing.expectEqualStrings("*.example.org", theirs.sans[1]);
    try testing.expectEqual(Alg.es512, theirs.public_key.alg());
    try testing.expectError(error.UnsupportedCsr, parseCsr(testing.allocator, ossl_der));
    // One flipped bit in the signed part must break the signature.
    const bad = try testing.allocator.dupe(u8, ossl_der);
    defer testing.allocator.free(bad);
    bad[40] ^= 1;
    try testing.expect(std.meta.isError(parseCsrAny(testing.allocator, bad)));

    // Ours: build with a P-521 key, parse back, same key and SANs.
    const kp = testKeyPair521(46);
    const der_bytes = try csrDer(testing.allocator, kp, &.{ "example.org", "www.example.org" });
    defer testing.allocator.free(der_bytes);
    try testing.expect(std.mem.indexOf(u8, der_bytes, oid_ecdsa_sha512) != null);
    try testing.expect(std.mem.indexOf(u8, der_bytes, oid_ecdsa_sha256) == null);
    var back = try parseCsrAny(testing.allocator, der_bytes);
    defer back.deinit();
    try testing.expectEqual(@as(usize, 2), back.sans.len);
    try testing.expect(back.public_key.eql(.{ .es512 = kp.public_key }));
    // The same bytes through an AnyKeyPair.
    var any: jws.AnyKeyPair = .{ .es512 = kp.* };
    defer std.crypto.secureZero(u8, std.mem.asBytes(&any));
    const via_any = try csrDer(testing.allocator, &any, &.{ "example.org", "www.example.org" });
    defer testing.allocator.free(via_any);
    try testing.expectEqualSlices(u8, der_bytes, via_any);

    // A signature algorithm that disagrees with the key's curve is refused by name.
    const mismatched = try testing.allocator.dupe(u8, der_bytes);
    defer testing.allocator.free(mismatched);
    const at = std.mem.lastIndexOf(u8, mismatched, oid_ecdsa_sha512).? + oid_ecdsa_sha512.len - 1;
    mismatched[at] = 0x02; // ecdsa-with-SHA256
    try testing.expectError(error.UnsupportedCsr, parseCsrAny(testing.allocator, mismatched));
}

test "ES512 TLS-ALPN-01 validation certificate: independent parser reads it, carries the P-521 OIDs" {
    const kp = testKeyPair521(71);
    const id: [32]u8 = @splat(0x5a);
    const cert_der = try tlsAlpnCertDer(testing.allocator, kp, "example.org", id, "\x01\x02", tls_alpn_not_before, tls_alpn_not_after);
    defer testing.allocator.free(cert_der);
    try pkix.safe.validateForStdParse(cert_der);
    const cert: std.crypto.Certificate = .{ .buffer = cert_der, .index = 0 };
    const parsed = try cert.parse();
    try testing.expectEqual(std.crypto.Certificate.NamedCurve.secp521r1, parsed.pub_key_algo.X9_62_id_ecPublicKey);
    try testing.expectEqual(std.crypto.Certificate.Algorithm.ecdsa_with_SHA512, parsed.signature_algorithm);
    try testing.expect(std.mem.indexOf(u8, cert_der, oid_p521) != null);
    // The self-signature verifies over the TBSCertificate with the P-521 key.
    const tbs = try expectElem(cert_der, (try expectElem(cert_der, 0, 0x30)).start, 0x30);
    const cert_elem = try expectElem(cert_der, 0, 0x30);
    const sig_alg = try expectElem(cert_der, tbs.end, 0x30);
    const sig_bits = try expectElem(cert_der, sig_alg.end, 0x03);
    try testing.expectEqual(cert_elem.end, sig_bits.end);
    const sig = try Es512.Signature.fromDer(sig_bits.content(cert_der)[1..]);
    try sig.verify(cert_der[tbs.hdr..tbs.end], kp.public_key);
}

test "PKCS#8 and SEC1 PEM: openssl's P-521 key loads, ours reproduce openssl's bytes" {
    var any: jws.AnyKeyPair = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&any));
    try privateKeyFromPem(&any, testing.allocator, openssl_p521_pkcs8);
    try testing.expectEqual(Alg.es512, any.alg());
    const out8 = try pkcs8PrivateKeyToPem(testing.allocator, &any);
    defer testing.allocator.free(out8);
    try testing.expectEqualStrings(openssl_p521_pkcs8, out8);
    const out1 = try ecPrivateKeyToPem(testing.allocator, &any);
    defer testing.allocator.free(out1);
    try testing.expectEqualStrings(openssl_p521_sec1, out1);

    var sec1_any: jws.AnyKeyPair = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&sec1_any));
    try privateKeyFromPem(&sec1_any, testing.allocator, openssl_p521_sec1);
    try testing.expectEqualSlices(u8, &any.es512.secret_key.toBytes(), &sec1_any.es512.secret_key.toBytes());

    // Typed targets: the right curve loads, the wrong ones are refused.
    var typed: Es512.KeyPair = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&typed));
    try pkcs8PrivateKeyFromPem(&typed, testing.allocator, openssl_p521_pkcs8);
    try testing.expectEqualSlices(u8, &any.es512.secret_key.toBytes(), &typed.secret_key.toBytes());
    try ecPrivateKeyFromPem(&typed, testing.allocator, openssl_p521_sec1);
    var wrong: Es256.KeyPair = undefined;
    try testing.expectError(error.MalformedKey, pkcs8PrivateKeyFromPem(&wrong, testing.allocator, openssl_p521_pkcs8));
    try testing.expectError(error.MalformedKey, ecPrivateKeyFromPem(&wrong, testing.allocator, openssl_p521_sec1));
    var wrong384: Es384.KeyPair = undefined;
    try testing.expectError(error.MalformedKey, pkcs8PrivateKeyFromPem(&wrong384, testing.allocator, openssl_p521_pkcs8));
    var wrong521: Es512.KeyPair = undefined;
    try testing.expectError(error.MalformedKey, pkcs8PrivateKeyFromPem(&wrong521, testing.allocator, openssl_p384_pkcs8));
    try testing.expectError(error.MalformedKey, pkcs8PrivateKeyFromPem(&wrong521, testing.allocator, openssl_p256_pkcs8));
    // The EC PRIVATE KEY reader does not take a PRIVATE KEY block, and vice versa.
    try testing.expectError(error.MissingPemBlock, ecPrivateKeyFromPem(&typed, testing.allocator, openssl_p521_pkcs8));
    try testing.expectError(error.MissingPemBlock, pkcs8PrivateKeyFromPem(&typed, testing.allocator, openssl_p521_sec1));

    // Our own key round-trips through both forms.
    const kp = testKeyPair521(47);
    const pem = try pkcs8PrivateKeyToPem(testing.allocator, kp);
    defer testing.allocator.free(pem);
    var rt: Es512.KeyPair = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&rt));
    try pkcs8PrivateKeyFromPem(&rt, testing.allocator, pem);
    try testing.expectEqualSlices(u8, &kp.secret_key.toBytes(), &rt.secret_key.toBytes());
    try testing.expectEqualSlices(u8, &kp.public_key.toUncompressedSec1(), &rt.public_key.toUncompressedSec1());
    const pem1 = try ecPrivateKeyToPem(testing.allocator, kp);
    defer testing.allocator.free(pem1);
    var rt1: Es512.KeyPair = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&rt1));
    try ecPrivateKeyFromPem(&rt1, testing.allocator, pem1);
    try testing.expectEqualSlices(u8, &kp.secret_key.toBytes(), &rt1.secret_key.toBytes());

    // Damage: a PKCS#8 whose curve OID names an unsupported curve (secp224r1).
    const der_bytes = try pemDecode(testing.allocator, "PRIVATE KEY", openssl_p521_pkcs8);
    defer testing.allocator.free(der_bytes);
    const curve_at = std.mem.indexOf(u8, der_bytes, oid_p521).? + oid_p521.len - 1;
    der_bytes[curve_at] = 0x21;
    const bad_pem = try pemEncode(testing.allocator, "PRIVATE KEY", der_bytes);
    defer testing.allocator.free(bad_pem);
    try testing.expectError(error.MalformedKey, privateKeyFromPem(&any, testing.allocator, bad_pem));
}

test "ariCertId: the RFC 9773 §4.1 example (AKI 69885B6B…C8D4, serial 00876543 21)" {
    // The example certificate of RFC 9773 Appendix A; §4.1 gives its CertID.
    const pem =
        \\-----BEGIN CERTIFICATE-----
        \\MIIBQzCB66ADAgECAgUAh2VDITAKBggqhkjOPQQDAjAVMRMwEQYDVQQDEwpFeGFt
        \\cGxlIENBMCIYDzAwMDEwMTAxMDAwMDAwWhgPMDAwMTAxMDEwMDAwMDBaMBYxFDAS
        \\BgNVBAMTC2V4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeBZu
        \\7cbpAYNXZLbbh8rNIzuOoqOOtmxA1v7cRm//AwyMwWxyHz4zfwmBhcSrf47NUAFf
        \\qzLQ2PPQxdTXREYEnKMjMCEwHwYDVR0jBBgwFoAUaYhba4dGQEHhs3uEe6CuLN4B
        \\yNQwCgYIKoZIzj0EAwIDRwAwRAIge09+S5TZAlw5tgtiVvuERV6cT4mfutXIlwTb
        \\+FYN/8oCIClDsqBklhB9KAelFiYt9+6FDj3z4KGVelYM5MdsO3pK
        \\-----END CERTIFICATE-----
        \\
    ;
    const id = try ariCertIdFromPem(testing.allocator, pem);
    defer testing.allocator.free(id);
    try testing.expectEqualStrings("aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE", id);

    // The serial's leading 0x00 is content, not padding: the base64 starts "AI".
    const der_bytes = try pemDecode(testing.allocator, "CERTIFICATE", pem);
    defer testing.allocator.free(der_bytes);
    try testing.expectEqualSlices(u8, "\x00\x87\x65\x43\x21", (try pkix.chain.certSerialAndIssuer(der_bytes)).serial);
    try testing.expectEqual(@as(usize, 20), (try pkix.chain.certAuthorityKeyId(der_bytes)).?.len);

    // Junk and a truncated certificate: a typed error, not a panic.
    try testing.expectError(error.MalformedCertificate, ariCertId(testing.allocator, "junk"));
    try testing.expectError(error.MalformedCertificate, ariCertId(testing.allocator, der_bytes[0 .. der_bytes.len - 3]));
}

test "csrDerWith: must-staple encodes as openssl writes it; duplicates refused" {
    const kp = testKeyPair(42);
    const der_bytes = try csrDerWith(testing.allocator, kp, &.{"a.example"}, &.{must_staple});
    defer testing.allocator.free(der_bytes);
    // `openssl req -new -key k.pem -subj / -addext subjectAltName=DNS:a.example
    //  -addext tlsfeature=status_request -outform DER` (OpenSSL 3.5.5) carries
    // exactly this Extension: OID 1.3.6.1.5.5.7.1.24, no critical flag,
    // OCTET STRING { SEQUENCE { INTEGER 5 } }.
    const openssl_ext = "\x30\x11\x06\x08\x2b\x06\x01\x05\x05\x07\x01\x18\x04\x05\x30\x03\x02\x01\x05";
    try testing.expect(std.mem.indexOf(u8, der_bytes, openssl_ext) != null);
    var parsed = try parseCsrAny(testing.allocator, der_bytes);
    defer parsed.deinit();
    try testing.expectEqual(@as(usize, 1), parsed.sans.len);
    try testing.expectEqualStrings("a.example", parsed.sans[0]);

    const critical: Extension = .{ .oid = must_staple.oid, .critical = true, .value = must_staple.value };
    const crit_der = try csrDerWith(testing.allocator, kp, &.{"a.example"}, &.{critical});
    defer testing.allocator.free(crit_der);
    try testing.expect(std.mem.indexOf(u8, crit_der, "\x2b\x06\x01\x05\x05\x07\x01\x18\x01\x01\xff\x04\x05") != null);

    try testing.expectError(error.DuplicateExtension, csrDerWith(testing.allocator, kp, &.{"a.example"}, &.{ must_staple, must_staple }));
    const san_again: Extension = .{ .oid = oid_subject_alt_name, .value = "\x30\x00" };
    try testing.expectError(error.DuplicateExtension, csrDerWith(testing.allocator, kp, &.{"a.example"}, &.{san_again}));
}

test "issuerCommonName: the fixtures' issuers, and truncations never read past the end" {
    const leaf = try pemDecode(testing.allocator, "CERTIFICATE", test_cert_pem);
    defer testing.allocator.free(leaf);
    try testing.expectEqualStrings("acme-test-fixture", issuerCommonName(leaf).?);
    const root = try pemDecode(testing.allocator, "CERTIFICATE", test_root_cert_pem);
    defer testing.allocator.free(root);
    try testing.expectEqualStrings("acme-test-root", issuerCommonName(root).?);
    for (0..leaf.len) |n| _ = issuerCommonName(leaf[0..n]); // bounded: no panic on any prefix
    try testing.expectEqual(@as(?[]const u8, null), issuerCommonName(""));
}

// ── RSA (2026-10-16) ────────────────────────────────────────────────────────

// Fixtures (OpenSSL 3.5.5), a throwaway RSA-2048 key — not a secret:
//   openssl genrsa -out k.pkcs8.pem 2048                  (PKCS#8 "PRIVATE KEY")
//   openssl rsa -in k.pkcs8.pem -traditional -out k.pkcs1.pem   (PKCS#1 "RSA PRIVATE KEY")
const test_rsa_pkcs8_pem =
    \\-----BEGIN PRIVATE KEY-----
    \\MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCFclHEPYa49gNd
    \\vBIPrMUfKEKaeE3xmM469V6sBhj5FHYgQcd0JgA5ZfpGMLWd8caTT8Pq/KjIS3cF
    \\ThcTD3o0sEmGUVdIH8NiZBkZcps4VuRLjB1oi619M8TG8qqOLaTDlmt3SOaj5oRS
    \\cRUzb2vFYAQwK6iylBY4Lg+vIL0pHb5NqzPiW4K9996mCKXP7HOD+bECsTmcDKeh
    \\/iDxibaumlA5ojkF245wyf+yhJkB5iFIVdV97+nyTVHDvtTHGkgv463kTZ1nNrMS
    \\YXoqO2mLK11BxT2K/JgHMsRbpQnvHKx/qZxx4Rz0edQglZkHAr6USor7Rkj/Wrlu
    \\znvKVeqjAgMBAAECggEALP62Xj5Gmj/tM6JRzrI5Bv/qsS3mThNxWgTY5pTpv7Zr
    \\/AVh7KJRigj+AcOzwS1AAPSwwR9vA5YabBIACr+5u2FDcUQk818uYJMSuXdgqfb2
    \\ZBi648DQ/vnBHDm/U1BFkWM7Gg3dIp97t1aEyQKFKphs4RcfexMeiNPTGwAld+Kg
    \\W/BdFgbQrzEKkxSzSVbZ+8hTGfd1Okfancr/tfaV4xdHFeVUVk/yWfjeKEHMmBGQ
    \\YbXmSB2cYypcQ1LMYWoyw8uWTzEihe3rrNZt8TcAMAG6osRYrjV+cXlnqUnv87oQ
    \\0Ei6WgAdpmKIIEtCUwfIZ0C6me4aq4sMOY7emc0igQKBgQC7amDC5++Pj92r/oFI
    \\i/mn+0vyIkzoEVPkYo+TeImJk38owRbPZ58shX+pEL+iM40XbGa9+MrqExTmApSv
    \\s2ugZGtxGRim7CnihMB1SzWma85lD2lshK7vJ0vGgpCQGtCShJi6+fSZE1uyQZGT
    \\5niFOxSdmmJZA13cbHEik1zDgQKBgQC2R/k/VnFRL8kMKWk6OGQI7tZu/RfTf/hK
    \\U9H1Ng8a8END6Pvmgj+8BcVtgU2JLDgqpbf1dztvEUywkr+fvg5zLPuGBPtmcAQX
    \\BZ0j/h+HRjJ2YXyaS90UmSp6gxs9HzM0blqSTLBgJTZcvJYbE86HspNy87GBtenJ
    \\FO8ww38wIwKBgQCzYH+4TNFnMKVUJ0WKMB8FfmoUGGxPebY303XkCexp9vgwA49X
    \\d7BLpoKnSFaCYqDaGHDFxsg//X91Hmc9O5b5buO+3exQZ503JyQln5R78pca9wNK
    \\UDw2vf+yweinZGLYuXyNCQvpLzQGiudRDbewnPmAVvFmjOhbPpeSJkUVAQKBgBHj
    \\CCtV8TK1TLY7zg6ff/l8bmBfx5nCgfvRM9YrItpS31bnouhguZ5atp/jQ1eFllFh
    \\B6c3twZUHUFqdRFY1hQpQtlI3d6UeWJE88GXa0Kb+dGyCUce0Kf3y7pP6TlbOWwY
    \\tByNF/WnUSlSfCxWCjs4o81w6mc/EZzgyAPx+yYfAoGAOuKqYZUlQf6qESwycemd
    \\vWdplgQS86KELyJe4+i1vDSc7nEV4vLfw19Fq1RnPFbQyU/VBTi0yHnZm0VIm12F
    \\SfARyPbKN2wXy61GVGk8KjO7iKAa8ChCp9ZrtD3qErzG4ixRU/dxc5/zJgPY4HBO
    \\nKhgr4xUe9OqdoSafb5oCtM=
    \\-----END PRIVATE KEY-----
    \\
;
pub const test_rsa_pkcs1_pem =
    \\-----BEGIN RSA PRIVATE KEY-----
    \\MIIEowIBAAKCAQEAhXJRxD2GuPYDXbwSD6zFHyhCmnhN8ZjOOvVerAYY+RR2IEHH
    \\dCYAOWX6RjC1nfHGk0/D6vyoyEt3BU4XEw96NLBJhlFXSB/DYmQZGXKbOFbkS4wd
    \\aIutfTPExvKqji2kw5Zrd0jmo+aEUnEVM29rxWAEMCuospQWOC4PryC9KR2+Tasz
    \\4luCvffepgilz+xzg/mxArE5nAynof4g8Ym2rppQOaI5BduOcMn/soSZAeYhSFXV
    \\fe/p8k1Rw77UxxpIL+Ot5E2dZzazEmF6KjtpiytdQcU9ivyYBzLEW6UJ7xysf6mc
    \\ceEc9HnUIJWZBwK+lEqK+0ZI/1q5bs57ylXqowIDAQABAoIBACz+tl4+Rpo/7TOi
    \\Uc6yOQb/6rEt5k4TcVoE2OaU6b+2a/wFYeyiUYoI/gHDs8EtQAD0sMEfbwOWGmwS
    \\AAq/ubthQ3FEJPNfLmCTErl3YKn29mQYuuPA0P75wRw5v1NQRZFjOxoN3SKfe7dW
    \\hMkChSqYbOEXH3sTHojT0xsAJXfioFvwXRYG0K8xCpMUs0lW2fvIUxn3dTpH2p3K
    \\/7X2leMXRxXlVFZP8ln43ihBzJgRkGG15kgdnGMqXENSzGFqMsPLlk8xIoXt66zW
    \\bfE3ADABuqLEWK41fnF5Z6lJ7/O6ENBIuloAHaZiiCBLQlMHyGdAupnuGquLDDmO
    \\3pnNIoECgYEAu2pgwufvj4/dq/6BSIv5p/tL8iJM6BFT5GKPk3iJiZN/KMEWz2ef
    \\LIV/qRC/ojONF2xmvfjK6hMU5gKUr7NroGRrcRkYpuwp4oTAdUs1pmvOZQ9pbISu
    \\7ydLxoKQkBrQkoSYuvn0mRNbskGRk+Z4hTsUnZpiWQNd3GxxIpNcw4ECgYEAtkf5
    \\P1ZxUS/JDClpOjhkCO7Wbv0X03/4SlPR9TYPGvBDQ+j75oI/vAXFbYFNiSw4KqW3
    \\9Xc7bxFMsJK/n74Ocyz7hgT7ZnAEFwWdI/4fh0YydmF8mkvdFJkqeoMbPR8zNG5a
    \\kkywYCU2XLyWGxPOh7KTcvOxgbXpyRTvMMN/MCMCgYEAs2B/uEzRZzClVCdFijAf
    \\BX5qFBhsT3m2N9N15Ansafb4MAOPV3ewS6aCp0hWgmKg2hhwxcbIP/1/dR5nPTuW
    \\+W7jvt3sUGedNyckJZ+Ue/KXGvcDSlA8Nr3/ssHop2Ri2Ll8jQkL6S80BornUQ23
    \\sJz5gFbxZozoWz6XkiZFFQECgYAR4wgrVfEytUy2O84On3/5fG5gX8eZwoH70TPW
    \\KyLaUt9W56LoYLmeWraf40NXhZZRYQenN7cGVB1BanURWNYUKULZSN3elHliRPPB
    \\l2tCm/nRsglHHtCn98u6T+k5WzlsGLQcjRf1p1EpUnwsVgo7OKPNcOpnPxGc4MgD
    \\8fsmHwKBgDriqmGVJUH+qhEsMnHpnb1naZYEEvOihC8iXuPotbw0nO5xFeLy38Nf
    \\RatUZzxW0MlP1QU4tMh52ZtFSJtdhUnwEcj2yjdsF8utRlRpPCozu4igGvAoQqfW
    \\a7Q96hK8xuIsUVP3cXOf8yYD2OBwTpyoYK+MVHvTqnaEmn2+aArT
    \\-----END RSA PRIVATE KEY-----
    \\
;
// openssl genrsa -traditional -out k1024.pkcs1.pem 1024  (below the 2048-bit floor)
const test_rsa1024_pkcs1_pem =
    \\-----BEGIN RSA PRIVATE KEY-----
    \\MIICXgIBAAKBgQC3BdtOcvFZXdcEN67G+cr0x1x1EoggtxUT4PrJej4Gs7vRUT17
    \\1RKULU+WqideA60mO4SeEKJYESk0BkN5ocJdZ69TzKyCWPND10ef5+27PnJ8vNXM
    \\Kw0sfKrWssAKZhi3OgMxUByMdUqX9YjWgQSjQ/04pcXdAPgxkYduu147IwIDAQAB
    \\AoGAWRBMjHx63lZAEBlYwBNGpJ9vark97U2qwCW3ZNxL2s8UEuRJ2zzw8ZKrLFJZ
    \\HfMEC5rjClhl6B1Rw7NYmpQRFLh4Wzxqm/1w2DPD8rWbMLlKS/+mGYryhVYv6Gzv
    \\1ex0LAZCzEDF9bmNAdWg11ol5zlQumwpBoWIPKU6H4Ndr2ECQQDYviyRgm1Aubad
    \\XLL2f91Wdaa3IyEN9eocb4riWruj/cVbjxzsJi9pWwByIkO8wVErVT1VPWomEWwc
    \\oPfCbox3AkEA2CwruFcQHg/UZ9TY5R3NTWTK5atGH9oGvrdwL6CGTana9Mc4WvRJ
    \\2Yk0BTm1xdu6Y/uYD3xi8N+gMv3dpJwttQJBAMFHRWM01cxkT+6gHY8nku9o1xR1
    \\JSLX6r8U0NrtYmrpADeXtYj4vErNNeaRm6oVEhb8WkdLDv+Hhcs51/bwsh0CQQC1
    \\bEy9BwSV1j8zbSUjFOHqpD7MhfPyY27pvNZAgn50y6rhaBlZ7E/WbBnmkMqHZaOG
    \\qe6ygHghI+01Hm5X6mNJAkEAlVXEfGLAuoWEct995I+GN8GChfk45FKMz31cXNQE
    \\ejMOD3pYK2SpFW7U8Aqyu+NyGsW18BIuf/faksPY4ZRsrA==
    \\-----END RSA PRIVATE KEY-----
    \\
;
// openssl genrsa -traditional -out k4096.pkcs1.pem 4096  (exactly `jws.rsa_max_bits`; throwaway test key)
const test_rsa4096_pkcs1_pem =
    \\-----BEGIN RSA PRIVATE KEY-----
    \\MIIJKAIBAAKCAgEAqCF8szlu+YtN6zqmyMWN8opnfNCBHjQ3YZbZK/NqNqFFDz4N
    \\hAeokdlJ4638NPaPOUlmQ4JLTSfyCTbBj4An5fsvt/B7v7YsV9NinJdJ+un6ICM9
    \\/o/Qgsu2qaucK+mlfZIhNe6gFaLbJwbqrAtw8mNJvxVVinKucI/MgBg5tJwoAI0p
    \\AG4nnLSfCzCJ2fz3KPISjsotv6AD1V5hZ7DoI+qFIJ7njs6KOwTILHoOu4o8riO6
    \\Lz3SHbsBZMt2tux79bcrJIilHZ3IULXc72IWB/aMqEukQ7pgdiMLoxNkcB8sAlqA
    \\vXiQ/gQBymsVpbVM9bkT6px4t6gnhZp7ArxjT5B85C6r0cnH7Ee298Kp8yAw6a/c
    \\xqgy5Z+KYS0+9dJSHVuc1SK5CmxV1eXKz3rUZnS31ElVcBUyFF4pBt5zAtH0Wv6+
    \\OZYWfzEVW9Xa3I3Qf/XUIlN/C8k8ocezm53/8UZwgvCOxhR3hOwneN0EMZdIqBb1
    \\idhWBfDXDtOjfiLk7KHy9rPBCfIO6bffj50iYJ8PB/s8WVpZ3btCASRXTKROCr1c
    \\Vc7tHTsn6gp+coXgCyh0eytvZC5IiRZid9+chary1V+Z+QLEl09iuhUZ8vMoIfT/
    \\c1W6twWHfbv5nk7GEtjKlvvq2PG5mrPUtb7Lo16jem9EFMXuRdQIxK+fibECAwEA
    \\AQKCAgBI+0BGDAhAClgoY61COX8EaU/Cvj9N/RyNIA3lJiRU0mxH0YfMaAakSM3q
    \\JvvzgZNqKpJZe5V0SIKnvT0ILXkkO4TbM2iEL2/QL9H+Zy2V3TrV+HZQqdy46fTA
    \\cd24shNEDsqbvpl+ytKWfkofpFfC35aDe59GGcHe2ozKjbl+zMoQczX5GdfYDg97
    \\q/YqycP/4hRsJxb0t2DynaVqfUBHVuWy40dglgcq10iNBe6fOcJdVOTc3Nj4TtSs
    \\DCXcAYtNfdUcZrRFxtfNMSRWRR2LF1q3Mx56x8xXe57xitluUhmoa+C2Xj+SA+tD
    \\EnizFZ/yigQ7MvCzyCpftE7xQRVaH64vxdmTvKCqv0DzksQQGoUhFDJ/0vqgKbH/
    \\x7s7V+Z+U9GbSqQ/xxne+mXtNOgcIiZSZrtXX0/6O4I0BNN6/HNYooSBLBMtEho3
    \\6h7RmpjVh7n1AiCIV6bWv2d7ZFvVZGwX/tr48tw3pgyTDlQDXnloeO5QNeXYW0mB
    \\w5GqJZGetflM+95vhZvDSv8vKuy/G6uK3cuEnXr8remu4L5PuOkaARb6JUDfGd5k
    \\r9lgxJaRfgjSwfcc+q8QG4S1Id/SX8KKwUUWUtJjMNRHcoHxGsYo0j73qDbTbLVG
    \\MBcm+sNlFsPTD49NWf8ubpFsXsse6YHTkQFhWJ7zSB02Ph5qgQKCAQEA3qOdtIGY
    \\UfpqhbVQIVvMUc1PDxQV36r5MKa+baXjV7WlvHenSRGjDBhfdp2V40LvkW1ooDAa
    \\q+rpVhSPox3ArdBtrTeK+EiKc/N3DZ5Y+sb4PlyYgT87VfFxw1z+YRoQ+wYodPTx
    \\swE4a5LsHzWWu50Q34lcRsM72rlXMY72NM/IWdhBwxHwJSOhLeURofloIgL7KS5U
    \\DWsV2o1Sq5eskJpJrIwoD8rhWf0peoEvqQJY/0dY6+TvMvebAgdU+EDtDdJjZw4v
    \\PnMGDXth5ZqefIsgv0lTs9LekUJXhjZ5+rwsTvvlA7xSG8yITzXar5Syaq0+GNx5
    \\WRlaOscuqVYT8wKCAQEAwVLx7GcK5+zUHcL/SByYkJLepcqGsPfE8XYfx/5oaHPz
    \\yQtqEYXn/mO1By1xyqJNCm6E4lO2gNMtO16e6FT42t5WhDvHO2z5THkOf3cCVniK
    \\A+0Om6FW//izRbjbVOC/wJp5xbmUVAZ5Z31JZ1qvIx1GIjI3CJeOd7gXsggGbNMo
    \\0hxocG/vJTj0Gs1Vkz3m2M/OiUlR0WZWoLh0NYjDk1W1Kt13yYuW7GuOndQ4g6zU
    \\0a+35HSUyRoepnRTzGN6F+YujZGfgkvl49Dz6bnBDik1+b6sYdjpH9GBckI24nzM
    \\rJIiY5IwppZRnxQaQ/0Uw0oPPuQhYeLsZiNdVnFoywKCAQBfncEzLp0uR+/LsMzT
    \\JsufLh+QCD5EqvcOT+5kxOPYXWjqgjDUDsEJhsYo+RDQY4Tj3isa8M3jm6XOlFID
    \\6dlATM1toPcMHotntN4ieSkZuq4OilHs4C0pgeIr1xpgtYMpa8GgSToseI+0k4rY
    \\9Hjh5ljCyAlbUqm4C/VIkW9nyvzuqRPFJUUPjjfAsCpcd/Ki+MjJLN5oTN8714nz
    \\q9Yu3DRb6G2kKquRrEpOFIFVgm6aZBfqZ43bQ7/MpT12yNuGHh8WuV7M4TVuQNkQ
    \\dNEwB8hunp1WE3AGzoksWOUWLA6TdVcrvYs96R95dVWQJrphWjnbD4UGIP9BUx3V
    \\F+TFAoIBAGHR33m39eu+iOH6TgOl/IiC2EfZf2fCJxPqqlAe6aOYsE0VCnmNYQL2
    \\Xp4gH4jhsMvLek+u/hSXRjbZPNzgSf8tK2fDe58VF9vbETvr8vHgEi3EYHTdIVFp
    \\/QQVcl2zTzNctqsWqPgPQpTb7y1t1FqXMGqTMAeX8E2hh9PcfavI+Mm/+BSUftQ9
    \\yj5ZkahsVQd1ttL+l3i2KLUwQBTqe9NsNbxXzYncqOQ91C8GOAZgiFsFZ64gUzyi
    \\i8m76L7twtSe8wVNHwHl94/bpd+ozwekUJxrH3xvLh6cerxexri5XzMeymnJifZw
    \\7yHoIRYv07axHZ+7/Swzj1xrHopj3hsCggEBAKz6qyZbxRIaHPAlUxHMP7QYmp0g
    \\TS+bOOHajZTMiR4oQAudlYNeyQWKqdz0QecdxB299b1R+AAEmQ7V7ZAuNm4jI8gP
    \\Lw9KKBPKt68paq1qStB1VO2O0EmrR1rgqe9hU7/w3gC190ORSEJ3Y0hOHPG9eMY5
    \\wO6vdxhWdeeqrL7t/H1imXWFqqok3zsGrZ7Oc5ROP8CUPyiN7dXSKZbgXuaDOKkU
    \\0GpcRoI+mMpsI/BbQAlzz14i0jvyr68LWb/K/Th25jDop0iXUUtQMuQbUapu/siR
    \\2z4FpSM0Ewsn0xnZkG0VRwKAkIiwmUq1Cevn3X6PRmjx7EgXGmLh4FjV11Q=
    \\-----END RSA PRIVATE KEY-----
    \\
;
// The CSR openssl builds for that key over the same two names:
//   openssl req -new -key k.pkcs8.pem -subj "/" -sha256 \
//     -addext "subjectAltName=DNS:example.com,DNS:www.example.com" -out csr.pem
//   $ openssl req -in csr.pem -verify -noout
//   Certificate request self-signature verify OK
// PKCS#1 v1.5 is deterministic, so `csrDer` for the same key and names must
// produce these exact bytes (so ours verifies under `openssl req -verify` too).
const test_rsa_openssl_csr_pem =
    \\-----BEGIN CERTIFICATE REQUEST-----
    \\MIICfzCCAWcCAQAwADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAIVy
    \\UcQ9hrj2A128Eg+sxR8oQpp4TfGYzjr1XqwGGPkUdiBBx3QmADll+kYwtZ3xxpNP
    \\w+r8qMhLdwVOFxMPejSwSYZRV0gfw2JkGRlymzhW5EuMHWiLrX0zxMbyqo4tpMOW
    \\a3dI5qPmhFJxFTNva8VgBDArqLKUFjguD68gvSkdvk2rM+Jbgr333qYIpc/sc4P5
    \\sQKxOZwMp6H+IPGJtq6aUDmiOQXbjnDJ/7KEmQHmIUhV1X3v6fJNUcO+1McaSC/j
    \\reRNnWc2sxJheio7aYsrXUHFPYr8mAcyxFulCe8crH+pnHHhHPR51CCVmQcCvpRK
    \\ivtGSP9auW7Oe8pV6qMCAwEAAaA6MDgGCSqGSIb3DQEJDjErMCkwJwYDVR0RBCAw
    \\HoILZXhhbXBsZS5jb22CD3d3dy5leGFtcGxlLmNvbTANBgkqhkiG9w0BAQsFAAOC
    \\AQEAaI/HPSAWF0mTMCcdUExhGDS02sk8GZu2tsPjguyP8Z4vhJyFkDzImGju/H6H
    \\MwwRXjJXs9zA+gGA55UrhoqXU6dG9Pz+iNYx9ZG8sCIVH7JR/2X/zyjT9izeG3dP
    \\n0U/2BEyEjFYhWmyg3cUPEur486ccPZoINWotnXxuuAjUpFWoZWhqfdLq86PJKRn
    \\EEbNGqn0yywvN/gOi49ad987xJQSeBBCwDHJy8I1o4rMMQnz2dMrxK3cpYm61LOj
    \\wq5+8TYiya3KL7SUqHhnSybZaxS3KcdnMYZQuJdtdM77wLGI6xLhQuAgB2ke7qSu
    \\xEd1CgMqgBIVHmIK1iaSDejkrw==
    \\-----END CERTIFICATE REQUEST-----
    \\
;

var test_rsa_pair_storage: rsa.KeyPair = undefined;
var test_rsa_pair_ready = false;

/// The fixture key as a pair in static storage, so tests pass it by pointer like production code.
fn testRsaPair() !*const rsa.KeyPair {
    if (!test_rsa_pair_ready) {
        try rsaPrivateKeyFromPem(&test_rsa_pair_storage, test_rsa_pkcs8_pem);
        test_rsa_pair_ready = true;
    }
    return &test_rsa_pair_storage;
}

test "RSA CSR: byte-identical to openssl's, parses back, SANs and signature verify" {
    const kp = try testRsaPair();
    const domains = [_][]const u8{ "example.com", "www.example.com" };
    const oracle = try pemDecode(testing.allocator, "CERTIFICATE REQUEST", test_rsa_openssl_csr_pem);
    defer testing.allocator.free(oracle);

    const ours = try csrDer(testing.allocator, kp, &domains);
    defer testing.allocator.free(ours);
    try testing.expectEqualSlices(u8, oracle, ours);
    // Through an AnyKeyPair (a borrowed pointer), the same bytes.
    const any: jws.AnyKeyPair = .{ .rs256 = kp };
    const via_any = try csrDer(testing.allocator, &any, &domains);
    defer testing.allocator.free(via_any);
    try testing.expectEqualSlices(u8, oracle, via_any);

    // openssl's own CSR parses and verifies.
    var parsed = try parseCsrAny(testing.allocator, oracle);
    defer parsed.deinit();
    try testing.expectEqual(Alg.rs256, parsed.public_key.alg());
    try testing.expectEqual(@as(usize, 2), parsed.sans.len);
    try testing.expectEqualStrings("example.com", parsed.sans[0]);
    try testing.expectEqualStrings("www.example.com", parsed.sans[1]);
    try testing.expect(parsed.public_key.eql(jws.publicOfPair(kp)));
    // The ES256-only parser names the algorithm as unsupported.
    try testing.expectError(error.UnsupportedCsr, parseCsr(testing.allocator, oracle));

    // Structure the CA sees: SPKI rsaEncryption + NULL, signatureAlgorithm sha256WithRSAEncryption + NULL.
    try testing.expect(std.mem.indexOf(u8, ours, "\x30\x0d\x06\x09" ++ oid_rsa_encryption ++ "\x05\x00\x03") != null);
    try testing.expect(std.mem.indexOf(u8, ours, "\x30\x0d\x06\x09" ++ oid_sha256_with_rsa ++ "\x05\x00\x03") != null);
}

test "RSA CSR: tampering, truncation and other RSA signature algorithms are refused" {
    const kp = try testRsaPair();
    const der_bytes = try csrDer(testing.allocator, kp, &.{"tamper.example"});
    defer testing.allocator.free(der_bytes);

    const at = std.mem.indexOf(u8, der_bytes, "tamper").?;
    const mutated = try testing.allocator.dupe(u8, der_bytes);
    defer testing.allocator.free(mutated);
    mutated[at] ^= 0x01;
    try testing.expectError(error.BadCsrSignature, parseCsrAny(testing.allocator, mutated));
    mutated[at] ^= 0x01;
    mutated[mutated.len - 1] ^= 0x01; // the signature's last octet
    try testing.expectError(error.BadCsrSignature, parseCsrAny(testing.allocator, mutated));
    mutated[mutated.len - 1] ^= 0x01;

    // sha384WithRSAEncryption (…01 01 0c) is a real RSA signature OID this module does not verify.
    const sig_oid_at = std.mem.lastIndexOf(u8, mutated, oid_sha256_with_rsa).?;
    mutated[sig_oid_at + oid_sha256_with_rsa.len - 1] = 0x0c;
    try testing.expectError(error.UnsupportedCsr, parseCsrAny(testing.allocator, mutated));

    var l: usize = 0;
    while (l < der_bytes.len) : (l += 13) {
        try testing.expect(if (parseCsrAny(testing.allocator, der_bytes[0..l])) |_| false else |_| true);
    }
    // Wildcards and domain validation behave as for EC keys.
    try testing.expectError(error.InvalidDomain, csrDer(testing.allocator, kp, &.{"-bad.example"}));
}

test "RSA key PEM: openssl's PKCS#1 and PKCS#8 load; ours is byte-identical to openssl" {
    var from8: rsa.KeyPair = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&from8));
    try rsaPrivateKeyFromPem(&from8, test_rsa_pkcs8_pem);
    var from1: rsa.KeyPair = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&from1));
    try rsaPrivateKeyFromPem(&from1, test_rsa_pkcs1_pem);
    try testing.expect(from8.public_key.equal(&from1.public_key));
    try testing.expect(from8.public_key.equal(&from8.secret_key.publicKey()));
    try testing.expectEqual(@as(usize, 2048), from8.public_key.bits());

    // `openssl rsa -traditional` / `openssl genrsa` write exactly these bytes.
    const pem1 = try rsaPrivateKeyToPem(testing.allocator, &from8);
    defer testing.allocator.free(pem1);
    defer std.crypto.secureZero(u8, pem1);
    try testing.expectEqualStrings(test_rsa_pkcs1_pem, pem1);
    const pem8 = try pkcs8PrivateKeyToPem(testing.allocator, &from1);
    defer testing.allocator.free(pem8);
    defer std.crypto.secureZero(u8, pem8);
    try testing.expectEqualStrings(test_rsa_pkcs8_pem, pem8);
    // An AnyKeyPair holding the pair writes the same text (Client's cert-key PEM path).
    const any: jws.AnyKeyPair = .{ .rs256 = &from8 };
    const any1 = try ecPrivateKeyToPem(testing.allocator, &any);
    defer testing.allocator.free(any1);
    defer std.crypto.secureZero(u8, any1);
    try testing.expectEqualStrings(test_rsa_pkcs1_pem, any1);
    const any8 = try pkcs8PrivateKeyToPem(testing.allocator, &any);
    defer testing.allocator.free(any8);
    defer std.crypto.secureZero(u8, any8);
    try testing.expectEqualStrings(test_rsa_pkcs8_pem, any8);

    // Leading junk and other PEM blocks are skipped; a PKCS#8 block is found after a PKCS#1-less preamble.
    var skip: rsa.KeyPair = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&skip));
    try rsaPrivateKeyFromPem(&skip, "junk\n-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n" ++ test_rsa_pkcs8_pem);
    try testing.expect(skip.public_key.equal(&from8.public_key));

    // Refusals (and `out` zeroed): no block, a block that is not a key, a 1024-bit key.
    var bad: rsa.KeyPair = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&bad));
    try testing.expectError(error.MissingPemBlock, rsaPrivateKeyFromPem(&bad, "no pem here"));
    try testing.expectError(error.MissingPemBlock, rsaPrivateKeyFromPem(&bad, "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n"));
    @memset(std.mem.asBytes(&bad), 0xaa);
    try testing.expectError(error.MalformedKey, rsaPrivateKeyFromPem(&bad, "-----BEGIN RSA PRIVATE KEY-----\nMAA=\n-----END RSA PRIVATE KEY-----\n"));
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&bad), 0));
    @memset(std.mem.asBytes(&bad), 0xaa);
    try testing.expectError(error.MalformedKey, rsaPrivateKeyFromPem(&bad, test_rsa1024_pkcs1_pem));
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&bad), 0));
    // An EC PKCS#8 key is not an RSA key.
    try testing.expectError(error.MalformedKey, rsaPrivateKeyFromPem(&bad, openssl_p256_pkcs8));

    // The EC loaders refuse RSA PEMs (an AnyKeyPair has no storage for an RSA pair).
    var ec: jws.AnyKeyPair = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&ec));
    // A 2048-bit PKCS#8 body overflows the EC loaders' 1 KiB secret-DER buffer first.
    try testing.expectError(error.InvalidPem, privateKeyFromPem(&ec, testing.allocator, test_rsa_pkcs8_pem));
    try testing.expectError(error.MissingPemBlock, privateKeyFromPem(&ec, testing.allocator, test_rsa_pkcs1_pem));
}

test "RSA key PEM: the 4096-bit ceiling is inclusive; with both labels present the first block wins" {
    var kp: rsa.KeyPair = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&kp));
    try rsaPrivateKeyFromPem(&kp, test_rsa4096_pkcs1_pem);
    try testing.expectEqual(@as(usize, jws.rsa_max_bits), kp.public_key.bits());

    // PKCS#1 before PKCS#8 and the other way round: the earlier block is
    // read. The 1024-bit key is the marker (refused), the 2048-bit one good.
    try testing.expectError(error.MalformedKey, rsaPrivateKeyFromPem(&kp, test_rsa1024_pkcs1_pem ++ test_rsa_pkcs8_pem));
    try rsaPrivateKeyFromPem(&kp, test_rsa_pkcs8_pem ++ test_rsa1024_pkcs1_pem);
    try testing.expectEqual(@as(usize, 2048), kp.public_key.bits());
}

test "TLS-ALPN-01 certificate: an RSA pair is refused (the validation key is EC)" {
    const kp = try testRsaPair();
    const any: jws.AnyKeyPair = .{ .rs256 = kp };
    const id: [32]u8 = @splat(0xAB);
    try testing.expectError(error.SigningFailed, tlsAlpnCertDer(testing.allocator, &any, "example.org", id, "\x01", tls_alpn_not_before, tls_alpn_not_after));
}

// `openssl req -new -key k.pem -subj / -addext
//  "subjectAltName=IP:192.0.2.1,IP:2001:db8::1,DNS:a.example" -outform DER`
// (OpenSSL 3.5.5, P-256 key; `openssl req -verify` OK).
const openssl_ip_csr_hex = "3081fb3081a102010030003059301306072a8648ce3d020106082a8648ce3d03010703420004f45aeeb349ed660135e274eacec814bbd7eb0a10ae13397b6a1d1a99fa64ee8b9ddabd6aedf91d8a236927a8c0c97936275d3b418c099475f5b7f74cb71f6145a03f303d06092a864886f70d01090e3130302e302c0603551d11042530238704c0000201871020010db80000000000000000000000018209612e6578616d706c65300a06082a8648ce3d0403020349003046022100a365eb67b0eefc069f5012522ac5fc4a74b933e9ade91a70944f49459a44ec37022100ed949f0931d7d0e242daa0973ccbfd7e930a966af166668e5993b1df16f24d60";

test "IP SANs (RFC 8738): csrDer writes openssl's GeneralNames; both CSRs parse back" {
    // The GeneralNames inside openssl's CSR: [7] c0000201, [7] 2001:db8::1, [2] a.example.
    const openssl_names = "\x30\x23\x87\x04\xc0\x00\x02\x01\x87\x10\x20\x01\x0d\xb8" ++ strRepeat("\x00", 11) ++
        "\x01\x82\x09a.example";
    const ours = try csrDer(testing.allocator, testKeyPair(42), &.{ "192.0.2.1", "2001:db8::1", "a.example" });
    defer testing.allocator.free(ours);
    try testing.expect(std.mem.indexOf(u8, ours, openssl_names) != null);

    var csr: [openssl_ip_csr_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&csr, openssl_ip_csr_hex);
    for ([_][]const u8{ ours, &csr }) |der_bytes| {
        var parsed = try parseCsrAny(testing.allocator, der_bytes);
        defer parsed.deinit();
        try testing.expectEqual(@as(usize, 1), parsed.sans.len);
        try testing.expectEqualStrings("a.example", parsed.sans[0]);
        try testing.expectEqual(@as(usize, 2), parsed.ip_sans.len);
        try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, parsed.ip_sans[0]);
        try testing.expectEqualSlices(u8, &(netaddr.parseIp6("2001:db8::1").?), parsed.ip_sans[1]);
    }
    // A 5-octet iPAddress is malformed.
    var bad = csr;
    const at = std.mem.indexOf(u8, &bad, "\x87\x04").?;
    bad[at + 1] = 5;
    try testing.expectError(error.MalformedCsr, parseCsrAny(testing.allocator, &bad));
}

// ── audit 2026-10-18: tests asked for by mutation survivors ─────────────────

test "isValidDomain: upper-case letters are hostname characters" {
    try testing.expect(isValidDomain("ZZ.Example"));
    try testing.expect(isValidDomain("Zed"));
}

test "pemDecode: an END line before the BEGIN line is not the end of the block" {
    const gpa = testing.allocator;
    const pem = try pemEncode(gpa, "CERTIFICATE", "abc-der");
    defer gpa.free(pem);
    const text = try std.fmt.allocPrint(gpa, "-----END CERTIFICATE-----\n{s}", .{pem});
    defer gpa.free(text);
    const der_bytes = try pemDecode(gpa, "CERTIFICATE", text);
    defer gpa.free(der_bytes);
    try testing.expectEqualStrings("abc-der", der_bytes);
}

test "EC private key PEM: an empty block body is InvalidPem" {
    var kp: Es256.KeyPair = undefined;
    try testing.expectError(error.InvalidPem, ecPrivateKeyFromPem(&kp, testing.allocator, "-----BEGIN EC PRIVATE KEY-----\n-----END EC PRIVATE KEY-----\n"));
}

test "PKCS#8 PEM: a version other than 0 or 1, or another key algorithm, is MalformedKey" {
    const gpa = testing.allocator;
    const pem = try pkcs8PrivateKeyToPem(gpa, testKeyPair(7));
    defer gpa.free(pem);
    const good = try pemDecode(gpa, "PRIVATE KEY", pem);
    defer gpa.free(good);
    var out: Es256.KeyPair = undefined;
    try pkcs8PrivateKeyFromPem(&out, gpa, pem);

    const off: usize = if (good[1] == 0x81) 3 else if (good[1] == 0x82) 4 else 2; // after SEQUENCE's header
    try testing.expectEqual(@as(u8, 0x02), good[off]);
    try testing.expectEqual(@as(u8, 0x00), good[off + 2]);
    const bad_version = try gpa.dupe(u8, good);
    defer gpa.free(bad_version);
    bad_version[off + 2] = 2;
    const bad_version_pem = try pemEncode(gpa, "PRIVATE KEY", bad_version);
    defer gpa.free(bad_version_pem);
    try testing.expectError(error.MalformedKey, pkcs8PrivateKeyFromPem(&out, gpa, bad_version_pem));

    const bad_alg = try gpa.dupe(u8, good);
    defer gpa.free(bad_alg);
    const at = std.mem.indexOf(u8, bad_alg, oid_ec_public_key).?;
    bad_alg[at + oid_ec_public_key.len - 1] ^= 1;
    const bad_alg_pem = try pemEncode(gpa, "PRIVATE KEY", bad_alg);
    defer gpa.free(bad_alg_pem);
    try testing.expectError(error.MalformedKey, pkcs8PrivateKeyFromPem(&out, gpa, bad_alg_pem));
}

test "EC private key PEM: a bare ECPrivateKey with only version and scalar loads into a typed pair" {
    const gpa = testing.allocator;
    const der_bytes = [_]u8{ 0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20 } ++ @as([32]u8, @splat(0x01));
    const pem = try pemEncode(gpa, "EC PRIVATE KEY", &der_bytes);
    defer gpa.free(pem);
    var out: Es256.KeyPair = undefined;
    try ecPrivateKeyFromPem(&out, gpa, pem);
    try testing.expectEqualSlices(u8, &(@as([32]u8, @splat(0x01))), &out.secret_key.toBytes());
}

test "EC private key PEM: a dash inside the body is not the END line" {
    var kp: Es256.KeyPair = undefined;
    try testing.expectError(error.InvalidPem, ecPrivateKeyFromPem(&kp, testing.allocator, "-----BEGIN EC PRIVATE KEY-----\nAAAA-XYZ\n-----END EC PRIVATE KEY-----\n"));
}

test "pemBlockCount counts every block; PKCS#8 version 1 is accepted" {
    const gpa = testing.allocator;
    const pem = try pkcs8PrivateKeyToPem(gpa, testKeyPair(7));
    defer gpa.free(pem);
    const two = try std.fmt.allocPrint(gpa, "{s}{s}", .{ pem, pem });
    defer gpa.free(two);
    try testing.expectEqual(@as(usize, 2), try pemBlockCount("PRIVATE KEY", two));

    const good = try pemDecode(gpa, "PRIVATE KEY", pem);
    defer gpa.free(good);
    const off: usize = if (good[1] == 0x81) 3 else if (good[1] == 0x82) 4 else 2;
    const v1 = try gpa.dupe(u8, good);
    defer gpa.free(v1);
    v1[off + 2] = 1; // RFC 5958 version 2 (v2) writes 1
    const v1_pem = try pemEncode(gpa, "PRIVATE KEY", v1);
    defer gpa.free(v1_pem);
    var out: Es256.KeyPair = undefined;
    try pkcs8PrivateKeyFromPem(&out, gpa, v1_pem);
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    const rep_result = comptime blk: {
        @setEvalBranchQuota(n * (s.len + 4) + 1000);
        var buf: [s.len * n:0]u8 = undefined;
        for (0..n) |i| @memcpy(buf[i * s.len ..][0..s.len], s);
        const rep_final = buf;
        break :blk rep_final;
    };
    return &rep_result;
}
