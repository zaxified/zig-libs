// SPDX-License-Identifier: MIT

//! Minimal X.509/PKCS building blocks for ACME: a small DER encoder, the
//! PKCS#10 certification request (RFC 2986) with a subjectAltName extension
//! request — the one ASN.1 structure an ACME client must *produce* — plus
//! PEM encode/decode, RFC 5915 EC private-key serialization and certificate
//! `notAfter` extraction (via `std.crypto.Certificate`, an independent
//! parser from the encoder here).
//!
//! Scope is deliberately tiny: P-256 keys, ES256 signatures, dNSName SANs.
//! The CSR uses an **empty subject** — RFC 8555 §7.4 requires the SAN
//! extension to carry the identifiers and Let's Encrypt ignores (and is
//! phasing out) the CN; skipping CN also avoids its 64-byte limit.
//! Everything decodes back: `parseCsr` is the bounds-checked structural
//! parser used by tests and by the mock CA to validate what we emit.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Es256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

// ── DER encoding (bottom-up, arena-backed) ──────────────────────────────────

pub const DerEncodeError = error{ OutOfMemory, ValueTooLarge };

/// Tiny DER builder: every helper returns a complete TLV slice allocated
/// from `a` (use an arena and free everything at once).
const Der = struct {
    a: Allocator,

    fn tlv(d: Der, tag: u8, content: []const u8) DerEncodeError![]const u8 {
        var head: [4]u8 = undefined;
        const head_len = try encodeHeader(&head, tag, content.len);
        const out = try d.a.alloc(u8, head_len + content.len);
        @memcpy(out[0..head_len], head[0..head_len]);
        @memcpy(out[head_len..], content);
        return out;
    }

    fn encodeHeader(buf: *[4]u8, tag: u8, len: usize) DerEncodeError!usize {
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
        return error.ValueTooLarge; // nothing here is remotely this large
    }

    fn cat(d: Der, parts: []const []const u8) DerEncodeError![]const u8 {
        return std.mem.concat(d.a, u8, parts);
    }

    fn seq(d: Der, parts: []const []const u8) DerEncodeError![]const u8 {
        return d.tlv(0x30, try d.cat(parts));
    }

    fn oid(d: Der, encoded: []const u8) DerEncodeError![]const u8 {
        return d.tlv(0x06, encoded);
    }

    /// BIT STRING with zero unused bits.
    fn bitString(d: Der, bytes: []const u8) DerEncodeError![]const u8 {
        return d.tlv(0x03, try d.cat(&.{ "\x00", bytes }));
    }
};

// Pre-encoded OID content bytes.
const oid_ec_public_key = "\x2a\x86\x48\xce\x3d\x02\x01"; // 1.2.840.10045.2.1
const oid_p256 = "\x2a\x86\x48\xce\x3d\x03\x01\x07"; // 1.2.840.10045.3.1.7
const oid_ecdsa_sha256 = "\x2a\x86\x48\xce\x3d\x04\x03\x02"; // 1.2.840.10045.4.3.2
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

// ── PKCS#10 CSR ─────────────────────────────────────────────────────────────

pub const CsrError = error{ OutOfMemory, ValueTooLarge, InvalidDomain, SigningFailed };

/// Build a DER-encoded PKCS#10 CSR for `domains`, signed with `key_pair`
/// (ES256). Structure: version 0, empty subject, P-256 SPKI, one
/// extensionRequest attribute carrying subjectAltName = dNSName list.
/// Caller owns the returned bytes.
pub fn csrDer(gpa: Allocator, key_pair: Es256.KeyPair, domains: []const []const u8) CsrError![]u8 {
    if (domains.len == 0) return error.InvalidDomain;
    for (domains) |name| {
        if (!isValidDomain(name)) return error.InvalidDomain;
    }

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const d: Der = .{ .a = arena.allocator() };

    // SubjectPublicKeyInfo: { { id-ecPublicKey, prime256v1 }, BIT STRING key }.
    const pub_sec1 = key_pair.public_key.toUncompressedSec1();
    const spki = try d.seq(&.{
        try d.seq(&.{ try d.oid(oid_ec_public_key), try d.oid(oid_p256) }),
        try d.bitString(&pub_sec1),
    });

    // subjectAltName GeneralNames: dNSName is [2] IMPLICIT IA5String.
    const names = try d.a.alloc([]const u8, domains.len);
    for (names, domains) |*slot, name| slot.* = try d.tlv(0x82, name);
    const san_value = try d.seq(names);
    const san_ext = try d.seq(&.{
        try d.oid(oid_subject_alt_name),
        // criticality omitted (DEFAULT FALSE), then extnValue OCTET STRING.
        try d.tlv(0x04, san_value),
    });
    const extensions = try d.seq(&.{san_ext});

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
    const sig = key_pair.sign(info, null) catch return error.SigningFailed;
    var sig_buf: [Es256.Signature.der_encoded_length_max]u8 = undefined;
    const sig_der = sig.toDer(&sig_buf);

    const csr = try d.seq(&.{
        info,
        try d.seq(&.{try d.oid(oid_ecdsa_sha256)}), // ecdsa-with-SHA256, params absent
        try d.bitString(sig_der),
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
    key_pair: Es256.KeyPair,
    domain: []const u8,
    acme_identifier: [32]u8,
    serial: []const u8,
    not_before: []const u8,
    not_after: []const u8,
) TlsAlpnError![]u8 {
    if (!isValidDomain(domain)) return error.InvalidDomain;

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const d: Der = .{ .a = arena.allocator() };

    // SubjectPublicKeyInfo — identical shape to the CSR's.
    const pub_sec1 = key_pair.public_key.toUncompressedSec1();
    const spki = try d.seq(&.{
        try d.seq(&.{ try d.oid(oid_ec_public_key), try d.oid(oid_p256) }),
        try d.bitString(&pub_sec1),
    });

    // AlgorithmIdentifier ecdsa-with-SHA256 (params absent) — shared by the
    // inner `signature` field and the outer `signatureAlgorithm`.
    const alg_id = try d.seq(&.{try d.oid(oid_ecdsa_sha256)});

    // Validity ::= SEQUENCE { notBefore UTCTime, notAfter UTCTime }.
    const validity = try d.seq(&.{
        try d.tlv(0x17, not_before),
        try d.tlv(0x17, not_after),
    });

    // subjectAltName: GeneralNames { [2] dNSName }, marked critical because
    // the subject is empty (RFC 5280 §4.2.1.6).
    const san_names = try d.seq(&.{try d.tlv(0x82, domain)});
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
    var sig_buf: [Es256.Signature.der_encoded_length_max]u8 = undefined;
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
    var key_pair = Es256.KeyPair.generateDeterministic(seed) catch return error.SigningFailed;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&key_pair));
    std.crypto.secureZero(u8, &seed);

    // 16-byte positive, minimal serial: force the top byte to 0x01..0x7f so
    // it is nonzero and has no leading-zero / high-bit ambiguity.
    var serial: [16]u8 = undefined;
    random.bytes(&serial);
    serial[0] = (serial[0] & 0x7f) | 0x01;

    const cert_der = try tlsAlpnCertDer(
        gpa,
        key_pair,
        domain,
        acme_identifier,
        &serial,
        tls_alpn_not_before,
        tls_alpn_not_after,
    );
    errdefer gpa.free(cert_der);
    const key_pem = try ecPrivateKeyToPem(gpa, key_pair);
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

/// Structural well-formedness scan: every element reachable through
/// constructed elements stays in bounds and tiles its parent. Run before
/// handing untrusted DER to `std.crypto.Certificate` (whose element parser
/// assumes well-formed lengths).
fn derWellFormed(bytes: []const u8) bool {
    return wellFormedRange(bytes, 0, bytes.len, 0) catch false;
}

fn wellFormedRange(bytes: []const u8, at: usize, end: usize, depth: u8) ReadError!bool {
    if (depth > 32) return error.Malformed;
    var index = at;
    while (index < end) {
        const e = try readElem(bytes, index);
        if (e.end > end) return error.Malformed;
        const constructed = (e.tag & 0x20) != 0;
        if (constructed) {
            if (!try wellFormedRange(bytes, e.start, e.end, depth + 1)) return false;
        }
        index = e.end;
    }
    return index == end;
}

// ── CSR parse-back (test / mock-CA oracle) ──────────────────────────────────

pub const ParseCsrError = error{ OutOfMemory, MalformedCsr, UnsupportedCsr, BadCsrSignature };

/// A structurally validated, signature-checked CSR.
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

/// Decode + verify a CSR of the exact shape `csrDer` produces (P-256 /
/// ES256 / SAN extension request): checks version, algorithms, extracts the
/// dNSName SANs and verifies the self-signature. The oracle half of the
/// encoder — also what the mock CA runs against the client's finalize.
pub fn parseCsr(gpa: Allocator, der_bytes: []const u8) ParseCsrError!ParsedCsr {
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
) (ReadError || error{ OutOfMemory, UnsupportedCsr, BadCsrSignature })!ParsedCsr {
    const csr = try expectElem(bytes, 0, 0x30);
    if (csr.end != bytes.len) return error.Malformed; // no trailing garbage

    const info = try expectElem(bytes, csr.start, 0x30);
    const info_full = bytes[info.hdr..info.end]; // signed bytes (header included)

    // version INTEGER 0
    const version = try expectElem(bytes, info.start, 0x02);
    if (!std.mem.eql(u8, version.content(bytes), "\x00")) return error.UnsupportedCsr;
    // subject (content not interpreted)
    const subject = try expectElem(bytes, version.end, 0x30);

    // SPKI: alg = { id-ecPublicKey, prime256v1 }, key = BIT STRING.
    const spki = try expectElem(bytes, subject.end, 0x30);
    const spki_alg = try expectElem(bytes, spki.start, 0x30);
    const alg_oid = try expectElem(bytes, spki_alg.start, 0x06);
    if (!std.mem.eql(u8, alg_oid.content(bytes), oid_ec_public_key)) return error.UnsupportedCsr;
    const curve_oid = try expectElem(bytes, alg_oid.end, 0x06);
    if (!std.mem.eql(u8, curve_oid.content(bytes), oid_p256)) return error.UnsupportedCsr;
    const key_bits = try expectElem(bytes, spki_alg.end, 0x03);
    const key_content = key_bits.content(bytes);
    if (key_content.len != 66 or key_content[0] != 0) return error.UnsupportedCsr;
    const public_key = Es256.PublicKey.fromSec1(key_content[1..]) catch return error.UnsupportedCsr;

    // Attributes [0] → extensionRequest → Extensions → subjectAltName.
    const attributes = try expectElem(bytes, spki.end, 0xa0);
    const sans = try findSans(gpa, bytes, attributes);
    errdefer gpa.free(sans);

    // signatureAlgorithm must be ecdsa-with-SHA256, signature a BIT STRING.
    const sig_alg = try expectElem(bytes, info.end, 0x30);
    const sig_oid = try expectElem(bytes, sig_alg.start, 0x06);
    if (!std.mem.eql(u8, sig_oid.content(bytes), oid_ecdsa_sha256)) return error.UnsupportedCsr;
    const sig_bits = try expectElem(bytes, sig_alg.end, 0x03);
    const sig_content = sig_bits.content(bytes);
    if (sig_content.len < 1 or sig_content[0] != 0) return error.Malformed;

    const sig = Es256.Signature.fromDer(sig_content[1..]) catch return error.BadCsrSignature;
    sig.verify(info_full, public_key) catch return error.BadCsrSignature;

    return .{ .gpa = gpa, .sans = sans, .public_key = public_key };
}

fn findSans(
    gpa: Allocator,
    bytes: []const u8,
    attributes: Elem,
) (ReadError || error{ OutOfMemory, UnsupportedCsr })![]const []const u8 {
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
            return collectDnsNames(gpa, bytes, next);
        }
    }
    return error.UnsupportedCsr; // no SAN — not a CSR this module produced
}

fn collectDnsNames(
    gpa: Allocator,
    bytes: []const u8,
    extn_value: Elem,
) (ReadError || error{OutOfMemory})![]const []const u8 {
    const general_names = try expectElem(bytes, extn_value.start, 0x30);
    var list: std.ArrayList([]const u8) = .empty;
    errdefer list.deinit(gpa);
    var at = general_names.start;
    while (at < general_names.end) {
        const name = try readElem(bytes, at);
        at = name.end;
        if (name.tag == 0x82) try list.append(gpa, name.content(bytes)); // dNSName
    }
    return list.toOwnedSlice(gpa);
}

// ── PEM ─────────────────────────────────────────────────────────────────────

pub const PemDecodeError = error{ OutOfMemory, MissingPemBlock, InvalidPem };

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
    std.debug.assert(label.len <= max_pem_label_len);
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

/// Number of `-----BEGIN <label>-----` blocks in `text`.
pub fn pemBlockCount(label: []const u8, text: []const u8) usize {
    std.debug.assert(label.len <= max_pem_label_len);
    var begin_buf: [max_pem_label_len + 16]u8 = undefined;
    const begin = std.fmt.bufPrint(&begin_buf, "-----BEGIN {s}-----", .{label}) catch unreachable;
    return std.mem.count(u8, text, begin);
}

// ── EC private key (RFC 5915) ───────────────────────────────────────────────

pub const KeyPemError = error{ OutOfMemory, MissingPemBlock, InvalidPem, MalformedKey };

/// Serialize a P-256 key pair as an openssl-compatible `EC PRIVATE KEY`
/// PEM (RFC 5915: version 1, private scalar, curve OID, public point).
pub fn ecPrivateKeyToPem(gpa: Allocator, key_pair: Es256.KeyPair) error{OutOfMemory}![]u8 {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const d: Der = .{ .a = arena.allocator() };

    const sk = key_pair.secret_key.toBytes();
    const pub_sec1 = key_pair.public_key.toUncompressedSec1();
    const ec = ecKeyDer(d, &sk, &pub_sec1) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ValueTooLarge => unreachable, // fixed-size structure
    };
    return pemEncode(gpa, "EC PRIVATE KEY", ec);
}

fn ecKeyDer(d: Der, sk: []const u8, pub_sec1: []const u8) DerEncodeError![]const u8 {
    return d.seq(&.{
        try d.tlv(0x02, "\x01"), // ecPrivkeyVer1
        try d.tlv(0x04, sk),
        try d.tlv(0xa0, try d.oid(oid_p256)), // parameters [0]
        try d.tlv(0xa1, try d.bitString(pub_sec1)), // publicKey [1]
    });
}

/// Load a P-256 key pair from an `EC PRIVATE KEY` PEM (RFC 5915 — the
/// format `ecPrivateKeyToPem` and `openssl ecparam -genkey` write; PKCS#8
/// `PRIVATE KEY` wrapping is not supported). `gpa` is scratch only.
pub fn ecPrivateKeyFromPem(gpa: Allocator, text: []const u8) KeyPemError!Es256.KeyPair {
    const der_bytes = try pemDecode(gpa, "EC PRIVATE KEY", text);
    defer gpa.free(der_bytes);
    return ecPrivateKeyFromDer(der_bytes) catch error.MalformedKey;
}

fn ecPrivateKeyFromDer(bytes: []const u8) (ReadError || error{MalformedKey})!Es256.KeyPair {
    const seq = try expectElem(bytes, 0, 0x30);
    const version = try expectElem(bytes, seq.start, 0x02);
    if (!std.mem.eql(u8, version.content(bytes), "\x01")) return error.MalformedKey;
    const priv = try expectElem(bytes, version.end, 0x04);
    const raw = priv.content(bytes);
    if (raw.len == 0 or raw.len > 32) return error.MalformedKey;
    var sk_bytes: [32]u8 = @splat(0);
    @memcpy(sk_bytes[32 - raw.len ..], raw); // RFC 5915 fixes the length; tolerate short
    const sk = Es256.SecretKey.fromBytes(sk_bytes) catch return error.MalformedKey;
    return Es256.KeyPair.fromSecretKey(sk) catch error.MalformedKey;
}

// ── certificate notAfter ────────────────────────────────────────────────────

pub const CertError = error{ OutOfMemory, MissingPemBlock, InvalidPem, MalformedCertificate };

/// `notAfter` (epoch seconds, UTC) of the FIRST certificate in a PEM chain.
/// Parsing is `std.crypto.Certificate` (independent of this file's encoder),
/// behind a bounds-checked structural pre-scan so malformed input errors
/// instead of tripping safety checks.
pub fn certNotAfter(gpa: Allocator, cert_pem: []const u8) CertError!u64 {
    const der_bytes = try pemDecode(gpa, "CERTIFICATE", cert_pem);
    defer gpa.free(der_bytes);
    if (der_bytes.len > std.math.maxInt(u32)) return error.MalformedCertificate;
    if (!derWellFormed(der_bytes)) return error.MalformedCertificate;
    const cert: std.crypto.Certificate = .{ .buffer = der_bytes, .index = 0 };
    const parsed = cert.parse() catch return error.MalformedCertificate;
    return parsed.validity.not_after;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn testKeyPair(comptime seed_byte: u8) Es256.KeyPair {
    return Es256.KeyPair.generateDeterministic(@splat(seed_byte)) catch unreachable;
}

test "DER: header length forms (short, 0x81, 0x82)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const d: Der = .{ .a = arena.allocator() };

    const short = try d.tlv(0x04, "abc");
    try testing.expectEqualSlices(u8, "\x04\x03abc", short);

    const mid = try d.tlv(0x04, "x" ** 200);
    try testing.expectEqualSlices(u8, "\x04\x81\xc8", mid[0..3]);
    try testing.expectEqual(@as(usize, 203), mid.len);

    const long = try d.tlv(0x04, "y" ** 300);
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
        "",              ".",            "example..com", "-bad.example", "bad-.example",
        "*.example.com", "exa mple.com",
        "chybí.diakritika",
        "x" ** 254,
    };
    for (cases) |bad| {
        try testing.expectError(error.InvalidDomain, csrDer(testing.allocator, kp, &.{bad}));
        try testing.expect(!isValidDomain(bad));
    }
    try testing.expectError(error.InvalidDomain, csrDer(testing.allocator, kp, &.{}));
    try testing.expect(isValidDomain("a.example"));
    try testing.expect(isValidDomain("xn--hkyrky-ptac70bc.example"));
    try testing.expect(isValidDomain("127.0.0.1")); // IP-shaped names pass the LDH check (mock/test use)
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
    const kp = try ecPrivateKeyFromPem(testing.allocator, cert.key_pem);
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
    const payload = "\x01\x02\x03" ++ ("D" ** 100); // forces a 2-line body
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
    try testing.expectEqual(@as(usize, 1), pemBlockCount("CERTIFICATE", noisy));
    try testing.expectEqual(@as(usize, 1), pemBlockCount("EC PRIVATE KEY", noisy));

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
    const back = try ecPrivateKeyFromPem(testing.allocator, pem);
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
    const parsed = try ecPrivateKeyFromPem(testing.allocator, openssl_key);
    // The [1] public-key BIT STRING in the fixture must match the point we
    // re-derive from the private scalar (cross-checks scalar-mult too).
    const der_bytes = try pemDecode(testing.allocator, "EC PRIVATE KEY", openssl_key);
    defer testing.allocator.free(der_bytes);
    const derived = parsed.public_key.toUncompressedSec1();
    try testing.expect(std.mem.indexOf(u8, der_bytes, &derived) != null);

    try testing.expectError(error.MissingPemBlock, ecPrivateKeyFromPem(testing.allocator, "no pem here"));
    try testing.expectError(error.MalformedKey, ecPrivateKeyFromPem(
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

fn fuzzParseCsr(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    // The CSR DER decoder (parse-back oracle side of csrDer/the mock CA's
    // finalize path): arbitrary bytes must only ever yield a typed error,
    // never a panic/OOB — and any success must be freed.
    var parsed = parseCsr(testing.allocator, buf[0..len]) catch return;
    parsed.deinit();
}

test "fuzz: parseCsr never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzParseCsr, .{});
}
