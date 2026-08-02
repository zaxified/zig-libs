// SPDX-License-Identifier: MIT
//! ocsp — RFC 6960 Online Certificate Status Protocol: build an OCSPRequest,
//! and (the security core) parse + cryptographically VERIFY an OCSPResponse and
//! extract a certificate's revocation status. The intended consumer is the P2
//! production HTTPS server's OCSP-stapling path — it fetches a signed OCSP
//! response for its own certificate and staples it into the TLS handshake, and
//! a client validates the stapled response before trusting the connection.
//!
//! ## What this module does
//!
//! - `buildRequest` — construct a DER `OCSPRequest` for a (subject, issuer)
//!   certificate pair: a single `CertID` = { hashAlgorithm (SHA-1 or SHA-256),
//!   issuerNameHash = H(issuer subject DN DER), issuerKeyHash = H(issuer
//!   subjectPublicKey BIT STRING value), serialNumber }, with an optional
//!   `id-pkix-ocsp-nonce` extension.
//! - `parseResponse` — bounds-checked, allocation-free DER decode of an
//!   `OCSPResponse` into views over the caller's buffer: response status, and
//!   for a successful `id-pkix-ocsp-basic` response the `tbsResponseData`,
//!   responderID, producedAt, the `SingleResponse` list, the responder
//!   signature + algorithm, any embedded responder certs, and a response nonce.
//! - `verify` — THE security-critical operation. Given a parsed response, the
//!   issuer certificate and the subject certificate, it establishes: (1) the
//!   responder is authorized (either the issuing CA itself, matched by name or
//!   key hash, OR a delegated responder cert carried in the response, directly
//!   signed by the issuer and bearing the id-kp-OCSPSigning EKU — RFC 6960
//!   §4.2.2.2); (2) the `tbsResponseData` signature verifies under the
//!   responder's key (RSA PKCS#1 v1.5 SHA-1/256/384/512, or ECDSA-P256
//!   SHA-256); (3) the `CertID` in the matched `SingleResponse` recomputes
//!   exactly to the subject cert (issuerNameHash/issuerKeyHash/serial) so the
//!   response actually applies to it; (4) `thisUpdate <= now <= nextUpdate`
//!   (caller-supplied `now_unix`, never a system clock; a configurable max-age
//!   bounds a missing nextUpdate); (5) a request nonce, if one was sent,
//!   matches. It returns a structured `Verdict` (good / revoked{time,reason} /
//!   unknown, responder identity, validity window) or a typed failure.
//!
//! ## Defensive DER posture
//!
//! A stapled OCSP response is fully attacker-influenceable (a MITM supplies it
//! in the handshake), and the delegated-responder certificate inside it is too.
//! Every byte decoded here goes through `x509.extensions.parseElement` — the
//! sibling x509 module's bounds-SAFE wrapper around
//! `std.crypto.Certificate.der.Element.parse`, which pre/post-validates every
//! offset so a malformed length yields a catchable error instead of a process
//! abort. This module NEVER calls `std.crypto.Certificate.parse` on untrusted
//! input (its extension-walk can panic on hostile DER in Zig 0.16); it walks
//! certificate structure itself with the same bounded reader. Trailing garbage
//! is rejected, all lengths are bounded, and every failure mode is a typed
//! error — the module fails closed.
//!
//! ## Reuse
//!
//! DER *decoding* primitives (`parseElement`, the `der.Element`/`Tag` types)
//! and the id-kp-OCSPSigning EKU check (`extensions.hasPurpose` +
//! `extensions.Purpose.ocsp_signing`) are reused from the sibling `x509`
//! module — no second ASN.1 reader is written here. Responder-signature
//! verification reuses `rsa.verifyPkcs1v15` and `p256.sign.ecdsaVerify`. Only the
//! narrow cert-structure walk (locating subject DN / SPKI / serial / validity /
//! tbs / signature) is local, because x509's equivalent (`chain.parseShape`) is
//! private; it is built on the same bounded `parseElement`.
//!
//! ## Deferred (out of scope by design)
//!
//! - OCSP *stapling* wire integration (embedding/reading the response in the
//!   TLS `status_request` extension) — that is the TLS server's job; this is
//!   the response library it calls.
//! - CRL-based revocation (a separate mechanism/module).
//! - Full path building for the delegated responder beyond the single
//!   issuer→responder link RFC 6960 §4.2.2.2 requires (the responder MUST be
//!   directly issued by the CA that issued the certificate in question).
//! - ECDSA-P256 with SHA-384/512 responder signatures (SHA-256 is the standard
//!   pairing and the only one seen in practice); RSA covers all three digests.
//!
//! Provenance: clean-room from RFC 6960 (a public IETF specification). Built on
//! this repo's `x509` (DER reader + EKU), `rsa` (RFC 8017 PKCS#1) and `p256`
//! (ECDSA-P256) modules. See SPEC.md / README.md.

const std = @import("std");
const x509 = @import("x509");
const rsa = @import("rsa");
const p256 = @import("p256");

const ext = x509.extensions;
const der = std.crypto.Certificate.der;
const Element = der.Element;

const Sha1 = std.crypto.hash.Sha1;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;
const Sha512 = std.crypto.hash.sha2.Sha512;

pub const der_writer = @import("der_writer.zig");
const Builder = der_writer.Builder;

pub const meta = .{
    .platform = .any,
    .role = .util, // pure request-build + response-verify logic; no I/O, no wire framing
    .concurrency = .reentrant, // no shared/global state; value-in / value-out
    .model_after = "RFC 6960 (OCSP); built on x509 (DER + EKU), rsa (PKCS#1), p256 (ECDSA)",
    .deps = .{ "x509", "rsa", "p256" },
};

// ── OID content octets (tag/length stripped) ────────────────────────────────

const oid_ocsp_basic = [_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01 }; // 1.3.6.1.5.5.7.48.1.1
const oid_ocsp_nonce = [_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02 }; // 1.3.6.1.5.5.7.48.1.2

const oid_sha1 = [_]u8{ 0x2b, 0x0e, 0x03, 0x02, 0x1a }; // 1.3.14.3.2.26
const oid_sha256 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 }; // 2.16.840.1.101.3.4.2.1
const oid_sha384 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02 };
const oid_sha512 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 };

const oid_rsa_encryption = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 }; // 1.2.840.113549.1.1.1
const oid_ec_public_key = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 }; // 1.2.840.10045.2.1

const oid_sha1_rsa = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05 };
const oid_sha256_rsa = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b };
const oid_sha384_rsa = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c };
const oid_sha512_rsa = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d };
const oid_ecdsa_sha256 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 }; // 1.2.840.10045.4.3.2

// ── low-level bounded DER reader (all on x509's parseElement) ────────────────

const Malformed = error{Malformed};

fn el(bytes: []const u8, index: u32) Malformed!Element {
    return ext.parseElement(bytes, index) catch error.Malformed;
}

/// Raw identifier octet — for context-specific/unnamed tags where the `Tag`
/// enum has no variant (`[0]` = 0x80/0xa0, ENUMERATED = 0x0a, …), mirroring the
/// `@bitCast` idiom x509's own extension walk uses.
fn rawTag(e: Element) u8 {
    return @as(u8, @bitCast(e.identifier));
}

fn contentOf(bytes: []const u8, e: Element) []const u8 {
    return bytes[e.slice.start..e.slice.end];
}

/// Full TLV bytes of an element that begins at `start` (`parse` returns only
/// the content slice; the TLV runs from the index passed to `parse` to the
/// content end).
fn tlvOf(bytes: []const u8, start: u32, e: Element) []const u8 {
    return bytes[start..e.slice.end];
}

// ── hashing ─────────────────────────────────────────────────────────────────

const HashAlgo = enum { sha1, sha256, sha384, sha512 };

fn hashAlgoFromOid(oid: []const u8) ?HashAlgo {
    if (std.mem.eql(u8, oid, &oid_sha1)) return .sha1;
    if (std.mem.eql(u8, oid, &oid_sha256)) return .sha256;
    if (std.mem.eql(u8, oid, &oid_sha384)) return .sha384;
    if (std.mem.eql(u8, oid, &oid_sha512)) return .sha512;
    return null;
}

/// Digest `data` with `algo` into `out`, returning the written prefix.
fn digest(algo: HashAlgo, data: []const u8, out: *[64]u8) []const u8 {
    switch (algo) {
        .sha1 => {
            Sha1.hash(data, out[0..Sha1.digest_length], .{});
            return out[0..Sha1.digest_length];
        },
        .sha256 => {
            Sha256.hash(data, out[0..Sha256.digest_length], .{});
            return out[0..Sha256.digest_length];
        },
        .sha384 => {
            Sha384.hash(data, out[0..Sha384.digest_length], .{});
            return out[0..Sha384.digest_length];
        },
        .sha512 => {
            Sha512.hash(data, out[0..Sha512.digest_length], .{});
            return out[0..Sha512.digest_length];
        },
    }
}

// ── certificate structure walk (local, bounded, no Certificate.parse) ───────

const PubKeyAlgo = enum { rsa, ec, other };

/// The certificate fields OCSP needs, as views over the input DER. Produced by
/// `parseCert` with the bounds-safe reader — never `std.crypto.Certificate.parse`.
const CertView = struct {
    der_bytes: []const u8, // the certificate TLV (trailing garbage trimmed)
    tbs: []const u8, // tbsCertificate TLV — the signed message
    serial: []const u8, // serialNumber INTEGER content
    issuer_name: []const u8, // issuer Name TLV (full SEQUENCE)
    subject_name: []const u8, // subject Name TLV (full SEQUENCE)
    not_before_unix: i64,
    not_after_unix: i64,
    spki: []const u8, // subjectPublicKeyInfo TLV (feed to rsa.PublicKey.fromDer)
    pub_key_bits: []const u8, // subjectPublicKey BIT STRING value (unused-bits octet stripped)
    pub_key_algo: PubKeyAlgo,
    sig_alg_oid: []const u8, // outer signatureAlgorithm OID content
    signature: []const u8, // signatureValue BIT STRING value (unused-bits octet stripped)
};

fn classifyPubKey(oid: []const u8) PubKeyAlgo {
    if (std.mem.eql(u8, oid, &oid_rsa_encryption)) return .rsa;
    if (std.mem.eql(u8, oid, &oid_ec_public_key)) return .ec;
    return .other;
}

fn parseCert(bytes: []const u8) Malformed!CertView {
    const cert = try el(bytes, 0);
    if (cert.identifier.tag != .sequence) return error.Malformed;
    const tbs_start = cert.slice.start;
    const tbs = try el(bytes, tbs_start);
    if (tbs.identifier.tag != .sequence) return error.Malformed;

    // version [0] EXPLICIT optional, then serialNumber INTEGER.
    var pos = tbs.slice.start;
    var first = try el(bytes, pos);
    if (rawTag(first) == 0xa0) {
        pos = first.slice.end;
        first = try el(bytes, pos);
    }
    const serial = first;
    if (serial.identifier.tag != .integer) return error.Malformed;

    const sig_alg_seq = try el(bytes, serial.slice.end);
    const issuer_start = sig_alg_seq.slice.end;
    const issuer = try el(bytes, issuer_start);
    if (issuer.identifier.tag != .sequence) return error.Malformed;

    const validity = try el(bytes, issuer.slice.end);
    if (validity.identifier.tag != .sequence) return error.Malformed;
    const nb_start = validity.slice.start;
    const nb = try el(bytes, nb_start);
    const na_start = nb.slice.end;
    const na = try el(bytes, na_start);
    const not_before = try parseCertTime(bytes, nb);
    const not_after = try parseCertTime(bytes, na);

    const subject_start = validity.slice.end;
    const subject = try el(bytes, subject_start);
    if (subject.identifier.tag != .sequence) return error.Malformed;

    const spki_start = subject.slice.end;
    const spki = try el(bytes, spki_start);
    if (spki.identifier.tag != .sequence) return error.Malformed;
    const alg_seq = try el(bytes, spki.slice.start);
    if (alg_seq.identifier.tag != .sequence) return error.Malformed;
    const alg_oid = try el(bytes, alg_seq.slice.start);
    if (alg_oid.identifier.tag != .object_identifier) return error.Malformed;
    const pub_algo = classifyPubKey(contentOf(bytes, alg_oid));
    const spk = try el(bytes, alg_seq.slice.end);
    if (spk.identifier.tag != .bitstring) return error.Malformed;
    const spk_content = contentOf(bytes, spk);
    if (spk_content.len < 1) return error.Malformed; // at least the unused-bits octet
    // subjectPublicKey value = BIT STRING content minus the leading unused-bits
    // octet (public keys are byte-aligned, so it is 0). This is exactly what
    // RFC 6960's issuerKeyHash digests and what SEC1 EC keys need.
    const pub_key_bits = spk_content[1..];

    // Outer signatureAlgorithm + signatureValue (siblings of tbsCertificate).
    const outer_alg = try el(bytes, tbs.slice.end);
    if (outer_alg.identifier.tag != .sequence) return error.Malformed;
    const outer_oid = try el(bytes, outer_alg.slice.start);
    if (outer_oid.identifier.tag != .object_identifier) return error.Malformed;
    const sig_val = try el(bytes, outer_alg.slice.end);
    if (sig_val.identifier.tag != .bitstring) return error.Malformed;
    const sig_content = contentOf(bytes, sig_val);
    if (sig_content.len < 1) return error.Malformed;

    return .{
        .der_bytes = bytes[0..cert.slice.end],
        .tbs = tlvOf(bytes, tbs_start, tbs),
        .serial = contentOf(bytes, serial),
        .issuer_name = tlvOf(bytes, issuer_start, issuer),
        .subject_name = tlvOf(bytes, subject_start, subject),
        .not_before_unix = not_before,
        .not_after_unix = not_after,
        .spki = tlvOf(bytes, spki_start, spki),
        .pub_key_bits = pub_key_bits,
        .pub_key_algo = pub_algo,
        .sig_alg_oid = contentOf(bytes, outer_oid),
        .signature = sig_content[1..],
    };
}

// ── time parsing (no system clock; pure text → unix seconds) ────────────────

fn digit(c: u8) Malformed!i64 {
    if (c < '0' or c > '9') return error.Malformed;
    return @as(i64, c - '0');
}

fn num(s: []const u8) Malformed!i64 {
    var acc: i64 = 0;
    for (s) |c| acc = acc * 10 + try digit(c);
    return acc;
}

/// Days since 1970-01-01 for a proleptic-Gregorian date (Howard Hinnant's
/// `days_from_civil`). Signed-int arithmetic throughout — no system calls.
fn daysFromCivil(year: i64, month: i64, day: i64) i64 {
    const y = year - @as(i64, @intFromBool(month <= 2));
    const era = @divFloor(if (y >= 0) y else y - 399, 400);
    const yoe = y - era * 400; // [0, 399]
    const mp = @mod(month + 9, 12); // Mar=0 … Feb=11
    const doy = @divFloor(153 * mp + 2, 5) + day - 1; // [0, 365]
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

fn ymdhmsToUnix(y: i64, mo: i64, d: i64, h: i64, mi: i64, s: i64) i64 {
    return daysFromCivil(y, mo, d) * 86400 + h * 3600 + mi * 60 + s;
}

/// Parse an X.509 `Validity` time element (UTCTime `YYMMDDHHMMSSZ` or
/// GeneralizedTime `YYYYMMDDHHMMSSZ`) to unix seconds. UTCTime's 2-digit year
/// uses the RFC 5280 sliding window (00–49 ⇒ 20xx, 50–99 ⇒ 19xx).
fn parseCertTime(bytes: []const u8, e: Element) Malformed!i64 {
    const s = contentOf(bytes, e);
    switch (e.identifier.tag) {
        .utc_time => {
            if (s.len < 13 or s[12] != 'Z') return error.Malformed;
            const yy = try num(s[0..2]);
            const year: i64 = if (yy < 50) 2000 + yy else 1900 + yy;
            return ymdhmsToUnix(year, try num(s[2..4]), try num(s[4..6]), try num(s[6..8]), try num(s[8..10]), try num(s[10..12]));
        },
        .generalized_time => return parseGeneralizedTime(s),
        else => return error.Malformed,
    }
}

/// Parse a bare `GeneralizedTime` content string `YYYYMMDDHHMMSSZ` to unix
/// seconds (the only form RFC 6960 uses for producedAt/thisUpdate/nextUpdate).
fn parseGeneralizedTime(s: []const u8) Malformed!i64 {
    if (s.len < 15 or s[14] != 'Z') return error.Malformed;
    return ymdhmsToUnix(try num(s[0..4]), try num(s[4..6]), try num(s[6..8]), try num(s[8..10]), try num(s[10..12]), try num(s[12..14]));
}

// ════════════════════════════════════════════════════════════════════════════
// Request building
// ════════════════════════════════════════════════════════════════════════════

pub const RequestHashAlgo = enum {
    sha1,
    sha256,

    fn oid(self: RequestHashAlgo) []const u8 {
        return switch (self) {
            .sha1 => &oid_sha1,
            .sha256 => &oid_sha256,
        };
    }
    fn hash(self: RequestHashAlgo) HashAlgo {
        return switch (self) {
            .sha1 => .sha1,
            .sha256 => .sha256,
        };
    }
};

pub const RequestOptions = struct {
    /// CertID hash algorithm. SHA-1 is the classic OCSP profile default (still
    /// what most responders key on); SHA-256 is also offered.
    hash: RequestHashAlgo = .sha1,
    /// Optional `id-pkix-ocsp-nonce` value. Keep it and pass the same bytes to
    /// `verify`'s `expected_nonce` to bind request↔response.
    nonce: ?[]const u8 = null,
};

pub const BuildRequestError = error{ Malformed, OutOfMemory };

/// Build a DER `OCSPRequest` (no optional signature) asking for the status of
/// `subject_cert_der`, whose issuer is `issuer_cert_der`. The returned bytes
/// are owned by `gpa`.
pub fn buildRequest(
    gpa: std.mem.Allocator,
    subject_cert_der: []const u8,
    issuer_cert_der: []const u8,
    opts: RequestOptions,
) BuildRequestError![]u8 {
    const subject = try parseCert(subject_cert_der);
    const issuer = try parseCert(issuer_cert_der);

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const b: Builder = .{ .a = arena.allocator() };

    var name_buf: [64]u8 = undefined;
    var key_buf: [64]u8 = undefined;
    const name_hash = digest(opts.hash.hash(), issuer.subject_name, &name_buf);
    const key_hash = digest(opts.hash.hash(), issuer.pub_key_bits, &key_buf);

    const alg_id = try b.seq(&.{ try b.oid(opts.hash.oid()), try b.null() });
    const cert_id = try b.seq(&.{
        alg_id,
        try b.octet(name_hash),
        try b.octet(key_hash),
        try b.integerRaw(subject.serial),
    });
    const request = try b.seq(&.{cert_id});
    const request_list = try b.seqOf(&.{request});

    var tbs_parts: [2][]const u8 = undefined;
    var n: usize = 0;
    tbs_parts[n] = request_list;
    n += 1;
    if (opts.nonce) |nonce| {
        // Nonce ::= OCTET STRING; extnValue wraps its DER, so the value is an
        // OCTET STRING nested inside the extnValue OCTET STRING.
        const nonce_ext = try b.seq(&.{
            try b.oid(&oid_ocsp_nonce),
            try b.octet(try b.octet(nonce)),
        });
        tbs_parts[n] = try b.explicit(2, try b.seqOf(&.{nonce_ext})); // requestExtensions [2]
        n += 1;
    }
    const tbs_request = try b.seq(tbs_parts[0..n]);
    const ocsp_request = try b.seq(&.{tbs_request});
    return gpa.dupe(u8, ocsp_request);
}

// ════════════════════════════════════════════════════════════════════════════
// Response parsing
// ════════════════════════════════════════════════════════════════════════════

pub const ResponseStatus = enum(u8) {
    successful = 0,
    malformed_request = 1,
    internal_error = 2,
    try_later = 3,
    sig_required = 5,
    unauthorized = 6,
    _,
};

/// Responder identity from the response's `ResponderID` CHOICE.
pub const Responder = union(enum) {
    /// `byName [1]` — the full `Name` SEQUENCE TLV.
    by_name: []const u8,
    /// `byKey [2]` — a `KeyHash` (SHA-1 of the responder's public key).
    by_key: []const u8,
};

/// A decoded `id-pkix-ocsp-basic` `BasicOCSPResponse`. All slices are views
/// into the buffer passed to `parseResponse`, which the caller must keep alive.
pub const Basic = struct {
    /// `tbsResponseData` TLV — exactly the bytes the responder signature covers.
    tbs_response_data: []const u8,
    responder: Responder,
    produced_at_unix: i64,
    /// `SingleResponse` SEQUENCE-OF content bytes (iterated during `verify`).
    responses: []const u8,
    /// Buffer the response slices index into (the whole `OCSPResponse` DER).
    source: []const u8,
    sig_alg_oid: []const u8,
    /// `signature` BIT STRING value (unused-bits octet stripped).
    signature: []const u8,
    /// `certs [0]` SEQUENCE-OF-Certificate content, if present (delegated
    /// responder cert chain).
    certs: ?[]const u8,
    /// Response `id-pkix-ocsp-nonce` value, if present.
    nonce: ?[]const u8,
};

pub const Response = struct {
    status: ResponseStatus,
    /// Present iff `status == .successful` and the response is `id-pkix-ocsp-basic`.
    basic: ?Basic,
};

pub const ParseError = error{Malformed};

/// Bounds-checked DER decode of an `OCSPResponse`. Never allocates, never
/// panics on malformed input, rejects trailing garbage past the outer SEQUENCE.
pub fn parseResponse(bytes: []const u8) ParseError!Response {
    const outer = try el(bytes, 0);
    if (outer.identifier.tag != .sequence) return error.Malformed;
    if (outer.slice.end != bytes.len) return error.Malformed; // no trailing garbage

    const status_elem = try el(bytes, outer.slice.start);
    if (rawTag(status_elem) != 0x0a) return error.Malformed; // ENUMERATED
    const status_bytes = contentOf(bytes, status_elem);
    if (status_bytes.len != 1) return error.Malformed;
    const status: ResponseStatus = @enumFromInt(status_bytes[0]);

    if (status != .successful) return .{ .status = status, .basic = null };

    // responseBytes [0] EXPLICIT ResponseBytes.
    if (status_elem.slice.end >= outer.slice.end) return error.Malformed;
    const rb_ctx = try el(bytes, status_elem.slice.end);
    if (rawTag(rb_ctx) != 0xa0) return error.Malformed;
    const rb = try el(bytes, rb_ctx.slice.start); // ResponseBytes SEQUENCE
    if (rb.identifier.tag != .sequence) return error.Malformed;
    const resp_type = try el(bytes, rb.slice.start);
    if (resp_type.identifier.tag != .object_identifier) return error.Malformed;
    const resp_octet = try el(bytes, resp_type.slice.end);
    if (resp_octet.identifier.tag != .octetstring) return error.Malformed;

    if (!std.mem.eql(u8, contentOf(bytes, resp_type), &oid_ocsp_basic)) {
        // Successful but a response type we do not decode (fail closed at verify).
        return .{ .status = status, .basic = null };
    }

    const basic = try parseBasic(bytes, resp_octet);
    return .{ .status = status, .basic = basic };
}

fn parseBasic(bytes: []const u8, resp_octet: Element) Malformed!Basic {
    // resp_octet content = BasicOCSPResponse SEQUENCE.
    const bor = try el(bytes, resp_octet.slice.start);
    if (bor.identifier.tag != .sequence) return error.Malformed;

    const tbs_start = bor.slice.start;
    const tbs = try el(bytes, tbs_start); // ResponseData
    if (tbs.identifier.tag != .sequence) return error.Malformed;

    const sig_alg = try el(bytes, tbs.slice.end); // signatureAlgorithm
    if (sig_alg.identifier.tag != .sequence) return error.Malformed;
    const sig_alg_oid = try el(bytes, sig_alg.slice.start);
    if (sig_alg_oid.identifier.tag != .object_identifier) return error.Malformed;

    const sig_val = try el(bytes, sig_alg.slice.end); // signature BIT STRING
    if (sig_val.identifier.tag != .bitstring) return error.Malformed;
    const sig_content = contentOf(bytes, sig_val);
    if (sig_content.len < 1) return error.Malformed;

    // certs [0] EXPLICIT SEQUENCE OF Certificate, optional.
    var certs: ?[]const u8 = null;
    if (sig_val.slice.end < bor.slice.end) {
        const certs_ctx = try el(bytes, sig_val.slice.end);
        if (rawTag(certs_ctx) == 0xa0) {
            const certs_seq = try el(bytes, certs_ctx.slice.start);
            if (certs_seq.identifier.tag != .sequence) return error.Malformed;
            certs = contentOf(bytes, certs_seq);
        }
    }

    // ── ResponseData fields ──
    var pos = tbs.slice.start;
    var e = try el(bytes, pos);
    if (rawTag(e) == 0xa0) { // version [0] EXPLICIT, skip
        pos = e.slice.end;
        e = try el(bytes, pos);
    }
    const responder: Responder = switch (rawTag(e)) {
        0xa1 => .{ .by_name = tlvOf(bytes, e.slice.start, try el(bytes, e.slice.start)) },
        0xa2 => blk: {
            const kh = try el(bytes, e.slice.start);
            if (kh.identifier.tag != .octetstring) return error.Malformed;
            break :blk .{ .by_key = contentOf(bytes, kh) };
        },
        else => return error.Malformed,
    };

    const produced = try el(bytes, e.slice.end);
    const produced_at = try parseGeneralizedTime(contentOf(bytes, produced));

    const responses_seq = try el(bytes, produced.slice.end);
    if (responses_seq.identifier.tag != .sequence) return error.Malformed;

    // responseExtensions [1] EXPLICIT, optional — scan for the nonce.
    var nonce: ?[]const u8 = null;
    if (responses_seq.slice.end < tbs.slice.end) {
        const re_ctx = try el(bytes, responses_seq.slice.end);
        if (rawTag(re_ctx) == 0xa1) {
            const re_seq = try el(bytes, re_ctx.slice.start);
            if (re_seq.identifier.tag != .sequence) return error.Malformed;
            nonce = try findNonce(bytes, re_seq);
        }
    }

    return .{
        .tbs_response_data = tlvOf(bytes, tbs_start, tbs),
        .responder = responder,
        .produced_at_unix = produced_at,
        .responses = contentOf(bytes, responses_seq),
        .source = bytes,
        .sig_alg_oid = contentOf(bytes, sig_alg_oid),
        .signature = sig_content[1..],
        .certs = certs,
        .nonce = nonce,
    };
}

/// Walk an `Extensions` SEQUENCE, returning the `id-pkix-ocsp-nonce` value
/// (the inner OCTET STRING content), or null.
fn findNonce(bytes: []const u8, exts_seq: Element) Malformed!?[]const u8 {
    var pos = exts_seq.slice.start;
    while (pos < exts_seq.slice.end) {
        const extn = try el(bytes, pos);
        if (extn.identifier.tag != .sequence) return error.Malformed;
        pos = extn.slice.end;
        const oid_elem = try el(bytes, extn.slice.start);
        if (oid_elem.identifier.tag != .object_identifier) return error.Malformed;
        var after = try el(bytes, oid_elem.slice.end);
        if (after.identifier.tag == .boolean) after = try el(bytes, after.slice.end); // skip critical
        if (after.identifier.tag != .octetstring) return error.Malformed;
        if (std.mem.eql(u8, contentOf(bytes, oid_elem), &oid_ocsp_nonce)) {
            // extnValue OCTET STRING wraps the DER of Nonce (itself an OCTET STRING).
            const inner = try el(bytes, after.slice.start);
            if (inner.identifier.tag != .octetstring) return error.Malformed;
            return contentOf(bytes, inner);
        }
    }
    return null;
}

// ════════════════════════════════════════════════════════════════════════════
// Verification — the security core
// ════════════════════════════════════════════════════════════════════════════

pub const CertStatus = union(enum) {
    good,
    revoked: struct {
        revocation_time_unix: i64,
        /// `CRLReason` code, if the response carried one (RFC 5280 §5.3.1).
        reason: ?u8,
    },
    unknown,
};

pub const Verdict = struct {
    status: CertStatus,
    responder: Responder,
    /// Whether a delegated responder cert (vs the issuing CA directly) signed.
    delegated: bool,
    this_update_unix: i64,
    next_update_unix: ?i64,
    produced_at_unix: i64,
};

pub const VerifyOptions = struct {
    /// Current time in unix seconds — supplied by the caller, NEVER read from a
    /// system clock here.
    now_unix: i64,
    /// Maximum age (seconds) accepted for a response whose `nextUpdate` is
    /// absent: reject if `now > thisUpdate + max_age_seconds`.
    max_age_seconds: i64 = 24 * 60 * 60,
    /// If set, the response MUST carry a matching nonce (RFC 6960 §4.4.1) —
    /// pass the same bytes given to `buildRequest`. Fails closed if the
    /// response omits the nonce.
    expected_nonce: ?[]const u8 = null,
};

pub const VerifyError = error{
    /// `responseStatus` was not `successful`.
    UnsuccessfulResponse,
    /// Successful response but not `id-pkix-ocsp-basic`, or structurally invalid.
    UnsupportedResponseType,
    /// The response, issuer cert, or a responder cert failed bounds-safe decode.
    Malformed,
    /// No authorized responder: neither the issuer (by name/key) nor a
    /// delegated cert that is issuer-signed.
    UntrustedResponder,
    /// The delegated responder cert lacks the id-kp-OCSPSigning EKU.
    ResponderMissingOcspSigning,
    /// The delegated responder cert is outside its validity window at `now`.
    ResponderCertExpired,
    /// The `tbsResponseData` signature did not verify under the responder key.
    SignatureInvalid,
    /// Responder signature or key algorithm is not supported.
    UnsupportedSignatureAlgorithm,
    /// The issuer/responder public key could not be loaded.
    InvalidResponderKey,
    /// No SingleResponse's CertID recomputes to the subject certificate.
    CertIdMismatch,
    /// `now > nextUpdate` (or `> thisUpdate + max_age` when nextUpdate absent).
    ResponseStale,
    /// `now < thisUpdate`.
    ResponseNotYetValid,
    /// Expected a nonce the response did not carry / did not match.
    NonceMismatch,
};

/// Verify a parsed OCSP response and return the subject certificate's status.
///
/// `issuer_cert_der` is the trusted issuer of `subject_cert_der` (both DER).
/// The order of checks is security-significant: the responder is authorized and
/// the `tbsResponseData` signature is verified BEFORE any SingleResponse
/// content is trusted; the CertID binding then confirms the response applies to
/// the subject cert; freshness and nonce are checked last.
pub fn verify(
    response: Response,
    issuer_cert_der: []const u8,
    subject_cert_der: []const u8,
    opts: VerifyOptions,
) VerifyError!Verdict {
    if (response.status != .successful) return error.UnsuccessfulResponse;
    const basic = response.basic orelse return error.UnsupportedResponseType;

    const issuer = parseCert(issuer_cert_der) catch return error.Malformed;
    const subject = parseCert(subject_cert_der) catch return error.Malformed;

    // ── 1. Resolve the authorized responder key ──
    var responder_algo: PubKeyAlgo = undefined;
    var responder_spki: []const u8 = undefined;
    var responder_bits: []const u8 = undefined;
    var delegated = false;

    if (responderMatches(basic.responder, issuer)) {
        responder_algo = issuer.pub_key_algo;
        responder_spki = issuer.spki;
        responder_bits = issuer.pub_key_bits;
    } else {
        const delegate = try resolveDelegate(basic, issuer, opts.now_unix);
        responder_algo = delegate.pub_key_algo;
        responder_spki = delegate.spki;
        responder_bits = delegate.pub_key_bits;
        delegated = true;
    }

    // ── 2. Verify the responder signature over tbsResponseData ──
    try verifySignature(
        responder_algo,
        responder_spki,
        responder_bits,
        basic.sig_alg_oid,
        basic.tbs_response_data,
        basic.signature,
    );

    // ── 3. Nonce binding (before trusting per-cert content is fine; signature
    //       already authenticated the whole tbs incl. the nonce) ──
    if (opts.expected_nonce) |want| {
        const got = basic.nonce orelse return error.NonceMismatch;
        if (!constEql(want, got)) return error.NonceMismatch;
    }

    // ── 4. Find the SingleResponse whose CertID binds to the subject cert ──
    const single = try findMatchingSingle(basic, issuer, subject.serial) orelse
        return error.CertIdMismatch;

    // ── 5. Freshness ──
    if (opts.now_unix < single.this_update_unix) return error.ResponseNotYetValid;
    if (single.next_update_unix) |nu| {
        if (opts.now_unix > nu) return error.ResponseStale;
    } else if (opts.now_unix > single.this_update_unix + opts.max_age_seconds) {
        return error.ResponseStale;
    }

    return .{
        .status = single.status,
        .responder = basic.responder,
        .delegated = delegated,
        .this_update_unix = single.this_update_unix,
        .next_update_unix = single.next_update_unix,
        .produced_at_unix = basic.produced_at_unix,
    };
}

/// Constant-time equality for the nonce comparison (defense against a timing
/// oracle on the nonce, cheap and harmless elsewhere).
fn constEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| diff |= x ^ y;
    return diff == 0;
}

/// Does the ResponderID name/key-hash the issuing CA itself?
fn responderMatches(responder: Responder, issuer: CertView) bool {
    switch (responder) {
        .by_name => |name| return std.mem.eql(u8, name, issuer.subject_name),
        .by_key => |kh| {
            var buf: [64]u8 = undefined;
            const h = digest(.sha1, issuer.pub_key_bits, &buf);
            return std.mem.eql(u8, kh, h);
        },
    }
}

/// Locate + authorize a delegated responder cert from `basic.certs`: it must
/// match the ResponderID, be directly signed by the issuer, carry the
/// id-kp-OCSPSigning EKU, and be valid at `now` (RFC 6960 §4.2.2.2).
fn resolveDelegate(basic: Basic, issuer: CertView, now_unix: i64) VerifyError!CertView {
    const certs = basic.certs orelse return error.UntrustedResponder;
    const bytes = basic.source;
    var pos: u32 = @intCast(@intFromPtr(certs.ptr) - @intFromPtr(bytes.ptr));
    const end: u32 = pos + @as(u32, @intCast(certs.len));

    while (pos < end) {
        const cert_elem = el(bytes, pos) catch return error.Malformed;
        if (cert_elem.identifier.tag != .sequence) return error.Malformed;
        const cert_der = bytes[pos..cert_elem.slice.end];
        pos = cert_elem.slice.end;

        const cand = parseCert(cert_der) catch return error.Malformed;
        if (!candidateMatchesResponder(cand, basic.responder)) continue;

        // Directly signed by the issuer (the only chaining RFC 6960 requires).
        verifySignature(
            issuer.pub_key_algo,
            issuer.spki,
            issuer.pub_key_bits,
            cand.sig_alg_oid,
            cand.tbs,
            cand.signature,
        ) catch |e| switch (e) {
            error.SignatureInvalid => return error.UntrustedResponder,
            else => return e,
        };

        // id-kp-OCSPSigning EKU (reuse x509's extension machinery).
        if (!try hasOcspSigningEku(cert_der)) return error.ResponderMissingOcspSigning;

        // Validity window.
        if (now_unix < cand.not_before_unix or now_unix > cand.not_after_unix)
            return error.ResponderCertExpired;

        return cand;
    }
    return error.UntrustedResponder;
}

fn candidateMatchesResponder(cand: CertView, responder: Responder) bool {
    switch (responder) {
        .by_name => |name| return std.mem.eql(u8, name, cand.subject_name),
        .by_key => |kh| {
            var buf: [64]u8 = undefined;
            const h = digest(.sha1, cand.pub_key_bits, &buf);
            return std.mem.eql(u8, kh, h);
        },
    }
}

/// Does `cert_der` carry extKeyUsage with id-kp-OCSPSigning (or anyEKU)?
/// Uses x509's bounds-safe extension walk + `Purpose` map — no local EKU parser.
fn hasOcspSigningEku(cert_der: []const u8) VerifyError!bool {
    const cert: std.crypto.Certificate = .{ .buffer = cert_der, .index = 0 };
    const slice = (ext.findExtensions(cert) catch return error.Malformed) orelse return false;
    var it = ext.iterate(slice, cert);
    while (it.next() catch return error.Malformed) |entry| {
        if (entry.id == .ext_key_usage) {
            return ext.hasPurpose(entry.value, .ocsp_signing) catch return error.Malformed;
        }
    }
    return false;
}

const SingleResult = struct {
    status: CertStatus,
    this_update_unix: i64,
    next_update_unix: ?i64,
};

/// Iterate SingleResponses, returning the first whose CertID recomputes to the
/// subject cert. Recomputes issuerNameHash/issuerKeyHash with the algorithm
/// named in each CertID, so a SHA-1 or SHA-256 CertID both bind correctly.
fn findMatchingSingle(basic: Basic, issuer: CertView, subject_serial: []const u8) VerifyError!?SingleResult {
    const bytes = basic.source;
    var pos: u32 = @intCast(@intFromPtr(basic.responses.ptr) - @intFromPtr(bytes.ptr));
    const end: u32 = pos + @as(u32, @intCast(basic.responses.len));

    while (pos < end) {
        const single = el(bytes, pos) catch return error.Malformed;
        if (single.identifier.tag != .sequence) return error.Malformed;
        pos = single.slice.end;

        const cert_id = el(bytes, single.slice.start) catch return error.Malformed;
        if (cert_id.identifier.tag != .sequence) return error.Malformed;

        if (!(certIdBinds(bytes, cert_id, issuer, subject_serial) catch return error.Malformed))
            continue;

        return try parseSingleTail(bytes, single, cert_id);
    }
    return null;
}

/// CertID = SEQUENCE { hashAlgorithm, issuerNameHash, issuerKeyHash, serial }.
/// Recompute the two hashes over the issuer cert and compare all three fields.
fn certIdBinds(bytes: []const u8, cert_id: Element, issuer: CertView, subject_serial: []const u8) Malformed!bool {
    const alg_seq = try el(bytes, cert_id.slice.start);
    if (alg_seq.identifier.tag != .sequence) return error.Malformed;
    const alg_oid = try el(bytes, alg_seq.slice.start);
    if (alg_oid.identifier.tag != .object_identifier) return error.Malformed;
    const algo = hashAlgoFromOid(contentOf(bytes, alg_oid)) orelse return false;

    const name_hash = try el(bytes, alg_seq.slice.end);
    if (name_hash.identifier.tag != .octetstring) return error.Malformed;
    const key_hash = try el(bytes, name_hash.slice.end);
    if (key_hash.identifier.tag != .octetstring) return error.Malformed;
    const serial = try el(bytes, key_hash.slice.end);
    if (serial.identifier.tag != .integer) return error.Malformed;

    var nb: [64]u8 = undefined;
    var kb: [64]u8 = undefined;
    const want_name = digest(algo, issuer.subject_name, &nb);
    const want_key = digest(algo, issuer.pub_key_bits, &kb);

    return std.mem.eql(u8, contentOf(bytes, name_hash), want_name) and
        std.mem.eql(u8, contentOf(bytes, key_hash), want_key) and
        std.mem.eql(u8, contentOf(bytes, serial), subject_serial);
}

/// Parse certStatus + thisUpdate + optional nextUpdate of a SingleResponse
/// (its certID has already been read as `cert_id`).
fn parseSingleTail(bytes: []const u8, single: Element, cert_id: Element) VerifyError!SingleResult {
    const status_elem = el(bytes, cert_id.slice.end) catch return error.Malformed;
    const status: CertStatus = switch (rawTag(status_elem)) {
        0x80 => .good, // good [0] IMPLICIT NULL
        0xa1 => try parseRevoked(bytes, status_elem), // revoked [1] IMPLICIT RevokedInfo
        0x82 => .unknown, // unknown [2] IMPLICIT UnknownInfo
        else => return error.Malformed,
    };

    const this_update = el(bytes, status_elem.slice.end) catch return error.Malformed;
    const this_update_unix = parseGeneralizedTime(contentOf(bytes, this_update)) catch return error.Malformed;

    var next_update_unix: ?i64 = null;
    if (this_update.slice.end < single.slice.end) {
        const nxt = el(bytes, this_update.slice.end) catch return error.Malformed;
        if (rawTag(nxt) == 0xa0) { // nextUpdate [0] EXPLICIT GeneralizedTime
            const gt = el(bytes, nxt.slice.start) catch return error.Malformed;
            next_update_unix = parseGeneralizedTime(contentOf(bytes, gt)) catch return error.Malformed;
        }
    }

    return .{
        .status = status,
        .this_update_unix = this_update_unix,
        .next_update_unix = next_update_unix,
    };
}

fn parseRevoked(bytes: []const u8, revoked: Element) VerifyError!CertStatus {
    // RevokedInfo ::= SEQUENCE { revocationTime GeneralizedTime,
    //                            revocationReason [0] EXPLICIT CRLReason OPTIONAL }
    const rt = el(bytes, revoked.slice.start) catch return error.Malformed;
    const rt_unix = parseGeneralizedTime(contentOf(bytes, rt)) catch return error.Malformed;
    var reason: ?u8 = null;
    if (rt.slice.end < revoked.slice.end) {
        const rc_ctx = el(bytes, rt.slice.end) catch return error.Malformed;
        if (rawTag(rc_ctx) == 0xa0) {
            const rc = el(bytes, rc_ctx.slice.start) catch return error.Malformed;
            const rc_bytes = contentOf(bytes, rc);
            if (rc_bytes.len == 1) reason = rc_bytes[0];
        }
    }
    return .{ .revoked = .{ .revocation_time_unix = rt_unix, .reason = reason } };
}

// ── responder signature verification ────────────────────────────────────────

const SigScheme = enum { rsa_sha1, rsa_sha256, rsa_sha384, rsa_sha512, ecdsa_sha256 };

fn sigSchemeFromOid(oid: []const u8) ?SigScheme {
    if (std.mem.eql(u8, oid, &oid_sha256_rsa)) return .rsa_sha256;
    if (std.mem.eql(u8, oid, &oid_sha384_rsa)) return .rsa_sha384;
    if (std.mem.eql(u8, oid, &oid_sha512_rsa)) return .rsa_sha512;
    if (std.mem.eql(u8, oid, &oid_sha1_rsa)) return .rsa_sha1;
    if (std.mem.eql(u8, oid, &oid_ecdsa_sha256)) return .ecdsa_sha256;
    return null;
}

/// Verify `signature` over `msg` under the responder key (`spki` for RSA,
/// SEC1 `key_bits` for ECDSA), dispatching on the signatureAlgorithm OID.
fn verifySignature(
    algo: PubKeyAlgo,
    spki: []const u8,
    key_bits: []const u8,
    sig_alg_oid: []const u8,
    msg: []const u8,
    signature: []const u8,
) VerifyError!void {
    const scheme = sigSchemeFromOid(sig_alg_oid) orelse return error.UnsupportedSignatureAlgorithm;
    switch (scheme) {
        .rsa_sha1, .rsa_sha256, .rsa_sha384, .rsa_sha512 => {
            if (algo != .rsa) return error.UnsupportedSignatureAlgorithm;
            const pk = rsa.PublicKey.fromDer(spki) catch return error.InvalidResponderKey;
            const ok = switch (scheme) {
                .rsa_sha1 => rsa.verifyPkcs1v15(pk, Sha1, msg, signature),
                .rsa_sha256 => rsa.verifyPkcs1v15(pk, Sha256, msg, signature),
                .rsa_sha384 => rsa.verifyPkcs1v15(pk, Sha384, msg, signature),
                .rsa_sha512 => rsa.verifyPkcs1v15(pk, Sha512, msg, signature),
                else => unreachable,
            };
            ok catch return error.SignatureInvalid;
        },
        .ecdsa_sha256 => {
            if (algo != .ec) return error.UnsupportedSignatureAlgorithm;
            const rs = ecdsaDerToRs(signature) orelse return error.SignatureInvalid;
            if (!p256.sign.ecdsaVerify(key_bits, msg, rs)) return error.SignatureInvalid;
        },
    }
}

/// Decode a DER `Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` into a
/// fixed 64-byte `r || s` big-endian buffer. Any malformed shape yields null
/// (⇒ signature invalid).
///
/// This used to be a local parser. It was replaced by `p256.sign.derToRaw`
/// because the local one accepted encodings DER forbids — most concretely a
/// SEQUENCE whose declared length runs past `s` (Wycheproof tcId 23), since it
/// checked that the SEQUENCE ended at the buffer end but never that `s` ended
/// at the SEQUENCE end. It also stripped every leading zero of an INTEGER
/// rather than exactly the sign octet, and read a negative INTEGER as a
/// positive magnitude. Each of those turns one signature into many accepted
/// encodings. The replacement is anchored on 484 Wycheproof vectors.
fn ecdsaDerToRs(sig: []const u8) ?[64]u8 {
    return p256.sign.derToRaw(sig);
}

test "ECDSA DER: encodings that DER forbids are rejected (Wycheproof rows)" {
    // Regression pins for the shapes the previous local parser let through.
    // All four carry the SAME otherwise-valid r and s as Wycheproof's tcId 1,
    // so nothing here is rejected for being a bad signature — only for being a
    // bad encoding.
    const cases = [_]struct { tc: u32, why: []const u8, hex: []const u8 }{
        .{
            .tc = 23,
            .why = "SEQUENCE length covers two extra 0x00 bytes after s",
            .hex = "304702202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18" ++
                "022100b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db0000",
        },
        .{
            .tc = 25,
            .why = "0x00 bytes appended after the SEQUENCE",
            .hex = "304502202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18" ++
                "022100b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db0000",
        },
        .{
            .tc = 9,
            .why = "non-minimal long-form length on the SEQUENCE",
            .hex = "3082004502202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18" ++
                "022100b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
        },
        .{
            .tc = 6,
            .why = "s omits the 0x00 sign octet, so it decodes as negative",
            .hex = "304402202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18" ++
                "0220b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
        },
    };
    for (cases) |c| {
        var buf: [128]u8 = undefined;
        const sig_der = std.fmt.hexToBytes(&buf, c.hex) catch unreachable;
        if (ecdsaDerToRs(sig_der) != null) {
            std.debug.print("accepted malformed DER (Wycheproof tcId {d}): {s}\n", .{ c.tc, c.why });
            return error.MalformedDerAccepted;
        }
    }

    // Positive control: the well-formed encoding of the same signature decodes.
    var ok_buf: [128]u8 = undefined;
    const ok_der = std.fmt.hexToBytes(&ok_buf, "304502202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18" ++
        "022100b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db") catch unreachable;
    try std.testing.expect(ecdsaDerToRs(ok_der) != null);
}

test {
    _ = @import("ocsp_test.zig");
    _ = @import("goldens.zig");
}
