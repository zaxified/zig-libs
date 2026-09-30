// SPDX-License-Identifier: MIT
//! Certificate revocation lists (RFC 5280 §5, §6.3): a bounded parse of a DER
//! `CertificateList` and `checkRevocation`, which answers "is this certificate
//! revoked?" for one CRL, one certificate and the CRL issuer's certificate.
//!
//! Fetching is the caller's (as for OCSP in the sibling `ocsp` module): this
//! file does no I/O and reads no clock.
//!
//! **What `checkRevocation` establishes before it answers** (RFC 5280 §6.3.3):
//! the CRL is well-formed and its inner and outer signature algorithms agree
//! (§5.1.1.2); its issuer is the certificate's issuer and the issuer
//! certificate's subject, and that certificate's key signed it (any algorithm
//! `chain.verifySignedBy` verifies — RSA, RSASSA-PSS, ECDSA, Ed25519, ML-DSA,
//! SLH-DSA); the issuer certificate may sign CRLs (`keyUsage.cRLSign` when
//! `keyUsage` is present, §4.2.1.3) and its subjectKeyIdentifier matches the
//! CRL's authorityKeyIdentifier when both are present; `thisUpdate <= now <
//! nextUpdate`; and the certificate lies in the CRL's scope (§5.2.5 issuing
//! distribution point). Only then is the serial looked up.
//!
//! **Fails closed, not open, on what it does not implement:** delta CRLs
//! (`DeltaCrlUnsupported`), indirect CRLs and the `certificateIssuer` entry
//! extension (`IndirectCrlUnsupported`), CRLs covering only some reasons or
//! attribute certificates, and distribution points named relative to the
//! issuer (`CrlScopeUnsupported`), and any unrecognized critical CRL or entry
//! extension (`UnsupportedCriticalExtension`). Each of these is a CRL that
//! cannot prove "not revoked" to this module, so none of them yields `.good`.

const std = @import("std");
const Certificate = std.crypto.Certificate;
const der = Certificate.der;
const extensions = @import("extensions.zig");
const chain = @import("chain.zig");

/// RFC 5280 §5.3.1 CRLReason. Value 7 is unassigned.
pub const Reason = enum(u8) {
    unspecified = 0,
    key_compromise = 1,
    ca_compromise = 2,
    affiliation_changed = 3,
    superseded = 4,
    cessation_of_operation = 5,
    certificate_hold = 6,
    remove_from_crl = 8,
    privilege_withdrawn = 9,
    aa_compromise = 10,
};

pub const Status = union(enum) {
    /// Not on the CRL, and the CRL is valid, current and in scope for it.
    good,
    revoked: Revoked,
};

pub const Revoked = struct {
    /// `revocationDate`, Unix seconds.
    revocation_time: i64,
    /// `reasonCode` entry extension; null when absent (RFC 5280: treat as
    /// `unspecified`). `certificate_hold` is reported as revoked too — the
    /// hold is in force while the entry is listed.
    reason: ?Reason,
    /// `invalidityDate` entry extension, Unix seconds.
    invalidity_time: ?i64,
};

pub const ParseError = error{
    /// Structure, tag, length or time encoding is not a CRL.
    CrlMalformed,
    /// `version` present and not v2, or extensions present in a v1 CRL.
    CrlUnsupportedVersion,
    /// `tbsCertList.signature` differs from the outer `signatureAlgorithm`.
    CrlSignatureAlgorithmMismatch,
    /// An extension marked critical that this module does not process.
    UnsupportedCriticalExtension,
    /// The CRL is larger than a u32 offset can address.
    CrlTooLarge,
    /// `indirectCRL` in the IDP, or a `certificateIssuer` entry extension.
    IndirectCrlUnsupported,
};

pub const CheckError = ParseError || chain.VerifyChainError || error{
    /// The certificate's issuer name is not the CRL's issuer name.
    CrlIssuerMismatch,
    /// The CRL issuer certificate has `keyUsage` without `cRLSign`.
    KeyUsageForbidsCrlSigning,
    /// The CRL's authorityKeyIdentifier and the issuer certificate's
    /// subjectKeyIdentifier are both present and differ.
    CrlKeyIdentifierMismatch,
    /// `now < thisUpdate`.
    CrlNotYetValid,
    /// `now >= nextUpdate`, or no nextUpdate and `thisUpdate + max_age <= now`.
    CrlExpired,
    /// No nextUpdate and no `Options.max_age_sec` to bound it.
    CrlMissingNextUpdate,
    /// A delta CRL (§5.2.4); only complete CRLs are processed.
    DeltaCrlUnsupported,
    /// IDP `onlySomeReasons`, `onlyContainsAttributeCerts`, or a
    /// distribution point named relative to the CRL issuer.
    CrlScopeUnsupported,
    /// The certificate lies outside the CRL's scope: its distribution points
    /// do not name this CRL's, or it is a CA on a user-only CRL, or the reverse.
    CrlScopeMismatch,
};

pub const Options = struct {
    /// Unix seconds. Caller-supplied; this module reads no clock.
    now_sec: i64,
    /// Accept a CRL without nextUpdate for this long after thisUpdate.
    /// Null: such a CRL is `CrlMissingNextUpdate` (RFC 5280 §5.1.2.5 makes
    /// nextUpdate mandatory for conforming issuers).
    max_age_sec: ?i64 = null,
};

/// Views into a parsed CRL's buffer.
pub const Crl = struct {
    der_bytes: []const u8,
    signed: chain.SignedData,
    /// Issuer `Name`, RDNSequence content.
    issuer: []const u8,
    this_update: i64,
    next_update: ?i64,
    /// `cRLNumber` INTEGER content.
    crl_number: ?[]const u8 = null,
    authority_key_id: ?[]const u8 = null,
    /// `issuingDistributionPoint` extnValue.
    idp: ?[]const u8 = null,
    delta: bool = false,
    /// The `revokedCertificates` SEQUENCE OF content, validated entry by entry.
    entries: der.Element.Slice = der.Element.Slice.empty,
    entry_count: u32 = 0,

    /// The entry for `serial` (INTEGER content bytes), or null.
    pub fn find(c: *const Crl, serial: []const u8) ?Entry {
        var it = c.iterator();
        const want = trimInteger(serial);
        while (it.next()) |e| {
            if (std.mem.eql(u8, trimInteger(e.serial), want)) return e;
        }
        return null;
    }

    pub fn iterator(c: *const Crl) EntryIterator {
        return .{ .bytes = c.der_bytes, .pos = c.entries.start, .end = c.entries.end };
    }
};

pub const Entry = struct {
    /// `userCertificate` INTEGER content.
    serial: []const u8,
    revocation_time: i64,
    reason: ?Reason,
    invalidity_time: ?i64,
};

/// Walks entries `parse` has already validated; cannot fail.
pub const EntryIterator = struct {
    bytes: []const u8,
    pos: u32,
    end: u32,

    pub fn next(it: *EntryIterator) ?Entry {
        if (it.pos >= it.end) return null;
        const e = parseEntry(it.bytes, it.pos) catch unreachable; // validated by `parse`
        it.pos = e.next;
        return e.entry;
    }
};

// ── OIDs ────────────────────────────────────────────────────────────────────

const oid_crl_number = [_]u8{ 0x55, 0x1d, 0x14 }; // 2.5.29.20
const oid_reason_code = [_]u8{ 0x55, 0x1d, 0x15 }; // 2.5.29.21
const oid_invalidity_date = [_]u8{ 0x55, 0x1d, 0x18 }; // 2.5.29.24
const oid_delta_indicator = [_]u8{ 0x55, 0x1d, 0x1b }; // 2.5.29.27
const oid_idp = [_]u8{ 0x55, 0x1d, 0x1c }; // 2.5.29.28
const oid_certificate_issuer = [_]u8{ 0x55, 0x1d, 0x1d }; // 2.5.29.29
const oid_aki = [_]u8{ 0x55, 0x1d, 0x23 }; // 2.5.29.35
const oid_freshest_crl = [_]u8{ 0x55, 0x1d, 0x2e }; // 2.5.29.46
const oid_aia = [_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01 }; // 1.3.6.1.5.5.7.1.1

// ── parse ───────────────────────────────────────────────────────────────────

fn el(bytes: []const u8, index: u32) ParseError!der.Element {
    if (index >= bytes.len) return error.CrlMalformed;
    return extensions.parseElement(bytes, index) catch error.CrlMalformed;
}

fn wantTag(e: der.Element, tag: der.Tag) ParseError!void {
    if (e.identifier.class != .universal or e.identifier.tag != tag) return error.CrlMalformed;
}

fn rawTag(e: der.Element) u8 {
    return @bitCast(e.identifier);
}

fn content(bytes: []const u8, e: der.Element) []const u8 {
    return bytes[e.slice.start..e.slice.end];
}

/// The full TLV of `e`, starting at `start` (where its header begins).
fn tlv(bytes: []const u8, start: u32, e: der.Element) []const u8 {
    return bytes[start..e.slice.end];
}

fn parseTime(bytes: []const u8, e: der.Element) ParseError!i64 {
    if (e.identifier.tag != .utc_time and e.identifier.tag != .generalized_time) return error.CrlMalformed;
    const t = Certificate.parseTime(.{ .buffer = bytes, .index = 0 }, e) catch return error.CrlMalformed;
    return std.math.cast(i64, t) orelse error.CrlMalformed;
}

/// Parse and structurally validate a DER CRL. Every entry and extension is
/// walked once here, so an unrecognized critical extension anywhere is an
/// error now, not on lookup. Does not verify the signature (see
/// `checkRevocation`).
pub fn parse(crl_der: []const u8) ParseError!Crl {
    if (crl_der.len > std.math.maxInt(u32)) return error.CrlTooLarge;
    const bytes = crl_der;
    const outer = try el(bytes, 0);
    try wantTag(outer, .sequence);
    if (outer.slice.end != bytes.len) return error.CrlMalformed; // trailing bytes

    const tbs_start = outer.slice.start;
    const tbs = try el(bytes, tbs_start);
    try wantTag(tbs, .sequence);
    const alg_start = tbs.slice.end;
    const alg = try el(bytes, alg_start);
    try wantTag(alg, .sequence);
    const sig = try el(bytes, alg.slice.end);
    try wantTag(sig, .bitstring);
    if (sig.slice.end != outer.slice.end) return error.CrlMalformed;
    if (sig.slice.start >= sig.slice.end or bytes[sig.slice.start] != 0) return error.CrlMalformed;
    const alg_oid = try el(bytes, alg.slice.start);
    try wantTag(alg_oid, .object_identifier);
    const alg_params: ?[]const u8 = if (alg_oid.slice.end < alg.slice.end) blk: {
        const p = try el(bytes, alg_oid.slice.end);
        if (p.slice.end != alg.slice.end) return error.CrlMalformed;
        break :blk bytes[alg_oid.slice.end..p.slice.end];
    } else null;

    // tbsCertList
    var pos = tbs.slice.start;
    var first = try el(bytes, pos);
    var v2 = false;
    if (first.identifier.tag == .integer and first.identifier.class == .universal) {
        const v = content(bytes, first);
        if (v.len != 1 or v[0] != 1) return error.CrlUnsupportedVersion;
        v2 = true;
        pos = first.slice.end;
        first = try el(bytes, pos);
    }
    // signature AlgorithmIdentifier, byte-equal to the outer one.
    try wantTag(first, .sequence);
    if (!std.mem.eql(u8, tlv(bytes, pos, first), tlv(bytes, alg_start, alg)))
        return error.CrlSignatureAlgorithmMismatch;
    pos = first.slice.end;

    const issuer = try el(bytes, pos);
    try wantTag(issuer, .sequence);
    pos = issuer.slice.end;

    const this_elem = try el(bytes, pos);
    const this_update = try parseTime(bytes, this_elem);
    pos = this_elem.slice.end;

    var crl: Crl = .{
        .der_bytes = bytes,
        .signed = .{
            .buffer = bytes,
            .message_slice = .{ .start = tbs_start, .end = tbs.slice.end },
            .signature_slice = .{ .start = sig.slice.start + 1, .end = sig.slice.end },
            .sig_alg_oid = content(bytes, alg_oid),
            .sig_alg_params = alg_params,
            .issuer_slice = issuer.slice,
        },
        .issuer = content(bytes, issuer),
        .this_update = this_update,
        .next_update = null,
    };

    if (pos < tbs.slice.end) {
        const e = try el(bytes, pos);
        if (e.identifier.tag == .utc_time or e.identifier.tag == .generalized_time) {
            crl.next_update = try parseTime(bytes, e);
            pos = e.slice.end;
        }
    }
    if (pos < tbs.slice.end) {
        const e = try el(bytes, pos);
        if (e.identifier.class == .universal and e.identifier.tag == .sequence) {
            crl.entries = e.slice;
            var p = e.slice.start;
            while (p < e.slice.end) {
                const r = try parseEntry(bytes, p);
                if (r.next > e.slice.end) return error.CrlMalformed;
                if (r.has_extensions and !v2) return error.CrlUnsupportedVersion;
                p = r.next;
                crl.entry_count += 1;
            }
            pos = e.slice.end;
        }
    }
    if (pos < tbs.slice.end) {
        const e = try el(bytes, pos);
        if (rawTag(e) != 0xa0) return error.CrlMalformed; // [0] EXPLICIT Extensions
        if (!v2) return error.CrlUnsupportedVersion;
        const exts = try el(bytes, e.slice.start);
        try wantTag(exts, .sequence);
        if (exts.slice.end != e.slice.end) return error.CrlMalformed;
        try parseCrlExtensions(bytes, exts.slice, &crl);
        pos = e.slice.end;
    }
    if (pos != tbs.slice.end) return error.CrlMalformed;
    return crl;
}

fn parseCrlExtensions(bytes: []const u8, slice: der.Element.Slice, crl: *Crl) ParseError!void {
    var it = extensions.iterate(slice, .{ .buffer = bytes, .index = 0 });
    while (it.next() catch return error.CrlMalformed) |x| {
        if (std.mem.eql(u8, x.oid, &oid_crl_number)) {
            const n = try el(x.value, 0);
            try wantTag(n, .integer);
            crl.crl_number = content(x.value, n);
        } else if (std.mem.eql(u8, x.oid, &oid_aki)) {
            crl.authority_key_id = (extensions.parseAuthorityKeyIdentifier(x.value) catch return error.CrlMalformed).key_identifier;
        } else if (std.mem.eql(u8, x.oid, &oid_idp)) {
            crl.idp = x.value;
            _ = try parseIdp(x.value); // structure checked now
        } else if (std.mem.eql(u8, x.oid, &oid_delta_indicator)) {
            crl.delta = true;
        } else if (std.mem.eql(u8, x.oid, &oid_freshest_crl) or std.mem.eql(u8, x.oid, &oid_aia)) {
            // Informational pointers; nothing to enforce.
        } else if (x.critical) {
            return error.UnsupportedCriticalExtension;
        }
    }
}

const ParsedEntry = struct { entry: Entry, next: u32, has_extensions: bool };

fn parseEntry(bytes: []const u8, pos: u32) ParseError!ParsedEntry {
    const seq = try el(bytes, pos);
    try wantTag(seq, .sequence);
    const serial = try el(bytes, seq.slice.start);
    try wantTag(serial, .integer);
    if (serial.slice.start == serial.slice.end) return error.CrlMalformed;
    const date = try el(bytes, serial.slice.end);
    var entry: Entry = .{
        .serial = content(bytes, serial),
        .revocation_time = try parseTime(bytes, date),
        .reason = null,
        .invalidity_time = null,
    };
    var has_extensions = false;
    if (date.slice.end < seq.slice.end) {
        const exts = try el(bytes, date.slice.end);
        try wantTag(exts, .sequence);
        if (exts.slice.end != seq.slice.end) return error.CrlMalformed;
        has_extensions = true;
        var it = extensions.iterate(exts.slice, .{ .buffer = bytes, .index = 0 });
        while (it.next() catch return error.CrlMalformed) |x| {
            if (std.mem.eql(u8, x.oid, &oid_reason_code)) {
                const r = try el(x.value, 0);
                if (rawTag(r) != 0x0a) return error.CrlMalformed; // ENUMERATED (std.der has no tag name for it)
                const v = content(x.value, r);
                if (v.len != 1) return error.CrlMalformed;
                entry.reason = std.enums.fromInt(Reason, v[0]) orelse return error.CrlMalformed;
            } else if (std.mem.eql(u8, x.oid, &oid_invalidity_date)) {
                const t = try el(x.value, 0);
                if (t.identifier.tag != .generalized_time) return error.CrlMalformed;
                entry.invalidity_time = try parseTime(x.value, t);
            } else if (std.mem.eql(u8, x.oid, &oid_certificate_issuer)) {
                // Only meaningful on an indirect CRL (RFC 5280 makes it
                // critical); refused whether or not it is marked so.
                return error.IndirectCrlUnsupported;
            } else if (x.critical) {
                return error.UnsupportedCriticalExtension;
            }
        }
    } else if (date.slice.end != seq.slice.end) return error.CrlMalformed;
    return .{ .entry = entry, .next = seq.slice.end, .has_extensions = has_extensions };
}

// ── issuing distribution point (RFC 5280 §5.2.5) ────────────────────────────

const Idp = struct {
    /// `fullName` GeneralNames content, when the distribution point is named.
    full_name: ?[]const u8 = null,
    relative_name: bool = false,
    only_user: bool = false,
    only_ca: bool = false,
    only_some_reasons: bool = false,
    indirect: bool = false,
    only_attribute: bool = false,
};

fn idpBool(value: []const u8, e: der.Element) ParseError!bool {
    const v = content(value, e);
    if (v.len != 1) return error.CrlMalformed;
    return v[0] != 0;
}

fn parseIdp(value: []const u8) ParseError!Idp {
    const seq = try el(value, 0);
    try wantTag(seq, .sequence);
    if (seq.slice.end != value.len) return error.CrlMalformed;
    var idp: Idp = .{};
    var p = seq.slice.start;
    while (p < seq.slice.end) {
        const f = try el(value, p);
        switch (rawTag(f)) {
            0xa0 => { // distributionPoint [0] DistributionPointName
                const name = try el(value, f.slice.start);
                switch (rawTag(name)) {
                    0xa0 => idp.full_name = content(value, name),
                    0xa1 => idp.relative_name = true,
                    else => return error.CrlMalformed,
                }
            },
            0x81 => idp.only_user = try idpBool(value, f),
            0x82 => idp.only_ca = try idpBool(value, f),
            0x83 => idp.only_some_reasons = true,
            0x84 => idp.indirect = try idpBool(value, f),
            0x85 => idp.only_attribute = try idpBool(value, f),
            else => return error.CrlMalformed,
        }
        p = f.slice.end;
    }
    return idp;
}

/// Does any GeneralName in `a` equal (byte for byte, tag included) any in `b`?
/// Both are GeneralNames content.
fn namesIntersect(a: []const u8, b: []const u8) ParseError!bool {
    var i: u32 = 0;
    while (i < a.len) {
        const x = try el(a, i);
        const xs = a[i..x.slice.end];
        var j: u32 = 0;
        while (j < b.len) {
            const y = try el(b, j);
            if (std.mem.eql(u8, xs, b[j..y.slice.end])) return true;
            j = y.slice.end;
        }
        i = x.slice.end;
    }
    return false;
}

/// RFC 5280 §6.3.3 (b)(2): is `cert_der` in the scope of a CRL carrying `idp`?
fn checkScope(idp_value: []const u8, cert_der: []const u8) CheckError!void {
    const idp = try parseIdp(idp_value);
    if (idp.indirect) return error.IndirectCrlUnsupported;
    if (idp.only_some_reasons or idp.only_attribute or idp.relative_name) return error.CrlScopeUnsupported;
    if (idp.only_user or idp.only_ca) {
        const is_ca = try chain.certIsCa(cert_der);
        if (idp.only_user and is_ca) return error.CrlScopeMismatch;
        if (idp.only_ca and !is_ca) return error.CrlScopeMismatch;
    }
    const idp_names = idp.full_name orelse return; // not partitioned by name
    // The certificate must name this CRL among its own distribution points.
    const dps = (try chain.certExtensionValue(cert_der, .crl_distribution_points)) orelse
        return error.CrlScopeMismatch;
    const seq = try el(dps, 0);
    try wantTag(seq, .sequence);
    var p = seq.slice.start;
    while (p < seq.slice.end) {
        const dp = try el(dps, p);
        try wantTag(dp, .sequence);
        var q = dp.slice.start;
        while (q < dp.slice.end) {
            const f = try el(dps, q);
            if (rawTag(f) == 0xa0) { // distributionPoint
                const name = try el(dps, f.slice.start);
                if (rawTag(name) == 0xa0 and try namesIntersect(content(dps, name), idp_names)) return;
            }
            // A cRLIssuer [2] naming another issuer is the indirect case,
            // refused above; reasons [1] cannot widen the scope.
            q = f.slice.end;
        }
        p = dp.slice.end;
    }
    return error.CrlScopeMismatch;
}

// ── the check ───────────────────────────────────────────────────────────────

/// The revocation status of `cert_der` according to `crl_der`, issued and
/// signed by `issuer_der` (the certificate that issued `cert_der`; RFC 5280
/// allows a separate CRL signer only for indirect CRLs, which are refused).
/// See the file doc for everything checked before the answer.
pub fn checkRevocation(crl_der: []const u8, cert_der: []const u8, issuer_der: []const u8, opts: Options) CheckError!Status {
    const crl = try parse(crl_der);
    if (crl.delta) return error.DeltaCrlUnsupported;

    const cert_id = try chain.certSerialAndIssuer(cert_der);
    if (!std.mem.eql(u8, cert_id.issuer, crl.issuer)) return error.CrlIssuerMismatch;

    if (try chain.certExtensionValue(issuer_der, .key_usage)) |v| {
        const ku = try extensions.parseKeyUsage(v);
        if (!ku.crl_sign) return error.KeyUsageForbidsCrlSigning;
    }
    if (crl.authority_key_id) |aki| {
        if (try chain.certExtensionValue(issuer_der, .subject_key_identifier)) |v| {
            const ski = try extensions.parseSubjectKeyIdentifier(v);
            if (!std.mem.eql(u8, aki, ski)) return error.CrlKeyIdentifierMismatch;
        }
    }
    // Signature, and CRL issuer name == issuer certificate subject.
    try chain.verifySignedBy(crl.signed, issuer_der);

    if (opts.now_sec < crl.this_update) return error.CrlNotYetValid;
    if (crl.next_update) |nu| {
        if (opts.now_sec >= nu) return error.CrlExpired;
    } else {
        const max_age = opts.max_age_sec orelse return error.CrlMissingNextUpdate;
        if (opts.now_sec >= crl.this_update +| max_age) return error.CrlExpired;
    }

    if (crl.idp) |idp| try checkScope(idp, cert_der);

    if (crl.find(cert_id.serial)) |e| {
        return .{ .revoked = .{ .revocation_time = e.revocation_time, .reason = e.reason, .invalidity_time = e.invalidity_time } };
    }
    return .good;
}

/// INTEGER content without redundant leading zero octets, so a serial
/// compares by value when one side was encoded non-minimally.
fn trimInteger(b: []const u8) []const u8 {
    var s = b;
    while (s.len > 1 and s[0] == 0 and s[1] & 0x80 == 0) s = s[1..];
    return s;
}
