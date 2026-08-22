// SPDX-License-Identifier: MIT
//! Real, mechanical DER parsing for the X.509v3 extension fields RFC 5280
//! §6 path validation needs that `std.crypto.Certificate.Parsed` does NOT
//! expose: `basicConstraints`, `keyUsage`, `extKeyUsage`,
//! `subjectKeyIdentifier`, `authorityKeyIdentifier`, `nameConstraints`.
//! (std's `Parsed` only pulls out `subjectAltName` among extensions — see
//! `findExtensions`'s doc comment for why the rest need a fresh DER walk.)
//!
//! Everything in this file is bounds-checked TLV decoding built on
//! `std.crypto.Certificate`'s PUBLIC primitives (`der.Element.parse`,
//! `parseVersion`, `parseExtensionId`, the `GeneralNameTag` enum) — no
//! cryptography, no policy DECISION (matching a name against a constraint,
//! chaining EKU/pathLen across a path, building a path) — those are the hard
//! RFC 5280 §6 core and are implemented in `chain.zig`. This file only turns
//! raw extension bytes into typed Zig values.

const std = @import("std");
const Certificate = std.crypto.Certificate;
const der = Certificate.der;

// ── bounds-safe DER element parsing ─────────────────────────────────────────

/// Bounds-safe wrapper around `std.crypto.Certificate.der.Element.parse`.
///
/// The std primitive reads its own header bytes with plain `bytes[i]`
/// indexing (a Zig-safety-checked panic, not a catchable error, if `i` is
/// out of bounds) and computes `slice.end` purely from the encoded length
/// field — it never validates that `slice.end` actually fits within
/// `bytes.len`. That is fine for std's own callers, which immediately feed
/// the result into another `der.Element.parse` call that will itself panic
/// the moment it reads past the buffer — but it means a single malformed
/// length field (whether from a corrupt certificate or, as this module
/// found, a badly-shaped test fixture) that is used to index `bytes`
/// directly, without an intervening `parse` call, crashes the whole
/// process instead of surfacing a typed error.
///
/// Since every function in this file and in `chain.zig` walks
/// attacker-influenced certificate DER (RFC 5280 §6 path validation exists
/// specifically to reject hostile input), every call site here goes
/// through this wrapper instead of the bare std function: it pre-validates
/// that the identifier/length-encoding bytes are actually in `bytes` before
/// letting std read them, and post-validates that the resulting
/// `slice.start <= slice.end <= bytes.len` — turning what would otherwise
/// be an uncontrolled abort into `error.CertificateFieldHasInvalidLength`.
pub fn parseElement(bytes: []const u8, index: u32) der.Element.ParseError!der.Element {
    const idx: usize = index;
    // Need `bytes[idx]` (identifier) and `bytes[idx + 1]` (first length
    // byte) to both be valid indices.
    if (idx + 1 >= bytes.len) return error.CertificateFieldHasInvalidLength;
    const size_byte = bytes[idx + 1];
    if ((size_byte >> 7) != 0) {
        // Long form: `size_byte`'s low 7 bits count the following
        // length-encoding bytes, which std itself will read one at a time.
        const len_size: usize = size_byte & 0x7f;
        if (len_size > @sizeOf(u32)) return error.CertificateFieldHasInvalidLength;
        if (idx + 2 + len_size > bytes.len) return error.CertificateFieldHasInvalidLength;
    }
    const elem = try der.Element.parse(bytes, index);
    if (elem.slice.start > elem.slice.end or elem.slice.end > bytes.len) {
        return error.CertificateFieldHasInvalidLength;
    }
    return elem;
}

// ── locating the extensions block ───────────────────────────────────────────

pub const FindExtensionsError = der.Element.ParseError ||
    Certificate.ParseVersionError ||
    Certificate.ParseBitStringError;

/// Re-locates the `extensions [3] EXPLICIT Extensions` field of a v3
/// certificate's `TBSCertificate` (RFC 5280 §4.1.2.9). `std.crypto.Certificate.parse`
/// walks this same DER path internally to pull out `subjectAltName` alone,
/// but that walk (and the `tbs_certificate`/`pub_key_info` element
/// boundaries it computes) is private — `Parsed` has no field that exposes
/// "here is the raw extensions SEQUENCE." This function duplicates only the
/// *structural* traversal (version → serialNumber → signature →
/// issuer → validity → subject → subjectPublicKeyInfo → extensions),
/// using std's own PUBLIC `der.Element.parse`/`parseVersion` primitives —
/// no crypto, no re-parsing of anything std already validated for us
/// (callers are expected to have already called `cert.parse()` and checked
/// the result before also calling this).
///
/// Returns `null` for a v1/v2 certificate (no extensions field exists) or a
/// v3 certificate that omits the field.
pub fn findExtensions(cert: Certificate) FindExtensionsError!?der.Element.Slice {
    const bytes = cert.buffer;
    const certificate = try parseElement(bytes, cert.index);
    const tbs_certificate = try parseElement(bytes, certificate.slice.start);
    const version_elem = try parseElement(bytes, tbs_certificate.slice.start);
    const version = try Certificate.parseVersion(bytes, version_elem);
    if (version != .v3) return null;

    const serial_number = if (@as(u8, @bitCast(version_elem.identifier)) == 0xa0)
        try parseElement(bytes, version_elem.slice.end)
    else
        version_elem;
    const tbs_signature = try parseElement(bytes, serial_number.slice.end);
    const issuer = try parseElement(bytes, tbs_signature.slice.end);
    const validity = try parseElement(bytes, issuer.slice.end);
    const subject = try parseElement(bytes, validity.slice.end);
    const pub_key_info = try parseElement(bytes, subject.slice.end);

    if (pub_key_info.slice.end >= tbs_certificate.slice.end) return null;

    // `[3] EXPLICIT` on a context-specific constructed tag numbered 3 shares
    // its raw tag-number bit pattern with the universal BIT STRING tag (both
    // are 3) — this is the same coincidence `std.crypto.Certificate.parse`
    // relies on internally for this exact check, not a new assumption.
    const outer_extensions = try parseElement(bytes, pub_key_info.slice.end);
    if (outer_extensions.identifier.tag != .bitstring) return null;

    return (try parseElement(bytes, outer_extensions.slice.start)).slice;
}

// ── iterating extensions ─────────────────────────────────────────────────

pub const ExtensionEntry = struct {
    /// Recognized extension OID, when `std.crypto.Certificate.ExtensionId.map`
    /// has an entry for it; `null` for an OID std doesn't recognize (the raw
    /// bytes are still in `oid`).
    id: ?Certificate.ExtensionId,
    oid: []const u8,
    critical: bool,
    /// The extension's `extnValue OCTET STRING` CONTENT bytes (already
    /// unwrapped one level — callers parse this per-extension, e.g.
    /// `parseBasicConstraints`).
    value: []const u8,
    /// The same bytes as offsets into the certificate buffer. `value` is
    /// enough to parse an extension; this is for the callers that must hand
    /// a `std.crypto.Certificate.Parsed`-shaped slice back to std (which
    /// stores offsets, not pointers).
    value_slice: der.Element.Slice,
};

pub const IterateError = der.Element.ParseError || error{CertificateFieldHasWrongDataType};

/// Walks one `Extensions ::= SEQUENCE OF Extension` block (the slice
/// `findExtensions` returns), yielding each `Extension ::= SEQUENCE {
/// extnID OBJECT IDENTIFIER, critical BOOLEAN DEFAULT FALSE, extnValue
/// OCTET STRING }` (RFC 5280 §4.2).
pub const ExtensionIterator = struct {
    bytes: []const u8,
    pos: u32,
    end: u32,

    pub fn next(it: *ExtensionIterator) IterateError!?ExtensionEntry {
        if (it.pos >= it.end) return null;
        const extension = try parseElement(it.bytes, it.pos);
        it.pos = extension.slice.end;

        const oid_elem = try parseElement(it.bytes, extension.slice.start);
        const oid_bytes = it.bytes[oid_elem.slice.start..oid_elem.slice.end];
        const id = Certificate.parseExtensionId(it.bytes, oid_elem) catch |err| switch (err) {
            error.CertificateHasUnrecognizedObjectId => null,
            error.CertificateFieldHasWrongDataType => |e| return e,
        };

        const after_oid = try parseElement(it.bytes, oid_elem.slice.end);
        var critical = false;
        const value_elem = if (after_oid.identifier.tag == .boolean) v: {
            // Empty BOOLEAN content is malformed DER, but don't read OOB for
            // it — treat as the ASN.1 default (false), same idiom as
            // `parseKeyUsage`'s zero-length BIT STRING content check.
            if (after_oid.slice.start < after_oid.slice.end) {
                critical = it.bytes[after_oid.slice.start] != 0;
            }
            break :v try parseElement(it.bytes, after_oid.slice.end);
        } else after_oid;

        return .{
            .id = id,
            .oid = oid_bytes,
            .critical = critical,
            .value = it.bytes[value_elem.slice.start..value_elem.slice.end],
            .value_slice = value_elem.slice,
        };
    }
};

pub fn iterate(extensions_slice: der.Element.Slice, cert: Certificate) ExtensionIterator {
    return .{ .bytes = cert.buffer, .pos = extensions_slice.start, .end = extensions_slice.end };
}

// ── basicConstraints (RFC 5280 §4.2.1.9) ────────────────────────────────────

pub const BasicConstraints = struct {
    is_ca: bool = false,
    /// `pathLenConstraint`, when present. Only meaningful when `is_ca` is
    /// true (RFC 5280 §4.2.1.9: "CAs MUST NOT include the pathLenConstraint
    /// field unless the cA boolean is asserted"). Applying this constraint
    /// while walking a path is chain.zig's job, not this parser's.
    path_len_constraint: ?u32 = null,
};

pub const ParseBasicConstraintsError = der.Element.ParseError || error{
    CertificateFieldHasWrongDataType,
    CertificateFieldHasInvalidLength,
};

/// `BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint
/// INTEGER (0..MAX) OPTIONAL }`. `value` is an `ExtensionEntry.value` (already
/// the extnValue OCTET STRING content — the encoded SEQUENCE itself).
pub fn parseBasicConstraints(value: []const u8) ParseBasicConstraintsError!BasicConstraints {
    const seq = try parseElement(value, 0);
    if (seq.identifier.tag != .sequence) return error.CertificateFieldHasWrongDataType;
    if (seq.slice.start >= seq.slice.end) return .{};

    var result: BasicConstraints = .{};
    var elem = try parseElement(value, seq.slice.start);
    if (elem.identifier.tag == .boolean) {
        // Empty BOOLEAN content is malformed DER, but don't read OOB for
        // it — treat as the ASN.1 default (false), same idiom as
        // `parseKeyUsage`'s zero-length BIT STRING content check.
        if (elem.slice.start < elem.slice.end) {
            result.is_ca = value[elem.slice.start] != 0;
        }
        if (elem.slice.end >= seq.slice.end) return result;
        elem = try parseElement(value, elem.slice.end);
    }
    if (elem.identifier.tag == .integer) {
        result.path_len_constraint = try parseSmallUint(value, elem);
    }
    return result;
}

fn parseSmallUint(bytes: []const u8, elem: der.Element) ParseBasicConstraintsError!u32 {
    const int_bytes = bytes[elem.slice.start..elem.slice.end];
    if (int_bytes.len == 0 or int_bytes.len > 5) return error.CertificateFieldHasInvalidLength;
    var acc: u32 = 0;
    for (int_bytes) |b| acc = (acc << 8) | b;
    return acc;
}

// ── keyUsage (RFC 5280 §4.2.1.3) ─────────────────────────────────────────────

/// Bit order matches the ASN.1 `KeyUsage ::= BIT STRING { digitalSignature(0),
/// ..., decipherOnly(8) }` NamedBitList numbering (bit 0 = MSB of the first
/// content octet, X.690 §8.6/§11.2.7) — NOT struct-declaration-order-is-LSB;
/// see `parseKeyUsage`.
pub const KeyUsage = struct {
    digital_signature: bool = false,
    non_repudiation: bool = false,
    key_encipherment: bool = false,
    data_encipherment: bool = false,
    key_agreement: bool = false,
    key_cert_sign: bool = false,
    crl_sign: bool = false,
    encipher_only: bool = false,
    decipher_only: bool = false,
};

pub const ParseKeyUsageError = der.Element.ParseError || error{
    CertificateFieldHasWrongDataType,
    CertificateHasInvalidBitString,
};

/// `value` is the extnValue OCTET STRING content, itself a `BIT STRING`
/// (unused-bits-count byte followed by content octets, per X.690 §8.6).
pub fn parseKeyUsage(value: []const u8) ParseKeyUsageError!KeyUsage {
    const bs = try parseElement(value, 0);
    if (bs.identifier.tag != .bitstring) return error.CertificateFieldHasWrongDataType;
    const content = value[bs.slice.start..bs.slice.end];
    if (content.len == 0) return error.CertificateHasInvalidBitString;
    const unused_bits = content[0];
    if (unused_bits > 7) return error.CertificateHasInvalidBitString;
    const bits = content[1..];

    const bitAt = struct {
        fn get(b: []const u8, unused: u8, n: u4) bool {
            const byte_i = n / 8;
            if (byte_i >= b.len) return false;
            // Last used byte: bits below `unused` from the LSB side don't exist.
            if (byte_i == b.len - 1 and (7 - n % 8) < unused) return false;
            const bit_i_from_msb: u3 = @intCast(n % 8);
            const mask: u8 = @as(u8, 0x80) >> bit_i_from_msb;
            return (b[byte_i] & mask) != 0;
        }
    }.get;

    return .{
        .digital_signature = bitAt(bits, unused_bits, 0),
        .non_repudiation = bitAt(bits, unused_bits, 1),
        .key_encipherment = bitAt(bits, unused_bits, 2),
        .data_encipherment = bitAt(bits, unused_bits, 3),
        .key_agreement = bitAt(bits, unused_bits, 4),
        .key_cert_sign = bitAt(bits, unused_bits, 5),
        .crl_sign = bitAt(bits, unused_bits, 6),
        .encipher_only = bitAt(bits, unused_bits, 7),
        .decipher_only = bitAt(bits, unused_bits, 8),
    };
}

// ── extKeyUsage (RFC 5280 §4.2.1.12) ────────────────────────────────────────

/// The `id-kp-*` purposes RFC 5280 §4.2.1.12 names explicitly, plus
/// `any_extended_key_usage` (§4.2.1.12's `anyExtendedKeyUsage`, 2.5.29.37.0).
/// mTLS client-cert auth wants `.client_auth`; OPC-UA application
/// certificates don't mandate an EKU at all (OPC 10000-6 leaves it to the
/// application), so a caller validating those should treat "extension
/// absent" as "no purpose restriction", not a failure.
pub const Purpose = enum {
    server_auth, // 1.3.6.1.5.5.7.3.1
    client_auth, // 1.3.6.1.5.5.7.3.2
    code_signing, // 1.3.6.1.5.5.7.3.3
    email_protection, // 1.3.6.1.5.5.7.3.4
    time_stamping, // 1.3.6.1.5.5.7.3.8
    ocsp_signing, // 1.3.6.1.5.5.7.3.9
    any_extended_key_usage, // 2.5.29.37.0

    const oid_server_auth = [_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 };
    const oid_client_auth = [_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02 };
    const oid_code_signing = [_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03 };
    const oid_email_protection = [_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04 };
    const oid_time_stamping = [_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08 };
    const oid_ocsp_signing = [_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09 };
    const oid_any = [_]u8{ 0x55, 0x1d, 0x25, 0x00 };

    pub const map = std.StaticStringMap(Purpose).initComptime(.{
        .{ &oid_server_auth, .server_auth },
        .{ &oid_client_auth, .client_auth },
        .{ &oid_code_signing, .code_signing },
        .{ &oid_email_protection, .email_protection },
        .{ &oid_time_stamping, .time_stamping },
        .{ &oid_ocsp_signing, .ocsp_signing },
        .{ &oid_any, .any_extended_key_usage },
    });
};

pub const ExtKeyUsageIterator = struct {
    bytes: []const u8,
    pos: u32,
    end: u32,

    /// Next purpose. `known` is `null` for an OID `Purpose.map` doesn't
    /// recognize (`raw_oid` still gives the caller the bytes); no allocation
    /// — this mirrors `Certificate.der`'s own no-alloc iteration style.
    pub fn next(it: *ExtKeyUsageIterator) der.Element.ParseError!?struct { known: ?Purpose, raw_oid: []const u8 } {
        if (it.pos >= it.end) return null;
        const oid_elem = try parseElement(it.bytes, it.pos);
        it.pos = oid_elem.slice.end;
        const oid_bytes = it.bytes[oid_elem.slice.start..oid_elem.slice.end];
        return .{ .known = Purpose.map.get(oid_bytes), .raw_oid = oid_bytes };
    }
};

pub const ParseExtKeyUsageError = der.Element.ParseError || error{CertificateFieldHasWrongDataType};

/// `value` is the extnValue OCTET STRING content: `ExtKeyUsageSyntax ::=
/// SEQUENCE SIZE (1..MAX) OF KeyPurposeId` (KeyPurposeId ::= OBJECT IDENTIFIER).
pub fn parseExtKeyUsage(value: []const u8) ParseExtKeyUsageError!ExtKeyUsageIterator {
    const seq = try parseElement(value, 0);
    if (seq.identifier.tag != .sequence) return error.CertificateFieldHasWrongDataType;
    return .{ .bytes = value, .pos = seq.slice.start, .end = seq.slice.end };
}

/// Convenience over `parseExtKeyUsage`: does `value` list `want` (or
/// `anyExtendedKeyUsage`)?
pub fn hasPurpose(value: []const u8, want: Purpose) ParseExtKeyUsageError!bool {
    var it = try parseExtKeyUsage(value);
    while (try it.next()) |entry| {
        if (entry.known == want or entry.known == .any_extended_key_usage) return true;
    }
    return false;
}

// ── subjectKeyIdentifier / authorityKeyIdentifier (RFC 5280 §4.2.1.1/.2) ────

pub const ParseSubjectKeyIdentifierError = der.Element.ParseError || error{CertificateFieldHasWrongDataType};

/// `value` is the extnValue OCTET STRING content, which for
/// `SubjectKeyIdentifier ::= KeyIdentifier` (`KeyIdentifier ::= OCTET STRING`)
/// is itself ANOTHER OCTET STRING TLV wrapping the actual key-identifier
/// bytes — `extnValue`'s outer OCTET STRING is unwrapped by `iterate`
/// already (that's `ExtensionEntry.value`), but `KeyIdentifier`'s own
/// `OCTET STRING` tag+length is a second, inner layer that still needs
/// stripping here. Getting this wrong (returning `value` unchanged) silently
/// breaks every authorityKeyIdentifier/subjectKeyIdentifier comparison in
/// `chain.zig`'s path builder: a real SKI extnValue is `04 <len> <key
/// bytes>`, two bytes longer than the AKI side's already-unwrapped
/// `keyIdentifier` content, so a byte-for-byte match against a correctly
/// unwrapped AKI would never succeed.
pub fn parseSubjectKeyIdentifier(value: []const u8) ParseSubjectKeyIdentifierError![]const u8 {
    const elem = try parseElement(value, 0);
    if (elem.identifier.tag != .octetstring) return error.CertificateFieldHasWrongDataType;
    return value[elem.slice.start..elem.slice.end];
}

pub const AuthorityKeyIdentifier = struct {
    /// The `keyIdentifier [0] IMPLICIT KeyIdentifier OPTIONAL` field, when
    /// present. The alternative `authorityCertIssuer [1]` /
    /// `authorityCertSerialNumber [2]` forms (naming the issuer by name+serial
    /// instead of by key hash) are NOT parsed here — `keyIdentifier` is the
    /// form essentially every CA emits; add [1]/[2] support if a consumer
    /// actually needs it.
    key_identifier: ?[]const u8 = null,
};

pub const ParseAuthorityKeyIdentifierError = der.Element.ParseError || error{CertificateFieldHasWrongDataType};

/// `value` is the extnValue OCTET STRING content: `AuthorityKeyIdentifier ::=
/// SEQUENCE { keyIdentifier [0] IMPLICIT KeyIdentifier OPTIONAL, ... }`.
pub fn parseAuthorityKeyIdentifier(value: []const u8) ParseAuthorityKeyIdentifierError!AuthorityKeyIdentifier {
    const seq = try parseElement(value, 0);
    if (seq.identifier.tag != .sequence) return error.CertificateFieldHasWrongDataType;
    if (seq.slice.start >= seq.slice.end) return .{};

    const first = try parseElement(value, seq.slice.start);
    // `[0] IMPLICIT KeyIdentifier` -> context-specific primitive tag number 0
    // (raw identifier byte 0x80); reuses the same "context tag number as
    // Tag enum discriminant" reading `findExtensions` already relies on.
    if (@as(u8, @bitCast(first.identifier)) == 0x80) {
        return .{ .key_identifier = value[first.slice.start..first.slice.end] };
    }
    return .{};
}

// ── nameConstraints (RFC 5280 §4.2.1.10) ────────────────────────────────────

pub const NameConstraints = struct {
    /// Raw `GeneralSubtrees` (`SEQUENCE OF GeneralSubtree`) bytes for
    /// `permittedSubtrees [0]`, when present. Walk with `subtreeIterator`.
    permitted: ?[]const u8 = null,
    /// Same shape, for `excludedSubtrees [1]`.
    excluded: ?[]const u8 = null,
};

pub const ParseNameConstraintsError = der.Element.ParseError || error{CertificateFieldHasWrongDataType};

/// `value` is the extnValue OCTET STRING content: `NameConstraints ::=
/// SEQUENCE { permittedSubtrees [0] GeneralSubtrees OPTIONAL, excludedSubtrees
/// [1] GeneralSubtrees OPTIONAL }`.
pub fn parseNameConstraints(value: []const u8) ParseNameConstraintsError!NameConstraints {
    const seq = try parseElement(value, 0);
    if (seq.identifier.tag != .sequence) return error.CertificateFieldHasWrongDataType;

    var result: NameConstraints = .{};
    var pos = seq.slice.start;
    while (pos < seq.slice.end) {
        const elem = try parseElement(value, pos);
        pos = elem.slice.end;
        switch (@as(u8, @bitCast(elem.identifier))) {
            0xa0 => result.permitted = value[elem.slice.start..elem.slice.end], // [0] EXPLICIT/constructed
            0xa1 => result.excluded = value[elem.slice.start..elem.slice.end], // [1]
            else => {},
        }
    }
    return result;
}

pub const SubtreeEntry = struct {
    /// The `base GeneralName`'s CHOICE tag, reusing
    /// `std.crypto.Certificate.GeneralNameTag` (same enum std's own
    /// `verifyHostName` SAN walk uses).
    tag: Certificate.GeneralNameTag,
    /// The `base GeneralName`'s content bytes (e.g. ASCII for `dNSName`/
    /// `rfc822Name`/`uniformResourceIdentifier`, DER `Name` bytes for
    /// `directoryName`, raw address+mask bytes for `iPAddress`).
    value: []const u8,
};

/// Walks one `GeneralSubtrees` blob (`permitted`/`excluded` from
/// `NameConstraints`), yielding each subtree's `base GeneralName` only.
/// The optional `minimum [0] BaseDistance DEFAULT 0` / `maximum [1]
/// BaseDistance OPTIONAL` fields (RFC 5280 §4.2.1.10: "MUST NOT be used" for
/// minimum != 0 and maximum is not used in the RFC's own PKIX profile) are
/// skipped rather than parsed — the iterator advances by the *outer*
/// `GeneralSubtree` SEQUENCE's own slice, so a well-formed encoding with
/// those fields present is still walked correctly; they are simply not
/// surfaced.
pub const SubtreeIterator = struct {
    bytes: []const u8,
    pos: u32,
    end: u32,

    pub fn next(it: *SubtreeIterator) der.Element.ParseError!?SubtreeEntry {
        if (it.pos >= it.end) return null;
        const subtree = try parseElement(it.bytes, it.pos); // GeneralSubtree ::= SEQUENCE
        it.pos = subtree.slice.end;
        const base = try parseElement(it.bytes, subtree.slice.start); // base GeneralName
        return .{
            .tag = @enumFromInt(@intFromEnum(base.identifier.tag)),
            .value = it.bytes[base.slice.start..base.slice.end],
        };
    }
};

pub fn subtreeIterator(subtrees: []const u8) SubtreeIterator {
    return .{ .bytes = subtrees, .pos = 0, .end = @intCast(subtrees.len) };
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;
const rsa = @import("rsa");

/// Fixed-seed key + a real self-signed cert from `rsa.selfSignedCert`
/// (already unit-tested against `std.crypto.Certificate` in the `rsa`
/// module) — cross-validates `findExtensions`/`iterate`/`parseBasicConstraints`/
/// `parseKeyUsage` against a real, independently-produced DER certificate
/// instead of only hand-built byte fixtures.
fn testCert(gpa: std.mem.Allocator, is_ca: bool) ![]u8 {
    var prng = std.Random.DefaultPrng.init(0xc0ffee);
    const kp = try rsa.generate(prng.random(), 512, 65537);
    return rsa.selfSignedCert(gpa, kp.secret_key, kp.public_key, std.crypto.hash.sha2.Sha256, .{
        .common_name = "x509 extensions test",
        .not_before = "260101000000Z",
        .not_after = "300101000000Z",
        .is_ca = is_ca,
    });
}

fn findExt(cert: Certificate, want: Certificate.ExtensionId) !?ExtensionEntry {
    const ext_slice = (try findExtensions(cert)) orelse return null;
    var it = iterate(ext_slice, cert);
    while (try it.next()) |entry| {
        if (entry.id == want) return entry;
    }
    return null;
}

test "findExtensions + basicConstraints round-trip against rsa.selfSignedCert (CA)" {
    const gpa = testing.allocator;
    const der_bytes = try testCert(gpa, true);
    defer gpa.free(der_bytes);

    const cert: Certificate = .{ .buffer = der_bytes, .index = 0 };
    _ = try cert.parse(); // sanity: std itself accepts this certificate

    const entry = (try findExt(cert, .basic_constraints)).?;
    try testing.expect(entry.critical);
    const bc = try parseBasicConstraints(entry.value);
    try testing.expect(bc.is_ca);
    try testing.expectEqual(@as(?u32, null), bc.path_len_constraint);
}

test "findExtensions + basicConstraints round-trip against rsa.selfSignedCert (leaf)" {
    const gpa = testing.allocator;
    const der_bytes = try testCert(gpa, false);
    defer gpa.free(der_bytes);

    const cert: Certificate = .{ .buffer = der_bytes, .index = 0 };
    _ = try cert.parse();

    const entry = (try findExt(cert, .basic_constraints)).?;
    const bc = try parseBasicConstraints(entry.value);
    try testing.expect(!bc.is_ca);
}

test "keyUsage round-trip: CA sets keyCertSign+cRLSign, leaf sets only digitalSignature" {
    const gpa = testing.allocator;

    const ca_der = try testCert(gpa, true);
    defer gpa.free(ca_der);
    const leaf_der = try testCert(gpa, false);
    defer gpa.free(leaf_der);

    const ca_cert: Certificate = .{ .buffer = ca_der, .index = 0 };
    const leaf_cert: Certificate = .{ .buffer = leaf_der, .index = 0 };

    const ca_ku = try parseKeyUsage((try findExt(ca_cert, .key_usage)).?.value);
    try testing.expect(ca_ku.digital_signature);
    try testing.expect(ca_ku.key_cert_sign);
    try testing.expect(ca_ku.crl_sign);
    try testing.expect(!ca_ku.key_encipherment);

    const leaf_ku = try parseKeyUsage((try findExt(leaf_cert, .key_usage)).?.value);
    try testing.expect(leaf_ku.digital_signature);
    try testing.expect(!leaf_ku.key_cert_sign);
    try testing.expect(!leaf_ku.crl_sign);
}

test "parseBasicConstraints: pathLenConstraint present" {
    // Hand-built `BasicConstraints ::= SEQUENCE { cA TRUE, pathLenConstraint 3 }`
    // — `rsa.selfSignedCert` never emits a pathLenConstraint, so this exercises
    // the branch a real fixture can't reach.
    const value = [_]u8{ 0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x03 };
    const bc = try parseBasicConstraints(&value);
    try testing.expect(bc.is_ca);
    try testing.expectEqual(@as(?u32, 3), bc.path_len_constraint);
}

test "parseBasicConstraints: zero-length BOOLEAN content does not read OOB" {
    // Regression for a crash: `SEQUENCE { BOOLEAN len 0 }` ending exactly at
    // the buffer edge used to read `value[elem.slice.start]` with
    // `elem.slice.start == value.len`, panicking instead of erroring or
    // defaulting. Malformed DER (BOOLEAN must carry exactly one content
    // octet), so the parser treats it as the ASN.1 default (cA = false)
    // rather than rejecting it outright — matching `parseKeyUsage`'s
    // zero-length-content idiom.
    const value = [_]u8{ 0x30, 0x02, 0x01, 0x00 };
    const bc = try parseBasicConstraints(&value);
    try testing.expect(!bc.is_ca);
    try testing.expectEqual(@as(?u32, null), bc.path_len_constraint);
}

test "ExtensionIterator.next: zero-length critical BOOLEAN content does not read OOB" {
    // Regression for a crash: a `critical` BOOLEAN with zero-length content
    // ending exactly at the buffer edge used to read
    // `it.bytes[after_oid.slice.start]` with `after_oid.slice.start ==
    // it.bytes.len`, panicking instead of defaulting `critical = false`.
    // The zero-length BOOLEAN content leaves no extnValue TLV to follow, so
    // this input is malformed past the point of the fixed read: after
    // defaulting `critical = false` without panicking, the iterator still
    // correctly errors trying to parse the (absent) extnValue element
    // instead of crashing.
    const bytes = [_]u8{ 0x30, 0x07, 0x06, 0x03, 0x55, 0x04, 0x03, 0x01, 0x00 };
    var it: ExtensionIterator = .{ .bytes = &bytes, .pos = 0, .end = bytes.len };
    try testing.expectError(error.CertificateFieldHasInvalidLength, it.next());
}

test "parseExtKeyUsage: serverAuth + clientAuth" {
    // ExtKeyUsageSyntax ::= SEQUENCE OF KeyPurposeId, two OIDs:
    // 1.3.6.1.5.5.7.3.1 (serverAuth), 1.3.6.1.5.5.7.3.2 (clientAuth).
    const value = [_]u8{
        0x30, 0x14,
        0x06, 0x08,
        0x2b, 0x06,
        0x01, 0x05,
        0x05, 0x07,
        0x03, 0x01,
        0x06, 0x08,
        0x2b, 0x06,
        0x01, 0x05,
        0x05, 0x07,
        0x03, 0x02,
    };
    try testing.expect(try hasPurpose(&value, .server_auth));
    try testing.expect(try hasPurpose(&value, .client_auth));
    try testing.expect(!try hasPurpose(&value, .code_signing));
}

test "parseAuthorityKeyIdentifier: keyIdentifier [0]" {
    // AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] IMPLICIT OCTET STRING }
    const value = [_]u8{ 0x30, 0x06, 0x80, 0x04, 0xde, 0xad, 0xbe, 0xef };
    const aki = try parseAuthorityKeyIdentifier(&value);
    try testing.expectEqualSlices(u8, &.{ 0xde, 0xad, 0xbe, 0xef }, aki.key_identifier.?);
}

test "parseSubjectKeyIdentifier: unwraps the inner OCTET STRING TLV" {
    // extnValue content = OCTET STRING(4 bytes) wrapping 0xde 0xad 0xbe 0xef.
    const value = [_]u8{ 0x04, 0x04, 0xde, 0xad, 0xbe, 0xef };
    try testing.expectEqualSlices(u8, &.{ 0xde, 0xad, 0xbe, 0xef }, try parseSubjectKeyIdentifier(&value));
}

test "nameConstraints: permitted dNSName subtree" {
    // NameConstraints ::= SEQUENCE {
    //   permittedSubtrees [0] { SEQUENCE { GeneralSubtree { base dNSName "example.com" } } }
    // }
    // GeneralSubtree ::= SEQUENCE { base GeneralName }; dNSName is [2] IMPLICIT IA5String.
    // Implicit tagging (RFC 5280's PKIX1Implicit88 module): `[0]
    // GeneralSubtrees` replaces GeneralSubtrees' own SEQUENCE tag with 0xa0
    // rather than wrapping it in an extra layer, so `permitted`'s content is
    // the concatenated `GeneralSubtree` elements directly (just `general_subtree`
    // here, since this fixture has exactly one).
    const dns_name = "example.com";
    const general_subtree = [_]u8{ 0x30, 2 + dns_name.len, 0x82, dns_name.len } ++ dns_name[0..dns_name.len].*;
    const permitted = [_]u8{ 0xa0, general_subtree.len } ++ general_subtree;
    const value = [_]u8{ 0x30, permitted.len } ++ permitted;

    const nc = try parseNameConstraints(&value);
    try testing.expect(nc.excluded == null);
    var it = subtreeIterator(nc.permitted.?);
    const entry = (try it.next()).?;
    try testing.expectEqual(Certificate.GeneralNameTag.dNSName, entry.tag);
    try testing.expectEqualStrings(dns_name, entry.value);
    try testing.expect((try it.next()) == null);
}

// ── fuzz: this file's own bounded DER walk, never std's ─────────────────────
//
// Every function here is the library's OWN bounded parser (built on
// `parseElement`, which pre/post-validates offsets — see its doc comment),
// as opposed to `std.crypto.Certificate.parse` (a single-certificate parse
// std itself does not bounds-check safely against untrusted DER; see
// SPEC.md's ReleaseSafe policy note and root.zig / chain.zig doc comments
// for that tracked-but-not-fuzzed hazard). `findExtensions` below is called
// directly on a raw buffer WITHOUT going through `Certificate.parse` first —
// exactly what makes it a self-contained, fuzz-safe target: no std parser
// sits in front of it.

test "fuzz: findExtensions + all extension-value parsers never panic on arbitrary bytes" {
    try testing.fuzz({}, fuzzExtensions, .{});
}

fn fuzzExtensions(_: void, smith: *std.testing.Smith) !void {
    var buf: [768]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const bytes = buf[0..len];

    // Shape 1: the whole buffer as a "certificate" — exercises
    // `findExtensions`'s structural walk (version → serialNumber →
    // signature → issuer → validity → subject → subjectPublicKeyInfo →
    // extensions) directly against hostile bytes, with NO prior
    // `Certificate.parse()` call (this function does not require one to
    // avoid panicking, only to be meaningful — see its doc comment).
    const cert: Certificate = .{ .buffer = bytes, .index = 0 };
    if (findExtensions(cert) catch null) |ext_slice| {
        var it = iterate(ext_slice, cert);
        while (it.next() catch null) |entry| {
            _ = parseBasicConstraints(entry.value) catch {};
            _ = parseKeyUsage(entry.value) catch {};
            _ = hasPurpose(entry.value, .server_auth) catch {};
            _ = parseSubjectKeyIdentifier(entry.value) catch {};
            _ = parseAuthorityKeyIdentifier(entry.value) catch {};
            if (parseNameConstraints(entry.value) catch null) |nc| {
                if (nc.permitted) |p| {
                    var sit = subtreeIterator(p);
                    while (sit.next() catch null) |_| {}
                }
                if (nc.excluded) |e| {
                    var sit = subtreeIterator(e);
                    while (sit.next() catch null) |_| {}
                }
            }
        }
    }

    // Shape 2: the buffer as a bare `extnValue` OCTET STRING content — the
    // actual shape each of these functions receives in production (an
    // already-unwrapped `ExtensionEntry.value`), independent of whether
    // `findExtensions`/`iterate` above happened to walk that far.
    _ = parseBasicConstraints(bytes) catch {};
    _ = parseKeyUsage(bytes) catch {};
    _ = hasPurpose(bytes, .client_auth) catch {};
    _ = parseSubjectKeyIdentifier(bytes) catch {};
    _ = parseAuthorityKeyIdentifier(bytes) catch {};
    if (parseNameConstraints(bytes) catch null) |nc| {
        if (nc.permitted) |p| {
            var sit = subtreeIterator(p);
            while (sit.next() catch null) |_| {}
        }
        if (nc.excluded) |e| {
            var sit = subtreeIterator(e);
            while (sit.next() catch null) |_| {}
        }
    }
}
