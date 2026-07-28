// SPDX-License-Identifier: MIT
//! Certificate-DER safety: the canonical guard in front of
//! `std.crypto.Certificate.parse` for this collection.
//!
//! ## The hazard
//!
//! `std.crypto.Certificate`'s DER reader (`der.Element.parse`) reads its
//! identifier and length octets with plain `bytes[i]` indexing — a
//! Zig-safety-checked panic, not a catchable error, when `i` is out of bounds —
//! and computes an element's end as `start + declared_length` *without clamping
//! it against the buffer*. `Certificate.parse` then walks the tbsCertificate
//! field by field, each step parsing at the previous element's `slice.end`, and
//! at several points probes for an OPTIONAL sibling at a boundary without first
//! checking that any byte exists there. Feed it a truncated or malformed
//! certificate and the parser indexes past the buffer. Empirically, on Zig
//! 0.16.0 (verified out of band, see `SPEC.md`):
//!
//!   * in **Debug** it panics — `index out of bounds` — aborting the process;
//!   * in **ReleaseFast** the same inputs either read out of bounds *silently*
//!     (returning a `Parsed` built from whatever lay past the buffer) or
//!     segfault outright.
//!
//! On a TLS / OPC-UA / IEC 62351 (GOOSE) server the peer certificate is fully
//! attacker-controlled, so this is a remotely-triggerable crash — and the
//! silent-OOB-read ReleaseFast variant is arguably worse than a crash. Three
//! modules in this collection hit this independently and each grew its own
//! guard (`x509`'s per-element `extensions.parseElement`, `iec62351`'s
//! `tlsprofile.structurallySafe`, `opcua`'s `security.safeCertificate`); this
//! file is the single reconciled implementation they all now route through.
//!
//! ## The fix, in two layers
//!
//! 1. **`validate` / `validateCertificate`** — a recursive-descent DER
//!    well-formedness validator that walks the whole TLV structure *without
//!    trusting std's reader at all* (its own bounds-checked header decoder) and
//!    returns a typed error for any length that overruns its container, any
//!    truncated tag or length, any indefinite-length encoding (BER, illegal in
//!    DER), any high-tag-number identifier, a length-of-length beyond four
//!    octets (more than the `u32` std computes ends in), and nesting past a
//!    bounded depth. Every accepted element provably sits wholly inside the
//!    buffer.
//!
//! 2. **`safeCertificate`** — well-formedness is *necessary but not sufficient*
//!    to make `std.crypto.Certificate.parse` total. A well-formed but
//!    minimally-shaped input such as `30 02 30 00` (`SEQUENCE { SEQUENCE {} }`)
//!    passes `validateCertificate`, yet std, having consumed the empty inner
//!    element as the tbsCertificate, then parses the *next* field at the buffer
//!    boundary and indexes past the end (Debug panic / ReleaseFast OOB read —
//!    both reproduced). The remedy is a fixed amount of zero padding behind a
//!    validated copy: std's boundary probes then read `00 00` empty TLVs out of
//!    the padding instead of off the end, and every loop std runs is bounded by
//!    an element end this validator already proved in-bounds, so a bounded
//!    number of such probes cannot walk through `parse_slack` zero bytes.
//!    `safeCertificate` validates, copies into caller-supplied scratch, zero-
//!    pads, and hands back a `std.crypto.Certificate` that is safe to `parse`.
//!    With it, the same `30 02 30 00` yields a clean
//!    `error.CertificateFieldHasWrongDataType` in **both** Debug and
//!    ReleaseFast (verified).
//!
//! So the scratch-copy convenience is **kept, because it is required**: the
//! well-formedness check alone does not neutralise the std hazard, only the
//! validated-plus-padded buffer does. See `SPEC.md` for the full argument and
//! the out-of-band panic reproduction.
//!
//! Provenance: clean-room from X.690 (DER encoding rules) and the observed
//! behaviour of `std.crypto.Certificate` (MIT, part of Zig std). No third-party
//! code.

const std = @import("std");
const Certificate = std.crypto.Certificate;

/// Deepest TLV nesting the validator will descend before giving up. A DER
/// X.509 certificate nests roughly six or seven levels in practice; anything
/// past this is either an attack or something no certificate parser has any
/// business inspecting. Matches the bound the `opcua` guard used.
pub const max_depth: u8 = 32;

/// Largest certificate `safeCertificate` will look at. A 4096-bit RSA
/// application certificate is ~1.6 kB, so this is generous; the point of a
/// bound at all is that a caller can size a fixed scratch buffer for the parse.
pub const max_certificate_len: usize = 8192;

/// Zero bytes `safeCertificate` appends behind the certificate so std's
/// boundary probes read empty TLVs out of the padding rather than off the end
/// of the buffer. Two bytes (`00 00`, an empty element) satisfy one probe;
/// std makes at most a handful in a row and every loop it runs is bounded by a
/// validated element end, so this is comfortably more than enough.
pub const parse_slack: usize = 64;

/// Every way `validate` / `validateCertificate` can reject an input. All are
/// returned, never panicked.
pub const Error = error{
    /// Zero-length input.
    Empty,
    /// The buffer ends inside a tag, a length octet, or an element's content.
    Truncated,
    /// BER indefinite-length form (`0x80`). Illegal in DER.
    IndefiniteLength,
    /// High-tag-number identifier (low five bits all set, `0x1f`). No X.509
    /// DER tag uses it, and std's parser does not handle it.
    MultiByteTag,
    /// Long-form length using more than four octets — more than the `u32` std
    /// computes element ends in.
    LengthTooLarge,
    /// A declared content length runs past the end of its container.
    LengthOverrun,
    /// Nesting deeper than `max_depth`.
    MaxDepthExceeded,
    /// `validateCertificate` only: the outer element is not a single
    /// `SEQUENCE` that exactly fills the buffer.
    NotCertificate,
};

const Header = struct {
    /// Offset of the first content octet.
    content_start: usize,
    /// Offset one past the last content octet.
    content_end: usize,
    /// Identifier bit 6 set — the element has child TLVs.
    constructed: bool,
};

/// Decode one TLV header at `bytes[start..end)` with fully bounds-checked
/// indexing — this is the primitive that does **not** trust std's reader. It
/// never reads outside `[start, end)` and guarantees the returned
/// `content_end <= end`.
fn decodeHeader(bytes: []const u8, start: usize, end: usize) Error!Header {
    // Need the identifier octet and at least the first length octet.
    if (start + 2 > end) return error.Truncated;
    const tag = bytes[start];
    if (tag & 0x1f == 0x1f) return error.MultiByteTag;
    const size_byte = bytes[start + 1];

    var content_start: usize = start + 2;
    var content_len: usize = size_byte;
    if (size_byte & 0x80 != 0) {
        const n: usize = size_byte & 0x7f;
        if (n == 0) return error.IndefiniteLength;
        if (n > 4) return error.LengthTooLarge;
        // The length octets themselves must be inside the container.
        if (start + 2 + n > end) return error.Truncated;
        content_len = 0;
        for (bytes[start + 2 ..][0..n]) |b| content_len = (content_len << 8) | b;
        content_start = start + 2 + n;
    }

    // `content_start <= end` holds here (short form: start+2 <= end from the
    // first check; long form: start+2+n <= end just checked), so the
    // subtraction cannot underflow.
    if (content_len > end - content_start) return error.LengthOverrun;
    return .{
        .content_start = content_start,
        .content_end = content_start + content_len,
        .constructed = tag & 0x20 != 0,
    };
}

/// Recursively require every TLV in `bytes[start..end)` to be well-formed and
/// to tile the region exactly (no gaps, no overrun). Descends into constructed
/// elements only.
fn walk(bytes: []const u8, start: usize, end: usize, depth: u8) Error!void {
    if (depth == 0) return error.MaxDepthExceeded;
    var i = start;
    while (i < end) {
        const h = try decodeHeader(bytes, i, end);
        if (h.constructed) try walk(bytes, h.content_start, h.content_end, depth - 1);
        i = h.content_end;
    }
}

/// Validate that `bytes` is a well-formed exact tiling of one or more DER TLVs.
/// Returns a typed error — never panics — for any malformed input. This is the
/// general recursive-descent well-formedness check; `validateCertificate` adds
/// the certificate-shape requirement on top.
pub fn validate(bytes: []const u8) Error!void {
    if (bytes.len == 0) return error.Empty;
    return walk(bytes, 0, bytes.len, max_depth);
}

/// `validate`, additionally requiring the input to be a single `SEQUENCE` that
/// exactly fills the buffer — i.e. shaped like `Certificate ::= SEQUENCE`.
/// This does not prove the input *is* a valid certificate (that is std's job,
/// via `safeCertificate`); it proves it is safe to hand to std's parser once
/// padded.
pub fn validateCertificate(bytes: []const u8) Error!void {
    if (bytes.len == 0) return error.Empty;
    const outer = try decodeHeader(bytes, 0, bytes.len);
    // Universal SEQUENCE is tag 0x30 (constructed, tag number 16).
    if (bytes[0] != 0x30) return error.NotCertificate;
    if (outer.content_end != bytes.len) return error.NotCertificate;
    return walk(bytes, outer.content_start, outer.content_end, max_depth);
}

pub const SafeCertificateError = Error || error{
    /// The certificate is larger than `max_certificate_len`.
    TooLarge,
    /// `scratch` is smaller than `certificate_der.len + parse_slack`.
    ScratchTooSmall,
};

/// Validate `certificate_der` and return a `std.crypto.Certificate` backed by a
/// zero-padded copy of it in `scratch`, safe to hand to
/// `std.crypto.Certificate.parse` without any risk of panic, out-of-bounds
/// read, or segfault regardless of optimisation mode.
///
/// `scratch` must be at least `certificate_der.len + parse_slack` bytes; a
/// caller with a compile-time bound can use
/// `[max_certificate_len + parse_slack]u8`. The returned certificate borrows
/// `scratch`, so `scratch` must outlive it (and every `Parsed` derived from
/// it).
///
/// See this file's and `SPEC.md`'s discussion for why validation alone is not
/// enough and the padding is required.
pub fn safeCertificate(certificate_der: []const u8, scratch: []u8) SafeCertificateError!Certificate {
    if (certificate_der.len == 0) return error.Empty;
    if (certificate_der.len > max_certificate_len) return error.TooLarge;
    if (scratch.len < certificate_der.len + parse_slack) return error.ScratchTooSmall;
    try validateCertificate(certificate_der);
    @memcpy(scratch[0..certificate_der.len], certificate_der);
    @memset(scratch[certificate_der.len..][0..parse_slack], 0);
    return .{ .buffer = scratch[0 .. certificate_der.len + parse_slack], .index = 0 };
}

// ── SubjectPublicKeyInfo extraction (never via Certificate.parse) ───────────

/// Well-known `AlgorithmIdentifier` OIDs, as raw OID *content* bytes (no
/// tag/length octets) — directly comparable with `Spki.algorithm_oid` /
/// `Spki.namedCurveOid`.
pub const oid_rsa_encryption = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 }; // 1.2.840.113549.1.1.1
pub const oid_ec_public_key = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 }; // 1.2.840.10045.2.1
pub const oid_prime256v1 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 }; // 1.2.840.10045.3.1.7
pub const oid_secp384r1 = [_]u8{ 0x2b, 0x81, 0x04, 0x00, 0x22 }; // 1.3.132.0.34
pub const oid_ed25519 = [_]u8{ 0x2b, 0x65, 0x70 }; // 1.3.101.112

/// A certificate's `SubjectPublicKeyInfo`, decomposed.
///
/// **Lifetime / borrowing contract: every field is a sub-slice of the
/// `certificate_der` buffer passed to `spkiOf` — nothing is copied and nothing
/// is allocated.** The whole `Spki` is therefore valid exactly as long as that
/// buffer is, and becomes dangling the moment the caller frees or reuses it.
/// A caller that needs the key material to outlive the certificate bytes must
/// copy it (or parse it into an owned key type, e.g. `rsa.PublicKey.fromDer`,
/// which copies) before the buffer goes away. `spkiOf` never mutates its input.
pub const Spki = struct {
    /// The full `SubjectPublicKeyInfo` TLV — tag and length octets included,
    /// exactly the shape `rsa.PublicKey.fromDer` and OpenSSL's
    /// `d2i_PUBKEY` accept.
    der: []const u8,
    /// The `AlgorithmIdentifier.algorithm` OID's *content* bytes (no tag or
    /// length octets) — compare against `oid_rsa_encryption` and friends.
    algorithm_oid: []const u8,
    /// `AlgorithmIdentifier.parameters`, full TLV, or `null` when the
    /// AlgorithmIdentifier carries no second field at all. For an EC key this
    /// is the `namedCurve` OBJECT IDENTIFIER (see `namedCurveOid`); for RSA it
    /// is conventionally a NULL.
    parameters: ?[]const u8,
    /// The `subjectPublicKey` BIT STRING's content with the leading
    /// unused-bits octet already stripped — for an EC key this is the SEC1
    /// point, for RSA the embedded PKCS#1 `RSAPublicKey` DER. A BIT STRING
    /// with a non-zero unused-bit count is rejected by `spkiOf` outright, so
    /// this is always whole octets.
    key_bits: []const u8,

    /// Whether the key's algorithm OID equals `oid_content` (raw OID content
    /// bytes — use one of the `oid_*` constants in this file).
    pub fn algorithmIs(self: Spki, oid_content: []const u8) bool {
        return std.mem.eql(u8, self.algorithm_oid, oid_content);
    }

    /// The `namedCurve` OID's content bytes when `parameters` is a single
    /// OBJECT IDENTIFIER (the only EC parameter form RFC 5480 §2.1.1 permits
    /// in a PKIX certificate), `null` otherwise — including for the
    /// `implicitCurve`/`specifiedCurve` forms, which are deliberately NOT
    /// decoded: a caller must treat "no named curve" as "cannot compare".
    pub fn namedCurveOid(self: Spki) ?[]const u8 {
        const p = self.parameters orelse return null;
        if (p.len == 0 or p[0] != 0x06) return null; // universal, primitive, OBJECT IDENTIFIER
        const h = decodeHeader(p, 0, p.len) catch return null;
        if (h.content_end != p.len) return null; // exactly one OID, no trailing bytes
        return p[h.content_start..h.content_end];
    }
};

pub const SpkiError = Error || error{
    /// The input is well-formed DER but its `TBSCertificate` field sequence
    /// does not reach a `subjectPublicKeyInfo` (a field is missing, or the
    /// outer/`tbsCertificate` element is not a SEQUENCE).
    MalformedTbsCertificate,
    /// `subjectPublicKeyInfo` is not `SEQUENCE { AlgorithmIdentifier SEQUENCE
    /// { OBJECT IDENTIFIER, parameters OPTIONAL }, BIT STRING }`, carries
    /// extra fields, or its BIT STRING is empty / not byte-aligned (non-zero
    /// unused-bit count).
    MalformedSubjectPublicKeyInfo,
};

/// One TLV header at `pos`, or `null` when no element starts there (the
/// container is exhausted, or its remainder is too short to hold a header).
/// Total on any input: `decodeHeader` is the bounds-checked primitive that
/// does not trust std's reader, and `pos + 2 > limit` is checked before any
/// indexing.
fn nextField(bytes: []const u8, pos: usize, limit: usize) ?Header {
    if (pos + 2 > limit) return null;
    return decodeHeader(bytes, pos, limit) catch null;
}

/// Extract a certificate's `SubjectPublicKeyInfo` **without ever calling
/// `std.crypto.Certificate.parse`** — the point of this function.
///
/// `certificate_der` is untrusted, attacker-controlled input by assumption
/// (a TLS/OPC-UA peer certificate, a SAML `<ds:X509Certificate>`, an OCSP
/// responder certificate). It is first run through `validateCertificate`, so
/// every TLV in the buffer is proven to sit wholly inside it and to tile its
/// container exactly; the field walk that follows (version → serialNumber →
/// signature → issuer → validity → subject → subjectPublicKeyInfo, RFC 5280
/// §4.1) then uses only this file's own bounds-checked `decodeHeader`. No
/// validity dates, algorithm OIDs, extensions or signature bytes are decoded
/// — none of them is needed to name the key, and each one is another parser
/// to get wrong. **Fails closed:** anything that does not decode exactly is a
/// typed `SpkiError`, never a panic and never a partial result.
///
/// **Lifetime:** the returned `Spki`'s fields all borrow `certificate_der` —
/// see `Spki`'s doc comment.
///
/// Note what this does and does not prove. It proves that the returned bytes
/// are the certificate's SubjectPublicKeyInfo field. It proves nothing about
/// the certificate's signature, validity window, issuer, or extensions — this
/// is a field accessor, not a verifier. Use `chain.verifyChain` for that.
pub fn spkiOf(certificate_der: []const u8) SpkiError!Spki {
    try validateCertificate(certificate_der);
    const b = certificate_der;

    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    const certificate = decodeHeader(b, 0, b.len) catch return error.MalformedTbsCertificate;
    const tbs_start = certificate.content_start;
    const tbs = nextField(b, tbs_start, certificate.content_end) orelse return error.MalformedTbsCertificate;
    if (b[tbs_start] != 0x30) return error.MalformedTbsCertificate;

    // TBSCertificate ::= SEQUENCE { version [0] EXPLICIT DEFAULT v1,
    //   serialNumber, signature, issuer, validity, subject,
    //   subjectPublicKeyInfo, ... }
    const lim = tbs.content_end;
    var pos = tbs.content_start;
    var f = nextField(b, pos, lim) orelse return error.MalformedTbsCertificate;
    if (b[pos] == 0xa0) { // the OPTIONAL version tag; serialNumber is the next field
        pos = f.content_end;
        f = nextField(b, pos, lim) orelse return error.MalformedTbsCertificate;
    }
    pos = f.content_end; // -> signature
    for (0..4) |_| { // signature, issuer, validity, subject
        f = nextField(b, pos, lim) orelse return error.MalformedTbsCertificate;
        pos = f.content_end;
    }

    // SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier,
    //   subjectPublicKey BIT STRING }
    const spki_start = pos;
    const spki = nextField(b, spki_start, lim) orelse return error.MalformedTbsCertificate;
    if (b[spki_start] != 0x30) return error.MalformedSubjectPublicKeyInfo;

    const alg_start = spki.content_start;
    const alg = nextField(b, alg_start, spki.content_end) orelse return error.MalformedSubjectPublicKeyInfo;
    if (b[alg_start] != 0x30) return error.MalformedSubjectPublicKeyInfo;

    const oid_start = alg.content_start;
    const oid = nextField(b, oid_start, alg.content_end) orelse return error.MalformedSubjectPublicKeyInfo;
    if (b[oid_start] != 0x06) return error.MalformedSubjectPublicKeyInfo;

    const parameters: ?[]const u8 = if (oid.content_end < alg.content_end) params: {
        const p = nextField(b, oid.content_end, alg.content_end) orelse return error.MalformedSubjectPublicKeyInfo;
        if (p.content_end != alg.content_end) return error.MalformedSubjectPublicKeyInfo; // exactly one parameters field
        break :params b[oid.content_end..p.content_end];
    } else null;

    const bits_start = alg.content_end;
    const bits = nextField(b, bits_start, spki.content_end) orelse return error.MalformedSubjectPublicKeyInfo;
    if (b[bits_start] != 0x03) return error.MalformedSubjectPublicKeyInfo; // BIT STRING
    if (bits.content_end != spki.content_end) return error.MalformedSubjectPublicKeyInfo; // exactly two fields
    if (bits.content_end == bits.content_start) return error.MalformedSubjectPublicKeyInfo; // no unused-bits octet
    if (b[bits.content_start] != 0) return error.MalformedSubjectPublicKeyInfo; // must be whole octets

    return .{
        .der = b[spki_start..spki.content_end],
        .algorithm_oid = b[oid.content_start..oid.content_end],
        .parameters = parameters,
        .key_bits = b[bits.content_start + 1 .. bits.content_end],
    };
}

// ── tests ───────────────────────────────────────────────────────────────────
//
// The bar here is the union of what the three modules that used to carry their
// own guard did — every-prefix and every-single-byte-mutation sweeps of a real
// certificate (from `opcua`), a `std.testing.fuzz` walk (from `iec62351`), and
// explicit hostile shapes — plus a regression test pinned to the exact std
// hazard this module exists to neutralise.

const testing = std.testing;
const fixtures = @import("fixtures_test.zig");

test "validate: a real certificate is well-formed" {
    try validate(&fixtures.leaf_rsa);
    try validateCertificate(&fixtures.leaf_rsa);
}

test "validate: empty and one-byte inputs are typed errors" {
    try testing.expectError(error.Empty, validate(""));
    try testing.expectError(error.Empty, validateCertificate(""));
    try testing.expectError(error.Truncated, validate(&.{0x30}));
    try testing.expectError(error.Truncated, validateCertificate(&.{0x30}));
}

test "validate: explicit hostile shapes each map to the right typed error" {
    // A length that overruns its container.
    try testing.expectError(error.LengthOverrun, validate(&.{ 0x30, 0x05, 0x02, 0x01, 0x00 }));
    // Truncated length: long form promises one octet that is not there.
    try testing.expectError(error.Truncated, validate(&.{ 0x30, 0x81 }));
    // A length-of-length that itself overruns the buffer (says 4 octets, has 1).
    try testing.expectError(error.Truncated, validate(&.{ 0x30, 0x84, 0xff }));
    // Indefinite length (BER only).
    try testing.expectError(error.IndefiniteLength, validate(&.{ 0x30, 0x80, 0x00, 0x00 }));
    // Length-of-length beyond four octets.
    try testing.expectError(error.LengthTooLarge, validate(&.{ 0x30, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00 }));
    // High-tag-number identifier.
    try testing.expectError(error.MultiByteTag, validate(&.{ 0x1f, 0x01, 0x00 }));
    // A four-gigabyte SEQUENCE header with no content: the length octets are
    // all present (not truncated), but the declared length overruns.
    try testing.expectError(error.LengthOverrun, validate(&.{ 0x30, 0x84, 0xff, 0xff, 0xff, 0xff }));
    // Well-formed but not a certificate shape.
    try testing.expectError(error.NotCertificate, validateCertificate(&.{ 0x02, 0x01, 0x00 }));
    // A trailing byte past the outer SEQUENCE.
    try testing.expectError(error.NotCertificate, validateCertificate(&.{ 0x30, 0x00, 0x00 }));
}

test "validate: nesting past the depth bound is a typed error" {
    // Build `max_depth + 1` nested SEQUENCEs from the inside out, each two
    // bytes of header around the next; the innermost is an empty SEQUENCE.
    const levels = max_depth + 1;
    var nested: [2 * (max_depth + 1)]u8 = undefined;
    var content_len: usize = 0;
    var idx = nested.len;
    for (0..levels) |_| {
        idx -= 1;
        nested[idx] = @intCast(content_len); // length (always < 0x80 here)
        idx -= 1;
        nested[idx] = 0x30; // SEQUENCE tag
        content_len += 2; // this element is now the content of the next one out
    }
    try testing.expectError(error.MaxDepthExceeded, validate(nested[idx..]));
}

test "safeCertificate: a real certificate round-trips and parses" {
    var scratch: [max_certificate_len + parse_slack]u8 = undefined;
    const cert = try safeCertificate(&fixtures.leaf_rsa, &scratch);
    _ = try cert.parse();
}

test "safeCertificate: guard length and scratch preconditions" {
    var small: [4]u8 = undefined;
    try testing.expectError(error.ScratchTooSmall, safeCertificate(&fixtures.leaf_rsa, &small));
    try testing.expectError(error.Empty, safeCertificate("", &small));
    var scratch: [max_certificate_len + parse_slack]u8 = undefined;
    const huge = [_]u8{0x30} ** (max_certificate_len + 1);
    try testing.expectError(error.TooLarge, safeCertificate(&huge, &scratch));
}

test "hostile: every prefix of a real certificate is a typed error, never a panic" {
    var scratch: [max_certificate_len + parse_slack]u8 = undefined;
    const cert = &fixtures.leaf_rsa;
    // The genuine article works — this test is not vacuous.
    _ = try safeCertificate(cert, &scratch);
    for (0..cert.len) |cut| {
        // A strict prefix can never be a SEQUENCE that fills its own buffer,
        // so it is always rejected. The exact error varies with where the cut
        // falls (Truncated / LengthOverrun / NotCertificate); the load-bearing
        // property is that it is *a typed error*, never an abort.
        if (validateCertificate(cert[0..cut])) |_| try testing.expect(false) else |_| {}
        if (safeCertificate(cert[0..cut], &scratch)) |_| try testing.expect(false) else |_| {}
    }
}

test "hostile: every single-byte mutation of a real certificate never panics" {
    var scratch: [max_certificate_len + parse_slack]u8 = undefined;
    const mutant = try testing.allocator.dupe(u8, &fixtures.leaf_rsa);
    defer testing.allocator.free(mutant);
    for (0..mutant.len) |i| {
        for ([_]u8{ 0x00, 0x01, 0x7f, 0x80, 0xff }) |v| {
            const original = mutant[i];
            mutant[i] = v;
            // Whatever the verdict, it is Ok-and-parses or a typed error —
            // never an abort or an out-of-bounds read.
            if (safeCertificate(mutant, &scratch)) |cert| {
                if (cert.parse()) |_| {} else |_| {}
            } else |_| {}
            mutant[i] = original;
        }
    }
}

test "regression: the std hazard is neutralised (verified panic out of band)" {
    // `30 02 30 00` is `SEQUENCE { SEQUENCE {} }`: well-formed DER, but a
    // certificate with an empty tbsCertificate. Handed to the RAW parser it
    // panics on this exact Zig version —
    //
    //   var c: std.crypto.Certificate = .{ .buffer = &.{0x30,0x02,0x30,0x00}, .index = 0 };
    //   _ = try c.parse();  // Debug: `index out of bounds: index 4, len 4`
    //                       //        at std/crypto/Certificate.zig; ReleaseFast:
    //                       //        silent out-of-bounds read.
    //
    // (Reproduced out of band — it is deliberately NOT called here because it
    // would abort the test binary. See SPEC.md.) Routed through the guard it is
    // a clean typed error in every optimisation mode.
    const hostile: []const u8 = &.{ 0x30, 0x02, 0x30, 0x00 };
    // The input is well-formed and certificate-shaped: the guard does not
    // reject it structurally...
    try validateCertificate(hostile);
    // ...but the validated, padded copy makes std's parse total: it now
    // reaches a clean typed error instead of walking off the end.
    var scratch: [max_certificate_len + parse_slack]u8 = undefined;
    const cert = try safeCertificate(hostile, &scratch);
    try testing.expectError(error.CertificateFieldHasWrongDataType, cert.parse());
}

// ── spkiOf ──────────────────────────────────────────────────────────────────

const rsa = @import("rsa");

/// Oracle for the walk: std's own field walk, reached through the guard so it
/// cannot panic. `Parsed.pubKey()` is the BIT STRING content std lands on —
/// which must be byte-identical to what `spkiOf` reports as `key_bits`, even
/// though the two walks share no code.
fn stdPubKey(cert_der: []const u8, scratch: []u8) ![]const u8 {
    const cert = try safeCertificate(cert_der, scratch);
    const parsed = try cert.parse();
    return parsed.pubKey();
}

test "spkiOf: agrees with std's own walk on every std-parsable fixture" {
    var scratch: [max_certificate_len + parse_slack]u8 = undefined;
    inline for (.{
        "root_rsa",    "inter_rsa",   "leaf_rsa",   "subleaf_rsa",
        "root_ec256",  "inter_ec256", "leaf_ec256", "root_ec384",
        "inter_ec384", "leaf_ec384",  "root_ed",    "inter_ed",
        "leaf_ed",
    }) |name| {
        const cert_der = &@field(fixtures, name);
        const spki = try spkiOf(cert_der);
        try testing.expectEqualSlices(u8, try stdPubKey(cert_der, &scratch), spki.key_bits);
        // The reported TLV really is a sub-slice of the caller's buffer (the
        // documented borrowing contract) and really is a SEQUENCE.
        try testing.expect(@intFromPtr(spki.der.ptr) >= @intFromPtr(cert_der.ptr));
        try testing.expect(@intFromPtr(spki.der.ptr) + spki.der.len <= @intFromPtr(cert_der.ptr) + cert_der.len);
        try testing.expectEqual(@as(u8, 0x30), spki.der[0]);
    }
}

test "spkiOf: RSA fixture yields a SPKI rsa.PublicKey.fromDer accepts" {
    const spki = try spkiOf(&fixtures.leaf_rsa);
    try testing.expect(spki.algorithmIs(&oid_rsa_encryption));
    try testing.expectEqual(@as(?[]const u8, null), spki.namedCurveOid());
    const pk = try rsa.PublicKey.fromDer(spki.der);
    try testing.expectEqual(@as(usize, 2048), pk.n.bits());
    // Same key, reached the other way: the BIT STRING content is the bare
    // PKCS#1 RSAPublicKey.
    const pk2 = try rsa.PublicKey.fromDer(spki.key_bits);
    try testing.expectEqual(pk.n.bits(), pk2.n.bits());
}

test "spkiOf: EC fixtures report the right named curve; Ed25519 reports none" {
    const p256 = try spkiOf(&fixtures.leaf_ec256);
    try testing.expect(p256.algorithmIs(&oid_ec_public_key));
    try testing.expectEqualSlices(u8, &oid_prime256v1, p256.namedCurveOid().?);
    try testing.expectEqual(@as(u8, 0x04), p256.key_bits[0]); // uncompressed SEC1
    try testing.expectEqual(@as(usize, 65), p256.key_bits.len);
    // The extracted point is a real curve point, not just the right length.
    _ = try std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey.fromSec1(p256.key_bits);

    const p384 = try spkiOf(&fixtures.leaf_ec384);
    try testing.expectEqualSlices(u8, &oid_secp384r1, p384.namedCurveOid().?);

    const ed = try spkiOf(&fixtures.leaf_ed);
    try testing.expect(ed.algorithmIs(&oid_ed25519));
    try testing.expectEqual(@as(?[]const u8, null), ed.parameters); // no AlgorithmIdentifier parameters at all
    try testing.expectEqual(@as(usize, 32), ed.key_bits.len);
}

test "spkiOf: works on RSASSA-PSS certificates, which std cannot parse at all" {
    // The whole reason this is not built on `Certificate.parse`: std rejects a
    // PSS-signed certificate outright (`CertificateHasUnrecognizedObjectId`)
    // before yielding anything, yet its SubjectPublicKeyInfo is a wholly
    // separate, perfectly ordinary field.
    var scratch: [max_certificate_len + parse_slack]u8 = undefined;
    const cert = try safeCertificate(&fixtures.inter_pss, &scratch);
    try testing.expectError(error.CertificateHasUnrecognizedObjectId, cert.parse());

    inline for (.{ "root_pss", "inter_pss", "leaf_pss" }) |name| {
        const spki = try spkiOf(&@field(fixtures, name));
        try testing.expect(spki.key_bits.len > 0);
        try testing.expectEqual(@as(u8, 0x30), spki.der[0]);
    }
}

test "spkiOf: hostile input — every prefix of a real certificate is a typed error, never a panic" {
    // Item 4 of the verify gate: run in Debug, where the std panic this module
    // exists to avoid would fire.
    inline for (.{ "leaf_rsa", "leaf_ec256", "leaf_pss" }) |name| {
        const cert = &@field(fixtures, name);
        _ = try spkiOf(cert); // not vacuous: the genuine article works
        for (0..cert.len) |cut| {
            // A strict prefix is never a SEQUENCE that fills its own buffer.
            if (spkiOf(cert[0..cut])) |_| try testing.expect(false) else |_| {}
        }
    }
}

test "spkiOf: hostile input — every single-byte mutation is a typed error or a clean result" {
    const mutant = try testing.allocator.dupe(u8, &fixtures.leaf_ec256);
    defer testing.allocator.free(mutant);
    for (0..mutant.len) |i| {
        for ([_]u8{ 0x00, 0x01, 0x03, 0x30, 0x7f, 0x80, 0xa0, 0xff }) |v| {
            const original = mutant[i];
            mutant[i] = v;
            if (spkiOf(mutant)) |spki| {
                // Whatever it found must still lie inside the input buffer.
                try testing.expect(@intFromPtr(spki.der.ptr) >= @intFromPtr(mutant.ptr));
                try testing.expect(@intFromPtr(spki.der.ptr) + spki.der.len <= @intFromPtr(mutant.ptr) + mutant.len);
                _ = spki.namedCurveOid();
                _ = rsa.PublicKey.fromDer(spki.der) catch {};
                _ = std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey.fromSec1(spki.key_bits) catch {};
            } else |_| {}
            mutant[i] = original;
        }
    }
}

test "spkiOf: shapes that are well-formed DER but not a certificate fail closed" {
    // `SEQUENCE { SEQUENCE {} }` — the exact shape that walks std's parser off
    // the end of the buffer. Here it simply runs out of TBSCertificate fields.
    try testing.expectError(error.MalformedTbsCertificate, spkiOf(&.{ 0x30, 0x02, 0x30, 0x00 }));
    // Not a certificate at all.
    try testing.expectError(error.NotCertificate, spkiOf(&.{ 0x02, 0x01, 0x00 }));
    // Certificate-shaped with only five TBS fields (serialNumber .. subject):
    // no subjectPublicKeyInfo follows at all.
    const five = [_]u8{ 0x30, 0x0c, 0x30, 0x0a } ++ [_]u8{ 0x02, 0x00 } ** 5;
    try testing.expectError(error.MalformedTbsCertificate, spkiOf(&five));
    // Six TBS fields, so a subjectPublicKeyInfo slot exists — but it holds an
    // INTEGER rather than a SEQUENCE.
    const six = [_]u8{ 0x30, 0x0e, 0x30, 0x0c } ++ [_]u8{ 0x02, 0x00 } ** 6;
    try testing.expectError(error.MalformedSubjectPublicKeyInfo, spkiOf(&six));
}

test "spkiOf: a BIT STRING with unused bits is rejected rather than silently truncated" {
    // Flip the leaf's subjectPublicKey unused-bits octet from 0 to 1: the key
    // is no longer whole octets, so it must not be handed on as if it were.
    const mutant = try testing.allocator.dupe(u8, &fixtures.leaf_ec256);
    defer testing.allocator.free(mutant);
    const good = try spkiOf(mutant);
    const unused_bits_index = (@intFromPtr(good.key_bits.ptr) - @intFromPtr(mutant.ptr)) - 1;
    mutant[unused_bits_index] = 1;
    try testing.expectError(error.MalformedSubjectPublicKeyInfo, spkiOf(mutant));
}

test "fuzz: arbitrary bytes through spkiOf never panic" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            var buf: [1024]u8 = undefined;
            smith.bytes(&buf);
            const n: usize = smith.valueRangeAtMost(u16, 0, buf.len);
            if (spkiOf(buf[0..n])) |spki| {
                _ = spki.namedCurveOid();
                _ = spki.algorithmIs(&oid_rsa_encryption);
                _ = rsa.PublicKey.fromDer(spki.der) catch {};
                _ = std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey.fromSec1(spki.key_bits) catch {};
            } else |_| {}
        }
    }.run, .{});
}

test "fuzz: arbitrary bytes through the validator and the safe parser never panic" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            var buf: [1024]u8 = undefined;
            smith.bytes(&buf);
            const n: usize = smith.valueRangeAtMost(u16, 0, buf.len);
            const input = buf[0..n];
            // The validator must be total on arbitrary bytes.
            validate(input) catch {};
            validateCertificate(input) catch {};
            // And the safe parser: validate → pad → parse, never a crash.
            var scratch: [max_certificate_len + parse_slack]u8 = undefined;
            if (n <= max_certificate_len) {
                if (safeCertificate(input, &scratch)) |cert| {
                    if (cert.parse()) |_| {} else |_| {}
                } else |_| {}
            }
        }
    }.run, .{});
}
