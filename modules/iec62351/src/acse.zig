// SPDX-License-Identifier: MIT

//! IEC 62351-4 — authentication for the MMS (ISO 9506) application profile.
//!
//! ## What this file does and does not touch
//!
//! IEC 62351-4 splits into a **T-profile** and an **A-profile**:
//!
//! - **T-profile (transport).** TLS under the MMS connection, on port 3782
//!   rather than the plain-text 102. That is a policy over a TLS session, not
//!   a protocol of its own, and it lives in `tlsprofile.zig` (IEC 62351-3),
//!   which `iec62351-4` normatively references.
//! - **A-profile (application).** Peer authentication at the ACSE association
//!   layer: the AARQ carries `sender-acse-requirements`, a `mechanism-name`
//!   OID, and a `calling-authentication-value`; the AARE answers with the
//!   `responder-*` counterparts. **That is what this file implements.**
//!
//! **ACSE itself is not reimplemented here.** The caller owns the AARQ/AARE
//! bytes — from `iec61850`'s MMS client, from a capture, from anywhere — and
//! this file only *finds*, *builds* and *splices* the three authentication
//! fields inside them. The shape expected of those bytes is written down
//! precisely below, and every departure from it is a typed error rather than
//! a misparse.
//!
//! ## The PDU shape this file expects
//!
//! ```text
//! AARQ-apdu ::= [APPLICATION 0] IMPLICIT SEQUENCE {   -- identifier 0x60
//!     protocol-version              [0] IMPLICIT BIT STRING OPTIONAL,
//!     application-context-name      [1],
//!     ...
//!     sender-acse-requirements      [10] IMPLICIT BIT STRING OPTIONAL,  -- 0x8a
//!     mechanism-name                [11] IMPLICIT OBJECT IDENTIFIER OPTIONAL, -- 0x8b
//!     calling-authentication-value  [12] EXPLICIT Authentication-value OPTIONAL, -- 0xac
//!     ...
//!     user-information              [30] ...
//! }
//! AARE-apdu ::= [APPLICATION 1] IMPLICIT SEQUENCE { ... }             -- 0x61
//!     -- responder-acse-requirements / mechanism-name /
//!     -- responding-authentication-value carry the same [10]/[11]/[12] tags.
//!
//! Authentication-value ::= CHOICE {
//!     charstring  [0] IMPLICIT GraphicString,   -- 0x80
//!     bitstring   [1] IMPLICIT BIT STRING,      -- 0x81
//!     external    [2] IMPLICIT EXTERNAL,        -- 0xa2
//!     other       [3] IMPLICIT SEQUENCE {       -- 0xa3
//!         other-mechanism-name  OBJECT IDENTIFIER,
//!         other-mechanism-value ANY }
//! }
//! ```
//!
//! `[12]` is **EXPLICIT** (constructed, `0xac`) because `Authentication-value`
//! is a CHOICE — a CHOICE cannot be implicitly tagged. Reading it as implicit
//! is the single most common way to get this wrong: the outer octet then
//! looks like a `charstring` whose content is the real element's header.
//! `parseAuthValue` therefore requires the explicit wrapper and rejects a bare
//! alternative.
//!
//! ## Mechanism names
//!
//! `mechanism_password_1` (`2.2.3.1`, the ACSE `password-1` mechanism of
//! ISO 8650-1) is the well-known, publicly specified OID that MMS deployments
//! actually use for the A-profile password mechanism, and it is provided as a
//! constant. IEC 62351-4's own mechanism OIDs live under the IEC arc and their
//! exact leaves are not reproduced in publicly available material; only the
//! **arc** (`1.0.62351.4`) is provided, clearly flagged, and any OID at all
//! can be supplied through `MechanismName.custom`. Nothing here pretends to a
//! registration it cannot cite.
//!
//! ## The signed token
//!
//! `SignedToken` is **this module's own encoding**, not a reproduction of the
//! standard's: the exact ASN.1 of the 62351-4 signed authentication value is
//! paywalled. It is a small, canonical, replay-resistant structure that rides
//! in the `other` alternative, and it exists so that "a signed token in the
//! authentication-value" is something you can build, verify and test rather
//! than a sentence in a document. A deployment that must interoperate with a
//! specific vendor supplies that vendor's bytes through
//! `AuthValue.external`/`AuthValue.other` instead — the seam is there
//! precisely because this part is modelled.

const std = @import("std");
const rsa = @import("rsa");
const ber = @import("ber.zig");

const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

// ── tags ────────────────────────────────────────────────────────────────────

pub const tag = struct {
    pub const aarq: u8 = 0x60;
    pub const aare: u8 = 0x61;
    /// `[10] IMPLICIT BIT STRING` — sender-/responder-acse-requirements.
    pub const acse_requirements: u8 = 0x8a;
    /// `[11] IMPLICIT OBJECT IDENTIFIER` — mechanism-name.
    pub const mechanism_name: u8 = 0x8b;
    /// `[12] EXPLICIT Authentication-value` — calling-/responding-.
    pub const authentication_value: u8 = 0xac;

    /// `Authentication-value` CHOICE alternatives.
    pub const av_charstring: u8 = 0x80;
    pub const av_bitstring: u8 = 0x81;
    pub const av_external: u8 = 0xa2;
    pub const av_other: u8 = 0xa3;

    pub const oid: u8 = 0x06;
    pub const sequence: u8 = 0x30;
};

/// Which APDU is being handled. The authentication field tags are identical
/// in both; only the outer identifier and the field *names* differ.
pub const PduKind = enum {
    aarq,
    aare,

    pub fn identifier(k: PduKind) u8 {
        return switch (k) {
            .aarq => tag.aarq,
            .aare => tag.aare,
        };
    }
};

// ── mechanism names ─────────────────────────────────────────────────────────

/// ACSE `password-1` — `{joint-iso-itu-t(2) association-control(2)
/// authentication-mechanism(3) password-1(1)}`, i.e. OID 2.2.3.1, encoded as
/// DER OBJECT IDENTIFIER *content* octets (no tag, no length). Specified by
/// ISO 8650-1 / ITU-T X.227 and used by MMS for the password mechanism.
pub const mechanism_password_1 = [_]u8{ 0x52, 0x03, 0x01 };

/// The IEC 62351-4 OID **arc**, `{iso(1) standard(0) 62351 4}` = 1.0.62351.4,
/// as DER content octets.
///
/// **This is an arc, not a mechanism.** The leaf identifying a specific
/// 62351-4 authentication mechanism is defined in the paywalled standard and
/// is deliberately not guessed here. Use `MechanismName.custom` with the OID
/// your peer actually sends.
pub const arc_iec62351_4 = [_]u8{ 0x28, 0x83, 0xe7, 0x0f, 0x04 };

pub const MechanismName = union(enum) {
    /// ACSE password-1 (2.2.3.1).
    password_1,
    /// Any OID, as DER content octets.
    custom: []const u8,

    pub fn bytes(m: MechanismName) []const u8 {
        return switch (m) {
            .password_1 => &mechanism_password_1,
            .custom => |b| b,
        };
    }
};

// ── acse-requirements ───────────────────────────────────────────────────────

/// The `ACSE-requirements` BIT STRING (ISO 8650-1): bit 0 `authentication`,
/// bit 1 `application-context-negotiation`.
pub const AcseRequirements = struct {
    authentication: bool = false,
    application_context_negotiation: bool = false,

    pub const BitStringError = error{InvalidBitString};

    /// Decode from the `[10]` element's content (a BIT STRING body: an
    /// unused-bit count followed by the bits).
    pub fn parse(content: []const u8) BitStringError!AcseRequirements {
        if (content.len == 0) return error.InvalidBitString;
        const unused = content[0];
        if (unused > 7) return error.InvalidBitString;
        const bits = content[1..];
        if (bits.len == 0) return .{};
        if (bits.len > 1 and unused != 0) {
            // Only the final octet may have unused bits; a longer body is
            // still legal, just not something this profile emits.
        }
        const b = bits[0];
        const bitAt = struct {
            fn get(byte: u8, n: u3, unused_bits: u8, only_octet: bool) bool {
                if (only_octet and (7 - @as(u8, n)) < unused_bits) return false;
                return byte & (@as(u8, 0x80) >> n) != 0;
            }
        }.get;
        return .{
            .authentication = bitAt(b, 0, unused, bits.len == 1),
            .application_context_negotiation = bitAt(b, 1, unused, bits.len == 1),
        };
    }

    /// Encode as a BIT STRING body (unused-bit count + one octet), minimally.
    pub fn encode(r: AcseRequirements, out: *[2]u8) []u8 {
        var b: u8 = 0;
        if (r.authentication) b |= 0x80;
        if (r.application_context_negotiation) b |= 0x40;
        if (b == 0) {
            out[0] = 0;
            return out[0..1];
        }
        out[0] = @ctz(b);
        out[1] = b;
        return out[0..2];
    }
};

// ── authentication-value ────────────────────────────────────────────────────

pub const BitStringView = struct {
    unused_bits: u8,
    bits: []const u8,
};

pub const Other = struct {
    /// `other-mechanism-name`, DER OID content octets.
    mechanism: []const u8,
    /// `other-mechanism-value`, the whole encoded element (tag included) —
    /// it is an open `ANY` type, so it is handed over unmodified.
    value: []const u8,
};

/// One alternative of the `Authentication-value` CHOICE. All slices borrow
/// from the caller's buffer.
pub const AuthValue = union(enum) {
    /// `[0] IMPLICIT GraphicString` — the plain password mechanism.
    charstring: []const u8,
    /// `[1] IMPLICIT BIT STRING`.
    bitstring: BitStringView,
    /// `[2] IMPLICIT EXTERNAL` — content octets, handed over unmodified.
    external: []const u8,
    /// `[3] IMPLICIT SEQUENCE { mechanism, value }`.
    other: Other,

    pub fn alternativeTag(v: AuthValue) u8 {
        return switch (v) {
            .charstring => tag.av_charstring,
            .bitstring => tag.av_bitstring,
            .external => tag.av_external,
            .other => tag.av_other,
        };
    }
};

pub const ParseError = ber.Error || AcseRequirements.BitStringError || error{
    /// The outer identifier was not the AARQ/AARE the caller asked for.
    NotAnAssociationPdu,
    /// `[12]` was not the constructed, explicit wrapper the CHOICE requires,
    /// or its content was not exactly one element.
    MalformedAuthenticationValue,
    /// The alternative tag inside `[12]` is not one of the four the CHOICE
    /// defines.
    UnknownAuthenticationAlternative,
    /// A `[3] other` value did not contain an OID followed by a value.
    MalformedOtherMechanism,
};

/// The three authentication fields, located inside a caller-owned PDU.
/// `*_slice` members are the whole encoded elements, so a caller can strip or
/// re-emit them byte-for-byte.
pub const AuthFields = struct {
    kind: PduKind,
    requirements: ?AcseRequirements = null,
    requirements_slice: ?[]const u8 = null,
    /// DER OID content octets of `mechanism-name`.
    mechanism_name: ?[]const u8 = null,
    mechanism_name_slice: ?[]const u8 = null,
    value: ?AuthValue = null,
    value_slice: ?[]const u8 = null,

    /// True when the peer actually asserted authentication (the requirements
    /// bit is set *and* a value is present). Both halves matter: a
    /// `mechanism-name` with no value, or a value with the bit clear, is a
    /// malformed assertion that some stacks accept.
    pub fn assertsAuthentication(f: AuthFields) bool {
        const r = f.requirements orelse return false;
        return r.authentication and f.value != null;
    }
};

/// Locate the authentication fields inside an AARQ or AARE. `bytes` is the
/// whole APDU, starting at its `[APPLICATION n]` identifier.
pub fn findAuthFields(bytes: []const u8, kind: PduKind) ParseError!AuthFields {
    const outer = try ber.read(bytes);
    if (outer.tag != kind.identifier()) return error.NotAnAssociationPdu;

    var fields: AuthFields = .{ .kind = kind };
    var it = ber.iterate(outer.content);
    var offset: usize = 0;
    while (try it.next()) |e| {
        const whole = outer.content[offset..][0..e.encoded_len];
        offset = it.pos;
        switch (e.tag) {
            tag.acse_requirements => {
                fields.requirements = try AcseRequirements.parse(e.content);
                fields.requirements_slice = whole;
            },
            tag.mechanism_name => {
                fields.mechanism_name = e.content;
                fields.mechanism_name_slice = whole;
            },
            tag.authentication_value => {
                fields.value = try parseAuthValue(e);
                fields.value_slice = whole;
            },
            else => {},
        }
    }
    return fields;
}

/// Decode the `[12] EXPLICIT Authentication-value` element.
pub fn parseAuthValue(element: ber.Element) ParseError!AuthValue {
    if (!element.isConstructed()) return error.MalformedAuthenticationValue;
    const inner = try ber.read(element.content);
    if (inner.encoded_len != element.content.len) return error.MalformedAuthenticationValue;
    return switch (inner.tag) {
        tag.av_charstring => .{ .charstring = inner.content },
        tag.av_bitstring => blk: {
            if (inner.content.len == 0) break :blk error.MalformedAuthenticationValue;
            break :blk .{ .bitstring = .{ .unused_bits = inner.content[0], .bits = inner.content[1..] } };
        },
        tag.av_external => .{ .external = inner.content },
        tag.av_other => blk: {
            const oid = try ber.readTagged(inner.content, tag.oid);
            if (oid.encoded_len >= inner.content.len) break :blk error.MalformedOtherMechanism;
            const value = inner.content[oid.encoded_len..];
            const value_elem = try ber.read(value);
            if (value_elem.encoded_len != value.len) break :blk error.MalformedOtherMechanism;
            break :blk .{ .other = .{ .mechanism = oid.content, .value = value } };
        },
        else => error.UnknownAuthenticationAlternative,
    };
}

// ── building the fields ─────────────────────────────────────────────────────

pub const BuildParams = struct {
    requirements: AcseRequirements = .{ .authentication = true },
    mechanism: ?MechanismName = null,
    value: ?AuthValue = null,
};

/// Encode `[10]`, `[11]` and `[12]` back to back into `out`, in the ascending
/// tag order ACSE requires, and return the written slice. The caller splices
/// the result into its own AARQ/AARE (or uses `insertAuthFields`, which does
/// exactly that).
pub fn buildAuthFields(out: []u8, params: BuildParams) ber.Error![]u8 {
    var n: usize = 0;

    var req_buf: [2]u8 = undefined;
    const req = params.requirements.encode(&req_buf);
    n += (try ber.writeElement(out[n..], tag.acse_requirements, req)).len;

    if (params.mechanism) |m| {
        n += (try ber.writeElement(out[n..], tag.mechanism_name, m.bytes())).len;
    }
    if (params.value) |v| {
        n += (try writeAuthValue(out[n..], v)).len;
    }
    return out[0..n];
}

/// Encode a single `[12] EXPLICIT Authentication-value`.
pub fn writeAuthValue(out: []u8, v: AuthValue) ber.Error![]u8 {
    // Inner alternative first, into a scratch region at the end of `out`, so
    // the explicit wrapper's length is known before it is written.
    var scratch: [512]u8 = undefined;
    const inner: []const u8 = switch (v) {
        .charstring => |s| try ber.writeElement(&scratch, tag.av_charstring, s),
        .bitstring => |bs| blk: {
            if (1 + bs.bits.len > scratch.len) return error.BufferTooSmall;
            var body: [256]u8 = undefined;
            if (1 + bs.bits.len > body.len) return error.BufferTooSmall;
            body[0] = bs.unused_bits;
            @memcpy(body[1..][0..bs.bits.len], bs.bits);
            break :blk try ber.writeElement(&scratch, tag.av_bitstring, body[0 .. 1 + bs.bits.len]);
        },
        .external => |s| try ber.writeElement(&scratch, tag.av_external, s),
        .other => |o| blk: {
            var body: [512]u8 = undefined;
            const oid = try ber.writeElement(&body, tag.oid, o.mechanism);
            if (oid.len + o.value.len > body.len) return error.BufferTooSmall;
            @memcpy(body[oid.len..][0..o.value.len], o.value);
            break :blk try ber.writeElement(&scratch, tag.av_other, body[0 .. oid.len + o.value.len]);
        },
    };
    return ber.writeElement(out, tag.authentication_value, inner);
}

pub const InsertError = ParseError || ber.Error;

/// Rewrite `pdu` into `out` with the authentication fields replaced by
/// `fields` (the encoded output of `buildAuthFields`).
///
/// Any existing `[10]`/`[11]`/`[12]` elements are dropped, the new ones are
/// inserted so the child tags stay in ascending order, and the outer
/// `[APPLICATION n]` length is recomputed. Every other element is copied
/// byte-for-byte — this is a splice, not a re-encode, so a field this module
/// does not model cannot be corrupted by passing through it.
pub fn insertAuthFields(out: []u8, pdu: []const u8, kind: PduKind, fields: []const u8) InsertError![]u8 {
    const outer = try ber.read(pdu);
    if (outer.tag != kind.identifier()) return error.NotAnAssociationPdu;

    // Pass 1: measure.
    var body_len: usize = fields.len;
    {
        var it = ber.iterate(outer.content);
        while (try it.next()) |e| {
            if (isAuthTag(e.tag)) continue;
            body_len += e.encoded_len;
        }
    }
    const total = ber.encodedSize(body_len);
    if (out.len < total) return error.BufferTooSmall;

    // Pass 2: emit, inserting the new fields at the first child whose tag
    // sorts after [12] (or at the end).
    var w = try ber.writeHeader(out, outer.tag, body_len);
    var inserted = false;
    var it = ber.iterate(outer.content);
    var offset: usize = 0;
    while (try it.next()) |e| {
        const whole = outer.content[offset..][0..e.encoded_len];
        offset = it.pos;
        if (isAuthTag(e.tag)) continue;
        if (!inserted and sortsAfterAuth(e.tag)) {
            @memcpy(out[w..][0..fields.len], fields);
            w += fields.len;
            inserted = true;
        }
        @memcpy(out[w..][0..whole.len], whole);
        w += whole.len;
    }
    if (!inserted) {
        @memcpy(out[w..][0..fields.len], fields);
        w += fields.len;
    }
    return out[0..w];
}

fn isAuthTag(t: u8) bool {
    return t == tag.acse_requirements or t == tag.mechanism_name or t == tag.authentication_value;
}

/// Context-specific tag numbers above 12 sort after the authentication
/// fields. Universal/application tags (none appear as direct AARQ children)
/// are treated as sorting after, so they never land before `[10]`.
fn sortsAfterAuth(t: u8) bool {
    if (t & 0xc0 != 0x80) return true; // not context-specific
    return (t & 0x1f) > 12;
}

// ── the signed token ────────────────────────────────────────────────────────

/// Algorithms `SignedToken` can be sealed with.
pub const TokenAlgorithm = enum {
    /// RSASSA-PSS with SHA-256 (RFC 8017), salt length = hash length.
    rsa_pss_sha256,
    /// ECDSA P-256 with SHA-256, fixed-width 64-octet (r‖s) signature.
    ecdsa_p256_sha256,
};

pub const token_tag = struct {
    pub const version: u8 = 0x80;
    pub const time: u8 = 0x81;
    pub const identity: u8 = 0x82;
    pub const signature: u8 = 0x83;
};

/// A time-stamped, signed assertion of identity, carried in the `other`
/// alternative of `Authentication-value`.
///
/// **Encoding defined by this module** (see the file header). Shape:
///
/// ```text
/// SignedToken ::= SEQUENCE {
///     version   [0] IMPLICIT INTEGER,       -- always 1
///     time      [1] IMPLICIT INTEGER,       -- seconds since the UTC epoch
///     identity  [2] IMPLICIT UTF8String,    -- the AP-title/user asserted
///     signature [3] IMPLICIT OCTET STRING }
/// ```
///
/// The signature covers `SEQUENCE { version, time, identity }` — the same
/// three elements, re-encoded as their own SEQUENCE. Recomputing rather than
/// slicing means a verifier can never be fooled by a re-encoded prefix.
pub const SignedToken = struct {
    version: u8 = 1,
    /// Seconds since the UTC epoch. Injected by the caller — this module owns
    /// no clock.
    time_s: u64,
    identity: []const u8,
    signature: []const u8,

    pub const version_current: u8 = 1;

    pub const Error = ber.Error || error{
        MalformedToken,
        /// The signature did not verify.
        SignatureInvalid,
        /// The token's time is outside the accepted freshness window.
        TokenExpired,
        /// The token's time is ahead of local time beyond the allowed skew.
        TokenFromTheFuture,
        /// `version` is not one this module understands.
        UnsupportedVersion,
        SigningFailed,
    };

    /// Encode the octets the signature covers.
    pub fn signingInput(out: []u8, version: u8, time_s: u64, identity: []const u8) ber.Error![]u8 {
        var body: [512]u8 = undefined;
        var n: usize = 0;
        n += (try ber.writeElement(body[n..], token_tag.version, &.{version})).len;
        var time_buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &time_buf, time_s, .big);
        n += (try ber.writeElement(body[n..], token_tag.time, &time_buf)).len;
        n += (try ber.writeElement(body[n..], token_tag.identity, identity)).len;
        return ber.writeElement(out, tag.sequence, body[0..n]);
    }

    /// Encode the whole token (the signing input's three elements plus the
    /// signature, in one SEQUENCE).
    pub fn encode(t: SignedToken, out: []u8) ber.Error![]u8 {
        var body: [768]u8 = undefined;
        var n: usize = 0;
        n += (try ber.writeElement(body[n..], token_tag.version, &.{t.version})).len;
        var time_buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &time_buf, t.time_s, .big);
        n += (try ber.writeElement(body[n..], token_tag.time, &time_buf)).len;
        n += (try ber.writeElement(body[n..], token_tag.identity, t.identity)).len;
        n += (try ber.writeElement(body[n..], token_tag.signature, t.signature)).len;
        return ber.writeElement(out, tag.sequence, body[0..n]);
    }

    pub fn parse(bytes: []const u8) Error!SignedToken {
        const seq = try ber.readTagged(bytes, tag.sequence);
        if (seq.encoded_len != bytes.len) return error.MalformedToken;
        var it = ber.iterate(seq.content);

        const v = (try it.next()) orelse return error.MalformedToken;
        if (v.tag != token_tag.version or v.content.len != 1) return error.MalformedToken;
        const tm = (try it.next()) orelse return error.MalformedToken;
        if (tm.tag != token_tag.time or tm.content.len != 8) return error.MalformedToken;
        const id = (try it.next()) orelse return error.MalformedToken;
        if (id.tag != token_tag.identity) return error.MalformedToken;
        const sig = (try it.next()) orelse return error.MalformedToken;
        if (sig.tag != token_tag.signature or sig.content.len == 0) return error.MalformedToken;
        if (try it.next() != null) return error.MalformedToken;

        return .{
            .version = v.content[0],
            .time_s = std.mem.readInt(u64, tm.content[0..8], .big),
            .identity = id.content,
            .signature = sig.content,
        };
    }
};

pub const Signer = union(enum) {
    rsa_pss_sha256: struct { key: rsa.SecretKey, random: std.Random },
    ecdsa_p256_sha256: struct { key_pair: EcdsaP256.KeyPair, noise: ?[EcdsaP256.noise_length]u8 = null },
};

pub const TokenVerifier = union(enum) {
    rsa_pss_sha256: rsa.PublicKey,
    ecdsa_p256_sha256: EcdsaP256.PublicKey,
};

/// Sign and encode a token into `out`. `sig_buf` receives the raw signature
/// (the token borrows from it, so it must outlive the returned slice's use).
pub fn signToken(
    out: []u8,
    sig_buf: []u8,
    signer: Signer,
    version: u8,
    time_s: u64,
    identity: []const u8,
) SignedToken.Error![]u8 {
    var input_buf: [768]u8 = undefined;
    const input = try SignedToken.signingInput(&input_buf, version, time_s, identity);
    const sig: []const u8 = switch (signer) {
        .rsa_pss_sha256 => |r| rsa.signPss(r.key, Sha256, r.random, input, Sha256.digest_length, sig_buf) catch
            return error.SigningFailed,
        .ecdsa_p256_sha256 => |e| blk: {
            const s = e.key_pair.sign(input, e.noise) catch return error.SigningFailed;
            const n = EcdsaP256.Signature.encoded_length;
            if (sig_buf.len < n) return error.BufferTooSmall;
            @memcpy(sig_buf[0..n], &s.toBytes());
            break :blk sig_buf[0..n];
        },
    };
    return (SignedToken{ .version = version, .time_s = time_s, .identity = identity, .signature = sig }).encode(out);
}

pub const FreshnessWindow = struct {
    /// How old a token may be.
    max_age_s: u64 = 60,
    /// How far ahead of local time it may be.
    max_skew_s: u64 = 5,
};

/// Verify a token's signature *and* its freshness. `now_s` is injected —
/// there is no clock here.
///
/// The freshness check is not optional and not separate: a signature alone
/// makes a captured AARQ replayable forever, which is the whole reason the
/// token carries a time in the first place.
pub fn verifyToken(
    bytes: []const u8,
    verifier: TokenVerifier,
    now_s: u64,
    window: FreshnessWindow,
) SignedToken.Error!SignedToken {
    const t = try SignedToken.parse(bytes);
    if (t.version != SignedToken.version_current) return error.UnsupportedVersion;

    var input_buf: [768]u8 = undefined;
    const input = try SignedToken.signingInput(&input_buf, t.version, t.time_s, t.identity);
    switch (verifier) {
        .rsa_pss_sha256 => |pk| rsa.verifyPss(pk, Sha256, input, t.signature, Sha256.digest_length) catch
            return error.SignatureInvalid,
        .ecdsa_p256_sha256 => |pk| {
            const n = EcdsaP256.Signature.encoded_length;
            if (t.signature.len != n) return error.SignatureInvalid;
            const s = EcdsaP256.Signature.fromBytes(t.signature[0..n].*);
            s.verify(input, pk) catch return error.SignatureInvalid;
        },
    }

    if (t.time_s > now_s +| window.max_skew_s) return error.TokenFromTheFuture;
    if (now_s -| t.time_s > window.max_age_s) return error.TokenExpired;
    return t;
}

/// Constant-time password comparison, for the `charstring` mechanism.
///
/// The A-profile password mechanism sends a shared secret in the clear inside
/// the AARQ; it is only meaningful under the T-profile's TLS. Comparing it
/// with `std.mem.eql` additionally leaks its length-prefix through timing, so
/// the comparison is done over a hash of both sides — which also removes the
/// length dependence.
pub fn passwordMatches(presented: []const u8, expected: []const u8) bool {
    var a: [Sha256.digest_length]u8 = undefined;
    var b: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(presented, &a, .{});
    Sha256.hash(expected, &b, .{});
    return std.crypto.timing_safe.eql([Sha256.digest_length]u8, a, b);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// A minimal but realistic AARQ: protocol-version [0], application-context-name
/// [1] (the MMS context 1.0.9506.2.3), and user-information [30]. No
/// authentication fields — those get spliced in by the tests.
const sample_aarq = [_]u8{
    0x60, 0x1c,
    0x80, 0x02, 0x07, 0x80, // [0] protocol-version BIT STRING
    0xa1, 0x07, 0x06, 0x05, 0x28, 0xca, 0x22, 0x02, 0x03, // [1] application-context-name
    0xbe, 0x0d, 0x28, 0x0b, 0x06, 0x02, 0x51, 0x01, 0xa0, 0x05, 0xa8, 0x03, 0x80, 0x01, 0x05, // [30] user-information
};

test "sample AARQ is well-formed for the reader" {
    const outer = try ber.read(&sample_aarq);
    try testing.expectEqual(tag.aarq, outer.tag);
    try testing.expectEqual(sample_aarq.len, outer.encoded_len);
    var it = ber.iterate(outer.content);
    var n: usize = 0;
    while (try it.next()) |_| n += 1;
    try testing.expectEqual(@as(usize, 3), n);
}

test "findAuthFields: absent fields are reported as absent, not defaulted" {
    const f = try findAuthFields(&sample_aarq, .aarq);
    try testing.expect(f.requirements == null);
    try testing.expect(f.mechanism_name == null);
    try testing.expect(f.value == null);
    try testing.expect(!f.assertsAuthentication());
}

test "findAuthFields: the wrong APDU kind is refused" {
    try testing.expectError(error.NotAnAssociationPdu, findAuthFields(&sample_aarq, .aare));
}

test "password mechanism: build, splice, find, round-trip" {
    var fields_buf: [128]u8 = undefined;
    const fields = try buildAuthFields(&fields_buf, .{
        .requirements = .{ .authentication = true },
        .mechanism = .password_1,
        .value = .{ .charstring = "SECRET" },
    });

    var pdu_buf: [256]u8 = undefined;
    const pdu = try insertAuthFields(&pdu_buf, &sample_aarq, .aarq, fields);

    const f = try findAuthFields(pdu, .aarq);
    try testing.expect(f.assertsAuthentication());
    try testing.expect(f.requirements.?.authentication);
    try testing.expect(!f.requirements.?.application_context_negotiation);
    try testing.expectEqualSlices(u8, &mechanism_password_1, f.mechanism_name.?);
    try testing.expectEqualSlices(u8, "SECRET", f.value.?.charstring);

    // The unrelated fields survived the splice byte-for-byte.
    const outer = try ber.read(pdu);
    var it = ber.iterate(outer.content);
    const v0 = (try it.next()).?;
    try testing.expectEqual(@as(u8, 0x80), v0.tag);
    try testing.expectEqualSlices(u8, &.{ 0x07, 0x80 }, v0.content);
}

test "insertAuthFields: existing authentication fields are replaced, order preserved" {
    var fields_buf: [128]u8 = undefined;
    const first = try buildAuthFields(&fields_buf, .{ .mechanism = .password_1, .value = .{ .charstring = "one" } });
    var pdu_a: [256]u8 = undefined;
    const a = try insertAuthFields(&pdu_a, &sample_aarq, .aarq, first);

    var fields_buf2: [128]u8 = undefined;
    const second = try buildAuthFields(&fields_buf2, .{ .mechanism = .password_1, .value = .{ .charstring = "two" } });
    var pdu_b: [256]u8 = undefined;
    const b = try insertAuthFields(&pdu_b, a, .aarq, second);

    const f = try findAuthFields(b, .aarq);
    try testing.expectEqualSlices(u8, "two", f.value.?.charstring);

    // Exactly one of each authentication tag, and [30] still last.
    const outer = try ber.read(b);
    var it = ber.iterate(outer.content);
    var tags: [8]u8 = undefined;
    var n: usize = 0;
    while (try it.next()) |e| {
        tags[n] = e.tag;
        n += 1;
    }
    try testing.expectEqualSlices(u8, &.{ 0x80, 0xa1, 0x8a, 0x8b, 0xac, 0xbe }, tags[0..n]);
}

test "the [12] wrapper is explicit: a bare alternative is rejected" {
    // Hand-build an AARQ whose [12] is primitive (implicit tagging), the
    // classic mistake.
    var pdu: [64]u8 = undefined;
    var body: [64]u8 = undefined;
    var n: usize = 0;
    n += (try ber.writeElement(body[n..], tag.acse_requirements, &.{ 0x07, 0x80 })).len;
    n += (try ber.writeElement(body[n..], 0x8c, "SECRET")).len; // [12] IMPLICIT — wrong
    const bad = try ber.writeElement(&pdu, tag.aarq, body[0..n]);

    const f = try findAuthFields(bad, .aarq);
    // Tag 0x8c is not 0xac, so it is simply not recognised as the field.
    try testing.expect(f.value == null);
    try testing.expect(!f.assertsAuthentication());

    // And a *constructed* [12] whose content is not exactly one element fails.
    var body2: [64]u8 = undefined;
    var m: usize = 0;
    m += (try ber.writeElement(body2[m..], tag.av_charstring, "a")).len;
    m += (try ber.writeElement(body2[m..], tag.av_charstring, "b")).len;
    var pdu2: [64]u8 = undefined;
    var outer_body: [64]u8 = undefined;
    const k = (try ber.writeElement(&outer_body, tag.authentication_value, body2[0..m])).len;
    const bad2 = try ber.writeElement(&pdu2, tag.aarq, outer_body[0..k]);
    try testing.expectError(error.MalformedAuthenticationValue, findAuthFields(bad2, .aarq));
}

test "all four Authentication-value alternatives round-trip" {
    var out: [256]u8 = undefined;
    const values = [_]AuthValue{
        .{ .charstring = "password" },
        .{ .bitstring = .{ .unused_bits = 3, .bits = &.{0xa8} } },
        .{ .external = &.{ 0x06, 0x02, 0x51, 0x01 } },
        .{ .other = .{ .mechanism = &arc_iec62351_4, .value = &.{ 0x04, 0x03, 1, 2, 3 } } },
    };
    for (values) |v| {
        const enc = try writeAuthValue(&out, v);
        const e = try ber.read(enc);
        try testing.expectEqual(tag.authentication_value, e.tag);
        const back = try parseAuthValue(e);
        try testing.expectEqual(v.alternativeTag(), back.alternativeTag());
        switch (back) {
            .charstring => |s| try testing.expectEqualSlices(u8, v.charstring, s),
            .bitstring => |bs| {
                try testing.expectEqual(v.bitstring.unused_bits, bs.unused_bits);
                try testing.expectEqualSlices(u8, v.bitstring.bits, bs.bits);
            },
            .external => |s| try testing.expectEqualSlices(u8, v.external, s),
            .other => |o| {
                try testing.expectEqualSlices(u8, v.other.mechanism, o.mechanism);
                try testing.expectEqualSlices(u8, v.other.value, o.value);
            },
        }
    }
}

test "an unknown CHOICE alternative is a typed error, not a guess" {
    var out: [64]u8 = undefined;
    var inner: [32]u8 = undefined;
    const i = try ber.writeElement(&inner, 0x87, "x"); // [7] — not a defined alternative
    const enc = try ber.writeElement(&out, tag.authentication_value, i);
    const e = try ber.read(enc);
    try testing.expectError(error.UnknownAuthenticationAlternative, parseAuthValue(e));
}

test "AcseRequirements: encode/parse round-trip" {
    const cases = [_]AcseRequirements{
        .{},
        .{ .authentication = true },
        .{ .application_context_negotiation = true },
        .{ .authentication = true, .application_context_negotiation = true },
    };
    for (cases) |c| {
        var buf: [2]u8 = undefined;
        const body = c.encode(&buf);
        const back = try AcseRequirements.parse(body);
        try testing.expectEqual(c.authentication, back.authentication);
        try testing.expectEqual(c.application_context_negotiation, back.application_context_negotiation);
    }
    try testing.expectError(error.InvalidBitString, AcseRequirements.parse(&.{}));
    try testing.expectError(error.InvalidBitString, AcseRequirements.parse(&.{ 0x09, 0x80 }));
}

test "assertsAuthentication needs both the bit and the value" {
    var fields_buf: [128]u8 = undefined;
    // Bit set, no value.
    {
        const fields = try buildAuthFields(&fields_buf, .{ .requirements = .{ .authentication = true } });
        var pdu_buf: [256]u8 = undefined;
        const pdu = try insertAuthFields(&pdu_buf, &sample_aarq, .aarq, fields);
        const f = try findAuthFields(pdu, .aarq);
        try testing.expect(!f.assertsAuthentication());
    }
    // Value present, bit clear.
    {
        const fields = try buildAuthFields(&fields_buf, .{
            .requirements = .{ .authentication = false },
            .value = .{ .charstring = "p" },
        });
        var pdu_buf: [256]u8 = undefined;
        const pdu = try insertAuthFields(&pdu_buf, &sample_aarq, .aarq, fields);
        const f = try findAuthFields(pdu, .aarq);
        try testing.expect(f.value != null);
        try testing.expect(!f.assertsAuthentication());
    }
}

test "passwordMatches is constant-time and length-independent in shape" {
    try testing.expect(passwordMatches("hunter2", "hunter2"));
    try testing.expect(!passwordMatches("hunter2", "hunter3"));
    try testing.expect(!passwordMatches("hunter2", "hunter22"));
    try testing.expect(!passwordMatches("", "x"));
    try testing.expect(passwordMatches("", ""));
}

// ── signed token ────────────────────────────────────────────────────────────

const keys = @import("test_keys.zig");
const test_now_s: u64 = 1_600_000_000;

test "signed token: RSASSA-PSS round-trip through the authentication-value" {
    var sk = try keys.rsa2048SecretKey();
    defer sk.deinit();
    const pk = try keys.rsa2048PublicKey();
    var prng = std.Random.DefaultPrng.init(0x4a4a);

    var sig_buf: [rsa.max_modulus_len]u8 = undefined;
    var token_buf: [768]u8 = undefined;
    const token = try signToken(&token_buf, &sig_buf, .{
        .rsa_pss_sha256 = .{ .key = sk, .random = prng.random() },
    }, 1, test_now_s, "substation-A/client1");

    // Wrapped in the `other` alternative, spliced into an AARQ, then found
    // and verified from the other side.
    var fields_buf: [1024]u8 = undefined;
    const fields = try buildAuthFields(&fields_buf, .{
        .mechanism = .{ .custom = &arc_iec62351_4 },
        .value = .{ .other = .{ .mechanism = &arc_iec62351_4, .value = token } },
    });
    var pdu_buf: [1536]u8 = undefined;
    const pdu = try insertAuthFields(&pdu_buf, &sample_aarq, .aarq, fields);

    const f = try findAuthFields(pdu, .aarq);
    const got = try verifyToken(f.value.?.other.value, .{ .rsa_pss_sha256 = pk }, test_now_s + 5, .{});
    try testing.expectEqualSlices(u8, "substation-A/client1", got.identity);
    try testing.expectEqual(test_now_s, got.time_s);
}

test "signed token: ECDSA round-trip" {
    const kp = try EcdsaP256.KeyPair.generateDeterministic([_]u8{0x21} ** EcdsaP256.KeyPair.seed_length);
    var sig_buf: [64]u8 = undefined;
    var token_buf: [512]u8 = undefined;
    const token = try signToken(&token_buf, &sig_buf, .{
        .ecdsa_p256_sha256 = .{ .key_pair = kp, .noise = [_]u8{0x9e} ** EcdsaP256.noise_length },
    }, 1, test_now_s, "ied-7");
    const got = try verifyToken(token, .{ .ecdsa_p256_sha256 = kp.public_key }, test_now_s, .{});
    try testing.expectEqualSlices(u8, "ied-7", got.identity);
}

test "signed token: tampering with any covered field breaks the signature" {
    const kp = try EcdsaP256.KeyPair.generateDeterministic([_]u8{0x21} ** EcdsaP256.KeyPair.seed_length);
    var sig_buf: [64]u8 = undefined;
    var token_buf: [512]u8 = undefined;
    const token = try signToken(&token_buf, &sig_buf, .{
        .ecdsa_p256_sha256 = .{ .key_pair = kp, .noise = [_]u8{0x9e} ** EcdsaP256.noise_length },
    }, 1, test_now_s, "ied-7");

    // Flip a byte of the identity...
    var tampered: [512]u8 = undefined;
    @memcpy(tampered[0..token.len], token);
    const idx = std.mem.indexOf(u8, tampered[0..token.len], "ied-7").?;
    tampered[idx] = 'X';
    try testing.expectError(error.SignatureInvalid, verifyToken(
        tampered[0..token.len],
        .{ .ecdsa_p256_sha256 = kp.public_key },
        test_now_s,
        .{},
    ));

    // ...and the time.
    @memcpy(tampered[0..token.len], token);
    const time_idx = std.mem.indexOf(u8, tampered[0..token.len], &.{ token_tag.time, 0x08 }).?;
    tampered[time_idx + 9] ^= 0x01;
    try testing.expectError(error.SignatureInvalid, verifyToken(
        tampered[0..token.len],
        .{ .ecdsa_p256_sha256 = kp.public_key },
        test_now_s,
        .{},
    ));
}

test "signed token: a valid signature does not survive the freshness window" {
    const kp = try EcdsaP256.KeyPair.generateDeterministic([_]u8{0x21} ** EcdsaP256.KeyPair.seed_length);
    var sig_buf: [64]u8 = undefined;
    var token_buf: [512]u8 = undefined;
    const token = try signToken(&token_buf, &sig_buf, .{
        .ecdsa_p256_sha256 = .{ .key_pair = kp, .noise = [_]u8{0x9e} ** EcdsaP256.noise_length },
    }, 1, test_now_s, "ied-7");
    const v: TokenVerifier = .{ .ecdsa_p256_sha256 = kp.public_key };

    try testing.expectError(error.TokenExpired, verifyToken(token, v, test_now_s + 3600, .{ .max_age_s = 60 }));
    try testing.expectError(error.TokenFromTheFuture, verifyToken(token, v, test_now_s - 3600, .{ .max_skew_s = 5 }));
    // Exactly at the edges it still passes.
    _ = try verifyToken(token, v, test_now_s + 60, .{ .max_age_s = 60 });
    _ = try verifyToken(token, v, test_now_s - 5, .{ .max_skew_s = 5 });
}

test "signed token: the wrong public key fails" {
    const kp = try EcdsaP256.KeyPair.generateDeterministic([_]u8{0x21} ** EcdsaP256.KeyPair.seed_length);
    const other = try EcdsaP256.KeyPair.generateDeterministic([_]u8{0x22} ** EcdsaP256.KeyPair.seed_length);
    var sig_buf: [64]u8 = undefined;
    var token_buf: [512]u8 = undefined;
    const token = try signToken(&token_buf, &sig_buf, .{
        .ecdsa_p256_sha256 = .{ .key_pair = kp, .noise = null },
    }, 1, test_now_s, "ied-7");
    try testing.expectError(error.SignatureInvalid, verifyToken(
        token,
        .{ .ecdsa_p256_sha256 = other.public_key },
        test_now_s,
        .{},
    ));
}

test "signed token: an unknown version is rejected before the signature is trusted" {
    const kp = try EcdsaP256.KeyPair.generateDeterministic([_]u8{0x21} ** EcdsaP256.KeyPair.seed_length);
    var sig_buf: [64]u8 = undefined;
    var token_buf: [512]u8 = undefined;
    const token = try signToken(&token_buf, &sig_buf, .{
        .ecdsa_p256_sha256 = .{ .key_pair = kp, .noise = null },
    }, 9, test_now_s, "ied-7");
    try testing.expectError(error.UnsupportedVersion, verifyToken(
        token,
        .{ .ecdsa_p256_sha256 = kp.public_key },
        test_now_s,
        .{},
    ));
}

test "signed token: structurally broken tokens are typed errors" {
    try testing.expectError(error.Truncated, SignedToken.parse(&.{0x30}));
    try testing.expectError(error.UnexpectedTag, SignedToken.parse(&.{ 0x31, 0x00 }));
    // A SEQUENCE with only three elements (no signature).
    var out: [128]u8 = undefined;
    const input = try SignedToken.signingInput(&out, 1, test_now_s, "x");
    try testing.expectError(error.MalformedToken, SignedToken.parse(input));
}

test "fuzz: ACSE field discovery never panics" {
    try testing.fuzz({}, fuzzFind, .{});
}

fn fuzzFind(_: void, smith: *std.testing.Smith) !void {
    var buf: [128]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u8, 0, buf.len);
    const bytes = buf[0..len];
    const kind: PduKind = if (smith.value(bool)) .aarq else .aare;
    const f = findAuthFields(bytes, kind) catch return;
    // Anything reported must point inside the input.
    if (f.mechanism_name) |m| try testing.expect(m.len <= bytes.len);
    if (f.value_slice) |s| try testing.expect(s.len <= bytes.len);
    _ = f.assertsAuthentication();
}

test "fuzz: token parsing never panics and never verifies garbage" {
    try testing.fuzz({}, fuzzToken, .{});
}

fn fuzzToken(_: void, smith: *std.testing.Smith) !void {
    const kp = EcdsaP256.KeyPair.generateDeterministic([_]u8{0x21} ** EcdsaP256.KeyPair.seed_length) catch unreachable;
    var buf: [128]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u8, 0, buf.len);
    const bytes = buf[0..len];
    _ = SignedToken.parse(bytes) catch return;
    // Random bytes must never verify against a real key.
    try testing.expect(std.meta.isError(verifyToken(
        bytes,
        .{ .ecdsa_p256_sha256 = kp.public_key },
        test_now_s,
        .{},
    )));
}
