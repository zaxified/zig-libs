// SPDX-License-Identifier: MIT

//! IEC 62351-6 clause 8 — layer-2 security for the IEC 61850-8-1 GOOSE and
//! IEC 61850-9-2 Sampled Value profiles.
//!
//! ## The seam: caller-supplied PDU bytes
//!
//! This file never encodes or decodes a `goosePdu`/`savPdu`. It takes the
//! **already-encoded APDU** and the few link-layer header values that go in
//! front of it, and produces (or checks) the authenticated frame around them.
//! Security is a wrapper over a wire format, not a fork of it — so `iec61850`
//! (or any other producer of GOOSE/SV APDU bytes) is a *caller*, never a
//! dependency. See README.md for how the two wire together.
//!
//! ## The frame this module builds and checks
//!
//! Everything below is measured from the **EtherType** field — i.e. the
//! caller hands over the frame with the Ethernet MAC addresses (and any
//! 802.1Q tag) already stripped:
//!
//! ```text
//! offset  0 : EtherType   (2)   0x88b8 GOOSE / 0x88ba SV   <- MAC domain starts
//! offset  2 : APPID       (2)
//! offset  4 : Length      (2)   octets from APPID through the end of the frame
//! offset  6 : Reserved 1  (2)
//! offset  8 : Reserved 2  (2)
//! offset 10 : APDU        (n)                              <- MAC domain ends
//! offset 10+n: Extension  (e)   the security extension, when present
//! ```
//!
//! `Length` counts the eight header octets plus the APDU **plus the
//! Extension** (IEC 61850-8-1 §A.3: "8 + m"), so it changes when the
//! extension is added. The EtherType is *not* counted by `Length` but *is*
//! covered by the MAC.
//!
//! ## The covered range is the whole vulnerability
//!
//! IEC TS 62351-6:2007 states the authentication value is computed "starting
//! with the EtherType field through the end of the APDU". `Frame.macDomain`
//! is the single place that range is expressed, and every compute/verify path
//! goes through it. Two consequences that the tests assert explicitly:
//!
//! 1. **`Length`, `Reserved 1` and `Reserved 2` are inside the range.** They
//!    describe the extension itself (present-flag and extension length), so
//!    they must already hold their final values *before* the tag is computed
//!    — otherwise an attacker who can rewrite them can move the boundary
//!    between "APDU" and "Extension" without invalidating the tag. `build`
//!    fills the header first and MACs afterwards, and `verify` re-derives the
//!    boundary from the header it just authenticated.
//! 2. **The range is derived from `Length`, not from the buffer length.** A
//!    GOOSE frame is padded to the 64-octet Ethernet minimum; if the domain
//!    ran to the end of the caller's buffer, that attacker-visible padding
//!    would silently join the message.
//!
//! The classic implementation bug — starting the domain at APPID instead of
//! at the EtherType, a two-octet shift — is a dedicated negative test
//! (`shifted range`), not a comment.
//!
//! ## Which edition, and what changed
//!
//! Two documents exist and they do not agree:
//!
//! - **IEC TS 62351-6:2007** (Technical Specification). Authentication is a
//!   **digital signature**: SHA-256 hash, RSASSA-PSS (RFC 3447) signature.
//!   `Reserved 2` carries a CRC over the first octets of the PDU and the
//!   extension length lives in the low octet of `Reserved 1`.
//! - **IEC 62351-6:2020** (International Standard; the cover is labelled
//!   "Edition 1.0" even though it supersedes the 2007 TS). Clause 8.2
//!   ("Extended PDU" / "Format of extension octets") redefines `Reserved 1`
//!   and the extension octets, and clause 6.2 adds an explicit replay-
//!   protection state machine (see `replay.zig`). The signature profile is
//!   **replaced by symmetric MACs** — HMAC-SHA256 (80/128/256-bit tags) and
//!   AES-GMAC (64/128-bit tags) — because signature generation and
//!   verification cannot meet IEC 61850-5's 3 ms transfer-time class for a
//!   trip message on IED-class hardware.
//!
//! **This module implements the 2020 MAC profile as its default** (`HeaderProfile.ed2020`)
//! and keeps the 2007 signature profile reachable, because deployed equipment
//! still carries it and because a slow, non-real-time GOOSE (or an offline
//! forensic check of a captured frame) can afford a signature. Which one is in
//! force is an explicit parameter, never a guess.
//!
//! ## Honest limits of the modelling
//!
//! IEC 62351-6 is paywalled and publishes no test vectors. What is *grounded*
//! in publicly available material, and what is *this module's model*, is
//! separated field by field in `SPEC.md` §"Provenance of the wire model".
//! The short version: the algorithm numbering and tag lengths, the `0x85`
//! authentication-value tag, the extension's field order and the covered
//! range are taken from public descriptions of the standard; the exact BER
//! framing of the `Extension` SEQUENCE is this module's model. Every place
//! that matters is a parameter or has a `raw` escape hatch (`RawSealer` /
//! `RawVerifier`), so a caller holding the actual standard can substitute the
//! real bytes without forking this file.

const std = @import("std");
const rsa = @import("rsa");
const ber = @import("ber.zig");

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

// ── frame geometry ──────────────────────────────────────────────────────────

/// IEC 61850-8-1 GOOSE EtherType.
pub const ether_type_goose: u16 = 0x88b8;
/// IEC 61850-9-2 Sampled Value EtherType.
pub const ether_type_sv: u16 = 0x88ba;

/// Octets of EtherType in front of the 61850 link-layer header.
pub const ether_type_size = 2;
/// APPID + Length + Reserved 1 + Reserved 2.
pub const header_size = 8;
/// Offset of the APDU from the start of the EtherType field.
pub const apdu_offset = ether_type_size + header_size;

/// Where the security extension's octet length is carried. The two editions
/// disagree; see the module doc comment.
pub const LengthField = enum {
    /// IEC 62351-6:2020 — `Reserved 2` holds the extension length.
    reserved2,
    /// IEC TS 62351-6:2007 — the low octet of `Reserved 1` holds it
    /// (`Reserved 2` carries a CRC instead, which this module neither
    /// computes nor checks; see `SPEC.md`).
    reserved1_low_byte,
};

/// How the two reserved octets signal the presence and size of the security
/// extension. Made explicit rather than hard-coded so a deployment can state
/// which reading its equipment implements.
pub const HeaderProfile = struct {
    /// Bit of `Reserved 1` (0 = LSB) that signals "a security Extension is
    /// appended". `null` means presence is inferred from a non-zero length
    /// field instead — the 2007 shape, which has no flag bit.
    ///
    /// Note the collision worth knowing about: IEC 61850-8-1 Ed. 2.1 assigns
    /// `Reserved 1` bit 15 to the *simulation* flag. A deployment using both
    /// must pick a different `flag_bit`, which is exactly why this is a field.
    flag_bit: ?u4 = 15,
    /// Which field carries the extension length.
    length_field: LengthField = .reserved2,

    /// IEC 62351-6:2020 — flag in `Reserved 1` bit 15, length in `Reserved 2`.
    pub const ed2020: HeaderProfile = .{ .flag_bit = 15, .length_field = .reserved2 };
    /// IEC TS 62351-6:2007 — no flag bit, length in the low octet of `Reserved 1`.
    pub const ts2007: HeaderProfile = .{ .flag_bit = null, .length_field = .reserved1_low_byte };

    fn extensionLen(p: HeaderProfile, reserved1: u16, reserved2: u16) usize {
        return switch (p.length_field) {
            .reserved2 => reserved2,
            .reserved1_low_byte => reserved1 & 0xff,
        };
    }

    fn flagSet(p: HeaderProfile, reserved1: u16) bool {
        const bit = p.flag_bit orelse return false;
        return reserved1 & (@as(u16, 1) << bit) != 0;
    }

    /// Encode `ext_len` (and the presence flag) into the two reserved fields,
    /// preserving any other `Reserved 1` bits the caller set.
    fn encodeReserved(p: HeaderProfile, reserved1_extra: u16, ext_len: usize) EncodeError!struct { u16, u16 } {
        var r1 = reserved1_extra;
        var r2: u16 = 0;
        switch (p.length_field) {
            .reserved2 => {
                if (ext_len > std.math.maxInt(u16)) return error.ExtensionTooLong;
                r2 = @intCast(ext_len);
            },
            .reserved1_low_byte => {
                if (ext_len > 0xff) return error.ExtensionTooLong;
                if (r1 & 0xff != 0) return error.ReservedBitsConflict;
                r1 |= @intCast(ext_len);
            },
        }
        if (p.flag_bit) |bit| {
            if (ext_len > 0) r1 |= @as(u16, 1) << bit;
        }
        return .{ r1, r2 };
    }
};

pub const ParseError = error{
    /// The buffer is shorter than the header, or shorter than `Length` claims.
    Truncated,
    /// `Length` is below the 8-octet header minimum.
    LengthTooSmall,
    /// The extension length does not fit inside the frame `Length` declares.
    ExtensionLengthMismatch,
    /// The presence flag and the length field disagree (flag set with a
    /// zero length, or a non-zero length with the flag clear).
    ExtensionFlagMismatch,
    /// The frame carries no security extension but one was required.
    NoExtension,
};

/// A parsed, borrowed view of an (optionally authenticated) GOOSE/SV frame.
/// All slices point into the caller's buffer; nothing is copied.
pub const Frame = struct {
    /// EtherType through the end of the frame `Length` declares — trailing
    /// Ethernet padding is *not* included.
    bytes: []const u8,
    ether_type: u16,
    appid: u16,
    length: u16,
    reserved1: u16,
    reserved2: u16,
    apdu: []const u8,
    /// Empty when the frame carries no security extension.
    extension: []const u8,

    /// The exact octet range the MAC or signature covers: the EtherType field
    /// through the end of the APDU, inclusive of `Length`/`Reserved 1`/
    /// `Reserved 2` and exclusive of the Extension. This is the *only*
    /// definition of the covered range in the module.
    pub fn macDomain(f: Frame) []const u8 {
        return f.bytes[0 .. apdu_offset + f.apdu.len];
    }

    pub fn hasExtension(f: Frame) bool {
        return f.extension.len != 0;
    }
};

/// Parse a frame starting at the EtherType field. `bytes` may be longer than
/// the frame (Ethernet padding); the excess is ignored and excluded from
/// `Frame.bytes`.
pub fn parse(bytes: []const u8, profile: HeaderProfile) ParseError!Frame {
    if (bytes.len < apdu_offset) return error.Truncated;
    const length = std.mem.readInt(u16, bytes[4..6], .big);
    if (length < header_size) return error.LengthTooSmall;
    const frame_len = ether_type_size + @as(usize, length);
    if (bytes.len < frame_len) return error.Truncated;

    const frame = bytes[0..frame_len];
    const reserved1 = std.mem.readInt(u16, bytes[6..8], .big);
    const reserved2 = std.mem.readInt(u16, bytes[8..10], .big);

    const ext_len = profile.extensionLen(reserved1, reserved2);
    if (profile.flag_bit != null and profile.flagSet(reserved1) != (ext_len != 0)) {
        return error.ExtensionFlagMismatch;
    }
    const payload_len: usize = @as(usize, length) - header_size;
    if (ext_len > payload_len) return error.ExtensionLengthMismatch;
    const apdu_len = payload_len - ext_len;

    return .{
        .bytes = frame,
        .ether_type = std.mem.readInt(u16, bytes[0..2], .big),
        .appid = std.mem.readInt(u16, bytes[2..4], .big),
        .length = length,
        .reserved1 = reserved1,
        .reserved2 = reserved2,
        .apdu = frame[apdu_offset..][0..apdu_len],
        .extension = frame[apdu_offset + apdu_len ..],
    };
}

// ── the security extension ──────────────────────────────────────────────────

/// Outer tag of the appended `Extension` — a universal SEQUENCE.
pub const extension_tag: u8 = 0x30;
/// Tag of the authentication value inside it. `0x85` — context-specific [5],
/// primitive — is the tag IEC 61850-90-5 uses for the signature field of the
/// routed (R-GOOSE/R-SV) session PDU, and the same value is used here.
pub const auth_value_tag: u8 = 0x85;

/// Largest MAC tag any modelled algorithm produces (HMAC-SHA256-256).
pub const max_mac_len = 32;

/// The authentication value carried inside the `Extension`.
///
/// Field order and widths follow the published description of the 62351-6:2020
/// extension octets: a version octet, the key's current/next-change times,
/// an initialisation vector (present only for the AES-GMAC/GCM algorithms,
/// absent for HMAC), the key identifier, and finally the tag.
///
/// The frame carries **no algorithm identifier**: which algorithm `key_id`
/// selects comes from configuration (the SCL key policy of clause 9.2.3 / the
/// key-distribution centre of IEC 62351-9), so both `encode` and `parse` take
/// the IV-presence decision from the caller's algorithm choice rather than
/// guessing it from lengths.
pub const AuthenticationValue = struct {
    /// Version of the extension format. 1 in every description seen.
    version: u8 = 1,
    /// "TimeOfCurrentKey" — seconds since epoch at which the current key
    /// became active.
    time_of_current_key: u32 = 0,
    /// "TimeToNextKey" — minutes until the next key change.
    time_to_next_key: u16 = 0,
    /// GMAC/GCM initialisation vector; `null` for the HMAC and signature
    /// profiles.
    iv: ?[12]u8 = null,
    /// Key identifier assigned by the key-distribution centre.
    key_id: u32 = 0,
    /// The MAC or signature octets. Borrowed on parse, borrowed on encode.
    tag: []const u8,

    /// Octets of the authentication value itself (the `0x85` element's content).
    pub fn valueLen(v: AuthenticationValue) usize {
        return 1 + 4 + 2 + (if (v.iv != null) @as(usize, 12) else 0) + 4 + v.tag.len;
    }

    /// Octets of the whole `Extension` element, i.e. what goes in the
    /// header's extension-length field.
    pub fn encodedLen(v: AuthenticationValue) usize {
        return ber.encodedSize(ber.encodedSize(v.valueLen()));
    }

    /// Encode the complete `Extension` element into `out`.
    pub fn encode(v: AuthenticationValue, out: []u8) ber.Error![]u8 {
        const inner_len = ber.encodedSize(v.valueLen());
        const total = ber.encodedSize(inner_len);
        if (out.len < total) return error.BufferTooSmall;

        const seq_hdr = try ber.writeHeader(out, extension_tag, inner_len);
        const inner = out[seq_hdr..][0..inner_len];
        const av_hdr = try ber.writeHeader(inner, auth_value_tag, v.valueLen());
        var w = inner[av_hdr..];

        w[0] = v.version;
        std.mem.writeInt(u32, w[1..5], v.time_of_current_key, .big);
        std.mem.writeInt(u16, w[5..7], v.time_to_next_key, .big);
        var off: usize = 7;
        if (v.iv) |iv| {
            @memcpy(w[off..][0..12], &iv);
            off += 12;
        }
        std.mem.writeInt(u32, w[off..][0..4], v.key_id, .big);
        off += 4;
        @memcpy(w[off..][0..v.tag.len], v.tag);
        return out[0..total];
    }

    pub const ParseAvError = ber.Error || error{
        /// The value is shorter than the fixed fields it must carry.
        MalformedExtension,
        /// The tag is longer than any modelled algorithm produces and the
        /// caller did not opt into a signature-sized tag.
        TagTooLong,
    };

    /// Decode an `Extension` element. `expect_iv` comes from the algorithm
    /// bound to the key, not from the bytes. `max_tag` bounds the tag length
    /// accepted (`max_mac_len` for the MAC profiles, the modulus size for a
    /// signature).
    pub fn parse(extension: []const u8, expect_iv: bool, max_tag: usize) ParseAvError!AuthenticationValue {
        const seq = try ber.readTagged(extension, extension_tag);
        if (seq.encoded_len != extension.len) return error.MalformedExtension;
        const av = try ber.readTagged(seq.content, auth_value_tag);
        if (av.encoded_len != seq.content.len) return error.MalformedExtension;

        const fixed: usize = 1 + 4 + 2 + (if (expect_iv) @as(usize, 12) else 0) + 4;
        if (av.content.len < fixed) return error.MalformedExtension;
        const tag_len = av.content.len - fixed;
        if (tag_len == 0) return error.MalformedExtension;
        if (tag_len > max_tag) return error.TagTooLong;

        var v: AuthenticationValue = .{ .tag = av.content[fixed..] };
        v.version = av.content[0];
        v.time_of_current_key = std.mem.readInt(u32, av.content[1..5], .big);
        v.time_to_next_key = std.mem.readInt(u16, av.content[5..7], .big);
        var off: usize = 7;
        if (expect_iv) {
            var iv: [12]u8 = undefined;
            @memcpy(&iv, av.content[off..][0..12]);
            v.iv = iv;
            off += 12;
        }
        v.key_id = std.mem.readInt(u32, av.content[off..][0..4], .big);
        return v;
    }
};

// ── MAC algorithms ──────────────────────────────────────────────────────────

/// The MAC algorithm registry. The numbering and the tag lengths are those of
/// the IEC 61850-90-5 "Security Algorithms" octet, which IEC 62351-6:2020
/// adopts for the layer-2 profiles.
///
/// **HMAC-SHA-3 is deliberately absent.** SHA-3 HMACs appear in discussions
/// of the IEC 62351 series but not in the -6 algorithm table this module was
/// built from, so inventing numbers for them would be worse than not shipping
/// them: use `RawSealer`/`RawVerifier` if a deployment requires one.
pub const MacAlgorithm = enum(u8) {
    none = 0,
    /// HMAC-SHA-256 truncated to 80 bits (10 octets).
    hmac_sha256_80 = 1,
    /// HMAC-SHA-256 truncated to 128 bits (16 octets).
    hmac_sha256_128 = 2,
    /// HMAC-SHA-256, full 256-bit tag (32 octets).
    hmac_sha256_256 = 3,
    /// AES-GMAC with a 64-bit tag (8 octets), NIST SP 800-38D.
    aes_gmac_64 = 4,
    /// AES-GMAC with a 128-bit tag (16 octets).
    aes_gmac_128 = 5,
    _,

    /// Tag length in octets; 0 for `none` and for unknown values.
    pub fn tagLen(a: MacAlgorithm) usize {
        return switch (a) {
            .none => 0,
            .hmac_sha256_80 => 10,
            .hmac_sha256_128 => 16,
            .hmac_sha256_256 => 32,
            .aes_gmac_64 => 8,
            .aes_gmac_128 => 16,
            _ => 0,
        };
    }

    /// GMAC needs a 96-bit IV in the extension; HMAC does not.
    pub fn needsIv(a: MacAlgorithm) bool {
        return switch (a) {
            .aes_gmac_64, .aes_gmac_128 => true,
            else => false,
        };
    }
};

pub const MacError = error{
    /// `none`, or a value outside the registry.
    UnsupportedAlgorithm,
    /// `out` is smaller than the algorithm's tag length.
    BufferTooSmall,
    /// A GMAC algorithm was selected without an IV.
    IvRequired,
    /// A GMAC key is neither 16 nor 32 octets.
    KeyLength,
};

/// Compute the MAC of `domain` (which must be `Frame.macDomain`) into `out`,
/// returning the truncated tag.
pub fn computeMac(
    algorithm: MacAlgorithm,
    key: []const u8,
    domain: []const u8,
    iv: ?[12]u8,
    out: []u8,
) MacError![]u8 {
    const n = algorithm.tagLen();
    if (n == 0) return error.UnsupportedAlgorithm;
    if (out.len < n) return error.BufferTooSmall;
    switch (algorithm) {
        .hmac_sha256_80, .hmac_sha256_128, .hmac_sha256_256 => {
            var full: [HmacSha256.mac_length]u8 = undefined;
            HmacSha256.create(&full, domain, key);
            @memcpy(out[0..n], full[0..n]);
        },
        .aes_gmac_64, .aes_gmac_128 => {
            const nonce = iv orelse return error.IvRequired;
            var tag: [16]u8 = undefined;
            switch (key.len) {
                16 => Aes128Gcm.encrypt(&.{}, &tag, &.{}, domain, nonce, key[0..16].*),
                32 => Aes256Gcm.encrypt(&.{}, &tag, &.{}, domain, nonce, key[0..32].*),
                else => return error.KeyLength,
            }
            @memcpy(out[0..n], tag[0..n]);
        },
        else => return error.UnsupportedAlgorithm,
    }
    return out[0..n];
}

/// Constant-time verification of `received` against a freshly computed MAC.
///
/// The length check is not secret (it is visible in the frame header) so an
/// early `false` there leaks nothing; the octet comparison itself is
/// `std.crypto.timing_safe.eql` over a fixed-size array, never `std.mem.eql`.
pub fn verifyMac(
    algorithm: MacAlgorithm,
    key: []const u8,
    domain: []const u8,
    iv: ?[12]u8,
    received: []const u8,
) bool {
    const n = algorithm.tagLen();
    if (n == 0 or received.len != n) return false;
    var buf: [max_mac_len]u8 = undefined;
    const computed = computeMac(algorithm, key, domain, iv, &buf) catch return false;
    return constantTimeEql(computed, received);
}

/// Constant-time equality for two equal-length octet strings. Dispatches to
/// `std.crypto.timing_safe.eql` on the fixed sizes this module produces, and
/// falls back to an accumulate-XOR loop (which is itself branch-free over the
/// content) for any other length, e.g. a signature.
pub fn constantTimeEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    const ts = std.crypto.timing_safe;
    return switch (a.len) {
        8 => ts.eql([8]u8, a[0..8].*, b[0..8].*),
        10 => ts.eql([10]u8, a[0..10].*, b[0..10].*),
        16 => ts.eql([16]u8, a[0..16].*, b[0..16].*),
        32 => ts.eql([32]u8, a[0..32].*, b[0..32].*),
        64 => ts.eql([64]u8, a[0..64].*, b[0..64].*),
        else => blk: {
            var diff: u8 = 0;
            for (a, b) |x, y| diff |= x ^ y;
            break :blk diff == 0;
        },
    };
}

// ── the escape seam ─────────────────────────────────────────────────────────

/// Plug in an algorithm this module does not model — an HMAC-SHA-3 variant, a
/// national profile, or a hardware security module. `ctx` is opaque to this
/// module.
pub const RawSealer = struct {
    ctx: *anyopaque,
    /// Tag length this sealer will produce, needed before the tag exists so
    /// the header's length fields can be filled in first.
    tag_len: usize,
    /// Whether an IV field belongs in the extension.
    needs_iv: bool = false,
    /// Write exactly `tag_len` octets of tag for `domain` into `out`.
    sealFn: *const fn (ctx: *anyopaque, domain: []const u8, iv: ?[12]u8, out: []u8) anyerror!void,
};

/// The verifying counterpart of `RawSealer`. Implementations **must** compare
/// in constant time (`constantTimeEql` is exported for that).
pub const RawVerifier = struct {
    ctx: *anyopaque,
    tag_len: usize,
    needs_iv: bool = false,
    verifyFn: *const fn (ctx: *anyopaque, domain: []const u8, iv: ?[12]u8, tag: []const u8) bool,
};

// ── sealing and verifying a whole frame ─────────────────────────────────────

/// How the frame is authenticated on the sending side.
pub const Sealer = union(enum) {
    mac: struct { algorithm: MacAlgorithm, key: []const u8 },
    /// IEC TS 62351-6:2007 signature profile: SHA-256 + RSASSA-PSS (RFC 8017),
    /// salt length equal to the hash length.
    rsa_pss_sha256: struct { key: rsa.SecretKey, random: std.Random },
    /// ECDSA over P-256 with SHA-256, fixed-width (r‖s) 64-octet signature.
    /// Not in the 2007 profile — offered because 62351-4's end-to-end profile
    /// lists `ecdsa-with-SHA256` and the same domain is signed either way.
    ecdsa_p256_sha256: struct { key_pair: EcdsaP256.KeyPair, noise: ?[EcdsaP256.noise_length]u8 = null },
    raw: RawSealer,

    /// Tag length this sealer produces. Needed *before* sealing, because the
    /// header length fields are covered by the tag.
    pub fn tagLen(s: Sealer) usize {
        return switch (s) {
            .mac => |m| m.algorithm.tagLen(),
            .rsa_pss_sha256 => |r| (r.key.n.bits() + 7) / 8,
            .ecdsa_p256_sha256 => EcdsaP256.Signature.encoded_length,
            .raw => |r| r.tag_len,
        };
    }

    pub fn needsIv(s: Sealer) bool {
        return switch (s) {
            .mac => |m| m.algorithm.needsIv(),
            .rsa_pss_sha256, .ecdsa_p256_sha256 => false,
            .raw => |r| r.needs_iv,
        };
    }
};

/// How the frame is checked on the receiving side.
pub const Verifier = union(enum) {
    mac: struct { algorithm: MacAlgorithm, key: []const u8 },
    rsa_pss_sha256: rsa.PublicKey,
    ecdsa_p256_sha256: EcdsaP256.PublicKey,
    raw: RawVerifier,

    /// Largest tag this verifier will accept — a parse bound, so a hostile
    /// extension length cannot make the parser hand back an oversized slice.
    pub fn maxTagLen(v: Verifier) usize {
        return switch (v) {
            .mac => |m| m.algorithm.tagLen(),
            .rsa_pss_sha256 => |pk| (pk.n.bits() + 7) / 8,
            .ecdsa_p256_sha256 => EcdsaP256.Signature.encoded_length,
            .raw => |r| r.tag_len,
        };
    }

    pub fn needsIv(v: Verifier) bool {
        return switch (v) {
            .mac => |m| m.algorithm.needsIv(),
            .rsa_pss_sha256, .ecdsa_p256_sha256 => false,
            .raw => |r| r.needs_iv,
        };
    }
};

pub const EncodeError = error{
    /// The extension does not fit in the profile's length field.
    ExtensionTooLong,
    /// The 2007 profile needs the low octet of `Reserved 1` for the length,
    /// but the caller set bits there.
    ReservedBitsConflict,
    /// `Length` would exceed 65535 octets.
    FrameTooLong,
    /// The output buffer cannot hold the authenticated frame.
    BufferTooSmall,
    /// A GMAC algorithm was selected without an IV in the authentication value.
    IvRequired,
    /// An IV was supplied for an algorithm that takes none (or vice versa).
    IvMismatch,
};

pub const SealError = EncodeError || MacError || ber.Error ||
    error{ SignatureFailed, UnsupportedAlgorithm };

pub const BuildParams = struct {
    ether_type: u16 = ether_type_goose,
    appid: u16,
    /// The already-encoded goosePdu/savPdu. Never inspected.
    apdu: []const u8,
    /// Bits the caller wants set in `Reserved 1` besides the presence flag
    /// (e.g. IEC 61850-8-1's simulation bit under a profile that keeps it).
    reserved1_extra: u16 = 0,
    header: HeaderProfile = .ed2020,
    /// Everything but `tag`, which this function fills in.
    auth: AuthenticationValue = .{ .tag = &.{} },
};

/// Build an authenticated frame into `out` and return the written slice.
///
/// Ordering is the security-critical part and is fixed here: the header
/// (including `Length` counting the extension, and the reserved fields
/// carrying the presence flag and extension length) is written **first**, the
/// tag is computed over `Frame.macDomain` of that finished header, and only
/// then is the extension appended.
pub fn build(out: []u8, params: BuildParams, sealer: Sealer) SealError![]u8 {
    const tag_len = sealer.tagLen();
    if (tag_len == 0) return error.UnsupportedAlgorithm;
    if (sealer.needsIv() != (params.auth.iv != null)) return error.IvMismatch;

    var auth = params.auth;
    var tag_buf: [rsa.max_modulus_len]u8 = undefined;
    if (tag_len > tag_buf.len) return error.BufferTooSmall;
    auth.tag = tag_buf[0..tag_len];
    const ext_len = auth.encodedLen();

    const payload = params.apdu.len + ext_len;
    if (payload + header_size > std.math.maxInt(u16)) return error.FrameTooLong;
    const length: u16 = @intCast(header_size + payload);
    const total = ether_type_size + @as(usize, length);
    if (out.len < total) return error.BufferTooSmall;

    const r1, const r2 = try params.header.encodeReserved(params.reserved1_extra, ext_len);
    std.mem.writeInt(u16, out[0..2], params.ether_type, .big);
    std.mem.writeInt(u16, out[2..4], params.appid, .big);
    std.mem.writeInt(u16, out[4..6], length, .big);
    std.mem.writeInt(u16, out[6..8], r1, .big);
    std.mem.writeInt(u16, out[8..10], r2, .big);
    @memcpy(out[apdu_offset..][0..params.apdu.len], params.apdu);

    // The domain is now final: header with the extension already accounted
    // for, plus the APDU. Nothing after this point may touch it.
    const domain = out[0 .. apdu_offset + params.apdu.len];
    try seal(sealer, domain, auth.iv, tag_buf[0..tag_len]);

    _ = try auth.encode(out[apdu_offset + params.apdu.len ..][0..ext_len]);
    return out[0..total];
}

fn seal(sealer: Sealer, domain: []const u8, iv: ?[12]u8, out: []u8) SealError!void {
    switch (sealer) {
        .mac => |m| _ = try computeMac(m.algorithm, m.key, domain, iv, out),
        .rsa_pss_sha256 => |r| {
            const Sha256 = std.crypto.hash.sha2.Sha256;
            _ = rsa.signPss(r.key, Sha256, r.random, domain, Sha256.digest_length, out) catch
                return error.SignatureFailed;
        },
        .ecdsa_p256_sha256 => |e| {
            const sig = e.key_pair.sign(domain, e.noise) catch return error.SignatureFailed;
            @memcpy(out[0..EcdsaP256.Signature.encoded_length], &sig.toBytes());
        },
        .raw => |r| r.sealFn(r.ctx, domain, iv, out) catch return error.SignatureFailed,
    }
}

pub const VerifyError = ParseError || AuthenticationValue.ParseAvError ||
    error{
        /// The tag did not match. Deliberately the *only* failure the caller
        /// can distinguish for a well-formed frame with a wrong tag.
        AuthenticationFailed,
    };

/// Parse and authenticate a frame. Returns the decoded authentication value
/// (key id, key times, IV) on success so the caller can feed the key-policy
/// and replay layers; returns `error.AuthenticationFailed` when the tag does
/// not match the frame's own `macDomain`.
pub fn verify(
    bytes: []const u8,
    profile: HeaderProfile,
    verifier: Verifier,
) VerifyError!struct { frame: Frame, auth: AuthenticationValue } {
    const frame = try parse(bytes, profile);
    if (!frame.hasExtension()) return error.NoExtension;
    const auth = try AuthenticationValue.parse(frame.extension, verifier.needsIv(), verifier.maxTagLen());
    if (verifier.needsIv() != (auth.iv != null)) return error.MalformedExtension;
    if (!checkTag(verifier, frame.macDomain(), auth.iv, auth.tag)) return error.AuthenticationFailed;
    return .{ .frame = frame, .auth = auth };
}

fn checkTag(verifier: Verifier, domain: []const u8, iv: ?[12]u8, tag: []const u8) bool {
    return switch (verifier) {
        .mac => |m| verifyMac(m.algorithm, m.key, domain, iv, tag),
        .rsa_pss_sha256 => |pk| blk: {
            const Sha256 = std.crypto.hash.sha2.Sha256;
            rsa.verifyPss(pk, Sha256, domain, tag, Sha256.digest_length) catch break :blk false;
            break :blk true;
        },
        .ecdsa_p256_sha256 => |pk| blk: {
            if (tag.len != EcdsaP256.Signature.encoded_length) break :blk false;
            const sig = EcdsaP256.Signature.fromBytes(tag[0..EcdsaP256.Signature.encoded_length].*);
            sig.verify(domain, pk) catch break :blk false;
            break :blk true;
        },
        .raw => |r| r.tag_len == tag.len and r.verifyFn(r.ctx, domain, iv, tag),
    };
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// A short, fixed GOOSE APDU stand-in. This module never parses an APDU, so
/// the bytes only have to be stable, not valid `goosePdu` BER.
const sample_apdu = [_]u8{
    0x61, 0x1a, 0x80, 0x04, 0x74, 0x65, 0x73, 0x74, 0x81, 0x02, 0x03, 0xe8,
    0x82, 0x02, 0x00, 0x01, 0x83, 0x01, 0x00, 0x84, 0x08, 0x66, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00,
};

const sample_key = [_]u8{
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
};

fn buildSample(out: []u8, algorithm: MacAlgorithm, key: []const u8) ![]u8 {
    return build(out, .{
        .appid = 0x3001,
        .apdu = &sample_apdu,
        .auth = .{
            .time_of_current_key = 0x5f00_0000,
            .time_to_next_key = 60,
            .key_id = 0x0000_0007,
            .iv = if (algorithm.needsIv()) [_]u8{0x11} ** 12 else null,
            .tag = &.{},
        },
    }, .{ .mac = .{ .algorithm = algorithm, .key = key } });
}

test "build/verify round-trip for every modelled MAC algorithm" {
    var out: [512]u8 = undefined;
    const gmac_key = [_]u8{0x2a} ** 16;
    for ([_]MacAlgorithm{
        .hmac_sha256_80, .hmac_sha256_128, .hmac_sha256_256, .aes_gmac_64, .aes_gmac_128,
    }) |alg| {
        const key: []const u8 = if (alg.needsIv()) &gmac_key else &sample_key;
        const frame = try buildSample(&out, alg, key);
        const r = try verify(frame, .ed2020, .{ .mac = .{ .algorithm = alg, .key = key } });
        try testing.expectEqual(@as(u16, 0x3001), r.frame.appid);
        try testing.expectEqualSlices(u8, &sample_apdu, r.frame.apdu);
        try testing.expectEqual(@as(u32, 7), r.auth.key_id);
        try testing.expectEqual(alg.tagLen(), r.auth.tag.len);
    }
}

test "header: Length counts the extension, Reserved 1 flags it, Reserved 2 sizes it" {
    var out: [512]u8 = undefined;
    const frame_bytes = try buildSample(&out, .hmac_sha256_128, &sample_key);
    const f = try parse(frame_bytes, .ed2020);

    const ext_len = f.extension.len;
    try testing.expectEqual(header_size + sample_apdu.len + ext_len, @as(usize, f.length));
    try testing.expectEqual(@as(u16, 0x8000), f.reserved1);
    try testing.expectEqual(@as(u16, @intCast(ext_len)), f.reserved2);
    // The domain stops at the extension, and starts at the EtherType.
    try testing.expectEqual(apdu_offset + sample_apdu.len, f.macDomain().len);
    try testing.expectEqual(@as(u16, ether_type_goose), std.mem.readInt(u16, f.macDomain()[0..2], .big));
}

test "negative: a tampered APDU octet fails" {
    var out: [512]u8 = undefined;
    const frame_bytes = try buildSample(&out, .hmac_sha256_128, &sample_key);
    out[apdu_offset + 5] ^= 0x01;
    try testing.expectError(error.AuthenticationFailed, verify(
        frame_bytes,
        .ed2020,
        .{ .mac = .{ .algorithm = .hmac_sha256_128, .key = &sample_key } },
    ));
}

test "negative: a tampered header octet inside the domain fails" {
    var out: [512]u8 = undefined;
    const frame_bytes = try buildSample(&out, .hmac_sha256_128, &sample_key);
    out[2] ^= 0x01; // APPID — inside the covered range
    try testing.expectError(error.AuthenticationFailed, verify(
        frame_bytes,
        .ed2020,
        .{ .mac = .{ .algorithm = .hmac_sha256_128, .key = &sample_key } },
    ));
}

test "negative: a tampered tag octet fails" {
    var out: [512]u8 = undefined;
    const frame_bytes = try buildSample(&out, .hmac_sha256_128, &sample_key);
    out[frame_bytes.len - 1] ^= 0x80;
    try testing.expectError(error.AuthenticationFailed, verify(
        frame_bytes,
        .ed2020,
        .{ .mac = .{ .algorithm = .hmac_sha256_128, .key = &sample_key } },
    ));
}

test "negative: a truncated tag fails rather than verifying a prefix" {
    var out: [512]u8 = undefined;
    const frame_bytes = try buildSample(&out, .hmac_sha256_128, &sample_key);
    const f = try parse(frame_bytes, .ed2020);
    const ext_len = f.extension.len;

    // Shorten the extension by four octets everywhere it is described: the
    // BER lengths, Reserved 2, and the frame Length.
    var shortened: [512]u8 = undefined;
    @memcpy(shortened[0..frame_bytes.len], frame_bytes);
    const new_ext_len = ext_len - 4;
    std.mem.writeInt(u16, shortened[4..6], f.length - 4, .big);
    std.mem.writeInt(u16, shortened[8..10], @intCast(new_ext_len), .big);
    const ext_start = apdu_offset + sample_apdu.len;
    shortened[ext_start + 1] -= 4; // SEQUENCE length
    shortened[ext_start + 3] -= 4; // authentication-value length

    try testing.expectError(error.AuthenticationFailed, verify(
        shortened[0 .. frame_bytes.len - 4],
        .ed2020,
        .{ .mac = .{ .algorithm = .hmac_sha256_128, .key = &sample_key } },
    ));
}

test "negative: a tag computed over a shifted range does not verify" {
    // The classic bug: start the domain at APPID instead of at the EtherType.
    var out: [512]u8 = undefined;
    const frame_bytes = try buildSample(&out, .hmac_sha256_256, &sample_key);
    const f = try parse(frame_bytes, .ed2020);

    var shifted: [max_mac_len]u8 = undefined;
    const wrong = try computeMac(.hmac_sha256_256, &sample_key, f.macDomain()[2..], null, &shifted);
    try testing.expect(!constantTimeEql(wrong, f.extension[f.extension.len - 32 ..]));

    // ...and the same domain extended by one octet past the APDU (i.e. into
    // the extension) is equally wrong.
    const over = try computeMac(.hmac_sha256_256, &sample_key, f.bytes[0 .. f.macDomain().len + 1], null, &shifted);
    try testing.expect(!constantTimeEql(over, f.extension[f.extension.len - 32 ..]));
}

test "negative: Ethernet padding is excluded from the covered range" {
    var out: [512]u8 = undefined;
    const frame_bytes = try buildSample(&out, .hmac_sha256_128, &sample_key);
    // Pad to the 60-octet Ethernet minimum with attacker-chosen octets.
    var padded: [128]u8 = undefined;
    @memcpy(padded[0..frame_bytes.len], frame_bytes);
    @memset(padded[frame_bytes.len..], 0xee);
    const r = try verify(padded[0..], .ed2020, .{ .mac = .{ .algorithm = .hmac_sha256_128, .key = &sample_key } });
    try testing.expectEqual(frame_bytes.len, r.frame.bytes.len);
}

test "negative: wrong key fails" {
    var out: [512]u8 = undefined;
    const frame_bytes = try buildSample(&out, .hmac_sha256_80, &sample_key);
    const other = [_]u8{0x0c} ** 20;
    try testing.expectError(error.AuthenticationFailed, verify(
        frame_bytes,
        .ed2020,
        .{ .mac = .{ .algorithm = .hmac_sha256_80, .key = &other } },
    ));
}

test "negative: the same bytes read under the wrong algorithm fail" {
    var out: [512]u8 = undefined;
    const frame_bytes = try buildSample(&out, .hmac_sha256_128, &sample_key);
    // HMAC-SHA256-128 and AES-GMAC-128 produce the same 16-octet tag, so this
    // is genuine algorithm confusion rather than a length mismatch. Reading
    // the HMAC extension as a GMAC one re-slices twelve octets of it as an IV
    // and the remainder as a (short) tag, so the frame is still structurally
    // parseable — and fails on the tag, which is the outcome that matters.
    try testing.expectError(error.AuthenticationFailed, verify(
        frame_bytes,
        .ed2020,
        .{ .mac = .{ .algorithm = .aes_gmac_128, .key = &[_]u8{0x2a} ** 16 } },
    ));
}

test "parse: reserved-field disagreement is rejected" {
    var out: [512]u8 = undefined;
    const frame_bytes = try buildSample(&out, .hmac_sha256_128, &sample_key);

    // Flag set, length zero.
    var a: [512]u8 = undefined;
    @memcpy(a[0..frame_bytes.len], frame_bytes);
    std.mem.writeInt(u16, a[8..10], 0, .big);
    try testing.expectError(error.ExtensionFlagMismatch, parse(a[0..frame_bytes.len], .ed2020));

    // Length non-zero, flag clear.
    var b: [512]u8 = undefined;
    @memcpy(b[0..frame_bytes.len], frame_bytes);
    std.mem.writeInt(u16, b[6..8], 0, .big);
    try testing.expectError(error.ExtensionFlagMismatch, parse(b[0..frame_bytes.len], .ed2020));

    // Extension longer than the frame Length allows.
    var c: [512]u8 = undefined;
    @memcpy(c[0..frame_bytes.len], frame_bytes);
    std.mem.writeInt(u16, c[8..10], 0xfff0, .big);
    try testing.expectError(error.ExtensionLengthMismatch, parse(c[0..frame_bytes.len], .ed2020));
}

test "parse: rejects short buffers and a Length below the header" {
    try testing.expectError(error.Truncated, parse(&.{ 0x88, 0xb8, 0x30, 0x01 }, .ed2020));
    var short = [_]u8{ 0x88, 0xb8, 0x30, 0x01, 0x00, 0x04, 0, 0, 0, 0 };
    try testing.expectError(error.LengthTooSmall, parse(&short, .ed2020));
    var claims_more = [_]u8{ 0x88, 0xb8, 0x30, 0x01, 0x00, 0x40, 0, 0, 0, 0 };
    try testing.expectError(error.Truncated, parse(&claims_more, .ed2020));
}

test "unauthenticated frames round-trip and are rejected by verify" {
    // A plain 61850-8-1 frame: no extension, both reserved fields zero.
    var out: [64]u8 = undefined;
    std.mem.writeInt(u16, out[0..2], ether_type_goose, .big);
    std.mem.writeInt(u16, out[2..4], 0x3001, .big);
    std.mem.writeInt(u16, out[4..6], @intCast(header_size + sample_apdu.len), .big);
    std.mem.writeInt(u16, out[6..8], 0, .big);
    std.mem.writeInt(u16, out[8..10], 0, .big);
    @memcpy(out[apdu_offset..][0..sample_apdu.len], &sample_apdu);
    const bytes = out[0 .. apdu_offset + sample_apdu.len];

    const f = try parse(bytes, .ed2020);
    try testing.expect(!f.hasExtension());
    try testing.expectEqualSlices(u8, &sample_apdu, f.apdu);
    try testing.expectError(error.NoExtension, verify(
        bytes,
        .ed2020,
        .{ .mac = .{ .algorithm = .hmac_sha256_128, .key = &sample_key } },
    ));
}

test "ts2007 header profile: length in Reserved 1, no flag bit" {
    var out: [512]u8 = undefined;
    const frame_bytes = try build(&out, .{
        .appid = 0x4002,
        .apdu = &sample_apdu,
        .header = .ts2007,
        .auth = .{ .key_id = 1, .tag = &.{} },
    }, .{ .mac = .{ .algorithm = .hmac_sha256_128, .key = &sample_key } });

    const f = try parse(frame_bytes, .ts2007);
    try testing.expectEqual(@as(u16, 0), f.reserved2);
    try testing.expectEqual(f.extension.len, @as(usize, f.reserved1 & 0xff));
    const r = try verify(frame_bytes, .ts2007, .{ .mac = .{ .algorithm = .hmac_sha256_128, .key = &sample_key } });
    try testing.expectEqualSlices(u8, &sample_apdu, r.frame.apdu);

    // Reading the same bytes under the 2020 profile misreads the extension
    // length and must not authenticate.
    try testing.expect(std.meta.isError(verify(
        frame_bytes,
        .ed2020,
        .{ .mac = .{ .algorithm = .hmac_sha256_128, .key = &sample_key } },
    )));
}

test "ts2007: a 2048-bit signature extension does not fit the single length octet" {
    // Recorded as a test because it is a real tension in the 2007 shape, not
    // a limitation of this implementation: a single length octet caps the
    // extension at 255 octets, while the 2007 profile's own RSASSA-PSS
    // signature is 128 octets for a 1024-bit key and 256 for a 2048-bit one.
    // A deployment on 2048-bit keys therefore cannot be using a one-octet
    // length field, whatever the secondary literature says — which is exactly
    // why `HeaderProfile` is a parameter. See SPEC.md.
    const keys = @import("test_keys.zig");
    var sk = try keys.rsa2048SecretKey();
    defer sk.deinit();
    var prng = std.Random.DefaultPrng.init(3);

    var out: [1024]u8 = undefined;
    try testing.expectError(error.ExtensionTooLong, build(&out, .{
        .appid = 1,
        .apdu = &sample_apdu,
        .header = .ts2007,
        .auth = .{ .key_id = 1, .tag = &.{} },
    }, .{ .rsa_pss_sha256 = .{ .key = sk, .random = prng.random() } }));

    // A 1024-bit signature (128 octets of tag, 139 octets of extension) does fit.
    var sk1024 = try keys.rsa1024SecretKey();
    defer sk1024.deinit();
    const frame_bytes = try build(&out, .{
        .appid = 1,
        .apdu = &sample_apdu,
        .header = .ts2007,
        .auth = .{ .key_id = 1, .tag = &.{} },
    }, .{ .rsa_pss_sha256 = .{ .key = sk1024, .random = prng.random() } });
    const r = try verify(frame_bytes, .ts2007, .{ .rsa_pss_sha256 = try keys.rsa1024PublicKey() });
    try testing.expectEqual(@as(usize, 128), r.auth.tag.len);
}

test "IV presence must match the algorithm in both directions" {
    var out: [512]u8 = undefined;
    // GMAC without an IV.
    try testing.expectError(error.IvMismatch, build(&out, .{
        .appid = 1,
        .apdu = &sample_apdu,
        .auth = .{ .key_id = 1, .tag = &.{} },
    }, .{ .mac = .{ .algorithm = .aes_gmac_128, .key = &[_]u8{0x2a} ** 16 } }));
    // HMAC with one.
    try testing.expectError(error.IvMismatch, build(&out, .{
        .appid = 1,
        .apdu = &sample_apdu,
        .auth = .{ .key_id = 1, .iv = [_]u8{0} ** 12, .tag = &.{} },
    }, .{ .mac = .{ .algorithm = .hmac_sha256_128, .key = &sample_key } }));
}

test "AuthenticationValue: encode/parse round-trip with and without an IV" {
    var out: [128]u8 = undefined;
    const tag = [_]u8{0xa5} ** 16;
    for ([_]?[12]u8{ null, [_]u8{0x33} ** 12 }) |iv| {
        const v: AuthenticationValue = .{
            .version = 1,
            .time_of_current_key = 0x1234_5678,
            .time_to_next_key = 0x4321,
            .iv = iv,
            .key_id = 0x0bad_c0de,
            .tag = &tag,
        };
        const enc = try v.encode(&out);
        try testing.expectEqual(v.encodedLen(), enc.len);
        const back = try AuthenticationValue.parse(enc, iv != null, max_mac_len);
        try testing.expectEqual(v.time_of_current_key, back.time_of_current_key);
        try testing.expectEqual(v.time_to_next_key, back.time_to_next_key);
        try testing.expectEqual(v.key_id, back.key_id);
        try testing.expectEqualSlices(u8, &tag, back.tag);
        if (iv) |want| try testing.expectEqualSlices(u8, &want, &back.iv.?) else try testing.expect(back.iv == null);
    }
}

test "AuthenticationValue: parse rejects trailing bytes and empty tags" {
    var out: [128]u8 = undefined;
    const tag = [_]u8{0xa5} ** 16;
    const enc = try (AuthenticationValue{ .key_id = 1, .tag = &tag }).encode(&out);
    var longer: [128]u8 = undefined;
    @memcpy(longer[0..enc.len], enc);
    longer[enc.len] = 0x00;
    try testing.expectError(error.MalformedExtension, AuthenticationValue.parse(longer[0 .. enc.len + 1], false, max_mac_len));

    // A value that stops exactly at the fixed fields has a zero-length tag.
    const empty = try (AuthenticationValue{ .key_id = 1, .tag = &.{} }).encode(&out);
    try testing.expectError(error.MalformedExtension, AuthenticationValue.parse(empty, false, max_mac_len));
}

test "AuthenticationValue: an over-long tag is refused by the parse bound" {
    var out: [128]u8 = undefined;
    const tag = [_]u8{0xa5} ** 40;
    const enc = try (AuthenticationValue{ .key_id = 1, .tag = &tag }).encode(&out);
    try testing.expectError(error.TagTooLong, AuthenticationValue.parse(enc, false, max_mac_len));
}

// ── signature profile ───────────────────────────────────────────────────────

test "RSASSA-PSS/SHA-256 signature profile round-trips and rejects tampering" {
    const keys = @import("test_keys.zig");
    const sk = try keys.rsa2048SecretKey();
    const pk = try keys.rsa2048PublicKey();
    var prng = std.Random.DefaultPrng.init(0x62351_06);

    var out: [1024]u8 = undefined;
    const frame_bytes = try build(&out, .{
        .appid = 0x3002,
        .apdu = &sample_apdu,
        .auth = .{ .key_id = 42, .tag = &.{} },
    }, .{ .rsa_pss_sha256 = .{ .key = sk, .random = prng.random() } });

    const r = try verify(frame_bytes, .ed2020, .{ .rsa_pss_sha256 = pk });
    try testing.expectEqual(@as(usize, 256), r.auth.tag.len);
    try testing.expectEqual(@as(u32, 42), r.auth.key_id);

    out[apdu_offset + 3] ^= 0x08;
    try testing.expectError(error.AuthenticationFailed, verify(frame_bytes, .ed2020, .{ .rsa_pss_sha256 = pk }));
}

test "ECDSA P-256/SHA-256 signature profile round-trips and rejects tampering" {
    const seed = [_]u8{0x17} ** EcdsaP256.KeyPair.seed_length;
    const kp = EcdsaP256.KeyPair.generateDeterministic(seed) catch unreachable;

    var out: [512]u8 = undefined;
    const frame_bytes = try build(&out, .{
        .appid = 0x3003,
        .apdu = &sample_apdu,
        .auth = .{ .key_id = 9, .tag = &.{} },
    }, .{ .ecdsa_p256_sha256 = .{ .key_pair = kp, .noise = [_]u8{0x5c} ** EcdsaP256.noise_length } });

    const r = try verify(frame_bytes, .ed2020, .{ .ecdsa_p256_sha256 = kp.public_key });
    try testing.expectEqual(@as(usize, 64), r.auth.tag.len);

    out[4] ^= 0x00; // no-op, keep Length intact
    out[apdu_offset] ^= 0x40;
    try testing.expectError(error.AuthenticationFailed, verify(frame_bytes, .ed2020, .{ .ecdsa_p256_sha256 = kp.public_key }));
}

// ── the raw escape seam ─────────────────────────────────────────────────────

/// Stand-in for an unmodelled algorithm: HMAC-SHA-512 truncated to 20 octets,
/// which appears in no IEC 62351-6 table. It exists to prove the seam works,
/// not to suggest anyone deploy it.
const DemoRaw = struct {
    key: []const u8,

    fn compute(ctx: *anyopaque, domain: []const u8, iv: ?[12]u8, out: []u8) anyerror!void {
        _ = iv;
        const self: *DemoRaw = @ptrCast(@alignCast(ctx));
        var full: [64]u8 = undefined;
        std.crypto.auth.hmac.sha2.HmacSha512.create(&full, domain, self.key);
        @memcpy(out[0..20], full[0..20]);
    }

    fn check(ctx: *anyopaque, domain: []const u8, iv: ?[12]u8, tag: []const u8) bool {
        var expected: [20]u8 = undefined;
        compute(ctx, domain, iv, &expected) catch return false;
        return constantTimeEql(&expected, tag);
    }
};

test "raw seam: an unmodelled algorithm round-trips and still rejects tampering" {
    var demo: DemoRaw = .{ .key = &sample_key };
    const sealer: Sealer = .{ .raw = .{ .ctx = &demo, .tag_len = 20, .sealFn = DemoRaw.compute } };
    const verifier: Verifier = .{ .raw = .{ .ctx = &demo, .tag_len = 20, .verifyFn = DemoRaw.check } };

    var out: [512]u8 = undefined;
    const frame_bytes = try build(&out, .{ .appid = 7, .apdu = &sample_apdu, .auth = .{ .tag = &.{} } }, sealer);
    const r = try verify(frame_bytes, .ed2020, verifier);
    try testing.expectEqual(@as(usize, 20), r.auth.tag.len);

    out[apdu_offset + 1] ^= 0x02;
    try testing.expectError(error.AuthenticationFailed, verify(frame_bytes, .ed2020, verifier));
}

/// A deliberately careless `RawVerifier` callback: it ignores `tag` entirely
/// and always says yes. Stands in for an implementer who forgot to check the
/// tag length themselves and relies on the module's own defense-in-depth.
fn alwaysTrueRaw(_: *anyopaque, _: []const u8, _: ?[12]u8, _: []const u8) bool {
    return true;
}

test "checkTag: a RawVerifier's declared tag_len is enforced even if verifyFn itself is careless" {
    // `DemoRaw` above always checks length correctly (via `constantTimeEql`),
    // so it alone could never distinguish `checkTag`'s own `r.tag_len ==
    // tag.len` guard from redundancy: the guard is what actually matters when
    // a `RawVerifier` implementation, like this one, does not check length —
    // without it, a verifier configured for one tag length would accept a
    // frame carrying a tag of any other length as long as `verifyFn` (here,
    // unconditionally) says yes.
    var demo: DemoRaw = .{ .key = &sample_key };
    const sealer: Sealer = .{ .raw = .{ .ctx = &demo, .tag_len = 20, .sealFn = DemoRaw.compute } };

    var out: [512]u8 = undefined;
    const frame_bytes = try build(&out, .{ .appid = 7, .apdu = &sample_apdu, .auth = .{ .tag = &.{} } }, sealer);

    // The frame carries a 20-byte tag on the wire. A verifier misconfigured
    // with tag_len = 32 must be rejected outright — the naive `verifyFn`
    // would happily say yes to anything, so only the length guard saves this.
    const mismatched_verifier: Verifier = .{ .raw = .{ .ctx = &demo, .tag_len = 32, .verifyFn = alwaysTrueRaw } };
    try testing.expectError(error.AuthenticationFailed, verify(frame_bytes, .ed2020, mismatched_verifier));

    // Sanity: the matching tag_len (with the same careless verifyFn) does
    // "verify" — this test is about the length guard, not about `alwaysTrueRaw`
    // being a real check.
    const matched_verifier: Verifier = .{ .raw = .{ .ctx = &demo, .tag_len = 20, .verifyFn = alwaysTrueRaw } };
    _ = try verify(frame_bytes, .ed2020, matched_verifier);
}

test "constantTimeEql agrees with mem.eql on every length it special-cases" {
    var a: [64]u8 = undefined;
    for (&a, 0..) |*x, i| x.* = @truncate(i *% 31);
    for ([_]usize{ 0, 1, 7, 8, 10, 16, 20, 32, 64 }) |n| {
        var b: [64]u8 = a;
        try testing.expectEqual(std.mem.eql(u8, a[0..n], b[0..n]), constantTimeEql(a[0..n], b[0..n]));
        if (n > 0) {
            b[n - 1] ^= 0x80;
            try testing.expect(!constantTimeEql(a[0..n], b[0..n]));
        }
    }
    try testing.expect(!constantTimeEql(a[0..8], a[0..16]));
}

test "fuzz: frame parse never panics and stays inside the buffer" {
    try testing.fuzz({}, fuzzParse, .{});
}

fn fuzzParse(_: void, smith: *std.testing.Smith) !void {
    var buf: [160]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u8, 0, buf.len);
    const bytes = buf[0..len];
    const profile: HeaderProfile = if (smith.value(bool)) .ed2020 else .ts2007;

    const f = parse(bytes, profile) catch return;
    try testing.expect(f.bytes.len <= bytes.len);
    try testing.expect(f.apdu.len + f.extension.len + header_size == f.length);
    try testing.expect(f.macDomain().len <= f.bytes.len);

    // Verification of arbitrary bytes must fail cleanly, never trap.
    _ = verify(bytes, profile, .{ .mac = .{ .algorithm = .hmac_sha256_128, .key = &sample_key } }) catch return;
}

test "fuzz: extension parse never panics for arbitrary extension octets" {
    try testing.fuzz({}, fuzzExtension, .{});
}

fn fuzzExtension(_: void, smith: *std.testing.Smith) !void {
    var buf: [96]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u8, 0, buf.len);
    const expect_iv = smith.value(bool);
    const v = AuthenticationValue.parse(buf[0..len], expect_iv, max_mac_len) catch return;
    try testing.expect(v.tag.len <= max_mac_len);
    try testing.expectEqual(expect_iv, v.iv != null);
}
