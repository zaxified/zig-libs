// SPDX-License-Identifier: MIT

//! session_key.zig — the two "Data exchange formats" megolm.md defines for
//! sharing ratchet state out of band: the **session-sharing format**
//! (signed, sent by the session owner when a session is first shared) and
//! the **session-export format** (unsigned, used when re-sharing a
//! ratcheted-forward copy would otherwise invalidate the original
//! signature — see megolm.md "Session export format").
//!
//! ```
//! session-sharing (SessionKey), version 0x02:
//! +---+----+--------+--------+--------+--------+------+-----------+
//! | V | i  | R(i,0) | R(i,1) | R(i,2) | R(i,3) | Kpub | Signature |
//! +---+----+--------+--------+--------+--------+------+-----------+
//! 0   1    5        37       69      101      133    165         229   bytes
//!
//! session-export (ExportedSessionKey), version 0x01: identical, minus
//! Signature (bytes 0..165 only).
//! ```
//!
//! `i` is big-endian u32. Both wrap the SAME 165-byte "signed part"
//! (version || i || ratchet || Kpub); the session-sharing format appends a
//! 64-byte Ed25519 signature OVER those 165 bytes (verified against the
//! `Kpub` embedded in them — self-certifying, like a self-signed cert) and
//! self-verifies on decode; the export format has nothing to verify against
//! (there is no separate authority key) and an importer's caller is
//! responsible for authenticating the out-of-band channel it arrived over
//! (mirrors vodozemac's `InboundGroupSession::import` doc comment).

const std = @import("std");
const ratchet_mod = @import("ratchet.zig");

const Ed25519 = std.crypto.sign.Ed25519;

pub const share_version: u8 = 0x02;
pub const export_version: u8 = 0x01;

const index_len = 4;
const pubkey_len = Ed25519.PublicKey.encoded_length; // 32
const signature_len = Ed25519.Signature.encoded_length; // 64

/// Length of the "signed part" shared by both formats: version(1) +
/// index(4) + ratchet(128) + Kpub(32).
pub const signed_part_len = 1 + index_len + ratchet_mod.ratchet_len + pubkey_len; // 165
pub const export_len = signed_part_len; // 165 -- export format IS the signed part, unsigned
pub const share_len = signed_part_len + signature_len; // 229

pub const DecodeError = error{
    WrongLength,
    UnsupportedVersion,
    InvalidPublicKey,
    InvalidSignature,
};

/// The unsigned session-export format.
pub const ExportedSessionKey = struct {
    ratchet_index: u32,
    ratchet: [ratchet_mod.ratchet_len]u8,
    signing_key: [pubkey_len]u8,

    pub fn encodeSignedPart(self: *const ExportedSessionKey, version: u8, out: *[signed_part_len]u8) void {
        out[0] = version;
        std.mem.writeInt(u32, out[1..][0..index_len], self.ratchet_index, .big);
        @memcpy(out[1 + index_len ..][0..ratchet_mod.ratchet_len], &self.ratchet);
        @memcpy(out[1 + index_len + ratchet_mod.ratchet_len ..][0..pubkey_len], &self.signing_key);
    }

    pub fn encode(self: *const ExportedSessionKey) [export_len]u8 {
        var out: [export_len]u8 = undefined;
        self.encodeSignedPart(export_version, &out);
        return out;
    }

    pub fn decode(bytes: []const u8) DecodeError!ExportedSessionKey {
        if (bytes.len != export_len) return error.WrongLength;
        if (bytes[0] != export_version) return error.UnsupportedVersion;
        return decodeSignedPartUnchecked(bytes[0..signed_part_len]);
    }

    pub fn toBase64(self: *const ExportedSessionKey, allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        const raw = self.encode();
        return base64Encode(allocator, &raw);
    }

    pub fn fromBase64(allocator: std.mem.Allocator, s: []const u8) (DecodeError || std.mem.Allocator.Error || std.base64.Error)!ExportedSessionKey {
        const raw = try base64Decode(allocator, s);
        defer allocator.free(raw);
        return decode(raw);
    }

    pub fn secureZero(self: *ExportedSessionKey) void {
        std.crypto.secureZero(u8, &self.ratchet);
    }
};

/// The signed session-sharing format.
pub const SessionKey = struct {
    inner: ExportedSessionKey,
    signature: [signature_len]u8,

    pub fn encode(self: *const SessionKey) [share_len]u8 {
        var out: [share_len]u8 = undefined;
        self.inner.encodeSignedPart(share_version, out[0..signed_part_len]);
        @memcpy(out[signed_part_len..], &self.signature);
        return out;
    }

    /// Decode AND verify: the embedded `Kpub` must validate the trailing
    /// signature over the leading 165 bytes (self-certifying — this is
    /// what makes `SessionKey`, unlike `ExportedSessionKey`, safe to trust
    /// without a separate out-of-band authentication step, PROVIDED the
    /// channel it arrived over authenticates the sender at all — see the
    /// module doc comment and SPEC.md's threat model).
    pub fn decode(bytes: []const u8) DecodeError!SessionKey {
        if (bytes.len != share_len) return error.WrongLength;
        if (bytes[0] != share_version) return error.UnsupportedVersion;

        const signed_part = bytes[0..signed_part_len];
        const sig_bytes = bytes[signed_part_len..][0..signature_len].*;
        const inner = try decodeSignedPartUnchecked(signed_part);

        const pk = Ed25519.PublicKey.fromBytes(inner.signing_key) catch return error.InvalidPublicKey;
        const sig = Ed25519.Signature.fromBytes(sig_bytes);
        sig.verify(signed_part, pk) catch return error.InvalidSignature;

        return .{ .inner = inner, .signature = sig_bytes };
    }

    pub fn toBase64(self: *const SessionKey, allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        const raw = self.encode();
        return base64Encode(allocator, &raw);
    }

    pub fn fromBase64(allocator: std.mem.Allocator, s: []const u8) (DecodeError || std.mem.Allocator.Error || std.base64.Error)!SessionKey {
        const raw = try base64Decode(allocator, s);
        defer allocator.free(raw);
        return decode(raw);
    }

    pub fn secureZero(self: *SessionKey) void {
        self.inner.secureZero();
    }
};

fn decodeSignedPartUnchecked(bytes: *const [signed_part_len]u8) DecodeError!ExportedSessionKey {
    const index = std.mem.readInt(u32, bytes[1..][0..index_len], .big);
    const ratchet: [ratchet_mod.ratchet_len]u8 = bytes[1 + index_len ..][0..ratchet_mod.ratchet_len].*;
    const signing_key: [pubkey_len]u8 = bytes[1 + index_len + ratchet_mod.ratchet_len ..][0..pubkey_len].*;
    return .{ .ratchet_index = index, .ratchet = ratchet, .signing_key = signing_key };
}

fn base64Encode(allocator: std.mem.Allocator, bytes: []const u8) std.mem.Allocator.Error![]u8 {
    const codec = std.base64.standard_no_pad;
    const out = try allocator.alloc(u8, codec.Encoder.calcSize(bytes.len));
    _ = codec.Encoder.encode(out, bytes);
    return out;
}

fn base64Decode(allocator: std.mem.Allocator, s: []const u8) (std.mem.Allocator.Error || std.base64.Error)![]u8 {
    const codec = std.base64.standard_no_pad;
    const size = try codec.Decoder.calcSizeForSlice(s);
    const out = try allocator.alloc(u8, size);
    errdefer allocator.free(out);
    try codec.Decoder.decode(out, s);
    return out;
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "ExportedSessionKey encode/decode round-trip" {
    var key = ExportedSessionKey{
        .ratchet_index = 0x01020304,
        .ratchet = [_]u8{0x77} ** ratchet_mod.ratchet_len,
        .signing_key = [_]u8{0x33} ** pubkey_len,
    };
    const raw = key.encode();
    try testing.expectEqual(@as(usize, export_len), raw.len);
    try testing.expectEqual(export_version, raw[0]);

    const decoded = try ExportedSessionKey.decode(&raw);
    try testing.expectEqual(key.ratchet_index, decoded.ratchet_index);
    try testing.expectEqualSlices(u8, &key.ratchet, &decoded.ratchet);
    try testing.expectEqualSlices(u8, &key.signing_key, &decoded.signing_key);
}

test "ExportedSessionKey rejects wrong length and wrong version" {
    try testing.expectError(error.WrongLength, ExportedSessionKey.decode(&[_]u8{0} ** (export_len - 1)));
    var bad_version = [_]u8{0} ** export_len;
    bad_version[0] = share_version; // 0x02 instead of 0x01
    try testing.expectError(error.UnsupportedVersion, ExportedSessionKey.decode(&bad_version));
}

test "SessionKey signs itself and self-verifies on decode" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();
    const kp = Ed25519.KeyPair.generate(io);

    var inner = ExportedSessionKey{
        .ratchet_index = 0,
        .ratchet = [_]u8{0x11} ** ratchet_mod.ratchet_len,
        .signing_key = kp.public_key.toBytes(),
    };
    var signed_part: [signed_part_len]u8 = undefined;
    inner.encodeSignedPart(share_version, &signed_part);
    const sig = try kp.sign(&signed_part, null);

    const key = SessionKey{ .inner = inner, .signature = sig.toBytes() };
    const raw = key.encode();

    const decoded = try SessionKey.decode(&raw);
    try testing.expectEqual(inner.ratchet_index, decoded.inner.ratchet_index);
    try testing.expectEqualSlices(u8, &inner.ratchet, &decoded.inner.ratchet);
}

test "SessionKey rejects a tampered signature" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();
    const kp = Ed25519.KeyPair.generate(io);

    var inner = ExportedSessionKey{
        .ratchet_index = 0,
        .ratchet = [_]u8{0x22} ** ratchet_mod.ratchet_len,
        .signing_key = kp.public_key.toBytes(),
    };
    var signed_part: [signed_part_len]u8 = undefined;
    inner.encodeSignedPart(share_version, &signed_part);
    const sig = try kp.sign(&signed_part, null);

    const key = SessionKey{ .inner = inner, .signature = sig.toBytes() };
    var raw = key.encode();
    raw[raw.len - 1] ^= 0xFF; // tamper one byte of the trailing signature

    try testing.expectError(error.InvalidSignature, SessionKey.decode(&raw));
}

test "SessionKey rejects a signature that doesn't match the embedded ratchet (tampered payload)" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();
    const kp = Ed25519.KeyPair.generate(io);

    var inner = ExportedSessionKey{
        .ratchet_index = 0,
        .ratchet = [_]u8{0x22} ** ratchet_mod.ratchet_len,
        .signing_key = kp.public_key.toBytes(),
    };
    var signed_part: [signed_part_len]u8 = undefined;
    inner.encodeSignedPart(share_version, &signed_part);
    const sig = try kp.sign(&signed_part, null);

    const key = SessionKey{ .inner = inner, .signature = sig.toBytes() };
    var raw = key.encode();
    raw[10] ^= 0xFF; // tamper a ratchet byte -- signature no longer matches

    try testing.expectError(error.InvalidSignature, SessionKey.decode(&raw));
}

fn testIo() std.Io.Threaded {
    return std.Io.Threaded.init(testing.allocator, .{});
}
