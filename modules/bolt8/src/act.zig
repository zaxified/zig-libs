// SPDX-License-Identifier: MIT

//! BOLT#8 handshake message framing — Act One/Two/Three's fixed byte
//! shapes ("Authenticated Key Exchange Handshake Specification", "Handshake
//! Exchange"). REAL, not a Fable stub: parsing/serializing these fixed
//! layouts is pure wire-shape logic with no cryptographic decision in it
//! (the crypto — what the ciphertext fields actually CONTAIN — lives in
//! `handshake.zig`, mirroring how `sphinx.packet` (framing) is split from
//! `sphinx.core` (crypto) in this repo's sibling Lightning module).
//!
//! Every message starts with a single version byte (`0` = this spec;
//! anything else MUST be rejected before any further parsing — "Handshake
//! Versioning"):
//!
//!   Act One   (50 bytes): version(1) ‖ e.pub(33, compressed, cleartext) ‖ c(16, AEAD tag only — zero-length ciphertext)
//!   Act Two   (50 bytes): version(1) ‖ e.pub(33, compressed, cleartext) ‖ c(16, AEAD tag only)
//!   Act Three (66 bytes): version(1) ‖ c(49 = enc-static-key(33)+tag(16)) ‖ t(16, AEAD tag only)

const std = @import("std");

/// The one handshake version this module speaks ("Handshake Versioning":
/// "A version of 0 indicates that no change is necessary").
pub const version: u8 = 0;

pub const act1_len = 50;
pub const act2_len = 50;
pub const act3_len = 66;

pub const ParseError = error{
    /// Fewer than the fixed act length was available ("Read _exactly_ N
    /// bytes from the network buffer" — a short read is a hard failure,
    /// not a partial-parse; BOLT#8's own `*_READ_FAILED` test vectors).
    ShortRead,
    /// The leading version byte was not `0` ("Clients MUST reject
    /// handshake attempts initiated with an unknown version" —
    /// `*_BAD_VERSION` test vectors).
    BadVersion,
};

/// Act One: `-> e, es`. Sent initiator -> responder. `e_pub` travels in
/// the clear (Noise's `e` token is never itself encrypted — only the
/// following zero-length AEAD payload's TAG is transmitted, since the
/// plaintext has no length to hide); `tag` is that payload's 16-byte
/// Poly1305 tag with no ciphertext bytes attached.
pub const Act1 = struct {
    e_pub: [33]u8,
    tag: [16]u8,

    pub fn toBytes(self: Act1) [act1_len]u8 {
        var out: [act1_len]u8 = undefined;
        out[0] = version;
        out[1..34].* = self.e_pub;
        out[34..50].* = self.tag;
        return out;
    }

    pub fn fromBytes(bytes: []const u8) ParseError!Act1 {
        if (bytes.len < act1_len) return error.ShortRead;
        if (bytes[0] != version) return error.BadVersion;
        return .{ .e_pub = bytes[1..34].*, .tag = bytes[34..50].* };
    }
};

/// Act Two: `<- e, ee`. Sent responder -> initiator. Byte-identical shape
/// to `Act1` (kept as its own type — not a type alias — so call sites read
/// as which act they are handling, matching the spec's own act-numbered
/// prose).
pub const Act2 = struct {
    e_pub: [33]u8,
    tag: [16]u8,

    pub fn toBytes(self: Act2) [act2_len]u8 {
        var out: [act2_len]u8 = undefined;
        out[0] = version;
        out[1..34].* = self.e_pub;
        out[34..50].* = self.tag;
        return out;
    }

    pub fn fromBytes(bytes: []const u8) ParseError!Act2 {
        if (bytes.len < act2_len) return error.ShortRead;
        if (bytes[0] != version) return error.BadVersion;
        return .{ .e_pub = bytes[1..34].*, .tag = bytes[34..50].* };
    }
};

/// Act Three: `-> s, se`. Sent initiator -> responder. `c` is the
/// initiator's static public key ENCRYPTED with the running key (33-byte
/// plaintext + 16-byte tag = 49 bytes); `t` is a second, separate
/// zero-length AEAD payload's tag (the act's own final authenticating
/// step, distinct AEAD invocation from the one that produced `c`).
pub const Act3 = struct {
    c: [49]u8,
    t: [16]u8,

    pub fn toBytes(self: Act3) [act3_len]u8 {
        var out: [act3_len]u8 = undefined;
        out[0] = version;
        out[1..50].* = self.c;
        out[50..66].* = self.t;
        return out;
    }

    pub fn fromBytes(bytes: []const u8) ParseError!Act3 {
        if (bytes.len < act3_len) return error.ShortRead;
        if (bytes[0] != version) return error.BadVersion;
        return .{ .c = bytes[1..50].*, .t = bytes[50..66].* };
    }
};

// ── tests: real KATs (BOLT#8 Appendix A) — pure framing, no crypto ──────
//
// Hex constants live in `kat_vectors.zig` (single source of truth).

const testing = std.testing;
const kv = @import("kat_vectors.zig");
const act1_bytes = kv.act1_bytes;
const act2_bytes = kv.act2_bytes;
const act3_bytes = kv.act3_bytes;

test "Act1: round-trips the published act1 bytes byte-exact" {
    const a = try Act1.fromBytes(act1_bytes);
    try testing.expectEqualSlices(u8, act1_bytes[1..34], &a.e_pub);
    try testing.expectEqualSlices(u8, act1_bytes[34..50], &a.tag);
    try testing.expectEqualSlices(u8, act1_bytes, &a.toBytes());
}

test "Act2: round-trips the published act2 bytes byte-exact" {
    const a = try Act2.fromBytes(act2_bytes);
    try testing.expectEqualSlices(u8, act2_bytes[1..34], &a.e_pub);
    try testing.expectEqualSlices(u8, act2_bytes[34..50], &a.tag);
    try testing.expectEqualSlices(u8, act2_bytes, &a.toBytes());
}

test "Act3: round-trips the published act3 bytes byte-exact" {
    const a = try Act3.fromBytes(act3_bytes);
    try testing.expectEqualSlices(u8, act3_bytes[1..50], &a.c);
    try testing.expectEqualSlices(u8, act3_bytes[50..66], &a.t);
    try testing.expectEqualSlices(u8, act3_bytes, &a.toBytes());
}

test "Act2: 'transport-initiator act2 short read test' — 49 bytes fails ShortRead" {
    try testing.expectError(error.ShortRead, Act2.fromBytes(act2_bytes[0 .. act2_len - 1]));
}

test "Act2: 'transport-initiator act2 bad version test' — leading 0x01 fails BadVersion" {
    var bad = act2_bytes.*;
    bad[0] = 0x01;
    try testing.expectError(error.BadVersion, Act2.fromBytes(&bad));
}

test "Act1: 'transport-responder act1 short read test' — 49 bytes fails ShortRead" {
    try testing.expectError(error.ShortRead, Act1.fromBytes(act1_bytes[0 .. act1_len - 1]));
}

test "Act1: 'transport-responder act1 bad version test' — leading 0x01 fails BadVersion" {
    var bad = act1_bytes.*;
    bad[0] = 0x01;
    try testing.expectError(error.BadVersion, Act1.fromBytes(&bad));
}

test "Act3: 'transport-responder act3 bad version test' — leading 0x01 fails BadVersion" {
    var bad = act3_bytes.*;
    bad[0] = 0x01;
    try testing.expectError(error.BadVersion, Act3.fromBytes(&bad));
}

test "Act3: 'transport-responder act3 short read test' — 65 bytes fails ShortRead" {
    try testing.expectError(error.ShortRead, Act3.fromBytes(act3_bytes[0 .. act3_len - 1]));
}

// ── fuzz: the untrusted-wire handshake framing never panics/OOB ────────────

fn fuzzAct1Decode(_: void, smith: *std.testing.Smith) !void {
    var buf: [act1_len + 32]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const a = Act1.fromBytes(buf[0..len]) catch return;
    _ = a.toBytes();
}
test "fuzz Act1.fromBytes never panics" {
    try testing.fuzz({}, fuzzAct1Decode, .{});
}

fn fuzzAct2Decode(_: void, smith: *std.testing.Smith) !void {
    var buf: [act2_len + 32]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const a = Act2.fromBytes(buf[0..len]) catch return;
    _ = a.toBytes();
}
test "fuzz Act2.fromBytes never panics" {
    try testing.fuzz({}, fuzzAct2Decode, .{});
}

fn fuzzAct3Decode(_: void, smith: *std.testing.Smith) !void {
    var buf: [act3_len + 32]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const a = Act3.fromBytes(buf[0..len]) catch return;
    _ = a.toBytes();
}
test "fuzz Act3.fromBytes never panics" {
    try testing.fuzz({}, fuzzAct3Decode, .{});
}
