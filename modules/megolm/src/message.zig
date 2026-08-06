// SPDX-License-Identifier: MIT

//! message.zig — the Megolm wire message format (megolm.md "Message
//! format"): one version byte, a small Protocol-Buffers-flavored payload
//! carrying the ratchet index and ciphertext, an 8-byte truncated
//! HMAC-SHA-256 MAC, and a 64-byte Ed25519 signature.
//!
//! ```
//! +---+------------------------------------+-----------+------------------+
//! | V | Payload Bytes                      | MAC Bytes | Signature Bytes  |
//! +---+------------------------------------+-----------+------------------+
//! 0   1                                    N          N+8                N+72   bytes
//! ```
//!
//! The payload is NOT general Protocol Buffers — it is the specific
//! two-field encoding the spec spells out byte-by-byte (LEB128 varints,
//! tag byte then value): `0x08` (field 1, varint) => the message index,
//! `0x12` (field 2, length-delimited) => the ciphertext. This file
//! implements exactly those two field shapes, nothing general-purpose.
//!
//! This module owns the CODEC only (bytes <-> `Message`, plus the exact
//! byte ranges the MAC/signature cover). Computing/verifying the MAC and
//! signature themselves is `session.zig`'s job (it is the only place that
//! holds keys) — see that file's `OutboundSession.encrypt`/
//! `InboundGroupSession.decrypt`.

const std = @import("std");

/// The spec's message-format version byte. This module implements ONLY
/// this (8-byte truncated MAC) variant — see SPEC.md for the newer
/// vodozemac-only 32-byte-MAC variant (version 4) this module deliberately
/// does not implement (not part of the published spec).
pub const version: u8 = 0x03;

pub const wire_mac_len = 8;
pub const signature_len = 64;
/// Bytes after the payload: MAC + signature.
const suffix_len = wire_mac_len + signature_len;
/// The smallest a well-formed message can be: version + an empty payload
/// (which is itself never valid — see `decode`'s `MissingIndex`/
/// `MissingCiphertext` — but this bounds the truncation check before any
/// payload parsing happens) + the fixed suffix.
const min_len = 1 + suffix_len;

pub const DecodeError = error{
    MessageTooShort,
    UnsupportedVersion,
    /// A payload field tag this decoder doesn't recognize (only `0x08`
    /// message-index and `0x12` ciphertext are defined).
    UnknownField,
    /// A varint or length-delimited field ran past the end of its buffer.
    Truncated,
    /// A varint used more bytes than a u64 (or, for the message index
    /// specifically, more than a u32) can represent.
    VarintTooLong,
    /// The payload didn't carry both required fields.
    MissingIndex,
    MissingCiphertext,
};

/// A decoded (or about-to-be-encoded) Megolm message. Owns `ciphertext`.
pub const Message = struct {
    message_index: u32,
    ciphertext: []u8,
    mac: [wire_mac_len]u8,
    signature: [signature_len]u8,

    pub fn deinit(self: *Message, allocator: std.mem.Allocator) void {
        allocator.free(self.ciphertext);
        self.* = undefined;
    }

    /// `version || payload` — the bytes the wire MAC is computed over.
    /// Caller frees.
    pub fn macBytes(self: *const Message, allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        return encodePayload(allocator, self.message_index, self.ciphertext);
    }

    /// `macBytes() || mac` — the bytes the Ed25519 signature is computed
    /// over (spec: "the entire message ... are passed through HMAC-
    /// SHA-256 ... Finally, the authenticated message is signed"). Caller
    /// frees.
    pub fn signatureBytes(self: *const Message, allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        const payload = try self.macBytes(allocator);
        defer allocator.free(payload);
        const out = try allocator.alloc(u8, payload.len + wire_mac_len);
        @memcpy(out[0..payload.len], payload);
        @memcpy(out[payload.len..], &self.mac);
        return out;
    }

    /// The full wire encoding: `signatureBytes() || signature`. Caller
    /// frees.
    pub fn encode(self: *const Message, allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        const signed = try self.signatureBytes(allocator);
        defer allocator.free(signed);
        const out = try allocator.alloc(u8, signed.len + signature_len);
        @memcpy(out[0..signed.len], signed);
        @memcpy(out[signed.len..], &self.signature);
        return out;
    }

    pub fn toBase64(self: *const Message, allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        const raw = try self.encode(allocator);
        defer allocator.free(raw);
        return base64Encode(allocator, raw);
    }

    /// Parse `bytes` into a `Message`; `ciphertext` is a fresh allocation
    /// the caller owns (via `deinit`). Fuzz-safe: every truncation/
    /// malformed-varint/unknown-tag shape returns a `DecodeError`, never
    /// panics or reads out of bounds.
    pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) (DecodeError || std.mem.Allocator.Error)!Message {
        if (bytes.len < min_len) return error.MessageTooShort;
        if (bytes[0] != version) return error.UnsupportedVersion;

        const payload = bytes[1 .. bytes.len - suffix_len];
        const mac_bytes = bytes[bytes.len - suffix_len ..][0..wire_mac_len];
        const sig_bytes = bytes[bytes.len - signature_len ..][0..signature_len];

        var message_index: ?u32 = null;
        var ciphertext_slice: ?[]const u8 = null;
        var pos: usize = 0;
        while (pos < payload.len) {
            const tag = try readVarint(payload[pos..]);
            pos += tag.len;
            switch (tag.value) {
                0x08 => {
                    const v = try readVarint(payload[pos..]);
                    pos += v.len;
                    if (v.value > std.math.maxInt(u32)) return error.VarintTooLong;
                    message_index = @intCast(v.value);
                },
                0x12 => {
                    const l = try readVarint(payload[pos..]);
                    pos += l.len;
                    if (l.value > @as(u64, payload.len - pos)) return error.Truncated;
                    const len: usize = @intCast(l.value);
                    ciphertext_slice = payload[pos..][0..len];
                    pos += len;
                },
                else => return error.UnknownField,
            }
        }

        const index = message_index orelse return error.MissingIndex;
        const ct_src = ciphertext_slice orelse return error.MissingCiphertext;
        const ciphertext = try allocator.dupe(u8, ct_src);
        errdefer allocator.free(ciphertext);

        return .{
            .message_index = index,
            .ciphertext = ciphertext,
            .mac = mac_bytes.*,
            .signature = sig_bytes.*,
        };
    }

    pub fn fromBase64(allocator: std.mem.Allocator, s: []const u8) (DecodeError || std.mem.Allocator.Error || Base64DecodeError)!Message {
        const raw = try base64Decode(allocator, s);
        defer allocator.free(raw);
        return decode(allocator, raw);
    }
};

/// `version || tag(0x08) || varint(message_index) || tag(0x12) ||
/// varint(ciphertext.len) || ciphertext`. Caller frees.
fn encodePayload(allocator: std.mem.Allocator, message_index: u32, ciphertext: []const u8) std.mem.Allocator.Error![]u8 {
    var buf: [1 + 10 + 1 + 10]u8 = undefined; // version + max-index-varint + tag + max-len-varint
    var pos: usize = 0;
    buf[pos] = version;
    pos += 1;
    buf[pos] = 0x08;
    pos += 1;
    pos += writeVarint(buf[pos..], message_index);
    buf[pos] = 0x12;
    pos += 1;
    pos += writeVarint(buf[pos..], @as(u64, ciphertext.len));

    const out = try allocator.alloc(u8, pos + ciphertext.len);
    @memcpy(out[0..pos], buf[0..pos]);
    @memcpy(out[pos..], ciphertext);
    return out;
}

// ── LEB128 varints (megolm.md "Message format": "high bit set ... least
// significant bits ... in the first byte" — standard unsigned LEB128,
// identical to Protocol Buffers' varint) ───────────────────────────────

fn varintLen(v: u64) usize {
    var n: usize = 1;
    var x = v >> 7;
    while (x != 0) : (x >>= 7) n += 1;
    return n;
}

fn writeVarint(buf: []u8, value: u64) usize {
    var x = value;
    var i: usize = 0;
    while (true) {
        var b: u8 = @intCast(x & 0x7f);
        x >>= 7;
        if (x != 0) b |= 0x80;
        buf[i] = b;
        i += 1;
        if (x == 0) break;
    }
    return i;
}

const Varint = struct { value: u64, len: usize };

/// Max LEB128 bytes for a u64 (`ceil(64/7)`) — bounds the read loop so a
/// malicious/truncated buffer of continuation-bit-set bytes can't spin
/// forever or overflow the shift.
const max_varint_bytes = 10;

fn readVarint(buf: []const u8) (error{ Truncated, VarintTooLong })!Varint {
    var value: u64 = 0;
    var i: usize = 0;
    while (i < max_varint_bytes) {
        if (i >= buf.len) return error.Truncated;
        const b = buf[i];
        const shift: u6 = @intCast(i * 7);
        value |= @as(u64, b & 0x7f) << shift;
        i += 1;
        if (b & 0x80 == 0) return .{ .value = value, .len = i };
    }
    return error.VarintTooLong;
}

// ── base64 (unpadded standard alphabet — matches vodozemac's
// `Base64Unpadded` and libolm's wire encoding; see session_key.zig for the
// same choice) ───────────────────────────────────────────────────────────

pub const Base64DecodeError = std.base64.Error;

fn base64Encode(allocator: std.mem.Allocator, bytes: []const u8) std.mem.Allocator.Error![]u8 {
    const codec = std.base64.standard_no_pad;
    const out = try allocator.alloc(u8, codec.Encoder.calcSize(bytes.len));
    _ = codec.Encoder.encode(out, bytes);
    return out;
}

fn base64Decode(allocator: std.mem.Allocator, s: []const u8) (std.mem.Allocator.Error || Base64DecodeError)![]u8 {
    const codec = std.base64.standard_no_pad;
    const size = try codec.Decoder.calcSizeForSlice(s);
    const out = try allocator.alloc(u8, size);
    errdefer allocator.free(out);
    try codec.Decoder.decode(out, s);
    return out;
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

// EXTERNAL ANCHOR (grade 1): libolm's own C test suite,
// `tests/test_message.cpp`, "Group message encode test" — the low-level
// tag/varint encoding of `_olm_encode_group_message(version=3, counter=200,
// ciphertext_len=10, ...)`. Fetched:
//   curl -sL https://gitlab.matrix.org/matrix-org/olm/-/raw/master/tests/test_message.cpp
// The expected bytes there are the literal C string
// `"\x03" "\x08\xC8\x01" "\x12\x0A"` (this module's `encodePayload`'s
// header, before the ciphertext bytes it prefixes).
test "encodePayload header matches libolm's Group message encode test vector" {
    const ciphertext = "0123456789"; // 10 bytes -- only the length matters for this vector
    const out = try encodePayload(testing.allocator, 200, ciphertext);
    defer testing.allocator.free(out);

    const expected_header = [_]u8{ 0x03, 0x08, 0xC8, 0x01, 0x12, 0x0A };
    try testing.expectEqualSlices(u8, &expected_header, out[0..expected_header.len]);
    try testing.expectEqualSlices(u8, ciphertext, out[expected_header.len..]);
}

test "varint round-trip over a range of values including multi-byte boundaries" {
    const values = [_]u64{ 0, 1, 127, 128, 129, 16383, 16384, 200, 0xFFFFFFFF, std.math.maxInt(u32) };
    for (values) |v| {
        var buf: [max_varint_bytes]u8 = undefined;
        const n = writeVarint(&buf, v);
        try testing.expectEqual(varintLen(v), n);
        const decoded = try readVarint(buf[0..n]);
        try testing.expectEqual(v, decoded.value);
        try testing.expectEqual(n, decoded.len);
    }
}

test "readVarint rejects a truncated buffer and an over-long varint" {
    try testing.expectError(error.Truncated, readVarint(&.{0x80}));
    const all_continuation = [_]u8{0x80} ** 11;
    try testing.expectError(error.VarintTooLong, readVarint(&all_continuation));
}

fn dummyMessage(allocator: std.mem.Allocator) !Message {
    const ciphertext = try allocator.dupe(u8, "hello ciphertext");
    return .{
        .message_index = 42,
        .ciphertext = ciphertext,
        .mac = [_]u8{0xAA} ** wire_mac_len,
        .signature = [_]u8{0xBB} ** signature_len,
    };
}

test "Message encode/decode round-trip" {
    var msg = try dummyMessage(testing.allocator);
    defer msg.deinit(testing.allocator);

    const raw = try msg.encode(testing.allocator);
    defer testing.allocator.free(raw);

    var decoded = try Message.decode(testing.allocator, raw);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(msg.message_index, decoded.message_index);
    try testing.expectEqualSlices(u8, msg.ciphertext, decoded.ciphertext);
    try testing.expectEqualSlices(u8, &msg.mac, &decoded.mac);
    try testing.expectEqualSlices(u8, &msg.signature, &decoded.signature);
}

test "Message base64 round-trip" {
    var msg = try dummyMessage(testing.allocator);
    defer msg.deinit(testing.allocator);

    const b64 = try msg.toBase64(testing.allocator);
    defer testing.allocator.free(b64);
    // Unpadded standard alphabet: no '=', no '-'/'_'.
    try testing.expect(std.mem.indexOfScalar(u8, b64, '=') == null);

    var decoded = try Message.fromBase64(testing.allocator, b64);
    defer decoded.deinit(testing.allocator);
    try testing.expectEqual(msg.message_index, decoded.message_index);
    try testing.expectEqualSlices(u8, msg.ciphertext, decoded.ciphertext);
}

test "decode rejects: too short, wrong version, unknown field tag" {
    try testing.expectError(error.MessageTooShort, Message.decode(testing.allocator, &[_]u8{0x03} ** 10));

    var too_short_but_versioned = [_]u8{0} ** (min_len - 1);
    too_short_but_versioned[0] = version;
    try testing.expectError(error.MessageTooShort, Message.decode(testing.allocator, &too_short_but_versioned));

    var wrong_version = [_]u8{0} ** min_len;
    wrong_version[0] = 0x04;
    try testing.expectError(error.UnsupportedVersion, Message.decode(testing.allocator, &wrong_version));

    // version + one unknown tag byte (0x20) then the fixed suffix.
    var unknown_tag = [_]u8{0} ** (min_len + 1);
    unknown_tag[0] = version;
    unknown_tag[1] = 0x20;
    try testing.expectError(error.UnknownField, Message.decode(testing.allocator, &unknown_tag));
}

test "decode rejects a ciphertext length claiming more bytes than remain (truncation-safe)" {
    // version, tag 0x08, index=0 (1-byte varint), tag 0x12, length=200 (a
    // 2-byte varint claiming way more than actually remains), then the
    // fixed 72-byte suffix and nothing else: 1+1+1+1+2 header + suffix.
    var buf = [_]u8{0} ** (1 + 1 + 1 + 1 + 2 + suffix_len);
    buf[0] = version;
    buf[1] = 0x08;
    buf[2] = 0x00;
    buf[3] = 0x12;
    buf[4] = 0xC8; // varint continuation bit set...
    buf[5] = 0x01; // ...= 200, but far fewer bytes actually remain
    try testing.expectError(error.Truncated, Message.decode(testing.allocator, &buf));
}

// ── fuzz: the wire-message decoder ───────────────────────────────────────
//
// `Message.decode`/`fromBase64` take a byte string straight off the wire —
// a Matrix `m.room.encrypted` event body is attacker-supplied in full —
// and walk it with hand-rolled LEB128 varints and offset arithmetic
// (`payload = bytes[1 .. len - 72]`, then a tag/value loop that advances
// `pos` by amounts the input chooses). Until this harness existed the
// module carried NO `testing.fuzz(` call at all, so `scripts/fuzz-sweep.sh`
// — whose target list is `grep -rl 'testing.fuzz(' modules/*/src/*.zig` —
// never listed `megolm` and it received zero fuzz budget in the repo's own
// sweeps.
//
// Raw entropy would spend almost every iteration on `MessageTooShort` /
// `UnsupportedVersion`, so this builds the FRAME (version byte + the fixed
// 72-byte MAC+signature suffix) around fuzzer-chosen payload bytes, and
// generates the payload as a tag/varint stream — including deliberately
// NON-MINIMAL varints (`0x80 0x00` for zero), over-claimed
// length-delimited fields, duplicate and out-of-order fields, and 10-byte
// maximal varints — because those are exactly the shapes the offset
// arithmetic has to survive.
//
// Reachability was verified rather than assumed: with a temporary
// `@panic` on `decode`'s SUCCESS return, a 60 s `scripts/fuzz-sweep.sh`
// run found it — so the harness really does drive the tag loop to
// completion, not just its early rejects. Probe then removed.
test "fuzz: Message.decode / fromBase64 never panic on arbitrary bytes" {
    try testing.fuzz({}, fuzzMessageDecode, .{});
}

/// Writes `v` as LEB128 using exactly `pad` extra continuation bytes — a
/// non-minimal but structurally legal encoding. `pad == 0` is the minimal
/// form. Returns the number of bytes written.
fn fuzzWriteVarintPadded(buf: []u8, v: u64, pad: usize) usize {
    var x = v;
    var i: usize = 0;
    while (true) {
        var b: u8 = @intCast(x & 0x7f);
        x >>= 7;
        if (x != 0) b |= 0x80;
        if (i >= buf.len) return i;
        buf[i] = b;
        i += 1;
        if (x == 0) break;
    }
    var p: usize = 0;
    while (p < pad and i < buf.len and i < max_varint_bytes) : (p += 1) {
        buf[i - 1] |= 0x80; // re-open the previous byte
        buf[i] = 0x00; // ...and continue with a zero group
        i += 1;
    }
    return i;
}

fn fuzzMessageDecode(_: void, smith: *std.testing.Smith) !void {
    const allocator = testing.allocator;

    var buf: [512]u8 = undefined;
    var n: usize = 0;

    if (smith.boolWeighted(1, 7)) {
        // Minority: unstructured bytes, so the length/version gates and the
        // "not even a frame" shapes get their own coverage.
        n = smith.slice(&buf);
    } else {
        buf[0] = if (smith.boolWeighted(1, 9)) smith.value(u8) else version;
        n = 1;
        // Payload: a tag/value stream the decoder has to walk.
        while (n + 16 < buf.len - suffix_len and !smith.eosWeightedSimple(4, 1)) {
            const tag: u64 = switch (smith.value(enum { index, ciphertext, unknown, wide })) {
                .index => 0x08,
                .ciphertext => 0x12,
                .unknown => smith.value(u8),
                .wide => smith.value(u64),
            };
            n += fuzzWriteVarintPadded(buf[n..], tag, smith.valueRangeAtMost(u8, 0, 3));
            switch (tag) {
                0x08 => {
                    // A u32-overflowing index must be `VarintTooLong`, and a
                    // non-minimal one is the malleability shape.
                    const v: u64 = if (smith.boolWeighted(2, 1)) smith.value(u32) else smith.value(u64);
                    n += fuzzWriteVarintPadded(buf[n..], v, smith.valueRangeAtMost(u8, 0, 9));
                },
                0x12 => {
                    const claimed: u64 = if (smith.boolWeighted(4, 1))
                        smith.valueRangeAtMost(u8, 0, 32)
                    else
                        smith.value(u64);
                    n += fuzzWriteVarintPadded(buf[n..], claimed, smith.valueRangeAtMost(u8, 0, 3));
                    const room = buf.len - suffix_len - n;
                    const want: usize = @min(@as(usize, @intCast(@min(claimed, 32))), room);
                    n += smith.slice(buf[n..][0..want]);
                },
                else => {},
            }
        }
        // The fixed suffix: 8-byte MAC + 64-byte Ed25519 signature. Its
        // CONTENT is irrelevant to `decode` (verification lives in
        // session.zig), but its 72-byte presence is what separates a
        // walkable payload from `MessageTooShort`.
        const suffix_room = @min(suffix_len, buf.len - n);
        n += smith.slice(buf[n..][0..suffix_room]);
    }

    if (Message.decode(allocator, buf[0..n])) |msg| {
        var m = msg;
        m.deinit(allocator);
    } else |_| {}

    // Same bytes through the base64 wrapper, plus (sometimes) a corrupted
    // alphabet so `base64Decode`'s own reject paths are reached.
    const b64 = try base64Encode(allocator, buf[0..n]);
    defer allocator.free(b64);
    if (b64.len > 0 and smith.boolWeighted(3, 1)) b64[smith.index(b64.len)] = smith.value(u8);
    if (Message.fromBase64(allocator, b64)) |msg| {
        var m = msg;
        m.deinit(allocator);
    } else |_| {}
}
