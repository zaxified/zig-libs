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
//!
//! ## ⚠ The MAC/signature cover the RECEIVED bytes, not a re-encoding
//!
//! `decode` retains the received `version || payload || mac` span
//! (`received_signed`) and `macBytes`/`signatureBytes` return slices of
//! **that**, so verification authenticates the exact bytes that arrived.
//!
//! They used to re-encode the payload from the decoded fields via
//! `encodePayload`, i.e. they authenticated a CANONICALISED form. Since
//! this decoder — like libolm's and like vodozemac's prost-based one —
//! accepts non-minimal LEB128 varints, reordered fields and duplicates
//! (last wins), that made the wire format malleable: the wave-2 audit
//! (W2-33) rewrote the index varint `0x00` of a real libolm message as
//! `0x80 0x00`, and the resulting 94-byte message — one libolm never
//! emitted — still decrypted to `"Message"` under the UNCHANGED
//! signature. Any dedup / replay / audit cache keyed on the wire bytes
//! (which is how a Matrix client would key one) is defeated by that.
//!
//! libolm is the reference and it authenticates its input buffer
//! directly. In `src/inbound_group_session.c`'s `_decrypt`, after
//! base64-decoding, the SAME `message, message_length` pointer pair is
//! handed to both `_olm_crypto_ed25519_verify(&session->signing_key,
//! message, message_length, message + message_length)` and
//! `megolm_cipher->ops->decrypt(..., message, message_length, ...)` —
//! the received range, never a re-encoding (checked against
//! gitlab.matrix.org master while making this fix). So this is the
//! reference's own behaviour, not an added strictness. Note the
//! deliberate *non*-choice: the decoder is NOT made canonical-only.
//! Rejecting non-minimal varints or reordered fields would make us
//! stricter than libolm/vodozemac accept, and once the authenticated
//! range is the received range it buys nothing — a non-canonical frame
//! can then only come from the holder of the signing key, who could have
//! sent anything anyway. `encode` on a decoded `Message` is byte-
//! identical to its input, which is the property a wire-keyed cache
//! needs; the fuzz harness asserts exactly that.

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
    /// For a DECODED message: an owned copy of the received
    /// `version || payload || mac` bytes — everything the Ed25519
    /// signature covers. `macBytes`/`signatureBytes` return slices of this
    /// so verification authenticates what actually arrived rather than a
    /// canonical re-encoding of the decoded fields (see the module doc
    /// comment; W2-33). `null` for a `Message` built for ENCODING (the
    /// sender defines the canonical bytes), in which case those two
    /// functions fall back to `encodePayload`.
    received_signed: ?[]u8 = null,

    pub fn deinit(self: *Message, allocator: std.mem.Allocator) void {
        allocator.free(self.ciphertext);
        if (self.received_signed) |s| allocator.free(s);
        self.* = undefined;
    }

    /// `version || payload` — the bytes the wire MAC is computed over.
    /// For a decoded message this is the RECEIVED range verbatim, never a
    /// re-encoding. Caller frees.
    pub fn macBytes(self: *const Message, allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        if (self.received_signed) |s| return allocator.dupe(u8, s[0 .. s.len - wire_mac_len]);
        return encodePayload(allocator, self.message_index, self.ciphertext);
    }

    /// `macBytes() || mac` — the bytes the Ed25519 signature is computed
    /// over (spec: "the entire message ... are passed through HMAC-
    /// SHA-256 ... Finally, the authenticated message is signed"). For a
    /// decoded message this is the RECEIVED range verbatim. Caller frees.
    pub fn signatureBytes(self: *const Message, allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        if (self.received_signed) |s| return allocator.dupe(u8, s);
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

        // The signed range EXACTLY as received: version || payload || mac.
        // This is what the MAC and the Ed25519 signature must be checked
        // against — see the module doc comment (W2-33).
        const received_signed = try allocator.dupe(u8, bytes[0 .. bytes.len - signature_len]);
        errdefer allocator.free(received_signed);

        return .{
            .message_index = index,
            .ciphertext = ciphertext,
            .mac = mac_bytes.*,
            .signature = sig_bytes.*,
            .received_signed = received_signed,
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

// ── W2-33: the authenticated range is the RECEIVED range ────────────────

test "W2-33: signatureBytes/macBytes on a decoded message are the received bytes verbatim" {
    var msg = try dummyMessage(testing.allocator);
    defer msg.deinit(testing.allocator);

    // Re-encode the SAME logical message with a deliberately non-minimal
    // index varint (0 written as `0x80 0x00`) — a shape this decoder, like
    // libolm's and vodozemac's, accepts. Its decoded FIELDS are identical
    // to the minimal encoding's, so a canonical-re-encoding verifier
    // cannot tell the two apart. Its BYTES must be what gets authenticated.
    const noncanon = try nonMinimalIndexEncoding(testing.allocator, 0, msg.ciphertext, msg.mac, msg.signature);
    defer testing.allocator.free(noncanon);

    var decoded = try Message.decode(testing.allocator, noncanon);
    defer decoded.deinit(testing.allocator);
    try testing.expectEqual(@as(u32, 0), decoded.message_index);

    const sig_range = try decoded.signatureBytes(testing.allocator);
    defer testing.allocator.free(sig_range);
    try testing.expectEqualSlices(u8, noncanon[0 .. noncanon.len - signature_len], sig_range);

    const mac_range = try decoded.macBytes(testing.allocator);
    defer testing.allocator.free(mac_range);
    try testing.expectEqualSlices(u8, noncanon[0 .. noncanon.len - suffix_len], mac_range);

    // The canonical re-encoding of the same fields is a DIFFERENT byte
    // string — which is exactly why authenticating it was a hole.
    const reencoded = try encodePayload(testing.allocator, decoded.message_index, decoded.ciphertext);
    defer testing.allocator.free(reencoded);
    try testing.expect(!std.mem.eql(u8, reencoded, mac_range));
}

test "W2-33: decode -> encode is byte-identical, including for a non-canonical frame" {
    var msg = try dummyMessage(testing.allocator);
    defer msg.deinit(testing.allocator);
    const raw = try msg.encode(testing.allocator);
    defer testing.allocator.free(raw);

    const noncanon = try nonMinimalIndexEncoding(testing.allocator, 42, msg.ciphertext, msg.mac, msg.signature);
    defer testing.allocator.free(noncanon);
    try testing.expect(!std.mem.eql(u8, raw, noncanon));

    for ([_][]const u8{ raw, noncanon }) |input| {
        var decoded = try Message.decode(testing.allocator, input);
        defer decoded.deinit(testing.allocator);
        const round_tripped = try decoded.encode(testing.allocator);
        defer testing.allocator.free(round_tripped);
        // A wire-keyed dedup/replay cache is only sound if this holds.
        try testing.expectEqualSlices(u8, input, round_tripped);
    }
}

/// `version || 0x08 || varint(index) padded to 2 bytes || 0x12 ||
/// varint(len) || ciphertext || mac || signature`. Structurally legal,
/// accepted by this decoder and by libolm's, but NOT the canonical form
/// `encodePayload` produces. Caller frees.
fn nonMinimalIndexEncoding(
    allocator: std.mem.Allocator,
    index: u32,
    ciphertext: []const u8,
    mac: [wire_mac_len]u8,
    signature: [signature_len]u8,
) std.mem.Allocator.Error![]u8 {
    var hdr: [1 + 11 + 1 + 10]u8 = undefined;
    var pos: usize = 0;
    hdr[pos] = version;
    pos += 1;
    hdr[pos] = 0x08;
    pos += 1;
    // index with one extra continuation group (the audit's `0x80 0x00`
    // shape when index == 0).
    const n = writeVarint(hdr[pos..], index);
    hdr[pos + n - 1] |= 0x80;
    hdr[pos + n] = 0x00;
    pos += n + 1;
    hdr[pos] = 0x12;
    pos += 1;
    pos += writeVarint(hdr[pos..], @as(u64, ciphertext.len));

    const out = try allocator.alloc(u8, pos + ciphertext.len + suffix_len);
    @memcpy(out[0..pos], hdr[0..pos]);
    @memcpy(out[pos..][0..ciphertext.len], ciphertext);
    @memcpy(out[pos + ciphertext.len ..][0..wire_mac_len], &mac);
    @memcpy(out[pos + ciphertext.len + wire_mac_len ..][0..signature_len], &signature);
    return out;
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
        defer m.deinit(allocator);
        // ORACLE (W2-33), not just "does not crash": whatever `decode`
        // accepts, `encode` must reproduce BYTE-IDENTICALLY. That is the
        // property a dedup/replay cache keyed on the wire bytes depends
        // on, and it is exactly what the canonical-re-encoding
        // `macBytes`/`signatureBytes` broke — this assertion fires on any
        // input whose accepted encoding is not the canonical one
        // (non-minimal varints, reordering, duplicates), which the payload
        // generator above deliberately produces.
        const re = try m.encode(allocator);
        defer allocator.free(re);
        try testing.expectEqualSlices(u8, buf[0..n], re);
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
