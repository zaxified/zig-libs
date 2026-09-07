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
/// Test-only (`build.zig`'s `test_deps`, never `deps`): fuzz corpus framing.
const testkit = @import("testkit");

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
/// ⛔ The half `--fuzz` hid. The reachability note above was measured under
/// `scripts/fuzz-sweep.sh`, which drives the generator properly — but the
/// ORDINARY lane replays `options.corpus` plus one empty input, and this
/// target had no corpus. With the input exhausted, `smith.boolWeighted(1, 7)`
/// returns its first weight, so the unstructured arm — `n = smith.slice(&buf)`,
/// the length/version gates and the "not even a frame" shapes it exists for —
/// had **never run outside `--fuzz`**, and the structured arm built exactly
/// one deterministic frame. `zig build test-megolm` was exercising one input.
///
/// The byte draw now comes FIRST and unconditionally; the branch afterwards
/// decides whether to keep those octets or rebuild a structured frame over
/// them. A seed is the frame as a `testkit.fuzz` slice seed, then the `u64`
/// words the knobs read — `1` selects the unstructured arm, `0` the generator.
/// Writes the octets `messageRound`'s generator arm reads, in the order it
/// draws them.
/// ⚠ The widths are not uniform and that is the whole point: a scalar draw
/// takes EIGHT octets, an `eos` draw takes ONE, and a `slice` draw takes a
/// `u32` length and then its bytes. A tail written as `u64` words alone goes
/// out of phase at the first `eos` and every draw after it collapses.
const TailWriter = struct {
    buf: [1024]u8 = undefined,
    n: usize = 0,

    fn word(self: *TailWriter, v: u64) void {
        std.mem.writeInt(u64, self.buf[self.n..][0..8], v, .little);
        self.n += 8;
    }

    /// One `eos` draw that says "keep going", then a whole payload field:
    /// the tag discriminant, both arbitrary-tag draws, the tag varint's
    /// padding, and — for the two tags that have a value — the width knob,
    /// the value and its padding.
    fn field(self: *TailWriter, kind: u64, tag: u64, narrow: u64, v: u64) void {
        self.buf[self.n] = 0; // eos: keep going
        self.n += 1;
        self.word(kind);
        self.word(if (kind == 2) tag else 0); // narrow_tag
        self.word(if (kind == 3) tag else 0); // wide_tag
        self.word(0); // padding on the tag varint
        if (tag == 0x08 or tag == 0x12) {
            self.word(narrow);
            self.word(v);
            self.word(0); // padding on the value varint
        }
    }

    /// A `smith.slice` draw: the `u32` length, then the bytes.
    fn bytes(self: *TailWriter, b: []const u8) void {
        std.mem.writeInt(u32, self.buf[self.n..][0..4], @intCast(b.len), .little);
        self.n += 4;
        @memcpy(self.buf[self.n..][0..b.len], b);
        self.n += b.len;
    }

    fn stop(self: *TailWriter) void {
        self.buf[self.n] = 1; // eos: stop
        self.n += 1;
    }

    fn slice(self: *TailWriter) []const u8 {
        return self.buf[0..self.n];
    }
};

const MessageCorpus = struct {
    store: [10 * (4 + 512 + 48 * 8)]u8 = undefined,
    used: usize = 0,
    entries: [10][]const u8 = undefined,
    n: usize = 0,

    fn push(self: *MessageCorpus, frame: []const u8, words: []const u64) void {
        const start = self.used;
        var at = start + testkit.fuzz.seedInto(self.store[start..], frame).len;
        for (words) |w| {
            std.mem.writeInt(u64, self.store[at..][0..8], w, .little);
            at += 8;
        }
        self.entries[self.n] = self.store[start..at];
        self.used = at;
        self.n += 1;
    }

    /// The same, with the tail written octet by octet.
    /// ⛔ Why the generator arm needs this and `push` is not enough: the loop
    /// condition is `smith.eosWeightedSimple`, and an eos draw consumes ONE
    /// octet, not eight. After the first field every later `u64` word in a
    /// `push` tail is read four octets out of phase, which is why the whole
    /// generator produced exactly ONE field on every seed (measured
    /// 2026-09-08: `fields = 1`, `tag_kinds = {1, 0, 0, 0}` over the entire
    /// corpus — the `0x12` ciphertext branch had never run).
    fn pushRaw(self: *MessageCorpus, frame: []const u8, tail: []const u8) void {
        const start = self.used;
        var at = start + testkit.fuzz.seedInto(self.store[start..], frame).len;
        @memcpy(self.store[at..][0..tail.len], tail);
        at += tail.len;
        self.entries[self.n] = self.store[start..at];
        self.used = at;
        self.n += 1;
    }

    fn build(self: *MessageCorpus, a: std.mem.Allocator) []const []const u8 {
        var msg = dummyMessage(a) catch unreachable;
        defer msg.deinit(a);
        const raw = msg.encode(a) catch unreachable;
        const noncanon = nonMinimalIndexEncoding(a, 42, msg.ciphertext, msg.mac, msg.signature) catch unreachable;

        // The unstructured arm (word `1`), which had never run at all. The
        // trailing `0` is the base64-corruption knob: leave the wrapper alone.
        self.push(raw, &.{ 1, 0 }); // a real, canonical frame
        self.push(noncanon, &.{ 1, 0 }); // structurally legal, NOT canonical:
        // this is the input the `decode -> encode` byte-identity oracle exists
        // for, and the one a canonical re-encoding would break.
        self.push(raw[0 .. raw.len - 1], &.{ 1, 0 }); // one octet short of the suffix
        self.push(raw[0..1], &.{ 1, 0 }); // the version byte alone: MessageTooShort
        var wrong_version = a.dupe(u8, raw) catch unreachable;
        wrong_version[0] = 0x02;
        self.push(wrong_version, &.{ 1, 0 }); // UnsupportedVersion
        // The same real frame, but with the base64 wrapper corrupted at
        // offset 0 — `base64Decode`'s own reject path.
        self.push(raw, &.{ 1, 1, 0, 0xff });
        // The generator arm (word `0`): a real version byte, then an index
        // field and a ciphertext field, then the suffix.
        self.push("", &.{ 0, 1, 0, 0, 0, 0, 0, 0 });

        // ⛔ …except it did not. Measured 2026-09-08, the seed above wrote
        // exactly ONE field and then ran out: the `eos` draw that opens each
        // loop iteration eats a single octet, so every `u64` word after it is
        // read out of phase and collapses to its range minimum. `tag_kinds`
        // was `{1, 0, 0, 0}` over the whole corpus — the `0x12` CIPHERTEXT
        // branch, the arbitrary-tag branches and the wide-length knob had
        // never run at all. These two seeds write the tail octet by octet.
        var t: TailWriter = .{};
        t.word(0); // unstructured? no -> the generator
        t.word(0); // arbitrary version byte? no -> a real one
        t.field(0, 0x08, 1, 42); // index = 42, narrow (u32) form
        t.field(1, 0x12, 1, 8); // a ciphertext field, narrow claimed length
        t.bytes("megolmct"); // ...and the 8 octets it claims
        t.stop();
        t.bytes(&([_]u8{0} ** suffix_len)); // the 72-octet MAC + signature
        self.pushRaw("", t.slice());

        var u: TailWriter = .{};
        u.word(0);
        u.word(1); // arbitrary version byte
        u.word(0x99); // ...this one
        u.field(0, 0x08, 0, 0x1_0000_0000); // wide index: VarintTooLong
        u.field(1, 0x12, 0, 0x1_0000_0000); // wide claimed length
        u.bytes("");
        u.field(2, 0x20, 0, 0); // tag_kind 2: an arbitrary NARROW tag
        u.field(3, 0x12_3456, 0, 0); // tag_kind 3: an arbitrary WIDE tag
        u.stop();
        u.bytes(&([_]u8{0} ** suffix_len));
        self.pushRaw("", u.slice());

        self.push("", &.{}); // and the input this target used to run for ever
        return self.entries[0..self.n];
    }
};

test "fuzz: Message.decode / fromBase64 never panic on arbitrary bytes" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var corpus: MessageCorpus = .{};
    try testing.fuzz({}, fuzzMessageDecode, .{ .corpus = corpus.build(arena.allocator()) });
}

test "corpus: the message seeds drive both arms, and the counts are pinned" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var corpus: MessageCorpus = .{};
    // ⭐ Driven through `messageRound`, the same function the fuzzer calls, so
    // the byte-identity oracle and every knob are the harness's own and cannot
    // drift out of order from a hand-copied replay.
    var knobs: MessageKnobs = .{};
    for (corpus.build(arena.allocator())) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        try messageRound(&smith, &knobs);
    }
    // ⛔ `unstructured` was **0** for every input this target ever ran outside
    // `--fuzz`: the whole arm was unreachable in the ordinary lane. And
    // `decoded`/`ciphertext_octets` say the seeds are frames, not shapes that
    // die at the length gate.
    try testing.expectEqual(@as(usize, 6), knobs.unstructured);
    try testing.expectEqual(@as(usize, 4), knobs.decoded);
    try testing.expectEqual(@as(usize, 56), knobs.ciphertext_octets);
    // The knobs INSIDE the generator arm, measured 2026-09-08. Before the two
    // `TailWriter` seeds: `fields = 1`, `tag_kinds = {1, 0, 0, 0}`,
    // `wide_length = 0`, `arbitrary_version = 1`, `decoded = 3`,
    // `ciphertext_octets = 48` — the generator emitted a single index field on
    // every seed and the `0x12` ciphertext branch had never run. Pinned as a
    // histogram, not a total: a total cannot tell "all four tag kinds ran"
    // from "one ran four times", which is the whole question about a
    // discriminant knob.
    try testing.expectEqual(@as(usize, 2), knobs.arbitrary_version);
    try testing.expectEqual(@as(usize, 7), knobs.fields);
    try testing.expectEqualSlices(usize, &[_]usize{ 3, 2, 1, 1 }, &knobs.tag_kinds);
    try testing.expectEqual(@as(usize, 2), knobs.wide_index);
    try testing.expectEqual(@as(usize, 1), knobs.wide_length);
    try testing.expectEqual(@as(usize, 1), knobs.b64_corrupted);
    try testing.expectEqual(@as(usize, 3), knobs.from_b64);
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

/// What one round of `messageRound` chose, so the corpus guard can pin the
/// knobs the harness draws AFTER its byte draw instead of replaying a
/// look-alike of them. ⛔ Every field here is a knob that returns its weight
/// minimum once the input is exhausted; a corpus without a tail pins them all
/// to one value and the branches behind them never run.
const MessageKnobs = struct {
    unstructured: usize = 0,
    arbitrary_version: usize = 0,
    fields: usize = 0,
    tag_kinds: [4]usize = @splat(0),
    wide_index: usize = 0,
    wide_length: usize = 0,
    b64_corrupted: usize = 0,
    decoded: usize = 0,
    ciphertext_octets: usize = 0,
    from_b64: usize = 0,
};

fn fuzzMessageDecode(_: void, smith: *std.testing.Smith) !void {
    var knobs: MessageKnobs = .{};
    return messageRound(smith, &knobs);
}

/// One fuzz iteration, factored out so the guard drives the SAME draws the
/// fuzzer does rather than a copy that can drift out of order.
fn messageRound(smith: *std.testing.Smith, knobs: *MessageKnobs) !void {
    const allocator = testing.allocator;

    var buf: [512]u8 = undefined;
    // The byte draw comes FIRST and unconditionally. It used to sit inside
    // the `boolWeighted(1, 7)` arm, which meant that outside `--fuzz` -- where
    // the input is exhausted and the draw returns its first weight -- the arm
    // never ran and no octet of any seed ever reached `decode`.
    var n: usize = smith.slice(&buf);

    if (smith.boolWeighted(1, 7)) {
        // Minority: the drawn octets ARE the message, so the length/version
        // gates and the "not even a frame" shapes get their own coverage.
        knobs.unstructured += 1;
    } else {
        buf[0] = if (smith.boolWeighted(1, 9)) blk: {
            knobs.arbitrary_version += 1;
            break :blk smith.value(u8);
        } else version;
        n = 1;
        // Payload: a tag/value stream the decoder has to walk.
        while (n + 16 < buf.len - suffix_len and !smith.eosWeightedSimple(4, 1)) {
            // The field tag decides which branch of the payload generator
            // runs, so the DISCRIMINANT must not be a bounded draw: a bounded
            // draw returns its range minimum unless a whole eight-octet word
            // lands inside the range, which would pin every seed on `0x08`.
            // `value(u64)` has full-range weights, so every input word
            // survives and the reduction happens here (the gate's own option
            // 2). The two arbitrary tag values are drawn into their own
            // bindings rather than inline: `check-fuzz-reach`'s R2(c) rule
            // scans the whole `const … = switch …;` initializer for a
            // collapsing call, so an inline `smith.value(u8)` in an ARM reads
            // to it as a collapsing discriminant. Separating them keeps the
            // gate reading the discriminant it is actually about.
            knobs.fields += 1;
            const tag_kind = smith.value(u64) % 4;
            knobs.tag_kinds[@intCast(tag_kind)] += 1;
            const narrow_tag: u64 = smith.value(u8);
            const wide_tag: u64 = smith.value(u64);
            const tag: u64 = switch (tag_kind) {
                0 => 0x08,
                1 => 0x12,
                2 => narrow_tag,
                else => wide_tag,
            };
            n += fuzzWriteVarintPadded(buf[n..], tag, smith.valueRangeAtMost(u8, 0, 3));
            switch (tag) {
                0x08 => {
                    // A u32-overflowing index must be `VarintTooLong`, and a
                    // non-minimal one is the malleability shape.
                    const v: u64 = if (smith.boolWeighted(2, 1)) smith.value(u32) else blk: {
                        knobs.wide_index += 1;
                        break :blk smith.value(u64);
                    };
                    n += fuzzWriteVarintPadded(buf[n..], v, smith.valueRangeAtMost(u8, 0, 9));
                },
                0x12 => {
                    const claimed: u64 = if (smith.boolWeighted(4, 1))
                        smith.valueRangeAtMost(u8, 0, 32)
                    else blk: {
                        knobs.wide_length += 1;
                        break :blk smith.value(u64);
                    };
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
        knobs.decoded += 1;
        knobs.ciphertext_octets += m.ciphertext.len;
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
    if (b64.len > 0 and smith.boolWeighted(3, 1)) {
        b64[smith.index(b64.len)] = smith.value(u8);
        knobs.b64_corrupted += 1;
    }
    if (Message.fromBase64(allocator, b64)) |msg| {
        var m = msg;
        knobs.from_b64 += 1;
        m.deinit(allocator);
    } else |_| {}
}
