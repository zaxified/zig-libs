// SPDX-License-Identifier: MIT
//! BOLT#4 "Packet Structure": the fixed 1366-byte on-wire onion packet —
//! `version(1) ‖ public_key(33) ‖ hop_payloads(1300) ‖ hmac(32)`. This is
//! pure wire framing: parsing/serializing the four
//! fixed-size fields, plus the one structural check BOLT#4's "Onion
//! Decryption" §Requirements assigns to this layer — that `public_key` is a
//! well-formed compressed secp256k1 point ("if `public_key` is not a valid
//! pubkey: MUST abort processing the packet and fail"). Everything else
//! (deriving the shared secret from that key, obfuscating/verifying
//! `hop_payloads`) is `core.zig`'s job.

const std = @import("std");
const Secp256k1 = @import("k256").Secp256k1;

/// BOLT#4 "Packet Structure": "For this specification (version 0),
/// `version` has a constant value of `0x00`."
pub const version_byte: u8 = 0x00;

/// Compressed secp256k1 public key length (SEC1 `0x02`/`0x03` prefix + 32
/// bytes of `x`).
pub const pubkey_len: usize = 33;

/// BOLT#4 "Packet Structure": the fixed size of the (obfuscated)
/// `hop_payloads` field, regardless of how many hops are actually used.
pub const hop_payloads_len: usize = 1300;

/// BOLT#4 "Packet Structure": the packet-integrity HMAC-SHA256 output size.
pub const hmac_len: usize = 32;

/// `1 (version) + 33 (public_key) + 1300 (hop_payloads) + 32 (hmac)`.
pub const packet_len: usize = 1 + pubkey_len + hop_payloads_len + hmac_len;

comptime {
    std.debug.assert(packet_len == 1366);
}

pub const ParseError = error{
    /// `bytes.len != packet_len` — the caller handed this a slice API
    /// instead of the fixed-size wire form (`fromBytes` below only takes
    /// the exact-size array, so this only applies to `fromSlice`).
    WrongLength,
    /// BOLT#4 "Onion Decryption": "if `version` is not 0: MUST abort
    /// processing the packet and fail."
    UnsupportedVersion,
    /// BOLT#4 "Onion Decryption": "if `public_key` is not a valid pubkey:
    /// MUST abort processing the packet and fail" — the 33 bytes do not
    /// decode to an on-curve compressed secp256k1 point
    /// (`Secp256k1.fromSec1`'s `error.InvalidEncoding`/`error.NotSquare`/
    /// `error.NonCanonicalEncoding`, collapsed to this one case here).
    InvalidPublicKey,
};

/// The BOLT#4 onion packet: a `version` byte, a 33-byte compressed
/// ephemeral `public_key`, the (obfuscated) 1300-byte `hop_payloads`
/// blob, and the packet-integrity `hmac`. All four fields are plain wire
/// bytes at this layer — `hop_payloads` is opaque here (its internal
/// per-hop framing is `hopframe.zig`'s concern; whether `hmac` actually
/// verifies against `hop_payloads ‖ associated_data` is `core.zig`'s
/// concern).
pub const OnionPacket = struct {
    version: u8 = version_byte,
    public_key: [pubkey_len]u8,
    hop_payloads: [hop_payloads_len]u8,
    hmac: [hmac_len]u8,

    pub const encoded_length = packet_len;

    /// Parse the fixed 1366-byte wire form. Enforces both packet-level
    /// checks BOLT#4 "Onion Decryption" assigns before any crypto runs:
    /// `version == 0` and `public_key` decodes to a valid on-curve
    /// compressed secp256k1 point. Does NOT verify `hmac` (that requires
    /// the shared secret — `core.zig`'s `process`).
    pub fn fromBytes(bytes: [packet_len]u8) ParseError!OnionPacket {
        const version = bytes[0];
        if (version != version_byte) return error.UnsupportedVersion;

        const public_key = bytes[1..][0..pubkey_len].*;
        _ = Secp256k1.fromSec1(&public_key) catch return error.InvalidPublicKey;

        const hop_payloads = bytes[1 + pubkey_len ..][0..hop_payloads_len].*;
        const hmac = bytes[1 + pubkey_len + hop_payloads_len ..][0..hmac_len].*;

        return .{
            .version = version,
            .public_key = public_key,
            .hop_payloads = hop_payloads,
            .hmac = hmac,
        };
    }

    /// Same as `fromBytes`, but accepts a runtime-length slice (e.g. bytes
    /// straight off the wire) and rejects anything not exactly
    /// `packet_len` long before delegating.
    pub fn fromSlice(bytes: []const u8) ParseError!OnionPacket {
        if (bytes.len != packet_len) return error.WrongLength;
        return fromBytes(bytes[0..packet_len].*);
    }

    /// Serialize back to the fixed 1366-byte wire form
    /// (`fromBytes(pkt.toBytes()) == pkt` for any packet built through
    /// `fromBytes`, since every field width is exact and there is no
    /// padding).
    pub fn toBytes(pkt: OnionPacket) [packet_len]u8 {
        var out: [packet_len]u8 = undefined;
        out[0] = pkt.version;
        out[1..][0..pubkey_len].* = pkt.public_key;
        out[1 + pubkey_len ..][0..hop_payloads_len].* = pkt.hop_payloads;
        out[1 + pubkey_len + hop_payloads_len ..][0..hmac_len].* = pkt.hmac;
        return out;
    }
};

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

fn hexBytes(comptime len: usize, hex_str: []const u8) [len]u8 {
    var out: [len]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex_str) catch unreachable;
    return out;
}

test "packet_len is 1366 (1 + 33 + 1300 + 32)" {
    try testing.expectEqual(@as(usize, 1366), packet_len);
}

test "fromBytes/toBytes round-trip on a synthetic packet" {
    var hop_payloads: [hop_payloads_len]u8 = undefined;
    for (&hop_payloads, 0..) |*b, i| b.* = @truncate(i);
    const pkt = OnionPacket{
        .public_key = hexBytes(pubkey_len, "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619"),
        .hop_payloads = hop_payloads,
        .hmac = [_]u8{0xab} ** hmac_len,
    };
    const bytes = pkt.toBytes();
    const parsed = try OnionPacket.fromBytes(bytes);
    try testing.expectEqual(pkt.version, parsed.version);
    try testing.expectEqualSlices(u8, &pkt.public_key, &parsed.public_key);
    try testing.expectEqualSlices(u8, &pkt.hop_payloads, &parsed.hop_payloads);
    try testing.expectEqualSlices(u8, &pkt.hmac, &parsed.hmac);
    try testing.expectEqualSlices(u8, &bytes, &parsed.toBytes());
}

test "fromBytes rejects a non-zero version byte" {
    var bytes = [_]u8{0} ** packet_len;
    bytes[0] = 1;
    // Fill in a valid pubkey so UnsupportedVersion is the only possible failure.
    bytes[1..][0..pubkey_len].* = hexBytes(pubkey_len, "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619");
    try testing.expectError(error.UnsupportedVersion, OnionPacket.fromBytes(bytes));
}

test "fromBytes rejects an invalid public_key encoding" {
    var bytes = [_]u8{0} ** packet_len;
    bytes[0] = version_byte;
    // 0x01 is not one of SEC1's defined encoding-type bytes (0 = identity,
    // 2/3 = compressed, 4 = uncompressed) — `Secp256k1.fromSec1` rejects it
    // unconditionally, regardless of the following bytes.
    bytes[1] = 0x01;
    try testing.expectError(error.InvalidPublicKey, OnionPacket.fromBytes(bytes));
}

test "fromSlice rejects the wrong length" {
    try testing.expectError(error.WrongLength, OnionPacket.fromSlice(&.{ 1, 2, 3 }));
}

// ── fuzz: the untrusted-wire entry point never panics/OOB ──────────────────

const fuzzseed = @import("testkit").fuzz;

/// `packet_len` plus a margin, so lengths on BOTH sides of the exact-length
/// gate are reachable. A seed larger than this reads back EMPTY — which is
/// why the corpus below stops at `packet_len + 8` and not at the buffer.
const decode_buf_len = packet_len + 32;

/// A wire packet assembled at comptime, so a 1366-octet seed can be a
/// `comptime` literal. `fromSlice` refuses anything that is not exactly
/// `packet_len`, so a corpus of short strings would only ever reach
/// `error.WrongLength` and nothing behind it.
fn wire(
    comptime version: u8,
    comptime pubkey_hex: []const u8,
    comptime payload_fill: u8,
    comptime hmac_fill: u8,
    comptime extra: usize,
) [packet_len + extra]u8 {
    @setEvalBranchQuota(200_000);
    var out: [packet_len + extra]u8 = undefined;
    @memset(out[0..], 0);
    out[0] = version;
    var key: [pubkey_len]u8 = undefined;
    _ = std.fmt.hexToBytes(&key, pubkey_hex) catch unreachable;
    out[1..][0..pubkey_len].* = key;
    @memset(out[1 + pubkey_len ..][0..hop_payloads_len], payload_fill);
    @memset(out[1 + pubkey_len + hop_payloads_len ..][0..hmac_len], hmac_fill);
    return out;
}

/// The compressed secp256k1 point the value tests above use — the one pubkey
/// in this module known to be on the curve.
const good_pubkey_hex = "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619";

/// The accepted packet, kept as a named constant so a truncation of it can
/// be spelled as a slice.
const good_packet = wire(version_byte, good_pubkey_hex, 0x00, 0x00, 0);

const decode_seeds = [_][]const u8{
    fuzzseed.seed(""), // the empty slice: exactly what the collapsed draw ran, for ever
    fuzzseed.seed(&.{ 1, 2, 3 }), // the WrongLength case the value test uses
    fuzzseed.seed(&good_packet), // ⭐ a complete, accepted packet
    fuzzseed.seed(&wire(version_byte, good_pubkey_hex, 0xff, 0xff, 0)), // the same, all-ones payload and hmac: `toBytes` must round-trip it
    fuzzseed.seed(&wire(version_byte, "03eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619", 0x5a, 0xa5, 0)), // the odd-y sign byte for the same x
    fuzzseed.seed(&wire(1, good_pubkey_hex, 0x00, 0x00, 0)), // UnsupportedVersion, with a valid key so nothing else can fail first
    fuzzseed.seed(&wire(0xff, good_pubkey_hex, 0x00, 0x00, 0)), // the same at the far end of the version octet
    fuzzseed.seed(&wire(version_byte, "01" ++ "00" ** 32, 0x00, 0x00, 0)), // 0x01 is not a SEC1 encoding type: InvalidPublicKey
    fuzzseed.seed(&wire(version_byte, "00" ** 33, 0x00, 0x00, 0)), // 33 zero octets: the identity encoding padded out
    fuzzseed.seed(&wire(version_byte, "02" ++ "00" ** 32, 0x00, 0x00, 0)), // ⭐ a well-formed prefix over x = 0, which is not on the curve
    fuzzseed.seed(&wire(version_byte, "02" ++ "ff" ** 32, 0x00, 0x00, 0)), // x above the field prime: the non-canonical branch
    fuzzseed.seed(good_packet[0 .. packet_len - 1]), // ⭐ one octet short of the exact length
    fuzzseed.seed(&wire(version_byte, good_pubkey_hex, 0x00, 0x00, 1)), // ⭐ one octet over
    fuzzseed.seed(&wire(version_byte, good_pubkey_hex, 0x00, 0x00, 8)), // eight over, still inside the buffer
};

fn fuzzOnionPacketDecode(_: void, smith: *std.testing.Smith) !void {
    var buf: [decode_buf_len]u8 = undefined;
    // ⚠ One `smith.slice`, never `bytes` then a ranged draw. `bytes` consumes
    // `@min(buf.len, in.len)` octets, so the ranged length that followed found
    // fewer than the eight it reads as a little-endian `u64` and returned the
    // range MINIMUM: `len` was 0 for every input this lane can carry, and
    // `fromSlice` refused it with `error.WrongLength` before touching a byte.
    // `fromBytes` — the version check, the SEC1 decode, and `toBytes` behind
    // it — had never run from this target at all. Measured 2026-09-07 over the
    // corpus: 0 of 14 seeds arrived non-empty and 0 packets parsed before;
    // 13 of 14 and 3 after.
    const len: usize = smith.slice(&buf);
    const pkt = OnionPacket.fromSlice(buf[0..len]) catch return;
    _ = pkt.toBytes();
}
test "fuzz OnionPacket.fromSlice never panics" {
    try testing.fuzz({}, fuzzOnionPacketDecode, .{ .corpus = &decode_seeds });
}

test "corpus: every seed reaches fromSlice, and which of them get past the length gate is pinned" {
    // ⭐ The trap here is the opposite of an `accepted > 0` guard: `fromSlice`
    // is an EXACT-length gate, so a seed that is one octet off — or one that
    // overran the buffer and read back empty — never reaches the version
    // check or the SEC1 decode at all. So the numbers pinned are how many
    // seeds passed the length gate (`WrongLength` vs everything else) and how
    // many of those parsed; a corpus of only-refusals would show as
    // `past_length == accepted == 0`.
    var nonempty: usize = 0;
    var past_length: usize = 0;
    var accepted: usize = 0;
    var round_tripped: usize = 0;
    for (decode_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [decode_buf_len]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        if (len == packet_len) past_length += 1;
        if (OnionPacket.fromSlice(buf[0..len])) |pkt| {
            accepted += 1;
            if (std.mem.eql(u8, buf[0..len], &pkt.toBytes())) round_tripped += 1;
        } else |_| {}
    }
    // One seed is deliberately the empty slice.
    try testing.expectEqual(decode_seeds.len - 1, nonempty);
    // Measured 2026-09-07. Before the draw was restructured all three were 0:
    // the only input this target ever handed `fromSlice` was the empty slice,
    // which `error.WrongLength` refuses on the first line.
    try testing.expectEqual(@as(usize, 9), past_length);
    try testing.expectEqual(@as(usize, 3), accepted);
    try testing.expectEqual(accepted, round_tripped);
}
