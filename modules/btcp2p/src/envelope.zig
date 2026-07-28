// SPDX-License-Identifier: MIT
//! The Bitcoin P2P message envelope: 4-byte network magic, the 12-byte
//! NUL-padded command string, the little-endian payload length, and the
//! double-SHA256 checksum (`bitcointx.hash256.sha256d(payload)[0..4]`) --
//! the untrusted-input boundary every other message in this module sits
//! behind. `decodeMessage` is the one function a caller reading off a raw
//! TCP stream needs: it validates magic, checksum, and an upper bound on
//! payload size *before* handing back a borrowed payload slice, so
//! nothing downstream ever sees a wrong-network, corrupted, or
//! oversized-claim payload.
//!
//! ## Threat model
//!
//! `decodeMessage` is the one function in this whole module that faces a
//! byte stream directly controlled by a remote peer before any other
//! validation has run. Three fail-closed checks, in order:
//!
//! 1. **Magic** -- the leading 4 bytes must match the caller's expected
//!    `Network`; a mismatched magic is usually a sign of stream
//!    desync (or a peer on the wrong network) and is rejected outright
//!    (`error.BadMagic`) rather than resynchronized here (resynchronizing
//!    a byte stream is a connection-lifecycle concern -- out of scope for
//!    a codec, see `SPEC.md`).
//! 2. **Declared length vs. a hard ceiling** -- `length` is checked
//!    against `MAX_PAYLOAD_LENGTH` *before* it is used to slice `bytes`,
//!    so a hostile 4-byte length field claiming gigabytes can never be
//!    used to demand an allocation or a slice past what's actually
//!    present (`error.PayloadTooLarge`), independent of and prior to the
//!    ordinary `error.Truncated` bounds check against `bytes.len`.
//! 3. **Checksum** -- `sha256d(payload)`'s first 4 bytes must match the
//!    header's `checksum` field (`error.BadChecksum`), so a
//!    bit-corrupted-in-transit or deliberately-tampered payload is
//!    rejected before any per-message decoder ever sees it.
//!
//! Only after all three does `decodeMessage` return -- every message
//! decoder in this module (`handshake.zig`, `inventory.zig`, `block.zig`,
//! ...) can then assume its input already passed the envelope gate.

const std = @import("std");
const Allocator = std.mem.Allocator;
const bitcointx = @import("bitcointx");

/// Which of Bitcoin's deployed networks a message belongs to -- each has
/// its own magic bytes so nodes never cross-parse messages from the
/// wrong chain. `namecoin` (a distinct 5th magic sharing Bitcoin's wire
/// format) is out of scope: this module only names the four Bitcoin
/// networks a caller of this repo would actually run.
pub const Network = enum {
    mainnet,
    testnet3,
    regtest,
    signet,
};

/// Magic bytes as sent on the wire (raw bytes, not decoded as an
/// integer). Source: the Bitcoin Developer Reference / wiki protocol
/// documentation's "Known magic values" table
/// (en.bitcoin.it/wiki/Protocol_documentation), cross-checked against
/// Bitcoin Core's `src/chainparams.cpp` `pchMessageStart` for each
/// network (mainnet/testnet3/regtest byte-identical; `signet` here is
/// the *default* signet magic -- a custom-challenge signet computes its
/// own magic from the challenge script, out of scope for a fixed table).
pub fn magic(network: Network) [4]u8 {
    return switch (network) {
        .mainnet => .{ 0xf9, 0xbe, 0xb4, 0xd9 },
        .testnet3 => .{ 0x0b, 0x11, 0x09, 0x07 },
        .regtest => .{ 0xfa, 0xbf, 0xb5, 0xda },
        .signet => .{ 0x0a, 0x03, 0xcf, 0x40 },
    };
}

/// Reverse lookup of `magic` -- `null` if `bytes` matches none of the
/// four known networks (a caller listening for any of several networks
/// on one socket, e.g. a test harness, can use this instead of trying
/// each `Network` in turn).
pub fn networkFromMagic(bytes: [4]u8) ?Network {
    const all = [_]Network{ .mainnet, .testnet3, .regtest, .signet };
    for (all) |n| {
        if (std.mem.eql(u8, &bytes, &magic(n))) return n;
    }
    return null;
}

pub const COMMAND_LEN = 12;
pub const HEADER_LEN = 4 + COMMAND_LEN + 4 + 4; // magic + command + length + checksum = 24

/// Bitcoin Core's `MAX_PROTOCOL_MESSAGE_LENGTH` (`src/net.h`,
/// github.com/bitcoin/bitcoin) -- the ceiling every mainline node
/// enforces on an incoming message's declared payload length, checked by
/// `decodeMessage` *before* that length is used to size anything.
pub const MAX_PAYLOAD_LENGTH: u32 = 4_000_000;

pub const DecodeError = error{
    /// Fewer than `HEADER_LEN` bytes present, or fewer bytes remain than
    /// the header's declared `length` promises.
    Truncated,
    /// The leading 4 bytes don't match the caller's expected `Network`.
    BadMagic,
    /// The header's declared `length` exceeds `MAX_PAYLOAD_LENGTH`,
    /// rejected before it is ever used to slice or allocate.
    PayloadTooLarge,
    /// `sha256d(payload)[0..4]` doesn't match the header's `checksum`.
    BadChecksum,
};

/// One decoded message: the raw (NUL-padded) command string and a
/// borrowed view of the payload (see module doc comment -- `bytes`
/// passed to `decodeMessage` must outlive this).
pub const Message = struct {
    command: [COMMAND_LEN]u8,
    payload: []const u8,

    /// The command with its NUL padding stripped, e.g. `"version"` not
    /// `"version\x00\x00\x00\x00\x00"`.
    pub fn commandName(self: Message) []const u8 {
        const end = std.mem.indexOfScalar(u8, &self.command, 0) orelse self.command.len;
        return self.command[0..end];
    }
};

pub const DecodedMessage = struct {
    message: Message,
    /// Bytes consumed from the front of the input -- `HEADER_LEN +
    /// payload.len`. Lets a caller reading several messages back-to-back
    /// off a stream buffer advance past exactly one message.
    consumed: usize,
};

/// Decodes one message envelope from the front of `bytes` against the
/// expected `network` -- see module doc comment for the exact
/// fail-closed check order. `bytes` may hold more than one message (only
/// the first `HEADER_LEN + length` bytes are consumed and returned; see
/// `DecodedMessage.consumed`).
pub fn decodeMessage(bytes: []const u8, network: Network) DecodeError!DecodedMessage {
    if (bytes.len < HEADER_LEN) return error.Truncated;
    if (!std.mem.eql(u8, bytes[0..4], &magic(network))) return error.BadMagic;

    var command: [COMMAND_LEN]u8 = undefined;
    @memcpy(&command, bytes[4..16]);

    const length = std.mem.readInt(u32, bytes[16..20], .little);
    if (length > MAX_PAYLOAD_LENGTH) return error.PayloadTooLarge;

    const checksum = bytes[20..24];
    const total: u64 = @as(u64, HEADER_LEN) + length;
    if (total > bytes.len) return error.Truncated;
    const payload = bytes[HEADER_LEN..][0..length];

    const digest = bitcointx.hash256.sha256d(payload);
    if (!std.mem.eql(u8, digest[0..4], checksum)) return error.BadChecksum;

    return .{
        .message = .{ .command = command, .payload = payload },
        .consumed = @intCast(total),
    };
}

pub const EncodeError = Allocator.Error || error{
    /// `command_name.len` exceeds `COMMAND_LEN` (12) -- every deployed
    /// command name fits (`"version"` is the longest of the messages
    /// this module implements at 7), so this only fires on a caller
    /// programming error, not untrusted input.
    CommandTooLong,
    /// `payload.len` exceeds `MAX_PAYLOAD_LENGTH` -- refuses to produce a
    /// message no compliant peer would accept.
    PayloadTooLarge,
};

/// Builds one complete wire message: magic + NUL-padded command + length
/// + checksum + `payload`. `payload` is typically the output of one of
/// this module's other `serialize*` functions (or `bitcointx.serialize`
/// for a `tx` message).
pub fn encodeMessage(allocator: Allocator, network: Network, command_name: []const u8, payload: []const u8) EncodeError![]u8 {
    if (command_name.len > COMMAND_LEN) return error.CommandTooLong;
    if (payload.len > MAX_PAYLOAD_LENGTH) return error.PayloadTooLarge;

    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.appendSlice(allocator, &magic(network));

    var command: [COMMAND_LEN]u8 = @splat(0);
    @memcpy(command[0..command_name.len], command_name);
    try buf.appendSlice(allocator, &command);

    var length_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &length_bytes, @intCast(payload.len), .little);
    try buf.appendSlice(allocator, &length_bytes);

    const digest = bitcointx.hash256.sha256d(payload);
    try buf.appendSlice(allocator, digest[0..4]);

    try buf.appendSlice(allocator, payload);
    return buf.toOwnedSlice(allocator);
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

// ── externally anchored: Bitcoin wiki's own annotated hex dumps ──────────
// (en.bitcoin.it/wiki/Protocol_documentation, fetched directly -- not
// hand-transcribed from memory) -- the checksum bytes and magic bytes are
// exactly as published, not self-derived.

test "external: verack envelope byte-exact against the wiki's published hex dump" {
    // "Hexdump of the verack message": magic + "verack" command (NUL
    // padded to 12) + zero-length payload + its published checksum
    // (sha256d of the empty string, first 4 bytes).
    const wire = [_]u8{
        0xf9, 0xbe, 0xb4, 0xd9, // magic (mainnet)
        0x76, 0x65, 0x72, 0x61, 0x63, 0x6b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // "verack"
        0x00, 0x00, 0x00, 0x00, // length = 0
        0x5d, 0xf6, 0xe0, 0xe2, // checksum (published)
    };
    const decoded = try decodeMessage(&wire, .mainnet);
    try testing.expectEqualStrings("verack", decoded.message.commandName());
    try testing.expectEqual(@as(usize, 0), decoded.message.payload.len);
    try testing.expectEqual(wire.len, decoded.consumed);

    // in-house cross-check: sha256d("")'s first 4 bytes really are the
    // wiki's published checksum, not just "decodeMessage happens to
    // agree with itself".
    const empty_digest = bitcointx.hash256.sha256d(&.{});
    try testing.expectEqualSlices(u8, &.{ 0x5d, 0xf6, 0xe0, 0xe2 }, empty_digest[0..4]);
}

test "external: version message envelope (protocol 60002, wiki's modern example) checksum verifies" {
    // "And here's a modern (60002) protocol version client advertising
    // itself..." -- the wiki's second version-message example, the first
    // to include a real checksum. Payload bytes themselves are exercised
    // byte-field-by-field in handshake.zig's tests; this test is only
    // about the envelope (magic/length/checksum), so the payload is
    // reproduced but not further decoded here.
    const wire = [_]u8{
        0xf9, 0xbe, 0xb4, 0xd9, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x64, 0x00, 0x00, 0x00, 0x35, 0x8d, 0x49, 0x32, 0x62, 0xea, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x11, 0xb2, 0xd0, 0x50, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x3b, 0x2e, 0xb3, 0x5d, 0x8c, 0xe6, 0x17, 0x65, 0x0f, 0x2f, 0x53, 0x61, 0x74, 0x6f, 0x73, 0x68,
        0x69, 0x3a, 0x30, 0x2e, 0x37, 0x2e, 0x32, 0x2f, 0xc0, 0x3e, 0x03, 0x00,
    };
    const decoded = try decodeMessage(&wire, .mainnet);
    try testing.expectEqualStrings("version", decoded.message.commandName());
    try testing.expectEqual(@as(usize, 100), decoded.message.payload.len);
    try testing.expectEqual(wire.len, decoded.consumed);
}

test "networkFromMagic round-trips every known network's magic" {
    const all = [_]Network{ .mainnet, .testnet3, .regtest, .signet };
    for (all) |n| {
        try testing.expectEqual(@as(?Network, n), networkFromMagic(magic(n)));
    }
    try testing.expectEqual(@as(?Network, null), networkFromMagic(.{ 0, 0, 0, 0 }));
}

test "self round-trip: encodeMessage -> decodeMessage recovers command + payload" {
    const allocator = testing.allocator;
    const payload = "hello, peer";
    const wire = try encodeMessage(allocator, .testnet3, "myecho", payload);
    defer allocator.free(wire);

    const decoded = try decodeMessage(wire, .testnet3);
    try testing.expectEqualStrings("myecho", decoded.message.commandName());
    try testing.expectEqualSlices(u8, payload, decoded.message.payload);
}

test "hostile: wrong network magic is rejected" {
    const allocator = testing.allocator;
    const wire = try encodeMessage(allocator, .mainnet, "x", "y");
    defer allocator.free(wire);
    try testing.expectError(error.BadMagic, decodeMessage(wire, .testnet3));
}

test "hostile: tampered payload fails checksum" {
    const allocator = testing.allocator;
    var wire = try encodeMessage(allocator, .mainnet, "x", "abc");
    defer allocator.free(wire);
    wire[wire.len - 1] ^= 0xff; // flip a payload byte after the checksum was computed
    try testing.expectError(error.BadChecksum, decodeMessage(wire, .mainnet));
}

test "hostile: a length field claiming more than MAX_PAYLOAD_LENGTH is rejected before any slicing" {
    var header: [HEADER_LEN]u8 = undefined;
    @memcpy(header[0..4], &magic(.mainnet));
    @memset(header[4..16], 0);
    std.mem.writeInt(u32, header[16..20], MAX_PAYLOAD_LENGTH + 1, .little);
    @memset(header[20..24], 0);
    try testing.expectError(error.PayloadTooLarge, decodeMessage(&header, .mainnet));
}

test "hostile: a length field claiming more bytes than actually follow fails closed (not OOB)" {
    var header: [HEADER_LEN]u8 = undefined;
    @memcpy(header[0..4], &magic(.mainnet));
    @memset(header[4..16], 0);
    std.mem.writeInt(u32, header[16..20], 1000, .little); // claims 1000 bytes, none follow
    @memset(header[20..24], 0);
    try testing.expectError(error.Truncated, decodeMessage(&header, .mainnet));
}

test "hostile: fewer than HEADER_LEN bytes total fails closed" {
    try testing.expectError(error.Truncated, decodeMessage(&.{ 0xf9, 0xbe, 0xb4, 0xd9 }, .mainnet));
}

test "EncodeError.CommandTooLong: a command name over 12 bytes is rejected" {
    try testing.expectError(error.CommandTooLong, encodeMessage(testing.allocator, .mainnet, "waytoolongcommandname", "x"));
}

// ── fuzz: decodeMessage never panics on an arbitrary byte stream ─────────
//
// This is the untrusted-input boundary for the entire module (see module
// doc comment): every byte a peer ever sends reaches `decodeMessage`
// first. Half the time the harness stamps in a real magic (so the parser
// actually reaches the length/checksum logic instead of always bailing
// on `BadMagic`); the rest is fully arbitrary.
test "fuzz: decodeMessage never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzDecodeMessage, .{});
}

fn fuzzDecodeMessage(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const bytes = buf[0..len];

    const nets = [_]Network{ .mainnet, .testnet3, .regtest, .signet };
    if (bytes.len >= 4 and smith.value(bool)) {
        const idx = smith.valueRangeAtMost(u8, 0, nets.len - 1);
        @memcpy(bytes[0..4], &magic(nets[idx]));
    }

    for (nets) |n| {
        _ = decodeMessage(bytes, n) catch {};
    }
}
