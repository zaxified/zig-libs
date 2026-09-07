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
    /// The 12-byte command field is not `IsCommandValid()`-shaped (Bitcoin
    /// Core `CMessageHeader::IsCommandValid()`, `src/protocol.cpp`): every
    /// byte before the first NUL must be printable ASCII (`0x20..0x7E`),
    /// and every byte from the first NUL onward must also be NUL. Without
    /// this, `"version\x00EVIL"` and `"version\x00\x00\x00\x00\x00"` are
    /// indistinguishable to `commandName()` (both cut at the first NUL),
    /// letting a peer smuggle arbitrary bytes past any logging/
    /// rate-limiting/dedup keyed on the command name.
    InvalidCommand,
};

/// Bitcoin Core's `CMessageHeader::IsCommandValid()`: every byte before
/// the first NUL is printable ASCII, every byte from the first NUL
/// onward (inclusive) is NUL. Rejects both a non-printable command byte
/// and "junk after the NUL padding starts" in one pass.
fn isCommandValid(command: [COMMAND_LEN]u8) bool {
    var seen_nul = false;
    for (command) |b| {
        if (seen_nul) {
            if (b != 0) return false;
        } else if (b == 0) {
            seen_nul = true;
        } else if (b < 0x20 or b > 0x7e) {
            return false;
        }
    }
    return true;
}

/// One decoded message: the raw (NUL-padded) command string and a
/// borrowed view of the payload (see module doc comment -- `bytes`
/// passed to `decodeMessage` must outlive this).
pub const Message = struct {
    command: [COMMAND_LEN]u8,
    payload: []const u8,

    /// The command with its NUL padding stripped, e.g. `"version"` not
    /// `"version\x00\x00\x00\x00\x00"`.
    ///
    /// Pointer receiver is load-bearing, not style: `command` is a fixed
    /// array EMBEDDED in `Message` itself (not a slice into memory owned
    /// elsewhere), so a by-value `self` would make the returned slice point
    /// into the callee's own stack-local copy of `Message` -- dangling the
    /// instant this function returns. A caller that consumes the result
    /// immediately in the same expression can appear to work by accident
    /// (the stack slot hasn't been reused yet); one more call in between is
    /// enough to read back poisoned/garbage bytes instead of the command.
    pub fn commandName(self: *const Message) []const u8 {
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
    if (!isCommandValid(command)) return error.InvalidCommand;

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

/// `testkit.fuzz`, for the corpus at the bottom of this file. A corpus entry
/// is NOT the frame: `Smith.slice` reads a little-endian `u32` length first,
/// so a raw envelope would arrive minus its own first four octets (which for
/// a Bitcoin message is exactly the magic). `testkit/src/fuzz.zig` carries
/// the other two hazards.
const testkit = @import("testkit");
const seed = testkit.fuzz.seed;
const seedHex = testkit.fuzz.seedHex;

// ── externally anchored: Bitcoin wiki's own annotated hex dumps ──────────
// (en.bitcoin.it/wiki/Protocol_documentation, fetched directly -- not
// hand-transcribed from memory) -- the checksum bytes and magic bytes are
// exactly as published, not self-derived.

/// "Hexdump of the verack message": magic + "verack" command (NUL padded to
/// 12) + zero-length payload + its published checksum (sha256d of the empty
/// string, first 4 bytes). Container-level so the fuzz corpus below seeds the
/// SAME octets this test anchors, rather than a re-transcription of them.
const verack_wire = [_]u8{
    0xf9, 0xbe, 0xb4, 0xd9, // magic (mainnet)
    0x76, 0x65, 0x72, 0x61, 0x63, 0x6b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // "verack"
    0x00, 0x00, 0x00, 0x00, // length = 0
    0x5d, 0xf6, 0xe0, 0xe2, // checksum (published)
};

test "external: verack envelope byte-exact against the wiki's published hex dump" {
    const wire = verack_wire;
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

/// "And here's a modern (60002) protocol version client advertising
/// itself..." -- the wiki's second version-message example, the first to
/// include a real checksum. Payload bytes themselves are exercised
/// byte-field-by-field in handshake.zig's tests; the test below is only about
/// the envelope (magic/length/checksum). Container-level for the same reason
/// as `verack_wire`.
const version_wire = [_]u8{
    0xf9, 0xbe, 0xb4, 0xd9, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x64, 0x00, 0x00, 0x00, 0x35, 0x8d, 0x49, 0x32, 0x62, 0xea, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x11, 0xb2, 0xd0, 0x50, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x3b, 0x2e, 0xb3, 0x5d, 0x8c, 0xe6, 0x17, 0x65, 0x0f, 0x2f, 0x53, 0x61, 0x74, 0x6f, 0x73, 0x68,
    0x69, 0x3a, 0x30, 0x2e, 0x37, 0x2e, 0x32, 0x2f, 0xc0, 0x3e, 0x03, 0x00,
};

test "external: version message envelope (protocol 60002, wiki's modern example) checksum verifies" {
    const wire = version_wire;
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

// ── externally anchored: Bitcoin Core's src/kernel/chainparams.cpp (fetched
// directly, not hand-transcribed) ──────────────────────────────────────────
// Prior to this, only `mainnet`'s magic had a byte-level external anchor
// (the wiki hex dumps above); `testnet3`/`regtest`/`signet` were pinned only
// by a self round-trip against this same file's own table, which cannot
// notice a mistyped literal. `pchMessageStart` is a plain 4-byte literal for
// testnet3/regtest; `signet`'s default network has no literal at all --
// Core derives it at runtime as the first 4 bytes of
// `sha256d(CompactSize-prefixed default signet challenge script)` (the
// `HashWriter h{}; h << consensus.signet_challenge;` vector-serialization
// convention), so that one is independently *derived* here, not pasted.

test "external: testnet3 magic byte-exact against Core's CTestNetParams::pchMessageStart" {
    try testing.expectEqualSlices(u8, &.{ 0x0b, 0x11, 0x09, 0x07 }, &magic(.testnet3));
}

test "external: regtest magic byte-exact against Core's CRegTestParams::pchMessageStart" {
    try testing.expectEqualSlices(u8, &.{ 0xfa, 0xbf, 0xb5, 0xda }, &magic(.regtest));
}

test "external: signet default magic derives from Core's published default challenge script" {
    // Core's default signet challenge (SigNetParams, `!options.challenge`
    // branch): a 71-byte 2-of-2 P2MS challenge script, published as a hex
    // literal in chainparams.cpp.
    const challenge = "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae";
    var challenge_bytes: [challenge.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&challenge_bytes, challenge) catch unreachable;

    // Core serializes the challenge through its generic `Serialize(Stream&,
    // const std::vector<uint8_t>&)` operator, which is CompactSize-length-
    // prefixed, then double-SHA256s the result -- not a bare hash of the
    // challenge bytes (a bare-hash derivation gives 0f1bf2e1, not the
    // published magic; this was checked as part of writing this test).
    var buf: [1 + challenge_bytes.len]u8 = undefined;
    const prefix = bitcointx.encodeCompactSize(challenge_bytes.len, &buf) catch unreachable;
    @memcpy(buf[prefix.len..], &challenge_bytes);

    const digest = bitcointx.hash256.sha256d(&buf);
    try testing.expectEqualSlices(u8, &.{ 0x0a, 0x03, 0xcf, 0x40 }, digest[0..4]);
    try testing.expectEqualSlices(u8, digest[0..4], &magic(.signet));
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

test "F2 regression: commandName's slice survives an intervening call (not a dangling stack pointer)" {
    // Before the fix, `commandName(self: Message) []const u8` took its
    // receiver BY VALUE. `command` is a `[COMMAND_LEN]u8` EMBEDDED in
    // `Message` (not a slice into caller-owned memory), so `&self.command`
    // pointed into `commandName`'s own stack-local copy of `self` -- a
    // frame that is invalid the instant the function returns. Reading the
    // slice's bytes in the SAME expression that produced it (as in
    // `testing.expectEqualStrings("version", decoded.message.commandName())`
    // above) can pass by accident, because nothing has reused that stack
    // slot yet. This test forces a call in between obtaining the slice and
    // reading its bytes -- e.g. `std.fmt.bufPrint`, the same shape
    // `example/main.zig`'s `std.debug.print` call actually tripped over,
    // where the intervening call clobbered the freed frame with Zig's
    // undefined-memory poison (0xaa) before the bytes were ever read.
    const allocator = testing.allocator;
    const wire = try encodeMessage(allocator, .mainnet, "version", "");
    defer allocator.free(wire);
    const decoded = try decodeMessage(wire, .mainnet);
    const name = decoded.message.commandName();

    var buf: [64]u8 = undefined;
    const formatted = try std.fmt.bufPrint(&buf, "cmd={s}", .{name});
    try testing.expectEqualStrings("cmd=version", formatted);
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

test "F1 regression: junk after the command's NUL padding starts is rejected (IsCommandValid)" {
    // Before the fix, `commandName()` cut at the first NUL and nothing
    // validated the bytes AFTER it, so `"version\x00EVIL"` and
    // `"version\x00\x00\x00\x00\x00"` decoded to the identical command
    // string -- a peer could smuggle 4 arbitrary bytes past any
    // logging/rate-limiting/dedup keyed on the command name (wave-2 audit
    // finding `btcp2p` F1). The checksum covers only the payload, not the
    // command field, so tampering the command post-encode keeps it valid.
    const allocator = testing.allocator;
    var wire = try encodeMessage(allocator, .mainnet, "version", "");
    defer allocator.free(wire);
    // command field is bytes[4..16]; "version" is 7 bytes, so [11..16) is
    // NUL padding today -- overwrite one padding byte with non-NUL junk.
    wire[4 + 11] = 'X';
    try testing.expectError(error.InvalidCommand, decodeMessage(wire, .mainnet));
}

test "F1 regression: a non-printable byte before the NUL is rejected (IsCommandValid)" {
    const allocator = testing.allocator;
    var wire = try encodeMessage(allocator, .mainnet, "version", "");
    defer allocator.free(wire);
    wire[4 + 0] = 0x01; // first command byte -> control character, not printable ASCII
    try testing.expectError(error.InvalidCommand, decodeMessage(wire, .mainnet));
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
// doc comment): every byte a peer ever sends reaches `decodeMessage` first.

/// Complete envelopes, in the format `Smith.slice` reads (see `testkit.fuzz`).
///
/// ⭐ This module is the reason a corpus is not optional here. An envelope has
/// to clear a 4-byte magic, a `IsCommandValid()`-shaped 12-byte command AND a
/// 4-byte `sha256d` prefix over its own payload before `decodeMessage` returns
/// anything: uniform random octets reach the checksum comparison with
/// probability ~2^-32 and pass it with ~2^-32 more. No amount of undirected
/// fuzzing gets past the gate; only real frames do, and the wiki publishes two.
const decode_seeds = [_][]const u8{
    seed(&verack_wire), // the wiki's published verack envelope
    seed(&version_wire), // the wiki's 60002 version envelope, 124 octets
    seed(&(verack_wire ++ verack_wire)), // two messages back to back: `consumed` must stop at the first
    seedHex("0b110907" ++ "76657261636b000000000000" ++ "00000000" ++ "5df6e0e2"), // the same verack on testnet3
    seedHex("fabfb5da" ++ "76657261636b000000000000" ++ "00000000" ++ "5df6e0e2"), // and on regtest
    seedHex("0a03cf40" ++ "76657261636b000000000000" ++ "00000000" ++ "5df6e0e2"), // and on signet
    seedHex("00000000" ++ "76657261636b000000000000" ++ "00000000" ++ "5df6e0e2"), // BadMagic on all four
    seedHex("f9beb4d9" ++ "76657261636b000000000058" ++ "00000000" ++ "5df6e0e2"), // InvalidCommand: junk past the NUL padding
    seedHex("f9beb4d9" ++ "01657261636b000000000000" ++ "00000000" ++ "5df6e0e2"), // InvalidCommand: a control byte before it
    seedHex("f9beb4d9" ++ "76657261636b000000000000" ++ "01093d00" ++ "00000000"), // PayloadTooLarge: MAX_PAYLOAD_LENGTH + 1
    seedHex("f9beb4d9" ++ "76657261636b000000000000" ++ "e8030000" ++ "00000000"), // Truncated: claims 1000 octets, none follow
    seedHex("f9beb4d9"), // Truncated: shorter than HEADER_LEN
    seedHex("f9beb4d9" ++ "76657261636b000000000000" ++ "00000000" ++ "5df6e0e3"), // BadChecksum: last checksum octet flipped
    seedHex("f9beb4d9" ++ "76657261636b000000000000" ++ "01000000" ++ "5df6e0e2" ++ "00"), // BadChecksum: a payload the checksum does not cover
    // The two knobs drawn AFTER the byte draw, one `u64` word each: `1`
    // enables the magic stamp, then the index into `nets`.
    // ⛔ Measured 2026-09-08 over the fourteen seeds above: `smith.value(bool)`
    // returned `true` **0 times**. `Smith.slice` leaves the seed exhausted and
    // an exhausted draw is the weight minimum, so the stamp had never been
    // applied to a single envelope. Each of these three is the SAME
    // magic-less verack, refused by all four networks as it stands and
    // accepted by exactly one once the stamp runs — which is what makes the
    // branch visible in the ordinary lane rather than only under `--fuzz`.
    stampedSeed("00000000" ++ "76657261636b000000000000" ++ "00000000" ++ "5df6e0e2", &.{ 1, 0 }), // -> mainnet
    stampedSeed("00000000" ++ "76657261636b000000000000" ++ "00000000" ++ "5df6e0e2", &.{ 1, 2 }), // -> regtest
    stampedSeed("00000000" ++ "76657261636b000000000000" ++ "00000000" ++ "5df6e0e2", &.{ 1, 3 }), // -> signet
    stampedSeed("f9beb4d9" ++ "76657261636b000000000000" ++ "00000000" ++ "5df6e0e2", &.{ 0, 0 }), // the knob explicitly OFF
};

/// `seedHex` plus a tail of `u64` words for the knobs `fuzzDecodeMessage`
/// draws after the byte draw. Without the tail those draws return their range
/// minimum on every replay, which for `value(bool)` is `false`.
fn stampedSeed(comptime h: []const u8, comptime words: []const u64) []const u8 {
    return &struct {
        const frame = fblk: {
            if (h.len % 2 != 0) @compileError("odd-length hex seed: " ++ h);
            @setEvalBranchQuota(@max(1000, 40 * h.len));
            var out: [h.len / 2]u8 = undefined;
            _ = std.fmt.hexToBytes(&out, h) catch @compileError("bad hex seed: " ++ h);
            break :fblk out;
        };
        const tail = wblk: {
            var w: [words.len * 8]u8 = undefined;
            for (words, 0..) |x, i| std.mem.writeInt(u64, w[i * 8 ..][0..8], x, .little);
            break :wblk w;
        };
        const bytes = std.mem.toBytes(@as(u32, frame.len)) ++ frame ++ tail;
    }.bytes;
}

test "fuzz: decodeMessage never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzDecodeMessage, .{ .corpus = &decode_seeds });
}

fn fuzzDecodeMessage(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
    // length. `bytes` takes `@min(buf.len, in.len)` octets and the ranged draw
    // then finds fewer than the eight it needs and returns the range MINIMUM,
    // so `len` was 0 for every seed and `decodeMessage` saw `buf[0..0]` every
    // single time, with the seed sitting unread in `buf`.
    const len: usize = smith.slice(&buf);
    const bytes = buf[0..len];

    const nets = [_]Network{ .mainnet, .testnet3, .regtest, .signet };
    // Stamping a real magic over the first four octets is a `--fuzz` aid: it
    // gets the mutation engine past `BadMagic` to the length/checksum logic.
    // ⚠ The comment that used to sit here claimed it happened "half the time",
    // and that was never true — with `len` collapsed to 0 the `bytes.len >= 4`
    // guard was false on every single execution, so this branch had never run
    // once. Over the corpus it still does not run (each seed leaves the input
    // exhausted, and `value(bool)` on an exhausted input is the weight minimum,
    // i.e. `false`) — which is what we want, since every seed carries the magic
    // it means to test.
    if (bytes.len >= 4 and smith.value(bool)) {
        const idx = smith.valueRangeAtMost(u8, 0, nets.len - 1);
        @memcpy(bytes[0..4], &magic(nets[idx]));
    }

    for (nets) |n| {
        _ = decodeMessage(bytes, n) catch {};
    }
}

test "corpus: every envelope seed reaches decodeMessage, and the accepted count is pinned" {
    // ⭐ The measurement, executable rather than written in a comment. Two
    // things it holds that no other test does: a seed longer than the harness's
    // buffer reads back EMPTY (`Smith.slice` falls back to the range minimum),
    // which is silent everywhere else; and a corpus where nothing is accepted
    // is a corpus that only exercises the refusal path. Acceptance is not
    // reach, so this pins the number rather than asserting it is > 0.
    //
    // `accepted` mirrors the harness, which offers each frame to all four
    // networks: a seed counts once if ANY network takes it.
    var nonempty: usize = 0;
    var accepted: usize = 0;
    var stamped: usize = 0;
    var stamped_accepted: usize = 0;
    const nets = [_]Network{ .mainnet, .testnet3, .regtest, .signet };
    for (decode_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [512]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        const bytes = buf[0..len];
        // The same two knobs the harness draws, in the same order.
        var was_stamped = false;
        if (bytes.len >= 4 and smith.value(bool)) {
            const idx = smith.valueRangeAtMost(u8, 0, nets.len - 1);
            @memcpy(bytes[0..4], &magic(nets[idx]));
            stamped += 1;
            was_stamped = true;
        }
        for (nets) |n| {
            if (decodeMessage(bytes, n)) |_| {
                accepted += 1;
                if (was_stamped) stamped_accepted += 1;
                break;
            } else |_| {}
        }
    }
    try testing.expectEqual(decode_seeds.len, nonempty);
    // 6 = the two mainnet frames + the back-to-back pair + one verack each on
    // testnet3, regtest and signet. Measured 2026-09-07: 0 of 14 seeds
    // non-empty and 0 accepted before the draw was fixed, 14 of 14 and 6 after.
    // Measured 2026-09-08: the magic stamp fired on 0 of those 14. It fires on
    // 3 of 18 now, and `stamped_accepted` is the number that says the stamp
    // did something — those three seeds carry an all-zero magic no network
    // takes, so they can only be accepted because the branch rewrote it.
    try testing.expectEqual(@as(usize, 3), stamped);
    try testing.expectEqual(@as(usize, 3), stamped_accepted);
    try testing.expectEqual(@as(usize, 10), accepted);
}
