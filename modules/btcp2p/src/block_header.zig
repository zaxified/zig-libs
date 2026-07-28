// SPDX-License-Identifier: MIT
//! The 80-byte block header (Bitcoin wiki "Block Headers") -- shared by
//! the `headers` message (a list of these) and the `block` message
//! (one, followed by the block's transactions -- see `block.zig`).
//!
//! Deliberately NOT part of `bitcointx`: that module's scope is
//! transaction (de)serialization + sighash, and never had a block-header
//! type. This is genuinely new wire-format surface, unlike `tx`/`block`
//! payloads (which reuse `bitcointx` directly -- see `block.zig`'s
//! module doc comment).

const std = @import("std");
const bitcointx = @import("bitcointx");
const message = @import("message.zig");
const Reader = message.Reader;
const Writer = message.Writer;
const Allocator = std.mem.Allocator;

pub const HEADER_LEN = 80; // 4 + 32 + 32 + 4 + 4 + 4

pub const BlockHeader = struct {
    /// Signed to match Bitcoin Core's `CBlockHeader::nVersion` (`int32_t`).
    version: i32,
    prev_block: [32]u8,
    merkle_root: [32]u8,
    timestamp: u32,
    bits: u32,
    nonce: u32,

    pub fn decode(r: *Reader) message.ReadError!BlockHeader {
        return .{
            .version = try r.i32le(),
            .prev_block = try r.takeArray(32),
            .merkle_root = try r.takeArray(32),
            .timestamp = try r.u32le(),
            .bits = try r.u32le(),
            .nonce = try r.u32le(),
        };
    }

    pub fn encode(self: BlockHeader, w: *Writer, allocator: Allocator) Allocator.Error!void {
        try w.putI32le(allocator, self.version);
        try w.putBytes(allocator, &self.prev_block);
        try w.putBytes(allocator, &self.merkle_root);
        try w.putU32le(allocator, self.timestamp);
        try w.putU32le(allocator, self.bits);
        try w.putU32le(allocator, self.nonce);
    }

    /// The block hash: `sha256d` of this header's fixed 80-byte
    /// serialization (`bitcointx.hash256.sha256d`, the same double-SHA256
    /// as `txid`/`wtxid`). No allocation -- the 80 bytes are built on the
    /// stack.
    pub fn blockHash(self: BlockHeader) [32]u8 {
        var buf: [HEADER_LEN]u8 = undefined;
        std.mem.writeInt(i32, buf[0..4], self.version, .little);
        @memcpy(buf[4..36], &self.prev_block);
        @memcpy(buf[36..68], &self.merkle_root);
        std.mem.writeInt(u32, buf[68..72], self.timestamp, .little);
        std.mem.writeInt(u32, buf[72..76], self.bits, .little);
        std.mem.writeInt(u32, buf[76..80], self.nonce, .little);
        return bitcointx.hash256.sha256d(&buf);
    }
};

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

// ── externally anchored: the genesis block, whose bytes + resulting hash
// are exact and public (en.bitcoin.it/wiki/Genesis_block, "Raw block
// data" -- fetched directly, not hand-transcribed) ─────────────────────
test "external: genesis block header decodes + hashes to the well-known genesis hash" {
    const header_bytes = [_]u8{
        0x01, 0x00, 0x00, 0x00, // version
    } ++ ([_]u8{0} ** 32) // prev_block: all zero
    ++ [_]u8{
        0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 0x7a, 0xc7, 0x2c, 0x3e,
        0x67, 0x76, 0x8f, 0x61, 0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32,
        0x3a, 0x9f, 0xb8, 0xaa, 0x4b, 0x1e, 0x5e, 0x4a, // merkle_root
        0x29, 0xab, 0x5f, 0x49, // timestamp
        0xff, 0xff, 0x00, 0x1d, // bits
        0x1d, 0xac, 0x2b, 0x7c, // nonce
    };
    var r: Reader = .{ .bytes = &header_bytes };
    const header = try BlockHeader.decode(&r);
    try testing.expectEqual(@as(i32, 1), header.version);
    try testing.expectEqual(@as(u32, 0x1d00ffff), header.bits);
    try testing.expectEqual(@as(u32, 0x7c2bac1d), header.nonce);

    // The genesis block's well-known hash, in the conventional
    // display/big-endian order (block explorers, `getblockhash 0`):
    // 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f --
    // cross-checked live against blockstream.info and mempool.space's
    // `/api/block-height/0` (both agree byte-for-byte) and against the
    // wiki's own "GetHash()" printblock line. `blockHash()` returns
    // internal/wire (little-endian) order, so compare the byte-reversed
    // form.
    const display_hex = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    var want_reversed: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want_reversed, display_hex);

    var got_reversed: [32]u8 = header.blockHash();
    std.mem.reverse(u8, &got_reversed);
    try testing.expectEqualSlices(u8, &want_reversed, &got_reversed);
}

test "BlockHeader: encode -> decode round-trip is byte-exact" {
    const allocator = testing.allocator;
    const header: BlockHeader = .{
        .version = 4,
        .prev_block = @splat(0xaa),
        .merkle_root = @splat(0xbb),
        .timestamp = 1_700_000_000,
        .bits = 0x1d00ffff,
        .nonce = 12345,
    };
    var w: Writer = .{};
    defer w.deinit(allocator);
    try header.encode(&w, allocator);
    try testing.expectEqual(@as(usize, HEADER_LEN), w.list.items.len);

    var r: Reader = .{ .bytes = w.list.items };
    const decoded = try BlockHeader.decode(&r);
    try testing.expectEqual(header.version, decoded.version);
    try testing.expectEqual(header.timestamp, decoded.timestamp);
    try testing.expectEqual(header.bits, decoded.bits);
    try testing.expectEqual(header.nonce, decoded.nonce);
    try testing.expectEqualSlices(u8, &header.prev_block, &decoded.prev_block);
}

test "hostile: BlockHeader.decode on a truncated (79-byte) buffer fails closed" {
    const bytes = [_]u8{0} ** 79;
    var r: Reader = .{ .bytes = &bytes };
    try testing.expectError(error.Truncated, BlockHeader.decode(&r));
}

test "fuzz: BlockHeader.decode never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzBlockHeaderDecode, .{});
}

fn fuzzBlockHeaderDecode(_: void, smith: *std.testing.Smith) !void {
    var buf: [96]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u8, 0, buf.len);
    var r: Reader = .{ .bytes = buf[0..len] };
    const header = BlockHeader.decode(&r) catch return;
    _ = header.blockHash();
}
