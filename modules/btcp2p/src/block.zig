// SPDX-License-Identifier: MIT
//! `tx` and `block` -- the two payload messages that carry consensus
//! data. Both reuse `bitcointx` directly rather than reimplementing
//! transaction serialization:
//!
//! - **`tx`**'s payload IS `bitcointx`'s wire format exactly -- a `tx`
//!   message's payload is one transaction, so this module re-exports
//!   `bitcointx.deserialize`/`bitcointx.serialize` at the root (see
//!   `root.zig`) with no wrapper code at all.
//! - **`block`**'s payload is a `block_header` (this module's own type --
//!   `bitcointx` never had one, see `block_header.zig`'s doc comment)
//!   followed by a CompactSize transaction count and that many
//!   back-to-back transactions. `bitcointx.deserializePartial` was built
//!   with exactly this in mind: its own doc comment says "so a caller
//!   can decode several transactions packed back-to-back, e.g. from a
//!   `getdata`/block payload" -- `decodeBlock` below is that caller.
//!
//! ## Hostile-input handling
//!
//! `decodeBlock`'s transaction-count loop inherits its safety from
//! `bitcointx.deserializePartial` itself: each loop iteration only
//! appends a `Transaction` to the result *after* a full, successful
//! parse of one -- so a hostile huge `txn_count` can never by itself
//! force a large allocation (the loop's very first iteration fails
//! closed with `bitcointx`'s own `error.Truncated`/`error.TooManyItems`
//! once real bytes run out, exactly as `tx.zig`'s own doc comment
//! describes for a single transaction). A cheap remaining-bytes bound
//! (defense-in-depth, not the actual safety net) is still checked before
//! the loop runs, using the smallest possible legacy transaction's size
//! as the per-item floor.

const std = @import("std");
const Allocator = std.mem.Allocator;
const bitcointx = @import("bitcointx");
const message = @import("message.zig");
const Reader = message.Reader;
const Writer = message.Writer;
const block_header = @import("block_header.zig");
const BlockHeader = block_header.BlockHeader;

pub const DecodeError = message.ReadError || message.CompactSizeError || bitcointx.tx.DeserializeError || error{TooManyItems};

/// The smallest possible wire-valid transaction: 4-byte version + a
/// 1-byte vin count (minimally 1 -- `bitcointx`'s own doc comment: a
/// legacy 0-vin count is indistinguishable from the segwit marker) + one
/// minimal input (32-byte prevout hash + 4-byte index + 1-byte empty
/// scriptSig length + 4-byte sequence = 41) + a 1-byte vout count + one
/// minimal output (8-byte value + 1-byte empty scriptPubKey length = 9)
/// + a 4-byte locktime = 4+1+41+1+9+4 = 60 bytes.
const MIN_TX_LEN = 60;

pub const Block = struct {
    header: BlockHeader,
    txns: []bitcointx.Transaction,

    pub fn deinit(self: *Block, allocator: Allocator) void {
        for (self.txns) |*t| t.deinit(allocator);
        allocator.free(self.txns);
        self.* = .{ .header = self.header, .txns = &.{} };
    }
};

pub fn decodeBlock(allocator: Allocator, bytes: []const u8) DecodeError!Block {
    var r: Reader = .{ .bytes = bytes };
    const header = try BlockHeader.decode(&r);
    const count = try r.compactSize();
    if (count > r.remaining() / MIN_TX_LEN) return error.TooManyItems;

    var txns: std.ArrayList(bitcointx.Transaction) = .empty;
    errdefer {
        for (txns.items) |*t| t.deinit(allocator);
        txns.deinit(allocator);
    }
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        const res = try bitcointx.deserializePartial(allocator, r.rest());
        r.pos += res.consumed;
        try txns.append(allocator, res.tx);
    }
    return .{ .header = header, .txns = try txns.toOwnedSlice(allocator) };
}

pub fn serializeBlock(allocator: Allocator, blk: Block) Allocator.Error![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try blk.header.encode(&w, allocator);
    try w.putCompactSize(allocator, blk.txns.len);
    for (blk.txns) |t| {
        const tx_bytes = try bitcointx.serialize(allocator, t);
        defer allocator.free(tx_bytes);
        try w.putBytes(allocator, tx_bytes);
    }
    return w.toOwned(allocator);
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

// ── externally anchored: the genesis block's full raw bytes
// (en.bitcoin.it/wiki/Genesis_block "Raw block data", fetched directly)
// -- exercises decodeBlock's header + coinbase-tx reuse of bitcointx
// end to end against a real, published block. ───────────────────────────
test "external: genesis block decodes byte-exact against the wiki's published raw hex" {
    const raw = [_]u8{
        0x01, 0x00, 0x00, 0x00, // version
    } ++ ([_]u8{0} ** 32) // prev_block
    ++ [_]u8{
        0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 0x7a, 0xc7, 0x2c, 0x3e,
        0x67, 0x76, 0x8f, 0x61, 0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32,
        0x3a, 0x9f, 0xb8, 0xaa, 0x4b, 0x1e, 0x5e, 0x4a, // merkle_root
        0x29, 0xab, 0x5f, 0x49, // timestamp
        0xff, 0xff, 0x00, 0x1d, // bits
        0x1d, 0xac, 0x2b, 0x7c, // nonce
        0x01, // 1 transaction
        // -- coinbase transaction --
        0x01, 0x00, 0x00, 0x00, // tx version
        0x01, // 1 input
    } ++ ([_]u8{0} ** 32) // null prevout hash
    ++ [_]u8{ 0xff, 0xff, 0xff, 0xff } // prevout index
    ++ [_]u8{0x4d} // scriptSig length = 77
    ++ [_]u8{
        0x04, 0xff, 0xff, 0x00, 0x1d, 0x01, 0x04, 0x45, 0x54, 0x68, 0x65, 0x20, 0x54, 0x69, 0x6d, 0x65,
        0x73, 0x20, 0x30, 0x33, 0x2f, 0x4a, 0x61, 0x6e, 0x2f, 0x32, 0x30, 0x30, 0x39, 0x20, 0x43, 0x68,
        0x61, 0x6e, 0x63, 0x65, 0x6c, 0x6c, 0x6f, 0x72, 0x20, 0x6f, 0x6e, 0x20, 0x62, 0x72, 0x69, 0x6e,
        0x6b, 0x20, 0x6f, 0x66, 0x20, 0x73, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x20, 0x62, 0x61, 0x69, 0x6c,
        0x6f, 0x75, 0x74, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x62, 0x61, 0x6e, 0x6b, 0x73,
    } // scriptSig ("The Times 03/Jan/2009 Chancellor on brink of second bailout for banks")
    ++ [_]u8{ 0xff, 0xff, 0xff, 0xff } // sequence
    ++ [_]u8{0x01} // 1 output
    ++ [_]u8{ 0x00, 0xf2, 0x05, 0x2a, 0x01, 0x00, 0x00, 0x00 } // value = 50 BTC
    ++ [_]u8{0x43} // pk_script length = 67
    ++ [_]u8{
        0x41, 0x04, 0x67, 0x8a, 0xfd, 0xb0, 0xfe, 0x55, 0x48, 0x27, 0x19, 0x67, 0xf1, 0xa6, 0x71, 0x30,
        0xb7, 0x10, 0x5c, 0xd6, 0xa8, 0x28, 0xe0, 0x39, 0x09, 0xa6, 0x79, 0x62, 0xe0, 0xea, 0x1f, 0x61,
        0xde, 0xb6, 0x49, 0xf6, 0xbc, 0x3f, 0x4c, 0xef, 0x38, 0xc4, 0xf3, 0x55, 0x04, 0xe5, 0x1e, 0xc1,
        0x12, 0xde, 0x5c, 0x38, 0x4d, 0xf7, 0xba, 0x0b, 0x8d, 0x57, 0x8a, 0x4c, 0x70, 0x2b, 0x6b, 0xf1,
        0x1d, 0x5f, 0xac,
    } // pk_script
    ++ [_]u8{ 0x00, 0x00, 0x00, 0x00 }; // lock_time

    const allocator = testing.allocator;
    var blk = try decodeBlock(allocator, &raw);
    defer blk.deinit(allocator);

    try testing.expectEqual(@as(i32, 1), blk.header.version);
    try testing.expectEqual(@as(usize, 1), blk.txns.len);
    try testing.expectEqual(@as(i64, 50 * 100_000_000), blk.txns[0].vout[0].value);
    try testing.expect(std.mem.indexOf(u8, blk.txns[0].vin[0].script_sig, "The Times 03/Jan/2009") != null);

    const reser = try serializeBlock(allocator, blk);
    defer allocator.free(reser);
    try testing.expectEqualSlices(u8, &raw, reser);
}

test "hostile: decodeBlock rejects a txn_count with insufficient bytes behind it (no OOM)" {
    const allocator = testing.allocator;
    var w: Writer = .{};
    defer w.deinit(allocator);
    const header: BlockHeader = .{ .version = 1, .prev_block = @splat(0), .merkle_root = @splat(0), .timestamp = 0, .bits = 0, .nonce = 0 };
    try header.encode(&w, allocator);
    try w.putCompactSize(allocator, 0xffffffff); // hostile huge count, nothing follows
    try testing.expectError(error.TooManyItems, decodeBlock(allocator, w.list.items));
}

test "hostile: decodeBlock on a truncated header fails closed" {
    const allocator = testing.allocator;
    try testing.expectError(error.Truncated, decodeBlock(allocator, &[_]u8{0} ** 40));
}

test "fuzz: decodeBlock never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzDecodeBlock, .{});
}

fn fuzzDecodeBlock(_: void, smith: *std.testing.Smith) !void {
    const allocator = testing.allocator;
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    // Bias the byte right after the 80-byte header (the txn_count
    // CompactSize) toward small counts half the time -- otherwise a
    // uniformly random byte there is >50% a multi-byte 0xfd/0xfe/0xff
    // CompactSize prefix that almost always truncates immediately,
    // rarely reaching the actual per-tx `deserializePartial` loop.
    if (buf.len > block_header.HEADER_LEN and smith.value(bool)) {
        buf[block_header.HEADER_LEN] = smith.valueRangeAtMost(u8, 0, 3);
    }
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    var blk = decodeBlock(allocator, buf[0..len]) catch return;
    defer blk.deinit(allocator);
}
