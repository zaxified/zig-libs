// SPDX-License-Identifier: MIT
//! BIP152 compact block relay: `cmpctblock`, `getblocktxn`, `blocktxn` (the
//! feature message `sendcmpct` is in `relay.zig`), and the short transaction
//! ids a `cmpctblock` carries.
//!
//! - `cmpctblock`: `header(80) || nonce(8, LE) || shortids(CompactSize count,
//!   6 octets each) || prefilledtxn(CompactSize count, each `index(CompactSize,
//!   differentially encoded) || tx`)`.
//! - `getblocktxn`: `block_hash(32) || indexes(CompactSize count, each
//!   CompactSize, differentially encoded)`.
//! - `blocktxn`: `block_hash(32) || transactions(CompactSize count, then the
//!   transactions)`.
//!
//! A differentially encoded index list stores `index_i - index_(i-1) - 1`
//! (the first one as is), so the absolute indexes are strictly ascending; as in
//! Bitcoin Core every difference and every absolute index must fit 16 bits
//! (`error.IndexOverflow`). The element count of a `cmpctblock` is bounded by
//! Core's `MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT` (66666).
//!
//! Short id (BIP152): `SipHash-2-4` keyed with the first 16 octets of
//! `SHA256(header || nonce)`, over the transaction's txid (version 1) or wtxid
//! (version 2), truncated to its low 6 octets, serialized little-endian.
//!
//! Transactions are `bitcointx`'s, serialized with their witnesses when they
//! have them. Decoded values own their allocations.

const std = @import("std");
const Allocator = std.mem.Allocator;
const bitcointx = @import("bitcointx");
const message = @import("message.zig");
const Reader = message.Reader;
const Writer = message.Writer;
const block_header = @import("block_header.zig");
const BlockHeader = block_header.BlockHeader;

/// Command names, as `envelope.encodeMessage` takes them.
pub const command = struct {
    pub const cmpctblock = "cmpctblock";
    pub const getblocktxn = "getblocktxn";
    pub const blocktxn = "blocktxn";
};

/// Core's bound on `shortids + prefilledtxn` (4,000,000 / 60).
pub const MAX_CMPCTBLOCK_TXS: u64 = 66666;
const MIN_TX_LEN = 60; // the smallest wire-valid transaction, as in `block.zig`

pub const DecodeError = message.ReadError || message.CompactSizeError || bitcointx.tx.DeserializeError || error{
    TooManyItems,
    /// A differential index, or an absolute one, above 65535.
    IndexOverflow,
};

pub const EncodeError = bitcointx.SerializeError || error{
    /// Indexes not strictly ascending.
    NotAscending,
    IndexOverflow,
};

pub const ShortId = [6]u8;

/// The SipHash key of a `cmpctblock` (`SHA256(header || nonce)[0..16]`).
pub fn shortIdKey(header: BlockHeader, nonce: u64) [16]u8 {
    var buf: [block_header.HEADER_LEN + 8]u8 = undefined;
    std.mem.writeInt(i32, buf[0..4], header.version, .little);
    @memcpy(buf[4..36], &header.prev_block);
    @memcpy(buf[36..68], &header.merkle_root);
    std.mem.writeInt(u32, buf[68..72], header.timestamp, .little);
    std.mem.writeInt(u32, buf[72..76], header.bits, .little);
    std.mem.writeInt(u32, buf[76..80], header.nonce, .little);
    std.mem.writeInt(u64, buf[80..88], nonce, .little);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&buf, &digest, .{});
    return digest[0..16].*;
}

/// The short id of a transaction hash (its txid, or its wtxid for version 2).
// secret-api-ok: the BIP152 SipHash key is derived from the public block header and nonce (shortIdKey), not a secret
pub fn shortId(key: *const [16]u8, tx_hash: [32]u8) ShortId {
    var out: [8]u8 = undefined;
    std.crypto.auth.siphash.SipHash64(2, 4).create(&out, &tx_hash, key);
    return out[0..6].*;
}

pub const PrefilledTx = struct {
    /// Absolute position in the block.
    index: u16,
    tx: bitcointx.Transaction,
};

pub const CmpctBlock = struct {
    header: BlockHeader,
    nonce: u64,
    short_ids: []ShortId,
    prefilled: []PrefilledTx,

    pub fn deinit(self: *CmpctBlock, allocator: Allocator) void {
        allocator.free(self.short_ids);
        for (self.prefilled) |*p| p.tx.deinit(allocator);
        allocator.free(self.prefilled);
        self.short_ids = &.{};
        self.prefilled = &.{};
    }
};

/// Reads one differential index: `last` is the previous absolute index + 1 (0 at the start).
fn nextIndex(r: *Reader, last: u64) (message.CompactSizeError || error{IndexOverflow})!u16 {
    const diff = try r.compactSize();
    if (diff > std.math.maxInt(u16)) return error.IndexOverflow;
    const abs = last + diff;
    if (abs > std.math.maxInt(u16)) return error.IndexOverflow;
    return @intCast(abs);
}

pub fn decodeCmpctBlock(allocator: Allocator, bytes: []const u8) (DecodeError)!CmpctBlock {
    var r: Reader = .{ .bytes = bytes };
    const header = try BlockHeader.decode(&r);
    const nonce = try r.u64le();
    const n_short = try r.compactSize();
    if (n_short > MAX_CMPCTBLOCK_TXS or n_short > r.remaining() / 6) return error.TooManyItems;
    const short_ids = try allocator.alloc(ShortId, @intCast(n_short));
    errdefer allocator.free(short_ids);
    for (short_ids) |*s| s.* = try r.takeArray(6);

    const n_pre = try r.compactSize();
    if (n_pre > MAX_CMPCTBLOCK_TXS - n_short or n_pre > r.remaining() / (1 + MIN_TX_LEN)) return error.TooManyItems;
    var pre: std.ArrayList(PrefilledTx) = .empty;
    errdefer {
        for (pre.items) |*p| p.tx.deinit(allocator);
        pre.deinit(allocator);
    }
    var last: u64 = 0;
    var i: u64 = 0;
    while (i < n_pre) : (i += 1) {
        const idx = try nextIndex(&r, last);
        last = @as(u64, idx) + 1;
        const res = try bitcointx.deserializePartial(allocator, r.rest());
        r.pos += res.consumed;
        pre.append(allocator, .{ .index = idx, .tx = res.tx }) catch |e| {
            var t = res.tx;
            t.deinit(allocator);
            return e;
        };
    }
    return .{ .header = header, .nonce = nonce, .short_ids = short_ids, .prefilled = try pre.toOwnedSlice(allocator) };
}

pub fn serializeCmpctBlock(allocator: Allocator, c: CmpctBlock) (EncodeError || Allocator.Error)![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try c.header.encode(&w, allocator);
    try w.putU64le(allocator, c.nonce);
    try w.putCompactSize(allocator, c.short_ids.len);
    for (c.short_ids) |s| try w.putBytes(allocator, &s);
    try w.putCompactSize(allocator, c.prefilled.len);
    var next: u32 = 0;
    for (c.prefilled) |p| {
        if (p.index < next) return error.NotAscending;
        try w.putCompactSize(allocator, p.index - next);
        next = @as(u32, p.index) + 1;
        const tx_bytes = try bitcointx.serialize(allocator, p.tx);
        defer allocator.free(tx_bytes);
        try w.putBytes(allocator, tx_bytes);
    }
    return w.toOwned(allocator);
}

pub const GetBlockTxn = struct {
    block_hash: [32]u8,
    /// Absolute indexes, strictly ascending.
    indexes: []u16,

    pub fn deinit(self: *GetBlockTxn, allocator: Allocator) void {
        allocator.free(self.indexes);
        self.indexes = &.{};
    }
};

pub fn decodeGetBlockTxn(allocator: Allocator, bytes: []const u8) (DecodeError || Allocator.Error)!GetBlockTxn {
    var r: Reader = .{ .bytes = bytes };
    const hash = try r.takeArray(32);
    const count = try r.compactSize();
    // Every index is at least one octet; and at most 65536 distinct ones exist.
    if (count > r.remaining() or count > 65536) return error.TooManyItems;
    const idx = try allocator.alloc(u16, @intCast(count));
    errdefer allocator.free(idx);
    var last: u64 = 0;
    for (idx) |*x| {
        x.* = try nextIndex(&r, last);
        last = @as(u64, x.*) + 1;
    }
    return .{ .block_hash = hash, .indexes = idx };
}

pub fn serializeGetBlockTxn(allocator: Allocator, g: GetBlockTxn) (EncodeError || Allocator.Error)![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try w.putBytes(allocator, &g.block_hash);
    try w.putCompactSize(allocator, g.indexes.len);
    var next: u32 = 0;
    for (g.indexes) |x| {
        if (x < next) return error.NotAscending;
        try w.putCompactSize(allocator, x - next);
        next = @as(u32, x) + 1;
    }
    return w.toOwned(allocator);
}

pub const BlockTxn = struct {
    block_hash: [32]u8,
    txns: []bitcointx.Transaction,

    pub fn deinit(self: *BlockTxn, allocator: Allocator) void {
        for (self.txns) |*t| t.deinit(allocator);
        allocator.free(self.txns);
        self.txns = &.{};
    }
};

pub fn decodeBlockTxn(allocator: Allocator, bytes: []const u8) (DecodeError || Allocator.Error)!BlockTxn {
    var r: Reader = .{ .bytes = bytes };
    const hash = try r.takeArray(32);
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
        txns.append(allocator, res.tx) catch |e| {
            var t = res.tx;
            t.deinit(allocator);
            return e;
        };
    }
    return .{ .block_hash = hash, .txns = try txns.toOwnedSlice(allocator) };
}

pub fn serializeBlockTxn(allocator: Allocator, b: BlockTxn) (bitcointx.SerializeError)![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try w.putBytes(allocator, &b.block_hash);
    try w.putCompactSize(allocator, b.txns.len);
    for (b.txns) |t| {
        const tx_bytes = try bitcointx.serialize(allocator, t);
        defer allocator.free(tx_bytes);
        try w.putBytes(allocator, tx_bytes);
    }
    return w.toOwned(allocator);
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "short id: SipHash-2-4 over the SHA-256 key, low 6 octets (independent SipHash in tools/shortid_kat.py)" {
    var raw: [80]u8 = undefined;
    for (&raw, 0..) |*b, i| b.* = @truncate(i * 7 + 1);
    var r: Reader = .{ .bytes = &raw };
    const header = try BlockHeader.decode(&r);
    const key = shortIdKey(header, 0x0123456789ABCDEF);
    var want_key: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want_key, "29f32f089bfa4eda5227342a4f9a8b9a");
    try testing.expectEqualSlices(u8, &want_key, &key);
    var h: [32]u8 = undefined;
    for (&h, 0..) |*b, i| b.* = @truncate(i * 11 + 3);
    var want: [6]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, "a309e8c6ad05");
    try testing.expectEqualSlices(u8, &want, &shortId(&key, h));
}

test "getblocktxn: indexes are differential and ascending" {
    const a = testing.allocator;
    var idx = [_]u16{ 0, 1, 5, 6, 65535 };
    const bytes = try serializeGetBlockTxn(a, .{ .block_hash = @splat(1), .indexes = &idx });
    defer a.free(bytes);
    // 32 hash, count 5, then 0, 0, 3, 0, 65528 (0xfd 0xf8 0xff).
    try testing.expectEqualSlices(u8, &.{ 5, 0, 0, 3, 0, 0xfd, 0xf8, 0xff }, bytes[32..]);
    var d = try decodeGetBlockTxn(a, bytes);
    defer d.deinit(a);
    try testing.expectEqualSlices(u16, &idx, d.indexes);
    var bad = [_]u16{ 3, 3 };
    try testing.expectError(error.NotAscending, serializeGetBlockTxn(a, .{ .block_hash = @splat(1), .indexes = &bad }));
    // A difference over 16 bits, an absolute index over 16 bits, a count the bytes cannot hold.
    const hdr: [32]u8 = @splat(1);
    const big_diff = try std.mem.concat(a, u8, &.{ &hdr, &.{ 1, 0xfe, 0, 0, 1, 0 } });
    defer a.free(big_diff);
    try testing.expectError(error.IndexOverflow, decodeGetBlockTxn(a, big_diff));
    const overflow = try std.mem.concat(a, u8, &.{ &hdr, &.{ 2, 0xfd, 0xff, 0xff, 0 } });
    defer a.free(overflow);
    try testing.expectError(error.IndexOverflow, decodeGetBlockTxn(a, overflow));
    const lie = try std.mem.concat(a, u8, &.{ &hdr, &.{ 9, 0, 0 } });
    defer a.free(lie);
    try testing.expectError(error.TooManyItems, decodeGetBlockTxn(a, lie));
}

fn smallTx(a: Allocator) !bitcointx.Transaction {
    // One input, one output, no witness: the smallest shape `bitcointx` accepts.
    var raw: [60]u8 = @splat(0);
    raw[0] = 1; // version
    raw[4] = 1; // one input
    raw[4 + 1 + 36] = 0; // empty scriptSig
    @memset(raw[42..46], 0xff);
    raw[46] = 1; // one output
    return bitcointx.deserialize(a, &raw);
}

test "cmpctblock and blocktxn round trip, prefilled indexes differential" {
    const a = testing.allocator;
    var raw: [80]u8 = undefined;
    for (&raw, 0..) |*b, i| b.* = @truncate(i);
    var rd: Reader = .{ .bytes = &raw };
    const header = try BlockHeader.decode(&rd);
    var sids = [_]ShortId{ .{ 1, 2, 3, 4, 5, 6 }, .{ 7, 8, 9, 10, 11, 12 } };
    var pre = [_]PrefilledTx{
        .{ .index = 0, .tx = try smallTx(a) },
        .{ .index = 3, .tx = try smallTx(a) },
    };
    defer for (&pre) |*p| p.tx.deinit(a);
    const bytes = try serializeCmpctBlock(a, .{ .header = header, .nonce = 42, .short_ids = &sids, .prefilled = &pre });
    defer a.free(bytes);
    try testing.expectEqual(@as(u8, 2), bytes[88]); // two short ids
    var d = try decodeCmpctBlock(a, bytes);
    defer d.deinit(a);
    try testing.expectEqual(@as(u64, 42), d.nonce);
    try testing.expectEqualSlices(ShortId, &sids, d.short_ids);
    try testing.expectEqual(@as(usize, 2), d.prefilled.len);
    try testing.expectEqual(@as(u16, 3), d.prefilled[1].index);
    // The second prefilled index is stored as 3 - (0 + 1) = 2.
    const second = 88 + 1 + 12 + 1 + 1 + 60; // count, ids, count, first index, first tx
    try testing.expectEqual(@as(u8, 2), bytes[second]);
    // Truncation anywhere is an error, never a panic.
    for (0..bytes.len) |n| {
        if (decodeCmpctBlock(a, bytes[0..n])) |*ok| {
            var x = ok.*;
            x.deinit(a);
            return error.TestUnexpectedResult;
        } else |_| {}
    }
    var txs = [_]bitcointx.Transaction{ pre[0].tx, pre[1].tx };
    const tb = try serializeBlockTxn(a, .{ .block_hash = @splat(3), .txns = &txs });
    defer a.free(tb);
    var bt = try decodeBlockTxn(a, tb);
    defer bt.deinit(a);
    try testing.expectEqual(@as(usize, 2), bt.txns.len);
    try testing.expectError(error.TooManyItems, decodeBlockTxn(a, &(@as([32]u8, @splat(1)) ++ [_]u8{ 0xfd, 0xff, 0xff })));
    var unordered = [_]PrefilledTx{ pre[1], pre[0] };
    try testing.expectError(error.NotAscending, serializeCmpctBlock(a, .{ .header = header, .nonce = 0, .short_ids = &.{}, .prefilled = &unordered }));
}
