// SPDX-License-Identifier: MIT
//! Inventory vectors (`inv_vect`) and the four messages built directly
//! from a list of them: `inv`, `getdata`, `notfound` (byte-for-byte
//! identical payload shape -- "Payload (maximum 50,000 entries...):
//! count / inventory" -- per the wiki, distinguished only by which
//! envelope command carries them, not by anything in the payload
//! itself), plus `getblocks`/`getheaders` (also identical to each
//! other: `version` + block-locator hashes + `hash_stop`) and `headers`
//! (a list of `block_header` + trailing `txn_count`).
//!
//! ## Hostile-input handling
//!
//! Every list here is attacker-controlled-count-prefixed. Two
//! independent defenses, mirroring `bitcointx.tx`'s proven pattern (see
//! that module's doc comment, "Hostile-input handling"):
//!
//! 1. **A documented protocol maximum, where the spec states one** --
//!    `inv`/`getdata`/`notfound` are capped at `MAX_INV_ENTRIES` (50,000,
//!    the wiki's own stated maximum), rejected with `error.TooManyItems`
//!    before any allocation. `getblocks`/`getheaders`/`headers` have no
//!    documented hard maximum, so no arbitrary one is invented here (see
//!    CONVENTIONS.md's "model after a proven implementation", not
//!    "invent a plausible-looking limit").
//! 2. **A cheap remaining-bytes bound, always** -- every list here is
//!    additionally checked against `remaining_bytes / min_item_size`
//!    *before* the parse loop runs, so a hostile huge count with too few
//!    bytes behind it is rejected outright. This is defense-in-depth on
//!    top of the real safety net: the parse loop itself only ever grows
//!    its `ArrayList` one successfully-parsed item at a time, so even
//!    without either check a hostile count could never by itself force a
//!    large allocation -- the first out-of-bounds item read fails closed
//!    with `error.Truncated` first.

const std = @import("std");
const Allocator = std.mem.Allocator;
const message = @import("message.zig");
const Reader = message.Reader;
const Writer = message.Writer;
const block_header = @import("block_header.zig");
const BlockHeader = block_header.BlockHeader;

pub const DecodeError = message.ReadError || message.CompactSizeError || error{TooManyItems};

// ── inv_vect ─────────────────────────────────────────────────────────────

/// "The object type is currently defined as one of the following
/// possibilities" (wiki) -- kept as a raw `u32`, not a closed `enum`,
/// because "Other Data Type values are considered reserved for future
/// implementations": a codec that hard-rejects an unrecognized type
/// would break forward compatibility with a future soft-fork's new
/// inventory type. `knownName` is a convenience for the values actually
/// deployed today.
pub const INV_ERROR: u32 = 0;
pub const INV_MSG_TX: u32 = 1;
pub const INV_MSG_BLOCK: u32 = 2;
pub const INV_MSG_FILTERED_BLOCK: u32 = 3; // getdata-only, BIP37
pub const INV_MSG_CMPCT_BLOCK: u32 = 4; // BIP152
pub const INV_MSG_WITNESS_TX: u32 = 0x40000001; // BIP144
pub const INV_MSG_WITNESS_BLOCK: u32 = 0x40000002; // BIP144
pub const INV_MSG_FILTERED_WITNESS_BLOCK: u32 = 0x40000003; // getdata-only, BIP144

pub fn knownName(kind: u32) ?[]const u8 {
    return switch (kind) {
        INV_ERROR => "ERROR",
        INV_MSG_TX => "MSG_TX",
        INV_MSG_BLOCK => "MSG_BLOCK",
        INV_MSG_FILTERED_BLOCK => "MSG_FILTERED_BLOCK",
        INV_MSG_CMPCT_BLOCK => "MSG_CMPCT_BLOCK",
        INV_MSG_WITNESS_TX => "MSG_WITNESS_TX",
        INV_MSG_WITNESS_BLOCK => "MSG_WITNESS_BLOCK",
        INV_MSG_FILTERED_WITNESS_BLOCK => "MSG_FILTERED_WITNESS_BLOCK",
        else => null,
    };
}

pub const InvVect = struct {
    kind: u32,
    hash: [32]u8,

    const WIRE_LEN = 36; // 4 + 32

    pub fn decode(r: *Reader) message.ReadError!InvVect {
        return .{ .kind = try r.u32le(), .hash = try r.takeArray(32) };
    }

    pub fn encode(self: InvVect, w: *Writer, allocator: Allocator) Allocator.Error!void {
        try w.putU32le(allocator, self.kind);
        try w.putBytes(allocator, &self.hash);
    }
};

/// "Payload (maximum 50,000 entries, which is just over 1.8 megabytes)"
/// -- the wiki's own stated cap for `inv`/`getdata`/`notfound`.
pub const MAX_INV_ENTRIES: u64 = 50_000;

/// The shared `inv`/`getdata`/`notfound` payload: a `count`-prefixed
/// list of `inv_vect`. One type serves all three messages -- see module
/// doc comment.
pub const InventoryList = struct {
    items: []InvVect,

    pub fn deinit(self: *InventoryList, allocator: Allocator) void {
        allocator.free(self.items);
        self.* = .{ .items = &.{} };
    }
};

pub fn decodeInventoryList(allocator: Allocator, bytes: []const u8) (DecodeError || Allocator.Error)!InventoryList {
    var r: Reader = .{ .bytes = bytes };
    const count = try r.compactSize();
    if (count > MAX_INV_ENTRIES) return error.TooManyItems;
    if (count > r.remaining() / InvVect.WIRE_LEN) return error.TooManyItems;

    var items: std.ArrayList(InvVect) = .empty;
    errdefer items.deinit(allocator);
    var i: u64 = 0;
    while (i < count) : (i += 1) try items.append(allocator, try InvVect.decode(&r));
    return .{ .items = try items.toOwnedSlice(allocator) };
}

pub fn serializeInventoryList(allocator: Allocator, list: InventoryList) Allocator.Error![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try w.putCompactSize(allocator, list.items.len);
    for (list.items) |item| try item.encode(&w, allocator);
    return w.toOwned(allocator);
}

// `inv`/`getdata`/`notfound` are one wire shape under three names (module
// doc comment); these aliases let a caller spell out the message it means.
pub const Inv = InventoryList;
pub const GetData = InventoryList;
pub const NotFound = InventoryList;
pub const decodeInv = decodeInventoryList;
pub const serializeInv = serializeInventoryList;
pub const decodeGetData = decodeInventoryList;
pub const serializeGetData = serializeInventoryList;
pub const decodeNotFound = decodeInventoryList;
pub const serializeNotFound = serializeInventoryList;

// ── getblocks / getheaders ───────────────────────────────────────────────

/// `getblocks`/`getheaders` share this exact payload shape (module doc
/// comment): a protocol version, a block-locator hash list ("newest back
/// to genesis block"), and a stop hash.
pub const BlockLocator = struct {
    version: u32,
    hashes: [][32]u8,
    hash_stop: [32]u8,

    pub fn deinit(self: *BlockLocator, allocator: Allocator) void {
        allocator.free(self.hashes);
        self.* = .{ .version = 0, .hashes = &.{}, .hash_stop = @splat(0) };
    }
};

pub fn decodeBlockLocator(allocator: Allocator, bytes: []const u8) (DecodeError || Allocator.Error)!BlockLocator {
    var r: Reader = .{ .bytes = bytes };
    const version = try r.u32le();
    const count = try r.compactSize();
    if (count > r.remaining() / 32) return error.TooManyItems;

    var hashes: std.ArrayList([32]u8) = .empty;
    errdefer hashes.deinit(allocator);
    var i: u64 = 0;
    while (i < count) : (i += 1) try hashes.append(allocator, try r.takeArray(32));
    const hash_stop = try r.takeArray(32);
    return .{ .version = version, .hashes = try hashes.toOwnedSlice(allocator), .hash_stop = hash_stop };
}

pub fn serializeBlockLocator(allocator: Allocator, loc: BlockLocator) Allocator.Error![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try w.putU32le(allocator, loc.version);
    try w.putCompactSize(allocator, loc.hashes.len);
    for (loc.hashes) |h| try w.putBytes(allocator, &h);
    try w.putBytes(allocator, &loc.hash_stop);
    return w.toOwned(allocator);
}

pub const GetBlocks = BlockLocator;
pub const GetHeaders = BlockLocator;
pub const decodeGetBlocks = decodeBlockLocator;
pub const serializeGetBlocks = serializeBlockLocator;
pub const decodeGetHeaders = decodeBlockLocator;
pub const serializeGetHeaders = serializeBlockLocator;

// ── headers ──────────────────────────────────────────────────────────────

/// One `headers`-message entry: a block header plus its trailing
/// `txn_count` (wiki: "always 0" for this message in practice, but the
/// field is on the wire regardless -- stored, not asserted, to preserve
/// byte-exact round-trip of whatever a peer actually sent).
pub const HeaderEntry = struct {
    header: BlockHeader,
    txn_count: u64,
};

pub const Headers = struct {
    entries: []HeaderEntry,

    pub fn deinit(self: *Headers, allocator: Allocator) void {
        allocator.free(self.entries);
        self.* = .{ .entries = &.{} };
    }
};

pub fn decodeHeaders(allocator: Allocator, bytes: []const u8) (DecodeError || Allocator.Error)!Headers {
    var r: Reader = .{ .bytes = bytes };
    const count = try r.compactSize();
    // Smallest possible entry: 80-byte header + a 1-byte txn_count.
    if (count > r.remaining() / (block_header.HEADER_LEN + 1)) return error.TooManyItems;

    var entries: std.ArrayList(HeaderEntry) = .empty;
    errdefer entries.deinit(allocator);
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        const header = try BlockHeader.decode(&r);
        const txn_count = try r.compactSize();
        try entries.append(allocator, .{ .header = header, .txn_count = txn_count });
    }
    return .{ .entries = try entries.toOwnedSlice(allocator) };
}

pub fn serializeHeaders(allocator: Allocator, h: Headers) Allocator.Error![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try w.putCompactSize(allocator, h.entries.len);
    for (h.entries) |e| {
        try e.header.encode(&w, allocator);
        try w.putCompactSize(allocator, e.txn_count);
    }
    return w.toOwned(allocator);
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "external anchor: Wireshark's bitcoin dissector reads our inv payload field-for-field" {
    // Audit F4. `inv`/`getdata`/`notfound` is the highest-volume message on the
    // network and had NO oracle that could fail independently of whoever wrote
    // this encoder — the wiki documents the field layout but publishes no hex
    // dump, so the only decode test was self-labelled `in-house` and everything
    // else was round-trip. A round-trip proves our encoder and our decoder share
    // a convention, not that the convention is Bitcoin's.
    //
    // The oracle here is Wireshark's `bitcoin` dissector: a mature third-party
    // reading of the same specification, which this repo already uses for the
    // same purpose elsewhere (`scripts/dissect.py`). These bytes were emitted,
    // wrapped in Ethernet/IPv4/TCP:8333, and handed to `sharkd`; the assertions
    // below are what IT said they mean, transcribed. It is not a captured
    // packet — no network access here — but it is an independent decoder, which
    // is the property the finding was actually missing.
    //
    // Reproduce (needs `text2pcap` + `sharkd`, wireshark-common; sharkd needs
    // `decode_as_entry: tcp.port,8333,(none),Bitcoin` in its config dir because
    // the dissector does not claim the port on its own):
    //
    //   bitcoin.magic      == 0xf9beb4d9   Packet magic
    //   bitcoin.command    == "inv"        Command name
    //   bitcoin.length     == 73           Payload Length
    //   bitcoin.checksum   == 0x5ac96253   Payload checksum
    //   bitcoin.inv.count  == 2            Count            @ payload offset 0
    //   bitcoin.inv.type   == 1            MSG_TX (1)       @ payload offset 1
    //   bitcoin.inv.hash   == d3ad…0304    Data hash        @ payload offset 5
    //   bitcoin.inv.type   == 2            MSG_BLOCK (2)    @ payload offset 37
    //   bitcoin.inv.hash   == 6fe2…0000    Data hash        @ payload offset 41
    //
    // The oracle demonstrably BITES: re-emitting the same payload with the
    // `type` field big-endian instead of little-endian makes the same dissector
    // report `Type: Unknown (16777216)` and `Type: Unknown (33554432)` instead
    // of MSG_TX/MSG_BLOCK. It is reading the field, not echoing us.
    const allocator = testing.allocator;

    // The exact payload bytes sharkd was shown (the `inv` message payload,
    // i.e. after magic/command/length/checksum).
    const wire = [_]u8{
        0x02, // CompactSize count = 2
        0x01, 0x00, 0x00, 0x00, // type = MSG_TX (LE)
        0xd3, 0xad, 0x1b, 0x0b,
        0x2e, 0x8f, 0x6a, 0x7c,
        0x4d, 0x5e, 0x6f, 0x70,
        0x81, 0x92, 0xa3, 0xb4,
        0xc5, 0xd6, 0xe7, 0xf8,
        0x09, 0x1a, 0x2b, 0x3c,
        0x4d, 0x5e, 0x6f, 0x70,
        0x81, 0x92, 0x03, 0x04,
        0x02, 0x00, 0x00, 0x00, // type = MSG_BLOCK (LE)
        // the mainnet genesis block hash, wire (internal) byte order
        0x6f, 0xe2, 0x8c, 0x0a,
        0xb6, 0xf1, 0xb3, 0x72,
        0xc1, 0xa6, 0xa2, 0x46,
        0xae, 0x63, 0xf7, 0x4f,
        0x93, 0x1e, 0x83, 0x65,
        0xe1, 0x5a, 0x08, 0x9c,
        0x68, 0xd6, 0x19, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };

    // 1. Our decoder agrees with the dissector's reading of these bytes.
    var list = try decodeInventoryList(allocator, &wire);
    defer list.deinit(allocator);
    try testing.expectEqual(@as(usize, 2), list.items.len);
    try testing.expectEqual(INV_MSG_TX, list.items[0].kind);
    try testing.expectEqualStrings("MSG_TX", knownName(list.items[0].kind).?);
    try testing.expectEqualSlices(u8, wire[5..37], &list.items[0].hash);
    try testing.expectEqual(INV_MSG_BLOCK, list.items[1].kind);
    try testing.expectEqualStrings("MSG_BLOCK", knownName(list.items[1].kind).?);
    try testing.expectEqualSlices(u8, wire[41..73], &list.items[1].hash);

    // 2. Our ENCODER produces those bytes — this is the direction the finding
    // was about, and the one a decode-only test cannot pin.
    const out = try serializeInventoryList(allocator, list);
    defer allocator.free(out);
    try testing.expectEqualSlices(u8, &wire, out);

    // 3. The framed length the dissector reported.
    try testing.expectEqual(@as(usize, 73), wire.len);
}

test "in-house: InventoryList decodes a single MSG_TX inv_vect" {
    // The wiki documents `inv_vect`'s fields and the type-value table but
    // publishes no standalone hex dump for `inv`/`getdata`/`notfound`;
    // this vector is hand-built from those documented fields -- in-house,
    // not externally-anchored (see SPEC.md's verification table).
    const hash: [32]u8 = @splat(0x42);
    const allocator = testing.allocator;
    var w: Writer = .{};
    defer w.deinit(allocator);
    try w.putCompactSize(allocator, 1);
    try w.putU32le(allocator, INV_MSG_TX);
    try w.putBytes(allocator, &hash);

    var list = try decodeInventoryList(allocator, w.list.items);
    defer list.deinit(allocator);
    try testing.expectEqual(@as(usize, 1), list.items.len);
    try testing.expectEqual(INV_MSG_TX, list.items[0].kind);
    try testing.expectEqualStrings("MSG_TX", knownName(list.items[0].kind).?);
}

test "InventoryList: encode -> decode round-trip, empty list" {
    const allocator = testing.allocator;
    const empty: InventoryList = .{ .items = &.{} };
    const bytes = try serializeInventoryList(allocator, empty);
    defer allocator.free(bytes);
    try testing.expectEqualSlices(u8, &.{0x00}, bytes); // CompactSize(0)

    var decoded = try decodeInventoryList(allocator, bytes);
    defer decoded.deinit(allocator);
    try testing.expectEqual(@as(usize, 0), decoded.items.len);
}

test "hostile: InventoryList rejects a count over MAX_INV_ENTRIES" {
    const allocator = testing.allocator;
    var w: Writer = .{};
    defer w.deinit(allocator);
    try w.putCompactSize(allocator, MAX_INV_ENTRIES + 1);
    try testing.expectError(error.TooManyItems, decodeInventoryList(allocator, w.list.items));
}

test "hostile: InventoryList rejects a huge count with insufficient bytes behind it (no OOM)" {
    const allocator = testing.allocator;
    var w: Writer = .{};
    defer w.deinit(allocator);
    try w.putCompactSize(allocator, 1000); // well under MAX_INV_ENTRIES, but nothing follows
    try testing.expectError(error.TooManyItems, decodeInventoryList(allocator, w.list.items));
}

test "BlockLocator: encode -> decode round-trip" {
    const allocator = testing.allocator;
    var hashes = [_][32]u8{ @splat(0x11), @splat(0x22) };
    const loc: BlockLocator = .{ .version = 70015, .hashes = &hashes, .hash_stop = @splat(0) };
    const bytes = try serializeBlockLocator(allocator, loc);
    defer allocator.free(bytes);

    var decoded = try decodeBlockLocator(allocator, bytes);
    defer decoded.deinit(allocator);
    try testing.expectEqual(@as(u32, 70015), decoded.version);
    try testing.expectEqual(@as(usize, 2), decoded.hashes.len);
    try testing.expectEqualSlices(u8, &hashes[0], &decoded.hashes[0]);
    try testing.expectEqualSlices(u8, &hashes[1], &decoded.hashes[1]);
}

test "hostile: BlockLocator rejects a hash count with insufficient bytes behind it" {
    const allocator = testing.allocator;
    var w: Writer = .{};
    defer w.deinit(allocator);
    try w.putU32le(allocator, 1);
    try w.putCompactSize(allocator, 500); // claims 500 hashes, none follow
    try testing.expectError(error.TooManyItems, decodeBlockLocator(allocator, w.list.items));
}

test "Headers: encode -> decode round-trip preserves txn_count" {
    const allocator = testing.allocator;
    const header: BlockHeader = .{
        .version = 1,
        .prev_block = @splat(0),
        .merkle_root = @splat(0xab),
        .timestamp = 1231006505,
        .bits = 0x1d00ffff,
        .nonce = 2083236893,
    };
    var entries = [_]HeaderEntry{.{ .header = header, .txn_count = 0 }};
    const h: Headers = .{ .entries = &entries };
    const bytes = try serializeHeaders(allocator, h);
    defer allocator.free(bytes);

    var decoded = try decodeHeaders(allocator, bytes);
    defer decoded.deinit(allocator);
    try testing.expectEqual(@as(usize, 1), decoded.entries.len);
    try testing.expectEqual(@as(u64, 0), decoded.entries[0].txn_count);
    try testing.expectEqual(header.nonce, decoded.entries[0].header.nonce);
}

test "hostile: Headers rejects a count with insufficient bytes behind it" {
    const allocator = testing.allocator;
    var w: Writer = .{};
    defer w.deinit(allocator);
    try w.putCompactSize(allocator, 1_000_000); // way more than fits in the remaining 0 bytes
    try testing.expectError(error.TooManyItems, decodeHeaders(allocator, w.list.items));
}

test "fuzz: decodeInventoryList never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzInventoryList, .{});
}

fn fuzzInventoryList(_: void, smith: *std.testing.Smith) !void {
    const allocator = testing.allocator;
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    var list = decodeInventoryList(allocator, buf[0..len]) catch return;
    defer list.deinit(allocator);
}

test "fuzz: decodeBlockLocator never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzBlockLocator, .{});
}

fn fuzzBlockLocator(_: void, smith: *std.testing.Smith) !void {
    const allocator = testing.allocator;
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    var loc = decodeBlockLocator(allocator, buf[0..len]) catch return;
    defer loc.deinit(allocator);
}

test "fuzz: decodeHeaders never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzHeaders, .{});
}

fn fuzzHeaders(_: void, smith: *std.testing.Smith) !void {
    const allocator = testing.allocator;
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    var h = decodeHeaders(allocator, buf[0..len]) catch return;
    defer h.deinit(allocator);
}

test "external anchor: the inventory type numbers are the protocol's, not ours" {
    // `knownName` and the frozen `inv` anchor above only ever exercise MSG_TX
    // and MSG_BLOCK, and they compare against these very constants — so every
    // assertion stays true if a constant is edited. That is a test of the
    // mechanism, not of the value. These numbers are wire contract: a wrong one
    // means we ask a peer for an inventory type it does not recognise, or we
    // silently misread the type it sends us, with no local test disagreeing.
    //
    // Values as published, spelled out here so the source is auditable:
    //   0,1,2   — Bitcoin protocol `inv` message, ERROR/MSG_TX/MSG_BLOCK
    //   3       — BIP37 `MSG_FILTERED_BLOCK` (getdata-only)
    //   4       — BIP152 `MSG_CMPCT_BLOCK`
    //   0x4000… — BIP144 sets bit 30 on the base type to request the witness
    //             serialisation, giving 0x40000001/2/3.
    try testing.expectEqual(@as(u32, 0), INV_ERROR);
    try testing.expectEqual(@as(u32, 1), INV_MSG_TX);
    try testing.expectEqual(@as(u32, 2), INV_MSG_BLOCK);
    try testing.expectEqual(@as(u32, 3), INV_MSG_FILTERED_BLOCK);
    try testing.expectEqual(@as(u32, 4), INV_MSG_CMPCT_BLOCK);
    try testing.expectEqual(@as(u32, 0x40000001), INV_MSG_WITNESS_TX);
    try testing.expectEqual(@as(u32, 0x40000002), INV_MSG_WITNESS_BLOCK);
    try testing.expectEqual(@as(u32, 0x40000003), INV_MSG_FILTERED_WITNESS_BLOCK);

    // The BIP144 witness flag is bit 30 of the base type, not three unrelated
    // magic numbers — pin the relationship too, so a future type stays derivable.
    const witness_flag: u32 = 1 << 30;
    try testing.expectEqual(INV_MSG_WITNESS_TX, INV_MSG_TX | witness_flag);
    try testing.expectEqual(INV_MSG_WITNESS_BLOCK, INV_MSG_BLOCK | witness_flag);
    try testing.expectEqual(INV_MSG_FILTERED_WITNESS_BLOCK, INV_MSG_FILTERED_BLOCK | witness_flag);
}
