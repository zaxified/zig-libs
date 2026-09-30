// SPDX-License-Identifier: MIT
//! The feature-negotiation and relay-policy messages every current Bitcoin
//! Core peer sends around the handshake (decision 2026-09-30, user; the
//! survey found them missing although every modern peer speaks them).
//!
//! Four carry no payload at all — the command name is the whole message:
//!
//! - **`sendheaders`** (BIP130): "announce new blocks to me with `headers`,
//!   not `inv`". Sent after the handshake.
//! - **`wtxidrelay`** (BIP339): announce transactions by wtxid. It MUST be
//!   sent after `version` and BEFORE `verack`; a peer that receives it later
//!   disconnects.
//! - **`sendaddrv2`** (BIP155): "send me `addrv2`" — same window as
//!   `wtxidrelay` (between `version` and `verack`). This module does not
//!   decode `addrv2` itself yet (SPEC backlog), so a caller that sends
//!   `sendaddrv2` must be ready for it.
//! - **`mempool`** (BIP35): "send me an `inv` of your mempool".
//!
//! Two carry fixed-width fields:
//!
//! - **`feefilter`** (BIP133): an `int64` fee rate in satoshis per kilobyte
//!   below which the peer should not relay transactions to us.
//! - **`sendcmpct`** (BIP152): `bool` announce (high-bandwidth mode) and a
//!   `uint64` compact-block version (1: txids, 2: wtxids). The compact-block
//!   messages themselves (`cmpctblock`, `getblocktxn`, `blocktxn`) are not
//!   decoded here (SPEC backlog).
//!
//! The ordering rules are the caller's to follow, like the handshake's: this
//! module is a codec. A payload-less message is decoded by `expectEmpty`,
//! which refuses bytes it does not expect rather than ignoring them.

const std = @import("std");
const Allocator = std.mem.Allocator;
const message = @import("message.zig");
const Reader = message.Reader;
const Writer = message.Writer;

/// Command names, as `envelope.encodeMessage` takes them.
pub const command = struct {
    pub const sendheaders = "sendheaders";
    pub const wtxidrelay = "wtxidrelay";
    pub const sendaddrv2 = "sendaddrv2";
    pub const mempool = "mempool";
    pub const feefilter = "feefilter";
    pub const sendcmpct = "sendcmpct";
};

pub const EmptyError = error{UnexpectedPayload};

/// The payload of a message defined to have none (`sendheaders`,
/// `wtxidrelay`, `sendaddrv2`, `mempool`, and `verack`/`getaddr`).
pub fn expectEmpty(payload: []const u8) EmptyError!void {
    if (payload.len != 0) return error.UnexpectedPayload;
}

// ── feefilter (BIP133) ────────────────────────────────────────────────────

/// 21 million BTC in satoshis: Bitcoin Core's `MAX_MONEY`, the bound its
/// `MoneyRange` check applies to a received fee filter.
pub const MAX_MONEY: i64 = 21_000_000 * 100_000_000;

pub const FeeFilter = struct {
    /// Satoshis per 1000 bytes (virtual size).
    feerate: i64,
};

pub const FeeFilterError = message.ReadError || EmptyError || error{FeeRateOutOfRange};

/// Exactly eight bytes; a fee rate outside `0..MAX_MONEY` is refused (the
/// range Core accepts — it ignores a filter outside it, so refusing makes
/// the caller's choice explicit rather than silently dropping).
pub fn decodeFeeFilter(payload: []const u8) FeeFilterError!FeeFilter {
    var r: Reader = .{ .bytes = payload };
    const rate = try r.i64le();
    try expectEmpty(r.rest());
    if (rate < 0 or rate > MAX_MONEY) return error.FeeRateOutOfRange;
    return .{ .feerate = rate };
}

pub fn serializeFeeFilter(allocator: Allocator, f: FeeFilter) Allocator.Error![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try w.putI64le(allocator, f.feerate);
    return w.toOwned(allocator);
}

// ── sendcmpct (BIP152) ────────────────────────────────────────────────────

pub const SendCmpct = struct {
    /// High-bandwidth mode: push `cmpctblock` without an announcement first.
    announce: bool,
    /// 1 (short ids over txids) or 2 (over wtxids, segwit); others exist
    /// only as future versions, which BIP152 says to ignore — so a decoder
    /// passes any value through for the caller to check.
    version: u64,
};

pub const SendCmpctError = message.ReadError || EmptyError;

/// Exactly nine bytes. `announce` is a Bitcoin `bool`: any non-zero byte is
/// true, as Core reads it.
pub fn decodeSendCmpct(payload: []const u8) SendCmpctError!SendCmpct {
    var r: Reader = .{ .bytes = payload };
    const announce = try r.boolByte();
    const version = try r.u64le();
    try expectEmpty(r.rest());
    return .{ .announce = announce, .version = version };
}

pub fn serializeSendCmpct(allocator: Allocator, s: SendCmpct) Allocator.Error![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try w.putU8(allocator, @intFromBool(s.announce));
    try w.putU64le(allocator, s.version);
    return w.toOwned(allocator);
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;
const envelope = @import("envelope.zig");
const testkit = @import("testkit");
const seedHex = testkit.fuzz.seedHex;

test "payload-less messages: the whole wire message is the 24-byte header" {
    // sha256d("") starts 5d f6 e0 e2 — the checksum every empty-payload
    // message carries (the wiki's `verack` hex dump shows the same four
    // bytes). Command names are NUL-padded to 12.
    const Case = struct { cmd: []const u8, hex: []const u8 };
    const cases = [_]Case{
        .{ .cmd = command.sendheaders, .hex = "f9beb4d9" ++ "73656e646865616465727300" ++ "00000000" ++ "5df6e0e2" },
        .{ .cmd = command.wtxidrelay, .hex = "f9beb4d9" ++ "777478696472656c61790000" ++ "00000000" ++ "5df6e0e2" },
        .{ .cmd = command.sendaddrv2, .hex = "f9beb4d9" ++ "73656e64616464727632" ++ "0000" ++ "00000000" ++ "5df6e0e2" },
        .{ .cmd = command.mempool, .hex = "f9beb4d9" ++ "6d656d706f6f6c0000000000" ++ "00000000" ++ "5df6e0e2" },
    };
    for (cases) |c| {
        const wire = try envelope.encodeMessage(testing.allocator, .mainnet, c.cmd, "");
        defer testing.allocator.free(wire);
        var want: [24]u8 = undefined;
        _ = try std.fmt.hexToBytes(&want, c.hex);
        try testing.expectEqualSlices(u8, &want, wire);
        const got = try envelope.decodeMessage(wire, .mainnet);
        try testing.expectEqualStrings(c.cmd, got.message.commandName());
        try expectEmpty(got.message.payload);
    }
    try testing.expectError(error.UnexpectedPayload, expectEmpty("\x00"));
}

test "feefilter: the BIP133 layout, the money range, exact length" {
    // 1000 sat/kvB (Core's default minimum relay fee), little-endian int64.
    const bytes = try serializeFeeFilter(testing.allocator, .{ .feerate = 1000 });
    defer testing.allocator.free(bytes);
    try testing.expectEqualSlices(u8, &.{ 0xe8, 0x03, 0, 0, 0, 0, 0, 0 }, bytes);
    try testing.expectEqual(@as(i64, 1000), (try decodeFeeFilter(bytes)).feerate);

    try testing.expectEqual(@as(i64, 0), (try decodeFeeFilter(&(@as([8]u8, @splat(0))))).feerate);
    const max = std.mem.toBytes(std.mem.nativeToLittle(i64, MAX_MONEY));
    try testing.expectEqual(MAX_MONEY, (try decodeFeeFilter(&max)).feerate);
    const over = std.mem.toBytes(std.mem.nativeToLittle(i64, MAX_MONEY + 1));
    try testing.expectError(error.FeeRateOutOfRange, decodeFeeFilter(&over));
    const neg = std.mem.toBytes(std.mem.nativeToLittle(i64, -1));
    try testing.expectError(error.FeeRateOutOfRange, decodeFeeFilter(&neg));
    try testing.expectError(error.Truncated, decodeFeeFilter(bytes[0..7]));
    try testing.expectError(error.UnexpectedPayload, decodeFeeFilter(&(@as([9]u8, @splat(0)))));
}

test "sendcmpct: the BIP152 layout, bool semantics, exact length" {
    const bytes = try serializeSendCmpct(testing.allocator, .{ .announce = true, .version = 2 });
    defer testing.allocator.free(bytes);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0, 0, 0, 0, 0, 0, 0 }, bytes);
    const got = try decodeSendCmpct(bytes);
    try testing.expect(got.announce);
    try testing.expectEqual(@as(u64, 2), got.version);
    // Any non-zero byte is true.
    try testing.expect((try decodeSendCmpct(&.{ 0x07, 1, 0, 0, 0, 0, 0, 0, 0 })).announce);
    try testing.expect(!(try decodeSendCmpct(&.{ 0x00, 1, 0, 0, 0, 0, 0, 0, 0 })).announce);
    try testing.expectError(error.Truncated, decodeSendCmpct(bytes[0..8]));
    try testing.expectError(error.UnexpectedPayload, decodeSendCmpct(&(@as([10]u8, @splat(0)))));
}

const relay_seeds = [_][]const u8{
    seedHex("e803000000000000"), // feefilter 1000
    seedHex("010200000000000000"), // sendcmpct announce v2
    seedHex(""),
    seedHex("ff"),
};

test "fuzz: feefilter / sendcmpct / expectEmpty never panic on arbitrary bytes" {
    try testing.fuzz({}, fuzzRelay, .{ .corpus = &relay_seeds });
}

fn fuzzRelay(_: void, smith: *std.testing.Smith) !void {
    var buf: [32]u8 = undefined;
    const len: usize = smith.slice(&buf);
    const b = buf[0..len];
    if (decodeFeeFilter(b)) |f| {
        try testing.expect(len == 8 and f.feerate >= 0 and f.feerate <= MAX_MONEY);
    } else |_| {}
    if (decodeSendCmpct(b)) |_| try testing.expect(len == 9) else |_| {}
    if (expectEmpty(b)) |_| try testing.expect(len == 0) else |_| {}
}
