// SPDX-License-Identifier: MIT
//! `ping`/`pong`, `addr`/`getaddr`, and `reject` -- connection
//! housekeeping that isn't the handshake or block/tx relay.
//!
//! Scope decisions (checked against the current wiki, not assumed --
//! see also SPEC.md):
//!
//! - **`ping`/`pong`** implemented in their *modern* (BIP31, protocol
//!   >= 60001) form only: an 8-byte `nonce` each way. The pre-BIP31
//!   `ping` (zero-length payload, no `pong` reply at all) predates every
//!   protocol version any peer on the network negotiates today; a
//!   zero-length legacy `ping` is trivially representable as an empty
//!   byte slice if a caller ever needs it, so it isn't given its own
//!   type here.
//! - **`addr`** implemented; **`addrv2`** (BIP155, the wider address
//!   format for Tor v3 / I2P / CJDNS peers) is a distinct, larger
//!   surface deliberately deferred -- see SPEC.md.
//! - **`reject`** (BIP61) implemented for completeness/legacy-peer
//!   interop, but flagged: Bitcoin Core deprecated it in v0.18.0,
//!   disabled it by default in v0.19, and removed it entirely in v0.20.0
//!   (2020, github.com/bitcoin/bitcoin PR #15437) over the fingerprinting/
//!   bandwidth concerns BIP61 itself documents. No mainline peer on the
//!   network today sends this message; a caller of this module should
//!   not expect one back.
//! - **`mempool`**, **`sendheaders`**, **`feefilter`**, **`sendcmpct`**/
//!   `cmpctblock`/`getblocktxn`/`blocktxn` (BIP152 compact blocks),
//!   `filterload`/`filteradd`/`filterclear`/`merkleblock` (BIP37 bloom
//!   filters), and `checkorder`/`submitorder`/`reply` (IP Transactions,
//!   "deprecated... no longer used" per the wiki itself) are all out of
//!   scope -- not requested, and each is either its own protocol
//!   extension (BIP37/BIP152) or long-dead. **`alert`** is deliberately
//!   never implemented: the alert system was retired after a signature
//!   forgery in its trust model was found, and Bitcoin Core burned the
//!   signing key -- there is nothing left to verify against, and no
//!   modern peer sends or honors it.

const std = @import("std");
const Allocator = std.mem.Allocator;
const message = @import("message.zig");
const Reader = message.Reader;
const Writer = message.Writer;
const net_addr = @import("net_addr.zig");
const TimedNetAddr = net_addr.TimedNetAddr;

pub const DecodeError = message.ReadError || message.CompactSizeError;

// ── ping / pong ──────────────────────────────────────────────────────────

pub const Ping = struct { nonce: u64 };
pub const Pong = struct { nonce: u64 };

pub fn decodePing(bytes: []const u8) message.ReadError!Ping {
    var r: Reader = .{ .bytes = bytes };
    return .{ .nonce = try r.u64le() };
}

pub fn serializePing(allocator: Allocator, p: Ping) Allocator.Error![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try w.putU64le(allocator, p.nonce);
    return w.toOwned(allocator);
}

pub fn decodePong(bytes: []const u8) message.ReadError!Pong {
    var r: Reader = .{ .bytes = bytes };
    return .{ .nonce = try r.u64le() };
}

pub fn serializePong(allocator: Allocator, p: Pong) Allocator.Error![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try w.putU64le(allocator, p.nonce);
    return w.toOwned(allocator);
}

// ── addr / getaddr ───────────────────────────────────────────────────────

/// "Number of address entries (max: 1000)" -- the wiki's own stated cap.
pub const MAX_ADDR_ENTRIES: u64 = 1000;

pub const Addr = struct {
    entries: []TimedNetAddr,

    pub fn deinit(self: *Addr, allocator: Allocator) void {
        allocator.free(self.entries);
        self.* = .{ .entries = &.{} };
    }
};

pub fn decodeAddr(allocator: Allocator, bytes: []const u8) (DecodeError || Allocator.Error || error{TooManyItems})!Addr {
    var r: Reader = .{ .bytes = bytes };
    const count = try r.compactSize();
    if (count > MAX_ADDR_ENTRIES) return error.TooManyItems;
    const min_entry_len = 4 + 8 + 16 + 2; // time + services + ip + port = 30
    if (count > r.remaining() / min_entry_len) return error.TooManyItems;

    var entries: std.ArrayList(TimedNetAddr) = .empty;
    errdefer entries.deinit(allocator);
    var i: u64 = 0;
    while (i < count) : (i += 1) try entries.append(allocator, try TimedNetAddr.decode(&r));
    return .{ .entries = try entries.toOwnedSlice(allocator) };
}

pub fn serializeAddr(allocator: Allocator, a: Addr) Allocator.Error![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try w.putCompactSize(allocator, a.entries.len);
    for (a.entries) |e| try e.encode(&w, allocator);
    return w.toOwned(allocator);
}

// ── reject (BIP61 -- deprecated, see module doc comment) ────────────────

pub const RejectCode = enum(u8) {
    malformed = 0x01,
    invalid = 0x10,
    obsolete = 0x11,
    duplicate = 0x12,
    nonstandard = 0x40,
    dust = 0x41,
    insufficientfee = 0x42,
    checkpoint = 0x43,
    _, // any other byte is opaque -- do not fail-closed on an unrecognized ccode
};

pub const Reject = struct {
    /// Name of the rejected message type (`var_str`), e.g. `"tx"`.
    message: []const u8,
    ccode: RejectCode,
    /// Human-readable reason (`var_str`).
    reason: []const u8,
    /// "Optional extra data" -- typically the TXID or block hash of the
    /// rejected object when present, but the wiki gives no length prefix
    /// for it (`0+ char`): treated as "the rest of the payload".
    data: []const u8,

    pub fn deinit(_: *Reject, _: Allocator) void {}
};

pub fn decodeReject(bytes: []const u8) DecodeError!Reject {
    var r: Reader = .{ .bytes = bytes };
    const msg = try r.varBytes();
    const ccode: RejectCode = @enumFromInt(try r.byte());
    const reason = try r.varBytes();
    const data = r.rest();
    return .{ .message = msg, .ccode = ccode, .reason = reason, .data = data };
}

pub fn serializeReject(allocator: Allocator, rej: Reject) Allocator.Error![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try w.putVarBytes(allocator, rej.message);
    try w.putU8(allocator, @intFromEnum(rej.ccode));
    try w.putVarBytes(allocator, rej.reason);
    try w.putBytes(allocator, rej.data);
    return w.toOwned(allocator);
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "Ping/Pong: round-trip" {
    const allocator = testing.allocator;
    const ping_bytes = try serializePing(allocator, .{ .nonce = 0x0102030405060708 });
    defer allocator.free(ping_bytes);
    try testing.expectEqualSlices(u8, &.{ 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01 }, ping_bytes);
    const ping = try decodePing(ping_bytes);
    try testing.expectEqual(@as(u64, 0x0102030405060708), ping.nonce);

    const pong_bytes = try serializePong(allocator, .{ .nonce = 42 });
    defer allocator.free(pong_bytes);
    const pong = try decodePong(pong_bytes);
    try testing.expectEqual(@as(u64, 42), pong.nonce);
}

test "hostile: decodePing on fewer than 8 bytes fails closed" {
    try testing.expectError(error.Truncated, decodePing(&.{ 1, 2, 3 }));
}

// ── externally anchored: wiki's "Hexdump example of addr message" ───────
test "external: Addr decodes the wiki's own worked example byte-exact" {
    const payload = [_]u8{
        0x01, // 1 address in this message
        0xe2, 0x15, 0x10, 0x4d, // time
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // services
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff, 0x0a, 0x00, 0x00, 0x01,
        0x20, 0x8d, // port
    };
    const allocator = testing.allocator;
    var addr = try decodeAddr(allocator, &payload);
    defer addr.deinit(allocator);
    try testing.expectEqual(@as(usize, 1), addr.entries.len);
    try testing.expectEqual(@as(u32, 0x4d1015e2), addr.entries[0].time);
    try testing.expectEqual(@as(u16, 8333), addr.entries[0].addr.port);

    const reser = try serializeAddr(allocator, addr);
    defer allocator.free(reser);
    try testing.expectEqualSlices(u8, &payload, reser);
}

test "hostile: Addr rejects a count over MAX_ADDR_ENTRIES" {
    const allocator = testing.allocator;
    var w: Writer = .{};
    defer w.deinit(allocator);
    try w.putCompactSize(allocator, MAX_ADDR_ENTRIES + 1);
    try testing.expectError(error.TooManyItems, decodeAddr(allocator, w.list.items));
}

test "hostile: Addr rejects a count over MAX_ADDR_ENTRIES even with genuinely enough bytes behind it (isolates the wiki's own cap from the separate insufficient-bytes guard)" {
    // The previous test's count (MAX_ADDR_ENTRIES + 1) has NO bytes behind
    // it at all, so it can't tell whether MAX_ADDR_ENTRIES's own ceiling
    // check (line above) or the separate "not enough bytes for this many
    // entries" guard is what actually rejected it — removing the
    // MAX_ADDR_ENTRIES check entirely still passed every existing test.
    // This test supplies REAL, fully-decodable entries past the cap so
    // only the explicit ceiling can catch it.
    const allocator = testing.allocator;
    const over_cap = MAX_ADDR_ENTRIES + 1;
    var w: Writer = .{};
    defer w.deinit(allocator);
    try w.putCompactSize(allocator, over_cap);
    const one_entry: TimedNetAddr = .{ .time = 0, .addr = .{ .services = 0, .ip = @splat(0), .port = 0 } };
    var i: u64 = 0;
    while (i < over_cap) : (i += 1) try one_entry.encode(&w, allocator);
    try testing.expectError(error.TooManyItems, decodeAddr(allocator, w.list.items));
}

test "hostile: Addr rejects a huge count with insufficient bytes behind it" {
    const allocator = testing.allocator;
    var w: Writer = .{};
    defer w.deinit(allocator);
    try w.putCompactSize(allocator, 900); // under MAX_ADDR_ENTRIES, but nothing follows
    try testing.expectError(error.TooManyItems, decodeAddr(allocator, w.list.items));
}

test "Reject: round-trip, matches the wiki's documented CCodes" {
    const allocator = testing.allocator;
    const txid: [32]u8 = @splat(0xcd);
    const rej: Reject = .{ .message = "tx", .ccode = .dust, .reason = "output below dust threshold", .data = &txid };
    const bytes = try serializeReject(allocator, rej);
    defer allocator.free(bytes);

    var decoded = try decodeReject(bytes);
    defer decoded.deinit(allocator);
    try testing.expectEqualStrings("tx", decoded.message);
    try testing.expectEqual(RejectCode.dust, decoded.ccode);
    try testing.expectEqualStrings("output below dust threshold", decoded.reason);
    try testing.expectEqualSlices(u8, &([_]u8{0xcd} ** 32), decoded.data);
}

test "Reject: an unrecognized ccode byte is opaque, not rejected" {
    const allocator = testing.allocator;
    var w: Writer = .{};
    defer w.deinit(allocator);
    try w.putVarBytes(allocator, "block");
    try w.putU8(allocator, 0x99); // not one of the documented CCodes
    try w.putVarBytes(allocator, "unknown");
    var rej = try decodeReject(w.list.items);
    defer rej.deinit(allocator);
    try testing.expectEqual(@as(u8, 0x99), @intFromEnum(rej.ccode));
}

test "hostile: decodeAddr/decodeReject never panic on truncated buffers" {
    try testing.expectError(error.Truncated, decodeReject(&.{}));
    const allocator = testing.allocator;
    // count=1 with 0 bytes remaining: the fail-fast remaining-bytes bound
    // (not a per-field Truncated) is what actually catches this -- see
    // module doc comment.
    try testing.expectError(error.TooManyItems, decodeAddr(allocator, &.{0x01}));
}

test "fuzz: decodeAddr never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzAddr, .{});
}

fn fuzzAddr(_: void, smith: *std.testing.Smith) !void {
    const allocator = testing.allocator;
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    var a = decodeAddr(allocator, buf[0..len]) catch return;
    defer a.deinit(allocator);
}

test "fuzz: decodeReject never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzReject, .{});
}

fn fuzzReject(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    _ = decodeReject(buf[0..len]) catch return;
}
