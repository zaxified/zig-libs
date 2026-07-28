// SPDX-License-Identifier: MIT
//! `version`/`verack` -- the connection handshake. "When a node creates
//! an outgoing connection, it will immediately advertise its version...
//! No further communication is possible until both peers have exchanged
//! their version" (Bitcoin wiki). This module only (de)serializes the
//! two messages; the handshake *sequencing* (send version, wait for
//! verack, reject any other message first) is connection-lifecycle state
//! this codec-only library does not own -- see `SPEC.md`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const message = @import("message.zig");
const Reader = message.Reader;
const Writer = message.Writer;
const net_addr = @import("net_addr.zig");
const NetAddr = net_addr.NetAddr;

pub const DecodeError = message.ReadError || message.CompactSizeError;

/// Bits of `Version.services` / `NetAddr.services` -- "The following
/// services are currently assigned" per the wiki's version-message
/// section. Not exhaustive of every historical proposal (`NODE_XTHIN`
/// was "never formally proposed... and discontinued" -- omitted); these
/// are the deployed bits a caller actually needs to test/set.
pub const NODE_NETWORK: u64 = 1;
pub const NODE_GETUTXO: u64 = 1 << 1;
pub const NODE_BLOOM: u64 = 1 << 2;
pub const NODE_WITNESS: u64 = 1 << 3;
pub const NODE_COMPACT_FILTERS: u64 = 1 << 6;
pub const NODE_NETWORK_LIMITED: u64 = 1 << 10;

/// The `version` message payload.
///
/// `addr_recv`/`addr_from` use the NO-timestamp `net_addr` form (the
/// wiki: "Network addresses are not prefixed with a timestamp in the
/// version message" -- unlike `addr`'s `TimedNetAddr` entries).
/// `user_agent` is a borrowed slice (see `message.zig`'s module doc
/// comment). `relay` is `null` when the field is absent (wire versions
/// below 70001 -- BIP37 -- never send it); present in every version
/// actually deployed on the network today.
pub const Version = struct {
    version: i32,
    services: u64,
    timestamp: i64,
    addr_recv: NetAddr,
    addr_from: NetAddr,
    nonce: u64,
    user_agent: []const u8,
    start_height: i32,
    relay: ?bool = null,

    pub fn deinit(_: *Version, _: Allocator) void {}
};

pub fn decodeVersion(bytes: []const u8) DecodeError!Version {
    var r: Reader = .{ .bytes = bytes };
    const version = try r.i32le();
    const services = try r.u64le();
    const timestamp = try r.i64le();
    const addr_recv = try NetAddr.decode(&r);
    const addr_from = try NetAddr.decode(&r);
    const nonce = try r.u64le();
    const user_agent = try r.varBytes();
    const start_height = try r.i32le();
    const relay: ?bool = if (r.remaining() > 0) try r.boolByte() else null;
    return .{
        .version = version,
        .services = services,
        .timestamp = timestamp,
        .addr_recv = addr_recv,
        .addr_from = addr_from,
        .nonce = nonce,
        .user_agent = user_agent,
        .start_height = start_height,
        .relay = relay,
    };
}

pub fn serializeVersion(allocator: Allocator, v: Version) Allocator.Error![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try w.putI32le(allocator, v.version);
    try w.putU64le(allocator, v.services);
    try w.putI64le(allocator, v.timestamp);
    try v.addr_recv.encode(&w, allocator);
    try v.addr_from.encode(&w, allocator);
    try w.putU64le(allocator, v.nonce);
    try w.putVarBytes(allocator, v.user_agent);
    try w.putI32le(allocator, v.start_height);
    if (v.relay) |relay| try w.putBool(allocator, relay);
    return w.toOwned(allocator);
}

/// `verack` (and `getaddr`, `mempool`, ...) carry no payload at all; this
/// checks exactly that.
pub fn decodeEmpty(bytes: []const u8) error{UnexpectedPayload}!void {
    if (bytes.len != 0) return error.UnexpectedPayload;
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

// ── externally anchored: the wiki's own "modern (60002) protocol
// version" hex dump, field-by-field ───────────────────────────────────
test "external: decodeVersion matches the wiki's published field breakdown byte-exact" {
    // Payload only (envelope stripped -- see envelope.zig's test for the
    // full wire form of this exact message).
    const payload = [_]u8{
        0x62, 0xea, 0x00, 0x00, // version = 60002
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // services = 1 (NODE_NETWORK)
        0x11, 0xb2, 0xd0, 0x50, 0x00, 0x00, 0x00, 0x00, // timestamp
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // addr_recv
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // addr_from
        0x3b, 0x2e, 0xb3, 0x5d, 0x8c, 0xe6, 0x17, 0x65, // nonce
        0x0f, 0x2f, 0x53, 0x61, 0x74, 0x6f, 0x73, 0x68, 0x69, 0x3a, 0x30, 0x2e, 0x37, 0x2e, 0x32, 0x2f, // "/Satoshi:0.7.2/" (var_str)
        0xc0, 0x3e, 0x03, 0x00, // start_height
    };
    var v = try decodeVersion(&payload);
    defer v.deinit(testing.allocator);
    try testing.expectEqual(@as(i32, 60002), v.version);
    try testing.expectEqual(NODE_NETWORK, v.services);
    try testing.expectEqualStrings("/Satoshi:0.7.2/", v.user_agent);
    try testing.expectEqual(@as(i32, 212672), v.start_height); // wiki: "block #212672"
    try testing.expectEqual(@as(?bool, null), v.relay); // protocol 60002 predates BIP37's relay byte

    const reser = try serializeVersion(testing.allocator, v);
    defer testing.allocator.free(reser);
    try testing.expectEqualSlices(u8, &payload, reser);
}

test "Version: round-trip with a relay byte present (protocol >= 70001)" {
    const allocator = testing.allocator;
    const v: Version = .{
        .version = 70015,
        .services = NODE_NETWORK | NODE_WITNESS,
        .timestamp = 1_600_000_000,
        .addr_recv = .{ .services = 0, .ip = @splat(0), .port = 0 },
        .addr_from = .{ .services = 0, .ip = @splat(0), .port = 0 },
        .nonce = 0xdeadbeefcafebabe,
        .user_agent = "/zig-libs:0.1/",
        .start_height = 800_000,
        .relay = true,
    };
    const bytes = try serializeVersion(allocator, v);
    defer allocator.free(bytes);

    var decoded = try decodeVersion(bytes);
    defer decoded.deinit(allocator);
    try testing.expectEqual(v.version, decoded.version);
    try testing.expectEqual(v.services, decoded.services);
    try testing.expectEqualStrings(v.user_agent, decoded.user_agent);
    try testing.expectEqual(@as(?bool, true), decoded.relay);
}

test "decodeEmpty: accepts a zero-length payload, rejects any other" {
    try decodeEmpty(&.{});
    try testing.expectError(error.UnexpectedPayload, decodeEmpty(&.{0x00}));
}

test "hostile: decodeVersion on a truncated buffer (cut mid addr_recv) fails closed" {
    const payload = [_]u8{ 0x62, 0xea, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    try testing.expectError(error.Truncated, decodeVersion(&payload));
}

test "hostile: decodeVersion with a user_agent length prefix exceeding remaining bytes fails closed" {
    const allocator = testing.allocator;
    var w: Writer = .{};
    defer w.deinit(allocator);
    try w.putI32le(allocator, 1);
    try w.putU64le(allocator, 0);
    try w.putI64le(allocator, 0);
    const zero_addr: NetAddr = .{ .services = 0, .ip = @splat(0), .port = 0 };
    try zero_addr.encode(&w, allocator);
    try zero_addr.encode(&w, allocator);
    try w.putU64le(allocator, 0);
    try w.putCompactSize(allocator, 0xff); // claims 255 bytes of user_agent, none follow
    try testing.expectError(error.Truncated, decodeVersion(w.list.items));
}

test "fuzz: decodeVersion never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzDecodeVersion, .{});
}

fn fuzzDecodeVersion(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    var v = decodeVersion(buf[0..len]) catch return;
    v.deinit(testing.allocator);
}
