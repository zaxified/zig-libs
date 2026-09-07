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

pub const DecodeError = message.ReadError || message.CompactSizeError || error{SubversionTooLong};

/// Cap on `Version.user_agent`. Bitcoin Core: "Maximum length of the user
/// agent string in `version` message" — `MAX_SUBVERSION_LENGTH = 256` in
/// `src/net.h` (fetched and read 2026-08-07,
/// https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/net.h).
/// Unlike `varBytes`'s only other generic cap (the 4 MB envelope ceiling in
/// `envelope.zig`), this is field-specific: `varBytes` itself stays
/// uncapped because `housekeeping.zig`'s `reject` message/reason fields
/// reuse it too, and neither is bounded to 256.
pub const max_subversion_length: usize = 256;

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
    if (user_agent.len > max_subversion_length) return error.SubversionTooLong;
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

/// `testkit.fuzz`, for the corpus at the bottom of this file. A corpus entry
/// is not the frame: `Smith.slice` reads a little-endian `u32` length first,
/// so a raw frame would arrive minus its own first four octets.
/// `testkit/src/fuzz.zig` carries the other two hazards.
const testkit = @import("testkit");
const seed = testkit.fuzz.seed;
const seedHex = testkit.fuzz.seedHex;

// ── externally anchored: the wiki's own "modern (60002) protocol
// version" hex dump, field-by-field ───────────────────────────────────

/// The wiki's 60002 `version` PAYLOAD (envelope stripped -- see
/// envelope.zig's test for the full wire form of this exact message).
/// Container-level so the fuzz corpus below seeds the SAME octets this test
/// anchors, rather than a re-transcription of them.
const wiki_version_payload = [_]u8{
    0x62, 0xea, 0x00, 0x00, // version = 60002
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // services = 1 (NODE_NETWORK)
    0x11, 0xb2, 0xd0, 0x50, 0x00, 0x00, 0x00, 0x00, // timestamp
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // addr_recv
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // addr_from
    0x3b, 0x2e, 0xb3, 0x5d, 0x8c, 0xe6, 0x17, 0x65, // nonce
    0x0f, 0x2f, 0x53, 0x61, 0x74, 0x6f, 0x73, 0x68, 0x69, 0x3a, 0x30, 0x2e, 0x37, 0x2e, 0x32, 0x2f, // "/Satoshi:0.7.2/" (var_str)
    0xc0, 0x3e, 0x03, 0x00, // start_height
};

test "external: decodeVersion matches the wiki's published field breakdown byte-exact" {
    const payload = wiki_version_payload;
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

test "decodeVersion: user_agent exactly at max_subversion_length is accepted, one byte more is SubversionTooLong" {
    const allocator = testing.allocator;
    var at_cap: [max_subversion_length]u8 = @splat('a');
    const v: Version = .{
        .version = 70015,
        .services = 0,
        .timestamp = 0,
        .addr_recv = .{ .services = 0, .ip = @splat(0), .port = 0 },
        .addr_from = .{ .services = 0, .ip = @splat(0), .port = 0 },
        .nonce = 0,
        .user_agent = &at_cap,
        .start_height = 0,
    };
    const bytes = try serializeVersion(allocator, v);
    defer allocator.free(bytes);
    var decoded = try decodeVersion(bytes);
    defer decoded.deinit(allocator);
    try testing.expectEqual(@as(usize, max_subversion_length), decoded.user_agent.len);

    var over: [max_subversion_length + 1]u8 = @splat('a');
    var v2 = v;
    v2.user_agent = &over;
    const bytes2 = try serializeVersion(allocator, v2);
    defer allocator.free(bytes2);
    try testing.expectError(error.SubversionTooLong, decodeVersion(bytes2));
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

/// `version` payloads, in the format `Smith.slice` reads (see `testkit.fuzz`).
///
/// The fixed prefix is 80 octets (version + services + timestamp + two
/// `net_addr`s + nonce) before the first variable-length field, so a random
/// draw shorter than that never reaches `varBytes` at all, and one longer than
/// it lands in `SubversionTooLong` only if the CompactSize it happens to hit
/// says more than 256 with the octets to back it. Both boundaries are here
/// explicitly.
const version_seeds = [_][]const u8{
    seed(&wiki_version_payload), // the wiki's 60002 payload: no relay octet (pre-BIP37)
    seed(&(wiki_version_payload ++ [_]u8{0x01})), // the same with BIP37's relay = true appended
    seedHex("00" ** 80 ++ "00" ++ "00000000"), // an empty user_agent
    seedHex("00" ** 80 ++ "fd0001" ++ "61" ** 256 ++ "00000000"), // a user_agent exactly at max_subversion_length
    seedHex("00" ** 80 ++ "fd0101" ++ "61" ** 257 ++ "00000000"), // SubversionTooLong: one octet over
    seedHex("00" ** 80 ++ "fdff00"), // Truncated: claims 255 user_agent octets, none follow
    seedHex("62ea0000" ++ "0100000000000000"), // Truncated: cut mid addr_recv, the hostile test's payload
};

test "fuzz: decodeVersion never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzDecodeVersion, .{ .corpus = &version_seeds });
}

fn fuzzDecodeVersion(_: void, smith: *std.testing.Smith) !void {
    // ⚠ 512, not the 256 this harness carried before. `max_subversion_length`
    // is 256, so the shortest `version` message that can reach
    // `error.SubversionTooLong` is 80 + 3 + 257 + 4 = 344 octets -- and a seed
    // longer than the buffer is not a big seed, it reads back EMPTY
    // (`Smith.slice` falls back to the range minimum). With a 256-octet buffer
    // this harness could not have reached that refusal, nor even a legal
    // maximum-length user_agent, no matter what it was fed.
    var buf: [512]u8 = undefined;
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
    // length. `bytes` takes `@min(buf.len, in.len)` octets and the ranged draw
    // then finds fewer than the eight it needs and returns the range MINIMUM,
    // so `len` was 0 for every seed and `decodeVersion` saw `buf[0..0]` every
    // single time, with the seed sitting unread in `buf`.
    const len: usize = smith.slice(&buf);
    var v = decodeVersion(buf[0..len]) catch return;
    v.deinit(testing.allocator);
}

test "corpus: every version seed reaches the decoder, and the accepted count is pinned" {
    // ⭐ The measurement, executable rather than written in a comment. Two
    // things it holds that no other test does: a seed longer than the harness's
    // buffer reads back EMPTY (`Smith.slice` falls back to the range minimum),
    // which is silent everywhere else -- and it is exactly what the two
    // 34x-octet seeds above would have done against the old 256-octet buffer;
    // and a corpus where nothing is accepted is a corpus that only exercises
    // the refusal path. Acceptance is not reach, so this pins the number
    // rather than asserting it is > 0.
    var nonempty: usize = 0;
    var accepted: usize = 0;
    for (version_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [512]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        if (decodeVersion(buf[0..len])) |_| {
            accepted += 1;
        } else |_| {}
    }
    try testing.expectEqual(version_seeds.len, nonempty);
    // Measured 2026-09-07: 0 of 7 seeds non-empty and 0 accepted before the
    // draw was fixed, 7 of 7 non-empty and 4 accepted after.
    try testing.expectEqual(@as(usize, 4), accepted);
}

test "external anchor: max_subversion_length is Bitcoin Core's MAX_SUBVERSION_LENGTH" {
    // The boundary test above is written in terms of `max_subversion_length`,
    // so it passes for any value of it — raising the constant to 65535 leaves
    // the whole suite green while silently accepting a `version` message no
    // Core node would. The number itself is the interop claim: Core's
    // `src/net.h` declares `static const unsigned int MAX_SUBVERSION_LENGTH =
    // 256;` and `CNode::SetSubVersion` truncates to it, so a peer that sends
    // more is talking to something that is not Bitcoin Core.
    try testing.expectEqual(@as(usize, 256), max_subversion_length);
}
