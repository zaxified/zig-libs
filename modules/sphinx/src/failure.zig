// SPDX-License-Identifier: MIT
//! BOLT#4 "Returning Errors": the return path of an onion. The node that fails an
//! HTLC builds a failure packet with `create`, every node on the way back
//! obfuscates it with its own shared secret (`forward`), and the origin peels
//! the layers off with `unwrap` until one hop's HMAC verifies, which names the
//! hop that erred. All three take the per-hop 32-byte shared secret that
//! `deriveHopSecrets` (sender) or `process` (relay, its ECDH) produced.
//!
//! Packet layout (before obfuscation): `hmac(32) ‖ failure_len(u16 BE) ‖
//! failuremsg ‖ pad_len(u16 BE) ‖ pad`. `hmac` is HMAC-SHA256 under the `um` key over
//! everything after it; the whole packet is then XORed with the `ammag` key's ChaCha20
//! stream. BOLT#4 requires `failure_len + pad_len >= 256` and recommends exactly
//! 256 (`create`'s default; `createPadded` takes another pad, the spec's own
//! test vector uses 1024), and limits a return packet to 32768 bytes (a relay
//! truncates a longer one).
//!
//! Reference: lightning-onion (lnd) `DecryptError` / `EncryptError`: the origin refuses a packet
//! shorter than 292 bytes and always runs a constant number of rounds (27), a
//! relay obfuscates whatever it received. `failuremsg` is opaque here (BOLT#4
//! "Failure Messages" is the caller's); `parseFailure` only cuts it out.
//! Not implemented: `attribution_data` (BOLT#4 "option_attribution_data").

const std = @import("std");
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const ChaCha20IETF = std.crypto.stream.chacha.ChaCha20IETF;
const timing_safe = std.crypto.timing_safe;
const keyderive = @import("keyderive.zig");
const burn = @import("burn.zig");

pub const hmac_len = 32;
/// BOLT#4: `failure_len + pad_len` is at least this, and `create` pads to exactly this.
pub const min_padded_len = 256;
/// BOLT#4: the longest return packet; a relay truncates a longer one.
pub const max_packet_len = 32768;
/// The shortest packet `unwrap` accepts (`hmac`, two length fields, 256 bytes of message and pad; lnd's bound).
pub const min_packet_len = hmac_len + 2 + 2 + min_padded_len;
/// `unwrap` runs this many rounds at least (BOLT#4 origin requirement, "27 times"), to hide the position of the erring hop.
pub const origin_rounds = 27;

/// Stack bytes zeroed after each entry point: HMAC and ChaCha20 states, the 1 KiB stream chunk, derived keys.
const burn_len = 8 * 1024;
const chunk_len = 1024;

fn applyStream(key: *const [32]u8, buf: []u8, comptime xor: bool) void {
    const zero_nonce = @as([ChaCha20IETF.nonce_length]u8, @splat(0));
    var ks: [chunk_len]u8 = undefined;
    var counter: u32 = 0;
    var off: usize = 0;
    while (off < buf.len) {
        const n = @min(chunk_len, buf.len - off);
        ChaCha20IETF.stream(ks[0..n], counter, key.*, zero_nonce);
        if (xor) for (buf[off..][0..n], ks[0..n]) |*b, k| {
            b.* ^= k;
        };
        off += n;
        counter += chunk_len / 64;
    }
    std.crypto.secureZero(u8, &ks);
}

fn obfuscate(buf: []u8, shared_secret: *const [32]u8) void {
    var ammag: [32]u8 = undefined;
    keyderive.generateKey(&ammag, .ammag, shared_secret);
    applyStream(&ammag, buf, true);
    std.crypto.secureZero(u8, &ammag);
}

pub const CreateError = error{
    /// The packet (`hmac`, lengths, message, pad) would exceed `max_packet_len`.
    FailureTooLong,
    /// `out` is shorter than `packetLen`.
    OutputTooSmall,
};

/// Total length of the packet `create` builds for a `failure_len`-byte message.
pub fn packetLen(failure_len: usize) usize {
    return hmac_len + 2 + failure_len + 2 + (min_padded_len -| failure_len);
}

/// The erring node's packet for `failuremsg`, padded so that message plus pad is
/// 256 bytes (or the message alone, when longer), authenticated and obfuscated
/// under `shared_secret`. Writes into `out`, returns the used prefix.
pub fn create(out: []u8, shared_secret: *const [32]u8, failuremsg: []const u8) CreateError![]u8 {
    return createPadded(out, shared_secret, failuremsg, @intCast(min_padded_len -| failuremsg.len));
}

/// `create` with an explicit pad length (zero bytes). BOLT#4 requires
/// `failuremsg.len + pad_len >= 256`; this is not checked, a shorter packet is
/// refused by `unwrap` as `PacketTooShort`.
pub fn createPadded(out: []u8, shared_secret: *const [32]u8, failuremsg: []const u8, pad_len: u16) CreateError![]u8 {
    const total = hmac_len + 2 + failuremsg.len + 2 + pad_len;
    if (total > max_packet_len) return error.FailureTooLong;
    if (out.len < total) return error.OutputTooSmall;
    burn.run(burn_len, void, createBody, .{ out[0..total], shared_secret, failuremsg });
    return out[0..total];
}

fn createBody(buf: []u8, shared_secret: *const [32]u8, failuremsg: []const u8) void {
    const fl = failuremsg.len;
    std.mem.writeInt(u16, buf[hmac_len..][0..2], @intCast(fl), .big);
    @memcpy(buf[hmac_len + 2 ..][0..fl], failuremsg);
    const pad_len = buf.len - (hmac_len + 4 + fl);
    std.mem.writeInt(u16, buf[hmac_len + 2 + fl ..][0..2], @intCast(pad_len), .big);
    @memset(buf[hmac_len + 4 + fl ..], 0);
    var um: [32]u8 = undefined;
    keyderive.generateKey(&um, .um, shared_secret);
    HmacSha256.create(buf[0..hmac_len], buf[hmac_len..], &um);
    std.crypto.secureZero(u8, &um);
    obfuscate(buf, shared_secret);
}

/// A relay's step: obfuscate the packet received from downstream with this
/// hop's `ammag` stream, in place. A packet longer than `max_packet_len` is
/// cut to its first 32768 bytes first (BOLT#4); the result is the used prefix.
pub fn forward(packet: []u8, shared_secret: *const [32]u8) []u8 {
    const p = packet[0..@min(packet.len, max_packet_len)];
    burn.run(burn_len, void, forwardBody, .{ p, shared_secret });
    return p;
}

fn forwardBody(p: []u8, shared_secret: *const [32]u8) void {
    obfuscate(p, shared_secret);
}

pub const UnwrapError = error{
    /// Shorter than `min_packet_len`.
    PacketTooShort,
    /// No hop's HMAC verified: the packet is corrupted, from a hop off the route, or from a node that does not follow BOLT#4.
    SourceUnidentified,
};

pub const Source = struct {
    /// Index into the `shared_secrets` passed to `unwrap` (0 = the first hop after the sender).
    hop: usize,
    /// The authenticated bytes after the HMAC (`failure_len ‖ failuremsg ‖ pad_len ‖ pad`), a view into the packet.
    data: []const u8,
};

/// The origin's step: peel one obfuscation layer per hop (`shared_secrets[i]`
/// belongs to the i-th hop of the route, first to last) until a hop's HMAC
/// verifies. That hop erred. `packet` is overwritten (decrypted up to the
/// source; in the `SourceUnidentified` case through all layers); `Source.data`
/// points into it.
///
/// Like lnd it always runs at least `origin_rounds` rounds, using a dummy secret
/// after the source is found, so the time does not show the source's position
/// (best effort: the dummy rounds generate and discard the stream but do not
/// touch the packet). A packet of any length of at least `min_packet_len` is
/// processed; one over `max_packet_len` cannot have been produced by a conforming
/// erring node, and verifies only if an old node did.
pub fn unwrap(packet: []u8, shared_secrets: []const [32]u8) UnwrapError!Source {
    if (packet.len < min_packet_len) return error.PacketTooShort;
    const hop = burn.run(burn_len, ?usize, unwrapBody, .{ packet, shared_secrets }) orelse return error.SourceUnidentified;
    return .{ .hop = hop, .data = packet[hmac_len..] };
}

fn unwrapBody(packet: []u8, shared_secrets: []const [32]u8) ?usize {
    const dummy: [32]u8 = @splat(1);
    var found: ?usize = null;
    for (0..@max(origin_rounds, shared_secrets.len)) |i| {
        const real = found == null and i < shared_secrets.len;
        const ss = if (real) &shared_secrets[i] else &dummy;
        var ammag: [32]u8 = undefined;
        var um: [32]u8 = undefined;
        keyderive.generateKey(&ammag, .ammag, ss);
        keyderive.generateKey(&um, .um, ss);
        if (real) applyStream(&ammag, packet, true) else applyStream(&ammag, packet, false);
        var mac: [hmac_len]u8 = undefined;
        HmacSha256.create(&mac, packet[hmac_len..], &um);
        if (real and timing_safe.eql([hmac_len]u8, mac, packet[0..hmac_len].*)) found = i;
        std.crypto.secureZero(u8, &ammag);
        std.crypto.secureZero(u8, &um);
    }
    return found;
}

pub const ParseError = error{MalformedFailure};

/// The `failuremsg` inside `Source.data`: `failure_len` and that many bytes. The
/// pad and its length field are not checked (they are authenticated, and BOLT#4
/// gives the reader nothing to verify about them).
pub fn parseFailure(data: []const u8) ParseError![]const u8 {
    if (data.len < 2) return error.MalformedFailure;
    const fl = std.mem.readInt(u16, data[0..2], .big);
    if (data.len - 2 < fl) return error.MalformedFailure;
    return data[2..][0..fl];
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;
const vec = @import("failure_vectors.zig");

fn hexN(comptime n: usize, s: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

fn secrets() [5][32]u8 {
    var out: [5][32]u8 = undefined;
    inline for (vec.shared_secrets, 0..) |h, i| out[i] = hexN(32, h);
    return out;
}

test "ammag and um keys equal the BOLT#4 vector" {
    const ss = secrets();
    for (ss, 0..) |s, i| {
        var k: [32]u8 = undefined;
        keyderive.generateKey(&k, .ammag, &s);
        try testing.expectEqualSlices(u8, &hexN(32, vec.ammag_keys[i]), &k);
    }
    var um: [32]u8 = undefined;
    keyderive.generateKey(&um, .um, &ss[4]);
    try testing.expectEqualSlices(u8, &hexN(32, vec.um_key_4), &um);
}

test "KAT: create at hop 4 and forward through hops 3..0 gives the vector's error packet" {
    const ss = secrets();
    var buf: [max_packet_len]u8 = undefined;
    const fm = hexN(2, vec.simple_failure);
    var p = try create(&buf, &ss[4], &fm);
    try testing.expectEqual(@as(usize, 292), p.len);
    var i: usize = 4;
    while (i > 0) {
        i -= 1;
        p = forward(p, &ss[i]);
    }
    try testing.expectEqualSlices(u8, &hexN(292, vec.simple_packet), p);
}

test "KAT: unwrap of the vector's packet names hop 4 and yields the failure message" {
    const ss = secrets();
    var pkt = hexN(292, vec.simple_packet);
    const src = try unwrap(&pkt, &ss);
    try testing.expectEqual(@as(usize, 4), src.hop);
    try testing.expectEqual(@as(usize, 2 + 2 + 2 + 254), src.data.len);
    try testing.expectEqualSlices(u8, &hexN(2, vec.simple_failure), try parseFailure(src.data));
}

test "KAT: spec trace, a 320-byte failure padded to 1024: raw, hop 2 and hop 0 packets, and unwrap" {
    const ss = secrets();
    var buf: [2048]u8 = undefined;
    const fm = hexN(320, vec.trace_failure);
    // The raw packet (before node 4's ammag pass): hmac ++ failure_len ++ msg ++ pad_len ++ pad.
    var p = try createPadded(&buf, &ss[4], &fm, vec.trace_pad_len);
    try testing.expectEqual(@as(usize, 1060), p.len);
    var ammag: [32]u8 = undefined;
    keyderive.generateKey(&ammag, .ammag, &ss[4]);
    applyStream(&ammag, p, true); // undo node 4's pass
    try testing.expectEqualSlices(u8, &hexN(1060, vec.trace_raw_packet), p);
    applyStream(&ammag, p, true);
    var i: usize = 4;
    while (i > 0) {
        i -= 1;
        p = forward(p, &ss[i]);
        if (i == 2) try testing.expectEqualSlices(u8, &hexN(1060, vec.trace_packet_node2), p);
    }
    try testing.expectEqualSlices(u8, &hexN(1060, vec.trace_packet_node0), p);
    const src = try unwrap(p, &ss);
    try testing.expectEqual(@as(usize, 4), src.hop);
    try testing.expectEqualSlices(u8, &fm, try parseFailure(src.data));
}

test "every hop can be the source; the route may be longer than the failing hop's index" {
    const ss = secrets();
    var buf: [1024]u8 = undefined;
    for (0..5) |src_hop| {
        var p = try create(&buf, &ss[src_hop], "hello");
        var i = src_hop;
        while (i > 0) {
            i -= 1;
            p = forward(p, &ss[i]);
        }
        const src = try unwrap(p, &ss);
        try testing.expectEqual(src_hop, src.hop);
        try testing.expectEqualStrings("hello", try parseFailure(src.data));
    }
}

test "unwrap: a packet no hop authenticates is SourceUnidentified (corruption, short route, foreign secret)" {
    const ss = secrets();
    const orig = hexN(292, vec.simple_packet);
    // bit flip in the hmac, in the body, in the last byte
    for ([_]usize{ 0, 31, 32, 100, 291 }) |at| {
        var pkt = orig;
        pkt[at] ^= 1;
        try testing.expectError(error.SourceUnidentified, unwrap(&pkt, &ss));
    }
    // the source hop is missing from the route
    var pkt = orig;
    try testing.expectError(error.SourceUnidentified, unwrap(&pkt, ss[0..4]));
    // empty route
    pkt = orig;
    try testing.expectError(error.SourceUnidentified, unwrap(&pkt, ss[0..0]));
    // another route's secrets
    var other = ss;
    other[4][0] ^= 1;
    pkt = orig;
    try testing.expectError(error.SourceUnidentified, unwrap(&pkt, &other));
}

test "unwrap: lengths 291 refused, 292 accepted; a route longer than 27 hops still finds hop 30" {
    const ss = secrets();
    var short: [291]u8 = undefined;
    @memset(&short, 0);
    try testing.expectError(error.PacketTooShort, unwrap(&short, &ss));

    var route: [40][32]u8 = undefined;
    for (&route, 0..) |*r, i| @memset(r, @intCast(i + 1));
    var buf: [512]u8 = undefined;
    var p = try create(&buf, &route[30], "far");
    var i: usize = 30;
    while (i > 0) {
        i -= 1;
        p = forward(p, &route[i]);
    }
    const src = try unwrap(p, &route);
    try testing.expectEqual(@as(usize, 30), src.hop);
}

test "create: pad rules (256 total, 0 pad from 256 up), limits, output size" {
    const ss = secrets();
    var buf: [max_packet_len]u8 = undefined;
    // message length m -> packet 32 + 2 + m + 2 + max(0, 256 - m)
    const cases = [_]struct { m: usize, total: usize, pad: usize }{
        .{ .m = 0, .total = 292, .pad = 256 },
        .{ .m = 1, .total = 292, .pad = 255 },
        .{ .m = 255, .total = 292, .pad = 1 },
        .{ .m = 256, .total = 292, .pad = 0 },
        .{ .m = 257, .total = 293, .pad = 0 },
        .{ .m = 1000, .total = 1036, .pad = 0 },
        .{ .m = max_packet_len - 36, .total = max_packet_len, .pad = 0 },
    };
    const msg = try testing.allocator.alloc(u8, max_packet_len);
    defer testing.allocator.free(msg);
    @memset(msg, 0x5a);
    for (cases) |c| {
        try testing.expectEqual(c.total, packetLen(c.m));
        const p = try create(&buf, &ss[0], msg[0..c.m]);
        try testing.expectEqual(c.total, p.len);
        var one = [_][32]u8{ss[0]};
        const src = try unwrap(p, &one);
        try testing.expectEqual(c.m + 4 + c.pad, src.data.len);
        try testing.expectEqualSlices(u8, msg[0..c.m], try parseFailure(src.data));
        try testing.expectEqual(c.pad, std.mem.readInt(u16, src.data[2 + c.m ..][0..2], .big));
        try testing.expect(std.mem.allEqual(u8, src.data[4 + c.m ..], 0));
    }
    try testing.expectError(error.FailureTooLong, create(&buf, &ss[0], msg[0 .. max_packet_len - 35]));
    try testing.expectError(error.FailureTooLong, createPadded(&buf, &ss[0], "x", max_packet_len));
    try testing.expectError(error.OutputTooSmall, create(buf[0..291], &ss[0], "x"));
    // exactly big enough
    _ = try create(buf[0..292], &ss[0], "x");
    // a pad that leaves the packet under 292 is built, unwrap refuses it
    var p2 = try createPadded(&buf, &ss[0], "x", 10);
    var one = [_][32]u8{ss[0]};
    try testing.expectError(error.PacketTooShort, unwrap(p2, &one));
    p2 = try createPadded(&buf, &ss[0], "x", 255);
    try testing.expectEqual(@as(usize, 292), p2.len);
}

test "forward: truncates to 32768 bytes, leaves shorter packets at their length" {
    const ss = secrets();
    const big = try testing.allocator.alloc(u8, max_packet_len + 100);
    defer testing.allocator.free(big);
    @memset(big, 0);
    const out = forward(big, &ss[0]);
    try testing.expectEqual(@as(usize, max_packet_len), out.len);
    try testing.expect(!std.mem.allEqual(u8, out, 0));
    // the bytes past the cut are untouched
    try testing.expect(std.mem.allEqual(u8, big[max_packet_len..], 0));
    var small: [292]u8 = @splat(0);
    try testing.expectEqual(@as(usize, 292), forward(&small, &ss[0]).len);
    var empty: [0]u8 = .{};
    try testing.expectEqual(@as(usize, 0), forward(&empty, &ss[0]).len);
}

test "forward is its own inverse (stream cipher), also across the 1 KiB chunk edge" {
    const ss = secrets();
    for ([_]usize{ 292, 1023, 1024, 1025, 2048, 5000 }) |n| {
        const a = try testing.allocator.alloc(u8, n);
        defer testing.allocator.free(a);
        for (a, 0..) |*b, i| b.* = @truncate(i *% 31);
        const orig = try testing.allocator.dupe(u8, a);
        defer testing.allocator.free(orig);
        _ = forward(a, &ss[1]);
        try testing.expect(!std.mem.eql(u8, a, orig));
        // equals a one-shot stream XOR
        const want = try testing.allocator.dupe(u8, orig);
        defer testing.allocator.free(want);
        var key: [32]u8 = undefined;
        keyderive.generateKey(&key, .ammag, &ss[1]);
        const st = try testing.allocator.alloc(u8, n);
        defer testing.allocator.free(st);
        keyderive.generateCipherStream(&key, st);
        for (want, st) |*w, s| w.* ^= s;
        try testing.expectEqualSlices(u8, want, a);
        _ = forward(a, &ss[1]);
        try testing.expectEqualSlices(u8, orig, a);
    }
}

test "parseFailure: bounds" {
    try testing.expectError(error.MalformedFailure, parseFailure(""));
    try testing.expectError(error.MalformedFailure, parseFailure(&.{0}));
    try testing.expectEqual(@as(usize, 0), (try parseFailure(&.{ 0, 0 })).len);
    try testing.expectEqualSlices(u8, &.{ 7, 8 }, try parseFailure(&.{ 0, 2, 7, 8 }));
    try testing.expectEqualSlices(u8, &.{ 7, 8 }, try parseFailure(&.{ 0, 2, 7, 8, 9 }));
    try testing.expectError(error.MalformedFailure, parseFailure(&.{ 0, 3, 7, 8 }));
    try testing.expectError(error.MalformedFailure, parseFailure(&.{ 0xff, 0xff, 1 }));
}

test "unwrap: an authenticated packet with a bad failure_len is attributed, parseFailure refuses it" {
    const ss = secrets();
    var buf: [400]u8 = undefined;
    // 292-byte body whose failure_len claims 1000 bytes, MACed by hop 1 and wrapped by hop 0
    @memset(buf[0..292], 0);
    std.mem.writeInt(u16, buf[32..34], 1000, .big);
    var um: [32]u8 = undefined;
    keyderive.generateKey(&um, .um, &ss[1]);
    HmacSha256.create(buf[0..32], buf[32..292], &um);
    obfuscate(buf[0..292], &ss[1]);
    const p = forward(buf[0..292], &ss[0]);
    const src = try unwrap(p, &ss);
    try testing.expectEqual(@as(usize, 1), src.hop);
    try testing.expectError(error.MalformedFailure, parseFailure(src.data));
}
