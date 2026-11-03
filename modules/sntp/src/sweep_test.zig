// SPDX-License-Identifier: MIT
//! No-panic sweep tests for sntp, wave GV. Finding SN-1, see
//! ~/CML/20261029-panic-sweep/sntp-sweep.report.md.
const std = @import("std");
const testing = std.testing;
const sntp = @import("root.zig");
const Timestamp = sntp.Timestamp;
const testkit = @import("testkit");
const net = std.Io.net;

test "fromUnixNanos: the largest i128 does not overflow the offset addition (sweep SN-1)" {
    // maxInt(i128) + the 1900 offset used to be a signed overflow.
    const t = Timestamp.fromUnixNanos(std.math.maxInt(i128));
    const secs: u128 = @as(u128, std.math.maxInt(i128)) / std.time.ns_per_s;
    try testing.expectEqual(@as(u32, @truncate(secs)), t.seconds);
}

test "fromUnixNanos: instants past the u64 nanosecond range wrap like the era rollover (sweep SN-1)" {
    const off = sntp.ntp_unix_offset_ns;
    const ns_per_s = std.time.ns_per_s;
    // NTP-ns == maxInt(u64) is the old edge and must be unchanged ...
    const edge = Timestamp.fromUnixNanos(@as(i128, std.math.maxInt(u64)) - off);
    try testing.expectEqual(Timestamp.fromNanosSinceNtpEpoch(std.math.maxInt(u64)), edge);
    // ... one nanosecond further (NTP-ns == 2^64) used to trap in `@intCast`.
    const past = Timestamp.fromUnixNanos((@as(i128, 1) << 64) - off);
    const ns: u128 = @as(u128, 1) << 64;
    const rem: u64 = @intCast(ns % ns_per_s);
    try testing.expectEqual(@as(u32, @truncate(ns / ns_per_s)), past.seconds);
    try testing.expectEqual(@as(u32, @intCast((rem << 32) / ns_per_s)), past.fraction);
    // The seconds field is periodic with 2^32 s, far beyond the u64 range too.
    const x: i128 = (@as(i128, 1) << 70) - off;
    const period: i128 = (@as(i128, 1) << 32) * ns_per_s;
    try testing.expectEqual(Timestamp.fromUnixNanos(x), Timestamp.fromUnixNanos(x + period));
    // Before 1900 stays the zero sentinel, including the most negative value.
    try testing.expectEqual(Timestamp.zero, Timestamp.fromUnixNanos(std.math.minInt(i128)));
}

/// Loopback "NTP server": reads the request, then sends a forged
/// Kiss-o'-Death with a wrong nonce, a 47-byte datagram, a truncated-looking
/// garbage datagram and finally the genuine reply, all from the right address.
fn forgingServer(io: std.Io, sock: net.Socket) void {
    var buf: [64]u8 = undefined;
    const t: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(3000), .clock = .awake } };
    const incoming = sock.receiveTimeout(io, &buf, t.toDeadline(io)) catch return;
    const req = sntp.Packet.decode(incoming.data) catch return;
    const nonce = req.transmit;
    const wrong: Timestamp = .{ .seconds = nonce.seconds, .fraction = nonce.fraction +% 1 };
    const kod: sntp.Packet = .{ .mode = .server, .stratum = 0, .reference_id = "DENY".*, .originate = wrong, .receive = nonce, .transmit = nonce };
    const kod_wire = kod.encode();
    sock.send(io, &incoming.from, &kod_wire) catch return;
    sock.send(io, &incoming.from, kod_wire[0..47]) catch return;
    const good: sntp.Packet = .{ .mode = .server, .stratum = 2, .originate = nonce, .receive = nonce, .transmit = nonce };
    const good_wire = good.encode();
    sock.send(io, &incoming.from, &good_wire) catch return;
}

test "query: forged replies (wrong-nonce KoD, short datagram) are skipped, the genuine reply after them wins (sweep audit GV-A3)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    const sock = addr.bind(io, .{ .mode = .dgram }) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    defer sock.close(io);
    const server: net.IpAddress = .{ .ip4 = .loopback(sock.address.getPort()) };
    var fut = try io.concurrent(forgingServer, .{ io, sock });
    var kiss: sntp.KissOfDeath = undefined;
    const res = sntp.query(io, server, .{ .timeout_ms = 3000 }, &kiss);
    fut.await(io);
    const result = try res;
    try testing.expectEqual(@as(u8, 2), result.reply.stratum);
}

// ── grade-2 additions (2026-11-03): every new pub input ─────────────────────

test "sweep: Timestamp.diffNanos / toUnixNanosInferEra / toUnixNanosNear take any value" {
    const edges = [_]u32{ 0, 1, 0x7FFF_FFFF, 0x8000_0000, 0xFFFF_FFFF };
    const pivots = [_]i128{ std.math.minInt(i128), -1, 0, 1, std.math.maxInt(i128), 3_800_000_000 * @as(i128, std.time.ns_per_s) };
    for (edges) |sa| for (edges) |fa| for (edges) |sb| {
        const a: Timestamp = .{ .seconds = sa, .fraction = fa };
        const b: Timestamp = .{ .seconds = sb, .fraction = 0xFFFF_FFFF };
        _ = a.diffNanos(b);
        _ = a.toUnixNanosInferEra();
        for (pivots) |p| _ = a.toUnixNanosNear(p);
        const smp: sntp.Sample = .{ .originate = a, .receive = b, .transmit = a, .destination = b };
        _ = smp.offsetNanos();
        _ = smp.roundtripDelayNanos();
        _ = smp.minErrorNanos();
    };
}

test "sweep: Packet helpers over every poll / precision / root value, checkSynchronization over hostile packets" {
    var buf: [16]u8 = undefined;
    for (0..256) |i| {
        var p: sntp.Packet = .{ .poll = @bitCast(@as(u8, @intCast(i))), .precision = @bitCast(@as(u8, @intCast(i))), .stratum = @intCast(i) };
        _ = p.pollSeconds();
        _ = p.precisionSeconds();
        _ = p.referenceText(&buf);
        p.reference_id = .{ 0xFF, 0, 0x7F, 0x20 };
        _ = p.referenceText(&buf);
        p.root_delay = std.math.maxInt(u32);
        p.root_dispersion = std.math.maxInt(u32);
        _ = p.rootDelayNanos();
        _ = p.rootDispersionNanos();
        p.reference = .{ .seconds = @truncate(@as(u64, i) * 0x01010101), .fraction = 1 };
        p.transmit = .{ .seconds = @truncate(@as(u64, 255 - i) * 0x01010101) };
        sntp.checkSynchronization(p) catch {};
    }
}

test "sweep: Auth.verify / sign / compute over every length, key size and algorithm" {
    var key: [70]u8 = @splat(0x5A);
    var data: [140]u8 = @splat(0xA5);
    var out: [sntp.packet_len + sntp.Auth.max_trailer_len]u8 = undefined;
    var mac: [sntp.Auth.max_mac_len]u8 = undefined;
    inline for (@typeInfo(sntp.MacAlgorithm).@"enum".field_names) |name| {
        const alg = @field(sntp.MacAlgorithm, name);
        for ([_]usize{ 0, 3, 4, 16, 32, 33, 70 }) |kl| {
            const a: sntp.Auth = .{ .algorithm = alg, .key_id = 0xFFFF_FFFF, .key = key[0..kl] };
            for ([_]u3{ 0, 3, 4, 5, 7 }) |v| {
                _ = a.compute(v, data[0..sntp.packet_len], &mac) catch continue;
                _ = a.sign(v, data[0..sntp.packet_len], &out) catch continue;
                for (0..data.len + 1) |n| a.verify(v, data[0..n]) catch {};
            }
        }
    }
}

test "sweep: query refuses a mismatched local address without a socket" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const server: net.IpAddress = .{ .ip6 = .loopback(9) };
    try testing.expectError(error.LocalAddressMismatch, sntp.query(threaded.io(), server, .{ .local_address = .{ .ip4 = .loopback(0) } }, null));
}

fn authServer(io: std.Io, sock: net.Socket, a: sntp.Auth) void {
    var buf: [128]u8 = undefined;
    const t: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(3000), .clock = .awake } };
    const incoming = sock.receiveTimeout(io, &buf, t.toDeadline(io)) catch return;
    if (incoming.data.len != 48 + 4 + 20) return;
    a.verify(4, incoming.data) catch return; // the request itself must carry a valid MAC
    const nonce = (sntp.Packet.decode(incoming.data[0..48]) catch return).transmit;
    const good: sntp.Packet = .{ .mode = .server, .stratum = 2, .originate = nonce, .receive = nonce, .transmit = nonce };
    // 1: a crypto-NAK (needs no key), 2: a reply with a wrong MAC, 3: the genuine one
    var nak: [52]u8 = @splat(0);
    @memcpy(nak[0..48], &good.encode());
    sock.send(io, &incoming.from, &nak) catch return;
    var out: [sntp.packet_len + sntp.Auth.max_trailer_len]u8 = undefined;
    const wrong: sntp.Auth = .{ .algorithm = a.algorithm, .key_id = a.key_id, .key = "an entirely different key" };
    const n1 = wrong.sign(4, &good.encode(), &out) catch return;
    sock.send(io, &incoming.from, out[0..n1]) catch return;
    const n2 = a.sign(4, &good.encode(), &out) catch return;
    sock.send(io, &incoming.from, out[0..n2]) catch return;
}

test "query with a key: a forged NAK and a wrong-MAC reply do not end it, the genuine signed reply wins (review M3)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    const sock = addr.bind(io, .{ .mode = .dgram }) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    defer sock.close(io);
    const server: net.IpAddress = .{ .ip4 = .loopback(sock.address.getPort()) };
    const a: sntp.Auth = .{ .algorithm = .sha256, .key_id = 5, .key = "0123456789abcdef" };
    var fut = try io.concurrent(authServer, .{ io, sock, a });
    const res = sntp.query(io, server, .{ .timeout_ms = 3000, .auth = a, .check_sync = false }, null);
    fut.await(io);
    const result = try res;
    try testing.expectEqual(@as(u8, 2), result.reply.stratum);
}

fn nakOnlyServer(io: std.Io, sock: net.Socket) void {
    var buf: [128]u8 = undefined;
    const t: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(3000), .clock = .awake } };
    const incoming = sock.receiveTimeout(io, &buf, t.toDeadline(io)) catch return;
    const nonce = (sntp.Packet.decode(incoming.data[0..48]) catch return).transmit;
    const p: sntp.Packet = .{ .mode = .server, .stratum = 2, .originate = nonce, .receive = nonce, .transmit = nonce };
    var nak: [52]u8 = @splat(0);
    @memcpy(nak[0..48], &p.encode());
    sock.send(io, &incoming.from, &nak) catch return;
}

test "query with a key: only a NAK arrives -> CryptoNak at the deadline, not an early return (review M3)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    const sock = addr.bind(io, .{ .mode = .dgram }) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    defer sock.close(io);
    const server: net.IpAddress = .{ .ip4 = .loopback(sock.address.getPort()) };
    const a: sntp.Auth = .{ .algorithm = .sha1, .key_id = 5, .key = "0123456789abcdef" };
    var fut = try io.concurrent(nakOnlyServer, .{ io, sock });
    const res = sntp.query(io, server, .{ .timeout_ms = 400, .auth = a }, null);
    fut.await(io);
    try testing.expectError(error.CryptoNak, res);
}

test "Auth.validate refuses key id 0, the crypto-NAK marker (review L1)" {
    const a: sntp.Auth = .{ .algorithm = .sha1, .key_id = 0, .key = "0123456789abcdef" };
    try testing.expectError(error.InvalidAuthKey, a.validate());
}

test "diffNanos: a difference of exactly half an era is -half an era both ways (review L5)" {
    const half: Timestamp = .{ .seconds = 0x8000_0000 };
    const want: i128 = -(@as(i128, 1) << 31) * std.time.ns_per_s;
    try testing.expectEqual(want, half.diffNanos(.zero));
    try testing.expectEqual(want, Timestamp.zero.diffNanos(half));
}
