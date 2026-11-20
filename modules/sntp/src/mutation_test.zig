// SPDX-License-Identifier: MIT
//! Tests added by the whole-module mutation of `root.zig`: boundary
//! cases the mutants found open (clamp edge, era boundary, rounding direction,
//! printable-ASCII limits, key length limits, datagram length checks) and a
//! scripted loopback "server" that sees what `query` puts on the wire and
//! answers with a skewed clock, so the T1/T4 clock, the request fields, the
//! authentication version and the datagram truncation rule are all observed.
const std = @import("std");
const testing = std.testing;
const sntp = @import("root.zig");
const Timestamp = sntp.Timestamp;
const Packet = sntp.Packet;
const testkit = @import("testkit");
const net = std.Io.net;

const ns_per_s: i128 = std.time.ns_per_s;
const era_ns: i128 = (@as(i128, 1) << 32) * ns_per_s;

test "Timestamp.isZero: either field alone makes it non-zero" {
    try testing.expect(Timestamp.zero.isZero());
    try testing.expect(!(Timestamp{ .seconds = 1 }).isZero());
    try testing.expect(!(Timestamp{ .fraction = 1 }).isZero());
}

test "fromUnixNanos: one nanosecond after 1900 is not the zero sentinel" {
    try testing.expectEqual(Timestamp.zero, Timestamp.fromUnixNanos(-sntp.ntp_unix_offset_ns));
    // 2^32 / 1e9 = 4.29 -> 4
    try testing.expectEqual(Timestamp{ .seconds = 0, .fraction = 4 }, Timestamp.fromUnixNanos(1 - sntp.ntp_unix_offset_ns));
}

test "toUnixNanosInferEra: seconds == the Unix offset is 1970 itself (era 0), one below is era 1" {
    const at_1970: Timestamp = .{ .seconds = @intCast(sntp.ntp_unix_offset_s) };
    try testing.expectEqual(@as(i128, 0), at_1970.toUnixNanosInferEra());
    const before: Timestamp = .{ .seconds = @intCast(sntp.ntp_unix_offset_s - 1) };
    try testing.expectEqual(era_ns - ns_per_s, before.toUnixNanosInferEra());
}

test "toUnixNanosNear: nearest era, half an era rounds up, a far-below pivot rounds toward minus infinity" {
    const t: Timestamp = .{ .seconds = @intCast(sntp.ntp_unix_offset_s) }; // Unix 0
    try testing.expectEqual(@as(i128, 0), t.toUnixNanosNear(@divTrunc(era_ns * 4, 10)));
    try testing.expectEqual(era_ns, t.toUnixNanosNear(@divTrunc(era_ns * 6, 10)));
    try testing.expectEqual(era_ns, t.toUnixNanosNear(@divTrunc(era_ns, 2)));
    try testing.expectEqual(-era_ns, t.toUnixNanosNear(-@divTrunc(era_ns * 8, 10)));
}

test "Packet: rootDelaySeconds and rootDispersionSeconds read their own fields" {
    const p: Packet = .{ .root_delay = 0x0002_0000, .root_dispersion = 0x0001_8000 };
    try testing.expectEqual(@as(f64, 2.0), p.rootDelaySeconds());
    try testing.expectEqual(@as(f64, 1.5), p.rootDispersionSeconds());
}

test "Packet.pollSeconds: 0 is 1 s, 62 the largest shift, 63 and negatives are 0" {
    try testing.expectEqual(@as(u64, 1), (Packet{ .poll = 0 }).pollSeconds());
    try testing.expectEqual(@as(u64, 1) << 62, (Packet{ .poll = 62 }).pollSeconds());
    try testing.expectEqual(@as(u64, 0), (Packet{ .poll = 63 }).pollSeconds());
    try testing.expectEqual(@as(u64, 0), (Packet{ .poll = -1 }).pollSeconds());
}

test "Packet.referenceText: space and tilde are printable, 0x1f, 0x7f and 0x80 are dots" {
    var buf: [16]u8 = undefined;
    const a: Packet = .{ .stratum = 1, .reference_id = .{ 0x20, 0x7e, 'A', 0 } };
    try testing.expectEqualStrings(". ~A.", a.referenceText(&buf));
    const b: Packet = .{ .stratum = 1, .reference_id = .{ 0x1f, 0x7f, 0x80, 'x' } };
    try testing.expectEqualStrings("....x.", b.referenceText(&buf));
    const c: Packet = .{ .stratum = 2, .reference_id = .{ 10, 20, 30, 40 } };
    try testing.expectEqualStrings("10.20.30.40", c.referenceText(&buf));
    const d: Packet = .{ .stratum = 1, .reference_id = .{ 'G', 'P', 'S', 0 } };
    try testing.expectEqualStrings(".GPS.", d.referenceText(&buf));
}

test "decodeResponse: a kiss code is four bytes in 0x21..0x7e, nothing else" {
    const kod = [_][4]u8{ "!ABC".*, "ABC~".*, "~~~~".*, "!!!!".* };
    for (kod) |id| {
        const wire = (Packet{ .mode = .server, .stratum = 0, .reference_id = id }).encode();
        try testing.expectError(error.KissOfDeath, sntp.decodeResponse(&wire, null));
    }
    const not_kod = [_][4]u8{ " ABC".*, "ABC ".*, "\x7fABC".*, "AB\x7fC".*, "\x1fABC".*, "ABC\x80".* };
    for (not_kod) |id| {
        const wire = (Packet{ .mode = .server, .stratum = 0, .reference_id = id }).encode();
        try testing.expectError(error.UnsynchronizedStratum, sntp.decodeResponse(&wire, null));
    }
}

test "checkSynchronization: transmit == reference and root delay 32 s (lambda exactly 16 s) pass" {
    const t3: Timestamp = .{ .seconds = 3_900_000_000 };
    var r: sntp.Reply = .{ .mode = .server, .stratum = 2, .receive = t3, .transmit = t3, .reference = t3 };
    try sntp.checkSynchronization(r);
    r.reference = .zero;
    r.root_delay = 32 << 16;
    try sntp.checkSynchronization(r);
}

test "Auth.validate: a CMAC key is exactly 16 or 32 bytes, not longer" {
    const key: [40]u8 = @splat(0x33);
    const ok128: sntp.Auth = .{ .algorithm = .aes128_cmac, .key_id = 1, .key = key[0..16] };
    try ok128.validate();
    const ok256: sntp.Auth = .{ .algorithm = .aes256_cmac, .key_id = 1, .key = key[0..32] };
    try ok256.validate();
    const long128: sntp.Auth = .{ .algorithm = .aes128_cmac, .key_id = 1, .key = key[0..17] };
    try testing.expectError(error.InvalidAuthKey, long128.validate());
    const long256: sntp.Auth = .{ .algorithm = .aes256_cmac, .key_id = 1, .key = key[0..33] };
    try testing.expectError(error.InvalidAuthKey, long256.validate());
}

test "Auth.verify: 52 bytes with a non-zero key id is AuthFailed, a longer datagram than the MAC fits is AuthFailed" {
    const a: sntp.Auth = .{ .algorithm = .sha1, .key_id = 9, .key = "0123456789abcdef" };
    const req = (Packet{ .mode = .client }).encode();
    var out: [sntp.packet_len + sntp.Auth.max_trailer_len]u8 = @splat(0);
    const n = try a.sign(4, &req, &out);
    try a.verify(4, out[0..n]);
    try testing.expectError(error.AuthFailed, a.verify(4, out[0 .. n + 1]));
    // key id present, MAC missing: not a crypto-NAK (that is key id 0)
    try testing.expectError(error.AuthFailed, a.verify(4, out[0 .. sntp.packet_len + 4]));
    @memset(out[sntp.packet_len..][0..4], 0);
    try testing.expectError(error.CryptoNak, a.verify(4, out[0 .. sntp.packet_len + 4]));
}

// ── scripted loopback server ────────────────────────────────────────────────

const Script = struct {
    /// Server clock minus the real clock.
    skew_ns: i128 = 0,
    /// Held between T2 and T3.
    hold_ms: u32 = 0,
    root_dispersion: u32 = 0,
    auth: ?sntp.Auth = null,
    /// NTP version the server uses for the request's MAC check and its own MAC.
    auth_version: u3 = 4,
    /// Pad the reply datagram with zeros to this many bytes (0 = as built).
    pad_to: usize = 0,
    // What the server saw.
    got_len: usize = 0,
    got: [128]u8 = undefined,
};

fn serverNow(io: std.Io, skew_ns: i128) Timestamp {
    return Timestamp.fromUnixNanos(@as(i128, std.Io.Timestamp.now(io, .real).nanoseconds) + skew_ns);
}

fn scriptServer(io: std.Io, sock: net.Socket, s: *Script) void {
    var buf: [128]u8 = undefined;
    const t: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(3000), .clock = .awake } };
    const incoming = sock.receiveTimeout(io, &buf, t.toDeadline(io)) catch return;
    s.got_len = incoming.data.len;
    @memcpy(s.got[0..incoming.data.len], incoming.data);
    if (s.auth) |a| a.verify(s.auth_version, incoming.data) catch return;
    const req = Packet.decode(incoming.data[0..sntp.packet_len]) catch return;
    const t2 = serverNow(io, s.skew_ns);
    if (s.hold_ms != 0) io.sleep(.fromMilliseconds(s.hold_ms), .awake) catch return;
    const t3 = serverNow(io, s.skew_ns);
    const reply: Packet = .{ .mode = .server, .stratum = 2, .originate = req.transmit, .receive = t2, .transmit = t3, .root_dispersion = s.root_dispersion };
    var wire: [sntp.packet_len + sntp.Auth.max_trailer_len]u8 = @splat(0);
    var n: usize = sntp.packet_len;
    if (s.auth) |a| {
        n = a.sign(s.auth_version, &reply.encode(), &wire) catch return;
    } else wire[0..sntp.packet_len].* = reply.encode();
    var out: [256]u8 = @splat(0);
    @memcpy(out[0..n], wire[0..n]);
    sock.send(io, &incoming.from, out[0..@max(n, s.pad_to)]) catch return;
}

fn runQuery(s: *Script, opts: sntp.QueryOptions) !sntp.QueryResult {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    const sock = addr.bind(io, .{ .mode = .dgram }) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    defer sock.close(io);
    const server: net.IpAddress = .{ .ip4 = .loopback(sock.address.getPort()) };
    var fut = try io.concurrent(scriptServer, .{ io, sock, s });
    const res = sntp.query(io, server, opts, null);
    fut.await(io);
    return res;
}

test "query: T1 and T4 come from the wall clock, the request is a plain client packet with a fresh nonce" {
    var s: Script = .{ .skew_ns = 10 * ns_per_s, .hold_ms = 60 };
    const before = try sntp.nowTimestamp();
    const r = try runQuery(&s, .{ .version = 3 });
    // The server runs 10 s ahead: offset ~ +10 s, round trip ~ 0 (the 60 ms the
    // server held the packet are subtracted).
    try testing.expect(r.offset_ns > 9 * ns_per_s and r.offset_ns < 11 * ns_per_s);
    try testing.expect(r.roundtrip_ns > -1_000_000 and r.roundtrip_ns < ns_per_s);
    try testing.expectEqual(@as(usize, sntp.packet_len), s.got_len);
    const pkt = try Packet.decode(s.got[0..sntp.packet_len]);
    try testing.expectEqual(sntp.Mode.client, pkt.mode);
    try testing.expectEqual(@as(u3, 3), pkt.version);
    // nothing but mode, version and the transmit nonce
    try testing.expectEqualSlices(u8, &(Packet{ .version = 3, .mode = .client, .transmit = pkt.transmit }).encode(), s.got[0..sntp.packet_len]);
    // the nonce keeps the current second and carries 32 random bits
    const secs_diff = @as(i64, pkt.transmit.seconds) - @as(i64, before.seconds);
    try testing.expect(secs_diff >= 0 and secs_diff < 5);
    try testing.expect(pkt.transmit.fraction != 0);
}

test "query: timeout_ms = 0 waits for the reply instead of timing out at once" {
    var s: Script = .{ .hold_ms = 50 };
    const r = try runQuery(&s, .{ .timeout_ms = 0 });
    try testing.expectEqual(@as(u8, 2), r.reply.stratum);
}

test "query: check_sync decides whether a reply with a useless root dispersion is believed" {
    var s: Script = .{ .root_dispersion = 100 << 16 };
    try testing.expectError(error.RootDistanceExceeded, runQuery(&s, .{}));
    var s2: Script = .{ .root_dispersion = 100 << 16 };
    const r = try runQuery(&s2, .{ .check_sync = false });
    try testing.expectEqual(@as(u8, 2), r.reply.stratum);
}

test "query with a key: version 3 signs and verifies with the 32-byte SHA-256 MAC both ways" {
    const a: sntp.Auth = .{ .algorithm = .sha256, .key_id = 5, .key = "0123456789abcdef" };
    var s: Script = .{ .auth = a, .auth_version = 3 };
    const r = try runQuery(&s, .{ .version = 3, .auth = a });
    try testing.expectEqual(@as(u8, 2), r.reply.stratum);
    try testing.expectEqual(@as(usize, sntp.packet_len + 4 + 32), s.got_len);
}

test "query with a key: a datagram longer than the receive buffer is discarded, not verified at its cut length" {
    const a: sntp.Auth = .{ .algorithm = .sha1, .key_id = 5, .key = "0123456789abcdef" };
    // a genuine signed reply (72 bytes) padded past the 116-byte buffer
    var s: Script = .{ .auth = a, .pad_to = 200 };
    try testing.expectError(error.Timeout, runQuery(&s, .{ .auth = a, .timeout_ms = 400 }));
}

test "query: an unusable key is refused before the socket is bound (a taken local port does not mask it)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    const taken = addr.bind(io, .{ .mode = .dgram }) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    defer taken.close(io);
    const port = taken.address.getPort();
    const server: net.IpAddress = .{ .ip4 = .loopback(9) };
    const bad: sntp.Auth = .{ .algorithm = .sha1, .key_id = 1, .key = "k" };
    try testing.expectError(error.InvalidAuthKey, sntp.query(io, server, .{ .local_address = .{ .ip4 = .loopback(port) }, .auth = bad }, null));
}
