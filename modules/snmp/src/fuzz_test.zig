// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver for snmp (added 2026-10-10).
//!
//! `SNMP_FUZZ=<runs>[,<first seed>]` runs the harnesses (testkit's fuzz driver;
//! `_ONLY` selects one by name, `_MS`, `_SEEDFILE`, `_INPUT` as documented
//! there). Each is generic over its source of choices.
//! - `snmp-wire`: genuine v1/v2c messages (get, getnext, getbulk, response,
//!   set, trap, inform with every varbind value type), SNMPv3 envelopes and
//!   USM security parameters, encoded by the module, damaged (0-3 octets,
//!   truncation) and decoded: the undamaged ones decode to what was encoded,
//!   the damaged never panic, and an accepted one iterates to its end.
//! - `snmp-auth-priv`: USM authentication and privacy as an oracle: a signed
//!   message verifies, a flipped octet anywhere (auth field included), a
//!   wrong key or a wrong protocol is refused; encrypt/decrypt round-trips
//!   for DES-CBC and AES-128-CFB, a wrong key, salt or length does not.
//! - `snmp-v3-reply`: a `V3Client` against the in-memory `FakeAgent` whose
//!   reply to the discovery probe or to the request is damaged: undamaged it
//!   returns the agent's value; over an authenticated level a damaged reply is
//!   never data; whatever the level, a reply never panics the client.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const ber = @import("ber.zig");
const message = @import("message.zig");
const v3 = @import("v3.zig");
const usm = @import("usm.zig");
const priv = @import("priv.zig");
const receiver = @import("receiver.zig");
const v3client = @import("v3client.zig");
const client_mod = @import("client.zig");
const Oid = @import("oid.zig").Oid;
pub const fuzz_driver = testkit.fuzz.driver;

/// `frame` into `buf` with 0-3 octets damaged (half within the first 48) and
/// maybe truncated. The driver's `Rng` only.
pub fn damage(src: anytype, buf: []u8, frame: []const u8) usize {
    var n = @min(frame.len, buf.len);
    @memcpy(buf[0..n], frame[0..n]);
    for (0..src.valueRangeAtMost(u8, 0, 3)) |_| {
        if (n == 0) break;
        const span = if (src.value(bool)) @min(n, 48) else n;
        buf[src.index(span)] = src.value(u8);
    }
    if (src.valueRangeAtMost(u8, 0, 3) == 0) n = src.index(n + 1);
    return n;
}

/// Reach counters for one harness file's labels (see jwt's fuzz_test.zig).
pub fn Marker(comptime Label: type) type {
    return struct {
        var counts: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

        pub fn mark(comptime l: Label) void {
            counts[@intFromEnum(l)] += 1;
            fuzz_driver.hit(@tagName(l));
        }

        pub fn reach(comptime harness: anytype, comptime name: []const u8, seeds: usize) !void {
            counts = @splat(0);
            for (0..seeds) |seed| {
                var prng = std.Random.DefaultPrng.init(seed);
                var rng: fuzz_driver.Rng = .{ .r = prng.random() };
                harness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
                    std.debug.print(name ++ " seed {d}: {t}\n", .{ seed, err });
                    return err;
                };
            }
            for (counts, 0..) |n, i| if (n == 0) {
                std.debug.print("reach: " ++ name ++ " label {t} never hit in {d} seeds\n", .{ @as(Label, @enumFromInt(i)), seeds });
                return error.HarnessDoesNotReach;
            };
        }
    };
}

fn flipBit(src: anytype, buf: []u8) void {
    buf[src.index(buf.len)] ^= @as(u8, 1) << @intCast(src.valueRangeAtMost(u8, 0, 7));
}

const all_auth = [_]usm.AuthProtocol{ .hmac_md5, .hmac_sha1, .hmac_sha224, .hmac_sha256, .hmac_sha384, .hmac_sha512 };
const all_priv = [_]priv.PrivProtocol{ .des_cbc, .aes128_cfb };

// ── snmp-wire ───────────────────────────────────────────────────────────────

const WireMark = Marker(enum {
    genuine_decoded,
    damaged_decoded,
    damaged_refused,
    v3_decoded,
    v3_encrypted,
    usm_parsed,
    trap_parsed,
    varbinds_iterated,
    ber_value,
});

/// Varbinds covering every value type, drawn.
fn drawVarbinds(comptime S: type, src: *S, out: []message.VarBind, strings: *[64]u8) usize {
    const n = src.index(out.len + 1);
    src.bytes(strings);
    for (out[0..n], 0..) |*vb, i| {
        vb.name = Oid.parse("1.3.6.1.2.1.1.1.0") catch unreachable;
        vb.value = switch (src.index(13)) {
            0 => .{ .integer = @as(i64, @bitCast(src.value(u64))) },
            1 => .{ .octet_string = strings[i * 4 ..][0..src.index(5)] },
            2 => .null,
            3 => .{ .oid = Oid.parse("1.3.6.1.4.1.9999.1") catch unreachable },
            4 => .{ .ip_address = .{ 10, 0, 0, @intCast(i) } },
            5 => .{ .counter32 = src.value(u32) },
            6 => .{ .gauge32 = src.value(u32) },
            7 => .{ .time_ticks = src.value(u32) },
            8 => .{ .@"opaque" = strings[i * 4 ..][0..src.index(5)] },
            9 => .{ .counter64 = src.value(u64) },
            10 => .no_such_object,
            11 => .no_such_instance,
            else => .end_of_mib_view,
        };
    }
    return n;
}

fn walkVarbinds(list: message.VarBindList) void {
    var it = list.iterator();
    while (it.next() catch return) |vb| {
        _ = vb;
    }
    WireMark.mark(.varbinds_iterated);
}

pub fn fuzzWire(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var vbs: [6]message.VarBind = undefined;
    var strings: [64]u8 = undefined;
    const nvb = drawVarbinds(S, src, &vbs, &strings);
    var buf: [1500]u8 = undefined;
    var wire: []const u8 = &.{};
    var kind: enum { v2c, v3_plain, v3_enc, usm_params, raw } = .v2c;
    if (S == fuzz_driver.Rng) {
        kind = switch (src.valueRangeAtMost(u8, 0, 9)) {
            0, 1, 2, 3 => .v2c,
            4, 5 => .v3_plain,
            6 => .v3_enc,
            7 => .usm_params,
            else => .raw,
        };
    } else kind = .raw;
    var scratch: [64]u8 = undefined;
    const pdu_types = [_]message.PduType{ .get_request, .get_next_request, .get_bulk_request, .response, .set_request, .trap_v2, .inform_request };
    const pdu_type = pdu_types[src.index(pdu_types.len)];
    const pdu: message.EncodePdu = .{
        .type = pdu_type,
        .request_id = @bitCast(src.value(u32)),
        .error_status = @intCast(src.index(19)),
        .error_index = @intCast(src.index(6)),
        .varbinds = vbs[0..nvb],
    };
    switch (kind) {
        .v2c => {
            const community = strings[0..src.index(9)];
            wire = try message.encode(&buf, if (src.value(bool)) .v2c else .v1, community, pdu);
        },
        .v3_plain => wire = try v3.encode(&buf, .{
            .msg_id = @bitCast(src.value(u32) & 0x7fff_ffff),
            .flags = .{ .auth = src.value(bool) },
            .security_parameters = try usm.encode(&scratch, .{ .engine_id = strings[0..src.index(9)], .engine_boots = @intCast(src.index(1000)), .engine_time = @intCast(src.index(100000)), .user_name = strings[8..][0..src.index(9)], .auth_params = &.{}, .priv_params = &.{} }),
            .context_engine_id = strings[0..src.index(9)],
            .pdu = pdu,
        }),
        .v3_enc => wire = try v3.encodeEncrypted(&buf, .{
            .msg_id = @bitCast(src.value(u32) & 0x7fff_ffff),
            .security_parameters = try usm.encode(&scratch, .{ .engine_id = strings[0..9], .engine_boots = 3, .engine_time = 400, .user_name = "u", .auth_params = strings[0..12], .priv_params = strings[12..20] }),
            .encrypted_pdu = strings[20..][0..src.index(40)],
        }),
        .usm_params => wire = try usm.encode(&buf, .{ .engine_id = strings[0..src.index(9)], .engine_boots = @intCast(src.index(1000)), .engine_time = @intCast(src.index(100000)), .user_name = strings[8..][0..src.index(9)], .auth_params = strings[0..12], .priv_params = strings[12..20] }),
        .raw => {},
    }

    var dmg: [1500]u8 = undefined;
    var input: []const u8 = wire;
    var changed = false;
    if (S == fuzz_driver.Rng) {
        if (kind != .raw and src.valueRangeAtMost(u8, 0, 2) != 0) {
            const n = damage(src, &dmg, wire);
            changed = n != wire.len or !std.mem.eql(u8, dmg[0..n], wire);
            input = dmg[0..n];
        } else if (kind == .raw) {
            input = dmg[0..src.slice(&dmg)];
            changed = true;
        }
    } else {
        input = dmg[0..src.slice(&dmg)];
        changed = true;
    }

    // v1/v2c.
    if (message.decode(input)) |m| {
        if (!changed and kind == .v2c) {
            if (m.version != .v1 and m.version != .v2c) return error.WrongVersion;
            const rid = switch (m.pdu) {
                .get_request, .get_next_request, .response, .set_request, .trap_v2, .inform_request, .report => |p| p.request_id,
                .get_bulk_request => |p| p.request_id,
                .trap_v1 => 0,
            };
            if (rid != pdu.request_id) return error.RequestIdChanged;
            const list = switch (m.pdu) {
                .get_request, .get_next_request, .response, .set_request, .trap_v2, .inform_request, .report => |p| p.varbinds,
                .get_bulk_request => |p| p.varbinds,
                .trap_v1 => |p| p.varbinds,
            };
            if ((list.count() catch return error.VarbindsUnreadable) != nvb) return error.VarbindCountChanged;
            WireMark.mark(.genuine_decoded);
        } else WireMark.mark(.damaged_decoded);
        switch (m.pdu) {
            .get_request, .get_next_request, .response, .set_request, .trap_v2, .inform_request, .report => |p| walkVarbinds(p.varbinds),
            .get_bulk_request => |p| walkVarbinds(p.varbinds),
            .trap_v1 => |p| walkVarbinds(p.varbinds),
        }
    } else |_| {
        if (!changed and kind == .v2c) return error.GenuineMessageRefused;
        WireMark.mark(.damaged_refused);
    }
    if (receiver.parseTrap(input)) |_| WireMark.mark(.trap_parsed) else |_| {}

    // v3 envelope.
    if (v3.decode(input)) |m| {
        WireMark.mark(.v3_decoded);
        switch (m.data) {
            .plaintext => |s| walkVarbinds(switch (s.pdu) {
                .get_request, .get_next_request, .response, .set_request, .trap_v2, .inform_request, .report => |p| p.varbinds,
                .get_bulk_request => |p| p.varbinds,
                .trap_v1 => |p| p.varbinds,
            }),
            .encrypted => WireMark.mark(.v3_encrypted),
        }
        if (usm.parse(m.security_parameters)) |_| WireMark.mark(.usm_parsed) else |_| {}
    } else |_| {
        if (!changed and (kind == .v3_plain or kind == .v3_enc)) return error.GenuineV3Refused;
    }
    if (usm.parse(input)) |_| WireMark.mark(.usm_parsed) else |_| {}

    // BER primitives on every element the bytes hold, constructed ones opened.
    berWalk(input, 0);
}

fn berWalk(bytes: []const u8, depth: usize) void {
    var d = ber.Decoder.init(bytes);
    var guard: usize = 0;
    while (!d.done() and guard < 64) : (guard += 1) {
        const tlv = d.any() catch return;
        if (ber.parseValue(tlv)) |_| WireMark.mark(.ber_value) else |_| {}
        _ = ber.parseInteger(tlv.content) catch {};
        _ = ber.parseUnsigned(tlv.content) catch {};
        _ = ber.parseUnsigned32(tlv.content) catch {};
        _ = ber.parseOid(tlv.content) catch {};
        if (tlv.tag & 0x20 != 0 and depth < 6) berWalk(tlv.content, depth + 1);
    }
}

fn fuzzWireSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [1024]u8 = undefined;
    var src: testkit.fuzz.ScriptSource = .init(script[0..smith.slice(&script)]);
    try fuzzWire(testkit.fuzz.ScriptSource, &src, testing.allocator);
}

test "fuzz: the SNMP decoders never panic on damaged messages" {
    try testing.fuzz({}, fuzzWireSmith, .{});
}

test "fuzz driver: SNMP_FUZZ (wire)" {
    try fuzz_driver.run(fuzzWire, .{ .prefix = "SNMP_FUZZ", .name = "snmp-wire" });
}

test "fuzz harness: wire, 500 seeds, reaches every outcome" {
    try WireMark.reach(fuzzWire, "snmp-wire", 500);
}

// ── snmp-auth-priv ──────────────────────────────────────────────────────────

const AuthMark = Marker(enum {
    verified,
    flip_refused,
    wrong_key_refused,
    wrong_protocol_refused,
    short_key_refused,
    round_trip,
    wrong_key_differs,
    wrong_salt_differs,
    bad_salt_refused,
    scoped_pdu_refused,
});

pub fn fuzzAuthPriv(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    const proto = all_auth[src.index(all_auth.len)];
    var key: [usm.max_key_len]u8 = undefined;
    src.bytes(&key);
    const klen = proto.keyLen();
    var engine: [16]u8 = undefined;
    src.bytes(&engine);
    var strings: [32]u8 = undefined;
    src.bytes(&strings);

    // A signed authNoPriv message: USM parameters with a zero-filled auth field.
    var zeros = [_]u8{0} ** usm.max_digest_len;
    var usm_buf: [160]u8 = undefined;
    const usm_bytes = try usm.encode(&usm_buf, .{
        .engine_id = engine[0 .. 5 + src.index(12)],
        .engine_boots = @intCast(src.index(1000)),
        .engine_time = @intCast(src.index(100000)),
        .user_name = strings[0..src.index(17)],
        .auth_params = zeros[0..proto.digestLen()],
        .priv_params = &.{},
    });
    var vb = [_]message.VarBind{.{ .name = try Oid.parse("1.3.6.1.2.1.1.5.0"), .value = .{ .octet_string = strings[16..][0..src.index(16)] } }};
    var msg_buf: [800]u8 = undefined;
    const encoded = try v3.encode(&msg_buf, .{
        .msg_id = @intCast(src.index(1 << 20)),
        .flags = .{ .auth = true },
        .security_parameters = usm_bytes,
        .context_engine_id = engine[0..8],
        .pdu = .{ .type = .response, .request_id = @intCast(src.index(1 << 20)), .varbinds = &vb },
    });
    // The encoder fills the buffer from the back: `encoded` is its tail.
    const msg = msg_buf[@intFromPtr(encoded.ptr) - @intFromPtr(&msg_buf) ..][0..encoded.len];
    {
        const m = try v3.decode(msg);
        const params = try usm.parse(m.security_parameters);
        const off = usm.authOffsetFor(proto, msg, params) orelse return error.NoAuthOffset;
        try usm.sign(proto, key[0..klen], msg, off);
    }
    {
        const m = try v3.decode(msg);
        const params = try usm.parse(m.security_parameters);
        try usm.verify(proto, key[0..klen], msg, params);
        AuthMark.mark(.verified);
    }
    // A flipped octet anywhere: refused at the envelope, the parameters or the MAC.
    {
        var bad: [800]u8 = undefined;
        @memcpy(bad[0..msg.len], msg);
        flipBit(src, bad[0..msg.len]);
        const refused = blk: {
            const m = v3.decode(bad[0..msg.len]) catch break :blk true;
            const params = usm.parse(m.security_parameters) catch break :blk true;
            usm.verify(proto, key[0..klen], bad[0..msg.len], params) catch break :blk true;
            break :blk false;
        };
        if (!refused) return error.FlippedMessageVerified;
        AuthMark.mark(.flip_refused);
    }
    // A different key, a different protocol, a short key.
    {
        const m = try v3.decode(msg);
        const params = try usm.parse(m.security_parameters);
        var other = key;
        flipBit(src, other[0..klen]);
        if (usm.verify(proto, other[0..klen], msg, params)) |_| return error.WrongKeyVerified else |_| AuthMark.mark(.wrong_key_refused);
        const p2 = all_auth[src.index(all_auth.len)];
        if (p2 != proto) {
            if (usm.verify(p2, key[0..p2.keyLen()], msg, params)) |_| return error.WrongProtocolVerified else |_| AuthMark.mark(.wrong_protocol_refused);
        }
        if (usm.verify(proto, key[0..src.index(klen)], msg, params)) |_| return error.ShortKeyVerified else |_| AuthMark.mark(.short_key_refused);
    }

    // Privacy.
    const pp = all_priv[src.index(all_priv.len)];
    const plen = pp.keyLen();
    var plain: [120]u8 = undefined;
    const pl = 1 + src.index(plain.len);
    src.bytes(plain[0..pl]);
    var salts = priv.SaltSource.counter(src.value(u64));
    const boots = src.index(1000);
    const time = src.index(100000);
    var ct_buf: [160]u8 = undefined;
    const enc = try priv.encrypt(pp, key[0..plen], @intCast(boots), @intCast(time), &salts, plain[0..pl], &ct_buf);
    var out: [160]u8 = undefined;
    const back = try priv.decrypt(pp, key[0..plen], @intCast(boots), @intCast(time), &enc.salt, enc.ciphertext, &out);
    if (back.len < pl or !std.mem.eql(u8, back[0..pl], plain[0..pl])) return error.PrivacyRoundTripFailed;
    AuthMark.mark(.round_trip);
    if (pl >= 8) {
        var k2 = key;
        // DES ignores the low (parity) bit of every key octet: flip another one.
        if (pp == .des_cbc) {
            k2[src.index(plen)] ^= @as(u8, 1) << @intCast(src.valueRangeAtMost(u8, 1, 7));
        } else flipBit(src, k2[0..plen]);
        const wrong = priv.decrypt(pp, k2[0..plen], @intCast(boots), @intCast(time), &enc.salt, enc.ciphertext, &out) catch &[_]u8{};
        if (wrong.len >= pl and std.mem.eql(u8, wrong[0..pl], plain[0..pl])) return error.WrongKeyDecrypted;
        AuthMark.mark(.wrong_key_differs);
        var salt2 = enc.salt;
        flipBit(src, &salt2);
        const wrong2 = priv.decrypt(pp, key[0..plen], @intCast(boots), @intCast(time), &salt2, enc.ciphertext, &out) catch &[_]u8{};
        if (wrong2.len >= pl and std.mem.eql(u8, wrong2[0..pl], plain[0..pl])) return error.WrongSaltDecrypted;
        AuthMark.mark(.wrong_salt_differs);
    }
    if (priv.decrypt(pp, key[0..plen], @intCast(boots), @intCast(time), enc.salt[0..src.index(8)], enc.ciphertext, &out)) |_| return error.ShortSaltAccepted else |_| AuthMark.mark(.bad_salt_refused);
    // The decrypted garbage of a wrong key is not a ScopedPDU.
    var garbage: [160]u8 = undefined;
    src.bytes(&garbage);
    if (priv.decryptScopedPdu(pp, key[0..plen], @intCast(boots), @intCast(time), &enc.salt, garbage[0 .. 8 * (1 + src.index(18))], &out)) |_| {} else |_| AuthMark.mark(.scoped_pdu_refused);
}

fn fuzzAuthPrivSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [1024]u8 = undefined;
    var src: testkit.fuzz.ScriptSource = .init(script[0..smith.slice(&script)]);
    try fuzzAuthPriv(testkit.fuzz.ScriptSource, &src, testing.allocator);
}

test "fuzz: USM authentication and privacy as an oracle" {
    try testing.fuzz({}, fuzzAuthPrivSmith, .{});
}

test "fuzz driver: SNMP_FUZZ (auth + priv)" {
    try fuzz_driver.run(fuzzAuthPriv, .{ .prefix = "SNMP_FUZZ", .name = "snmp-auth-priv" });
}

test "fuzz harness: auth + priv, 300 seeds, reaches every outcome" {
    try AuthMark.reach(fuzzAuthPriv, "snmp-auth-priv", 300);
}

// ── snmp-v3-reply ───────────────────────────────────────────────────────────

const ReplyMark = Marker(enum {
    genuine,
    discovery_tampered,
    request_tampered_refused,
    request_tampered_unauthenticated_accepted,
    authenticated,
    auth_priv,
});

const expected_name = "zig-libs";

fn Tamper(comptime S: type) type {
    return struct {
        agent: *v3client.FakeAgent,
        src: *S,
        at: usize,
        calls: usize = 0,
        changed: bool = false,

        const Self = @This();

        fn transport(self: *Self) client_mod.Transport {
            return .{ .ctx = self, .exchangeFn = exchange };
        }

        fn exchange(ctx: *anyopaque, req: []const u8, reply_buf: []u8) client_mod.TransportError!usize {
            const self: *Self = @ptrCast(@alignCast(ctx));
            const t = self.agent.transport();
            const n = try t.exchangeFn(t.ctx, req, reply_buf);
            const call = self.calls;
            self.calls += 1;
            if (call != self.at) return n;
            var tmp: [client_mod.max_message_len]u8 = undefined;
            const m = if (S == fuzz_driver.Rng) damage(self.src, &tmp, reply_buf[0..n]) else self.src.slice(&tmp);
            self.changed = m != n or !std.mem.eql(u8, tmp[0..m], reply_buf[0..n]);
            @memcpy(reply_buf[0..m], tmp[0..m]);
            return m;
        }
    };
}

pub fn fuzzV3Reply(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    const level: v3client.SecurityLevel = @enumFromInt(src.index(3));
    const auth = all_auth[src.index(all_auth.len)];
    const pp = all_priv[src.index(all_priv.len)];
    const user: v3client.User = .{
        .name = "fuzz-user",
        .level = level,
        .auth_protocol = auth,
        .auth_password = "fuzz auth password",
        .priv_protocol = pp,
        .priv_password = "fuzz priv password",
    };
    const vals = [_]message.VarBind{.{ .name = try Oid.parse("1.3.6.1.2.1.1.5.0"), .value = .{ .octet_string = expected_name } }};
    var agent: v3client.FakeAgent = .{ .user = user, .values = &vals };
    // Which exchange is tampered with: the discovery probe (0), the request (1), none.
    var at: usize = 99;
    if (S == fuzz_driver.Rng) {
        at = switch (src.valueRangeAtMost(u8, 0, 9)) {
            0, 1 => 99,
            2, 3 => 0,
            else => 1,
        };
    } else at = src.index(2);
    var t: Tamper(S) = .{ .agent = &agent, .src = src, .at = at };
    var c = v3client.V3Client.init(t.transport(), user, .{ .salt_seed = .{ .fixed_for_test = 0x1234_5678 } });
    var ok = true;
    var got: ?[]const u8 = null;
    c.discover() catch {
        ok = false;
    };
    if (ok) {
        if (c.get(&.{try Oid.parse("1.3.6.1.2.1.1.5.0")})) |resp| {
            var it = resp.varbinds.iterator();
            if (it.next() catch null) |vb| switch (vb.value) {
                .octet_string => |s| got = s,
                else => {},
            };
        } else |_| {}
    }
    const genuine_value = got != null and std.mem.eql(u8, got.?, expected_name);
    if (!t.changed) {
        if (!genuine_value) {
            std.debug.print("snmp-v3-reply: an untampered exchange did not return the agent's value ({t})\n", .{level});
            return error.GenuineExchangeFailed;
        }
        ReplyMark.mark(.genuine);
        if (level.hasAuth()) ReplyMark.mark(.authenticated);
        if (level.hasPriv()) ReplyMark.mark(.auth_priv);
        return;
    }
    if (at == 0) {
        // The discovery Report is unauthenticated by construction; what the
        // client builds on it may fail but must never hand back another value.
        if (got != null and !genuine_value) return error.DiscoveryTamperChangedTheData;
        ReplyMark.mark(.discovery_tampered);
        return;
    }
    if (level.hasAuth()) {
        if (got != null) {
            std.debug.print("snmp-v3-reply: a damaged authenticated reply ({t}) was returned as data\n", .{level});
            return error.DamagedAuthenticatedReplyAccepted;
        }
        ReplyMark.mark(.request_tampered_refused);
    } else if (got != null) ReplyMark.mark(.request_tampered_unauthenticated_accepted) else ReplyMark.mark(.request_tampered_refused);
}

fn fuzzV3ReplySmith(_: void, smith: *std.testing.Smith) !void {
    var script: [1024]u8 = undefined;
    var src: testkit.fuzz.ScriptSource = .init(script[0..smith.slice(&script)]);
    try fuzzV3Reply(testkit.fuzz.ScriptSource, &src, testing.allocator);
}

test "fuzz: a damaged v3 reply is never data over an authenticated level" {
    try testing.fuzz({}, fuzzV3ReplySmith, .{});
}

test "fuzz driver: SNMP_FUZZ (v3 reply)" {
    try fuzz_driver.run(fuzzV3Reply, .{ .prefix = "SNMP_FUZZ", .name = "snmp-v3-reply", .scale = 64 });
}

test "fuzz harness: v3 reply, 500 seeds, reaches every outcome" {
    try ReplyMark.reach(fuzzV3Reply, "snmp-v3-reply", 500);
}
