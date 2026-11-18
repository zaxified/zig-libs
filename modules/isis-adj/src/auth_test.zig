// SPDX-License-Identifier: MIT

//! IIH authentication (`Config.auth_keys`): two adjacencies sign and verify
//! each other's hellos through the real encode -> `rxHelloBytes` path; a hello
//! with no, a wrong or a malformed Authentication TLV is refused before it
//! touches the FSM. The no-key path is pinned byte-for-byte by the golden
//! hellos in `root.zig`.

const std = @import("std");
const isis = @import("isis");
const fsm = @import("fsm.zig");
const testing = std.testing;

const Adjacency = fsm.Adjacency;
const Config = fsm.Config;
const State = fsm.State;
const Key = isis.auth.Key;

const sys_a: fsm.SystemId = .{ 0, 0, 0, 0, 0, 0xA };
const sys_b: fsm.SystemId = .{ 0, 0, 0, 0, 0, 0xB };

const key_sha256: Key = .{ .algorithm = .hmac_sha256, .id = 5, .secret = "link-secret" };

fn cfgWith(sid: fsm.SystemId, ext: u32, keys: []const Key) Config {
    return .{ .system_id = sid, .extended_local_circuit_id = ext, .auth_keys = keys };
}

/// Drive A and B to Up by exchanging serialized hellos; returns the rounds.
fn handshake(a: *Adjacency, b: *Adjacency) !void {
    var abuf: [256]u8 = undefined;
    var bbuf: [256]u8 = undefined;
    var wa = try fsm.buildHello(&abuf, a.start(0).send_hello.?);
    var wb = try fsm.buildHello(&bbuf, b.start(0).send_hello.?);
    var t: fsm.Time = 1;
    var round: usize = 0;
    while (round < 6 and !(a.currentState() == .up and b.currentState() == .up)) : (round += 1) {
        const ea = try a.rxHelloBytes(wb, t);
        const eb = try b.rxHelloBytes(wa, t);
        try testing.expectEqual(@as(?fsm.RejectReason, null), ea.rejected);
        try testing.expectEqual(@as(?fsm.RejectReason, null), eb.rejected);
        wa = try fsm.buildHello(&abuf, a.helloFields());
        wb = try fsm.buildHello(&bbuf, b.helloFields());
        t += 1;
    }
    try testing.expectEqual(State.up, a.currentState());
    try testing.expectEqual(State.up, b.currentState());
}

test "auth: both sides keyed reach Up, for every algorithm" {
    const algs = [_]isis.auth.Algorithm{ .cleartext, .hmac_md5, .hmac_sha1, .hmac_sha224, .hmac_sha256, .hmac_sha384, .hmac_sha512 };
    for (algs) |alg| {
        const keys = [_]Key{.{ .algorithm = alg, .id = 9, .secret = "shared" }};
        var a = Adjacency.init(cfgWith(sys_a, 0xA1, &keys));
        var b = Adjacency.init(cfgWith(sys_b, 0xB1, &keys));
        try handshake(&a, &b);
    }
}

test "auth: the hello is signed with keys[0] and #10 is its first TLV" {
    const keys = [_]Key{ key_sha256, .{ .algorithm = .hmac_md5, .secret = "old" } };
    var a = Adjacency.init(cfgWith(sys_a, 0xA1, &keys));
    const hf = a.start(0).send_hello.?;
    try testing.expectEqual(isis.auth.Algorithm.hmac_sha256, hf.auth.?.algorithm);
    var buf: [256]u8 = undefined;
    const w = try fsm.buildHello(&buf, hf);
    try testing.expectEqual(isis.auth.tlv_code, w[isis.pdu.p2p_iih_fixed_len]);
    try testing.expectEqual(@as(usize, 0), try isis.auth.verify(w, &.{key_sha256}));
    // Unkeyed: no #10 at all.
    var u = Adjacency.init(cfgWith(sys_a, 0xA1, &.{}));
    const uf = u.start(0).send_hello.?;
    try testing.expect(uf.auth == null);
    const uw = try fsm.buildHello(&buf, uf);
    try testing.expectEqual(@as(?isis.auth.Located, null), try isis.auth.find(uw));
}

test "auth: a keyed receiver refuses an unauthenticated hello, mutating nothing" {
    var a = Adjacency.init(cfgWith(sys_a, 0xA1, &.{}));
    var b = Adjacency.init(cfgWith(sys_b, 0xB1, &.{key_sha256}));
    _ = b.start(0);
    var buf: [256]u8 = undefined;
    const w = try fsm.buildHello(&buf, a.start(0).send_hello.?);
    const before = b;
    const e = try b.rxHelloBytes(w, 1);
    try testing.expectEqual(@as(?fsm.RejectReason, .auth_missing), e.rejected);
    try testing.expect(e.transition == null);
    try testing.expectEqual(before.state, b.state);
    try testing.expectEqual(before.neighbor_system_id, b.neighbor_system_id);
    try testing.expectEqual(before.hold_deadline, b.hold_deadline);
}

test "auth: an unkeyed receiver accepts an authenticated hello (no key = no check)" {
    var a = Adjacency.init(cfgWith(sys_a, 0xA1, &.{key_sha256}));
    var b = Adjacency.init(cfgWith(sys_b, 0xB1, &.{}));
    _ = b.start(0);
    var buf: [256]u8 = undefined;
    const w = try fsm.buildHello(&buf, a.start(0).send_hello.?);
    const e = try b.rxHelloBytes(w, 1);
    try testing.expectEqual(@as(?fsm.RejectReason, null), e.rejected);
    try testing.expectEqual(State.initializing, b.currentState());
}

fn expectRefused(sender_keys: []const Key, receiver_keys: []const Key, want: fsm.RejectReason) !void {
    var a = Adjacency.init(cfgWith(sys_a, 0xA1, sender_keys));
    var b = Adjacency.init(cfgWith(sys_b, 0xB1, receiver_keys));
    _ = b.start(0);
    var buf: [256]u8 = undefined;
    const w = try fsm.buildHello(&buf, a.start(0).send_hello.?);
    const e = try b.rxHelloBytes(w, 1);
    try testing.expectEqual(@as(?fsm.RejectReason, want), e.rejected);
    try testing.expectEqual(State.down, b.currentState());
    try testing.expect(b.neighbor_system_id == null);
}

test "auth: wrong secret, Key ID, algorithm or type are refused" {
    var wrong_secret = key_sha256;
    wrong_secret.secret = "link-secreT";
    try expectRefused(&.{key_sha256}, &.{wrong_secret}, .auth_failed);
    var wrong_id = key_sha256;
    wrong_id.id = 6;
    try expectRefused(&.{key_sha256}, &.{wrong_id}, .auth_failed);
    var wrong_alg = key_sha256;
    wrong_alg.algorithm = .hmac_sha384;
    try expectRefused(&.{key_sha256}, &.{wrong_alg}, .auth_failed);
    try expectRefused(&.{key_sha256}, &.{.{ .algorithm = .hmac_md5, .secret = "link-secret" }}, .auth_failed);
    try expectRefused(&.{.{ .algorithm = .cleartext, .secret = "pw" }}, &.{.{ .algorithm = .cleartext, .secret = "pW" }}, .auth_failed);
    // The strict RFC 5310 key preparation is a different key for a long secret.
    const long = "0123456789abcdef0123456789abcdef0123456789"; // 42 > L = 32
    var plain: Key = .{ .algorithm = .hmac_sha256, .id = 1, .secret = long };
    var strict = plain;
    strict.strict_rfc5310 = true;
    try expectRefused(&.{plain}, &.{strict}, .auth_failed);
    plain.strict_rfc5310 = true;
    var a = Adjacency.init(cfgWith(sys_a, 0xA1, &.{plain}));
    var b = Adjacency.init(cfgWith(sys_b, 0xB1, &.{strict}));
    try handshake(&a, &b);
}

test "auth: key rollover, each side signs with its first key and accepts both" {
    const old: Key = .{ .algorithm = .hmac_sha1, .id = 1, .secret = "old" };
    const new: Key = .{ .algorithm = .hmac_sha1, .id = 2, .secret = "new" };
    var a = Adjacency.init(cfgWith(sys_a, 0xA1, &.{ new, old }));
    var b = Adjacency.init(cfgWith(sys_b, 0xB1, &.{ old, new }));
    try handshake(&a, &b);
}

test "auth: one flipped octet anywhere in a signed hello is refused" {
    var a = Adjacency.init(cfgWith(sys_a, 0xA1, &.{key_sha256}));
    var buf: [256]u8 = undefined;
    const w = try fsm.buildHello(&buf, a.start(0).send_hello.?);
    var copy: [256]u8 = undefined;
    for (0..w.len) |i| {
        @memcpy(copy[0..w.len], w);
        copy[i] ^= 0x01;
        var b = Adjacency.init(cfgWith(sys_b, 0xB1, &.{key_sha256}));
        _ = b.start(0);
        const e = b.rxHelloBytes(copy[0..w.len], 1) catch continue; // a decode refusal is a refusal too
        if (e.rejected == null) {
            std.debug.print("flip at {d} accepted\n", .{i});
            return error.TestUnexpectedResult;
        }
    }
}

test "auth: a malformed or unknown Authentication TLV is refused as auth_failed" {
    var b = Adjacency.init(cfgWith(sys_b, 0xB1, &.{key_sha256}));
    _ = b.start(0);
    var buf: [128]u8 = undefined;
    // HMAC-MD5 type with a 15-octet value: MalformedAuth.
    {
        var pb = try isis.pdu.P2pHelloBuilder.init(&buf, .{ .source_id = sys_a, .holding_time = 30 });
        var v: [16]u8 = @splat(0);
        v[0] = isis.auth.auth_type.hmac_md5;
        try pb.tlvs.addTlv(isis.auth.tlv_code, &v);
        const e = try b.rxHelloBytes(pb.finish(), 1);
        try testing.expectEqual(@as(?fsm.RejectReason, .auth_failed), e.rejected);
    }
    // Private type 255.
    {
        var pb = try isis.pdu.P2pHelloBuilder.init(&buf, .{ .source_id = sys_a, .holding_time = 30 });
        try pb.tlvs.addTlv(isis.auth.tlv_code, &.{ 255, 1 });
        const e = try b.rxHelloBytes(pb.finish(), 1);
        try testing.expectEqual(@as(?fsm.RejectReason, .auth_failed), e.rejected);
    }
    // A broken TLV stream is still a decode error, as without keys.
    {
        var pb = try isis.pdu.P2pHelloBuilder.init(&buf, .{ .source_id = sys_a, .holding_time = 30 });
        try pb.tlvs.addTlv(1, &.{ 3, 0x49, 0, 1 });
        const w = pb.finish();
        buf[w.len - 5] = 40;
        try testing.expectError(error.TruncatedTlv, b.rxHelloBytes(w, 1));
    }
    try testing.expectEqual(State.down, b.currentState());
}

test "auth: an Up adjacency's hold is not refreshed by an unauthenticated copy of the neighbour's hello" {
    var a = Adjacency.init(cfgWith(sys_a, 0xA1, &.{key_sha256}));
    var b = Adjacency.init(cfgWith(sys_b, 0xB1, &.{key_sha256}));
    try handshake(&a, &b);
    const deadline = b.hold_deadline;
    // The same fields, built without a key (an on-link forger without it).
    var hf = a.helloFields();
    hf.auth = null;
    hf.holding_time = 65535;
    var buf: [256]u8 = undefined;
    const e = try b.rxHelloBytes(try fsm.buildHello(&buf, hf), 5);
    try testing.expectEqual(@as(?fsm.RejectReason, .auth_missing), e.rejected);
    try testing.expectEqual(deadline, b.hold_deadline);
    try testing.expectEqual(State.up, b.currentState());
}

test "auth: buildHello with a key needs room for the #10 TLV" {
    var a = Adjacency.init(cfgWith(sys_a, 0xA1, &.{key_sha256}));
    const hf = a.start(0).send_hello.?;
    var big: [256]u8 = undefined;
    const n = (try fsm.buildHello(&big, hf)).len;
    var small: [256]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, fsm.buildHello(small[0 .. n - 1], hf));
    _ = try fsm.buildHello(small[0..n], hf);
    // A cleartext password too long for a TLV value.
    const pw: [255]u8 = @splat('x');
    var c = Adjacency.init(cfgWith(sys_a, 0xA1, &.{.{ .algorithm = .cleartext, .secret = &pw }}));
    try testing.expectError(error.ValueTooLong, fsm.buildHello(&big, c.start(0).send_hello.?));
}
