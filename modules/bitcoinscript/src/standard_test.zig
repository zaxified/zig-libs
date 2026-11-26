// SPDX-License-Identifier: MIT
//! Tests for `standard.zig` (Core `Solver` / `IsStandard` /
//! `ExtractDestination`): one positive per template, then the boundary and
//! near-miss rows of each matcher.

const std = @import("std");
const ripemd160 = @import("ripemd160");
const standard = @import("standard.zig");

const t = std.testing;

fn rep(comptime b: u8, comptime n: usize) [n]u8 {
    return @splat(b);
}
const S = standard;

const h20 = rep(0x11, 20);
const h32 = rep(0x22, 32);
const key33 = [_]u8{0x02} ++ rep(0x33, 32);
const key33b = [_]u8{0x03} ++ rep(0x44, 32);
const key65 = [_]u8{0x04} ++ rep(0x55, 64);
const key65h = [_]u8{0x07} ++ rep(0x66, 64);

test "solve: pubkeyhash, scripthash, witness programs, anchor" {
    const p2pkh = [_]u8{ 0x76, 0xa9, 0x14 } ++ h20 ++ [_]u8{ 0x88, 0xac };
    try t.expectEqualSlices(u8, &h20, S.solve(&p2pkh).pubkeyhash);
    const p2sh = [_]u8{ 0xa9, 0x14 } ++ h20 ++ [_]u8{0x87};
    try t.expectEqualSlices(u8, &h20, S.solve(&p2sh).scripthash);
    const wpkh = [_]u8{ 0x00, 0x14 } ++ h20;
    try t.expectEqualSlices(u8, &h20, S.solve(&wpkh).witness_v0_keyhash);
    const wsh = [_]u8{ 0x00, 0x20 } ++ h32;
    try t.expectEqualSlices(u8, &h32, S.solve(&wsh).witness_v0_scripthash);
    const tr = [_]u8{ 0x51, 0x20 } ++ h32;
    try t.expectEqualSlices(u8, &h32, S.solve(&tr).witness_v1_taproot);
    try t.expect(S.solve(&[_]u8{ 0x51, 0x02, 0x4e, 0x73 }) == .anchor);
    // v1 with another 2-byte program is just unknown
    const unk = S.solve(&[_]u8{ 0x51, 0x02, 0x4e, 0x74 }).witness_unknown;
    try t.expectEqual(@as(u8, 1), unk.version);
    try t.expectEqualSlices(u8, &.{ 0x4e, 0x74 }, unk.program);
    // v16, 40-byte program (the longest)
    const v16 = [_]u8{ 0x60, 40 } ++ rep(0x77, 40);
    try t.expectEqual(@as(u8, 16), S.solve(&v16).witness_unknown.version);
    // v0 of another length is nonstandard, v1 of 33 bytes unknown
    try t.expect(S.solve(&([_]u8{ 0x00, 0x15 } ++ rep(0, 21))) == .nonstandard);
    try t.expect(S.solve(&([_]u8{ 0x51, 0x21 } ++ rep(0, 33))) == .witness_unknown);
    // 1-byte program is no witness program
    try t.expect(S.solve(&[_]u8{ 0x51, 0x01, 0x00 }) == .nonstandard);
}

test "solve: near misses of the fixed templates" {
    var p2pkh = [_]u8{ 0x76, 0xa9, 0x14 } ++ h20 ++ [_]u8{ 0x88, 0xac };
    p2pkh[24] = 0xad;
    try t.expect(S.solve(&p2pkh) == .nonstandard);
    p2pkh[24] = 0xac;
    p2pkh[23] = 0x87;
    try t.expect(S.solve(&p2pkh) == .nonstandard);
    var p2sh = [_]u8{ 0xa9, 0x14 } ++ h20 ++ [_]u8{0x87};
    p2sh[22] = 0x88;
    try t.expect(S.solve(&p2sh) == .nonstandard);
    // trailing byte after a P2SH script
    try t.expect(S.solve(&([_]u8{ 0xa9, 0x14 } ++ h20 ++ [_]u8{ 0x87, 0x00 })) == .nonstandard);
    try t.expect(S.solve(&.{}) == .nonstandard);
}

test "solve: bare pubkey (compressed, uncompressed, hybrid; header/length must agree)" {
    const c = [_]u8{33} ++ key33 ++ [_]u8{0xac};
    try t.expectEqualSlices(u8, &key33, S.solve(&c).pubkey);
    const u = [_]u8{65} ++ key65 ++ [_]u8{0xac};
    try t.expectEqualSlices(u8, &key65, S.solve(&u).pubkey);
    const h = [_]u8{65} ++ key65h ++ [_]u8{0xac};
    try t.expectEqualSlices(u8, &key65h, S.solve(&h).pubkey);
    // 33 bytes with a 65-byte header, 65 bytes with a compressed header
    var bad = c;
    bad[1] = 0x04;
    try t.expect(S.solve(&bad) == .nonstandard);
    var bad2 = u;
    bad2[1] = 0x02;
    try t.expect(S.solve(&bad2) == .nonstandard);
    var bad3 = c;
    bad3[1] = 0x05;
    try t.expect(S.solve(&bad3) == .nonstandard);
    // wrong final opcode
    var bad4 = c;
    bad4[34] = 0xad;
    try t.expect(S.solve(&bad4) == .nonstandard);
}

test "solve: nulldata" {
    try t.expect(S.solve(&[_]u8{0x6a}) == .nulldata);
    try t.expect(S.solve(&[_]u8{ 0x6a, 0x04, 1, 2, 3, 4 }) == .nulldata);
    try t.expect(S.solve(&[_]u8{ 0x6a, 0x51, 0x60, 0x00 }) == .nulldata); // OP_N pushes are push-only
    try t.expect(S.solve(&[_]u8{ 0x6a, 0x61 }) == .nonstandard); // OP_NOP is not a push
    try t.expect(S.solve(&[_]u8{ 0x6a, 0x04, 1, 2 }) == .nonstandard); // truncated push
}

fn ms(comptime m: u8, comptime keys: []const []const u8) []const u8 {
    comptime {
        var s: []const u8 = &[_]u8{0x50 + m};
        for (keys) |k| s = s ++ [_]u8{@intCast(k.len)} ++ k;
        s = s ++ [_]u8{ 0x50 + @as(u8, keys.len), 0xae };
        return s;
    }
}

test "solve: bare multisig" {
    const s = comptime ms(2, &.{ &key33, &key65, &key33b });
    const got = S.solve(s).multisig;
    try t.expectEqual(@as(u8, 2), got.required);
    try t.expectEqual(@as(u8, 3), got.n);
    try t.expectEqualSlices(u8, &key33, got.keys()[0]);
    try t.expectEqualSlices(u8, &key65, got.keys()[1]);
    try t.expectEqualSlices(u8, &key33b, got.keys()[2]);

    // m > n, n mismatch, extra key, missing OP_CHECKMULTISIG tail, 0-of-n
    try t.expect(S.solve(comptime ms(3, &.{ &key33, &key33b })) == .nonstandard);
    var wrong_n = comptime ms(1, &.{ &key33, &key33b }).*;
    wrong_n[wrong_n.len - 2] = 0x53;
    try t.expect(S.solve(&wrong_n) == .nonstandard);
    try t.expect(S.solve(comptime ms(0, &.{&key33})) == .nonstandard);
    const one = comptime ms(1, &.{&key33});
    try t.expect(S.solve(one[0 .. one.len - 1]) == .nonstandard);
    try t.expect(S.solve(one) == .multisig);
    // a trailing byte after OP_CHECKMULTISIG makes the last-opcode test fail
    try t.expect(S.solve(&(one.*[0..one.len].* ++ [_]u8{0xae})) == .nonstandard);
    // a key of invalid size ends the key list early
    const badkey = comptime [_]u8{0x02} ++ rep(0x33, 31);
    try t.expect(S.solve(comptime ms(1, &.{ &key33, &badkey })) == .nonstandard);
    // 16 keys fit; 17 do not
    const k16keys: [16][]const u8 = @splat(&key33);
    const k16 = comptime ms(16, &k16keys);
    try t.expectEqual(@as(u8, 16), S.solve(k16).multisig.n);
    var k17: [2 + 17 * 34 + 2 + 0]u8 = undefined;
    k17[0] = 0x51;
    for (0..17) |i| {
        k17[1 + i * 34] = 33;
        @memcpy(k17[2 + i * 34 ..][0..33], &key33);
    }
    k17[1 + 17 * 34] = 0x60;
    k17[2 + 17 * 34] = 0xae;
    try t.expect(S.solve(k17[0 .. 3 + 17 * 34]) == .nonstandard);
}

test "isStandard: multisig up to 3 keys, datacarrier bound" {
    try t.expectEqual(S.TxoutType.multisig, S.isStandard(comptime ms(2, &.{ &key33, &key33b, &key65 }), .{}).?);
    try t.expect(S.isStandard(comptime ms(1, &.{ &key33, &key33b, &key65, &key65h }), .{}) == null);
    try t.expect(S.isStandard(&[_]u8{0x51}, .{}) == null);
    try t.expectEqual(S.TxoutType.witness_v1_taproot, S.isStandard(&([_]u8{ 0x51, 0x20 } ++ h32), .{}).?);
    const data = [_]u8{ 0x6a, 0x04, 1, 2, 3, 4 };
    try t.expectEqual(S.TxoutType.nulldata, S.isStandard(&data, .{}).?);
    try t.expectEqual(S.TxoutType.nulldata, S.isStandard(&data, .{ .max_datacarrier_bytes = 6 }).?);
    try t.expect(S.isStandard(&data, .{ .max_datacarrier_bytes = 5 }) == null);
    try t.expect(S.isStandard(&data, .{ .max_datacarrier_bytes = null }) == null);
    // unknown witness versions are standard (Core relays them)
    try t.expectEqual(S.TxoutType.witness_unknown, S.isStandard(&[_]u8{ 0x52, 0x02, 0xaa, 0xbb }, .{}).?);
}

test "extractDestination" {
    const p2pkh = [_]u8{ 0x76, 0xa9, 0x14 } ++ h20 ++ [_]u8{ 0x88, 0xac };
    try t.expectEqualSlices(u8, &h20, &S.extractDestination(&p2pkh).?.pubkeyhash);
    const c = [_]u8{33} ++ key33 ++ [_]u8{0xac};
    var want: [20]u8 = undefined;
    ripemd160.hash160(&key33, &want);
    try t.expectEqualSlices(u8, &want, &S.extractDestination(&c).?.pubkeyhash);
    try t.expectEqualSlices(u8, &h20, &S.extractDestination(&([_]u8{ 0xa9, 0x14 } ++ h20 ++ [_]u8{0x87})).?.scripthash);
    try t.expectEqualSlices(u8, &h20, &S.extractDestination(&([_]u8{ 0x00, 0x14 } ++ h20)).?.witness_v0_keyhash);
    try t.expectEqualSlices(u8, &h32, &S.extractDestination(&([_]u8{ 0x00, 0x20 } ++ h32)).?.witness_v0_scripthash);
    try t.expectEqualSlices(u8, &h32, &S.extractDestination(&([_]u8{ 0x51, 0x20 } ++ h32)).?.witness_v1_taproot);
    try t.expect(S.extractDestination(&[_]u8{ 0x51, 0x02, 0x4e, 0x73 }).? == .pay_to_anchor);
    const w = S.extractDestination(&[_]u8{ 0x52, 0x02, 0xaa, 0xbb }).?.witness_unknown;
    try t.expectEqual(@as(u8, 2), w.version);
    try t.expectEqualSlices(u8, &.{ 0xaa, 0xbb }, w.program);
    try t.expect(S.extractDestination(comptime ms(1, &.{&key33})) == null);
    try t.expect(S.extractDestination(&[_]u8{0x6a}) == null);
    try t.expect(S.extractDestination(&[_]u8{0x51}) == null);
}

test "mutation 2026-11-25: solve rejects every one-byte deviation of the fixed templates and the 17th-key shapes" {
    // P2SH: each of the three fixed bytes, and a longer script.
    const p2sh = [_]u8{ 0xa9, 0x14 } ++ h20 ++ [_]u8{0x87};
    var a0 = p2sh;
    a0[0] = 0xaa;
    var a1 = p2sh;
    a1[1] = 0x15;
    var a22 = p2sh;
    a22[22] = 0x88;
    const alonger = p2sh ++ [_]u8{0x00};
    for ([_][]const u8{ &a0, &a1, &a22, &alonger }) |s| try t.expect(S.solve(s) == .nonstandard);
    // Witness programs: the version and the length gate each template.
    try t.expect(S.solve(&([_]u8{ 0x51, 0x14 } ++ h20)) == .witness_unknown); // v1, 20 bytes
    try t.expect(S.solve(&([_]u8{ 0x52, 0x20 } ++ h32)) == .witness_unknown); // v2, 32 bytes
    try t.expect(S.solve(&([_]u8{ 0x00, 0x21 } ++ rep(0, 33))) == .nonstandard); // v0, 33 bytes
    try t.expect(S.solve(&[_]u8{ 0x52, 0x02, 0x4e, 0x73 }) == .witness_unknown); // v2 with the anchor program
    try t.expect(S.solve(&[_]u8{ 0x51, 0x02, 0x00, 0x73 }) == .witness_unknown); // v1, other first byte
    // Bare pubkey: header byte, trailing byte, longer script.
    const pk65 = [_]u8{65} ++ key65 ++ [_]u8{0xac};
    var p65h = pk65;
    p65h[0] = 0x42;
    var p65e = pk65;
    p65e[66] = 0xad;
    try t.expect(S.solve(&pk65) == .pubkey);
    try t.expect(S.solve(&p65h) == .nonstandard);
    try t.expect(S.solve(&p65e) == .nonstandard);
    try t.expect(S.solve(&(pk65 ++ [_]u8{0x00})) == .nonstandard);
    const pk33 = [_]u8{33} ++ key33 ++ [_]u8{0xac};
    var p33h = pk33;
    p33h[0] = 0x20;
    try t.expect(S.solve(&pk33) == .pubkey);
    try t.expect(S.solve(&p33h) == .nonstandard);
    try t.expect(S.solve(&(pk33 ++ [_]u8{0x00})) == .nonstandard);
    // P2PKH: each fixed byte and a longer script.
    const p2pkh = [_]u8{ 0x76, 0xa9, 0x14 } ++ h20 ++ [_]u8{ 0x88, 0xac };
    try t.expect(S.solve(&p2pkh) == .pubkeyhash);
    var k0 = p2pkh;
    k0[0] = 0x77;
    var k1 = p2pkh;
    k1[1] = 0xaa;
    var k2 = p2pkh;
    k2[2] = 0x15;
    for ([_][]const u8{ &k0, &k1, &k2, &(p2pkh ++ [_]u8{0x00}) }) |s| try t.expect(S.solve(s) == .nonstandard);
    // Bare multisig: a 66-byte "uncompressed" key is no key; the closing opcode must be OP_CHECKMULTISIG.
    const key66 = key65 ++ [_]u8{0x00};
    const bad_key = [_]u8{ 0x51, 66 } ++ key66 ++ [_]u8{ 0x51, 0xae };
    try t.expect(S.solve(&bad_key) == .nonstandard);
    const verify_form = [_]u8{ 0x51, 33 } ++ key33 ++ [_]u8{ 0x51, 0xaf };
    try t.expect(S.solve(&verify_form) == .nonstandard);
    const good = [_]u8{ 0x51, 33 } ++ key33 ++ [_]u8{ 0x51, 0xae };
    try t.expect(S.solve(&good) == .multisig);
}
