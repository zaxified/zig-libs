// SPDX-License-Identifier: MIT

//! Authentication TLV (#10) known-answer tests and receive-side cases.
//!
//! The `kats` table is the output of `tools/auth_kat.py` (Python `hmac` /
//! `hashlib`, PDUs assembled there field by field, LSP checksum by its own
//! ISO 8473 code). Each test rebuilds the same PDU with this module's
//! builders, signs it, and must reproduce the bytes exactly; then `verify`
//! must accept it and refuse every corruption.

const std = @import("std");
const isis = @import("root.zig");
const testing = std.testing;

const auth = isis.auth;
const pdu = isis.pdu;
const tlvs = isis.tlvs;
const tlv = isis.tlv;

const Kat = struct { name: []const u8, wire: []const u8 };

/// Regenerate with `python3 -I tools/auth_kat.py`.
const kats = [_]Kat{
    .{ .name = "p2p_md5", .wire = "8314010611010003031921680000ff001e0030010a1136818182ea80a9b8b80d373a15a7ca377b0104034900018101cc" },
    .{ .name = "p2p_clear", .wire = "8314010611010003031921680000ff001e0027010a08016c65746d65696e0104034900018101cc" },
    .{ .name = "lan_sha1", .wire = "831b01060f010003011921680000ff0009003a401921680000ff010a17030007a3d01d8d2f08fc05e85ec6536379b365fdf8240a010403490001" },
    .{ .name = "csnp_sha1_k22", .wire = "8321010618010003004c1921680000ff000000000000000000ffffffffffffffff0a170300013effcfe479c6c361306fd648478ad9736a35b40a0910044c1921680000ff0000000000051234" },
    .{ .name = "csnp_sha1_k22_strict", .wire = "8321010618010003004c1921680000ff000000000000000000ffffffffffffffff0a170300016f82b2ceb2df8b30da249a0cdea9709a94ec16100910044c1921680000ff0000000000051234" },
    .{ .name = "psnp_sha224", .wire = "831101061a01000300441921680000ff000a1f03000274a05efbc3477d5b6a592912e5051ee7eb2ade73b2fbc70f63bbec080910044c1921680000ff0000000000051234" },
    .{ .name = "lsp_sha256", .wire = "831b010612010003004904b01921680000ff000000000005afdb030a230300033124a474f461cb28b9003959f61282c6ca577e46ff6612ddfc02a31f71407f6d0104034900018101cc" },
    .{ .name = "lsp_sha256_k40", .wire = "831b010612010003004904b01921680000ff000000000005ae5a030a230300032cbd4afc95589b9b813eb2b523518371d06e4ca0563c4b8383e82ece75adb5bf0104034900018101cc" },
    .{ .name = "lsp_sha256_k40_strict", .wire = "831b010612010003004904b01921680000ff000000000005e013030a2303000370b4bb5f26a85c8c68e2f1a9560f46fbb1236f26d76f4db51f28c5c66e5ef4bb0104034900018101cc" },
    .{ .name = "lsp_md5", .wire = "831b010612010003003704b01921680000ff0000000000059f87030a1136e9ae508767b85bdf0dcf72a7666fb7ea0104034900018101cc" },
    .{ .name = "lsp_sha384", .wire = "831b010612010003005904b01921680000ff000000000005bdb0030a3303beef534b8ad43755e4f8dee34991f0f2ad8a2058828d9b6e5d07592215e531369a662a56c89411d40c2aeb3a701d30e845520104034900018101cc" },
    .{ .name = "p2p_sha512_long", .wire = "8314010611010003031921680000ff001e0062010a4303ffff22796cf0022d630e83fdac7b434ef4580094fa9df5a480d8f1e3d91a3aeab952322d96f2ea98c8c80a153d4920518f29fcbec2734c31c19854582f8c5dde1db50104034900018101cc" },
    .{ .name = "p2p_sha512_long_strict", .wire = "8314010611010003031921680000ff001e0062010a4303ffff22796cf0022d630e83fdac7b434ef4580094fa9df5a480d8f1e3d91a3aeab952322d96f2ea98c8c80a153d4920518f29fcbec2734c31c19854582f8c5dde1db50104034900018101cc" },
};

const sys = [6]u8{ 0x19, 0x21, 0x68, 0x00, 0x00, 0xff };
const area = [_]u8{ 0x49, 0x00, 0x01 };

const key_short = "isis-test-key";
const key_22: [22]u8 = blk: {
    var k: [22]u8 = undefined;
    for (&k, 0..) |*b, i| b.* = @intCast(0x41 + i);
    break :blk k;
};
const key_40: [40]u8 = blk: {
    var k: [40]u8 = undefined;
    for (k[0..26], 0..) |*b, i| b.* = @intCast(0x61 + i);
    for (k[26..], 0..) |*b, i| b.* = @intCast(0x30 + i);
    break :blk k;
};
const key_long: [130]u8 = blk: {
    var k: [130]u8 = undefined;
    for (&k, 0..) |*b, i| b.* = @intCast(1 + i);
    break :blk k;
};

const entry: tlvs.LspEntry = .{
    .remaining_lifetime = 1100,
    .lsp_id = sys ++ [2]u8{ 0, 0 },
    .sequence_number = 5,
    .checksum = 0x1234,
};

const Kind = enum { p2p, lan, lsp, csnp, psnp };

fn build(buf: []u8, kind: Kind, key: auth.Key) ![]u8 {
    const n = switch (kind) {
        .p2p => blk: {
            var b = try pdu.P2pHelloBuilder.init(buf, .{ .source_id = sys, .holding_time = 30 });
            try auth.addPlaceholder(&b.tlvs, key);
            try tlvs.addAreaAddresses(&b.tlvs, &.{&area});
            try tlvs.addProtocolsSupported(&b.tlvs, &.{tlvs.nlpid_ipv4});
            break :blk b.finish().len;
        },
        .lan => blk: {
            var b = try pdu.LanHelloBuilder.init(buf, .{
                .circuit_type = .level1,
                .source_id = sys,
                .holding_time = 9,
                .lan_id = sys ++ [1]u8{1},
            });
            try auth.addPlaceholder(&b.tlvs, key);
            try tlvs.addAreaAddresses(&b.tlvs, &.{&area});
            break :blk b.finish().len;
        },
        .lsp => blk: {
            var b = try pdu.LspBuilder.init(buf, .{
                .remaining_lifetime = 1200,
                .lsp_id = sys ++ [2]u8{ 0, 0 },
                .sequence_number = 5,
                .flags = pdu.LspFlags.fromByte(0x03),
            });
            try auth.addPlaceholder(&b.tlvs, key);
            try tlvs.addAreaAddresses(&b.tlvs, &.{&area});
            try tlvs.addProtocolsSupported(&b.tlvs, &.{tlvs.nlpid_ipv4});
            break :blk b.finishStamped().len;
        },
        .csnp => blk: {
            var b = try pdu.CsnpBuilder.init(buf, .{
                .source_id = sys ++ [1]u8{0},
                .start_lsp_id = @splat(0),
                .end_lsp_id = @splat(0xff),
            });
            try auth.addPlaceholder(&b.tlvs, key);
            try tlvs.addLspEntries(&b.tlvs, &.{entry});
            break :blk b.finish().len;
        },
        .psnp => blk: {
            var b = try pdu.PsnpBuilder.init(buf, .{ .source_id = sys ++ [1]u8{0} });
            try auth.addPlaceholder(&b.tlvs, key);
            try tlvs.addLspEntries(&b.tlvs, &.{entry});
            break :blk b.finish().len;
        },
    };
    try auth.sign(buf[0..n], key);
    return buf[0..n];
}

const Case = struct { name: []const u8, kind: Kind, key: auth.Key };

const cases = [_]Case{
    .{ .name = "p2p_md5", .kind = .p2p, .key = .{ .algorithm = .hmac_md5, .secret = key_short } },
    .{ .name = "p2p_clear", .kind = .p2p, .key = .{ .algorithm = .cleartext, .secret = "letmein" } },
    .{ .name = "lan_sha1", .kind = .lan, .key = .{ .algorithm = .hmac_sha1, .id = 7, .secret = key_short } },
    .{ .name = "csnp_sha1_k22", .kind = .csnp, .key = .{ .algorithm = .hmac_sha1, .id = 1, .secret = &key_22 } },
    .{ .name = "csnp_sha1_k22_strict", .kind = .csnp, .key = .{ .algorithm = .hmac_sha1, .id = 1, .secret = &key_22, .strict_rfc5310 = true } },
    .{ .name = "psnp_sha224", .kind = .psnp, .key = .{ .algorithm = .hmac_sha224, .id = 2, .secret = key_short } },
    .{ .name = "lsp_sha256", .kind = .lsp, .key = .{ .algorithm = .hmac_sha256, .id = 3, .secret = key_short } },
    .{ .name = "lsp_sha256_k40", .kind = .lsp, .key = .{ .algorithm = .hmac_sha256, .id = 3, .secret = &key_40 } },
    .{ .name = "lsp_sha256_k40_strict", .kind = .lsp, .key = .{ .algorithm = .hmac_sha256, .id = 3, .secret = &key_40, .strict_rfc5310 = true } },
    .{ .name = "lsp_md5", .kind = .lsp, .key = .{ .algorithm = .hmac_md5, .secret = key_short } },
    .{ .name = "lsp_sha384", .kind = .lsp, .key = .{ .algorithm = .hmac_sha384, .id = 0xBEEF, .secret = key_short } },
    .{ .name = "p2p_sha512_long", .kind = .p2p, .key = .{ .algorithm = .hmac_sha512, .id = 65535, .secret = &key_long } },
    .{ .name = "p2p_sha512_long_strict", .kind = .p2p, .key = .{ .algorithm = .hmac_sha512, .id = 65535, .secret = &key_long, .strict_rfc5310 = true } },
};

fn katWire(name: []const u8, out: []u8) []u8 {
    for (kats) |k| {
        if (std.mem.eql(u8, k.name, name)) return std.fmt.hexToBytes(out, k.wire) catch unreachable;
    }
    unreachable;
}

test "auth KATs: builders + sign reproduce the independent Python bytes, verify accepts them" {
    comptime std.debug.assert(cases.len == kats.len);
    for (cases) |c| {
        var buf: [512]u8 = undefined;
        var want_buf: [512]u8 = undefined;
        const got = try build(&buf, c.kind, c.key);
        const want = katWire(c.name, &want_buf);
        testing.expectEqualSlices(u8, want, got) catch |e| {
            std.debug.print("KAT {s} differs\n", .{c.name});
            return e;
        };
        try testing.expectEqual(@as(usize, 0), try auth.verify(want, &.{c.key}));
        if (c.kind == .lsp) try testing.expectEqual(pdu.ChecksumStatus.good, try pdu.checkLspChecksum(want));
        // Signing an already signed PDU changes nothing.
        try auth.sign(buf[0..got.len], c.key);
        try testing.expectEqualSlices(u8, want, buf[0..got.len]);
    }
}

test "auth KATs: plain and strict RFC 5310 key preparation differ exactly for L < |K| <= B" {
    var a: [512]u8 = undefined;
    var b: [512]u8 = undefined;
    const pairs = [_][2][]const u8{
        .{ "csnp_sha1_k22", "csnp_sha1_k22_strict" },
        .{ "lsp_sha256_k40", "lsp_sha256_k40_strict" },
    };
    for (pairs) |p| try testing.expect(!std.mem.eql(u8, katWire(p[0], &a), katWire(p[1], &b)));
    // A key longer than the block is hashed by both rules.
    try testing.expectEqualSlices(u8, katWire("p2p_sha512_long", &a), katWire("p2p_sha512_long_strict", &b));
    // And a strict-signed PDU does not verify with the plain key (or back).
    const plain: auth.Key = .{ .algorithm = .hmac_sha256, .id = 3, .secret = &key_40 };
    var strict = plain;
    strict.strict_rfc5310 = true;
    try testing.expectError(error.AuthFailed, auth.verify(katWire("lsp_sha256_k40_strict", &a), &.{plain}));
    try testing.expectError(error.AuthFailed, auth.verify(katWire("lsp_sha256_k40", &a), &.{strict}));
    // For a key of at most L octets the flag changes nothing.
    const short: auth.Key = .{ .algorithm = .hmac_sha256, .id = 3, .secret = key_short, .strict_rfc5310 = true };
    try testing.expectEqual(@as(usize, 0), try auth.verify(katWire("lsp_sha256", &a), &.{short}));
}

test "auth: every octet of every KAT PDU is covered (one flipped bit fails), except the LSP's aging fields and outside a cleartext password" {
    for (cases) |c| {
        var buf: [512]u8 = undefined;
        const wire = katWire(c.name, &buf);
        for (0..wire.len) |i| {
            if (c.kind == .lsp and (i == 10 or i == 11 or i == 24 or i == 25)) continue;
            // Cleartext protects nothing but itself: only the password octets
            // (after code, length and type at 20..23) are checked.
            if (c.key.algorithm == .cleartext and (i < 23 or i >= 23 + c.key.secret.len)) continue;
            wire[i] ^= 0x01;
            defer wire[i] ^= 0x01;
            if (auth.verify(wire, &.{c.key})) |_| {
                std.debug.print("KAT {s}: flip at {d} still verifies\n", .{ c.name, i });
                return error.TestUnexpectedResult;
            } else |_| {}
        }
    }
}

test "auth: an LSP still verifies after aging (Remaining Lifetime) and with a stale checksum" {
    var buf: [512]u8 = undefined;
    const wire = katWire("lsp_sha256", &buf);
    const key: auth.Key = .{ .algorithm = .hmac_sha256, .id = 3, .secret = key_short };
    std.mem.writeInt(u16, wire[10..12], 17, .big);
    try testing.expectEqual(@as(usize, 0), try auth.verify(wire, &.{key}));
    wire[24] ^= 0xff;
    wire[25] ^= 0x0f;
    try testing.expectEqual(@as(usize, 0), try auth.verify(wire, &.{key}));
}

test "auth: missing TLV, unknown key, Key ID mismatch, wrong algorithm, wrong secret" {
    var buf: [512]u8 = undefined;
    const md5: auth.Key = .{ .algorithm = .hmac_md5, .secret = key_short };
    const sha1: auth.Key = .{ .algorithm = .hmac_sha1, .id = 7, .secret = key_short };

    // No Authentication TLV at all, for each PDU kind.
    {
        var b = try pdu.P2pHelloBuilder.init(&buf, .{ .source_id = sys, .holding_time = 30 });
        try tlvs.addAreaAddresses(&b.tlvs, &.{&area});
        const w = b.finish();
        try testing.expectError(error.AuthMissing, auth.verify(w, &.{md5}));
        try testing.expectEqual(@as(?auth.Located, null), try auth.find(w));
        try testing.expectError(error.AuthMissing, auth.sign(buf[0..w.len], md5));
    }
    {
        var b = try pdu.LspBuilder.init(&buf, .{ .remaining_lifetime = 1, .lsp_id = @splat(1), .sequence_number = 1, .flags = pdu.LspFlags.fromByte(3) });
        try testing.expectError(error.AuthMissing, auth.verify(b.finishStamped(), &.{md5}));
    }
    {
        var b = try pdu.CsnpBuilder.init(&buf, .{ .source_id = @splat(1), .start_lsp_id = @splat(0), .end_lsp_id = @splat(0xff) });
        try testing.expectError(error.AuthMissing, auth.verify(b.finish(), &.{md5}));
    }
    {
        var b = try pdu.PsnpBuilder.init(&buf, .{ .source_id = @splat(1) });
        try testing.expectError(error.AuthMissing, auth.verify(b.finish(), &.{md5}));
    }
    {
        var b = try pdu.LanHelloBuilder.init(&buf, .{ .source_id = sys, .holding_time = 9, .lan_id = @splat(1) });
        try testing.expectError(error.AuthMissing, auth.verify(b.finish(), &.{md5}));
    }

    var w_buf: [512]u8 = undefined;
    const lan = katWire("lan_sha1", &w_buf);
    try testing.expectEqual(@as(usize, 1), try auth.verify(lan, &.{ md5, sha1 }));
    // Key ID 8 configured, 7 on the wire.
    var other_id = sha1;
    other_id.id = 8;
    try testing.expectError(error.KeyNotFound, auth.verify(lan, &.{other_id}));
    // Only an HMAC-MD5 key configured for an RFC 5310 PDU.
    try testing.expectError(error.KeyNotFound, auth.verify(lan, &.{md5}));
    // Same Key ID, different SHA: the TLV length does not fit, refused.
    var sha256 = sha1;
    sha256.algorithm = .hmac_sha256;
    try testing.expectError(error.AuthFailed, auth.verify(lan, &.{sha256}));
    // Same id and algorithm, other secret.
    var wrong = sha1;
    wrong.secret = "isis-test-kez";
    try testing.expectError(error.AuthFailed, auth.verify(lan, &.{wrong}));
    // Empty key set.
    try testing.expectError(error.KeyNotFound, auth.verify(lan, &.{}));
    // sign with a key that does not match the placeholder.
    try testing.expectError(error.KeyMismatch, auth.sign(lan, other_id));
    try testing.expectError(error.KeyMismatch, auth.sign(lan, md5));
    try testing.expectError(error.KeyMismatch, auth.sign(lan, sha256));

    var md5_buf: [512]u8 = undefined;
    const p2p = katWire("p2p_md5", &md5_buf);
    var md5_wrong = md5;
    md5_wrong.secret = "nope";
    // RFC 5304 §2: a set of keys may be tried; the second one matches.
    try testing.expectEqual(@as(usize, 1), try auth.verify(p2p, &.{ md5_wrong, md5 }));
    try testing.expectError(error.AuthFailed, auth.verify(p2p, &.{md5_wrong}));
    try testing.expectError(error.KeyNotFound, auth.verify(p2p, &.{sha1}));
    try testing.expectError(error.KeyMismatch, auth.sign(p2p, sha1));
}

test "auth: cleartext compares the whole password" {
    var buf: [512]u8 = undefined;
    const w = katWire("p2p_clear", &buf);
    const good: auth.Key = .{ .algorithm = .cleartext, .secret = "letmein" };
    try testing.expectEqual(@as(usize, 0), try auth.verify(w, &.{good}));
    for ([_][]const u8{ "letmei", "letmeinn", "letmeIn", "" }) |pw| {
        const k: auth.Key = .{ .algorithm = .cleartext, .secret = pw };
        try testing.expectError(error.AuthFailed, auth.verify(w, &.{k}));
        try testing.expectError(error.KeyMismatch, auth.sign(w, k));
    }
    try auth.sign(w, good);
    try testing.expectError(error.KeyNotFound, auth.verify(w, &.{.{ .algorithm = .hmac_md5, .secret = "letmein" }}));
}

test "auth.parse: every type, truncated values, unknown types" {
    try testing.expectError(error.MalformedAuth, auth.parse(&.{}));
    // HMAC-MD5 must be exactly 17 octets.
    var v: [20]u8 = @splat(0);
    v[0] = auth.auth_type.hmac_md5;
    try testing.expectError(error.MalformedAuth, auth.parse(v[0..16]));
    try testing.expectError(error.MalformedAuth, auth.parse(v[0..18]));
    try testing.expect((try auth.parse(v[0..17])) == .hmac_md5);
    // RFC 5310 needs type + Key ID; a zero-length digest parses (verify refuses it).
    v[0] = auth.auth_type.crypto;
    v[1] = 0x12;
    v[2] = 0x34;
    try testing.expectError(error.MalformedAuth, auth.parse(v[0..1]));
    try testing.expectError(error.MalformedAuth, auth.parse(v[0..2]));
    const c = try auth.parse(v[0..3]);
    try testing.expectEqual(@as(u16, 0x1234), c.crypto.key_id);
    try testing.expectEqual(@as(usize, 0), c.crypto.digest.len);
    // Cleartext of length zero.
    v[0] = auth.auth_type.cleartext;
    try testing.expectEqual(@as(usize, 0), (try auth.parse(v[0..1])).cleartext.len);
    // Reserved 0 and private 255 are carried, not verified.
    for ([_]u8{ 0, 2, 255 }) |t| {
        v[0] = t;
        const o = try auth.parse(v[0..4]);
        try testing.expectEqual(t, o.other.auth_type);
        try testing.expectEqual(@as(usize, 3), o.other.value.len);
    }
}

test "auth: a truncated or unknown Authentication TLV inside a PDU" {
    var buf: [128]u8 = undefined;
    const key: auth.Key = .{ .algorithm = .hmac_md5, .secret = key_short };
    // HMAC-MD5 TLV with 15 octets of value.
    {
        var b = try pdu.P2pHelloBuilder.init(&buf, .{ .source_id = sys, .holding_time = 30 });
        var v: [16]u8 = @splat(0);
        v[0] = auth.auth_type.hmac_md5;
        try b.tlvs.addTlv(auth.tlv_code, v[0..16]);
        const w = b.finish();
        try testing.expectError(error.MalformedAuth, auth.verify(w, &.{key}));
        try testing.expectError(error.MalformedAuth, auth.sign(buf[0..w.len], key));
    }
    // RFC 5310 TLV whose digest is one octet short of SHA-256.
    {
        const k: auth.Key = .{ .algorithm = .hmac_sha256, .id = 1, .secret = key_short };
        var b = try pdu.PsnpBuilder.init(&buf, .{ .source_id = @splat(1) });
        var v: [34]u8 = @splat(0);
        v[0] = auth.auth_type.crypto;
        v[2] = 1;
        try b.tlvs.addTlv(auth.tlv_code, v[0..34]);
        const w = b.finish();
        try testing.expectError(error.AuthFailed, auth.verify(w, &.{k}));
        try testing.expectError(error.KeyMismatch, auth.sign(buf[0..w.len], k));
    }
    // Unknown auth type 255.
    {
        var b = try pdu.CsnpBuilder.init(&buf, .{ .source_id = @splat(1), .start_lsp_id = @splat(0), .end_lsp_id = @splat(0xff) });
        try b.tlvs.addTlv(auth.tlv_code, &.{ 255, 1, 2 });
        const w = b.finish();
        try testing.expectError(error.UnsupportedAuthType, auth.verify(w, &.{key}));
        try testing.expectError(error.KeyMismatch, auth.sign(buf[0..w.len], key));
    }
    // A TLV that overruns the PDU before the Authentication TLV.
    {
        var b = try pdu.P2pHelloBuilder.init(&buf, .{ .source_id = sys, .holding_time = 30 });
        try b.tlvs.addTlv(1, &.{ 3, 0x49, 0, 1 });
        const w = b.finish();
        buf[w.len - 5] = 40; // the area TLV now claims 40 octets
        try testing.expectError(error.TruncatedTlv, auth.verify(w, &.{key}));
    }
    // A PDU type without a modeled body.
    {
        var w: [8]u8 = .{ 0x83, 8, 1, 6, 9, 1, 0, 3 };
        try testing.expectError(error.UnsupportedPduType, auth.verify(&w, &.{key}));
        try testing.expectError(error.UnsupportedPduType, auth.sign(&w, key));
    }
}

test "auth: the first Authentication TLV counts, a second is hashed payload" {
    var buf: [256]u8 = undefined;
    const k1: auth.Key = .{ .algorithm = .hmac_sha1, .id = 1, .secret = "one" };
    const k2: auth.Key = .{ .algorithm = .hmac_sha1, .id = 2, .secret = "two" };
    var b = try pdu.P2pHelloBuilder.init(&buf, .{ .source_id = sys, .holding_time = 30 });
    try auth.addPlaceholder(&b.tlvs, k1);
    try auth.addPlaceholder(&b.tlvs, k2);
    const n = b.finish().len;
    try auth.sign(buf[0..n], k1);
    try testing.expectEqual(@as(usize, 0), try auth.verify(buf[0..n], &.{k1}));
    try testing.expectError(error.KeyNotFound, auth.verify(buf[0..n], &.{k2}));
    // The second TLV is covered by the first one's digest.
    buf[n - 1] ^= 1;
    try testing.expectError(error.AuthFailed, auth.verify(buf[0..n], &.{k1}));
}

test "auth: the digest ends at PDU Length, bytes after it are not covered" {
    var buf: [256]u8 = undefined;
    const k: auth.Key = .{ .algorithm = .hmac_sha256, .id = 9, .secret = key_short };
    var b = try pdu.CsnpBuilder.init(&buf, .{ .source_id = @splat(1), .start_lsp_id = @splat(0), .end_lsp_id = @splat(0xff) });
    try auth.addPlaceholder(&b.tlvs, k);
    const n = b.finish().len;
    buf[n] = 0xAA;
    try auth.sign(buf[0 .. n + 1], k);
    try testing.expectEqual(@as(usize, 0), try auth.verify(buf[0 .. n + 1], &.{k}));
    buf[n] = 0x55;
    try testing.expectEqual(@as(usize, 0), try auth.verify(buf[0 .. n + 1], &.{k}));
    try testing.expectEqual(@as(usize, 0), try auth.verify(buf[0..n], &.{k}));
}

test "auth.addPlaceholder: layout per algorithm, limits" {
    inline for (.{ .hmac_md5, .hmac_sha1, .hmac_sha224, .hmac_sha256, .hmac_sha384, .hmac_sha512 }) |alg| {
        const a: auth.Algorithm = alg;
        var buf: [80]u8 = undefined;
        var b = tlv.Builder.init(&buf);
        try auth.addPlaceholder(&b, .{ .algorithm = a, .id = 0x0102, .secret = "k" });
        const w = b.written();
        try testing.expectEqual(auth.tlv_code, w[0]);
        try testing.expectEqual(a.authType(), w[2]);
        const t = try auth.parse(w[2..]);
        switch (t) {
            .hmac_md5 => |d| {
                try testing.expectEqual(@as(u8, 17), w[1]);
                try testing.expectEqualSlices(u8, &@as([16]u8, @splat(0)), d);
            },
            .crypto => |c| {
                try testing.expectEqual(@as(u16, 0x0102), c.key_id);
                try testing.expectEqual(a.digestLen(), c.digest.len);
                for (c.digest, 0..) |x, i| try testing.expectEqual(([_]u8{ 0x87, 0x8F, 0xE1, 0xF3 })[i % 4], x);
            },
            else => return error.TestUnexpectedResult,
        }
    }
    var buf: [300]u8 = undefined;
    var b = tlv.Builder.init(&buf);
    const pw: [255]u8 = @splat('p');
    try testing.expectError(error.ValueTooLong, auth.addPlaceholder(&b, .{ .algorithm = .cleartext, .secret = &pw }));
    try auth.addPlaceholder(&b, .{ .algorithm = .cleartext, .secret = pw[0..254] });
    try testing.expectEqual(@as(usize, 257), b.pos);
    var small: [18]u8 = undefined;
    var sb = tlv.Builder.init(&small);
    try testing.expectError(error.BufferTooSmall, auth.addPlaceholder(&sb, .{ .algorithm = .hmac_md5, .secret = "k" }));
    var fit: [19]u8 = undefined;
    var fb = tlv.Builder.init(&fit);
    try auth.addPlaceholder(&fb, .{ .algorithm = .hmac_md5, .secret = "k" });
}

// -- delta mutation 2026-11-18: survivors turned into tests -------------------

test "auth: strict_rfc5310 changes nothing for a key of exactly L octets, or for HMAC-MD5" {
    var buf: [256]u8 = undefined;
    const k32: [32]u8 = key_40[0..32].*;
    const plain: auth.Key = .{ .algorithm = .hmac_sha256, .id = 4, .secret = &k32 };
    var strict = plain;
    strict.strict_rfc5310 = true;
    var b = try pdu.PsnpBuilder.init(&buf, .{ .source_id = @splat(2) });
    try auth.addPlaceholder(&b.tlvs, plain);
    const n = b.finish().len;
    try auth.sign(buf[0..n], plain);
    try testing.expectEqual(@as(usize, 0), try auth.verify(buf[0..n], &.{strict}));

    // RFC 5304 HMAC-MD5 is plain RFC 2104 whatever the flag says: a 40-octet
    // key (> L = 16, <= B = 64) is not pre-hashed.
    const md5: auth.Key = .{ .algorithm = .hmac_md5, .secret = &key_40 };
    var md5_strict = md5;
    md5_strict.strict_rfc5310 = true;
    var b2 = try pdu.PsnpBuilder.init(&buf, .{ .source_id = @splat(2) });
    try auth.addPlaceholder(&b2.tlvs, md5);
    const n2 = b2.finish().len;
    try auth.sign(buf[0..n2], md5);
    try testing.expectEqual(@as(usize, 0), try auth.verify(buf[0..n2], &.{md5_strict}));
}

test "auth: a key of another algorithm never matches, whatever its secret or id" {
    var buf: [512]u8 = undefined;
    const w = katWire("p2p_clear", &buf);
    // An HMAC key whose secret is the cleartext password.
    try testing.expectError(error.KeyMismatch, auth.sign(w, .{ .algorithm = .hmac_md5, .secret = "letmein" }));

    // An RFC 5310 TLV whose digest is 16 octets, Key ID 0: an HMAC-MD5 key has
    // that length and that (default) id, and must still not be used for it.
    var pbuf: [128]u8 = undefined;
    var b = try pdu.P2pHelloBuilder.init(&pbuf, .{ .source_id = sys, .holding_time = 30 });
    var v: [19]u8 = @splat(0);
    v[0] = auth.auth_type.crypto;
    try b.tlvs.addTlv(auth.tlv_code, &v);
    const n = b.finish().len;
    const md5: auth.Key = .{ .algorithm = .hmac_md5, .secret = key_short };
    try testing.expectError(error.KeyMismatch, auth.sign(pbuf[0..n], md5));
    try testing.expectError(error.KeyNotFound, auth.verify(pbuf[0..n], &.{md5}));
}
