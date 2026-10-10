// SPDX-License-Identifier: MIT

//! Known-answer tests against external anchors: NIST CAVP (186-4 ECDSA
//! SigVer/SigGen/KeyPair/PKV and the ECC CDH primitive), Wycheproof (ECDH,
//! ECDSA DER and P1363) and RFC 6979 A.2.7. Every table's row count is
//! asserted, so a regenerated file with fewer rows goes red here. Recipe:
//! `tools/gen_vectors.py`.

const std = @import("std");
const testing = std.testing;
const root = @import("root.zig");
const cavp = @import("cavp_vectors.zig");
const wp_ecdsa = @import("wycheproof_ecdsa_vectors.zig");
const wp_ecdh = @import("wycheproof_ecdh_vectors.zig");

const P521 = root.P521;
const sha2 = std.crypto.hash.sha2;

fn hex(comptime n: usize, s: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

fn hexAlloc(buf: []u8, s: []const u8) []u8 {
    return std.fmt.hexToBytes(buf, s) catch unreachable;
}

fn sec1(qx: []const u8, qy: []const u8) [133]u8 {
    return [_]u8{4} ++ hex(66, qx) ++ hex(66, qy);
}

fn EcdsaFor(comptime h: cavp.Hash) type {
    return root.Ecdsa(switch (h) {
        .sha1 => std.crypto.hash.Sha1,
        .sha224 => sha2.Sha224,
        .sha256 => sha2.Sha256,
        .sha384 => sha2.Sha384,
        .sha512 => sha2.Sha512,
    });
}

fn sigVerOne(comptime h: cavp.Hash, v: cavp.SigVer) !bool {
    const E = EcdsaFor(h);
    var mbuf: [256]u8 = undefined;
    const msg = hexAlloc(&mbuf, v.msg);
    const q = sec1(v.qx, v.qy);
    const pk = E.PublicKey.fromSec1(&q) catch return false;
    const sig: E.Signature = .{ .r = hex(66, v.r), .s = hex(66, v.s) };
    sig.verify(msg, pk) catch return false;
    return true;
}

test "CAVP 186-4 SigVer P-521 (SHA-1/224/256/384/512): 75 rows" {
    try testing.expectEqual(@as(usize, 75), cavp.sigver.len);
    var pass: usize = 0;
    for (cavp.sigver) |v| {
        const got = switch (v.hash) {
            inline else => |h| try sigVerOne(h, v),
        };
        if (got != v.ok) {
            std.debug.print("SigVer mismatch: msg={s} expected {}\n", .{ v.msg[0..16], v.ok });
            return error.TestUnexpectedResult;
        }
        if (got) pass += 1;
    }
    try testing.expectEqual(@as(usize, 15), pass);
}

fn sigGenOne(comptime h: cavp.Hash, v: cavp.SigGen) !void {
    const E = EcdsaFor(h);
    const H = @FieldType(E.Signer, "h");
    var mbuf: [256]u8 = undefined;
    const msg = hexAlloc(&mbuf, v.msg);
    var digest: [H.digest_length]u8 = undefined;
    H.hash(msg, &digest, .{});
    const d = hex(66, v.d);
    var sig: E.Signature = undefined;
    try E.signPrehashedWithNonceForTesting(&sig, &d, &digest, &hex(66, v.k));
    try testing.expectEqualSlices(u8, &hex(66, v.r), &sig.r);
    try testing.expectEqualSlices(u8, &hex(66, v.s), &sig.s);
    var kp: E.KeyPair = undefined;
    try E.KeyPair.fromSecretKeyInto(&kp, &.{ .bytes = d });
    try testing.expectEqualSlices(u8, &sec1(v.qx, v.qy), &kp.public_key.toUncompressedSec1());
    try sig.verify(msg, kp.public_key);
}

test "CAVP 186-4 SigGen P-521 (SHA-224/256/384/512, given k): 60 rows" {
    try testing.expectEqual(@as(usize, 60), cavp.siggen.len);
    for (cavp.siggen) |v| switch (v.hash) {
        inline else => |h| try sigGenOne(h, v),
    };
}

test "CAVP 186-4 KeyPair P-521: 10 rows" {
    try testing.expectEqual(@as(usize, 10), cavp.keypair.len);
    for (cavp.keypair) |v| {
        var kp: root.EcdsaP521Sha512.KeyPair = undefined;
        try root.EcdsaP521Sha512.KeyPair.fromSecretKeyInto(&kp, &.{ .bytes = hex(66, v.d) });
        try testing.expectEqualSlices(u8, &sec1(v.qx, v.qy), &kp.public_key.toUncompressedSec1());
    }
}

test "CAVP 186-4 PKV P-521: 12 rows (4 valid)" {
    try testing.expectEqual(@as(usize, 12), cavp.pkv.len);
    var valid: usize = 0;
    for (cavp.pkv) |v| {
        const ok = if (root.EcdsaP521Sha512.PublicKey.fromSec1(&sec1(v.qx, v.qy))) |_| true else |_| false;
        try testing.expectEqual(v.ok, ok);
        if (ok) valid += 1;
    }
    try testing.expectEqual(@as(usize, 4), valid);
}

test "CAVP ECC CDH primitive P-521: 25 rows" {
    try testing.expectEqual(@as(usize, 25), cavp.cdh.len);
    for (cavp.cdh) |v| {
        const d = hex(66, v.d);
        var z: [66]u8 = undefined;
        try root.ecdhInto(&z, &d, &sec1(v.qx, v.qy));
        try testing.expectEqualSlices(u8, &hex(66, v.z), &z);
        const q = try P521.basePoint.mul(d, .big);
        try testing.expectEqualSlices(u8, &sec1(v.qiut_x, v.qiut_y), &q.toUncompressedSec1());
    }
}

test "RFC 6979 A.2.7: P-521, SHA-512, \"sample\" and \"test\"" {
    const E = root.EcdsaP521Sha512;
    const x = hex(66, "00fad06daa62ba3b25d2fb40133da757205de67f5bb0018fee8c86e1b68c7e75caa896eb32f1f47c70855836a6d16fcc1466f6d8fbec67db89ec0c08b0e996b83538");
    var kp: E.KeyPair = undefined;
    try E.KeyPair.fromSecretKeyInto(&kp, &.{ .bytes = x });
    const ux = hex(66, "01894550d0785932e00eaa23b694f213f8c3121f86dc97a04e5a7167db4e5bcd371123d46e45db6b5d5370a7f20fb633155d38ffa16d2bd761dcac474b9a2f5023a4");
    try testing.expectEqualSlices(u8, &ux, kp.public_key.toUncompressedSec1()[1..67]);
    const cases = .{
        .{ "sample", "00c328fafcbd79dd77850370c46325d987cb525569fb63c5d3bc53950e6d4c5f174e25a1ee9017b5d450606add152b534931d7d4e8455cc91f9b15bf05ec36e377fa", "00617cce7cf5064806c467f678d3b4080d6f1cc50af26ca209417308281b68af282623eaa63e5b5c0723d8b8c37ff0777b1a20f8ccb1dccc43997f1ee0e44da4a67a" },
        .{ "test", "013e99020abf5cee7525d16b69b229652ab6bdf2affcaef38773b4b7d08725f10cdb93482fdcc54edcee91eca4166b2a7c6265ef0ce2bd7051b7cef945babd47ee6d", "01fbd0013c674aa79cb39849527916ce301c66ea7ce8b80682786ad60f98f7e78a19ca69eff5c57400e3b3a0ad66ce0978214d13baf4e9ac60752f7b155e2de4dce3" },
    };
    inline for (cases) |c| {
        const sig = try kp.sign(c[0], null);
        try testing.expectEqualSlices(u8, &hex(66, c[1]), &sig.r);
        try testing.expectEqualSlices(u8, &hex(66, c[2]), &sig.s);
        try sig.verify(c[0], kp.public_key);
    }
}

const Tally = struct { valid: usize = 0, invalid: usize = 0, acc_ok: usize = 0, acc_bad: usize = 0 };

fn checkResult(t: *Tally, id: u32, result: anytype, ok: bool) !void {
    switch (result) {
        .valid => if (ok) {
            t.valid += 1;
        } else {
            std.debug.print("wycheproof tcId {d}: valid case refused\n", .{id});
            return error.TestUnexpectedResult;
        },
        .invalid => if (!ok) {
            t.invalid += 1;
        } else {
            std.debug.print("wycheproof tcId {d}: invalid case accepted\n", .{id});
            return error.TestUnexpectedResult;
        },
        .acceptable => if (ok) {
            t.acc_ok += 1;
        } else {
            t.acc_bad += 1;
        },
    }
}

test "Wycheproof ECDSA secp521r1/SHA-512 DER: 542 rows" {
    const E = root.EcdsaP521Sha512;
    try testing.expectEqual(@as(usize, 542), wp_ecdsa.der_count);
    var t: Tally = .{};
    var n: usize = 0;
    for (wp_ecdsa.der_groups) |g| {
        var kbuf: [133]u8 = undefined;
        const pk = try E.PublicKey.fromSec1(hexAlloc(&kbuf, g.key));
        for (g.cases) |c| {
            n += 1;
            var mbuf: [8192]u8 = undefined;
            var sbuf: [8192]u8 = undefined;
            const msg = hexAlloc(&mbuf, c.msg);
            const der = hexAlloc(&sbuf, c.sig);
            const ok = blk: {
                const sig = E.Signature.fromDer(der) catch break :blk false;
                sig.verify(msg, pk) catch break :blk false;
                // A signature that verifies must also round-trip through
                // our encoder to the same bytes: strict DER is canonical.
                var buf: [E.Signature.der_encoded_length_max]u8 = undefined;
                try testing.expectEqualSlices(u8, der, sig.toDer(&buf));
                break :blk true;
            };
            try checkResult(&t, c.id, c.result, ok);
        }
    }
    try testing.expectEqual(@as(usize, 542), n);
    try testing.expectEqual(@as(usize, 542), t.valid + t.invalid + t.acc_ok + t.acc_bad);
    try testing.expectEqual(@as(usize, 232), t.valid);
}

test "Wycheproof ECDSA secp521r1/SHA-512 P1363: 304 rows" {
    const E = root.EcdsaP521Sha512;
    try testing.expectEqual(@as(usize, 304), wp_ecdsa.p1363_count);
    var t: Tally = .{};
    var n: usize = 0;
    for (wp_ecdsa.p1363_groups) |g| {
        var kbuf: [133]u8 = undefined;
        const pk = try E.PublicKey.fromSec1(hexAlloc(&kbuf, g.key));
        for (g.cases) |c| {
            n += 1;
            var mbuf: [8192]u8 = undefined;
            const msg = hexAlloc(&mbuf, c.msg);
            const sig = E.Signature.fromBytes(hex(132, c.sig));
            const ok = if (sig.verify(msg, pk)) |_| true else |_| false;
            try checkResult(&t, c.id, c.result, ok);
        }
    }
    try testing.expectEqual(@as(usize, 304), n);
}

test "Wycheproof ECDH secp521r1: 669 rows" {
    try testing.expectEqual(@as(usize, 669), wp_ecdh.count);
    try testing.expectEqual(@as(usize, 669), wp_ecdh.cases.len);
    var t: Tally = .{};
    for (wp_ecdh.cases) |c| {
        var pbuf: [8192]u8 = undefined;
        const public = hexAlloc(&pbuf, c.public);
        const d = hex(66, c.private);
        var z: [66]u8 = undefined;
        const ok = if (root.ecdhInto(&z, &d, public)) |_| true else |_| false;
        if (ok and c.result != .invalid) {
            var want: [66]u8 = undefined;
            const w = hexAlloc(&want, c.shared);
            try testing.expectEqualSlices(u8, w, &z);
        }
        try checkResult(&t, c.id, c.result, ok);
    }
    try testing.expectEqual(@as(usize, 669), t.valid + t.invalid + t.acc_ok + t.acc_bad);
}
