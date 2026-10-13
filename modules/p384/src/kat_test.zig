// SPDX-License-Identifier: MIT

//! Known-answer tests against external anchors: NIST CAVP (186-4 ECDSA
//! SigVer/SigGen/KeyPair/PKV and the ECC CDH primitive), Wycheproof (ECDH,
//! ECDSA SHA-384 and SHA-512 in DER and P1363 forms) and RFC 6979 A.2.6.
//! The SHA-512 rows matter: the digest is 64 bytes, longer than the 48-byte
//! group order, so they pin the leftmost-384-bits truncation (bits2int).
//! Every table's row count is asserted, so a regenerated file with fewer rows
//! goes red here. Recipe: `tools/gen_vectors.py`.

const std = @import("std");
const testing = std.testing;
const root = @import("root.zig");
const cavp = @import("cavp_vectors.zig");
const wp_ecdsa = @import("wycheproof_ecdsa_vectors.zig");
const wp_ecdh = @import("wycheproof_ecdh_vectors.zig");

const P384 = root.P384;
const sha2 = std.crypto.hash.sha2;

fn hex(comptime n: usize, s: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

fn hexAlloc(buf: []u8, s: []const u8) []u8 {
    return std.fmt.hexToBytes(buf, s) catch unreachable;
}

fn sec1(qx: []const u8, qy: []const u8) [97]u8 {
    return [_]u8{4} ++ hex(48, qx) ++ hex(48, qy);
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
    const sig: E.Signature = .{ .r = hex(48, v.r), .s = hex(48, v.s) };
    sig.verify(msg, pk) catch return false;
    return true;
}

test "CAVP 186-4 SigVer P-384 (SHA-1/224/256/384/512): 75 rows" {
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
    const d = hex(48, v.d);
    var sig: E.Signature = undefined;
    try E.signPrehashedWithNonceForTesting(&sig, &d, &digest, &hex(48, v.k));
    try testing.expectEqualSlices(u8, &hex(48, v.r), &sig.r);
    try testing.expectEqualSlices(u8, &hex(48, v.s), &sig.s);
    var kp: E.KeyPair = undefined;
    try E.KeyPair.fromSecretKeyInto(&kp, &.{ .bytes = d });
    try testing.expectEqualSlices(u8, &sec1(v.qx, v.qy), &kp.public_key.toUncompressedSec1());
    try sig.verify(msg, kp.public_key);
}

test "CAVP 186-4 SigGen P-384 (SHA-224/256/384/512, given k): 60 rows" {
    try testing.expectEqual(@as(usize, 60), cavp.siggen.len);
    for (cavp.siggen) |v| switch (v.hash) {
        inline else => |h| try sigGenOne(h, v),
    };
}

test "CAVP 186-4 KeyPair P-384: 10 rows" {
    try testing.expectEqual(@as(usize, 10), cavp.keypair.len);
    for (cavp.keypair) |v| {
        var kp: root.EcdsaP384Sha384.KeyPair = undefined;
        try root.EcdsaP384Sha384.KeyPair.fromSecretKeyInto(&kp, &.{ .bytes = hex(48, v.d) });
        try testing.expectEqualSlices(u8, &sec1(v.qx, v.qy), &kp.public_key.toUncompressedSec1());
    }
}

test "CAVP 186-4 PKV P-384: 12 rows (4 valid)" {
    try testing.expectEqual(@as(usize, 12), cavp.pkv.len);
    var valid: usize = 0;
    for (cavp.pkv) |v| {
        // An over-long coordinate (more than 48 bytes) cannot be put into a
        // SEC1 point at all; CAVP marks those rows as failing.
        if (v.qx.len != 96 or v.qy.len != 96) {
            try testing.expect(!v.ok);
            continue;
        }
        const ok = if (root.EcdsaP384Sha384.PublicKey.fromSec1(&sec1(v.qx, v.qy))) |_| true else |_| false;
        try testing.expectEqual(v.ok, ok);
        if (ok) valid += 1;
    }
    try testing.expectEqual(@as(usize, 4), valid);
}

test "CAVP ECC CDH primitive P-384: 25 rows" {
    try testing.expectEqual(@as(usize, 25), cavp.cdh.len);
    for (cavp.cdh) |v| {
        const d = hex(48, v.d);
        var z: [48]u8 = undefined;
        try root.ecdhInto(&z, &d, &sec1(v.qx, v.qy));
        try testing.expectEqualSlices(u8, &hex(48, v.z), &z);
        const q = try P384.basePoint.mul(d, .big);
        try testing.expectEqualSlices(u8, &sec1(v.qiut_x, v.qiut_y), &q.toUncompressedSec1());
    }
}

test "RFC 6979 A.2.6: P-384, SHA-1/224/256/384/512, \"sample\" and \"test\"" {
    const x = hex(48, "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5");
    const ux = hex(48, "ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64def8f0ea9055866064a254515480bc13");
    const uy = hex(48, "8015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db1288b231c3ae0d4fe7344fd2533264720");
    // (hash, message, k, r, s)
    const cases = .{
        .{ .sha1, "sample", "4471ef7518bb2c7c20f62eae1c387ad0c5e8e470995db4acf694466e6ab096630f29e5938d25106c3c340045a2db01a7", "ec748d839243d6fbef4fc5c4859a7dffd7f3abddf72014540c16d73309834fa37b9ba002899f6fda3a4a9386790d4eb2", "a3bcfa947beef4732bf247ac17f71676cb31a847b9ff0cbc9c9ed4c1a5b3facf26f49ca031d4857570ccb5ca4424a443" },
        .{ .sha224, "sample", "a4e4d2f0e729eb786b31fc20ad5d849e304450e0ae8e3e341134a5c1afa03cab8083ee4e3c45b06a5899ea56c51b5879", "42356e76b55a6d9b4631c865445dbe54e056d3b3431766d0509244793c3f9366450f76ee3de43f5a125333a6be060122", "9da0c81787064021e78df658f2fbb0b042bf304665db721f077a4298b095e4834c082c03d83028efbf93a3c23940ca8d" },
        .{ .sha256, "sample", "180ae9f9aec5438a44bc159a1fcb277c7be54fa20e7cf404b490650a8acc414e375572342863c899f9f2edf9747a9b60", "21b13d1e013c7fa1392d03c5f99af8b30c570c6f98d4ea8e354b63a21d3daa33bde1e888e63355d92fa2b3c36d8fb2cd", "f3aa443fb107745bf4bd77cb3891674632068a10ca67e3d45db2266fa7d1feebefdc63eccd1ac42ec0cb8668a4fa0ab0" },
        .{ .sha384, "sample", "94ed910d1a099dad3254e9242ae85abde4ba15168eaf0ca87a555fd56d10fbca2907e3e83ba95368623b8c4686915cf9", "94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c81a648152e44acf96e36dd1e80fabe46", "99ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94fa329c145786e679e7b82c71a38628ac8" },
        .{ .sha512, "sample", "92fc3c7183a883e24216d1141f1a8976c5b0dd797dfa597e3d7b32198bd35331a4e966532593a52980d0e3aaa5e10ec3", "ed0959d5880ab2d869ae7f6c2915c6d60f96507f9cb3e047c0046861da4a799cfe30f35cc900056d7c99cd7882433709", "512c8cceee3890a84058ce1e22dbc2198f42323ce8aca9135329f03c068e5112dc7cc3ef3446defceb01a45c2667fdd5" },
        .{ .sha1, "test", "66cc2c8f4d303fc962e5ff6a27bd79f84ec812ddae58cf5243b64a4ad8094d47ec3727f3a3c186c15054492e30698497", "4bc35d3a50ef4e30576f58cd96ce6bf638025ee624004a1f7789a8b8e43d0678acd9d29876daf46638645f7f404b11c7", "d5a6326c494ed3ff614703878961c0fde7b2c278f9a65fd8c4b7186201a2991695ba1c84541327e966fa7b50f7382282" },
        .{ .sha224, "test", "18fa39db95aa5f561f30fa3591dc59c0fa3653a80daffa0b48d1a4c6dfcbff6e3d33be4dc5eb8886a8ecd093f2935726", "e8c9d0b6ea72a0e7837fea1d14a1a9557f29faa45d3e7ee888fc5bf954b5e62464a9a817c47ff78b8c11066b24080e72", "07041d4a7a0379ac7232ff72e6f77b6ddb8f09b16cce0ec3286b2bd43fa8c6141c53ea5abef0d8231077a04540a96b66" },
        .{ .sha256, "test", "0cfac37587532347dc3389fdc98286bba8c73807285b184c83e62e26c401c0faa48dd070ba79921a3457abff2d630ad7", "6d6defac9ab64dabafe36c6bf510352a4cc27001263638e5b16d9bb51d451559f918eedaf2293be5b475cc8f0188636b", "2d46f3becbcc523d5f1a1256bf0c9b024d879ba9e838144c8ba6baeb4b53b47d51ab373f9845c0514eefb14024787265" },
        .{ .sha384, "test", "015ee46a5bf88773ed9123a5ab0807962d193719503c527b031b4c2d225092ada71f4a459bc0da98adb95837db8312ea", "8203b63d3c853e8d77227fb377bcf7b7b772e97892a80f36ab775d509d7a5feb0542a7f0812998da8f1dd3ca3cf023db", "ddd0760448d42d8a43af45af836fce4de8be06b485e9b61b827c2f13173923e06a739f040649a667bf3b828246baa5a5" },
        .{ .sha512, "test", "3780c4f67cb15518b6acae34c9f83568d2e12e47deab6c50a4e4ee5319d1e8ce0e2cc8a136036dc4b9c00e6888f66b6c", "a0d5d090c9980faf3c2ce57b7ae951d31977dd11c775d314af55f76c676447d06fb6495cd21b4b6e340fc236584fb277", "976984e59b4c77b0e8e4460dca3d9f20e07b9bb1f63beefaf576f6b2e8b224634a2092cd3792e0159ad9cee37659c736" },
    };
    inline for (cases) |c| {
        const E = EcdsaFor(c[0]);
        const H = @FieldType(E.Signer, "h");
        var kp: E.KeyPair = undefined;
        try E.KeyPair.fromSecretKeyInto(&kp, &.{ .bytes = x });
        try testing.expectEqualSlices(u8, &([_]u8{4} ++ ux ++ uy), &kp.public_key.toUncompressedSec1());
        // Deterministic signing derives the RFC's k and so its (r, s).
        const sig = try kp.sign(c[1], null);
        try testing.expectEqualSlices(u8, &hex(48, c[3]), &sig.r);
        try testing.expectEqualSlices(u8, &hex(48, c[4]), &sig.s);
        try sig.verify(c[1], kp.public_key);
        // With the RFC's k given explicitly the same signature results.
        var digest: [H.digest_length]u8 = undefined;
        H.hash(c[1], &digest, .{});
        var sig2: E.Signature = undefined;
        try E.signPrehashedWithNonceForTesting(&sig2, &x, &digest, &hex(48, c[2]));
        try testing.expectEqualSlices(u8, &sig.r, &sig2.r);
        try testing.expectEqualSlices(u8, &sig.s, &sig2.s);
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

fn wycheproofDer(comptime E: type, groups: anytype, count: usize, n_valid: usize) !void {
    var t: Tally = .{};
    var n: usize = 0;
    for (groups) |g| {
        var kbuf: [97]u8 = undefined;
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
    try testing.expectEqual(count, n);
    try testing.expectEqual(count, t.valid + t.invalid + t.acc_ok + t.acc_bad);
    try testing.expectEqual(n_valid, t.valid);
}

fn wycheproofP1363(comptime E: type, groups: anytype, count: usize, n_valid: usize) !void {
    var t: Tally = .{};
    var n: usize = 0;
    for (groups) |g| {
        var kbuf: [97]u8 = undefined;
        const pk = try E.PublicKey.fromSec1(hexAlloc(&kbuf, g.key));
        for (g.cases) |c| {
            n += 1;
            var mbuf: [8192]u8 = undefined;
            const msg = hexAlloc(&mbuf, c.msg);
            const sig = E.Signature.fromBytes(hex(96, c.sig));
            const ok = if (sig.verify(msg, pk)) |_| true else |_| false;
            try checkResult(&t, c.id, c.result, ok);
        }
    }
    try testing.expectEqual(count, n);
    try testing.expectEqual(n_valid, t.valid);
}

test "Wycheproof ECDSA secp384r1/SHA-384 DER: 504 rows" {
    try testing.expectEqual(@as(usize, 504), wp_ecdsa.sha384_der_count);
    try wycheproofDer(root.EcdsaP384Sha384, wp_ecdsa.sha384_der_groups, 504, 194);
}

test "Wycheproof ECDSA secp384r1/SHA-384 P1363: 261 rows" {
    try testing.expectEqual(@as(usize, 261), wp_ecdsa.sha384_p1363_count);
    try wycheproofP1363(root.EcdsaP384Sha384, wp_ecdsa.sha384_p1363_groups, 261, 193);
}

// SHA-512 over P-384: the 64-byte digest is truncated to its leftmost 48 bytes.
test "Wycheproof ECDSA secp384r1/SHA-512 DER: 542 rows" {
    try testing.expectEqual(@as(usize, 542), wp_ecdsa.sha512_der_count);
    try wycheproofDer(root.Ecdsa(sha2.Sha512), wp_ecdsa.sha512_der_groups, 542, 231);
}

test "Wycheproof ECDSA secp384r1/SHA-512 P1363: 299 rows" {
    try testing.expectEqual(@as(usize, 299), wp_ecdsa.sha512_p1363_count);
    try wycheproofP1363(root.Ecdsa(sha2.Sha512), wp_ecdsa.sha512_p1363_groups, 299, 230);
}

test "Wycheproof ECDH secp384r1: 798 rows" {
    try testing.expectEqual(@as(usize, 798), wp_ecdh.count);
    try testing.expectEqual(@as(usize, 798), wp_ecdh.cases.len);
    var t: Tally = .{};
    for (wp_ecdh.cases) |c| {
        var pbuf: [8192]u8 = undefined;
        const public = hexAlloc(&pbuf, c.public);
        const d = hex(48, c.private);
        var z: [48]u8 = undefined;
        const ok = if (root.ecdhInto(&z, &d, public)) |_| true else |_| false;
        if (ok and c.result != .invalid) {
            var want: [48]u8 = undefined;
            const w = hexAlloc(&want, c.shared);
            try testing.expectEqualSlices(u8, w, &z);
        }
        try checkResult(&t, c.id, c.result, ok);
    }
    try testing.expectEqual(@as(usize, 798), t.valid + t.invalid + t.acc_ok + t.acc_bad);
    try testing.expectEqual(@as(usize, 771), t.valid);
}

// Refusals that no external vector pins on its own (mirrors p521's audit
// 2026-10-10): zero secret key, zero r or s, non-strict DER signatures.
test "refusals: zero secret key, zero r or s, non-strict DER signatures" {
    const E = root.EcdsaP384Sha384;
    const zero: [48]u8 = @splat(0);

    try testing.expectError(error.IdentityElement, E.KeyPair.fromSecretKey(.{ .bytes = zero }));

    const kp = try E.KeyPair.generateDeterministic(@splat(7));
    var bad_kp = kp;
    bad_kp.secret_key.bytes = zero;
    try testing.expectError(error.IdentityElement, bad_kp.sign("m", null));

    const sig = try kp.sign("m", null);
    var bad = sig;
    bad.r = zero;
    try testing.expectError(error.IdentityElement, bad.verify("m", kp.public_key));
    bad = sig;
    bad.s = zero;
    try testing.expectError(error.IdentityElement, bad.verify("m", kp.public_key));

    // Strict DER: a negative INTEGER and a SEQUENCE length that disagrees
    // with the content are refused; the well-formed twin parses.
    try testing.expectError(error.InvalidEncoding, E.Signature.fromDer(&.{ 0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01 }));
    try testing.expectError(error.InvalidEncoding, E.Signature.fromDer(&.{ 0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01 }));
    try testing.expectError(error.InvalidEncoding, E.Signature.fromDer(&.{ 0x30, 0x05, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01 }));
    const ok = try E.Signature.fromDer(&.{ 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01 });
    try testing.expectEqual(@as(u8, 1), ok.r[47]);
}
