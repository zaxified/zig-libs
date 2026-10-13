// SPDX-License-Identifier: MIT

//! Known-answer tests for ECDH and for ECDSA over hashes other than SHA-256,
//! against external anchors: NIST CAVP (186-4 ECDSA SigVer/SigGen/KeyPair/PKV
//! and the ECC CDH primitive) and Wycheproof (ECDH; ECDSA SHA-512 in DER and
//! P1363 forms, SHA3-256 in DER form). The SHA-512 rows matter: the digest is
//! 64 bytes, longer than the 32-byte group order, so they pin the
//! leftmost-256-bits truncation (bits2int). Every table's row count is
//! asserted, so a regenerated file with fewer rows goes red here. The SHA-256
//! Wycheproof files and RFC 6979 live in `wycheproof_kat_test.zig` and
//! `kat_test.zig`. Recipe: `tools/gen_vectors.py`.

const std = @import("std");
const testing = std.testing;
const root = @import("root.zig");
const sign = @import("sign.zig");
const cavp = @import("cavp_vectors.zig");
const wp_ecdsa = @import("wycheproof_ecdsa_vectors.zig");
const wp_ecdh = @import("wycheproof_ecdh_vectors.zig");

const P256 = root.P256;
const sha2 = std.crypto.hash.sha2;

fn hex(comptime n: usize, s: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

fn hexAlloc(buf: []u8, s: []const u8) []u8 {
    return std.fmt.hexToBytes(buf, s) catch unreachable;
}

fn sec1(qx: []const u8, qy: []const u8) [65]u8 {
    return [_]u8{4} ++ hex(32, qx) ++ hex(32, qy);
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
    const sig: E.Signature = .{ .r = hex(32, v.r), .s = hex(32, v.s) };
    sig.verify(msg, pk) catch return false;
    return true;
}

test "CAVP 186-4 SigVer P-256 (SHA-1/224/256/384/512): 75 rows" {
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
    var mbuf: [256]u8 = undefined;
    const msg = hexAlloc(&mbuf, v.msg);
    const d = hex(32, v.d);
    var kp: E.KeyPair = undefined;
    try E.KeyPair.fromSecretKeyInto(&kp, &.{ .bytes = d });
    try testing.expectEqualSlices(u8, &sec1(v.qx, v.qy), &kp.public_key.toUncompressedSec1());
    const sig: E.Signature = .{ .r = hex(32, v.r), .s = hex(32, v.s) };
    try sig.verify(msg, kp.public_key);
    if (h == .sha256) {
        // The given-k signer is SHA-256 only: it must reproduce the row.
        const got = try sign.ecdsaSign(&d, msg, &hex(32, v.k));
        try testing.expectEqualSlices(u8, &hex(32, v.r), got[0..32]);
        try testing.expectEqualSlices(u8, &hex(32, v.s), got[32..64]);
    }
}

test "CAVP 186-4 SigGen P-256 (SHA-224/256/384/512): 60 rows, signatures verified, SHA-256 re-signed with the given k" {
    try testing.expectEqual(@as(usize, 60), cavp.siggen.len);
    for (cavp.siggen) |v| switch (v.hash) {
        inline else => |h| try sigGenOne(h, v),
    };
}

test "CAVP 186-4 KeyPair P-256: 10 rows" {
    try testing.expectEqual(@as(usize, 10), cavp.keypair.len);
    for (cavp.keypair) |v| {
        var kp: root.EcdsaP256Sha256.KeyPair = undefined;
        try root.EcdsaP256Sha256.KeyPair.fromSecretKeyInto(&kp, &.{ .bytes = hex(32, v.d) });
        try testing.expectEqualSlices(u8, &sec1(v.qx, v.qy), &kp.public_key.toUncompressedSec1());
    }
}

test "CAVP 186-4 PKV P-256: 12 rows (4 valid)" {
    try testing.expectEqual(@as(usize, 12), cavp.pkv.len);
    var valid: usize = 0;
    for (cavp.pkv) |v| {
        // An over-long coordinate (more than 32 bytes) cannot be put into a
        // SEC1 point at all; CAVP marks those rows as failing.
        if (v.qx.len != 64 or v.qy.len != 64) {
            try testing.expect(!v.ok);
            continue;
        }
        const ok = if (P256.fromSec1(&sec1(v.qx, v.qy))) |_| true else |_| false;
        try testing.expectEqual(v.ok, ok);
        if (ok) valid += 1;
    }
    try testing.expectEqual(@as(usize, 4), valid);
}

test "CAVP ECC CDH primitive P-256: 25 rows" {
    try testing.expectEqual(@as(usize, 25), cavp.cdh.len);
    for (cavp.cdh) |v| {
        const d = hex(32, v.d);
        var z: [32]u8 = undefined;
        try root.ecdhInto(&z, &d, &sec1(v.qx, v.qy));
        try testing.expectEqualSlices(u8, &hex(32, v.z), &z);
        const q = try P256.basePoint.mul(d, .big);
        try testing.expectEqualSlices(u8, &sec1(v.qiut_x, v.qiut_y), &q.toUncompressedSec1());
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

/// DER rows: the module's strict `derToRaw`, then the std-scaffold verifier
/// of `Ecdsa(H)` AND the module's own `ecdsaVerifyDigest` must agree, and
/// both must give the verdict upstream says.
fn wycheproofDer(comptime H: type, groups: anytype, count: usize, n_valid: usize) !void {
    const E = root.Ecdsa(H);
    var t: Tally = .{};
    var n: usize = 0;
    for (groups) |g| {
        var kbuf: [65]u8 = undefined;
        const key = hexAlloc(&kbuf, g.key);
        const pk = try E.PublicKey.fromSec1(key);
        for (g.cases) |c| {
            n += 1;
            var mbuf: [8192]u8 = undefined;
            var sbuf: [8192]u8 = undefined;
            const msg = hexAlloc(&mbuf, c.msg);
            const der = hexAlloc(&sbuf, c.sig);
            const ok = blk: {
                const raw = sign.derToRaw(der) orelse break :blk false;
                const via_scaffold = if (E.Signature.fromBytes(raw).verify(msg, pk)) |_| true else |_| false;
                var digest: [H.digest_length]u8 = undefined;
                H.hash(msg, &digest, .{});
                const via_fast = sign.ecdsaVerifyDigest(key, &digest, raw);
                try testing.expectEqual(via_scaffold, via_fast);
                break :blk via_scaffold;
            };
            try checkResult(&t, c.id, c.result, ok);
        }
    }
    try testing.expectEqual(count, n);
    try testing.expectEqual(count, t.valid + t.invalid + t.acc_ok + t.acc_bad);
    try testing.expectEqual(n_valid, t.valid);
}

fn wycheproofP1363(comptime H: type, groups: anytype, count: usize, n_valid: usize) !void {
    const E = root.Ecdsa(H);
    var t: Tally = .{};
    var n: usize = 0;
    for (groups) |g| {
        var kbuf: [65]u8 = undefined;
        const key = hexAlloc(&kbuf, g.key);
        const pk = try E.PublicKey.fromSec1(key);
        for (g.cases) |c| {
            n += 1;
            var mbuf: [8192]u8 = undefined;
            const msg = hexAlloc(&mbuf, c.msg);
            const raw = hex(64, c.sig);
            const via_scaffold = if (E.Signature.fromBytes(raw).verify(msg, pk)) |_| true else |_| false;
            var digest: [H.digest_length]u8 = undefined;
            H.hash(msg, &digest, .{});
            const via_fast = sign.ecdsaVerifyDigest(key, &digest, raw);
            try testing.expectEqual(via_scaffold, via_fast);
            try checkResult(&t, c.id, c.result, via_scaffold);
        }
    }
    try testing.expectEqual(count, n);
    try testing.expectEqual(n_valid, t.valid);
}

// SHA-512 over P-256: the 64-byte digest is truncated to its leftmost 32 bytes.
test "Wycheproof ECDSA secp256r1/SHA-512 DER: 554 rows" {
    try testing.expectEqual(@as(usize, 554), wp_ecdsa.sha512_der_count);
    try wycheproofDer(sha2.Sha512, wp_ecdsa.sha512_der_groups, 554, 243);
}

test "Wycheproof ECDSA secp256r1/SHA-512 P1363: 311 rows" {
    try testing.expectEqual(@as(usize, 311), wp_ecdsa.sha512_p1363_count);
    try wycheproofP1363(sha2.Sha512, wp_ecdsa.sha512_p1363_groups, 311, 242);
}

test "Wycheproof ECDSA secp256r1/SHA3-256 DER: 482 rows" {
    try testing.expectEqual(@as(usize, 482), wp_ecdsa.sha3_256_der_count);
    try wycheproofDer(std.crypto.hash.sha3.Sha3_256, wp_ecdsa.sha3_256_der_groups, 482, 178);
}

test "Wycheproof ECDH secp256r1: 363 rows" {
    try testing.expectEqual(@as(usize, 363), wp_ecdh.count);
    try testing.expectEqual(@as(usize, 363), wp_ecdh.cases.len);
    var t: Tally = .{};
    for (wp_ecdh.cases) |c| {
        var pbuf: [8192]u8 = undefined;
        const public = hexAlloc(&pbuf, c.public);
        const d = hex(32, c.private);
        var z: [32]u8 = undefined;
        const ok = if (root.ecdhInto(&z, &d, public)) |_| true else |_| false;
        if (ok and c.result != .invalid) {
            var want: [32]u8 = undefined;
            const w = hexAlloc(&want, c.shared);
            try testing.expectEqualSlices(u8, w, &z);
        }
        try checkResult(&t, c.id, c.result, ok);
    }
    try testing.expectEqual(@as(usize, 363), t.valid + t.invalid + t.acc_ok + t.acc_bad);
    try testing.expectEqual(@as(usize, 330), t.valid);
    try testing.expectEqual(@as(usize, 26), t.invalid);
    // The seven "acceptable" rows are compressed-point and unnamed-curve
    // variants: either verdict is allowed, but the tally must account for all.
    try testing.expectEqual(@as(usize, 7), t.acc_ok + t.acc_bad);
}

// Refusals that no external vector pins on its own: a zero or out-of-range
// secret, zero r or s.
test "refusals: zero r or s, zero secret key" {
    const E = root.EcdsaP256Sha256;
    const zero: [32]u8 = @splat(0);

    var kp: E.KeyPair = undefined;
    try testing.expectError(error.IdentityElement, E.KeyPair.fromSecretKeyInto(&kp, &.{ .bytes = zero }));

    const pair = try E.KeyPair.generateDeterministic(@splat(7));
    const sig = try pair.sign("m", null);
    var bad = sig;
    bad.r = zero;
    try testing.expectError(error.IdentityElement, bad.verify("m", pair.public_key));
    bad = sig;
    bad.s = zero;
    try testing.expectError(error.IdentityElement, bad.verify("m", pair.public_key));
}
