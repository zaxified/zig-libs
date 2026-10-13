// SPDX-License-Identifier: MIT

//! Tests asked for by the mutation audit of 2026-10-13 (mutant schemata,
//! 120 mutants): each pins a refusal or an edge that no external vector
//! reaches, and each names the class of mutant it kills. Recipe for the two
//! DRBG known answers: `tools/gen_drbg_kat.py` (Python hmac/hashlib and
//! integer affine arithmetic, independent of this module).

const std = @import("std");
const testing = std.testing;
const root = @import("root.zig");

const P384 = root.P384;
const Fe = root.Fe;
const E = root.EcdsaP384Sha384;

fn hex(comptime n: usize, comptime s: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

fn nBytes() [48]u8 {
    var b: [48]u8 = undefined;
    std.mem.writeInt(u384, &b, root.scalar.field_order, .big);
    return b;
}

fn samePoint(want: P384, got: P384) !void {
    try testing.expectEqual(want.z.isZero(), got.z.isZero());
    if (want.z.isZero()) return;
    try testing.expectEqualSlices(u8, &want.toUncompressedSec1(), &got.toUncompressedSec1());
}

test "audit: public multiplies refuse the identity as an input point" {
    const s: [48]u8 = @splat(0x11);
    const id = P384.identityElement;
    const g = P384.basePoint;
    try testing.expectError(error.IdentityElement, id.mulPublic(s, .big));
    try testing.expectError(error.IdentityElement, P384.mulDoubleBasePublic(id, s, g, s, .big));
    try testing.expectError(error.IdentityElement, P384.mulDoubleBasePublic(g, s, id, s, .big));
    try testing.expectError(error.IdentityElement, id.mul(s, .big));
}

test "audit: ECDH refuses an identity peer and secrets outside [1, n − 1]" {
    const kp = try E.KeyPair.generateDeterministic(@splat(3));
    const peer = kp.public_key.toUncompressedSec1();
    var z: [48]u8 = undefined;
    try testing.expectError(error.IdentityElement, root.ecdhInto(&z, &kp.secret_key.bytes, &.{0x00}));
    try testing.expectError(error.NonCanonical, root.ecdhInto(&z, &nBytes(), &peer));
    try testing.expectError(error.NonCanonical, root.ecdhInto(&z, &@as([48]u8, @splat(0xff)), &peer));
    try testing.expectError(error.IdentityElement, root.ecdhInto(&z, &@as([48]u8, @splat(0)), &peer));
    // n − 1 is in range: the shared point is −(peer), whose x is the peer's.
    var nm1 = nBytes();
    nm1[47] -= 1;
    try root.ecdhInto(&z, &nm1, &peer);
    try testing.expectEqualSlices(u8, peer[1..49], &z);
}

test "audit: key derivation and signing refuse a secret ≥ n" {
    for ([_][48]u8{ nBytes(), @splat(0xff) }) |d| {
        try testing.expectError(error.NonCanonical, E.KeyPair.fromSecretKey(.{ .bytes = d }));
        var kp = try E.KeyPair.generateDeterministic(@splat(9));
        kp.secret_key.bytes = d;
        try testing.expectError(error.NonCanonical, kp.sign("m", null));
    }
}

test "audit: SEC1 decoding refuses trailing bytes and wrong lengths" {
    try testing.expectError(error.InvalidEncoding, P384.fromSec1(&.{ 0x00, 0x01 }));
    const c = P384.basePoint.toCompressedSec1();
    try testing.expectError(error.InvalidEncoding, P384.fromSec1(&(c ++ [_]u8{0})));
    try testing.expectError(error.InvalidEncoding, P384.fromSec1(c[0..48]));
    const u = P384.basePoint.toUncompressedSec1();
    try testing.expectError(error.InvalidEncoding, P384.fromSec1(&(u ++ [_]u8{0})));
    try testing.expectError(error.IdentityElement, E.PublicKey.fromSec1(&.{0x00}));
}

test "audit: affine (0, 0) is the identity" {
    const p = try P384.fromAffineCoordinates(.{ .x = Fe.zero, .y = Fe.zero });
    try testing.expectError(error.IdentityElement, p.rejectIdentity());
}

test "audit: points with x = 0 exist (b is a residue) and addMixed treats them as points" {
    // y² = b at x = 0: (0, √b) is on the curve. Only (0, 0) is the identity.
    const y = Fe.fromInt(0xc306610fb0ae5a159cf45c06069f22a6c5eb3641c602d42dea2c4b4f75550793406d80d2b91ad54f9048bd487af1ade1) catch unreachable;
    const q0 = try P384.fromAffineCoordinates(.{ .x = Fe.zero, .y = y });
    const g2 = P384.basePoint.dbl();
    try samePoint(g2.add(q0), g2.addMixed(.{ .x = Fe.zero, .y = y }));
    try testing.expect(!g2.addMixed(.{ .x = Fe.zero, .y = y }).equivalent(g2));
}

test "audit: double-base verify with −G and with a zero second scalar" {
    var a: [48]u8 = @splat(0);
    a[47] = 0x35;
    a[10] = 0x9a;
    var b: [48]u8 = @splat(0);
    b[47] = 0x07;
    b[3] = 0x41;
    const g = P384.basePoint;
    const q = try g.mul(b, .big);
    // −G has G's x but is not G: the comb shortcut must not take it.
    const ng = g.neg();
    try samePoint((try ng.mul(a, .big)).add(try q.mul(b, .big)), try P384.mulDoubleBasePublic(ng, a, q, b, .big));
    // A zero second scalar: the sum is the first term alone.
    try samePoint(try g.mul(a, .big), try P384.mulDoubleBasePublic(g, a, q, @splat(0), .big));
}

test "audit: a nonce that makes s = 0 is refused" {
    const Scalar = root.Scalar;
    const d = hex(48, "1e97a5d10c7e2654da93b4ca9d3d1b20e99bfb7f1e22f170cde61d43a2d6ab8ef5496d525306e69093a802a178b7155d");
    var k: [48]u8 = @splat(0);
    k[47] = 0x2a;
    // r from k·G; e = −r·d makes s = k⁻¹(e + r·d) = 0.
    const rx = (try P384.basePoint.mul(k, .big)).affineCoordinates().x.toBytes(.big);
    const r = Scalar.fromBytesReduce(rx, .big);
    const e = r.mul(try Scalar.fromBytes(d, .big)).neg().toBytes(.big);
    var sig: E.Signature = undefined;
    try testing.expectError(error.IdentityElement, E.signPrehashedWithNonceForTesting(&sig, &d, &e, &k));
    // The same nonce with another digest signs.
    var e2 = e;
    e2[47] ^= 1;
    try E.signPrehashedWithNonceForTesting(&sig, &d, &e2, &k);
}

test "audit: strict DER refuses a redundant leading zero" {
    _ = try E.Signature.fromDer(&.{ 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01 });
    _ = try E.Signature.fromDer(&.{ 0x30, 0x07, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x01 });
    try testing.expectError(error.InvalidEncoding, E.Signature.fromDer(&.{ 0x30, 0x07, 0x02, 0x02, 0x00, 0x7f, 0x02, 0x01, 0x01 }));
    try testing.expectError(error.InvalidEncoding, E.Signature.fromDer(&.{ 0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x01 }));
}

test "audit: DRBG known answers (generateDeterministic, §3.6 noise)" {
    const kp = try E.KeyPair.generateDeterministic(@splat(0x07));
    try testing.expectEqualSlices(u8, &hex(48, "1e97a5d10c7e2654da93b4ca9d3d1b20e99bfb7f1e22f170cde61d43a2d6ab8ef5496d525306e69093a802a178b7155d"), &kp.secret_key.bytes);
    try testing.expectEqualSlices(u8, &([_]u8{4} ++ hex(48, "c2543cedbd76cd552197a3fa8c2eb22b2b6fda158f757a57a66d2fc344ae5951e42046f37b4fd49759134d2e9456691e") ++
        hex(48, "d93a5ddc3c8c7b55311d7f8ac5b25aefa6a915e6c48abf544601f6cb487cf548ff32da26a0ccba1779bfd9280c0d8a92")), &kp.public_key.toUncompressedSec1());
    const sig = try kp.sign("abc", @splat(0x55));
    try testing.expectEqualSlices(u8, &hex(48, "0b913b2fe8109984d7a7d889b7fa37e7bfe31fe8c8c24c76e0be216c3b230c9cf52822b5d97bd53e242b22fe00bfc58d"), &sig.r);
    try testing.expectEqualSlices(u8, &hex(48, "edc4a2375566615c59a5c76d7d7b06ec2fc9dee5d06052212935916354b26b17cdd5a372c4e406f79ab8a08739a343ec"), &sig.s);
    // The incremental signer carries the noise too.
    var st = try kp.signer(@splat(0x55));
    st.update("ab");
    st.update("c");
    const sig2 = try st.finalize();
    try testing.expectEqualSlices(u8, &sig.toBytes(), &sig2.toBytes());
}
