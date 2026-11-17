// SPDX-License-Identifier: MIT
//! Tests added by the 2026-11-17 whole-module mutation of `root.zig`: the
//! length and scalar boundaries and the "zeroed on error" contracts that the
//! known-answer suite did not pin.
const std = @import("std");
const t = std.testing;
const ctap2pin = @import("root.zig");

const Aes256Cbc = ctap2pin.Aes256Cbc;
const One = ctap2pin.One;
const Two = ctap2pin.Two;

/// The NIST P-256 group order n, big-endian.
const p256_order: [32]u8 = .{
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
};

/// A valid private scalar (7) and its public key.
fn validPair() struct { d: [32]u8, pk: ctap2pin.PublicKey } {
    var d: [32]u8 = @splat(0);
    d[31] = 7;
    const pk = ctap2pin.publicKeyFromScalar(&d) catch unreachable;
    return .{ .d = d, .pk = pk };
}

test "AES-256-CBC: a destination shorter than the plaintext, or longer than the ciphertext, is InvalidLength" {
    const key: [32]u8 = @splat(1);
    const iv: [16]u8 = @splat(2);
    const data: [32]u8 = @splat(3);
    var out: [64]u8 = undefined;
    try t.expectError(error.InvalidLength, Aes256Cbc.encrypt(out[0..16], &data, &key, iv));
    try t.expectError(error.InvalidLength, Aes256Cbc.decrypt(out[0..48], &data, &key, iv));
}

test "ECDH: the order plus one (big-endian) is non-canonical, although its little-endian reading is below the order" {
    var n_plus_1 = p256_order;
    n_plus_1[31] += 1;
    try t.expectError(error.InvalidScalar, ctap2pin.publicKeyFromScalar(&n_plus_1));
    const peer = validPair().pk;
    var z: [32]u8 = undefined;
    try t.expectError(error.InvalidScalar, ctap2pin.ecdhZ(&z, &n_plus_1, peer));
    // the order itself and the largest canonical scalar (n - 1) behave as documented
    try t.expectError(error.InvalidScalar, ctap2pin.publicKeyFromScalar(&p256_order));
    var n_minus_1 = p256_order;
    n_minus_1[31] -= 1;
    _ = try ctap2pin.publicKeyFromScalar(&n_minus_1);
}

test "ecdhZ zeroes the output on every error" {
    const ok = validPair();
    var off_curve = ok.pk;
    off_curve.y[31] +%= 1;
    const zero_scalar: [32]u8 = @splat(0);
    var out: [32]u8 = @splat(0xAA);
    try t.expectError(error.InvalidPublicKey, ctap2pin.ecdhZ(&out, &ok.d, off_curve));
    try t.expectEqual(@as([32]u8, @splat(0)), out);
    out = @splat(0xAA);
    try t.expectError(error.InvalidScalar, ctap2pin.ecdhZ(&out, &zero_scalar, ok.pk));
    try t.expectEqual(@as([32]u8, @splat(0)), out);
    out = @splat(0xAA);
    const big: [32]u8 = @splat(0xFF);
    try t.expectError(error.InvalidScalar, ctap2pin.ecdhZ(&out, &big, ok.pk));
    try t.expectEqual(@as([32]u8, @splat(0)), out);
}

test "encapsulate zeroes the whole result on an ECDH error, both protocols" {
    const ok = validPair();
    var off_curve = ok.pk;
    off_curve.y[31] +%= 1;
    inline for (.{ One, Two }) |P| {
        var enc: P.Encaps = undefined;
        @memset(std.mem.asBytes(&enc), 0xAA);
        try t.expectError(error.InvalidPublicKey, P.encapsulate(&enc, &ok.d, off_curve));
        for (std.mem.asBytes(&enc)) |b| try t.expectEqual(@as(u8, 0), b);
    }
}

test "protocol two encrypt: a destination shorter than the IV is InvalidLength, not a slice panic" {
    var key: Two.SharedSecret = @splat(4);
    const iv: [16]u8 = @splat(5);
    const pt: [16]u8 = @splat(6);
    var dst: [40]u8 = undefined;
    try t.expectError(error.InvalidLength, Two.encrypt(&key, iv, dst[0..8], &pt));
    try t.expectError(error.InvalidLength, Two.encrypt(&key, iv, dst[0..0], &pt));
    try t.expectError(error.InvalidLength, Two.encrypt(&key, iv, dst[0..40], &pt));
    try t.expectError(error.InvalidLength, Two.encrypt(&key, iv, dst[0..31], &pt));
    try Two.encrypt(&key, iv, dst[0..32], &pt);
}

test "verify: a signature longer than the MAC is refused, whatever follows the genuine MAC" {
    const key32: [32]u8 = @splat(9);
    const msg = "message";
    const mac1 = try One.authenticate(&key32, msg);
    var long1: [One.signature_length + 1]u8 = undefined;
    long1[0..One.signature_length].* = mac1;
    long1[One.signature_length] = 0;
    try t.expect(One.verify(&key32, msg, &mac1));
    try t.expect(!One.verify(&key32, msg, &long1));
    const mac2 = Two.authenticate(&key32, msg);
    var long2: [Two.signature_length + 1]u8 = undefined;
    long2[0..Two.signature_length].* = mac2;
    long2[Two.signature_length] = 0;
    try t.expect(Two.verify(&key32, msg, &mac2));
    try t.expect(!Two.verify(&key32, msg, &long2));
}
