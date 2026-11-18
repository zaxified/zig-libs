// SPDX-License-Identifier: MIT
//! Tests added by the 2026-11-17 whole-module mutation of `root.zig`: the
//! boundaries the RFC 9474 vectors do not reach (the PSS salt-length gate,
//! an over-long blinded message, `finalize`'s context check at the largest
//! modulus, and the two non-canonical inputs that must stay
//! `SignatureVerificationFailed`).
const std = @import("std");
const t = std.testing;
const blindrsa = @import("root.zig");
const kat = @import("kat_vectors.zig");
const rsa = @import("rsa");

const Sha384 = std.crypto.hash.sha2.Sha384;

test "blind: a salt length other than 0 or the digest length is InvalidSaltLength, whatever the value" {
    const pk = try kat.publicKey();
    var prng = std.Random.DefaultPrng.init(0x5a17);
    var ctx: blindrsa.Context = undefined;
    var out: [blindrsa.max_modulus_len]u8 = undefined;
    for ([_]usize{ 1, 24, 47, 49, 96 }) |salt_len| {
        try t.expectError(error.InvalidSaltLength, blindrsa.blind(pk, Sha384, "msg", salt_len, prng.random(), &ctx, &out));
    }
    // and the two defined values are accepted
    for ([_]usize{ 0, Sha384.digest_length }) |salt_len| {
        _ = try blindrsa.blind(pk, Sha384, "msg", salt_len, prng.random(), &ctx, &out);
    }
}

test "blindSign: a blinded message one byte LONGER than the modulus is InvalidBlindedMessage, not a copy past the buffer" {
    const sk = try kat.secretKey();
    const pk = try kat.publicKey();
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x21)));
    var long: [kat.n.len + 1]u8 = undefined;
    long[0] = 0;
    @memcpy(long[1..], &kat.a1.blinded_msg);
    var out: [blindrsa.max_modulus_len + 1]u8 = undefined;
    try t.expectError(error.InvalidBlindedMessage, blindrsa.blindSign(&sk, pk, csprng.random(), &long, &out));
}

fn rInvOne() [blindrsa.max_modulus_len]u8 {
    var r = @as([blindrsa.max_modulus_len]u8, @splat(0));
    r[blindrsa.max_modulus_len - 1] = 1;
    return r;
}

test "finalize: a context of the largest supported modulus length is accepted, the verdict comes from the signature check" {
    // n = 2^(8 * max_modulus_len) - 1 is odd and as wide as the module allows; no private key is needed to
    // get PAST the context check, and the unrelated blind signature then fails the trailing verify.
    const n = @as([blindrsa.max_modulus_len]u8, @splat(0xff));
    const pk = try rsa.PublicKey.fromBytes(&n, &.{ 0x01, 0x00, 0x01 });
    var blind_sig = @as([blindrsa.max_modulus_len]u8, @splat(0x11));
    blind_sig[0] = 0;
    const ctx = blindrsa.Context{
        .prepared_msg = "m",
        .salt_len = 0,
        .r_inv = rInvOne(),
        .modulus_len = blindrsa.max_modulus_len,
    };
    var out: [blindrsa.max_modulus_len]u8 = undefined;
    try t.expectError(error.SignatureVerificationFailed, blindrsa.finalize(pk, Sha384, &blind_sig, &ctx, &out));
}

test "finalize: a blind signature >= n, and a stored inverse >= n, are SignatureVerificationFailed (not InvalidContext)" {
    const pk = try kat.publicKey();
    var ctx = blindrsa.Context{
        .prepared_msg = &kat.a1.prepared_msg,
        .salt_len = kat.a1.salt.len,
        .r_inv = undefined,
        .modulus_len = kat.n.len,
    };
    @memset(&ctx.r_inv, 0);
    @memcpy(ctx.r_inv[0..kat.a1.inv.len], &kat.a1.inv);
    var out: [blindrsa.max_modulus_len]u8 = undefined;
    // z = n
    try t.expectError(error.SignatureVerificationFailed, blindrsa.finalize(pk, Sha384, &kat.n, &ctx, &out));
    // r_inv = 2^(8k) - 1 >= n
    @memset(ctx.r_inv[0..kat.n.len], 0xff);
    try t.expectError(error.SignatureVerificationFailed, blindrsa.finalize(pk, Sha384, &kat.a1.blind_sig, &ctx, &out));
}
