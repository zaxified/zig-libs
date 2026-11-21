// SPDX-License-Identifier: MIT
//! The padded signature format (`verifyPadded` / `signPadded`): the
//! reference's `FALCON_SIG_PADDED`, liboqs/PQClean `Falcon-padded-512/-1024`
//! (`0x30 + logn || nonce || compressed s2 || zeros`, 666 / 1280 bytes;
//! PQClean `falcon-padded-512/clean/pqclean.c`, MIT). The compressed s2 inside
//! is the same encoding the NIST KATs pin for the compressed format, so a
//! compressed signature repacked into the padded layout must verify, and the
//! padded signer's output must unpack to a compressed one that verifies.

const std = @import("std");
const falcon = @import("root.zig");
const sign = @import("sign.zig");

fn repack(comptime len: usize, header: u8, nonce: *const [40]u8, sig_field: []const u8) [len]u8 {
    var out: [len]u8 = @splat(0);
    out[0] = header;
    out[1..41].* = nonce.*;
    @memcpy(out[41..][0 .. sig_field.len - 1], sig_field[1..]);
    return out;
}

test "padded: constants match the reference (666 / 1280 bytes, headers 0x39 / 0x3a)" {
    try std.testing.expectEqual(@as(usize, 666), falcon.padded_sig_length);
    try std.testing.expectEqual(@as(usize, 1280), falcon.padded_sig_length_1024);
    try std.testing.expectEqual(@as(u8, 0x39), falcon.padded_sig_header);
    try std.testing.expectEqual(@as(u8, 0x3a), falcon.padded_sig_header_1024);
}

test "padded Falcon-512: compressed <-> padded, sign/verify, strict decode" {
    var kprng: sign.ShakePrng = undefined;
    kprng.init("padded-test key 512");
    defer kprng.deinit();
    var sk: falcon.SigningKey = undefined;
    var pk: falcon.PublicKey = undefined;
    try falcon.generateKeyPair(kprng.random(), &sk, &pk);
    defer sk.secureZero();
    var sp: sign.ShakePrng = undefined;
    sp.init("padded-test sign 512");
    defer sp.deinit();
    const msg = "padded format";

    // A compressed signature repacked into the padded layout verifies.
    var nonce: [40]u8 = undefined;
    var field: [falcon.max_sig_field_length]u8 = undefined;
    const flen = try falcon.signRandomized(&sk, msg, sp.random(), &nonce, &field);
    try pk.verify(msg, &nonce, field[0..flen]);
    var padded = repack(falcon.padded_sig_length, falcon.padded_sig_header, &nonce, field[0..flen]);
    try pk.verifyPadded(msg, &padded);

    // signPadded's output verifies, and its body is a compressed signature.
    var sig: [falcon.padded_sig_length]u8 = undefined;
    try falcon.signPadded(&sk, msg, sp.random(), &sig);
    try pk.verifyPadded(msg, &sig);
    try std.testing.expectEqual(falcon.padded_sig_header, sig[0]);
    var end: usize = sig.len;
    while (sig[end - 1] == 0) end -= 1;
    var as_field: [falcon.max_sig_field_length]u8 = undefined;
    as_field[0] = falcon.sig_header;
    @memcpy(as_field[1..][0 .. end - 41], sig[41..end]);
    try pk.verify(msg, sig[1..41], as_field[0 .. end - 40]);

    // Strict decode: another header, a nonzero pad byte, another message.
    var bad = padded;
    bad[0] = falcon.sig_header;
    try std.testing.expectError(error.InvalidSignature, pk.verifyPadded(msg, &bad));
    bad = padded;
    bad[bad.len - 1] = 1;
    try std.testing.expectError(error.InvalidSignature, pk.verifyPadded(msg, &bad));
    try std.testing.expectError(error.SignatureVerificationFailed, pk.verifyPadded("other", &padded));
}

test "padded Falcon-1024: sign/verify and the repacked compressed form" {
    var kprng: sign.ShakePrng = undefined;
    kprng.init("padded-test key 1024");
    defer kprng.deinit();
    var sk: falcon.SigningKey1024 = undefined;
    var pk: falcon.PublicKey1024 = undefined;
    try falcon.generateKeyPair1024(kprng.random(), &sk, &pk);
    defer sk.secureZero();
    var sp: sign.ShakePrng = undefined;
    sp.init("padded-test sign 1024");
    defer sp.deinit();
    const msg = "padded format 1024";
    var sig: [falcon.padded_sig_length_1024]u8 = undefined;
    try falcon.signPadded1024(&sk, msg, sp.random(), &sig);
    try pk.verifyPadded(msg, &sig);
    var nonce: [40]u8 = undefined;
    var field: [falcon.max_sig_field_length_1024]u8 = undefined;
    const flen = try falcon.signRandomized1024(&sk, msg, sp.random(), &nonce, &field);
    var padded = repack(falcon.padded_sig_length_1024, falcon.padded_sig_header_1024, &nonce, field[0..flen]);
    try pk.verifyPadded(msg, &padded);
    padded[50] ^= 1;
    try std.testing.expect(std.meta.isError(pk.verifyPadded(msg, &padded)));
}
