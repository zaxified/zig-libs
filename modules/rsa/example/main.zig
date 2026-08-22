// SPDX-License-Identifier: MIT

//! What a certificate-less signer does with `rsa`: generate a fresh key
//! pair, sign a document with RSASSA-PKCS1-v1.5/SHA-256, verify it, then
//! show the failure named case — a tampered document — and OAEP
//! encrypt/decrypt of a short secret to the same key pair's public half.
//!
//! Built by `zig build check-examples` against the PUBLISHED module — no
//! access to anything `rsa` does not export. The modulus size below (512
//! bits) is a toy size chosen ONLY so this example compiles and would run
//! fast — a real deployment needs >= 2048 bits.

const std = @import("std");
const rsa = @import("rsa");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub fn main() !void {
    // Deterministic seed: fine for a reproducible example, never for a
    // real key (the module's own doc comment on `generate` says so).
    var prng = std.Random.DefaultPrng.init(0xC0FFEE_1234_5678);
    const random = prng.random();

    var kp = try rsa.generate(random, 512, 65537);
    defer kp.secret_key.deinit();

    const doc = "invoice #4021: pay 1200.00 EUR by 2026-09-01";
    var sig_buf: [rsa.max_modulus_len]u8 = undefined;
    const sig = try rsa.signPkcs1v15(kp.secret_key, Sha256, doc, &sig_buf);
    try rsa.verifyPkcs1v15(kp.public_key, Sha256, doc, sig);
    std.debug.print("PKCS1v15/SHA-256 signature verified over {d} bytes\n", .{doc.len});

    // A tampered document must fail verification by name.
    const tampered = "invoice #4021: pay 9200.00 EUR by 2026-09-01";
    rsa.verifyPkcs1v15(kp.public_key, Sha256, tampered, sig) catch |err| switch (err) {
        error.SignatureVerificationFailed => std.debug.print("tampered document correctly rejected\n", .{}),
    };

    // OAEP: encrypt a short secret to the public key, decrypt with the
    // private half. `label` is the RFC 8017 associated-data string —
    // empty is the common case.
    const secret = "session-key-material";
    var ct_buf: [rsa.max_modulus_len]u8 = undefined;
    const ct = try rsa.encryptOaep(kp.public_key, Sha256, random, secret, "", &ct_buf);

    var pt_buf: [rsa.max_modulus_len]u8 = undefined;
    const pt = try rsa.decryptOaep(kp.secret_key, Sha256, ct, "", &pt_buf);
    std.debug.print("OAEP round-trip matches original: {}\n", .{std.mem.eql(u8, secret, pt)});

    // Generation itself validates its own parameters and names the
    // rejection rather than panicking on a caller mistake (odd bit count).
    if (rsa.generate(random, 513, 65537)) |_| {
        std.debug.print("unexpectedly generated an odd-bit-count key\n", .{});
    } else |err| switch (err) {
        error.InvalidBits => std.debug.print("odd bit count correctly rejected (InvalidBits)\n", .{}),
        error.InvalidExponent => return err,
    }
}
