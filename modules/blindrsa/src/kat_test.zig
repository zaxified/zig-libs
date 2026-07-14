// SPDX-License-Identifier: MIT
//! blindrsa KAT + property tests, driven by `kat_vectors.zig`'s RFC 9474
//! Appendix A.1/A.4 values.
//!
//! Layout: `pssEncode` and `verify` byte-exact KATs first, then the
//! crypto core — `blindWithFactor` (fed the RFC's own fixed blinding
//! factor `kat.r`, so `blinded_msg`/`ctx.r_inv` are BYTE-EXACT KATs),
//! `blindSign` (inputs and outputs fully pinned by the vector — the §7.2
//! internal private-op blind is output-invariant, so this stays a true
//! byte-exact KAT despite consuming randomness), `finalize` (byte-exact
//! against the published `sig`), fail-closed reject tests, and a full
//! random-path round-trip over a fresh `rsa.generate` keypair.

const std = @import("std");
const testing = std.testing;
const blindrsa = @import("root.zig");
const kat = @import("kat_vectors.zig");
const rsa = @import("rsa");
const Sha384 = std.crypto.hash.sha2.Sha384;

// ── REAL: pssEncode byte-exact against RFC 9474 Appendix A ─────────────

test "pssEncode reproduces RFC 9474 Appendix A.1 encoded_msg byte-exact (RSABSSA-SHA384-PSS-Randomized)" {
    const pk = try kat.publicKey();
    const em_bits = pk.n.bits() - 1;
    var em: [blindrsa.max_modulus_len]u8 = undefined;
    try blindrsa.pssEncode(Sha384, &kat.a1.prepared_msg, &kat.a1.salt, em_bits, em[0..kat.a1.encoded_msg.len]);
    try testing.expectEqualSlices(u8, &kat.a1.encoded_msg, em[0..kat.a1.encoded_msg.len]);
}

test "pssEncode reproduces RFC 9474 Appendix A.4 encoded_msg byte-exact (RSABSSA-SHA384-PSSZERO-Deterministic)" {
    const pk = try kat.publicKey();
    const em_bits = pk.n.bits() - 1;
    var em: [blindrsa.max_modulus_len]u8 = undefined;
    try blindrsa.pssEncode(Sha384, &kat.a4.prepared_msg, &kat.a4.salt, em_bits, em[0..kat.a4.encoded_msg.len]);
    try testing.expectEqualSlices(u8, &kat.a4.encoded_msg, em[0..kat.a4.encoded_msg.len]);
}

// ── REAL: verify against RFC 9474 Appendix A published signatures ──────

test "verify accepts the RFC 9474 Appendix A.1 signature (salt_len 48)" {
    const pk = try kat.publicKey();
    try blindrsa.verify(pk, Sha384, &kat.a1.prepared_msg, &kat.a1.sig, kat.a1.salt.len);
}

test "verify accepts the RFC 9474 Appendix A.4 signature (salt_len 0, PSSZERO)" {
    const pk = try kat.publicKey();
    try blindrsa.verify(pk, Sha384, &kat.a4.prepared_msg, &kat.a4.sig, kat.a4.salt.len);
}

test "verify rejects a tampered signature (fail-closed)" {
    const pk = try kat.publicKey();
    var tampered = kat.a1.sig;
    tampered[0] ^= 0x01;
    try testing.expectError(error.SignatureVerificationFailed, blindrsa.verify(pk, Sha384, &kat.a1.prepared_msg, &tampered, kat.a1.salt.len));

    var tampered_last = kat.a1.sig;
    tampered_last[tampered_last.len - 1] ^= 0x80;
    try testing.expectError(error.SignatureVerificationFailed, blindrsa.verify(pk, Sha384, &kat.a1.prepared_msg, &tampered_last, kat.a1.salt.len));
}

test "verify rejects the wrong message" {
    const pk = try kat.publicKey();
    try testing.expectError(
        error.SignatureVerificationFailed,
        blindrsa.verify(pk, Sha384, "not the signed message", &kat.a1.sig, kat.a1.salt.len),
    );
}

test "verify rejects the wrong salt_len (A.1's salt_len against A.4's PSSZERO signature and vice versa)" {
    const pk = try kat.publicKey();
    try testing.expectError(
        error.SignatureVerificationFailed,
        blindrsa.verify(pk, Sha384, &kat.a4.prepared_msg, &kat.a4.sig, kat.a1.salt.len),
    );
    try testing.expectError(
        error.SignatureVerificationFailed,
        blindrsa.verify(pk, Sha384, &kat.a1.prepared_msg, &kat.a1.sig, kat.a4.salt.len),
    );
}

test "verify rejects a signature produced under a different message than its own prepared_msg (cross-vector)" {
    // a1.sig verifies a1.prepared_msg (48-byte salt); it must NOT verify
    // a4.prepared_msg (== raw msg, no prefix) even though both derive from
    // the same underlying application-level msg.
    const pk = try kat.publicKey();
    try testing.expectError(
        error.SignatureVerificationFailed,
        blindrsa.verify(pk, Sha384, &kat.a4.prepared_msg, &kat.a1.sig, kat.a1.salt.len),
    );
}

// ── crypto core: byte-exact KATs against RFC 9474 Appendix A ───────────

test "blindWithFactor reproduces RFC 9474 Appendix A.1 blinded_msg + inv byte-exact (fed the RFC's fixed r)" {
    const pk = try kat.publicKey();
    var ctx: blindrsa.Context = undefined;
    var blinded_msg: [blindrsa.max_modulus_len]u8 = undefined;
    const got = try blindrsa.blindWithFactor(pk, Sha384, &kat.a1.prepared_msg, &kat.a1.salt, &kat.r, &ctx, &blinded_msg);
    try testing.expectEqualSlices(u8, &kat.a1.blinded_msg, got);
    // The Context must carry the RFC's published inv (r⁻¹ mod n) —
    // independently validates the local extended-Euclid inverse against
    // RFC-published data — plus the right verify parameters.
    try testing.expectEqualSlices(u8, &kat.a1.inv, ctx.r_inv[0..kat.a1.inv.len]);
    try testing.expectEqual(kat.a1.salt.len, ctx.salt_len);
    try testing.expectEqual(kat.a1.blinded_msg.len, ctx.modulus_len);
}

test "blindWithFactor reproduces RFC 9474 Appendix A.4 blinded_msg + inv byte-exact (PSSZERO, same r)" {
    const pk = try kat.publicKey();
    var ctx: blindrsa.Context = undefined;
    var blinded_msg: [blindrsa.max_modulus_len]u8 = undefined;
    const got = try blindrsa.blindWithFactor(pk, Sha384, &kat.a4.prepared_msg, &kat.a4.salt, &kat.r, &ctx, &blinded_msg);
    try testing.expectEqualSlices(u8, &kat.a4.blinded_msg, got);
    try testing.expectEqualSlices(u8, &kat.a4.inv, ctx.r_inv[0..kat.a4.inv.len]);
    try testing.expectEqual(@as(usize, 0), ctx.salt_len);
}

test "blindSign reproduces RFC 9474 Appendix A.1 blind_sig byte-exact (SS7.2 internal blinding is output-invariant)" {
    const sk = try kat.secretKey();
    const pk = try kat.publicKey();
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x11} ** 32);
    var out: [blindrsa.max_modulus_len]u8 = undefined;
    const got = try blindrsa.blindSign(sk, pk, csprng.random(), &kat.a1.blinded_msg, &out);
    try testing.expectEqualSlices(u8, &kat.a1.blind_sig, got);
    // Different internal blinding randomness, identical output.
    var csprng2 = std.Random.DefaultCsprng.init([_]u8{0x55} ** 32);
    var out2: [blindrsa.max_modulus_len]u8 = undefined;
    const got2 = try blindrsa.blindSign(sk, pk, csprng2.random(), &kat.a1.blinded_msg, &out2);
    try testing.expectEqualSlices(u8, &kat.a1.blind_sig, got2);
}

test "blindSign reproduces RFC 9474 Appendix A.4 blind_sig byte-exact" {
    const sk = try kat.secretKey();
    const pk = try kat.publicKey();
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x12} ** 32);
    var out: [blindrsa.max_modulus_len]u8 = undefined;
    const got = try blindrsa.blindSign(sk, pk, csprng.random(), &kat.a4.blinded_msg, &out);
    try testing.expectEqualSlices(u8, &kat.a4.blind_sig, got);
}

test "blindSign rejects a wrong-length or out-of-range blinded_msg (RFC 9474 SS4 BlindSign range check)" {
    const sk = try kat.secretKey();
    const pk = try kat.publicKey();
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x13} ** 32);
    var out: [blindrsa.max_modulus_len]u8 = undefined;
    // Wrong length (one byte short).
    try testing.expectError(
        error.InvalidBlindedMessage,
        blindrsa.blindSign(sk, pk, csprng.random(), kat.a1.blinded_msg[1..], &out),
    );
    // Right length, but OS2IP(value) >= n (n itself, then all-0xff).
    try testing.expectError(
        error.InvalidBlindedMessage,
        blindrsa.blindSign(sk, pk, csprng.random(), &kat.n, &out),
    );
    const too_big = [_]u8{0xff} ** kat.n.len;
    try testing.expectError(
        error.InvalidBlindedMessage,
        blindrsa.blindSign(sk, pk, csprng.random(), &too_big, &out),
    );
}

test "finalize unblinds the RFC 9474 Appendix A.1 blind_sig byte-exact (and its internal verify accepted)" {
    const pk = try kat.publicKey();
    const ctx = blindrsa.Context{
        .prepared_msg = &kat.a1.prepared_msg,
        .salt_len = kat.a1.salt.len,
        .r_inv = kat.a1.inv,
        .modulus_len = kat.a1.blind_sig.len,
    };
    var out: [blindrsa.max_modulus_len]u8 = undefined;
    const got = try blindrsa.finalize(pk, Sha384, &kat.a1.blind_sig, &ctx, &out);
    // Byte-exact against the RFC's published sig; the ONLY way finalize
    // returns is through its real trailing verify() call.
    try testing.expectEqualSlices(u8, &kat.a1.sig, got);
}

test "finalize unblinds the RFC 9474 Appendix A.4 blind_sig byte-exact (PSSZERO)" {
    const pk = try kat.publicKey();
    const ctx = blindrsa.Context{
        .prepared_msg = &kat.a4.prepared_msg,
        .salt_len = kat.a4.salt.len,
        .r_inv = kat.a4.inv,
        .modulus_len = kat.a4.blind_sig.len,
    };
    var out: [blindrsa.max_modulus_len]u8 = undefined;
    const got = try blindrsa.finalize(pk, Sha384, &kat.a4.blind_sig, &ctx, &out);
    try testing.expectEqualSlices(u8, &kat.a4.sig, got);
}

// ── fail-closed reject tests ────────────────────────────────────────────

test "finalize fails closed on a tampered blind_sig (trailing verify rejects; no signature returned)" {
    const pk = try kat.publicKey();
    const ctx = blindrsa.Context{
        .prepared_msg = &kat.a1.prepared_msg,
        .salt_len = kat.a1.salt.len,
        .r_inv = kat.a1.inv,
        .modulus_len = kat.a1.blind_sig.len,
    };
    var out: [blindrsa.max_modulus_len]u8 = undefined;

    var tampered = kat.a1.blind_sig;
    tampered[0] ^= 0x01;
    try testing.expectError(error.SignatureVerificationFailed, blindrsa.finalize(pk, Sha384, &tampered, &ctx, &out));

    var tampered_last = kat.a1.blind_sig;
    tampered_last[tampered_last.len - 1] ^= 0x80;
    try testing.expectError(error.SignatureVerificationFailed, blindrsa.finalize(pk, Sha384, &tampered_last, &ctx, &out));

    // Wrong length: rejected before any math.
    try testing.expectError(
        error.InvalidBlindSignatureLength,
        blindrsa.finalize(pk, Sha384, kat.a1.blind_sig[1..], &ctx, &out),
    );
}

test "finalize fails closed when the Context does not match the blind_sig (wrong message / wrong salt_len / wrong inv)" {
    const pk = try kat.publicKey();
    var out: [blindrsa.max_modulus_len]u8 = undefined;

    // A.1's blind_sig against A.4's prepared_msg (and vice-versa contexts).
    const wrong_msg_ctx = blindrsa.Context{
        .prepared_msg = &kat.a4.prepared_msg,
        .salt_len = kat.a1.salt.len,
        .r_inv = kat.a1.inv,
        .modulus_len = kat.a1.blind_sig.len,
    };
    try testing.expectError(error.SignatureVerificationFailed, blindrsa.finalize(pk, Sha384, &kat.a1.blind_sig, &wrong_msg_ctx, &out));

    // Right message, wrong salt_len convention.
    const wrong_salt_ctx = blindrsa.Context{
        .prepared_msg = &kat.a1.prepared_msg,
        .salt_len = 0,
        .r_inv = kat.a1.inv,
        .modulus_len = kat.a1.blind_sig.len,
    };
    try testing.expectError(error.SignatureVerificationFailed, blindrsa.finalize(pk, Sha384, &kat.a1.blind_sig, &wrong_salt_ctx, &out));

    // Corrupted r_inv: unblinds to garbage, verify rejects.
    var bad_inv = kat.a1.inv;
    bad_inv[7] ^= 0x40;
    const bad_inv_ctx = blindrsa.Context{
        .prepared_msg = &kat.a1.prepared_msg,
        .salt_len = kat.a1.salt.len,
        .r_inv = bad_inv,
        .modulus_len = kat.a1.blind_sig.len,
    };
    try testing.expectError(error.SignatureVerificationFailed, blindrsa.finalize(pk, Sha384, &kat.a1.blind_sig, &bad_inv_ctx, &out));
}

test "blindWithFactor rejects a bad blinding factor: zero, >= n, and gcd(r, n) != 1 (r = a factor of n)" {
    const pk = try kat.publicKey();
    var ctx: blindrsa.Context = undefined;
    var blinded_msg: [blindrsa.max_modulus_len]u8 = undefined;

    const zero = [_]u8{0} ** kat.n.len;
    try testing.expectError(
        error.InvalidBlindingFactor,
        blindrsa.blindWithFactor(pk, Sha384, &kat.a1.prepared_msg, &kat.a1.salt, &zero, &ctx, &blinded_msg),
    );
    // r >= n (n itself is non-canonical mod n).
    try testing.expectError(
        error.InvalidBlindingFactor,
        blindrsa.blindWithFactor(pk, Sha384, &kat.a1.prepared_msg, &kat.a1.salt, &kat.n, &ctx, &blinded_msg),
    );
    // gcd(r, n) != 1: r = p, a prime factor of n — not invertible mod n.
    var r_is_p = [_]u8{0} ** kat.n.len;
    @memcpy(r_is_p[kat.n.len - kat.p.len ..], &kat.p);
    try testing.expectError(
        error.InvalidBlindingFactor,
        blindrsa.blindWithFactor(pk, Sha384, &kat.a1.prepared_msg, &kat.a1.salt, &r_is_p, &ctx, &blinded_msg),
    );
}

// ── random-path round-trips ─────────────────────────────────────────────

test "random-r blind -> blindSign -> finalize -> verify round-trip over the RFC 4096-bit key (both PSS and PSSZERO)" {
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x22} ** 32);
    const random = csprng.random();
    const sk = try kat.secretKey();
    const pk = try kat.publicKey();

    inline for ([_]usize{ Sha384.digest_length, 0 }) |salt_len| {
        var salt_buf: [Sha384.digest_length]u8 = undefined;
        random.bytes(&salt_buf);
        const salt = salt_buf[0..salt_len];

        var ctx: blindrsa.Context = undefined;
        var blinded_msg: [blindrsa.max_modulus_len]u8 = undefined;
        const blinded = try blindrsa.blind(pk, Sha384, &kat.a1.prepared_msg, salt, random, &ctx, &blinded_msg);
        // A fresh random r must NOT reproduce the RFC's blinded_msg
        // (that would mean r wasn't actually random).
        try testing.expect(!std.mem.eql(u8, &kat.a1.blinded_msg, blinded));

        var blind_sig_buf: [blindrsa.max_modulus_len]u8 = undefined;
        const blind_sig = try blindrsa.blindSign(sk, pk, random, blinded, &blind_sig_buf);

        var sig_buf: [blindrsa.max_modulus_len]u8 = undefined;
        const sig = try blindrsa.finalize(pk, Sha384, blind_sig, &ctx, &sig_buf);
        try blindrsa.verify(pk, Sha384, &kat.a1.prepared_msg, sig, salt_len);
    }
}

test "full round-trip: fresh rsa.generate() keypair, blind -> blindSign -> finalize -> verify true" {
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x99} ** 32);
    const random = csprng.random();
    // Smallest modulus that actually fits a full SHA-384 PSS encoding
    // (em_len >= hLen + sLen + 2 = 48 + 48 + 2 = 98 bytes => >= 784 bits);
    // rounded up for test speed (rsa.generate is exercised elsewhere at
    // realistic sizes in the rsa module's own test suite).
    const kp = try rsa.generate(random, 1024, 65537);

    const msg = "blindrsa round-trip smoke test";
    var prep_buf: [blindrsa.randomizer_len + msg.len]u8 = undefined;
    const prepared_msg = blindrsa.prepareRandomize(msg, random, &prep_buf);

    var salt: [Sha384.digest_length]u8 = undefined;
    random.bytes(&salt);

    var ctx: blindrsa.Context = undefined;
    var blinded_msg: [blindrsa.max_modulus_len]u8 = undefined;
    const blinded = try blindrsa.blind(kp.public_key, Sha384, prepared_msg, &salt, random, &ctx, &blinded_msg);

    var blind_sig_buf: [blindrsa.max_modulus_len]u8 = undefined;
    const blind_sig = try blindrsa.blindSign(kp.secret_key, kp.public_key, random, blinded, &blind_sig_buf);

    var sig_buf: [blindrsa.max_modulus_len]u8 = undefined;
    const sig = try blindrsa.finalize(kp.public_key, Sha384, blind_sig, &ctx, &sig_buf);

    try blindrsa.verify(kp.public_key, Sha384, prepared_msg, sig, salt.len);

    // Tamper the SAME session's blind_sig: finalize must fail closed.
    var tampered: [blindrsa.max_modulus_len]u8 = undefined;
    @memcpy(tampered[0..blind_sig.len], blind_sig);
    tampered[blind_sig.len / 2] ^= 0x04;
    var out2: [blindrsa.max_modulus_len]u8 = undefined;
    try testing.expectError(
        error.SignatureVerificationFailed,
        blindrsa.finalize(kp.public_key, Sha384, tampered[0..blind_sig.len], &ctx, &out2),
    );
}
