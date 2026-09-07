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

// ── output-buffer-too-small: caller-controlled, was std.debug.assert ───
//
// `prepareRandomize`/`blindCore` (via `blind`/`blindWithFactor`)/`blindSign`/
// `finalize` used to guard their caller-supplied `out`/`blinded_msg_out`
// buffer with `std.debug.assert`. ReleaseFast compiles that assert out
// together with the slice bounds check on the write that follows, so an
// undersized buffer became a silent out-of-bounds write in the build that
// ships. Each test below is written in terms of the module's own length
// (`randomizer_len`, the modulus length carried by the RFC vectors/`Context`)
// rather than a literal, so it keeps measuring the mechanism if those move.

test "prepareRandomize: an out buffer one byte short of randomizer_len + msg.len is an error, not an assert" {
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x50} ** 32);
    var out: [blindrsa.randomizer_len + 5 - 1]u8 = undefined;
    try testing.expectError(error.OutputTooSmall, blindrsa.prepareRandomize("hello", csprng.random(), &out));

    var exact: [blindrsa.randomizer_len + 5]u8 = undefined;
    _ = try blindrsa.prepareRandomize("hello", csprng.random(), &exact);
}

test "blind/blindWithFactor: a blinded_msg_out one byte short of the modulus length is an error, not an assert" {
    const pk = try kat.publicKey();
    const modulus_len = kat.a1.blinded_msg.len;
    var ctx: blindrsa.Context = undefined;

    var too_small_buf: [blindrsa.max_modulus_len]u8 = undefined;
    const too_small = too_small_buf[0 .. modulus_len - 1];
    try testing.expectError(
        error.OutputTooSmall,
        blindrsa.blindWithFactor(pk, Sha384, &kat.a1.prepared_msg, &kat.a1.salt, &kat.r, &ctx, too_small),
    );

    var csprng = std.Random.DefaultCsprng.init([_]u8{0x51} ** 32);
    var salt: [Sha384.digest_length]u8 = undefined;
    csprng.random().bytes(&salt);
    try testing.expectError(
        error.OutputTooSmall,
        blindrsa.blind(pk, Sha384, &kat.a1.prepared_msg, &salt, csprng.random(), &ctx, too_small),
    );

    // Exact size still works.
    var exact_buf: [blindrsa.max_modulus_len]u8 = undefined;
    _ = try blindrsa.blindWithFactor(pk, Sha384, &kat.a1.prepared_msg, &kat.a1.salt, &kat.r, &ctx, exact_buf[0..modulus_len]);
}

test "blindSign: an out buffer one byte short of the modulus length is an error, not an assert" {
    const sk = try kat.secretKey();
    const pk = try kat.publicKey();
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x52} ** 32);
    const modulus_len = kat.a1.blind_sig.len;

    var too_small_buf: [blindrsa.max_modulus_len]u8 = undefined;
    try testing.expectError(
        error.OutputTooSmall,
        blindrsa.blindSign(sk, pk, csprng.random(), &kat.a1.blinded_msg, too_small_buf[0 .. modulus_len - 1]),
    );

    var exact_buf: [blindrsa.max_modulus_len]u8 = undefined;
    _ = try blindrsa.blindSign(sk, pk, csprng.random(), &kat.a1.blinded_msg, exact_buf[0..modulus_len]);
}

test "finalize: an out buffer one byte short of ctx.modulus_len is an error, not an assert" {
    const pk = try kat.publicKey();
    const ctx = blindrsa.Context{
        .prepared_msg = &kat.a1.prepared_msg,
        .salt_len = kat.a1.salt.len,
        .r_inv = kat.a1.inv,
        .modulus_len = kat.a1.blind_sig.len,
    };
    var too_small_buf: [blindrsa.max_modulus_len]u8 = undefined;
    try testing.expectError(
        error.OutputTooSmall,
        blindrsa.finalize(pk, Sha384, &kat.a1.blind_sig, &ctx, too_small_buf[0 .. ctx.modulus_len - 1]),
    );

    var exact_buf: [blindrsa.max_modulus_len]u8 = undefined;
    _ = try blindrsa.finalize(pk, Sha384, &kat.a1.blind_sig, &ctx, exact_buf[0..ctx.modulus_len]);
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
    const prepared_msg = try blindrsa.prepareRandomize(msg, random, &prep_buf);

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

// A rigged `std.Random` that always returns `p` (a prime factor of the RFC
// 9474 KAT modulus `n = p*q`), zero-padded to whatever width is requested —
// so every `sampleFe` draw `blind` makes (both the blinding factor `r` and
// `maskedInvert`'s internal masking scalar `u`) comes back as `p` itself:
// non-invertible mod `n` (gcd(p, n) == p), and the mask can never rescue
// it (`v = p*u mod n` still shares the factor `p` with `n`). This is the
// ONLY way to reach `blind`'s retry-exhausted `error.InvalidBlindingFactor`
// path through the PUBLIC API without inverting SHA-384 — no existing test
// exercises it (the retry-exhaustion path was previously unreachable by
// any test in this suite).
const RiggedRandom = struct {
    p: []const u8,

    fn fill(self: *const RiggedRandom, buf: []u8) void {
        @memset(buf, 0);
        if (buf.len >= self.p.len) {
            @memcpy(buf[buf.len - self.p.len ..], self.p);
        } else {
            @memcpy(buf, self.p[self.p.len - buf.len ..]);
        }
    }
};

test "blind gives up and reports InvalidBlindingFactor rather than proceed with a non-invertible r (RNG rigged to always draw a factor of n)" {
    const pk = try kat.publicKey();
    var rigged = RiggedRandom{ .p = &kat.p };
    const random = std.Random.init(&rigged, RiggedRandom.fill);

    var ctx: blindrsa.Context = undefined;
    var blinded_msg: [blindrsa.max_modulus_len]u8 = undefined;
    try testing.expectError(
        error.InvalidBlindingFactor,
        blindrsa.blind(pk, Sha384, &kat.a1.prepared_msg, &kat.a1.salt, random, &ctx, &blinded_msg),
    );
}

// ── fuzz: verify on hostile signature bytes ─────────────────────────────
//
// `verify` is the module's untrusted-input entry point: a signer (or an
// attacker impersonating one) hands back a `blind_sig`/`sig` the client
// unblinds and checks with THIS function, against the client's own fixed
// `(pk, prepared_msg, salt_len)`. It must reduce to a typed
// `rsa.VerifyPssError` for any signature bytes at all — never panic —
// including lengths that don't match the 512-byte RFC 9474 modulus.
// Biased toward "nearly valid" by corrupting a handful of bytes of the
// RFC's own real published signature rather than drawing pure random
// bytes, which the first `OS2IP`/range check would reject on almost every
// draw.
/// `testkit.fuzz` — see that module for why a corpus entry is not the frame.
const tkfuzz = @import("testkit").fuzz;
const seed = tkfuzz.seedHex;

/// Damage scripts in the format `Smith.slice` reads (see `testkit.fuzz`).
///
/// ⛔ This target is a DAMAGE harness: it does not decode a frame, it corrupts
/// RFC 9474's own published signature. The script is what has to come out of
/// the byte draw, and it is read with a `testkit.fuzz.Cursor`:
///
///     TT            truncation: 0 = the full 512 octets, else drop TT from the end
///     NN            number of flips, 0..8
///     (PPPP VV)*    per flip: position (big-endian, mod the length) and new value
///
/// The truncation octet exists because the harness's own comment promised
/// "including lengths that don't match the 512-byte RFC 9474 modulus" while
/// `bytes` was a fixed-size array — the length never varied at all.
const damage_seeds = [_][]const u8{
    seed(""), // full length, 0 flips: the PRISTINE signature — the one input the old harness ran
    seed("00" ++ "01" ++ "0000" ++ "FF"), // the most significant octet: pushes m past n
    seed("00" ++ "01" ++ "0000" ++ "00"), // the same octet cleared
    seed("00" ++ "01" ++ "01FF" ++ "AA"), // the middle of the modulus
    seed("00" ++ "01" ++ "01FF" ++ "5A"), // the same position, a different value
    seed("00" ++ "08" ++ "0000" ++ "01" ++ "0040" ++ "02" ++ "0080" ++ "03" ++
        "00C0" ++ "04" ++ "0100" ++ "05" ++ "0140" ++ "06" ++ "0180" ++ "07" ++
        "01FF" ++ "08"), // the maximum, spread across the whole signature
    seed("01"), // 511 octets: one short of the modulus, unflipped
    seed("FF"), // 257 octets: half a signature
    seed("01" ++ "01" ++ "0000" ++ "AA"), // short AND corrupted
};

test "fuzz: verify never panics on corrupted signature bytes" {
    try std.testing.fuzz({}, fuzzVerify, .{ .corpus = &damage_seeds });
}

/// Apply one damage script to a copy of the KAT signature. Returns the
/// resulting slice and the number of flips applied — shared with the guard so
/// it cannot drift onto a different subject.
fn applyDamage(script: []const u8, bytes: *[kat.a1.sig.len]u8) struct { sig: []const u8, flips: usize } {
    bytes.* = kat.a1.sig;
    var cur: tkfuzz.Cursor = .{ .bytes = script };
    const drop = cur.byte();
    const len = bytes.len - @min(@as(usize, drop), bytes.len);
    const sig = bytes[0..len];
    const n_flips = cur.ranged(0, 8);
    if (sig.len != 0) {
        var i: u32 = 0;
        while (i < n_flips) : (i += 1) {
            sig[cur.word() % sig.len] = cur.byte();
        }
    }
    return .{ .sig = sig, .flips = if (sig.len == 0) 0 else n_flips };
}

fn fuzzVerify(_: void, smith: *std.testing.Smith) !void {
    const pk = kat.publicKey() catch return;

    var script: [64]u8 = undefined;
    // ⚠ The damage script comes out of ONE `smith.slice` call, and it is the
    // FIRST draw. The flip count used to be `smith.valueRangeAtMost(u8, 0, 8)`
    // — a ranged draw, which reads eight octets as a little-endian u64 and
    // returns the range MINIMUM unless that whole word lands in the range. It
    // was therefore **0 on every replay**, so the loop never executed and this
    // harness verified RFC 9474's pristine signature, unaltered, every single
    // time. A damage harness that applied no damage; and its own comment's
    // promise about "lengths that don't match the 512-byte modulus" was never
    // kept, because `bytes` was a fixed-size array. Measured 2026-09-07 over
    // the corpus above: **0 of 9 scripts changed a byte, 1 distinct signature
    // and 1 distinct length before; 5 of 9 flip, 17 flips in total, 9 distinct
    // signatures and 3 distinct lengths after.**
    const n: usize = smith.slice(&script);
    var bytes: [kat.a1.sig.len]u8 = undefined;
    const damaged = applyDamage(script[0..n], &bytes);

    blindrsa.verify(pk, Sha384, &kat.a1.prepared_msg, damaged.sig, kat.a1.salt.len) catch return;
}

test "corpus: every damage script actually damages, and the counts are pinned" {
    // ⭐ The measurement, executable rather than written in a comment. For a
    // damage harness the number that matters is not "did it verify" but "did
    // anything change": `distinct` and `lengths` are 1 and 1 for the collapsed
    // draw, and the empty input cannot move either.
    const pk = kat.publicKey() catch unreachable;
    var flips: usize = 0;
    var distinct: usize = 0;
    var lengths: usize = 0;
    var verified: usize = 0;
    var seen: [damage_seeds.len][kat.a1.sig.len]u8 = undefined;
    var seen_len: [damage_seeds.len]usize = undefined;
    for (damage_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var script: [64]u8 = undefined;
        const n: usize = smith.slice(&script);
        var bytes: [kat.a1.sig.len]u8 = undefined;
        const damaged = applyDamage(script[0..n], &bytes);
        flips += damaged.flips;

        var already = false;
        for (seen[0..distinct], seen_len[0..distinct]) |s, l| {
            if (l == damaged.sig.len and std.mem.eql(u8, s[0..l], damaged.sig)) already = true;
        }
        if (!already) {
            seen[distinct] = bytes;
            seen_len[distinct] = damaged.sig.len;
            distinct += 1;
        }
        if (blindrsa.verify(pk, Sha384, &kat.a1.prepared_msg, damaged.sig, kat.a1.salt.len)) |_| {
            verified += 1;
        } else |_| {}
    }
    // Distinct lengths, counted separately from distinct contents.
    {
        var ls: [damage_seeds.len]usize = undefined;
        for (damage_seeds) |sd| {
            var smith: std.testing.Smith = .{ .in = sd };
            var script: [64]u8 = undefined;
            const n: usize = smith.slice(&script);
            var bytes: [kat.a1.sig.len]u8 = undefined;
            const damaged = applyDamage(script[0..n], &bytes);
            var already = false;
            for (ls[0..lengths]) |l| {
                if (l == damaged.sig.len) already = true;
            }
            if (!already) {
                ls[lengths] = damaged.sig.len;
                lengths += 1;
            }
        }
    }
    // Measured 2026-09-07: with the flip count drawn as a ranged value, 0
    // flips, 1 distinct signature and 1 distinct length across the whole
    // corpus — RFC 9474's pristine one, nine times. After:
    try testing.expectEqual(@as(usize, 17), flips);
    try testing.expectEqual(@as(usize, 9), distinct);
    try testing.expectEqual(@as(usize, 3), lengths);
    try testing.expectEqual(@as(usize, 1), verified);
}
