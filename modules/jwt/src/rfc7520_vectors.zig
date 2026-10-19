// SPDX-License-Identifier: MIT

//! RFC 7520 ("Examples of Protecting Content Using JOSE") §4.1 and §4.2 —
//! the published RS256 and PS384 signatures over one 2048-bit RSA key
//! (§3.4, Figure 4), verbatim.
//!
//! Why these: RS256 (PKCS#1 v1.5) is deterministic, so §4.1 pins our SIGNER
//! byte for byte, not only our verifier. PSS draws a salt, so §4.2 cannot pin
//! the signer; it pins the verifier against an independent PS384 signature
//! (MGF1-SHA-384, salt = 48 bytes, the RFC 7518 §3.5 choice), and the
//! signer is checked by round trip plus golang-jwt accepting our PS tokens
//! (`tools/bench.zig`, `interop`).
//!
//! Source: <https://www.rfc-editor.org/rfc/rfc7520.txt>, fetched 2026-10-13.
//! The RFC wraps these strings; they were joined by script (whitespace
//! dropped), and `n == p·q` plus both headers were checked before
//! transcription. A bad join fails verification, never silently passes.
//!
//! The payload of both examples is a line of text, not a JSON object, so
//! these are JWS rather than JWT: the tests build a `ParsedToken` by hand
//! with only the three fields `verify` reads (`alg`, `signing_input`,
//! `signature`), instead of `parse`, which requires JSON claims.

const std = @import("std");
const testing = std.testing;
const jwt = @import("root.zig");
const b64 = std.base64.url_safe_no_pad;

/// Figure 4, the public and CRT members used here.
const n_b64 = "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_" ++ "AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpP" ++ "e7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg" ++ "_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw";
const e_b64 = "AQAB";
const p_b64 = "3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nRaO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9" ++ "JR0AzZ0N2fvuIAmr_WCsmGpeNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8bUq0k";
const q_b64 = "uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15v" ++ "MMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc";

/// Figure 13 (§4.1.3), RS256.
const rs256_jws = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9.SXTigJlzIGEgZGF" ++ "uZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9" ++ "hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW9" ++ "1IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.MRjdkly7_-oTPTS3AXP41iQIGKa80A0ZmTuV5MEaHoxnW2e5CZ5NlKt" ++ "ainoFmKZopdHM1O2U4mwzJdQx996ivp83xuglII7PNDi84wnB-BDkoBwA78185hX-Es4JIwmDLJK3lfWRa-XtL0R" ++ "nltuYv746iYTh_qHRD68BNt1uSNCrUCTJDt5aAE6x8wW1Kt9eRo4QPocSadnHXFxnt8Is9UzpERV0ePPQdLuW3IS" ++ "_de3xyIrDaLGdjluPxUAhb6L2aXic1U12podGU0KLUQSE_oI-ZnmKJ3F4uOZDnd6QZWJushZ41Axf_fcIe8u9ipH" ++ "84ogoree7vjbU5y18kDquDg";

/// Figure 20 (§4.2.3), PS384.
const ps384_jws = "eyJhbGciOiJQUzM4NCIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9.SXTigJlzIGEgZGF" ++ "uZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9" ++ "hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW9" ++ "1IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.cu22eBqkYDKgIlTpzDXGvaFfz6WGoz7fUDcfT0kkOy42miAh2qyBzk1" ++ "xEsnk2IpN6-tPid6VrklHkqsGqDqHCdP6O8TTB5dDDItllVo6_1OLPpcbUrhiUSMxbbXUvdvWXzg-UD8biiReQFl" ++ "fz28zGWVsdiNAUf8ZnyPEgVFn442ZdNqiVJRmBqrYRXe8P_ijQ7p8Vdz0TTrxUeT3lm8d9shnr2lfJT8ImUjvAA2" ++ "Xez2Mlp8cBE5awDzT0qI0n6uiP1aCN_2_jLAeQTlqRHtfa64QQSUmFAAjVKPbByi7xho0uTOcbH510a6GYmJUAfm" ++ "WjwZ6oD4ifKo8DYM-X72Eaw";

const Parts = struct { signing_input: []const u8, sig: []u8 };

/// Split a compact JWS and decode its signature into `sig_buf`.
fn split(jws: []const u8, sig_buf: []u8) !Parts {
    const last = std.mem.findScalarLast(u8, jws, '.').?;
    const sig_b64 = jws[last + 1 ..];
    const len = try b64.Decoder.calcSizeForSlice(sig_b64);
    try b64.Decoder.decode(sig_buf[0..len], sig_b64);
    return .{ .signing_input = jws[0..last], .sig = sig_buf[0..len] };
}

/// A `ParsedToken` with only what `verify` reads; the rest is never touched.
fn bare(alg: jwt.Alg, signing_input: []const u8, sig: []const u8) jwt.ParsedToken {
    return .{ .header = undefined, .claims = undefined, .arena = undefined, .alg = alg, .signing_input = signing_input, .signature = sig };
}

fn decodeAlloc(gpa: std.mem.Allocator, s: []const u8) ![]u8 {
    const out = try gpa.alloc(u8, try b64.Decoder.calcSizeForSlice(s));
    try b64.Decoder.decode(out, s);
    return out;
}

fn publicKey() !jwt.Key {
    const n = try decodeAlloc(testing.allocator, n_b64);
    defer testing.allocator.free(n);
    return jwt.Key.rsaFromModExp(n, &.{ 1, 0, 1 });
}

fn keyPair(out: *jwt.rsa.KeyPair) !void {
    const gpa = testing.allocator;
    const n = try decodeAlloc(gpa, n_b64);
    defer gpa.free(n);
    const p = try decodeAlloc(gpa, p_b64);
    defer gpa.free(p);
    const q = try decodeAlloc(gpa, q_b64);
    defer gpa.free(q);
    try jwt.rsa.SecretKey.fromPrimes(&out.secret_key, p, q, &.{ 1, 0, 1 });
    out.public_key = try jwt.rsa.PublicKey.fromBytes(n, &.{ 1, 0, 1 });
}

test "RFC 7520 §4.1: the published RS256 signature verifies" {
    var sig_buf: [512]u8 = undefined;
    const parts = try split(rs256_jws, &sig_buf);
    const key = try publicKey();
    var t = bare(.RS256, parts.signing_input, parts.sig);
    try jwt.verify(&t, key);
    // The same bytes under another hash, and one flipped bit, do not.
    t.alg = .RS384;
    try testing.expectError(error.BadSignature, jwt.verify(&t, key));
    t.alg = .PS256;
    try testing.expectError(error.BadSignature, jwt.verify(&t, key));
    parts.sig[100] ^= 1;
    t.alg = .RS256;
    try testing.expectError(error.BadSignature, jwt.verify(&t, key));
}

test "RFC 7520 §4.1: our RS256 signer reproduces the published signature byte for byte" {
    var sig_buf: [512]u8 = undefined;
    const parts = try split(rs256_jws, &sig_buf);
    var kp: jwt.rsa.KeyPair = undefined;
    try keyPair(&kp);
    defer kp.secret_key.deinit();
    var out: [jwt.SigningKey.max_signature_len]u8 = undefined;
    const sig = try (jwt.SigningKey{ .rs256 = &kp }).sign(parts.signing_input, &out);
    try testing.expectEqualSlices(u8, parts.sig, sig);
}

test "RFC 7520 §4.2: the published PS384 signature verifies; nothing else does" {
    var sig_buf: [512]u8 = undefined;
    const parts = try split(ps384_jws, &sig_buf);
    const key = try publicKey();
    var t = bare(.PS384, parts.signing_input, parts.sig);
    try jwt.verify(&t, key);
    inline for (.{ jwt.Alg.PS256, jwt.Alg.PS512, jwt.Alg.RS384 }) |other| {
        t.alg = other;
        try testing.expectError(error.BadSignature, jwt.verify(&t, key));
    }
    t.alg = .PS384;
    t.signature = parts.sig[0 .. parts.sig.len - 1];
    try testing.expectError(error.BadSignature, jwt.verify(&t, key));
    parts.sig[7] ^= 0x80;
    t.signature = parts.sig;
    try testing.expectError(error.BadSignature, jwt.verify(&t, key));
}

test "PS256/384/512: our signatures verify, are randomized, and carry the RFC 7518 salt length" {
    var kp: jwt.rsa.KeyPair = undefined;
    try keyPair(&kp);
    defer kp.secret_key.deinit();
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x52)));
    const random = csprng.random();
    const key = try publicKey();
    const input = "eyJhbGciOiJQUzI1NiJ9.eyJzdWIiOiJ4In0";
    inline for (.{
        .{ "ps256", jwt.Alg.PS256, std.crypto.hash.sha2.Sha256 },
        .{ "ps384", jwt.Alg.PS384, std.crypto.hash.sha2.Sha384 },
        .{ "ps512", jwt.Alg.PS512, std.crypto.hash.sha2.Sha512 },
    }) |case| {
        const sk = @unionInit(jwt.SigningKey, case[0], .{ .key = &kp, .random = random });
        try testing.expectEqual(case[1], sk.alg());
        var a: [jwt.SigningKey.max_signature_len]u8 = undefined;
        var b: [jwt.SigningKey.max_signature_len]u8 = undefined;
        const sa = try sk.sign(input, &a);
        const sb = try sk.sign(input, &b);
        try testing.expect(!std.mem.eql(u8, sa, sb)); // fresh salt each time
        var t = bare(case[1], input, sa);
        try jwt.verify(&t, key);
        try jwt.verify(&t, sk.verificationKey());
        // A PSS signature with a salt length other than the hash length is
        // refused (RFC 7518 §3.5; golang-jwt's default would auto-detect it).
        var c: [256]u8 = undefined;
        const s0 = try jwt.rsa.signPss(&kp.secret_key, case[2], random, input, 0, &c);
        t.signature = s0;
        try testing.expectError(error.BadSignature, jwt.verify(&t, key));
        try jwt.rsa.verifyPss(kp.public_key, case[2], input, s0, 0); // ...yet it is a valid PSS signature
    }
}

test "RS256/384/512 and PS*: encode round-trips through parseAndVerify" {
    var kp: jwt.rsa.KeyPair = undefined;
    try keyPair(&kp);
    defer kp.secret_key.deinit();
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x17)));
    const keys = [_]jwt.SigningKey{
        .{ .rs256 = &kp },                                        .{ .rs384 = &kp },                                        .{ .rs512 = &kp },
        .{ .ps256 = .{ .key = &kp, .random = csprng.random() } }, .{ .ps384 = .{ .key = &kp, .random = csprng.random() } }, .{ .ps512 = .{ .key = &kp, .random = csprng.random() } },
    };
    const opts: jwt.Options = .{ .now_s = 1_790_000_000, .issuer = .{ .required = "https://issuer.test" }, .audience = .any };
    for (keys) |sk| {
        const token = try jwt.encodeJson(testing.allocator, "{\"iss\":\"https://issuer.test\",\"exp\":4102444800}", sk, .{ .kid = "bilbo" });
        defer testing.allocator.free(token);
        var parsed = try jwt.parseAndVerify(testing.allocator, token, sk.verificationKey(), opts);
        defer parsed.deinit();
        try testing.expectEqual(sk.alg(), parsed.alg);
        // An RSA token never verifies under an EC key (RFC 8725 §2.1).
        const ec = try jwt.EcdsaP256Sha256.KeyPair.generateDeterministic(@as([32]u8, @splat(7)));
        try testing.expectError(error.AlgKeyMismatch, jwt.parseAndVerify(testing.allocator, token, .{ .ecdsa_p256 = ec.public_key }, opts));
    }
}

test "RSA keys: below 2048 bits refused; a 2049-bit modulus (std's PSS assert) is a clean BadSignature" {
    const gpa = testing.allocator;
    const n = try decodeAlloc(gpa, n_b64);
    defer gpa.free(n);
    // 1024-bit odd modulus: the top half of n with its low bit set.
    var half: [128]u8 = n[0..128].*;
    half[127] |= 1;
    try testing.expectError(error.InvalidKey, jwt.Key.rsaFromModExp(&half, &.{ 1, 0, 1 }));
    // 2049 bits (k = 257, emLen = 256): std's EMSA_PSS_VERIFY asserts
    // emLen == k here; this module must just say no.
    var wide: [257]u8 = undefined;
    wide[0] = 1;
    @memcpy(wide[1..], n);
    const key = try jwt.Key.rsaFromModExp(&wide, &.{ 1, 0, 1 });
    try testing.expectEqual(@as(usize, 257), key.rsa.modulus_len);
    const sig = @as([257]u8, @splat(0x33));
    inline for (.{ jwt.Alg.PS256, jwt.Alg.PS384, jwt.Alg.PS512, jwt.Alg.RS256 }) |alg| {
        var t = bare(alg, "a.b", &sig);
        try testing.expectError(error.BadSignature, jwt.verify(&t, key));
    }
    // Signing refuses a short key too.
    var small: jwt.rsa.KeyPair = undefined;
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(9)));
    try jwt.rsa.generate(&small, csprng.random(), 1024, 65537);
    defer small.secret_key.deinit();
    var out: [jwt.SigningKey.max_signature_len]u8 = undefined;
    try testing.expectError(error.InvalidKey, (jwt.SigningKey{ .rs256 = &small }).sign("a.b", &out));
    try testing.expectError(error.InvalidKey, jwt.encodeJson(gpa, "{}", .{ .ps256 = .{ .key = &small, .random = csprng.random() } }, .{}));
}
