// SPDX-License-Identifier: MIT
//! sealedbox — NaCl `crypto_box_seal`: anonymous-sender public-key encryption.
//!
//! Encrypt to a recipient's X25519 public key with **no sender key**: a fresh
//! ephemeral keypair is generated per message, so the recipient cannot identify
//! the sender. This is a thin, faithful wrapper over `std.crypto.nacl.SealedBox`
//! — we do NOT roll our own crypto; the nonce derivation and AEAD are std's.
//! (X25519 keys are Curve25519, so a WireGuard pubkey doubles as a recipient key.)
//!
//! Key text serialization: base64 (`std.base64.standard`, RFC 4648 `A–Za–z0–9+/`
//! with `=` padding) and lowercase hex codecs for the 32-byte public and secret
//! keys, so keys can live in config files and wire protocols. Parsing is strict
//! (exact length, no whitespace) and returns typed errors — never panics.
//!
//! Provenance: extracted from the authors' axp project — `axp-core/src/sealed.zig`
//! (the enrollment sealed-box wrapper); Apache-2.0, relicensed MIT by the
//! copyright holder. Model after libsodium `crypto_box_seal` / Go `nacl/box`.
//! No third-party source copied — the construction is the public NaCl standard.

const std = @import("std");

pub const meta = .{
    .status = .extract,
    .platform = .any,
    .role = .util,
    .concurrency = .reentrant,
    .model_after = "libsodium crypto_box_seal / Go nacl/box",
    .deps = .{},
};

pub const SealedBox = std.crypto.nacl.SealedBox;
pub const KeyPair = SealedBox.KeyPair;

/// Recipient public-key length (32, Curve25519).
pub const public_length = SealedBox.public_length;
/// Secret-key (X25519 scalar) length (32).
pub const secret_length = SealedBox.secret_length;
/// Bytes a sealed message adds over the plaintext (ephemeral pubkey + Poly1305 tag = 48).
pub const overhead = SealedBox.seal_length;

/// Ciphertext length for a plaintext of `plaintext_len` bytes.
pub fn sealedLen(plaintext_len: usize) usize {
    return plaintext_len + overhead;
}

// ── buffer API (no allocation; matches the axp seed) ──────────────────────────

/// Seal `msg` to `recipient_pk`. `out` must be exactly `msg.len + overhead` bytes.
/// `io` supplies entropy for the per-message ephemeral keypair. (Seed: axp sealed.zig.)
pub fn seal(io: std.Io, out: []u8, msg: []const u8, recipient_pk: [public_length]u8) !void {
    std.debug.assert(out.len == msg.len + overhead);
    try SealedBox.seal(io, out, msg, recipient_pk);
}

/// Open a sealed message with the recipient keypair. `out` must be exactly
/// `sealed.len - overhead` bytes. Returns an error (never panics) on a too-short
/// or tampered ciphertext. (Seed: axp sealed.zig.)
pub fn open(out: []u8, sealed: []const u8, kp: KeyPair) !void {
    if (sealed.len < overhead or sealed.len != out.len + overhead)
        return error.InvalidCiphertext;
    try SealedBox.open(out, sealed, kp);
}

// ── allocating convenience ────────────────────────────────────────────────────

/// Seal `msg`, returning a freshly allocated ciphertext (`msg.len + overhead`).
pub fn sealAlloc(gpa: std.mem.Allocator, io: std.Io, msg: []const u8, recipient_pk: [public_length]u8) ![]u8 {
    const out = try gpa.alloc(u8, sealedLen(msg.len));
    errdefer gpa.free(out);
    try seal(io, out, msg, recipient_pk);
    return out;
}

/// Open a sealed message, returning the freshly allocated plaintext.
/// Errors (never panics) on a too-short/tampered ciphertext.
pub fn openAlloc(gpa: std.mem.Allocator, sealed: []const u8, kp: KeyPair) ![]u8 {
    if (sealed.len < overhead) return error.InvalidCiphertext;
    const out = try gpa.alloc(u8, sealed.len - overhead);
    errdefer gpa.free(out);
    try open(out, sealed, kp);
    return out;
}

// ── key text serialization (base64 / hex) ─────────────────────────────────────
//
// Base64 is `std.base64.standard`: the RFC 4648 standard alphabet (`A–Z a–z 0–9
// + /`) WITH `=` padding — a 32-byte key is always exactly 44 chars ending in
// one `=`. Hex is lowercase on encode; parsing accepts upper- and lowercase.
// Parsers are strict: exact length required, no whitespace or other embedded
// characters tolerated. Malformed input yields `error.InvalidLength` (wrong
// text length) or `error.InvalidKeyEncoding` (bad characters / bad padding) —
// never a panic. All codecs are allocation-free (fixed-size arrays).

/// Base64 text length of an encoded 32-byte key (44, includes the `=` pad).
pub const base64_pk_len = std.base64.standard.Encoder.calcSize(public_length);
/// Hex text length of an encoded 32-byte public key (64).
pub const hex_pk_len = public_length * 2;
/// Base64 text length of an encoded secret key (same as `base64_pk_len`).
pub const base64_sk_len = std.base64.standard.Encoder.calcSize(secret_length);
/// Hex text length of an encoded secret key (same as `hex_pk_len`).
pub const hex_sk_len = secret_length * 2;

/// Errors returned by the key text parsers. Typed — malformed text never panics.
pub const KeyEncodingError = error{ InvalidLength, InvalidKeyEncoding };

/// Encode a recipient public key as standard base64 (44 chars, `=`-padded).
pub fn encodePublicKeyBase64(pk: [public_length]u8) [base64_pk_len]u8 {
    return encodeKeyBase64(pk);
}

/// Parse a base64-encoded public key. Strict: exactly 44 chars, standard
/// alphabet, correct `=` padding, no whitespace.
pub fn parsePublicKeyBase64(text: []const u8) KeyEncodingError![public_length]u8 {
    return parseKeyBase64(text);
}

/// Encode a recipient public key as lowercase hex (64 chars).
pub fn encodePublicKeyHex(pk: [public_length]u8) [hex_pk_len]u8 {
    return std.fmt.bytesToHex(pk, .lower);
}

/// Parse a hex-encoded public key. Strict: exactly 64 hex digits (either case),
/// no whitespace.
pub fn parsePublicKeyHex(text: []const u8) KeyEncodingError![public_length]u8 {
    return parseKeyHex(text);
}

/// Encode a secret key as standard base64 (44 chars). **SECRET material** —
/// the output grants full decryption capability; store/transmit accordingly.
pub fn encodeSecretKeyBase64(sk: [secret_length]u8) [base64_sk_len]u8 {
    return encodeKeyBase64(sk);
}

/// Parse a base64-encoded secret key (**SECRET material**). Same strict rules
/// as `parsePublicKeyBase64`. Returns the raw X25519 scalar; rebuild a usable
/// keypair with `keyPairFromSecretKey`.
pub fn parseSecretKeyBase64(text: []const u8) KeyEncodingError![secret_length]u8 {
    return parseKeyBase64(text);
}

/// Encode a secret key as lowercase hex (64 chars). **SECRET material.**
pub fn encodeSecretKeyHex(sk: [secret_length]u8) [hex_sk_len]u8 {
    return std.fmt.bytesToHex(sk, .lower);
}

/// Parse a hex-encoded secret key (**SECRET material**). Same strict rules as
/// `parsePublicKeyHex`.
pub fn parseSecretKeyHex(text: []const u8) KeyEncodingError![secret_length]u8 {
    return parseKeyHex(text);
}

/// Recompute the public key from a stored secret key (X25519 base-point
/// multiplication via std). The secret scalar alone fully round-trips a keypair.
/// `error.IdentityElement` only for pathological all-weak scalars.
pub fn publicFromSecret(sk: [secret_length]u8) error{IdentityElement}![public_length]u8 {
    return std.crypto.dh.X25519.recoverPublicKey(sk);
}

/// Rebuild a usable `KeyPair` from a stored secret key (public key is
/// recomputed — std's X25519 `KeyPair` treats the secret scalar as the seed).
pub fn keyPairFromSecretKey(sk: [secret_length]u8) error{IdentityElement}!KeyPair {
    return .{ .public_key = try publicFromSecret(sk), .secret_key = sk };
}

fn encodeKeyBase64(key: [32]u8) [base64_pk_len]u8 {
    var out: [base64_pk_len]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&out, &key);
    return out;
}

fn parseKeyBase64(text: []const u8) KeyEncodingError![32]u8 {
    if (text.len != base64_pk_len) return error.InvalidLength;
    // Right length but wrong padding shape (e.g. trailing "==") would decode to
    // fewer than 32 bytes — reject before decoding into the fixed-size output.
    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(text) catch
        return error.InvalidKeyEncoding;
    if (decoded_len != 32) return error.InvalidKeyEncoding;
    var out: [32]u8 = undefined;
    std.base64.standard.Decoder.decode(&out, text) catch return error.InvalidKeyEncoding;
    return out;
}

fn parseKeyHex(text: []const u8) KeyEncodingError![32]u8 {
    if (text.len != hex_pk_len) return error.InvalidLength;
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch return error.InvalidKeyEncoding;
    return out;
}

// ── tests ────────────────────────────────────────────────────────────────────

test "round-trip: buffer API, various sizes including empty" {
    const io = std.testing.io;
    const kp = KeyPair.generate(io);

    const msgs = [_][]const u8{ "", "x", "hello sealed box", "a" ** 100 };
    inline for (msgs) |msg| {
        var boxed: [msg.len + overhead]u8 = undefined;
        try seal(io, &boxed, msg, kp.public_key);
        try std.testing.expectEqual(sealedLen(msg.len), boxed.len);

        var opened: [msg.len]u8 = undefined;
        try open(&opened, &boxed, kp);
        try std.testing.expectEqualSlices(u8, msg, &opened);
    }
}

test "round-trip: sealAlloc/openAlloc" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    const kp = KeyPair.generate(io);

    const msgs = [_][]const u8{ "", "allocating convenience round-trip" };
    for (msgs) |msg| {
        const boxed = try sealAlloc(gpa, io, msg, kp.public_key);
        defer gpa.free(boxed);
        try std.testing.expectEqual(sealedLen(msg.len), boxed.len);
        try std.testing.expectEqual(msg.len + overhead, boxed.len);

        const opened = try openAlloc(gpa, boxed, kp);
        defer gpa.free(opened);
        try std.testing.expectEqualSlices(u8, msg, opened);
    }
}

test "tamper: flipped byte in box or ephemeral pk fails authentication" {
    const io = std.testing.io;
    const kp = KeyPair.generate(io);
    const msg = "tamper me";

    var boxed: [msg.len + overhead]u8 = undefined;
    try seal(io, &boxed, msg, kp.public_key);
    var opened: [msg.len]u8 = undefined;

    // flip a byte in the box portion (past the ephemeral pk prefix)
    var t1 = boxed;
    t1[t1.len - 1] ^= 0x01;
    try std.testing.expectError(error.AuthenticationFailed, open(&opened, &t1, kp));

    // flip a byte in the ephemeral pk prefix
    var t2 = boxed;
    t2[0] ^= 0x01;
    try std.testing.expectError(error.AuthenticationFailed, open(&opened, &t2, kp));
}

test "wrong recipient keypair fails authentication" {
    const io = std.testing.io;
    const kp = KeyPair.generate(io);
    const wrong_kp = KeyPair.generate(io);
    const msg = "for someone else";

    var boxed: [msg.len + overhead]u8 = undefined;
    try seal(io, &boxed, msg, kp.public_key);
    var opened: [msg.len]u8 = undefined;
    try std.testing.expectError(error.AuthenticationFailed, open(&opened, &boxed, wrong_kp));
}

test "too-short/garbage ciphertext: clean error, no panic" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    const kp = KeyPair.generate(io);

    var opened: [4]u8 = undefined;

    // shorter than the overhead
    const short = [_]u8{0xaa} ** (overhead - 1);
    try std.testing.expectError(error.InvalidCiphertext, open(&opened, &short, kp));
    try std.testing.expectError(error.InvalidCiphertext, openAlloc(gpa, &short, kp));

    // empty ciphertext
    try std.testing.expectError(error.InvalidCiphertext, open(&opened, "", kp));
    try std.testing.expectError(error.InvalidCiphertext, openAlloc(gpa, "", kp));

    // long enough but out-length mismatch
    const mismatched = [_]u8{0xbb} ** (overhead + 10);
    try std.testing.expectError(error.InvalidCiphertext, open(&opened, &mismatched, kp));

    // well-sized garbage: must fail authentication, never panic
    var garbage: [4 + overhead]u8 = undefined;
    io.random(&garbage);
    try std.testing.expectError(error.AuthenticationFailed, open(&opened, &garbage, kp));
}

test "KAT: public key base64 + hex, exact strings and decode-back" {
    const pk: [public_length]u8 = blk: {
        var k: [public_length]u8 = undefined;
        for (&k, 0..) |*b, i| b.* = @intCast(i);
        break :blk k; // 00 01 02 … 1f
    };

    const b64 = encodePublicKeyBase64(pk);
    try std.testing.expectEqual(base64_pk_len, b64.len);
    try std.testing.expectEqualStrings("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", &b64);
    try std.testing.expectEqual(pk, try parsePublicKeyBase64(&b64));

    const hex = encodePublicKeyHex(pk);
    try std.testing.expectEqual(hex_pk_len, hex.len);
    try std.testing.expectEqualStrings(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        &hex,
    );
    try std.testing.expectEqual(pk, try parsePublicKeyHex(&hex));
    // hex parsing accepts uppercase too
    try std.testing.expectEqual(pk, try parsePublicKeyHex(
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
    ));
}

test "KAT: secret key (RFC 7748 Alice) base64 + hex + public recompute" {
    // RFC 7748 §6.1 Alice's secret and public key.
    const sk_hex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    const pk_hex = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    const sk = try parseSecretKeyHex(sk_hex);

    const b64 = encodeSecretKeyBase64(sk);
    try std.testing.expectEqualStrings("dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=", &b64);
    try std.testing.expectEqual(sk, try parseSecretKeyBase64(&b64));

    const hex = encodeSecretKeyHex(sk);
    try std.testing.expectEqualStrings(sk_hex, &hex);
    try std.testing.expectEqual(sk, try parseSecretKeyHex(&hex));

    // secret → public rebuild matches the RFC vector
    const pk = try publicFromSecret(sk);
    try std.testing.expectEqualStrings(pk_hex, &encodePublicKeyHex(pk));
    const kp = try keyPairFromSecretKey(sk);
    try std.testing.expectEqual(pk, kp.public_key);
    try std.testing.expectEqual(sk, kp.secret_key);
}

test "round-trip: generated keys survive text serialization; rebuilt keypair opens" {
    const io = std.testing.io;
    const kp = KeyPair.generate(io);

    // public key: base64 + hex round-trip
    try std.testing.expectEqual(kp.public_key, try parsePublicKeyBase64(&encodePublicKeyBase64(kp.public_key)));
    try std.testing.expectEqual(kp.public_key, try parsePublicKeyHex(&encodePublicKeyHex(kp.public_key)));

    // secret key: base64 + hex round-trip
    try std.testing.expectEqual(kp.secret_key, try parseSecretKeyBase64(&encodeSecretKeyBase64(kp.secret_key)));
    try std.testing.expectEqual(kp.secret_key, try parseSecretKeyHex(&encodeSecretKeyHex(kp.secret_key)));

    // end-to-end: serialize both keys → parse back → seal to parsed public key
    // → open with a keypair rebuilt from the stored secret
    const pk_stored = encodePublicKeyBase64(kp.public_key);
    const sk_stored = encodeSecretKeyHex(kp.secret_key);
    const pk_back = try parsePublicKeyBase64(&pk_stored);
    const kp_back = try keyPairFromSecretKey(try parseSecretKeyHex(&sk_stored));
    try std.testing.expectEqual(kp.public_key, kp_back.public_key);

    const msg = "keys came from a config file";
    var boxed: [msg.len + overhead]u8 = undefined;
    try seal(io, &boxed, msg, pk_back);
    var opened: [msg.len]u8 = undefined;
    try open(&opened, &boxed, kp_back);
    try std.testing.expectEqualSlices(u8, msg, &opened);
}

test "malformed key text: typed errors, no panic" {
    const good_b64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    const good_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    // base64: wrong length (short, long, empty)
    try std.testing.expectError(error.InvalidLength, parsePublicKeyBase64(good_b64[0 .. good_b64.len - 1]));
    try std.testing.expectError(error.InvalidLength, parsePublicKeyBase64(good_b64 ++ "A"));
    try std.testing.expectError(error.InvalidLength, parsePublicKeyBase64(""));
    // base64: non-alphabet chars at right length
    try std.testing.expectError(error.InvalidKeyEncoding, parsePublicKeyBase64("!" ++ good_b64[1..]));
    try std.testing.expectError(error.InvalidKeyEncoding, parsePublicKeyBase64("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh?="));
    // base64: embedded whitespace is rejected (strict policy)
    try std.testing.expectError(error.InvalidKeyEncoding, parsePublicKeyBase64(" " ++ good_b64[1..]));
    // base64: wrong padding shape (44 chars but decodes to 31 or 33 bytes)
    try std.testing.expectError(error.InvalidKeyEncoding, parsePublicKeyBase64(good_b64[0..42] ++ "=="));
    try std.testing.expectError(error.InvalidKeyEncoding, parsePublicKeyBase64(good_b64[0..43] ++ "A"));

    // hex: odd length, wrong length, empty
    try std.testing.expectError(error.InvalidLength, parsePublicKeyHex(good_hex[0..63]));
    try std.testing.expectError(error.InvalidLength, parsePublicKeyHex(good_hex[0..62]));
    try std.testing.expectError(error.InvalidLength, parsePublicKeyHex(good_hex ++ "00"));
    try std.testing.expectError(error.InvalidLength, parsePublicKeyHex(""));
    // hex: non-hex chars / whitespace at right length
    try std.testing.expectError(error.InvalidKeyEncoding, parsePublicKeyHex("zz" ++ good_hex[2..]));
    try std.testing.expectError(error.InvalidKeyEncoding, parsePublicKeyHex(" " ++ good_hex[1..]));

    // secret parsers share the code path — spot-check both error kinds
    try std.testing.expectError(error.InvalidLength, parseSecretKeyBase64("short"));
    try std.testing.expectError(error.InvalidKeyEncoding, parseSecretKeyBase64("*" ++ good_b64[1..]));
    try std.testing.expectError(error.InvalidLength, parseSecretKeyHex("abc"));
    try std.testing.expectError(error.InvalidKeyEncoding, parseSecretKeyHex("g" ++ good_hex[1..]));
}
