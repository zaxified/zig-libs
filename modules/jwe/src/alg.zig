// SPDX-License-Identifier: MIT

//! jwe.alg — RFC 7518 §4 key management algorithms: how the JWE Encrypted
//! Key segment is produced from / turned back into the per-message CEK.
//!
//! All REAL:
//!   - `dirCek`          — `dir` (§4.5): the CEK IS the shared key.
//!   - `rsaOaepWrap`/`rsaOaepUnwrap` — RSA-OAEP / RSA-OAEP-256 (§4.3), a thin
//!     wire over the `rsa` module's `encryptOaep`/`decryptOaep`.
//!   - `gcmkwWrap`/`gcmkwUnwrap` — AxxxGCMKW (§4.7), direct
//!     `std.crypto.aead.aes_gcm` (same std gap as `enc.zig`: no AES-192).
//!   - `pbes2DeriveKek`  — the PBES2 (§4.8) KDF: `std.crypto.pwhash.pbkdf2`
//!     over `Alg || 0x00 || p2s`; the KEK it produces feeds `aeskw`.
//!   - `aeskw` (re-export) — RFC 3394 AES Key Wrap: AxxxKW (§4.4) directly,
//!     every PBES2-* variant indirectly. Byte-exact against RFC 3394 §4.1;
//!     see the shared `aeskw` module (A192KW stays a typed AES-192 std gap).
//!   - `ecdhes` (re-export) — ECDH-ES key agreement (§4.6): ephemeral-static
//!     ECDH (P-256/X25519) + the Concat KDF. Direct mode derives the CEK
//!     itself; `ECDH-ES+AxxxKW` derives a KEK that feeds `aeskw`. Byte-exact
//!     against RFC 7518 Appendix C; see `ecdhes.zig`.

const std = @import("std");
const rsa = @import("rsa");
const aead = std.crypto.aead.aes_gcm;

pub const aeskw = @import("aeskw");
pub const ecdhes = @import("ecdhes.zig");

pub const Error = error{
    BufferTooSmall,
    /// A KEK/CEK length std 0.16 has no cipher for (AES-192 — see
    /// `enc.zig`'s module doc comment for the underlying std gap).
    UnsupportedKeyLength,
    /// `shared_key`'s length doesn't match what `enc` needs (`dirCek`), or
    /// a wrap/unwrap primitive rejected its key.
    InvalidKey,
    /// RSA-OAEP wrap (encrypt) failed — see `rsa.EncryptOaepError`.
    WrapFailed,
    /// RSA-OAEP unwrap (decrypt) or AES-GCM key-unwrap tag check failed.
    UnwrapFailed,
    /// `std.crypto.pwhash.pbkdf2` rejected its parameters (e.g. zero rounds).
    KdfFailed,
} || aeskw.Error || ecdhes.Error;

/// `dir` (RFC 7518 §4.5): the CEK IS `shared_key` — there is no encrypted
/// key at all (the JWE Encrypted Key segment is empty in compact form).
pub fn dirCek(shared_key: []const u8, cek_len: usize, out: []u8) Error![]u8 {
    if (shared_key.len != cek_len) return error.InvalidKey;
    if (out.len < cek_len) return error.BufferTooSmall;
    @memcpy(out[0..cek_len], shared_key[0..cek_len]);
    return out[0..cek_len];
}

/// Which hash RSA-OAEP uses — `RSA-OAEP` is SHA-1 (legacy, RFC 7518 §4.3),
/// `RSA-OAEP-256` is SHA-256 (§4.3, the modern choice — prefer it).
pub const OaepHash = enum { sha1, sha256 };

/// Wrap `cek` under an RSA public key (§4.3) — real, thin wiring over
/// `rsa.encryptOaep` with the JOSE-mandated empty label. `random` MUST be
/// cryptographically secure (OAEP's security proof requires an
/// unpredictable seed — see `rsa`'s own doc comment).
pub fn rsaOaepWrap(pk: rsa.PublicKey, hash: OaepHash, random: std.Random, cek: []const u8, out: []u8) Error![]u8 {
    return switch (hash) {
        .sha1 => rsa.encryptOaep(pk, std.crypto.hash.Sha1, random, cek, "", out) catch return error.WrapFailed,
        .sha256 => rsa.encryptOaep(pk, std.crypto.hash.sha2.Sha256, random, cek, "", out) catch return error.WrapFailed,
    };
}

/// Unwrap the JWE Encrypted Key under an RSA private key (§4.3) — real,
/// thin wiring over `rsa.decryptOaep`.
pub fn rsaOaepUnwrap(sk: rsa.SecretKey, hash: OaepHash, encrypted_key: []const u8, out: []u8) Error![]u8 {
    return switch (hash) {
        .sha1 => rsa.decryptOaep(sk, std.crypto.hash.Sha1, encrypted_key, "", out) catch return error.UnwrapFailed,
        .sha256 => rsa.decryptOaep(sk, std.crypto.hash.sha2.Sha256, encrypted_key, "", out) catch return error.UnwrapFailed,
    };
}

/// AxxxGCMKW wrap (RFC 7518 §4.7): AES-GCM-encrypt `cek` under `kek` with a
/// caller-supplied random 96-bit `iv` and no AAD (§4.7.1 — the header
/// carries `iv`/`tag` as its own params, produced/consumed by the caller of
/// this function). Real — direct `std.crypto.aead.aes_gcm`, same 16/32-byte
/// key support (no AES-192) as `enc.gcm`.
pub fn gcmkwWrap(kek: []const u8, iv: [12]u8, cek: []const u8, ct_out: []u8, tag_out: *[16]u8) Error![]u8 {
    if (ct_out.len < cek.len) return error.BufferTooSmall;
    const ct = ct_out[0..cek.len];
    switch (kek.len) {
        16 => aead.Aes128Gcm.encrypt(ct, tag_out, cek, "", iv, kek[0..16].*),
        32 => aead.Aes256Gcm.encrypt(ct, tag_out, cek, "", iv, kek[0..32].*),
        else => return error.UnsupportedKeyLength, // 24 = AES-192, no std cipher
    }
    return ct;
}

/// AxxxGCMKW unwrap — the inverse of `gcmkwWrap`.
pub fn gcmkwUnwrap(kek: []const u8, iv: [12]u8, tag: [16]u8, encrypted_key: []const u8, out: []u8) Error![]u8 {
    if (out.len < encrypted_key.len) return error.BufferTooSmall;
    const pt = out[0..encrypted_key.len];
    switch (kek.len) {
        16 => aead.Aes128Gcm.decrypt(pt, encrypted_key, tag, "", iv, kek[0..16].*) catch return error.UnwrapFailed,
        32 => aead.Aes256Gcm.decrypt(pt, encrypted_key, tag, "", iv, kek[0..32].*) catch return error.UnwrapFailed,
        else => return error.UnsupportedKeyLength,
    }
    return pt;
}

/// Which AxxxKW the PBES2 KEK feeds — fixes the derived-key length and the
/// PRF (RFC 7518 §4.8.1: HS256↔A128KW, HS384↔A192KW, HS512↔A256KW; the hash
/// and the wrapped key's bit-size always match).
pub const Pbes2Variant = enum {
    hs256_a128kw,
    hs384_a192kw,
    hs512_a256kw,

    pub fn jwaName(self: Pbes2Variant) []const u8 {
        return switch (self) {
            .hs256_a128kw => "PBES2-HS256+A128KW",
            .hs384_a192kw => "PBES2-HS384+A192KW",
            .hs512_a256kw => "PBES2-HS512+A256KW",
        };
    }

    pub fn kekLen(self: Pbes2Variant) usize {
        return switch (self) {
            .hs256_a128kw => 16,
            .hs384_a192kw => 24,
            .hs512_a256kw => 32,
        };
    }
};

/// Largest `Alg || 0x00 || p2s` salt value this module builds (bounds a
/// stack buffer — the alg name is <= 19 bytes; `p2s` itself is capped by the
/// caller, conventionally 8-64 bytes).
pub const max_pbes2_salt_value_len: usize = 128;

/// RFC 7518 §4.8.1.1 PBES2 key derivation: PBKDF2 over `password` with salt
/// value `UTF8(alg name) || 0x00 || salt_input`, `iterations` rounds, PRF =
/// HMAC-SHA-2 matching `variant`, output length = `variant.kekLen()`. A
/// direct `std.crypto.pwhash.pbkdf2` call; the resulting KEK then feeds
/// `aeskw.wrap`/`unwrap` (RFC 3394).
pub fn pbes2DeriveKek(
    variant: Pbes2Variant,
    password: []const u8,
    salt_input: []const u8,
    iterations: u32,
    out: []u8,
) Error![]u8 {
    const kek_len = variant.kekLen();
    if (out.len < kek_len) return error.BufferTooSmall;

    const alg_name = variant.jwaName();
    var salt_buf: [max_pbes2_salt_value_len]u8 = undefined;
    const salt_value_len = alg_name.len + 1 + salt_input.len;
    if (salt_value_len > salt_buf.len) return error.BufferTooSmall;
    @memcpy(salt_buf[0..alg_name.len], alg_name);
    salt_buf[alg_name.len] = 0x00;
    @memcpy(salt_buf[alg_name.len + 1 ..][0..salt_input.len], salt_input);
    const salt_value = salt_buf[0..salt_value_len];

    const kek = out[0..kek_len];
    switch (variant) {
        .hs256_a128kw => std.crypto.pwhash.pbkdf2(kek, password, salt_value, iterations, std.crypto.auth.hmac.sha2.HmacSha256) catch return error.KdfFailed,
        .hs384_a192kw => std.crypto.pwhash.pbkdf2(kek, password, salt_value, iterations, std.crypto.auth.hmac.sha2.HmacSha384) catch return error.KdfFailed,
        .hs512_a256kw => std.crypto.pwhash.pbkdf2(kek, password, salt_value, iterations, std.crypto.auth.hmac.sha2.HmacSha512) catch return error.KdfFailed,
    }
    return kek;
}

test "dirCek: CEK is literally the shared key" {
    const shared = [_]u8{0xab} ** 32;
    var out: [32]u8 = undefined;
    const cek = try dirCek(&shared, 32, &out);
    try std.testing.expectEqualSlices(u8, &shared, cek);
}

test "dirCek: wrong shared-key length is rejected, not silently truncated" {
    const shared = [_]u8{0xab} ** 16;
    var out: [32]u8 = undefined;
    try std.testing.expectError(error.InvalidKey, dirCek(&shared, 32, &out));
}

test "RSA-OAEP-256 wrap/unwrap real round-trip (RFC 7516 A.1's 2048-bit key, SHA-256 variant)" {
    // Reuses the RFC 7516 Appendix A.1 RSA key (n/e/p/q) — see
    // kat_rfc7516.zig for the byte-exact SHA-1 (`RSA-OAEP`) decrypt-only KAT
    // using the same key; this test exercises the SHA-256 (`RSA-OAEP-256`)
    // variant end-to-end (wrap then unwrap), which is necessarily
    // self-consistency rather than a published KAT (OAEP is randomized).
    const n_b64 = "oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUWcJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3Spsk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2asbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMStPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2djYgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw";
    const p_b64 = "1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lffNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0";
    const q_b64 = "wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBmUDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aXIWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc";

    const dec = std.base64.url_safe_no_pad.Decoder;
    var n_buf: [300]u8 = undefined;
    var p_buf: [150]u8 = undefined;
    var q_buf: [150]u8 = undefined;
    const n = n_buf[0..try dec.calcSizeForSlice(n_b64)];
    try dec.decode(n, n_b64);
    const p = p_buf[0..try dec.calcSizeForSlice(p_b64)];
    try dec.decode(p, p_b64);
    const q = q_buf[0..try dec.calcSizeForSlice(q_b64)];
    try dec.decode(q, q_b64);
    const e = [_]u8{ 0x01, 0x00, 0x01 };

    const pk = try rsa.PublicKey.fromBytes(n, &e);
    const sk = try rsa.SecretKey.fromPrimes(p, q, &e);

    const cek = [_]u8{0x77} ** 32;
    var wrapped: [256]u8 = undefined;
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x11} ** 32);
    const ek = try rsaOaepWrap(pk, .sha256, csprng.random(), &cek, &wrapped);

    var recovered: [256]u8 = undefined;
    const got = try rsaOaepUnwrap(sk, .sha256, ek, &recovered);
    try std.testing.expectEqualSlices(u8, &cek, got);
}

test "GCMKW real round-trip" {
    const kek = [_]u8{0x55} ** 32;
    const cek = [_]u8{0x99} ** 32; // pretend A256GCM CEK
    var iv: [12]u8 = undefined;
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x22} ** 32);
    csprng.random().bytes(&iv);
    var ct: [32]u8 = undefined;
    var tag: [16]u8 = undefined;
    _ = try gcmkwWrap(&kek, iv, &cek, &ct, &tag);

    var recovered: [32]u8 = undefined;
    const got = try gcmkwUnwrap(&kek, iv, tag, &ct, &recovered);
    try std.testing.expectEqualSlices(u8, &cek, got);
}

test "GCMKW A192 (24-byte KEK) is a documented std gap" {
    const kek = [_]u8{0x55} ** 24;
    const cek = [_]u8{0x99} ** 32;
    var ct: [32]u8 = undefined;
    var tag: [16]u8 = undefined;
    try std.testing.expectError(error.UnsupportedKeyLength, gcmkwWrap(&kek, [_]u8{0} ** 12, &cek, &ct, &tag));
}

test "PBES2 KDF wiring is real: deterministic, salt/iteration/password sensitive, correct output length" {
    var out1: [16]u8 = undefined;
    var out2: [16]u8 = undefined;
    const salt = "a-fixed-salt-in";
    _ = try pbes2DeriveKek(.hs256_a128kw, "correct horse battery staple", salt, 1000, &out1);
    _ = try pbes2DeriveKek(.hs256_a128kw, "correct horse battery staple", salt, 1000, &out2);
    try std.testing.expectEqualSlices(u8, &out1, &out2); // deterministic

    var out3: [16]u8 = undefined;
    _ = try pbes2DeriveKek(.hs256_a128kw, "different password", salt, 1000, &out3);
    try std.testing.expect(!std.mem.eql(u8, &out1, &out3));

    var out4: [16]u8 = undefined;
    _ = try pbes2DeriveKek(.hs256_a128kw, "correct horse battery staple", salt, 1001, &out4);
    try std.testing.expect(!std.mem.eql(u8, &out1, &out4));

    // HS384 -> 24-byte KEK, HS512 -> 32-byte KEK (RFC 7518 §4.8.1).
    var out384: [24]u8 = undefined;
    const kek384 = try pbes2DeriveKek(.hs384_a192kw, "pw", salt, 1000, &out384);
    try std.testing.expectEqual(@as(usize, 24), kek384.len);
    var out512: [32]u8 = undefined;
    const kek512 = try pbes2DeriveKek(.hs512_a256kw, "pw", salt, 1000, &out512);
    try std.testing.expectEqual(@as(usize, 32), kek512.len);
}

test "aeskw (A128KW/A256KW core) re-export is live — RFC 3394 §4.1 through alg.aeskw" {
    // The byte-exact KATs live in aeskw.zig (RFC 3394 §4.1) and
    // kat_rfc7516.zig (RFC 7516 A.3); this exercises the same core through
    // this file's re-export, i.e. the path AxxxKW/PBES2-* dispatch takes.
    const kek = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const key_data = [_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    var wrapped: [24]u8 = undefined;
    const ct = try aeskw.wrap(&kek, &key_data, &wrapped);
    try std.testing.expectEqual(@as(u8, 0x1f), ct[0]); // RFC 3394 §4.1 first byte
    var back: [16]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &key_data, try aeskw.unwrap(&kek, ct, &back));
}
