// SPDX-License-Identifier: MIT

//! jwe.enc — RFC 7518 §5 content-encryption algorithms: the "enc" header
//! parameter's algorithm family, i.e. what actually protects the plaintext
//! (as opposed to `alg.zig`, which protects the CEK).
//!
//! REAL: `A128GCM`/`A256GCM` — direct `std.crypto.aead.aes_gcm` calls.
//! `A192GCM` is a **std gap, not a stub**: Zig 0.16's `std.crypto.aead.aes_gcm`
//! ships only `Aes128Gcm`/`Aes256Gcm` (no `Aes192Gcm`, because
//! `std.crypto.core.aes` itself has no AES-192 block cipher) — there is no
//! std primitive to call, so this returns `error.UnsupportedKeyLength`
//! rather than a `TODO(fable)` stub. Fixing it needs an AES-192 core to
//! exist first (upstream std, or a new from-scratch primitive), which is a
//! different kind of work than reviewing an already-written careful core.
//!
//! REAL (see the `cbc_hmac` namespace): `A128CBC-HS256`/`A256CBC-HS512`
//! (RFC 7518 §5.2) — AES-CBC (raw block-chaining + PKCS#7 padding from the
//! shared `aescbc` module) + HMAC-SHA-2 "encrypt-then-MAC" with the §5.2.2
//! key split, AAD-bit-length encoding, and verify-before-decrypt ordering;
//! byte-exact against RFC 7518 Appendix B. `A192CBC-HS384` hits the same
//! AES-192 std gap as `A192GCM` (its HMAC-SHA-384 half is validated against
//! the B.2 vector below; its CBC half has no std cipher to call).

const std = @import("std");
const aead = std.crypto.aead.aes_gcm;
const aescbc = @import("aescbc");

const root = @import("root.zig");
const Enc = root.Enc;

pub const Error = error{
    BufferTooSmall,
    /// `enc` needs a key length std 0.16 has no cipher for (AES-192; see
    /// module doc comment), or `enc` is `.unknown`.
    UnsupportedKeyLength,
    /// GCM tag or CBC-HMAC tag did not verify — or, equivalently for
    /// CBC-HMAC, the PKCS#7 padding was invalid (deliberately the SAME error,
    /// so a padding failure is indistinguishable from a tag failure — no
    /// padding oracle). Callers must not act on `plaintext` when this is
    /// returned (GCM decrypt clears its output buffer on tag mismatch,
    /// matching `std.crypto.aead`'s own contract; CBC-HMAC rejects a bad tag
    /// BEFORE decrypting anything).
    AuthenticationFailed,
};

/// Largest CEK this module handles (`A256CBC-HS512`'s 64-byte MAC_KEY‖ENC_KEY).
pub const max_cek_len: usize = 64;
/// Largest IV (`AxxxCBC-HSxxx`'s 16-byte block-aligned IV).
pub const max_iv_len: usize = 16;
/// Largest Authentication Tag (`A256CBC-HS512`'s 32-byte truncated HMAC).
pub const max_tag_len: usize = 32;

/// Encrypt `plaintext` under `enc` (dispatches to `gcm` or `cbc_hmac`).
/// `ciphertext_out` must be at least `plaintext.len` (GCM: an exact match;
/// CBC-HMAC: up to one block of PKCS#7 padding larger — size for
/// `plaintext.len + 16` if you need to support both). Returns the written
/// ciphertext length.
pub fn encrypt(
    enc: Enc,
    cek: []const u8,
    iv: []const u8,
    aad: []const u8,
    plaintext: []const u8,
    ciphertext_out: []u8,
    tag_out: []u8,
) Error!usize {
    if (enc.isGcm()) return gcm.encrypt(enc, cek, iv, aad, plaintext, ciphertext_out, tag_out);
    return cbc_hmac.encrypt(enc, cek, iv, aad, plaintext, ciphertext_out, tag_out);
}

/// Decrypt + verify. Returns the written plaintext length.
pub fn decrypt(
    enc: Enc,
    cek: []const u8,
    iv: []const u8,
    aad: []const u8,
    ciphertext: []const u8,
    tag: []const u8,
    plaintext_out: []u8,
) Error!usize {
    if (enc.isGcm()) return gcm.decrypt(enc, cek, iv, aad, ciphertext, tag, plaintext_out);
    return cbc_hmac.decrypt(enc, cek, iv, aad, ciphertext, tag, plaintext_out);
}

/// `A128GCM`/`A192GCM`/`A256GCM` (RFC 7518 §5.3) — direct
/// `std.crypto.aead.aes_gcm`. Real, not a stub.
pub const gcm = struct {
    pub fn encrypt(
        enc: Enc,
        key: []const u8,
        iv: []const u8,
        aad: []const u8,
        plaintext: []const u8,
        ciphertext_out: []u8,
        tag_out: []u8,
    ) Error!usize {
        if (ciphertext_out.len < plaintext.len or tag_out.len < 16 or iv.len != 12) return error.BufferTooSmall;
        const ct = ciphertext_out[0..plaintext.len];
        const tag = tag_out[0..16];
        switch (enc) {
            .A128GCM => {
                if (key.len != 16) return error.BufferTooSmall;
                aead.Aes128Gcm.encrypt(ct, tag, plaintext, aad, iv[0..12].*, key[0..16].*);
            },
            .A256GCM => {
                if (key.len != 32) return error.BufferTooSmall;
                aead.Aes256Gcm.encrypt(ct, tag, plaintext, aad, iv[0..12].*, key[0..32].*);
            },
            .A192GCM => return error.UnsupportedKeyLength, // std gap, see module doc comment
            else => return error.UnsupportedKeyLength,
        }
        return plaintext.len;
    }

    pub fn decrypt(
        enc: Enc,
        key: []const u8,
        iv: []const u8,
        aad: []const u8,
        ciphertext: []const u8,
        tag: []const u8,
        plaintext_out: []u8,
    ) Error!usize {
        if (plaintext_out.len < ciphertext.len or tag.len != 16 or iv.len != 12) return error.BufferTooSmall;
        const pt = plaintext_out[0..ciphertext.len];
        const tag_arr = tag[0..16].*;
        switch (enc) {
            .A128GCM => {
                if (key.len != 16) return error.BufferTooSmall;
                aead.Aes128Gcm.decrypt(pt, ciphertext, tag_arr, aad, iv[0..12].*, key[0..16].*) catch return error.AuthenticationFailed;
            },
            .A256GCM => {
                if (key.len != 32) return error.BufferTooSmall;
                aead.Aes256Gcm.decrypt(pt, ciphertext, tag_arr, aad, iv[0..12].*, key[0..32].*) catch return error.AuthenticationFailed;
            },
            .A192GCM => return error.UnsupportedKeyLength,
            else => return error.UnsupportedKeyLength,
        }
        return ciphertext.len;
    }
};

/// `A128CBC-HS256`/`A256CBC-HS512` (RFC 7518 §5.2) — AES-CBC (PKCS#7) +
/// HMAC-SHA-2, encrypt-then-MAC. `A192CBC-HS384` is the same std AES-192 gap
/// as `A192GCM` (see module doc comment): the HMAC-SHA-384 half is
/// std-reachable (validated against the B.2 vector in a test below), but
/// there is no AES-192 block cipher to build its CBC half from —
/// `error.UnsupportedKeyLength`, never silently wrong.
///
/// The construction (§5.2.2.1), with the classic footguns handled:
///
///   - **key split**: CEK = MAC_KEY ‖ ENC_KEY, MAC_KEY = the FIRST half,
///     ENC_KEY = the SECOND half (§5.2.1 steps 1-2; 16+16 / 32+32 bytes).
///   - **AAD length encoding (`AL`)**: the number of **bits** in the AAD as
///     an unsigned 64-bit **big-endian** integer (§5.1 step 5, §5.2.2.1
///     step 4) — bits, not bytes.
///   - **MAC input order**: `HMAC(MAC_KEY, AAD ‖ IV ‖ ciphertext ‖ AL)` —
///     AAD and IV come *before* the ciphertext.
///   - **tag truncation**: the Authentication Tag is the **left-most**
///     `T_LEN` octets of the raw HMAC output (`T_LEN` = 16/32 for
///     HS256/HS512 — half the underlying hash's output).
///   - **verify-before-decrypt, constant-time**: `decrypt` recomputes the
///     tag over the *received* ciphertext and compares via
///     `std.crypto.timing_safe.eql` BEFORE running any CBC decryption
///     (Vaudenay's CBC padding-oracle family is what verify-after-decrypt
///     reopens). A subsequent PKCS#7 padding failure surfaces as the SAME
///     `error.AuthenticationFailed` as a tag mismatch, checked without
///     secret-dependent early exits — a padding error is indistinguishable
///     from a tag error to the caller.
///
/// KAT: RFC 7518 Appendix B.1/B.3 byte-exact both directions (B.2's HMAC
/// half only — see above), plus RFC 7516 Appendix A.3's full compact-token
/// example in `kat_rfc7516.zig`.
pub const cbc_hmac = struct {
    const aes_core = std.crypto.core.aes;
    const hmac = std.crypto.auth.hmac.sha2;
    const block_len = 16;

    pub fn encrypt(
        enc: Enc,
        cek: []const u8,
        iv: []const u8,
        aad: []const u8,
        plaintext: []const u8,
        ciphertext_out: []u8,
        tag_out: []u8,
    ) Error!usize {
        return switch (enc) {
            .@"A128CBC-HS256" => encryptImpl(aes_core.Aes128, hmac.HmacSha256, cek, iv, aad, plaintext, ciphertext_out, tag_out),
            .@"A256CBC-HS512" => encryptImpl(aes_core.Aes256, hmac.HmacSha512, cek, iv, aad, plaintext, ciphertext_out, tag_out),
            .@"A192CBC-HS384" => error.UnsupportedKeyLength, // std AES-192 gap, see doc comment
            else => error.UnsupportedKeyLength,
        };
    }

    pub fn decrypt(
        enc: Enc,
        cek: []const u8,
        iv: []const u8,
        aad: []const u8,
        ciphertext: []const u8,
        tag: []const u8,
        plaintext_out: []u8,
    ) Error!usize {
        return switch (enc) {
            .@"A128CBC-HS256" => decryptImpl(aes_core.Aes128, hmac.HmacSha256, cek, iv, aad, ciphertext, tag, plaintext_out),
            .@"A256CBC-HS512" => decryptImpl(aes_core.Aes256, hmac.HmacSha512, cek, iv, aad, ciphertext, tag, plaintext_out),
            .@"A192CBC-HS384" => error.UnsupportedKeyLength, // std AES-192 gap, see doc comment
            else => error.UnsupportedKeyLength,
        };
    }

    fn encryptImpl(
        comptime Aes: type,
        comptime Hmac: type,
        cek: []const u8,
        iv: []const u8,
        aad: []const u8,
        plaintext: []const u8,
        ciphertext_out: []u8,
        tag_out: []u8,
    ) Error!usize {
        const half = Hmac.mac_length / 2; // MAC_KEY = ENC_KEY = T_LEN bytes (§5.2.2.1)
        comptime std.debug.assert(Aes.key_bits / 8 == half);
        if (cek.len != 2 * half or iv.len != block_len) return error.BufferTooSmall;
        // PKCS#7 always pads: a full-block plaintext gains one whole pad block.
        const padded_len = plaintext.len + (block_len - plaintext.len % block_len);
        if (ciphertext_out.len < padded_len or tag_out.len < half) return error.BufferTooSmall;
        const mac_key = cek[0..half];
        const enc_key = cek[half..][0..half];

        // PKCS#7-pad, then raw AES-CBC-encrypt in place (§5.2.2.1 step 2),
        // both via the shared `aescbc` module. Safe to pad and encrypt into
        // the same buffer: `aescbc.encrypt` copies each input block into a
        // local register before it overwrites that same span of `out`.
        _ = aescbc.padPkcs7(plaintext, ciphertext_out[0..padded_len]) catch return error.BufferTooSmall;
        _ = aescbc.encrypt(Aes, enc_key.*, iv[0..block_len].*, ciphertext_out[0..padded_len], ciphertext_out[0..padded_len]) catch |err| switch (err) {
            error.NotBlockAligned => unreachable, // padded_len is always block_len-aligned
            error.BufferTooSmall => return error.BufferTooSmall,
        };

        // T = leftmost `half` bytes of HMAC(MAC_KEY, AAD ‖ IV ‖ E ‖ AL);
        // AL = AAD length in BITS, 64-bit big-endian (§5.2.2.1 steps 3-5).
        var full: [Hmac.mac_length]u8 = undefined;
        computeTag(Hmac, mac_key, aad, iv, ciphertext_out[0..padded_len], &full);
        @memcpy(tag_out[0..half], full[0..half]);
        return padded_len;
    }

    fn decryptImpl(
        comptime Aes: type,
        comptime Hmac: type,
        cek: []const u8,
        iv: []const u8,
        aad: []const u8,
        ciphertext: []const u8,
        tag: []const u8,
        plaintext_out: []u8,
    ) Error!usize {
        const half = Hmac.mac_length / 2;
        comptime std.debug.assert(Aes.key_bits / 8 == half);
        if (cek.len != 2 * half or iv.len != block_len or tag.len != half) return error.BufferTooSmall;
        if (plaintext_out.len < ciphertext.len) return error.BufferTooSmall;
        // A PKCS#7 ciphertext is >= 1 block and block-aligned; anything else
        // is unauthenticatable input, same fail-closed error as a bad tag.
        if (ciphertext.len == 0 or ciphertext.len % block_len != 0) return error.AuthenticationFailed;
        const mac_key = cek[0..half];
        const enc_key = cek[half..][0..half];

        // Verify BEFORE decrypting (encrypt-then-MAC), constant-time.
        var full: [Hmac.mac_length]u8 = undefined;
        computeTag(Hmac, mac_key, aad, iv, ciphertext, &full);
        if (!std.crypto.timing_safe.eql([half]u8, full[0..half].*, tag[0..half].*)) {
            return error.AuthenticationFailed;
        }

        // AES-CBC decrypt (tag already verified) via the shared `aescbc`
        // module, then strip PKCS#7 padding without secret-dependent early
        // exits — `aescbc.unpadPkcs7` surfaces every malformed-padding shape
        // as the single `error.InvalidPadding`, which is remapped to the SAME
        // `error.AuthenticationFailed` as a tag mismatch here: a padding
        // error must stay indistinguishable from an authentication error (no
        // padding oracle).
        _ = aescbc.decrypt(Aes, enc_key.*, iv[0..block_len].*, ciphertext, plaintext_out[0..ciphertext.len]) catch |err| switch (err) {
            error.NotBlockAligned => unreachable, // checked above: ciphertext.len % block_len == 0
            error.BufferTooSmall => return error.BufferTooSmall,
        };
        return aescbc.unpadPkcs7(plaintext_out[0..ciphertext.len]) catch return error.AuthenticationFailed;
    }

    fn computeTag(
        comptime Hmac: type,
        mac_key: []const u8,
        aad: []const u8,
        iv: []const u8,
        ciphertext: []const u8,
        out: *[Hmac.mac_length]u8,
    ) void {
        var al: [8]u8 = undefined;
        std.mem.writeInt(u64, &al, @as(u64, aad.len) * 8, .big);
        var mac = Hmac.init(mac_key);
        mac.update(aad);
        mac.update(iv);
        mac.update(ciphertext);
        mac.update(&al);
        mac.final(out);
    }

    /// RFC 7518 Appendix B known-answer vectors, transcribed verbatim and
    /// exercised by the KAT tests further down this file (B.1/B.3 through
    /// `encrypt`/`decrypt` above, both directions; B.2's HMAC half directly —
    /// AES-192 std gap), plus the independent `std.crypto`-only sanity
    /// oracle test.
    pub const kat = struct {
        /// B.1 — AES_128_CBC_HMAC_SHA_256.
        pub const b1 = struct {
            pub const k = [_]u8{
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
            };
            pub const mac_key = k[0..16];
            pub const enc_key = k[16..32];
            pub const p = [_]u8{
                0x41, 0x20, 0x63, 0x69, 0x70, 0x68, 0x65, 0x72, 0x20, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x20,
                0x6d, 0x75, 0x73, 0x74, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x65, 0x71, 0x75,
                0x69, 0x72, 0x65, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x62, 0x65, 0x20, 0x73, 0x65, 0x63, 0x72, 0x65,
                0x74, 0x2c, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x69, 0x74, 0x20, 0x6d, 0x75, 0x73, 0x74, 0x20, 0x62,
                0x65, 0x20, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x74, 0x6f, 0x20, 0x66, 0x61, 0x6c, 0x6c, 0x20, 0x69,
                0x6e, 0x74, 0x6f, 0x20, 0x74, 0x68, 0x65, 0x20, 0x68, 0x61, 0x6e, 0x64, 0x73, 0x20, 0x6f, 0x66,
                0x20, 0x74, 0x68, 0x65, 0x20, 0x65, 0x6e, 0x65, 0x6d, 0x79, 0x20, 0x77, 0x69, 0x74, 0x68, 0x6f,
                0x75, 0x74, 0x20, 0x69, 0x6e, 0x63, 0x6f, 0x6e, 0x76, 0x65, 0x6e, 0x69, 0x65, 0x6e, 0x63, 0x65,
            };
            pub const iv = [_]u8{ 0x1a, 0xf3, 0x8c, 0x2d, 0xc2, 0xb9, 0x6f, 0xfd, 0xd8, 0x66, 0x94, 0x09, 0x23, 0x41, 0xbc, 0x04 };
            pub const a = [_]u8{
                0x54, 0x68, 0x65, 0x20, 0x73, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x20, 0x70, 0x72, 0x69, 0x6e, 0x63,
                0x69, 0x70, 0x6c, 0x65, 0x20, 0x6f, 0x66, 0x20, 0x41, 0x75, 0x67, 0x75, 0x73, 0x74, 0x65, 0x20,
                0x4b, 0x65, 0x72, 0x63, 0x6b, 0x68, 0x6f, 0x66, 0x66, 0x73,
            };
            pub const al = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x50 };
            pub const e = [_]u8{
                0xc8, 0x0e, 0xdf, 0xa3, 0x2d, 0xdf, 0x39, 0xd5, 0xef, 0x00, 0xc0, 0xb4, 0x68, 0x83, 0x42, 0x79,
                0xa2, 0xe4, 0x6a, 0x1b, 0x80, 0x49, 0xf7, 0x92, 0xf7, 0x6b, 0xfe, 0x54, 0xb9, 0x03, 0xa9, 0xc9,
                0xa9, 0x4a, 0xc9, 0xb4, 0x7a, 0xd2, 0x65, 0x5c, 0x5f, 0x10, 0xf9, 0xae, 0xf7, 0x14, 0x27, 0xe2,
                0xfc, 0x6f, 0x9b, 0x3f, 0x39, 0x9a, 0x22, 0x14, 0x89, 0xf1, 0x63, 0x62, 0xc7, 0x03, 0x23, 0x36,
                0x09, 0xd4, 0x5a, 0xc6, 0x98, 0x64, 0xe3, 0x32, 0x1c, 0xf8, 0x29, 0x35, 0xac, 0x40, 0x96, 0xc8,
                0x6e, 0x13, 0x33, 0x14, 0xc5, 0x40, 0x19, 0xe8, 0xca, 0x79, 0x80, 0xdf, 0xa4, 0xb9, 0xcf, 0x1b,
                0x38, 0x4c, 0x48, 0x6f, 0x3a, 0x54, 0xc5, 0x10, 0x78, 0x15, 0x8e, 0xe5, 0xd7, 0x9d, 0xe5, 0x9f,
                0xbd, 0x34, 0xd8, 0x48, 0xb3, 0xd6, 0x95, 0x50, 0xa6, 0x76, 0x46, 0x34, 0x44, 0x27, 0xad, 0xe5,
                0x4b, 0x88, 0x51, 0xff, 0xb5, 0x98, 0xf7, 0xf8, 0x00, 0x74, 0xb9, 0x47, 0x3c, 0x82, 0xe2, 0xdb,
            };
            pub const t = [_]u8{
                0x65, 0x2c, 0x3f, 0xa3, 0x6b, 0x0a, 0x7c, 0x5b, 0x32, 0x19, 0xfa, 0xb3, 0xa3, 0x0b, 0xc1, 0xc4,
            };
        };

        /// B.2 — AES_192_CBC_HMAC_SHA_384 (same P/IV/A/AL as B.1; K/E/T differ).
        pub const b2 = struct {
            pub const k = [_]u8{
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
            };
            pub const mac_key = k[0..24];
            pub const enc_key = k[24..48];
            pub const e = [_]u8{
                0xea, 0x65, 0xda, 0x6b, 0x59, 0xe6, 0x1e, 0xdb, 0x41, 0x9b, 0xe6, 0x2d, 0x19, 0x71, 0x2a, 0xe5,
                0xd3, 0x03, 0xee, 0xb5, 0x00, 0x52, 0xd0, 0xdf, 0xd6, 0x69, 0x7f, 0x77, 0x22, 0x4c, 0x8e, 0xdb,
                0x00, 0x0d, 0x27, 0x9b, 0xdc, 0x14, 0xc1, 0x07, 0x26, 0x54, 0xbd, 0x30, 0x94, 0x42, 0x30, 0xc6,
                0x57, 0xbe, 0xd4, 0xca, 0x0c, 0x9f, 0x4a, 0x84, 0x66, 0xf2, 0x2b, 0x22, 0x6d, 0x17, 0x46, 0x21,
                0x4b, 0xf8, 0xcf, 0xc2, 0x40, 0x0a, 0xdd, 0x9f, 0x51, 0x26, 0xe4, 0x79, 0x66, 0x3f, 0xc9, 0x0b,
                0x3b, 0xed, 0x78, 0x7a, 0x2f, 0x0f, 0xfc, 0xbf, 0x39, 0x04, 0xbe, 0x2a, 0x64, 0x1d, 0x5c, 0x21,
                0x05, 0xbf, 0xe5, 0x91, 0xba, 0xe2, 0x3b, 0x1d, 0x74, 0x49, 0xe5, 0x32, 0xee, 0xf6, 0x0a, 0x9a,
                0xc8, 0xbb, 0x6c, 0x6b, 0x01, 0xd3, 0x5d, 0x49, 0x78, 0x7b, 0xcd, 0x57, 0xef, 0x48, 0x49, 0x27,
                0xf2, 0x80, 0xad, 0xc9, 0x1a, 0xc0, 0xc4, 0xe7, 0x9c, 0x7b, 0x11, 0xef, 0xc6, 0x00, 0x54, 0xe3,
            };
            pub const t = [_]u8{
                0x84, 0x90, 0xac, 0x0e, 0x58, 0x94, 0x9b, 0xfe, 0x51, 0x87, 0x5d, 0x73, 0x3f, 0x93, 0xac, 0x20,
                0x75, 0x16, 0x80, 0x39, 0xcc, 0xc7, 0x33, 0xd7,
            };
        };

        /// B.3 — AES_256_CBC_HMAC_SHA_512 (same P/IV/A/AL as B.1; K/E/T differ).
        pub const b3 = struct {
            pub const k = [_]u8{
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
                0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
            };
            pub const mac_key = k[0..32];
            pub const enc_key = k[32..64];
            pub const e = [_]u8{
                0x4a, 0xff, 0xaa, 0xad, 0xb7, 0x8c, 0x31, 0xc5, 0xda, 0x4b, 0x1b, 0x59, 0x0d, 0x10, 0xff, 0xbd,
                0x3d, 0xd8, 0xd5, 0xd3, 0x02, 0x42, 0x35, 0x26, 0x91, 0x2d, 0xa0, 0x37, 0xec, 0xbc, 0xc7, 0xbd,
                0x82, 0x2c, 0x30, 0x1d, 0xd6, 0x7c, 0x37, 0x3b, 0xcc, 0xb5, 0x84, 0xad, 0x3e, 0x92, 0x79, 0xc2,
                0xe6, 0xd1, 0x2a, 0x13, 0x74, 0xb7, 0x7f, 0x07, 0x75, 0x53, 0xdf, 0x82, 0x94, 0x10, 0x44, 0x6b,
                0x36, 0xeb, 0xd9, 0x70, 0x66, 0x29, 0x6a, 0xe6, 0x42, 0x7e, 0xa7, 0x5c, 0x2e, 0x08, 0x46, 0xa1,
                0x1a, 0x09, 0xcc, 0xf5, 0x37, 0x0d, 0xc8, 0x0b, 0xfe, 0xcb, 0xad, 0x28, 0xc7, 0x3f, 0x09, 0xb3,
                0xa3, 0xb7, 0x5e, 0x66, 0x2a, 0x25, 0x94, 0x41, 0x0a, 0xe4, 0x96, 0xb2, 0xe2, 0xe6, 0x60, 0x9e,
                0x31, 0xe6, 0xe0, 0x2c, 0xc8, 0x37, 0xf0, 0x53, 0xd2, 0x1f, 0x37, 0xff, 0x4f, 0x51, 0x95, 0x0b,
                0xbe, 0x26, 0x38, 0xd0, 0x9d, 0xd7, 0xa4, 0x93, 0x09, 0x30, 0x80, 0x6d, 0x07, 0x03, 0xb1, 0xf6,
            };
            pub const t = [_]u8{
                0x4d, 0xd3, 0xb4, 0xc0, 0x88, 0xa7, 0xf4, 0x5c, 0x21, 0x68, 0x39, 0x64, 0x5b, 0x20, 0x12, 0xbf,
                0x2e, 0x62, 0x69, 0xa8, 0xc5, 0x6a, 0x81, 0x6d, 0xbc, 0x1b, 0x26, 0x77, 0x61, 0x95, 0x5b, 0xc5,
            };
        };
    };
};

test "A128GCM real round-trip (self-consistency, not a KAT)" {
    const key = [_]u8{0x42} ** 16;
    const iv = [_]u8{0x24} ** 12;
    const aad = "additional-data";
    const pt = "The quick brown fox jumps over the lazy dog.";
    var ct: [pt.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    _ = try gcm.encrypt(.A128GCM, &key, &iv, aad, pt, &ct, &tag);

    var recovered: [pt.len]u8 = undefined;
    const n = try gcm.decrypt(.A128GCM, &key, &iv, aad, &ct, &tag, &recovered);
    try std.testing.expectEqualStrings(pt, recovered[0..n]);
}

test "A256GCM real round-trip + tamper detection" {
    const key = [_]u8{0x7a} ** 32;
    const iv = [_]u8{0x11} ** 12;
    const aad = "";
    const pt = "encrypt me please";
    var ct: [pt.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    _ = try gcm.encrypt(.A256GCM, &key, &iv, aad, pt, &ct, &tag);

    var recovered: [pt.len]u8 = undefined;
    const n = try gcm.decrypt(.A256GCM, &key, &iv, aad, &ct, &tag, &recovered);
    try std.testing.expectEqualStrings(pt, recovered[0..n]);

    // Flip one ciphertext byte -> must fail closed, never "decrypt" garbage
    // silently.
    ct[0] ^= 0x01;
    try std.testing.expectError(error.AuthenticationFailed, gcm.decrypt(.A256GCM, &key, &iv, aad, &ct, &tag, &recovered));
}

test "A192GCM is a documented std gap, not silently wrong" {
    const key = [_]u8{0} ** 24;
    const iv = [_]u8{0} ** 12;
    var ct: [4]u8 = undefined;
    var tag: [16]u8 = undefined;
    try std.testing.expectError(error.UnsupportedKeyLength, gcm.encrypt(.A192GCM, &key, &iv, "", "abcd", &ct, &tag));
}

test "RFC 7518 B.1 (A128CBC-HS256): byte-exact E and T, both directions" {
    const b1 = cbc_hmac.kat.b1;
    var ct: [b1.e.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    const n = try cbc_hmac.encrypt(.@"A128CBC-HS256", &b1.k, &b1.iv, &b1.a, &b1.p, &ct, &tag);
    try std.testing.expectEqualSlices(u8, &b1.e, ct[0..n]);
    try std.testing.expectEqualSlices(u8, &b1.t, &tag);

    var pt: [b1.e.len]u8 = undefined;
    const m = try cbc_hmac.decrypt(.@"A128CBC-HS256", &b1.k, &b1.iv, &b1.a, &b1.e, &b1.t, &pt);
    try std.testing.expectEqualSlices(u8, &b1.p, pt[0..m]);
}

test "RFC 7518 B.3 (A256CBC-HS512): byte-exact E and T, both directions" {
    // B.3 reuses B.1's P/IV/A (RFC 7518 §B.3); only K/E/T differ.
    const b1 = cbc_hmac.kat.b1;
    const b3 = cbc_hmac.kat.b3;
    var ct: [b3.e.len]u8 = undefined;
    var tag: [32]u8 = undefined;
    const n = try cbc_hmac.encrypt(.@"A256CBC-HS512", &b3.k, &b1.iv, &b1.a, &b1.p, &ct, &tag);
    try std.testing.expectEqualSlices(u8, &b3.e, ct[0..n]);
    try std.testing.expectEqualSlices(u8, &b3.t, &tag);

    var pt: [b3.e.len]u8 = undefined;
    const m = try cbc_hmac.decrypt(.@"A256CBC-HS512", &b3.k, &b1.iv, &b1.a, &b3.e, &b3.t, &pt);
    try std.testing.expectEqualSlices(u8, &b1.p, pt[0..m]);
}

test "RFC 7518 B.2 (A192CBC-HS384): AES-192 std gap — CBC half typed-unsupported, HMAC half byte-exact" {
    // Verified against std 0.16's source: `std.crypto.core.aes` exports only
    // `Aes128`/`Aes256` (no AES-192 key schedule in any backend —
    // aesni/armcrypto/soft), so there is no block cipher to build
    // A192CBC-HS384's CBC half from. The dispatch must fail typed, never
    // silently substitute a wrong key size:
    const b1 = cbc_hmac.kat.b1;
    const b2 = cbc_hmac.kat.b2;
    var ct: [b2.e.len]u8 = undefined;
    var tag: [24]u8 = undefined;
    try std.testing.expectError(
        error.UnsupportedKeyLength,
        cbc_hmac.encrypt(.@"A192CBC-HS384", &b2.k, &b1.iv, &b1.a, &b1.p, &ct, &tag),
    );
    var pt: [b2.e.len]u8 = undefined;
    try std.testing.expectError(
        error.UnsupportedKeyLength,
        cbc_hmac.decrypt(.@"A192CBC-HS384", &b2.k, &b1.iv, &b1.a, &b2.e, &b2.t, &pt),
    );

    // The construction's HMAC-SHA-384 half IS std-reachable — validate T
    // byte-exact against the transcribed E (B.2 reuses B.1's IV/A/AL), so
    // the only missing piece is genuinely the AES-192 core.
    const HmacSha384 = std.crypto.auth.hmac.sha2.HmacSha384;
    var mac = HmacSha384.init(b2.mac_key);
    mac.update(&b1.a);
    mac.update(&b1.iv);
    mac.update(&b2.e);
    mac.update(&b1.al);
    var full: [48]u8 = undefined;
    mac.final(&full);
    try std.testing.expectEqualSlices(u8, &b2.t, full[0..24]);
}

test "CBC-HMAC decrypt fails closed: tag mismatch and padding failure are the SAME error" {
    const Aes128 = std.crypto.core.aes.Aes128;
    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    const b1 = cbc_hmac.kat.b1;
    var pt: [b1.e.len]u8 = undefined;

    // (1) Tag mismatch -> AuthenticationFailed (rejected before any decryption).
    var bad_tag = b1.t;
    bad_tag[0] ^= 0x01;
    try std.testing.expectError(
        error.AuthenticationFailed,
        cbc_hmac.decrypt(.@"A128CBC-HS256", &b1.k, &b1.iv, &b1.a, &b1.e, &bad_tag, &pt),
    );

    // (2) Tampered ciphertext -> AuthenticationFailed.
    var bad_ct = b1.e;
    bad_ct[0] ^= 0x01;
    try std.testing.expectError(
        error.AuthenticationFailed,
        cbc_hmac.decrypt(.@"A128CBC-HS256", &b1.k, &b1.iv, &b1.a, &bad_ct, &b1.t, &pt),
    );

    // (3) Padding failure with a VALID tag -> the same AuthenticationFailed.
    // Hand-build (std-only, not via this module) a one-block ciphertext whose
    // decryption ends in 0x00 — an always-invalid PKCS#7 pad — then MAC it
    // correctly with the real MAC_KEY. The only failure left is padding; the
    // caller must not be able to tell it apart from a tag failure.
    var block: [16]u8 = .{0x41} ** 16;
    block[15] = 0x00;
    for (&block, b1.iv) |*b, p| b.* ^= p;
    Aes128.initEnc(b1.enc_key.*).encrypt(&block, &block);
    var mac = HmacSha256.init(b1.mac_key);
    mac.update(&b1.a);
    mac.update(&b1.iv);
    mac.update(&block);
    mac.update(&[8]u8{ 0, 0, 0, 0, 0, 0, 0x01, 0x50 }); // AL for b1.a (42 bytes = 0x150 bits)
    var full: [32]u8 = undefined;
    mac.final(&full);
    var out: [16]u8 = undefined;
    try std.testing.expectError(
        error.AuthenticationFailed,
        cbc_hmac.decrypt(.@"A128CBC-HS256", &b1.k, &b1.iv, &b1.a, &block, full[0..16], &out),
    );
}

test "CBC-HMAC round-trip: non-block-aligned plaintext (partial-block PKCS#7 pad)" {
    const key = [_]u8{0x33} ** 32;
    const iv = [_]u8{0x44} ** 16;
    const aad = "jwe-aad";
    const pt = "seventeen bytes!!"; // 17 bytes -> one full block + 1 byte + 15 pad
    var ct: [32]u8 = undefined;
    var tag: [16]u8 = undefined;
    const n = try cbc_hmac.encrypt(.@"A128CBC-HS256", &key, &iv, aad, pt, &ct, &tag);
    try std.testing.expectEqual(@as(usize, 32), n);

    var out: [32]u8 = undefined;
    const m = try cbc_hmac.decrypt(.@"A128CBC-HS256", &key, &iv, aad, ct[0..n], &tag, &out);
    try std.testing.expectEqualStrings(pt, out[0..m]);
}

// ── independent std-only sanity oracle (RFC 7518 §B.1) ──────────────────────
//
// Reproduces the B.1 vector's E and T using ONLY std.crypto primitives
// (manual PKCS#7 CBC via std.crypto.core.aes block calls + HmacSha256) —
// deliberately NOT calling this module's own `cbc_hmac`. Kept as an
// independently-verified target: if `cbc_hmac`'s implementation ever
// disagrees with this, the bug is in `cbc_hmac`, not in a mistranscribed
// constant.

test "std-only sanity oracle: reproduces RFC 7518 B.1 E and T from std.crypto alone" {
    const Aes128 = std.crypto.core.aes.Aes128;
    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    const b1 = cbc_hmac.kat.b1;

    // Manual PKCS#7 CBC-encrypt: pad P to a block multiple (P is exactly
    // 128 bytes here, a full block, so PKCS#7 adds one whole pad block of
    // 0x10 bytes per RFC 5652 §6.3), then chain-XOR + single-block-ECB-encrypt.
    var padded: [b1.p.len + 16]u8 = undefined;
    @memcpy(padded[0..b1.p.len], &b1.p);
    @memset(padded[b1.p.len..], 16);

    var e: [padded.len]u8 = undefined;
    const enc_ctx = Aes128.initEnc(b1.enc_key.*);
    var prev: [16]u8 = b1.iv;
    var i: usize = 0;
    while (i < padded.len) : (i += 16) {
        var block: [16]u8 = padded[i..][0..16].*;
        for (&block, prev) |*bb, pp| bb.* ^= pp;
        enc_ctx.encrypt(&block, &block);
        @memcpy(e[i..][0..16], &block);
        prev = block;
    }
    try std.testing.expectEqualSlices(u8, &b1.e, &e);

    // T = left half of HMAC-SHA256(MAC_KEY, A || IV || E || AL).
    var mac = HmacSha256.init(b1.mac_key);
    mac.update(&b1.a);
    mac.update(&b1.iv);
    mac.update(&e);
    mac.update(&b1.al);
    var full_tag: [32]u8 = undefined;
    mac.final(&full_tag);
    try std.testing.expectEqualSlices(u8, &b1.t, full_tag[0..16]);
}
