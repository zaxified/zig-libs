// SPDX-License-Identifier: MIT
//! Official known-answer vectors for every primitive `ctap2pin` composes.
//! No single official CTAP2 pinUvAuthProtocol KAT table exists, so each
//! piece is anchored to its own published vector (transcribed from the
//! cited primary source, not from any implementation's test suite):
//!
//!   - AES-256-CBC: NIST SP 800-38A, Appendix F.2.5 (CBC-AES256.Encrypt)
//!     and F.2.6 (CBC-AES256.Decrypt) — same key/IV/PT/CT table.
//!   - HKDF-SHA-256: RFC 5869, Appendix A.1 (Basic test case with SHA-256).
//!   - P-256 ECDH: RFC 5903, Section 8.1 (256-Bit Random ECP Group) —
//!     initiator/responder private keys, both public keys, and the shared
//!     `girx` (the DH shared secret value per that section).
//!   - HMAC-SHA-256: RFC 4231, Section 4.3 (Test Case 2).
//!
//! All values are lowercase hex strings except the RFC 4231 key/data,
//! which the RFC defines as ASCII text.

/// NIST SP 800-38A Appendix F.2.5/F.2.6 — CBC-AES256. Four blocks; the
/// decrypt case (F.2.6) is the same table read CT→PT.
pub const nist_sp800_38a_cbc_aes256 = .{
    .key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
    .iv = "000102030405060708090a0b0c0d0e0f",
    .plaintext = "6bc1bee22e409f96e93d7e117393172a" ++
        "ae2d8a571e03ac9c9eb76fac45af8e51" ++
        "30c81c46a35ce411e5fbc1191a0a52ef" ++
        "f69f2445df4f9b17ad2b417be66c3710",
    .ciphertext = "f58c4c04d6e5f1ba779eabfb5f7bfbd6" ++
        "9cfc4e967edb808d679f777bc6702c7d" ++
        "39f23369a9d9bacfa530e26304231461" ++
        "b2eb05e2c39be9fcda6c19078c6a9d1b",
};

/// RFC 5869 Appendix A.1 — HKDF-SHA-256 basic test case.
pub const rfc5869_a1 = .{
    .ikm = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", // 22 bytes
    .salt = "000102030405060708090a0b0c", // 13 bytes
    .info = "f0f1f2f3f4f5f6f7f8f9", // 10 bytes
    .prk = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
    .okm = "3cb25f25faacd57a90434f64d0362f2a" ++
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf" ++
        "34007208d5b887185865", // L = 42
};

/// RFC 5903 Section 8.1 — P-256 ECDH (IKE group 19). `i`/`r` are the
/// initiator/responder private scalars; `gi`/`gr` their public keys;
/// `girx` is the shared secret Z (the x-coordinate of `i*r*G`).
pub const rfc5903_p256 = .{
    .i = "c88f01f510d9ac3f70a292daa2316de544e9aab8afe84049c62a9c57862d1433",
    .gix = "dad0b65394221cf9b051e1feca5787d098dfe637fc90b9ef945d0c3772581180",
    .giy = "5271a0461cdb8252d61f1c456fa3e59ab1f45b33accf5f58389e0577b8990bb3",
    .r = "c6ef9c5d78ae012a011164acb397ce2088685d8f06bf9be0b283ab46476bee53",
    .grx = "d12dfb5289c8d4f81208b70270398c342296970a0bccb74c736fc7554494bf63",
    .gry = "56fbf3ca366cc23e8157854c13c58d6aac23f046ada30f8353e74f33039872ab",
    .girx = "d6840f6b42f6edafd13116e0e12565202fef8e9ece7dce03812464d04b9442de",
    .giry = "522bde0af0d8585b8def9c183b5ae38f50235206a8674ecb5d98edb20eb153a2",
};

/// RFC 4231 Section 4.3 — HMAC-SHA-256 Test Case 2 (ASCII key/data).
pub const rfc4231_tc2 = .{
    .key = "Jefe",
    .data = "what do ya want for nothing?",
    .mac = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
};

test "vectors: hex fields are well-formed" {
    const std = @import("std");
    const t = std.testing;
    try t.expectEqual(@as(usize, 64), nist_sp800_38a_cbc_aes256.key.len);
    try t.expectEqual(@as(usize, 32), nist_sp800_38a_cbc_aes256.iv.len);
    try t.expectEqual(@as(usize, 128), nist_sp800_38a_cbc_aes256.plaintext.len);
    try t.expectEqual(@as(usize, 128), nist_sp800_38a_cbc_aes256.ciphertext.len);
    try t.expectEqual(@as(usize, 44), rfc5869_a1.ikm.len);
    try t.expectEqual(@as(usize, 84), rfc5869_a1.okm.len); // L = 42 bytes
    inline for (.{ rfc5903_p256.i, rfc5903_p256.gix, rfc5903_p256.giy, rfc5903_p256.r, rfc5903_p256.grx, rfc5903_p256.gry, rfc5903_p256.girx, rfc5903_p256.giry }) |field| {
        try t.expectEqual(@as(usize, 64), field.len);
    }
    try t.expectEqual(@as(usize, 64), rfc4231_tc2.mac.len);
}
