// SPDX-License-Identifier: MIT
//! Official HOTP/TOTP test vectors, transcribed byte-exact from the RFC
//! appendices (public IETF specification artifacts, not copied from any
//! implementation's test suite; see `../NOTICE`):
//!
//! - **RFC 4226 Appendix D** ("HOTP Algorithm: Test Values"): the ASCII
//!   secret `"12345678901234567890"`, counts 0..9 — including the
//!   intermediate HMAC-SHA-1 digests and the truncated 31-bit integers
//!   (the "Decimal" column) alongside the final 6-digit HOTP codes.
//! - **RFC 6238 Appendix B** ("Test Vectors"): 6 unix times × 3 hash
//!   functions, 8-digit codes, `period = 30`, `t0 = 0`. Per the appendix's
//!   note (and the errata-confirmed reference-code behavior), each mode
//!   uses an ASCII secret of exactly the HMAC hash's block-input
//!   convention used by the RFC's reference program: `"1234567890"`
//!   repeated and truncated to **20 bytes for SHA-1, 32 bytes for
//!   SHA-256, 64 bytes for SHA-512** — the Appendix B table only prints
//!   the 20-byte one, but the codes below only reproduce with the
//!   per-mode lengths.

/// RFC 4226 Appendix D secret (20 ASCII bytes).
pub const rfc4226_secret = "12345678901234567890";

pub const Rfc4226Vector = struct {
    count: u64,
    /// Intermediate `HMAC-SHA-1(secret, count)`, 40 lowercase hex chars.
    hmac_hex: []const u8,
    /// Dynamic-truncation result `P` (the RFC's "Decimal" column),
    /// before `mod 10^6`.
    truncated: u32,
    /// The 6-digit HOTP value.
    hotp6: u32,
};

/// RFC 4226 Appendix D, all three tables merged by count.
pub const rfc4226_vectors = [_]Rfc4226Vector{
    .{ .count = 0, .hmac_hex = "cc93cf18508d94934c64b65d8ba7667fb7cde4b0", .truncated = 1284755224, .hotp6 = 755224 },
    .{ .count = 1, .hmac_hex = "75a48a19d4cbe100644e8ac1397eea747a2d33ab", .truncated = 1094287082, .hotp6 = 287082 },
    .{ .count = 2, .hmac_hex = "0bacb7fa082fef30782211938bc1c5e70416ff44", .truncated = 137359152, .hotp6 = 359152 },
    .{ .count = 3, .hmac_hex = "66c28227d03a2d5529262ff016a1e6ef76557ece", .truncated = 1726969429, .hotp6 = 969429 },
    .{ .count = 4, .hmac_hex = "a904c900a64b35909874b33e61c5938a8e15ed1c", .truncated = 1640338314, .hotp6 = 338314 },
    .{ .count = 5, .hmac_hex = "a37e783d7b7233c083d4f62926c7a25f238d0316", .truncated = 868254676, .hotp6 = 254676 },
    .{ .count = 6, .hmac_hex = "bc9cd28561042c83f219324d3c607256c03272ae", .truncated = 1918287922, .hotp6 = 287922 },
    .{ .count = 7, .hmac_hex = "a4fb960c0bc06e1eabb804e5b397cdc4b45596fa", .truncated = 82162583, .hotp6 = 162583 },
    .{ .count = 8, .hmac_hex = "1b3c89f65e6c9e883012052823443f048b4332db", .truncated = 673399871, .hotp6 = 399871 },
    .{ .count = 9, .hmac_hex = "1637409809a679dc698207310c8c7fc07290d9e5", .truncated = 645520489, .hotp6 = 520489 },
};

/// RFC 6238 Appendix B secrets: ASCII `"1234567890"` repeated, truncated
/// to the per-mode length (20 / 32 / 64 bytes).
pub const rfc6238_secret_sha1 = "12345678901234567890";
pub const rfc6238_secret_sha256 = "12345678901234567890123456789012";
pub const rfc6238_secret_sha512 = "1234567890123456789012345678901234567890123456789012345678901234";

pub const Rfc6238Vector = struct {
    /// The "Time (sec)" column: unix time.
    unix_time: u64,
    /// The "Value of T (hex)" column: the expected time-step counter
    /// (`floor(unix_time / 30)`), given here as the decoded integer.
    t: u64,
    /// The 8-digit TOTP per mode.
    sha1: u32,
    sha256: u32,
    sha512: u32,
};

/// RFC 6238 Appendix B, all 18 rows (6 times × 3 modes) merged by time.
/// 8 digits, period 30, t0 = 0. Codes with a leading zero (e.g. SHA-1 at
/// T=1111111109 → "07081804") are stored as the numeric value.
pub const rfc6238_vectors = [_]Rfc6238Vector{
    .{ .unix_time = 59, .t = 0x0000000000000001, .sha1 = 94287082, .sha256 = 46119246, .sha512 = 90693936 },
    .{ .unix_time = 1111111109, .t = 0x00000000023523EC, .sha1 = 7081804, .sha256 = 68084774, .sha512 = 25091201 },
    .{ .unix_time = 1111111111, .t = 0x00000000023523ED, .sha1 = 14050471, .sha256 = 67062674, .sha512 = 99943326 },
    .{ .unix_time = 1234567890, .t = 0x000000000273EF07, .sha1 = 89005924, .sha256 = 91819424, .sha512 = 93441116 },
    .{ .unix_time = 2000000000, .t = 0x0000000003F940AA, .sha1 = 69279037, .sha256 = 90698825, .sha512 = 38618901 },
    .{ .unix_time = 20000000000, .t = 0x0000000027BC86AA, .sha1 = 65353130, .sha256 = 77737706, .sha512 = 47863826 },
};
