// SPDX-License-Identifier: MIT
//! Official ECDSA-P256/SHA-256 test vectors transcribed from RFC 6979
//! Appendix A.2.5 ("Deterministic ECDSA", curve NIST P-256, hash SHA-256) — a
//! public IETF specification artifact, not copied from any implementation's test
//! suite (see `../../NOTICE`). These are the EXTERNAL anchor for p256's
//! end-to-end verify: each `(r, s)` is the RFC-published signature of `message`
//! under the RFC-published key, so accepting it exercises p256's whole
//! field/group/scalar stack against a reference produced independently of both
//! p256 and std.
//!
//! Key (RFC 6979 A.2.5): the public key `U = (Ux, Uy)` for private key
//! `x = C9AFA9D8…120F6721`. The verify path only needs the public key, encoded
//! here uncompressed-SEC1 (`04 || Ux || Uy`).

pub const public_key_sec1: []const u8 =
    "04" ++
    "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6" ++ // Ux
    "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"; //   Uy

pub const Vector = struct {
    /// ASCII message (RFC 6979 uses the literal strings "sample" / "test").
    message: []const u8,
    /// Signature `r`, 32-byte big-endian hex.
    r: []const u8,
    /// Signature `s`, 32-byte big-endian hex.
    s: []const u8,
};

pub const vectors = [_]Vector{
    // With SHA-256, message = "sample".
    .{
        .message = "sample",
        .r = "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
        .s = "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
    },
    // With SHA-256, message = "test".
    .{
        .message = "test",
        .r = "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367",
        .s = "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083",
    },
};

test "vector count matches RFC 6979 A.2.5 SHA-256 rows (2)" {
    const std = @import("std");
    try std.testing.expectEqual(@as(usize, 2), vectors.len);
}
