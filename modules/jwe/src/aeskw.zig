// SPDX-License-Identifier: MIT

//! jwe.alg.aeskw — RFC 3394 AES Key Wrap, the careful core behind
//! A128KW/A256KW (RFC 7518 §4.4) and, indirectly, every PBES2-* variant
//! (§4.8 — the PBKDF2-derived KEK in `alg.pbes2DeriveKek` still has to pass
//! through this wrap/unwrap to become a JWE Encrypted Key).
//!
//! Implementation notes (the footguns, now handled):
//!
//!   - **constant-time integrity check**: `unwrap`'s final comparison of the
//!     recovered register `A` against `default_iv` goes through
//!     `std.crypto.timing_safe.eql` — an early-exit `std.mem.eql` would turn
//!     a wrong-KEK/corrupted-ciphertext unwrap into a timing side channel.
//!     On failure the partially-recovered key material in `out` is zeroed
//!     before returning, so a failed unwrap never leaks bytes derived from
//!     the KEK.
//!   - **exact recurrence**: the 6-round wrap (`A`, `R[1..n]` register
//!     shifting, RFC 3394 §2.2.1) and its unwrap inverse (§2.2.2) follow the
//!     RFC's `t = n*j + i` counter arithmetic, XORed big-endian into the
//!     *top* 8 bytes of the AES block. Byte-exact against RFC 3394 §4.1 (see
//!     the test below) and RFC 7516 §A.3.3 (see `kat_rfc7516.zig`).
//!   - **length validation**: `plaintext`/`ciphertext` must be an exact
//!     8-byte-multiple, wrap input `>= 16` bytes (2 blocks), unwrap input
//!     `>= 24` bytes (default IV block + >= 2 wrapped blocks) — RFC 3394 §2.
//!
//! Mirrored from (not imported — sibling modules stay independent, see
//! CONVENTIONS.md): `modules/dnp3/src/sa.zig`'s `aeskw` namespace, the
//! already-validated RFC 3394 implementation in this repo. Re-expressed here
//! against the RFC text; same construction, same §4 vectors.
//!
//! **A192KW remains a std gap, not a stub**: a 192-bit KEK needs an AES-192
//! block cipher and `std.crypto.core.aes` (0.16) ships only `Aes128`/
//! `Aes256` — a 24-byte KEK returns `error.UnsupportedKeyLength`, matching
//! how `enc.zig` types the same gap for `A192GCM`.

const std = @import("std");
const aes = std.crypto.core.aes;

/// RFC 3394 §2.2.3.1 default initial value — the integrity-check register's
/// expected value after a correct unwrap.
pub const default_iv = [8]u8{ 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6 };

pub const Error = error{
    /// `plaintext`/`ciphertext` isn't an 8-byte multiple, or is shorter than
    /// the RFC's minimum (16 bytes to wrap, 24 to unwrap).
    InvalidLength,
    BufferTooSmall,
    /// The KEK length has no std AES core: anything other than 16 (AES-128)
    /// or 32 (AES-256) bytes — notably A192KW's 24-byte KEK (std 0.16 ships
    /// no AES-192 block cipher; see the module doc comment).
    UnsupportedKeyLength,
    /// Unwrap's integrity check failed (wrong KEK or corrupted ciphertext).
    Unauthentic,
};

/// AES Key Wrap (RFC 3394 §2.2.1). `plaintext.len` must be a multiple of 8
/// and >= 16; `kek.len` selects AES-128 (16) or AES-256 (32) — see the
/// module doc comment for why AES-192 isn't listed. Writes
/// `plaintext.len + 8` bytes to `out` and returns that slice.
///
/// KAT: RFC 3394 §4.1 (this file's test below) and the RFC 7516 A.3
/// (`A128KW` + `A128CBC-HS256`) compact-token example in `kat_rfc7516.zig`.
pub fn wrap(kek: []const u8, plaintext: []const u8, out: []u8) Error![]u8 {
    if (plaintext.len < 16 or plaintext.len % 8 != 0) return error.InvalidLength;
    const n = plaintext.len / 8;
    const total = plaintext.len + 8;
    if (out.len < total) return error.BufferTooSmall;

    // R[1..n] = plaintext blocks; A = IV. Registers live in `out` as
    // A(8) || R1 || R2 ... so the shifting operates in place.
    var a: [8]u8 = default_iv;
    @memcpy(out[8..total], plaintext);
    const r = out[8..total];

    var j: usize = 0;
    while (j < 6) : (j += 1) {
        var i: usize = 0;
        while (i < n) : (i += 1) {
            var block: [16]u8 = undefined;
            @memcpy(block[0..8], &a);
            @memcpy(block[8..16], r[i * 8 ..][0..8]);
            try encBlock(kek, &block);
            // t = n*j + (i+1), XORed big-endian into the MSB half (§2.2.1
            // step 2: A = MSB(64, B) ^ t).
            const t: u64 = @as(u64, n) * @as(u64, j) + @as(u64, i) + 1;
            @memcpy(&a, block[0..8]);
            xorCounter(&a, t);
            @memcpy(r[i * 8 ..][0..8], block[8..16]);
        }
    }
    @memcpy(out[0..8], &a);
    return out[0..total];
}

/// AES Key Unwrap (RFC 3394 §2.2.2) — the inverse of `wrap`. `ciphertext.len`
/// must be a multiple of 8 and >= 24. Returns the `ciphertext.len - 8`
/// recovered plaintext bytes, or `error.Unauthentic` if the constant-time
/// integrity check fails (in which case `out` is zeroed — no partial-key
/// leak).
pub fn unwrap(kek: []const u8, ciphertext: []const u8, out: []u8) Error![]u8 {
    if (ciphertext.len < 24 or ciphertext.len % 8 != 0) return error.InvalidLength;
    const n = ciphertext.len / 8 - 1;
    if (out.len < n * 8) return error.BufferTooSmall;

    var a: [8]u8 = ciphertext[0..8].*;
    const r = out[0 .. n * 8];
    @memcpy(r, ciphertext[8..]);

    var j: usize = 6;
    while (j > 0) {
        j -= 1;
        var i: usize = n;
        while (i > 0) {
            i -= 1;
            const t: u64 = @as(u64, n) * @as(u64, j) + @as(u64, i) + 1;
            var block: [16]u8 = undefined;
            @memcpy(block[0..8], &a);
            xorCounter(block[0..8], t);
            @memcpy(block[8..16], r[i * 8 ..][0..8]);
            decBlock(kek, &block) catch |err| {
                std.crypto.secureZero(u8, r);
                return err;
            };
            @memcpy(&a, block[0..8]);
            @memcpy(r[i * 8 ..][0..8], block[8..16]);
        }
    }
    // Constant-time integrity check against the default IV (§2.2.3); an
    // early-exit compare here would be a timing oracle. Fail closed AND
    // clean: never hand back partially-recovered key material.
    if (!std.crypto.timing_safe.eql([8]u8, a, default_iv)) {
        std.crypto.secureZero(u8, r);
        return error.Unauthentic;
    }
    return r;
}

fn encBlock(kek: []const u8, block: *[16]u8) error{UnsupportedKeyLength}!void {
    switch (kek.len) {
        16 => aes.Aes128.initEnc(kek[0..16].*).encrypt(block, block),
        32 => aes.Aes256.initEnc(kek[0..32].*).encrypt(block, block),
        else => return error.UnsupportedKeyLength,
    }
}

fn decBlock(kek: []const u8, block: *[16]u8) error{UnsupportedKeyLength}!void {
    switch (kek.len) {
        16 => aes.Aes128.initDec(kek[0..16].*).decrypt(block, block),
        32 => aes.Aes256.initDec(kek[0..32].*).decrypt(block, block),
        else => return error.UnsupportedKeyLength,
    }
}

fn xorCounter(a: *[8]u8, t: u64) void {
    var tb: [8]u8 = undefined;
    std.mem.writeInt(u64, &tb, t, .big);
    for (a, tb) |*x, y| x.* ^= y;
}

test "RFC 3394 §4.1 KAT — 128-bit KEK wraps 128-bit key data, byte-exact both directions" {
    // Input:
    //   KEK (128-bit):      00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
    //   Key Data (128-bit): 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF
    // Output:
    //   Ciphertext (192-bit): 1F A6 8B 0A 81 12 B4 47
    //                         AE F3 4B D8 FB 5A 7B 82
    //                         9D 3E 86 23 71 D2 CF E5
    const kek = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const key_data = [_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    const ciphertext = [_]u8{
        0x1f, 0xa6, 0x8b, 0x0a, 0x81, 0x12, 0xb4, 0x47,
        0xae, 0xf3, 0x4b, 0xd8, 0xfb, 0x5a, 0x7b, 0x82,
        0x9d, 0x3e, 0x86, 0x23, 0x71, 0xd2, 0xcf, 0xe5,
    };
    var out: [24]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &ciphertext, try wrap(&kek, &key_data, &out));
    var back: [16]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &key_data, try unwrap(&kek, &ciphertext, &back));
}

test "AES-256 KEK round-trip (multi-block key data)" {
    const kek = [_]u8{0x5a} ** 32;
    const key = [_]u8{0xc3} ** 32; // n = 4 blocks
    var ct: [40]u8 = undefined;
    const wrapped = try wrap(&kek, &key, &ct);
    var pt: [32]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &key, try unwrap(&kek, wrapped, &pt));
}

test "unwrap fails closed: wrong KEK / corrupted ciphertext -> Unauthentic, output zeroed" {
    const kek = [_]u8{0x11} ** 16;
    const key = [_]u8{0x22} ** 16;
    var ct: [24]u8 = undefined;
    _ = try wrap(&kek, &key, &ct);

    var out: [16]u8 = undefined;
    const bad_kek = [_]u8{0x12} ** 16;
    try std.testing.expectError(error.Unauthentic, unwrap(&bad_kek, &ct, &out));
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 16), &out); // no partial-key leak

    var corrupt = ct;
    corrupt[9] ^= 0x01;
    out = undefined;
    try std.testing.expectError(error.Unauthentic, unwrap(&kek, &corrupt, &out));
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 16), &out);
}

test "length + KEK validation (incl. the A192KW 24-byte-KEK std gap)" {
    const kek = [_]u8{0} ** 16;
    var buf: [64]u8 = undefined;
    try std.testing.expectError(error.InvalidLength, wrap(&kek, &.{ 1, 2, 3 }, &buf)); // not a multiple of 8
    try std.testing.expectError(error.InvalidLength, wrap(&kek, &[_]u8{0} ** 8, &buf)); // < 16
    try std.testing.expectError(error.InvalidLength, unwrap(&kek, &[_]u8{0} ** 16, &buf)); // < 24
    try std.testing.expectError(error.BufferTooSmall, wrap(&kek, &[_]u8{0} ** 16, buf[0..16]));

    const kek192 = [_]u8{0} ** 24;
    try std.testing.expectError(error.UnsupportedKeyLength, wrap(&kek192, &[_]u8{0} ** 16, &buf));
    try std.testing.expectError(error.UnsupportedKeyLength, unwrap(&kek192, &[_]u8{0} ** 24, &buf));
}
