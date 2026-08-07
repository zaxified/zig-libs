// SPDX-License-Identifier: MIT

//! aeskw — RFC 3394 AES Key Wrap, the canonical implementation for this repo.
//! std ships no key-wrap primitive, so this construction had been mirrored
//! three times independently (`modules/jwe/src/aeskw.zig`, `modules/dnp3/src
//! /sa.zig`'s `aeskw` namespace, and `modules/xmlenc/src/root.zig`'s local
//! unwrap-only core) before landing here as one module the other three now
//! adopt.
//!
//! Implementation notes (the footguns, now handled):
//!
//!   - **constant-time integrity check**: `unwrap`'s final comparison of the
//!     recovered register `A` against `default_iv` goes through
//!     `std.crypto.timing_safe.eql` — an early-exit `std.mem.eql` would turn
//!     a wrong-KEK/corrupted-ciphertext unwrap into a timing side channel.
//!     On failure the partially-recovered key material in `out` is zeroed
//!     via `std.crypto.secureZero` before returning, so a failed unwrap
//!     never leaks bytes derived from the KEK.
//!   - **exact recurrence**: the 6-round wrap (`A`, `R[1..n]` register
//!     shifting, RFC 3394 §2.2.1) and its unwrap inverse (§2.2.2) follow the
//!     RFC's `t = n*j + i` counter arithmetic, XORed big-endian into the
//!     *top* 8 bytes of the AES block. Byte-exact against RFC 3394 §4.1,
//!     §4.3, §4.5, and §4.6 (see the tests below).
//!   - **length validation**: `plaintext`/`ciphertext` must be an exact
//!     8-byte multiple, wrap input `>= 16` bytes (2 semiblocks), unwrap
//!     input `>= 24` bytes (default-IV block + >= 2 wrapped semiblocks) —
//!     RFC 3394 §2.
//!
//! **A192KW remains a std gap, not a stub**: a 192-bit KEK needs an AES-192
//! block cipher and `std.crypto.core.aes` (0.16) ships only `Aes128`/
//! `Aes256` — a 24-byte KEK returns `error.UnsupportedKeyLength`.
//!
//! **RFC 5649 (AES Key Wrap with Padding) is deferred, not implemented.**
//! This module covers only the unpadded RFC 3394 construction (plaintext
//! key data must already be an 8-byte multiple, >= 16 bytes) — see
//! SPEC.md.

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
    /// or 32 (AES-256) bytes — notably a 192-bit KEK (std 0.16 ships no
    /// AES-192 block cipher; see the module doc comment).
    UnsupportedKeyLength,
    /// Unwrap's integrity check failed (wrong KEK or corrupted ciphertext).
    Unauthentic,
};

/// AES Key Wrap (RFC 3394 §2.2.1). `plaintext.len` must be a multiple of 8
/// and >= 16; `kek.len` selects AES-128 (16) or AES-256 (32) — see the
/// module doc comment for why a 192-bit KEK isn't supported. Writes
/// `plaintext.len + 8` bytes to `out` and returns that slice.
///
/// KAT: RFC 3394 §4.1, §4.3, §4.5, §4.6 (this file's tests below).
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
///
/// Zeroization posture (CONVENTIONS §2.1): the failure-path wipe of `out` above
/// is the module's only one, and that is the complete set. The `a` register and
/// the 16-byte `block` staging buffer are the KW construction's own working
/// state — Z3, the class `std` leaves unwiped in its own ciphers — and so is
/// the AES round-key schedule inside `encBlock`/`decBlock`. `kek` and `out` are
/// caller-owned slices (Z2). There is no Z1 storage here: this module allocates
/// nothing and keeps nothing between calls.
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

fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

test "RFC 3394 §4.1 KAT — 128-bit KEK wraps 128-bit key data, byte-exact both directions" {
    const kek = hexToBytes("000102030405060708090A0B0C0D0E0F");
    const key_data = hexToBytes("00112233445566778899AABBCCDDEEFF");
    const ciphertext = hexToBytes("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5");

    var out: [24]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &ciphertext, try wrap(&kek, &key_data, &out));
    var back: [16]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &key_data, try unwrap(&kek, &ciphertext, &back));
}

test "RFC 3394 §4.3 KAT — 256-bit KEK wraps 128-bit key data, byte-exact both directions" {
    const kek = hexToBytes("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    const key_data = hexToBytes("00112233445566778899AABBCCDDEEFF");
    const ciphertext = hexToBytes("64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7");

    var out: [24]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &ciphertext, try wrap(&kek, &key_data, &out));
    var back: [16]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &key_data, try unwrap(&kek, &ciphertext, &back));
}

test "RFC 3394 §4.5 KAT — 256-bit KEK wraps 192-bit key data (n=3), byte-exact both directions" {
    const kek = hexToBytes("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    const key_data = hexToBytes("00112233445566778899AABBCCDDEEFF0001020304050607");
    const ciphertext = hexToBytes("A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1");

    var out: [32]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &ciphertext, try wrap(&kek, &key_data, &out));
    var back: [24]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &key_data, try unwrap(&kek, &ciphertext, &back));
}

test "RFC 3394 §4.6 KAT — 256-bit KEK wraps 256-bit key data (n=4), byte-exact both directions" {
    const kek = hexToBytes("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    const key_data = hexToBytes("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F");
    const ciphertext = hexToBytes("28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21");

    var out: [40]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &ciphertext, try wrap(&kek, &key_data, &out));
    var back: [32]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &key_data, try unwrap(&kek, &ciphertext, &back));
}

test "unwrap fails closed: wrong KEK / corrupted ciphertext -> Unauthentic, output zeroed (with a correct-KEK positive control)" {
    const kek = [_]u8{0x11} ** 16;
    const key = [_]u8{0x22} ** 16;
    var ct: [24]u8 = undefined;
    _ = try wrap(&kek, &key, &ct);

    // Positive control: the correct KEK recovers the exact key data.
    var good_out: [16]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &key, try unwrap(&kek, &ct, &good_out));

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

// ── fuzz: `unwrap` on an attacker-controlled ciphertext ─────────────────────
//
// W2 A3 (F2): CLASS B, zero `testing.fuzz(` harnesses — this module was
// absent from `scripts/fuzz-sweep.sh`'s target list entirely, despite
// `unwrap`'s own SPEC.md naming it a wire-facing entry point: "the wrapped
// blob may arrive over an untrusted channel". Per the campaign brief, the
// AES core and the wrap/unwrap recurrence are already pinned byte-exact by
// the RFC 3394 KATs above; fuzzing arbitrary bytes into `unwrap` would not
// re-test those (a random ciphertext almost never survives the integrity
// check to reach a specific arithmetic step) — what it DOES test is the two
// length guards and the no-partial-key-leak invariant on failure, which is
// the actual parsing/framing surface named in the finding.
//
// Two oracles, not one:
//  1. On `error.Unauthentic` (the overwhelmingly likely outcome for random
//     bytes), `out` must be all-zero — SPEC's stated no-partial-key-leak
//     guarantee, and the one already covered by only a single hand-built
//     case in the unit test above.
//  2. A genuine wrap→unwrap round trip over fuzzed plaintext, at every
//     legal semiblock count, closes with an exact-recovery check. A round
//     trip alone cannot see a bug that shifts both `wrap` and `unwrap` the
//     same way (the campaign brief's own caveat), which is exactly why (1)
//     exists as an independent check that does not go through `wrap` at
//     all.
test "fuzz: unwrap never leaks partial key material on failure, on arbitrary ciphertext" {
    try std.testing.fuzz({}, fuzzUnwrapNoLeak, .{});
}

fn fuzzUnwrapNoLeak(_: void, smith: *std.testing.Smith) !void {
    const kek_len: usize = if (smith.value(bool)) 16 else 32;
    var kek_buf: [32]u8 = undefined;
    smith.bytes(kek_buf[0..kek_len]);
    const kek = kek_buf[0..kek_len];

    // Length drawn first so every mutated byte lands inside `ct`, not
    // scattered across a fixed 256-byte draw a small `ct_len` would discard.
    var ct_buf: [256]u8 = undefined;
    const ct_len = smith.valueRangeAtMost(u16, 0, ct_buf.len);
    smith.bytes(ct_buf[0..ct_len]);
    const ct = ct_buf[0..ct_len];

    var out: [256]u8 = undefined;
    if (unwrap(kek, ct, &out)) |_| {
        // Astronomically unlikely for random bytes (would require the
        // integrity register to land on the default IV by chance), but not
        // impossible in principle -- nothing to assert beyond "no crash".
    } else |err| {
        if (err != error.Unauthentic) return;
        const n = ct.len / 8 - 1;
        for (out[0..n]) |b| try std.testing.expectEqual(@as(u8, 0), b);
    }
}

test "fuzz: wrap then unwrap recovers the exact plaintext, at every legal size" {
    try std.testing.fuzz({}, fuzzWrapUnwrapRoundTrip, .{});
}

fn fuzzWrapUnwrapRoundTrip(_: void, smith: *std.testing.Smith) !void {
    const kek_len: usize = if (smith.value(bool)) 16 else 32;
    var kek_buf: [32]u8 = undefined;
    smith.bytes(kek_buf[0..kek_len]);
    const kek = kek_buf[0..kek_len];

    // n semiblocks, n in [2, 31] -> plaintext length in [16, 248], a
    // multiple of 8 as `wrap` requires. Drawn before the bytes it bounds,
    // same reasoning as above.
    const n = smith.valueRangeAtMost(u8, 2, 31);
    var pt_buf: [248]u8 = undefined;
    const pt_len = @as(usize, n) * 8;
    smith.bytes(pt_buf[0..pt_len]);
    const pt = pt_buf[0..pt_len];

    var ct_buf: [256]u8 = undefined;
    const ct = try wrap(kek, pt, &ct_buf);

    var out: [248]u8 = undefined;
    const recovered = try unwrap(kek, ct, &out);
    try std.testing.expectEqualSlices(u8, pt, recovered);
}

test "length + KEK validation (incl. the 192-bit-KEK std gap), with positive controls" {
    const kek = [_]u8{0} ** 16;
    var buf: [64]u8 = undefined;

    // Positive controls: the same shapes succeed at the boundary.
    _ = try wrap(&kek, &[_]u8{0} ** 16, &buf); // exactly 16 bytes: OK
    var ct: [24]u8 = undefined;
    _ = try wrap(&kek, &[_]u8{0} ** 16, &ct);
    var pt: [16]u8 = undefined;
    _ = try unwrap(&kek, &ct, &pt); // exactly 24 bytes: OK

    try std.testing.expectError(error.InvalidLength, wrap(&kek, &.{ 1, 2, 3 }, &buf)); // not a multiple of 8
    try std.testing.expectError(error.InvalidLength, wrap(&kek, &[_]u8{0} ** 8, &buf)); // < 16
    try std.testing.expectError(error.InvalidLength, unwrap(&kek, &[_]u8{0} ** 16, &buf)); // < 24
    try std.testing.expectError(error.BufferTooSmall, wrap(&kek, &[_]u8{0} ** 16, buf[0..16]));
    try std.testing.expectError(error.BufferTooSmall, unwrap(&kek, &ct, pt[0..8]));
    // Boundary: out short by exactly one byte must also be rejected, not just
    // a wildly-undersized buffer.
    try std.testing.expectError(error.BufferTooSmall, wrap(&kek, &[_]u8{0} ** 16, buf[0..23]));
    try std.testing.expectError(error.BufferTooSmall, unwrap(&kek, &ct, pt[0..15]));

    const kek192 = [_]u8{0} ** 24;
    try std.testing.expectError(error.UnsupportedKeyLength, wrap(&kek192, &[_]u8{0} ** 16, &buf));
    try std.testing.expectError(error.UnsupportedKeyLength, unwrap(&kek192, &[_]u8{0} ** 24, &buf));
}
