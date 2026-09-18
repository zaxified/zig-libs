// SPDX-License-Identifier: MIT

//! aescbc — raw AES-CBC block-cipher mode (NIST SP800-38A §6.2) over
//! `std.crypto.core.aes`'s `Aes128`/`Aes256`, plus the two padding schemes
//! that consumers in this repo compose CBC with.
//!
//! `std.crypto.core.aes` (Zig 0.16) ships the AES block cipher but no CBC
//! mode — CBC has been hand-rolled independently in `xmlenc` (XML-Encryption
//! content decryption, W3C xmlenc padding) and `jwe` (`A128CBC-HS256` /
//! `A256CBC-HS512`, RFC 7518 §5.2, PKCS#7 padding). This module extracts a
//! single well-tested core so both can collapse onto it.
//!
//! **AES-192 is not offered.** `std.crypto.core.aes` exports only
//! `Aes128`/`Aes256` in 0.16 (no AES-192 key schedule in any backend); since
//! this module is comptime-generic over the block-cipher type rather than
//! dispatching on a runtime key-length enum, an AES-192 caller gets a
//! compile error selecting `Aes128`/`Aes256`, not a runtime
//! `error.UnsupportedKeyLength` — there is no third type to pass. Callers
//! that dispatch on a runtime algorithm identifier (as `jwe`/`xmlenc` do)
//! are expected to reject AES-192 themselves before reaching this module,
//! exactly as they already do.
//!
//! See SPEC.md for the padding-oracle caveat and which consumer uses which
//! padding scheme.

const std = @import("std");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Raw AES-CBC (NIST SP800-38A) + PKCS#7/XML-Enc padding helpers, zero-alloc; padding-oracle caveat — consumers own authenticate-before-unpad",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util,
    .concurrency = .reentrant,
    .model_after = "NIST SP800-38A §6.2 (CBC mode); RFC 5652 §6.3 (PKCS#7 padding); W3C XML-Encryption Syntax and Processing 1.1 §5.2 (xmlenc padding)",
    .deps = .{},
};

/// AES block size in bytes (fixed at 128 bits regardless of key length).
pub const block_len = 16;

/// Raw-CBC errors (no padding involved).
pub const Error = error{
    /// `plaintext`/`ciphertext` length is not a multiple of `block_len`.
    /// Raw CBC only operates on block-aligned buffers; pad first.
    NotBlockAligned,
    /// `out` is smaller than the input.
    BufferTooSmall,
};

/// Padding-helper errors. Deliberately a single generic member: CBC padding
/// oracles (Vaudenay) are built by distinguishing *why* an unpad failed, so
/// every malformed-padding shape below collapses to this one error — never
/// branch a caller's control flow on anything more specific. See SPEC.md.
pub const PaddingError = error{InvalidPadding};

/// Encrypt `plaintext` (must be `block_len`-aligned) into `out` under raw
/// CBC: `C[0] = E(P[0] XOR IV)`, `C[i] = E(P[i] XOR C[i-1])`. `Aes` is
/// `std.crypto.core.aes.Aes128` or `Aes256`; `key` is
/// `[Aes.key_bits / 8]u8`. `out` must be at least `plaintext.len` bytes.
/// No allocation. Returns the written length (== `plaintext.len`).
/// Zeroization posture (CONVENTIONS §2.1): nothing here is wiped, deliberately.
/// The AES round-key schedule (`Aes.initEnc`/`initDec`'s context) and the
/// per-block staging buffers are Z3 — the internal working state of a
/// transform, which `std`'s own `core.aes` does not wipe either. `key` and `iv`
/// arrive by value from caller-owned storage (Z2): the caller wipes those, and
/// the plaintext/ciphertext live in the caller's `out`/input slices, which the
/// caller likewise owns. This module allocates nothing and holds nothing across
/// calls, so it has no Z1 storage at all.
pub fn encrypt(
    comptime Aes: type,
    key: [Aes.key_bits / 8]u8,
    iv: [block_len]u8,
    plaintext: []const u8,
    out: []u8,
) Error!usize {
    if (plaintext.len % block_len != 0) return error.NotBlockAligned;
    if (out.len < plaintext.len) return error.BufferTooSmall;

    const ctx = Aes.initEnc(key);
    var prev: [block_len]u8 = iv;
    var i: usize = 0;
    while (i < plaintext.len) : (i += block_len) {
        var block: [block_len]u8 = plaintext[i..][0..block_len].*;
        for (&block, prev) |*b, p| b.* ^= p;
        ctx.encrypt(&block, &block);
        @memcpy(out[i..][0..block_len], &block);
        prev = block;
    }
    return plaintext.len;
}

/// Decrypt `ciphertext` (must be `block_len`-aligned) into `out` under raw
/// CBC: `P[0] = D(C[0]) XOR IV`, `P[i] = D(C[i]) XOR C[i-1]`. Same `Aes`/
/// `key`/`iv` contract as `encrypt`. No allocation, no padding stripped —
/// pair with `unpadPkcs7`/`unpadXmlEnc` as needed. Returns the written
/// length (== `ciphertext.len`).
pub fn decrypt(
    comptime Aes: type,
    key: [Aes.key_bits / 8]u8,
    iv: [block_len]u8,
    ciphertext: []const u8,
    out: []u8,
) Error!usize {
    if (ciphertext.len % block_len != 0) return error.NotBlockAligned;
    if (out.len < ciphertext.len) return error.BufferTooSmall;

    const ctx = Aes.initDec(key);
    var prev: [block_len]u8 = iv;
    var i: usize = 0;
    while (i < ciphertext.len) : (i += block_len) {
        const ct_block: [block_len]u8 = ciphertext[i..][0..block_len].*;
        var pt: [block_len]u8 = undefined;
        ctx.decrypt(&pt, &ct_block);
        for (&pt, prev) |*b, p| b.* ^= p;
        @memcpy(out[i..][0..block_len], &pt);
        prev = ct_block;
    }
    return ciphertext.len;
}

// ── PKCS#7 padding (RFC 5652 §6.3) ──────────────────────────────────────────
//
// Every pad byte equals the pad length N (1 <= N <= block_len). Always pads,
// even when the message is already block-aligned (a full-block message gains
// one whole pad block) — that is what makes unpadding unambiguous. This is
// the scheme `jwe`'s `A128CBC-HS256`/`A256CBC-HS512` (RFC 7518 §5.2.2.1
// step 2) needs.

/// PKCS#7-padded length for a `msg_len`-byte message. Always adds between 1
/// and `block_len` bytes (never zero).
pub fn paddedLenPkcs7(msg_len: usize) usize {
    return msg_len + (block_len - msg_len % block_len);
}

/// Write `msg` followed by PKCS#7 padding into `out`. `out` must be at least
/// `paddedLenPkcs7(msg.len)` bytes. Returns the padded length.
pub fn padPkcs7(msg: []const u8, out: []u8) error{BufferTooSmall}!usize {
    const padded_len = paddedLenPkcs7(msg.len);
    if (out.len < padded_len) return error.BufferTooSmall;
    @memcpy(out[0..msg.len], msg);
    const pad: u8 = @intCast(padded_len - msg.len);
    @memset(out[msg.len..padded_len], pad);
    return padded_len;
}

/// Strip PKCS#7 padding from a decrypted, block-aligned buffer. Validates
/// `1 <= N <= block_len` AND that all N trailing bytes equal N, accumulating
/// every check into a single flag with no secret-dependent early exit (no
/// distinct control-flow signal for "bad length" vs. "bad pad byte") before
/// returning `InvalidPadding`. Returns the unpadded length on success.
///
/// ⭐ MEASURED, not reviewed (`src/ctgrind_harness.zig`, target `pkcs7`; the
/// row is pinned in `scripts/checks/ctgrind-expected.tsv`). With the whole padded
/// buffer marked undefined, memcheck reports ONE context in this file, at the
/// `if (invalid != 0)` below — the accept/reject decision this function returns
/// to its caller anyway. The scan loop contributes none, so there is no early
/// exit and no per-reason signal, which is what the paragraph above claims.
/// It is measured because the same `@intFromBool`/`u1` idiom did NOT survive
/// the compiler in `fss` (`dpf.zig:326`): written branch-free, lowered to a
/// jump on the secret at one of its three call sites. Reading this code is not
/// evidence about the binary built from it.
pub fn unpadPkcs7(buf: []const u8) PaddingError!usize {
    if (buf.len == 0 or buf.len % block_len != 0) return error.InvalidPadding;
    const n = buf[buf.len - 1];
    var invalid: u1 = @intFromBool(n == 0) | @intFromBool(n > block_len);
    // Clamp so the scan below stays in bounds even for an out-of-range `n`
    // (`invalid` is already latched in that case).
    const pad_len: usize = @min(@as(usize, n), block_len);
    var k: usize = 0;
    while (k < block_len) : (k += 1) {
        const in_pad: u1 = @intFromBool(k < pad_len);
        const mismatch: u1 = @intFromBool(buf[buf.len - 1 - k] != n);
        invalid |= in_pad & mismatch;
    }
    if (invalid != 0) return error.InvalidPadding;
    return buf.len - pad_len;
}

// ── XML-Encryption padding (W3C xmlenc-core-1 §5.2) ─────────────────────────
//
// The FINAL byte N (1 <= N <= block_len) is the pad length; the preceding
// N-1 pad bytes are ARBITRARY — only the length byte is meaningful, unlike
// PKCS#7. This is the scheme `xmlenc`'s AES-CBC content decryption needs.
// There is deliberately no `padXmlEnc`: this module only ever needs to
// *decrypt* XML-Enc (xmlenc is a decryption-only module; see its SPEC.md),
// and an encoder is free to fill the non-final pad bytes with anything,
// including zero — `padPkcs7` already produces a valid XML-Enc padding as a
// special case if a caller ever needs to encrypt one.

/// Strip XML-Encryption padding from a decrypted, block-aligned buffer.
/// Validates only `1 <= N <= block_len` (the non-final pad bytes are
/// unconstrained by the scheme itself, so there is nothing else to check) and
/// returns `InvalidPadding` on an out-of-range length byte. Returns the
/// unpadded length on success.
///
/// Branch-free on `N` itself, matching `unpadPkcs7`'s shape: `N` is the LAST
/// byte of the just-decrypted plaintext, i.e. secret-derived, so a data-
/// dependent early `if (n == 0 or n > block_len)` would branch on that secret
/// byte. The check used to do exactly that; accumulating into `invalid` and
/// branching only once, on a value that no longer varies with `N`'s specific
/// magnitude beyond in/out of range, closes that gap the way `unpadPkcs7`
/// already does. No *additional* leak follows from the old shape beyond what
/// the return value (accept/reject) already reveals — `xmlenc`'s decrypt path
/// has no MAC ahead of this CBC decrypt, so accept/reject is observable
/// either way — but this SPEC previously claimed BOTH helpers were
/// branch-free when only `unpadPkcs7` was; this makes the claim true.
pub fn unpadXmlEnc(buf: []const u8) PaddingError!usize {
    if (buf.len == 0 or buf.len % block_len != 0) return error.InvalidPadding;
    const n = buf[buf.len - 1];
    const invalid: u1 = @intFromBool(n == 0) | @intFromBool(n > block_len);
    const pad_len: usize = @min(@as(usize, n), block_len);
    if (invalid != 0) return error.InvalidPadding;
    return buf.len - pad_len;
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

/// Test-only (`build.zig`'s `test_deps`, never `deps`): the fuzz corpus seed
/// helpers, in the format `std.testing.Smith` actually reads.
const testkit = @import("testkit");

const Aes128 = std.crypto.core.aes.Aes128;
const Aes256 = std.crypto.core.aes.Aes256;

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

// NIST SP800-38A Appendix F.2.1 — CBC-AES128.Encrypt/Decrypt.
const f_2_1_key = hex("2b7e151628aed2a6abf7158809cf4f3c");
const f_2_1_iv = hex("000102030405060708090a0b0c0d0e0f");
const f_2_1_plaintext = hex("6bc1bee22e409f96e93d7e117393172a" ++
    "ae2d8a571e03ac9c9eb76fac45af8e51" ++
    "30c81c46a35ce411e5fbc1191a0a52ef" ++
    "f69f2445df4f9b17ad2b417be66c3710");
const f_2_1_ciphertext = hex("7649abac8119b246cee98e9b12e9197d" ++
    "5086cb9b507219ee95db113a917678b2" ++
    "73bed6b8e3c1743b7116e69e22229516" ++
    "3ff1caa1681fac09120eca307586e1a7");

// NIST SP800-38A Appendix F.2.5 — CBC-AES256.Encrypt/Decrypt (also
// transcribed in ctap2pin/src/kat_vectors.zig and xmlenc/src/root.zig).
const f_2_5_key = hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
const f_2_5_iv = f_2_1_iv;
const f_2_5_plaintext = f_2_1_plaintext;
const f_2_5_ciphertext = hex("f58c4c04d6e5f1ba779eabfb5f7bfbd6" ++
    "9cfc4e967edb808d679f777bc6702c7d" ++
    "39f23369a9d9bacfa530e26304231461" ++
    "b2eb05e2c39be9fcda6c19078c6a9d1b");

test "NIST SP800-38A F.2.1 (AES-128-CBC): byte-exact encrypt" {
    var out: [f_2_1_plaintext.len]u8 = undefined;
    const n = try encrypt(Aes128, f_2_1_key, f_2_1_iv, &f_2_1_plaintext, &out);
    try testing.expectEqualSlices(u8, &f_2_1_ciphertext, out[0..n]);
}

test "NIST SP800-38A F.2.1 (AES-128-CBC): byte-exact decrypt" {
    var out: [f_2_1_ciphertext.len]u8 = undefined;
    const n = try decrypt(Aes128, f_2_1_key, f_2_1_iv, &f_2_1_ciphertext, &out);
    try testing.expectEqualSlices(u8, &f_2_1_plaintext, out[0..n]);
}

test "NIST SP800-38A F.2.5 (AES-256-CBC): byte-exact encrypt" {
    var out: [f_2_5_plaintext.len]u8 = undefined;
    const n = try encrypt(Aes256, f_2_5_key, f_2_5_iv, &f_2_5_plaintext, &out);
    try testing.expectEqualSlices(u8, &f_2_5_ciphertext, out[0..n]);
}

test "NIST SP800-38A F.2.5 (AES-256-CBC): byte-exact decrypt" {
    var out: [f_2_5_ciphertext.len]u8 = undefined;
    const n = try decrypt(Aes256, f_2_5_key, f_2_5_iv, &f_2_5_ciphertext, &out);
    try testing.expectEqualSlices(u8, &f_2_5_plaintext, out[0..n]);
}

test "raw CBC rejects non-block-aligned input" {
    var out: [32]u8 = undefined;
    try testing.expectError(error.NotBlockAligned, encrypt(Aes128, f_2_1_key, f_2_1_iv, "not sixteen", &out));
    try testing.expectError(error.NotBlockAligned, decrypt(Aes128, f_2_1_key, f_2_1_iv, "not sixteen", &out));
}

test "raw CBC rejects an undersized out buffer" {
    var out: [16]u8 = undefined; // plaintext is 2 blocks, out is 1
    const pt = [_]u8{0x41} ** 32;
    try testing.expectError(error.BufferTooSmall, encrypt(Aes128, f_2_1_key, f_2_1_iv, &pt, &out));
}

test "raw CBC decrypt rejects an undersized out buffer" {
    var out: [16]u8 = undefined; // ciphertext is 2 blocks, out is 1
    const ct = [_]u8{0x41} ** 32;
    try testing.expectError(error.BufferTooSmall, decrypt(Aes128, f_2_1_key, f_2_1_iv, &ct, &out));
}

test "raw CBC round-trip: empty message" {
    var out: [0]u8 = undefined;
    const n = try encrypt(Aes128, f_2_1_key, f_2_1_iv, "", &out);
    try testing.expectEqual(@as(usize, 0), n);
    const m = try decrypt(Aes128, f_2_1_key, f_2_1_iv, "", &out);
    try testing.expectEqual(@as(usize, 0), m);
}

test "raw CBC round-trip: multi-block message, self-consistency" {
    const key = [_]u8{0x5a} ** 32;
    const iv = [_]u8{0x11} ** block_len;
    // Four AES blocks (64 bytes) of distinguishable, non-repeating content.
    var pt: [64]u8 = undefined;
    for (&pt, 0..) |*b, i| b.* = @truncate(i);

    var ct: [pt.len]u8 = undefined;
    _ = try encrypt(Aes256, key, iv, &pt, &ct);
    var recovered: [pt.len]u8 = undefined;
    const n = try decrypt(Aes256, key, iv, &ct, &recovered);
    try testing.expectEqualSlices(u8, &pt, recovered[0..n]);
}

// ── PKCS#7 tests ─────────────────────────────────────────────────────────────

test "PKCS#7 pad/unpad round-trip: not block-aligned" {
    const msg = "seventeen bytes!!"; // 17 bytes -> one full block + 1 pad block
    var padded: [32]u8 = undefined;
    const n = try padPkcs7(msg, &padded);
    try testing.expectEqual(@as(usize, 32), n);
    try testing.expectEqual(@as(usize, 32), paddedLenPkcs7(msg.len));
    // Trailing 15 bytes are all 0x0f (pad length 15).
    for (padded[17..32]) |b| try testing.expectEqual(@as(u8, 15), b);

    const m = try unpadPkcs7(padded[0..n]);
    try testing.expectEqualStrings(msg, padded[0..m]);
}

test "PKCS#7 pad/unpad round-trip: exactly block-aligned still gains a full pad block" {
    const msg = [_]u8{0x42} ** 16;
    var padded: [32]u8 = undefined;
    const n = try padPkcs7(&msg, &padded);
    try testing.expectEqual(@as(usize, 32), n);
    for (padded[16..32]) |b| try testing.expectEqual(@as(u8, 16), b);

    const m = try unpadPkcs7(padded[0..n]);
    try testing.expectEqualSlices(u8, &msg, padded[0..m]);
}

test "PKCS#7 pad/unpad round-trip through real CBC encrypt/decrypt" {
    const key = [_]u8{0x33} ** 16;
    const iv = [_]u8{0x44} ** block_len;
    const msg = "A message that is not a multiple of the block size.";

    var padded: [128]u8 = undefined;
    const padded_len = try padPkcs7(msg, &padded);

    var ct: [128]u8 = undefined;
    _ = try encrypt(Aes128, key, iv, padded[0..padded_len], ct[0..padded_len]);

    var pt: [128]u8 = undefined;
    _ = try decrypt(Aes128, key, iv, ct[0..padded_len], pt[0..padded_len]);
    const n = try unpadPkcs7(pt[0..padded_len]);
    try testing.expectEqualStrings(msg, pt[0..n]);
}

test "PKCS#7 unpad rejects: zero-length pad byte (0x00)" {
    var buf = [_]u8{0x41} ** block_len;
    buf[block_len - 1] = 0x00;
    try testing.expectError(error.InvalidPadding, unpadPkcs7(&buf));
}

test "PKCS#7 unpad rejects: pad length > block_len" {
    var buf = [_]u8{0x41} ** block_len;
    buf[block_len - 1] = 0x11; // 17 > 16
    try testing.expectError(error.InvalidPadding, unpadPkcs7(&buf));
}

test "PKCS#7 unpad rejects: inconsistent pad bytes" {
    var buf = [_]u8{0x41} ** block_len;
    buf[block_len - 1] = 0x04; // claims last 4 bytes == 0x04
    buf[block_len - 2] = 0x04;
    buf[block_len - 3] = 0x04;
    buf[block_len - 4] = 0x99; // ...but this one doesn't match
    try testing.expectError(error.InvalidPadding, unpadPkcs7(&buf));
}

test "PKCS#7 unpad rejects: empty or non-block-aligned buffer" {
    try testing.expectError(error.InvalidPadding, unpadPkcs7(&[_]u8{}));
    try testing.expectError(error.InvalidPadding, unpadPkcs7(&[_]u8{ 1, 2, 3 }));
}

test "PKCS#7 unpad accepts: pad length == block_len with a full pad block, empty-ish message" {
    const buf = [_]u8{0x10} ** block_len; // valid: N=16, all 16 bytes == 16
    const n = try unpadPkcs7(&buf);
    try testing.expectEqual(@as(usize, 0), n);
}

// ── XML-Enc padding tests ────────────────────────────────────────────────────

test "XML-Enc unpad accepts a valid pad with arbitrary non-final pad bytes" {
    var buf = [_]u8{0x41} ** block_len;
    buf[block_len - 1] = 0x04; // N=4
    buf[block_len - 2] = 0xAA; // arbitrary, NOT required to equal N
    buf[block_len - 3] = 0x00; // arbitrary
    buf[block_len - 4] = 0xFF; // arbitrary
    const n = try unpadXmlEnc(&buf);
    try testing.expectEqual(@as(usize, block_len - 4), n);
}

test "XML-Enc unpad accepts: pad length == block_len with a full pad block, empty-ish message" {
    const buf = [_]u8{0x10} ** block_len; // valid: N=16, all 16 bytes are pad
    const n = try unpadXmlEnc(&buf);
    try testing.expectEqual(@as(usize, 0), n);
}

test "XML-Enc unpad rejects: zero-length pad byte" {
    var buf = [_]u8{0x41} ** block_len;
    buf[block_len - 1] = 0x00;
    try testing.expectError(error.InvalidPadding, unpadXmlEnc(&buf));
}

test "XML-Enc unpad rejects: pad length > block_len" {
    var buf = [_]u8{0x41} ** block_len;
    buf[block_len - 1] = 0xFF;
    try testing.expectError(error.InvalidPadding, unpadXmlEnc(&buf));
}

test "XML-Enc unpad rejects: empty or non-block-aligned buffer" {
    try testing.expectError(error.InvalidPadding, unpadXmlEnc(&[_]u8{}));
    try testing.expectError(error.InvalidPadding, unpadXmlEnc(&[_]u8{ 1, 2, 3, 4 }));
}

test "XML-Enc unpad round-trip through real CBC encrypt/decrypt" {
    const key = [_]u8{0x77} ** 32;
    const iv = [_]u8{0x88} ** block_len;
    const msg = "recovered plaintext";
    // xmlenc-style pad: last byte = N, preceding N-1 bytes arbitrary (use
    // PKCS#7's own construction here as one valid instance of the scheme).
    var padded: [64]u8 = undefined;
    const padded_len = try padPkcs7(msg, &padded);

    var ct: [64]u8 = undefined;
    _ = try encrypt(Aes256, key, iv, padded[0..padded_len], ct[0..padded_len]);
    var pt: [64]u8 = undefined;
    _ = try decrypt(Aes256, key, iv, ct[0..padded_len], pt[0..padded_len]);
    const n = try unpadXmlEnc(pt[0..padded_len]);
    try testing.expectEqualStrings(msg, pt[0..n]);
}

// ── fuzz: the unpad guards, on arbitrary decrypted-buffer content ──────────
//
// W2 A3 (F2): CLASS B, zero `testing.fuzz(` harnesses — this module was
// absent from `scripts/fuzz-sweep.sh`'s target list entirely. Per the
// campaign brief, `encrypt`/`decrypt`'s AES-CBC core is a crypto primitive
// already pinned byte-exact against NIST SP800-38A above; fuzzing it again
// would duplicate the KATs, not add to them. The genuinely untested-by-fuzz
// surface is the framing/parsing logic in `unpadPkcs7`/`unpadXmlEnc`: both
// consume a buffer that, on a chosen-ciphertext path, is attacker-shaped
// (the audit's own framing — F2's evidence column).
//
// Oracle: not "never panics" alone. Success from either function is a
// specific, checkable claim about the buffer's *last byte* and (for PKCS#7)
// every byte in the claimed pad — so the harness asserts that claim holds,
// which is strictly stronger than surviving without a crash.
// ⚠ Both halves of this harness were dead until 2026-09-07. It opened with
//
//     const len = smith.valueRangeAtMost(u16, 0, buf.len);
//     smith.bytes(buf[0..len]);
//
// and carried no corpus. A ranged draw reads eight octets as a little-endian
// u64 and returns the range MINIMUM when fewer than eight remain, so `len` was
// 0 on every input — and the comment that used to sit here, "length drawn first
// so every mutated byte lands inside `data`", described a `data` that was
// always empty. `unpadPkcs7("")`/`unpadXmlEnc("")` both return `InvalidPadding`
// at the first line, so NEITHER of the two invariant blocks below had ever
// executed a single assertion.
//
// The fix is one byte-first draw (`smith.slice`) plus a corpus: a random
// 16-octet buffer ends in a pad byte in `1..16` about 6% of the time, so
// arbitrary bytes do reach the success path eventually, but not in the one
// input the ordinary lane runs. The seeds below pin both accepting shapes and
// the four distinct refusals.
const unpad_seeds = [_][]const u8{
    // PKCS#7-valid, one block: 11 octets of message + 5 × 0x05.
    testkit.fuzz.seedHex("6161616161616161616161" ++ "0505050505"),
    // PKCS#7-valid, two blocks, a full block of padding (N = 16).
    testkit.fuzz.seedHex("00112233445566778899aabbccddeeff" ++ ("10" ** 16)),
    // PKCS#7-valid with N = 1: the shortest pad the scheme allows.
    testkit.fuzz.seedHex("000102030405060708090a0b0c0d0e" ++ "01"),
    // ⭐ The scheme split: last byte 0x10 but the preceding 15 are not, so
    // PKCS#7 refuses and XML-Enc — which only reads the LENGTH byte — accepts
    // and returns 0. The one seed that tells the two functions apart.
    testkit.fuzz.seedHex(("a5" ** 15) ++ "10"),
    // N = 0: refused by both, and the reason `unpadPkcs7` latches a flag
    // instead of returning early.
    testkit.fuzz.seedHex(("a5" ** 15) ++ "00"),
    // N = 17 > block_len: refused by both, and the input that would run the
    // `@min` clamp off the end of the buffer if it were not clamped.
    testkit.fuzz.seedHex(("a5" ** 15) ++ "11"),
    // 20 octets: not block-aligned, refused before the last byte is read.
    testkit.fuzz.seedHex("00112233445566778899aabbccddeeff" ++ "05050505"),
    // The input this target ran, and only ran, for ever.
    testkit.fuzz.seed(""),
};

test "fuzz: unpad functions never panic, and a successful unpad's invariant actually holds" {
    try testing.fuzz({}, fuzzUnpad, .{ .corpus = &unpad_seeds });
}

fn fuzzUnpad(_: void, smith: *testing.Smith) !void {
    // One byte-first draw: the length is the seed's own, not a collapsing
    // ranged draw taken before it.
    var buf: [512]u8 = undefined;
    const len = smith.slice(&buf);
    const data = buf[0..len];

    if (unpadPkcs7(data)) |n| {
        try testing.expect(data.len > 0 and data.len % block_len == 0);
        const pad = data[data.len - 1];
        try testing.expect(pad >= 1 and pad <= block_len);
        try testing.expectEqual(data.len - @as(usize, pad), n);
        for (data[n..]) |b| try testing.expectEqual(pad, b);
    } else |_| {}

    if (unpadXmlEnc(data)) |n| {
        try testing.expect(data.len > 0 and data.len % block_len == 0);
        const pad = data[data.len - 1];
        try testing.expect(pad >= 1 and pad <= block_len);
        try testing.expectEqual(data.len - @as(usize, pad), n);
    } else |_| {}
}

test "corpus: every unpad seed reaches the guards, counts pinned" {
    var nonempty: usize = 0;
    var pkcs7_ok: usize = 0;
    var xmlenc_ok: usize = 0;
    // ⛔ A count of successes alone would not notice a corpus that collapsed to
    // one seed. `pkcs7_octets` is the number the empty input cannot make: it
    // only moves when a seed's OWN length and pad byte were both read.
    var pkcs7_octets: usize = 0;
    for (unpad_seeds) |sd| {
        var smith: testing.Smith = .{ .in = sd };
        var buf: [512]u8 = undefined;
        const len = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        if (unpadPkcs7(buf[0..len])) |n| {
            pkcs7_ok += 1;
            pkcs7_octets += n;
        } else |_| {}
        if (unpadXmlEnc(buf[0..len])) |_| {
            xmlenc_ok += 1;
        } else |_| {}
    }
    try testing.expectEqual(unpad_seeds.len - 1, nonempty); // the last seed is empty
    try testing.expectEqual(@as(usize, 3), pkcs7_ok);
    // One more than PKCS#7: the "length byte only" seed, which is the whole
    // difference between the two schemes.
    try testing.expectEqual(@as(usize, 4), xmlenc_ok);
    try testing.expectEqual(@as(usize, 42), pkcs7_octets); // 11 + 16 + 15
}

test "raw CBC vs jwe's/xmlenc's hand-rolled shape: same output on the same input" {
    // Sanity oracle: reproduce the loop shape from jwe/src/enc.zig and
    // xmlenc/src/root.zig using ONLY std.crypto (not this module's own
    // encrypt/decrypt) and confirm they agree with the module.
    const key = [_]u8{0x21} ** 16;
    const iv = [_]u8{0x22} ** block_len;
    const pt = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 } ** 2;

    var expected: [pt.len]u8 = undefined;
    {
        const ctx = Aes128.initEnc(key);
        var prev: [block_len]u8 = iv;
        var i: usize = 0;
        while (i < pt.len) : (i += block_len) {
            var block: [block_len]u8 = pt[i..][0..block_len].*;
            for (&block, prev) |*b, p| b.* ^= p;
            ctx.encrypt(&block, &block);
            @memcpy(expected[i..][0..block_len], &block);
            prev = block;
        }
    }

    var out: [pt.len]u8 = undefined;
    _ = try encrypt(Aes128, key, iv, &pt, &out);
    try testing.expectEqualSlices(u8, &expected, &out);
}
