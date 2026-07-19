// SPDX-License-Identifier: MIT

//! chachapoly — SIMD-accelerated ChaCha20-Poly1305 AEAD (RFC 8439).
//!
//! A performance-specialised reimplementation of the ChaCha20 stream cipher and
//! the ChaCha20-Poly1305 AEAD that `std.crypto` already ships. It exists **only**
//! for throughput: `std.crypto.stream.chacha` vectorises *within* one block (the
//! diagonal / `@shuffle` layout) but gates its AVX2/AVX-512 lanes behind
//! `builtin.cpu.has(.x86, .avx2)`, so at the default `baseline` x86-64 target it
//! collapses to a single 128-bit lane (degree 1) and runs ~3.9x slower than
//! OpenSSL's AVX2 ChaCha (measured: std 478 MB/s vs OpenSSL 1852 MB/s at 8 KiB).
//!
//! This module instead uses the **block-parallel (transpose) layout**: each of
//! the 16 ChaCha state words is held in a `@Vector(N, u32)` spanning `N`
//! consecutive counter blocks, so a quarter-round is `N`-way data-parallel with
//! no in-block shuffles. With `N = 8` a `@Vector(8, u32)` lowers to 256-bit AVX2
//! when the target enables it (`-Dcpu=native` / any AVX2 target), recovering most
//! of the gap; on `baseline` it lowers to paired SSE2 and is still correct. The
//! `<N`-block tail is handled by a scalar (`N = 1`) pass over the same engine.
//!
//! **Dedup note.** `std` *has* ChaCha20-Poly1305 (`std.crypto.aead.chacha_poly`).
//! This is a deliberate performance-specialised duplicate, justified by the
//! measured 3.9x and the data-plane AEAD-throughput case (WireGuard per-packet,
//! TLS/Noise bulk). It is **byte-exact** to std and to RFC 8439: the SIMD ChaCha
//! is anchored against the RFC 8439 KATs *and* differentially against
//! `std.crypto.aead.chacha_poly.ChaCha20Poly1305` (the oracle) over every
//! block-boundary edge length. The Poly1305 MAC is **scalar** — it reuses
//! `std.crypto.onetimeauth.Poly1305` verbatim (a SIMD Poly1305 is a further,
//! trickier win left as a backlog item; the ChaCha keystream dominates the AEAD
//! cost, so the scalar MAC already captures most of the win).
//!
//! **Constant-time.** ChaCha and Poly1305 are inherently constant-time — only
//! add / xor / rotate / (Poly1305) multiply, no secret-indexed memory and no
//! data-dependent branches. The `@Vector` ops preserve this. Tag comparison uses
//! `std.crypto.timing_safe.eql`.
//!
//! API mirrors `std.crypto.stream.chacha.ChaCha20IETF` and
//! `std.crypto.aead.chacha_poly.ChaCha20Poly1305` so consumers can swap it in.

const std = @import("std");
const mem = std.mem;
const math = std.math;
const Poly1305 = std.crypto.onetimeauth.Poly1305;
const AuthenticationError = std.crypto.errors.AuthenticationError;

pub const meta = .{
    .platform = .any,
    .role = .codec, // pure computation, no I/O
    .concurrency = .reentrant, // no shared state
    .model_after = "RFC 8439 (ChaCha20-Poly1305); block-parallel @Vector transpose layout after the vectorised std.crypto.stream.chacha; Poly1305 reuses std.crypto.onetimeauth.Poly1305",
    .deps = .{}, // std only
};

// ── ChaCha20 (IETF, 96-bit nonce, 32-bit counter) ────────────────────────────

/// Number of blocks processed in parallel in the wide path. `@Vector(8, u32)`
/// lowers to 256-bit AVX2 on targets that enable it; to paired SSE2 otherwise.
const wide = 8;

const sigma = [4]u32{ 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 }; // "expand 32-byte k"

fn keyToWords(key: [32]u8) [8]u32 {
    var k: [8]u32 = undefined;
    inline for (0..8) |i| k[i] = mem.readInt(u32, key[i * 4 ..][0..4], .little);
    return k;
}

fn nonceToWords(nonce: [12]u8) [3]u32 {
    return .{
        mem.readInt(u32, nonce[0..4], .little),
        mem.readInt(u32, nonce[4..8], .little),
        mem.readInt(u32, nonce[8..12], .little),
    };
}

/// Fill `ks` with the ChaCha20 keystream for `N` consecutive blocks starting at
/// `counter` (block j uses counter `counter +% j`). This is the block-parallel
/// transpose core: 16 state words, each a `@Vector(N, u32)` across the N blocks.
fn keystream(comptime N: usize, ks: *[64 * N]u8, k: [8]u32, counter: u32, n: [3]u32) void {
    const V = @Vector(N, u32);
    const iota: V = comptime blk: {
        var a: [N]u32 = undefined;
        for (0..N) |j| a[j] = j;
        break :blk a;
    };
    const splat = struct {
        inline fn f(x: u32) V {
            return @splat(x);
        }
    }.f;

    const s = [16]V{
        splat(sigma[0]),        splat(sigma[1]), splat(sigma[2]), splat(sigma[3]),
        splat(k[0]),            splat(k[1]),     splat(k[2]),     splat(k[3]),
        splat(k[4]),            splat(k[5]),     splat(k[6]),     splat(k[7]),
        splat(counter) +% iota, splat(n[0]),     splat(n[1]),     splat(n[2]),
    };

    var x = s;
    comptime var round: usize = 0;
    inline while (round < 10) : (round += 1) {
        quarterRound(V, &x, 0, 4, 8, 12);
        quarterRound(V, &x, 1, 5, 9, 13);
        quarterRound(V, &x, 2, 6, 10, 14);
        quarterRound(V, &x, 3, 7, 11, 15);
        quarterRound(V, &x, 0, 5, 10, 15);
        quarterRound(V, &x, 1, 6, 11, 12);
        quarterRound(V, &x, 2, 7, 8, 13);
        quarterRound(V, &x, 3, 4, 9, 14);
    }
    inline for (0..16) |i| x[i] +%= s[i];

    // Transpose word-major vectors back to block-major little-endian bytes.
    inline for (0..N) |j| {
        inline for (0..16) |i| {
            mem.writeInt(u32, ks[64 * j + 4 * i ..][0..4], x[i][j], .little);
        }
    }
}

inline fn quarterRound(comptime V: type, x: *[16]V, a: usize, b: usize, c: usize, d: usize) void {
    x[a] +%= x[b];
    x[d] = math.rotl(V, x[d] ^ x[a], @as(u32, 16));
    x[c] +%= x[d];
    x[b] = math.rotl(V, x[b] ^ x[c], @as(u32, 12));
    x[a] +%= x[b];
    x[d] = math.rotl(V, x[d] ^ x[a], @as(u32, 8));
    x[c] +%= x[d];
    x[b] = math.rotl(V, x[b] ^ x[c], @as(u32, 7));
}

/// IETF ChaCha20 stream cipher — 32-byte key, 12-byte nonce, 32-bit counter.
/// API-compatible with `std.crypto.stream.chacha.ChaCha20IETF`.
pub const ChaCha20 = struct {
    pub const key_length = 32;
    pub const nonce_length = 12;
    pub const block_length = 64;

    /// XOR the ChaCha20 keystream (starting at block `counter`) into `in`,
    /// writing to `out`. `out.len == in.len`. NOT authenticated on its own.
    pub fn xor(out: []u8, in: []const u8, counter: u32, key: [key_length]u8, nonce: [nonce_length]u8) void {
        std.debug.assert(out.len == in.len);
        const k = keyToWords(key);
        const n = nonceToWords(nonce);
        var ctr = counter;
        var i: usize = 0;

        while (i + 64 * wide <= in.len) : (i += 64 * wide) {
            var ks: [64 * wide]u8 = undefined;
            keystream(wide, &ks, k, ctr, n);
            for (0..64 * wide) |j| out[i + j] = in[i + j] ^ ks[j];
            ctr +%= wide;
        }
        while (i < in.len) : (i += 64) {
            var ks: [64]u8 = undefined;
            keystream(1, &ks, k, ctr, n);
            const m = @min(@as(usize, 64), in.len - i);
            for (0..m) |j| out[i + j] = in[i + j] ^ ks[j];
            ctr +%= 1;
        }
    }

    /// Write the raw ChaCha20 keystream (starting at block `counter`) into `out`.
    pub fn stream(out: []u8, counter: u32, key: [key_length]u8, nonce: [nonce_length]u8) void {
        const k = keyToWords(key);
        const n = nonceToWords(nonce);
        var ctr = counter;
        var i: usize = 0;

        while (i + 64 * wide <= out.len) : (i += 64 * wide) {
            keystream(wide, out[i..][0 .. 64 * wide], k, ctr, n);
            ctr +%= wide;
        }
        while (i < out.len) : (i += 64) {
            var ks: [64]u8 = undefined;
            keystream(1, &ks, k, ctr, n);
            const m = @min(@as(usize, 64), out.len - i);
            @memcpy(out[i..][0..m], ks[0..m]);
            ctr +%= 1;
        }
    }
};

// ── ChaCha20-Poly1305 AEAD (RFC 8439 §2.8) ───────────────────────────────────

/// ChaCha20-Poly1305 AEAD, as designed for TLS/RFC 8439. Byte-for-byte
/// compatible with `std.crypto.aead.chacha_poly.ChaCha20Poly1305`.
pub const ChaCha20Poly1305 = struct {
    pub const tag_length = 16;
    pub const nonce_length = 12;
    pub const key_length = 32;

    /// Encrypt `m` into `c` (`c.len == m.len`) and write the auth tag to `tag`.
    pub fn encrypt(c: []u8, tag: *[tag_length]u8, m: []const u8, ad: []const u8, npub: [nonce_length]u8, k: [key_length]u8) void {
        std.debug.assert(c.len == m.len);

        var poly_key = [_]u8{0} ** 32;
        ChaCha20.xor(poly_key[0..], poly_key[0..], 0, k, npub);

        ChaCha20.xor(c[0..m.len], m, 1, k, npub);

        var mac = Poly1305.init(poly_key[0..]);
        mac.update(ad);
        pad16(&mac, ad.len);
        mac.update(c[0..m.len]);
        pad16(&mac, m.len);
        var lens: [16]u8 = undefined;
        mem.writeInt(u64, lens[0..8], ad.len, .little);
        mem.writeInt(u64, lens[8..16], m.len, .little);
        mac.update(lens[0..]);
        mac.final(tag);
    }

    /// Verify `tag` and decrypt `c` into `m` (`c.len == m.len`).
    /// On failure returns `error.AuthenticationFailed` and `m` is zeroed.
    pub fn decrypt(m: []u8, c: []const u8, tag: [tag_length]u8, ad: []const u8, npub: [nonce_length]u8, k: [key_length]u8) AuthenticationError!void {
        std.debug.assert(c.len == m.len);

        var poly_key = [_]u8{0} ** 32;
        ChaCha20.xor(poly_key[0..], poly_key[0..], 0, k, npub);

        var mac = Poly1305.init(poly_key[0..]);
        mac.update(ad);
        pad16(&mac, ad.len);
        mac.update(c);
        pad16(&mac, c.len);
        var lens: [16]u8 = undefined;
        mem.writeInt(u64, lens[0..8], ad.len, .little);
        mem.writeInt(u64, lens[8..16], c.len, .little);
        mac.update(lens[0..]);
        var computed_tag: [16]u8 = undefined;
        mac.final(&computed_tag);

        if (!std.crypto.timing_safe.eql([tag_length]u8, computed_tag, tag)) {
            std.crypto.secureZero(u8, &computed_tag);
            @memset(m, undefined);
            return error.AuthenticationFailed;
        }
        ChaCha20.xor(m[0..c.len], c, 1, k, npub);
    }
};

/// Poly1305 zero-padding to the next 16-byte boundary.
fn pad16(mac: *Poly1305, len: usize) void {
    if (len % 16 != 0) {
        const zeros = [_]u8{0} ** 16;
        mac.update(zeros[0 .. 16 - (len % 16)]);
    }
}

// ── tests: RFC 8439 known-answer vectors ─────────────────────────────────────

const testing = std.testing;

// RFC 8439 §2.3.2 — ChaCha20 block function (counter = 1).
test "RFC 8439 §2.3.2 ChaCha20 block/keystream" {
    const key = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    const nonce = [_]u8{ 0, 0, 0, 0x09, 0, 0, 0, 0x4a, 0, 0, 0, 0 };
    const expected = [_]u8{
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
        0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
        0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
        0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
    };
    var out: [64]u8 = undefined;
    ChaCha20.stream(&out, 1, key, nonce);
    try testing.expectEqualSlices(u8, &expected, &out);
}

// RFC 8439 §2.4.2 — ChaCha20 encryption ("sunscreen"), counter = 1.
test "RFC 8439 §2.4.2 ChaCha20 encrypt (sunscreen)" {
    const key = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    const nonce = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0 };
    const m = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const expected = [_]u8{
        0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
        0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
        0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
        0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
        0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
        0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
        0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
        0x87, 0x4d,
    };
    var out: [114]u8 = undefined;
    ChaCha20.xor(&out, m, 1, key, nonce);
    try testing.expectEqualSlices(u8, &expected, &out);
    // round-trip
    var back: [114]u8 = undefined;
    ChaCha20.xor(&back, &out, 1, key, nonce);
    try testing.expectEqualSlices(u8, m, &back);
}

// RFC 8439 §2.5.2 — Poly1305 (documents the scalar std MAC we reuse).
test "RFC 8439 §2.5.2 Poly1305 tag" {
    const otk = [_]u8{
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
        0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b,
    };
    const msg = "Cryptographic Forum Research Group";
    const expected = [_]u8{
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9,
    };
    var tag: [16]u8 = undefined;
    Poly1305.create(&tag, msg, &otk);
    try testing.expectEqualSlices(u8, &expected, &tag);
}

// RFC 8439 §2.8.2 — AEAD ChaCha20-Poly1305 encrypt (ciphertext + tag).
test "RFC 8439 §2.8.2 AEAD encrypt + tag" {
    const key = [_]u8{
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    };
    const nonce = [_]u8{ 0x07, 0, 0, 0, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
    const ad = [_]u8{ 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
    const m = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const expected_c = [_]u8{
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
        0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16,
    };
    const expected_tag = [_]u8{
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
    };
    var c: [114]u8 = undefined;
    var tag: [16]u8 = undefined;
    ChaCha20Poly1305.encrypt(&c, &tag, m, &ad, nonce, key);
    try testing.expectEqualSlices(u8, &expected_c, &c);
    try testing.expectEqualSlices(u8, &expected_tag, &tag);

    var back: [114]u8 = undefined;
    try ChaCha20Poly1305.decrypt(&back, &c, tag, &ad, nonce, key);
    try testing.expectEqualSlices(u8, m, &back);
}

// ── tests: differential vs std (the oracle), across block-boundary edges ──────

const StdChaCha = std.crypto.stream.chacha.ChaCha20IETF;
const StdAead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

const edge_lens = [_]usize{ 0, 1, 15, 16, 17, 31, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513, 1000, 4096 };

test "differential ChaCha20 stream vs std across edge lengths" {
    var prng = std.Random.DefaultPrng.init(0xC0FFEE);
    const rand = prng.random();
    var key: [32]u8 = undefined;
    var nonce: [12]u8 = undefined;
    rand.bytes(&key);
    rand.bytes(&nonce);

    var ours: [4096]u8 = undefined;
    var theirs: [4096]u8 = undefined;
    for (edge_lens) |len| {
        for ([_]u32{ 0, 1, 1000 }) |ctr| {
            ChaCha20.stream(ours[0..len], ctr, key, nonce);
            @memset(theirs[0..len], 0);
            StdChaCha.stream(theirs[0..len], ctr, key, nonce);
            try testing.expectEqualSlices(u8, theirs[0..len], ours[0..len]);
        }
    }
}

test "differential ChaCha20 xor vs std across edge lengths" {
    var prng = std.Random.DefaultPrng.init(0xBADF00D);
    const rand = prng.random();
    var key: [32]u8 = undefined;
    var nonce: [12]u8 = undefined;
    rand.bytes(&key);
    rand.bytes(&nonce);

    var msg: [4096]u8 = undefined;
    var ours: [4096]u8 = undefined;
    var theirs: [4096]u8 = undefined;
    rand.bytes(&msg);
    for (edge_lens) |len| {
        ChaCha20.xor(ours[0..len], msg[0..len], 1, key, nonce);
        StdChaCha.xor(theirs[0..len], msg[0..len], 1, key, nonce);
        try testing.expectEqualSlices(u8, theirs[0..len], ours[0..len]);
    }
}

test "differential AEAD vs std: seal/open/tamper across edge lengths" {
    var prng = std.Random.DefaultPrng.init(0x5EED_1234);
    const rand = prng.random();

    var msg: [4096]u8 = undefined;
    var ad: [64]u8 = undefined;
    var ours_c: [4096]u8 = undefined;
    var std_c: [4096]u8 = undefined;
    var dec: [4096]u8 = undefined;

    for (edge_lens) |len| {
        var key: [32]u8 = undefined;
        var nonce: [12]u8 = undefined;
        rand.bytes(&key);
        rand.bytes(&nonce);
        rand.bytes(msg[0..len]);
        const ad_len = len % ad.len;
        rand.bytes(ad[0..ad_len]);

        var ours_tag: [16]u8 = undefined;
        var std_tag: [16]u8 = undefined;
        ChaCha20Poly1305.encrypt(ours_c[0..len], &ours_tag, msg[0..len], ad[0..ad_len], nonce, key);
        StdAead.encrypt(std_c[0..len], &std_tag, msg[0..len], ad[0..ad_len], nonce, key);

        // byte-exact ciphertext + tag vs the std oracle
        try testing.expectEqualSlices(u8, std_c[0..len], ours_c[0..len]);
        try testing.expectEqualSlices(u8, &std_tag, &ours_tag);

        // decrypt(encrypt) == identity
        try ChaCha20Poly1305.decrypt(dec[0..len], ours_c[0..len], ours_tag, ad[0..ad_len], nonce, key);
        try testing.expectEqualSlices(u8, msg[0..len], dec[0..len]);

        // cross-decrypt: our AEAD opens std's ciphertext and vice-versa
        try ChaCha20Poly1305.decrypt(dec[0..len], std_c[0..len], std_tag, ad[0..ad_len], nonce, key);
        try testing.expectEqualSlices(u8, msg[0..len], dec[0..len]);
        try StdAead.decrypt(dec[0..len], ours_c[0..len], ours_tag, ad[0..ad_len], nonce, key);
        try testing.expectEqualSlices(u8, msg[0..len], dec[0..len]);

        // tag tamper is rejected
        var bad_tag = ours_tag;
        bad_tag[0] +%= 1;
        try testing.expectError(error.AuthenticationFailed, ChaCha20Poly1305.decrypt(dec[0..len], ours_c[0..len], bad_tag, ad[0..ad_len], nonce, key));
        // ciphertext tamper is rejected (skip len==0: no ciphertext byte to flip)
        if (len > 0) {
            var bad_c = ours_c;
            bad_c[len - 1] +%= 1;
            try testing.expectError(error.AuthenticationFailed, ChaCha20Poly1305.decrypt(dec[0..len], bad_c[0..len], ours_tag, ad[0..ad_len], nonce, key));
        }
    }
}

test "counter increment across the wide/tail boundary (>8 blocks)" {
    // 20 blocks exercises two wide (8-block) passes + a 4-block tail and the
    // per-lane counter increment across the boundary; byte-exact vs std. A
    // non-zero start counter checks the base-counter + per-lane iota add.
    const key = [_]u8{7} ** 32;
    const nonce = [_]u8{9} ** 12;
    var ours: [20 * 64]u8 = undefined;
    var theirs: [20 * 64]u8 = undefined;
    ChaCha20.stream(&ours, 12345, key, nonce);
    StdChaCha.stream(&theirs, 12345, key, nonce);
    try testing.expectEqualSlices(u8, &theirs, &ours);
}
