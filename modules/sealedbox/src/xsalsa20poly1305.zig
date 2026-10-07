// SPDX-License-Identifier: MIT
//! XSalsa20-Poly1305 (NaCl `crypto_secretbox`) with a multi-block Salsa20.
//!
//! `std.crypto.stream.salsa` computes one 64-byte block at a time (one block
//! per 4-lane vector), which held `seal`/`open` of 64 KiB at ~2.4x libsodium's
//! time (SPEC.md § Performance). Here Salsa20 runs `lanes` blocks side by side:
//! state word `i` of all blocks lives in one `@Vector(lanes, u32)`, so a round
//! is 16 plain vector add/rotate/xor chains with no shuffles. Keystream is
//! byte-identical to std's (pinned by the differential tests below and the
//! PyNaCl KATs in kat_test.zig); only the schedule differs.
//!
//! Salsa20, HSalsa20 and XSalsa20 are D. J. Bernstein's public-domain
//! designs ("Salsa20 specification", "Extending the Salsa20 nonce"). No
//! third-party source was copied.

const std = @import("std");
const mem = std.mem;
const math = std.math;
const crypto = std.crypto;

pub const poly1305 = @import("poly1305.zig");

pub const key_length = 32;
pub const nonce_length = 24;
pub const tag_length = poly1305.mac_length;

const sigma = [4]u32{ 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 }; // "expand 32-byte k"

/// Blocks computed per batch: the target's natural u32 vector width
/// (8 with AVX2, 4 with SSE/NEON), at least 4.
const lanes = @max(4, std.simd.suggestVectorLength(u32) orelse 4);

fn Lanes(comptime n: comptime_int) type {
    return @Vector(n, u32);
}

inline fn quarter(comptime V: type, x: *[16]V, comptime a: usize, comptime b: usize, comptime c: usize, comptime d: usize) void {
    x[b] ^= math.rotl(V, x[a] +% x[d], 7);
    x[c] ^= math.rotl(V, x[b] +% x[a], 9);
    x[d] ^= math.rotl(V, x[c] +% x[b], 13);
    x[a] ^= math.rotl(V, x[d] +% x[c], 18);
}

inline fn doubleRounds(comptime V: type, x: *[16]V) void {
    for (0..10) |_| {
        quarter(V, x, 0, 4, 8, 12);
        quarter(V, x, 5, 9, 13, 1);
        quarter(V, x, 10, 14, 2, 6);
        quarter(V, x, 15, 3, 7, 11);
        quarter(V, x, 0, 1, 2, 3);
        quarter(V, x, 5, 6, 7, 4);
        quarter(V, x, 10, 11, 8, 9);
        quarter(V, x, 15, 12, 13, 14);
    }
}

/// The Salsa20 input words for `key` and an 8-byte `nonce`; words 8 and 9
/// (the block counter) are left to the caller.
fn baseState(key: *const [8]u32, nonce: [2]u32) [16]u32 {
    return .{
        sigma[0], key[0],   key[1],   key[2],
        key[3],   sigma[1], nonce[0], nonce[1],
        0,        0,        sigma[2], key[4],
        key[5],   key[6],   key[7],   sigma[3],
    };
}

/// XOR `n` consecutive keystream blocks starting at block `counter` into
/// `in`, writing `out` (both exactly `64 * n` bytes).
inline fn xorBlocks(comptime n: comptime_int, out: []u8, in: []const u8, base: *const [16]u32, counter: u64) void {
    const V = Lanes(n);
    var x: [16]V = undefined;
    inline for (0..16) |i| x[i] = @splat(base[i]);
    var lo: V = undefined;
    var hi: V = undefined;
    inline for (0..n) |b| {
        const c = counter +% b;
        lo[b] = @truncate(c);
        hi[b] = @truncate(c >> 32);
    }
    x[8] = lo;
    x[9] = hi;
    doubleRounds(V, &x);
    // Feed-forward from the inputs rebuilt, not a saved copy: 16 more live
    // vectors would spill the round loop.
    inline for (0..16) |i| x[i] +%= switch (i) {
        8 => lo,
        9 => hi,
        else => @as(V, @splat(base[i])),
    };

    if (n == 1) {
        inline for (0..16) |i| {
            const w = mem.readInt(u32, in[4 * i ..][0..4], .little) ^ x[i][0];
            mem.writeInt(u32, out[4 * i ..][0..4], w, .little);
        }
        return;
    }
    // Words 4q..: of every block sit in lane b of x[4q..]; transposing each
    // n x n group turns them into one vector per block, XORed in one go.
    inline for (0..16 / n) |q| {
        var t: [n]V = x[n * q ..][0..n].*;
        transpose(n, &t);
        inline for (0..n) |b| {
            const off = 64 * b + 4 * n * q;
            const ks = if (native_le) t[b] else @byteSwap(t[b]);
            const iv: V = @bitCast(in[off..][0 .. 4 * n].*);
            out[off..][0 .. 4 * n].* = @bitCast(iv ^ ks);
        }
    }
}

const native_le = @import("builtin").cpu.arch.endian() == .little;

/// In-place transpose of an n x n matrix held as n row vectors: stage `d`
/// swaps bit `d` of the row and the lane index, so after all log2(n) stages
/// element (i, j) is at (j, i). Every step is a two-input `@shuffle`.
inline fn transpose(comptime n: comptime_int, a: *[n]@Vector(n, u32)) void {
    comptime var d = 1;
    inline while (d < n) : (d *= 2) {
        const lo_mask: [n]i32 = comptime blk: {
            var m: [n]i32 = undefined;
            for (0..n) |j| m[j] = if (j & d == 0) @intCast(j) else ~@as(i32, @intCast(j - d));
            break :blk m;
        };
        const hi_mask: [n]i32 = comptime blk: {
            var m: [n]i32 = undefined;
            for (0..n) |j| m[j] = if (j & d == 0) @intCast(j + d) else ~@as(i32, @intCast(j));
            break :blk m;
        };
        inline for (0..n) |i| {
            if (i & d == 0) {
                const lo = @shuffle(u32, a[i], a[i + d], lo_mask);
                const hi = @shuffle(u32, a[i], a[i + d], hi_mask);
                a[i] = lo;
                a[i + d] = hi;
            }
        }
    }
}

/// Salsa20 stream XOR: `out = in ^ keystream(key, nonce)` starting at block
/// `counter`. `out` and `in` may alias exactly.
pub fn salsa20Xor(out: []u8, in: []const u8, counter: u64, key: *const [8]u32, nonce: [2]u32) void {
    std.debug.assert(out.len == in.len);
    const base = baseState(key, nonce);
    var ctr = counter;
    var i: usize = 0;
    while (in.len - i >= 64 * lanes) : (i += 64 * lanes) {
        xorBlocks(lanes, out[i..][0 .. 64 * lanes], in[i..][0 .. 64 * lanes], &base, ctr);
        ctr +%= lanes;
    }
    while (in.len - i >= 64) : (i += 64) {
        xorBlocks(1, out[i..][0..64], in[i..][0..64], &base, ctr);
        ctr +%= 1;
    }
    if (i < in.len) {
        var buf = [_]u8{0} ** 64;
        const rest = in.len - i;
        @memcpy(buf[0..rest], in[i..]);
        xorBlocks(1, &buf, &buf, &base, ctr);
        @memcpy(out[i..], buf[0..rest]);
        crypto.secureZero(u8, &buf);
    }
}

/// HSalsa20: the 32-byte subkey for a 16-byte `input` under `key`.
pub fn hsalsa20(input: [16]u8, key: [32]u8) [32]u8 {
    var k: [8]u32 = undefined;
    for (&k, 0..) |*w, i| w.* = mem.readInt(u32, key[4 * i ..][0..4], .little);
    var x: [16]Lanes(1) = undefined;
    const base = baseState(&k, .{ mem.readInt(u32, input[0..4], .little), mem.readInt(u32, input[4..8], .little) });
    inline for (0..16) |i| x[i] = @splat(base[i]);
    x[8] = @splat(mem.readInt(u32, input[8..12], .little));
    x[9] = @splat(mem.readInt(u32, input[12..16], .little));
    doubleRounds(Lanes(1), &x);
    var out: [32]u8 = undefined;
    inline for (.{ 0, 5, 10, 15, 6, 7, 8, 9 }, 0..) |w, j| mem.writeInt(u32, out[4 * j ..][0..4], x[w][0], .little);
    crypto.secureZero(u32, &k);
    return out;
}

const Extended = struct { key: [8]u32, nonce: [2]u32 };

fn extend(k: [key_length]u8, npub: [nonce_length]u8) Extended {
    var sub = hsalsa20(npub[0..16].*, k);
    defer crypto.secureZero(u8, &sub);
    var e: Extended = undefined;
    for (&e.key, 0..) |*w, i| w.* = mem.readInt(u32, sub[4 * i ..][0..4], .little);
    e.nonce = .{ mem.readInt(u32, npub[16..20], .little), mem.readInt(u32, npub[20..24], .little) };
    return e;
}

/// Block 0 of the stream: its first 32 bytes are the one-time Poly1305 key,
/// the other 32 encrypt the first 32 message bytes.
fn firstBlock(e: *const Extended) [64]u8 {
    var b = [_]u8{0} ** 64;
    salsa20Xor(&b, &b, 0, &e.key, e.nonce);
    return b;
}

/// Encrypt `m` into `c` (same length) and write the tag. Same output as
/// `std.crypto.aead.salsa_poly.XSalsa20Poly1305.encrypt` with empty `ad`.
pub fn encrypt(c: []u8, tag: *[tag_length]u8, m: []const u8, npub: [nonce_length]u8, k: [key_length]u8) void {
    std.debug.assert(c.len == m.len);
    var e = extend(k, npub);
    defer crypto.secureZero(u32, &e.key);
    var block0 = firstBlock(&e);
    defer crypto.secureZero(u8, &block0);
    const head = @min(32, m.len);
    for (c[0..head], m[0..head], block0[32..][0..head]) |*o, a, b| o.* = a ^ b;
    salsa20Xor(c[head..], m[head..], 1, &e.key, e.nonce);
    poly1305.create(tag, c, block0[0..32]);
}

/// Verify the tag over `c` and, only if it matches, decrypt `c` into `m`.
/// On error `m` is left untouched.
pub fn decrypt(m: []u8, c: []const u8, tag: [tag_length]u8, npub: [nonce_length]u8, k: [key_length]u8) crypto.errors.AuthenticationError!void {
    std.debug.assert(c.len == m.len);
    var e = extend(k, npub);
    defer crypto.secureZero(u32, &e.key);
    var block0 = firstBlock(&e);
    defer crypto.secureZero(u8, &block0);
    var computed: [tag_length]u8 = undefined;
    poly1305.create(&computed, c, block0[0..32]);
    const ok = crypto.timing_safe.eql([tag_length]u8, computed, tag);
    crypto.secureZero(u8, &computed);
    if (!ok) return error.AuthenticationFailed;
    const head = @min(32, c.len);
    for (m[0..head], c[0..head], block0[32..][0..head]) |*o, a, b| o.* = a ^ b;
    salsa20Xor(m[head..], c[head..], 1, &e.key, e.nonce);
}

// ── differential tests against std ───────────────────────────────────────────

const StdXSalsa = crypto.stream.salsa.XSalsa20;
const StdBox = crypto.aead.salsa_poly.XSalsa20Poly1305;

test "salsa20Xor matches std across lengths and counters" {
    var prng = std.Random.DefaultPrng.init(0x5a15a20);
    const r = prng.random();
    var in: [64 * 20 + 7]u8 = undefined;
    var a: [in.len]u8 = undefined;
    var b: [in.len]u8 = undefined;
    r.bytes(&in);
    // Lengths around every batch and block edge; counters that carry into
    // the high word inside a batch.
    const counters = [_]u64{ 0, 1, 0xffff_fffe, 0xffff_fff9 };
    for (counters) |ctr| {
        var len: usize = 0;
        while (len <= in.len) : (len += if (len < 70 or len % 64 > 60) 1 else 13) {
            var key: [32]u8 = undefined;
            var nonce: [8]u8 = undefined;
            r.bytes(&key);
            r.bytes(&nonce);
            crypto.stream.salsa.Salsa20.xor(a[0..len], in[0..len], ctr, key, nonce);
            var kw: [8]u32 = undefined;
            for (&kw, 0..) |*w, i| w.* = mem.readInt(u32, key[4 * i ..][0..4], .little);
            salsa20Xor(b[0..len], in[0..len], ctr, &kw, .{ mem.readInt(u32, nonce[0..4], .little), mem.readInt(u32, nonce[4..8], .little) });
            try std.testing.expectEqualSlices(u8, a[0..len], b[0..len]);
        }
    }
}

test "salsa20Xor in place equals out of place" {
    var buf: [64 * 9 + 3]u8 = undefined;
    for (&buf, 0..) |*x, i| x.* = @truncate(i *% 31);
    var out: [buf.len]u8 = undefined;
    const key = [_]u32{ 1, 2, 3, 4, 5, 6, 7, 8 };
    salsa20Xor(&out, &buf, 3, &key, .{ 9, 10 });
    salsa20Xor(&buf, &buf, 3, &key, .{ 9, 10 });
    try std.testing.expectEqualSlices(u8, &out, &buf);
}

test "encrypt/decrypt match std XSalsa20Poly1305" {
    var prng = std.Random.DefaultPrng.init(0xb0c5);
    const r = prng.random();
    var m: [3000]u8 = undefined;
    var c1: [m.len]u8 = undefined;
    var c2: [m.len]u8 = undefined;
    var back: [m.len]u8 = undefined;
    r.bytes(&m);
    var len: usize = 0;
    while (len <= m.len) : (len += if (len < 100) 1 else 61) {
        var k: [32]u8 = undefined;
        var n: [24]u8 = undefined;
        r.bytes(&k);
        r.bytes(&n);
        var t1: [16]u8 = undefined;
        var t2: [16]u8 = undefined;
        StdBox.encrypt(c1[0..len], &t1, m[0..len], "", n, k);
        encrypt(c2[0..len], &t2, m[0..len], n, k);
        try std.testing.expectEqualSlices(u8, c1[0..len], c2[0..len]);
        try std.testing.expectEqual(t1, t2);
        try decrypt(back[0..len], c2[0..len], t2, n, k);
        try std.testing.expectEqualSlices(u8, m[0..len], back[0..len]);
        if (len > 0) {
            c2[len / 2] ^= 1;
            @memset(back[0..len], 0xee);
            try std.testing.expectError(error.AuthenticationFailed, decrypt(back[0..len], c2[0..len], t2, n, k));
            for (back[0..len]) |x| try std.testing.expectEqual(@as(u8, 0xee), x);
        }
    }
}

test "hsalsa20 matches std XSalsa20 subkey (via the stream)" {
    // XSalsa20(k, n) == Salsa20(hsalsa20(n[0..16], k), n[16..24]).
    var prng = std.Random.DefaultPrng.init(7);
    const r = prng.random();
    for (0..32) |_| {
        var k: [32]u8 = undefined;
        var n: [24]u8 = undefined;
        r.bytes(&k);
        r.bytes(&n);
        var a = [_]u8{0} ** 128;
        var b = [_]u8{0} ** 128;
        StdXSalsa.xor(&a, &a, 0, k, n);
        crypto.stream.salsa.Salsa20.xor(&b, &b, 0, hsalsa20(n[0..16].*, k), n[16..24].*);
        try std.testing.expectEqualSlices(u8, &a, &b);
    }
}
