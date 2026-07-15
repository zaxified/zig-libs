// SPDX-License-Identifier: MIT
//! gaussian — SamplerZ, Falcon/FN-DSA's discrete Gaussian sampler over Z,
//! plus the ChaCha20-based signer PRNG it draws from. Ported from the
//! Falcon Round-3 reference (`rng.c` `prng_*`, `sign.c`
//! `gaussian0_sampler`/`BerExp`/`sampler`) closely enough to be BYTE-EXACT
//! against the reference's KAT signatures.
//!
//! ================================================================
//! *** THE side-channel-critical primitive in this whole module. ***
//! ================================================================
//!
//! A sampler whose timing/branches/memory-access depend on the SAMPLED
//! VALUE (not just mu/sigma) leaks the secret NTRU basis through valid,
//! correctly-verifying signatures. This port mirrors the reference's
//! constant-time structure:
//!   * `gaussian0` walks the FULL RCDT table every call with a branchless
//!     subtract-borrow comparison chain (no early exit, no value-dependent
//!     table index).
//!   * `berExp` always consumes the same lazy byte loop shape; the ONE
//!     data-dependent early break (`while (!w && i>0)`) is copied verbatim
//!     from the reference, which documents it as an acceptable/rare-path
//!     leak of the comparison, not of z.
//!   * `sampler`'s reject loop iterates a value-dependent number of times
//!     (as the reference does) — its constant-time claim rests on the
//!     Bernoulli scaling decorrelating iteration count from mu/sigma, per
//!     the reference's own analysis, NOT on a fixed iteration count.
//!
//! CONSTANT-TIME STATUS (must be audited before ANY production signing):
//! this reproduces the reference's *branch/table structure*, but (a) the
//! underlying `fpr` arithmetic here is native `f64`, whose HARDWARE timing
//! (subnormals, divide) is not audited for data-independence, and (b) no
//! machine-checked constant-time verification (dudect / ctgrind / binsec)
//! has been run. Treat as KAT-correct, NOT yet side-channel-cleared.

const std = @import("std");
const fpr = @import("fpr.zig");

/// The Falcon signer PRNG: ChaCha20 with the reference's exact state layout,
/// interleaved output buffer, and `get_u8`/`get_u64` extraction semantics
/// (reference `rng.c`). Reproducing this byte-for-byte is required for
/// KAT-exact signatures.
pub const Prng = struct {
    buf: [512]u8 = undefined,
    ptr: usize = 0,
    state: [256]u8 = undefined,

    /// Seed from 56 bytes previously squeezed from a SHAKE256 context
    /// (reference `prng_init` after `inner_shake256_extract(src, tmp, 56)`).
    pub fn init(seed56: *const [56]u8) Prng {
        var p: Prng = .{};
        @memset(&p.state, 0);
        // On a little-endian host the reference's LE-decode-then-native-store
        // (and the 48..56 counter fold) is a byte-for-byte copy.
        @memcpy(p.state[0..56], seed56);
        p.refill();
        return p;
    }

    fn u32le(b: []const u8) u32 {
        return @as(u32, b[0]) | (@as(u32, b[1]) << 8) | (@as(u32, b[2]) << 16) | (@as(u32, b[3]) << 24);
    }

    fn refill(p: *Prng) void {
        const CW = [4]u32{ 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };
        var cc: u64 = @as(u64, u32le(p.state[48..52])) | (@as(u64, u32le(p.state[52..56])) << 32);
        var u: usize = 0;
        while (u < 8) : (u += 1) {
            var st: [16]u32 = undefined;
            st[0] = CW[0];
            st[1] = CW[1];
            st[2] = CW[2];
            st[3] = CW[3];
            var v: usize = 0;
            while (v < 12) : (v += 1) st[4 + v] = u32le(p.state[v * 4 .. v * 4 + 4]);
            st[14] ^= @truncate(cc);
            st[15] ^= @truncate(cc >> 32);
            var i: usize = 0;
            while (i < 10) : (i += 1) {
                qround(&st, 0, 4, 8, 12);
                qround(&st, 1, 5, 9, 13);
                qround(&st, 2, 6, 10, 14);
                qround(&st, 3, 7, 11, 15);
                qround(&st, 0, 5, 10, 15);
                qround(&st, 1, 6, 11, 12);
                qround(&st, 2, 7, 8, 13);
                qround(&st, 3, 4, 9, 14);
            }
            v = 0;
            while (v < 4) : (v += 1) st[v] +%= CW[v];
            v = 4;
            while (v < 14) : (v += 1) st[v] +%= u32le(p.state[(v - 4) * 4 .. (v - 4) * 4 + 4]);
            st[14] +%= u32le(p.state[40..44]) ^ @as(u32, @truncate(cc));
            st[15] +%= u32le(p.state[44..48]) ^ @as(u32, @truncate(cc >> 32));
            cc += 1;
            v = 0;
            while (v < 16) : (v += 1) {
                const idx = (u << 2) + (v << 5);
                p.buf[idx + 0] = @truncate(st[v]);
                p.buf[idx + 1] = @truncate(st[v] >> 8);
                p.buf[idx + 2] = @truncate(st[v] >> 16);
                p.buf[idx + 3] = @truncate(st[v] >> 24);
            }
        }
        // Store cc back as LE u64 at state[48..56].
        var w = cc;
        var b: usize = 48;
        while (b < 56) : (b += 1) {
            p.state[b] = @truncate(w);
            w >>= 8;
        }
        p.ptr = 0;
    }

    fn qround(st: *[16]u32, a: usize, b: usize, c: usize, d: usize) void {
        st[a] +%= st[b];
        st[d] ^= st[a];
        st[d] = std.math.rotl(u32, st[d], 16);
        st[c] +%= st[d];
        st[b] ^= st[c];
        st[b] = std.math.rotl(u32, st[b], 12);
        st[a] +%= st[b];
        st[d] ^= st[a];
        st[d] = std.math.rotl(u32, st[d], 8);
        st[c] +%= st[d];
        st[b] ^= st[c];
        st[b] = std.math.rotl(u32, st[b], 7);
    }

    pub fn getU64(p: *Prng) u64 {
        var u = p.ptr;
        if (u >= p.buf.len - 9) {
            p.refill();
            u = 0;
        }
        p.ptr = u + 8;
        return @as(u64, p.buf[u + 0]) | (@as(u64, p.buf[u + 1]) << 8) |
            (@as(u64, p.buf[u + 2]) << 16) | (@as(u64, p.buf[u + 3]) << 24) |
            (@as(u64, p.buf[u + 4]) << 32) | (@as(u64, p.buf[u + 5]) << 40) |
            (@as(u64, p.buf[u + 6]) << 48) | (@as(u64, p.buf[u + 7]) << 56);
    }

    pub fn getU8(p: *Prng) u8 {
        const v = p.buf[p.ptr];
        p.ptr += 1;
        if (p.ptr == p.buf.len) p.refill();
        return v;
    }
};

/// Half-Gaussian base sampler (sigma = 1.8205), reference
/// `gaussian0_sampler`. Branchless RCDT walk over the full table.
pub fn gaussian0(p: *Prng) i32 {
    const dist = [_]u32{
        10745844, 3068844,  3741698,
        5559083,  1580863,  8248194,
        2260429,  13669192, 2736639,
        708981,   4421575,  10046180,
        169348,   7122675,  4136815,
        30538,    13063405, 7650655,
        4132,     14505003, 7826148,
        417,      16768101, 11363290,
        31,       8444042,  8086568,
        1,        12844466, 265321,
        0,        1232676,  13644283,
        0,        38047,    9111839,
        0,        870,      6138264,
        0,        14,       12545723,
        0,        0,        3104126,
        0,        0,        28824,
        0,        0,        198,
        0,        0,        1,
    };
    const lo = p.getU64();
    const hi = p.getU8();
    const v0: u32 = @as(u32, @truncate(lo)) & 0xFFFFFF;
    const v1: u32 = @as(u32, @truncate(lo >> 24)) & 0xFFFFFF;
    const v2: u32 = @as(u32, @truncate(lo >> 48)) | (@as(u32, hi) << 16);
    var z: i32 = 0;
    var u: usize = 0;
    while (u < dist.len) : (u += 3) {
        const w0 = dist[u + 2];
        const w1 = dist[u + 1];
        const w2 = dist[u + 0];
        var cc: u32 = (v0 -% w0) >> 31;
        cc = (v1 -% w1 -% cc) >> 31;
        cc = (v2 -% w2 -% cc) >> 31;
        z += @intCast(cc);
    }
    return z;
}

/// Sample a bit with probability exp(-x), x >= 0 (reference `BerExp`).
pub fn berExp(p: *Prng, x: f64, ccs: f64) bool {
    var s: i32 = @intCast(fpr.trunc(fpr.mul(x, fpr.inv_log2)));
    const r = fpr.sub(x, fpr.mul(fpr.of(s), fpr.log2));
    // Saturate s at 63.
    var sw: u32 = @bitCast(s);
    sw ^= (sw ^ 63) & (0 -% ((63 -% sw) >> 31));
    s = @bitCast(sw);
    const z: u64 = ((fpr.expm_p63(r, ccs) << 1) -% 1) >> @intCast(s & 63);
    var i: i32 = 64;
    var w: u32 = 0;
    while (true) {
        i -= 8;
        const zbyte: u32 = @as(u32, @truncate(z >> @intCast(i))) & 0xFF;
        w = @as(u32, p.getU8()) -% zbyte;
        if (!(w == 0 and i > 0)) break;
    }
    return (w >> 31) != 0;
}

/// SamplerZ: one integer from a discrete Gaussian of center `mu` and
/// inverse std-dev `isigma`, with `sigma_min` the degree's minimum
/// (reference `Zf(sampler)`). Reproduces the reference's PRNG consumption
/// order exactly, which is required for KAT-exact signatures.
pub fn samplerZ(p: *Prng, mu: f64, isigma: f64, sigma_min_v: f64) i32 {
    const s: i32 = @intCast(fpr.floor(mu));
    const r = fpr.sub(mu, fpr.of(s));
    const dss = fpr.half(fpr.sqr(isigma));
    const ccs = fpr.mul(isigma, sigma_min_v);
    while (true) {
        const z0 = gaussian0(p);
        const b: i32 = @intCast(p.getU8() & 1);
        const z: i32 = b + ((b << 1) - 1) * z0;
        var x = fpr.mul(fpr.sqr(fpr.sub(fpr.of(z), r)), dss);
        x = fpr.sub(x, fpr.mul(fpr.of(@as(i64, z0) * @as(i64, z0)), fpr.inv_2sqrsigma0));
        if (berExp(p, x, ccs)) return s + z;
    }
}

test "Prng: deterministic given the same seed" {
    var seed: [56]u8 = undefined;
    for (&seed, 0..) |*x, i| x.* = @intCast(i & 0xff);
    var a = Prng.init(&seed);
    var bb = Prng.init(&seed);
    try std.testing.expectEqual(a.getU64(), bb.getU64());
    try std.testing.expectEqual(a.getU8(), bb.getU8());
}
