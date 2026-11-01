// SPDX-License-Identifier: MIT
//! The XOF- and PRF-driven samplers of ML-KEM: the matrix Â from ρ
//! (SampleNTT over SHAKE128, FIPS 203 Algorithm 7) and the noise vectors
//! from σ / r (SamplePolyCBD over PRF_η = SHAKE256, Algorithm 8, §4.1).

const std = @import("std");
const poly = @import("poly.zig");
const keccak4 = @import("keccak4.zig");

const Poly = poly.Poly;
const Shake128 = std.crypto.hash.sha3.Shake128;
const Shake256 = std.crypto.hash.sha3.Shake256;

const xof_block = 168;
/// Three SHAKE128 blocks hold 168 candidates; 256 accepted values need
/// about 315 bytes on average, so a fourth block is rare.
const xof_first_blocks = 3;

/// m[i][j] = SampleNTT(ρ ‖ j ‖ i) (= Â[i][j]), or with `transposed`
/// SampleNTT(ρ ‖ i ‖ j) (= Âᵀ[i][j]). The k² entries are expanded four at a
/// time with the 4-way Keccak; the last batch (k = 3: 9 = 4 + 4 + 1) runs
/// through the same x4 path with dummy lanes (a copy of lane 0, ignored).
pub fn matrix(comptime k: usize, m: *[k][k]Poly, rho: *const [32]u8, transposed: bool) void {
    const n = k * k;
    var base: usize = 0;
    while (base < n) : (base += 4) {
        const lanes = @min(4, n - base);
        var seeds: [4][34]u8 = undefined;
        var polys: [4]*Poly = undefined;
        for (0..4) |l| {
            const idx = base + (if (l < lanes) l else 0);
            const i = idx / k;
            const j = idx % k;
            seeds[l][0..32].* = rho.*;
            seeds[l][32] = @intCast(if (transposed) i else j);
            seeds[l][33] = @intCast(if (transposed) j else i);
            polys[l] = &m[i][j];
        }
        sampleNtt4(polys, lanes, &seeds);
    }
}

fn sampleNtt4(polys: [4]*Poly, lanes: usize, seeds: *const [4][34]u8) void {
    var x = keccak4.Shake128x4.init(34, .{ &seeds[0], &seeds[1], &seeds[2], &seeds[3] });
    var buf: [4][xof_block * xof_first_blocks]u8 = undefined;
    for (0..xof_first_blocks) |b| {
        x.squeezeInto(.{
            buf[0][b * xof_block ..][0..xof_block],
            buf[1][b * xof_block ..][0..xof_block],
            buf[2][b * xof_block ..][0..xof_block],
            buf[3][b * xof_block ..][0..xof_block],
        });
    }
    // Candidates land in FIPS 203 order in `tmp`; the internal layout is
    // applied once per polynomial at the end.
    var tmp: [4][256 + poly.rej_slack]i16 = undefined;
    var ctr: [4]usize = .{ 256, 256, 256, 256 };
    var pending: usize = 0;
    for (0..lanes) |l| {
        ctr[l] = poly.rejUniform(&tmp[l], 0, &buf[l]);
        if (ctr[l] < 256) pending += 1;
    }
    while (pending > 0) {
        var blk: [4][xof_block]u8 = undefined;
        x.squeezeBlocks(&blk);
        for (0..lanes) |l| {
            if (ctr[l] >= 256) continue;
            ctr[l] = poly.rejUniform(&tmp[l], ctr[l], &blk[l]);
            if (ctr[l] >= 256) pending -= 1;
        }
    }
    for (0..lanes) |l| {
        polys[l].coeffs().* = tmp[l][0..256].*;
        polys[l].fromNttOrder();
    }
}

fn matrixScalar(comptime k: usize, m: *[k][k]Poly, rho: *const [32]u8, transposed: bool) void {
    for (0..k) |i| {
        for (0..k) |j| {
            var seed: [34]u8 = undefined;
            seed[0..32].* = rho.*;
            const a: u8 = @intCast(if (transposed) i else j);
            const b: u8 = @intCast(if (transposed) j else i);
            seed[32] = a;
            seed[33] = b;
            sampleNtt(&m[i][j], &seed);
        }
    }
}

fn sampleNtt(p: *Poly, seed: *const [34]u8) void {
    var x = Shake128.init(.{});
    x.update(seed);
    var buf: [xof_block * xof_first_blocks]u8 = undefined;
    x.squeeze(&buf);
    var tmp: [256 + poly.rej_slack]i16 = undefined;
    var ctr = poly.rejUniform(&tmp, 0, &buf);
    while (ctr < 256) {
        x.squeeze(buf[0..xof_block]);
        ctr = poly.rejUniform(&tmp, ctr, buf[0..xof_block]);
    }
    p.coeffs().* = tmp[0..256].*;
    p.fromNttOrder();
}

fn prf(comptime eta: u2, out: *[64 * @as(usize, eta)]u8, s: *const [32]u8, nonce: u8) void {
    var h = Shake256.init(.{});
    defer std.crypto.secureZero(u8, std.mem.asBytes(&h));
    h.update(s);
    h.update(&[1]u8{nonce});
    h.squeeze(out);
}

fn noisePoly(comptime eta: u2, p: *Poly, s: *const [32]u8, nonce: u8) void {
    var buf: [64 * @as(usize, eta)]u8 = undefined;
    defer std.crypto.secureZero(u8, &buf);
    prf(eta, &buf, s, nonce);
    p.cbd(eta, &buf);
}

/// One PRF_η + SamplePolyCBD_η call: `p` from `s ‖ nonce`, `eta` is 2 or 3.
const NoiseJob = struct { p: *Poly, nonce: u8, eta: u2 };

/// Run `jobs` four at a time through the 4-way SHAKE256. A batch squeezes
/// two blocks when any of its jobs has η = 3 (192 bytes), else one (128).
fn noiseBatched(jobs: []const NoiseJob, s: *const [32]u8) void {
    var i: usize = 0;
    while (i < jobs.len) : (i += 4) {
        const lanes = @min(4, jobs.len - i);
        var ins: [4][33]u8 = undefined;
        var two_blocks = false;
        for (0..4) |l| {
            const job = jobs[i + (if (l < lanes) l else 0)];
            ins[l][0..32].* = s.*;
            ins[l][32] = job.nonce;
            if (l < lanes and job.eta == 3) two_blocks = true;
        }
        var x = keccak4.Shake256x4.init(33, .{ &ins[0], &ins[1], &ins[2], &ins[3] });
        defer std.crypto.secureZero(u8, std.mem.asBytes(&x));
        var out: [4][2 * 136]u8 = undefined;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&out));
        var blk: [4][136]u8 = undefined;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&blk));
        x.squeezeBlocks(&blk);
        for (0..4) |l| out[l][0..136].* = blk[l];
        if (two_blocks) {
            x.squeezeBlocks(&blk);
            for (0..4) |l| out[l][136..].* = blk[l];
        }
        for (0..lanes) |l| {
            switch (jobs[i + l].eta) {
                2 => jobs[i + l].p.cbd(2, out[l][0..128]),
                3 => jobs[i + l].p.cbd(3, out[l][0..192]),
                else => unreachable,
            }
        }
        std.crypto.secureZero(u8, std.mem.asBytes(&ins));
    }
}

/// K-PKE.KeyGen lines 8–15: s from nonces 0..k−1, e from k..2k−1.
pub fn noiseKeygen(comptime k: usize, comptime eta1: u2, s: *[k]Poly, e: *[k]Poly, sigma: *const [32]u8) void {
    var jobs: [2 * k]NoiseJob = undefined;
    for (0..k) |i| {
        jobs[i] = .{ .p = &s[i], .nonce = @intCast(i), .eta = eta1 };
        jobs[k + i] = .{ .p = &e[i], .nonce = @intCast(k + i), .eta = eta1 };
    }
    noiseBatched(&jobs, sigma);
}

/// K-PKE.Encrypt lines 9–17: y (η1) from 0..k−1, e1 (η2) from k..2k−1,
/// e2 (η2) from 2k.
pub fn noiseEncrypt(comptime k: usize, comptime eta1: u2, y: *[k]Poly, e1: *[k]Poly, e2: *Poly, r: *const [32]u8) void {
    var jobs: [2 * k + 1]NoiseJob = undefined;
    for (0..k) |i| {
        jobs[i] = .{ .p = &y[i], .nonce = @intCast(i), .eta = eta1 };
        jobs[k + i] = .{ .p = &e1[i], .nonce = @intCast(k + i), .eta = 2 };
    }
    jobs[2 * k] = .{ .p = e2, .nonce = @intCast(2 * k), .eta = 2 };
    noiseBatched(&jobs, r);
}

fn noiseKeygenScalar(comptime k: usize, comptime eta1: u2, s: *[k]Poly, e: *[k]Poly, sigma: *const [32]u8) void {
    for (0..k) |i| noisePoly(eta1, &s[i], sigma, @intCast(i));
    for (0..k) |i| noisePoly(eta1, &e[i], sigma, @intCast(k + i));
}

fn noiseEncryptScalar(comptime k: usize, comptime eta1: u2, y: *[k]Poly, e1: *[k]Poly, e2: *Poly, r: *const [32]u8) void {
    for (0..k) |i| noisePoly(eta1, &y[i], r, @intCast(i));
    for (0..k) |i| noisePoly(2, &e1[i], r, @intCast(k + i));
    noisePoly(2, e2, r, @intCast(2 * k));
}

test "x4 matrix and noise samplers equal the scalar path" {
    var prng = std.Random.DefaultPrng.init(0x7e57);
    const rnd = prng.random();
    inline for (.{ .{ 2, 3, 3 }, .{ 3, 2, 2 }, .{ 4, 2, 2 } }) |par| {
        const k = par[0];
        const eta1: u2 = par[1];
        for (0..8) |round| {
            var rho: [32]u8 = undefined;
            rnd.bytes(&rho);
            for ([_]bool{ false, true }) |tr| {
                var a: [k][k]Poly = undefined;
                var b: [k][k]Poly = undefined;
                matrix(k, &a, &rho, tr);
                matrixScalar(k, &b, &rho, tr);
                for (0..k) |i| for (0..k) |j|
                    try std.testing.expectEqualSlices(i16, b[i][j].coeffsConst(), a[i][j].coeffsConst());
            }
            _ = round;
            var s1: [k]Poly = undefined;
            var e1: [k]Poly = undefined;
            var s2: [k]Poly = undefined;
            var e2: [k]Poly = undefined;
            noiseKeygen(k, eta1, &s1, &e1, &rho);
            noiseKeygenScalar(k, eta1, &s2, &e2, &rho);
            for (0..k) |i| {
                try std.testing.expectEqualSlices(i16, s2[i].coeffsConst(), s1[i].coeffsConst());
                try std.testing.expectEqualSlices(i16, e2[i].coeffsConst(), e1[i].coeffsConst());
            }
            var y1: [k]Poly = undefined;
            var f1: [k]Poly = undefined;
            var g1: Poly = undefined;
            var y2: [k]Poly = undefined;
            var f2: [k]Poly = undefined;
            var g2: Poly = undefined;
            noiseEncrypt(k, eta1, &y1, &f1, &g1, &rho);
            noiseEncryptScalar(k, eta1, &y2, &f2, &g2, &rho);
            for (0..k) |i| {
                try std.testing.expectEqualSlices(i16, y2[i].coeffsConst(), y1[i].coeffsConst());
                try std.testing.expectEqualSlices(i16, f2[i].coeffsConst(), f1[i].coeffsConst());
            }
            try std.testing.expectEqualSlices(i16, g2.coeffsConst(), g1.coeffsConst());
        }
    }
}
