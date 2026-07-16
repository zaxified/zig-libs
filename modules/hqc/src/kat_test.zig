// SPDX-License-Identifier: MIT
//! kat_test — reproduces the reference implementation's own intermediate
//! values (kat_vectors.zig) byte-exactly through this module's `Xof`,
//! `Prng`, `hashI`, `hashG`, and `sampleFixedWeightRejection`/`sampleVect`.
//!
//! This is the load-bearing check for Part 1: if `Xof.getBytes`'s 8-byte
//! rounding quirk (see prng.zig) were missing or wrong, the chained
//! y-then-x test below would fail (it did, during development, before
//! that quirk was found and fixed — see prng.zig's module doc).

const std = @import("std");
const params = @import("params.zig");
const prng = @import("prng.zig");
const gf2x = @import("gf2x.zig");
const v = @import("kat_vectors.zig");

fn hexBytes(comptime len: usize, hex: []const u8) [len]u8 {
    var out: [len]u8 = undefined;
    const decoded = std.fmt.hexToBytes(&out, hex) catch unreachable;
    std.debug.assert(decoded.len == len);
    return out;
}

test "KAT: keygen chain — seed_dk -> (y, x), chained same Xof context" {
    const t = std.testing;
    const P = params.hqc128;
    const seed_dk = hexBytes(32, v.hqc128_seed_dk);

    var xof = prng.Xof.init(&seed_dk);

    var y_support: [P.omega]u32 = undefined;
    prng.sampleFixedWeightRejection(&xof, P.n, P.nMu(), P.rejectionThreshold(), P.omega, &y_support);
    var y = [_]u64{0} ** P.words();
    prng.writeSupportToVector(P.omega, &y_support, &y);
    var y_bytes = [_]u8{0} ** P.nBytes();
    const R = gf2x.Ring(P.n);
    R.toBytes(y, &y_bytes);

    const want_y = hexBytes(P.nBytes(), v.hqc128_y);
    try t.expectEqualSlices(u8, &want_y, &y_bytes);

    // x continues the SAME xof context (no re-init) — this is the part
    // that only passes if getBytes's stream-position rounding is right.
    var x_support: [P.omega]u32 = undefined;
    prng.sampleFixedWeightRejection(&xof, P.n, P.nMu(), P.rejectionThreshold(), P.omega, &x_support);
    var x = [_]u64{0} ** P.words();
    prng.writeSupportToVector(P.omega, &x_support, &x);
    var x_bytes = [_]u8{0} ** P.nBytes();
    R.toBytes(x, &x_bytes);

    const want_x = hexBytes(P.nBytes(), v.hqc128_x);
    try t.expectEqualSlices(u8, &want_x, &x_bytes);
}

test "KAT: keygen chain — seed_ek -> h (SampleVect)" {
    const t = std.testing;
    const P = params.hqc128;
    const seed_ek = hexBytes(32, v.hqc128_seed_ek);

    var xof = prng.Xof.init(&seed_ek);
    var h = [_]u64{0} ** P.words();
    prng.sampleVect(&xof, P.n, &h);

    var h_bytes = [_]u8{0} ** P.nBytes();
    const R = gf2x.Ring(P.n);
    R.toBytes(h, &h_bytes);

    const want_h = hexBytes(P.nBytes(), v.hqc128_h);
    try t.expectEqualSlices(u8, &want_h, &h_bytes);
}

test "KAT: hash chain — I(seed_pke) == seed_dk || seed_ek" {
    const t = std.testing;
    const seed_pke = hexBytes(32, v.hqc128_seed_pke);
    var out: [64]u8 = undefined;
    prng.hashI(&out, &seed_pke);

    const want_dk = hexBytes(32, v.hqc128_seed_dk);
    const want_ek = hexBytes(32, v.hqc128_seed_ek);
    try t.expectEqualSlices(u8, &want_dk, out[0..32]);
    try t.expectEqualSlices(u8, &want_ek, out[32..64]);
}

test "KAT: hash chain — Xof(seed_kem) == seed_pke || sigma" {
    const t = std.testing;
    const seed_kem = hexBytes(32, v.hqc128_seed_kem);
    var xof = prng.Xof.init(&seed_kem);
    var out: [48]u8 = undefined; // seed_bytes(32) + security_bytes(16)
    xof.getBytes(&out);

    const want_pke = hexBytes(32, v.hqc128_seed_pke);
    const want_sigma = hexBytes(16, v.hqc128_sigma);
    try t.expectEqualSlices(u8, &want_pke, out[0..32]);
    try t.expectEqualSlices(u8, &want_sigma, out[32..48]);
}

test "KAT: hash chain — G(H(ek_kem), m, salt) == K || theta" {
    const t = std.testing;
    const hek = hexBytes(32, v.hqc128_hek);
    const m = hexBytes(16, v.hqc128_m);
    const salt = hexBytes(16, v.hqc128_salt);

    var out: [64]u8 = undefined;
    prng.hashG(&out, &hek, &m, &salt);

    const want_K = hexBytes(32, v.hqc128_K);
    const want_theta = hexBytes(32, v.hqc128_theta);
    try t.expectEqualSlices(u8, &want_K, out[0..32]);
    try t.expectEqualSlices(u8, &want_theta, out[32..64]);
}
