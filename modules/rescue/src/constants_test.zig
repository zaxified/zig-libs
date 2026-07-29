// SPDX-License-Identifier: MIT

//! Proof that the numbers this module *generates* are the reference numbers.
//!
//! `vectors_test.zig` already proves the whole construction end to end, but a
//! vector failure says only "something upstream of the digest is wrong". These
//! tests name the layer: a wrong round constant fails here, a wrong round order
//! fails only there.
//!
//! Two independent claims:
//!
//! 1. **The RPO round constants are the deployed ones** — the SHAKE256
//!    derivation in `params.zig` is compared element-by-element with the tables
//!    miden-crypto embeds in its source. 168 values, extracted by script.
//! 2. **The S-box exponents are computed, not remembered** — `alpha = 7` is
//!    shown to be forced, `1/alpha` is produced by the extended Euclidean
//!    algorithm and checked three ways, including replaying the 72-multiply
//!    addition chain symbolically over exponents.

const std = @import("std");
const gl = @import("goldilocks.zig");
const params = @import("params.zig");
const perm = @import("perm.zig");
const xlix_consts = @import("xlix_constants.zig");
const up = @import("upstream_vectors.zig");

const P128 = perm.Permutation(params.Instance.bits128);
const P160 = perm.Permutation(params.Instance.bits160);

// ── 1. round constants ──────────────────────────────────────────────────────

test "SHAKE256-derived round constants == miden-crypto's embedded ARK1/ARK2" {
    // The whole "derive, don't embed" claim in one assertion. If the seed
    // string, the 9-bytes-per-integer chunking, the little-endian read or the
    // interleaved ARK1/ARK2 layout were wrong, this is what says so.
    for (0..params.num_rounds) |r| {
        try std.testing.expectEqualSlices(gl.Fe, &up.miden_ark1[r], P128.ark1(r));
        try std.testing.expectEqualSlices(gl.Fe, &up.miden_ark2[r], P128.ark2(r));
    }
}

test "the 160-bit instance derives a full, distinct, canonical constant set" {
    // No upstream table exists for m = 16 to compare against — the anchor for
    // this instance is the report's 19 published digests in `vectors_test.zig`.
    // What is checkable here is that it is a *different* stream (a copy-paste
    // of the 128-bit seed would still hash deterministically) and well-formed.
    const rc128 = params.roundConstants(params.Instance.bits128);
    const rc160 = params.roundConstants(params.Instance.bits160);
    try std.testing.expectEqual(@as(usize, 2 * 12 * 7), rc128.len);
    try std.testing.expectEqual(@as(usize, 2 * 16 * 7), rc160.len);
    try std.testing.expect(rc128[0] != rc160[0]);
    for (rc160) |c| try std.testing.expect(c < gl.P);
}

test "SHA-256 over both derived constant tables, pinned from an outside port" {
    // Grade 2. These two digests were NOT taken from this module's output —
    // they were produced by an independent Python port of the sage generator
    // (`hashlib.shake_256` + `int.to_bytes(8,'little')`), which shares no code
    // with the Zig here, and are reproducible in three lines:
    //
    //   import hashlib
    //   rc = ...  # 9-byte LE chunks of shake_256("RPO(p,m,c,s)"), each % p
    //   hashlib.sha256(b''.join(v.to_bytes(8,'little') for v in rc)).hexdigest()
    //
    // This is what covers the 160-bit table, which has no upstream ARK to
    // compare against.
    const cases = .{
        .{ params.Instance.bits128, "6a6d93807a4e26aa804616a043e5d81532ea80c1f3484c8b09ddf7e0a7d5595a" },
        .{ params.Instance.bits160, "9f13d2b924f121f24a3acf4e5d39212aca35b997d80babad804ac671eb3b4f46" },
    };
    inline for (cases) |c| {
        const rc = params.roundConstants(c[0]);
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        for (rc) |v| {
            var b: [8]u8 = undefined;
            std.mem.writeInt(u64, &b, v, .little);
            h.update(&b);
        }
        var out: [32]u8 = undefined;
        h.final(&out);
        var hex: [64]u8 = undefined;
        _ = std.fmt.bufPrint(&hex, "{x}", .{&out}) catch unreachable;
        try std.testing.expectEqualStrings(c[1], &hex);
    }
}

test "the m = 12 MDS row is corroborated by a second, unrelated implementation" {
    // params.zig takes it from the sage `get_mds`; Winterfell's Rust `MDS`
    // constant is an independently maintained copy of the same row.
    const row = params.mdsRow(params.Instance.bits128);
    try std.testing.expectEqualSlices(gl.Fe, &xlix_consts.mds_row, &row);
    // The m = 16 row has no second source; it is pinned only by the 160-bit
    // report vectors. Assert its shape so a truncation cannot pass silently.
    const row16 = params.mdsRow(params.Instance.bits160);
    try std.testing.expectEqual(@as(usize, 16), row16.len);
    for (row16) |v| try std.testing.expect(v != 0);
}

// ── 2. the S-box exponents ──────────────────────────────────────────────────

test "alpha = 7 is forced: 3 and 5 are not coprime to p - 1" {
    // x^k is a bijection on GF(p) iff gcd(k, p-1) = 1. p - 1 = 2^32 * (2^32 - 1)
    // and 2^32 - 1 = 3 * 5 * 17 * 257 * 65537, so 3 and 5 are both out and 7 is
    // the smallest odd exponent that works — the same argument that pushes
    // Poseidon to x^5 on its fields pushes Rescue to x^7 here.
    const m: u128 = gl.P - 1;
    try std.testing.expectEqual(@as(u128, 0), m % 3);
    try std.testing.expectEqual(@as(u128, 0), m % 5);
    try std.testing.expect(m % 7 != 0);
    for ([_]u64{ 3, 4, 5, 6 }) |k| {
        try std.testing.expect(std.math.gcd(k, gl.P - 1) != 1);
    }
    try std.testing.expectEqual(@as(u64, 1), std.math.gcd(@as(u64, 7), gl.P - 1));
    try std.testing.expectEqual(@as(u64, 7), gl.alpha);
}

test "inv_alpha is computed and satisfies alpha * inv_alpha = 1 mod (p - 1)" {
    const m: u128 = gl.P - 1;
    const prod = (@as(u128, gl.alpha) * @as(u128, gl.inv_alpha)) % m;
    try std.testing.expectEqual(@as(u128, 1), prod);
    // ...and lands on the value both deployed implementations publish.
    try std.testing.expectEqual(up.published_inv_alpha, gl.inv_alpha);
    // The extended Euclid routine is not a one-trick pony.
    for ([_]u64{ 7, 11, 13, 17 * 19, 1 << 60 | 1 }) |k| {
        if (std.math.gcd(k, gl.P - 1) != 1) continue;
        const inv = gl.invModPMinus1(k);
        try std.testing.expectEqual(@as(u128, 1), (@as(u128, k) * @as(u128, inv)) % m);
    }
}

test "the 72-multiply addition chain really raises to inv_alpha" {
    // Replay `goldilocks.sboxInv` over EXPONENTS instead of field elements:
    // square -> double, multiply -> add. If the chain ever drifts from the
    // exponent it claims, this catches it without needing a field at all.
    // (Exponents stay below 2^64, so u128 arithmetic is exact.)
    const S = struct {
        fn expAcc(base: u128, tail: u128, n: u8) u128 {
            var r = base;
            for (0..n) |_| r *= 2;
            return r + tail;
        }
    };
    const x: u128 = 1;
    const t1 = x * 2;
    const t2 = t1 * 2;
    const t3 = S.expAcc(t2, t2, 3);
    const t4 = S.expAcc(t3, t3, 6);
    const t5 = S.expAcc(t4, t4, 12);
    const t6 = S.expAcc(t5, t3, 6);
    const t7 = S.expAcc(t6, t6, 31);
    const a = ((t7 * 2 + t6) * 2) * 2;
    const b = t1 + t2 + x;
    try std.testing.expectEqual(@as(u128, gl.inv_alpha), a + b);

    // Cross-check against the generic ladder on real inputs, too.
    var prng = std.Random.DefaultPrng.init(0x1F);
    const rnd = prng.random();
    for (0..256) |_| {
        const v = gl.fromU64(rnd.int(u64));
        try std.testing.expectEqual(gl.pow(v, gl.inv_alpha), gl.sboxInv(v));
        try std.testing.expectEqual(gl.pow(v, gl.alpha), gl.sbox(v));
    }
}

test "the Rescue-XLIX constants are a different set from RPO's" {
    // Guards against xlix.zig accidentally being wired to params.zig's tables,
    // which would make its published KAT the only thing standing between the
    // two constructions.
    try std.testing.expect(xlix_consts.ark1[0][0] != P128.ark1(0)[0]);
    try std.testing.expect(xlix_consts.ark2[6][11] != P128.ark2(6)[11]);
}
