// SPDX-License-Identifier: MIT
//! Known-answer tests for the xmss module against the official XMSS
//! reference implementation (see kat_vectors.zig for provenance and the
//! deterministic input conventions reproduced here), plus round-trip,
//! tamper and stateful-index behavior tests.

const std = @import("std");
const xmss = @import("root.zig");
const vec = @import("kat_vectors.zig");

const n = xmss.n;

fn decodeHex(comptime hex_str: []const u8) [hex_str.len / 2]u8 {
    var out: [hex_str.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex_str) catch unreachable;
    return out;
}

/// Test-only reduced-height instantiations (no IANA OID; private-use range).
const Xmss4 = xmss.XmssSha2(4, 0xF0000004);
const Xmss2 = xmss.XmssSha2(2, 0xF0000002);
const Xmss6 = xmss.XmssSha2(6, 0xF0000006);

test "KAT: PRF primitive vs reference" {
    var key: [n]u8 = undefined;
    var in32: [32]u8 = undefined;
    for (&key, &in32, 0..) |*k, *m, i| {
        k.* = @truncate(i);
        m.* = @truncate(2 * i);
    }
    try std.testing.expectEqualSlices(u8, &decodeHex(vec.prf_out), &xmss.prf(&key, &in32));
}

test "KAT: F chain step (thash_f) vs reference" {
    var in: [n]u8 = undefined;
    var pub_seed: [n]u8 = undefined;
    for (&in, &pub_seed, 0..) |*a, *b, i| {
        a.* = @truncate(3 * i);
        b.* = @truncate(5 * i);
    }
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, j| word.* = @intCast(7 * j + 1);
    var adrs = xmss.Adrs.fromWords(words);
    try std.testing.expectEqualSlices(u8, &decodeHex(vec.f_out), &xmss.chainStep(&in, &pub_seed, &adrs));
}

test "KAT: H randomized tree hash (thash_h) vs reference" {
    var in: [2 * n]u8 = undefined;
    var pub_seed: [n]u8 = undefined;
    for (&in, 0..) |*a, i| a.* = @truncate(11 * i);
    for (&pub_seed, 0..) |*b, i| b.* = @truncate(13 * i);
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, j| word.* = @intCast(9 * j + 2);
    var adrs = xmss.Adrs.fromWords(words);
    const out = xmss.randHash(in[0..n], in[n..], &pub_seed, &adrs);
    try std.testing.expectEqualSlices(u8, &decodeHex(vec.h_out), &out);
}

test "KAT: H_msg vs reference" {
    var r: [n]u8 = undefined;
    var root: [n]u8 = undefined;
    for (&r, &root, 0..) |*a, *b, i| {
        a.* = @truncate(17 * i);
        b.* = @truncate(19 * i);
    }
    const out = xmss.hashMsg(&r, &root, 0x1234, "XMSS KAT message");
    try std.testing.expectEqualSlices(u8, &decodeHex(vec.hmsg_out), &out);
}

fn wotsKatAdrs() xmss.Adrs {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, j| word.* = @intCast(500000000 * j);
    return xmss.Adrs.fromWords(words);
}

test "KAT: WOTS+ pkGen, sign and pkFromSig round-trip vs reference" {
    var sk_seed: [n]u8 = undefined;
    var pub_seed: [n]u8 = undefined;
    var m: [n]u8 = undefined;
    for (&sk_seed, &pub_seed, 0..) |*s, *p, i| {
        s.* = @truncate(i);
        p.* = @truncate(2 * i);
    }
    for (&m, 0..) |*b, i| b.* = @truncate(3 * i);

    var adrs = wotsKatAdrs();
    const pk = xmss.wotsPkGen(&sk_seed, &pub_seed, &adrs);
    const pk_ref = decodeHex(vec.wots_pk);
    try std.testing.expectEqualSlices(u8, &pk_ref, std.mem.asBytes(&pk));

    adrs = wotsKatAdrs();
    const sig = xmss.wotsSign(&m, &sk_seed, &pub_seed, &adrs);
    try std.testing.expectEqualSlices(u8, &decodeHex(vec.wots_sig), std.mem.asBytes(&sig));

    // §3.1.6: completing the chains from the signature yields the public key.
    adrs = wotsKatAdrs();
    const pk_from_sig = xmss.wotsPkFromSig(&sig, &m, &pub_seed, &adrs);
    try std.testing.expectEqualSlices(u8, &pk_ref, std.mem.asBytes(&pk_from_sig));

    // A tampered digest must not map back to the public key.
    var m2 = m;
    m2[0] ^= 1;
    adrs = wotsKatAdrs();
    const pk_bad = xmss.wotsPkFromSig(&sig, &m2, &pub_seed, &adrs);
    try std.testing.expect(!std.mem.eql(u8, &pk_ref, std.mem.asBytes(&pk_bad)));
}

const Seeds = struct { sk_seed: [n]u8, sk_prf: [n]u8, pub_seed: [n]u8 };

/// Reference keypair seed convention: seed[0..96] with byte i = i, split as
/// sk_seed || sk_prf || pub_seed.
fn refSeeds() Seeds {
    var out: Seeds = undefined;
    for (&out.sk_seed, &out.sk_prf, &out.pub_seed, 0..) |*a, *b, *c, i| {
        a.* = @truncate(i);
        b.* = @truncate(i + n);
        c.* = @truncate(i + 2 * n);
    }
    return out;
}

const interop_msg = "XMSS interop test message";

test "KAT: reduced-height h=4 keygen + sign byte-exact vs reference" {
    const seeds = refSeeds();
    var kp = Xmss4.keyGen(seeds.sk_seed, seeds.sk_prf, seeds.pub_seed);

    const pk_ref = decodeHex(vec.xmss4_pk);
    try std.testing.expectEqualSlices(u8, pk_ref[0..n], &kp.pk.root);
    try std.testing.expectEqualSlices(u8, pk_ref[n..], &kp.pk.seed);

    var sig: [Xmss4.signature_length]u8 = undefined;
    try Xmss4.sign(&kp.sk, &sig, interop_msg);
    try std.testing.expectEqual(@as(u32, 1), kp.sk.idx); // state advanced
    try std.testing.expectEqualSlices(u8, &decodeHex(vec.xmss4_sig_idx0), &sig);
    try std.testing.expect(Xmss4.verify(kp.pk, interop_msg, &sig));

    // Jump the index like the reference generator does and sign again.
    kp.sk.idx = 11;
    try Xmss4.sign(&kp.sk, &sig, interop_msg);
    try std.testing.expectEqualSlices(u8, &decodeHex(vec.xmss4_sig_idx11), &sig);
    try std.testing.expect(Xmss4.verify(kp.pk, interop_msg, &sig));
}

test "KAT: verify external XMSS-SHA2_10_256 (pk, msg, sig) triples" {
    const X = xmss.XmssSha2_10_256;
    const pk_ref = decodeHex(vec.xmss10_pk);
    const pk = X.PublicKey{ .root = pk_ref[0..n].*, .seed = pk_ref[n..].* };

    const sig0 = decodeHex(vec.xmss10_sig_idx0);
    const sig517 = decodeHex(vec.xmss10_sig_idx517);
    try std.testing.expect(X.verify(pk, interop_msg, &sig0));
    try std.testing.expect(X.verify(pk, interop_msg, &sig517));

    // Wrong message.
    try std.testing.expect(!X.verify(pk, "XMSS interop test messagf", &sig0));
    try std.testing.expect(!X.verify(pk, "", &sig0));

    // Tampered signature fields: index word, randomness r, WOTS+ chain
    // value, auth-path node, trailing byte.
    inline for (.{ 3, 4 + 5, 4 + n + 7, 4 + n + xmss.wots_len * n + 3, X.signature_length - 1 }) |pos| {
        var bad = sig0;
        bad[pos] ^= 0x01;
        try std.testing.expect(!X.verify(pk, interop_msg, &bad));
    }

    // Signature/auth-path from one leaf must not verify as another leaf:
    // graft sig517's index onto sig0's body.
    var cross = sig0;
    cross[0..4].* = sig517[0..4].*;
    try std.testing.expect(!X.verify(pk, interop_msg, &cross));

    // Out-of-range index (2^10) and truncated/oversized buffers.
    var oor = sig0;
    std.mem.writeInt(u32, oor[0..4], 1024, .big);
    try std.testing.expect(!X.verify(pk, interop_msg, &oor));
    try std.testing.expect(!X.verify(pk, interop_msg, sig0[0 .. sig0.len - 1]));
    var oversized: [X.signature_length + 1]u8 = undefined;
    @memset(&oversized, 0);
    oversized[0..sig0.len].* = sig0;
    try std.testing.expect(!X.verify(pk, interop_msg, &oversized));

    // Wrong public key root.
    var pk_bad = pk;
    pk_bad.root[0] ^= 1;
    try std.testing.expect(!X.verify(pk_bad, interop_msg, &sig0));
}

const auth_off = 4 + n + xmss.wots_len * n;

/// buildAuth is the O(2^h) from-scratch auth-path reference; assert the BDS
/// path embedded in `sig` (at `idx`) matches it byte-for-byte.
fn expectAuthMatchesFromScratch(comptime X: type, sk_seed: *const [n]u8, pub_seed: *const [n]u8, idx: u32, sig: []const u8) !void {
    var expected: [X.h][n]u8 = undefined;
    X.buildAuth(sk_seed, pub_seed, idx, &expected);
    for (expected, 0..) |node, j| {
        try std.testing.expectEqualSlices(u8, &node, sig[auth_off + j * n ..][0..n]);
    }
}

test "BDS: h=4 exhaustive sequential signing + differential vs from-scratch auth" {
    const X = Xmss4;
    const seeds = refSeeds();
    var kp = X.keyGen(seeds.sk_seed, seeds.sk_prf, seeds.pub_seed);

    // Sign every leaf sequentially. Each signature must verify, carry the
    // right index, and its BDS-produced auth path must byte-match a fully
    // independent from-scratch computation (buildAuth) — the differential
    // that proves the traversal is correct at every index of the whole tree.
    var sig: [X.signature_length]u8 = undefined;
    var idx: u32 = 0;
    while (idx < X.max_signatures) : (idx += 1) {
        try std.testing.expectEqual(idx, kp.sk.idx);
        try std.testing.expectEqual(idx, kp.sk.bds.covered_idx);
        try X.sign(&kp.sk, &sig, "bds sweep");
        try std.testing.expectEqual(idx, std.mem.readInt(u32, sig[0..4], .big));
        try std.testing.expect(X.verify(kp.pk, "bds sweep", &sig));
        try expectAuthMatchesFromScratch(X, &seeds.sk_seed, &seeds.pub_seed, idx, &sig);
    }
    // Whole key consumed → permanently exhausted.
    try std.testing.expectError(error.KeyExhausted, X.sign(&kp.sk, &sig, "one too many"));
}

test "BDS: h=6 sequential sweep verifies every leaf; differential across the 2^(h-1) transition" {
    const X = Xmss6;
    var sk_seed: [n]u8 = undefined;
    var sk_prf: [n]u8 = undefined;
    var pub_seed: [n]u8 = undefined;
    for (&sk_seed, &sk_prf, &pub_seed, 0..) |*a, *b, *c, i| {
        a.* = @truncate(41 * i + 7);
        b.* = @truncate(53 * i + 11);
        c.* = @truncate(67 * i + 13);
    }
    var kp = X.keyGen(sk_seed, sk_prf, pub_seed);

    // Sign all 2^6 leaves (cheap: each sign is ~O(h)); verify each. Run the
    // O(2^h) from-scratch differential only at boundary indices — in
    // particular 31→32, the left/right-subtree transition at leaf 2^(h-1),
    // which exercises the top-level auth-node refresh and treehash restart.
    var sig: [X.signature_length]u8 = undefined;
    var idx: u32 = 0;
    while (idx < X.max_signatures) : (idx += 1) {
        try X.sign(&kp.sk, &sig, "h6 sweep");
        try std.testing.expectEqual(idx, std.mem.readInt(u32, sig[0..4], .big));
        try std.testing.expect(X.verify(kp.pk, "h6 sweep", &sig));
        switch (idx) {
            0, 1, 2, 30, 31, 32, 33, 62, 63 => try expectAuthMatchesFromScratch(X, &sk_seed, &pub_seed, idx, &sig),
            else => {},
        }
    }
    try std.testing.expectError(error.KeyExhausted, X.sign(&kp.sk, &sig, "one too many"));
}

test "BDS: out-of-band index jump resynchronizes to a byte-exact auth path" {
    // A caller that sets idx directly (e.g. index partitioning, or a restored
    // key) must still emit the correct auth path. sign() detects the desync
    // (covered_idx != idx) and rebuilds the traversal state; the result must
    // byte-match the from-scratch auth path for that leaf.
    const seeds = refSeeds();

    // h=4 jumps (cheap, several targets incl. last leaf).
    inline for (.{ 1, 5, 11, 15 }) |target| {
        var kp = Xmss4.keyGen(seeds.sk_seed, seeds.sk_prf, seeds.pub_seed);
        kp.sk.idx = target; // out-of-band jump (bds still at leaf 0)
        var sig: [Xmss4.signature_length]u8 = undefined;
        try Xmss4.sign(&kp.sk, &sig, "jump4");
        try std.testing.expectEqual(@as(u32, target), std.mem.readInt(u32, sig[0..4], .big));
        try std.testing.expect(Xmss4.verify(kp.pk, "jump4", &sig));
        try expectAuthMatchesFromScratch(Xmss4, &seeds.sk_seed, &seeds.pub_seed, target, &sig);
    }

    // One h=6 jump landing exactly on the 2^(h-1) transition leaf.
    var kp6 = Xmss6.keyGen(seeds.sk_seed, seeds.sk_prf, seeds.pub_seed);
    kp6.sk.idx = 32;
    var sig6: [Xmss6.signature_length]u8 = undefined;
    try Xmss6.sign(&kp6.sk, &sig6, "jump6");
    try std.testing.expect(Xmss6.verify(kp6.pk, "jump6", &sig6));
    try expectAuthMatchesFromScratch(Xmss6, &seeds.sk_seed, &seeds.pub_seed, 32, &sig6);
}

test "round-trip h=2: stateful index walk and exhaustion" {
    var sk_seed: [n]u8 = undefined;
    var sk_prf: [n]u8 = undefined;
    var pub_seed: [n]u8 = undefined;
    for (&sk_seed, &sk_prf, &pub_seed, 0..) |*a, *b, *c, i| {
        a.* = @truncate(97 * i + 1);
        b.* = @truncate(89 * i + 2);
        c.* = @truncate(83 * i + 3);
    }
    var kp = Xmss2.keyGen(sk_seed, sk_prf, pub_seed);

    var sigs: [4][Xmss2.signature_length]u8 = undefined;
    for (&sigs, 0..) |*sig, i| {
        try std.testing.expectEqual(@as(u32, @intCast(i)), kp.sk.idx);
        try Xmss2.sign(&kp.sk, sig, "stateful message");
        try std.testing.expect(Xmss2.verify(kp.pk, "stateful message", sig));
        // Each signature consumes a distinct one-time key.
        try std.testing.expectEqual(@as(u32, @intCast(i)), std.mem.readInt(u32, sig[0..4], .big));
    }

    // All 2^2 one-time keys used: the key is exhausted, permanently.
    var overflow_sig: [Xmss2.signature_length]u8 = undefined;
    try std.testing.expectError(error.KeyExhausted, Xmss2.sign(&kp.sk, &overflow_sig, "one too many"));

    // Signatures do not transfer between messages.
    try std.testing.expect(!Xmss2.verify(kp.pk, "another message", &sigs[0]));

    // Distinct indexes produce distinct signatures over the same message.
    try std.testing.expect(!std.mem.eql(u8, &sigs[0], &sigs[1]));
}
