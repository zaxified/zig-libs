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
