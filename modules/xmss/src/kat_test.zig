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
    xmss.chainStep(&in, &pub_seed, &adrs);
    try std.testing.expectEqualSlices(u8, &decodeHex(vec.f_out), &in);
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
    var kp: Xmss4.KeyPair = undefined;
    Xmss4.keyGen(&kp, &seeds.sk_seed, &seeds.sk_prf, &seeds.pub_seed);

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

    // The computed root is compared in full: of 2048 tampered randomizers
    // (each a fresh, unrelated root), about eight would match pk.root in any
    // single byte.
    for (0..2048) |i| {
        var bad = sig0;
        bad[4] ^= @truncate(i);
        bad[5] ^= @truncate((i >> 8) + 1);
        try std.testing.expect(!X.verify(pk, interop_msg, &bad));
    }
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
    var kp: X.KeyPair = undefined;
    X.keyGen(&kp, &seeds.sk_seed, &seeds.sk_prf, &seeds.pub_seed);

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
    var kp: X.KeyPair = undefined;
    X.keyGen(&kp, &sk_seed, &sk_prf, &pub_seed);

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
        var kp: Xmss4.KeyPair = undefined;
        Xmss4.keyGen(&kp, &seeds.sk_seed, &seeds.sk_prf, &seeds.pub_seed);
        kp.sk.idx = target; // out-of-band jump (bds still at leaf 0)
        var sig: [Xmss4.signature_length]u8 = undefined;
        try Xmss4.sign(&kp.sk, &sig, "jump4");
        try std.testing.expectEqual(@as(u32, target), std.mem.readInt(u32, sig[0..4], .big));
        try std.testing.expect(Xmss4.verify(kp.pk, "jump4", &sig));
        try expectAuthMatchesFromScratch(Xmss4, &seeds.sk_seed, &seeds.pub_seed, target, &sig);
    }

    // One h=6 jump landing exactly on the 2^(h-1) transition leaf.
    var kp6: Xmss6.KeyPair = undefined;
    Xmss6.keyGen(&kp6, &seeds.sk_seed, &seeds.sk_prf, &seeds.pub_seed);
    kp6.sk.idx = 32;
    var sig6: [Xmss6.signature_length]u8 = undefined;
    try Xmss6.sign(&kp6.sk, &sig6, "jump6");
    try std.testing.expect(Xmss6.verify(kp6.pk, "jump6", &sig6));
    try expectAuthMatchesFromScratch(Xmss6, &seeds.sk_seed, &seeds.pub_seed, 32, &sig6);
}

test "KAT: h=2 sequential stateful walk byte-exact vs reference (leaves 0-2), exhaustion at leaf 3" {
    // Same keypair-seed convention as the h=4/h=10 vectors (byte i = i,
    // 0..95); see kat_vectors.zig for the full provenance note, including
    // why leaf 3 (the last of the 4 one-time keys) is excluded from the
    // byte comparison: the reference implementation itself corrupts that
    // leaf's index field before it leaves the reference's own signer.
    const seeds = refSeeds();
    var kp: Xmss2.KeyPair = undefined;
    Xmss2.keyGen(&kp, &seeds.sk_seed, &seeds.sk_prf, &seeds.pub_seed);

    const pk_ref = decodeHex(vec.xmss2_pk);
    try std.testing.expectEqualSlices(u8, pk_ref[0..n], &kp.pk.root);
    try std.testing.expectEqualSlices(u8, pk_ref[n..], &kp.pk.seed);

    const walk_msg = "XMSS h=2 stateful walk test";
    const ref_sigs = .{ vec.xmss2_sig_idx0, vec.xmss2_sig_idx1, vec.xmss2_sig_idx2 };

    var sigs: [4][Xmss2.signature_length]u8 = undefined;
    inline for (ref_sigs, 0..) |ref_hex, i| {
        try std.testing.expectEqual(@as(u32, @intCast(i)), kp.sk.idx);
        try Xmss2.sign(&kp.sk, &sigs[i], walk_msg);
        try std.testing.expectEqualSlices(u8, &decodeHex(ref_hex), &sigs[i]);
        try std.testing.expect(Xmss2.verify(kp.pk, walk_msg, &sigs[i]));
        try std.testing.expectEqual(@as(u32, @intCast(i)), std.mem.readInt(u32, sigs[i][0..4], .big));
    }

    // Leaf 3 (idx = 3 = 2^2 - 1): last valid one-time key. Not byte-anchored
    // (see above), but must still sign, verify, and carry the correct idx —
    // this module does not have the reference's terminal-leaf bug.
    try std.testing.expectEqual(@as(u32, 3), kp.sk.idx);
    try Xmss2.sign(&kp.sk, &sigs[3], walk_msg);
    try std.testing.expectEqual(@as(u32, 3), std.mem.readInt(u32, sigs[3][0..4], .big));
    try std.testing.expect(Xmss2.verify(kp.pk, walk_msg, &sigs[3]));

    // All 2^2 one-time keys used: the key is exhausted, permanently.
    var overflow_sig: [Xmss2.signature_length]u8 = undefined;
    try std.testing.expectError(error.KeyExhausted, Xmss2.sign(&kp.sk, &overflow_sig, "one too many"));

    // Signatures do not transfer between messages.
    try std.testing.expect(!Xmss2.verify(kp.pk, "another message", &sigs[0]));

    // Distinct indexes produce distinct signatures over the same message.
    try std.testing.expect(!std.mem.eql(u8, &sigs[0], &sigs[1]));
}

test "Adrs: every setter writes its RFC 8391 section 2.5 word, setType clears the type-specific words, toBytes is big-endian" {
    const Adrs = xmss.Adrs;
    var a: Adrs = .{};
    a.setLayerAddress(0x01020304);
    a.setTreeAddress(0x1112131415161718);
    a.setType(Adrs.type_hashtree);
    a.setTreeHeight(0x31323334);
    a.setTreeIndex(0x41424344);
    a.setKeyAndMask(0x51525354);
    try std.testing.expectEqualSlices(u32, &.{ 0x01020304, 0x11121314, 0x15161718, 2, 0, 0x31323334, 0x41424344, 0x51525354 }, &a.words);
    try std.testing.expectEqual(@as(u32, 0x41424344), a.getTreeIndex());

    const bytes = a.toBytes();
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 }, bytes[0..12]);
    try std.testing.expectEqualSlices(u8, &.{ 0x41, 0x42, 0x43, 0x44, 0x51, 0x52, 0x53, 0x54 }, bytes[24..32]);

    // The type word changes, everything after it resets; layer and tree stay.
    a.setType(Adrs.type_ots);
    try std.testing.expectEqualSlices(u32, &.{ 0x01020304, 0x11121314, 0x15161718, 0, 0, 0, 0, 0 }, &a.words);
    a.setOtsAddress(7);
    a.setChainAddress(8);
    a.setHashAddress(9);
    a.setKeyAndMask(10);
    try std.testing.expectEqualSlices(u32, &.{ 7, 8, 9, 10 }, a.words[4..8]);
    a.setType(Adrs.type_ltree);
    try std.testing.expectEqualSlices(u32, &.{ 1, 0, 0, 0, 0 }, a.words[3..8]);
    a.setLtreeAddress(11);
    try std.testing.expectEqual(@as(u32, 11), a.words[4]);
    try std.testing.expectEqualSlices(u32, &.{ 0, 0, 0 }, a.words[5..8]);
}

test "ltree: starts from tree height 0 whatever the caller's address held" {
    const seeds = refSeeds();
    var pk_a: [xmss.wots_len][n]u8 = undefined;
    for (&pk_a, 0..) |*node, i| {
        for (node, 0..) |*b, j| b.* = @truncate(i * 31 + j * 7 + 3);
    }
    var pk_b = pk_a;
    var fresh: xmss.Adrs = .{};
    fresh.setType(xmss.Adrs.type_ltree);
    fresh.setLtreeAddress(3);
    var dirty = fresh;
    dirty.setTreeHeight(9);
    dirty.setTreeIndex(5);
    dirty.setKeyAndMask(2);
    const a = xmss.ltree(&pk_a, &seeds.pub_seed, &fresh);
    const b = xmss.ltree(&pk_b, &seeds.pub_seed, &dirty);
    try std.testing.expectEqualSlices(u8, &a, &b);
}

test "keyGen initialises the whole BDS state: nothing of the caller's memory survives in the key" {
    const X = Xmss4;
    const seeds = refSeeds();
    var kp_a: X.KeyPair = undefined;
    @memset(std.mem.asBytes(&kp_a), 0xAA);
    var kp_b: X.KeyPair = undefined;
    @memset(std.mem.asBytes(&kp_b), 0x00);
    X.keyGen(&kp_a, &seeds.sk_seed, &seeds.sk_prf, &seeds.pub_seed);
    X.keyGen(&kp_b, &seeds.sk_seed, &seeds.sk_prf, &seeds.pub_seed);
    const a = &kp_a.sk.bds;
    const b = &kp_b.sk.bds;
    try std.testing.expectEqualSlices(u8, std.mem.asBytes(&a.stack), std.mem.asBytes(&b.stack));
    try std.testing.expectEqualSlices(u5, &a.stacklevels, &b.stacklevels);
    try std.testing.expectEqual(b.stackoffset, a.stackoffset);
    try std.testing.expectEqualSlices(u8, std.mem.asBytes(&a.auth), std.mem.asBytes(&b.auth));
    try std.testing.expectEqualSlices(u8, std.mem.asBytes(&a.keep), std.mem.asBytes(&b.keep));
    try std.testing.expectEqual(b.covered_idx, a.covered_idx);
    for (a.treehash, b.treehash) |ta, tb| {
        try std.testing.expectEqualSlices(u8, &tb.node, &ta.node);
        try std.testing.expectEqual(tb.next_idx, ta.next_idx);
        try std.testing.expectEqual(tb.target_h, ta.target_h);
        try std.testing.expectEqual(tb.stackusage, ta.stackusage);
        try std.testing.expectEqual(tb.completed, ta.completed);
    }
}

/// Sign every leaf of `X` in order; each signature verifies, carries its index and
/// matches the from-scratch auth path (at every leaf with `check_all`, else only at `check_idx`).
fn sweepTree(comptime X: type, comptime check_all: bool, check_idx: []const u32) !void {
    var sk_seed: [n]u8 = undefined;
    var sk_prf: [n]u8 = undefined;
    var pub_seed: [n]u8 = undefined;
    for (&sk_seed, &sk_prf, &pub_seed, 0..) |*a, *b, *c, i| {
        a.* = @truncate(29 * i + 3);
        b.* = @truncate(37 * i + 5);
        c.* = @truncate(43 * i + 9);
    }
    var kp: X.KeyPair = undefined;
    X.keyGen(&kp, &sk_seed, &sk_prf, &pub_seed);
    var sig: [X.signature_length]u8 = undefined;
    var idx: u32 = 0;
    while (idx < X.max_signatures) : (idx += 1) {
        try X.sign(&kp.sk, &sig, "sweep");
        try std.testing.expectEqual(idx, std.mem.readInt(u32, sig[0..4], .big));
        try std.testing.expect(X.verify(kp.pk, "sweep", &sig));
        const check = check_all or std.mem.indexOfScalar(u32, check_idx, idx) != null;
        if (check) try expectAuthMatchesFromScratch(X, &sk_seed, &pub_seed, idx, &sig);
    }
    try std.testing.expectError(error.KeyExhausted, X.sign(&kp.sk, &sig, "one too many"));
}

test "BDS: odd heights h=3 and h=5 (keep array of floor(h/2) slots) sweep every leaf against the from-scratch path" {
    try sweepTree(xmss.XmssSha2(3, 0xF0000003), true, &.{});
    try sweepTree(xmss.XmssSha2(5, 0xF0000005), true, &.{});
}

test "BDS: h=8 sweep verifies every leaf; from-scratch differential around the half-way and last leaves" {
    try sweepTree(xmss.XmssSha2(8, 0xF0000008), false, &.{ 0, 1, 2, 3, 126, 127, 128, 129, 252, 253, 254, 255 });
}

test "BDS: an out-of-band jump after real signing rebuilds from a clean traversal state" {
    // The jump tests above start from a key that has never signed (stack empty).
    // After a run of signs the shared treehash stack holds entries; the rebuild
    // has to start from an empty one or the replayed state is not the state a
    // key at that leaf would have.
    const X = Xmss6;
    const seeds = refSeeds();
    var kp_a: X.KeyPair = undefined;
    X.keyGen(&kp_a, &seeds.sk_seed, &seeds.sk_prf, &seeds.pub_seed);
    var kp_b: X.KeyPair = undefined;
    X.keyGen(&kp_b, &seeds.sk_seed, &seeds.sk_prf, &seeds.pub_seed);
    var sig_a: [X.signature_length]u8 = undefined;
    var sig_b: [X.signature_length]u8 = undefined;
    var used: u32 = 0;
    while (used < 11) : (used += 1) try X.sign(&kp_a.sk, &sig_a, "warm up");
    kp_a.sk.bds.stackoffset = X.h; // a stack base left over from the signing above
    kp_a.sk.idx = 37; // out-of-band jump on a key whose stack is in use
    kp_b.sk.idx = 37; // the same jump on a key that never signed
    var k: u32 = 0;
    while (k < 6) : (k += 1) {
        try X.sign(&kp_a.sk, &sig_a, "after jump");
        try X.sign(&kp_b.sk, &sig_b, "after jump");
        try std.testing.expectEqualSlices(u8, &sig_b, &sig_a);
        try std.testing.expect(X.verify(kp_a.pk, "after jump", &sig_a));
        try expectAuthMatchesFromScratch(X, &seeds.sk_seed, &seeds.pub_seed, 37 + k, &sig_a);
    }
}
