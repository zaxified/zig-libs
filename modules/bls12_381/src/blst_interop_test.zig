// SPDX-License-Identifier: MIT
//! Interop against supranational/blst, run as a black box by
//! `tools/blst-vectors` (vectors in `blst_vectors.zig`, see its header).
//! For each of the six ciphersuites: our `keyGen` (draft -05) reproduces
//! blst's `key_gen_v5` from the same IKM; `skToPk`, `sign` and (POP) `popProve` reproduce
//! blst's bytes; `verify`/`popVerify` accept blst's output and refuse it
//! with one message bit flipped; the aggregate of every case and (POP) the
//! shared-message fast aggregate reproduce blst's and verify. EIP-2333
//! master and child keys reproduce blst's `derive_*_eip2333`.

const std = @import("std");
const v = @import("blst_vectors.zig");
const bls_sig = @import("bls_sig.zig");
const scheme = @import("scheme.zig");
const eip2333 = @import("eip2333.zig");

const testing = std.testing;
const max_hex = 512;

fn unhex(comptime n: usize, hex: []const u8) ![n]u8 {
    var out: [n]u8 = undefined;
    if (hex.len != 2 * n) return error.BadVectorLength;
    _ = try std.fmt.hexToBytes(&out, hex);
    return out;
}

fn unhexSlice(buf: []u8, hex: []const u8) ![]u8 {
    return std.fmt.hexToBytes(buf[0 .. hex.len / 2], hex);
}

fn checkSuite(comptime S: type, comptime suite: v.Suite, comptime pop: bool) !void {
    try testing.expectEqualStrings(suite.dst, S.dst_sig);
    var pks: [suite.sign.len]S.PublicKey = undefined;
    var msg_bufs: [suite.sign.len][max_hex]u8 = undefined;
    var msgs: [suite.sign.len][]const u8 = undefined;
    for (suite.sign, 0..) |c, i| {
        var ikm_buf: [64]u8 = undefined;
        const ikm = try unhexSlice(&ikm_buf, c.ikm);
        // draft -05 KeyGen against blst's key_gen_v5. The signing key is
        // blst's default (-04-compatible) key_gen output, taken as bytes.
        try testing.expectEqual(try unhex(32, c.sk_v5), (try bls_sig.keyGen(ikm, "")).toBytes());
        const sk = try bls_sig.SecretKey.fromBytes(try unhex(32, c.sk));

        const pk = S.skToPk(sk);
        try testing.expectEqual(try unhex(S.PublicKey.encoded_bytes, c.pk), pk.toBytes());
        pks[i] = pk;

        const msg = try unhexSlice(&msg_bufs[i], c.msg);
        msgs[i] = msg;
        const sig = S.sign(sk, msg);
        const want_sig = try unhex(S.Signature.encoded_bytes, c.sig);
        try testing.expectEqual(want_sig, sig.toBytes());
        const foreign = try S.Signature.fromBytes(want_sig);
        try testing.expect(S.verify(pk, msg, foreign));
        // Negative control: one flipped message bit (or one appended byte
        // for the empty message).
        if (msg.len > 0) {
            var bad = msg_bufs[i];
            bad[0] ^= 1;
            try testing.expect(!S.verify(pk, bad[0..msg.len], foreign));
        } else {
            try testing.expect(!S.verify(pk, "\x00", foreign));
        }

        if (pop) {
            const want_pop = try unhex(S.Signature.encoded_bytes, c.pop);
            try testing.expectEqual(want_pop, S.popProve(sk).toBytes());
            try testing.expect(S.popVerify(pk, try S.Signature.fromBytes(want_pop)));
        }
    }
    const agg = try S.Signature.fromBytes(try unhex(S.Signature.encoded_bytes, suite.aggregate));
    try testing.expect(try S.aggregateVerify(&pks, &msgs, agg));
    try testing.expect(!try S.aggregateVerify(pks[1..], msgs[1..], agg));

    if (pop) {
        const f = suite.fast.?;
        var fpks: [4]S.PublicKey = undefined;
        for (f.sks, &fpks) |sk_hex, *pk| {
            pk.* = S.skToPk(try bls_sig.SecretKey.fromBytes(try unhex(32, sk_hex)));
        }
        var fmsg_buf: [max_hex]u8 = undefined;
        const fmsg = try unhexSlice(&fmsg_buf, f.msg);
        const fagg = try S.Signature.fromBytes(try unhex(S.Signature.encoded_bytes, f.aggregate));
        try testing.expect(try S.fastAggregateVerify(&fpks, fmsg, fagg));
        try testing.expect(!try S.fastAggregateVerify(fpks[0..3], fmsg, fagg));
    }
}

test "blst interop: min-pk Basic" {
    try checkSuite(scheme.MinPkBasic, v.min_pk_basic, false);
}
test "blst interop: min-pk MessageAugmentation" {
    try checkSuite(scheme.MinPkAug, v.min_pk_aug, false);
}
test "blst interop: min-pk ProofOfPossession" {
    try checkSuite(scheme.MinPkPop, v.min_pk_pop, true);
}
test "blst interop: min-sig Basic" {
    try checkSuite(scheme.MinSigBasic, v.min_sig_basic, false);
}
test "blst interop: min-sig MessageAugmentation" {
    try checkSuite(scheme.MinSigAug, v.min_sig_aug, false);
}
test "blst interop: min-sig ProofOfPossession" {
    try checkSuite(scheme.MinSigPop, v.min_sig_pop, true);
}

test "blst interop: EIP-2333 master and child keys" {
    for (v.eip2333) |c| {
        var seed_buf: [128]u8 = undefined;
        const seed = try unhexSlice(&seed_buf, c.seed);
        const master = try eip2333.deriveMasterSk(seed);
        try testing.expectEqual(try unhex(32, c.master), master.toBytes());
        try testing.expectEqual(try unhex(32, c.child), eip2333.deriveChildSk(master, c.index).toBytes());
    }
}
