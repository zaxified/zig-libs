// SPDX-License-Identifier: MIT
//! MuSig2 + adaptor: the 2-of-2 atomic-swap / PTLC flow. Two signers run a
//! MuSig2 session whose `SessionContext.adaptor` is `T = t·G`; the aggregate
//! of their partial signatures is a pre-signature of this module
//! (`PreSignature{ r, s', needs_negation = nonceNeedsNegation }`) under the
//! aggregate key, `preVerify` accepts it, `adapt` with `t` is a plain BIP340
//! signature under the aggregate key (tweaked or not), and `extract` recovers
//! `t` from the pre-signature and the published signature. Tested over many
//! keys / messages so both parities of the final nonce occur.

const std = @import("std");
const testing = std.testing;
const bip340 = @import("bip340");
const k256 = @import("k256");
const musig2 = @import("musig2");
const adaptor = @import("root.zig");

fn plainPk(sk: *const bip340.SecretKey) !musig2.PlainPublicKey {
    const p = try k256.Secp256k1.combMulBase(sk.bytes, .big);
    const aff = p.affineCoordinates();
    var b: [33]u8 = undefined;
    b[0] = if (aff.y.isOdd()) 3 else 2;
    b[1..33].* = aff.x.toBytes(.big);
    return musig2.PlainPublicKey.fromBytes(b);
}

fn runFlow(seed: u8, tweaks: []const musig2.Tweak, parities: *[2]usize) !void {
    const sk_a = try bip340.SecretKey.fromBytes(@splat(seed));
    const sk_b = try bip340.SecretKey.fromBytes(@splat(seed +% 1));
    const pks = [_]musig2.PlainPublicKey{ try plainPk(&sk_a), try plainPk(&sk_b) };
    var msg: [32]u8 = @splat(seed);
    msg[0] ^= 0x5a;

    var agg = try musig2.keyAgg(&pks);
    for (tweaks) |tw| agg = try agg.applyTweak(tw.tweak, tw.is_xonly);
    const aggpk = agg.getXonlyPubkey();

    const t_secret: [32]u8 = @splat(seed +% 7);
    const t_point = try adaptor.AdaptorPoint.fromSecret(&t_secret);
    const adaptor_pk = try musig2.PlainPublicKey.fromBytes(t_point.toBytes());

    var na: musig2.NonceGenResult = undefined;
    var nb: musig2.NonceGenResult = undefined;
    try musig2.nonceGen(&na, &sk_a.bytes, pks[0].bytes, aggpk, &msg, null, &@as([32]u8, @splat(seed +% 3)), testing.io);
    try musig2.nonceGen(&nb, &sk_b.bytes, pks[1].bytes, aggpk, &msg, null, &@as([32]u8, @splat(seed +% 4)), testing.io);
    const pubnonces = [_]musig2.PubNonce{ na.pubnonce, nb.pubnonce };
    const ctx: musig2.SessionContext = .{
        .aggnonce = try musig2.nonceAgg(&pubnonces),
        .pubkeys = &pks,
        .tweaks = tweaks,
        .msg = &msg,
        .adaptor = adaptor_pk,
    };

    const psig_a = try musig2.sign(&na.secnonce, &sk_a, ctx);
    const psig_b = try musig2.sign(&nb.secnonce, &sk_b, ctx);
    try musig2.partialSigVerifyAdaptor(psig_a, &pubnonces, &pks, tweaks, &msg, adaptor_pk, 0);
    try musig2.partialSigVerifyAdaptor(psig_b, &pubnonces, &pks, tweaks, &msg, adaptor_pk, 1);
    // The same partial signature does not verify against a session without the adaptor.
    try testing.expectError(error.InvalidPartialSignature, musig2.partialSigVerify(psig_a, &pubnonces, &pks, tweaks, &msg, 0));

    const agg_sig = try musig2.partialSigAgg(&.{ psig_a, psig_b }, ctx);
    const negation = try musig2.nonceNeedsNegation(ctx);
    parities[@intFromBool(negation)] += 1;
    const presig: adaptor.PreSignature = .{ .r = agg_sig[0..32].*, .s_prime = agg_sig[32..64].*, .needs_negation = negation };

    const pubkey = try bip340.XOnlyPublicKey.fromBytes(aggpk);
    try testing.expect(adaptor.preVerify(pubkey, &msg, t_point, presig));
    // Not a signature yet.
    try testing.expect(!bip340.verify(pubkey, &msg, try bip340.Signature.fromBytes(agg_sig)));
    // Wrong adaptor point / flipped parity bit are refused.
    const other_t = try adaptor.AdaptorPoint.fromSecret(&@as([32]u8, @splat(seed +% 9)));
    try testing.expect(!adaptor.preVerify(pubkey, &msg, other_t, presig));
    var flipped = presig;
    flipped.needs_negation = !flipped.needs_negation;
    try testing.expect(!adaptor.preVerify(pubkey, &msg, t_point, flipped));

    const full = try adaptor.adapt(presig, &t_secret);
    const full_sig = try bip340.Signature.fromBytes(full);
    try testing.expect(bip340.verify(pubkey, &msg, full_sig));
    try testing.expectEqualSlices(u8, &t_secret, &(try adaptor.extract(presig, full_sig, t_point)));
}

test "MuSig2 + adaptor: pre-signature, adapt and extract over an aggregate key (both nonce parities, tweaked and not)" {
    var parities: [2]usize = .{ 0, 0 };
    var seed: u8 = 1;
    while (seed < 25) : (seed += 1) try runFlow(seed, &.{}, &parities);
    const tw = [_]musig2.Tweak{ .{ .tweak = @splat(0x31), .is_xonly = false }, .{ .tweak = @splat(0x42), .is_xonly = true } };
    seed = 40;
    while (seed < 60) : (seed += 1) try runFlow(seed, &tw, &parities);
    try testing.expect(parities[0] > 3 and parities[1] > 3);
}
