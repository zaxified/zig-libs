// SPDX-License-Identifier: MIT

//! What a two-party payment channel does with `musig2`: co-sign the settlement
//! transaction so that what lands on chain is one ordinary 64-byte BIP340
//! signature under one ordinary x-only key. No script, no multisig branch,
//! nothing that tells an observer two parties were involved — which is the
//! entire reason to run MuSig2 instead of a 2-of-2 script.
//!
//! Both signers run here in turn because that is the shape of the protocol a
//! caller has to drive: the module supplies the round functions, not the
//! session. Each signer's secret nonce never leaves its own scope.
//!
//! This is an example in the gate sense — it is built against the PUBLISHED
//! module (`@import("musig2")` plus its declared deps `bip340` and `k256`,
//! which are published modules a real consumer can depend on too). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling. The module's own tests cannot notice
//! either, because they live inside it.
//!
//! Every secret here is a fixed literal so the run is reproducible. A
//! deployment draws each signer's key and each `rand_prime` from a CSPRNG;
//! BIP327 is explicit that reusing a `rand_prime` across two sessions leaks
//! the secret key, so this file's constants are for reading, not copying.

const std = @import("std");
const musig2 = @import("musig2");
const bip340 = @import("bip340");
const k256 = @import("k256");

/// The two channel parties' secret keys.
const alice_sk_bytes: [32]u8 = .{
    0x2f, 0x84, 0x0b, 0xd7, 0x51, 0x1c, 0xe6, 0x39, 0xa0, 0x75, 0x3e, 0xc8, 0x42, 0x9b, 0x06, 0xfd,
    0x18, 0x53, 0xa7, 0x24, 0x6b, 0xcf, 0x90, 0x11, 0x37, 0xe2, 0x5a, 0x8c, 0x04, 0xd1, 0x76, 0x2b,
};
const bob_sk_bytes: [32]u8 = .{
    0x93, 0x1a, 0x40, 0x6e, 0xb5, 0x27, 0x0c, 0xd8, 0x64, 0xf3, 0x11, 0x9a, 0x05, 0x7c, 0xe0, 0x38,
    0x21, 0xbd, 0x49, 0x86, 0x0f, 0x52, 0xa3, 0xc7, 0x70, 0x1e, 0xd4, 0x69, 0x3b, 0x08, 0x95, 0x42,
};

/// One fresh `rand'` per signer per session (BIP327's `NonceGen` input).
const alice_rand: [32]u8 = @splat(0x31);
const bob_rand: [32]u8 = @splat(0x72);

/// The settlement transaction's sighash — what actually gets signed.
const sighash = "sighash:channel-8841:settle:alice=250000,bob=750000";

/// One signer's local state between the two rounds.
const Signer = struct {
    sk: bip340.SecretKey,
    pk: musig2.PlainPublicKey,
    secnonce: musig2.SecNonce,
    pubnonce: musig2.PubNonce,
};

/// A signer's own plain (33-byte, compressed) public key. BIP327 identifies
/// signers by this form, but the module has no `PlainPublicKey.fromSecretKey`
/// — so a consumer computes `d*G` itself through `k256`, the module's own
/// curve dependency.
fn plainPubkey(sk: bip340.SecretKey) !musig2.PlainPublicKey {
    const point = try k256.Secp256k1.combMulBase(sk.bytes, .big);
    return musig2.PlainPublicKey.fromBytes(point.toCompressedSec1());
}

pub fn main() !void {
    // `nonceGen` takes an `std.Io` it never reads (its randomness is the
    // explicit `rand_prime` parameter), but the signature demands one, so a
    // consumer has to have an instance in hand to call it at all.
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();

    const alice_sk = try bip340.SecretKey.fromBytes(alice_sk_bytes);
    const bob_sk = try bip340.SecretKey.fromBytes(bob_sk_bytes);

    // ── setup: the channel's aggregate key ───────────────────────────────
    // BIP327's KeyAgg is order-dependent, and `keySort` is the canonical
    // ordering both parties apply so they derive the same channel key from
    // the same set without negotiating an order.
    const alice_pk = try plainPubkey(alice_sk);
    const bob_pk = try plainPubkey(bob_sk);
    var pubkeys = [_]musig2.PlainPublicKey{ alice_pk, bob_pk };
    musig2.keySort(&pubkeys);

    const keyagg = musig2.keyAgg(&pubkeys) catch |err| switch (err) {
        // A party that sent a malformed key is named, so the other can say
        // which one rather than "channel setup failed".
        error.InvalidPublicKey => {
            std.debug.print("a party contributed an invalid public key\n", .{});
            return;
        },
        error.PointAtInfinity => {
            std.debug.print("aggregate key is the point at infinity, refusing\n", .{});
            return;
        },
    };
    const channel_key = keyagg.getXonlyPubkey();
    std.debug.print("channel key: {s}\n", .{std.fmt.bytesToHex(channel_key, .lower)});

    // ── round 1: each party commits to a fresh nonce pair ────────────────
    // Only the 66-byte pubnonce is exchanged. Binding `msg` and `aggpk` into
    // the derivation is optional in the spec but strictly better: a nonce
    // derived for this sighash cannot be reused under another one.
    //
    // `partialSigVerify` and `partialSigAgg` index `pubnonces`/`psigs` with
    // the SAME index they use for `pubkeys`, so every per-signer array below
    // is built in the order `keySort` just produced — not in the order the
    // two parties happen to appear in this file.
    var signers: [2]Signer = undefined;
    for (pubkeys, &signers) |pk, *s| {
        const is_alice = std.mem.eql(u8, &pk.bytes, &alice_pk.bytes);
        const sk = if (is_alice) alice_sk else bob_sk;
        const rand = if (is_alice) alice_rand else bob_rand;
        const generated = musig2.nonceGen(
            sk.bytes,
            pk.toBytes(),
            channel_key,
            sighash,
            null,
            rand,
            io,
        ) catch |err| switch (err) {
            // Negligible but not impossible; a signer redraws rather than
            // publishing a commitment it cannot open.
            error.InvalidNonce => {
                std.debug.print("degenerate nonce, redraw\n", .{});
                return;
            },
        };
        s.* = .{ .sk = sk, .pk = pk, .secnonce = generated.secnonce, .pubnonce = generated.pubnonce };
    }
    defer for (&signers) |*s| s.secnonce.deinit();

    const pubnonces = [_]musig2.PubNonce{ signers[0].pubnonce, signers[1].pubnonce };
    const aggnonce = try musig2.nonceAgg(&pubnonces);

    // ── round 2: each party produces a partial signature ─────────────────
    // The session context is the same value on both sides. It has to be
    // constructible from outside, and it is — every field is public.
    const ctx: musig2.SessionContext = .{
        .aggnonce = aggnonce,
        .pubkeys = &pubkeys,
        .msg = sighash,
    };

    var psigs: [2]musig2.PartialSignature = undefined;
    for (&signers, &psigs) |*s, *out| {
        out.* = musig2.sign(s.secnonce, s.sk, ctx) catch |err| switch (err) {
            // The mandatory self-check. A signer never publishes an
            // unverified partial signature, because a faulty one leaks
            // information about the secret key.
            error.SignatureVerificationFailed => {
                std.debug.print("self-verification failed, refusing to publish\n", .{});
                return;
            },
            else => return err,
        };
    }

    // ── the coordinator: check each share BEFORE aggregating ─────────────
    // Otherwise a single bad party yields one useless signature and no way to
    // say who broke it.
    for (psigs, 0..) |psig, i| {
        musig2.partialSigVerify(psig, &pubnonces, &pubkeys, &.{}, sighash, i) catch |err| switch (err) {
            error.InvalidPartialSignature => {
                std.debug.print("partial signature from signer {d} is bad — blame that party\n", .{i});
                return;
            },
            else => return err,
        };
    }

    const sig_bytes = try musig2.partialSigAgg(&psigs, ctx);

    // ── an ordinary Bitcoin node ─────────────────────────────────────────
    // It has never heard of MuSig2. This is the headline property: the output
    // is a plain BIP340 signature under a plain x-only key.
    const onchain_key = try bip340.XOnlyPublicKey.fromBytes(channel_key);
    const onchain_sig = try bip340.Signature.fromBytes(sig_bytes);
    if (!bip340.verify(onchain_key, sighash, onchain_sig)) {
        return error.AggregateSignatureRejected;
    }
    std.debug.print("settlement verifies as a solo BIP340 signature\n", .{});

    // ── the rejections a coordinator must handle ─────────────────────────
    // 1. A party that signed a DIFFERENT sighash — the classic channel
    //    attack, where one side tries to settle an older, better-for-them
    //    state. Its partial signature is valid for its own session and
    //    invalid for this one.
    const other_sighash = "sighash:channel-8841:settle:alice=900000,bob=100000";
    if (musig2.partialSigVerify(psigs[0], &pubnonces, &pubkeys, &.{}, other_sighash, 0)) |_| {
        return error.WrongMessagePartialAccepted;
    } else |err| switch (err) {
        error.InvalidPartialSignature => std.debug.print("partial signature for another sighash rejected\n", .{}),
        else => return err,
    }

    // 2. A signer trying to use the OTHER party's secret nonce with its own
    //    key — the shape a nonce-reuse or state-confusion bug takes. The
    //    module refuses before touching the secret key, by name.
    if (musig2.sign(signers[1].secnonce, signers[0].sk, ctx)) |_| {
        return error.MismatchedNonceAccepted;
    } else |err| switch (err) {
        error.SecretKeyMismatch => std.debug.print("secnonce/key mismatch rejected\n", .{}),
        else => return err,
    }

    // 3. A third party trying to join a session it is not part of. BIP327
    //    marks this check optional; the module performs it, which is what
    //    lets the caller distinguish "not your session" from "bad signature".
    const outsider_sk = try bip340.SecretKey.fromBytes(@splat(0x11));
    const outsider_pk = try plainPubkey(outsider_sk);
    const outsider_nonce = try musig2.nonceGen(
        outsider_sk.bytes,
        outsider_pk.toBytes(),
        channel_key,
        sighash,
        null,
        @splat(0x99),
        io,
    );
    var outsider_secnonce = outsider_nonce.secnonce;
    defer outsider_secnonce.deinit();
    if (musig2.sign(outsider_secnonce, outsider_sk, ctx)) |_| {
        return error.OutsiderSignatureAccepted;
    } else |err| switch (err) {
        error.PubkeyNotInSession => std.debug.print("signer outside the session rejected\n", .{}),
        else => return err,
    }

    // 4. A tampered aggregate signature must fail at the ordinary BIP340
    //    verifier, which returns a bool — a caller writing `try` here has
    //    written nothing.
    var forged = sig_bytes;
    forged[63] ^= 0x01;
    if (bip340.Signature.fromBytes(forged)) |parsed| {
        if (bip340.verify(onchain_key, sighash, parsed)) return error.TamperedSignatureAccepted;
        std.debug.print("tampered aggregate signature rejected\n", .{});
    } else |err| switch (err) {
        error.InvalidSignature => std.debug.print("tampered aggregate signature does not even parse\n", .{}),
    }
}
