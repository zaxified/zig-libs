// SPDX-License-Identifier: MIT

//! What a consensus-layer validator set does with `bls12_381`: each
//! validator proves possession of its own key once at registration
//! (`popProve`/`popVerify`), then the set co-signs one block header and a
//! collector aggregates the three signatures into one for the network to
//! carry instead of three. Then the other things a client does: verify
//! many independent signatures in one batch, derive a validator key from a
//! seed (EIP-2333), use the min-sig suite (drand's), and a G2 MSM.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only,
//! no `test_deps`, no access to anything the module does not export). If a
//! type needed to call the API is not public, or an error cannot be named
//! from outside, this file stops compiling. The module's own tests cannot
//! notice either, because they live inside it.

const std = @import("std");
const bls12_381 = @import("bls12_381");
const bls_sig = bls12_381.bls_sig;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    // Three validators, each with their own secret material. `keyGen`'s IKM
    // must be >= 32 bytes (draft precondition) — a real deployment draws
    // this from a CSPRNG or a keystore; fixed bytes here keep the example
    // deterministic.
    const ikms = [_][]const u8{
        "validator-a-seed-material-000000",
        "validator-b-seed-material-000000",
        "validator-c-seed-material-000000",
    };

    var sks: [3]bls_sig.SecretKey = undefined;
    var pks: [3]bls_sig.PublicKey = undefined;
    for (ikms, 0..) |ikm, i| {
        try bls_sig.keyGen(&sks[i], ikm, "");
        pks[i] = bls_sig.skToPk(&sks[i]);
        if (!bls_sig.keyValidate(pks[i])) return error.BadKey;
    }

    // Registration-time step: each validator proves possession of the key
    // behind its public key, defeating rogue-key attacks against the
    // aggregate verify used below (draft §3.3.4's precondition).
    for (&sks, pks) |*sk, pk| {
        const proof = bls_sig.popProve(sk);
        if (!bls_sig.popVerify(pk, proof)) return error.PopFailed;
    }

    // `keyGen` also names its precondition failure: an IKM under 32 bytes
    // is rejected rather than silently accepted.
    var rejected: bls_sig.SecretKey = undefined;
    bls_sig.keyGen(&rejected, "too-short", "") catch |err| switch (err) {
        error.IkmTooShort => std.debug.print("short IKM correctly rejected\n", .{}),
        else => return err,
    };

    // All three validators co-sign the same block header.
    const header = "block #4,102,881 state_root=0xabc123";
    var sigs: [3]bls_sig.Signature = undefined;
    for (&sks, 0..) |*sk, i| sigs[i] = bls_sig.sign(sk, header);

    // The collector aggregates into a single signature for the wire.
    const agg = try bls_sig.aggregate(&sigs);
    std.debug.print("aggregated {d} signatures into one ({d} bytes on the wire)\n", .{
        sigs.len, bls_sig.Signature.encoded_bytes,
    });

    // A receiver with just the aggregate and the three public keys verifies
    // the whole set in one pairing check.
    const ok = try bls_sig.fastAggregateVerify(&pks, header, agg);
    std.debug.print("fastAggregateVerify: {}\n", .{ok});
    if (!ok) return error.VerifyFailed;

    // `aggregate`/`fastAggregateVerify` name their empty-input precondition
    // too — a collector that received zero signatures must be able to
    // detect that case rather than crash.
    const empty: []const bls_sig.Signature = &.{};
    _ = bls_sig.aggregate(empty) catch |err| switch (err) {
        error.EmptySet => std.debug.print("empty signature set correctly rejected\n", .{}),
        else => return err,
    };

    // A tampered header must fail verification against the same aggregate.
    const tampered_ok = try bls_sig.fastAggregateVerify(&pks, "block #4,102,881 state_root=0xdeadbeef", agg);
    std.debug.print("fastAggregateVerify on tampered header: {}\n", .{tampered_ok});
    if (tampered_ok) return error.ShouldHaveFailed;

    // Independent attestations, each over its own message: one batch check
    // (one final exponentiation) instead of one per signature.
    const atts = [_][]const u8{ "att slot 1", "att slot 2", "att slot 3" };
    var att_sigs: [3]bls_sig.Signature = undefined;
    for (&sks, atts, &att_sigs) |*sk, m, *sig| sig.* = bls_sig.sign(sk, m);
    const batch_ok = try bls_sig.verifyBatch(io, &pks, &atts, &att_sigs);
    std.debug.print("verifyBatch of {d} attestations: {}\n", .{ atts.len, batch_ok });
    if (!batch_ok) return error.BatchFailed;

    // An Ethereum validator signing key from a mnemonic-derived seed, by
    // its EIP-2334 path.
    const seed = [_]u8{0x5e} ** 32;
    const path = try bls12_381.eip2333.parsePath("m/12381/3600/0/0/0");
    var vsk: bls_sig.SecretKey = undefined;
    try bls12_381.eip2333.derivePath(&vsk, &seed, path.slice());
    defer vsk.deinit();
    const vpk = bls_sig.skToPk(&vsk);
    std.debug.print("validator 0 pubkey starts {x}\n", .{vpk.toBytes()[0..4]});

    // The min-sig suite: 48-byte signatures, 96-byte keys (drand quicknet's
    // BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_).
    const S = bls_sig.MinSigBasic;
    const beacon_pk = S.skToPk(&sks[0]);
    const beacon_sig = S.sign(&sks[0], "round 1000");
    std.debug.print("min-sig: {d}-byte signature verifies: {}\n", .{ S.Signature.encoded_bytes, S.verify(beacon_pk, "round 1000", beacon_sig) });
    if (!S.verify(beacon_pk, "round 1000", beacon_sig)) return error.MinSigFailed;

    // A G2 multi-scalar multiplication (public data only).
    const g2 = bls12_381.G2;
    const points = [_]g2.Affine{ g2.Affine.generator, g2.Affine.generator };
    const one = bls12_381.Fr.one;
    const sum = try bls12_381.msm.g2Msm(std.heap.page_allocator, &points, &.{ one, one });
    const twice = g2.Jacobian.fromAffine(g2.Affine.generator).double();
    if (!std.mem.eql(u8, &g2.toBytesCompressed(sum.toAffine()), &g2.toBytesCompressed(twice.toAffine())))
        return error.MsmMismatch;
    std.debug.print("g2Msm(G, G; 1, 1) == 2G\n", .{});
}
