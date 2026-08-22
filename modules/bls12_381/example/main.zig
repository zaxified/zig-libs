// SPDX-License-Identifier: MIT

//! What a consensus-layer validator set does with `bls12_381`: each
//! validator proves possession of its own key once at registration
//! (`popProve`/`popVerify`), then the set co-signs one block header and a
//! collector aggregates the three signatures into one for the network to
//! carry instead of three.
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

pub fn main() !void {
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
        sks[i] = try bls_sig.keyGen(ikm, "");
        pks[i] = bls_sig.skToPk(sks[i]);
        if (!bls_sig.keyValidate(pks[i])) return error.BadKey;
    }

    // Registration-time step: each validator proves possession of the key
    // behind its public key, defeating rogue-key attacks against the
    // aggregate verify used below (draft §3.3.4's precondition).
    for (sks, pks) |sk, pk| {
        const proof = bls_sig.popProve(sk);
        if (!bls_sig.popVerify(pk, proof)) return error.PopFailed;
    }

    // `keyGen` also names its precondition failure: an IKM under 32 bytes
    // is rejected rather than silently accepted.
    _ = bls_sig.keyGen("too-short", "") catch |err| switch (err) {
        error.IkmTooShort => std.debug.print("short IKM correctly rejected\n", .{}),
        else => return err,
    };

    // All three validators co-sign the same block header.
    const header = "block #4,102,881 state_root=0xabc123";
    var sigs: [3]bls_sig.Signature = undefined;
    for (sks, 0..) |sk, i| sigs[i] = bls_sig.sign(sk, header);

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
}
