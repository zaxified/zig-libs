// SPDX-License-Identifier: MIT

//! What a custody service does with `dkg`: bring up a 2-of-3 ECDSA signing key
//! for a new customer without ever assembling that key anywhere. There is no
//! dealer to compromise and no machine to trust — each node contributes to the
//! secret, none learns it, and what comes out is a plain secp256k1 public key
//! the rest of the world can treat as ordinary.
//!
//! GJKR is the construction that makes this bias-resistant: parties commit
//! (Pedersen) and the qualified set is fixed BEFORE anyone reveals a Feldman
//! commitment, so a node that waits to see everyone else's contribution still
//! cannot steer the resulting key.
//!
//! This is an example in the gate sense — it is built against the PUBLISHED
//! module (`@import("dkg")`; `threshold_ecdsa` and `paillier` are the module's
//! own dependencies, not this file's). If a type needed to call the API is not
//! public, or an error cannot be named from outside, this file stops
//! compiling. The module's own tests cannot notice either, because they live
//! inside it.
//!
//! One thing a consumer must not copy from this file: the fixed PRNG seed
//! below. `Dkg.run` takes a `std.Random`, so nothing stops a caller passing a
//! seeded generator — and the group secret is then a pure function of that
//! seed. A deployment must pass a CSPRNG-backed `std.Random`; the literal here
//! exists only so the run is reproducible.

const std = @import("std");
const dkg = @import("dkg");

/// The custody policy: any two of three nodes can sign.
const config: dkg.Config = .{ .t = 2, .n = 3 };

/// FOR THIS EXAMPLE ONLY — see the module doc comment above.
const reproducible_seed: u64 = 0xC0FFEE_1234;

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    var prng: std.Random.DefaultPrng = .init(reproducible_seed);
    const random = prng.random();

    // ── the three nodes run the protocol ─────────────────────────────────
    // `Corruption{}` means "everyone behaved"; the driver runs both rounds,
    // the complaint phase and the QUAL determination, and hands each party
    // back its own output.
    const outputs = dkg.Dkg.run(gpa, config, .{}, random) catch |err| switch (err) {
        error.OutOfMemory => return err,
        error.InvalidConfig => {
            std.debug.print("impossible policy: {d}-of-{d}\n", .{ config.t, config.n });
            return;
        },
        // The protocol ran but could not produce a key — too few honest
        // dealers survived QUAL. A custody service retries with a different
        // node set rather than shipping a key nobody can sign with.
        error.ProtocolError, error.EmptyQual => {
            std.debug.print("DKG aborted: not enough qualified dealers\n", .{});
            return;
        },
        else => return err,
    };
    defer {
        for (outputs) |*o| o.deinit(); // wipe every secret share we handled
        gpa.free(outputs);
    }

    // ── the checks the service runs before it trusts the key ─────────────
    // 1. Every node must have derived the SAME public key. A disagreement
    //    here means the nodes are holding shares of different keys, which
    //    only shows up at the first signing attempt otherwise.
    if (!dkg.checks.allSameQ(outputs)) return error.NodesDisagreeOnGroupKey;

    // 2. Each node's published verifying share must match its secret share.
    //    This is what lets a later signing round blame a specific node.
    for (outputs) |o| {
        if (!dkg.checks.verifyingShareConsistent(o)) {
            std.debug.print("node {d} published an inconsistent verifying share\n", .{o.index});
            return;
        }
    }

    // 3. The decisive one: any `t` shares must Lagrange-reconstruct a secret
    //    whose public point is the group key. This is offline and it is the
    //    only check that catches a node that accepted a bad share during the
    //    protocol.
    if (!try dkg.checks.reconstructsToQ(gpa, outputs[0..config.t])) {
        return error.SharesDoNotReconstructGroupKey;
    }

    const group_key = outputs[0].group_public_key.toBytes();
    std.debug.print("group key {s} ({d} shares, threshold {d})\n", .{
        std.fmt.bytesToHex(group_key[0..8].*, .lower),
        outputs.len,
        config.t,
    });

    // ── persistence: each node stores its own output ─────────────────────
    // A node restarts; its share has to survive as bytes and come back
    // identical, so both directions of the codec have to be public.
    const stored = outputs[1].toBytes();
    const restored = dkg.DkgShareOutput.fromBytes(stored) catch |err| switch (err) {
        // On-disk bytes are not trusted input either: a corrupted share file
        // is a named error, not a panic on a non-curve point.
        error.InvalidEncoding, error.InvalidElement => {
            std.debug.print("stored share is corrupt, node must re-key\n", .{});
            return;
        },
    };
    if (restored.index != outputs[1].index) return error.ShareRoundTripChangedIndex;
    std.debug.print("node {d} reloaded its {d}-byte share\n", .{ restored.index, stored.len });

    // ── the rejection the service must handle: a Byzantine dealer ────────
    // Node 2 sends node 3 a share that does not open its own broadcast
    // commitment, and then fails to defend itself when node 3 complains. The
    // protocol must disqualify it and still finish with a usable key among
    // the honest majority — that is the whole difference between a DKG and a
    // key exchange that any single participant can sabotage.
    var byzantine_prng: std.Random.DefaultPrng = .init(reproducible_seed +% 1);
    const survived = try dkg.Dkg.run(gpa, config, .{
        .bad_dealer = 2,
        .bad_receiver = 3,
        .defend_honestly = false,
    }, byzantine_prng.random());
    defer {
        for (survived) |*o| o.deinit();
        gpa.free(survived);
    }

    if (!dkg.checks.allSameQ(survived)) return error.ByzantineDealerSplitTheKey;
    if (!try dkg.checks.reconstructsToQ(gpa, survived[0..config.t])) {
        return error.ByzantineShareAcceptedIntoTheKey;
    }
    for (survived) |o| {
        if (!dkg.checks.verifyingShareConsistent(o)) return error.ByzantineRunLeftAnInconsistentShare;
    }
    // `Dkg.run` reports outputs, not the QUAL set, so a consumer cannot ask
    // WHICH dealer was disqualified — only that what came out is consistent.
    std.debug.print("a dealer that cheated and could not defend itself did not break the key\n", .{});

    // ── the other rejection: a policy that cannot be satisfied ───────────
    // A misconfigured deployment asking for 4-of-3 must be told so, not left
    // to discover it when the fourth signer never appears.
    if (dkg.Dkg.run(gpa, .{ .t = 4, .n = 3 }, .{}, random)) |bad| {
        gpa.free(bad);
        return error.ImpossiblePolicyAccepted;
    } else |err| switch (err) {
        error.InvalidConfig => std.debug.print("4-of-3 policy rejected before any key material was drawn\n", .{}),
        else => return err,
    }
}
