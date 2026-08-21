// SPDX-License-Identifier: MIT

//! What a state-commitment service does with `rescue`: publish one 32-byte
//! Merkle root over a set of accounts, then answer "is this account in the
//! committed state?" with an inclusion path a light client can re-hash on its
//! own. The hash has to be the one the prover's circuit uses, which is why it
//! is `Rpo256` (miden-crypto's framing) and not SHA-2 — the whole point of an
//! arithmetization-oriented hash is that the verifier's re-hash is also a
//! cheap constraint.
//!
//! This is an example in the gate sense — it is built against the PUBLISHED
//! module (`@import("rescue")` and nothing else). If a type needed to call the
//! API is not public, or an error cannot be named from outside, this file
//! stops compiling. The module's own tests cannot notice either, because they
//! live inside it.
//!
//! Everything here is in memory and deterministic: RPO takes no key, no
//! randomness and no I/O, so a light client and the service that built the
//! tree reach the same root from the same leaves or the account is not there.

const std = @import("std");
const rescue = @import("rescue");

/// One account as the state tree stores it: the fields are already field
/// elements, because a circuit cannot work on bytes. `Fe` is `pub` for exactly
/// this reason — a caller holds field elements, not digests.
const Account = struct {
    id: rescue.Fe,
    balance: rescue.Fe,
    nonce: rescue.Fe,
};

const accounts = [_]Account{
    .{ .id = 1001, .balance = 250, .nonce = 7 },
    .{ .id = 1002, .balance = 4_000, .nonce = 0 },
    .{ .id = 1003, .balance = 12, .nonce = 41 },
    .{ .id = 1004, .balance = 999_000, .nonce = 3 },
};

/// Leaf hash. `hashElements` is the variable-width sponge: it absorbs the
/// whole record, so two accounts that differ in any one field get different
/// leaves.
fn leafOf(a: Account) rescue.Rpo256.Digest {
    return rescue.Rpo256.hashElements(&.{ a.id, a.balance, a.nonce });
}

/// Recompute the root from a leaf and its sibling path. `merge` is the
/// two-child node hash; `index_bits` says, one level at a time, whether this
/// subtree was the LEFT (0) or RIGHT (1) child — a light client that gets that
/// order wrong computes a different root, which is the failure this function
/// exists to make impossible to fake.
fn rootFromPath(
    leaf: rescue.Rpo256.Digest,
    path: []const rescue.Rpo256.Digest,
    index_bits: usize,
) rescue.Rpo256.Digest {
    var node = leaf;
    for (path, 0..) |sibling, level| {
        const is_right = (index_bits >> @intCast(level)) & 1 == 1;
        node = if (is_right) rescue.Rpo256.merge(sibling, node) else rescue.Rpo256.merge(node, sibling);
    }
    return node;
}

pub fn main() !void {
    // ── the service: build the tree, publish the root ────────────────────
    var leaves: [accounts.len]rescue.Rpo256.Digest = undefined;
    for (accounts, &leaves) |a, *l| l.* = leafOf(a);

    const node01 = rescue.Rpo256.merge(leaves[0], leaves[1]);
    const node23 = rescue.Rpo256.merge(leaves[2], leaves[3]);
    const root = rescue.Rpo256.merge(node01, node23);

    // A root leaves the process as bytes, never as four field elements — the
    // module has to offer that conversion or every consumer invents its own
    // endianness. `digestToBytes` is it.
    const root_bytes = rescue.Rpo256.digestToBytes(root);
    std.debug.print("state root: {s}\n", .{std.fmt.bytesToHex(root_bytes, .lower)});

    // ── the light client: verify account 1003 is in that state ───────────
    // It holds the account record and two sibling digests, nothing else.
    const claimed = accounts[2];
    const proof = [_]rescue.Rpo256.Digest{ leaves[3], node01 };
    const index_bits: usize = 0b10; // leaf 2: right at the top, left below it

    const recomputed = rootFromPath(leafOf(claimed), &proof, index_bits);
    if (!std.mem.eql(u8, &rescue.Rpo256.digestToBytes(recomputed), &root_bytes)) {
        return error.HonestInclusionProofRejected;
    }
    std.debug.print("account {d} is in the committed state\n", .{claimed.id});

    // ── the rejection a caller must handle ───────────────────────────────
    // A relying party's real job is refusing. Someone hands the client the
    // same path with a bigger balance: the leaf changes, so the root changes,
    // and the client must notice rather than trust the record it was given.
    var forged = claimed;
    forged.balance = 12_000_000;
    const forged_root = rootFromPath(leafOf(forged), &proof, index_bits);
    if (std.mem.eql(u8, &rescue.Rpo256.digestToBytes(forged_root), &root_bytes)) {
        return error.TamperedLeafAccepted;
    }
    std.debug.print("inflated balance rejected: root does not match\n", .{});

    // ── the other rejection: an input the sponge refuses ─────────────────
    // The specification's own sponge (a different framing over the same
    // permutation — a consumer picks one and must not mix them) refuses an
    // empty absorb rather than returning the padding-only digest. A service
    // hashing a caller-supplied attribute list has to handle that by name,
    // which means the error set has to be reachable from out here.
    if (rescue.spec128.hash(&.{})) |_| {
        return error.EmptyInputAccepted;
    } else |err| switch (err) {
        error.EmptyInput => std.debug.print("empty attribute list refused, as specified\n", .{}),
    }

    // The two framings are genuinely different hashes: same input, same
    // permutation, different digest. Printing both is the cheapest way for a
    // consumer to convince itself it must not treat them as interchangeable.
    const spec_digest = try rescue.spec128.hash(&.{ claimed.id, claimed.balance, claimed.nonce });
    const miden_digest = leafOf(claimed);
    std.debug.print("spec128 vs Rpo256 on the same record: {s}\n", .{
        if (std.mem.eql(u8, std.mem.sliceAsBytes(spec_digest[0..]), std.mem.sliceAsBytes(miden_digest[0..])))
            "identical (unexpected)"
        else
            "different framings, different digests",
    });
}
