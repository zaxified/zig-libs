// SPDX-License-Identifier: MIT

//! What a rollup's membership gateway does with `poseidon`: keep a Merkle
//! tree of commitments whose root is published on chain, and check an
//! inclusion proof a client sends in, using the SAME hash the circuit uses.
//! That last part is the whole reason to reach for Poseidon instead of
//! SHA-256 — the off-chain check here and the in-circuit check must agree
//! bit-for-bit, or every proof the client produces is rejected by the
//! verifier for reasons no log will explain.
//!
//! This is an example in the gate sense — it is built against the PUBLISHED
//! module (`@import("poseidon")` and nothing else). If a type needed to call
//! the API is not public, or an error cannot be named from outside, this file
//! stops compiling. The module's own tests cannot notice either, because they
//! live inside it.
//!
//! No entropy, no I/O: Poseidon is a deterministic permutation over a prime
//! field, so a gateway that boots twice derives the same tables both times.

const std = @import("std");
const poseidon = @import("poseidon");

/// The BN254 scalar field — circomlib's parameter set, the one deployed
/// circom circuits use. A caller has to be able to name this type to hold a
/// leaf at all, and it is re-exported for exactly that.
const Fr = poseidon.bn254.Fr;

/// Depth-2 tree: four leaves, two internal nodes, one root.
const tree_depth = 2;
const leaf_count = 1 << tree_depth;

/// One client's commitment as it arrives on the wire: 32 bytes, big-endian.
/// Not every 32-byte string is a field element — see `parseLeaf`.
const wire_leaves: [leaf_count][32]u8 = .{
    hexLeaf(0x1111_1111),
    hexLeaf(0x2222_2222),
    hexLeaf(0x3333_3333),
    hexLeaf(0x4444_4444),
};

/// A 32-byte big-endian encoding of a small integer, standing in for a
/// commitment a client actually computed.
fn hexLeaf(comptime v: u32) [32]u8 {
    var out: [32]u8 = @splat(0);
    std.mem.writeInt(u32, out[28..32], v, .big);
    return out;
}

/// Decode one wire leaf into a field element. The rejection matters: a
/// 32-byte value at or above the field modulus is NOT a leaf, and accepting
/// it by silently reducing would let two distinct wire encodings map to one
/// tree position.
fn parseLeaf(bytes: [32]u8) !Fr {
    return Fr.fromBytes(bytes) catch |err| switch (err) {
        // Both halves of the field's own error set, named from out here.
        error.NonCanonical, error.Overflow => error.LeafNotAFieldElement,
    };
}

/// An inclusion proof as a client sends it: the sibling at each level, from
/// the leaf upwards, plus the leaf's index (which fixes left/right at every
/// level, so it is not sent per level).
const InclusionProof = struct {
    index: usize,
    siblings: [tree_depth]Fr,
};

pub fn main() !void {
    // Build the instance ONCE. `init` runs the Grain LFSR and the MDS
    // security checks — milliseconds, not nanoseconds — so a gateway does
    // this at startup and shares the value; it is immutable afterwards.
    //
    // `initChecked` is the same derivation with the failure surfaced instead
    // of panicked on. It cannot fail for a shipped parameter set, but a
    // service that would rather return 503 than abort writes it this way.
    const p = poseidon.bn254.Compress2.initChecked() catch |err| switch (err) {
        error.MdsCandidatesExhausted, error.RootIsolationFailed, error.NotInvertible => {
            std.debug.print("poseidon parameters did not derive: {s}\n", .{@errorName(err)});
            return;
        },
    };

    // ── build the tree ───────────────────────────────────────────────────
    var leaves: [leaf_count]Fr = undefined;
    for (wire_leaves, &leaves) |bytes, *leaf| leaf.* = try parseLeaf(bytes);

    var level: [leaf_count]Fr = leaves;
    var width: usize = leaf_count;
    while (width > 1) : (width /= 2) {
        // `compress` is the 2-to-1 node function — `Poseidon(2)` with a zero
        // initial state, which is what circomlib's Merkle gadgets emit.
        for (0..width / 2) |i| level[i] = p.compress(level[2 * i], level[2 * i + 1]);
    }
    const published_root = level[0];
    std.debug.print("published root: {s}\n", .{hex(published_root)});

    // ── check a client's inclusion proof ─────────────────────────────────
    // Leaf 2's path: its sibling (leaf 3), then the left subtree's node.
    const honest: InclusionProof = .{
        .index = 2,
        .siblings = .{ leaves[3], p.compress(leaves[0], leaves[1]) },
    };
    if (!rootOf(&p, leaves[2], honest).eql(published_root)) return error.HonestProofRejected;
    std.debug.print("leaf 2 proved in: root matches\n", .{});

    // ── the rejection a caller must handle ───────────────────────────────
    // A client that swaps in a sibling it likes better gets a different root
    // and must be turned away. This is the ONLY defence — nothing in the
    // proof itself is signed, so the recomputed root IS the check.
    const forged: InclusionProof = .{
        .index = 2,
        .siblings = .{ leaves[0], honest.siblings[1] }, // wrong sibling
    };
    if (rootOf(&p, leaves[2], forged).eql(published_root)) return error.ForgedProofAccepted;
    std.debug.print("forged sibling rejected: recomputed root differs\n", .{});

    // Claiming the right leaf at the wrong index fails the same way, because
    // the index decides which side of every `compress` the node lands on.
    const misplaced: InclusionProof = .{ .index = 3, .siblings = honest.siblings };
    if (rootOf(&p, leaves[2], misplaced).eql(published_root)) return error.WrongIndexAccepted;
    std.debug.print("wrong index rejected\n", .{});

    // A wire leaf at or above the modulus is refused before it ever reaches
    // the tree — the field's canonical-encoding check, surfaced by name.
    const too_big: [32]u8 = @splat(0xff);
    if (parseLeaf(too_big)) |_| {
        return error.OutOfRangeLeafAccepted;
    } else |err| switch (err) {
        error.LeafNotAFieldElement => std.debug.print("out-of-range wire leaf rejected\n", .{}),
    }

    // ── domain separation ────────────────────────────────────────────────
    // A gateway that stores more than one kind of thing must not let a leaf
    // from one namespace verify against another. `hash` at a wider arity
    // takes the tag as just another input — a Poseidon(3) over
    // (tag, value, salt) — which is what the matching circuit does.
    const wide = poseidon.bn254.Perm(4).init();
    const tagged = wide.hash(.{
        poseidon.bn254.fromU64(1), // namespace tag
        leaves[0],
        poseidon.bn254.fromU64(0xdead_beef), // client salt
    });
    std.debug.print("namespaced commitment: {s}\n", .{hex(tagged)});
}

/// Recompute the root a proof implies. `index`'s bit at each level says
/// whether the walked node is the left or the right input to `compress`.
fn rootOf(p: *const poseidon.bn254.Compress2, leaf: Fr, proof: InclusionProof) Fr {
    var node = leaf;
    var idx = proof.index;
    for (proof.siblings) |sibling| {
        node = if (idx & 1 == 0) p.compress(node, sibling) else p.compress(sibling, node);
        idx >>= 1;
    }
    return node;
}

fn hex(x: Fr) [16]u8 {
    const bytes = x.toBytes();
    return std.fmt.bytesToHex(bytes[0..8].*, .lower);
}
