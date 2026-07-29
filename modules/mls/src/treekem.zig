// SPDX-License-Identifier: MIT
//! mls.treekem — the genuinely-hard part of this arc (`SPEC.md`'s "Arc
//! breakdown" flags this whole file as Fable-tier). Two REAL, mechanical
//! pieces (RFC 9420 §7.6's `HPKECiphertext`/`UpdatePathNode`/`UpdatePath`
//! wire structs — plain composition of `tree.zig`/`codec.zig`, no
//! algorithmic judgment call) and FIVE tree ALGORITHMS that ARE the Fable
//! tier — `resolution`/`parentHash`/`validateParentHashes`/
//! `processUpdatePath`/`applyUpdatePath`, now IMPLEMENTED and pinned
//! byte-exact against the official mlswg interop vectors behind
//! `gate.treekem_core_implemented` (`kat_treekem_test.zig`: all 14 trees'
//! resolutions, 275 parent-hash tamper rejections, 62 update paths, 328
//! receiver views, 62 merges → `tree_hash_after`).
//!
//! **Why these five, and only these five, are the hard tier** (matching
//! `SPEC.md`'s tiering and the task brief that scoped this scaffold):
//! encrypting/decrypting an `HPKECiphertext` is ALREADY DONE
//! (`crypto.EncryptWithLabel`/`DecryptWithLabel`, Part 1); deriving a KEM
//! keypair from a seed is ALREADY DONE (`hpke.X25519Kem.deriveKeyPair`);
//! hashing a tree is ALREADY DONE (`treehash.zig`, this Part). What's
//! NOT done is the TREE ALGORITHM binding those primitives together
//! correctly under adversarial tree state — which node indices a path
//! secret must be encrypted to (`resolution`), which chain of hashes
//! proves a parent node's key was legitimately introduced by a group
//! member rather than forged by an outsider (`parentHash` +
//! `validateParentHashes`), and the two directions of the actual
//! `UpdatePath` walk (`applyUpdatePath` merges the PUBLIC side;
//! `processUpdatePath` derives the PRIVATE side and the resulting
//! `commit_secret`). Getting any of these five wrong is a real security
//! bug (a wrong resolution set can let a malicious member inject an
//! unauthorized key into another member's derived path; a forged/
//! unchecked parent hash lets an outsider splice keys into the tree) —
//! the "hardest TIER, not crypto-only" bar this repo's Fable pool applies.
//!
//! Model: RFC 9420 §4.1 (resolution), §7.4-§7.6 (path-secret derivation,
//! `UpdatePath` wire shape and encrypt/decrypt), §7.9/§7.9.1/§7.9.2
//! (parent hash construction and chain validation).

const std = @import("std");
const codec = @import("codec.zig");
const crypto = @import("crypto.zig");
const suite = @import("suite.zig");
const treemath = @import("treemath.zig");
const tree = @import("tree.zig");
const wire = @import("wire_lists.zig");
const treehash = @import("treehash.zig");
const gate = @import("gate.zig");

pub const Error = tree.Error;

// ── §7.6: HPKECiphertext / UpdatePathNode / UpdatePath (REAL — plain wire
// structs, no algorithmic content) ────────────────────────────────────────

pub const HPKECiphertext = struct {
    kem_output: []const u8,
    ciphertext: []const u8,

    pub fn encodedLen(self: HPKECiphertext) usize {
        const l = wire.varintLen;
        return l(self.kem_output.len) + self.kem_output.len + l(self.ciphertext.len) + self.ciphertext.len;
    }
    pub fn encode(self: HPKECiphertext, w: *codec.Writer) codec.Error!void {
        try w.writeVector(self.kem_output);
        try w.writeVector(self.ciphertext);
    }
    pub fn decode(r: *codec.Reader) codec.Error!HPKECiphertext {
        return .{ .kem_output = try r.readVector(), .ciphertext = try r.readVector() };
    }
};

pub const UpdatePathNode = struct {
    encryption_key: []const u8,
    /// One ciphertext per node in the resolution of the corresponding
    /// copath node (RFC 9420 §7.6: "The length of the
    /// encrypted_path_secret vector MUST be equal to the length of the
    /// resolution of the copath node").
    encrypted_path_secret: []const HPKECiphertext,

    pub fn encodedLen(self: UpdatePathNode) usize {
        return wire.varintLen(self.encryption_key.len) + self.encryption_key.len +
            wire.varVecLen(HPKECiphertext, self.encrypted_path_secret);
    }
    pub fn encode(self: UpdatePathNode, w: *codec.Writer) codec.Error!void {
        try w.writeVector(self.encryption_key);
        try wire.encodeVarVec(HPKECiphertext, w, self.encrypted_path_secret);
    }
    pub fn decode(allocator: std.mem.Allocator, r: *codec.Reader) !UpdatePathNode {
        const encryption_key = try r.readVector();
        const cts = try wire.decodeVarVec(HPKECiphertext, false, allocator, r, HPKECiphertext.decode);
        return .{ .encryption_key = encryption_key, .encrypted_path_secret = cts };
    }
    pub fn deinit(self: UpdatePathNode, allocator: std.mem.Allocator) void {
        allocator.free(self.encrypted_path_secret);
    }
};

/// RFC 9420 §7.6. `nodes` is in the same order as the sender's filtered
/// direct path (RFC 9420 §4.1.2 — direct path with nodes whose copath
/// child has an EMPTY `resolution` removed; computing this ordering is
/// itself part of `applyUpdatePath`/`processUpdatePath`'s Fable-core job,
/// since it depends on `resolution`), root last.
pub const UpdatePath = struct {
    leaf_node: tree.LeafNode,
    nodes: []const UpdatePathNode,

    pub fn encodedLen(self: UpdatePath) usize {
        return self.leaf_node.encodedLen() + wire.varVecLen(UpdatePathNode, self.nodes);
    }
    pub fn encode(self: UpdatePath, w: *codec.Writer) Error!void {
        try self.leaf_node.encode(w);
        try wire.encodeVarVec(UpdatePathNode, w, self.nodes);
    }
    pub fn decode(allocator: std.mem.Allocator, r: *codec.Reader) !UpdatePath {
        const leaf_node = try tree.LeafNode.decode(allocator, r);
        errdefer leaf_node.deinit(allocator);
        const nodes = try wire.decodeVarVec(UpdatePathNode, true, allocator, r, UpdatePathNode.decode);
        return .{ .leaf_node = leaf_node, .nodes = nodes };
    }
    pub fn deinit(self: UpdatePath, allocator: std.mem.Allocator) void {
        self.leaf_node.deinit(allocator);
        for (self.nodes) |n| n.deinit(allocator);
        allocator.free(self.nodes);
    }
};

// ── Fable core #1: resolution (RFC 9420 §4.1) ─────────────────────────────

/// RFC 9420 §4.1's "resolution" — the ORDERED list of node
/// indices that collectively cover all non-blank descendants of `index`:
///
///   * non-blank node `n` → `[n] ++ unmerged(n)`, where `unmerged(n)` is
///     `n`'s `ParentNode.unmerged_leaves` **converted from LEAF indices to
///     NODE indices** (`unmerged_leaves` stores `0..n_leaves-1`; a
///     resolution is a list of ARRAY indices, so each entry must be
///     DOUBLED — `2 * leaf_index` — before appending; a leaf node itself
///     has no `unmerged_leaves` field, so a non-blank LEAF's resolution is
///     just `[index]`).
///   * blank leaf → `[]` (empty).
///   * blank parent → `resolution(left(index)) ++ resolution(right(index))`
///     (left-first, depth-first — `treemath.left`/`.right`, Part 1).
///
/// Two callers depend on this being exactly right: `parentHash`'s
/// `original_sibling_tree_hash` (needs the SIBLING's resolution, with
/// `P.unmerged_leaves` leaves conceptually blanked first — a second,
/// related but DISTINCT transform, see `parentHash`'s own doc comment),
/// and `processUpdatePath`/`applyUpdatePath`'s copath encryption targets
/// (RFC 9420 §7.5/§7.6: "There is one encryption of the path secret to
/// each public key in the resolution of the non-updated child" — a wrong
/// resolution here either drops a legitimate recipient's ciphertext or
/// hands a path secret to a node that shouldn't have it).
pub fn resolution(allocator: std.mem.Allocator, t: *const tree.RatchetTree, index: usize) Error![]usize {
    return resolutionExcluding(allocator, t, index, &.{});
}

/// `resolution` with RFC 9420 §7.5's exclusion applied: "Any new member
/// (from an Add proposal) added in the same Commit MUST be excluded from
/// this resolution."
///
/// **This one sentence is the whole reason this variant exists, and it is
/// easy to miss because it is stated in §7.5 rather than anywhere in §12.**
/// A member added by the same Commit that carries the UpdatePath must NOT
/// receive the path secrets through that UpdatePath — it gets its state
/// from the `Welcome` instead. So the committer builds one fewer ciphertext
/// than a naive reading of "the resolution of the copath node" suggests,
/// and a receiver that does not apply the same exclusion computes a
/// resolution one entry too long, mismatches the ciphertext count, and
/// cannot process the Commit at all. `passive-client-handling-commit.json`
/// contains exactly this case; see `group.processCommit`'s Add handling.
///
/// `excluded` holds LEAF indices. Exclusion applies both to a leaf reached
/// directly and to a leaf named in a `ParentNode.unmerged_leaves` list —
/// a newly added member is unmerged at its non-blank ancestors, so leaving
/// it in through that path would defeat the exclusion just as surely.
pub fn resolutionExcluding(
    allocator: std.mem.Allocator,
    t: *const tree.RatchetTree,
    index: usize,
    excluded: []const u32,
) Error![]usize {
    var list: std.ArrayList(usize) = .empty;
    errdefer list.deinit(allocator);
    try resolutionInto(allocator, t, index, excluded, &list);
    return list.toOwnedSlice(allocator);
}

fn isExcludedLeaf(excluded: []const u32, node_index: usize) bool {
    if (!treemath.is_leaf(node_index)) return false;
    const leaf_index = node_index / 2;
    for (excluded) |e| if (e == leaf_index) return true;
    return false;
}

fn resolutionInto(
    allocator: std.mem.Allocator,
    t: *const tree.RatchetTree,
    index: usize,
    excluded: []const u32,
    list: *std.ArrayList(usize),
) Error!void {
    if (t.nodes[index]) |node| {
        // Non-blank node: itself, then (parent nodes only) its unmerged
        // leaves — each a LEAF index on the wire, DOUBLED to the array/node
        // index a resolution is made of (RFC 9420 §4.1.1).
        if (isExcludedLeaf(excluded, index)) return;
        try list.append(allocator, index);
        switch (node) {
            .parent => |p| for (p.unmerged_leaves) |li| {
                if (isExcludedLeaf(excluded, 2 * @as(usize, li))) continue;
                try list.append(allocator, 2 * @as(usize, li));
            },
            .leaf => {},
        }
        return;
    }
    if (treemath.is_leaf(index)) return; // blank leaf: empty resolution
    // Blank parent: left child's resolution, then right child's (left-first,
    // depth-first). `index` is odd here, so left/right can never be null.
    try resolutionInto(allocator, t, treemath.left(index) orelse return error.Malformed, excluded, list);
    try resolutionInto(allocator, t, treemath.right(index) orelse return error.Malformed, excluded, list);
}

// ── shared private helpers for the parent-hash / UpdatePath cores ─────────

/// `true` iff node index `x` lies in the subtree rooted at node index `y`
/// (inclusive). In the array representation, `y` covers exactly the index
/// span `[y - (2^level(y) - 1), y + (2^level(y) - 1)]` (RFC 9420 Appendix
/// C's layout).
fn inSubtree(x: usize, y: usize) bool {
    const span = (@as(usize, 1) << @intCast(treemath.level(y))) - 1;
    return x + span >= y and x <= y + span;
}

/// RFC 9420 §7.9's `original_sibling_tree_hash`: the tree hash of the
/// subtree rooted at `s_index`, computed over a COPY of the tree in which
/// every leaf in `exclude` (a `ParentNode.unmerged_leaves` list, LEAF
/// indices) is blanked and removed from every remaining parent node's own
/// `unmerged_leaves` — never a mutation of the live `t`.
fn originalSiblingTreeHash(
    comptime S: type,
    allocator: std.mem.Allocator,
    t: *const tree.RatchetTree,
    s_index: usize,
    exclude: []const u32,
) Error![S.Hash.digest_length]u8 {
    // Fast path (the RFC's own observation): if none of the excluded
    // leaves lives under S, the original tree hash IS the current tree
    // hash of S.
    var any_inside = false;
    for (exclude) |li| {
        if (inSubtree(2 * @as(usize, li), s_index)) {
            any_inside = true;
            break;
        }
    }
    if (!any_inside) return treehash.treeHash(S, allocator, t, s_index);

    const scratch = try allocator.dupe(?tree.Node, t.nodes);
    defer allocator.free(scratch);
    var owned_lists: std.ArrayList([]u32) = .empty;
    defer {
        for (owned_lists.items) |l| allocator.free(l);
        owned_lists.deinit(allocator);
    }
    for (exclude) |li| {
        const idx = 2 * @as(usize, li);
        if (idx < scratch.len) scratch[idx] = null;
    }
    var idx: usize = 1;
    while (idx < scratch.len) : (idx += 2) {
        const node = scratch[idx] orelse continue;
        const p = switch (node) {
            .parent => |p| p,
            .leaf => continue,
        };
        var keep: usize = 0;
        for (p.unmerged_leaves) |ul| {
            if (std.mem.indexOfScalar(u32, exclude, ul) == null) keep += 1;
        }
        if (keep == p.unmerged_leaves.len) continue;
        const filtered = try allocator.alloc(u32, keep);
        owned_lists.append(allocator, filtered) catch |e| {
            allocator.free(filtered);
            return e;
        };
        var w: usize = 0;
        for (p.unmerged_leaves) |ul| {
            if (std.mem.indexOfScalar(u32, exclude, ul) == null) {
                filtered[w] = ul;
                w += 1;
            }
        }
        var np = p;
        np.unmerged_leaves = filtered;
        scratch[idx] = .{ .parent = np };
    }
    const view = tree.RatchetTree{ .allocator = t.allocator, .nodes = scratch };
    return treehash.treeHash(S, allocator, &view, s_index);
}

/// `Hash(ParentHashInput)` for parent node `p` with copath child `s_index`,
/// where `ph` is the `parent_hash` field value to embed (RFC 9420 §7.9's
/// wire struct: `HPKEPublicKey encryption_key; opaque parent_hash<V>;
/// opaque original_sibling_tree_hash<V>;` — `HPKEPublicKey` is itself an
/// `opaque <V>` vector).
fn parentHashRaw(
    comptime S: type,
    allocator: std.mem.Allocator,
    t: *const tree.RatchetTree,
    p: tree.ParentNode,
    s_index: usize,
    ph: []const u8,
) Error![S.Hash.digest_length]u8 {
    const orig = try originalSiblingTreeHash(S, allocator, t, s_index, p.unmerged_leaves);
    const total = wire.varintLen(p.encryption_key.len) + p.encryption_key.len +
        wire.varintLen(ph.len) + ph.len +
        wire.varintLen(orig.len) + orig.len;
    const buf = try allocator.alloc(u8, total);
    defer allocator.free(buf);
    var w = codec.Writer.init(buf);
    try w.writeVector(p.encryption_key);
    try w.writeVector(ph);
    try w.writeVector(&orig);
    return S.hash(w.finish());
}

/// The next node ABOVE `index` on the filtered direct path (RFC 9420
/// §4.1.2: a direct-path node is filtered out when its child on the copath
/// has an empty resolution), plus that node's copath child. `null` when no
/// such node exists (`index` is the root, or everything above it is
/// filtered out).
const FilteredLink = struct { p: usize, s: usize };

fn nextFilteredAncestor(allocator: std.mem.Allocator, t: *const tree.RatchetTree, index: usize) Error!?FilteredLink {
    const n_leaves = t.nLeaves();
    const r = treemath.root(n_leaves);
    var prev = index;
    while (prev != r) {
        const q = treemath.parent(prev, n_leaves) orelse return null;
        const sib = treemath.sibling(prev, n_leaves) orelse return null;
        const res = try resolution(allocator, t, sib);
        const non_empty = res.len > 0;
        allocator.free(res);
        if (non_empty) return .{ .p = q, .s = sib };
        prev = q;
    }
    return null;
}

/// One entry of a leaf's filtered direct path: the direct-path node kept by
/// the §4.1.2 filter and its copath child (the child whose resolution the
/// corresponding `UpdatePathNode`'s ciphertexts are encrypted to).
const FdpEntry = struct { node: usize, copath_child: usize };

/// The filtered direct path of the leaf at node index `leaf_node_index`
/// (RFC 9420 §4.1.2), leaf-to-root order — the node ordering `UpdatePath
/// .nodes` mirrors (§7.6). Caller frees the returned slice.
fn filteredDirectPath(
    allocator: std.mem.Allocator,
    t: *const tree.RatchetTree,
    leaf_node_index: usize,
    excluded: []const u32,
) Error![]FdpEntry {
    const n_leaves = t.nLeaves();
    var dp_buf: [treemath.max_path_len]usize = undefined;
    const dp = treemath.direct_path(leaf_node_index, n_leaves, &dp_buf) catch return error.Malformed;
    var cp_buf: [treemath.max_path_len]usize = undefined;
    const cp = treemath.copath(leaf_node_index, n_leaves, &cp_buf) catch return error.Malformed;
    var list: std.ArrayList(FdpEntry) = .empty;
    errdefer list.deinit(allocator);
    for (dp, cp) |d, c| {
        // §7.5's exclusion changes the FILTER too, not just the ciphertext
        // count: a copath subtree containing nothing but members added by
        // this Commit resolves to the empty list, so its direct-path node
        // drops out of the filtered path entirely and the UpdatePath is one
        // node shorter.
        const res = try resolutionExcluding(allocator, t, c, excluded);
        const non_empty = res.len > 0;
        allocator.free(res);
        if (non_empty) try list.append(allocator, .{ .node = d, .copath_child = c });
    }
    return list.toOwnedSlice(allocator);
}

/// The `parent_hash` FIELD carried by the node at `index`, or `null` when
/// the node carries none (a blank node, or a leaf whose `leaf_node_source`
/// is not `commit` — RFC 9420 §7.9.1: only `ParentNode`s and commit-sourced
/// `LeafNode`s have a parent hash).
fn parentHashField(t: *const tree.RatchetTree, index: usize) ?[]const u8 {
    const node = t.nodes[index] orelse return null;
    return switch (node) {
        .parent => |p| p.parent_hash,
        .leaf => |l| if (l.leaf_node_source == .commit) l.parent_hash else null,
    };
}

// ── Fable core #2/#3: parentHash + validateParentHashes (RFC 9420 §7.9) ──

/// RFC 9420 §7.9's parent hash of the node ABOVE `index` in the
/// tree (call it `P`, with `index`'s subtree being `P`'s child `D` — using
/// Figure 20's labels, `D` = the child on the direct path, `S` = the
/// OTHER child) — `Hash(ParentHashInput)` where:
///
/// ```
/// struct {
///     HPKEPublicKey encryption_key;       // P's own encryption_key
///     opaque parent_hash<V>;              // "" if P is the root, else
///                                         // the (recursively computed)
///                                         // parent hash of the NEXT node
///                                         // up P's filtered direct path
///                                         // — this function calling
///                                         // itself one level up
///     opaque original_sibling_tree_hash<V>; // treeHash(S), but with every
///                                         // leaf in P.unmerged_leaves
///                                         // conceptually blanked first
///                                         // (§7.9's own worked example:
///                                         // "blank L and remove it from
///                                         // Y.unmerged_leaves") — NOT
///                                         // simply treeHash(S) as it sits
///                                         // in `t` today
/// } ParentHashInput;
/// ```
///
/// `original_sibling_tree_hash` is the OTHER genuinely hard piece here
/// (beyond the recursion itself): it needs a COPY of the subtree at `S`
/// with `P.unmerged_leaves ∩ subtree(S)` blanked out and removed from
/// every ancestor's OWN `unmerged_leaves` within that copy, then
/// `treehash.treeHash` over the copy — not a mutation of the live `t`.
///
/// `validateParentHashes` (below) is the §7.9.2 chain-verification
/// algorithm built on top of this: node `D`'s parent hash is valid
/// w.r.t. `P` iff `D` is a descendant of `P`, `D.parent_hash ==
/// parentHash(P with copath child S)`, AND `D` is in `resolution(C)`
/// (`C` = the child of `P` on `D`'s side) with `P.unmerged_leaves ∩
/// subtree(C) == resolution(C) \ {D}` — a full chain is valid iff it can
/// be built bottom-up from some leaf to the root this way (§7.9.2).
pub fn parentHash(comptime S: type, allocator: std.mem.Allocator, t: *const tree.RatchetTree, index: usize) Error![S.Hash.digest_length]u8 {
    // P = the next node above `index` on the filtered direct path (§4.1.2
    // filter; nodes whose copath child resolves to nothing are skipped,
    // exactly the nodes an UpdatePath leaves blank). No such node — `index`
    // is the root, or everything above is filtered — means there is no
    // parent hash to compute here (the VALUE would be the zero-length
    // string, which this fixed-width-digest function cannot express).
    const link = (try nextFilteredAncestor(allocator, t, index)) orelse return error.Malformed;
    const p = switch (t.nodes[link.p] orelse return error.Malformed) {
        .parent => |p| p,
        .leaf => return error.Malformed,
    };
    // ParentHashInput.parent_hash — "the parent hash of the next node
    // after P on the filtered direct path" (§7.9). That value is, by
    // §7.9.1's own definition, exactly what P's OWN `parent_hash` field
    // holds (both were written by the same UpdatePath): reading the stored
    // field is the recursion's memoized form, and it also keeps this
    // function correct on trees whose upper direct path was later blanked
    // by an Update/Remove (where a literal re-recursion would find a blank
    // node and fail on a perfectly valid tree). For the root the stored
    // field is the zero-length string (§7.5: "The root node always has a
    // zero-length hash for its parent hash"), which doubles as the
    // recursion's base case.
    return parentHashRaw(S, allocator, t, p, link.s, p.parent_hash);
}

/// RFC 9420 §7.9.2: verify that every non-blank `ParentNode` in
/// `t` is "parent-hash valid" — reachable by a chain of `parentHash`
/// checks from some leaf to the root (see `parentHash`'s doc comment for
/// the per-link criteria). Also verifies each `LeafNode` whose
/// `leaf_node_source == .commit` has `parent_hash` matching the parent
/// hash of the first node in ITS filtered direct path (RFC 9420 §7.9.1).
/// Used by `tree-validation.json`'s KAT (both the positive case — a
/// well-formed tree's chain verifies — and a NEGATIVE test the harness
/// adds: a single tampered `parent_hash` byte must be REJECTED, not
/// silently accepted).
pub fn validateParentHashes(comptime S: type, allocator: std.mem.Allocator, t: *const tree.RatchetTree) Error!void {
    // RFC 9420 §7.9.2, the "top down" formulation: every non-blank
    // ParentNode P must have EXACTLY ONE descendant D for which P is
    // parent-hash valid. Per-link criteria, with C = P's child on D's
    // side and Sib = the other child:
    //   * D is a descendant of P               (implied by D ∈ resolution(C));
    //   * D.parent_hash == ParentHash(P with copath child Sib)
    //     (= Hash({P.encryption_key, P.parent_hash, original tree hash of
    //     Sib}) — P's own stored parent_hash field IS "the parent hash of
    //     the next node after P on the filtered direct path", §7.9.1, both
    //     written by the same UpdatePath);
    //   * D ∈ resolution(C), and P.unmerged_leaves ∩ subtree(C) ==
    //     resolution(C) \ {D}.
    // Chains need no explicit stitching in this formulation: each
    // non-blank parent's own field is covered by ITS parent's exactly-one
    // check, so a single tampered parent_hash byte breaks either the
    // node's own coverage (its child's field no longer matches) or its
    // link upward — both land here as error.Malformed.
    var idx: usize = 1;
    while (idx < t.nodes.len) : (idx += 2) {
        const node = t.nodes[idx] orelse continue;
        const p = switch (node) {
            .parent => |pn| pn,
            .leaf => return error.Malformed, // an internal slot must hold a parent node
        };
        var matches: usize = 0;
        for ([2]bool{ false, true }) |right_side| {
            const c_idx = if (right_side) treemath.right(idx) orelse return error.Malformed else treemath.left(idx) orelse return error.Malformed;
            const s_idx = if (right_side) treemath.left(idx) orelse return error.Malformed else treemath.right(idx) orelse return error.Malformed;
            const expected = try parentHashRaw(S, allocator, t, p, s_idx, p.parent_hash);
            const res_c = try resolution(allocator, t, c_idx);
            defer allocator.free(res_c);
            for (res_c, 0..) |d_idx, di| {
                const d_ph = parentHashField(t, d_idx) orelse continue;
                if (!std.mem.eql(u8, d_ph, &expected)) continue;
                if (!try unmergedMatchesResolution(allocator, p.unmerged_leaves, c_idx, res_c, di)) continue;
                matches += 1;
            }
        }
        if (matches != 1) return error.Malformed;
    }
}

/// The third §7.9.2 link criterion: `P.unmerged_leaves ∩ subtree(C)` (leaf
/// indices doubled to node indices) equals `resolution(C)` with the entry
/// at `d_pos` removed — i.e. everything the sender encrypted to besides D
/// was an unmerged leaf of P, so nothing else could hold P's secret.
fn unmergedMatchesResolution(
    allocator: std.mem.Allocator,
    unmerged: []const u32,
    c_idx: usize,
    res_c: []const usize,
    d_pos: usize,
) Error!bool {
    var lhs: std.ArrayList(usize) = .empty;
    defer lhs.deinit(allocator);
    for (unmerged) |li| {
        const n = 2 * @as(usize, li);
        if (inSubtree(n, c_idx)) try lhs.append(allocator, n);
    }
    if (lhs.items.len != res_c.len - 1) return false;
    var rhs: std.ArrayList(usize) = .empty;
    defer rhs.deinit(allocator);
    for (res_c, 0..) |n, i| {
        if (i != d_pos) try rhs.append(allocator, n);
    }
    std.mem.sort(usize, lhs.items, {}, std.sort.asc(usize));
    std.mem.sort(usize, rhs.items, {}, std.sort.asc(usize));
    return std.mem.eql(usize, lhs.items, rhs.items);
}

// ── Fable core #4/#5: UpdatePath processing (RFC 9420 §7.4-§7.6) ─────────

pub const PathSecretEntry = struct {
    /// Node index (array representation) this path secret belongs to.
    node: usize,
    path_secret: []const u8,
};

/// The receiving member's private TreeKEM state going INTO
/// `processUpdatePath` — what it already knows from earlier epochs, per
/// `treekem.json`'s `leaves_private` vector field (`SPEC.md`'s KAT
/// section): its own leaf's current HPKE private key, plus any path
/// secrets/private keys it already holds at ancestor nodes (sparse — a
/// member only knows the nodes on ITS OWN direct path).
pub const PrivateLeafState = struct {
    leaf_index: usize,
    /// This leaf's own current HPKE private key bytes (matches
    /// `hpke.X25519Kem.KeyPair.secret_key`'s wire shape — suite `0x0001`
    /// only, see `tree.LeafNode.verifySignature`'s equivalent scoping
    /// note).
    encryption_priv: []const u8,
    known_path_secrets: []const PathSecretEntry,
};

pub const ProcessedUpdatePath = struct {
    /// The root path secret, RFC 9420 §7.4's `path_secret[last]` — this
    /// becomes the group's `commit_secret` fed into the (later-part) key
    /// schedule.
    commit_secret: []const u8,
    /// Every path secret this receiver was able to derive along the
    /// sender's filtered direct path (from the one it decrypted, up to
    /// the root) — `treekem.json`'s per-leaf `path_secrets` KAT field.
    derived_path_secrets: []const PathSecretEntry,
};

/// The RECEIVER half of RFC 9420 §7.5 ("the recipient decrypts
/// the path secrets") + §7.4's derivation chain:
///
/// 1. `path_secret[0]` is the value some ancestor of `receiver` already
///    holds a decryption key for — identify the node in `update_path
///    .nodes`' filtered direct path for which `receiver` is in the
///    subtree of the non-updated (copath) child, then the entry in that
///    copath node's `resolution` for which `receiver` holds a private key
///    (`receiver.known_path_secrets`/`receiver.encryption_priv`), then
///    `DecryptWithLabel(that private key, "UpdatePathNode", group_context,
///    kem_output, ciphertext)` (`crypto.DecryptWithLabel`, Part 1, already
///    built — this stub's only NEW work is finding the right ciphertext
///    via `resolution`, not the decryption primitive itself).
/// 2. Walk UP the filtered direct path from there: `path_secret[n] =
///    DeriveSecret(path_secret[n-1], "path")` (`crypto.DeriveSecret`,
///    already built).
/// 3. At each node, `node_secret[n] = DeriveSecret(path_secret[n],
///    "node")`, `(node_priv[n], node_pub[n]) =
///    KEM.DeriveKeyPair(node_secret[n])`
///    (`hpke.X25519Kem.deriveKeyPair`, already built) — verify `node_pub
///    [n]` matches `update_path.nodes[n].encryption_key` (RFC 9420 §7.5
///    step 6: "Verify that the derived public keys are the same").
/// 4. The LAST path secret derived (the root's) is the `commit_secret`.
///
/// `group_context` is the caller-supplied, ALREADY-ENCODED `GroupContext`
/// object (RFC 9420 §8.1 — cipher_suite/group_id/epoch/
/// confirmed_transcript_hash/tree_hash/extensions; building `GroupContext`
/// itself is Part 4's job per `SPEC.md`'s arc breakdown, so this stub
/// takes the bytes directly rather than depending on a type this Part
/// doesn't own).
pub fn processUpdatePath(
    comptime S: type,
    allocator: std.mem.Allocator,
    t: *const tree.RatchetTree,
    receiver: PrivateLeafState,
    sender_leaf_index: usize,
    update_path: UpdatePath,
    group_context: []const u8,
    /// RFC 9420 §7.5's excluded set: the LEAF indices of members added by
    /// the same Commit that carries this `UpdatePath`. Pass `&.{}` for an
    /// `UpdatePath` that stands alone (an Update-only Commit, or the
    /// `treekem.json` vectors, none of which carry an Add).
    added_this_commit: []const u32,
) Error!ProcessedUpdatePath {
    const sender_node = 2 * sender_leaf_index;
    const receiver_node = 2 * receiver.leaf_index;
    if (sender_node >= t.nodes.len or receiver_node >= t.nodes.len) return error.InvalidLeafIndex;

    // §7.6: UpdatePath.nodes mirrors the sender's filtered direct path,
    // leaf-to-root, one entry per surviving direct-path node.
    const fdp = try filteredDirectPath(allocator, t, sender_node, added_this_commit);
    defer allocator.free(fdp);
    if (update_path.nodes.len != fdp.len) return error.Malformed;

    // §7.5 (decrypt) step 1: the ONE filtered-direct-path node whose
    // copath child's subtree contains the receiver — the lowest common
    // ancestor of sender and receiver among the surviving nodes.
    var overlap: usize = fdp.len;
    for (fdp, 0..) |e, i| {
        if (inSubtree(receiver_node, e.copath_child)) {
            overlap = i;
            break;
        }
    }
    if (overlap == fdp.len) return error.Malformed; // receiver == sender, or not in this tree

    // §7.5 (decrypt) step 2: the resolution entry the receiver holds a
    // private key for. The ciphertext list is ordered BY that resolution
    // (§7.6), so the entry's position selects the ciphertext.
    const res = try resolutionExcluding(allocator, t, fdp[overlap].copath_child, added_this_commit);
    defer allocator.free(res);
    if (update_path.nodes[overlap].encrypted_path_secret.len != res.len) return error.Malformed;

    var key_pair: ?S.Kem.KeyPair = null;
    var ct_pos: usize = 0;
    outer: for (res, 0..) |r, i| {
        if (r == receiver_node) {
            if (receiver.encryption_priv.len != S.Kem.Nsk) return error.WrongKeyLength;
            // The KEM needs the matching public key too (X25519 decap
            // folds pkR into kem_context); the receiver's own leaf in the
            // tree carries it.
            const pk = switch (t.nodes[r] orelse return error.Malformed) {
                .leaf => |l| l.encryption_key,
                .parent => return error.Malformed,
            };
            if (pk.len != S.Kem.Npk) return error.WrongKeyLength;
            key_pair = .{
                .secret_key = receiver.encryption_priv[0..S.Kem.Nsk].*,
                .public_key = pk[0..S.Kem.Npk].*,
            };
            ct_pos = i;
            break :outer;
        }
        for (receiver.known_path_secrets) |kps| {
            if (kps.node != r) continue;
            // §7.4: node_secret = DeriveSecret(path_secret, "node");
            // key pair = KEM.DeriveKeyPair(node_secret).
            if (kps.path_secret.len != S.Nh) return error.WrongKeyLength;
            const node_secret = try crypto.DeriveSecret(S, kps.path_secret[0..S.Nh].*, "node");
            key_pair = S.Kem.deriveKeyPair(&node_secret);
            ct_pos = i;
            break :outer;
        }
    }
    const kp = key_pair orelse return error.Malformed; // no resolution entry we can decrypt

    // §7.5 (decrypt) step 3: DecryptWithLabel the selected ciphertext.
    const ct = update_path.nodes[overlap].encrypted_path_secret[ct_pos];
    if (ct.kem_output.len != S.Kem.Npk) return error.Malformed;
    if (ct.ciphertext.len != S.Nh + S.Aead.tag_length) return error.Malformed;
    const enc: S.Kem.EncappedKey = ct.kem_output[0..S.Kem.Npk].*;
    var path_secret: [S.Nh]u8 = undefined;
    // Exactly-sized heap scratch rather than `crypto.DecryptWithLabel`'s
    // fixed stack buffer: the context here is a serialized `GroupContext`,
    // which carries the group's extensions and so has no upper bound (see
    // `crypto.encryptContextLen`). Sizing it exactly also means the `catch`
    // below cannot swallow a buffer-size error as a decryption failure.
    const ctx_scratch = try allocator.alloc(u8, try crypto.encryptContextLen("UpdatePathNode", group_context));
    defer allocator.free(ctx_scratch);
    crypto.DecryptWithLabelScratch(S, enc, kp, "UpdatePathNode", group_context, ct.ciphertext, &path_secret, ctx_scratch) catch
        return error.Malformed; // AEAD/decap failure = reject (Error has no HPKE-specific member)

    // §7.4/§7.5 steps 4-6: walk the chain up the filtered direct path,
    // deriving each node's key pair and checking it against the public key
    // the UpdatePath announced for that node.
    var derived: std.ArrayList(PathSecretEntry) = .empty;
    errdefer {
        for (derived.items) |e| allocator.free(e.path_secret);
        derived.deinit(allocator);
    }
    var i = overlap;
    while (i < fdp.len) : (i += 1) {
        if (i > overlap) path_secret = try crypto.DeriveSecret(S, path_secret, "path");
        const node_secret = try crypto.DeriveSecret(S, path_secret, "node");
        const node_kp = S.Kem.deriveKeyPair(&node_secret);
        if (!std.mem.eql(u8, &node_kp.public_key, update_path.nodes[i].encryption_key)) return error.Malformed;
        const owned = try allocator.dupe(u8, &path_secret);
        derived.append(allocator, .{ .node = fdp[i].node, .path_secret = owned }) catch |e| {
            allocator.free(owned);
            return e;
        };
    }

    // §7.4 / §12.4.2: commit_secret = path_secret[n+1], one "path"
    // derivation PAST the last (root) path secret of the UpdatePath —
    // pinned byte-exact by treekem.json (each vector's commit_secret is
    // DeriveSecret(root path secret, "path"), not the root secret itself).
    const commit = try crypto.DeriveSecret(S, path_secret, "path");
    const commit_owned = try allocator.dupe(u8, &commit);
    errdefer allocator.free(commit_owned);
    return .{
        .commit_secret = commit_owned,
        .derived_path_secrets = try derived.toOwnedSlice(allocator),
    };
}

/// The receiver's PUBLIC-side merge, RFC 9420 §7.5 ("First, the
/// recipient merges UpdatePath into the tree"), steps 1-3:
///
/// 1. Blank every node on `sender_leaf_index`'s direct path.
/// 2. For each node in `sender_leaf_index`'s FILTERED direct path (§4.1.2
///    — depends on `resolution` to compute, since a node is filtered out
///    when its copath child's resolution is empty), set its public key to
///    the matching `update_path.nodes[n].encryption_key` and its
///    `unmerged_leaves` to `[]` (a fresh key pair means nobody is
///    "unmerged" relative to it anymore).
/// 3. Compute parent hashes for the filtered direct path (root to leaf —
///    `parentHash`, above) and verify `update_path.leaf_node.parent_hash`
///    matches the parent hash of the FIRST node in that path (closest to
///    the leaf) — this is what makes an `UpdatePath` "parent-hash valid"
///    relative to `t` (RFC 9420 §7.9.2, the same check `tree-
///    validation.json`'s static-tree case runs via `validateParentHashes`,
///    here run against the NEWLY MERGED nodes instead of a pre-existing
///    tree).
///
/// Deliberately separate from `processUpdatePath` (the PRIVATE-side
/// secret derivation) — RFC 9420 itself splits these into "First"/
/// "Second" steps because a member merges the public tree state
/// regardless of whether IT can decrypt anything from this particular
/// `UpdatePath` (only nodes in the resolution the sender encrypted to
/// can), but every member updates the same public tree.
pub fn applyUpdatePath(
    allocator: std.mem.Allocator,
    t: *tree.RatchetTree,
    sender_leaf_index: usize,
    update_path: UpdatePath,
    /// RFC 9420 §7.5's excluded set — see `processUpdatePath`. It changes
    /// the FILTERED direct path, hence which nodes this merge writes to.
    added_this_commit: []const u32,
) Error!void {
    // Suite note: this signature carries no `comptime S` (fixed by the
    // scaffold), yet step 3's parent hashes need the suite hash — so it
    // uses the module's only wired suite, `suite.default` (`0x0001`), the
    // same single-suite scoping `tree.LeafNode.verifySignature` documents
    // for its 32/64-byte Ed25519 widths.
    const S = suite.default;
    const sender_node = 2 * sender_leaf_index;
    if (sender_node >= t.nodes.len) return error.InvalidLeafIndex;
    if (update_path.leaf_node.leaf_node_source != .commit) return error.Malformed;
    const leaf_claimed_ph = update_path.leaf_node.parent_hash orelse return error.Malformed;

    // The §4.1.2 filter is computed BEFORE mutating: copath-child
    // resolutions only inspect subtrees disjoint from the direct path, so
    // blanking the direct path wouldn't change them anyway — but the
    // UpdatePath's node count must be checked against the tree as it
    // stands.
    const fdp = try filteredDirectPath(allocator, t, sender_node, added_this_commit);
    defer allocator.free(fdp);
    if (update_path.nodes.len != fdp.len) return error.Malformed;

    // The tree adopts the new LeafNode: duplicate its ALLOCATED containers
    // (capabilities/extension/credential lists) with the tree's own
    // allocator so `RatchetTree.deinit` frees exactly what it owns, while
    // the byte slices keep aliasing the caller's UpdatePath buffer
    // (`tree.zig`'s decode convention: aliased bytes must outlive the
    // tree).
    const new_leaf = try dupLeafNodeLists(t.allocator, update_path.leaf_node);

    // §7.5 merge step 1: blank the sender's whole direct path (and replace
    // the sender's leaf).
    var dp_buf: [treemath.max_path_len]usize = undefined;
    const dp = treemath.direct_path(sender_node, t.nLeaves(), &dp_buf) catch return error.Malformed;
    for (dp) |idx| blankNode(t, idx);
    blankNode(t, sender_node);
    t.nodes[sender_node] = .{ .leaf = new_leaf };

    // §7.5 merge step 2: each surviving (filtered-direct-path) node gets
    // the UpdatePath's public key and an EMPTY unmerged_leaves list — a
    // fresh key pair means nobody is unmerged relative to it.
    for (fdp, update_path.nodes) |e, upn| {
        t.nodes[e.node] = .{
            .parent = .{
                .encryption_key = upn.encryption_key,
                .parent_hash = "", // root value; overwritten below for the non-top nodes
                .unmerged_leaves = &.{},
            },
        };
    }

    // §7.5 merge step 3: parent hashes, computed root to leaf so each
    // node's stored field can feed its child's ParentHashInput (§7.9.1).
    // The topmost surviving node keeps the zero-length hash ("The root
    // node always has a zero-length hash for its parent hash" — also the
    // right value when the true root was filtered out: there is then no
    // next node on the filtered direct path at all). The digests are
    // allocated from `allocator` and adopted by the tree's ParentNodes;
    // NOTE `ParentNode.deinit` does not free `parent_hash` (the module's
    // aliasing convention), so callers that deinit the tree should pass an
    // arena here (or track the filtered-direct-path nodes themselves).
    if (fdp.len > 0) {
        var i = fdp.len - 1;
        while (i > 0) {
            i -= 1;
            const upper = switch (t.nodes[fdp[i + 1].node].?) {
                .parent => |p| p,
                .leaf => return error.Malformed,
            };
            const digest = try parentHashRaw(S, allocator, t, upper, fdp[i + 1].copath_child, upper.parent_hash);
            const owned = try allocator.dupe(u8, &digest);
            var cur = switch (t.nodes[fdp[i].node].?) {
                .parent => |p| p,
                .leaf => return error.Malformed,
            };
            cur.parent_hash = owned;
            t.nodes[fdp[i].node] = .{ .parent = cur };
        }
        // §7.9.2 (per-Commit check): the committer's new leaf must carry
        // the parent hash of the FIRST node in its filtered direct path —
        // `parentHash` of the leaf position, now that the merged nodes are
        // in place. A mismatch means the UpdatePath is not parent-hash
        // valid relative to this tree.
        const expected = try parentHash(S, allocator, t, sender_node);
        if (!std.mem.eql(u8, leaf_claimed_ph, &expected)) return error.Malformed;
    } else {
        // No nodes above the leaf survive filtering (single-leaf tree):
        // the leaf's parent hash is the zero-length string.
        if (leaf_claimed_ph.len != 0) return error.Malformed;
    }
}

/// Blank one node slot, freeing what the tree owned there (`RatchetTree
/// .blank` is file-private to `tree.zig`; `nodes` is public, so this is the
/// same two lines).
fn blankNode(t: *tree.RatchetTree, index: usize) void {
    if (t.nodes[index]) |old| old.deinit(t.allocator);
    t.nodes[index] = null;
}

/// A copy of `l` whose ALLOCATED containers (the five `Capabilities`
/// vectors, the `extensions` list, an x509 credential's outer slice) are
/// fresh `gpa` allocations the tree can own and free via `LeafNode
/// .deinit`; plain byte slices still alias the source buffer (the module's
/// decode convention).
fn dupLeafNodeLists(gpa: std.mem.Allocator, l: tree.LeafNode) Error!tree.LeafNode {
    var out = l;
    out.capabilities.versions = try gpa.dupe(u16, l.capabilities.versions);
    errdefer gpa.free(out.capabilities.versions);
    out.capabilities.cipher_suites = try gpa.dupe(u16, l.capabilities.cipher_suites);
    errdefer gpa.free(out.capabilities.cipher_suites);
    out.capabilities.extensions = try gpa.dupe(u16, l.capabilities.extensions);
    errdefer gpa.free(out.capabilities.extensions);
    out.capabilities.proposals = try gpa.dupe(u16, l.capabilities.proposals);
    errdefer gpa.free(out.capabilities.proposals);
    out.capabilities.credentials = try gpa.dupe(u16, l.capabilities.credentials);
    errdefer gpa.free(out.capabilities.credentials);
    out.extensions = try gpa.dupe(tree.Extension, l.extensions);
    errdefer gpa.free(out.extensions);
    out.credential = switch (l.credential) {
        .basic => |id| .{ .basic = id },
        .x509 => |certs| .{ .x509 = try gpa.dupe([]const u8, certs) },
    };
    return out;
}

test {
    // Keep the gate import reachable even before any gated test exists in
    // this file itself (all gated calls live in kat_treekem_test.zig).
    _ = gate.treekem_core_implemented;
}
