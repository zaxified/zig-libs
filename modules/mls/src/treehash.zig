// SPDX-License-Identifier: MIT
//! mls.treehash — RFC 9420 §7.8's tree hash: a recursive summary of the
//! subtree below each node, computed leaf-up, root-down through
//! `treemath.zig`'s `left`/`right`. Deliberately IMPLEMENTED here, not
//! stubbed — the task brief explicitly asks for this judgment call, and
//! tree hashing is mechanical recursive hashing over already-real
//! encodings (`tree.zig`'s `LeafNode`/`ParentNode`), NOT the
//! resolution/parent-hash-chain/path-secret ALGORITHMS `treekem.zig`
//! stubs (§4.1/§7.9/§7.4-§7.6) — no adversarial-tree-state judgment call
//! is needed to hash a tree correctly, only to VALIDATE one, which is
//! `treekem.zig`'s job. `tree-validation.json`'s `tree_hashes` KAT field
//! (`kat_treekem_test.zig`) proves this byte-exact against the official
//! RFC 9420 interop vectors, ungated.
//!
//! No caching — `treeHash(t, i)` recomputes the whole subtree under `i`
//! from scratch every call (`O(subtree size)`), matching RFC 9420's own
//! "computed recursively from the leaves up to the root" framing rather
//! than a caller-maintained cache; the KAT's largest tree (34 leaves, 67
//! nodes) makes this a non-issue. A later part maintaining a live group
//! over many epochs would want a cache (the RFC's own "efficiency of
//! recomputation can be improved by caching intermediate tree hashes"
//! note, §7.9) — out of scope for this scaffold.
//!
//! Model: RFC 9420 §7.8 (`NodeType`/`TreeHashInput`/`LeafNodeHashInput`/
//! `ParentNodeHashInput`).

const std = @import("std");
const codec = @import("codec.zig");
const treemath = @import("treemath.zig");
const tree = @import("tree.zig");
const wire = @import("wire_lists.zig");

pub const Error = tree.Error;

/// RFC 9420 §7.8: the tree hash of node `index` in `t` — `Hash
/// (TreeHashInput)` where `TreeHashInput = { NodeType node_type; select {
/// leaf: LeafNodeHashInput { uint32 leaf_index; optional<LeafNode>
/// leaf_node; }; parent: ParentNodeHashInput { optional<ParentNode>
/// parent_node; opaque left_hash<V>; opaque right_hash<V>; }; }; }`.
/// `S.Hash.digest_length`-sized output, `S.hash(...)` (`suite.zig`) is the
/// hash primitive.
pub fn treeHash(comptime S: type, allocator: std.mem.Allocator, t: *const tree.RatchetTree, index: usize) Error![S.Hash.digest_length]u8 {
    if (treemath.is_leaf(index)) {
        const leaf_index: u32 = @intCast(index / 2);
        const maybe_leaf: ?tree.LeafNode = if (t.nodes[index]) |n| switch (n) {
            .leaf => |l| l,
            .parent => return error.Malformed, // a leaf-position slot must be a Node.leaf if present
        } else null;

        var body_len: usize = 1 + 4 + 1;
        if (maybe_leaf) |l| body_len += l.encodedLen();
        const buf = try allocator.alloc(u8, body_len);
        defer allocator.free(buf);
        var w = codec.Writer.init(buf);
        try w.writeEnum(tree.NodeType, .leaf);
        try w.writeU32(leaf_index);
        try w.writePresence(maybe_leaf != null);
        if (maybe_leaf) |l| try l.encode(&w);
        return S.hash(w.finish());
    } else {
        const left_idx = treemath.left(index) orelse return error.Malformed;
        const right_idx = treemath.right(index) orelse return error.Malformed;
        const left_hash = try treeHash(S, allocator, t, left_idx);
        const right_hash = try treeHash(S, allocator, t, right_idx);

        const maybe_parent: ?tree.ParentNode = if (t.nodes[index]) |n| switch (n) {
            .parent => |p| p,
            .leaf => return error.Malformed, // an internal-position slot must be a Node.parent if present
        } else null;

        var body_len: usize = 1 + 1;
        if (maybe_parent) |p| body_len += p.encodedLen();
        body_len += wire.varintLen(left_hash.len) + left_hash.len;
        body_len += wire.varintLen(right_hash.len) + right_hash.len;
        const buf = try allocator.alloc(u8, body_len);
        defer allocator.free(buf);
        var w = codec.Writer.init(buf);
        try w.writeEnum(tree.NodeType, .parent);
        try w.writePresence(maybe_parent != null);
        if (maybe_parent) |p| try p.encode(&w);
        try w.writeVector(&left_hash);
        try w.writeVector(&right_hash);
        return S.hash(w.finish());
    }
}

/// The tree hash of the whole tree — the root's tree hash, RFC 9420 §7.8:
/// "The tree hash of an entire tree corresponds to the tree hash of the
/// root node."
pub fn rootHash(comptime S: type, allocator: std.mem.Allocator, t: *const tree.RatchetTree) Error![S.Hash.digest_length]u8 {
    return treeHash(S, allocator, t, treemath.root(t.nLeaves()));
}
