// SPDX-License-Identifier: MIT
//! BIP341 script-tree construction: the `TapLeaf`/`TapBranch` hashes, the
//! Merkle root of a tree of scripts, the tweaked output key committing to it,
//! and — per leaf — the Merkle path and the control block a script-path
//! spend must carry.
//!
//! Two input shapes, one implementation:
//!  - an explicit shape (`Node`: a leaf or a pair of subtrees), which is how
//!    BIP341's `wallet-test-vectors.json` describes trees;
//!  - a depth-first list of `DepthLeaf` (depth, leaf version, script), the
//!    BIP371 `PSBT_OUT_TAP_TREE` encoding. Depths must form a COMPLETE binary
//!    tree (every branch has exactly two children).
//! `buildFromTree` flattens a `Node` into the depth list and calls
//! `buildFromLeaves`, so the two cannot disagree.
//!
//! Leaf order in `SpendInfo.leaves` is the depth-first, left-to-right order
//! of the input (the order the BIP341 vectors list `leafHashes` and
//! `scriptPathControlBlocks` in). The order of a branch's two children never
//! changes the Merkle root (`tapBranchHash` sorts them) — only the order of
//! `leaves`.
//!
//! Everything here is public data (scripts, hashes, keys): nothing is
//! constant-time and nothing is zeroized. Clean-room from BIP341/BIP371.

const std = @import("std");
const Allocator = std.mem.Allocator;
const bip340 = @import("bip340");
const root = @import("root.zig");

/// BIP341's default (and, today, only defined) tapscript leaf version.
pub const default_leaf_version: u8 = 0xc0;

/// BIP341 control-block size: `1` (version|parity) + `32` (internal key).
pub const control_base_size: usize = 33;
/// One Merkle path element in a control block.
pub const control_node_size: usize = 32;
/// Longest Merkle path a control block may carry (BIP341, consensus).
pub const max_path_len: usize = 128;

/// `hash_TapLeaf`: `taggedHash("TapLeaf", leaf_version ‖ compact_size(len) ‖
/// script)`. Any `leaf_version` byte is hashed as given; `validLeafVersion`
/// says which ones BIP341 permits.
pub fn tapLeafHash(leaf_version: u8, script: []const u8) [32]u8 {
    var h = bip340.hash.taggedHasher("TapLeaf");
    h.update(&[_]u8{leaf_version});
    var cs: [9]u8 = undefined;
    h.update(compactSize(script.len, &cs));
    h.update(script);
    return h.finalResult();
}

/// `hash_TapBranch`: `taggedHash("TapBranch", min(a,b) ‖ max(a,b))` — the two
/// children ordered lexicographically, so a branch hash does not depend on
/// which side either child sits.
pub fn tapBranchHash(a: [32]u8, b: [32]u8) [32]u8 {
    var h = bip340.hash.taggedHasher("TapBranch");
    if (std.mem.lessThan(u8, &b, &a)) {
        h.update(&b);
        h.update(&a);
    } else {
        h.update(&a);
        h.update(&b);
    }
    return h.finalResult();
}

/// A leaf version BIP341 allows in a control block: even (the low bit is the
/// output-key parity) and not `0x50` (that first-byte value marks an annex).
pub fn validLeafVersion(v: u8) bool {
    return (v & 0xfe) == v and v != 0x50;
}

/// One script and the leaf version it runs under.
pub const Leaf = struct {
    version: u8 = default_leaf_version,
    script: []const u8,
};

/// An explicit tree shape: a leaf, or a branch of exactly two subtrees.
pub const Node = union(enum) {
    leaf: Leaf,
    branch: [2]*const Node,
};

/// A leaf with its depth, as in BIP371 `PSBT_OUT_TAP_TREE`. A list of these in
/// depth-first order describes a tree; a lone `depth = 0` entry is a
/// single-leaf tree.
pub const DepthLeaf = struct {
    depth: u8,
    version: u8 = default_leaf_version,
    script: []const u8,
};

pub const TreeError = error{
    /// The depths do not describe a complete binary tree: an incomplete
    /// branch (a subtree with a single child), or more leaves after the tree
    /// was already complete (e.g. a depth-0 leaf followed by anything).
    InvalidTreeShape,
    /// A leaf deeper than 128 — its control block would exceed BIP341's
    /// maximum path length.
    TreeTooDeep,
    /// A leaf version that is odd or `0x50` (see `validLeafVersion`).
    InvalidLeafVersion,
};

pub const BuildError = TreeError || root.TweakError || Allocator.Error;

/// A leaf of a built tree. `script` borrows the caller's memory (it is NOT
/// copied); `path` is owned by the `SpendInfo`.
pub const LeafInfo = struct {
    version: u8,
    script: []const u8,
    leaf_hash: [32]u8,
    /// Sibling hashes from the leaf up to the root (length = the leaf's
    /// depth); exactly the control block's path bytes.
    path: []const [32]u8,
};

/// A built tree and the output it commits to. Free with `deinit` (with the
/// allocator given to the builder). `leaves[i].script` slices point into the
/// caller's input and must outlive their use here.
pub const SpendInfo = struct {
    internal_key: bip340.XOnlyPublicKey,
    /// `null` when the tree has no leaves (key-path-only output), else the
    /// tree's Merkle root (the single leaf hash for a one-leaf tree).
    merkle_root: ?[32]u8,
    /// The Taproot output key `Q = P + t·G` and its y-parity.
    output: root.TweakedPublicKey,
    /// The raw tweak hash `t` (see `root.TweakResult`).
    tweak: [32]u8,
    leaves: []const LeafInfo,
    /// Backing storage of every `leaves[i].path`.
    path_storage: []const [32]u8,

    pub fn deinit(self: *SpendInfo, allocator: Allocator) void {
        allocator.free(self.leaves);
        allocator.free(self.path_storage);
        self.* = undefined;
    }

    /// Byte length of leaf `i`'s control block: `33 + 32·depth`.
    pub fn controlBlockLen(self: SpendInfo, i: usize) usize {
        return control_base_size + control_node_size * self.leaves[i].path.len;
    }

    /// Write leaf `i`'s control block, `(version | parity) ‖ internal_x ‖
    /// path`, into `out` (which must hold `controlBlockLen(i)` bytes) and
    /// return the filled prefix.
    pub fn controlBlock(self: SpendInfo, i: usize, out: []u8) []u8 {
        const leaf = self.leaves[i];
        const n = self.controlBlockLen(i);
        std.debug.assert(out.len >= n);
        out[0] = leaf.version | @as(u8, self.output.parity);
        out[1..33].* = self.internal_key.toBytes();
        for (leaf.path, 0..) |node, k| {
            out[control_base_size + control_node_size * k ..][0..32].* = node;
        }
        return out[0..n];
    }

    /// Allocating form of `controlBlock`; the caller frees the result.
    pub fn controlBlockAlloc(self: SpendInfo, allocator: Allocator, i: usize) Allocator.Error![]u8 {
        const buf = try allocator.alloc(u8, self.controlBlockLen(i));
        return self.controlBlock(i, buf);
    }
};

/// Build from a depth-first leaf list (BIP371 shape). An empty list is a
/// key-path-only output (`merkle_root == null`). Every failure is a typed
/// error; nothing is leaked on the error path.
pub fn buildFromLeaves(allocator: Allocator, internal: bip340.XOnlyPublicKey, list: []const DepthLeaf) BuildError!SpendInfo {
    const n = list.len;
    if (n == 0) return finish(internal, null, &.{}, &.{});

    for (list) |l| {
        if (l.depth > max_path_len) return error.TreeTooDeep;
        if (!validLeafVersion(l.version)) return error.InvalidLeafVersion;
    }

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Per-leaf path being accumulated bottom-up, and the stack of completed
    // subtrees (each covers a contiguous range of leaves).
    const paths = try arena.alloc(std.ArrayList([32]u8), n);
    for (paths) |*p| p.* = .empty;
    const Entry = struct { depth: u8, hash: [32]u8, first: usize, end: usize };
    const stack = try arena.alloc(Entry, n);
    var top: usize = 0;
    const hashes = try arena.alloc([32]u8, n);

    for (list, 0..) |l, i| {
        // A depth-0 entry is a complete tree; nothing may follow it.
        if (top > 0 and stack[top - 1].depth == 0) return error.InvalidTreeShape;
        hashes[i] = tapLeafHash(l.version, l.script);
        stack[top] = .{ .depth = l.depth, .hash = hashes[i], .first = i, .end = i + 1 };
        top += 1;
        // Two siblings of equal depth merge into their parent.
        while (top >= 2 and stack[top - 1].depth == stack[top - 2].depth and stack[top - 1].depth > 0) {
            const r = stack[top - 1];
            const lft = stack[top - 2];
            for (lft.first..lft.end) |k| try paths[k].append(arena, r.hash);
            for (r.first..r.end) |k| try paths[k].append(arena, lft.hash);
            stack[top - 2] = .{
                .depth = lft.depth - 1,
                .hash = tapBranchHash(lft.hash, r.hash),
                .first = lft.first,
                .end = r.end,
            };
            top -= 1;
        }
    }
    if (top != 1 or stack[0].depth != 0) return error.InvalidTreeShape;

    var total: usize = 0;
    for (paths) |p| total += p.items.len;
    const storage = try allocator.alloc([32]u8, total);
    errdefer allocator.free(storage);
    const leaves = try allocator.alloc(LeafInfo, n);
    errdefer allocator.free(leaves);
    var off: usize = 0;
    for (list, 0..) |l, i| {
        const len = paths[i].items.len;
        @memcpy(storage[off..][0..len], paths[i].items);
        leaves[i] = .{ .version = l.version, .script = l.script, .leaf_hash = hashes[i], .path = storage[off..][0..len] };
        off += len;
    }
    return finish(internal, stack[0].hash, leaves, storage);
}

/// Build from an explicit shape. `null` is the empty tree (key-path-only).
pub fn buildFromTree(allocator: Allocator, internal: bip340.XOnlyPublicKey, tree: ?*const Node) BuildError!SpendInfo {
    const t = tree orelse return buildFromLeaves(allocator, internal, &.{});
    var flat: std.ArrayList(DepthLeaf) = .empty;
    defer flat.deinit(allocator);
    try flatten(allocator, t, 0, &flat);
    return buildFromLeaves(allocator, internal, flat.items);
}

fn flatten(allocator: Allocator, node: *const Node, depth: usize, out: *std.ArrayList(DepthLeaf)) BuildError!void {
    if (depth > max_path_len) return error.TreeTooDeep; // bounds the recursion, too
    switch (node.*) {
        .leaf => |l| try out.append(allocator, .{ .depth = @intCast(depth), .version = l.version, .script = l.script }),
        .branch => |b| {
            try flatten(allocator, b[0], depth + 1, out);
            try flatten(allocator, b[1], depth + 1, out);
        },
    }
}

/// Tweak the internal key with `merkle_root` and assemble the result. The
/// caller's `errdefer`s free `leaves`/`storage` if the tweak fails.
fn finish(internal: bip340.XOnlyPublicKey, merkle_root: ?[32]u8, leaves: []const LeafInfo, storage: []const [32]u8) BuildError!SpendInfo {
    const tw = try root.tweakPublicKey(internal, merkle_root);
    return .{
        .internal_key = internal,
        .merkle_root = merkle_root,
        .output = tw.output,
        .tweak = tw.tweak,
        .leaves = leaves,
        .path_storage = storage,
    };
}

/// Bitcoin CompactSize encoding of `n` into `buf`; returns the used prefix.
fn compactSize(n: usize, buf: *[9]u8) []const u8 {
    if (n < 0xfd) {
        buf[0] = @intCast(n);
        return buf[0..1];
    } else if (n <= 0xffff) {
        buf[0] = 0xfd;
        std.mem.writeInt(u16, buf[1..3], @intCast(n), .little);
        return buf[0..3];
    } else if (n <= 0xffff_ffff) {
        buf[0] = 0xfe;
        std.mem.writeInt(u32, buf[1..5], @intCast(n), .little);
        return buf[0..5];
    }
    buf[0] = 0xff;
    std.mem.writeInt(u64, buf[1..9], n, .little);
    return buf[0..9];
}
