// SPDX-License-Identifier: MIT
//! mls.treemath — MLS's array-based binary tree math (RFC 9420 Appendix
//! C): the pure-integer-arithmetic node relationships (`left`/`right`/
//! `parent`/`sibling`, `root`, `direct_path`, `copath`, `is_leaf`,
//! `node_width`, `level`) every later part's ratchet-tree/TreeKEM
//! operations are built on. This file is a byte-exact (well, index-exact)
//! port of the RFC's own Python reference — RFC 9420 Appendix C literally
//! publishes the algorithm as code, so "model after a proven
//! implementation" (`CONVENTIONS.md` §1) here means "port the RFC's own
//! pseudocode", not "invent an equivalent".
//!
//! Array-based tree layout (RFC 9420 Appendix C): a complete balanced
//! binary tree with `n_leaves` leaves is represented as a flat array of
//! `node_width(n_leaves) = 2*(n_leaves-1)+1` nodes; leaves sit at EVEN
//! indices (`2*i` for leaf `i`), internal nodes at ODD indices. Node
//! relationships fall out of bit manipulation on the index alone — no
//! pointers, no allocation, nothing to keep in sync as the tree grows
//! (RFC 9420's own "Add: append N+1 blanks; Remove: truncate to (N-1)/2"
//! is why MLS picked this representation for the ratchet tree in the
//! first place).
//!
//! `left`/`right`/`parent`/`sibling` return `null` exactly where the RFC's
//! Python raises an `Exception` (leaf has no children; root has no
//! parent/sibling) — a typed optional, not a panic, since a later part
//! calls these with node indices read off the wire (an attacker-supplied
//! tree size or node index is untrusted input).
//!
//! Model: RFC 9420 Appendix C (Array-Based Trees) — this file's `log2`/
//! `level`/`node_width`/`root`/`left`/`right`/`parent`/`sibling`/
//! `direct_path`/`copath` are direct translations of the RFC's own
//! `log2`/`level`/`node_width`/`root`/`left`/`right`/`parent`/`sibling`/
//! `direct_path`/`copath` Python functions.

const std = @import("std");

/// A generous bound on tree depth (`level(root(n_leaves))`) any
/// `direct_path`/`copath` caller should size its output buffer to —
/// `usize` node indices mean `n_leaves` up to `2^63`ish is representable
/// at all, and 64 is already far beyond any real MLS group's tree depth
/// (a depth-64 tree holds `2^64` members).
pub const max_path_len: usize = 64;

pub const Error = error{
    /// `direct_path`/`copath`'s `out` buffer was too small for this
    /// tree's actual path length — grow it (`max_path_len` is a safe
    /// bound for any tree this module can index at all).
    BufferTooShort,
};

/// RFC 9420 Appendix C `log2(x)`: "The exponent of the largest power of 2
/// less than [or equal to] `x`" — `log2(0) = 0` by the RFC's own explicit
/// special case (not a well-defined logarithm, but the value every other
/// function here relies on at `x = 0`).
fn log2(x: usize) usize {
    if (x == 0) return 0;
    var k: usize = 0;
    while ((x >> @intCast(k)) > 0) : (k += 1) {}
    return k - 1;
}

/// RFC 9420 Appendix C `level(x)`: leaves (even indices) are level 0;
/// `level(x)` for an internal node is the number of trailing 1-bits in
/// `x`'s binary representation (equivalently, "if a node's children are
/// at different levels, its level is the max level of its children plus
/// one" — the array encoding makes this fall out of the bit pattern
/// directly rather than needing a recursive tree walk).
pub fn level(x: usize) usize {
    if (x & 1 == 0) return 0;
    var k: usize = 0;
    while ((x >> @intCast(k)) & 1 == 1) : (k += 1) {}
    return k;
}

/// RFC 9420 Appendix C `node_width(n)`: the number of array slots needed
/// to hold a tree with `n` leaves. `0` leaves is the empty tree (`0`
/// nodes) — every other `n` needs `2*(n-1)+1` slots (`n` leaves + `n-1`
/// internal nodes).
pub fn node_width(n_leaves: usize) usize {
    if (n_leaves == 0) return 0;
    return 2 * (n_leaves - 1) + 1;
}

/// RFC 9420 Appendix C `root(n)`: the index of the root of a tree with
/// `n` leaves — the largest power of 2 not exceeding `node_width(n)`,
/// minus 1 (the array's rightmost node at the tree's top level).
pub fn root(n_leaves: usize) usize {
    const w = node_width(n_leaves);
    if (w == 0) return 0;
    return (@as(usize, 1) << @intCast(log2(w))) - 1;
}

/// `true` iff `x` is a leaf node (an even array index) — RFC 9420
/// Appendix C's "leaf nodes are even-numbered nodes".
pub fn is_leaf(x: usize) bool {
    return x & 1 == 0;
}

/// RFC 9420 Appendix C `left(x)`: the left child of internal node `x`, or
/// `null` if `x` is a leaf (the RFC's Python raises `Exception('leaf node
/// has no children')` here — this port returns `null` instead, see the
/// module doc comment).
pub fn left(x: usize) ?usize {
    const k = level(x);
    if (k == 0) return null;
    return x ^ (@as(usize, 1) << @intCast(k - 1));
}

/// RFC 9420 Appendix C `right(x)`: the right child of internal node `x`,
/// or `null` if `x` is a leaf.
pub fn right(x: usize) ?usize {
    const k = level(x);
    if (k == 0) return null;
    return x ^ (@as(usize, 3) << @intCast(k - 1));
}

/// RFC 9420 Appendix C `parent(x, n)`: the parent of `x` in a tree with
/// `n` leaves, or `null` if `x` is the root (the RFC's Python raises
/// `Exception('root node has no parent')`).
pub fn parent(x: usize, n_leaves: usize) ?usize {
    const r = root(n_leaves);
    if (x == r) return null;
    const k = level(x);
    const b = (x >> @intCast(k + 1)) & 1;
    return (x | (@as(usize, 1) << @intCast(k))) ^ (b << @intCast(k + 1));
}

/// RFC 9420 Appendix C `sibling(x, n)`: the other child of `x`'s parent,
/// or `null` if `x` is the root (no parent, hence no sibling).
pub fn sibling(x: usize, n_leaves: usize) ?usize {
    const p = parent(x, n_leaves) orelse return null;
    // `p` is always an internal node (the parent of something), so
    // `left(p)`/`right(p)` are never null — matches the RFC's Python,
    // which calls `right(p)`/`left(p)` unconditionally here.
    if (x < p) return right(p) orelse unreachable;
    return left(p) orelse unreachable;
}

/// RFC 9420 Appendix C `direct_path(x, n)`: the path from `x` to the root
/// (EXCLUSIVE of `x` itself, INCLUSIVE of the root), ordered leaf-to-root.
/// Empty if `x` is already the root. Writes into caller-supplied `out`
/// (bounded — `max_path_len` is always sufficient) and returns the used
/// prefix, `error.BufferTooShort` if `out` is too small (never a panic on
/// an oversized/attacker-influenced tree).
pub fn direct_path(x: usize, n_leaves: usize, out: []usize) Error![]usize {
    const r = root(n_leaves);
    if (x == r) return out[0..0];
    var count: usize = 0;
    var cur = x;
    while (cur != r) {
        // `cur != r` at loop entry guarantees `parent` is non-null.
        cur = parent(cur, n_leaves) orelse unreachable;
        if (count >= out.len) return error.BufferTooShort;
        out[count] = cur;
        count += 1;
    }
    return out[0..count];
}

/// RFC 9420 Appendix C `copath(x, n)`: `[sibling(y, n) for y in [x] +
/// direct_path(x, n)[:-1]]` — the sibling of `x` itself, then the sibling
/// of every direct-path node EXCEPT the root (the root has no sibling).
/// Same length as `direct_path(x, n)`; empty if `x` is the root.
pub fn copath(x: usize, n_leaves: usize, out: []usize) Error![]usize {
    const r = root(n_leaves);
    if (x == r) return out[0..0];
    var dp_buf: [max_path_len]usize = undefined;
    const dp = try direct_path(x, n_leaves, &dp_buf);
    if (out.len < dp.len) return error.BufferTooShort;
    // ys = [x] ++ dp[0 .. dp.len - 1]; copath = sibling(y, n) for y in ys.
    out[0] = sibling(x, n_leaves) orelse unreachable; // x != r, checked above
    var i: usize = 1;
    while (i < dp.len) : (i += 1) {
        out[i] = sibling(dp[i - 1], n_leaves) orelse unreachable; // dp entries are never the root except possibly the last, which isn't read here
    }
    return out[0..dp.len];
}

// ── tests ─────────────────────────────────────────────────────────────

const testing = std.testing;

test "log2/level/node_width/root: small hand-checked values" {
    try testing.expectEqual(@as(usize, 0), node_width(0));
    try testing.expectEqual(@as(usize, 1), node_width(1));
    try testing.expectEqual(@as(usize, 3), node_width(2));
    try testing.expectEqual(@as(usize, 7), node_width(4));
    try testing.expectEqual(@as(usize, 0), root(1));
    try testing.expectEqual(@as(usize, 1), root(2));
    try testing.expectEqual(@as(usize, 3), root(4));
    try testing.expectEqual(@as(usize, 0), level(0)); // leaf
    try testing.expectEqual(@as(usize, 1), level(1));
    try testing.expectEqual(@as(usize, 2), level(3));
}

test "is_leaf: even indices only" {
    try testing.expect(is_leaf(0));
    try testing.expect(!is_leaf(1));
    try testing.expect(is_leaf(2));
    try testing.expect(!is_leaf(3));
}

test "left/right/parent/sibling: n_leaves=4 tree, matches RFC 9420 Appendix C Figure 32 by hand" {
    //        3
    //     .--+--.
    //     1     5
    //    / \   / \
    //   0   2 4   6
    try testing.expectEqual(@as(?usize, null), left(0)); // leaf
    try testing.expectEqual(@as(?usize, 0), left(1));
    try testing.expectEqual(@as(?usize, 2), right(1));
    try testing.expectEqual(@as(?usize, 1), left(3));
    try testing.expectEqual(@as(?usize, 5), right(3));
    try testing.expectEqual(@as(?usize, 4), left(5));
    try testing.expectEqual(@as(?usize, 6), right(5));

    try testing.expectEqual(@as(?usize, 1), parent(0, 4));
    try testing.expectEqual(@as(?usize, 3), parent(1, 4));
    try testing.expectEqual(@as(?usize, 1), parent(2, 4));
    try testing.expectEqual(@as(?usize, null), parent(3, 4)); // root
    try testing.expectEqual(@as(?usize, 5), parent(4, 4));
    try testing.expectEqual(@as(?usize, 3), parent(5, 4));
    try testing.expectEqual(@as(?usize, 5), parent(6, 4));

    try testing.expectEqual(@as(?usize, 2), sibling(0, 4));
    try testing.expectEqual(@as(?usize, 5), sibling(1, 4));
    try testing.expectEqual(@as(?usize, 0), sibling(2, 4));
    try testing.expectEqual(@as(?usize, null), sibling(3, 4)); // root
    try testing.expectEqual(@as(?usize, 6), sibling(4, 4));
    try testing.expectEqual(@as(?usize, 1), sibling(5, 4));
    try testing.expectEqual(@as(?usize, 4), sibling(6, 4));
}

test "direct_path/copath: n_leaves=4, leaf 0" {
    var dp_buf: [max_path_len]usize = undefined;
    const dp = try direct_path(0, 4, &dp_buf);
    try testing.expectEqualSlices(usize, &[_]usize{ 1, 3 }, dp);

    var cp_buf: [max_path_len]usize = undefined;
    const cp = try copath(0, 4, &cp_buf);
    // ys = [0, 1]; copath = [sibling(0,4), sibling(1,4)] = [2, 5]
    try testing.expectEqualSlices(usize, &[_]usize{ 2, 5 }, cp);
}

test "direct_path/copath: the root itself has empty direct_path/copath" {
    var buf: [max_path_len]usize = undefined;
    try testing.expectEqual(@as(usize, 0), (try direct_path(3, 4, &buf)).len);
    try testing.expectEqual(@as(usize, 0), (try copath(3, 4, &buf)).len);
}

test "direct_path: BufferTooShort on an undersized output buffer, never a panic" {
    var tiny: [1]usize = undefined;
    try testing.expectError(error.BufferTooShort, direct_path(0, 4, &tiny));
}

test "direct_path/copath self-consistency across every node of a 512-leaf tree" {
    const n_leaves: usize = 512;
    const w = node_width(n_leaves);
    var x: usize = 0;
    while (x < w) : (x += 1) {
        var dp_buf: [max_path_len]usize = undefined;
        const dp = try direct_path(x, n_leaves, &dp_buf);
        var cp_buf: [max_path_len]usize = undefined;
        const cp = try copath(x, n_leaves, &cp_buf);
        try testing.expectEqual(dp.len, cp.len);
        if (x == root(n_leaves)) {
            try testing.expectEqual(@as(usize, 0), dp.len);
            continue;
        }
        // direct_path's last entry must be the root; walking `parent`
        // from `x` step by step must reproduce `dp` exactly.
        try testing.expectEqual(root(n_leaves), dp[dp.len - 1]);
        var cur = x;
        for (dp) |expected| {
            cur = parent(cur, n_leaves).?;
            try testing.expectEqual(expected, cur);
        }
        // Every copath entry is the sibling of the corresponding
        // direct-path predecessor (x itself, then dp[0..len-1]).
        try testing.expectEqual(sibling(x, n_leaves).?, cp[0]);
        for (dp[0 .. dp.len - 1], 1..) |node, i| {
            try testing.expectEqual(sibling(node, n_leaves).?, cp[i]);
        }
    }
}
