// SPDX-License-Identifier: MIT

//! distance — the reference edit-distance metric, a plain full-matrix
//! implementation kept deliberately separate from the incremental DP-over-trie
//! walk in `search.zig`.
//!
//! The metric is **optimal string alignment (OSA)**, the *restricted*
//! Damerau–Levenshtein distance: insertions, deletions, substitutions, and
//! transpositions of two ADJACENT characters, each counted as one edit, under
//! the OSA restriction that no substring is edited more than once (so a
//! transposed pair is never also touched by another edit). OSA is what a
//! two-previous-row DP over a trie can compute; true (unrestricted)
//! Damerau–Levenshtein cannot, and is a documented non-goal (see SPEC.md).
//!
//! Distance is over **bytes**, not Unicode scalar values: a multi-byte UTF-8
//! codepoint counts as multiple byte-edits (e.g. replacing `ě` (0xC4 0x9B) with
//! `e` (0x65) is distance 2). Unicode-aware distance is the caller's concern —
//! fold/normalize before indexing, the same contract as `trie`.
//!
//! This function exists to be OBVIOUSLY correct: it is the differential oracle
//! `search.zig` is checked against, and a public single-pair verification
//! helper. It is allocation-free (three rolling rows in fixed inline buffers)
//! and therefore length-bounded; both inputs must be ≤ `max_ref_len` bytes.

const std = @import("std");

/// Maximum input length `osaDistance` accepts. Comfortably above any address
/// string; a longer input yields `error.TooLong` rather than a silent wrong
/// answer. This is a limit of the *reference* helper only — the production
/// `search.zig` walk has its own, separate depth limit.
pub const max_ref_len: usize = 4096;

pub const RefError = error{TooLong};

/// Exact optimal-string-alignment (restricted Damerau–Levenshtein) distance
/// between `a` and `b`, over bytes. Allocation-free; both inputs must be
/// ≤ `max_ref_len`. Symmetric: `osaDistance(a, b) == osaDistance(b, a)`.
pub fn osaDistance(a: []const u8, b: []const u8) RefError!u32 {
    if (a.len > max_ref_len or b.len > max_ref_len) return error.TooLong;
    const n = b.len;

    // Three rolling rows over `b`, each length n+1: the grandparent row
    // (`prev_prev`, for the transposition term), the parent row (`prev`), and
    // the row being filled (`cur`). Distances are ≤ max(a.len, b.len) ≤ 4096,
    // so u16 cells never overflow.
    var buf0: [max_ref_len + 1]u16 = undefined;
    var buf1: [max_ref_len + 1]u16 = undefined;
    var buf2: [max_ref_len + 1]u16 = undefined;
    var prev_prev: []u16 = buf0[0 .. n + 1];
    var prev: []u16 = buf1[0 .. n + 1];
    var cur: []u16 = buf2[0 .. n + 1];

    // Row i = 0 (empty prefix of `a`): distance to b[0..j] is j deletions.
    for (0..n + 1) |j| prev[j] = @intCast(j);
    if (a.len == 0) return prev[n];

    var i: usize = 1;
    while (i <= a.len) : (i += 1) {
        cur[0] = @intCast(i); // distance from a[0..i] to empty = i insertions
        var j: usize = 1;
        while (j <= n) : (j += 1) {
            const cost: u16 = if (a[i - 1] == b[j - 1]) 0 else 1;
            var v: u16 = @min(@min(cur[j - 1] + 1, prev[j] + 1), prev[j - 1] + cost);
            // Adjacent transposition: a[i-1]==b[j-2] and a[i-2]==b[j-1].
            if (i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]) {
                v = @min(v, prev_prev[j - 2] + 1);
            }
            cur[j] = v;
        }
        // Rotate the three rolling rows: the old grandparent buffer is recycled
        // as the next `cur`.
        const spare = prev_prev;
        prev_prev = prev;
        prev = cur;
        cur = spare;
    }
    return prev[n];
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "osa: identical strings are distance 0" {
    try testing.expectEqual(@as(u32, 0), try osaDistance("praha", "praha"));
    try testing.expectEqual(@as(u32, 0), try osaDistance("", ""));
}

test "osa: single edits are distance 1" {
    try testing.expectEqual(@as(u32, 1), try osaDistance("praha", "praga")); // substitution
    try testing.expectEqual(@as(u32, 1), try osaDistance("praha", "prahaX")); // insertion
    try testing.expectEqual(@as(u32, 1), try osaDistance("praha", "praa")); // deletion
    try testing.expectEqual(@as(u32, 1), try osaDistance("teh", "the")); // transposition
}

test "osa: empty vs non-empty is the length" {
    try testing.expectEqual(@as(u32, 5), try osaDistance("", "praha"));
    try testing.expectEqual(@as(u32, 3), try osaDistance("abc", ""));
}

test "osa: symmetry" {
    const pairs = [_][2][]const u8{
        .{ "kitten", "sitting" },
        .{ "flaw", "lawn" },
        .{ "abcdef", "azced" },
        .{ "", "xyz" },
    };
    for (pairs) |p| {
        try testing.expectEqual(try osaDistance(p[0], p[1]), try osaDistance(p[1], p[0]));
    }
}

test "osa: classic Levenshtein distances" {
    try testing.expectEqual(@as(u32, 3), try osaDistance("kitten", "sitting"));
    try testing.expectEqual(@as(u32, 2), try osaDistance("flaw", "lawn"));
}

test "osa: OSA restriction — 'ca' -> 'abc' is 3, not 2" {
    // A true (unrestricted) Damerau–Levenshtein counts this as 2; the OSA
    // restriction forbids editing an already-transposed region again, so it is
    // 3. This pins that we implement OSA, deliberately, and nothing else.
    try testing.expectEqual(@as(u32, 3), try osaDistance("ca", "abc"));
}

test "osa: multi-byte UTF-8 counts as multiple byte edits" {
    // 'ě' is 0xC4 0x9B (2 bytes); replacing it with ASCII 'e' is one deletion +
    // one substitution over bytes = distance 2.
    try testing.expectEqual(@as(u32, 2), try osaDistance("město", "mesto"));
}

test "osa: rejects over-long inputs" {
    var big: [max_ref_len + 1]u8 = undefined;
    @memset(&big, 'a');
    try testing.expectError(error.TooLong, osaDistance(&big, "a"));
    try testing.expectError(error.TooLong, osaDistance("a", &big));
}
