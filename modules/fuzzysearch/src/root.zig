//! fuzzysearch — bounded-edit-distance typo-tolerant lookup over a static
//! string set (the typo-tolerant sibling of the exact-prefix `trie`).
//!
//! Placeholder: pre-wired by the coordinator; core implementation pending.

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .util,
    .concurrency = .single_owner,
    .model_after = "Levenshtein automaton over a trie; BK-tree (Burkhard-Keller)",
    .deps = .{"trie"},
};

test "smoke" {
    try std.testing.expect(true);
}
