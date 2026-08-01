// SPDX-License-Identifier: MIT
//! Drives `preprocess` through the vendored json5/json5-tests corpus
//! (json5_tests_vectors.zig), honouring the upstream extension convention in
//! both directions: `.json`/`.json5` fixtures must come out as parseable
//! JSON, and `.js`/`.txt` fixtures must NOT.
//!
//! This module is a JSON5-TO-JSON PREPROCESSOR, not a standalone JSON5
//! decoder: `preprocess` itself only fails on allocator exhaustion (its key
//! error-recovery paths emit `$err_trace_N` diagnostics rather than
//! propagating a Zig error -- see root.zig's "error recovery" comments and
//! the pre-existing "error recovery: space inside unquoted key" /
//! "unquoted key with no colon before EOF" tests, which pin that on
//! purpose). So "the parser accepted/rejected X" here means: preprocess(X)
//! succeeded (as it almost always does) AND its output is fed to
//! `std.json.parseFromSlice`, which is where JSON5-vs-JSON syntax actually
//! gets enforced.
//!
//! Vectors marked `out_of_scope` are counted (`total_out_of_scope` below is
//! a canary against silently dropping one) but not asserted against
//! `expect` -- each names a specific README "Deferred" bullet.
//!
//! `known_disagreement` vectors ARE asserted, but against the OPPOSITE of
//! `expect` -- pinning a case where this module's own recovery-by-design
//! deliberately accepts input the corpus says must be rejected. See the
//! comment beside `known_disagreements` below.

const std = @import("std");
const testing = std.testing;
const json5 = @import("root.zig");
const vectors_mod = @import("json5_tests_vectors.zig");
const Expect = vectors_mod.Expect;

/// One corpus case where root.zig's malformed-unquoted-key recovery (the
/// "$err_trace_N" synthetic entry -- see root.zig's "error recovery: junk
/// before ':'" branch) turns what json5-tests calls a must-reject case into
/// successfully-parsed JSON. This is not a bug: `preprocess`'s own
/// pre-existing tests ("error recovery: space inside unquoted key",
/// "unquoted key with no colon before EOF does not slice OOB") assert this
/// EXACT recovery behavior for exactly this input shape (an unquoted key
/// with an embedded space before its colon -- "multi-word" here). The module
/// was built to never fail hard on malformed config/editor input;
/// json5-tests was built to assert hard failure on non-identifier unquoted
/// keys. Both are correct for what they're each testing.
///
/// `objects/illegal-unquoted-key-number.txt` ("10twenty: ...") is NOT in
/// this list even though it looks like the same shape: empirically it
/// already rejects correctly (the leading digits "10" break object
/// structure before recovery ever gets a chance), so it needs no carve-out.
const known_disagreements = [_][]const u8{
    "objects/illegal-unquoted-key-symbol.txt",
};

fn isKnownDisagreement(path: []const u8) bool {
    for (known_disagreements) |p| {
        if (std.mem.eql(u8, p, path)) return true;
    }
    return false;
}

/// Run one fixture through preprocess -> std.json and report whether the
/// result is parseable JSON.
fn actuallyParses(alloc: std.mem.Allocator, content: []const u8) !bool {
    const out = try json5.preprocess(alloc, content);
    defer alloc.free(out);
    // duplicate_field_behavior: std.json defaults to erroring on a repeated
    // key, but JSON syntax permits duplicate keys (objects/duplicate-keys.json
    // is a plain `.json` must-parse case) -- JS's own JSON.parse keeps the
    // last occurrence, so `.use_last` is what "is this valid JSON5" should
    // mean here, not a change to root.zig's behavior.
    const parsed = std.json.parseFromSlice(std.json.Value, alloc, out, .{ .duplicate_field_behavior = .use_last }) catch |err| {
        // Allocation failures are real test failures, not a "rejected" verdict.
        if (err == error.OutOfMemory) return err;
        return false;
    };
    parsed.deinit();
    return true;
}

test "json5-tests corpus: vendored count matches expectation (canary)" {
    // If this trips, testdata/json5-tests/ was re-vendored or hand-edited
    // without updating json5_tests_vectors.zig -- regenerate it, don't
    // adjust this number to match.
    try testing.expectEqual(@as(usize, 112), vectors_mod.vectors.len);
    var out_of_scope_count: usize = 0;
    for (vectors_mod.vectors) |v| {
        if (v.out_of_scope != null) out_of_scope_count += 1;
    }
    try testing.expectEqual(@as(usize, 37), out_of_scope_count);
}

test "json5-tests corpus: in-scope fixtures match the upstream extension convention" {
    const alloc = testing.allocator;
    var checked: usize = 0;
    var skipped_out_of_scope: usize = 0;
    var skipped_disagreement: usize = 0;
    var mismatches: usize = 0;
    var resolved_disagreements: usize = 0;

    // Accumulate every mismatch instead of failing at the first one -- a
    // single `try` inside this loop would silently hide every case after
    // whichever one happens to sort first.
    for (vectors_mod.vectors) |v| {
        if (v.out_of_scope) |_| {
            // Still must not crash/OOM even though we don't assert the verdict.
            const out = try json5.preprocess(alloc, v.content);
            alloc.free(out);
            skipped_out_of_scope += 1;
            continue;
        }
        if (isKnownDisagreement(v.path)) {
            // Assert the OPPOSITE of `expect`: this module's recovery
            // deliberately turns this must-reject case into a parse.
            const parses = try actuallyParses(alloc, v.content);
            if (v.expect == .must_reject and !parses) {
                std.debug.print(
                    "known_disagreements entry '{s}' now correctly rejects -- " ++
                        "the disagreement is gone; remove it from known_disagreements " ++
                        "and let it be asserted normally.\n",
                    .{v.path},
                );
                resolved_disagreements += 1;
            }
            skipped_disagreement += 1;
            continue;
        }

        const parses = try actuallyParses(alloc, v.content);
        const actual: Expect = if (parses) .must_parse else .must_reject;
        if (actual != v.expect) {
            std.debug.print(
                "MISMATCH case '{s}': expected {s}, got {s}\ncontent:\n{s}\n\n",
                .{ v.path, @tagName(v.expect), @tagName(actual), v.content },
            );
            mismatches += 1;
        }
        checked += 1;
    }

    try testing.expectEqual(@as(usize, 1), skipped_disagreement);
    try testing.expectEqual(@as(usize, 37), skipped_out_of_scope);
    try testing.expectEqual(vectors_mod.vectors.len, checked + skipped_out_of_scope + skipped_disagreement);
    try testing.expectEqual(@as(usize, 0), resolved_disagreements);
    try testing.expectEqual(@as(usize, 0), mismatches);
}
