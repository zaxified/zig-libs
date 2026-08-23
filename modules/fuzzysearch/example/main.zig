// SPDX-License-Identifier: MIT

//! What a Czech address-autocomplete consumer does with `fuzzysearch`: build
//! a small street-name index, freeze it, search with a realistic typo, and
//! check the returned RANKING (not just membership) against the module's own
//! brute-force reference oracle `osaDistance` — a separate full-matrix
//! implementation from the pruned automaton `search` walks (see SPEC.md
//! "Differential oracle"), so agreement between the two is a genuine
//! cross-check, not the same code answering itself twice.
//!
//! Also round-trips the frozen buffer through a copy (standing in for
//! "write to a file, read it back") and checks the reloaded index answers
//! identically — the part a consumer persisting the index to disk gets wrong.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export).

const std = @import("std");
const fuzzysearch = @import("fuzzysearch");

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // A small realistic street-name set — the driving RÚIAN autocomplete case.
    const pairs = [_]fuzzysearch.Pair{
        .{ .key = "vaclavske namesti", .value = 100 },
        .{ .key = "narodni trida", .value = 90 },
        .{ .key = "vodickova", .value = 80 },
        .{ .key = "vinohradska", .value = 70 },
        .{ .key = "krizovnicka", .value = 60 },
    };
    const buf = try fuzzysearch.freezeFromPairs(gpa, gpa, &pairs);
    defer gpa.free(buf);

    const f = try fuzzysearch.Frozen.load(buf);
    try std.testing.expectEqual(@as(u64, pairs.len), f.keyCount());

    // The user mistyped ("Vaclvske" -> "Vaclavske" from the README's own
    // driving example, folded to the module's lowercase-key convention).
    const query = "vaclvske namesti";
    var results: [4]fuzzysearch.Match = undefined;
    var key_buf: [4 * 32]u8 = undefined;
    const r = try f.search(query, 2, &results, &key_buf, .{});
    if (r.status != .complete) return error.UnexpectedTruncation;
    if (r.items.len == 0) return error.NoMatches;

    // Rank check: the closest key really is the typo's intended target, and
    // the returned order is non-decreasing distance throughout.
    if (!std.mem.eql(u8, r.items[0].key, "vaclavske namesti")) return error.WrongTopMatch;
    var prev_distance: u32 = 0;
    for (r.items, 0..) |m, i| {
        if (i > 0 and m.distance < prev_distance) return error.RankingOutOfOrder;
        prev_distance = m.distance;
        // Cross-check every reported distance against the brute-force
        // reference metric — a DIFFERENT implementation (full-matrix DP,
        // not the pruned trie automaton) computing the same OSA distance.
        const want = try fuzzysearch.osaDistance(query, m.key);
        if (want != m.distance) return error.DistanceDisagreesWithOracle;
    }
    std.debug.print(
        "search(\"{s}\", k=2): top match \"{s}\" (distance {d}), {d} result(s), all agree with the brute-force oracle\n",
        .{ query, r.items[0].key, r.items[0].distance, r.items.len },
    );

    // Round-trip: copy the frozen buffer (standing in for "persisted to a
    // file, mmapped back") and check the reloaded index answers identically —
    // the part a consumer who writes the index to disk actually exercises.
    {
        const copy = try gpa.dupe(u8, buf);
        defer gpa.free(copy);
        const f2 = try fuzzysearch.Frozen.load(copy);
        var results2: [4]fuzzysearch.Match = undefined;
        var key_buf2: [4 * 32]u8 = undefined;
        const r2 = try f2.search(query, 2, &results2, &key_buf2, .{});
        if (r2.items.len != r.items.len) return error.RoundTripMismatch;
        for (r.items, r2.items) |a, b| {
            if (a.distance != b.distance or a.value != b.value or !std.mem.eql(u8, a.key, b.key)) {
                return error.RoundTripMismatch;
            }
        }
        std.debug.print("round-trip through a copied buffer: {d} result(s), byte-identical\n", .{r2.items.len});
    }

    // Negative case: a query over `max_query_len` (256 bytes) is refused by
    // name rather than silently truncated.
    {
        var long_query: [fuzzysearch.max_query_len + 1]u8 = undefined;
        @memset(&long_query, 'a');
        var results3: [4]fuzzysearch.Match = undefined;
        var key_buf3: [4 * 32]u8 = undefined;
        if (f.search(&long_query, 1, &results3, &key_buf3, .{})) |_| {
            return error.ExpectedRejection;
        } else |err| switch (err) {
            error.QueryTooLong => std.debug.print("query of {d} bytes: QueryTooLong (expected)\n", .{long_query.len}),
            else => return err,
        }
    }
}
