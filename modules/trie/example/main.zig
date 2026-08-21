// SPDX-License-Identifier: MIT

//! What an address-search consumer does with `trie`: build a frozen index
//! from a handful of `(key, value)` pairs, then answer the three query shapes
//! a real autocomplete box needs — exact lookup, ranked top-N completions
//! under a typed prefix, and a full lexicographic listing under that prefix.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling.

const std = @import("std");
const trie = @import("trie");

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // Street names, ranked by a popularity/relevance score a real ingest
    // pipeline would compute (higher wins ties in `topN`).
    const pairs = [_]trie.Pair{
        .{ .key = "Karlova", .value = 90 },
        .{ .key = "Karlovo namesti", .value = 70 },
        .{ .key = "Karlovarska", .value = 40 },
        .{ .key = "Karlin", .value = 55 },
        .{ .key = "Vinohradska", .value = 60 },
    };

    // Build once, freeze into a self-describing byte buffer the caller owns.
    const frozen_bytes = try trie.freezeFromPairs(gpa, gpa, &pairs);
    defer gpa.free(frozen_bytes);
    std.debug.print("froze {d} keys into {d} bytes\n", .{ pairs.len, frozen_bytes.len });

    // Untrusted-buffer open: full node-region CRC check, appropriate for an
    // index that arrived over the network or from disk.
    const idx = trie.Frozen.loadVerified(frozen_bytes) catch |err| switch (err) {
        error.BodyCorrupt => {
            std.debug.print("frozen buffer failed its CRC check\n", .{});
            return;
        },
        else => return err,
    };
    std.debug.print("index reports {d} keys\n", .{idx.keyCount()});

    // Exact lookup: no allocation on this path.
    const exact = try idx.lookup("Karlin");
    std.debug.print("exact 'Karlin' -> {?d}\n", .{exact});
    const miss = try idx.lookup("Karlinska");
    std.debug.print("exact 'Karlinska' -> {?d} (not a stored key)\n", .{miss});

    // Ranked top-N completions under a typed prefix, with a bounded visit
    // budget — the DoS guard a real autocomplete endpoint relies on for a
    // predictable worst-case latency.
    var results: [3]trie.Completion = undefined;
    var key_buf: [128]u8 = undefined;
    const top = try idx.topN("Karl", &results, &key_buf, .{ .max_visited = 1000 });
    std.debug.print("top-{d} under 'Karl' (status={s}):\n", .{ top.items.len, @tagName(top.status) });
    for (top.items) |c| std.debug.print("  {s} (score {d})\n", .{ c.key, c.value });

    // Full lexicographic listing under the same prefix, for a "show all
    // matches" view rather than a ranked shortlist.
    var it = try idx.prefixIterator(gpa, "Karl");
    defer it.deinit();
    var list_key_buf: [128]u8 = undefined;
    std.debug.print("every match under 'Karl':\n", .{});
    while (try it.next(&list_key_buf)) |c| {
        std.debug.print("  {s} (score {d})\n", .{ c.key, c.value });
    }
}
