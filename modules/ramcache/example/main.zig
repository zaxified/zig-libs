// SPDX-License-Identifier: MIT

//! What a consumer does with `ramcache`: cache the result of an expensive
//! lookup (here, a config blob keyed by a request id), serve repeated
//! requests from RAM, invalidate a whole batch of derived entries with one
//! generation bump, and use the zero-copy `pin`/`release` borrow instead of
//! copying `get`'s result when the caller can bound how long it holds it.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or a caller-owned allocation has no
//! documented release path, this file stops compiling or leaks under the
//! `DebugAllocator`.

const std = @import("std");
const ramcache = @import("ramcache");

/// Stands in for "recompute this from the slow path" — a DB row, a parsed
/// config file, whatever `put` is saving the caller from redoing.
fn expensiveLookup(gpa: std.mem.Allocator, id: []const u8) ![]u8 {
    return std.fmt.allocPrint(gpa, "config-blob-for-{s}", .{id});
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var cache = ramcache.Cache.init(gpa, .{
        .max_bytes = 4096,
        .max_entries = 64,
        .default_ttl_ns = 60 * std.time.ns_per_s,
    });
    defer cache.deinit();

    var gen: u64 = 1;
    const now: i64 = 1_700_000_000_000_000_000;

    // First lookup for "req-42": miss, populate from the slow path.
    if (cache.get("req-42", now, gen) == null) {
        const blob = try expensiveLookup(gpa, "req-42");
        defer gpa.free(blob); // put dupes the bytes into its own storage
        cache.put("req-42", blob, now, cache.options.default_ttl_ns, gen);
    }

    // Second lookup: a hit. The returned slice borrows cache storage — valid
    // only until this key is next replaced/evicted/cleared, so we print it
    // immediately rather than holding onto it.
    if (cache.get("req-42", now, gen)) |v| {
        std.debug.print("hit: {s}\n", .{v});
    } else {
        @panic("expected a hit on the second lookup");
    }

    // A caller that needs to hold the bytes across other cache operations
    // uses `pin` instead of `get`+copy: the entry is exempt from eviction
    // while borrowed, and `release` re-files it.
    if (cache.pin("req-42", now, gen)) |borrow| {
        std.debug.print("pinned: {s} (pinned entries now={d})\n", .{ borrow.bytes, cache.stats.pinned });
        // Mutating other keys while "req-42" is borrowed is safe — it cannot
        // be chosen as an eviction victim.
        cache.put("req-99", "other-blob", now, 0, gen);
        cache.release(borrow);
    } else {
        @panic("expected pin to find the entry it was just given");
    }

    // Generation bump: every gen-tied entry (gen != 0) is now stale, dropped
    // lazily on next `get`. TTL-only entries (gen == 0, like "req-99" above)
    // are unaffected.
    gen += 1;
    if (cache.get("req-42", now, gen) != null) @panic("generation bump should have invalidated req-42");
    if (cache.get("req-99", now, gen) == null) @panic("gen-0 entry must survive a generation bump");

    // Write-behind seam: put() always marks an entry dirty; a coordinator
    // acks with markClean once persisted. isDirty/markClean answer false for
    // an absent key rather than erroring — no error set to name here, since
    // this module is designed so a cache miss/OOM is never fatal (put
    // silently no-ops on OOM instead of returning an error).
    std.debug.print("req-99 dirty={} markClean={}\n", .{
        cache.isDirty("req-99"),
        cache.markClean("req-99"),
    });
    std.debug.print("req-99 dirty after markClean={}\n", .{cache.isDirty("req-99")});

    std.debug.print("stats: hits={d} misses={d} entries={d}\n", .{
        cache.stats.hits,
        cache.stats.misses,
        cache.stats.entries,
    });
}
