// SPDX-License-Identifier: MIT

//! What a consumer bounding a kvtree store's RAM sits between the pager and
//! its backing storage with `pagecache`: wrap a `Storage` in a `PageCache`,
//! hand `PageCache.storage()` to `kvtree.Db.open` instead of the raw
//! backend, and use the store exactly as if the cache were not there — put,
//! get, and watch hits/misses accumulate. `SimStorage` (kvtree's own
//! deterministic in-memory backend) stands in for a real file so this
//! example needs no disk.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling. The module's own tests cannot notice
//! either, because they live inside it.

const std = @import("std");
const pagecache = @import("pagecache");
const kvtree = @import("kvtree");

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var sim = kvtree.SimStorage.init(gpa);
    defer sim.deinit();

    var cache = pagecache.PageCache.init(gpa, sim.storage(), .{ .max_pages = 8 });
    defer cache.deinit();

    // The store is opened over the CACHE's Storage vtable, not the raw
    // SimStorage -- every page read/write kvtree issues now flows through
    // pagecache's bounded, write-through layer.
    var db = try kvtree.Db.open(gpa, cache.storage(), "orders", .{});
    defer db.close();

    try db.put("order:1001", "shipped");
    try db.put("order:1002", "pending");

    const first = try db.get(gpa, "order:1001") orelse return error.MissingKey;
    defer gpa.free(first);
    std.debug.print("order:1001 = {s}\n", .{first});

    // Re-reading the same key a second time should hit the cache rather
    // than fall through to the inner Storage.
    const again = try db.get(gpa, "order:1001") orelse return error.MissingKey;
    defer gpa.free(again);

    const s = cache.stats();
    std.debug.print("cache stats: hits={d} misses={d} resident_pages={d}\n", .{ s.hits, s.misses, s.resident_pages });
    std.debug.assert(s.hits > 0);

    // A second exclusive opener over the same store is refused by name --
    // kvtree's whole correctness case rests on being the sole writer of its
    // COW meta pages, and the cache does not change that contract.
    var second = kvtree.Db.open(gpa, cache.storage(), "orders", .{}) catch |err| switch (err) {
        error.Locked => {
            std.debug.print("second exclusive opener correctly rejected\n", .{});
            return;
        },
        else => return err,
    };
    second.close();
    return error.ExpectedLocked;
}
