// SPDX-License-Identifier: MIT

//! What a caller of `kvtree` does: open an ordered store over an in-memory
//! backend, commit a multi-key transaction atomically, take a snapshot for
//! a stable read view, then keep writing while the snapshot is still open
//! — the store must serve both the old and the new version.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only,
//! no `test_deps`, no access to anything the module does not export). If a
//! type needed to call the API is not public, or an error cannot be named
//! from outside, this file stops compiling. The module's own tests cannot
//! notice either, because they live inside it.

const std = @import("std");
const kvtree = @import("kvtree");

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // `SimStorage` is kvtree's re-export of `kv`'s deterministic in-memory
    // backend — a caller never has to import `kv` directly to get one.
    var sim = kvtree.SimStorage.init(gpa);
    defer sim.deinit();

    var db = try kvtree.Db.open(gpa, sim.storage(), "routing-table.kvt", .{});
    defer db.close();

    // A second opener over the same store is refused rather than allowed
    // to race this one's COW commits.
    if (kvtree.Db.open(gpa, sim.storage(), "routing-table.kvt", .{})) |_| {
        return error.ShouldHaveBeenLocked;
    } else |err| switch (err) {
        error.Locked => std.debug.print("second opener correctly refused: store is locked\n", .{}),
        else => return err,
    }

    // Seed three routes in one atomic transaction.
    {
        var txn = try db.begin();
        errdefer txn.rollback();
        try txn.put("route/10.0.0.0/8", "nexthop=eth0");
        try txn.put("route/172.16.0.0/12", "nexthop=eth1");
        try txn.put("route/192.168.0.0/16", "nexthop=eth2");
        try txn.commit();
    }

    // Pin a snapshot before the next write — its view must stay frozen even
    // as the writer commits a newer version underneath it.
    var snap = try db.snapshot();

    // Withdraw a route and add a replacement after the snapshot was taken.
    try db.del("route/172.16.0.0/12");
    try db.put("route/172.16.0.0/12", "nexthop=eth3");

    // The live db sees the update...
    const live = try db.get(gpa, "route/172.16.0.0/12");
    defer if (live) |v| gpa.free(v);
    std.debug.print("live view: 172.16.0.0/12 -> {s}\n", .{live.?});

    // ...but the pinned snapshot still sees the version it opened against.
    const snapped = try snap.get(gpa, "route/172.16.0.0/12");
    defer if (snapped) |v| gpa.free(v);
    std.debug.print("snapshot view: 172.16.0.0/12 -> {s}\n", .{snapped.?});
    snap.release();

    // Ordered range scan over the current (post-update) tree.
    var cur = try db.cursor();
    defer cur.deinit();
    try cur.first();
    std.debug.print("routing table, key order:\n", .{});
    while (try cur.next()) |entry| {
        std.debug.print("  {s} = {s}\n", .{ entry.key, entry.val });
    }

    // A lookup for an absent key comes back null, not an error.
    const missing = try db.get(gpa, "route/absent");
    std.debug.print("absent key: {}\n", .{missing == null});
}
