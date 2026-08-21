// SPDX-License-Identifier: MIT

//! What a multi-core write-path consumer does with `shardstore`: open a
//! sharded store, route puts/gets across shards by key, and confirm the
//! shard-count identity guard refuses a reopen with a different `n_shards`
//! instead of silently reading half the keys back as absent.
//!
//! Uses the module's own `SimStorage` (an in-memory backend, re-exported so
//! a caller never has to import `kvtree` directly) rather than real files —
//! this example cares about the routing/identity contract, not disk I/O.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to open/route the store is not public, or an error cannot be named
//! from outside, this file stops compiling.

const std = @import("std");
const shardstore = @import("shardstore");

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var sim = shardstore.SimStorage.init(gpa);
    defer sim.deinit();
    // kvtree is a COW page store: its meta slots overwrite in place, which
    // SimStorage's default append-only tripwire would otherwise flag.
    sim.allow_overwrite = true;

    var store = try shardstore.Store.init(gpa, sim.storage(), .{ .n_shards = 4 });

    // Put a spread of session keys; shardFor shows which shard each landed
    // on, so a caller can partition dedicated writer threads per shard.
    var kbuf: [32]u8 = undefined;
    var vbuf: [32]u8 = undefined;
    for (0..40) |n| {
        const k = try std.fmt.bufPrint(&kbuf, "session-{d}", .{n});
        const v = try std.fmt.bufPrint(&vbuf, "user-{d}", .{n});
        try store.put(k, v);
    }
    const sample_key = "session-7";
    std.debug.print("{s} routes to shard {d} of {d}\n", .{ sample_key, store.shardFor(sample_key), store.n_shards });

    const got = try store.get(gpa, sample_key);
    defer if (got) |g| gpa.free(g);
    std.debug.print("get({s}) = {s}\n", .{ sample_key, got.? });

    try store.delete(sample_key);
    const gone = try store.get(gpa, sample_key);
    defer if (gone) |g| gpa.free(g);
    std.debug.print("after delete, present={}\n", .{gone != null});

    store.deinit();

    // Reopening with a DIFFERENT shard count is refused by name: routing is
    // hash % n_shards, so silently accepting it would read most keys back as
    // absent (the module's manifest guard exists precisely for this).
    _ = shardstore.Store.init(gpa, sim.storage(), .{ .n_shards = 8 }) catch |err| switch (err) {
        error.ShardCountMismatch => std.debug.print("reopen with a different n_shards was correctly refused\n", .{}),
        else => return err,
    };

    // The original count still opens and the surviving data is intact.
    var reopened = try shardstore.Store.init(gpa, sim.storage(), .{ .n_shards = 4 });
    defer reopened.deinit();
    const survivor = try reopened.get(gpa, "session-3");
    defer if (survivor) |g| gpa.free(g);
    std.debug.print("session-3 survived reopen: {s}\n", .{survivor.?});
}
