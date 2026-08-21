// SPDX-License-Identifier: MIT

//! What a service front-ending Postgres does with `readthrough`: wrap a
//! lookup-by-id fetch in a `Cache`, so a hot key is served without hitting
//! the database and a miss loads through exactly once, then flows into the
//! cache and into the caller's return in one step. Also exercises the
//! negative-caching path (a "not found" row) and explicit invalidation
//! (the row changed upstream), both real operational events, not just the
//! happy path.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling. The module's own tests cannot notice
//! either, because they live inside it.

const std = @import("std");
const readthrough = @import("readthrough");

/// A tiny stand-in "users" table plus a call counter, so the example can
/// show the cache actually suppresses repeat backend fetches. `down_key`
/// simulates one row whose backend fetch fails (a transient DB error), so
/// the example can also exercise the loader-error path.
const FakeUsersTable = struct {
    rows: std.StringHashMapUnmanaged([]const u8) = .empty,
    fetches: usize = 0,
    down_key: ?[]const u8 = null,

    fn load(ctx: ?*anyopaque, key: []const u8) anyerror!readthrough.LoadOutcome {
        const self: *FakeUsersTable = @ptrCast(@alignCast(ctx.?));
        self.fetches += 1;
        if (self.down_key) |dk| {
            if (std.mem.eql(u8, dk, key)) return error.BackendUnavailable;
        }
        if (self.rows.get(key)) |v| return .{ .value = v };
        return .missing; // no such user id
    }

    fn loader(self: *FakeUsersTable) readthrough.Loader {
        return .{ .ctx = self, .load = load };
    }
};

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();

    var table: FakeUsersTable = .{};
    try table.rows.put(gpa, "user:1", "Ada Lovelace");
    defer table.rows.deinit(gpa);

    var cache = readthrough.Cache.init(gpa, .{
        .io = threaded.io(),
        .loader = table.loader(),
        .ttl_ns = std.time.ns_per_min,
        .negative_ttl_ns = std.time.ns_per_s,
        .max_bytes = 1 << 16,
        .max_entries = 256,
    });
    defer cache.deinit();

    // First read: a miss, so it loads through the fake table.
    const first = try cache.get("user:1");
    defer cache.free(first);
    switch (first) {
        .value => |v| std.debug.print("user:1 (miss->load) = {s}\n", .{v}),
        .missing => unreachable, // the row exists in the table
    }

    // Second read: a fresh hit, no backend call.
    const second = try cache.get("user:1");
    defer cache.free(second);
    std.debug.print("fetches after two gets of the same key: {d}\n", .{table.fetches});

    // A row that does not exist negatively caches, so a repeated lookup for
    // a bad id also does not hammer the backend.
    const missing_outcome = try cache.get("user:999");
    switch (missing_outcome) {
        .missing => std.debug.print("user:999 correctly reported missing\n", .{}),
        .value => return error.UnexpectedValueForAbsentRow,
    }
    _ = try cache.get("user:999"); // served from the negative cache
    std.debug.print("fetches after two lookups of a missing key: {d}\n", .{table.fetches});

    // Upstream update: the caller invalidates the entry explicitly so the
    // next read observes the new value rather than a stale one.
    try table.rows.put(gpa, "user:1", "Ada, Countess of Lovelace");
    cache.invalidate("user:1");
    const refreshed = try cache.get("user:1");
    defer cache.free(refreshed);
    switch (refreshed) {
        .value => |v| std.debug.print("user:1 after invalidate = {s}\n", .{v}),
        .missing => return error.UnexpectedMissingAfterInvalidate,
    }

    const stats = cache.getStats();
    std.debug.print("stats: hits={d} misses={d} loads={d} negative_hits={d} invalidations={d}\n", .{
        stats.hits, stats.misses, stats.loads, stats.negative_hits, stats.invalidations,
    });

    // A second cache, over a backend row that fails, with loader-error
    // caching turned on: the first read surfaces the real backend error by
    // name, and a read within the negative TTL surfaces the module's own
    // `CachedLoaderError` instead of re-hitting the failing backend.
    table.down_key = "user:down";
    var flaky_cache = readthrough.Cache.init(gpa, .{
        .io = threaded.io(),
        .loader = table.loader(),
        .negative_ttl_ns = std.time.ns_per_min,
        .cache_loader_errors = true,
        .max_bytes = 1 << 16,
        .max_entries = 256,
    });
    defer flaky_cache.deinit();

    _ = flaky_cache.get("user:down") catch |err| switch (err) {
        error.BackendUnavailable => std.debug.print("first read: real backend error surfaced\n", .{}),
        else => return err,
    };
    _ = flaky_cache.get("user:down") catch |err| switch (err) {
        error.CachedLoaderError => std.debug.print("second read: served from the negative error cache\n", .{}),
        else => return err,
    };
}
