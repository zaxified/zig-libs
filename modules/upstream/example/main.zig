// SPDX-License-Identifier: MIT

//! What an API gateway does with `upstream`: register a small backend
//! fleet, route calls across it with automatic failover when a backend
//! fails, and read back the pool's health snapshot.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling. The module's own tests cannot notice
//! either, because they live inside it.

const std = @import("std");
const upstream = @import("upstream");

/// The gateway's routed operation: "fetch from this backend". A real
/// implementation would open a connection to `u.address`; this one
/// simulates one backend being down so `call()`'s failover path runs.
const Fetch = struct {
    down_id: []const u8,

    pub fn call(self: *Fetch, u: *upstream.Upstream) error{BackendUnavailable}!u16 {
        if (std.mem.eql(u8, u.id, self.down_id)) return error.BackendUnavailable;
        return 200; // simulated HTTP status
    }
};

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var pool: upstream.Pool = .init(gpa, .{
        .strategy = .round_robin,
        .breaker = .{ .failure_threshold = 5, .cooldown_ms = 30_000 },
    });
    defer pool.deinit();

    _ = try pool.add(.{ .id = "api-1", .address = "10.0.0.1:8080" });
    _ = try pool.add(.{ .id = "api-2", .address = "10.0.0.2:8080", .weight = 2 });

    // A malformed address must fail by a nameable error, not a panic — a
    // gateway loading upstreams from config has to be able to reject one
    // bad line without crashing.
    if (pool.add(.{ .id = "bad", .address = "no-port-here" })) |_| {
        unreachable;
    } else |err| switch (err) {
        error.InvalidHostPort => std.debug.print("rejected malformed address, as expected\n", .{}),
        error.TooManyUpstreams, error.DuplicateId, error.OutOfMemory => return err,
    }

    // "api-1" is down: call() should fail over to "api-2" and still
    // succeed.
    var op: Fetch = .{ .down_id = "api-1" };
    const status = try pool.call(&op, .{ .max_tries = 3 });
    std.debug.print("routed call succeeded with status {d}\n", .{status});

    const stats = pool.upstreamStats(pool.getById("api-1").?);
    std.debug.print("api-1: healthy={} failures={d}\n", .{ stats.healthy, stats.failures });

    // Take every upstream down and confirm the pool-level error is
    // nameable, not just "some error".
    pool.getById("api-1").?.down.store(true, .seq_cst);
    pool.getById("api-2").?.down.store(true, .seq_cst);
    var op2: Fetch = .{ .down_id = "" };
    if (pool.call(&op2, .{ .max_tries = 3 })) |_| {
        unreachable;
    } else |err| switch (err) {
        error.NoHealthyUpstream => std.debug.print("no healthy upstream, as expected\n", .{}),
        error.BackendUnavailable => return err,
    }

    const pool_stats = pool.stats();
    std.debug.print("pool: {d} upstreams, {d} healthy, {d} in-flight\n", .{
        pool_stats.upstreams,
        pool_stats.healthy,
        pool_stats.in_flight,
    });
}
