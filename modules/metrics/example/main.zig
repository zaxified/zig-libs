// SPDX-License-Identifier: MIT

//! What a consumer does with `metrics` without ever standing up an HTTP
//! server: register the three instrument kinds, drive them the way request
//! handling would, and render the registry to Prometheus text exposition
//! format straight into an in-memory buffer — `Registry.writeText` takes any
//! `std.Io.Writer`, so a batch job that ships metrics over something other
//! than `GET /metrics` (a push-gateway POST body, a log line) still gets the
//! module's exposition logic for free.
//!
//! Built against the PUBLISHED module (`@import("metrics")`) only. `router`
//! and `http` are declared deps (the request middleware needs them) but this
//! example never wires up a server — the registry and the instruments work
//! standalone.

const std = @import("std");
const metrics = @import("metrics");

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();

    // get-or-register: the same (name, label values) always returns the
    // same instrument pointer, so a handler calls this on every request with
    // no separate "did I already register this" bookkeeping.
    const requests = try registry.counter(
        "orders_total",
        "Total orders processed, by outcome.",
        &.{.{ .name = "outcome", .value = "accepted" }},
    );
    const rejected = try registry.counter(
        "orders_total",
        "Total orders processed, by outcome.",
        &.{.{ .name = "outcome", .value = "rejected" }},
    );
    const queue_depth = try registry.gauge("order_queue_depth", "Orders waiting to be processed.", &.{});
    const latency = try registry.histogram(
        "order_processing_seconds",
        "Time to process one order.",
        &.{},
        &metrics.default_buckets,
    );

    // A handful of simulated orders.
    const sample_latencies_s = [_]f64{ 0.003, 0.02, 0.08, 0.4, 0.02 };
    queue_depth.set(@floatFromInt(sample_latencies_s.len));
    for (sample_latencies_s, 0..) |s, i| {
        latency.observe(s);
        if (i == 2) {
            rejected.inc(); // one order failed validation
        } else {
            requests.inc();
        }
        queue_depth.dec();
    }

    std.debug.print("accepted={d} rejected={d} queue_depth={d:.0}\n", .{
        requests.value(), rejected.value(), queue_depth.value(),
    });

    // Render straight into a fixed buffer -- no socket, no `http` server --
    // proving `writeText` only needs a `std.Io.Writer`.
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try registry.writeText(&w);
    std.debug.print("\n--- Prometheus exposition ---\n{s}", .{w.buffered()});
}
