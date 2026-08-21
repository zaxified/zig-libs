// SPDX-License-Identifier: MIT

//! What a consumer building a custom `Sink` adapter (their own SQL table, a
//! remote KV) checks BEFORE wiring it into a `Coordinator`: that it honors
//! the `Sink` vtable contract `writebehind` flushes through. `MapSink` is the
//! module's own in-memory reference sink — exercised here directly, the way
//! a consumer would exercise their own adapter in a unit test.
//!
//! This example also assembles a complete `Options` — including a `SimStorage`
//! WAL backend, which needs no real file (unlike `FsStorage`) — to show that
//! wiring a `Coordinator`'s configuration is entirely reachable through public
//! types.
//!
//! It deliberately stops there and never calls `Coordinator.init`. See the
//! note at the bottom of this file for why.
//!
//! Built against the PUBLISHED module (`@import("writebehind")`) only.

const std = @import("std");
const writebehind = @import("writebehind");

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    // ── exercise a Sink adapter through the vtable the coordinator uses ─────
    var map_sink = writebehind.MapSink.init(gpa);
    defer map_sink.deinit();
    const sink = map_sink.sink();

    try sink.write("order:42", "shipped");
    try sink.write("order:43", "pending");
    try sink.delete("order:43");

    const readback = (try sink.read(gpa, "order:42")) orelse return error.MissingKey;
    defer gpa.free(readback);
    std.debug.print("sink readback: order:42 = {s}\n", .{readback});
    std.debug.print("sink readback: order:43 = {?s} (deleted)\n", .{try sink.read(gpa, "order:43")});
    std.debug.print("map_sink entry count: {d}\n", .{map_sink.count()});

    // ── assemble a full Coordinator configuration ───────────────────────────
    // `SimStorage` is the deterministic, in-memory WAL backend `jobqueue`
    // (via `kv`) ships for exactly this purpose — no real file needed to
    // build (or in a real test, run) the durable-log half of the pipeline.
    var wal_sim = writebehind.SimStorage.init(gpa);
    defer wal_sim.deinit();

    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const options: writebehind.Options = .{
        .io = io,
        .sink = sink,
        .wal_store = wal_sim.storage(),
        .wal_path = "wal",
        .max_cache_bytes = 1 << 20,
        .max_cache_entries = 4096,
        .n_workers = 1,
    };
    std.debug.print(
        "coordinator options assembled: wal_path={s} max_cache_entries={d} n_workers={?d}\n",
        .{ options.wal_path, options.max_cache_entries, options.n_workers },
    );

    // `writebehind.Coordinator.init(gpa, options)` is NOT called here.
    // Unconditionally, it does:
    //     self.pool = try workerpool.WorkerPool.init(gpa, .{ .io = options.io, ... });
    // and `WorkerPool.init` floors `n_workers` at 1 and calls
    // `std.Thread.spawn` for each one before it returns — there is no
    // synchronous/inline dispatch mode. So although the WAL storage (`SimStorage`)
    // and the sink (`MapSink`) both have genuine in-memory seams, the
    // Coordinator itself has none: constructing one always spawns a live OS
    // thread, which is out of scope for this example (see the task's I/O
    // rule) and is the one place in this module's public API a consumer
    // cannot reach without real concurrency.
}
