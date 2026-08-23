// SPDX-License-Identifier: MIT

//! What a metrics-collection service does with `tsdb`: resolve a series by
//! (name, labels), append a batch of samples, stream a `[from, to)` window
//! back out, and expire old data with a retention sweep — all over an
//! in-memory `kvtree.SimStorage` backend so the example needs no real disk.
//! Also shows the named failure a second exclusive opener over the same
//! store gets, since `tsdb` borrows a `kvtree.Db` the caller owns.
//!
//! Built by `zig build check-examples` against the PUBLISHED module — no
//! access to anything `tsdb` (or its declared dep `kvtree`) does not export.

const std = @import("std");
const tsdb = @import("tsdb");
const kvtree = @import("kvtree");

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var sim = tsdb.SimStorage.init(gpa);
    defer sim.deinit();

    // `kv.Storage`'s append-only tripwire assert stays armed by default;
    // kvtree (which tsdb is built on) is a COW page store that legitimately
    // overwrites its double-buffered meta slots and reused freed pages in
    // place, so it MUST opt in here, the same way every one of kvtree's own
    // tests and harnesses do (see `SimStorage.allow_overwrite`'s doc
    // comment).
    sim.allow_overwrite = true;

    // Default (exclusive) locking, even though the backend is in-memory:
    // the lock is what the second-opener check further down actually
    // exercises. `.lock = .none` opts OUT of taking it, which would make
    // that later "second opener is refused" check meaningless -- nothing
    // would be held for it to contend with.
    var tree = try kvtree.Db.open(gpa, sim.storage(), "metrics.kvt", .{});
    defer tree.close();

    var db = tsdb.Db.init(gpa, &tree);
    defer db.deinit();

    const labels = [_]tsdb.Label{
        .{ .name = "host", .value = "edge-07" },
        .{ .name = "region", .value = "eu-west" },
    };
    const series = try db.seriesId("cpu.load1", &labels);
    std.debug.print("series id: {d}\n", .{series});

    // Same (name, labels) resolves to the same id regardless of label order.
    const reordered = [_]tsdb.Label{
        .{ .name = "region", .value = "eu-west" },
        .{ .name = "host", .value = "edge-07" },
    };
    const same_series = try db.seriesId("cpu.load1", &reordered);
    std.debug.print("label-order-independent resolve matches: {}\n", .{series == same_series});

    // Append a batch of samples atomically.
    const points = [_]tsdb.Sample{
        .{ .ts = 1_000, .value = 0.42 },
        .{ .ts = 1_060, .value = 0.55 },
        .{ .ts = 1_120, .value = 0.61 },
        .{ .ts = 1_180, .value = 0.38 },
    };
    try db.appendMany(series, &points);

    // Stream the middle window back out, ordered.
    var range = try db.range(series, 1_050, 1_150);
    defer range.deinit();
    var count: usize = 0;
    while (try range.next()) |s| {
        std.debug.print("  ts={d} value={d:.2}\n", .{ s.ts, s.value });
        count += 1;
    }
    std.debug.print("{d} sample(s) in [1050, 1150)\n", .{count});

    // Expire everything before ts=1100.
    const swept = try db.sweep(1_100, .{});
    std.debug.print("retention sweep: deleted={d} examined={d} chunks={d} done={}\n", .{
        swept.deleted,
        swept.examined,
        swept.chunks,
        swept.done,
    });

    // A second exclusive opener over the SAME store fails by name rather
    // than corrupting the first opener's COW pages — kvtree's whole
    // correctness case rests on being the sole writer.
    if (kvtree.Db.open(gpa, sim.storage(), "metrics.kvt", .{})) |second_const| {
        var second = second_const;
        second.close();
        @panic("unexpected: second exclusive handle was opened over a locked store");
    } else |err| switch (err) {
        error.Locked => std.debug.print("second exclusive open correctly rejected (Locked)\n", .{}),
        else => return err,
    }
}
