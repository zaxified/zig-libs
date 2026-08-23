// SPDX-License-Identifier: MIT

//! What an address-lookup service does with `geoindex`: build a spatial
//! index from a batch of `(lat, lon, record id)` points, freeze it to a
//! flat byte buffer (the thing that would actually get mmap'd read-only in
//! production), then answer a bounding-box query and a nearest-neighbour
//! query against the frozen buffer with no further allocation.

const std = @import("std");
const geoindex = @import("geoindex");

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // A caller builds incrementally (a record scan, not a fixed slice), then
    // freezes once. `record id` is any u32 the caller chose to carry in the
    // value slot — here just a small enum-ish code.
    var builder = geoindex.Builder.init(gpa);
    defer builder.deinit();

    const City = struct { lat: f64, lon: f64, id: u32 };
    const cities = [_]City{
        .{ .lat = 50.0755, .lon = 14.4378, .id = 1 }, // Praha
        .{ .lat = 49.1951, .lon = 16.6068, .id = 2 }, // Brno
        .{ .lat = 49.7384, .lon = 13.3736, .id = 3 }, // Plzeň
        .{ .lat = 49.5938, .lon = 17.2509, .id = 4 }, // Olomouc
        .{ .lat = 50.6607, .lon = 15.6348, .id = 5 }, // Liberec
    };
    for (cities) |c| try builder.add(c.lat, c.lon, c.id);

    // A build-time reject: latitude is out of range. The error has to be
    // nameable so an ingest pipeline can quarantine the bad record instead
    // of aborting the whole batch.
    if (builder.add(120.0, 14.0, 999)) |_| {
        return error.OutOfRangeLatitudeUnexpectedlyAccepted;
    } else |err| switch (err) {
        error.OutOfRange => std.debug.print("add(lat=120): OutOfRange (expected)\n", .{}),
        else => return err,
    }

    const buf = try builder.freeze(gpa);
    defer gpa.free(buf);
    std.debug.print("frozen index: {d} bytes for {d} points\n", .{ buf.len, builder.count() });

    // Production shape: load a read-only slice (an mmap in a real service),
    // zero-copy, no per-query allocation for `bbox`.
    const frozen = try geoindex.Frozen.load(buf);
    std.debug.print("item count: {d}\n", .{frozen.itemCount()});

    // Central Bohemia bbox: catches Praha + Plzeň, not Brno/Olomouc/Liberec.
    var bbox_out: [8]geoindex.Match = undefined;
    const bbox_result = try frozen.bbox(49.5, 50.5, 13.0, 15.0, &bbox_out, .{});
    std.debug.print("bbox status={s} matches:\n", .{@tagName(bbox_result.status)});
    for (bbox_result.items) |m| std.debug.print("  id={d} lat={d:.4} lon={d:.4}\n", .{ m.value, m.lat, m.lon });

    // Nearest 2 cities to a point close to Brno. `knnScratchLen` sizes the
    // scratch heap the caller owns; `Frozen` never allocates internally.
    const k = 2;
    var knn_out: [k]geoindex.Neighbor = undefined;
    const scratch_len = geoindex.knnScratchLen(k, geoindex.default_fanout, frozen.itemCount());
    const scratch = try gpa.alloc(geoindex.HeapEntry, scratch_len);
    defer gpa.free(scratch);
    const knn_result = try frozen.knn(49.2, 16.6, k, &knn_out, scratch, .{});
    std.debug.print("knn status={s} nearest {d}:\n", .{ @tagName(knn_result.status), k });
    for (knn_result.items) |n| std.debug.print("  id={d} dist2={d:.6}\n", .{ n.value, n.dist2 });
}
