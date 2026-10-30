// SPDX-License-Identifier: MIT
//! No-panic sweep tests (wave GN). Every test name ends with its finding ID.
const std = @import("std");
const kvtree = @import("kvtree");
const tsdb = @import("root.zig");
const codec = tsdb.codec;
const chunk = tsdb.chunk;
const testing = std.testing;
const Allocator = std.mem.Allocator;

const Fixture = struct {
    sim: *kvtree.SimStorage,
    tree: *kvtree.Db,
    db: tsdb.Db,
    gpa: Allocator,

    fn init(gpa: Allocator) !Fixture {
        const sim = try gpa.create(kvtree.SimStorage);
        sim.* = kvtree.SimStorage.init(gpa);
        sim.allow_overwrite = true;
        const tree = try gpa.create(kvtree.Db);
        tree.* = try kvtree.Db.open(gpa, sim.storage(), "series.kvt", .{});
        return .{ .sim = sim, .tree = tree, .db = tsdb.Db.init(gpa, tree), .gpa = gpa };
    }

    fn deinit(self: *Fixture) void {
        self.db.deinit();
        self.tree.close();
        self.gpa.destroy(self.tree);
        self.sim.deinit();
        self.gpa.destroy(self.sim);
    }

    fn setCounter(self: *Fixture, v: u64) !void {
        var b: [8]u8 = undefined;
        std.mem.writeInt(u64, &b, v, .big);
        try self.tree.put(&codec.meta_key_next_series, &b);
    }
};

fn all(gpa: Allocator, db: *tsdb.Db, series: tsdb.SeriesId) ![]tsdb.Sample {
    var out: std.ArrayList(tsdb.Sample) = .empty;
    errdefer out.deinit(gpa);
    var r = try db.range(series, std.math.minInt(i64), std.math.maxInt(i64));
    defer r.deinit();
    while (try r.next()) |s| try out.append(gpa, s);
    return out.toOwnedSlice(gpa);
}

test "a series counter at maxInt on disk is CorruptIndex, not an overflow (sweep TS-1)" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();
    try fx.setCounter(std.math.maxInt(u64));
    try testing.expectError(error.CorruptIndex, fx.db.seriesId("a", &.{}));
}

test "a batch that needs more ids than the stored counter has left is CorruptIndex (sweep TS-1)" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();
    // the batch needs two ids, only one is left below the wrap.
    try fx.setCounter(std.math.maxInt(u64) - 1);
    var out: [2]tsdb.SeriesId = undefined;
    try testing.expectError(error.CorruptIndex, fx.db.seriesIds(&.{
        .{ .name = "x", .labels = &.{} },
        .{ .name = "y", .labels = &.{} },
    }, &out));
    // nothing was registered by the refused batch
    try testing.expect((try fx.db.lookupSeries("x", &.{})) == null);
}

test "a stored series with id 0 resolves in a batch with new ones (sweep TS-2)" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();
    try fx.setCounter(0); // a rotted counter hands out id 0
    const zero = try fx.db.seriesId("a", &.{});
    try testing.expectEqual(@as(tsdb.SeriesId, 0), zero);
    var out: [2]tsdb.SeriesId = undefined;
    try fx.db.seriesIds(&.{
        .{ .name = "a", .labels = &.{} },
        .{ .name = "b", .labels = &.{} },
    }, &out);
    try testing.expectEqual(@as(tsdb.SeriesId, 0), out[0]);
    try testing.expect(out[1] != 0);
}

test "sweepToBudget with chunk_deletes = 0 finishes (sweep TS-3)" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();
    const s = try fx.db.seriesId("m", &.{});
    for (0..50) |i| try fx.db.append(s, @intCast(i), 1);
    const before = try fx.db.liveSize();
    const r = try fx.db.sweepToBudget(before / 2, .{ .chunk_deletes = 0 });
    try testing.expect(r.done);
    try testing.expect(r.deleted > 0);
    try testing.expectEqual(try fx.db.liveSize(), r.after);
}

test "compact: zero chunk options read as the default (sweep TS-4)" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();
    const s = try fx.db.seriesId("m", &.{});
    for (0..200) |i| try fx.db.append(s, @intCast(i), 1);
    const c = try fx.db.compact(std.math.maxInt(i64), .{ .min_run = 1, .chunk_points = 0, .chunk_examines = 0 });
    try testing.expect(c.done);
    try testing.expectEqual(@as(usize, 200), c.compacted);
    const got = try all(testing.allocator, &fx.db, s);
    defer testing.allocator.free(got);
    try testing.expectEqual(@as(usize, 200), got.len);
}

test "deleteSeries: chunk_deletes = 0 reads as the default (sweep TS-4)" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();
    const s = try fx.db.seriesId("m", &.{});
    for (0..200) |i| try fx.db.append(s, @intCast(i), 1);
    const d = try fx.db.deleteSeries(s, .{ .chunk_deletes = 0 });
    try testing.expect(d.existed);
    try testing.expectEqual(@as(usize, 200), d.deleted);
}

test "an empty block writer has a defined first and last timestamp (sweep TS-4)" {
    const w = chunk.Writer.init();
    try testing.expectEqual(@as(i64, 0), w.firstTs());
    try testing.expectEqual(@as(i64, 0), w.lastTs());
}

/// `n_series` series of 300 constant samples (ts 0..299), compacted into one
/// block each: a cutoff of 100 straddles every block and keeps 200 samples.
fn straddlingStore(fx: *Fixture, n_series: usize) !void {
    var name: [8]u8 = undefined;
    for (0..n_series) |k| {
        const nm = try std.fmt.bufPrint(&name, "s{d}", .{k});
        const s = try fx.db.seriesId(nm, &.{});
        for (0..300) |i| try fx.db.append(s, @intCast(i), 1);
    }
    // one chunk, so a series' run is not cut in two blocks at a chunk edge
    const c = try fx.db.compact(std.math.maxInt(i64), .{ .min_run = 1, .chunk_points = 1 << 20, .chunk_examines = 1 << 20 });
    try testing.expectEqual(n_series, c.blocks_written);
}

test "a retention chunk stops once the straddling suffixes it holds reach chunk_deletes (sweep TS-6)" {
    const gpa = testing.allocator;
    var fx = try Fixture.init(gpa);
    defer fx.deinit();
    try straddlingStore(&fx, 50); // 50 x 200 kept = 10000 samples
    const r = try fx.db.sweep(100, .{ .chunk_deletes = 1000 });
    try testing.expect(r.done);
    try testing.expectEqual(@as(usize, 50 * 100), r.deleted);
    // A chunk holds < chunk_deletes + one block's worth (200 here) of kept
    // samples, so 10000 of them need at least 10000 / 1200 chunks. One chunk
    // (the old behaviour) held all of them.
    try testing.expect(r.chunks >= 8);
}

test "chunk_deletes = 1 over many straddling blocks converges on the one-shot end state (progress/equivalence guard, sweep TS-6)" {
    const gpa = testing.allocator;
    var one = try Fixture.init(gpa);
    defer one.deinit();
    var tiny = try Fixture.init(gpa);
    defer tiny.deinit();
    try straddlingStore(&one, 20);
    try straddlingStore(&tiny, 20);
    const r1 = try one.db.sweep(100, .{});
    try testing.expect(r1.done);
    try testing.expectEqual(@as(usize, 1), r1.chunks);
    const r2 = try tiny.db.sweep(100, .{ .chunk_deletes = 1 });
    try testing.expect(r2.done);
    try testing.expectEqual(r1.deleted, r2.deleted);
    try testing.expect(r2.chunks >= 20);
    for (1..21) |id| {
        const a = try all(gpa, &one.db, id);
        defer gpa.free(a);
        const b = try all(gpa, &tiny.db, id);
        defer gpa.free(b);
        try testing.expectEqual(@as(usize, 200), a.len);
        try testing.expectEqualSlices(tsdb.Sample, a, b);
    }
    try testing.expectEqual(try one.db.liveSize(), try tiny.db.liveSize());
}

test "a canonical form over the cap is refused before it is built (sweep TS-7)" {
    // 1000 labels: the sorted scratch copy takes ~48000 bytes of the 56000
    // available, the form (10000 bytes if built whole) cannot also fit.
    var names: [1000][5]u8 = undefined;
    var labels: [1000]codec.Label = undefined;
    for (&names, &labels, 0..) |*n, *l, i| {
        _ = std.fmt.bufPrint(n, "n{d:0>4}", .{i}) catch unreachable;
        l.* = .{ .name = n, .value = "v" };
    }
    var buf: [56000]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const gpa = fba.allocator();
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try testing.expectError(error.SeriesTooLong, codec.canonicalize(gpa, &out, "m", &labels));
}

test "a stored descriptor claiming 65535 labels in a few bytes is Malformed without a 2 MiB allocation (sweep TS-7)" {
    var buf: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    try testing.expectError(error.Malformed, codec.parseCanonical(fba.allocator(), &.{ 0, 0, 0xff, 0xff }));
}

test "chunk size options of 0 mean the default, not one commit per key (sweep D10)" {
    const gpa = testing.allocator;
    var fx = try Fixture.init(gpa);
    defer fx.deinit();
    const s = try fx.db.seriesId("m", &.{});
    for (0..300) |i| try fx.db.append(s, @intCast(i), 1);
    const r = try fx.db.sweep(150, .{ .chunk_deletes = 0, .chunk_examines = 0 });
    try testing.expect(r.done);
    try testing.expectEqual(@as(usize, 150), r.deleted);
    try testing.expectEqual(@as(usize, 1), r.chunks); // old: one chunk per key

    const c = try fx.db.compact(std.math.maxInt(i64), .{ .min_run = 1, .chunk_points = 0, .chunk_examines = 0 });
    try testing.expect(c.done);
    try testing.expectEqual(@as(usize, 150), c.compacted);
    try testing.expect(c.chunks <= 2); // old: >= 150

    const d = try fx.db.deleteSeries(s, .{ .chunk_deletes = 0 });
    try testing.expectEqual(@as(usize, 150), d.deleted);
    try testing.expect(d.chunks <= 2);
}

test "a label list that cannot fit the cap is refused before any allocation (sweep D11)" {
    const labels = try testing.allocator.alloc(codec.Label, 65535);
    defer testing.allocator.free(labels);
    @memset(labels, .{ .name = "n", .value = "v" });
    var out: std.ArrayList(u8) = .empty;
    // The failing allocator turns any allocation (the sorted scratch copy)
    // into OutOfMemory: SeriesTooLong proves none was tried.
    try testing.expectError(error.SeriesTooLong, codec.canonicalize(testing.failing_allocator, &out, "m", labels));
    // a list that does fit is still accepted
    var ok: std.ArrayList(u8) = .empty;
    defer ok.deinit(testing.allocator);
    var names: [100][4]u8 = undefined;
    for (&names, labels[0..100], 0..) |*n, *l, i| {
        _ = std.fmt.bufPrint(n, "n{d:0>3}", .{i}) catch unreachable;
        l.* = .{ .name = n, .value = "v" };
    }
    try codec.canonicalize(testing.allocator, &ok, "m", labels[0..100]);
}

test "max_series: own commits keep the series count valid, a foreign commit forces one recount (sweep D12)" {
    const gpa = testing.allocator;
    var fx = try Fixture.init(gpa);
    defer fx.deinit();
    fx.db.opts.max_series = 1000;
    var name: [8]u8 = undefined;
    var first: tsdb.SeriesId = 0;
    for (0..200) |k| {
        const nm = try std.fmt.bufPrint(&name, "s{d}", .{k});
        const id = try fx.db.seriesId(nm, &.{});
        if (k == 0) first = id;
        try fx.db.append(id, 1, 1); // a commit between two registrations
        try fx.db.appendMany(id, &.{.{ .ts = 2, .value = 2 }});
    }
    // old: one rescan of the reverse index per new series (200)
    try testing.expectEqual(@as(usize, 1), fx.db.series_recounts);

    // the count stays exact across a delete and a batch registration
    _ = try fx.db.deleteSeries(first, .{});
    const specs = [_]tsdb.Db.SeriesSpec{ .{ .name = "x1", .labels = &.{} }, .{ .name = "x2", .labels = &.{} } };
    var ids: [2]tsdb.SeriesId = undefined;
    try fx.db.seriesIds(&specs, &ids);
    try testing.expectEqual(@as(usize, 1), fx.db.series_recounts);
    fx.db.opts.max_series = 201; // 199 + 2 = 201 registered
    try testing.expectError(error.TooManySeries, fx.db.seriesId("one-more", &.{}));
    try testing.expectEqual(@as(usize, 1), fx.db.series_recounts);

    // a second handle registers a series: the first one must see it
    var other = tsdb.Db.initOptions(gpa, fx.tree, .{ .max_series = 1000 });
    defer other.deinit();
    _ = try other.seriesId("foreign", &.{});
    fx.db.opts.max_series = 202; // exactly full with the foreign series
    try testing.expectError(error.TooManySeries, fx.db.seriesId("another", &.{}));
    try testing.expectEqual(@as(usize, 2), fx.db.series_recounts);
}

test "deleteSeries removes a block whose header does not decode (sweep D13)" {
    const gpa = testing.allocator;
    var fx = try Fixture.init(gpa);
    defer fx.deinit();
    const s = try fx.db.seriesId("m", &.{});
    for (0..100) |i| try fx.db.append(s, @intCast(i), 1);
    _ = try fx.db.compact(std.math.maxInt(i64), .{ .min_run = 1 });
    // Rot the block's value: a header that does not decode.
    var cur = try fx.tree.cursor();
    var bkey: [codec.block_key_len]u8 = undefined;
    try cur.seek(&[_]u8{codec.tag_block});
    const e = (try cur.next()).?;
    @memcpy(&bkey, e.key[0..codec.block_key_len]);
    cur.deinit();
    try fx.tree.put(&bkey, &[_]u8{ 0xff, 0xff });
    const d = try fx.db.deleteSeries(s, .{});
    try testing.expect(d.existed);
    try testing.expectEqual(@as(usize, 0), d.deleted); // not countable
    try testing.expectEqual(@as(?tsdb.SeriesId, null), try fx.db.lookupSeries("m", &.{}));
    var c2 = try fx.tree.cursor();
    defer c2.deinit();
    try c2.seek(&[_]u8{codec.tag_block});
    const left = try c2.next();
    try testing.expect(left == null or left.?.key[0] != codec.tag_block);
}
