// SPDX-License-Identifier: MIT

//! Migration from the previous format (version 1): a writer's `open` of a
//! version-1 log converts it in place, checks it, and reports; damaged data is
//! refused before anything is written; a crash anywhere in between is resumed
//! by the next `open`, and a reader is told to wait.
//!
//! The version-1 logs here are written byte by byte from the format's
//! description (`root.zig`, "the previous format"), not by old code.

const std = @import("std");
const seglog = @import("root.zig");
const Log = seglog.Log;
const SimStorage = seglog.SimStorage;
const CrashMode = seglog.CrashMode;
const testing = std.testing;
const gpa = testing.allocator;

fn crc(b: []const u8) u32 {
    return std.hash.crc.@"CRC-32/ISCSI".hash(b);
}

/// A version-1 segment to write.
pub const Seg = struct {
    id: u64,
    payloads: []const []const u8 = &.{},
    sealed: bool = true,
    /// Bytes after the last record: a torn one (newest segment only).
    tail: []const u8 = "",
    /// No file at all (the format named a segment before creating it).
    missing: bool = false,
};

fn segName(buf: []u8, id: u64) []const u8 {
    return std.mem.print(buf, "seg-{d:0>20}.log", .{id}) catch unreachable;
}

/// Each record's offset in its version-1 segment, for the position tests.
const Offsets = std.ArrayList(struct { seg: u64, off: u64, payload: []const u8 });

pub fn writeV1(sim: *SimStorage, segs: []const Seg, pending: []const u64, offsets: ?*Offsets) !void {
    for (segs) |s| {
        if (s.missing) continue;
        var b: std.ArrayList(u8) = .empty;
        defer b.deinit(gpa);
        try b.appendSlice(gpa, "SGLS");
        try appendInt(&b, u32, 1);
        try appendInt(&b, u64, s.id);
        for (s.payloads) |p| {
            if (offsets) |o| try o.append(gpa, .{ .seg = s.id, .off = b.items.len, .payload = p });
            try appendRecord(&b, 1, p);
        }
        if (s.sealed) {
            var sp: [16]u8 = undefined;
            std.mem.writeInt(u64, sp[0..8], s.payloads.len, .little);
            std.mem.writeInt(u64, sp[8..16], b.items.len, .little);
            try appendRecord(&b, 2, &sp);
        }
        try b.appendSlice(gpa, s.tail);
        var nb: [40]u8 = undefined;
        try sim.installFile(segName(&nb, s.id), b.items);
    }
    var m: std.ArrayList(u8) = .empty;
    defer m.deinit(gpa);
    try m.appendSlice(gpa, "SGLM");
    try appendInt(&m, u32, 1);
    try appendInt(&m, u32, @intCast(segs.len));
    try appendInt(&m, u32, @intCast(pending.len));
    for (segs) |s| try appendInt(&m, u64, s.id);
    for (pending) |id| try appendInt(&m, u64, id);
    try appendInt(&m, u32, crc(m.items));
    try sim.installFile("MANIFEST", m.items);
}

fn appendInt(b: *std.ArrayList(u8), comptime T: type, v: T) !void {
    var x: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &x, v, .little);
    try b.appendSlice(gpa, &x);
}

fn appendRecord(b: *std.ArrayList(u8), typ: u8, p: []const u8) !void {
    const at = b.items.len;
    try appendInt(b, u32, 0);
    try b.append(gpa, typ);
    try appendInt(b, u32, @intCast(p.len));
    try b.appendSlice(gpa, p);
    std.mem.writeInt(u32, b.items[at..][0..4], crc(b.items[at + 4 ..]), .little);
}

/// Payloads start with their time, as egw-hub's do.
pub fn tsOf(p: []const u8) i64 {
    return if (p.len >= 8) std.mem.readInt(i64, p[0..8], .little) else -1;
}

fn stamped(comptime ts: i64, comptime text: []const u8) []const u8 {
    comptime {
        var b: [8 + text.len]u8 = undefined;
        std.mem.writeInt(i64, b[0..8], ts, .little);
        @memcpy(b[8..], text);
        const out = b;
        return &out;
    }
}

const fixture = [_]Seg{
    .{ .id = 10, .payloads = &.{ stamped(100, "a"), stamped(101, "bb"), stamped(102, "ccc") } },
    .{ .id = 11, .payloads = &.{ stamped(200, "d"), stamped(201, "") } },
    .{ .id = 12, .payloads = &.{ stamped(300, "ee"), stamped(301, "fff") }, .sealed = false, .tail = "\x01\x02\x03\x04\x01" },
};
const fixture_payloads = [_][]const u8{ stamped(100, "a"), stamped(101, "bb"), stamped(102, "ccc"), stamped(200, "d"), stamped(201, ""), stamped(300, "ee"), stamped(301, "fff") };

fn openAuto(sim: *SimStorage, report: ?*seglog.MigrationReport) !Log {
    return Log.open(gpa, sim.storage(), .{ .legacy_ts = tsOf, .migration_report = report });
}

/// The migrated log holds exactly the fixture, in order, with LSNs 1… and
/// the stamped times; nothing of the old format is left.
fn expectMigrated(sim: *SimStorage, log: *Log) !void {
    var it = log.iterator(null);
    defer it.deinit();
    for (fixture_payloads, 1..) |p, lsn| {
        const r = (try it.next()) orelse return error.RecordMissing;
        try testing.expectEqualSlices(u8, p, r.payload);
        try testing.expectEqual(@as(u64, lsn), r.lsn);
        try testing.expectEqual(tsOf(p), r.ts);
    }
    try testing.expectEqual(@as(?seglog.Record, null), try it.next());
    var v = try log.verify(gpa);
    defer v.deinit(gpa);
    try testing.expect(v.clean());
    try testing.expectEqualSlices(u64, &.{ 10, 11, 12 }, log.segments());
    try testing.expect(sim.fileContent("MIGRATE.tmp") == null);
    for ([_]u64{ 10, 11, 12 }) |id| {
        var nb: [40]u8 = undefined;
        const f = sim.fileContent(segName(&nb, id)) orelse return error.SegmentMissing;
        try testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, f[4..8], .little));
    }
    try testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, sim.fileContent("MANIFEST").?[4..8], .little));
}

test "migration: a version-1 log opens converted, checked, and reported" {
    var sim = SimStorage.init(gpa);
    defer sim.deinit();
    try writeV1(&sim, &fixture, &.{9}, null);
    try sim.installFile("seg-00000000000000000009.log", "a pending drop");
    var rep: seglog.MigrationReport = .{};
    {
        var log = try openAuto(&sim, &rep);
        defer log.close();
        const m = log.migration().?;
        try testing.expectEqual(@as(u32, 1), m.from_version);
        try testing.expectEqual(@as(u32, 2), m.to_version);
        try testing.expectEqual(@as(u64, 3), m.segments);
        try testing.expectEqual(@as(u64, 7), m.records);
        try testing.expectEqual(@as(u64, 5), m.torn_bytes);
        try testing.expect(m.positions == .translate_from_v1);
        try testing.expect(m.failure == null);
        try testing.expect(m.bytes_after > m.bytes_before); // an LSN and a time per record
        try testing.expectEqual(m.records, rep.records); // the out-parameter too
        try expectMigrated(&sim, &log);
        try testing.expect(sim.fileContent("seg-00000000000000000009.log") == null); // the drop finished
        // The newest segment takes appends, and LSNs go on.
        const a = try log.appendAt(400, "g");
        try testing.expectEqual(@as(u64, 8), a.lsn);
    }
    // Once is enough.
    var log = try openAuto(&sim, null);
    defer log.close();
    try testing.expectEqual(@as(?seglog.MigrationReport, null), log.migration());
    try testing.expectEqual(@as(u64, 9), log.nextLsn());
}

test "migration: every saved version-1 position translates to its record" {
    var sim = SimStorage.init(gpa);
    defer sim.deinit();
    var offs: Offsets = .empty;
    defer offs.deinit(gpa);
    try writeV1(&sim, &fixture, &.{}, &offs);
    var log = try openAuto(&sim, null);
    defer log.close();
    for (offs.items) |o| {
        const p = (try log.translatePosition(.{ .segment = o.seg, .offset = o.off })).?;
        var it = log.iterator(p);
        defer it.deinit();
        try testing.expectEqualSlices(u8, o.payload, (try it.next()).?.payload);
    }
    // The end of a closed segment's data (where its seal was): the seal now.
    const end10: u64 = 16 + 3 * 9 + 8 * 3 + 1 + 2 + 3;
    const p = (try log.translatePosition(.{ .segment = 10, .offset = end10 })).?;
    try testing.expectEqual(@as(u64, 40 + 3 * 25 + 8 * 3 + 1 + 2 + 3), p.offset);
    try testing.expectEqual(@as(?seglog.Position, null), try log.translatePosition(.{ .segment = 10, .offset = 17 }));
}

/// Every file's bytes, to show a refused migration changed nothing.
fn snapshot(sim: *SimStorage, names: []const []const u8) ![][]u8 {
    const out = try gpa.alloc([]u8, names.len);
    for (names, out) |n, *o| o.* = try gpa.dupe(u8, sim.fileContent(n) orelse "");
    return out;
}

fn freeSnapshot(s: [][]u8) void {
    for (s) |x| gpa.free(x);
    gpa.free(s);
}

const all_files = [_][]const u8{ "MANIFEST", "seg-00000000000000000010.log", "seg-00000000000000000011.log", "seg-00000000000000000012.log" };

fn expectRefused(sim: *SimStorage, seg: u64, reason: @FieldType(seglog.MigrationFailure, "reason")) !void {
    const before = try snapshot(sim, &all_files);
    defer freeSnapshot(before);
    var rep: seglog.MigrationReport = .{};
    try testing.expectError(error.MigrationFailed, openAuto(sim, &rep));
    const f = rep.failure.?;
    try testing.expectEqual(seg, f.segment);
    try testing.expectEqual(reason, f.reason);
    const after = try snapshot(sim, &all_files);
    defer freeSnapshot(after);
    for (before, after) |b, a| try testing.expectEqualSlices(u8, b, a);
    try testing.expect(sim.fileContent("MIGRATE.tmp") == null);
}

test "migration: damage refuses it before anything is written" {
    { // a CRC in a closed segment
        var sim = SimStorage.init(gpa);
        defer sim.deinit();
        try writeV1(&sim, &fixture, &.{}, null);
        sim.fileContent("seg-00000000000000000011.log").?[16 + 9 + 3] ^= 0xff;
        try expectRefused(&sim, 11, .bad_record);
    }
    { // a closed segment cut short: its seal is gone
        var sim = SimStorage.init(gpa);
        defer sim.deinit();
        var segs = fixture;
        segs[0].sealed = false;
        try writeV1(&sim, &segs, &.{}, null);
        try expectRefused(&sim, 10, .bad_seal);
    }
    { // a seal that miscounts
        var sim = SimStorage.init(gpa);
        defer sim.deinit();
        try writeV1(&sim, &fixture, &.{}, null);
        const f = sim.fileContent("seg-00000000000000000010.log").?;
        const seal_payload = f.len - 16;
        f[seal_payload] = 9;
        std.mem.writeInt(u32, f[seal_payload - 9 ..][0..4], crc(f[seal_payload - 5 ..]), .little);
        try expectRefused(&sim, 10, .bad_seal);
    }
    { // a closed segment's file missing
        var sim = SimStorage.init(gpa);
        defer sim.deinit();
        var segs = fixture;
        segs[1].missing = true;
        try writeV1(&sim, &segs, &.{}, null);
        try expectRefused(&sim, 11, .bad_header);
    }
    { // a header naming another segment
        var sim = SimStorage.init(gpa);
        defer sim.deinit();
        try writeV1(&sim, &fixture, &.{}, null);
        sim.fileContent("seg-00000000000000000010.log").?[8] = 99;
        try expectRefused(&sim, 10, .bad_header);
    }
}

test "migration: a missing or empty newest segment is an empty one, not damage" {
    for ([_]bool{ true, false }) |missing| {
        var sim = SimStorage.init(gpa);
        defer sim.deinit();
        var segs = fixture;
        segs[2] = .{ .id = 12, .sealed = false, .missing = missing };
        try writeV1(&sim, &segs, &.{}, null);
        var log = try openAuto(&sim, null);
        defer log.close();
        try testing.expectEqual(@as(u64, 5), log.migration().?.records);
        try testing.expectEqual(@as(?u64, 12), log.activeSegment());
        try testing.expectEqual(@as(u64, 6), (try log.append("x")).lsn);
    }
}

test "migration: refused on request; readers wait; the log is left as it was" {
    var sim = SimStorage.init(gpa);
    defer sim.deinit();
    try writeV1(&sim, &fixture, &.{}, null);
    const before = try snapshot(&sim, &all_files);
    defer freeSnapshot(before);
    var rep: seglog.MigrationReport = .{};
    try testing.expectError(error.NeedsMigration, Log.open(gpa, sim.storage(), .{ .migration = .refuse, .migration_report = &rep }));
    try testing.expectEqual(@as(u32, 1), rep.from_version);
    try testing.expectError(error.MigrationInProgress, Log.openReadOnly(gpa, sim.storage(), .{}));
    const after = try snapshot(&sim, &all_files);
    defer freeSnapshot(after);
    for (before, after) |b, a| try testing.expectEqualSlices(u8, b, a);
}

test "migration: progress is reported segment by segment" {
    const Count = struct {
        n: u64 = 0,
        fn on(ctx: ?*anyopaque, p: seglog.MigrationProgress) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.n += 1;
            std.debug.assert(p.done == self.n and p.segments == 3);
        }
    };
    var sim = SimStorage.init(gpa);
    defer sim.deinit();
    try writeV1(&sim, &fixture, &.{}, null);
    var c: Count = .{};
    var log = try Log.open(gpa, sim.storage(), .{ .on_migration_progress = Count.on, .migration_ctx = &c });
    defer log.close();
    try testing.expectEqual(@as(u64, 3), c.n);
}

// ── the crash sweep ─────────────────────────────────────────────────────────

fn migratingOpenOps() !usize {
    var sim = SimStorage.init(gpa);
    defer sim.deinit();
    try writeV1(&sim, &fixture, &.{}, null);
    const before = sim.ops_seen;
    var log = try openAuto(&sim, null);
    log.close();
    return sim.ops_seen - before;
}

/// After a crash at `point`, possibly another inside the recovering `open`
/// at `second`, the log ends up migrated and complete.
fn crashAndRecover(mode: CrashMode, point: usize, second: ?usize, seed: u64) !void {
    var sim = SimStorage.init(gpa);
    defer sim.deinit();
    try writeV1(&sim, &fixture, &.{}, null);
    sim.crash_mode = mode;
    sim.reorder_seed = seed;
    sim.ops_until_crash = point;
    if (openAuto(&sim, null)) |l| {
        var log = l;
        log.close();
        return error.DidNotCrash;
    } else |e| switch (e) {
        error.Crashed => {},
        else => return e,
    }
    sim.reboot();
    // Between the two, a reader is told to wait, or reads a finished log
    // (the crash came after the last manifest commit) — never half of one.
    if (Log.openReadOnly(gpa, sim.storage(), .{})) |r| {
        var reader = r;
        reader.close();
    } else |e| switch (e) {
        error.MigrationInProgress, error.NotFound => {},
        else => return e,
    }
    if (second) |s| {
        sim.crash_mode = mode;
        sim.ops_until_crash = s;
        if (openAuto(&sim, null)) |l| {
            var log = l;
            log.close();
        } else |e| switch (e) {
            error.Crashed => {},
            else => return e,
        }
        sim.reboot();
    }
    var log = try openAuto(&sim, null);
    defer log.close();
    try expectMigrated(&sim, &log);
}

test "migration crash sweep: a crash at any side effect, and inside the recovery, is finished by the next open" {
    const total = try migratingOpenOps();
    try testing.expect(total > 20);
    for ([_]CrashMode{ .lose_unsynced, .keep_unsynced, .torn_tail }) |mode| {
        for (0..total) |point| {
            crashAndRecover(mode, point, null, 0) catch |e| {
                std.debug.print("migration sweep FAILED: mode={t} point={d}/{d}\n", .{ mode, point, total });
                return e;
            };
            for (0..8) |second| crashAndRecover(mode, point, second, 0) catch |e| {
                std.debug.print("migration sweep FAILED: mode={t} point={d}/{d} second={d}\n", .{ mode, point, total, second });
                return e;
            };
        }
    }
    for ([_]u64{ 1, 2, 3, 5 }) |seed| for (0..total) |point| {
        crashAndRecover(.reorder_unsynced, point, null, seed) catch |e| {
            std.debug.print("migration reorder sweep FAILED: seed={d} point={d}/{d}\n", .{ seed, point, total });
            return e;
        };
    };
}

/// A storage that flips a byte in whatever is written to `MIGRATE.tmp` past
/// its header: a bad disk or bad RAM under the migration.
const FlipMigrate = struct {
    inner: seglog.Storage,
    armed: bool = true,
    tmp: ?seglog.Storage.Handle = null,

    fn storage(self: *FlipMigrate) seglog.Storage {
        return .{ .ctx = self, .vtable = &vt };
    }
    const S = seglog.Storage;
    const vt: S.VTable = .{
        .open = open_,
        .size = size_,
        .pread = pread_,
        .writeAll = writeAll_,
        .sync = sync_,
        .truncate = truncate_,
        .close = close_,
        .rename = rename_,
        .delete = delete_,
        .syncDir = syncDir_,
        .tryLockExclusive = lock_,
    };
    fn c(ctx: *anyopaque) *FlipMigrate {
        return @ptrCast(@alignCast(ctx));
    }
    fn open_(ctx: *anyopaque, p: []const u8, m: S.OpenMode) S.Error!S.Handle {
        const h = try c(ctx).inner.open(p, m);
        if (std.mem.eql(u8, p, "MIGRATE.tmp") and m != .read_only) c(ctx).tmp = h;
        return h;
    }
    fn size_(ctx: *anyopaque, h: S.Handle) S.Error!u64 {
        return c(ctx).inner.size(h);
    }
    fn pread_(ctx: *anyopaque, h: S.Handle, b: []u8, off: u64) S.Error!usize {
        return c(ctx).inner.pread(h, b, off);
    }
    fn writeAll_(ctx: *anyopaque, h: S.Handle, b: []const u8, off: u64) S.Error!void {
        const self = c(ctx);
        if (self.armed and self.tmp == h and off >= 40 and b.len > 30) {
            var copy: [4096]u8 = undefined;
            const n = @min(b.len, copy.len);
            @memcpy(copy[0..n], b[0..n]);
            copy[30] ^= 0x40; // inside the first record's payload
            try self.inner.writeAll(h, copy[0..n], off);
            if (n < b.len) try self.inner.writeAll(h, b[n..], off + n);
            return;
        }
        return self.inner.writeAll(h, b, off);
    }
    fn sync_(ctx: *anyopaque, h: S.Handle) S.Error!void {
        return c(ctx).inner.sync(h);
    }
    fn truncate_(ctx: *anyopaque, h: S.Handle, len: u64) S.Error!void {
        return c(ctx).inner.truncate(h, len);
    }
    fn close_(ctx: *anyopaque, h: S.Handle) void {
        if (c(ctx).tmp == h) c(ctx).tmp = null;
        c(ctx).inner.close(h);
    }
    fn rename_(ctx: *anyopaque, a: []const u8, b: []const u8) S.Error!void {
        return c(ctx).inner.rename(a, b);
    }
    fn delete_(ctx: *anyopaque, p: []const u8) S.Error!void {
        return c(ctx).inner.delete(p);
    }
    fn syncDir_(ctx: *anyopaque) S.Error!void {
        return c(ctx).inner.syncDir();
    }
    fn lock_(ctx: *anyopaque, h: S.Handle) S.Error!bool {
        return c(ctx).inner.tryLockExclusive(h);
    }
};

test "migration: a converted segment that does not read back is caught, and the next open finishes the job" {
    var sim = SimStorage.init(gpa);
    defer sim.deinit();
    try writeV1(&sim, &fixture, &.{}, null);
    var flip: FlipMigrate = .{ .inner = sim.storage() };
    var rep: seglog.MigrationReport = .{};
    try testing.expectError(error.MigrationFailed, Log.open(gpa, flip.storage(), .{ .legacy_ts = tsOf, .migration_report = &rep }));
    try testing.expectEqual(@as(u64, 10), rep.failure.?.segment);
    try testing.expect(rep.failure.?.reason == .mismatch);
    try testing.expect(sim.fileContent("MIGRATE.tmp") == null);
    // Under way, not done: readers wait, and a sound disk finishes it.
    try testing.expectError(error.MigrationInProgress, Log.openReadOnly(gpa, sim.storage(), .{}));
    flip.armed = false;
    var log = try Log.open(gpa, flip.storage(), .{ .legacy_ts = tsOf });
    defer log.close();
    try expectMigrated(&sim, &log);
}

test "migration: resuming, a file already converted must be the segment the manifest names" {
    var sim = SimStorage.init(gpa);
    defer sim.deinit();
    try writeV1(&sim, &fixture, &.{}, null);
    {
        var log = try openAuto(&sim, null);
        log.close();
    }
    // As if a crash came after segment 11's rename and before the manifest
    // said so — except that the file there is not segment 11's conversion.
    const man = sim.fileContent("MANIFEST").?;
    const entry = 16 + 24 * 1; // segment 11
    man[entry + 16] = 2; // not yet converted
    std.mem.writeInt(u32, man[man.len - 4 ..][0..4], crc(man[0 .. man.len - 4]), .little);
    const f = sim.fileContent("seg-00000000000000000011.log").?;
    f[16] +%= 1; // its base LSN
    std.mem.writeInt(u32, f[36..40], crc(f[0..36]), .little);
    var rep: seglog.MigrationReport = .{};
    try testing.expectError(error.MigrationFailed, openAuto(&sim, &rep));
    try testing.expectEqual(@as(u64, 11), rep.failure.?.segment);
    try testing.expect(rep.failure.?.reason == .bad_header);
}
