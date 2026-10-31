// SPDX-License-Identifier: MIT
//! No-panic sweep tests for blobstore (wave GW). Findings BS-1 .. BS-4, see
//! ~/CML/20261029-panic-sweep/blobstore-sweep.report.md.
const std = @import("std");
const t = std.testing;
const root = @import("root.zig");
const Store = root.Store;
const Digest = root.Digest;

fn testStore(tmp: *std.testing.TmpDir, base_buf: []u8) !Store {
    const base = try std.mem.print(base_buf, ".zig-cache/tmp/{s}/store", .{&tmp.sub_path});
    return Store.init(t.io, base);
}

const hex64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

test "gc: a stale temp whose mtime is older than u64 nanoseconds is reaped, not a cast panic (sweep BS-1)" {
    // The trigger needs a filesystem with 64-bit timestamps (tmpfs; ext4 stops at
    // 1901), hence /dev/shm. 1000-01-01: age ~ 3.2e19 ns > maxInt(u64).
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var bb: [256]u8 = undefined;
    const base = try std.mem.print(&bb, "/dev/shm/zl-sweep-bs1-{s}", .{&tmp.sub_path});
    const cwd = std.Io.Dir.cwd();
    cwd.createDir(t.io, base, .default_dir) catch return error.SkipZigTest;
    defer cwd.deleteTree(t.io, base) catch {};
    const store = try Store.init(t.io, base);
    var pb: [300]u8 = undefined;
    try cwd.createDir(t.io, try std.mem.print(&pb, "{s}/cas", .{base}), .default_dir);
    const tp = try std.mem.print(&pb, "{s}/cas/.ingest-ancient.part", .{base});
    try cwd.writeFile(t.io, .{ .sub_path = tp, .data = "x" });
    var f = try cwd.openFile(t.io, tp, .{ .mode = .read_write });
    defer f.close(t.io);
    const ancient: i96 = -30_610_224_000 * std.time.ns_per_s;
    f.setTimestamps(t.io, .{ .modify_timestamp = .{ .new = .{ .nanoseconds = ancient } } }) catch return error.SkipZigTest;
    const st = try f.stat(t.io);
    try t.expect(st.mtime.nanoseconds < 0); // the filesystem really stored it
    const stats = try store.gc(t.allocator, &.{}, .{});
    try t.expectEqual(@as(u64, 1), stats.temps_removed);
}

test "gc: a keep list longer than u32 is an error, not a narrowing cast (sweep BS-2)" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var bb: [256]u8 = undefined;
    const store = try testStore(&tmp, &bb);
    // A slice with a fabricated length: gc must refuse before reading any element.
    const one: [1]Digest = .{.{ .hex = hex64.* }};
    const big: []const Digest = @as([*]const Digest, &one)[0 .. (1 << 32) + 1];
    try t.expectError(error.OutOfMemory, store.gc(t.allocator, big, .{}));
}

test "casPath/casCommit: a fanout field outside 1..32 (struct literal) is InvalidFanout (sweep BS-3)" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var bb: [256]u8 = undefined;
    const good = try testStore(&tmp, &bb);
    for ([_]u8{ 0, 33, 200 }) |fo| {
        const s: Store = .{ .io = good.io, .base = good.base, .fanout = fo, .refcount = true };
        var pb: [768]u8 = undefined;
        try t.expectError(error.InvalidFanout, s.casPath(&pb, hex64));
        var tb: [768]u8 = undefined;
        const temp = try good.casCreateTemp("fan", &tb);
        temp.file.close(t.io);
        try t.expectError(error.InvalidFanout, s.casCommit(hex64, temp.tmp));
        good.discardTemp(temp.tmp);
    }
}

test "casCreateTemp: uniq may not leave its path component, nothing else is refused (sweep BS-4)" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var bb: [256]u8 = undefined;
    const store = try testStore(&tmp, &bb);
    var tb: [768]u8 = undefined;
    try t.expectError(error.InvalidName, store.casCreateTemp("../x", &tb));
    try t.expectError(error.InvalidName, store.casCreateTemp("a/b", &tb));
    try t.expectError(error.InvalidName, store.casCreateTemp("", &tb));
    try t.expectError(error.InvalidName, store.casCreateTemp(".hidden", &tb));
    try t.expectError(error.InvalidName, store.casCreateTemp("a\x00b", &tb));
    // the whole temp name `.ingest-<uniq>.part` must fit NAME_MAX (255): 242 is the longest
    const too_long: [243]u8 = @splat('u');
    try t.expectError(error.InvalidName, store.casCreateTemp(&too_long, &tb));
    const longest: [242]u8 = @splat('u');
    const edge = try store.casCreateTemp(&longest, &tb);
    edge.file.close(t.io);
    store.discardTemp(edge.tmp);
    // axp-vault's shape "{device}-{key}-{idx}" with device 128 + key 100 chars (> 128 overall)
    const device: [128]u8 = @splat('d');
    const key: [100]u8 = @splat('k');
    var ub: [300]u8 = undefined;
    const uniq = try std.mem.print(&ub, "{s}-{s}-7", .{ &device, &key });
    const ok = try store.casCreateTemp(uniq, &tb);
    ok.file.close(t.io);
    store.discardTemp(ok.tmp);
    // characters beyond segmentSafe's set were accepted before and still are
    const odd = try store.casCreateTemp("dev 1:ü", &tb);
    odd.file.close(t.io);
    store.discardTemp(odd.tmp);
}

test "putNamed: a record readNamed would refuse is refused up front (sweep BS-5)" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var bb: [256]u8 = undefined;
    const store = try testStore(&tmp, &bb);
    // fabricated length, never dereferenced: the check precedes any I/O
    const one: [1]u8 = .{0};
    const big: []const u8 = @as([*]const u8, &one)[0 .. 64 * 1024 * 1024 + 1];
    try t.expectError(error.StreamTooLong, store.putNamed("ns", "k", big));
}

test "gc / hasAnyRcSidecar: a fanout field outside 1..32 is InvalidFanout (sweep BS-6)" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var bb: [256]u8 = undefined;
    const good = try testStore(&tmp, &bb);
    for ([_]u8{ 0, 33, 255 }) |fo| {
        const s: Store = .{ .io = good.io, .base = good.base, .fanout = fo, .refcount = true };
        try t.expectError(error.InvalidFanout, s.gc(t.allocator, &.{}, .{}));
        try t.expectError(error.InvalidFanout, s.hasAnyRcSidecar());
    }
}

// ── delta audit GW (gwa-a) ──────────────────────────────────────────────────

test "casPath: the fanout bounds 1 and 32 are accepted (sweep audit GW-B2)" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var bb: [256]u8 = undefined;
    const good = try testStore(&tmp, &bb);
    for ([_]u8{ 1, 2, 31, 32 }) |fo| {
        const s: Store = .{ .io = good.io, .base = good.base, .fanout = fo, .refcount = true };
        var pb: [768]u8 = undefined;
        const p = try s.casPath(&pb, hex64);
        try t.expect(std.mem.endsWith(u8, p, "/" ++ hex64));
        try t.expect(!(try s.hasAnyRcSidecar()));
        _ = try s.gc(t.allocator, &.{}, .{});
    }
}

test "putNamed: a record of exactly 64 MiB is accepted and read back whole (sweep audit GW-B3)" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var bb: [256]u8 = undefined;
    const store = try testStore(&tmp, &bb);
    const n = 64 * 1024 * 1024;
    const big = try std.heap.page_allocator.alloc(u8, n);
    defer std.heap.page_allocator.free(big);
    @memset(big, 7);
    try store.putNamed("ns", "big", big);
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const got = (try store.readNamed(arena_state.allocator(), "ns", "big")).?;
    try t.expectEqual(@as(usize, n), got.len);
}

test "gc: a temp made by casCreateTemp is the kind the reaper deletes (sweep audit GW-B4)" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var bb: [256]u8 = undefined;
    const store = try testStore(&tmp, &bb);
    var tb: [768]u8 = undefined;
    const temp = try store.casCreateTemp("abandoned-1", &tb);
    temp.file.close(t.io);
    const stats = try store.gc(t.allocator, &.{}, .{ .stale_after_ns = 1 });
    try t.expectEqual(@as(u64, 1), stats.temps_removed);
    // and a young temp survives the default 24 h window
    const temp2 = try store.casCreateTemp("young-1", &tb);
    temp2.file.close(t.io);
    const stats2 = try store.gc(t.allocator, &.{}, .{});
    try t.expectEqual(@as(u64, 0), stats2.temps_removed);
    store.discardTemp(temp2.tmp);
}
