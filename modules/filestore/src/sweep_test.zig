// SPDX-License-Identifier: MIT
//! No-panic sweep tests for filestore (wave GW). No finding required a code
//! change; these pin the "clean" verdicts of
//! ~/CML/20261029-panic-sweep/filestore-sweep.report.md against hostile files
//! under `base`.
const std = @import("std");
const t = std.testing;
const fs = @import("root.zig");

fn testStore(tmp: *std.testing.TmpDir, base_buf: []u8) !fs.Store {
    const base = try std.mem.print(base_buf, ".zig-cache/tmp/{s}/store", .{&tmp.sub_path});
    return fs.Store.init(t.io, base);
}

test "hostile base: a directory where a record or sidecar is expected is an error, never a crash (sweep FS-clean)" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var bb: [256]u8 = undefined;
    const store = try testStore(&tmp, &bb);
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try tmp.dir.createDirPath(t.io, "store/k/rec");
    try t.expectError(error.IsDir, store.getBytes(arena, "k", "rec"));
    try tmp.dir.createDirPath(t.io, "store/k/.good.expiry");
    try store.putBytes("k", "good", "v");
    _ = store.getBytes(arena, "k", "good") catch {}; // error or value, no crash
}

test "hostile base: a corrupt or oversized expiry sidecar reads as no TTL (sweep FS-clean)" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var bb: [256]u8 = undefined;
    const store = try testStore(&tmp, &bb);
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try store.putBytes("k", "a", "va");
    const junk = [_][]const u8{ "", "not a number", "99999999999999999999999999999999999999", "-", &@as([4096]u8, @splat('7')) };
    for (junk) |j| {
        try tmp.dir.writeFile(t.io, .{ .sub_path = "store/k/.a.expiry", .data = j });
        const got = try store.getBytes(arena, "k", "a");
        try t.expectEqualStrings("va", got.?);
    }
}

test "list: foreign names are not listed, so listTyped and sweep keep working (sweep FS-1)" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var bb: [256]u8 = undefined;
    const store = try testStore(&tmp, &bb);
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try store.put(t.allocator, u8, "k", "a", 1);
    try tmp.dir.writeFile(t.io, .{ .sub_path = "store/k/a~backup", .data = "2" });
    try tmp.dir.writeFile(t.io, .{ .sub_path = "store/k/has space", .data = "3" });
    const long: [200]u8 = @splat('z');
    try tmp.dir.writeFile(t.io, .{ .sub_path = "store/k/" ++ long, .data = "4" });
    const keys = try store.list(arena, "k");
    try t.expectEqual(@as(usize, 1), keys.len);
    try t.expectEqualStrings("a", keys[0]);
    const typed = try store.listTyped(u8, arena, "k");
    try t.expectEqual(@as(usize, 1), typed.items.len);
    try t.expectEqual(@as(usize, 0), try store.sweep(arena, "k"));
}

test "putBytes/putManyBytes: a record getBytes would refuse is refused up front (sweep FS-6)" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var bb: [256]u8 = undefined;
    const store = try testStore(&tmp, &bb);
    const one: [1]u8 = .{0};
    const big: []const u8 = @as([*]const u8, &one)[0 .. 64 * 1024 * 1024 + 1]; // never dereferenced
    try t.expectError(error.StreamTooLong, store.putBytes("k", "r", big));
    try t.expectError(error.StreamTooLong, store.putManyBytes("k", &.{.{ .key = "r", .bytes = big }}));
}

test "ttl: a huge ttl_ns saturates and a negative one is already expired (sweep FS-clean)" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var bb: [256]u8 = undefined;
    var store = try testStore(&tmp, &bb);
    store.clock = .{ .nowFn = struct {
        fn f(_: ?*anyopaque) i64 {
            return std.math.maxInt(i64) - 5;
        }
    }.f };
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try store.putWithTTL("k", "big", "v", std.math.maxInt(i64));
    try store.putWithTTL("k", "neg", "v", std.math.minInt(i64));
    try t.expect((try store.getBytes(arena, "k", "neg")) == null);
}

test "delete on a never-created kind: observed result is an fsync error, not false (backlog note)" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var bb: [256]u8 = undefined;
    const store = try testStore(&tmp, &bb);
    try t.expectError(error.FileNotFound, store.delete("nokind", "k"));
}

// ── delta audit GW (gwa-a) ──────────────────────────────────────────────────

test "putBytes/getBytes: a record of exactly 64 MiB is accepted and read back whole (sweep audit GW-F1)" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var bb: [256]u8 = undefined;
    const store = try testStore(&tmp, &bb);
    const n = 64 * 1024 * 1024;
    const big = try std.heap.page_allocator.alloc(u8, n);
    defer std.heap.page_allocator.free(big);
    @memset(big, 7);
    try store.putBytes("k", "big", big);
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const got = (try store.getBytes(arena_state.allocator(), "k", "big")).?;
    try t.expectEqual(@as(usize, n), got.len);
    try store.putManyBytes("k", &.{.{ .key = "big2", .bytes = big }});
    const got2 = (try store.getBytes(arena_state.allocator(), "k", "big2")).?;
    try t.expectEqual(@as(usize, n), got2.len);
}

test "list: a 128-byte key is listed, a 129-byte name is not (sweep audit GW-F2)" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var bb: [256]u8 = undefined;
    const store = try testStore(&tmp, &bb);
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const ok: [128]u8 = @splat('k');
    const bad: [129]u8 = @splat('k');
    try store.putBytes("k", &ok, "v");
    try tmp.dir.writeFile(t.io, .{ .sub_path = "store/k/" ++ bad, .data = "x" });
    const keys = try store.list(arena_state.allocator(), "k");
    try t.expectEqual(@as(usize, 1), keys.len);
    try t.expectEqual(@as(usize, 128), keys[0].len);
}
