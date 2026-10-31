// SPDX-License-Identifier: MIT
//! No-panic sweep tests (wave GY). Findings DF-*, see
//! ~/CML/20261029-panic-sweep/diskfree-sweep.report.md.
const std = @import("std");
const testing = std.testing;
const mounts = @import("mounts.zig");
const mountinfo = @import("mountinfo.zig");
const statfs = @import("statfs.zig");

const mounts_text =
    "sysfs /sys sysfs rw 0 0\n" ++
    "/dev/sda1 /mnt/a\\040b ext4 rw,noatime 0 0\n" ++
    "tmpfs /run tmpfs rw 0 0\n";

const mountinfo_text =
    "36 35 98:0 / /sys rw - sysfs sysfs rw\n" ++
    "37 36 98:1 /sub /mnt/a\\040b rw,noatime master:1 shared:2 - ext4 /dev/sda1 rw,errors=continue\n" ++
    "38 36 0:5 / /run rw - tmpfs tmpfs rw\n";

// ── DF-2: OutOfMemory must not turn into a silently short table ─────────────

test "parseMounts: an allocation failure is OutOfMemory, never a short table (sweep DF-2)" {
    var counter = testing.FailingAllocator.init(testing.allocator, .{});
    const base = try mounts.parseMounts(counter.allocator(), mounts_text);
    try testing.expectEqual(@as(usize, 3), base.len);
    mounts.freeAll(counter.allocator(), base);
    var i: usize = 0;
    while (i <= counter.alloc_index) : (i += 1) {
        var fa = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = i });
        if (mounts.parseMounts(fa.allocator(), mounts_text)) |entries| {
            defer mounts.freeAll(testing.allocator, entries);
            try testing.expectEqual(@as(usize, 3), entries.len);
        } else |err| try testing.expectEqual(error.OutOfMemory, err);
    }
}

test "parseMountinfo: an allocation failure is OutOfMemory, never a short table (sweep DF-2)" {
    var counter = testing.FailingAllocator.init(testing.allocator, .{});
    const base = try mountinfo.parseMountinfo(counter.allocator(), mountinfo_text);
    try testing.expectEqual(@as(usize, 3), base.len);
    mountinfo.freeAll(counter.allocator(), base);
    var i: usize = 0;
    while (i <= counter.alloc_index) : (i += 1) {
        var fa = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = i });
        if (mountinfo.parseMountinfo(fa.allocator(), mountinfo_text)) |entries| {
            defer mountinfo.freeAll(testing.allocator, entries);
            try testing.expectEqual(@as(usize, 3), entries.len);
        } else |err| try testing.expectEqual(error.OutOfMemory, err);
    }
}

// ── Clean entry points: hostile input stays bounded and total ───────────────

test "unescapeOctal: truncated and out-of-range escapes at the end are literal" {
    for ([_][]const u8{ "\\", "\\0", "\\04", "\\040", "a\\04", "\\400", "\\8", "\\\\" }) |raw| {
        const out = try mounts.unescapeOctal(testing.allocator, raw);
        defer testing.allocator.free(out);
        if (std.mem.eql(u8, raw, "\\040")) {
            try testing.expectEqualStrings(" ", out);
        } else {
            try testing.expectEqualStrings(raw, out);
        }
    }
}

test "parseMountinfo: 1000 optional fields, missing or doubled separator, junk numbers" {
    const a = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(a);
    try buf.appendSlice(a, "1 1 0:1 / / rw");
    for (0..1000) |_| try buf.appendSlice(a, " shared:1");
    try buf.appendSlice(a, " - ext4 /dev/x rw\n");
    try buf.appendSlice(a, "2 1 0:1 / /x rw shared:1 ext4 /dev/x rw\n"); // no separator
    try buf.appendSlice(a, "3 1 0:1 / /x rw - - ext4 /dev/x rw\n"); // two dashes
    try buf.appendSlice(a, "99999999999 1 0:1 / /x rw - ext4 /dev/x rw\n"); // id past u32
    try buf.appendSlice(a, "4 1 x:y / /x rw - ext4 /dev/x rw\n");
    try buf.appendSlice(a, "5 1 0:1 / /x rw - ext4\n"); // truncated after fs type
    const entries = try mountinfo.parseMountinfo(a, buf.items);
    defer mountinfo.freeAll(a, entries);
    try testing.expectEqual(@as(usize, 1), entries.len);
}

test "parse: 100 000 mount rows stay linear and exact" {
    const a = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(a);
    for (0..100_000) |_| try buf.appendSlice(a, "d /m t o 0 0\n");
    const entries = try mounts.parseMounts(a, buf.items);
    defer mounts.freeAll(a, entries);
    try testing.expectEqual(@as(usize, 100_000), entries.len);
}

test "Usage: zero and maximal counters never panic and never invent a size" {
    const hostile = [_]i64{ 0, 1, -1, std.math.maxInt(i64), std.math.minInt(i64) };
    const counts = [_]u64{ 0, 1, std.math.maxInt(u64) };
    for (hostile) |bs| for (hostile) |fs| for (counts) |t| for (counts) |f| for (counts) |av| {
        const u: statfs.Usage = .{
            .block_size = bs,
            .fragment_size = fs,
            .blocks_total = t,
            .blocks_free = f,
            .blocks_available = av,
            .inodes_total = 0,
            .inodes_free = 0,
            .fs_type_magic = 0,
            .name_max = 0,
        };
        _ = u.totalBytes();
        _ = u.freeBytes();
        _ = u.availableBytes();
        _ = u.usedBytes();
        if (u.usePercent()) |p| try testing.expect(p <= 100);
    };
}

test "statfs.query: over-long paths are an error, not a panic" {
    const long: [5000]u8 = @splat('a');
    try testing.expectError(error.NameTooLong, statfs.query(&long));
    const edge: [4096]u8 = @splat('a');
    try testing.expectError(error.NameTooLong, statfs.query(&edge));
}

// ── DF-1: OutOfMemory in readVirtualFile is not "no data" ───────────────────

test "readVirtualFile: an allocation failure is OutOfMemory, never null (sweep DF-1)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var f = try tmp.dir.createFile(io, "t.txt", .{});
        defer f.close(io);
        var wbuf: [64]u8 = undefined;
        var w = f.writer(io, &wbuf);
        try w.interface.writeAll("a b c d\ne f g h\n");
        try w.interface.flush();
    }
    var path_buf: [128]u8 = undefined;
    const path = try std.mem.print(&path_buf, ".zig-cache/tmp/{s}/t.txt", .{&tmp.sub_path});

    var counter = testing.FailingAllocator.init(testing.allocator, .{});
    const base = (try mounts.readVirtualFile(counter.allocator(), io, path, 4096)).?;
    counter.allocator().free(base);
    try testing.expect(counter.alloc_index > 0);
    var i: usize = 0;
    var saw_oom = false;
    while (i <= counter.alloc_index) : (i += 1) {
        var fa = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = i });
        if (mounts.readVirtualFile(fa.allocator(), io, path, 4096)) |maybe| {
            const text = maybe orelse return error.OomBecameNull;
            defer testing.allocator.free(text);
            try testing.expectEqualStrings("a b c d\ne f g h\n", text);
        } else |err| {
            try testing.expectEqual(error.OutOfMemory, err);
            saw_oom = true;
        }
    }
    try testing.expect(saw_oom);
}
