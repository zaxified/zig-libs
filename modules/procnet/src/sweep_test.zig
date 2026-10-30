// SPDX-License-Identifier: MIT

//! No-panic sweep regressions (wave GO review fixes). Each test names its finding.

const std = @import("std");
const builtin = @import("builtin");
const procnet = @import("root.zig");
const process = procnet.process;
const pidfiles = procnet.pidfiles;

const testing = std.testing;

test "indexSocketOwners: max_total_fds bounds the walk and sets truncated (sweep REV-PN-1)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // This process holds well over one descriptor (stdio, the Io instance's
    // own fds), so a budget of ONE examined descriptor must be hit no later
    // than inside this process, whatever else runs on the machine.
    var capped = try process.indexSocketOwners(testing.allocator, io, .{ .max_total_fds = 1 });
    defer capped.deinit(testing.allocator);
    try testing.expect(capped.truncated);
    try testing.expect(capped.owners.len <= 1);

    // Same machine, no fd budget in play: the sweep finishes. (A machine
    // with more than 1<<20 descriptors would truncate legitimately; skip.)
    var full = try process.indexSocketOwners(testing.allocator, io, .{});
    defer full.deinit(testing.allocator);
    if (full.truncated) return error.SkipZigTest;
    try testing.expect(capped.scanned <= full.scanned);
}

fn owner(inode: u64, pid: u32) process.SocketOwner {
    return .{ .inode = inode, .pid = pid, .fd = 3 };
}

test "SocketOwnerIndex.find/findAll return the exact equal-inode run (sweep REV-PN-3)" {
    var buf: [11]process.SocketOwner = .{
        owner(3, 1),  owner(5, 1), owner(5, 2), owner(5, 3), owner(5, 4),
        owner(5, 5),  owner(8, 1), owner(8, 2), owner(9, 1), owner(12, 1),
        owner(12, 2),
    };
    const idx: process.SocketOwnerIndex = .{ .owners = &buf, .scanned = 0, .denied = 0, .vanished = 0, .truncated = false };
    try testing.expectEqual(@as(usize, 5), idx.findAll(5).len);
    try testing.expectEqual(@as(u32, 1), idx.find(5).?.pid);
    try testing.expectEqual(@as(usize, 2), idx.findAll(8).len);
    try testing.expectEqual(@as(usize, 1), idx.findAll(3).len);
    try testing.expectEqual(@as(usize, 2), idx.findAll(12).len);
    try testing.expectEqual(@as(u32, 1), idx.find(12).?.pid);
    try testing.expectEqual(@as(usize, 0), idx.findAll(4).len);
    try testing.expectEqual(@as(usize, 0), idx.findAll(13).len);
    try testing.expectEqual(@as(usize, 0), idx.findAll(0).len);
    try testing.expect(idx.find(4) == null);
    try testing.expect(idx.find(13) == null);
    try testing.expect(idx.find(0) == null);
}

fn nowNs() u64 {
    var ts: std.posix.timespec = undefined;
    _ = std.posix.system.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

/// Time `calls` find+findAll lookups of the one inode that fills the whole index.
fn timeRun(gpa: std.mem.Allocator, n: usize, calls: usize) !u64 {
    const owners = try gpa.alloc(process.SocketOwner, n);
    defer gpa.free(owners);
    for (owners, 0..) |*o, i| o.* = owner(7, @intCast(i));
    const idx: process.SocketOwnerIndex = .{ .owners = owners, .scanned = 0, .denied = 0, .vanished = 0, .truncated = false };
    var best: u64 = std.math.maxInt(u64);
    for (0..3) |_| {
        var sink: usize = 0;
        const t0 = nowNs();
        for (0..calls) |_| {
            sink +%= idx.findAll(7).len;
            sink +%= idx.find(7).?.pid;
        }
        const dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(sink);
        best = @min(best, dt);
    }
    return best;
}

test "SocketOwnerIndex.find cost does not grow with the equal-inode run (sweep REV-PN-3)" {
    // A linear run walk costs ~256x more at 65536 owners than at 256; a
    // binary search costs about 2x. 32 is far from both.
    const small = try timeRun(testing.allocator, 256, 2000);
    const big = try timeRun(testing.allocator, 65536, 2000);
    try testing.expect(big < @max(small, 1) * 32);
}

test "PidStatus.cpus_allowed beyond cpus_allowed_len is deterministic (sweep REV-PN-4)" {
    const text = "Name:\tx\nCpus_allowed_list:\t0-3\n";
    // Pre-fill the result slots with different junk: an `undefined` field
    // would keep whatever the destination held, so the two parses differ.
    var a: pidfiles.PidStatus = undefined;
    var b: pidfiles.PidStatus = undefined;
    @memset(std.mem.asBytes(&a), 0xA5);
    @memset(std.mem.asBytes(&b), 0x5A);
    a = pidfiles.parsePidStatus(text);
    b = pidfiles.parsePidStatus(text);
    try testing.expectEqualSlices(u8, std.mem.asBytes(&a), std.mem.asBytes(&b));
    try testing.expectEqual(@as(u8, 1), a.cpus_allowed_len);
    for (a.cpus_allowed[a.cpus_allowed_len..]) |r| {
        try testing.expectEqual(@as(u64, 0), r.first);
        try testing.expectEqual(@as(u64, 0), r.last);
    }
}
