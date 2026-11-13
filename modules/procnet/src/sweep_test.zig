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
    // The budget also ends the walk across processes: a sweep that kept
    // visiting every remaining process would scan as many as the full one.
    if (full.scanned >= 4) try testing.expect(capped.scanned < full.scanned);
    // The default budget is large enough not to bite a normal machine.
    try testing.expect((process.SocketOwnerOptions{}).max_total_fds >= 1 << 16);
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

test "SocketOwnerIndex: inode 0 never matches even when owners hold inode 0 (sweep audit GO-PN-1)" {
    var buf: [4]process.SocketOwner = .{ owner(0, 1), owner(0, 2), owner(7, 1), owner(7, 2) };
    const idx: process.SocketOwnerIndex = .{ .owners = &buf, .scanned = 0, .denied = 0, .vanished = 0, .truncated = false };
    try testing.expectEqual(@as(usize, 0), idx.findAll(0).len);
    try testing.expect(idx.find(0) == null);
    try testing.expectEqual(@as(usize, 2), idx.findAll(7).len);
    try testing.expectEqual(@as(u32, 1), idx.find(7).?.pid);
}

// ── mutation audit 2026-11-13 (delta over bbe3a85c5): tests asked for by survivors ──

const linux = std.os.linux;

/// A throw-away file under `.zig-cache/tmp`; `path_buf` receives its path.
fn tmpFileWith(io: std.Io, tmp: *std.testing.TmpDir, text: []const u8, path_buf: []u8) ![]const u8 {
    var f = try tmp.dir.createFile(io, "t.txt", .{});
    defer f.close(io);
    var wbuf: [256]u8 = undefined;
    var w = f.writer(io, &wbuf);
    try w.interface.writeAll(text);
    try w.interface.flush();
    return std.mem.print(path_buf, ".zig-cache/tmp/{s}/t.txt", .{&tmp.sub_path});
}

test "readVirtualLines: an untruncated read keeps a last line with no newline; a limit equal to the size is flagged but complete" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [128]u8 = undefined;
    const text = "head\nrow 12345";
    const path = try tmpFileWith(io, &tmp, text, &pb);

    const r = procnet.readVirtualLinesReporting(testing.allocator, io, path, 4096) orelse return error.ReadFailed;
    defer testing.allocator.free(r.bytes);
    try testing.expect(!r.truncated);
    try testing.expectEqualStrings(text, r.bytes);

    // Exactly `limit` bytes: every byte arrives, but the flag is set too
    // (`appendRemaining(.limited(n))` cannot tell a file of n bytes from a longer one),
    // so `truncated` is conservative at the boundary, never wrong the other way.
    const exact = procnet.readVirtualFileReporting(testing.allocator, io, path, text.len) orelse return error.ReadFailed;
    defer testing.allocator.free(exact.bytes);
    try testing.expect(exact.truncated);
    try testing.expectEqualStrings(text, exact.bytes);

    // One byte less is a cut: the plain read keeps the prefix, the line read
    // drops the fragment; a cut with no newline at all leaves nothing.
    const cut = procnet.readVirtualFileReporting(testing.allocator, io, path, text.len - 1) orelse return error.ReadFailed;
    defer testing.allocator.free(cut.bytes);
    try testing.expect(cut.truncated);
    try testing.expectEqualStrings(text[0 .. text.len - 1], cut.bytes);
    const lines = procnet.readVirtualLinesReporting(testing.allocator, io, path, text.len - 1) orelse return error.ReadFailed;
    defer testing.allocator.free(lines.bytes);
    try testing.expect(lines.truncated);
    try testing.expectEqualStrings("head\n", lines.bytes);
    const none = procnet.readVirtualLinesReporting(testing.allocator, io, path, 3) orelse return error.ReadFailed;
    defer testing.allocator.free(none.bytes);
    try testing.expect(none.truncated);
    try testing.expectEqual(@as(usize, 0), none.bytes.len);
}

test "readVirtualFile: a read error is null, not an empty file; a missing file is null" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [128]u8 = undefined;
    // A directory opens for reading but every read fails (EISDIR).
    const dir_path = try std.mem.print(&pb, ".zig-cache/tmp/{s}", .{&tmp.sub_path});
    try testing.expect(procnet.readVirtualFileReporting(testing.allocator, io, dir_path, 4096) == null);
    try testing.expect(procnet.readVirtualLinesReporting(testing.allocator, io, dir_path, 4096) == null);
    try testing.expect(procnet.readVirtualFile(testing.allocator, io, "/proc/procnet-no-such-file", 4096) == null);
}

test "readVirtualLinesReporting: allocation failure at every step is null or a whole result, never a leak" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [128]u8 = undefined;
    const path = try tmpFileWith(io, &tmp, "head\nrow-one 12345\nrow-two 67890\n", &pb);
    for ([_]usize{ 4096, 20 }) |limit| {
        var i: usize = 0;
        while (i < 12) : (i += 1) {
            // `resize_fail_index = 0` also refuses the in-place shrink, so the
            // final `toOwnedSlice` has to allocate (and can fail) too.
            var fa = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = i, .resize_fail_index = 0 });
            if (procnet.readVirtualLinesReporting(fa.allocator(), io, path, limit)) |r| {
                try testing.expectEqual(limit == 20, r.truncated);
                fa.allocator().free(r.bytes);
            }
        }
    }
}

test "read*Reporting: a live read of this machine's own tables is not truncated" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const gpa = testing.allocator;

    const dev = try procnet.readNetDevReporting(gpa, io);
    defer gpa.free(dev.entries);
    try testing.expect(!dev.truncated);
    if (dev.entries.len == 0) return error.SkipZigTest; // no /proc/net/dev here
    const arp = try procnet.readArpReporting(gpa, io);
    defer gpa.free(arp.entries);
    try testing.expect(!arp.truncated);
    const rt = try procnet.readRoutesReporting(gpa, io);
    defer gpa.free(rt.entries);
    try testing.expect(!rt.truncated);
    const dk = try procnet.readDiskstatsReporting(gpa, io);
    defer gpa.free(dk.entries);
    try testing.expect(!dk.truncated);
    const v6 = try procnet.readIpv6RoutesReporting(gpa, io);
    defer gpa.free(v6.entries);
    try testing.expect(!v6.truncated);
    // The plain twins are the same read minus the flag.
    const dev2 = try procnet.readNetDev(gpa, io);
    defer gpa.free(dev2);
    try testing.expectEqual(dev.entries.len, dev2.len);

    // /proc/stat and /proc/meminfo are read whole: a limit that cut them would
    // zero the figures.
    const st = try procnet.readStat(gpa, io);
    defer st.deinit(gpa);
    try testing.expect(st.cpu.total() > 0);
    const mi = procnet.readMeminfo(gpa, io);
    try testing.expect((mi.mem_total orelse 0) > 0);

    const ct = try procnet.readConntrack(gpa, io, 64);
    defer gpa.free(ct.flows);
    try testing.expect(!ct.text_truncated);
    try testing.expectEqual(ct.flows.len, @min(ct.total, 64));
}

fn mkSock(domain: u32, typ: u32) !i32 {
    const rc = linux.socket(domain, typ, 0);
    if (linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
    const fd: i32 = @intCast(rc);
    errdefer _ = linux.close(fd);
    if (domain == linux.AF.INET) {
        var a: linux.sockaddr.in = .{ .port = 0, .addr = std.mem.nativeToBig(u32, 0x7f000001) };
        if (linux.errno(linux.bind(fd, @ptrCast(&a), @sizeOf(linux.sockaddr.in))) != .SUCCESS) return error.SkipZigTest;
    } else {
        var a: linux.sockaddr.in6 = .{ .port = 0, .flowinfo = 0, .addr = @splat(0), .scope_id = 0 };
        a.addr[15] = 1;
        if (linux.errno(linux.bind(fd, @ptrCast(&a), @sizeOf(linux.sockaddr.in6))) != .SUCCESS) return error.SkipZigTest;
    }
    return fd;
}

fn sockPort(fd: i32, domain: u32) u16 {
    if (domain == linux.AF.INET) {
        var a: linux.sockaddr.in = undefined;
        var len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
        _ = linux.getsockname(fd, @ptrCast(&a), &len);
        return std.mem.bigToNative(u16, a.port);
    }
    var a: linux.sockaddr.in6 = undefined;
    var len: linux.socklen_t = @sizeOf(linux.sockaddr.in6);
    _ = linux.getsockname(fd, @ptrCast(&a), &len);
    return std.mem.bigToNative(u16, a.port);
}

fn inodeOfFd(io: std.Io, fd: i32) !u64 {
    var pb: [64]u8 = undefined;
    const path = try std.mem.print(&pb, "/proc/self/fd/{d}", .{fd});
    var lb: [64]u8 = undefined;
    const n = try std.Io.Dir.cwd().readLink(io, path, &lb);
    return process.parseSocketInode(lb[0..n]) orelse error.NotASocket;
}

test "readSockets: this process's own sockets decode with their protocol, port, state and inode" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const domains = [_]u32{ linux.AF.INET, linux.AF.INET6 };
    var fds: [4]i32 = .{ -1, -1, -1, -1 };
    var ports: [4]u16 = undefined;
    var ino: [4]u64 = undefined;
    defer {
        for (fds) |fd| {
            if (fd >= 0) _ = linux.close(fd);
        }
    }
    for (domains, 0..) |d, k| {
        const tcp = mkSock(d, linux.SOCK.STREAM) catch continue;
        fds[2 * k] = tcp;
        if (linux.errno(linux.listen(tcp, 1)) != .SUCCESS) return error.SkipZigTest;
        const udp = mkSock(d, linux.SOCK.DGRAM) catch continue;
        fds[2 * k + 1] = udp;
        ports[2 * k] = sockPort(tcp, d);
        ports[2 * k + 1] = sockPort(udp, d);
        ino[2 * k] = try inodeOfFd(io, tcp);
        ino[2 * k + 1] = try inodeOfFd(io, udp);
    }
    if (fds[0] < 0 or fds[1] < 0) return error.SkipZigTest;

    const t = try procnet.readSockets(testing.allocator, io);
    defer t.deinit(testing.allocator);
    try testing.expect(!t.truncated);
    var k: usize = 0;
    while (k < 4) : (k += 1) {
        if (fds[k] < 0) continue;
        var found = false;
        for (t.entries) |e| {
            if (e.inode != ino[k]) continue;
            found = true;
            try testing.expectEqual(ports[k], e.local_port);
            if (k % 2 == 0) {
                try testing.expectEqual(procnet.sockets.Proto.tcp, e.proto);
                try testing.expectEqual(procnet.SockState.listen, e.state);
            } else {
                try testing.expectEqual(procnet.sockets.Proto.udp, e.proto);
                try testing.expectEqual(procnet.SockState.close, e.state);
            }
        }
        try testing.expect(found);
    }
}

test "indexSocketOwners: owners carry inode, pid, fd and name; order, accounting and bounds hold" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const gpa = testing.allocator;

    const a = try mkSock(linux.AF.INET, linux.SOCK.STREAM);
    defer _ = linux.close(a);
    const b = try mkSock(linux.AF.INET, linux.SOCK.DGRAM);
    defer _ = linux.close(b);
    const drc = linux.dup(b);
    if (linux.errno(drc) != .SUCCESS) return error.SkipZigTest;
    const c: i32 = @intCast(drc);
    defer _ = linux.close(c);
    const ia = try inodeOfFd(io, a);
    const ib = try inodeOfFd(io, b);
    const self_pid: u32 = @intCast(linux.getpid());

    var idx = try process.indexSocketOwners(gpa, io, .{});
    defer idx.deinit(gpa);

    // Every owner is a real socket; the list is sorted (inode, pid, fd).
    for (idx.owners, 0..) |o, i| {
        try testing.expect(o.inode != 0);
        if (i == 0) continue;
        const p = idx.owners[i - 1];
        try testing.expect(p.inode < o.inode or (p.inode == o.inode and (p.pid < o.pid or (p.pid == o.pid and p.fd < o.fd))));
    }
    // This process's sockets, with the right descriptor numbers.
    const fa = idx.findAll(ia);
    try testing.expectEqual(@as(usize, 1), fa.len);
    try testing.expectEqual(self_pid, fa[0].pid);
    try testing.expectEqual(@as(u32, @intCast(a)), fa[0].fd);
    // A dup'ed descriptor is a second owner row, lowest descriptor first.
    const fb = idx.findAll(ib);
    try testing.expectEqual(@as(usize, 2), fb.len);
    try testing.expectEqual(self_pid, fb[0].pid);
    try testing.expectEqual(self_pid, fb[1].pid);
    try testing.expectEqual(@as(u32, @intCast(@min(b, c))), fb[0].fd);
    try testing.expectEqual(@as(u32, @intCast(@max(b, c))), fb[1].fd);
    try testing.expectEqual(fb[0].fd, idx.find(ib).?.fd);
    // The owner's name is the process's own `comm`.
    var cb: [64]u8 = undefined;
    const comm = procnet.readVirtualFileInto(io, "/proc/self/comm", &cb) orelse return error.SkipZigTest;
    try testing.expectEqualStrings(std.mem.trim(u8, comm, " \n"), fa[0].name());

    // Accounting: this process was scanned; a process this uid may not read
    // (pid 1 for a non-root caller) is counted as denied.
    try testing.expect(idx.scanned >= 1);
    if (linux.getuid() != 0) {
        if (std.Io.Dir.cwd().openDir(io, "/proc/1/fd", .{ .iterate = true })) |d| {
            var dd = d;
            dd.close(io);
        } else |err| switch (err) {
            error.AccessDenied, error.PermissionDenied => try testing.expect(idx.denied >= 1),
            else => {},
        }
    }

    // max_processes bounds scanned + denied + vanished exactly.
    const seen = idx.scanned + idx.denied + idx.vanished;
    if (seen >= 3) {
        var one = try process.indexSocketOwners(gpa, io, .{ .max_processes = 1 });
        defer one.deinit(gpa);
        try testing.expect(one.truncated);
        try testing.expectEqual(@as(u32, 1), one.scanned + one.denied + one.vanished);
    }

    // max_fds_per_process: this process holds more than one descriptor, so a
    // budget of one examines one and says so, and finds at most one of ours.
    var onefd = try process.indexSocketOwners(gpa, io, .{ .max_fds_per_process = 1 });
    defer onefd.deinit(gpa);
    try testing.expect(onefd.truncated);
    var mine: usize = 0;
    for (onefd.owners) |o| {
        if (o.pid == self_pid) mine += 1;
    }
    try testing.expect(mine <= 1);
}

test "parseIpv6Routes: every column is validated in its own place and lands in its own field (mutation audit)" {
    const gpa = testing.allocator;
    const z = "00000000000000000000000000000000";
    const a = "20010db8000000000000000000000001";
    const nh = "fe800000000000000000000000000001";
    var cols = [9][]const u8{ a, "40", z, "00", nh, "00000100", "00000002", "00000003", "00000004" };
    var buf: [256]u8 = undefined;
    const row = struct {
        fn f(b: []u8, c: [9][]const u8) []const u8 {
            return std.mem.print(b, "{s} {s} {s} {s} {s} {s} {s} {s} {s} eth0\n", .{ c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7], c[8] }) catch unreachable;
        }
    }.f;
    {
        const rs = try procnet.parseIpv6Routes(gpa, row(&buf, cols));
        defer gpa.free(rs);
        try testing.expectEqual(@as(usize, 1), rs.len);
        try testing.expectEqual(@as(u8, 0x40), rs[0].dest.bits);
        try testing.expectEqual(@as(u8, 0), rs[0].src.bits);
        try testing.expectEqual(@as(u32, 0x100), rs[0].metric);
        try testing.expectEqual(@as(u32, 2), rs[0].refcnt);
        try testing.expectEqual(@as(u32, 3), rs[0].use);
        try testing.expectEqual(@as(u32, 4), rs[0].flags);
        try testing.expect(rs[0].next_hop != null);
        try testing.expectEqualStrings("eth0", rs[0].iface());
    }
    // A zero next hop is on-link (null); the prefix length 128 is the last good one, 129 the first bad one.
    cols[4] = z;
    cols[3] = "80";
    {
        const rs = try procnet.parseIpv6Routes(gpa, row(&buf, cols));
        defer gpa.free(rs);
        try testing.expectEqual(@as(usize, 1), rs.len);
        try testing.expect(rs[0].next_hop == null);
        try testing.expectEqual(@as(u8, 128), rs[0].src.bits);
    }
    cols[4] = nh;
    cols[3] = "00";
    // One bad token per column, each of the three shapes the decoders must refuse.
    const bad_hex128 = [_][]const u8{ "2001db8g000000000000000000000001", "+f010db8000000000000000000000001", "20010db800000000000000000000001" };
    const bad_pfx = [_][]const u8{ "f", "+8", "081", "81", "g0" };
    const bad_u32 = [_][]const u8{ "0000000g", "+0000001", "1", "000000001" };
    inline for (.{ 0, 2, 4 }) |c| for (bad_hex128) |bad| {
        var t = cols;
        t[c] = bad;
        const rs = try procnet.parseIpv6Routes(gpa, row(&buf, t));
        defer gpa.free(rs);
        try testing.expectEqual(@as(usize, 0), rs.len);
    };
    inline for (.{ 1, 3 }) |c| for (bad_pfx) |bad| {
        var t = cols;
        t[c] = bad;
        const rs = try procnet.parseIpv6Routes(gpa, row(&buf, t));
        defer gpa.free(rs);
        try testing.expectEqual(@as(usize, 0), rs.len);
    };
    inline for (.{ 5, 6, 7, 8 }) |c| for (bad_u32) |bad| {
        var t = cols;
        t[c] = bad;
        const rs = try procnet.parseIpv6Routes(gpa, row(&buf, t));
        defer gpa.free(rs);
        try testing.expectEqual(@as(usize, 0), rs.len);
    };
    // A row that stops before the device column is not a row.
    const short = try procnet.parseIpv6Routes(gpa, row(&buf, cols)[0 .. row(&buf, cols).len - 5]);
    defer gpa.free(short);
    try testing.expectEqual(@as(usize, 0), short.len);
}

test "parseLimits: every kind of unusable row is counted once; a late `Limit` line is a row, not a header (mutation audit)" {
    const l = pidfiles.parseLimits("Limit Soft Limit Hard Limit Units\n" ++
        "Max cpu time 5 abc seconds\n" ++ // hard value not a number
        "Max file size abc 5 bytes\n" ++ // soft value not a number
        "Max data size 7\n" ++ // one value only
        "Bogus row 1 2\n" ++ // no known label
        "Limits late line\n" ++ // not the first line: counted, not skipped as a header
        "\n" ++ // blank: ignored
        "Max stack size 8 9 bytes\n");
    try testing.expectEqual(@as(u32, 5), l.skipped_rows);
    try testing.expectEqual(@as(?u64, 8), l.get(.stack_size).?.soft);
    try testing.expectEqual(@as(?u64, 9), l.get(.stack_size).?.hard);
    try testing.expect(l.get(.cpu_time) == null);
    try testing.expect(l.get(.file_size) == null);
    try testing.expect(l.get(.data_size) == null);
}

test "readUnix: a listener this process binds is in the table, and the table is not truncated (mutation audit)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var name_buf: [64]u8 = undefined;
    const pid: u32 = @intCast(linux.getpid());
    const name = std.mem.print(&name_buf, "\x00procnet-sweep-test-{d}", .{pid}) catch unreachable;
    const addr = std.Io.net.UnixAddress.init(name) catch return error.SkipZigTest;
    var server = addr.listen(io, .{}) catch return error.SkipZigTest;
    defer server.deinit(io);
    // Skip only when the host has no /proc/net/unix at all.
    const probe = procnet.readVirtualFile(testing.allocator, io, "/proc/net/unix", 4096) orelse return error.SkipZigTest;
    testing.allocator.free(probe);
    const t = try procnet.readUnix(testing.allocator, io);
    defer t.deinit(testing.allocator);
    try testing.expect(!t.truncated);
    var found = false;
    for (t.entries) |e| {
        if (std.mem.startsWith(u8, e.path(), "@procnet-sweep-test-")) found = true;
    }
    try testing.expect(found);
}

fn fdOpen(fd: usize) bool {
    return linux.errno(linux.fcntl(@intCast(fd), linux.F.GETFD, 0)) == .SUCCESS;
}

fn fdIsSocket(io: std.Io, fd: usize) bool {
    return if (inodeOfFd(io, @intCast(fd))) |_| true else |_| false;
}

fn countProcDirs(io: std.Io, le: u32) !struct { le: usize, gt: usize } {
    var d = try std.Io.Dir.cwd().openDir(io, "/proc", .{ .iterate = true });
    defer d.close(io);
    var le_n: usize = 0;
    var gt_n: usize = 0;
    var it = d.iterate();
    while (try it.next(io)) |e| {
        const p = std.fmt.parseInt(u32, e.name, 10) catch continue;
        if (p <= le) le_n += 1 else gt_n += 1;
    }
    return .{ .le = le_n, .gt = gt_n };
}

test "indexSocketOwners: max_fds_per_process examines exactly that many descriptors of one process (mutation audit)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const gpa = testing.allocator;
    const a = try mkSock(linux.AF.INET, linux.SOCK.STREAM);
    defer _ = linux.close(a);
    const b = try mkSock(linux.AF.INET, linux.SOCK.DGRAM);
    defer _ = linux.close(b);
    const self_pid: u32 = @intCast(linux.getpid());

    // While it walks THIS process the sweep holds two handles of its own
    // (`/proc`, then `/proc/<pid>/fd`), which take the two lowest free numbers;
    // the kernel lists a process's descriptors in ascending order.
    var open: [1024]bool = undefined;
    for (&open, 0..) |*o, i| o.* = fdOpen(i);
    var lows: [2]usize = undefined;
    var nl: usize = 0;
    for (open, 0..) |o, i| {
        if (!o and nl < 2) {
            lows[nl] = i;
            nl += 1;
        }
    }
    if (nl < 2) return error.SkipZigTest;
    open[lows[0]] = true;
    open[lows[1]] = true;
    var order: [1024]usize = undefined;
    var n: usize = 0;
    for (open, 0..) |o, i| {
        if (o) {
            order[n] = i;
            n += 1;
        }
    }
    var first_sock: usize = n;
    for (order[0..n], 0..) |fd, pos| {
        if (fdIsSocket(io, fd)) {
            first_sock = pos;
            break;
        }
    }
    try testing.expect(first_sock < n);

    var k: usize = 0;
    while (k <= @min(n, first_sock + 4)) : (k += 1) {
        var expected: usize = 0;
        for (order[0..k]) |fd| {
            if (fdIsSocket(io, fd)) expected += 1;
        }
        var r = try process.indexSocketOwners(gpa, io, .{ .max_fds_per_process = k });
        defer r.deinit(gpa);
        var mine: usize = 0;
        for (r.owners) |o| {
            if (o.pid == self_pid) mine += 1;
        }
        try testing.expectEqual(expected, mine);
    }
}

/// Move `fd` to a number above every descriptor this process normally holds, so
/// it is the last one a walk of the process reaches.
fn highFd(fd: i32) !i32 {
    defer _ = linux.close(fd);
    const rc = linux.fcntl(fd, linux.F.DUPFD, 600);
    if (linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
    return @intCast(rc);
}

test "indexSocketOwners: a max_owners cap ends the walk at the process that fills it; /proc entries that are not pids are not scanned (mutation audit)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const gpa = testing.allocator;
    const a = try highFd(try mkSock(linux.AF.INET, linux.SOCK.STREAM));
    defer _ = linux.close(a);
    const b = try highFd(try mkSock(linux.AF.INET, linux.SOCK.DGRAM));
    defer _ = linux.close(b);
    const self_pid: u32 = @intCast(linux.getpid());

    // A process with a higher pid, holding the same sockets: the walk visits
    // pids in ascending order, so a cap met inside this process must keep it
    // from ever reaching the child.
    const frc = linux.fork();
    if (linux.errno(frc) != .SUCCESS) return error.SkipZigTest;
    if (frc == 0) {
        while (true) _ = linux.pause();
    }
    const child: linux.pid_t = @intCast(frc);
    defer {
        _ = linux.kill(child, .KILL);
        var st: i32 = 0;
        _ = linux.waitpid(child, &st, 0);
    }

    // The machine moves under a sweep: retry until two full sweeps around the
    // capped ones agree, else skip.
    var attempt: usize = 0;
    while (attempt < 10) : (attempt += 1) {
        const before = try countProcDirs(io, self_pid);
        var full = try process.indexSocketOwners(gpa, io, .{});
        defer full.deinit(gpa);
        var c_self: usize = 0;
        for (full.owners) |o| {
            if (o.pid <= self_pid) c_self += 1;
        }
        // Owners of every process up to and including this one; this process's
        // sockets are its highest descriptors, so the cap is met by its last
        // descriptor and nothing in it is left to trip the per-fd guard.
        var capped = try process.indexSocketOwners(gpa, io, .{ .max_owners = c_self });
        defer capped.deinit(gpa);
        var lower = try process.indexSocketOwners(gpa, io, .{ .max_owners = c_self -| 1 });
        defer lower.deinit(gpa);
        var full2 = try process.indexSocketOwners(gpa, io, .{});
        defer full2.deinit(gpa);
        var c_self2: usize = 0;
        for (full2.owners) |o| {
            if (o.pid <= self_pid) c_self2 += 1;
        }
        if (full.owners.len != full2.owners.len or c_self != c_self2 or full.truncated or c_self < 2) continue;

        // Only numeric /proc entries are processes (`self`, `net`, `sys` ... are not).
        try testing.expect(full.scanned + full.denied + full.vanished <= before.le + before.gt + 16);
        try testing.expect(capped.truncated);
        try testing.expectEqual(c_self, capped.owners.len);
        // The walk stopped at this process: the child above it was not visited.
        try testing.expect(capped.scanned + capped.denied + capped.vanished <= before.le);
        try testing.expect(lower.truncated);
        try testing.expectEqual(c_self - 1, lower.owners.len);
        return;
    }
    return error.SkipZigTest;
}

test "indexSocketOwners: a descriptor-exhausted open is a denied process and a partial sweep (mutation audit)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var f: usize = 0;
    while (f < 4096 and fdOpen(f)) f += 1;
    var old: linux.rlimit = undefined;
    if (linux.errno(linux.getrlimit(.NOFILE, &old)) != .SUCCESS) return error.SkipZigTest;
    var low = old;
    low.cur = f + 1; // exactly one descriptor left: the sweep's `/proc` handle takes it
    if (low.cur > old.max or linux.errno(linux.setrlimit(.NOFILE, &low)) != .SUCCESS) return error.SkipZigTest;
    const res = process.indexSocketOwners(testing.allocator, io, .{});
    _ = linux.setrlimit(.NOFILE, &old);
    const idx = try res;
    defer idx.deinit(testing.allocator);
    if (idx.scanned == 0 and idx.denied == 0 and !idx.truncated) return error.SkipZigTest; // `/proc` itself would not open
    try testing.expectEqual(@as(u32, 0), idx.scanned);
    try testing.expect(idx.denied >= 1);
    try testing.expect(idx.truncated);
}

test "readSockets: a table past the read limit is reported truncated and ends on a whole row (mutation audit)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const gpa = testing.allocator;
    const max_socks: usize = 9000;
    var old: linux.rlimit = undefined;
    if (linux.errno(linux.getrlimit(.NOFILE, &old)) != .SUCCESS) return error.SkipZigTest;
    if (old.max < max_socks + 256) return error.SkipZigTest;
    var raised = old;
    raised.cur = @max(old.cur, max_socks + 256);
    if (linux.errno(linux.setrlimit(.NOFILE, &raised)) != .SUCCESS) return error.SkipZigTest;
    defer _ = linux.setrlimit(.NOFILE, &old);

    const fds = try gpa.alloc(i32, max_socks);
    defer gpa.free(fds);
    var n: usize = 0;
    defer for (fds[0..n]) |fd| {
        _ = linux.close(fd);
    };
    var over = false;
    while (n < max_socks and !over) {
        var batch: usize = 0;
        while (batch < 500 and n < max_socks) : (batch += 1) {
            fds[n] = mkSock(linux.AF.INET, linux.SOCK.DGRAM) catch return error.SkipZigTest;
            n += 1;
        }
        const probe = procnet.readVirtualFileReporting(gpa, io, "/proc/net/udp", procnet.sockets.socket_table_read_limit) orelse return error.SkipZigTest;
        over = probe.truncated;
        gpa.free(probe.bytes);
    }
    if (!over) return error.SkipZigTest;

    const inode_of_port = try gpa.alloc(u64, 65536);
    defer gpa.free(inode_of_port);
    @memset(inode_of_port, 0);
    for (fds[0..n]) |fd| inode_of_port[sockPort(fd, linux.AF.INET)] = try inodeOfFd(io, fd);

    const t = try procnet.readSockets(gpa, io);
    defer t.deinit(gpa);
    try testing.expect(t.truncated);
    var ours: usize = 0;
    for (t.entries) |e| {
        if (e.proto != .udp or e.local != .v4 or !std.mem.eql(u8, &e.local.v4, &[4]u8{ 127, 0, 0, 1 })) continue;
        const want = inode_of_port[e.local_port];
        if (want == 0) continue;
        ours += 1;
        // A row cut inside its inode digits would still parse, with the wrong inode.
        try testing.expectEqual(want, e.inode);
    }
    try testing.expect(ours > 1000);
}
