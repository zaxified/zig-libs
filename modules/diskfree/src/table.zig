// SPDX-License-Identifier: MIT
//! "Every mount with its usage" in one call: the `df` listing (`df`, `df -a`,
//! `df -l`) as data. What `gopsutil`'s `disk.Partitions` + `disk.Usage` and
//! `sysinfo`'s `Disks` give in one call, built from the module's own pieces:
//! the mount table (`mounts`), one `statfs` per mount point (`statfs`), the
//! type-name filter (`classify`).
//!
//! The walk is bounded: a 1 MiB mount table can list ~130k rows and each costs
//! a `statfs` (which a dead network mount can block), so at most
//! `Options.max_mounts` DISTINCT mount points are queried and the result says
//! when it cut (`Table.truncated`). Entries naming the same mount point are one
//! row: the LAST one, the mount on top, which is what a `statfs` of that path
//! answers for. A mount whose `statfs` fails (unmounted since the read, no
//! permission) is left out, as `df` leaves it out with a warning.

const std = @import("std");
const statfs = @import("statfs.zig");
const mounts = @import("mounts.zig");
const classify = @import("classify.zig");

pub const Options = struct {
    /// `df -a`: also list kernel-virtual filesystems (`classify.isPseudo`) and
    /// mounts with no blocks at all. Default off, as `df`.
    include_pseudo: bool = false,
    /// `df -l`: drop network filesystems (`classify.isRemote`) BEFORE their
    /// `statfs` is made, so a dead NFS server is never asked. Default off.
    local_only: bool = false,
    /// Most distinct mount points looked at; the rest set `Table.truncated`.
    max_mounts: usize = 512,
};

/// One listed filesystem. The strings borrow from the entries the table was
/// built from.
pub const Row = struct {
    device: []const u8,
    mount_point: []const u8,
    fs_type: []const u8,
    usage: statfs.Usage,
};

pub const Table = struct {
    rows: []Row,
    /// More distinct mount points existed than `Options.max_mounts`.
    truncated: bool,

    pub fn deinit(t: Table, gpa: std.mem.Allocator) void {
        gpa.free(t.rows);
    }
};

/// A table and the entries its rows borrow from, freed together.
pub const Owned = struct {
    entries: []mounts.MountEntry,
    table: Table,

    pub fn deinit(o: Owned, gpa: std.mem.Allocator) void {
        o.table.deinit(gpa);
        mounts.freeAll(gpa, o.entries);
    }
};

/// Build the listing from already-read `entries`. `queryFn(path)` is
/// `statfs.query` (a parameter so tests and callers with another source of
/// numbers can supply their own).
pub fn collectWith(gpa: std.mem.Allocator, entries: []const mounts.MountEntry, opts: Options, comptime queryFn: anytype) std.mem.Allocator.Error!Table {
    // One slot per distinct mount point, first-seen order, last entry wins.
    var seen: std.StringHashMapUnmanaged(usize) = .empty;
    defer seen.deinit(gpa);
    var kept: std.ArrayList(mounts.MountEntry) = .empty;
    defer kept.deinit(gpa);
    var truncated = false;
    for (entries) |e| {
        if (seen.get(e.mount_point)) |i| {
            kept.items[i] = e;
        } else if (kept.items.len >= opts.max_mounts) {
            truncated = true;
        } else {
            try seen.put(gpa, e.mount_point, kept.items.len);
            try kept.append(gpa, e);
        }
    }
    var rows: std.ArrayList(Row) = .empty;
    errdefer rows.deinit(gpa);
    for (kept.items) |e| {
        if (!opts.include_pseudo and classify.isPseudo(e.fs_type)) continue;
        if (opts.local_only and classify.isRemote(e.fs_type, e.device)) continue;
        const u = queryFn(e.mount_point) catch continue;
        if (!opts.include_pseudo and u.blocks_total == 0) continue;
        try rows.append(gpa, .{ .device = e.device, .mount_point = e.mount_point, .fs_type = e.fs_type, .usage = u });
    }
    return .{ .rows = try rows.toOwnedSlice(gpa), .truncated = truncated };
}

/// `collectWith` over `statfs.query`.
pub fn collect(gpa: std.mem.Allocator, entries: []const mounts.MountEntry, opts: Options) std.mem.Allocator.Error!Table {
    return collectWith(gpa, entries, opts, statfs.query);
}

/// Read `/proc/self/mounts` and list it. `null` when it cannot be read (`/proc`
/// not mounted), as `mounts.readMounts`.
pub fn readTable(gpa: std.mem.Allocator, io: std.Io, opts: Options) !?Owned {
    const entries = (try mounts.readMounts(gpa, io)) orelse return null;
    errdefer mounts.freeAll(gpa, entries);
    const t = try collect(gpa, entries, opts);
    return .{ .entries = entries, .table = t };
}

const testing = std.testing;

fn fakeQuery(path: []const u8) statfs.StatfsError!statfs.Usage {
    const base: statfs.Usage = .{
        .block_size = 4096,
        .fragment_size = 4096,
        .blocks_total = 100,
        .blocks_free = 50,
        .blocks_available = 40,
        .inodes_total = 10,
        .inodes_free = 5,
        .fs_type_magic = 0,
        .name_max = 255,
    };
    if (std.mem.eql(u8, path, "/gone")) return error.FileNotFound;
    if (std.mem.eql(u8, path, "/empty")) {
        var u = base;
        u.blocks_total = 0;
        return u;
    }
    var u = base;
    u.blocks_total = 100 + path.len; // a distinct number per mount point
    return u;
}

fn ent(dev: []const u8, mp: []const u8, ty: []const u8) mounts.MountEntry {
    return .{ .device = @constCast(dev), .mount_point = @constCast(mp), .fs_type = @constCast(ty), .options = @constCast("rw") };
}

test "collectWith: df's default view, -a, -l, dedupe by mount point, failures dropped" {
    const es = [_]mounts.MountEntry{
        ent("/dev/sda1", "/", "ext4"),
        ent("proc", "/proc", "proc"),
        ent("srv:/x", "/net", "nfs4"),
        ent("tmpfs", "/tmp", "tmpfs"),
        ent("none", "/empty", "weirdfs"),
        ent("/dev/sdb1", "/gone", "ext4"),
        ent("/dev/sdc1", "/data", "ext4"),
        ent("/dev/sdd1", "/data", "xfs"), // stacked on /data: this one is the row
    };
    const g = testing.allocator;
    {
        const t = try collectWith(g, &es, .{}, fakeQuery);
        defer t.deinit(g);
        try testing.expect(!t.truncated);
        // /proc (pseudo), /empty (no blocks), /gone (statfs fails) are out.
        try testing.expectEqual(@as(usize, 4), t.rows.len);
        try testing.expectEqualStrings("/", t.rows[0].mount_point);
        try testing.expectEqualStrings("/net", t.rows[1].mount_point);
        try testing.expectEqualStrings("/tmp", t.rows[2].mount_point);
        try testing.expectEqualStrings("/data", t.rows[3].mount_point);
        try testing.expectEqualStrings("xfs", t.rows[3].fs_type);
        try testing.expectEqualStrings("/dev/sdd1", t.rows[3].device);
        try testing.expectEqual(@as(u64, 105), t.rows[3].usage.blocks_total);
    }
    {
        const t = try collectWith(g, &es, .{ .include_pseudo = true }, fakeQuery);
        defer t.deinit(g);
        try testing.expectEqual(@as(usize, 6), t.rows.len); // /gone still fails
        try testing.expectEqualStrings("/proc", t.rows[1].mount_point);
        try testing.expectEqual(@as(u64, 0), t.rows[4].usage.blocks_total); // /empty kept
    }
    {
        const t = try collectWith(g, &es, .{ .local_only = true }, fakeQuery);
        defer t.deinit(g);
        try testing.expectEqual(@as(usize, 3), t.rows.len);
        for (t.rows) |r| try testing.expect(!std.mem.eql(u8, r.mount_point, "/net"));
    }
}

var query_count: usize = 0;
fn countingQuery(path: []const u8) statfs.StatfsError!statfs.Usage {
    query_count += 1;
    return fakeQuery(path);
}

test "collectWith: local_only never asks a network mount; max_mounts bounds the walk and says so" {
    const g = testing.allocator;
    const es = [_]mounts.MountEntry{
        ent("a:/x", "/n1", "nfs"),
        ent("//h/s", "/n2", "cifs"),
        ent("/dev/a", "/a", "ext4"),
        ent("/dev/b", "/b", "ext4"),
        ent("/dev/c", "/c", "ext4"),
    };
    query_count = 0;
    {
        const t = try collectWith(g, &es, .{ .local_only = true }, countingQuery);
        defer t.deinit(g);
        try testing.expectEqual(@as(usize, 3), t.rows.len);
        try testing.expectEqual(@as(usize, 3), query_count); // the two network mounts: no statfs
    }
    query_count = 0;
    {
        const t = try collectWith(g, &es, .{ .max_mounts = 3 }, countingQuery);
        defer t.deinit(g);
        try testing.expect(t.truncated);
        try testing.expectEqual(@as(usize, 3), query_count);
        try testing.expectEqual(@as(usize, 3), t.rows.len);
    }
    {
        // A repeated mount point does not count twice against the bound.
        const dup = [_]mounts.MountEntry{ ent("d", "/a", "ext4"), ent("e", "/a", "ext4"), ent("f", "/b", "ext4") };
        const t = try collectWith(g, &dup, .{ .max_mounts = 2 }, fakeQuery);
        defer t.deinit(g);
        try testing.expect(!t.truncated);
        try testing.expectEqual(@as(usize, 2), t.rows.len);
    }
    {
        const t = try collectWith(g, &es, .{ .max_mounts = 0 }, fakeQuery);
        defer t.deinit(g);
        try testing.expect(t.truncated);
        try testing.expectEqual(@as(usize, 0), t.rows.len);
    }
    {
        const none = [_]mounts.MountEntry{};
        const t = try collectWith(g, &none, .{}, fakeQuery);
        defer t.deinit(g);
        try testing.expect(!t.truncated);
        try testing.expectEqual(@as(usize, 0), t.rows.len);
    }
}

test "collectWith: OutOfMemory at any allocation frees everything and propagates" {
    const es = [_]mounts.MountEntry{
        ent("/dev/a", "/", "ext4"),
        ent("/dev/b", "/b", "ext4"),
        ent("/dev/c", "/b", "xfs"),
        ent("/dev/d", "/d", "ext4"),
    };
    var fail_index: usize = 0;
    while (fail_index < 40) : (fail_index += 1) {
        var fa = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = fail_index });
        if (collectWith(fa.allocator(), &es, .{}, fakeQuery)) |t| {
            t.deinit(fa.allocator());
            break;
        } else |e| try testing.expectEqual(error.OutOfMemory, e);
    }
    try testing.expect(fail_index > 0 and fail_index < 40);
}

test "collect over the real statfs: the root filesystem is listed with real numbers" {
    const g = testing.allocator;
    const es = [_]mounts.MountEntry{ent("rootdev", "/", "ext4")};
    const t = try collect(g, &es, .{});
    defer t.deinit(g);
    try testing.expectEqual(@as(usize, 1), t.rows.len);
    try testing.expect(t.rows[0].usage.blocks_total > 0);
    try testing.expect(t.rows[0].usage.blocks_available <= t.rows[0].usage.blocks_total);
}
