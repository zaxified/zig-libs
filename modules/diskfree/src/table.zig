// SPDX-License-Identifier: MIT
//! "Every mount with its usage" in one call: the `df` listing (`df`, `df -a`,
//! `df -l`) as data. What `gopsutil`'s `disk.Partitions` + `disk.Usage` and
//! `sysinfo`'s `Disks` give in one call, built from the module's own pieces:
//! the mount table (`mounts`), one `statfs` per mount point (`statfs`), the
//! type-name filter (`classify`).
//!
//! The walk is bounded: a 1 MiB mount table can list ~130k rows and each costs
//! a `statfs` (which a dead network mount can block), so at most
//! `Options.max_mounts` mounts (after the type filters) are queried and the result says
//! when it cut (`Table.truncated`). Entries naming the same mount point are one
//! row: the LAST one, the mount on top, which is what a `statfs` of that path
//! answers for. A mount whose `statfs` fails (unmounted since the read, no
//! permission) is left out, as `df` leaves it out with a warning.

const std = @import("std");
const statfs = @import("statfs.zig");
const mounts = @import("mounts.zig");
const classify = @import("classify.zig");
const lookup = @import("lookup.zig");
const mountinfo = @import("mountinfo.zig");

/// Types GNU df 9.7 hides from its default listing on the development host
/// (squashfs loop mounts, devtmpfs; measured, `tools/df-where-diff.sh`), though
/// they hold real blocks. NOT the default here: OpenWrt's root is squashfs and
/// a consumer like axp lists it. Pass as `Options.skip_fs_types` for `df`'s view.
pub const df_default_skip = [_][]const u8{ "squashfs", "devtmpfs" };

pub const Options = struct {
    /// `df -a`: also list kernel-virtual filesystems (`classify.isPseudo`) and
    /// mounts with no blocks at all. Default off, as `df`.
    include_pseudo: bool = false,
    /// `df -l`: drop network filesystems (`classify.isRemote`) BEFORE their
    /// `statfs` is made, so a dead NFS server is never asked. Default off.
    local_only: bool = false,
    /// Most mounts QUERIED: the cap counts the mounts that pass the type
    /// filters (pseudo, network), not every table row, so a host with hundreds
    /// of snap/cgroup/pseudo mounts cannot push the real ones past it. The rest
    /// set `Table.truncated`. Default 512.
    max_mounts: usize = 512,
    /// `df -x TYPE`: fs types never listed (exact `fs_type` match), applied with
    /// the other filters. Default none. `df_default_skip` is what GNU df 9.7
    /// leaves out of its default view on the development host.
    skip_fs_types: []const []const u8 = &.{},
    /// The same table parsed as mountinfo, entry for entry (`tree[i]` describes
    /// `entries[i]`): lets `collectWith` skip mounts covered by a later mount.
    tree: ?[]const mountinfo.MountinfoEntry = null,
    /// `readTable` only: how much of `/proc/self/mounts` to read. Default 1 MiB
    /// (`mounts.mount_table_read_limit`); a cut sets `Table.read_truncated`.
    read_limit: usize = mounts.mount_table_read_limit,
    /// `collect`/`collectWith` only: the caller read `entries` with a cut (from
    /// `mounts.Read.truncated`); copied into `Table.read_truncated`.
    input_truncated: bool = false,
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
    /// The listing is incomplete: more mounts passed the filters than
    /// `Options.max_mounts`, OR the table itself was cut at the read limit
    /// (`read_truncated`; stacked and deeper mounts are at the END of the file).
    truncated: bool,
    /// The mount table was cut at the read limit (a subset of `truncated`).
    read_truncated: bool = false,

    pub fn deinit(t: Table, gpa: std.mem.Allocator) void {
        gpa.free(t.rows);
    }
};

/// A table and the mount table its rows borrow from, freed together.
pub const Owned = struct {
    infos: []mountinfo.MountinfoEntry,
    /// `infos` as plain mount entries (device = the mount source), borrowed.
    entries: []mounts.MountEntry,
    table: Table,

    pub fn deinit(o: Owned, gpa: std.mem.Allocator) void {
        o.table.deinit(gpa);
        gpa.free(o.entries);
        mountinfo.freeAll(gpa, o.infos);
    }
};

/// Build the listing from already-read `entries`. `queryFn(path)` is
/// `statfs.query` (a parameter so tests and callers with another source of
/// numbers can supply their own).
///
/// Which rows: one per distinct mount point (the LAST entry, the mount on
/// top); entries whose mount point is not a canonical absolute path (`lookup.isCanonical`) are skipped
/// (a relative `rel` would make `statfs` answer for a directory of the CALLER's
/// cwd); a mount covered by a later mount on one of its ancestor directories
/// is skipped when `Options.tree` is given (its path now belongs to the covering
/// filesystem, so a `statfs` would report ANOTHER filesystem's numbers under this
/// device). Without the mount tree (plain `/proc/self/mounts` entries have no ids)
/// that case cannot be seen and the covered mount is listed with the covering
/// filesystem's numbers: `readTable` always supplies the tree. Then the type
/// filters, then the `max_mounts` cap, in table order.
pub fn collectWith(gpa: std.mem.Allocator, entries: []const mounts.MountEntry, opts: Options, comptime queryFn: anytype) std.mem.Allocator.Error!Table {
    // One row per distinct mount point: the LAST entry (the mount on top), at ITS
    // position in the table (so "a later entry" means a later mount).
    var last: std.StringHashMapUnmanaged(usize) = .empty;
    defer last.deinit(gpa);
    for (entries, 0..) |e, i| {
        if (!lookup.isCanonical(e.mount_point)) continue;
        try last.put(gpa, e.mount_point, i);
    }
    var kept: std.ArrayList(usize) = .empty;
    defer kept.deinit(gpa);
    for (entries, 0..) |e, i| {
        if (last.get(e.mount_point)) |w| if (w == i) try kept.append(gpa, i);
    }
    // A tree that is not entry-for-entry with `entries` is ignored, never indexed.
    const tree: ?[]const mountinfo.MountinfoEntry = if (opts.tree) |t| (if (t.len == entries.len) t else null) else null;
    var rows: std.ArrayList(Row) = .empty;
    errdefer rows.deinit(gpa);
    var truncated = false;
    var candidates: usize = 0; // bounds the tree lookups to max_mounts of them
    for (kept.items) |i| {
        const e = entries[i];
        if (!opts.include_pseudo and classify.isPseudo(e.fs_type)) continue;
        if (opts.local_only and classify.isRemote(e.fs_type, e.device)) continue;
        if (skipped(opts.skip_fs_types, e.fs_type)) continue;
        if (candidates >= opts.max_mounts) {
            truncated = true;
            continue;
        }
        candidates += 1;
        if (tree) |t| {
            const top = lookup.containing(t, e.mount_point) catch null;
            if (top == null or top.? != i) continue; // covered by a later mount
        }
        const u = queryFn(e.mount_point) catch continue;
        if (!opts.include_pseudo and u.blocks_total == 0) continue;
        try rows.append(gpa, .{ .device = e.device, .mount_point = e.mount_point, .fs_type = e.fs_type, .usage = u });
    }
    return .{
        .rows = try rows.toOwnedSlice(gpa),
        .truncated = truncated or opts.input_truncated,
        .read_truncated = opts.input_truncated,
    };
}

fn skipped(list: []const []const u8, fs_type: []const u8) bool {
    for (list) |t| if (std.mem.eql(u8, t, fs_type)) return true;
    return false;
}

/// `collectWith` over `statfs.query`.
pub fn collect(gpa: std.mem.Allocator, entries: []const mounts.MountEntry, opts: Options) std.mem.Allocator.Error!Table {
    return collectWith(gpa, entries, opts, statfs.query);
}

/// Read `/proc/self/mountinfo` (at most `opts.read_limit`) and list it, with the
/// mount tree so covered mounts are left out. `null` when it cannot be read
/// (`/proc` not mounted). A cut read sets `table.read_truncated`. Row devices are
/// the mount sources.
pub fn readTable(gpa: std.mem.Allocator, io: std.Io, opts: Options) !?Owned {
    const r = (try mountinfo.readMountinfoLimited(gpa, io, opts.read_limit)) orelse return null;
    errdefer r.deinit(gpa);
    const view = try gpa.alloc(mounts.MountEntry, r.entries.len);
    errdefer gpa.free(view);
    for (r.entries, view) |i, *v| v.* = .{ .device = i.mount_source, .mount_point = i.mount_point, .fs_type = i.fs_type, .options = i.options };
    var o = opts;
    o.input_truncated = r.truncated;
    o.tree = r.entries;
    const t = try collect(gpa, view, o);
    return .{ .infos = r.entries, .entries = view, .table = t };
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

test "collectWith: relative and non-canonical mount points are never queried" {
    const g = testing.allocator;
    const es = [_]mounts.MountEntry{
        ent("d", "/", "ext4"),
        ent("d", "rel", "ext4"),
        ent("d", "/a/../b", "ext4"),
        ent("d", "/a/", "ext4"),
        ent("d", "/under", "xfs"),
    };
    query_count = 0;
    const t = try collectWith(g, &es, .{}, countingQuery);
    defer t.deinit(g);
    // Only "/" and "/under" are queried.
    try testing.expectEqual(@as(usize, 2), t.rows.len);
    try testing.expectEqual(@as(usize, 2), query_count);
    try testing.expectEqualStrings("/under", t.rows[1].mount_point);
}

test "collectWith: with the mount tree, a mount covered by a later ancestor mount is not listed" {
    const g = testing.allocator;
    const es = [_]mounts.MountEntry{
        ent("r", "/", "ext4"),
        ent("i", "/h/inner", "tmpfs"),
        ent("h", "/h", "tmpfs"), // mounted after /h/inner: covers it
        ent("a1", "/a", "tmpfs"),
        ent("a2", "/a", "xfs"), // stacked on /a
    };
    const info = try mountinfo.parseMountinfo(g, "1 0 0:1 / / rw - ext4 r rw\n2 1 0:2 / /h/inner rw - tmpfs i rw\n3 1 0:3 / /h rw - tmpfs h rw\n4 1 0:4 / /a rw - tmpfs a1 rw\n5 4 0:5 / /a rw - xfs a2 rw\n");
    defer mountinfo.freeAll(g, info);
    const t = try collectWith(g, &es, .{ .tree = info }, fakeQuery);
    defer t.deinit(g);
    try testing.expectEqual(@as(usize, 3), t.rows.len);
    try testing.expectEqualStrings("/", t.rows[0].mount_point);
    try testing.expectEqualStrings("/h", t.rows[1].mount_point);
    try testing.expectEqualStrings("/a", t.rows[2].mount_point);
    try testing.expectEqualStrings("a2", t.rows[2].device);
}

test "readTable: a tiny read limit cuts the table and the table says so" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const o = (try readTable(testing.allocator, threaded.io(), .{ .read_limit = 100 })) orelse return error.SkipZigTest;
    defer o.deinit(testing.allocator);
    try testing.expect(o.table.read_truncated and o.table.truncated);
    const full = (try readTable(testing.allocator, threaded.io(), .{})) orelse return error.SkipZigTest;
    defer full.deinit(testing.allocator);
    try testing.expect(!full.table.read_truncated);
    try testing.expect(o.entries.len < full.entries.len);
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
