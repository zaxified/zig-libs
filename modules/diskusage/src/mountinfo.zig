// SPDX-License-Identifier: MIT
//! `/proc/self/mountinfo` parser (`proc(5)`) — the richer source, and per the
//! reasoning below, generally the better one for anything beyond a `df`-style
//! summary.
//!
//! **Why this file exists alongside `mounts.zig` instead of replacing it.**
//! `mountinfo` carries what `mounts` cannot: the mount ID and parent ID (a
//! real tree, not a flat list — `findmnt`/`libmount` build the mount tree
//! from exactly these two fields), the mount's *root within its filesystem*
//! (distinguishing a bind mount of a subdirectory from the whole
//! filesystem), and `major:minor` (identifies the underlying device/block
//! group without a second syscall). It is also what modern tooling actually
//! reads — `findmnt`, `libmount`, `systemd` all parse `mountinfo`, not
//! `mounts`. `mounts.zig` earns its place anyway: it is the simpler,
//! `fstab`/`mtab`(5)-shaped four-column format a "what is mounted" consumer
//! most often actually wants, it is what `mount`(8)'s traditional output and
//! `/etc/mtab` mirror, and its column order changes only if the kernel
//! breaks four decades of userspace, whereas `mountinfo`'s optional-fields
//! section has grown twice since Linux 2.6.26 introduced it. Cover both,
//! choose per need: `mounts` for "what's mounted and how full", `mountinfo`
//! for anything that needs the tree, the bind-mount root, or the device
//! number.

const std = @import("std");
const mounts = @import("mounts.zig");

/// One `/proc/self/mountinfo` row. String fields are allocator-owned and
/// already unescaped where the kernel escapes them (`root`, `mount_point`,
/// `mount_source` — see `mounts.unescapeOctal`); `options`/`optional_fields`/
/// `super_options` are comma/space-separated tag lists the kernel does not
/// escape (no arbitrary path bytes can appear in them).
pub const MountinfoEntry = struct {
    /// Unique ID for this mount (field 1) — not stable across
    /// unmount/remount, only within one `/proc/self/mountinfo` snapshot.
    mount_id: u32,
    /// ID of the parent mount (field 2); the ID of the mount at
    /// `mount_point`'s parent directory, or `mount_id` itself for the root
    /// of the mount namespace.
    parent_id: u32,
    /// Major device number (field 3, before the `:`).
    dev_major: u32,
    /// Minor device number (field 3, after the `:`).
    dev_minor: u32,
    /// Root of the mount *within its filesystem* (field 4) — `/` for a
    /// normal mount, a subdirectory for a bind mount of less than the whole
    /// filesystem.
    root: []u8,
    /// Mount point relative to the process's root (field 5).
    mount_point: []u8,
    /// Per-mount options (field 6, e.g. `rw,noatime`) — distinct from
    /// `super_options`, which are per-filesystem-instance.
    options: []u8,
    /// Optional fields (field 7, zero or more, e.g. `shared:2`,
    /// `master:1`, `propagate_from:3`, `unbindable`), space-joined verbatim
    /// as they appeared before the `-` separator; empty if none.
    optional_fields: []u8,
    /// Filesystem type (field 9, e.g. `ext4`, `overlay`).
    fs_type: []u8,
    /// Mount source (field 10) — device path or pseudo-name, same role as
    /// `mounts.MountEntry.device`.
    mount_source: []u8,
    /// Per-filesystem-instance super options (field 11, e.g.
    /// `rw,errors=continue`).
    super_options: []u8,

    pub fn free(self: MountinfoEntry, gpa: std.mem.Allocator) void {
        gpa.free(self.root);
        gpa.free(self.mount_point);
        gpa.free(self.options);
        gpa.free(self.optional_fields);
        gpa.free(self.fs_type);
        gpa.free(self.mount_source);
        gpa.free(self.super_options);
    }
};

pub fn freeAll(gpa: std.mem.Allocator, entries: []MountinfoEntry) void {
    for (entries) |e| e.free(gpa);
    gpa.free(entries);
}

/// Parses already-read `/proc/self/mountinfo`-shaped text. Offline, no I/O.
/// A malformed line (too few fields, a missing `-` separator, or a
/// non-numeric ID/major:minor) is skipped, not fatal — matching
/// `mounts.parseMounts` and `procnet`'s parsers.
pub fn parseMountinfo(gpa: std.mem.Allocator, text: []const u8) ![]MountinfoEntry {
    var out: std.ArrayList(MountinfoEntry) = .empty;
    errdefer freeAll(gpa, out.toOwnedSlice(gpa) catch &.{});

    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (parseLine(gpa, line)) |entry| {
            try out.append(gpa, entry);
        } else |_| {
            continue;
        }
    }
    return out.toOwnedSlice(gpa);
}

fn parseLine(gpa: std.mem.Allocator, line: []const u8) !MountinfoEntry {
    var toks = std.mem.tokenizeAny(u8, line, " \t");

    const mount_id = try std.fmt.parseInt(u32, toks.next() orelse return error.Malformed, 10);
    const parent_id = try std.fmt.parseInt(u32, toks.next() orelse return error.Malformed, 10);

    const maj_min = toks.next() orelse return error.Malformed;
    const colon = std.mem.indexOfScalar(u8, maj_min, ':') orelse return error.Malformed;
    const dev_major = try std.fmt.parseInt(u32, maj_min[0..colon], 10);
    const dev_minor = try std.fmt.parseInt(u32, maj_min[colon + 1 ..], 10);

    const root_raw = toks.next() orelse return error.Malformed;
    const mount_point_raw = toks.next() orelse return error.Malformed;
    const options = toks.next() orelse return error.Malformed;

    // Zero or more optional fields, terminated by a bare "-" token.
    var opt_start: ?usize = null;
    var opt_end: usize = 0;
    var found_sep = false;
    while (toks.next()) |tok| {
        if (std.mem.eql(u8, tok, "-")) {
            found_sep = true;
            break;
        }
        if (opt_start == null) opt_start = tokenOffset(line, tok);
        opt_end = tokenOffset(line, tok) + tok.len;
    }
    if (!found_sep) return error.Malformed;
    const optional_fields_raw = if (opt_start) |s| line[s..opt_end] else "";

    const fs_type = toks.next() orelse return error.Malformed;
    const mount_source_raw = toks.next() orelse return error.Malformed;
    const super_options = toks.next() orelse return error.Malformed;

    const root = try mounts.unescapeOctal(gpa, root_raw);
    errdefer gpa.free(root);
    const mount_point = try mounts.unescapeOctal(gpa, mount_point_raw);
    errdefer gpa.free(mount_point);
    const mount_source = try mounts.unescapeOctal(gpa, mount_source_raw);
    errdefer gpa.free(mount_source);

    const options_dup = try gpa.dupe(u8, options);
    errdefer gpa.free(options_dup);
    const optional_fields_dup = try gpa.dupe(u8, optional_fields_raw);
    errdefer gpa.free(optional_fields_dup);
    const fs_type_dup = try gpa.dupe(u8, fs_type);
    errdefer gpa.free(fs_type_dup);
    const super_options_dup = try gpa.dupe(u8, super_options);

    return .{
        .mount_id = mount_id,
        .parent_id = parent_id,
        .dev_major = dev_major,
        .dev_minor = dev_minor,
        .root = root,
        .mount_point = mount_point,
        .options = options_dup,
        .optional_fields = optional_fields_dup,
        .fs_type = fs_type_dup,
        .mount_source = mount_source,
        .super_options = super_options_dup,
    };
}

/// Byte offset of `tok` within `line`, assuming `tok` is a slice of `line`
/// (always true for tokens returned by `std.mem.tokenizeAny` over `line`).
fn tokenOffset(line: []const u8, tok: []const u8) usize {
    return @intFromPtr(tok.ptr) - @intFromPtr(line.ptr);
}

/// Reads and parses `/proc/self/mountinfo`. `null` on a missing/unreadable
/// file (e.g. `/proc` not mounted) — not an error, matching
/// `mounts.readMounts`.
pub fn readMountinfo(gpa: std.mem.Allocator, io: std.Io) !?[]MountinfoEntry {
    const text = readVirtualFile(gpa, io, "/proc/self/mountinfo", 1024 * 1024) orelse return null;
    defer gpa.free(text);
    return try parseMountinfo(gpa, text);
}

fn readVirtualFile(gpa: std.mem.Allocator, io: std.Io, path: []const u8, limit: usize) ?[]u8 {
    var dir = std.Io.Dir.cwd();
    var file = dir.openFile(io, path, .{}) catch return null;
    defer file.close(io);

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = file.read(io, &buf) catch break;
        if (n == 0) break;
        out.appendSlice(gpa, buf[0..n]) catch break;
        if (out.items.len >= limit) break;
    }
    if (out.items.len > limit) out.shrinkRetainingCapacity(limit);
    return out.toOwnedSlice(gpa) catch null;
}

const testing = std.testing;

test "parseMountinfo: real kernel capture" {
    const text = @embedFile("testdata/mountinfo_sample.txt");
    const entries = try parseMountinfo(testing.allocator, text);
    defer freeAll(testing.allocator, entries);

    try testing.expect(entries.len > 0);

    var found_root = false;
    for (entries) |e| {
        if (std.mem.eql(u8, e.mount_point, "/")) {
            found_root = true;
            try testing.expectEqualStrings("ext4", e.fs_type);
            try testing.expectEqualStrings("/", e.root);
            try testing.expect(std.mem.startsWith(u8, e.mount_source, "/dev/"));
            try testing.expect(e.mount_id > 0);
            try testing.expect(e.parent_id > 0);
        }
    }
    try testing.expect(found_root);
}

test "parseMountinfo: optional fields captured, and absent when the row has none" {
    const text = @embedFile("testdata/mountinfo_sample.txt");
    const entries = try parseMountinfo(testing.allocator, text);
    defer freeAll(testing.allocator, entries);

    var found_shared = false;
    var found_none = false;
    for (entries) |e| {
        if (std.mem.indexOf(u8, e.optional_fields, "shared:") != null) found_shared = true;
        if (e.optional_fields.len == 0) found_none = true;
    }
    try testing.expect(found_shared);
    try testing.expect(found_none);
}

test "parseMountinfo: octal-escaped mount point with a space decodes correctly" {
    const text = @embedFile("testdata/mountinfo_escaped.txt");
    const entries = try parseMountinfo(testing.allocator, text);
    defer freeAll(testing.allocator, entries);

    try testing.expectEqual(@as(usize, 1), entries.len);
    try testing.expectEqualStrings("/mnt/My Backup Drive", entries[0].mount_point);
    try testing.expectEqualStrings("/dev/sdb1", entries[0].mount_source);
    try testing.expectEqual(@as(u32, 42), entries[0].mount_id);
    try testing.expectEqual(@as(u32, 8), entries[0].dev_major);
    try testing.expectEqual(@as(u32, 17), entries[0].dev_minor);
}

test "parseMountinfo: malformed line (no '-' separator) is skipped, not fatal" {
    const text =
        "36 35 98:0 / / rw,noatime shared:1 - ext3 /dev/root rw,errors=continue\n" ++
        "this is not a mountinfo line at all\n" ++
        "37 35 98:1 / /boot rw shared:2 - vfat /dev/root2 rw\n";
    const entries = try parseMountinfo(testing.allocator, text);
    defer freeAll(testing.allocator, entries);
    try testing.expectEqual(@as(usize, 2), entries.len);
}

test "parseMountinfo: empty text yields zero entries, not an error" {
    const entries = try parseMountinfo(testing.allocator, "");
    defer freeAll(testing.allocator, entries);
    try testing.expectEqual(@as(usize, 0), entries.len);
}

// Same threat model as `mounts.zig`'s fuzz harness (see its doc comment):
// `/proc/self/mountinfo` is kernel-emitted but not trusted input in a
// bind-mounted/faked-`/proc` container, and this parser also accepts a
// caller-supplied snapshot file. The numeric-field parsing here
// (`mount_id`/`parent_id`/`major:minor`) is extra surface `mounts.zig`
// doesn't have, and the "-" separator scan is its own bounds-sensitive loop.
const fuzz_fixture = @embedFile("testdata/mountinfo_sample.txt");

test "fuzz: parseMountinfo never panics, OOB or leaks, arbitrary or mutated-real bytes" {
    try std.testing.fuzz({}, fuzzParseMountinfoNeverLeaks, .{ .corpus = &.{fuzz_fixture} });
}

fn fuzzParseMountinfoNeverLeaks(_: void, smith: *std.testing.Smith) !void {
    var buf: [2048]u8 = undefined;
    const text = mutateSample(smith, fuzz_fixture, &buf);
    const entries = try parseMountinfo(testing.allocator, text);
    freeAll(testing.allocator, entries);
}

/// One draw in five is pure arbitrary bytes; the rest mutates the real
/// `/proc/self/mountinfo` capture. Shared shape with `mounts.zig`'s
/// `mutateSample` and `procnet`'s.
fn mutateSample(smith: *std.testing.Smith, sample: []const u8, buf: []u8) []const u8 {
    if (smith.valueRangeAtMost(u8, 0, 4) == 0) {
        smith.bytes(buf);
        const len = smith.valueRangeAtMost(u16, 0, @intCast(buf.len));
        return buf[0..len];
    }
    const len = @min(sample.len, buf.len);
    @memcpy(buf[0..len], sample[0..len]);
    const n_mutations = smith.valueRangeAtMost(u8, 0, 24);
    var i: u8 = 0;
    while (i < n_mutations) : (i += 1) {
        if (len == 0) break;
        buf[smith.index(len)] = smith.value(u8);
    }
    return buf[0..len];
}
