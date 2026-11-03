// SPDX-License-Identifier: MIT
//! Path -> containing mount over an already-parsed mount table: `df FILE` /
//! `findmnt -T FILE` without the second process, and "is this path a mount
//! point" (`mountpoint(1)`).
//!
//! **Lexical, by design.** The answer is computed from the table and the path
//! text alone: no file is opened and no symlink followed, so it works on a
//! saved snapshot and cannot hang on a dead network mount. `.`, empty and
//! `..` components are folded (a `..` above `/` stays at `/`), but a symlink
//! in the path is NOT resolved: `/var/run/x` on a system where `/var/run` ->
//! `/run` is answered for `/var`, not for `/run`. A caller that needs the
//! symlink-resolved answer resolves the path first (`realpath`) and passes the
//! result. The path must be absolute, as every `mount_point` is.
//!
//! **Which mount wins.** The longest `mount_point` that is a component-wise
//! prefix of the path; of equal length the LAST table entry (a later mount on
//! the same directory covers an earlier one, and the kernel lists a stack
//! bottom to top). Not modelled: a mount hidden because a LATER mount covers one
//! of its ancestor directories (`/a/b` mounted, then `/a` mounted over it) is
//! still reported for paths below `/a/b`; telling those apart needs the
//! `mountinfo` parent/child ids and `findmnt` itself does it from the kernel's
//! tree. That is rare on a real host and wrong only in that case.
//!
//! Works on `mounts.MountEntry` and `mountinfo.MountinfoEntry` alike (anything
//! with a `mount_point: []const u8` field), never allocates and never panics
//! on a hostile table: a mount point that is not a normalized absolute path
//! simply never matches, except that trailing slashes are ignored.

const std = @import("std");

pub const LookupError = error{
    /// The path is not absolute (does not start with `/`).
    RelativePath,
    /// The path contains a NUL byte (not a path the kernel could name).
    InvalidPath,
    /// The path is longer than `max_path` (Linux `PATH_MAX`).
    NameTooLong,
};

/// Linux `PATH_MAX`, the longest path `containing` accepts (without a NUL).
pub const max_path = 4095;

/// Fold `.`, empty and `..` components of the absolute `path` into `buf`;
/// returns the normalized slice (`/` for the root, no trailing slash).
pub fn normalize(path: []const u8, buf: *[max_path]u8) LookupError![]const u8 {
    if (path.len == 0 or path[0] != '/') return error.RelativePath;
    if (std.mem.findScalar(u8, path, 0) != null) return error.InvalidPath;
    if (path.len > max_path) return error.NameTooLong;
    var n: usize = 0;
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |c| {
        if (c.len == 0 or std.mem.eql(u8, c, ".")) continue;
        if (std.mem.eql(u8, c, "..")) {
            // Drop the last component: back to the previous '/'.
            while (n > 0 and buf[n - 1] != '/') n -= 1;
            if (n > 0) n -= 1; // the '/' itself
            continue;
        }
        // Folding only ever shortens, so this stays within `path.len`, but a
        // component list like "/a" is bounded by the input length anyway.
        buf[n] = '/';
        @memcpy(buf[n + 1 ..][0..c.len], c);
        n += 1 + c.len;
    }
    if (n == 0) {
        buf[0] = '/';
        return buf[0..1];
    }
    return buf[0..n];
}

fn trimmed(mp: []const u8) []const u8 {
    var m = mp;
    while (m.len > 1 and m[m.len - 1] == '/') m = m[0 .. m.len - 1];
    return m;
}

/// True when `mp` (trailing slashes ignored) is `path` or one of its ancestors.
fn covers(mp_raw: []const u8, path: []const u8) bool {
    const mp = trimmed(mp_raw);
    if (mp.len == 0 or mp[0] != '/') return false;
    if (mp.len == 1) return true; // "/"
    if (!std.mem.startsWith(u8, path, mp)) return false;
    return path.len == mp.len or path[mp.len] == '/';
}

/// Index of the entry whose mount contains `path`, or null when no entry's
/// mount point covers it (an empty table, or a table without `/`).
pub fn containing(entries: anytype, path: []const u8) LookupError!?usize {
    var buf: [max_path]u8 = undefined;
    const p = try normalize(path, &buf);
    var best: ?usize = null;
    var best_len: usize = 0;
    for (entries, 0..) |e, i| {
        const mp: []const u8 = e.mount_point;
        if (!covers(mp, p)) continue;
        const l = trimmed(mp).len;
        if (best == null or l >= best_len) {
            best = i;
            best_len = l;
        }
    }
    return best;
}

/// True when some entry's mount point IS `path` (after the same folding): the
/// table-only `mountpoint(1)`. A bind mount or a stacked mount counts; so does
/// the root (`/`) whenever the table lists it.
pub fn isMountPoint(entries: anytype, path: []const u8) LookupError!bool {
    var buf: [max_path]u8 = undefined;
    const p = try normalize(path, &buf);
    for (entries) |e| {
        const mp = trimmed(e.mount_point);
        if (std.mem.eql(u8, mp, p)) return true;
    }
    return false;
}

const testing = std.testing;

const Fake = struct { mount_point: []const u8 };

test "normalize: folds ., .., // and trailing slashes; refuses relative, NUL, too long" {
    var b: [max_path]u8 = undefined;
    const cases = [_][2][]const u8{
        .{ "/", "/" },
        .{ "//", "/" },
        .{ "/a/b/", "/a/b" },
        .{ "/a//b/./c", "/a/b/c" },
        .{ "/a/b/../c", "/a/c" },
        .{ "/a/b/../../..", "/" },
        .{ "/..", "/" },
        .{ "/../../a", "/a" },
        .{ "/a/..b/c", "/a/..b/c" },
        .{ "/a/b/..", "/a" },
        .{ "/.", "/" },
        .{ "/a/...", "/a/..." },
    };
    for (cases) |c| try testing.expectEqualStrings(c[1], try normalize(c[0], &b));
    try testing.expectError(error.RelativePath, normalize("", &b));
    try testing.expectError(error.RelativePath, normalize("a/b", &b));
    try testing.expectError(error.InvalidPath, normalize("/a\x00b", &b));
    var long_buf: [max_path + 1]u8 = @splat('x');
    long_buf[0] = '/';
    const long: []const u8 = &long_buf;
    try testing.expectError(error.NameTooLong, normalize(long, &b));
    try testing.expectEqual(@as(usize, max_path), (try normalize(long[0..max_path], &b)).len);
}

test "containing: longest prefix at a component boundary, last entry wins a tie" {
    const t = [_]Fake{
        .{ .mount_point = "/" },
        .{ .mount_point = "/var" },
        .{ .mount_point = "/var/log" },
        .{ .mount_point = "/var/lib" },
        .{ .mount_point = "/var/log" }, // stacked on the earlier /var/log
        .{ .mount_point = "/mnt/data disk" },
    };
    try testing.expectEqual(@as(?usize, 0), try containing(&t, "/"));
    try testing.expectEqual(@as(?usize, 0), try containing(&t, "/etc/passwd"));
    try testing.expectEqual(@as(?usize, 1), try containing(&t, "/var"));
    try testing.expectEqual(@as(?usize, 1), try containing(&t, "/var/cache/x"));
    // Component boundary: /var/logs is not under /var/log.
    try testing.expectEqual(@as(?usize, 1), try containing(&t, "/var/logs"));
    try testing.expectEqual(@as(?usize, 4), try containing(&t, "/var/log"));
    try testing.expectEqual(@as(?usize, 4), try containing(&t, "/var/log/syslog"));
    try testing.expectEqual(@as(?usize, 3), try containing(&t, "/var/lib/x/../y"));
    try testing.expectEqual(@as(?usize, 1), try containing(&t, "/var/log/.."));
    try testing.expectEqual(@as(?usize, 0), try containing(&t, "/var/../etc"));
    try testing.expectEqual(@as(?usize, 5), try containing(&t, "/mnt/data disk/f"));
    try testing.expectEqual(@as(?usize, 0), try containing(&t, "/mnt/data"));
    try testing.expectError(error.RelativePath, containing(&t, "var"));
}

test "containing: empty table, no root entry, hostile mount points" {
    const none = [_]Fake{};
    try testing.expectEqual(@as(?usize, null), try containing(&none, "/x"));
    const noroot = [_]Fake{ .{ .mount_point = "/a" }, .{ .mount_point = "" }, .{ .mount_point = "rel" }, .{ .mount_point = "//" } };
    try testing.expectEqual(@as(?usize, 3), try containing(&noroot, "/zzz")); // "//" is root once trailing slashes go
    try testing.expectEqual(@as(?usize, 0), try containing(&noroot, "/a/b"));
    const bad = [_]Fake{ .{ .mount_point = "" }, .{ .mount_point = "rel" }, .{ .mount_point = "/a/../b" } };
    try testing.expectEqual(@as(?usize, null), try containing(&bad, "/b")); // not normalized: never matches
    // Trailing slashes in a mount point are ignored.
    const ts = [_]Fake{.{ .mount_point = "/a///" }};
    try testing.expectEqual(@as(?usize, 0), try containing(&ts, "/a/x"));
}

test "isMountPoint: exact, folded, stacked, root" {
    const t = [_]Fake{ .{ .mount_point = "/" }, .{ .mount_point = "/var/log" } };
    try testing.expect(try isMountPoint(&t, "/"));
    try testing.expect(try isMountPoint(&t, "/var/log"));
    try testing.expect(try isMountPoint(&t, "/var/./log/"));
    try testing.expect(try isMountPoint(&t, "/var/x/../log"));
    try testing.expect(!(try isMountPoint(&t, "/var")));
    try testing.expect(!(try isMountPoint(&t, "/var/log/x")));
    try testing.expectError(error.RelativePath, isMountPoint(&t, "var/log"));
    const none = [_]Fake{};
    try testing.expect(!(try isMountPoint(&none, "/")));
}

test "containing: works on the real parsers' entry types" {
    const mounts = @import("mounts.zig");
    const mountinfo = @import("mountinfo.zig");
    const text = @embedFile("testdata/mounts_sample.txt");
    const ents = try mounts.parseMounts(testing.allocator, text);
    defer mounts.freeAll(testing.allocator, ents);
    const i = (try containing(ents, "/")).?;
    try testing.expectEqualStrings("/", ents[i].mount_point);
    const info = try mountinfo.parseMountinfo(testing.allocator, @embedFile("testdata/mountinfo_sample.txt"));
    defer mountinfo.freeAll(testing.allocator, info);
    const j = (try containing(info, "/")).?;
    try testing.expectEqualStrings("/", info[j].mount_point);
    try testing.expect(try isMountPoint(info, "/"));
}
