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
//! **Which mount wins.** Two rules, picked by the entry type at compile time:
//!   * `mountinfo.MountinfoEntry` (has `mount_id`/`parent_id`): the real mount
//!     TREE. Start at the last entry mounted on `/`, then repeatedly take the last
//!     child (an entry whose `parent_id` is the current `mount_id`) whose mount
//!     point covers the path. That gets stacked mounts (the upper one is a child of
//!     the lower, same point) and a mount hidden under a LATER mount on an ancestor
//!     directory (`/h/inner`, then `/h` over it: both are children of the same
//!     parent, the later `/h` covers the path, `/h/inner` is never reached) right.
//!     The walk is bounded by the table size, so a hostile parent cycle ends.
//!     Each step scans the table (O(depth x n)); for an untrusted table use `Index` +
//!     `containingIndexed`, which gives the same answer in O(n log n).
//!     Without any entry on `/` (a chroot's table) it falls back to the flat rule.
//!   * anything else (`mounts.MountEntry`, no ids): the longest covering mount
//!     point, the last entry on a tie. A table sorted by kernel mount ID is NOT
//!     in creation or tree order (the real root `/` usually comes after `/proc`,
//!     `/dev`, ...), so "last covering" would be wrong; the flat rule cannot see
//!     a mount hidden under a later ancestor. Use mountinfo when that matters.
//! Checked against `df --output=target` in a user+mount namespace with stacked,
//! bind, space-named and hidden mounts (`tools/df-where-ns.sh`, SPEC "Anchoring").
//!
//! **A cut table.** `mounts.readMounts` keeps at most 1 MiB (whole lines), and
//! stacked and deeper mounts are at the END of the file (ids ascend), so on a cut
//! table the answer can name a shallower ancestor. `locate` carries the reader's
//! `truncated` flag into its `Answer`; `containing` on a bare slice cannot know.
//! Read with `mounts.readMountsLimited`/`mountinfo.readMountinfoLimited` (or
//! `table.readTable`) to get the flag.
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
/// `path` must be normalized (`normalize`); a `mp` that is not a canonical
/// absolute path never covers anything.
pub fn covers(mp_raw: []const u8, path: []const u8) bool {
    const mp = trimmed(mp_raw);
    if (mp.len == 0 or mp[0] != '/') return false;
    if (mp.len == 1) return true; // "/"
    if (!std.mem.startsWith(u8, path, mp)) return false;
    return path.len == mp.len or path[mp.len] == '/';
}

fn ElemOf(comptime T: type) type {
    return switch (@typeInfo(T)) {
        .pointer => |p| switch (@typeInfo(p.child)) {
            .array => |a| a.child,
            else => p.child,
        },
        else => @compileError("lookup: entries must be a slice or a pointer to an array"),
    };
}

/// Index of the entry whose mount contains `path`, or null when no entry's
/// mount point covers it (an empty table, or a table without `/`). See the
/// module doc for the two rules (mount tree for mountinfo entries, longest
/// prefix for plain mount entries).
pub fn containing(entries: anytype, path: []const u8) LookupError!?usize {
    var buf: [max_path]u8 = undefined;
    const p = try normalize(path, &buf);
    if (comptime @hasField(ElemOf(@TypeOf(entries)), "parent_id")) {
        // Tree walk from the last entry mounted on "/".
        var cur: ?usize = null;
        for (entries, 0..) |e, i| {
            const mp: []const u8 = e.mount_point;
            if (std.mem.eql(u8, trimmed(mp), "/")) cur = i;
        }
        var c = cur orelse return flatContaining(entries, p);
        var steps: usize = 0;
        while (steps < entries.len) : (steps += 1) {
            var next: ?usize = null;
            for (entries, 0..) |e, i| {
                if (i == c or e.parent_id != entries[c].mount_id) continue;
                const mp: []const u8 = e.mount_point;
                if (covers(mp, p)) next = i;
            }
            c = next orelse break;
        }
        return c;
    }
    return flatContaining(entries, p);
}

/// A prebuilt index over a mountinfo table for `containingIndexed`: the walk of
/// `containing` with every step answered from a parent-id sorted index instead of
/// a scan of the whole table, and a parent cycle resolved by remembering the
/// visited entries instead of walking it `entries.len` times. Build it ONCE per
/// table and query it many times (`table.collectWith` does); `containing` on a
/// table the kernel wrote needs none of it, but on an untrusted saved table the
/// scan costs O(n^2) per call (a cycle of n entries makes n steps of n compares).
/// Results are identical to `containing` on every table, hostile ones included.
/// Not thread-safe (queries reuse its scratch arrays).
pub const Index = struct {
    /// Entry indices sorted by (`parent_id`, index): the children of one mount are a
    /// contiguous run, in table order.
    by_parent: []usize,
    /// Scratch: step at which an entry was first visited by the current query
    /// (`unseen` otherwise) and the visit order; both are cleaned after a query.
    seen: []usize,
    order: []usize,
    /// The last entry mounted on `/` (null: the flat rule applies).
    root: ?usize,

    const unseen = std.math.maxInt(usize);

    /// Index `entries` (a slice of anything with `mount_id`, `parent_id`, `mount_point`).
    pub fn init(gpa: std.mem.Allocator, entries: anytype) std.mem.Allocator.Error!Index {
        const n = entries.len;
        const by_parent = try gpa.alloc(usize, n);
        errdefer gpa.free(by_parent);
        const seen = try gpa.alloc(usize, n);
        errdefer gpa.free(seen);
        const order = try gpa.alloc(usize, n);
        errdefer gpa.free(order);
        var root: ?usize = null;
        for (entries, 0..) |e, i| {
            by_parent[i] = i;
            seen[i] = unseen;
            const mp: []const u8 = e.mount_point;
            if (std.mem.eql(u8, trimmed(mp), "/")) root = i;
        }
        const Ctx = struct {
            es: @TypeOf(entries),
            fn lessThan(c: @This(), a: usize, b: usize) bool {
                const pa = c.es[a].parent_id;
                const pb = c.es[b].parent_id;
                if (pa != pb) return pa < pb;
                return a < b;
            }
        };
        std.mem.sortUnstable(usize, by_parent, Ctx{ .es = entries }, Ctx.lessThan);
        return .{ .by_parent = by_parent, .seen = seen, .order = order, .root = root };
    }

    pub fn deinit(ix: Index, gpa: std.mem.Allocator) void {
        gpa.free(ix.by_parent);
        gpa.free(ix.seen);
        gpa.free(ix.order);
    }
};

/// `containing` over a table indexed by `Index.init(gpa, entries)` (the SAME
/// `entries`, unchanged): same answer, O(n log n) in the worst case instead of
/// O(n^2). Only for mountinfo entries (the ones with ids).
pub fn containingIndexed(ix: *Index, entries: anytype, path: []const u8) LookupError!?usize {
    comptime std.debug.assert(@hasField(ElemOf(@TypeOf(entries)), "parent_id"));
    std.debug.assert(entries.len == ix.by_parent.len);
    var buf: [max_path]u8 = undefined;
    const p = try normalize(path, &buf);
    var c = ix.root orelse return flatContaining(entries, p);
    const n = entries.len;
    var steps: usize = 0;
    var recorded: usize = 0;
    var result: ?usize = null;
    while (steps < n) : (steps += 1) {
        if (ix.seen[c] != Index.unseen) {
            // A cycle: positions repeat with period `len` from `first`; the original
            // walk stops after `n` steps, at the entry in position `n`.
            const first = ix.seen[c];
            const len = steps - first;
            result = ix.order[first + (n - steps) % len];
            break;
        }
        ix.seen[c] = steps;
        ix.order[steps] = c;
        recorded = steps + 1;
        c = indexNext(ix, entries, c, p) orelse {
            result = c;
            break;
        };
    }
    for (ix.order[0..recorded]) |i| ix.seen[i] = Index.unseen;
    return result orelse c;
}

/// The last child of entry `c` (an entry whose `parent_id` is `c`'s `mount_id`) whose mount point covers `p`.
fn indexNext(ix: *const Index, entries: anytype, c: usize, p: []const u8) ?usize {
    const want = entries[c].mount_id;
    // First position whose parent_id >= want.
    var lo: usize = 0;
    var hi: usize = ix.by_parent.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (entries[ix.by_parent[mid]].parent_id < want) lo = mid + 1 else hi = mid;
    }
    var k = lo;
    while (k < ix.by_parent.len and entries[ix.by_parent[k]].parent_id == want) k += 1;
    // `lo..k` are the children, ascending by index: take the last covering one.
    while (k > lo) {
        k -= 1;
        const i = ix.by_parent[k];
        if (i == c) continue;
        const mp: []const u8 = entries[i].mount_point;
        if (covers(mp, p)) return i;
    }
    return null;
}

fn flatContaining(entries: anytype, p: []const u8) ?usize {
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

/// True when `mp` is exactly what `normalize` makes of it: an absolute path with
/// no `.`/`..`/empty component, no NUL, no trailing slash (except `/`). The shape
/// of every mount point the kernel emits; anything else is hostile or hand-made.
pub fn isCanonical(mp: []const u8) bool {
    var buf: [max_path]u8 = undefined;
    const n = normalize(mp, &buf) catch return false;
    return std.mem.eql(u8, n, mp);
}

/// An answer that knows whether the table it came from was complete.
pub const Answer = struct {
    index: ?usize,
    /// The table was cut at the read limit: `index` may name a shallower
    /// ancestor than the true mount (stacked and deeper mounts come last in
    /// the file), and null may mean "the mount was in the cut part".
    table_truncated: bool,
};

/// `containing` for a table read with `readMountsLimited`/`readMountinfoLimited`
/// (pass its `entries` and `truncated`).
pub fn locate(entries: anytype, truncated: bool, path: []const u8) LookupError!Answer {
    return .{ .index = try containing(entries, path), .table_truncated = truncated };
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

test "containing (flat rule): component boundary, longest prefix, last entry on a tie" {
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
    // A real table is in mount-ID order, which is not tree order: "/" can come last.
    const rootlast = [_]Fake{ .{ .mount_point = "/proc" }, .{ .mount_point = "/dev" }, .{ .mount_point = "/" } };
    try testing.expectEqual(@as(?usize, 0), try containing(&rootlast, "/proc/x"));
    try testing.expectEqual(@as(?usize, 2), try containing(&rootlast, "/etc"));
}

const TFake = struct { mount_id: u32, parent_id: u32, mount_point: []const u8 };

test "containing (mount tree): stacked, hidden under a later ancestor, root listed last, hostile cycles" {
    const t = [_]TFake{
        .{ .mount_id = 28, .parent_id = 34, .mount_point = "/h/inner" }, // 0, covered by 1
        .{ .mount_id = 29, .parent_id = 34, .mount_point = "/h" }, // 1
        .{ .mount_id = 30, .parent_id = 34, .mount_point = "/a" }, // 2
        .{ .mount_id = 31, .parent_id = 30, .mount_point = "/a" }, // 3 stacked on 2
        .{ .mount_id = 32, .parent_id = 31, .mount_point = "/a/b" }, // 4 on the upper /a
        .{ .mount_id = 34, .parent_id = 2, .mount_point = "/" }, // 5 root, listed last
    };
    try testing.expectEqual(@as(?usize, 5), try containing(&t, "/etc"));
    try testing.expectEqual(@as(?usize, 1), try containing(&t, "/h/inner/f")); // hidden: /h wins
    try testing.expectEqual(@as(?usize, 1), try containing(&t, "/h"));
    try testing.expectEqual(@as(?usize, 3), try containing(&t, "/a/x")); // the upper of the stack
    try testing.expectEqual(@as(?usize, 4), try containing(&t, "/a/b/x"));
    var ix = try Index.init(testing.allocator, &t);
    defer ix.deinit(testing.allocator);
    for ([_][]const u8{ "/etc", "/h/inner/f", "/h", "/a/x", "/a/b/x" }) |pp|
        try testing.expectEqual(try containing(&t, pp), try containingIndexed(&ix, &t, pp));
    const cyc = [_]TFake{ .{ .mount_id = 1, .parent_id = 2, .mount_point = "/" }, .{ .mount_id = 2, .parent_id = 1, .mount_point = "/x" }, .{ .mount_id = 3, .parent_id = 3, .mount_point = "/x" } };
    _ = try containing(&cyc, "/x/y");
    const nr = [_]TFake{ .{ .mount_id = 1, .parent_id = 0, .mount_point = "/a" }, .{ .mount_id = 2, .parent_id = 1, .mount_point = "/a/b" } };
    try testing.expectEqual(@as(?usize, 1), try containing(&nr, "/a/b/c"));
}

test "containingIndexed: same answer as containing on random hostile tables (cycles, duplicate ids)" {
    var prng = std.Random.DefaultPrng.init(0x6d6f756e74);
    const r = prng.random();
    const points = [_][]const u8{ "/", "/a", "/a/b", "/h", "/h/inner", "/a/", "rel", "" };
    const paths = [_][]const u8{ "/", "/a", "/a/b/c", "/h/inner/f", "/zzz", "/a/b/../x" };
    var tbl: [24]TFake = undefined;
    var round: usize = 0;
    while (round < 3000) : (round += 1) {
        const n = r.intRangeAtMost(usize, 0, tbl.len);
        const idr = r.intRangeAtMost(u32, 1, @intCast(n + 2));
        for (tbl[0..n]) |*e| e.* = .{
            .mount_id = r.intRangeAtMost(u32, 1, idr),
            .parent_id = r.intRangeAtMost(u32, 0, idr),
            .mount_point = points[r.uintLessThan(usize, points.len)],
        };
        const es = tbl[0..n];
        var ix = try Index.init(testing.allocator, es);
        defer ix.deinit(testing.allocator);
        for (paths) |pp| {
            try testing.expectEqual(try containing(es, pp), try containingIndexed(&ix, es, pp));
            // The scratch is cleaned: a second query on the same index is unchanged.
            try testing.expectEqual(try containing(es, pp), try containingIndexed(&ix, es, pp));
        }
        try testing.expectError(error.RelativePath, containingIndexed(&ix, es, "a"));
    }
}

test "containingIndexed: a parent cycle through every entry of a large table is answered" {
    // The root (index 0, id 1) is its own descendant: 1 -> 2 -> 3 -> ... -> n -> 1.
    // `containing` would need n steps of n compares each (9e8 for this n); the index
    // makes it n small steps. The walk stops after n steps, at position n = the root.
    const gpa = testing.allocator;
    const n: usize = 30000;
    const es = try gpa.alloc(TFake, n);
    defer gpa.free(es);
    for (es, 0..) |*e, i| e.* = .{
        .mount_id = @intCast(i + 1),
        .parent_id = if (i == 0) @intCast(n) else @intCast(i),
        .mount_point = if (i == 0) "/" else "/x",
    };
    var ix = try Index.init(gpa, es);
    defer ix.deinit(gpa);
    try testing.expectEqual(@as(?usize, 0), try containingIndexed(&ix, es, "/x/y"));
    try testing.expectEqual(@as(?usize, 0), try containingIndexed(&ix, es, "/other"));
    // The same table without the back edge: the deepest mount (the last entry) wins.
    es[0].parent_id = 0;
    ix.deinit(gpa);
    ix = try Index.init(gpa, es);
    try testing.expectEqual(@as(?usize, n - 1), try containingIndexed(&ix, es, "/x/y"));
}

test "containingIndexed: two entries that are each other's covering child, behind many non-covering children" {
    // Entries 1..3 share mount id 2; 2 and 3 are children of id 2 (so of each other and
    // of themselves): the walk alternates between them, and every step meets all the
    // junk children of id 2 first. The index stops after the first repeat.
    const gpa = testing.allocator;
    for ([_]usize{ 0, 1, 2, 3, 7, 40, 20000 }) |junk| {
        const es = try gpa.alloc(TFake, 4 + junk);
        defer gpa.free(es);
        es[0] = .{ .mount_id = 1, .parent_id = 0, .mount_point = "/" };
        es[1] = .{ .mount_id = 2, .parent_id = 1, .mount_point = "/x" };
        es[2] = .{ .mount_id = 2, .parent_id = 2, .mount_point = "/x" };
        es[3] = .{ .mount_id = 2, .parent_id = 2, .mount_point = "/x" };
        for (es[4..], 0..) |*e, k| e.* = .{ .mount_id = @intCast(100 + k), .parent_id = 2, .mount_point = "/zzz" };
        var ix = try Index.init(gpa, es);
        defer ix.deinit(gpa);
        const got = try containingIndexed(&ix, es, "/x/y");
        if (junk <= 40) try testing.expectEqual(try containing(es, "/x/y"), got);
        try testing.expect(got.? >= 1 and got.? <= 3);
        try testing.expectEqual(@as(?usize, 0), try containingIndexed(&ix, es, "/q")); // only the root covers
    }
}

test "locate: carries the reader's truncation flag; a generated >1 MiB table is cut and says so" {
    const g = testing.allocator;
    var threaded = std.Io.Threaded.init(g, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const mounts = @import("mounts.zig");
    // 1.3 MiB of rows; the DEEP mount that a lookup needs is the last row.
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(g);
    try text.appendSlice(g, "rootfs / ext4 rw 0 0\n");
    var i: usize = 0;
    while (text.items.len < (1 << 20) + (300 << 10)) : (i += 1) try text.print(g, "dev{d} /m/{d} tmpfs rw 0 0\n", .{ i, i });
    try text.appendSlice(g, "last /deep/last tmpfs rw 0 0\n");
    try tmp.dir.writeFile(io, .{ .sub_path = "big.txt", .data = text.items });
    const path = try tmp.dir.realPathFileAlloc(io, "big.txt", g);
    defer g.free(path);
    var cut = false;
    const body = (try mounts.readVirtualFileCut(g, io, path, 1 << 20, &cut)).?;
    defer g.free(body);
    try testing.expect(cut);
    try testing.expect(body.len <= (1 << 20) and body[body.len - 1] == '\n');
    const es = try mounts.parseMounts(g, body);
    defer mounts.freeAll(g, es);
    const ans = try locate(es, cut, "/deep/last/file");
    // The deep mount was in the cut part: the answer is the root, and it says the table was cut.
    try testing.expectEqual(@as(?usize, 0), ans.index);
    try testing.expect(ans.table_truncated);
    // An uncut read of a small file says so too.
    var cut2 = true;
    const small = (try mounts.readVirtualFileCut(g, io, path, 4 << 20, &cut2)).?;
    defer g.free(small);
    try testing.expect(!cut2);
    try testing.expectEqual(text.items.len, small.len);
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

test "containing / containingIndexed: a root entry written with trailing slashes is the root (whole-module mutation 2026-11-19)" {
    // The tree walk must start at this entry (a flat longest-prefix answer would name
    // /h/inner for the first path): `trimmed` is what makes "//" the root in both finders.
    const t = [_]TFake{
        .{ .mount_id = 1, .parent_id = 0, .mount_point = "//" },
        .{ .mount_id = 2, .parent_id = 1, .mount_point = "/h/inner" },
        .{ .mount_id = 3, .parent_id = 1, .mount_point = "/h" }, // later, covers /h/inner
    };
    try testing.expectEqual(@as(?usize, 2), try containing(&t, "/h/inner/f"));
    var ix = try Index.init(testing.allocator, &t);
    defer ix.deinit(testing.allocator);
    try testing.expectEqual(@as(?usize, 2), try containingIndexed(&ix, &t, "/h/inner/f"));
    try testing.expectEqual(@as(?usize, 0), try containingIndexed(&ix, &t, "/etc"));
}
