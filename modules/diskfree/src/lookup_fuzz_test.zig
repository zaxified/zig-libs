// SPDX-License-Identifier: MIT
//! Fuzz harness (deterministic driver `DISKFREE_FUZZ`) for the table-level API:
//! `lookup.containing` / `lookup.isMountPoint` / `lookup.normalize` against an
//! independent component-wise oracle, `classify.*` on arbitrary names, and
//! `table.collectWith` invariants (bounded, unique mount points, subset of
//! the input, no leak under allocation failure) over a hostile table.
//!
//! Every decision is read out of the byte blob (`src.bytes`), never drawn from
//! a range: a `Smith` ranged draw returns its minimum for text input (see
//! `mounts.zig`'s harness comment). Paths and mount points are built from a
//! small alphabet dense in `/`, `.`, `..` and repeated names, so that prefix,
//! boundary and fold cases are hit often.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const lookup = @import("lookup.zig");
const classify = @import("classify.zig");
const table = @import("table.zig");
const mounts = @import("mounts.zig");
const statfs = @import("statfs.zig");

const blob_len = 1024;
const alphabet = "////..ab\x00 ";

const ScriptSource = struct {
    cur: testkit.fuzz.Cursor,
    pub fn bytes(self: *ScriptSource, buf: []u8) void {
        for (buf) |*b| b.* = self.cur.byte();
    }
};

const Label = enum { rel_path, abs_ok, matched, unmatched, mp_noncanonical, tie, folded_dotdot, table_rows, table_trunc };
var reach: [@typeInfo(Label).@"enum".field_names.len]usize = @splat(0);
fn mark(comptime l: Label) void {
    reach[@backingInt(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

/// A text of `n` bytes from the dense alphabet, `/`-prefixed with probability 3/4.
fn text(raw: []const u8, out: []u8, force_abs: bool) []u8 {
    for (raw, 0..) |b, i| out[i] = alphabet[b % alphabet.len];
    if (force_abs and raw.len > 0) out[0] = '/';
    return out[0..raw.len];
}

/// Independent oracle: the components of a normalized path, by a stack.
fn comps(gpa: std.mem.Allocator, p: []const u8) !std.ArrayList([]const u8) {
    var st: std.ArrayList([]const u8) = .empty;
    errdefer st.deinit(gpa);
    var it = std.mem.tokenizeScalar(u8, p, '/');
    while (it.next()) |c| {
        if (std.mem.eql(u8, c, ".")) continue;
        if (std.mem.eql(u8, c, "..")) {
            _ = st.pop();
            continue;
        }
        try st.append(gpa, c);
    }
    return st;
}

/// Does the mount point `mp` cover the component list `pc`? A mount point is
/// valid only when it is a canonical absolute path (after trailing slashes):
/// no empty, `.` or `..` component, and `/`-prefixed. Returns its depth or null.
fn oracleCover(mp_raw: []const u8, pc: []const []const u8) ?usize {
    var mp = mp_raw;
    while (mp.len > 1 and mp[mp.len - 1] == '/') mp = mp[0 .. mp.len - 1];
    if (mp.len == 0 or mp[0] != '/') return null;
    if (mp.len == 1) return 0;
    var depth: usize = 0;
    var it = std.mem.splitScalar(u8, mp[1..], '/');
    while (it.next()) |c| : (depth += 1) {
        if (c.len == 0 or std.mem.eql(u8, c, ".") or std.mem.eql(u8, c, "..")) return null;
        if (depth >= pc.len or !std.mem.eql(u8, c, pc[depth])) return null;
    }
    return depth;
}

fn fakeQuery(path: []const u8) statfs.StatfsError!statfs.Usage {
    var u: statfs.Usage = .{ .block_size = 4096, .fragment_size = 4096, .blocks_total = path.len % 3, .blocks_free = 0, .blocks_available = 0, .inodes_total = 0, .inodes_free = 0, .fs_type_magic = 0, .name_max = 255 };
    if (path.len % 5 == 0) return error.FileNotFound;
    u.flags = @intCast(path.len);
    return u;
}

const names = [_][]const u8{ "ext4", "proc", "nfs", "fuse.sshfs", "tmpfs", "cgroup2", "x", "" };
const devs = [_][]const u8{ "/dev/a", "h:/x", "//h/s", "none", "a:b", "" };

fn harness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var raw: [blob_len]u8 = undefined;
    src.bytes(&raw);
    // Layout: [0] control, [1] entry count, [2..130] path, then 8 mount points of 16 bytes.
    const ctl = raw[0];
    const n_entries: usize = raw[1] % 9;
    var pbuf: [128]u8 = undefined;
    const path = text(raw[2..][0 .. raw[1] / 9 % 64 + 1 + (ctl % 3) * 20], &pbuf, ctl & 4 != 0);
    var mpbuf: [8][16]u8 = undefined;
    var es: [8]mounts.MountEntry = undefined;
    for (0..n_entries) |i| {
        const chunk = raw[130 + i * 16 ..][0..16];
        const mlen = chunk[0] % 16;
        const mp = text(chunk[1 .. 1 + mlen], &mpbuf[i], chunk[0] & 0x40 != 0);
        es[i] = .{
            .device = @constCast(devs[chunk[15] % devs.len]),
            .mount_point = mp,
            .fs_type = @constCast(names[chunk[14] % names.len]),
            .options = @constCast(""),
        };
    }
    const entries = es[0..n_entries];

    // lookup vs the oracle.
    const got = lookup.containing(entries, path);
    if (path.len == 0 or path[0] != '/') {
        mark(.rel_path);
        try testing.expectError(error.RelativePath, got);
    } else if (std.mem.findScalar(u8, path, 0) != null) {
        try testing.expectError(error.InvalidPath, got);
    } else {
        mark(.abs_ok);
        var pc = try comps(gpa, path);
        defer pc.deinit(gpa);
        var want: ?usize = null;
        var want_depth: usize = 0;
        for (entries, 0..) |e, i| {
            const d = oracleCover(e.mount_point, pc.items) orelse continue;
            if (want != null and d == want_depth) mark(.tie);
            if (want == null or d >= want_depth) {
                want = i;
                want_depth = d;
            }
        }
        for (entries) |e| if (e.mount_point.len > 0 and e.mount_point[0] != '/') {
            mark(.mp_noncanonical);
            break;
        };
        if (std.mem.find(u8, path, "..") != null) mark(.folded_dotdot);
        try testing.expectEqual(want, try got);
        if (want != null) mark(.matched) else mark(.unmatched);
        // isMountPoint: some entry's trimmed mount point equals the folded path.
        var nb: [lookup.max_path]u8 = undefined;
        const norm = try lookup.normalize(path, &nb);
        var is_mp = false;
        for (entries) |e| {
            var m: []const u8 = e.mount_point;
            while (m.len > 1 and m[m.len - 1] == '/') m = m[0 .. m.len - 1];
            if (std.mem.eql(u8, m, norm)) is_mp = true;
        }
        try testing.expectEqual(is_mp, try lookup.isMountPoint(entries, path));
        // normalize is idempotent and canonical.
        var nb2: [lookup.max_path]u8 = undefined;
        try testing.expectEqualStrings(norm, try lookup.normalize(norm, &nb2));
        try testing.expect(norm[0] == '/');
        try testing.expect(norm.len == 1 or norm[norm.len - 1] != '/');
        try testing.expect(std.mem.find(u8, norm, "//") == null);
        try testing.expect(std.mem.find(u8, norm, "/./") == null and !std.mem.endsWith(u8, norm, "/."));
        try testing.expect(std.mem.find(u8, norm, "/../") == null and !std.mem.endsWith(u8, norm, "/.."));
    }

    // classify: total on any bytes.
    _ = classify.isPseudo(path);
    _ = classify.isRemote(path, path);
    if (n_entries > 0) _ = classify.isRemote(entries[0].fs_type, entries[0].mount_point);

    // table: invariants, under allocation failure too.
    const opts: table.Options = .{
        .include_pseudo = ctl & 8 != 0,
        .local_only = ctl & 16 != 0,
        .max_mounts = ctl >> 5,
    };
    var fa = testing.FailingAllocator.init(gpa, .{ .fail_index = if (ctl & 2 != 0) raw[2] % 6 else std.math.maxInt(usize) });
    if (table.collectWith(fa.allocator(), entries, opts, fakeQuery)) |t| {
        defer t.deinit(fa.allocator());
        try testing.expect(t.rows.len <= @min(opts.max_mounts, n_entries));
        if (t.rows.len > 0) mark(.table_rows);
        if (t.truncated) mark(.table_trunc);
        for (t.rows, 0..) |r, i| {
            for (t.rows[i + 1 ..]) |o| try testing.expect(!std.mem.eql(u8, r.mount_point, o.mount_point));
            if (!opts.include_pseudo) try testing.expect(!classify.isPseudo(r.fs_type));
            if (opts.local_only) try testing.expect(!classify.isRemote(r.fs_type, r.device));
        }
    } else |e| try testing.expectEqual(error.OutOfMemory, e);
}

test "fuzz driver: DISKFREE_FUZZ (lookup, classify, table)" {
    try fuzz_driver.run(harness, .{ .prefix = "DISKFREE_FUZZ", .name = "diskfree-lookup" });
}

test "fuzz: lookup/table harness, arbitrary bytes under testing.fuzz" {
    try std.testing.fuzz({}, fuzzOne, .{});
}

fn fuzzOne(_: void, smith: *std.testing.Smith) !void {
    var raw: [blob_len]u8 = undefined;
    smith.bytes(&raw);
    var src: ScriptSource = .{ .cur = .{ .bytes = &raw } };
    try harness(ScriptSource, &src, testing.allocator);
}

test "fuzz harness (lookup): 400 seeds in every test run, and they get everywhere" {
    reach = @splat(0);
    for (0..400) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        harness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("diskfree lookup seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in 400 seeds\n", .{@as(Label, @fromBackingInt(@intCast(i)))});
        return error.HarnessDoesNotReach;
    };
}
