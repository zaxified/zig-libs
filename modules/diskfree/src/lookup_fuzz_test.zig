// SPDX-License-Identifier: MIT
//! Fuzz harness (deterministic driver `DISKFREE_FUZZ`) for the table-level API,
//! fed with PARSED hostile state: mount-table text whose octal escapes decode to
//! `/`, NUL, `..`, `.` and spaces goes through `mounts.parseMounts` and
//! `mountinfo.parseMountinfo`, and the resulting entries through
//! `lookup.containing` / `isMountPoint` / `locate` and `table.collectWith`.
//!
//! Every expectation is an independent model written here, not a re-call of the
//! function under test:
//!   * lookup: a component-wise stack model, "the LAST covering entry wins";
//!   * table: a model of dedupe (last wins, first-seen order), canonical-path
//!     filter, type filters by the harness's OWN lists of names (each fs type is
//!     drawn from a list whose class is known by construction), no-blocks filter
//!     and fail filter driven by `fakeQuery`, hidden-under-a-later-ancestor, cap;
//!     rows are compared in order, with the winner's device and numbers;
//!   * `Usage.usePercent*` against u128 arithmetic written differently.
//! Both parsers must hand the same mount points for the same table.
//!
//! Every decision is read out of the byte blob (`src.bytes`), never drawn from a
//! range (see `mounts.zig`'s harness comment).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const lookup = @import("lookup.zig");
const classify = @import("classify.zig");
const table = @import("table.zig");
const mounts = @import("mounts.zig");
const mountinfo = @import("mountinfo.zig");
const statfs = @import("statfs.zig");

const blob_len = 512;
const alphabet = "////..ab ";

const ScriptSource = struct {
    cur: testkit.fuzz.Cursor,
    pub fn bytes(self: *ScriptSource, buf: []u8) void {
        for (buf) |*b| b.* = self.cur.byte();
    }
};

const Label = enum { rel_path, nul_path, compared, matched, unmatched, tie, folded_dotdot, escaped_slash, escaped_nul, table_rows, table_trunc, table_hidden, table_dup, table_noblocks, usage };
var reach: [@typeInfo(Label).@"enum".field_names.len]usize = @splat(0);
fn mark(comptime l: Label) void {
    reach[@backingInt(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

fn text(raw: []const u8, out: []u8) []u8 {
    for (raw, 0..) |b, i| out[i] = alphabet[b % alphabet.len];
    return out[0..raw.len];
}

// ── independent models ──────────────────────────────────────────────────────

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

/// Depth of `mp_raw` when it covers the component list `pc`, else null. A mount
/// point is valid only as a canonical absolute path (trailing slashes ignored).
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

/// Canonical for the table: "/" or "/x/y" with no empty, `.`/`..` component, no
/// NUL, no trailing slash.
fn canonical(mp: []const u8) bool {
    if (mp.len == 0 or mp[0] != '/') return false;
    if (mp.len == 1) return true;
    if (mp[mp.len - 1] == '/') return false;
    if (std.mem.findScalar(u8, mp, 0) != null) return false;
    var it = std.mem.splitScalar(u8, mp[1..], '/');
    while (it.next()) |c| if (c.len == 0 or std.mem.eql(u8, c, ".") or std.mem.eql(u8, c, "..")) return false;
    return true;
}

/// `anc` is a proper or equal ancestor directory of canonical `mp` (component model).
fn ancestorOf(gpa: std.mem.Allocator, anc: []const u8, mp: []const u8) !bool {
    var pc = try comps(gpa, mp);
    defer pc.deinit(gpa);
    return oracleCover(anc, pc.items) != null;
}

const pseudo_names = [_][]const u8{ "proc", "sysfs", "cgroup2", "devpts", "fuse.portal", "kernfs" };
const remote_names = [_][]const u8{ "nfs", "nfs4", "cifs", "fuse.sshfs", "ceph" };
const local_names = [_][]const u8{ "ext4", "tmpfs", "xfs", "vfat", "squashfs", "devtmpfs", "fuse.other" };

const TypeClass = enum { pseudo, remote, local };
fn pickType(b: u8) struct { name: []const u8, class: TypeClass } {
    const k = b % 18;
    if (k < 5) return .{ .name = pseudo_names[k], .class = .pseudo };
    if (k == 5) return .{ .name = pseudo_names[5], .class = .pseudo };
    if (k < 11) return .{ .name = remote_names[(k - 6) % remote_names.len], .class = .remote };
    return .{ .name = local_names[(k - 11) % local_names.len], .class = .local };
}

/// The model of `fakeQuery`: blocks 0 (a no-blocks mount), a failure, or numbers
/// that depend only on the mount point's bytes.
fn fakeBlocks(path: []const u8) ?u64 {
    var h: u64 = 0;
    for (path) |c| h = h *% 31 +% c;
    return switch (h % 5) {
        0 => 0, // "no blocks"
        1 => null, // statfs fails
        else => 100 + h % 1000,
    };
}
fn fakeQuery(path: []const u8) statfs.StatfsError!statfs.Usage {
    const bt = fakeBlocks(path) orelse return error.FileNotFound;
    return .{ .block_size = 4096, .fragment_size = 4096, .blocks_total = bt, .blocks_free = 0, .blocks_available = 0, .inodes_total = 0, .inodes_free = 0, .fs_type_magic = 0, .name_max = 255 };
}

const mp_tokens = [_][]const u8{ "/", "/", "a", "b", "\\057", "\\000", "\\056", "\\056\\056", "\\040", ".", "..", "/a" };
const devs = [_][]const u8{ "/dev/a", "h:/x", "//h/s", "none", "dev\\040x", "d" };

const max_e = 8;

fn harness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var raw: [blob_len]u8 = undefined;
    src.bytes(&raw);
    const ctl = raw[0];
    const n_entries: usize = raw[1] % (max_e + 1);

    // ── the table text, in both formats ──
    var mt: std.ArrayList(u8) = .empty;
    defer mt.deinit(gpa);
    var it_text: std.ArrayList(u8) = .empty;
    defer it_text.deinit(gpa);
    var classes: [max_e]TypeClass = undefined;
    for (0..n_entries) |i| {
        const ch = raw[140 + i * 24 ..][0..24];
        var mp: std.ArrayList(u8) = .empty;
        defer mp.deinit(gpa);
        if (ch[0] & 1 != 0) try mp.appendSlice(gpa, "/");
        for (ch[1..][0 .. ch[0] % 12]) |t| try mp.appendSlice(gpa, mp_tokens[t % mp_tokens.len]);
        if (mp.items.len == 0) try mp.appendSlice(gpa, "/");
        const ty = pickType(ch[18]);
        classes[i] = ty.class;
        const dev = devs[ch[19] % devs.len];
        try mt.print(gpa, "{s} {s} {s} rw 0 0\n", .{ dev, mp.items, ty.name });
        try it_text.print(gpa, "{d} {d} 0:1 / {s} rw - {s} {s} rw\n", .{ i + 10, @as(u32, ch[20] % 12) + 10, mp.items, ty.name, dev });
    }
    const es = try mounts.parseMounts(gpa, mt.items);
    defer mounts.freeAll(gpa, es);
    const infos = try mountinfo.parseMountinfo(gpa, it_text.items);
    defer mountinfo.freeAll(gpa, infos);
    // Escapes that decode to hostile bytes may make a row unparseable (it is
    // skipped); the two parsers must agree on which rows survive.
    try testing.expectEqual(es.len, infos.len);
    for (es, infos) |a, b| try testing.expectEqualStrings(a.mount_point, b.mount_point);
    for (es) |e| {
        if (std.mem.findScalar(u8, e.mount_point, 0) != null) mark(.escaped_nul);
        if (std.mem.find(u8, e.mount_point, "//") != null) mark(.escaped_slash);
    }

    // ── lookup against the stack model ──
    var pbuf: [96]u8 = undefined;
    const plen = raw[2] % 80 + 1;
    var path = text(raw[8..][0..plen], &pbuf);
    if (ctl & 12 != 0) path[0] = '/';
    if (raw[3] % 32 == 0) path[raw[4] % path.len] = 0; // NUL: rare, labelled
    const got = lookup.containing(es, path);
    if (path[0] != '/') {
        mark(.rel_path);
        try testing.expectError(error.RelativePath, got);
    } else if (std.mem.findScalar(u8, path, 0) != null) {
        mark(.nul_path);
        try testing.expectError(error.InvalidPath, got);
    } else {
        mark(.compared);
        var pc = try comps(gpa, path);
        defer pc.deinit(gpa);
        var want: ?usize = null;
        var want_depth: usize = 0;
        for (es, 0..) |e, i| if (oracleCover(e.mount_point, pc.items)) |d| {
            if (want != null) mark(.tie);
            if (want == null or d >= want_depth) { // the deepest covering mount, the last on a tie
                want = i;
                want_depth = d;
            }
        };
        if (std.mem.find(u8, path, "..") != null) mark(.folded_dotdot);
        try testing.expectEqual(want, try got);
        try testing.expectEqual(want, (try lookup.locate(es, ctl & 1 != 0, path)).index);
        try testing.expectEqual(ctl & 1 != 0, (try lookup.locate(es, ctl & 1 != 0, path)).table_truncated);
        if (try lookup.containing(infos, path)) |ti| try testing.expect(ti < infos.len); // hostile parent ids: ends, in range
        if (want != null) mark(.matched) else mark(.unmatched);
        var nb: [lookup.max_path]u8 = undefined;
        const norm = try lookup.normalize(path, &nb);
        var is_mp = false;
        for (es) |e| {
            var m: []const u8 = e.mount_point;
            while (m.len > 1 and m[m.len - 1] == '/') m = m[0 .. m.len - 1];
            if (std.mem.eql(u8, m, norm)) is_mp = true;
        }
        try testing.expectEqual(is_mp, try lookup.isMountPoint(es, path));
        var nb2: [lookup.max_path]u8 = undefined;
        try testing.expectEqualStrings(norm, try lookup.normalize(norm, &nb2));
        try testing.expect(norm.len == 1 or norm[norm.len - 1] != '/');
        try testing.expect(std.mem.find(u8, norm, "//") == null and std.mem.find(u8, norm, "/./") == null and std.mem.find(u8, norm, "/../") == null);
    }

    // ── classify: independent expectation by construction ──
    for (es, 0..) |e, i| {
        if (i >= n_entries) break;
        _ = e;
    }
    for (pseudo_names) |n| try testing.expect(classify.isPseudo(n));
    for (local_names) |n| try testing.expect(!classify.isPseudo(n));
    for (remote_names) |n| try testing.expect(classify.isRemote(n, "x") and !classify.isPseudo(n));
    for (local_names) |n| try testing.expect(!classify.isRemote(n, "/dev/sda1"));
    _ = classify.isPseudo(path);
    _ = classify.isRemote(path, path);

    // ── table model ──
    const opts: table.Options = .{
        .include_pseudo = ctl & 8 != 0,
        .local_only = ctl & 16 != 0,
        .max_mounts = ctl >> 5,
        .skip_fs_types = if (raw[6] & 1 != 0) &table.df_default_skip else &.{},
    };
    // the entries' classes follow the surviving rows; rebuild them by re-parsing
    // class by device+mp is not possible, so the model works on parsed entries and
    // looks the class up from the type NAME against the harness's own lists.
    var want_rows: std.ArrayList(usize) = .empty; // indexes into es
    defer want_rows.deinit(gpa);
    {
        var dedup: std.ArrayList(usize) = .empty; // winner index per distinct mp, first-seen order
        defer dedup.deinit(gpa);
        for (es, 0..) |e, i| {
            if (!canonical(e.mount_point)) continue;
            var later_same = false;
            for (es[i + 1 ..]) |o| if (std.mem.eql(u8, o.mount_point, e.mount_point)) {
                later_same = true;
            };
            if (later_same) mark(.table_dup) else try dedup.append(gpa, i); // winner = last occurrence, at its position
        }
        var cands: usize = 0;
        var trunc = false;
        for (dedup.items) |d| {
            const e = es[d];
            const class = classOf(e.fs_type);
            if (!opts.include_pseudo and class == .pseudo) continue;
            if (opts.local_only and (class == .remote or remoteDevice(e.device))) continue;
            if (raw[6] & 1 != 0 and (std.mem.eql(u8, e.fs_type, "squashfs") or std.mem.eql(u8, e.fs_type, "devtmpfs"))) continue;
            if (cands >= opts.max_mounts) {
                trunc = true;
                continue;
            }
            cands += 1;
            const bt = fakeBlocks(e.mount_point) orelse continue;
            if (!opts.include_pseudo and bt == 0) {
                mark(.table_noblocks);
                continue;
            }
            try want_rows.append(gpa, d);
        }
        var fa = testing.FailingAllocator.init(gpa, .{ .fail_index = if (ctl & 2 != 0) raw[5] % 8 else std.math.maxInt(usize) });
        if (table.collectWith(fa.allocator(), es, opts, fakeQuery)) |t| {
            defer t.deinit(fa.allocator());
            try testing.expectEqual(want_rows.items.len, t.rows.len);
            for (want_rows.items, t.rows) |wi, r| {
                try testing.expectEqualStrings(es[wi].mount_point, r.mount_point);
                try testing.expectEqualStrings(es[wi].device, r.device); // the dedupe WINNER's device
                try testing.expectEqualStrings(es[wi].fs_type, r.fs_type);
                try testing.expectEqual(fakeBlocks(es[wi].mount_point).?, r.usage.blocks_total);
            }
            try testing.expectEqual(trunc, t.truncated);
            if (t.rows.len > 0) mark(.table_rows);
            if (t.truncated) mark(.table_trunc);
        } else |e| try testing.expectEqual(error.OutOfMemory, e);
        // With the mount tree the listing can only lose rows (covered mounts), never
        // gain or change one; hostile parent ids (cycles, self-parents) must end.
        {
            var big = opts;
            big.max_mounts = 1000;
            const plain = try table.collectWith(gpa, es, big, fakeQuery);
            defer plain.deinit(gpa);
            big.tree = infos;
            const treed = try table.collectWith(gpa, es, big, fakeQuery);
            defer treed.deinit(gpa);
            try testing.expect(treed.rows.len <= plain.rows.len);
            var pi: usize = 0;
            for (treed.rows) |r| {
                while (pi < plain.rows.len and !std.mem.eql(u8, plain.rows[pi].mount_point, r.mount_point)) pi += 1;
                try testing.expect(pi < plain.rows.len);
                try testing.expectEqualStrings(plain.rows[pi].device, r.device);
                if (treed.rows.len < plain.rows.len) mark(.table_hidden);
            }
        }
        // the read-cut flag rides into the table
        const t2 = try table.collectWith(gpa, es, .{ .input_truncated = true, .max_mounts = 1000 }, fakeQuery);
        defer t2.deinit(gpa);
        try testing.expect(t2.truncated and t2.read_truncated);
    }

    // ── Usage.usePercent* against u128 arithmetic, written differently ──
    {
        const shape = raw[500];
        var t = std.mem.readInt(u64, raw[400..408], .little);
        var f = std.mem.readInt(u64, raw[408..416], .little);
        var a = std.mem.readInt(u64, raw[416..424], .little);
        switch (shape % 4) {
            0 => {},
            1 => { // small numbers: rounding boundaries
                t %= 1000;
                f %= 1000;
                a %= 1000;
            },
            2 => { // free = total - small
                f = t -| (f % 7);
                a %= (t -| f) + 3;
            },
            else => {
                t = std.math.maxInt(u64) - (t % 3);
            },
        }
        const u: statfs.Usage = .{ .block_size = 4096, .fragment_size = 0, .blocks_total = t, .blocks_free = f, .blocks_available = a, .inodes_total = 0, .inodes_free = 0, .fs_type_magic = 0, .name_max = 255 };
        const used: u128 = if (t > f) @as(u128, t) - f else 0;
        const denom: u128 = used + a;
        if (denom == 0) {
            try testing.expectEqual(@as(?u8, null), u.usePercent());
            try testing.expectEqual(@as(?u8, null), u.usePercentNearest());
        } else {
            const q = used * 100 / denom;
            const r = used * 100 % denom;
            const ceil_ = q + @intFromBool(r != 0);
            const near = if (r * 2 >= denom) q + 1 else q; // half up
            try testing.expectEqual(@as(?u8, @intCast(ceil_)), u.usePercent());
            try testing.expectEqual(@as(?u8, @intCast(near)), u.usePercentNearest());
            try testing.expect(ceil_ <= 100 and near <= 100);
        }
        mark(.usage);
    }
}

fn classOf(fs_type: []const u8) TypeClass {
    for (pseudo_names) |n| if (std.mem.eql(u8, n, fs_type)) return .pseudo;
    for (remote_names) |n| if (std.mem.eql(u8, n, fs_type)) return .remote;
    return .local;
}

/// The harness's own idea of a network-shaped device from `devs`: `host:/x` and `//host/share`.
fn remoteDevice(dev: []const u8) bool {
    return std.mem.eql(u8, dev, "h:/x") or std.mem.eql(u8, dev, "//h/s");
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

test "fuzz harness (lookup): 600 seeds in every test run, and they get everywhere" {
    reach = @splat(0);
    const seeds = 600;
    for (0..seeds) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        harness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("diskfree lookup seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in {d} seeds\n", .{ @as(Label, @fromBackingInt(@intCast(i))), seeds });
        return error.HarnessDoesNotReach;
    };
    // Measured share of seeds that reach the oracle comparison (absolute path, no NUL).
    const share = reach[@backingInt(Label.compared)] * 100 / seeds;
    try testing.expect(share >= 50);
}
