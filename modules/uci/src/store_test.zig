// SPDX-License-Identifier: MIT
//! Tests of the file layer (`store.zig`, `batch.zig`): the black-box capture of
//! the real `uci` replayed through `Session`, commit durability and crash
//! points, hostile names and files, read errors that are not absence.

const std = @import("std");
const testing = std.testing;
const uci = @import("root.zig");
const store_mod = @import("store.zig");
const linux = std.os.linux;
const t = testing;

const base_conf = "config iface 'lan'\n\toption proto 'static'\n\tlist dns '1.1.1.1'\n\tlist dns '8.8.8.8'\n\n" ++
    "config rule\n\toption name 'r0'\n\nconfig rule\n\toption name 'r1'\n";

const Fixture = struct {
    tmp: std.testing.TmpDir,
    conf: std.Io.Dir,
    save: std.Io.Dir,

    fn init() !Fixture {
        var tmp = t.tmpDir(.{});
        errdefer tmp.cleanup();
        try tmp.dir.createDir(t.io, "conf", .default_dir);
        try tmp.dir.createDir(t.io, "save", .default_dir);
        return .{
            .tmp = tmp,
            .conf = try tmp.dir.openDir(t.io, "conf", .{ .iterate = true }),
            .save = try tmp.dir.openDir(t.io, "save", .{ .iterate = true }),
        };
    }
    fn deinit(self: *Fixture) void {
        self.conf.close(t.io);
        self.save.close(t.io);
        self.tmp.cleanup();
    }
    fn store(self: *const Fixture) uci.Store {
        return .{ .io = t.io, .conf = self.conf, .save = self.save };
    }
    fn put(self: *const Fixture, dir: std.Io.Dir, name: []const u8, data: []const u8) !void {
        _ = self;
        try dir.writeFile(t.io, .{ .sub_path = name, .data = data });
    }
    fn read(self: *const Fixture, dir: std.Io.Dir, name: []const u8) ![]u8 {
        _ = self;
        return dir.readFileAlloc(t.io, name, t.allocator, .limited(1 << 20));
    }
};

fn mkfifoAt(dir: std.Io.Dir, name: []const u8) !void {
    var z: [64]u8 = undefined;
    const p = try std.mem.printSentinel(&z, "{s}", .{name}, 0);
    const rc = linux.mknodat(dir.handle, p, linux.S.IFIFO | 0o600, 0);
    if (linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
}

// ── the real binary's behaviour, replayed ───────────────────────────────────

test "capture: batch and import -m through Session equal the real uci (show text, committed model)" {
    const text = @embedFile("testdata/store_capture.txt");
    var cases: usize = 0;
    var it = std.mem.splitSequence(u8, text, "=== case ");
    _ = it.next(); // before the first
    while (it.next()) |chunk| {
        const nl = std.mem.indexOfScalar(u8, chunk, '\n').?;
        const name = chunk[0..nl];
        const kind_s = section(chunk, "--- kind\n", "--- input\n");
        const input = section(chunk, "--- input\n", "--- show\n");
        const want_show = section(chunk, "--- show\n", "--- committed\n");
        const want_file = section(chunk, "--- committed\n", "=== end\n");
        var fx = try Fixture.init();
        defer fx.deinit();
        try fx.put(fx.conf, "t", base_conf);
        var s = uci.Session.init(t.allocator, fx.store());
        defer s.deinit();
        if (std.mem.startsWith(u8, kind_s, "batch")) {
            try s.run(input, .{ .keep_going = true }, null, null);
        } else {
            var pkg = try uci.parse(t.allocator, input);
            defer pkg.deinit(t.allocator);
            const ed = try s.editor("t");
            uci.merge(ed, &pkg) catch |e| try t.expectEqual(error.DuplicateSection, e);
        }
        const ed = try s.editor("t");
        const got = try ed.show(t.allocator, "t", .{});
        defer t.allocator.free(got);
        t.expectEqualStrings(want_show, got) catch |e| {
            std.debug.print("case {s}\n", .{name});
            return e;
        };
        try fx.store().commitEditor(t.allocator, "t", ed, try fx.store().stamp("t"));
        var back = try fx.store().load(t.allocator, "t", null);
        defer back.deinit(t.allocator);
        var want = try uci.parse(t.allocator, want_file);
        defer want.deinit(t.allocator);
        try t.expect(back.eql(&want));
        cases += 1;
    }
    try t.expectEqual(@as(usize, 14), cases);
}

fn section(chunk: []const u8, from: []const u8, to: []const u8) []const u8 {
    const a = std.mem.indexOf(u8, chunk, from).? + from.len;
    const b = std.mem.indexOfPos(u8, chunk, a, to).?;
    return chunk[a..b];
}

// ── commit ──────────────────────────────────────────────────────────────────

test "commit: replaces the file, keeps its mode, empties the delta, leaves no temp" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.put(fx.conf, "net", base_conf);
    {
        const f = try fx.conf.openFile(t.io, "net", .{});
        defer f.close(t.io);
        try f.setPermissions(t.io, @fromBackingInt(@intCast(0o640)));
    }
    const before = try fx.conf.statFile(t.io, "net", .{});
    try fx.put(fx.save, "net", "net.lan.proto='dhcp'\n");
    const st = fx.store();
    try t.expect(try st.hasStaged(t.allocator, "net"));
    try st.commitStaged(t.allocator, "net", null);
    const after = try fx.conf.statFile(t.io, "net", .{});
    try t.expect(before.inode != after.inode); // a new file, renamed in
    try t.expectEqual(@as(u32, 0o640), @as(u32, @backingInt(after.permissions)) & 0o7777);
    try t.expect(!try st.hasStaged(t.allocator, "net"));
    const delta = (try st.staged(t.allocator, "net")).?;
    defer t.allocator.free(delta);
    try t.expectEqual(@as(usize, 0), delta.len); // emptied, not deleted (as uci does)
    var p = try st.load(t.allocator, "net", null);
    defer p.deinit(t.allocator);
    try t.expectEqualStrings("dhcp", p.section("iface", "lan").?.get("proto").?);
    // no debris in the config directory
    var n: usize = 0;
    var it = fx.conf.iterate();
    while (try it.next(t.io)) |e| {
        try t.expectEqualStrings("net", e.name);
        n += 1;
    }
    try t.expectEqual(@as(usize, 1), n);
    // nothing pending: commitStaged writes nothing (same inode), still ok
    try st.commitStaged(t.allocator, "net", null);
    try t.expectEqual(after.inode, (try fx.conf.statFile(t.io, "net", .{})).inode);
    try t.expectError(error.PackageNotFound, st.commitStaged(t.allocator, "absent", null));
}

test "commit: a new file is 0600 and a committed file has no package line" {
    var fx = try Fixture.init();
    defer fx.deinit();
    const st = fx.store();
    var pkg = try uci.parse(t.allocator, base_conf);
    defer pkg.deinit(t.allocator);
    pkg.name = "net";
    try st.commit(t.allocator, "net", &pkg);
    const s = try fx.conf.statFile(t.io, "net", .{});
    try t.expectEqual(@as(u32, 0o600), @as(u32, @backingInt(s.permissions)) & 0o7777);
    const bytes = try fx.read(fx.conf, "net");
    defer t.allocator.free(bytes);
    try t.expect(std.mem.indexOf(u8, bytes, "package") == null);
}

/// Same sections in the same order, same options as a SET (a save/replay may
/// move a changed option to the end of its section; list order is kept).
fn eqlUnordered(a: *const uci.Package, b: *const uci.Package) bool {
    if (a.sections.len != b.sections.len) return false;
    for (a.sections, b.sections) |*sa, *sb| {
        if (!std.mem.eql(u8, sa.type, sb.type) or sa.anonymous != sb.anonymous) return false;
        if ((sa.name == null) != (sb.name == null)) return false;
        if (sa.name) |n| if (!std.mem.eql(u8, n, sb.name.?)) return false;
        var na: usize = 0;
        for (sa.options) |*oa| {
            if (oa.values.len == 0) continue;
            na += 1;
            const ob = sb.option(oa.key) orelse return false;
            if (!oa.eql(ob)) return false;
        }
        var nb: usize = 0;
        for (sb.options) |*ob| {
            if (ob.values.len != 0) nb += 1;
        }
        if (na != nb) return false;
    }
    return true;
}

fn tempCount(fx: *const Fixture, dir: std.Io.Dir) !usize {
    _ = fx;
    var d = try dir.openDir(t.io, ".", .{ .iterate = true });
    defer d.close(t.io);
    var it = d.iterate();
    var n: usize = 0;
    while (try it.next(t.io)) |e| {
        if (std.mem.indexOf(u8, e.name, ".uci-tmp-") != null) n += 1;
    }
    return n;
}

const CommitSetup = struct {
    old: uci.Package,
    new: uci.Package,
    old_bytes: []u8,
    new_bytes: []u8,

    fn init(fx: *const Fixture) !CommitSetup {
        var old = try uci.parse(t.allocator, base_conf);
        errdefer old.deinit(t.allocator);
        try fx.store().commit(t.allocator, "net", &old);
        const old_bytes = try fx.read(fx.conf, "net");
        errdefer t.allocator.free(old_bytes);
        var ed = try uci.Editor.init(t.allocator, &old);
        defer ed.deinit();
        try ed.set("lan", "proto", "dhcp");
        var new = try ed.toPackage(t.allocator);
        errdefer new.deinit(t.allocator);
        const new_bytes = try uci.serialize(t.allocator, &new);
        return .{ .old = old, .new = new, .old_bytes = old_bytes, .new_bytes = new_bytes };
    }
    fn deinit(self: *CommitSetup) void {
        self.old.deinit(t.allocator);
        self.new.deinit(t.allocator);
        t.allocator.free(self.old_bytes);
        t.allocator.free(self.new_bytes);
    }
};

test "commit: a crash at every point leaves the old bytes or the new bytes, debris is reaped" {
    var fx = try Fixture.init();
    defer fx.deinit();
    const st = fx.store();
    var cs = try CommitSetup.init(&fx);
    defer cs.deinit();
    try t.expect(!std.mem.eql(u8, cs.old_bytes, cs.new_bytes));
    var k: u32 = 1;
    while (k <= 6) : (k += 1) {
        try fx.put(fx.save, "net", "net.lan.x='1'\n");
        store_mod.crash_hook.arm(k);
        defer store_mod.crash_hook.arm(null);
        const r = st.commit(t.allocator, "net", &cs.new);
        if (k == 6) {
            try r; // five crash points exist; the sixth never fires
        } else {
            try t.expectError(error.WriteFailed, r); // a crash point surfaces as WriteFailed ...
            try t.expect(store_mod.crash_hook.tripped); // ... and is told apart by the hook
        }
        store_mod.crash_hook.arm(null);
        const got = try fx.read(fx.conf, "net");
        defer t.allocator.free(got);
        // BYTES on disk: exactly the old file before the rename, the new one after
        try t.expectEqualSlices(u8, if (k <= 2) cs.old_bytes else cs.new_bytes, got);
        // the debris of a crash before the rename is one temp; after it, none
        try t.expectEqual(@as(usize, if (k <= 2) 1 else 0), try tempCount(&fx, fx.conf));
        // the delta is cleared only by the last step; a reload at point 5 replays it
        try t.expectEqual(k != 6, try st.hasStaged(t.allocator, "net"));
        if (k == 5) {
            var live = try st.loadStaged(t.allocator, "net", null);
            defer live.deinit(t.allocator);
            try t.expectEqualStrings("1", live.section("iface", "lan").?.get("x").?);
        }
        // the next commit reaps the debris and restores the old file
        try st.commit(t.allocator, "net", &cs.old);
        try t.expectEqual(@as(usize, 0), try tempCount(&fx, fx.conf));
        const back = try fx.read(fx.conf, "net");
        defer t.allocator.free(back);
        try t.expectEqualSlices(u8, cs.old_bytes, back);
    }
}

test "commit: the order is write, chmod, fsync file, rename, fsync directory; a missing step turns it red" {
    var fx = try Fixture.init();
    defer fx.deinit();
    const st = fx.store();
    var cs = try CommitSetup.init(&fx);
    defer cs.deinit();
    const S = store_mod.Step;
    const want = [_]S{ .write, .chmod, .fsync_file, .rename, .fsync_dir };
    const hook = &store_mod.crash_hook;
    defer {
        hook.recording = false;
        hook.skip = null;
    }
    hook.startRecording();
    try st.commit(t.allocator, "net", &cs.new);
    try t.expectEqualSlices(S, &want, hook.steps[0..hook.n_steps]);
    // the two mutants the review named, plus chmod: each leaves the recorded order different
    for ([_]S{ .fsync_file, .fsync_dir, .chmod }) |m| {
        hook.skip = m;
        hook.startRecording();
        try st.commit(t.allocator, "net", &cs.old);
        try t.expect(!std.mem.eql(S, &want, hook.steps[0..hook.n_steps]));
        try t.expectEqual(want.len - 1, hook.n_steps);
        hook.skip = null;
    }
}

test "commit: a short write (ENOSPC) leaves the original intact and removes the temp" {
    var fx = try Fixture.init();
    defer fx.deinit();
    const st = fx.store();
    var cs = try CommitSetup.init(&fx);
    defer cs.deinit();
    try fx.put(fx.save, "net", "net.lan.x='1'\n");
    store_mod.crash_hook.fail_write = true;
    defer store_mod.crash_hook.fail_write = false;
    try t.expectError(error.WriteFailed, st.commit(t.allocator, "net", &cs.new));
    try t.expectError(error.WriteFailed, st.importText(t.allocator, "net", base_conf, null));
    const got = try fx.read(fx.conf, "net");
    defer t.allocator.free(got);
    try t.expectEqualSlices(u8, cs.old_bytes, got);
    try t.expectEqual(@as(usize, 0), try tempCount(&fx, fx.conf));
    try t.expect(try st.hasStaged(t.allocator, "net")); // the delta was not touched
}

test "commit: a failing directory fsync and a delta that cannot be emptied have their own errors" {
    var fx = try Fixture.init();
    defer fx.deinit();
    const st = fx.store();
    var cs = try CommitSetup.init(&fx);
    defer cs.deinit();
    try fx.put(fx.save, "net", "net.lan.x='1'\n");
    store_mod.crash_hook.fail_dir_sync = true;
    try t.expectError(error.CommittedNotDurable, st.commit(t.allocator, "net", &cs.new));
    store_mod.crash_hook.fail_dir_sync = false;
    const got = try fx.read(fx.conf, "net");
    defer t.allocator.free(got);
    try t.expectEqualSlices(u8, cs.new_bytes, got); // visible
    try t.expect(!try st.hasStaged(t.allocator, "net")); // and the delta is cleared anyway
    // a delta that is a directory: revert refuses, the file is in place
    var fx2 = try Fixture.init();
    defer fx2.deinit();
    try fx2.put(fx2.conf, "net", base_conf);
    try fx2.save.createDir(t.io, "net", .default_dir);
    try t.expectError(error.StagedNotCleared, fx2.store().commit(t.allocator, "net", &cs.new));
    const got2 = try fx2.read(fx2.conf, "net");
    defer t.allocator.free(got2);
    try t.expectEqualSlices(u8, cs.new_bytes, got2);
}

test "commit: stale temps of the package are reaped by exact pattern, regular files only" {
    var fx = try Fixture.init();
    defer fx.deinit();
    const st = fx.store();
    var cs = try CommitSetup.init(&fx);
    defer cs.deinit();
    var nb: [64]u8 = undefined;
    for (0..40) |i| {
        const n = try std.fmt.bufPrint(&nb, ".net.uci-tmp-{x:0>16}", .{i + 0xabc000});
        try fx.put(fx.conf, n, "debris");
    }
    try fx.put(fx.conf, ".net.uci-tmp-ZZ", "not a temp name");
    try fx.put(fx.conf, ".other.uci-tmp-0123456789abcdef", "another package's");
    try fx.put(fx.conf, "net.uci-tmp-0123456789abcdef", "no leading dot");
    try fx.conf.symLink(t.io, "net", ".net.uci-tmp-ffffffffffffffff", .{});
    try fx.conf.createDir(t.io, ".net.uci-tmp-eeeeeeeeeeeeeeee", .default_dir);
    for (0..4) |_| try st.commit(t.allocator, "net", &cs.new); // 16 per call
    var d = try fx.conf.openDir(t.io, ".", .{ .iterate = true });
    defer d.close(t.io);
    var it = d.iterate();
    var left: usize = 0;
    while (try it.next(t.io)) |e| {
        left += 1;
        const ok = std.mem.eql(u8, e.name, "net") or std.mem.eql(u8, e.name, ".net.uci-tmp-ZZ") or
            std.mem.eql(u8, e.name, ".other.uci-tmp-0123456789abcdef") or std.mem.eql(u8, e.name, "net.uci-tmp-0123456789abcdef") or
            std.mem.eql(u8, e.name, ".net.uci-tmp-ffffffffffffffff") or std.mem.eql(u8, e.name, ".net.uci-tmp-eeeeeeeeeeeeeeee");
        if (!ok) {
            std.debug.print("unexpected: {s}\n", .{e.name});
            return error.TestUnexpectedResult;
        }
    }
    try t.expectEqual(@as(usize, 6), left);
    try t.expect(store_mod.isTempOf(".net.uci-tmp-0123456789abcdef", "net"));
    try t.expect(!store_mod.isTempOf(".net.uci-tmp-0123456789abcdeF", "net"));
}

test "lock: a writer waits for another holder of the package's flock, with a bound" {
    var fx = try Fixture.init();
    defer fx.deinit();
    var cs = try CommitSetup.init(&fx);
    defer cs.deinit();
    var st = fx.store();
    st.options.lock_timeout_ms = 60;
    const holder = try fx.conf.openFile(t.io, "net", .{ .mode = .read_only });
    try t.expect(try holder.tryLock(t.io, .exclusive));
    try fx.put(fx.save, "net", "net.lan.x='1'\n");
    try t.expectError(error.LockTimeout, st.commit(t.allocator, "net", &cs.new));
    try t.expectError(error.LockTimeout, st.replace(t.allocator, "net", &cs.new));
    try t.expectError(error.LockTimeout, st.importText(t.allocator, "net", base_conf, null));
    try t.expectError(error.LockTimeout, st.commitStaged(t.allocator, "net", null));
    const got = try fx.read(fx.conf, "net");
    defer t.allocator.free(got);
    try t.expectEqualSlices(u8, cs.old_bytes, got); // nothing changed
    try t.expect(try st.hasStaged(t.allocator, "net"));
    // a waiter gets in once the holder lets go
    const Rel = struct {
        fn run(f: std.Io.File) void {
            t.io.sleep(.fromMilliseconds(150), .awake) catch {};
            f.close(t.io);
        }
    };
    st.options.lock_timeout_ms = 5000;
    const th = try std.Thread.spawn(.{}, Rel.run, .{holder});
    try st.commit(t.allocator, "net", &cs.new);
    th.join();
    const after = try fx.read(fx.conf, "net");
    defer t.allocator.free(after);
    try t.expectEqualSlices(u8, cs.new_bytes, after);
}

test "commit: text that parse would refuse is not written" {
    var fx = try Fixture.init();
    defer fx.deinit();
    const st = fx.store();
    var pkg = try uci.parse(t.allocator, base_conf);
    defer pkg.deinit(t.allocator);
    try st.commit(t.allocator, "net", &pkg);
    var ed = try uci.Editor.init(t.allocator, &pkg);
    defer ed.deinit();
    const big = try t.allocator.alloc(u8, uci.max_line_len + 10);
    defer t.allocator.free(big);
    @memset(big, 'a');
    try ed.set("lan", "long", big);
    try t.expectError(error.WouldNotReload, st.commitEditor(t.allocator, "net", &ed, try st.stamp("net")));
    var back = try st.load(t.allocator, "net", null);
    defer back.deinit(t.allocator);
    try t.expect(back.eql(&pkg));
    // a size cap on the store
    var small = fx.store();
    small.options.max_bytes = 16;
    try t.expectError(error.FileTooLarge, small.load(t.allocator, "net", null));
    try t.expectError(error.FileTooLarge, small.commit(t.allocator, "other", &pkg));
}

test "import: replaces the file at once, leaves the delta, writes nothing on a parse error" {
    var fx = try Fixture.init();
    defer fx.deinit();
    const st = fx.store();
    try fx.put(fx.conf, "net", base_conf);
    try fx.put(fx.save, "net", "net.lan.x='1'\n");
    try st.importText(t.allocator, "net", "config iface 'z'\n\toption a '1'\n", null);
    var p = try st.load(t.allocator, "net", null);
    defer p.deinit(t.allocator);
    try t.expect(p.section("iface", "z") != null and p.section("iface", "lan") == null);
    try t.expect(try st.hasStaged(t.allocator, "net")); // untouched, as the binary leaves it
    var d: uci.Diagnostics = .{};
    try t.expectError(error.BadKeyword, st.importText(t.allocator, "net", "bogus\n", &d));
    try t.expectEqual(@as(usize, 1), d.line);
    var p2 = try st.load(t.allocator, "net", null);
    defer p2.deinit(t.allocator);
    try t.expect(p2.eql(&p));
}

// ── staged overlay, revert ──────────────────────────────────────────────────

test "loadStaged overlays the delta; revert empties it and keeps the file" {
    var fx = try Fixture.init();
    defer fx.deinit();
    const st = fx.store();
    try fx.put(fx.conf, "net", base_conf);
    try fx.put(fx.save, "net", "net.lan.proto='dhcp'\n");
    var live = try st.loadStaged(t.allocator, "net", null);
    defer live.deinit(t.allocator);
    try t.expectEqualStrings("dhcp", live.section("iface", "lan").?.get("proto").?);
    var base = try st.load(t.allocator, "net", null);
    defer base.deinit(t.allocator);
    try t.expectEqualStrings("static", base.section("iface", "lan").?.get("proto").?);
    try st.revert("net");
    try t.expect(!try st.hasStaged(t.allocator, "net"));
    try st.revert("net"); // twice is fine
    try st.revert("never-staged"); // no delta file: nothing to do
    try fx.put(fx.save, "net", "garbage line\n");
    var d: uci.Diagnostics = .{};
    try t.expectError(error.BadDelta, st.loadStaged(t.allocator, "net", &d));
    try t.expectEqual(@as(usize, 1), d.line);
}

// ── hostile names and files ─────────────────────────────────────────────────

test "names: absolute, .., separators, dots, empty and long are refused by default" {
    var fx = try Fixture.init();
    defer fx.deinit();
    const st = fx.store();
    var pkg = try uci.parse(t.allocator, base_conf);
    defer pkg.deinit(t.allocator);
    var long_buf: [129]u8 = @splat('a');
    const long: []const u8 = &long_buf;
    const names = [_][]const u8{ "", ".", "..", "../net", "/etc/passwd", "a/b", "a.b", ".hidden", "a b", "a\x00b", long, "net\n" };
    for (names) |n| {
        try t.expectError(error.InvalidPackageName, st.load(t.allocator, n, null));
        try t.expectError(error.InvalidPackageName, st.loadStaged(t.allocator, n, null));
        try t.expectError(error.InvalidPackageName, st.staged(t.allocator, n));
        try t.expectError(error.InvalidPackageName, st.revert(n));
        try t.expectError(error.InvalidPackageName, st.commit(t.allocator, n, &pkg));
        try t.expectError(error.InvalidPackageName, st.importText(t.allocator, n, "", null));
        try t.expectError(error.InvalidPackageName, st.readFile(t.allocator, fx.conf, n));
        try t.expect(!uci.validPackageName(n));
    }
    try t.expect(uci.validPackageName("luci-app_x1"));
    // a path name works only when asked for
    try fx.tmp.dir.createDir(t.io, "sub", .default_dir);
    var open = fx.store();
    open.options.allow_paths = true;
    open.conf = fx.tmp.dir;
    try open.commit(t.allocator, "sub/net", &pkg);
    var back = try open.load(t.allocator, "sub/net", null);
    back.deinit(t.allocator);
    try t.expectError(error.PackageNotFound, open.load(t.allocator, "sub/none", null));
    try t.expectError(error.InvalidPackageName, open.load(t.allocator, "", null));
}

test "files: FIFO, directory, /dev/zero and unsafe links are refused without blocking" {
    var fx = try Fixture.init();
    defer fx.deinit();
    const st = fx.store();
    var pkg = try uci.parse(t.allocator, base_conf);
    defer pkg.deinit(t.allocator);
    try mkfifoAt(fx.conf, "fifo");
    try fx.conf.createDir(t.io, "dir", .default_dir);
    fx.conf.symLink(t.io, "/dev/zero", "zero", .{}) catch return error.SkipZigTest;
    try fx.put(fx.conf, "real", base_conf);
    try fx.conf.symLink(t.io, "../outside", "esc", .{}); // leaves the directory
    try fx.conf.symLink(t.io, "nowhere", "dangling", .{});
    try fx.conf.symLink(t.io, "real", "hop", .{});
    try fx.conf.symLink(t.io, "hop", "chain", .{}); // a link to a link
    try fx.conf.symLink(t.io, "/etc/hostname", "abs", .{});
    for ([_][]const u8{ "fifo", "dir", "zero", "esc", "dangling", "chain", "abs" }) |n| {
        try t.expectError(error.NotRegularFile, st.load(t.allocator, n, null));
        try t.expectError(error.NotRegularFile, st.loadStaged(t.allocator, n, null));
        try t.expectError(error.NotRegularFile, st.commit(t.allocator, n, &pkg));
        try t.expectError(error.NotRegularFile, st.importText(t.allocator, n, "", null));
        try t.expectError(error.NotRegularFile, st.readFile(t.allocator, fx.conf, n));
    }
    // a FIFO as a delta file
    try mkfifoAt(fx.save, "fifo");
    try t.expectError(error.NotRegularFile, st.staged(t.allocator, "fifo"));
    try t.expectError(error.NotRegularFile, st.revert("fifo"));
    try t.expectError(error.PackageNotFound, st.load(t.allocator, "absent", null));
    const bytes = try fx.read(fx.conf, "real");
    defer t.allocator.free(bytes);
    try t.expectEqualStrings(base_conf, bytes);
}

test "capture: what the binary does with a link, FIFO or directory as the config file, and what we do" {
    const text = @embedFile("testdata/store_capture.txt");
    var seen: usize = 0;
    var it = std.mem.splitSequence(u8, text, "=== file ");
    _ = it.next();
    while (it.next()) |chunk| {
        const nl = std.mem.indexOfScalar(u8, chunk, '\n').?;
        const name = chunk[0..nl];
        const show_rc = std.mem.trim(u8, section(chunk, "--- show_rc\n", "--- set_rc\n"), "\n");
        const binary_reads = std.mem.eql(u8, show_rc, "0");
        var fx = try Fixture.init();
        defer fx.deinit();
        try fx.put(fx.conf, "real", base_conf);
        try fx.put(fx.tmp.dir, "outside", base_conf);
        if (std.mem.eql(u8, name, "link-same-dir")) {
            try fx.conf.symLink(t.io, "real", "t", .{});
        } else if (std.mem.eql(u8, name, "link-escape")) {
            try fx.conf.symLink(t.io, "../outside", "t", .{});
        } else if (std.mem.eql(u8, name, "link-dangling")) {
            try fx.conf.symLink(t.io, "nowhere", "t", .{});
        } else if (std.mem.eql(u8, name, "link-chain")) {
            try fx.conf.symLink(t.io, "real", "hop", .{});
            try fx.conf.symLink(t.io, "hop", "t", .{});
        } else if (std.mem.eql(u8, name, "fifo")) {
            try mkfifoAt(fx.conf, "t");
        } else try fx.conf.createDir(t.io, "t", .default_dir);
        const st = fx.store();
        if (st.load(t.allocator, "t", null)) |p| {
            var pp = p;
            pp.deinit(t.allocator);
            // we read it only where the binary does, and only the safe shape
            try t.expect(binary_reads);
            try t.expectEqualStrings("link-same-dir", name);
            // and a commit through it behaves as the binary's: the target changes, the link stays
            var ed = try st.baseEditor(t.allocator, "t", null);
            defer ed.deinit();
            try ed.set("lan", "k", "1");
            try st.commitEditor(t.allocator, "t", &ed, try st.stamp("t"));
            const real = try fx.read(fx.conf, "real");
            defer t.allocator.free(real);
            try t.expectEqual(true, std.mem.indexOf(u8, real, "option k") != null);
            try t.expect((try fx.conf.statFile(t.io, "t", .{ .follow_symlinks = false })).kind == .sym_link);
        } else |e| {
            // where the binary refuses (rc 1) we refuse; where it follows a
            // chain or a link out of the directory we deliberately do not
            if (!binary_reads) {
                try t.expect(e == error.NotRegularFile or e == error.PackageNotFound);
            } else try t.expectEqual(error.NotRegularFile, e);
            try t.expect(std.mem.eql(u8, name, "link-escape") or std.mem.eql(u8, name, "link-chain") or !binary_reads);
        }
        seen += 1;
    }
    try t.expectEqual(@as(usize, 6), seen);
}

test "-C and -p: an override file replaces the base for reading; extra delta directories replay before save's (as measured)" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.put(fx.conf, "net", "config iface 'lan'\n\toption proto 'static'\n");
    try fx.tmp.dir.createDir(t.io, "ov", .default_dir);
    try fx.tmp.dir.createDir(t.io, "p2", .default_dir);
    var ov = try fx.tmp.dir.openDir(t.io, "ov", .{});
    defer ov.close(t.io);
    var p2 = try fx.tmp.dir.openDir(t.io, "p2", .{});
    defer p2.close(t.io);
    try fx.put(ov, "net", "config iface 'lan'\n\toption proto 'OVERRIDE'\n");
    try fx.put(p2, "net", "net.lan.proto='fromp2'\nnet.lan.w='p'\n");
    try fx.put(fx.save, "net", "net.lan.w='save'\n");
    var st = fx.store();
    st.override = ov;
    st.extra_save = &.{p2};
    var staged = try st.loadStaged(t.allocator, "net", null);
    defer staged.deinit(t.allocator);
    const lan = staged.section("iface", "lan").?;
    try t.expectEqualStrings("fromp2", lan.get("proto").?); // base 'static', then p2
    try t.expectEqualStrings("save", lan.get("w").?); // save's delta comes last
    var view = try st.loadView(t.allocator, "net", null);
    defer view.deinit(t.allocator);
    try t.expectEqualStrings("fromp2", view.section("iface", "lan").?.get("proto").?); // delta still beats the override
    var plain = fx.store();
    plain.override = ov;
    var v2 = try plain.loadView(t.allocator, "net", null);
    defer v2.deinit(t.allocator);
    try t.expectEqualStrings("OVERRIDE", v2.section("iface", "lan").?.get("proto").?);
    var c = try plain.loadStaged(t.allocator, "net", null); // commit's view ignores the override
    defer c.deinit(t.allocator);
    try t.expectEqualStrings("static", c.section("iface", "lan").?.get("proto").?);
}

test "merge: a refused merge changes nothing" {
    var base = try uci.parse(t.allocator, base_conf);
    defer base.deinit(t.allocator);
    var ed = try uci.Editor.init(t.allocator, &base);
    defer ed.deinit();
    var before = try ed.toPackage(t.allocator);
    defer before.deinit(t.allocator);
    // the first section is fine, the third clashes in type: nothing may be applied
    var bad = try uci.parse(t.allocator, "config x 'fresh'\n\toption a '1'\nconfig rule\n\toption q 'z'\nconfig other 'lan'\n");
    defer bad.deinit(t.allocator);
    try t.expectError(error.DuplicateSection, uci.merge(&ed, &bad));
    var after = try ed.toPackage(t.allocator);
    defer after.deinit(t.allocator);
    try t.expect(before.eql(&after));
}

test "files: a link to a plain name in the same directory is followed and stays a link (as the binary does)" {
    var fx = try Fixture.init();
    defer fx.deinit();
    const st = fx.store();
    try fx.put(fx.conf, "real", base_conf);
    try fx.conf.symLink(t.io, "real", "lnk", .{});
    var p = try st.load(t.allocator, "lnk", null);
    defer p.deinit(t.allocator);
    try t.expect(p.section("iface", "lan") != null);
    var ed = try uci.Editor.init(t.allocator, &p);
    defer ed.deinit();
    try ed.set("lan", "k", "v");
    try st.commitEditor(t.allocator, "lnk", &ed, try st.stamp("lnk"));
    const kind = (try fx.conf.statFile(t.io, "lnk", .{ .follow_symlinks = false })).kind;
    try t.expect(kind == .sym_link);
    var back = try st.load(t.allocator, "real", null);
    defer back.deinit(t.allocator);
    try t.expectEqualStrings("v", back.section("iface", "lan").?.get("k").?);
    try t.expectEqual(@as(usize, 0), try tempCount(&fx, fx.conf));
}

test "revert: a symlink or a FIFO at the delta name is refused, nothing is created or truncated" {
    var fx = try Fixture.init();
    defer fx.deinit();
    const st = fx.store();
    try fx.put(fx.tmp.dir, "victim", "precious");
    try fx.save.symLink(t.io, "../victim", "net", .{});
    try t.expectError(error.NotRegularFile, st.revert("net"));
    const v = try fx.read(fx.tmp.dir, "victim");
    defer t.allocator.free(v);
    try t.expectEqualStrings("precious", v);
    // no delta at all: revert does not create one
    try st.revert("absent");
    try t.expectError(error.FileNotFound, fx.save.statFile(t.io, "absent", .{}));
}

test "save and partial revert: the delta replays to the editor's state; a section or option goes back to the committed one" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.put(fx.conf, "t", base_conf);
    var s = uci.Session.init(t.allocator, fx.store());
    defer s.deinit();
    try s.run("set t.lan.a=1\nadd t rule\nset t.@rule[-1].name=n\ndelete t.@rule[0]\nadd_list t.lan.dns=9.9.9.9\ndelete t.lan.proto\nset t.fresh=thing\nset t.fresh.q='a b'\nreorder t.fresh=0\n", .{}, null, null);
    try s.save("t");
    // a second session, built from the files alone, sees the same state
    var s2 = uci.Session.init(t.allocator, fx.store());
    defer s2.deinit();
    var p1 = try (try s.editor("t")).toPackage(t.allocator);
    defer p1.deinit(t.allocator);
    var p2 = try (try s2.editor("t")).toPackage(t.allocator);
    defer p2.deinit(t.allocator);
    try t.expect(eqlUnordered(&p1, &p2));
    try t.expect(try fx.store().hasStaged(t.allocator, "t"));
    // option, then section, then the deleted/added ones
    try s.run("revert t.lan.proto\n", .{}, null, null);
    var p3 = try (try s.editor("t")).toPackage(t.allocator);
    defer p3.deinit(t.allocator);
    try t.expectEqualStrings("static", p3.section("iface", "lan").?.get("proto").?);
    try t.expectEqualStrings("1", p3.section("iface", "lan").?.get("a").?); // other edits stay
    try s.run("revert t.lan\nrevert t.fresh\n", .{}, null, null);
    var p4 = try (try s.editor("t")).toPackage(t.allocator);
    defer p4.deinit(t.allocator);
    const lan = p4.section("iface", "lan").?;
    try t.expect(lan.get("a") == null and lan.getList("dns").len == 2);
    try t.expect(p4.section("thing", "fresh") == null);
    try t.expectError(error.NoSuchSection, s.run("revert t.@nosuch[0]\n", .{}, null, null));
    // a reverted state saved again is the committed file: an empty delta
    try s.run("revert t.@rule[0]\n", .{}, null, null);
    try s.save("t");
    // the added rule is still there (revert of an unrelated section); revert whole package
    try s.run("revert t\n", .{}, null, null);
    try t.expect(!try fx.store().hasStaged(t.allocator, "t"));
}

test "a read error is not absence" {
    if (linux.getuid() == 0) return error.SkipZigTest; // root reads anything
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.put(fx.conf, "net", base_conf);
    {
        const f = try fx.conf.openFile(t.io, "net", .{});
        defer f.close(t.io);
        try f.setPermissions(t.io, @fromBackingInt(@intCast(0)));
    }
    const st = fx.store();
    try t.expectError(error.AccessDenied, st.load(t.allocator, "net", null));
    try t.expectError(error.AccessDenied, st.loadStaged(t.allocator, "net", null));
    var pkg = try uci.parse(t.allocator, base_conf);
    defer pkg.deinit(t.allocator);
    // a commit has to open the file to lock it: refused as such, nothing replaced
    try t.expectError(error.AccessDenied, st.commit(t.allocator, "net", &pkg));
    // a directory that cannot be searched: a stat failure, not "no such package"
    var fx2 = try Fixture.init();
    defer fx2.deinit();
    try fx2.put(fx2.save, "net", "x");
    {
        const f = try fx2.save.openFile(t.io, "net", .{});
        defer f.close(t.io);
        try f.setPermissions(t.io, @fromBackingInt(@intCast(0)));
    }
    try t.expectError(error.AccessDenied, fx2.store().staged(t.allocator, "net"));
}

// ── Session ─────────────────────────────────────────────────────────────────

fn getOpt(s: *uci.Session, pkg: []const u8, sec: []const u8, key: []const u8) !?[]u8 {
    var p = try (try s.editor(pkg)).toPackage(t.allocator);
    defer p.deinit(t.allocator);
    const sc = p.sectionByName(sec) orelse return null;
    const v = sc.get(key) orelse return null;
    return try t.allocator.dupe(u8, v);
}

test "Session: stops at the first failing command by default, keeps going on request" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.put(fx.conf, "t", base_conf);
    var s = uci.Session.init(t.allocator, fx.store());
    defer s.deinit();
    var rep: uci.RunReport = .{};
    try t.expectError(error.NoSuchSection, s.run("set t.lan.a=1\nset t.nope.b=2\nset t.lan.c=3\n", .{}, &rep, null));
    try t.expectEqual(@as(usize, 1), rep.executed);
    try t.expectEqual(@as(usize, 1), rep.failed);
    try t.expectEqual(@as(usize, 1), rep.first_failed);
    // earlier commands stay applied in memory, later ones never ran, disk untouched
    const a = (try getOpt(&s, "t", "lan", "a")).?;
    defer t.allocator.free(a);
    try t.expectEqualStrings("1", a);
    try t.expect((try getOpt(&s, "t", "lan", "c")) == null);
    const file = try fx.read(fx.conf, "t");
    defer t.allocator.free(file);
    try t.expectEqualStrings(base_conf, file);
    try s.run("set t.nope.b=2\nset t.lan.c=3\nbogus\n", .{ .keep_going = true }, &rep, null);
    try t.expectEqual(@as(usize, 1), rep.executed);
    try t.expectEqual(@as(usize, 2), rep.failed);
    try t.expect(rep.first_error.? == error.NoSuchSection);
    s.discard("t");
    try t.expect((try getOpt(&s, "t", "lan", "a")) == null);
}

test "Session: command errors are named, not collapsed" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.put(fx.conf, "t", base_conf);
    var s = uci.Session.init(t.allocator, fx.store());
    defer s.deinit();
    const cases = [_]struct { []const u8, anyerror }{
        .{ "frob t.lan.a=1", error.UnknownCommand },
        .{ "set t.lan.a", error.BadCommand },
        .{ "set t", error.BadCommand },
        .{ "set =x", error.BadCommand },
        .{ "set t..a=1", error.BadCommand },
        .{ "add t", error.BadCommand },
        .{ "reorder t.lan=x", error.BadCommand },
        .{ "delete t", error.BadCommand },
        .{ "delete t.lan.dns=x", error.BadCommand },
        .{ "set t.lan.bad-key=1", error.InvalidName },
        .{ "rename t.@rule[0]=lan", error.DuplicateSection },
        .{ "set a/b.lan.a=1", error.InvalidPackageName },
        .{ "set absent.lan.a=1", error.PackageNotFound },
        .{ "set t.lan.a=1 extra", error.BadCommand },
    };
    for (cases) |c| try t.expectError(c[1], s.run(c[0], .{}, null, null));
}

test "Session: commit writes what the editor holds; revert drops edits and the delta" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.put(fx.conf, "t", base_conf);
    try fx.put(fx.save, "t", "t.lan.x='fromcli'\n");
    var s = uci.Session.init(t.allocator, fx.store());
    defer s.deinit();
    // the CLI's staged change is part of the session's view, and commit folds it in
    try s.run("set t.lan.y=2\nadd t rule\nset t.@rule[-1].name=new\ncommit\n", .{}, null, null);
    var back = try fx.store().load(t.allocator, "t", null);
    defer back.deinit(t.allocator);
    try t.expectEqualStrings("fromcli", back.section("iface", "lan").?.get("x").?);
    try t.expectEqualStrings("new", back.nth("rule", -1).?.get("name").?);
    try t.expect(!try fx.store().hasStaged(t.allocator, "t"));
    // revert: edits gone, delta emptied
    try fx.put(fx.save, "t", "t.lan.z='1'\n");
    try s.run("set t.lan.w=1\nrevert t\nset t.lan.v=1\ncommit t\n", .{}, null, null);
    var b2 = try fx.store().load(t.allocator, "t", null);
    defer b2.deinit(t.allocator);
    const lan = b2.section("iface", "lan").?;
    try t.expect(lan.get("w") == null and lan.get("z") == null);
    try t.expectEqualStrings("1", lan.get("v").?);
    // commit of a package never opened: from its delta; of a missing one: not found
    try fx.put(fx.save, "t", "t.lan.q='9'\n");
    var s2 = uci.Session.init(t.allocator, fx.store());
    defer s2.deinit();
    try s2.commit("t");
    var b3 = try fx.store().load(t.allocator, "t", null);
    defer b3.deinit(t.allocator);
    try t.expectEqualStrings("9", b3.section("iface", "lan").?.get("q").?);
    try t.expectError(error.PackageNotFound, s2.commit("absent"));
}

test "Session: the number of open packages is bounded" {
    var fx = try Fixture.init();
    defer fx.deinit();
    var s = uci.Session.init(t.allocator, fx.store());
    defer s.deinit();
    var nb: [16]u8 = undefined;
    var i: usize = 0;
    while (i <= 256) : (i += 1) {
        const n = try std.fmt.bufPrint(&nb, "p{d}", .{i});
        try fx.put(fx.conf, n, "config a 'b'\n");
        if (i < 256) {
            _ = try s.editor(n);
        } else try t.expectError(error.TooManyPackages, s.editor(n));
    }
}

test "merge: named sections need the same type, anonymous ones are added" {
    var base = try uci.parse(t.allocator, base_conf);
    defer base.deinit(t.allocator);
    var ed = try uci.Editor.init(t.allocator, &base);
    defer ed.deinit();
    var add = try uci.parse(t.allocator, "config iface 'lan'\n\tlist dns '9.9.9.9'\nconfig rule\n\toption name 'x'\n");
    defer add.deinit(t.allocator);
    try uci.merge(&ed, &add);
    var clash = try uci.parse(t.allocator, "config other 'lan'\n");
    defer clash.deinit(t.allocator);
    try t.expectError(error.DuplicateSection, uci.merge(&ed, &clash));
    var out = try ed.toPackage(t.allocator);
    defer out.deinit(t.allocator);
    try t.expectEqual(@as(usize, 3), out.section("iface", "lan").?.getList("dns").len);
    try t.expectEqual(@as(usize, 3), blk: {
        var n: usize = 0;
        var it = out.iterate("rule");
        while (it.next()) |_| n += 1;
        break :blk n;
    });
}

// ── script splitting and show delimiter ─────────────────────────────────────

test "parseScript: words, quotes, comments, and ; discarding the rest of the line" {
    var sc = try uci.parseScript(t.allocator, "# c\n\n  set a.b.c=\"x y\"  # tail\r\nset a.b.c='1'; set a.b.d=2\nadd a 'ty pe'\n;\nset a\\ b=c\n", null);
    defer sc.deinit(t.allocator);
    try t.expectEqual(@as(usize, 4), sc.commands.len);
    try t.expectEqualStrings("a.b.c=x y", sc.commands[0][1]);
    try t.expectEqual(@as(usize, 2), sc.commands[1].len);
    try t.expectEqualStrings("ty pe", sc.commands[2][2]);
    try t.expectEqualStrings("a b=c", sc.commands[3][1]);
    var d: uci.Diagnostics = .{};
    try t.expectError(error.TooManyArguments, uci.parseScript(t.allocator, "\nset 1 2 3 4 5 6 7 8 9\n", &d));
    try t.expectEqual(@as(usize, 2), d.line);
    try t.expectError(error.UnterminatedQuote, uci.parseScript(t.allocator, "set 'a\n", null));
    const long = try t.allocator.alloc(u8, uci.max_line_len + 1);
    defer t.allocator.free(long);
    @memset(long, 'a');
    try t.expectError(error.LineTooLong, uci.parseScript(t.allocator, long, null));
}

test "show: a list delimiter is honoured and counted into the output cap" {
    var base = try uci.parse(t.allocator, base_conf);
    defer base.deinit(t.allocator);
    var ed = try uci.Editor.init(t.allocator, &base);
    defer ed.deinit();
    const s = try ed.show(t.allocator, "t", .{ .delimiter = "," });
    defer t.allocator.free(s);
    try t.expect(std.mem.indexOf(u8, s, "t.lan.dns='1.1.1.1','8.8.8.8'\n") != null);
    const huge = try t.allocator.alloc(u8, uci.max_show_len + 1);
    defer t.allocator.free(huge);
    @memset(huge, ',');
    try t.expectError(error.OutputTooLarge, ed.show(t.allocator, "t", .{ .delimiter = huge }));
    // the delimiter counts by its LENGTH: just under the cap by itself, over it with the rest of the text
    try t.expectError(error.OutputTooLarge, ed.show(t.allocator, "t", .{ .delimiter = huge[0 .. uci.max_show_len - 50] }));
}

// ── lost updates, lock details, error precedence (last review round) ───────

test "ChangedOnDisk: an editor commit refuses to overwrite another commit; replace overwrites on purpose" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.put(fx.conf, "t", base_conf);
    var s = uci.Session.init(t.allocator, fx.store());
    defer s.deinit();
    try s.run("set t.lan.mine=1\n", .{}, null, null);
    // another writer commits between our load and our commit
    try fx.store().importText(t.allocator, "t", "config iface 'lan'\n\toption theirs '1'\n", null);
    try t.expectError(error.ChangedOnDisk, s.commit("t"));
    try t.expectError(error.ChangedOnDisk, s.commit(null)); // and again: still refused
    const got = try fx.read(fx.conf, "t");
    defer t.allocator.free(got);
    try t.expect(std.mem.indexOf(u8, got, "theirs") != null and std.mem.indexOf(u8, got, "mine") == null);
    try t.expectEqual(@as(usize, 0), try tempCount(&fx, fx.conf));
    s.discard("t");
    try s.run("set t.lan.mine=1\n", .{}, null, null);
    try s.commit("t");
    const both = try fx.read(fx.conf, "t");
    defer t.allocator.free(both);
    try t.expect(std.mem.indexOf(u8, both, "theirs") != null and std.mem.indexOf(u8, both, "mine") != null);
    // a deleted file is a change too, and `replace` overwrites without asking
    const stamp = try fx.store().stamp("t");
    try fx.conf.deleteFile(t.io, "t");
    var base = try uci.parse(t.allocator, base_conf);
    defer base.deinit(t.allocator);
    var ed = try uci.Editor.init(t.allocator, &base);
    defer ed.deinit();
    try t.expectError(error.ChangedOnDisk, fx.store().commitEditor(t.allocator, "t", &ed, stamp));
    var pkg = try ed.toPackage(t.allocator);
    defer pkg.deinit(t.allocator);
    try fx.store().replace(t.allocator, "t", &pkg);
}

test "ChangedOnDisk: a commit by the real uci binary in between is noticed (set UCI_BIN to run)" {
    const bin = std.testing.environ.getPosix("UCI_BIN") orelse return error.SkipZigTest;
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.put(fx.conf, "t", base_conf);
    var s = uci.Session.init(t.allocator, fx.store());
    defer s.deinit();
    try s.run("set t.lan.mine=1\n", .{}, null, null);
    var cb: [160]u8 = undefined;
    var sb: [160]u8 = undefined;
    const cpath = try std.fmt.bufPrint(&cb, ".zig-cache/tmp/{s}/conf", .{&fx.tmp.sub_path});
    const spath = try std.fmt.bufPrint(&sb, ".zig-cache/tmp/{s}/save", .{&fx.tmp.sub_path});
    for ([_][]const []const u8{
        &.{ bin, "-c", cpath, "-t", spath, "set", "t.lan.theirs=1" },
        &.{ bin, "-c", cpath, "-t", spath, "commit", "t" },
    }) |argv| {
        const r = try std.process.run(t.allocator, t.io, .{ .argv = argv });
        defer t.allocator.free(r.stdout);
        defer t.allocator.free(r.stderr);
        try t.expect(r.term == .exited and r.term.exited == 0);
    }
    try t.expectError(error.ChangedOnDisk, s.commit("t"));
    const got = try fx.read(fx.conf, "t");
    defer t.allocator.free(got);
    try t.expect(std.mem.indexOf(u8, got, "theirs") != null and std.mem.indexOf(u8, got, "mine") == null);
}

test "lock: a second real process holding the flock blocks a commit, within a bound" {
    var fx = try Fixture.init();
    defer fx.deinit();
    var cs = try CommitSetup.init(&fx);
    defer cs.deinit();
    var pb: [160]u8 = undefined;
    const path = try std.fmt.bufPrint(&pb, ".zig-cache/tmp/{s}/conf/net", .{&fx.tmp.sub_path});
    var child = std.process.spawn(t.io, .{
        .argv = &.{ "flock", "-x", path, "sleep", "1" },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    }) catch return error.SkipZigTest;
    t.io.sleep(.fromMilliseconds(300), .awake) catch {};
    var st = fx.store();
    st.options.lock_timeout_ms = 100;
    try t.expectError(error.LockTimeout, st.commit(t.allocator, "net", &cs.new));
    st.options.lock_timeout_ms = 10_000;
    try st.commit(t.allocator, "net", &cs.new); // waits until the holder exits
    _ = child.wait(t.io) catch {};
    const got = try fx.read(fx.conf, "net");
    defer t.allocator.free(got);
    try t.expectEqualSlices(u8, cs.new_bytes, got);
}

var swap_dir: std.Io.Dir = undefined;
var swap_done = false;
fn swapNet() void {
    if (swap_done) return;
    swap_done = true;
    swap_dir.writeFile(t.io, .{ .sub_path = "net.swap", .data = base_conf }) catch return;
    swap_dir.rename("net.swap", swap_dir, "net", t.io) catch {};
}

test "lock: a rename between open and lock is noticed and the lock retried on the new file" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.put(fx.conf, "net", base_conf);
    var pkg = try uci.parse(t.allocator, base_conf);
    defer pkg.deinit(t.allocator);
    const hook = &store_mod.crash_hook;
    swap_dir = fx.conf;
    swap_done = false;
    hook.lock_retries = 0;
    hook.after_open = &swapNet;
    defer hook.after_open = null;
    try fx.store().commit(t.allocator, "net", &pkg);
    try t.expectEqual(@as(u32, 1), hook.lock_retries);
}

test "lock: a timeout of maxInt does not wrap, and a holder released fast lets the commit in" {
    var fx = try Fixture.init();
    defer fx.deinit();
    var cs = try CommitSetup.init(&fx);
    defer cs.deinit();
    var st = fx.store();
    st.options.lock_timeout_ms = std.math.maxInt(u32);
    const holder = try fx.conf.openFile(t.io, "net", .{ .mode = .read_only });
    try t.expect(try holder.tryLock(t.io, .exclusive));
    const Rel = struct {
        fn run(f: std.Io.File) void {
            t.io.sleep(.fromMilliseconds(100), .awake) catch {};
            f.close(t.io);
        }
    };
    const th = try std.Thread.spawn(.{}, Rel.run, .{holder});
    try st.commit(t.allocator, "net", &cs.new);
    th.join();
}

test "lock: a new package has no lock, so no stale temp is reaped; the next commit reaps" {
    var fx = try Fixture.init();
    defer fx.deinit();
    var pkg = try uci.parse(t.allocator, base_conf);
    defer pkg.deinit(t.allocator);
    try fx.put(fx.conf, ".newp.uci-tmp-0123456789abcdef", "maybe another creator's live temp");
    try fx.store().commit(t.allocator, "newp", &pkg); // creates it: unlocked
    try t.expectEqual(@as(usize, 1), try tempCount(&fx, fx.conf));
    try fx.store().commit(t.allocator, "newp", &pkg); // exists now: locked, reaps
    try t.expectEqual(@as(usize, 0), try tempCount(&fx, fx.conf));
}

test "names: a control byte is refused even with allow_paths" {
    var fx = try Fixture.init();
    defer fx.deinit();
    var st = fx.store();
    st.options.allow_paths = true;
    for ([_][]const u8{ "a\nb", "a\rb", "a\x01b", "a\x7fb", "sub/x\ny" }) |n| {
        try t.expectError(error.InvalidPackageName, st.load(t.allocator, n, null));
        try t.expectError(error.InvalidPackageName, st.stamp(n));
        try t.expectError(error.InvalidPackageName, st.revert(n));
    }
}

test "Session.commit after CommittedNotDurable: the editor stays dirty and stale, a retry is ChangedOnDisk, discard reloads" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.put(fx.conf, "t", base_conf);
    var s = uci.Session.init(t.allocator, fx.store());
    defer s.deinit();
    try s.run("set t.lan.x=1\n", .{}, null, null);
    store_mod.crash_hook.fail_dir_sync = true;
    try t.expectError(error.CommittedNotDurable, s.commit("t"));
    store_mod.crash_hook.fail_dir_sync = false;
    const on_disk = try fx.read(fx.conf, "t");
    defer t.allocator.free(on_disk);
    try t.expect(std.mem.indexOf(u8, on_disk, "option x '1'") != null); // the new file is there
    try t.expectError(error.ChangedOnDisk, s.commit("t")); // the editor did not move on
    s.discard("t");
    var p = try (try s.editor("t")).toPackage(t.allocator);
    defer p.deinit(t.allocator);
    try t.expectEqualStrings("1", p.section("iface", "lan").?.get("x").?); // reloaded from disk
    // both a failing directory sync and an undeletable delta: StagedNotCleared wins
    var fx2 = try Fixture.init();
    defer fx2.deinit();
    try fx2.put(fx2.conf, "net", base_conf);
    try fx2.save.createDir(t.io, "net", .default_dir);
    var pkg = try uci.parse(t.allocator, base_conf);
    defer pkg.deinit(t.allocator);
    store_mod.crash_hook.fail_dir_sync = true;
    defer store_mod.crash_hook.fail_dir_sync = false;
    try t.expectError(error.StagedNotCleared, fx2.store().commit(t.allocator, "net", &pkg));
}

// ── deterministic fuzz harness: scripts through a Session ───────────────────

const fuzz_driver = @import("testkit").fuzz.driver;
pub const SessionLabel = enum { script_rejected, cmds_ok, cmds_failed, model_checked, committed, saved_replayed, partial_revert_ran, save_moved };
pub var session_reach: [@typeInfo(SessionLabel).@"enum".field_names.len]usize = @splat(0);
var session_seed: usize = 0;

fn smark(comptime l: SessionLabel) void {
    session_reach[@backingInt(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

const f_cmds = [_][]const u8{ "set", "add", "add_list", "del_list", "delete", "rename", "reorder", "revert", "commit", "set", "set", "add_list" };
const f_secs = [_][]const u8{ "lan", "@rule[0]", "@rule[-1]", "@rule[9]", "new", "cfg0392bd", "wan", "" };
const f_keys = [_][]const u8{ "proto", "dns", "a", "b", "bad-key", "name" };
const f_vals = [_][]const u8{ "x", "", "1", "q r", "'q r'", "\"a\\\"b\"", "9", "0" };
const f_types = [_][]const u8{ "rule", "iface", "bad type", "t" };

/// Random command scripts through `parseScript` and a `Session` over a real
/// directory: whatever the commands do, the editor stays a model that
/// serializes and parses back equal, `show` works, and (every 16th seed) a
/// commit followed by a load gives the same model.
pub fn sessionHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var buf: [160]u8 = undefined;
    const n: usize = src.slice(&buf);
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(gpa);
    var i: usize = 0;
    var count: usize = 0;
    while (i + 4 <= n and count < 12) : (count += 1) {
        const b = buf[i..][0..4];
        i += 4;
        const cmd = f_cmds[b[0] % f_cmds.len];
        const sec = f_secs[b[1] % f_secs.len];
        const key = f_keys[b[2] % f_keys.len];
        const val = f_vals[b[3] % f_vals.len];
        if (b[3] == 255) {
            try text.append(gpa, b[2]); // a raw byte now and then
            try text.append(gpa, '\n');
            continue;
        }
        if (std.mem.eql(u8, cmd, "add")) {
            try text.print(gpa, "add t {s}\n", .{f_types[b[1] % f_types.len]});
        } else if (std.mem.eql(u8, cmd, "revert") and b[0] & 0x10 != 0) {
            if (b[0] & 0x20 != 0) try text.print(gpa, "revert t.{s}.{s}\n", .{ sec, key }) else try text.print(gpa, "revert t.{s}\n", .{sec});
        } else if (std.mem.eql(u8, cmd, "revert") or std.mem.eql(u8, cmd, "commit")) {
            try text.print(gpa, "{s} t\n", .{cmd});
        } else if (std.mem.eql(u8, cmd, "set") and b[2] % 5 == 0) {
            try text.print(gpa, "set t.{s}={s}\n", .{ sec, f_types[b[1] % f_types.len] });
        } else if (std.mem.eql(u8, cmd, "rename") or std.mem.eql(u8, cmd, "reorder")) {
            if (b[0] & 0x10 != 0) try text.print(gpa, "{s} t.{s}={s}\n", .{ cmd, sec, val }) else try text.print(gpa, "{s} t.{s}.{s}={s}\n", .{ cmd, sec, key, val });
        } else if (std.mem.eql(u8, cmd, "delete")) {
            if (b[0] & 0x10 != 0) try text.print(gpa, "delete t.{s}\n", .{sec}) else if (b[0] & 0x20 != 0) try text.print(gpa, "delete t.{s}.{s}={s}\n", .{ sec, key, val }) else try text.print(gpa, "delete t.{s}.{s}\n", .{ sec, key });
        } else {
            try text.print(gpa, "{s} t.{s}.{s}={s}\n", .{ cmd, sec, key, val });
        }
    }

    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.put(fx.conf, "t", base_conf);
    var s = uci.Session.init(gpa, fx.store());
    defer s.deinit();
    var rep: uci.RunReport = .{};
    s.run(text.items, .{ .keep_going = true }, &rep, null) catch |e| switch (e) {
        error.OutOfMemory => return e,
        else => {
            smark(.script_rejected);
            return;
        },
    };
    if (rep.executed > 0) smark(.cmds_ok);
    if (rep.failed > 0) smark(.cmds_failed);
    const ed = try s.editor("t");
    var pkg = try ed.toPackage(gpa);
    defer pkg.deinit(gpa);
    const shown = try ed.show(gpa, "t", .{});
    gpa.free(shown);
    if (uci.serialize(gpa, &pkg)) |out| {
        defer gpa.free(out);
        var back = try uci.parse(gpa, out);
        defer back.deinit(gpa);
        if (!store_mod.eqlOnDisk(&back, &pkg)) {
            std.debug.print("script:\n{s}\nserialized:\n{s}\n", .{ text.items, out });
            return error.ModelDoesNotRoundTrip;
        }
        smark(.model_checked);
    } else |e| switch (e) {
        error.OutOfMemory => return e,
        else => {}, // a documented refusal
    }
    if (std.mem.indexOf(u8, text.items, "revert t.") != null and rep.executed > 0) smark(.partial_revert_ran);
    // `save`: another session built from the files alone sees the same model
    save_check: {
        s.save("t") catch |e| switch (e) {
            error.OutOfMemory => return e,
            // two sections with one id (a named one called like a generated
            // anonymous id) have no delta: a documented refusal
            error.DuplicateSection => break :save_check,
            else => return e,
        };
        var s2 = uci.Session.init(gpa, fx.store());
        defer s2.deinit();
        var p2 = try (try s2.editor("t")).toPackage(gpa);
        defer p2.deinit(gpa);
        if (!eqlUnordered(&p2, &pkg)) {
            std.debug.print("script:\n{s}\n", .{text.items});
            return error.SavedDeltaDoesNotReplay;
        }
        smark(.saved_replayed);
        const delta = try fx.save.readFileAlloc(t.io, "t", gpa, .limited(1 << 20));
        defer gpa.free(delta);
        if (std.mem.indexOfScalar(u8, delta, '^') != null) smark(.save_moved);
    }
    session_seed += 1;
    if (session_seed % 16 == 0) {
        fx.store().commitEditor(gpa, "t", ed, try fx.store().stamp("t")) catch |e| switch (e) {
            error.OutOfMemory => return e,
            error.WouldNotReload, error.InvalidName, error.UnserializableValue, error.DuplicateSection => return,
            else => return e,
        };
        var back = try fx.store().load(gpa, "t", null);
        defer back.deinit(gpa);
        if (!store_mod.eqlOnDisk(&back, &pkg)) return error.CommitDoesNotReload;
        smark(.committed);
    }
}

test "fuzz harness: sessions reach ok and failing commands, round trips and commits" {
    session_reach = @splat(0);
    session_seed = 0;
    for (0..640) |seed_n| {
        var prng = std.Random.DefaultPrng.init(seed_n);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        sessionHarness(fuzz_driver.Rng, &rng, t.allocator) catch |err| {
            std.debug.print("uci session seed {d}: {t}\n", .{ seed_n, err });
            return err;
        };
    }
    for (session_reach, 0..) |c, k| {
        if (k == @backingInt(SessionLabel.script_rejected)) continue; // reached only by a quote left open
        try t.expect(c > 0);
    }
}

// ── delta audit fixes (2026-11-04) ───────────────────────────────────────────

fn bigConf(gpa: std.mem.Allocator, n: usize, reversed: bool) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    for (0..n) |i| {
        const k = if (reversed) n - 1 - i else i;
        try out.print(gpa, "config t 's{d}'\n\toption o '1'\n", .{k});
    }
    return out.toOwnedSlice(gpa);
}

fn countLines(text: []const u8, first: u8) usize {
    var n: usize = 0;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |l| n += @intFromBool(l.len > 0 and l[0] == first);
    return n;
}

test "save: one reorder among 6000 sections is one record and reloads (audit 1)" {
    var fx = try Fixture.init();
    defer fx.deinit();
    const conf = try bigConf(t.allocator, 6000, false);
    defer t.allocator.free(conf);
    try fx.put(fx.conf, "big", conf);
    var s = uci.Session.init(t.allocator, fx.store());
    defer s.deinit();
    try s.run("reorder big.s5999=0\n", .{}, null, null);
    try s.save("big");
    const delta = try fx.read(fx.save, "big");
    defer t.allocator.free(delta);
    try t.expectEqual(@as(usize, 1), countLines(delta, '^'));
    try t.expect(delta.len < 100);
    var s2 = uci.Session.init(t.allocator, fx.store());
    defer s2.deinit();
    const ed = try s2.editor("big");
    try t.expectEqualStrings("s5999", ed.sections.items[0].id);
    try t.expectEqualStrings("s0", ed.sections.items[1].id);
}

test "save: a reshuffle too costly to replay is refused, the old delta stays (audit 1)" {
    var fx = try Fixture.init();
    defer fx.deinit();
    const conf = try bigConf(t.allocator, 4000, false);
    defer t.allocator.free(conf);
    try fx.put(fx.conf, "big", conf);
    const rev = try bigConf(t.allocator, 4000, true);
    defer t.allocator.free(rev);
    var pkg = try uci.parse(t.allocator, rev);
    defer pkg.deinit(t.allocator);
    var ed = try uci.Editor.init(t.allocator, &pkg);
    defer ed.deinit();
    try fx.put(fx.save, "big", "big.s1.o='7'\n");
    try t.expectError(error.WouldNotReload, fx.store().saveEditor(t.allocator, "big", &ed));
    const delta = try fx.read(fx.save, "big");
    defer t.allocator.free(delta);
    try t.expectEqualStrings("big.s1.o='7'\n", delta);
    try t.expectEqual(@as(usize, 0), try tempCount(&fx, fx.save));
}

test "diffRecords: moves are few and replay to the target order (random reshuffles)" {
    var prng = std.Random.DefaultPrng.init(0x5eed);
    const rnd = prng.random();
    for (0..300) |round| {
        const n = 1 + rnd.uintLessThan(usize, 12);
        const text = try bigConf(t.allocator, n, false);
        defer t.allocator.free(text);
        var pkg = try uci.parse(t.allocator, text);
        defer pkg.deinit(t.allocator);
        var from = try uci.Editor.init(t.allocator, &pkg);
        defer from.deinit();
        var to = try uci.Editor.init(t.allocator, &pkg);
        defer to.deinit();
        var ops = rnd.uintLessThan(usize, 6);
        while (ops > 0) : (ops -= 1) {
            switch (rnd.uintLessThan(usize, 4)) {
                0, 1 => if (to.sections.items.len > 0) {
                    const id = to.sections.items[rnd.uintLessThan(usize, to.sections.items.len)].id;
                    try to.reorder(id, rnd.uintLessThan(usize, to.sections.items.len + 1));
                },
                2 => if (to.sections.items.len > 0) try to.delete(to.sections.items[rnd.uintLessThan(usize, to.sections.items.len)].id),
                else => _ = try to.add("t"),
            }
        }
        const rec = try uci.diffRecords(t.allocator, &from, &to, "p", null);
        defer t.allocator.free(rec);
        var replay = try uci.Editor.init(t.allocator, &pkg);
        defer replay.deinit();
        try replay.applyDelta("p", rec, null);
        errdefer std.debug.print("round {d}: n={d}\n{s}\n", .{ round, n, rec });
        try t.expectEqual(to.sections.items.len, replay.sections.items.len);
        for (to.sections.items, replay.sections.items) |a, b| try t.expectEqualStrings(a.id, b.id);
        try t.expect(countLines(rec, '^') <= n);
    }
}

test "save: a package name no delta record can carry is refused, nothing is written (audit 2)" {
    var fx = try Fixture.init();
    defer fx.deinit();
    var st = fx.store();
    st.options.allow_paths = true;
    const names = [_][]const u8{ "-x", "net.v2", "a=b", "a b", "a'b", "+x" };
    for (names) |nm| {
        try fx.put(fx.conf, nm, "config t 'lan'\n\toption x '0'\n");
        var s = uci.Session.init(t.allocator, st);
        defer s.deinit();
        const ed = try s.editor(nm);
        try ed.set("lan", "x", "1");
        try t.expectError(error.InvalidPackageName, s.save(nm));
        try t.expectError(error.FileNotFound, fx.save.access(t.io, nm, .{}));
    }
    var p = try uci.parse(t.allocator, "config t 'lan'\n");
    defer p.deinit(t.allocator);
    var d = try uci.Editor.init(t.allocator, &p);
    defer d.deinit();
    try t.expectError(error.InvalidName, uci.diffRecords(t.allocator, &d, &d, "-x", null));
    const none = try uci.diffRecords(t.allocator, &d, &d, "x-y", null);
    defer t.allocator.free(none);
    try t.expectEqual(@as(usize, 0), none.len);
}

test "reapTemps: stale temps of a 100 and a 128 byte name are reaped; a temp name over NAME_MAX is a truthful error (audit 3)" {
    var fx = try Fixture.init();
    defer fx.deinit();
    var pkg = try uci.parse(t.allocator, base_conf);
    defer pkg.deinit(t.allocator);
    for ([_]usize{ 100, 128 }) |len| {
        var nb: [128]u8 = undefined;
        @memset(nb[0..len], 'n');
        const name = nb[0..len];
        try fx.store().commit(t.allocator, name, &pkg);
        var tb: [200]u8 = undefined;
        const tmp = try std.fmt.bufPrint(&tb, ".{s}.uci-tmp-0123456789abcdef", .{name});
        try fx.put(fx.conf, tmp, "debris");
        try t.expectEqual(@as(usize, 1), try tempCount(&fx, fx.conf));
        try fx.store().commit(t.allocator, name, &pkg);
        try t.expectEqual(@as(usize, 0), try tempCount(&fx, fx.conf));
    }
    var st = fx.store();
    st.options.allow_paths = true;
    var long: [240]u8 = undefined;
    @memset(&long, 'l');
    try t.expectError(error.InvalidPackageName, st.replace(t.allocator, &long, &pkg));
}

test "merge: the same name twice in one Package with two types changes nothing (audit 4)" {
    var pkg0 = try uci.parse(t.allocator, "config t 'x'\n");
    defer pkg0.deinit(t.allocator);
    var ed = try uci.Editor.init(t.allocator, &pkg0);
    defer ed.deinit();
    const secs = [_]uci.Section{
        .{ .type = "a", .name = "dup", .anonymous = false, .options = &.{} },
        .{ .type = "b", .name = "dup", .anonymous = false, .options = &.{} },
    };
    const hand: uci.Package = .{ .sections = &secs };
    try t.expectError(error.DuplicateSection, uci.merge(&ed, &hand));
    try t.expectEqual(@as(usize, 1), ed.sections.items.len);
    // parse itself refuses such a text, so no parsed Package holds this
    try t.expectError(error.DuplicateSection, uci.parse(t.allocator, "config a 'dup'\nconfig b 'dup'\n"));
    // the same type twice is fine (the second continues the first)
    const same = [_]uci.Section{ secs[0], secs[0] };
    const hand2: uci.Package = .{ .sections = &same };
    try uci.merge(&ed, &hand2);
    try t.expectEqual(@as(usize, 2), ed.sections.items.len);
}

test "revert: the truncation is fsynced (audit 5)" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.put(fx.save, "net", "net.lan.x='1'\n");
    const hook = &store_mod.crash_hook;
    defer {
        hook.recording = false;
        hook.skip = null;
    }
    hook.startRecording();
    try fx.store().revert("net");
    try t.expectEqualSlices(store_mod.Step, &.{.fsync_delta}, hook.steps[0..hook.n_steps]);
    hook.skip = .fsync_delta;
    hook.startRecording();
    try fx.store().revert("net");
    try t.expectEqual(@as(usize, 0), hook.n_steps);
}

test "lock: a tryLock failure that is not 'held' is LockFailed, not ReadFailed (audit 5)" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.put(fx.conf, "net", base_conf);
    var pkg = try uci.parse(t.allocator, base_conf);
    defer pkg.deinit(t.allocator);
    store_mod.crash_hook.fail_trylock = true;
    defer store_mod.crash_hook.fail_trylock = false;
    try t.expectError(error.LockFailed, fx.store().commit(t.allocator, "net", &pkg));
}

fn workScript(gpa: std.mem.Allocator, n: usize, cmds: usize) ![]u8 {
    var sc: std.ArrayList(u8) = .empty;
    errdefer sc.deinit(gpa);
    for (0..cmds) |i| try sc.print(gpa, "reorder t.s{d}={d}\n", .{ n - 1, if (i % 2 == 0) @as(usize, 0) else n - 1 });
    return sc.toOwnedSlice(gpa);
}

test "Session: the work limit ends a run even with keep_going, and stays spent until resetBudget (audit 6)" {
    var fx = try Fixture.init();
    defer fx.deinit();
    const conf = try bigConf(t.allocator, 8000, false);
    defer t.allocator.free(conf);
    const script = try workScript(t.allocator, 8000, 3000);
    defer t.allocator.free(script);
    try fx.put(fx.conf, "t", conf);
    var s = uci.Session.init(t.allocator, fx.store());
    defer s.deinit();
    var rep: uci.RunReport = .{};
    try t.expectError(error.WorkLimitExceeded, s.run(script, .{ .keep_going = true }, &rep, null));
    try t.expect(rep.executed > 100 and rep.executed < 3000);
    try t.expectEqual(@as(usize, 0), rep.failed); // a limit is not "a failing line"
    // spent: the next command is refused at once, however cheap
    try t.expectError(error.WorkLimitExceeded, s.run("set t.s0.o=2\n", .{ .keep_going = true }, &rep, null));
    try t.expectEqual(@as(usize, 0), rep.executed);
    s.resetBudget();
    try s.run("set t.s0.o=2\n", .{}, &rep, null);
    try t.expectEqual(@as(usize, 1), rep.executed);
}

test "merge: the item cap is exact at root.max_total_items (audit 6)" {
    const cap = uci.max_total_items;
    const secs = try t.allocator.alloc(uci.Section, cap + 1);
    defer t.allocator.free(secs);
    @memset(secs, .{ .type = "t", .name = null, .anonymous = true, .options = &.{} });
    var empty = try uci.parse(t.allocator, "");
    defer empty.deinit(t.allocator);
    var ed = try uci.Editor.init(t.allocator, &empty);
    defer ed.deinit();
    const over: uci.Package = .{ .sections = secs };
    try t.expectError(error.MemoryLimitExceeded, uci.merge(&ed, &over));
    try t.expectEqual(@as(usize, 0), ed.sections.items.len);
    const exact: uci.Package = .{ .sections = secs[0..cap] };
    try uci.merge(&ed, &exact);
    try t.expectEqual(cap, ed.sections.items.len);
    const one: uci.Package = .{ .sections = secs[0..1] };
    try t.expectError(error.MemoryLimitExceeded, uci.merge(&ed, &one));
    try t.expectEqual(cap, ed.sections.items.len);
}

test "names with allow_paths: 255 bytes at most; a file where a directory should be is absence, a link loop is an error" {
    var fx = try Fixture.init();
    defer fx.deinit();
    var st = fx.store();
    st.options.allow_paths = true;
    var long_buf: [256]u8 = @splat('a');
    try t.expectError(error.InvalidPackageName, st.load(t.allocator, &long_buf, null));
    try t.expectError(error.InvalidPackageName, st.stamp(&long_buf));
    // `net` is a file: `net/x` cannot exist (ENOTDIR) -- absent, like any missing package
    try fx.put(fx.conf, "net", base_conf);
    try t.expectError(error.PackageNotFound, st.load(t.allocator, "net/x", null));
    try t.expect(try st.stamp("net/x") == null);
    // a link loop is NOT absence: the file may well be there, we cannot tell
    try fx.conf.symLink(t.io, "loop", "loop", .{});
    try t.expectError(error.ReadFailed, st.load(t.allocator, "loop/x", null));
    try t.expectError(error.ReadFailed, st.stamp("loop/x"));
}

// ── the real calls, seen through a wrapped `std.Io` ──────────────────────────
// The step recorder in `store.zig` is placed by hand next to each call, so a
// call deleted while its `recStep` stays would pass the order test. This wrapper
// sees the calls themselves (fsync of the temp, rename, fsync of the directory,
// chmod, truncate, lock attempts, random names) and can fail them or change the
// file system under the store at a chosen moment.

const CallProbe = struct {
    const Ev = enum { sync_file, sync_dir, rename };
    var real: std.Io.VTable = undefined;
    var vt: std.Io.VTable = undefined;
    var events: [32]Ev = undefined;
    var n: usize = 0;
    var syncs: u32 = 0;
    var fail_sync: u32 = 0; // fail the k-th fsync (1-based); 0 = never
    var reads: u32 = 0;
    var swap_after_reads: u32 = 0; // after this many reads, replace `sw_name` in `sw_dir`
    var sw_dir: std.Io.Dir = undefined;
    var sw_name: []const u8 = "";
    var sw_text: []const u8 = "";
    var fail_setlen = false;
    var fail_setperm = false;
    var trylocks: u32 = 0;
    var rand_calls: u32 = 0;
    var first_random: ?[8]u8 = null; // the first `random` call returns these bytes
    var shrink_before_read = false; // the next read finds the file cut to two bytes
    var grow_after_read = false; // the next read is followed by an append
    var mode_before_chmod: ?u32 = null;
    var dir_on_open: []const u8 = ""; // the next open of this name finds a directory there

    fn rec(e: Ev) void {
        if (n < events.len) {
            events[n] = e;
            n += 1;
        }
    }
    fn sync(ud: ?*anyopaque, f: std.Io.File) std.Io.File.SyncError!void {
        const is_dir = if (real.fileStat(ud, f)) |s| s.kind == .directory else |_| false;
        rec(if (is_dir) .sync_dir else .sync_file);
        syncs += 1;
        if (fail_sync == syncs) return error.InputOutput;
        return real.fileSync(ud, f);
    }
    fn rename(ud: ?*anyopaque, od: std.Io.Dir, op: []const u8, nd: std.Io.Dir, np: []const u8) std.Io.Dir.RenameError!void {
        rec(.rename);
        return real.dirRename(ud, od, op, nd, np);
    }
    fn setLen(ud: ?*anyopaque, f: std.Io.File, len: u64) std.Io.File.SetLengthError!void {
        if (fail_setlen) return error.InputOutput;
        return real.fileSetLength(ud, f, len);
    }
    fn setPerm(ud: ?*anyopaque, f: std.Io.File, p: std.Io.File.Permissions) std.Io.File.SetPermissionsError!void {
        if (real.fileStat(ud, f)) |s| {
            mode_before_chmod = @as(u32, @intCast(@backingInt(s.permissions))) & 0o777;
        } else |_| {}
        if (fail_setperm) return error.InputOutput;
        return real.fileSetPermissions(ud, f, p);
    }
    fn tryLock(ud: ?*anyopaque, f: std.Io.File, l: std.Io.File.Lock) std.Io.File.LockError!bool {
        trylocks += 1;
        return real.fileTryLock(ud, f, l);
    }
    fn random(ud: ?*anyopaque, buf: []u8) void {
        rand_calls += 1;
        if (rand_calls == 1) if (first_random) |b| {
            @memcpy(buf, b[0..buf.len]);
            return;
        };
        real.random(ud, buf);
    }
    fn openFile(ud: ?*anyopaque, d: std.Io.Dir, sub: []const u8, o: std.Io.Dir.OpenFileOptions) std.Io.File.OpenError!std.Io.File {
        if (dir_on_open.len != 0 and std.mem.eql(u8, sub, dir_on_open)) {
            dir_on_open = "";
            d.deleteFile(t.io, sub) catch @panic("swap delete");
            d.createDir(t.io, sub, .default_dir) catch @panic("swap mkdir");
        }
        return real.dirOpenFile(ud, d, sub, o);
    }
    fn readPos(ud: ?*anyopaque, f: std.Io.File, data: []const []u8, off: u64) std.Io.File.ReadPositionalError!usize {
        if (shrink_before_read) {
            shrink_before_read = false;
            sw_dir.writeFile(t.io, .{ .sub_path = sw_name, .data = "x\n" }) catch @panic("shrink");
        }
        const r = try real.fileReadPositional(ud, f, data, off);
        if (grow_after_read) {
            grow_after_read = false;
            sw_dir.writeFile(t.io, .{ .sub_path = sw_name, .data = base_conf ++ "# grown\n" }) catch @panic("grow");
        }
        reads += 1;
        if (swap_after_reads != 0 and reads == swap_after_reads) {
            swap_after_reads = 0;
            // another process commits right now: a new file with a new inode
            sw_dir.writeFile(t.io, .{ .sub_path = ".swap", .data = sw_text }) catch @panic("swap write");
            sw_dir.rename(".swap", sw_dir, sw_name, t.io) catch @panic("swap rename");
        }
        return r;
    }
    fn arm() std.Io {
        real = t.io.vtable.*;
        vt = real;
        vt.fileSync = sync;
        vt.dirRename = rename;
        vt.fileReadPositional = readPos;
        vt.dirOpenFile = openFile;
        vt.fileSetLength = setLen;
        vt.fileSetPermissions = setPerm;
        vt.fileTryLock = tryLock;
        vt.random = random;
        dir_on_open = "";
        fail_setlen = false;
        fail_setperm = false;
        trylocks = 0;
        rand_calls = 0;
        first_random = null;
        shrink_before_read = false;
        grow_after_read = false;
        mode_before_chmod = null;
        n = 0;
        syncs = 0;
        fail_sync = 0;
        reads = 0;
        swap_after_reads = 0;
        return .{ .userdata = t.io.userdata, .vtable = &vt };
    }
};

test "commit: the real calls are fsync(temp), rename, fsync(directory), and each failure is told apart" {
    var fx = try Fixture.init();
    defer fx.deinit();
    var cs = try CommitSetup.init(&fx);
    defer cs.deinit();
    var st = fx.store();
    st.io = CallProbe.arm();
    try fx.put(fx.save, "net", "net.lan.x='1'\n");
    try st.commit(t.allocator, "net", &cs.new);
    // the last fsync is the emptied delta (audit 5)
    try t.expectEqualSlices(CallProbe.Ev, &.{ .sync_file, .rename, .sync_dir, .sync_file }, CallProbe.events[0..CallProbe.n]);
    // the first fsync (the temp file) fails: nothing visible, nothing left, delta kept
    _ = CallProbe.arm();
    CallProbe.fail_sync = 1;
    try fx.put(fx.save, "net", "net.lan.x='1'\n");
    try t.expectError(error.WriteFailed, st.commit(t.allocator, "net", &cs.old));
    try t.expectEqualSlices(CallProbe.Ev, &.{.sync_file}, CallProbe.events[0..CallProbe.n]);
    const got = try fx.read(fx.conf, "net");
    defer t.allocator.free(got);
    try t.expectEqualSlices(u8, cs.new_bytes, got);
    try t.expectEqual(@as(usize, 0), try tempCount(&fx, fx.conf));
    try t.expect(try st.hasStaged(t.allocator, "net"));
    // the second (the directory) fails: the file IS visible, the delta is cleared
    _ = CallProbe.arm();
    CallProbe.fail_sync = 2;
    try t.expectError(error.CommittedNotDurable, st.commit(t.allocator, "net", &cs.old));
    const got2 = try fx.read(fx.conf, "net");
    defer t.allocator.free(got2);
    try t.expectEqualSlices(u8, cs.old_bytes, got2);
    try t.expect(!try st.hasStaged(t.allocator, "net"));
    // the third (the emptied delta) fails: the file is visible but the delta may come back
    _ = CallProbe.arm();
    CallProbe.fail_sync = 3;
    try fx.put(fx.save, "net", "net.lan.x='1'\n");
    try t.expectError(error.StagedNotCleared, st.commit(t.allocator, "net", &cs.new));
    const got3 = try fx.read(fx.conf, "net");
    defer t.allocator.free(got3);
    try t.expectEqualSlices(u8, cs.new_bytes, got3);
}

test "files: a regular file swapped for a directory between lstat and open is NotRegularFile" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.put(fx.conf, "net", base_conf);
    var st = fx.store();
    st.io = CallProbe.arm();
    CallProbe.dir_on_open = "net";
    try t.expectError(error.NotRegularFile, st.load(t.allocator, "net", null));
}

test "files: a file that shrinks or grows while it is read is ReadFailed, never a short buffer" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.put(fx.conf, "net", base_conf);
    var st = fx.store();
    st.io = CallProbe.arm();
    CallProbe.sw_dir = fx.conf;
    CallProbe.sw_name = "net";
    CallProbe.shrink_before_read = true;
    try t.expectError(error.ReadFailed, st.load(t.allocator, "net", null));
    try fx.put(fx.conf, "net", base_conf);
    CallProbe.grow_after_read = true;
    try t.expectError(error.ReadFailed, st.load(t.allocator, "net", null));
}

test "Stamp: inode, size and mtime each make two stamps differ; no file equals no file" {
    var fx = try Fixture.init();
    defer fx.deinit();
    const st = fx.store();
    try fx.put(fx.conf, "net", base_conf);
    const a = (try st.stamp("net")).?;
    try t.expect(a.eql(a));
    var b = a;
    b.inode +%= 1;
    try t.expect(!a.eql(b));
    b = a;
    b.size += 1;
    try t.expect(!a.eql(b));
    b = a;
    b.mtime.nanoseconds += 1;
    try t.expect(!a.eql(b));
    try t.expect(try st.stamp("none") == null);
    // a package that did not exist when it was loaded: the first commit may create it
    var pkg = try uci.parse(t.allocator, base_conf);
    defer pkg.deinit(t.allocator);
    var ed = try uci.Editor.init(t.allocator, &pkg);
    defer ed.deinit();
    try st.commitEditor(t.allocator, "created", &ed, null);
    try t.expectError(error.ChangedOnDisk, st.commitEditor(t.allocator, "created", &ed, null));
    // a stamp is of a regular file only
    try mkfifoAt(fx.conf, "fifo");
    try fx.conf.createDir(t.io, "dir", .default_dir);
    try t.expectError(error.NotRegularFile, st.stamp("fifo"));
    try t.expectError(error.NotRegularFile, st.stamp("dir"));
}

test "lock: commitEditor and saveEditor wait for the holder too; a vanished file is no lock; the wait is exactly bounded" {
    var fx = try Fixture.init();
    defer fx.deinit();
    var cs = try CommitSetup.init(&fx);
    defer cs.deinit();
    var st = fx.store();
    st.options.lock_timeout_ms = 40;
    var ed = try uci.Editor.init(t.allocator, &cs.old);
    defer ed.deinit();
    const stamp = try st.stamp("net");
    const holder = try fx.conf.openFile(t.io, "net", .{ .mode = .read_only });
    try t.expect(try holder.tryLock(t.io, .exclusive));
    try t.expectError(error.LockTimeout, st.commitEditor(t.allocator, "net", &ed, stamp));
    try t.expectError(error.LockTimeout, st.saveEditor(t.allocator, "net", &ed));
    // 0 ms = one attempt; 20 ms = two (0 and 20 are both "not yet over"); never one more
    st.io = CallProbe.arm();
    st.options.lock_timeout_ms = 0;
    try t.expectError(error.LockTimeout, st.replace(t.allocator, "net", &cs.new));
    try t.expectEqual(@as(u32, 1), CallProbe.trylocks);
    CallProbe.trylocks = 0;
    st.options.lock_timeout_ms = 20;
    try t.expectError(error.LockTimeout, st.replace(t.allocator, "net", &cs.new));
    try t.expectEqual(@as(u32, 2), CallProbe.trylocks);
    holder.close(t.io);
    // the file vanishes between open and lock: no lock, the commit goes on and creates it
    st = fx.store();
    const Del = struct {
        var dir: std.Io.Dir = undefined;
        fn run() void {
            dir.deleteFile(t.io, "net") catch {};
        }
    };
    Del.dir = fx.conf;
    store_mod.crash_hook.after_open = &Del.run;
    defer store_mod.crash_hook.after_open = null;
    try st.commit(t.allocator, "net", &cs.new);
    store_mod.crash_hook.after_open = null;
    const got = try fx.read(fx.conf, "net");
    defer t.allocator.free(got);
    try t.expectEqualSlices(u8, cs.new_bytes, got);
}

test "save: needs a save directory, keeps the delta's mode, reaps its stale temps, refuses a directory and a size over the cap" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.put(fx.conf, "net", base_conf);
    const st = fx.store();
    var s = uci.Session.init(t.allocator, st);
    defer s.deinit();
    try s.run("set net.lan.a=1\n", .{}, null, null);
    // an existing delta keeps its mode; a stale temp of the package is reaped
    try fx.put(fx.save, "net", "");
    try fx.save.setFilePermissions(t.io, "net", @fromBackingInt(@intCast(0o640)), .{});
    try fx.put(fx.save, ".net.uci-tmp-0123456789abcdef", "stale");
    try s.save("net");
    const sst = try fx.save.statFile(t.io, "net", .{});
    try t.expectEqual(@as(u32, 0o640), @as(u32, @intCast(@backingInt(sst.permissions))) & 0o777);
    try t.expectEqual(@as(usize, 0), try tempCount(&fx, fx.save));
    try t.expect(try st.hasStaged(t.allocator, "net"));
    // no save directory
    var nos = st;
    nos.save = null;
    var s2 = uci.Session.init(t.allocator, nos);
    defer s2.deinit();
    try t.expectError(error.NoSaveDirectory, s2.save("net"));
    // a directory where the delta file belongs is refused, nothing is replaced
    var pkg = try uci.parse(t.allocator, base_conf);
    defer pkg.deinit(t.allocator);
    var ed = try uci.Editor.init(t.allocator, &pkg);
    defer ed.deinit();
    try fx.put(fx.conf, "dn", base_conf);
    try fx.save.createDir(t.io, "dn", .default_dir);
    try ed.set("lan", "a", "1");
    try t.expectError(error.NotRegularFile, st.saveEditor(t.allocator, "dn", &ed));
    // a delta over the size cap is refused
    var small = st;
    small.options.max_bytes = base_conf.len + 20;
    const big: [300]u8 = @splat('x');
    try ed.set("lan", "big", &big);
    try t.expectError(error.FileTooLarge, small.saveEditor(t.allocator, "net", &ed));
}

test "save with -p: the delta holds what the session added to base plus extras, and a reload sees both" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.put(fx.conf, "net", base_conf);
    try fx.tmp.dir.createDir(t.io, "extra", .default_dir);
    var ex = try fx.tmp.dir.openDir(t.io, "extra", .{ .iterate = true });
    defer ex.close(t.io);
    try ex.writeFile(t.io, .{ .sub_path = "net", .data = "net.lan.x='1'\n" });
    const exs = [_]std.Io.Dir{ex};
    var st = fx.store();
    st.extra_save = &exs;
    var s = uci.Session.init(t.allocator, st);
    defer s.deinit();
    try s.run("set net.lan.y=2\n", .{}, null, null);
    var seen = try (try s.editor("net")).toPackage(t.allocator); // the session's own view holds the extra directory's x
    defer seen.deinit(t.allocator);
    try t.expectEqualStrings("1", seen.section("iface", "lan").?.get("x").?);
    try s.save("net");
    const d = (try st.staged(t.allocator, "net")).?;
    defer t.allocator.free(d);
    try t.expect(std.mem.indexOf(u8, d, "net.lan.x") == null); // x is the extra directory's, not ours
    try t.expect(std.mem.indexOf(u8, d, "net.lan.y='2'") != null);
    var live = try st.loadStaged(t.allocator, "net", null);
    defer live.deinit(t.allocator);
    try t.expectEqualStrings("1", live.section("iface", "lan").?.get("x").?);
    try t.expectEqualStrings("2", live.section("iface", "lan").?.get("y").?);
}

test "commit: temp starts 0600, a chmod or truncate failure is told apart, a name collision is retried not trampled" {
    var fx = try Fixture.init();
    defer fx.deinit();
    var cs = try CommitSetup.init(&fx);
    defer cs.deinit();
    try fx.conf.setFilePermissions(t.io, "net", @fromBackingInt(@intCast(0o644)), .{});
    var st = fx.store();
    st.io = CallProbe.arm();
    // the mode the temp file has when chmod is called: never wider than 0600
    try st.commit(t.allocator, "net", &cs.new);
    try t.expectEqual(@as(?u32, 0o600), CallProbe.mode_before_chmod);
    const m = try fx.conf.statFile(t.io, "net", .{});
    try t.expectEqual(@as(u32, 0o644), @as(u32, @intCast(@backingInt(m.permissions))) & 0o777); // the old file's mode is kept
    // chmod fails: nothing visible, no temp left
    CallProbe.fail_setperm = true;
    try t.expectError(error.WriteFailed, st.commit(t.allocator, "net", &cs.old));
    CallProbe.fail_setperm = false;
    try t.expectEqual(@as(usize, 0), try tempCount(&fx, fx.conf));
    const got = try fx.read(fx.conf, "net");
    defer t.allocator.free(got);
    try t.expectEqualSlices(u8, cs.new_bytes, got);
    // the delta cannot be truncated: the file is in place, the error says so
    try fx.put(fx.save, "net", "net.lan.x='1'\n");
    CallProbe.fail_setlen = true;
    try t.expectError(error.StagedNotCleared, st.commit(t.allocator, "net", &cs.old));
    try t.expectError(error.WriteFailed, st.revert("net"));
    CallProbe.fail_setlen = false;
    // the first random name is taken by a link (reap leaves links alone): the commit uses another
    try fx.conf.symLink(t.io, "net", ".net.uci-tmp-0123456789abcdef", .{});
    CallProbe.first_random = .{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
    CallProbe.rand_calls = 0;
    try st.commit(t.allocator, "net", &cs.new);
    const link = try fx.conf.statFile(t.io, ".net.uci-tmp-0123456789abcdef", .{ .follow_symlinks = false });
    try t.expect(link.kind == .sym_link);
    const got2 = try fx.read(fx.conf, "net");
    defer t.allocator.free(got2);
    try t.expectEqualSlices(u8, cs.new_bytes, got2);
}

test "reap: decoys with the right length but a wrong part are left alone; a long package name does not crash it" {
    var fx = try Fixture.init();
    defer fx.deinit();
    const st = fx.store();
    var cs = try CommitSetup.init(&fx);
    defer cs.deinit();
    const decoys = [_][]const u8{
        ".abc.uci-tmp-0123456789abcdef", // another package, same length of name
        "xnet.uci-tmp-0123456789abcdef", // no leading dot
        ".net.uci-tmq-0123456789abcdef", // wrong infix
        ".net.uci-tmp-0123456789abcdef00", // longer
    };
    for (decoys) |d| try fx.put(fx.conf, d, "not ours");
    try fx.put(fx.conf, ".net.uci-tmp-fedcba9876543210", "ours");
    try st.commit(t.allocator, "net", &cs.new);
    for (decoys) |d| _ = try fx.conf.statFile(t.io, d, .{});
    try t.expectError(error.FileNotFound, fx.conf.statFile(t.io, ".net.uci-tmp-fedcba9876543210", .{}));
    // a package name longer than the reaper's buffer: its stale temp is skipped, never copied out of bounds
    var long: [100]u8 = @splat('n');
    var pkg = try uci.parse(t.allocator, base_conf);
    defer pkg.deinit(t.allocator);
    try st.commit(t.allocator, &long, &pkg);
    var tmpn: [200]u8 = undefined;
    const tn = try std.fmt.bufPrint(&tmpn, ".{s}.uci-tmp-0123456789abcdef", .{&long});
    try fx.put(fx.conf, tn, "stale");
    try st.commit(t.allocator, &long, &pkg);
}

test "session size: the items of all open packages count, not each alone" {
    var fx = try Fixture.init();
    defer fx.deinit();
    var txt: std.ArrayList(u8) = .empty;
    defer txt.deinit(t.allocator);
    for (0..80_000) |i| try txt.print(t.allocator, "config t 's{d}'\n\toption a '1'\n\n", .{i});
    for ([_][]const u8{ "p1", "p2", "p3" }) |n| try fx.put(fx.conf, n, txt.items);
    var s = uci.Session.init(t.allocator, fx.store());
    defer s.deinit();
    _ = try s.editor("p1");
    _ = try s.editor("p2");
    try t.expectError(error.MemoryLimitExceeded, s.editor("p3"));
}

test "commit: text over max_input_len is FileTooLarge even when the store's cap is higher; an allocation failure stays OutOfMemory" {
    var fx = try Fixture.init();
    defer fx.deinit();
    var st = fx.store();
    st.options.max_bytes = 1 << 30;
    var pkg = try uci.parse(t.allocator, base_conf);
    defer pkg.deinit(t.allocator);
    var ed = try uci.Editor.init(t.allocator, &pkg);
    defer ed.deinit();
    const val: [15_000]u8 = @splat('v');
    var kb: [16]u8 = undefined;
    for (0..1200) |i| try ed.set("lan", try std.fmt.bufPrint(&kb, "k{d}", .{i}), &val);
    var big = try ed.toPackage(t.allocator);
    defer big.deinit(t.allocator);
    try t.expectError(error.FileTooLarge, st.replace(t.allocator, "huge", &big));
    try t.expectError(error.FileNotFound, fx.conf.statFile(t.io, "huge", .{}));
    // every allocation of a commit can fail; the error is OutOfMemory, nothing else
    var cs = try CommitSetup.init(&fx);
    defer cs.deinit();
    const st2 = fx.store();
    var i: usize = 0;
    while (i < 400) : (i += 1) {
        var fa = std.testing.FailingAllocator.init(t.allocator, .{ .fail_index = i });
        if (st2.commit(fa.allocator(), "net", &cs.new)) |_| {
            if (!fa.has_induced_failure) break;
        } else |e| try t.expectEqual(error.OutOfMemory, e);
    }
    try t.expect(i < 400);
}

test "Session: a second commit works (fresh stamp), commit(null) writes only what changed, a revert of a staged change is a change" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.put(fx.conf, "a", base_conf);
    try fx.put(fx.conf, "b", base_conf);
    const st = fx.store();
    var s = uci.Session.init(t.allocator, st);
    defer s.deinit();
    try s.run("set a.lan.x=1\n", .{}, null, null);
    _ = try s.editor("b"); // open, never changed
    const ib = (try st.stamp("b")).?;
    try s.commit(null);
    try t.expect((try st.stamp("b")).?.eql(ib)); // the clean package was not rewritten
    const ia = (try st.stamp("a")).?;
    try s.commit(null); // nothing is dirty any more
    try t.expect((try st.stamp("a")).?.eql(ia));
    try s.run("set a.lan.x=2\n", .{}, null, null);
    try s.commit(null); // a stale stamp would be ChangedOnDisk
    try s.run("set a.lan.x=3\n", .{}, null, null);
    try s.commit("a");
    try s.run("set a.lan.x=4\n", .{}, null, null);
    try s.commit("a");
    // a change that exists only in the delta: reverting it in the session is a change to write
    try fx.put(fx.save, "b", "b.lan.y='1'\n");
    s.discard("b");
    try s.run("revert b.lan\n", .{}, null, null);
    try s.commit(null);
    try t.expect(!try st.hasStaged(t.allocator, "b"));
    var pb = try st.load(t.allocator, "b", null);
    defer pb.deinit(t.allocator);
    try t.expect(pb.section("iface", "lan").?.get("y") == null);
    // an added section is a change
    try s.run("add a rule\n", .{}, null, null);
    try s.commit(null);
    var pa = try st.load(t.allocator, "a", null);
    defer pa.deinit(t.allocator);
    try t.expectEqual(@as(usize, 4), pa.sections.len);
}

test "batch: argument counts and shapes are refused" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.put(fx.conf, "t", base_conf);
    var s = uci.Session.init(t.allocator, fx.store());
    defer s.deinit();
    const bad = [_][]const u8{
        "commit t extra\n", "revert t extra\n", "delete t.lan=5\n", "reorder t.lan.dns=1\n", "set t.lan.a\n",
        "set .lan.a=1\n",   "set t.lan.=1\n",   "set t..a=1\n",     "add t\n",               "add t a b\n",
    };
    for (bad) |script| try t.expectError(error.BadCommand, s.run(script, .{}, null, null));
    // the value starts at the FIRST '='
    try s.run("set t.lan.a=b=c\n", .{}, null, null);
    var p = try (try s.editor("t")).toPackage(t.allocator);
    defer p.deinit(t.allocator);
    try t.expectEqualStrings("b=c", p.section("iface", "lan").?.get("a").?);
}

test "merge: a clash after a valid new section changes nothing; hand-built bad names, types and keys are refused" {
    var base = try uci.parse(t.allocator, base_conf);
    defer base.deinit(t.allocator);
    var ed = try uci.Editor.init(t.allocator, &base);
    defer ed.deinit();
    var clash = try uci.parse(t.allocator, "config thing 'fresh'\n\nconfig rule 'lan'\n");
    defer clash.deinit(t.allocator);
    try t.expectError(error.DuplicateSection, uci.merge(&ed, &clash));
    try t.expect(ed.find("fresh") == null); // the valid section before the clash was not added
    const opt = [_]uci.Option{.{ .key = "k", .kind = .single, .values = &.{"v"} }};
    const bad_opt = [_]uci.Option{.{ .key = "k k", .kind = .single, .values = &.{"v"} }};
    // a valid section first: when the second is refused, the first must not have been merged
    const ok = uci.Section{ .type = "thing", .name = "okname", .anonymous = false, .options = &opt };
    const bad_type = uci.Package{ .sections = &.{ ok, .{ .type = "a b", .name = null, .anonymous = true, .options = &opt } } };
    const bad_name = uci.Package{ .sections = &.{ ok, .{ .type = "t", .name = "a b", .anonymous = false, .options = &opt } } };
    const bad_key = uci.Package{ .sections = &.{ ok, .{ .type = "t", .name = null, .anonymous = true, .options = &bad_opt } } };
    try t.expectError(error.InvalidName, uci.merge(&ed, &bad_type));
    try t.expectError(error.InvalidName, uci.merge(&ed, &bad_name));
    try t.expectError(error.InvalidName, uci.merge(&ed, &bad_key));
    try t.expect(ed.find("okname") == null);
}

test "eqlOnDisk: every difference between two models is seen, options with no value are not" {
    const eql = store_mod.eqlOnDisk;
    const o1 = [_]uci.Option{.{ .key = "k", .kind = .single, .values = &.{"v"} }};
    const o2 = [_]uci.Option{.{ .key = "k", .kind = .single, .values = &.{"w"} }};
    const e1 = [_]uci.Option{.{ .key = "e", .kind = .list, .values = &.{} }};
    const mk = struct {
        fn p(secs: []const uci.Section) uci.Package {
            return .{ .sections = secs };
        }
    }.p;
    const named = [_]uci.Section{.{ .type = "t", .name = "n", .anonymous = false, .options = &o1 }};
    const named_same = [_]uci.Section{.{ .type = "t", .name = "n", .anonymous = false, .options = &o1 }};
    const other_name = [_]uci.Section{.{ .type = "t", .name = "m", .anonymous = false, .options = &o1 }};
    const other_type = [_]uci.Section{.{ .type = "u", .name = "n", .anonymous = false, .options = &o1 }};
    const other_val = [_]uci.Section{.{ .type = "t", .name = "n", .anonymous = false, .options = &o2 }};
    const anon = [_]uci.Section{.{ .type = "t", .name = null, .anonymous = true, .options = &o1 }};
    const anon_named_null = [_]uci.Section{.{ .type = "t", .name = null, .anonymous = false, .options = &o1 }};
    const empty_opt = [_]uci.Section{.{ .type = "t", .name = "n", .anonymous = false, .options = &(e1 ++ o1) }};
    const no_opts = [_]uci.Section{.{ .type = "t", .name = "n", .anonymous = false, .options = &.{} }};
    const two = named ++ other_name;
    const a = mk(&named);
    try t.expect(eql(&a, &mk(&named_same)));
    try t.expect(!eql(&a, &mk(&other_name)));
    try t.expect(!eql(&a, &mk(&other_type)));
    try t.expect(!eql(&a, &mk(&other_val)));
    try t.expect(!eql(&a, &mk(&anon)));
    try t.expect(!eql(&mk(&anon), &mk(&anon_named_null)));
    try t.expect(!eql(&a, &mk(&anon_named_null))); // a name against none, both flagged named
    try t.expect(!eql(&mk(&anon_named_null), &a));
    try t.expect(!eql(&a, &mk(&two)));
    try t.expect(!eql(&mk(&two), &a));
    try t.expect(!eql(&a, &mk(&no_opts)));
    try t.expect(!eql(&mk(&no_opts), &a));
    try t.expect(eql(&a, &mk(&empty_opt)));
    try t.expect(eql(&mk(&empty_opt), &a));
    try t.expect(eql(&mk(&.{}), &mk(&.{})));
    try t.expect(!eql(&a, &mk(&.{})));
}

test "diffRecords: exact records for a section, an option, and the whole state" {
    var base = try uci.parse(t.allocator, base_conf);
    defer base.deinit(t.allocator);
    var a = try uci.Editor.init(t.allocator, &base);
    defer a.deinit();
    try a.set("lan", "keep", "k");
    var pa = try a.toPackage(t.allocator);
    defer pa.deinit(t.allocator);
    var b = try uci.Editor.init(t.allocator, &pa);
    defer b.deinit();
    try b.setSection("lan", "wifi");
    try b.set("lan", "proto", "dhcp");
    try b.addList("lan", "dns", "9.9.9.9");
    try b.set("lan", "extra", "1");
    try b.setSection("lan2", "thing");
    const gpa = t.allocator;
    const key_only = try uci.diffRecords(gpa, &a, &b, "t", .{ .section = "lan", .key = "proto" });
    defer gpa.free(key_only);
    try t.expectEqualStrings("t.lan.proto='dhcp'\n", key_only);
    const sec_fw = try uci.diffRecords(gpa, &a, &b, "t", .{ .section = "lan" });
    defer gpa.free(sec_fw);
    try t.expectEqualStrings("t.lan='wifi'\nt.lan.proto='dhcp'\n-t.lan.dns\n|t.lan.dns='1.1.1.1'\n|t.lan.dns='8.8.8.8'\n|t.lan.dns='9.9.9.9'\nt.lan.extra='1'\n^t.lan='0'\n", sec_fw);
    const all = try uci.diffRecords(gpa, &a, &b, "t", null);
    defer gpa.free(all);
    try t.expectEqualStrings("t.lan='wifi'\nt.lan.proto='dhcp'\n-t.lan.dns\n|t.lan.dns='1.1.1.1'\n|t.lan.dns='8.8.8.8'\n|t.lan.dns='9.9.9.9'\nt.lan.extra='1'\nt.lan2='thing'\n", all);
    // and back: a section that only `b` has is deleted by a section-level filter, never by a key-level one
    const gone_key = try uci.diffRecords(gpa, &b, &a, "t", .{ .section = "lan2", .key = "x" });
    defer gpa.free(gone_key);
    try t.expectEqualStrings("", gone_key);
    const gone = try uci.diffRecords(gpa, &b, &a, "t", .{ .section = "lan2" });
    defer gpa.free(gone);
    try t.expectEqualStrings("-t.lan2\n", gone);
    const back = try uci.diffRecords(gpa, &b, &a, "t", .{ .section = "lan" });
    defer gpa.free(back);
    try t.expectEqualStrings("t.lan='iface'\nt.lan.proto='static'\n-t.lan.dns\n|t.lan.dns='1.1.1.1'\n|t.lan.dns='8.8.8.8'\n-t.lan.extra\n^t.lan='0'\n", back);
}

test "diffRecords: a named section and an anonymous one with one id are told apart; two with one id are refused" {
    var base = try uci.parse(t.allocator, base_conf);
    defer base.deinit(t.allocator);
    var a = try uci.Editor.init(t.allocator, &base);
    defer a.deinit();
    var probe = try uci.Editor.init(t.allocator, &base);
    defer probe.deinit();
    const id = try probe.add("rule"); // the id the next anonymous section of `a` gets
    // b: the same base, then a NAMED section called like that id
    var b = try uci.Editor.init(t.allocator, &base);
    defer b.deinit();
    try b.setSection(id, "rule");
    // c: a NAMED section called like that id, then the anonymous one with that id
    var c = try uci.Editor.init(t.allocator, &base);
    defer c.deinit();
    var probe2 = try uci.Editor.init(t.allocator, &base);
    defer probe2.deinit();
    try probe2.setSection("tmp", "x");
    const id2 = try probe2.add("rule"); // what an add after one named creation gets
    try c.setSection(id2, "rule");
    _ = try c.add("rule");
    // a gets the anonymous section
    _ = try a.add("rule");
    const gpa = t.allocator;
    // anonymous -> named of the same id: a delete and a create, replayed to the same model
    const recs = try uci.diffRecords(gpa, &a, &b, "t", null);
    defer gpa.free(recs);
    try t.expect(std.mem.indexOf(u8, recs, "-t.") != null);
    var pa = try a.toPackage(gpa);
    defer pa.deinit(gpa);
    var replay = try uci.applyDelta(gpa, &pa, "t", recs, null);
    defer replay.deinit(gpa);
    var pb = try b.toPackage(gpa);
    defer pb.deinit(gpa);
    try t.expect(store_mod.eqlOnDisk(&replay, &pb));
    // named -> anonymous of the same id
    const back = try uci.diffRecords(gpa, &b, &a, "t", null);
    defer gpa.free(back);
    var replay2 = try uci.applyDelta(gpa, &pb, "t", back, null);
    defer replay2.deinit(gpa);
    try t.expect(store_mod.eqlOnDisk(&replay2, &pa));
    // two sections with one id on either side
    try t.expectError(error.DuplicateSection, uci.diffRecords(gpa, &c, &a, "t", null));
    try t.expectError(error.DuplicateSection, uci.diffRecords(gpa, &a, &c, "t", null));
}

test "Session: the stamp is taken before the file is read, at editor() and again after a commit" {
    var fx = try Fixture.init();
    defer fx.deinit();
    try fx.put(fx.conf, "net", base_conf);
    var st = fx.store();
    st.io = CallProbe.arm();
    CallProbe.sw_dir = fx.conf;
    CallProbe.sw_name = "net";
    CallProbe.sw_text = "config iface 'lan'\n\toption proto 'other'\n";
    var s = uci.Session.init(t.allocator, st);
    defer s.deinit();
    // another process commits right after this session has read the file (the
    // second read is the "did it grow" probe): the stamp predates that
    CallProbe.swap_after_reads = 2;
    _ = try s.editor("net");
    try s.run("set net.lan.a=1\n", .{}, null, null);
    try t.expectError(error.ChangedOnDisk, s.commit("net"));
    // the same after a successful commit: reload() takes its stamp first too
    s.discard("net");
    CallProbe.sw_text = base_conf;
    try s.run("set net.lan.a=2\n", .{}, null, null);
    CallProbe.reads = 0;
    CallProbe.swap_after_reads = 2;
    CallProbe.sw_text = "config iface 'lan'\n\toption proto 'third'\n";
    try s.commit("net"); // reload reads the file it just wrote; the swap lands after that read
    try s.run("set net.lan.a=3\n", .{}, null, null);
    try t.expectError(error.ChangedOnDisk, s.commit("net"));
}

test "commit: a model that parse reads differently is WouldNotReload and nothing is written" {
    var fx = try Fixture.init();
    defer fx.deinit();
    const st = fx.store();
    const two = [_][]const u8{ "a", "b" };
    const opts = [_]uci.Option{.{ .key = "k", .kind = .single, .values = &two }};
    const secs = [_]uci.Section{.{ .type = "t", .name = "n", .anonymous = false, .options = &opts }};
    const pkg = uci.Package{ .sections = &secs };
    try t.expectError(error.WouldNotReload, st.commit(t.allocator, "odd", &pkg));
    try t.expectError(error.FileNotFound, fx.conf.statFile(t.io, "odd", .{}));
}
