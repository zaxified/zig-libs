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
        try fx.store().commitEditor(t.allocator, "t", ed);
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
        } else try t.expectError(error.SimulatedCrash, r);
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
    try t.expectError(error.WouldNotReload, st.commitEditor(t.allocator, "net", &ed));
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
            try st.commitEditor(t.allocator, "t", &ed);
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
    try st.commitEditor(t.allocator, "lnk", &ed);
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
}

// ── deterministic fuzz harness: scripts through a Session ───────────────────

const fuzz_driver = @import("testkit").fuzz.driver;
pub const SessionLabel = enum { script_rejected, cmds_ok, cmds_failed, model_checked, committed, saved_replayed, partial_revert_ran };
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
    }
    session_seed += 1;
    if (session_seed % 16 == 0) {
        fx.store().commitEditor(gpa, "t", ed) catch |e| switch (e) {
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
