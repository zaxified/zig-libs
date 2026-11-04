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
    try t.expectEqual(@as(usize, 13), cases);
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

test "commit: a crash at every step leaves the old file or the new one, never a mixture" {
    var fx = try Fixture.init();
    defer fx.deinit();
    const st = fx.store();
    var old = try uci.parse(t.allocator, base_conf);
    defer old.deinit(t.allocator);
    try st.commit(t.allocator, "net", &old);
    var ed = try uci.Editor.init(t.allocator, &old);
    defer ed.deinit();
    try ed.set("lan", "proto", "dhcp");
    var new = try ed.toPackage(t.allocator);
    defer new.deinit(t.allocator);
    var k: u32 = 1;
    while (k <= 4) : (k += 1) {
        store_mod.crash_hook.arm(k);
        defer store_mod.crash_hook.arm(null);
        const r = st.commit(t.allocator, "net", &new);
        if (k == 4) {
            try r; // four crash points exist; the fourth never fires
        } else {
            try t.expectError(error.SimulatedCrash, r);
        }
        store_mod.crash_hook.arm(null);
        var got = try st.load(t.allocator, "net", null);
        defer got.deinit(t.allocator);
        const is_old = got.eql(&old);
        const is_new = got.eql(&new);
        try t.expect(is_old != is_new); // exactly one of them
        if (k <= 2) try t.expect(is_old); // not renamed yet
        if (k >= 3) try t.expect(is_new); // renamed
        // reset to old for the next round
        try st.commit(t.allocator, "net", &old);
    }
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

test "files: FIFO, directory, symlink and /dev/zero are refused without blocking; absent is not an error class of its own" {
    var fx = try Fixture.init();
    defer fx.deinit();
    const st = fx.store();
    var pkg = try uci.parse(t.allocator, base_conf);
    defer pkg.deinit(t.allocator);
    try mkfifoAt(fx.conf, "fifo");
    try fx.conf.createDir(t.io, "dir", .default_dir);
    fx.conf.symLink(t.io, "/dev/zero", "zero", .{}) catch return error.SkipZigTest;
    try fx.put(fx.conf, "real", base_conf);
    try fx.conf.symLink(t.io, "real", "link", .{});
    for ([_][]const u8{ "fifo", "dir", "zero", "link" }) |n| {
        try t.expectError(error.NotRegularFile, st.load(t.allocator, n, null));
        try t.expectError(error.NotRegularFile, st.loadStaged(t.allocator, n, null));
        try t.expectError(error.NotRegularFile, st.commit(t.allocator, n, &pkg));
        try t.expectError(error.NotRegularFile, st.importText(t.allocator, n, "", null));
    }
    // a FIFO as a delta file
    try mkfifoAt(fx.save, "fifo");
    try t.expectError(error.NotRegularFile, st.staged(t.allocator, "fifo"));
    try t.expectError(error.NotRegularFile, st.revert("fifo"));
    try t.expectError(error.PackageNotFound, st.load(t.allocator, "absent", null));
    // the link target is untouched
    const bytes = try fx.read(fx.conf, "real");
    defer t.allocator.free(bytes);
    try t.expectEqualStrings(base_conf, bytes);
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
    // the commit does not need to read the old file, only to look at it
    try st.commit(t.allocator, "net", &pkg);
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
        .{ "revert t.lan", error.UnsupportedCommand },
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
pub const SessionLabel = enum { script_rejected, cmds_ok, cmds_failed, model_checked, committed };
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
        if (!back.eql(&pkg)) return error.ModelDoesNotRoundTrip;
        smark(.model_checked);
    } else |e| switch (e) {
        error.OutOfMemory => return e,
        else => {}, // a documented refusal
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
        if (!back.eql(&pkg)) return error.CommitDoesNotReload;
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
