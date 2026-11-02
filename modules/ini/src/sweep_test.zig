// SPDX-License-Identifier: MIT
//! No-panic sweep tests (wave GY). Finding IN-1, see
//! ~/CML/20261029-panic-sweep/ini-sweep.report.md.
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const testing = std.testing;
const ini = @import("root.zig");

/// Run `body` in a forked child; its exit status. A child still running after
/// ten seconds is killed and counts as hung (`error.ChildHung`).
fn runChild(comptime body: fn () u8) !u32 {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const rc = linux.fork();
    if (linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
    if (rc == 0) linux.exit_group(body());
    const pid: linux.pid_t = @intCast(rc);
    var status: u32 = 0;
    var waited_ms: usize = 0;
    while (true) {
        const r = linux.waitpid(pid, @ptrCast(&status), linux.W.NOHANG);
        if (linux.errno(r) != .SUCCESS) return error.WaitFailed;
        if (r == @as(usize, @intCast(pid))) break;
        if (waited_ms >= 10_000) {
            _ = linux.kill(pid, .KILL);
            _ = linux.waitpid(pid, @ptrCast(&status), 0);
            return error.ChildHung;
        }
        const ts: linux.timespec = .{ .sec = 0, .nsec = 10 * std.time.ns_per_ms };
        _ = linux.nanosleep(&ts, null);
        waited_ms += 10;
    }
    if (!linux.W.IFEXITED(status)) return error.ChildDied;
    return linux.W.EXITSTATUS(status);
}

// ── IN-1: a lookup costs O(1), not O(file) ──────────────────────────────────

/// 1 MiB of one section with 260 000 entries, 2000 lookups of absent keys,
/// then 150 000 one-line sections, 2000 lookups. The linear scan took ~6 s +
/// ~1.5 s in ReleaseFast; the index makes both a few milliseconds.
fn manyLookups() u8 {
    const a = std.heap.page_allocator; // global-alloc-ok: forked sweep child that exits or panics; testing.allocator cannot follow it into the child
    var kb: [24]u8 = undefined;
    var text: std.ArrayList(u8) = .empty;
    text.appendSlice(a, "[core]\n") catch return 9;
    while (text.items.len < (1 << 20)) text.appendSlice(a, "kk=\n") catch return 9;
    var d = ini.parse(a, text.items, .{ .case_insensitive_keys = true }) catch return 9;
    for (0..2000) |i| {
        const k = std.fmt.bufPrint(&kb, "k{d}", .{i}) catch return 9;
        if (d.get("core", k) != null) return 1;
    }
    d.deinit();
    text.clearRetainingCapacity();
    while (text.items.len < (1 << 20)) text.appendSlice(a, "[core]\n") catch return 9;
    var d2 = ini.parse(a, text.items, .{ .case_insensitive_sections = true }) catch return 9;
    for (0..2000) |i| {
        const k = std.fmt.bufPrint(&kb, "k{d}", .{i}) catch return 9;
        if (d2.get("CORE", k) != null) return 1;
    }
    return 0;
}

test "get on a 1 MiB document is O(1) per lookup, not a scan of the file (sweep IN-1)" {
    try testing.expectEqual(@as(u32, 0), try runChild(manyLookups));
}

test "lookup semantics through the index: last wins across repeated sections, folding, long names (sweep IN-1)" {
    const long: [200]u8 = @splat('x');
    var upper: [200]u8 = @splat('X');
    upper[100] = 'x';
    var tbuf: [1024]u8 = undefined;
    const text = try std.mem.print(&tbuf, "[A]\nk=1\nK=2\n[b]\nk=3\n[a]\nk=4\n[{s}]\n{s}=L\n", .{ &long, &long });

    var cs = try ini.parse(testing.allocator, text, .{});
    defer cs.deinit();
    try testing.expectEqualStrings("4", cs.get("a", "k").?);
    try testing.expectEqualStrings("1", cs.get("A", "k").?);
    try testing.expectEqualStrings("2", cs.get("A", "K").?);
    try testing.expect(cs.get("A", "x") == null);
    try testing.expect(cs.get("zz", "k") == null);
    try testing.expect(!cs.hasSection("B"));
    try testing.expect(cs.get(&upper, &upper) == null);

    var ci = try ini.parse(testing.allocator, text, .{ .case_insensitive_sections = true, .case_insensitive_keys = true });
    defer ci.deinit();
    try testing.expectEqualStrings("4", ci.get("A", "k").?); // [A] and [a] are one section; the last k wins
    try testing.expectEqualStrings("4", ci.get("a", "K").?);
    try testing.expectEqualStrings("L", ci.get(&upper, &upper).?);
    try testing.expect(ci.hasSection("B"));
    var n: usize = 0;
    var it = ci.entries("a");
    while (it.next()) |_| n += 1;
    try testing.expectEqual(@as(usize, 3), n);
    var none = ci.entries("absent");
    try testing.expect(none.next() == null);
}

test "every allocation of a parse (index included) can fail without a leak (sweep IN-1)" {
    const text = "top=1\n[a]\nk=1\n[B]\nk=2\n[A]\nj=3\n";
    var counter = testing.FailingAllocator.init(testing.allocator, .{});
    var base = try ini.parse(counter.allocator(), text, .{ .case_insensitive_sections = true });
    base.deinit();
    var i: usize = 0;
    while (i <= counter.alloc_index) : (i += 1) {
        var fa = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = i });
        if (ini.parse(fa.allocator(), text, .{ .case_insensitive_sections = true })) |d| {
            var dd = d;
            dd.deinit();
        } else |err| try testing.expectEqual(error.OutOfMemory, err);
    }
}

// ── Clean entry points: hostile text ────────────────────────────────────────

test "hostile text: NUL bytes, CR-only line ends, continuation at EOF, bare separators" {
    const texts = [_][]const u8{
        "[a]\x00\nk\x00=v\x00\n",
        "[a]\rk=v\rj=w\r",
        "[a]\nk=v\n  ",
        "[a]\nk=v\n  cont",
        "[a]\nk=v\n  cont\\",
        "=\n[=]\n[\n]\n]\n",
        "\xEF\xBB\xBF",
        "\xEF\xBB",
        "[a]\nkkk\r",
    };
    inline for (.{ ini.Options{}, ini.Options.python, ini.Options.desktop, ini.Options{ .strict = false, .continuation_lines = true, .inline_comments = true } }) |o| {
        for (texts) |t| {
            var info: ini.ErrorInfo = .{};
            if (ini.parseDiag(testing.allocator, t, o, &info)) |d| {
                var dd = d;
                _ = dd.get("a", "k");
                dd.deinit();
            } else |err| switch (err) {
                error.OutOfMemory => return err,
                else => try testing.expect(info.line >= 1),
            }
        }
    }
}

// ── RV-IN-1: the index must stay small ──────────────────────────────────────

test "the lookup index adds ~nothing per distinct section: bytes allocated for a 1 MiB document (sweep RV-IN-1)" {
    // 1 MiB of `[sN]\nk=v\n`: ~81 500 distinct sections. Two bounds:
    //  * the index itself, summed from its tables: ~39 bytes per section here;
    //  * everything one parse allocates, as a gross ceiling. allocated_bytes
    //    is cumulative and the parse arena grows its chunks by 1.5x, so it is a
    //    STEP function of the document size, not a smooth one: measured in
    //    ReleaseFast it is 33.2 MB at 70 000 sections and 61.6 MB at 78 000
    //    (one more chunk), so a fixed bound near any one reading goes red when
    //    the document size moves past a step. 47.9 MB is the figure before any
    //    index existed, 134.6 MB a per-group list + key map; the ceiling sits
    //    between the worst step of the flat index and the list design.
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(testing.allocator);
    var i: usize = 0;
    while (text.items.len < (1 << 20)) : (i += 1) {
        var tmp: [32]u8 = undefined;
        try text.appendSlice(testing.allocator, try std.fmt.bufPrint(&tmp, "[s{d}]\nk=v\n", .{i}));
    }
    var fa = testing.FailingAllocator.init(testing.allocator, .{});
    var d = try ini.parse(fa.allocator(), text.items, .{});
    defer d.deinit();
    // Slots: SecSet is u32 + 1 metadata byte, KeySet is {u32 group, two pointers} = 24 + 1.
    const index_bytes = d.sec_next.len * @sizeOf(u32) + d.sec_set.capacity() * 5 + d.key_set.capacity() * 25;
    try testing.expect(index_bytes <= 80 * d.sections.len);
    try testing.expect(fa.allocated_bytes <= 80_000_000);
    try testing.expectEqualStrings("v", d.get("s5000", "k").?);
    try testing.expect(d.get("s5000", "j") == null);
    try testing.expect(!d.hasSection("s9999999"));
}

// ── The API added with the writer (goal 3): hostile text, every pub input ───

const hostile = [_][]const u8{
    "",                              "\x00",                   "\xEF\xBB\xBF",           "\xEF\xBB\xBF\n",
    "[",                             "]",                      "[]",                     "[\x00]",
    "=",                             "\r",                     "\r\n",                   "\n\r\n\n",
    "%",                             "%%",                     "%(",                     "%()s",
    "%(k)s",                         "$",                      "$$",                     "${",
    "${}",                           "${:}",                   "${a:b:c}",               "\\",
    "\\;",                           ";",                      ",",                      "@",
    ".",                             "_",                      "[a]\nk=v\n  more\n",     "  ",
    "\xff\xfe",                      "-",                      "+",                      "_1",
    "1e",                            "1e99999999999999999999", "9999999999999999999999", "-",
    "\x00\x00\n\x00=\x00\n[\x00]\n",
};

test "every new pub function over hostile input: errors, never a panic" {
    const a = testing.allocator;
    const Map = struct { k: []const u8 = "", n: u8 = 0, f: f32 = 0, b: bool = false, e: enum { x, y } = .x, o: ?i8 = null };
    for (hostile) |h| {
        _ = ini.intValue(i8, h) catch {};
        _ = ini.intValue(u128, h) catch {};
        _ = ini.floatValue(f16, h) catch {};
        _ = ini.floatValue(f128, h) catch {};
        _ = ini.boolValue(h) catch {};
        for ([_]ini.ListOptions{ .{}, .desktop, .{ .escapes = .none, .separator = 0 } }) |lo| {
            if (ini.parseList(a, h, lo)) |l| {
                var ll = l;
                ll.deinit(a);
            } else |e| switch (e) {
                error.OutOfMemory => return e,
                else => {},
            }
        }
        a.free(try ini.quote(a, h));
        a.free(try ini.escapeDesktop(a, h));

        var sc = ini.Scanner.init(h, .python);
        while (sc.next()) |_| {}
        var r: std.Io.Reader = .fixed(h);
        var st = ini.StreamScanner.init(&r, .desktop);
        while (try st.next()) |_| {}

        inline for (.{ ini.Options{ .strict = false }, ini.Options{ .strict = false, .separators = "", .comment_chars = "" }, ini.Options{ .strict = false, .default_section = "" }, ini.Options{ .strict = false, .comment_chars = "[", .separators = "[" } }) |o| {
            var line_buf: [256]u8 = undefined;
            const text = try std.fmt.bufPrint(&line_buf, "[a]\nk={s}\nn={s}\n", .{ h, h });
            var d = try ini.parse(a, text, o);
            defer d.deinit();
            _ = d.getInt(i64, "a", h) catch {};
            _ = d.getFloat(f64, "a", "k") catch {};
            _ = d.getLocale("a", "k", h);
            _ = d.getLocale(h, h, h);
            _ = d.getInherited(h, h, 0);
            _ = d.mapSection(Map, "a") catch {};
            _ = d.mapSection(Map, h) catch {};
            _ = d.firstDuplicate();
            var m = d.merged(h);
            while (m.next()) |_| {}
            for ([_]ini.InterpolateOptions{ .{}, .{ .style = .extended }, .{ .max_depth = 255, .max_bytes = 0, .max_steps = 0 } }) |io| {
                if (d.interpolated(a, "a", "k", io)) |v| {
                    if (v) |x| a.free(x);
                } else |e| switch (e) {
                    error.OutOfMemory => return e,
                    else => {},
                }
            }
            var sink: [64]u8 = undefined;
            var w: std.Io.Writer = .fixed(&sink);
            d.write(a, &w, .{ .options = o, .separator = h, .continuation_indent = h, .eol = h }) catch |e| switch (e) {
                error.OutOfMemory => return e,
                else => {},
            };

            var ed = try ini.Editor.init(a, text, o);
            defer ed.deinit();
            ed.separator = if (h.len != 0) h else null;
            ed.continuation_indent = h;
            _ = ed.get(h, h);
            ed.set(h, h, h) catch {};
            ed.set("a", h, h) catch {};
            ed.set("a", "k", h) catch {};
            ed.setNoValue(h, h) catch {};
            ed.setComment("a", "k", h) catch {};
            ed.setComment(h, null, h) catch {};
            ed.addSection(h) catch {};
            if (try ed.getComment(a, h, h)) |c| a.free(c);
            _ = try ed.remove(h, h);
            _ = try ed.removeSection(h);
            _ = try ed.removeSection("a");
            a.free(try ed.toOwnedSlice(a));
            if (ed.document(a)) |dd| {
                var ddd = dd;
                ddd.deinit();
            } else |e| switch (e) {
                error.OutOfMemory => return e,
                else => {},
            }
        }
    }
}

/// 1 MiB of entries, then a thousand edits at the far end: each is O(1) in the
/// file size. Runs in a child so a scan per edit is a ten-second `ChildHung`.
fn manyEdits() u8 {
    const a = std.heap.page_allocator; // global-alloc-ok: forked sweep child that exits or panics; testing.allocator cannot follow it into the child
    var text: std.ArrayList(u8) = .empty;
    text.appendSlice(a, "[core]\n") catch return 9;
    var tmp: [32]u8 = undefined;
    var n: usize = 0;
    while (text.items.len < (1 << 20)) : (n += 1) text.appendSlice(a, std.fmt.bufPrint(&tmp, "k{d}=v\n", .{n}) catch return 9) catch return 9;
    var ed = ini.Editor.init(a, text.items, .{}) catch return 9;
    for (0..20_000) |i| {
        const k = std.fmt.bufPrint(&tmp, "k{d}", .{n - 1 - i}) catch return 9;
        ed.set("core", k, "edited") catch return 1;
        if (i % 2 == 0) _ = ed.remove("core", k) catch return 2;
        if (ed.get("core", "k0") == null) return 3;
    }
    return 0;
}

test "editing a 1 MiB file costs O(1) per edit" {
    try testing.expectEqual(@as(u32, 0), try runChild(manyEdits));
}

test "StreamScanner with an unread reader error is an error, not a panic" {
    const Failing = struct {
        fn stream(_: *std.Io.Reader, _: *std.Io.Writer, _: std.Io.Limit) std.Io.Reader.StreamError!usize {
            return error.ReadFailed;
        }
    };
    var buf: [8]u8 = undefined;
    var r: std.Io.Reader = .{ .vtable = &.{ .stream = Failing.stream }, .buffer = &buf, .seek = 0, .end = 0 };
    var st = ini.StreamScanner.init(&r, .{});
    try testing.expectError(error.ReadFailed, st.next());
}

// ── GY audit ────────────────────────────────────────────────────────────────

const key_cs_text = "[s]\nKey=1\nkey=2\nOnly=3\n[T]\nOnly=4\n";

test "case-insensitive keys: an upper-case-only key and later duplicates are found through any case (sweep audit GY-IN1)" {
    var d = try ini.parse(testing.allocator, key_cs_text, .{ .case_insensitive_keys = true });
    defer d.deinit();
    try testing.expectEqualStrings("2", d.get("s", "KEY").?);
    try testing.expectEqualStrings("2", d.get("s", "Key").?);
    try testing.expectEqualStrings("3", d.get("s", "only").?);
    try testing.expectEqualStrings("3", d.get("s", "ONLY").?);
    try testing.expectEqualStrings("4", d.get("T", "oNLY").?);
    try testing.expect(d.get("S", "only") == null); // sections stay case-sensitive here
}

/// ~87 000 sections that all hold the same key with a different value: every
/// section must answer with its own value (a key lookup must not cross groups),
/// and the build must not degrade to a quadratic collision chain (the group id
/// is mixed into the key hash). Runs in a child so a degenerate hash is a
/// ten-second `ChildHung`, not a stuck test run.
fn sameKeyManyGroups() u8 {
    const a = std.heap.page_allocator; // global-alloc-ok: forked sweep child that exits or panics; testing.allocator cannot follow it into the child
    var text: std.ArrayList(u8) = .empty;
    var tmp: [48]u8 = undefined;
    var n: usize = 0;
    while (text.items.len < (1 << 20)) : (n += 1) {
        text.appendSlice(a, std.fmt.bufPrint(&tmp, "[s{d}]\nk={d}\n", .{ n, n }) catch return 9) catch return 9;
    }
    var d = ini.parse(a, text.items, .{}) catch return 9;
    var kb: [24]u8 = undefined;
    var sb: [24]u8 = undefined;
    for (0..n) |i| {
        const sec = std.fmt.bufPrint(&sb, "s{d}", .{i}) catch return 9;
        const want = std.fmt.bufPrint(&kb, "{d}", .{i}) catch return 9;
        const got = d.get(sec, "k") orelse return 1;
        if (!std.mem.eql(u8, got, want)) return 2;
    }
    return 0;
}

test "one key in ~87 000 sections: every section answers with its own value, in linear time (sweep audit GY-IN2)" {
    try testing.expectEqual(@as(u32, 0), try runChild(sameKeyManyGroups));
}
