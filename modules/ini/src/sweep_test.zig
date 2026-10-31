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
    const a = std.heap.page_allocator;
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
    // 1 MiB of `[sN]\nk=v\n`: ~95 000 distinct sections. Measured with a counting
    // allocator (ReleaseFast): 47 939 KiB before any index existed, 134 570 KiB
    // with a per-group list + key map, 48 258 KiB with the flat index. The
    // bound is 1.25x the no-index figure; allocated_bytes is cumulative, so it
    // is an upper bound of the peak.
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
    try testing.expect(fa.allocated_bytes <= 60_000_000);
    try testing.expectEqualStrings("v", d.get("s5000", "k").?);
    try testing.expect(d.get("s5000", "j") == null);
    try testing.expect(!d.hasSection("s9999999"));
}
