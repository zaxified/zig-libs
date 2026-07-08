// SPDX-License-Identifier: MIT

//! `/proc/<pid>/stat` — the per-process accounting line: name, scheduling
//! state, parent pid and resident memory, for every running process.

const std = @import("std");
const procnet = @import("root.zig");

/// One process's `stat` snapshot.
pub const ProcessEntry = struct {
    pid: u32,
    /// `man proc(5)` single-letter state code: `R` running, `S` sleeping,
    /// `D` uninterruptible sleep, `Z` zombie, `T` stopped, `I` idle, ...
    state: u8,
    ppid: u32,
    rss_kb: u64,
    name_buf: [procnet.comm_max]u8 = @splat(0),
    name_len: u8 = 0,

    /// The process name (`comm`) — kernel-truncated to 15 chars + NUL, so
    /// this is never the full argv0 for a long command name.
    pub fn name(e: *const ProcessEntry) []const u8 {
        return e.name_buf[0..e.name_len];
    }
};

/// Parse one `/proc/<pid>/stat` line. Format: `<pid> (<comm>) <state> <ppid>
/// <pgrp> ... <rss>`. `comm` sits between the *first* `(` and the *last*
/// `)` — the kernel does not escape parens or spaces the process put in its
/// own name (`(sd-pam)`, `(my (weird) name)`), so scanning from the outside
/// in is the only robust split. The space-separated fields after `comm` are
/// 0-indexed from `state`; `rss` (in pages, converted to kB) is field 24 of
/// the `proc(5)` table, i.e. token index 21 counting from `state` = 0.
/// Returns null if the line has no balanced `(...)` or too few fields.
pub fn parseProcStat(line: []const u8) ?ProcessEntry {
    const lp = std.mem.indexOfScalar(u8, line, '(') orelse return null;
    const rp = std.mem.lastIndexOfScalar(u8, line, ')') orelse return null;
    if (rp <= lp) return null;

    const pid_s = std.mem.trim(u8, line[0..lp], " \t\n");
    const pid = std.fmt.parseInt(u32, pid_s, 10) catch return null;
    const name = line[lp + 1 .. rp];

    var f = std.mem.tokenizeAny(u8, line[rp + 1 ..], " \t\n");
    const state_s = f.next() orelse return null; // field 3
    if (state_s.len == 0) return null;
    const ppid_s = f.next() orelse return null; // field 4

    var i: usize = 2;
    var rss_s: []const u8 = "0";
    while (i <= 21) : (i += 1) {
        const t = f.next() orelse break;
        if (i == 21) rss_s = t; // field 24: resident set size, in pages
    }

    var e: ProcessEntry = .{
        .pid = pid,
        .state = state_s[0],
        .ppid = std.fmt.parseInt(u32, ppid_s, 10) catch 0,
        .rss_kb = (std.fmt.parseInt(u64, rss_s, 10) catch 0) * 4, // 4 KB pages
    };
    e.name_len = procnet.copyClamped(&e.name_buf, name);
    return e;
}

/// Enumerate up to `max` processes from the live `/proc` tree. Each PID's
/// `stat` is read independently, so a process that exits mid-scan (a race
/// inherent to `/proc`) is simply absent from the result, not an error.
/// Caller owns the returned slice (`gpa.free`).
pub fn listProcesses(gpa: std.mem.Allocator, io: std.Io, max: usize) std.mem.Allocator.Error![]ProcessEntry {
    var out: std.ArrayList(ProcessEntry) = .empty;
    errdefer out.deinit(gpa);

    var dir = std.Io.Dir.cwd().openDir(io, "/proc", .{ .iterate = true }) catch
        return out.toOwnedSlice(gpa);
    defer dir.close(io);

    var it = dir.iterate();
    while (it.next(io) catch null) |entry| {
        if (out.items.len >= max) break;
        _ = std.fmt.parseInt(u32, entry.name, 10) catch continue; // numeric dirs = pids

        var pb: [64]u8 = undefined;
        const path = std.fmt.bufPrint(&pb, "/proc/{s}/stat", .{entry.name}) catch continue;
        const text = procnet.readVirtualFile(gpa, io, path, 4096) orelse continue;
        defer gpa.free(text);
        const pe = parseProcStat(text) orelse continue;
        try out.append(gpa, pe);
    }
    return out.toOwnedSlice(gpa);
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "parseProcStat: real /proc/1/stat-shaped line (systemd)" {
    const line = "1 (systemd) S 0 1 1 0 -1 4194560 55321 3271011 40 4482 106 88 1058 621 20 0 1 0 3 170939904 2237 18446744073709551615 0 0 0 0 0 0 671173123 4096 1260 1 0 0 17 3 0 0 0 0 0 0 0 0 0 0";
    const e = parseProcStat(line).?;
    try testing.expectEqual(@as(u32, 1), e.pid);
    try testing.expectEqualStrings("systemd", e.name());
    try testing.expectEqual(@as(u8, 'S'), e.state);
    try testing.expectEqual(@as(u32, 0), e.ppid);
    try testing.expectEqual(@as(u64, 2237 * 4), e.rss_kb);
}

test "parseProcStat: name containing its own parens (sd-pam-style)" {
    const line = "1234 ((sd-pam)) S 1233 1233 1233 0 -1 1077936384 10 0 0 0 0 0 0 0 20 0 1 0 5 170000000 200 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0";
    const e = parseProcStat(line).?;
    try testing.expectEqual(@as(u32, 1234), e.pid);
    try testing.expectEqualStrings("(sd-pam)", e.name());
    try testing.expectEqual(@as(u32, 1233), e.ppid);
}

test "parseProcStat: name containing spaces and a lone close-paren" {
    const line = "42 (my weird) name) R 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1 0 300 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0";
    const e = parseProcStat(line).?;
    try testing.expectEqualStrings("my weird) name", e.name());
    try testing.expectEqual(@as(u8, 'R'), e.state);
    try testing.expectEqual(@as(u64, 300 * 4), e.rss_kb);
}

test "parseProcStat: name longer than TASK_COMM_LEN is truncated, not dropped" {
    const line = "7 (this-process-name-is-way-too-long-for-the-kernel) Z 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0";
    const e = parseProcStat(line).?;
    try testing.expectEqual(@as(usize, procnet.comm_max), e.name().len);
    try testing.expectEqual(@as(u8, 'Z'), e.state);
}

test "parseProcStat: malformed lines return null, not a panic" {
    try testing.expectEqual(@as(?ProcessEntry, null), parseProcStat(""));
    try testing.expectEqual(@as(?ProcessEntry, null), parseProcStat("no-parens-here S 1 1"));
    try testing.expectEqual(@as(?ProcessEntry, null), parseProcStat("1 (ok S 1 1")); // no close paren
    try testing.expectEqual(@as(?ProcessEntry, null), parseProcStat("bad-pid (ok) S 1 1"));
    try testing.expectEqual(@as(?ProcessEntry, null), parseProcStat("1 (ok) S")); // missing ppid
}

test "parseProcStat: too few trailing fields still yields rss 0, not an error" {
    const line = "9 (short) S 1 1";
    const e = parseProcStat(line).?;
    try testing.expectEqual(@as(u64, 0), e.rss_kb);
    try testing.expectEqual(@as(u32, 1), e.ppid);
}
