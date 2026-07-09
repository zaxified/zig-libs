// SPDX-License-Identifier: MIT
//! RFC 3164 (BSD) legacy syslog encoder — the pre-5424 line format still
//! spoken by many collectors:
//!
//!   `<PRI>Mmm dd hh:mm:ss HOSTNAME TAG[PID]: MSG`
//!
//! The timestamp is the local wall clock with a space-padded day; there is no
//! year, no fractional seconds and no timezone (RFC 3164 §4.1.2). Parsing the
//! 3164 format is intentionally NOT provided (see README DEFER list).

const std = @import("std");
const m = @import("message.zig");

pub const Facility = m.Facility;
pub const Severity = m.Severity;
pub const Timestamp = m.Timestamp;

/// Max TAG length before truncation (RFC 3164 §5.3 recommends ≤ 32 alnum).
pub const max_tag = 32;

const month_abbr = [_][]const u8{
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
};

/// A legacy BSD syslog message.
pub const Message = struct {
    facility: Facility = .user,
    severity: Severity = .notice,
    timestamp: ?Timestamp = null,
    hostname: []const u8 = "-",
    tag: []const u8 = "",
    pid: ?[]const u8 = null,
    msg: []const u8 = "",

    /// Custom-format entry point — also reachable via `{f}`.
    pub fn format(self: *const Message, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.print("<{d}>", .{m.priority(self.facility, self.severity)});

        if (self.timestamp) |ts| {
            const c = m.decompose(ts);
            try w.writeAll(month_abbr[c.month - 1]);
            try w.writeByte(' ');
            if (c.day < 10) try w.writeByte(' '); // space-pad the day to width 2
            try w.print("{d} {d:0>2}:{d:0>2}:{d:0>2} ", .{ c.day, c.hour, c.minute, c.second });
        }

        try w.writeAll(self.hostname);
        try w.writeByte(' ');

        // TAG (truncated), then optional [PID], then ": " and the message text.
        const tag = self.tag[0..@min(self.tag.len, max_tag)];
        try w.writeAll(tag);
        if (self.pid) |pid| {
            try w.writeByte('[');
            try w.writeAll(pid);
            try w.writeByte(']');
        }
        try w.writeAll(": ");
        try w.writeAll(self.msg);
    }
};

/// Format `msg` into `buf`, returning the written slice.
pub fn bufPrint(msg: *const Message, buf: []u8) error{NoSpaceLeft}![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    msg.format(&w) catch return error.NoSpaceLeft;
    return w.buffered();
}

const t = std.testing;

test "RFC 3164 line with tag, pid and space-padded day" {
    const msg = Message{
        .facility = .local0,
        .severity = .warning,
        .timestamp = .{ .unix_ms = 1783600496000 }, // 2026-07-09T12:34:56Z
        .hostname = "host",
        .tag = "app",
        .pid = "123",
        .msg = "hello",
    };
    var buf: [128]u8 = undefined;
    try t.expectEqualStrings(
        "<132>Jul  9 12:34:56 host app[123]: hello",
        try bufPrint(&msg, &buf),
    );
}

test "RFC 3164 line without a pid" {
    const msg = Message{
        .facility = .user,
        .severity = .notice,
        .timestamp = .{ .unix_ms = 1783600496000 },
        .hostname = "host",
        .tag = "cron",
        .msg = "job done",
    };
    var buf: [128]u8 = undefined;
    try t.expectEqualStrings(
        "<13>Jul  9 12:34:56 host cron: job done",
        try bufPrint(&msg, &buf),
    );
}

test "TAG longer than 32 bytes is truncated" {
    const msg = Message{
        .facility = .user,
        .severity = .notice,
        .hostname = "h",
        .tag = "t" ** 40,
        .msg = "x",
    };
    var buf: [128]u8 = undefined;
    const out = try bufPrint(&msg, &buf);
    try t.expect(std.mem.indexOf(u8, out, ("t" ** max_tag) ++ ": x") != null);
    try t.expect(std.mem.indexOf(u8, out, "t" ** (max_tag + 1)) == null);
}
