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

/// Printable US-ASCII (33‥126); anything else — CR/LF, space, tab, and every
/// other control byte — maps to `-`. RFC 3164 has no in-band framing of its
/// own (unlike RFC 6587's octet-counted TCP), so a receiver that frames BSD
/// lines on `\n` would otherwise let an untrusted HOSTNAME or PID forge a
/// second record. Mirrors `message.zig`'s `writeField` sanitization for the
/// RFC 5424 header fields — same "non-printable bytes in header fields map
/// to `-`" bound SPEC.md already states, now held for BOTH encoders.
fn writeSanitized(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    for (s) |b| try w.writeByte(if (b >= 33 and b <= 126) b else '-');
}

/// TAG per RFC 3164 §5.3: alphanumeric only, truncated to `max_tag`. Also
/// closes the narrower ambiguity where a printable-but-non-alnum byte (a
/// space, or the `:` delimiter itself) inside TAG shifts where a receiver
/// believes CONTENT begins (RFC 3164 §4.1.3).
fn writeTag(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    const tag = s[0..@min(s.len, max_tag)];
    for (tag) |b| switch (b) {
        'A'...'Z', 'a'...'z', '0'...'9' => try w.writeByte(b),
        else => try w.writeByte('-'),
    };
}

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

        // An unrepresentable (e.g. pre-1970/hostile) instant is omitted, like
        // an absent timestamp — never a panic on the out-of-range decompose.
        if (self.timestamp) |ts| {
            if (m.decompose(ts)) |c| {
                try w.writeAll(month_abbr[c.month - 1]);
                try w.writeByte(' ');
                if (c.day < 10) try w.writeByte(' '); // space-pad the day to width 2
                try w.print("{d} {d:0>2}:{d:0>2}:{d:0>2} ", .{ c.day, c.hour, c.minute, c.second });
            } else |_| {}
        }

        try writeSanitized(w, self.hostname);
        try w.writeByte(' ');

        // TAG (alnum-filtered + truncated), then optional [PID], then ": "
        // and the message text.
        try writeTag(w, self.tag);
        if (self.pid) |pid| {
            try w.writeByte('[');
            try writeSanitized(w, pid);
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

test "day 10 (the space-pad boundary) is NOT space-padded" {
    // The `< 10` vs `<= 10` boundary had no test pinned exactly at day 10 —
    // every other test uses a single-digit day (9). One day later than the
    // other fixtures (2026-07-10, same time of day) exercises the boundary
    // directly.
    const msg = Message{
        .facility = .user,
        .severity = .notice,
        .timestamp = .{ .unix_ms = 1783686896000 }, // 2026-07-10T12:34:56Z
        .hostname = "host",
        .tag = "app",
        .msg = "hi",
    };
    var buf: [128]u8 = undefined;
    try t.expectEqualStrings(
        "<13>Jul 10 12:34:56 host app: hi",
        try bufPrint(&msg, &buf),
    );
}

test "RFC 3164 line: hostname/tag/pid strip non-printable/non-alnum bytes so an untrusted field cannot forge a second record" {
    const msg = Message{
        .facility = .user,
        .severity = .notice,
        .hostname = "evil\nhost",
        .tag = "cron job:x",
        .pid = "1\n2",
        .msg = "ok",
    };
    var buf: [256]u8 = undefined;
    const out = try bufPrint(&msg, &buf);
    // No raw control byte anywhere before MSG: a receiver that frames on
    // '\n' cannot see this one line as two (RFC 3164 §4.1.3 record forgery).
    try t.expect(std.mem.indexOfScalar(u8, out, '\n') == null);
    // TAG keeps only alnum bytes (RFC 3164 §5.3) — a space or the ':'
    // delimiter itself does not survive, so it can't shift where a
    // receiver believes CONTENT begins.
    try t.expect(std.mem.indexOf(u8, out, "cron") != null);
    try t.expect(std.mem.indexOf(u8, out, "job:x") == null);
}

test "RFC 3164 line: MSG is passed through raw (deliberate — matches the RFC 5424 encoder and the external rsyslogd anchor)" {
    const msg = Message{
        .facility = .user,
        .severity = .notice,
        .hostname = "host",
        .tag = "app",
        .msg = "line one\nline two", // MSG framing is the caller's/transport's job, not this encoder's
    };
    var buf: [128]u8 = undefined;
    const out = try bufPrint(&msg, &buf);
    try t.expect(std.mem.indexOf(u8, out, "line one\nline two") != null);
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
