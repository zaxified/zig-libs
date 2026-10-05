// SPDX-License-Identifier: MIT
//! RFC 3164 (BSD) legacy syslog encoder — the pre-5424 line format still
//! spoken by many collectors:
//!
//!   `<PRI>Mmm dd hh:mm:ss HOSTNAME TAG[PID]: MSG`
//!   `<PRI>Mmm dd hh:mm:ss TAG[PID]: MSG`          (no HOSTNAME: glibc's shape)
//!
//! The timestamp is the local wall clock with a space-padded day; there is no
//! year, no fractional seconds and no timezone (RFC 3164 §4.1.2). Parsing the
//! 3164 format is intentionally NOT provided (see README DEFER list).
//!
//! HOSTNAME is sent only when it is one (`validHostname`): RFC 3164 has no
//! NILVALUE and no field delimiter but the space, so a receiver decides
//! whether the first word IS a hostname by looking at it, and a word that is
//! not -- `-`, `a b` sanitized to `a-b:`, an IPv6 literal's `:` -- is read as
//! the TAG, the real TAG shifted into MSG (rsyslogd, `rsyslog_oracle_test.zig`).
//! Omitting it is what glibc's `syslog()` does; the receiver fills in the
//! sender.

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

/// HOSTNAME a receiver reads as one (RFC 3164 §4.1.2: "the hostname, the
/// IPv4 address, or the IPv6 address"): dot-separated labels of 1‥63
/// letters, digits, `-` and `_`, a label neither starting nor ending with
/// `-` (RFC 1123 §2.1; `_` as in real host names), ≤ 255 bytes. An IPv4
/// literal passes as labels of digits. An IPv6 literal does not: its `:` is
/// the TAG delimiter, and rsyslogd reads `2001:db8::1 app:` as TAG `2001` --
/// RFC 5424 carries it (`Message.hostname`).
pub fn validHostname(s: []const u8) bool {
    if (s.len == 0 or s.len > 255) return false;
    var labels = std.mem.splitScalar(u8, s, '.');
    while (labels.next()) |label| {
        if (label.len == 0 or label.len > 63) return false;
        if (label[0] == '-' or label[label.len - 1] == '-') return false;
        for (label) |b| switch (b) {
            'A'...'Z', 'a'...'z', '0'...'9', '-', '_' => {},
            else => return false,
        };
    }
    return true;
}

/// PID: printable US-ASCII (33‥126) minus `[` and `]`; anything else maps to
/// `-`. RFC 3164 has no in-band framing of its own (unlike RFC 6587's
/// octet-counted TCP), so a receiver that frames BSD lines on `\n` would
/// otherwise let an untrusted PID forge a second record -- the same bound
/// `message.zig`'s `writeField` holds for the RFC 5424 header fields; and a
/// bracket would close `[PID]` early (`a]b` arrived as PID `a` at rsyslogd).
fn writePid(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    for (s) |b| try w.writeByte(if (b >= 33 and b <= 126 and b != '[' and b != ']') b else '-');
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
    /// Sent only when `validHostname` holds; `null`, empty or anything else
    /// omits the field (see the file comment). Until 2026-10-05 the default
    /// was `"-"`, which a receiver read as the TAG.
    hostname: ?[]const u8 = null,
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

        if (self.hostname) |h| if (validHostname(h)) {
            try w.writeAll(h);
            try w.writeByte(' ');
        };

        // TAG (alnum-filtered + truncated), then optional [PID], then ": "
        // and the message text.
        try writeTag(w, self.tag);
        if (self.pid) |pid| {
            try w.writeByte('[');
            try writePid(w, pid);
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
    // Not a hostname: omitted, not sanitized into a word a receiver reads as TAG.
    try t.expectEqualStrings("<13>cron-job-x[1-2]: ok", out);
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

test "HOSTNAME: sent only when it is one; else omitted (glibc's shape)" {
    // rsyslogd 8.2512 read each of these first words as the TAG
    // (`rsyslog_oracle_vectors.zig` before 2026-10-05): the old default "-",
    // an empty one, a trailing '-', an IPv6 literal, a word ending in ':',
    // and a hostname that forges TAG and PID.
    var buf: [128]u8 = undefined;
    for ([_]?[]const u8{ null, "", "-", "--", "a-", "-a", "2001:db8::1", "::1", "h:", "host:1", "[h]", "evil app[1]:", "a..b", "x" ** 64 }) |h| {
        const msg = Message{ .facility = .local0, .severity = .warning, .timestamp = .{ .unix_ms = 1783600496000 }, .hostname = h, .tag = "app", .pid = "123", .msg = "hello" };
        try t.expectEqualStrings("<132>Jul  9 12:34:56 app[123]: hello", try bufPrint(&msg, &buf));
    }
    for ([_][]const u8{ "host", "1", "host_1", "Host.Example.COM", "192.0.2.1", "a-b.c", "x" ** 63 }) |h| {
        const msg = Message{ .facility = .local0, .severity = .warning, .timestamp = .{ .unix_ms = 1783600496000 }, .hostname = h, .tag = "app", .msg = "hello" };
        const out = try bufPrint(&msg, &buf);
        try t.expect(std.mem.startsWith(u8, out, "<132>Jul  9 12:34:56 "));
        try t.expect(std.mem.endsWith(u8, out, " app: hello"));
        try t.expectEqualStrings(h, out["<132>Jul  9 12:34:56 ".len .. out.len - " app: hello".len]);
    }
}

test "PID: brackets cannot close [PID] early" {
    const msg = Message{ .hostname = "host", .tag = "app", .pid = "a]b[c", .msg = "x" };
    var buf: [64]u8 = undefined;
    try t.expectEqualStrings("<13>host app[a-b-c]: x", try bufPrint(&msg, &buf));
}
