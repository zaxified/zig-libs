// SPDX-License-Identifier: MIT
//! RFC 5424 syslog message model + wire formatter.
//!
//! Pure codec: `Message.format` writes the exact RFC 5424 line
//! `<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD [MSG]` to any
//! `std.Io.Writer`. Nullable header fields render as the NILVALUE `-`.
//! Timestamps are injected (Unix ms) so formatting is deterministic and
//! testable with no clock; `syslog.nowTimestamp()` (root) is the live helper.

const std = @import("std");

// ── PRI: facility + severity ────────────────────────────────────────────────

/// RFC 5424 §6.2.1 facility codes (0‥23). Names follow the common syslog
/// convention (glibc `LOG_*`).
pub const Facility = enum(u5) {
    kern = 0,
    user = 1,
    mail = 2,
    daemon = 3,
    auth = 4,
    syslog = 5,
    lpr = 6,
    news = 7,
    uucp = 8,
    cron = 9,
    authpriv = 10,
    ftp = 11,
    ntp = 12,
    log_audit = 13,
    log_alert = 14,
    clock = 15,
    local0 = 16,
    local1 = 17,
    local2 = 18,
    local3 = 19,
    local4 = 20,
    local5 = 21,
    local6 = 22,
    local7 = 23,
};

/// RFC 5424 §6.2.1 severity codes (0‥7), most→least severe.
pub const Severity = enum(u3) {
    emerg = 0,
    alert = 1,
    crit = 2,
    err = 3,
    warning = 4,
    notice = 5,
    info = 6,
    debug = 7,
};

/// The `<PRI>` numeric value: `facility * 8 + severity` (RFC 5424 §6.2.1).
pub fn priority(f: Facility, s: Severity) u8 {
    return @as(u8, @intFromEnum(f)) * 8 + @intFromEnum(s);
}

// ── timestamp ───────────────────────────────────────────────────────────────

/// An injected wall-clock instant. `unix_ms` is milliseconds since the Unix
/// epoch (UTC). `offset_minutes` is the numeric timezone offset used only for
/// *display*: `null` renders as `Z` (UTC); a value shifts the shown clock and
/// emits `±HH:MM`.
pub const Timestamp = struct {
    unix_ms: i64,
    offset_minutes: ?i16 = null,
};

/// Broken-down calendar fields, already shifted by `offset_minutes`.
pub const CalendarTime = struct {
    year: u16,
    month: u4, // 1‥12
    day: u8, // 1‥31
    hour: u5,
    minute: u6,
    second: u6,
    milli: u16, // 0‥999
    offset_minutes: ?i16,
};

/// Decompose a `Timestamp` into displayable calendar fields. Assumes a
/// post-1970 instant (the shifted second count must be ≥ 0).
pub fn decompose(ts: Timestamp) CalendarTime {
    const off_ms: i64 = @as(i64, ts.offset_minutes orelse 0) * 60_000;
    const adjusted = ts.unix_ms + off_ms;
    const total_secs = @divFloor(adjusted, 1000);
    const milli: u16 = @intCast(@mod(adjusted, 1000));

    const es = std.time.epoch.EpochSeconds{ .secs = @intCast(total_secs) };
    const day = es.getEpochDay();
    const yd = day.calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();

    return .{
        .year = yd.year,
        .month = md.month.numeric(),
        .day = @as(u8, md.day_index) + 1,
        .hour = ds.getHoursIntoDay(),
        .minute = ds.getMinutesIntoHour(),
        .second = ds.getSecondsIntoMinute(),
        .milli = milli,
        .offset_minutes = ts.offset_minutes,
    };
}

/// Write the RFC 3339 timestamp with millisecond precision
/// (`2026-07-09T12:34:56.789Z` or `…+02:00`).
pub fn writeRfc3339(w: *std.Io.Writer, ts: Timestamp) std.Io.Writer.Error!void {
    const c = decompose(ts);
    try w.print("{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}", .{
        c.year, c.month, c.day, c.hour, c.minute, c.second, c.milli,
    });
    if (c.offset_minutes) |om| {
        if (om == 0) {
            try w.writeAll("+00:00");
        } else {
            const sign: u8 = if (om < 0) '-' else '+';
            const a: u16 = @abs(om);
            try w.writeByte(sign);
            try w.print("{d:0>2}:{d:0>2}", .{ a / 60, a % 60 });
        }
    } else {
        try w.writeByte('Z');
    }
}

// ── structured data ─────────────────────────────────────────────────────────

/// One `name="value"` parameter inside an SD element.
pub const SdParam = struct {
    name: []const u8,
    value: []const u8,
};

/// One `[SD-ID param="v" …]` structured-data element.
pub const SdElement = struct {
    id: []const u8,
    params: []const SdParam = &.{},
};

// ── RFC 5424 field length limits (§6) ───────────────────────────────────────

pub const max_hostname = 255;
pub const max_app_name = 48;
pub const max_procid = 128;
pub const max_msgid = 32;
pub const max_sd_name = 32;

// ── message ─────────────────────────────────────────────────────────────────

/// A structured RFC 5424 message. Build one and call `format`. Header fields
/// are optional; `null` (or empty) emits the NILVALUE `-`. Over-length header
/// fields are silently **truncated** to their RFC limit and bytes outside
/// printable US-ASCII (33‥126) are replaced with `-`.
pub const Message = struct {
    facility: Facility = .user,
    severity: Severity = .notice,
    timestamp: ?Timestamp = null,
    hostname: ?[]const u8 = null,
    app_name: ?[]const u8 = null,
    procid: ?[]const u8 = null,
    msgid: ?[]const u8 = null,
    structured_data: []const SdElement = &.{},
    msg: []const u8 = "",

    /// Custom-format entry point — also reachable via `{f}`.
    pub fn format(self: *const Message, w: *std.Io.Writer) std.Io.Writer.Error!void {
        // <PRI>VERSION SP
        try w.print("<{d}>1 ", .{priority(self.facility, self.severity)});

        // TIMESTAMP SP
        if (self.timestamp) |ts| {
            try writeRfc3339(w, ts);
        } else {
            try w.writeByte('-');
        }
        try w.writeByte(' ');

        // HOSTNAME SP APP-NAME SP PROCID SP MSGID SP
        try writeField(w, self.hostname, max_hostname);
        try w.writeByte(' ');
        try writeField(w, self.app_name, max_app_name);
        try w.writeByte(' ');
        try writeField(w, self.procid, max_procid);
        try w.writeByte(' ');
        try writeField(w, self.msgid, max_msgid);
        try w.writeByte(' ');

        // STRUCTURED-DATA
        try writeStructuredData(w, self.structured_data);

        // [SP MSG] — the MSG (and its leading space) is omitted when empty.
        if (self.msg.len > 0) {
            try w.writeByte(' ');
            try w.writeAll(self.msg);
        }
    }
};

/// Write a header field: NILVALUE `-` when absent/empty, else the value
/// truncated to `max` bytes with non-printable bytes mapped to `-`.
fn writeField(w: *std.Io.Writer, value: ?[]const u8, max: usize) std.Io.Writer.Error!void {
    const s = value orelse return w.writeByte('-');
    if (s.len == 0) return w.writeByte('-');
    var n: usize = 0;
    for (s) |b| {
        if (n >= max) break;
        try w.writeByte(if (b >= 33 and b <= 126) b else '-');
        n += 1;
    }
}

/// Write an SD-NAME (element id / param name): printable US-ASCII minus the
/// four reserved bytes `= SP ] "`, truncated to `max_sd_name`.
fn writeSdName(w: *std.Io.Writer, name: []const u8) std.Io.Writer.Error!void {
    var n: usize = 0;
    for (name) |b| {
        if (n >= max_sd_name) break;
        const ok = b > 32 and b < 127 and b != '=' and b != ']' and b != '"';
        try w.writeByte(if (ok) b else '-');
        n += 1;
    }
}

/// Escape an SD-PARAM value per RFC 5424 §6.3.3: `"`, `\` and `]` are
/// backslash-escaped; every other byte passes through verbatim.
fn writeSdValue(w: *std.Io.Writer, value: []const u8) std.Io.Writer.Error!void {
    for (value) |b| switch (b) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        ']' => try w.writeAll("\\]"),
        else => try w.writeByte(b),
    };
}

/// Write the STRUCTURED-DATA field: NILVALUE `-` when empty, else a run of
/// `[SD-ID param="value" …]` elements.
fn writeStructuredData(w: *std.Io.Writer, sd: []const SdElement) std.Io.Writer.Error!void {
    if (sd.len == 0) return w.writeByte('-');
    for (sd) |el| {
        try w.writeByte('[');
        try writeSdName(w, el.id);
        for (el.params) |p| {
            try w.writeByte(' ');
            try writeSdName(w, p.name);
            try w.writeAll("=\"");
            try writeSdValue(w, p.value);
            try w.writeByte('"');
        }
        try w.writeByte(']');
    }
}

/// Format `msg` into `buf`, returning the written slice.
/// `error.NoSpaceLeft` if `buf` is too small for the whole line.
pub fn bufPrint(msg: *const Message, buf: []u8) error{NoSpaceLeft}![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    msg.format(&w) catch return error.NoSpaceLeft;
    return w.buffered();
}

// ── tests ───────────────────────────────────────────────────────────────────

const t = std.testing;

test "priority = facility*8 + severity" {
    try t.expectEqual(@as(u8, 0), priority(.kern, .emerg));
    try t.expectEqual(@as(u8, 34), priority(.auth, .crit)); // RFC 5424 §6.5 example
    try t.expectEqual(@as(u8, 132), priority(.local0, .warning));
    try t.expectEqual(@as(u8, 165), priority(.local4, .notice));
    try t.expectEqual(@as(u8, 191), priority(.local7, .debug)); // max
}

test "full RFC 5424 line with structured data" {
    const msg = Message{
        .facility = .auth,
        .severity = .crit,
        .timestamp = .{ .unix_ms = 1783600496789 }, // 2026-07-09T12:34:56.789Z
        .hostname = "mymachine.example.com",
        .app_name = "evntslog",
        .procid = null,
        .msgid = "ID47",
        .structured_data = &.{
            .{ .id = "exampleSDID@32473", .params = &.{
                .{ .name = "iut", .value = "3" },
                .{ .name = "eventSource", .value = "Application" },
                .{ .name = "eventID", .value = "1011" },
            } },
        },
        .msg = "An application event log entry",
    };
    var buf: [512]u8 = undefined;
    const out = try bufPrint(&msg, &buf);
    try t.expectEqualStrings(
        "<34>1 2026-07-09T12:34:56.789Z mymachine.example.com evntslog - ID47 " ++
            "[exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] " ++
            "An application event log entry",
        out,
    );
}

test "minimal message: all NILVALUE fields, no MSG" {
    const msg = Message{ .facility = .user, .severity = .notice };
    var buf: [64]u8 = undefined;
    try t.expectEqualStrings("<13>1 - - - - - -", try bufPrint(&msg, &buf));
}

test "structured-data value escaping of \" \\ ]" {
    const msg = Message{
        .facility = .user,
        .severity = .notice,
        .structured_data = &.{
            .{ .id = "ex@1", .params = &.{.{ .name = "k", .value = "a\"b\\c]d" }} },
        },
    };
    var buf: [128]u8 = undefined;
    try t.expectEqualStrings(
        "<13>1 - - - - - [ex@1 k=\"a\\\"b\\\\c\\]d\"]",
        try bufPrint(&msg, &buf),
    );
}

test "timestamp with a positive UTC offset" {
    const msg = Message{
        .facility = .user,
        .severity = .notice,
        .timestamp = .{ .unix_ms = 1767323045000, .offset_minutes = 120 },
    };
    var buf: [64]u8 = undefined;
    // instant 2026-01-02T03:04:05Z displayed at +02:00 → 05:04:05+02:00
    try t.expectEqualStrings(
        "<13>1 2026-01-02T05:04:05.000+02:00 - - - - -",
        try bufPrint(&msg, &buf),
    );
}

test "header fields truncate at RFC 5424 length limits" {
    const msg = Message{
        .facility = .user,
        .severity = .notice,
        .hostname = "h" ** 300,
        .app_name = "a" ** 60,
        .procid = "p" ** 200,
        .msgid = "m" ** 40,
    };
    var buf: [1024]u8 = undefined;
    const out = try bufPrint(&msg, &buf);

    // Tokenize the header on spaces and check each field's length.
    var it = std.mem.tokenizeScalar(u8, out, ' ');
    _ = it.next(); // <13>1
    _ = it.next(); // timestamp "-"
    try t.expectEqual(@as(usize, max_hostname), it.next().?.len);
    try t.expectEqual(@as(usize, max_app_name), it.next().?.len);
    try t.expectEqual(@as(usize, max_procid), it.next().?.len);
    try t.expectEqual(@as(usize, max_msgid), it.next().?.len);
}

test "non-printable bytes in a header field become '-'" {
    const msg = Message{
        .facility = .user,
        .severity = .notice,
        .hostname = "a\tb c", // TAB and SPACE are not printable header bytes
    };
    var buf: [64]u8 = undefined;
    const out = try bufPrint(&msg, &buf);
    try t.expect(std.mem.indexOf(u8, out, "a-b-c ") != null);
}

test "bufPrint reports NoSpaceLeft when the buffer is too small" {
    const msg = Message{ .facility = .user, .severity = .notice, .msg = "x" ** 100 };
    var tiny: [16]u8 = undefined;
    try t.expectError(error.NoSpaceLeft, bufPrint(&msg, &tiny));
}
