// SPDX-License-Identifier: MIT
//! RFC 5424 syslog message model + wire formatter.
//!
//! Pure codec: `Message.format` writes the exact RFC 5424 line
//! `<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD [MSG]` to any
//! `std.Io.Writer`. Nullable header fields render as the NILVALUE `-`.
//! Timestamps are injected (Unix ms) so formatting is deterministic and
//! testable with no clock; `syslog.nowTimestamp()` (root) is the live helper.

const std = @import("std");
const datefmt = @import("datefmt");

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

/// Largest `total_secs` `decompose` accepts: 9999-12-31T23:59:59Z, the last
/// instant RFC 3339's 4-digit year (`{d:0>4}`) can represent.
const max_epoch_secs: i64 = 253402300799;

/// Largest sane UTC offset magnitude, in minutes: ±23:59. Real timezone
/// offsets never exceed ±14:00, but this is the widest value `±HH:MM`
/// (two-digit hours) can still render meaningfully.
const max_offset_minutes: u16 = 1439;

pub const DecomposeError = error{
    /// The shifted instant is before the Unix epoch, or past year 9999 —
    /// not representable as an RFC 3339 calendar time. Guards against a
    /// hostile/negative timestamp crashing the formatter.
    TimestampOutOfRange,
};

/// Decompose a `Timestamp` into displayable calendar fields. Only a
/// representable instant (Unix epoch ‥ year 9999, after the `offset_minutes`
/// shift) succeeds; anything else returns `error.TimestampOutOfRange` rather
/// than panicking on the out-of-range `@intCast`.
pub fn decompose(ts: Timestamp) DecomposeError!CalendarTime {
    const off_ms: i64 = @as(i64, ts.offset_minutes orelse 0) * 60_000;
    const adjusted = ts.unix_ms +| off_ms;
    const total_secs = @divFloor(adjusted, 1000);
    if (total_secs < 0 or total_secs > max_epoch_secs) return error.TimestampOutOfRange;
    const milli: u16 = @intCast(@mod(adjusted, 1000));

    // `datefmt`'s branchless civil-from-days, not `std.time.epoch`. std's
    // `calculateYearDay` walks **one loop iteration per year since 1970** --
    // 56 of them in 2026, and one more every New Year -- and its
    // `calculateMonthDay` then walks the months. This runs once per message,
    // so it is the record rate that pays for it. Measured in `http`, which had
    // the identical four lines: **3,043 instructions per call down to 141**.
    //
    // The range check above is what makes this safe: `DateParts.year` is an
    // `i32`, and seconds past year 9999 would overflow it.
    const p = datefmt.unixToParts(total_secs);

    return .{
        .year = @intCast(p.year),
        .month = @intCast(p.month),
        .day = @intCast(p.day),
        .hour = @intCast(p.hour),
        .minute = @intCast(p.minute),
        .second = @intCast(p.second),
        .milli = milli,
        .offset_minutes = ts.offset_minutes,
    };
}

/// Write the RFC 3339 timestamp with millisecond precision
/// (`2026-07-09T12:34:56.789Z` or `…+02:00`). Errors (without writing) on a
/// timestamp `decompose` rejects; `Message.format` renders such a timestamp
/// as the NILVALUE `-` instead.
pub fn writeRfc3339(w: *std.Io.Writer, ts: Timestamp) (std.Io.Writer.Error || DecomposeError)!void {
    try writeCalendar(w, try decompose(ts));
}

fn writeCalendar(w: *std.Io.Writer, c: CalendarTime) std.Io.Writer.Error!void {
    try w.print("{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}", .{
        c.year, c.month, c.day, c.hour, c.minute, c.second, c.milli,
    });
    if (c.offset_minutes) |om| {
        if (om == 0) {
            try w.writeAll("+00:00");
        } else {
            const sign: u8 = if (om < 0) '-' else '+';
            // Clamp to the largest sane UTC offset (±23:59 = 1439 minutes) so a
            // wild-but-in-range `i16` (e.g. from a hostile/buggy caller) still
            // prints a valid `±HH:MM` instead of a nonsensical `±546:07`.
            const a: u16 = @min(@as(u16, @abs(om)), max_offset_minutes);
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

        // TIMESTAMP SP — an unrepresentable (e.g. pre-1970/hostile) instant
        // renders as the NILVALUE `-` rather than crashing the formatter.
        if (self.timestamp) |ts| {
            if (decompose(ts)) |c|
                try writeCalendar(w, c)
            else |_|
                try w.writeByte('-');
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

test "SD-ID and param name: the four reserved bytes ('=', SP, ']', '\"') become '-'" {
    // `writeSdName`'s doc comment claims these four bytes are excluded, but
    // nothing exercised that filter — every other test's SD-ID/param names
    // are already reserved-byte-free. A reserved byte reaching the wire
    // unescaped here (unlike param VALUEs, which are backslash-escaped)
    // would corrupt the `[ID param="v"]` framing itself — e.g. a raw ']'
    // in an SD-ID closes the element early.
    const msg = Message{
        .facility = .user,
        .severity = .notice,
        .structured_data = &.{
            .{ .id = "a=b c]d\"e", .params = &.{.{ .name = "x=y z]w\"v", .value = "ok" }} },
        },
    };
    var buf: [128]u8 = undefined;
    try t.expectEqualStrings(
        "<13>1 - - - - - [a-b-c-d-e x-y-z-w-v=\"ok\"]",
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

test "decompose rejects out-of-range timestamps instead of panicking" {
    // Pre-1970 instants (negative unix_ms, or pushed negative by the offset
    // shift) would panic the old `@intCast(total_secs)` — now a clean error.
    try t.expectError(error.TimestampOutOfRange, decompose(.{ .unix_ms = -1 }));
    try t.expectError(error.TimestampOutOfRange, decompose(.{ .unix_ms = -1_000_000_000 }));
    try t.expectError(error.TimestampOutOfRange, decompose(.{ .unix_ms = 0, .offset_minutes = -1 }));
    // Absurd far-future instant (would overflow the u16 year) is rejected too.
    try t.expectError(error.TimestampOutOfRange, decompose(.{ .unix_ms = std.math.maxInt(i64) }));
    // The epoch itself and a valid instant still decompose.
    try t.expectEqual(@as(u16, 1970), (try decompose(.{ .unix_ms = 0 })).year);
    try t.expectEqual(@as(u16, 2026), (try decompose(.{ .unix_ms = 1783600496789 })).year);
}

test "format renders NILVALUE '-' for a hostile out-of-range timestamp" {
    const msg = Message{
        .facility = .user,
        .severity = .notice,
        .timestamp = .{ .unix_ms = -1000 }, // pre-epoch
    };
    var buf: [64]u8 = undefined;
    // No panic; the timestamp field is the NILVALUE, like an absent one.
    try t.expectEqualStrings("<13>1 - - - - - -", try bufPrint(&msg, &buf));
}

test "writeRfc3339 clamps a wild offset_minutes instead of printing garbage" {
    // offset_minutes = maxInt/minInt(i16) is nonsense for a UTC offset (real
    // offsets never exceed ±14:00), but the type allows it. Without a clamp
    // this prints "+546:07"/"-546:08"; clamped, it prints the largest sane
    // offset "±23:59". The calendar date itself still shifts by the full
    // (unclamped) offset via `decompose` — only the printed `±HH:MM` suffix
    // is clamped — so this only checks the suffix, not the date.
    var buf: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try writeRfc3339(&w, .{ .unix_ms = 0, .offset_minutes = 32767 });
    try t.expect(std.mem.endsWith(u8, w.buffered(), "+23:59"));

    w = std.Io.Writer.fixed(&buf);
    // Base far enough from the epoch that shifting back ~22.7 days by the
    // wild negative offset stays inside decompose's valid range.
    try writeRfc3339(&w, .{ .unix_ms = 100_000_000_000, .offset_minutes = -32768 });
    try t.expect(std.mem.endsWith(u8, w.buffered(), "-23:59"));
}

test "bufPrint reports NoSpaceLeft when the buffer is too small" {
    const msg = Message{ .facility = .user, .severity = .notice, .msg = "x" ** 100 };
    var tiny: [16]u8 = undefined;
    try t.expectError(error.NoSpaceLeft, bufPrint(&msg, &tiny));
}

test "the calendar: leap days, year boundaries and both ends of the range" {
    // `decompose` is where the RFC 3339 timestamp's date comes from, and until
    // 2026-08-29 it walked `std.time.epoch`'s year-at-a-time loop. The two
    // implementations agree on ordinary dates and differ where a calendar is
    // easy to get wrong, so those are what is pinned here rather than the
    // 2026-07-09 instant the formatter tests already use.
    const cases = [_]struct { ms: i64, want: []const u8 }{
        .{ .ms = 0, .want = "1970-01-01T00:00:00.000Z" },
        .{ .ms = 1709164800_000, .want = "2024-02-29T00:00:00.000Z" }, // leap day
        .{ .ms = 1709251199_999, .want = "2024-02-29T23:59:59.999Z" }, // its last ms
        .{ .ms = 1709251200_000, .want = "2024-03-01T00:00:00.000Z" }, // the day after
        .{ .ms = 1735689599_999, .want = "2024-12-31T23:59:59.999Z" }, // year boundary
        .{ .ms = 1735689600_000, .want = "2025-01-01T00:00:00.000Z" },
        .{ .ms = 4107542400_000, .want = "2100-03-01T00:00:00.000Z" }, // 2100 is NOT a leap year
        .{ .ms = 253402300799_000, .want = "9999-12-31T23:59:59.000Z" }, // the last instant accepted
    };
    for (cases) |c| {
        var buf: [64]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        try writeRfc3339(&w, .{ .unix_ms = c.ms });
        try std.testing.expectEqualStrings(c.want, w.buffered());
    }
}
