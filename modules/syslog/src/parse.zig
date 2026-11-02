// SPDX-License-Identifier: MIT
//! The receiving side of the codec: a strict RFC 5424 parser, a lenient
//! RFC 3164 parser and the RFC 6587 frame splitter. No listener: bytes come
//! from wherever the caller read them, so everything here is hostile input.
//!
//! Nothing allocates and nothing is copied: every field of a result is a slice
//! of the input. Every function returns an error (or, for the lenient RFC 3164
//! parser, a best reading) on any input, and the iterators stop rather than
//! fail when a caller hands them a `structured_data` of its own.
//!
//! `parse` follows the ABNF of RFC 5424 §6 to the letter, with two listed
//! exceptions the oracle (`tools/go_oracle`) records: the bytes of an SD
//! PARAM-VALUE and of a MSG are not checked to be UTF-8 (this module's own encoder
//! passes the caller's bytes through, and rsyslogd takes them), and a repeated
//! SD-ID is not refused (RFC 5424 §6.3.2 forbids sending one; a receiver reading it
//! loses nothing). Both are visible to the caller.

const std = @import("std");
const datefmt = @import("datefmt");
const message = @import("message.zig");
const bsd = @import("bsd.zig");

const Facility = message.Facility;
const Severity = message.Severity;

/// Why `parse` refused a line. The first field that broke the grammar names it.
pub const ParseError = error{
    /// No `<PRI>`, a PRI outside 0‥191, or more than three digits.
    InvalidPriority,
    /// VERSION is not `1*3DIGIT` without a leading zero.
    InvalidVersion,
    /// Neither `-` nor a real RFC 3339 date and time of RFC 5424's shape.
    InvalidTimestamp,
    InvalidHostname,
    InvalidAppName,
    InvalidProcId,
    InvalidMsgId,
    InvalidStructuredData,
    /// STRUCTURED-DATA is not followed by the end of the line or a space.
    InvalidMessageStart,
};

/// RFC 5424's TIMESTAMP. `unix_us` is the instant, UTC: the printed clock with
/// the printed offset taken out. `offset_minutes` is that offset, `null` for `Z`.
pub const ParsedTimestamp = struct {
    unix_us: i64,
    offset_minutes: ?i16,

    /// The encoder's millisecond `Timestamp` (microseconds are floored away).
    pub fn toTimestamp(self: ParsedTimestamp) message.Timestamp {
        return .{ .unix_ms = @divFloor(self.unix_us, 1000), .offset_minutes = self.offset_minutes };
    }
};

/// One RFC 5424 message; every slice points into the parsed line.
pub const Parsed = struct {
    facility: Facility,
    severity: Severity,
    version: u16,
    timestamp: ?ParsedTimestamp,
    hostname: ?[]const u8,
    app_name: ?[]const u8,
    procid: ?[]const u8,
    msgid: ?[]const u8,
    /// The raw run of SD-ELEMENTs, escapes intact; `null` for the NILVALUE.
    structured_data: ?[]const u8,
    /// MSG without its BOM. Empty when the line has none.
    msg: []const u8,
    /// MSG started with a BOM: the sender states it is UTF-8 (RFC 5424 §6.4).
    msg_utf8: bool,

    /// Walk the SD-ELEMENTs.
    pub fn elements(self: *const Parsed) SdElementIterator {
        return .{ .rest = self.structured_data orelse "" };
    }
};

/// Walks a run of SD-ELEMENTs. On bytes that are not the grammar (a
/// `structured_data` the caller built, never one `parse` returned) it stops.
pub const SdElementIterator = struct {
    rest: []const u8,

    pub fn next(it: *SdElementIterator) ?SdElementView {
        if (it.rest.len == 0 or it.rest[0] != '[') return null;
        const end = scanElement(it.rest) catch return null;
        const body = it.rest[1 .. end - 1];
        it.rest = it.rest[end..];
        const id_end = std.mem.findScalar(u8, body, ' ') orelse body.len;
        return .{ .id = body[0..id_end], .params_raw = body[id_end..] };
    }
};

/// `[ID name="value" …]`.
pub const SdElementView = struct {
    id: []const u8,
    params_raw: []const u8,

    pub fn params(self: SdElementView) SdParamIterator {
        return .{ .rest = self.params_raw };
    }
};

pub const SdParamIterator = struct {
    rest: []const u8,

    pub fn next(it: *SdParamIterator) ?SdParamView {
        const r = it.rest;
        if (r.len == 0 or r[0] != ' ') return null;
        const name_end = scanSdName(r, 1) catch return null;
        if (name_end + 1 >= r.len or r[name_end] != '=' or r[name_end + 1] != '"') return null;
        const value_start = name_end + 2;
        const value_end = scanSdValue(r, value_start) catch return null;
        it.rest = r[value_end + 1 ..];
        return .{ .name = r[1..name_end], .raw_value = r[value_start..value_end] };
    }
};

/// One SD-PARAM; `raw_value` still has its escapes.
pub const SdParamView = struct {
    name: []const u8,
    raw_value: []const u8,

    /// The value unescaped into `buf` (never longer than `raw_value`).
    pub fn value(self: SdParamView, buf: []u8) error{NoSpaceLeft}![]const u8 {
        var w: std.Io.Writer = .fixed(buf);
        self.writeValue(&w) catch return error.NoSpaceLeft;
        return w.buffered();
    }

    /// The value unescaped: `\"`, `\\` and `\]` lose the backslash; a backslash
    /// before anything else stays (RFC 5424 §6.3.3).
    pub fn writeValue(self: SdParamView, w: *std.Io.Writer) std.Io.Writer.Error!void {
        const s = self.raw_value;
        var i: usize = 0;
        var start: usize = 0;
        while (i + 1 < s.len) {
            if (s[i] != '\\') {
                i += 1;
                continue;
            }
            const c = s[i + 1];
            if (c == '"' or c == '\\' or c == ']') {
                try w.writeAll(s[start..i]);
                start = i + 1;
            }
            i += 2;
        }
        try w.writeAll(s[start..]);
    }
};

/// Parse one RFC 5424 line (no frame, no trailing newline handling: a final
/// `\n` belongs to MSG, as the RFC's octets do).
pub fn parse(line: []const u8) ParseError!Parsed {
    var p: usize = 0;
    const pri = try parsePri(line, &p);

    // VERSION SP: NONZERO-DIGIT 0*2DIGIT.
    const v_start = p;
    var version: u16 = 0;
    while (p < line.len and p - v_start < 3 and isDigit(line[p])) : (p += 1) {
        version = version * 10 + (line[p] - '0');
    }
    if (p == v_start or line[v_start] == '0') return error.InvalidVersion;
    if (p >= line.len or line[p] != ' ') return error.InvalidVersion;
    p += 1;

    const timestamp = try parseTimestampField(line, &p);
    const hostname = headerField(line, &p, message.max_hostname) orelse return error.InvalidHostname;
    const app_name = headerField(line, &p, message.max_app_name) orelse return error.InvalidAppName;
    const procid = headerField(line, &p, message.max_procid) orelse return error.InvalidProcId;
    const msgid = headerField(line, &p, message.max_msgid) orelse return error.InvalidMsgId;

    // STRUCTURED-DATA.
    if (p >= line.len) return error.InvalidStructuredData;
    var sd: ?[]const u8 = null;
    if (line[p] == '-') {
        p += 1;
    } else {
        const sd_start = p;
        if (line[p] != '[') return error.InvalidStructuredData;
        while (p < line.len and line[p] == '[') {
            p += scanElement(line[p..]) catch return error.InvalidStructuredData;
        }
        sd = line[sd_start..p];
    }

    // [SP MSG]
    var msg: []const u8 = "";
    var msg_utf8 = false;
    if (p < line.len) {
        if (line[p] != ' ') return error.InvalidMessageStart;
        msg = line[p + 1 ..];
        if (std.mem.startsWith(u8, msg, "\xEF\xBB\xBF")) {
            msg = msg[3..];
            msg_utf8 = true;
        }
    }

    return .{
        .facility = pri.facility,
        .severity = pri.severity,
        .version = version,
        .timestamp = timestamp,
        .hostname = hostname.value,
        .app_name = app_name.value,
        .procid = procid.value,
        .msgid = msgid.value,
        .structured_data = sd,
        .msg = msg,
        .msg_utf8 = msg_utf8,
    };
}

const Pri = struct { facility: Facility, severity: Severity };

fn isDigit(b: u8) bool {
    return b >= '0' and b <= '9';
}

/// `<PRIVAL>`: 1‥3 digits, 0‥191. A leading zero is refused ("<034>"): RFC 3164
/// §4.1.1 forbids it and RFC 5424's own examples never carry one.
fn parsePri(line: []const u8, p: *usize) error{InvalidPriority}!Pri {
    if (line.len < 3 or line[0] != '<') return error.InvalidPriority;
    var i: usize = 1;
    var v: u16 = 0;
    while (i < line.len and i <= 3 and isDigit(line[i])) : (i += 1) {
        v = v * 10 + (line[i] - '0');
    }
    if (i == 1 or i >= line.len or line[i] != '>' or v > 191) return error.InvalidPriority;
    if (line[1] == '0' and i > 2) return error.InvalidPriority;
    p.* = i + 1;
    return priFromValue(@intCast(v));
}

fn priFromValue(v: u8) Pri {
    return .{ .facility = @fromBackingInt(@as(u5, @intCast(v / 8))), .severity = @fromBackingInt(@as(u3, @intCast(v % 8))) };
}

const Field = struct { value: ?[]const u8 };

/// `-` or `1*<max>PRINTUSASCII`, then one space. Null on a broken field.
fn headerField(line: []const u8, p: *usize, max: usize) ?Field {
    const start = p.*;
    var i = start;
    while (i < line.len and line[i] != ' ') : (i += 1) {
        const b = line[i];
        if (b < 33 or b > 126) return null;
        if (i - start >= max) return null;
    }
    if (i == start or i >= line.len) return null;
    p.* = i + 1;
    const s = line[start..i];
    return .{ .value = if (s.len == 1 and s[0] == '-') null else s };
}

fn twoDigits(s: []const u8, at: usize) ?u32 {
    if (at + 2 > s.len or !isDigit(s[at]) or !isDigit(s[at + 1])) return null;
    return @as(u32, s[at] - '0') * 10 + (s[at + 1] - '0');
}

fn parseTimestampField(line: []const u8, p: *usize) error{InvalidTimestamp}!?ParsedTimestamp {
    const start = p.*;
    if (start >= line.len) return error.InvalidTimestamp;
    if (line[start] == '-') {
        if (start + 1 >= line.len or line[start + 1] != ' ') return error.InvalidTimestamp;
        p.* = start + 2;
        return null;
    }
    const end = std.mem.findScalarPos(u8, line, start, ' ') orelse return error.InvalidTimestamp;
    const ts = parseRfc3339(line[start..end]) orelse return error.InvalidTimestamp;
    p.* = end + 1;
    return ts;
}

/// `YYYY-MM-DDTHH:MM:SS[.1*6DIGIT](Z|±HH:MM)`, RFC 5424 §6.2.3: `T` and `Z`
/// upper case, no leap second, a real calendar date.
fn parseRfc3339(s: []const u8) ?ParsedTimestamp {
    if (s.len < 20) return null;
    const yh = twoDigits(s, 0) orelse return null;
    const yl = twoDigits(s, 2) orelse return null;
    const year = yh * 100 + yl;
    if (s[4] != '-' or s[7] != '-' or s[10] != 'T' or s[13] != ':' or s[16] != ':') return null;
    const month = twoDigits(s, 5) orelse return null;
    const day = twoDigits(s, 8) orelse return null;
    const hour = twoDigits(s, 11) orelse return null;
    const minute = twoDigits(s, 14) orelse return null;
    const second = twoDigits(s, 17) orelse return null;
    if (month < 1 or month > 12 or hour > 23 or minute > 59 or second > 59) return null;
    if (day < 1 or day > datefmt.daysInMonth(@intCast(year), month)) return null;

    var i: usize = 19;
    var micro: u32 = 0;
    if (s[i] == '.') {
        i += 1;
        const frac_start = i;
        while (i < s.len and isDigit(s[i]) and i - frac_start < 6) : (i += 1) {
            micro = micro * 10 + (s[i] - '0');
        }
        const digits = i - frac_start;
        if (digits == 0) return null;
        for (digits..6) |_| micro *= 10;
    }
    if (i >= s.len) return null;

    var offset: ?i16 = null;
    switch (s[i]) {
        'Z' => {
            if (i + 1 != s.len) return null;
        },
        '+', '-' => {
            if (i + 6 != s.len or s[i + 3] != ':') return null;
            const oh = twoDigits(s, i + 1) orelse return null;
            const om = twoDigits(s, i + 4) orelse return null;
            if (oh > 23 or om > 59) return null;
            const total: i16 = @intCast(oh * 60 + om);
            offset = if (s[i] == '-') -total else total;
        },
        else => return null,
    }

    const days = datefmt.ymdToEpochDay(@intCast(year), month, day);
    const wall: i64 = days * 86_400 + hour * 3600 + minute * 60 + second;
    const utc = wall - @as(i64, offset orelse 0) * 60;
    return .{ .unix_us = utc * 1_000_000 + micro, .offset_minutes = offset };
}

/// `1*32` bytes of SD-NAME from `start`; the index of the byte after it.
fn scanSdName(s: []const u8, start: usize) error{Invalid}!usize {
    var i = start;
    while (i < s.len) : (i += 1) {
        const b = s[i];
        if (b <= 32 or b >= 127 or b == '=' or b == ']' or b == '"') break;
        if (i - start >= message.max_sd_name) return error.Invalid;
    }
    if (i == start) return error.Invalid;
    return i;
}

/// A PARAM-VALUE from `start`; the index of its closing `"`. An unescaped `]`
/// is outside the grammar (§6.3.3: MUST be escaped).
fn scanSdValue(s: []const u8, start: usize) error{Invalid}!usize {
    var i = start;
    while (i < s.len) : (i += 1) {
        switch (s[i]) {
            '"' => return i,
            ']' => return error.Invalid,
            '\\' => i += 1,
            else => {},
        }
    }
    return error.Invalid;
}

/// One whole `[…]` at the start of `s`; the length of it.
fn scanElement(s: []const u8) error{Invalid}!usize {
    if (s.len == 0 or s[0] != '[') return error.Invalid;
    var i = try scanSdName(s, 1);
    while (i < s.len) {
        switch (s[i]) {
            ']' => return i + 1,
            ' ' => {
                i = try scanSdName(s, i + 1);
                if (i + 1 >= s.len or s[i] != '=' or s[i + 1] != '"') return error.Invalid;
                i = (try scanSdValue(s, i + 2)) + 1;
            },
            else => return error.Invalid,
        }
    }
    return error.Invalid;
}

// ── RFC 3164 ────────────────────────────────────────────────────────────────

/// RFC 3164's timestamp as printed: no year, no zone. A date is not validated
/// against a year (29 Feb cannot be), only against the month's longest.
pub const BsdTimestamp = struct { month: u4, day: u5, hour: u5, minute: u6, second: u6 };

/// One RFC 3164 line as far as it could be read.
pub const ParsedBsd = struct {
    facility: Facility,
    severity: Severity,
    /// The line began with a valid `<PRI>`. Without one RFC 3164 §4.3.3 says
    /// to take `user.notice` and treat the line as CONTENT.
    has_priority: bool,
    timestamp: ?BsdTimestamp,
    /// The timestamp when the sender wrote RFC 3339 instead, which is what Go's
    /// `log/syslog` sends over a network.
    timestamp_rfc3339: ?ParsedTimestamp,
    hostname: ?[]const u8,
    tag: ?[]const u8,
    pid: ?[]const u8,
    /// Everything after `TAG[PID]: `, or the rest of the line when no TAG could
    /// be told apart.
    msg: []const u8,
};

const month_names = [_]*const [3:0]u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
const month_days = [_]u5{ 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

/// Read `Mmm dd hh:mm:ss ` (the day space-padded or not) at `s[p..]`; the
/// index after its trailing space.
fn bsdTimestamp(s: []const u8, p: usize) ?struct { ts: BsdTimestamp, end: usize } {
    if (p + 14 > s.len) return null;
    const mon: u4 = for (month_names, 1..) |n, i| {
        if (std.mem.eql(u8, s[p..][0..3], n)) break @intCast(i);
    } else return null;
    if (s[p + 3] != ' ') return null;
    var i = p + 4;
    var day: u32 = 0;
    if (s[i] == ' ') i += 1; // space padding
    const d_start = i;
    while (i < s.len and i - d_start < 2 and isDigit(s[i])) : (i += 1) day = day * 10 + (s[i] - '0');
    if (i == d_start or day == 0 or day > month_days[mon - 1]) return null;
    if (i + 9 > s.len or s[i] != ' ') return null;
    i += 1;
    const hour = twoDigits(s, i) orelse return null;
    const minute = twoDigits(s, i + 3) orelse return null;
    const second = twoDigits(s, i + 6) orelse return null;
    if (s[i + 2] != ':' or s[i + 5] != ':' or hour > 23 or minute > 59 or second > 60) return null;
    i += 8;
    if (i < s.len and s[i] != ' ') return null;
    const end = if (i < s.len) i + 1 else i;
    return .{
        .ts = .{ .month = mon, .day = @intCast(day), .hour = @intCast(hour), .minute = @intCast(minute), .second = @intCast(second) },
        .end = end,
    };
}

/// A TAG of the shape a sender writes, ended by `:` or `[`: `TAG:` or
/// `TAG[PID]:` at the start of `word`.
const TagShape = struct { tag: []const u8, pid: ?[]const u8, after: usize };

/// Bytes a real TAG carries: letters, digits, and what path-like or
/// service-like names add (`app.service`, `sshd-session`, `kernel/x`).
fn isTagByte(b: u8) bool {
    return switch (b) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '_', '.', '/' => true,
        else => false,
    };
}

fn tagShape(s: []const u8) ?TagShape {
    var i: usize = 0;
    while (i < s.len and isTagByte(s[i])) : (i += 1) {}
    if (i == 0 or i >= s.len or i > 255) return null;
    const tag = s[0..i];
    var pid: ?[]const u8 = null;
    if (s[i] == '[') {
        const close = std.mem.findScalarPos(u8, s, i + 1, ']') orelse return null;
        const body = s[i + 1 .. close];
        for (body) |b| if (b < 33 or b > 126 or b == '[') return null;
        pid = body;
        i = close + 1;
        if (i >= s.len) return null;
    }
    if (s[i] != ':') return null;
    i += 1;
    if (i < s.len and s[i] == ' ') i += 1;
    return .{ .tag = tag, .pid = pid, .after = i };
}

/// Read one RFC 3164 line, leniently: real senders break every rule of it, so
/// this never fails. What cannot be told apart stays in `msg`:
///
///   - no valid `<PRI>`: `user.notice`, `has_priority` false, the line is MSG;
///   - a word is the HOSTNAME only when `bsd.validHostname` holds and it is not
///     itself a `TAG:`, and then only if a `TAG:` follows it or, with a
///     timestamp in front, any text does. Without a timestamp, `host more words`
///     is all MSG: nothing says the first word names a host.
pub fn parseBsd(line: []const u8) ParsedBsd {
    var r: ParsedBsd = .{
        .facility = .user,
        .severity = .notice,
        .has_priority = false,
        .timestamp = null,
        .timestamp_rfc3339 = null,
        .hostname = null,
        .tag = null,
        .pid = null,
        .msg = line,
    };
    var p: usize = 0;
    const pri = parsePri(line, &p) catch return r;
    r.facility = pri.facility;
    r.severity = pri.severity;
    r.has_priority = true;
    r.msg = line[p..];

    var stamped = false;
    if (bsdTimestamp(line, p)) |stamp| {
        r.timestamp = stamp.ts;
        p = stamp.end;
        stamped = true;
    } else if (std.mem.findScalarPos(u8, line, p, ' ')) |sp| {
        if (parseRfc3339(line[p..sp])) |ts| {
            r.timestamp_rfc3339 = ts;
            p = sp + 1;
            stamped = true;
        }
    }
    r.msg = line[p..];

    if (tagShape(line[p..])) |shape| {
        r.tag = shape.tag;
        r.pid = shape.pid;
        r.msg = line[p + shape.after ..];
        return r;
    }

    const sp = std.mem.findScalarPos(u8, line, p, ' ') orelse return r;
    const word = line[p..sp];
    if (!bsd.validHostname(word)) return r;
    const after = sp + 1;
    if (tagShape(line[after..])) |shape| {
        r.hostname = word;
        r.tag = shape.tag;
        r.pid = shape.pid;
        r.msg = line[after + shape.after ..];
    } else if (stamped) {
        r.hostname = word;
        r.msg = line[after..];
    }
    return r;
}

// ── either form ─────────────────────────────────────────────────────────────

/// What a listener gets when it cannot know which form a sender uses.
pub const ParsedAny = union(enum) { rfc5424: Parsed, rfc3164: ParsedBsd };

/// `parse` when the line is well-formed RFC 5424, else `parseBsd`, the rule
/// rsyslogd's default parser chain and syslog_loose apply. Never fails.
pub fn parseAny(line: []const u8) ParsedAny {
    if (parse(line)) |m| return .{ .rfc5424 = m } else |_| return .{ .rfc3164 = parseBsd(line) };
}

// ── RFC 6587 frames ─────────────────────────────────────────────────────────

pub const FrameError = error{
    /// MSG-LEN is not a number (a leading zero, or more digits than any limit).
    BadLength,
    /// The frame is, or says it will be, longer than `max_frame`.
    FrameTooLarge,
};

/// The default limit for `nextFrame`: rsyslogd's own default is 8 KiB, and
/// 64 KiB holds any message a sane sender makes.
pub const default_max_frame: usize = 64 * 1024;

pub const Frame = struct {
    /// The SYSLOG-MSG, without length prefix or trailer.
    payload: []const u8,
    /// Bytes of the buffer this frame took; drop them before the next call.
    consumed: usize,
};

/// Split the next frame off a TCP stream's buffered bytes: `null` until a whole
/// one is there. A first byte that is a digit means octet counting (§3.4.1);
/// anything else non-transparent framing (§3.4.2, ended by LF or NUL; an empty
/// line is consumed and returned as an empty payload).
///
/// On an error the stream cannot be resynchronised with any certainty: close it.
pub fn nextFrame(buf: []const u8, max_frame: usize) FrameError!?Frame {
    if (buf.len == 0) return null;
    if (isDigit(buf[0])) {
        if (buf[0] == '0') return error.BadLength;
        var len: usize = 0;
        var i: usize = 0;
        while (i < buf.len and isDigit(buf[i])) : (i += 1) {
            len = std.math.mul(usize, len, 10) catch return error.BadLength;
            len = std.math.add(usize, len, buf[i] - '0') catch return error.BadLength;
            if (len > max_frame) return error.FrameTooLarge;
        }
        if (i >= buf.len) return null;
        if (buf[i] != ' ') return error.BadLength;
        i += 1;
        if (buf.len - i < len) return null;
        return .{ .payload = buf[i..][0..len], .consumed = i + len };
    }
    const scan = buf[0..@min(buf.len, max_frame +| 1)];
    for (scan, 0..) |b, i| {
        if (b == '\n' or b == 0) return .{ .payload = buf[0..i], .consumed = i + 1 };
    }
    if (buf.len > max_frame) return error.FrameTooLarge;
    return null;
}

// ── tests ───────────────────────────────────────────────────────────────────

const t = std.testing;

test "RFC 5424 §6.5 example 1: no SD, BOM, nil PROCID" {
    const m = try parse("<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - \xEF\xBB\xBF'su root' failed for lonvick on /dev/pts/8");
    try t.expectEqual(Facility.auth, m.facility);
    try t.expectEqual(Severity.crit, m.severity);
    try t.expectEqual(@as(u16, 1), m.version);
    try t.expectEqual(@as(i64, 1065910455003000), m.timestamp.?.unix_us);
    try t.expectEqual(@as(?i16, null), m.timestamp.?.offset_minutes);
    try t.expectEqualStrings("mymachine.example.com", m.hostname.?);
    try t.expectEqualStrings("su", m.app_name.?);
    try t.expectEqual(@as(?[]const u8, null), m.procid);
    try t.expectEqualStrings("ID47", m.msgid.?);
    try t.expectEqual(@as(?[]const u8, null), m.structured_data);
    try t.expect(m.msg_utf8);
    try t.expectEqualStrings("'su root' failed for lonvick on /dev/pts/8", m.msg);
}

test "RFC 5424 §6.5 example 2: offset, micro precision, no MSGID" {
    const m = try parse("<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - - %% It's time to make the do-nuts.");
    try t.expectEqual(@as(?i16, -420), m.timestamp.?.offset_minutes);
    try t.expectEqual(@as(i64, 1061727255000003), m.timestamp.?.unix_us);
    try t.expectEqual(@as(?[]const u8, null), m.msgid);
    try t.expect(!m.msg_utf8);
    try t.expectEqualStrings("%% It's time to make the do-nuts.", m.msg);
}

test "RFC 5424 §6.5 examples 3 and 4: structured data, with and without MSG" {
    const sd3 = "[exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"]";
    const m3 = try parse("<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 " ++ sd3 ++ " An application event log entry...");
    try t.expectEqualStrings(sd3, m3.structured_data.?);
    var els = m3.elements();
    const el = els.next().?;
    try t.expectEqualStrings("exampleSDID@32473", el.id);
    var ps = el.params();
    try t.expectEqualStrings("iut", ps.next().?.name);
    const p2 = ps.next().?;
    try t.expectEqualStrings("eventSource", p2.name);
    var b: [32]u8 = undefined;
    try t.expectEqualStrings("Application", try p2.value(&b));
    try t.expectEqualStrings("eventID", ps.next().?.name);
    try t.expectEqual(@as(?SdParamView, null), ps.next());
    try t.expectEqual(@as(?SdElementView, null), els.next());

    const m4 = try parse("<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 " ++ sd3 ++ "[examplePriority@32473 class=\"high\"]");
    try t.expectEqualStrings("", m4.msg);
    var e4 = m4.elements();
    _ = e4.next().?;
    try t.expectEqualStrings("examplePriority@32473", e4.next().?.id);
}

test "SD-PARAM value unescapes the three escapes and keeps any other backslash" {
    const m = try parse("<13>1 - - - - - [id a=\"x\\\"y\\\\z\\]w\\q\" b=\"\"]");
    var els = m.elements();
    var ps = els.next().?.params();
    var buf: [32]u8 = undefined;
    try t.expectEqualStrings("x\"y\\z]w\\q", try ps.next().?.value(&buf));
    try t.expectEqualStrings("", try ps.next().?.value(&buf));
    // A buffer too small is an error, not a cut.
    var small: [2]u8 = undefined;
    var again = m.elements();
    var ps2 = again.next().?.params();
    try t.expectError(error.NoSpaceLeft, ps2.next().?.value(&small));
}

test "the minimal line, and MSG edges" {
    const m = try parse("<0>1 - - - - - -");
    try t.expectEqual(Facility.kern, m.facility);
    try t.expectEqual(Severity.emerg, m.severity);
    try t.expectEqual(@as(?ParsedTimestamp, null), m.timestamp);
    try t.expectEqualStrings("", m.msg);
    try t.expectEqualStrings("", (try parse("<0>1 - - - - - - ")).msg);
    try t.expectEqualStrings(" x\n", (try parse("<0>1 - - - - - -  x\n")).msg);
    try t.expectEqual(@as(u16, 999), (try parse("<191>999 - - - - - -")).version);
}

test "every grammar break has its own error" {
    const cases = [_]struct { []const u8, ParseError }{
        .{ "", error.InvalidPriority },
        .{ "13>1 - - - - - -", error.InvalidPriority },
        .{ "<>1 - - - - - -", error.InvalidPriority },
        .{ "<192>1 - - - - - -", error.InvalidPriority },
        .{ "<1000>1 - - - - - -", error.InvalidPriority },
        .{ "<013>1 - - - - - -", error.InvalidPriority },
        .{ "<13", error.InvalidPriority },
        .{ "<13>", error.InvalidVersion },
        .{ "<13>0 - - - - - -", error.InvalidVersion },
        .{ "<13>01 - - - - - -", error.InvalidVersion },
        .{ "<13>1000 - - - - - -", error.InvalidVersion },
        .{ "<13>1", error.InvalidVersion },
        .{ "<13>1 ", error.InvalidTimestamp },
        .{ "<13>1 2003-10-11 - - - - -", error.InvalidTimestamp },
        .{ "<13>1 2003-13-11T22:14:15Z - - - - -", error.InvalidTimestamp },
        .{ "<13>1 2003-02-29T22:14:15Z - - - - -", error.InvalidTimestamp },
        .{ "<13>1 2003-10-11T24:14:15Z - - - - -", error.InvalidTimestamp },
        .{ "<13>1 2003-10-11T22:14:60Z - - - - -", error.InvalidTimestamp },
        .{ "<13>1 2003-10-11T22:14:15 - - - - -", error.InvalidTimestamp },
        .{ "<13>1 2003-10-11t22:14:15Z - - - - -", error.InvalidTimestamp },
        .{ "<13>1 2003-10-11T22:14:15z - - - - -", error.InvalidTimestamp },
        .{ "<13>1 2003-10-11T22:14:15.Z - - - - -", error.InvalidTimestamp },
        .{ "<13>1 2003-10-11T22:14:15.1234567Z - - - - -", error.InvalidTimestamp },
        .{ "<13>1 2003-10-11T22:14:15+24:00 - - - - -", error.InvalidTimestamp },
        .{ "<13>1 2003-10-11T22:14:15+01:60 - - - - -", error.InvalidTimestamp },
        .{ "<13>1 -x - - - - -", error.InvalidTimestamp },
        .{ "<13>1 -", error.InvalidTimestamp },
        .{ "<13>1 - ", error.InvalidHostname },
        .{ "<13>1 -  - - - -", error.InvalidHostname },
        .{ "<13>1 - a\x7f - - - -", error.InvalidHostname },
        .{ "<13>1 - h", error.InvalidHostname },
        .{ "<13>1 - - ", error.InvalidAppName },
        .{ "<13>1 - - - ", error.InvalidProcId },
        .{ "<13>1 - - - - ", error.InvalidMsgId },
        .{ "<13>1 - - - - - ", error.InvalidStructuredData },
        .{ "<13>1 - - - - - x", error.InvalidStructuredData },
        .{ "<13>1 - - - - - [", error.InvalidStructuredData },
        .{ "<13>1 - - - - - []", error.InvalidStructuredData },
        .{ "<13>1 - - - - - [id", error.InvalidStructuredData },
        .{ "<13>1 - - - - - [id ]", error.InvalidStructuredData },
        .{ "<13>1 - - - - - [id a]", error.InvalidStructuredData },
        .{ "<13>1 - - - - - [id a=b]", error.InvalidStructuredData },
        .{ "<13>1 - - - - - [id a=\"b]", error.InvalidStructuredData },
        .{ "<13>1 - - - - - [id a=\"b]\"]", error.InvalidStructuredData },
        .{ "<13>1 - - - - - [id a=\"b\\", error.InvalidStructuredData },
        .{ "<13>1 - - - - - [id=x a=\"b\"]", error.InvalidStructuredData },
        .{ "<13>1 - - - - - [" ++ (&@as([33]u8, @splat('a'))) ++ "]", error.InvalidStructuredData },
        .{ "<13>1 - - - - - -x", error.InvalidMessageStart },
        .{ "<13>1 - - - - - [id]x", error.InvalidMessageStart },
    };
    for (cases) |c| {
        const got = parse(c[0]);
        if (got) |_| {
            std.debug.print("accepted: {s}\n", .{c[0]});
            return error.TestUnexpectedResult;
        } else |e| if (e != c[1]) {
            std.debug.print("{s}: {t}, wanted {t}\n", .{ c[0], e, c[1] });
            return error.TestUnexpectedResult;
        }
    }
}

test "header field limits hold at the RFC's numbers" {
    var buf: [600]u8 = undefined;
    const ok = try std.fmt.bufPrint(&buf, "<13>1 - {s} {s} {s} {s} -", .{ &@as([255]u8, @splat('h')), &@as([48]u8, @splat('a')), &@as([128]u8, @splat('p')), &@as([32]u8, @splat('m')) });
    const m = try parse(ok);
    try t.expectEqual(@as(usize, 255), m.hostname.?.len);
    try t.expectError(error.InvalidHostname, parse(try std.fmt.bufPrint(&buf, "<13>1 - {s} - - - -", .{&@as([256]u8, @splat('h'))})));
    try t.expectError(error.InvalidAppName, parse(try std.fmt.bufPrint(&buf, "<13>1 - - {s} - - -", .{&@as([49]u8, @splat('a'))})));
    try t.expectError(error.InvalidProcId, parse(try std.fmt.bufPrint(&buf, "<13>1 - - - {s} - -", .{&@as([129]u8, @splat('p'))})));
    try t.expectError(error.InvalidMsgId, parse(try std.fmt.bufPrint(&buf, "<13>1 - - - - {s} -", .{&@as([33]u8, @splat('m'))})));
}

test "the year zero, year 9999 and a leap day read back as instants" {
    try t.expectEqual(@as(i64, -62167219200000000), (try parse("<13>1 0000-01-01T00:00:00Z - - - - -")).timestamp.?.unix_us);
    try t.expectEqual(@as(i64, 253402300799999999), (try parse("<13>1 9999-12-31T23:59:59.999999Z - - - - -")).timestamp.?.unix_us);
    try t.expectEqual(@as(i64, 951782400000000), (try parse("<13>1 2000-02-29T00:00:00Z - - - - -")).timestamp.?.unix_us);
    const shifted = (try parse("<13>1 1970-01-01T01:00:00+01:00 - - - - -")).timestamp.?;
    try t.expectEqual(@as(i64, 0), shifted.unix_us);
    try t.expectEqual(@as(i64, 0), shifted.toTimestamp().unix_ms);
}

test "SD iterators stop on bytes that are not the grammar" {
    var els: SdElementIterator = .{ .rest = "[id a=\"b" };
    try t.expectEqual(@as(?SdElementView, null), els.next());
    var ps: SdParamIterator = .{ .rest = " a=" };
    try t.expectEqual(@as(?SdParamView, null), ps.next());
    ps = .{ .rest = " a=\"b" };
    try t.expectEqual(@as(?SdParamView, null), ps.next());
    ps = .{ .rest = "x" };
    try t.expectEqual(@as(?SdParamView, null), ps.next());
}

test "RFC 3164: the RFC's examples and glibc's shape" {
    const a = parseBsd("<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8");
    try t.expect(a.has_priority);
    try t.expectEqual(Facility.auth, a.facility);
    try t.expectEqual(Severity.crit, a.severity);
    try t.expectEqual(@as(u4, 10), a.timestamp.?.month);
    try t.expectEqual(@as(u5, 11), a.timestamp.?.day);
    try t.expectEqualStrings("mymachine", a.hostname.?);
    try t.expectEqualStrings("su", a.tag.?);
    try t.expectEqualStrings("'su root' failed for lonvick on /dev/pts/8", a.msg);

    const b = parseBsd("<13>Feb  5 17:32:18 10.0.0.99 Use the BFG!");
    try t.expectEqual(@as(u5, 5), b.timestamp.?.day);
    try t.expectEqualStrings("10.0.0.99", b.hostname.?);
    try t.expectEqual(@as(?[]const u8, null), b.tag);
    try t.expectEqualStrings("Use the BFG!", b.msg);

    const c = parseBsd("<30>Oct  1 00:00:00 sshd[42]: hi: there");
    try t.expectEqual(@as(?[]const u8, null), c.hostname);
    try t.expectEqualStrings("sshd", c.tag.?);
    try t.expectEqualStrings("42", c.pid.?);
    try t.expectEqualStrings("hi: there", c.msg);
}

test "RFC 3164: Go's network form carries RFC 3339" {
    const m = parseBsd("<14>2026-07-09T12:34:56+02:00 web-1 api[9]: ok\n");
    try t.expectEqual(@as(?i16, 120), m.timestamp_rfc3339.?.offset_minutes);
    try t.expectEqualStrings("web-1", m.hostname.?);
    try t.expectEqualStrings("api", m.tag.?);
    try t.expectEqualStrings("9", m.pid.?);
    try t.expectEqualStrings("ok\n", m.msg);
}

test "RFC 3164: whatever is broken stays in MSG" {
    // No PRI, a bad PRI: user.notice, the whole line.
    for ([_][]const u8{ "plain text", "", "<", "<999>x", "<x>y", "<13" }) |s| {
        const m = parseBsd(s);
        try t.expect(!m.has_priority);
        try t.expectEqual(Facility.user, m.facility);
        try t.expectEqual(Severity.notice, m.severity);
        try t.expectEqualStrings(s, m.msg);
    }
    // A day past the month's longest is not a timestamp.
    const bad = parseBsd("<13>Feb 30 00:00:00 h t: m");
    try t.expectEqual(@as(?BsdTimestamp, null), bad.timestamp);
    try t.expectEqualStrings("Feb 30 00:00:00 h t: m", bad.msg);
    // No stamp: no guess at a hostname, only a TAG.
    const ns = parseBsd("<13>host more words");
    try t.expectEqual(@as(?[]const u8, null), ns.hostname);
    try t.expectEqualStrings("host more words", ns.msg);
    // A cut `[PID` is not a TAG.
    const cut = parseBsd("<13>app[12");
    try t.expectEqual(@as(?[]const u8, null), cut.tag);
    try t.expectEqualStrings("app[12", cut.msg);
    // A stamp at the very end of the line.
    const end = parseBsd("<13>Oct 11 22:14:15");
    try t.expectEqual(@as(u5, 22), end.timestamp.?.hour);
    try t.expectEqualStrings("", end.msg);
}

test "parseAny takes RFC 5424 when it holds, RFC 3164 otherwise" {
    try t.expect(parseAny("<13>1 - - - - - - x") == .rfc5424);
    try t.expect(parseAny("<13>Oct 11 22:14:15 h t: x") == .rfc3164);
    try t.expect(parseAny("") == .rfc3164);
}

test "nextFrame: octet counting, and a frame arriving in pieces" {
    const s = "5 hello12 <13>1 - - x\ntail";
    try t.expectEqual(@as(?Frame, null), try nextFrame("", 100));
    for (1..7) |n| try t.expectEqual(@as(?Frame, null), try nextFrame(s[0..n], 100));
    const f = (try nextFrame(s, 100)).?;
    try t.expectEqualStrings("hello", f.payload);
    try t.expectEqual(@as(usize, 7), f.consumed);
    const g = (try nextFrame(s[f.consumed..], 100)).?;
    try t.expectEqualStrings("<13>1 - - x\n", g.payload);
}

test "nextFrame: non-transparent framing by LF and NUL" {
    const s = "<13>a\n<14>b\x00<15>c";
    const f = (try nextFrame(s, 100)).?;
    try t.expectEqualStrings("<13>a", f.payload);
    const g = (try nextFrame(s[f.consumed..], 100)).?;
    try t.expectEqualStrings("<14>b", g.payload);
    try t.expectEqual(@as(?Frame, null), try nextFrame(s[f.consumed + g.consumed ..], 100));
    try t.expectEqualStrings("", (try nextFrame("\nx", 100)).?.payload);
}

test "nextFrame: limits and broken lengths" {
    try t.expectError(error.BadLength, nextFrame("0 x", 100));
    try t.expectError(error.BadLength, nextFrame("05 hello", 100));
    try t.expectError(error.BadLength, nextFrame("5x hello", 100));
    try t.expectError(error.FrameTooLarge, nextFrame("101 x", 100));
    try t.expectError(error.FrameTooLarge, nextFrame("99999999999999999999999999 x", 100));
    try t.expectError(error.BadLength, nextFrame("99999999999999999999999999 x", std.math.maxInt(usize)));
    try t.expectEqualStrings("x", (try nextFrame("1 x", 1)).?.payload);
    var long: [101]u8 = @splat('a');
    try t.expectError(error.FrameTooLarge, nextFrame(&long, 100));
    try t.expectEqual(@as(?Frame, null), try nextFrame(long[0..100], 100));
    long[100] = '\n';
    try t.expectEqual(@as(usize, 100), (try nextFrame(&long, 100)).?.payload.len);
}
