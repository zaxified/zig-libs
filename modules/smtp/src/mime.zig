// SPDX-License-Identifier: MIT

//! RFC 5322 + RFC 2045/2047 — the encoding primitives a message is built from.
//!
//! * **Header folding** (RFC 5322 §2.2.3). Lines fold at whitespace, aiming for
//!   78 octets and never exceeding 998 — the hard limit that makes a message
//!   invalid, not merely ugly. Both are checked, never assumed: a token that
//!   cannot fit on a folded line of its own is `error.LineTooLong`.
//! * **Encoded words** (RFC 2047) for non-ASCII header text, both `B` and `Q`,
//!   choosing whichever is shorter. A word never exceeds the 75-octet limit of
//!   §2 and a multi-octet UTF-8 sequence is never split across two words, which
//!   is the mistake that produces the mojibake every mail client has a bug
//!   report about.
//! * **quoted-printable** (RFC 2045 §6.7) with 76-column soft breaks that never
//!   split an `=XX` triple, and trailing whitespace protected at end of line.
//! * **base64** (§6.8) in 76-column lines.
//! * **RFC 5322 §3.3 dates** from a caller-supplied epoch second and UTC
//!   offset. This module reads no clock: time is an input, exactly like
//!   randomness. That keeps every rendered message reproducible in a test.
//!
//! Header values are validated before anything else: a CR, LF or NUL inside a
//! header value is `error.ControlCharacterInHeader`. That is header injection —
//! a `Subject` taken from a web form and containing `\r\nBcc: someone@else` is
//! how a contact form becomes a spam relay.

const std = @import("std");
const testing = std.testing;

pub const HeaderError = error{
    /// A header name outside RFC 5322 `ftext` (printable ASCII except ':').
    InvalidHeaderName,
    /// CR, LF or NUL inside a header value.
    ControlCharacterInHeader,
    /// A line could not be folded below `Options.max_line`.
    LineTooLong,
} || std.Io.Writer.Error;

pub const Options = struct {
    /// Where folding starts trying to break (RFC 5322 §2.1.1 "SHOULD").
    fold_at: usize = 78,
    /// The hard ceiling (§2.1.1 "MUST"), excluding CRLF.
    max_line: usize = 998,
    /// Charset announced in encoded words and `Content-Type`.
    charset: []const u8 = "utf-8",
};

pub fn isAscii(s: []const u8) bool {
    for (s) |c| if (c >= 0x80) return false;
    return true;
}

fn validHeaderName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |c| {
        if (c < 33 or c > 126 or c == ':') return false;
    }
    return true;
}

fn checkValue(v: []const u8) HeaderError!void {
    for (v) |c| {
        if (c == '\r' or c == '\n' or c == 0) return error.ControlCharacterInHeader;
    }
}

// ── folding ────────────────────────────────────────────────────────────────

/// Emits a header line, folding at the whitespace between tokens. The caller
/// pushes tokens; the folder decides where the CRLF-SP goes.
pub const Folder = struct {
    w: *std.Io.Writer,
    opts: Options,
    len: usize = 0,
    /// True when nothing has been written on the current line yet.
    fresh: bool = true,

    pub fn init(w: *std.Io.Writer, opts: Options) Folder {
        return .{ .w = w, .opts = opts };
    }

    /// Write text with no folding opportunity before it (the header name).
    pub fn raw(self: *Folder, s: []const u8) HeaderError!void {
        if (self.len + s.len > self.opts.max_line) return error.LineTooLong;
        try self.w.writeAll(s);
        self.len += s.len;
        self.fresh = false;
    }

    /// Write one token, preceded by a space or by a fold.
    pub fn token(self: *Folder, s: []const u8) HeaderError!void {
        if (self.fresh) {
            if (s.len > self.opts.max_line) return error.LineTooLong;
            try self.w.writeAll(s);
            self.len += s.len;
            self.fresh = false;
            return;
        }
        if (self.len + 1 + s.len > self.opts.fold_at and s.len + 1 <= self.opts.max_line) {
            try self.w.writeAll("\r\n ");
            self.len = 1;
        } else {
            try self.w.writeAll(" ");
            self.len += 1;
        }
        if (self.len + s.len > self.opts.max_line) return error.LineTooLong;
        try self.w.writeAll(s);
        self.len += s.len;
    }

    /// Append to the current token with no fold opportunity (a trailing comma).
    pub fn append(self: *Folder, s: []const u8) HeaderError!void {
        if (self.len + s.len > self.opts.max_line) return error.LineTooLong;
        try self.w.writeAll(s);
        self.len += s.len;
    }

    /// Break the line here regardless of width — used when the next token is
    /// known not to fit and would otherwise be split badly.
    pub fn forceFold(self: *Folder) HeaderError!void {
        try self.w.writeAll("\r\n ");
        self.len = 1;
        self.fresh = false;
    }

    pub fn finishLine(self: *Folder) HeaderError!void {
        try self.w.writeAll("\r\n");
        self.len = 0;
        self.fresh = true;
    }
};

// ── RFC 2047 encoded words ─────────────────────────────────────────────────

fn needsEncoding(c: u8) bool {
    // Q-encoding must escape anything outside printable ASCII, plus '=', '?',
    // '_' and (inside a phrase) the specials. Escaping the specials too keeps
    // the word usable in both contexts.
    return switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9', '!', '*', '+', '-', '/' => false,
        else => true,
    };
}

/// Whether `s` can go into a header without RFC 2047 encoding.
pub fn headerTextNeedsEncoding(s: []const u8) bool {
    for (s) |c| {
        if (c >= 0x80 or c < 32 or c == 127) return true;
    }
    // A literal "=?" would be read back as the start of an encoded word.
    return std.mem.indexOf(u8, s, "=?") != null;
}

/// Length of one UTF-8 sequence starting at `s[0]`; 1 for anything invalid, so
/// arbitrary bytes still make progress (they are simply encoded octet-wise).
fn utf8Len(s: []const u8) usize {
    const n = std.unicode.utf8ByteSequenceLength(s[0]) catch return 1;
    if (n > s.len) return 1;
    _ = std.unicode.utf8Decode(s[0..n]) catch return 1;
    return n;
}

/// Emit `text` as one or more RFC 2047 encoded words through `f`, each at most
/// 75 octets. Adjacent words are separate tokens, so the folder puts them on
/// separate lines when needed; RFC 2047 §6.2 says a decoder joins adjacent
/// encoded words and drops the whitespace between them.
pub fn writeEncodedWords(f: *Folder, text: []const u8, opts: Options) HeaderError!void {
    // "=?" + charset + "?B?" + payload + "?=" — the fixed part.
    const overhead = 2 + opts.charset.len + 3 + 2;
    if (overhead + 4 > 75) return error.LineTooLong; // absurd charset name

    var rest = text;
    while (rest.len != 0) {
        // RFC 2047 §2 caps a word at 75 octets, but a word must also FIT the
        // fold width where it lands, or every header would end up one word per
        // line. Shorten the word to the room left on this line; if there is not
        // enough room for a useful word, fold first and use the full width.
        var avail = if (f.opts.fold_at > f.len + 1) f.opts.fold_at - f.len - 1 else 0;
        if (avail < overhead + 8) {
            try f.forceFold();
            avail = f.opts.fold_at - 2;
        }
        const budget = @min(@as(usize, 75), avail) - overhead;
        const use_q = preferQ(rest);
        var taken: usize = 0;
        var cost: usize = 0;
        while (taken < rest.len) {
            const n = utf8Len(rest[taken..]);
            const add = if (use_q) qCost(rest[taken..][0..n]) else 0;
            if (use_q) {
                if (cost + add > budget) break;
                cost += add;
            } else {
                // base64: 4 octets per 3 input octets, rounded up.
                const next = 4 * ((taken + n + 2) / 3);
                if (next > budget) break;
                cost = next;
            }
            taken += n;
        }
        if (taken == 0) {
            // One character alone does not fit the budget — impossible for
            // utf-8 with a sane charset name, but never loop forever.
            return error.LineTooLong;
        }
        var buf: [128]u8 = undefined;
        var bw: std.Io.Writer = .fixed(&buf);
        bw.print("=?{s}?{s}?", .{ opts.charset, if (use_q) "Q" else "B" }) catch return error.LineTooLong;
        if (use_q) {
            writeQWord(&bw, rest[0..taken]) catch return error.LineTooLong;
        } else {
            var enc: [96]u8 = undefined;
            const out = std.base64.standard.Encoder.encode(&enc, rest[0..taken]);
            bw.writeAll(out) catch return error.LineTooLong;
        }
        bw.writeAll("?=") catch return error.LineTooLong;
        try f.token(bw.buffered());
        rest = rest[taken..];
    }
}

/// Encoded width of one source sequence under Q. A space becomes `_`, one
/// octet — forgetting that makes every ASCII-mostly subject pick B.
fn qCost(seq: []const u8) usize {
    var n: usize = 0;
    for (seq) |c| n += if (c != ' ' and needsEncoding(c)) @as(usize, 3) else 1;
    return n;
}

/// Pick Q when it is not longer than B — Q keeps ASCII-mostly text readable,
/// which matters when a human reads a raw header.
fn preferQ(text: []const u8) bool {
    const q = qCost(text);
    const b = 4 * ((text.len + 2) / 3);
    return q <= b;
}

fn writeQWord(w: *std.Io.Writer, text: []const u8) std.Io.Writer.Error!void {
    for (text) |c| {
        if (c == ' ') {
            try w.writeByte('_');
        } else if (needsEncoding(c)) {
            try w.print("={X:0>2}", .{c});
        } else {
            try w.writeByte(c);
        }
    }
}

// ── headers ────────────────────────────────────────────────────────────────

/// An unstructured header (`Subject`, `Comments`, …): encoded-word encoded when
/// it is not plain ASCII, folded at whitespace either way.
pub fn writeUnstructured(w: *std.Io.Writer, name: []const u8, value: []const u8, opts: Options) HeaderError!void {
    if (!validHeaderName(name)) return error.InvalidHeaderName;
    try checkValue(value);
    var f: Folder = .init(w, opts);
    try f.raw(name);
    try f.raw(":");
    if (headerTextNeedsEncoding(value)) {
        try writeEncodedWords(&f, value, opts);
    } else {
        var it = std.mem.tokenizeAny(u8, value, " \t");
        while (it.next()) |tok| try f.token(tok);
    }
    try f.finishLine();
}

/// A header whose value is already in its final form (`Content-Type`,
/// `MIME-Version`, a caller-supplied `raw` header). Folded at whitespace, never
/// encoded.
pub fn writeRawHeader(w: *std.Io.Writer, name: []const u8, value: []const u8, opts: Options) HeaderError!void {
    if (!validHeaderName(name)) return error.InvalidHeaderName;
    try checkValue(value);
    var f: Folder = .init(w, opts);
    try f.raw(name);
    try f.raw(":");
    var it = std.mem.tokenizeAny(u8, value, " \t");
    while (it.next()) |tok| try f.token(tok);
    try f.finishLine();
}

/// One mailbox: an addr-spec plus an optional display name.
pub const Address = struct {
    name: ?[]const u8 = null,
    addr: []const u8,
};

fn nameNeedsQuoting(s: []const u8) bool {
    for (s) |c| {
        switch (c) {
            // RFC 5322 §3.2.3 specials, plus anything that would need folding
            // help.
            '(', ')', '<', '>', '[', ']', ':', ';', '@', '\\', ',', '.', '"' => return true,
            else => {},
        }
        if (c < 33 and c != ' ') return true;
    }
    return false;
}

fn writeQuotedName(f: *Folder, s: []const u8) HeaderError!void {
    var buf: [512]u8 = undefined;
    var bw: std.Io.Writer = .fixed(&buf);
    bw.writeByte('"') catch return error.LineTooLong;
    for (s) |c| {
        if (c == '"' or c == '\\') bw.writeByte('\\') catch return error.LineTooLong;
        bw.writeByte(c) catch return error.LineTooLong;
    }
    bw.writeByte('"') catch return error.LineTooLong;
    try f.token(bw.buffered());
}

/// Write one address through the folder. `trailing` is appended with no fold
/// opportunity (the comma of an address list).
pub fn writeAddress(f: *Folder, a: Address, trailing: []const u8, opts: Options) HeaderError!void {
    try checkValue(a.addr);
    if (a.name) |n| {
        try checkValue(n);
        if (headerTextNeedsEncoding(n)) {
            try writeEncodedWords(f, n, opts);
        } else if (nameNeedsQuoting(n)) {
            try writeQuotedName(f, n);
        } else {
            var it = std.mem.tokenizeAny(u8, n, " \t");
            var any = false;
            while (it.next()) |tok| {
                try f.token(tok);
                any = true;
            }
            if (!any) {
                // A name of only whitespace behaves as no name at all.
                var buf: [512]u8 = undefined;
                const angle = std.fmt.bufPrint(&buf, "<{s}>{s}", .{ a.addr, trailing }) catch return error.LineTooLong;
                try f.token(angle);
                return;
            }
        }
        var buf: [512]u8 = undefined;
        const angle = std.fmt.bufPrint(&buf, "<{s}>{s}", .{ a.addr, trailing }) catch return error.LineTooLong;
        try f.token(angle);
    } else {
        var buf: [512]u8 = undefined;
        const bare = std.fmt.bufPrint(&buf, "{s}{s}", .{ a.addr, trailing }) catch return error.LineTooLong;
        try f.token(bare);
    }
}

/// An address-list header (`From`, `To`, `Cc`, `Reply-To`).
pub fn writeAddressList(w: *std.Io.Writer, name: []const u8, list: []const Address, opts: Options) HeaderError!void {
    if (!validHeaderName(name)) return error.InvalidHeaderName;
    if (list.len == 0) return;
    var f: Folder = .init(w, opts);
    try f.raw(name);
    try f.raw(":");
    for (list, 0..) |a, i| {
        try writeAddress(&f, a, if (i + 1 < list.len) "," else "", opts);
    }
    try f.finishLine();
}

// ── RFC 5322 §3.3 dates ────────────────────────────────────────────────────

/// A point in time as the composer needs it: the epoch second plus the UTC
/// offset to display. No clock is read anywhere in this module — the caller
/// supplies both, so a rendered message is reproducible.
pub const DateTime = struct {
    unix: i64,
    offset_minutes: i32 = 0,
};

const day_names = [_][]const u8{ "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun" };
const month_names = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

const Civil = struct { year: i64, month: u8, day: u8, hour: u8, minute: u8, second: u8, weekday: u8 };

fn floorDiv(a: i64, b: i64) i64 {
    const q = @divTrunc(a, b);
    return if ((@rem(a, b) != 0) and ((a < 0) != (b < 0))) q - 1 else q;
}

/// Howard Hinnant's civil_from_days, the standard branch-free calendar.
fn civilFromUnix(secs: i64) Civil {
    const days = floorDiv(secs, 86400);
    var rem = secs - days * 86400;
    if (rem < 0) rem += 86400;

    const z = days + 719468;
    const era = floorDiv(z, 146097);
    const doe = z - era * 146097; // [0, 146096]
    const yoe = @divTrunc(doe - @divTrunc(doe, 1460) + @divTrunc(doe, 36524) - @divTrunc(doe, 146096), 365);
    const y = yoe + era * 400;
    const doy = doe - (365 * yoe + @divTrunc(yoe, 4) - @divTrunc(yoe, 100));
    const mp = @divTrunc(5 * doy + 2, 153);
    const d = doy - @divTrunc(153 * mp + 2, 5) + 1;
    const m = mp + (if (mp < 10) @as(i64, 3) else -9);

    // 1970-01-01 was a Thursday (index 3 with Monday = 0).
    const wd = @mod(days + 3, 7);
    return .{
        .year = y + @as(i64, if (m <= 2) 1 else 0),
        .month = @intCast(m),
        .day = @intCast(d),
        .hour = @intCast(@divTrunc(rem, 3600)),
        .minute = @intCast(@divTrunc(@mod(rem, 3600), 60)),
        .second = @intCast(@mod(rem, 60)),
        .weekday = @intCast(wd),
    };
}

/// `Tue, 22 Jul 2026 10:00:00 +0200` — RFC 5322 §3.3 `date-time`.
pub fn writeDate(w: *std.Io.Writer, dt: DateTime) std.Io.Writer.Error!void {
    const local = dt.unix + @as(i64, dt.offset_minutes) * 60;
    const c = civilFromUnix(local);
    const off = dt.offset_minutes;
    const sign: u8 = if (off < 0) '-' else '+';
    const abs: u32 = @intCast(if (off < 0) -off else off);
    try w.print("{s}, {d:0>2} {s} {d} {d:0>2}:{d:0>2}:{d:0>2} {c}{d:0>2}{d:0>2}", .{
        day_names[c.weekday],
        c.day,
        month_names[c.month - 1],
        c.year,
        c.hour,
        c.minute,
        c.second,
        sign,
        abs / 60,
        abs % 60,
    });
}

pub fn formatDate(buf: []u8, dt: DateTime) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    writeDate(&w, dt) catch return buf[0..0];
    return w.buffered();
}

// ── content transfer encodings ─────────────────────────────────────────────

/// RFC 2045 §6.7. Writes CRLF-separated lines with **no trailing CRLF** (the
/// caller supplies whatever separator comes next — for a MIME part that is the
/// CRLF belonging to the boundary delimiter).
pub fn writeQuotedPrintable(w: *std.Io.Writer, body: []const u8) std.Io.Writer.Error!void {
    var col: usize = 0;
    var i: usize = 0;
    // Deferred whitespace: a SP/TAB is only safe once a non-whitespace byte
    // follows it on the same line (§6.7 rule 3).
    var held: ?u8 = null;

    while (i < body.len) : (i += 1) {
        const c = body[i];
        const is_eol = c == '\n' or (c == '\r' and i + 1 < body.len and body[i + 1] == '\n');
        if (is_eol) {
            if (held) |h| {
                // Trailing whitespace must be encoded so it survives transport.
                if (col + 3 > 75) {
                    try w.writeAll("=\r\n");
                    col = 0;
                }
                try w.print("={X:0>2}", .{h});
                held = null;
            }
            try w.writeAll("\r\n");
            col = 0;
            if (c == '\r') i += 1;
            continue;
        }
        if (held) |h| {
            if (col + 1 > 75) {
                try w.writeAll("=\r\n");
                col = 0;
            }
            try w.writeByte(h);
            col += 1;
            held = null;
        }
        if (c == ' ' or c == '\t') {
            held = c;
            continue;
        }
        const literal = c >= 33 and c <= 126 and c != '=';
        const width: usize = if (literal) 1 else 3;
        if (col + width > 75) {
            try w.writeAll("=\r\n");
            col = 0;
        }
        if (literal) {
            try w.writeByte(c);
        } else {
            try w.print("={X:0>2}", .{c});
        }
        col += width;
    }
    if (held) |h| {
        if (col + 3 > 75) try w.writeAll("=\r\n");
        try w.print("={X:0>2}", .{h});
    }
}

/// RFC 2045 §6.8 — 76-column base64, no trailing CRLF.
pub fn writeBase64(w: *std.Io.Writer, data: []const u8) std.Io.Writer.Error!void {
    const enc = std.base64.standard.Encoder;
    var buf: [80]u8 = undefined;
    var i: usize = 0;
    var first = true;
    while (i < data.len) : (i += 57) {
        const chunk = data[i..@min(i + 57, data.len)];
        const out = enc.encode(&buf, chunk);
        if (!first) try w.writeAll("\r\n");
        try w.writeAll(out);
        first = false;
    }
}

/// Copy `body` with every line ending normalised to CRLF — the `7bit`/`8bit`
/// path. Nothing is added or removed at the end: the part's own trailing CRLF
/// (or absence of one) is preserved, because the CRLF that precedes a MIME
/// boundary delimiter belongs to the delimiter (RFC 2046 §5.1.1), not to the
/// body, and `message.zig` adds exactly that one.
pub fn writeVerbatimCrlf(w: *std.Io.Writer, body: []const u8) std.Io.Writer.Error!void {
    var i: usize = 0;
    while (i < body.len) : (i += 1) {
        const c = body[i];
        if (c == '\r' or c == '\n') {
            if (c == '\r' and i + 1 < body.len and body[i + 1] == '\n') i += 1;
            try w.writeAll("\r\n");
            continue;
        }
        try w.writeByte(c);
    }
}

/// Every line of `bytes` must be at most `max` octets (RFC 5322 §2.1.1). Run on
/// the finished message: enforcement, not an assumption.
pub fn checkLineLengths(bytes: []const u8, max: usize) error{LineTooLong}!void {
    var start: usize = 0;
    var i: usize = 0;
    while (i < bytes.len) : (i += 1) {
        if (bytes[i] == '\n') {
            var end = i;
            if (end > start and bytes[end - 1] == '\r') end -= 1;
            if (end - start > max) return error.LineTooLong;
            start = i + 1;
        }
    }
    if (bytes.len - start > max) return error.LineTooLong;
}

// ── tests ──────────────────────────────────────────────────────────────────

fn renderHeader(gpa: std.mem.Allocator, comptime f: anytype, args: anytype) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(gpa);
    errdefer aw.deinit();
    try @call(.auto, f, .{&aw.writer} ++ args);
    return aw.toOwnedSlice();
}

test "RFC 5322 §3.3 date formatting, including negative offsets and epoch edges" {
    var buf: [64]u8 = undefined;
    // 2026-07-22T10:00:00Z is a Wednesday.
    try testing.expectEqualStrings("Wed, 22 Jul 2026 10:00:00 +0000", formatDate(&buf, .{ .unix = 1784714400 }));
    try testing.expectEqualStrings("Wed, 22 Jul 2026 12:00:00 +0200", formatDate(&buf, .{ .unix = 1784714400, .offset_minutes = 120 }));
    try testing.expectEqualStrings("Wed, 22 Jul 2026 05:30:00 -0430", formatDate(&buf, .{ .unix = 1784714400, .offset_minutes = -270 }));
    try testing.expectEqualStrings("Thu, 01 Jan 1970 00:00:00 +0000", formatDate(&buf, .{ .unix = 0 }));
    try testing.expectEqualStrings("Wed, 31 Dec 1969 23:59:59 +0000", formatDate(&buf, .{ .unix = -1 }));
    // A leap day, and the 2038 boundary.
    try testing.expectEqualStrings("Sat, 29 Feb 2020 12:00:00 +0000", formatDate(&buf, .{ .unix = 1582977600 }));
    try testing.expectEqualStrings("Tue, 19 Jan 2038 03:14:08 +0000", formatDate(&buf, .{ .unix = 2147483648 }));
}

test "an ASCII header folds at whitespace and never exceeds the limits" {
    const gpa = testing.allocator;
    const long = "The quick brown fox jumps over the lazy dog and keeps on jumping " ++
        "until the line is much longer than seventy-eight characters wide";
    const out = try renderHeader(gpa, writeUnstructured, .{ "Subject", long, Options{} });
    defer gpa.free(out);
    try checkLineLengths(out, 998);
    var it = std.mem.splitSequence(u8, out[0 .. out.len - 2], "\r\n");
    var n: usize = 0;
    while (it.next()) |l| : (n += 1) {
        try testing.expect(l.len <= 78);
        if (n > 0) try testing.expect(l[0] == ' '); // continuation lines are folded
    }
    try testing.expect(n > 1);
    // Unfolding (RFC 5322 §2.2.3) removes the CRLF and keeps the WSP that
    // followed it, so the original text comes back exactly.
    var unfolded: std.ArrayList(u8) = .empty;
    defer unfolded.deinit(gpa);
    var it2 = std.mem.splitSequence(u8, out[0 .. out.len - 2], "\r\n");
    while (it2.next()) |l| try unfolded.appendSlice(gpa, l);
    try testing.expectEqualStrings("Subject: " ++ long, unfolded.items);
}

test "a short header is one line" {
    const gpa = testing.allocator;
    const out = try renderHeader(gpa, writeUnstructured, .{ "Subject", "hello", Options{} });
    defer gpa.free(out);
    try testing.expectEqualStrings("Subject: hello\r\n", out);
}

test "header injection through a value is refused" {
    const gpa = testing.allocator;
    try testing.expectError(error.ControlCharacterInHeader, renderHeader(gpa, writeUnstructured, .{ "Subject", "hi\r\nBcc: victim@example.net", Options{} }));
    try testing.expectError(error.ControlCharacterInHeader, renderHeader(gpa, writeUnstructured, .{ "Subject", "hi\nX: y", Options{} }));
    try testing.expectError(error.ControlCharacterInHeader, renderHeader(gpa, writeUnstructured, .{ "Subject", "hi\x00", Options{} }));
    try testing.expectError(error.InvalidHeaderName, renderHeader(gpa, writeUnstructured, .{ "Sub:ject", "hi", Options{} }));
    try testing.expectError(error.InvalidHeaderName, renderHeader(gpa, writeUnstructured, .{ "", "hi", Options{} }));
    try testing.expectError(error.InvalidHeaderName, renderHeader(gpa, writeUnstructured, .{ "Sub ject", "hi", Options{} }));
}

test "a token that cannot be folded below the hard limit is an error" {
    const gpa = testing.allocator;
    const monster = "A" ** 1200;
    try testing.expectError(error.LineTooLong, renderHeader(gpa, writeUnstructured, .{ "Subject", monster, Options{} }));
    // ...but a 900-octet token is legal, ugly as it is.
    const big = try renderHeader(gpa, writeUnstructured, .{ "Subject", "A" ** 900, Options{} });
    defer gpa.free(big);
    try checkLineLengths(big, 998);
}

test "RFC 2047: non-ASCII subjects become encoded words under 76 octets" {
    const gpa = testing.allocator;
    const out = try renderHeader(gpa, writeUnstructured, .{ "Subject", "Příliš žluťoučký kůň úpěl ďábelské ódy", Options{} });
    defer gpa.free(out);
    try checkLineLengths(out, 998);
    try testing.expect(std.mem.startsWith(u8, out, "Subject: =?utf-8?"));
    var it = std.mem.splitSequence(u8, out[0 .. out.len - 2], "\r\n");
    while (it.next()) |l| {
        try testing.expect(l.len <= 78);
        // Every encoded word is at most 75 octets (RFC 2047 §2).
        var wit = std.mem.tokenizeAny(u8, l, " ");
        while (wit.next()) |word| {
            if (std.mem.startsWith(u8, word, "=?")) try testing.expect(word.len <= 75);
        }
    }
}

test "RFC 2047: a UTF-8 sequence is never split across two encoded words" {
    const gpa = testing.allocator;
    // 120 two-octet characters — long enough to need several words.
    const text = "á" ** 120;
    const out = try renderHeader(gpa, writeUnstructured, .{ "Subject", text, Options{} });
    defer gpa.free(out);
    // Decode every word and concatenate: the result must be the input.
    var joined: std.ArrayList(u8) = .empty;
    defer joined.deinit(gpa);
    var it = std.mem.tokenizeAny(u8, out, " \r\n");
    while (it.next()) |word| {
        if (!std.mem.startsWith(u8, word, "=?")) continue;
        try decodeEncodedWord(gpa, word, &joined);
    }
    try testing.expectEqualStrings(text, joined.items);
    try testing.expect(std.unicode.utf8ValidateSlice(joined.items));
}

test "RFC 2047: B and Q are both produced and both decode" {
    const gpa = testing.allocator;
    // Mostly-ASCII text prefers Q...
    const q = try renderHeader(gpa, writeUnstructured, .{ "Subject", "Hello wörld", Options{} });
    defer gpa.free(q);
    try testing.expect(std.mem.indexOf(u8, q, "?Q?") != null);
    // ...text that is almost all non-ASCII prefers B.
    const b = try renderHeader(gpa, writeUnstructured, .{ "Subject", "ěščřžýáíé", Options{} });
    defer gpa.free(b);
    try testing.expect(std.mem.indexOf(u8, b, "?B?") != null);

    for ([_][]const u8{ q, b }) |out| {
        var joined: std.ArrayList(u8) = .empty;
        defer joined.deinit(gpa);
        var it = std.mem.tokenizeAny(u8, out, " \r\n");
        while (it.next()) |word| {
            if (std.mem.startsWith(u8, word, "=?")) try decodeEncodedWord(gpa, word, &joined);
        }
        try testing.expect(joined.items.len != 0);
    }
    try testing.expect(std.mem.indexOf(u8, q, "w=C3=B6rld") != null);
}

test "a literal '=?' in an ASCII subject is encoded so it is not read back as a word" {
    const gpa = testing.allocator;
    const out = try renderHeader(gpa, writeUnstructured, .{ "Subject", "=?utf-8?B?bm90IHJlYWxseQ==?=", Options{} });
    defer gpa.free(out);
    var joined: std.ArrayList(u8) = .empty;
    defer joined.deinit(gpa);
    var it = std.mem.tokenizeAny(u8, out, " \r\n");
    while (it.next()) |word| {
        if (std.mem.startsWith(u8, word, "=?")) try decodeEncodedWord(gpa, word, &joined);
    }
    try testing.expectEqualStrings("=?utf-8?B?bm90IHJlYWxseQ==?=", joined.items);
}

/// Minimal RFC 2047 decoder, used only by tests as the inverse oracle.
fn decodeEncodedWord(gpa: std.mem.Allocator, word: []const u8, out: *std.ArrayList(u8)) !void {
    try testing.expect(std.mem.startsWith(u8, word, "=?"));
    try testing.expect(std.mem.endsWith(u8, word, "?="));
    const inner = word[2 .. word.len - 2];
    const q1 = std.mem.indexOfScalar(u8, inner, '?').?;
    const q2 = std.mem.indexOfScalarPos(u8, inner, q1 + 1, '?').?;
    const enc = inner[q1 + 1 .. q2];
    const payload = inner[q2 + 1 ..];
    if (enc[0] == 'B' or enc[0] == 'b') {
        const n = try std.base64.standard.Decoder.calcSizeForSlice(payload);
        const buf = try gpa.alloc(u8, n);
        defer gpa.free(buf);
        try std.base64.standard.Decoder.decode(buf, payload);
        try out.appendSlice(gpa, buf);
    } else {
        var i: usize = 0;
        while (i < payload.len) : (i += 1) {
            if (payload[i] == '_') {
                try out.append(gpa, ' ');
            } else if (payload[i] == '=') {
                const v = try std.fmt.parseInt(u8, payload[i + 1 ..][0..2], 16);
                try out.append(gpa, v);
                i += 2;
            } else {
                try out.append(gpa, payload[i]);
            }
        }
    }
}

test "address headers: display names plain, quoted and encoded" {
    const gpa = testing.allocator;
    {
        const out = try renderHeader(gpa, writeAddressList, .{ "From", &[_]Address{.{ .name = "Alice Example", .addr = "alice@example.com" }}, Options{} });
        defer gpa.free(out);
        try testing.expectEqualStrings("From: Alice Example <alice@example.com>\r\n", out);
    }
    {
        // A '.' or a ',' in a display name forces a quoted-string.
        const out = try renderHeader(gpa, writeAddressList, .{ "From", &[_]Address{.{ .name = "Example, Dr. A", .addr = "alice@example.com" }}, Options{} });
        defer gpa.free(out);
        try testing.expectEqualStrings("From: \"Example, Dr. A\" <alice@example.com>\r\n", out);
    }
    {
        const out = try renderHeader(gpa, writeAddressList, .{ "To", &[_]Address{.{ .addr = "bob@example.net" }}, Options{} });
        defer gpa.free(out);
        try testing.expectEqualStrings("To: bob@example.net\r\n", out);
    }
    {
        const out = try renderHeader(gpa, writeAddressList, .{ "To", &[_]Address{.{ .name = "Bůh", .addr = "b@example.net" }}, Options{} });
        defer gpa.free(out);
        try testing.expect(std.mem.indexOf(u8, out, "=?utf-8?") != null);
        try testing.expect(std.mem.indexOf(u8, out, "<b@example.net>") != null);
    }
    {
        // A name containing a quote is escaped, not dropped.
        const out = try renderHeader(gpa, writeAddressList, .{ "To", &[_]Address{.{ .name = "Say \"hi\"", .addr = "b@example.net" }}, Options{} });
        defer gpa.free(out);
        try testing.expectEqualStrings("To: \"Say \\\"hi\\\"\" <b@example.net>\r\n", out);
    }
}

test "a long address list folds between addresses and keeps every comma" {
    const gpa = testing.allocator;
    const list = [_]Address{
        .{ .name = "Recipient One", .addr = "one@example.com" },
        .{ .name = "Recipient Two", .addr = "two@example.com" },
        .{ .name = "Recipient Three", .addr = "three@example.com" },
        .{ .addr = "four@example.com" },
    };
    const out = try renderHeader(gpa, writeAddressList, .{ "To", &list, Options{} });
    defer gpa.free(out);
    try checkLineLengths(out, 998);
    var it = std.mem.splitSequence(u8, out[0 .. out.len - 2], "\r\n");
    while (it.next()) |l| try testing.expect(l.len <= 78);
    try testing.expectEqual(@as(usize, 3), std.mem.count(u8, out, ","));
    try testing.expect(std.mem.indexOf(u8, out, "<four@example.com>") == null);
    try testing.expect(std.mem.indexOf(u8, out, "four@example.com") != null);
}

test "quoted-printable: the RFC 2045 §6.7 rules" {
    const gpa = testing.allocator;
    const cases = [_]struct { in: []const u8, want: []const u8 }{
        .{ .in = "hello", .want = "hello" },
        .{ .in = "a=b", .want = "a=3Db" },
        .{ .in = "caf\xc3\xa9", .want = "caf=C3=A9" },
        // Trailing whitespace must be encoded (rule 3).
        .{ .in = "trailing \r\nnext", .want = "trailing=20\r\nnext" },
        .{ .in = "tab\t\r\n", .want = "tab=09\r\n" },
        // Interior whitespace stays literal.
        .{ .in = "a b\tc", .want = "a b\tc" },
        // Bare LF is a hard line break.
        .{ .in = "one\ntwo", .want = "one\r\ntwo" },
        // A control character is encoded.
        .{ .in = "bell\x07", .want = "bell=07" },
    };
    for (cases) |c| {
        var aw: std.Io.Writer.Allocating = .init(gpa);
        defer aw.deinit();
        try writeQuotedPrintable(&aw.writer, c.in);
        try testing.expectEqualStrings(c.want, aw.written());
    }
}

test "quoted-printable soft breaks never exceed 76 columns nor split a triple" {
    const gpa = testing.allocator;
    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    // Non-ASCII throughout, so every character is three octets encoded.
    try writeQuotedPrintable(&aw.writer, "ř" ** 200);
    var it = std.mem.splitSequence(u8, aw.written(), "\r\n");
    while (it.next()) |l| {
        try testing.expect(l.len <= 76);
        // A soft break ends the line with '=' and the rest must be whole
        // triples: no line may end with a partial "=X".
        const body = if (std.mem.endsWith(u8, l, "=")) l[0 .. l.len - 1] else l;
        try testing.expect(body.len % 3 == 0);
    }
    // Decoding gives the input back.
    const back = try decodeQuotedPrintable(gpa, aw.written());
    defer gpa.free(back);
    try testing.expectEqualStrings("ř" ** 200, back);
}

fn decodeQuotedPrintable(gpa: std.mem.Allocator, s: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        if (s[i] == '=') {
            if (i + 2 < s.len and s[i + 1] == '\r' and s[i + 2] == '\n') {
                i += 2;
                continue;
            }
            const v = try std.fmt.parseInt(u8, s[i + 1 ..][0..2], 16);
            try out.append(gpa, v);
            i += 2;
        } else {
            try out.append(gpa, s[i]);
        }
    }
    return out.toOwnedSlice(gpa);
}

test "base64 bodies are 76-column and decode back" {
    const gpa = testing.allocator;
    var data: [500]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i * 7 + 3);
    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    try writeBase64(&aw.writer, &data);
    var it = std.mem.splitSequence(u8, aw.written(), "\r\n");
    while (it.next()) |l| try testing.expect(l.len <= 76);
    try testing.expect(!std.mem.endsWith(u8, aw.written(), "\r\n"));

    var joined: std.ArrayList(u8) = .empty;
    defer joined.deinit(gpa);
    var it2 = std.mem.splitSequence(u8, aw.written(), "\r\n");
    while (it2.next()) |l| try joined.appendSlice(gpa, l);
    const n = try std.base64.standard.Decoder.calcSizeForSlice(joined.items);
    const back = try gpa.alloc(u8, n);
    defer gpa.free(back);
    try std.base64.standard.Decoder.decode(back, joined.items);
    try testing.expectEqualSlices(u8, &data, back);
}

test "checkLineLengths finds the offending line" {
    try checkLineLengths("short\r\nalso short\r\n", 998);
    try testing.expectError(error.LineTooLong, checkLineLengths("ok\r\n" ++ "A" ** 999 ++ "\r\n", 998));
    try testing.expectError(error.LineTooLong, checkLineLengths("A" ** 999, 998));
    try checkLineLengths("A" ** 998, 998);
}

test "fuzz: arbitrary header text never crashes and never emits a bare CR/LF" {
    try testing.fuzz({}, fuzzHeaders, .{});
}

fn fuzzHeaders(_: void, smith: *std.testing.Smith) !void {
    const gpa = testing.allocator;
    var raw: [300]u8 = undefined;
    smith.bytes(&raw);
    const len = smith.valueRangeAtMost(u16, 0, raw.len);
    const value = raw[0..len];

    if (renderHeader(gpa, writeUnstructured, .{ "Subject", value, Options{} })) |out| {
        defer gpa.free(out);
        try checkLineLengths(out, 998);
        // Every CR must be followed by LF and every LF preceded by CR.
        for (out, 0..) |c, i| {
            if (c == '\r') std.debug.assert(i + 1 < out.len and out[i + 1] == '\n');
            if (c == '\n') std.debug.assert(i > 0 and out[i - 1] == '\r');
        }
    } else |_| {}

    if (renderHeader(gpa, writeAddressList, .{ "To", &[_]Address{.{ .name = value, .addr = "a@example.com" }}, Options{} })) |out| {
        defer gpa.free(out);
        try checkLineLengths(out, 998);
    } else |_| {}

    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    try writeQuotedPrintable(&aw.writer, value);
    var it = std.mem.splitSequence(u8, aw.written(), "\r\n");
    while (it.next()) |l| std.debug.assert(l.len <= 76);
}
