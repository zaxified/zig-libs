// SPDX-License-Identifier: MIT

//! RFC 5321 §4.2 — the SMTP reply, as a pure incremental parser.
//!
//! A reply is one or more lines. Every line starts with the SAME three-digit
//! code; a line whose fourth octet is `-` is a continuation, a line whose
//! fourth octet is SP (or which is exactly three octets long) is the last one.
//! Getting that `-` vs SP test wrong is the classic SMTP parsing bug: a client
//! that stops at the first line desynchronises for the rest of the session,
//! because every later reply is read one command too early.
//!
//! Nothing here reads, blocks or allocates a socket: `feed(bytes)` then
//! `next() -> ?Reply`, identical results whether the bytes arrive one at a time
//! or a megabyte at a time.
//!
//! The reply code is mapped to a **typed** error that keeps the one distinction
//! a caller actually needs: 4yz is transient (retry the same command later),
//! 5yz is permanent (do not retry it verbatim). Collapsing those two into one
//! "SMTP error" is what turns a greylisted message into a bounce.
//!
//! RFC 3463 enhanced status codes are parsed out of the first line when they
//! are present and their class digit agrees with the reply code. They are only
//! meaningful when the server advertised `ENHANCEDSTATUSCODES` (RFC 2034); the
//! session layer is what knows that, so this layer reports what it saw and
//! judges nothing.

const std = @import("std");
const testing = std.testing;

/// The first digit of a reply code (RFC 5321 §4.2.1).
pub const Class = enum(u8) {
    /// 1yz — positive preliminary. No SMTP command defined in RFC 5321 uses it.
    preliminary = 1,
    /// 2yz — the command was accepted and completed.
    completion = 2,
    /// 3yz — the server wants more input (`354` after DATA, `334` during AUTH).
    intermediate = 3,
    /// 4yz — transient negative. The identical command may succeed later; this
    /// is the code a caller retries on (greylisting, "out of disk", …).
    transient = 4,
    /// 5yz — permanent negative. Retrying the identical command will fail the
    /// identical way; the caller must change something (or bounce).
    permanent = 5,
};

/// RFC 3463 enhanced status code: `class.subject.detail`.
pub const Enhanced = struct {
    class: u8,
    subject: u16,
    detail: u16,

    pub fn format(self: Enhanced, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.print("{d}.{d}.{d}", .{ self.class, self.subject, self.detail });
    }
};

/// The two failure verdicts a caller has to tell apart, plus the "the server
/// said something, but not what this command needs" case.
pub const ReplyError = error{
    /// 4yz — retryable.
    TransientFailure,
    /// 5yz — not retryable as-is.
    PermanentFailure,
    /// A syntactically valid reply whose code is not one this step accepts
    /// (e.g. 250 where 354 was required).
    UnexpectedReply,
};

/// One complete reply. `text` points into the parser's buffer and is valid
/// until the next `next()` call — `clone` it to keep it.
pub const Reply = struct {
    code: u16,
    /// RFC 3463 code from the first line, when present and consistent with
    /// `code`. Trust it only if `ENHANCEDSTATUSCODES` was advertised.
    enhanced: ?Enhanced = null,
    /// Every line's text, LF-joined, reply codes and the `-`/SP separator
    /// removed. The enhanced-status prefix is NOT stripped: it is part of what
    /// the server said, and stripping it would hide a mismatch.
    text: []const u8,
    /// How many physical lines the reply occupied.
    lines: usize,

    pub fn class(self: Reply) Class {
        return @enumFromInt(self.code / 100);
    }

    pub fn isPositive(self: Reply) bool {
        const c = self.code / 100;
        return c == 2 or c == 3;
    }

    /// The typed permanent/transient verdict. 2yz and 3yz return `{}`.
    pub fn check(self: Reply) ReplyError!void {
        return switch (self.code / 100) {
            2, 3 => {},
            4 => error.TransientFailure,
            5 => error.PermanentFailure,
            // 1yz has no meaning in SMTP; treat as "not what we asked for"
            // rather than silently succeeding.
            else => error.UnexpectedReply,
        };
    }

    /// Require an exact code (`expectCode(354)` after DATA). A wrong-but-valid
    /// reply keeps its permanent/transient nature so the caller's retry logic
    /// still works.
    pub fn expectCode(self: Reply, want: u16) ReplyError!void {
        if (self.code == want) return;
        try self.check();
        return error.UnexpectedReply;
    }

    /// A heap copy that outlives the parser's buffer.
    pub fn clone(self: Reply, gpa: std.mem.Allocator) std.mem.Allocator.Error!Owned {
        return .{ .reply = .{
            .code = self.code,
            .enhanced = self.enhanced,
            .text = try gpa.dupe(u8, self.text),
            .lines = self.lines,
        } };
    }
};

/// A `Reply` that owns its text.
pub const Owned = struct {
    reply: Reply,

    pub fn deinit(self: *Owned, gpa: std.mem.Allocator) void {
        gpa.free(self.reply.text);
        self.* = undefined;
    }
};

/// Hostile-input ceilings. Every one bounds memory an unauthenticated peer can
/// make us hold; none is a tuning knob.
pub const Limits = struct {
    /// Longest single reply line, excluding CRLF. RFC 5321 §4.5.3.1.5 sets the
    /// minimum a server may assume at 512 octets *including* CRLF; real servers
    /// occasionally exceed it, so this is a tolerance ceiling, not the spec
    /// figure.
    max_line: usize = 4096,
    /// Most continuation lines in one reply. An EHLO response with more
    /// capabilities than this is refused rather than buffered.
    max_lines: usize = 256,
    /// Most accumulated reply text (the LF-joined result).
    max_text: usize = 64 * 1024,
    /// Most un-parsed input held at once.
    max_pending: usize = 256 * 1024,
};

pub const Options = struct {
    /// Accept a bare LF as a line terminator. Off by default: SMTP lines are
    /// CRLF-terminated, and treating a bare LF as a terminator is exactly the
    /// parser disagreement the 2023 "SMTP smuggling" attacks exploited. Turn it
    /// on only to talk to a specific broken peer.
    allow_bare_lf: bool = false,
};

pub const ParseError = error{
    /// Fewer than three octets, or a fourth octet that is neither SP nor `-`.
    MalformedReply,
    /// The first three octets are not digits, or the first digit is not 1..5.
    InvalidReplyCode,
    /// A continuation line carried a different code than the first line.
    ReplyCodeMismatch,
    /// A line exceeded `Limits.max_line` before any CRLF appeared.
    ReplyLineTooLong,
    /// More lines than `Limits.max_lines`, or more text than `max_text` — the
    /// "continuation that never terminates" case.
    ReplyTooLong,
    /// More buffered input than `Limits.max_pending`.
    PendingTooLarge,
    /// A LF that was not preceded by CR (see `Options.allow_bare_lf`).
    BareLineFeed,
    /// A CR that was not followed by LF.
    BareCarriageReturn,
} || std.mem.Allocator.Error;

/// Incremental reply decoder.
///
///     var p: Parser = .init(gpa, .{}, .{});
///     defer p.deinit();
///     try p.feed(bytes_from_the_wire);
///     while (try p.next()) |reply| { ... }   // valid until the next call
pub const Parser = struct {
    gpa: std.mem.Allocator,
    limits: Limits,
    opts: Options,

    pending: std.ArrayList(u8) = .empty,
    cursor: usize = 0,
    /// Text accumulated for the reply currently being assembled.
    text: std.ArrayList(u8) = .empty,
    /// Buffer handed to the caller (kept apart from `text` so assembling the
    /// next reply cannot invalidate the one just returned before it is asked
    /// for).
    out: std.ArrayList(u8) = .empty,
    code: ?u16 = null,
    enhanced: ?Enhanced = null,
    lines: usize = 0,

    pub fn init(gpa: std.mem.Allocator, limits: Limits, opts: Options) Parser {
        return .{ .gpa = gpa, .limits = limits, .opts = opts };
    }

    pub fn deinit(self: *Parser) void {
        self.pending.deinit(self.gpa);
        self.text.deinit(self.gpa);
        self.out.deinit(self.gpa);
        self.* = undefined;
    }

    /// True when no reply is half-decoded and nothing is buffered.
    pub fn atBoundary(self: *const Parser) bool {
        return self.code == null and self.pending.items.len == self.cursor;
    }

    pub fn feed(self: *Parser, bytes: []const u8) ParseError!void {
        self.compact();
        if (self.pending.items.len + bytes.len > self.limits.max_pending) return error.PendingTooLarge;
        try self.pending.appendSlice(self.gpa, bytes);
    }

    fn compact(self: *Parser) void {
        if (self.cursor == 0) return;
        const rest = self.pending.items.len - self.cursor;
        std.mem.copyForwards(u8, self.pending.items[0..rest], self.pending.items[self.cursor..]);
        self.pending.shrinkRetainingCapacity(rest);
        self.cursor = 0;
    }

    /// Decode the next complete reply, or null if more bytes are needed.
    pub fn next(self: *Parser) ParseError!?Reply {
        while (true) {
            const buf = self.pending.items[self.cursor..];
            const nl = std.mem.indexOfScalar(u8, buf, '\n') orelse {
                // No terminator yet. A CR at the very end may still become
                // CRLF, so only bound the wait here.
                if (buf.len > self.limits.max_line + 1) return error.ReplyLineTooLong;
                return null;
            };
            if (nl > self.limits.max_line + 1) return error.ReplyLineTooLong;

            var line = buf[0..nl];
            if (line.len != 0 and line[line.len - 1] == '\r') {
                line = line[0 .. line.len - 1];
            } else if (!self.opts.allow_bare_lf) {
                return error.BareLineFeed;
            }
            // A CR anywhere else in the line is a framing lie.
            if (std.mem.indexOfScalar(u8, line, '\r') != null) return error.BareCarriageReturn;

            // `line` points into `pending`, so it must be consumed BEFORE the
            // buffer is compacted underneath it.
            const done = try self.consumeLine(line);
            self.cursor += nl + 1;
            self.compact();
            if (done) |r| return r;
        }
    }

    /// Fold one CRLF-stripped line into the reply being assembled; returns the
    /// reply when the line was the last one.
    fn consumeLine(self: *Parser, line: []const u8) ParseError!?Reply {
        if (line.len < 3) return error.MalformedReply;
        for (line[0..3]) |c| if (c < '0' or c > '9') return error.InvalidReplyCode;
        const code: u16 = @as(u16, line[0] - '0') * 100 +
            @as(u16, line[1] - '0') * 10 + @as(u16, line[2] - '0');
        if (code < 100 or code > 599) return error.InvalidReplyCode;

        // "3DIGIT [ (SP / '-') textstring ]" — a bare three-octet line is a
        // legal last line with no text.
        var last = true;
        var text: []const u8 = "";
        if (line.len > 3) {
            switch (line[3]) {
                ' ' => last = true,
                '-' => last = false,
                else => return error.MalformedReply,
            }
            text = line[4..];
        }

        if (self.code) |first| {
            if (first != code) return error.ReplyCodeMismatch;
            if (self.lines >= self.limits.max_lines) return error.ReplyTooLong;
            if (self.text.items.len + 1 + text.len > self.limits.max_text) return error.ReplyTooLong;
            try self.text.append(self.gpa, '\n');
            try self.text.appendSlice(self.gpa, text);
        } else {
            self.code = code;
            self.enhanced = parseEnhanced(text, code);
            if (text.len > self.limits.max_text) return error.ReplyTooLong;
            try self.text.appendSlice(self.gpa, text);
        }
        self.lines += 1;
        if (!last) return null;

        self.out.clearRetainingCapacity();
        std.mem.swap(std.ArrayList(u8), &self.text, &self.out);
        const r: Reply = .{
            .code = code,
            .enhanced = self.enhanced,
            .text = self.out.items,
            .lines = self.lines,
        };
        self.code = null;
        self.enhanced = null;
        self.lines = 0;
        return r;
    }
};

/// RFC 3463 §2: `class "." subject "." detail`, first token of the text, with
/// the class digit agreeing with the reply code. A mismatch means the token is
/// ordinary text (some servers really do start a message with "5.0" prose), so
/// it is reported as "no enhanced code" rather than as an error.
pub fn parseEnhanced(text: []const u8, code: u16) ?Enhanced {
    const end = std.mem.indexOfScalar(u8, text, ' ') orelse text.len;
    const tok = text[0..end];
    var it = std.mem.splitScalar(u8, tok, '.');
    const a = it.next() orelse return null;
    const b = it.next() orelse return null;
    const c = it.next() orelse return null;
    if (it.next() != null) return null;
    if (a.len != 1) return null;
    if (b.len == 0 or b.len > 3 or c.len == 0 or c.len > 3) return null;
    const class = std.fmt.parseInt(u8, a, 10) catch return null;
    const subject = std.fmt.parseInt(u16, b, 10) catch return null;
    const detail = std.fmt.parseInt(u16, c, 10) catch return null;
    // RFC 3463 defines only 2/4/5 and requires agreement with the reply code.
    if (class != 2 and class != 4 and class != 5) return null;
    if (class != code / 100) return null;
    return .{ .class = class, .subject = subject, .detail = detail };
}

// ── tests ──────────────────────────────────────────────────────────────────

fn collect(gpa: std.mem.Allocator, input: []const u8, byte_at_a_time: bool) !std.ArrayList(Owned) {
    var p: Parser = .init(gpa, .{}, .{});
    defer p.deinit();
    var out: std.ArrayList(Owned) = .empty;
    errdefer {
        for (out.items) |*o| o.deinit(gpa);
        out.deinit(gpa);
    }
    if (byte_at_a_time) {
        for (input) |b| {
            try p.feed(&[_]u8{b});
            while (try p.next()) |r| try out.append(gpa, try r.clone(gpa));
        }
    } else {
        try p.feed(input);
        while (try p.next()) |r| try out.append(gpa, try r.clone(gpa));
    }
    return out;
}

fn freeAll(gpa: std.mem.Allocator, list: *std.ArrayList(Owned)) void {
    for (list.items) |*o| o.deinit(gpa);
    list.deinit(gpa);
}

test "single-line reply, whole read and byte-at-a-time agree" {
    const gpa = testing.allocator;
    const wire = "220 mail.example.com ESMTP ready\r\n";
    for ([_]bool{ false, true }) |drip| {
        var got = try collect(gpa, wire, drip);
        defer freeAll(gpa, &got);
        try testing.expectEqual(@as(usize, 1), got.items.len);
        try testing.expectEqual(@as(u16, 220), got.items[0].reply.code);
        try testing.expectEqualStrings("mail.example.com ESMTP ready", got.items[0].reply.text);
        try testing.expectEqual(@as(usize, 1), got.items[0].reply.lines);
    }
}

test "the '-' vs SP continuation test: a multi-line EHLO reply is ONE reply" {
    const gpa = testing.allocator;
    // RFC 5321 §4.1.1.1 shape, with the last line separated by SP.
    const wire =
        "250-mail.example.com greets client.example.org\r\n" ++
        "250-PIPELINING\r\n" ++
        "250-SIZE 35882577\r\n" ++
        "250-8BITMIME\r\n" ++
        "250-STARTTLS\r\n" ++
        "250-ENHANCEDSTATUSCODES\r\n" ++
        "250 SMTPUTF8\r\n";
    for ([_]bool{ false, true }) |drip| {
        var got = try collect(gpa, wire, drip);
        defer freeAll(gpa, &got);
        try testing.expectEqual(@as(usize, 1), got.items.len);
        const r = got.items[0].reply;
        try testing.expectEqual(@as(u16, 250), r.code);
        try testing.expectEqual(@as(usize, 7), r.lines);
        try testing.expectEqualStrings(
            "mail.example.com greets client.example.org\nPIPELINING\nSIZE 35882577\n" ++
                "8BITMIME\nSTARTTLS\nENHANCEDSTATUSCODES\nSMTPUTF8",
            r.text,
        );
    }
}

test "a line with a code and no text is a legal last line" {
    const gpa = testing.allocator;
    var got = try collect(gpa, "250-x\r\n250\r\n", false);
    defer freeAll(gpa, &got);
    try testing.expectEqual(@as(usize, 1), got.items.len);
    try testing.expectEqualStrings("x\n", got.items[0].reply.text);
}

test "several replies in one read are not merged" {
    const gpa = testing.allocator;
    var got = try collect(gpa, "250 ok\r\n354 go ahead\r\n250 queued\r\n", false);
    defer freeAll(gpa, &got);
    try testing.expectEqual(@as(usize, 3), got.items.len);
    try testing.expectEqual(@as(u16, 250), got.items[0].reply.code);
    try testing.expectEqual(@as(u16, 354), got.items[1].reply.code);
    try testing.expectEqual(@as(u16, 250), got.items[2].reply.code);
}

test "permanent vs transient is the distinction that survives" {
    const gpa = testing.allocator;
    var got = try collect(gpa, "451 4.7.1 try later\r\n550 5.1.1 no such user\r\n250 ok\r\n", false);
    defer freeAll(gpa, &got);
    try testing.expectError(error.TransientFailure, got.items[0].reply.check());
    try testing.expectError(error.PermanentFailure, got.items[1].reply.check());
    try got.items[2].reply.check();

    // A valid-but-wrong code keeps its class.
    try testing.expectError(error.UnexpectedReply, got.items[2].reply.expectCode(354));
    try testing.expectError(error.PermanentFailure, got.items[1].reply.expectCode(354));
}

test "RFC 3463 enhanced status codes" {
    const gpa = testing.allocator;
    var got = try collect(gpa, "550 5.1.1 <a@example.com>: unknown\r\n" ++
        "451 4.7.1 greylisted\r\n" ++
        "250 2.0.0 Ok\r\n" ++
        "550 5.1 malformed enhanced\r\n" ++
        "550 4.1.1 class disagrees with the reply code\r\n" ++
        "250 no enhanced code at all\r\n", false);
    defer freeAll(gpa, &got);
    try testing.expectEqual(Enhanced{ .class = 5, .subject = 1, .detail = 1 }, got.items[0].reply.enhanced.?);
    try testing.expectEqual(Enhanced{ .class = 4, .subject = 7, .detail = 1 }, got.items[1].reply.enhanced.?);
    try testing.expectEqual(Enhanced{ .class = 2, .subject = 0, .detail = 0 }, got.items[2].reply.enhanced.?);
    try testing.expect(got.items[3].reply.enhanced == null);
    try testing.expect(got.items[4].reply.enhanced == null);
    try testing.expect(got.items[5].reply.enhanced == null);
    // The enhanced prefix stays in the text — it is what the server said.
    try testing.expectEqualStrings("5.1.1 <a@example.com>: unknown", got.items[0].reply.text);
}

test "hostile replies are typed errors, never accepted" {
    const gpa = testing.allocator;
    const cases = [_]struct { wire: []const u8, want: anyerror }{
        .{ .wire = "no code here\r\n", .want = error.InvalidReplyCode },
        .{ .wire = "2x0 non-digit\r\n", .want = error.InvalidReplyCode },
        .{ .wire = "099 first digit 0\r\n", .want = error.InvalidReplyCode },
        .{ .wire = "700 first digit 7\r\n", .want = error.InvalidReplyCode },
        .{ .wire = "25\r\n", .want = error.MalformedReply },
        .{ .wire = "250x bad separator\r\n", .want = error.MalformedReply },
        .{ .wire = "250\tbad separator\r\n", .want = error.MalformedReply },
        .{ .wire = "250-first\r\n251 different code\r\n", .want = error.ReplyCodeMismatch },
        .{ .wire = "220 bare lf\n", .want = error.BareLineFeed },
        .{ .wire = "220 bare\rcr\r\n", .want = error.BareCarriageReturn },
    };
    for (cases) |c| {
        for ([_]bool{ false, true }) |drip| {
            var p: Parser = .init(gpa, .{}, .{});
            defer p.deinit();
            var got: ParseError!?Reply = null;
            if (drip) {
                for (c.wire) |b| {
                    try p.feed(&[_]u8{b});
                    got = p.next();
                    if (got) |_| {} else |_| break;
                }
            } else {
                try p.feed(c.wire);
                got = p.next();
            }
            testing.expectError(c.want, got) catch |e| {
                std.debug.print("case: {s}\n", .{c.wire});
                return e;
            };
        }
    }
}

test "a continuation that never terminates is bounded" {
    const gpa = testing.allocator;
    var p: Parser = .init(gpa, .{ .max_lines = 8 }, .{});
    defer p.deinit();
    var i: usize = 0;
    const err = while (i < 100) : (i += 1) {
        p.feed("250-x\r\n") catch |e| break e;
        if (p.next() catch |e| break e) |_| break error.UnexpectedSuccess;
    } else error.UnexpectedSuccess;
    try testing.expectEqual(anyerror.ReplyTooLong, err);
}

test "an over-long line is refused before it is buffered whole" {
    const gpa = testing.allocator;
    var p: Parser = .init(gpa, .{ .max_line = 64 }, .{});
    defer p.deinit();
    const long = "250 " ++ "A" ** 200 ++ "\r\n";
    try p.feed(long);
    try testing.expectError(error.ReplyLineTooLong, p.next());
}

test "text accumulation is bounded even with a legal line count" {
    const gpa = testing.allocator;
    var p: Parser = .init(gpa, .{ .max_text = 32 }, .{});
    defer p.deinit();
    try p.feed("250-" ++ "A" ** 20 ++ "\r\n250-" ++ "B" ** 20 ++ "\r\n250 done\r\n");
    try testing.expectError(error.ReplyTooLong, p.next());
}

test "pending input is bounded" {
    const gpa = testing.allocator;
    var p: Parser = .init(gpa, .{ .max_pending = 16 }, .{});
    defer p.deinit();
    try testing.expectError(error.PendingTooLarge, p.feed("2" ** 32));
}

test "bare LF is accepted only when explicitly opted into" {
    const gpa = testing.allocator;
    var p: Parser = .init(gpa, .{}, .{ .allow_bare_lf = true });
    defer p.deinit();
    try p.feed("220 lenient\n");
    const r = (try p.next()).?;
    try testing.expectEqualStrings("lenient", r.text);
}

test "fuzz: no reply stream can crash, hang or leak the parser" {
    try testing.fuzz({}, fuzzReply, .{});
}

fn fuzzReply(_: void, smith: *std.testing.Smith) !void {
    const gpa = testing.allocator;
    var raw: [512]u8 = undefined;
    smith.bytes(&raw);
    const len = smith.valueRangeAtMost(u16, 0, raw.len);
    const input = raw[0..len];
    for ([_]bool{ false, true }) |bare_lf| {
        var p: Parser = .init(gpa, .{ .max_line = 256, .max_lines = 16, .max_text = 1024, .max_pending = 4096 }, .{ .allow_bare_lf = bare_lf });
        defer p.deinit();
        p.feed(input) catch continue;
        while (true) {
            const r = p.next() catch break;
            const rr = r orelse break;
            // Every accepted reply must satisfy the invariants the rest of the
            // module relies on.
            std.debug.assert(rr.code >= 100 and rr.code <= 599);
            std.debug.assert(rr.lines >= 1);
            if (rr.enhanced) |e| std.debug.assert(e.class == rr.code / 100);
        }
    }
}
