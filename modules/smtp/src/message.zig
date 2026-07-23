// SPDX-License-Identifier: MIT

//! RFC 5322 + RFC 2045/2046 — the message composer.
//!
//! A `Message` is plain data: a caller writes it as a struct literal, including
//! nested `multipart/mixed` and `multipart/alternative` trees, and `render`
//! turns it into one RFC 5322 document. Nothing is read from the environment —
//! the date and the randomness are both inputs (`mime.DateTime`, `std.Random`),
//! so the same `Message` renders to the same bytes every time, which is what
//! makes a byte-exact golden possible at all.
//!
//! Three things are enforced rather than hoped for:
//!
//! * **The boundary really is unique.** RFC 2046 §5.1.1 requires that the
//!   boundary delimiter not appear inside any body part. Every child is
//!   rendered *first*, then a boundary is drawn and checked against every one
//!   of those bytes; a collision draws again, and after
//!   `RenderOptions.max_boundary_attempts` it is `error.BoundaryCollision`.
//!   "128 random bits will never collide" is true right up until the caller
//!   attaches a file that contains a previous message.
//! * **The 998-octet line limit** (RFC 5322 §2.1.1). Headers fold; bodies that
//!   cannot be represented inside the limit as `7bit` are transfer-encoded; and
//!   the finished document is scanned before it is returned.
//! * **No control character reaches a header.** A CR or LF in a subject, a
//!   display name or a caller-supplied header value is
//!   `error.ControlCharacterInHeader` — that is header injection.
//!
//! The CRLF that precedes a boundary delimiter belongs to the delimiter, not to
//! the part (RFC 2046 §5.1.1), so a part's content is emitted exactly as it is
//! and the container adds the separator. That is what makes
//! `decode(render(x)) == x` hold for bodies that do and do not end in a line
//! break.

const std = @import("std");
const testing = std.testing;
const mime = @import("mime.zig");
const command = @import("command.zig");

pub const Encoding = enum {
    seven_bit,
    eight_bit,
    quoted_printable,
    base64,

    pub fn text(self: Encoding) []const u8 {
        return switch (self) {
            .seven_bit => "7bit",
            .eight_bit => "8bit",
            .quoted_printable => "quoted-printable",
            .base64 => "base64",
        };
    }
};

pub const Disposition = enum {
    attachment,
    /// `inline` is a Zig keyword; the wire token is still "inline".
    displayed_inline,

    pub fn text(self: Disposition) []const u8 {
        return switch (self) {
            .attachment => "attachment",
            .displayed_inline => "inline",
        };
    }
};

pub const Subtype = enum {
    /// Independent parts, shown one after another (RFC 2046 §5.1.3).
    mixed,
    /// The same content in several forms, best last (RFC 2046 §5.1.4).
    alternative,
    /// A compound object: HTML plus the images it references (RFC 2387).
    related,

    pub fn text(self: Subtype) []const u8 {
        return switch (self) {
            .mixed => "mixed",
            .alternative => "alternative",
            .related => "related",
        };
    }
};

/// A `text/*` part.
pub const Text = struct {
    /// The subtype: "plain", "html", …
    subtype: []const u8 = "plain",
    charset: []const u8 = "utf-8",
    body: []const u8,
    /// null selects `7bit` for ASCII bodies with short lines and
    /// `quoted-printable` otherwise.
    encoding: ?Encoding = null,
};

/// A file part with `Content-Disposition`.
pub const Attachment = struct {
    filename: []const u8,
    content_type: []const u8 = "application/octet-stream",
    data: []const u8,
    disposition: Disposition = .attachment,
    /// `Content-ID`, without the angle brackets — for `multipart/related`.
    content_id: ?[]const u8 = null,
    /// null selects base64.
    encoding: ?Encoding = null,
};

pub const Multipart = struct {
    subtype: Subtype = .mixed,
    parts: []const Part,
};

pub const Part = union(enum) {
    text: Text,
    attachment: Attachment,
    multipart: Multipart,
};

/// A caller-supplied header. `raw` values are folded but never encoded, for a
/// value the caller has already structured (`List-Unsubscribe`, a DKIM
/// signature produced elsewhere, …).
pub const Header = struct {
    name: []const u8,
    value: []const u8,
    raw: bool = false,
};

pub const Message = struct {
    from: mime.Address,
    /// RFC 5322 §3.6.2 — required when `from` names someone other than the
    /// actual sender.
    sender: ?mime.Address = null,
    to: []const mime.Address = &.{},
    cc: []const mime.Address = &.{},
    /// Recipients that get the message without appearing in it. NOT emitted as
    /// a header unless `RenderOptions.include_bcc` — a `Bcc` header that
    /// reaches the recipients is a privacy incident.
    bcc: []const mime.Address = &.{},
    reply_to: []const mime.Address = &.{},
    subject: []const u8 = "",
    /// RFC 5322 §3.6.1. Supplied by the caller: this module reads no clock.
    date: mime.DateTime,
    /// The `Message-ID` without angle brackets, or null to generate one.
    message_id: ?[]const u8 = null,
    /// Right-hand side of a generated `Message-ID`.
    message_id_domain: []const u8 = "localhost",
    in_reply_to: ?[]const u8 = null,
    references: []const []const u8 = &.{},
    headers: []const Header = &.{},
    body: Part,
};

pub const RenderOptions = struct {
    mime: mime.Options = .{},
    /// Emit a `Bcc` header. Off by default; see `Message.bcc`.
    include_bcc: bool = false,
    /// Prefix of every generated boundary. Keep it distinctive: it is what
    /// makes an accidental collision with body content implausible in the
    /// first place.
    boundary_prefix: []const u8 = "=_zigsmtp_",
    /// Random octets behind the prefix.
    boundary_entropy: usize = 16,
    /// How many times a colliding boundary is redrawn before giving up.
    max_boundary_attempts: usize = 8,
    /// Nesting ceiling for multipart trees.
    max_depth: usize = 8,
};

pub const RenderError = error{
    /// A line could not be brought under `mime.Options.max_line`.
    LineTooLong,
    /// Every drawn boundary occurred inside a part.
    BoundaryCollision,
    /// A `multipart` with no parts (RFC 2046 §5.1.1 requires at least one).
    EmptyMultipart,
    /// Deeper nesting than `RenderOptions.max_depth`.
    DepthExceeded,
    /// An address that is not a legal `addr-spec`.
    InvalidAddress,
    /// A header name outside RFC 5322 `ftext`.
    InvalidHeaderName,
    /// CR, LF or NUL in a header value, display name or filename.
    ControlCharacterInHeader,
} || std.mem.Allocator.Error;

fn wrap(e: anyerror) RenderError {
    return switch (e) {
        error.OutOfMemory, error.WriteFailed => error.OutOfMemory,
        error.LineTooLong => error.LineTooLong,
        error.InvalidHeaderName => error.InvalidHeaderName,
        error.ControlCharacterInHeader => error.ControlCharacterInHeader,
        else => error.ControlCharacterInHeader,
    };
}

/// One rendered part: its MIME headers, and its content with no separator.
const Rendered = struct {
    headers: []u8,
    content: []u8,

    fn deinit(self: *Rendered, gpa: std.mem.Allocator) void {
        gpa.free(self.headers);
        gpa.free(self.content);
        self.* = undefined;
    }
};

/// Render `msg` into one RFC 5322 document (CRLF line endings, ready to hand to
/// `data.writeData`). `random` supplies boundaries and, when needed, the
/// `Message-ID`.
pub fn render(
    gpa: std.mem.Allocator,
    msg: Message,
    random: std.Random,
    opts: RenderOptions,
) RenderError![]u8 {
    var body = try renderPart(gpa, msg.body, random, opts, 0);
    defer body.deinit(gpa);

    var aw: std.Io.Writer.Allocating = .init(gpa);
    errdefer aw.deinit();
    const w = &aw.writer;

    // RFC 5322 §3.6 order is not mandated, but this is the conventional one and
    // keeping it stable is what lets a golden exist.
    {
        var f: mime.Folder = .init(w, opts.mime);
        f.raw("Date:") catch |e| return wrap(e);
        var db: [64]u8 = undefined;
        f.token(mime.formatDate(&db, msg.date)) catch |e| return wrap(e);
        f.finishLine() catch |e| return wrap(e);
    }
    try writeAddrHeader(w, "From", &[_]mime.Address{msg.from}, opts);
    if (msg.sender) |s| try writeAddrHeader(w, "Sender", &[_]mime.Address{s}, opts);
    if (msg.reply_to.len != 0) try writeAddrHeader(w, "Reply-To", msg.reply_to, opts);
    if (msg.to.len != 0) try writeAddrHeader(w, "To", msg.to, opts);
    if (msg.cc.len != 0) try writeAddrHeader(w, "Cc", msg.cc, opts);
    if (opts.include_bcc and msg.bcc.len != 0) try writeAddrHeader(w, "Bcc", msg.bcc, opts);

    {
        var idbuf: [128]u8 = undefined;
        const id = if (msg.message_id) |m| m else generateMessageId(&idbuf, random, msg.message_id_domain) catch return error.LineTooLong;
        var line: [256]u8 = undefined;
        const v = std.fmt.bufPrint(&line, "<{s}>", .{id}) catch return error.LineTooLong;
        mime.writeRawHeader(w, "Message-ID", v, opts.mime) catch |e| return wrap(e);
    }
    if (msg.in_reply_to) |r| {
        var line: [256]u8 = undefined;
        const v = std.fmt.bufPrint(&line, "<{s}>", .{r}) catch return error.LineTooLong;
        mime.writeRawHeader(w, "In-Reply-To", v, opts.mime) catch |e| return wrap(e);
    }
    if (msg.references.len != 0) {
        var f: mime.Folder = .init(w, opts.mime);
        f.raw("References:") catch |e| return wrap(e);
        for (msg.references) |r| {
            var line: [256]u8 = undefined;
            const v = std.fmt.bufPrint(&line, "<{s}>", .{r}) catch return error.LineTooLong;
            for (v) |c| if (c == '\r' or c == '\n' or c == 0) return error.ControlCharacterInHeader;
            f.token(v) catch |e| return wrap(e);
        }
        f.finishLine() catch |e| return wrap(e);
    }
    mime.writeUnstructured(w, "Subject", msg.subject, opts.mime) catch |e| return wrap(e);

    for (msg.headers) |h| {
        if (h.raw) {
            mime.writeRawHeader(w, h.name, h.value, opts.mime) catch |e| return wrap(e);
        } else {
            mime.writeUnstructured(w, h.name, h.value, opts.mime) catch |e| return wrap(e);
        }
    }

    mime.writeRawHeader(w, "MIME-Version", "1.0", opts.mime) catch |e| return wrap(e);
    w.writeAll(body.headers) catch return error.OutOfMemory;
    w.writeAll("\r\n") catch return error.OutOfMemory;
    w.writeAll(body.content) catch return error.OutOfMemory;
    // A message ends with a line break. Exactly one: a part whose content
    // already ends with CRLF must not gain a blank line.
    if (!std.mem.endsWith(u8, aw.written(), "\r\n")) w.writeAll("\r\n") catch return error.OutOfMemory;

    const out = try aw.toOwnedSlice();
    errdefer gpa.free(out);
    mime.checkLineLengths(out, opts.mime.max_line) catch return error.LineTooLong;
    return out;
}

fn writeAddrHeader(
    w: *std.Io.Writer,
    name: []const u8,
    list: []const mime.Address,
    opts: RenderOptions,
) RenderError!void {
    for (list) |a| {
        command.validateMailbox(a.addr, .{}, true) catch |e| return switch (e) {
            error.ControlCharacterInArgument => error.ControlCharacterInHeader,
            else => error.InvalidAddress,
        };
    }
    mime.writeAddressList(w, name, list, opts.mime) catch |e| return wrap(e);
}

fn generateMessageId(buf: []u8, random: std.Random, domain: []const u8) ![]const u8 {
    var raw: [16]u8 = undefined;
    random.bytes(&raw);
    var hex: [32]u8 = undefined;
    _ = std.fmt.bufPrint(&hex, "{x}", .{&raw}) catch unreachable;
    return std.fmt.bufPrint(buf, "{s}@{s}", .{ hex, domain });
}

// ── parts ──────────────────────────────────────────────────────────────────

fn renderPart(
    gpa: std.mem.Allocator,
    part: Part,
    random: std.Random,
    opts: RenderOptions,
    depth: usize,
) RenderError!Rendered {
    if (depth > opts.max_depth) return error.DepthExceeded;
    return switch (part) {
        .text => |t| renderText(gpa, t, opts),
        .attachment => |a| renderAttachment(gpa, a, opts),
        .multipart => |m| renderMultipart(gpa, m, random, opts, depth),
    };
}

/// `7bit` is only legal for a body that is ASCII, has no NUL and has no line
/// over the limit. Anything else gets quoted-printable, which is reversible for
/// arbitrary bytes.
fn autoTextEncoding(body: []const u8, max_line: usize) Encoding {
    var line: usize = 0;
    for (body) |c| {
        if (c == '\n') {
            line = 0;
            continue;
        }
        if (c == '\r') continue;
        if (c >= 0x80 or c == 0) return .quoted_printable;
        line += 1;
        if (line > max_line) return .quoted_printable;
    }
    return .seven_bit;
}

fn renderText(gpa: std.mem.Allocator, t: Text, opts: RenderOptions) RenderError!Rendered {
    const enc = t.encoding orelse autoTextEncoding(t.body, opts.mime.max_line);

    var hw: std.Io.Writer.Allocating = .init(gpa);
    errdefer hw.deinit();
    {
        var line: [512]u8 = undefined;
        const ct = std.fmt.bufPrint(&line, "text/{s}; charset=\"{s}\"", .{ t.subtype, t.charset }) catch return error.LineTooLong;
        mime.writeRawHeader(&hw.writer, "Content-Type", ct, opts.mime) catch |e| return wrap(e);
    }
    mime.writeRawHeader(&hw.writer, "Content-Transfer-Encoding", enc.text(), opts.mime) catch |e| return wrap(e);

    var cw: std.Io.Writer.Allocating = .init(gpa);
    errdefer cw.deinit();
    switch (enc) {
        .seven_bit, .eight_bit => mime.writeVerbatimCrlf(&cw.writer, t.body) catch return error.OutOfMemory,
        .quoted_printable => mime.writeQuotedPrintable(&cw.writer, t.body) catch return error.OutOfMemory,
        .base64 => mime.writeBase64(&cw.writer, t.body) catch return error.OutOfMemory,
    }
    return .{ .headers = try hw.toOwnedSlice(), .content = try cw.toOwnedSlice() };
}

fn renderAttachment(gpa: std.mem.Allocator, a: Attachment, opts: RenderOptions) RenderError!Rendered {
    const enc = a.encoding orelse .base64;
    for (a.filename) |c| {
        if (c == '\r' or c == '\n' or c == 0 or c == '"') return error.ControlCharacterInHeader;
    }

    var hw: std.Io.Writer.Allocating = .init(gpa);
    errdefer hw.deinit();
    {
        var line: [1024]u8 = undefined;
        var lw: std.Io.Writer = .fixed(&line);
        lw.writeAll(a.content_type) catch return error.LineTooLong;
        writeFilenameParam(&lw, "name", a.filename) catch return error.LineTooLong;
        mime.writeRawHeader(&hw.writer, "Content-Type", lw.buffered(), opts.mime) catch |e| return wrap(e);
    }
    mime.writeRawHeader(&hw.writer, "Content-Transfer-Encoding", enc.text(), opts.mime) catch |e| return wrap(e);
    {
        var line: [1024]u8 = undefined;
        var lw: std.Io.Writer = .fixed(&line);
        lw.writeAll(a.disposition.text()) catch return error.LineTooLong;
        writeFilenameParam(&lw, "filename", a.filename) catch return error.LineTooLong;
        mime.writeRawHeader(&hw.writer, "Content-Disposition", lw.buffered(), opts.mime) catch |e| return wrap(e);
    }
    if (a.content_id) |cid| {
        var line: [256]u8 = undefined;
        const v = std.fmt.bufPrint(&line, "<{s}>", .{cid}) catch return error.LineTooLong;
        for (v) |c| if (c == '\r' or c == '\n' or c == 0) return error.ControlCharacterInHeader;
        mime.writeRawHeader(&hw.writer, "Content-ID", v, opts.mime) catch |e| return wrap(e);
    }

    var cw: std.Io.Writer.Allocating = .init(gpa);
    errdefer cw.deinit();
    switch (enc) {
        .base64 => mime.writeBase64(&cw.writer, a.data) catch return error.OutOfMemory,
        .quoted_printable => mime.writeQuotedPrintable(&cw.writer, a.data) catch return error.OutOfMemory,
        .seven_bit, .eight_bit => mime.writeVerbatimCrlf(&cw.writer, a.data) catch return error.OutOfMemory,
    }
    return .{ .headers = try hw.toOwnedSlice(), .content = try cw.toOwnedSlice() };
}

/// A parameter that is plain ASCII goes out as `name="value"`; anything else
/// uses the RFC 2231 §4 extended syntax (`name*=UTF-8''pct-encoded`), which is
/// the standard answer and what Python's `email` module round-trips. An
/// encoded-word inside a parameter is common in the wild and illegal, so it is
/// not produced here.
fn writeFilenameParam(w: *std.Io.Writer, name: []const u8, value: []const u8) std.Io.Writer.Error!void {
    if (mime.isAscii(value) and std.mem.indexOfAny(u8, value, "\"\\;") == null) {
        try w.print("; {s}=\"{s}\"", .{ name, value });
        return;
    }
    try w.print("; {s}*=UTF-8''", .{name});
    for (value) |c| {
        const safe = switch (c) {
            'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => true,
            else => false,
        };
        if (safe) try w.writeByte(c) else try w.print("%{X:0>2}", .{c});
    }
}

fn renderMultipart(
    gpa: std.mem.Allocator,
    m: Multipart,
    random: std.Random,
    opts: RenderOptions,
    depth: usize,
) RenderError!Rendered {
    if (m.parts.len == 0) return error.EmptyMultipart;

    var kids: std.ArrayList(Rendered) = .empty;
    defer {
        for (kids.items) |*k| k.deinit(gpa);
        kids.deinit(gpa);
    }
    for (m.parts) |p| {
        var r = try renderPart(gpa, p, random, opts, depth + 1);
        errdefer r.deinit(gpa);
        try kids.append(gpa, r);
    }

    // Draw a boundary and CHECK it against every child's bytes (RFC 2046
    // §5.1.1). Redraw on collision; give up rather than emit a broken message.
    var boundary_buf: [96]u8 = undefined;
    const boundary = blk: {
        var attempt: usize = 0;
        while (attempt < opts.max_boundary_attempts) : (attempt += 1) {
            const cand = drawBoundary(&boundary_buf, random, opts) catch return error.BoundaryCollision;
            var clash = false;
            for (kids.items) |k| {
                if (std.mem.indexOf(u8, k.headers, cand) != null or
                    std.mem.indexOf(u8, k.content, cand) != null)
                {
                    clash = true;
                    break;
                }
            }
            if (!clash) break :blk cand;
        }
        return error.BoundaryCollision;
    };

    var hw: std.Io.Writer.Allocating = .init(gpa);
    errdefer hw.deinit();
    {
        var line: [256]u8 = undefined;
        const ct = std.fmt.bufPrint(&line, "multipart/{s}; boundary=\"{s}\"", .{ m.subtype.text(), boundary }) catch return error.LineTooLong;
        mime.writeRawHeader(&hw.writer, "Content-Type", ct, opts.mime) catch |e| return wrap(e);
    }

    var cw: std.Io.Writer.Allocating = .init(gpa);
    errdefer cw.deinit();
    const w = &cw.writer;
    for (kids.items) |k| {
        w.print("--{s}\r\n", .{boundary}) catch return error.OutOfMemory;
        w.writeAll(k.headers) catch return error.OutOfMemory;
        w.writeAll("\r\n") catch return error.OutOfMemory;
        w.writeAll(k.content) catch return error.OutOfMemory;
        // The CRLF that starts the next delimiter line belongs to the
        // delimiter, not to this part.
        w.writeAll("\r\n") catch return error.OutOfMemory;
    }
    w.print("--{s}--", .{boundary}) catch return error.OutOfMemory;

    return .{ .headers = try hw.toOwnedSlice(), .content = try cw.toOwnedSlice() };
}

/// `bchars` of RFC 2046 §5.1.1, ≤ 70 octets. base64url's alphabet is a subset,
/// so the random tail needs no further escaping.
fn drawBoundary(buf: []u8, random: std.Random, opts: RenderOptions) ![]const u8 {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
    const n = opts.boundary_prefix.len + opts.boundary_entropy;
    if (n > @min(buf.len, 70)) return error.NoSpaceLeft;
    @memcpy(buf[0..opts.boundary_prefix.len], opts.boundary_prefix);
    for (buf[opts.boundary_prefix.len..n]) |*c| c.* = alphabet[random.uintLessThan(u8, alphabet.len)];
    return buf[0..n];
}

// ── tests ──────────────────────────────────────────────────────────────────

fn fixedRandom(seed: u64) std.Random.DefaultPrng {
    return std.Random.DefaultPrng.init(seed);
}

const epoch_2026 = mime.DateTime{ .unix = 1784714400, .offset_minutes = 0 }; // Wed, 22 Jul 2026 10:00:00 +0000

test "a plain-text message renders to the byte-exact document we expect" {
    const gpa = testing.allocator;
    var prng = fixedRandom(1);
    const out = try render(gpa, .{
        .from = .{ .name = "Alice Example", .addr = "alice@example.com" },
        .to = &.{.{ .name = "Bob Example", .addr = "bob@example.net" }},
        .subject = "Hello",
        .date = epoch_2026,
        .message_id = "fixed-id@example.com",
        .body = .{ .text = .{ .body = "Hello, world.\r\n" } },
    }, prng.random(), .{});
    defer gpa.free(out);

    try testing.expectEqualStrings(
        "Date: Wed, 22 Jul 2026 10:00:00 +0000\r\n" ++
            "From: Alice Example <alice@example.com>\r\n" ++
            "To: Bob Example <bob@example.net>\r\n" ++
            "Message-ID: <fixed-id@example.com>\r\n" ++
            "Subject: Hello\r\n" ++
            "MIME-Version: 1.0\r\n" ++
            "Content-Type: text/plain; charset=\"utf-8\"\r\n" ++
            "Content-Transfer-Encoding: 7bit\r\n" ++
            "\r\n" ++
            "Hello, world.\r\n",
        out,
    );
}

test "the canonical body: a line that is exactly a period survives composition" {
    const gpa = testing.allocator;
    var prng = fixedRandom(2);
    const body = "first\r\n.\r\nlast\r\n";
    const out = try render(gpa, .{
        .from = .{ .addr = "a@example.com" },
        .to = &.{.{ .addr = "b@example.net" }},
        .date = epoch_2026,
        .message_id = "id@example.com",
        .body = .{ .text = .{ .body = body } },
    }, prng.random(), .{});
    defer gpa.free(out);
    // The composer does NOT dot-stuff — that is the DATA layer's job, and doing
    // it twice would deliver ".." to the recipient.
    try testing.expect(std.mem.endsWith(u8, out, "\r\n\r\nfirst\r\n.\r\nlast\r\n"));

    // Through the DATA layer it becomes "..", and comes back as ".".
    const dm = @import("data.zig");
    const wire = try dm.stuffAlloc(gpa, out, .{});
    defer gpa.free(wire);
    try testing.expect(std.mem.indexOf(u8, wire, "\r\n..\r\n") != null);
    const back = try dm.unstuffAlloc(gpa, wire, .{});
    defer gpa.free(back);
    try testing.expectEqualStrings(out, back);
}

test "non-ASCII text picks quoted-printable and non-ASCII headers are encoded" {
    const gpa = testing.allocator;
    var prng = fixedRandom(3);
    const out = try render(gpa, .{
        .from = .{ .name = "Přemysl Oráč", .addr = "premysl@example.com" },
        .to = &.{.{ .addr = "b@example.net" }},
        .subject = "Žluťoučký kůň",
        .date = epoch_2026,
        .message_id = "id@example.com",
        .body = .{ .text = .{ .body = "Příliš žluťoučký kůň úpěl ďábelské ódy.\r\n" } },
    }, prng.random(), .{});
    defer gpa.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "Content-Transfer-Encoding: quoted-printable") != null);
    try testing.expect(std.mem.indexOf(u8, out, "Subject: =?utf-8?") != null);
    try testing.expect(std.mem.indexOf(u8, out, "=C5=BElu=C5=A5ou=C4=8Dk=C3=BD") != null);
    // No raw high byte may remain anywhere in the document.
    for (out) |c| try testing.expect(c < 0x80);
    try mime.checkLineLengths(out, 998);
}

test "multipart/mixed with an attachment, and the boundary is not in any part" {
    const gpa = testing.allocator;
    var prng = fixedRandom(4);
    const out = try render(gpa, .{
        .from = .{ .addr = "a@example.com" },
        .to = &.{.{ .addr = "b@example.net" }},
        .subject = "With attachment",
        .date = epoch_2026,
        .message_id = "id@example.com",
        .body = .{ .multipart = .{ .subtype = .mixed, .parts = &.{
            .{ .text = .{ .body = "See attached.\r\n" } },
            .{ .attachment = .{
                .filename = "notes.txt",
                .content_type = "text/plain",
                .data = "attachment body\n",
            } },
        } } },
    }, prng.random(), .{});
    defer gpa.free(out);

    const b_start = std.mem.indexOf(u8, out, "boundary=\"").? + 10;
    const b_end = std.mem.indexOfScalarPos(u8, out, b_start, '"').?;
    const boundary = out[b_start..b_end];
    try testing.expect(std.mem.startsWith(u8, boundary, "=_zigsmtp_"));
    try testing.expectEqual(@as(usize, 3), std.mem.count(u8, out, boundary) - 1 + 1 - 1); // opener + 2 delimiters + closer counted below
    // Exactly: the Content-Type parameter, two "--b" delimiters and one "--b--".
    try testing.expectEqual(@as(usize, 4), std.mem.count(u8, out, boundary));
    try testing.expect(std.mem.indexOf(u8, out, "Content-Disposition: attachment; filename=\"notes.txt\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "Content-Transfer-Encoding: base64") != null);
    try testing.expect(std.mem.endsWith(u8, out, "--\r\n"));
    try mime.checkLineLengths(out, 998);
}

test "a boundary that collides with a part's content is redrawn" {
    const gpa = testing.allocator;
    // A deterministic RNG plus a body containing exactly what it will draw:
    // render once to learn the boundary, then embed it in the body and render
    // again with the same seed. The second render MUST NOT reuse it.
    var prng = fixedRandom(7);
    const first = try render(gpa, .{
        .from = .{ .addr = "a@example.com" },
        .date = epoch_2026,
        .message_id = "id@example.com",
        .body = .{ .multipart = .{ .parts = &.{
            .{ .text = .{ .body = "one\r\n" } },
            .{ .text = .{ .body = "two\r\n" } },
        } } },
    }, prng.random(), .{});
    defer gpa.free(first);
    const s = std.mem.indexOf(u8, first, "boundary=\"").? + 10;
    const e = std.mem.indexOfScalarPos(u8, first, s, '"').?;
    const drawn = try gpa.dupe(u8, first[s..e]);
    defer gpa.free(drawn);

    const poisoned = try std.fmt.allocPrint(gpa, "a body that quotes --{s} verbatim\r\n", .{drawn});
    defer gpa.free(poisoned);

    var prng2 = fixedRandom(7);
    const second = try render(gpa, .{
        .from = .{ .addr = "a@example.com" },
        .date = epoch_2026,
        .message_id = "id@example.com",
        .body = .{ .multipart = .{ .parts = &.{
            .{ .text = .{ .body = poisoned } },
            .{ .text = .{ .body = "two\r\n" } },
        } } },
    }, prng2.random(), .{});
    defer gpa.free(second);

    const s2 = std.mem.indexOf(u8, second, "boundary=\"").? + 10;
    const e2 = std.mem.indexOfScalarPos(u8, second, s2, '"').?;
    try testing.expect(!std.mem.eql(u8, drawn, second[s2..e2]));
    // The quoted text is still there, and the real delimiters use the new one.
    try testing.expect(std.mem.indexOf(u8, second, drawn) != null);
}

test "boundary redraw gives up rather than emitting a broken message" {
    const gpa = testing.allocator;
    // With zero entropy every draw is the same string, and a body containing it
    // can never be framed.
    var prng = fixedRandom(9);
    const r = render(gpa, .{
        .from = .{ .addr = "a@example.com" },
        .date = epoch_2026,
        .message_id = "id@example.com",
        .body = .{ .multipart = .{ .parts = &.{
            .{ .text = .{ .body = "contains =_zigsmtp_ inline\r\n" } },
            .{ .text = .{ .body = "two\r\n" } },
        } } },
    }, prng.random(), .{ .boundary_entropy = 0 });
    try testing.expectError(error.BoundaryCollision, r);
}

test "multipart/alternative nests inside multipart/mixed" {
    const gpa = testing.allocator;
    var prng = fixedRandom(5);
    const out = try render(gpa, .{
        .from = .{ .addr = "a@example.com" },
        .to = &.{.{ .addr = "b@example.net" }},
        .date = epoch_2026,
        .message_id = "id@example.com",
        .body = .{ .multipart = .{ .subtype = .mixed, .parts = &.{
            .{ .multipart = .{ .subtype = .alternative, .parts = &.{
                .{ .text = .{ .subtype = "plain", .body = "plain version\r\n" } },
                .{ .text = .{ .subtype = "html", .body = "<p>html version</p>\r\n" } },
            } } },
            .{ .attachment = .{ .filename = "a.bin", .data = &[_]u8{ 0, 1, 2, 3, 255 } } },
        } } },
    }, prng.random(), .{});
    defer gpa.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "multipart/mixed;") != null);
    try testing.expect(std.mem.indexOf(u8, out, "multipart/alternative;") != null);
    try testing.expect(std.mem.indexOf(u8, out, "text/html;") != null);
    // The two boundaries differ.
    const first_b = out[std.mem.indexOf(u8, out, "boundary=\"").? + 10 ..];
    const b1 = first_b[0..std.mem.indexOfScalar(u8, first_b, '"').?];
    const rest = first_b[std.mem.indexOf(u8, first_b, "boundary=\"").? + 10 ..];
    const b2 = rest[0..std.mem.indexOfScalar(u8, rest, '"').?];
    try testing.expect(!std.mem.eql(u8, b1, b2));
    try mime.checkLineLengths(out, 998);
}

test "an empty multipart and an over-deep tree are typed errors" {
    const gpa = testing.allocator;
    var prng = fixedRandom(6);
    try testing.expectError(error.EmptyMultipart, render(gpa, .{
        .from = .{ .addr = "a@example.com" },
        .date = epoch_2026,
        .body = .{ .multipart = .{ .parts = &.{} } },
    }, prng.random(), .{}));

    const leaf = Part{ .text = .{ .body = "x\r\n" } };
    const l1 = Part{ .multipart = .{ .parts = &.{leaf} } };
    const l2 = Part{ .multipart = .{ .parts = &.{l1} } };
    const l3 = Part{ .multipart = .{ .parts = &.{l2} } };
    try testing.expectError(error.DepthExceeded, render(gpa, .{
        .from = .{ .addr = "a@example.com" },
        .date = epoch_2026,
        .body = l3,
    }, prng.random(), .{ .max_depth = 1 }));
}

test "header injection through subject, display name or a custom header" {
    const gpa = testing.allocator;
    var prng = fixedRandom(8);
    const base = Message{
        .from = .{ .addr = "a@example.com" },
        .date = epoch_2026,
        .message_id = "id@example.com",
        .body = .{ .text = .{ .body = "x\r\n" } },
    };
    {
        var m = base;
        m.subject = "hi\r\nBcc: victim@example.net";
        try testing.expectError(error.ControlCharacterInHeader, render(gpa, m, prng.random(), .{}));
    }
    {
        var m = base;
        m.from = .{ .name = "A\r\nX: y", .addr = "a@example.com" };
        try testing.expectError(error.ControlCharacterInHeader, render(gpa, m, prng.random(), .{}));
    }
    {
        var m = base;
        m.headers = &.{.{ .name = "X-Thing", .value = "a\r\nX-Other: b" }};
        try testing.expectError(error.ControlCharacterInHeader, render(gpa, m, prng.random(), .{}));
    }
    {
        var m = base;
        m.from = .{ .addr = "a@example.com\r\nRCPT TO:<v@example.net>" };
        try testing.expectError(error.ControlCharacterInHeader, render(gpa, m, prng.random(), .{}));
    }
    {
        var m = base;
        m.from = .{ .addr = "not-an-address" };
        try testing.expectError(error.InvalidAddress, render(gpa, m, prng.random(), .{}));
    }
    {
        var m = base;
        m.body = .{ .attachment = .{ .filename = "a\r\nb.txt", .data = "x" } };
        try testing.expectError(error.ControlCharacterInHeader, render(gpa, m, prng.random(), .{}));
    }
}

test "Bcc never reaches the message unless the caller asks" {
    const gpa = testing.allocator;
    var prng = fixedRandom(10);
    const m = Message{
        .from = .{ .addr = "a@example.com" },
        .to = &.{.{ .addr = "b@example.net" }},
        .bcc = &.{.{ .addr = "secret@example.org" }},
        .date = epoch_2026,
        .message_id = "id@example.com",
        .body = .{ .text = .{ .body = "x\r\n" } },
    };
    const out = try render(gpa, m, prng.random(), .{});
    defer gpa.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "secret@example.org") == null);

    const with = try render(gpa, m, prng.random(), .{ .include_bcc = true });
    defer gpa.free(with);
    try testing.expect(std.mem.indexOf(u8, with, "Bcc: secret@example.org") != null);
}

test "a non-ASCII filename uses RFC 2231, not an illegal encoded word" {
    const gpa = testing.allocator;
    var prng = fixedRandom(11);
    const out = try render(gpa, .{
        .from = .{ .addr = "a@example.com" },
        .date = epoch_2026,
        .message_id = "id@example.com",
        .body = .{ .attachment = .{ .filename = "účtenka.pdf", .content_type = "application/pdf", .data = "%PDF-1.4\n" } },
    }, prng.random(), .{});
    defer gpa.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "filename*=UTF-8''%C3%BA%C4%8Dtenka.pdf") != null);
    try testing.expect(std.mem.indexOf(u8, out, "=?utf-8?") == null);
}

test "a generated Message-ID is random, well-formed and deterministic per seed" {
    const gpa = testing.allocator;
    const m = Message{
        .from = .{ .addr = "a@example.com" },
        .date = epoch_2026,
        .message_id_domain = "client.example.org",
        .body = .{ .text = .{ .body = "x\r\n" } },
    };
    var p1 = fixedRandom(42);
    const a = try render(gpa, m, p1.random(), .{});
    defer gpa.free(a);
    var p2 = fixedRandom(42);
    const b = try render(gpa, m, p2.random(), .{});
    defer gpa.free(b);
    var p3 = fixedRandom(43);
    const c = try render(gpa, m, p3.random(), .{});
    defer gpa.free(c);
    try testing.expectEqualStrings(a, b);
    try testing.expect(!std.mem.eql(u8, a, c));
    try testing.expect(std.mem.indexOf(u8, a, "@client.example.org>") != null);
}

test "a very long line in a 7bit-looking body forces an encoding that fits" {
    const gpa = testing.allocator;
    var prng = fixedRandom(12);
    const out = try render(gpa, .{
        .from = .{ .addr = "a@example.com" },
        .date = epoch_2026,
        .message_id = "id@example.com",
        .body = .{ .text = .{ .body = "A" ** 5000 ++ "\r\n" } },
    }, prng.random(), .{});
    defer gpa.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "Content-Transfer-Encoding: quoted-printable") != null);
    try mime.checkLineLengths(out, 998);
}

test "fuzz: any body and subject renders to a document that respects the limits" {
    try testing.fuzz({}, fuzzRender, .{});
}

fn fuzzRender(_: void, smith: *std.testing.Smith) !void {
    const gpa = testing.allocator;
    var raw: [400]u8 = undefined;
    smith.bytes(&raw);
    const n = smith.valueRangeAtMost(u16, 0, raw.len);
    const blob = raw[0..n];
    const split = if (blob.len == 0) 0 else smith.valueRangeAtMost(u16, 0, @intCast(blob.len));

    var prng = fixedRandom(smith.value(u64));
    const m = Message{
        .from = .{ .addr = "a@example.com" },
        .to = &.{.{ .addr = "b@example.net" }},
        .subject = blob[0..split],
        .date = .{ .unix = smith.value(i32) },
        .message_id = "id@example.com",
        .body = .{ .multipart = .{ .parts = &.{
            .{ .text = .{ .body = blob[split..] } },
            .{ .attachment = .{ .filename = "f.bin", .data = blob } },
        } } },
    };
    const out = render(gpa, m, prng.random(), .{}) catch return;
    defer gpa.free(out);
    try mime.checkLineLengths(out, 998);
    // The boundary must not appear inside the parts it delimits: count it.
    const s = std.mem.indexOf(u8, out, "boundary=\"").? + 10;
    const e = std.mem.indexOfScalarPos(u8, out, s, '"').?;
    const boundary = out[s..e];
    std.debug.assert(std.mem.count(u8, out, boundary) == 4);
}
