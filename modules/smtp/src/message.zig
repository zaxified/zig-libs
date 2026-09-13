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
/// value the caller has already structured (`List-Unsubscribe`, …) — folding
/// collapses runs of whitespace and re-breaks long values. `verbatim` values
/// are written exactly as given after `name:`, for bytes that must not change:
/// a DKIM signature produced elsewhere, whose `simple` canonicalization breaks
/// under any whitespace change (A1 F8). A verbatim value may be pre-folded, but
/// only as CRLF followed by SP or HTAB, and every line must fit the line limit.
pub const Header = struct {
    name: []const u8,
    value: []const u8,
    raw: bool = false,
    verbatim: bool = false,
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
/// F10: `RenderOptions.max_depth` bounds `renderPart`'s recursion, but the
/// field itself was unbounded — a caller (or a value forwarded from
/// untrusted config) could set it high enough to blow the stack before the
/// check on any one call ever fires. Measured (ReleaseFast): depth 12,288
/// still returns cleanly (~1.6 MB of stack), depth 16,384 segfaults. 512 is
/// two orders of magnitude under that crash boundary — room for legitimate
/// nesting on an 8 MB thread stack and still safe on a constrained one.
const max_safe_depth: usize = 512;

pub fn render(
    gpa: std.mem.Allocator,
    msg: Message,
    random: std.Random,
    opts: RenderOptions,
) RenderError![]u8 {
    if (opts.max_depth > max_safe_depth) return error.DepthExceeded;
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
        // F7: `id` (and `msg.message_id_domain`, folded into it by
        // `generateMessageId`) is routinely lifted out of a message this
        // library did not render, so a `<` or `>` inside it would splice in
        // a second msg-id (RFC 5322 §3.6.4 allows exactly one). CR/LF/NUL
        // are already `writeRawHeader`'s job; angle brackets are not.
        try checkNoAngleBrackets(id);
        var line: [256]u8 = undefined;
        const v = std.fmt.bufPrint(&line, "<{s}>", .{id}) catch return error.LineTooLong;
        mime.writeRawHeader(w, "Message-ID", v, opts.mime) catch |e| return wrap(e);
    }
    if (msg.in_reply_to) |r| {
        try checkNoAngleBrackets(r);
        var line: [256]u8 = undefined;
        const v = std.fmt.bufPrint(&line, "<{s}>", .{r}) catch return error.LineTooLong;
        mime.writeRawHeader(w, "In-Reply-To", v, opts.mime) catch |e| return wrap(e);
    }
    if (msg.references.len != 0) {
        var f: mime.Folder = .init(w, opts.mime);
        f.raw("References:") catch |e| return wrap(e);
        for (msg.references) |r| {
            try checkNoAngleBrackets(r);
            var line: [256]u8 = undefined;
            const v = std.fmt.bufPrint(&line, "<{s}>", .{r}) catch return error.LineTooLong;
            for (v) |c| if (c == '\r' or c == '\n' or c == 0) return error.ControlCharacterInHeader;
            f.token(v) catch |e| return wrap(e);
        }
        f.finishLine() catch |e| return wrap(e);
    }
    mime.writeUnstructured(w, "Subject", msg.subject, opts.mime) catch |e| return wrap(e);

    for (msg.headers) |h| {
        if (h.verbatim) {
            mime.writeVerbatimHeader(w, h.name, h.value, opts.mime) catch |e| return wrap(e);
        } else if (h.raw) {
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

/// Shared by every parameter that lands inside a **quoted** header value
/// (`charset="…"`, `boundary="…"`, `Content-Type: …` itself): a bare `"` lets
/// the caller's value close the quote early and append parameters the caller
/// never asked for (F4 — `~/CML/20260901-zig-libs-audit/A1/smtp.md`), on top
/// of the CR/LF/NUL header-injection check every other field already gets.
fn checkQuotedParam(s: []const u8) RenderError!void {
    for (s) |c| if (c == '\r' or c == '\n' or c == 0 or c == '"') return error.ControlCharacterInHeader;
}

/// F4 sibling for the `<{s}>` shape (`Message-ID`, `In-Reply-To`,
/// `References`, `Content-ID`): a `<` or `>` inside the caller's value lets
/// it close the angle bracket early and append a second msg-id. CR/LF/NUL
/// are covered separately, by `writeRawHeader` or a field-local check.
fn checkNoAngleBrackets(s: []const u8) RenderError!void {
    for (s) |c| if (c == '<' or c == '>') return error.ControlCharacterInHeader;
}

fn renderText(gpa: std.mem.Allocator, t: Text, opts: RenderOptions) RenderError!Rendered {
    const enc = t.encoding orelse autoTextEncoding(t.body, opts.mime.max_line);
    try checkQuotedParam(t.subtype);
    try checkQuotedParam(t.charset);

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
    // F4: `content_type` is written UNQUOTED (it is the media type itself,
    // not a parameter value), so a caller-controlled `"` or `;` does not
    // even need to break out of anything — it lands as a second parameter
    // directly. `filename` already gets this same class of check.
    for (a.content_type) |c| {
        if (c == '\r' or c == '\n' or c == 0 or c == '"' or c == ';') return error.ControlCharacterInHeader;
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
        try checkNoAngleBrackets(cid);
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

test "F10: an unbounded max_depth itself is refused, not just the recursion it would allow" {
    const gpa = testing.allocator;
    var prng = fixedRandom(6);
    const m = Message{
        .from = .{ .addr = "a@example.com" },
        .date = epoch_2026,
        .body = .{ .text = .{ .body = "x\r\n" } },
    };
    try testing.expectError(error.DepthExceeded, render(gpa, m, prng.random(), .{ .max_depth = 1 << 30 }));
    // Positive control: the default and a generous-but-bounded value work.
    const out = try render(gpa, m, prng.random(), .{ .max_depth = max_safe_depth });
    gpa.free(out);
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
    // message_id, in_reply_to and references are as caller-controlled as
    // subject or a custom header (an In-Reply-To is routinely built from a
    // Message-ID lifted out of an incoming message this library did not
    // render), but unlike every other field above, nothing exercised
    // injecting through them until now — message_id/in_reply_to rely
    // entirely on `writeRawHeader`'s internal check, with no field-local
    // backstop the way references/filename/content_id have.
    {
        var m = base;
        m.message_id = "a\r\nX-Injected: yes";
        try testing.expectError(error.ControlCharacterInHeader, render(gpa, m, prng.random(), .{}));
    }
    {
        var m = base;
        m.in_reply_to = "a\r\nX-Injected: yes";
        try testing.expectError(error.ControlCharacterInHeader, render(gpa, m, prng.random(), .{}));
    }
    {
        var m = base;
        m.references = &.{"a\r\nX-Injected: yes"};
        try testing.expectError(error.ControlCharacterInHeader, render(gpa, m, prng.random(), .{}));
    }
    // F7: `<`/`>` in the four fields interpolated into `<{s}>` splice in a
    // second msg-id, without needing CR/LF at all.
    {
        var m = base;
        m.message_id = "a@x.test> <victim@y.test";
        try testing.expectError(error.ControlCharacterInHeader, render(gpa, m, prng.random(), .{}));
    }
    {
        var m = base;
        m.in_reply_to = "a@x.test> <victim@y.test";
        try testing.expectError(error.ControlCharacterInHeader, render(gpa, m, prng.random(), .{}));
    }
    {
        var m = base;
        m.references = &.{"a@x.test> <victim@y.test"};
        try testing.expectError(error.ControlCharacterInHeader, render(gpa, m, prng.random(), .{}));
    }
    {
        var m = base;
        m.body = .{ .attachment = .{ .filename = "a.txt", .content_id = "a@x.test> <victim@y.test", .data = "x" } };
        try testing.expectError(error.ControlCharacterInHeader, render(gpa, m, prng.random(), .{}));
    }
    // Positive control: a legitimate message-id round-trips (this is what
    // the check above must NOT reject).
    {
        var m = base;
        m.message_id = "clean-id@x.test";
        const out = try render(gpa, m, prng.random(), .{});
        gpa.free(out);
    }
}

test "F4: MIME parameter injection through subtype, charset or content_type" {
    const gpa = testing.allocator;
    var prng = fixedRandom(8);
    const base = Message{
        .from = .{ .addr = "a@example.com" },
        .date = epoch_2026,
        .message_id = "id@example.com",
        .body = .{ .text = .{ .body = "x\r\n" } },
    };
    // `charset = 'x"; boundary="B'` used to widen `Content-Type: text/plain;
    // charset="x"; boundary="B"` with an attacker-chosen parameter.
    {
        var m = base;
        m.body = .{ .text = .{ .charset = "x\"; boundary=\"B", .body = "x\r\n" } };
        try testing.expectError(error.ControlCharacterInHeader, render(gpa, m, prng.random(), .{}));
    }
    {
        var m = base;
        m.body = .{ .text = .{ .subtype = "a; charset=\"evil\"", .body = "x\r\n" } };
        try testing.expectError(error.ControlCharacterInHeader, render(gpa, m, prng.random(), .{}));
    }
    {
        var m = base;
        m.body = .{ .attachment = .{ .filename = "f", .content_type = "x\"; boundary=\"B", .data = "x" } };
        try testing.expectError(error.ControlCharacterInHeader, render(gpa, m, prng.random(), .{}));
    }
    {
        var m = base;
        m.body = .{ .attachment = .{ .filename = "f", .content_type = "application/pdf; evil=1", .data = "x" } };
        try testing.expectError(error.ControlCharacterInHeader, render(gpa, m, prng.random(), .{}));
    }
    // Positive control: ordinary values still render.
    {
        var m = base;
        m.body = .{ .text = .{ .subtype = "plain", .charset = "utf-8", .body = "x\r\n" } };
        const out = try render(gpa, m, prng.random(), .{});
        gpa.free(out);
    }
    {
        var m = base;
        m.body = .{ .attachment = .{ .filename = "f.pdf", .content_type = "application/pdf", .data = "x" } };
        const out = try render(gpa, m, prng.random(), .{});
        gpa.free(out);
    }
}

test "a verbatim header keeps its bytes; raw still folds; injection and long lines are refused (A1 F8)" {
    const gpa = testing.allocator;
    const sig = "v=1; a=rsa-sha256;  c=simple/simple;\td=example.com;\r\n\tb=AbC";
    var prng = fixedRandom(1);
    const doc = try render(gpa, .{
        .from = .{ .addr = "a@example.com" },
        .date = epoch_2026,
        .message_id = "id@example.com",
        .headers = &.{.{ .name = "DKIM-Signature", .value = sig, .verbatim = true }},
        .body = .{ .text = .{ .body = "hi\r\n" } },
    }, prng.random(), .{});
    defer gpa.free(doc);
    try testing.expect(std.mem.indexOf(u8, doc, "\r\nDKIM-Signature:" ++ sig ++ "\r\n") != null);

    // Positive control: the same value as `raw` is folded and its whitespace collapsed.
    var prng2 = fixedRandom(1);
    const folded = try render(gpa, .{
        .from = .{ .addr = "a@example.com" },
        .date = epoch_2026,
        .message_id = "id@example.com",
        .headers = &.{.{ .name = "DKIM-Signature", .value = "v=1;  c=simple/simple;", .raw = true }},
        .body = .{ .text = .{ .body = "hi\r\n" } },
    }, prng2.random(), .{});
    defer gpa.free(folded);
    try testing.expect(std.mem.indexOf(u8, folded, "v=1;  c=") == null);

    const bad = [_][]const u8{
        "v=1\r\nBcc: victim@example.net", // CRLF not followed by WSP: injection
        "v=1\nb=x", // bare LF
        "v=1\rb=x", // bare CR
        "v=1\x00", // NUL
    };
    for (bad) |v| {
        var p = fixedRandom(1);
        try testing.expectError(error.ControlCharacterInHeader, render(gpa, .{
            .from = .{ .addr = "a@example.com" },
            .date = epoch_2026,
            .message_id = "id@example.com",
            .headers = &.{.{ .name = "X-V", .value = v, .verbatim = true }},
            .body = .{ .text = .{ .body = "hi\r\n" } },
        }, p.random(), .{}));
    }
    var p = fixedRandom(1);
    const long = [_]u8{'b'} ** 1000;
    try testing.expectError(error.LineTooLong, render(gpa, .{
        .from = .{ .addr = "a@example.com" },
        .date = epoch_2026,
        .message_id = "id@example.com",
        .headers = &.{.{ .name = "X-V", .value = &long, .verbatim = true }},
        .body = .{ .text = .{ .body = "hi\r\n" } },
    }, p.random(), .{}));
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

/// A corpus entry carrying `blob`, plus a 24-octet tail for the three draws
/// the harness takes AFTER the blob: the subject/body split point, the PRNG
/// seed, and the date.
///
/// ⚠ `testkit.fuzz.seed` would be wrong here and silently so. A seed whose
/// frame ends exactly where `Smith.slice` stops leaves the input EXHAUSTED,
/// and every draw after that returns its weight minimum -- so `split` would be
/// 0 for every seed in the corpus and the subject would always be empty, in a
/// harness whose whole point is "any body AND subject". The eight octets after
/// the frame are what `valueRangeAtMost` reads as a little-endian u64; the
/// sixteen after those feed `value(u64)` and `value(i32)`.
///
/// ⛔ Those last sixteen octets used to be `[_]u8{0} ** 16` on every seed — a
/// tail that exists is not a tail that carries anything. So the PRNG seed was
/// 0 for all ten seeds, meaning the MIME boundary was the SAME string every
/// time and the harness's `count(boundary) == 4` assertion had only ever been
/// evaluated against one boundary; and `date.unix` was 0 for all ten, so the
/// Date header was 1970-01-01T00:00:00Z on every render and no pre-epoch or
/// late date was ever formatted. Both are spelled out per seed now.
///
/// ⚠ `unix` is drawn with `value(i32)`, which reads eight octets as a
/// little-endian u64 and falls back to 0 when the value is outside the type's
/// weight range. The word therefore has to be the ZERO-EXTENDED 32-bit
/// pattern, not the sign-extended one: `@as(u64, @as(u32, @bitCast(unix)))`.
fn seedSplit(
    comptime blob: []const u8,
    comptime split: u64,
    comptime prng_seed: u64,
    comptime unix: i32,
) []const u8 {
    return &struct {
        const bytes = std.mem.toBytes(@as(u32, @intCast(blob.len))) ++
            blob[0..blob.len].* ++
            std.mem.toBytes(split) ++
            std.mem.toBytes(prng_seed) ++
            std.mem.toBytes(@as(u64, @as(u32, @bitCast(unix))));
    }.bytes;
}

/// Subject-plus-body blobs, in the format `Smith.slice` reads, each with the
/// split point that decides how much of it becomes the Subject header.
const render_seeds = [_][]const u8{
    seedSplit("Hello, worldThis is the body text.", 12, 0x9E37_79B9_7F4A_7C15, 1_767_225_600), // an ordinary ASCII message, 2026-01-01
    seedSplit("žluťoučký kůňpříliš dlouhý text", 15, 0x0123_4567_89AB_CDEF, -1), // a non-ASCII subject (forces an RFC 2047 encoded word), one second before the epoch
    seedSplit("A" ** 400, 200, 0xF0E1_D2C3_B4A5_9687, std.math.maxInt(i32)), // exactly the harness buffer, split down the middle, the 2038 edge
    seedSplit("A" ** 400, 0, 0xFFFF_FFFF_FFFF_FFFF, std.math.minInt(i32)), // the same with no subject at all, the 1901 edge
    seedSplit("Subject line\r\n\r\nBody text\r\n", 12, 0x6C62_1F4D_3A98_5E27, 0), // a subject with CRLF right behind it in the body, the epoch itself
    seedSplit("\r\n" ** 50, 20, 0x2468_ACE0_1357_9BDF, 951_782_400), // nothing but line breaks, 2000-02-29 (a leap day)
    seedSplit("=" ** 200, 100, 0x1357_9BDF_2468_ACE0, 1_000_000_000), // every octet quoted-printable must escape
    seedSplit("." ** 100, 40, 0x5A5A_5A5A_A5A5_A5A5, -2_147_483_648 + 1), // leading dots, which the transport layer will stuff
    seedSplit("\x00" ** 32, 16, 0x0000_0000_0000_0001, 86_399), // NULs: the subject must be refused, not smuggled
    seedSplit(" " ** 200, 100, 0xDEAD_BEEF_CAFE_F00D, -86_400), // nothing but fold points, one day before the epoch
};

test "fuzz: any body and subject renders to a document that respects the limits" {
    try testing.fuzz({}, fuzzRender, .{ .corpus = &render_seeds });
}

fn fuzzRender(_: void, smith: *std.testing.Smith) !void {
    const gpa = testing.allocator;
    var raw: [400]u8 = undefined;
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
    // length. `bytes` takes `@min(raw.len, in.len)` octets and the ranged draw
    // then finds fewer than the eight it needs and returns the range MINIMUM,
    // so `n` was 0 for every seed and `render` was handed an empty subject AND
    // an empty body, with the seed sitting unread in `raw`.
    const n = smith.slice(&raw);
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

test "corpus: every render seed reaches the renderer, and the counts are pinned" {
    // ⭐ The measurement, executable rather than written in a comment. A seed
    // longer than the harness's buffer reads back EMPTY (`Smith.slice` falls
    // back to the range minimum), which is silent everywhere else.
    //
    // The second count is the one that guards `seedSplit`'s tail: it is how
    // many seeds actually put something in the Subject. Written with a plain
    // `testkit.fuzz.seed` it would be 0 -- the split draw would find no input
    // left and return its range minimum -- and nothing else in the suite would
    // notice that half of "any body and subject" had gone missing.
    const gpa = testing.allocator;
    var nonempty: usize = 0;
    var rendered: usize = 0;
    var subject_nonempty: usize = 0;
    // The two knobs behind the split. `boundaries` is the count of DISTINCT
    // MIME boundaries the corpus produces: with the old all-zero tail the PRNG
    // seed was 0 on every seed and this was 1, so the harness's
    // `count(boundary) == 4` assertion had only ever met one boundary string.
    var boundaries: std.StringHashMapUnmanaged(void) = .empty;
    defer boundaries.deinit(gpa);
    var pre_epoch: usize = 0;
    for (render_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var raw: [400]u8 = undefined;
        const n = smith.slice(&raw);
        if (n != 0) nonempty += 1;
        const blob = raw[0..n];
        const split = if (blob.len == 0) 0 else smith.valueRangeAtMost(u16, 0, @intCast(blob.len));
        if (split != 0) subject_nonempty += 1;
        var prng = fixedRandom(smith.value(u64));
        const unix = smith.value(i32);
        if (unix < 0) pre_epoch += 1;
        const m = Message{
            .from = .{ .addr = "a@example.com" },
            .to = &.{.{ .addr = "b@example.net" }},
            .subject = blob[0..split],
            .date = .{ .unix = unix },
            .message_id = "id@example.com",
            .body = .{ .multipart = .{ .parts = &.{
                .{ .text = .{ .body = blob[split..] } },
                .{ .attachment = .{ .filename = "f.bin", .data = blob } },
            } } },
        };
        if (render(gpa, m, prng.random(), .{})) |out| {
            defer gpa.free(out);
            rendered += 1;
            const bs = std.mem.indexOf(u8, out, "boundary=\"").? + 10;
            const be = std.mem.indexOfScalarPos(u8, out, bs, '"').?;
            if (!boundaries.contains(out[bs..be])) {
                const owned = try gpa.dupe(u8, out[bs..be]);
                errdefer gpa.free(owned);
                try boundaries.put(gpa, owned, {});
            }
        } else |_| {}
    }
    defer {
        var it = boundaries.keyIterator();
        while (it.next()) |k| gpa.free(k.*);
    }
    try testing.expectEqual(render_seeds.len, nonempty);
    // Measured 2026-09-07: 0 of 10 seeds non-empty before the draw was fixed
    // and `render` only ever saw an empty subject and an empty body; 10 of 10
    // after.
    try testing.expectEqual(@as(usize, 8), rendered);
    try testing.expectEqual(@as(usize, 9), subject_nonempty);
    // Measured 2026-09-08. With the old all-zero 16-octet tail these were 1 and
    // 0: one boundary string for the whole corpus and not a single pre-epoch
    // date. ⛔ Not `> 1` — the count is what notices a seed losing its tail.
    try testing.expectEqual(@as(usize, 8), boundaries.count());
    try testing.expectEqual(@as(usize, 4), pre_epoch);
}
