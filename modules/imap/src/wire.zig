// SPDX-License-Identifier: MIT

//! The IMAP wire grammar (RFC 9051 §9), decode side, as seen by a **client**:
//! atoms, quoted strings, literals, `NIL`, numbers, and parenthesised lists.
//!
//! This is the layer every response body is built out of. It reads from a
//! `std.Io.Reader`, so the caller decides what is underneath — a TCP socket, a
//! TLS stream, or a fixed buffer in a test.
//!
//! Ported from `emersion/go-imap` v2 `internal/imapwire/decoder.go` (MIT — see
//! `modules/imap/NOTICE`), including its tolerances for what real servers
//! actually send. Divergences are listed at the bottom of this file.
//!
//! ## Two things worth knowing before reading further
//!
//! **We are the client, so a literal is never non-synchronising.** `{123+}`
//! is a client-to-server construct (RFC 7888): it lets a client send a literal
//! without waiting for the server's `+` continuation. A server never sends one,
//! and go-imap only accepts it when decoding as a *server*. Accepting it here
//! would mean accepting a frame no legitimate peer produces.
//!
//! **A literal's length arrives from the network and is used to allocate.**
//! That is the shape behind three of this repo's real bugs (`raft`, `df-elect`,
//! `threshold_ecdsa`), so it is capped by `Options.max_literal` and the cap is
//! checked *before* the allocation, not after.

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const utf7 = @import("utf7.zig");

pub const Error = error{
    /// A byte that cannot appear where it appeared.
    UnexpectedByte,
    /// A number that is not a number, or does not fit its type.
    BadNumber,
    /// A literal whose announced size exceeds `Options.max_literal`.
    LiteralTooLarge,
    /// More nested lists than `Options.max_depth`.
    DepthExceeded,
    /// A server sent `{123+}`, which only a client may send.
    NonSyncLiteral,
    InvalidUtf7,
    InvalidUtf8,
    ReadFailed,
    EndOfStream,
    OutOfMemory,
};

pub const Options = struct {
    /// Largest literal accepted, in bytes. A `FETCH` of a whole message is the
    /// legitimate reason this is not small; the point of the cap is that a
    /// server cannot name a size we then try to allocate.
    max_literal: u32 = 8 << 20,
    /// Nesting limit for parenthesised lists. `BODYSTRUCTURE` of a deeply
    /// nested multipart is the legitimate reason this is not 8; the point is
    /// that recursion is bounded. Matches go-imap's `maxListDepth`.
    max_depth: usize = 1000,
};

/// True for RFC 9051 `ATOM-CHAR`: anything but the specials and CTLs.
pub fn isAtomChar(ch: u8) bool {
    return switch (ch) {
        '(', ')', '{', ' ', '%', '*', '"', '\\', ']' => false,
        else => !std.ascii.isControl(ch),
    };
}

/// `ASTRING-CHAR` — `ATOM-CHAR` plus `]`, because unquoted mailbox names in
/// the wild contain it.
pub fn isAstringChar(ch: u8) bool {
    return isAtomChar(ch) or ch == ']';
}

/// Decodes IMAP data from `r`. Strings are allocated from `gpa`; the intended
/// use is an arena reset once per response, so nothing here frees individually.
pub const Decoder = struct {
    r: *std.Io.Reader,
    gpa: Allocator,
    opts: Options = .{},
    depth: usize = 0,

    pub fn init(gpa: Allocator, r: *std.Io.Reader, opts: Options) Decoder {
        return .{ .r = r, .gpa = gpa, .opts = opts };
    }

    // ── bytes ───────────────────────────────────────────────────────────────

    /// Consume `ch` if it is next.
    pub fn accept(d: *Decoder, ch: u8) Error!bool {
        const got = d.r.peekByte() catch |e| return mapRead(e);
        if (got != ch) return false;
        d.r.toss(1);
        return true;
    }

    pub fn expect(d: *Decoder, ch: u8) Error!void {
        if (!try d.accept(ch)) return error.UnexpectedByte;
    }

    /// The field separator, with go-imap's two tolerances for real servers:
    ///
    ///   * a space directly before CRLF is trailing whitespace, not a
    ///     separator — some servers emit one (go-imap issue 571). **The space
    ///     is still consumed**, which is what lets `crlf` succeed after this
    ///     returns false;
    ///   * a missing space is accepted when the next field is a parenthesised
    ///     list, which some servers omit.
    pub fn sp(d: *Decoder) Error!bool {
        if (try d.accept(' ')) {
            const next = d.r.peekByte() catch |e| return mapRead(e);
            return next != '\r' and next != '\n';
        }
        const next = d.r.peekByte() catch |e| return mapRead(e);
        return next == '(';
    }

    pub fn expectSp(d: *Decoder) Error!void {
        if (!try d.sp()) return error.UnexpectedByte;
    }

    /// End of line. Tolerates a leading space (go-imap issue 540) and a lone
    /// LF, because both appear in the wild; requires the LF.
    pub fn crlf(d: *Decoder) Error!bool {
        _ = try d.accept(' ');
        _ = try d.accept('\r');
        return d.accept('\n');
    }

    pub fn expectCrlf(d: *Decoder) Error!void {
        if (!try d.crlf()) return error.UnexpectedByte;
    }

    // ── atoms, strings, numbers ─────────────────────────────────────────────

    /// A run of bytes satisfying `valid`, or null if the first byte does not.
    pub fn run(d: *Decoder, valid: *const fn (u8) bool) Error!?[]const u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(d.gpa);
        while (true) {
            const ch = d.r.peekByte() catch |e| switch (e) {
                error.EndOfStream => break, // a run may end the stream
                else => return mapRead(e),
            };
            if (!valid(ch)) break;
            d.r.toss(1);
            try out.append(d.gpa, ch);
        }
        if (out.items.len == 0) return null;
        return try out.toOwnedSlice(d.gpa);
    }

    pub fn atom(d: *Decoder) Error!?[]const u8 {
        return d.run(isAtomChar);
    }

    pub fn expectAtom(d: *Decoder) Error![]const u8 {
        return (try d.atom()) orelse error.UnexpectedByte;
    }

    /// Everything up to (not including) the end of the line.
    pub fn text(d: *Decoder) Error!?[]const u8 {
        return d.run(struct {
            fn f(ch: u8) bool {
                return ch != '\r' and ch != '\n';
            }
        }.f);
    }

    /// A quoted string, unescaping `\"` and `\\`.
    pub fn quoted(d: *Decoder) Error!?[]const u8 {
        if (!try d.accept('"')) return null;
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(d.gpa);
        while (true) {
            var ch = d.r.takeByte() catch |e| return mapRead(e);
            if (ch == '"') break;
            if (ch == '\\') ch = d.r.takeByte() catch |e| return mapRead(e);
            try out.append(d.gpa, ch);
        }
        return try out.toOwnedSlice(d.gpa);
    }

    /// A literal: `{n}` CRLF followed by exactly n bytes.
    pub fn literal(d: *Decoder) Error!?[]const u8 {
        if (!try d.accept('{')) return null;

        const size = (try d.number()) orelse return error.BadNumber;
        // Only a client may announce a non-synchronising literal; a server
        // saying `{n+}` is malformed, not merely unusual.
        if (try d.accept('+')) return error.NonSyncLiteral;
        try d.expect('}');
        try d.expectCrlf();

        // Checked BEFORE the allocation: the size came off the wire.
        if (size > d.opts.max_literal) return error.LiteralTooLarge;

        const buf = try d.gpa.alloc(u8, size);
        errdefer d.gpa.free(buf);
        const got = d.r.readSliceShort(buf) catch |e| return mapRead(e);
        if (got != size) return error.EndOfStream;
        return buf;
    }

    /// `string` = quoted / literal.
    pub fn string(d: *Decoder) Error!?[]const u8 {
        if (try d.quoted()) |s| return s;
        return d.literal();
    }

    pub fn expectString(d: *Decoder) Error![]const u8 {
        return (try d.string()) orelse error.UnexpectedByte;
    }

    /// `astring` = string / ASTRING-CHAR run. Unquoted mailbox names take the
    /// second form, which is why `]` is allowed in it.
    pub fn expectAstring(d: *Decoder) Error![]const u8 {
        if (try d.string()) |s| return s;
        return (try d.run(isAstringChar)) orelse error.UnexpectedByte;
    }

    /// `nstring` = string / NIL. Returns null for NIL.
    pub fn expectNString(d: *Decoder) Error!?[]const u8 {
        if (try d.atom()) |a| {
            defer d.gpa.free(a);
            if (!std.ascii.eqlIgnoreCase(a, "NIL")) return error.UnexpectedByte;
            return null;
        }
        return try d.expectString();
    }

    pub fn number(d: *Decoder) Error!?u32 {
        const digits = (try d.run(std.ascii.isDigit)) orelse return null;
        defer d.gpa.free(digits);
        return std.fmt.parseInt(u32, digits, 10) catch error.BadNumber;
    }

    pub fn expectNumber(d: *Decoder) Error!u32 {
        return (try d.number()) orelse error.BadNumber;
    }

    pub fn number64(d: *Decoder) Error!?i64 {
        const digits = (try d.run(std.ascii.isDigit)) orelse return null;
        defer d.gpa.free(digits);
        return std.fmt.parseInt(i64, digits, 10) catch error.BadNumber;
    }

    /// `body-fld-octets`, with go-imap's workaround for servers that answer
    /// `-1` (issue 534). Reported as 0 rather than rejected, because the
    /// alternative is failing a whole FETCH over a size field.
    pub fn expectBodyFldOctets(d: *Decoder) Error!u32 {
        if (try d.accept('-')) {
            try d.expect('1');
            return 0;
        }
        return d.expectNumber();
    }

    // ── lists ───────────────────────────────────────────────────────────────

    /// Iterator over a parenthesised list. `next` returns true once per
    /// element; the caller parses the element between calls.
    pub const List = struct {
        d: *Decoder,
        started: bool = false,
        finished: bool = false,

        pub fn next(l: *List) Error!bool {
            if (l.finished) return false;
            if (!l.started) {
                l.started = true;
                if (try l.d.accept(')')) {
                    l.close();
                    return false; // "()"
                }
                return true;
            }
            if (try l.d.accept(')')) {
                l.close();
                return false;
            }
            try l.d.expectSp();
            return true;
        }

        fn close(l: *List) void {
            l.finished = true;
            l.d.depth -= 1;
        }
    };

    /// Begin a list if `(` is next.
    pub fn maybeList(d: *Decoder) Error!?List {
        if (!try d.accept('(')) return null;
        d.depth += 1;
        if (d.depth >= d.opts.max_depth) {
            d.depth -= 1;
            return error.DepthExceeded;
        }
        return List{ .d = d };
    }

    pub fn expectList(d: *Decoder) Error!List {
        return (try d.maybeList()) orelse error.UnexpectedByte;
    }

    // ── mailbox names ───────────────────────────────────────────────────────

    /// A mailbox name: an astring, modified-UTF-7-decoded, with `INBOX`
    /// case-folded to its canonical spelling (RFC 9051 §5.1 — INBOX is the one
    /// name that is case-insensitive).
    pub fn expectMailbox(d: *Decoder) Error![]const u8 {
        const raw = try d.expectAstring();
        if (std.ascii.eqlIgnoreCase(raw, "INBOX")) {
            d.gpa.free(raw);
            return try d.gpa.dupe(u8, "INBOX");
        }
        defer d.gpa.free(raw);
        return utf7.decodeAlloc(d.gpa, raw) catch |e| switch (e) {
            error.InvalidUtf7 => error.InvalidUtf7,
            error.InvalidUtf8 => error.InvalidUtf8,
            error.OutOfMemory => error.OutOfMemory,
        };
    }

    // ── skipping ────────────────────────────────────────────────────────────

    /// Consume one value of any shape without interpreting it — how a client
    /// stays in sync across an extension it does not implement.
    pub fn discardValue(d: *Decoder) Error!void {
        if (try d.string()) |s| {
            d.gpa.free(s);
            return;
        }
        if (try d.maybeList()) |l| {
            var it = l;
            while (try it.next()) try d.discardValue();
            return;
        }
        if (try d.atom()) |a| {
            d.gpa.free(a);
            return;
        }
        return error.UnexpectedByte;
    }

    /// Consume the rest of the line, including its CRLF.
    pub fn discardLine(d: *Decoder) Error!void {
        if (try d.text()) |t| d.gpa.free(t);
        _ = try d.crlf();
    }
};

fn mapRead(e: std.Io.Reader.Error) Error {
    return switch (e) {
        error.EndOfStream => error.EndOfStream,
        error.ReadFailed => error.ReadFailed,
    };
}

// ── tests ───────────────────────────────────────────────────────────────────

fn decoderOver(gpa: Allocator, r: *std.Io.Reader) Decoder {
    return Decoder.init(gpa, r, .{});
}

test "atom, and where an atom stops" {
    const gpa = testing.allocator;
    var r = std.Io.Reader.fixed("IMAP4rev2 (\\Seen)");
    var d = decoderOver(gpa, &r);

    const a = try d.expectAtom();
    defer gpa.free(a);
    try testing.expectEqualStrings("IMAP4rev2", a);

    // A space is not an atom char, so the atom ended without consuming it.
    try testing.expect(try d.sp());
    // '(' is not an atom char either.
    try testing.expect((try d.atom()) == null);
}

test "quoted string: escapes, and only the two that exist" {
    const gpa = testing.allocator;
    var r = std.Io.Reader.fixed("\"a\\\"b\\\\c\"");
    var d = decoderOver(gpa, &r);
    const s = (try d.quoted()).?;
    defer gpa.free(s);
    try testing.expectEqualStrings("a\"b\\c", s);
}

test "literal: RFC 9051 §7.5.2 shape" {
    const gpa = testing.allocator;
    // The example from the RFC's FETCH response, shortened.
    var r = std.Io.Reader.fixed("{12}\r\nHello there\n");
    var d = decoderOver(gpa, &r);
    const s = (try d.literal()).?;
    defer gpa.free(s);
    try testing.expectEqualStrings("Hello there\n", s);
    try testing.expectEqual(@as(usize, 12), s.len);
}

test "literal: a server may not send a non-synchronising literal" {
    const gpa = testing.allocator;
    // `{12+}` is the client-to-server form (RFC 7888). From a server it is
    // malformed, and accepting it would mean accepting a frame no legitimate
    // peer produces.
    var r = std.Io.Reader.fixed("{12+}\r\nHello there\n");
    var d = decoderOver(gpa, &r);
    try testing.expectError(error.NonSyncLiteral, d.literal());
}

test "literal: the announced size is capped before it is allocated" {
    const gpa = testing.allocator;
    var r = std.Io.Reader.fixed("{4294967295}\r\n");
    var d = Decoder.init(gpa, &r, .{ .max_literal = 1024 });
    // Not EndOfStream: the cap must fire before anything tries to hold 4 GiB.
    try testing.expectError(error.LiteralTooLarge, d.literal());
}

test "literal: a truncated body is an error, not a short string" {
    const gpa = testing.allocator;
    var r = std.Io.Reader.fixed("{20}\r\ntoo short");
    var d = decoderOver(gpa, &r);
    try testing.expectError(error.EndOfStream, d.literal());
}

test "NIL is not the string \"NIL\"" {
    const gpa = testing.allocator;
    var r = std.Io.Reader.fixed("NIL \"NIL\"");
    var d = decoderOver(gpa, &r);

    try testing.expect((try d.expectNString()) == null);
    try d.expectSp();
    const s = (try d.expectNString()).?;
    defer gpa.free(s);
    try testing.expectEqualStrings("NIL", s);
}

test "list: RFC 9051 FLAGS response body" {
    const gpa = testing.allocator;
    var r = std.Io.Reader.fixed("(\\Answered \\Flagged \\Deleted \\Seen \\Draft)");
    var d = decoderOver(gpa, &r);

    var flags: std.ArrayList([]const u8) = .empty;
    defer {
        for (flags.items) |f| gpa.free(f);
        flags.deinit(gpa);
    }

    var it = try d.expectList();
    while (try it.next()) {
        // A flag is `\` + atom; the backslash is not an atom char.
        try d.expect('\\');
        try flags.append(gpa, try d.expectAtom());
    }

    try testing.expectEqual(@as(usize, 5), flags.items.len);
    try testing.expectEqualStrings("Answered", flags.items[0]);
    try testing.expectEqualStrings("Draft", flags.items[4]);
}

test "list: the empty list is not one empty element" {
    const gpa = testing.allocator;
    var r = std.Io.Reader.fixed("()");
    var d = decoderOver(gpa, &r);
    var it = try d.expectList();
    try testing.expect(!try it.next());
    try testing.expectEqual(@as(usize, 0), d.depth);
}

test "list: nesting is bounded, and the bound is reached by nesting" {
    const gpa = testing.allocator;
    var deep: std.ArrayList(u8) = .empty;
    defer deep.deinit(gpa);
    try deep.appendNTimes(gpa, '(', 40);

    var r = std.Io.Reader.fixed(deep.items);
    var d = Decoder.init(gpa, &r, .{ .max_depth = 8 });

    var n: usize = 0;
    while (n < 40) : (n += 1) {
        const l = d.maybeList() catch |e| {
            try testing.expectEqual(error.DepthExceeded, e);
            break;
        };
        _ = l;
    }
    // Bounded where the option says, not wherever the stack gives out.
    try testing.expectEqual(@as(usize, 7), n);
}

test "SP: a space before CRLF is trailing whitespace, not a separator" {
    const gpa = testing.allocator;
    // go-imap issue 571 -- servers do this, and reading it as a separator makes
    // the next field parse start on the CRLF.
    var r = std.Io.Reader.fixed("OK \r\n");
    var d = decoderOver(gpa, &r);

    const a = try d.expectAtom();
    defer gpa.free(a);
    try testing.expectEqualStrings("OK", a);

    try testing.expect(!try d.sp()); // consumed the space, reported no field
    try testing.expect(try d.crlf()); // ...and the line still ends cleanly
}

test "SP: a missing space before a list is tolerated" {
    const gpa = testing.allocator;
    var r = std.Io.Reader.fixed("FLAGS(\\Seen)");
    var d = decoderOver(gpa, &r);

    const a = try d.expectAtom();
    defer gpa.free(a);
    try testing.expectEqualStrings("FLAGS", a);
    try testing.expect(try d.sp()); // no space in the input at all
    var it = try d.expectList();
    try testing.expect(try it.next());
}

test "CRLF: a lone LF ends a line, a lone CR does not" {
    const gpa = testing.allocator;
    var lf = std.Io.Reader.fixed("\n");
    var d1 = decoderOver(gpa, &lf);
    try testing.expect(try d1.crlf());

    var cr = std.Io.Reader.fixed("\rX");
    var d2 = decoderOver(gpa, &cr);
    try testing.expect(!try d2.crlf());
}

test "mailbox: INBOX is case-folded, other names are not" {
    const gpa = testing.allocator;
    var r = std.Io.Reader.fixed("iNbOx Drafts");
    var d = decoderOver(gpa, &r);

    const inbox = try d.expectMailbox();
    defer gpa.free(inbox);
    try testing.expectEqualStrings("INBOX", inbox);

    try d.expectSp();
    const drafts = try d.expectMailbox();
    defer gpa.free(drafts);
    try testing.expectEqualStrings("Drafts", drafts);
}

test "mailbox: the name is modified-UTF-7 decoded" {
    const gpa = testing.allocator;
    var r = std.Io.Reader.fixed("\"~peter/mail/&U,BTFw-/&ZeVnLIqe-\"");
    var d = decoderOver(gpa, &r);
    const name = try d.expectMailbox();
    defer gpa.free(name);
    try testing.expectEqualStrings("~peter/mail/\u{53f0}\u{5317}/\u{65e5}\u{672c}\u{8a9e}", name);
}

test "astring: an unquoted mailbox name may contain ']'" {
    const gpa = testing.allocator;
    // ']' is an ASTRING-CHAR but not an ATOM-CHAR; parsing this as an atom
    // would truncate the name.
    var r = std.Io.Reader.fixed("weird]name");
    var d = decoderOver(gpa, &r);
    const s = try d.expectAstring();
    defer gpa.free(s);
    try testing.expectEqualStrings("weird]name", s);
}

test "number: overflow is rejected, not truncated" {
    const gpa = testing.allocator;
    var r = std.Io.Reader.fixed("4294967296");
    var d = decoderOver(gpa, &r);
    try testing.expectError(error.BadNumber, d.expectNumber());
}

test "body-fld-octets: the -1 servers actually send" {
    const gpa = testing.allocator;
    var r = std.Io.Reader.fixed("-1 42");
    var d = decoderOver(gpa, &r);
    try testing.expectEqual(@as(u32, 0), try d.expectBodyFldOctets());
    try d.expectSp();
    try testing.expectEqual(@as(u32, 42), try d.expectBodyFldOctets());
}

test "discardValue: stays in sync across an unknown extension" {
    const gpa = testing.allocator;
    // An extension item we do not implement, followed by one we do.
    var r = std.Io.Reader.fixed("(NESTED (\"a\" {3}\r\nxyz) 12) DONE");
    var d = decoderOver(gpa, &r);

    try d.discardValue();
    try d.expectSp();
    const a = try d.expectAtom();
    defer gpa.free(a);
    try testing.expectEqualStrings("DONE", a);
}

test "a full untagged line, field by field" {
    const gpa = testing.allocator;
    // RFC 9051 §7.3.1's EXISTS shape plus a tagged completion.
    var r = std.Io.Reader.fixed("* 172 EXISTS\r\nA023 OK LIST completed\r\n");
    var d = decoderOver(gpa, &r);

    try d.expect('*');
    try d.expectSp();
    try testing.expectEqual(@as(u32, 172), try d.expectNumber());
    try d.expectSp();
    const kind = try d.expectAtom();
    defer gpa.free(kind);
    try testing.expectEqualStrings("EXISTS", kind);
    try d.expectCrlf();

    const tag = try d.expectAtom();
    defer gpa.free(tag);
    try testing.expectEqualStrings("A023", tag);
    try d.expectSp();
    const status = try d.expectAtom();
    defer gpa.free(status);
    try testing.expectEqualStrings("OK", status);
    try d.discardLine();
}

// ── divergence from the Go original ─────────────────────────────────────────
//
// D3. Go latches the first failure in `dec.err` and has every method return
//     bool, so a caller may run a whole parse and check once at the end. Here
//     every method returns an error union. The accepted grammar is identical;
//     what differs is that a Zig caller cannot ignore a failure and keep
//     parsing into undefined state.
//
// D4. Go's `Decoder.MaxSize` bounds the total bytes read (literals excluded).
//     That belongs to the response reader rather than to the grammar, so it
//     is not here; `Options.max_literal` and `Options.max_depth` are, and both
//     are enforced before the allocation or recursion they bound.
