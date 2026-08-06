// SPDX-License-Identifier: MIT

//! Commands (RFC 9051 §6), encode side.
//!
//! Ported from `emersion/go-imap` v2 `internal/imapwire/encoder.go` and the
//! command builders in `imapclient` (MIT — see `modules/imap/NOTICE`).
//!
//! ## Why a string is sometimes a literal
//!
//! `astring` is `atom / quoted / literal`, so a client may always quote — but
//! not always. A quoted string cannot contain NUL, CR or LF, cannot exceed the
//! 4096 bytes servers are only required to accept, and cannot carry raw UTF-8
//! unless IMAP4rev2 or `UTF8=ACCEPT` is in play. Anything else must go as a
//! literal, and a literal is where the protocol turns synchronous: the client
//! writes `{n}` and then **waits for the server's `+` continuation** before
//! sending the bytes.
//!
//! The encoder cannot do that wait itself — it holds no reader. So it takes a
//! **seam**: `Options.on_sync`, a callback the session installs, which the
//! encoder invokes after writing `{n}` and before writing the payload. With
//! `LITERAL+` (any size) or `LITERAL-` (up to 4096) no wait is needed and the
//! encoder emits `{n+}` directly. With neither, and no callback installed, it
//! returns `error.SyncLiteralRequired` rather than emitting something the
//! server will misread.
//!
//! The seam exists because it was originally missing: the handshake was wired
//! into `LOGIN` alone, so a `SEARCH BODY "a\r\nb"` — perfectly legal, and
//! literal-only — failed against a real server. One callback covers every
//! command instead of one command.
//!
//! ## Why arguments are checked rather than escaped
//!
//! `string`/`literal` frame their value, so a CR in a password is harmless: it
//! travels inside a counted literal. `atom` does not frame anything — it is the
//! grammar productions that have no quoted form at all (a tag, a `sequence-set`,
//! the text between `BODY[` and `]`). A CR there ends the command line and the
//! rest of the caller's value becomes **a second, fully-formed command** on an
//! authenticated connection; `1:*\r\nT9 DELETE "Important"` as a `seq_set` is
//! the whole exploit. There is nothing to escape it *into*, so those arguments
//! are refused — `error.ControlCharacterInArgument`, the same posture and the
//! same spelling as the sibling `smtp` module's `checkArg`. Quoting instead
//! would be worse than refusing: a value that reaches the server altered is a
//! mail client acting on a mailbox the user did not name.

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const utf7 = @import("utf7.zig");
const wire = @import("wire.zig");

/// Run the synchronising-literal wait: the caller reads until the server's
/// `+` continuation. Installed by the session; see the module note.
pub const SyncFn = *const fn (ctx: ?*anyopaque) anyerror!void;

pub const Error = error{
    WriteFailed,
    /// The `on_sync` callback failed. The session keeps the underlying error.
    SyncFailed,
    /// The value can only be sent as a synchronising literal, which the
    /// session must drive. See the note above.
    SyncLiteralRequired,
    /// A flag with a backslash anywhere but the front, or a non-atom byte.
    InvalidFlag,
    /// CR, LF or NUL inside an unframed argument — the command-injection
    /// vector. Same name as `smtp`'s, deliberately.
    ControlCharacterInArgument,
    /// Not a `sequence-set` (RFC 9051 §9): digits, `*`, `:`, `,`, or the
    /// RFC 5182 `$`.
    InvalidSequenceSet,
    /// A `BODY[...]` section specifier carrying a byte that would leave the
    /// brackets.
    InvalidSection,
    InvalidUtf8,
    OutOfMemory,
};

/// CR, LF and NUL can never appear in an unframed argument: the first two end
/// the command line, and the third truncates it for a C-based server. Mirrors
/// `smtp/src/command.zig`'s `checkArg`.
pub fn checkArg(s: []const u8) Error!void {
    for (s) |c| {
        if (c == '\r' or c == '\n' or c == 0) return error.ControlCharacterInArgument;
    }
}

/// RFC 9051 §9 `sequence-set`: `seq-number` is a non-zero 32-bit number or
/// `*`, joined by `:` into a range and by `,` into a set. RFC 5182 adds `$`,
/// the last saved result, which stands alone.
///
/// This is stricter than `checkArg` on purpose. A sequence-set has no quoted
/// form, so anything that is not one has to be refused rather than encoded
/// differently, and refusing only CR/LF would still let a space through —
/// `FETCH 1 2 (UID)` is a different command from the one the caller asked for.
pub fn checkSequenceSet(s: []const u8) Error!void {
    if (std.mem.eql(u8, s, "$")) return;
    var rest = s;
    while (true) {
        rest = try seqNumber(rest);
        if (rest.len != 0 and rest[0] == ':') rest = try seqNumber(rest[1..]);
        if (rest.len == 0) return;
        if (rest[0] != ',') return error.InvalidSequenceSet;
        rest = rest[1..];
    }
}

fn seqNumber(s: []const u8) Error![]const u8 {
    if (s.len == 0) return error.InvalidSequenceSet;
    if (s[0] == '*') return s[1..];
    // `nz-number = digit-nz *DIGIT` — no leading zero, and it must fit.
    if (s[0] < '1' or s[0] > '9') return error.InvalidSequenceSet;
    var i: usize = 0;
    while (i < s.len and std.ascii.isDigit(s[i])) i += 1;
    _ = std.fmt.parseInt(u32, s[0..i], 10) catch return error.InvalidSequenceSet;
    return s[i..];
}

/// The text between `BODY[` and `]` — RFC 9051 §9 `section-spec`: part
/// numbers, `HEADER`, `HEADER.FIELDS (…)`, `TEXT`, `MIME`, or empty.
///
/// Checked by character class rather than by the full grammar, because a
/// client asking for a section this module has not heard of should get the
/// *server's* answer and not ours. What is refused is exactly the two ways out
/// of the brackets: `]` closes them early (the auditor's second reproducer
/// emitted `BODY.PEEK[HEADER]\r\nT9 LOGOUT]`), and any control byte ends the
/// line. Non-ASCII goes too — a section specifier is ASCII in every form the
/// grammar has.
pub fn checkSection(s: []const u8) Error!void {
    for (s) |c| {
        if (c == ']' or c < 0x20 or c >= 0x7f) return error.InvalidSection;
    }
}

pub const Options = struct {
    /// Raw UTF-8 inside quoted strings. Requires IMAP4rev2 or `UTF8=ACCEPT`;
    /// without it, mailbox names go out as modified UTF-7.
    quoted_utf8: bool = false,
    /// `LITERAL-`: non-synchronising literals up to 4096 bytes.
    literal_minus: bool = false,
    /// `LITERAL+`: non-synchronising literals of any size.
    literal_plus: bool = false,
    /// Drives the continuation wait when a synchronising literal is needed.
    on_sync: ?SyncFn = null,
    sync_ctx: ?*anyopaque = null,
};

/// The largest string servers must accept in quoted form, and `LITERAL-`'s
/// ceiling (RFC 7888 §4).
pub const max_quoted = 4096;

/// Command tags. go-imap's format: `T` followed by a counter that never
/// repeats on a connection, so a late response can always be matched to the
/// command that caused it.
pub const Tagger = struct {
    n: u64 = 0,

    pub fn next(t: *Tagger, gpa: Allocator) Error![]u8 {
        t.n += 1;
        return std.fmt.allocPrint(gpa, "T{d}", .{t.n}) catch error.OutOfMemory;
    }
};

pub const Encoder = struct {
    w: *std.Io.Writer,
    gpa: Allocator,
    opts: Options = .{},

    pub fn init(gpa: Allocator, w: *std.Io.Writer, opts: Options) Encoder {
        return .{ .w = w, .gpa = gpa, .opts = opts };
    }

    fn raw(e: *Encoder, s: []const u8) Error!void {
        e.w.writeAll(s) catch return error.WriteFailed;
    }

    /// An unframed argument. Nothing here can be escaped, so a byte that would
    /// end the line is refused; see the module note.
    pub fn atom(e: *Encoder, s: []const u8) Error!void {
        try checkArg(s);
        return e.raw(s);
    }

    pub fn sp(e: *Encoder) Error!void {
        return e.raw(" ");
    }

    /// A grammar delimiter. Public, therefore checked: a caller reaching for
    /// `special('\r')` is writing a command boundary, not a delimiter.
    pub fn special(e: *Encoder, ch: u8) Error!void {
        const one = [_]u8{ch};
        try checkArg(&one);
        return e.raw(&one);
    }

    pub fn crlf(e: *Encoder) Error!void {
        return e.raw("\r\n");
    }

    pub fn number(e: *Encoder, v: u32) Error!void {
        var buf: [10]u8 = undefined;
        const s = std.fmt.bufPrint(&buf, "{d}", .{v}) catch unreachable;
        return e.raw(s);
    }

    /// A quoted string, escaping `"` and `\`. Assumes the value is otherwise
    /// quotable; use `string` to choose the form. The three bytes a quoted
    /// string can never hold are checked rather than assumed, because this is
    /// public and a direct caller would otherwise inject through it.
    pub fn quoted(e: *Encoder, s: []const u8) Error!void {
        try checkArg(s);
        try e.raw("\"");
        var start: usize = 0;
        for (s, 0..) |ch, i| {
            if (ch != '"' and ch != '\\') continue;
            try e.raw(s[start..i]);
            try e.raw("\\");
            start = i;
        }
        try e.raw(s[start..]);
        try e.raw("\"");
    }

    /// True when `s` may travel as a quoted string.
    pub fn quotable(e: *const Encoder, s: []const u8) bool {
        if (s.len > max_quoted) return false;
        for (s) |ch| {
            // NUL, CR and LF can never appear in a quoted string: the first
            // would truncate it for a C-based server, the other two would end
            // the line.
            if (ch == 0 or ch == '\r' or ch == '\n') return false;
            if (!e.opts.quoted_utf8 and ch > 0x7f) return false;
        }
        return true;
    }

    /// `string` — quoted where possible, literal otherwise.
    pub fn string(e: *Encoder, s: []const u8) Error!void {
        if (e.quotable(s)) return e.quoted(s);
        return e.literal(s);
    }

    /// A literal, in whichever form the connection allows.
    pub fn literal(e: *Encoder, s: []const u8) Error!void {
        const non_sync = e.opts.literal_plus or
            (e.opts.literal_minus and s.len <= max_quoted);

        if (non_sync) {
            try e.raw("{");
            try e.number(@intCast(s.len));
            try e.raw("+}\r\n");
            try e.raw(s);
            return;
        }

        const wait = e.opts.on_sync orelse return error.SyncLiteralRequired;

        // `{n}` CRLF, flush, wait for the server's `+`, then the payload. The
        // flush matters: the server cannot answer a request still sitting in
        // our buffer.
        try e.raw("{");
        try e.number(@intCast(s.len));
        try e.raw("}\r\n");
        e.w.flush() catch return error.WriteFailed;
        wait(e.opts.sync_ctx) catch return error.SyncFailed;
        try e.raw(s);
    }

    /// A mailbox name. `INBOX` is the one name that is case-insensitive, and
    /// it goes out as a bare atom the way every server writes it. Everything
    /// else is encoded — modified UTF-7 normally, raw UTF-8 with `&` escaped
    /// when the connection accepts UTF-8.
    pub fn mailbox(e: *Encoder, name: []const u8) Error!void {
        if (std.ascii.eqlIgnoreCase(name, "INBOX")) return e.atom("INBOX");

        if (e.opts.quoted_utf8) {
            // Raw UTF-8 is allowed, but `&` still introduces a shift sequence,
            // so it must be escaped or the name changes meaning.
            var out: std.ArrayList(u8) = .empty;
            defer out.deinit(e.gpa);
            for (name) |ch| {
                try out.append(e.gpa, ch);
                if (ch == '&') try out.append(e.gpa, '-');
            }
            return e.string(out.items);
        }

        const encoded = utf7.encodeAlloc(e.gpa, name) catch |err| switch (err) {
            error.InvalidUtf8 => return error.InvalidUtf8,
            error.OutOfMemory => return error.OutOfMemory,
        };
        defer e.gpa.free(encoded);
        return e.string(encoded);
    }

    /// A flag. `\*` is allowed (flag-perm); otherwise a backslash may only
    /// lead, and the rest must be atom characters.
    pub fn flag(e: *Encoder, f: []const u8) Error!void {
        if (!validFlag(f)) return error.InvalidFlag;
        return e.raw(f);
    }

    // ── whole commands ──────────────────────────────────────────────────────

    /// `TAG CAPABILITY`
    pub fn capability(e: *Encoder, tag: []const u8) Error!void {
        try e.atom(tag);
        try e.sp();
        try e.atom("CAPABILITY");
        try e.crlf();
    }

    /// `TAG NOOP`
    pub fn noop(e: *Encoder, tag: []const u8) Error!void {
        try e.atom(tag);
        try e.sp();
        try e.atom("NOOP");
        try e.crlf();
    }

    /// `TAG LOGOUT`
    pub fn logout(e: *Encoder, tag: []const u8) Error!void {
        try e.atom(tag);
        try e.sp();
        try e.atom("LOGOUT");
        try e.crlf();
    }

    /// `TAG STARTTLS`
    pub fn startTls(e: *Encoder, tag: []const u8) Error!void {
        try e.atom(tag);
        try e.sp();
        try e.atom("STARTTLS");
        try e.crlf();
    }

    /// `TAG LOGIN user pass`. Both arguments are astrings, so a password
    /// containing a quote, a backslash or a newline is handled by the encoding
    /// rather than by rejecting it.
    pub fn login(e: *Encoder, tag: []const u8, user: []const u8, pass: []const u8) Error!void {
        try e.atom(tag);
        try e.sp();
        try e.atom("LOGIN");
        try e.sp();
        try e.string(user);
        try e.sp();
        try e.string(pass);
        try e.crlf();
    }

    /// `TAG SELECT mailbox` — or `EXAMINE`, which is the same command with the
    /// mailbox opened read-only.
    pub fn select(e: *Encoder, tag: []const u8, name: []const u8, read_only: bool) Error!void {
        try e.atom(tag);
        try e.sp();
        try e.atom(if (read_only) "EXAMINE" else "SELECT");
        try e.sp();
        try e.mailbox(name);
        try e.crlf();
    }
};

/// What `Encoder.flag` accepts. Public so `search`'s pre-flight can ask the
/// question without a second copy of the rule.
pub fn validFlag(s: []const u8) bool {
    if (s.len == 0) return false;
    if (std.mem.eql(u8, s, "\\*")) return true;
    for (s, 0..) |ch, i| {
        if (ch == '\\') {
            if (i != 0) return false;
        } else if (!wire.isAtomChar(ch)) return false;
    }
    return true;
}

// ── tests ───────────────────────────────────────────────────────────────────

const Sink = struct {
    buf: [8192]u8 = undefined,
    w: std.Io.Writer = undefined,

    fn init(s: *Sink) void {
        s.w = std.Io.Writer.fixed(&s.buf);
    }
    fn written(s: *Sink) []const u8 {
        return s.w.buffered();
    }
    fn enc(s: *Sink, gpa: Allocator, opts: Options) Encoder {
        return Encoder.init(gpa, &s.w, opts);
    }
};

test "RFC 9051 §6.1.1: CAPABILITY" {
    var s: Sink = undefined;
    s.init();
    var e = s.enc(testing.allocator, .{});
    try e.capability("abcd");
    try testing.expectEqualStrings("abcd CAPABILITY\r\n", s.written());
}

test "RFC 9051 §6.2.3: LOGIN" {
    var s: Sink = undefined;
    s.init();
    var e = s.enc(testing.allocator, .{});
    try e.login("a001", "SMITH", "SESAME");
    // The RFC prints the arguments as bare atoms; `astring` also permits the
    // quoted form, and quoting unconditionally is what keeps one code path for
    // values that contain specials.
    try testing.expectEqualStrings("a001 LOGIN \"SMITH\" \"SESAME\"\r\n", s.written());
}

test "RFC 9051 §6.3.2: SELECT, and EXAMINE is the read-only spelling" {
    var s: Sink = undefined;
    s.init();
    var e = s.enc(testing.allocator, .{});
    try e.select("A142", "INBOX", false);
    try testing.expectEqualStrings("A142 SELECT INBOX\r\n", s.written());

    var s2: Sink = undefined;
    s2.init();
    var e2 = s2.enc(testing.allocator, .{});
    try e2.select("A932", "blurdybloop", true);
    try testing.expectEqualStrings("A932 EXAMINE \"blurdybloop\"\r\n", s2.written());
}

test "INBOX goes out unquoted whatever its case, other names are quoted" {
    var s: Sink = undefined;
    s.init();
    var e = s.enc(testing.allocator, .{});
    try e.mailbox("iNbOx");
    try e.sp();
    try e.mailbox("Drafts");
    try testing.expectEqualStrings("INBOX \"Drafts\"", s.written());
}

test "a non-ASCII mailbox name is encoded as modified UTF-7" {
    var s: Sink = undefined;
    s.init();
    var e = s.enc(testing.allocator, .{});
    try e.mailbox("~peter/mail/\u{53f0}\u{5317}/\u{65e5}\u{672c}\u{8a9e}");
    // Byte-identical to the spelling RFC 3501 §5.1.3 prints.
    try testing.expectEqualStrings("\"~peter/mail/&U,BTFw-/&ZeVnLIqe-\"", s.written());
}

test "with UTF8=ACCEPT the name stays UTF-8 — but '&' must still be escaped" {
    var s: Sink = undefined;
    s.init();
    var e = s.enc(testing.allocator, .{ .quoted_utf8 = true });
    try e.mailbox("R&D/\u{53f0}");
    // '&' introduces a shift sequence even in UTF-8 mode; leaving it bare
    // would silently rename the mailbox.
    try testing.expectEqualStrings("\"R&-D/\u{53f0}\"", s.written());
}

test "quoting escapes exactly the two characters that need it" {
    var s: Sink = undefined;
    s.init();
    var e = s.enc(testing.allocator, .{});
    try e.string("a\"b\\c d");
    try testing.expectEqualStrings("\"a\\\"b\\\\c d\"", s.written());
}

test "a password with a newline cannot be quoted, and says so" {
    var s: Sink = undefined;
    s.init();
    var e = s.enc(testing.allocator, .{});
    // CR/LF would end the command line. Without LITERAL+/- the session has to
    // run the continuation handshake, so the encoder refuses rather than
    // emitting something the server will misread.
    try testing.expectError(error.SyncLiteralRequired, e.login("a1", "u", "pa\r\nss"));
}

test "LITERAL+ turns the same password into a non-synchronising literal" {
    var s: Sink = undefined;
    s.init();
    var e = s.enc(testing.allocator, .{ .literal_plus = true });
    try e.login("a1", "u", "pa\r\nss");
    try testing.expectEqualStrings("a1 LOGIN \"u\" {6+}\r\npa\r\nss\r\n", s.written());
}

test "LITERAL- has a ceiling; LITERAL+ does not" {
    const gpa = testing.allocator;
    const big = try gpa.alloc(u8, max_quoted + 1);
    defer gpa.free(big);
    @memset(big, 'x');

    var s: Sink = undefined;
    s.init();
    var minus = s.enc(gpa, .{ .literal_minus = true });
    // Over 4096 bytes LITERAL- does not apply, so a synchronising literal is
    // required (RFC 7888 §4).
    try testing.expectError(error.SyncLiteralRequired, minus.string(big));

    var s2: Sink = undefined;
    s2.init();
    var plus = s2.enc(gpa, .{ .literal_plus = true });
    try plus.string(big);
    try testing.expect(std.mem.startsWith(u8, s2.written(), "{4097+}\r\nxxx"));
}

test "a non-ASCII value is a literal unless UTF-8 is accepted" {
    var s: Sink = undefined;
    s.init();
    var e = s.enc(testing.allocator, .{ .literal_plus = true });
    try e.string("caf\u{e9}");
    try testing.expectEqualStrings("{5+}\r\ncaf\u{e9}", s.written());

    var s2: Sink = undefined;
    s2.init();
    var e2 = s2.enc(testing.allocator, .{ .quoted_utf8 = true });
    try e2.string("caf\u{e9}");
    try testing.expectEqualStrings("\"caf\u{e9}\"", s2.written());
}

test "flags: the backslash may only lead" {
    var s: Sink = undefined;
    s.init();
    var e = s.enc(testing.allocator, .{});
    try e.flag("\\Seen");
    try e.sp();
    try e.flag("$Forwarded");
    try e.sp();
    try e.flag("\\*");
    try testing.expectEqualStrings("\\Seen $Forwarded \\*", s.written());

    try testing.expectError(error.InvalidFlag, e.flag("Se\\en"));
    try testing.expectError(error.InvalidFlag, e.flag(""));
    try testing.expectError(error.InvalidFlag, e.flag("with space"));
}

test "tags never repeat" {
    const gpa = testing.allocator;
    var t: Tagger = .{};
    const a = try t.next(gpa);
    defer gpa.free(a);
    const b = try t.next(gpa);
    defer gpa.free(b);
    try testing.expectEqualStrings("T1", a);
    try testing.expectEqualStrings("T2", b);
}

test "an unframed argument cannot carry a byte that ends the command line" {
    var s: Sink = undefined;
    s.init();
    var e = s.enc(testing.allocator, .{});

    // The exploit, at the primitive: `atom` had no validation at all, so this
    // put `T1 FETCH 1:*` and then a whole second command on the wire.
    try testing.expectError(
        error.ControlCharacterInArgument,
        e.atom("1:*\r\nT9 DELETE \"Important\""),
    );
    try testing.expectError(error.ControlCharacterInArgument, e.atom("a\nb"));
    try testing.expectError(error.ControlCharacterInArgument, e.atom("a\x00b"));
    // `quoted` is public and escapes only `"` and `\`, so it was the second way
    // through; `special` is public and takes a byte, so it was the third.
    try testing.expectError(error.ControlCharacterInArgument, e.quoted("a\r\nT9 NOOP"));
    try testing.expectError(error.ControlCharacterInArgument, e.special('\r'));
    try testing.expectError(error.ControlCharacterInArgument, e.special(0));

    // Nothing was emitted by any of them.
    try testing.expectEqualStrings("", s.written());

    // What is framed stays legal: a literal counts its own bytes, so a CR in a
    // password is not an injection and must not start being refused.
    var s2: Sink = undefined;
    s2.init();
    var e2 = s2.enc(testing.allocator, .{ .literal_plus = true });
    try e2.login("a1", "u", "pa\r\nss");
    try testing.expectEqualStrings("a1 LOGIN \"u\" {6+}\r\npa\r\nss\r\n", s2.written());
}

test "sequence-set: the grammar, not just the absence of CRLF" {
    for ([_][]const u8{ "1", "1:*", "*", "2:4", "12:13", "1:5,7,9:*", "$", "4294967295" }) |ok| {
        checkSequenceSet(ok) catch |err| {
            std.debug.print("rejected a valid sequence-set {s}: {}\n", .{ ok, err });
            return error.TestUnexpectedResult;
        };
    }
    for ([_][]const u8{
        "1:*\r\nT9 DELETE \"Important\"", // the audit's reproducer
        "", // FETCH with no set at all
        "1 2", // a space is a second argument, not a set
        "0", // nz-number
        "01", // leading zero
        "1:", "1,", ",1", ":2", "1::2", "4294967296", "1;2", "$1", "1 ",
    }) |bad| {
        testing.expectError(error.InvalidSequenceSet, checkSequenceSet(bad)) catch {
            std.debug.print("accepted a bad sequence-set: {s}\n", .{bad});
            return error.TestUnexpectedResult;
        };
    }
}

test "section specifier: the two ways out of the brackets are shut" {
    for ([_][]const u8{ "", "HEADER", "TEXT", "1.2", "HEADER.FIELDS (FROM TO)", "2.MIME" }) |ok| {
        try checkSection(ok);
    }
    // `]` closes the brackets early; the auditor's second reproducer used both.
    try testing.expectError(error.InvalidSection, checkSection("HEADER]\r\nT9 LOGOUT"));
    try testing.expectError(error.InvalidSection, checkSection("HEADER] (FLAGS"));
    try testing.expectError(error.InvalidSection, checkSection("A\rB"));
    try testing.expectError(error.InvalidSection, checkSection("A\x00B"));
    try testing.expectError(error.InvalidSection, checkSection("caf\u{e9}"));
}

test "round trip: what the encoder writes, the response reader's grammar reads" {
    // Not a proof of correctness -- both sides are ours -- but it does catch a
    // whole class of framing slip, e.g. a missing CRLF or an unbalanced quote.
    const gpa = testing.allocator;
    var s: Sink = undefined;
    s.init();
    var e = s.enc(gpa, .{});
    try e.select("A142", "Sent \"Items\"", false);

    var r = std.Io.Reader.fixed(s.written());
    var d = wire.Decoder.init(gpa, &r, .{});

    const tag = try d.expectAtom();
    defer gpa.free(tag);
    try testing.expectEqualStrings("A142", tag);
    try d.expectSp();
    const cmd = try d.expectAtom();
    defer gpa.free(cmd);
    try testing.expectEqualStrings("SELECT", cmd);
    try d.expectSp();
    const name = try d.expectMailbox();
    defer gpa.free(name);
    try testing.expectEqualStrings("Sent \"Items\"", name);
    try d.expectCrlf();
}
