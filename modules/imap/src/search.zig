// SPDX-License-Identifier: MIT

//! `SEARCH` (RFC 9051 §6.4.4) — the criteria on the way out, and both reply
//! shapes on the way back.
//!
//! Ported from `emersion/go-imap` v2 `imapclient/search.go` (MIT — see
//! `modules/imap/NOTICE`).
//!
//! ## Two reply shapes, and why both are here
//!
//! IMAP4rev1 answers with `* SEARCH 2 84 882` — a bare list of numbers, with
//! no way to tell which command it belongs to. IMAP4rev2 (and the `ESEARCH`
//! extension before it) answers with
//! `* ESEARCH (TAG "A282") MIN 2 COUNT 3`, which carries the tag and can
//! return aggregates instead of every number.
//!
//! A client that only understands the new form breaks against rev1 servers,
//! and one that only understands the old form cannot ask for `COUNT` at all.
//! Both are parsed into the same result.

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const wire = @import("wire.zig");
const command = @import("command.zig");

pub const Error = wire.Error || error{
    /// A `search-correlator` whose name is not `TAG`.
    BadCorrelator,
};

pub const HeaderField = struct { key: []const u8, value: []const u8 };

/// What to return. All false means the server picks (`ALL` for rev1 servers).
pub const Return = struct {
    min: bool = false,
    max: bool = false,
    all: bool = false,
    count: bool = false,

    fn any(r: Return) bool {
        return r.min or r.max or r.all or r.count;
    }
};

/// Search keys. Everything left at its default is simply not sent; what is
/// set is ANDed, which is the grammar's own default.
pub const Criteria = struct {
    seq_set: ?[]const u8 = null,
    uid_set: ?[]const u8 = null,

    /// Dates in IMAP's own `1-Feb-1994` form. Kept as text: this module does
    /// not own a calendar, and a caller with a `datefmt` timestamp formats it
    /// once rather than having every criterion carry a conversion.
    since: ?[]const u8 = null,
    before: ?[]const u8 = null,
    sent_since: ?[]const u8 = null,
    sent_before: ?[]const u8 = null,

    header: []const HeaderField = &.{},
    body: []const []const u8 = &.{},
    text: []const []const u8 = &.{},

    flag: []const []const u8 = &.{},
    not_flag: []const []const u8 = &.{},

    larger: ?u32 = null,
    smaller: ?u32 = null,

    not: []const *const Criteria = &.{},
    either: []const [2]*const Criteria = &.{},
};

/// `TAG [UID] SEARCH [RETURN (...)] criteria`.
pub fn encode(
    e: *command.Encoder,
    tag: []const u8,
    by_uid: bool,
    ret: Return,
    crit: *const Criteria,
) command.Error!void {
    // Before any output: the criteria tree is walked for the values that go out
    // unframed. A nested `NOT (…)` is written after its parent's `NOT (`, so
    // discovering a bad key down there mid-write would strand an unbalanced
    // paren in the session's buffer.
    try command.checkArg(tag);
    try checkKeys(crit);

    try e.atom(tag);
    try e.sp();
    if (by_uid) {
        try e.atom("UID");
        try e.sp();
    }
    try e.atom("SEARCH");

    if (ret.any()) {
        try e.sp();
        try e.atom("RETURN");
        try e.sp();
        try e.special('(');
        var n: usize = 0;
        const items = [_]struct { on: bool, name: []const u8 }{
            .{ .on = ret.min, .name = "MIN" },
            .{ .on = ret.max, .name = "MAX" },
            .{ .on = ret.all, .name = "ALL" },
            .{ .on = ret.count, .name = "COUNT" },
        };
        for (items) |i| {
            if (!i.on) continue;
            if (n > 0) try e.sp();
            try e.atom(i.name);
            n += 1;
        }
        try e.special(')');
    }

    try e.sp();
    try writeKeys(e, crit);
    try e.crlf();
}

/// The five flags whose search keys the grammar spells out; see `writeFlagKey`.
const system_flags = [_]struct { flag: []const u8, yes: []const u8, no: []const u8 }{
    .{ .flag = "\\Seen", .yes = "SEEN", .no = "UNSEEN" },
    .{ .flag = "\\Answered", .yes = "ANSWERED", .no = "UNANSWERED" },
    .{ .flag = "\\Flagged", .yes = "FLAGGED", .no = "UNFLAGGED" },
    .{ .flag = "\\Deleted", .yes = "DELETED", .no = "UNDELETED" },
    .{ .flag = "\\Draft", .yes = "DRAFT", .no = "UNDRAFT" },
};

/// The pre-flight for `writeKeys`, in the same order and over the same fields:
/// every value that `writeKeys` sends unframed (`atom`, `flag`) is validated
/// here, and every value it sends through `string` is skipped, because a
/// literal frames its own payload and cannot escape the command.
fn checkKeys(c: *const Criteria) command.Error!void {
    if (c.seq_set) |s| try command.checkSequenceSet(s);
    if (c.uid_set) |s| try command.checkSequenceSet(s);
    for (c.flag) |f| if (!validFlag(f)) return error.InvalidFlag;
    for (c.not_flag) |f| if (!validFlag(f)) return error.InvalidFlag;
    for (c.not) |sub| try checkKeys(sub);
    for (c.either) |pair| {
        try checkKeys(pair[0]);
        try checkKeys(pair[1]);
    }
}

/// A system flag is spelled as its own search key and never reaches `flag()`,
/// so the pre-flight accepts exactly what `writeFlagKey` would emit: the five
/// system names, or whatever `Encoder.flag` itself would accept.
fn validFlag(f: []const u8) bool {
    for (system_flags) |s| {
        if (std.ascii.eqlIgnoreCase(f, s.flag)) return true;
    }
    return command.validFlag(f);
}

fn writeKeys(e: *command.Encoder, c: *const Criteria) command.Error!void {
    var first = true;
    const item = struct {
        fn sep(enc: *command.Encoder, f: *bool) command.Error!void {
            if (!f.*) try enc.sp();
            f.* = false;
        }
    };

    if (c.seq_set) |s| {
        try item.sep(e, &first);
        try e.atom(s);
    }
    if (c.uid_set) |s| {
        try item.sep(e, &first);
        try e.atom("UID");
        try e.sp();
        try e.atom(s);
    }

    const dates = [_]struct { key: []const u8, val: ?[]const u8 }{
        .{ .key = "SINCE", .val = c.since },
        .{ .key = "BEFORE", .val = c.before },
        .{ .key = "SENTSINCE", .val = c.sent_since },
        .{ .key = "SENTBEFORE", .val = c.sent_before },
    };
    for (dates) |d| {
        const v = d.val orelse continue;
        try item.sep(e, &first);
        try e.atom(d.key);
        try e.sp();
        try e.string(v);
    }

    for (c.header) |h| {
        try item.sep(e, &first);
        // Five header names are keys of their own in the grammar; everything
        // else goes through the generic HEADER form.
        const shorthand = [_][]const u8{ "BCC", "CC", "FROM", "SUBJECT", "TO" };
        var matched = false;
        for (shorthand) |s| {
            if (!std.ascii.eqlIgnoreCase(h.key, s)) continue;
            try e.atom(s);
            matched = true;
            break;
        }
        if (!matched) {
            try e.atom("HEADER");
            try e.sp();
            try e.string(h.key);
        }
        try e.sp();
        try e.string(h.value);
    }

    for (c.body) |s| {
        try item.sep(e, &first);
        try e.atom("BODY");
        try e.sp();
        try e.string(s);
    }
    for (c.text) |s| {
        try item.sep(e, &first);
        try e.atom("TEXT");
        try e.sp();
        try e.string(s);
    }
    for (c.flag) |f| {
        try item.sep(e, &first);
        try writeFlagKey(e, f, false);
    }
    for (c.not_flag) |f| {
        try item.sep(e, &first);
        try writeFlagKey(e, f, true);
    }

    if (c.larger) |n| {
        try item.sep(e, &first);
        try e.atom("LARGER");
        try e.sp();
        try e.number(n);
    }
    if (c.smaller) |n| {
        try item.sep(e, &first);
        try e.atom("SMALLER");
        try e.sp();
        try e.number(n);
    }

    for (c.not) |sub| {
        try item.sep(e, &first);
        try e.atom("NOT");
        try e.sp();
        try e.special('(');
        try writeKeys(e, sub);
        try e.special(')');
    }
    for (c.either) |pair| {
        try item.sep(e, &first);
        try e.atom("OR");
        try e.sp();
        try e.special('(');
        try writeKeys(e, pair[0]);
        try e.special(')');
        try e.sp();
        try e.special('(');
        try writeKeys(e, pair[1]);
        try e.special(')');
    }

    // "SEARCH" with no key at all is not a command; ALL is the identity.
    if (first) try e.atom("ALL");
}

/// The system flags have search keys of their own (`\Seen` is `SEEN`, and its
/// negation is `UNSEEN` rather than `NOT SEEN`); a keyword goes through
/// `KEYWORD` / `UNKEYWORD`.
fn writeFlagKey(e: *command.Encoder, f: []const u8, negate: bool) command.Error!void {
    for (system_flags) |s| {
        if (!std.ascii.eqlIgnoreCase(f, s.flag)) continue;
        return e.atom(if (negate) s.no else s.yes);
    }
    try e.atom(if (negate) "UNKEYWORD" else "KEYWORD");
    try e.sp();
    try e.flag(f);
}

// ── the reply ───────────────────────────────────────────────────────────────

pub const Result = struct {
    /// The tag the server correlated the reply with, when it sent one. Only
    /// `ESEARCH` carries this; a rev1 `* SEARCH` cannot be correlated at all.
    tag: ?[]const u8 = null,
    /// True when the numbers are UIDs rather than sequence numbers.
    uid: bool = false,
    /// Present only if asked for.
    min: ?u32 = null,
    max: ?u32 = null,
    count: ?u32 = null,
    /// The `ALL` set, verbatim (`2,84,882` or `2:4,7`). Kept as written: a
    /// range is not the same information as its expansion, and expanding
    /// `1:4294967295` is how a client runs out of memory.
    all: ?[]const u8 = null,
    /// A rev1 `* SEARCH` reply's numbers, in the order sent.
    numbers: []const u32 = &.{},
};

/// Parse the body of `* SEARCH ...`, i.e. everything after the word.
pub fn parseSearch(d: *wire.Decoder) Error!Result {
    var nums: std.ArrayList(u32) = .empty;
    errdefer nums.deinit(d.gpa);
    while (try d.sp()) {
        const n = (try d.number()) orelse break;
        try nums.append(d.gpa, n);
    }
    return .{ .numbers = try nums.toOwnedSlice(d.gpa) };
}

/// Parse the body of `* ESEARCH ...`.
pub fn parseESearch(d: *wire.Decoder) Error!Result {
    var out: Result = .{};

    if (try d.accept('(')) {
        const name = try d.expectAtom();
        defer d.gpa.free(name);
        if (!std.ascii.eqlIgnoreCase(name, "TAG")) return error.BadCorrelator;
        try d.expectSp();
        out.tag = try d.expectAstring();
        try d.expect(')');
    }

    if (!try d.sp()) return out;
    var name = try d.expectAtom();

    if (std.ascii.eqlIgnoreCase(name, "UID")) {
        out.uid = true;
        d.gpa.free(name);
        if (!try d.sp()) return out;
        name = try d.expectAtom();
    }

    while (true) {
        try d.expectSp();
        if (std.ascii.eqlIgnoreCase(name, "MIN")) {
            out.min = try d.expectNumber();
        } else if (std.ascii.eqlIgnoreCase(name, "MAX")) {
            out.max = try d.expectNumber();
        } else if (std.ascii.eqlIgnoreCase(name, "COUNT")) {
            out.count = try d.expectNumber();
        } else if (std.ascii.eqlIgnoreCase(name, "ALL")) {
            out.all = (try d.run(isSeqSetChar)) orelse return error.UnexpectedByte;
        } else {
            // An extension return item: consume its value and keep going.
            try d.discardValue();
        }
        d.gpa.free(name);

        if (!try d.sp()) return out;
        name = try d.expectAtom();
    }
}

fn isSeqSetChar(ch: u8) bool {
    return ch == '*' or wire.isAtomChar(ch);
}

// ── tests ───────────────────────────────────────────────────────────────────

const Sink = struct {
    buf: [1024]u8 = undefined,
    w: std.Io.Writer = undefined,

    fn init(s: *Sink) void {
        s.w = std.Io.Writer.fixed(&s.buf);
    }
    fn enc(s: *Sink) command.Encoder {
        return command.Encoder.init(testing.allocator, &s.w, .{});
    }
    fn out(s: *Sink) []const u8 {
        return s.w.buffered();
    }
};

const Fx = struct {
    arena: std.heap.ArenaAllocator,
    r: std.Io.Reader,
    d: wire.Decoder = undefined,

    fn init(f: *Fx, input: []const u8) void {
        f.arena = std.heap.ArenaAllocator.init(testing.allocator);
        f.r = std.Io.Reader.fixed(input);
        f.d = wire.Decoder.init(f.arena.allocator(), &f.r, .{});
    }
    fn deinit(f: *Fx) void {
        f.arena.deinit();
    }
};

test "RFC 9051 §6.4.4: SEARCH RETURN (MIN COUNT) with a NOT" {
    var s: Sink = undefined;
    s.init();
    var e = s.enc();

    const smith = Criteria{ .header = &.{.{ .key = "FROM", .value = "Smith" }} };
    try encode(&e, "A282", false, .{ .min = true, .count = true }, &.{
        .flag = &.{"\\Flagged"},
        .since = "1-Feb-1994",
        .not = &.{&smith},
    });
    try testing.expectEqualStrings(
        "A282 SEARCH RETURN (MIN COUNT) SINCE \"1-Feb-1994\" FLAGGED NOT (FROM \"Smith\")\r\n",
        s.out(),
    );
}

test "an empty RETURN list is not the same as no RETURN at all" {
    // RFC 9051 §6.4.4: "RETURN ()" means ALL, and is how a rev2 client asks
    // for the ESEARCH form of the default result.
    var s: Sink = undefined;
    s.init();
    var e = s.enc();
    try encode(&e, "A283", false, .{}, &.{ .flag = &.{"\\Flagged"} });
    try testing.expectEqualStrings("A283 SEARCH FLAGGED\r\n", s.out());
}

test "system flags have their own keys, and their own negations" {
    var s: Sink = undefined;
    s.init();
    var e = s.enc();
    try encode(&e, "A1", false, .{}, &.{
        .flag = &.{"\\Seen"},
        .not_flag = &.{ "\\Deleted", "$Junk" },
    });
    // Not "NOT SEEN" and not "NOT KEYWORD \Deleted": the grammar spells these.
    try testing.expectEqualStrings(
        "A1 SEARCH SEEN UNDELETED UNKEYWORD $Junk\r\n",
        s.out(),
    );
}

test "a header that is not one of the five shorthands uses HEADER" {
    var s: Sink = undefined;
    s.init();
    var e = s.enc();
    try encode(&e, "A1", false, .{}, &.{
        .header = &.{
            .{ .key = "TO", .value = "a@x.test" },
            .{ .key = "X-Spam", .value = "yes" },
        },
    });
    try testing.expectEqualStrings(
        "A1 SEARCH TO \"a@x.test\" HEADER \"X-Spam\" \"yes\"\r\n",
        s.out(),
    );
}

test "OR takes two parenthesised key sets" {
    var s: Sink = undefined;
    s.init();
    var e = s.enc();
    const a = Criteria{ .body = &.{"hello"} };
    const b = Criteria{ .text = &.{"world"} };
    try encode(&e, "A1", true, .{}, &.{ .either = &.{.{ &a, &b }} });
    try testing.expectEqualStrings(
        "A1 UID SEARCH OR (BODY \"hello\") (TEXT \"world\")\r\n",
        s.out(),
    );
}

test "a criteria with no keys at all searches ALL" {
    var s: Sink = undefined;
    s.init();
    var e = s.enc();
    try encode(&e, "A1", false, .{}, &.{});
    // "A1 SEARCH\r\n" would not be a command.
    try testing.expectEqualStrings("A1 SEARCH ALL\r\n", s.out());
}

test "RFC 9051 §6.4.4: the ESEARCH reply" {
    var f: Fx = undefined;
    f.init("(TAG \"A282\") MIN 2 COUNT 3\r\n");
    defer f.deinit();

    const r = try parseESearch(&f.d);
    try testing.expectEqualStrings("A282", r.tag.?);
    try testing.expectEqual(@as(u32, 2), r.min.?);
    try testing.expectEqual(@as(u32, 3), r.count.?);
    try testing.expect(r.max == null);
    try testing.expect(!r.uid);
}

test "ESEARCH: UID marks the numbers, and ALL stays a set" {
    var f: Fx = undefined;
    f.init("(TAG \"A283\") UID ALL 2,10:11\r\n");
    defer f.deinit();

    const r = try parseESearch(&f.d);
    try testing.expect(r.uid);
    // Kept verbatim: expanding 10:11 loses nothing here, but expanding
    // 1:4294967295 is how a client runs out of memory.
    try testing.expectEqualStrings("2,10:11", r.all.?);
}

test "ESEARCH: an unknown return item does not break the rest" {
    var f: Fx = undefined;
    f.init("(TAG \"A1\") MIN 1 FUZZ (1 2) COUNT 7\r\n");
    defer f.deinit();
    const r = try parseESearch(&f.d);
    try testing.expectEqual(@as(u32, 1), r.min.?);
    try testing.expectEqual(@as(u32, 7), r.count.?);
}

test "ESEARCH: a correlator that is not TAG is rejected" {
    var f: Fx = undefined;
    f.init("(NOTATAG \"A1\") MIN 1\r\n");
    defer f.deinit();
    try testing.expectError(error.BadCorrelator, parseESearch(&f.d));
}

test "the IMAP4rev1 reply shape: a bare list of numbers" {
    var f: Fx = undefined;
    f.init(" 2 84 882\r\n");
    defer f.deinit();
    const r = try parseSearch(&f.d);
    try testing.expectEqual(@as(usize, 3), r.numbers.len);
    try testing.expectEqual(@as(u32, 2), r.numbers[0]);
    try testing.expectEqual(@as(u32, 882), r.numbers[2]);
    // It carries no tag, which is exactly why ESEARCH exists.
    try testing.expect(r.tag == null);
}

test "an empty rev1 reply means no matches, not a parse failure" {
    var f: Fx = undefined;
    f.init("\r\n");
    defer f.deinit();
    const r = try parseSearch(&f.d);
    try testing.expectEqual(@as(usize, 0), r.numbers.len);
}

test "a criteria set cannot smuggle a second command onto the wire" {
    const inject = "1:*\r\nT9 DELETE \"Important\"";

    var s: Sink = undefined;
    s.init();
    var e = s.enc();
    try testing.expectError(
        error.InvalidSequenceSet,
        encode(&e, "T1", false, .{}, &.{ .seq_set = inject }),
    );
    try testing.expectEqualStrings("", s.out());

    try testing.expectError(
        error.InvalidSequenceSet,
        encode(&e, "T2", false, .{}, &.{ .uid_set = inject }),
    );
    try testing.expectEqualStrings("", s.out());

    // Nested: `writeKeys` recurses, and the parent had already written `NOT (`
    // before the child's key was reached. The pre-flight is what makes this a
    // clean refusal rather than an unbalanced paren left in the buffer.
    const inner = Criteria{ .seq_set = inject };
    const mid = Criteria{ .not = &.{&inner} };
    try testing.expectError(
        error.InvalidSequenceSet,
        encode(&e, "T3", false, .{}, &.{ .not = &.{&mid} }),
    );
    try testing.expectEqualStrings("", s.out());

    const a = Criteria{ .body = &.{"hello"} };
    try testing.expectError(
        error.InvalidSequenceSet,
        encode(&e, "T4", false, .{}, &.{ .either = &.{.{ &a, &inner }} }),
    );
    try testing.expectEqualStrings("", s.out());

    // A keyword flag reaches the wire through `flag()`, which already refused
    // control characters — but it did so mid-write.
    try testing.expectError(
        error.InvalidFlag,
        encode(&e, "T5", false, .{}, &.{ .flag = &.{"Junk\r\nT9 LOGOUT"} }),
    );
    try testing.expectEqualStrings("", s.out());

    // A CRLF in a BODY/TEXT/HEADER value is *not* an injection: those go out as
    // counted literals. Refusing them would be a regression.
    var s2: Sink = undefined;
    s2.init();
    var e2 = command.Encoder.init(testing.allocator, &s2.w, .{ .literal_plus = true });
    try encode(&e2, "T6", false, .{}, &.{ .body = &.{"a\r\nb"} });
    try testing.expectEqualStrings("T6 SEARCH BODY {4+}\r\na\r\nb\r\n", s2.out());
}

test "fuzz: no SEARCH set or flag can put a second command line on the wire" {
    try testing.fuzz({}, fuzzEncode, .{});
}

/// Only the unframed criteria are driven here — `seq_set`, `uid_set` and the
/// flag keys. `body`/`text`/`header` values are deliberately left out: those go
/// through `string`, which may emit a literal whose payload legitimately holds
/// a CR, and mixing them in would make the invariant untestable rather than
/// stronger.
fn fuzzEncode(_: void, smith: *std.testing.Smith) !void {
    var raw: [96]u8 = undefined;
    smith.bytes(&raw);
    const seq = raw[0..smith.valueRangeAtMost(u8, 0, 32)];
    const uid = raw[32..][0..smith.valueRangeAtMost(u8, 0, 32)];
    const flag_key = raw[64..][0..smith.valueRangeAtMost(u8, 0, 32)];

    var buf: [1024]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    var e = command.Encoder.init(std.testing.allocator, &w, .{});

    const inner = Criteria{
        .seq_set = if (smith.value(bool)) seq else null,
        .flag = &.{flag_key},
    };
    const crit = Criteria{
        .uid_set = if (smith.value(bool)) uid else null,
        .larger = smith.value(u32),
        .not = &.{&inner},
    };
    if (encode(&e, "T1", smith.value(bool), .{ .count = smith.value(bool) }, &crit)) |_| {
        const line = w.buffered();
        std.debug.assert(std.mem.endsWith(u8, line, "\r\n"));
        const body = line[0 .. line.len - 2];
        std.debug.assert(std.mem.indexOfScalar(u8, body, '\r') == null);
        std.debug.assert(std.mem.indexOfScalar(u8, body, '\n') == null);
        std.debug.assert(std.mem.indexOfScalar(u8, body, 0) == null);
    } else |_| {
        std.debug.assert(w.buffered().len == 0);
    }
}
