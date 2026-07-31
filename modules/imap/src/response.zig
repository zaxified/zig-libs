// SPDX-License-Identifier: MIT

//! Server responses (RFC 9051 §7), read one line at a time on top of `wire`.
//!
//! Every line a server sends is one of three shapes:
//!
//!   * `+ text` — a continuation request: send the rest of your command;
//!   * `TAG OK/NO/BAD ...` — the completion of the command carrying that tag;
//!   * `* ...` — untagged data, which may arrive at any time and is **not**
//!     necessarily a reply to anything the client just sent.
//!
//! Ported from `emersion/go-imap` v2 `imapclient/client.go`'s `readResponse`
//! family (MIT — see `modules/imap/NOTICE`), including the tolerances it
//! carries for real servers.
//!
//! **Everything returned borrows from the allocator handed to `Reader.init`.**
//! The intended use is an arena reset after each response is consumed; nothing
//! here frees individually.

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const wire = @import("wire.zig");
const fetchmod = @import("fetch.zig");
const searchmod = @import("search.zig");

pub const Error = wire.Error || fetchmod.Error || searchmod.Error || error{
    /// A status word that is not OK / NO / BAD / PREAUTH / BYE.
    BadStatus,
    /// A tagged response may only carry OK, NO or BAD.
    BadTaggedStatus,
};

/// RFC 9051 §7.1.
pub const StatusType = enum {
    ok,
    no,
    bad,
    preauth,
    bye,

    pub fn parse(s: []const u8) ?StatusType {
        const table = .{
            .{ "OK", StatusType.ok },
            .{ "NO", StatusType.no },
            .{ "BAD", StatusType.bad },
            .{ "PREAUTH", StatusType.preauth },
            .{ "BYE", StatusType.bye },
        };
        inline for (table) |e| {
            if (std.ascii.eqlIgnoreCase(s, e[0])) return e[1];
        }
        return null;
    }
};

/// The optional `[...]` in a status response. Codes this client acts on are
/// parsed; anything else keeps its name and drops its arguments, which is what
/// lets an unknown extension pass through without desynchronising the stream.
pub const Code = union(enum) {
    none,
    alert,
    capability: []const []const u8,
    permanent_flags: []const []const u8,
    uid_validity: u32,
    uid_next: u32,
    unseen: u32,
    read_only,
    read_write,
    try_create,
    other: []const u8,
};

pub const Status = struct {
    type: StatusType,
    code: Code = .none,
    /// Absent when the server sent none. RFC 9051 requires one; some servers
    /// omit it (go-imap issues 500 and 502).
    text: ?[]const u8 = null,
};

/// Untagged data (`*`).
pub const Data = union(enum) {
    status: Status,
    capability: []const []const u8,
    flags: []const []const u8,
    exists: u32,
    recent: u32,
    expunge: u32,
    /// `* n FETCH (...)`
    fetch: fetchmod.Message,
    /// `* SEARCH ...` — the IMAP4rev1 shape, with no tag to correlate on.
    search: searchmod.Result,
    /// `* ESEARCH (TAG "x") ...` — the IMAP4rev2 shape.
    esearch: searchmod.Result,
    /// A kind this module does not parse yet. `rest` is the remainder of the
    /// line, verbatim, so a caller can handle it and the reader stays in sync.
    other: struct {
        kind: []const u8,
        number: ?u32 = null,
        rest: ?[]const u8 = null,
    },
};

pub const Response = union(enum) {
    /// `+ [text]`
    continuation: ?[]const u8,
    /// `TAG OK|NO|BAD ...`
    tagged: struct { tag: []const u8, status: Status },
    /// `* ...`
    data: Data,
};

pub const Reader = struct {
    d: wire.Decoder,
    fetch_opts: fetchmod.Options = .{},

    pub fn init(gpa: Allocator, r: *std.Io.Reader, opts: wire.Options) Reader {
        return .{ .d = wire.Decoder.init(gpa, r, opts) };
    }

    /// Read exactly one response line.
    pub fn next(self: *Reader) Error!Response {
        const d = &self.d;

        if (try d.accept('+')) {
            // Continuation. The text is optional -- servers commonly send a
            // bare "+" when the payload is a SASL challenge of zero length.
            var text: ?[]const u8 = null;
            if (try d.sp()) text = try d.text();
            try d.expectCrlf();
            return .{ .continuation = text };
        }

        const untagged = try d.accept('*');
        const tag: ?[]const u8 = if (untagged) null else try d.expectAtom();
        try d.expectSp();
        const word = try d.expectAtom();

        if (tag) |t| {
            const st = StatusType.parse(word) orelse return error.BadStatus;
            // resp-cond-state is OK / NO / BAD only: a tagged PREAUTH or BYE
            // would mean the connection changed state as a command result,
            // which the grammar does not allow.
            switch (st) {
                .ok, .no, .bad => {},
                .preauth, .bye => return error.BadTaggedStatus,
            }
            const status = try self.readStatusTail(st);
            try d.expectCrlf();
            return .{ .tagged = .{ .tag = t, .status = status } };
        }

        return .{ .data = try self.readData(word) };
    }

    /// `* ...` — the word already read is either a status, a data kind, or a
    /// NUMBER that prefixes the real kind (`* 172 EXISTS`).
    fn readData(self: *Reader, first: []const u8) Error!Data {
        const d = &self.d;

        var number: ?u32 = null;
        var word = first;
        if (first.len > 0 and std.ascii.isDigit(first[0])) {
            number = std.fmt.parseInt(u32, first, 10) catch return error.BadNumber;
            try d.expectSp();
            word = try d.expectAtom();
        }

        if (StatusType.parse(word)) |st| {
            const status = try self.readStatusTail(st);
            try d.expectCrlf();
            return .{ .status = status };
        }

        if (std.ascii.eqlIgnoreCase(word, "CAPABILITY")) {
            const caps = try self.readCapabilities();
            try d.expectCrlf();
            return .{ .capability = caps };
        }

        if (std.ascii.eqlIgnoreCase(word, "FLAGS")) {
            try d.expectSp();
            const flags = try self.readFlagList();
            try d.expectCrlf();
            return .{ .flags = flags };
        }

        if (std.ascii.eqlIgnoreCase(word, "SEARCH")) {
            const r = try searchmod.parseSearch(d);
            try d.expectCrlf();
            return .{ .search = r };
        }
        if (std.ascii.eqlIgnoreCase(word, "ESEARCH")) {
            try d.expectSp();
            const r = try searchmod.parseESearch(d);
            try d.expectCrlf();
            return .{ .esearch = r };
        }

        if (number) |n| {
            if (std.ascii.eqlIgnoreCase(word, "FETCH")) {
                try d.expectSp();
                var p = fetchmod.Parser{ .d = d, .opts = self.fetch_opts };
                const m = try p.message(n);
                try d.expectCrlf();
                return .{ .fetch = m };
            }
            if (std.ascii.eqlIgnoreCase(word, "EXISTS")) {
                try d.expectCrlf();
                return .{ .exists = n };
            }
            if (std.ascii.eqlIgnoreCase(word, "RECENT")) {
                try d.expectCrlf();
                return .{ .recent = n };
            }
            if (std.ascii.eqlIgnoreCase(word, "EXPUNGE")) {
                try d.expectCrlf();
                return .{ .expunge = n };
            }
        }

        // Unknown kind: hand the caller the rest of the line verbatim rather
        // than guessing at its grammar, and consume the CRLF so the next
        // response starts where it should.
        var rest: ?[]const u8 = null;
        if (try d.sp()) rest = try d.text();
        try d.expectCrlf();
        return .{ .other = .{ .kind = word, .number = number, .rest = rest } };
    }

    /// Everything after the status word: an optional `[code]` and an optional
    /// text. Does NOT consume the CRLF.
    fn readStatusTail(self: *Reader, st: StatusType) Error!Status {
        const d = &self.d;

        // RFC 9051 requires a text here. Some servers send none at all, so a
        // missing SP is not an error (go-imap issues 500 and 502).
        var has_sp = try d.sp();

        var code: Code = .none;
        if (has_sp and try d.accept('[')) {
            code = try self.readCode();
            try d.expect(']');
            has_sp = try d.sp();
        }

        const text: ?[]const u8 = if (has_sp) try d.text() else null;
        return .{ .type = st, .code = code, .text = text };
    }

    fn readCode(self: *Reader) Error!Code {
        const d = &self.d;
        const name = try d.expectAtom();

        if (std.ascii.eqlIgnoreCase(name, "ALERT")) return .alert;
        if (std.ascii.eqlIgnoreCase(name, "READ-ONLY")) return .read_only;
        if (std.ascii.eqlIgnoreCase(name, "READ-WRITE")) return .read_write;
        if (std.ascii.eqlIgnoreCase(name, "TRYCREATE")) return .try_create;

        if (std.ascii.eqlIgnoreCase(name, "CAPABILITY")) {
            return .{ .capability = try self.readCapabilities() };
        }
        if (std.ascii.eqlIgnoreCase(name, "PERMANENTFLAGS")) {
            try d.expectSp();
            return .{ .permanent_flags = try self.readFlagList() };
        }
        if (std.ascii.eqlIgnoreCase(name, "UIDVALIDITY")) {
            try d.expectSp();
            return .{ .uid_validity = try d.expectNumber() };
        }
        if (std.ascii.eqlIgnoreCase(name, "UIDNEXT")) {
            try d.expectSp();
            return .{ .uid_next = try d.expectNumber() };
        }
        if (std.ascii.eqlIgnoreCase(name, "UNSEEN")) {
            try d.expectSp();
            return .{ .unseen = try d.expectNumber() };
        }

        // An extension we do not implement. Its arguments are "any text except
        // ]", so skipping to the bracket is exactly right and keeps us in sync.
        if (try d.sp()) {
            while (true) {
                const ch = d.r.peekByte() catch |e| switch (e) {
                    error.EndOfStream => return error.EndOfStream,
                    else => return error.ReadFailed,
                };
                if (ch == ']') break;
                d.r.toss(1);
            }
        }
        return .{ .other = name };
    }

    /// `capability-data` — a space-separated run of atoms to end of line.
    fn readCapabilities(self: *Reader) Error![]const []const u8 {
        const d = &self.d;
        var caps: std.ArrayList([]const u8) = .empty;
        errdefer caps.deinit(d.gpa);
        while (try d.sp()) {
            const raw = (try d.atom()) orelse break;
            try caps.append(d.gpa, try canonicalCap(d.gpa, raw));
        }
        return caps.toOwnedSlice(d.gpa);
    }

    /// `flag-list` — `(` flag *(SP flag) `)`.
    fn readFlagList(self: *Reader) Error![]const []const u8 {
        const d = &self.d;
        var flags: std.ArrayList([]const u8) = .empty;
        errdefer flags.deinit(d.gpa);

        var it = try d.expectList();
        while (try it.next()) {
            // Some servers start the list with a space (go-imap PR 633).
            _ = try d.sp();
            try flags.append(d.gpa, try self.readFlag());
        }
        return flags.toOwnedSlice(d.gpa);
    }

    fn readFlag(self: *Reader) Error![]const u8 {
        const d = &self.d;
        const system = try d.accept('\\');
        if (system and try d.accept('*')) {
            // flag-perm's wildcard: "the server supports creating keywords".
            // `*` is not an ATOM-CHAR, so it has to be taken before the atom.
            return try d.gpa.dupe(u8, "\\*");
        }
        const name = try d.expectAtom();
        if (!system) return name;
        defer d.gpa.free(name);
        return std.fmt.allocPrint(d.gpa, "\\{s}", .{name}) catch error.OutOfMemory;
    }
};

/// Capability names are case-insensitive and conventionally upper-case — with
/// exactly two exceptions, which are spelled in mixed case everywhere in the
/// RFCs and in every server's output.
fn canonicalCap(gpa: Allocator, name: []const u8) Error![]const u8 {
    for ([_][]const u8{ "IMAP4rev1", "IMAP4rev2" }) |exact| {
        if (std.ascii.eqlIgnoreCase(name, exact)) {
            gpa.free(name);
            return try gpa.dupe(u8, exact);
        }
    }
    const out = @constCast(name);
    for (out) |*ch| ch.* = std.ascii.toUpper(ch.*);
    return out;
}

// ── tests ───────────────────────────────────────────────────────────────────
//
// Tier 1 throughout: every transcript below is copied from RFC 9051's own
// worked examples. Where a behaviour has no RFC example because it exists to
// tolerate servers that break the RFC, the test says so and names the
// go-imap issue that documents the server.

const Fixture = struct {
    arena: std.heap.ArenaAllocator,
    r: std.Io.Reader,

    fn init(input: []const u8) Fixture {
        return .{
            .arena = std.heap.ArenaAllocator.init(testing.allocator),
            .r = std.Io.Reader.fixed(input),
        };
    }
    fn deinit(f: *Fixture) void {
        f.arena.deinit();
    }
    fn reader(f: *Fixture) Reader {
        return Reader.init(f.arena.allocator(), &f.r, .{});
    }
};

test "RFC 9051 §6.3.2: the whole SELECT transcript" {
    var f = Fixture.init(
        "* 172 EXISTS\r\n" ++
            "* OK [UIDVALIDITY 3857529045] UIDs valid\r\n" ++
            "* OK [UIDNEXT 4392] Predicted next UID\r\n" ++
            "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n" ++
            "* OK [PERMANENTFLAGS (\\Deleted \\Seen \\*)] Limited\r\n" ++
            "* LIST () \"/\" INBOX\r\n" ++
            "A142 OK [READ-WRITE] SELECT completed\r\n",
    );
    defer f.deinit();
    var rd = f.reader();

    try testing.expectEqual(@as(u32, 172), (try rd.next()).data.exists);

    const uidv = (try rd.next()).data.status;
    try testing.expectEqual(StatusType.ok, uidv.type);
    try testing.expectEqual(@as(u32, 3857529045), uidv.code.uid_validity);
    try testing.expectEqualStrings("UIDs valid", uidv.text.?);

    const uidn = (try rd.next()).data.status;
    try testing.expectEqual(@as(u32, 4392), uidn.code.uid_next);

    const flags = (try rd.next()).data.flags;
    try testing.expectEqual(@as(usize, 5), flags.len);
    try testing.expectEqualStrings("\\Answered", flags[0]);
    try testing.expectEqualStrings("\\Draft", flags[4]);

    const perm = (try rd.next()).data.status.code.permanent_flags;
    try testing.expectEqual(@as(usize, 3), perm.len);
    try testing.expectEqualStrings("\\Deleted", perm[0]);
    // The wildcard: `*` is not an ATOM-CHAR, so a parser that only reads atoms
    // after the backslash loses it -- and with it, "keywords may be created".
    try testing.expectEqualStrings("\\*", perm[2]);

    // LIST is not parsed yet; it must still come back intact and in sync.
    const list = (try rd.next()).data.other;
    try testing.expectEqualStrings("LIST", list.kind);
    try testing.expectEqualStrings("() \"/\" INBOX", list.rest.?);

    const done = (try rd.next()).tagged;
    try testing.expectEqualStrings("A142", done.tag);
    try testing.expectEqual(StatusType.ok, done.status.type);
    try testing.expectEqual(Code.read_write, done.status.code);
    try testing.expectEqualStrings("SELECT completed", done.status.text.?);
}

test "RFC 9051 §6.1.1: CAPABILITY, and the two mixed-case names" {
    var f = Fixture.init(
        "* CAPABILITY IMAP4rev2 STARTTLS AUTH=GSSAPI LOGINDISABLED\r\n" ++
            "abcd OK CAPABILITY completed\r\n",
    );
    defer f.deinit();
    var rd = f.reader();

    const caps = (try rd.next()).data.capability;
    try testing.expectEqual(@as(usize, 4), caps.len);
    // Upper-cased, except IMAP4rev1/rev2 which keep their spelling everywhere.
    try testing.expectEqualStrings("IMAP4rev2", caps[0]);
    try testing.expectEqualStrings("STARTTLS", caps[1]);
    try testing.expectEqualStrings("AUTH=GSSAPI", caps[2]);
    try testing.expectEqualStrings("LOGINDISABLED", caps[3]);

    const done = (try rd.next()).tagged;
    try testing.expectEqualStrings("abcd", done.tag);
}

test "capability names are case-insensitive on the wire" {
    var f = Fixture.init("* CAPABILITY imap4rev2 starttls IdLe\r\n");
    defer f.deinit();
    var rd = f.reader();
    const caps = (try rd.next()).data.capability;
    try testing.expectEqualStrings("IMAP4rev2", caps[0]);
    try testing.expectEqualStrings("STARTTLS", caps[1]);
    try testing.expectEqualStrings("IDLE", caps[2]);
}

test "RFC 9051 §7.1.5: the greeting, and BYE" {
    var f = Fixture.init(
        "* OK [CAPABILITY IMAP4rev2 STARTTLS] IMAP4rev2 Service Ready\r\n" ++
            "* BYE Autologout; idle for too long\r\n",
    );
    defer f.deinit();
    var rd = f.reader();

    const greeting = (try rd.next()).data.status;
    try testing.expectEqual(StatusType.ok, greeting.type);
    // The greeting carries capabilities INSIDE the response code, which is how
    // a client avoids a round trip before STARTTLS.
    try testing.expectEqual(@as(usize, 2), greeting.code.capability.len);
    try testing.expectEqualStrings("IMAP4rev2", greeting.code.capability[0]);
    try testing.expectEqualStrings("IMAP4rev2 Service Ready", greeting.text.?);

    const bye = (try rd.next()).data.status;
    try testing.expectEqual(StatusType.bye, bye.type);
    try testing.expectEqualStrings("Autologout; idle for too long", bye.text.?);
}

test "continuation request, with and without text" {
    var f = Fixture.init("+ Ready for additional command text\r\n+ \r\n+\r\n");
    defer f.deinit();
    var rd = f.reader();

    try testing.expectEqualStrings(
        "Ready for additional command text",
        (try rd.next()).continuation.?,
    );
    // "+ " with nothing after it, and a bare "+" -- both are what servers send
    // for a zero-length SASL challenge.
    try testing.expect((try rd.next()).continuation == null);
    try testing.expect((try rd.next()).continuation == null);
}

test "a NO with a code the client acts on" {
    var f = Fixture.init("A003 NO [TRYCREATE] No such mailbox\r\n");
    defer f.deinit();
    var rd = f.reader();
    const t = (try rd.next()).tagged;
    try testing.expectEqual(StatusType.no, t.status.type);
    try testing.expectEqual(Code.try_create, t.status.code);
    try testing.expectEqualStrings("No such mailbox", t.status.text.?);
}

test "tolerance: a status response with no text at all" {
    // RFC 9051 requires the text. Servers omit it (go-imap issues 500, 502),
    // and treating that as a parse error would fail the whole command.
    var f = Fixture.init("A001 OK\r\n* OK\r\n");
    defer f.deinit();
    var rd = f.reader();

    const t = (try rd.next()).tagged;
    try testing.expectEqual(StatusType.ok, t.status.type);
    try testing.expect(t.status.text == null);

    const u = (try rd.next()).data.status;
    try testing.expect(u.text == null);
}

test "tolerance: a flag list that starts with a space" {
    // go-imap PR 633 -- a real server does this.
    var f = Fixture.init("* FLAGS ( \\Seen \\Draft)\r\n");
    defer f.deinit();
    var rd = f.reader();
    const flags = (try rd.next()).data.flags;
    try testing.expectEqual(@as(usize, 2), flags.len);
    try testing.expectEqualStrings("\\Seen", flags[0]);
    try testing.expectEqualStrings("\\Draft", flags[1]);
}

test "an unknown response code is skipped without losing the line" {
    var f = Fixture.init("A001 OK [FUTUREEXTENSION 1 2 (3 4)] done\r\n");
    defer f.deinit();
    var rd = f.reader();
    const t = (try rd.next()).tagged;
    try testing.expectEqualStrings("FUTUREEXTENSION", t.status.code.other);
    // The point of skipping rather than failing: the text after it survives.
    try testing.expectEqualStrings("done", t.status.text.?);
}

test "an unknown untagged kind keeps its number and its remainder" {
    // A kind this module does not model at all -- VANISHED belongs to QRESYNC.
    var f = Fixture.init("* 42 VANISHED (EARLIER) 41:42\r\nA1 OK done\r\n");
    defer f.deinit();
    var rd = f.reader();

    const o = (try rd.next()).data.other;
    try testing.expectEqualStrings("VANISHED", o.kind);
    try testing.expectEqual(@as(u32, 42), o.number.?);
    try testing.expectEqualStrings("(EARLIER) 41:42", o.rest.?);

    // ...and the reader is still in sync for the next line, which is the whole
    // reason for handing back the remainder instead of erroring.
    try testing.expectEqualStrings("A1", (try rd.next()).tagged.tag);
}

test "keyword flags (no backslash) survive alongside system flags" {
    var f = Fixture.init("* FLAGS (\\Seen $Forwarded NonJunk)\r\n");
    defer f.deinit();
    var rd = f.reader();
    const flags = (try rd.next()).data.flags;
    try testing.expectEqualStrings("\\Seen", flags[0]);
    try testing.expectEqualStrings("$Forwarded", flags[1]);
    try testing.expectEqualStrings("NonJunk", flags[2]);
}

test "a tagged response may not carry PREAUTH or BYE" {
    // resp-cond-state is OK / NO / BAD. PREAUTH is a greeting and BYE is
    // untagged; either as a command completion means the peer is confused
    // about connection state, which is not something to accept quietly.
    var f = Fixture.init("A001 PREAUTH ok\r\n");
    defer f.deinit();
    var rd = f.reader();
    try testing.expectError(error.BadTaggedStatus, rd.next());
}

test "an unknown status word is an error, not silently ignored" {
    var f = Fixture.init("A001 MAYBE something\r\n");
    defer f.deinit();
    var rd = f.reader();
    try testing.expectError(error.BadStatus, rd.next());
}

test "EXISTS / RECENT / EXPUNGE all take their number from the prefix" {
    var f = Fixture.init("* 23 EXISTS\r\n* 5 RECENT\r\n* 44 EXPUNGE\r\n");
    defer f.deinit();
    var rd = f.reader();
    try testing.expectEqual(@as(u32, 23), (try rd.next()).data.exists);
    try testing.expectEqual(@as(u32, 5), (try rd.next()).data.recent);
    try testing.expectEqual(@as(u32, 44), (try rd.next()).data.expunge);
}

test "FETCH, SEARCH and ESEARCH now come back parsed, not as raw text" {
    var f = Fixture.init(
        "* 12 FETCH (UID 4827313 FLAGS (\\Seen))\r\n" ++
            "* SEARCH 2 84 882\r\n" ++
            "* ESEARCH (TAG \"A282\") MIN 2 COUNT 3\r\n",
    );
    defer f.deinit();
    var rd = f.reader();

    const m = (try rd.next()).data.fetch;
    try testing.expectEqual(@as(u32, 12), m.seq);
    try testing.expectEqual(@as(u32, 4827313), m.uid().?);

    const s1 = (try rd.next()).data.search;
    try testing.expectEqual(@as(usize, 3), s1.numbers.len);

    const s2 = (try rd.next()).data.esearch;
    try testing.expectEqualStrings("A282", s2.tag.?);
    try testing.expectEqual(@as(u32, 3), s2.count.?);
}
