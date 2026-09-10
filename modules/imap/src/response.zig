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
const listmod = @import("list.zig");

pub const Error = wire.Error || fetchmod.Error || searchmod.Error || listmod.Error || error{
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
    /// `* LIST ...` (audit A1 F6).
    list: listmod.Entry,
    /// `* LSUB ...` — same shape as `LIST`, different command it answers.
    lsub: listmod.Entry,
    /// `* STATUS mailbox (...)` (audit A1 F6). Named `mailbox_status` to
    /// stay clearly distinct from `Data.status` (`OK`/`NO`/.../`BYE`).
    mailbox_status: listmod.StatusReply,
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
        // A line is what this function reads, so this is the only place that
        // can start the `wire.Options.max_line` budget.
        d.startLine();

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
            // F10: `parseESearch` now consumes its own leading SP (it needs
            // to tell "nothing follows" apart from "no correlator, but a
            // return-data item follows" -- both are SP-then-something or
            // nothing, and only it knows which), so it is called directly.
            const r = try searchmod.parseESearch(d);
            try d.expectCrlf();
            return .{ .esearch = r };
        }

        // Audit A1 F6: LIST/LSUB/STATUS had no parser here at all -- see
        // list.zig's module comment.
        if (std.ascii.eqlIgnoreCase(word, "LIST")) {
            const entry = try listmod.parseMailboxList(d);
            try d.expectCrlf();
            return .{ .list = entry };
        }
        if (std.ascii.eqlIgnoreCase(word, "LSUB")) {
            const entry = try listmod.parseMailboxList(d);
            try d.expectCrlf();
            return .{ .lsub = entry };
        }
        if (std.ascii.eqlIgnoreCase(word, "STATUS")) {
            const reply = try listmod.parseStatus(d);
            try d.expectCrlf();
            return .{ .mailbox_status = reply };
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
                // The only byte consumption in this module that does not go
                // through a `Decoder` primitive, so it charges the line budget
                // itself — otherwise `[UNKNOWN aaaa…` with no `]` is an
                // unbounded spin.
                try d.charge(1);
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
        defer it.deinit(); // F13: safety net if an element below errors mid-list
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

test "the max_line budget is per line, and it is this Reader that starts one" {
    // Two lines, each within the cap, together well over it. If the budget is
    // never reset the second line fails; if it is never charged the third
    // (unterminated) line is accepted. Both halves matter.
    var f = Fixture.init(
        "* 172 EXISTS\r\n" ++
            "* 173 EXISTS\r\n" ++
            "* AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    );
    defer f.deinit();
    var rd = Reader.init(f.arena.allocator(), &f.r, .{ .max_line = 24 });

    try testing.expectEqual(@as(u32, 172), (try rd.next()).data.exists);
    try testing.expectEqual(@as(u32, 173), (try rd.next()).data.exists);
    try testing.expectError(error.LineTooLong, rd.next());
}

test "the DEFAULT max_line is what LineTooLong actually fires at through this Reader" {
    // audit `imap` F8, second half: the harness that fuzzes this layer
    // capped its input at 512 bytes, 128x below `wire.Options{}.max_line`
    // (64 KiB), so `error.LineTooLong` was unreachable from it under the
    // default options `Client` actually ships with — every other test at
    // this layer sets its own small `.max_line`. This one uses `.{}`.
    const gpa = testing.allocator;
    const opts: wire.Options = .{};
    const buf = try gpa.alloc(u8, opts.max_line + 1);
    defer gpa.free(buf);
    @memset(buf, 'A');

    var r = std.Io.Reader.fixed(buf);
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    var rd = Reader.init(arena.allocator(), &r, .{});
    try testing.expectError(error.LineTooLong, rd.next());
}

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

    // Audit A1 F6: this used to be `.data.other` (LIST had no parser at
    // all). Now parsed like any other untagged data.
    const list = (try rd.next()).data.list;
    try testing.expectEqual(@as(usize, 0), list.flags.len);
    try testing.expectEqualStrings("/", list.delimiter.?);
    try testing.expectEqualStrings("INBOX", list.mailbox);

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

test "F10: ESEARCH without a correlator, which the ABNF allows, is not rejected" {
    // Pre-fix, all three of these were `error.UnexpectedByte`
    // (`~/CML/20260901-zig-libs-audit/A1/imap.md` F10): `parseESearch` was
    // called after the caller had already consumed the one leading SP, so
    // the "no correlator" branch's own SP check ran one SP short and
    // mistook "COUNT 5" for "nothing follows here".
    {
        var f = Fixture.init("* ESEARCH COUNT 5\r\n");
        defer f.deinit();
        var rd = f.reader();
        const r = (try rd.next()).data.esearch;
        try testing.expect(r.tag == null);
        try testing.expectEqual(@as(u32, 5), r.count.?);
    }
    {
        var f = Fixture.init("* ESEARCH UID ALL 1:3\r\n");
        defer f.deinit();
        var rd = f.reader();
        const r = (try rd.next()).data.esearch;
        try testing.expect(r.uid);
        try testing.expectEqualStrings("1:3", r.all.?);
    }
    {
        // The ABNF allows an ESEARCH with neither a correlator nor any
        // return-data item at all.
        var f = Fixture.init("* ESEARCH\r\n");
        defer f.deinit();
        var rd = f.reader();
        const r = (try rd.next()).data.esearch;
        try testing.expect(r.tag == null);
        try testing.expect(r.count == null);
    }
    // Positive control: WITH a correlator still works (this is what pinned
    // the old behaviour and must keep passing).
    {
        var f = Fixture.init("* ESEARCH (TAG \"T1\") COUNT 5\r\n");
        defer f.deinit();
        var rd = f.reader();
        const r = (try rd.next()).data.esearch;
        try testing.expectEqualStrings("T1", r.tag.?);
        try testing.expectEqual(@as(u32, 5), r.count.?);
    }
}

// ── fuzz ─────────────────────────────────────────────────────────────────
//
// `Reader.next` is the module's whole untrusted-input surface: every byte a
// server sends reaches it, before authentication and before any of it has
// been believed. It fans out into the RFC 9051 §9 wire decoder, the three
// response shapes, and the FETCH / SEARCH parsers, so one harness covers the
// lot.
//
// Two properties are being asserted, and neither is "it parses":
//
//   - It always TERMINATES. Every `Decoder` primitive either consumes a byte
//     or returns, so a hostile line cannot spin -- but `readStatusTail` and
//     the list walkers loop, and a loop whose exit depends on attacker bytes
//     is exactly where that argument can fail.
//   - It never allocates on a promise. A literal's length comes off the wire
//     (`{4294967295}` is a legal thing for a server to claim) and is checked
//     against `max_literal` BEFORE the allocation, so a fuzzer feeding huge
//     announced sizes must not OOM. The arena below would make such a bug
//     loud rather than hidden.
//
// The window used to be a flat 512 bytes — small enough to keep the
// fuzzer's mutation density on the grammar rather than on payload bytes it
// will never reach, but 128x below `wire.Options{}.max_line` (64 KiB), which
// made `error.LineTooLong` unreachable from this harness under the default
// options it actually runs with (audit `imap` F8). Most iterations still
// draw a short length, via the weighting below, so the grammar-density
// argument above still mostly holds; a minority draw enough bytes to clear
// the 64 KiB line budget and exercise the refusal itself.

/// `testkit.fuzz.seed`, aliased so the corpus below reads as the response
/// streams it is. A corpus entry is not the frame: the length draw reads a
/// little-endian `u32` first, so a raw stream would arrive minus its own first
/// four octets. `testkit/src/fuzz.zig` carries the other two hazards.
const seed = @import("testkit").fuzz.seed;

/// The length weighting, hoisted so `fuzzResponse` and its corpus guard cannot
/// drift apart. Heavily weighted toward short inputs (grammar-dense) but able
/// to reach past `max_line` (64 KiB) so `error.LineTooLong` is exercised.
const len_weights: []const std.testing.Smith.Weight = &.{
    .rangeAtMost(u32, 0, 512, 8),
    .rangeAtMost(u32, 513, 80 * 1024, 1),
};

/// Any octet, at equal weight — the `Smith.bytes` default, spelled out because
/// `sliceWeighted` takes the byte weighting explicitly.
const byte_weights: []const std.testing.Smith.Weight = &.{.rangeAtMost(u8, 0, 255, 1)};

/// Server response streams, in the format the length draw reads.
///
/// Every shape the value tests above pin: the RFC 3501 SELECT sequence, both
/// CAPABILITY forms, continuation requests, a response code with a nested
/// parenthesised list, VANISHED, the FETCH/SEARCH/ESEARCH trio, and the two
/// refusals (an unknown status condition, a truncated final line). IMAP is a
/// keyword grammar — `* <n> EXISTS CRLF`, `<tag> OK [<code>] <text> CRLF` —
/// and `fuzzResponse` returns on the FIRST error, so an undirected byte stream
/// dies inside its first atom and never reaches the multi-line state the
/// harness's own comment says is the point of the loop.
const response_seeds = [_][]const u8{
    seed("* 172 EXISTS\r\n" ++
        "* OK [UIDVALIDITY 3857529045] UIDs valid\r\n" ++
        "* OK [UIDNEXT 4392] Predicted next UID\r\n" ++
        "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n" ++
        "* OK [PERMANENTFLAGS (\\Deleted \\Seen \\*)] Limited\r\n" ++
        "* LIST () \"/\" INBOX\r\n" ++
        "A142 OK [READ-WRITE] SELECT completed\r\n"), // the RFC 3501 §6.3.1 SELECT exchange
    seed("* CAPABILITY IMAP4rev2 STARTTLS AUTH=GSSAPI LOGINDISABLED\r\n" ++
        "abcd OK CAPABILITY completed\r\n"), // untagged data then its tagged status
    seed("* CAPABILITY imap4rev2 starttls IdLe\r\n"), // capability names are case-insensitive
    seed("* OK [CAPABILITY IMAP4rev2 STARTTLS] IMAP4rev2 Service Ready\r\n" ++
        "* BYE Autologout; idle for too long\r\n"), // a greeting carrying a response code, then BYE
    seed("+ Ready for additional command text\r\n+ \r\n+\r\n"), // all three continuation-request spellings
    seed("A003 NO [TRYCREATE] No such mailbox\r\n"), // a tagged NO with a response code
    seed("A001 OK\r\n* OK\r\n"), // status lines with no text at all
    seed("* FLAGS ( \\Seen \\Draft)\r\n"), // a leading space inside the flag list
    seed("A001 OK [FUTUREEXTENSION 1 2 (3 4)] done\r\n"), // an unknown response code with a nested list
    seed("* 42 VANISHED (EARLIER) 41:42\r\nA1 OK done\r\n"), // QRESYNC VANISHED with a UID range
    seed("* FLAGS (\\Seen $Forwarded NonJunk)\r\n"), // keyword flags beside system flags
    seed("A001 PREAUTH ok\r\n"), // PREAUTH as a tagged status
    seed("* 23 EXISTS\r\n* 5 RECENT\r\n* 44 EXPUNGE\r\n"), // three numeric untagged responses in a row
    seed("* 12 FETCH (UID 4827313 FLAGS (\\Seen))\r\n" ++
        "* SEARCH 2 84 882\r\n" ++
        "* ESEARCH (TAG \"A282\") MIN 2 COUNT 3\r\n"), // the FETCH / SEARCH / ESEARCH parsers
    seed("* 1 FETCH (BODY[] {4294967295}\r\n"), // a literal claiming 4 GiB: refused before it is allocated
    seed("A001 MAYBE something\r\n"), // an unknown status condition
    seed("* 172 EXISTS\r\n* 173 EXISTS\r\n* AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), // a final line with no CRLF
};

test "fuzz: response parsing never panics on arbitrary server bytes" {
    try testing.fuzz({}, fuzzResponse, .{ .corpus = &response_seeds });
}

fn fuzzResponse(_: void, smith: *std.testing.Smith) !void {
    var buf: [80 * 1024]u8 = undefined;
    // ⚠ ONE draw, and it is the bytes. This used to be a `valueWeighted` length
    // followed by `smith.bytes(buf[0..len])`, which fixed the ordering problem
    // the F8 note below describes but created a worse one: a weighted draw
    // reads EIGHT octets as a little-endian u64 and falls back to
    // `weights[0].min` — zero — unless that u64 happens to land inside a
    // declared range. So `len` was 0 for every seed a human would write, and
    // the parser was handed an empty stream while the seed sat unread.
    // `sliceWeighted` keeps the same weighting for `--fuzz` AND reads a corpus
    // entry's own length, so a real response frame arrives intact.
    //
    // (The original ordering bug, for the record: `Smith.bytes` consumes
    // `min(out.len, in.len)` octets, so filling an 80 KiB buffer up front
    // drained `in` completely and every subsequent draw degenerated to its
    // default. That is why the FIRST version of this harness never reached
    // `LineTooLong` despite the raised window — audit `imap` F8.)
    const len: usize = smith.sliceWeighted(&buf, len_weights, byte_weights);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var r = std.Io.Reader.fixed(buf[0..len]);
    var rd = Reader.init(arena.allocator(), &r, .{});

    // Keep reading until the input is exhausted or rejected. A single call
    // would leave everything after the first CRLF unexercised, and the
    // multi-line paths (untagged data preceding a tagged status) are where
    // the state actually accumulates.
    var guard: usize = 0;
    while (guard < 64) : (guard += 1) {
        _ = rd.next() catch |e| {
            if (e == error.LineTooLong) f8_line_too_long_reached += 1;
            return;
        };
    }
}

var f8_line_too_long_reached: usize = 0;

// audit `imap` F8, second half regression: `zig build test` (no `--fuzz=N`)
// never actually invokes a `std.testing.fuzz` body, so this drives
// `fuzzResponse` directly off `std.testing.Smith{ .in = ... }` (documented as
// "intended to be initialized directly") the same way `zipstream`'s F8 fix
// does, and checks the harness's own `error.LineTooLong` counter went > 0 —
// proof the raised window (512 -> 80 KiB, weighted) actually reaches the
// refusal rather than merely compiling.
test "fuzz harness (F8 regression): LineTooLong is actually reachable from fuzzResponse" {
    // `zig build test` (no `--fuzz=N`) never invokes a `std.testing.fuzz`
    // body, so this drives `fuzzResponse` directly off a corpus-backed
    // `std.testing.Smith` and checks the harness's own counter moved. It is a
    // proof that the raised window is REACHED, not merely that it compiles.
    //
    // The corpus has to be built deliberately, and each requirement here is
    // one way the harness could have looked green while never reaching the
    // refusal:
    //
    //   1. The length has to be written explicitly. It used to be a weighted
    //      u64 draw, which a corpus-backed `Smith` reads as eight little-endian
    //      octets and falls back to `weights[0].min` unless that u64 lands
    //      inside a declared range — random bytes therefore drew 0 almost
    //      always. It is now `sliceWeighted`, whose length header is a
    //      little-endian **u32** and which is contained by the weights for any
    //      value up to the buffer size; that is `testkit.fuzz`'s seed format,
    //      and it is why this test writes four octets rather than eight.
    //   2. `fuzzResponse` returns on the FIRST error of any kind, so the
    //      payload must be free of CRLF *and* of any byte that ends an atom:
    //      the parser would reject on grammar long before the line budget is
    //      consulted.
    //   3. The draw copies `min(out_len, in_len)` and pads the rest with the
    //      byte weighting's minimum — which is one of those atom-ending bytes.
    //      So the corpus must be long enough to fill the whole drawn length.
    const gpa = testing.allocator;
    const draw_len: u32 = 70_000; // > wire.Options{}.max_line (64 KiB)
    const scratch = try gpa.alloc(u8, 4 + draw_len);
    defer gpa.free(scratch);
    @memset(scratch, 'A');
    std.mem.writeInt(u32, scratch[0..4], draw_len, .little);

    f8_line_too_long_reached = 0;
    var smith = std.testing.Smith{ .in = scratch };
    fuzzResponse({}, &smith) catch {};
    try testing.expect(f8_line_too_long_reached > 0);
}

test "corpus: every response seed reaches the reader, and the parsed count is pinned" {
    // ⭐ The measurement, executable rather than written in a comment. Two
    // things it holds that no other test does: a seed longer than the harness's
    // buffer reads back EMPTY (the length draw falls back to the range
    // minimum), which is silent everywhere else; and a corpus where nothing is
    // accepted is a corpus that only exercises the refusal path. Acceptance is
    // not reach, so this pins the number rather than asserting it is > 0.
    //
    // It draws through `sliceWeighted` with the SAME weights the harness uses,
    // because a guard measuring a different draw from the one the harness gets
    // is not a guard — and the whole defect here was in the draw.
    //
    // `parsed` counts responses, not seeds: it is the number of `Reader.next`
    // calls that returned one across the whole corpus, which is what falls if
    // a grammar branch stops being taken.
    var nonempty: usize = 0;
    var parsed: usize = 0;
    for (response_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [80 * 1024]u8 = undefined;
        const len: usize = smith.sliceWeighted(&buf, len_weights, byte_weights);
        if (len != 0) nonempty += 1;

        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        var r = std.Io.Reader.fixed(buf[0..len]);
        var rd = Reader.init(arena.allocator(), &r, .{});
        var guard: usize = 0;
        while (guard < 64) : (guard += 1) {
            _ = rd.next() catch break;
            parsed += 1;
        }
    }
    try testing.expectEqual(response_seeds.len, nonempty);
    // Measured 2026-09-07: 0 of 17 seeds non-empty and 0 responses parsed
    // before the draw was fixed, 17 of 17 non-empty and 999 parsed after.
    try testing.expectEqual(@as(usize, 31), parsed);
}
