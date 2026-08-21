// SPDX-License-Identifier: MIT

//! `FETCH` (RFC 9051 §6.4.5 and §7.5.2): what to ask for, and how to read the
//! `msg-att` list that comes back — `ENVELOPE`, `BODYSTRUCTURE`, body
//! sections, flags, sizes, UIDs.
//!
//! Ported from `emersion/go-imap` v2 `imapclient/fetch.go` (MIT — see
//! `modules/imap/NOTICE`).
//!
//! ## BODYSTRUCTURE recurses, so it is bounded
//!
//! A multipart body contains bodies, which may themselves be multipart, and a
//! `message/rfc822` part contains a whole nested message with its own
//! structure. The grammar therefore has no depth limit of its own, and the
//! input arrives from the network — so `Options.max_depth` bounds it, and the
//! bound is enforced on entry to each nested body rather than discovered when
//! the stack runs out.
//!
//! Everything returned borrows from the decoder's allocator; the session hands
//! it an arena that is reset once per response.

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const wire = @import("wire.zig");
const command = @import("command.zig");

pub const Error = wire.Error || error{
    /// A `body-fld-param` list with an odd number of strings.
    ParamWithoutValue,
    /// More nested bodies than `Options.max_depth`.
    BodyTooDeep,
    /// A `msg-att` name this parser does not know how to skip.
    UnknownAttribute,
};

pub const Options = struct {
    /// Nesting limit for `BODYSTRUCTURE`. A real message nests two or three
    /// deep; anything near this is a malformed or hostile server.
    max_depth: usize = 64,
};

// ── envelope ────────────────────────────────────────────────────────────────

/// One `address` (RFC 9051 §7.5.2). A group marker is an address with a null
/// `host`: the start carries the group name in `mailbox`, the end has both
/// null.
pub const Address = struct {
    name: ?[]const u8 = null,
    /// The obsolete source route (`adl`), kept because the grammar has it.
    route: ?[]const u8 = null,
    mailbox: ?[]const u8 = null,
    host: ?[]const u8 = null,

    pub fn isGroupStart(a: Address) bool {
        return a.host == null and a.mailbox != null;
    }
    pub fn isGroupEnd(a: Address) bool {
        return a.host == null and a.mailbox == null;
    }
};

pub const Envelope = struct {
    /// Kept as sent. Parsing RFC 5322 dates is a separate concern (`datefmt`),
    /// and a malformed date must not fail the whole FETCH.
    date: ?[]const u8 = null,
    subject: ?[]const u8 = null,
    from: []const Address = &.{},
    sender: []const Address = &.{},
    reply_to: []const Address = &.{},
    to: []const Address = &.{},
    cc: []const Address = &.{},
    bcc: []const Address = &.{},
    in_reply_to: ?[]const u8 = null,
    message_id: ?[]const u8 = null,
};

// ── body structure ──────────────────────────────────────────────────────────

pub const Param = struct { key: []const u8, value: []const u8 };

pub const Disposition = struct {
    value: []const u8,
    params: []const Param = &.{},
};

pub const SinglePartExt = struct {
    md5: ?[]const u8 = null,
    disposition: ?Disposition = null,
    language: []const []const u8 = &.{},
    location: ?[]const u8 = null,
};

pub const MultiPartExt = struct {
    params: []const Param = &.{},
    disposition: ?Disposition = null,
    language: []const []const u8 = &.{},
    location: ?[]const u8 = null,
};

pub const SinglePart = struct {
    type: []const u8,
    subtype: []const u8,
    params: []const Param = &.{},
    id: ?[]const u8 = null,
    description: ?[]const u8 = null,
    /// `NIL` here means 7bit: the field is required, and servers that omit it
    /// mean the default rather than "unknown".
    encoding: []const u8 = "7bit",
    size: u32 = 0,
    /// `text/*` only.
    num_lines: ?i64 = null,
    /// `message/rfc822` and `message/global` only.
    message: ?*const NestedMessage = null,
    ext: ?SinglePartExt = null,
};

pub const NestedMessage = struct {
    envelope: Envelope,
    body: *const BodyStructure,
    num_lines: i64,
};

pub const MultiPart = struct {
    children: []const *const BodyStructure,
    subtype: []const u8,
    ext: ?MultiPartExt = null,
};

pub const BodyStructure = union(enum) {
    single: SinglePart,
    multi: MultiPart,

    pub fn mediaType(bs: BodyStructure, buf: []u8) ![]const u8 {
        return switch (bs) {
            .single => |s| std.fmt.bufPrint(buf, "{s}/{s}", .{ s.type, s.subtype }),
            .multi => |m| std.fmt.bufPrint(buf, "multipart/{s}", .{m.subtype}),
        };
    }
};

// ── message attributes ──────────────────────────────────────────────────────

pub const Item = union(enum) {
    uid: u32,
    flags: []const []const u8,
    envelope: Envelope,
    /// Kept verbatim, for the same reason as `Envelope.date`.
    internal_date: []const u8,
    rfc822_size: i64,
    body_structure: BodyStructure,
    /// `BODY[...]` — `section` is the text between the brackets, `data` is the
    /// payload (`NIL` becomes null).
    body_section: struct { section: []const u8, data: ?[]const u8 },
    /// A name this parser does not model; its value was consumed so the rest
    /// of the list still reads.
    other: []const u8,
};

pub const Message = struct {
    seq: u32,
    items: []const Item,

    /// The UID if one was fetched.
    pub fn uid(m: Message) ?u32 {
        for (m.items) |it| if (it == .uid) return it.uid;
        return null;
    }
    pub fn find(m: Message, comptime tag: std.meta.Tag(Item)) ?Item {
        for (m.items) |it| if (it == tag) return it;
        return null;
    }
};

// ── request side ────────────────────────────────────────────────────────────

/// What to ask for. Anything false is simply not requested.
pub const Request = struct {
    uid: bool = false,
    flags: bool = false,
    envelope: bool = false,
    internal_date: bool = false,
    rfc822_size: bool = false,
    body_structure: bool = false,
    /// Section specifiers, e.g. `""` (whole body), `"HEADER"`, `"TEXT"`,
    /// `"1.2"`, `"HEADER.FIELDS (FROM TO)"`.
    sections: []const []const u8 = &.{},
    /// Use `BODY.PEEK[...]`, which does not set `\Seen`. Almost always what a
    /// client wants: fetching a body should not mark mail as read behind the
    /// user's back.
    peek: bool = true,
};

/// `TAG [UID] FETCH seq-set (items...)`.
pub fn encode(
    e: *command.Encoder,
    tag: []const u8,
    seq_set: []const u8,
    by_uid: bool,
    req: Request,
) command.Error!void {
    // Everything the caller supplied is checked *before* the first byte goes
    // out. The encoder writes straight into the session's buffer, so failing
    // half way would leave `T1 FETCH ` sitting in front of the next command.
    try command.checkArg(tag);
    try command.checkSequenceSet(seq_set);
    for (req.sections) |sec| try command.checkSection(sec);

    try e.atom(tag);
    try e.sp();
    if (by_uid) {
        try e.atom("UID");
        try e.sp();
    }
    try e.atom("FETCH");
    try e.sp();
    try e.atom(seq_set);
    try e.sp();
    try e.special('(');

    var n: usize = 0;
    const simple = [_]struct { on: bool, name: []const u8 }{
        // Item order is free; this is the order RFC 9051 §6.4.5 prints, so the
        // encoder's output can be compared with the RFC byte for byte.
        .{ .on = req.uid, .name = "UID" },
        .{ .on = req.flags, .name = "FLAGS" },
        .{ .on = req.internal_date, .name = "INTERNALDATE" },
        .{ .on = req.rfc822_size, .name = "RFC822.SIZE" },
        .{ .on = req.envelope, .name = "ENVELOPE" },
        .{ .on = req.body_structure, .name = "BODYSTRUCTURE" },
    };
    for (simple) |s| {
        if (!s.on) continue;
        if (n > 0) try e.sp();
        try e.atom(s.name);
        n += 1;
    }
    for (req.sections) |sec| {
        if (n > 0) try e.sp();
        try e.atom(if (req.peek) "BODY.PEEK[" else "BODY[");
        try e.atom(sec);
        try e.special(']');
        n += 1;
    }
    // An empty item list is not valid; ask for the one thing every client
    // needs rather than emitting "()".
    if (n == 0) try e.atom("UID");

    try e.special(')');
    try e.crlf();
}

// ── response side ───────────────────────────────────────────────────────────

pub const Parser = struct {
    d: *wire.Decoder,
    opts: Options = .{},
    depth: usize = 0,

    /// Parse the `(...)` that follows `* n FETCH`.
    pub fn message(p: *Parser, seq: u32) Error!Message {
        var items: std.ArrayList(Item) = .empty;
        errdefer items.deinit(p.d.gpa);

        var it = try p.d.expectList();
        while (try it.next()) try items.append(p.d.gpa, try p.attribute());

        return .{ .seq = seq, .items = try items.toOwnedSlice(p.d.gpa) };
    }

    fn attribute(p: *Parser) Error!Item {
        const d = p.d;
        // The name stops at '[' so `BODY[HEADER]` splits into name and section.
        const name = (try d.run(isAttNameChar)) orelse return error.UnexpectedByte;

        if (std.ascii.eqlIgnoreCase(name, "UID")) {
            try d.expectSp();
            return .{ .uid = try d.expectNumber() };
        }
        if (std.ascii.eqlIgnoreCase(name, "FLAGS")) {
            try d.expectSp();
            return .{ .flags = try p.flagList() };
        }
        if (std.ascii.eqlIgnoreCase(name, "ENVELOPE")) {
            try d.expectSp();
            return .{ .envelope = try p.envelope() };
        }
        if (std.ascii.eqlIgnoreCase(name, "INTERNALDATE")) {
            try d.expectSp();
            return .{ .internal_date = try d.expectString() };
        }
        if (std.ascii.eqlIgnoreCase(name, "RFC822.SIZE")) {
            try d.expectSp();
            return .{ .rfc822_size = (try d.number64()) orelse return error.BadNumber };
        }
        if (std.ascii.eqlIgnoreCase(name, "BODYSTRUCTURE")) {
            try d.expectSp();
            return .{ .body_structure = try p.body() };
        }
        if (std.ascii.eqlIgnoreCase(name, "BODY")) {
            // `BODY` alone is the non-extensible BODYSTRUCTURE; `BODY[` starts
            // a section.
            if (!try d.accept('[')) {
                try d.expectSp();
                return .{ .body_structure = try p.body() };
            }
            const section = (try d.run(isSectionChar)) orelse try d.gpa.dupe(u8, "");
            try d.expect(']');
            // An optional partial origin, e.g. BODY[]<0>.
            if (try d.accept('<')) {
                _ = try d.expectNumber();
                try d.expect('>');
            }
            try d.expectSp();
            return .{ .body_section = .{
                .section = section,
                .data = try d.expectNString(),
            } };
        }

        // Unknown: consume its value so the remaining attributes still parse.
        if (try d.sp()) try d.discardValue();
        return .{ .other = name };
    }

    fn flagList(p: *Parser) Error![]const []const u8 {
        const d = p.d;
        var flags: std.ArrayList([]const u8) = .empty;
        errdefer flags.deinit(d.gpa);
        var it = try d.expectList();
        while (try it.next()) {
            _ = try d.sp(); // servers that open the list with a space
            const system = try d.accept('\\');
            if (system and try d.accept('*')) {
                try flags.append(d.gpa, try d.gpa.dupe(u8, "\\*"));
                continue;
            }
            const nm = try d.expectAtom();
            if (!system) {
                try flags.append(d.gpa, nm);
            } else {
                defer d.gpa.free(nm);
                const joined = std.fmt.allocPrint(d.gpa, "\\{s}", .{nm}) catch
                    return error.OutOfMemory;
                try flags.append(d.gpa, joined);
            }
        }
        return flags.toOwnedSlice(d.gpa);
    }

    pub fn envelope(p: *Parser) Error!Envelope {
        const d = p.d;
        var env: Envelope = .{};

        try d.expect('(');
        env.date = try d.expectNString();
        try d.expectSp();
        env.subject = try d.expectNString();
        try d.expectSp();

        const lists = [_]*[]const Address{
            &env.from, &env.sender, &env.reply_to, &env.to, &env.cc, &env.bcc,
        };
        for (lists) |slot| {
            slot.* = try p.addressList();
            try d.expectSp();
        }

        env.in_reply_to = try d.expectNString();
        try d.expectSp();
        env.message_id = try d.expectNString();
        try d.expect(')');
        return env;
    }

    /// `env-from` and friends: a list of addresses, or NIL.
    fn addressList(p: *Parser) Error![]const Address {
        const d = p.d;
        if (try d.atom()) |a| {
            defer d.gpa.free(a);
            if (!std.ascii.eqlIgnoreCase(a, "NIL")) return error.UnexpectedByte;
            return &.{};
        }
        var out: std.ArrayList(Address) = .empty;
        errdefer out.deinit(d.gpa);
        var it = try d.expectList();
        while (try it.next()) try out.append(d.gpa, try p.address());
        return out.toOwnedSlice(d.gpa);
    }

    fn address(p: *Parser) Error!Address {
        const d = p.d;
        var a: Address = .{};
        try d.expect('(');
        a.name = try d.expectNString();
        try d.expectSp();
        a.route = try d.expectNString();
        try d.expectSp();
        a.mailbox = try d.expectNString();
        try d.expectSp();
        a.host = try d.expectNString();
        try d.expect(')');
        return a;
    }

    /// `body` — a single part or a multipart, recursively.
    pub fn body(p: *Parser) Error!BodyStructure {
        const d = p.d;

        p.depth += 1;
        defer p.depth -= 1;
        // Checked on the way IN: the alternative is finding the limit when the
        // stack is already gone.
        if (p.depth > p.opts.max_depth) return error.BodyTooDeep;

        try d.expect('(');

        // A single part starts with its media type as a string; a multipart
        // starts with a nested body, i.e. '('.
        var bs: BodyStructure = undefined;
        if (try d.string()) |media_type| {
            bs = .{ .single = try p.singlePart(media_type) };
        } else {
            bs = .{ .multi = try p.multiPart() };
        }

        // Future extension fields: skip whatever is left before the ')'.
        while (try d.sp()) try d.discardValue();
        try d.expect(')');
        return bs;
    }

    fn singlePart(p: *Parser, media_type: []const u8) Error!SinglePart {
        const d = p.d;
        var s: SinglePart = .{ .type = media_type, .subtype = undefined };

        try d.expectSp();
        s.subtype = try d.expectString();
        try d.expectSp();
        s.params = try p.fldParam();
        try d.expectSp();
        s.id = try d.expectNString();
        try d.expectSp();
        s.description = try d.expectNString();
        try d.expectSp();
        s.encoding = (try d.expectNString()) orelse "7bit";
        try d.expectSp();
        s.size = try d.expectBodyFldOctets();

        // Some servers stop here even for message/* and text/* (go-imap
        // issue 557), so a missing SP ends the part rather than failing it.
        var has_sp = try d.sp();
        if (!has_sp) return s;

        if (std.ascii.eqlIgnoreCase(s.type, "message") and
            (std.ascii.eqlIgnoreCase(s.subtype, "rfc822") or
                std.ascii.eqlIgnoreCase(s.subtype, "global")))
        {
            const msg = d.gpa.create(NestedMessage) catch return error.OutOfMemory;
            msg.envelope = try p.envelope();
            try d.expectSp();
            const child = d.gpa.create(BodyStructure) catch return error.OutOfMemory;
            child.* = try p.body();
            msg.body = child;
            try d.expectSp();
            msg.num_lines = (try d.number64()) orelse return error.BadNumber;
            s.message = msg;
            has_sp = false;
        } else if (std.ascii.eqlIgnoreCase(s.type, "text")) {
            s.num_lines = (try d.number64()) orelse return error.BadNumber;
            has_sp = false;
        }

        if (!has_sp) has_sp = try d.sp();
        if (has_sp) s.ext = try p.ext1part();
        return s;
    }

    fn ext1part(p: *Parser) Error!SinglePartExt {
        const d = p.d;
        var x: SinglePartExt = .{};
        x.md5 = try d.expectNString();
        if (!try d.sp()) return x;
        x.disposition = try p.fldDsp();
        if (!try d.sp()) return x;
        x.language = try p.fldLang();
        if (!try d.sp()) return x;
        x.location = try d.expectNString();
        return x;
    }

    fn multiPart(p: *Parser) Error!MultiPart {
        const d = p.d;
        var children: std.ArrayList(*const BodyStructure) = .empty;
        errdefer children.deinit(d.gpa);

        var subtype: []const u8 = "";
        while (true) {
            const child = d.gpa.create(BodyStructure) catch return error.OutOfMemory;
            child.* = try p.body();
            try children.append(d.gpa, child);
            // The children run until a SP is followed by a string rather than
            // another body -- that string is the multipart subtype.
            if (try d.sp()) {
                if (try d.string()) |st| {
                    subtype = st;
                    break;
                }
            }
        }

        var m = MultiPart{
            .children = try children.toOwnedSlice(d.gpa),
            .subtype = subtype,
        };
        if (try d.sp()) m.ext = try p.extMpart();
        return m;
    }

    fn extMpart(p: *Parser) Error!MultiPartExt {
        const d = p.d;
        var x: MultiPartExt = .{};
        x.params = try p.fldParam();
        if (!try d.sp()) return x;
        x.disposition = try p.fldDsp();
        if (!try d.sp()) return x;
        x.language = try p.fldLang();
        if (!try d.sp()) return x;
        x.location = try d.expectNString();
        return x;
    }

    fn fldDsp(p: *Parser) Error!?Disposition {
        const d = p.d;
        if (try d.atom()) |a| {
            defer d.gpa.free(a);
            if (!std.ascii.eqlIgnoreCase(a, "NIL")) return error.UnexpectedByte;
            return null;
        }
        try d.expect('(');
        const value = try d.expectString();
        try d.expectSp();
        const params = try p.fldParam();
        try d.expect(')');
        return .{ .value = value, .params = params };
    }

    /// `body-fld-param` — `(key value key value ...)` or NIL. Keys are
    /// lower-cased: MIME parameter names are case-insensitive, and a caller
    /// looking for "charset" should not have to try "CHARSET" as well.
    fn fldParam(p: *Parser) Error![]const Param {
        const d = p.d;
        if (try d.atom()) |a| {
            defer d.gpa.free(a);
            if (!std.ascii.eqlIgnoreCase(a, "NIL")) return error.UnexpectedByte;
            return &.{};
        }

        var out: std.ArrayList(Param) = .empty;
        errdefer out.deinit(d.gpa);
        var key: ?[]const u8 = null;
        var it = try d.expectList();
        while (try it.next()) {
            const s = try d.expectString();
            if (key == null) {
                const lowered = @constCast(s);
                for (lowered) |*ch| ch.* = std.ascii.toLower(ch.*);
                key = lowered;
            } else {
                try out.append(d.gpa, .{ .key = key.?, .value = s });
                key = null;
            }
        }
        if (key != null) return error.ParamWithoutValue;
        return out.toOwnedSlice(d.gpa);
    }

    fn fldLang(p: *Parser) Error![]const []const u8 {
        const d = p.d;
        if (try d.atom()) |a| {
            defer d.gpa.free(a);
            if (!std.ascii.eqlIgnoreCase(a, "NIL")) return error.UnexpectedByte;
            return &.{};
        }
        if (try d.string()) |one| {
            const out = d.gpa.alloc([]const u8, 1) catch return error.OutOfMemory;
            out[0] = one;
            return out;
        }
        var out: std.ArrayList([]const u8) = .empty;
        errdefer out.deinit(d.gpa);
        var it = try d.expectList();
        while (try it.next()) try out.append(d.gpa, try d.expectString());
        return out.toOwnedSlice(d.gpa);
    }
};

fn isAttNameChar(ch: u8) bool {
    return ch != '[' and wire.isAtomChar(ch);
}

fn isSectionChar(ch: u8) bool {
    return ch != ']';
}

// ── tests ───────────────────────────────────────────────────────────────────

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
    fn parser(f: *Fx) Parser {
        return .{ .d = &f.d };
    }
};

test "Message.find returns the first item carrying the requested tag" {
    const t = std.testing;
    const items = [_]Item{
        .{ .uid = 7 },
        .{ .rfc822_size = 4096 },
        .{ .internal_date = "17-Jul-1996 02:44:25 -0700" },
    };
    const m: Message = .{ .seq = 1, .items = &items };

    try t.expectEqual(@as(?u32, 7), m.uid());
    try t.expectEqual(@as(i64, 4096), m.find(.rfc822_size).?.rfc822_size);
    try t.expectEqualStrings("17-Jul-1996 02:44:25 -0700", m.find(.internal_date).?.internal_date);
    // A tag that was not fetched is absent, not a default.
    try t.expectEqual(@as(?Item, null), m.find(.flags));
}

test "RFC 9051 §7.5.2: the ENVELOPE example" {
    var f: Fx = undefined;
    f.init("(\"Wed, 17 Jul 1996 02:23:25 -0700 (PDT)\" " ++
        "\"IMAP4rev2 WG mtg summary and minutes\" " ++
        "((\"Terry Gray\" NIL \"gray\" \"cac.washington.edu\")) " ++
        "((\"Terry Gray\" NIL \"gray\" \"cac.washington.edu\")) " ++
        "((\"Terry Gray\" NIL \"gray\" \"cac.washington.edu\")) " ++
        "((NIL NIL \"imap\" \"cac.washington.edu\")) " ++
        "((NIL NIL \"minutes\" \"CNRI.Reston.VA.US\")" ++
        "(\"John Klensin\" NIL \"KLENSIN\" \"фЛТ.MIT.EDU\")) NIL NIL " ++
        "\"<B27397-0100000@cac.washington.edu>\")");
    defer f.deinit();
    var p = f.parser();

    const env = try p.envelope();
    try testing.expectEqualStrings("IMAP4rev2 WG mtg summary and minutes", env.subject.?);
    try testing.expectEqual(@as(usize, 1), env.from.len);
    try testing.expectEqualStrings("Terry Gray", env.from[0].name.?);
    try testing.expectEqualStrings("gray", env.from[0].mailbox.?);
    try testing.expectEqualStrings("cac.washington.edu", env.from[0].host.?);
    // A NIL personal name is absent, not the string "NIL".
    try testing.expect(env.to[0].name == null);
    try testing.expectEqual(@as(usize, 2), env.cc.len);
    // NIL address lists come back empty, and are not an error.
    try testing.expectEqual(@as(usize, 0), env.bcc.len);
    try testing.expect(env.in_reply_to == null);
    try testing.expectEqualStrings("<B27397-0100000@cac.washington.edu>", env.message_id.?);
}

test "BODYSTRUCTURE: a single text part" {
    var f: Fx = undefined;
    f.init("(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"US-ASCII\") NIL NIL \"7BIT\" 3028 92)");
    defer f.deinit();
    var p = f.parser();

    const bs = try p.body();
    const s = bs.single;
    try testing.expectEqualStrings("TEXT", s.type);
    try testing.expectEqualStrings("PLAIN", s.subtype);
    try testing.expectEqual(@as(u32, 3028), s.size);
    // text/* carries a line count that no other media type has.
    try testing.expectEqual(@as(i64, 92), s.num_lines.?);
    // Parameter keys are lower-cased so a caller can look up "charset".
    try testing.expectEqual(@as(usize, 1), s.params.len);
    try testing.expectEqualStrings("charset", s.params[0].key);
    try testing.expectEqualStrings("US-ASCII", s.params[0].value);
}

test "BODYSTRUCTURE: a multipart, and the subtype comes after the children" {
    var f: Fx = undefined;
    f.init("((\"TEXT\" \"PLAIN\" (\"CHARSET\" \"US-ASCII\") NIL NIL \"7BIT\" 1152 23)" ++
        "(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"US-ASCII\" \"NAME\" \"cc.diff\") " ++
        "\"<960723163407.20117h@cac.washington.edu>\" \"Compiler diff\" " ++
        "\"BASE64\" 4554 73) \"MIXED\")");
    defer f.deinit();
    var p = f.parser();

    const bs = try p.body();
    const m = bs.multi;
    try testing.expectEqualStrings("MIXED", m.subtype);
    try testing.expectEqual(@as(usize, 2), m.children.len);
    try testing.expectEqualStrings("PLAIN", m.children[0].single.subtype);
    try testing.expectEqualStrings("BASE64", m.children[1].single.encoding);
    try testing.expectEqualStrings(
        "<960723163407.20117h@cac.washington.edu>",
        m.children[1].single.id.?,
    );
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("multipart/MIXED", try bs.mediaType(&buf));
}

test "BODYSTRUCTURE: message/rfc822 nests a whole message" {
    var f: Fx = undefined;
    f.init("(\"MESSAGE\" \"RFC822\" NIL NIL NIL \"7BIT\" 1024 " ++
        "(\"Wed, 1 Jan 2020 00:00:00 +0000\" \"Inner\" " ++
        "((NIL NIL \"a\" \"x.test\")) NIL NIL NIL NIL NIL NIL \"<i@x.test>\") " ++
        "(\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 512 10) 20)");
    defer f.deinit();
    var p = f.parser();

    const bs = try p.body();
    const msg = bs.single.message.?;
    try testing.expectEqualStrings("Inner", msg.envelope.subject.?);
    try testing.expectEqualStrings("<i@x.test>", msg.envelope.message_id.?);
    try testing.expectEqualStrings("PLAIN", msg.body.single.subtype);
    try testing.expectEqual(@as(i64, 20), msg.num_lines);
}

test "BODYSTRUCTURE: a NIL encoding means 7bit, not unknown" {
    var f: Fx = undefined;
    f.init("(\"APPLICATION\" \"OCTET-STREAM\" NIL NIL NIL NIL 42)");
    defer f.deinit();
    var p = f.parser();
    const bs = try p.body();
    try testing.expectEqualStrings("7bit", bs.single.encoding);
}

test "BODYSTRUCTURE: the -1 size some servers send" {
    var f: Fx = undefined;
    f.init("(\"APPLICATION\" \"PDF\" NIL NIL NIL \"BASE64\" -1)");
    defer f.deinit();
    var p = f.parser();
    const bs = try p.body();
    try testing.expectEqual(@as(u32, 0), bs.single.size);
}

test "BODYSTRUCTURE: recursion is bounded on the way in" {
    const gpa = testing.allocator;
    // 200 nested multiparts. Without a bound this is a stack overflow driven
    // by network input, not a parse error.
    var deep: std.ArrayList(u8) = .empty;
    defer deep.deinit(gpa);
    try deep.appendNTimes(gpa, '(', 200);

    var f: Fx = undefined;
    f.init(deep.items);
    defer f.deinit();
    var p = Parser{ .d = &f.d, .opts = .{ .max_depth = 16 } };
    try testing.expectError(error.BodyTooDeep, p.body());
}

test "BODYSTRUCTURE: extension fields present and absent both parse" {
    var f: Fx = undefined;
    f.init("(\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 100 5 " ++
        "\"d41d8cd98f00b204e9800998ecf8427e\" " ++
        "(\"attachment\" (\"filename\" \"a.txt\")) \"en\" \"http://x.test/a\")");
    defer f.deinit();
    var p = f.parser();

    const s = (try p.body()).single;
    const ext = s.ext.?;
    try testing.expectEqualStrings("d41d8cd98f00b204e9800998ecf8427e", ext.md5.?);
    try testing.expectEqualStrings("attachment", ext.disposition.?.value);
    try testing.expectEqualStrings("filename", ext.disposition.?.params[0].key);
    try testing.expectEqualStrings("a.txt", ext.disposition.?.params[0].value);
    try testing.expectEqual(@as(usize, 1), ext.language.len);
    try testing.expectEqualStrings("en", ext.language[0]);
    try testing.expectEqualStrings("http://x.test/a", ext.location.?);
}

test "an unknown extension field after the structure is skipped, not fatal" {
    var f: Fx = undefined;
    f.init("(\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 100 5 NIL NIL NIL NIL (\"FUTURE\" 1))");
    defer f.deinit();
    var p = f.parser();
    const s = (try p.body()).single;
    try testing.expectEqual(@as(u32, 100), s.size);
}

test "msg-att: the RFC 9051 §6.4.5 FETCH example" {
    var f: Fx = undefined;
    f.init("(FLAGS (\\Seen) INTERNALDATE \"17-Jul-1996 02:44:25 -0700\" " ++
        "RFC822.SIZE 4286 UID 4827313)");
    defer f.deinit();
    var p = f.parser();

    const m = try p.message(12);
    try testing.expectEqual(@as(u32, 12), m.seq);
    try testing.expectEqual(@as(usize, 4), m.items.len);
    try testing.expectEqual(@as(u32, 4827313), m.uid().?);
    try testing.expectEqualStrings("\\Seen", m.items[0].flags[0]);
    try testing.expectEqualStrings("17-Jul-1996 02:44:25 -0700", m.items[1].internal_date);
    try testing.expectEqual(@as(i64, 4286), m.items[2].rfc822_size);
}

test "msg-att: BODY[...] splits the section from the payload" {
    var f: Fx = undefined;
    f.init("(UID 7 BODY[HEADER.FIELDS (FROM TO)] {18}\r\nFrom: a\r\nTo: b\r\n\r\n)");
    defer f.deinit();
    var p = f.parser();

    const m = try p.message(1);
    const sec = m.items[1].body_section;
    try testing.expectEqualStrings("HEADER.FIELDS (FROM TO)", sec.section);
    try testing.expectEqualStrings("From: a\r\nTo: b\r\n\r\n", sec.data.?);
}

test "msg-att: an empty section and a NIL payload" {
    var f: Fx = undefined;
    f.init("(BODY[] NIL)");
    defer f.deinit();
    var p = f.parser();
    const m = try p.message(1);
    try testing.expectEqualStrings("", m.items[0].body_section.section);
    try testing.expect(m.items[0].body_section.data == null);
}

test "msg-att: a partial origin is consumed" {
    var f: Fx = undefined;
    f.init("(BODY[TEXT]<0> \"abc\")");
    defer f.deinit();
    var p = f.parser();
    const m = try p.message(1);
    try testing.expectEqualStrings("abc", m.items[0].body_section.data.?);
}

test "msg-att: an unknown attribute is skipped and the rest still parses" {
    var f: Fx = undefined;
    f.init("(MODSEQ (12345) UID 9)");
    defer f.deinit();
    var p = f.parser();
    const m = try p.message(1);
    try testing.expectEqualStrings("MODSEQ", m.items[0].other);
    try testing.expectEqual(@as(u32, 9), m.uid().?);
}

test "encode: the request the RFC prints, and BODY.PEEK by default" {
    var buf: [512]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    var e = command.Encoder.init(testing.allocator, &w, .{});

    try encode(&e, "A654", "2:4", false, .{
        .flags = true,
        .internal_date = true,
        .rfc822_size = true,
        .envelope = true,
    });
    try testing.expectEqualStrings(
        "A654 FETCH 2:4 (FLAGS INTERNALDATE RFC822.SIZE ENVELOPE)\r\n",
        w.buffered(),
    );
}

test "encode: peek is the default, because fetching must not mark mail read" {
    var buf: [512]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    var e = command.Encoder.init(testing.allocator, &w, .{});
    try encode(&e, "A1", "1", true, .{ .uid = true, .sections = &.{"HEADER"} });
    try testing.expectEqualStrings(
        "A1 UID FETCH 1 (UID BODY.PEEK[HEADER])\r\n",
        w.buffered(),
    );

    var buf2: [512]u8 = undefined;
    var w2 = std.Io.Writer.fixed(&buf2);
    var e2 = command.Encoder.init(testing.allocator, &w2, .{});
    try encode(&e2, "A2", "1", false, .{ .sections = &.{""}, .peek = false });
    try testing.expectEqualStrings("A2 FETCH 1 (BODY[])\r\n", w2.buffered());
}

test "encode: an empty request still asks for something valid" {
    var buf: [512]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    var e = command.Encoder.init(testing.allocator, &w, .{});
    try encode(&e, "A1", "1", false, .{});
    // "()" is not a valid item list.
    try testing.expectEqualStrings("A1 FETCH 1 (UID)\r\n", w.buffered());
}

test "encode: a seq_set cannot smuggle a second command onto the wire" {
    // The audit's reproducer, verbatim. Before the fix this emitted
    // `T1 FETCH 1:*\r\nT9 DELETE "Important" (UID)\r\n` — a fully-formed
    // DELETE on an authenticated connection, from a caller who thought they
    // were naming messages.
    var buf: [512]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    var e = command.Encoder.init(testing.allocator, &w, .{});
    try testing.expectError(
        error.InvalidSequenceSet,
        encode(&e, "T1", "1:*\r\nT9 DELETE \"Important\"", false, .{ .uid = true }),
    );
    // Not one byte, either: a half-written command would sit in the session's
    // buffer and prefix whatever the caller sends next.
    try testing.expectEqualStrings("", w.buffered());

    // The section variant: `BODY.PEEK[HEADER]\r\nT9 LOGOUT]`.
    try testing.expectError(
        error.InvalidSection,
        encode(&e, "T2", "1", false, .{ .sections = &.{"HEADER]\r\nT9 LOGOUT"} }),
    );
    try testing.expectEqualStrings("", w.buffered());

    // A bad section in the *second* slot must not leave the first one written.
    try testing.expectError(
        error.InvalidSection,
        encode(&e, "T3", "1", false, .{ .sections = &.{ "HEADER", "TEXT]\r\nT9 LOGOUT" } }),
    );
    try testing.expectEqualStrings("", w.buffered());

    // And a tag is an unframed argument too.
    try testing.expectError(
        error.ControlCharacterInArgument,
        encode(&e, "T4\r\nT9 LOGOUT", "1", false, .{}),
    );
    try testing.expectEqualStrings("", w.buffered());
}

test "fuzz: no FETCH argument can put a second command line on the wire" {
    try testing.fuzz({}, fuzzEncode, .{});
}

/// `fetch.encode` never calls `string`, so it never emits a literal: every byte
/// it writes is either a constant or a caller argument written unframed. That
/// makes the invariant exact — one CRLF, at the very end, and no stray CR or LF
/// anywhere before it. The shape is `smtp/src/command.zig`'s `fuzzCommands`.
fn fuzzEncode(_: void, smith: *std.testing.Smith) !void {
    var raw: [96]u8 = undefined;
    smith.bytes(&raw);
    // From 0: the empty seq_set and the empty section are both interesting, and
    // a harness that cannot draw them cannot reach half of this grammar.
    const seq = raw[0..smith.valueRangeAtMost(u8, 0, 48)];
    const sec = raw[48..][0..smith.valueRangeAtMost(u8, 0, 48)];
    const tag = if (smith.value(bool)) "T1" else seq;

    var buf: [1024]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    var e = command.Encoder.init(std.testing.allocator, &w, .{});

    const req: Request = .{
        .uid = smith.value(bool),
        .flags = smith.value(bool),
        .body_structure = smith.value(bool),
        .sections = &.{sec},
        .peek = smith.value(bool),
    };
    if (encode(&e, tag, seq, smith.value(bool), req)) |_| {
        const line = w.buffered();
        std.debug.assert(std.mem.endsWith(u8, line, "\r\n"));
        const body = line[0 .. line.len - 2];
        std.debug.assert(std.mem.indexOfScalar(u8, body, '\r') == null);
        std.debug.assert(std.mem.indexOfScalar(u8, body, '\n') == null);
        std.debug.assert(std.mem.indexOfScalar(u8, body, 0) == null);
    } else |_| {
        // A refusal must also be a clean refusal: nothing half-written.
        std.debug.assert(w.buffered().len == 0);
    }
}
