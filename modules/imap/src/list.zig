// SPDX-License-Identifier: MIT

//! `LIST` / `LSUB` (RFC 9051 §6.3.9, §6.3.10) and `STATUS` (§6.3.11) — the
//! mailbox-listing and mailbox-info commands.
//!
//! Audit A1 F6 (`~/CML/20260901-zig-libs-audit/A1/imap.md`): this module had
//! no parser for any of the three at all. `wire.expectMailbox` — which does
//! the UTF-7 decoding and `INBOX` canonicalisation a mailbox NAME needs — had
//! exactly one caller, and it was this module's own tests; `client.zig` had
//! no `list`/`lsub`/`status` method, and `response.zig`'s own test said so
//! directly: "LIST is not parsed yet; it must still come back intact and in
//! sync." This file is new production code, not a port: `LIST`/`LSUB`/
//! `STATUS` are not in `emersion/go-imap`'s ported surface (see
//! `modules/imap/NOTICE`), so there is no upstream file to port from — the
//! shape follows this module's own established encode/parse split
//! (`fetch.zig`/`search.zig`: `encode(*command.Encoder, ...)` on the way out,
//! `parseX(*wire.Decoder)` on the way in, both driven by `client.zig`).

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const wire = @import("wire.zig");
const command = @import("command.zig");
const utf7 = @import("utf7.zig");

pub const Error = wire.Error;

/// One `* LIST` / `* LSUB` reply — RFC 9051 §7.3.1's `mailbox-list`.
pub const Entry = struct {
    /// `mbx-list-flags`: `\Noselect`, `\HasChildren`, `\Marked`, ... — always
    /// backslash-prefixed. Unlike a message's `FLAGS` (`flag-list`), there is
    /// no bare-keyword form here (RFC 9051 §7.3.1's `mbx-list-oflag` /
    /// `mbx-list-sflag` are both `"\" atom` productions), so this does not
    /// need the `\*` special case `response.Reader.readFlag` has.
    flags: []const []const u8 = &.{},
    /// The hierarchy delimiter — `(DQUOTE QUOTED-CHAR DQUOTE / nil)`. Null
    /// for `NIL`, meaning the server has no hierarchy concept for this name
    /// (a flat namespace, or this specific entry names one).
    delimiter: ?[]const u8 = null,
    /// Modified-UTF-7-decoded, `INBOX`-canonicalised (`wire.expectMailbox`) —
    /// the fix this whole file exists for: before it, a caller got the raw,
    /// still-encoded bytes back because nothing on the read path ever called
    /// the decoder (F6).
    mailbox: []const u8,
};

/// Parse the body of `* LIST ...` / `* LSUB ...`, i.e. everything after the
/// word — both share `mailbox-list` (RFC 9051 §7.3.1).
pub fn parseMailboxList(d: *wire.Decoder) Error!Entry {
    try d.expectSp();
    var flags: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (flags.items) |f| d.gpa.free(f);
        flags.deinit(d.gpa);
    }
    {
        var it = try d.expectList();
        defer it.deinit(); // F13-style safety net if an element below errors mid-list
        while (try it.next()) {
            try d.expect('\\');
            const name = try d.expectAtom();
            defer d.gpa.free(name);
            const with_slash = std.fmt.allocPrint(d.gpa, "\\{s}", .{name}) catch
                return error.OutOfMemory;
            try flags.append(d.gpa, with_slash);
        }
    }

    try d.expectSp();
    const delimiter: ?[]const u8 = try d.quoted() orelse blk: {
        const nil = try d.expectAtom();
        defer d.gpa.free(nil);
        if (!std.ascii.eqlIgnoreCase(nil, "NIL")) return error.UnexpectedByte;
        break :blk null;
    };
    errdefer if (delimiter) |del| d.gpa.free(del);

    try d.expectSp();
    const mailbox = try d.expectMailbox();
    errdefer d.gpa.free(mailbox);

    // `[SP mbox-list-extended]`: `(tag val ...)` extension items this module
    // does not interpret. Discarded, not rejected — the same tolerance
    // `response.Reader.readCode` gives an unknown `[CODE ...]`: an extension
    // this client does not implement must not desynchronise the stream.
    if (try d.sp()) try d.discardValue();

    return .{ .flags = try flags.toOwnedSlice(d.gpa), .delimiter = delimiter, .mailbox = mailbox };
}

/// `TAG SP "LIST" SP mailbox SP list-mailbox` (RFC 9051 §6.3.9) — the basic
/// (non-extended) form. `reference` and `pattern` both travel through
/// `Encoder.mailbox`: `list-mailbox = 1*list-char / string` explicitly
/// permits the `string` form for the pattern too (QUOTED-CHAR allows `%`/`*`
/// literally), and `mailbox`'s modified-UTF-7 encoding is a no-op on plain
/// ASCII wildcards — it only ever transforms non-ASCII bytes or an `&`.
pub fn encodeList(e: *command.Encoder, tag: []const u8, reference: []const u8, pattern: []const u8) command.Error!void {
    try e.atom(tag);
    try e.sp();
    try e.atom("LIST");
    try e.sp();
    try e.mailbox(reference);
    try e.sp();
    try e.mailbox(pattern);
    try e.crlf();
}

/// `TAG SP "LSUB" SP mailbox SP list-mailbox` (RFC 9051 §6.3.10) — same
/// grammar as `LIST`, different command word and reply kind.
pub fn encodeLsub(e: *command.Encoder, tag: []const u8, reference: []const u8, pattern: []const u8) command.Error!void {
    try e.atom(tag);
    try e.sp();
    try e.atom("LSUB");
    try e.sp();
    try e.mailbox(reference);
    try e.sp();
    try e.mailbox(pattern);
    try e.crlf();
}

/// `status-att` (RFC 9051 §6.3.11) this module reads. `RECENT` is obsolete in
/// RFC 9051 (dropped from the ABNF) but RFC 3501 servers still send it on
/// request, so it stays available for a rev1 peer.
pub const StatusItem = enum {
    messages,
    recent,
    uid_next,
    uid_validity,
    unseen,
    deleted,
    size,
    highest_mod_seq,

    fn wireName(self: StatusItem) []const u8 {
        return switch (self) {
            .messages => "MESSAGES",
            .recent => "RECENT",
            .uid_next => "UIDNEXT",
            .uid_validity => "UIDVALIDITY",
            .unseen => "UNSEEN",
            .deleted => "DELETED",
            .size => "SIZE",
            .highest_mod_seq => "HIGHESTMODSEQ",
        };
    }
};

pub const StatusAttrs = struct {
    messages: ?u32 = null,
    recent: ?u32 = null,
    uid_next: ?u32 = null,
    uid_validity: ?u32 = null,
    unseen: ?u32 = null,
    deleted: ?u32 = null,
    /// `number64` (RFC 9051 §9): a mailbox's total size can exceed 32 bits.
    size: ?i64 = null,
    highest_mod_seq: ?i64 = null,
};

/// A `* STATUS` reply — RFC 9051 §7.3.2.
pub const StatusReply = struct {
    /// Modified-UTF-7-decoded, `INBOX`-canonicalised, same as `Entry.mailbox`.
    mailbox: []const u8,
    attrs: StatusAttrs = .{},
};

fn expectNumber64(d: *wire.Decoder) Error!i64 {
    return (try d.number64()) orelse error.BadNumber;
}

/// Parse the body of `* STATUS ...`, i.e. everything after the word.
pub fn parseStatus(d: *wire.Decoder) Error!StatusReply {
    try d.expectSp();
    const mailbox = try d.expectMailbox();
    errdefer d.gpa.free(mailbox);
    try d.expectSp();

    var attrs: StatusAttrs = .{};
    var it = try d.expectList();
    defer it.deinit();
    while (try it.next()) {
        const name = try d.expectAtom();
        defer d.gpa.free(name);
        try d.expectSp();
        if (std.ascii.eqlIgnoreCase(name, "MESSAGES")) {
            attrs.messages = try d.expectNumber();
        } else if (std.ascii.eqlIgnoreCase(name, "RECENT")) {
            attrs.recent = try d.expectNumber();
        } else if (std.ascii.eqlIgnoreCase(name, "UIDNEXT")) {
            attrs.uid_next = try d.expectNumber();
        } else if (std.ascii.eqlIgnoreCase(name, "UIDVALIDITY")) {
            attrs.uid_validity = try d.expectNumber();
        } else if (std.ascii.eqlIgnoreCase(name, "UNSEEN")) {
            attrs.unseen = try d.expectNumber();
        } else if (std.ascii.eqlIgnoreCase(name, "DELETED")) {
            attrs.deleted = try d.expectNumber();
        } else if (std.ascii.eqlIgnoreCase(name, "SIZE")) {
            attrs.size = try expectNumber64(d);
        } else if (std.ascii.eqlIgnoreCase(name, "HIGHESTMODSEQ")) {
            attrs.highest_mod_seq = try expectNumber64(d);
        } else {
            // An extension status-att this module does not know: discard its
            // value (same tolerance as `mbox-list-extended` above) rather
            // than fail the whole reply over one attribute.
            try d.discardValue();
        }
    }
    return .{ .mailbox = mailbox, .attrs = attrs };
}

/// `TAG SP "STATUS" SP mailbox SP "(" status-att *(SP status-att) ")"`
/// (RFC 9051 §6.3.11).
pub fn encodeStatus(e: *command.Encoder, tag: []const u8, mailbox: []const u8, items: []const StatusItem) command.Error!void {
    try e.atom(tag);
    try e.sp();
    try e.atom("STATUS");
    try e.sp();
    try e.mailbox(mailbox);
    try e.sp();
    try e.special('(');
    for (items, 0..) |item, i| {
        if (i > 0) try e.sp();
        try e.atom(item.wireName());
    }
    try e.special(')');
    try e.crlf();
}

// ── tests ───────────────────────────────────────────────────────────────────
//
// Tier 1 where possible: the LIST/LSUB/STATUS transcripts are RFC 9051's own
// worked examples (§6.3.9, §6.3.11). No upstream decoder exists to diff
// against for these three commands (see the module comment), so the second
// oracle this module leans on elsewhere is round-trip: encode a command,
// parse a reply shaped like a real server's, and confirm the decoded mailbox
// name is what a UTF-7-aware peer would have meant.

fn decoderOver(gpa: Allocator, r: *std.Io.Reader) wire.Decoder {
    return wire.Decoder.init(gpa, r, .{});
}

test "RFC 9051 §6.3.9: LIST reply with flags and a delimiter" {
    const gpa = testing.allocator;
    var r = std.Io.Reader.fixed(" (\\Noselect) \"/\" ~/Mail/foo\r\n");
    var d = decoderOver(gpa, &r);

    const entry = try parseMailboxList(&d);
    defer {
        for (entry.flags) |f| gpa.free(f);
        gpa.free(entry.flags);
        gpa.free(entry.delimiter.?);
        gpa.free(entry.mailbox);
    }
    try testing.expectEqual(@as(usize, 1), entry.flags.len);
    try testing.expectEqualStrings("\\Noselect", entry.flags[0]);
    try testing.expectEqualStrings("/", entry.delimiter.?);
    try testing.expectEqualStrings("~/Mail/foo", entry.mailbox);
}

test "LIST reply: no flags, NIL delimiter, and INBOX case-folded" {
    const gpa = testing.allocator;
    var r = std.Io.Reader.fixed(" () NIL iNbOx\r\n");
    var d = decoderOver(gpa, &r);

    const entry = try parseMailboxList(&d);
    defer {
        gpa.free(entry.flags);
        gpa.free(entry.mailbox);
    }
    try testing.expectEqual(@as(usize, 0), entry.flags.len);
    try testing.expect(entry.delimiter == null);
    try testing.expectEqualStrings("INBOX", entry.mailbox);
}

test "LIST reply: multiple flags, and a UTF-7-encoded mailbox name decodes" {
    const gpa = testing.allocator;
    // Built through this module's OWN encoder rather than a hand-typed
    // literal -- no upstream decoder exists to diff a LIST reply against
    // (see the module comment), so the oracle here is the same round-trip
    // the rest of this module leans on: encode "Отправленные" (Russian
    // "Sent"), splice it into a reply line, and confirm the PARSER decodes
    // it back to the original. Before F6 this string would have reached the
    // caller verbatim, still shifted -- nothing on the read path ever called
    // the decoder.
    const encoded = try utf7.encodeAlloc(gpa, "Отправленные");
    defer gpa.free(encoded);
    const line = try std.fmt.allocPrint(gpa, " (\\HasChildren \\Marked) \"/\" {s}\r\n", .{encoded});
    defer gpa.free(line);

    var r = std.Io.Reader.fixed(line);
    var d = decoderOver(gpa, &r);

    const entry = try parseMailboxList(&d);
    defer {
        for (entry.flags) |f| gpa.free(f);
        gpa.free(entry.flags);
        gpa.free(entry.delimiter.?);
        gpa.free(entry.mailbox);
    }
    try testing.expectEqual(@as(usize, 2), entry.flags.len);
    try testing.expectEqualStrings("\\HasChildren", entry.flags[0]);
    try testing.expectEqualStrings("\\Marked", entry.flags[1]);
    try testing.expectEqualStrings("Отправленные", entry.mailbox);
}

test "LIST reply: an unknown mbox-list-extended item is discarded, not rejected" {
    const gpa = testing.allocator;
    var r = std.Io.Reader.fixed(" () \"/\" INBOX (\"CHILDINFO\" (\"SUBSCRIBED\"))\r\n");
    var d = decoderOver(gpa, &r);
    const entry = try parseMailboxList(&d);
    defer {
        gpa.free(entry.flags);
        gpa.free(entry.delimiter.?);
        gpa.free(entry.mailbox);
    }
    try testing.expectEqualStrings("INBOX", entry.mailbox);
    // The reader is back in sync: nothing left but the line terminator.
    try d.expectCrlf();
}

test "RFC 9051 §6.3.11: STATUS reply, every attribute this module reads" {
    const gpa = testing.allocator;
    var r = std.Io.Reader.fixed(
        " blurdybloop (MESSAGES 231 UIDNEXT 44292 UIDVALIDITY 3857529045 UNSEEN 5 DELETED 0 SIZE 4294967296 HIGHESTMODSEQ 9)\r\n",
    );
    var d = decoderOver(gpa, &r);

    const reply = try parseStatus(&d);
    defer gpa.free(reply.mailbox);
    try testing.expectEqualStrings("blurdybloop", reply.mailbox);
    try testing.expectEqual(@as(u32, 231), reply.attrs.messages.?);
    try testing.expectEqual(@as(u32, 44292), reply.attrs.uid_next.?);
    try testing.expectEqual(@as(u32, 3857529045), reply.attrs.uid_validity.?);
    try testing.expectEqual(@as(u32, 5), reply.attrs.unseen.?);
    try testing.expectEqual(@as(u32, 0), reply.attrs.deleted.?);
    // Past u32 range -- this is what `number64` (not `number`) is for.
    try testing.expectEqual(@as(i64, 4294967296), reply.attrs.size.?);
    try testing.expectEqual(@as(i64, 9), reply.attrs.highest_mod_seq.?);
}

test "STATUS reply: an unknown status-att extension is discarded, not rejected" {
    const gpa = testing.allocator;
    var r = std.Io.Reader.fixed(" INBOX (MESSAGES 3 X-VENDOR-THING 12345)\r\n");
    var d = decoderOver(gpa, &r);
    const reply = try parseStatus(&d);
    defer gpa.free(reply.mailbox);
    try testing.expectEqual(@as(u32, 3), reply.attrs.messages.?);
    try testing.expect(reply.attrs.unseen == null);
    try d.expectCrlf(); // back in sync: nothing left but the line terminator
}

test "encodeList / encodeLsub / encodeStatus write the documented grammar" {
    const gpa = testing.allocator;

    var buf1: [64]u8 = undefined;
    var w1 = std.Io.Writer.fixed(&buf1);
    var e1 = command.Encoder.init(gpa, &w1, .{});
    try encodeList(&e1, "A1", "", "%");
    try testing.expectEqualStrings("A1 LIST \"\" \"%\"\r\n", w1.buffered());

    var buf2: [64]u8 = undefined;
    var w2 = std.Io.Writer.fixed(&buf2);
    var e2 = command.Encoder.init(gpa, &w2, .{});
    try encodeLsub(&e2, "A2", "", "*");
    try testing.expectEqualStrings("A2 LSUB \"\" \"*\"\r\n", w2.buffered());

    var buf3: [64]u8 = undefined;
    var w3 = std.Io.Writer.fixed(&buf3);
    var e3 = command.Encoder.init(gpa, &w3, .{});
    try encodeStatus(&e3, "A3", "blurdybloop", &.{ .messages, .uid_next });
    try testing.expectEqualStrings("A3 STATUS \"blurdybloop\" (MESSAGES UIDNEXT)\r\n", w3.buffered());
}
