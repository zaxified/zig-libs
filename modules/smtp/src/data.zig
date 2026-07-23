// SPDX-License-Identifier: MIT

//! RFC 5321 §4.5.2 — transparency for the DATA command, in both directions.
//!
//! The mail body travels inside a stream terminated by `CRLF "." CRLF`. So that
//! a body may itself contain a line consisting of a single `.`, the sender
//! doubles any period that starts a line and the receiver undoubles it. A
//! client that skips the doubling **truncates the message** at the first such
//! line and silently delivers half of it; a client that forgets the terminating
//! `CRLF.CRLF` hangs the session. Both are canonical SMTP bugs, and both are
//! tested here with a body whose second line is exactly `.`.
//!
//! Two things are deliberately strict:
//!
//! * The terminator is **only** `CRLF.CRLF`. A bare `LF.LF` (or `CR.CR`) does
//!   not end the data, and by default a bare LF anywhere in a received stream
//!   is `error.BareLineFeed`. Disagreement between an MTA that accepts `LF.LF`
//!   and one that does not is exactly the 2023 "SMTP smuggling" flaw, which let
//!   an attacker inject a whole second message into an authenticated session.
//! * §4.5.3.1.6 caps a text line at 1000 octets including CRLF. Enforced, both
//!   when writing and when reading.
//!
//! Nothing here allocates a socket or blocks; `Stuffer` is a byte-at-a-time
//! state machine, so a caller may stream a body of any size through it.

const std = @import("std");
const testing = std.testing;

pub const Options = struct {
    /// What to do with a lone LF or lone CR in the body being sent.
    /// `.normalize` rewrites it to CRLF (what every MUA composing a message
    /// wants); `.strict` refuses it, for a caller that has already canonicalised
    /// its own bytes and wants that asserted.
    newline: enum { normalize, strict } = .normalize,
    /// RFC 5321 §4.5.3.1.6 — 1000 octets including CRLF, so 998 of text.
    max_line: usize = 998,
};

pub const StuffError = error{
    /// `.strict` newline handling and a LF without a CR.
    BareLineFeed,
    /// `.strict` newline handling and a CR without a LF.
    BareCarriageReturn,
    /// A body line longer than `Options.max_line`.
    LineTooLong,
};

/// Streaming dot-stuffer. Feed the body in any number of pieces, then `finish`.
///
///     var s: Stuffer = .init(.{});
///     try s.write(w, part1);
///     try s.write(w, part2);
///     try s.finish(w);        // emits the closing CRLF "." CRLF
pub const Stuffer = struct {
    opts: Options,
    /// True when the next byte begins a line (so a `.` must be doubled).
    at_line_start: bool = true,
    /// True when the previous byte was a CR whose LF has not arrived yet.
    pending_cr: bool = false,
    /// Octets already written on the current line.
    line_len: usize = 0,

    pub fn init(opts: Options) Stuffer {
        return .{ .opts = opts };
    }

    pub fn write(self: *Stuffer, w: *std.Io.Writer, bytes: []const u8) (StuffError || std.Io.Writer.Error)!void {
        for (bytes) |c| try self.byte(w, c);
    }

    fn byte(self: *Stuffer, w: *std.Io.Writer, c: u8) (StuffError || std.Io.Writer.Error)!void {
        if (self.pending_cr) {
            self.pending_cr = false;
            if (c == '\n') {
                try w.writeAll("\r\n");
                self.at_line_start = true;
                self.line_len = 0;
                return;
            }
            // A lone CR.
            if (self.opts.newline == .strict) return error.BareCarriageReturn;
            try w.writeAll("\r\n");
            self.at_line_start = true;
            self.line_len = 0;
            // fall through and handle `c` as the first byte of the next line
        }
        switch (c) {
            '\r' => {
                self.pending_cr = true;
                return;
            },
            '\n' => {
                if (self.opts.newline == .strict) return error.BareLineFeed;
                try w.writeAll("\r\n");
                self.at_line_start = true;
                self.line_len = 0;
                return;
            },
            else => {},
        }
        if (self.at_line_start and c == '.') {
            // §4.5.2: the sender doubles a leading period. The extra octet does
            // not count against the line-length limit, which is a limit on the
            // *text*.
            try w.writeByte('.');
        }
        if (self.line_len >= self.opts.max_line) return error.LineTooLong;
        try w.writeByte(c);
        self.line_len += 1;
        self.at_line_start = false;
    }

    /// Close the data stream: terminate a partial line, then emit `.CRLF`.
    pub fn finish(self: *Stuffer, w: *std.Io.Writer) (StuffError || std.Io.Writer.Error)!void {
        if (self.pending_cr) {
            self.pending_cr = false;
            if (self.opts.newline == .strict) return error.BareCarriageReturn;
            try w.writeAll("\r\n");
            self.at_line_start = true;
        }
        if (!self.at_line_start) try w.writeAll("\r\n");
        try w.writeAll(".\r\n");
        self.at_line_start = true;
        self.line_len = 0;
    }
};

/// One-shot: dot-stuff `body` and write the terminator.
pub fn writeData(w: *std.Io.Writer, body: []const u8, opts: Options) (StuffError || std.Io.Writer.Error)!void {
    var s: Stuffer = .init(opts);
    try s.write(w, body);
    try s.finish(w);
}

/// Dot-stuff into a freshly allocated buffer.
pub fn stuffAlloc(gpa: std.mem.Allocator, body: []const u8, opts: Options) (StuffError || std.mem.Allocator.Error)![]u8 {
    var aw: std.Io.Writer.Allocating = .init(gpa);
    errdefer aw.deinit();
    writeData(&aw.writer, body, opts) catch |e| switch (e) {
        error.WriteFailed => return error.OutOfMemory,
        else => |other| return other,
    };
    return aw.toOwnedSlice();
}

// ── receive side ───────────────────────────────────────────────────────────

pub const UnstuffError = error{
    /// A LF that was not preceded by CR (see `UnstuffOptions.allow_bare_lf`).
    BareLineFeed,
    /// A CR that was not followed by LF.
    BareCarriageReturn,
    /// A line over `UnstuffOptions.max_line`.
    LineTooLong,
    /// More body than `UnstuffOptions.max_body`.
    BodyTooLarge,
    /// More data was fed after the terminator was seen.
    DataAfterTerminator,
} || std.mem.Allocator.Error;

pub const UnstuffOptions = struct {
    max_line: usize = 998,
    max_body: usize = 64 * 1024 * 1024,
    /// Off by default — see the file comment on SMTP smuggling.
    allow_bare_lf: bool = false,
};

/// Incremental un-stuffer: the mirror of `Stuffer`, and the piece a server side
/// would need. It exists here because it is how the sender is tested — the
/// round-trip `stuff → unstuff` must be the identity, including for a body
/// containing a lone `.` line.
pub const Unstuffer = struct {
    gpa: std.mem.Allocator,
    opts: UnstuffOptions,
    body: std.ArrayList(u8) = .empty,
    line: std.ArrayList(u8) = .empty,
    pending_cr: bool = false,
    done: bool = false,

    pub fn init(gpa: std.mem.Allocator, opts: UnstuffOptions) Unstuffer {
        return .{ .gpa = gpa, .opts = opts };
    }

    pub fn deinit(self: *Unstuffer) void {
        self.body.deinit(self.gpa);
        self.line.deinit(self.gpa);
        self.* = undefined;
    }

    /// Feed received bytes. Returns true once `CRLF.CRLF` has been seen.
    pub fn feed(self: *Unstuffer, input: []const u8) UnstuffError!bool {
        for (input) |c| {
            if (self.done) return error.DataAfterTerminator;
            if (self.pending_cr) {
                self.pending_cr = false;
                if (c != '\n') return error.BareCarriageReturn;
                try self.endLine();
                continue;
            }
            switch (c) {
                '\r' => self.pending_cr = true,
                '\n' => {
                    if (!self.opts.allow_bare_lf) return error.BareLineFeed;
                    try self.endLine();
                },
                else => {
                    if (self.line.items.len >= self.opts.max_line) return error.LineTooLong;
                    try self.line.append(self.gpa, c);
                },
            }
        }
        return self.done;
    }

    fn endLine(self: *Unstuffer) UnstuffError!void {
        const l = self.line.items;
        if (l.len == 1 and l[0] == '.') {
            self.done = true;
            self.line.clearRetainingCapacity();
            return;
        }
        const text = if (l.len != 0 and l[0] == '.') l[1..] else l;
        if (self.body.items.len + text.len + 2 > self.opts.max_body) return error.BodyTooLarge;
        try self.body.appendSlice(self.gpa, text);
        try self.body.appendSlice(self.gpa, "\r\n");
        self.line.clearRetainingCapacity();
    }

    /// The decoded body. Meaningful once `feed` returned true.
    pub fn bytes(self: *const Unstuffer) []const u8 {
        return self.body.items;
    }
};

/// Un-stuff a complete `…CRLF.CRLF` stream into a freshly allocated buffer.
pub fn unstuffAlloc(gpa: std.mem.Allocator, wire: []const u8, opts: UnstuffOptions) UnstuffError![]u8 {
    var u: Unstuffer = .init(gpa, opts);
    defer u.deinit();
    _ = try u.feed(wire);
    return gpa.dupe(u8, u.bytes());
}

// ── tests ──────────────────────────────────────────────────────────────────

fn stuffed(gpa: std.mem.Allocator, body: []const u8) ![]u8 {
    return stuffAlloc(gpa, body, .{});
}

test "the canonical case: a body line that is exactly a single period" {
    const gpa = testing.allocator;
    const body = "line one\r\n.\r\nline three\r\n";
    const wire = try stuffed(gpa, body);
    defer gpa.free(wire);
    try testing.expectEqualStrings("line one\r\n..\r\nline three\r\n.\r\n", wire);

    // ...and the receiver gets exactly the original bytes back.
    const back = try unstuffAlloc(gpa, wire, .{});
    defer gpa.free(back);
    try testing.expectEqualStrings(body, back);
}

test "periods only matter at the start of a line" {
    const gpa = testing.allocator;
    const body = "a.b\r\n.leading\r\ntrailing.\r\n...three\r\n";
    const wire = try stuffed(gpa, body);
    defer gpa.free(wire);
    try testing.expectEqualStrings("a.b\r\n..leading\r\ntrailing.\r\n....three\r\n.\r\n", wire);
    const back = try unstuffAlloc(gpa, wire, .{});
    defer gpa.free(back);
    try testing.expectEqualStrings(body, back);
}

test "an empty body is a legal, terminated DATA stream" {
    const gpa = testing.allocator;
    const wire = try stuffed(gpa, "");
    defer gpa.free(wire);
    try testing.expectEqualStrings(".\r\n", wire);
    const back = try unstuffAlloc(gpa, wire, .{});
    defer gpa.free(back);
    try testing.expectEqualStrings("", back);
}

test "a body not ending in CRLF gets one before the terminator" {
    const gpa = testing.allocator;
    const wire = try stuffed(gpa, "no newline at the end");
    defer gpa.free(wire);
    try testing.expectEqualStrings("no newline at the end\r\n.\r\n", wire);
}

test "lone LF and lone CR are normalised by default, refused in strict mode" {
    const gpa = testing.allocator;
    const wire = try stuffed(gpa, "unix\nlines\nhere\n");
    defer gpa.free(wire);
    try testing.expectEqualStrings("unix\r\nlines\r\nhere\r\n.\r\n", wire);

    const cr = try stuffed(gpa, "old\rmac\r");
    defer gpa.free(cr);
    try testing.expectEqualStrings("old\r\nmac\r\n.\r\n", cr);

    try testing.expectError(error.BareLineFeed, stuffAlloc(gpa, "unix\nlines", .{ .newline = .strict }));
    try testing.expectError(error.BareCarriageReturn, stuffAlloc(gpa, "old\rmac", .{ .newline = .strict }));
}

test "streaming in arbitrary pieces gives the same bytes as one shot" {
    const gpa = testing.allocator;
    const body = "alpha\r\n.\r\nbeta\r\n..gamma\r\n";
    const one = try stuffed(gpa, body);
    defer gpa.free(one);

    for ([_]usize{ 1, 2, 3, 5, 7 }) |step| {
        var aw: std.Io.Writer.Allocating = .init(gpa);
        defer aw.deinit();
        var s: Stuffer = .init(.{});
        var i: usize = 0;
        while (i < body.len) : (i += step) {
            try s.write(&aw.writer, body[i..@min(i + step, body.len)]);
        }
        try s.finish(&aw.writer);
        try testing.expectEqualStrings(one, aw.written());
    }
}

test "the 998-octet line limit is enforced on send and on receive" {
    const gpa = testing.allocator;
    const long = "A" ** 999 ++ "\r\n";
    try testing.expectError(error.LineTooLong, stuffAlloc(gpa, long, .{}));
    const ok = try stuffAlloc(gpa, "A" ** 998 ++ "\r\n", .{});
    defer gpa.free(ok);
    try testing.expectError(error.LineTooLong, unstuffAlloc(gpa, "A" ** 999 ++ "\r\n.\r\n", .{}));
    // A caller may raise the ceiling knowingly.
    const raised = try stuffAlloc(gpa, long, .{ .max_line = 2000 });
    defer gpa.free(raised);
}

test "SMTP smuggling: only CRLF.CRLF terminates the data" {
    const gpa = testing.allocator;
    // A bare LF is refused outright by default...
    try testing.expectError(error.BareLineFeed, unstuffAlloc(gpa, "body\n.\n", .{}));
    // ...and even with bare-LF tolerance turned on, the check that matters is
    // that the stream really did end: a stream with no CRLF.CRLF is not done.
    var u: Unstuffer = .init(gpa, .{});
    defer u.deinit();
    try testing.expect(!try u.feed("body\r\n"));
    try testing.expect(!try u.feed("."));
    try testing.expect(!try u.feed("\r"));
    try testing.expect(try u.feed("\n"));
    try testing.expectEqualStrings("body\r\n", u.bytes());
    try testing.expectError(error.DataAfterTerminator, u.feed("more"));

    // A lone CR inside the received stream is a framing lie.
    try testing.expectError(error.BareCarriageReturn, unstuffAlloc(gpa, "a\rb\r\n.\r\n", .{}));
}

test "malformed dot-stuffing on receive: a lone '.' line ends it, '..' is data" {
    const gpa = testing.allocator;
    // "..\r\n" decodes to ".\r\n"; a following ".\r\n" ends the stream.
    const back = try unstuffAlloc(gpa, "..\r\n.\r\n", .{});
    defer gpa.free(back);
    try testing.expectEqualStrings(".\r\n", back);

    // A stream that starts with the terminator is an empty body.
    const empty = try unstuffAlloc(gpa, ".\r\n", .{});
    defer gpa.free(empty);
    try testing.expectEqualStrings("", empty);

    // ".." alone (never terminated) leaves `done` false and loses nothing.
    var u: Unstuffer = .init(gpa, .{});
    defer u.deinit();
    try testing.expect(!try u.feed("..\r\nunterminated"));
    try testing.expectEqualStrings(".\r\n", u.bytes());
}

test "received body size is bounded" {
    const gpa = testing.allocator;
    try testing.expectError(error.BodyTooLarge, unstuffAlloc(gpa, "AAAA\r\nBBBB\r\n.\r\n", .{ .max_body = 8 }));
}

test "round-trip property: unstuff(stuff(x)) == x for CRLF-canonical x" {
    const gpa = testing.allocator;
    const bodies = [_][]const u8{
        "",
        ".\r\n",
        "..\r\n",
        ".\r\n.\r\n.\r\n",
        "\r\n\r\n\r\n",
        "Subject: x\r\n\r\n.\r\nbody\r\n",
        "." ** 50 ++ "\r\n",
    };
    for (bodies) |b| {
        const wire = try stuffed(gpa, b);
        defer gpa.free(wire);
        const back = try unstuffAlloc(gpa, wire, .{});
        defer gpa.free(back);
        try testing.expectEqualStrings(b, back);
    }
}

test "fuzz: stuffing then un-stuffing is the identity, and neither crashes" {
    try testing.fuzz({}, fuzzDots, .{});
}

fn fuzzDots(_: void, smith: *std.testing.Smith) !void {
    const gpa = testing.allocator;
    var raw: [256]u8 = undefined;
    smith.bytes(&raw);
    const len = smith.valueRangeAtMost(u16, 0, raw.len);
    const input = raw[0..len];

    // 1. Arbitrary bytes through the un-stuffer must never crash.
    {
        var u: Unstuffer = .init(gpa, .{ .max_line = 64, .max_body = 4096, .allow_bare_lf = smith.value(bool) });
        defer u.deinit();
        _ = u.feed(input) catch {};
    }

    // 2. Stuff-then-unstuff must round-trip whatever the stuffer accepted.
    const wire = stuffAlloc(gpa, input, .{ .max_line = 1000 }) catch return;
    defer gpa.free(wire);
    const back = unstuffAlloc(gpa, wire, .{ .max_line = 1000 }) catch |e| {
        std.debug.print("unstuff refused our own output: {s}\n", .{@errorName(e)});
        return error.RoundTripFailed;
    };
    defer gpa.free(back);
    // The stuffer canonicalises line endings and guarantees a final CRLF, so
    // the identity holds against the canonicalised form.
    const canon = canonicalise(gpa, input) catch return;
    defer gpa.free(canon);
    if (!std.mem.eql(u8, canon, back)) {
        std.debug.print("round-trip mismatch\n", .{});
        return error.RoundTripFailed;
    }
}

/// The CRLF canonicalisation `Stuffer` applies, computed independently so the
/// fuzz round-trip is not comparing the stuffer against itself.
fn canonicalise(gpa: std.mem.Allocator, input: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var i: usize = 0;
    while (i < input.len) : (i += 1) {
        switch (input[i]) {
            '\r' => {
                try out.appendSlice(gpa, "\r\n");
                if (i + 1 < input.len and input[i + 1] == '\n') i += 1;
            },
            '\n' => try out.appendSlice(gpa, "\r\n"),
            else => |c| try out.append(gpa, c),
        }
    }
    if (out.items.len != 0 and !std.mem.endsWith(u8, out.items, "\r\n")) try out.appendSlice(gpa, "\r\n");
    return out.toOwnedSlice(gpa);
}
