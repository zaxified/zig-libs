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
//!   not end the data — not even with `UnstuffOptions.allow_bare_lf`, which
//!   only stops a bare LF from being an error — and by default a bare LF
//!   anywhere in a received stream is `error.BareLineFeed`. Disagreement between an MTA that accepts `LF.LF`
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
            // §4.5.2: the sender doubles a leading period. The doubled dot IS
            // part of the transmitted line §4.5.3.1.6's 998-octet limit
            // covers, so it must be checked and charged against `line_len`
            // exactly like any other octet — the *receiving* side
            // (`Unstuffer`) already counts it, so a `Stuffer` that let it
            // through free could emit a line one octet longer than its own
            // `Unstuffer` (or any compliant receiver) will accept (wave-2
            // audit `smtp` F2).
            if (self.line_len >= self.opts.max_line) return error.LineTooLong;
            try w.writeByte('.');
            self.line_len += 1;
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

/// RFC 1870 §3's size of `body` as `Stuffer` sends it: octets including CRLF
/// pairs after `opts.newline` handling, excluding doubled dots and the
/// terminating `.CRLF`. A body not ending in a line break counts the CRLF
/// `finish` adds. `.strict` refuses a lone LF or CR here, as `Stuffer` would.
pub fn messageSize(body: []const u8, opts: Options) StuffError!u64 {
    var n: u64 = 0;
    var at_line_start = true;
    var i: usize = 0;
    while (i < body.len) : (i += 1) {
        switch (body[i]) {
            '\r' => {
                if (i + 1 < body.len and body[i + 1] == '\n') {
                    i += 1;
                } else if (opts.newline == .strict) return error.BareCarriageReturn;
                n += 2;
                at_line_start = true;
            },
            '\n' => {
                if (opts.newline == .strict) return error.BareLineFeed;
                n += 2;
                at_line_start = true;
            },
            else => {
                n += 1;
                at_line_start = false;
            },
        }
    }
    if (!at_line_start) n += 2;
    return n;
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
    /// Off by default — see the file comment on SMTP smuggling. On, a bare LF
    /// ends a line of DATA instead of being `error.BareLineFeed`; it never
    /// takes part in the terminator, which stays `CRLF "." CRLF`.
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
    /// The line before the current one ended in CRLF. True at the start: the
    /// stream begins after the CRLF of the 354 exchange.
    prev_crlf: bool = true,

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
                try self.endLine(true);
                continue;
            }
            switch (c) {
                '\r' => self.pending_cr = true,
                '\n' => {
                    if (!self.opts.allow_bare_lf) return error.BareLineFeed;
                    try self.endLine(false);
                },
                else => {
                    if (self.line.items.len >= self.opts.max_line) return error.LineTooLong;
                    try self.line.append(self.gpa, c);
                },
            }
        }
        return self.done;
    }

    /// `crlf`: this line ended in CRLF rather than a tolerated bare LF.
    fn endLine(self: *Unstuffer, crlf: bool) UnstuffError!void {
        const l = self.line.items;
        const prev_crlf = self.prev_crlf;
        self.prev_crlf = crlf;
        // RFC 5321 §4.1.1.4: the terminator is CRLF "." CRLF — both breaks
        // CRLF. A "." line with a bare LF on either side is data, so
        // `\n.\n`, `\n.\r\n` and `\r\n.\n` cannot end the stream even with
        // `allow_bare_lf` (CVE-2023-51764, A1 F2).
        if (l.len == 1 and l[0] == '.' and crlf and prev_crlf) {
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

test "F2: a line-start dot counts against the line limit on both send and receive" {
    // Regression for the wave-2 audit's F2: Stuffer used to exclude the
    // transparency dot from `line_len`, so a body line of exactly `max_line`
    // (998) octets starting with '.' produced a 999-octet wire line — one
    // octet longer than Unstuffer (which DOES count the dot) will accept.
    // Reproduced pre-fix: `stuffAlloc` on ". A"*997 ++"\r\n" succeeded, and
    // feeding that exact wire output straight back into `unstuffAlloc`
    // failed with `error.LineTooLong` — our own encoder emitted a line our
    // own decoder rejected.
    const gpa = testing.allocator;

    // A leading dot doubles on the wire, so a source line of `n` octets
    // starting with '.' becomes an (n+1)-octet wire line — one octet of the
    // 998-octet wire budget is spent on the doubling itself. At the cap:
    // source "." + 996 'A's = 997 source octets → wire ".." + 996 'A's = 998
    // wire octets, exactly the budget. Both the stuffer and a receiver
    // applying the same 998-octet cap must accept it, and stuffing then
    // unstuffing it must round-trip.
    {
        const body = "." ++ "A" ** 996 ++ "\r\n";
        const wire = try stuffAlloc(gpa, body, .{});
        defer gpa.free(wire);
        const back = try unstuffAlloc(gpa, wire, .{});
        defer gpa.free(back);
        try testing.expectEqualStrings(body, back);
    }

    // One source octet more — "." + 997 'A's = 998 source octets — would
    // double to a 999-octet wire line, one over budget. This is the exact
    // audit repro: the OLD Stuffer accepted this (it never charged the
    // doubled dot against `line_len`), producing a wire line its own
    // Unstuffer then refused with `error.LineTooLong`. The fixed Stuffer
    // must refuse it too, at the point of writing, not silently emit a
    // non-compliant line for its own receiver to reject.
    {
        const body = "." ++ "A" ** 997 ++ "\r\n";
        try testing.expectError(error.LineTooLong, stuffAlloc(gpa, body, .{}));
    }
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

    // A1 F2 — WITH bare-LF tolerance on, the three CVE-2023-51764 spellings
    // still do not end the data: the smuggled command stays inside the body
    // instead of being handed back as the start of a second transaction.
    for ([_][]const u8{ "\n.\n", "\n.\r\n", "\r\n.\n" }) |term| {
        var t: Unstuffer = .init(gpa, .{ .allow_bare_lf = true });
        defer t.deinit();
        const smuggle = try std.mem.concat(gpa, u8, &.{ "a", term, "MAIL FROM:<evil@x.test>\r\n" });
        defer gpa.free(smuggle);
        try testing.expect(!try t.feed(smuggle));
        try testing.expect(try t.feed(".\r\n"));
        try testing.expect(std.mem.indexOf(u8, t.bytes(), "MAIL FROM:<evil@x.test>\r\n") != null);
    }
}

test "messageSize is RFC 1870's size of what Stuffer sends (A1 F6)" {
    try testing.expectEqual(@as(u64, 20), try messageSize("Subject: t\r\n\r\nline\r\n", .{}));
    // LF endings are sent as CRLF: 17 bytes given, 20 on the wire.
    try testing.expectEqual(@as(u64, 20), try messageSize("Subject: t\n\nline\n", .{}));
    try testing.expectEqual(@as(u64, 6), try messageSize("a\rb", .{})); // lone CR, then the final CRLF
    try testing.expectEqual(@as(u64, 0), try messageSize("", .{}));
    try testing.expectError(error.BareLineFeed, messageSize("a\nb", .{ .newline = .strict }));
    try testing.expectError(error.BareCarriageReturn, messageSize("a\rb", .{ .newline = .strict }));
    // It agrees with the bytes Stuffer actually writes, minus doubled dots and ".\r\n".
    const gpa = testing.allocator;
    const body = "x\n.y\r\nz";
    const wire = try stuffAlloc(gpa, body, .{});
    defer gpa.free(wire);
    try testing.expectEqual(@as(u64, wire.len - 1 - 3), try messageSize(body, .{})); // one doubled dot, ".\r\n"
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

/// `testkit.fuzz.seed`, aliased so the corpus below reads as the bodies it is.
/// A corpus entry is not the frame: `Smith.slice` reads a little-endian `u32`
/// length first, so a raw body would arrive minus its own first four octets.
/// `testkit/src/fuzz.zig` carries the other two hazards.
const seed = @import("testkit").fuzz.seed;

/// DATA bodies and wire streams, in the format `Smith.slice` reads.
///
/// The bodies from the round-trip property test above, the three framing lies
/// (`bare LF`, `bare CR`, data after the terminator), and — the reason this
/// corpus exists — the four line-length cases either side of the 1000-octet
/// `max_line` the harness configures, with and without the transparency dot
/// that the wave-2 F2 finding was about.
const dot_seeds = [_][]const u8{
    seed(".\r\n"), // a single dot line
    seed("..\r\n"), // a doubled dot: data, not a terminator
    seed(".\r\n.\r\n.\r\n"), // three of them
    seed("\r\n\r\n\r\n"), // empty lines only
    seed("Subject: x\r\n\r\n.\r\nbody\r\n"), // a header block with a dot line inside the body
    seed("." ** 50 ++ "\r\n"), // 50 dots: only the leading one doubles
    seed("..\r\n.\r\n"), // wire form: "..\r\n" decodes to ".\r\n", then the terminator
    seed(".\r\n" ++ "more"), // DataAfterTerminator on the receive side
    seed("body\n.\n"), // BareLineFeed unless allow_bare_lf
    seed("a\rb\r\n.\r\n"), // BareCarriageReturn: a framing lie in either mode
    seed("AAAA\r\nBBBB\r\n.\r\n"), // two short lines and a terminator
    seed("no trailing newline"), // the stuffer must add the final CRLF itself
    seed("A" ** 1000 ++ "\r\n"), // exactly max_line on the wire: accepted
    seed("A" ** 1001 ++ "\r\n"), // LineTooLong: one octet over
    seed("." ++ "A" ** 998 ++ "\r\n"), // 999 source octets doubling to exactly max_line
    seed("." ++ "A" ** 999 ++ "\r\n"), // LineTooLong: the doubled dot is what puts it over
};

test "fuzz: stuffing then un-stuffing is the identity, and neither crashes" {
    try testing.fuzz({}, fuzzDots, .{ .corpus = &dot_seeds });
}

fn fuzzDots(_: void, smith: *std.testing.Smith) !void {
    const gpa = testing.allocator;
    // F2 (wave-2 audit): 256 raw bytes, even doubled by stuffing, could never
    // reach the 1000-octet `max_line` both sides below are configured with,
    // so this harness could never exercise the line-length boundary where
    // the stuffer/unstuffer asymmetry lived. 1100 comfortably clears it
    // (worst case a single all-dots line, doubled, still exceeds 1000).
    // ⚠ And that fix bought NOTHING on its own: the length below was drawn
    // with `smith.valueRangeAtMost` after a `smith.bytes` that had already
    // consumed the input, so it was 0 and the harness fed the stuffer an EMPTY
    // body no matter how large this buffer was. The boundary the F2 note is
    // about is reached only now, and only because the corpus contains the four
    // seeds that sit either side of it.
    var raw: [1100]u8 = undefined;
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
    // length -- see above.
    const len = smith.slice(&raw);
    const input = raw[0..len];

    // 1. Arbitrary bytes through the un-stuffer must never crash.
    // ⚠ `allow_bare_lf` used to be one more draw off the same Smith, taken
    // AFTER the length. Every draw after a `slice` that consumed the whole
    // seed returns the weight minimum -- `false` for a bool -- so the lenient
    // mode would never be entered on a corpus replay. Both are simply tried.
    for ([_]bool{ false, true }) |bare_lf| {
        var u: Unstuffer = .init(gpa, .{ .max_line = 64, .max_body = 4096, .allow_bare_lf = bare_lf });
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

test "corpus: every dot seed reaches the stuffer, and the counts are pinned" {
    // ⭐ The measurement, executable rather than written in a comment. A seed
    // longer than the harness's buffer reads back EMPTY (`Smith.slice` falls
    // back to the range minimum), which is silent everywhere else.
    //
    // Two counts, because the two halves of the harness disagree on purpose:
    // the stuffer at `max_line = 1000` takes the long lines, the receiving
    // `Unstuffer` at `max_line = 64` does not. A single "accepted" would also
    // be a poor guard here for the reason `bacnet/service` was: `stuffAlloc("")`
    // succeeds, so the collapsed harness's one and only execution "passed".
    const gpa = testing.allocator;
    var nonempty: usize = 0;
    var stuff_ok: usize = 0;
    var unstuff_terminated: usize = 0;
    for (dot_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var raw: [1100]u8 = undefined;
        const len = smith.slice(&raw);
        if (len != 0) nonempty += 1;
        const input = raw[0..len];
        if (stuffAlloc(gpa, input, .{ .max_line = 1000 })) |wire| {
            gpa.free(wire);
            stuff_ok += 1;
        } else |_| {}
        var u: Unstuffer = .init(gpa, .{ .max_line = 64, .max_body = 4096 });
        defer u.deinit();
        if (u.feed(input)) |done| {
            if (done) unstuff_terminated += 1;
        } else |_| {}
    }
    try testing.expectEqual(dot_seeds.len, nonempty);
    // Measured 2026-09-07: 0 of 16 seeds non-empty before the draw was fixed
    // and the stuffer only ever saw the empty body; 16 of 16 after.
    try testing.expectEqual(@as(usize, 14), stuff_ok);
    try testing.expectEqual(@as(usize, 3), unstuff_terminated);
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
