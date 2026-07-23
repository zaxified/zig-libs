// SPDX-License-Identifier: MIT

//! RFC 5321 §4.1.1.1 / RFC 1869 — the ESMTP capability set announced by EHLO.
//!
//! The EHLO reply is a multi-line 250: the first line is the server's greeting
//! (its domain, plus free text), every later line is one `ehlo-keyword` with
//! optional parameters. Keywords are case-insensitive; unknown ones are kept
//! verbatim and ignored, which is what RFC 1869 §4.5 requires — a client that
//! errors on an unknown extension breaks against every future server.
//!
//! The extensions resolved here are the ones that change what the client is
//! allowed to do: STARTTLS (RFC 3207), AUTH (RFC 4954), PIPELINING (RFC 2920),
//! SIZE (RFC 1870), 8BITMIME (RFC 6152), SMTPUTF8 (RFC 6531),
//! ENHANCEDSTATUSCODES (RFC 2034), CHUNKING/BINARYMIME (RFC 3030) and DSN
//! (RFC 3461). The last three are *reported* but not implemented; see SPEC.md.
//!
//! **Security note.** A capability set learned before STARTTLS is attacker
//! controlled: an active attacker can add, remove or forge any line of it. RFC
//! 3207 §4.2 therefore requires the client to discard it and re-issue EHLO on
//! the encrypted stream. `Capabilities.deinit` + a fresh `parse` is that
//! discard, and `session.zig` performs it unconditionally.

const std = @import("std");
const testing = std.testing;

/// SASL mechanisms this module can actually perform, plus a catch-all.
pub const Mechanism = enum {
    plain,
    login,

    pub fn name(self: Mechanism) []const u8 {
        return switch (self) {
            .plain => "PLAIN",
            .login => "LOGIN",
        };
    }
};

/// Which mechanisms the server offered. `other` is true when it offered
/// something we do not implement (CRAM-MD5, GSSAPI, XOAUTH2, …) — useful for a
/// caller's diagnostics, never for a decision.
pub const AuthSet = struct {
    plain: bool = false,
    login: bool = false,
    other: bool = false,

    pub fn supports(self: AuthSet, m: Mechanism) bool {
        return switch (m) {
            .plain => self.plain,
            .login => self.login,
        };
    }

    pub fn any(self: AuthSet) bool {
        return self.plain or self.login;
    }
};

pub const Limits = struct {
    /// Most capability lines kept. The reply parser bounds the reply itself;
    /// this bounds what we retain from it.
    max_lines: usize = 256,
    /// Longest capability line kept verbatim.
    max_line: usize = 1024,
};

pub const ParseError = error{
    /// The EHLO reply had no lines at all.
    EmptyEhloReply,
    /// More capability lines than `Limits.max_lines`.
    TooManyCapabilities,
} || std.mem.Allocator.Error;

/// The resolved capability set. `lines` keeps every keyword line verbatim so a
/// caller can inspect an extension this module does not model.
pub const Capabilities = struct {
    gpa: std.mem.Allocator,
    /// The first token of the greeting line — the server's own domain (or
    /// address literal). Never trusted for anything; reported for logs.
    domain: []u8 = &.{},
    /// The whole greeting line.
    greeting: []u8 = &.{},
    /// Every capability line after the greeting, verbatim.
    lines: [][]u8 = &.{},

    starttls: bool = false,
    pipelining: bool = false,
    eightbitmime: bool = false,
    smtputf8: bool = false,
    enhanced_status_codes: bool = false,
    chunking: bool = false,
    binarymime: bool = false,
    dsn: bool = false,
    auth: AuthSet = .{},
    /// `SIZE` was advertised.
    size_advertised: bool = false,
    /// The declared maximum message size, when `SIZE` carried a usable number.
    /// null with `size_advertised` true means "advertised, no fixed maximum"
    /// (RFC 1870 §6.2) or an unparsable parameter.
    max_size: ?u64 = null,

    pub fn empty(gpa: std.mem.Allocator) Capabilities {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *Capabilities) void {
        self.gpa.free(self.domain);
        self.gpa.free(self.greeting);
        for (self.lines) |l| self.gpa.free(l);
        self.gpa.free(self.lines);
        self.* = undefined;
    }

    /// Case-insensitive keyword lookup over the verbatim lines.
    pub fn has(self: *const Capabilities, keyword: []const u8) bool {
        return self.line(keyword) != null;
    }

    /// The verbatim line for `keyword`, or null.
    pub fn line(self: *const Capabilities, keyword: []const u8) ?[]const u8 {
        for (self.lines) |l| {
            const kw = firstToken(l);
            if (std.ascii.eqlIgnoreCase(kw, keyword)) return l;
        }
        return null;
    }

    /// Everything after the keyword on its line (the parameters), or null when
    /// the keyword is absent. An empty slice means "advertised, no parameters".
    pub fn params(self: *const Capabilities, keyword: []const u8) ?[]const u8 {
        const l = self.line(keyword) orelse return null;
        const kw = firstToken(l);
        var rest = l[kw.len..];
        while (rest.len != 0 and (rest[0] == ' ' or rest[0] == '\t')) rest = rest[1..];
        return rest;
    }

    /// Would a message of `size` octets be refused outright by RFC 1870 §6.2?
    /// False when no fixed maximum was advertised — the server may still say no
    /// at MAIL time, which is the answer that counts.
    pub fn sizeExceeded(self: *const Capabilities, size: u64) bool {
        const max = self.max_size orelse return false;
        return size > max;
    }
};

fn firstToken(s: []const u8) []const u8 {
    const end = std.mem.indexOfAny(u8, s, " \t") orelse s.len;
    return s[0..end];
}

/// Parse the LF-joined text of a 250 EHLO reply (`reply.Reply.text`).
pub fn parse(gpa: std.mem.Allocator, text: []const u8, limits: Limits) ParseError!Capabilities {
    var caps: Capabilities = .empty(gpa);
    errdefer caps.deinit();

    var it = std.mem.splitScalar(u8, text, '\n');
    const greeting = it.next() orelse return error.EmptyEhloReply;
    caps.greeting = try gpa.dupe(u8, greeting[0..@min(greeting.len, limits.max_line)]);
    caps.domain = try gpa.dupe(u8, firstToken(caps.greeting));

    var lines: std.ArrayList([]u8) = .empty;
    errdefer {
        for (lines.items) |l| gpa.free(l);
        lines.deinit(gpa);
    }
    while (it.next()) |raw| {
        if (raw.len == 0) continue;
        if (lines.items.len >= limits.max_lines) return error.TooManyCapabilities;
        const kept = try gpa.dupe(u8, raw[0..@min(raw.len, limits.max_line)]);
        errdefer gpa.free(kept);
        try lines.append(gpa, kept);
        applyKeyword(&caps, kept);
    }
    caps.lines = try lines.toOwnedSlice(gpa);
    return caps;
}

fn applyKeyword(caps: *Capabilities, l: []const u8) void {
    const kw = firstToken(l);
    var rest = l[kw.len..];
    while (rest.len != 0 and (rest[0] == ' ' or rest[0] == '\t')) rest = rest[1..];

    if (std.ascii.eqlIgnoreCase(kw, "STARTTLS")) {
        caps.starttls = true;
    } else if (std.ascii.eqlIgnoreCase(kw, "PIPELINING")) {
        caps.pipelining = true;
    } else if (std.ascii.eqlIgnoreCase(kw, "8BITMIME")) {
        caps.eightbitmime = true;
    } else if (std.ascii.eqlIgnoreCase(kw, "SMTPUTF8")) {
        caps.smtputf8 = true;
    } else if (std.ascii.eqlIgnoreCase(kw, "ENHANCEDSTATUSCODES")) {
        caps.enhanced_status_codes = true;
    } else if (std.ascii.eqlIgnoreCase(kw, "CHUNKING")) {
        caps.chunking = true;
    } else if (std.ascii.eqlIgnoreCase(kw, "BINARYMIME")) {
        caps.binarymime = true;
    } else if (std.ascii.eqlIgnoreCase(kw, "DSN")) {
        caps.dsn = true;
    } else if (std.ascii.eqlIgnoreCase(kw, "SIZE")) {
        caps.size_advertised = true;
        // RFC 1870 §6.2: the parameter is optional, and "0" means no fixed
        // maximum. An unparsable parameter is treated the same way — the
        // server's MAIL-time answer is what actually binds.
        if (rest.len != 0) {
            if (std.fmt.parseInt(u64, rest, 10)) |v| {
                if (v != 0) caps.max_size = v;
            } else |_| {}
        }
    } else if (std.ascii.eqlIgnoreCase(kw, "AUTH")) {
        parseAuthList(caps, rest);
    } else if (kw.len > 5 and std.ascii.eqlIgnoreCase(kw[0..5], "AUTH=")) {
        // The broken-but-widespread sendmail form `AUTH=LOGIN PLAIN`, kept
        // alive by RFC 4954 §4's note about pre-standard implementations.
        var joined_buf: [256]u8 = undefined;
        const tail = kw[5..];
        const n = @min(tail.len, joined_buf.len);
        @memcpy(joined_buf[0..n], tail[0..n]);
        parseAuthList(caps, joined_buf[0..n]);
        parseAuthList(caps, rest);
    }
}

fn parseAuthList(caps: *Capabilities, list: []const u8) void {
    var it = std.mem.tokenizeAny(u8, list, " \t");
    while (it.next()) |m| {
        if (std.ascii.eqlIgnoreCase(m, "PLAIN")) {
            caps.auth.plain = true;
        } else if (std.ascii.eqlIgnoreCase(m, "LOGIN")) {
            caps.auth.login = true;
        } else {
            caps.auth.other = true;
        }
    }
}

// ── tests ──────────────────────────────────────────────────────────────────

test "a realistic EHLO reply resolves every extension we model" {
    const gpa = testing.allocator;
    // Shape taken from a Postfix/Exim style greeting.
    const text =
        "mail.example.com Hello client.example.org [192.0.2.1]\n" ++
        "SIZE 35882577\n" ++
        "8BITMIME\n" ++
        "PIPELINING\n" ++
        "STARTTLS\n" ++
        "AUTH PLAIN LOGIN CRAM-MD5\n" ++
        "ENHANCEDSTATUSCODES\n" ++
        "SMTPUTF8\n" ++
        "CHUNKING\n" ++
        "DSN";
    var caps = try parse(gpa, text, .{});
    defer caps.deinit();

    try testing.expectEqualStrings("mail.example.com", caps.domain);
    try testing.expect(caps.starttls);
    try testing.expect(caps.pipelining);
    try testing.expect(caps.eightbitmime);
    try testing.expect(caps.smtputf8);
    try testing.expect(caps.enhanced_status_codes);
    try testing.expect(caps.chunking);
    try testing.expect(caps.dsn);
    try testing.expect(!caps.binarymime);
    try testing.expect(caps.size_advertised);
    try testing.expectEqual(@as(?u64, 35882577), caps.max_size);
    try testing.expect(caps.auth.plain and caps.auth.login and caps.auth.other);
    try testing.expect(caps.auth.supports(.plain));
    try testing.expect(caps.sizeExceeded(35882578));
    try testing.expect(!caps.sizeExceeded(35882577));
}

test "keywords are case-insensitive and unknown ones are kept, not rejected" {
    const gpa = testing.allocator;
    var caps = try parse(gpa, "srv\nstarttls\nPiPeLiNiNg\nX-VENDOR-THING param1 param2\nWEIRD!KEYWORD", .{});
    defer caps.deinit();
    try testing.expect(caps.starttls);
    try testing.expect(caps.pipelining);
    try testing.expect(caps.has("x-vendor-thing"));
    try testing.expectEqualStrings("param1 param2", caps.params("X-VENDOR-THING").?);
    // A syntactically invalid keyword is retained verbatim and simply never
    // matches anything we act on.
    try testing.expect(caps.has("WEIRD!KEYWORD"));
    try testing.expect(caps.params("nope") == null);
    try testing.expectEqual(@as(usize, 4), caps.lines.len);
}

test "SIZE without a parameter, with 0, and with garbage" {
    const gpa = testing.allocator;
    {
        var c = try parse(gpa, "srv\nSIZE", .{});
        defer c.deinit();
        try testing.expect(c.size_advertised);
        try testing.expect(c.max_size == null);
        try testing.expect(!c.sizeExceeded(1 << 40));
    }
    {
        var c = try parse(gpa, "srv\nSIZE 0", .{});
        defer c.deinit();
        try testing.expect(c.size_advertised and c.max_size == null);
    }
    {
        var c = try parse(gpa, "srv\nSIZE not-a-number", .{});
        defer c.deinit();
        try testing.expect(c.size_advertised and c.max_size == null);
    }
    {
        var c = try parse(gpa, "srv\nSIZE 99999999999999999999999999", .{});
        defer c.deinit();
        try testing.expect(c.size_advertised and c.max_size == null);
    }
}

test "the legacy AUTH= form is understood" {
    const gpa = testing.allocator;
    var caps = try parse(gpa, "srv\nAUTH=LOGIN PLAIN", .{});
    defer caps.deinit();
    try testing.expect(caps.auth.login and caps.auth.plain);
}

test "AUTH with only mechanisms we cannot perform" {
    const gpa = testing.allocator;
    var caps = try parse(gpa, "srv\nAUTH GSSAPI CRAM-MD5 XOAUTH2", .{});
    defer caps.deinit();
    try testing.expect(!caps.auth.any());
    try testing.expect(caps.auth.other);
}

test "an empty reply text and a greeting-only reply" {
    const gpa = testing.allocator;
    var c = try parse(gpa, "", .{});
    defer c.deinit();
    try testing.expectEqualStrings("", c.domain);
    try testing.expectEqual(@as(usize, 0), c.lines.len);

    var d = try parse(gpa, "mail.example.com at your service", .{});
    defer d.deinit();
    try testing.expectEqualStrings("mail.example.com", d.domain);
    try testing.expectEqual(@as(usize, 0), d.lines.len);
}

test "capability count and line length are bounded" {
    const gpa = testing.allocator;
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(gpa);
    try text.appendSlice(gpa, "srv");
    for (0..40) |i| try text.print(gpa, "\nX-CAP-{d}", .{i});
    try testing.expectError(error.TooManyCapabilities, parse(gpa, text.items, .{ .max_lines = 8 }));

    var c = try parse(gpa, "srv\nX-LONG " ++ "A" ** 100, .{ .max_line = 16 });
    defer c.deinit();
    try testing.expectEqual(@as(usize, 16), c.lines[0].len);
}

test "fuzz: arbitrary EHLO text never crashes or leaks" {
    try testing.fuzz({}, fuzzCaps, .{});
}

fn fuzzCaps(_: void, smith: *std.testing.Smith) !void {
    const gpa = testing.allocator;
    var raw: [512]u8 = undefined;
    smith.bytes(&raw);
    const len = smith.valueRangeAtMost(u16, 0, raw.len);
    var caps = parse(gpa, raw[0..len], .{ .max_lines = 32, .max_line = 64 }) catch return;
    defer caps.deinit();
    _ = caps.has("STARTTLS");
    _ = caps.params("SIZE");
    _ = caps.sizeExceeded(1234);
}
