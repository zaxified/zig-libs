// SPDX-License-Identifier: MIT

//! RFC 5321 §4.1 — SMTP commands, serialised into a caller-supplied buffer.
//!
//! Every builder here is pure: bytes in, one CRLF-terminated command line out,
//! no allocation and no I/O. Two rules are enforced rather than documented:
//!
//! 1. **No control character reaches the wire.** A CR, LF or NUL inside any
//!    caller-supplied argument is `error.ControlCharacterInArgument`. This is
//!    the SMTP command-injection vector — a `RCPT TO:<a@example.com>\r\nRCPT
//!    TO:<victim@example.net>` built from an unvalidated web form is how open
//!    relays get built out of closed ones.
//! 2. **The RFC 5321 §4.5.3.1 size ceilings.** local-part ≤ 64, domain ≤ 255,
//!    path ≤ 256, command line ≤ 512 octets including CRLF. A caller may raise
//!    the line ceiling (extensions are allowed to), but never silently.
//!
//! Addresses are validated against the `Mailbox` grammar of §4.1.2 as far as a
//! sender needs: dot-atom or quoted-string local part, dot-atom domain or an
//! address literal. Non-ASCII is refused unless the caller says SMTPUTF8 was
//! negotiated (RFC 6531 §3.2).

const std = @import("std");
const testing = std.testing;
const netaddr = @import("netaddr");

pub const CommandError = error{
    /// CR, LF or NUL inside an argument.
    ControlCharacterInArgument,
    /// The command line would exceed `Limits.max_command_line`, or the buffer
    /// the caller supplied is too small.
    CommandTooLong,
    /// A path, local-part or domain over its RFC 5321 §4.5.3.1 ceiling.
    PathTooLong,
    /// Not a legal `Mailbox`.
    InvalidAddress,
    /// A non-ASCII address without SMTPUTF8 (RFC 6531).
    NonAsciiAddress,
    /// The EHLO/HELO argument is neither a `Domain` nor an address literal.
    InvalidDomain,
};

pub const Limits = struct {
    /// RFC 5321 §4.5.3.1.4: 512 octets including CRLF. Extensions may raise it,
    /// so it is a field; the default is the figure in the RFC.
    max_command_line: usize = 512,
    /// §4.5.3.1.1
    max_local_part: usize = 64,
    /// §4.5.3.1.2
    max_domain: usize = 255,
    /// §4.5.3.1.3 (includes the angle brackets)
    max_path: usize = 256,
};

/// RFC 6152 / RFC 3030 `BODY=` parameter on MAIL FROM.
pub const BodyType = enum {
    seven_bit,
    eight_bit_mime,
    binary_mime,

    pub fn text(self: BodyType) []const u8 {
        return switch (self) {
            .seven_bit => "7BIT",
            .eight_bit_mime => "8BITMIME",
            .binary_mime => "BINARYMIME",
        };
    }
};

/// ESMTP parameters on MAIL FROM. Each is emitted only when the corresponding
/// extension was advertised — that check belongs to the session layer, which
/// has the capability set; this layer only serialises what it is told.
pub const MailParams = struct {
    /// RFC 1870 `SIZE=` — the message size estimate.
    size: ?u64 = null,
    /// RFC 6152 / RFC 3030 `BODY=`.
    body: ?BodyType = null,
    /// RFC 6531 `SMTPUTF8`.
    smtputf8: bool = false,
};

pub const RcptParams = struct {};

fn checkArg(s: []const u8) CommandError!void {
    for (s) |c| {
        if (c == '\r' or c == '\n' or c == 0) return error.ControlCharacterInArgument;
    }
}

fn isAscii(s: []const u8) bool {
    for (s) |c| if (c >= 0x80) return false;
    return true;
}

fn isAtext(c: u8) bool {
    return switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9' => true,
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '/', '=', '?', '^', '_', '`', '{', '|', '}', '~' => true,
        else => false,
    };
}

/// RFC 5321 §4.1.2 `Dot-string = Atom *("." Atom)`.
fn validDotString(s: []const u8, allow_utf8: bool) bool {
    if (s.len == 0) return false;
    var atom_len: usize = 0;
    for (s) |c| {
        if (c == '.') {
            if (atom_len == 0) return false; // leading or doubled dot
            atom_len = 0;
            continue;
        }
        if (!isAtext(c) and !(allow_utf8 and c >= 0x80)) return false;
        atom_len += 1;
    }
    return atom_len != 0; // no trailing dot
}

/// RFC 5321 §4.1.2 `Quoted-string = DQUOTE *QcontentSMTP DQUOTE`.
fn validQuotedString(s: []const u8, allow_utf8: bool) bool {
    if (s.len < 2 or s[0] != '"' or s[s.len - 1] != '"') return false;
    var i: usize = 1;
    var escaped = false;
    while (i < s.len - 1) : (i += 1) {
        const c = s[i];
        if (escaped) {
            // quoted-pairSMTP = %d92 %d32-126
            if (c < 32 or c > 126) return false;
            escaped = false;
            continue;
        }
        if (c == '\\') {
            escaped = true;
            continue;
        }
        // qtextSMTP = %d32-33 / %d35-91 / %d93-126
        if (c == '"') return false;
        if (c < 32 or c == 127) return false;
        if (c >= 0x80 and !allow_utf8) return false;
    }
    return !escaped;
}

/// RFC 5321 §4.1.2 `Domain` (sub-domains of Let-dig/Ldh-str), or §4.1.3
/// address literal `[…]`.
pub fn validDomain(d: []const u8, allow_utf8: bool) bool {
    if (d.len == 0) return false;
    if (d[0] == '[') return validAddressLiteral(d);
    var label_len: usize = 0;
    var prev: u8 = 0;
    for (d, 0..) |c, i| {
        if (c == '.') {
            if (label_len == 0 or prev == '-') return false;
            label_len = 0;
            prev = c;
            continue;
        }
        const ok = switch (c) {
            'A'...'Z', 'a'...'z', '0'...'9' => true,
            '-' => label_len != 0, // Ldh-str may not start a label
            else => allow_utf8 and c >= 0x80,
        };
        if (!ok) return false;
        if (label_len > 63) return false;
        label_len += 1;
        prev = c;
        _ = i;
    }
    return label_len != 0 and prev != '-';
}

/// RFC 5321 §4.1.3: `[192.0.2.1]` or `[IPv6:2001:db8::1]`. Parsed with the
/// sibling `netaddr` module, so the literal really is an address.
pub fn validAddressLiteral(d: []const u8) bool {
    if (d.len < 3 or d[0] != '[' or d[d.len - 1] != ']') return false;
    const inner = d[1 .. d.len - 1];
    if (inner.len > 6 and std.ascii.eqlIgnoreCase(inner[0..5], "IPv6:")) {
        return netaddr.parseIp6(inner[5..]) != null;
    }
    return netaddr.parseIp4(inner) != null;
}

/// Format an IP as the RFC 5321 §4.1.3 address literal an EHLO argument wants
/// when the client has no resolvable FQDN. Returns a slice of `buf`.
pub fn addressLiteral(buf: []u8, ip: netaddr.Ip) error{NoSpaceLeft}![]const u8 {
    var tmp: [netaddr.max_ip_text_len]u8 = undefined;
    const text = netaddr.formatIp(ip, &tmp);
    return switch (ip) {
        .v4 => std.fmt.bufPrint(buf, "[{s}]", .{text}),
        .v6 => std.fmt.bufPrint(buf, "[IPv6:{s}]", .{text}),
    } catch error.NoSpaceLeft;
}

/// Validate a `Mailbox` (`local-part "@" Domain`) for use in a MAIL/RCPT path.
/// The empty string is NOT accepted here — the null reverse-path is expressed
/// by passing `null` to `mail`, not by an empty address.
pub fn validateMailbox(addr: []const u8, limits: Limits, allow_utf8: bool) CommandError!void {
    try checkArg(addr);
    if (!allow_utf8 and !isAscii(addr)) return error.NonAsciiAddress;
    if (addr.len == 0) return error.InvalidAddress;
    if (addr.len + 2 > limits.max_path) return error.PathTooLong;

    // The last '@' separates local-part from domain: a quoted local part may
    // legally contain '@'.
    const at = std.mem.lastIndexOfScalar(u8, addr, '@') orelse return error.InvalidAddress;
    const local = addr[0..at];
    const domain = addr[at + 1 ..];
    if (local.len == 0 or domain.len == 0) return error.InvalidAddress;
    if (local.len > limits.max_local_part) return error.PathTooLong;
    if (domain.len > limits.max_domain) return error.PathTooLong;

    const local_ok = if (local[0] == '"')
        validQuotedString(local, allow_utf8)
    else
        validDotString(local, allow_utf8);
    if (!local_ok) return error.InvalidAddress;
    if (!validDomain(domain, allow_utf8)) return error.InvalidAddress;
}

// ── builders ───────────────────────────────────────────────────────────────

const Builder = struct {
    buf: []u8,
    len: usize = 0,
    limits: Limits,

    fn put(self: *Builder, s: []const u8) CommandError!void {
        if (self.len + s.len > self.buf.len) return error.CommandTooLong;
        @memcpy(self.buf[self.len .. self.len + s.len], s);
        self.len += s.len;
    }

    fn print(self: *Builder, comptime fmt: []const u8, args: anytype) CommandError!void {
        const rest = self.buf[self.len..];
        const out = std.fmt.bufPrint(rest, fmt, args) catch return error.CommandTooLong;
        self.len += out.len;
    }

    fn finish(self: *Builder) CommandError![]const u8 {
        try self.put("\r\n");
        if (self.len > self.limits.max_command_line) return error.CommandTooLong;
        return self.buf[0..self.len];
    }
};

/// `EHLO <domain>` — RFC 5321 §4.1.1.1. `domain` must be a fully-qualified
/// domain or an address literal (`addressLiteral`).
pub fn ehlo(buf: []u8, domain: []const u8, limits: Limits) CommandError![]const u8 {
    return greet(buf, "EHLO ", domain, limits);
}

/// `HELO <domain>` — RFC 5321 §4.1.1.1, the fallback when EHLO is refused.
pub fn helo(buf: []u8, domain: []const u8, limits: Limits) CommandError![]const u8 {
    return greet(buf, "HELO ", domain, limits);
}

fn greet(buf: []u8, verb: []const u8, domain: []const u8, limits: Limits) CommandError![]const u8 {
    try checkArg(domain);
    if (domain.len > limits.max_domain) return error.PathTooLong;
    // EHLO of a UTF-8 domain is legal only under SMTPUTF8, and the greeting is
    // sent before SMTPUTF8 can be known — so it is always ASCII here.
    if (!validDomain(domain, false)) return error.InvalidDomain;
    var b: Builder = .{ .buf = buf, .limits = limits };
    try b.put(verb);
    try b.put(domain);
    return b.finish();
}

/// `MAIL FROM:<path> [params]` — RFC 5321 §4.1.1.2. `from == null` is the null
/// reverse-path `<>` used by bounce messages (§3.6.3).
pub fn mail(buf: []u8, from: ?[]const u8, p: MailParams, limits: Limits) CommandError![]const u8 {
    var b: Builder = .{ .buf = buf, .limits = limits };
    try b.put("MAIL FROM:<");
    if (from) |f| {
        try validateMailbox(f, limits, p.smtputf8);
        try b.put(f);
    }
    try b.put(">");
    if (p.size) |s| try b.print(" SIZE={d}", .{s});
    if (p.body) |t| try b.print(" BODY={s}", .{t.text()});
    if (p.smtputf8) try b.put(" SMTPUTF8");
    return b.finish();
}

/// `RCPT TO:<path>` — RFC 5321 §4.1.1.3. The null path is NOT legal here.
pub fn rcpt(buf: []u8, to: []const u8, _: RcptParams, limits: Limits, smtputf8: bool) CommandError![]const u8 {
    try validateMailbox(to, limits, smtputf8);
    var b: Builder = .{ .buf = buf, .limits = limits };
    try b.put("RCPT TO:<");
    try b.put(to);
    try b.put(">");
    return b.finish();
}

pub fn data(buf: []u8, limits: Limits) CommandError![]const u8 {
    var b: Builder = .{ .buf = buf, .limits = limits };
    try b.put("DATA");
    return b.finish();
}

pub fn rset(buf: []u8, limits: Limits) CommandError![]const u8 {
    var b: Builder = .{ .buf = buf, .limits = limits };
    try b.put("RSET");
    return b.finish();
}

pub fn quit(buf: []u8, limits: Limits) CommandError![]const u8 {
    var b: Builder = .{ .buf = buf, .limits = limits };
    try b.put("QUIT");
    return b.finish();
}

/// `NOOP [string]` — §4.1.1.9.
pub fn noop(buf: []u8, arg: ?[]const u8, limits: Limits) CommandError![]const u8 {
    var b: Builder = .{ .buf = buf, .limits = limits };
    try b.put("NOOP");
    if (arg) |a| {
        try checkArg(a);
        try b.put(" ");
        try b.put(a);
    }
    return b.finish();
}

/// `VRFY <string>` — §4.1.1.6. Most servers refuse it; provided for
/// completeness and never used by the session.
pub fn vrfy(buf: []u8, arg: []const u8, limits: Limits) CommandError![]const u8 {
    try checkArg(arg);
    var b: Builder = .{ .buf = buf, .limits = limits };
    try b.put("VRFY ");
    try b.put(arg);
    return b.finish();
}

/// `STARTTLS` — RFC 3207 §2.
pub fn starttls(buf: []u8, limits: Limits) CommandError![]const u8 {
    var b: Builder = .{ .buf = buf, .limits = limits };
    try b.put("STARTTLS");
    return b.finish();
}

/// `AUTH <mechanism> [initial-response]` — RFC 4954 §4. `initial` must already
/// be base64 (or `=` for an empty initial response).
pub fn auth(buf: []u8, mechanism: []const u8, initial: ?[]const u8, limits: Limits) CommandError![]const u8 {
    try checkArg(mechanism);
    var b: Builder = .{ .buf = buf, .limits = limits };
    try b.put("AUTH ");
    try b.put(mechanism);
    if (initial) |i| {
        try checkArg(i);
        try b.put(" ");
        try b.put(if (i.len == 0) "=" else i);
    }
    return b.finish();
}

/// A bare base64 line during a SASL exchange, or the `*` cancellation of
/// RFC 4954 §4.
pub fn authContinue(buf: []u8, payload: []const u8, limits: Limits) CommandError![]const u8 {
    try checkArg(payload);
    var b: Builder = .{ .buf = buf, .limits = limits };
    try b.put(payload);
    return b.finish();
}

// ── tests ──────────────────────────────────────────────────────────────────

test "the RFC 5321 §4.1.1 command shapes, byte for byte" {
    var buf: [600]u8 = undefined;
    try testing.expectEqualStrings("EHLO client.example.org\r\n", try ehlo(&buf, "client.example.org", .{}));
    try testing.expectEqualStrings("HELO client.example.org\r\n", try helo(&buf, "client.example.org", .{}));
    try testing.expectEqualStrings("MAIL FROM:<sender@example.com>\r\n", try mail(&buf, "sender@example.com", .{}, .{}));
    try testing.expectEqualStrings("MAIL FROM:<>\r\n", try mail(&buf, null, .{}, .{}));
    try testing.expectEqualStrings("RCPT TO:<rcpt@example.net>\r\n", try rcpt(&buf, "rcpt@example.net", .{}, .{}, false));
    try testing.expectEqualStrings("DATA\r\n", try data(&buf, .{}));
    try testing.expectEqualStrings("RSET\r\n", try rset(&buf, .{}));
    try testing.expectEqualStrings("QUIT\r\n", try quit(&buf, .{}));
    try testing.expectEqualStrings("NOOP\r\n", try noop(&buf, null, .{}));
    try testing.expectEqualStrings("NOOP ping\r\n", try noop(&buf, "ping", .{}));
    try testing.expectEqualStrings("STARTTLS\r\n", try starttls(&buf, .{}));
    try testing.expectEqualStrings("VRFY Smith\r\n", try vrfy(&buf, "Smith", .{}));
    try testing.expectEqualStrings("AUTH LOGIN\r\n", try auth(&buf, "LOGIN", null, .{}));
    try testing.expectEqualStrings("AUTH PLAIN AGE=\r\n", try auth(&buf, "PLAIN", "AGE=", .{}));
    try testing.expectEqualStrings("AUTH PLAIN =\r\n", try auth(&buf, "PLAIN", "", .{}));
}

test "MAIL FROM ESMTP parameters" {
    var buf: [600]u8 = undefined;
    try testing.expectEqualStrings(
        "MAIL FROM:<a@example.com> SIZE=1234 BODY=8BITMIME\r\n",
        try mail(&buf, "a@example.com", .{ .size = 1234, .body = .eight_bit_mime }, .{}),
    );
    try testing.expectEqualStrings(
        "MAIL FROM:<a@example.com> SMTPUTF8\r\n",
        try mail(&buf, "a@example.com", .{ .smtputf8 = true }, .{}),
    );
    try testing.expectEqualStrings(
        "MAIL FROM:<a@example.com> BODY=7BIT\r\n",
        try mail(&buf, "a@example.com", .{ .body = .seven_bit }, .{}),
    );
}

test "command injection: CR/LF/NUL in any argument is refused" {
    var buf: [600]u8 = undefined;
    const evil = "a@example.com>\r\nRCPT TO:<victim@example.net";
    try testing.expectError(error.ControlCharacterInArgument, rcpt(&buf, evil, .{}, .{}, false));
    try testing.expectError(error.ControlCharacterInArgument, mail(&buf, evil, .{}, .{}));
    try testing.expectError(error.ControlCharacterInArgument, ehlo(&buf, "host\r\nQUIT", .{}));
    try testing.expectError(error.ControlCharacterInArgument, noop(&buf, "x\ny", .{}));
    try testing.expectError(error.ControlCharacterInArgument, auth(&buf, "PLAIN\r\nQUIT", null, .{}));
    try testing.expectError(error.ControlCharacterInArgument, rcpt(&buf, "a\x00b@example.com", .{}, .{}, false));
}

test "address grammar: what is a Mailbox and what is not" {
    const ok = [_][]const u8{
        "simple@example.com",
        "very.common@example.com",
        "disposable.style.email.with+symbol@example.com",
        "other.email-with-hyphen@example.com",
        "fully-qualified-domain@example.com",
        "user.name+tag+sorting@example.com",
        "x@example.com",
        "example-indeed@strange-example.com",
        "!#$%&'*+-/=?^_`{|}~@example.com",
        "\"quoted local part\"@example.com",
        "\"very.(),:;<>[]\\\".VERY.\\\"very@\\\\ \\\"very\\\".unusual\"@strange.example.com",
        "postmaster@[192.0.2.1]",
        "postmaster@[IPv6:2001:db8::1]",
    };
    for (ok) |a| validateMailbox(a, .{}, false) catch |e| {
        std.debug.print("expected valid: {s} -> {t}\n", .{ a, e });
        return e;
    };

    const bad = [_][]const u8{
        "",
        "no-at-sign",
        "@example.com",
        "user@",
        ".leading.dot@example.com",
        "trailing.dot.@example.com",
        "double..dot@example.com",
        "user@-example.com",
        "user@example-.com",
        "user@exa mple.com",
        "user@[999.1.1.1]",
        "user@[IPv6:not-an-address]",
        "unquoted space@example.com",
        "\"unterminated@example.com",
    };
    for (bad) |a| {
        const r = validateMailbox(a, .{}, false);
        testing.expectError(error.InvalidAddress, r) catch {
            std.debug.print("expected invalid: {s}\n", .{a});
            return error.TestUnexpectedResult;
        };
    }
}

test "RFC 5321 §4.5.3.1 size ceilings" {
    var buf: [1024]u8 = undefined;
    const long_local = "a" ** 65 ++ "@example.com";
    try testing.expectError(error.PathTooLong, validateMailbox(long_local, .{}, false));
    const long_domain = "a@" ++ ("b" ** 60 ++ ".") ** 5 ++ "example.com";
    try testing.expectError(error.PathTooLong, validateMailbox(long_domain, .{}, false));
    // A path just over 256 octets.
    const long_path = "a" ** 60 ++ "@" ++ ("x" ** 30 ++ ".") ** 6 ++ "example.com";
    try testing.expect(long_path.len + 2 > 256);
    try testing.expectError(error.PathTooLong, validateMailbox(long_path, .{}, false));
    // The line ceiling bites even when every component is legal.
    try testing.expectError(error.CommandTooLong, noop(&buf, "x" ** 600, .{}));
    // ...and a caller may raise it deliberately.
    const long_noop = try noop(&buf, "x" ** 600, .{ .max_command_line = 1024 });
    try testing.expectEqual(@as(usize, 607), long_noop.len);
    // A buffer smaller than the command is an error, not a truncation.
    var tiny: [4]u8 = undefined;
    try testing.expectError(error.CommandTooLong, quit(&tiny, .{}));
}

test "non-ASCII addresses need SMTPUTF8" {
    var buf: [600]u8 = undefined;
    const utf8 = "poštovní@example.com";
    try testing.expectError(error.NonAsciiAddress, validateMailbox(utf8, .{}, false));
    try validateMailbox(utf8, .{}, true);
    try testing.expectError(error.NonAsciiAddress, rcpt(&buf, utf8, .{}, .{}, false));
    const line = try rcpt(&buf, utf8, .{}, .{}, true);
    try testing.expectEqualStrings("RCPT TO:<poštovní@example.com>\r\n", line);
}

test "EHLO argument must be a domain or an address literal" {
    var buf: [600]u8 = undefined;
    try testing.expectError(error.InvalidDomain, ehlo(&buf, "", .{}));
    try testing.expectError(error.InvalidDomain, ehlo(&buf, "not a domain", .{}));
    try testing.expectError(error.InvalidDomain, ehlo(&buf, "-leading-hyphen.example", .{}));
    try testing.expectError(error.InvalidDomain, ehlo(&buf, "[300.1.1.1]", .{}));
    try testing.expectEqualStrings("EHLO [192.0.2.1]\r\n", try ehlo(&buf, "[192.0.2.1]", .{}));
    try testing.expectEqualStrings("EHLO [IPv6:2001:db8::1]\r\n", try ehlo(&buf, "[IPv6:2001:db8::1]", .{}));
    // localhost (a single label) is legal syntax, whatever a server thinks of it.
    try testing.expectEqualStrings("EHLO localhost\r\n", try ehlo(&buf, "localhost", .{}));
}

test "addressLiteral formats what ehlo accepts" {
    var lit: [64]u8 = undefined;
    var buf: [600]u8 = undefined;
    const v4 = try addressLiteral(&lit, .{ .v4 = .{ 192, 0, 2, 1 } });
    try testing.expectEqualStrings("[192.0.2.1]", v4);
    _ = try ehlo(&buf, v4, .{});

    var lit6: [64]u8 = undefined;
    const ip6 = netaddr.parseIp6("2001:db8::1").?;
    const v6 = try addressLiteral(&lit6, .{ .v6 = ip6 });
    try testing.expectEqualStrings("[IPv6:2001:db8::1]", v6);
    _ = try ehlo(&buf, v6, .{});
}

test "fuzz: no argument makes a builder emit a control character or overrun" {
    try testing.fuzz({}, fuzzCommands, .{});
}

fn fuzzCommands(_: void, smith: *std.testing.Smith) !void {
    var raw: [300]u8 = undefined;
    smith.bytes(&raw);
    const len = smith.valueRangeAtMost(u16, 0, raw.len);
    const arg = raw[0..len];
    const utf8 = smith.value(bool);

    var buf: [1024]u8 = undefined;
    inline for (.{ ehlo, helo }) |f| {
        if (f(&buf, arg, .{})) |line| {
            std.debug.assert(std.mem.endsWith(u8, line, "\r\n"));
            std.debug.assert(std.mem.indexOfScalar(u8, line[0 .. line.len - 2], '\n') == null);
        } else |_| {}
    }
    if (mail(&buf, arg, .{ .smtputf8 = utf8 }, .{})) |line| {
        std.debug.assert(std.mem.indexOfScalar(u8, line[0 .. line.len - 2], '\r') == null);
    } else |_| {}
    if (rcpt(&buf, arg, .{}, .{}, utf8)) |line| {
        std.debug.assert(std.mem.indexOfScalar(u8, line[0 .. line.len - 2], '\r') == null);
        std.debug.assert(line.len <= 512);
    } else |_| {}
    if (auth(&buf, "PLAIN", arg, .{})) |line| {
        std.debug.assert(std.mem.indexOfScalar(u8, line[0 .. line.len - 2], '\n') == null);
    } else |_| {}
}
