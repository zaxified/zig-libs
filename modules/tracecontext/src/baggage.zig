// SPDX-License-Identifier: MIT

//! W3C Baggage — parse and serialize the `baggage` header.
//!
//! Text of record: W3C Candidate Recommendation Snapshot 30 May 2024,
//! <https://www.w3.org/TR/2024/CR-baggage-20240530/> (section numbers below
//! are that document's). Everything here is allocation-free; the only
//! storage is a caller-supplied scratch buffer for decoded values.
//!
//! A header value is a comma list of members `key=value`, each optionally
//! followed by `;property` or `;key=value` properties (§3.3.1):
//!
//!     baggage: key1=value1;property1;property2, key2 = value2, key3=value3; propertyKey=propertyValue
//!
//! - **Parse** (`Baggage.parse`): strict. Any malformed member, more than
//!   `max_members` members or more than `max_len` bytes is an error, never
//!   a panic. `Baggage.parseLenient` instead follows §3.5 ("it MAY remove
//!   that entry") and §3.3.2 ("MAY drop list-members"): malformed members
//!   are skipped and whole members past a limit are dropped.
//! - **Values** are percent-decoded (§3.3.1.3); an octet sequence that is
//!   not UTF-8 becomes U+FFFD. A `%` not followed by two hex digits is a
//!   malformed member (the `%` MUST be encoded). Decoded values are written
//!   into the scratch buffer, which must be at least as long as the input
//!   (decoding never grows a value). Property values stay as on the wire
//!   (still percent-encoded; `decodeValue` decodes one).
//! - **Several `baggage` header fields** are one list (§3: combine per RFC
//!   9110 §5.3, i.e. join with `,`); the limits apply to the combination
//!   (§3.3.2), so pass the joined value.
//! - **Write** (`Baggage.write`): percent-encodes every value octet outside
//!   `baggage-octet` and `%` itself, upper-case hex. When the list does not
//!   fit in `buf` / `max_len`, whole members are left out from the right —
//!   never a partial member (§3.3.2).
//! - Duplicate keys are kept in order (§3.3.1.1); `get` returns the first.

const std = @import("std");

/// Header name (§3.1: lowercase).
pub const default_header = "baggage";
/// The minimum limits every platform MUST propagate (§3.3.2).
pub const max_members = 64;
pub const max_len = 8192;

/// RFC 7230 §3.2.6 `tchar`.
fn isTchar(c: u8) bool {
    return switch (c) {
        'a'...'z', 'A'...'Z', '0'...'9' => true,
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        else => false,
    };
}

/// RFC 7230 `token`: a non-empty run of `tchar`. Keys of members and
/// properties (§3.3.1).
pub fn isToken(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| if (!isTchar(c)) return false;
    return true;
}

/// `baggage-octet` (§3.3.1): %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E.
pub fn isBaggageOctet(c: u8) bool {
    return switch (c) {
        0x21, 0x23...0x2B, 0x2D...0x3A, 0x3C...0x5B, 0x5D...0x7E => true,
        else => false,
    };
}

fn allBaggageOctets(s: []const u8) bool {
    for (s) |c| if (!isBaggageOctet(c)) return false;
    return true;
}

const ows = " \t";

/// One property of a member: `key` alone (`value == null`) or `key=value`.
/// The value is as on the wire (percent-encoded).
pub const Property = struct { key: []const u8, value: ?[]const u8 };

/// `property = key OWS "=" OWS value / key OWS`, OWS trimmed (§3.3.1.4).
fn parseProperty(piece: []const u8) ?Property {
    const p = std.mem.trim(u8, piece, ows);
    if (std.mem.findScalar(u8, p, '=')) |eq| {
        const key = std.mem.trim(u8, p[0..eq], ows);
        const value = std.mem.trim(u8, p[eq + 1 ..], ows);
        if (!isToken(key) or !allBaggageOctets(value)) return null;
        return .{ .key = key, .value = value };
    }
    if (!isToken(p)) return null;
    return .{ .key = p, .value = null };
}

/// True when `text` is one or more `;`-separated valid properties (no
/// leading/trailing `;`, no empty piece).
fn validProperties(text: []const u8) bool {
    var it = std.mem.splitScalar(u8, text, ';');
    while (it.next()) |piece| if (parseProperty(piece) == null) return false;
    return true;
}

pub const PropertyIterator = struct {
    rest: ?[]const u8,

    pub fn next(it: *PropertyIterator) ?Property {
        const r = it.rest orelse return null;
        var piece = r;
        if (std.mem.findScalar(u8, r, ';')) |i| {
            piece = r[0..i];
            it.rest = r[i + 1 ..];
        } else it.rest = null;
        return parseProperty(piece);
    }
};

pub const DecodeError = error{
    /// A `%` not followed by two hex digits.
    BadEscape,
    NoSpaceLeft,
};

const Raw = struct { byte: u8, next: usize };

fn rawAt(src: []const u8, i: usize) error{BadEscape}!Raw {
    if (src[i] != '%') return .{ .byte = src[i], .next = i + 1 };
    if (src.len - i < 3) return error.BadEscape;
    const hi = std.fmt.charToDigit(src[i + 1], 16) catch return error.BadEscape;
    const lo = std.fmt.charToDigit(src[i + 2], 16) catch return error.BadEscape;
    return .{ .byte = hi << 4 | lo, .next = i + 3 };
}

const replacement = "\xEF\xBF\xBD"; // U+FFFD

/// Percent-decode `src` into `out` (§3.3.1.3): octet sequences that are not
/// UTF-8 become U+FFFD, one per offending octet. Returns the decoded slice
/// of `out`; `out.len >= src.len` always suffices.
pub fn decodeValue(src: []const u8, out: []u8) DecodeError![]u8 {
    var i: usize = 0;
    var n: usize = 0;
    while (i < src.len) {
        const first = try rawAt(src, i);
        var seq: [4]u8 = undefined;
        seq[0] = first.byte;
        var len: usize = 1;
        var next = first.next;
        if (first.byte >= 0x80) {
            const want: usize = std.unicode.utf8ByteSequenceLength(first.byte) catch 1;
            var ok = want >= 2;
            var j = first.next;
            var k: usize = 1;
            while (ok and k < want) : (k += 1) {
                if (j >= src.len) {
                    ok = false;
                    break;
                }
                const q = try rawAt(src, j);
                seq[k] = q.byte;
                j = q.next;
            }
            if (ok) _ = std.unicode.utf8Decode(seq[0..want]) catch {
                ok = false;
            };
            if (ok) {
                len = want;
                next = j;
            } else {
                @memcpy(seq[0..3], replacement);
                len = 3;
            }
        }
        if (out.len - n < len) return error.NoSpaceLeft;
        @memcpy(out[n..][0..len], seq[0..len]);
        n += len;
        i = next;
    }
    return out[0..n];
}

fn encodedValueLen(v: []const u8) usize {
    var n: usize = 0;
    for (v) |c| n += if (isBaggageOctet(c) and c != '%') 1 else 3;
    return n;
}

fn writeEncoded(w: *std.Io.Writer, v: []const u8) void {
    const hex = "0123456789ABCDEF";
    for (v) |c| {
        if (isBaggageOctet(c) and c != '%') {
            w.writeByte(c) catch unreachable;
        } else {
            w.writeAll(&.{ '%', hex[c >> 4], hex[c & 0xf] }) catch unreachable;
        }
    }
}

/// A parsed / mintable baggage list: up to `max_members` members in wire
/// order. Members borrow the parsed input, the scratch buffer, and the
/// slices handed to `put`; nothing is allocated.
pub const Baggage = struct {
    members_buf: [max_members]Member = undefined,
    len: u8 = 0,

    pub const Member = struct {
        key: []const u8,
        /// Percent-decoded.
        value: []const u8,
        /// The properties after the value as `p1;k2=v2` text (wire form, OWS
        /// possibly inside; empty = none). Walk them with `propertyIterator`.
        properties: []const u8 = "",

        pub fn propertyIterator(m: Member) PropertyIterator {
            return .{ .rest = if (m.properties.len == 0) null else m.properties };
        }

        fn encodedLen(m: Member) usize {
            var n = m.key.len + 1 + encodedValueLen(m.value);
            var it = m.propertyIterator();
            while (it.next()) |p| n += 1 + p.key.len + if (p.value) |v| 1 + v.len else 0;
            return n;
        }
    };

    pub const ParseError = error{
        /// A member breaks the grammar (§3.3.1), including an empty member
        /// and a `%` that is not a valid escape.
        BadMember,
        /// More than `max_members` members.
        TooManyMembers,
        /// More than `max_len` bytes (OWS around the whole value excluded).
        TooLong,
        /// `scratch` shorter than the input.
        NoSpaceLeft,
    };

    /// Parse a combined header value; see the module doc. `scratch.len` must
    /// be at least `v.len` (`max_len` always suffices). An empty or
    /// whitespace-only value is an empty list.
    pub fn parse(v: []const u8, scratch: []u8) ParseError!Baggage {
        const t = std.mem.trim(u8, v, ows);
        if (t.len > max_len) return error.TooLong;
        if (scratch.len < t.len) return error.NoSpaceLeft;
        var b: Baggage = .{};
        if (t.len == 0) return b;
        var used: usize = 0;
        var it = std.mem.splitScalar(u8, t, ',');
        while (it.next()) |raw| {
            const m = try parseMember(raw, scratch, &used);
            if (b.len == max_members) return error.TooManyMembers;
            b.members_buf[b.len] = m;
            b.len += 1;
        }
        return b;
    }

    /// Like `parse`, but never fails on content: a malformed member is
    /// skipped (§3.5) and members past `max_members` or ending beyond byte
    /// `max_len` are dropped whole (§3.3.2). Only a too-short `scratch`
    /// is an error.
    pub fn parseLenient(v: []const u8, scratch: []u8) error{NoSpaceLeft}!Baggage {
        const t = std.mem.trim(u8, v, ows);
        // Members ending past `max_len` are dropped, so no decoded byte comes from beyond it.
        if (scratch.len < @min(t.len, max_len)) return error.NoSpaceLeft;
        var b: Baggage = .{};
        if (t.len == 0) return b;
        var used: usize = 0;
        var off: usize = 0;
        var rest: ?[]const u8 = t;
        while (rest) |r| {
            const comma = std.mem.findScalar(u8, r, ',');
            const raw = if (comma) |k| r[0..k] else r;
            off += raw.len;
            if (off > max_len or b.len == max_members) break;
            if (parseMember(raw, scratch, &used)) |m| {
                b.members_buf[b.len] = m;
                b.len += 1;
            } else |e| switch (e) {
                error.BadMember => {},
                error.NoSpaceLeft => return error.NoSpaceLeft,
            }
            rest = if (comma) |k| r[k + 1 ..] else null;
            off += 1;
        }
        return b;
    }

    pub fn members(b: *const Baggage) []const Member {
        return b.members_buf[0..b.len];
    }

    /// The decoded value of the first member named `key`, or null.
    pub fn get(b: *const Baggage, key: []const u8) ?[]const u8 {
        for (b.members()) |m| if (std.mem.eql(u8, m.key, key)) return m.value;
        return null;
    }

    /// Set `key` to `value` (the DECODED value; encoded on `write`). The
    /// first member of that name is updated in place, keeping its position
    /// (§3.5 "update"); otherwise a member is appended. `properties` is
    /// wire-form property text (`p1;k=v`, empty for none), replacing the old
    /// one. All slices are borrowed.
    pub fn put(b: *Baggage, key: []const u8, value: []const u8, properties: []const u8) error{ BadMember, TooManyMembers }!void {
        if (!isToken(key)) return error.BadMember;
        const props = std.mem.trim(u8, properties, ows);
        if (props.len != 0 and !validProperties(props)) return error.BadMember;
        const m: Member = .{ .key = key, .value = value, .properties = props };
        for (b.members_buf[0..b.len]) |*e| if (std.mem.eql(u8, e.key, key)) {
            e.* = m;
            return;
        };
        if (b.len == max_members) return error.TooManyMembers;
        b.members_buf[b.len] = m;
        b.len += 1;
    }

    /// Remove every member named `key` (§3.5 "delete"); false when none.
    pub fn delete(b: *Baggage, key: []const u8) bool {
        var w: usize = 0;
        for (b.members_buf[0..b.len]) |m| {
            if (std.mem.eql(u8, m.key, key)) continue;
            b.members_buf[w] = m;
            w += 1;
        }
        const removed = w != b.len;
        b.len = @intCast(w);
        return removed;
    }

    /// Render `key=value;props,…` into `buf` with no optional whitespace.
    /// Whole members are left out from the right until the text fits both
    /// `buf` and `max_len` (§3.3.2); the result may be empty — send no
    /// header then.
    pub fn write(b: *const Baggage, buf: []u8) []const u8 {
        const limit = @min(buf.len, max_len);
        var keep: usize = b.len;
        var total: usize = 0;
        for (b.members(), 0..) |m, i| total += m.encodedLen() + @intFromBool(i != 0);
        while (keep > 0 and total > limit) {
            keep -= 1;
            total -= b.members_buf[keep].encodedLen() + @intFromBool(keep != 0);
        }
        var w: std.Io.Writer = .fixed(buf);
        for (b.members_buf[0..keep], 0..) |m, i| {
            if (i != 0) w.writeByte(',') catch unreachable;
            w.writeAll(m.key) catch unreachable;
            w.writeByte('=') catch unreachable;
            writeEncoded(&w, m.value);
            var it = m.propertyIterator();
            while (it.next()) |p| {
                w.writeByte(';') catch unreachable;
                w.writeAll(p.key) catch unreachable;
                if (p.value) |v| {
                    w.writeByte('=') catch unreachable;
                    w.writeAll(v) catch unreachable;
                }
            }
        }
        return w.buffered();
    }
};

/// `list-member = key OWS "=" OWS value *( OWS ";" OWS property )`; `raw`
/// is one comma-separated piece. Decodes the value into `scratch[used..]`.
fn parseMember(raw: []const u8, scratch: []u8, used: *usize) error{ BadMember, NoSpaceLeft }!Baggage.Member {
    const m = std.mem.trim(u8, raw, ows);
    if (m.len == 0) return error.BadMember;
    const semi = std.mem.findScalar(u8, m, ';');
    const head = if (semi) |i| m[0..i] else m;
    const eq = std.mem.findScalar(u8, head, '=') orelse return error.BadMember;
    const key = std.mem.trim(u8, head[0..eq], ows);
    const enc = std.mem.trim(u8, head[eq + 1 ..], ows);
    if (!isToken(key) or !allBaggageOctets(enc)) return error.BadMember;
    var props: []const u8 = "";
    if (semi) |i| {
        props = std.mem.trim(u8, m[i + 1 ..], ows);
        if (!validProperties(props)) return error.BadMember;
    }
    const value = decodeValue(enc, scratch[used.*..]) catch |e| switch (e) {
        error.BadEscape => return error.BadMember,
        error.NoSpaceLeft => return error.NoSpaceLeft,
    };
    used.* += value.len;
    return .{ .key = key, .value = value, .properties = props };
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;
const fuzzseed = @import("testkit").fuzz;

fn parseT(v: []const u8, scratch: *[max_len]u8) !Baggage {
    return Baggage.parse(v, scratch);
}

// Spec §3.3.3: three members, the third with a key=value property.
test "spec 3.3.3 example: members, properties, OWS" {
    var s: [max_len]u8 = undefined;
    const hdr = "key1=value1;property1;property2, key2 = value2, key3=value3; propertyKey=propertyValue";
    try testing.expectEqual(@as(usize, 86), hdr.len); // the spec counts 86 bytes
    const b = try parseT(hdr, &s);
    try testing.expectEqual(@as(usize, 3), b.members().len);
    try testing.expectEqualStrings("key1", b.members()[0].key);
    try testing.expectEqualStrings("value1", b.members()[0].value);
    var it = b.members()[0].propertyIterator();
    const p1 = it.next().?;
    try testing.expectEqualStrings("property1", p1.key);
    try testing.expect(p1.value == null);
    try testing.expectEqualStrings("property2", it.next().?.key);
    try testing.expect(it.next() == null);
    try testing.expectEqualStrings("value2", b.get("key2").?);
    try testing.expectEqual(@as(usize, 0), b.members()[1].properties.len);
    var it3 = b.members()[2].propertyIterator();
    const pk = it3.next().?;
    try testing.expectEqualStrings("propertyKey", pk.key);
    try testing.expectEqualStrings("propertyValue", pk.value.?);
    try testing.expect(it3.next() == null);
    // Written back: normalized, no optional whitespace.
    var out: [256]u8 = undefined;
    try testing.expectEqualStrings(
        "key1=value1;property1;property2,key2=value2,key3=value3;propertyKey=propertyValue",
        b.write(&out),
    );
}

// Spec §3.4: userId=alice, serverNode="DF 28", isProduction=false.
test "spec 3.4 examples: encoded values, Amelie, split and padded headers" {
    var s: [max_len]u8 = undefined;
    var b = try parseT("userId=alice,serverNode=DF%2028,isProduction=false", &s);
    try testing.expectEqualStrings("alice", b.get("userId").?);
    try testing.expectEqualStrings("DF 28", b.get("serverNode").?);
    try testing.expectEqualStrings("false", b.get("isProduction").?);
    var out: [128]u8 = undefined;
    try testing.expectEqualStrings("userId=alice,serverNode=DF%2028,isProduction=false", b.write(&out));

    b = try parseT("userId=Am%C3%A9lie,serverNode=DF%2028,isProduction=false", &s);
    try testing.expectEqualStrings("Am\u{e9}lie", b.get("userId").?);
    try testing.expectEqualStrings("userId=Am%C3%A9lie,serverNode=DF%2028,isProduction=false", b.write(&out));

    // Two header fields, combined with a comma (RFC 9110 §5.3).
    b = try parseT("userId=alice" ++ "," ++ "serverNode=DF%2028,isProduction=false", &s);
    try testing.expectEqual(@as(usize, 3), b.members().len);

    // "Values and names might begin and end with spaces" (tabs too).
    b = try parseT("userId =   alice," ++ " serverNode = DF%2028, isProduction = false", &s);
    try testing.expectEqualStrings("alice", b.get("userId").?);
    try testing.expectEqualStrings("DF 28", b.get("serverNode").?);
    try testing.expectEqualStrings("false", b.get("isProduction").?);
    b = try parseT(" \tk\t=\tv\t;\tp\t=\tq\t ", &s);
    try testing.expectEqualStrings("v", b.get("k").?);
    try testing.expectEqualStrings("k=v;p=q", b.write(&out));
}

test "empty and whitespace-only values are an empty list" {
    var s: [max_len]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), (try parseT("", &s)).members().len);
    try testing.expectEqual(@as(usize, 0), (try parseT(" \t ", &s)).members().len);
    var out: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), (Baggage{}).write(&out).len);
}

test "value grammar: empty value, equal signs, token keys" {
    var s: [max_len]u8 = undefined;
    var b = try parseT("a=,b=x=y=z,Tok!#$&'*+-.^_`|~9=1", &s);
    try testing.expectEqualStrings("", b.get("a").?);
    try testing.expectEqualStrings("x=y=z", b.get("b").?);
    try testing.expectEqualStrings("1", b.get("Tok!#$&'*+-.^_`|~9").?);
    // `=` in a property value too.
    b = try parseT("a=1;p=q=r", &s);
    var it = b.members()[0].propertyIterator();
    try testing.expectEqualStrings("q=r", it.next().?.value.?);
}

test "percent-decoding: escapes, case, %25, U+FFFD for non-UTF-8" {
    var s: [max_len]u8 = undefined;
    var b = try parseT("a=%41%62%2f%2F%25%3b%2C%22%5C,b=100%25", &s);
    try testing.expectEqualStrings("Ab//%;,\"\\", b.get("a").?);
    try testing.expectEqualStrings("100%", b.get("b").?);
    // Lone continuation, truncated 3-byte sequence, overlong, surrogate, 0xFF.
    b = try parseT("a=%80,b=%E2%82,c=%C0%AF,d=%ED%A0%80,e=%FF,f=ok%E2%82%AC", &s);
    try testing.expectEqualStrings("\u{FFFD}", b.get("a").?);
    try testing.expectEqualStrings("\u{FFFD}\u{FFFD}", b.get("b").?);
    try testing.expectEqualStrings("\u{FFFD}\u{FFFD}", b.get("c").?);
    try testing.expectEqualStrings("\u{FFFD}\u{FFFD}\u{FFFD}", b.get("d").?);
    try testing.expectEqualStrings("\u{FFFD}", b.get("e").?);
    try testing.expectEqualStrings("ok\u{20AC}", b.get("f").?);
    // A 4-byte sequence decodes whole.
    b = try parseT("a=%F0%9F%98%80", &s);
    try testing.expectEqualStrings("\u{1F600}", b.get("a").?);
    // Decoded text re-encodes to canonical upper-case hex.
    var out: [64]u8 = undefined;
    b = try parseT("a=%f0%9f%98%80%2f", &s);
    try testing.expectEqualStrings("a=%F0%9F%98%80/", b.write(&out));
}

test "malformed members are errors, not panics" {
    var s: [max_len]u8 = undefined;
    const bad = [_][]const u8{
        "novalue", // no `=`
        "=v", // empty key
        " =v",
        "k k=v", // space inside a key
        "k(=v", // non-token key
        "k=v v", // space inside a value
        "k=\"v\"", // DQUOTE
        "k=a\\b", // backslash
        "k=\x7f",
        "k=\xc3\xa9", // raw non-ASCII
        "k=%", // bad escapes
        "k=%4",
        "k=%zz",
        "k=%4g",
        "k=v;", // empty property
        "k=v;;p",
        "k=v;=x", // property with empty key
        "k=v;p q",
        "k=v;p=\"",
        "a=1,", // empty members
        ",a=1",
        "a=1,,b=2",
        ",",
    };
    for (bad) |h| try testing.expectError(error.BadMember, Baggage.parse(h, &s));
    // `;` starts a property, and a property value is never percent-decoded or checked for escapes.
    _ = try Baggage.parse("k=a;b", &s);
    _ = try Baggage.parse("a=1;p=%zz,b=2", &s);
    // NUL and control bytes inside a header never parse.
    try testing.expectError(error.BadMember, Baggage.parse("k=a\x00b", &s));
    try testing.expectError(error.BadMember, Baggage.parse("k=a\r\nb", &s));
}

test "limits: 64 members pass, 65 fail; 8192 bytes pass, 8193 fail" {
    var s: [max_len]u8 = undefined;
    var hdr: [max_len + 64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&hdr);
    for (0..65) |i| {
        if (i != 0) try w.writeByte(',');
        try w.print("k{d}=v", .{i});
    }
    const all = w.buffered();
    const last_comma = std.mem.findScalarLast(u8, all, ',').?;
    const b64 = try Baggage.parse(all[0..last_comma], &s);
    try testing.expectEqual(@as(usize, 64), b64.members().len);
    try testing.expectError(error.TooManyMembers, Baggage.parse(all, &s));

    var big: [max_len + 1]u8 = undefined;
    @memset(&big, 'x');
    big[0] = 'k';
    big[1] = '=';
    const ok = try Baggage.parse(big[0..max_len], &s);
    try testing.expectEqual(@as(usize, max_len - 2), ok.members()[0].value.len);
    try testing.expectError(error.TooLong, Baggage.parse(big[0 .. max_len + 1], &s));
    // OWS around the whole value is not part of the baggage-string.
    var padded: [max_len + 2]u8 = undefined;
    @memcpy(padded[1 .. max_len + 1], big[0..max_len]);
    padded[0] = ' ';
    padded[max_len + 1] = '\t';
    _ = try Baggage.parse(&padded, &s);
    // A scratch shorter than the input is refused, not overrun.
    var small: [4]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, Baggage.parse("k=value", &small));
}

test "parseLenient: skips malformed members, drops whole members past a limit" {
    var s: [max_len]u8 = undefined;
    var b = try Baggage.parseLenient("a=1, bad, =x,b=%zz,c=3;,d=4;p", &s);
    try testing.expectEqual(@as(usize, 2), b.members().len);
    try testing.expectEqualStrings("1", b.get("a").?);
    try testing.expectEqualStrings("4", b.get("d").?);

    var hdr: [max_len + 64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&hdr);
    for (0..70) |i| {
        if (i != 0) try w.writeByte(',');
        try w.print("k{d}=v", .{i});
    }
    b = try Baggage.parseLenient(w.buffered(), &s);
    try testing.expectEqual(@as(usize, 64), b.members().len);
    try testing.expectEqualStrings("k63", b.members()[63].key);

    // Bytes: one 8000-byte member, then one that would end past 8192: dropped
    // whole, the first kept.
    var big: [9000]u8 = undefined;
    @memset(&big, 'x');
    big[0] = 'a';
    big[1] = '=';
    big[8000] = ',';
    big[8001] = 'b';
    big[8002] = '=';
    b = try Baggage.parseLenient(&big, &s);
    try testing.expectEqual(@as(usize, 1), b.members().len);
    try testing.expectEqual(@as(usize, 7998), b.members()[0].value.len);
    // A member ending exactly at 8192 stays.
    big[8100] = ',';
    big[8101] = 'c';
    big[8102] = '=';
    b = try Baggage.parseLenient(big[0..8192], &s);
    try testing.expectEqual(@as(usize, 3), b.members().len);
    try testing.expectEqualStrings("c", b.members()[2].key);
    try testing.expectEqual(@as(usize, 8192 - 8103), b.members()[2].value.len);
}

test "encode: every octet class, both ways" {
    var out: [1024]u8 = undefined;
    var s: [max_len]u8 = undefined;
    var b: Baggage = .{};
    // All 256 values, all must survive a write/parse round trip.
    var all: [256]u8 = undefined;
    for (&all, 0..) |*c, i| c.* = @intCast(i);
    try b.put("all", &all, "");
    const txt = b.write(&out);
    for (txt) |c| try testing.expect(isBaggageOctet(c));
    const back = try Baggage.parse(txt, &s);
    // Bytes >= 0x80 are not valid UTF-8 as a run, so only the ASCII half is exact.
    try testing.expectEqualStrings(all[0..128], back.get("all").?[0..128]);
    // Exactly the required set is encoded: space, DQUOTE, comma, semicolon, backslash, `%`, CTLs, non-ASCII.
    var one: Baggage = .{};
    try one.put("k", " \",;\\%\x01\x7f\u{e9}!#=~", "");
    try testing.expectEqualStrings("k=%20%22%2C%3B%5C%25%01%7F%C3%A9!#=~", one.write(&out));
}

test "round trip with properties, and put/get/delete" {
    var s: [max_len]u8 = undefined;
    var out: [512]u8 = undefined;
    var b = try parseT("a=1;p;q=r,b=Am%C3%A9lie,a=2", &s);
    const txt = b.write(&out);
    try testing.expectEqualStrings("a=1;p;q=r,b=Am%C3%A9lie,a=2", txt);
    var s2: [max_len]u8 = undefined;
    const again = try parseT(txt, &s2);
    try testing.expectEqual(b.len, again.len);
    for (b.members(), again.members()) |x, y| {
        try testing.expectEqualStrings(x.key, y.key);
        try testing.expectEqualStrings(x.value, y.value);
        try testing.expectEqualStrings(x.properties, y.properties);
    }
    // Duplicates keep their order; get returns the first.
    try testing.expectEqualStrings("1", b.get("a").?);
    // put updates the first in place (properties replaced), appends new.
    try b.put("a", "x y", "z");
    try b.put("c", "3", "");
    try testing.expectEqualStrings("a=x%20y;z,b=Am%C3%A9lie,a=2,c=3", b.write(&out));
    try testing.expectError(error.BadMember, b.put("bad key", "v", ""));
    try testing.expectError(error.BadMember, b.put("k", "v", "p;;q"));
    try testing.expectError(error.BadMember, b.put("k", "v", ";p"));
    try testing.expect(b.delete("a"));
    try testing.expect(!b.delete("a"));
    try testing.expectEqualStrings("b=Am%C3%A9lie,c=3", b.write(&out));
    // 65th member refused.
    var full: Baggage = .{};
    var keys: [max_members][4]u8 = undefined; // put borrows the key
    for (&keys, 0..) |*k, i| try full.put(std.fmt.bufPrint(k, "k{d}", .{i}) catch unreachable, "v", "");
    try testing.expectError(error.TooManyMembers, full.put("extra", "v", ""));
    try full.put("k0", "w", ""); // updating a full list is fine
}

test "write leaves out whole members from the right, never a partial one" {
    var b: Baggage = .{};
    try b.put("aa", "11", "p"); // "aa=11;p" = 7
    try b.put("bb", "22", ""); // "bb=22" = 5, total 13
    try b.put("cc", "33", ""); // total 19
    var out: [32]u8 = undefined;
    try testing.expectEqualStrings("aa=11;p,bb=22,cc=33", b.write(&out));
    try testing.expectEqualStrings("aa=11;p,bb=22,cc=33", b.write(out[0..19]));
    try testing.expectEqualStrings("aa=11;p,bb=22", b.write(out[0..18]));
    try testing.expectEqualStrings("aa=11;p,bb=22", b.write(out[0..13]));
    try testing.expectEqualStrings("aa=11;p", b.write(out[0..12]));
    try testing.expectEqualStrings("aa=11;p", b.write(out[0..7]));
    try testing.expectEqualStrings("", b.write(out[0..6]));
    try testing.expectEqualStrings("", b.write(out[0..0]));
    // The 8192 cap applies to the output even with a larger buffer.
    var huge: Baggage = .{};
    const v: [4000]u8 = @splat('x');
    try huge.put("a", &v, "");
    try huge.put("b", &v, "");
    try huge.put("c", &v, "");
    var big: [20000]u8 = undefined;
    const got = huge.write(&big);
    try testing.expect(got.len <= max_len);
    try testing.expectEqual(@as(usize, 2 * 4002 + 1), got.len);
}

test "decodeValue: bounded output, bad escapes" {
    var out: [3]u8 = undefined;
    try testing.expectEqualStrings("abc", try decodeValue("abc", &out));
    try testing.expectError(error.NoSpaceLeft, decodeValue("abcd", &out));
    try testing.expectError(error.NoSpaceLeft, decodeValue("%80%80", &out)); // two U+FFFD = 6 bytes
    try testing.expectError(error.BadEscape, decodeValue("a%2", &out));
    try testing.expectError(error.BadEscape, decodeValue("%E2%8", &out));
}

fn checkInput(input: []const u8) !void {
    var s: [max_len]u8 = undefined;
    var s2: [max_len]u8 = undefined;
    var out: [max_len + 64]u8 = undefined;
    const strict = Baggage.parse(input, &s);
    const lenient = try Baggage.parseLenient(input, &s2);
    if (strict) |sb| {
        // What strict accepts, lenient accepts identically.
        try testing.expectEqual(sb.len, lenient.len);
    } else |_| {}
    // Whatever was parsed serializes to text that strictly re-parses to the same list.
    const txt = lenient.write(&out);
    var s3: [max_len]u8 = undefined;
    const back = try Baggage.parse(txt, &s3);
    try testing.expectEqual(lenient.len, back.len);
    for (lenient.members(), back.members()) |x, y| {
        try testing.expectEqualStrings(x.key, y.key);
        try testing.expectEqualStrings(x.value, y.value);
    }
}

fn fuzzOne(_: void, smith: *std.testing.Smith) !void {
    var raw: [512]u8 = undefined;
    const n: usize = smith.slice(&raw);
    try checkInput(raw[0..n]);
}

test "fuzz: baggage parse never panics, round trip holds" {
    try std.testing.fuzz({}, fuzzOne, .{ .corpus = &.{
        fuzzseed.seed("key1=value1;property1;property2, key2 = value2, key3=value3; propertyKey=propertyValue"),
        fuzzseed.seed("userId=Am%C3%A9lie,serverNode=DF%2028,isProduction=false"),
        fuzzseed.seed("a=%E2%82,b=%FF%FE,c=%"),
        fuzzseed.seed("a=1;;,,;="),
    } });
}

test "deterministic structured fuzz: 3000 inputs from a baggage-shaped alphabet" {
    const alphabet = "abcAB09=;, \t%2F8CE\xc3\xa9\"\\_-";
    var prng = std.Random.DefaultPrng.init(0xba66a6e);
    const rnd = prng.random();
    var buf: [200]u8 = undefined;
    var accepted: usize = 0;
    for (0..3000) |_| {
        const n = rnd.uintLessThan(usize, buf.len);
        for (buf[0..n]) |*c| c.* = alphabet[rnd.uintLessThan(usize, alphabet.len)];
        try checkInput(buf[0..n]);
        var s: [max_len]u8 = undefined;
        if (Baggage.parse(buf[0..n], &s)) |_| accepted += 1 else |_| {}
    }
    // Reach: some inputs are valid (the empty one at least, mostly short ones).
    try testing.expect(accepted > 0);
}
