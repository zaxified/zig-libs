// SPDX-License-Identifier: MIT
//! `GeneralName` (RFC 5280 §4.2.1.6) decoding and the name-constraint
//! matching rules of RFC 5280 §4.2.1.10, one function per name type, as
//! `chain.checkNameConstraints` and `hostname` use them.
//!
//! Every matcher answers `Match`: `inside`, `outside`, or `unsupported` when
//! the name or the constraint cannot be read under that type's rules (a
//! malformed domain, a mailbox with a quoted local part, a URI without a host
//! or with an IP host). The caller fails closed on `unsupported`: an excluded
//! subtree it cannot evaluate rejects, a permitted one does not admit. Go's
//! `Verify` does the same — it reports such a name as an error rather than
//! deciding either way.
//!
//! Domain-shaped constraints (dNSName, the domain of an rfc822Name, the host
//! of a URI) share one rule, `matchDomain`, the reading Go and rustls-webpki
//! apply: an empty constraint matches every domain; `.example.com` matches
//! names with at least one label more; `example.com` matches itself and every
//! subdomain. RFC 5280 reads a bare rfc822/URI domain constraint as "that
//! host only"; the shared rule is wider, which on the excluded side refuses
//! more and on the permitted side admits subdomains of a name the CA was
//! constrained to anyway.

const std = @import("std");
const Certificate = std.crypto.Certificate;
const der = Certificate.der;
const extensions = @import("extensions.zig");
const netaddr = @import("netaddr");

pub const Tag = Certificate.GeneralNameTag;

/// One decoded `GeneralName`: its CHOICE tag and its content bytes (IA5String
/// text for rfc822/dNS/URI, the `Name` content for directoryName, 4 or 16
/// octets for an iPAddress SAN, 8 or 32 for an iPAddress constraint).
pub const GeneralName = struct {
    tag: Tag,
    value: []const u8,
};

/// Walks a `GeneralNames ::= SEQUENCE OF GeneralName`, i.e. a raw
/// `subjectAltName` extnValue. An empty input yields nothing (no SAN).
pub const GeneralNameIterator = struct {
    pub const Error = der.Element.ParseError || error{CertificateFieldHasWrongDataType};

    bytes: []const u8,
    pos: u32,
    end: u32,

    pub fn init(san_ext_value: []const u8) Error!GeneralNameIterator {
        if (san_ext_value.len == 0) return .{ .bytes = san_ext_value, .pos = 0, .end = 0 };
        const seq = try extensions.parseElement(san_ext_value, 0);
        if (@as(u8, @bitCast(seq.identifier)) != 0x30) return error.CertificateFieldHasWrongDataType;
        if (seq.slice.end != san_ext_value.len) return error.CertificateFieldHasInvalidLength;
        return .{ .bytes = san_ext_value, .pos = seq.slice.start, .end = seq.slice.end };
    }

    pub fn next(it: *GeneralNameIterator) Error!?GeneralName {
        if (it.pos >= it.end) return null;
        const elem = try extensions.parseElement(it.bytes, it.pos);
        if (elem.slice.end > it.end) return error.CertificateFieldHasInvalidLength;
        it.pos = elem.slice.end;
        // GeneralName is a CHOICE of context-specific [0]..[8]; anything else
        // is not a GeneralName at all.
        if (elem.identifier.class != .context_specific) return error.CertificateFieldHasWrongDataType;
        const n = @backingInt(elem.identifier.tag);
        if (n > 8) return error.CertificateFieldHasWrongDataType;
        return .{ .tag = @fromBackingInt(@intCast(n)), .value = it.bytes[elem.slice.start..elem.slice.end] };
    }
};

/// `id-at-commonName` (2.5.4.3), OID content octets, for `nameAttribute`.
pub const oid_common_name = [_]u8{ 0x55, 0x04, 0x03 };

pub const NameAttributeError = der.Element.ParseError || error{CertificateFieldHasWrongDataType};

/// The first value of attribute `oid` (OID content octets) in a `Name`, as
/// the content octets of its string, or null. `name` is RDNSequence content
/// (no outer SEQUENCE header), as `chain.certSerialAndIssuer` returns the
/// issuer. Every element is bounded by its parent, so any input errors
/// rather than reads out of bounds.
pub fn nameAttribute(name: []const u8, oid: []const u8) NameAttributeError!?[]const u8 {
    if (name.len > std.math.maxInt(u32)) return error.CertificateFieldHasInvalidLength;
    // RDNSequence ::= SEQUENCE OF RelativeDistinguishedName ::= SET OF
    // AttributeTypeAndValue ::= SEQUENCE { type OID, value ANY }.
    var rdn_at: u32 = 0;
    while (rdn_at < name.len) {
        const rdn = try extensions.parseElement(name, rdn_at);
        if (@as(u8, @bitCast(rdn.identifier)) != 0x31) return error.CertificateFieldHasWrongDataType;
        rdn_at = rdn.slice.end;
        var atv_at = rdn.slice.start;
        while (atv_at < rdn.slice.end) {
            const atv = try extensions.parseElement(name, atv_at);
            if (@as(u8, @bitCast(atv.identifier)) != 0x30) return error.CertificateFieldHasWrongDataType;
            if (atv.slice.end > rdn.slice.end) return error.CertificateFieldHasInvalidLength;
            atv_at = atv.slice.end;
            const type_elem = try extensions.parseElement(name, atv.slice.start);
            if (@as(u8, @bitCast(type_elem.identifier)) != 0x06) return error.CertificateFieldHasWrongDataType;
            if (type_elem.slice.end >= atv.slice.end) return error.CertificateFieldHasInvalidLength;
            const value = try extensions.parseElement(name, type_elem.slice.end);
            if (value.slice.end != atv.slice.end) return error.CertificateFieldHasInvalidLength;
            if (std.mem.eql(u8, name[type_elem.slice.start..type_elem.slice.end], oid)) return name[value.slice.start..value.slice.end];
        }
    }
    return null;
}

pub const Match = enum { inside, outside, unsupported };

fn fromBool(b: bool) Match {
    return if (b) .inside else .outside;
}

/// Whether `match` can evaluate constraints of this type at all. The other
/// four (otherName, x400Address, ediPartyName, registeredID) have no matching
/// rule in RFC 5280 §4.2.1.10, and no implementation we know of matches them.
pub fn typeSupported(tag: Tag) bool {
    return switch (tag) {
        .rfc822Name, .dNSName, .directoryName, .uniformResourceIdentifier, .iPAddress => true,
        else => false,
    };
}

/// Dispatch on `tag`: `name` against one constraint `base` of the same type.
pub fn match(tag: Tag, name: []const u8, base: []const u8) Match {
    return switch (tag) {
        .dNSName => matchDns(name, base),
        .rfc822Name => matchRfc822(name, base),
        .uniformResourceIdentifier => matchUri(name, base),
        .directoryName => fromBool(matchDirectory(rdnSequence(name), rdnSequence(base))),
        .iPAddress => matchIp(name, base),
        else => .unsupported,
    };
}

/// A dNSName SAN entry against a dNSName constraint (`matchDomain`).
pub fn matchDns(name: []const u8, constraint: []const u8) Match {
    return matchDomain(name, constraint);
}

/// The shared domain rule (module doc). `unsupported` when either side is
/// not a well-formed domain: an empty label (leading, trailing or doubled
/// dot — a trailing-dot name is the same DNS name to a resolver, so it must
/// not slip past an excluded `example.com` as "different"), or a byte
/// outside printable ASCII.
pub fn matchDomain(name: []const u8, constraint: []const u8) Match {
    if (!validDomain(name)) return .unsupported;
    if (constraint.len == 0) return .inside;
    const subdomains_only = constraint[0] == '.';
    const c = if (subdomains_only) constraint[1..] else constraint;
    if (!validDomain(c)) return .unsupported;
    if (name.len == c.len) return fromBool(!subdomains_only and std.ascii.eqlIgnoreCase(name, c));
    if (name.len < c.len + 2) return .outside;
    return fromBool(name[name.len - c.len - 1] == '.' and std.ascii.eqlIgnoreCase(name[name.len - c.len ..], c));
}

fn validDomain(d: []const u8) bool {
    if (d.len == 0 or d.len > 253) return false;
    var label_len: usize = 0;
    for (d) |b| {
        if (b == '.') {
            if (label_len == 0) return false;
            label_len = 0;
            continue;
        }
        if (b <= 0x20 or b >= 0x7f) return false;
        label_len += 1;
        if (label_len > 63) return false;
    }
    return label_len != 0;
}

/// A mailbox split at the `@` that ends its local part. `local` is raw: a
/// quoted local part (`"a@b"`, RFC 5321 §4.1.2 Quoted-string) keeps its
/// quotes and backslash escapes, and `localEql` compares two of them by
/// their unescaped content, as Go does.
pub const Mailbox = struct { local: []const u8, domain: []const u8 };

pub fn parseMailbox(s: []const u8) ?Mailbox {
    if (s.len == 0) return null;
    var i: usize = 0;
    if (s[0] == '"') {
        i = 1;
        while (true) : (i += 1) {
            if (i >= s.len) return null;
            const b = s[i];
            if (b == '"') break;
            if (b == '\\') {
                i += 1;
                if (i >= s.len or s[i] < 0x20 or s[i] >= 0x7f) return null;
                continue;
            }
            if (b < 0x20 or b >= 0x7f) return null;
        }
        i += 1;
        if (i >= s.len or s[i] != '@') return null;
    } else {
        // Dot-atom: printable ASCII without the specials RFC 5322 §3.2.3
        // keeps out of atext.
        while (i < s.len and s[i] != '@') : (i += 1) {
            const b = s[i];
            if (b <= 0x20 or b >= 0x7f) return null;
            if (std.mem.findScalar(u8, "\"(),:;<>[\\]", b) != null) return null;
        }
        if (i == 0 or i >= s.len) return null;
    }
    const domain = s[i + 1 ..];
    if (std.mem.findScalar(u8, domain, '@') != null) return null;
    return .{ .local = s[0..i], .domain = domain };
}

/// Unescaped content of a local part from `parseMailbox`, one byte at a time.
const LocalBytes = struct {
    raw: []const u8,
    i: usize,

    fn init(raw: []const u8) LocalBytes {
        if (raw.len >= 2 and raw[0] == '"') return .{ .raw = raw[1 .. raw.len - 1], .i = 0 };
        return .{ .raw = raw, .i = 0 };
    }

    fn next(it: *LocalBytes) ?u8 {
        if (it.i >= it.raw.len) return null;
        if (it.raw[it.i] == '\\' and it.i + 1 < it.raw.len) it.i += 1;
        defer it.i += 1;
        return it.raw[it.i];
    }
};

/// Case-sensitive equality of two local parts by unescaped content, so
/// `"user"` equals `user`.
pub fn localEql(a: []const u8, b: []const u8) bool {
    var x: LocalBytes = .init(a);
    var y: LocalBytes = .init(b);
    while (true) {
        const p = x.next();
        const q = y.next();
        if (p == null or q == null) return p == null and q == null;
        if (p.? != q.?) return false;
    }
}

/// An rfc822Name SAN entry against an rfc822Name constraint. A constraint
/// holding `@` names one mailbox: local part compared exactly (unescaped),
/// domain case-insensitively. Otherwise the constraint is a domain and the
/// mailbox's domain is matched by `matchDomain`.
pub fn matchRfc822(name: []const u8, constraint: []const u8) Match {
    const mb = parseMailbox(name) orelse return .unsupported;
    if (!validDomain(mb.domain)) return .unsupported;
    if (std.mem.findScalar(u8, constraint, '@') != null) {
        const c = parseMailbox(constraint) orelse return .unsupported;
        if (!validDomain(c.domain)) return .unsupported;
        return fromBool(localEql(mb.local, c.local) and std.ascii.eqlIgnoreCase(mb.domain, c.domain));
    }
    return matchDomain(mb.domain, constraint);
}

/// The host of a URI's authority (RFC 3986 §3.2): after `scheme://`, before
/// the first `/`, `?` or `#`, without `userinfo@` and `:port`. Null when the
/// URI has no authority, the host is empty, or the host is an IP literal
/// (`[…]` or dotted IPv4) — a URI constraint is a domain rule and cannot
/// place an address (RFC 5280 §4.2.1.10 asks for a fully qualified domain).
pub fn uriHost(uri: []const u8) ?[]const u8 {
    const colon = std.mem.findScalar(u8, uri, ':') orelse return null;
    if (colon == 0) return null;
    for (uri[0..colon], 0..) |b, i| {
        const ok = std.ascii.isAlphabetic(b) or (i > 0 and (std.ascii.isDigit(b) or b == '+' or b == '-' or b == '.'));
        if (!ok) return null;
    }
    const rest = uri[colon + 1 ..];
    if (!std.mem.startsWith(u8, rest, "//")) return null;
    const auth_all = rest[2..];
    const auth_end = std.mem.findAny(u8, auth_all, "/?#") orelse auth_all.len;
    var host = auth_all[0..auth_end];
    if (std.mem.findScalarLast(u8, host, '@')) |at| host = host[at + 1 ..];
    if (host.len != 0 and host[0] == '[') return null;
    if (std.mem.findScalarLast(u8, host, ':')) |c| {
        for (host[c + 1 ..]) |b| if (!std.ascii.isDigit(b)) return null;
        host = host[0..c];
    }
    if (host.len == 0) return null;
    if (std.mem.findScalar(u8, host, '%') != null) return null;
    if (parseIp4(host) != null) return null;
    return host;
}

/// A uniformResourceIdentifier SAN entry against a URI constraint: the
/// URI's host (`uriHost`) by `matchDomain`.
pub fn matchUri(uri: []const u8, constraint: []const u8) Match {
    const host = uriHost(uri) orelse return .unsupported;
    return matchDomain(host, constraint);
}

/// An iPAddress SAN entry (4 or 16 octets) against an iPAddress constraint
/// (address ‖ mask, 8 or 32 octets). Different families never match (an
/// IPv4-mapped IPv6 address is not its IPv4 address here, as in Go).
pub fn matchIp(addr: []const u8, constraint: []const u8) Match {
    if (constraint.len != 8 and constraint.len != 32) return .unsupported;
    if (addr.len != 4 and addr.len != 16) return .unsupported;
    const half = constraint.len / 2;
    if (addr.len != half) return .outside;
    const net = constraint[0..half];
    const mask = constraint[half..];
    for (addr, net, mask) |a, n, m| {
        if ((a & m) != (n & m)) return .outside;
    }
    return .inside;
}

/// The RDNSequence of a directoryName value. A constraint base and a SAN
/// entry carry the whole `Name` (`[4] EXPLICIT Name`: a SEQUENCE element),
/// a certificate's subject is passed as its content (the RDN SETs) — so a
/// value that is exactly one SEQUENCE element is unwrapped, anything else
/// (already an RDN list: RDNs are SETs, never SEQUENCEs) is returned as is.
/// Until 2026-10-19 the two shapes were compared as they came: a real
/// excluded directoryName never matched a subject (bypass) and a permitted
/// one never admitted it.
fn rdnSequence(v: []const u8) []const u8 {
    if (v.len < 2 or v[0] != 0x30) return v;
    const e = extensions.parseElement(v, 0) catch return v;
    if (e.slice.end != v.len) return v;
    return v[e.slice.start..e.slice.end];
}

/// directoryName: the constraint's RDNSequence must be an element-wise
/// prefix of the name's (whole encoded RDNs compared, so a match cannot end
/// inside one).
pub fn matchDirectory(name: []const u8, base: []const u8) bool {
    if (base.len == 0) return true;
    var name_pos: u32 = 0;
    var base_pos: u32 = 0;
    const name_end: u32 = @intCast(name.len);
    const base_end: u32 = @intCast(base.len);
    while (base_pos < base_end) {
        const base_elem = extensions.parseElement(base, base_pos) catch return false;
        if (name_pos >= name_end) return false;
        const name_elem = extensions.parseElement(name, name_pos) catch return false;
        if (!std.mem.eql(u8, base[base_pos..base_elem.slice.end], name[name_pos..name_elem.slice.end])) return false;
        base_pos = base_elem.slice.end;
        name_pos = name_elem.slice.end;
    }
    return true;
}

/// Dotted-quad IPv4, four decimal parts 0–255 without leading zeros (as Go's
/// `net.ParseIP` since 1.17: `010.0.0.1` is not an address). The `netaddr`
/// parser: one implementation for the whole collection (until 2026-10-17 this
/// file carried its own copy; a differential run over 20 M inputs found no
/// disagreement before the switch).
pub const parseIp4 = netaddr.parseIp4;

/// RFC 4291 §2.2 text form: eight groups of 1–4 hex digits, one `::`
/// standing for one or more zero groups, optionally a dotted IPv4 tail.
/// No zone (`%eth0`) and no brackets. The `netaddr` parser, as above.
pub const parseIp6 = netaddr.parseIp6;

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "matchDomain: bare, leading-dot and empty constraints" {
    try testing.expectEqual(Match.inside, matchDomain("example.com", "example.com"));
    try testing.expectEqual(Match.inside, matchDomain("a.example.com", "example.com"));
    try testing.expectEqual(Match.inside, matchDomain("A.EXAMPLE.com", "example.COM"));
    try testing.expectEqual(Match.outside, matchDomain("xexample.com", "example.com"));
    try testing.expectEqual(Match.outside, matchDomain("example.com", ".example.com"));
    try testing.expectEqual(Match.inside, matchDomain("a.example.com", ".example.com"));
    try testing.expectEqual(Match.inside, matchDomain("a.b.example.com", ".example.com"));
    try testing.expectEqual(Match.outside, matchDomain("xexample.com", ".example.com"));
    try testing.expectEqual(Match.inside, matchDomain("anything.org", ""));
    try testing.expectEqual(Match.outside, matchDomain("com", "example.com"));
}

test "matchDomain: malformed names and constraints are unsupported (fail closed)" {
    try testing.expectEqual(Match.unsupported, matchDomain("a.example.com.", "example.com"));
    try testing.expectEqual(Match.unsupported, matchDomain(".a.example.com", "example.com"));
    try testing.expectEqual(Match.unsupported, matchDomain("a..example.com", "example.com"));
    try testing.expectEqual(Match.unsupported, matchDomain("", "example.com"));
    try testing.expectEqual(Match.unsupported, matchDomain("a b.com", "b.com"));
    try testing.expectEqual(Match.unsupported, matchDomain("a.example.com", "example..com"));
    try testing.expectEqual(Match.unsupported, matchDomain("a.example.com", "."));
}

test "matchRfc822: mailbox, host and domain constraints" {
    try testing.expectEqual(Match.inside, matchRfc822("user@example.com", "user@example.com"));
    try testing.expectEqual(Match.inside, matchRfc822("user@EXAMPLE.com", "user@example.com"));
    try testing.expectEqual(Match.outside, matchRfc822("User@example.com", "user@example.com"));
    try testing.expectEqual(Match.inside, matchRfc822("x@example.com", "example.com"));
    try testing.expectEqual(Match.inside, matchRfc822("x@a.example.com", "example.com"));
    try testing.expectEqual(Match.outside, matchRfc822("x@example.com", ".example.com"));
    try testing.expectEqual(Match.inside, matchRfc822("x@a.example.com", ".example.com"));
    // Quoted local parts are read, as Go does (probe O-email, 2026-10-11).
    try testing.expectEqual(Match.inside, matchRfc822("\"a@b\"@example.com", "example.com"));
    try testing.expectEqual(Match.outside, matchRfc822("\"a@b\"@example.com", "user@example.com"));
    try testing.expectEqual(Match.outside, matchRfc822("\"a@b\"@example.com", ".example.com"));
    try testing.expectEqual(Match.inside, matchRfc822("\"user\"@example.com", "user@example.com"));
    try testing.expectEqual(Match.inside, matchRfc822("\"us\\er\"@example.com", "user@example.com"));
    try testing.expectEqual(Match.unsupported, matchRfc822("\"open@example.com", "example.com"));
    try testing.expectEqual(Match.unsupported, matchRfc822("\"a\"b@example.com", "example.com"));
    try testing.expectEqual(Match.unsupported, matchRfc822("a b@example.com", "example.com"));
    try testing.expectEqual(Match.unsupported, matchRfc822("a@b@example.com", "example.com"));
    try testing.expectEqual(Match.unsupported, matchRfc822("no-at-sign", "example.com"));
    try testing.expectEqual(Match.unsupported, matchRfc822("@example.com", "example.com"));
}

test "uriHost: authority host extraction" {
    try testing.expectEqualStrings("example.com", uriHost("https://example.com/x").?);
    try testing.expectEqualStrings("example.com", uriHost("https://user@example.com:8443/p").?);
    try testing.expectEqualStrings("example.com", uriHost("spiffe://example.com/ns/a").?);
    try testing.expectEqualStrings("example.com", uriHost("https://example.com?q#f").?);
    try testing.expect(uriHost("urn:uuid:1234") == null);
    try testing.expect(uriHost("https://192.0.2.1/") == null);
    try testing.expect(uriHost("https://[::1]/") == null);
    try testing.expect(uriHost("https:///path") == null);
    try testing.expect(uriHost("https://example.com:80x/") == null);
    try testing.expect(uriHost("//example.com") == null);
}

test "matchUri" {
    try testing.expectEqual(Match.inside, matchUri("https://a.example.com/", ".example.com"));
    try testing.expectEqual(Match.outside, matchUri("https://example.com/", ".example.com"));
    try testing.expectEqual(Match.outside, matchUri("https://example.org/", "example.com"));
    try testing.expectEqual(Match.unsupported, matchUri("urn:x", "example.com"));
}

test "matchIp" {
    const c4 = [_]u8{ 192, 0, 2, 0, 255, 255, 255, 0 };
    try testing.expectEqual(Match.inside, matchIp(&.{ 192, 0, 2, 7 }, &c4));
    try testing.expectEqual(Match.outside, matchIp(&.{ 192, 0, 3, 7 }, &c4));
    try testing.expectEqual(Match.outside, matchIp(&(@as([16]u8, @splat(0))), &c4));
    try testing.expectEqual(Match.unsupported, matchIp(&.{ 1, 2, 3 }, &c4));
    try testing.expectEqual(Match.unsupported, matchIp(&.{ 1, 2, 3, 4 }, c4[0..6]));
}

test "parseIp4 / parseIp6" {
    try testing.expectEqual([4]u8{ 192, 0, 2, 1 }, parseIp4("192.0.2.1").?);
    try testing.expect(parseIp4("192.0.2") == null);
    try testing.expect(parseIp4("192.0.2.1.5") == null);
    try testing.expect(parseIp4("192.0.2.256") == null);
    try testing.expect(parseIp4("010.0.0.1") == null);
    try testing.expect(parseIp4("1..2.3") == null);

    const db8 = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    try testing.expectEqual(db8, parseIp6("2001:db8::1").?);
    try testing.expectEqual(db8, parseIp6("2001:0db8:0:0:0:0:0:1").?);
    try testing.expectEqual(db8, parseIp6("2001:DB8::0001").?);
    var loop: [16]u8 = @splat(0);
    loop[15] = 1;
    try testing.expectEqual(loop, parseIp6("::1").?);
    try testing.expectEqual(@as([16]u8, @splat(0)), parseIp6("::").?);
    const mapped = [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1 };
    try testing.expectEqual(mapped, parseIp6("::ffff:192.0.2.1").?);
    var tail: [16]u8 = @splat(0);
    tail[0] = 0x20;
    tail[1] = 0x01;
    try testing.expectEqual(tail, parseIp6("2001::").?);
    try testing.expect(parseIp6("2001:db8::1::2") == null);
    try testing.expect(parseIp6("1:2:3:4:5:6:7:8:9") == null);
    try testing.expect(parseIp6("1:2:3:4:5:6:7::8") == null);
    try testing.expect(parseIp6("12345::") == null);
    try testing.expect(parseIp6(":1::") == null);
    try testing.expect(parseIp6("1:") == null);
    try testing.expect(parseIp6("1:2:3:4:5:6:7") == null);
    try testing.expect(parseIp6("fe80::1%eth0") == null);
    try testing.expect(parseIp6("[::1]") == null);
}

test "GeneralNameIterator: SAN with dNSName, rfc822Name, iPAddress" {
    const san = [_]u8{
        0x30, 0x19,
        0x82, 0x0b,
        'e',  'x',
        'a',  'm',
        'p',  'l',
        'e',  '.',
        'c',  'o',
        'm',  0x81,
        0x04, 'a',
        '@',  'b',
        'c',  0x87,
        0x04, 192,
        0,    2,
        1,
    };
    var it = try GeneralNameIterator.init(&san);
    const a = (try it.next()).?;
    try testing.expectEqual(Tag.dNSName, a.tag);
    try testing.expectEqualStrings("example.com", a.value);
    try testing.expectEqual(Tag.rfc822Name, (try it.next()).?.tag);
    const c = (try it.next()).?;
    try testing.expectEqual(Tag.iPAddress, c.tag);
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, c.value);
    try testing.expect((try it.next()) == null);

    var empty = try GeneralNameIterator.init(&.{});
    try testing.expect((try empty.next()) == null);
    // A universal-class element is not a GeneralName.
    var bad = try GeneralNameIterator.init(&.{ 0x30, 0x03, 0x04, 0x01, 0x00 });
    try testing.expectError(error.CertificateFieldHasWrongDataType, bad.next());
}
