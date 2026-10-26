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
        .directoryName => matchDirectory(rdnSequence(name), rdnSequence(base)),
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

/// directoryName: the constraint's RDNSequence must be a prefix of the
/// name's, RDN by RDN (a match cannot end inside one), each pair compared by
/// `rdnEql`. `unsupported` when either side cannot be read, so an excluded
/// subtree rejects it.
///
/// Until 2026-10-26 the RDNs were compared byte for byte: a subordinate CA
/// under an excluded `O=Evil Org` could issue `O=evil org`, `O=Evil  Org` or
/// the same text as a PrintableString instead of a UTF8String, and pass
/// (audit 2026-10-26, F1); an unreadable name or base counted as outside, so
/// an excluded subtree let it through (F2).
pub fn matchDirectory(name: []const u8, base: []const u8) Match {
    if (base.len == 0) return .inside;
    if (name.len > std.math.maxInt(u32) or base.len > std.math.maxInt(u32)) return .unsupported;
    var name_pos: u32 = 0;
    var base_pos: u32 = 0;
    while (base_pos < base.len) {
        const base_rdn = rdnAt(base, base_pos) orelse return .unsupported;
        if (name_pos >= name.len) return .outside;
        const name_rdn = rdnAt(name, name_pos) orelse return .unsupported;
        switch (rdnEql(name[name_rdn.start..name_rdn.end], base[base_rdn.start..base_rdn.end])) {
            .equal => {},
            .different => return .outside,
            .unreadable => return .unsupported,
        }
        base_pos = base_rdn.end;
        name_pos = name_rdn.end;
    }
    return .inside;
}

/// The content of the RDN (a SET) at `pos`, or null when it is not one.
fn rdnAt(seq: []const u8, pos: u32) ?struct { start: u32, end: u32 } {
    const e = extensions.parseElement(seq, pos) catch return null;
    if (@as(u8, @bitCast(e.identifier)) != 0x31) return null;
    return .{ .start = e.slice.start, .end = e.slice.end };
}

const Eql = enum { equal, different, unreadable };

/// Two RDNs (SET contents) are equal when they hold the same number of
/// AttributeTypeAndValues and every one of `b`'s has an equal one in `a`
/// (`atvEql`; a SET is unordered, and canonical forms need not sort as the
/// DER encodings do).
fn rdnEql(a: []const u8, b: []const u8) Eql {
    const n_a = countAtvs(a) orelse return .unreadable;
    const n_b = countAtvs(b) orelse return .unreadable;
    if (n_a != n_b) return .different;
    var b_pos: u32 = 0;
    while (b_pos < b.len) {
        const b_atv = extensions.parseElement(b, b_pos) catch return .unreadable;
        b_pos = b_atv.slice.end;
        var found = false;
        var a_pos: u32 = 0;
        while (a_pos < a.len) {
            const a_atv = extensions.parseElement(a, a_pos) catch return .unreadable;
            a_pos = a_atv.slice.end;
            switch (atvEql(a[a_atv.slice.start..a_atv.slice.end], b[b_atv.slice.start..b_atv.slice.end])) {
                .equal => found = true,
                .different => {},
                .unreadable => return .unreadable,
            }
        }
        if (!found) return .different;
    }
    return .equal;
}

/// AttributeTypeAndValues in an RDN, each a SEQUENCE; null if any is not.
fn countAtvs(rdn: []const u8) ?usize {
    var n: usize = 0;
    var pos: u32 = 0;
    while (pos < rdn.len) : (n += 1) {
        const e = extensions.parseElement(rdn, pos) catch return null;
        if (@as(u8, @bitCast(e.identifier)) != 0x30) return null;
        pos = e.slice.end;
    }
    return n;
}

/// One AttributeTypeAndValue (SEQUENCE content) against another: the same
/// type OID, and values equal as `valueEql` reads them.
fn atvEql(a: []const u8, b: []const u8) Eql {
    const ta, const va = splitAtv(a) orelse return .unreadable;
    const tb, const vb = splitAtv(b) orelse return .unreadable;
    if (!std.mem.eql(u8, ta, tb)) return .different;
    return valueEql(va, vb);
}

/// The type OID (whole TLV) and the value (whole TLV) of an ATV.
fn splitAtv(atv: []const u8) ?struct { []const u8, []const u8 } {
    const t = extensions.parseElement(atv, 0) catch return null;
    if (@as(u8, @bitCast(t.identifier)) != 0x06 or t.slice.end >= atv.len) return null;
    const v = extensions.parseElement(atv, t.slice.end) catch return null;
    if (v.slice.end != atv.len) return null;
    return .{ atv[0..t.slice.end], atv[t.slice.end..] };
}

/// RFC 5280 §7.1: two directory string values match after string
/// preparation. Implemented as OpenSSL canonicalises names for its own
/// name-constraint check (`x509_name_canon`): every directory string type is
/// read as Unicode (UTF8String, PrintableString, IA5String, VisibleString,
/// TeletexString as Latin-1, BMPString, UniversalString), leading and
/// trailing white space dropped, inner runs of it one space, ASCII letters
/// folded to lower case — so the string type and those spellings no longer
/// tell two names apart. Not done: RFC 4518's full Unicode case folding and
/// normalisation (a non-ASCII letter in another case still differs, as in
/// OpenSSL). Any other value type compares as encoded.
fn valueEql(a: []const u8, b: []const u8) Eql {
    const ea = extensions.parseElement(a, 0) catch return .unreadable;
    const eb = extensions.parseElement(b, 0) catch return .unreadable;
    const tag_a: u8 = @bitCast(ea.identifier);
    const tag_b: u8 = @bitCast(eb.identifier);
    if (!isDirectoryString(tag_a) or !isDirectoryString(tag_b)) return if (std.mem.eql(u8, a, b)) .equal else .different;
    var x: Canonical = .{ .tag = tag_a, .bytes = a[ea.slice.start..ea.slice.end] };
    var y: Canonical = .{ .tag = tag_b, .bytes = b[eb.slice.start..eb.slice.end] };
    while (true) {
        const p = x.next() catch return .unreadable;
        const q = y.next() catch return .unreadable;
        if (p == null or q == null) {
            if (p != null or q != null) {
                // Read the longer one to its end: an encoding error there
                // still makes the pair unreadable, not merely different.
                while (x.next() catch return .unreadable) |_| {}
                while (y.next() catch return .unreadable) |_| {}
                return .different;
            }
            return .equal;
        }
        if (p.? != q.?) {
            while (x.next() catch return .unreadable) |_| {}
            while (y.next() catch return .unreadable) |_| {}
            return .different;
        }
    }
}

fn isDirectoryString(tag: u8) bool {
    return switch (tag) {
        0x0c, 0x13, 0x14, 0x16, 0x1a, 0x1c, 0x1e => true,
        else => false,
    };
}

/// The code points of a directory string, prepared as `valueEql` says.
const Canonical = struct {
    tag: u8,
    bytes: []const u8,
    i: usize = 0,
    started: bool = false,
    space: bool = false,
    held: ?u21 = null,

    const Error = error{Unreadable};

    fn next(c: *Canonical) Error!?u21 {
        if (c.held) |cp| {
            c.held = null;
            return cp;
        }
        while (try c.decode()) |cp| {
            if (isSpace(cp)) {
                if (c.started) c.space = true;
                continue;
            }
            c.started = true;
            const folded = if (cp >= 'A' and cp <= 'Z') cp + ('a' - 'A') else cp;
            if (c.space) {
                c.space = false;
                c.held = folded;
                return ' ';
            }
            return folded;
        }
        return null;
    }

    fn isSpace(cp: u21) bool {
        return cp == ' ' or (cp >= 0x09 and cp <= 0x0d);
    }

    fn decode(c: *Canonical) Error!?u21 {
        if (c.i >= c.bytes.len) return null;
        const rest = c.bytes[c.i..];
        switch (c.tag) {
            0x0c => {
                const n = std.unicode.utf8ByteSequenceLength(rest[0]) catch return error.Unreadable;
                if (n > rest.len) return error.Unreadable;
                const cp = std.unicode.utf8Decode(rest[0..n]) catch return error.Unreadable;
                c.i += n;
                return cp;
            },
            0x13, 0x16, 0x1a => {
                if (rest[0] >= 0x80) return error.Unreadable;
                c.i += 1;
                return rest[0];
            },
            0x14 => {
                c.i += 1;
                return rest[0];
            },
            0x1e => {
                if (rest.len < 2) return error.Unreadable;
                const cp = std.mem.readInt(u16, rest[0..2], .big);
                if (cp >= 0xd800 and cp <= 0xdfff) return error.Unreadable;
                c.i += 2;
                return cp;
            },
            0x1c => {
                if (rest.len < 4) return error.Unreadable;
                const cp = std.mem.readInt(u32, rest[0..4], .big);
                if (cp > 0x10ffff or (cp >= 0xd800 and cp <= 0xdfff)) return error.Unreadable;
                c.i += 4;
                return @intCast(cp);
            },
            else => unreachable,
        }
    }
};

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

/// SET { SEQUENCE { OID 2.5.4.<attr>, <str_tag> value } }.
fn rdnFor(comptime attr: u8, comptime str_tag: u8, comptime v: []const u8) [11 + v.len]u8 {
    return [_]u8{ 0x31, 9 + v.len, 0x30, 7 + v.len, 0x06, 0x03, 0x55, 0x04, attr, str_tag, v.len } ++ v[0..v.len].*;
}

test "matchDirectory: RDN prefix, prepared string comparison, unreadable is unsupported" {
    const o = rdnFor(0x0a, 0x0c, "Evil Org");
    const cn = rdnFor(0x03, 0x0c, "leaf");
    try testing.expectEqual(Match.inside, matchDirectory(&(o ++ cn), &o));
    try testing.expectEqual(Match.inside, matchDirectory(&(o ++ cn), &(o ++ cn)));
    try testing.expectEqual(Match.outside, matchDirectory(&o, &(o ++ cn)));
    try testing.expectEqual(Match.outside, matchDirectory(&(cn ++ o), &o));
    try testing.expectEqual(Match.inside, matchDirectory(&o, ""));
    // Spellings of the same value.
    try testing.expectEqual(Match.inside, matchDirectory(&rdnFor(0x0a, 0x13, "EVIL ORG"), &o));
    try testing.expectEqual(Match.inside, matchDirectory(&rdnFor(0x0a, 0x16, "\tevil\n org "), &o));
    try testing.expectEqual(Match.inside, matchDirectory(&rdnFor(0x0a, 0x1c, "\x00\x00\x00E\x00\x00\x00v\x00\x00\x00i\x00\x00\x00l\x00\x00\x00 \x00\x00\x00O\x00\x00\x00r\x00\x00\x00g"), &o));
    // Not the same value: another word, another attribute type, inner space
    // removed, a non-ASCII letter in another case (no Unicode folding).
    try testing.expectEqual(Match.outside, matchDirectory(&rdnFor(0x0a, 0x0c, "Evil Orgs"), &o));
    try testing.expectEqual(Match.outside, matchDirectory(&rdnFor(0x0b, 0x0c, "Evil Org"), &o));
    try testing.expectEqual(Match.outside, matchDirectory(&rdnFor(0x0a, 0x0c, "EvilOrg"), &o));
    try testing.expectEqual(Match.outside, matchDirectory(&rdnFor(0x0a, 0x0c, "\xc3\xa9"), &rdnFor(0x0a, 0x0c, "\xc3\x89")));
    // A non-string value compares as encoded.
    const int_rdn = [_]u8{ 0x31, 0x0a, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x02, 0x01, 0x05 };
    try testing.expectEqual(Match.inside, matchDirectory(&int_rdn, &int_rdn));
    try testing.expectEqual(Match.outside, matchDirectory(&int_rdn, &rdnFor(0x0a, 0x0c, "\x05")));
    // A multi-valued RDN is a set: order does not matter, count does.
    const atv_o = o[2..];
    const atv_ou = rdnFor(0x0b, 0x0c, "Unit")[2..];
    const mv_a = [_]u8{ 0x31, atv_o.len + atv_ou.len } ++ atv_o.* ++ atv_ou.*;
    const mv_b = [_]u8{ 0x31, atv_o.len + atv_ou.len } ++ atv_ou.* ++ atv_o.*;
    try testing.expectEqual(Match.inside, matchDirectory(&mv_a, &mv_b));
    try testing.expectEqual(Match.outside, matchDirectory(&mv_a, &o));
    // Unreadable on either side.
    try testing.expectEqual(Match.unsupported, matchDirectory(&rdnFor(0x0a, 0x0c, "Evil\xffOrg"), &o));
    try testing.expectEqual(Match.unsupported, matchDirectory(&o, &rdnFor(0x0a, 0x0c, "Evil\xffOrg")));
    try testing.expectEqual(Match.unsupported, matchDirectory(&rdnFor(0x0a, 0x13, "Evil\x80"), &o));
    try testing.expectEqual(Match.unsupported, matchDirectory(&rdnFor(0x0a, 0x1e, "abc"), &o));
    try testing.expectEqual(Match.unsupported, matchDirectory(&rdnFor(0x0a, 0x1e, "\xd8\x00"), &o));
    try testing.expectEqual(Match.unsupported, matchDirectory(&rdnFor(0x0a, 0x1c, "\x00\x11\x00\x00"), &o));
    try testing.expectEqual(Match.unsupported, matchDirectory(o[0 .. o.len - 1], &o));
    try testing.expectEqual(Match.unsupported, matchDirectory(&o, o[2..]));
    // Different, but unreadable past the difference: still unsupported.
    try testing.expectEqual(Match.unsupported, matchDirectory(&rdnFor(0x0a, 0x0c, "Xvil Org\xff"), &o));
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
    // A context tag past [8] is no GeneralName CHOICE either.
    var tag9 = try GeneralNameIterator.init(&.{ 0x30, 0x03, 0x89, 0x01, 0x00 });
    try testing.expectError(error.CertificateFieldHasWrongDataType, tag9.next());
    // Bytes after the GeneralNames SEQUENCE.
    try testing.expectError(error.CertificateFieldHasInvalidLength, GeneralNameIterator.init(&.{ 0x30, 0x03, 0x82, 0x01, 'a', 0x00 }));
}
