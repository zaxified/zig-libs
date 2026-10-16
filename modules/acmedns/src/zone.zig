// SPDX-License-Identifier: MIT

//! The DNS questions a DNS-01 solver asks before and after it publishes:
//! where a `_acme-challenge` name really lives (its CNAME chain), which zone
//! that is (the SOA walk), who serves the zone (NS → addresses), and whether
//! each of them already answers with the value (the propagation check). lego
//! (`challenge/dns01`: `FindZoneByFqdn`, `getChallengeFqdn`, the
//! authoritative-NS pre-check) and certmagic (`DNS01Solver.Wait`) ask the same.
//!
//! Names are dotted text without the trailing root dot, compared ASCII
//! case-insensitively. All queries go through `dns.Resolver`; the caller
//! supplies a recursive resolver for the walk, and the authoritative servers
//! are asked one by one with RD clear.

const std = @import("std");
const dns = @import("dns");
const netaddr = @import("netaddr");

pub const max_name_len = dns.message.max_name_text_len;

/// CNAME hops `followCname` takes before giving up (lego and Go stop at a
/// small constant too).
pub const max_cname_hops = 8;

pub const Error = dns.Resolver.Error || error{
    /// No suffix of the name answered with an SOA owned by itself.
    ZoneNotFound,
    /// The CNAME chain loops or is longer than `max_cname_hops`.
    CnameLoop,
};

/// Where TXT records for `name` must actually be published: `name` itself,
/// or the end of its CNAME chain — the delegation lego follows by default
/// (`_acme-challenge.example.org CNAME _acme-challenge.dns-provider.net`, or
/// acme-dns's `<uuid>.auth.example.net`). Asked of `r` (recursive), one hop
/// per query, so a resolver that flattens the chain is followed too.
pub fn followCname(r: *dns.Resolver, name: []const u8, out: *[max_name_len]u8) Error![]const u8 {
    var cur = try copyName(out, name);
    var seen: [max_cname_hops + 1][max_name_len]u8 = undefined;
    var seen_len: [max_cname_hops + 1]usize = undefined;
    var hops: usize = 0;
    while (true) {
        var msg = try r.query(cur, .cname);
        defer msg.deinit();
        var target: ?[]const u8 = null;
        for (msg.answers) |rec| {
            if (rec.class == .in and rec.data == .cname and eqlName(rec.name, cur)) {
                target = rec.data.cname;
                break;
            }
        }
        const t = target orelse return cur;
        @memcpy(seen[hops][0..cur.len], cur);
        seen_len[hops] = cur.len;
        hops += 1;
        if (hops > max_cname_hops) return error.CnameLoop;
        for (0..hops) |i| if (eqlName(seen[i][0..seen_len[i]], t)) return error.CnameLoop;
        cur = try copyName(out, t);
    }
}

/// The zone `fqdn` belongs to: the longest suffix of it (itself included)
/// for which `r` returns an SOA record owned by that very name in the answer
/// section. NXDOMAIN, NODATA and a CNAME (never at a zone apex) move on to
/// the parent. The root is never a candidate.
pub fn findZone(r: *dns.Resolver, fqdn: []const u8, out: *[max_name_len]u8) Error![]const u8 {
    var cand = trimDot(fqdn);
    while (cand.len != 0) {
        var msg = try r.query(cand, .soa);
        defer msg.deinit();
        if (msg.rcode() == .no_error) {
            for (msg.answers) |rec| {
                if (rec.class == .in and rec.data == .soa and eqlName(rec.name, cand)) return copyName(out, cand);
            }
        }
        const dot = std.mem.indexOfScalar(u8, cand, '.') orelse break;
        cand = cand[dot + 1 ..];
    }
    return error.ZoneNotFound;
}

/// The names of `zone`'s NS records, as `r` reports them. Caller frees with
/// `freeNames`.
pub fn nameservers(r: *dns.Resolver, gpa: std.mem.Allocator, zone: []const u8) Error![][]u8 {
    var msg = try r.query(zone, .ns);
    defer msg.deinit();
    var names: std.ArrayList([]u8) = .empty;
    errdefer freeNames(gpa, names.items);
    defer names.deinit(gpa);
    for (msg.answers) |rec| {
        if (rec.class == .in and rec.data == .ns and eqlName(rec.name, zone)) {
            try names.append(gpa, try gpa.dupe(u8, trimDot(rec.data.ns)));
        }
    }
    return names.toOwnedSlice(gpa);
}

pub fn freeNames(gpa: std.mem.Allocator, names: []const []u8) void {
    for (names) |n| gpa.free(n);
    gpa.free(names);
}

/// Does the server at `ip`:`port`, asked with RD clear, answer TXT `fqdn`
/// with a record whose concatenated strings equal `value`?
pub fn serverHasTxt(
    io: std.Io,
    gpa: std.mem.Allocator,
    ip: netaddr.Ip,
    port: u16,
    timeout_ms: u32,
    fqdn: []const u8,
    value: []const u8,
) Error!bool {
    return serverHasTxtRd(io, gpa, ip, port, timeout_ms, fqdn, value, false);
}

/// `serverHasTxt` with the RD bit chosen: set to ask a recursive resolver.
pub fn serverHasTxtRd(
    io: std.Io,
    gpa: std.mem.Allocator,
    ip: netaddr.Ip,
    port: u16,
    timeout_ms: u32,
    fqdn: []const u8,
    value: []const u8,
    recursion_desired: bool,
) Error!bool {
    var r = dns.Resolver.init(io, gpa, .{
        .servers = &.{ip},
        .port = port,
        .timeout_ms = timeout_ms,
        .attempts = 1,
        .use_hosts = false,
        .use_search = false,
        .recursion_desired = recursion_desired,
    });
    defer r.deinit();
    var msg = try r.query(fqdn, .txt);
    defer msg.deinit();
    return txtPresent(&msg, fqdn, value);
}

/// Does the server at `ip`:`port` (RD clear) answer TXT `fqdn` with any
/// record at all? (A cleanup check: nothing may be left behind.)
pub fn serverHasTxtAny(io: std.Io, gpa: std.mem.Allocator, ip: netaddr.Ip, port: u16, timeout_ms: u32, fqdn: []const u8) Error!bool {
    var r = dns.Resolver.init(io, gpa, .{
        .servers = &.{ip},
        .port = port,
        .timeout_ms = timeout_ms,
        .attempts = 1,
        .use_hosts = false,
        .use_search = false,
        .recursion_desired = false,
    });
    defer r.deinit();
    var msg = try r.query(fqdn, .txt);
    defer msg.deinit();
    for (msg.answers) |rec| {
        if (rec.class == .in and rec.data == .txt and eqlName(rec.name, fqdn)) return true;
    }
    return false;
}

/// Pure over a decoded reply: a TXT answer owned by `fqdn` carries `value`.
pub fn txtPresent(msg: *const dns.Message, fqdn: []const u8, value: []const u8) bool {
    for (msg.answers) |rec| {
        if (rec.class != .in or rec.data != .txt or !eqlName(rec.name, fqdn)) continue;
        if (txtEquals(rec.data.txt, value)) return true;
    }
    return false;
}

/// The character-strings, concatenated in wire order, equal `value`
/// (compared without allocating).
fn txtEquals(strings: []const []const u8, value: []const u8) bool {
    var at: usize = 0;
    for (strings) |s| {
        if (value.len - at < s.len) return false;
        if (!std.mem.eql(u8, value[at..][0..s.len], s)) return false;
        at += s.len;
    }
    return at == value.len;
}

pub fn eqlName(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(trimDot(a), trimDot(b));
}

pub fn trimDot(name: []const u8) []const u8 {
    return if (name.len > 0 and name[name.len - 1] == '.') name[0 .. name.len - 1] else name;
}

fn copyName(out: *[max_name_len]u8, name: []const u8) error{NameTooLong}![]const u8 {
    const n = trimDot(name);
    if (n.len > max_name_len) return error.NameTooLong;
    // `name` may already live in `out` (a CNAME target is copied over the
    // previous name): `copyForwards` handles the overlap.
    std.mem.copyForwards(u8, out[0..n.len], n);
    return out[0..n.len];
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "txtPresent: owner, class, split strings, partial values" {
    const recs = [_]dns.Record{
        .{ .name = "_acme-challenge.example.org", .ty = .txt, .class = .in, .ttl = 60, .data = .{ .txt = &.{ "abc", "def" } } },
        .{ .name = "other.example.org", .ty = .txt, .class = .in, .ttl = 60, .data = .{ .txt = &.{"xyz"} } },
        .{ .name = "_acme-challenge.example.org", .ty = .txt, .class = .ch, .ttl = 60, .data = .{ .txt = &.{"chaos"} } },
    };
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    const msg: dns.Message = .{ .arena = &arena, .header = .{}, .questions = &.{}, .answers = &recs, .authorities = &.{}, .additionals = &.{} };
    defer arena.deinit();
    try testing.expect(txtPresent(&msg, "_ACME-challenge.example.org.", "abcdef"));
    try testing.expect(!txtPresent(&msg, "_acme-challenge.example.org", "abcde"));
    try testing.expect(!txtPresent(&msg, "_acme-challenge.example.org", "abcdefg"));
    try testing.expect(!txtPresent(&msg, "_acme-challenge.example.org", "xyz"));
    try testing.expect(!txtPresent(&msg, "_acme-challenge.example.org", "chaos"));
    try testing.expect(txtPresent(&msg, "other.example.org", "xyz"));
}

test "copyName: a CNAME target copied over the name it came from" {
    var out: [max_name_len]u8 = undefined;
    const a = try copyName(&out, "_acme-challenge.example.org.");
    try testing.expectEqualStrings("_acme-challenge.example.org", a);
    const b = try copyName(&out, out[16..a.len]);
    try testing.expectEqualStrings("example.org", b);
    const long: [254]u8 = @splat('a');
    try testing.expectError(error.NameTooLong, copyName(&out, &long));
}
