// SPDX-License-Identifier: MIT

//! System resolver configuration — /etc/resolv.conf and /etc/hosts parsing,
//! plus the search-list candidate iterator. Pure string logic (no I/O), so
//! everything here is unit-testable on fixtures.
//!
//! Semantics mirror glibc's resolver and Go's `net/dnsconfig_unix.go` /
//! `net/dnsclient_unix.go` (`conf.nameList`): MAXNS=3 nameservers, MAXDNSRCH=6
//! search domains, last `search`/`domain` directive wins, glibc option caps
//! (ndots ≤ 15, timeout ≤ 30, attempts ≤ 5).

const std = @import("std");
const netaddr = @import("netaddr");
const message = @import("message.zig");

// ── /etc/resolv.conf ────────────────────────────────────────────────────────

/// glibc MAXNS.
pub const max_nameservers = 3;
/// glibc MAXDNSRCH.
pub const max_search = 6;

pub const ResolvConf = struct {
    servers_buf: [max_nameservers]netaddr.Ip = undefined,
    nservers: usize = 0,
    /// Slices into the parsed text — keep the source buffer alive.
    search_buf: [max_search][]const u8 = undefined,
    nsearch: usize = 0,
    ndots: u8 = 1,
    /// Per-attempt timeout, seconds (`options timeout:n`).
    timeout_s: u8 = 5,
    attempts: u8 = 2,

    pub fn servers(c: *const ResolvConf) []const netaddr.Ip {
        return c.servers_buf[0..c.nservers];
    }

    pub fn search(c: *const ResolvConf) []const []const u8 {
        return c.search_buf[0..c.nsearch];
    }
};

/// Parse resolv.conf text. Never fails: unknown directives and malformed
/// values are skipped, missing directives keep glibc defaults. Search-domain
/// slices point into `content`.
pub fn parseResolvConf(content: []const u8) ResolvConf {
    var conf: ResolvConf = .{};
    var lines = std.mem.tokenizeAny(u8, content, "\r\n");
    while (lines.next()) |whole_line| {
        const line = whole_line[0 .. std.mem.indexOfAny(u8, whole_line, "#;") orelse whole_line.len];
        var words = std.mem.tokenizeAny(u8, line, " \t");
        const key = words.next() orelse continue;
        if (std.mem.eql(u8, key, "nameserver")) {
            const ip_text = words.next() orelse continue;
            const ip = parseIpMaybeZone(ip_text) orelse continue;
            if (conf.nservers < max_nameservers) {
                conf.servers_buf[conf.nservers] = ip;
                conf.nservers += 1;
            }
        } else if (std.mem.eql(u8, key, "search") or std.mem.eql(u8, key, "domain")) {
            conf.nsearch = 0; // the last directive wins (glibc/Go)
            while (words.next()) |raw| {
                if (conf.nsearch == max_search) break;
                var domain = raw;
                if (domain.len > 1 and domain[domain.len - 1] == '.')
                    domain = domain[0 .. domain.len - 1];
                if (domain.len == 0 or std.mem.eql(u8, domain, ".")) continue;
                conf.search_buf[conf.nsearch] = domain;
                conf.nsearch += 1;
            }
        } else if (std.mem.eql(u8, key, "options")) {
            while (words.next()) |opt| {
                if (std.mem.startsWith(u8, opt, "ndots:")) {
                    conf.ndots = parseCapped(opt["ndots:".len..], 15) orelse conf.ndots;
                } else if (std.mem.startsWith(u8, opt, "timeout:")) {
                    conf.timeout_s = parseCapped(opt["timeout:".len..], 30) orelse conf.timeout_s;
                } else if (std.mem.startsWith(u8, opt, "attempts:")) {
                    conf.attempts = parseCapped(opt["attempts:".len..], 5) orelse conf.attempts;
                }
            }
        }
    }
    return conf;
}

/// Parse a small decimal with a glibc-style upper cap; null on junk.
fn parseCapped(text: []const u8, cap: u8) ?u8 {
    const v = std.fmt.parseInt(u8, text, 10) catch return null;
    return @min(v, cap);
}

/// Parse an IP literal, tolerating a `%zone` suffix (dropped — routing scope
/// is out of scope here, matching the seed).
fn parseIpMaybeZone(text: []const u8) ?netaddr.Ip {
    const bare = text[0 .. std.mem.indexOfScalar(u8, text, '%') orelse text.len];
    return netaddr.parseIp(bare);
}

// ── /etc/hosts ──────────────────────────────────────────────────────────────

/// Reverse lookup in hosts-file text: the first (canonical) hostname of the
/// first entry whose address equals `ip` (IPv4-mapped compared as IPv4), or
/// null. The name is copied into `out`.
pub fn hostsNameForIp(content: []const u8, ip: netaddr.Ip, out: []u8) ?[]const u8 {
    const want = ip.unmap();
    var lines = std.mem.tokenizeAny(u8, content, "\r\n");
    while (lines.next()) |whole_line| {
        const line = whole_line[0 .. std.mem.indexOfScalar(u8, whole_line, '#') orelse whole_line.len];
        var words = std.mem.tokenizeAny(u8, line, " \t");
        const ip_text = words.next() orelse continue;
        const entry_ip = parseIpMaybeZone(ip_text) orelse continue;
        if (!entry_ip.unmap().eql(want)) continue;
        const name = words.next() orelse continue;
        if (name.len > out.len) continue;
        @memcpy(out[0..name.len], name);
        return out[0..name.len];
    }
    return null;
}

/// Forward lookup in hosts-file text: collect the address of every entry
/// whose canonical name or any alias equals `name` (ASCII case-insensitive,
/// one trailing dot on `name` ignored). Returns how many were written to
/// `out` (extra matches beyond `out.len` are dropped).
pub fn hostsIpsForName(content: []const u8, name: []const u8, out: []netaddr.Ip) usize {
    var want = name;
    if (want.len > 1 and want[want.len - 1] == '.') want = want[0 .. want.len - 1];
    var n: usize = 0;
    var lines = std.mem.tokenizeAny(u8, content, "\r\n");
    while (lines.next()) |whole_line| {
        const line = whole_line[0 .. std.mem.indexOfScalar(u8, whole_line, '#') orelse whole_line.len];
        var words = std.mem.tokenizeAny(u8, line, " \t");
        const ip_text = words.next() orelse continue;
        const entry_ip = parseIpMaybeZone(ip_text) orelse continue;
        while (words.next()) |host| {
            if (!std.ascii.eqlIgnoreCase(host, want)) continue;
            if (n < out.len) {
                out[n] = entry_ip;
                n += 1;
            }
            break;
        }
    }
    return n;
}

// ── search-list expansion ───────────────────────────────────────────────────

/// Yields the fully-qualified name candidates to try for a query, in order —
/// Go `conf.nameList` semantics:
/// - a rooted name (trailing dot) is tried verbatim and alone;
/// - a name with at least `ndots` dots is tried bare first, then with each
///   search domain appended;
/// - otherwise search domains come first and the bare name last.
/// Candidates longer than 253 chars are skipped.
pub const NameIterator = struct {
    name: []const u8,
    search: []const []const u8,
    ndots: u8,
    index: usize = 0,

    pub fn init(name: []const u8, search: []const []const u8, ndots: u8) NameIterator {
        return .{ .name = name, .search = search, .ndots = ndots };
    }

    /// The next candidate, or null when exhausted. Composed candidates are
    /// built in `buf` (needs `message.max_name_text_len` bytes); the bare
    /// name is returned as-is.
    pub fn next(it: *NameIterator, buf: []u8) ?[]const u8 {
        if (it.name.len == 0) return null;
        if (it.name[it.name.len - 1] == '.') { // rooted: verbatim, once
            if (it.index != 0) return null;
            it.index = 1;
            return if (it.name.len <= message.max_name_text_len + 1) it.name else null;
        }
        const dots = std.mem.count(u8, it.name, ".");
        const bare_first = dots >= it.ndots;
        const total = it.search.len + 1;
        while (it.index < total) {
            const i = it.index;
            it.index += 1;
            const bare_slot: usize = if (bare_first) 0 else total - 1;
            if (i == bare_slot) {
                if (it.name.len <= message.max_name_text_len) return it.name;
                continue;
            }
            const domain = it.search[if (bare_first) i - 1 else i];
            const need = it.name.len + 1 + domain.len;
            if (need > message.max_name_text_len or need > buf.len) continue;
            @memcpy(buf[0..it.name.len], it.name);
            buf[it.name.len] = '.';
            @memcpy(buf[it.name.len + 1 ..][0..domain.len], domain);
            return buf[0..need];
        }
        return null;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

const resolv_fixture =
    "# a comment\n" ++
    "nameserver 192.0.2.53   ; trailing comment\n" ++
    "nameserver 2001:db8::53\n" ++
    "nameserver fe80::1%eth0\n" ++
    "nameserver 198.51.100.1\n" ++ // 4th — beyond MAXNS, dropped
    "nameserver not-an-ip\n" ++
    "domain old.example\n" ++
    "search corp.example sub.corp.example legacy.example.\n" ++
    "options ndots:2 timeout:7 attempts:3 rotate\n" ++
    "sortlist 130.155.160.0/255.255.240.0\n" ++
    "unknown directive\n";

test "parseResolvConf: fixture" {
    const conf = parseResolvConf(resolv_fixture);

    try testing.expectEqual(@as(usize, 3), conf.nservers);
    try testing.expect(conf.servers()[0].eql(netaddr.parseIp("192.0.2.53").?));
    try testing.expect(conf.servers()[1].eql(netaddr.parseIp("2001:db8::53").?));
    try testing.expect(conf.servers()[2].eql(netaddr.parseIp("fe80::1").?)); // zone stripped

    // "search" overrode "domain"; trailing dot normalized away.
    try testing.expectEqual(@as(usize, 3), conf.nsearch);
    try testing.expectEqualStrings("corp.example", conf.search()[0]);
    try testing.expectEqualStrings("sub.corp.example", conf.search()[1]);
    try testing.expectEqualStrings("legacy.example", conf.search()[2]);

    try testing.expectEqual(@as(u8, 2), conf.ndots);
    try testing.expectEqual(@as(u8, 7), conf.timeout_s);
    try testing.expectEqual(@as(u8, 3), conf.attempts);
}

test "parseResolvConf: defaults on empty/garbage input" {
    for ([_][]const u8{ "", "\n\n", "# only comments\n", "nameserver\n" }) |src| {
        const conf = parseResolvConf(src);
        try testing.expectEqual(@as(usize, 0), conf.nservers);
        try testing.expectEqual(@as(usize, 0), conf.nsearch);
        try testing.expectEqual(@as(u8, 1), conf.ndots);
        try testing.expectEqual(@as(u8, 5), conf.timeout_s);
        try testing.expectEqual(@as(u8, 2), conf.attempts);
    }
}

test "parseResolvConf: glibc option caps" {
    const conf = parseResolvConf("options ndots:99 timeout:99 attempts:99\n");
    try testing.expectEqual(@as(u8, 15), conf.ndots);
    try testing.expectEqual(@as(u8, 30), conf.timeout_s);
    try testing.expectEqual(@as(u8, 5), conf.attempts);
}

const hosts_fixture =
    "# /etc/hosts fixture\n" ++
    "127.0.0.1\tlocalhost\n" ++
    "::1\t\tlocalhost ip6-localhost ip6-loopback\n" ++
    "192.0.2.10\tGateway.Example gw   # comment\n" ++
    "192.0.2.11\tfileserver files\n" ++
    "2001:db8::11\tfileserver\n" ++
    "not-an-ip\tjunk\n" ++
    "192.0.2.12\n"; // entry with no names

test "hostsNameForIp: fixture" {
    var buf: [255]u8 = undefined;
    try testing.expectEqualStrings(
        "localhost",
        hostsNameForIp(hosts_fixture, netaddr.parseIp("127.0.0.1").?, &buf).?,
    );
    try testing.expectEqualStrings(
        "Gateway.Example",
        hostsNameForIp(hosts_fixture, netaddr.parseIp("192.0.2.10").?, &buf).?,
    );
    // IPv4-mapped query matches the plain v4 entry.
    try testing.expectEqualStrings(
        "Gateway.Example",
        hostsNameForIp(hosts_fixture, netaddr.parseIp("::ffff:192.0.2.10").?, &buf).?,
    );
    try testing.expectEqualStrings(
        "localhost",
        hostsNameForIp(hosts_fixture, netaddr.parseIp("::1").?, &buf).?,
    );
    try testing.expect(hostsNameForIp(hosts_fixture, netaddr.parseIp("203.0.113.1").?, &buf) == null);
    // The nameless entry must not match anything.
    try testing.expect(hostsNameForIp(hosts_fixture, netaddr.parseIp("192.0.2.12").?, &buf) == null);
}

test "hostsIpsForName: fixture" {
    var ips: [8]netaddr.Ip = undefined;

    // Canonical name across two families.
    try testing.expectEqual(@as(usize, 2), hostsIpsForName(hosts_fixture, "fileserver", &ips));
    try testing.expect(ips[0].eql(netaddr.parseIp("192.0.2.11").?));
    try testing.expect(ips[1].eql(netaddr.parseIp("2001:db8::11").?));

    // Alias matches; case-insensitive; trailing dot tolerated.
    try testing.expectEqual(@as(usize, 1), hostsIpsForName(hosts_fixture, "GW", &ips));
    try testing.expectEqual(@as(usize, 1), hostsIpsForName(hosts_fixture, "gateway.example.", &ips));
    try testing.expectEqual(@as(usize, 2), hostsIpsForName(hosts_fixture, "LOCALHOST", &ips));

    try testing.expectEqual(@as(usize, 0), hostsIpsForName(hosts_fixture, "nowhere", &ips));

    // Output cap respected.
    var one: [1]netaddr.Ip = undefined;
    try testing.expectEqual(@as(usize, 1), hostsIpsForName(hosts_fixture, "fileserver", &one));
}

fn expectCandidates(name: []const u8, search: []const []const u8, ndots: u8, expected: []const []const u8) !void {
    var it = NameIterator.init(name, search, ndots);
    var buf: [message.max_name_text_len]u8 = undefined;
    for (expected) |want| {
        const got = it.next(&buf) orelse return error.TestUnexpectedResult;
        try testing.expectEqualStrings(want, got);
    }
    try testing.expectEqual(@as(?[]const u8, null), it.next(&buf));
}

test "NameIterator: Go conf.nameList semantics" {
    const search = [_][]const u8{ "corp.example", "example" };

    // Rooted: verbatim, alone.
    try expectCandidates("host.example.com.", &search, 1, &.{"host.example.com."});

    // dots >= ndots: bare first, then search.
    try expectCandidates("host.example.com", &search, 1, &.{
        "host.example.com", "host.example.com.corp.example", "host.example.com.example",
    });

    // dots < ndots: search first, bare last.
    try expectCandidates("myhost", &search, 1, &.{
        "myhost.corp.example", "myhost.example", "myhost",
    });

    // ndots boundary: exactly ndots dots counts as "has ndots".
    try expectCandidates("a.b", &search, 1, &.{ "a.b", "a.b.corp.example", "a.b.example" });
    try expectCandidates("a.b", &search, 2, &.{ "a.b.corp.example", "a.b.example", "a.b" });

    // No search list: just the bare name.
    try expectCandidates("myhost", &.{}, 1, &.{"myhost"});

    // Empty name: nothing.
    try expectCandidates("", &search, 1, &.{});
}

test "NameIterator: over-long candidates are skipped" {
    const long_domain = "d" ** 250;
    const search = [_][]const u8{ long_domain, "ok.example" };
    // "name." + 250 chars > 253 → skipped; the short domain and bare survive.
    try expectCandidates("myhost", &search, 1, &.{ "myhost.ok.example", "myhost" });
}
