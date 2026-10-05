// SPDX-License-Identifier: MIT

//! OFFLINE anchor for the parse/format/prefix core: glibc's inet_pton and
//! inet_ntop and Python's ipaddress, both black boxes, taken by
//! `tools/parse_oracle.py` into `parse_vectors.zig` and replayed here with no
//! Python at test time. Only their answers were recorded.
//!
//! glibc decides what is an address (Python is the tiebreaker where the two
//! differ) and how it is printed (RFC 5952; Python again where glibc and
//! RFC 5952 part ways); Python alone answers prefixes, range summarization and
//! prefix-set collapse. Every place this module answers differently is listed
//! below with the judgement; a differing case without an entry fails, and so
//! does an entry whose case has started to agree.

const std = @import("std");
const testing = std.testing;
const netaddr = @import("root.zig");
const vectors = @import("parse_vectors.zig");

const Ip = netaddr.Ip;

const Divergence = struct { text: []const u8, why: []const u8 };

/// Literals whose PARSE verdict differs from glibc's.
const parse_divergences = [_]Divergence{};

/// The one class of address whose canonical TEXT differs from glibc's
/// inet_ntop: IPv4-compatible `::a.b.c.d` (first 96 bits zero, group 6 not
/// zero). glibc prints it dotted (`::1.2.3.4`); Python, Go's netip and this
/// module print hex (`::102:304`). RFC 5952 §5 recommends mixed notation only
/// where a well-known prefix marks the embedded IPv4; ::/96 was deprecated by
/// RFC 4291 §2.5.5.1, and IPv4-mapped (`::ffff:1.2.3.4`) stays dotted in all
/// four. Two of three foreign printers side with us.
fn glibcPrintsDotted(a: Ip) bool {
    const b = switch (a) {
        .v4 => return false,
        .v6 => |b| b,
    };
    return std.mem.allEqual(u8, b[0..12], 0) and (b[12] | b[13]) != 0;
}

/// Prefix texts Python reads and this module refuses. Every one is a Python
/// extension of CIDR syntax; Go's netip.ParsePrefix (asked 2026-10-05, go1.26)
/// refuses each of them as we do.
const prefix_divergences = [_]Divergence{
    .{ .text = "1.2.3.4", .why = "no '/': Python reads a bare address as /32; Go and we require CIDR notation (parseIp reads addresses)" },
    .{ .text = "::00", .why = "as \"1.2.3.4\": a bare address, read by Python as ::/128" },
    .{ .text = "1.2.3.4/08", .why = "a leading zero in the length: Python accepts it; Go and we refuse it, like every other numeric field here" },
    .{ .text = "2001:db8::/064", .why = "as 1.2.3.4/08" },
    .{ .text = "1.2.3.4/00", .why = "as 1.2.3.4/08" },
    .{ .text = "::/00", .why = "as 1.2.3.4/08" },
    .{ .text = "1.2.3.4/255.255.255.0", .why = "a netmask instead of a length: a Python extension; Go and we refuse it" },
    .{ .text = "1.2.3.4/0.0.0.255", .why = "a hostmask instead of a length: a Python extension; Go and we refuse it" },
    .{ .text = "fe80::1%eth0/64", .why = "a zone in a prefix: Python drops it; Go and we refuse it (zones are out of scope by SPEC)" },
};

fn hexBytes(comptime n: usize, hex: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

fn glibcParse(l: vectors.Literal) ?Ip {
    if (l.v4) |h| return .{ .v4 = hexBytes(4, h) };
    if (l.v6) |h| return .{ .v6 = hexBytes(16, h) };
    return null;
}

fn sameOpt(a: ?Ip, b: ?Ip) bool {
    if (a == null or b == null) return a == null and b == null;
    return a.?.eql(b.?);
}

const Hits = struct {
    seen: []bool,
    fn listed(h: Hits, table: []const Divergence, text: []const u8) bool {
        for (table, 0..) |d, i| if (std.mem.eql(u8, d.text, text)) {
            h.seen[i] = true;
            return true;
        };
        return false;
    }
    fn stale(h: Hits, table: []const Divergence) usize {
        var n: usize = 0;
        for (table, h.seen) |d, s| if (!s) {
            std.debug.print("divergence {s} no longer differs: delete it\n", .{d.text});
            n += 1;
        };
        return n;
    }
};

test "parse oracle: what is an address, as glibc inet_pton decides" {
    var seen = [_]bool{false} ** parse_divergences.len;
    const h: Hits = .{ .seen = &seen };
    var bad: usize = 0;
    for (vectors.literals) |l| {
        const ours = netaddr.parseIp(l.text);
        if (sameOpt(ours, glibcParse(l))) continue;
        if (h.listed(&parse_divergences, l.text)) continue;
        bad += 1;
        std.debug.print("parse {s}: glibc {?s}/{?s}, python {?s}, ours {s}\n", .{
            l.text, l.v4, l.v6, l.py, if (ours == null) "refused" else "accepted",
        });
    }
    bad += h.stale(&parse_divergences);
    try testing.expectEqual(@as(usize, 0), bad);
}

test "parse oracle: canonical text, as glibc inet_ntop prints it" {
    var bad: usize = 0;
    var dotted: usize = 0;
    for (vectors.literals) |l| {
        const addr = glibcParse(l) orelse continue;
        var buf: [netaddr.max_ip_text_len]u8 = undefined;
        const ours = netaddr.formatIp(addr, &buf);
        if (glibcPrintsDotted(addr)) {
            // The divergence must be exactly that: glibc dotted, we as Python.
            dotted += 1;
            try testing.expect(!std.mem.eql(u8, ours, l.ntop.?));
            try testing.expectEqualStrings(l.py.?, ours);
            continue;
        }
        if (std.mem.eql(u8, ours, l.ntop.?)) continue;
        bad += 1;
        std.debug.print("format {s}: glibc {s}, python {?s}, ours {s}\n", .{ l.text, l.ntop.?, l.py, ours });
    }
    try testing.expectEqual(@as(usize, 0), bad);
    try testing.expect(dotted > 0);
}

test "parse oracle: prefixes, as Python ip_network(strict=False) reads them" {
    var seen = [_]bool{false} ** prefix_divergences.len;
    const h: Hits = .{ .seen = &seen };
    var bad: usize = 0;
    for (vectors.prefixes) |c| {
        var buf: [netaddr.max_prefix_text_len]u8 = undefined;
        const ours: ?[]const u8 = if (netaddr.parsePrefix(c.text)) |p| netaddr.formatPrefix(p.masked(), &buf) else null;
        const agree = if (ours == null or c.py == null) ours == null and c.py == null else std.mem.eql(u8, ours.?, c.py.?);
        if (agree) continue;
        if (h.listed(&prefix_divergences, c.text)) continue;
        bad += 1;
        std.debug.print("prefix {s}: python {?s}, ours {?s}\n", .{ c.text, c.py, ours });
    }
    bad += h.stale(&prefix_divergences);
    try testing.expectEqual(@as(usize, 0), bad);
}

fn expectPrefixTexts(got: []const netaddr.Prefix, want: []const []const u8) !void {
    try testing.expectEqual(want.len, got.len);
    for (got, want) |p, w| {
        var buf: [netaddr.max_prefix_text_len]u8 = undefined;
        try testing.expectEqualStrings(w, netaddr.formatPrefix(p, &buf));
    }
}

test "parse oracle: summarize as Python summarize_address_range" {
    for (vectors.ranges) |c| {
        const got = try netaddr.summarize(testing.allocator, .{ .from = netaddr.parseIp(c.from).?, .to = netaddr.parseIp(c.to).? });
        defer testing.allocator.free(got);
        expectPrefixTexts(got, c.out) catch |e| {
            std.debug.print("summarize {s} .. {s}\n", .{ c.from, c.to });
            return e;
        };
    }
}

test "parse oracle: mergePrefixes as Python collapse_addresses" {
    var in: [16]netaddr.Prefix = undefined;
    for (vectors.merges) |c| {
        for (c.in, 0..) |t, i| in[i] = netaddr.parsePrefix(t).?;
        const got = try netaddr.mergePrefixes(testing.allocator, in[0..c.in.len]);
        defer testing.allocator.free(got);
        expectPrefixTexts(got, c.out) catch |e| {
            std.debug.print("merge {any}\n", .{c.in});
            return e;
        };
    }
}
