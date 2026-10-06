// SPDX-License-Identifier: MIT

//! **External anchor for `config.zig`: what glibc did with the same files.**
//!
//! `testdata/config_oracle.zig` was taken by `tools/config_oracle.py` under
//! `unshare -rmn`: each resolv.conf / hosts fixture bind-mounted over the real
//! path, glibc asked through getaddrinfo / gethostbyaddr in a fresh process,
//! and every query it sent recorded by a fake DNS server. Here, offline:
//!
//! - **search list**: the candidates `NameIterator` yields over the parsed
//!   search list and ndots are the names glibc queried, in glibc's order;
//! - **servers and attempts**: `servers()` tried `attempts` times round is
//!   the sequence of servers glibc tried when every one answered SERVFAIL;
//! - **hosts**: `hostsIpsForName` per family and `hostsNameForIp` give what
//!   getaddrinfo and gethostbyaddr returned.
//!
//! `divergences` lists where this module deliberately follows Go's resolver
//! instead, each pinned to our side.

const std = @import("std");
const testing = std.testing;
const netaddr = @import("netaddr");
const config = @import("config.zig");
const rec = @import("testdata/config_oracle.zig");

fn ipText(a: std.mem.Allocator, ip: netaddr.Ip) ![]const u8 {
    var buf: [netaddr.max_ip_text_len]u8 = undefined;
    return a.dupe(u8, netaddr.formatIp(ip, &buf));
}

const Divergence = struct { fixture: []const u8, ours: []const []const u8, why: []const u8 };

/// Server sequences where the Resolver follows Go's `dnsconfig` rather than
/// glibc. Each is pinned to what this module does.
const divergences = [_]Divergence{
    .{
        .fixture = "no_nameserver",
        .ours = &.{ "127.0.0.1", "::1", "127.0.0.1", "::1" },
        .why = "no nameserver line: Resolver.serverList falls back to Go's 127.0.0.1 and ::1; glibc uses 127.0.0.1 alone",
    },
    .{
        .fixture = "attempts_junk",
        .ours = &.{ "127.0.0.1", "127.0.0.1" },
        .why = "attempts below 1: glibc then sends no query at all; Go keeps the default (2), and so does this module",
    },
    .{
        .fixture = "attempts_zero",
        .ours = &.{ "127.0.0.1", "127.0.0.1" },
        .why = "as attempts_junk",
    },
};

test "glibc oracle: the search-list candidates are the names glibc queried, in its order" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for (rec.resolv) |fx| {
        const conf = config.parseResolvConf(fx.text);
        for (fx.lookups) |lk| {
            var ours: std.ArrayList([]const u8) = .empty;
            var it = config.NameIterator.init(lk.name, conf.search(), conf.ndots);
            var buf: [256]u8 = undefined;
            while (it.next(&buf)) |cand| {
                // glibc's queries are logged without the root dot.
                const bare = if (cand.len > 1 and cand[cand.len - 1] == '.') cand[0 .. cand.len - 1] else cand;
                try ours.append(a, try a.dupe(u8, bare));
            }
            testing.expectEqual(lk.queries.len, ours.items.len) catch |e| {
                std.debug.print("{s} / {s}: glibc queried {d} names, ours {d}\n", .{ fx.name, lk.name, lk.queries.len, ours.items.len });
                for (ours.items) |o| std.debug.print("  ours: {s}\n", .{o});
                return e;
            };
            for (lk.queries, ours.items) |want, got| testing.expectEqualStrings(want, got) catch |e| {
                std.debug.print("{s} / {s}\n", .{ fx.name, lk.name });
                return e;
            };
        }
    }
}

test "glibc oracle: nameservers and attempts are the servers glibc tried, in its order" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var listed: usize = 0;
    for (rec.servers) |fx| {
        const conf = config.parseResolvConf(fx.text);
        var ours: std.ArrayList([]const u8) = .empty;
        const fallback = [_]netaddr.Ip{ .{ .v4 = .{ 127, 0, 0, 1 } }, .{ .v6 = [_]u8{0} ** 15 ++ [_]u8{1} } };
        const servers = if (conf.servers().len > 0) conf.servers() else &fallback;
        for (0..conf.attempts) |_| for (servers) |s| try ours.append(a, try ipText(a, s));

        const known = for (divergences) |d| {
            if (std.mem.eql(u8, d.fixture, fx.name)) break d;
        } else null;
        const want = if (known) |d| d.ours else fx.tried;
        if (known != null) listed += 1;
        testing.expectEqual(want.len, ours.items.len) catch |e| {
            std.debug.print("{s}: expected {d} tries, ours {d}\n", .{ fx.name, want.len, ours.items.len });
            return e;
        };
        for (want, ours.items) |w, o| try testing.expectEqualStrings(w, o);
    }
    try testing.expectEqual(divergences.len, listed);
}

test "glibc oracle: hosts lookups return what getaddrinfo and gethostbyaddr returned" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    inline for (.{ .{ rec.hosts_v4, .v4 }, .{ rec.hosts_v6, .v6 } }) |pair| {
        for (pair[0]) |ans| {
            var out: [16]netaddr.Ip = undefined;
            const n = config.hostsIpsForName(rec.hosts_text, ans.name, &out);
            var ours: std.ArrayList([]const u8) = .empty;
            for (out[0..n]) |ip| if (ip == pair[1]) try ours.append(a, try ipText(a, ip));
            const want: []const []const u8 = ans.addrs orelse &.{};
            testing.expectEqual(want.len, ours.items.len) catch |e| {
                std.debug.print("hosts {s} ({s}): glibc {d} addresses, ours {d}\n", .{ ans.name, @tagName(pair[1]), want.len, ours.items.len });
                return e;
            };
            for (want, ours.items) |w, o| try testing.expectEqualStrings(w, o);
        }
    }
    for (rec.hosts_reverse) |r| {
        var buf: [256]u8 = undefined;
        const got = config.hostsNameForIp(rec.hosts_text, netaddr.parseIp(r.addr).?, &buf);
        if (r.name) |want| {
            try testing.expectEqualStrings(want, got orelse return error.TestUnexpectedResult);
        } else try testing.expectEqual(@as(?[]const u8, null), got);
    }
}
