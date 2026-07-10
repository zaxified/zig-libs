// SPDX-License-Identifier: MIT

//! dns — DNS resolver: RFC 1035 message codec + UDP/TCP/DoH transports +
//! forward (A/AAAA) and reverse (PTR) lookups. The codec decodes the common
//! record set — A/AAAA/PTR/CNAME/NS/MX/TXT/SOA (RFC 1035), SRV (RFC 2782),
//! CAA (RFC 8659) — plus EDNS(0) OPT; anything else surfaces as raw rdata.
//!
//! Layout mirrors the http module: this file owns the shared vocabulary and
//! the netaddr-powered helpers; `message.zig` is the pure, transport-agnostic
//! wire codec (offline golden-byte testable — the part that must be
//! bulletproof); `config.zig` parses /etc/resolv.conf + /etc/hosts and
//! implements search-list expansion; `Resolver.zig` is the blocking client
//! over `std.Io.net` (UDP with TC→TCP retry, TCP) and the sibling `http`
//! module (DoH, RFC 8484 wire + the common DoH-JSON variant via `std.json`).
//!
//! Why not std: `std.Io.net.HostName.lookup` is forward-only and opaque —
//! no PTR, no explicit server/transport control, no DoH.
//!
//! ```zig
//! var resolver = dns.Resolver.init(io, gpa, .{});
//! defer resolver.deinit();
//! const ips = try resolver.lookupIp("example.com");      // hosts + A/AAAA
//! var msg = try resolver.resolve("example.com", .mx);    // any record type
//! defer msg.deinit();
//! const names = try resolver.reverse(ip);                // PTR
//! ```

const std = @import("std");
const netaddr = @import("netaddr");

pub const meta = .{
    .platform = .any, // lookupIp's RFC 6724 ordering kicks in on Linux only
    .role = .client,
    .concurrency = .blocking, // every lookup blocks; one owner per Resolver
    .model_after = "Go net dnsclient + miekg/dns (codec) / c-ares; RFC 1035/2782/8659 (wire), RFC 8484 (DoH)",
    .deps = .{ "netaddr", "http", "std.json", "std.Io.net" },
};

/// Pure wire codec (encode query / decode response) — no I/O.
pub const message = @import("message.zig");

/// /etc/resolv.conf + /etc/hosts parsing and search-list logic — no I/O.
pub const config = @import("config.zig");

/// The blocking resolver over UDP/TCP/DoH. See `Resolver.init`.
pub const Resolver = @import("Resolver.zig");

// Codec vocabulary, re-exported for consumers.
pub const Type = message.Type;
pub const Class = message.Class;
pub const Rcode = message.Rcode;
pub const Header = message.Header;
pub const Question = message.Question;
pub const Record = message.Record;
pub const Message = message.Message;
pub const encodeQuery = message.encodeQuery;
pub const decode = message.decode;

// ── netaddr bridges ─────────────────────────────────────────────────────────

/// The address carried by an A/AAAA record, or null for any other type.
pub fn recordIp(record: Record) ?netaddr.Ip {
    return switch (record.data) {
        .a => |b| .{ .v4 = b },
        .aaaa => |b| .{ .v6 = b },
        else => null,
    };
}

/// Longest output of `reverseName` (v6 nibble form: 32×2 + "ip6.arpa").
pub const max_reverse_name_len = 72;

/// Build the reverse-lookup name for `ip`: `d.c.b.a.in-addr.arpa` for IPv4
/// (RFC 1035 §3.5) or the nibble form `…ip6.arpa` for IPv6 (RFC 3596 §2.5).
/// IPv4-mapped IPv6 addresses are looked up as IPv4, like Go's reverseaddr
/// and getnameinfo. Asserts `buf.len >= max_reverse_name_len`.
pub fn reverseName(ip: netaddr.Ip, buf: []u8) []const u8 {
    std.debug.assert(buf.len >= max_reverse_name_len);
    var w: std.Io.Writer = .fixed(buf);
    switch (ip.unmap()) {
        .v4 => |b| {
            var i: usize = 4;
            while (i > 0) {
                i -= 1;
                w.print("{d}.", .{b[i]}) catch unreachable;
            }
            w.writeAll("in-addr.arpa") catch unreachable;
        },
        .v6 => |b| {
            const hex = "0123456789abcdef";
            var i: usize = 16;
            while (i > 0) {
                i -= 1;
                w.writeByte(hex[b[i] & 0xf]) catch unreachable;
                w.writeByte('.') catch unreachable;
                w.writeByte(hex[b[i] >> 4]) catch unreachable;
                w.writeByte('.') catch unreachable;
            }
            w.writeAll("ip6.arpa") catch unreachable;
        },
    }
    return w.buffered();
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test {
    _ = message;
    _ = config;
    _ = Resolver;
}

test "reverseName: IPv4" {
    var buf: [max_reverse_name_len]u8 = undefined;
    try testing.expectEqualStrings(
        "8.8.8.8.in-addr.arpa",
        reverseName(netaddr.parseIp("8.8.8.8").?, &buf),
    );
    try testing.expectEqualStrings(
        "1.2.0.192.in-addr.arpa",
        reverseName(netaddr.parseIp("192.0.2.1").?, &buf),
    );
    try testing.expectEqualStrings(
        "255.255.255.255.in-addr.arpa",
        reverseName(netaddr.parseIp("255.255.255.255").?, &buf),
    );
}

test "reverseName: IPv6 nibble form (RFC 3596 example)" {
    var buf: [max_reverse_name_len]u8 = undefined;
    try testing.expectEqualStrings(
        "b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.0.0.0.0.1.2.3.4.ip6.arpa",
        reverseName(netaddr.parseIp("4321:0:1:2:3:4:567:89ab").?, &buf),
    );
    try testing.expectEqualStrings(
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
        reverseName(netaddr.parseIp("::1").?, &buf),
    );
}

test "reverseName: IPv4-mapped IPv6 goes to in-addr.arpa" {
    var buf: [max_reverse_name_len]u8 = undefined;
    try testing.expectEqualStrings(
        "4.4.8.8.in-addr.arpa",
        reverseName(netaddr.parseIp("::ffff:8.8.4.4").?, &buf),
    );
}

test "reverseName round-trips through the codec" {
    var buf: [max_reverse_name_len]u8 = undefined;
    const rev = reverseName(netaddr.parseIp("2001:db8::1").?, &buf);
    var qbuf: [message.max_query_len]u8 = undefined;
    const packet = try encodeQuery(&qbuf, rev, .ptr, .{ .id = 7 });
    var msg = try decode(testing.allocator, packet);
    defer msg.deinit();
    try testing.expectEqualStrings(rev, msg.questions[0].name);
    try testing.expectEqual(Type.ptr, msg.questions[0].ty);
}

test "recordIp extracts A/AAAA only" {
    const a: Record = .{
        .name = "x",
        .ty = .a,
        .class = .in,
        .ttl = 0,
        .data = .{ .a = .{ 192, 0, 2, 1 } },
    };
    try testing.expect(recordIp(a).?.eql(netaddr.parseIp("192.0.2.1").?));

    const aaaa: Record = .{
        .name = "x",
        .ty = .aaaa,
        .class = .in,
        .ttl = 0,
        .data = .{ .aaaa = netaddr.parseIp6("2001:db8::1").? },
    };
    try testing.expect(recordIp(aaaa).?.eql(netaddr.parseIp("2001:db8::1").?));

    const cname: Record = .{
        .name = "x",
        .ty = .cname,
        .class = .in,
        .ttl = 0,
        .data = .{ .cname = "y" },
    };
    try testing.expectEqual(@as(?netaddr.Ip, null), recordIp(cname));
}
