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
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "RFC 1035 resolver — A/AAAA/PTR/CNAME/NS/MX/TXT/SOA/SRV/CAA over UDP/TCP + DoH",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{ .linux64, .linux32 },
    .platform = .any, // lookupIp's RFC 6724 ordering kicks in on Linux only
    .role = .client,
    .concurrency = .blocking, // every lookup blocks; one owner per Resolver
    .model_after = "Go net dnsclient + miekg/dns (codec) / c-ares; RFC 1035/2782/8659 (wire), RFC 8484 (DoH)",
    .deps = .{ "netaddr", "http" }, // also uses std.json, std.Io.net
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
pub const max_query_len = message.max_query_len;
pub const QueryOptions = message.QueryOptions;
pub const EncodeError = message.EncodeError;

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

pub const ReverseNameError = error{
    /// `buf.len < max_reverse_name_len`. Returned rather than asserted:
    /// `buf` is a caller-supplied buffer, and ReleaseFast compiles the
    /// assert out — the `std.Io.Writer.fixed` writes below stay memory-safe
    /// either way (they clamp to the buffer), but every one of them is
    /// `catch unreachable`, so a buffer too small to hold the result turned
    /// a recoverable "won't fit" into undefined behaviour in the build that
    /// ships.
    OutputTooSmall,
};

/// Build the reverse-lookup name for `ip`: `d.c.b.a.in-addr.arpa` for IPv4
/// (RFC 1035 §3.5) or the nibble form `…ip6.arpa` for IPv6 (RFC 3596 §2.5).
/// IPv4-mapped IPv6 addresses are looked up as IPv4, like Go's reverseaddr
/// and getnameinfo. `buf.len < max_reverse_name_len` is `error.OutputTooSmall`.
pub fn reverseName(ip: netaddr.Ip, buf: []u8) ReverseNameError![]const u8 {
    if (buf.len < max_reverse_name_len) return error.OutputTooSmall;
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
    _ = @import("goldens.zig");
}

test "reverseName: IPv4" {
    var buf: [max_reverse_name_len]u8 = undefined;
    try testing.expectEqualStrings(
        "8.8.8.8.in-addr.arpa",
        try reverseName(netaddr.parseIp("8.8.8.8").?, &buf),
    );
    try testing.expectEqualStrings(
        "1.2.0.192.in-addr.arpa",
        try reverseName(netaddr.parseIp("192.0.2.1").?, &buf),
    );
    try testing.expectEqualStrings(
        "255.255.255.255.in-addr.arpa",
        try reverseName(netaddr.parseIp("255.255.255.255").?, &buf),
    );
}

test "reverseName: IPv6 nibble form (RFC 3596 example)" {
    var buf: [max_reverse_name_len]u8 = undefined;
    try testing.expectEqualStrings(
        "b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.0.0.0.0.1.2.3.4.ip6.arpa",
        try reverseName(netaddr.parseIp("4321:0:1:2:3:4:567:89ab").?, &buf),
    );
    try testing.expectEqualStrings(
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
        try reverseName(netaddr.parseIp("::1").?, &buf),
    );
}

test "reverseName: IPv4-mapped IPv6 goes to in-addr.arpa" {
    var buf: [max_reverse_name_len]u8 = undefined;
    try testing.expectEqualStrings(
        "4.4.8.8.in-addr.arpa",
        try reverseName(netaddr.parseIp("::ffff:8.8.4.4").?, &buf),
    );
}

// reverseName used to guard buf.len with std.debug.assert; ReleaseFast
// compiles it out. The Writer.fixed writes inside stay memory-safe either
// way (they clamp to the buffer), but every one is `catch unreachable`, so
// a too-small buf turned a recoverable "won't fit" into undefined behaviour
// in the build that ships. Written in terms of max_reverse_name_len rather
// than a literal so it keeps measuring the mechanism if that bound moves.
test "reverseName: a buf one byte short of max_reverse_name_len is an error, not an assert" {
    var buf: [max_reverse_name_len]u8 = undefined;
    try testing.expectError(
        error.OutputTooSmall,
        reverseName(netaddr.parseIp("2001:db8::1").?, buf[0 .. max_reverse_name_len - 1]),
    );
    _ = try reverseName(netaddr.parseIp("2001:db8::1").?, buf[0..max_reverse_name_len]);
}

test "reverseName round-trips through the codec" {
    var buf: [max_reverse_name_len]u8 = undefined;
    const rev = try reverseName(netaddr.parseIp("2001:db8::1").?, &buf);
    var qbuf: [message.max_query_len]u8 = undefined;
    const packet = try encodeQuery(&qbuf, rev, .ptr, .{ .id = 7 });
    var msg = try decode(testing.allocator, packet);
    defer msg.deinit();
    try testing.expectEqualStrings(rev, msg.questions[0].name);
    try testing.expectEqual(Type.ptr, msg.questions[0].ty);
}

test "codec-only consumer never names the message submodule" {
    // max_query_len / QueryOptions / EncodeError reachable straight off the
    // root import — a size-sensitive codec consumer must not have to name
    // `dns.message` (which would put `Resolver`, and thus `http`, in reach).
    var buf: [max_query_len]u8 = undefined;
    const options: QueryOptions = .{ .id = 42, .edns_udp_size = null };
    const packet: []const u8 = try encodeQuery(&buf, "example.com", .a, options);
    try testing.expect(packet.len > 0 and packet.len <= max_query_len);

    // A too-long name (> 253 text chars, RFC 1035 §3.1) surfaces the
    // EncodeError variant through the root type.
    var long_name_buf: [300]u8 = undefined;
    @memset(&long_name_buf, 'a');
    const bad_result = encodeQuery(&buf, &long_name_buf, .a, .{});
    try testing.expectError(error.NameTooLong, bad_result);
    const err_value: EncodeError = error.NameTooLong;
    try testing.expectEqual(EncodeError.NameTooLong, err_value);
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
