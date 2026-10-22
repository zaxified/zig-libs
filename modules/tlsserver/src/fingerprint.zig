// SPDX-License-Identifier: MIT

//! tlsserver.fingerprint — JA4, the TLS client fingerprint of a ClientHello
//! (FoxIO, `technical_details/JA4.md`; JA4 itself is BSD-3-Clause — the
//! other JA4+ methods are under the FoxIO License and are not here). For
//! bot and abuse detection: the same client software gives the same
//! fingerprint whatever it connects to, and the extension order (which
//! Chrome randomises) does not count.
//!
//! `a_b_c`, 36 characters:
//!
//! - **a** (10): `t` (TCP) or `q` (QUIC); the version — the highest of
//!   `supported_versions`, else `legacy_version` — as `13`, `12`, `11`,
//!   `10`, `s3`, `s2` (DTLS `d1` `d2` `d3`), `00` if unknown; `d` with SNI,
//!   `i` without; the number of cipher suites and of extensions, two digits
//!   each, at most 99; the first and last character of the first ALPN
//!   value (`00` without one; a first or last octet that is not ASCII
//!   alphanumeric: the first and last digit of the value in hex);
//! - **b** (12): the first 12 hex digits of SHA-256 over the cipher suites
//!   as 4-digit lowercase hex, sorted, comma-separated (`000000000000`
//!   without any);
//! - **c** (12): the same over the extension types sorted, without SNI (0)
//!   and ALPN (16), then `_` and the `signature_algorithms` in their order
//!   (no `_` without them); `000000000000` when no extension is left.
//!
//! GREASE values (RFC 8701, `0x?a?a` with equal octets) are left out
//! everywhere. A ClientHello with more than `max_entries` cipher suites or
//! extensions has no fingerprint here (no real client sends that many).

const std = @import("std");
const hello = @import("hello.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Transport = enum { tcp, quic };

pub const ja4_len = 36;
pub const max_entries = 512;

pub const Error = error{TooManyEntries};

/// RFC 8701 GREASE: 0x0a0a, 0x1a1a, …, 0xfafa.
pub fn isGrease(v: u16) bool {
    return (v & 0x0f0f) == 0x0a0a and (v >> 8) == (v & 0xff);
}

/// The JA4 fingerprint of `ch` (see the file comment).
pub fn ja4(ch: *const hello.ClientHello, transport: Transport, out: *[ja4_len]u8) Error!void {
    var ciphers: [max_entries]u16 = undefined;
    var n_ciphers: usize = 0;
    var cs = ch.cipherSuites();
    while (cs.next()) |c| {
        if (isGrease(c)) continue;
        if (n_ciphers == max_entries) return error.TooManyEntries;
        ciphers[n_ciphers] = c;
        n_ciphers += 1;
    }
    var exts: [max_entries]u16 = undefined;
    var n_exts: usize = 0;
    var n_counted: usize = 0;
    var rest = ch.extensions_raw;
    // `parseClientHello` checked the block: every header and length fits.
    while (rest.len >= 4) {
        const t = std.mem.readInt(u16, rest[0..2], .big);
        const len = std.mem.readInt(u16, rest[2..4], .big);
        rest = rest[4 + @as(usize, len) ..];
        if (isGrease(t)) continue;
        n_counted += 1;
        if (t == @backingInt(hello.ExtensionType.server_name) or t == @backingInt(hello.ExtensionType.application_layer_protocol_negotiation)) continue;
        if (n_exts == max_entries) return error.TooManyEntries;
        exts[n_exts] = t;
        n_exts += 1;
    }

    out[0] = if (transport == .quic) 'q' else 't';
    @memcpy(out[1..3], versionCode(ch));
    out[3] = if (ch.server_name != null) 'd' else 'i';
    twoDigits(out[4..6], n_ciphers);
    twoDigits(out[6..8], n_counted);
    alpnCode(ch, out[8..10]);
    out[10] = '_';

    std.mem.sort(u16, ciphers[0..n_ciphers], {}, std.sort.asc(u16));
    if (n_ciphers == 0) out[11..23].* = @splat('0') else {
        var h: Sha256 = .init(.{});
        hexList(&h, ciphers[0..n_ciphers]);
        truncatedHex(&h, out[11..23]);
    }
    out[23] = '_';

    std.mem.sort(u16, exts[0..n_exts], {}, std.sort.asc(u16));
    if (n_exts == 0) out[24..36].* = @splat('0') else {
        var h: Sha256 = .init(.{});
        hexList(&h, exts[0..n_exts]);
        if (ch.signatureAlgorithms()) |algs| {
            h.update("_");
            var it = algs;
            var first = true;
            while (it.next()) |a| {
                if (isGrease(a)) continue;
                if (!first) h.update(",");
                first = false;
                h.update(&hex4(a));
            }
        }
        truncatedHex(&h, out[24..36]);
    }
}

fn versionCode(ch: *const hello.ClientHello) *const [2]u8 {
    var v: u16 = ch.legacy_version;
    if (ch.supportedVersions()) |sv| {
        var it = sv;
        var best: ?u16 = null;
        while (it.next()) |x| {
            if (isGrease(x)) continue;
            best = if (best) |b| @max(b, x) else x;
        }
        if (best) |b| v = b;
    }
    return switch (v) {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        0xfeff => "d1",
        0xfefd => "d2",
        0xfefc => "d3",
        else => "00",
    };
}

fn twoDigits(out: *[2]u8, n: usize) void {
    const v = @min(n, 99);
    out[0] = '0' + @as(u8, @intCast(v / 10));
    out[1] = '0' + @as(u8, @intCast(v % 10));
}

fn alpnCode(ch: *const hello.ClientHello, out: *[2]u8) void {
    out.* = "00".*;
    var it = ch.alpn() orelse return;
    const first = it.next() orelse return;
    if (first.len == 0) return;
    const a = first[0];
    const z = first[first.len - 1];
    if (std.ascii.isAlphanumeric(a) and std.ascii.isAlphanumeric(z)) {
        out.* = .{ a, z };
    } else {
        const digits = "0123456789abcdef";
        out.* = .{ digits[a >> 4], digits[z & 0x0f] };
    }
}

fn hex4(v: u16) [4]u8 {
    var b: [4]u8 = undefined;
    _ = std.fmt.bufPrint(&b, "{x:0>4}", .{v}) catch unreachable;
    return b;
}

fn hexList(h: *Sha256, items: []const u16) void {
    for (items, 0..) |v, i| {
        if (i != 0) h.update(",");
        h.update(&hex4(v));
    }
}

fn truncatedHex(h: *Sha256, out: *[12]u8) void {
    var d: [Sha256.digest_length]u8 = undefined;
    h.final(&d);
    const full = std.fmt.bytesToHex(d[0..6], .lower);
    out.* = full;
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

/// A ClientHello body: suites, then the extensions (type, data) in order.
fn body(buf: []u8, legacy_version: u16, suites: []const u16, exts: []const struct { u16, []const u8 }) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    w.writeInt(u16, legacy_version, .big) catch unreachable;
    w.splatByteAll(7, 32) catch unreachable;
    w.writeByte(0) catch unreachable;
    w.writeInt(u16, @intCast(2 * suites.len), .big) catch unreachable;
    for (suites) |s| w.writeInt(u16, s, .big) catch unreachable;
    w.writeAll(&.{ 1, 0 }) catch unreachable;
    var total: usize = 0;
    for (exts) |e| total += 4 + e[1].len;
    w.writeInt(u16, @intCast(total), .big) catch unreachable;
    for (exts) |e| {
        w.writeInt(u16, e[0], .big) catch unreachable;
        w.writeInt(u16, @intCast(e[1].len), .big) catch unreachable;
        w.writeAll(e[1]) catch unreachable;
    }
    return w.buffered();
}

const sigalgs_data = [_]u8{ 0, 16, 4, 3, 8, 4, 4, 1, 5, 3, 8, 5, 5, 1, 8, 6, 6, 1 };
const sni_data = [_]u8{ 0, 14, 0, 0, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm' };
const alpn_h2 = [_]u8{ 0, 12, 2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1' };

/// JA4.md's worked example: 15 suites, 16 extensions (SNI and ALPN among
/// them), its signature algorithms — with GREASE added, and the suites and
/// extensions shuffled, neither of which counts.
fn exampleBody(buf: []u8, alpn: []const u8) []const u8 {
    const suites = [_]u16{ 0x2a2a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035 };
    return body(buf, 0x0303, &suites, &.{
        .{ 0x3a3a, "" },
        .{ 0x0033, &.{ 0, 0 } },
        .{ 0x0000, &sni_data },
        .{ 0x0017, "" },
        .{ 0xff01, &.{0} },
        .{ 0x000a, &.{ 0, 4, 0, 0x1d, 0, 0x17 } },
        .{ 0x000b, &.{ 1, 0 } },
        .{ 0x0023, "" },
        .{ 0x0010, alpn },
        .{ 0x0005, &.{ 1, 0, 0, 0, 0 } },
        .{ 0x000d, &sigalgs_data },
        .{ 0x0012, "" },
        .{ 0x002d, &.{ 1, 1 } },
        .{ 0x002b, &.{ 6, 0x8a, 0x8a, 3, 4, 3, 3 } },
        .{ 0x001b, &.{ 2, 0, 2 } },
        .{ 0x4469, &.{ 0, 3, 2, 'h', '2' } },
        .{ 0x0015, &.{ 0, 0, 0 } },
    });
}

test "JA4: the specification's worked example, GREASE and order ignored" {
    var buf: [1024]u8 = undefined;
    const ch = try hello.parseClientHello(exampleBody(&buf, &alpn_h2));
    var out: [ja4_len]u8 = undefined;
    try ja4(&ch, .tcp, &out);
    try testing.expectEqualStrings("t13d1516h2_8daaf6152771_e5627efa2ab1", &out);
    try ja4(&ch, .quic, &out);
    try testing.expectEqualStrings("q13d1516h2_8daaf6152771_e5627efa2ab1", &out);
}

test "JA4: ALPN codes, no SNI, no signature algorithms, TLS 1.2, nothing at all" {
    var buf: [1024]u8 = undefined;
    var out: [ja4_len]u8 = undefined;
    // A first ALPN value ending in a non-alphanumeric octet: its hex.
    var ch = try hello.parseClientHello(exampleBody(&buf, &.{ 0, 4, 3, 'h', '3', 0xab }));
    try ja4(&ch, .tcp, &out);
    try testing.expectEqualStrings("t13d15166b", out[0..10]);
    // No SNI, no ALPN, no signature_algorithms, supported_versions absent.
    ch = try hello.parseClientHello(body(&buf, 0x0303, &.{0x1301}, &.{.{ 0x000a, &.{ 0, 2, 0, 0x1d } }}));
    try ja4(&ch, .tcp, &out);
    // "1301" hashed alone; "000a" alone.
    try testing.expectEqualStrings("t12i010100_", out[0..11]);
    try testing.expectEqualStrings(&shaPrefix("1301"), out[11..23]);
    try testing.expectEqualStrings(&shaPrefix("000a"), out[24..36]);
    // No extensions at all, no suites but GREASE; an unknown version.
    ch = try hello.parseClientHello(body(&buf, 0x7f00, &.{0x0a0a}, &.{}));
    try ja4(&ch, .tcp, &out);
    try testing.expectEqualStrings("t00i000000_000000000000_000000000000", &out);
    // Only SNI and ALPN: counted, but nothing left to hash.
    ch = try hello.parseClientHello(body(&buf, 0x0303, &.{0x1301}, &.{ .{ 0, &sni_data }, .{ 16, &alpn_h2 } }));
    try ja4(&ch, .tcp, &out);
    try testing.expectEqualStrings("t12d0102h2", out[0..10]);
    try testing.expectEqualStrings("000000000000", out[24..36]);
}

fn shaPrefix(s: []const u8) [12]u8 {
    var h: Sha256 = .init(.{});
    h.update(s);
    var o: [12]u8 = undefined;
    truncatedHex(&h, &o);
    return o;
}

test "isGrease: the sixteen RFC 8701 values only" {
    var n: usize = 0;
    for (0..0x10000) |v| {
        if (isGrease(@intCast(v))) n += 1;
    }
    try testing.expectEqual(@as(usize, 16), n);
    try testing.expect(isGrease(0xfafa) and !isGrease(0x0a1a));
}
