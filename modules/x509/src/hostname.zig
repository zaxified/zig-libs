// SPDX-License-Identifier: MIT
//! Server identity check: does a certificate's subjectAltName cover the
//! host a client connected to (RFC 9525 §6; Go `Certificate.VerifyHostname`).
//!
//! What it does not do, on purpose: fall back to the subject's commonName.
//! RFC 9525 dropped that fallback and Go ignores the CN ("the legacy Common
//! Name field is ignored"); std's `Parsed.verifyHostName`, which this module
//! used before, still falls back when the certificate has no SAN, so a
//! CN-only certificate passed `Options.expected_host`. It also could not
//! match an IP host at all.
//!
//! Rules: an IP host (dotted IPv4, or IPv6 bare or in `[brackets]`) is
//! compared octet-wise with iPAddress entries only, an IPv4 host and its
//! IPv4-mapped IPv6 form being the same address (as Go's `net.IP.Equal`). A
//! DNS host is compared with dNSName entries only, ASCII case-insensitively,
//! one trailing dot ignored on the host (not on a
//! presented name, as Go: probe O-trailing, 2026-10-11). A presented name may hold a
//! wildcard only as its whole left-most label (`*.example.com`), standing for
//! exactly one non-empty label; partial wildcards (`f*.example.com`) and
//! wildcards anywhere else match only a byte-identical host.

const std = @import("std");
const Certificate = std.crypto.Certificate;
const extensions = @import("extensions.zig");
const names = @import("names.zig");

pub const Error = error{CertificateHostMismatch} ||
    extensions.FindExtensionsError ||
    extensions.IterateError ||
    names.GeneralNameIterator.Error;

pub const Host = union(enum) {
    /// `name` without one trailing dot; `raw` as given (what a presented
    /// name that is not a valid pattern is compared with, byte for byte).
    dns: struct { name: []const u8, raw: []const u8 },
    ip4: [4]u8,
    ip6: [16]u8,
};

/// Classifies `host`. An IPv6 literal may be bracketed (`[2001:db8::1]`),
/// as in a URL authority. Never null for a non-empty input: anything that is
/// not an address is a DNS name, and `matchDnsName` decides whether it can
/// match.
pub fn parseHost(host: []const u8) ?Host {
    if (host.len == 0) return null;
    var h = host;
    // Brackets may enclose either family (Go strips them first).
    if (h.len >= 3 and h[0] == '[' and h[h.len - 1] == ']') h = h[1 .. h.len - 1];
    if (names.parseIp4(h)) |a| return .{ .ip4 = a };
    if (names.parseIp6(h)) |a| return .{ .ip6 = a };
    if (h.len != host.len) return null; // brackets around a non-address
    if (h[h.len - 1] == '.') h = h[0 .. h.len - 1];
    return .{ .dns = .{ .name = h, .raw = host } };
}

/// Checks `host` against the subjectAltName of the DER certificate `cert_der`.
/// No SAN extension, or no entry of the host's kind, is a mismatch.
pub fn verify(cert_der: []const u8, host: []const u8) Error!void {
    const cert: Certificate = .{ .buffer = cert_der, .index = 0 };
    const exts = (try extensions.findExtensions(cert)) orelse return error.CertificateHostMismatch;
    var it = extensions.iterate(exts, cert);
    while (try it.next()) |entry| {
        if (entry.id == .subject_alt_name) return verifySan(entry.value, host);
    }
    return error.CertificateHostMismatch;
}

/// `verify` against a raw subjectAltName extnValue (`GeneralNames`).
pub fn verifySan(san: []const u8, host: []const u8) Error!void {
    const want = parseHost(host) orelse return error.CertificateHostMismatch;
    var it = try names.GeneralNameIterator.init(san);
    while (try it.next()) |gn| {
        switch (want) {
            .dns => |d| if (gn.tag == .dNSName and matchDnsNameRaw(gn.value, d.name, d.raw)) return,
            .ip4 => |a| if (gn.tag == .iPAddress and ipEqual(gn.value, &a)) return,
            .ip6 => |a| if (gn.tag == .iPAddress and ipEqual(gn.value, &a)) return,
        }
    }
    return error.CertificateHostMismatch;
}

const v4_mapped_prefix = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

/// Octet equality, an IPv4 address equal to its `::ffff:a.b.c.d` form.
fn ipEqual(presented: []const u8, want: []const u8) bool {
    if (presented.len == want.len) return std.mem.eql(u8, presented, want);
    const short, const long = if (presented.len == 4 and want.len == 16)
        .{ presented, want }
    else if (presented.len == 16 and want.len == 4)
        .{ want, presented }
    else
        return false;
    return std.mem.eql(u8, long[0..12], &v4_mapped_prefix) and std.mem.eql(u8, long[12..], short);
}

/// One dNSName SAN entry `presented` against a DNS host (trailing dot
/// already stripped by `parseHost`). Pure; the rules are the module doc's.
pub fn matchDnsName(presented: []const u8, host: []const u8) bool {
    return matchDnsNameRaw(presented, host, host);
}

/// `matchDnsName` where `raw` is the host as given (with its trailing dot):
/// a presented name or host that is not a valid pattern is compared with it
/// exactly, ASCII case-insensitively, as Go does — so SAN `example.com.`
/// matches host `example.com.` but not `example.com`.
fn matchDnsNameRaw(presented: []const u8, host: []const u8, raw: []const u8) bool {
    if (!validHostLabels(host, false) or !validHostLabels(presented, true))
        return presented.len != 0 and std.ascii.eqlIgnoreCase(presented, raw);

    if (presented.len >= 2 and presented[0] == '*' and presented[1] == '.') {
        // Wildcard: the host's first label is any one non-empty label; the
        // rest must match label for label.
        const dot = std.mem.findScalar(u8, host, '.') orelse return false;
        if (dot == 0) return false;
        return std.ascii.eqlIgnoreCase(host[dot..], presented[1..]);
    }
    return std.ascii.eqlIgnoreCase(presented, host);
}

/// Every label non-empty and of `[A-Za-z0-9_-]` (Go also allows `_` and
/// `-` anywhere in a label, so `foo_bar.example.com` is a name). With
/// `wildcard`, the first label may be exactly `*`, and then at least two
/// labels must follow it — `*.com` names no host.
fn validHostLabels(s: []const u8, wildcard: bool) bool {
    if (s.len == 0 or s.len > 253) return false;
    var labels = std.mem.splitScalar(u8, s, '.');
    var i: usize = 0;
    var wild = false;
    while (labels.next()) |label| : (i += 1) {
        if (label.len == 0 or label.len > 63) return false;
        if (wildcard and i == 0 and std.mem.eql(u8, label, "*")) {
            wild = true;
            continue;
        }
        for (label) |b| {
            if (!(std.ascii.isAlphanumeric(b) or b == '-' or b == '_')) return false;
        }
    }
    if (wild and i < 3) return false;
    return true;
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "matchDnsName: exact, case, trailing dot" {
    try testing.expect(matchDnsName("example.com", "example.com"));
    try testing.expect(matchDnsName("Example.COM", "example.com"));
    try testing.expect(!matchDnsName("example.com.", "example.com"));
    try testing.expect(!matchDnsName("example.com", "www.example.com"));
    try testing.expect(!matchDnsName("www.example.com", "example.com"));
}

test "matchDnsName: wildcards" {
    try testing.expect(matchDnsName("*.example.com", "a.example.com"));
    try testing.expect(matchDnsName("*.example.com", "A.EXAMPLE.COM"));
    try testing.expect(!matchDnsName("*.example.com", "example.com"));
    try testing.expect(!matchDnsName("*.example.com", "a.b.example.com"));
    try testing.expect(!matchDnsName("*.com", "foo.com"));
    try testing.expect(!matchDnsName("f*.example.com", "fa.example.com"));
    try testing.expect(!matchDnsName("*.*.example.com", "a.b.example.com"));
    try testing.expect(!matchDnsName("a.*.example.com", "a.b.example.com"));
    try testing.expect(!matchDnsName("*", "localhost"));
    // A wildcard is not a host character: a host spelled `*.example.com`
    // matches the identical presented name only.
    try testing.expect(matchDnsName("*.example.com", "*.example.com"));
    try testing.expect(matchDnsNameRaw("example.com.", "example.com", "example.com."));
    try testing.expect(!matchDnsNameRaw("example.com.", "example.com", "example.com"));
}

test "parseHost" {
    try testing.expectEqual([4]u8{ 192, 0, 2, 1 }, parseHost("192.0.2.1").?.ip4);
    try testing.expect(parseHost("[2001:db8::1]").? == .ip6);
    try testing.expect(parseHost("2001:db8::1").? == .ip6);
    try testing.expectEqualStrings("example.com", parseHost("example.com.").?.dns.name);
    try testing.expectEqual([4]u8{ 192, 0, 2, 1 }, parseHost("[192.0.2.1]").?.ip4);
    try testing.expect(parseHost("[example.com]") == null);
    try testing.expect(parseHost("") == null);
}

test "verifySan: DNS host needs a dNSName, IP host an iPAddress; CN never consulted" {
    // SEQUENCE { dNSName "example.com", iPAddress 192.0.2.1, iPAddress 2001:db8::1 }
    const san = [_]u8{ 0x30, 0x25 } ++
        [_]u8{ 0x82, 0x0b } ++ "example.com".* ++
        [_]u8{ 0x87, 0x04, 192, 0, 2, 1 } ++
        [_]u8{ 0x87, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    try verifySan(&san, "example.com");
    try verifySan(&san, "EXAMPLE.com.");
    try verifySan(&san, "192.0.2.1");
    try verifySan(&san, "::ffff:192.0.2.1");
    try verifySan(&san, "[2001:db8::1]");
    try verifySan(&san, "2001:0db8::0001");
    try testing.expectError(error.CertificateHostMismatch, verifySan(&san, "www.example.com"));
    try testing.expectError(error.CertificateHostMismatch, verifySan(&san, "192.0.2.2"));
    // The dNSName "example.com" is not an address and an address is not a name.
    const ip_as_dns = [_]u8{ 0x30, 0x0b, 0x82, 0x09 } ++ "192.0.2.1".*;
    try testing.expectError(error.CertificateHostMismatch, verifySan(&ip_as_dns, "192.0.2.1"));
    // No SAN at all.
    try testing.expectError(error.CertificateHostMismatch, verifySan(&.{}, "example.com"));
}
