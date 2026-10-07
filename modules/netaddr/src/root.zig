// SPDX-License-Identifier: MIT

//! netaddr — IP address parse/format, CIDR/prefix math + RFC 6724 selection.
//!
//! Pure address logic with no I/O dependency: IPv4/IPv6 literal parsing and
//! RFC 5952 canonical formatting, `host:port` splitting, CIDR prefix
//! operations (`Prefix`: mask/contains/overlap, host math, supernet, address
//! iteration; `IpRange` with `summarize` and `mergePrefixes`), address
//! scope/policy classification, and the RFC 6724 "which address do I connect
//! to first" ordering that `http`, `dns` and `icmp` build on. Beside that,
//! the rest of Go `net/netip` + `go4.org/netipx`: zones (`ZonedIp`),
//! `AddrPort`, address ordering and next/prev, `IpRange` and the queryable
//! `IpSet` built by `IpSetBuilder`.
//!
//! The RFC 6724 logic is clean-room from the RFC, covering
//! the full destination rule set, cross-checked against Go's
//! `net/addrselect.go`. Like Go, rules that need OS state we don't track are
//! skipped (rule 3 deprecated addresses, rule 4 home addresses, rule 7 native
//! transport).
//!
//! The prefix/CIDR ops model after Go `net/netip.Prefix` + `go4.org/netipx`
//! (behavior only, clean-room — implemented from documented semantics, not
//! from their source).
//!
//! Scalar operations never allocate and work on caller-provided
//! buffers/slices; only the slice-returning `summarize`, `mergePrefixes`,
//! `IpRange.prefixes` and the `IpSet` family allocate, via a caller-passed
//! allocator.

const std = @import("std");
const builtin = @import("builtin");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "IP parse/format (RFC 5952) + RFC 6724 source/dest selection + CIDR/Prefix ops + Go netip/netipx parity (zones, AddrPort, ordering, IpRange, IpSet)",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any, // pure logic; `systemSource` helper is Linux-only
    .role = .util,
    .concurrency = .reentrant,
    .model_after = "Go net/addrselect.go + glibc getaddrinfo (RFC 6724); Go net/netip + go4.org/netipx (CIDR/prefix ops, zones, AddrPort, IPRange, IPSet)",
    .deps = .{}, // std only
};

// ── address type ────────────────────────────────────────────────────────────

/// An IP address as raw bytes, network byte order. The v4/v6 distinction is
/// preserved (an IPv4-mapped IPv6 address stays `.v6`; see `unmap`).
pub const Ip = union(enum) {
    v4: [4]u8,
    v6: [16]u8,

    pub fn eql(a: Ip, b: Ip) bool {
        return switch (a) {
            .v4 => |qa| switch (b) {
                .v4 => |qb| std.mem.eql(u8, &qa, &qb),
                .v6 => false,
            },
            .v6 => |ba| switch (b) {
                .v4 => false,
                .v6 => |bb| std.mem.eql(u8, &ba, &bb),
            },
        };
    }

    /// The address as 16 bytes; IPv4 becomes IPv4-mapped (`::ffff:a.b.c.d`).
    pub fn as16(ip: Ip) [16]u8 {
        return switch (ip) {
            .v4 => |q| [_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff } ++ q,
            .v6 => |b| b,
        };
    }

    /// An IPv4-mapped IPv6 address (`::ffff:0:0/96`) as `.v4`; other
    /// addresses unchanged.
    pub fn unmap(ip: Ip) Ip {
        return switch (ip) {
            .v4 => ip,
            .v6 => |b| if (isV4Mapped(b)) .{ .v4 = b[12..16].* } else ip,
        };
    }

    /// True for `::ffff:a.b.c.d` (and false for plain v4).
    pub fn isIpv4Mapped(ip: Ip) bool {
        return switch (ip) {
            .v4 => false,
            .v6 => |b| isV4Mapped(b),
        };
    }

    /// `0.0.0.0` or `::`.
    pub fn isUnspecified(ip: Ip) bool {
        return switch (ip) {
            .v4 => |q| std.mem.allEqual(u8, &q, 0),
            .v6 => |b| std.mem.allEqual(u8, &b, 0),
        };
    }

    /// `127.0.0.0/8` (also when IPv4-mapped) or `::1`.
    pub fn isLoopback(ip: Ip) bool {
        return switch (ip.unmap()) {
            .v4 => |q| q[0] == 127,
            .v6 => |b| std.mem.allEqual(u8, b[0..15], 0) and b[15] == 1,
        };
    }

    /// `169.254.0.0/16` (also when IPv4-mapped) or `fe80::/10`.
    pub fn isLinkLocalUnicast(ip: Ip) bool {
        return switch (ip.unmap()) {
            .v4 => |q| q[0] == 169 and q[1] == 254,
            .v6 => |b| b[0] == 0xfe and (b[1] & 0xc0) == 0x80,
        };
    }

    /// `224.0.0.0/4` (also when IPv4-mapped) or `ff00::/8`.
    pub fn isMulticast(ip: Ip) bool {
        return switch (ip.unmap()) {
            .v4 => |q| (q[0] & 0xf0) == 0xe0,
            .v6 => |b| b[0] == 0xff,
        };
    }

    /// IPv6 unique-local `fc00::/7` (RFC 4193).
    pub fn isUniqueLocal(ip: Ip) bool {
        return switch (ip) {
            .v4 => false,
            .v6 => |b| (b[0] & 0xfe) == 0xfc,
        };
    }

    /// Private addresses as Go `netip.Addr.IsPrivate` defines them: IPv4
    /// private-use `10/8`, `172.16/12`, `192.168/16` (RFC 1918) and IPv6
    /// unique-local `fc00::/7` (RFC 4193, also `isUniqueLocal`).
    ///
    /// v4-mapped addresses are unwrapped first, so `::ffff:10.0.0.1` counts —
    /// a check that missed that is exactly how a filter gets bypassed.
    ///
    /// Until 2026-10-07 this was RFC 1918 only; it now matches Go (user
    /// decision, parity). Combining this with loopback, link-local, CGNAT
    /// `100.64/10`, TEST-NET, broadcast … into one "is this safe to connect
    /// to" predicate is policy, not addressing, so it stays with the caller
    /// that has the threat model; `rdap`'s SSRF guard is the worked example.
    pub fn isPrivate(ip: Ip) bool {
        return switch (ip.unmap()) {
            .v4 => |q| q[0] == 10 or
                (q[0] == 172 and q[1] >= 16 and q[1] <= 31) or
                (q[0] == 192 and q[1] == 168),
            .v6 => |b| (b[0] & 0xfe) == 0xfc,
        };
    }

    /// Global unicast in Go `netip`'s sense: anything that is not
    /// unspecified, loopback, multicast, link-local unicast or the v4
    /// limited broadcast `255.255.255.255`. Private (RFC 1918) and
    /// unique-local (`fc00::/7`) addresses count — "global" here is about the
    /// address kind, not reachability. v4-mapped addresses are unwrapped
    /// first.
    pub fn isGlobalUnicast(ip: Ip) bool {
        const u = ip.unmap();
        if (u == .v4 and std.mem.allEqual(u8, &u.v4, 0xff)) return false;
        return !(u.isUnspecified() or u.isLoopback() or u.isMulticast() or u.isLinkLocalUnicast());
    }

    /// Link-local multicast: `224.0.0.0/24` (also when IPv4-mapped) or an
    /// IPv6 multicast address of scope 2 (`ffx2::/16`).
    pub fn isLinkLocalMulticast(ip: Ip) bool {
        return switch (ip.unmap()) {
            .v4 => |q| q[0] == 224 and q[1] == 0 and q[2] == 0,
            .v6 => |b| b[0] == 0xff and (b[1] & 0x0f) == 0x02,
        };
    }

    /// IPv6 interface-local multicast, scope 1 (`ffx1::/16`). No IPv4
    /// counterpart.
    pub fn isInterfaceLocalMulticast(ip: Ip) bool {
        return switch (ip) {
            .v4 => false,
            .v6 => |b| b[0] == 0xff and (b[1] & 0x0f) == 0x01,
        };
    }

    /// Address width: 32 for v4, 128 for v6 (Go `BitLen`).
    pub fn bitLen(ip: Ip) u8 {
        return widthOf(ip);
    }

    /// Total order like Go `netip.Addr.Compare`: every v4 address sorts
    /// before every v6 one (an IPv4-mapped address is v6), then numerically.
    pub fn compare(a: Ip, b: Ip) std.math.Order {
        const fa = std.meta.activeTag(a);
        const fb = std.meta.activeTag(b);
        if (fa != fb) return if (fa == .v4) .lt else .gt;
        return std.math.order(ipToInt(a), ipToInt(b));
    }

    /// `compare(a, b) == .lt`, shaped for `std.sort` (`lessThan(ctx, a, b)`).
    pub fn lessThan(_: void, a: Ip, b: Ip) bool {
        return a.compare(b) == .lt;
    }

    /// The next address in the same family; null after the last one
    /// (`255.255.255.255`, `ffff:…:ffff`). Never crosses families: the
    /// successor of `::ffff:255.255.255.255` is `::1:0:0:0`.
    pub fn next(ip: Ip) ?Ip {
        const v = ipToInt(ip);
        if (v == hostMask(widthOf(ip), 0)) return null;
        return ipFromInt(std.meta.activeTag(ip), v + 1);
    }

    /// The previous address in the same family; null before `0.0.0.0` / `::`.
    pub fn prev(ip: Ip) ?Ip {
        const v = ipToInt(ip);
        if (v == 0) return null;
        return ipFromInt(std.meta.activeTag(ip), v - 1);
    }

    /// The masked prefix of length `bits` containing `ip` (Go
    /// `Addr.Prefix`); null when `bits` exceeds the family width.
    pub fn prefix(ip: Ip, bits: u8) ?Prefix {
        if (bits > widthOf(ip)) return null;
        return (Prefix{ .addr = ip, .bits = bits }).masked();
    }

    /// The raw bytes: 4 for v4, 16 for v6 (Go `AsSlice`; with `fromSlice`
    /// the binary form Go's `MarshalBinary` writes for a zone-less address).
    /// Borrows: the slice points into `ip.*`, so call it on a variable that
    /// outlives the slice, not on a temporary.
    pub fn asSlice(ip: *const Ip) []const u8 {
        return switch (ip.*) {
            .v4 => |*q| q,
            .v6 => |*b| b,
        };
    }

    /// 4 bytes → v4, 16 bytes → v6 (no unmapping), anything else → null
    /// (Go `AddrFromSlice`).
    pub fn fromSlice(bytes: []const u8) ?Ip {
        return switch (bytes.len) {
            4 => .{ .v4 = bytes[0..4].* },
            16 => .{ .v6 = bytes[0..16].* },
            else => null,
        };
    }

    /// The address part of a `std.Io.net.IpAddress` (port and interface
    /// dropped; `AddrPort.fromStd` keeps them). Not unmapped: a v4-mapped
    /// `ip6` stays `.v6`, as everywhere in this module.
    pub fn fromStd(a: std.Io.net.IpAddress) Ip {
        return switch (a) {
            .ip4 => |x| .{ .v4 = x.bytes },
            .ip6 => |x| .{ .v6 = x.bytes },
        };
    }

    /// A `std.Io.net.IpAddress` for `ip` and `port` (no interface).
    pub fn toStd(ip: Ip, port: u16) std.Io.net.IpAddress {
        return switch (ip) {
            .v4 => |q| .{ .ip4 = .{ .bytes = q, .port = port } },
            .v6 => |b| .{ .ip6 = .{ .bytes = b, .port = port } },
        };
    }

    /// `{f}` formatting: the `formatIp` text.
    pub fn format(ip: Ip, w: *std.Io.Writer) std.Io.Writer.Error!void {
        var buf: [max_ip_text_len]u8 = undefined;
        try w.writeAll(formatIp(ip, &buf));
    }

    pub const ipv4_unspecified: Ip = .{ .v4 = @splat(0) };
    pub const ipv4_broadcast: Ip = .{ .v4 = @splat(0xff) };
    pub const ipv6_unspecified: Ip = .{ .v6 = @splat(0) };
    pub const ipv6_loopback: Ip = .{ .v6 = [_]u8{0} ** 15 ++ [_]u8{1} };
    /// `ff02::1`.
    pub const ipv6_link_local_all_nodes: Ip = .{ .v6 = [_]u8{ 0xff, 0x02 } ++ [_]u8{0} ** 13 ++ [_]u8{1} };
    /// `ff02::2`.
    pub const ipv6_link_local_all_routers: Ip = .{ .v6 = [_]u8{ 0xff, 0x02 } ++ [_]u8{0} ** 13 ++ [_]u8{2} };

    fn isV4Mapped(b: [16]u8) bool {
        return std.mem.allEqual(u8, b[0..10], 0) and b[10] == 0xff and b[11] == 0xff;
    }
};

// ── parsing ─────────────────────────────────────────────────────────────────

/// Parse an IPv4 or IPv6 literal. Returns null on malformed input; never
/// panics. Zone suffixes (`fe80::1%eth0`) are rejected — split the zone off
/// before calling.
pub fn parseIp(text: []const u8) ?Ip {
    // The first separator decides the family, so each literal is scanned by
    // one parser only (an IPv6 literal used to be tried as IPv4 first).
    for (text) |c| switch (c) {
        '.' => return if (parseIp4(text)) |q| .{ .v4 = q } else null,
        ':' => return if (parseIp6(text)) |b| .{ .v6 = b } else null,
        else => {},
    };
    return null;
}

/// Parse a dotted-quad IPv4 literal. Strict, matching Go `netip.ParseAddr`:
/// exactly four decimal octets 0–255, no leading zeros, nothing else.
pub fn parseIp4(text: []const u8) ?[4]u8 {
    var out: [4]u8 = undefined;
    var k: usize = 0;
    var octet: u16 = 0;
    var digits: u8 = 0;
    for (text) |c| {
        if (c >= '0' and c <= '9') {
            if (digits == 1 and octet == 0) return null; // no leading zeros
            octet = octet * 10 + (c - '0');
            if (octet > 255) return null; // also caps an octet at three digits
            digits += 1;
        } else if (c == '.') {
            if (digits == 0 or k == 3) return null;
            out[k] = @intCast(octet);
            k += 1;
            octet = 0;
            digits = 0;
        } else return null;
    }
    if (digits == 0 or k != 3) return null;
    out[3] = @intCast(octet);
    return out;
}

/// Parse an IPv6 literal (RFC 4291 §2.2): full form, `::` compression, and an
/// embedded dotted-quad tail (`::ffff:1.2.3.4`). Zone suffixes are rejected.
/// One pass: groups are written in place, and the ones after a `::` are moved
/// to the end once their count is known.
pub fn parseIp6(text: []const u8) ?[16]u8 {
    var out: [16]u8 = @splat(0);
    var g: usize = 0; // groups written
    var ellipsis: ?usize = null; // group index where `::` stands
    var i: usize = 0;
    if (text.len >= 2 and text[0] == ':' and text[1] == ':') {
        ellipsis = 0;
        i = 2;
    } else if (text.len == 0 or text[0] == ':') return null;
    while (i < text.len) {
        var v: u32 = 0;
        var n: usize = 0;
        while (i + n < text.len) : (n += 1) {
            const d = std.fmt.charToDigit(text[i + n], 16) catch break;
            v = (v << 4) | d;
            if (n == 4) return null; // a fifth hex digit
        }
        if (n == 0) return null; // empty group, `:::`, a stray byte
        if (i + n < text.len and text[i + n] == '.') {
            // Dotted-quad tail: the rest must be exactly one IPv4 literal,
            // in the last two group positions.
            if (g > 6 or (ellipsis == null and g != 6)) return null;
            const q = parseIp4(text[i..]) orelse return null;
            @memcpy(out[g * 2 ..][0..4], &q);
            g += 2;
            break;
        }
        if (g == 8) return null;
        out[g * 2] = @intCast(v >> 8);
        out[g * 2 + 1] = @intCast(v & 0xff);
        g += 1;
        i += n;
        if (i == text.len) break;
        if (text[i] != ':') return null; // includes a `%zone`
        i += 1;
        if (i == text.len) return null; // a trailing single `:`
        if (text[i] == ':') {
            if (ellipsis != null) return null; // a second `::`
            ellipsis = g;
            i += 1;
        }
    }
    if (ellipsis) |e| {
        if (g == 8) return null; // `::` must elide at least one group
        const tail = (g - e) * 2;
        std.mem.copyBackwards(u8, out[16 - tail ..], out[e * 2 ..][0..tail]);
        @memset(out[e * 2 .. 16 - tail], 0);
    } else if (g != 8) return null;
    return out;
}

// ── formatting ──────────────────────────────────────────────────────────────

/// Enough for any output of `formatIp` (matches INET6_ADDRSTRLEN − 1).
pub const max_ip_text_len = 45;

// F2 (audit 2026-09-04): this constant was not anchored to anything -- a
// caller passing `buf[0..max_ip_text_len]` and a future edit shrinking the
// constant would silently turn every `catch unreachable` below into UB, and
// the failure mode is different in every build mode (Debug/ReleaseSafe
// panic, ReleaseFast hangs on the resulting corrupted loop state,
// ReleaseSmall silently truncates the address). Pin it at comptime instead
// of hoping a test notices: the longest string `formatIp` can produce is the
// full 8-group v6 form with no zero-run compression (a compressible run only
// ever makes the output shorter) -- 8 groups of up to 4 hex digits plus 7
// `:` separators.
comptime {
    const worst_v6_len = 8 * 4 + 7; // 39
    if (worst_v6_len > max_ip_text_len)
        @compileError("max_ip_text_len is too small for formatIp's longest possible output");
}

/// Format an address canonically: dotted quad for v4, RFC 5952 for v6
/// (lowercase, longest zero run compressed leftmost, IPv4-mapped rendered
/// mixed as `::ffff:a.b.c.d`).
///
/// `buf` is a pointer to an array, not a slice, so "too small a buffer" is a
/// compile error rather than a runtime one. It used to be a slice guarded by
/// `std.debug.assert`, which is `if (!ok) unreachable` and therefore compiled
/// OUT of ReleaseFast and ReleaseSmall -- exactly the modes an integrator
/// ships. A caller who passed a short buffer got a clean crash while testing
/// and a silent write past the end of it in production. A caller holding a
/// larger buffer passes `buf[0..max_ip_text_len]`.
pub fn formatIp(ip: Ip, buf: *[max_ip_text_len]u8) []const u8 {
    switch (ip) {
        .v4 => |q| return buf[0..writeDottedQuad(buf, 0, q)],
        .v6 => |b| {
            if (Ip.isV4Mapped(b)) {
                @memcpy(buf[0..7], "::ffff:");
                return buf[0..writeDottedQuad(buf, 7, b[12..16].*)];
            }

            var groups: [8]u16 = undefined;
            for (&groups, 0..) |*g, k| g.* = (@as(u16, b[k * 2]) << 8) | b[k * 2 + 1];

            // Longest run of ≥ 2 zero groups, leftmost on ties (RFC 5952 §4.2).
            var best_start: usize = 0;
            var best_len: usize = 0;
            var run_start: usize = 0;
            var run_len: usize = 0;
            for (groups, 0..) |g, k| {
                if (g == 0) {
                    if (run_len == 0) run_start = k;
                    run_len += 1;
                    if (run_len > best_len) {
                        best_len = run_len;
                        best_start = run_start;
                    }
                } else run_len = 0;
            }
            if (best_len < 2) best_len = 0; // never compress a single group

            var w: usize = 0;
            var g: usize = 0;
            while (g < 8) {
                if (best_len != 0 and g == best_start) {
                    buf[w] = ':';
                    buf[w + 1] = ':';
                    w += 2;
                    g += best_len;
                    continue;
                }
                if (w != 0 and buf[w - 1] != ':') {
                    buf[w] = ':';
                    w += 1;
                }
                w = writeHexGroup(buf, w, groups[g]);
                g += 1;
            }
            return buf[0..w];
        },
    }
}

/// Write `q` as a dotted quad at `buf[w..]`; returns the new end. Hand-rolled
/// rather than `bufPrint`: formatting is a hot path (logs, keys), and the
/// generic formatter cost as much as the rest of `formatIp` together.
fn writeDottedQuad(buf: *[max_ip_text_len]u8, start: usize, q: [4]u8) usize {
    var w = start;
    for (q, 0..) |octet, k| {
        if (k != 0) {
            buf[w] = '.';
            w += 1;
        }
        if (octet >= 100) {
            buf[w] = '0' + octet / 100;
            w += 1;
        }
        if (octet >= 10) {
            buf[w] = '0' + (octet / 10) % 10;
            w += 1;
        }
        buf[w] = '0' + octet % 10;
        w += 1;
    }
    return w;
}

/// Write `v` in lowercase hex without leading zeros (RFC 5952 §4.1, §4.3).
fn writeHexGroup(buf: *[max_ip_text_len]u8, start: usize, v: u16) usize {
    const digits = "0123456789abcdef";
    const n: usize = if (v >= 0x1000) 4 else if (v >= 0x100) 3 else if (v >= 0x10) 2 else 1;
    var k: usize = n;
    var x = v;
    while (k > 0) {
        k -= 1;
        buf[start + k] = digits[x & 0xf];
        x >>= 4;
    }
    return start + n;
}

/// Enough for any output of `formatIpExpanded` (8 groups of 4 + 7 colons).
pub const max_ip_expanded_text_len = 39;

/// Format with no compression (Go `StringExpanded`): v4 as `formatIp`,
/// every v6 address — v4-mapped included — as eight 4-digit lowercase hex
/// groups, `2001:0db8:0000:0000:0000:0000:0000:0001`.
pub fn formatIpExpanded(ip: Ip, buf: *[max_ip_expanded_text_len]u8) []const u8 {
    switch (ip) {
        .v4 => |q| return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ q[0], q[1], q[2], q[3] }) catch unreachable,
        .v6 => |b| {
            const hex = "0123456789abcdef";
            var w: usize = 0;
            for (b, 0..) |byte, k| {
                if (k != 0 and k % 2 == 0) {
                    buf[w] = ':';
                    w += 1;
                }
                buf[w] = hex[byte >> 4];
                buf[w + 1] = hex[byte & 0xf];
                w += 2;
            }
            return buf[0..w];
        },
    }
}

// ── zones (RFC 4007 §11 scoped literals) ────────────────────────────────────
//
// Go `netip.Addr` carries the zone inside the address; here the zone-less
// `Ip` stays the substrate every other module switches on, and a zone rides
// next to it in `ZonedIp` / `AddrPort`. The zone is stored inline (no
// lifetime tied to the parsed text) and capped at `max_zone_len` bytes:
// interface names are at most 15 (IFNAMSIZ − 1) and a numeric scope id at
// most 10 digits, so the cap refuses nothing a kernel would accept — Go
// accepts any length.

/// Longest zone `Zone` holds.
pub const max_zone_len = 31;

/// An IPv6 zone (`eth0`, `3`): any non-empty text up to `max_zone_len`
/// bytes, opaque as in Go — not resolved, not checked against interfaces.
pub const Zone = struct {
    len: u8 = 0,
    buf: [max_zone_len]u8 = @splat(0),

    pub const none: Zone = .{};

    /// The zone for `text`; `none` for empty text, null when longer than
    /// `max_zone_len`.
    pub fn fromSlice(text: []const u8) ?Zone {
        if (text.len > max_zone_len) return null;
        var z: Zone = .{ .len = @intCast(text.len) };
        @memcpy(z.buf[0..text.len], text);
        return z;
    }

    pub fn slice(z: *const Zone) []const u8 {
        return z.buf[0..z.len];
    }

    pub fn isNone(z: Zone) bool {
        return z.len == 0;
    }

    pub fn eql(a: Zone, b: Zone) bool {
        return std.mem.eql(u8, a.slice(), b.slice());
    }

    /// Byte-wise order; no zone sorts first (Go compares zone strings).
    pub fn order(a: Zone, b: Zone) std.math.Order {
        return std.mem.order(u8, a.slice(), b.slice());
    }
};

/// An address with an optional zone (Go `netip.Addr` as a whole). A v4
/// address never carries one: `init` drops it, as Go `WithZone` does.
pub const ZonedIp = struct {
    ip: Ip,
    zone: Zone = .none,

    /// `ip` with zone `zone_text` (empty = no zone; ignored for v4, like Go
    /// `WithZone`); null when the zone is longer than `max_zone_len`.
    pub fn init(ip: Ip, zone_text: []const u8) ?ZonedIp {
        if (ip == .v4) return .{ .ip = ip };
        return .{ .ip = ip, .zone = Zone.fromSlice(zone_text) orelse return null };
    }

    pub fn eql(a: ZonedIp, b: ZonedIp) bool {
        return a.ip.eql(b.ip) and a.zone.eql(b.zone);
    }

    /// `Ip.compare`, then the zone (Go `Addr.Compare`).
    pub fn compare(a: ZonedIp, b: ZonedIp) std.math.Order {
        const o = a.ip.compare(b.ip);
        return if (o != .eq) o else a.zone.order(b.zone);
    }

    /// `{f}` formatting: the `formatIpZoned` text.
    pub fn format(z: ZonedIp, w: *std.Io.Writer) std.Io.Writer.Error!void {
        var buf: [max_zoned_ip_text_len]u8 = undefined;
        try w.writeAll(formatIpZoned(z, &buf));
    }
};

/// Parse an address that may carry an IPv6 zone (`fe80::1%eth0`), like Go
/// `netip.ParseAddr`: the zone is everything after the first `%`, any bytes,
/// non-empty; a zone on an IPv4 literal is refused. Null on malformed input
/// or a zone longer than `max_zone_len`.
pub fn parseIpZoned(text: []const u8) ?ZonedIp {
    const pct = std.mem.indexOfScalar(u8, text, '%') orelse
        return .{ .ip = parseIp(text) orelse return null };
    const zone_text = text[pct + 1 ..];
    if (zone_text.len == 0) return null;
    const b = parseIp6(text[0..pct]) orelse return null;
    return .{ .ip = .{ .v6 = b }, .zone = Zone.fromSlice(zone_text) orelse return null };
}

/// Enough for any output of `formatIpZoned`.
pub const max_zoned_ip_text_len = max_ip_text_len + 1 + max_zone_len;

/// `formatIp`, then `%zone` when there is one (never after a v4 address,
/// which cannot carry one — a hand-built value that does prints without it).
pub fn formatIpZoned(z: ZonedIp, buf: *[max_zoned_ip_text_len]u8) []const u8 {
    const ip_text = formatIp(z.ip, buf[0..max_ip_text_len]);
    if (z.zone.isNone() or z.ip == .v4) return ip_text;
    buf[ip_text.len] = '%';
    const zs = z.zone.slice();
    @memcpy(buf[ip_text.len + 1 ..][0..zs.len], zs);
    return buf[0 .. ip_text.len + 1 + zs.len];
}

// ── address + port ──────────────────────────────────────────────────────────

/// A numeric address, its zone and a port (Go `netip.AddrPort`). Unlike
/// `parseHostPort`, which splits text and leaves the host unparsed, this is
/// a value: the address is parsed, and no name is ever accepted.
pub const AddrPort = struct {
    ip: Ip,
    port: u16,
    zone: Zone = .none,

    pub fn eql(a: AddrPort, b: AddrPort) bool {
        return a.port == b.port and a.ip.eql(b.ip) and a.zone.eql(b.zone);
    }

    /// Address (with zone), then port (Go `AddrPort.Compare`).
    pub fn compare(a: AddrPort, b: AddrPort) std.math.Order {
        const o = (ZonedIp{ .ip = a.ip, .zone = a.zone }).compare(.{ .ip = b.ip, .zone = b.zone });
        return if (o != .eq) o else std.math.order(a.port, b.port);
    }

    /// From a `std.Io.net.IpAddress`. A non-zero IPv6 interface index
    /// becomes a numeric zone (`%3`); the flow label is dropped.
    pub fn fromStd(a: std.Io.net.IpAddress) AddrPort {
        return switch (a) {
            .ip4 => |x| .{ .ip = .{ .v4 = x.bytes }, .port = x.port },
            .ip6 => |x| blk: {
                var ap: AddrPort = .{ .ip = .{ .v6 = x.bytes }, .port = x.port };
                if (!x.interface.isNone()) {
                    const s = std.fmt.bufPrint(&ap.zone.buf, "{d}", .{x.interface.index}) catch unreachable; // ≤ 10 digits
                    ap.zone.len = @intCast(s.len);
                }
                break :blk ap;
            },
        };
    }

    /// To a `std.Io.net.IpAddress`. A numeric zone becomes the interface
    /// index; an interface NAME needs the OS (`std.Io.net.Interface.Name
    /// .resolve`), which this pure module does not call — `ZoneNotNumeric`.
    /// Only the form `fromStd` writes counts as numeric — plain decimal
    /// 1..2^32−1, no sign, no leading zero — so a round trip never changes
    /// the zone text; `0` (= no interface in std), `+5` or `007` is refused.
    pub fn toStd(ap: AddrPort) error{ZoneNotNumeric}!std.Io.net.IpAddress {
        var a = ap.ip.toStd(ap.port);
        if (!ap.zone.isNone() and a == .ip6) {
            const z = ap.zone.slice();
            if (z[0] < '1' or z[0] > '9') return error.ZoneNotNumeric;
            for (z) |c| if (c < '0' or c > '9') return error.ZoneNotNumeric;
            const index = std.fmt.parseInt(u32, z, 10) catch return error.ZoneNotNumeric;
            a.ip6.interface = .{ .index = index };
        }
        return a;
    }

    /// `{f}` formatting: the `formatAddrPort` text.
    pub fn format(ap: AddrPort, w: *std.Io.Writer) std.Io.Writer.Error!void {
        var buf: [max_addr_port_text_len]u8 = undefined;
        try w.writeAll(formatAddrPort(ap, &buf));
    }
};

/// Parse `a.b.c.d:port` or `[v6]:port` / `[v6%zone]:port` (Go
/// `netip.ParseAddrPort`): the split is at the last `:`, brackets are
/// required around and only allowed around IPv6, the port is required.
/// The port follows this module's `parsePort` (decimal, no leading zero) —
/// Go also takes `080`. Null on malformed input.
pub fn parseAddrPort(text: []const u8) ?AddrPort {
    const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse return null;
    const port = parsePort(text[colon + 1 ..]) orelse return null;
    const host = text[0..colon];
    if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']') {
        const z = parseIpZoned(host[1 .. host.len - 1]) orelse return null;
        if (z.ip != .v6) return null; // brackets only around IPv6
        return .{ .ip = z.ip, .zone = z.zone, .port = port };
    }
    // Unbracketed: IPv4 only (an IPv6 literal would be ambiguous).
    return .{ .ip = .{ .v4 = parseIp4(host) orelse return null }, .port = port };
}

/// Enough for any output of `formatAddrPort` (`[` addr%zone `]:` 5 digits).
pub const max_addr_port_text_len = 1 + max_zoned_ip_text_len + 2 + 5;

/// `a.b.c.d:port`, or `[v6%zone]:port` for every IPv6 address.
pub fn formatAddrPort(ap: AddrPort, buf: *[max_addr_port_text_len]u8) []const u8 {
    var w: usize = 0;
    if (ap.ip == .v6) {
        buf[0] = '[';
        w = 1;
    }
    w += formatIpZoned(.{ .ip = ap.ip, .zone = ap.zone }, buf[w..][0..max_zoned_ip_text_len]).len;
    if (ap.ip == .v6) {
        buf[w] = ']';
        w += 1;
    }
    w += (std.fmt.bufPrint(buf[w..], ":{d}", .{ap.port}) catch unreachable).len;
    return buf[0..w];
}

// ── host:port splitting ─────────────────────────────────────────────────────

pub const HostPort = struct { host: []const u8, port: u16 };

/// Split `host:port` / `[v6]:port` (Go `net.SplitHostPort` semantics; the
/// port is required). `host` is a slice into `text`, brackets stripped, not
/// validated (it may be a name, a v4/v6 literal, or `v6%zone`). Unbracketed
/// input with more than one `:` is rejected as an ambiguous v6 literal.
pub fn parseHostPort(text: []const u8) ?HostPort {
    if (text.len == 0) return null;
    if (text[0] == '[') {
        const close = std.mem.indexOfScalar(u8, text, ']') orelse return null;
        const host = text[1..close];
        if (host.len == 0) return null;
        if (close + 2 >= text.len or text[close + 1] != ':') return null;
        const port = parsePort(text[close + 2 ..]) orelse return null;
        return .{ .host = host, .port = port };
    }
    const colon = std.mem.indexOfScalar(u8, text, ':') orelse return null;
    if (std.mem.indexOfScalarPos(u8, text, colon + 1, ':') != null) return null;
    if (colon == 0) return null;
    const port = parsePort(text[colon + 1 ..]) orelse return null;
    return .{ .host = text[0..colon], .port = port };
}

// F8 (audit 2026-09-04, tightened per user decision Q2-B 2026-09-11):
// `parsePort` used to keep accepting a leading zero ("host:080" read as port
// 80), unlike every other numeric field in this module (`parseIp4`'s octets,
// `parsePrefix`'s bits). There is no ambiguous *value* here -- "0080" always
// means decimal 80, never octal -- so this was never a parse-confusion bug,
// only an inconsistency. The user decided to close it directly rather than
// gate it behind a switch: any single digit ("0"..."9") is still accepted
// (that is not a *leading* zero), but two or more digits starting with '0'
// are now rejected, matching `parseIp4`/`parsePrefix`. This is an observable
// behavior change across `parseHostPort`'s ~20 direct consumers; the ones
// that actually reach `parsePort`/`parseHostPort` (`http`, `bacnet`, `probe`)
// were checked in the same batch -- none had a leading-zero port fixture.
fn parsePort(text: []const u8) ?u16 {
    if (text.len == 0 or text.len > 5) return null;
    if (text.len > 1 and text[0] == '0') return null; // leading zero, len >= 2
    var v: u32 = 0;
    for (text) |c| {
        if (c < '0' or c > '9') return null;
        v = v * 10 + (c - '0');
    }
    return if (v <= std.math.maxInt(u16)) @intCast(v) else null;
}

// ── CIDR prefixes ───────────────────────────────────────────────────────────
//
// Model after Go `net/netip.Prefix` + `go4.org/netipx` (IPSet normalize /
// range summarize) — behavior only, clean-room. All bit math is done on the
// address as an unsigned integer in big-endian (network) byte order, so
// numeric comparison matches address order for both families.

/// Address family tag (`.v4` / `.v6`) of the `Ip` union.
const IpFamily = std.meta.Tag(Ip);

fn widthOf(ip: Ip) u8 {
    return switch (ip) {
        .v4 => 32,
        .v6 => 128,
    };
}

/// The address value as an unsigned integer in the low `widthOf(ip)` bits.
fn ipToInt(ip: Ip) u128 {
    return switch (ip) {
        .v4 => |q| std.mem.readInt(u32, &q, .big),
        .v6 => |b| std.mem.readInt(u128, &b, .big),
    };
}

fn ipFromInt(fam: IpFamily, value: u128) Ip {
    switch (fam) {
        .v4 => {
            var q: [4]u8 = undefined;
            std.mem.writeInt(u32, &q, @truncate(value), .big);
            return .{ .v4 = q };
        },
        .v6 => {
            var b: [16]u8 = undefined;
            std.mem.writeInt(u128, &b, value, .big);
            return .{ .v6 = b };
        },
    }
}

/// Network mask for a `bits`-long prefix in a `width`-bit family, as ones in
/// the low `width` bits. `bits` is clamped to `width`; never panics.
fn netMask(width: u8, bits: u8) u128 {
    const b = @min(bits, width);
    if (b == 0) return 0;
    const host: u7 = @intCast(width - b); // b >= 1 → host <= 127
    const all: u128 = if (width == 128)
        std.math.maxInt(u128)
    else
        (@as(u128, 1) << @intCast(width)) - 1;
    return all & ~((@as(u128, 1) << host) - 1);
}

/// Host mask: the complement of `netMask` within the family width.
fn hostMask(width: u8, bits: u8) u128 {
    const host = width - @min(bits, width);
    if (host >= 128) return std.math.maxInt(u128);
    return (@as(u128, 1) << @intCast(host)) - 1;
}

/// Enough for any output of `formatPrefix` (`max_ip_text_len` + "/128").
pub const max_prefix_text_len = max_ip_text_len + 4;

/// An IP network in CIDR notation: an address plus a prefix length. The
/// address may carry host bits (`192.0.2.5/24` is representable; every
/// operation masks internally — call `masked` for the canonical network
/// form). The v4/v6 distinction is strict: a v4 prefix never contains an
/// IPv4-mapped v6 address — `Ip.unmap` inputs first when mixing is possible.
pub const Prefix = struct {
    addr: Ip,
    bits: u8,

    pub fn eql(a: Prefix, b: Prefix) bool {
        return a.bits == b.bits and a.addr.eql(b.addr);
    }

    /// Family width in bits: 32 for v4, 128 for v6.
    pub fn width(p: Prefix) u8 {
        return widthOf(p.addr);
    }

    /// True when the prefix denotes exactly one address (/32 or /128).
    pub fn isSingleIp(p: Prefix) bool {
        return p.bits >= p.width();
    }

    /// Canonical form: host bits zeroed and `bits` clamped to the family
    /// width. `192.0.2.5/24` → `192.0.2.0/24`.
    pub fn masked(p: Prefix) Prefix {
        const w = p.width();
        const b = @min(p.bits, w);
        return .{
            .addr = ipFromInt(std.meta.activeTag(p.addr), ipToInt(p.addr) & netMask(w, b)),
            .bits = b,
        };
    }

    /// The network address (the `masked` address; both families).
    pub fn network(p: Prefix) Ip {
        return p.masked().addr;
    }

    /// The v4 directed-broadcast address (host bits all-ones); null for v6,
    /// which has no broadcast. For /31 and /32 this is simply the last
    /// address (RFC 3021 point-to-point links have no broadcast either).
    pub fn broadcast(p: Prefix) ?Ip {
        if (p.addr != .v4) return null;
        const net = ipToInt(p.addr) & netMask(32, p.bits);
        return ipFromInt(.v4, net | hostMask(32, p.bits));
    }

    /// First usable host address: network + 1 for v4 prefixes up to /30;
    /// the network address itself for v4 /31 + /32 (RFC 3021) and for v6.
    pub fn firstHost(p: Prefix) Ip {
        const w = p.width();
        const b = @min(p.bits, w);
        const net = ipToInt(p.addr) & netMask(w, b);
        const reserve = p.addr == .v4 and b <= 30;
        return ipFromInt(std.meta.activeTag(p.addr), if (reserve) net + 1 else net);
    }

    /// Last usable host address: broadcast − 1 for v4 prefixes up to /30;
    /// the last address for v4 /31 + /32 (RFC 3021) and for v6.
    pub fn lastHost(p: Prefix) Ip {
        const w = p.width();
        const b = @min(p.bits, w);
        const last = (ipToInt(p.addr) & netMask(w, b)) | hostMask(w, b);
        const reserve = p.addr == .v4 and b <= 30;
        return ipFromInt(std.meta.activeTag(p.addr), if (reserve) last - 1 else last);
    }

    /// Number of addresses the prefix covers (2^host-bits), saturating at
    /// `maxInt(u128)` for a v6 /0.
    pub fn hostCount(p: Prefix) u128 {
        const w = p.width();
        const host = w - @min(p.bits, w);
        if (host >= 128) return std.math.maxInt(u128);
        return @as(u128, 1) << @intCast(host);
    }

    /// True when `ip` falls inside the prefix. Family-checked: always false
    /// across v4/v6 (including IPv4-mapped v6 against a v4 prefix).
    pub fn contains(p: Prefix, ip: Ip) bool {
        if (std.meta.activeTag(p.addr) != std.meta.activeTag(ip)) return false;
        const m = netMask(p.width(), p.bits);
        return (ipToInt(ip) & m) == (ipToInt(p.addr) & m);
    }

    /// True when `other` is a subnet of (or equal to) `p`.
    pub fn containsPrefix(p: Prefix, other: Prefix) bool {
        if (std.meta.activeTag(p.addr) != std.meta.activeTag(other.addr)) return false;
        const w = p.width();
        if (@min(other.bits, w) < @min(p.bits, w)) return false;
        return p.contains(other.addr);
    }

    /// True when the two prefixes share at least one address.
    pub fn overlaps(p: Prefix, other: Prefix) bool {
        if (std.meta.activeTag(p.addr) != std.meta.activeTag(other.addr)) return false;
        const w = p.width();
        const m = netMask(w, @min(@min(p.bits, w), @min(other.bits, w)));
        return (ipToInt(p.addr) & m) == (ipToInt(other.addr) & m);
    }

    /// The enclosing prefix at `new_bits` (a shorter prefix length), masked.
    /// Null when `new_bits` is longer than `p.bits`; never panics.
    pub fn supernet(p: Prefix, new_bits: u8) ?Prefix {
        if (new_bits > @min(p.bits, p.width())) return null;
        return (Prefix{ .addr = p.addr, .bits = new_bits }).masked();
    }

    /// The inclusive address range the prefix covers (network … last).
    pub fn range(p: Prefix) IpRange {
        const w = p.width();
        const net = ipToInt(p.addr) & netMask(w, p.bits);
        const fam = std.meta.activeTag(p.addr);
        return .{
            .from = ipFromInt(fam, net),
            .to = ipFromInt(fam, net | hostMask(w, p.bits)),
        };
    }

    /// The last address of the prefix (all host bits set; netipx
    /// `PrefixLastIP`). For a v4 prefix this is the broadcast address.
    pub fn lastAddr(p: Prefix) Ip {
        return p.range().to;
    }

    /// Go `netip.Prefix.Compare`: family (v4 first), then the masked
    /// address, then the length, then the unmasked address. A hand-built
    /// `bits` past the family width is clamped, as by every `Prefix`
    /// operation, so `{1.2.3.4, 40}` compares equal to `{1.2.3.4, 32}`
    /// although `eql` (field-wise) says otherwise; Go has no such value
    /// (it is "invalid" and sorts first).
    pub fn compare(a: Prefix, b: Prefix) std.math.Order {
        const fa = std.meta.activeTag(a.addr);
        const fb = std.meta.activeTag(b.addr);
        if (fa != fb) return if (fa == .v4) .lt else .gt;
        const ma = a.masked();
        const mb = b.masked();
        const o1 = std.math.order(ipToInt(ma.addr), ipToInt(mb.addr));
        if (o1 != .eq) return o1;
        const o2 = std.math.order(ma.bits, mb.bits);
        if (o2 != .eq) return o2;
        return std.math.order(ipToInt(a.addr), ipToInt(b.addr));
    }

    /// netipx `ComparePrefix`: family (v4 first), then the length (shorter
    /// first), then the address. `bits` clamped as in `compare`.
    pub fn compareLengthFirst(a: Prefix, b: Prefix) std.math.Order {
        const fa = std.meta.activeTag(a.addr);
        const fb = std.meta.activeTag(b.addr);
        if (fa != fb) return if (fa == .v4) .lt else .gt;
        const o = std.math.order(@min(a.bits, a.width()), @min(b.bits, b.width()));
        if (o != .eq) return o;
        return std.math.order(ipToInt(a.addr), ipToInt(b.addr));
    }

    /// `{f}` formatting: the `formatPrefix` text.
    pub fn format(p: Prefix, w: *std.Io.Writer) std.Io.Writer.Error!void {
        var buf: [max_prefix_text_len]u8 = undefined;
        try w.writeAll(formatPrefix(p, &buf));
    }

    /// Iterate every address in the prefix, network to last address.
    /// Caller-driven and allocation-free; host bits are masked away first.
    pub fn addresses(p: Prefix) AddrIterator {
        const r = p.range();
        return .{
            .family = std.meta.activeTag(p.addr),
            .cur = ipToInt(r.from),
            .last = ipToInt(r.to),
        };
    }
};

/// Parse CIDR notation (`192.0.2.0/24`, `2001:db8::/32`). The address part
/// may carry host bits (tolerated; see `Prefix.masked`); the prefix length
/// must be decimal without leading zeros and at most 32 for v4 / 128 for v6.
/// Returns null on malformed input; never panics.
pub fn parsePrefix(text: []const u8) ?Prefix {
    const slash = std.mem.indexOfScalar(u8, text, '/') orelse return null;
    const addr = parseIp(text[0..slash]) orelse return null;
    const bits_text = text[slash + 1 ..];
    if (bits_text.len == 0 or bits_text.len > 3) return null;
    if (bits_text.len > 1 and bits_text[0] == '0') return null;
    var v: u16 = 0;
    for (bits_text) |c| {
        if (c < '0' or c > '9') return null;
        v = v * 10 + (c - '0');
    }
    if (v > widthOf(addr)) return null;
    return .{ .addr = addr, .bits = @intCast(v) };
}

/// Format as CIDR notation, the address part canonical per `formatIp`.
///
/// Array pointer rather than slice for the same reason as `formatIp`: the size
/// requirement is checked by the compiler, not by an assert that disappears in
/// the release modes.
///
/// `p.bits` is clamped to the family width before printing (F6, audit
/// 2026-09-04): every other `Prefix` operation already clamps internally
/// (`masked`, `netMask`, `hostCount`, ...), but this one printed the raw
/// field. A hand-built `Prefix{ .addr = v4, .bits = 200 }` -- unreachable
/// through `parsePrefix`, which rejects `bits > width` up front, but not
/// through the struct literal -- used to format as e.g. `192.0.2.1/200`,
/// text that `parsePrefix` itself then refused to read back.
pub fn formatPrefix(p: Prefix, buf: *[max_prefix_text_len]u8) []const u8 {
    const ip_text = formatIp(p.addr, buf[0..max_ip_text_len]);
    const bits = @min(p.bits, p.width());
    const bits_text = std.fmt.bufPrint(buf[ip_text.len..], "/{d}", .{bits}) catch unreachable;
    return buf[0 .. ip_text.len + bits_text.len];
}

/// Parse an address or a prefix, keeping only the address (netipx
/// `ParsePrefixOrAddr`): `192.0.2.1` and `192.0.2.1/24` both give
/// `192.0.2.1` — the address as written, host bits kept. A bare address
/// may carry a zone (`parseIpZoned`); a prefix may not (`parsePrefix`).
pub fn parsePrefixOrAddr(text: []const u8) ?ZonedIp {
    if (std.mem.indexOfScalar(u8, text, '/') != null) return .{ .ip = (parsePrefix(text) orelse return null).addr };
    return parseIpZoned(text);
}

/// An inclusive address range (netipx `IPRange`). Well-formed when both
/// ends share a family and `from <= to` (`isValid`); every query answers
/// false/null for a malformed one, `summarize` rejects it with
/// `InvalidRange`.
pub const IpRange = struct {
    from: Ip,
    to: Ip,

    pub fn isValid(r: IpRange) bool {
        return std.meta.activeTag(r.from) == std.meta.activeTag(r.to) and
            ipToInt(r.from) <= ipToInt(r.to);
    }

    pub fn eql(a: IpRange, b: IpRange) bool {
        return a.from.eql(b.from) and a.to.eql(b.to);
    }

    /// True when `ip` lies in `[from, to]`; always false across families.
    pub fn contains(r: IpRange, ip: Ip) bool {
        if (!r.isValid() or std.meta.activeTag(ip) != std.meta.activeTag(r.from)) return false;
        const v = ipToInt(ip);
        return ipToInt(r.from) <= v and v <= ipToInt(r.to);
    }

    /// True when the ranges share an address; false across families or
    /// when either is malformed.
    pub fn overlaps(a: IpRange, b: IpRange) bool {
        if (!a.isValid() or !b.isValid()) return false;
        if (std.meta.activeTag(a.from) != std.meta.activeTag(b.from)) return false;
        return ipToInt(a.from) <= ipToInt(b.to) and ipToInt(b.from) <= ipToInt(a.to);
    }

    /// The range as one prefix when it is exactly one (netipx
    /// `IPRange.Prefix`); null otherwise or when malformed.
    pub fn toPrefix(r: IpRange) ?Prefix {
        if (!r.isValid()) return null;
        const fam = std.meta.activeTag(r.from);
        const from = ipToInt(r.from);
        const to = ipToInt(r.to);
        const w = widthOf(r.from);
        const h = rangeBlockBits(w, from, to);
        if (from + hostMask(w, w - h) != to) return null;
        return .{ .addr = ipFromInt(fam, from), .bits = w - h };
    }

    /// The minimal prefix list covering the range — `summarize` (netipx
    /// `IPRange.Prefixes`). Caller owns the slice.
    pub fn prefixes(r: IpRange, gpa: std.mem.Allocator) SummarizeError![]Prefix {
        return summarize(gpa, r);
    }

    /// `{f}` formatting: the `formatIpRange` text.
    pub fn format(r: IpRange, w: *std.Io.Writer) std.Io.Writer.Error!void {
        var buf: [max_ip_range_text_len]u8 = undefined;
        try w.writeAll(formatIpRange(r, &buf));
    }
};

/// Parse `from-to` (netipx `ParseIPRange`): two addresses split at the first
/// `-`, no spaces, same family, `from <= to`. As in netipx a zone on either
/// end is accepted and dropped — a range is zone-less. Null otherwise.
pub fn parseIpRange(text: []const u8) ?IpRange {
    const dash = std.mem.indexOfScalar(u8, text, '-') orelse return null;
    const from = parseIpZoned(text[0..dash]) orelse return null;
    const to = parseIpZoned(text[dash + 1 ..]) orelse return null;
    const r: IpRange = .{ .from = from.ip, .to = to.ip };
    return if (r.isValid()) r else null;
}

/// Enough for any output of `formatIpRange`.
pub const max_ip_range_text_len = 2 * max_ip_text_len + 1;

/// `from-to`, both ends per `formatIp` (the form `parseIpRange` reads).
pub fn formatIpRange(r: IpRange, buf: *[max_ip_range_text_len]u8) []const u8 {
    const a = formatIp(r.from, buf[0..max_ip_text_len]);
    buf[a.len] = '-';
    const b = formatIp(r.to, buf[a.len + 1 ..][0..max_ip_text_len]);
    return buf[0 .. a.len + 1 + b.len];
}

/// Caller-driven address iterator (see `Prefix.addresses`).
pub const AddrIterator = struct {
    family: IpFamily,
    cur: u128,
    last: u128,
    done: bool = false,

    pub fn next(it: *AddrIterator) ?Ip {
        if (it.done) return null;
        const ip = ipFromInt(it.family, it.cur);
        if (it.cur == it.last) it.done = true else it.cur += 1;
        return ip;
    }
};

pub const SummarizeError = error{ OutOfMemory, InvalidRange };

/// Aggregate an inclusive range into the minimal ordered list of CIDR
/// prefixes covering exactly that range (the netipx range-summarize
/// algorithm). `InvalidRange` on a family mismatch or `from > to`. Caller
/// owns the returned slice.
pub fn summarize(gpa: std.mem.Allocator, r: IpRange) SummarizeError![]Prefix {
    const fam = std.meta.activeTag(r.from);
    if (fam != std.meta.activeTag(r.to)) return error.InvalidRange;
    const from = ipToInt(r.from);
    const to = ipToInt(r.to);
    if (from > to) return error.InvalidRange;
    var out: std.ArrayList(Prefix) = .empty;
    errdefer out.deinit(gpa);
    try appendRangePrefixes(gpa, &out, fam, from, to);
    return out.toOwnedSlice(gpa);
}

/// Append the minimal prefixes covering `[from, to]` (in-family values,
/// `from <= to`). Greedy: at each step emit the largest block that starts at
/// `from` (limited by alignment) and still fits inside the range.
fn appendRangePrefixes(
    gpa: std.mem.Allocator,
    out: *std.ArrayList(Prefix),
    fam: IpFamily,
    from: u128,
    to: u128,
) error{OutOfMemory}!void {
    const w: u8 = switch (fam) {
        .v4 => 32,
        .v6 => 128,
    };
    var cur = from;
    while (true) {
        const h = rangeBlockBits(w, cur, to);
        try out.append(gpa, .{ .addr = ipFromInt(fam, cur), .bits = w - h });
        const block_last = cur + hostMask(w, w - h); // cur is 2^h-aligned: no overflow
        if (block_last >= to) return;
        cur = block_last + 1;
    }
}

/// Host bits of the largest block that starts at `cur` and fits in
/// `[cur, to]` (`cur <= to`, both within a `w`-bit family): limited by the
/// alignment of `cur` (trailing zeros) and by how much of the range remains.
fn rangeBlockBits(w: u8, cur: u128, to: u128) u8 {
    const tz: u8 = @min(w, @ctz(cur));
    const span = to - cur;
    const avail: u8 = if (span == std.math.maxInt(u128))
        128 // whole v6 space; span + 1 would overflow
    else
        @intCast(127 - @clz(span + 1)); // floor(log2(addresses left))
    return @min(tz, avail);
}

const RangeKey = struct { fam: IpFamily, from: u128, to: u128 };

fn rangeKeyLess(_: void, a: RangeKey, b: RangeKey) bool {
    if (a.fam != b.fam) return @intFromEnum(a.fam) < @intFromEnum(b.fam);
    if (a.from != b.from) return a.from < b.from;
    return a.to < b.to;
}

/// Coalesce a prefix list: mask every prefix, then merge overlapping and
/// adjacent ones into the minimal equivalent prefix list (the netipx IPSet
/// normalize step). v4 and v6 never merge with each other; the result is
/// sorted (v4 first, then by address). Caller owns the returned slice.
pub fn mergePrefixes(gpa: std.mem.Allocator, prefixes: []const Prefix) error{OutOfMemory}![]Prefix {
    const ranges = try gpa.alloc(RangeKey, prefixes.len);
    defer gpa.free(ranges);
    for (prefixes, ranges) |p, *rk| {
        const r = p.range();
        rk.* = .{
            .fam = std.meta.activeTag(p.addr),
            .from = ipToInt(r.from),
            .to = ipToInt(r.to),
        };
    }
    std.sort.pdq(RangeKey, ranges, {}, rangeKeyLess);

    var out: std.ArrayList(Prefix) = .empty;
    errdefer out.deinit(gpa);
    var i: usize = 0;
    while (i < ranges.len) {
        const fam = ranges[i].fam;
        const from = ranges[i].from;
        var to = ranges[i].to;
        var j = i + 1;
        // Absorb every overlapping or directly adjacent range. When `to` is
        // the family maximum the first clause already matches everything, so
        // `to + 1` below can never overflow.
        while (j < ranges.len and ranges[j].fam == fam and
            (ranges[j].from <= to or ranges[j].from == to + 1)) : (j += 1)
        {
            to = @max(to, ranges[j].to);
        }
        try appendRangePrefixes(gpa, &out, fam, from, to);
        i = j;
    }
    return out.toOwnedSlice(gpa);
}

// ── address sets ────────────────────────────────────────────────────────────
//
// netipx `IPSet` / `IPSetBuilder`, behaviour only (clean-room). A set is a
// sorted list of disjoint, non-adjacent inclusive ranges — v4 before v6,
// each family in address order — so membership is a binary search and
// every set operation a linear merge. The v4/v6 split is strict as
// everywhere here: a v4 set never contains an IPv4-mapped v6 address.

/// A queryable, immutable set of addresses. Build one with `IpSetBuilder`;
/// `IpSet.empty` is the empty set. Owns its storage (`deinit`); read-only
/// queries are safe from many threads at once.
pub const IpSet = struct {
    /// Sorted, disjoint, non-adjacent; v4 spans before v6. Internal — read
    /// through `rangeCount`/`rangeAt`, `ranges` or `prefixes`.
    spans: []const RangeKey = &.{},

    pub const empty: IpSet = .{};

    pub fn deinit(s: *IpSet, gpa: std.mem.Allocator) void {
        gpa.free(s.spans);
        s.* = .empty;
    }

    pub fn isEmpty(s: IpSet) bool {
        return s.spans.len == 0;
    }

    /// Number of maximal ranges in the set.
    pub fn rangeCount(s: IpSet) usize {
        return s.spans.len;
    }

    /// The `i`-th maximal range (`i < rangeCount()`), in set order.
    pub fn rangeAt(s: IpSet, i: usize) IpRange {
        const k = s.spans[i];
        return .{ .from = ipFromInt(k.fam, k.from), .to = ipFromInt(k.fam, k.to) };
    }

    /// Every maximal range, in order (netipx `Ranges`). Caller owns it.
    pub fn ranges(s: IpSet, gpa: std.mem.Allocator) error{OutOfMemory}![]IpRange {
        const out = try gpa.alloc(IpRange, s.spans.len);
        for (out, 0..) |*r, i| r.* = s.rangeAt(i);
        return out;
    }

    /// The minimal prefix list equal to the set, in order (netipx
    /// `Prefixes`). Caller owns it.
    pub fn prefixes(s: IpSet, gpa: std.mem.Allocator) error{OutOfMemory}![]Prefix {
        var out: std.ArrayList(Prefix) = .empty;
        errdefer out.deinit(gpa);
        for (s.spans) |k| try appendRangePrefixes(gpa, &out, k.fam, k.from, k.to);
        return out.toOwnedSlice(gpa);
    }

    pub fn contains(s: IpSet, ip: Ip) bool {
        const fam = std.meta.activeTag(ip);
        const v = ipToInt(ip);
        const i = firstSpanEndingAtOrAfter(s.spans, fam, v);
        return i < s.spans.len and s.spans[i].fam == fam and s.spans[i].from <= v;
    }

    /// True when every address of `r` is in the set; false for a malformed
    /// range.
    pub fn containsRange(s: IpSet, r: IpRange) bool {
        if (!r.isValid()) return false;
        const fam = std.meta.activeTag(r.from);
        const from = ipToInt(r.from);
        const i = firstSpanEndingAtOrAfter(s.spans, fam, from);
        return i < s.spans.len and s.spans[i].fam == fam and
            s.spans[i].from <= from and ipToInt(r.to) <= s.spans[i].to;
    }

    pub fn containsPrefix(s: IpSet, p: Prefix) bool {
        return s.containsRange(p.range());
    }

    /// True when the set shares an address with `r`; false for a malformed
    /// range.
    pub fn overlapsRange(s: IpSet, r: IpRange) bool {
        if (!r.isValid()) return false;
        const fam = std.meta.activeTag(r.from);
        const i = firstSpanEndingAtOrAfter(s.spans, fam, ipToInt(r.from));
        return i < s.spans.len and s.spans[i].fam == fam and s.spans[i].from <= ipToInt(r.to);
    }

    pub fn overlapsPrefix(s: IpSet, p: Prefix) bool {
        return s.overlapsRange(p.range());
    }

    /// True when the two sets share an address.
    pub fn overlaps(a: IpSet, b: IpSet) bool {
        var i: usize = 0;
        var j: usize = 0;
        while (i < a.spans.len and j < b.spans.len) {
            const x = a.spans[i];
            const y = b.spans[j];
            if (x.fam == y.fam and x.from <= y.to and y.from <= x.to) return true;
            if (spanEndsBefore(x, y)) i += 1 else j += 1;
        }
        return false;
    }

    pub fn eql(a: IpSet, b: IpSet) bool {
        if (a.spans.len != b.spans.len) return false;
        for (a.spans, b.spans) |x, y| {
            if (x.fam != y.fam or x.from != y.from or x.to != y.to) return false;
        }
        return true;
    }

    pub const FreePrefix = struct { prefix: Prefix, rest: IpSet };

    /// Take a `bits`-long prefix out of the set (netipx `RemoveFreePrefix`):
    /// among the set's `prefixes()`, the longest one no longer than `bits`
    /// (the tightest fit; on a tie the first in set order) gives up its
    /// first `bits`-long subprefix. Returns that prefix and the set without
    /// it (a new set the caller owns; `s` is unchanged), or null when no
    /// prefix of the set is that large or `bits` exceeds every family's
    /// width. netipx answers `bits` > 128 with "ok" and an invalid prefix;
    /// here that is null.
    pub fn removeFreePrefix(s: IpSet, gpa: std.mem.Allocator, bits: u8) error{OutOfMemory}!?FreePrefix {
        var best: ?Prefix = null;
        for (s.spans) |k| {
            const w: u8 = if (k.fam == .v4) 32 else 128;
            if (bits > w) continue;
            var cur = k.from;
            while (true) {
                const h = rangeBlockBits(w, cur, k.to);
                const pbits = w - h;
                if (pbits <= bits and (best == null or pbits > best.?.bits))
                    best = .{ .addr = ipFromInt(k.fam, cur), .bits = pbits };
                const last = cur + hostMask(w, pbits);
                if (last >= k.to) break;
                cur = last + 1;
            }
        }
        const found = best orelse return null;
        const p: Prefix = .{ .addr = found.addr, .bits = bits };
        var b: IpSetBuilder = .empty;
        defer b.deinit(gpa);
        try b.addSet(gpa, s);
        try b.removePrefix(gpa, p);
        return .{ .prefix = p, .rest = try b.toSet(gpa) };
    }
};

/// Index of the first span whose end is at or after `(fam, v)`.
fn firstSpanEndingAtOrAfter(spans: []const RangeKey, fam: IpFamily, v: u128) usize {
    var lo: usize = 0;
    var hi: usize = spans.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const k = spans[mid];
        const before = @intFromEnum(k.fam) < @intFromEnum(fam) or (k.fam == fam and k.to < v);
        if (before) lo = mid + 1 else hi = mid;
    }
    return lo;
}

/// `x` ends before `y` ends, in set order (family, then end address).
fn spanEndsBefore(x: RangeKey, y: RangeKey) bool {
    if (x.fam != y.fam) return @intFromEnum(x.fam) < @intFromEnum(y.fam);
    return x.to < y.to;
}

/// Builds an `IpSet` (netipx `IPSetBuilder`). Adds and removes apply in
/// call order — a removal affects only what was added before it — and
/// inputs may overlap in any way. Operations are batched: adds are
/// collected and normalised (sort + merge, O(n log n)) when a removal,
/// `complement`, `intersect` or `toSet` needs the current membership. Each
/// switch from removing back to adding applies the pending removals (O(n)),
/// so a caller that alternates single adds and removes pays O(n) per
/// switch — group the adds, then the removes, where the order allows.
/// `IpSetBuilder.empty` is the empty builder; `deinit` frees it, and it
/// stays usable after `toSet`.
///
/// Errors are returned at the call, not accumulated as netipx does: the
/// only invalid input is a malformed `IpRange` (`InvalidRange`), and a
/// `Prefix` with `bits` past its family width is clamped like every other
/// `Prefix` operation.
pub const IpSetBuilder = struct {
    in: std.ArrayList(RangeKey) = .empty,
    out: std.ArrayList(RangeKey) = .empty,
    /// `in` is sorted, disjoint and non-adjacent.
    normal: bool = true,

    pub const empty: IpSetBuilder = .{};
    pub const Error = error{ OutOfMemory, InvalidRange };

    pub fn deinit(b: *IpSetBuilder, gpa: std.mem.Allocator) void {
        b.in.deinit(gpa);
        b.out.deinit(gpa);
        b.* = .empty;
    }

    pub fn clone(b: *const IpSetBuilder, gpa: std.mem.Allocator) error{OutOfMemory}!IpSetBuilder {
        var c: IpSetBuilder = .{ .normal = b.normal };
        errdefer c.deinit(gpa);
        try c.in.appendSlice(gpa, b.in.items);
        try c.out.appendSlice(gpa, b.out.items);
        return c;
    }

    pub fn add(b: *IpSetBuilder, gpa: std.mem.Allocator, ip: Ip) error{OutOfMemory}!void {
        try b.addKey(gpa, keyOfIp(ip));
    }

    pub fn addPrefix(b: *IpSetBuilder, gpa: std.mem.Allocator, p: Prefix) error{OutOfMemory}!void {
        try b.addKey(gpa, keyOfPrefix(p));
    }

    pub fn addRange(b: *IpSetBuilder, gpa: std.mem.Allocator, r: IpRange) Error!void {
        try b.addKey(gpa, try keyOfRange(r));
    }

    pub fn addSet(b: *IpSetBuilder, gpa: std.mem.Allocator, s: IpSet) error{OutOfMemory}!void {
        if (b.out.items.len != 0) try b.flush(gpa);
        try b.in.appendSlice(gpa, s.spans);
        b.normal = false;
    }

    pub fn remove(b: *IpSetBuilder, gpa: std.mem.Allocator, ip: Ip) error{OutOfMemory}!void {
        try b.out.append(gpa, keyOfIp(ip));
    }

    pub fn removePrefix(b: *IpSetBuilder, gpa: std.mem.Allocator, p: Prefix) error{OutOfMemory}!void {
        try b.out.append(gpa, keyOfPrefix(p));
    }

    pub fn removeRange(b: *IpSetBuilder, gpa: std.mem.Allocator, r: IpRange) Error!void {
        try b.out.append(gpa, try keyOfRange(r));
    }

    pub fn removeSet(b: *IpSetBuilder, gpa: std.mem.Allocator, s: IpSet) error{OutOfMemory}!void {
        try b.out.appendSlice(gpa, s.spans);
    }

    /// Replace the contents with everything NOT in them — over both
    /// families: the complement of the empty builder is `0.0.0.0/0` + `::/0`.
    pub fn complement(b: *IpSetBuilder, gpa: std.mem.Allocator) error{OutOfMemory}!void {
        try b.flush(gpa);
        const universe = [_]RangeKey{
            .{ .fam = .v4, .from = 0, .to = std.math.maxInt(u32) },
            .{ .fam = .v6, .from = 0, .to = std.math.maxInt(u128) },
        };
        var next: std.ArrayList(RangeKey) = .empty;
        errdefer next.deinit(gpa);
        try subtractSpans(gpa, &next, &universe, b.in.items);
        b.in.deinit(gpa);
        b.in = next;
    }

    /// Keep only the addresses that are also in `s`.
    pub fn intersect(b: *IpSetBuilder, gpa: std.mem.Allocator, s: IpSet) error{OutOfMemory}!void {
        try b.flush(gpa);
        var next: std.ArrayList(RangeKey) = .empty;
        errdefer next.deinit(gpa);
        var i: usize = 0;
        var j: usize = 0;
        while (i < b.in.items.len and j < s.spans.len) {
            const x = b.in.items[i];
            const y = s.spans[j];
            if (x.fam == y.fam) {
                const lo = @max(x.from, y.from);
                const hi = @min(x.to, y.to);
                if (lo <= hi) try next.append(gpa, .{ .fam = x.fam, .from = lo, .to = hi });
            }
            if (spanEndsBefore(x, y)) i += 1 else j += 1;
        }
        b.in.deinit(gpa);
        b.in = next;
    }

    /// The current contents as an `IpSet` the caller owns (netipx `IPSet`).
    pub fn toSet(b: *IpSetBuilder, gpa: std.mem.Allocator) error{OutOfMemory}!IpSet {
        try b.flush(gpa);
        return .{ .spans = try gpa.dupe(RangeKey, b.in.items) };
    }

    fn addKey(b: *IpSetBuilder, gpa: std.mem.Allocator, k: RangeKey) error{OutOfMemory}!void {
        // A pending removal must apply to what was added before it only.
        if (b.out.items.len != 0) try b.flush(gpa);
        try b.in.append(gpa, k);
        b.normal = false;
    }

    /// Normalise `in`, then apply and clear the pending removals.
    fn flush(b: *IpSetBuilder, gpa: std.mem.Allocator) error{OutOfMemory}!void {
        if (!b.normal) {
            normalizeSpans(&b.in);
            b.normal = true;
        }
        if (b.out.items.len == 0) return;
        normalizeSpans(&b.out);
        var next: std.ArrayList(RangeKey) = .empty;
        errdefer next.deinit(gpa);
        try subtractSpans(gpa, &next, b.in.items, b.out.items);
        b.in.deinit(gpa);
        b.in = next;
        b.out.clearRetainingCapacity();
    }
};

fn keyOfIp(ip: Ip) RangeKey {
    const v = ipToInt(ip);
    return .{ .fam = std.meta.activeTag(ip), .from = v, .to = v };
}

fn keyOfPrefix(p: Prefix) RangeKey {
    const r = p.range();
    return .{ .fam = std.meta.activeTag(p.addr), .from = ipToInt(r.from), .to = ipToInt(r.to) };
}

fn keyOfRange(r: IpRange) error{InvalidRange}!RangeKey {
    if (!r.isValid()) return error.InvalidRange;
    return .{ .fam = std.meta.activeTag(r.from), .from = ipToInt(r.from), .to = ipToInt(r.to) };
}

/// Sort, then merge overlapping and adjacent spans in place.
fn normalizeSpans(list: *std.ArrayList(RangeKey)) void {
    const items = list.items;
    if (items.len == 0) return;
    std.sort.pdq(RangeKey, items, {}, rangeKeyLess);
    var w: usize = 0;
    for (items[1..]) |k| {
        const cur = &items[w];
        // `cur.to` at the family maximum matches the first clause, so
        // `cur.to + 1` is never evaluated there.
        if (k.fam == cur.fam and (k.from <= cur.to or k.from == cur.to + 1)) {
            cur.to = @max(cur.to, k.to);
        } else {
            w += 1;
            items[w] = k;
        }
    }
    list.shrinkRetainingCapacity(w + 1);
}

/// Append `a \ b` to `out`; both inputs normalised, so is the result.
fn subtractSpans(
    gpa: std.mem.Allocator,
    out: *std.ArrayList(RangeKey),
    a: []const RangeKey,
    b: []const RangeKey,
) error{OutOfMemory}!void {
    var j: usize = 0;
    for (a) |x| {
        // Skip what ends before `x` begins; it cannot touch later spans either.
        while (j < b.len and (@intFromEnum(b[j].fam) < @intFromEnum(x.fam) or
            (b[j].fam == x.fam and b[j].to < x.from))) j += 1;
        var cur = x.from;
        var covered = false;
        var k = j;
        while (k < b.len and b[k].fam == x.fam and b[k].from <= x.to) : (k += 1) {
            if (b[k].from > cur) try out.append(gpa, .{ .fam = x.fam, .from = cur, .to = b[k].from - 1 });
            if (b[k].to >= x.to) {
                covered = true;
                break;
            }
            cur = b[k].to + 1; // b[k].to < x.to <= max: no overflow
        }
        if (!covered) try out.append(gpa, .{ .fam = x.fam, .from = cur, .to = x.to });
        j = k;
    }
}

// ── RFC 6724 classification ─────────────────────────────────────────────────

/// RFC 4007 address scope. Backed by the on-the-wire multicast scope values
/// so unnamed multicast scopes pass through numerically (mirrors Go's
/// `classifyScope`), and so `<`/`>` compare "smaller scope" correctly.
pub const Scope = enum(u4) {
    node_local = 0x1,
    link_local = 0x2,
    admin_local = 0x4,
    site_local = 0x5,
    organization_local = 0x8,
    global = 0xe,
    _,
};

/// Classify an address's scope per RFC 6724 §3. Loopback counts as
/// link-local (RFC 4007 §4); multicast scope is the low nibble of byte 1;
/// deprecated site-local unicast (`fec0::/10`) is honored.
pub fn scopeOf(ip: Ip) Scope {
    if (ip.isLoopback() or ip.isLinkLocalUnicast()) return .link_local;
    switch (ip) {
        .v4 => return .global,
        .v6 => |b| {
            if (Ip.isV4Mapped(b)) return .global;
            if (b[0] == 0xff) return @enumFromInt(@as(u4, @truncate(b[1])));
            if (b[0] == 0xfe and (b[1] & 0xc0) == 0xc0) return .site_local;
            return .global;
        },
    }
}

/// One row of the RFC 6724 §2.1 default policy table.
pub const Policy = struct { precedence: u8, label: u8 };

const PolicyEntry = struct { prefix: [16]u8, bits: u8, policy: Policy };

fn policyEntry(comptime prefix_text: []const u8, comptime bits: u8, precedence: u8, label: u8) PolicyEntry {
    return .{
        .prefix = comptime (parseIp6(prefix_text) orelse @compileError("bad policy prefix")),
        .bits = bits,
        .policy = .{ .precedence = precedence, .label = label },
    };
}

/// RFC 6724 §2.1 default policy table, longest prefix first (first match
/// wins). Identical rows to Go's `rfc6724policyTable`.
const policy_table = [_]PolicyEntry{
    policyEntry("::1", 128, 50, 0),
    policyEntry("::ffff:0.0.0.0", 96, 35, 4),
    policyEntry("::", 96, 1, 3),
    policyEntry("2001::", 32, 5, 5),
    policyEntry("2002::", 16, 30, 2),
    policyEntry("3ffe::", 16, 1, 12),
    policyEntry("fec0::", 10, 1, 11),
    policyEntry("fc00::", 7, 3, 13),
    policyEntry("::", 0, 40, 1),
};

/// Look up the RFC 6724 policy (precedence + label) for an address. IPv4 is
/// classified as IPv4-mapped, so plain v4 gets precedence 35 / label 4.
pub fn policyOf(ip: Ip) Policy {
    const b = ip.as16();
    for (policy_table) |e| {
        if (prefixMatches(&e.prefix, e.bits, &b)) return e.policy;
    }
    unreachable; // ::/0 matches everything
}

/// RFC 6724 §2.1 destination precedence (higher = preferred).
pub fn precedenceOf(ip: Ip) u8 {
    return policyOf(ip).precedence;
}

/// RFC 6724 §2.1 policy label (used by rule 5, "prefer matching label").
pub fn labelOf(ip: Ip) u8 {
    return policyOf(ip).label;
}

fn prefixMatches(prefix: *const [16]u8, bits: u8, b: *const [16]u8) bool {
    const full: usize = bits / 8;
    if (!std.mem.eql(u8, prefix[0..full], b[0..full])) return false;
    const rem: u3 = @intCast(bits % 8);
    if (rem == 0) return true;
    const mask = @as(u8, 0xff) << @intCast(8 - @as(u4, rem));
    return (prefix[full] & mask) == (b[full] & mask);
}

/// CommonPrefixLen(A, B) per RFC 6724 §2.2, mirroring Go: both sides are
/// unmapped first; different families → 0; IPv6 comparison is capped at the
/// first 64 bits, IPv4 at 32.
pub fn commonPrefixLen(a: Ip, b: Ip) u8 {
    const au = a.unmap();
    const bu = b.unmap();
    if (std.meta.activeTag(au) != std.meta.activeTag(bu)) return 0;
    const a16 = au.as16();
    const b16 = bu.as16();
    const range = switch (au) {
        .v4 => a16[12..16].len + 12, // bytes 12..16
        .v6 => 8, // first 64 bits only
    };
    const off: usize = switch (au) {
        .v4 => 12,
        .v6 => 0,
    };
    var cpl: u8 = 0;
    var i: usize = off;
    while (i < range) : (i += 1) {
        const x = a16[i] ^ b16[i];
        if (x == 0) {
            cpl += 8;
            continue;
        }
        cpl += @clz(x);
        break;
    }
    return cpl;
}

// ── RFC 6724 destination ordering ───────────────────────────────────────────

const Attr = struct { scope: u4, precedence: u8, label: u8 };

fn attrOf(ip: Ip) Attr {
    const p = policyOf(ip);
    return .{ .scope = @intFromEnum(scopeOf(ip)), .precedence = p.precedence, .label = p.label };
}

fn attrOfSource(ip: ?Ip) Attr {
    const i = ip orelse return .{ .scope = 0, .precedence = 0, .label = 0 };
    return attrOf(i);
}

/// RFC 6724 §6 pairwise comparison: should destination `da` (with selected
/// source `sa`, null = unusable) be tried before `db`? Implements rules
/// 1/2/5/6/8/9; rules 3/4/7 need OS state we don't track (same as Go).
/// Returning false for equal pairs keeps the sort stable (rule 10).
fn destinationBefore(da: Ip, sa: ?Ip, db: Ip, sb: ?Ip) bool {
    // Rule 1: avoid unusable destinations.
    if (sa != null and sb == null) return true;
    if (sa == null and sb != null) return false;

    const ada = attrOf(da);
    const adb = attrOf(db);
    const asa = attrOfSource(sa);
    const asb = attrOfSource(sb);

    // Rule 2: prefer matching scope.
    const a_scope_match = ada.scope == asa.scope;
    const b_scope_match = adb.scope == asb.scope;
    if (a_scope_match and !b_scope_match) return true;
    if (!a_scope_match and b_scope_match) return false;

    // Rule 3 (avoid deprecated) + rule 4 (prefer home): not implemented.

    // Rule 5: prefer matching label.
    const a_label_match = ada.label == asa.label;
    const b_label_match = adb.label == asb.label;
    if (a_label_match and !b_label_match) return true;
    if (!a_label_match and b_label_match) return false;

    // Rule 6: prefer higher precedence.
    if (ada.precedence > adb.precedence) return true;
    if (ada.precedence < adb.precedence) return false;

    // Rule 7 (prefer native transport): not implemented.

    // Rule 8: prefer smaller scope.
    if (ada.scope < adb.scope) return true;
    if (ada.scope > adb.scope) return false;

    // Rule 9: use longest matching prefix — IPv6 only, like Go (applying it
    // to IPv4 misorders common subnets; see Go issues 13283/18518).
    if (da == .v6 and db == .v6 and sa != null and sb != null) {
        const ca = commonPrefixLen(sa.?, da);
        const cb = commonPrefixLen(sb.?, db);
        if (ca > cb) return true;
        if (ca < cb) return false;
    }

    // Rule 10: leave order unchanged.
    return false;
}

/// Stable in-place sort of destination candidates into RFC 6724 connect
/// order, given the source address the OS would pick per destination
/// (`srcs[i]` pairs with `dsts[i]`, null = destination unusable / no route).
/// Both slices are permuted in tandem. Pure and allocation-free — this is the
/// Go `sortByRFC6724withSrcs` shape, ideal for tests and for callers that
/// already know their sources.
///
/// Returns `error.MismatchedLengths` when `dsts.len != srcs.len`. That is an
/// error and not `std.debug.assert` on purpose: both slices are caller-
/// supplied and independent, so nothing but the assert kept `srcs[i]` (and
/// the `srcs[j] = srcs[j - 1]` shuffle below) inside `srcs`'s own bounds —
/// and ReleaseFast compiles the assert and the bounds check out together, so
/// a shorter `srcs` became an out-of-bounds read/write in the build that
/// ships.
pub fn sortDestinationsWithSources(dsts: []Ip, srcs: []?Ip) error{MismatchedLengths}!void {
    if (dsts.len != srcs.len) return error.MismatchedLengths;
    if (dsts.len < 2) return;
    // Insertion sort: stable (rule 10), no scratch, and candidate lists from
    // DNS are tiny so O(n²) comparisons are irrelevant.
    var i: usize = 1;
    while (i < dsts.len) : (i += 1) {
        const d = dsts[i];
        const s = srcs[i];
        var j = i;
        while (j > 0 and destinationBefore(d, s, dsts[j - 1], srcs[j - 1])) : (j -= 1) {
            dsts[j] = dsts[j - 1];
            srcs[j] = srcs[j - 1];
        }
        dsts[j] = d;
        srcs[j] = s;
    }
}

/// Upper bound on `sortDestinations` candidates (keeps it allocation-free).
pub const max_sort_candidates = 64;

/// Sort `dsts` in place into RFC 6724 connect-preference order. `srcFor`
/// returns the source address the OS would use to reach a destination, or
/// null when the destination is unusable (no route) — pass `systemSource` on
/// Linux for glibc-getaddrinfo-like behavior. Each destination is probed
/// exactly once.
///
/// Returns `error.TooManyCandidates` when `dsts.len > max_sort_candidates`.
/// That is an error and not `std.debug.assert` on purpose: the scratch array
/// below is a fixed 64-slot **stack** array, ReleaseFast compiles both the
/// assert and the bounds check out, and `dsts` is typically a resolver's
/// answer set — data off the wire. A hostname with more than 64 address
/// records would have written past a stack buffer. Callers that would rather
/// sort a prefix than fail can slice to `max_sort_candidates` themselves;
/// silently sorting part of the set would answer a different question.
pub fn sortDestinations(dsts: []Ip, srcFor: *const fn (Ip) ?Ip) error{TooManyCandidates}!void {
    if (dsts.len > max_sort_candidates) return error.TooManyCandidates;
    if (dsts.len < 2) return;
    var srcs: [max_sort_candidates]?Ip = undefined;
    for (dsts, 0..) |d, i| srcs[i] = srcFor(d);
    sortDestinationsWithSources(dsts, srcs[0..dsts.len]) catch unreachable; // lengths match by construction
}

/// Ask the OS which source address it would pick for `dst`: connect() on a
/// UDP socket performs a route lookup without sending a packet, then
/// getsockname() reveals the chosen source — the trick glibc's getaddrinfo
/// uses for its RFC 6724 rules. Returns null when the destination is
/// unreachable (or the address family is unavailable). Linux-only (raw
/// syscalls, no libc, no std.Io instance needed).
pub fn systemSource(dst: Ip) ?Ip {
    if (comptime builtin.os.tag != .linux)
        @compileError("netaddr.systemSource is Linux-only (UDP-connect route probe)");
    const linux = std.os.linux;
    const fam: u32 = switch (dst) {
        .v4 => linux.AF.INET,
        .v6 => linux.AF.INET6,
    };
    const rc = linux.socket(fam, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return null;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);

    const port_discard = std.mem.nativeToBig(u16, 9); // any port works
    switch (dst) {
        .v4 => |q| {
            var sa: linux.sockaddr.in = .{ .port = port_discard, .addr = @bitCast(q) };
            if (linux.errno(linux.connect(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in))) != .SUCCESS)
                return null;
            var out: linux.sockaddr.in = undefined;
            var len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
            if (linux.errno(linux.getsockname(fd, @ptrCast(&out), &len)) != .SUCCESS)
                return null;
            return .{ .v4 = @bitCast(out.addr) };
        },
        .v6 => |b| {
            var sa: linux.sockaddr.in6 = .{ .port = port_discard, .flowinfo = 0, .addr = b, .scope_id = 0 };
            if (linux.errno(linux.connect(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in6))) != .SUCCESS)
                return null;
            var out: linux.sockaddr.in6 = undefined;
            var len: linux.socklen_t = @sizeOf(linux.sockaddr.in6);
            if (linux.errno(linux.getsockname(fd, @ptrCast(&out), &len)) != .SUCCESS)
                return null;
            return .{ .v6 = out.addr };
        },
    }
}

// ── RFC 6724 source selection ───────────────────────────────────────────────

/// Pick the best source address for `dst` out of `candidates` (e.g. the
/// host's configured addresses), per RFC 6724 §5. Returns the index of the
/// winner, or null if no candidate shares the destination's address family.
///
/// Implemented rules: 1 (same address), 2 (appropriate scope), 6 (matching
/// label), 8 (longest matching prefix). Rules needing OS state are skipped:
/// 3 (avoid deprecated), 4 (home addresses), 5 (outgoing interface),
/// 7 (temporary addresses) — same corners glibc documents and Go leaves to
/// the OS. First candidate wins ties, so pass candidates in interface order.
pub fn selectSource(candidates: []const Ip, dst: Ip) ?usize {
    const want_v4 = dst.unmap() == .v4;
    var best: ?usize = null;
    for (candidates, 0..) |c, i| {
        if ((c.unmap() == .v4) != want_v4) continue;
        if (best == null or sourceBefore(c, candidates[best.?], dst)) best = i;
    }
    return best;
}

/// RFC 6724 §5 pairwise: is source `sa` strictly better than `sb` for `dst`?
fn sourceBefore(sa: Ip, sb: Ip, dst: Ip) bool {
    // Rule 1: prefer same address.
    if (sa.eql(dst)) return true;
    if (sb.eql(dst)) return false;

    // Rule 2: prefer appropriate scope.
    const scope_a = @intFromEnum(scopeOf(sa));
    const scope_b = @intFromEnum(scopeOf(sb));
    const scope_d = @intFromEnum(scopeOf(dst));
    if (scope_a < scope_b) return scope_a >= scope_d;
    if (scope_b < scope_a) return scope_b < scope_d;

    // Rules 3/4/5 (deprecated / home / outgoing interface): not implemented.

    // Rule 6: prefer matching label.
    const label_d = labelOf(dst);
    const a_match = labelOf(sa) == label_d;
    const b_match = labelOf(sb) == label_d;
    if (a_match and !b_match) return true;
    if (!a_match and b_match) return false;

    // Rule 7 (temporary addresses): not implemented.

    // Rule 8: longest matching prefix.
    return commonPrefixLen(sa, dst) > commonPrefixLen(sb, dst);
}

// ── tests: parse/format ─────────────────────────────────────────────────────

const testing = std.testing;

fn expectRoundTrip(text: []const u8, canonical: []const u8) !void {
    const ip = parseIp(text) orelse return error.TestUnexpectedResult;
    var buf: [max_ip_text_len]u8 = undefined;
    try testing.expectEqualStrings(canonical, formatIp(ip, &buf));
    // Canonical text must re-parse to the same address.
    const again = parseIp(canonical) orelse return error.TestUnexpectedResult;
    switch (ip) {
        .v4 => try testing.expect(again == .v4 and ip.eql(again)),
        .v6 => try testing.expect(again == .v6 and ip.eql(again)),
    }
}

test {
    _ = @import("rfc6724_oracle_test.zig");
    _ = @import("parse_oracle_test.zig");
    _ = @import("netip_api_test.zig");
    _ = @import("netip_oracle_test.zig");
    _ = @import("fuzz_test.zig");
}

test "Ip.eql: a v4 address and its v4-mapped v6 form are NOT equal" {
    // TEETH for the invariant this module's whole type rests on, and with it
    // the address identity of every module that stores an `Ip`. Measured at
    // the 2026-09-04 audit pass: making `1.2.3.4` compare equal to
    // `::ffff:1.2.3.4` left the suite at **47/47 green**.
    //
    // The direction matters and it is deliberate. `Ip` is a tagged union, so
    // the two are distinct values; a consumer that wants them identified must
    // normalise first and say so. An allow-list keyed on `Ip.eql` that
    // silently identified them would accept `::ffff:127.0.0.1` wherever it
    // meant to accept only `127.0.0.1`, and the reverse for a deny-list.
    const v4 = parseIp("1.2.3.4").?;
    const mapped = parseIp("::ffff:1.2.3.4").?;
    try testing.expect(!v4.eql(mapped));
    try testing.expect(!mapped.eql(v4));

    // Loopback, because that is the pair a security guard actually meets.
    const lo4 = parseIp("127.0.0.1").?;
    const lo_mapped = parseIp("::ffff:127.0.0.1").?;
    try testing.expect(!lo4.eql(lo_mapped));

    // ...while each still equals itself, and unequal addresses of one family
    // stay unequal — so the test above cannot pass by `eql` simply being false.
    try testing.expect(v4.eql(parseIp("1.2.3.4").?));
    try testing.expect(mapped.eql(parseIp("::ffff:1.2.3.4").?));
    try testing.expect(!v4.eql(parseIp("1.2.3.5").?));
    try testing.expect(!mapped.eql(parseIp("::ffff:1.2.3.5").?));

    // The same for the v4-compatible form, which shares the low 32 bits with
    // both of the above and is a third distinct value.
    const compat = parseIp("::1.2.3.4").?;
    try testing.expect(!compat.eql(v4));
    try testing.expect(!compat.eql(mapped));
}

test "parseIp4 accepts strict dotted quads" {
    try testing.expectEqual([4]u8{ 192, 168, 0, 1 }, parseIp4("192.168.0.1").?);
    try testing.expectEqual([4]u8{ 0, 0, 0, 0 }, parseIp4("0.0.0.0").?);
    try testing.expectEqual([4]u8{ 255, 255, 255, 255 }, parseIp4("255.255.255.255").?);
}

test "parseIp4 rejects malformed input" {
    const bad = [_][]const u8{
        "",          "1",          "1.2.3",      "1.2.3.4.5", "256.1.1.1",
        "1.2.3.256", "01.2.3.4",   "1.02.3.4",   "1.2.3.04",  "1.2.3.4 ",
        " 1.2.3.4",  "1.2.3.four", "1..3.4",     ".1.2.3",    "1.2.3.",
        "1.2.3.-4",  "999.9.9.9",  "1.2.3.4/24",
    };
    for (bad) |t| try testing.expectEqual(@as(?[4]u8, null), parseIp4(t));
}

test "parseIp6 accepts valid literals" {
    // Full form.
    try testing.expect(parseIp6("2001:0db8:0000:0000:0000:0000:0000:0001") != null);
    try testing.expect(parseIp6("1:2:3:4:5:6:7:8") != null);
    // Compression.
    try testing.expectEqual([_]u8{0} ** 16, parseIp6("::").?);
    try testing.expectEqual([_]u8{0} ** 15 ++ [_]u8{1}, parseIp6("::1").?);
    try testing.expect(parseIp6("1::") != null);
    try testing.expect(parseIp6("1:2:3:4:5:6:7::") != null);
    try testing.expect(parseIp6("::1:2:3:4:5:6:7") != null);
    // Embedded IPv4.
    const mapped = parseIp6("::ffff:1.2.3.4").?;
    try testing.expectEqual([_]u8{ 1, 2, 3, 4 }, mapped[12..16].*);
    try testing.expect(parseIp6("1:2:3:4:5:6:1.2.3.4") != null);
    try testing.expect(parseIp6("::1.2.3.4") != null);
    // Case-insensitive hex.
    try testing.expectEqual(parseIp6("2001:DB8::1").?, parseIp6("2001:db8::1").?);
}

test "parseIp6 rejects malformed input" {
    const bad = [_][]const u8{
        "",                  ":",                ":::",                   "1:2:3:4:5:6:7",
        "1:2:3:4:5:6:7:8:9", "1::2::3",          "12345::",               "1:2:3:4:5:6:7:8::",
        "::1:2:3:4:5:6:7:8", "fe80::1%eth0",     "g::1",                  "1:2:3:4:5:6:1.2.3",
        "1.2.3.4::",         "::1.2.3.400",      "1:2:3:4:5:6:7:1.2.3.4", ":1::2",
        "1::2:",             "::ffff:1.2.3.4.5", "::1.2.3.4:5",
    };
    for (bad) |t| try testing.expectEqual(@as(?[16]u8, null), parseIp6(t));
}

test "formatIp canonical RFC 5952 output" {
    // v4
    try expectRoundTrip("192.168.0.1", "192.168.0.1");
    // v6 canonicalization
    try expectRoundTrip("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1");
    try expectRoundTrip("::1", "::1");
    try expectRoundTrip("::", "::");
    try expectRoundTrip("2001:db8:0:1:1:1:1:1", "2001:db8:0:1:1:1:1:1"); // no single-zero compression
    try expectRoundTrip("2001:0:0:1:0:0:0:1", "2001:0:0:1::1"); // longest run wins
    try expectRoundTrip("2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1"); // leftmost on tie
    try expectRoundTrip("1:0:0:4:0:0:0:8", "1:0:0:4::8");
    try expectRoundTrip("2001:DB8::ABCD", "2001:db8::abcd"); // lowercase
    try expectRoundTrip("1:2:3:4:5:6:7::", "1:2:3:4:5:6:7:0");
    // IPv4-mapped stays mixed-notation (and distinct from plain v4).
    try expectRoundTrip("::ffff:1.2.3.4", "::ffff:1.2.3.4");
    try expectRoundTrip("::1.2.3.4", "::102:304"); // v4-compatible is NOT special-cased
}

test "parseHostPort" {
    const hp = parseHostPort("example.com:8080").?;
    try testing.expectEqualStrings("example.com", hp.host);
    try testing.expectEqual(@as(u16, 8080), hp.port);

    const v4 = parseHostPort("1.2.3.4:80").?;
    try testing.expectEqualStrings("1.2.3.4", v4.host);
    try testing.expectEqual(@as(u16, 80), v4.port);

    const v6 = parseHostPort("[2001:db8::1]:443").?;
    try testing.expectEqualStrings("2001:db8::1", v6.host);
    try testing.expectEqual(@as(u16, 443), v6.port);

    const zone = parseHostPort("[fe80::1%eth0]:22").?;
    try testing.expectEqualStrings("fe80::1%eth0", zone.host);

    const bad = [_][]const u8{
        "",           "example.com",     "example.com:", ":80",    "host:x",
        "host:99999", "2001:db8::1:443", "[::1]",        "[::1]:", "[]:80",
        "[::1]80",    "host:-1",
    };
    for (bad) |t| try testing.expect(parseHostPort(t) == null);
}

// F8 (audit 2026-09-04, closed per user decision Q2-B 2026-09-11):
// `parsePort` used to keep a leading zero, unlike every other numeric field
// in this module (`parseIp4`'s octets, `parsePrefix`'s bits). Now rejected
// the same way. This test used to pin acceptance; it is flipped here to pin
// rejection, so a future regression back to the old asymmetry is a
// deliberate edit that touches this line, not a side effect nobody notices.
test "F8: parsePort's leading zero is rejected, like other numeric fields" {
    try testing.expectEqual(@as(?HostPort, null), parseHostPort("host:0080"));
    try testing.expectEqual(@as(?HostPort, null), parseHostPort("host:00000"));
    try testing.expectEqual(@as(?HostPort, null), parseHostPort("host:00"));
    // A single digit is not a *leading* zero: "0" itself must still parse.
    const hp = parseHostPort("host:0").?;
    try testing.expectEqual(@as(u16, 0), hp.port);
    const hp2 = parseHostPort("host:80").?;
    try testing.expectEqual(@as(u16, 80), hp2.port);
    // Contrast: the sibling numeric fields reject the same shape, as before.
    try testing.expectEqual(@as(?[4]u8, null), parseIp4("01.2.3.4"));
    try testing.expectEqual(@as(?Prefix, null), parsePrefix("10.0.0.0/08"));
}

// F4 (audit 2026-09-04): the three numeric sub-parsers (`parseIp4`'s octet,
// `parseIp6`'s hex group, `parsePort`) each stop overlong digit runs with a
// length check that runs BEFORE the accumulator loop, so the loop itself
// never sees enough digits to overflow its accumulator type. That length
// gate was untested on its own -- every existing bad-input case up to this
// point also fails the *value* check (`> 255`, `> width`, `> 65535`), so a
// regression that weakened only the length gate (while leaving the value
// check intact) had nothing here that would catch it. These cases are
// chosen to fail on LENGTH alone, one digit past each gate's cap, with a
// digit run that the value check could not have rejected on its own.
//
// Verified live against a mutant: dropping `parseIp4`'s `part.len > 3`
// clause (keeping the `v > 255` check) turns an 18-digit octet from a clean
// `null` into an "integer overflow" panic building `v` -- see the F4
// disposition in `A1/netaddr.md` for the measured run.
test "F4: the numeric parsers' length gates fire before their value checks would" {
    // parseIp4: an octet one digit past the 3-digit cap; a 4-digit run this
    // large would overflow the `u16` accumulator (part.len > 3) before `v`
    // could ever reach the `v > 255` check.
    try testing.expectEqual(@as(?[4]u8, null), parseIp4("1.2.3.9999"));
    try testing.expectEqual(@as(?[4]u8, null), parseIp4("65535.0.0.1"));

    // parseIp6: a hex group one digit past the 4-digit cap.
    try testing.expectEqual(@as(?[16]u8, null), parseIp6("1:2:3:4:5:6:7:80000"));

    // parsePort (via parseHostPort): one digit past the 5-digit cap -- and
    // the boundary itself (5 digits, max value) still accepted.
    try testing.expect(parseHostPort("host:100000") == null);
    try testing.expect(parseHostPort("host:65535") != null);

    // parsePrefix bits: one digit past the 3-digit cap.
    try testing.expectEqual(@as(?Prefix, null), parsePrefix("10.0.0.0/1000"));
    try testing.expectEqual(@as(?Prefix, null), parsePrefix("2001:db8::/12800"));
}

// F4 (audit 2026-09-04): the /30 boundary of the RFC 3021 first/last-host
// reservation (reserved through /30, not reserved at /31 and /32) had /31
// and /32 covered but not the last reserved width itself.
test "F4: firstHost/lastHost reserve network and broadcast through /30, not past it" {
    const p30 = mkPrefix("192.0.2.0/30"); // 4 addresses, 2 usable
    try expectIpText("192.0.2.1", p30.firstHost());
    try expectIpText("192.0.2.2", p30.lastHost());
    try testing.expect(!p30.firstHost().eql(p30.network()));
    try testing.expect(!p30.lastHost().eql(p30.broadcast().?));
}

// F4 + F6 (audit 2026-09-04): `bits > width` is unreachable through
// `parsePrefix` (it rejects `v > widthOf(addr)` up front) but not through a
// hand-built `Prefix{ .bits = 200 }` literal -- and every op that clamps
// internally needs that clamp exercised at least once from outside
// `parsePrefix`'s own guard. `formatPrefix` used to be the one operation
// that printed the raw, unclamped field (F6, fixed above): it produced
// `192.0.2.1/200`, which `parsePrefix` itself then refused to read back.
test "F4/F6: bits > width is clamped by every Prefix op, formatPrefix included" {
    const p: Prefix = .{ .addr = .{ .v4 = .{ 192, 0, 2, 1 } }, .bits = 200 };
    try testing.expectEqual(@as(u128, 1), p.hostCount()); // clamped to /32
    try testing.expect(p.isSingleIp());
    try testing.expect(p.contains(.{ .v4 = .{ 192, 0, 2, 1 } }));
    try expectPrefixText("192.0.2.1/32", p.masked());

    var buf: [max_prefix_text_len]u8 = undefined;
    const text = formatPrefix(p, &buf);
    try testing.expectEqualStrings("192.0.2.1/32", text);
    // The whole point: what formatPrefix prints, parsePrefix reads back.
    const reparsed = parsePrefix(text) orelse return error.TestUnexpectedResult;
    try testing.expect(reparsed.eql(p.masked()));
}

// ── tests: classification ───────────────────────────────────────────────────

fn mkIp(text: []const u8) Ip {
    return parseIp(text).?;
}

test "scopeOf follows RFC 6724 / Go classifyScope" {
    try testing.expectEqual(Scope.link_local, scopeOf(mkIp("::1"))); // loopback = link-local scope
    try testing.expectEqual(Scope.link_local, scopeOf(mkIp("127.0.0.1")));
    try testing.expectEqual(Scope.link_local, scopeOf(mkIp("fe80::1")));
    try testing.expectEqual(Scope.link_local, scopeOf(mkIp("169.254.1.1")));
    try testing.expectEqual(Scope.site_local, scopeOf(mkIp("fec0::1")));
    try testing.expectEqual(Scope.global, scopeOf(mkIp("2001:db8::1")));
    try testing.expectEqual(Scope.global, scopeOf(mkIp("8.8.8.8")));
    try testing.expectEqual(Scope.global, scopeOf(mkIp("::ffff:8.8.8.8")));
    try testing.expectEqual(Scope.global, scopeOf(mkIp("fd00::1"))); // ULA is global scope
    // Multicast scope = low nibble of byte 1.
    try testing.expectEqual(Scope.node_local, scopeOf(mkIp("ff01::1")));
    try testing.expectEqual(Scope.link_local, scopeOf(mkIp("ff02::1")));
    try testing.expectEqual(Scope.site_local, scopeOf(mkIp("ff05::2")));
    try testing.expectEqual(Scope.organization_local, scopeOf(mkIp("ff08::1")));
    try testing.expectEqual(Scope.global, scopeOf(mkIp("ff0e::1")));
}

test "policy precedence follows the RFC 6724 table" {
    // Core RFC 6724 precedence-table vectors…
    try testing.expectEqual(@as(u8, 50), precedenceOf(mkIp("::1")));
    try testing.expectEqual(@as(u8, 40), precedenceOf(mkIp("2606:4700::1111")));
    try testing.expectEqual(@as(u8, 35), precedenceOf(mkIp("192.0.2.1")));
    try testing.expectEqual(@as(u8, 30), precedenceOf(mkIp("2002::1")));
    try testing.expectEqual(@as(u8, 5), precedenceOf(mkIp("2001:0::1")));
    try testing.expectEqual(@as(u8, 3), precedenceOf(mkIp("fd00::1")));
    // …plus the remaining site-local / 6bone rows.
    try testing.expectEqual(@as(u8, 1), precedenceOf(mkIp("fec0::1")));
    try testing.expectEqual(@as(u8, 1), precedenceOf(mkIp("3ffe::1")));
    try testing.expectEqual(@as(u8, 1), precedenceOf(mkIp("::0.0.0.2"))); // ::/96
    try testing.expectEqual(@as(u8, 35), precedenceOf(mkIp("::ffff:8.8.8.8")));
    // 2001::/32 is Teredo only — 2001:db8:: falls through to ::/0.
    try testing.expectEqual(@as(u8, 40), precedenceOf(mkIp("2001:db8::1")));
}

test "policy labels follow the RFC 6724 table" {
    try testing.expectEqual(@as(u8, 0), labelOf(mkIp("::1")));
    try testing.expectEqual(@as(u8, 1), labelOf(mkIp("2606:4700::1111")));
    try testing.expectEqual(@as(u8, 4), labelOf(mkIp("192.0.2.1")));
    try testing.expectEqual(@as(u8, 2), labelOf(mkIp("2002::1")));
    try testing.expectEqual(@as(u8, 5), labelOf(mkIp("2001:0::1")));
    try testing.expectEqual(@as(u8, 13), labelOf(mkIp("fd00::1")));
    try testing.expectEqual(@as(u8, 11), labelOf(mkIp("fec0::1")));
    try testing.expectEqual(@as(u8, 12), labelOf(mkIp("3ffe::1")));
    try testing.expectEqual(@as(u8, 3), labelOf(mkIp("::0.0.0.2")));
}

test "commonPrefixLen per RFC 6724 §2.2" {
    // Same v6 /48 site, diverging in the 6th byte (0x01^0x02 → 6 shared bits).
    try testing.expectEqual(@as(u8, 46), commonPrefixLen(mkIp("2001:db8:1::1"), mkIp("2001:db8:2::1")));
    try testing.expectEqual(@as(u8, 48), commonPrefixLen(mkIp("2001:db8:1::1"), mkIp("2001:db8:1:ffff::1")));
    try testing.expectEqual(@as(u8, 64), commonPrefixLen(mkIp("2001:db8::1"), mkIp("2001:db8::2")));
    // v4 compares 32 bits.
    try testing.expectEqual(@as(u8, 24), commonPrefixLen(mkIp("192.168.1.1"), mkIp("192.168.1.200")));
    try testing.expectEqual(@as(u8, 32), commonPrefixLen(mkIp("10.0.0.1"), mkIp("10.0.0.1")));
    // Family mismatch → 0; mapped v4 counts as v4.
    try testing.expectEqual(@as(u8, 0), commonPrefixLen(mkIp("10.0.0.1"), mkIp("2001:db8::1")));
    try testing.expectEqual(@as(u8, 32), commonPrefixLen(mkIp("::ffff:10.0.0.1"), mkIp("10.0.0.1")));
}

// ── tests: destination ordering (RFC 6724 §10.2 vectors) ────────────────────

fn expectOrder(dsts: []Ip, srcs: []?Ip, expected: []const []const u8) !void {
    try sortDestinationsWithSources(dsts, srcs);
    for (expected, 0..) |e, i| {
        var buf: [max_ip_text_len]u8 = undefined;
        try testing.expectEqualStrings(e, formatIp(dsts[i], &buf));
    }
}

test "RFC 6724 §10.2: prefer matching scope (v6 src link-local)" {
    var dsts = [_]Ip{ mkIp("2001:db8:1::1"), mkIp("198.51.100.121") };
    var srcs = [_]?Ip{ mkIp("fe80::1"), mkIp("198.51.100.117") };
    try expectOrder(&dsts, &srcs, &.{ "198.51.100.121", "2001:db8:1::1" });
}

test "RFC 6724 §10.2: prefer higher precedence (v6 over v4)" {
    var dsts = [_]Ip{ mkIp("198.51.100.121"), mkIp("2001:db8:1::1") };
    var srcs = [_]?Ip{ mkIp("198.51.100.117"), mkIp("2001:db8:1::2") };
    try expectOrder(&dsts, &srcs, &.{ "2001:db8:1::1", "198.51.100.121" });
}

test "RFC 6724 §10.2: prefer matching scope (v4 src link-local)" {
    var dsts = [_]Ip{ mkIp("2001:db8:1::1"), mkIp("10.1.2.3") };
    var srcs = [_]?Ip{ mkIp("2001:db8:1::2"), mkIp("169.254.13.78") };
    try expectOrder(&dsts, &srcs, &.{ "2001:db8:1::1", "10.1.2.3" });
}

test "RFC 6724 §10.2: prefer smaller scope" {
    var dsts = [_]Ip{ mkIp("2001:db8:1::1"), mkIp("fe80::1") };
    var srcs = [_]?Ip{ mkIp("2001:db8:1::2"), mkIp("fe80::2") };
    try expectOrder(&dsts, &srcs, &.{ "fe80::1", "2001:db8:1::1" });
}

test "RFC 6724 rule 1: unusable destinations sink to the end" {
    var dsts = [_]Ip{ mkIp("2001:db8::1"), mkIp("10.0.0.1") };
    var srcs = [_]?Ip{ null, mkIp("10.0.0.2") };
    try expectOrder(&dsts, &srcs, &.{ "10.0.0.1", "2001:db8::1" });
}

test "RFC 6724 rule 5: prefer matching label" {
    // Both destinations global scope with matching-scope sources; 6to4 dst
    // with 6to4 src matches labels (2==2), native dst with 6to4 src does not.
    var dsts = [_]Ip{ mkIp("2001:db8:1::1"), mkIp("2002:c633:6401::1") };
    var srcs = [_]?Ip{ mkIp("2002:c633:6401::2"), mkIp("2002:c633:6401::2") };
    try expectOrder(&dsts, &srcs, &.{ "2002:c633:6401::1", "2001:db8:1::1" });
}

test "RFC 6724 rule 6: prefer higher precedence (native over 6to4)" {
    var dsts = [_]Ip{ mkIp("2002:c633:6401::1"), mkIp("2001:db8:1::1") };
    var srcs = [_]?Ip{ mkIp("2002:c633:6401::2"), mkIp("2001:db8:1::2") };
    try expectOrder(&dsts, &srcs, &.{ "2001:db8:1::1", "2002:c633:6401::1" });
}

test "RFC 6724 rule 9: longest matching prefix (v6 only)" {
    var dsts = [_]Ip{ mkIp("2001:db8:3ffe::1"), mkIp("2001:db8:1::1") };
    var srcs = [_]?Ip{ mkIp("2001:db8:3f44::2"), mkIp("2001:db8:1::2") };
    // cpl(src,dst): 40 bits vs 64 bits → the /64-sharing pair wins.
    try expectOrder(&dsts, &srcs, &.{ "2001:db8:1::1", "2001:db8:3ffe::1" });

    // The same shape in v4 must NOT reorder (rule 9 is v6-only).
    var dsts4 = [_]Ip{ mkIp("10.55.0.1"), mkIp("10.0.0.1") };
    var srcs4 = [_]?Ip{ mkIp("10.99.0.2"), mkIp("10.0.0.2") };
    try expectOrder(&dsts4, &srcs4, &.{ "10.55.0.1", "10.0.0.1" });
}

test "sort is stable for equal keys" {
    var dsts = [_]Ip{ mkIp("127.0.0.2"), mkIp("127.0.0.3") };
    var srcs = [_]?Ip{ mkIp("127.0.0.1"), mkIp("127.0.0.1") };
    try expectOrder(&dsts, &srcs, &.{ "127.0.0.2", "127.0.0.3" });
}

test "sortDestinations probes each destination once via the callback" {
    const probe = struct {
        var calls: usize = 0;
        fn srcFor(d: Ip) ?Ip {
            calls += 1;
            return switch (d) {
                .v4 => mkIp("10.0.0.99"),
                .v6 => null, // pretend v6 is unrouted
            };
        }
    };
    var dsts = [_]Ip{ mkIp("2001:db8::1"), mkIp("10.0.0.1"), mkIp("2001:db8::2") };
    try sortDestinations(&dsts, probe.srcFor);
    try testing.expectEqual(@as(usize, 3), probe.calls);
    var buf: [max_ip_text_len]u8 = undefined;
    try testing.expectEqualStrings("10.0.0.1", formatIp(dsts[0], &buf));
}

test "destination policy prefers ::1 over 127.0.0.1 like glibc" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var dsts = [_]Ip{ mkIp("127.0.0.1"), mkIp("::1") };
    // Skip on hosts with IPv6 disabled (rule 1 then demotes ::1).
    if (systemSource(dsts[1]) == null) return error.SkipZigTest;
    try sortDestinations(&dsts, systemSource);
    try testing.expect(dsts[0].eql(mkIp("::1")));
}

// `srcs` in `sortDestinations` is a fixed stack array of `max_sort_candidates`
// slots. The old guard was `std.debug.assert`, which ReleaseFast removes along
// with the bounds check -- and the slice being sorted is normally a resolver's
// answer set, i.e. off the wire. Written in terms of the constant, so it keeps
// measuring the mechanism if the bound ever moves.
test "sortDestinations: one past the candidate bound is an error, not a stack write" {
    const n = max_sort_candidates + 1;
    var dsts: [n]Ip = undefined;
    for (&dsts, 0..) |*d, i| d.* = .{ .v4 = .{ 10, 0, @intCast(i / 256), @intCast(i % 256) } };

    const S = struct {
        fn srcFor(_: Ip) ?Ip {
            return .{ .v4 = .{ 10, 0, 0, 1 } };
        }
    };
    try std.testing.expectError(error.TooManyCandidates, sortDestinations(&dsts, S.srcFor));

    // Exactly at the bound still works.
    try sortDestinations(dsts[0..max_sort_candidates], S.srcFor);
}

// sortDestinationsWithSources used to guard dsts.len == srcs.len with
// std.debug.assert, which ReleaseFast removes along with the bounds check on
// every srcs[i] read and srcs[j] = srcs[j - 1] write below it -- and both
// slices are independent caller-supplied arguments, so nothing else kept
// srcs in bounds. A caller passing a shorter srcs slice (e.g. mismatched
// buffers assembled from two different sources) got an out-of-bounds
// read/write in the build that ships.
test "sortDestinationsWithSources: mismatched slice lengths are an error, not a stack write" {
    var dsts = [_]Ip{ mkIp("198.51.100.121"), mkIp("2001:db8:1::1"), mkIp("10.0.0.1") };
    var short_srcs = [_]?Ip{ mkIp("198.51.100.117"), mkIp("2001:db8:1::2") };
    try std.testing.expectError(error.MismatchedLengths, sortDestinationsWithSources(&dsts, &short_srcs));

    // Equal lengths still work.
    var matched_srcs = [_]?Ip{ mkIp("198.51.100.117"), mkIp("2001:db8:1::2"), mkIp("10.0.0.2") };
    try sortDestinationsWithSources(&dsts, &matched_srcs);
}

test "systemSource resolves a loopback source on Linux" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const src = systemSource(mkIp("127.0.0.1")) orelse return error.TestUnexpectedResult;
    try testing.expect(src.isLoopback());
}

// ── tests: source selection ─────────────────────────────────────────────────

test "selectSource: same address wins (rule 1)" {
    const cands = [_]Ip{ mkIp("2001:db8::5"), mkIp("2001:db8::7") };
    try testing.expectEqual(@as(?usize, 1), selectSource(&cands, mkIp("2001:db8::7")));
}

test "selectSource: appropriate scope (rule 2)" {
    // Global destination: prefer the global source over link-local.
    const cands = [_]Ip{ mkIp("fe80::1"), mkIp("2001:db8::1") };
    try testing.expectEqual(@as(?usize, 1), selectSource(&cands, mkIp("2606:4700::1111")));
    // Link-local destination: prefer the link-local source (smallest
    // sufficient scope).
    try testing.expectEqual(@as(?usize, 0), selectSource(&cands, mkIp("fe80::99")));
}

test "selectSource: appropriate scope (rule 2), candidate scope order reversed" {
    // `sourceBefore`'s scope check has two symmetric branches
    // (`scope_a < scope_b` and `scope_b < scope_a`); the tests above only
    // ever compare a later, *larger*-scope candidate against an earlier,
    // smaller-scope one, so the `scope_a < scope_b` branch (later candidate
    // has the SMALLER scope) never runs. Put the global address first and
    // the link-local one second to force it.
    const cands = [_]Ip{ mkIp("2001:db8::1"), mkIp("fe80::1") };
    // Global destination: the global candidate (already best) must stay
    // best — scope_a(link) >= scope_d(global) is false.
    try testing.expectEqual(@as(?usize, 0), selectSource(&cands, mkIp("2606:4700::1111")));
    // Link-local destination: the later, smaller-scope candidate must take
    // over — scope_a(link) >= scope_d(link) is true.
    try testing.expectEqual(@as(?usize, 1), selectSource(&cands, mkIp("fe80::99")));
}

test "selectSource: matching label (rule 6)" {
    // ULA destination (label 13): prefer the ULA source over global.
    const cands = [_]Ip{ mkIp("2001:db8::1"), mkIp("fd00:aaaa::1") };
    try testing.expectEqual(@as(?usize, 1), selectSource(&cands, mkIp("fd00:bbbb::1")));
}

test "selectSource: longest matching prefix (rule 8)" {
    const cands = [_]Ip{ mkIp("2001:db8:2::1"), mkIp("2001:db8:1::99") };
    try testing.expectEqual(@as(?usize, 1), selectSource(&cands, mkIp("2001:db8:1::1")));
}

test "selectSource: family filter" {
    const cands = [_]Ip{ mkIp("10.0.0.1"), mkIp("192.168.1.1") };
    try testing.expectEqual(@as(?usize, null), selectSource(&cands, mkIp("2001:db8::1")));
    try testing.expect(selectSource(&cands, mkIp("10.0.0.9")) != null);
}

test "Ip classification helpers" {
    try testing.expect(mkIp("127.0.0.1").isLoopback());
    try testing.expect(mkIp("::1").isLoopback());
    try testing.expect(mkIp("::ffff:127.0.0.1").isLoopback());
    try testing.expect(!mkIp("128.0.0.1").isLoopback());
    try testing.expect(mkIp("::").isUnspecified());
    try testing.expect(mkIp("0.0.0.0").isUnspecified());
    try testing.expect(mkIp("ff02::1").isMulticast());
    try testing.expect(mkIp("224.0.0.1").isMulticast());
    try testing.expect(mkIp("fe80::1").isLinkLocalUnicast());
    try testing.expect(mkIp("169.254.0.1").isLinkLocalUnicast());
    try testing.expect(mkIp("fd12::1").isUniqueLocal());
    try testing.expect(!mkIp("fe80::1").isUniqueLocal());
    try testing.expect(mkIp("::ffff:1.2.3.4").isIpv4Mapped());
    try testing.expect(!mkIp("1.2.3.4").isIpv4Mapped());
    try testing.expect(mkIp("::ffff:1.2.3.4").unmap().eql(mkIp("1.2.3.4")));
}

// ── tests: prefixes / CIDR ──────────────────────────────────────────────────

fn mkPrefix(text: []const u8) Prefix {
    return parsePrefix(text).?;
}

fn expectPrefixText(expected: []const u8, p: Prefix) !void {
    var buf: [max_prefix_text_len]u8 = undefined;
    try testing.expectEqualStrings(expected, formatPrefix(p, &buf));
}

fn expectIpText(expected: []const u8, ip: Ip) !void {
    var buf: [max_ip_text_len]u8 = undefined;
    try testing.expectEqualStrings(expected, formatIp(ip, &buf));
}

fn expectPrefixList(expected: []const []const u8, got: []const Prefix) !void {
    try testing.expectEqual(expected.len, got.len);
    for (expected, got) |e, p| try expectPrefixText(e, p);
}

test "parsePrefix accepts CIDR notation" {
    const p4 = mkPrefix("192.0.2.0/24");
    try testing.expect(p4.addr.eql(mkIp("192.0.2.0")));
    try testing.expectEqual(@as(u8, 24), p4.bits);
    const p6 = mkPrefix("2001:db8::/32");
    try testing.expect(p6.addr.eql(mkIp("2001:db8::")));
    try testing.expectEqual(@as(u8, 32), p6.bits);
    // Host bits tolerated; /0 and full-width accepted.
    try testing.expect(parsePrefix("192.0.2.5/24") != null);
    try testing.expect(parsePrefix("0.0.0.0/0") != null);
    try testing.expect(parsePrefix("192.0.2.1/32") != null);
    try testing.expect(parsePrefix("::/0") != null);
    try testing.expect(parsePrefix("2001:db8::1/128") != null);
}

test "parsePrefix rejects malformed input" {
    const bad = [_][]const u8{
        "",              "192.0.2.0",       "192.0.2.0/",     "/24",
        "192.0.2.0/33",  "192.0.2.0/64",    "2001:db8::/129", "192.0.2.0/-1",
        "192.0.2.0/024", "192.0.2.0/2 4",   "192.0.2.0/a",    "192.0.2.0//24",
        "1.2.3/24",      "2001:db8::/1281",
    };
    for (bad) |t| try testing.expect(parsePrefix(t) == null);
}

test "formatPrefix and masked canonicalization" {
    try expectPrefixText("192.0.2.5/24", mkPrefix("192.0.2.5/24")); // host bits kept
    try expectPrefixText("192.0.2.0/24", mkPrefix("192.0.2.5/24").masked());
    try expectPrefixText("2001:db8::/32", mkPrefix("2001:db8:ffff::1/32").masked());
    try expectPrefixText("0.0.0.0/0", mkPrefix("255.255.255.255/0").masked());
    try expectPrefixText("::/0", mkPrefix("2001:db8::1/0").masked());
    // masked is idempotent on already-canonical prefixes.
    try testing.expect(mkPrefix("10.0.0.0/8").masked().eql(mkPrefix("10.0.0.0/8")));
}

test "Prefix.contains across boundaries" {
    const p = mkPrefix("192.0.2.0/24");
    try testing.expect(p.contains(mkIp("192.0.2.0")));
    try testing.expect(p.contains(mkIp("192.0.2.130")));
    try testing.expect(p.contains(mkIp("192.0.2.255")));
    try testing.expect(!p.contains(mkIp("192.0.1.255")));
    try testing.expect(!p.contains(mkIp("192.0.3.0")));
    // Host bits on the prefix address don't matter.
    try testing.expect(mkPrefix("192.0.2.5/24").contains(mkIp("192.0.2.200")));
    // v6.
    const p6 = mkPrefix("2001:db8::/32");
    try testing.expect(p6.contains(mkIp("2001:db8::1")));
    try testing.expect(p6.contains(mkIp("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff")));
    try testing.expect(!p6.contains(mkIp("2001:db9::")));
    try testing.expect(!p6.contains(mkIp("2001:db7:ffff::")));
    // Family-checked: never true across v4/v6, even for mapped addresses.
    try testing.expect(!p.contains(mkIp("2001:db8::1")));
    try testing.expect(!p6.contains(mkIp("192.0.2.1")));
    try testing.expect(!p.contains(mkIp("::ffff:192.0.2.1")));
    // /0 contains the whole family; /32 only itself.
    try testing.expect(mkPrefix("0.0.0.0/0").contains(mkIp("203.0.113.7")));
    try testing.expect(mkPrefix("192.0.2.1/32").contains(mkIp("192.0.2.1")));
    try testing.expect(!mkPrefix("192.0.2.1/32").contains(mkIp("192.0.2.2")));
}

test "containsPrefix and overlaps" {
    const p8 = mkPrefix("10.0.0.0/8");
    const p16 = mkPrefix("10.1.0.0/16");
    try testing.expect(p8.containsPrefix(p16));
    try testing.expect(!p16.containsPrefix(p8));
    try testing.expect(p8.containsPrefix(p8));
    try testing.expect(!p8.containsPrefix(mkPrefix("11.0.0.0/16")));
    try testing.expect(!p8.containsPrefix(mkPrefix("2001:db8::/32")));

    try testing.expect(p8.overlaps(p16));
    try testing.expect(p16.overlaps(p8));
    try testing.expect(p8.overlaps(p8));
    try testing.expect(!mkPrefix("10.0.0.0/25").overlaps(mkPrefix("10.0.0.128/25")));
    try testing.expect(!p8.overlaps(mkPrefix("11.0.0.0/8")));
    try testing.expect(!p8.overlaps(mkPrefix("::/0"))); // family mismatch
    const p6a = mkPrefix("2001:db8::/32");
    const p6b = mkPrefix("2001:db8:aaaa::/48");
    try testing.expect(p6a.overlaps(p6b) and p6a.containsPrefix(p6b));
    try testing.expect(!p6b.overlaps(mkPrefix("2001:db8:bbbb::/48")));
}

test "network, broadcast, first/last host" {
    const p = mkPrefix("192.0.2.5/24");
    try expectIpText("192.0.2.0", p.network());
    try expectIpText("192.0.2.255", p.broadcast().?);
    try expectIpText("192.0.2.1", p.firstHost());
    try expectIpText("192.0.2.254", p.lastHost());
    // /31 + /32: no network/broadcast reservation (RFC 3021).
    const p31 = mkPrefix("192.0.2.0/31");
    try expectIpText("192.0.2.0", p31.firstHost());
    try expectIpText("192.0.2.1", p31.lastHost());
    const p32 = mkPrefix("192.0.2.9/32");
    try expectIpText("192.0.2.9", p32.firstHost());
    try expectIpText("192.0.2.9", p32.lastHost());
    // v6 has no broadcast; hosts span the whole prefix.
    const p6 = mkPrefix("2001:db8::/64");
    try testing.expect(p6.broadcast() == null);
    try expectIpText("2001:db8::", p6.firstHost());
    try expectIpText("2001:db8::ffff:ffff:ffff:ffff", p6.lastHost());
}

test "hostCount" {
    try testing.expectEqual(@as(u128, 256), mkPrefix("192.0.2.0/24").hostCount());
    try testing.expectEqual(@as(u128, 2), mkPrefix("192.0.2.0/31").hostCount());
    try testing.expectEqual(@as(u128, 1), mkPrefix("192.0.2.1/32").hostCount());
    try testing.expectEqual(@as(u128, 1) << 32, mkPrefix("0.0.0.0/0").hostCount());
    try testing.expectEqual(@as(u128, 1), mkPrefix("2001:db8::1/128").hostCount());
    try testing.expectEqual(@as(u128, 1) << 64, mkPrefix("2001:db8::/64").hostCount());
    // v6 /0 saturates (2^128 does not fit in u128).
    try testing.expectEqual(std.math.maxInt(u128), mkPrefix("::/0").hostCount());
}

test "isSingleIp and supernet" {
    try testing.expect(mkPrefix("192.0.2.1/32").isSingleIp());
    try testing.expect(!mkPrefix("192.0.2.0/31").isSingleIp());
    try testing.expect(mkPrefix("2001:db8::1/128").isSingleIp());
    try testing.expect(!mkPrefix("2001:db8::/127").isSingleIp());

    try expectPrefixText("192.0.2.0/24", mkPrefix("192.0.2.128/25").supernet(24).?);
    try testing.expect(mkPrefix("192.0.2.0/24").supernet(25) == null); // longer → null
    try expectPrefixText("0.0.0.0/0", mkPrefix("192.0.2.0/24").supernet(0).?);
    try expectPrefixText("2001:db8::/32", mkPrefix("2001:db8:aaaa::/48").supernet(32).?);
}

test "address iterator yields the exact sequence" {
    var it = mkPrefix("192.0.2.8/30").addresses();
    try expectIpText("192.0.2.8", it.next().?);
    try expectIpText("192.0.2.9", it.next().?);
    try expectIpText("192.0.2.10", it.next().?);
    try expectIpText("192.0.2.11", it.next().?);
    try testing.expect(it.next() == null);
    try testing.expect(it.next() == null); // stays exhausted

    var single = mkPrefix("10.0.0.1/32").addresses();
    try expectIpText("10.0.0.1", single.next().?);
    try testing.expect(single.next() == null);

    // Host bits are masked away before iterating.
    var it6 = mkPrefix("2001:db8::1/127").addresses();
    try expectIpText("2001:db8::", it6.next().?);
    try expectIpText("2001:db8::1", it6.next().?);
    try testing.expect(it6.next() == null);
}

test "summarize: minimal covering prefix list" {
    const gpa = testing.allocator;
    // 192.0.2.0–192.0.2.130 → /25 + /31 + /32.
    {
        const ps = try summarize(gpa, .{ .from = mkIp("192.0.2.0"), .to = mkIp("192.0.2.130") });
        defer gpa.free(ps);
        try expectPrefixList(&.{ "192.0.2.0/25", "192.0.2.128/31", "192.0.2.130/32" }, ps);
    }
    // Aligned range → a single prefix.
    {
        const ps = try summarize(gpa, .{ .from = mkIp("10.0.0.0"), .to = mkIp("10.0.0.255") });
        defer gpa.free(ps);
        try expectPrefixList(&.{"10.0.0.0/24"}, ps);
    }
    // Single address.
    {
        const ps = try summarize(gpa, .{ .from = mkIp("10.0.0.7"), .to = mkIp("10.0.0.7") });
        defer gpa.free(ps);
        try expectPrefixList(&.{"10.0.0.7/32"}, ps);
    }
    // v6 range.
    {
        const ps = try summarize(gpa, .{ .from = mkIp("2001:db8::"), .to = mkIp("2001:db8::5") });
        defer gpa.free(ps);
        try expectPrefixList(&.{ "2001:db8::/126", "2001:db8::4/127" }, ps);
    }
    // Whole address space (exercises the overflow-free paths).
    {
        const ps = try summarize(gpa, .{ .from = mkIp("0.0.0.0"), .to = mkIp("255.255.255.255") });
        defer gpa.free(ps);
        try expectPrefixList(&.{"0.0.0.0/0"}, ps);
    }
    {
        const ps = try summarize(gpa, .{
            .from = mkIp("::"),
            .to = mkIp("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
        });
        defer gpa.free(ps);
        try expectPrefixList(&.{"::/0"}, ps);
    }
    // Invalid ranges: reversed or family-mixed — an error, never a panic.
    try testing.expectError(error.InvalidRange, summarize(gpa, .{
        .from = mkIp("10.0.0.9"),
        .to = mkIp("10.0.0.1"),
    }));
    try testing.expectError(error.InvalidRange, summarize(gpa, .{
        .from = mkIp("10.0.0.1"),
        .to = mkIp("2001:db8::1"),
    }));
}

test "Prefix.range round-trips through summarize" {
    const gpa = testing.allocator;
    const cases = [_][]const u8{
        "192.0.2.0/24",  "10.0.0.0/8",      "192.0.2.1/32", "0.0.0.0/0",
        "2001:db8::/32", "2001:db8::1/128",
    };
    for (cases) |t| {
        const p = mkPrefix(t);
        const ps = try summarize(gpa, p.range());
        defer gpa.free(ps);
        try testing.expectEqual(@as(usize, 1), ps.len);
        try testing.expect(ps[0].eql(p.masked()));
    }
}

test "mergePrefixes coalesces adjacent and overlapping prefixes" {
    const gpa = testing.allocator;
    { // adjacent halves → the parent /24
        const ps = try mergePrefixes(gpa, &.{ mkPrefix("10.0.0.0/25"), mkPrefix("10.0.0.128/25") });
        defer gpa.free(ps);
        try expectPrefixList(&.{"10.0.0.0/24"}, ps);
    }
    { // overlap: the /25 is inside the /24
        const ps = try mergePrefixes(gpa, &.{ mkPrefix("10.0.0.0/24"), mkPrefix("10.0.0.128/25") });
        defer gpa.free(ps);
        try expectPrefixList(&.{"10.0.0.0/24"}, ps);
    }
    { // unsorted input, a disjoint island, v6 alongside v4
        const ps = try mergePrefixes(gpa, &.{
            mkPrefix("192.0.2.128/25"),
            mkPrefix("2001:db8::/33"),
            mkPrefix("10.0.0.0/24"),
            mkPrefix("192.0.2.0/25"),
            mkPrefix("2001:db8:8000::/33"),
        });
        defer gpa.free(ps);
        try expectPrefixList(&.{ "10.0.0.0/24", "192.0.2.0/24", "2001:db8::/32" }, ps);
    }
    { // adjacent but not alignable: stays two prefixes
        const ps = try mergePrefixes(gpa, &.{ mkPrefix("10.0.1.0/24"), mkPrefix("10.0.2.0/24") });
        defer gpa.free(ps);
        try expectPrefixList(&.{ "10.0.1.0/24", "10.0.2.0/24" }, ps);
    }
    { // empty input
        const ps = try mergePrefixes(gpa, &.{});
        defer gpa.free(ps);
        try testing.expectEqual(@as(usize, 0), ps.len);
    }
}

// ── fuzz: untrusted-input string parsers never panic ────────────────────────

fn fuzzParseIp(_: void, smith: *std.testing.Smith) !void {
    var buf: [64]u8 = undefined;
    // ⚠ `smith.slice` in one call, never `bytes` then a ranged draw.
    // `Smith.bytes` consumes the WHOLE remaining input, and a ranged draw
    // returns the range's MINIMUM unless the 8 bytes it reads as a
    // little-endian `u64` already lie inside the range — so the length drawn
    // after it was always 0. Instrumented on 2026-09-04:
    // **1 round, 0 non-empty inputs, 0 that parsed as an address**; with a
    // hand-written corpus of 12 real literals, 13 rounds and still 0
    // non-empty. The same harness with `slice` gets 9 non-empty and 2 that
    // parse. Three parsers of untrusted text were contributing one empty
    // string to the gate.
    const len: usize = smith.slice(&buf);
    _ = parseIp(buf[0..len]);
}
test "fuzz parseIp never panics" {
    try testing.fuzz({}, fuzzParseIp, .{});
}

fn fuzzParsePrefix(_: void, smith: *std.testing.Smith) !void {
    var buf: [72]u8 = undefined;
    // ⚠ `smith.slice` in one call, never `bytes` then a ranged draw.
    // `Smith.bytes` consumes the WHOLE remaining input, and a ranged draw
    // returns the range's MINIMUM unless the 8 bytes it reads as a
    // little-endian `u64` already lie inside the range — so the length drawn
    // after it was always 0. Instrumented on 2026-09-04:
    // **1 round, 0 non-empty inputs, 0 that parsed as an address**; with a
    // hand-written corpus of 12 real literals, 13 rounds and still 0
    // non-empty. The same harness with `slice` gets 9 non-empty and 2 that
    // parse. Three parsers of untrusted text were contributing one empty
    // string to the gate.
    const len: usize = smith.slice(&buf);
    _ = parsePrefix(buf[0..len]);
}
test "fuzz parsePrefix never panics" {
    try testing.fuzz({}, fuzzParsePrefix, .{});
}

fn fuzzParseHostPort(_: void, smith: *std.testing.Smith) !void {
    var buf: [80]u8 = undefined;
    // ⚠ `smith.slice` in one call, never `bytes` then a ranged draw.
    // `Smith.bytes` consumes the WHOLE remaining input, and a ranged draw
    // returns the range's MINIMUM unless the 8 bytes it reads as a
    // little-endian `u64` already lie inside the range — so the length drawn
    // after it was always 0. Instrumented on 2026-09-04:
    // **1 round, 0 non-empty inputs, 0 that parsed as an address**; with a
    // hand-written corpus of 12 real literals, 13 rounds and still 0
    // non-empty. The same harness with `slice` gets 9 non-empty and 2 that
    // parse. Three parsers of untrusted text were contributing one empty
    // string to the gate.
    const len: usize = smith.slice(&buf);
    _ = parseHostPort(buf[0..len]);
}
test "fuzz parseHostPort never panics" {
    try testing.fuzz({}, fuzzParseHostPort, .{});
}

test "Ip.isPrivate: RFC 1918 + RFC 4193 ranges and their boundaries" {
    const yes = [_][]const u8{
        "10.0.0.0",    "10.255.255.255",
        "172.16.0.0",  "172.31.255.255",
        "192.168.0.0", "192.168.255.255",
        "::ffff:10.0.0.1", // v4-mapped must not slip past
        "fc00::", "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", // RFC 4193, as Go
    };
    for (yes) |t| try std.testing.expect(parseIp(t).?.isPrivate());

    // The boundaries are where an off-by-one lives: 172.15 and 172.32 are
    // public, and 192.167/192.169 are not 192.168.
    const no = [_][]const u8{
        "9.255.255.255",   "11.0.0.0",
        "172.15.255.255",  "172.32.0.0",
        "192.167.255.255", "192.169.0.0",
        "8.8.8.8",         "fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        "fe00::",          "::1",
        "fe80::1",
    };
    for (no) |t| try std.testing.expect(!parseIp(t).?.isPrivate());
}
