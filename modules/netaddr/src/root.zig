// SPDX-License-Identifier: MIT

//! netaddr — IP address parse/format + RFC 6724 destination/source selection.
//!
//! Pure address logic with no I/O dependency: IPv4/IPv6 literal parsing and
//! RFC 5952 canonical formatting, `host:port` splitting, address scope/policy
//! classification, and the RFC 6724 "which address do I connect to first"
//! ordering that `http`, `dns` and `icmp` build on.
//!
//! The RFC 6724 logic is ported from zig-fping's `src/netutil.zig`
//! (`sortByDestinationPolicy`, `policyPrecedence`, `destinationReachable`) and
//! extended to the full destination rule set, cross-checked against Go's
//! `net/addrselect.go`. Like Go, rules that need OS state we don't track are
//! skipped (rule 3 deprecated addresses, rule 4 home addresses, rule 7 native
//! transport).
//!
//! No allocation anywhere; everything works on caller-provided buffers/slices.

const std = @import("std");
const builtin = @import("builtin");

pub const meta = .{
    .status = .extract, // seeded in zig-fping/src/netutil.zig
    .platform = .any, // pure logic; `systemSource` helper is Linux-only
    .role = .util,
    .concurrency = .reentrant,
    .model_after = "Go net/addrselect.go + glibc getaddrinfo (RFC 6724)",
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

    fn isV4Mapped(b: [16]u8) bool {
        return std.mem.allEqual(u8, b[0..10], 0) and b[10] == 0xff and b[11] == 0xff;
    }
};

// ── parsing ─────────────────────────────────────────────────────────────────

/// Parse an IPv4 or IPv6 literal. Returns null on malformed input; never
/// panics. Zone suffixes (`fe80::1%eth0`) are rejected — split the zone off
/// before calling.
pub fn parseIp(text: []const u8) ?Ip {
    if (parseIp4(text)) |q| return .{ .v4 = q };
    if (parseIp6(text)) |b| return .{ .v6 = b };
    return null;
}

/// Parse a dotted-quad IPv4 literal. Strict, matching Go `netip.ParseAddr`:
/// exactly four decimal octets 0–255, no leading zeros, nothing else.
pub fn parseIp4(text: []const u8) ?[4]u8 {
    var out: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, text, '.');
    var i: usize = 0;
    while (it.next()) |part| : (i += 1) {
        if (i >= 4) return null;
        if (part.len == 0 or part.len > 3) return null;
        if (part.len > 1 and part[0] == '0') return null; // no leading zeros
        var v: u16 = 0;
        for (part) |c| {
            if (c < '0' or c > '9') return null;
            v = v * 10 + (c - '0');
        }
        if (v > 255) return null;
        out[i] = @intCast(v);
    }
    return if (i == 4) out else null;
}

/// Parse an IPv6 literal (RFC 4291 §2.2): full form, `::` compression, and an
/// embedded dotted-quad tail (`::ffff:1.2.3.4`). Zone suffixes are rejected.
pub fn parseIp6(text: []const u8) ?[16]u8 {
    if (std.mem.indexOfScalar(u8, text, '%') != null) return null; // no zone
    var out: [16]u8 = @splat(0);
    if (std.mem.indexOf(u8, text, "::")) |i| {
        const head = parseGroupList(text[0..i], false) orelse return null;
        const tail = parseGroupList(text[i + 2 ..], true) orelse return null;
        if (head.len + tail.len > 7) return null; // `::` must elide ≥ 1 group
        for (head.groups[0..head.len], 0..) |g, k| writeGroup(&out, k, g);
        const start = 8 - tail.len;
        for (tail.groups[0..tail.len], 0..) |g, k| writeGroup(&out, start + k, g);
        return out;
    }
    const all = parseGroupList(text, true) orelse return null;
    if (all.len != 8) return null;
    for (all.groups[0..8], 0..) |g, k| writeGroup(&out, k, g);
    return out;
}

const GroupList = struct { groups: [8]u16 = undefined, len: usize = 0 };

/// Parse a colon-separated list of 16-bit hex groups; `v4_tail` permits a
/// trailing dotted quad contributing the last two groups.
fn parseGroupList(text: []const u8, v4_tail: bool) ?GroupList {
    var gl: GroupList = .{};
    if (text.len == 0) return gl;
    var it = std.mem.splitScalar(u8, text, ':');
    while (it.next()) |tok| {
        if (tok.len == 0) return null;
        if (std.mem.indexOfScalar(u8, tok, '.') != null) {
            if (!v4_tail or it.next() != null) return null; // must be last
            const q = parseIp4(tok) orelse return null;
            if (gl.len > 6) return null;
            gl.groups[gl.len] = (@as(u16, q[0]) << 8) | q[1];
            gl.groups[gl.len + 1] = (@as(u16, q[2]) << 8) | q[3];
            gl.len += 2;
            return gl;
        }
        if (tok.len > 4) return null;
        var v: u16 = 0;
        for (tok) |c| {
            const d = std.fmt.charToDigit(c, 16) catch return null;
            v = (v << 4) | d;
        }
        if (gl.len >= 8) return null;
        gl.groups[gl.len] = v;
        gl.len += 1;
    }
    return gl;
}

fn writeGroup(out: *[16]u8, index: usize, group: u16) void {
    out[index * 2] = @intCast(group >> 8);
    out[index * 2 + 1] = @intCast(group & 0xff);
}

// ── formatting ──────────────────────────────────────────────────────────────

/// Enough for any output of `formatIp` (matches INET6_ADDRSTRLEN − 1).
pub const max_ip_text_len = 45;

/// Format an address canonically: dotted quad for v4, RFC 5952 for v6
/// (lowercase, longest zero run compressed leftmost, IPv4-mapped rendered
/// mixed as `::ffff:a.b.c.d`). Asserts `buf.len >= max_ip_text_len`.
pub fn formatIp(ip: Ip, buf: []u8) []const u8 {
    std.debug.assert(buf.len >= max_ip_text_len);
    switch (ip) {
        .v4 => |q| return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ q[0], q[1], q[2], q[3] }) catch unreachable,
        .v6 => |b| {
            if (Ip.isV4Mapped(b))
                return std.fmt.bufPrint(buf, "::ffff:{d}.{d}.{d}.{d}", .{ b[12], b[13], b[14], b[15] }) catch unreachable;

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
                const s = std.fmt.bufPrint(buf[w..], "{x}", .{groups[g]}) catch unreachable;
                w += s.len;
                g += 1;
            }
            return buf[0..w];
        },
    }
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

fn parsePort(text: []const u8) ?u16 {
    if (text.len == 0 or text.len > 5) return null;
    var v: u32 = 0;
    for (text) |c| {
        if (c < '0' or c > '9') return null;
        v = v * 10 + (c - '0');
    }
    return if (v <= std.math.maxInt(u16)) @intCast(v) else null;
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
pub fn sortDestinationsWithSources(dsts: []Ip, srcs: []?Ip) void {
    std.debug.assert(dsts.len == srcs.len);
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
/// exactly once. Asserts `dsts.len <= max_sort_candidates`.
pub fn sortDestinations(dsts: []Ip, srcFor: *const fn (Ip) ?Ip) void {
    std.debug.assert(dsts.len <= max_sort_candidates);
    if (dsts.len < 2) return;
    var srcs: [max_sort_candidates]?Ip = undefined;
    for (dsts, 0..) |d, i| srcs[i] = srcFor(d);
    sortDestinationsWithSources(dsts, srcs[0..dsts.len]);
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
        "1::2:",             "::ffff:1.2.3.4.5",
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
    // Vectors from the zig-fping seed…
    try testing.expectEqual(@as(u8, 50), precedenceOf(mkIp("::1")));
    try testing.expectEqual(@as(u8, 40), precedenceOf(mkIp("2606:4700::1111")));
    try testing.expectEqual(@as(u8, 35), precedenceOf(mkIp("192.0.2.1")));
    try testing.expectEqual(@as(u8, 30), precedenceOf(mkIp("2002::1")));
    try testing.expectEqual(@as(u8, 5), precedenceOf(mkIp("2001:0::1")));
    try testing.expectEqual(@as(u8, 3), precedenceOf(mkIp("fd00::1")));
    // …plus the rows the seed skipped.
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
    sortDestinationsWithSources(dsts, srcs);
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
    sortDestinations(&dsts, probe.srcFor);
    try testing.expectEqual(@as(usize, 3), probe.calls);
    var buf: [max_ip_text_len]u8 = undefined;
    try testing.expectEqualStrings("10.0.0.1", formatIp(dsts[0], &buf));
}

test "destination policy prefers ::1 over 127.0.0.1 like glibc" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var dsts = [_]Ip{ mkIp("127.0.0.1"), mkIp("::1") };
    // Skip on hosts with IPv6 disabled (rule 1 then demotes ::1).
    if (systemSource(dsts[1]) == null) return error.SkipZigTest;
    sortDestinations(&dsts, systemSource);
    try testing.expect(dsts[0].eql(mkIp("::1")));
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
