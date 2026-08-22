// SPDX-License-Identifier: MIT

//! `/proc/net/route` — the kernel IPv4 routing table: destination network,
//! gateway (if any) and owning interface, as the kernel actually sees them.

const std = @import("std");
const netaddr = @import("netaddr");
const procnet = @import("root.zig");

/// One routing-table row.
pub const RouteEntry = struct {
    /// Destination network (host bits already zeroed by the kernel's own
    /// mask column — `masked()` is a no-op here but costs nothing to call).
    dest: netaddr.Prefix,
    /// The next-hop gateway, or null for an on-link/direct route (the
    /// kernel prints an all-zero gateway for those).
    gateway: ?netaddr.Ip,
    /// Raw `RTF_*` flags (`linux/route.h`) from the hex `Flags` column, as
    /// `route -n` prints them in its own `Flags` column: `0x1` = `RTF_UP`,
    /// `0x2` = `RTF_GATEWAY`, `0x4` = `RTF_HOST`, ... Captured because
    /// `RTF_UP` is the only column that says whether a row is a live route
    /// at all, and no other field in this struct implies it.
    flags: u16,
    metric: u32,
    iface_buf: [procnet.if_name_max]u8 = @splat(0),
    iface_len: u8 = 0,

    /// The owning interface (e.g. "wlp2s0").
    pub fn iface(e: *const RouteEntry) []const u8 {
        return e.iface_buf[0..e.iface_len];
    }
};

/// Decode an 8-hex-char little-endian IPv4 address (the form
/// `/proc/net/{route,tcp,udp}` print) into an `Ip`, or null if malformed.
/// The kernel prints the `__be32` as a host-order `u32`, so the low byte is
/// the first octet.
fn leHexToV4(s: []const u8) ?netaddr.Ip {
    if (s.len != 8) return null;
    const v = std.fmt.parseInt(u32, s, 16) catch return null;
    return .{ .v4 = .{
        @truncate(v & 0xff),
        @truncate((v >> 8) & 0xff),
        @truncate((v >> 16) & 0xff),
        @truncate((v >> 24) & 0xff),
    } };
}

/// Whether `octets` (in real network order — first entry is the first
/// transmitted octet, e.g. `leHexToV4`'s output) is a valid CIDR netmask: a
/// contiguous run of leading one-bits followed only by zero-bits. `@popCount`
/// alone (what `parseRoutes` used to feed straight into `Prefix.bits`) cannot
/// tell a real mask like `255.255.255.0` from a non-contiguous bit pattern
/// like `255.255.0.255` — both have 24 set bits, but only the first describes
/// the same address set as a `/24` prefix (wave-2 audit `procnet` F3).
fn isContiguousMask(octets: [4]u8) bool {
    const v: u32 = (@as(u32, octets[0]) << 24) | (@as(u32, octets[1]) << 16) |
        (@as(u32, octets[2]) << 8) | @as(u32, octets[3]);
    const inv = ~v;
    // A run of leading ones followed by trailing zeros in `v` is exactly a
    // run of leading zeros followed by trailing ones in `~v`, i.e. `~v` is
    // `2^k - 1` for some k — the classic `n & (n +% 1) == 0` test (wrapping
    // add so `~v == 0xFFFFFFFF`, the `/0` mask, is handled without overflow
    // UB: `0xFFFFFFFF +% 1` wraps to `0`).
    return inv & (inv +% 1) == 0;
}

/// Parse `/proc/net/route` (header line, then `Iface Destination Gateway
/// Flags RefCnt Use Metric Mask MTU Window IRTT` columns, addresses as
/// little-endian hex) into typed entries. Malformed rows are skipped, not
/// fatal. Caller owns the returned slice (`gpa.free`).
pub fn parseRoutes(gpa: std.mem.Allocator, text: []const u8) std.mem.Allocator.Error![]RouteEntry {
    var out: std.ArrayList(RouteEntry) = .empty;
    errdefer out.deinit(gpa);

    var lines = std.mem.splitScalar(u8, text, '\n');
    _ = lines.next(); // header
    while (lines.next()) |line| {
        if (std.mem.trim(u8, line, " \t\r").len == 0) continue;
        var f = std.mem.tokenizeAny(u8, line, " \t");
        const iface_s = f.next() orelse continue;
        const dhex = f.next() orelse continue;
        const ghex = f.next() orelse continue;
        const flags_s = f.next() orelse continue;
        _ = f.next() orelse continue; // RefCnt — kernel prints a constant 0 here
        _ = f.next() orelse continue; // Use — a lookup counter, not route state
        const metric_s = f.next() orelse continue;
        const mhex = f.next() orelse continue;

        const dst = leHexToV4(dhex) orelse continue;
        const gw = leHexToV4(ghex) orelse continue;
        const mask_ip = leHexToV4(mhex) orelse continue;
        if (!isContiguousMask(mask_ip.v4)) continue; // F3: not a real CIDR mask
        // `/proc/net/route` prints Flags as bare hex with NO "0x" prefix,
        // unlike `/proc/net/arp`'s columns — base 16, not base 0.
        const flags = std.fmt.parseInt(u16, flags_s, 16) catch continue;

        var mask_bits: u8 = 0;
        for (mask_ip.v4) |byte| mask_bits += @popCount(byte);
        var e: RouteEntry = .{
            .dest = .{ .addr = dst, .bits = mask_bits },
            .gateway = if (gw.v4[0] == 0 and gw.v4[1] == 0 and gw.v4[2] == 0 and gw.v4[3] == 0) null else gw,
            .flags = flags,
            .metric = std.fmt.parseInt(u32, metric_s, 10) catch 0,
        };
        e.iface_len = procnet.copyClamped(&e.iface_buf, iface_s);
        try out.append(gpa, e);
    }
    return out.toOwnedSlice(gpa);
}

/// Read + parse the live `/proc/net/route`. A missing/unreadable file
/// yields an empty slice, not an error.
pub fn readRoutes(gpa: std.mem.Allocator, io: std.Io) std.mem.Allocator.Error![]RouteEntry {
    const text = procnet.readVirtualFile(gpa, io, "/proc/net/route", 256 * 1024) orelse return &.{};
    defer gpa.free(text);
    return parseRoutes(gpa, text);
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;
const fixture = @embedFile("testdata/route.txt");

test "parseRoutes: real /proc/net/route fixture" {
    const entries = try parseRoutes(testing.allocator, fixture);
    defer testing.allocator.free(entries);
    try testing.expectEqual(@as(usize, 5), entries.len);

    // wlp2s0  00000000  8A01000A  ... 600  00000000  → 0.0.0.0/0 gw 10.0.1.138
    try testing.expectEqual(netaddr.Ip{ .v4 = .{ 0, 0, 0, 0 } }, entries[0].dest.addr);
    try testing.expectEqual(@as(u8, 0), entries[0].dest.bits);
    try testing.expectEqual(netaddr.Ip{ .v4 = .{ 10, 0, 1, 138 } }, entries[0].gateway.?);
    try testing.expectEqual(@as(u32, 600), entries[0].metric);
    try testing.expectEqualStrings("wlp2s0", entries[0].iface());

    // wlp2s0  0001000A  00000000  ... 00FFFFFF → 10.0.1.0/24, no gateway (on-link)
    try testing.expectEqual(netaddr.Ip{ .v4 = .{ 10, 0, 1, 0 } }, entries[1].dest.addr);
    try testing.expectEqual(@as(u8, 24), entries[1].dest.bits);
    try testing.expectEqual(@as(?netaddr.Ip, null), entries[1].gateway);

    // The `Flags` column, which this parser used to tokenize past. The
    // default route is 0x0003 = RTF_UP|RTF_GATEWAY; the on-link routes are
    // 0x0001 = RTF_UP alone. Note these are bare hex, no "0x" prefix —
    // parsing them base-0 like `arp.zig`'s columns would read 3 as 3 and
    // then silently mis-read any row whose flags happen to start with a
    // digit sequence base-0 rejects.
    try testing.expectEqual(@as(u16, 0x0003), entries[0].flags);
    try testing.expectEqual(@as(u16, 0x0001), entries[1].flags);
}

test "parseRoutes: Flags is read as bare hex — base 0 would silently mis-read it" {
    // `/proc/net/route` prints Flags with no "0x", so `parseInt(.., 0)` —
    // the base `arp.zig` correctly uses for ITS "0x"-prefixed columns —
    // falls back to decimal here and is wrong without erroring.
    //   "0011" = RTF_UP|RTF_DYNAMIC = 17. Base 0 reads it as 17? No: 17
    //   decimal is 11, so base 0 yields 11 (RTF_UP|RTF_GATEWAY|RTF_HOST|
    //   RTF_REINSTATE) — a different, entirely plausible-looking flag set.
    // The second row is the case where base 0 does not merely mis-read but
    // drops the route: "001C" is not decimal at all, so a base-10/base-0
    // parse errors and the row is skipped.
    const text =
        \\hdr
        \\eth0 0001000A 8A01000A 0011 0 0 100 00FFFFFF 0 0 0
        \\eth1 0002000A 8A01000A 001C 0 0 200 00FFFFFF 0 0 0
        \\
    ;
    const entries = try parseRoutes(testing.allocator, text);
    defer testing.allocator.free(entries);
    try testing.expectEqual(@as(usize, 2), entries.len);
    try testing.expectEqual(@as(u16, 0x11), entries[0].flags);
    try testing.expect(entries[0].flags != 11); // what a base-0 parse would give
    try testing.expectEqual(@as(u16, 0x1C), entries[1].flags);
}

test "parseRoutes: empty table (header only)" {
    const entries = try parseRoutes(testing.allocator, "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n");
    defer testing.allocator.free(entries);
    try testing.expectEqual(@as(usize, 0), entries.len);
}

test "parseRoutes: malformed rows are skipped, not fatal" {
    const text =
        \\Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
        \\eth0 not-hex 00000000 0001 0 0 0 00FFFFFF 0 0 0
        \\eth0 0001000A
        \\eth0 0001000A 00000000 0001 0 0 100 00FFFFFF 0 0 0
        \\
    ;
    const entries = try parseRoutes(testing.allocator, text);
    defer testing.allocator.free(entries);
    try testing.expectEqual(@as(usize, 1), entries.len);
    try testing.expectEqual(@as(u32, 100), entries[0].metric);
}

test "parseRoutes: a non-contiguous mask is skipped, not silently accepted (F3)" {
    // Regression for the wave-2 audit's F3: `@popCount(mask)` alone cannot
    // tell 255.255.255.0 (a real /24) from 255.255.0.255 (24 set bits, but
    // not a contiguous run — no such CIDR prefix exists). "FF00FFFF" decodes
    // (via the same little-endian scheme as the address columns) to network
    // octets [255,255,0,255]: 24 bits set, none of them contiguous from the
    // top. The good row alongside it (00FFFFFF = 255.255.255.0, a real /24)
    // proves the parser is not just rejecting every row.
    const text =
        \\Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
        \\eth0 0001000A 00000000 0001 0 0 100 FF00FFFF 0 0 0
        \\eth0 0001000A 00000000 0001 0 0 200 00FFFFFF 0 0 0
        \\
    ;
    const entries = try parseRoutes(testing.allocator, text);
    defer testing.allocator.free(entries);
    try testing.expectEqual(@as(usize, 1), entries.len);
    try testing.expectEqual(@as(u32, 200), entries[0].metric);
    try testing.expectEqual(@as(u8, 24), entries[0].dest.bits);
}

test "isContiguousMask: leading-ones masks accepted, non-contiguous rejected" {
    try testing.expect(isContiguousMask(.{ 0, 0, 0, 0 })); // /0
    try testing.expect(isContiguousMask(.{ 255, 255, 255, 255 })); // /32
    try testing.expect(isContiguousMask(.{ 255, 255, 255, 0 })); // /24
    try testing.expect(isContiguousMask(.{ 255, 255, 254, 0 })); // /23
    try testing.expect(isContiguousMask(.{ 255, 255, 255, 128 })); // /25
    try testing.expect(!isContiguousMask(.{ 255, 255, 0, 255 })); // hole in the middle
    try testing.expect(!isContiguousMask(.{ 0, 255, 255, 255 })); // ones not leading
    try testing.expect(!isContiguousMask(.{ 255, 0, 255, 0 })); // scattered
}

test "parseRoutes: interface name longer than IFNAMSIZ is truncated, not dropped" {
    const text = "hdr\nthis-interface-name-is-way-too-long 00000000 00000000 0001 0 0 0 00000000 0 0 0\n";
    const entries = try parseRoutes(testing.allocator, text);
    defer testing.allocator.free(entries);
    try testing.expectEqual(@as(usize, 1), entries.len);
    try testing.expectEqual(@as(usize, procnet.if_name_max), entries[0].iface().len);
}

// ── fuzz: parseRoutes never panics, OOB or leaks ────────────────────────────
//
// `/proc/net/route` is kernel-emitted but the decode entry point is the same
// hostile-input surface as any wire parser (a bind-mounted/faked `/proc`, a
// snapshot read from a file). Allocates (`ArrayList` + `copyClamped` into a
// fixed buffer), so this runs under `std.testing.allocator` with the result
// freed on every path — a leak on a skipped-row error path is a real finding.
test "fuzz: parseRoutes never panics, OOB or leaks, arbitrary or mutated-real bytes" {
    try std.testing.fuzz({}, fuzzParseRoutesNeverLeaks, .{ .corpus = &.{fixture} });
}

fn fuzzParseRoutesNeverLeaks(_: void, smith: *std.testing.Smith) !void {
    var buf: [1024]u8 = undefined;
    const text = mutateSample(smith, fixture, &buf);
    const entries = try parseRoutes(testing.allocator, text);
    testing.allocator.free(entries);
}

/// One draw in five is pure arbitrary bytes; the rest starts from the real
/// `/proc/net/route` fixture and applies a handful of byte-level mutations —
/// arbitrary bytes essentially never spell the right column count with
/// 8-hex-char addresses, so mutating a known-good table reaches the row
/// decode logic (the little-endian hex, the contiguous-mask check) far more
/// often than a from-scratch random blob would.
fn mutateSample(smith: *std.testing.Smith, sample: []const u8, buf: []u8) []const u8 {
    if (smith.valueRangeAtMost(u8, 0, 4) == 0) {
        smith.bytes(buf);
        const len = smith.valueRangeAtMost(u16, 0, @intCast(buf.len));
        return buf[0..len];
    }
    const len = @min(sample.len, buf.len);
    @memcpy(buf[0..len], sample[0..len]);
    const n_mutations = smith.valueRangeAtMost(u8, 0, 24);
    var i: u8 = 0;
    while (i < n_mutations) : (i += 1) {
        if (len == 0) break;
        buf[smith.index(len)] = smith.value(u8);
    }
    const out_len = smith.valueRangeAtMost(u16, 0, @intCast(len));
    return buf[0..out_len];
}
