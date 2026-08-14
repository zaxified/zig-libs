// SPDX-License-Identifier: MIT

//! `/proc/net/arp` — the kernel IPv4 neighbor (ARP) table: which IP↔MAC
//! pairs the local segment has actually seen on the wire.

const std = @import("std");
const netaddr = @import("netaddr");
const procnet = @import("root.zig");

/// One neighbor-table row.
pub const ArpEntry = struct {
    ip: netaddr.Ip,
    mac: [6]u8,
    /// Raw `ATF_*` flags (`linux/if_arp.h`) from the hex `Flags` column
    /// (e.g. `0x2` = `ATF_COM`, complete entry; `0x0` = incomplete).
    flags: u16,
    device_buf: [procnet.if_name_max]u8 = @splat(0),
    device_len: u8 = 0,

    /// The owning interface (e.g. "eth0").
    pub fn device(e: *const ArpEntry) []const u8 {
        return e.device_buf[0..e.device_len];
    }
};

/// Parse a `hh:hh:hh:hh:hh:hh` MAC literal, or null if malformed.
fn parseMac(text: []const u8) ?[6]u8 {
    var mac: [6]u8 = undefined;
    var it = std.mem.splitScalar(u8, text, ':');
    var i: usize = 0;
    while (it.next()) |part| : (i += 1) {
        if (i >= 6 or part.len != 2) return null;
        mac[i] = std.fmt.parseInt(u8, part, 16) catch return null;
    }
    return if (i == 6) mac else null;
}

/// Parse `/proc/net/arp` (header line, then `IP HWtype Flags HWaddr Mask
/// Device` columns) into typed entries. Malformed rows are skipped, not
/// fatal — one corrupt line should never sink the whole table. Caller owns
/// the returned slice (`gpa.free`).
pub fn parseArp(gpa: std.mem.Allocator, text: []const u8) std.mem.Allocator.Error![]ArpEntry {
    var out: std.ArrayList(ArpEntry) = .empty;
    errdefer out.deinit(gpa);

    var lines = std.mem.splitScalar(u8, text, '\n');
    _ = lines.next(); // header: "IP address  HW type  Flags  HW address  Mask  Device"
    while (lines.next()) |line| {
        if (std.mem.trim(u8, line, " \t\r").len == 0) continue;
        var f = std.mem.tokenizeAny(u8, line, " \t");
        const ip_s = f.next() orelse continue;
        _ = f.next() orelse continue; // HW type
        const flags_s = f.next() orelse continue;
        const mac_s = f.next() orelse continue;
        _ = f.next() orelse continue; // Mask (always "*")
        const dev_s = f.next() orelse "";

        const ip = netaddr.parseIp(ip_s) orelse continue;
        const mac = parseMac(mac_s) orelse continue;
        const flags = std.fmt.parseInt(u16, flags_s, 0) catch continue; // "0x2" — base 0 auto-detects

        var e: ArpEntry = .{ .ip = ip, .mac = mac, .flags = flags };
        e.device_len = procnet.copyClamped(&e.device_buf, dev_s);
        try out.append(gpa, e);
    }
    return out.toOwnedSlice(gpa);
}

/// Read + parse the live `/proc/net/arp`. A missing/unreadable file yields
/// an empty slice (no ARP module, or first boot with an empty cache), not an
/// error.
pub fn readArp(gpa: std.mem.Allocator, io: std.Io) std.mem.Allocator.Error![]ArpEntry {
    const text = procnet.readVirtualFile(gpa, io, "/proc/net/arp", 256 * 1024) orelse return &.{};
    defer gpa.free(text);
    return parseArp(gpa, text);
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;
const fixture = @embedFile("testdata/arp.txt");

test "parseArp: real /proc/net/arp fixture" {
    const entries = try parseArp(testing.allocator, fixture);
    defer testing.allocator.free(entries);
    try testing.expectEqual(@as(usize, 5), entries.len);

    try testing.expectEqual(netaddr.Ip{ .v4 = .{ 10, 0, 1, 21 } }, entries[0].ip);
    try testing.expectEqual([6]u8{ 0, 0, 0, 0, 0, 0 }, entries[0].mac);
    try testing.expectEqual(@as(u16, 0), entries[0].flags);
    try testing.expectEqualStrings("wlp2s0", entries[0].device());

    try testing.expectEqual(netaddr.Ip{ .v4 = .{ 192, 168, 250, 128 } }, entries[2].ip);
    try testing.expectEqual([6]u8{ 0x00, 0x0c, 0x29, 0xf4, 0x43, 0x0b }, entries[2].mac);
    try testing.expectEqual(@as(u16, 2), entries[2].flags);
    try testing.expectEqualStrings("vmnet1", entries[2].device());
}

test "parseArp: empty table (header only)" {
    const entries = try parseArp(testing.allocator, "IP address       HW type     Flags       HW address            Mask     Device\n");
    defer testing.allocator.free(entries);
    try testing.expectEqual(@as(usize, 0), entries.len);
}

test "parseArp: malformed rows are skipped, not fatal" {
    const text =
        \\IP address       HW type     Flags       HW address            Mask     Device
        \\not-an-ip        0x1         0x0         00:00:00:00:00:00     *        wlp2s0
        \\10.0.1.1         0x1         0x0         bad-mac               *        wlp2s0
        \\10.0.1.2         0x1
        \\10.0.1.3         0x1         0x6         aa:bb:cc:dd:ee:ff     *        eth0
        \\
    ;
    const entries = try parseArp(testing.allocator, text);
    defer testing.allocator.free(entries);
    try testing.expectEqual(@as(usize, 1), entries.len);
    try testing.expectEqual(netaddr.Ip{ .v4 = .{ 10, 0, 1, 3 } }, entries[0].ip);
    try testing.expectEqual(@as(u16, 6), entries[0].flags);
}

test "parseMac: a MAC field with more than 6 colon-separated groups is rejected, not an OOB write" {
    // `mac: [6]u8` is fixed-size; the `i >= 6` guard (arp.zig:32) is the only
    // thing stopping a 7th group from writing past the end of it. Without
    // the guard this panics: `index out of bounds: index 6, len 6`.
    try testing.expectEqual(@as(?[6]u8, null), parseMac("aa:bb:cc:dd:ee:ff:11"));
    // Sanity: a well-formed 6-group MAC still parses.
    try testing.expectEqual(
        @as(?[6]u8, [6]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }),
        parseMac("aa:bb:cc:dd:ee:ff"),
    );
}

test "parseArp: a >6-group MAC field is a malformed row, skipped not fatal" {
    const text = "hdr\n10.0.1.9 0x1 0x2 aa:bb:cc:dd:ee:ff:11 * eth0\n";
    const entries = try parseArp(testing.allocator, text);
    defer testing.allocator.free(entries);
    try testing.expectEqual(@as(usize, 0), entries.len);
}

test "parseArp: device name longer than IFNAMSIZ is truncated, not dropped" {
    const text = "hdr\n10.0.0.1 0x1 0x2 aa:bb:cc:dd:ee:ff * this-interface-name-is-way-too-long\n";
    const entries = try parseArp(testing.allocator, text);
    defer testing.allocator.free(entries);
    try testing.expectEqual(@as(usize, 1), entries.len);
    try testing.expectEqual(@as(usize, procnet.if_name_max), entries[0].device().len);
}

// ── fuzz: parseArp never panics, OOB or leaks ───────────────────────────────
//
// `/proc/net/arp` is kernel-emitted but the decode entry point is the same
// hostile-input surface as any wire parser (a bind-mounted/faked `/proc`, a
// snapshot read from a file). Allocates, so this runs under
// `std.testing.allocator` with the result freed on every path.
test "fuzz: parseArp never panics, OOB or leaks, arbitrary or mutated-real bytes" {
    try std.testing.fuzz({}, fuzzParseArpNeverLeaks, .{ .corpus = &.{fixture} });
}

fn fuzzParseArpNeverLeaks(_: void, smith: *std.testing.Smith) !void {
    var buf: [1024]u8 = undefined;
    const text = mutateSample(smith, fixture, &buf);
    const entries = try parseArp(testing.allocator, text);
    testing.allocator.free(entries);
}

/// One draw in five is pure arbitrary bytes; the rest starts from the real
/// `/proc/net/arp` fixture and applies a handful of byte-level mutations —
/// arbitrary bytes essentially never spell a well-formed `hh:hh:hh:hh:hh:hh`
/// MAC or a valid dotted IP, so mutating a known-good table reaches
/// `parseMac`'s per-group bounds check (audit-found: a 7th colon group is
/// the only thing standing between this and an OOB write) far more often
/// than a from-scratch random blob would.
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
