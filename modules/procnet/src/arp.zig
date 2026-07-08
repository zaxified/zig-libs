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

test "parseArp: device name longer than IFNAMSIZ is truncated, not dropped" {
    const text = "hdr\n10.0.0.1 0x1 0x2 aa:bb:cc:dd:ee:ff * this-interface-name-is-way-too-long\n";
    const entries = try parseArp(testing.allocator, text);
    defer testing.allocator.free(entries);
    try testing.expectEqual(@as(usize, 1), entries.len);
    try testing.expectEqual(@as(usize, procnet.if_name_max), entries[0].device().len);
}
