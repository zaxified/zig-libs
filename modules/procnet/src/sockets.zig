// SPDX-License-Identifier: MIT

//! `/proc/net/{tcp,udp,tcp6,udp6}` — the kernel's own socket tables: every
//! bound/listening/connected socket, independent of which process holds it
//! (contrast `process.zig`, which is per-PID). The kernel's connection-state
//! enum (`net/tcp_states.h`) is reused for UDP too: a UDP row is only ever
//! `.close` (unconnected/bound) or `.established` (connect()-ed).

const std = @import("std");
const netaddr = @import("netaddr");
const procnet = @import("root.zig");

/// Which `/proc/net/*` table a row came from.
pub const Proto = enum { tcp, udp };

/// `net/tcp_states.h` `TCP_*` values, as printed (hex) in the `st` column.
/// Non-exhaustive: an unrecognized code decodes to its raw value rather than
/// failing the whole row.
pub const SockState = enum(u8) {
    established = 0x01,
    syn_sent = 0x02,
    syn_recv = 0x03,
    fin_wait1 = 0x04,
    fin_wait2 = 0x05,
    time_wait = 0x06,
    /// Also UDP's "unconnected/bound" state — the kernel reuses this same
    /// code for both meanings; there is no separate UDP state space.
    close = 0x07,
    close_wait = 0x08,
    last_ack = 0x09,
    listen = 0x0A,
    closing = 0x0B,
    new_syn_recv = 0x0C,
    _,
};

/// One socket-table row.
pub const SocketEntry = struct {
    proto: Proto,
    local: netaddr.Ip,
    port: u16,
    state: SockState,
};

/// Decode one 8-hex-char little-endian `u32` group the same way
/// `/proc/net/route` does (kernel prints host-order hex of the network-order
/// word, so the low byte of the parsed int is the first address byte of
/// that word). Shared by v4 (one group) and v6 (four groups) decoding.
fn leHexWord(s: []const u8) ?[4]u8 {
    if (s.len != 8) return null;
    const v = std.fmt.parseInt(u32, s, 16) catch return null;
    return .{
        @truncate(v & 0xff),
        @truncate((v >> 8) & 0xff),
        @truncate((v >> 16) & 0xff),
        @truncate((v >> 24) & 0xff),
    };
}

/// Decode a `/proc/net/{tcp,udp}` local-address hex string: 8 hex chars for
/// IPv4, 32 for IPv6 (four little-endian `u32` words, concatenated in
/// address order — verified against real `tcp6`/`udp6` snapshots). Null on
/// any other length or malformed hex.
fn parseLocalAddr(s: []const u8) ?netaddr.Ip {
    if (s.len == 8) {
        const b = leHexWord(s) orelse return null;
        return .{ .v4 = b };
    }
    if (s.len == 32) {
        var b: [16]u8 = undefined;
        var g: usize = 0;
        while (g < 4) : (g += 1) {
            const word = leHexWord(s[g * 8 .. g * 8 + 8]) orelse return null;
            @memcpy(b[g * 4 .. g * 4 + 4], &word);
        }
        return .{ .v6 = b };
    }
    return null;
}

/// Parse one `/proc/net/{tcp,tcp6,udp,udp6}`-shaped table (header line, then
/// `sl local_address rem_address st …` columns) into typed entries tagged
/// `proto`. Malformed rows are skipped, not fatal. Caller owns the returned
/// slice (`gpa.free`).
fn parseTable(gpa: std.mem.Allocator, text: []const u8, proto: Proto) std.mem.Allocator.Error![]SocketEntry {
    var out: std.ArrayList(SocketEntry) = .empty;
    errdefer out.deinit(gpa);

    var lines = std.mem.splitScalar(u8, text, '\n');
    _ = lines.next(); // header: "sl  local_address rem_address   st ..."
    while (lines.next()) |line| {
        if (std.mem.trim(u8, line, " \t\r").len == 0) continue;
        var f = std.mem.tokenizeAny(u8, line, " \t");
        _ = f.next() orelse continue; // sl
        const local = f.next() orelse continue;
        _ = f.next() orelse continue; // rem_address
        const state_s = f.next() orelse continue;

        const colon = std.mem.indexOfScalar(u8, local, ':') orelse continue;
        const ip = parseLocalAddr(local[0..colon]) orelse continue;
        const port = std.fmt.parseInt(u16, local[colon + 1 ..], 16) catch continue;
        const state_raw = std.fmt.parseInt(u8, state_s, 16) catch continue;

        try out.append(gpa, .{ .proto = proto, .local = ip, .port = port, .state = @enumFromInt(state_raw) });
    }
    return out.toOwnedSlice(gpa);
}

/// Parse a `/proc/net/tcp` or `/proc/net/tcp6` blob (auto-detects v4 vs v6
/// per row by address hex length; a caller may even pass both concatenated).
pub fn parseTcp(gpa: std.mem.Allocator, text: []const u8) std.mem.Allocator.Error![]SocketEntry {
    return parseTable(gpa, text, .tcp);
}

/// Parse a `/proc/net/udp` or `/proc/net/udp6` blob. See `parseTcp`.
pub fn parseUdp(gpa: std.mem.Allocator, text: []const u8) std.mem.Allocator.Error![]SocketEntry {
    return parseTable(gpa, text, .udp);
}

/// Read + parse all four live tables (`tcp`, `tcp6`, `udp`, `udp6`) into one
/// combined slice. A missing/unreadable table (IPv6 disabled, module not
/// loaded) contributes nothing rather than failing the whole read. Caller
/// owns the returned slice (`gpa.free`).
pub fn readSockets(gpa: std.mem.Allocator, io: std.Io) std.mem.Allocator.Error![]SocketEntry {
    var out: std.ArrayList(SocketEntry) = .empty;
    errdefer out.deinit(gpa);

    const Spec = struct { path: []const u8, proto: Proto };
    for ([_]Spec{
        .{ .path = "/proc/net/tcp", .proto = .tcp },
        .{ .path = "/proc/net/tcp6", .proto = .tcp },
        .{ .path = "/proc/net/udp", .proto = .udp },
        .{ .path = "/proc/net/udp6", .proto = .udp },
    }) |spec| {
        const text = procnet.readVirtualFile(gpa, io, spec.path, 512 * 1024) orelse continue;
        defer gpa.free(text);
        const rows = try parseTable(gpa, text, spec.proto);
        defer gpa.free(rows);
        try out.appendSlice(gpa, rows);
    }
    return out.toOwnedSlice(gpa);
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;
const tcp_fixture = @embedFile("testdata/tcp.txt");
const tcp6_fixture = @embedFile("testdata/tcp6.txt");
const udp_fixture = @embedFile("testdata/udp.txt");
const udp6_fixture = @embedFile("testdata/udp6.txt");

test "parseTcp: real /proc/net/tcp fixture (v4)" {
    const entries = try parseTcp(testing.allocator, tcp_fixture);
    defer testing.allocator.free(entries);
    try testing.expectEqual(@as(usize, 5), entries.len);

    // "00000000:0277 ... 0A" -> 0.0.0.0:631 LISTEN
    try testing.expectEqual(netaddr.Ip{ .v4 = .{ 0, 0, 0, 0 } }, entries[0].local);
    try testing.expectEqual(@as(u16, 631), entries[0].port);
    try testing.expectEqual(SockState.listen, entries[0].state);

    // "3600007F:0035 ... 0A" -> 127.0.0.54:53 LISTEN
    try testing.expectEqual(netaddr.Ip{ .v4 = .{ 127, 0, 0, 54 } }, entries[2].local);
    try testing.expectEqual(@as(u16, 53), entries[2].port);

    // "2810002A:DC8E ... 01" -> established outbound (not LISTEN)
    try testing.expectEqual(SockState.established, entries[4].state);
    try testing.expectEqual(@as(u16, 0xDC8E), entries[4].port);
    for (entries) |e| try testing.expectEqual(Proto.tcp, e.proto);
}

test "parseTcp: real /proc/net/tcp6 fixture (v6)" {
    const entries = try parseTcp(testing.allocator, tcp6_fixture);
    defer testing.allocator.free(entries);
    try testing.expectEqual(@as(usize, 4), entries.len);

    // "00000000000000000000000000000000:0277" -> ::  :631
    try testing.expectEqual(netaddr.Ip{ .v6 = @splat(0) }, entries[0].local);
    try testing.expectEqual(@as(u16, 631), entries[0].port);

    // "00000000000000000000000001000000:0386" -> ::1 :902
    var want: [16]u8 = @splat(0);
    want[15] = 1;
    try testing.expectEqual(netaddr.Ip{ .v6 = want }, entries[2].local);
    try testing.expectEqual(@as(u16, 0x0386), entries[2].port);
}

test "parseUdp: real /proc/net/udp fixture" {
    const entries = try parseUdp(testing.allocator, udp_fixture);
    defer testing.allocator.free(entries);
    try testing.expectEqual(@as(usize, 4), entries.len);

    // "017AA8C0:0035 ... 07" -> 192.168.122.1:53, unconnected/bound
    try testing.expectEqual(netaddr.Ip{ .v4 = .{ 192, 168, 122, 1 } }, entries[0].local);
    try testing.expectEqual(@as(u16, 53), entries[0].port);
    try testing.expectEqual(SockState.close, entries[0].state);
    for (entries) |e| try testing.expectEqual(Proto.udp, e.proto);
}

test "parseUdp: real /proc/net/udp6 fixture" {
    const entries = try parseUdp(testing.allocator, udp6_fixture);
    defer testing.allocator.free(entries);
    try testing.expectEqual(@as(usize, 3), entries.len);
    try testing.expect(entries[0].local == .v6);
}

test "parseTcp: empty table (header only)" {
    const entries = try parseTcp(testing.allocator, "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n");
    defer testing.allocator.free(entries);
    try testing.expectEqual(@as(usize, 0), entries.len);
}

test "parseTcp: malformed rows are skipped, not fatal" {
    const text =
        \\hdr
        \\   0: bad-addr:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0 100 0 0 10 0
        \\   1: 00000000:0277
        \\   2: 00000000:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0 100 0 0 10 0
        \\
    ;
    const entries = try parseTcp(testing.allocator, text);
    defer testing.allocator.free(entries);
    try testing.expectEqual(@as(usize, 1), entries.len);
}
