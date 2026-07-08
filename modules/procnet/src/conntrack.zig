// SPDX-License-Identifier: MIT

//! `/proc/net/nf_conntrack` — active connection-tracking flows: the
//! kernel's stateful-firewall view of "what is talking to what right now".
//! The table can be huge (hundreds of thousands of flows on a busy NAT
//! gateway), so parsing takes a caller-supplied cap and always reports the
//! true total separately from the (possibly truncated) sample.

const std = @import("std");
const netaddr = @import("netaddr");
const procnet = @import("root.zig");

/// One tracked flow, decoded from the *original*-direction tuple (the first
/// `src=`/`dst=`/`sport=`/`dport=` on the line — conntrack prints the
/// original tuple then the reply tuple).
pub const ConntrackFlow = struct {
    src: netaddr.Ip,
    dst: netaddr.Ip,
    sport: u16,
    dport: u16,
    proto_buf: [8]u8 = @splat(0), // "tcp" / "udp" / "icmp" / ...
    proto_len: u8 = 0,
    /// TCP connection state (e.g. "ESTABLISHED", "TIME_WAIT"); empty for
    /// non-TCP protocols, which the table doesn't track a state machine for.
    state_buf: [16]u8 = @splat(0),
    state_len: u8 = 0,

    /// The layer-4 protocol name.
    pub fn proto(f: *const ConntrackFlow) []const u8 {
        return f.proto_buf[0..f.proto_len];
    }

    /// The TCP state, or `""` for a stateless protocol.
    pub fn state(f: *const ConntrackFlow) []const u8 {
        return f.state_buf[0..f.state_len];
    }
};

/// The result of a (possibly capped) conntrack read: a bounded sample plus
/// the true total row count, so a caller always knows whether `flows` is
/// the whole table or a truncated view.
pub const ConntrackResult = struct {
    flows: []ConntrackFlow,
    total: usize,

    pub fn deinit(r: ConntrackResult, gpa: std.mem.Allocator) void {
        gpa.free(r.flows);
    }
};

/// Value of the first `key=` token on `line` (the original tuple — later
/// occurrences from the reply tuple are ignored), or null if absent.
/// e.g. `kvField(line, "dst=")` → `"93.184.216.34"`.
fn kvField(line: []const u8, key: []const u8) ?[]const u8 {
    const i = std.mem.indexOf(u8, line, key) orelse return null;
    const rest = line[i + key.len ..];
    const end = std.mem.indexOfAny(u8, rest, " \t") orelse rest.len;
    return rest[0..end];
}

/// True if `s` is a non-empty run of `[A-Z_]` (a conntrack state word like
/// `ESTABLISHED`; excludes bracketed markers like `[ASSURED]`).
fn isUpperWord(s: []const u8) bool {
    for (s) |c| if (!((c >= 'A' and c <= 'Z') or c == '_')) return false;
    return s.len > 0;
}

/// Parse `/proc/net/nf_conntrack` (one flow per line: `<family> <l3num>
/// <proto> <l4num> <timeout> [<TCP state>] key=value...`) into at most `max`
/// typed flows, plus the true total line count. Malformed lines are counted
/// (toward `total`) but skipped from `flows`, not fatal. Caller owns
/// `result.flows` (`result.deinit(gpa)`).
pub fn parseConntrack(gpa: std.mem.Allocator, text: []const u8, max: usize) std.mem.Allocator.Error!ConntrackResult {
    var out: std.ArrayList(ConntrackFlow) = .empty;
    errdefer out.deinit(gpa);
    var total: usize = 0;

    var lines = std.mem.tokenizeAny(u8, text, "\r\n");
    while (lines.next()) |line| {
        total += 1;
        if (out.items.len >= max) continue;

        var hdr = std.mem.tokenizeAny(u8, line, " \t");
        _ = hdr.next() orelse continue; // family (ipv4/ipv6) — src/dst literals disambiguate this already
        _ = hdr.next() orelse continue; // L3 protonum
        const proto_name = hdr.next() orelse continue;

        const src_s = kvField(line, "src=") orelse continue;
        const dst_s = kvField(line, "dst=") orelse continue;
        const sport_s = kvField(line, "sport=") orelse "0";
        const dport_s = kvField(line, "dport=") orelse "0";
        const src = netaddr.parseIp(src_s) orelse continue;
        const dst = netaddr.parseIp(dst_s) orelse continue;

        var state: []const u8 = "";
        var st = std.mem.tokenizeAny(u8, line, " \t");
        while (st.next()) |tok| {
            if (tok.len >= 3 and isUpperWord(tok)) {
                state = tok;
                break;
            }
        }

        var flow: ConntrackFlow = .{
            .src = src,
            .dst = dst,
            .sport = std.fmt.parseInt(u16, sport_s, 10) catch 0,
            .dport = std.fmt.parseInt(u16, dport_s, 10) catch 0,
        };
        flow.proto_len = procnet.copyClamped(&flow.proto_buf, proto_name);
        flow.state_len = procnet.copyClamped(&flow.state_buf, state);
        try out.append(gpa, flow);
    }
    return .{ .flows = try out.toOwnedSlice(gpa), .total = total };
}

/// Read + parse the live `/proc/net/nf_conntrack`, capped at `max` flows. A
/// missing/unreadable file (module not loaded) yields an empty result, not
/// an error.
pub fn readConntrack(gpa: std.mem.Allocator, io: std.Io, max: usize) std.mem.Allocator.Error!ConntrackResult {
    const text = procnet.readVirtualFile(gpa, io, "/proc/net/nf_conntrack", 4 * 1024 * 1024) orelse
        return .{ .flows = &.{}, .total = 0 };
    defer gpa.free(text);
    return parseConntrack(gpa, text, max);
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;
const fixture = @embedFile("testdata/nf_conntrack.txt");

test "parseConntrack: real /proc/net/nf_conntrack fixture" {
    var result = try parseConntrack(testing.allocator, fixture, 50);
    defer result.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 4), result.total);
    try testing.expectEqual(@as(usize, 4), result.flows.len);

    const f0 = result.flows[0];
    try testing.expectEqualStrings("tcp", f0.proto());
    try testing.expectEqual(netaddr.Ip{ .v4 = .{ 10, 0, 1, 50 } }, f0.src);
    try testing.expectEqual(netaddr.Ip{ .v4 = .{ 93, 184, 216, 34 } }, f0.dst);
    try testing.expectEqual(@as(u16, 54210), f0.sport);
    try testing.expectEqual(@as(u16, 443), f0.dport);
    try testing.expectEqualStrings("ESTABLISHED", f0.state());

    const f1 = result.flows[1]; // udp: no connection-state machine
    try testing.expectEqualStrings("udp", f1.proto());
    try testing.expectEqualStrings("", f1.state());

    const f2 = result.flows[2];
    try testing.expectEqualStrings("TIME_WAIT", f2.state());

    const f3 = result.flows[3]; // ipv6 flow
    try testing.expectEqual(netaddr.Ip{ .v6 = (netaddr.parseIp("fe80::1").?).v6 }, f3.src);
    try testing.expectEqual(@as(u16, 22), f3.sport);
}

test "parseConntrack: max caps the sample but total counts every line" {
    var result = try parseConntrack(testing.allocator, fixture, 2);
    defer result.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 4), result.total);
    try testing.expectEqual(@as(usize, 2), result.flows.len);
}

test "parseConntrack: empty table" {
    var result = try parseConntrack(testing.allocator, "", 50);
    defer result.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 0), result.total);
    try testing.expectEqual(@as(usize, 0), result.flows.len);
}

test "parseConntrack: malformed lines count toward total but are skipped" {
    const text =
        \\ipv4 2 tcp 6 100 ESTABLISHED src=not-an-ip dst=10.0.0.1 sport=1 dport=2 mark=0
        \\ipv4 2 tcp 6 100 no-src-field dst=10.0.0.1 sport=1 dport=2 mark=0
        \\ipv4 2 udp 17 30 src=10.0.0.5 dst=10.0.0.6 sport=5 dport=6 mark=0
    ;
    var result = try parseConntrack(testing.allocator, text, 50);
    defer result.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 3), result.total);
    try testing.expectEqual(@as(usize, 1), result.flows.len);
    try testing.expectEqualStrings("udp", result.flows[0].proto());
}
