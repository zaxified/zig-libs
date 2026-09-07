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
/// the total row count, so a caller always knows whether `flows` is the whole
/// table or a truncated view.
pub const ConntrackResult = struct {
    flows: []ConntrackFlow,
    /// Rows in the text that was parsed — which is the whole file only when
    /// `text_truncated` is false. The doc used to call this "the true total"
    /// unconditionally while `readConntrack` handed it a 4 MiB prefix, so
    /// past ~20 000 flows the very signal that says "you are seeing a partial
    /// view" was itself partial, and short by a plausible amount
    /// (W2 re-audit 2026-09-02, `procnet` F6).
    total: usize,
    /// The source file was longer than the read limit, so `total` counts only
    /// the prefix that was read. `parseConntrack` on caller-supplied text
    /// never sets this — the caller knows where its text came from.
    text_truncated: bool = false,

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
/// typed flows, plus the total line count of the text handed in. Malformed lines are counted
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
        flow.proto_len = @intCast(procnet.copyClamped(&flow.proto_buf, proto_name));
        flow.state_len = @intCast(procnet.copyClamped(&flow.state_buf, state));
        try out.append(gpa, flow);
    }
    return .{ .flows = try out.toOwnedSlice(gpa), .total = total };
}

/// Read + parse the live `/proc/net/nf_conntrack`, capped at `max` flows. A
/// missing/unreadable file (module not loaded) yields an empty result, not
/// an error.
pub fn readConntrack(gpa: std.mem.Allocator, io: std.Io, max: usize) std.mem.Allocator.Error!ConntrackResult {
    const r = procnet.readVirtualFileReporting(gpa, io, "/proc/net/nf_conntrack", 4 * 1024 * 1024) orelse
        return .{ .flows = &.{}, .total = 0 };
    defer gpa.free(r.bytes);
    var out = try parseConntrack(gpa, r.bytes, max);
    out.text_truncated = r.truncated;
    return out;
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

// ── fuzz: parseConntrack never panics, OOB or leaks ─────────────────────────
//
// `/proc/net/nf_conntrack` is kernel-emitted but the decode entry point is
// the same hostile-input surface as any wire parser (a bind-mounted/faked
// `/proc`, a snapshot read from a file) — and its `src=`/`dst=`/`sport=`/
// `dport=` key=value scan is the most free-form grammar of any table in this
// module, unlike the others' fixed column order. Allocates, so this runs
// under `std.testing.allocator` with the result freed on every path (via
// `ConntrackResult.deinit`, the module's own free path).
/// The shared script reader. See `fuzzsample.zig` for what collapsed here and
/// why the choices now come out of the seed's own octets instead of a draw.
const fuzzsample = @import("fuzzsample.zig");
const seed = fuzzsample.seed;

/// Scripts for the sample builder: `sampleIndex, mode, mutationCount,
/// truncate(2)`, then `offset(2), value` per mutation. `mode` 0 asks for
/// arbitrary bytes and a truncation at or over the sample's length means "do
/// not truncate", so `\xff\xff` is the whole table.
///
/// The mutation half is what this target is for: arbitrary bytes essentially
/// never spell a `key=value` token the free-form `kvField` scan recognizes, so
/// damaging a known-good table reaches the src/dst/sport/dport decode logic far
/// more often than a from-scratch random blob would.
const conntrack_samples = [_][]const u8{fixture};

const conntrack_seeds = [_][]const u8{
    seed("\x00\x01\x00\xff\xff"), // the real table, undamaged
    seed("\x00\x01\x01\xff\xff" ++ "\x00\x30="), // an extra '=' inside a key=value token
    seed("\x00\x01\x02\xff\xff" ++ "\x00\x30=\x00\x31="), // two of them, adjacent
    seed("\x00\x01\x01\xff\xff" ++ "\x00\x30\x20"), // a space splitting a token in half
    seed("\x00\x01\x04\xff\xff" ++ "\x00\x28.\x00\x2a.\x00\x2c.\x00\x2e."), // dots through an address value
    seed("\x00\x01\x02\xff\xff" ++ "\x00\x20\x0a\x00\x21\x0a"), // newlines cut a row in half
    seed("\x00\x01\x02\xff\xff" ++ "\x00\x20\x00\x00\x21\x00"), // NULs inside a row
    seed("\x00\x01\x18\xff\xff"), // the maximum mutation count
    seed("\x00\x01\x00\x00\x40"), // truncated to 64 octets, mid-row
    seed("\x00\x01\x00\x00\x01"), // truncated to a single octet
    seed("\x00\x01\x00\x00\x00"), // truncated to nothing
    seed("\x00\x00\x00\x00\x00\x00\x20" ++ "src=1.2.3.4 dst=5.6.7.8 sport=1 "), // arbitrary mode: a hand-written line
    seed("\x00\x00\x00\x00\x00\x00\x08" ++ "\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8"), // arbitrary mode: high bytes
    seed(""), // the empty script: exactly what the collapsed helper ran
};

test "fuzz: parseConntrack never panics, OOB or leaks, arbitrary or mutated-real bytes" {
    try std.testing.fuzz({}, fuzzParseConntrackNeverLeaks, .{ .corpus = &conntrack_seeds });
}

fn fuzzParseConntrackNeverLeaks(_: void, smith: *std.testing.Smith) !void {
    var script: [512]u8 = undefined;
    const n: usize = smith.slice(&script);
    var buf: [1024]u8 = undefined;
    var choice: fuzzsample.Choice = .{};
    const text = fuzzsample.build(script[0..n], &conntrack_samples, &buf, &choice);
    var result = try parseConntrack(testing.allocator, text, 50);
    result.deinit(testing.allocator);
}

test "corpus: every conntrack script reaches the parser, and the flows decoded are pinned" {
    // ⭐ `parseConntrack("")` succeeds with zero flows, so acceptance says
    // nothing. The numbers an empty input cannot produce are the flows decoded
    // and the rows the parser walked — and the two differ, because a row that
    // is skipped still counts toward `total`.
    var nonempty: usize = 0;
    var flows: usize = 0;
    var rows: usize = 0;
    var mutations: usize = 0;
    for (conntrack_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var script: [512]u8 = undefined;
        const n: usize = smith.slice(&script);
        if (n != 0) nonempty += 1;
        var buf: [1024]u8 = undefined;
        var choice: fuzzsample.Choice = .{};
        const text = fuzzsample.build(script[0..n], &conntrack_samples, &buf, &choice);
        mutations += choice.mutations;
        var result = parseConntrack(testing.allocator, text, 50) catch continue;
        defer result.deinit(testing.allocator);
        flows += result.flows.len;
        rows += result.total;
    }
    // One seed is deliberately the empty script.
    try testing.expectEqual(conntrack_seeds.len - 1, nonempty);
    // Measured 2026-09-07: 0 flows and 0 mutations before the draws were
    // restructured — every iteration parsed the empty string.
    try testing.expectEqual(@as(usize, 30), flows);
    try testing.expectEqual(@as(usize, 37), rows);
    try testing.expectEqual(@as(usize, 36), mutations);
}

test "a capped read says so, instead of reporting a short total as the true one" {
    const gpa = testing.allocator;
    // Build a table larger than the read limit we hand it, then read it the
    // way `readConntrack` does. Before the fix `total` was the row count of
    // the 4 MiB prefix, presented by the doc as "the true total row count" —
    // a partial answer to the very question "is this view partial?", and
    // short by a plausible amount (W2 re-audit 2026-09-02, `procnet` F6).
    const line = "ipv4     2 tcp      6 431999 ESTABLISHED src=10.0.0.1 dst=10.0.0.2 sport=1 dport=2 [ASSURED] mark=0 use=1\n";
    const rows = 200;
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(gpa);
    for (0..rows) |_| try text.appendSlice(gpa, line);

    // Whole text: the total is the true one and nothing claims truncation.
    {
        var r = try parseConntrack(gpa, text.items, 8);
        defer r.deinit(gpa);
        try testing.expectEqual(@as(usize, rows), r.total);
        try testing.expect(!r.text_truncated);
    }
    // A prefix: fewer rows, and `total` alone cannot say which case it is —
    // 150 is a perfectly plausible row count for a real table.
    {
        const cut = line.len * 50 + 3;
        var r = try parseConntrack(gpa, text.items[0..cut], 8);
        defer r.deinit(gpa);
        try testing.expect(r.total < rows);
        try testing.expect(!r.text_truncated); // caller-supplied text: not our call
    }
}

test "readVirtualFileReporting tells its caller when the limit was the end" {
    const gpa = testing.allocator;
    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // `/proc/version` is one line and always present on Linux. Read it whole,
    // then read a prefix of it: the difference between the two is exactly the
    // bit `readVirtualFile` used to throw away, and the bit `readConntrack`
    // and `readSockets` need in order to keep the promises their docs make.
    const whole = procnet.readVirtualFileReporting(gpa, io, "/proc/version", 64 * 1024) orelse
        return error.SkipZigTest;
    defer gpa.free(whole.bytes);
    try testing.expect(whole.bytes.len > 8);
    try testing.expect(!whole.truncated);

    const prefix = procnet.readVirtualFileReporting(gpa, io, "/proc/version", 8) orelse
        return error.SkipZigTest;
    defer gpa.free(prefix.bytes);
    try testing.expectEqual(@as(usize, 8), prefix.bytes.len);
    try testing.expect(prefix.truncated);
    try testing.expectEqualStrings(whole.bytes[0..8], prefix.bytes);
}
