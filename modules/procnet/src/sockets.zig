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
    /// The local port, from the `local_address` column.
    local_port: u16,
    /// The peer, from the `rem_address` column. A listening or unconnected
    /// socket has an all-zero peer (`0.0.0.0:0` / `[::]:0`) — that is a real
    /// value the kernel prints, not a missing one; `ss` renders it `*:*`.
    /// Use `state` (not a zero test on this field) to decide whether a peer
    /// is meaningful.
    remote: netaddr.Ip,
    remote_port: u16,
    state: SockState,
    /// The uid owning the socket, from the `uid` column — what `ss -e` shows
    /// as `uid:N`. Numeric only: mapping it to a name means `/etc/passwd` or
    /// NSS, which is a caller's concern, not this parser's.
    uid: u32,
    /// The socket's inode number. **This is the only key that joins a socket
    /// to a process** — `ss -p` works by scanning `/proc/<pid>/fd/*` for a
    /// symlink whose target is `socket:[<inode>]`; see
    /// `process.indexSocketOwners`.
    ///
    /// Legitimately `0` for a socket that has no inode to own: a `TIME_WAIT`
    /// or otherwise orphaned socket outlives the file that referenced it, and
    /// the kernel prints `0` there. A zero inode therefore means "no process
    /// can own this", not "unknown" — the join must never match on it.
    inode: u64,
    /// The kernel's `tx_queue`/`rx_queue` columns — what `ss` shows as
    /// Send-Q / Recv-Q. `rx_queue`'s meaning depends on `state`, because the
    /// kernel overloads the column:
    ///   * `.listen`: the current depth of the accept queue — connections
    ///     completed but not yet `accept(2)`-ed. Not a byte count.
    ///   * every other state: bytes received but not yet read by the
    ///     application.
    /// `tx_queue` is bytes written but not yet acknowledged by the peer.
    ///
    /// ⚠ For a listening socket `tx_queue` is always `0` here, and that is
    /// the file's own value, not a parse failure. `ss` prints the configured
    /// backlog in its Send-Q column for listeners — measured live against a
    /// `listen(3)` socket with two pending connections, `ss` reported
    /// `Recv-Q 2  Send-Q 3` while `/proc/net/tcp` printed
    /// `00000000:00000002`, i.e. rx 2 (agreeing with `ss`) and tx 0. The
    /// backlog is not in this file at all; `ss` gets it from the
    /// `NETLINK_SOCK_DIAG` path it prefers, which this module does not use.
    tx_queue: u32,
    rx_queue: u32,
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

/// Decode a `/proc/net/{tcp,udp}` address hex string — the same encoding in
/// both the `local_address` and `rem_address` columns: 8 hex chars for IPv4,
/// 32 for IPv6 (four little-endian `u32` words, concatenated in address
/// order — verified against real `tcp6`/`udp6` snapshots). Null on any other
/// length or malformed hex.
fn parseSocketAddr(s: []const u8) ?netaddr.Ip {
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

/// An `<address-hex>:<port-hex>` column (`local_address`, `rem_address`).
const HostPort = struct { ip: netaddr.Ip, port: u16 };

/// Split and decode one `addr:port` column. Null if it has no `:`, an
/// address of the wrong width, or non-hex in either half.
fn parseHostPort(s: []const u8) ?HostPort {
    const colon = std.mem.indexOfScalar(u8, s, ':') orelse return null;
    const ip = parseSocketAddr(s[0..colon]) orelse return null;
    const port = std.fmt.parseInt(u16, s[colon + 1 ..], 16) catch return null;
    return .{ .ip = ip, .port = port };
}

/// Split and decode the fused `tx_queue:rx_queue` column (`%08X:%08X`).
fn parseQueues(s: []const u8) ?struct { tx: u32, rx: u32 } {
    const colon = std.mem.indexOfScalar(u8, s, ':') orelse return null;
    const tx = std.fmt.parseInt(u32, s[0..colon], 16) catch return null;
    const rx = std.fmt.parseInt(u32, s[colon + 1 ..], 16) catch return null;
    return .{ .tx = tx, .rx = rx };
}

/// Parse one `/proc/net/{tcp,tcp6,udp,udp6}`-shaped table (header line, then
/// `sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt
/// uid timeout inode …` columns) into typed entries tagged `proto`.
/// Malformed rows are skipped, not fatal. Caller owns the returned slice
/// (`gpa.free`).
///
/// A row must carry every column up to and including `inode` to be accepted.
/// That is deliberately stricter than "as far as `st`": a `SocketEntry`
/// reporting `inode = 0` because the column was absent is indistinguishable
/// from one reporting the kernel's own `0` for an orphaned socket, and the
/// process join reads that field. Skipping the row keeps "0 means no owner"
/// true. Columns past `inode` (`ref`, the `sk` pointer, and the TCP
/// diagnostics `rto`/`ato`/`snd_cwnd`/`ssthresh`) are not required, so a
/// kernel that grows or shrinks that tail does not empty the table.
fn parseTable(gpa: std.mem.Allocator, text: []const u8, proto: Proto) std.mem.Allocator.Error![]SocketEntry {
    var out: std.ArrayList(SocketEntry) = .empty;
    errdefer out.deinit(gpa);

    var lines = std.mem.splitScalar(u8, text, '\n');
    _ = lines.next(); // header: "sl  local_address rem_address   st ..."
    while (lines.next()) |line| {
        if (std.mem.trim(u8, line, " \t\r").len == 0) continue;
        var f = std.mem.tokenizeAny(u8, line, " \t");
        _ = f.next() orelse continue; // sl
        const local_s = f.next() orelse continue;
        const remote_s = f.next() orelse continue;
        const state_s = f.next() orelse continue;
        const queues_s = f.next() orelse continue; // tx_queue:rx_queue
        _ = f.next() orelse continue; // tr:tm->when — retransmit/keepalive timer, see DEFER
        _ = f.next() orelse continue; // retrnsmt
        const uid_s = f.next() orelse continue;
        _ = f.next() orelse continue; // timeout
        const inode_s = f.next() orelse continue;

        const local = parseHostPort(local_s) orelse continue;
        const remote = parseHostPort(remote_s) orelse continue;
        const state_raw = std.fmt.parseInt(u8, state_s, 16) catch continue;
        const queues = parseQueues(queues_s) orelse continue;
        const uid = std.fmt.parseInt(u32, uid_s, 10) catch continue;
        const inode = std.fmt.parseInt(u64, inode_s, 10) catch continue;

        try out.append(gpa, .{
            .proto = proto,
            .local = local.ip,
            .local_port = local.port,
            .remote = remote.ip,
            .remote_port = remote.port,
            .state = @enumFromInt(state_raw),
            .uid = uid,
            .inode = inode,
            .tx_queue = queues.tx,
            .rx_queue = queues.rx,
        });
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

/// How much of each `/proc/net/*` socket table `readSockets` will read.
/// Named rather than inline because the number is a policy, and a visible
/// one: a row runs about 150 bytes, so this is roughly 3 500 sockets per
/// table. Past it the read TRUNCATES (see `procnet.readVirtualFile`) — the
/// listing is short by the tail, the last partial row is dropped as
/// malformed, and nothing errors. A host that routinely holds more sockets
/// than this wants a caller-side read with its own limit, which the public
/// `readVirtualFile` + `parseTcp`/`parseUdp` split already allows.
pub const socket_table_read_limit = 512 * 1024;

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
        const text = procnet.readVirtualFile(gpa, io, spec.path, socket_table_read_limit) orelse continue;
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
    try testing.expectEqual(@as(u16, 631), entries[0].local_port);
    try testing.expectEqual(SockState.listen, entries[0].state);

    // "3600007F:0035 ... 0A" -> 127.0.0.54:53 LISTEN
    try testing.expectEqual(netaddr.Ip{ .v4 = .{ 127, 0, 0, 54 } }, entries[2].local);
    try testing.expectEqual(@as(u16, 53), entries[2].local_port);

    // "2810002A:DC8E ... 01" -> established outbound (not LISTEN)
    try testing.expectEqual(SockState.established, entries[4].state);
    try testing.expectEqual(@as(u16, 0xDC8E), entries[4].local_port);
    for (entries) |e| try testing.expectEqual(Proto.tcp, e.proto);
}

test "parseTcp: rem_address, uid and inode columns are captured, not stepped over" {
    // Every assertion here reads a column the parser used to tokenize past.
    // Concrete expected values taken from the fixture text by hand, not
    // recomputed from the parser, so a decode that changes shows up as a
    // failure rather than agreeing with itself.
    const entries = try parseTcp(testing.allocator, tcp_fixture);
    defer testing.allocator.free(entries);

    // Row 0 — a listener: "00000000:0000" peer, root-owned, inode 5194665.
    try testing.expectEqual(netaddr.Ip{ .v4 = .{ 0, 0, 0, 0 } }, entries[0].remote);
    try testing.expectEqual(@as(u16, 0), entries[0].remote_port);
    try testing.expectEqual(@as(u32, 0), entries[0].uid);
    try testing.expectEqual(@as(u64, 5194665), entries[0].inode);

    // Row 2 — systemd-resolved's listener, uid 991 (not root), inode 9507.
    try testing.expectEqual(@as(u32, 991), entries[2].uid);
    try testing.expectEqual(@as(u64, 9507), entries[2].inode);

    // Row 4 — an ESTABLISHED connection, so the peer column carries a real
    // address: "01190026:01BB" decodes little-endian to 38.0.25.1:443.
    try testing.expectEqual(netaddr.Ip{ .v4 = .{ 38, 0, 25, 1 } }, entries[4].remote);
    try testing.expectEqual(@as(u16, 443), entries[4].remote_port);
    try testing.expectEqual(@as(u32, 1000), entries[4].uid);
    try testing.expectEqual(@as(u64, 5235142), entries[4].inode);
}

test "parseTcp: tx_queue/rx_queue are captured as two separate values" {
    // The kernel prints them fused as one `%08X:%08X` token; splitting on the
    // colon is the whole of the decode, and getting it wrong (e.g. parsing
    // the fused token as a single int) fails to parse rather than silently
    // half-working — so the interesting case is a row where the two halves
    // DIFFER, which no real capture in `testdata/` happens to have.
    const text =
        \\hdr
        \\   0: 00000000:0277 00000000:0000 0A 0000007B:000001C8 00:00000000 00000000     0        0 4242 1 0000000000000000 100 0 0 10 0
        \\
    ;
    const entries = try parseTcp(testing.allocator, text);
    defer testing.allocator.free(entries);
    try testing.expectEqual(@as(usize, 1), entries.len);
    try testing.expectEqual(@as(u32, 123), entries[0].tx_queue); // 0x7B
    try testing.expectEqual(@as(u32, 456), entries[0].rx_queue); // 0x1C8
}

test "parseTcp: a row truncated before the inode column is skipped, not given inode 0" {
    // `inode = 0` is a MEANINGFUL value (an orphaned/TIME_WAIT socket has no
    // inode), so a short row must not be admitted with a defaulted 0 — that
    // would make "no process can own this" indistinguishable from "the column
    // was not there". The two rows below are identical except that the first
    // stops one column short of `inode`.
    const short = "hdr\n   0: 00000000:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0\n";
    const full = "hdr\n   0: 00000000:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 7 1 0000000000000000 100 0 0 10 0\n";

    const a = try parseTcp(testing.allocator, short);
    defer testing.allocator.free(a);
    try testing.expectEqual(@as(usize, 0), a.len);

    const b = try parseTcp(testing.allocator, full);
    defer testing.allocator.free(b);
    try testing.expectEqual(@as(usize, 1), b.len);
    try testing.expectEqual(@as(u64, 7), b[0].inode);
}

test "parseTcp: a real orphaned socket keeps the kernel's inode 0" {
    // Captured shape of a TIME_WAIT row: state 06, uid 0, inode 0. The
    // parser must pass that 0 through, not treat it as a malformed row.
    const text = "hdr\n   3: 0100007F:1F90 0100007F:C1B2 06 00000000:00000000 03:0000059C 00000000     0        0 0 3 0000000000000000\n";
    const entries = try parseTcp(testing.allocator, text);
    defer testing.allocator.free(entries);
    try testing.expectEqual(@as(usize, 1), entries.len);
    try testing.expectEqual(SockState.time_wait, entries[0].state);
    try testing.expectEqual(@as(u64, 0), entries[0].inode);
}

test "parseTcp: real /proc/net/tcp6 fixture (v6)" {
    const entries = try parseTcp(testing.allocator, tcp6_fixture);
    defer testing.allocator.free(entries);
    try testing.expectEqual(@as(usize, 4), entries.len);

    // "00000000000000000000000000000000:0277" -> ::  :631
    try testing.expectEqual(netaddr.Ip{ .v6 = @splat(0) }, entries[0].local);
    try testing.expectEqual(@as(u16, 631), entries[0].local_port);

    // "00000000000000000000000001000000:0386" -> ::1 :902
    var want: [16]u8 = @splat(0);
    want[15] = 1;
    try testing.expectEqual(netaddr.Ip{ .v6 = want }, entries[2].local);
    try testing.expectEqual(@as(u16, 0x0386), entries[2].local_port);

    // The v6 peer column uses the same four-little-endian-word encoding as
    // the local one: row 3's "01190026 84300000 00000000 00000000" decodes
    // word-by-word to 26:00:19:01 / 00:00:30:84 / zeros, i.e.
    // 2600:1901:0:3084::, port 0x01BB = 443.
    try testing.expectEqual(
        netaddr.Ip{ .v6 = .{ 0x26, 0x00, 0x19, 0x01, 0x00, 0x00, 0x30, 0x84, 0, 0, 0, 0, 0, 0, 0, 0 } },
        entries[3].remote,
    );
    try testing.expectEqual(@as(u16, 443), entries[3].remote_port);
    try testing.expectEqual(@as(u32, 1000), entries[3].uid);
    try testing.expectEqual(@as(u64, 5235142), entries[3].inode);
}

test "parseUdp: real /proc/net/udp fixture" {
    const entries = try parseUdp(testing.allocator, udp_fixture);
    defer testing.allocator.free(entries);
    try testing.expectEqual(@as(usize, 4), entries.len);

    // "017AA8C0:0035 ... 07" -> 192.168.122.1:53, unconnected/bound
    try testing.expectEqual(netaddr.Ip{ .v4 = .{ 192, 168, 122, 1 } }, entries[0].local);
    try testing.expectEqual(@as(u16, 53), entries[0].local_port);
    try testing.expectEqual(SockState.close, entries[0].state);
    for (entries) |e| try testing.expectEqual(Proto.udp, e.proto);

    // Row 2 is the one UDP socket in the capture that is connect()-ed: a
    // DHCP client, 10.0.20.1:68 -> 10.0.1.138:67. UDP reuses the TCP state
    // codes, so `.established` here means "has a peer", and the peer column
    // is where that peer actually is.
    try testing.expectEqual(SockState.established, entries[2].state);
    try testing.expectEqual(netaddr.Ip{ .v4 = .{ 10, 0, 1, 138 } }, entries[2].remote);
    try testing.expectEqual(@as(u16, 67), entries[2].remote_port);
    try testing.expectEqual(@as(u64, 95765), entries[2].inode);
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

// ── fuzz: parseTcp/parseUdp never panic, OOB or leak ────────────────────────
//
// `/proc/net/{tcp,tcp6,udp,udp6}` is kernel-emitted but the decode entry
// point is the same hostile-input surface as any wire parser (a bind-
// mounted/faked `/proc`, a snapshot read from a file). Allocates, so this
// runs under `std.testing.allocator` with the result freed on every path.
const socket_corpus = [_][]const u8{ tcp_fixture, tcp6_fixture, udp_fixture, udp6_fixture };

test "fuzz: parseTcp/parseUdp never panic, OOB or leak, arbitrary or mutated-real bytes" {
    try std.testing.fuzz({}, fuzzParseSocketsNeverLeaks, .{ .corpus = &socket_corpus });
}

fn fuzzParseSocketsNeverLeaks(_: void, smith: *std.testing.Smith) !void {
    var buf: [1024]u8 = undefined;
    const sample = socket_corpus[smith.index(socket_corpus.len)];
    const text = mutateSample(smith, sample, &buf);

    const tcp_entries = try parseTcp(testing.allocator, text);
    testing.allocator.free(tcp_entries);
    const udp_entries = try parseUdp(testing.allocator, text);
    testing.allocator.free(udp_entries);
}

/// One draw in five is pure arbitrary bytes; the rest starts from a real
/// `/proc/net/{tcp,tcp6,udp,udp6}` fixture and applies a handful of
/// byte-level mutations — arbitrary bytes essentially never spell an
/// `addr:port` column with the exact 8- or 32-hex-char address length both
/// `parseLocalAddr`'s v4/v6 branches require, so mutating a known-good table
/// reaches that decode logic far more often than a from-scratch random blob
/// would.
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
