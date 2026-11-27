// SPDX-License-Identifier: MIT
//! Killing tests of the 2026-11-27 whole-module mutation audit. Each test names
//! the behaviour it pins; expected values come from the RFCs (5424, 3164, 6587),
//! from SPEC.md or from the doc comments of the function, never from running the
//! code. Where the module's own policy is wider than an RFC the test says so.

const std = @import("std");
const linux = std.os.linux;
const testing = std.testing;
const message = @import("message.zig");
const bsd = @import("bsd.zig");
const parser = @import("parse.zig");
const transport = @import("transport.zig");
const unix = @import("unix.zig");
const logger = @import("logger.zig");
const net = std.Io.net;

// ── helpers ─────────────────────────────────────────────────────────────────

fn monoMs() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / 1_000_000;
}

fn countFds() usize {
    var n: usize = 0;
    var fd: linux.fd_t = 0;
    while (fd < 512) : (fd += 1) {
        if (linux.errno(linux.fcntl(fd, linux.F.GETFD, 0)) == .SUCCESS) n += 1;
    }
    return n;
}

fn cloexec(fd: linux.fd_t) bool {
    const r = linux.fcntl(fd, linux.F.GETFD, 0);
    return linux.errno(r) == .SUCCESS and (r & 1) != 0;
}

fn sockPath(tmp: *testing.TmpDir, buf: []u8, name: []const u8) ![]const u8 {
    return std.fmt.bufPrint(buf, ".zig-cache/tmp/{s}/{s}", .{ tmp.sub_path, name });
}

fn unixAddr(path: []const u8) linux.sockaddr.un {
    var addr: linux.sockaddr.un = .{ .family = linux.AF.UNIX, .path = @splat(0) };
    @memcpy(addr.path[0..path.len], path);
    return addr;
}

fn listenUnix(path: []const u8, backlog: u32) !linux.fd_t {
    const addr = unixAddr(path);
    const rc = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
    const fd: linux.fd_t = @intCast(rc);
    if (linux.errno(linux.bind(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.un))) != .SUCCESS) return error.SkipZigTest;
    if (linux.errno(linux.listen(fd, backlog)) != .SUCCESS) return error.SkipZigTest;
    return fd;
}

fn bindDgram(path: []const u8) !linux.fd_t {
    const addr = unixAddr(path);
    const rc = linux.socket(linux.AF.UNIX, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
    const fd: linux.fd_t = @intCast(rc);
    if (linux.errno(linux.bind(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.un))) != .SUCCESS) return error.SkipZigTest;
    return fd;
}

/// The next connection within `ms`, or null.
fn acceptWithin(l: linux.fd_t, ms: i32) ?linux.fd_t {
    var pfd = [1]linux.pollfd{.{ .fd = l, .events = linux.POLL.IN, .revents = 0 }};
    if (linux.poll(&pfd, 1, ms) != 1) return null;
    const rc = linux.accept(l, null, null);
    if (linux.errno(rc) != .SUCCESS) return null;
    return @intCast(rc);
}

fn readExact(fd: linux.fd_t, want: []const u8) !void {
    var buf: [4096]u8 = undefined;
    try testing.expect(want.len <= buf.len);
    var got: usize = 0;
    while (got < want.len) {
        var pfd = [1]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN, .revents = 0 }};
        if (linux.poll(&pfd, 1, 2000) != 1) return error.NoData;
        const n = linux.read(fd, buf[got..].ptr, want.len - got);
        if (linux.errno(n) != .SUCCESS or n == 0) return error.NoData;
        got += n;
    }
    try testing.expectEqualStrings(want, buf[0..got]);
}

fn expectNothing(fd: linux.fd_t) !void {
    var pfd = [1]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN, .revents = 0 }};
    try testing.expectEqual(@as(usize, 0), linux.poll(&pfd, 1, 50));
}

fn recvDgram(fd: linux.fd_t, buf: []u8) ![]u8 {
    var pfd = [1]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN, .revents = 0 }};
    if (linux.poll(&pfd, 1, 2000) != 1) return error.NoData;
    const n = linux.read(fd, buf.ptr, buf.len);
    if (linux.errno(n) != .SUCCESS) return error.NoData;
    return buf[0..n];
}

// ── message.zig ─────────────────────────────────────────────────────────────

test "mutation 2026-11-27: decompose reports the clamped offset it shifted by (RFC 5424 §6.2.3 caps ±23:59)" {
    const a = try message.decompose(.{ .unix_ms = 0, .offset_minutes = 32767 });
    try testing.expectEqual(@as(?i16, 1439), a.offset_minutes);
    const b = try message.decompose(.{ .unix_ms = 100_000_000_000, .offset_minutes = -32768 });
    try testing.expectEqual(@as(?i16, -1439), b.offset_minutes);
}

test "mutation 2026-11-27: SD-NAME keeps every PRINTUSASCII byte except '=' SP ']' '\"' and maps the rest to '-' (RFC 5424 §6)" {
    var buf: [64]u8 = undefined;
    var b: usize = 0;
    while (b < 256) : (b += 1) {
        const name = [_]u8{ 'x', @intCast(b) };
        const m = message.Message{ .structured_data = &.{.{ .id = &name }} };
        const out = try message.bufPrint(&m, &buf);
        const keep = b > 32 and b < 127 and b != '=' and b != ']' and b != '"';
        const want: u8 = if (keep) @intCast(b) else '-';
        try testing.expectEqual(want, out[out.len - 2]);
        try testing.expectEqual(@as(u8, ']'), out[out.len - 1]);
    }
}

test "mutation 2026-11-27: header field bytes: exactly 33..126 pass, the rest become '-' (RFC 5424 §6 PRINTUSASCII)" {
    var buf: [64]u8 = undefined;
    var b: usize = 0;
    while (b < 256) : (b += 1) {
        const host = [_]u8{ 'x', @intCast(b) };
        const out = try message.bufPrint(&.{ .hostname = &host }, &buf);
        // "<13>1 - " then the field
        const want: u8 = if (b >= 33 and b <= 126) @intCast(b) else '-';
        try testing.expectEqual(want, out[9]);
    }
}

// ── bsd.zig ─────────────────────────────────────────────────────────────────

fn joinLabels(buf: []u8, lens: []const usize) []const u8 {
    var n: usize = 0;
    for (lens, 0..) |l, i| {
        if (i != 0) {
            buf[n] = '.';
            n += 1;
        }
        @memset(buf[n..][0..l], 'a');
        n += l;
    }
    return buf[0..n];
}

test "mutation 2026-11-27: validHostname: exactly letters, digits, '-' '_' and the '.' separator (RFC 1123 labels, SPEC.md)" {
    var b: usize = 0;
    while (b < 256) : (b += 1) {
        const h = [_]u8{ 'a', @intCast(b), 'b' };
        const ok = (b >= 'A' and b <= 'Z') or (b >= 'a' and b <= 'z') or (b >= '0' and b <= '9') or b == '-' or b == '_' or b == '.';
        try testing.expectEqual(ok, bsd.validHostname(&h));
    }
}

test "mutation 2026-11-27: validHostname: 255 bytes pass, 256 do not (SPEC.md: <= 255 bytes)" {
    var buf: [300]u8 = undefined;
    try testing.expectEqual(@as(usize, 255), joinLabels(&buf, &.{ 51, 51, 51, 50, 48 }).len);
    try testing.expect(bsd.validHostname(buf[0..255]));
    try testing.expectEqual(@as(usize, 256), joinLabels(&buf, &.{ 51, 51, 51, 51, 48 }).len);
    try testing.expect(!bsd.validHostname(buf[0..256]));
    // a label of 63 passes, 64 does not
    try testing.expect(bsd.validHostname(joinLabels(&buf, &.{63})));
    try testing.expect(!bsd.validHostname(joinLabels(&buf, &.{64})));
}

test "mutation 2026-11-27: RFC 3164 PID bytes: 33..126 minus '[' and ']'; TAG bytes: alphanumeric only (RFC 3164 §5.3)" {
    var buf: [64]u8 = undefined;
    var b: usize = 0;
    while (b < 256) : (b += 1) {
        const x = [_]u8{@intCast(b)};
        const pid_out = try bsd.bufPrint(&.{ .tag = "t", .pid = &x }, &buf);
        const pid_ok = b >= 33 and b <= 126 and b != '[' and b != ']';
        try testing.expectEqual(@as(u8, if (pid_ok) @intCast(b) else '-'), pid_out[6]);
        const tag_out = try bsd.bufPrint(&.{ .tag = &x }, &buf);
        const alnum = (b >= 'A' and b <= 'Z') or (b >= 'a' and b <= 'z') or (b >= '0' and b <= '9');
        try testing.expectEqual(@as(u8, if (alnum) @intCast(b) else '-'), tag_out[4]);
    }
}

// ── parse.zig ───────────────────────────────────────────────────────────────

test "mutation 2026-11-27: an SD element a caller built is walked only when it is the grammar (stops otherwise)" {
    const bad = [_][]const u8{ "xa=\"v\"", " a", " a=", " a=x\"v\"", " =\"v\"", " a=\"v", " a \"v\"" };
    for (bad) |raw| {
        const view = parser.SdElementView{ .id = "x", .params_raw = raw };
        var it = view.params();
        try testing.expect(it.next() == null);
    }
    const good = parser.SdElementView{ .id = "x", .params_raw = " a=\"v\"" };
    var it = good.params();
    const p = it.next().?;
    try testing.expectEqualStrings("a", p.name);
    try testing.expectEqualStrings("v", p.raw_value);
}

test "mutation 2026-11-27: PRI is 1..3 digits: <0> is kern.emerg, a long digit run is an error not an overflow (RFC 5424 §6.2.1)" {
    const r = parser.parseBsd("<0>");
    try testing.expect(r.has_priority);
    try testing.expectEqual(message.Facility.kern, r.facility);
    try testing.expectEqual(message.Severity.emerg, r.severity);
    try testing.expectError(error.InvalidPriority, parser.parse("<99999>1 - - - - - -"));
    try testing.expectError(error.InvalidPriority, parser.parse("<1234567890123>1 - - - - - -"));
}

test "mutation 2026-11-27: a header that ends inside HOSTNAME has no SP after it and is refused (RFC 5424 §6)" {
    try testing.expectError(error.InvalidHostname, parser.parse("<13>1 - hh"));
}

test "mutation 2026-11-27: TIMESTAMP grammar: separators, month 01..12, exact end, offset colon (RFC 5424 §6.2.3 / RFC 3339)" {
    const bad = [_][]const u8{
        "2026/07-09T12:34:56Z",
        "2026-00-09T12:34:56Z",
        "2026-13-09T12:34:56Z",
        "2026-99-09T12:34:56Z",
        "2026-07-09T12:34:56Zjunk",
        "2026-07-09T12:34:56+02-00",
        "2026-07-09T12:34:56+0200x",
    };
    for (bad) |ts| {
        var buf: [96]u8 = undefined;
        const line = try std.fmt.bufPrint(&buf, "<13>1 {s} h a p m -", .{ts});
        try testing.expectError(error.InvalidTimestamp, parser.parse(line));
    }
}

test "mutation 2026-11-27: ParsedTimestamp.toTimestamp floors microseconds (doc), also before the epoch" {
    const m = try parser.parse("<13>1 1969-12-31T23:59:59.999999Z - - - - -");
    try testing.expectEqual(@as(i64, -1), m.timestamp.?.unix_us);
    try testing.expectEqual(@as(i64, -1), m.timestamp.?.toTimestamp().unix_ms);
}

test "mutation 2026-11-27: SD-NAME in the parser takes '!' (33) and '~' (126), refuses DEL (RFC 5424 §6.3.2)" {
    const m = try parser.parse("<13>1 - - - - - [!~ ~!=\"v\"]");
    var els = m.elements();
    const e = els.next().?;
    try testing.expectEqualStrings("!~", e.id);
    var ps = e.params();
    try testing.expectEqualStrings("~!", ps.next().?.name);
    try testing.expectError(error.InvalidStructuredData, parser.parse("<13>1 - - - - - [a\x7f]"));
}

fn bsdTs(line: []const u8) ?parser.BsdTimestamp {
    return parser.parseBsd(line).timestamp;
}

test "mutation 2026-11-27: RFC 3164 timestamp 'Mmm dd hh:mm:ss' (§4.1.2): field values, shortest form, refused shapes" {
    // the shortest form: unpadded day, nothing after it (14 bytes)
    const t = bsdTs("<13>Jan 1 00:00:00").?;
    try testing.expectEqual(@as(u5, 1), t.day);
    // every field distinct
    const d = bsdTs("<13>Feb 29 02:03:04 h t: m").?;
    try testing.expectEqual(@as(u4, 2), d.month);
    try testing.expectEqual(@as(u5, 29), d.day);
    try testing.expectEqual(@as(u5, 2), d.hour);
    try testing.expectEqual(@as(u6, 3), d.minute);
    try testing.expectEqual(@as(u6, 4), d.second);
    const bad = [_][]const u8{
        "<13>Jan,10 00:00:00 h t: m", // no space after the month
        "<13>Jan 001 00:00:00 h t: m", // a day has at most two digits
        "<13>Jan  0 00:00:00 h t: m", // day 0
        "<13>Jan 00 00:00:00 h t: m",
        "<13>Jan 10x00:00:00 h t: m", // no space before the time
        "<13>Jan 10 24:00:00 h t: m", // hour 24
        "<13>Jan 10 00:60:00 h t: m", // minute 60
        "<13>Jan 10 00x00:00 h t: m",
        "<13>Jan 10 00:00x00 h t: m",
    };
    for (bad) |l| try testing.expect(bsdTs(l) == null);
}

test "mutation 2026-11-27: RFC 3164 seconds: 60 is read, 61 is refused (module policy, SPEC; RFC 3164 has no rule)" {
    // Not RFC 5424's rule: there §6.2.3 forbids a leap second and `parse` refuses it.
    try testing.expect(bsdTs("<13>Jan  1 00:00:60 h t: m") != null);
    try testing.expect(bsdTs("<13>Jan  1 00:00:61 h t: m") == null);
}

test "mutation 2026-11-27: TAG policy is wider than RFC 3164 §4.1.3 on purpose (as rsyslogd): letters digits - _ . /, up to 255 bytes" {
    var b: usize = 0;
    while (b < 256) : (b += 1) {
        const line = [_]u8{ '<', '1', '3', '>', @intCast(b), ':', ' ', 'm' };
        const r = parser.parseBsd(&line);
        const ok = (b >= 'A' and b <= 'Z') or (b >= 'a' and b <= 'z') or (b >= '0' and b <= '9') or b == '-' or b == '_' or b == '.' or b == '/';
        if (ok) {
            try testing.expectEqual(@as(u8, @intCast(b)), r.tag.?[0]);
            try testing.expectEqualStrings("m", r.msg);
        } else try testing.expect(r.tag == null);
    }
    var buf: [320]u8 = undefined;
    for ([_]struct { n: usize, ok: bool }{ .{ .n = 255, .ok = true }, .{ .n = 256, .ok = false }, .{ .n = 300, .ok = false } }) |c| {
        @memcpy(buf[0..4], "<13>");
        @memset(buf[4..][0..c.n], 'a');
        @memcpy(buf[4 + c.n ..][0..3], ": m");
        const r = parser.parseBsd(buf[0 .. 4 + c.n + 3]);
        try testing.expectEqual(c.ok, r.tag != null);
    }
}

test "mutation 2026-11-27: RFC 3164 PID in the parser: 33..126 without '[', and no space is swallowed after 'TAG:'" {
    var b: usize = 0;
    while (b < 256) : (b += 1) {
        if (b == ']') continue;
        const line = [_]u8{ '<', '1', '3', '>', 't', '[', @intCast(b), ']', ':', ' ', 'm' };
        const r = parser.parseBsd(&line);
        if (b >= 33 and b <= 126 and b != '[') {
            try testing.expectEqual(@as(u8, @intCast(b)), r.pid.?[0]);
        } else try testing.expect(r.pid == null);
    }
    const r = parser.parseBsd("<13>tag:msg");
    try testing.expectEqualStrings("tag", r.tag.?);
    try testing.expectEqualStrings("msg", r.msg);
}

test "mutation 2026-11-27: RFC 6587 octet count past usize is BadLength, not a wrapped length" {
    try testing.expectError(error.BadLength, parser.nextFrame("18446744073709551616 x", std.math.maxInt(usize)));
    try testing.expectError(error.BadLength, parser.nextFrame("18446744073709551619 x", std.math.maxInt(usize)));
}

// ── transport.zig: datagrams ────────────────────────────────────────────────

test "mutation 2026-11-27: buildDatagram: exactly the limit is sent whole, one byte more is cut with the marker" {
    var scratch: [2048]u8 = undefined;
    const opts: transport.Options = .{ .udp_limit = 100, .trunc_marker = "[T]" };
    var body: [200]u8 = @splat('x');
    // "<13>1 - - - - - - " is 18 bytes
    const whole = transport.buildDatagram(&.{ .msg = body[0..82] }, &scratch, opts);
    try testing.expectEqual(@as(usize, 100), whole.len);
    try testing.expect(!std.mem.endsWith(u8, whole, "[T]"));
    const cut = transport.buildDatagram(&.{ .msg = body[0..83] }, &scratch, opts);
    try testing.expectEqual(@as(usize, 100), cut.len);
    try testing.expect(std.mem.endsWith(u8, cut, "[T]"));
}

test "mutation 2026-11-27: markTruncated: the marker never lands past what was written; the cut keeps UTF-8 sequences whole" {
    var scratch: [64]u8 = undefined;
    @memcpy(scratch[0..3], "abc");
    try testing.expectEqualStrings("abcM", transport.markTruncated(&scratch, scratch[0..3], 40, "M"));
    // cut after the lead byte of a 2-byte sequence: back to the lead (doc: back over continuation bytes)
    @memset(&scratch, 'a');
    scratch[0] = 0xC3;
    scratch[1] = 0xA9;
    try testing.expectEqualStrings("M", transport.markTruncated(&scratch, scratch[0..20], 2, "M"));
    // lead + four continuation bytes is no UTF-8 sequence (at most three): the cut stays
    @memset(&scratch, 'a');
    @memcpy(scratch[0..5], "\xF0\x80\x80\x80\x80");
    try testing.expectEqualStrings("\xF0\x80\x80\x80M", transport.markTruncated(&scratch, scratch[0..20], 5, "M"));
    // continuation bytes with no lead before them: the cut stays, nothing underflows
    @memset(&scratch, 'a');
    @memcpy(scratch[0..4], "\x80\x80\x80\x80");
    try testing.expectEqualStrings("\x80\x80M", transport.markTruncated(&scratch, scratch[0..20], 3, "M"));
}

fn udpReceiver4() !struct { fd: linux.fd_t, port: u16 } {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
    const fd: linux.fd_t = @intCast(rc);
    var sa: linux.sockaddr.in = .{ .port = 0, .addr = std.mem.nativeToBig(u32, 0x7f000001) };
    if (linux.errno(linux.bind(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in))) != .SUCCESS) return error.SkipZigTest;
    var len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
    if (linux.errno(linux.getsockname(fd, @ptrCast(&sa), &len)) != .SUCCESS) return error.SkipZigTest;
    return .{ .fd = fd, .port = std.mem.bigToNative(u16, sa.port) };
}

fn udpReceiver6() !struct { fd: linux.fd_t, port: u16 } {
    const rc = linux.socket(linux.AF.INET6, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
    const fd: linux.fd_t = @intCast(rc);
    var sa: linux.sockaddr.in6 = .{ .port = 0, .flowinfo = 0, .addr = @as([16]u8, @splat(0)), .scope_id = 0 };
    sa.addr[15] = 1;
    if (linux.errno(linux.bind(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in6))) != .SUCCESS) return error.SkipZigTest;
    var len: linux.socklen_t = @sizeOf(linux.sockaddr.in6);
    if (linux.errno(linux.getsockname(fd, @ptrCast(&sa), &len)) != .SUCCESS) return error.SkipZigTest;
    return .{ .fd = fd, .port = std.mem.bigToNative(u16, sa.port) };
}

test "mutation 2026-11-27: UdpEmitter over IPv4 loopback: the datagram arrives and the emitter's own Options (limit, marker) apply" {
    const r = try udpReceiver4();
    defer _ = linux.close(r.fd);
    var e = try transport.UdpEmitter.open(testing.io, .{ .ip4 = .loopback(r.port) }, .{ .udp_limit = 60, .trunc_marker = "[T]" });
    defer e.close();
    try testing.expect(e.socket.address == .ip4); // an IPv4 peer is sent to from an IPv4 socket
    var buf: [2048]u8 = undefined;
    try e.send(&.{ .msg = "hello" });
    try testing.expectEqualStrings("<13>1 - - - - - - hello", try recvDgram(r.fd, &buf));
    const long: [100]u8 = @splat('x');
    try e.send(&.{ .msg = &long });
    const got = try recvDgram(r.fd, &buf);
    try testing.expectEqual(@as(usize, 60), got.len);
    try testing.expect(std.mem.endsWith(u8, got, "[T]"));
    try e.sendBsd(&.{ .tag = "t", .msg = &long });
    const got2 = try recvDgram(r.fd, &buf);
    try testing.expectEqual(@as(usize, 60), got2.len);
    try testing.expect(std.mem.endsWith(u8, got2, "[T]"));
}

test "mutation 2026-11-27: UdpEmitter over IPv6 loopback sends from an IPv6 socket" {
    const r = try udpReceiver6();
    defer _ = linux.close(r.fd);
    var e = transport.UdpEmitter.open(testing.io, .{ .ip6 = .loopback(r.port) }, .{}) catch return error.SkipZigTest;
    defer e.close();
    var buf: [256]u8 = undefined;
    try e.send(&.{ .msg = "six" });
    try testing.expectEqualStrings("<13>1 - - - - - - six", try recvDgram(r.fd, &buf));
}

// ── transport.zig: TcpEmitter / ReconnectingEmitter over unix stream sockets ─

test "mutation 2026-11-27: a broken TcpEmitter answers Broken on every send form without touching the socket" {
    var e: transport.TcpEmitter = .{ .io = testing.io, .stream = undefined, .broken = true };
    try testing.expectError(error.Broken, e.send(&.{ .msg = "x" }));
    try testing.expectError(error.Broken, e.sendBsd(&.{ .tag = "t", .msg = "x" }));
    try testing.expectError(error.Broken, e.sendRaw("x"));
}

test "mutation 2026-11-27: sendRaw of exactly 2048 and 2049 bytes arrives whole, framed with its length" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [128]u8 = undefined;
    const path = try sockPath(&tmp, &pb, "s");
    const l = try listenUnix(path, 8);
    defer _ = linux.close(l);
    var e = try transport.TcpEmitter.connectUnix(testing.io, path, 1000);
    defer e.close();
    const c = acceptWithin(l, 2000) orelse return error.NoConnection;
    defer _ = linux.close(c);
    e.framing = .octet_counting;
    for ([_]usize{ 2048, 2049 }) |n| {
        const payload = try testing.allocator.alloc(u8, n);
        defer testing.allocator.free(payload);
        @memset(payload, 'q');
        try e.sendRaw(payload);
        const want = try std.fmt.allocPrint(testing.allocator, "{d} {s}", .{ n, payload });
        defer testing.allocator.free(want);
        var rd: [4200]u8 = undefined;
        var got: usize = 0;
        while (got < want.len) {
            var pfd = [1]linux.pollfd{.{ .fd = c, .events = linux.POLL.IN, .revents = 0 }};
            try testing.expectEqual(@as(usize, 1), linux.poll(&pfd, 1, 2000));
            got += linux.read(c, rd[got..].ptr, want.len - got);
        }
        try testing.expectEqualStrings(want, rd[0..got]);
    }
}

test "mutation 2026-11-27: connect sockets are CLOEXEC and a failed connect leaks no descriptor" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [128]u8 = undefined;
    const path = try sockPath(&tmp, &pb, "s");
    const l = try listenUnix(path, 8);
    defer _ = linux.close(l);
    var e = try transport.TcpEmitter.connectUnix(testing.io, path, 1000);
    defer e.close();
    try testing.expect(cloexec(e.stream.socket.handle));
    var nb: [128]u8 = undefined;
    const none = try sockPath(&tmp, &nb, "none");
    _ = transport.TcpEmitter.connectUnix(testing.io, none, 100) catch {};
    const before = countFds();
    for (0..25) |_| {
        try testing.expectError(error.ConnectionRefused, transport.TcpEmitter.connectUnix(testing.io, none, 100));
    }
    try testing.expectEqual(before, countFds());
    var u = try unix.UnixEmitter.open(path);
    defer u.close();
    try testing.expect(cloexec(u.fd));
}

test "mutation 2026-11-27: connecting to a unix stream socket whose backlog is full is Timeout (the connect cannot wait)" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [128]u8 = undefined;
    const path = try sockPath(&tmp, &pb, "s");
    const l = try listenUnix(path, 0);
    defer _ = linux.close(l);
    var keep: [6]transport.TcpEmitter = undefined;
    var n: usize = 0;
    defer for (keep[0..n]) |*k| k.close();
    var failure: ?anyerror = null;
    while (n < keep.len) {
        keep[n] = transport.TcpEmitter.connectUnix(testing.io, path, 100) catch |err| {
            failure = err;
            break;
        };
        n += 1;
    }
    try testing.expectEqual(@as(?anyerror, error.Timeout), failure);
}

fn recon(path: []const u8, cfg: transport.ReconnectingEmitter.Config) transport.ReconnectingEmitter {
    return transport.ReconnectingEmitter.init(testing.io, .{ .unix = path }, cfg);
}

test "mutation 2026-11-27: ReconnectingEmitter keeps a live connection, close() drops it, config reaches the connection" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [128]u8 = undefined;
    const path = try sockPath(&tmp, &pb, "s");
    const l = try listenUnix(path, 8);
    defer _ = linux.close(l);
    var e = recon(path, .{ .framing = .lf, .send_timeout_ms = 1234 });
    defer e.close();
    try e.send(&.{ .msg = "one" });
    const c = acceptWithin(l, 2000) orelse return error.NoConnection;
    defer _ = linux.close(c);
    try testing.expectEqual(transport.Framing.lf, e.conn.?.framing);
    try testing.expectEqual(@as(u32, 1234), e.conn.?.send_timeout_ms);
    try readExact(c, "<13>1 - - - - - - one\n");
    // a live idle connection is reused: no second connection, no blocking peek
    try e.send(&.{ .msg = "two" });
    try readExact(c, "<13>1 - - - - - - two\n");
    try testing.expect(acceptWithin(l, 50) == null);
    try testing.expectEqual(@as(u64, 0), e.reconnects);
    // a trailer byte inside a formatted message becomes a space (RFC 6587 §3.4.2), both formats
    try e.send(&.{ .msg = "a\nb" });
    try readExact(c, "<13>1 - - - - - - a b\n");
    try e.sendBsd(&.{ .tag = "t", .msg = "a\nb" });
    try readExact(c, "<13>t: a b\n");
    // bytes the peer sent are not eaten by the liveness check (MSG_PEEK)
    _ = linux.write(c, "z", 1);
    try e.send(&.{ .msg = "three" });
    var z: [1]u8 = undefined;
    const rc = linux.recvfrom(e.conn.?.stream.socket.handle, &z, 1, linux.MSG.DONTWAIT, null, null);
    try testing.expectEqual(@as(usize, 1), rc);
    try testing.expectEqual(@as(u8, 'z'), z[0]);
    e.close();
    try testing.expect(e.conn == null);
}

test "mutation 2026-11-27: a write that fails on a live-looking connection is retried on a new one: retries = 1 yes, 0 no" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [128]u8 = undefined;
    const path = try sockPath(&tmp, &pb, "s");
    const l = try listenUnix(path, 8);
    defer _ = linux.close(l);
    var e = recon(path, .{ .retries = 1 });
    defer e.close();
    try e.send(&.{ .msg = "one" });
    const c1 = acceptWithin(l, 2000) orelse return error.NoConnection;
    defer _ = linux.close(c1);
    try readExact(c1, "<13>1 - - - - - - one\x00");
    // our write side is shut down: the peer is alive, the write fails
    _ = linux.shutdown(e.conn.?.stream.socket.handle, linux.SHUT.WR);
    try e.send(&.{ .msg = "two" });
    const c2 = acceptWithin(l, 2000) orelse return error.NoConnection;
    defer _ = linux.close(c2);
    try readExact(c2, "<13>1 - - - - - - two\x00");
    try testing.expectEqual(@as(u64, 1), e.reconnects);

    var z = recon(path, .{ .retries = 0 });
    defer z.close();
    try z.send(&.{ .msg = "a" });
    const c3 = acceptWithin(l, 2000) orelse return error.NoConnection;
    defer _ = linux.close(c3);
    _ = linux.shutdown(z.conn.?.stream.socket.handle, linux.SHUT.WR);
    try testing.expectError(error.WriteFailed, z.send(&.{ .msg = "b" }));
    try testing.expect(z.conn == null);
    try testing.expect(acceptWithin(l, 50) == null);
}

test "mutation 2026-11-27: a Timeout with nothing written keeps the connection usable" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [128]u8 = undefined;
    const path = try sockPath(&tmp, &pb, "s");
    const l = try listenUnix(path, 8);
    defer _ = linux.close(l);
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var e = recon(path, .{ .send_timeout_ms = 0 });
    e.io = threaded.io();
    defer e.close();
    var failure: ?anyerror = null;
    var i: usize = 0;
    while (i < 2_000_000) : (i += 1) {
        e.sendRaw("") catch |err| {
            failure = err;
            break;
        };
    }
    const c = acceptWithin(l, 2000) orelse return error.NoConnection;
    defer _ = linux.close(c);
    try testing.expectEqual(@as(?anyerror, error.Timeout), failure);
    try testing.expect(e.conn != null);
    try testing.expect(!e.conn.?.broken);
}

test "mutation 2026-11-27: a restarted peer is followed without leaking the dead connection's descriptor" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [128]u8 = undefined;
    const path = try sockPath(&tmp, &pb, "s");
    const l = try listenUnix(path, 8);
    defer _ = linux.close(l);
    var e = recon(path, .{});
    defer e.close();
    try e.send(&.{ .msg = "x" });
    var c = acceptWithin(l, 2000) orelse return error.NoConnection;
    const before = countFds();
    for (0..5) |_| {
        _ = linux.close(c);
        try e.send(&.{ .msg = "x" });
        c = acceptWithin(l, 2000) orelse return error.NoConnection;
    }
    _ = linux.close(c);
    try testing.expectEqual(before - 1, countFds());
    try testing.expectEqual(@as(u64, 5), e.reconnects);
}

test "mutation 2026-11-27: a failed connect schedules the next one backoff_ms after the failure (monotonic ms)" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [128]u8 = undefined;
    const path = try sockPath(&tmp, &pb, "none");
    var e = recon(path, .{ .backoff_ms = 5000 });
    defer e.close();
    const t0 = monoMs();
    try testing.expectError(error.ConnectionRefused, e.send(&.{ .msg = "x" }));
    const t1 = monoMs();
    try testing.expect(e.next_connect_ms >= t0 + 5000);
    try testing.expect(e.next_connect_ms <= t1 + 5000);
}

test "mutation 2026-11-27: a .host target: a name too long is UnknownHostName, a refused port is the connect's own error" {
    const io = testing.io;
    var long: [300]u8 = @splat('a');
    var bad = transport.ReconnectingEmitter.init(io, .{ .host = .{ .name = &long, .port = 1 } }, .{});
    try testing.expectError(error.UnknownHostName, bad.send(&.{ .msg = "x" }));

    var addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try addr.listen(io, .{});
    const port = server.socket.address.getPort();
    server.deinit(io);
    var e = transport.ReconnectingEmitter.init(io, .{ .host = .{ .name = "127.0.0.1", .port = port } }, .{});
    try testing.expectError(error.ConnectionRefused, e.send(&.{ .msg = "x" }));
}

test "mutation 2026-11-27: a .host target honours Config.connect_timeout_ms (a blackholed connect ends in ~100 ms, not 5 s)" {
    const io = testing.io;
    var addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try addr.listen(io, .{ .kernel_backlog = 0 });
    defer server.deinit(io);
    const target = server.socket.address;
    var keep: [16]transport.TcpEmitter = undefined;
    var n: usize = 0;
    defer for (keep[0..n]) |*k| k.close();
    var filled = false;
    while (n < keep.len) {
        keep[n] = transport.TcpEmitter.connectTimeout(io, target, 50) catch {
            filled = true;
            break;
        };
        n += 1;
    }
    if (!filled) return error.SkipZigTest;
    var e = transport.ReconnectingEmitter.init(io, .{ .host = .{ .name = "127.0.0.1", .port = target.getPort() } }, .{ .connect_timeout_ms = 100 });
    const t0 = monoMs();
    try testing.expectError(error.Timeout, e.send(&.{ .msg = "x" }));
    try testing.expect(monoMs() - t0 < 2500);
}

// ── transport.zig / unix.zig: private helpers, tested in their own files ────

// ── unix.zig ────────────────────────────────────────────────────────────────

test "mutation 2026-11-27: journal field names: A-Z 0-9 _ after the first byte, no digit or '_' first (journald rule, unix.zig doc)" {
    const V = unix.journal.validFieldName;
    var b: usize = 0;
    while (b < 256) : (b += 1) {
        const name = [_]u8{ 'A', @intCast(b) };
        const ok = (b >= 'A' and b <= 'Z') or (b >= '0' and b <= '9') or b == '_';
        if (ok) try V(&name) else try testing.expectError(error.FieldNameInvalidChar, V(&name));
        const first = [_]u8{ @intCast(b), 'A' };
        const bad_start = b == '_' or (b >= '0' and b <= '9');
        if (bad_start) {
            try testing.expectError(error.FieldNameInvalidStart, V(&first));
        } else if ((b >= 'A' and b <= 'Z')) {
            try V(&first);
        } else try testing.expectError(error.FieldNameInvalidChar, V(&first));
    }
}

test "mutation 2026-11-27: UnixEmitter with nobody at the path is WriteFailed (ENOENT), not MessageTooLarge" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [128]u8 = undefined;
    const path = try sockPath(&tmp, &pb, "none");
    var e = try unix.UnixEmitter.open(path);
    defer e.close();
    try testing.expectError(error.WriteFailed, e.sendRaw("x"));
}

test "mutation 2026-11-27: an entry past the datagram limit goes through a sealed memfd with one SCM_RIGHTS descriptor, none leaked" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [128]u8 = undefined;
    const path = try sockPath(&tmp, &pb, "j");
    const rx = try bindDgram(path);
    defer _ = linux.close(rx);
    var e = try unix.journal.Emitter.open(path);
    defer e.close();
    const value = try testing.allocator.alloc(u8, 1 << 20);
    defer testing.allocator.free(value);
    @memset(value, 'v');
    const before = countFds();
    try e.send(&.{.{ .name = "MESSAGE", .value = value }});
    try testing.expectEqual(before, countFds());

    var dummy: [8]u8 = undefined;
    var iov = [1]std.posix.iovec{.{ .base = &dummy, .len = dummy.len }};
    var ctrl: [64]u8 align(8) = undefined;
    var msg: linux.msghdr = .{ .name = null, .namelen = 0, .iov = &iov, .iovlen = 1, .control = &ctrl, .controllen = ctrl.len, .flags = 0 };
    var pfd = [1]linux.pollfd{.{ .fd = rx, .events = linux.POLL.IN, .revents = 0 }};
    try testing.expectEqual(@as(usize, 1), linux.poll(&pfd, 1, 2000));
    const rc = linux.recvmsg(rx, &msg, 0);
    try testing.expectEqual(@as(usize, 0), rc); // an empty datagram carries the descriptor
    // struct cmsghdr { size_t len; int level; int type; } then the int
    const cmsg_len = std.mem.readInt(usize, ctrl[0..8], .little);
    try testing.expectEqual(@as(usize, 20), cmsg_len); // CMSG_LEN(sizeof(int)): exactly one descriptor
    try testing.expectEqual(@as(i32, 1), std.mem.readInt(i32, ctrl[8..12], .little)); // SOL_SOCKET
    try testing.expectEqual(@as(i32, 1), std.mem.readInt(i32, ctrl[12..16], .little)); // SCM_RIGHTS
    const mfd = std.mem.readInt(i32, ctrl[16..20], .little);
    defer _ = linux.close(mfd);
    // sealed against further change (F_GET_SEALS = 1034; all four seals)
    try testing.expectEqual(@as(usize, 0xF), linux.fcntl(mfd, 1034, 0));
    var head: [16]u8 = undefined;
    try testing.expectEqual(@as(usize, 16), linux.pread(mfd, &head, head.len, 0));
    try testing.expectEqualStrings("MESSAGE=vvvvvvvv", &head);
    try testing.expectEqual(@as(usize, (1 << 20) + "MESSAGE=\n".len), linux.lseek(mfd, 0, linux.SEEK.END));
}

// ── logger.zig ──────────────────────────────────────────────────────────────

const Cap = struct {
    buf: [8192]u8 = undefined,
    len: usize = 0,
    n: usize = 0,
    trailer: ?u8 = null,
    local: bool = false,

    fn sink(c: *Cap) logger.Sink {
        return .{ .ctx = c, .sendFn = send, .local = c.local, .trailer = c.trailer };
    }
    fn send(ctx: *anyopaque, bytes: []const u8) logger.Sink.Error!void {
        const c: *Cap = @ptrCast(@alignCast(ctx));
        @memcpy(c.buf[0..bytes.len], bytes);
        c.len = bytes.len;
        c.n += 1;
    }
    fn line(c: *const Cap) []const u8 {
        return c.buf[0..c.len];
    }
};

fn fixed() message.Timestamp {
    return .{ .unix_ms = 1783600496123 };
}

test "mutation 2026-11-27: Sink.from* set local and trailer as the target says" {
    var u: unix.UnixEmitter = .{ .fd = -1, .addr = unixAddr("x") };
    try testing.expect(logger.Sink.fromUnix(&u).local);
    var rt = recon("x", .{});
    const s1 = logger.Sink.fromReconnecting(&rt);
    try testing.expect(s1.local);
    try testing.expectEqual(@as(?u8, 0), s1.trailer);
    var rn = transport.ReconnectingEmitter.init(testing.io, .{ .tcp = .{ .ip4 = .loopback(1) } }, .{});
    const s2 = logger.Sink.fromReconnecting(&rn);
    try testing.expect(!s2.local);
    try testing.expectEqual(@as(?u8, null), s2.trailer);
    var w: std.Io.Writer = .fixed(&.{});
    var we: transport.WriterEmitter = .{ .writer = &w, .framing = .lf };
    try testing.expectEqual(@as(?u8, '\n'), logger.Sink.fromWriter(&we).trailer);
}

test "mutation 2026-11-27: Sink.fromUdp reports a refused datagram as WriteFailed" {
    const r = try udpReceiver4();
    defer _ = linux.close(r.fd);
    var e = try transport.UdpEmitter.open(testing.io, .{ .ip4 = .loopback(r.port) }, .{});
    defer e.close();
    const s = logger.Sink.fromUdp(&e);
    const huge = try testing.allocator.alloc(u8, 70_000); // past the 65507-byte UDP maximum
    defer testing.allocator.free(huge);
    @memset(huge, 'x');
    try testing.expectError(error.WriteFailed, s.sendFn(s.ctx, huge));
}

test "mutation 2026-11-27: Logger options: max_line clamps to 8192, an equal severity is logged by print, the facility is in the 5424 PRI" {
    var c: Cap = .{};
    var l = logger.Logger.init(c.sink(), .{ .hostname = "h", .app_name = "a", .procid = "1", .now = fixed, .max_line = 100_000, .facility = .local3, .max_severity = .warning });
    try testing.expectEqual(@as(usize, 8192), l.max_line);
    try l.print(.warning, "x{d}", .{1});
    try testing.expectEqual(@as(usize, 1), c.n);
    try testing.expect(std.mem.startsWith(u8, c.line(), "<156>1 ")); // local3 (19) * 8 + warning (4)
    try l.print(.notice, "x{d}", .{1});
    try testing.expectEqual(@as(usize, 1), c.n);
}

test "mutation 2026-11-27: Logger: a trailer byte at the very end of a line is replaced, text past 4 KiB is cut to 4096 bytes with the marker" {
    var c: Cap = .{ .trailer = '\n' };
    var l = logger.Logger.init(c.sink(), .{ .hostname = "h", .app_name = "a", .procid = "1", .now = fixed });
    try l.log(.info, "abc\n");
    try testing.expectEqual(@as(u8, ' '), c.line()[c.len - 1]);
    try testing.expect(std.mem.indexOfScalar(u8, c.line(), '\n') == null);

    var c2: Cap = .{};
    var l2 = logger.Logger.init(c2.sink(), .{ .hostname = "h", .app_name = "a", .procid = "1", .now = fixed, .max_line = 8192 });
    const long: [5000]u8 = @splat('x');
    try l2.print(.info, "{s}", .{@as([]const u8, &long)});
    const m = try parser.parse(c2.line());
    try testing.expectEqual(@as(usize, 4096), m.msg.len);
    try testing.expect(std.mem.endsWith(u8, m.msg, logger.trunc_marker));
}

test "mutation 2026-11-27: Logger RFC 3164: an empty PID is left out, a one-byte PID is kept" {
    var c: Cap = .{};
    var l = logger.Logger.init(c.sink(), .{ .format = .rfc3164, .hostname = "h", .app_name = "a", .procid = "", .now = fixed });
    try l.info("m");
    try testing.expect(std.mem.indexOfScalar(u8, c.line(), '[') == null);
    var l1 = logger.Logger.init(c.sink(), .{ .format = .rfc3164, .hostname = "h", .app_name = "a", .procid = "7", .now = fixed });
    try l1.info("m");
    try testing.expect(std.mem.indexOf(u8, c.line(), "a[7]: m") != null);
}

test "mutation 2026-11-27: Logger defaults: the wall clock and the executable's name" {
    var c: Cap = .{};
    var l = logger.Logger.init(c.sink(), .{ .hostname = "h", .procid = "1" });
    try l.info("m");
    const m = try parser.parse(c.line());
    try testing.expect(m.timestamp.?.unix_us > 1_577_836_800 * 1_000_000); // after 2020-01-01
    var path: [4096]u8 = undefined;
    const rc = linux.readlink("/proc/self/exe", &path, path.len);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
    const full = path[0..rc];
    const base = full[std.mem.findScalarLast(u8, full, '/').? + 1 ..];
    try testing.expectEqualStrings(base[0..@min(base.len, 48)], l.appName());
}

const Excl = struct {
    inside: std.atomic.Value(u32) = .init(0),
    overlap: std.atomic.Value(u32) = .init(0),

    fn send(ctx: *anyopaque, bytes: []const u8) logger.Sink.Error!void {
        _ = bytes;
        const x: *Excl = @ptrCast(@alignCast(ctx));
        if (x.inside.fetchAdd(1, .acq_rel) != 0) _ = x.overlap.fetchAdd(1, .monotonic);
        const ts: linux.timespec = .{ .sec = 0, .nsec = 20_000 };
        _ = linux.nanosleep(&ts, null);
        _ = x.inside.fetchSub(1, .acq_rel);
    }
};

fn hammer(l: *logger.Logger) void {
    for (0..150) |_| l.info("m") catch {};
}

test "mutation 2026-11-27: Logger: only one thread at a time is inside the sink (the lock excludes)" {
    var x: Excl = .{};
    var l = logger.Logger.init(.{ .ctx = &x, .sendFn = Excl.send }, .{ .hostname = "h", .app_name = "a", .procid = "1", .now = fixed });
    var ts: [4]std.Thread = undefined;
    for (&ts) |*t| t.* = try std.Thread.spawn(.{}, hammer, .{&l});
    for (ts) |t| t.join();
    try testing.expectEqual(@as(u32, 0), x.overlap.load(.monotonic));
}

const Chain = struct {
    s1: std.Io.Writer,
    s2: std.Io.Writer,
    b1: [64]u8 = undefined,
    b2: [64]u8 = undefined,
    rec: [64]u8 = undefined,
    n: usize = 0,

    fn init(c: *Chain) void {
        c.s1 = .{ .vtable = &.{ .drain = drain1 }, .buffer = &c.b1 };
        c.s2 = .{ .vtable = &.{ .drain = drain2 }, .buffer = &c.b2 };
    }
    fn drainAll(w: *std.Io.Writer, data: []const []const u8, splat: usize, sink: *std.Io.Writer) std.Io.Writer.Error!usize {
        try sink.writeAll(w.buffered());
        w.end = 0;
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            try sink.writeAll(d);
            n += d.len;
        }
        for (0..splat) |_| try sink.writeAll(data[data.len - 1]);
        return n + data[data.len - 1].len * splat;
    }
    fn drain1(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const c: *Chain = @alignCast(@fieldParentPtr("s1", w));
        return drainAll(w, data, splat, &c.s2);
    }
    fn drain2(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const c: *Chain = @alignCast(@fieldParentPtr("s2", w));
        _ = splat;
        @memcpy(c.rec[c.n..][0..w.end], w.buffer[0..w.end]);
        c.n += w.end;
        w.end = 0;
        var n: usize = 0;
        for (data) |d| {
            @memcpy(c.rec[c.n..][0..d.len], d);
            c.n += d.len;
            n += d.len;
        }
        return n;
    }
};

test "mutation 2026-11-27: WriterEmitter flushes its writer and then the downstream writer after every message" {
    var c: Chain = .{ .s1 = undefined, .s2 = undefined };
    c.init();
    var e: transport.WriterEmitter = .{ .writer = &c.s1, .downstream = &c.s2, .framing = .lf };
    try e.sendRaw("hi");
    try testing.expectEqualStrings("hi\n", c.rec[0..c.n]);
}
