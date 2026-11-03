// SPDX-License-Identifier: MIT
//! The cross-platform userspace configuration protocol: the text `get=1` / `set=1`
//! exchange over `/var/run/wireguard/<ifname>.sock` that wireguard-go, boringtun
//! and other userspace implementations serve in place of the kernel's netlink
//! family. Same `Config` and `Device` as `Wireguard`, so a program can drive both.
//!
//!     var c: uapi.Client = .{ .gpa = gpa };
//!     var dev: Device = undefined;
//!     try c.getDevice("wg0", &dev);
//!     defer dev.deinit(gpa);
//!     try c.setDevice(&.{ .ifname = "wg0", .listen_port = 51820 });
//!
//! Written from https://www.wireguard.com/xplatform/ and read against wireguard-go
//! `device/uapi.go` (b3bc704ef0ee, MIT). The frames are checked against a real
//! wireguard-go by `zig build interop-wireguard -- --wireguard-go`, which froze
//! `testdata/uapi_get.txt`. The socket's other end is another process: every line
//! and count it sends is hostile input, bounded by `Client.limits`, `max_reply`, the
//! line length and a deadline over the whole exchange.

const std = @import("std");
const linux = std.os.linux;
const root = @import("root.zig");
const conf = @import("conf.zig");
const hs = @import("handshake.zig");
const wipe = @import("wipe.zig");
const burn = @import("burn.zig");

const Allocator = std.mem.Allocator;
const Config = root.Config;
const Device = root.Device;
const Peer = root.Peer;
const AllowedIp = root.AllowedIp;
const Key = root.Key;

pub const default_dir = "/var/run/wireguard";

/// A line longer than this is refused: the longest real one is about 90 bytes.
pub const max_line_len: usize = 512;

// ── hex keys, constant time ─────────────────────────────────────────────────

/// A key as 64 lowercase hex characters. No table and no branch on the key.
pub fn keyToHex(key: *const Key, out: *[64]u8) void {
    for (key, 0..) |b, i| {
        out[i * 2] = hexDigit(b >> 4);
        out[i * 2 + 1] = hexDigit(b & 0xf);
    }
}

fn hexDigit(n: u8) u8 {
    const v: u16 = n;
    // 0xff.. when v > 9: the letters start 39 above '0' + 10.
    const over = (@as(u16, 9) -% v) >> 8;
    return @truncate(0x30 + v + (over & 39));
}

/// 64 hex characters, either case, into `out` (zeroed on error). No branch and
/// no table on the characters; the only thing that depends on them is the verdict.
pub fn keyFromHex(text: []const u8, out: *Key) error{InvalidKey}!void {
    if (text.len != 64) {
        std.crypto.secureZero(u8, out);
        return error.InvalidKey;
    }
    var bad: u16 = 0;
    for (out, 0..) |*b, i| {
        const hi = hexValue(text[i * 2]);
        const lo = hexValue(text[i * 2 + 1]);
        bad |= (hi | lo) & 0x100;
        b.* = @truncate((hi << 4) | (lo & 0xf));
    }
    if (bad != 0) {
        std.crypto.secureZero(u8, out);
        return error.InvalidKey;
    }
}

/// The nibble, or a value with bit 8 set when `c` is no hex digit.
fn hexValue(c: u8) u16 {
    const x: u16 = c;
    const d = x ^ 0x30;
    const digit = ((d -% 10) >> 8) & 0xff; // 0xff iff 0..9
    const a = ((x | 0x20) -% 0x61) & 0xff;
    const alpha = ((a -% 6) >> 8) & 0xff; // 0xff iff a..f
    const invalid = ~(digit | alpha) & 0xff;
    return (d & digit) | ((a + 10) & alpha) | (invalid << 1);
}

// ── set ─────────────────────────────────────────────────────────────────────

/// The request text, `set=1` to the blank line. `cfg.ifname` is not in it: the
/// socket says which device. `error.InvalidConfig`: an allowed-ip whose family,
/// length and prefix disagree, the text form of which would mean something else.
pub fn writeSet(w: *std.Io.Writer, cfg: *const Config) (std.Io.Writer.Error || error{InvalidConfig})!void {
    try w.writeAll("set=1\n");
    if (cfg.private_key) |*k| try writeKey(w, "private_key", k);
    if (cfg.listen_port) |v| try w.print("listen_port={d}\n", .{v});
    if (cfg.fwmark) |v| try w.print("fwmark={d}\n", .{v});
    if (cfg.replace_peers) try w.writeAll("replace_peers=true\n");
    for (cfg.peers) |*p| {
        try writeKey(w, "public_key", &p.public_key);
        if (p.remove) {
            try w.writeAll("remove=true\n");
            continue;
        }
        if (p.update_only) try w.writeAll("update_only=true\n");
        if (p.preshared_key) |*k| try writeKey(w, "preshared_key", k);
        if (p.endpoint) |e| {
            var buf: [conf.max_endpoint_text_len]u8 = undefined;
            try w.print("endpoint={s}\n", .{conf.formatEndpoint(e, &buf)});
        }
        if (p.persistent_keepalive_interval) |v| try w.print("persistent_keepalive_interval={d}\n", .{v});
        if (p.replace_allowed_ips) try w.writeAll("replace_allowed_ips=true\n");
        for (p.allowed_ips) |*ip| {
            if (!ip.valid()) return error.InvalidConfig;
            try w.writeAll("allowed_ip=");
            try conf.formatAllowedIp(w, ip);
            try w.writeByte('\n');
        }
    }
    try w.writeByte('\n');
}

fn writeKey(w: *std.Io.Writer, name: []const u8, key: *const Key) std.Io.Writer.Error!void {
    var b: [64]u8 = undefined;
    keyToHex(key, &b);
    defer std.crypto.secureZero(u8, &b);
    try w.print("{s}={s}\n", .{ name, &b });
}

// ── get ─────────────────────────────────────────────────────────────────────

pub const ParseError = error{
    OutOfMemory,
    /// A line this protocol cannot mean: no `=`, a bad number, a bad key, a peer
    /// field before any `public_key`.
    MalformedReply,
    /// Over `root.Limits`.
    LimitExceeded,
};

/// Reads the reply to `get=1` one line at a time. Keeps no slice of any line.
/// Pure: `Client` feeds it from the socket, tests and fuzzers from bytes.
pub const GetParser = struct {
    gpa: Allocator,
    limits: root.Limits = .{},
    dev: Device = .{},
    peers: std.ArrayList(Peer) = .empty,
    ips: std.ArrayList(AllowedIp) = .empty,
    total_ips: u64 = 0,
    in_peer: bool = false,
    /// Set when the `errno=` line came. Any other number: the device refused.
    errno: ?i64 = null,

    pub fn init(gpa: Allocator, limits: root.Limits) GetParser {
        return .{ .gpa = gpa, .limits = limits };
    }

    pub fn deinit(p: *GetParser) void {
        for (p.peers.items) |peer| p.gpa.free(peer.allowed_ips);
        std.crypto.secureZero(u8, std.mem.sliceAsBytes(p.peers.allocatedSlice()));
        p.peers.deinit(p.gpa);
        p.ips.deinit(p.gpa);
        std.crypto.secureZero(u8, std.mem.asBytes(&p.dev));
        p.* = undefined;
    }

    /// One line, without its newline. A key this module does not know is
    /// skipped, for the protocol to grow.
    pub fn feedLine(p: *GetParser, line: []const u8) ParseError!void {
        const eq = std.mem.findScalar(u8, line, '=') orelse return error.MalformedReply;
        const key = line[0..eq];
        const v = line[eq + 1 ..];
        if (std.mem.eql(u8, key, "errno")) {
            p.errno = std.fmt.parseInt(i64, v, 10) catch return error.MalformedReply;
        } else if (std.mem.eql(u8, key, "public_key")) {
            try p.closePeer();
            if (p.peers.items.len >= p.limits.max_peers) return error.LimitExceeded;
            var k: Key = undefined;
            keyFromHex(v, &k) catch return error.MalformedReply;
            try p.reservePeer();
            p.peers.appendAssumeCapacity(.{ .public_key = k });
            p.in_peer = true;
        } else if (!p.in_peer) {
            if (std.mem.eql(u8, key, "private_key")) {
                try secretKeyLine(v, &p.dev.private_key);
            } else if (std.mem.eql(u8, key, "listen_port")) {
                p.dev.listen_port = number(u16, v) orelse return error.MalformedReply;
            } else if (std.mem.eql(u8, key, "fwmark")) {
                p.dev.fwmark = number(u32, v) orelse return error.MalformedReply;
            } else if (isPeerKey(key)) {
                return error.MalformedReply;
            }
        } else {
            const peer = &p.peers.items[p.peers.items.len - 1];
            if (std.mem.eql(u8, key, "preshared_key")) {
                try secretKeyLine(v, &peer.preshared_key);
            } else if (std.mem.eql(u8, key, "endpoint")) {
                peer.endpoint = conf.parseEndpoint(v) orelse return error.MalformedReply;
            } else if (std.mem.eql(u8, key, "persistent_keepalive_interval")) {
                peer.persistent_keepalive_interval = number(u16, v) orelse return error.MalformedReply;
            } else if (std.mem.eql(u8, key, "last_handshake_time_sec")) {
                peer.last_handshake_time.sec = number(i64, v) orelse return error.MalformedReply;
            } else if (std.mem.eql(u8, key, "last_handshake_time_nsec")) {
                peer.last_handshake_time.nsec = number(i64, v) orelse return error.MalformedReply;
            } else if (std.mem.eql(u8, key, "tx_bytes")) {
                peer.tx_bytes = number(u64, v) orelse return error.MalformedReply;
            } else if (std.mem.eql(u8, key, "rx_bytes")) {
                peer.rx_bytes = number(u64, v) orelse return error.MalformedReply;
            } else if (std.mem.eql(u8, key, "protocol_version")) {
                peer.protocol_version = number(u32, v) orelse return error.MalformedReply;
            } else if (std.mem.eql(u8, key, "allowed_ip")) {
                p.total_ips += 1;
                if (p.total_ips > p.limits.max_allowed_ips) return error.LimitExceeded;
                try p.ips.append(p.gpa, AllowedIp.parse(v) catch return error.MalformedReply);
            }
        }
    }

    /// A private or pre-shared key line. Under a burn: the `?Key` on its way into `out`
    /// is one more copy in the dead frame, and `defer` wipes only `k`. Per key line,
    /// not per line of the reply, where it would cost 4 KiB per allowed-ip.
    fn secretKeyLine(v: []const u8, out: *?Key) ParseError!void {
        return burn.run(burn.cp_burn, ParseError!void, secretKeyLineBody, .{ v, out });
    }

    fn secretKeyLineBody(v: []const u8, out: *?Key) ParseError!void {
        var k: Key = undefined;
        defer std.crypto.secureZero(u8, &k);
        keyFromHex(v, &k) catch return error.MalformedReply;
        out.* = if (isZero(&k)) null else k;
    }

    fn isPeerKey(key: []const u8) bool {
        for ([_][]const u8{ "preshared_key", "endpoint", "persistent_keepalive_interval", "last_handshake_time_sec", "last_handshake_time_nsec", "tx_bytes", "rx_bytes", "protocol_version", "allowed_ip" }) |k| {
            if (std.mem.eql(u8, key, k)) return true;
        }
        return false;
    }

    /// Like `DeviceParser`: growth wipes the block it leaves (peers hold PSKs).
    fn reservePeer(p: *GetParser) error{OutOfMemory}!void {
        if (p.peers.items.len < p.peers.capacity) return;
        const cap = @max(4, p.peers.capacity * 2);
        const fresh = try p.gpa.alloc(Peer, cap);
        @memcpy(fresh[0..p.peers.items.len], p.peers.items);
        const old = p.peers.allocatedSlice();
        std.crypto.secureZero(u8, std.mem.sliceAsBytes(old));
        p.gpa.free(old);
        p.peers.items = fresh[0..p.peers.items.len];
        p.peers.capacity = cap;
    }

    fn closePeer(p: *GetParser) error{OutOfMemory}!void {
        if (!p.in_peer) return;
        const last = &p.peers.items[p.peers.items.len - 1];
        last.allowed_ips = try p.ips.toOwnedSlice(p.gpa);
        // Lines after a refused `public_key` must not land on this peer again,
        // whose list would then be overwritten and lost.
        p.in_peer = false;
    }

    /// Hand over the device; the parser is left empty, for `deinit`. The public
    /// key is derived (the protocol does not carry one), and it is the one line of
    /// this file that spends an X25519.
    pub fn finishInto(p: *GetParser, out: *Device) error{OutOfMemory}!void {
        try p.closePeer();
        p.in_peer = false;
        const peers = try p.gpa.alloc(Peer, p.peers.items.len);
        @memcpy(peers, p.peers.items);
        const old = p.peers.allocatedSlice();
        std.crypto.secureZero(u8, std.mem.sliceAsBytes(old));
        p.gpa.free(old);
        p.peers = .empty;
        out.* = p.dev;
        out.peers = peers;
        std.crypto.secureZero(u8, std.mem.asBytes(&p.dev));
        p.dev = .{};
        if (out.private_key) |*k| {
            var kp: hs.Keypair = undefined;
            defer std.crypto.secureZero(u8, &kp.private);
            out.public_key = if (hs.Keypair.fromPrivateKey(k, &kp)) kp.public else |_| null;
        }
    }
};

pub fn number(comptime T: type, v: []const u8) ?T {
    // parseInt takes a sign and underscores; the protocol has plain digits.
    if (v.len == 0) return null;
    for (v) |c| if (c < '0' or c > '9') return null;
    return std.fmt.parseInt(T, v, 10) catch null;
}

fn isZero(k: *const Key) bool {
    var acc: u8 = 0;
    for (k) |b| acc |= b;
    return acc == 0;
}

// ── the socket ──────────────────────────────────────────────────────────────

pub const ClientError = error{
    OutOfMemory,
    /// Not a valid interface name (and so not a path to build).
    InvalidName,
    /// An `InvalidConfig` allowed-ip.
    InvalidConfig,
    /// No such socket, or nobody listening: not a userspace device.
    NoSuchDevice,
    AccessDenied,
    SendFailed,
    /// The peer closed early.
    RecvFailed,
    /// `timeout_ms` passed before the exchange ended.
    TimedOut,
    MalformedReply,
    /// The reply is longer than `max_reply`, or holds more than `limits`.
    LimitExceeded,
    /// The device refused: `Client.last_errno` has its number.
    DeviceError,
    SystemResources,
    Unexpected,
};

pub const Client = struct {
    gpa: Allocator,
    /// Where the sockets are.
    dir: []const u8 = default_dir,
    /// A deadline over one whole `getDevice` or `setDevice`, connect to last byte,
    /// on the monotonic clock; 0 = none. The other end is a process that may hang, or
    /// dribble: a receive timeout alone would let it hold us for as long as it
    /// keeps sending a byte now and then.
    timeout_ms: u32 = 5000,
    /// Smaller than `root.Limits`' defaults: that is the kernel's own ceiling, and
    /// this socket's other end is less trusted. Raise them for a bigger device.
    limits: root.Limits = default_limits,
    /// The reply as a whole; with `max_line_len` it bounds the parser's work.
    max_reply: usize = default_max_reply,
    /// The device's error number from the last `DeviceError`.
    last_errno: i64 = 0,

    /// 4096 peers and 65536 allowed-ips (16 per peer), 2 MB or so of `Device`.
    pub const default_limits: root.Limits = .{ .max_peers = 4096, .max_allowed_ips = 65536 };
    /// Those limits as text: about 300 bytes per peer and 25 per allowed-ip, 2.9 MB.
    pub const default_max_reply: usize = 4 * 1024 * 1024;

    /// Fetch `ifname`'s configuration and state. Free with `Device.deinit`.
    pub fn getDevice(c: *Client, ifname: []const u8, out: *Device) ClientError!void {
        const deadline: Deadline = .after(c.timeout_ms);
        const fd = try c.connect(ifname, deadline);
        defer _ = linux.close(fd);
        try c.getOverFd(fd, ifname, out, deadline);
    }

    /// Apply `cfg` to the device named in `cfg.ifname`. A partial failure is the
    /// protocol's own: the device applied the lines before the one it refused.
    pub fn setDevice(c: *Client, cfg: *const Config) ClientError!void {
        const deadline: Deadline = .after(c.timeout_ms);
        const fd = try c.connect(cfg.ifname, deadline);
        defer _ = linux.close(fd);
        try c.setOverFd(fd, cfg, deadline);
    }

    fn getOverFd(c: *Client, fd: i32, ifname: []const u8, out: *Device, deadline: Deadline) ClientError!void {
        try sendAll(fd, "get=1\n\n", deadline);
        var parser: GetParser = .init(c.gpa, c.limits);
        defer parser.deinit();
        var r: LineReader = .{ .fd = fd, .max_total = c.max_reply, .deadline = deadline };
        defer r.wipe();
        while (true) {
            const line = try r.next();
            if (line.len == 0) break;
            parser.feedLine(line) catch |err| return switch (err) {
                error.OutOfMemory => error.OutOfMemory,
                error.MalformedReply => error.MalformedReply,
                error.LimitExceeded => error.LimitExceeded,
            };
        }
        const code = parser.errno orelse return error.MalformedReply;
        if (code != 0) {
            c.last_errno = code;
            return error.DeviceError;
        }
        try parser.finishInto(out);
        const n = @min(ifname.len, out.name_buf.len - 1);
        @memcpy(out.name_buf[0..n], ifname[0..n]);
        out.name_len = @intCast(n);
    }

    fn setOverFd(c: *Client, fd: i32, cfg: *const Config, deadline: Deadline) ClientError!void {
        // The text holds the keys: built in blocks that are wiped when released.
        var wa = wipe.WipingAllocator.init(c.gpa);
        var text: std.Io.Writer.Allocating = .init(wa.allocator());
        defer text.deinit();
        writeSet(&text.writer, cfg) catch |err| return switch (err) {
            error.WriteFailed => error.OutOfMemory,
            error.InvalidConfig => error.InvalidConfig,
        };
        try sendAll(fd, text.written(), deadline);
        var r: LineReader = .{ .fd = fd, .max_total = max_line_len * 4, .deadline = deadline };
        var code: ?i64 = null;
        while (true) {
            const line = try r.next();
            if (line.len == 0) break;
            if (std.mem.startsWith(u8, line, "errno="))
                code = std.fmt.parseInt(i64, line[6..], 10) catch return error.MalformedReply;
        }
        const v = code orelse return error.MalformedReply;
        if (v != 0) {
            c.last_errno = v;
            return error.DeviceError;
        }
    }

    fn connect(c: *const Client, ifname: []const u8, deadline: Deadline) ClientError!i32 {
        if (!validName(ifname)) return error.InvalidName;
        var sa: linux.sockaddr.un = .{ .path = @splat(0) };
        const path = std.mem.print(&sa.path, "{s}/{s}.sock", .{ c.dir, ifname }) catch return error.InvalidName;
        if (path.len >= sa.path.len) return error.InvalidName;

        const rc = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .ACCES, .PERM => return error.AccessDenied,
            .MFILE, .NFILE, .NOBUFS, .NOMEM => return error.SystemResources,
            else => return error.Unexpected,
        }
        const fd: i32 = @intCast(rc);
        errdefer _ = linux.close(fd);
        // connect has no poll form that fits a Unix socket's full backlog: bound it
        // by the socket's own timeout, the time that is left.
        if (deadline.end_ms != null) try setTimeouts(fd, try deadline.remainingMs());
        while (true) {
            switch (linux.errno(linux.connect(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.un)))) {
                .SUCCESS => return fd,
                .INTR => continue,
                .NOENT, .CONNREFUSED, .NOTDIR => return error.NoSuchDevice,
                .ACCES, .PERM => return error.AccessDenied,
                .AGAIN => return error.TimedOut,
                .NOMEM, .NOBUFS => return error.SystemResources,
                else => return error.Unexpected,
            }
        }
    }
};

/// The end of one exchange on the monotonic clock. `.{}` = no end.
const Deadline = struct {
    end_ms: ?u64 = null,

    fn nowMs() u64 {
        var ts: linux.timespec = undefined;
        _ = linux.clock_gettime(.MONOTONIC, &ts);
        return @as(u64, @intCast(ts.sec)) *| 1000 +| @as(u64, @intCast(@divTrunc(ts.nsec, 1_000_000)));
    }

    fn after(ms: u32) Deadline {
        return if (ms == 0) .{} else .{ .end_ms = nowMs() +| ms };
    }

    /// At least 1, or `TimedOut`.
    fn remainingMs(d: Deadline) ClientError!u32 {
        const end = d.end_ms orelse return std.math.maxInt(u32);
        const now = nowMs();
        if (now >= end) return error.TimedOut;
        return @intCast(@min(end - now, std.math.maxInt(i32)));
    }

    /// Until `fd` is ready for `events`, or the end.
    fn wait(d: Deadline, fd: i32, events: i16) ClientError!void {
        if (d.end_ms == null) return;
        while (true) {
            const left = try d.remainingMs();
            var pfd = [1]linux.pollfd{.{ .fd = fd, .events = events, .revents = 0 }};
            const rc = linux.poll(&pfd, 1, @intCast(left));
            switch (linux.errno(rc)) {
                .SUCCESS => if (rc != 0) return,
                .INTR => {},
                else => return error.Unexpected,
            }
        }
    }
};

/// An interface name that also is one path component.
fn validName(ifname: []const u8) bool {
    if (ifname.len == 0 or ifname.len >= root.ifnamsiz) return false;
    if (std.mem.eql(u8, ifname, ".") or std.mem.eql(u8, ifname, "..")) return false;
    for (ifname) |ch| if (ch == '/' or ch == 0) return false;
    return true;
}

fn setTimeouts(fd: i32, millis: u32) ClientError!void {
    const tv: linux.timeval = .{ .sec = @intCast(millis / 1000), .usec = @intCast((millis % 1000) * 1000) };
    for ([_]u32{ linux.SO.RCVTIMEO, linux.SO.SNDTIMEO }) |opt| {
        switch (linux.errno(linux.setsockopt(fd, linux.SOL.SOCKET, opt, @ptrCast(&tv), @sizeOf(linux.timeval)))) {
            .SUCCESS => {},
            else => return error.Unexpected,
        }
    }
}

fn sendAll(fd: i32, bytes: []const u8, deadline: Deadline) ClientError!void {
    var rest = bytes;
    // Under a deadline a send never blocks: `wait` does, for what is left.
    const flags: u32 = linux.MSG.NOSIGNAL | (if (deadline.end_ms != null) @as(u32, linux.MSG.DONTWAIT) else 0);
    while (rest.len != 0) {
        try deadline.wait(fd, linux.POLL.OUT);
        // MSG_NOSIGNAL: a daemon that went away is an error here, never a SIGPIPE
        // in the consumer's process.
        const rc = linux.sendto(fd, rest.ptr, rest.len, flags, null, 0);
        switch (linux.errno(rc)) {
            .SUCCESS => rest = rest[rc..],
            .INTR, .AGAIN => continue,
            else => return error.SendFailed,
        }
    }
}

/// Lines off a stream. The buffer sees key text, so it is wiped.
const LineReader = struct {
    fd: i32,
    max_total: usize,
    deadline: Deadline = .{},
    total: usize = 0,
    buf: [8192]u8 = undefined,
    start: usize = 0,
    end: usize = 0,

    fn wipe(r: *LineReader) void {
        std.crypto.secureZero(u8, &r.buf);
    }

    /// The next line without its newline; valid until the next call.
    fn next(r: *LineReader) ClientError![]const u8 {
        while (true) {
            if (std.mem.findScalar(u8, r.buf[r.start..r.end], '\n')) |i| {
                if (i > max_line_len) return error.MalformedReply;
                const line = r.buf[r.start..][0..i];
                r.start += i + 1;
                return line;
            }
            if (r.end - r.start > max_line_len) return error.MalformedReply;
            if (r.start != 0) {
                const live = r.end - r.start;
                std.mem.copyForwards(u8, r.buf[0..live], r.buf[r.start..r.end]);
                r.start = 0;
                r.end = live;
            }
            try r.deadline.wait(r.fd, linux.POLL.IN);
            const rc = linux.recvfrom(r.fd, r.buf[r.end..].ptr, r.buf.len - r.end, 0, null, null);
            switch (linux.errno(rc)) {
                .SUCCESS => {},
                .INTR => continue,
                else => return error.RecvFailed,
            }
            if (rc == 0) return error.RecvFailed; // closed before the blank line
            r.total += rc;
            if (r.total > r.max_total) return error.LimitExceeded;
            r.end += rc;
        }
    }
};

/// The sockets in `dir`: the names of the userspace devices on this machine
/// (`wg show interfaces`, `wgctrl.Client.Devices`). Free with `gpa.free`.
/// A missing directory is an empty list: no userspace device has run yet.
pub fn listDevices(io: std.Io, gpa: Allocator, dir_path: []const u8) (Allocator.Error || error{ AccessDenied, Unexpected })![]root.DeviceName {
    var names: std.ArrayList(root.DeviceName) = .empty;
    errdefer names.deinit(gpa);
    var dir = std.Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return names.toOwnedSlice(gpa),
        error.AccessDenied, error.PermissionDenied => return error.AccessDenied,
        else => return error.Unexpected,
    };
    defer dir.close(io);
    var it = dir.iterate();
    while (it.next(io) catch return error.Unexpected) |e| {
        if (e.kind != .unix_domain_socket) continue;
        if (!std.mem.endsWith(u8, e.name, ".sock")) continue;
        const stem = e.name[0 .. e.name.len - ".sock".len];
        if (!validName(stem)) continue;
        try names.append(gpa, root.DeviceName.init(stem));
    }
    return names.toOwnedSlice(gpa);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "hex keys: both cases in, lowercase out, every byte value, and refusals" {
    var k: Key = undefined;
    for (&k, 0..) |*b, i| b.* = @intCast(i * 8 + 3);
    var t: [64]u8 = undefined;
    keyToHex(&k, &t);
    var std_hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&std_hex, "{x}", .{&k}) catch unreachable;
    try testing.expectEqualStrings(&std_hex, &t);

    for (0..256) |v| {
        const b: u8 = @intCast(v);
        const kk: Key = @splat(b);
        keyToHex(&kk, &t);
        var back: Key = undefined;
        try keyFromHex(&t, &back);
        try testing.expectEqual(kk, back);
        for (&t) |*c| c.* = std.ascii.toUpper(c.*);
        try keyFromHex(&t, &back);
        try testing.expectEqual(kk, back);
    }
    // Every non-hex character, at both nibble positions, against std's idea.
    for (0..256) |v| {
        const c: u8 = @intCast(v);
        var bad: [64]u8 = @splat('0');
        bad[10] = c;
        var out: Key = @splat(1);
        const ok = std.ascii.isHex(c);
        if (keyFromHex(&bad, &out)) |_| {
            try testing.expect(ok);
        } else |_| {
            try testing.expect(!ok);
            try testing.expectEqual(@as(Key, @splat(0)), out);
        }
        bad = @splat('0');
        bad[11] = c;
        try testing.expectEqual(ok, std.meta.isError(keyFromHex(&bad, &out)) == false);
    }
    var out: Key = undefined;
    try testing.expectError(error.InvalidKey, keyFromHex("abc", &out));
}

const hex_a = "e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a";
const hex_b = "b85996fecc9c7f1fc6d2572a76eda11d59bcd20be8e543b15ce4bd85a8e75a33";
const hex_c = "188515093e952f5f22e865cef3012e72f8b5f0b598ac0309d5dacce3b70fcf52";

test "writeSet: the exact frame" {
    const k_a = blk: {
        var k: Key = undefined;
        try keyFromHex(hex_a, &k);
        break :blk k;
    };
    const k_b = blk: {
        var k: Key = undefined;
        try keyFromHex(hex_b, &k);
        break :blk k;
    };
    const k_c = blk: {
        var k: Key = undefined;
        try keyFromHex(hex_c, &k);
        break :blk k;
    };
    const ips = [_]AllowedIp{ AllowedIp.v4(.{ 192, 168, 4, 4 }, 32), AllowedIp.v6(blk: {
        var a: [16]u8 = @splat(0);
        a[0] = 0xfd;
        a[15] = 1;
        break :blk a;
    }, 128) };
    const peers = [_]root.PeerConfig{
        .{
            .public_key = k_b,
            .update_only = true,
            .preshared_key = k_c,
            .endpoint = .{ .v4 = .{ .addr = .{ 203, 0, 113, 1 }, .port = 12912 } },
            .persistent_keepalive_interval = 25,
            .replace_allowed_ips = true,
            .allowed_ips = &ips,
        },
        // Removal says nothing else, whatever the rest of the entry holds.
        .{ .public_key = k_c, .remove = true, .preshared_key = k_a, .allowed_ips = &ips },
    };
    const cfg: Config = .{ .ifname = "wg0", .private_key = k_a, .listen_port = 12912, .fwmark = 0, .replace_peers = true, .peers = &peers };
    var out: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    try writeSet(&w, &cfg);
    try testing.expectEqualStrings("set=1\nprivate_key=" ++ hex_a ++
        "\nlisten_port=12912\nfwmark=0\nreplace_peers=true\npublic_key=" ++ hex_b ++
        "\nupdate_only=true\npreshared_key=" ++ hex_c ++
        "\nendpoint=203.0.113.1:12912\npersistent_keepalive_interval=25\nreplace_allowed_ips=true\nallowed_ip=192.168.4.4/32\nallowed_ip=fd00::1/128\npublic_key=" ++ hex_c ++
        "\nremove=true\n\n", w.buffered());

    var w2: std.Io.Writer = .fixed(&out);
    try writeSet(&w2, &Config{});
    try testing.expectEqualStrings("set=1\n\n", w2.buffered());

    // An entry the text would misrepresent.
    var bad_ip = ips[0];
    bad_ip.cidr = 33;
    const bad_peers = [_]root.PeerConfig{.{ .public_key = k_b, .allowed_ips = (&bad_ip)[0..1] }};
    var w3: std.Io.Writer = .fixed(&out);
    try testing.expectError(error.InvalidConfig, writeSet(&w3, &Config{ .peers = &bad_peers }));
}

fn parseAll(gpa: Allocator, text: []const u8, limits: root.Limits, out: *Device) !?i64 {
    var p: GetParser = .init(gpa, limits);
    defer p.deinit();
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        if (line.len == 0) break;
        try p.feedLine(line);
    }
    try p.finishInto(out);
    return p.errno;
}

test "GetParser: a real wireguard-go reply, frozen from tools/interop.zig --uapi" {
    const text = @embedFile("testdata/uapi_get.txt");
    var dev: Device = undefined;
    const code = try parseAll(testing.allocator, text, .{}, &dev);
    defer dev.deinit(testing.allocator);
    try testing.expectEqual(@as(?i64, 0), code);
    try testing.expectEqual(@as(u16, 51821), dev.listen_port);
    try testing.expect(dev.private_key != null and dev.public_key != null);
    try testing.expectEqual(@as(usize, 2), dev.peers.len);
    const a = dev.peers[0];
    const b = dev.peers[1];
    // wireguard-go's peer order is a Go map's: each is found by what it has.
    const named = if (a.endpoint != null) a else b;
    const other = if (a.endpoint != null) b else a;
    try testing.expectEqual(@as(u16, 12912), named.endpoint.?.v4.port);
    try testing.expectEqual(@as(u16, 25), named.persistent_keepalive_interval);
    try testing.expectEqual(@as(u32, 1), named.protocol_version);
    try testing.expectEqual(@as(usize, 2), named.allowed_ips.len);
    try testing.expect(named.preshared_key != null);
    try testing.expect(other.preshared_key == null); // all-zero on the wire
    try testing.expect(other.endpoint == null);
    try testing.expectEqual(@as(usize, 1), other.allowed_ips.len);
}

test "GetParser: what it refuses, and what it skips" {
    const a = testing.allocator;
    var dev: Device = undefined;
    const pk = "public_key=" ++ hex_b ++ "\n";
    try testing.expectError(error.MalformedReply, parseAll(a, "no-equals\n", .{}, &dev));
    try testing.expectError(error.MalformedReply, parseAll(a, "listen_port=65536\n", .{}, &dev));
    try testing.expectError(error.MalformedReply, parseAll(a, "listen_port=-1\n", .{}, &dev));
    try testing.expectError(error.MalformedReply, parseAll(a, "listen_port=\n", .{}, &dev));
    try testing.expectError(error.MalformedReply, parseAll(a, "fwmark=+1\n", .{}, &dev));
    try testing.expectError(error.MalformedReply, parseAll(a, "private_key=zz\n", .{}, &dev));
    try testing.expectError(error.MalformedReply, parseAll(a, "public_key=zz\n", .{}, &dev));
    try testing.expectError(error.MalformedReply, parseAll(a, "allowed_ip=10.0.0.1/32\n", .{}, &dev));
    try testing.expectError(error.MalformedReply, parseAll(a, pk ++ "allowed_ip=10.0.0.1/33\n", .{}, &dev));
    try testing.expectError(error.MalformedReply, parseAll(a, pk ++ "endpoint=nope\n", .{}, &dev));
    try testing.expectError(error.MalformedReply, parseAll(a, pk ++ "tx_bytes=x\n", .{}, &dev));
    try testing.expectError(error.MalformedReply, parseAll(a, "errno=x\n", .{}, &dev));
    try testing.expectError(error.LimitExceeded, parseAll(a, pk ++ pk, .{ .max_peers = 1 }, &dev));
    try testing.expectError(error.LimitExceeded, parseAll(a, pk ++ "allowed_ip=10.0.0.1/32\nallowed_ip=10.0.0.2/32\n", .{ .max_allowed_ips = 1 }, &dev));

    // Fed on after a refusal (the fuzzer does): nothing leaks, nothing lands wrong.
    {
        var q: GetParser = .init(a, .{ .max_peers = 1 });
        defer q.deinit();
        try q.feedLine(pk[0 .. pk.len - 1]);
        try q.feedLine("allowed_ip=10.0.0.1/32");
        try testing.expectError(error.LimitExceeded, q.feedLine(pk[0 .. pk.len - 1]));
        try testing.expectError(error.MalformedReply, q.feedLine("allowed_ip=10.0.0.2/32"));
        try testing.expectError(error.LimitExceeded, q.feedLine(pk[0 .. pk.len - 1]));
    }

    const code = try parseAll(a, "future_key=1\n" ++ pk ++ "another_future_key=2\nerrno=5\n", .{}, &dev);
    defer dev.deinit(a);
    try testing.expectEqual(@as(?i64, 5), code);
    try testing.expectEqual(@as(usize, 1), dev.peers.len);
    try testing.expect(dev.public_key == null);
}

test "GetParser: out of memory anywhere frees everything" {
    const text = "private_key=" ++ hex_a ++ "\npublic_key=" ++ hex_b ++ "\nallowed_ip=10.0.0.1/32\nallowed_ip=10.0.0.2/32\npublic_key=" ++ hex_c ++ "\nallowed_ip=10.0.0.3/32\nerrno=0\n";
    var fail_at: usize = 0;
    while (true) : (fail_at += 1) {
        var fa = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = fail_at });
        var dev: Device = undefined;
        if (parseAll(fa.allocator(), text, .{}, &dev)) |_| {
            dev.deinit(fa.allocator());
            break;
        } else |err| try testing.expectEqual(error.OutOfMemory, err);
    }
}

test "hex keys: more than 64 characters are refused, and the output is zeroed" {
    const zero: Key = @splat(0);
    var k: Key = @splat(0x55);
    try testing.expectError(error.InvalidKey, keyFromHex(hex_a ++ "0", &k));
    try testing.expectEqual(zero, k);
    k = @splat(0x55);
    try testing.expectError(error.InvalidKey, keyFromHex(hex_a ++ hex_b, &k));
    try testing.expectEqual(zero, k);
    try keyFromHex(hex_a, &k); // 64 is still fine
    var dev: Device = undefined;
    try testing.expectError(error.MalformedReply, parseAll(testing.allocator, "private_key=" ++ hex_a ++ "0\n", .{}, &dev));
}

test "GetParser: max_allowed_ips is a limit on the total: the limit itself passes" {
    const a = testing.allocator;
    const pk = "public_key=" ++ hex_b ++ "\n";
    var dev: Device = undefined;
    _ = try parseAll(a, pk ++ "allowed_ip=10.0.0.1/32\nallowed_ip=10.0.0.2/32\n", .{ .max_allowed_ips = 2 }, &dev);
    defer dev.deinit(a);
    try testing.expectEqual(@as(usize, 2), dev.peers[0].allowed_ips.len);
    try testing.expectError(error.LimitExceeded, parseAll(a, pk ++ "allowed_ip=10.0.0.1/32\nallowed_ip=10.0.0.2/32\nallowed_ip=10.0.0.3/32\n", .{ .max_allowed_ips = 2 }, &dev));
}

test "GetParser: an all-zero private or pre-shared key is no key" {
    const a = testing.allocator;
    const zeros: [64]u8 = @splat('0');
    var dev: Device = undefined;
    _ = try parseAll(a, "private_key=" ++ zeros ++ "\npublic_key=" ++ hex_b ++ "\npreshared_key=" ++ zeros ++ "\n", .{}, &dev);
    defer dev.deinit(a);
    try testing.expect(dev.private_key == null);
    try testing.expect(dev.public_key == null);
    try testing.expect(dev.peers[0].preshared_key == null);
    // A key that is not all zero stays one.
    var dev2: Device = undefined;
    const nonzero: [64]u8 = blk: {
        var t: [64]u8 = zeros;
        t[63] = '1';
        break :blk t;
    };
    _ = try parseAll(a, "private_key=" ++ nonzero ++ "\n", .{}, &dev2);
    defer dev2.deinit(a);
    try testing.expect(dev2.private_key != null and dev2.public_key != null);
}

test "GetParser: finishing leaves no private key in the parser" {
    var p: GetParser = .init(testing.allocator, .{});
    defer p.deinit();
    var key: Key = undefined;
    try keyFromHex(hex_a, &key);
    try p.feedLine("private_key=" ++ hex_a);
    var dev: Device = undefined;
    try p.finishInto(&dev);
    defer dev.deinit(testing.allocator);
    try testing.expectEqual(key, dev.private_key.?);
    try testing.expectEqual(@as(?usize, null), std.mem.find(u8, std.mem.asBytes(&p.dev), &key));
    try testing.expect(p.dev.private_key == null);
}

/// An allocator that notes whether a block of `watch` bytes is clean when it is freed.
const FreeCheck = struct {
    child: Allocator,
    watch: usize,
    freed: usize = 0,
    dirty: usize = 0,

    fn allocator(self: *FreeCheck) Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Allocator.VTable = .{ .alloc = alloc, .resize = resize, .remap = remap, .free = free };

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *FreeCheck = @ptrCast(@alignCast(ctx));
        return self.child.rawAlloc(len, alignment, ret_addr);
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *FreeCheck = @ptrCast(@alignCast(ctx));
        return self.child.rawResize(memory, alignment, new_len, ret_addr);
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *FreeCheck = @ptrCast(@alignCast(ctx));
        return self.child.rawRemap(memory, alignment, new_len, ret_addr);
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *FreeCheck = @ptrCast(@alignCast(ctx));
        if (memory.len == self.watch) {
            self.freed += 1;
            if (!std.mem.allEqual(u8, memory, 0)) self.dirty += 1;
        }
        self.child.rawFree(memory, alignment, ret_addr);
    }
};

test "GetParser: the peer block it outgrows is wiped before it is freed" {
    // `Allocator.free` fills the block with 0xaa first where runtime safety is on, which
    // hides the wipe from anything under it: only a build without safety can see it.
    if (std.debug.runtime_safety) return error.SkipZigTest;
    // Capacity 4 first; the fifth peer moves the list to 8 and frees the 4-peer block.
    var fc: FreeCheck = .{ .child = testing.allocator, .watch = 4 * @sizeOf(Peer) };
    var p: GetParser = .init(fc.allocator(), .{});
    defer p.deinit();
    for (0..5) |_| {
        try p.feedLine("public_key=" ++ hex_b);
        try p.feedLine("preshared_key=" ++ hex_a);
    }
    try testing.expectEqual(@as(usize, 1), fc.freed);
    try testing.expectEqual(@as(usize, 0), fc.dirty);
}

test "Client: the line buffer is wiped" {
    var r: LineReader = .{ .fd = -1, .max_total = 1 << 20 };
    @memset(r.buf[0..200], 0x5a);
    @memcpy(r.buf[8000..][0..12], "private_key=");
    r.wipe();
    for (r.buf) |x| try testing.expectEqual(@as(u8, 0), x);
}

/// A reply of exactly `total` bytes: filler lines, then `errno=0` and the blank line.
fn replyOf(buf: []u8, total: usize) []const u8 {
    const tail = "errno=0\n\n";
    var n: usize = 0;
    while (n + tail.len < total) {
        const room = total - tail.len - n;
        // Never leave one byte: it would have to be a blank line.
        const len: usize = if (room > 100) (if (room - 100 == 1) 99 else 100) else room;
        @memset(buf[n..][0 .. len - 1], 'x');
        buf[n + len - 1] = '\n';
        n += len;
    }
    @memcpy(buf[n..][0..tail.len], tail);
    return buf[0 .. n + tail.len];
}

test "Client: the reply limit is on the whole reply: the limit itself passes, one byte more does not" {
    const a = testing.allocator;
    var buf: [4096]u8 = undefined;
    // get: `max_reply` 9 holds exactly `errno=0` and the blank line.
    for ([_]struct { max: usize, ok: bool }{ .{ .max = 9, .ok = true }, .{ .max = 8, .ok = false } }) |c| {
        const fds = try pair();
        defer _ = linux.close(fds[0]);
        var cl: Client = .{ .gpa = a, .max_reply = c.max };
        var d: FakeDaemon = .{ .fd = fds[1], .reply = "errno=0\n\n" };
        const th = try std.Thread.spawn(.{}, FakeDaemon.run, .{&d});
        var dev: Device = undefined;
        if (c.ok) {
            try cl.getOverFd(fds[0], "wg0", &dev, .{});
            dev.deinit(a);
        } else try testing.expectError(error.LimitExceeded, cl.getOverFd(fds[0], "wg0", &dev, .{}));
        th.join();
    }
    // set: the reply to a set may be 4 lines long, `max_line_len * 4` = 2048 bytes.
    for ([_]struct { total: usize, ok: bool }{ .{ .total = 2048, .ok = true }, .{ .total = 2049, .ok = false } }) |c| {
        const fds = try pair();
        defer _ = linux.close(fds[0]);
        var cl: Client = .{ .gpa = a };
        var d: FakeDaemon = .{ .fd = fds[1], .reply = replyOf(&buf, c.total) };
        const th = try std.Thread.spawn(.{}, FakeDaemon.run, .{&d});
        if (c.ok) {
            try cl.setOverFd(fds[0], &Config{}, .{});
        } else try testing.expectError(error.LimitExceeded, cl.setOverFd(fds[0], &Config{}, .{}));
        th.join();
    }
}

test "Client: a socket path fills a sockaddr_un up to 107 bytes, 108 is refused" {
    // dir + "/wg0.sock" is 9 bytes longer than dir.
    const d98: [98]u8 = @splat('x');
    const d99: [99]u8 = @splat('x');
    var dev: Device = undefined;
    var c: Client = .{ .gpa = testing.allocator, .dir = &d98 };
    try testing.expectError(error.NoSuchDevice, c.getDevice("wg0", &dev));
    c.dir = &d99;
    try testing.expectError(error.InvalidName, c.getDevice("wg0", &dev));
}

/// Client over a socketpair, a thread playing the daemon.
const FakeDaemon = struct {
    fd: i32,
    reply: []const u8,
    got: [2048]u8 = undefined,
    got_len: usize = 0,

    fn run(d: *FakeDaemon) void {
        // Read to the blank line, then answer.
        while (d.got_len < 2 or !std.mem.endsWith(u8, d.got[0..d.got_len], "\n\n")) {
            const rc = linux.recvfrom(d.fd, d.got[d.got_len..].ptr, d.got.len - d.got_len, 0, null, null);
            if (linux.errno(rc) != .SUCCESS or rc == 0) break;
            d.got_len += rc;
        }
        _ = linux.sendto(d.fd, d.reply.ptr, d.reply.len, linux.MSG.NOSIGNAL, null, 0);
        _ = linux.close(d.fd);
    }
};

fn pair() ![2]i32 {
    var fds: [2]i32 = undefined;
    if (linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &fds)) != .SUCCESS) return error.SkipZigTest;
    return fds;
}

test "Client: get and set over a socket, an error number, a daemon that goes away" {
    const a = testing.allocator;
    var c: Client = .{ .gpa = a };

    {
        const fds = try pair();
        defer _ = linux.close(fds[0]);
        var d: FakeDaemon = .{ .fd = fds[1], .reply = "listen_port=7\npublic_key=" ++ hex_b ++ "\nallowed_ip=10.0.0.1/32\nerrno=0\n\n" };
        const th = try std.Thread.spawn(.{}, FakeDaemon.run, .{&d});
        var dev: Device = undefined;
        try c.getOverFd(fds[0], "wg0", &dev, .{});
        defer dev.deinit(a);
        th.join();
        try testing.expectEqualStrings("get=1\n\n", d.got[0..d.got_len]);
        try testing.expectEqual(@as(u16, 7), dev.listen_port);
        try testing.expectEqualStrings("wg0", dev.ifname());
        try testing.expectEqual(@as(usize, 1), dev.peers[0].allowed_ips.len);
    }
    {
        const fds = try pair();
        defer _ = linux.close(fds[0]);
        var d: FakeDaemon = .{ .fd = fds[1], .reply = "errno=0\n\n" };
        const th = try std.Thread.spawn(.{}, FakeDaemon.run, .{&d});
        try c.setOverFd(fds[0], &Config{ .listen_port = 9 }, .{});
        th.join();
        try testing.expectEqualStrings("set=1\nlisten_port=9\n\n", d.got[0..d.got_len]);
    }
    {
        const fds = try pair();
        defer _ = linux.close(fds[0]);
        var d: FakeDaemon = .{ .fd = fds[1], .reply = "errno=22\n\n" };
        const th = try std.Thread.spawn(.{}, FakeDaemon.run, .{&d});
        try testing.expectError(error.DeviceError, c.setOverFd(fds[0], &Config{}, .{}));
        th.join();
        try testing.expectEqual(@as(i64, 22), c.last_errno);
    }
    {
        const fds = try pair();
        defer _ = linux.close(fds[0]);
        var d: FakeDaemon = .{ .fd = fds[1], .reply = "errno=1\n\n" };
        const th = try std.Thread.spawn(.{}, FakeDaemon.run, .{&d});
        var dev: Device = undefined;
        try testing.expectError(error.DeviceError, c.getOverFd(fds[0], "wg0", &dev, .{}));
        th.join();
        try testing.expectEqual(@as(i64, 1), c.last_errno);
    }
    // Closed before the blank line.
    {
        const fds = try pair();
        defer _ = linux.close(fds[0]);
        var d: FakeDaemon = .{ .fd = fds[1], .reply = "listen_port=7\n" };
        const th = try std.Thread.spawn(.{}, FakeDaemon.run, .{&d});
        var dev: Device = undefined;
        try testing.expectError(error.RecvFailed, c.getOverFd(fds[0], "wg0", &dev, .{}));
        th.join();
    }
    // No errno line at all.
    {
        const fds = try pair();
        defer _ = linux.close(fds[0]);
        var d: FakeDaemon = .{ .fd = fds[1], .reply = "listen_port=7\n\n" };
        const th = try std.Thread.spawn(.{}, FakeDaemon.run, .{&d});
        var dev: Device = undefined;
        try testing.expectError(error.MalformedReply, c.getOverFd(fds[0], "wg0", &dev, .{}));
        th.join();
    }
    // A line with no end, and a reply with no end.
    {
        const fds = try pair();
        defer _ = linux.close(fds[0]);
        const long: [max_line_len + 100]u8 = @splat('x');
        var d: FakeDaemon = .{ .fd = fds[1], .reply = &long };
        const th = try std.Thread.spawn(.{}, FakeDaemon.run, .{&d});
        var dev: Device = undefined;
        try testing.expectError(error.MalformedReply, c.getOverFd(fds[0], "wg0", &dev, .{}));
        th.join();
    }
    {
        const fds = try pair();
        defer _ = linux.close(fds[0]);
        var tiny: Client = .{ .gpa = a, .max_reply = 16 };
        var d: FakeDaemon = .{ .fd = fds[1], .reply = "listen_port=7\nlisten_port=7\nlisten_port=7\nerrno=0\n\n" };
        const th = try std.Thread.spawn(.{}, FakeDaemon.run, .{&d});
        var dev: Device = undefined;
        try testing.expectError(error.LimitExceeded, tiny.getOverFd(fds[0], "wg0", &dev, .{}));
        th.join();
    }
    // The other end gone: an error, no SIGPIPE.
    {
        const fds = try pair();
        defer _ = linux.close(fds[0]);
        _ = linux.close(fds[1]);
        try testing.expectError(error.SendFailed, c.setOverFd(fds[0], &Config{}, .{}));
    }
}

const Dribble = struct {
    fd: i32,
    /// One byte, then a pause, until the other end goes away.
    fn run(d: *Dribble) void {
        var rx: [64]u8 = undefined;
        _ = linux.recvfrom(d.fd, &rx, rx.len, 0, null, null);
        while (true) {
            const rc = linux.sendto(d.fd, "x", 1, linux.MSG.NOSIGNAL, null, 0);
            if (linux.errno(rc) != .SUCCESS) break;
            var pfd = [1]linux.pollfd{.{ .fd = d.fd, .events = 0, .revents = 0 }};
            _ = linux.poll(&pfd, 1, 20);
        }
        _ = linux.close(d.fd);
    }
};

test "Client: the deadline covers the exchange: a daemon that dribbles, one that says nothing" {
    const a = testing.allocator;
    var c: Client = .{ .gpa = a };
    const fds = try pair();
    var d: Dribble = .{ .fd = fds[1] };
    const th = try std.Thread.spawn(.{}, Dribble.run, .{&d});
    const t0 = Deadline.nowMs();
    var dev: Device = undefined;
    try testing.expectError(error.TimedOut, c.getOverFd(fds[0], "wg0", &dev, .after(120)));
    const took = Deadline.nowMs() - t0;
    try testing.expect(took >= 100 and took < 4000);
    _ = linux.close(fds[0]);
    th.join();

    // Silent, after reading what we said. (set: its own path through the reader.)
    const fds2 = try pair();
    defer _ = linux.close(fds2[0]);
    defer _ = linux.close(fds2[1]);
    try testing.expectError(error.TimedOut, c.setOverFd(fds2[0], &Config{}, .after(30)));
    // A deadline already over refuses before any byte moves.
    try testing.expectError(error.TimedOut, c.setOverFd(fds2[0], &Config{}, .{ .end_ms = 1 }));
}

test "Client: a line over the limit is refused, whole or still arriving" {
    var r: LineReader = .{ .fd = -1, .max_total = 1 << 20 };
    const n = max_line_len + 1;
    @memset(r.buf[0..n], 'x');
    r.buf[n] = '\n';
    r.end = n + 1;
    try testing.expectError(error.MalformedReply, r.next());
    var ok: LineReader = .{ .fd = -1, .max_total = 1 << 20 };
    @memset(ok.buf[0 .. n - 1], 'x');
    ok.buf[n - 1] = '\n';
    ok.end = n;
    try testing.expectEqual(max_line_len, (try ok.next()).len);
}

test "Client: the defaults are smaller than the kernel's limits" {
    const c: Client = .{ .gpa = testing.allocator };
    try testing.expectEqual(@as(u32, 4096), c.limits.max_peers);
    try testing.expectEqual(@as(u32, 65536), c.limits.max_allowed_ips);
    try testing.expectEqual(@as(usize, 4 << 20), c.max_reply);
    try testing.expect(c.limits.max_peers < (root.Limits{}).max_peers);
}

test "Client: names that are no path component are refused before any syscall" {
    var c: Client = .{ .gpa = testing.allocator, .dir = "/nonexistent-wg-dir" };
    var dev: Device = undefined;
    for ([_][]const u8{ "", ".", "..", "a/b", "0123456789abcdef", "a\x00b" }) |bad| {
        try testing.expectError(error.InvalidName, c.getDevice(bad, &dev));
        try testing.expectError(error.InvalidName, c.setDevice(&Config{ .ifname = bad }));
    }
    try testing.expectError(error.NoSuchDevice, c.getDevice("wg0", &dev));
    // A directory path that cannot fit a sockaddr_un.
    const long_dir: [200]u8 = @splat('x');
    var long: Client = .{ .gpa = testing.allocator, .dir = &long_dir };
    try testing.expectError(error.InvalidName, long.getDevice("wg0", &dev));
}

test "listDevices: a missing directory is an empty list" {
    const names = try listDevices(testing.io, testing.allocator, "/nonexistent-wg-dir");
    defer testing.allocator.free(names);
    try testing.expectEqual(@as(usize, 0), names.len);
}

const uapi_fuzz = struct {
    const fuzz_driver = @import("testkit").fuzz.driver;
    const Label = enum { raw_line, built_ok, built_bad, roundtrip };
    var reach: [@typeInfo(Label).@"enum".field_names.len]usize = @splat(0);

    fn mark(comptime l: Label) void {
        reach[@backingInt(l)] += 1;
        fuzz_driver.hit(@tagName(l));
    }

    const fragments = [_][]const u8{
        "private_key=" ++ hex_a,         "public_key=" ++ hex_b, "public_key=" ++ hex_c,             "preshared_key=" ++ hex_c,       "listen_port=51820", "fwmark=7",
        "endpoint=1.2.3.4:5",            "endpoint=[::1%3]:5",   "persistent_keepalive_interval=25", "allowed_ip=10.0.0.0/8",         "allowed_ip=::/0",   "tx_bytes=1",
        "rx_bytes=18446744073709551615", "protocol_version=1",   "last_handshake_time_sec=1",        "last_handshake_time_nsec=2",    "errno=0",           "errno=-1",
        "unknown=",                      "=",                    "preshared_key=",                   "tx_bytes=18446744073709551616",
    };

    fn harness(comptime S: type, smith: *S, gpa: std.mem.Allocator) anyerror!void {
        var p: GetParser = .init(gpa, .{ .max_peers = 8, .max_allowed_ips = 8 });
        defer p.deinit();
        var raw: [256]u8 = undefined;
        const n = smith.slice(&raw);
        var it = std.mem.splitScalar(u8, raw[0..n], '\n');
        while (it.next()) |line| {
            mark(.raw_line);
            p.feedLine(line) catch {};
        }
        var q: GetParser = .init(gpa, .{ .max_peers = 8, .max_allowed_ips = 8 });
        defer q.deinit();
        const lines = smith.value(u8) % 16;
        var ok = true;
        for (0..lines) |_| {
            q.feedLine(fragments[smith.value(u8) % fragments.len]) catch {
                ok = false;
                mark(.built_bad);
            };
        }
        if (ok) mark(.built_ok);
        // Whatever the parser holds finishes, frees, and prints as a set frame
        // that parses back to the same peer count.
        var dev: Device = undefined;
        try q.finishInto(&dev);
        defer dev.deinit(gpa);
        var cfgs: std.ArrayList(root.PeerConfig) = .empty;
        defer cfgs.deinit(gpa);
        for (dev.peers) |peer| {
            try cfgs.append(gpa, .{
                .public_key = peer.public_key,
                .preshared_key = peer.preshared_key,
                .endpoint = peer.endpoint,
                .persistent_keepalive_interval = peer.persistent_keepalive_interval,
                .allowed_ips = peer.allowed_ips,
            });
        }
        var text: std.Io.Writer.Allocating = .init(gpa);
        defer text.deinit();
        try writeSet(&text.writer, &Config{ .peers = cfgs.items, .private_key = dev.private_key, .listen_port = dev.listen_port, .fwmark = dev.fwmark });
        var r: GetParser = .init(gpa, .{});
        defer r.deinit();
        var lit = std.mem.splitScalar(u8, text.written(), '\n');
        _ = lit.next(); // set=1
        while (lit.next()) |line| {
            if (line.len == 0) break;
            try r.feedLine(line);
        }
        var back: Device = undefined;
        try r.finishInto(&back);
        defer back.deinit(gpa);
        if (back.peers.len != dev.peers.len or back.listen_port != dev.listen_port or back.fwmark != dev.fwmark)
            return error.RoundTripMismatch;
        if (!std.meta.eql(back.private_key, dev.private_key)) return error.RoundTripMismatch;
        for (back.peers, dev.peers) |x, y| {
            if (!std.mem.eql(u8, &x.public_key, &y.public_key) or x.allowed_ips.len != y.allowed_ips.len or x.persistent_keepalive_interval != y.persistent_keepalive_interval)
                return error.RoundTripMismatch;
            if (!std.meta.eql(x.preshared_key, y.preshared_key) or !std.meta.eql(x.endpoint, y.endpoint))
                return error.RoundTripMismatch;
            for (x.allowed_ips, y.allowed_ips) |ip1, ip2| {
                if (ip1.family != ip2.family or ip1.cidr != ip2.cidr or !std.mem.eql(u8, ip1.bytes(), ip2.bytes()))
                    return error.RoundTripMismatch;
            }
        }
        mark(.roundtrip);
    }
};

test "fuzz driver: WIREGUARD_FUZZ (wireguard-uapi)" {
    try uapi_fuzz.fuzz_driver.run(uapi_fuzz.harness, .{ .prefix = "WIREGUARD_FUZZ", .name = "wireguard-uapi" });
}

test "fuzz harness: 300 seeds of wireguard-uapi in every test run, and they get everywhere" {
    uapi_fuzz.reach = @splat(0);
    for (0..300) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: uapi_fuzz.fuzz_driver.Rng = .{ .r = prng.random() };
        try uapi_fuzz.harness(uapi_fuzz.fuzz_driver.Rng, &rng, testing.allocator);
    }
    for (uapi_fuzz.reach, 0..) |n, i| {
        if (n == 0) {
            std.debug.print("reach: wireguard-uapi label {d} never hit\n", .{i});
            return error.HarnessDoesNotReach;
        }
    }
}
