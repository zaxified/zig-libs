// SPDX-License-Identifier: MIT

//! proxyproto — HAProxy PROXY protocol v1 (text) and v2 (binary): a pure
//! parser, a reader that consumes the header from a `std.Io.Reader` only when
//! one is present and the peer is trusted, a TLV walker with typed helpers, and
//! a writer for the proxy side.
//!
//! A server behind a load balancer learns the real client address only from the
//! header the balancer prepends to the stream. Accepting it from anybody lets
//! any client claim any address, so `read` takes the trusted peers as part of
//! its options and an empty list refuses every header (SPEC.md § Trust).
//!
//! Wire format: HAProxy `doc/proxy-protocol.txt`, versions 1 and 2. Written
//! clean-room from the specification.

const std = @import("std");
const netaddr = @import("netaddr");
const crc32c = @import("crc32c");

pub const meta = .{
    .doc = "PROXY protocol v1/v2 (HAProxy) — allocation-free parser, peek-and-toss reader with a trusted-peers rule as the default, TLV walker (ALPN, authority, CRC32C, SSL sub-TLVs, unique id, netns, cloud ids), v1/v2 writer",
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "HAProxy doc/proxy-protocol.txt; Go pires/go-proxyproto; nginx proxy_protocol",
    .deps = .{ "netaddr", "crc32c" },
};

// ── constants ───────────────────────────────────────────────────────────────

/// The 12-byte v2 signature.
pub const v2_signature = "\r\n\r\n\x00\r\nQUIT\n";
const v1_prefix = "PROXY ";

/// A v1 line, CRLF included, is at most 107 bytes (spec § 2.1).
pub const max_v1_len = 107;

/// Default cap on a whole v2 header (16 fixed bytes + the length field).
/// 536 is the figure the specification derives for a header that always fits
/// one minimum-size IPv4 datagram (576 − 20 IP − 20 TCP): the largest header a
/// balancer is expected to send. A unix-socket address block alone is 216.
pub const default_max_v2_len = 536;

/// A unix-socket address field is 108 bytes, NUL padded.
pub const unix_path_len = 108;

/// TLV type codes.
pub const tlv_type = struct {
    pub const alpn: u8 = 0x01;
    pub const authority: u8 = 0x02;
    pub const crc32c: u8 = 0x03;
    pub const noop: u8 = 0x04;
    pub const unique_id: u8 = 0x05;
    pub const ssl: u8 = 0x20;
    pub const ssl_version: u8 = 0x21;
    pub const ssl_cn: u8 = 0x22;
    pub const ssl_cipher: u8 = 0x23;
    pub const ssl_sig_alg: u8 = 0x24;
    pub const ssl_key_alg: u8 = 0x25;
    pub const netns: u8 = 0x30;
    pub const gcp: u8 = 0xE0;
    pub const aws: u8 = 0xEA;
    pub const azure: u8 = 0xEE;
};

// ── types ───────────────────────────────────────────────────────────────────

pub const Command = enum { local, proxy };
pub const Family = enum { unspec, tcp4, tcp6, udp4, udp6, unix_stream, unix_dgram };

/// One end of the original connection.
pub const Addr = union(enum) {
    inet: Inet,
    /// The path, NUL padding removed; borrowed from the parsed buffer.
    unix: []const u8,

    pub const Inet = struct { ip: netaddr.Ip, port: u16 };

    pub fn eql(a: Addr, b: Addr) bool {
        return switch (a) {
            .inet => |x| switch (b) {
                .inet => |y| x.port == y.port and x.ip.eql(y.ip),
                .unix => false,
            },
            .unix => |x| switch (b) {
                .inet => false,
                .unix => |y| std.mem.eql(u8, x, y),
            },
        };
    }
};

pub const Header = struct {
    /// 1 (text) or 2 (binary).
    version: u2 = 2,
    /// `.local`: the connection was made by the proxy itself (health check);
    /// use the real endpoints. Addresses are always null then.
    command: Command = .proxy,
    /// `.unspec` also means "use the real endpoints"; addresses are null.
    family: Family = .unspec,
    source: ?Addr = null,
    destination: ?Addr = null,
    /// The raw v2 TLV area (empty for v1, LOCAL and UNSPEC). Borrowed.
    tlvs: []const u8 = "",

    pub fn tlvIterator(h: Header) TlvIterator {
        return .{ .rest = h.tlvs };
    }

    /// The value of the first TLV of type `t`.
    pub fn tlv(h: Header, t: u8) error{Malformed}!?[]const u8 {
        return findTlv(h.tlvs, t);
    }
    pub fn alpn(h: Header) error{Malformed}!?[]const u8 {
        return h.tlv(tlv_type.alpn);
    }
    pub fn authority(h: Header) error{Malformed}!?[]const u8 {
        return h.tlv(tlv_type.authority);
    }
    pub fn uniqueId(h: Header) error{Malformed}!?[]const u8 {
        return h.tlv(tlv_type.unique_id);
    }
    pub fn netns(h: Header) error{Malformed}!?[]const u8 {
        return h.tlv(tlv_type.netns);
    }
    /// The checksum carried by the header (already verified by `parse`).
    pub fn crc32cValue(h: Header) error{Malformed}!?u32 {
        const v = (try h.tlv(tlv_type.crc32c)) orelse return null;
        if (v.len != 4) return error.Malformed;
        return std.mem.readInt(u32, v[0..4], .big);
    }
    pub fn ssl(h: Header) error{Malformed}!?Ssl {
        const v = (try h.tlv(tlv_type.ssl)) orelse return null;
        return try Ssl.parse(v);
    }
    /// Cloud-provider ids, raw (first byte is the provider's sub-type).
    pub fn aws(h: Header) error{Malformed}!?[]const u8 {
        return h.tlv(tlv_type.aws);
    }
    pub fn azure(h: Header) error{Malformed}!?[]const u8 {
        return h.tlv(tlv_type.azure);
    }
    pub fn gcp(h: Header) error{Malformed}!?[]const u8 {
        return h.tlv(tlv_type.gcp);
    }
};

pub const Tlv = struct { type: u8, value: []const u8 };

/// Walks a TLV area, checking every bound. A truncated TLV is
/// `error.Malformed`; iteration then stops being meaningful.
pub const TlvIterator = struct {
    rest: []const u8,

    pub fn next(it: *TlvIterator) error{Malformed}!?Tlv {
        if (it.rest.len == 0) return null;
        if (it.rest.len < 3) return error.Malformed;
        const l: usize = std.mem.readInt(u16, it.rest[1..3], .big);
        if (it.rest.len - 3 < l) return error.Malformed;
        const t: Tlv = .{ .type = it.rest[0], .value = it.rest[3..][0..l] };
        it.rest = it.rest[3 + l ..];
        return t;
    }
};

/// The value of the first TLV of type `t` in `tlvs`.
pub fn findTlv(tlvs: []const u8, t: u8) error{Malformed}!?[]const u8 {
    var it: TlvIterator = .{ .rest = tlvs };
    while (try it.next()) |x| if (x.type == t) return x.value;
    return null;
}

/// The PP2_TYPE_SSL value: a flag byte, a verify word and sub-TLVs.
pub const Ssl = struct {
    client: u8,
    /// 0 when the client certificate verified (or none was asked for).
    verify: u32,
    subtlvs: []const u8,

    pub fn parse(value: []const u8) error{Malformed}!Ssl {
        if (value.len < 5) return error.Malformed;
        return .{ .client = value[0], .verify = std.mem.readInt(u32, value[1..5], .big), .subtlvs = value[5..] };
    }
    /// The client connected over SSL/TLS.
    pub fn usesSsl(s: Ssl) bool {
        return s.client & 0x01 != 0;
    }
    /// The client presented a certificate on this connection.
    pub fn certConn(s: Ssl) bool {
        return s.client & 0x02 != 0;
    }
    /// The client presented a certificate at least once in the session.
    pub fn certSess(s: Ssl) bool {
        return s.client & 0x04 != 0;
    }
    pub fn verified(s: Ssl) bool {
        return s.verify == 0;
    }
    pub fn version(s: Ssl) error{Malformed}!?[]const u8 {
        return findTlv(s.subtlvs, tlv_type.ssl_version);
    }
    pub fn cn(s: Ssl) error{Malformed}!?[]const u8 {
        return findTlv(s.subtlvs, tlv_type.ssl_cn);
    }
    pub fn cipher(s: Ssl) error{Malformed}!?[]const u8 {
        return findTlv(s.subtlvs, tlv_type.ssl_cipher);
    }
    pub fn sigAlg(s: Ssl) error{Malformed}!?[]const u8 {
        return findTlv(s.subtlvs, tlv_type.ssl_sig_alg);
    }
    pub fn keyAlg(s: Ssl) error{Malformed}!?[]const u8 {
        return findTlv(s.subtlvs, tlv_type.ssl_key_alg);
    }
};

// ── parse ───────────────────────────────────────────────────────────────────

pub const ParseError = error{ Malformed, TooLarge, BadChecksum };

pub const Parsed = struct { h: Header, consumed: usize };

pub const ParseResult = union(enum) {
    /// At least this many more bytes are needed to decide.
    need_more: usize,
    /// The bytes are not a PROXY header; keep them for the real protocol.
    absent,
    header: Parsed,
};

pub const Options = struct {
    /// Cap on the whole v2 header (16 + payload length).
    max_v2_len: usize = default_max_v2_len,
};

/// Parse a header at the start of `buf`. Pure and allocation-free; the result
/// borrows `buf`.
pub fn parse(buf: []const u8) ParseError!ParseResult {
    return parseOpts(buf, .{});
}

pub fn parseOpts(buf: []const u8, opts: Options) ParseError!ParseResult {
    if (buf.len == 0) return .{ .need_more = 1 };
    const m1 = @min(buf.len, v1_prefix.len);
    if (std.mem.eql(u8, buf[0..m1], v1_prefix[0..m1])) {
        if (buf.len < v1_prefix.len) return .{ .need_more = v1_prefix.len - buf.len };
        return parseV1(buf);
    }
    const m2 = @min(buf.len, v2_signature.len);
    if (std.mem.eql(u8, buf[0..m2], v2_signature[0..m2])) {
        if (buf.len < v2_signature.len) return .{ .need_more = v2_signature.len - buf.len };
        return parseV2(buf, opts);
    }
    return .absent;
}

fn parsePort(s: []const u8) ?u16 {
    if (s.len == 0 or s.len > 5) return null;
    if (s.len > 1 and s[0] == '0') return null;
    var v: u32 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return null;
        v = v * 10 + (c - '0');
    }
    if (v > 65535) return null;
    return @intCast(v);
}

fn parseV1(buf: []const u8) ParseError!ParseResult {
    const scan = buf[0..@min(buf.len, max_v1_len)];
    const lf = std.mem.indexOfScalar(u8, scan, '\n') orelse {
        if (buf.len >= max_v1_len) return error.Malformed;
        return .{ .need_more = 1 };
    };
    if (lf < v1_prefix.len + 1 or scan[lf - 1] != '\r') return error.Malformed;
    const line = scan[v1_prefix.len .. lf - 1];
    const consumed = lf + 1;
    var it = std.mem.splitScalar(u8, line, ' ');
    const proto = it.next() orelse return error.Malformed;
    if (std.mem.eql(u8, proto, "UNKNOWN")) {
        // Everything up to the CRLF is ignored.
        return .{ .header = .{ .h = .{ .version = 1 }, .consumed = consumed } };
    }
    const fam: Family = if (std.mem.eql(u8, proto, "TCP4"))
        .tcp4
    else if (std.mem.eql(u8, proto, "TCP6"))
        .tcp6
    else
        return error.Malformed;
    const s_txt = it.next() orelse return error.Malformed;
    const d_txt = it.next() orelse return error.Malformed;
    const sp_txt = it.next() orelse return error.Malformed;
    const dp_txt = it.next() orelse return error.Malformed;
    if (it.next() != null) return error.Malformed;
    const sip: netaddr.Ip = switch (fam) {
        .tcp4 => .{ .v4 = netaddr.parseIp4(s_txt) orelse return error.Malformed },
        else => .{ .v6 = netaddr.parseIp6(s_txt) orelse return error.Malformed },
    };
    const dip: netaddr.Ip = switch (fam) {
        .tcp4 => .{ .v4 = netaddr.parseIp4(d_txt) orelse return error.Malformed },
        else => .{ .v6 = netaddr.parseIp6(d_txt) orelse return error.Malformed },
    };
    const sp = parsePort(sp_txt) orelse return error.Malformed;
    const dp = parsePort(dp_txt) orelse return error.Malformed;
    return .{ .header = .{ .h = .{
        .version = 1,
        .family = fam,
        .source = .{ .inet = .{ .ip = sip, .port = sp } },
        .destination = .{ .inet = .{ .ip = dip, .port = dp } },
    }, .consumed = consumed } };
}

fn trimNul(b: []const u8) []const u8 {
    const n = std.mem.indexOfScalar(u8, b, 0) orelse b.len;
    return b[0..n];
}

/// The CRC TLV's value offset inside `tlvs`, if any; checks the structure.
fn checkTlvs(tlvs: []const u8) error{Malformed}!?usize {
    var it: TlvIterator = .{ .rest = tlvs };
    var crc_off: ?usize = null;
    while (try it.next()) |t| {
        if (t.type == tlv_type.crc32c) {
            if (t.value.len != 4 or crc_off != null) return error.Malformed;
            crc_off = tlvs.len - it.rest.len - 4;
        }
    }
    return crc_off;
}

fn parseV2(buf: []const u8, opts: Options) ParseError!ParseResult {
    if (buf.len < 16) return .{ .need_more = 16 - buf.len };
    if (buf[12] >> 4 != 2) return error.Malformed;
    const cmd = buf[12] & 0x0f;
    if (cmd > 1) return error.Malformed;
    const total = 16 + @as(usize, std.mem.readInt(u16, buf[14..16], .big));
    if (total > opts.max_v2_len) return error.TooLarge;
    if (buf.len < total) return .{ .need_more = total - buf.len };
    const payload = buf[16..total];
    if (cmd == 0) {
        // LOCAL: the protocol block, family included, is discarded.
        return .{ .header = .{ .h = .{ .command = .local }, .consumed = total } };
    }
    const fam: Family, const alen: usize = switch (buf[13]) {
        0x00 => .{ .unspec, 0 },
        0x11 => .{ .tcp4, 12 },
        0x12 => .{ .udp4, 12 },
        0x21 => .{ .tcp6, 36 },
        0x22 => .{ .udp6, 36 },
        0x31 => .{ .unix_stream, 216 },
        0x32 => .{ .unix_dgram, 216 },
        else => return error.Malformed,
    };
    if (fam == .unspec) return .{ .header = .{ .h = .{}, .consumed = total } };
    if (payload.len < alen) return error.Malformed;
    const tlvs = payload[alen..];
    if (try checkTlvs(tlvs)) |off| {
        const at = 16 + alen + off;
        var c: crc32c.Crc32c = .init();
        c.update(buf[0..at]);
        c.update(&.{ 0, 0, 0, 0 });
        c.update(buf[at + 4 .. total]);
        if (c.final() != std.mem.readInt(u32, buf[at..][0..4], .big)) return error.BadChecksum;
    }
    var h: Header = .{ .family = fam, .tlvs = tlvs };
    switch (fam) {
        .tcp4, .udp4 => {
            h.source = .{ .inet = .{ .ip = .{ .v4 = payload[0..4].* }, .port = std.mem.readInt(u16, payload[8..10], .big) } };
            h.destination = .{ .inet = .{ .ip = .{ .v4 = payload[4..8].* }, .port = std.mem.readInt(u16, payload[10..12], .big) } };
        },
        .tcp6, .udp6 => {
            h.source = .{ .inet = .{ .ip = .{ .v6 = payload[0..16].* }, .port = std.mem.readInt(u16, payload[32..34], .big) } };
            h.destination = .{ .inet = .{ .ip = .{ .v6 = payload[16..32].* }, .port = std.mem.readInt(u16, payload[34..36], .big) } };
        },
        .unix_stream, .unix_dgram => {
            h.source = .{ .unix = trimNul(payload[0..unix_path_len]) };
            h.destination = .{ .unix = trimNul(payload[unix_path_len..][0..unix_path_len]) };
        },
        .unspec => {},
    }
    return .{ .header = .{ .h = h, .consumed = total } };
}

// ── reader ──────────────────────────────────────────────────────────────────

pub const ReadOptions = struct {
    /// The address of the connection's real peer (the balancer), or null when
    /// it has no IP address (a unix socket): never trusted.
    peer: ?netaddr.Ip,
    /// Peers allowed to send a header. EMPTY MEANS NO PEER: every header is
    /// refused with `error.UntrustedPeer`.
    trusted: []const netaddr.Prefix = &.{},
    /// The header is mandatory: its absence is `error.Missing`.
    required: bool = false,
    max_v2_len: usize = default_max_v2_len,
};

pub const ReadError = ParseError || error{ UntrustedPeer, Missing, Truncated, ReadFailed };

fn isTrusted(peer: ?netaddr.Ip, list: []const netaddr.Prefix) bool {
    const p = peer orelse return false;
    const u = p.unmap();
    for (list) |pre| if (pre.contains(p) or pre.contains(u)) return true;
    return false;
}

/// Read a PROXY header from the start of `r`. Returns null, consuming nothing,
/// when the stream does not start with one (and `opts.required` is false). On
/// success the header's bytes are copied into `buf` (the result borrows it)
/// and consumed from `r`. On any error nothing is consumed.
///
/// ⚠ With `required = false`, a trusted peer that sends no header makes the
/// CLIENT's first bytes the candidate header: a client that opens with a valid
/// PROXY line would then pick its own address. Set `required = true` when the
/// balancer always sends a header.
///
/// For an untrusted peer a stream that only starts like a header (a byte
/// prefix of a signature, then EOF or a buffer too small to see more) is not an
/// error: `read` returns null (`error.Missing` when `required`) and the bytes
/// stay. A complete header is `error.UntrustedPeer`.
///
/// `r.buffer` must hold the largest header expected (`opts.max_v2_len`, 536 by
/// default): a reader whose buffer is smaller than a header needs gets
/// `error.TooLarge`. `buf` likewise.
pub fn read(r: *std.Io.Reader, buf: []u8, opts: ReadOptions) ReadError!?Header {
    const popts: Options = .{ .max_v2_len = opts.max_v2_len };
    var want: usize = 1;
    while (true) {
        if (want > r.buffer.len) {
            // An untrusted peer's partial prefix is not an error: no complete
            // header was seen (SPEC.md § Trust).
            if (!isTrusted(opts.peer, opts.trusted)) return if (opts.required) error.Missing else null;
            return error.TooLarge;
        }
        var eof = false;
        r.fill(want) catch |e| switch (e) {
            error.ReadFailed => return error.ReadFailed,
            error.EndOfStream => eof = true,
        };
        const data = r.buffered();
        const res = parseOpts(data, popts) catch |e| {
            if (!isTrusted(opts.peer, opts.trusted)) return error.UntrustedPeer;
            return e;
        };
        switch (res) {
            .absent => return if (opts.required) error.Missing else null,
            .need_more => |n| {
                if (eof) {
                    if (data.len != 0 and isTrusted(opts.peer, opts.trusted)) return error.Truncated;
                    return if (opts.required) error.Missing else null;
                }
                want = data.len + n;
            },
            .header => |p| {
                if (!isTrusted(opts.peer, opts.trusted)) return error.UntrustedPeer;
                if (p.consumed > buf.len) return error.TooLarge;
                @memcpy(buf[0..p.consumed], data[0..p.consumed]);
                r.toss(p.consumed);
                const again = parseOpts(buf[0..p.consumed], popts) catch return error.Malformed;
                return switch (again) {
                    .header => |q| q.h,
                    else => error.Malformed,
                };
            },
        }
    }
}

// ── writer ──────────────────────────────────────────────────────────────────

pub const WriteError = std.Io.Writer.Error || error{ InvalidHeader, Unsupported, TooLarge };

fn inetFor(fam: Family, a: ?Addr) error{InvalidHeader}!Addr.Inet {
    const x = a orelse return error.InvalidHeader;
    switch (x) {
        .inet => |i| {
            const ok = switch (fam) {
                .tcp4, .udp4 => i.ip == .v4,
                .tcp6, .udp6 => i.ip == .v6,
                else => false,
            };
            if (!ok) return error.InvalidHeader;
            return i;
        },
        .unix => return error.InvalidHeader,
    }
}

/// Write a v1 line. TCP4/TCP6 need matching addresses; UNSPEC and LOCAL write
/// `PROXY UNKNOWN`; UDP and unix families do not exist in v1 (`Unsupported`).
pub fn writeV1(w: *std.Io.Writer, h: Header) WriteError!void {
    if (h.command == .local) return w.writeAll("PROXY UNKNOWN\r\n");
    const name: []const u8 = switch (h.family) {
        .unspec => return w.writeAll("PROXY UNKNOWN\r\n"),
        .tcp4 => "TCP4",
        .tcp6 => "TCP6",
        else => return error.Unsupported,
    };
    const s = try inetFor(h.family, h.source);
    const d = try inetFor(h.family, h.destination);
    var sb: [netaddr.max_ip_text_len]u8 = undefined;
    var db: [netaddr.max_ip_text_len]u8 = undefined;
    try w.print("PROXY {s} {s} {s} {d} {d}\r\n", .{ name, netaddr.formatIp(s.ip, &sb), netaddr.formatIp(d.ip, &db), s.port, d.port });
}

/// Write a v2 header with the raw TLV area `tlvs` (`h.tlvs` is not used).
pub fn writeV2(w: *std.Io.Writer, h: Header, tlvs: []const u8) WriteError!void {
    return writeV2Impl(w, h, tlvs, false);
}

/// As `writeV2`, and append a CRC32C TLV over the whole header.
pub fn writeV2Crc(w: *std.Io.Writer, h: Header, tlvs: []const u8) WriteError!void {
    return writeV2Impl(w, h, tlvs, true);
}

fn writeV2Impl(w: *std.Io.Writer, h: Header, tlvs: []const u8, with_crc: bool) WriteError!void {
    var head: [16 + 216]u8 = undefined;
    @memcpy(head[0..12], v2_signature);
    var alen: usize = 0;
    if (h.command == .local) {
        head[12] = 0x20;
        head[13] = 0x00;
    } else {
        head[12] = 0x21;
        switch (h.family) {
            .unspec => head[13] = 0x00,
            .tcp4, .udp4 => {
                head[13] = if (h.family == .tcp4) 0x11 else 0x12;
                const s = try inetFor(h.family, h.source);
                const d = try inetFor(h.family, h.destination);
                @memcpy(head[16..20], &s.ip.v4);
                @memcpy(head[20..24], &d.ip.v4);
                std.mem.writeInt(u16, head[24..26], s.port, .big);
                std.mem.writeInt(u16, head[26..28], d.port, .big);
                alen = 12;
            },
            .tcp6, .udp6 => {
                head[13] = if (h.family == .tcp6) 0x21 else 0x22;
                const s = try inetFor(h.family, h.source);
                const d = try inetFor(h.family, h.destination);
                @memcpy(head[16..32], &s.ip.v6);
                @memcpy(head[32..48], &d.ip.v6);
                std.mem.writeInt(u16, head[48..50], s.port, .big);
                std.mem.writeInt(u16, head[50..52], d.port, .big);
                alen = 36;
            },
            .unix_stream, .unix_dgram => {
                head[13] = if (h.family == .unix_stream) 0x31 else 0x32;
                const s = h.source orelse return error.InvalidHeader;
                const d = h.destination orelse return error.InvalidHeader;
                if (s != .unix or d != .unix) return error.InvalidHeader;
                if (s.unix.len > unix_path_len or d.unix.len > unix_path_len) return error.InvalidHeader;
                // The parser stops at the first NUL: such a path would not round-trip.
                if (std.mem.indexOfScalar(u8, s.unix, 0) != null or std.mem.indexOfScalar(u8, d.unix, 0) != null) return error.InvalidHeader;
                @memset(head[16..232], 0);
                @memcpy(head[16..][0..s.unix.len], s.unix);
                @memcpy(head[16 + unix_path_len ..][0..d.unix.len], d.unix);
                alen = 216;
            },
        }
    }
    const have_crc = (checkTlvs(tlvs) catch return error.InvalidHeader) != null;
    if (have_crc and with_crc) return error.InvalidHeader;
    const crc_len: usize = if (with_crc) 7 else 0;
    const payload = alen + tlvs.len + crc_len;
    if (payload > std.math.maxInt(u16)) return error.TooLarge;
    std.mem.writeInt(u16, head[14..16], @intCast(payload), .big);
    const hl = 16 + alen;
    if (!with_crc) {
        try w.writeAll(head[0..hl]);
        return w.writeAll(tlvs);
    }
    var tail: [7]u8 = .{ tlv_type.crc32c, 0, 4, 0, 0, 0, 0 };
    var c: crc32c.Crc32c = .init();
    c.update(head[0..hl]);
    c.update(tlvs);
    c.update(&tail);
    std.mem.writeInt(u32, tail[3..7], c.final(), .big);
    try w.writeAll(head[0..hl]);
    try w.writeAll(tlvs);
    try w.writeAll(&tail);
}

test {
    _ = @import("fuzz_test.zig");
    _ = @import("tests.zig");
}
