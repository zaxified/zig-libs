// SPDX-License-Identifier: MIT

//! Differential driver against pires/go-proxyproto v0.16.0, the module's
//! survey reference (`tools/go_oracle` is the Go side, driven through its
//! public API only). A PROGRAM, not a test: `zig build interop-proxyproto`
//! runs it, `zig build check-interop` compiles it. It needs the Go oracle
//! binary and skips cleanly (exit 0, says so) without it:
//!
//!   (cd modules/proxyproto/tools/go_oracle && \
//!    go build -o ../../../../.zig-cache/pp-oracle/gooracle .)
//!   zig build interop-proxyproto -- [--cases N] [--seed S] [--oracle PATH]
//!
//! Three kinds of case, N/3 each:
//!   parse  bytes (valid headers of every family, TLVs, CRC32C, app data after
//!          the header, then mutated: truncated, bit flips, replaced / inserted /
//!          deleted bytes, rewritten length, hand-made v2 prefixes with random
//!          family bytes, v1 lines with hostile addresses and ports) parsed by
//!          both sides and the verdicts compared;
//!   zig    a random description is written by THIS module's writer, parsed by
//!          Go, and Go's verdict must equal the description;
//!   go     the same kind of description is written by Go, the bytes are parsed
//!          here and must equal the description; they are also compared byte
//!          for byte with what our writer produces.
//! plus one `S` case per header that carries an SSL TLV (Go's `tlvparse.SSL`).
//!
//! The verdict of a parse is a canonical line, identical on both sides:
//!
//!   v<1|2> <L|P> <fam> <src> <dst> <tlvs> n=<consumed bytes>
//!
//! `L` (v2 LOCAL, v1 UNKNOWN) prints `- - - -` for the rest: addresses and TLVs
//! of a LOCAL header are informational and discarded here. `fam` is tcp4 tcp6
//! udp4 udp6 unixs unixd unspec; an address is `<hex ip bytes>:<port>` or
//! `u:<hex path>`; `tlvs` is `-` or `<type hex>:<value hex>` joined by `,` (a
//! NOOP prints `04:-`: Go drops its value).
//!
//! A description (the line Go gets after `G`) is
//!   `<ver> <L|P> <fam> <src> <dst> <tlvs> <crc 0|1>`
//! with `-` for "none"; crc=1 appends a CRC32C TLV.
//!
//! Every disagreement is sorted into a class. The documented-difference
//! classes (`x_*`, see SPEC.md § Interop oracle) are expected and counted;
//! anything else is `diff`, printed, and makes the program exit 1.

const std = @import("std");
const pp = @import("proxyproto");
const netaddr = @import("netaddr");

/// Go's `MaxV2HeaderSize` (the payload after the 16 fixed bytes); our cap is
/// set to the same figure so both refuse the same headers.
const go_max_payload = 4096;
const our_cap = 16 + go_max_payload;

const Alloc = std.mem.Allocator;

// ── small helpers ────────────────────────────────────────────────────────────

fn hexInto(gpa: Alloc, out: *std.ArrayList(u8), b: []const u8) !void {
    for (b) |x| try out.print(gpa, "{x:0>2}", .{x});
}

fn hexDecode(gpa: Alloc, s: []const u8) ![]u8 {
    if (s.len % 2 != 0) return error.BadHex;
    const out = try gpa.alloc(u8, s.len / 2);
    for (out, 0..) |*o, i| {
        o.* = (try std.fmt.charToDigit(s[2 * i], 16)) << 4 | try std.fmt.charToDigit(s[2 * i + 1], 16);
    }
    return out;
}

fn famName(f: pp.Family) []const u8 {
    return switch (f) {
        .unspec => "unspec",
        .tcp4 => "tcp4",
        .tcp6 => "tcp6",
        .udp4 => "udp4",
        .udp6 => "udp6",
        .unix_stream => "unixs",
        .unix_dgram => "unixd",
    };
}

fn addrInto(gpa: Alloc, out: *std.ArrayList(u8), a: ?pp.Addr) !void {
    const x = a orelse return out.append(gpa, '-');
    switch (x) {
        .inet => |i| {
            switch (i.ip) {
                .v4 => |b| try hexInto(gpa, out, &b),
                .v6 => |b| try hexInto(gpa, out, &b),
            }
            try out.print(gpa, ":{d}", .{i.port});
        },
        .unix => |p| {
            try out.appendSlice(gpa, "u:");
            try hexInto(gpa, out, p);
        },
    }
}

fn tlvsInto(gpa: Alloc, out: *std.ArrayList(u8), tlvs: []const u8) !void {
    if (tlvs.len == 0) return out.append(gpa, '-');
    var it: pp.TlvIterator = .{ .rest = tlvs };
    var first = true;
    while (it.next() catch return out.appendSlice(gpa, "ERR")) |t| {
        if (!first) try out.append(gpa, ',');
        first = false;
        try out.print(gpa, "{x:0>2}:", .{t.type});
        if (t.type == pp.tlv_type.noop) try out.append(gpa, '-') else try hexInto(gpa, out, t.value);
    }
}

fn canonOf(gpa: Alloc, p: pp.Parsed) ![]const u8 {
    var o: std.ArrayList(u8) = .empty;
    const h = p.h;
    const local = h.command == .local or (h.version == 1 and h.family == .unspec);
    if (local) {
        try o.print(gpa, "v{d} L - - - - n={d}", .{ h.version, p.consumed });
    } else {
        try o.print(gpa, "v{d} P {s} ", .{ h.version, famName(h.family) });
        try addrInto(gpa, &o, h.source);
        try o.append(gpa, ' ');
        try addrInto(gpa, &o, h.destination);
        try o.append(gpa, ' ');
        try tlvsInto(gpa, &o, h.tlvs);
        try o.print(gpa, " n={d}", .{p.consumed});
    }
    return o.items;
}

// ── our verdict ──────────────────────────────────────────────────────────────

const Ours = union(enum) {
    header: []const u8, // canonical
    absent,
    incomplete,
    malformed,
    too_large,
    bad_crc,

    fn isErr(o: Ours) bool {
        return o != .header;
    }
};

fn oursParse(gpa: Alloc, bytes: []const u8) !Ours {
    const res = pp.parseOpts(bytes, .{ .max_v2_len = our_cap }) catch |e| return switch (e) {
        error.Malformed => .malformed,
        error.TooLarge => .too_large,
        error.BadChecksum => .bad_crc,
    };
    return switch (res) {
        .absent => .absent,
        .need_more => .incomplete,
        .header => |p| .{ .header = try canonOf(gpa, p) },
    };
}

// ── descriptions ─────────────────────────────────────────────────────────────

const Desc = struct {
    ver: u2,
    local: bool,
    fam: pp.Family,
    src: ?pp.Addr,
    dst: ?pp.Addr,
    tlvs: []const pp.Tlv,
    crc: bool,

    fn text(d: Desc, gpa: Alloc) ![]const u8 {
        var o: std.ArrayList(u8) = .empty;
        try o.print(gpa, "{d} {s} {s} ", .{ d.ver, if (d.local) "L" else "P", famName(d.fam) });
        try addrInto(gpa, &o, d.src);
        try o.append(gpa, ' ');
        try addrInto(gpa, &o, d.dst);
        try o.append(gpa, ' ');
        if (d.tlvs.len == 0) try o.append(gpa, '-') else for (d.tlvs, 0..) |t, i| {
            if (i != 0) try o.append(gpa, ',');
            try o.print(gpa, "{x:0>2}:", .{t.type});
            try hexInto(gpa, &o, t.value);
        }
        try o.print(gpa, " {d}", .{@intFromBool(d.crc)});
        return o.items;
    }

    fn rawTlvs(d: Desc, gpa: Alloc) ![]u8 {
        var o: std.ArrayList(u8) = .empty;
        for (d.tlvs) |t| {
            try o.append(gpa, t.type);
            var l: [2]u8 = undefined;
            std.mem.writeInt(u16, &l, @intCast(t.value.len), .big);
            try o.appendSlice(gpa, &l);
            try o.appendSlice(gpa, t.value);
        }
        return o.items;
    }

    /// The canonical verdict a parser must give for the `bytes` written from
    /// this description (n and the CRC value come from the bytes).
    fn expect(d: Desc, gpa: Alloc, bytes: []const u8) ![]const u8 {
        var o: std.ArrayList(u8) = .empty;
        if (d.local or (d.ver == 1 and d.fam == .unspec)) {
            try o.print(gpa, "v{d} L - - - - n={d}", .{ d.ver, bytes.len });
            return o.items;
        }
        try o.print(gpa, "v{d} P {s} ", .{ d.ver, famName(d.fam) });
        try addrInto(gpa, &o, d.src);
        try o.append(gpa, ' ');
        try addrInto(gpa, &o, d.dst);
        try o.append(gpa, ' ');
        if (d.ver == 1 or (d.tlvs.len == 0 and !d.crc)) {
            try o.append(gpa, '-');
        } else {
            for (d.tlvs, 0..) |t, i| {
                if (i != 0) try o.append(gpa, ',');
                try o.print(gpa, "{x:0>2}:", .{t.type});
                if (t.type == pp.tlv_type.noop) try o.append(gpa, '-') else try hexInto(gpa, &o, t.value);
            }
            if (d.crc) {
                if (d.tlvs.len != 0) try o.append(gpa, ',');
                try o.appendSlice(gpa, "03:");
                try hexInto(gpa, &o, bytes[bytes.len - 4 ..]);
            }
        }
        try o.print(gpa, " n={d}", .{bytes.len});
        return o.items;
    }

    /// Our writer's bytes, or null when it refuses the description.
    fn oursWrite(d: Desc, gpa: Alloc) !?[]u8 {
        var w: std.Io.Writer.Allocating = .init(gpa);
        defer w.deinit();
        const h: pp.Header = .{
            .version = d.ver,
            .command = if (d.local) .local else .proxy,
            .family = d.fam,
            .source = d.src,
            .destination = d.dst,
        };
        const res = if (d.ver == 1)
            pp.writeV1(&w.writer, h)
        else blk: {
            const raw = try d.rawTlvs(gpa);
            break :blk if (d.crc) pp.writeV2Crc(&w.writer, h, raw) else pp.writeV2(&w.writer, h, raw);
        };
        res catch return null;
        return try gpa.dupe(u8, w.written());
    }

    /// The description names something our writer is documented to refuse and
    /// Go silently accepts: a unix path over 108 bytes (Go truncates) or with
    /// a NUL (Go writes it; no parser can read it back).
    fn badUnixPath(d: Desc) bool {
        for ([_]?pp.Addr{ d.src, d.dst }) |a| if (a) |x| switch (x) {
            .unix => |p| if (p.len > pp.unix_path_len or std.mem.indexOfScalar(u8, p, 0) != null) return true,
            else => {},
        };
        return false;
    }
};

// ── generators ───────────────────────────────────────────────────────────────

fn randIp4(r: std.Random) netaddr.Ip {
    return switch (r.uintLessThan(u8, 8)) {
        0 => .{ .v4 = .{ 0, 0, 0, 0 } },
        1 => .{ .v4 = .{ 127, 0, 0, 1 } },
        2 => .{ .v4 = .{ 255, 255, 255, 255 } },
        else => blk: {
            var b: [4]u8 = undefined;
            r.bytes(&b);
            break :blk .{ .v4 = b };
        },
    };
}

fn randIp6(r: std.Random) netaddr.Ip {
    var b: [16]u8 = undefined;
    switch (r.uintLessThan(u8, 10)) {
        0 => @memset(&b, 0),
        1 => {
            @memset(&b, 0);
            b[15] = 1;
        },
        2, 3 => { // v4-mapped
            @memset(&b, 0);
            b[10] = 0xff;
            b[11] = 0xff;
            r.bytes(b[12..]);
        },
        4 => { // link-local
            r.bytes(&b);
            b[0] = 0xfe;
            b[1] = 0x80;
        },
        5 => { // sparse: many zero words
            @memset(&b, 0);
            for (0..r.uintLessThan(u8, 4)) |_| {
                const i = r.uintLessThan(usize, 8);
                r.bytes(b[2 * i ..][0..2]);
            }
        },
        else => r.bytes(&b),
    }
    return .{ .v6 = b };
}

fn randPort(r: std.Random) u16 {
    return switch (r.uintLessThan(u8, 8)) {
        0 => 0,
        1 => 65535,
        2 => 80,
        else => r.int(u16),
    };
}

fn randInet(r: std.Random, v6: bool) pp.Addr {
    return .{ .inet = .{ .ip = if (v6) randIp6(r) else randIp4(r), .port = randPort(r) } };
}

fn randPath(gpa: Alloc, r: std.Random, bad: bool) ![]const u8 {
    var len: usize = switch (r.uintLessThan(u8, 4)) {
        0 => 0,
        1 => r.uintAtMost(usize, 12),
        2 => pp.unix_path_len - r.uintAtMost(usize, 2),
        else => r.uintAtMost(usize, pp.unix_path_len),
    };
    if (bad and r.boolean()) len = pp.unix_path_len + 1 + r.uintAtMost(usize, 20);
    const p = try gpa.alloc(u8, len);
    for (p) |*c| c.* = if (r.uintLessThan(u8, 8) == 0) r.int(u8) | 1 else r.intRangeAtMost(u8, 0x20, 0x7e);
    if (bad and len != 0 and r.uintLessThan(u8, 6) == 0) p[r.uintLessThan(usize, len)] = 0;
    return p;
}

fn randValue(gpa: Alloc, r: std.Random) ![]u8 {
    const len: usize = switch (r.uintLessThan(u8, 10)) {
        0 => 0,
        1 => r.uintAtMost(usize, 300),
        else => r.uintAtMost(usize, 40),
    };
    const v = try gpa.alloc(u8, len);
    r.bytes(v);
    return v;
}

fn subTlv(gpa: Alloc, out: *std.ArrayList(u8), t: u8, v: []const u8) !void {
    try out.append(gpa, t);
    var l: [2]u8 = undefined;
    std.mem.writeInt(u16, &l, @intCast(v.len), .big);
    try out.appendSlice(gpa, &l);
    try out.appendSlice(gpa, v);
}

fn randSsl(gpa: Alloc, r: std.Random) ![]u8 {
    var o: std.ArrayList(u8) = .empty;
    try o.append(gpa, r.uintLessThan(u8, 8));
    var v: [4]u8 = undefined;
    r.bytes(&v);
    if (r.boolean()) @memset(&v, 0);
    try o.appendSlice(gpa, &v);
    const words = [_][]const u8{ "TLSv1.3", "TLSv1.2", "ECDHE-RSA-AES128-GCM-SHA256", "example.com", "RSA-SHA256", "RSA2048", "", "caf\xc3\xa9", "\xff\xfe" };
    if (r.uintLessThan(u8, 5) != 0) try subTlv(gpa, &o, pp.tlv_type.ssl_version, words[r.uintLessThan(usize, 2)]);
    if (r.boolean()) try subTlv(gpa, &o, pp.tlv_type.ssl_cn, words[3 + r.uintLessThan(usize, 6)]);
    if (r.boolean()) try subTlv(gpa, &o, pp.tlv_type.ssl_cipher, words[2 + r.uintLessThan(usize, 7)]);
    if (r.boolean()) try subTlv(gpa, &o, pp.tlv_type.ssl_sig_alg, words[4]);
    if (r.boolean()) try subTlv(gpa, &o, pp.tlv_type.ssl_key_alg, words[5]);
    if (r.uintLessThan(u8, 10) == 0) try subTlv(gpa, &o, 0x28, try randValue(gpa, r));
    return o.items;
}

fn randTlvs(gpa: Alloc, r: std.Random) ![]const pp.Tlv {
    const n = switch (r.uintLessThan(u8, 6)) {
        0, 1 => 0,
        else => r.intRangeAtMost(usize, 1, 4),
    };
    const out = try gpa.alloc(pp.Tlv, n);
    for (out) |*t| {
        const ty: u8 = switch (r.uintLessThan(u8, 12)) {
            0 => 1,
            1 => 2,
            2 => 4,
            3 => 5,
            4, 5 => 0x20,
            6 => 0x30,
            7 => r.intRangeAtMost(u8, 0xe0, 0xef),
            8 => r.intRangeAtMost(u8, 0xf0, 0xff),
            else => blk: {
                const x = r.int(u8);
                break :blk if (x == 3) 6 else x;
            },
        };
        t.* = .{ .type = ty, .value = if (ty == 0x20) try randSsl(gpa, r) else try randValue(gpa, r) };
    }
    return out;
}

/// `bad` also produces descriptions our writer refuses (long unix path).
fn randDesc(gpa: Alloc, r: std.Random, bad: bool) !Desc {
    const ver: u2 = if (r.uintLessThan(u8, 10) < 3) 1 else 2;
    if (r.uintLessThan(u8, 10) == 0) {
        return .{ .ver = ver, .local = true, .fam = .unspec, .src = null, .dst = null, .tlvs = if (ver == 2) try randTlvs(gpa, r) else &.{}, .crc = false };
    }
    const fam: pp.Family = if (ver == 1)
        (if (r.boolean()) .tcp4 else .tcp6)
    else switch (r.uintLessThan(u8, 6)) {
        0 => .tcp4,
        1 => .tcp6,
        2 => .udp4,
        3 => .udp6,
        4 => .unix_stream,
        else => .unix_dgram,
    };
    var d: Desc = .{ .ver = ver, .local = false, .fam = fam, .src = null, .dst = null, .tlvs = &.{}, .crc = false };
    switch (fam) {
        .tcp4, .udp4 => {
            d.src = randInet(r, false);
            d.dst = randInet(r, false);
        },
        .tcp6, .udp6 => {
            d.src = randInet(r, true);
            d.dst = randInet(r, true);
        },
        else => {
            d.src = .{ .unix = try randPath(gpa, r, bad) };
            d.dst = .{ .unix = try randPath(gpa, r, bad) };
        },
    }
    if (ver == 2) {
        d.tlvs = try randTlvs(gpa, r);
        d.crc = r.uintLessThan(u8, 4) == 0;
    }
    return d;
}

// ── byte-level generators and mutations ──────────────────────────────────────

const sig = pp.v2_signature;

fn v1Token(gpa: Alloc, r: std.Random, kind: enum { v4, v6, port }) ![]const u8 {
    const v4s = [_][]const u8{ "1.2.3", "1.2.3.4.5", "01.2.3.4", "256.1.1.1", "1.2.3.-4", "", "0.0.0.0", "255.255.255.255", "1.2.3.4%x", "+1.2.3.4", "::ffff:1.2.3.4", "1.2.3.04", "1.2.3.4.", ".1.2.3", "0x1.2.3.4", "1.2.3.4 " };
    const v6s = [_][]const u8{ "::", "::1", "1::", "fe80::1%eth0", "1:2:3:4:5:6:7:8:9", "12345::1", "::ffff:1.2.3.4", "1.2.3.4", "1::2::3", ":1:2:3:4:5:6:7", "0:0:0:0:0:0:0:0", "::0.0.0.0", "1:2:3:4:5:6:1.2.3.4", "2001:DB8::A", "2001:db8:0:0:0:0:0:1", "::ffff:01.2.3.4", "1:2:3:4:5:6:7::", "::1:2:3:4:5:6:7", "g::1", "1:2:3:4:5:6:7", "::ffff:1.2.3.256", "[::1]" };
    const ports = [_][]const u8{ "0", "00", "01", "65535", "65536", "-1", "+80", "80a", "", "1e3", "0x50", "99999", "100000", "007", "000000", " 1" };
    const hostile = r.uintLessThan(u8, 3) == 0;
    var o: std.ArrayList(u8) = .empty;
    switch (kind) {
        .v4 => if (hostile) try o.appendSlice(gpa, v4s[r.uintLessThan(usize, v4s.len)]) else {
            var b: [netaddr.max_ip_text_len]u8 = undefined;
            try o.appendSlice(gpa, netaddr.formatIp(randIp4(r), &b));
        },
        .v6 => if (hostile) try o.appendSlice(gpa, v6s[r.uintLessThan(usize, v6s.len)]) else {
            var b: [netaddr.max_ip_text_len]u8 = undefined;
            const ip = randIp6(r);
            switch (r.uintLessThan(u8, 3)) {
                0 => {
                    var eb: [netaddr.max_ip_expanded_text_len]u8 = undefined;
                    try o.appendSlice(gpa, netaddr.formatIpExpanded(ip, &eb));
                },
                else => try o.appendSlice(gpa, netaddr.formatIp(ip, &b)),
            }
        },
        .port => if (hostile) try o.appendSlice(gpa, ports[r.uintLessThan(usize, ports.len)]) else try o.print(gpa, "{d}", .{randPort(r)}),
    }
    return o.items;
}

fn v1Line(gpa: Alloc, r: std.Random) ![]const u8 {
    const protos = [_][]const u8{ "TCP4", "TCP4", "TCP4", "TCP6", "TCP6", "TCP6", "UNKNOWN", "UDP4", "tcp4", "TCP", "", "TCP5", "UNKNOWN extra 1 2 3" };
    const proto = protos[r.uintLessThan(usize, protos.len)];
    const six = std.mem.eql(u8, proto, "TCP6") or r.uintLessThan(u8, 12) == 0;
    var o: std.ArrayList(u8) = .empty;
    try o.appendSlice(gpa, if (r.uintLessThan(u8, 40) == 0) "PROXYX " else "PROXY ");
    try o.appendSlice(gpa, proto);
    if (std.mem.startsWith(u8, proto, "UNKNOWN") and r.boolean()) {
        // UNKNOWN: anything up to the CRLF is ignored.
        try o.print(gpa, " {s}", .{try v1Token(gpa, r, .v6)});
    } else if (!std.mem.startsWith(u8, proto, "UNKNOWN")) {
        const sep: []const u8 = if (r.uintLessThan(u8, 30) == 0) "  " else " ";
        try o.print(gpa, "{s}{s}{s}{s}{s}{s}{s}{s}", .{
            sep, try v1Token(gpa, r, if (six) .v6 else .v4),
            sep, try v1Token(gpa, r, if (six) .v6 else .v4),
            sep, try v1Token(gpa, r, .port),
            sep, try v1Token(gpa, r, .port),
        });
        if (r.uintLessThan(u8, 25) == 0) try o.appendSlice(gpa, " extra");
    }
    const ends = [_][]const u8{ "\r\n", "\r\n", "\r\n", "\r\n", "\r\n", "\r\n", "\n", "\r\r\n", "\r\n\r\n", "", "\n\r", "\r" };
    try o.appendSlice(gpa, ends[r.uintLessThan(usize, ends.len)]);
    return o.items;
}

fn rawV2(gpa: Alloc, r: std.Random) ![]const u8 {
    var o: std.ArrayList(u8) = .empty;
    try o.appendSlice(gpa, sig);
    try o.append(gpa, switch (r.uintLessThan(u8, 8)) {
        0, 1, 2 => 0x21,
        3, 4 => 0x20,
        5 => r.int(u8),
        6 => 0x22,
        else => 0x30 | r.uintLessThan(u8, 4),
    });
    const fams = [_]u8{ 0x00, 0x11, 0x12, 0x21, 0x22, 0x31, 0x32, 0x13, 0x10, 0x23, 0x01, 0x30, 0x41, 0xff };
    const fam: u8 = if (r.uintLessThan(u8, 6) == 0) r.int(u8) else fams[r.uintLessThan(usize, fams.len)];
    try o.append(gpa, fam);
    const want: usize = switch (fam >> 4) {
        1 => 12,
        2 => 36,
        3 => 216,
        else => 0,
    };
    var plen: usize = switch (r.uintLessThan(u8, 8)) {
        0 => want -| r.uintAtMost(usize, 3),
        1 => want + r.uintAtMost(usize, 20),
        2 => r.uintAtMost(usize, 60),
        3 => go_max_payload - 2 + r.uintAtMost(usize, 5),
        else => want + 3 * r.uintAtMost(usize, 10),
    };
    if (plen > 5000) plen = 5000;
    var l: [2]u8 = undefined;
    std.mem.writeInt(u16, &l, @intCast(plen), .big);
    try o.appendSlice(gpa, &l);
    const have = if (r.uintLessThan(u8, 8) == 0) plen -| r.uintAtMost(usize, 4) else plen;
    const start = o.items.len;
    try o.resize(gpa, start + have);
    r.bytes(o.items[start..]);
    // Make some of the payload TLV-shaped so the structure check is reached.
    if (have > want + 3 and r.boolean()) {
        o.items[start + want] = r.intRangeAtMost(u8, 1, 5);
        std.mem.writeInt(u16, o.items[start + want + 1 ..][0..2], @intCast(have - want - 3), .big);
    }
    return o.items;
}

const payloads = [_][]const u8{ "GET / HTTP/1.1\r\n", "\x16\x03\x01", "SSH-2.0-x\r\n", "PROXY", "x" };

fn mutate(gpa: Alloc, r: std.Random, in: []const u8) ![]const u8 {
    var b: std.ArrayList(u8) = .empty;
    try b.appendSlice(gpa, in);
    switch (r.uintLessThan(u8, 14)) {
        0, 1, 2, 3, 4 => {}, // untouched
        5 => if (b.items.len > 0) {
            b.shrinkRetainingCapacity(r.uintAtMost(usize, b.items.len));
        },
        6 => if (b.items.len > 0) {
            const n = r.intRangeAtMost(usize, 1, 3);
            for (0..n) |_| b.items[r.uintLessThan(usize, b.items.len)] ^= @as(u8, 1) << r.int(u3);
        },
        7 => if (b.items.len > 0) {
            b.items[r.uintLessThan(usize, b.items.len)] = r.int(u8);
        },
        8 => try b.insert(gpa, r.uintAtMost(usize, b.items.len), r.int(u8)),
        9 => if (b.items.len > 0) {
            _ = b.orderedRemove(r.uintLessThan(usize, b.items.len));
        },
        10 => if (b.items.len >= 16 and std.mem.startsWith(u8, b.items, sig)) {
            std.mem.writeInt(u16, b.items[14..16], r.int(u16) >> @intCast(r.uintLessThan(u8, 8)), .big);
        },
        11 => try b.appendSlice(gpa, payloads[r.uintLessThan(usize, payloads.len)]),
        12 => if (b.items.len > 13 and std.mem.startsWith(u8, b.items, sig)) {
            b.items[13] = r.int(u8);
        },
        else => if (b.items.len > 12 and std.mem.startsWith(u8, b.items, sig)) {
            b.items[12] = r.int(u8);
        },
    }
    if (r.uintLessThan(u8, 4) == 0) try b.appendSlice(gpa, payloads[r.uintLessThan(usize, payloads.len)]);
    return b.items;
}

// ── cases ────────────────────────────────────────────────────────────────────

const Kind = enum { parse, zig, go, ssl };

const Case = struct {
    kind: Kind,
    /// parse, zig, ssl: the bytes Go parses.
    bytes: []const u8 = "",
    /// zig and go: the description.
    desc: ?Desc = null,
    /// zig: the bytes our writer made are `bytes`; go: our writer's bytes (null if it refused).
    ours_bytes: ?[]const u8 = null,
    ours: Ours = .absent,
    /// ssl: index of the case whose bytes these are.
    parent: usize = 0,
};

fn sslSummary(h: pp.Header) ?bool {
    // true: our structural decode of the SSL TLV succeeds.
    const v = (h.tlv(pp.tlv_type.ssl) catch return false) orelse return null;
    const s = pp.Ssl.parse(v) catch return false;
    var it: pp.TlvIterator = .{ .rest = s.subtlvs };
    while (it.next() catch return false) |_| {}
    return true;
}

// ── classification ───────────────────────────────────────────────────────────

const Class = enum {
    // agreement
    same_header,
    same_absent,
    same_reject,
    same_incomplete,
    write_same_bytes,
    write_roundtrip_ok,
    // documented differences (SPEC.md § Interop oracle)
    x_proxy_unspec,
    x_local_family_byte,
    x_tlv_structure,
    x_crc_mismatch,
    x_crc_structure,
    x_unix_path_writer,
    x_v1_prefix,
    x_hp_override,
    x_ssl_content,
    x_write_bytes_differ,
    // everything else
    diff,
};

const GoParse = struct {
    ok: bool,
    canon: []const u8 = "",
    crc: []const u8 = "none",
    err: []const u8 = "",

    fn of(line: []const u8) GoParse {
        if (std.mem.startsWith(u8, line, "OK ")) {
            const rest = line[3..];
            const i = std.mem.lastIndexOf(u8, rest, " crc=") orelse return .{ .ok = false, .err = "BadAnswer" };
            return .{ .ok = true, .canon = rest[0..i], .crc = rest[i + 5 ..] };
        }
        if (std.mem.startsWith(u8, line, "ERR ")) return .{ .ok = false, .err = line[4..] };
        return .{ .ok = false, .err = "BadAnswer" };
    }
};

fn isSupportedFamByte(b: u8) bool {
    return switch (b) {
        0x00, 0x11, 0x12, 0x21, 0x22, 0x31, 0x32 => true,
        else => false,
    };
}

fn classifyParse(ours: Ours, g: GoParse, bytes: []const u8) Class {
    if (ours == .header and g.ok) {
        if (!std.mem.eql(u8, ours.header, g.canon)) return .diff;
        // Go does not verify the CRC32C itself; the oracle does, with the standard library.
        if (std.mem.eql(u8, g.crc, "bad") or std.mem.eql(u8, g.crc, "malformed")) return .diff;
        return .same_header;
    }
    if (ours == .header and !g.ok) {
        const v2 = bytes.len >= 16 and std.mem.startsWith(u8, bytes, sig);
        if (v2 and std.mem.eql(u8, g.err, "UnsupportedAddressFamilyAndProtocol")) {
            if (bytes[13] == 0x00 and bytes[12] & 0x0f == 1) return .x_proxy_unspec;
            if (bytes[12] & 0x0f == 0 and !isSupportedFamByte(bytes[13])) return .x_local_family_byte;
        }
        return .diff;
    }
    if (ours != .header and g.ok) {
        if (std.mem.indexOf(u8, g.canon, " ERR n=") != null) return .x_tlv_structure;
        if (ours == .bad_crc and std.mem.eql(u8, g.crc, "bad")) return .x_crc_mismatch;
        if (ours == .malformed and std.mem.eql(u8, g.crc, "malformed")) return .x_crc_structure;
        return .diff;
    }
    // both refuse
    const go_absent = std.mem.eql(u8, g.err, "NoProxyProtocol");
    return switch (ours) {
        .header => unreachable,
        .absent => if (go_absent)
            .same_absent
        else if (bytes.len > 5 and std.mem.startsWith(u8, bytes, "PROXY") and bytes[5] != ' ')
            .x_v1_prefix
        else
            .diff,
        .incomplete => .same_incomplete,
        .malformed, .too_large, .bad_crc => if (go_absent) .diff else .same_reject,
    };
}

// ── main ─────────────────────────────────────────────────────────────────────

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const gpa = init.gpa;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    var n_cases: usize = 150_000;
    var seed: u64 = 1;
    var oracle: []const u8 = ".zig-cache/pp-oracle/gooracle";
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--cases") and i + 1 < args.len) {
            i += 1;
            n_cases = try std.fmt.parseInt(usize, args[i], 10);
        } else if (std.mem.eql(u8, a, "--seed") and i + 1 < args.len) {
            i += 1;
            seed = try std.fmt.parseInt(u64, args[i], 0);
        } else if (std.mem.eql(u8, a, "--oracle") and i + 1 < args.len) {
            i += 1;
            oracle = args[i];
        } else {
            std.debug.print("usage: interop-proxyproto [--cases N] [--seed S] [--oracle PATH]\n", .{});
            return 2;
        }
    }

    const cwd = std.Io.Dir.cwd();
    cwd.access(io, oracle, .{}) catch {
        std.debug.print("interop-proxyproto: SKIPPED -- no Go oracle at {s} (build it: see tools/interop.zig header)\n", .{oracle});
        return 0;
    };

    var prng = std.Random.DefaultPrng.init(seed);
    const r = prng.random();

    // ── generate ────────────────────────────────────────────────────────────
    var cases: std.ArrayList(Case) = .empty;
    const per = n_cases / 3;
    for (0..per) |_| {
        const base: []const u8 = switch (r.uintLessThan(u8, 10)) {
            0, 1, 2, 3 => blk: {
                const d = try randDesc(arena, r, false);
                break :blk (try d.oursWrite(arena)) orelse "";
            },
            4, 5 => try v1Line(arena, r),
            6 => try rawV2(arena, r),
            else => blk: {
                // written by us, with a mutation target that keeps it header-shaped
                const d = try randDesc(arena, r, false);
                break :blk (try d.oursWrite(arena)) orelse "";
            },
        };
        const bytes = try mutate(arena, r, base);
        try cases.append(arena, .{ .kind = .parse, .bytes = bytes, .ours = try oursParse(arena, bytes) });
    }
    for (0..per) |_| {
        const d = try randDesc(arena, r, false);
        const b = (try d.oursWrite(arena)) orelse {
            std.debug.print("interop-proxyproto: our writer refused a valid description: {s}\n", .{try d.text(arena)});
            return 1;
        };
        try cases.append(arena, .{ .kind = .zig, .bytes = b, .desc = d, .ours_bytes = b, .ours = try oursParse(arena, b) });
    }
    for (0..n_cases - 2 * per) |_| {
        const d = try randDesc(arena, r, true);
        try cases.append(arena, .{ .kind = .go, .desc = d, .ours_bytes = try d.oursWrite(arena) });
    }
    // One SSL case per header with an SSL TLV (decided from our parse).
    const base_n = cases.items.len;
    for (0..base_n) |ci| {
        const c = cases.items[ci];
        if (c.kind == .go or c.ours != .header) continue;
        const p = (pp.parseOpts(c.bytes, .{ .max_v2_len = our_cap }) catch continue).header;
        if (sslSummary(p.h) != null) try cases.append(arena, .{ .kind = .ssl, .bytes = c.bytes, .ours = c.ours, .parent = ci });
    }

    // ── write the requests, run Go ──────────────────────────────────────────
    var req: std.ArrayList(u8) = .empty;
    for (cases.items) |c| switch (c.kind) {
        .parse, .zig => {
            try req.appendSlice(arena, "P ");
            if (c.bytes.len == 0) try req.append(arena, '-') else try hexInto(arena, &req, c.bytes);
            try req.append(arena, '\n');
        },
        .ssl => {
            try req.appendSlice(arena, "S ");
            try hexInto(arena, &req, c.bytes);
            try req.append(arena, '\n');
        },
        .go => try req.print(arena, "G {s}\n", .{try c.desc.?.text(arena)}),
    };
    const dir = ".zig-cache/pp-oracle";
    try cwd.createDirPath(io, dir);
    try cwd.writeFile(io, .{ .sub_path = dir ++ "/requests.txt", .data = req.items });
    {
        const fin = try cwd.openFile(io, dir ++ "/requests.txt", .{});
        defer fin.close(io);
        const fout = try cwd.createFile(io, dir ++ "/answers.txt", .{});
        defer fout.close(io);
        var child = std.process.spawn(io, .{
            .argv = &.{oracle},
            .stdin = .{ .file = fin },
            .stdout = .{ .file = fout },
            .stderr = .inherit,
        }) catch |e| {
            std.debug.print("interop-proxyproto: could not spawn {s} ({t})\n", .{ oracle, e });
            return 1;
        };
        switch (try child.wait(io)) {
            .exited => |code| if (code != 0) {
                std.debug.print("interop-proxyproto: the Go oracle exited with {d}\n", .{code});
                return 1;
            },
            else => {
                std.debug.print("interop-proxyproto: the Go oracle crashed\n", .{});
                return 1;
            },
        }
    }
    const answers = try cwd.readFileAlloc(io, dir ++ "/answers.txt", arena, .limited(1 << 30));

    // ── compare ─────────────────────────────────────────────────────────────
    const classes = try arena.alloc(Class, cases.items.len);
    var counts = std.EnumArray(Class, usize).initFill(0);
    var kind_counts = std.EnumArray(Kind, usize).initFill(0);
    var shown: usize = 0;
    var shown_w: usize = 0;
    var lines = std.mem.splitScalar(u8, answers, '\n');
    for (cases.items, 0..) |c, idx| {
        const line = lines.next() orelse {
            std.debug.print("interop-proxyproto: the oracle answered {d} lines for {d} cases\n", .{ idx, cases.items.len });
            return 1;
        };
        kind_counts.getPtr(c.kind).* += 1;
        const cls: Class = switch (c.kind) {
            .parse => classifyParse(c.ours, GoParse.of(line), c.bytes),
            .zig => blk: {
                const exp = try c.desc.?.expect(arena, c.bytes);
                const g = GoParse.of(line);
                const ours_ok = c.ours == .header and std.mem.eql(u8, c.ours.header, exp);
                const go_ok = g.ok and std.mem.eql(u8, g.canon, exp) and (std.mem.eql(u8, g.crc, "none") or std.mem.eql(u8, g.crc, "ok"));
                break :blk if (ours_ok and go_ok) .write_roundtrip_ok else .diff;
            },
            .go => blk: {
                var tok = std.mem.tokenizeScalar(u8, line, ' ');
                const tag = tok.next() orelse "";
                if (!std.mem.eql(u8, tag, "H")) {
                    // Go refused. Our writer must refuse too.
                    break :blk if (c.ours_bytes == null) .same_reject else .diff;
                }
                const hexs = tok.next() orelse "";
                const overridden = tok.next() != null;
                const gb = try hexDecode(arena, hexs);
                if (c.ours_bytes == null) break :blk if (c.desc.?.badUnixPath()) .x_unix_path_writer else .diff;
                const exp = try c.desc.?.expect(arena, gb);
                const back = try oursParse(arena, gb);
                const back_ok = back == .header and std.mem.eql(u8, back.header, exp);
                if (!back_ok) break :blk .diff;
                if (std.mem.eql(u8, gb, c.ours_bytes.?)) break :blk if (overridden) .x_hp_override else .write_same_bytes;
                break :blk .x_write_bytes_differ;
            },
            .ssl => blk: {
                // Only where both sides accepted the header itself.
                if (classes[c.parent] != .same_header and classes[c.parent] != .write_roundtrip_ok) continue;
                const p = (try pp.parseOpts(c.bytes, .{ .max_v2_len = our_cap })).header;
                const ours_ok = sslSummary(p.h).?;
                if (std.mem.eql(u8, line, "SSLOK")) break :blk if (ours_ok) .same_header else .diff;
                // Go's tlvparse checks string content (ASCII version/cipher, UTF-8 CN,
                // version present when the client flag says SSL); we decode the structure.
                if (std.mem.eql(u8, line, "SSLBAD")) break :blk if (ours_ok) .x_ssl_content else .same_reject;
                break :blk .diff;
            },
        };
        classes[idx] = cls;
        counts.getPtr(cls).* += 1;
        if ((cls == .diff and shown < 25) or (cls == .x_write_bytes_differ and shown_w < 6)) {
            if (cls != .diff) shown_w += 1 else shown += 1;
            std.debug.print("{s} case {d} ({t})\n", .{ if (cls == .diff) "DIFF" else "NOTE", idx, c.kind });
            if (c.ours_bytes) |ob| {
                var h: std.ArrayList(u8) = .empty;
                try hexInto(arena, &h, ob);
                std.debug.print("  ours bytes: {s}\n", .{h.items});
            }
            if (c.bytes.len != 0) {
                var h: std.ArrayList(u8) = .empty;
                try hexInto(arena, &h, c.bytes);
                std.debug.print("  bytes: {s}\n", .{h.items});
            }
            if (c.desc) |d| std.debug.print("  desc:  {s}\n", .{try d.text(arena)});
            switch (c.ours) {
                .header => |s| std.debug.print("  ours:  {s}\n", .{s}),
                else => std.debug.print("  ours:  {s}\n", .{@tagName(c.ours)}),
            }
            std.debug.print("  go:    {s}\n", .{line});
        }
    }

    std.debug.print("interop-proxyproto: seed {d}, {d} cases (parse {d}, zig-writes {d}, go-writes {d}, ssl {d})\n", .{
        seed,
        cases.items.len,
        kind_counts.get(.parse),
        kind_counts.get(.zig),
        kind_counts.get(.go),
        kind_counts.get(.ssl),
    });
    var unexplained: usize = 0;
    for (std.enums.values(Class)) |k| {
        const n = counts.get(k);
        if (n == 0) continue;
        std.debug.print("  {s:<24} {d}\n", .{ @tagName(k), n });
        if (k == .diff) unexplained = n;
    }
    if (unexplained != 0) {
        std.debug.print("interop-proxyproto: {d} UNEXPLAINED disagreements\n", .{unexplained});
        return 1;
    }
    std.debug.print("interop-proxyproto: 0 unexplained disagreements\n", .{});
    return 0;
}
