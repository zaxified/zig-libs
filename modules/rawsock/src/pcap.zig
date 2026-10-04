// SPDX-License-Identifier: MIT
//! Classic pcap savefiles (`.pcap`, the tcpdump/libpcap interchange format):
//! a 24-byte global header, then per frame a 16-byte record header and the
//! captured bytes. Pure codec — no socket, no file I/O of its own: the writer
//! targets any `std.Io.Writer`, the reader walks a byte slice the caller
//! already has (a whole file, an mmap, an embedded test fixture).
//!
//! Format (pcap-savefile(5), stable since libpcap 0.4):
//!
//! ```text
//! global header  u32 magic        0xa1b2c3d4 (µs timestamps) / 0xa1b23c4d (ns)
//!                u16 major = 2, u16 minor = 4
//!                i32 thiszone = 0, u32 sigfigs = 0
//!                u32 snaplen, u32 linktype (1 = Ethernet)
//! record header  u32 ts_sec, u32 ts_frac (µs or ns), u32 incl_len, u32 orig_len
//! ```
//!
//! All fields are in the WRITER's byte order; the magic tells a reader which
//! (`d4 c3 b2 a1` on disk = a little-endian writer). The writer here always
//! writes host order, exactly as libpcap does; the reader accepts both.
//!
//! Anchored against `tcpdump` 4.99.6 / libpcap 1.10.6: the two fixtures in the
//! tests are files `tcpdump -w` wrote (µs and `--time-stamp-precision=nano`),
//! the decoded timestamps and lengths are what `tcpdump -tt -r` printed for
//! them, and the writer reproduces both files byte for byte.
//!
//! pcapng is not handled (a different, block-structured format).

const std = @import("std");
const builtin = @import("builtin");

pub const magic_micro: u32 = 0xa1b2c3d4;
pub const magic_nano: u32 = 0xa1b23c4d;
pub const header_len = 24;
pub const record_header_len = 16;
/// `LINKTYPE_ETHERNET` — what an AF_PACKET `SOCK_RAW` capture produces.
pub const linktype_ethernet: u32 = 1;
/// libpcap's default and maximum snapshot length (`MAXIMUM_SNAPLEN`).
pub const default_snaplen: u32 = 262144;

pub const Precision = enum { micro, nano };

pub const HeaderOptions = struct {
    precision: Precision = .micro,
    snaplen: u32 = default_snaplen,
    linktype: u32 = linktype_ethernet,
};

/// Write the 24-byte global header.
pub fn writeHeader(w: *std.Io.Writer, opts: HeaderOptions) std.Io.Writer.Error!void {
    var h: [header_len]u8 = undefined;
    const e = builtin.cpu.arch.endian();
    std.mem.writeInt(u32, h[0..4], if (opts.precision == .nano) magic_nano else magic_micro, e);
    std.mem.writeInt(u16, h[4..6], 2, e);
    std.mem.writeInt(u16, h[6..8], 4, e);
    std.mem.writeInt(i32, h[8..12], 0, e); // thiszone: UTC
    std.mem.writeInt(u32, h[12..16], 0, e); // sigfigs
    std.mem.writeInt(u32, h[16..20], opts.snaplen, e);
    std.mem.writeInt(u32, h[20..24], opts.linktype, e);
    try w.writeAll(&h);
}

pub const RecordError = std.Io.Writer.Error || error{
    /// More bytes captured than the frame had on the wire, or more than a
    /// record length field can hold.
    InvalidRecord,
};

/// Write one record. `ts_ns` is nanoseconds since the Unix epoch; a µs file
/// stores it truncated to microseconds (what libpcap does with a kernel ns
/// timestamp). `orig_len` is the length on the wire (`Frame.wire_len`),
/// `data` what was captured (`Frame.bytes`, possibly shorter).
pub fn writeRecord(w: *std.Io.Writer, precision: Precision, ts_ns: u64, orig_len: u32, data: []const u8) RecordError!void {
    if (data.len > orig_len) return error.InvalidRecord;
    const sec = ts_ns / std.time.ns_per_s;
    if (sec > std.math.maxInt(u32)) return error.InvalidRecord;
    const sub = ts_ns % std.time.ns_per_s;
    var h: [record_header_len]u8 = undefined;
    const e = builtin.cpu.arch.endian();
    std.mem.writeInt(u32, h[0..4], @intCast(sec), e);
    std.mem.writeInt(u32, h[4..8], @intCast(if (precision == .nano) sub else sub / std.time.ns_per_us), e);
    std.mem.writeInt(u32, h[8..12], @intCast(data.len), e);
    std.mem.writeInt(u32, h[12..16], orig_len, e);
    try w.writeAll(&h);
    try w.writeAll(data);
}

pub const ReadError = error{
    /// Not a classic pcap file (pcapng, or not a capture at all).
    BadMagic,
    /// A version other than 2.x.
    UnsupportedVersion,
    /// The header or a record runs past the end of the input.
    Truncated,
    /// A record claims more captured bytes than any libpcap writes
    /// (`max(snaplen, 262144)`) — a corrupt length, not a frame.
    RecordTooLong,
};

pub const FileHeader = struct {
    precision: Precision,
    /// The file was written on a host of the other byte order.
    swapped: bool,
    version_minor: u16,
    snaplen: u32,
    linktype: u32,
};

pub const Record = struct {
    ts_ns: u64,
    /// Length on the wire.
    orig_len: u32,
    /// The captured bytes (borrowed from the input).
    data: []const u8,
};

/// Walks a pcap file held in memory. Every length is checked against the
/// input before a slice is formed; a hostile file yields an error, never an
/// out-of-bounds read, and each `next` consumes at least 16 bytes.
pub const Reader = struct {
    header: FileHeader,
    buf: []const u8,
    pos: usize = header_len,

    pub fn init(bytes: []const u8) ReadError!Reader {
        if (bytes.len < header_len) return error.Truncated;
        const raw = std.mem.readInt(u32, bytes[0..4], .little);
        const order: std.builtin.Endian, const precision: Precision = switch (raw) {
            magic_micro => .{ .little, .micro },
            magic_nano => .{ .little, .nano },
            @byteSwap(magic_micro) => .{ .big, .micro },
            @byteSwap(magic_nano) => .{ .big, .nano },
            else => return error.BadMagic,
        };
        if (std.mem.readInt(u16, bytes[4..6], order) != 2) return error.UnsupportedVersion;
        return .{
            .header = .{
                .precision = precision,
                .swapped = order != builtin.cpu.arch.endian(),
                .version_minor = std.mem.readInt(u16, bytes[6..8], order),
                .snaplen = std.mem.readInt(u32, bytes[16..20], order),
                .linktype = std.mem.readInt(u32, bytes[20..24], order),
            },
            .buf = bytes,
        };
    }

    fn byteOrder(r: *const Reader) std.builtin.Endian {
        const host = builtin.cpu.arch.endian();
        return if (r.header.swapped) (if (host == .little) .big else .little) else host;
    }

    pub fn next(r: *Reader) ReadError!?Record {
        if (r.pos == r.buf.len) return null;
        if (r.buf.len - r.pos < record_header_len) return error.Truncated;
        const h = r.buf[r.pos..][0..record_header_len];
        const o = r.byteOrder();
        const sec: u64 = std.mem.readInt(u32, h[0..4], o);
        const frac: u64 = std.mem.readInt(u32, h[4..8], o);
        const incl = std.mem.readInt(u32, h[8..12], o);
        const orig = std.mem.readInt(u32, h[12..16], o);
        if (incl > @max(r.header.snaplen, default_snaplen)) return error.RecordTooLong;
        const start = r.pos + record_header_len;
        if (r.buf.len - start < incl) return error.Truncated;
        r.pos = start + incl;
        return .{
            .ts_ns = sec * std.time.ns_per_s + (if (r.header.precision == .nano) frac else frac * std.time.ns_per_us),
            .orig_len = orig,
            .data = r.buf[start..r.pos],
        };
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

// `tcpdump -Z root -i lo -U -w us.pcap -c 4 udp` inside `unshare -rn`, while
// four `printf helloN > /dev/udp/127.0.0.1/9` ran (Linux 7.0, tcpdump 4.99.6,
// libpcap 1.10.6, x86-64). `ns.pcap` is the same four frames captured with
// `--time-stamp-precision=nano` by a second tcpdump at the same time.
const tcpdump_us = hex(
    "d4c3b2a102000400000000000000000000000400010000001520c26a05a8090030000000300000000000000000000000" ++
        "000000000800450000222b174000401111b27f0000017f000001b8cc0009000efe2168656c6c6f311520c26a5da80900" ++
        "3000000030000000000000000000000000000000080045000022bc954000401180337f0000017f000001b7fa0009000e" ++
        "fe2168656c6c6f321520c26a8fa809003000000030000000000000000000000000000000080045000022de8a40004011" ++
        "5e3e7f0000017f000001cc4d0009000efe2168656c6c6f331520c26ab1a8090030000000300000000000000000000000" ++
        "00000000080045000022015a400040113b6f7f0000017f000001b15a0009000efe2168656c6c6f34",
);
const tcpdump_ns = hex(
    "4d3cb2a102000400000000000000000000000400010000001520c26abd53b82530000000300000000000000000000000" ++
        "000000000800450000222b174000401111b27f0000017f000001b8cc0009000efe2168656c6c6f311520c26a0caeb925" ++
        "3000000030000000000000000000000000000000080045000022bc954000401180337f0000017f000001b7fa0009000e" ++
        "fe2168656c6c6f321520c26af56eba253000000030000000000000000000000000000000080045000022de8a40004011" ++
        "5e3e7f0000017f000001cc4d0009000efe2168656c6c6f331520c26a6cf4ba2530000000300000000000000000000000" ++
        "00000000080045000022015a400040113b6f7f0000017f000001b15a0009000efe2168656c6c6f34",
);

// What `tcpdump -tt -n -r ns.pcap --time-stamp-precision=nano` printed.
const tcpdump_ns_times = [_]u64{
    1791107093_632837053, 1791107093_632925708, 1791107093_632975093, 1791107093_633009260,
};

test "Reader decodes tcpdump's files to what tcpdump -tt -r printed" {
    if (builtin.cpu.arch.endian() != .little) return error.SkipZigTest; // fixtures are LE files
    var ns = try Reader.init(&tcpdump_ns);
    try testing.expectEqual(Precision.nano, ns.header.precision);
    try testing.expectEqual(default_snaplen, ns.header.snaplen); // "snapshot length 262144"
    try testing.expectEqual(linktype_ethernet, ns.header.linktype); // "link-type EN10MB"
    var us = try Reader.init(&tcpdump_us);
    try testing.expectEqual(Precision.micro, us.header.precision);
    var i: usize = 0;
    while (try ns.next()) |rn| : (i += 1) {
        const ru = (try us.next()).?;
        try testing.expectEqual(tcpdump_ns_times[i], rn.ts_ns);
        // The µs file holds the same instant truncated: tcpdump -tt -r us.pcap
        // printed 1791107093.632837 for the first.
        try testing.expectEqual(tcpdump_ns_times[i] / 1000 * 1000, ru.ts_ns);
        // 14 Ethernet + 20 IPv4 + 8 UDP + "helloN" = 48, captured whole.
        try testing.expectEqual(@as(u32, 48), rn.orig_len);
        try testing.expectEqual(@as(usize, 48), rn.data.len);
        try testing.expectEqualSlices(u8, rn.data, ru.data);
        try testing.expectEqual(@as(u8, '1' + @as(u8, @intCast(i))), rn.data[47]);
    }
    try testing.expectEqual(@as(usize, 4), i);
    try testing.expect((try us.next()) == null);
}

test "writeHeader + writeRecord reproduce tcpdump's files byte for byte" {
    if (builtin.cpu.arch.endian() != .little) return error.SkipZigTest;
    inline for (.{ .{ Precision.micro, &tcpdump_us }, .{ Precision.nano, &tcpdump_ns } }) |c| {
        var buf: [512]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        try writeHeader(&w, .{ .precision = c[0] });
        var r = try Reader.init(c[1]);
        var i: usize = 0;
        while (try r.next()) |rec| : (i += 1) {
            // Always from the ns times: the µs writer must truncate them the
            // way libpcap did.
            try writeRecord(&w, c[0], tcpdump_ns_times[i], rec.orig_len, rec.data);
        }
        try testing.expectEqualSlices(u8, c[1], w.buffered());
    }
}

test "Reader: big-endian files, truncation, corrupt lengths, foreign magic" {
    // A big-endian µs header + one 2-byte record captured from a 60-byte frame.
    const be = [_]u8{ 0xa1, 0xb2, 0xc3, 0xd4, 0, 2, 0, 4 } ++ [_]u8{0} ** 8 ++
        [_]u8{ 0, 0, 0, 64, 0, 0, 0, 1 } ++
        [_]u8{ 0, 0, 0, 10, 0, 0, 0, 5, 0, 0, 0, 2, 0, 0, 0, 60, 0xab, 0xcd };
    var r = try Reader.init(&be);
    try testing.expectEqual(@as(u32, 64), r.header.snaplen);
    const rec = (try r.next()).?;
    try testing.expectEqual(@as(u64, 10 * std.time.ns_per_s + 5 * std.time.ns_per_us), rec.ts_ns);
    try testing.expectEqual(@as(u32, 60), rec.orig_len);
    try testing.expectEqualSlices(u8, &.{ 0xab, 0xcd }, rec.data);
    try testing.expect((try r.next()) == null);

    try testing.expectError(error.Truncated, Reader.init(be[0..23]));
    // Record header cut short / record body cut short.
    var r2 = try Reader.init(be[0 .. header_len + 10]);
    try testing.expectError(error.Truncated, r2.next());
    var r3 = try Reader.init(be[0 .. be.len - 1]);
    try testing.expectError(error.Truncated, r3.next());
    // pcapng's section-header magic is not a pcap file.
    try testing.expectError(error.BadMagic, Reader.init(&([_]u8{ 0x0a, 0x0d, 0x0d, 0x0a } ++ [_]u8{0} ** 20)));
    var v1 = be;
    v1[5] = 1; // major version 1
    try testing.expectError(error.UnsupportedVersion, Reader.init(&v1));
    // incl_len 0x00100000 (1 MiB) > max(snaplen 64, 262144): corrupt.
    var big = be;
    big[24 + 8 + 1] = 0x10;
    var r4 = try Reader.init(&big);
    try testing.expectError(error.RecordTooLong, r4.next());
    // Exactly the libpcap maximum is allowed through to the length check.
    var max = be;
    std.mem.writeInt(u32, max[24 + 8 ..][0..4], default_snaplen, .big);
    var r5 = try Reader.init(&max);
    try testing.expectError(error.Truncated, r5.next());
}

test "writeRecord refuses a capture longer than the frame and a time past 2106" {
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try testing.expectError(error.InvalidRecord, writeRecord(&w, .micro, 0, 1, &.{ 1, 2 }));
    try testing.expectError(error.InvalidRecord, writeRecord(&w, .micro, (@as(u64, std.math.maxInt(u32)) + 1) * std.time.ns_per_s, 0, &.{}));
    // The last representable second still writes.
    try writeRecord(&w, .micro, @as(u64, std.math.maxInt(u32)) * std.time.ns_per_s, 0, &.{});
    try testing.expectEqual(@as(usize, record_header_len), w.buffered().len);
}
