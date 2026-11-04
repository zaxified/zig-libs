// SPDX-License-Identifier: MIT
//! pcapng savefiles (`.pcapng`, Wireshark's and `dumpcap`'s default format):
//! a sequence of length-framed blocks. Pure codec like `pcap.zig` — the writer
//! targets any `std.Io.Writer`, the reader walks a byte slice.
//!
//! Format (pcapng draft-ietf-opsawg-pcapng; every block is
//! `u32 type, u32 total_len, body, u32 total_len`, `total_len` a multiple of 4):
//!
//! ```text
//! Section Header  0x0A0D0D0A  u32 byte-order magic 0x1A2B3C4D, u16 major = 1,
//!                             u16 minor = 0, i64 section length, options
//! Interface Desc. 0x00000001  u16 linktype, u16 reserved, u32 snaplen, options
//!                             (option 9 if_tsresol, option 14 if_tsoffset)
//! Enhanced Packet 0x00000006  u32 interface, u32 ts high, u32 ts low,
//!                             u32 captured, u32 original, data (padded to 4), options
//! Simple Packet   0x00000003  u32 original, data (padded to 4) — no timestamp
//! ```
//!
//! The reader accepts either byte order per section, several sections and
//! interfaces (up to `max_interfaces` per section), and `if_tsresol` /
//! `if_tsoffset`. It skips every block type it has no use for (name
//! resolution, statistics, decryption secrets, custom blocks) and the obsolete
//! packet block. The writer emits host byte order, one interface, EPBs only.
//!
//! Anchored against Wireshark's `editcap` (black box): a file it converted
//! from the pcap corpus is read back to the same frames and times, and the
//! writer's output is read by `tcpdump -r` (libpcap 1.10.6) and `capinfos`.

const std = @import("std");
const builtin = @import("builtin");

pub const block_shb: u32 = 0x0A0D0D0A;
pub const block_idb: u32 = 0x00000001;
pub const block_spb: u32 = 0x00000003;
/// The obsolete Packet Block: libpcap and Wireshark still read it, so this does.
pub const block_pb: u32 = 0x00000002;
pub const block_epb: u32 = 0x00000006;
pub const byte_order_magic: u32 = 0x1A2B3C4D;
/// Interfaces one section may declare; more is `error.TooManyInterfaces`
/// (the table lives inside the `Reader`, which has no allocator).
pub const max_interfaces = 32;
/// Largest captured length a record may claim, as in `pcap.zig`.
pub const max_snaplen: u32 = 262144;

pub const Precision = enum { micro, nano };

pub const HeaderOptions = struct {
    precision: Precision = .nano,
    snaplen: u32 = max_snaplen,
    linktype: u16 = 1,
};

fn pad4(n: usize) usize {
    return (n + 3) & ~@as(usize, 3);
}

/// Write the Section Header Block and one Interface Description Block.
pub fn writeHeader(w: *std.Io.Writer, opts: HeaderOptions) std.Io.Writer.Error!void {
    const e = builtin.cpu.arch.endian();
    var shb: [28]u8 = undefined;
    std.mem.writeInt(u32, shb[0..4], block_shb, e);
    std.mem.writeInt(u32, shb[4..8], 28, e);
    std.mem.writeInt(u32, shb[8..12], byte_order_magic, e);
    std.mem.writeInt(u16, shb[12..14], 1, e);
    std.mem.writeInt(u16, shb[14..16], 0, e);
    std.mem.writeInt(i64, shb[16..24], -1, e); // section length unknown
    std.mem.writeInt(u32, shb[24..28], 28, e);
    try w.writeAll(&shb);

    // IDB: 8 bytes of body, if_tsresol (4 + 1 padded to 8), opt_endofopt (4).
    var idb: [32]u8 = undefined;
    std.mem.writeInt(u32, idb[0..4], block_idb, e);
    std.mem.writeInt(u32, idb[4..8], 32, e);
    std.mem.writeInt(u16, idb[8..10], opts.linktype, e);
    std.mem.writeInt(u16, idb[10..12], 0, e);
    std.mem.writeInt(u32, idb[12..16], opts.snaplen, e);
    std.mem.writeInt(u16, idb[16..18], 9, e); // if_tsresol
    std.mem.writeInt(u16, idb[18..20], 1, e);
    idb[20] = if (opts.precision == .nano) 9 else 6;
    idb[21] = 0;
    idb[22] = 0;
    idb[23] = 0;
    std.mem.writeInt(u16, idb[24..26], 0, e); // opt_endofopt
    std.mem.writeInt(u16, idb[26..28], 0, e);
    std.mem.writeInt(u32, idb[28..32], 32, e);
    try w.writeAll(&idb);
}

pub const RecordError = std.Io.Writer.Error || error{InvalidRecord};

/// Write one Enhanced Packet Block on interface 0. `precision` must be the one
/// given to `writeHeader`; `ts_ns` is nanoseconds since the epoch.
pub fn writeRecord(w: *std.Io.Writer, precision: Precision, ts_ns: u64, orig_len: u32, data: []const u8) RecordError!void {
    if (data.len > orig_len or data.len > max_snaplen) return error.InvalidRecord;
    const e = builtin.cpu.arch.endian();
    const total: u32 = @intCast(32 + pad4(data.len));
    const ticks: u64 = if (precision == .nano) ts_ns else ts_ns / std.time.ns_per_us;
    var h: [28]u8 = undefined;
    std.mem.writeInt(u32, h[0..4], block_epb, e);
    std.mem.writeInt(u32, h[4..8], total, e);
    std.mem.writeInt(u32, h[8..12], 0, e);
    std.mem.writeInt(u32, h[12..16], @intCast(ticks >> 32), e);
    std.mem.writeInt(u32, h[16..20], @truncate(ticks), e);
    std.mem.writeInt(u32, h[20..24], @intCast(data.len), e);
    std.mem.writeInt(u32, h[24..28], orig_len, e);
    try w.writeAll(&h);
    try w.writeAll(data);
    const zeros: [4]u8 = @splat(0);
    try w.writeAll(zeros[0 .. pad4(data.len) - data.len]);
    var t: [4]u8 = undefined;
    std.mem.writeInt(u32, &t, total, e);
    try w.writeAll(&t);
}

pub const ReadError = error{
    /// Not a pcapng file (the first block is not a Section Header).
    BadMagic,
    /// A section with a major version other than 1.
    UnsupportedVersion,
    /// A block runs past the end of the input.
    Truncated,
    /// A block length that is not a multiple of 4, shorter than the framing,
    /// whose trailer disagrees, or a body or option that does not fit it.
    BadBlock,
    /// A packet block naming an interface the section never declared.
    BadInterface,
    /// More than `max_interfaces` interfaces in one section.
    TooManyInterfaces,
    /// A captured length above `max_snaplen`.
    RecordTooLong,
    /// A timestamp resolution this reader does not support (decimal above
    /// 10^-18, binary above 2^-62) or an instant that does not fit 64-bit ns.
    BadTimestamp,
};

pub const Interface = struct {
    linktype: u16,
    snaplen: u32,
    /// One tick is `tick_num / tick_div` nanoseconds (`if_tsresol`; the
    /// default 10^-6 is 1000 / 1).
    tick_num: u64,
    tick_div: u64,
    /// `if_tsoffset`, seconds.
    offset_s: i64,
};

pub const Record = struct {
    ts_ns: u64,
    /// Length on the wire.
    orig_len: u32,
    /// The captured bytes (borrowed from the input).
    data: []const u8,
    /// Interface index within the section and its link type.
    interface: u32,
    linktype: u16,
    /// False for a Simple Packet Block, which carries no timestamp (`ts_ns` is 0).
    has_time: bool,
};

pub const Reader = struct {
    buf: []const u8,
    pos: usize = 0,
    order: std.builtin.Endian = .little,
    ifaces: [max_interfaces]Interface = @splat(.{ .linktype = 1, .snaplen = 0, .tick_num = 1000, .tick_div = 1, .offset_s = 0 }),
    n_ifaces: usize = 0,
    /// The error that ended reading, if any (see `next`).
    failed: ?ReadError = null,

    pub fn init(bytes: []const u8) ReadError!Reader {
        if (bytes.len < 12) return error.Truncated;
        if (std.mem.readInt(u32, bytes[0..4], .little) != block_shb) return error.BadMagic;
        return .{ .buf = bytes };
    }

    /// The next packet, skipping every other block; null at the end of the
    /// input. Every call consumes at least one block (12 bytes), so a loop over
    /// `next` runs at most `buf.len / 12 + 1` times.
    ///
    /// An error is TERMINAL: the reader keeps it and returns it again from
    /// every later call (it does not retry the same bad block, and does not
    /// resynchronise into the middle of one), so a loop that ignores it spins
    /// on an error, never on a record.
    pub fn next(r: *Reader) ReadError!?Record {
        if (r.failed) |e| return e;
        return r.nextBlock() catch |e| {
            r.failed = e;
            return e;
        };
    }

    fn nextBlock(r: *Reader) ReadError!?Record {
        while (r.pos < r.buf.len) {
            const blk = try r.block();
            const body = r.buf[blk.start + 8 .. blk.start + blk.len - 4];
            switch (blk.kind) {
                block_shb => try r.section(body),
                block_idb => try r.interface(body),
                block_epb => {
                    if (body.len < 20) return error.BadBlock;
                    return try r.packet(body, std.mem.readInt(u32, body[0..4], r.order));
                },
                block_pb => {
                    if (body.len < 20) return error.BadBlock;
                    return try r.packet(body, std.mem.readInt(u16, body[0..2], r.order));
                },
                block_spb => return try r.simple(body),
                else => {},
            }
        }
        return null;
    }

    const Block = struct { kind: u32, start: usize, len: usize };

    /// Frame the block at `pos` and advance past it.
    fn block(r: *Reader) ReadError!Block {
        const start = r.pos;
        if (r.buf.len - start < 12) return error.Truncated;
        const kind = std.mem.readInt(u32, r.buf[start..][0..4], .little);
        if (kind == block_shb) {
            // The Section Header fixes the byte order; its length field is
            // read in it, so look at the magic first.
            const m = std.mem.readInt(u32, r.buf[start + 8 ..][0..4], .little);
            if (r.buf.len - start < 28) return error.Truncated;
            r.order = if (m == byte_order_magic) .little else if (m == @byteSwap(byte_order_magic)) .big else return error.BadMagic;
        }
        const o = r.order;
        const kind_o = std.mem.readInt(u32, r.buf[start..][0..4], o);
        const len: usize = std.mem.readInt(u32, r.buf[start + 4 ..][0..4], o);
        if (len < 12 or len % 4 != 0) return error.BadBlock;
        if (r.buf.len - start < len) return error.Truncated;
        if (std.mem.readInt(u32, r.buf[start + len - 4 ..][0..4], o) != len) return error.BadBlock;
        r.pos = start + len;
        return .{ .kind = kind_o, .start = start, .len = len };
    }

    fn section(r: *Reader, body: []const u8) ReadError!void {
        if (body.len < 16) return error.BadBlock;
        if (std.mem.readInt(u16, body[4..6], r.order) != 1) return error.UnsupportedVersion;
        r.n_ifaces = 0; // interfaces are scoped to their section
    }

    fn interface(r: *Reader, body: []const u8) ReadError!void {
        if (body.len < 8) return error.BadBlock;
        if (r.n_ifaces >= max_interfaces) return error.TooManyInterfaces;
        const o = r.order;
        var it: Interface = .{
            .linktype = std.mem.readInt(u16, body[0..2], o),
            .snaplen = std.mem.readInt(u32, body[4..8], o),
            .tick_num = 1000, // default if_tsresol 6: microseconds
            .tick_div = 1,
            .offset_s = 0,
        };
        var opts = body[8..];
        while (opts.len >= 4) {
            const code = std.mem.readInt(u16, opts[0..2], o);
            const olen: usize = std.mem.readInt(u16, opts[2..4], o);
            if (code == 0) break;
            if (opts.len - 4 < olen) return error.BadBlock;
            const val = opts[4..][0..olen];
            // libpcap refuses an if_tsresol that is not one byte; so does this.
            if (code == 9 and olen != 1) return error.BadBlock;
            if (code == 9) {
                const v = val[0];
                if (v & 0x80 == 0) {
                    if (v > 18) return error.BadTimestamp;
                    // ns per tick = 10^9 / 10^v
                    var p: u64 = 1;
                    for (0..v) |_| p *= 10;
                    if (v <= 9) {
                        it.tick_num = 1_000_000_000 / p;
                        it.tick_div = 1;
                    } else {
                        it.tick_num = 1;
                        it.tick_div = p / 1_000_000_000;
                    }
                } else {
                    const n = v & 0x7f;
                    if (n > 62) return error.BadTimestamp;
                    it.tick_num = 1_000_000_000;
                    it.tick_div = @as(u64, 1) << @intCast(n);
                }
            } else if (code == 14 and olen == 8) {
                it.offset_s = std.mem.readInt(i64, val[0..8], o);
            }
            const adv = 4 + pad4(olen);
            if (opts.len < adv) break;
            opts = opts[adv..];
        }
        r.ifaces[r.n_ifaces] = it;
        r.n_ifaces += 1;
    }

    /// An Enhanced (or obsolete) Packet Block body, 20 bytes of header then the
    /// padded data; `id` is the interface the caller read from its own layout.
    fn packet(r: *Reader, body: []const u8, id: u32) ReadError!Record {
        const o = r.order;
        // `n_ifaces` is a public field: a caller's stray value stays inside the table.
        if (id >= @min(r.n_ifaces, max_interfaces)) return error.BadInterface;
        const it = r.ifaces[id];
        const ticks = (@as(u64, std.mem.readInt(u32, body[4..8], o)) << 32) | std.mem.readInt(u32, body[8..12], o);
        const cap = std.mem.readInt(u32, body[12..16], o);
        const orig = std.mem.readInt(u32, body[16..20], o);
        if (cap > max_snaplen) return error.RecordTooLong;
        if (body.len - 20 < pad4(cap)) return error.BadBlock;
        // ticks * tick_num / tick_div, in 128 bits: no overflow before the
        // check against 64-bit nanoseconds.
        const ns128: i128 = @as(i128, @intCast(@as(u128, ticks) * it.tick_num / it.tick_div)) + @as(i128, it.offset_s) * std.time.ns_per_s;
        if (ns128 < 0 or ns128 > std.math.maxInt(u64)) return error.BadTimestamp;
        return .{
            .ts_ns = @intCast(ns128),
            .orig_len = orig,
            .data = body[20..][0..cap],
            .interface = id,
            .linktype = it.linktype,
            .has_time = true,
        };
    }

    fn simple(r: *Reader, body: []const u8) ReadError!Record {
        if (body.len < 4) return error.BadBlock;
        if (r.n_ifaces == 0) return error.BadInterface;
        const it = r.ifaces[0];
        const orig = std.mem.readInt(u32, body[0..4], r.order);
        // The captured length is not stored: it is the original length clipped to
        // the interface's snaplen (0 = no limit), and the block must hold that
        // many bytes. libpcap and Wireshark both call a shorter block corrupt;
        // the padding after the data is never part of the packet.
        const cap: usize = if (it.snaplen != 0) @min(it.snaplen, orig) else orig;
        if (cap > body.len - 4) return error.BadBlock;
        return .{ .ts_ns = 0, .orig_len = orig, .data = body[4..][0..cap], .interface = 0, .linktype = it.linktype, .has_time = false };
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

const pcap = @import("pcap.zig");

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    @setEvalBranchQuota(100000);
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

// Three frames (an ARP request, a 13-byte runt that needs padding, a UDP
// datagram), as two classic pcap files this module's own `pcap` codec reads
// (ns and µs), and the same capture as the files Wireshark's `editcap -F
// pcapng` converted them to (black box, `editcap` 4.6.4: SHB with an
// application option, IDB with if_tsresol 9, and for the µs file an IDB with
// no options at all, i.e. the default 10^-6), and as the files this module's
// writer must reproduce byte for byte. `tcpdump -n --nano -tt -r` (libpcap
// 1.10.6) and `capinfos` read both `ours_*` files as three packets at
// 1700000000.123456789 / .123455789 / .123454789 (µs: ...456000 etc.).
const pcap_ns = hex(
    "4d3cb2a1020004000000000000000000000004000100000000f1536515cd5b072a0000002a000000ffffffffffff0011" ++
        "22334455080600010800060400010011223344550a0000010000000000000a00000201f153652dc95b07300000003000" ++
        "00000200000000090200000000098100000508004500001e00010000401100000a0000010a0000020035003500000000" ++
        "787802f1536545c55b072c0000002c00000002000000000900112233445508004500001e00010000400600000a000001" ++
        "c000020504d20050000000007878",
);

const pcap_us = hex(
    "d4c3b2a1020004000000000000000000000004000100000000f1536540e201002a0000002a000000ffffffffffff0011" ++
        "22334455080600010800060400010011223344550a0000010000000000000a00000201f153653fe20100300000003000" ++
        "00000200000000090200000000098100000508004500001e00010000401100000a0000010a0000020035003500000000" ++
        "787802f153653ee201002c0000002c00000002000000000900112233445508004500001e00010000400600000a000001" ++
        "c000020504d20050000000007878",
);

const editcap_ns = hex(
    "0a0d0d0a400000004d3c2b1a01000000ffffffffffffffff0400190045646974636170202857697265736861726b2920" ++
        "342e362e3400000000000000400000000100000020000000010000000000040009000100090000000000000020000000" ++
        "060000004c00000000000000fe9c971715cd853d2a0000002a000000ffffffffffff0011223344550806000108000604" ++
        "00010011223344550a0000010000000000000a00000200004c000000060000005000000000000000fe9c97172d932079" ++
        "30000000300000000200000000090200000000098100000508004500001e00010000401100000a0000010a0000020035" ++
        "003500000000787850000000060000004c00000000000000fe9c97174559bbb42c0000002c0000000200000000090011" ++
        "2233445508004500001e00010000400600000a000001c000020504d200500000000078784c000000",
);

const editcap_us = hex(
    "0a0d0d0a400000004d3c2b1a01000000ffffffffffffffff0400190045646974636170202857697265736861726b2920" ++
        "342e362e3400000000000000400000000100000014000000010000000000040014000000060000004c00000000000000" ++
        "240a0600402220182a0000002a000000ffffffffffff001122334455080600010800060400010011223344550a000001" ++
        "0000000000000a00000200004c000000060000005000000000000000240a06007f642f18300000003000000002000000" ++
        "00090200000000098100000508004500001e00010000401100000a0000010a0000020035003500000000787850000000" ++
        "060000004c00000000000000240a0600bea63e182c0000002c00000002000000000900112233445508004500001e0001" ++
        "0000400600000a000001c000020504d200500000000078784c000000",
);

const ours_ns = hex(
    "0a0d0d0a1c0000004d3c2b1a01000000ffffffffffffffff1c0000000100000020000000010000000000040009000100" ++
        "090000000000000020000000060000004c00000000000000fe9c971715cd853d2a0000002a000000ffffffffffff0011" ++
        "22334455080600010800060400010011223344550a0000010000000000000a00000200004c0000000600000050000000" ++
        "00000000fe9c97172d93207930000000300000000200000000090200000000098100000508004500001e000100004011" ++
        "00000a0000010a0000020035003500000000787850000000060000004c00000000000000fe9c97174559bbb42c000000" ++
        "2c00000002000000000900112233445508004500001e00010000400600000a000001c000020504d20050000000007878" ++
        "4c000000",
);

const ours_us = hex(
    "0a0d0d0a1c0000004d3c2b1a01000000ffffffffffffffff1c0000000100000020000000010000000000040009000100" ++
        "060000000000000020000000060000004c00000000000000240a0600402220182a0000002a000000ffffffffffff0011" ++
        "22334455080600010800060400010011223344550a0000010000000000000a00000200004c0000000600000050000000" ++
        "00000000240a06007f642f1830000000300000000200000000090200000000098100000508004500001e000100004011" ++
        "00000a0000010a0000020035003500000000787850000000060000004c00000000000000240a0600bea63e182c000000" ++
        "2c00000002000000000900112233445508004500001e00010000400600000a000001c000020504d20050000000007878" ++
        "4c000000",
);

const times_ns = [_]u64{ 1_700_000_000_123_456_789, 1_700_000_001_123_455_789, 1_700_000_002_123_454_789 };

fn expectFrames(file: []const u8, precision: pcap.Precision, ref: []const u8) !void {
    var want = try pcap.Reader.init(ref);
    var got = try Reader.init(file);
    var n: usize = 0;
    while (try want.next()) |w| : (n += 1) {
        const g = (try got.next()).?;
        try testing.expectEqualSlices(u8, w.data, g.data);
        try testing.expectEqual(w.orig_len, g.orig_len);
        try testing.expectEqual(w.ts_ns, g.ts_ns);
        const unit: u64 = if (precision == .micro) 1000 else 1;
        try testing.expectEqual(times_ns[n] / unit * unit, g.ts_ns);
        try testing.expectEqual(@as(u16, 1), g.linktype);
        try testing.expect(g.has_time);
    }
    try testing.expectEqual(@as(usize, 3), n);
    try testing.expect((try got.next()) == null);
}

test "Reader decodes the files editcap converted (ns, and µs by default resolution)" {
    try expectFrames(&editcap_ns, .nano, &pcap_ns);
    try expectFrames(&editcap_us, .micro, &pcap_us);
}

test "Reader decodes this writer's files to what libpcap and capinfos read" {
    try expectFrames(&ours_ns, .nano, &pcap_ns);
    try expectFrames(&ours_us, .micro, &pcap_us);
}

test "writer reproduces the frozen files byte for byte" {
    // The fixtures are little-endian files; the writer writes host order.
    if (builtin.cpu.arch.endian() != .little) return error.SkipZigTest;
    inline for (.{ .{ Precision.nano, &ours_ns, &pcap_ns }, .{ Precision.micro, &ours_us, &pcap_us } }) |c| {
        var out: [512]u8 = undefined;
        var w: std.Io.Writer = .fixed(&out);
        try writeHeader(&w, .{ .precision = c[0] });
        var rd = try pcap.Reader.init(c[2]);
        while (try rd.next()) |rec| try writeRecord(&w, c[0], rec.ts_ns, rec.orig_len, rec.data);
        try testing.expectEqualSlices(u8, c[1], w.buffered());
    }
}

test "writer output equals the hand-built stream in the HOST byte order (runs on every target)" {
    for ([_]Precision{ .nano, .micro }) |prec| {
        var out: [512]u8 = undefined;
        var w: std.Io.Writer = .fixed(&out);
        try writeHeader(&w, .{ .precision = prec, .snaplen = 1500 });
        try writeRecord(&w, prec, 7_000_000_000, 5, "abcde");
        try writeRecord(&w, prec, 9_000_000_000, 8, "abcdefgh");
        var b: Build = .{ .o = builtin.cpu.arch.endian() };
        b.shb(1);
        b.idb(1, if (prec == .nano) 9 else 6, null);
        const per: u64 = if (prec == .nano) 1 else 1000;
        b.epb(0, 7_000_000_000 / per, "abcde");
        b.epb(0, 9_000_000_000 / per, "abcdefgh");
        try testing.expectEqualSlices(u8, b.done(), w.buffered());
    }
}

/// A hand-built pcapng stream in either byte order, for the cases no tool
/// file covers.
const Build = struct {
    buf: [1024]u8 = undefined,
    n: usize = 0,
    o: std.builtin.Endian,
    start: usize = 0,

    fn u32_(b: *Build, v: u32) void {
        std.mem.writeInt(u32, b.buf[b.n..][0..4], v, b.o);
        b.n += 4;
    }
    fn u16_(b: *Build, v: u16) void {
        std.mem.writeInt(u16, b.buf[b.n..][0..2], v, b.o);
        b.n += 2;
    }
    fn bytes(b: *Build, d: []const u8) void {
        @memcpy(b.buf[b.n..][0..d.len], d);
        b.n += d.len;
        while (b.n % 4 != 0) : (b.n += 1) b.buf[b.n] = 0;
    }
    fn open(b: *Build, kind: u32) void {
        b.start = b.n;
        b.u32_(kind);
        b.u32_(0);
    }
    fn close(b: *Build) void {
        b.u32_(@intCast(b.n + 4 - b.start));
        std.mem.writeInt(u32, b.buf[b.start + 4 ..][0..4], @intCast(b.n - b.start), b.o);
    }
    fn shb(b: *Build, major: u16) void {
        b.open(block_shb);
        b.u32_(byte_order_magic);
        b.u16_(major);
        b.u16_(0);
        b.u32_(0xffffffff);
        b.u32_(0xffffffff);
        b.close();
    }
    /// An IDB with an optional if_tsresol and if_tsoffset.
    fn idb(b: *Build, linktype: u16, tsresol: ?u8, offset: ?i64) void {
        b.open(block_idb);
        b.u16_(linktype);
        b.u16_(0);
        b.u32_(1500);
        if (tsresol) |v| {
            b.u16_(9);
            b.u16_(1);
            b.bytes(&.{v});
        }
        if (offset) |v| {
            b.u16_(14);
            b.u16_(8);
            std.mem.writeInt(i64, b.buf[b.n..][0..8], v, b.o);
            b.n += 8;
        }
        b.u16_(0);
        b.u16_(0);
        b.close();
    }
    fn epb(b: *Build, iface: u32, ticks: u64, data: []const u8) void {
        b.open(block_epb);
        b.u32_(iface);
        b.u32_(@intCast(ticks >> 32));
        b.u32_(@truncate(ticks));
        b.u32_(@intCast(data.len));
        b.u32_(@intCast(data.len));
        b.bytes(data);
        b.close();
    }
    fn done(b: *const Build) []const u8 {
        return b.buf[0..b.n];
    }
};

test "Reader: both byte orders, several sections and interfaces, timestamp resolutions" {
    for ([_]std.builtin.Endian{ .little, .big }) |o| {
        var b: Build = .{ .o = o };
        b.shb(1);
        b.idb(1, 9, null); // iface 0: ns
        b.idb(105, 3, null); // iface 1: ms, another link type
        b.idb(1, 0x80 | 10, null); // iface 2: 2^-10 s
        b.idb(1, 9, 5); // iface 3: ns, one second later
        b.epb(0, 1_000_000_001, "a");
        b.epb(1, 1500, "bb");
        b.epb(2, 2048, "ccc");
        b.epb(3, 7, "dddd");
        // An unknown block type is skipped; a new section restarts interfaces.
        b.open(0x40000bad);
        b.bytes("whatever");
        b.close();
        b.shb(1);
        b.idb(1, null, null); // default µs
        b.epb(0, 1_500_000, "e");
        var r = try Reader.init(b.done());
        const want = [_]struct { u64, u16, []const u8 }{
            .{ 1_000_000_001, 1, "a" },
            .{ 1_500_000_000, 105, "bb" },
            .{ 2_000_000_000, 1, "ccc" },
            .{ 5_000_000_007, 1, "dddd" },
            .{ 1_500_000_000, 1, "e" },
        };
        for (want) |w| {
            const rec = (try r.next()).?;
            try testing.expectEqual(w[0], rec.ts_ns);
            try testing.expectEqual(w[1], rec.linktype);
            try testing.expectEqualStrings(w[2], rec.data);
        }
        try testing.expect((try r.next()) == null);
    }
}

test "Reader: Simple Packet Block carries no time and is clipped to its original length" {
    var b: Build = .{ .o = .little };
    b.shb(1);
    b.idb(1, null, null);
    b.open(block_spb);
    b.u32_(3); // orig_len 3, the block holds 4 bytes of padded data
    b.bytes("xyz");
    b.close();
    var r = try Reader.init(b.done());
    const rec = (try r.next()).?;
    try testing.expectEqualStrings("xyz", rec.data);
    try testing.expect(!rec.has_time);
    try testing.expectEqual(@as(u64, 0), rec.ts_ns);
}

test "Reader: the obsolete Packet Block is read, as libpcap and Wireshark read it" {
    // Probed 2026-11-03: `tcpdump -r` and `capinfos` both read a type-2 block.
    for ([_]std.builtin.Endian{ .little, .big }) |o| {
        var b: Build = .{ .o = o };
        b.shb(1);
        b.idb(1, 9, null);
        b.open(block_pb);
        b.u16_(0); // interface
        b.u16_(0); // drops
        b.u32_(0);
        b.u32_(1000);
        b.u32_(3);
        b.u32_(3);
        b.bytes("xyz");
        b.close();
        var r = try Reader.init(b.done());
        const rec = (try r.next()).?;
        try testing.expectEqual(@as(u64, 1000), rec.ts_ns);
        try testing.expectEqualStrings("xyz", rec.data);
    }
}

test "Reader: a Simple Packet Block longer than its block is corrupt; if_tsresol must be one byte; an error is terminal" {
    // libpcap: "block of type 3 ... is too short"; Wireshark: "block content length 12 of an SPB is too small for 100 bytes".
    var b: Build = .{ .o = .little };
    b.shb(1);
    b.idb(1, null, null);
    b.open(block_spb);
    b.u32_(100);
    b.bytes("abcde");
    b.close();
    var r = try Reader.init(b.done());
    try testing.expectError(error.BadBlock, r.next());
    // Terminal: the same error again, never a record from the middle of the bad block.
    try testing.expectError(error.BadBlock, r.next());
    try testing.expectError(error.BadBlock, r.next());
    // No snaplen limit, a short block: the data is exactly orig_len bytes, the padding is not.
    b = .{ .o = .little };
    b.shb(1);
    b.idb(1, null, null);
    b.open(block_spb);
    b.u32_(5);
    b.bytes("abcde");
    b.close();
    r = try Reader.init(b.done());
    try testing.expectEqualStrings("abcde", (try r.next()).?.data);
    // The block holds exactly orig_len bytes (no padding): accepted, it is not "too short".
    b = .{ .o = .little };
    b.shb(1);
    b.idb(1, null, null);
    b.open(block_spb);
    b.u32_(4);
    b.bytes("abcd");
    b.close();
    r = try Reader.init(b.done());
    try testing.expectEqualStrings("abcd", (try r.next()).?.data);
    // if_tsresol with a two-byte value: libpcap refuses it.
    b = .{ .o = .little };
    b.shb(1);
    b.open(block_idb);
    b.u16_(1);
    b.u16_(0);
    b.u32_(1500);
    b.u16_(9);
    b.u16_(2);
    b.bytes(&.{ 9, 9 });
    b.u16_(0);
    b.u16_(0);
    b.close();
    r = try Reader.init(b.done());
    try testing.expectError(error.BadBlock, r.next());
}

test "Reader: every refusal is a typed error" {
    // A packet for an interface that was never declared.
    var b: Build = .{ .o = .little };
    b.shb(1);
    b.epb(0, 1, "x");
    var r = try Reader.init(b.done());
    try testing.expectError(error.BadInterface, r.next());

    // Section major version 2.
    b = .{ .o = .little };
    b.shb(2);
    r = try Reader.init(b.done());
    try testing.expectError(error.UnsupportedVersion, r.next());

    // Resolutions the reader will not guess at: 10^-19, 2^-63.
    for ([_]u8{ 19, 0x80 | 63 }) |res| {
        b = .{ .o = .little };
        b.shb(1);
        b.idb(1, res, null);
        r = try Reader.init(b.done());
        try testing.expectError(error.BadTimestamp, r.next());
    }

    // An instant past 64-bit nanoseconds, and one before the epoch.
    b = .{ .o = .little };
    b.shb(1);
    b.idb(1, 3, null); // ms ticks: maxInt(u64) of them is far past 2554
    b.epb(0, std.math.maxInt(u64), "x");
    r = try Reader.init(b.done());
    try testing.expectError(error.BadTimestamp, r.next());
    b = .{ .o = .little };
    b.shb(1);
    b.idb(1, 9, -5);
    b.epb(0, 1, "x");
    r = try Reader.init(b.done());
    try testing.expectError(error.BadTimestamp, r.next());

    // Thirty-three interfaces in one section.
    b = .{ .o = .little };
    b.shb(1);
    for (0..max_interfaces + 1) |_| b.idb(1, null, null);
    r = try Reader.init(b.done());
    try testing.expectError(error.TooManyInterfaces, r.next());

    // A block length that is not a multiple of 4, too short, or whose trailer
    // disagrees.
    inline for (.{ 13, 8, 0xffff_fff4 }) |bad_len| {
        b = .{ .o = .little };
        b.shb(1);
        b.open(0x99);
        b.bytes("abcd");
        b.close();
        std.mem.writeInt(u32, b.buf[b.start + 4 ..][0..4], bad_len, .little);
        r = try Reader.init(b.done());
        try testing.expect(std.meta.isError(r.next()));
    }
    b = .{ .o = .little };
    b.shb(1);
    b.open(0x99);
    b.bytes("abcd");
    b.close();
    std.mem.writeInt(u32, b.buf[b.n - 4 ..][0..4], 99, .little);
    r = try Reader.init(b.done());
    try testing.expectError(error.BadBlock, r.next());

    // A captured length past the block, and past max_snaplen.
    b = .{ .o = .little };
    b.shb(1);
    b.idb(1, null, null);
    b.epb(0, 1, "abcd");
    std.mem.writeInt(u32, b.buf[b.start + 8 + 12 ..][0..4], 100, .little);
    r = try Reader.init(b.done());
    try testing.expectError(error.BadBlock, r.next());
    std.mem.writeInt(u32, b.buf[b.start + 8 + 12 ..][0..4], max_snaplen + 1, .little);
    r = try Reader.init(b.done());
    try testing.expectError(error.RecordTooLong, r.next());

    // An option that runs past its block.
    b = .{ .o = .little };
    b.shb(1);
    b.open(block_idb);
    b.u16_(1);
    b.u16_(0);
    b.u32_(1500);
    b.u16_(9);
    b.u16_(200);
    b.close();
    r = try Reader.init(b.done());
    try testing.expectError(error.BadBlock, r.next());
}

test "Reader: no prefix of a real file panics, loops, or reads outside the input" {
    for ([_][]const u8{ &editcap_ns, &editcap_us, &ours_ns }) |file| {
        var cut: usize = 12;
        while (cut < file.len) : (cut += 1) {
            var r = try Reader.init(file[0..cut]);
            var steps: usize = 0;
            while (steps <= cut / 12 + 1) : (steps += 1) {
                const rec = r.next() catch break;
                const got = rec orelse break;
                // Whatever came out lies inside the input.
                const base = @intFromPtr(file.ptr);
                try testing.expect(@intFromPtr(got.data.ptr) >= base);
                try testing.expect(@intFromPtr(got.data.ptr) + got.data.len <= base + cut);
            } else return error.DidNotTerminate;
        }
    }
}

test "writeRecord pads to four and a one-byte frame round-trips" {
    var out: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    try writeHeader(&w, .{});
    try writeRecord(&w, .nano, 1_700_000_000_123_456_789, 5, "abcde");
    var r = try Reader.init(w.buffered());
    const rec = (try r.next()).?;
    try testing.expectEqual(@as(u64, 1_700_000_000_123_456_789), rec.ts_ns);
    try testing.expectEqualStrings("abcde", rec.data);
    try testing.expectEqual(@as(u32, 5), rec.orig_len);
    try testing.expect((try r.next()) == null);
}

test "writeRecord refuses a record longer than its wire length" {
    var out: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    try testing.expectError(error.InvalidRecord, writeRecord(&w, .nano, 0, 2, "abc"));
}

test "Reader refuses what is not pcapng" {
    try testing.expectError(error.Truncated, Reader.init(""));
    try testing.expectError(error.BadMagic, Reader.init("\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00"));
}

// ── fuzz: the pcapng reader ──────────────────────────────────────────────────
//
// Same contract as the classic reader, over a block-structured format: records
// inside the input, typed errors, termination within `len / 12 + 1` blocks, and
// a round trip of every timed record through the writer.

const testkit = @import("testkit");
const fz = @import("fuzz_test.zig");
const NgMark = fz.Marker(enum { rejected, bad_block, records, round_trip });

const ng_seeds = [_][]const u8{
    testkit.fuzz.seed(&editcap_ns),
    testkit.fuzz.seed(&editcap_us),
    testkit.fuzz.seed(&ours_ns),
    testkit.fuzz.seed(ours_ns[0..60]), // header block and half an interface block
    testkit.fuzz.seed(ours_ns[0 .. ours_ns.len - 6]), // the last block cut short
    testkit.fuzz.seed(""),
};

test "fuzz: pcapng.Reader never panics on hostile files, and what it reads round-trips" {
    try testing.fuzz({}, fuzzNgSmith, .{ .corpus = &ng_seeds });
}

test "fuzz driver: RAWSOCK_FUZZ (pcapng)" {
    try fz.fuzz_driver.run(fuzzNg, .{ .prefix = "RAWSOCK_FUZZ", .name = "rawsock-pcapng" });
}

test "fuzz harness: pcapng, 300 seeds, reaches every outcome" {
    try NgMark.reach(fuzzNg, "rawsock-pcapng", 300);
}

fn fuzzNgSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [fz.script_cap]u8 = undefined;
    const n = smith.slice(&script);
    try fz.runFrom(fuzzNg, smith, script[0..n]);
}

fn fuzzNg(comptime S: type, smith: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var buf: [512]u8 = undefined;
    const len: usize = fz.drawInput(S, smith, &buf, &ng_seeds);
    const file = buf[0..len];
    var r = Reader.init(file) catch return NgMark.mark(.rejected);
    var out: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    try writeHeader(&w, .{});
    var kept: [8]struct { u64, u32, []const u8 } = undefined;
    var n_kept: usize = 0;
    var steps: usize = 0;
    while (steps <= len / 12 + 1) : (steps += 1) {
        const rec = r.next() catch |e| {
            if (e == error.BadBlock) NgMark.mark(.bad_block) else NgMark.mark(.rejected);
            break;
        } orelse break;
        const base = @intFromPtr(file.ptr);
        try testing.expect(@intFromPtr(rec.data.ptr) >= base and @intFromPtr(rec.data.ptr) + rec.data.len <= base + len);
        if (rec.has_time and rec.orig_len >= rec.data.len and n_kept < kept.len) {
            writeRecord(&w, .nano, rec.ts_ns, rec.orig_len, rec.data) catch continue;
            kept[n_kept] = .{ rec.ts_ns, rec.orig_len, rec.data };
            n_kept += 1;
        }
    } else return error.DidNotTerminate;
    if (n_kept == 0) return;
    NgMark.mark(.records);
    var back = try Reader.init(w.buffered());
    for (kept[0..n_kept]) |k| {
        const rec = (try back.next()).?;
        try testing.expectEqual(k[0], rec.ts_ns);
        try testing.expectEqual(k[1], rec.orig_len);
        try testing.expectEqualSlices(u8, k[2], rec.data);
    }
    try testing.expect((try back.next()) == null);
    NgMark.mark(.round_trip);
}

// ── delta audit 2026-11-04: the exact limits of every check ──────────────────

test "Reader: block framing at its limits (12-byte block at the very end, misaligned length, bad byte-order magic)" {
    var b: Build = .{ .o = .little };
    b.shb(1);
    b.open(0x40000bad); // the smallest block there is: type, length, trailer
    b.close();
    var r = try Reader.init(b.done());
    try testing.expect((try r.next()) == null);

    // A length of 14 with a matching trailer is not a multiple of 4.
    b = .{ .o = .little };
    b.shb(1);
    b.u32_(0x99);
    b.u32_(14);
    b.u16_(0);
    b.u32_(14);
    r = try Reader.init(b.done());
    try testing.expectError(error.BadBlock, r.next());

    // A section header whose magic is neither byte order.
    b = .{ .o = .little };
    b.shb(1);
    std.mem.writeInt(u32, b.buf[8..12], 0xdeadbeef, .little);
    r = try Reader.init(b.done());
    try testing.expectError(error.BadMagic, r.next());
}

test "Reader: option walking at its limits (end-of-options, an option filling the block, a short if_tsoffset)" {
    // Options after opt_endofopt are never read: this if_tsresol (ms) is ignored, the default (µs) holds.
    var b: Build = .{ .o = .little };
    b.shb(1);
    b.open(block_idb);
    b.u16_(1);
    b.u16_(0);
    b.u32_(1500);
    b.u16_(0);
    b.u16_(0);
    b.u16_(9);
    b.u16_(1);
    b.bytes(&.{3});
    b.close();
    b.epb(0, 1500, "x");
    var r = try Reader.init(b.done());
    try testing.expectEqual(@as(u64, 1_500_000), (try r.next()).?.ts_ns);

    // An option whose value ends exactly at the end of the block, with no end-of-options after it.
    b = .{ .o = .little };
    b.shb(1);
    b.open(block_idb);
    b.u16_(1);
    b.u16_(0);
    b.u32_(1500);
    b.u16_(2); // if_name
    b.u16_(4);
    b.bytes("abcd");
    b.close();
    b.epb(0, 7, "x");
    r = try Reader.init(b.done());
    try testing.expectEqual(@as(u64, 7000), (try r.next()).?.ts_ns);

    // if_tsoffset (14) that is not 8 bytes is skipped, not read.
    b = .{ .o = .little };
    b.shb(1);
    b.open(block_idb);
    b.u16_(1);
    b.u16_(0);
    b.u32_(1500);
    b.u16_(14);
    b.u16_(4);
    b.u32_(0x01020304);
    b.u16_(0);
    b.u16_(0);
    b.close();
    b.epb(0, 7, "x");
    r = try Reader.init(b.done());
    try testing.expectEqual(@as(u64, 7000), (try r.next()).?.ts_ns);
}

test "Reader: timestamp resolutions at their limits (10^-18, 2^-62), instant zero, and the largest record" {
    var b: Build = .{ .o = .little };
    b.shb(1);
    b.idb(1, 18, null);
    b.epb(0, 2_000_000_000, "x"); // 2e9 ticks of 1e-18 s: 2 ns
    b.idb(1, 0x80 | 62, null);
    b.epb(1, @as(u64, 1) << 62, "y"); // 2^62 ticks of 2^-62 s: one second
    b.idb(1, 9, null);
    b.epb(2, 0, ""); // the epoch itself, and an empty capture (a 20-byte body)
    var r = try Reader.init(b.done());
    try testing.expectEqual(@as(u64, 2), (try r.next()).?.ts_ns);
    try testing.expectEqual(@as(u64, 1_000_000_000), (try r.next()).?.ts_ns);
    const z = (try r.next()).?;
    try testing.expectEqual(@as(u64, 0), z.ts_ns);
    try testing.expectEqual(@as(usize, 0), z.data.len);

    // The largest record the reader and the writer take: max_snaplen bytes.
    const big = try testing.allocator.alloc(u8, max_snaplen);
    defer testing.allocator.free(big);
    @memset(big, 0xab);
    var w: std.Io.Writer.Allocating = .init(testing.allocator);
    defer w.deinit();
    try writeHeader(&w.writer, .{});
    try writeRecord(&w.writer, .nano, 5, max_snaplen, big);
    var rr = try Reader.init(w.written());
    const rec = (try rr.next()).?;
    try testing.expectEqual(@as(usize, max_snaplen), rec.data.len);
}

test "Reader: packet and simple blocks at their limits, and a stray public interface count" {
    // A Packet Block (obsolete) shorter than its 20-byte header.
    var b: Build = .{ .o = .little };
    b.shb(1);
    b.idb(1, 9, null);
    b.open(block_pb);
    b.u32_(0);
    b.u32_(0);
    b.close();
    var r = try Reader.init(b.done());
    try testing.expectError(error.BadBlock, r.next());

    // A Simple Packet Block before any interface; with one, clipped to its snaplen; with a body of 4 bytes and orig 0.
    b = .{ .o = .little };
    b.shb(1);
    b.open(block_spb);
    b.u32_(0);
    b.close();
    r = try Reader.init(b.done());
    try testing.expectError(error.BadInterface, r.next());
    b = .{ .o = .little };
    b.shb(1);
    b.open(block_idb);
    b.u16_(1);
    b.u16_(0);
    b.u32_(2); // snaplen 2
    b.u16_(0);
    b.u16_(0);
    b.close();
    b.open(block_spb);
    b.u32_(4);
    b.bytes("abcd");
    b.close();
    b.open(block_spb);
    b.u32_(0);
    b.close();
    r = try Reader.init(b.done());
    const clipped = (try r.next()).?;
    try testing.expectEqualStrings("ab", clipped.data);
    try testing.expectEqual(@as(u32, 4), clipped.orig_len);
    try testing.expectEqual(@as(usize, 0), (try r.next()).?.data.len);

    // `n_ifaces` is public: a stray count past the table never indexes it.
    b = .{ .o = .little };
    b.shb(1);
    b.idb(1, 9, null);
    b.epb(0, 1, "x");
    b.epb(500, 1, "x");
    r = try Reader.init(b.done());
    _ = (try r.next()).?;
    r.n_ifaces = 1000;
    try testing.expectError(error.BadInterface, r.next());
}
