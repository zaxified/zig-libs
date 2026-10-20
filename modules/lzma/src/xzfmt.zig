// SPDX-License-Identifier: MIT

//! The `.xz` container's fixed structures (xz-file-format 1.2.x): stream
//! header and footer, block header, and the running record hash the index is
//! checked against.

const std = @import("std");

pub const header_magic = [6]u8{ 0xFD, '7', 'z', 'X', 'Z', 0x00 };
pub const footer_magic = [2]u8{ 'Y', 'Z' };
pub const vli_max: u64 = std.math.maxInt(u63);

pub const filter_lzma2: u64 = 0x21;

pub const Check = enum(u8) {
    none = 0,
    crc32 = 1,
    crc64 = 4,
    sha256 = 10,
};

pub fn checkSize(k: Check) usize {
    return switch (k) {
        .none => 0,
        .crc32 => 4,
        .crc64 => 8,
        .sha256 => 32,
    };
}

fn checkFromId(id: u8) error{UnsupportedCheck}!Check {
    return switch (id) {
        0 => .none,
        1 => .crc32,
        4 => .crc64,
        10 => .sha256,
        else => error.UnsupportedCheck,
    };
}

pub const StreamError = error{ BadHeader, UnsupportedCheck, BadFooter };

/// The two flag bytes of a stream header, then their CRC-32.
pub fn parseStreamFlags(flags: *const [2]u8, crc: *const [4]u8) StreamError!Check {
    if (std.hash.Crc32.hash(flags) != std.mem.readInt(u32, crc, .little)) return error.BadHeader;
    if (flags[0] != 0 or flags[1] & 0xF0 != 0) return error.BadHeader;
    return checkFromId(flags[1] & 0x0F);
}

pub const Footer = struct { check: Check, backward: u64 };

/// The 12 footer bytes; `backward` is the index size in bytes.
pub fn parseFooter(f: *const [12]u8) StreamError!Footer {
    if (!std.mem.eql(u8, f[10..12], &footer_magic)) return error.BadFooter;
    if (std.hash.Crc32.hash(f[4..10]) != std.mem.readInt(u32, f[0..4], .little)) return error.BadFooter;
    if (f[8] != 0 or f[9] & 0xF0 != 0) return error.BadFooter;
    const check = try checkFromId(f[9] & 0x0F);
    return .{ .check = check, .backward = (@as(u64, std.mem.readInt(u32, f[4..8], .little)) + 1) * 4 };
}

pub const BlockHeader = struct {
    header_size: u32 = 0,
    compressed_size: ?u64 = null,
    uncompressed_size: ?u64 = null,
    dict_size: u32 = 0,
};

pub const BlockError = error{ BadHeader, UnsupportedFilter };

fn vliFrom(buf: []const u8, pos: *usize) ?u64 {
    var v: u64 = 0;
    var i: u6 = 0;
    while (true) : (i += 1) {
        if (i == 9 or pos.* >= buf.len) return null;
        const b = buf[pos.*];
        pos.* += 1;
        v |= @as(u64, b & 0x7F) << (7 * i);
        if (b & 0x80 == 0) {
            if (b == 0 and i != 0) return null;
            return v;
        }
    }
}

/// The dictionary size an LZMA2 properties byte stands for.
pub fn lzma2DictSize(b: u8) ?u32 {
    if (b > 40) return null;
    if (b == 40) return 0xFFFF_FFFF;
    return (@as(u32, 2) | (b & 1)) << @intCast(b / 2 + 11);
}

/// A whole block header (`buf.len` is its size), CRC-32 included.
pub fn parseBlockHeader(buf: []const u8) BlockError!BlockHeader {
    std.debug.assert(buf.len >= 8 and buf.len % 4 == 0);
    const body = buf[0 .. buf.len - 4];
    if (std.hash.Crc32.hash(body) != std.mem.readInt(u32, buf[buf.len - 4 ..][0..4], .little)) return error.BadHeader;
    const flags = buf[1];
    if (flags & 0x3C != 0) return error.BadHeader;
    const n_filters = (flags & 3) + 1;
    var h: BlockHeader = .{};
    var pos: usize = 2;
    if (flags & 0x40 != 0) {
        const v = vliFrom(body, &pos) orelse return error.BadHeader;
        if (v == 0 or v > vli_max) return error.BadHeader;
        h.compressed_size = v;
    }
    if (flags & 0x80 != 0) {
        const v = vliFrom(body, &pos) orelse return error.BadHeader;
        if (v > vli_max) return error.BadHeader;
        h.uncompressed_size = v;
    }
    var unsupported = false;
    var lzma2_props: ?u8 = null;
    for (0..n_filters) |_| {
        const id = vliFrom(body, &pos) orelse return error.BadHeader;
        const psize = vliFrom(body, &pos) orelse return error.BadHeader;
        if (psize > body.len - pos) return error.BadHeader;
        const props = body[pos..][0..@intCast(psize)];
        pos += props.len;
        if (id == filter_lzma2) {
            if (props.len != 1) return error.BadHeader;
            lzma2_props = props[0];
        } else unsupported = true;
    }
    if (unsupported) return error.UnsupportedFilter;
    if (n_filters != 1) return error.BadHeader;
    for (body[pos..]) |x| if (x != 0) return error.BadHeader;
    h.dict_size = lzma2DictSize(lzma2_props.?) orelse return error.BadHeader;
    return h;
}

/// The index records seen so far, as a count and a running CRC-64 over their
/// little-endian encoding: enough to tell the real index from a forged one
/// without keeping the records.
pub const IndexHash = struct {
    count: u64 = 0,
    total: u64 = 0,
    crc: std.hash.crc.@"CRC-64/XZ" = std.hash.crc.@"CRC-64/XZ".init(),

    pub fn add(h: *IndexHash, unpadded: u64, uncompressed: u64) error{Overflow}!void {
        if (unpadded > vli_max or uncompressed > vli_max) return error.Overflow;
        const t = std.math.add(u64, h.total, unpadded) catch return error.Overflow;
        h.total = std.math.add(u64, t, uncompressed) catch return error.Overflow;
        if (h.total > vli_max) return error.Overflow;
        h.count += 1;
        var b: [16]u8 = undefined;
        std.mem.writeInt(u64, b[0..8], unpadded, .little);
        std.mem.writeInt(u64, b[8..16], uncompressed, .little);
        h.crc.update(&b);
    }
};
