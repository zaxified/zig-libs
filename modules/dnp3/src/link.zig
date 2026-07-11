// SPDX-License-Identifier: MIT

//! dnp3.link — the Data Link Layer (IEEE 1815-2012 §9): the fixed 0x0564
//! frame, the control octet (DIR/PRM/FCB/FCV + a 4-bit function code), the
//! 16-bit destination/source link addresses, and the DNP3 CRC-16.
//!
//! Frame shape on the wire:
//!
//! ```
//! [0]=0x05 [1]=0x64 [2]=length [3]=control [4..6)=dest(LE) [6..8)=src(LE)
//! [8..10)=header CRC-16(LE)
//! -- then user data in blocks of up to 16 octets, each followed by its own
//! -- CRC-16(LE) over just that block.
//! ```
//!
//! `length` (octet [2]) counts control + dest + src + user-data octets —
//! i.e. `5 + user_data.len` — and explicitly excludes every CRC octet, per
//! §9.2.4.
//!
//! The CRC is CRC-16/DNP (poly 0x3D65, init 0x0000, reflected in/out, final
//! XOR 0xFFFF — reveng CRC-catalogue name "CRC-16/DNP", check("123456789")
//! = 0xEA82) applied independently to the 8-octet header block and to each
//! subsequent ≤16-octet user-data block (§9.2.4, §9.2.9).

const std = @import("std");

pub const start0: u8 = 0x05;
pub const start1: u8 = 0x64;

/// Octets in a data block before a CRC is inserted (§9.2.9).
pub const max_block_len: usize = 16;
/// Octets in the CRC trailer after each block (header block included).
pub const crc_len: usize = 2;
/// Header block size before its CRC (start x2 + length + control + dest + src).
pub const header_block_len: usize = 8;
/// Header block + its CRC.
pub const header_frame_len: usize = header_block_len + crc_len;
/// `length` octet is a single byte (max 255); user data <= 255 - 5.
pub const max_user_data_len: usize = 250;

/// Worst-case encoded frame length for `user_data_len` bytes of payload:
/// header (10) + payload + one CRC per full-or-partial 16-byte block.
pub fn maxFrameLen(user_data_len: usize) usize {
    const blocks = if (user_data_len == 0) 0 else std.math.divCeil(usize, user_data_len, max_block_len) catch unreachable;
    return header_frame_len + user_data_len + blocks * crc_len;
}

// ── CRC-16/DNP ───────────────────────────────────────────────────────────────

// Table generated from the *reflected* polynomial (reflect(0x3D65, 16) =
// 0xA6BC) so the byte loop below can shift right (LSB-first), matching the
// refin=true/refout=true convention. Verified against an independent
// bit-serial reference implementation of the (poly, init, refin, refout,
// xorout) parameters directly — see modules/dnp3/SPEC.md "CRC verification".
const crc16_table: [256]u16 = blk: {
    @setEvalBranchQuota(4096);
    var table: [256]u16 = undefined;
    for (&table, 0..) |*entry, i| {
        var crc: u16 = @intCast(i);
        for (0..8) |_| {
            crc = if (crc & 1 != 0) (crc >> 1) ^ 0xA6BC else crc >> 1;
        }
        entry.* = crc;
    }
    break :blk table;
};

/// CRC-16/DNP over `bytes`: init 0x0000, table-driven reflected polynomial,
/// final XOR 0xFFFF. `crc16("123456789") == 0xEA82` (the reveng CRC-catalogue
/// check value for "CRC-16/DNP").
pub fn crc16(bytes: []const u8) u16 {
    var crc: u16 = 0x0000;
    for (bytes) |b| crc = (crc >> 8) ^ crc16_table[@as(u8, @truncate(crc)) ^ b];
    return crc ^ 0xFFFF;
}

// ── control octet ────────────────────────────────────────────────────────────

/// Primary-station function codes (valid when `Control.prm == true`), §9.2.6.
pub const PrimaryFunction = enum(u4) {
    reset_link_states = 0,
    test_link_states = 2,
    confirmed_user_data = 3,
    unconfirmed_user_data = 4,
    request_link_status = 9,
    _,
};

/// Secondary-station function codes (valid when `Control.prm == false`), §9.2.6.
pub const SecondaryFunction = enum(u4) {
    ack = 0,
    nack = 1,
    link_status = 11, // a.k.a. RESPOND_LINK_STATUS / STATUS_OF_LINK
    not_supported = 15,
    _,
};

/// The link-layer control octet (§9.2.5): DIR/PRM/FCB/FCV + a 4-bit function
/// code. Whether `function` reads as `PrimaryFunction` or `SecondaryFunction`
/// is determined by `prm` — callers use `primaryFunction()`/
/// `secondaryFunction()` for the typed view.
pub const Control = struct {
    /// DIR bit (0x80): the two stations sharing a link each send frames in
    /// both directions; DIR marks which logical direction (conventionally
    /// true = master-originated) this particular frame belongs to.
    dir: bool,
    /// PRM bit (0x40): true = primary (request) frame, `function` is a
    /// `PrimaryFunction`; false = secondary (response) frame, `function` is
    /// a `SecondaryFunction`.
    prm: bool,
    /// Bit 0x20: Frame Count Bit. Meaningful only when `prm == true` — reset
    /// to a known value by RESET_LINK_STATES, then toggled each subsequent
    /// frame that requires confirmation, so the receiver can detect a
    /// retransmission. Reserved (must be 0) when `prm == false`.
    fcb: bool = false,
    /// Bit 0x10: Frame Count Valid when `prm == true` (whether `fcb` is
    /// meaningful for this function code); Data Flow Control when
    /// `prm == false` (secondary station asking the primary to pause).
    fcv_or_dfc: bool = false,
    /// Bits 0x0F: the function code, interpreted via `primaryFunction()` or
    /// `secondaryFunction()` depending on `prm`.
    function: u4,

    pub fn primaryFunction(self: Control) PrimaryFunction {
        return @enumFromInt(self.function);
    }

    pub fn secondaryFunction(self: Control) SecondaryFunction {
        return @enumFromInt(self.function);
    }

    pub fn toByte(self: Control) u8 {
        var b: u8 = @as(u8, self.function);
        if (self.dir) b |= 0x80;
        if (self.prm) b |= 0x40;
        if (self.fcb) b |= 0x20;
        if (self.fcv_or_dfc) b |= 0x10;
        return b;
    }

    pub fn fromByte(b: u8) Control {
        return .{
            .dir = (b & 0x80) != 0,
            .prm = (b & 0x40) != 0,
            .fcb = (b & 0x20) != 0,
            .fcv_or_dfc = (b & 0x10) != 0,
            .function = @truncate(b & 0x0F),
        };
    }
};

// ── errors ───────────────────────────────────────────────────────────────────

pub const EncodeError = error{
    /// More than `max_user_data_len` bytes of link user data.
    UserDataTooLong,
    /// `out` is too small for the encoded frame.
    BufferTooSmall,
};

pub const DecodeError = error{
    /// Fewer than 10 bytes (header block + its CRC).
    ShortFrame,
    /// `frame[0..2]` is not `{0x05, 0x64}`.
    BadStartBytes,
    /// `length` octet < 5 (can't even cover control+dest+src), or implies
    /// more user data than `max_user_data_len`.
    BadLengthField,
    /// The header-block CRC (bytes 0..8) doesn't match bytes 8..10.
    BadHeaderCrc,
    /// A user-data block's CRC doesn't match its trailing 2 bytes.
    BadBlockCrc,
    /// `frame` is shorter than `length` implies (a data block or its CRC
    /// runs past the end of the supplied bytes).
    TruncatedBlock,
    /// `user_data_out` is too small to hold the decoded user data.
    BufferTooSmall,
};

/// A decoded frame's header fields plus how much of `user_data_out` the
/// reassembled (CRC-stripped) user data occupies.
pub const DecodedFrame = struct {
    control: Control,
    dest: u16,
    src: u16,
    user_data_len: usize,
};

/// Encodes one data-link frame: header block (+CRC) followed by `user_data`
/// split into ≤16-byte blocks, each with its own trailing CRC. Returns the
/// slice of `out` actually used.
pub fn encodeFrame(control: Control, dest: u16, src: u16, user_data: []const u8, out: []u8) EncodeError![]u8 {
    if (user_data.len > max_user_data_len) return error.UserDataTooLong;
    if (out.len < maxFrameLen(user_data.len)) return error.BufferTooSmall;

    out[0] = start0;
    out[1] = start1;
    out[2] = @intCast(5 + user_data.len);
    out[3] = control.toByte();
    std.mem.writeInt(u16, out[4..6], dest, .little);
    std.mem.writeInt(u16, out[6..8], src, .little);
    const header_crc = crc16(out[0..header_block_len]);
    std.mem.writeInt(u16, out[8..10], header_crc, .little);

    var pos: usize = header_frame_len;
    var remaining = user_data;
    while (remaining.len > 0) {
        const n = @min(remaining.len, max_block_len);
        @memcpy(out[pos..][0..n], remaining[0..n]);
        const block_crc = crc16(out[pos..][0..n]);
        std.mem.writeInt(u16, out[pos + n ..][0..2], block_crc, .little);
        pos += n + crc_len;
        remaining = remaining[n..];
    }
    return out[0..pos];
}

/// Validates and decodes one data-link frame from `frame`, copying the
/// CRC-stripped, reassembled user data into `user_data_out`. Never panics —
/// every malformed/short/corrupt input maps to a `DecodeError`.
pub fn decodeFrame(frame: []const u8, user_data_out: []u8) DecodeError!DecodedFrame {
    if (frame.len < header_frame_len) return error.ShortFrame;
    if (frame[0] != start0 or frame[1] != start1) return error.BadStartBytes;

    const length = frame[2];
    if (length < 5) return error.BadLengthField;
    const user_len: usize = @as(usize, length) - 5;
    if (user_len > max_user_data_len) return error.BadLengthField;

    const header_crc_wire = std.mem.readInt(u16, frame[8..10], .little);
    if (crc16(frame[0..header_block_len]) != header_crc_wire) return error.BadHeaderCrc;

    const control = Control.fromByte(frame[3]);
    const dest = std.mem.readInt(u16, frame[4..6], .little);
    const src = std.mem.readInt(u16, frame[6..8], .little);

    if (user_data_out.len < user_len) return error.BufferTooSmall;

    var pos: usize = header_frame_len;
    var written: usize = 0;
    var remaining = user_len;
    while (remaining > 0) {
        const n = @min(remaining, max_block_len);
        if (frame.len < pos + n + crc_len) return error.TruncatedBlock;
        const block = frame[pos..][0..n];
        const block_crc_wire = std.mem.readInt(u16, frame[pos + n ..][0..2], .little);
        if (crc16(block) != block_crc_wire) return error.BadBlockCrc;
        @memcpy(user_data_out[written..][0..n], block);
        written += n;
        pos += n + crc_len;
        remaining -= n;
    }
    return .{ .control = control, .dest = dest, .src = src, .user_data_len = written };
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "CRC-16/DNP catalog check value" {
    // reveng CRC catalogue "CRC-16/DNP": check("123456789") = 0xEA82.
    try testing.expectEqual(@as(u16, 0xEA82), crc16("123456789"));
}

test "CRC-16/DNP known-answer vectors (cross-checked vs. an independent bit-serial reference)" {
    // Computed by a from-scratch Python bit-serial CRC engine built directly
    // from the (width=16, poly=0x3D65, init=0x0000, refin=true, refout=true,
    // xorout=0xFFFF) parameters -- an independent second implementation of
    // the same algorithm, not a port of the table above. See SPEC.md.
    try testing.expectEqual(@as(u16, 0xFFFF), crc16(""));
    try testing.expectEqual(@as(u16, 0xFFFF), crc16(&.{0x00}));
    try testing.expectEqual(@as(u16, 0xEDCA), crc16(&.{0xFF}));
    try testing.expectEqual(@as(u16, 0x9AFF), crc16("A"));
    try testing.expectEqual(@as(u16, 0xC078), crc16("AB"));
    try testing.expectEqual(@as(u16, 0xD35A), crc16("ABC"));
    try testing.expectEqual(
        @as(u16, 0x21E9),
        crc16(&.{ 0x05, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x00, 0x04 }),
    );
    try testing.expectEqual(
        @as(u16, 0x63A8),
        crc16(&.{ 0x05, 0x64, 0x0B, 0xC4, 0x01, 0x00, 0x00, 0x04, 0xC3, 0x01, 0xC0, 0xC0, 0x01 }),
    );
    var seq: [16]u8 = undefined;
    for (&seq, 0..) |*b, i| b.* = @intCast(i);
    try testing.expectEqual(@as(u16, 0x10EC), crc16(&seq));
    try testing.expectEqual(@as(u16, 0x91E0), crc16(&([_]u8{0xAA} ** 16)));
}

test "control octet round-trip" {
    const c = Control{ .dir = true, .prm = true, .fcb = true, .fcv_or_dfc = false, .function = @intFromEnum(PrimaryFunction.confirmed_user_data) };
    const b = c.toByte();
    try testing.expectEqual(@as(u8, 0xE3), b); // DIR|PRM|FCB | 0x03
    const back = Control.fromByte(b);
    try testing.expectEqual(c.dir, back.dir);
    try testing.expectEqual(c.prm, back.prm);
    try testing.expectEqual(c.fcb, back.fcb);
    try testing.expectEqual(c.fcv_or_dfc, back.fcv_or_dfc);
    try testing.expectEqual(PrimaryFunction.confirmed_user_data, back.primaryFunction());
}

test "frame round-trip: no user data (RESET_LINK_STATES)" {
    const control = Control{ .dir = true, .prm = true, .function = @intFromEnum(PrimaryFunction.reset_link_states) };
    var out: [32]u8 = undefined;
    const frame = try encodeFrame(control, 1, 1024, &.{}, &out);
    try testing.expectEqual(@as(usize, 10), frame.len);
    try testing.expectEqualSlices(u8, &.{ 0x05, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x00, 0x04 }, frame[0..8]);
    try testing.expectEqualSlices(u8, &.{ 0xE9, 0x21 }, frame[8..10]); // low-byte-first CRC

    var user_buf: [8]u8 = undefined;
    const decoded = try decodeFrame(frame, &user_buf);
    try testing.expectEqual(@as(u16, 1), decoded.dest);
    try testing.expectEqual(@as(u16, 1024), decoded.src);
    try testing.expectEqual(@as(usize, 0), decoded.user_data_len);
    try testing.expectEqual(PrimaryFunction.reset_link_states, decoded.control.primaryFunction());
}

test "frame round-trip: single short block" {
    const control = Control{ .dir = true, .prm = true, .fcv_or_dfc = true, .function = @intFromEnum(PrimaryFunction.unconfirmed_user_data) };
    const payload = "hello dnp3";
    var out: [64]u8 = undefined;
    const frame = try encodeFrame(control, 4, 3, payload, &out);

    var user_buf: [32]u8 = undefined;
    const decoded = try decodeFrame(frame, &user_buf);
    try testing.expectEqual(@as(usize, payload.len), decoded.user_data_len);
    try testing.expectEqualSlices(u8, payload, user_buf[0..decoded.user_data_len]);
}

test "frame round-trip: multi-block user data (>16 bytes)" {
    var payload: [40]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @intCast(i % 251);
    const control = Control{ .dir = false, .prm = true, .function = @intFromEnum(PrimaryFunction.unconfirmed_user_data) };

    var out: [80]u8 = undefined;
    const frame = try encodeFrame(control, 7, 8, &payload, &out);
    // 3 blocks (16+16+8) => header(10) + 40 + 3*2 = 56.
    try testing.expectEqual(@as(usize, 56), frame.len);

    var user_buf: [40]u8 = undefined;
    const decoded = try decodeFrame(frame, &user_buf);
    try testing.expectEqual(@as(usize, 40), decoded.user_data_len);
    try testing.expectEqualSlices(u8, &payload, user_buf[0..decoded.user_data_len]);
}

test "frame round-trip: exact block boundary (16 bytes)" {
    var payload: [16]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @intCast(i);
    var out: [64]u8 = undefined;
    const frame = try encodeFrame(.{ .dir = true, .prm = true, .function = 4 }, 1, 2, &payload, &out);
    try testing.expectEqual(@as(usize, header_frame_len + 16 + crc_len), frame.len);

    var user_buf: [16]u8 = undefined;
    const decoded = try decodeFrame(frame, &user_buf);
    try testing.expectEqualSlices(u8, &payload, user_buf[0..decoded.user_data_len]);
}

test "encode: user data too long" {
    var out: [512]u8 = undefined;
    var big: [max_user_data_len + 1]u8 = undefined;
    try testing.expectError(error.UserDataTooLong, encodeFrame(.{ .dir = true, .prm = true, .function = 4 }, 1, 1, &big, &out));
}

test "encode: buffer too small" {
    var out: [5]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, encodeFrame(.{ .dir = true, .prm = true, .function = 0 }, 1, 1, &.{}, &out));
}

test "decode: malformed frames never panic" {
    var user_buf: [64]u8 = undefined;

    try testing.expectError(error.ShortFrame, decodeFrame(&.{ 0x05, 0x64, 0x05 }, &user_buf));
    try testing.expectError(error.BadStartBytes, decodeFrame(&.{ 0x00, 0x00, 0x05, 0xC0, 0, 0, 0, 0, 0, 0 }, &user_buf));
    try testing.expectError(error.BadLengthField, decodeFrame(&.{ 0x05, 0x64, 0x02, 0xC0, 0, 0, 0, 0, 0, 0 }, &user_buf));

    // Header CRC deliberately wrong.
    try testing.expectError(error.BadHeaderCrc, decodeFrame(&.{ 0x05, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x00, 0x04, 0xFF, 0xFF }, &user_buf));

    // Valid header, corrupted single-byte payload block CRC.
    var good: [16]u8 = undefined;
    const frame = try encodeFrame(.{ .dir = true, .prm = true, .function = 4 }, 1, 1, "X", &good);
    const frame_len = frame.len;
    var corrupt = good;
    corrupt[frame_len - 1] ^= 0xFF;
    try testing.expectError(error.BadBlockCrc, decodeFrame(corrupt[0..frame_len], &user_buf));

    // Frame shorter than length implies.
    try testing.expectError(error.TruncatedBlock, decodeFrame(frame[0 .. frame.len - 1], &user_buf));

    // A sweep of pure garbage of every short length must never panic.
    var garbage: [24]u8 = .{0xAA} ** 24;
    var len: usize = 0;
    while (len <= garbage.len) : (len += 1) {
        _ = decodeFrame(garbage[0..len], &user_buf) catch {};
    }
}

test "decode: user_data_out too small" {
    var out: [32]u8 = undefined;
    const frame = try encodeFrame(.{ .dir = true, .prm = true, .function = 4 }, 1, 1, "hello", &out);
    var tiny: [2]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, decodeFrame(frame, &tiny));
}
