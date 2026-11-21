// SPDX-License-Identifier: MIT

//! The IEC 60870-5-101 serial link layer frame format FT1.2 (IEC 60870-5-1
//! §6.2.4.2, link procedures of IEC 60870-5-2): the framing a controlled or
//! controlling station puts on an RS-232/RS-485 line (or any byte stream) in
//! place of the APCI of the 104 profile. Pure framing: no port, no timer and no
//! link state machine; the caller reads and writes the bytes and owns the
//! retries, as it does with `apci`. The ASDU inside a variable frame is the same
//! one `asdu.zig` codes, with the 101 address sizes in `asdu.Params`.
//!
//! Three frame shapes:
//!
//! - single character `0xE5` (positive acknowledgement; some profiles use
//!   `0xA2` for a negative one);
//! - fixed length `0x10 C A CS 0x16` (link-layer service with no user data);
//! - variable length `0x68 L L 0x68 C A ASDU CS 0x16`, `L` counting `C`, `A`
//!   and the ASDU.
//!
//! `CS` is the sum modulo 256 of the octets from `C` up to the last user octet.
//! The link address `A` takes 0, 1 or 2 octets (little endian), a parameter of
//! the system like the ASDU address sizes.

const std = @import("std");

pub const start_fixed: u8 = 0x10;
pub const start_variable: u8 = 0x68;
pub const end_byte: u8 = 0x16;
/// The single-character positive acknowledgement.
pub const ack_char: u8 = 0xE5;
/// The single-character negative acknowledgement (profile-dependent).
pub const nack_char: u8 = 0xA2;

/// `L` is one octet and counts the control field, the address and the ASDU.
pub const max_length: usize = 255;
/// Largest variable frame: 4 header octets, `L` octets, checksum and end.
pub const max_frame_len: usize = 4 + max_length + 2;

pub const Error = error{
    /// The output slice is too small.
    BufferTooSmall,
    /// The user data does not fit `L` (control + address + ASDU > 255).
    TooLong,
    /// An address does not fit the configured link address length.
    AddressOutOfRange,
    /// The bytes are not a frame (wrong start or end octet, `L` repeated
    /// differently, length inconsistent with the octets present).
    BadFrame,
    BadChecksum,
    /// The slice ends inside the frame.
    Truncated,
};

/// How many octets the link address takes: 0 (point-to-point, none), 1 or 2.
pub const AddressLen = enum(u2) {
    none = 0,
    one = 1,
    two = 2,

    pub fn octets(self: AddressLen) usize {
        return @backingInt(self);
    }

    pub fn max(self: AddressLen) u16 {
        return switch (self) {
            .none => 0,
            .one => 0xFF,
            .two => 0xFFFF,
        };
    }
};

/// Which of the two link procedures the control field is read for. Unbalanced
/// (master polls slaves) and balanced (either side starts) differ in bit 7:
/// reserved in the first, the direction bit `DIR` in the second.
pub const Mode = enum { unbalanced, balanced };

/// The control field. `primary` frames start a transaction (`PRM = 1`),
/// secondary ones answer. The two flag bits and the function code mean different
/// things for each; the field names are the primary ones with the secondary
/// ones in the comments.
pub const Control = struct {
    primary: bool,
    /// Balanced mode only: the frame travels from the controlling station
    /// (`DIR = 1`) or towards it.
    dir: bool = false,
    /// Primary: frame count bit. Secondary: access demand `ACD`.
    fcb_acd: bool = false,
    /// Primary: frame count bit valid. Secondary: data flow control `DFC`.
    fcv_dfc: bool = false,
    /// Four-bit function code.
    function: u4,

    pub fn encode(self: Control, mode: Mode) u8 {
        var c: u8 = @as(u8, self.function);
        if (self.fcv_dfc) c |= 0x10;
        if (self.fcb_acd) c |= 0x20;
        if (self.primary) c |= 0x40;
        if (mode == .balanced and self.dir) c |= 0x80;
        return c;
    }

    pub fn decode(c: u8, mode: Mode) Control {
        return .{
            .primary = c & 0x40 != 0,
            .dir = mode == .balanced and c & 0x80 != 0,
            .fcb_acd = c & 0x20 != 0,
            .fcv_dfc = c & 0x10 != 0,
            .function = @truncate(c),
        };
    }
};

/// Function codes of a primary frame (IEC 60870-5-2 Table 1).
pub const PrimaryFunction = struct {
    pub const reset_remote_link: u4 = 0;
    pub const reset_user_process: u4 = 1;
    /// Balanced mode: test function for link.
    pub const test_link: u4 = 2;
    /// User data, confirmation expected (`FCV = 1`).
    pub const user_data_confirm: u4 = 3;
    /// User data, no reply (`FCV = 0`).
    pub const user_data_no_reply: u4 = 4;
    /// Unbalanced mode: request access demand.
    pub const request_access_demand: u4 = 8;
    pub const request_status_of_link: u4 = 9;
    /// Unbalanced mode: request user data class 1 and 2.
    pub const request_class1: u4 = 10;
    pub const request_class2: u4 = 11;
};

/// Function codes of a secondary frame (IEC 60870-5-2 Table 2).
pub const SecondaryFunction = struct {
    pub const ack: u4 = 0;
    pub const nack: u4 = 1;
    /// Unbalanced mode: user data (the answer to a class request).
    pub const user_data: u4 = 8;
    /// Unbalanced mode: no user data available.
    pub const nack_no_data: u4 = 9;
    pub const status_of_link: u4 = 11;
    pub const not_functioning: u4 = 14;
    pub const not_implemented: u4 = 15;
};

/// One decoded frame. `asdu` points into the buffer the frame was decoded from.
pub const Frame = union(enum) {
    single: u8,
    fixed: Fixed,
    variable: Variable,

    pub const Fixed = struct { control: u8, address: u16 };
    pub const Variable = struct { control: u8, address: u16, asdu: []const u8 };
};

fn sum(bytes: []const u8) u8 {
    var s: u8 = 0;
    for (bytes) |b| s +%= b;
    return s;
}

fn putAddress(out: []u8, len: AddressLen, address: u16) Error!void {
    if (address > len.max()) return error.AddressOutOfRange;
    switch (len) {
        .none => {},
        .one => out[0] = @truncate(address),
        .two => std.mem.writeInt(u16, out[0..2], address, .little),
    }
}

fn getAddress(bytes: []const u8, len: AddressLen) u16 {
    return switch (len) {
        .none => 0,
        .one => bytes[0],
        .two => std.mem.readInt(u16, bytes[0..2], .little),
    };
}

/// Writes the single character `ack_char` (or `nack_char`) and returns it as a slice.
pub fn encodeSingle(out: []u8, nack: bool) Error![]const u8 {
    if (out.len < 1) return error.BufferTooSmall;
    out[0] = if (nack) nack_char else ack_char;
    return out[0..1];
}

/// Encodes `0x10 C A CS 0x16`.
pub fn encodeFixed(out: []u8, alen: AddressLen, control: u8, address: u16) Error![]const u8 {
    const n = 4 + alen.octets();
    if (out.len < n) return error.BufferTooSmall;
    out[0] = start_fixed;
    out[1] = control;
    try putAddress(out[2..], alen, address);
    out[2 + alen.octets()] = sum(out[1 .. 2 + alen.octets()]);
    out[3 + alen.octets()] = end_byte;
    return out[0..n];
}

/// Encodes `0x68 L L 0x68 C A ASDU CS 0x16`.
pub fn encodeVariable(out: []u8, alen: AddressLen, control: u8, address: u16, asdu: []const u8) Error![]const u8 {
    const l = 1 + alen.octets() + asdu.len;
    if (l > max_length) return error.TooLong;
    const n = 4 + l + 2;
    if (out.len < n) return error.BufferTooSmall;
    out[0] = start_variable;
    out[1] = @intCast(l);
    out[2] = @intCast(l);
    out[3] = start_variable;
    out[4] = control;
    try putAddress(out[5..], alen, address);
    @memcpy(out[5 + alen.octets() ..][0..asdu.len], asdu);
    out[4 + l] = sum(out[4..][0..l]);
    out[5 + l] = end_byte;
    return out[0..n];
}

/// How many octets the frame starting at `bytes[0]` occupies, once enough of it
/// is there to say: null while the header is incomplete, `BadFrame` if the first
/// octet starts no frame.
pub fn frameLength(bytes: []const u8, alen: AddressLen) Error!?usize {
    if (bytes.len == 0) return null;
    switch (bytes[0]) {
        ack_char, nack_char => return 1,
        start_fixed => return 4 + alen.octets(),
        start_variable => {
            if (bytes.len < 4) return null;
            if (bytes[1] != bytes[2] or bytes[3] != start_variable) return error.BadFrame;
            if (bytes[1] < 1 + alen.octets()) return error.BadFrame;
            return 4 + @as(usize, bytes[1]) + 2;
        },
        else => return error.BadFrame,
    }
}

/// Decodes one whole frame (`bytes` is exactly the frame): checks the start and
/// end octets, the repeated length and the checksum.
pub fn decode(bytes: []const u8, alen: AddressLen) Error!Frame {
    const want = (try frameLength(bytes, alen)) orelse return error.Truncated;
    if (bytes.len < want) return error.Truncated;
    if (bytes.len > want) return error.BadFrame;
    switch (bytes[0]) {
        ack_char, nack_char => return .{ .single = bytes[0] },
        start_fixed => {
            const a = alen.octets();
            if (bytes[3 + a] != end_byte) return error.BadFrame;
            if (bytes[2 + a] != sum(bytes[1 .. 2 + a])) return error.BadChecksum;
            return .{ .fixed = .{ .control = bytes[1], .address = getAddress(bytes[2..], alen) } };
        },
        else => {
            const l: usize = bytes[1];
            if (bytes[5 + l] != end_byte) return error.BadFrame;
            if (bytes[4 + l] != sum(bytes[4..][0..l])) return error.BadChecksum;
            return .{ .variable = .{
                .control = bytes[4],
                .address = getAddress(bytes[5..], alen),
                .asdu = bytes[5 + alen.octets() .. 4 + l],
            } };
        },
    }
}

/// Splits a byte stream into frames, as `apci.Framer` does for the 104 profile.
/// A serial line delivers noise and half frames: octets that cannot start a
/// frame are skipped (counted in `skipped`), and a frame that fails its checks
/// costs its first octet and the search goes on from the next, so one bad frame
/// does not swallow the good one behind it.
pub const Framer = struct {
    buf: []u8,
    len: usize = 0,
    alen: AddressLen,
    /// Octets dropped while looking for the start of a frame.
    skipped: usize = 0,
    /// Frames dropped for a bad checksum or end octet.
    rejected: usize = 0,
    /// Octets of the frame `next` returned last, removed on the next call.
    consumed: usize = 0,

    /// `buf` holds at least `max_frame_len` octets.
    pub fn init(buf: []u8, alen: AddressLen) Framer {
        std.debug.assert(buf.len >= max_frame_len);
        return .{ .buf = buf, .alen = alen };
    }

    /// Octets `feed` can take now.
    pub fn room(self: *const Framer) usize {
        return self.buf.len - self.len;
    }

    pub fn feed(self: *Framer, bytes: []const u8) error{BufferTooSmall}!void {
        if (bytes.len > self.room()) return error.BufferTooSmall;
        @memcpy(self.buf[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }

    fn drop(self: *Framer, n: usize) void {
        std.mem.copyForwards(u8, self.buf[0 .. self.len - n], self.buf[n..self.len]);
        self.len -= n;
    }

    /// The next whole, valid frame, or null when more octets are needed. The
    /// frame's `asdu` points into the framer's buffer and stays valid until the
    /// next `next` or `feed`.
    pub fn next(self: *Framer) ?Frame {
        // The frame returned last time is removed first, so its slice stayed valid.
        if (self.consumed != 0) {
            self.drop(self.consumed);
            self.consumed = 0;
        }
        while (self.len > 0) {
            const want = frameLength(self.buf[0..self.len], self.alen) catch {
                self.skipped += 1;
                self.drop(1);
                continue;
            } orelse return null;
            if (self.len < want) return null;
            if (decode(self.buf[0..want], self.alen)) |f| {
                self.consumed = want;
                return f;
            } else |_| {
                self.rejected += 1;
                self.drop(1);
            }
        }
        return null;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "control field: primary and secondary bits, in both modes" {
    // Request status of link from a master: PRM, FC 9 -> 0x49.
    const req: Control = .{ .primary = true, .function = PrimaryFunction.request_status_of_link };
    try testing.expectEqual(@as(u8, 0x49), req.encode(.unbalanced));
    // Reset of remote link: 0x40; user data with confirmation and FCB/FCV: 0x73.
    try testing.expectEqual(@as(u8, 0x40), (Control{ .primary = true, .function = 0 }).encode(.unbalanced));
    const data: Control = .{ .primary = true, .fcb_acd = true, .fcv_dfc = true, .function = PrimaryFunction.user_data_confirm };
    try testing.expectEqual(@as(u8, 0x73), data.encode(.unbalanced));
    try testing.expectEqual(data, Control.decode(0x73, .unbalanced));
    // The secondary answer "status of link" with ACD and DFC clear: 0x0B; with ACD: 0x2B.
    try testing.expectEqual(@as(u8, 0x0B), (Control{ .primary = false, .function = SecondaryFunction.status_of_link }).encode(.unbalanced));
    try testing.expectEqual(@as(u8, 0x2B), (Control{ .primary = false, .fcb_acd = true, .function = 11 }).encode(.unbalanced));
    // DIR exists in balanced mode only.
    const dir: Control = .{ .primary = true, .dir = true, .function = 3 };
    try testing.expectEqual(@as(u8, 0xC3), dir.encode(.balanced));
    try testing.expectEqual(@as(u8, 0x43), dir.encode(.unbalanced));
    try testing.expect(Control.decode(0xC3, .balanced).dir);
    try testing.expect(!Control.decode(0xC3, .unbalanced).dir);
}

test "fixed frames (self-derived from the checksum rule): request status of link, reset, status answer" {
    var buf: [8]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{ 0x10, 0x49, 0x01, 0x4A, 0x16 }, try encodeFixed(&buf, .one, 0x49, 1));
    try testing.expectEqualSlices(u8, &.{ 0x10, 0x40, 0x01, 0x41, 0x16 }, try encodeFixed(&buf, .one, 0x40, 1));
    try testing.expectEqualSlices(u8, &.{ 0x10, 0x0B, 0x01, 0x0C, 0x16 }, try encodeFixed(&buf, .one, 0x0B, 1));
    // Two-octet address, little endian; the checksum covers both.
    try testing.expectEqualSlices(u8, &.{ 0x10, 0x49, 0x34, 0x12, 0x8F, 0x16 }, try encodeFixed(&buf, .two, 0x49, 0x1234));
    // No address at all (point to point).
    try testing.expectEqualSlices(u8, &.{ 0x10, 0x49, 0x49, 0x16 }, try encodeFixed(&buf, .none, 0x49, 0));
    const f = try decode(&.{ 0x10, 0x49, 0x34, 0x12, 0x8F, 0x16 }, .two);
    try testing.expectEqual(Frame{ .fixed = .{ .control = 0x49, .address = 0x1234 } }, f);
}

test "variable frame round trip, with the ASDU a 101 station would send" {
    // C_IC_NA_1 (general interrogation): type 100, one object, cause 6, CA 1, IOA 0, QOI 20.
    const asdu = [_]u8{ 0x64, 0x01, 0x06, 0x01, 0x00, 0x00, 0x14 };
    var buf: [32]u8 = undefined;
    const wire = try encodeVariable(&buf, .one, 0x73, 1, &asdu);
    // L = C + A + 7 = 9; CS = 0x73 + 0x01 + 0x64 + 0x01 + 0x06 + 0x01 + 0x14 = 0xF4.
    try testing.expectEqualSlices(u8, &.{ 0x68, 0x09, 0x09, 0x68, 0x73, 0x01, 0x64, 0x01, 0x06, 0x01, 0x00, 0x00, 0x14, 0xF4, 0x16 }, wire);
    const f = try decode(wire, .one);
    try testing.expectEqual(@as(u8, 0x73), f.variable.control);
    try testing.expectEqual(@as(u16, 1), f.variable.address);
    try testing.expectEqualSlices(u8, &asdu, f.variable.asdu);
    try testing.expectEqual(@as(?usize, wire.len), try frameLength(wire[0..4], .one));
}

test "single characters" {
    var buf: [1]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{0xE5}, try encodeSingle(&buf, false));
    try testing.expectEqualSlices(u8, &.{0xA2}, try encodeSingle(&buf, true));
    try testing.expectEqual(Frame{ .single = 0xE5 }, try decode(&.{0xE5}, .one));
}

test "decode refuses a bad checksum, end octet, repeated length, start octets and sizes" {
    const good = [_]u8{ 0x68, 0x04, 0x04, 0x68, 0x73, 0x01, 0xAA, 0xBB, 0xD9, 0x16 };
    _ = try decode(&good, .one);
    var bad = good;
    bad[8] ^= 1;
    try testing.expectError(error.BadChecksum, decode(&bad, .one));
    bad = good;
    bad[9] = 0x17;
    try testing.expectError(error.BadFrame, decode(&bad, .one));
    bad = good;
    bad[2] = 5;
    try testing.expectError(error.BadFrame, decode(&bad, .one));
    bad = good;
    bad[3] = 0x69;
    try testing.expectError(error.BadFrame, decode(&bad, .one));
    try testing.expectError(error.BadFrame, decode(&.{0x42}, .one));
    try testing.expectError(error.Truncated, decode(good[0..9], .one));
    try testing.expectError(error.BadFrame, decode(&(good ++ [_]u8{0}), .one));
    // L too small to hold the control field and the address.
    try testing.expectError(error.BadFrame, decode(&.{ 0x68, 0x01, 0x01, 0x68, 0x00, 0x00, 0x16 }, .one));
    try testing.expectError(error.Truncated, decode(&.{}, .one));
}

test "encoders refuse oversize input and an address that does not fit" {
    var big: [300]u8 = undefined;
    @memset(&big, 0);
    var out: [max_frame_len]u8 = undefined;
    // 1 + 1 + 253 = 255 fits, one more does not.
    _ = try encodeVariable(&out, .one, 0, 0, big[0..253]);
    try testing.expectError(error.TooLong, encodeVariable(&out, .one, 0, 0, big[0..254]));
    try testing.expectError(error.AddressOutOfRange, encodeFixed(&out, .one, 0, 256));
    try testing.expectError(error.AddressOutOfRange, encodeFixed(&out, .none, 0, 1));
    var tiny: [3]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, encodeFixed(&tiny, .one, 0, 1));
    try testing.expectError(error.BufferTooSmall, encodeVariable(&tiny, .one, 0, 1, &.{}));
}

test "framer: split input, back-to-back frames, noise and a bad frame in front of a good one" {
    var store: [max_frame_len * 2]u8 = undefined;
    var f = Framer.init(&store, .one);
    var fixed: [8]u8 = undefined;
    const status = try encodeFixed(&fixed, .one, 0x49, 1);
    var vbuf: [32]u8 = undefined;
    const data = try encodeVariable(&vbuf, .one, 0x73, 1, &.{ 1, 2, 3 });

    // Half a frame, then the rest.
    try f.feed(status[0..2]);
    try testing.expectEqual(@as(?Frame, null), f.next());
    try f.feed(status[2..]);
    try testing.expectEqual(Frame{ .fixed = .{ .control = 0x49, .address = 1 } }, f.next().?);
    try testing.expectEqual(@as(?Frame, null), f.next());

    // Noise, an ack char, a frame with a bad checksum, then a good frame.
    var bad: [8]u8 = undefined;
    @memcpy(bad[0..status.len], status);
    bad[3] ^= 0xFF;
    try f.feed(&.{ 0x00, 0x99 });
    try f.feed(&.{0xE5});
    try f.feed(bad[0..status.len]);
    try f.feed(data);
    try testing.expectEqual(Frame{ .single = 0xE5 }, f.next().?);
    const g = f.next().?;
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, g.variable.asdu);
    try testing.expect(f.skipped >= 2);
    try testing.expect(f.rejected >= 1);
    try testing.expectEqual(@as(?Frame, null), f.next());
    try testing.expectEqual(@as(usize, 0), f.len);
}

test "framer: a flood of garbage never fills it" {
    var store: [max_frame_len]u8 = undefined;
    var f = Framer.init(&store, .two);
    var junk: [64]u8 = undefined;
    @memset(&junk, 0x5A);
    for (0..100) |_| {
        try f.feed(&junk);
        try testing.expectEqual(@as(?Frame, null), f.next());
    }
    try testing.expectEqual(@as(usize, 0), f.len);
    try testing.expectEqual(@as(usize, 6400), f.skipped);
}
