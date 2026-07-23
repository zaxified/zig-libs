// SPDX-License-Identifier: MIT

//! COTP / ISO 8073 (X.224) class 0 — the connection-oriented transport TPDUs
//! that sit between TPKT and the ISO session layer.
//!
//! Three facts drive the code:
//!
//! * **`LI` counts the octets after itself, excluding user data.** That is what
//!   puts the session SPDU at offset `1 + LI` in a `DT`, and it is why a `DT`
//!   in class 0 always has `LI == 2`. A different value means the framing is
//!   already wrong, so it is refused rather than guessed at.
//! * **The variable part is order-independent and extensible.** One stack emits
//!   `size, called, calling`, another `size, calling, called`. The raw variable
//!   part is therefore kept alongside the parsed parameters, which is what makes
//!   `encodeConnectVerbatim` byte-exact for either.
//! * **Class 0 segments.** A response larger than the negotiated TPDU size
//!   arrives as several `DT`s with the EOT bit clear and one with it set. MMS
//!   PDUs routinely exceed 1024 octets (a `GetNameList` over a real IED's
//!   variables ran to 6675 in the captured traffic), so `Reassembler` exists
//!   and is not optional.
//!
//! Re-derived from the published ISO 8073 layout; this module takes no
//! dependency on the sibling `s7comm`, which needs the same layer.

const std = @import("std");

pub const Error = error{
    ShortTpdu,
    /// `LI` points past the octets present, or is zero.
    BadLengthIndicator,
    UnknownTpduCode,
    /// A transport class other than 0.
    UnsupportedClass,
    /// A `DT` whose `LI` is not the fixed class-0 value of 2.
    BadDataTpdu,
    /// A variable-part parameter whose length runs off the end.
    BadParameter,
    BufferTooSmall,
    /// More segments than the reassembly buffer can hold.
    ReassemblyOverflow,
};

pub const Code = enum(u8) {
    /// Connection request.
    cr = 0xE0,
    /// Connection confirm.
    cc = 0xD0,
    /// Disconnect request.
    dr = 0x80,
    /// Disconnect confirm.
    dc = 0xC0,
    /// Data.
    dt = 0xF0,
    /// Expedited data.
    ed = 0x10,
    /// TPDU error.
    er = 0x70,
    _,
};

/// Variable-part parameter codes.
pub const Param = struct {
    pub const tpdu_size: u8 = 0xC0;
    pub const calling_tsap: u8 = 0xC1;
    pub const called_tsap: u8 = 0xC2;
    pub const checksum: u8 = 0xC3;
    pub const version: u8 = 0xC4;
    pub const additional_option: u8 = 0xC6;
    pub const alternative_class: u8 = 0xC5;
};

/// The TPDU-size parameter is a log2 code, not an octet count. `0x0D` (8192)
/// is what every IEC 61850 stack observed here proposes.
pub const TpduSize = enum(u8) {
    b128 = 0x07,
    b256 = 0x08,
    b512 = 0x09,
    b1024 = 0x0A,
    b2048 = 0x0B,
    b4096 = 0x0C,
    b8192 = 0x0D,
    _,

    pub fn octets(self: TpduSize) usize {
        const code = @intFromEnum(self);
        if (code < 0x07 or code > 0x0D) return 0;
        return @as(usize, 1) << @intCast(code);
    }
};

/// Connection request / confirm. `variable_part` is kept raw so a decoded TPDU
/// re-encodes to the identical octets whatever order the peer used.
pub const Connect = struct {
    code: Code,
    dst_ref: u16,
    src_ref: u16,
    class_option: u8,
    variable_part: []const u8,
    /// Parsed conveniences; null when the peer omitted the parameter.
    tpdu_size: ?TpduSize = null,
    calling_tsap: ?[]const u8 = null,
    called_tsap: ?[]const u8 = null,

    pub fn class(self: Connect) u4 {
        return @truncate(self.class_option >> 4);
    }
};

pub const Data = struct {
    /// The class-0 TPDU number, always 0 in practice.
    number: u7,
    /// End of a segmented sequence.
    eot: bool,
    payload: []const u8,
};

pub const Disconnect = struct {
    dst_ref: u16,
    src_ref: u16,
    reason: u8,
    variable_part: []const u8,
};

pub const Tpdu = union(enum) {
    cr: Connect,
    cc: Connect,
    dt: Data,
    dr: Disconnect,
    dc: Disconnect,
    er: struct { dst_ref: u16, cause: u8, variable_part: []const u8 },
};

pub fn decode(bytes: []const u8) Error!Tpdu {
    if (bytes.len < 2) return error.ShortTpdu;
    const li: usize = bytes[0];
    if (li == 0) return error.BadLengthIndicator;
    if (bytes.len < li + 1) return error.BadLengthIndicator;
    const code: Code = @enumFromInt(bytes[1] & 0xF0);
    switch (code) {
        .cr, .cc => {
            // LI covers code + dst-ref + src-ref + class = 6 octets minimum.
            if (li < 6) return error.BadLengthIndicator;
            const dst_ref = std.mem.readInt(u16, bytes[2..4], .big);
            const src_ref = std.mem.readInt(u16, bytes[4..6], .big);
            const class_option = bytes[6];
            if (class_option >> 4 != 0) return error.UnsupportedClass;
            const vp = bytes[7 .. li + 1];
            var c = Connect{
                .code = code,
                .dst_ref = dst_ref,
                .src_ref = src_ref,
                .class_option = class_option,
                .variable_part = vp,
            };
            var it = ParamIterator{ .rest = vp };
            while (try it.next()) |p| {
                switch (p.code) {
                    Param.tpdu_size => if (p.value.len == 1) {
                        c.tpdu_size = @enumFromInt(p.value[0]);
                    },
                    Param.calling_tsap => c.calling_tsap = p.value,
                    Param.called_tsap => c.called_tsap = p.value,
                    else => {},
                }
            }
            return if (code == .cr) .{ .cr = c } else .{ .cc = c };
        },
        .dt => {
            // In class 0 the DT header is fixed: LI 2, code, then the
            // TPDU-number/EOT octet. Anything else is a framing error.
            if (li != 2) return error.BadDataTpdu;
            const n = bytes[2];
            return .{ .dt = .{
                .number = @truncate(n),
                .eot = n & 0x80 != 0,
                .payload = bytes[3..],
            } };
        },
        .dr, .dc => {
            if (li < 6) return error.BadLengthIndicator;
            const d = Disconnect{
                .dst_ref = std.mem.readInt(u16, bytes[2..4], .big),
                .src_ref = std.mem.readInt(u16, bytes[4..6], .big),
                .reason = bytes[6],
                .variable_part = bytes[7 .. li + 1],
            };
            return if (code == .dr) .{ .dr = d } else .{ .dc = d };
        },
        .er => {
            if (li < 4) return error.BadLengthIndicator;
            return .{ .er = .{
                .dst_ref = std.mem.readInt(u16, bytes[2..4], .big),
                .cause = bytes[4],
                .variable_part = bytes[5 .. li + 1],
            } };
        },
        else => return error.UnknownTpduCode,
    }
}

pub const Parameter = struct { code: u8, value: []const u8 };

pub const ParamIterator = struct {
    rest: []const u8,

    pub fn next(self: *ParamIterator) Error!?Parameter {
        if (self.rest.len == 0) return null;
        if (self.rest.len < 2) return error.BadParameter;
        const code = self.rest[0];
        const len: usize = self.rest[1];
        if (self.rest.len < 2 + len) return error.BadParameter;
        const value = self.rest[2 .. 2 + len];
        self.rest = self.rest[2 + len ..];
        return .{ .code = code, .value = value };
    }
};

/// Builds a CR/CC from parsed fields. Parameter order is `size, called,
/// calling` — the order both captured IEC 61850 stacks used.
pub fn encodeConnect(
    code: Code,
    dst_ref: u16,
    src_ref: u16,
    size: TpduSize,
    called_tsap: []const u8,
    calling_tsap: []const u8,
    out: []u8,
) Error![]u8 {
    const vp_len = 3 + 2 + called_tsap.len + 2 + calling_tsap.len;
    const li = 6 + vp_len;
    if (li > 254) return error.BufferTooSmall;
    if (out.len < li + 1) return error.BufferTooSmall;
    out[0] = @intCast(li);
    out[1] = @intFromEnum(code);
    std.mem.writeInt(u16, out[2..4], dst_ref, .big);
    std.mem.writeInt(u16, out[4..6], src_ref, .big);
    out[6] = 0x00; // class 0, no options
    var w: usize = 7;
    out[w] = Param.tpdu_size;
    out[w + 1] = 1;
    out[w + 2] = @intFromEnum(size);
    w += 3;
    out[w] = Param.called_tsap;
    out[w + 1] = @intCast(called_tsap.len);
    @memcpy(out[w + 2 ..][0..called_tsap.len], called_tsap);
    w += 2 + called_tsap.len;
    out[w] = Param.calling_tsap;
    out[w + 1] = @intCast(calling_tsap.len);
    @memcpy(out[w + 2 ..][0..calling_tsap.len], calling_tsap);
    w += 2 + calling_tsap.len;
    return out[0..w];
}

/// Rebuilds a CR/CC from a decoded one, preserving its variable part verbatim.
pub fn encodeConnectVerbatim(c: Connect, out: []u8) Error![]u8 {
    const li = 6 + c.variable_part.len;
    if (li > 254 or out.len < li + 1) return error.BufferTooSmall;
    out[0] = @intCast(li);
    out[1] = @intFromEnum(c.code);
    std.mem.writeInt(u16, out[2..4], c.dst_ref, .big);
    std.mem.writeInt(u16, out[4..6], c.src_ref, .big);
    out[6] = c.class_option;
    @memcpy(out[7..][0..c.variable_part.len], c.variable_part);
    return out[0 .. li + 1];
}

pub fn encodeData(payload: []const u8, eot: bool, out: []u8) Error![]u8 {
    if (out.len < 3 + payload.len) return error.BufferTooSmall;
    out[0] = 2;
    out[1] = @intFromEnum(Code.dt);
    out[2] = if (eot) 0x80 else 0x00;
    @memcpy(out[3..][0..payload.len], payload);
    return out[0 .. 3 + payload.len];
}

pub fn encodeDisconnect(dst_ref: u16, src_ref: u16, reason: u8, out: []u8) Error![]u8 {
    if (out.len < 7) return error.BufferTooSmall;
    out[0] = 6;
    out[1] = @intFromEnum(Code.dr);
    std.mem.writeInt(u16, out[2..4], dst_ref, .big);
    std.mem.writeInt(u16, out[4..6], src_ref, .big);
    out[6] = reason;
    return out[0..7];
}

/// Joins class-0 `DT` segments into one session PDU over caller-owned storage.
/// A peer that never sets EOT can only fill the buffer, never grow it.
pub const Reassembler = struct {
    buf: []u8,
    len: usize = 0,

    pub fn init(storage: []u8) Reassembler {
        return .{ .buf = storage };
    }

    pub fn reset(self: *Reassembler) void {
        self.len = 0;
    }

    /// Feeds one `DT`. Returns the complete SPDU when EOT was set, else null.
    pub fn push(self: *Reassembler, dt: Data) Error!?[]const u8 {
        if (self.len + dt.payload.len > self.buf.len) {
            self.len = 0;
            return error.ReassemblyOverflow;
        }
        @memcpy(self.buf[self.len..][0..dt.payload.len], dt.payload);
        self.len += dt.payload.len;
        if (!dt.eot) return null;
        const out = self.buf[0..self.len];
        self.len = 0;
        return out;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// The COTP connect request a real IEC 61850 client sent, captured on the wire.
const captured_cr = [_]u8{ 0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xC0, 0x01, 0x0D, 0xC2, 0x02, 0x00, 0x01, 0xC1, 0x02, 0x00, 0x01 };
const captured_cc = [_]u8{ 0x11, 0xD0, 0x00, 0x01, 0x00, 0x01, 0x00, 0xC0, 0x01, 0x0D, 0xC2, 0x02, 0x00, 0x01, 0xC1, 0x02, 0x00, 0x01 };

test "the captured connect request decodes field by field" {
    const cr = (try decode(&captured_cr)).cr;
    try testing.expectEqual(@as(u16, 0), cr.dst_ref);
    try testing.expectEqual(@as(u16, 1), cr.src_ref);
    try testing.expectEqual(@as(u4, 0), cr.class());
    try testing.expectEqual(TpduSize.b8192, cr.tpdu_size.?);
    try testing.expectEqual(@as(usize, 8192), cr.tpdu_size.?.octets());
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x01 }, cr.called_tsap.?);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x01 }, cr.calling_tsap.?);
}

test "the captured connect confirm decodes and re-encodes verbatim" {
    const cc = (try decode(&captured_cc)).cc;
    try testing.expectEqual(@as(u16, 1), cc.dst_ref);
    var out: [64]u8 = undefined;
    try testing.expectEqualSlices(u8, &captured_cc, try encodeConnectVerbatim(cc, &out));
}

test "encodeConnect reproduces the captured octets" {
    var out: [64]u8 = undefined;
    const built = try encodeConnect(.cr, 0, 1, .b8192, &[_]u8{ 0x00, 0x01 }, &[_]u8{ 0x00, 0x01 }, &out);
    try testing.expectEqualSlices(u8, &captured_cr, built);
}

test "data TPDUs round trip" {
    var out: [64]u8 = undefined;
    const built = try encodeData(&[_]u8{ 0x01, 0x00, 0x01, 0x00 }, true, &out);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0xF0, 0x80, 0x01, 0x00, 0x01, 0x00 }, built);
    const dt = (try decode(built)).dt;
    try testing.expect(dt.eot);
    try testing.expectEqual(@as(u7, 0), dt.number);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x00, 0x01, 0x00 }, dt.payload);

    const seg = try encodeData(&[_]u8{0xAA}, false, &out);
    try testing.expect(!(try decode(seg)).dt.eot);
}

test "malformed TPDUs are typed errors" {
    try testing.expectError(error.ShortTpdu, decode(&[_]u8{0x02}));
    try testing.expectError(error.BadLengthIndicator, decode(&[_]u8{ 0x00, 0xF0 }));
    // LI points past the buffer.
    try testing.expectError(error.BadLengthIndicator, decode(&[_]u8{ 0x20, 0xE0, 0x00 }));
    try testing.expectError(error.UnknownTpduCode, decode(&[_]u8{ 0x02, 0x20, 0x00 }));
    // A DT with LI != 2 in class 0.
    try testing.expectError(error.BadDataTpdu, decode(&[_]u8{ 0x03, 0xF0, 0x80, 0x00 }));
    // A CR whose LI does not cover the fixed part.
    try testing.expectError(error.BadLengthIndicator, decode(&[_]u8{ 0x05, 0xE0, 0x00, 0x00, 0x00, 0x01 }));
    // Class 4 is refused, not silently treated as class 0.
    try testing.expectError(error.UnsupportedClass, decode(&[_]u8{ 0x06, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x40 }));
}

test "a variable-part parameter that runs off the end is refused" {
    var bytes = captured_cr;
    bytes[8] = 0x20; // TPDU-size parameter claims 32 octets
    const cr = decode(&bytes);
    try testing.expectError(error.BadParameter, cr);
}

test "a dangling parameter code is refused" {
    var bytes: [8]u8 = .{ 0x07, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xC0 };
    try testing.expectError(error.BadParameter, decode(&bytes));
}

test "reassembly joins segments and refuses to grow" {
    var storage: [8]u8 = undefined;
    var r = Reassembler.init(&storage);
    try testing.expect((try r.push(.{ .number = 0, .eot = false, .payload = &[_]u8{ 1, 2, 3 } })) == null);
    const done = (try r.push(.{ .number = 0, .eot = true, .payload = &[_]u8{ 4, 5 } })).?;
    try testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4, 5 }, done);

    // A peer that never sets EOT fills the buffer and then errors.
    var r2 = Reassembler.init(&storage);
    _ = try r2.push(.{ .number = 0, .eot = false, .payload = &[_]u8{0} ** 8 });
    try testing.expectError(error.ReassemblyOverflow, r2.push(.{ .number = 0, .eot = false, .payload = &[_]u8{0} }));
}

test "disconnect round trips" {
    var out: [16]u8 = undefined;
    const dr = try encodeDisconnect(1, 2, 0x80, &out);
    const d = (try decode(dr)).dr;
    try testing.expectEqual(@as(u16, 1), d.dst_ref);
    try testing.expectEqual(@as(u16, 2), d.src_ref);
    try testing.expectEqual(@as(u8, 0x80), d.reason);
}

test "fuzz: cotp decode never panics" {
    try std.testing.fuzz({}, fuzzDecode, .{});
}

fn fuzzDecode(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const t = decode(buf[0..len]) catch return;
    var out: [1024]u8 = undefined;
    switch (t) {
        .cr, .cc => |c| {
            const again = try encodeConnectVerbatim(c, &out);
            try testing.expectEqualSlices(u8, buf[0..again.len], again);
        },
        .dt => |d| {
            const again = try encodeData(d.payload, d.eot, &out);
            try testing.expectEqualSlices(u8, buf[0..again.len], again);
        },
        else => {},
    }
}
