// SPDX-License-Identifier: MIT

//! COTP — the ISO 8073 / X.224 **class 0** connection-oriented transport
//! protocol, as RFC 1006 carries it over TCP. This is the layer between
//! `tpkt` and `s7`.
//!
//! Class 0 is a deliberately tiny subset: connect (`CR`), confirm (`CC`),
//! data (`DT`), disconnect (`DR`/`DC`) and error (`ER`). There is no
//! retransmission, no flow control and no checksum — TCP already provides all
//! of that, which is the whole point of RFC 1006.
//!
//! ```text
//! CR/CC:  LI code DST-REF(2) SRC-REF(2) class/option  [ params... ]
//! DT:     LI 0xF0 TPDU-NR|EOT                          user data...
//! DR:     LI 0x80 DST-REF(2) SRC-REF(2) reason         [ params... ]
//! ER:     LI 0x70 DST-REF(2) reject-cause              [ params... ]
//! ```
//!
//! **`LI` counts the octets after itself, excluding user data.** For a `DT`
//! that is always 2 (the code octet and the TPDU-NR octet); everything past
//! `LI + 1` is the S7 PDU. Getting this wrong is how a decoder ends up
//! handing the S7 layer a payload that starts one octet late.
//!
//! ## Rack and slot live inside the destination TSAP
//!
//! There is no "rack" or "slot" field anywhere in S7. The addressing everyone
//! means by *rack 0, slot 2* is encoded in the two-octet **destination TSAP**
//! carried in the `CR`:
//!
//! ```text
//!   +--------------------+--------------------------+
//!   | connection type    | rack * 0x20 + slot       |
//!   |  0x01 PG           |  rack in bits 7..5       |
//!   |  0x02 OP           |  slot in bits 4..0       |
//!   |  0x03 S7 basic     |                          |
//!   +--------------------+--------------------------+
//! ```
//!
//! A wrong slot does not produce an error message anywhere in the S7 layer:
//! the PLC simply refuses the transport connection (or, worse, some CPUs
//! accept it and then fail every read), which is why `Tsap` models this
//! explicitly rather than leaving callers to hand-pack two octets.

const std = @import("std");

pub const Error = error{
    /// Fewer octets than the smallest legal TPDU.
    ShortTpdu,
    /// The length indicator points past the end of the buffer.
    BadLengthIndicator,
    /// The TPDU code is not one this class-0 implementation knows.
    UnknownTpduCode,
    /// A CR/CC named a transport class other than 0.
    UnsupportedClass,
    /// A variable-part parameter's length runs past the end of the TPDU.
    BadParameter,
    /// A TSAP parameter whose length is not 2 octets.
    BadTsapLength,
    /// A TPDU-size parameter whose length is not 1 octet.
    BadTpduSizeLength,
    /// A DT carried a length indicator other than 2.
    BadDataTpdu,
    /// The caller's output buffer is too small.
    BufferTooSmall,
    /// The caller's variable part does not fit a length indicator.
    VariablePartTooLong,
};

/// TPDU codes. Only class-0 codes are modelled; the enum is non-exhaustive so
/// an unknown code decodes to a value with no name rather than being guessed.
pub const Code = enum(u8) {
    er = 0x70,
    dr = 0x80,
    dc = 0xC0,
    cc = 0xD0,
    cr = 0xE0,
    dt = 0xF0,
    _,
};

/// Variable-part parameter codes seen in practice on S7 links.
pub const ParamCode = enum(u8) {
    tpdu_size = 0xC0,
    src_tsap = 0xC1,
    dst_tsap = 0xC2,
    checksum = 0xC3,
    version = 0xC4,
    /// Additional option selection.
    additional_option = 0xC6,
    alternative_protocol = 0xC7,
    _,
};

/// TPDU size, carried as a base-2 logarithm in parameter `0xC0`.
/// Class 0 over RFC 1006 tops out at 2048.
pub const TpduSize = enum(u8) {
    size_128 = 0x07,
    size_256 = 0x08,
    size_512 = 0x09,
    size_1024 = 0x0A,
    size_2048 = 0x0B,
    _,

    pub fn bytes(self: TpduSize) ?u32 {
        return switch (@intFromEnum(self)) {
            0x07...0x0D => @as(u32, 1) << @intCast(@intFromEnum(self)),
            else => null,
        };
    }
};

/// The connection type in the high octet of a TSAP.
pub const ConnectionType = enum(u8) {
    /// Programming device (STEP 7). What most tools and this client use.
    pg = 0x01,
    /// Operator panel (HMI).
    op = 0x02,
    /// "S7 basic" / other communication.
    s7_basic = 0x03,
    _,
};

/// A two-octet transport service access point.
///
/// For an S7-300/400 the destination TSAP is `{connection type, rack*0x20 +
/// slot}`. S7-1200/1500 CPUs accept the same shape with rack 0 and slot 0 or
/// 1, and some configurations use raw values (e.g. `0x1000`) — hence `raw`.
pub const Tsap = struct {
    value: u16,

    /// The rack/slot form: `{conn, rack * 0x20 + slot}`.
    /// Rack is 3 bits (0..7), slot is 5 bits (0..31).
    pub fn rackSlot(conn: ConnectionType, rack_no: u3, slot_no: u5) Tsap {
        const low: u16 = (@as(u16, rack_no) * 0x20) + @as(u16, slot_no);
        return .{ .value = (@as(u16, @intFromEnum(conn)) << 8) | low };
    }

    /// Any two-octet value, for CPUs configured with a non-rack/slot TSAP.
    pub fn raw(v: u16) Tsap {
        return .{ .value = v };
    }

    pub fn connectionType(self: Tsap) ConnectionType {
        return @enumFromInt(@as(u8, @intCast(self.value >> 8)));
    }

    pub fn rack(self: Tsap) u3 {
        return @intCast((self.value >> 5) & 0x07);
    }

    pub fn slot(self: Tsap) u5 {
        return @intCast(self.value & 0x1F);
    }
};

/// A decoded CR or CC.
pub const ConnectTpdu = struct {
    code: Code,
    /// Credit (CDT) in the low nibble of the code octet. Always 0 in class 0.
    credit: u4 = 0,
    dst_ref: u16,
    src_ref: u16,
    /// Transport class; only 0 is supported here.
    class: u4 = 0,
    extended_formats: bool = false,
    no_explicit_flow_control: bool = false,
    src_tsap: ?Tsap = null,
    dst_tsap: ?Tsap = null,
    tpdu_size: ?TpduSize = null,
    /// The raw variable part, so unknown parameters survive a decode.
    variable_part: []const u8 = &.{},
};

/// A decoded DT.
pub const DataTpdu = struct {
    /// 7-bit TPDU send sequence number. Class 0 never uses it (it is always
    /// 0), but it is on the wire so it is modelled.
    number: u7 = 0,
    /// End-of-TSDU marker. Class 0 senders always set it; a peer that clears
    /// it is fragmenting, which this implementation refuses to reassemble.
    eot: bool = true,
    payload: []const u8,
};

/// A decoded DR.
pub const DisconnectTpdu = struct {
    dst_ref: u16,
    src_ref: u16,
    reason: u8,
};

/// A decoded ER.
pub const ErrorTpdu = struct {
    dst_ref: u16,
    reject_cause: u8,
};

/// Any class-0 TPDU, plus how many octets it consumed.
pub const Tpdu = union(enum) {
    cr: ConnectTpdu,
    cc: ConnectTpdu,
    dt: DataTpdu,
    dr: DisconnectTpdu,
    dc: DisconnectTpdu,
    er: ErrorTpdu,
};

/// A parameter in a CR/CC variable part.
pub const Parameter = struct {
    code: u8,
    value: []const u8,
};

/// Walks the `(code, length, value)` triples of a variable part.
pub const ParameterIterator = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn next(self: *ParameterIterator) Error!?Parameter {
        if (self.pos == self.bytes.len) return null;
        if (self.pos + 2 > self.bytes.len) return error.BadParameter;
        const code = self.bytes[self.pos];
        const len: usize = self.bytes[self.pos + 1];
        if (self.pos + 2 + len > self.bytes.len) return error.BadParameter;
        const value = self.bytes[self.pos + 2 ..][0..len];
        self.pos += 2 + len;
        return .{ .code = code, .value = value };
    }
};

fn be16(b: []const u8) u16 {
    return (@as(u16, b[0]) << 8) | b[1];
}

/// Decodes one TPDU from the payload of a TPKT.
///
/// `bytes` must be exactly one TPKT payload: for a `DT`, everything past the
/// length indicator is the user data, so a caller that hands over two
/// concatenated TPDUs gets the second one folded into the first's payload.
pub fn decode(bytes: []const u8) Error!Tpdu {
    if (bytes.len < 2) return error.ShortTpdu;
    const li: usize = bytes[0];
    if (li < 1) return error.BadLengthIndicator;
    // LI counts the octets after itself, user data excluded.
    if (1 + li > bytes.len) return error.BadLengthIndicator;
    const raw_code = bytes[1];
    const header = bytes[1 .. 1 + li];

    switch (raw_code & 0xF0) {
        @intFromEnum(Code.cr), @intFromEnum(Code.cc) => {
            if (header.len < 6) return error.ShortTpdu;
            const class_octet = header[5];
            const class: u4 = @intCast(class_octet >> 4);
            if (class != 0) return error.UnsupportedClass;
            var t: ConnectTpdu = .{
                .code = @enumFromInt(raw_code & 0xF0),
                .credit = @intCast(raw_code & 0x0F),
                .dst_ref = be16(header[1..3]),
                .src_ref = be16(header[3..5]),
                .class = class,
                .extended_formats = (class_octet & 0x02) != 0,
                .no_explicit_flow_control = (class_octet & 0x01) != 0,
                .variable_part = header[6..],
            };
            var it = ParameterIterator{ .bytes = t.variable_part };
            while (try it.next()) |p| switch (p.code) {
                @intFromEnum(ParamCode.src_tsap) => {
                    if (p.value.len != 2) return error.BadTsapLength;
                    t.src_tsap = Tsap.raw(be16(p.value));
                },
                @intFromEnum(ParamCode.dst_tsap) => {
                    if (p.value.len != 2) return error.BadTsapLength;
                    t.dst_tsap = Tsap.raw(be16(p.value));
                },
                @intFromEnum(ParamCode.tpdu_size) => {
                    if (p.value.len != 1) return error.BadTpduSizeLength;
                    t.tpdu_size = @enumFromInt(p.value[0]);
                },
                else => {},
            };
            return if ((raw_code & 0xF0) == @intFromEnum(Code.cr))
                .{ .cr = t }
            else
                .{ .cc = t };
        },
        @intFromEnum(Code.dt) => {
            // Class 0 fixes LI at 2: the code octet and the TPDU-NR octet.
            if (li != 2) return error.BadDataTpdu;
            const nr = header[1];
            return .{ .dt = .{
                .number = @intCast(nr & 0x7F),
                .eot = (nr & 0x80) != 0,
                .payload = bytes[1 + li ..],
            } };
        },
        @intFromEnum(Code.dr) => {
            if (header.len < 6) return error.ShortTpdu;
            return .{ .dr = .{
                .dst_ref = be16(header[1..3]),
                .src_ref = be16(header[3..5]),
                .reason = header[5],
            } };
        },
        @intFromEnum(Code.dc) => {
            if (header.len < 5) return error.ShortTpdu;
            return .{ .dc = .{
                .dst_ref = be16(header[1..3]),
                .src_ref = be16(header[3..5]),
                .reason = 0,
            } };
        },
        @intFromEnum(Code.er) => {
            if (header.len < 4) return error.ShortTpdu;
            return .{ .er = .{
                .dst_ref = be16(header[1..3]),
                .reject_cause = header[3],
            } };
        },
        else => return error.UnknownTpduCode,
    }
}

fn putTsap(out: []u8, code: u8, t: Tsap) usize {
    out[0] = code;
    out[1] = 2;
    out[2] = @intCast(t.value >> 8);
    out[3] = @intCast(t.value & 0xFF);
    return 4;
}

/// Encodes a CR or CC. Parameters are emitted in the order
/// `tpdu_size, src_tsap, dst_tsap`, which is what the reference C stack does;
/// other stacks use other orders and all of them decode.
pub fn encodeConnect(t: ConnectTpdu, out: []u8) Error![]u8 {
    var var_part: [16]u8 = undefined;
    var vlen: usize = 0;
    if (t.tpdu_size) |sz| {
        var_part[vlen] = @intFromEnum(ParamCode.tpdu_size);
        var_part[vlen + 1] = 1;
        var_part[vlen + 2] = @intFromEnum(sz);
        vlen += 3;
    }
    if (t.src_tsap) |s| vlen += putTsap(var_part[vlen..], @intFromEnum(ParamCode.src_tsap), s);
    if (t.dst_tsap) |d| vlen += putTsap(var_part[vlen..], @intFromEnum(ParamCode.dst_tsap), d);

    const li = 6 + vlen;
    if (li > 254) return error.VariablePartTooLong;
    if (out.len < 1 + li) return error.BufferTooSmall;
    out[0] = @intCast(li);
    out[1] = @intFromEnum(t.code) | @as(u8, t.credit);
    out[2] = @intCast(t.dst_ref >> 8);
    out[3] = @intCast(t.dst_ref & 0xFF);
    out[4] = @intCast(t.src_ref >> 8);
    out[5] = @intCast(t.src_ref & 0xFF);
    out[6] = (@as(u8, t.class) << 4) |
        (@as(u8, @intFromBool(t.extended_formats)) << 1) |
        @intFromBool(t.no_explicit_flow_control);
    @memcpy(out[7..][0..vlen], var_part[0..vlen]);
    return out[0 .. 1 + li];
}

/// Encodes a CR/CC re-using an already-decoded variable part verbatim, so a
/// decode/encode round trip is byte-exact regardless of parameter order.
pub fn encodeConnectVerbatim(t: ConnectTpdu, out: []u8) Error![]u8 {
    const li = 6 + t.variable_part.len;
    if (li > 254) return error.VariablePartTooLong;
    if (out.len < 1 + li) return error.BufferTooSmall;
    out[0] = @intCast(li);
    out[1] = @intFromEnum(t.code) | @as(u8, t.credit);
    out[2] = @intCast(t.dst_ref >> 8);
    out[3] = @intCast(t.dst_ref & 0xFF);
    out[4] = @intCast(t.src_ref >> 8);
    out[5] = @intCast(t.src_ref & 0xFF);
    out[6] = (@as(u8, t.class) << 4) |
        (@as(u8, @intFromBool(t.extended_formats)) << 1) |
        @intFromBool(t.no_explicit_flow_control);
    @memcpy(out[7..][0..t.variable_part.len], t.variable_part);
    return out[0 .. 1 + li];
}

/// The three-octet DT header that prefixes every S7 PDU.
pub fn dataHeader(number: u7, eot: bool) [3]u8 {
    return .{ 0x02, @intFromEnum(Code.dt), (@as(u8, @intFromBool(eot)) << 7) | @as(u8, number) };
}

/// Encodes a DT carrying `payload`.
pub fn encodeData(t: DataTpdu, out: []u8) Error![]u8 {
    if (out.len < 3 + t.payload.len) return error.BufferTooSmall;
    @memcpy(out[0..3], &dataHeader(t.number, t.eot));
    @memcpy(out[3..][0..t.payload.len], t.payload);
    return out[0 .. 3 + t.payload.len];
}

/// Encodes a DR.
pub fn encodeDisconnect(t: DisconnectTpdu, out: []u8) Error![]u8 {
    if (out.len < 7) return error.BufferTooSmall;
    out[0] = 6;
    out[1] = @intFromEnum(Code.dr);
    out[2] = @intCast(t.dst_ref >> 8);
    out[3] = @intCast(t.dst_ref & 0xFF);
    out[4] = @intCast(t.src_ref >> 8);
    out[5] = @intCast(t.src_ref & 0xFF);
    out[6] = t.reason;
    return out[0..7];
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "rack/slot lives in the low octet of the destination TSAP" {
    // The classic values every S7 tool shows.
    try testing.expectEqual(@as(u16, 0x0100), Tsap.rackSlot(.pg, 0, 0).value);
    try testing.expectEqual(@as(u16, 0x0101), Tsap.rackSlot(.pg, 0, 1).value);
    try testing.expectEqual(@as(u16, 0x0102), Tsap.rackSlot(.pg, 0, 2).value);
    // rack 1, slot 2 -> 1 * 0x20 + 2 = 0x22.
    try testing.expectEqual(@as(u16, 0x0122), Tsap.rackSlot(.pg, 1, 2).value);
    // rack 2, slot 4 -> 0x44.
    try testing.expectEqual(@as(u16, 0x0144), Tsap.rackSlot(.pg, 2, 4).value);
    // An OP (HMI) connection to rack 0 slot 1.
    try testing.expectEqual(@as(u16, 0x0201), Tsap.rackSlot(.op, 0, 1).value);

    const t = Tsap.rackSlot(.pg, 3, 17);
    try testing.expectEqual(ConnectionType.pg, t.connectionType());
    try testing.expectEqual(@as(u3, 3), t.rack());
    try testing.expectEqual(@as(u5, 17), t.slot());
    // The maximum representable rack/slot.
    const m = Tsap.rackSlot(.pg, 7, 31);
    try testing.expectEqual(@as(u16, 0x01FF), m.value);
    try testing.expectEqual(@as(u3, 7), m.rack());
    try testing.expectEqual(@as(u5, 31), m.slot());
}

test "CR round trip with all three parameters" {
    const cr: ConnectTpdu = .{
        .code = .cr,
        .dst_ref = 0,
        .src_ref = 1,
        .src_tsap = Tsap.rackSlot(.pg, 0, 0),
        .dst_tsap = Tsap.rackSlot(.pg, 0, 1),
        .tpdu_size = .size_1024,
    };
    var buf: [64]u8 = undefined;
    const enc = try encodeConnect(cr, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{
        0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00,
        0xC0, 0x01, 0x0A, 0xC1, 0x02, 0x01, 0x00,
        0xC2, 0x02, 0x01, 0x01,
    }, enc);

    const dec = (try decode(enc)).cr;
    try testing.expectEqual(@as(u16, 0), dec.dst_ref);
    try testing.expectEqual(@as(u16, 1), dec.src_ref);
    try testing.expectEqual(@as(u16, 0x0100), dec.src_tsap.?.value);
    try testing.expectEqual(@as(u16, 0x0101), dec.dst_tsap.?.value);
    try testing.expectEqual(TpduSize.size_1024, dec.tpdu_size.?);
    try testing.expectEqual(@as(u32, 1024), dec.tpdu_size.?.bytes().?);
}

test "DT header and payload" {
    const payload = [_]u8{ 0x32, 0x01, 0x00, 0x00 };
    var buf: [16]u8 = undefined;
    const enc = try encodeData(.{ .payload = &payload }, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0xF0, 0x80, 0x32, 0x01, 0x00, 0x00 }, enc);
    const dec = (try decode(enc)).dt;
    try testing.expect(dec.eot);
    try testing.expectEqual(@as(u7, 0), dec.number);
    try testing.expectEqualSlices(u8, &payload, dec.payload);

    // A fragmenting peer: EOT clear, TPDU number 3.
    const frag = [_]u8{ 0x02, 0xF0, 0x03, 0xAA };
    const d2 = (try decode(&frag)).dt;
    try testing.expect(!d2.eot);
    try testing.expectEqual(@as(u7, 3), d2.number);
}

test "DR round trip" {
    var buf: [16]u8 = undefined;
    const enc = try encodeDisconnect(.{ .dst_ref = 1, .src_ref = 2, .reason = 0 }, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x06, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00 }, enc);
    const dec = (try decode(enc)).dr;
    try testing.expectEqual(@as(u16, 1), dec.dst_ref);
    try testing.expectEqual(@as(u16, 2), dec.src_ref);
}

test "ER decodes its reject cause" {
    const er = [_]u8{ 0x04, 0x70, 0x00, 0x01, 0x01 };
    const dec = (try decode(&er)).er;
    try testing.expectEqual(@as(u16, 1), dec.dst_ref);
    try testing.expectEqual(@as(u8, 1), dec.reject_cause);
}

test "decode rejects hostile TPDUs" {
    try testing.expectError(error.ShortTpdu, decode(&[_]u8{}));
    try testing.expectError(error.ShortTpdu, decode(&[_]u8{0x02}));
    // LI points past the buffer.
    try testing.expectError(error.BadLengthIndicator, decode(&[_]u8{ 0x7F, 0xE0, 0x00 }));
    try testing.expectError(error.BadLengthIndicator, decode(&[_]u8{ 0xFF, 0xF0, 0x80, 0x32 }));
    // LI of zero.
    try testing.expectError(error.BadLengthIndicator, decode(&[_]u8{ 0x00, 0xF0 }));
    // Unknown code.
    try testing.expectError(error.UnknownTpduCode, decode(&[_]u8{ 0x02, 0x10, 0x00 }));
    // Class 4 in a CR.
    try testing.expectError(error.UnsupportedClass, decode(&[_]u8{ 0x06, 0xE0, 0, 0, 0, 1, 0x40 }));
    // A CR whose LI does not even cover the fixed part.
    try testing.expectError(error.ShortTpdu, decode(&[_]u8{ 0x03, 0xE0, 0x00, 0x00 }));
    // A DT with LI other than 2.
    try testing.expectError(error.BadDataTpdu, decode(&[_]u8{ 0x03, 0xF0, 0x80, 0x00 }));
    // A TSAP parameter of the wrong length.
    try testing.expectError(error.BadTsapLength, decode(&[_]u8{ 0x0B, 0xE0, 0, 0, 0, 1, 0, 0xC1, 0x03, 1, 2, 3 }));
    // A TPDU-size parameter of the wrong length.
    try testing.expectError(error.BadTpduSizeLength, decode(&[_]u8{ 0x0B, 0xE0, 0, 0, 0, 1, 0, 0xC0, 0x03, 1, 2, 3 }));
    // A parameter whose length runs off the end of the variable part.
    try testing.expectError(error.BadParameter, decode(&[_]u8{ 0x09, 0xE0, 0, 0, 0, 1, 0, 0xC1, 0x40, 1, 2, 3 }));
    // A dangling parameter code with no length octet.
    try testing.expectError(error.BadParameter, decode(&[_]u8{ 0x07, 0xE0, 0, 0, 0, 1, 0, 0xC1 }));
}

test "verbatim re-encode preserves an unusual parameter order" {
    // Parameter order src, dst, size — a different stack's choice.
    const wire = [_]u8{
        0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00,
        0xC1, 0x02, 0x01, 0x00, 0xC2, 0x02, 0x01,
        0x01, 0xC0, 0x01, 0x0A,
    };
    const dec = (try decode(&wire)).cr;
    try testing.expectEqual(@as(u16, 0x0101), dec.dst_tsap.?.value);
    var buf: [64]u8 = undefined;
    try testing.expectEqualSlices(u8, &wire, try encodeConnectVerbatim(dec, &buf));
    // The canonical encoder reorders, so it is *not* byte-equal.
    try testing.expect(!std.mem.eql(u8, &wire, try encodeConnect(dec, &buf)));
}

test "TpduSize.bytes maps only the defined codes" {
    try testing.expectEqual(@as(u32, 128), TpduSize.size_128.bytes().?);
    try testing.expectEqual(@as(u32, 2048), TpduSize.size_2048.bytes().?);
    try testing.expect(@as(TpduSize, @enumFromInt(0x00)).bytes() == null);
    try testing.expect(@as(TpduSize, @enumFromInt(0xFF)).bytes() == null);
}

test "fuzz: cotp decode never panics" {
    try std.testing.fuzz({}, fuzzDecode, .{});
}

fn fuzzDecode(_: void, smith: *std.testing.Smith) !void {
    var buf: [300]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const t = decode(buf[0..len]) catch return;
    var round: [512]u8 = undefined;
    switch (t) {
        .cr, .cc => |c| {
            // Whatever decoded must re-encode verbatim to the same octets.
            const again = try encodeConnectVerbatim(c, &round);
            try testing.expectEqualSlices(u8, buf[0 .. 1 + @as(usize, buf[0])], again);
        },
        .dt => |d| {
            const again = try encodeData(d, &round);
            try testing.expectEqualSlices(u8, buf[0..len], again);
        },
        else => {},
    }
}
