// SPDX-License-Identifier: MIT

//! ASDU — the Application Service Data Unit of IEC 60870-5-101/-104
//! (IEC 60870-5-101 §7.2), i.e. everything an I-format APDU carries after the
//! six APCI octets:
//!
//! ```text
//!   +---------+-----+-----+-----+-----+ - - - - - - - - - - - - - - +
//!   | type id | VSQ | COT | OA  | CA  |   information objects       |
//!   +---------+-----+-----+-----+-----+ - - - - - - - - - - - - - - +
//!      1        1     1     0/1   1/2
//! ```
//!
//! The first five fields are the *data unit identifier*:
//!
//! * **type id** — what the objects are (`M_SP_NA_1`, `C_SC_NA_1`, …).
//! * **VSQ** — variable structure qualifier: a 7-bit object count plus the
//!   **SQ bit**, which changes the object layout completely. `SQ = 0` means
//!   *count* objects each preceded by its own information-object address;
//!   `SQ = 1` means *one* address followed by *count* bare elements whose
//!   addresses run consecutively from it.
//! * **COT** — cause of transmission: a 6-bit cause plus the **P/N** bit
//!   (negative confirmation) and the **T** bit (test), optionally followed by
//!   a one-octet originator address.
//! * **CA** — common address of the ASDU (the station address).
//!
//! **Address sizing is per system, not per standard.** The information-object
//! address is 1..3 octets, the common address 1..2, and the originator octet
//! is present or absent. They live in `Params`, which every codec entry point
//! takes; `default_params` is the 3/2/with-originator profile that IEC
//! 60870-5-104 §7.1 fixes for the TCP/IP profile and that every deployment we
//! have seen uses. Nothing here bakes those numbers in.
//!
//! Pure functions over byte slices: no allocation, no I/O, no clock.

const std = @import("std");
const info = @import("info.zig");

// ── system parameters ───────────────────────────────────────────────────────

/// A `Params` value with an impossible field width.
pub const ParamsError = error{InvalidParams};

/// Per-system field widths (IEC 60870-5-101 §7.1, IEC 60870-5-104 §7.1).
pub const Params = struct {
    /// Octets of the information-object address: 1, 2 or 3.
    ioa_size: u8 = 3,
    /// Octets of the common address of ASDU: 1 or 2.
    ca_size: u8 = 2,
    /// Octets of the cause of transmission: 1 (cause only) or 2 (cause plus a
    /// one-octet originator address).
    cot_size: u8 = 2,

    pub fn validate(self: Params) ParamsError!void {
        if (self.ioa_size < 1 or self.ioa_size > 3) return error.InvalidParams;
        if (self.ca_size < 1 or self.ca_size > 2) return error.InvalidParams;
        if (self.cot_size < 1 or self.cot_size > 2) return error.InvalidParams;
    }

    /// Octets of the data unit identifier for these parameters.
    pub fn headerLen(self: Params) usize {
        return 2 + @as(usize, self.cot_size) + @as(usize, self.ca_size);
    }

    /// True when the originator address octet is on the wire.
    pub fn hasOriginator(self: Params) bool {
        return self.cot_size == 2;
    }

    /// Largest information-object address these parameters can express.
    pub fn maxIoa(self: Params) u32 {
        return switch (self.ioa_size) {
            1 => 0xFF,
            2 => 0xFFFF,
            else => 0xFF_FFFF,
        };
    }

    /// Largest common address these parameters can express. Note that the
    /// all-ones value is reserved as the broadcast address.
    pub fn maxCa(self: Params) u16 {
        return if (self.ca_size == 1) 0xFF else 0xFFFF;
    }

    /// The broadcast common address for these parameters (all bits set) —
    /// §7.2.4: an ASDU addressed to it is for every station on the link.
    pub fn broadcastCa(self: Params) u16 {
        return self.maxCa();
    }
};

/// The IEC 60870-5-104 profile: 3-octet IOA, 2-octet CA, originator present.
pub const default_params = Params{};

// ── type identification ─────────────────────────────────────────────────────

/// Type identification (§7.2.1 and the type list in IEC 60870-5-101 §7.2.1.1 /
/// IEC 60870-5-104 Annex A). Non-exhaustive: an unknown wire byte still
/// decodes into a `TypeId`, it just has no name — the codec then refuses it
/// with `error.UnsupportedTypeId` rather than guessing an element size.
pub const TypeId = enum(u8) {
    // monitoring — process information in the monitor direction
    m_sp_na_1 = 1, // single-point information
    m_sp_ta_1 = 2, // single-point with CP24Time2a
    m_dp_na_1 = 3, // double-point information
    m_dp_ta_1 = 4, // double-point with CP24Time2a
    m_st_na_1 = 5, // step position
    m_st_ta_1 = 6, // step position with CP24Time2a
    m_bo_na_1 = 7, // 32-bit bitstring
    m_bo_ta_1 = 8, // 32-bit bitstring with CP24Time2a
    m_me_na_1 = 9, // measured value, normalised
    m_me_ta_1 = 10, // measured value, normalised, with CP24Time2a
    m_me_nb_1 = 11, // measured value, scaled
    m_me_tb_1 = 12, // measured value, scaled, with CP24Time2a
    m_me_nc_1 = 13, // measured value, short float
    m_me_tc_1 = 14, // measured value, short float, with CP24Time2a
    m_it_na_1 = 15, // integrated totals
    m_it_ta_1 = 16, // integrated totals with CP24Time2a
    m_ps_na_1 = 20, // packed single-point with status change detection
    m_me_nd_1 = 21, // measured value, normalised, without quality
    m_sp_tb_1 = 30, // single-point with CP56Time2a
    m_dp_tb_1 = 31, // double-point with CP56Time2a
    m_st_tb_1 = 32, // step position with CP56Time2a
    m_bo_tb_1 = 33, // bitstring with CP56Time2a
    m_me_td_1 = 34, // measured value, normalised, with CP56Time2a
    m_me_te_1 = 35, // measured value, scaled, with CP56Time2a
    m_me_tf_1 = 36, // measured value, short float, with CP56Time2a
    m_it_tb_1 = 37, // integrated totals with CP56Time2a

    // control — process information in the control direction
    c_sc_na_1 = 45, // single command
    c_dc_na_1 = 46, // double command
    c_rc_na_1 = 47, // regulating step command
    c_se_na_1 = 48, // set-point command, normalised
    c_se_nb_1 = 49, // set-point command, scaled
    c_se_nc_1 = 50, // set-point command, short float
    c_bo_na_1 = 51, // 32-bit bitstring command
    c_sc_ta_1 = 58, // single command with CP56Time2a
    c_dc_ta_1 = 59, // double command with CP56Time2a
    c_rc_ta_1 = 60, // regulating step command with CP56Time2a
    c_se_ta_1 = 61, // set-point, normalised, with CP56Time2a
    c_se_tb_1 = 62, // set-point, scaled, with CP56Time2a
    c_se_tc_1 = 63, // set-point, short float, with CP56Time2a
    c_bo_ta_1 = 64, // bitstring command with CP56Time2a

    // system information
    m_ei_na_1 = 70, // end of initialisation
    c_ic_na_1 = 100, // (general) interrogation command
    c_ci_na_1 = 101, // counter interrogation command
    c_rd_na_1 = 102, // read command
    c_cs_na_1 = 103, // clock synchronisation command
    c_ts_na_1 = 104, // test command
    c_rp_na_1 = 105, // reset process command
    c_cd_na_1 = 106, // delay acquisition command
    c_ts_ta_1 = 107, // test command with CP56Time2a

    // parameter loading (recognised, elements not modelled — see SPEC.md)
    p_me_na_1 = 110,
    p_me_nb_1 = 111,
    p_me_nc_1 = 112,
    p_ac_na_1 = 113,

    _,

    /// True for the monitor-direction process-information types (1..40).
    pub fn isMonitoring(self: TypeId) bool {
        const v = @intFromEnum(self);
        return v >= 1 and v <= 40;
    }

    /// True for the control-direction process-information types (45..69).
    pub fn isCommand(self: TypeId) bool {
        const v = @intFromEnum(self);
        return v >= 45 and v <= 69;
    }
};

// ── cause of transmission ───────────────────────────────────────────────────

/// The six-bit cause of transmission (§7.2.3). Non-exhaustive — the private
/// ranges 48..63 are deployment-specific.
pub const Cot = enum(u6) {
    unused = 0,
    periodic = 1,
    background_scan = 2,
    spontaneous = 3,
    initialized = 4,
    request = 5,
    activation = 6,
    activation_con = 7,
    deactivation = 8,
    deactivation_con = 9,
    activation_termination = 10,
    return_remote = 11,
    return_local = 12,
    file_transfer = 13,
    interrogated_by_station = 20,
    interrogated_by_group_1 = 21,
    interrogated_by_group_16 = 36,
    requested_by_general_counter = 37,
    requested_by_counter_group_1 = 38,
    requested_by_counter_group_4 = 41,
    unknown_type_id = 44,
    unknown_cause = 45,
    unknown_common_address = 46,
    unknown_ioa = 47,
    _,

    /// Interrogation cause for inventory group `n` (1..16).
    pub fn interrogatedByGroup(n: u8) Cot {
        std.debug.assert(n >= 1 and n <= 16);
        return @enumFromInt(20 + n);
    }
};

/// Cause of transmission plus its two flag bits and the originator address.
pub const Cause = struct {
    cot: Cot = .unused,
    /// P/N — set means "negative confirmation": the requested action was not
    /// carried out. Only meaningful for the confirmation causes.
    negative: bool = false,
    /// T — set marks the ASDU as a test that must not affect the process.
    is_test: bool = false,
    /// Originator address (§7.2.3), present only when `Params.cot_size == 2`.
    /// 0 means "not used".
    originator: u8 = 0,

    pub fn causeByte(self: Cause) u8 {
        return @as(u8, @intFromEnum(self.cot)) |
            (if (self.negative) @as(u8, 0x40) else 0) |
            (if (self.is_test) @as(u8, 0x80) else 0);
    }

    pub fn fromByte(b: u8, originator: u8) Cause {
        return .{
            .cot = @enumFromInt(@as(u6, @truncate(b))),
            .negative = b & 0x40 != 0,
            .is_test = b & 0x80 != 0,
            .originator = originator,
        };
    }
};

/// Variable structure qualifier (§7.2.2).
pub const Vsq = struct {
    /// SQ — when set, the objects share one address that runs consecutively.
    sq: bool = false,
    /// Number of information objects (SQ = 0) or elements (SQ = 1).
    count: u7 = 0,

    pub fn toByte(self: Vsq) u8 {
        return @as(u8, self.count) | (if (self.sq) @as(u8, 0x80) else 0);
    }

    pub fn fromByte(b: u8) Vsq {
        return .{ .sq = b & 0x80 != 0, .count = @truncate(b) };
    }
};

/// The data unit identifier: the five header fields before the objects.
pub const Header = struct {
    type_id: TypeId,
    vsq: Vsq = .{},
    cause: Cause = .{},
    common_address: u16 = 0,
};

// ── information element shapes ──────────────────────────────────────────────

/// The kind of a type's *base* element, i.e. what it carries before any time
/// tag. Splitting "base element" from "time tag" is what keeps the type table
/// small: `M_SP_NA_1`, `M_SP_TA_1` and `M_SP_TB_1` all carry a `siq` base and
/// differ only in the tag appended to it.
pub const ElementKind = enum {
    /// No base element (the type carries only a time tag, or nothing at all).
    empty,
    siq,
    diq,
    /// VTI + QDS
    step,
    /// BSI(4) + QDS
    bitstring,
    /// NVA(2) + QDS
    normalized,
    /// SVA(2) + QDS
    scaled,
    /// R32(4) + QDS
    short_float,
    /// NVA(2), no quality octet (M_ME_ND_1)
    normalized_no_quality,
    /// BCR(5)
    counter,
    /// SIQ(1) + QDS(1) + CP24 elapsed — packed single point with change
    /// detection (M_PS_NA_1): 4 status/change octets + QDS
    packed_single,
    sco,
    dco,
    rco,
    /// NVA(2) + QOS
    setpoint_normalized,
    /// SVA(2) + QOS
    setpoint_scaled,
    /// R32(4) + QOS
    setpoint_float,
    /// BSI(4), no qualifier
    bitstring_command,
    qoi,
    qcc,
    qrp,
    coi,
    /// Fixed test bit pattern / test sequence counter, two octets.
    fbp,
    /// Parameter element: value(2 or 4) + QPM — recognised but not modelled.
    parameter,
};

/// Which time tag, if any, a type appends to its base element.
pub const TimeKind = enum {
    none,
    cp16,
    cp24,
    cp56,

    pub fn size(self: TimeKind) usize {
        return switch (self) {
            .none => 0,
            .cp16 => info.CP16Time2a.wire_len,
            .cp24 => info.CP24Time2a.wire_len,
            .cp56 => info.CP56Time2a.wire_len,
        };
    }
};

/// The wire shape of one type's information element.
pub const Shape = struct {
    base: ElementKind,
    time: TimeKind,

    /// Octets of one information element (excluding the object address).
    pub fn size(self: Shape) usize {
        const base: usize = switch (self.base) {
            .empty => 0,
            .siq, .diq, .sco, .dco, .rco, .qoi, .qcc, .qrp, .coi => 1,
            .step, .normalized_no_quality, .fbp => 2,
            .normalized, .scaled, .setpoint_normalized, .setpoint_scaled => 3,
            .bitstring_command => 4,
            .bitstring, .short_float, .counter, .setpoint_float, .packed_single => 5,
            .parameter => 3,
        };
        return base + self.time.size();
    }
};

/// The wire shape of `t`, or null when this module does not model it (file
/// transfer, unknown/private type ids). Callers turn null into
/// `error.UnsupportedTypeId`.
pub fn shapeOf(t: TypeId) ?Shape {
    return switch (t) {
        .m_sp_na_1 => .{ .base = .siq, .time = .none },
        .m_sp_ta_1 => .{ .base = .siq, .time = .cp24 },
        .m_sp_tb_1 => .{ .base = .siq, .time = .cp56 },
        .m_dp_na_1 => .{ .base = .diq, .time = .none },
        .m_dp_ta_1 => .{ .base = .diq, .time = .cp24 },
        .m_dp_tb_1 => .{ .base = .diq, .time = .cp56 },
        .m_st_na_1 => .{ .base = .step, .time = .none },
        .m_st_ta_1 => .{ .base = .step, .time = .cp24 },
        .m_st_tb_1 => .{ .base = .step, .time = .cp56 },
        .m_bo_na_1 => .{ .base = .bitstring, .time = .none },
        .m_bo_ta_1 => .{ .base = .bitstring, .time = .cp24 },
        .m_bo_tb_1 => .{ .base = .bitstring, .time = .cp56 },
        .m_me_na_1 => .{ .base = .normalized, .time = .none },
        .m_me_ta_1 => .{ .base = .normalized, .time = .cp24 },
        .m_me_td_1 => .{ .base = .normalized, .time = .cp56 },
        .m_me_nb_1 => .{ .base = .scaled, .time = .none },
        .m_me_tb_1 => .{ .base = .scaled, .time = .cp24 },
        .m_me_te_1 => .{ .base = .scaled, .time = .cp56 },
        .m_me_nc_1 => .{ .base = .short_float, .time = .none },
        .m_me_tc_1 => .{ .base = .short_float, .time = .cp24 },
        .m_me_tf_1 => .{ .base = .short_float, .time = .cp56 },
        .m_me_nd_1 => .{ .base = .normalized_no_quality, .time = .none },
        .m_it_na_1 => .{ .base = .counter, .time = .none },
        .m_it_ta_1 => .{ .base = .counter, .time = .cp24 },
        .m_it_tb_1 => .{ .base = .counter, .time = .cp56 },
        .m_ps_na_1 => .{ .base = .packed_single, .time = .none },

        .c_sc_na_1 => .{ .base = .sco, .time = .none },
        .c_sc_ta_1 => .{ .base = .sco, .time = .cp56 },
        .c_dc_na_1 => .{ .base = .dco, .time = .none },
        .c_dc_ta_1 => .{ .base = .dco, .time = .cp56 },
        .c_rc_na_1 => .{ .base = .rco, .time = .none },
        .c_rc_ta_1 => .{ .base = .rco, .time = .cp56 },
        .c_se_na_1 => .{ .base = .setpoint_normalized, .time = .none },
        .c_se_ta_1 => .{ .base = .setpoint_normalized, .time = .cp56 },
        .c_se_nb_1 => .{ .base = .setpoint_scaled, .time = .none },
        .c_se_tb_1 => .{ .base = .setpoint_scaled, .time = .cp56 },
        .c_se_nc_1 => .{ .base = .setpoint_float, .time = .none },
        .c_se_tc_1 => .{ .base = .setpoint_float, .time = .cp56 },
        .c_bo_na_1 => .{ .base = .bitstring_command, .time = .none },
        .c_bo_ta_1 => .{ .base = .bitstring_command, .time = .cp56 },

        .m_ei_na_1 => .{ .base = .coi, .time = .none },
        .c_ic_na_1 => .{ .base = .qoi, .time = .none },
        .c_ci_na_1 => .{ .base = .qcc, .time = .none },
        .c_rd_na_1 => .{ .base = .empty, .time = .none },
        .c_cs_na_1 => .{ .base = .empty, .time = .cp56 },
        .c_ts_na_1 => .{ .base = .fbp, .time = .none },
        .c_ts_ta_1 => .{ .base = .fbp, .time = .cp56 },
        .c_rp_na_1 => .{ .base = .qrp, .time = .none },
        .c_cd_na_1 => .{ .base = .empty, .time = .cp16 },
        .p_me_na_1, .p_me_nb_1, .p_me_nc_1 => .{ .base = .parameter, .time = .none },
        .p_ac_na_1 => .{ .base = .qrp, .time = .none }, // QPA, same width
        else => null,
    };
}

/// Octets of one information element of type `t`, excluding the object
/// address; null when the type is not modelled.
pub fn elementSize(t: TypeId) ?usize {
    const s = shapeOf(t) orelse return null;
    return s.size();
}

// ── decoded elements ────────────────────────────────────────────────────────

/// A decoded base information element.
pub const Element = union(ElementKind) {
    empty: void,
    siq: info.Siq,
    diq: info.Diq,
    step: struct { position: info.Vti, quality: info.Quality },
    bitstring: struct { bits: u32, quality: info.Quality },
    normalized: struct { value: info.Nva, quality: info.Quality },
    scaled: struct { value: i16, quality: info.Quality },
    short_float: struct { value: f32, quality: info.Quality },
    normalized_no_quality: info.Nva,
    counter: info.Bcr,
    packed_single: struct { status: u16, changed: u16, quality: info.Quality },
    sco: info.Sco,
    dco: info.Dco,
    rco: info.Rco,
    setpoint_normalized: struct { value: info.Nva, qos: info.Qos },
    setpoint_scaled: struct { value: i16, qos: info.Qos },
    setpoint_float: struct { value: f32, qos: info.Qos },
    bitstring_command: u32,
    qoi: info.Qoi,
    qcc: info.Qcc,
    qrp: info.Qrp,
    coi: info.Coi,
    fbp: u16,
    parameter: struct { raw: [2]u8, qpm: u8 },

    /// The select/execute bit, for the command elements that carry one.
    /// Null for anything that is not a command.
    pub fn selectExecute(self: Element) ?info.SelectExecute {
        return switch (self) {
            .sco => |v| v.select,
            .dco => |v| v.select,
            .rco => |v| v.select,
            .setpoint_normalized => |v| v.qos.select,
            .setpoint_scaled => |v| v.qos.select,
            .setpoint_float => |v| v.qos.select,
            else => null,
        };
    }
};

/// A decoded time tag.
pub const TimeTag = union(TimeKind) {
    none: void,
    cp16: info.CP16Time2a,
    cp24: info.CP24Time2a,
    cp56: info.CP56Time2a,

    /// The CP56Time2a, if this tag is one.
    pub fn cp56Time(self: TimeTag) ?info.CP56Time2a {
        return switch (self) {
            .cp56 => |t| t,
            else => null,
        };
    }
};

/// One decoded information object: its address, base element and time tag.
pub const Object = struct {
    ioa: u32,
    element: Element,
    time: TimeTag = .none,
};

pub const Error = error{
    /// Fewer octets than the data unit identifier needs.
    ShortAsdu,
    /// This module does not model the type id's element layout.
    UnsupportedTypeId,
    /// The object count is zero (§7.2.2 requires at least one).
    ZeroObjectCount,
    /// The body length does not match `count` objects of this type's size —
    /// the single most common sign of a corrupt or hostile ASDU.
    ObjectCountMismatch,
    /// An address does not fit in the octets `Params` allows for it.
    AddressOutOfRange,
    /// A non-zero originator address with a 1-octet cause of transmission.
    OriginatorNotAllowed,
    /// The output buffer is too small.
    BufferTooSmall,
    /// More objects added than a 7-bit count can express.
    TooManyObjects,
    /// With SQ = 1 the addresses must run consecutively from the first one.
    NonSequentialAddress,
} || ParamsError || info.TimeError;

// ── data unit identifier ────────────────────────────────────────────────────

/// Encodes the data unit identifier into `out`, returning the written slice.
pub fn encodeHeader(header: Header, params: Params, out: []u8) Error![]u8 {
    try params.validate();
    const n = params.headerLen();
    if (out.len < n) return error.BufferTooSmall;
    if (header.common_address > params.maxCa()) return error.AddressOutOfRange;
    if (!params.hasOriginator() and header.cause.originator != 0) return error.OriginatorNotAllowed;

    out[0] = @intFromEnum(header.type_id);
    out[1] = header.vsq.toByte();
    out[2] = header.cause.causeByte();
    var i: usize = 3;
    if (params.hasOriginator()) {
        out[i] = header.cause.originator;
        i += 1;
    }
    out[i] = @truncate(header.common_address);
    i += 1;
    if (params.ca_size == 2) {
        out[i] = @truncate(header.common_address >> 8);
        i += 1;
    }
    std.debug.assert(i == n);
    return out[0..n];
}

/// Decodes the data unit identifier from the front of `bytes`.
pub fn decodeHeader(bytes: []const u8, params: Params) Error!Header {
    try params.validate();
    const n = params.headerLen();
    if (bytes.len < n) return error.ShortAsdu;
    var i: usize = 3;
    var originator: u8 = 0;
    if (params.hasOriginator()) {
        originator = bytes[i];
        i += 1;
    }
    var ca: u16 = bytes[i];
    i += 1;
    if (params.ca_size == 2) {
        ca |= @as(u16, bytes[i]) << 8;
        i += 1;
    }
    return .{
        .type_id = @enumFromInt(bytes[0]),
        .vsq = Vsq.fromByte(bytes[1]),
        .cause = Cause.fromByte(bytes[2], originator),
        .common_address = ca,
    };
}

// ── whole-ASDU decoding ─────────────────────────────────────────────────────

/// A decoded ASDU: the header plus a validated object iterator. Decoding
/// checks up front that the body length matches exactly `count` objects of
/// this type's element size, so `ObjectIterator.next` can never run off the
/// end.
pub const Asdu = struct {
    header: Header,
    params: Params,
    shape: Shape,
    body: []const u8,

    pub fn objects(self: Asdu) ObjectIterator {
        return .{ .asdu = self, .index = 0 };
    }

    /// Number of information objects (or elements, when SQ = 1).
    pub fn count(self: Asdu) u7 {
        return self.header.vsq.count;
    }
};

/// Walks an ASDU's information objects, transparently handling both layouts:
/// with SQ = 0 each object carries its own address, with SQ = 1 one address is
/// read once and incremented per element.
pub const ObjectIterator = struct {
    asdu: Asdu,
    index: u7,

    pub fn next(self: *ObjectIterator) Error!?Object {
        if (self.index >= self.asdu.header.vsq.count) return null;
        const params = self.asdu.params;
        const esz = self.asdu.shape.size();
        const isz: usize = params.ioa_size;
        const i: usize = self.index;

        var ioa: u32 = undefined;
        var elem: []const u8 = undefined;
        if (self.asdu.header.vsq.sq) {
            const base = readAddress(self.asdu.body[0..isz]);
            ioa = base + @as(u32, @intCast(i));
            const off = isz + i * esz;
            elem = self.asdu.body[off..][0..esz];
        } else {
            const off = i * (isz + esz);
            ioa = readAddress(self.asdu.body[off..][0..isz]);
            elem = self.asdu.body[off + isz ..][0..esz];
        }
        self.index += 1;
        return .{
            .ioa = ioa,
            .element = try decodeElement(self.asdu.shape.base, elem),
            .time = try decodeTime(self.asdu.shape.time, elem[elem.len - self.asdu.shape.time.size() ..]),
        };
    }
};

/// Decodes a whole ASDU, validating that the body length agrees with the
/// object count and the type's element size.
pub fn decode(bytes: []const u8, params: Params) Error!Asdu {
    const header = try decodeHeader(bytes, params);
    const shape = shapeOf(header.type_id) orelse return error.UnsupportedTypeId;
    const body = bytes[params.headerLen()..];
    if (header.vsq.count == 0) return error.ZeroObjectCount;

    const esz = shape.size();
    const isz: usize = params.ioa_size;
    const n: usize = header.vsq.count;
    const expected = if (header.vsq.sq) isz + n * esz else n * (isz + esz);
    if (body.len != expected) return error.ObjectCountMismatch;

    return .{ .header = header, .params = params, .shape = shape, .body = body };
}

fn readAddress(bytes: []const u8) u32 {
    var v: u32 = 0;
    var i: usize = bytes.len;
    while (i > 0) {
        i -= 1;
        v = (v << 8) | bytes[i];
    }
    return v;
}

fn writeAddress(out: []u8, value: u32) void {
    var v = value;
    for (out) |*b| {
        b.* = @truncate(v);
        v >>= 8;
    }
}

// ── element codecs ──────────────────────────────────────────────────────────

/// Decodes one base element. `bytes` must be the whole element (base plus any
/// time tag); only the leading base octets are read.
pub fn decodeElement(kind: ElementKind, bytes: []const u8) Error!Element {
    const need = (Shape{ .base = kind, .time = .none }).size();
    if (bytes.len < need) return error.ObjectCountMismatch;
    return switch (kind) {
        .empty => .{ .empty = {} },
        .siq => .{ .siq = info.Siq.fromByte(bytes[0]) },
        .diq => .{ .diq = info.Diq.fromByte(bytes[0]) },
        .step => .{ .step = .{ .position = info.Vti.fromByte(bytes[0]), .quality = info.Quality.fromByte(bytes[1]) } },
        .bitstring => .{ .bitstring = .{ .bits = info.readU32(bytes[0..4]), .quality = info.Quality.fromByte(bytes[4]) } },
        .normalized => .{ .normalized = .{ .value = .{ .raw = info.readI16(bytes[0..2]) }, .quality = info.Quality.fromByte(bytes[2]) } },
        .scaled => .{ .scaled = .{ .value = info.readI16(bytes[0..2]), .quality = info.Quality.fromByte(bytes[2]) } },
        .short_float => .{ .short_float = .{ .value = info.readF32(bytes[0..4]), .quality = info.Quality.fromByte(bytes[4]) } },
        .normalized_no_quality => .{ .normalized_no_quality = .{ .raw = info.readI16(bytes[0..2]) } },
        .counter => .{ .counter = info.Bcr.decode(bytes[0..5]) },
        .packed_single => .{ .packed_single = .{
            .status = @as(u16, bytes[0]) | (@as(u16, bytes[1]) << 8),
            .changed = @as(u16, bytes[2]) | (@as(u16, bytes[3]) << 8),
            .quality = info.Quality.fromByte(bytes[4]),
        } },
        .sco => .{ .sco = info.Sco.fromByte(bytes[0]) },
        .dco => .{ .dco = info.Dco.fromByte(bytes[0]) },
        .rco => .{ .rco = info.Rco.fromByte(bytes[0]) },
        .setpoint_normalized => .{ .setpoint_normalized = .{ .value = .{ .raw = info.readI16(bytes[0..2]) }, .qos = info.Qos.fromByte(bytes[2]) } },
        .setpoint_scaled => .{ .setpoint_scaled = .{ .value = info.readI16(bytes[0..2]), .qos = info.Qos.fromByte(bytes[2]) } },
        .setpoint_float => .{ .setpoint_float = .{ .value = info.readF32(bytes[0..4]), .qos = info.Qos.fromByte(bytes[4]) } },
        .bitstring_command => .{ .bitstring_command = info.readU32(bytes[0..4]) },
        .qoi => .{ .qoi = @enumFromInt(bytes[0]) },
        .qcc => .{ .qcc = info.Qcc.fromByte(bytes[0]) },
        .qrp => .{ .qrp = @enumFromInt(bytes[0]) },
        .coi => .{ .coi = info.Coi.fromByte(bytes[0]) },
        .fbp => .{ .fbp = @as(u16, bytes[0]) | (@as(u16, bytes[1]) << 8) },
        .parameter => .{ .parameter = .{ .raw = .{ bytes[0], bytes[1] }, .qpm = bytes[2] } },
    };
}

/// Encodes one base element into the front of `out`, returning its length.
pub fn encodeElement(element: Element, out: []u8) Error!usize {
    const need = (Shape{ .base = @as(ElementKind, element), .time = .none }).size();
    if (out.len < need) return error.BufferTooSmall;
    switch (element) {
        .empty => {},
        .siq => |v| out[0] = v.toByte(),
        .diq => |v| out[0] = v.toByte(),
        .step => |v| {
            out[0] = v.position.toByte();
            out[1] = v.quality.toByte();
        },
        .bitstring => |v| {
            info.writeU32(out[0..4], v.bits);
            out[4] = v.quality.toByte();
        },
        .normalized => |v| {
            info.writeI16(out[0..2], v.value.raw);
            out[2] = v.quality.toByte();
        },
        .scaled => |v| {
            info.writeI16(out[0..2], v.value);
            out[2] = v.quality.toByte();
        },
        .short_float => |v| {
            info.writeF32(out[0..4], v.value);
            out[4] = v.quality.toByte();
        },
        .normalized_no_quality => |v| info.writeI16(out[0..2], v.raw),
        .counter => |v| _ = v.encode(out[0..5]),
        .packed_single => |v| {
            out[0] = @truncate(v.status);
            out[1] = @truncate(v.status >> 8);
            out[2] = @truncate(v.changed);
            out[3] = @truncate(v.changed >> 8);
            out[4] = v.quality.toByte();
        },
        .sco => |v| out[0] = v.toByte(),
        .dco => |v| out[0] = v.toByte(),
        .rco => |v| out[0] = v.toByte(),
        .setpoint_normalized => |v| {
            info.writeI16(out[0..2], v.value.raw);
            out[2] = v.qos.toByte();
        },
        .setpoint_scaled => |v| {
            info.writeI16(out[0..2], v.value);
            out[2] = v.qos.toByte();
        },
        .setpoint_float => |v| {
            info.writeF32(out[0..4], v.value);
            out[4] = v.qos.toByte();
        },
        .bitstring_command => |v| info.writeU32(out[0..4], v),
        .qoi => |v| out[0] = @intFromEnum(v),
        .qcc => |v| out[0] = v.toByte(),
        .qrp => |v| out[0] = @intFromEnum(v),
        .coi => |v| out[0] = v.toByte(),
        .fbp => |v| {
            out[0] = @truncate(v);
            out[1] = @truncate(v >> 8);
        },
        .parameter => |v| {
            out[0] = v.raw[0];
            out[1] = v.raw[1];
            out[2] = v.qpm;
        },
    }
    return need;
}

fn decodeTime(kind: TimeKind, bytes: []const u8) Error!TimeTag {
    return switch (kind) {
        .none => .none,
        .cp16 => .{ .cp16 = try info.CP16Time2a.decode(bytes) },
        .cp24 => .{ .cp24 = try info.CP24Time2a.decode(bytes) },
        .cp56 => .{ .cp56 = try info.CP56Time2a.decode(bytes) },
    };
}

fn encodeTime(tag: TimeTag, out: []u8) Error!usize {
    return switch (tag) {
        .none => 0,
        .cp16 => |t| (try t.encode(out)).len,
        .cp24 => |t| (try t.encode(out)).len,
        .cp56 => |t| (try t.encode(out)).len,
    };
}

// ── building ────────────────────────────────────────────────────────────────

/// Builds an ASDU into a caller-supplied buffer, one object at a time.
///
/// The object count in the VSQ is patched on every `add`, so the header is
/// always consistent with what has actually been written and `finish` is just
/// a slice.
pub const Builder = struct {
    buf: []u8,
    len: usize,
    params: Params,
    shape: Shape,
    sq: bool,
    count: u7,
    base_ioa: u32,

    /// Starts an ASDU. `cause`, `common_address` and `sq` are fixed for the
    /// whole unit; the object count starts at zero and grows with `add`.
    pub fn init(
        buf: []u8,
        params: Params,
        type_id: TypeId,
        cause: Cause,
        common_address: u16,
        sq: bool,
    ) Error!Builder {
        const shape = shapeOf(type_id) orelse return error.UnsupportedTypeId;
        const hdr = try encodeHeader(.{
            .type_id = type_id,
            .vsq = .{ .sq = sq, .count = 0 },
            .cause = cause,
            .common_address = common_address,
        }, params, buf);
        return .{
            .buf = buf,
            .len = hdr.len,
            .params = params,
            .shape = shape,
            .sq = sq,
            .count = 0,
            .base_ioa = 0,
        };
    }

    /// Appends one information object.
    ///
    /// With SQ = 1 the address is written only for the first object and every
    /// later `ioa` must equal `base + index`; a caller that violates that gets
    /// `error.NonSequentialAddress` rather than a silently wrong frame.
    pub fn add(self: *Builder, ioa: u32, element: Element, time: TimeTag) Error!void {
        if (self.count == std.math.maxInt(u7)) return error.TooManyObjects;
        if (ioa > self.params.maxIoa()) return error.AddressOutOfRange;
        if (@as(ElementKind, element) != self.shape.base) return error.UnsupportedTypeId;
        if (@as(TimeKind, time) != self.shape.time) return error.UnsupportedTypeId;

        const isz: usize = self.params.ioa_size;
        if (self.sq) {
            if (self.count == 0) {
                if (self.len + isz > self.buf.len) return error.BufferTooSmall;
                writeAddress(self.buf[self.len..][0..isz], ioa);
                self.len += isz;
                self.base_ioa = ioa;
            } else if (ioa != self.base_ioa + self.count) {
                return error.NonSequentialAddress;
            }
        } else {
            if (self.len + isz > self.buf.len) return error.BufferTooSmall;
            writeAddress(self.buf[self.len..][0..isz], ioa);
            self.len += isz;
        }

        const esz = self.shape.size();
        if (self.len + esz > self.buf.len) return error.BufferTooSmall;
        const base_len = try encodeElement(element, self.buf[self.len..]);
        _ = try encodeTime(time, self.buf[self.len + base_len ..]);
        self.len += esz;
        self.count += 1;
        // Keep the VSQ octet in step with what has been written.
        self.buf[1] = (Vsq{ .sq = self.sq, .count = self.count }).toByte();
    }

    /// The finished ASDU. Note that a zero-object ASDU is refused: §7.2.2
    /// requires at least one information object, and `decode` rejects it too.
    pub fn finish(self: *const Builder) Error![]u8 {
        if (self.count == 0) return error.ZeroObjectCount;
        return self.buf[0..self.len];
    }
};

/// Shorthand for the very common single-object ASDU.
pub fn buildSingle(
    buf: []u8,
    params: Params,
    type_id: TypeId,
    cause: Cause,
    common_address: u16,
    ioa: u32,
    element: Element,
    time: TimeTag,
) Error![]u8 {
    var b = try Builder.init(buf, params, type_id, cause, common_address, false);
    try b.add(ioa, element, time);
    return b.finish();
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "params validate and derive header length" {
    try default_params.validate();
    try testing.expectEqual(@as(usize, 6), default_params.headerLen());
    const compact = Params{ .ioa_size = 1, .ca_size = 1, .cot_size = 1 };
    try compact.validate();
    // type id + VSQ + 1 COT octet + 1 CA octet.
    try testing.expectEqual(@as(usize, 4), compact.headerLen());
    try testing.expect(!compact.hasOriginator());
    try testing.expectEqual(@as(u32, 0xFF), compact.maxIoa());
    try testing.expectEqual(@as(u16, 0xFF), compact.maxCa());
    try testing.expectEqual(@as(u16, 0xFFFF), default_params.broadcastCa());
    try testing.expectError(error.InvalidParams, (Params{ .ioa_size = 0 }).validate());
    try testing.expectError(error.InvalidParams, (Params{ .ioa_size = 4 }).validate());
    try testing.expectError(error.InvalidParams, (Params{ .ca_size = 3 }).validate());
    try testing.expectError(error.InvalidParams, (Params{ .cot_size = 0 }).validate());
}

test "data unit identifier round-trip, default 3/2/originator profile" {
    var buf: [8]u8 = undefined;
    const h = Header{
        .type_id = .c_ic_na_1,
        .vsq = .{ .sq = false, .count = 1 },
        .cause = .{ .cot = .activation, .originator = 0 },
        .common_address = 47,
    };
    const enc = try encodeHeader(h, default_params, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x64, 0x01, 0x06, 0x00, 0x2F, 0x00 }, enc);
    const back = try decodeHeader(enc, default_params);
    try testing.expectEqual(h, back);
}

test "cause of transmission carries P/N and T alongside the six-bit cause" {
    const neg = Cause{ .cot = .activation_con, .negative = true };
    try testing.expectEqual(@as(u8, 0x47), neg.causeByte());
    const t = Cause{ .cot = .activation, .is_test = true };
    try testing.expectEqual(@as(u8, 0x86), t.causeByte());
    const both = Cause.fromByte(0xC6, 3);
    try testing.expectEqual(Cot.activation, both.cot);
    try testing.expect(both.negative);
    try testing.expect(both.is_test);
    try testing.expectEqual(@as(u8, 3), both.originator);
    try testing.expectEqual(Cot.interrogated_by_group_1, Cot.interrogatedByGroup(1));
    try testing.expectEqual(Cot.interrogated_by_group_16, Cot.interrogatedByGroup(16));
}

test "alternative address sizings put the fields where the caller asked" {
    // 1-octet IOA, 1-octet CA, no originator.
    const p = Params{ .ioa_size = 1, .ca_size = 1, .cot_size = 1 };
    var buf: [32]u8 = undefined;
    const asdu = try buildSingle(&buf, p, .m_sp_na_1, .{ .cot = .spontaneous }, 7, 9, .{ .siq = .{ .on = true } }, .none);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x01, 0x03, 0x07, 0x09, 0x01 }, asdu);

    const dec = try decode(asdu, p);
    var it = dec.objects();
    const o = (try it.next()).?;
    try testing.expectEqual(@as(u32, 9), o.ioa);
    try testing.expect(o.element.siq.on);
    try testing.expectEqual(@as(u16, 7), dec.header.common_address);

    // 2-octet IOA, 2-octet CA, no originator.
    const p2 = Params{ .ioa_size = 2, .ca_size = 2, .cot_size = 1 };
    const asdu2 = try buildSingle(&buf, p2, .m_sp_na_1, .{ .cot = .spontaneous }, 0x1234, 0xBEEF, .{ .siq = .{} }, .none);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x01, 0x03, 0x34, 0x12, 0xEF, 0xBE, 0x00 }, asdu2);
    var it2 = (try decode(asdu2, p2)).objects();
    try testing.expectEqual(@as(u32, 0xBEEF), (try it2.next()).?.ioa);

    // An address that does not fit the configured width is refused.
    try testing.expectError(error.AddressOutOfRange, buildSingle(&buf, p, .m_sp_na_1, .{}, 7, 300, .{ .siq = .{} }, .none));
    try testing.expectError(error.AddressOutOfRange, encodeHeader(.{ .type_id = .m_sp_na_1, .common_address = 300 }, p, &buf));
    // So is an originator address with no octet to put it in.
    try testing.expectError(error.OriginatorNotAllowed, encodeHeader(.{ .type_id = .m_sp_na_1, .cause = .{ .originator = 1 } }, p, &buf));
}

test "SQ = 0 gives every object its own address" {
    var buf: [64]u8 = undefined;
    var b = try Builder.init(&buf, default_params, .m_sp_na_1, .{ .cot = .spontaneous }, 1, false);
    try b.add(100, .{ .siq = .{ .on = true } }, .none);
    try b.add(200, .{ .siq = .{ .on = false, .quality = .{ .iv = true } } }, .none);
    const out = try b.finish();
    try testing.expectEqualSlices(u8, &[_]u8{
        0x01, 0x02, 0x03, 0x00, 0x01, 0x00, // header, VSQ = count 2, SQ = 0
        0x64, 0x00, 0x00, 0x01, // IOA 100, SIQ on
        0xC8, 0x00, 0x00, 0x80, // IOA 200, SIQ off + IV
    }, out);

    const dec = try decode(out, default_params);
    try testing.expect(!dec.header.vsq.sq);
    var it = dec.objects();
    const a = (try it.next()).?;
    const c = (try it.next()).?;
    try testing.expectEqual(@as(u32, 100), a.ioa);
    try testing.expect(a.element.siq.on);
    try testing.expectEqual(@as(u32, 200), c.ioa);
    try testing.expect(c.element.siq.quality.iv);
    try testing.expect((try it.next()) == null);
}

test "SQ = 1 writes one address and runs the rest consecutively" {
    var buf: [64]u8 = undefined;
    var b = try Builder.init(&buf, default_params, .m_sp_na_1, .{ .cot = .interrogated_by_station }, 47, true);
    var i: u32 = 0;
    while (i < 4) : (i += 1) try b.add(1000 + i, .{ .siq = .{ .on = i % 2 == 1 } }, .none);
    const out = try b.finish();
    try testing.expectEqualSlices(u8, &[_]u8{
        0x01, 0x84, 0x14, 0x00, 0x2F, 0x00, // VSQ = SQ | count 4
        0xE8, 0x03, 0x00, // one IOA: 1000
        0x00, 0x01, 0x00, 0x01, // four bare SIQ elements
    }, out);

    const dec = try decode(out, default_params);
    try testing.expect(dec.header.vsq.sq);
    var it = dec.objects();
    i = 0;
    while (try it.next()) |o| : (i += 1) {
        try testing.expectEqual(@as(u32, 1000 + i), o.ioa);
        try testing.expectEqual(i % 2 == 1, o.element.siq.on);
    }
    try testing.expectEqual(@as(u32, 4), i);

    // A gap in the addresses cannot be expressed with SQ = 1.
    var b2 = try Builder.init(&buf, default_params, .m_sp_na_1, .{}, 1, true);
    try b2.add(10, .{ .siq = .{} }, .none);
    try testing.expectError(error.NonSequentialAddress, b2.add(12, .{ .siq = .{} }, .none));
}

test "the two layouts of the same data differ in length and bytes" {
    var a: [64]u8 = undefined;
    var c: [64]u8 = undefined;
    var seq = try Builder.init(&a, default_params, .m_me_nb_1, .{ .cot = .periodic }, 1, true);
    var list = try Builder.init(&c, default_params, .m_me_nb_1, .{ .cot = .periodic }, 1, false);
    var i: u32 = 0;
    while (i < 3) : (i += 1) {
        const e = Element{ .scaled = .{ .value = @intCast(i), .quality = .{} } };
        try seq.add(50 + i, e, .none);
        try list.add(50 + i, e, .none);
    }
    const seq_bytes = try seq.finish();
    const list_bytes = try list.finish();
    // SQ = 1 saves two addresses: 3*(3+3)+6 = 24 versus 3+3*3+6 = 18.
    try testing.expectEqual(@as(usize, 24), list_bytes.len);
    try testing.expectEqual(@as(usize, 18), seq_bytes.len);
    try testing.expect(!std.mem.eql(u8, seq_bytes, list_bytes));
}

test "decode rejects a body that disagrees with the object count" {
    var buf: [64]u8 = undefined;
    const good = try buildSingle(&buf, default_params, .m_sp_na_1, .{ .cot = .spontaneous }, 1, 5, .{ .siq = .{} }, .none);
    // Claim two objects but supply one object's worth of bytes.
    var bad: [16]u8 = undefined;
    @memcpy(bad[0..good.len], good);
    bad[1] = (Vsq{ .count = 2 }).toByte();
    try testing.expectError(error.ObjectCountMismatch, decode(bad[0..good.len], default_params));
    // One trailing octet too many.
    bad[1] = (Vsq{ .count = 1 }).toByte();
    bad[good.len] = 0xFF;
    try testing.expectError(error.ObjectCountMismatch, decode(bad[0 .. good.len + 1], default_params));
    // Zero objects.
    bad[1] = 0;
    try testing.expectError(error.ZeroObjectCount, decode(bad[0..default_params.headerLen()], default_params));
}

test "decode rejects a short ASDU and an unmodelled type id" {
    try testing.expectError(error.ShortAsdu, decode(&[_]u8{ 0x01, 0x01, 0x03 }, default_params));
    try testing.expectError(error.ShortAsdu, decode(&[_]u8{}, default_params));
    // Type 200 has no element layout here.
    try testing.expectError(error.UnsupportedTypeId, decode(&[_]u8{ 200, 0x01, 0x06, 0x00, 0x2F, 0x00, 0, 0, 0, 0 }, default_params));
    try testing.expect(shapeOf(@enumFromInt(200)) == null);
    try testing.expect(elementSize(@enumFromInt(126)) == null); // F_SC_NB_1, file transfer
}

test "element sizes match the standard for every modelled type" {
    const cases = [_]struct { t: TypeId, n: usize }{
        .{ .t = .m_sp_na_1, .n = 1 },  .{ .t = .m_sp_ta_1, .n = 4 },  .{ .t = .m_sp_tb_1, .n = 8 },
        .{ .t = .m_dp_na_1, .n = 1 },  .{ .t = .m_dp_tb_1, .n = 8 },  .{ .t = .m_st_na_1, .n = 2 },
        .{ .t = .m_st_tb_1, .n = 9 },  .{ .t = .m_bo_na_1, .n = 5 },  .{ .t = .m_bo_tb_1, .n = 12 },
        .{ .t = .m_me_na_1, .n = 3 },  .{ .t = .m_me_td_1, .n = 10 }, .{ .t = .m_me_nb_1, .n = 3 },
        .{ .t = .m_me_te_1, .n = 10 }, .{ .t = .m_me_nc_1, .n = 5 },  .{ .t = .m_me_tf_1, .n = 12 },
        .{ .t = .m_me_nd_1, .n = 2 },  .{ .t = .m_it_na_1, .n = 5 },  .{ .t = .m_it_tb_1, .n = 12 },
        .{ .t = .c_sc_na_1, .n = 1 },  .{ .t = .c_sc_ta_1, .n = 8 },  .{ .t = .c_dc_na_1, .n = 1 },
        .{ .t = .c_rc_na_1, .n = 1 },  .{ .t = .c_se_na_1, .n = 3 },  .{ .t = .c_se_nb_1, .n = 3 },
        .{ .t = .c_se_nc_1, .n = 5 },  .{ .t = .c_se_tc_1, .n = 12 }, .{ .t = .c_bo_na_1, .n = 4 },
        .{ .t = .m_ei_na_1, .n = 1 },  .{ .t = .c_ic_na_1, .n = 1 },  .{ .t = .c_ci_na_1, .n = 1 },
        .{ .t = .c_rd_na_1, .n = 0 },  .{ .t = .c_cs_na_1, .n = 7 },  .{ .t = .c_ts_na_1, .n = 2 },
        .{ .t = .c_rp_na_1, .n = 1 },  .{ .t = .c_cd_na_1, .n = 2 },  .{ .t = .c_ts_ta_1, .n = 9 },
    };
    for (cases) |c| try testing.expectEqual(c.n, elementSize(c.t).?);
}

test "every modelled type round-trips element bytes" {
    var buf: [64]u8 = undefined;
    const samples = [_]struct { t: TypeId, e: Element, tm: TimeTag }{
        .{ .t = .m_sp_na_1, .e = .{ .siq = .{ .on = true, .quality = .{ .nt = true } } }, .tm = .none },
        .{ .t = .m_dp_na_1, .e = .{ .diq = .{ .state = .on } }, .tm = .none },
        .{ .t = .m_st_na_1, .e = .{ .step = .{ .position = .{ .value = -7, .transient = true }, .quality = .{} } }, .tm = .none },
        .{ .t = .m_bo_na_1, .e = .{ .bitstring = .{ .bits = 0xDEADBEEF, .quality = .{ .ov = true } } }, .tm = .none },
        .{ .t = .m_me_na_1, .e = .{ .normalized = .{ .value = .{ .raw = -12345 }, .quality = .{} } }, .tm = .none },
        .{ .t = .m_me_nb_1, .e = .{ .scaled = .{ .value = 4321, .quality = .{} } }, .tm = .none },
        .{ .t = .m_me_nc_1, .e = .{ .short_float = .{ .value = -2.5, .quality = .{} } }, .tm = .none },
        .{ .t = .m_me_nd_1, .e = .{ .normalized_no_quality = .{ .raw = 999 } }, .tm = .none },
        .{ .t = .m_it_na_1, .e = .{ .counter = .{ .counter = -9, .sequence = 5, .carry = true } }, .tm = .none },
        .{ .t = .m_ps_na_1, .e = .{ .packed_single = .{ .status = 0x1234, .changed = 0x5678, .quality = .{} } }, .tm = .none },
        .{ .t = .c_sc_na_1, .e = .{ .sco = .{ .on = true, .select = .select } }, .tm = .none },
        .{ .t = .c_dc_na_1, .e = .{ .dco = .{ .state = .on } }, .tm = .none },
        .{ .t = .c_rc_na_1, .e = .{ .rco = .{ .step = .higher } }, .tm = .none },
        .{ .t = .c_se_na_1, .e = .{ .setpoint_normalized = .{ .value = .{ .raw = 8192 }, .qos = .{ .select = .select } } }, .tm = .none },
        .{ .t = .c_se_nb_1, .e = .{ .setpoint_scaled = .{ .value = 777, .qos = .{} } }, .tm = .none },
        .{ .t = .c_se_nc_1, .e = .{ .setpoint_float = .{ .value = 1.5, .qos = .{} } }, .tm = .none },
        .{ .t = .c_bo_na_1, .e = .{ .bitstring_command = 0xCAFEBABE }, .tm = .none },
        .{ .t = .m_ei_na_1, .e = .{ .coi = .{ .cause = 2, .local_change = true } }, .tm = .none },
        .{ .t = .c_ic_na_1, .e = .{ .qoi = .station }, .tm = .none },
        .{ .t = .c_ci_na_1, .e = .{ .qcc = .{ .request = .general, .freeze = .freeze_reset } }, .tm = .none },
        .{ .t = .c_rd_na_1, .e = .{ .empty = {} }, .tm = .none },
        .{ .t = .c_rp_na_1, .e = .{ .qrp = .general_reset }, .tm = .none },
        .{ .t = .c_ts_na_1, .e = .{ .fbp = 0x55AA }, .tm = .none },
        .{ .t = .c_cd_na_1, .e = .{ .empty = {} }, .tm = .{ .cp16 = .{ .milliseconds = 1234 } } },
        .{ .t = .m_sp_ta_1, .e = .{ .siq = .{ .on = true } }, .tm = .{ .cp24 = .{ .millisecond = 1, .second = 2, .minute = 3 } } },
    };
    const t56 = info.CP56Time2a{ .millisecond = 135, .second = 38, .minute = 18, .hour = 3, .day = 23, .month = 7, .year = 26 };
    for (samples) |s| {
        const enc = try buildSingle(&buf, default_params, s.t, .{ .cot = .spontaneous }, 47, 4242, s.e, s.tm);
        const dec = try decode(enc, default_params);
        var it = dec.objects();
        const o = (try it.next()).?;
        try testing.expectEqual(@as(u32, 4242), o.ioa);
        try testing.expectEqual(s.e, o.element);
        try testing.expectEqual(s.tm, o.time);
    }
    // The CP56Time2a-tagged types, driven off the same base elements.
    const tagged = [_]struct { t: TypeId, e: Element }{
        .{ .t = .m_sp_tb_1, .e = .{ .siq = .{ .on = true } } },
        .{ .t = .m_dp_tb_1, .e = .{ .diq = .{ .state = .off } } },
        .{ .t = .m_st_tb_1, .e = .{ .step = .{ .position = .{ .value = 3 }, .quality = .{} } } },
        .{ .t = .m_bo_tb_1, .e = .{ .bitstring = .{ .bits = 1, .quality = .{} } } },
        .{ .t = .m_me_td_1, .e = .{ .normalized = .{ .value = .{ .raw = -8192 }, .quality = .{} } } },
        .{ .t = .m_me_te_1, .e = .{ .scaled = .{ .value = 4321, .quality = .{} } } },
        .{ .t = .m_me_tf_1, .e = .{ .short_float = .{ .value = -2.5, .quality = .{} } } },
        .{ .t = .m_it_tb_1, .e = .{ .counter = .{ .counter = 7 } } },
        .{ .t = .c_sc_ta_1, .e = .{ .sco = .{ .on = true } } },
        .{ .t = .c_dc_ta_1, .e = .{ .dco = .{ .state = .on } } },
        .{ .t = .c_rc_ta_1, .e = .{ .rco = .{ .step = .lower } } },
        .{ .t = .c_se_ta_1, .e = .{ .setpoint_normalized = .{ .value = .{ .raw = 1 }, .qos = .{} } } },
        .{ .t = .c_se_tb_1, .e = .{ .setpoint_scaled = .{ .value = 2, .qos = .{} } } },
        .{ .t = .c_se_tc_1, .e = .{ .setpoint_float = .{ .value = 9.75, .qos = .{} } } },
        .{ .t = .c_bo_ta_1, .e = .{ .bitstring_command = 3 } },
        .{ .t = .c_cs_na_1, .e = .{ .empty = {} } },
        .{ .t = .c_ts_ta_1, .e = .{ .fbp = 0 } },
    };
    for (tagged) |s| {
        const enc = try buildSingle(&buf, default_params, s.t, .{ .cot = .activation }, 47, 1, s.e, .{ .cp56 = t56 });
        const dec = try decode(enc, default_params);
        var it = dec.objects();
        const o = (try it.next()).?;
        try testing.expectEqual(s.e, o.element);
        try testing.expectEqual(t56, o.time.cp56Time().?);
    }
}

test "the parameter-loading types (P_ME/P_AC) round-trip too" {
    // p_me_na_1/nb_1/nc_1 (-> .parameter, 3 octets) and p_ac_na_1 (-> .qrp,
    // "same width" per its comment) are the only four `shapeOf` rows neither
    // of the two tables above touches — "recognised, elements not modelled"
    // in the TypeId doc comment does not mean the codec path is untested,
    // but it was: nothing else in this module builds or decodes a
    // `.parameter` element or a P_AC_NA_1 ASDU.
    var buf: [64]u8 = undefined;

    for ([_]TypeId{ .p_me_na_1, .p_me_nb_1, .p_me_nc_1 }) |t| {
        try testing.expectEqual(@as(usize, 3), elementSize(t).?);
        const e: Element = .{ .parameter = .{ .raw = .{ 0xAB, 0xCD }, .qpm = 0x42 } };
        const enc = try buildSingle(&buf, default_params, t, .{ .cot = .activation }, 47, 9, e, .none);
        const dec = try decode(enc, default_params);
        var it = dec.objects();
        const o = (try it.next()).?;
        try testing.expectEqual(@as(u32, 9), o.ioa);
        try testing.expectEqual(e, o.element);
    }

    try testing.expectEqual(@as(usize, 1), elementSize(.p_ac_na_1).?);
    const e = Element{ .qrp = .general_reset };
    const enc = try buildSingle(&buf, default_params, .p_ac_na_1, .{ .cot = .activation }, 47, 3, e, .none);
    const dec = try decode(enc, default_params);
    var it = dec.objects();
    const o = (try it.next()).?;
    try testing.expectEqual(@as(u32, 3), o.ioa);
    try testing.expectEqual(e, o.element);
}

test "builder refuses an element or time tag that does not match the type" {
    var buf: [64]u8 = undefined;
    var b = try Builder.init(&buf, default_params, .m_sp_na_1, .{}, 1, false);
    try testing.expectError(error.UnsupportedTypeId, b.add(1, .{ .diq = .{} }, .none));
    try testing.expectError(error.UnsupportedTypeId, b.add(1, .{ .siq = .{} }, .{ .cp56 = .{} }));
    try testing.expectError(error.ZeroObjectCount, b.finish());
    // A buffer with no room for the objects.
    var tiny: [7]u8 = undefined;
    var t = try Builder.init(&tiny, default_params, .m_sp_na_1, .{}, 1, false);
    try testing.expectError(error.BufferTooSmall, t.add(1, .{ .siq = .{} }, .none));
    // ... and one too small even for the header.
    var tinier: [4]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, Builder.init(&tinier, default_params, .m_sp_na_1, .{}, 1, false));
    try testing.expectError(error.UnsupportedTypeId, Builder.init(&buf, default_params, @enumFromInt(200), .{}, 1, false));
}

test "a CP56Time2a with impossible fields fails the ASDU decode, not just the tag" {
    var buf: [64]u8 = undefined;
    const t56 = info.CP56Time2a{ .millisecond = 0, .second = 0, .minute = 0, .hour = 0, .day = 1, .month = 1, .year = 0 };
    const enc = try buildSingle(&buf, default_params, .m_sp_tb_1, .{ .cot = .spontaneous }, 47, 1, .{ .siq = .{} }, .{ .cp56 = t56 });
    // Corrupt the month to 13.
    enc[enc.len - 2] = 13;
    const dec = try decode(enc, default_params);
    var it = dec.objects();
    try testing.expectError(error.ImpossibleTime, it.next());
}

test "the select/execute bit is readable off every command element" {
    try testing.expectEqual(info.SelectExecute.select, (Element{ .sco = .{ .select = .select } }).selectExecute().?);
    try testing.expectEqual(info.SelectExecute.execute, (Element{ .dco = .{} }).selectExecute().?);
    try testing.expectEqual(info.SelectExecute.select, (Element{ .rco = .{ .select = .select } }).selectExecute().?);
    try testing.expectEqual(info.SelectExecute.select, (Element{ .setpoint_float = .{ .value = 0, .qos = .{ .select = .select } } }).selectExecute().?);
    try testing.expect((Element{ .siq = .{} }).selectExecute() == null);
}

test "127 objects is the ceiling a 7-bit count can express" {
    var buf: [1024]u8 = undefined;
    var b = try Builder.init(&buf, default_params, .m_sp_na_1, .{}, 1, true);
    var i: u32 = 0;
    while (i < 127) : (i += 1) try b.add(i, .{ .siq = .{} }, .none);
    try testing.expectError(error.TooManyObjects, b.add(127, .{ .siq = .{} }, .none));
    const out = try b.finish();
    try testing.expectEqual(@as(u7, 127), (try decode(out, default_params)).count());
}

test "fuzz: ASDU decode and object iteration never panic" {
    try std.testing.fuzz({}, fuzzAsdu, .{});
}

fn fuzzAsdu(_: void, smith: *std.testing.Smith) !void {
    var buf: [253]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const p = Params{
        .ioa_size = smith.valueRangeAtMost(u8, 1, 3),
        .ca_size = smith.valueRangeAtMost(u8, 1, 2),
        .cot_size = smith.valueRangeAtMost(u8, 1, 2),
    };
    const a = decode(buf[0..len], p) catch return;
    var it = a.objects();
    var seen: usize = 0;
    while (it.next() catch return) |_| {
        seen += 1;
        try testing.expect(seen <= std.math.maxInt(u7));
    }
}
