// SPDX-License-Identifier: MIT

//! OPC UA Binary encoding (OPC 10000-6 §5.2) — the built-in type codec every
//! OPC UA message body is built from. `Encoder`/`Decoder` wrap a
//! `std.Io.Writer`/`std.Io.Reader` pair so the codec is transport-agnostic:
//! `.fixed(&buf)` for offline tests, or a real opc.tcp stream's buffered
//! reader/writer in production (see `transport.zig`, which rides this codec
//! inside its message chunks).
//!
//! Every OPC UA integer/float is little-endian (§5.2.1 — the opposite of the
//! `snmp`/`coap` modules' network byte order). `String`, `ByteString`, and
//! `XmlElement` share one Int32-length-prefixed shape where length `-1` means
//! "null" — distinct from a present-but-empty value (length 0) — modeled here
//! as `?[]const u8` (`null` = OPC UA null, `&.{}` = present-but-empty).
//!
//! `NodeId` and `Variant` are real tagged unions (not stubs) — only their
//! `encode`/`decode` bodies are `@panic("TODO(agent): ...")`. Every other
//! built-in type (Boolean .. DiagnosticInfo) is a real Zig type with stubbed
//! codec methods on `Encoder`/`Decoder`.

const std = @import("std");

// ── errors ──────────────────────────────────────────────────────────────────

pub const EncodeError = std.Io.Writer.Error || error{
    /// A String/ByteString/XmlElement/array whose length doesn't fit the
    /// Int32 length prefix (OPC 10000-6 §5.2.2.4).
    ValueTooLarge,
};

pub const DecodeError = std.Io.Reader.Error || error{
    /// A length field that is neither -1 (null) nor a valid non-negative
    /// length for the remaining input (or exceeds a caller-supplied cap).
    BadLength,
    /// An encoding-byte value OPC 10000-6 doesn't define. NodeId (§5.2.2.9),
    /// ExpandedNodeId (§5.2.2.10), LocalizedText (§5.2.2.14), ExtensionObject
    /// (§5.2.2.15), Variant (§5.2.2.16), DataValue (§5.2.2.17), and
    /// DiagnosticInfo (§5.2.2.12) are all bit-flag/enum bytes with reserved
    /// combinations.
    BadEncodingByte,
    /// A Variant/ExtensionObject type-id names a built-in type this module
    /// doesn't (yet) decode.
    UnsupportedType,
    OutOfMemory,
};

// ── built-in scalar aliases (OPC 10000-6 §5.2.2.1-2.3, §5.2.2.5) ───────────

/// §5.2.2.5 — 100-nanosecond ticks since 1601-01-01T00:00:00Z (the Windows
/// FILETIME epoch), UTC.
pub const DateTime = i64;

/// §5.2.2.11 / §7.34 — a bit-packed severity/subcode value. Kept as a plain
/// `u32` here: the codec only needs to move the 4 bytes, the field-layout
/// helpers (`Severity`, subcode lookup) are a later part's concern.
pub const StatusCode = u32;

// ── Guid (§5.2.2.6) ─────────────────────────────────────────────────────────

/// The wire form of a GUID: `Data1(UInt32) Data2(UInt16) Data3(UInt16)
/// Data4(8 bytes)`, matching the Microsoft/RFC 4122 mixed-endian layout (the
/// first three fields are little-endian on the wire like every other OPC UA
/// integer; `data4` is an opaque 8-byte array, not integer-decoded).
pub const Guid = struct {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [8]u8,
};

// ── NodeId (§5.2.2.9) ────────────────────────────────────────────────────────

/// The wire encoding-byte values selecting which `NodeId` body follows
/// (OPC 10000-6 §5.2.2.9 Table 7). `two_byte`/`four_byte` are compact wire
/// forms of a `.numeric` identifier with a small namespace/value; `encode`
/// picks the smallest form that fits, `decode` accepts any of the three.
pub const NodeIdEncodingByte = enum(u8) {
    two_byte = 0x00,
    four_byte = 0x01,
    numeric = 0x02,
    string = 0x03,
    guid = 0x04,
    byte_string = 0x05,
    _,
};

/// A Node identifier: a namespace index plus an identifier of one of four
/// kinds. The `two_byte`/`four_byte`/`numeric` *wire* forms in
/// `NodeIdEncodingByte` are all this same `.numeric` variant at different
/// sizes — `encode` chooses the compact form, the variant here doesn't.
pub const NodeId = union(enum) {
    numeric: struct { namespace: u16, id: u32 },
    string: struct { namespace: u16, id: ?[]const u8 },
    guid: struct { namespace: u16, id: Guid },
    /// The "opaque" identifier form (encoding byte `.byte_string`): the
    /// identifier is itself a ByteString.
    byte_string: struct { namespace: u16, id: ?[]const u8 },
};

/// §5.2.2.10 — a `NodeId` optionally qualified by a namespace URI (in place
/// of, or in addition to, the numeric namespace index) and/or a server index
/// for a NodeId living in another server's address space.
pub const ExpandedNodeId = struct {
    node_id: NodeId,
    /// Present when the encoding byte's `0x80` bit is set.
    namespace_uri: ?[]const u8 = null,
    /// Present when the encoding byte's `0x40` bit is set.
    server_index: ?u32 = null,
};

// ── QualifiedName / LocalizedText (§5.2.2.13-2.14) ──────────────────────────

/// §5.2.2.13 — a name qualified by a namespace index (e.g. a BrowseName).
pub const QualifiedName = struct {
    namespace_index: u16,
    name: ?[]const u8,
};

/// §5.2.2.14 — human-readable text tagged with an optional locale. The
/// encoding byte's bit `0x01` marks `locale` present, bit `0x02` marks `text`
/// present (both may be absent: an empty LocalizedText).
pub const LocalizedText = struct {
    locale: ?[]const u8 = null,
    text: ?[]const u8 = null,
};

// ── ExtensionObject (§5.2.2.15) ─────────────────────────────────────────────

/// The `Encoding` byte of an ExtensionObject: whether `body` is absent, a
/// ByteString (the common case — a binary-encoded structure), or an
/// XmlElement.
pub const ExtensionObjectEncoding = enum(u8) {
    no_body = 0x00,
    byte_string = 0x01,
    xml_element = 0x02,
};

/// A type-tagged opaque structure: `TypeId` names the DataType NodeId, `body`
/// holds its pre-encoded bytes in the shape `encoding` names. Decoding `body`
/// into a concrete struct is the caller's job (this module has no type
/// registry) — that's a later part's concern once one exists.
pub const ExtensionObject = struct {
    type_id: NodeId,
    encoding: ExtensionObjectEncoding,
    body: []const u8 = &.{},
};

// ── Variant (§5.2.2.16) ─────────────────────────────────────────────────────

/// One scalar built-in-typed value, tagged the same way the Variant encoding
/// byte's low 6 bits name a built-in type id (1..25 in the spec's Table;
/// `Variant`/`DataValue`/`DiagnosticInfo`-as-Variant-payload themselves are
/// deliberately excluded — the spec allows them but this module's scope stops
/// at scalar Read/Write values for F1).
pub const VariantScalar = union(enum) {
    boolean: bool,
    sbyte: i8,
    byte: u8,
    int16: i16,
    uint16: u16,
    int32: i32,
    uint32: u32,
    int64: i64,
    uint64: u64,
    float: f32,
    double: f64,
    string: ?[]const u8,
    date_time: DateTime,
    guid: Guid,
    byte_string: ?[]const u8,
    xml_element: ?[]const u8,
    node_id: NodeId,
    expanded_node_id: ExpandedNodeId,
    status_code: StatusCode,
    qualified_name: QualifiedName,
    localized_text: LocalizedText,
    extension_object: ExtensionObject,
};

/// A dynamically-typed value: `Read`/`Write`'s payload type — no value at all
/// (`.empty`, wire mask `0x00`), one scalar of a built-in type (`.scalar`,
/// mirrors `VariantScalar`), or an array of a built-in type (`.array`, wire
/// mask bit `0x80`, optionally `0x40` for multi-dimensional — OPC 10000-6
/// §5.2.2.16). A tagged union rather than `VariantScalar` plus a `bool` (or an
/// optional array field alongside `scalar`) makes "scalar and array both set"
/// — a combination the wire mask can never actually produce — unrepresentable.
pub const Variant = union(enum) {
    empty,
    scalar: VariantScalar,
    array: VariantArray,
};

/// The array-shaped half of `Variant`. `items` carries the flat element data
/// (one slice per built-in type, `null` = the wire's "null array" i.e. Int32
/// count `-1`, mirroring the `?[]const T` null/present-but-empty convention
/// `services.zig`'s `encodeArray`/`decodeArray` already use for every other
/// OPC UA array field — a present-but-empty slice is length 0, not `null`).
/// `dimensions` is present (non-`null`) only when the wire's ArrayDimensions
/// bit (`0x40`) is set: one `Int32` per dimension, product == the flat
/// array's element count. Multi-dimensional arrays are stored flat in
/// `items` either way — this module doesn't reshape them into a nested form.
pub const VariantArray = struct {
    items: VariantArrayItems,
    dimensions: ?[]const i32 = null,
};

/// One array-of-T payload per built-in type (OPC 10000-6 §5.2.2.16 Table 14),
/// the array-shaped mirror of `VariantScalar`.
pub const VariantArrayItems = union(enum) {
    boolean: ?[]const bool,
    sbyte: ?[]const i8,
    byte: ?[]const u8,
    int16: ?[]const i16,
    uint16: ?[]const u16,
    int32: ?[]const i32,
    uint32: ?[]const u32,
    int64: ?[]const i64,
    uint64: ?[]const u64,
    float: ?[]const f32,
    double: ?[]const f64,
    string: ?[]const ?[]const u8,
    date_time: ?[]const DateTime,
    guid: ?[]const Guid,
    byte_string: ?[]const ?[]const u8,
    xml_element: ?[]const ?[]const u8,
    node_id: ?[]const NodeId,
    expanded_node_id: ?[]const ExpandedNodeId,
    status_code: ?[]const StatusCode,
    qualified_name: ?[]const QualifiedName,
    localized_text: ?[]const LocalizedText,
    extension_object: ?[]const ExtensionObject,
};

/// Maps a scalar's active tag to the Variant encoding byte's built-in type id
/// (OPC 10000-6 §5.2.2.16 Table 14) — the mirror of the `switch` in
/// `Decoder.decodeVariantScalarBody`.
fn variantTypeId(v: VariantScalar) u8 {
    return switch (v) {
        .boolean => 1,
        .sbyte => 2,
        .byte => 3,
        .int16 => 4,
        .uint16 => 5,
        .int32 => 6,
        .uint32 => 7,
        .int64 => 8,
        .uint64 => 9,
        .float => 10,
        .double => 11,
        .string => 12,
        .date_time => 13,
        .guid => 14,
        .byte_string => 15,
        .xml_element => 16,
        .node_id => 17,
        .expanded_node_id => 18,
        .status_code => 19,
        .qualified_name => 20,
        .localized_text => 21,
        .extension_object => 22,
    };
}

/// Same mapping as `variantTypeId`, over `VariantArrayItems`'s tags instead —
/// the two enums name the same 22 built-in types 1:1, so the numeric ids
/// match exactly.
fn arrayTypeId(v: VariantArrayItems) u8 {
    return switch (v) {
        .boolean => 1,
        .sbyte => 2,
        .byte => 3,
        .int16 => 4,
        .uint16 => 5,
        .int32 => 6,
        .uint32 => 7,
        .int64 => 8,
        .uint64 => 9,
        .float => 10,
        .double => 11,
        .string => 12,
        .date_time => 13,
        .guid => 14,
        .byte_string => 15,
        .xml_element => 16,
        .node_id => 17,
        .expanded_node_id => 18,
        .status_code => 19,
        .qualified_name => 20,
        .localized_text => 21,
        .extension_object => 22,
    };
}

/// The array-of-`T` wire shape shared by every `VariantArrayItems` tag and by
/// a multi-dimensional Variant's `ArrayDimensions` (`Int32` count, `-1` =
/// null array — the same convention `services.zig`'s private `encodeArray`
/// helper uses for every other OPC UA array field; duplicated here in miniature
/// rather than imported since `encoding.zig` sits *below* `services.zig` in
/// this module's dependency graph and can't import it back).
fn encodeVariantArraySlice(e: *Encoder, comptime T: type, items: ?[]const T, comptime encodeItem: fn (*Encoder, T) EncodeError!void) EncodeError!void {
    const arr = items orelse {
        try e.writer.writeInt(i32, -1, .little);
        return;
    };
    if (arr.len > std.math.maxInt(i32)) return error.ValueTooLarge;
    try e.writer.writeInt(i32, @intCast(arr.len), .little);
    for (arr) |item| try encodeItem(e, item);
}

fn decodeVariantArraySlice(d: *Decoder, comptime T: type, comptime decodeItem: fn (*Decoder) DecodeError!T) DecodeError!?[]T {
    const len = try d.reader.takeInt(i32, .little);
    if (len == -1) return null;
    if (len < -1) return error.BadLength;
    const n: usize = @intCast(len);
    var list = try std.ArrayList(T).initCapacity(d.allocator, n);
    errdefer list.deinit(d.allocator);
    for (0..n) |_| list.appendAssumeCapacity(try decodeItem(d));
    return try list.toOwnedSlice(d.allocator);
}

// ── DataValue (§5.2.2.17) ───────────────────────────────────────────────────

/// A `Read`/`Write` result: a `Variant` plus quality/timestamp metadata. Every
/// field is optional — the wire encoding-mask byte says which of the 6 are
/// present; a field left `null` here is simply absent on the wire.
pub const DataValue = struct {
    value: ?Variant = null,
    status: ?StatusCode = null,
    source_timestamp: ?DateTime = null,
    source_pico_seconds: ?u16 = null,
    server_timestamp: ?DateTime = null,
    server_pico_seconds: ?u16 = null,
};

// ── DiagnosticInfo (§5.2.2.12) ──────────────────────────────────────────────

/// Extended error/diagnostic detail attached to a service response. The
/// string-ish fields are `i32` *indices* into a side table of strings
/// returned alongside the response (not inline text) per §5.2.2.12 — that
/// table isn't modeled here yet (a later, service-layer part's concern).
/// `inner_diagnostic_info` recurses; the implementing agent owns how that
/// recursion is allocated (owned pointer via the `Decoder`'s allocator, an
/// arena, or a bounded nesting-depth guard against a hostile peer).
pub const DiagnosticInfo = struct {
    symbolic_id: ?i32 = null,
    namespace_uri: ?i32 = null,
    locale: ?i32 = null,
    locale_specific_text: ?i32 = null,
    additional_info: ?[]const u8 = null,
    inner_status_code: ?StatusCode = null,
    inner_diagnostic_info: ?*DiagnosticInfo = null,
};

// ── Encoder ──────────────────────────────────────────────────────────────────

/// Writes OPC UA Binary values into a `std.Io.Writer` (any backing: `.fixed`
/// over a caller buffer, a real connection's buffered writer, …). No
/// allocation — every method borrows its argument's memory for the duration
/// of the call.
pub const Encoder = struct {
    writer: *std.Io.Writer,

    pub fn init(writer: *std.Io.Writer) Encoder {
        return .{ .writer = writer };
    }

    pub fn encodeBoolean(e: *Encoder, value: bool) EncodeError!void {
        try e.writer.writeByte(if (value) 1 else 0);
    }

    pub fn encodeSByte(e: *Encoder, value: i8) EncodeError!void {
        try e.writer.writeInt(i8, value, .little);
    }

    pub fn encodeByte(e: *Encoder, value: u8) EncodeError!void {
        try e.writer.writeByte(value);
    }

    pub fn encodeInt16(e: *Encoder, value: i16) EncodeError!void {
        try e.writer.writeInt(i16, value, .little);
    }

    pub fn encodeUInt16(e: *Encoder, value: u16) EncodeError!void {
        try e.writer.writeInt(u16, value, .little);
    }

    pub fn encodeInt32(e: *Encoder, value: i32) EncodeError!void {
        try e.writer.writeInt(i32, value, .little);
    }

    pub fn encodeUInt32(e: *Encoder, value: u32) EncodeError!void {
        try e.writer.writeInt(u32, value, .little);
    }

    pub fn encodeInt64(e: *Encoder, value: i64) EncodeError!void {
        try e.writer.writeInt(i64, value, .little);
    }

    pub fn encodeUInt64(e: *Encoder, value: u64) EncodeError!void {
        try e.writer.writeInt(u64, value, .little);
    }

    pub fn encodeFloat(e: *Encoder, value: f32) EncodeError!void {
        try e.writer.writeInt(u32, @bitCast(value), .little);
    }

    pub fn encodeDouble(e: *Encoder, value: f64) EncodeError!void {
        try e.writer.writeInt(u64, @bitCast(value), .little);
    }

    pub fn encodeString(e: *Encoder, value: ?[]const u8) EncodeError!void {
        const bytes = value orelse {
            try e.writer.writeInt(i32, -1, .little);
            return;
        };
        if (bytes.len > std.math.maxInt(i32)) return error.ValueTooLarge;
        try e.writer.writeInt(i32, @intCast(bytes.len), .little);
        try e.writer.writeAll(bytes);
    }

    pub fn encodeDateTime(e: *Encoder, value: DateTime) EncodeError!void {
        try e.writer.writeInt(i64, value, .little);
    }

    pub fn encodeGuid(e: *Encoder, value: Guid) EncodeError!void {
        try e.writer.writeInt(u32, value.data1, .little);
        try e.writer.writeInt(u16, value.data2, .little);
        try e.writer.writeInt(u16, value.data3, .little);
        try e.writer.writeAll(&value.data4);
    }

    pub fn encodeByteString(e: *Encoder, value: ?[]const u8) EncodeError!void {
        try e.encodeString(value);
    }

    pub fn encodeXmlElement(e: *Encoder, value: ?[]const u8) EncodeError!void {
        try e.encodeString(value);
    }

    pub fn encodeNodeId(e: *Encoder, value: NodeId) EncodeError!void {
        try e.encodeNodeIdFlagged(value, 0);
    }

    /// Shared by `encodeNodeId` (flags 0) and `encodeExpandedNodeId` (which
    /// ORs in the `0x80`/`0x40` NamespaceUri/ServerIndex flag bits on top of
    /// the same encoding byte) — OPC 10000-6 §5.2.2.9/§5.2.2.10.
    fn encodeNodeIdFlagged(e: *Encoder, value: NodeId, extra_flags: u8) EncodeError!void {
        switch (value) {
            .numeric => |v| {
                if (v.namespace == 0 and v.id <= std.math.maxInt(u8)) {
                    try e.writer.writeByte(extra_flags | @intFromEnum(NodeIdEncodingByte.two_byte));
                    try e.writer.writeByte(@intCast(v.id));
                } else if (v.namespace <= std.math.maxInt(u8) and v.id <= std.math.maxInt(u16)) {
                    try e.writer.writeByte(extra_flags | @intFromEnum(NodeIdEncodingByte.four_byte));
                    try e.writer.writeByte(@intCast(v.namespace));
                    try e.writer.writeInt(u16, @intCast(v.id), .little);
                } else {
                    try e.writer.writeByte(extra_flags | @intFromEnum(NodeIdEncodingByte.numeric));
                    try e.writer.writeInt(u16, v.namespace, .little);
                    try e.writer.writeInt(u32, v.id, .little);
                }
            },
            .string => |v| {
                try e.writer.writeByte(extra_flags | @intFromEnum(NodeIdEncodingByte.string));
                try e.writer.writeInt(u16, v.namespace, .little);
                try e.encodeString(v.id);
            },
            .guid => |v| {
                try e.writer.writeByte(extra_flags | @intFromEnum(NodeIdEncodingByte.guid));
                try e.writer.writeInt(u16, v.namespace, .little);
                try e.encodeGuid(v.id);
            },
            .byte_string => |v| {
                try e.writer.writeByte(extra_flags | @intFromEnum(NodeIdEncodingByte.byte_string));
                try e.writer.writeInt(u16, v.namespace, .little);
                try e.encodeByteString(v.id);
            },
        }
    }

    pub fn encodeExpandedNodeId(e: *Encoder, value: ExpandedNodeId) EncodeError!void {
        var flags: u8 = 0;
        if (value.namespace_uri != null) flags |= 0x80;
        if (value.server_index != null) flags |= 0x40;
        try e.encodeNodeIdFlagged(value.node_id, flags);
        if (value.namespace_uri) |uri| try e.encodeString(uri);
        if (value.server_index) |si| try e.writer.writeInt(u32, si, .little);
    }

    pub fn encodeStatusCode(e: *Encoder, value: StatusCode) EncodeError!void {
        try e.writer.writeInt(u32, value, .little);
    }

    pub fn encodeQualifiedName(e: *Encoder, value: QualifiedName) EncodeError!void {
        try e.writer.writeInt(u16, value.namespace_index, .little);
        try e.encodeString(value.name);
    }

    pub fn encodeLocalizedText(e: *Encoder, value: LocalizedText) EncodeError!void {
        var mask: u8 = 0;
        if (value.locale != null) mask |= 0x01;
        if (value.text != null) mask |= 0x02;
        try e.writer.writeByte(mask);
        if (value.locale) |l| try e.encodeString(l);
        if (value.text) |t| try e.encodeString(t);
    }

    pub fn encodeExtensionObject(e: *Encoder, value: ExtensionObject) EncodeError!void {
        try e.encodeNodeId(value.type_id);
        try e.writer.writeByte(@intFromEnum(value.encoding));
        switch (value.encoding) {
            .no_body => {},
            .byte_string, .xml_element => try e.encodeByteString(value.body),
        }
    }

    fn encodeVariantScalarBody(e: *Encoder, scalar: VariantScalar) EncodeError!void {
        switch (scalar) {
            .boolean => |x| try e.encodeBoolean(x),
            .sbyte => |x| try e.encodeSByte(x),
            .byte => |x| try e.encodeByte(x),
            .int16 => |x| try e.encodeInt16(x),
            .uint16 => |x| try e.encodeUInt16(x),
            .int32 => |x| try e.encodeInt32(x),
            .uint32 => |x| try e.encodeUInt32(x),
            .int64 => |x| try e.encodeInt64(x),
            .uint64 => |x| try e.encodeUInt64(x),
            .float => |x| try e.encodeFloat(x),
            .double => |x| try e.encodeDouble(x),
            .string => |x| try e.encodeString(x),
            .date_time => |x| try e.encodeDateTime(x),
            .guid => |x| try e.encodeGuid(x),
            .byte_string => |x| try e.encodeByteString(x),
            .xml_element => |x| try e.encodeXmlElement(x),
            .node_id => |x| try e.encodeNodeId(x),
            .expanded_node_id => |x| try e.encodeExpandedNodeId(x),
            .status_code => |x| try e.encodeStatusCode(x),
            .qualified_name => |x| try e.encodeQualifiedName(x),
            .localized_text => |x| try e.encodeLocalizedText(x),
            .extension_object => |x| try e.encodeExtensionObject(x),
        }
    }

    /// Writes just the array's element data (`Int32` count + elements, no
    /// type-id/mask byte) — shared by every `VariantArrayItems` tag via
    /// `encodeVariantArraySlice`.
    fn encodeVariantArrayItems(e: *Encoder, items: VariantArrayItems) EncodeError!void {
        switch (items) {
            .boolean => |v| try encodeVariantArraySlice(e, bool, v, Encoder.encodeBoolean),
            .sbyte => |v| try encodeVariantArraySlice(e, i8, v, Encoder.encodeSByte),
            .byte => |v| try encodeVariantArraySlice(e, u8, v, Encoder.encodeByte),
            .int16 => |v| try encodeVariantArraySlice(e, i16, v, Encoder.encodeInt16),
            .uint16 => |v| try encodeVariantArraySlice(e, u16, v, Encoder.encodeUInt16),
            .int32 => |v| try encodeVariantArraySlice(e, i32, v, Encoder.encodeInt32),
            .uint32 => |v| try encodeVariantArraySlice(e, u32, v, Encoder.encodeUInt32),
            .int64 => |v| try encodeVariantArraySlice(e, i64, v, Encoder.encodeInt64),
            .uint64 => |v| try encodeVariantArraySlice(e, u64, v, Encoder.encodeUInt64),
            .float => |v| try encodeVariantArraySlice(e, f32, v, Encoder.encodeFloat),
            .double => |v| try encodeVariantArraySlice(e, f64, v, Encoder.encodeDouble),
            .string => |v| try encodeVariantArraySlice(e, ?[]const u8, v, Encoder.encodeString),
            .date_time => |v| try encodeVariantArraySlice(e, DateTime, v, Encoder.encodeDateTime),
            .guid => |v| try encodeVariantArraySlice(e, Guid, v, Encoder.encodeGuid),
            .byte_string => |v| try encodeVariantArraySlice(e, ?[]const u8, v, Encoder.encodeByteString),
            .xml_element => |v| try encodeVariantArraySlice(e, ?[]const u8, v, Encoder.encodeXmlElement),
            .node_id => |v| try encodeVariantArraySlice(e, NodeId, v, Encoder.encodeNodeId),
            .expanded_node_id => |v| try encodeVariantArraySlice(e, ExpandedNodeId, v, Encoder.encodeExpandedNodeId),
            .status_code => |v| try encodeVariantArraySlice(e, StatusCode, v, Encoder.encodeStatusCode),
            .qualified_name => |v| try encodeVariantArraySlice(e, QualifiedName, v, Encoder.encodeQualifiedName),
            .localized_text => |v| try encodeVariantArraySlice(e, LocalizedText, v, Encoder.encodeLocalizedText),
            .extension_object => |v| try encodeVariantArraySlice(e, ExtensionObject, v, Encoder.encodeExtensionObject),
        }
    }

    pub fn encodeVariant(e: *Encoder, value: Variant) EncodeError!void {
        switch (value) {
            .empty => try e.writer.writeByte(0),
            .scalar => |scalar| {
                try e.writer.writeByte(variantTypeId(scalar));
                try e.encodeVariantScalarBody(scalar);
            },
            .array => |arr| {
                var mask: u8 = 0x80 | arrayTypeId(arr.items);
                if (arr.dimensions != null) mask |= 0x40;
                try e.writer.writeByte(mask);
                try e.encodeVariantArrayItems(arr.items);
                if (arr.dimensions) |dims| {
                    if (dims.len > std.math.maxInt(i32)) return error.ValueTooLarge;
                    try e.writer.writeInt(i32, @intCast(dims.len), .little);
                    for (dims) |dim| try e.writer.writeInt(i32, dim, .little);
                }
            },
        }
    }

    /// Wire order (matching field declaration order, verified against
    /// open62541's `DataValue_encodeBinary`): Value, StatusCode,
    /// SourceTimestamp, SourcePicoseconds, ServerTimestamp,
    /// ServerPicoseconds — note picoseconds are *not* adjacent to each other;
    /// each rides right after its own timestamp.
    pub fn encodeDataValue(e: *Encoder, value: DataValue) EncodeError!void {
        var mask: u8 = 0;
        if (value.value != null) mask |= 0x01;
        if (value.status != null) mask |= 0x02;
        if (value.source_timestamp != null) mask |= 0x04;
        if (value.server_timestamp != null) mask |= 0x08;
        if (value.source_pico_seconds != null) mask |= 0x10;
        if (value.server_pico_seconds != null) mask |= 0x20;
        try e.writer.writeByte(mask);
        if (value.value) |v| try e.encodeVariant(v);
        if (value.status) |s| try e.encodeStatusCode(s);
        if (value.source_timestamp) |t| try e.encodeDateTime(t);
        if (value.source_pico_seconds) |p| try e.writer.writeInt(u16, p, .little);
        if (value.server_timestamp) |t| try e.encodeDateTime(t);
        if (value.server_pico_seconds) |p| try e.writer.writeInt(u16, p, .little);
    }

    /// Wire order (verified against open62541's `DiagnosticInfo_encodeBinary`):
    /// SymbolicId, NamespaceUri, Locale, LocalizedText(-index), AdditionalInfo,
    /// InnerStatusCode, InnerDiagnosticInfo. Note the encoding-mask bits are
    /// *not* in this order (bit 0x04 is the LocalizedText index, bit 0x08 is
    /// Locale) — the mask numbers the fields differently than the order they
    /// are written in.
    pub fn encodeDiagnosticInfo(e: *Encoder, value: DiagnosticInfo) EncodeError!void {
        var mask: u8 = 0;
        if (value.symbolic_id != null) mask |= 0x01;
        if (value.namespace_uri != null) mask |= 0x02;
        if (value.locale_specific_text != null) mask |= 0x04;
        if (value.locale != null) mask |= 0x08;
        if (value.additional_info != null) mask |= 0x10;
        if (value.inner_status_code != null) mask |= 0x20;
        if (value.inner_diagnostic_info != null) mask |= 0x40;
        try e.writer.writeByte(mask);
        if (value.symbolic_id) |v| try e.writer.writeInt(i32, v, .little);
        if (value.namespace_uri) |v| try e.writer.writeInt(i32, v, .little);
        if (value.locale) |v| try e.writer.writeInt(i32, v, .little);
        if (value.locale_specific_text) |v| try e.writer.writeInt(i32, v, .little);
        if (value.additional_info) |v| try e.encodeString(v);
        if (value.inner_status_code) |v| try e.encodeStatusCode(v);
        if (value.inner_diagnostic_info) |v| try e.encodeDiagnosticInfo(v.*);
    }
};

// ── Decoder ──────────────────────────────────────────────────────────────────

/// Reads OPC UA Binary values from a `std.Io.Reader`. `allocator` backs the
/// owned copies that String/ByteString/NodeId(string|byte_string)/
/// QualifiedName/LocalizedText/ExtensionObject/DiagnosticInfo need (their
/// bytes cannot simply borrow the reader's internal buffer past the next
/// read) — callers arena/free per message.
pub const Decoder = struct {
    reader: *std.Io.Reader,
    allocator: std.mem.Allocator,

    pub fn init(reader: *std.Io.Reader, allocator: std.mem.Allocator) Decoder {
        return .{ .reader = reader, .allocator = allocator };
    }

    pub fn decodeBoolean(d: *Decoder) DecodeError!bool {
        return (try d.reader.takeByte()) != 0;
    }

    pub fn decodeSByte(d: *Decoder) DecodeError!i8 {
        return d.reader.takeInt(i8, .little);
    }

    pub fn decodeByte(d: *Decoder) DecodeError!u8 {
        return d.reader.takeByte();
    }

    pub fn decodeInt16(d: *Decoder) DecodeError!i16 {
        return d.reader.takeInt(i16, .little);
    }

    pub fn decodeUInt16(d: *Decoder) DecodeError!u16 {
        return d.reader.takeInt(u16, .little);
    }

    pub fn decodeInt32(d: *Decoder) DecodeError!i32 {
        return d.reader.takeInt(i32, .little);
    }

    pub fn decodeUInt32(d: *Decoder) DecodeError!u32 {
        return d.reader.takeInt(u32, .little);
    }

    pub fn decodeInt64(d: *Decoder) DecodeError!i64 {
        return d.reader.takeInt(i64, .little);
    }

    pub fn decodeUInt64(d: *Decoder) DecodeError!u64 {
        return d.reader.takeInt(u64, .little);
    }

    pub fn decodeFloat(d: *Decoder) DecodeError!f32 {
        return @bitCast(try d.reader.takeInt(u32, .little));
    }

    pub fn decodeDouble(d: *Decoder) DecodeError!f64 {
        return @bitCast(try d.reader.takeInt(u64, .little));
    }

    /// `null` = the OPC UA null string (Int32 length -1); `&.{}` = present but
    /// empty (length 0). Non-null results are allocator-owned.
    pub fn decodeString(d: *Decoder) DecodeError!?[]const u8 {
        const len = try d.reader.takeInt(i32, .little);
        if (len == -1) return null;
        if (len < -1) return error.BadLength;
        const n: usize = @intCast(len);
        // `take` bounds-checks against the reader's remaining input itself
        // (surfacing `error.EndOfStream`, part of `DecodeError` via
        // `std.Io.Reader.Error`), so a hostile huge length can't force a huge
        // allocation below — it fails here first.
        const bytes = try d.reader.take(n);
        return try d.allocator.dupe(u8, bytes);
    }

    pub fn decodeDateTime(d: *Decoder) DecodeError!DateTime {
        return d.reader.takeInt(i64, .little);
    }

    pub fn decodeGuid(d: *Decoder) DecodeError!Guid {
        const data1 = try d.reader.takeInt(u32, .little);
        const data2 = try d.reader.takeInt(u16, .little);
        const data3 = try d.reader.takeInt(u16, .little);
        const data4 = (try d.reader.takeArray(8)).*;
        return .{ .data1 = data1, .data2 = data2, .data3 = data3, .data4 = data4 };
    }

    pub fn decodeByteString(d: *Decoder) DecodeError!?[]const u8 {
        return d.decodeString();
    }

    pub fn decodeXmlElement(d: *Decoder) DecodeError!?[]const u8 {
        return d.decodeString();
    }

    /// Shared by `decodeNodeId` (which reads a bare encoding byte) and
    /// `decodeExpandedNodeId` (which additionally strips the `0x80`/`0x40`
    /// flag bits before dispatching here) — OPC 10000-6 §5.2.2.9 Table 7.
    fn decodeNodeIdBody(d: *Decoder, form: u8) DecodeError!NodeId {
        const eb: NodeIdEncodingByte = @enumFromInt(form);
        switch (eb) {
            .two_byte => return .{ .numeric = .{ .namespace = 0, .id = try d.decodeByte() } },
            .four_byte => {
                const ns = try d.decodeByte();
                const id = try d.decodeUInt16();
                return .{ .numeric = .{ .namespace = ns, .id = id } };
            },
            .numeric => {
                const ns = try d.decodeUInt16();
                const id = try d.decodeUInt32();
                return .{ .numeric = .{ .namespace = ns, .id = id } };
            },
            .string => {
                const ns = try d.decodeUInt16();
                const s = try d.decodeString();
                return .{ .string = .{ .namespace = ns, .id = s } };
            },
            .guid => {
                const ns = try d.decodeUInt16();
                const g = try d.decodeGuid();
                return .{ .guid = .{ .namespace = ns, .id = g } };
            },
            .byte_string => {
                const ns = try d.decodeUInt16();
                const bs = try d.decodeByteString();
                return .{ .byte_string = .{ .namespace = ns, .id = bs } };
            },
            _ => return error.BadEncodingByte,
        }
    }

    pub fn decodeNodeId(d: *Decoder) DecodeError!NodeId {
        const byte = try d.decodeByte();
        return d.decodeNodeIdBody(byte & 0x3f);
    }

    pub fn decodeExpandedNodeId(d: *Decoder) DecodeError!ExpandedNodeId {
        const byte = try d.decodeByte();
        const node_id = try d.decodeNodeIdBody(byte & 0x3f);
        var result: ExpandedNodeId = .{ .node_id = node_id };
        if (byte & 0x80 != 0) result.namespace_uri = try d.decodeString();
        if (byte & 0x40 != 0) result.server_index = try d.decodeUInt32();
        return result;
    }

    pub fn decodeStatusCode(d: *Decoder) DecodeError!StatusCode {
        return d.reader.takeInt(u32, .little);
    }

    pub fn decodeQualifiedName(d: *Decoder) DecodeError!QualifiedName {
        const ns = try d.decodeUInt16();
        const name = try d.decodeString();
        return .{ .namespace_index = ns, .name = name };
    }

    pub fn decodeLocalizedText(d: *Decoder) DecodeError!LocalizedText {
        const mask = try d.decodeByte();
        if (mask & ~@as(u8, 0x03) != 0) return error.BadEncodingByte;
        var result: LocalizedText = .{};
        if (mask & 0x01 != 0) result.locale = try d.decodeString();
        if (mask & 0x02 != 0) result.text = try d.decodeString();
        return result;
    }

    pub fn decodeExtensionObject(d: *Decoder) DecodeError!ExtensionObject {
        const type_id = try d.decodeNodeId();
        const enc_byte = try d.decodeByte();
        const encoding = std.enums.fromInt(ExtensionObjectEncoding, enc_byte) orelse return error.BadEncodingByte;
        var body: []const u8 = &.{};
        switch (encoding) {
            .no_body => {},
            .byte_string, .xml_element => body = (try d.decodeByteString()) orelse &.{},
        }
        return .{ .type_id = type_id, .encoding = encoding, .body = body };
    }

    fn decodeVariantScalarBody(d: *Decoder, type_id: u8) DecodeError!VariantScalar {
        return switch (type_id) {
            1 => .{ .boolean = try d.decodeBoolean() },
            2 => .{ .sbyte = try d.decodeSByte() },
            3 => .{ .byte = try d.decodeByte() },
            4 => .{ .int16 = try d.decodeInt16() },
            5 => .{ .uint16 = try d.decodeUInt16() },
            6 => .{ .int32 = try d.decodeInt32() },
            7 => .{ .uint32 = try d.decodeUInt32() },
            8 => .{ .int64 = try d.decodeInt64() },
            9 => .{ .uint64 = try d.decodeUInt64() },
            10 => .{ .float = try d.decodeFloat() },
            11 => .{ .double = try d.decodeDouble() },
            12 => .{ .string = try d.decodeString() },
            13 => .{ .date_time = try d.decodeDateTime() },
            14 => .{ .guid = try d.decodeGuid() },
            15 => .{ .byte_string = try d.decodeByteString() },
            16 => .{ .xml_element = try d.decodeXmlElement() },
            17 => .{ .node_id = try d.decodeNodeId() },
            18 => .{ .expanded_node_id = try d.decodeExpandedNodeId() },
            19 => .{ .status_code = try d.decodeStatusCode() },
            20 => .{ .qualified_name = try d.decodeQualifiedName() },
            21 => .{ .localized_text = try d.decodeLocalizedText() },
            22 => .{ .extension_object = try d.decodeExtensionObject() },
            // 23=DataValue, 24=Variant, 25=DiagnosticInfo as a Variant payload
            // — valid per spec but out of this module's scope (see the
            // module doc comment: F1's Read/Write payload scope stops at the
            // 22 "plain" built-in types; recursive Variant-of-Variant and
            // DataValue/DiagnosticInfo-as-payload are deliberately not
            // modeled, for scalars or arrays alike).
            23, 24, 25 => return error.UnsupportedType,
            else => return error.BadEncodingByte,
        };
    }

    /// Reads just the array's element data (`Int32` count + elements, no
    /// mask byte) for built-in type id `type_id` (1..22) — the array-shaped
    /// mirror of `decodeVariantScalarBody`.
    fn decodeVariantArrayItems(d: *Decoder, type_id: u8) DecodeError!VariantArrayItems {
        return switch (type_id) {
            1 => .{ .boolean = try decodeVariantArraySlice(d, bool, Decoder.decodeBoolean) },
            2 => .{ .sbyte = try decodeVariantArraySlice(d, i8, Decoder.decodeSByte) },
            3 => .{ .byte = try decodeVariantArraySlice(d, u8, Decoder.decodeByte) },
            4 => .{ .int16 = try decodeVariantArraySlice(d, i16, Decoder.decodeInt16) },
            5 => .{ .uint16 = try decodeVariantArraySlice(d, u16, Decoder.decodeUInt16) },
            6 => .{ .int32 = try decodeVariantArraySlice(d, i32, Decoder.decodeInt32) },
            7 => .{ .uint32 = try decodeVariantArraySlice(d, u32, Decoder.decodeUInt32) },
            8 => .{ .int64 = try decodeVariantArraySlice(d, i64, Decoder.decodeInt64) },
            9 => .{ .uint64 = try decodeVariantArraySlice(d, u64, Decoder.decodeUInt64) },
            10 => .{ .float = try decodeVariantArraySlice(d, f32, Decoder.decodeFloat) },
            11 => .{ .double = try decodeVariantArraySlice(d, f64, Decoder.decodeDouble) },
            12 => .{ .string = try decodeVariantArraySlice(d, ?[]const u8, Decoder.decodeString) },
            13 => .{ .date_time = try decodeVariantArraySlice(d, DateTime, Decoder.decodeDateTime) },
            14 => .{ .guid = try decodeVariantArraySlice(d, Guid, Decoder.decodeGuid) },
            15 => .{ .byte_string = try decodeVariantArraySlice(d, ?[]const u8, Decoder.decodeByteString) },
            16 => .{ .xml_element = try decodeVariantArraySlice(d, ?[]const u8, Decoder.decodeXmlElement) },
            17 => .{ .node_id = try decodeVariantArraySlice(d, NodeId, Decoder.decodeNodeId) },
            18 => .{ .expanded_node_id = try decodeVariantArraySlice(d, ExpandedNodeId, Decoder.decodeExpandedNodeId) },
            19 => .{ .status_code = try decodeVariantArraySlice(d, StatusCode, Decoder.decodeStatusCode) },
            20 => .{ .qualified_name = try decodeVariantArraySlice(d, QualifiedName, Decoder.decodeQualifiedName) },
            21 => .{ .localized_text = try decodeVariantArraySlice(d, LocalizedText, Decoder.decodeLocalizedText) },
            22 => .{ .extension_object = try decodeVariantArraySlice(d, ExtensionObject, Decoder.decodeExtensionObject) },
            23, 24, 25 => return error.UnsupportedType,
            else => return error.BadEncodingByte,
        };
    }

    pub fn decodeVariant(d: *Decoder) DecodeError!Variant {
        const mask = try d.decodeByte();
        if (mask == 0) return .empty;
        const type_id = mask & 0x3f;
        const is_array = mask & 0x80 != 0;
        const has_dims = mask & 0x40 != 0;
        if (!is_array) {
            // ArrayDimensions without ValueIsArray is a combination OPC
            // 10000-6 §5.2.2.16 never produces — reject it like any other
            // malformed encoding byte rather than silently ignoring the bit.
            if (has_dims) return error.BadEncodingByte;
            return .{ .scalar = try d.decodeVariantScalarBody(type_id) };
        }
        const items = try d.decodeVariantArrayItems(type_id);
        errdefer freeVariantArrayItems(d.allocator, items);
        const dimensions: ?[]const i32 = if (has_dims) try decodeVariantArraySlice(d, i32, Decoder.decodeInt32) else null;
        return .{ .array = .{ .items = items, .dimensions = dimensions } };
    }

    pub fn decodeDataValue(d: *Decoder) DecodeError!DataValue {
        const mask = try d.decodeByte();
        if (mask & 0xc0 != 0) return error.BadEncodingByte;
        var result: DataValue = .{};
        if (mask & 0x01 != 0) result.value = try d.decodeVariant();
        if (mask & 0x02 != 0) result.status = try d.decodeStatusCode();
        if (mask & 0x04 != 0) result.source_timestamp = try d.decodeDateTime();
        if (mask & 0x10 != 0) result.source_pico_seconds = try d.decodeUInt16();
        if (mask & 0x08 != 0) result.server_timestamp = try d.decodeDateTime();
        if (mask & 0x20 != 0) result.server_pico_seconds = try d.decodeUInt16();
        return result;
    }

    pub fn decodeDiagnosticInfo(d: *Decoder) DecodeError!DiagnosticInfo {
        const mask = try d.decodeByte();
        if (mask & 0x80 != 0) return error.BadEncodingByte;
        var result: DiagnosticInfo = .{};
        if (mask & 0x01 != 0) result.symbolic_id = try d.decodeInt32();
        if (mask & 0x02 != 0) result.namespace_uri = try d.decodeInt32();
        if (mask & 0x08 != 0) result.locale = try d.decodeInt32();
        if (mask & 0x04 != 0) result.locale_specific_text = try d.decodeInt32();
        if (mask & 0x10 != 0) result.additional_info = try d.decodeString();
        if (mask & 0x20 != 0) result.inner_status_code = try d.decodeStatusCode();
        if (mask & 0x40 != 0) {
            const inner = try d.allocator.create(DiagnosticInfo);
            errdefer d.allocator.destroy(inner);
            inner.* = try d.decodeDiagnosticInfo();
            result.inner_diagnostic_info = inner;
        }
        return result;
    }
};

// ── free helpers ─────────────────────────────────────────────────────────────
// Mirrors `services.zig`'s `free*` idiom (a plain function per owned type,
// `allocator.free`/`.destroy` on exactly what `decode*` allocated) — needed
// here now that `Variant`/`DataValue` can themselves own heap memory (array
// elements, and scalar String/NodeId(string|byte_string)/QualifiedName/
// LocalizedText/ExtensionObject payloads), which `services.zig`'s Part 4
// response types (`ReadResponse`, `BrowseResponse`, …) embed.

fn freeOptStr(a: std.mem.Allocator, s: ?[]const u8) void {
    if (s) |bytes| a.free(bytes);
}

/// Frees the owned string inside a `.string`/`.byte_string` `NodeId`
/// (`.numeric`/`.guid` own no memory).
pub fn freeNodeId(a: std.mem.Allocator, v: NodeId) void {
    switch (v) {
        .numeric, .guid => {},
        .string => |s| freeOptStr(a, s.id),
        .byte_string => |s| freeOptStr(a, s.id),
    }
}

pub fn freeExpandedNodeId(a: std.mem.Allocator, v: ExpandedNodeId) void {
    freeNodeId(a, v.node_id);
    freeOptStr(a, v.namespace_uri);
}

pub fn freeQualifiedName(a: std.mem.Allocator, v: QualifiedName) void {
    freeOptStr(a, v.name);
}

pub fn freeLocalizedText(a: std.mem.Allocator, v: LocalizedText) void {
    freeOptStr(a, v.locale);
    freeOptStr(a, v.text);
}

pub fn freeExtensionObject(a: std.mem.Allocator, v: ExtensionObject) void {
    freeNodeId(a, v.type_id);
    if (v.body.len != 0) a.free(v.body);
}

pub fn freeVariantScalar(a: std.mem.Allocator, v: VariantScalar) void {
    switch (v) {
        .string, .byte_string, .xml_element => |s| freeOptStr(a, s),
        .node_id => |n| freeNodeId(a, n),
        .expanded_node_id => |en| freeExpandedNodeId(a, en),
        .qualified_name => |q| freeQualifiedName(a, q),
        .localized_text => |lt| freeLocalizedText(a, lt),
        .extension_object => |eo| freeExtensionObject(a, eo),
        .boolean, .sbyte, .byte, .int16, .uint16, .int32, .uint32, .int64, .uint64, .float, .double, .date_time, .guid, .status_code => {},
    }
}

fn freeOptStrArray(a: std.mem.Allocator, arr: ?[]const ?[]const u8) void {
    if (arr) |items| {
        for (items) |s| freeOptStr(a, s);
        a.free(items);
    }
}

pub fn freeVariantArrayItems(a: std.mem.Allocator, v: VariantArrayItems) void {
    switch (v) {
        inline .boolean, .sbyte, .byte, .int16, .uint16, .int32, .uint32, .int64, .uint64, .float, .double, .date_time, .guid, .status_code => |arr| if (arr) |s| a.free(s),
        .string, .byte_string, .xml_element => |arr| freeOptStrArray(a, arr),
        .node_id => |arr| if (arr) |items| {
            for (items) |n| freeNodeId(a, n);
            a.free(items);
        },
        .expanded_node_id => |arr| if (arr) |items| {
            for (items) |n| freeExpandedNodeId(a, n);
            a.free(items);
        },
        .qualified_name => |arr| if (arr) |items| {
            for (items) |q| freeQualifiedName(a, q);
            a.free(items);
        },
        .localized_text => |arr| if (arr) |items| {
            for (items) |lt| freeLocalizedText(a, lt);
            a.free(items);
        },
        .extension_object => |arr| if (arr) |items| {
            for (items) |eo| freeExtensionObject(a, eo);
            a.free(items);
        },
    }
}

pub fn freeVariant(a: std.mem.Allocator, v: Variant) void {
    switch (v) {
        .empty => {},
        .scalar => |s| freeVariantScalar(a, s),
        .array => |arr| {
            freeVariantArrayItems(a, arr.items);
            if (arr.dimensions) |d| a.free(d);
        },
    }
}

pub fn freeDataValue(a: std.mem.Allocator, v: DataValue) void {
    if (v.value) |val| freeVariant(a, val);
}

// ── tests ──

test "types are constructible (no encode/decode invoked)" {
    const testing = std.testing;
    const nid: NodeId = .{ .numeric = .{ .namespace = 0, .id = 2258 } };
    try testing.expect(nid == .numeric);
    const v: Variant = .{ .scalar = .{ .uint32 = 42 } };
    try testing.expect(v == .scalar);
    try testing.expect(v.scalar == .uint32);
}

fn testWriter(buf: []u8) std.Io.Writer {
    return .fixed(buf);
}

test "Boolean/SByte/Byte round-trip + KAT" {
    const testing = std.testing;
    var buf: [16]u8 = undefined;
    var w = testWriter(&buf);
    var e = Encoder.init(&w);
    try e.encodeBoolean(true);
    try e.encodeBoolean(false);
    try e.encodeSByte(-1);
    try e.encodeByte(0xff);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x00, 0xff, 0xff }, w.buffered());

    var r: std.Io.Reader = .fixed(w.buffered());
    var d = Decoder.init(&r, testing.allocator);
    try testing.expectEqual(true, try d.decodeBoolean());
    try testing.expectEqual(false, try d.decodeBoolean());
    try testing.expectEqual(@as(i8, -1), try d.decodeSByte());
    try testing.expectEqual(@as(u8, 0xff), try d.decodeByte());
}

test "integers little-endian KAT" {
    const testing = std.testing;
    var buf: [32]u8 = undefined;
    var w = testWriter(&buf);
    var e = Encoder.init(&w);
    try e.encodeInt16(-2);
    try e.encodeUInt16(0x1234);
    try e.encodeInt32(-2);
    try e.encodeUInt32(0x12345678);
    try e.encodeInt64(-2);
    try e.encodeUInt64(0x0123456789abcdef);
    try testing.expectEqualSlices(u8, &.{
        0xfe, 0xff, // Int16 -2
        0x34, 0x12, // UInt16
        0xfe, 0xff, 0xff, 0xff, // Int32 -2
        0x78, 0x56, 0x34, 0x12, // UInt32
        0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Int64 -2
        0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, // UInt64
    }, w.buffered());
}

test "Float/Double IEEE-754 LE KAT" {
    const testing = std.testing;
    var buf: [16]u8 = undefined;
    var w = testWriter(&buf);
    var e = Encoder.init(&w);
    try e.encodeFloat(1.0);
    try e.encodeDouble(1.0);
    // f32 1.0 = 0x3F800000, f64 1.0 = 0x3FF0000000000000, both LE.
    try testing.expectEqualSlices(u8, &.{
        0x00, 0x00, 0x80, 0x3f,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xf0, 0x3f,
    }, w.buffered());

    var r: std.Io.Reader = .fixed(w.buffered());
    var d = Decoder.init(&r, testing.allocator);
    try testing.expectEqual(@as(f32, 1.0), try d.decodeFloat());
    try testing.expectEqual(@as(f64, 1.0), try d.decodeDouble());
}

test "String: present, empty, null" {
    const testing = std.testing;
    var buf: [64]u8 = undefined;
    var w = testWriter(&buf);
    var e = Encoder.init(&w);
    try e.encodeString("hi");
    try e.encodeString(&.{});
    try e.encodeString(null);
    try testing.expectEqualSlices(u8, &.{
        0x02, 0x00, 0x00, 0x00, 'h', 'i', // len=2 "hi"
        0x00, 0x00, 0x00, 0x00, // len=0 present-but-empty
        0xff, 0xff, 0xff, 0xff, // len=-1 null
    }, w.buffered());

    var r: std.Io.Reader = .fixed(w.buffered());
    var d = Decoder.init(&r, testing.allocator);
    const s1 = (try d.decodeString()).?;
    defer testing.allocator.free(s1);
    try testing.expectEqualStrings("hi", s1);
    const s2 = (try d.decodeString()).?;
    defer testing.allocator.free(s2);
    try testing.expectEqual(@as(usize, 0), s2.len);
    try testing.expectEqual(@as(?[]const u8, null), try d.decodeString());
}

test "DateTime round-trip" {
    const testing = std.testing;
    var buf: [8]u8 = undefined;
    var w = testWriter(&buf);
    var e = Encoder.init(&w);
    // An arbitrary known instant expressed as 100ns ticks since 1601-01-01.
    const instant: DateTime = 132223104000000000;
    try e.encodeDateTime(instant);
    var r: std.Io.Reader = .fixed(w.buffered());
    var d = Decoder.init(&r, testing.allocator);
    try testing.expectEqual(instant, try d.decodeDateTime());
}

test "Guid round-trip" {
    const testing = std.testing;
    var buf: [16]u8 = undefined;
    var w = testWriter(&buf);
    var e = Encoder.init(&w);
    const g: Guid = .{ .data1 = 0x72962b91, .data2 = 0xfa75, .data3 = 0x4ae6, .data4 = .{ 0x8d, 0x28, 0xb4, 0x04, 0xdc, 0x7d, 0xaf, 0x63 } };
    try e.encodeGuid(g);
    try testing.expectEqualSlices(u8, &.{
        0x91, 0x2b, 0x96, 0x72, // Data1 LE
        0x75, 0xfa, // Data2 LE
        0xe6, 0x4a, // Data3 LE
        0x8d, 0x28, 0xb4, 0x04, 0xdc, 0x7d, 0xaf, 0x63, // Data4 raw
    }, w.buffered());
    var r: std.Io.Reader = .fixed(w.buffered());
    var d = Decoder.init(&r, testing.allocator);
    const g2 = try d.decodeGuid();
    try testing.expectEqualDeep(g, g2);
}

test "NodeId: two-byte form KAT + round-trip" {
    const testing = std.testing;
    var buf: [16]u8 = undefined;
    var w = testWriter(&buf);
    var e = Encoder.init(&w);
    const two_byte: NodeId = .{ .numeric = .{ .namespace = 0, .id = 13 } };
    try e.encodeNodeId(two_byte);
    try testing.expectEqualSlices(u8, &.{ 0x00, 13 }, w.buffered());

    var r: std.Io.Reader = .fixed(w.buffered());
    var d = Decoder.init(&r, testing.allocator);
    const decoded = try d.decodeNodeId();
    try testing.expectEqualDeep(two_byte, decoded);
}

test "NodeId: four-byte form KAT + round-trip" {
    const testing = std.testing;
    var buf: [16]u8 = undefined;
    var w = testWriter(&buf);
    var e = Encoder.init(&w);
    // ns=0 forces four-byte once id > 255 (matches open62541: FOURBYTE when
    // `numeric > u8_max || ns > 0`).
    const four_byte: NodeId = .{ .numeric = .{ .namespace = 0, .id = 500 } };
    try e.encodeNodeId(four_byte);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x00, 0xf4, 0x01 }, w.buffered());

    var r: std.Io.Reader = .fixed(w.buffered());
    var d = Decoder.init(&r, testing.allocator);
    try testing.expectEqualDeep(four_byte, try d.decodeNodeId());
}

test "NodeId: numeric (complete) form KAT + round-trip" {
    const testing = std.testing;
    var buf: [16]u8 = undefined;
    var w = testWriter(&buf);
    var e = Encoder.init(&w);
    // id=70000 > UInt16 max forces the "complete" numeric form regardless of
    // namespace (matches open62541: COMPLETE when `numeric > UInt16Max ||
    // nsIndex > ByteMax`).
    const numeric: NodeId = .{ .numeric = .{ .namespace = 10, .id = 70000 } };
    try e.encodeNodeId(numeric);
    try testing.expectEqualSlices(u8, &.{ 0x02, 0x0a, 0x00, 0x70, 0x11, 0x01, 0x00 }, w.buffered());

    var r: std.Io.Reader = .fixed(w.buffered());
    var d = Decoder.init(&r, testing.allocator);
    try testing.expectEqualDeep(numeric, try d.decodeNodeId());
}

test "NodeId: numeric form via oversize namespace (ns > 255 forces complete even for a small id)" {
    const testing = std.testing;
    var buf: [16]u8 = undefined;
    var w = testWriter(&buf);
    var e = Encoder.init(&w);
    const numeric: NodeId = .{ .numeric = .{ .namespace = 300, .id = 5 } };
    try e.encodeNodeId(numeric);
    try testing.expectEqual(@as(u8, 0x02), w.buffered()[0]);
    var r: std.Io.Reader = .fixed(w.buffered());
    var d = Decoder.init(&r, testing.allocator);
    try testing.expectEqualDeep(numeric, try d.decodeNodeId());
}

test "NodeId: string/guid/byte_string forms round-trip" {
    const testing = std.testing;
    var buf: [64]u8 = undefined;

    {
        var w = testWriter(&buf);
        var e = Encoder.init(&w);
        const nid: NodeId = .{ .string = .{ .namespace = 1, .id = "hello" } };
        try e.encodeNodeId(nid);
        var r: std.Io.Reader = .fixed(w.buffered());
        var d = Decoder.init(&r, testing.allocator);
        const decoded = try d.decodeNodeId();
        defer testing.allocator.free(decoded.string.id.?);
        try testing.expectEqual(@as(u16, 1), decoded.string.namespace);
        try testing.expectEqualStrings("hello", decoded.string.id.?);
    }
    {
        var w = testWriter(&buf);
        var e = Encoder.init(&w);
        const g: Guid = .{ .data1 = 1, .data2 = 2, .data3 = 3, .data4 = .{0} ** 8 };
        const nid: NodeId = .{ .guid = .{ .namespace = 2, .id = g } };
        try e.encodeNodeId(nid);
        var r: std.Io.Reader = .fixed(w.buffered());
        var d = Decoder.init(&r, testing.allocator);
        const decoded = try d.decodeNodeId();
        try testing.expectEqualDeep(nid, decoded);
    }
    {
        var w = testWriter(&buf);
        var e = Encoder.init(&w);
        const nid: NodeId = .{ .byte_string = .{ .namespace = 3, .id = "\x01\x02\x03" } };
        try e.encodeNodeId(nid);
        var r: std.Io.Reader = .fixed(w.buffered());
        var d = Decoder.init(&r, testing.allocator);
        const decoded = try d.decodeNodeId();
        defer testing.allocator.free(decoded.byte_string.id.?);
        try testing.expectEqual(@as(u16, 3), decoded.byte_string.namespace);
        try testing.expectEqualStrings("\x01\x02\x03", decoded.byte_string.id.?);
    }
}

test "ExpandedNodeId: flags + round-trip" {
    const testing = std.testing;
    var buf: [64]u8 = undefined;
    var w = testWriter(&buf);
    var e = Encoder.init(&w);
    const enid: ExpandedNodeId = .{
        .node_id = .{ .numeric = .{ .namespace = 0, .id = 5 } },
        .namespace_uri = "urn:example",
        .server_index = 7,
    };
    try e.encodeExpandedNodeId(enid);
    // encoding byte: two_byte(0x00) | namespace_uri(0x80) | server_index(0x40)
    try testing.expectEqual(@as(u8, 0xc0), w.buffered()[0]);

    var r: std.Io.Reader = .fixed(w.buffered());
    var d = Decoder.init(&r, testing.allocator);
    const decoded = try d.decodeExpandedNodeId();
    defer testing.allocator.free(decoded.namespace_uri.?);
    try testing.expectEqualDeep(enid.node_id, decoded.node_id);
    try testing.expectEqualStrings("urn:example", decoded.namespace_uri.?);
    try testing.expectEqual(@as(?u32, 7), decoded.server_index);
}

test "QualifiedName / LocalizedText round-trip" {
    const testing = std.testing;
    var buf: [64]u8 = undefined;

    {
        var w = testWriter(&buf);
        var e = Encoder.init(&w);
        const qn: QualifiedName = .{ .namespace_index = 3, .name = "Temperature" };
        try e.encodeQualifiedName(qn);
        var r: std.Io.Reader = .fixed(w.buffered());
        var d = Decoder.init(&r, testing.allocator);
        const decoded = try d.decodeQualifiedName();
        defer testing.allocator.free(decoded.name.?);
        try testing.expectEqual(@as(u16, 3), decoded.namespace_index);
        try testing.expectEqualStrings("Temperature", decoded.name.?);
    }
    {
        var w = testWriter(&buf);
        var e = Encoder.init(&w);
        const lt: LocalizedText = .{ .locale = "en-US", .text = "Hello" };
        try e.encodeLocalizedText(lt);
        try testing.expectEqual(@as(u8, 0x03), w.buffered()[0]);
        var r: std.Io.Reader = .fixed(w.buffered());
        var d = Decoder.init(&r, testing.allocator);
        const decoded = try d.decodeLocalizedText();
        defer testing.allocator.free(decoded.locale.?);
        defer testing.allocator.free(decoded.text.?);
        try testing.expectEqualStrings("en-US", decoded.locale.?);
        try testing.expectEqualStrings("Hello", decoded.text.?);
    }
    {
        // Empty LocalizedText: mask 0x00, no fields follow.
        var w = testWriter(&buf);
        var e = Encoder.init(&w);
        try e.encodeLocalizedText(.{});
        try testing.expectEqualSlices(u8, &.{0x00}, w.buffered());
    }
}

test "ExtensionObject: no_body / byte_string round-trip" {
    const testing = std.testing;
    var buf: [64]u8 = undefined;

    {
        var w = testWriter(&buf);
        var e = Encoder.init(&w);
        const eo: ExtensionObject = .{ .type_id = .{ .numeric = .{ .namespace = 0, .id = 297 } }, .encoding = .no_body };
        try e.encodeExtensionObject(eo);
        var r: std.Io.Reader = .fixed(w.buffered());
        var d = Decoder.init(&r, testing.allocator);
        const decoded = try d.decodeExtensionObject();
        try testing.expectEqualDeep(eo.type_id, decoded.type_id);
        try testing.expectEqual(ExtensionObjectEncoding.no_body, decoded.encoding);
        try testing.expectEqual(@as(usize, 0), decoded.body.len);
    }
    {
        var w = testWriter(&buf);
        var e = Encoder.init(&w);
        const eo: ExtensionObject = .{
            .type_id = .{ .numeric = .{ .namespace = 0, .id = 297 } },
            .encoding = .byte_string,
            .body = "\xde\xad\xbe\xef",
        };
        try e.encodeExtensionObject(eo);
        var r: std.Io.Reader = .fixed(w.buffered());
        var d = Decoder.init(&r, testing.allocator);
        const decoded = try d.decodeExtensionObject();
        defer testing.allocator.free(decoded.body);
        try testing.expectEqual(ExtensionObjectEncoding.byte_string, decoded.encoding);
        try testing.expectEqualSlices(u8, "\xde\xad\xbe\xef", decoded.body);
    }
}

test "Variant: Int32 scalar KAT + round-trip" {
    const testing = std.testing;
    var buf: [16]u8 = undefined;
    var w = testWriter(&buf);
    var e = Encoder.init(&w);
    const v: Variant = .{ .scalar = .{ .int32 = 42 } };
    try e.encodeVariant(v);
    // encoding byte = 6 (Int32's built-in type id), then Int32 LE.
    try testing.expectEqualSlices(u8, &.{ 6, 42, 0, 0, 0 }, w.buffered());

    var r: std.Io.Reader = .fixed(w.buffered());
    var d = Decoder.init(&r, testing.allocator);
    const decoded = try d.decodeVariant();
    try testing.expectEqual(@as(i32, 42), decoded.scalar.int32);
}

test "Variant: empty + String scalar round-trip" {
    const testing = std.testing;
    var buf: [32]u8 = undefined;

    {
        var w = testWriter(&buf);
        var e = Encoder.init(&w);
        try e.encodeVariant(.empty);
        try testing.expectEqualSlices(u8, &.{0}, w.buffered());
        var r: std.Io.Reader = .fixed(w.buffered());
        var d = Decoder.init(&r, testing.allocator);
        const decoded = try d.decodeVariant();
        try testing.expectEqual(@as(Variant, .empty), decoded);
    }
    {
        var w = testWriter(&buf);
        var e = Encoder.init(&w);
        try e.encodeVariant(.{ .scalar = .{ .string = "hi" } });
        var r: std.Io.Reader = .fixed(w.buffered());
        var d = Decoder.init(&r, testing.allocator);
        const decoded = try d.decodeVariant();
        defer freeVariant(testing.allocator, decoded);
        try testing.expectEqualStrings("hi", decoded.scalar.string.?);
    }
}

// ── Variant arrays (0x80 ValueIsArray / 0x40 ArrayDimensions) ───────────────

test "Variant array: every built-in type round-trips (present array)" {
    const testing = std.testing;
    var buf: [1024]u8 = undefined;

    {
        var w = testWriter(&buf);
        var e = Encoder.init(&w);
        const arr = [_]bool{ true, false, true };
        try e.encodeVariant(.{ .array = .{ .items = .{ .boolean = &arr } } });
        try testing.expectEqualSlices(u8, &.{ 0x80 | 1, 3, 0, 0, 0, 1, 0, 1 }, w.buffered());
        var r: std.Io.Reader = .fixed(w.buffered());
        var d = Decoder.init(&r, testing.allocator);
        const decoded = try d.decodeVariant();
        defer freeVariant(testing.allocator, decoded);
        try testing.expect(decoded == .array);
        try testing.expectEqualSlices(bool, &arr, decoded.array.items.boolean.?);
    }
    {
        var w = testWriter(&buf);
        var e = Encoder.init(&w);
        const arr = [_]i8{ -1, 2, -3 };
        try e.encodeVariant(.{ .array = .{ .items = .{ .sbyte = &arr } } });
        var r: std.Io.Reader = .fixed(w.buffered());
        var d = Decoder.init(&r, testing.allocator);
        const decoded = try d.decodeVariant();
        defer freeVariant(testing.allocator, decoded);
        try testing.expectEqualSlices(i8, &arr, decoded.array.items.sbyte.?);
    }
    {
        var w = testWriter(&buf);
        var e = Encoder.init(&w);
        const arr = [_]u8{ 1, 2, 3 };
        try e.encodeVariant(.{ .array = .{ .items = .{ .byte = &arr } } });
        var r: std.Io.Reader = .fixed(w.buffered());
        var d = Decoder.init(&r, testing.allocator);
        const decoded = try d.decodeVariant();
        defer freeVariant(testing.allocator, decoded);
        try testing.expectEqualSlices(u8, &arr, decoded.array.items.byte.?);
    }
    {
        var w = testWriter(&buf);
        var e = Encoder.init(&w);
        const arr = [_]i16{ -1, 2 };
        try e.encodeVariant(.{ .array = .{ .items = .{ .int16 = &arr } } });
        var r: std.Io.Reader = .fixed(w.buffered());
        var d = Decoder.init(&r, testing.allocator);
        const decoded = try d.decodeVariant();
        defer freeVariant(testing.allocator, decoded);
        try testing.expectEqualSlices(i16, &arr, decoded.array.items.int16.?);
    }
    {
        var w = testWriter(&buf);
        var e = Encoder.init(&w);
        const arr = [_]u16{ 1, 2 };
        try e.encodeVariant(.{ .array = .{ .items = .{ .uint16 = &arr } } });
        var r: std.Io.Reader = .fixed(w.buffered());
        var d = Decoder.init(&r, testing.allocator);
        const decoded = try d.decodeVariant();
        defer freeVariant(testing.allocator, decoded);
        try testing.expectEqualSlices(u16, &arr, decoded.array.items.uint16.?);
    }
    {
        var w = testWriter(&buf);
        var e = Encoder.init(&w);
        const arr = [_]i32{ -1, 2, 3 };
        try e.encodeVariant(.{ .array = .{ .items = .{ .int32 = &arr } } });
        var r: std.Io.Reader = .fixed(w.buffered());
        var d = Decoder.init(&r, testing.allocator);
        const decoded = try d.decodeVariant();
        defer freeVariant(testing.allocator, decoded);
        try testing.expectEqualSlices(i32, &arr, decoded.array.items.int32.?);
    }
    {
        var w = testWriter(&buf);
        var e = Encoder.init(&w);
        const arr = [_]u32{ 1, 2, 3 };
        try e.encodeVariant(.{ .array = .{ .items = .{ .uint32 = &arr } } });
        var r: std.Io.Reader = .fixed(w.buffered());
        var d = Decoder.init(&r, testing.allocator);
        const decoded = try d.decodeVariant();
        defer freeVariant(testing.allocator, decoded);
        try testing.expectEqualSlices(u32, &arr, decoded.array.items.uint32.?);
    }
    {
        var w = testWriter(&buf);
        var e = Encoder.init(&w);
        const arr = [_]i64{ -1, 2 };
        try e.encodeVariant(.{ .array = .{ .items = .{ .int64 = &arr } } });
        var r: std.Io.Reader = .fixed(w.buffered());
        var d = Decoder.init(&r, testing.allocator);
        const decoded = try d.decodeVariant();
        defer freeVariant(testing.allocator, decoded);
        try testing.expectEqualSlices(i64, &arr, decoded.array.items.int64.?);
    }
    {
        var w = testWriter(&buf);
        var e = Encoder.init(&w);
        const arr = [_]u64{ 1, 2 };
        try e.encodeVariant(.{ .array = .{ .items = .{ .uint64 = &arr } } });
        var r: std.Io.Reader = .fixed(w.buffered());
        var d = Decoder.init(&r, testing.allocator);
        const decoded = try d.decodeVariant();
        defer freeVariant(testing.allocator, decoded);
        try testing.expectEqualSlices(u64, &arr, decoded.array.items.uint64.?);
    }
    {
        var w = testWriter(&buf);
        var e = Encoder.init(&w);
        const arr = [_]f32{ 1.5, -2.5 };
        try e.encodeVariant(.{ .array = .{ .items = .{ .float = &arr } } });
        var r: std.Io.Reader = .fixed(w.buffered());
        var d = Decoder.init(&r, testing.allocator);
        const decoded = try d.decodeVariant();
        defer freeVariant(testing.allocator, decoded);
        try testing.expectEqualSlices(f32, &arr, decoded.array.items.float.?);
    }
    {
        var w = testWriter(&buf);
        var e = Encoder.init(&w);
        const arr = [_]f64{ 1.5, -2.5 };
        try e.encodeVariant(.{ .array = .{ .items = .{ .double = &arr } } });
        var r: std.Io.Reader = .fixed(w.buffered());
        var d = Decoder.init(&r, testing.allocator);
        const decoded = try d.decodeVariant();
        defer freeVariant(testing.allocator, decoded);
        try testing.expectEqualSlices(f64, &arr, decoded.array.items.double.?);
    }
    {
        var w = testWriter(&buf);
        var e = Encoder.init(&w);
        const arr = [_]?[]const u8{ "hello", "", null };
        try e.encodeVariant(.{ .array = .{ .items = .{ .string = &arr } } });
        var r: std.Io.Reader = .fixed(w.buffered());
        var d = Decoder.init(&r, testing.allocator);
        const decoded = try d.decodeVariant();
        defer freeVariant(testing.allocator, decoded);
        const got = decoded.array.items.string.?;
        try testing.expectEqualStrings("hello", got[0].?);
        try testing.expectEqual(@as(usize, 0), got[1].?.len);
        try testing.expectEqual(@as(?[]const u8, null), got[2]);
    }
    {
        var w = testWriter(&buf);
        var e = Encoder.init(&w);
        const arr = [_]DateTime{ 1, 2 };
        try e.encodeVariant(.{ .array = .{ .items = .{ .date_time = &arr } } });
        var r: std.Io.Reader = .fixed(w.buffered());
        var d = Decoder.init(&r, testing.allocator);
        const decoded = try d.decodeVariant();
        defer freeVariant(testing.allocator, decoded);
        try testing.expectEqualSlices(DateTime, &arr, decoded.array.items.date_time.?);
    }
    {
        var w = testWriter(&buf);
        var e = Encoder.init(&w);
        const arr = [_]Guid{.{ .data1 = 1, .data2 = 2, .data3 = 3, .data4 = .{0} ** 8 }};
        try e.encodeVariant(.{ .array = .{ .items = .{ .guid = &arr } } });
        var r: std.Io.Reader = .fixed(w.buffered());
        var d = Decoder.init(&r, testing.allocator);
        const decoded = try d.decodeVariant();
        defer freeVariant(testing.allocator, decoded);
        try testing.expectEqualDeep(&arr, decoded.array.items.guid.?);
    }
    {
        var w = testWriter(&buf);
        var e = Encoder.init(&w);
        const arr = [_]?[]const u8{ "\xde\xad", null };
        try e.encodeVariant(.{ .array = .{ .items = .{ .byte_string = &arr } } });
        var r: std.Io.Reader = .fixed(w.buffered());
        var d = Decoder.init(&r, testing.allocator);
        const decoded = try d.decodeVariant();
        defer freeVariant(testing.allocator, decoded);
        const got = decoded.array.items.byte_string.?;
        try testing.expectEqualSlices(u8, "\xde\xad", got[0].?);
        try testing.expectEqual(@as(?[]const u8, null), got[1]);
    }
    {
        var w = testWriter(&buf);
        var e = Encoder.init(&w);
        const arr = [_]?[]const u8{"<a/>"};
        try e.encodeVariant(.{ .array = .{ .items = .{ .xml_element = &arr } } });
        var r: std.Io.Reader = .fixed(w.buffered());
        var d = Decoder.init(&r, testing.allocator);
        const decoded = try d.decodeVariant();
        defer freeVariant(testing.allocator, decoded);
        try testing.expectEqualStrings("<a/>", decoded.array.items.xml_element.?[0].?);
    }
    {
        var w = testWriter(&buf);
        var e = Encoder.init(&w);
        const arr = [_]NodeId{ .{ .numeric = .{ .namespace = 0, .id = 2258 } }, .{ .string = .{ .namespace = 1, .id = "x" } } };
        try e.encodeVariant(.{ .array = .{ .items = .{ .node_id = &arr } } });
        var r: std.Io.Reader = .fixed(w.buffered());
        var d = Decoder.init(&r, testing.allocator);
        const decoded = try d.decodeVariant();
        defer freeVariant(testing.allocator, decoded);
        const got = decoded.array.items.node_id.?;
        try testing.expectEqualDeep(arr[0], got[0]);
        try testing.expectEqualStrings("x", got[1].string.id.?);
    }
    {
        var w = testWriter(&buf);
        var e = Encoder.init(&w);
        const arr = [_]ExpandedNodeId{.{ .node_id = .{ .numeric = .{ .namespace = 0, .id = 5 } }, .namespace_uri = "urn:x", .server_index = 1 }};
        try e.encodeVariant(.{ .array = .{ .items = .{ .expanded_node_id = &arr } } });
        var r: std.Io.Reader = .fixed(w.buffered());
        var d = Decoder.init(&r, testing.allocator);
        const decoded = try d.decodeVariant();
        defer freeVariant(testing.allocator, decoded);
        try testing.expectEqualStrings("urn:x", decoded.array.items.expanded_node_id.?[0].namespace_uri.?);
    }
    {
        var w = testWriter(&buf);
        var e = Encoder.init(&w);
        const arr = [_]StatusCode{ 0, 0x80010000 };
        try e.encodeVariant(.{ .array = .{ .items = .{ .status_code = &arr } } });
        var r: std.Io.Reader = .fixed(w.buffered());
        var d = Decoder.init(&r, testing.allocator);
        const decoded = try d.decodeVariant();
        defer freeVariant(testing.allocator, decoded);
        try testing.expectEqualSlices(StatusCode, &arr, decoded.array.items.status_code.?);
    }
    {
        var w = testWriter(&buf);
        var e = Encoder.init(&w);
        const arr = [_]QualifiedName{.{ .namespace_index = 3, .name = "Temp" }};
        try e.encodeVariant(.{ .array = .{ .items = .{ .qualified_name = &arr } } });
        var r: std.Io.Reader = .fixed(w.buffered());
        var d = Decoder.init(&r, testing.allocator);
        const decoded = try d.decodeVariant();
        defer freeVariant(testing.allocator, decoded);
        try testing.expectEqualStrings("Temp", decoded.array.items.qualified_name.?[0].name.?);
    }
    {
        var w = testWriter(&buf);
        var e = Encoder.init(&w);
        const arr = [_]LocalizedText{.{ .locale = "en", .text = "Hi" }};
        try e.encodeVariant(.{ .array = .{ .items = .{ .localized_text = &arr } } });
        var r: std.Io.Reader = .fixed(w.buffered());
        var d = Decoder.init(&r, testing.allocator);
        const decoded = try d.decodeVariant();
        defer freeVariant(testing.allocator, decoded);
        try testing.expectEqualStrings("Hi", decoded.array.items.localized_text.?[0].text.?);
    }
    {
        var w = testWriter(&buf);
        var e = Encoder.init(&w);
        const arr = [_]ExtensionObject{.{ .type_id = .{ .numeric = .{ .namespace = 0, .id = 297 } }, .encoding = .byte_string, .body = "\x01\x02" }};
        try e.encodeVariant(.{ .array = .{ .items = .{ .extension_object = &arr } } });
        var r: std.Io.Reader = .fixed(w.buffered());
        var d = Decoder.init(&r, testing.allocator);
        const decoded = try d.decodeVariant();
        defer freeVariant(testing.allocator, decoded);
        try testing.expectEqualSlices(u8, "\x01\x02", decoded.array.items.extension_object.?[0].body);
    }
}

test "Variant array: empty array vs null array are distinct, for a numeric/string/struct type each" {
    const testing = std.testing;
    var buf: [64]u8 = undefined;

    // Empty (present, len 0) Int32 array: count 0, no elements.
    {
        var w = testWriter(&buf);
        var e = Encoder.init(&w);
        const arr = [_]i32{};
        try e.encodeVariant(.{ .array = .{ .items = .{ .int32 = &arr } } });
        try testing.expectEqualSlices(u8, &.{ 0x80 | 6, 0, 0, 0, 0 }, w.buffered());
        var r: std.Io.Reader = .fixed(w.buffered());
        var d = Decoder.init(&r, testing.allocator);
        const decoded = try d.decodeVariant();
        defer freeVariant(testing.allocator, decoded);
        try testing.expectEqual(@as(usize, 0), decoded.array.items.int32.?.len);
    }
    // Null Int32 array: count -1, no elements, `items.int32 == null`.
    {
        var w = testWriter(&buf);
        var e = Encoder.init(&w);
        try e.encodeVariant(.{ .array = .{ .items = .{ .int32 = null } } });
        try testing.expectEqualSlices(u8, &.{ 0x80 | 6, 0xff, 0xff, 0xff, 0xff }, w.buffered());
        var r: std.Io.Reader = .fixed(w.buffered());
        var d = Decoder.init(&r, testing.allocator);
        const decoded = try d.decodeVariant();
        defer freeVariant(testing.allocator, decoded);
        try testing.expectEqual(@as(?[]const i32, null), decoded.array.items.int32);
    }
    // Empty String array.
    {
        var w = testWriter(&buf);
        var e = Encoder.init(&w);
        const arr = [_]?[]const u8{};
        try e.encodeVariant(.{ .array = .{ .items = .{ .string = &arr } } });
        var r: std.Io.Reader = .fixed(w.buffered());
        var d = Decoder.init(&r, testing.allocator);
        const decoded = try d.decodeVariant();
        defer freeVariant(testing.allocator, decoded);
        try testing.expectEqual(@as(usize, 0), decoded.array.items.string.?.len);
    }
    // Null String array.
    {
        var w = testWriter(&buf);
        var e = Encoder.init(&w);
        try e.encodeVariant(.{ .array = .{ .items = .{ .string = null } } });
        var r: std.Io.Reader = .fixed(w.buffered());
        var d = Decoder.init(&r, testing.allocator);
        const decoded = try d.decodeVariant();
        defer freeVariant(testing.allocator, decoded);
        try testing.expectEqual(@as(?[]const ?[]const u8, null), decoded.array.items.string);
    }
    // Empty NodeId array (struct type).
    {
        var w = testWriter(&buf);
        var e = Encoder.init(&w);
        const arr = [_]NodeId{};
        try e.encodeVariant(.{ .array = .{ .items = .{ .node_id = &arr } } });
        var r: std.Io.Reader = .fixed(w.buffered());
        var d = Decoder.init(&r, testing.allocator);
        const decoded = try d.decodeVariant();
        defer freeVariant(testing.allocator, decoded);
        try testing.expectEqual(@as(usize, 0), decoded.array.items.node_id.?.len);
    }
    // Null NodeId array.
    {
        var w = testWriter(&buf);
        var e = Encoder.init(&w);
        try e.encodeVariant(.{ .array = .{ .items = .{ .node_id = null } } });
        var r: std.Io.Reader = .fixed(w.buffered());
        var d = Decoder.init(&r, testing.allocator);
        const decoded = try d.decodeVariant();
        defer freeVariant(testing.allocator, decoded);
        try testing.expectEqual(@as(?[]const NodeId, null), decoded.array.items.node_id);
    }
}

test "Variant array: multi-dimensional (ArrayDimensions) round-trip" {
    const testing = std.testing;
    var buf: [64]u8 = undefined;
    var w = testWriter(&buf);
    var e = Encoder.init(&w);
    const flat = [_]i32{ 1, 2, 3, 4, 5, 6 }; // logically a 2x3 matrix
    const dims = [_]i32{ 2, 3 };
    try e.encodeVariant(.{ .array = .{ .items = .{ .int32 = &flat }, .dimensions = &dims } });
    // mask = ValueIsArray | ArrayDimensions | Int32(6) = 0xc6.
    try testing.expectEqual(@as(u8, 0x80 | 0x40 | 6), w.buffered()[0]);

    var r: std.Io.Reader = .fixed(w.buffered());
    var d = Decoder.init(&r, testing.allocator);
    const decoded = try d.decodeVariant();
    defer freeVariant(testing.allocator, decoded);
    try testing.expectEqualSlices(i32, &flat, decoded.array.items.int32.?);
    try testing.expectEqualSlices(i32, &dims, decoded.array.dimensions.?);
}

test "Variant: DataValue/Variant/DiagnosticInfo built-in type ids (23-25) remain out of scope, scalar or array" {
    const testing = std.testing;
    {
        // Scalar, type id 24 (Variant-of-Variant).
        var buf = [_]u8{24};
        var r: std.Io.Reader = .fixed(&buf);
        var d = Decoder.init(&r, testing.allocator);
        try testing.expectError(error.UnsupportedType, d.decodeVariant());
    }
    {
        // Array-flagged, type id 23 (DataValue array).
        var buf = [_]u8{ 0x80 | 23, 0, 0, 0, 0 };
        var r: std.Io.Reader = .fixed(&buf);
        var d = Decoder.init(&r, testing.allocator);
        try testing.expectError(error.UnsupportedType, d.decodeVariant());
    }
    {
        // Array-flagged, type id 25 (DiagnosticInfo array).
        var buf = [_]u8{ 0x80 | 25, 0, 0, 0, 0 };
        var r: std.Io.Reader = .fixed(&buf);
        var d = Decoder.init(&r, testing.allocator);
        try testing.expectError(error.UnsupportedType, d.decodeVariant());
    }
}

test "Variant array: ArrayDimensions bit without ValueIsArray is a malformed encoding byte" {
    const testing = std.testing;
    var buf = [_]u8{0x40 | 6}; // ArrayDimensions set, ValueIsArray clear
    var r: std.Io.Reader = .fixed(&buf);
    var d = Decoder.init(&r, testing.allocator);
    try testing.expectError(error.BadEncodingByte, d.decodeVariant());
}

test "DataValue: nested Variant round-trip" {
    const testing = std.testing;
    var buf: [64]u8 = undefined;
    var w = testWriter(&buf);
    var e = Encoder.init(&w);
    const dv: DataValue = .{
        .value = .{ .scalar = .{ .uint32 = 7 } },
        .status = 0,
        .source_timestamp = 132223104000000000,
    };
    try e.encodeDataValue(dv);
    try testing.expectEqual(@as(u8, 0x01 | 0x02 | 0x04), w.buffered()[0]);

    var r: std.Io.Reader = .fixed(w.buffered());
    var d = Decoder.init(&r, testing.allocator);
    const decoded = try d.decodeDataValue();
    try testing.expectEqual(@as(u32, 7), decoded.value.?.scalar.uint32);
    try testing.expectEqual(@as(?StatusCode, 0), decoded.status);
    try testing.expectEqual(@as(?DateTime, 132223104000000000), decoded.source_timestamp);
    try testing.expectEqual(@as(?u16, null), decoded.source_pico_seconds);
}

test "DataValue: all six fields round-trip in wire order" {
    const testing = std.testing;
    var buf: [64]u8 = undefined;
    var w = testWriter(&buf);
    var e = Encoder.init(&w);
    const dv: DataValue = .{
        .value = .{ .scalar = .{ .boolean = true } },
        .status = 0xdeadbeef,
        .source_timestamp = 1,
        .source_pico_seconds = 2,
        .server_timestamp = 3,
        .server_pico_seconds = 4,
    };
    try e.encodeDataValue(dv);
    var r: std.Io.Reader = .fixed(w.buffered());
    var d = Decoder.init(&r, testing.allocator);
    const decoded = try d.decodeDataValue();
    try testing.expectEqualDeep(dv, decoded);
}

test "DiagnosticInfo: recursive inner + round-trip" {
    const testing = std.testing;
    var buf: [64]u8 = undefined;
    var w = testWriter(&buf);
    var e = Encoder.init(&w);
    var inner: DiagnosticInfo = .{ .symbolic_id = 3 };
    const outer: DiagnosticInfo = .{
        .symbolic_id = 1,
        .namespace_uri = 2,
        .additional_info = "oops",
        .inner_diagnostic_info = &inner,
    };
    try e.encodeDiagnosticInfo(outer);

    var r: std.Io.Reader = .fixed(w.buffered());
    var d = Decoder.init(&r, testing.allocator);
    const decoded = try d.decodeDiagnosticInfo();
    defer testing.allocator.free(decoded.additional_info.?);
    defer if (decoded.inner_diagnostic_info) |p| testing.allocator.destroy(p);
    try testing.expectEqual(@as(?i32, 1), decoded.symbolic_id);
    try testing.expectEqual(@as(?i32, 2), decoded.namespace_uri);
    try testing.expectEqualStrings("oops", decoded.additional_info.?);
    try testing.expect(decoded.inner_diagnostic_info != null);
    try testing.expectEqual(@as(?i32, 3), decoded.inner_diagnostic_info.?.symbolic_id);
}

test "negatives: String length -1 is null, not empty; other negatives are BadLength" {
    const testing = std.testing;
    {
        var buf = [_]u8{ 0xff, 0xff, 0xff, 0xff }; // -1
        var r: std.Io.Reader = .fixed(&buf);
        var d = Decoder.init(&r, testing.allocator);
        try testing.expectEqual(@as(?[]const u8, null), try d.decodeString());
    }
    {
        var buf = [_]u8{ 0xfe, 0xff, 0xff, 0xff }; // -2: invalid
        var r: std.Io.Reader = .fixed(&buf);
        var d = Decoder.init(&r, testing.allocator);
        try testing.expectError(error.BadLength, d.decodeString());
    }
}

test "negatives: NodeId reserved encoding byte" {
    const testing = std.testing;
    var buf = [_]u8{0x3f}; // not a defined NodeId form
    var r: std.Io.Reader = .fixed(&buf);
    var d = Decoder.init(&r, testing.allocator);
    try testing.expectError(error.BadEncodingByte, d.decodeNodeId());
}

test "negatives: truncated input surfaces EndOfStream, not a panic" {
    const testing = std.testing;
    var buf = [_]u8{ 0x01, 0x02 }; // claims a UInt32 but only 2 bytes present
    var r: std.Io.Reader = .fixed(&buf);
    var d = Decoder.init(&r, testing.allocator);
    try testing.expectError(error.EndOfStream, d.decodeUInt32());
}
