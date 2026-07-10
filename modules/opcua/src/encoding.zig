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

/// A dynamically-typed value: `Read`/`Write`'s payload type. `scalar == null`
/// is the empty Variant (encoding byte `0x00`, no value at all).
pub const Variant = struct {
    scalar: ?VariantScalar = null,
    // TODO(agent): array support — the encoding byte's `0x80` (ValueIsArray)
    // and `0x40` (ArrayDimensions present) bits, and the two shapes they
    // imply: a flat array of `scalar`'s type, and (with `0x40`) a
    // multi-dimensional `ArrayDimensions: Int32[]` alongside it. Not modeled
    // yet — decide the storage (owned slice via the Decoder's allocator vs.
    // a caller-supplied buffer) when this is filled in.
};

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
        _ = e;
        _ = value;
        @panic("TODO(agent): Boolean — one byte, 0x00 = false, any nonzero = true, per OPC 10000-6 §5.2.2.1");
    }

    pub fn encodeSByte(e: *Encoder, value: i8) EncodeError!void {
        _ = e;
        _ = value;
        @panic("TODO(agent): SByte — 1 byte, per OPC 10000-6 §5.2.2.2");
    }

    pub fn encodeByte(e: *Encoder, value: u8) EncodeError!void {
        _ = e;
        _ = value;
        @panic("TODO(agent): Byte — 1 byte, per OPC 10000-6 §5.2.2.2");
    }

    pub fn encodeInt16(e: *Encoder, value: i16) EncodeError!void {
        _ = e;
        _ = value;
        @panic("TODO(agent): Int16 — 2 bytes little-endian, per OPC 10000-6 §5.2.2.3");
    }

    pub fn encodeUInt16(e: *Encoder, value: u16) EncodeError!void {
        _ = e;
        _ = value;
        @panic("TODO(agent): UInt16 — 2 bytes little-endian, per OPC 10000-6 §5.2.2.3");
    }

    pub fn encodeInt32(e: *Encoder, value: i32) EncodeError!void {
        _ = e;
        _ = value;
        @panic("TODO(agent): Int32 — 4 bytes little-endian, per OPC 10000-6 §5.2.2.3");
    }

    pub fn encodeUInt32(e: *Encoder, value: u32) EncodeError!void {
        _ = e;
        _ = value;
        @panic("TODO(agent): UInt32 — 4 bytes little-endian, per OPC 10000-6 §5.2.2.3");
    }

    pub fn encodeInt64(e: *Encoder, value: i64) EncodeError!void {
        _ = e;
        _ = value;
        @panic("TODO(agent): Int64 — 8 bytes little-endian, per OPC 10000-6 §5.2.2.3");
    }

    pub fn encodeUInt64(e: *Encoder, value: u64) EncodeError!void {
        _ = e;
        _ = value;
        @panic("TODO(agent): UInt64 — 8 bytes little-endian, per OPC 10000-6 §5.2.2.3");
    }

    pub fn encodeFloat(e: *Encoder, value: f32) EncodeError!void {
        _ = e;
        _ = value;
        @panic("TODO(agent): Float — IEEE 754 single precision, little-endian, per OPC 10000-6 §5.2.2.3");
    }

    pub fn encodeDouble(e: *Encoder, value: f64) EncodeError!void {
        _ = e;
        _ = value;
        @panic("TODO(agent): Double — IEEE 754 double precision, little-endian, per OPC 10000-6 §5.2.2.3");
    }

    pub fn encodeString(e: *Encoder, value: ?[]const u8) EncodeError!void {
        _ = e;
        _ = value;
        @panic("TODO(agent): String — Int32 byte length (-1 = null) + UTF-8 bytes (no NUL terminator), per OPC 10000-6 §5.2.2.4");
    }

    pub fn encodeDateTime(e: *Encoder, value: DateTime) EncodeError!void {
        _ = e;
        _ = value;
        @panic("TODO(agent): DateTime — Int64 100ns ticks since 1601-01-01 UTC, per OPC 10000-6 §5.2.2.5");
    }

    pub fn encodeGuid(e: *Encoder, value: Guid) EncodeError!void {
        _ = e;
        _ = value;
        @panic("TODO(agent): Guid — Data1(UInt32)+Data2(UInt16)+Data3(UInt16)+Data4(8 raw bytes), per OPC 10000-6 §5.2.2.6");
    }

    pub fn encodeByteString(e: *Encoder, value: ?[]const u8) EncodeError!void {
        _ = e;
        _ = value;
        @panic("TODO(agent): ByteString — same Int32-length-prefixed shape as String but raw (non-UTF-8) bytes, per OPC 10000-6 §5.2.2.7");
    }

    pub fn encodeXmlElement(e: *Encoder, value: ?[]const u8) EncodeError!void {
        _ = e;
        _ = value;
        @panic("TODO(agent): XmlElement — encoded exactly as a ByteString (UTF-8 XML text), per OPC 10000-6 §5.2.2.8");
    }

    pub fn encodeNodeId(e: *Encoder, value: NodeId) EncodeError!void {
        _ = e;
        _ = value;
        @panic("TODO(agent): NodeId — pick the most compact wire form (two_byte/four_byte/numeric/string/guid/byte_string) per OPC 10000-6 §5.2.2.9 Table 7");
    }

    pub fn encodeExpandedNodeId(e: *Encoder, value: ExpandedNodeId) EncodeError!void {
        _ = e;
        _ = value;
        @panic("TODO(agent): ExpandedNodeId — a NodeId plus the 0x80/0x40 encoding-byte flag bits for namespace_uri/server_index, per OPC 10000-6 §5.2.2.10");
    }

    pub fn encodeStatusCode(e: *Encoder, value: StatusCode) EncodeError!void {
        _ = e;
        _ = value;
        @panic("TODO(agent): StatusCode — UInt32, per OPC 10000-6 §5.2.2.11 / §7.34");
    }

    pub fn encodeQualifiedName(e: *Encoder, value: QualifiedName) EncodeError!void {
        _ = e;
        _ = value;
        @panic("TODO(agent): QualifiedName — UInt16 NamespaceIndex + String Name, per OPC 10000-6 §5.2.2.13");
    }

    pub fn encodeLocalizedText(e: *Encoder, value: LocalizedText) EncodeError!void {
        _ = e;
        _ = value;
        @panic("TODO(agent): LocalizedText — encoding byte (bit 0x01 Locale present / 0x02 Text present) then each present field as String, per OPC 10000-6 §5.2.2.14");
    }

    pub fn encodeExtensionObject(e: *Encoder, value: ExtensionObject) EncodeError!void {
        _ = e;
        _ = value;
        @panic("TODO(agent): ExtensionObject — NodeId TypeId + Byte Encoding + Body (ByteString or XmlElement per `encoding`), per OPC 10000-6 §5.2.2.15");
    }

    pub fn encodeVariant(e: *Encoder, value: Variant) EncodeError!void {
        _ = e;
        _ = value;
        @panic("TODO(agent): Variant — encoding byte (bits 0..5 built-in type id, 0x80 ValueIsArray, 0x40 ArrayDimensions present) then the typed value, per OPC 10000-6 §5.2.2.16");
    }

    pub fn encodeDataValue(e: *Encoder, value: DataValue) EncodeError!void {
        _ = e;
        _ = value;
        @panic("TODO(agent): DataValue — encoding-mask byte (which of the 6 fields are present) then each present field in wire order, per OPC 10000-6 §5.2.2.17");
    }

    pub fn encodeDiagnosticInfo(e: *Encoder, value: DiagnosticInfo) EncodeError!void {
        _ = e;
        _ = value;
        @panic("TODO(agent): DiagnosticInfo — encoding-mask byte (bits for the 7 optional fields, incl. recursive InnerDiagnosticInfo) then each present field, per OPC 10000-6 §5.2.2.12");
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
        _ = d;
        @panic("TODO(agent): Boolean — one byte, 0x00 = false, any nonzero = true, per OPC 10000-6 §5.2.2.1");
    }

    pub fn decodeSByte(d: *Decoder) DecodeError!i8 {
        _ = d;
        @panic("TODO(agent): SByte — 1 byte, per OPC 10000-6 §5.2.2.2");
    }

    pub fn decodeByte(d: *Decoder) DecodeError!u8 {
        _ = d;
        @panic("TODO(agent): Byte — 1 byte, per OPC 10000-6 §5.2.2.2");
    }

    pub fn decodeInt16(d: *Decoder) DecodeError!i16 {
        _ = d;
        @panic("TODO(agent): Int16 — 2 bytes little-endian, per OPC 10000-6 §5.2.2.3");
    }

    pub fn decodeUInt16(d: *Decoder) DecodeError!u16 {
        _ = d;
        @panic("TODO(agent): UInt16 — 2 bytes little-endian, per OPC 10000-6 §5.2.2.3");
    }

    pub fn decodeInt32(d: *Decoder) DecodeError!i32 {
        _ = d;
        @panic("TODO(agent): Int32 — 4 bytes little-endian, per OPC 10000-6 §5.2.2.3");
    }

    pub fn decodeUInt32(d: *Decoder) DecodeError!u32 {
        _ = d;
        @panic("TODO(agent): UInt32 — 4 bytes little-endian, per OPC 10000-6 §5.2.2.3");
    }

    pub fn decodeInt64(d: *Decoder) DecodeError!i64 {
        _ = d;
        @panic("TODO(agent): Int64 — 8 bytes little-endian, per OPC 10000-6 §5.2.2.3");
    }

    pub fn decodeUInt64(d: *Decoder) DecodeError!u64 {
        _ = d;
        @panic("TODO(agent): UInt64 — 8 bytes little-endian, per OPC 10000-6 §5.2.2.3");
    }

    pub fn decodeFloat(d: *Decoder) DecodeError!f32 {
        _ = d;
        @panic("TODO(agent): Float — IEEE 754 single precision, little-endian, per OPC 10000-6 §5.2.2.3");
    }

    pub fn decodeDouble(d: *Decoder) DecodeError!f64 {
        _ = d;
        @panic("TODO(agent): Double — IEEE 754 double precision, little-endian, per OPC 10000-6 §5.2.2.3");
    }

    /// `null` = the OPC UA null string (Int32 length -1); `&.{}` = present but
    /// empty (length 0). Non-null results are allocator-owned.
    pub fn decodeString(d: *Decoder) DecodeError!?[]const u8 {
        _ = d;
        @panic("TODO(agent): String — Int32 byte length (-1 = null) + UTF-8 bytes, per OPC 10000-6 §5.2.2.4");
    }

    pub fn decodeDateTime(d: *Decoder) DecodeError!DateTime {
        _ = d;
        @panic("TODO(agent): DateTime — Int64 100ns ticks since 1601-01-01 UTC, per OPC 10000-6 §5.2.2.5");
    }

    pub fn decodeGuid(d: *Decoder) DecodeError!Guid {
        _ = d;
        @panic("TODO(agent): Guid — Data1(UInt32)+Data2(UInt16)+Data3(UInt16)+Data4(8 raw bytes), per OPC 10000-6 §5.2.2.6");
    }

    pub fn decodeByteString(d: *Decoder) DecodeError!?[]const u8 {
        _ = d;
        @panic("TODO(agent): ByteString — same Int32-length-prefixed shape as String but raw (non-UTF-8) bytes, per OPC 10000-6 §5.2.2.7");
    }

    pub fn decodeXmlElement(d: *Decoder) DecodeError!?[]const u8 {
        _ = d;
        @panic("TODO(agent): XmlElement — decoded exactly as a ByteString (UTF-8 XML text), per OPC 10000-6 §5.2.2.8");
    }

    pub fn decodeNodeId(d: *Decoder) DecodeError!NodeId {
        _ = d;
        @panic("TODO(agent): NodeId — dispatch on the encoding byte (two_byte/four_byte/numeric/string/guid/byte_string), per OPC 10000-6 §5.2.2.9 Table 7");
    }

    pub fn decodeExpandedNodeId(d: *Decoder) DecodeError!ExpandedNodeId {
        _ = d;
        @panic("TODO(agent): ExpandedNodeId — a NodeId then, per the encoding byte's 0x80/0x40 bits, an optional namespace_uri/server_index, per OPC 10000-6 §5.2.2.10");
    }

    pub fn decodeStatusCode(d: *Decoder) DecodeError!StatusCode {
        _ = d;
        @panic("TODO(agent): StatusCode — UInt32, per OPC 10000-6 §5.2.2.11 / §7.34");
    }

    pub fn decodeQualifiedName(d: *Decoder) DecodeError!QualifiedName {
        _ = d;
        @panic("TODO(agent): QualifiedName — UInt16 NamespaceIndex + String Name, per OPC 10000-6 §5.2.2.13");
    }

    pub fn decodeLocalizedText(d: *Decoder) DecodeError!LocalizedText {
        _ = d;
        @panic("TODO(agent): LocalizedText — encoding byte (bit 0x01 Locale present / 0x02 Text present) then each present field as String, per OPC 10000-6 §5.2.2.14");
    }

    pub fn decodeExtensionObject(d: *Decoder) DecodeError!ExtensionObject {
        _ = d;
        @panic("TODO(agent): ExtensionObject — NodeId TypeId + Byte Encoding + Body (ByteString or XmlElement per the encoding byte), per OPC 10000-6 §5.2.2.15");
    }

    pub fn decodeVariant(d: *Decoder) DecodeError!Variant {
        _ = d;
        @panic("TODO(agent): Variant — encoding byte (bits 0..5 built-in type id, 0x80 ValueIsArray, 0x40 ArrayDimensions present) then the typed value, per OPC 10000-6 §5.2.2.16");
    }

    pub fn decodeDataValue(d: *Decoder) DecodeError!DataValue {
        _ = d;
        @panic("TODO(agent): DataValue — encoding-mask byte (which of the 6 fields are present) then each present field in wire order, per OPC 10000-6 §5.2.2.17");
    }

    pub fn decodeDiagnosticInfo(d: *Decoder) DecodeError!DiagnosticInfo {
        _ = d;
        @panic("TODO(agent): DiagnosticInfo — encoding-mask byte (bits for the 7 optional fields, incl. recursive InnerDiagnosticInfo) then each present field, per OPC 10000-6 §5.2.2.12");
    }
};

// ── tests ──

test "types are constructible (no encode/decode invoked)" {
    const testing = std.testing;
    const nid: NodeId = .{ .numeric = .{ .namespace = 0, .id = 2258 } };
    try testing.expect(nid == .numeric);
    const v: Variant = .{ .scalar = .{ .uint32 = 42 } };
    try testing.expect(v.scalar.? == .uint32);
}
