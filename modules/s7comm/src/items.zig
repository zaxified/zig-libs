// SPDX-License-Identifier: MIT

//! Read Var / Write Var: the item specification that names *what* to read or
//! write, and the data block that carries the values.
//!
//! ## The request item (12 octets, `S7ANY`)
//!
//! ```text
//! 0x12  0x0A  0x10  <transport size>  <count:2>  <db:2>  <area>  <address:3>
//!  ^     ^     ^
//!  |     |     +-- syntax id: 0x10 = S7ANY (the only one this module builds)
//!  |     +-------- length of everything after this octet (always 10 for S7ANY)
//!  +-------------- variable specification marker
//! ```
//!
//! **The three address octets are a BIT address**, not a byte address: to read
//! `DB1.DBW20` the octets are `20 * 8 = 160 = 0x0000A0`. Forgetting the `* 8`
//! is the single most common S7 bug — it does not fail loudly, it reads the
//! wrong eighth of the DB, and byte 0 (the one everybody tests with) is `0`
//! either way, so it survives the first test.
//!
//! For the `counter` and `timer` areas the address counts *elements*, not
//! bits: counter 3 is address 3, not 24.
//!
//! ## The data block
//!
//! ```text
//! <return code>  <transport size>  <length:2>  <payload...>  [pad]
//! ```
//!
//! Two traps live in those four octets:
//!
//! 1. **The length unit depends on the transport size.** For `bit`, `byte_word_dword`
//!    and `int` it is a count of **bits**; for `dint`, `real` and `octet_string`
//!    it is a count of **bytes**. A decoder that assumes one unit reads eight
//!    times too much or too little.
//! 2. **Every item except the last is padded to an even length.** The pad
//!    octet's value is *not* specified — real stacks emit uninitialised memory
//!    there — so it must be skipped, never validated.
//!
//! An item whose return code is not `success` carries **no payload and no
//! padding**: it is exactly the four header octets. A reply that mixes a
//! failed item and a successful one therefore has items of two different
//! shapes, which is the case a naive parser walks off the end of.

const std = @import("std");

pub const Error = error{
    /// Fewer octets than the structure needs.
    ShortItem,
    /// The variable-specification marker is not 0x12.
    BadVarSpec,
    /// The specification length octet is not 0x0A.
    BadSpecLength,
    /// The syntax id is not S7ANY.
    UnsupportedSyntaxId,
    /// The item count octet disagrees with the octets present.
    ItemCountMismatch,
    /// A data item's length field runs past the end of the block.
    BadDataLength,
    /// A data item's length contradicts its transport size (e.g. a bit-counted
    /// length that is not a whole number of octets).
    LengthTransportMismatch,
    /// The caller's output buffer is too small.
    BufferTooSmall,
    /// The caller asked for more than a 16-bit count or address can hold.
    AddressOutOfRange,
};

/// Marker that opens every variable specification.
pub const var_spec: u8 = 0x12;
/// Length of an S7ANY specification after the length octet.
pub const s7any_spec_len: u8 = 0x0A;
/// The "any pointer" syntax id — the only addressing mode this module builds.
/// Symbolic addressing (`0xB2`, S7-1200/1500 optimised blocks) is not
/// supported; see SPEC.md.
pub const syntax_s7any: u8 = 0x10;

/// Octets an encoded request item occupies.
pub const item_len: usize = 12;

/// The memory area an item addresses.
pub const Area = enum(u8) {
    system_info = 0x03,
    system_flags = 0x05,
    analog_inputs = 0x06,
    analog_outputs = 0x07,
    /// S5 counters. Address counts counters, not bits.
    counter = 0x1C,
    /// S5 timers. Address counts timers, not bits.
    timer = 0x1D,
    /// Direct peripheral access, bypassing the process image.
    direct_peripheral = 0x80,
    /// Process image of the inputs (PE / I / E).
    inputs = 0x81,
    /// Process image of the outputs (PA / Q / A).
    outputs = 0x82,
    /// Bit memory (merker / M / flags).
    flags = 0x83,
    /// Data block.
    db = 0x84,
    /// Instance data block.
    instance_db = 0x85,
    /// Local stack of the current block.
    local = 0x86,
    /// Previous local stack.
    previous_local = 0x87,
    _,

    /// True where the three address octets count elements rather than bits.
    pub fn addressesElements(self: Area) bool {
        return self == .counter or self == .timer;
    }
};

/// The transport size in the *request item*. This names the element type and
/// therefore how wide one unit of `count` is.
pub const TransportSize = enum(u8) {
    bit = 0x01,
    byte = 0x02,
    char = 0x03,
    word = 0x04,
    int = 0x05,
    dword = 0x06,
    dint = 0x07,
    real = 0x08,
    date = 0x09,
    tod = 0x0A,
    time = 0x0B,
    s5time = 0x0C,
    dt = 0x0F,
    counter = 0x1C,
    timer = 0x1D,
    iec_timer = 0x1E,
    iec_counter = 0x1F,
    hs_counter = 0x20,
    _,

    /// Octets one element occupies, or null for a size this module cannot
    /// bound (which then cannot be length-checked).
    pub fn elementBytes(self: TransportSize) ?u16 {
        return switch (self) {
            .bit => 1,
            .byte, .char => 1,
            .word, .int, .s5time, .counter, .timer => 2,
            .dword, .dint, .real, .date, .time => 4,
            .tod => 4,
            .dt => 8,
            .iec_timer, .iec_counter => 4,
            .hs_counter => 2,
            else => null,
        };
    }
};

/// The transport size in the *data block*, which is a much smaller set than
/// the request-item one and whose sole job is to say what unit the length
/// field is in.
pub const DataTransportSize = enum(u8) {
    /// Used by an item that failed: no payload follows.
    null_size = 0x00,
    bit = 0x03,
    /// The catch-all for byte, word and double-word transfers.
    byte_word_dword = 0x04,
    int = 0x05,
    dint = 0x06,
    real = 0x07,
    octet_string = 0x09,
    _,

    /// True when the length field counts bits rather than octets.
    /// `bit`, `byte_word_dword` and `int` count bits; `dint`, `real` and
    /// `octet_string` count octets.
    pub fn lengthInBits(self: DataTransportSize) bool {
        return switch (self) {
            .bit, .byte_word_dword, .int => true,
            else => false,
        };
    }
};

/// Per-item result. `success` is `0xFF`; everything else means no payload.
pub const ReturnCode = enum(u8) {
    reserved = 0x00,
    hardware_fault = 0x01,
    /// Accessing the object is not permitted.
    access_denied = 0x03,
    /// The address is outside the valid range for the object.
    invalid_address = 0x05,
    /// The requested data type is not supported.
    data_type_unsupported = 0x06,
    /// Date type inconsistent with the object.
    data_type_inconsistent = 0x07,
    /// The object (e.g. that DB) does not exist.
    object_does_not_exist = 0x0A,
    success = 0xFF,
    _,

    pub fn isSuccess(self: ReturnCode) bool {
        return self == .success;
    }
};

/// A request item: one contiguous run of one area.
pub const Item = struct {
    transport_size: TransportSize = .byte,
    /// Number of elements of `transport_size`.
    count: u16,
    /// Only meaningful when `area == .db` or `.instance_db`.
    db_number: u16 = 0,
    area: Area,
    /// Bit address (`byte * 8 + bit`) for every area except counters and
    /// timers, where it is an element index. 24 bits on the wire.
    address: u24,

    /// The conventional constructor: byte offset plus bit index.
    pub fn at(area: Area, db_number: u16, byte_offset: usize, bit: u3, ts: TransportSize, count: u16) Error!Item {
        if (area.addressesElements()) {
            if (bit != 0) return error.AddressOutOfRange;
            if (byte_offset > 0xFFFFFF) return error.AddressOutOfRange;
            return .{ .transport_size = ts, .count = count, .db_number = db_number, .area = area, .address = @intCast(byte_offset) };
        }
        const bits: u64 = @as(u64, byte_offset) * 8 + bit;
        if (bits > 0xFFFFFF) return error.AddressOutOfRange;
        return .{
            .transport_size = ts,
            .count = count,
            .db_number = db_number,
            .area = area,
            .address = @intCast(bits),
        };
    }

    /// The byte offset this item starts at (undefined for counter/timer areas,
    /// where `address` is an element index).
    pub fn byteOffset(self: Item) u32 {
        return if (self.area.addressesElements()) self.address else self.address >> 3;
    }

    /// The bit within `byteOffset()`.
    pub fn bitOffset(self: Item) u3 {
        return if (self.area.addressesElements()) 0 else @intCast(self.address & 0x07);
    }

    /// Octets of payload this item transfers, or null when the transport size
    /// has no fixed width.
    pub fn payloadBytes(self: Item) ?u32 {
        if (self.transport_size == .bit) return (@as(u32, self.count) + 7) / 8;
        const w = self.transport_size.elementBytes() orelse return null;
        return @as(u32, self.count) * w;
    }

    pub fn encode(self: Item, out: []u8) Error![]u8 {
        if (out.len < item_len) return error.BufferTooSmall;
        out[0] = var_spec;
        out[1] = s7any_spec_len;
        out[2] = syntax_s7any;
        out[3] = @intFromEnum(self.transport_size);
        out[4] = @intCast(self.count >> 8);
        out[5] = @intCast(self.count & 0xFF);
        out[6] = @intCast(self.db_number >> 8);
        out[7] = @intCast(self.db_number & 0xFF);
        out[8] = @intFromEnum(self.area);
        out[9] = @intCast((self.address >> 16) & 0xFF);
        out[10] = @intCast((self.address >> 8) & 0xFF);
        out[11] = @intCast(self.address & 0xFF);
        return out[0..item_len];
    }

    pub fn decode(bytes: []const u8) Error!Item {
        if (bytes.len < 2) return error.ShortItem;
        if (bytes[0] != var_spec) return error.BadVarSpec;
        if (bytes[1] != s7any_spec_len) return error.BadSpecLength;
        if (bytes.len < item_len) return error.ShortItem;
        if (bytes[2] != syntax_s7any) return error.UnsupportedSyntaxId;
        return .{
            .transport_size = @enumFromInt(bytes[3]),
            .count = (@as(u16, bytes[4]) << 8) | bytes[5],
            .db_number = (@as(u16, bytes[6]) << 8) | bytes[7],
            .area = @enumFromInt(bytes[8]),
            .address = (@as(u24, bytes[9]) << 16) | (@as(u24, bytes[10]) << 8) | bytes[11],
        };
    }
};

/// A data block entry: one item's payload, or one item's failure.
pub const DataItem = struct {
    return_code: ReturnCode = .success,
    transport_size: DataTransportSize = .byte_word_dword,
    /// Empty when `return_code` is not `success`.
    payload: []const u8 = &.{},
    /// The raw length field as it appeared on the wire. Kept because a failed
    /// item still carries one and stacks do not agree on what to put there.
    raw_length: u16 = 0,

    /// Octets this item occupies on the wire, padding excluded.
    pub fn wireLen(self: DataItem) usize {
        return 4 + self.payload.len;
    }

    /// Whether a pad octet follows this item when it is not the last one.
    pub fn needsPad(self: DataItem) bool {
        return self.payload.len % 2 == 1;
    }
};

/// Length field for a payload of `n` octets under `ts`.
pub fn encodeLength(ts: DataTransportSize, n: usize) Error!u16 {
    if (ts.lengthInBits()) {
        const bits = n * 8;
        if (bits > 0xFFFF) return error.BadDataLength;
        return @intCast(bits);
    }
    if (n > 0xFFFF) return error.BadDataLength;
    return @intCast(n);
}

/// Payload octets a length field of `raw` means under `ts`.
pub fn decodeLength(ts: DataTransportSize, raw: u16) Error!usize {
    if (!ts.lengthInBits()) return raw;
    if (raw % 8 != 0) {
        // A bit-counted length that is not a whole number of octets only makes
        // sense for a single-bit transfer, which every stack encodes as 1.
        if (ts == .bit and raw <= 8) return 1;
        return error.LengthTransportMismatch;
    }
    return raw / 8;
}

/// Walks the data block of a Read Var reply (or a Write Var request),
/// handling the padding and the "failed items carry nothing" rule.
pub const DataItemIterator = struct {
    bytes: []const u8,
    pos: usize = 0,
    /// How many items the parameter block promised. Used to know which item is
    /// the last one, because only the last is unpadded.
    remaining: u16,
    /// In a **request** the return-code octet is `0x00` (reserved) and the
    /// payload follows regardless; only in a **reply** does a non-success code
    /// mean "no payload". Iterating a Write Var request in reply mode is how a
    /// parser ends up dropping every value it was asked to write.
    request_mode: bool = false,

    /// Walks a reply's data block.
    pub fn init(bytes: []const u8, count: u16) DataItemIterator {
        return .{ .bytes = bytes, .remaining = count };
    }

    /// Walks a Write Var request's data block.
    pub fn initRequest(bytes: []const u8, count: u16) DataItemIterator {
        return .{ .bytes = bytes, .remaining = count, .request_mode = true };
    }

    pub fn next(self: *DataItemIterator) Error!?DataItem {
        if (self.remaining == 0) return null;
        if (self.pos >= self.bytes.len) return error.ShortItem;
        if (self.pos + 4 > self.bytes.len) return error.ShortItem;
        const rc: ReturnCode = @enumFromInt(self.bytes[self.pos]);
        const ts: DataTransportSize = @enumFromInt(self.bytes[self.pos + 1]);
        const raw: u16 = (@as(u16, self.bytes[self.pos + 2]) << 8) | self.bytes[self.pos + 3];
        self.remaining -= 1;
        if (!self.request_mode and !rc.isSuccess()) {
            // A failed item is exactly its four header octets: no payload and
            // no padding, whatever the length field claims.
            self.pos += 4;
            return .{ .return_code = rc, .transport_size = ts, .raw_length = raw };
        }
        const n = try decodeLength(ts, raw);
        if (self.pos + 4 + n > self.bytes.len) return error.BadDataLength;
        const payload = self.bytes[self.pos + 4 ..][0..n];
        self.pos += 4 + n;
        // Pad to an even length, but never past the end of the block: the last
        // item is not padded.
        if (n % 2 == 1 and self.remaining != 0) {
            if (self.pos >= self.bytes.len) return error.BadDataLength;
            self.pos += 1;
        }
        return .{ .return_code = rc, .transport_size = ts, .payload = payload, .raw_length = raw };
    }

    /// Octets consumed so far.
    pub fn consumed(self: *const DataItemIterator) usize {
        return self.pos;
    }
};

/// Appends one data item to `out` at `pos`, padding the *previous* item when
/// needed. Returns the new position.
pub const DataBlockWriter = struct {
    out: []u8,
    pos: usize = 0,
    /// True when the item just written left the block at an odd length.
    pending_pad: bool = false,

    /// Appends a reply item, i.e. one with return code `success`.
    pub fn add(self: *DataBlockWriter, ts: DataTransportSize, payload: []const u8) Error!void {
        return self.addWith(.success, ts, payload);
    }

    /// Appends a **request** item, whose return-code octet is `0x00`.
    pub fn addRequest(self: *DataBlockWriter, ts: DataTransportSize, payload: []const u8) Error!void {
        return self.addWith(.reserved, ts, payload);
    }

    pub fn addWith(self: *DataBlockWriter, rc: ReturnCode, ts: DataTransportSize, payload: []const u8) Error!void {
        try self.padIfNeeded();
        const raw = try encodeLength(ts, payload.len);
        if (self.pos + 4 + payload.len > self.out.len) return error.BufferTooSmall;
        self.out[self.pos] = @intFromEnum(rc);
        self.out[self.pos + 1] = @intFromEnum(ts);
        self.out[self.pos + 2] = @intCast(raw >> 8);
        self.out[self.pos + 3] = @intCast(raw & 0xFF);
        @memcpy(self.out[self.pos + 4 ..][0..payload.len], payload);
        self.pos += 4 + payload.len;
        self.pending_pad = payload.len % 2 == 1;
    }

    /// Appends a single-bit reply item (return code `success`, transport size
    /// `bit`, length 1, one value octet), the way a real CPU reports a bit
    /// read. Unlike `add`/`addWith`, a caller cannot build this shape by
    /// hand and pass it through `add`: the wire length is 1 bit, not 1
    /// octet, so `encodeLength` would compute the wrong `raw` length for it.
    /// Pads the *previous* item first, exactly like every other `add*`
    /// entry point -- a bit item written directly into `out` bypassing this
    /// method loses that padding when the item before it left an odd offset.
    pub fn addBit(self: *DataBlockWriter, value: bool) Error!void {
        try self.padIfNeeded();
        if (self.pos + 5 > self.out.len) return error.BufferTooSmall;
        self.out[self.pos] = @intFromEnum(ReturnCode.success);
        self.out[self.pos + 1] = @intFromEnum(DataTransportSize.bit);
        self.out[self.pos + 2] = 0;
        self.out[self.pos + 3] = 1;
        self.out[self.pos + 4] = @intFromBool(value);
        self.pos += 5;
        self.pending_pad = true; // length 1 is always odd
    }

    /// Appends a failed item: four octets, no payload, no padding after it.
    pub fn addError(self: *DataBlockWriter, rc: ReturnCode, raw_length: u16) Error!void {
        try self.padIfNeeded();
        if (self.pos + 4 > self.out.len) return error.BufferTooSmall;
        self.out[self.pos] = @intFromEnum(rc);
        self.out[self.pos + 1] = @intFromEnum(DataTransportSize.null_size);
        self.out[self.pos + 2] = @intCast(raw_length >> 8);
        self.out[self.pos + 3] = @intCast(raw_length & 0xFF);
        self.pos += 4;
        self.pending_pad = false;
    }

    /// A one-octet return code, which is what a Write Var reply's data block
    /// is made of.
    pub fn addReturnCode(self: *DataBlockWriter, rc: ReturnCode) Error!void {
        if (self.pos + 1 > self.out.len) return error.BufferTooSmall;
        self.out[self.pos] = @intFromEnum(rc);
        self.pos += 1;
        self.pending_pad = false;
    }

    fn padIfNeeded(self: *DataBlockWriter) Error!void {
        if (!self.pending_pad) return;
        if (self.pos + 1 > self.out.len) return error.BufferTooSmall;
        self.out[self.pos] = 0;
        self.pos += 1;
        self.pending_pad = false;
    }

    pub fn written(self: *const DataBlockWriter) []u8 {
        return self.out[0..self.pos];
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "the request address is a bit address" {
    // DB1.DBW20 -> 20 * 8 = 160 = 0x0000A0. These are the octets the reference
    // stack put on the wire (see goldens.zig).
    const it = try Item.at(.db, 1, 20, 0, .byte, 4);
    try testing.expectEqual(@as(u24, 0xA0), it.address);
    var buf: [16]u8 = undefined;
    try testing.expectEqualSlices(u8, &[_]u8{
        0x12, 0x0A, 0x10, 0x02, 0x00, 0x04, 0x00, 0x01, 0x84, 0x00, 0x00, 0xA0,
    }, try it.encode(&buf));

    // M10.2 -> 10 * 8 + 2 = 82 = 0x52.
    const m = try Item.at(.flags, 0, 10, 2, .bit, 1);
    try testing.expectEqual(@as(u24, 0x52), m.address);
    try testing.expectEqualSlices(u8, &[_]u8{
        0x12, 0x0A, 0x10, 0x01, 0x00, 0x01, 0x00, 0x00, 0x83, 0x00, 0x00, 0x52,
    }, try m.encode(&buf));

    // Round trip through the decoder.
    const back = try Item.decode(try m.encode(&buf));
    try testing.expectEqual(@as(u32, 10), back.byteOffset());
    try testing.expectEqual(@as(u3, 2), back.bitOffset());
}

test "counter and timer areas address elements, not bits" {
    const c = try Item.at(.counter, 0, 3, 0, .counter, 2);
    try testing.expectEqual(@as(u24, 3), c.address);
    try testing.expectEqual(@as(u32, 3), c.byteOffset());
    // A bit index makes no sense there.
    try testing.expectError(error.AddressOutOfRange, Item.at(.timer, 0, 3, 1, .timer, 1));
}

test "address range is 24 bits" {
    // The largest byte offset that still fits: 0xFFFFFF / 8 = 2097151.
    _ = try Item.at(.db, 1, 2097151, 7, .byte, 1);
    try testing.expectError(error.AddressOutOfRange, Item.at(.db, 1, 2097152, 0, .byte, 1));
}

test "item decode rejects a foreign syntax id and a bad marker" {
    var wire = [_]u8{ 0x12, 0x0A, 0x10, 0x02, 0x00, 0x04, 0x00, 0x01, 0x84, 0x00, 0x00, 0xA0 };
    _ = try Item.decode(&wire);
    wire[0] = 0x13;
    try testing.expectError(error.BadVarSpec, Item.decode(&wire));
    wire[0] = 0x12;
    wire[1] = 0x0B;
    try testing.expectError(error.BadSpecLength, Item.decode(&wire));
    wire[1] = 0x0A;
    // Symbolic addressing (S7-1200/1500 optimised blocks).
    wire[2] = 0xB2;
    try testing.expectError(error.UnsupportedSyntaxId, Item.decode(&wire));
    try testing.expectError(error.ShortItem, Item.decode(&[_]u8{ 0x12, 0x0A, 0x10 }));
    try testing.expectError(error.ShortItem, Item.decode(&[_]u8{0x12}));
}

test "length unit follows the data transport size" {
    // Bit-counted.
    try testing.expect(DataTransportSize.bit.lengthInBits());
    try testing.expect(DataTransportSize.byte_word_dword.lengthInBits());
    try testing.expect(DataTransportSize.int.lengthInBits());
    // Byte-counted.
    try testing.expect(!DataTransportSize.dint.lengthInBits());
    try testing.expect(!DataTransportSize.real.lengthInBits());
    try testing.expect(!DataTransportSize.octet_string.lengthInBits());

    try testing.expectEqual(@as(u16, 32), try encodeLength(.byte_word_dword, 4));
    try testing.expectEqual(@as(usize, 4), try decodeLength(.byte_word_dword, 32));
    try testing.expectEqual(@as(u16, 4), try encodeLength(.real, 4));
    try testing.expectEqual(@as(usize, 4), try decodeLength(.real, 4));
    try testing.expectEqual(@as(u16, 4), try encodeLength(.octet_string, 4));
    // A single bit: 1 bit on the wire, 1 octet of payload.
    try testing.expectEqual(@as(usize, 1), try decodeLength(.bit, 1));
    // A bit-counted length that is neither a whole octet nor a single bit.
    try testing.expectError(error.LengthTransportMismatch, decodeLength(.byte_word_dword, 12));
    try testing.expectError(error.LengthTransportMismatch, decodeLength(.int, 3));
}

test "data item iterator pads between items but not after the last" {
    // Three items of 1, 3 and 2 octets, exactly as the reference stack emits
    // them (see goldens.zig): pad octets are arbitrary, here 0xBA and 0x00.
    const block = [_]u8{
        0xFF, 0x04, 0x00, 0x08, 0x00, 0x00, // item 1: 1 octet + pad
        0xFF, 0x04, 0x00, 0x18, 0x04, 0x05, 0x06, 0xBA, // item 2: 3 octets + pad
        0xFF, 0x04, 0x00, 0x10, 0x00, 0x00, // item 3: 2 octets, no pad
    };
    var it = DataItemIterator.init(&block, 3);
    const a = (try it.next()).?;
    try testing.expectEqualSlices(u8, &[_]u8{0x00}, a.payload);
    const b = (try it.next()).?;
    try testing.expectEqualSlices(u8, &[_]u8{ 0x04, 0x05, 0x06 }, b.payload);
    const c = (try it.next()).?;
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00 }, c.payload);
    try testing.expect((try it.next()) == null);
    try testing.expectEqual(block.len, it.consumed());
}

test "a failed item carries no payload and is followed immediately by the next" {
    // Reference capture: DB 77 does not exist, DB 1 does.
    const block = [_]u8{
        0x0A, 0x00, 0x00, 0x04, // object does not exist, length field 4, no data
        0xFF, 0x04, 0x00, 0x10,
        0x00, 0x01,
    };
    var it = DataItemIterator.init(&block, 2);
    const bad = (try it.next()).?;
    try testing.expectEqual(ReturnCode.object_does_not_exist, bad.return_code);
    try testing.expectEqual(@as(usize, 0), bad.payload.len);
    try testing.expectEqual(@as(u16, 4), bad.raw_length);
    const good = (try it.next()).?;
    try testing.expect(good.return_code.isSuccess());
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x01 }, good.payload);
    try testing.expectEqual(block.len, it.consumed());
}

test "iterator refuses a length that runs past the block" {
    // Announces 0x0100 bits = 32 octets, has 2.
    const block = [_]u8{ 0xFF, 0x04, 0x01, 0x00, 0xAA, 0xBB };
    var it = DataItemIterator.init(&block, 1);
    try testing.expectError(error.BadDataLength, it.next());

    // Count says two items, block only holds one.
    const one = [_]u8{ 0xFF, 0x04, 0x00, 0x10, 0xAA, 0xBB };
    var it2 = DataItemIterator.init(&one, 2);
    _ = try it2.next();
    try testing.expectError(error.ShortItem, it2.next());

    // A truncated item header.
    const stub = [_]u8{ 0xFF, 0x04 };
    var it3 = DataItemIterator.init(&stub, 1);
    try testing.expectError(error.ShortItem, it3.next());
}

test "F7(b): a length one octet past the block is refused (boundary, not a gross overrun)" {
    // The audit's mutation `self.pos + 4 + n > self.bytes.len` ->
    // `> self.bytes.len + 1` survived the suite: the existing "runs past the
    // block" test overshoots by 30 octets (32 claimed, 2 present), which
    // both the real guard and the mutant reject. The exact boundary the
    // mutant opens up -- `pos + 4 + n == bytes.len + 1`, one octet over --
    // needs its own case.
    //
    // Positive control: header (4) + 2 octets present, length field claims
    // exactly 2 octets (16 bits) -- fits exactly, must succeed.
    const exact = [_]u8{ 0xFF, 0x04, 0x00, 0x10, 0xAA, 0xBB };
    var it_ok = DataItemIterator.init(&exact, 1);
    const good = (try it_ok.next()).?;
    try testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB }, good.payload);

    // Same block, length field claims 3 octets (24 bits) -- one more than
    // the 2 that are actually present. Must be refused, not read as
    // `bytes[4..][0..3]` (one octet past the 6-octet block).
    const over = [_]u8{ 0xFF, 0x04, 0x00, 0x18, 0xAA, 0xBB };
    var it_bad = DataItemIterator.init(&over, 1);
    try testing.expectError(error.BadDataLength, it_bad.next());
}

test "writer reproduces the reference padding" {
    var buf: [64]u8 = undefined;
    var w = DataBlockWriter{ .out = &buf };
    try w.add(.byte_word_dword, &[_]u8{0x00});
    try w.add(.byte_word_dword, &[_]u8{ 0x04, 0x05, 0x06 });
    try w.add(.byte_word_dword, &[_]u8{ 0x00, 0x00 });
    try testing.expectEqualSlices(u8, &[_]u8{
        0xFF, 0x04, 0x00, 0x08, 0x00, 0x00,
        0xFF, 0x04, 0x00, 0x18, 0x04, 0x05,
        0x06, 0x00, 0xFF, 0x04, 0x00, 0x10,
        0x00, 0x00,
    }, w.written());
    // And it re-parses to the same three payloads.
    var it = DataItemIterator.init(w.written(), 3);
    try testing.expectEqual(@as(usize, 1), (try it.next()).?.payload.len);
    try testing.expectEqual(@as(usize, 3), (try it.next()).?.payload.len);
    try testing.expectEqual(@as(usize, 2), (try it.next()).?.payload.len);
}

test "F3: a bit item pads the item before it, and re-parses correctly" {
    var buf: [64]u8 = undefined;
    var w = DataBlockWriter{ .out = &buf };
    // One octet (odd length -> pending_pad) followed by a bit item. Mirrors
    // the audit repro: a byte read from DB1 followed by a bit from M0.0.
    try w.add(.byte_word_dword, &[_]u8{0x5a});
    try w.addBit(true);
    try testing.expectEqualSlices(u8, &[_]u8{
        0xFF, 0x04, 0x00, 0x08, 0x5a, 0x00, // item 0 + pad
        0xFF, 0x03, 0x00, 0x01, 0x01, // item 1 (bit, value 1)
    }, w.written());
    // And it re-parses as two items, the second correctly a 1-octet bit
    // payload with the value set -- before the fix, the missing pad byte
    // shifted the decoder by one octet and item 1 came back as a `0x03`
    // (`access_denied`) failed item instead.
    var it = DataItemIterator.init(w.written(), 2);
    const item0 = (try it.next()).?;
    try testing.expect(item0.return_code.isSuccess());
    try testing.expectEqualSlices(u8, &[_]u8{0x5a}, item0.payload);
    const item1 = (try it.next()).?;
    try testing.expect(item1.return_code.isSuccess());
    try testing.expectEqual(DataTransportSize.bit, item1.transport_size);
    try testing.expectEqualSlices(u8, &[_]u8{0x01}, item1.payload);
}

test "writer refuses to overflow the caller's buffer" {
    var small: [5]u8 = undefined;
    var w = DataBlockWriter{ .out = &small };
    try testing.expectError(error.BufferTooSmall, w.add(.byte_word_dword, &[_]u8{ 1, 2 }));
}

test "payloadBytes covers the element widths" {
    try testing.expectEqual(@as(u32, 4), (try Item.at(.db, 1, 0, 0, .byte, 4)).payloadBytes().?);
    try testing.expectEqual(@as(u32, 8), (try Item.at(.db, 1, 0, 0, .word, 4)).payloadBytes().?);
    try testing.expectEqual(@as(u32, 16), (try Item.at(.db, 1, 0, 0, .real, 4)).payloadBytes().?);
    try testing.expectEqual(@as(u32, 1), (try Item.at(.db, 1, 0, 0, .bit, 1)).payloadBytes().?);
    try testing.expectEqual(@as(u32, 2), (try Item.at(.db, 1, 0, 0, .bit, 9)).payloadBytes().?);
    try testing.expectEqual(@as(u32, 4), (try Item.at(.counter, 0, 0, 0, .counter, 2)).payloadBytes().?);
    try testing.expect((try Item.at(.db, 1, 0, 0, @enumFromInt(0x77), 1)).payloadBytes() == null);
}

/// The corpus-entry format `Smith.slice` reads: a little-endian u32 length,
/// then the frame. Was a local copy in every file that needed it -- 33 across 12
/// modules in three shapes -- each with its own note about the same trap (the
/// array has to be container-level or the returned slice dangles with the RIGHT
/// length and garbage behind it). It lives in `testkit.fuzz` now, with tests
/// that drive the real `std.testing.Smith` over what it produces.
const fuzzSeed = @import("testkit").fuzz.seedHex;

/// Twelve-octet S7ANY item descriptors: one per transport size a client really
/// asks for, the two areas whose address counts elements rather than bits, and
/// the prefixes `decode` refuses.
const item_seeds = [_][]const u8{
    fuzzSeed("120a10020004000184000000"), // word, 4 elements, DB 1
    fuzzSeed("120a10010001000184000003"), // bit, DB 1, bit 3
    fuzzSeed("120a10020001000084000020"), // word, DB 0
    fuzzSeed("120a10040002000184000020"), // dword
    fuzzSeed("120a10010008000083000000"), // bit in the flag area
    fuzzSeed("120a10010001000081000000"), // inputs
    fuzzSeed("120a10010001000082000000"), // outputs
    fuzzSeed("120a1005000100001c000000"), // counter
    fuzzSeed("120a1005000100001d000000"), // timer
    fuzzSeed("120a10ff0001000184000000"), // a transport size nobody defines
    fuzzSeed("120a10020000000184000000"), // element count zero
    fuzzSeed("120a1002ffff000184000000"), // element count 65535
    fuzzSeed("110a10020004000184000000"), // wrong specification octet
    fuzzSeed("120b10020004000184000000"), // wrong length octet
    fuzzSeed("120a10"), // shorter than one item
};

test "fuzz: item decode never panics" {
    try std.testing.fuzz({}, fuzzItem, .{ .corpus = &item_seeds });
}

fn fuzzItem(_: void, smith: *std.testing.Smith) !void {
    var buf: [32]u8 = undefined;
    // ⚠ One `smith.slice` call, never `bytes` followed by a ranged length.
    // `Smith.bytes` consumes the whole remaining seed, and the ranged draw then
    // finds fewer than eight octets left and returns the range MINIMUM — so the
    // length was 0 for every seed and this harness only ever saw the empty
    // input. Measured on 2026-09-06 over the corpus above: **0 of 15
    // non-empty and 0 decoded before, 15 of 15 non-empty and 12 decoded after.**
    const len: usize = smith.slice(&buf);
    const it = Item.decode(buf[0..len]) catch return;
    var round: [item_len]u8 = undefined;
    try testing.expectEqualSlices(u8, buf[0..item_len], try it.encode(&round));
}

/// Data-item blocks as a Read/Write Var reply carries them: a return code, a
/// transport size, a length that is counted in BITS for `byte_word_dword`, and
/// the payload — with and without the odd-length pad octet.
const data_item_seeds = [_][]const u8{
    fuzzSeed("ff040008aa"), // one item, 8 bits = 1 octet
    fuzzSeed("ff040010aabb"), // one item, 2 octets
    fuzzSeed("ff040008aa00ff040008bb"), // two items, the first padded
    fuzzSeed("ff040100aabb"), // a length of 0x0100 bits = 32 octets, 2 present
    fuzzSeed("0a000000"), // an error entry: return code, null size, length 0
    fuzzSeed("0a0000000a000000"), // two error entries
    fuzzSeed("ff09000400110000"), // an octet-counted size
    fuzzSeed("ff04"), // truncated inside the header
    fuzzSeed("ff040000"), // declared length zero
    fuzzSeed("ffff0008aa"), // a transport size nobody defines
};

test "fuzz: data item iterator never panics or runs past its block" {
    try std.testing.fuzz({}, fuzzDataItems, .{ .corpus = &data_item_seeds });
}

fn fuzzDataItems(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    // ⚠ See `fuzzItem`. `count` is drawn AFTER the block now and with
    // `value(u64)`, not `valueRangeAtMost`: a ranged draw returns its minimum
    // unless the word it reads already lies inside the range, so the iterator
    // was always constructed with a count of 0 and stopped before its first
    // step. Measured on 2026-09-06 over the corpus above: **0 of 10 non-empty
    // and one single (block, count) pair before; 10 of 10 non-empty
    // and 6 distinct pairs after.**
    const len: usize = smith.slice(&buf);
    const count: u16 = @intCast(smith.value(u64) % 41);
    var it = DataItemIterator.init(buf[0..len], count);
    var guard: usize = 0;
    while (true) {
        guard += 1;
        try testing.expect(guard <= 64);
        const got = it.next() catch return;
        if (got == null) break;
        try testing.expect(it.consumed() <= len);
    }
}
