// SPDX-License-Identifier: MIT

//! **PCCC over CIP** (`Execute PCCC`, service 0x4B on the PCCC object, class
//! 0x67): the legacy SLC 500 / MicroLogix / PLC-5 data-table protocol (DF1
//! commands) carried in a CIP message, so that a driver written for those
//! controllers can talk to an EtherNet/IP device.
//!
//! The wire, as the references use it (pycomm3's `SLCDriver`, MIT, read for
//! behaviour; the DF1 command set is Allen-Bradley's publication 1770-6.5.16
//! and is not reproduced here):
//!
//! ```text
//! request  4B  02  20 67 24 01   07 <vendor:2> <serial:4>   <CMD> <STS> <TNS:2> <FNC> <data...>
//! reply    CB  00  <status> 00   07 <vendor:2> <serial:4>   <CMD|0x40> <STS> <TNS:2> <data...>
//! ```
//!
//! The seven octets after the CIP path are the *requester id* (a length octet
//! that is always 7, the requester's vendor id and serial number) and the
//! reply echoes them. `STS` is 0 in a request and the DF1 status in a reply;
//! `TNS` is the transaction number, echoed.
//!
//! This file is the codec and the data-table model: the commands an SLC-class
//! driver uses (the typed logical read `0xA2` and masked write `0xAB` with
//! three address fields, and the diagnostic status `06 03` that a driver asks
//! the processor type with), the file types and their element sizes, and the
//! status codes. The adapter serves them from caller-owned files.

const std = @import("std");

/// The PCCC object's class code, and its only instance.
pub const class_code: u16 = 0x67;
pub const instance: u16 = 1;
/// `Execute PCCC`.
pub const service_execute: u8 = 0x4B;
/// `20 67 24 01`: class 0x67, instance 1 (the path a request carries).
pub const path = [_]u8{ 0x20, 0x67, 0x24, 0x01 };

pub const DecodeError = error{
    /// Shorter than the requester id plus the four PCCC header octets.
    Truncated,
    /// The requester id's length octet is not 7.
    BadRequesterLength,
};

pub const EncodeError = error{BufferTooSmall};

/// Who is asking: the vendor id and serial number the reply echoes.
pub const Requester = struct {
    vendor_id: u16,
    serial: u32,

    pub const encoded_len: usize = 7;
};

/// DF1 commands (CMD) this module knows.
pub const Cmd = struct {
    /// The "unprotected / protected typed" family: functions in `Fnc`.
    pub const typed: u8 = 0x0F;
    /// Diagnostic and status commands.
    pub const status: u8 = 0x06;
    /// A reply carries the command with this bit set.
    pub const reply_bit: u8 = 0x40;
};

pub const Fnc = struct {
    /// CMD 0x0F: protected typed logical read, three address fields.
    pub const typed_read: u8 = 0xA2;
    /// CMD 0x0F: protected typed logical masked write, three address fields.
    pub const typed_masked_write: u8 = 0xAB;
    /// CMD 0x06: diagnostic status.
    pub const diagnostic_status: u8 = 0x03;
};

/// DF1 status codes (`STS`) a target answers with (the values pycomm3
/// documents).
pub const Sts = struct {
    pub const success: u8 = 0x00;
    /// "Illegal command or format; address may not exist or not enough
    /// elements in data file".
    pub const illegal: u8 = 0x10;
    /// "Function not allowed due to command protection selection".
    pub const protected: u8 = 0x60;
};

/// A data-file type: its type code on the wire and the size of one element.
pub const FileType = enum(u8) {
    output = 0x82,
    input = 0x83,
    status = 0x84,
    bit = 0x85,
    timer = 0x86,
    counter = 0x87,
    control = 0x88,
    integer = 0x89,
    float = 0x8A,
    string = 0x8D,
    ascii = 0x8E,
    long = 0x91,
    message = 0x92,
    pid = 0x93,
    pls = 0x94,
    _,

    /// Octets in one element (`null` for a type this module does not size).
    pub fn elementSize(self: FileType) ?usize {
        return switch (self) {
            .output, .input, .status, .bit, .integer, .ascii => 2,
            .timer, .counter, .control => 6,
            .float, .long => 4,
            .string => 84,
            .message => 50,
            .pid => 46,
            .pls => 12,
            _ => null,
        };
    }

    /// The file-type letter of an address (`N7:0` is `.integer`), case-blind.
    pub fn fromLetters(letters: []const u8) ?FileType {
        const table = [_]struct { []const u8, FileType }{
            .{ "O", .output },   .{ "I", .input },   .{ "S", .status },  .{ "B", .bit },
            .{ "T", .timer },    .{ "C", .counter }, .{ "R", .control }, .{ "N", .integer },
            .{ "F", .float },    .{ "ST", .string }, .{ "A", .ascii },   .{ "L", .long },
            .{ "MG", .message }, .{ "PD", .pid },    .{ "PLS", .pls },
        };
        for (table) |e| if (std.ascii.eqlIgnoreCase(letters, e[0])) return e[1];
        return null;
    }
};

/// A PCCC message after the requester id.
pub const Message = struct {
    cmd: u8,
    sts: u8,
    tns: u16,
    /// Everything after `TNS`: for a request the function code and its data,
    /// for a reply the data.
    body: []const u8,
};

/// The address fields of a typed logical read or write.
pub const TypedAddress = struct {
    /// Octets to transfer.
    byte_size: u8,
    file_number: u8,
    file_type: FileType,
    element: u8,
    /// Sub-element: a word index inside a structured element (a timer's
    /// preset is 1, its accumulator 2).
    sub_element: u8,

    pub const encoded_len: usize = 5;

    pub fn encode(self: TypedAddress, out: []u8) EncodeError![]u8 {
        if (out.len < encoded_len) return error.BufferTooSmall;
        out[0] = self.byte_size;
        out[1] = self.file_number;
        out[2] = @backingInt(self.file_type);
        out[3] = self.element;
        out[4] = self.sub_element;
        return out[0..encoded_len];
    }

    pub fn decode(bytes: []const u8) DecodeError!TypedAddress {
        if (bytes.len < encoded_len) return error.Truncated;
        return .{
            .byte_size = bytes[0],
            .file_number = bytes[1],
            .file_type = @fromBackingInt(bytes[2]),
            .element = bytes[3],
            .sub_element = bytes[4],
        };
    }
};

/// `Execute PCCC` request data: the requester id and one PCCC message.
pub fn encodeRequestData(who: Requester, msg: Message, out: []u8) EncodeError![]u8 {
    const need = Requester.encoded_len + 4 + msg.body.len;
    if (out.len < need) return error.BufferTooSmall;
    out[0] = 7;
    std.mem.writeInt(u16, out[1..3], who.vendor_id, .little);
    std.mem.writeInt(u32, out[3..7], who.serial, .little);
    out[7] = msg.cmd;
    out[8] = msg.sts;
    std.mem.writeInt(u16, out[9..11], msg.tns, .little);
    @memcpy(out[11..][0..msg.body.len], msg.body);
    return out[0..need];
}

/// The inverse: the same layout in a request and in a reply.
pub fn decodeData(bytes: []const u8) DecodeError!struct { who: Requester, msg: Message } {
    if (bytes.len < Requester.encoded_len + 4) return error.Truncated;
    if (bytes[0] != 7) return error.BadRequesterLength;
    return .{
        .who = .{
            .vendor_id = std.mem.readInt(u16, bytes[1..3], .little),
            .serial = std.mem.readInt(u32, bytes[3..7], .little),
        },
        .msg = .{
            .cmd = bytes[7],
            .sts = bytes[8],
            .tns = std.mem.readInt(u16, bytes[9..11], .little),
            .body = bytes[11..],
        },
    };
}

/// A typed logical read request body: `FNC 0xA2` and its address.
pub fn typedReadBody(addr: TypedAddress, out: []u8) EncodeError![]u8 {
    if (out.len < 1 + TypedAddress.encoded_len) return error.BufferTooSmall;
    out[0] = Fnc.typed_read;
    _ = try addr.encode(out[1..]);
    return out[0 .. 1 + TypedAddress.encoded_len];
}

/// A masked write request body: `FNC 0xAB`, the address, the 16-bit mask
/// (little-endian; 0xFFFF writes every bit of the first word) and the data.
pub fn typedMaskedWriteBody(addr: TypedAddress, mask: u16, data: []const u8, out: []u8) EncodeError![]u8 {
    const need = 1 + TypedAddress.encoded_len + 2 + data.len;
    if (out.len < need) return error.BufferTooSmall;
    out[0] = Fnc.typed_masked_write;
    _ = try addr.encode(out[1..]);
    std.mem.writeInt(u16, out[6..8], mask, .little);
    @memcpy(out[8..][0..data.len], data);
    return out[0..need];
}

/// A caller-owned data file the adapter serves: `number` is the file number
/// of the address (`N7` is 7), `data` its elements back to back.
pub const File = struct {
    number: u8,
    file_type: FileType,
    data: []u8,
    /// Whether a masked write may change it.
    writable: bool = true,
};

/// The processor name a diagnostic status reply carries (11 characters,
/// space padded), which is what a driver reports as the processor type.
pub const default_processor = "1747-L542B ";

/// What `serve` answers: the DF1 status and the reply data.
pub const Served = struct { sts: u8, data: []const u8 };

/// Serves one PCCC message against `files`. Returns the reply message body
/// (the data after `TNS`) in `out` and the status to put in the reply.
pub fn serve(files: []const File, processor: []const u8, msg: Message, out: []u8) Served {
    if (msg.cmd == Cmd.status and msg.body.len >= 1 and msg.body[0] == Fnc.diagnostic_status) {
        // Five octets of status, then the processor name, as DF1's
        // diagnostic status reply lays it out (the driver reads the name at
        // offset 5).
        if (out.len < 16) return .{ .sts = Sts.illegal, .data = &.{} };
        @memset(out[0..5], 0);
        @memset(out[5..16], ' ');
        @memcpy(out[5..][0..@min(processor.len, 11)], processor[0..@min(processor.len, 11)]);
        return .{ .sts = Sts.success, .data = out[0..16] };
    }
    if (msg.cmd != Cmd.typed or msg.body.len < 1) return .{ .sts = Sts.illegal, .data = &.{} };
    const fnc = msg.body[0];
    const addr = TypedAddress.decode(msg.body[1..]) catch return .{ .sts = Sts.illegal, .data = &.{} };
    const file = find(files, addr) orelse return .{ .sts = Sts.illegal, .data = &.{} };
    const esize = addr.file_type.elementSize() orelse return .{ .sts = Sts.illegal, .data = &.{} };
    const start = @as(usize, addr.element) * esize + @as(usize, addr.sub_element) * 2;
    const len: usize = addr.byte_size;
    if (len == 0 or start + len > file.data.len) return .{ .sts = Sts.illegal, .data = &.{} };
    switch (fnc) {
        Fnc.typed_read => {
            if (out.len < len) return .{ .sts = Sts.illegal, .data = &.{} };
            @memcpy(out[0..len], file.data[start..][0..len]);
            return .{ .sts = Sts.success, .data = out[0..len] };
        },
        Fnc.typed_masked_write => {
            const rest = msg.body[1 + TypedAddress.encoded_len ..];
            if (rest.len != 2 + len) return .{ .sts = Sts.illegal, .data = &.{} };
            if (!file.writable) return .{ .sts = Sts.protected, .data = &.{} };
            const mask = std.mem.readInt(u16, rest[0..2], .little);
            const data = rest[2..];
            // The mask belongs to the first 16-bit word; the rest of the
            // data is written whole.
            if (len >= 2) {
                const old = std.mem.readInt(u16, file.data[start..][0..2], .little);
                const val = std.mem.readInt(u16, data[0..2], .little);
                std.mem.writeInt(u16, file.data[start..][0..2], (old & ~mask) | (val & mask), .little);
                @memcpy(file.data[start + 2 ..][0 .. len - 2], data[2..]);
            } else {
                const m: u8 = @truncate(mask);
                file.data[start] = (file.data[start] & ~m) | (data[0] & m);
            }
            return .{ .sts = Sts.success, .data = &.{} };
        },
        else => return .{ .sts = Sts.illegal, .data = &.{} },
    }
}

fn find(files: []const File, addr: TypedAddress) ?File {
    for (files) |f| {
        if (f.number == addr.file_number and f.file_type == addr.file_type) return f;
    }
    return null;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "request and reply data share one layout: requester id, CMD, STS, TNS, body" {
    var buf: [64]u8 = undefined;
    var body: [16]u8 = undefined;
    const rb = try typedReadBody(.{ .byte_size = 2, .file_number = 7, .file_type = .integer, .element = 3, .sub_element = 0 }, &body);
    const wire = try encodeRequestData(.{ .vendor_id = 0x1009, .serial = 0x71191009 }, .{ .cmd = Cmd.typed, .sts = 0, .tns = 0x0030, .body = rb }, &buf);
    try testing.expectEqualSlices(u8, &.{
        0x07, 0x09, 0x10, 0x09, 0x10, 0x19, 0x71, // requester id
        0x0F, 0x00, 0x30, 0x00, // CMD, STS, TNS
        0xA2, 0x02, 0x07, 0x89, 0x03, 0x00, // read 2 octets of N7:3
    }, wire);
    const back = try decodeData(wire);
    try testing.expectEqual(@as(u32, 0x71191009), back.who.serial);
    try testing.expectEqual(@as(u16, 0x30), back.msg.tns);
    try testing.expectEqual(FileType.integer, (try TypedAddress.decode(back.msg.body[1..])).file_type);
    try testing.expectError(error.Truncated, decodeData(wire[0..10]));
    var bad = buf;
    bad[0] = 6;
    try testing.expectError(error.BadRequesterLength, decodeData(bad[0..wire.len]));
    try testing.expectError(error.BufferTooSmall, encodeRequestData(.{ .vendor_id = 0, .serial = 0 }, .{ .cmd = 0, .sts = 0, .tns = 0, .body = rb }, buf[0..10]));
}

test "file types: codes, element sizes, letters" {
    try testing.expectEqual(@as(?usize, 2), FileType.integer.elementSize());
    try testing.expectEqual(@as(?usize, 6), FileType.timer.elementSize());
    try testing.expectEqual(@as(?usize, 84), FileType.string.elementSize());
    try testing.expectEqual(@as(?usize, null), (@as(FileType, @fromBackingInt(0x01))).elementSize());
    try testing.expectEqual(@as(?FileType, .float), FileType.fromLetters("f"));
    try testing.expectEqual(@as(?FileType, .string), FileType.fromLetters("ST"));
    try testing.expectEqual(@as(?FileType, null), FileType.fromLetters("Q"));
    try testing.expectEqual(@as(u8, 0x89), @backingInt(FileType.integer));
}

fn pcccServe(files: []const File, body: []const u8, cmd: u8, out: []u8) Served {
    return serve(files, default_processor, .{ .cmd = cmd, .sts = 0, .tns = 1, .body = body }, out);
}

test "serve: typed reads of words, timers (sub-elements) and out-of-range" {
    var n7: [20]u8 = undefined;
    for (&n7, 0..) |*b, i| b.* = @intCast(i);
    var t4: [12]u8 = .{ 0, 0x80, 10, 0, 20, 0, 0, 0, 0, 0, 0, 0 };
    const files = [_]File{
        .{ .number = 7, .file_type = .integer, .data = &n7 },
        .{ .number = 4, .file_type = .timer, .data = &t4 },
    };
    var out: [64]u8 = undefined;
    var body: [8]u8 = undefined;
    // N7:2, one word.
    var r = pcccServe(&files, try typedReadBody(.{ .byte_size = 2, .file_number = 7, .file_type = .integer, .element = 2, .sub_element = 0 }, &body), Cmd.typed, &out);
    try testing.expectEqualSlices(u8, &.{ 4, 5 }, r.data);
    // N7:0, five words.
    r = pcccServe(&files, try typedReadBody(.{ .byte_size = 10, .file_number = 7, .file_type = .integer, .element = 0, .sub_element = 0 }, &body), Cmd.typed, &out);
    try testing.expectEqual(@as(usize, 10), r.data.len);
    // T4:0.ACC (sub-element 2) is the third word of the timer.
    r = pcccServe(&files, try typedReadBody(.{ .byte_size = 2, .file_number = 4, .file_type = .timer, .element = 0, .sub_element = 2 }, &body), Cmd.typed, &out);
    try testing.expectEqualSlices(u8, &.{ 20, 0 }, r.data);
    // Past the end, a missing file, the wrong type for the file, zero length: all "illegal".
    for ([_]TypedAddress{
        .{ .byte_size = 2, .file_number = 7, .file_type = .integer, .element = 10, .sub_element = 0 },
        .{ .byte_size = 2, .file_number = 9, .file_type = .integer, .element = 0, .sub_element = 0 },
        .{ .byte_size = 2, .file_number = 7, .file_type = .float, .element = 0, .sub_element = 0 },
        .{ .byte_size = 0, .file_number = 7, .file_type = .integer, .element = 0, .sub_element = 0 },
    }) |a| {
        r = pcccServe(&files, try typedReadBody(a, &body), Cmd.typed, &out);
        try testing.expectEqual(Sts.illegal, r.sts);
    }
    // An unknown function and an unknown command.
    try testing.expectEqual(Sts.illegal, pcccServe(&files, &.{0x55}, Cmd.typed, &out).sts);
    try testing.expectEqual(Sts.illegal, pcccServe(&files, &.{0x03}, 0x99, &out).sts);
}

test "serve: masked write changes the masked bits of the first word, protects read-only files, answers the diagnostic status" {
    var n7: [8]u8 = .{ 0xFF, 0xFF, 1, 2, 3, 4, 5, 6 };
    var ro: [2]u8 = .{ 1, 0 };
    const files = [_]File{
        .{ .number = 7, .file_type = .integer, .data = &n7 },
        .{ .number = 8, .file_type = .integer, .data = &ro, .writable = false },
    };
    var out: [64]u8 = undefined;
    var body: [32]u8 = undefined;
    // Clear bit 0 of N7:0 only.
    var r = pcccServe(&files, try typedMaskedWriteBody(.{ .byte_size = 2, .file_number = 7, .file_type = .integer, .element = 0, .sub_element = 0 }, 0x0001, &.{ 0x00, 0x00 }, &body), Cmd.typed, &out);
    try testing.expectEqual(Sts.success, r.sts);
    try testing.expectEqualSlices(u8, &.{ 0xFE, 0xFF }, n7[0..2]);
    // Two words, mask FFFF: the first replaced, the second written whole.
    r = pcccServe(&files, try typedMaskedWriteBody(.{ .byte_size = 4, .file_number = 7, .file_type = .integer, .element = 1, .sub_element = 0 }, 0xFFFF, &.{ 9, 9, 8, 8 }, &body), Cmd.typed, &out);
    try testing.expectEqual(Sts.success, r.sts);
    try testing.expectEqualSlices(u8, &.{ 9, 9, 8, 8 }, n7[2..6]);
    // The data must be as long as the byte size says; a read-only file is protected.
    try testing.expectEqual(Sts.illegal, pcccServe(&files, try typedMaskedWriteBody(.{ .byte_size = 4, .file_number = 7, .file_type = .integer, .element = 0, .sub_element = 0 }, 0xFFFF, &.{ 1, 2 }, &body), Cmd.typed, &out).sts);
    try testing.expectEqual(Sts.protected, pcccServe(&files, try typedMaskedWriteBody(.{ .byte_size = 2, .file_number = 8, .file_type = .integer, .element = 0, .sub_element = 0 }, 0xFFFF, &.{ 0, 0 }, &body), Cmd.typed, &out).sts);
    try testing.expectEqual(@as(u8, 1), ro[0]);
    // Diagnostic status: five octets, then the name at offset 5.
    r = pcccServe(&files, &.{Fnc.diagnostic_status}, Cmd.status, &out);
    try testing.expectEqual(Sts.success, r.sts);
    try testing.expectEqualStrings("1747-L542B ", r.data[5..16]);
}
