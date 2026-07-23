// SPDX-License-Identifier: MIT

//! **EPATH** (CIP Volume 1, Appendix C): the segment encoding that names what
//! a CIP request is talking to — an object class, an instance, an attribute, a
//! symbolic tag, or a route through a chassis.
//!
//! Four rules carry almost all of the bugs:
//!
//! 1. **The path size is counted in 16-bit words, not octets.** Everything an
//!    EPATH can contain is therefore padded to an even length, and a builder
//!    that forgets is off by one for the entire rest of the message.
//! 2. **A 16- or 32-bit logical segment carries a pad octet after its type
//!    octet** in a *padded* EPATH (which is what the message router and the
//!    connection path use). In a *packed* EPATH (inside some data segments)
//!    it does not. The same octets mean different things in the two contexts,
//!    so `padded` is an explicit parameter here and never a guess.
//! 3. **An ANSI Extended Symbol segment (`0x91`) is padded to even, and the
//!    pad is not part of the name.** `91 05 "SCADA" 00` is five characters
//!    followed by a pad octet, not a six-character name ending in NUL. A
//!    decoder that keeps the pad compares tag names wrongly forever after.
//! 4. **Array element indices are Member ID segments** (`0x28`/`0x29`/`0x2A`),
//!    not attribute or instance segments. `MyArray[3]` is
//!    `91 07 "MyArray" 00 28 03`.
//!
//! Every walk bounds itself against the buffer, so a segment whose declared
//! size runs past the path is a typed error rather than a read past the end.

const std = @import("std");

pub const DecodeError = error{
    /// The path ran out mid-segment.
    Truncated,
    /// A segment's declared size runs past the end of the path.
    SegmentOverruns,
    /// A segment type this module does not model.
    UnsupportedSegment,
    /// A logical segment with the reserved 3 format, or a reserved logical
    /// type.
    ReservedFormat,
    /// A symbolic segment with a zero length, which names nothing.
    EmptySymbol,
    /// A padded 16/32-bit logical segment whose pad octet is not zero. The
    /// spec fixes it at zero; a non-zero value means the path is misaligned.
    BadPad,
};

pub const EncodeError = error{
    BufferTooSmall,
    /// A symbolic name longer than the 255 octets the length field holds, or
    /// a link address longer than 255.
    TooLong,
    /// A path whose octet length is odd cannot be expressed as a word count.
    OddPathLength,
    /// A path longer than the 255 words the path-size octet holds.
    PathTooLong,
    /// A symbolic segment naming nothing.
    EmptySymbol,
};

/// The logical segment's *type* field (bits 4-2 of the segment octet).
pub const LogicalType = enum(u3) {
    class = 0,
    instance = 1,
    member = 2,
    connection_point = 3,
    attribute = 4,
    special = 5,
    service_id = 6,
    reserved = 7,
};

/// The logical segment's *format* field (bits 1-0).
pub const LogicalFormat = enum(u2) {
    bits_8 = 0,
    bits_16 = 1,
    bits_32 = 2,
    reserved = 3,
};

/// A logical segment: `{type, value}` plus the width it was written in, which
/// must be preserved so a re-encode is byte-exact (a peer may write instance 1
/// as a 16-bit segment even though 8 bits would do).
pub const Logical = struct {
    what: LogicalType,
    value: u32,
    format: LogicalFormat = .bits_8,

    /// The narrowest format that holds `value`.
    pub fn minimal(what: LogicalType, value: u32) Logical {
        return .{
            .what = what,
            .value = value,
            .format = if (value <= 0xFF) .bits_8 else if (value <= 0xFFFF) .bits_16 else .bits_32,
        };
    }
};

/// A port segment: which port to leave by, and the link address on it. The
/// backplane route every ControlLogix client sends is port 1, link `{slot}`.
pub const Port = struct {
    /// 1..14 directly, or any value when `extended_port` was used. Port 15 is
    /// the escape that means "the port number follows".
    port: u16,
    /// One octet for the common case; several for a link address that is an
    /// IP address or similar.
    link: []const u8,
};

/// A network segment. Only the single-octet forms and the "extended network"
/// form appear in practice.
pub const Network = struct {
    subtype: u5,
    /// The single-octet forms carry one value; the extended form carries a
    /// word-counted blob.
    data: []const u8,

    pub const schedule: u5 = 1;
    pub const fixed_tag: u5 = 2;
    pub const production_inhibit_time: u5 = 3;
    pub const production_inhibit_time_us: u5 = 0x10;
    pub const extended_network: u5 = 0x11;
};

/// The electronic key segment (`34 04 …`): the "am I talking to the device I
/// was configured for" check a `Forward_Open` carries.
pub const ElectronicKey = struct {
    vendor_id: u16,
    device_type: u16,
    product_code: u16,
    /// Bit 7 set = "compatibility mode": any revision at least this one.
    major_revision: u8,
    minor_revision: u8,

    pub const encoded_len: usize = 10;

    pub fn compatibilityMode(self: ElectronicKey) bool {
        return self.major_revision & 0x80 != 0;
    }
};

/// One EPATH segment.
pub const Segment = union(enum) {
    port: Port,
    logical: Logical,
    /// A short symbolic segment (`0x60 | length`).
    symbolic: []const u8,
    /// An ANSI Extended Symbol segment (`0x91`), which is what every Logix
    /// tag name is written as.
    ansi_symbol: []const u8,
    /// A Simple Data segment (`0x80`): a word-counted blob, used to carry a
    /// connection's configuration data.
    simple_data: []const u8,
    network: Network,
    electronic_key: ElectronicKey,
};

// ── segment octet helpers ───────────────────────────────────────────────────

const seg_type_port: u8 = 0x00;
const seg_type_logical: u8 = 0x20;
const seg_type_network: u8 = 0x40;
const seg_type_symbolic: u8 = 0x60;
const seg_type_data: u8 = 0x80;

/// The ANSI Extended Symbol segment octet.
pub const ansi_extended_symbol: u8 = 0x91;
/// The Simple Data segment octet.
pub const simple_data_segment: u8 = 0x80;

// ── iteration ───────────────────────────────────────────────────────────────

/// Walks an EPATH one segment at a time.
///
/// `padded` selects whether 16/32-bit logical segments carry a pad octet.
/// Message-router request paths and connection paths are padded; the packed
/// form appears inside some data segments.
pub const Iterator = struct {
    bytes: []const u8,
    off: usize = 0,
    padded: bool = true,

    pub fn init(bytes: []const u8) Iterator {
        return .{ .bytes = bytes };
    }

    pub fn initPacked(bytes: []const u8) Iterator {
        return .{ .bytes = bytes, .padded = false };
    }

    pub fn next(self: *Iterator) DecodeError!?Segment {
        if (self.off >= self.bytes.len) return null;
        const start = self.off;
        const b = self.bytes[start];
        const seg = try self.decodeAt(b);
        // A segment that consumed nothing would loop forever.
        std.debug.assert(self.off > start);
        return seg;
    }

    fn take(self: *Iterator, n: usize) DecodeError![]const u8 {
        if (self.off + n > self.bytes.len) return error.SegmentOverruns;
        const s = self.bytes[self.off..][0..n];
        self.off += n;
        return s;
    }

    fn decodeAt(self: *Iterator, b: u8) DecodeError!Segment {
        switch (b & 0xE0) {
            seg_type_port => return .{ .port = try self.decodePort(b) },
            seg_type_logical => return try self.decodeLogical(b),
            seg_type_network => return .{ .network = try self.decodeNetwork(b) },
            seg_type_symbolic => {
                self.off += 1;
                const n: usize = b & 0x1F;
                // 0x60 with a zero count is the "extended string" escape,
                // which no device seen emits; refuse rather than guess.
                if (n == 0) return error.EmptySymbol;
                const name = try self.take(n);
                if (n % 2 == 1) _ = try self.take(1); // pad to a word boundary
                return .{ .symbolic = name };
            },
            seg_type_data => {
                if (b == ansi_extended_symbol) {
                    self.off += 1;
                    const n: usize = (try self.take(1))[0];
                    if (n == 0) return error.EmptySymbol;
                    const name = try self.take(n);
                    if (n % 2 == 1) _ = try self.take(1);
                    return .{ .ansi_symbol = name };
                }
                if (b == simple_data_segment) {
                    self.off += 1;
                    const words: usize = (try self.take(1))[0];
                    return .{ .simple_data = try self.take(words * 2) };
                }
                return error.UnsupportedSegment;
            },
            else => return error.UnsupportedSegment,
        }
    }

    fn decodePort(self: *Iterator, b: u8) DecodeError!Port {
        const start = self.off;
        self.off += 1;
        const extended_size = b & 0x10 != 0;
        const port_id: u8 = b & 0x0F;
        const link_len: usize = if (extended_size) (try self.take(1))[0] else 1;
        var port: u16 = port_id;
        if (port_id == 0x0F) {
            const ext = try self.take(2);
            port = std.mem.readInt(u16, ext[0..2], .little);
        }
        const link = try self.take(link_len);
        // The pad makes **this segment** an even octet count, which is not the
        // same as making the running offset even once a packed path is in play.
        if ((self.off - start) % 2 == 1) _ = try self.take(1);
        return .{ .port = port, .link = link };
    }

    fn decodeLogical(self: *Iterator, b: u8) DecodeError!Segment {
        const what: LogicalType = @enumFromInt(@as(u3, @truncate(b >> 2)));
        const format: LogicalFormat = @enumFromInt(@as(u2, @truncate(b)));
        if (what == .reserved) return error.ReservedFormat;
        if (format == .reserved) return error.ReservedFormat;
        // The electronic key rides in the "special" logical type, and is a
        // fixed-shape 10-octet segment rather than a `{type, value}` pair.
        if (what == .special) {
            const body = try self.take(ElectronicKey.encoded_len);
            return .{ .electronic_key = try decodeElectronicKey(body) };
        }
        self.off += 1;
        switch (format) {
            .bits_8 => return .{ .logical = .{
                .what = what,
                .value = (try self.take(1))[0],
                .format = format,
            } },
            .bits_16 => {
                if (self.padded) {
                    if ((try self.take(1))[0] != 0) return error.BadPad;
                }
                const v = try self.take(2);
                return .{ .logical = .{
                    .what = what,
                    .value = std.mem.readInt(u16, v[0..2], .little),
                    .format = format,
                } };
            },
            .bits_32 => {
                if (self.padded) {
                    if ((try self.take(1))[0] != 0) return error.BadPad;
                }
                const v = try self.take(4);
                return .{ .logical = .{
                    .what = what,
                    .value = std.mem.readInt(u32, v[0..4], .little),
                    .format = format,
                } };
            },
            .reserved => unreachable,
        }
    }

    fn decodeNetwork(self: *Iterator, b: u8) DecodeError!Network {
        const subtype: u5 = @truncate(b);
        self.off += 1;
        switch (subtype) {
            Network.schedule,
            Network.fixed_tag,
            Network.production_inhibit_time,
            => return .{ .subtype = subtype, .data = try self.take(1) },
            Network.production_inhibit_time_us, Network.extended_network => {
                const words: usize = (try self.take(1))[0];
                return .{ .subtype = subtype, .data = try self.take(words * 2) };
            },
            else => return error.UnsupportedSegment,
        }
    }
};

/// The electronic key, decoded from a `34 04 …` segment. Kept separate from
/// `Iterator` because the key's body is fixed-shape and worth typing.
pub fn decodeElectronicKey(bytes: []const u8) DecodeError!ElectronicKey {
    if (bytes.len < ElectronicKey.encoded_len) return error.Truncated;
    if (bytes[0] != 0x34 or bytes[1] != 0x04) return error.UnsupportedSegment;
    return .{
        .vendor_id = std.mem.readInt(u16, bytes[2..4], .little),
        .device_type = std.mem.readInt(u16, bytes[4..6], .little),
        .product_code = std.mem.readInt(u16, bytes[6..8], .little),
        .major_revision = bytes[8],
        .minor_revision = bytes[9],
    };
}

/// Counts the segments in a path, which is also a cheap validity check.
pub fn countSegments(bytes: []const u8) DecodeError!usize {
    var it = Iterator.init(bytes);
    var n: usize = 0;
    while (try it.next()) |_| n += 1;
    return n;
}

/// The first logical segment of the given type, or null. This is how a
/// responder answers "which class is this request for".
pub fn findLogical(bytes: []const u8, what: LogicalType) DecodeError!?u32 {
    var it = Iterator.init(bytes);
    while (try it.next()) |seg| switch (seg) {
        .logical => |l| if (l.what == what) return l.value,
        else => {},
    };
    return null;
}

/// The first symbolic name in the path (short or ANSI extended), or null.
pub fn findSymbol(bytes: []const u8) DecodeError!?[]const u8 {
    var it = Iterator.init(bytes);
    while (try it.next()) |seg| switch (seg) {
        .symbolic => |s| return s,
        .ansi_symbol => |s| return s,
        else => {},
    };
    return null;
}

// ── building ────────────────────────────────────────────────────────────────

/// Writes EPATH segments into a caller-owned buffer.
///
/// `words()` is the value that goes in a request's path-size octet, and it
/// refuses an odd path rather than rounding — an odd EPATH cannot be expressed
/// in words, and rounding it silently corrupts everything downstream.
pub const Builder = struct {
    out: []u8,
    len: usize = 0,
    padded: bool = true,

    pub fn init(out: []u8) Builder {
        return .{ .out = out };
    }

    pub fn initPacked(out: []u8) Builder {
        return .{ .out = out, .padded = false };
    }

    pub fn bytes(self: *const Builder) []const u8 {
        return self.out[0..self.len];
    }

    pub fn words(self: *const Builder) EncodeError!u8 {
        if (self.len % 2 != 0) return error.OddPathLength;
        if (self.len / 2 > 255) return error.PathTooLong;
        return @intCast(self.len / 2);
    }

    fn put(self: *Builder, b: []const u8) EncodeError!void {
        if (self.len + b.len > self.out.len) return error.BufferTooSmall;
        @memcpy(self.out[self.len..][0..b.len], b);
        self.len += b.len;
    }

    pub fn logical(self: *Builder, l: Logical) EncodeError!void {
        const type_bits: u8 = @as(u8, @intFromEnum(l.what)) << 2;
        switch (l.format) {
            .bits_8 => try self.put(&[_]u8{ seg_type_logical | type_bits, @truncate(l.value) }),
            .bits_16 => {
                var b: [4]u8 = undefined;
                b[0] = seg_type_logical | type_bits | 1;
                b[1] = 0;
                std.mem.writeInt(u16, b[2..4], @truncate(l.value), .little);
                try self.put(if (self.padded) b[0..4] else &[_]u8{ b[0], b[2], b[3] });
            },
            .bits_32 => {
                var b: [6]u8 = undefined;
                b[0] = seg_type_logical | type_bits | 2;
                b[1] = 0;
                std.mem.writeInt(u32, b[2..6], l.value, .little);
                try self.put(if (self.padded) b[0..6] else &[_]u8{ b[0], b[2], b[3], b[4], b[5] });
            },
            .reserved => return error.BufferTooSmall,
        }
    }

    pub fn class(self: *Builder, v: u32) EncodeError!void {
        try self.logical(Logical.minimal(.class, v));
    }
    pub fn instance(self: *Builder, v: u32) EncodeError!void {
        try self.logical(Logical.minimal(.instance, v));
    }
    pub fn attribute(self: *Builder, v: u32) EncodeError!void {
        try self.logical(Logical.minimal(.attribute, v));
    }
    /// Array element indices go here — Logix writes them as member ids.
    pub fn member(self: *Builder, v: u32) EncodeError!void {
        try self.logical(Logical.minimal(.member, v));
    }
    pub fn connectionPoint(self: *Builder, v: u32) EncodeError!void {
        try self.logical(Logical.minimal(.connection_point, v));
    }

    /// An ANSI Extended Symbol segment, padded to even. This is how every
    /// Logix tag name is written.
    pub fn symbol(self: *Builder, name: []const u8) EncodeError!void {
        if (name.len == 0) return error.EmptySymbol;
        if (name.len > 255) return error.TooLong;
        try self.put(&[_]u8{ ansi_extended_symbol, @intCast(name.len) });
        try self.put(name);
        if (name.len % 2 == 1) try self.put(&[_]u8{0});
    }

    /// A short symbolic segment (`0x60 | length`), limited to 31 characters.
    pub fn shortSymbol(self: *Builder, name: []const u8) EncodeError!void {
        if (name.len == 0) return error.EmptySymbol;
        if (name.len > 31) return error.TooLong;
        try self.put(&[_]u8{seg_type_symbolic | @as(u8, @intCast(name.len))});
        try self.put(name);
        if (name.len % 2 == 1) try self.put(&[_]u8{0});
    }

    /// A port segment. `link` is one octet for a chassis slot and more for a
    /// link address that is an IP address or similar.
    pub fn port(self: *Builder, port_id: u16, link: []const u8) EncodeError!void {
        if (link.len == 0 or link.len > 255) return error.TooLong;
        const start = self.len;
        const extended_size = link.len > 1;
        const extended_port = port_id > 14;
        var head: u8 = if (extended_port) 0x0F else @intCast(port_id);
        if (extended_size) head |= 0x10;
        try self.put(&[_]u8{head});
        if (extended_size) try self.put(&[_]u8{@intCast(link.len)});
        if (extended_port) {
            var p: [2]u8 = undefined;
            std.mem.writeInt(u16, &p, port_id, .little);
            try self.put(&p);
        }
        try self.put(link);
        if ((self.len - start) % 2 == 1) try self.put(&[_]u8{0});
    }

    pub fn simpleData(self: *Builder, data: []const u8) EncodeError!void {
        if (data.len % 2 != 0) return error.OddPathLength;
        if (data.len / 2 > 255) return error.TooLong;
        try self.put(&[_]u8{ simple_data_segment, @intCast(data.len / 2) });
        try self.put(data);
    }

    pub fn electronicKey(self: *Builder, key: ElectronicKey) EncodeError!void {
        var b: [ElectronicKey.encoded_len]u8 = undefined;
        b[0] = 0x34;
        b[1] = 0x04;
        std.mem.writeInt(u16, b[2..4], key.vendor_id, .little);
        std.mem.writeInt(u16, b[4..6], key.device_type, .little);
        std.mem.writeInt(u16, b[6..8], key.product_code, .little);
        b[8] = key.major_revision;
        b[9] = key.minor_revision;
        try self.put(&b);
    }

    /// Re-emits a decoded segment, which is what makes a captured path
    /// re-encode byte for byte.
    pub fn segment(self: *Builder, seg: Segment) EncodeError!void {
        switch (seg) {
            .logical => |l| try self.logical(l),
            .symbolic => |s| try self.shortSymbol(s),
            .ansi_symbol => |s| try self.symbol(s),
            .simple_data => |d| try self.simpleData(d),
            .port => |p| try self.port(p.port, p.link),
            .network => |n| {
                switch (n.subtype) {
                    Network.schedule,
                    Network.fixed_tag,
                    Network.production_inhibit_time,
                    => {
                        if (n.data.len != 1) return error.BufferTooSmall;
                        try self.put(&[_]u8{seg_type_network | @as(u8, n.subtype)});
                        try self.put(n.data);
                    },
                    else => {
                        if (n.data.len % 2 != 0) return error.OddPathLength;
                        try self.put(&[_]u8{ seg_type_network | @as(u8, n.subtype), @intCast(n.data.len / 2) });
                        try self.put(n.data);
                    },
                }
            },
            .electronic_key => |k| try self.electronicKey(k),
        }
    }
};

/// The everyday `20 cc 24 ii [30 aa]` path, built in one call.
pub fn logicalPath(class_id: u32, instance: u32, attribute: ?u32, out: []u8) EncodeError![]const u8 {
    var b = Builder.init(out);
    try b.class(class_id);
    try b.instance(instance);
    if (attribute) |a| try b.attribute(a);
    return b.bytes();
}

/// Re-encodes an EPATH from its decoded segments — the check that proves the
/// decoder and encoder agree, rather than that a memcpy works.
pub fn reencode(path: []const u8, out: []u8) (DecodeError || EncodeError)![]const u8 {
    var it = Iterator.init(path);
    var b = Builder.init(out);
    while (try it.next()) |seg| try b.segment(seg);
    return b.bytes();
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "the everyday class/instance/attribute path" {
    var buf: [16]u8 = undefined;
    const p = try logicalPath(0x06, 1, null, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x20, 0x06, 0x24, 0x01 }, p);
    const p2 = try logicalPath(0x01, 1, 7, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x20, 0x01, 0x24, 0x01, 0x30, 0x07 }, p2);
    try testing.expectEqual(@as(?u32, 1), try findLogical(p2, .class));
    try testing.expectEqual(@as(?u32, 7), try findLogical(p2, .attribute));
    try testing.expectEqual(@as(?u32, null), try findLogical(p2, .member));
}

test "an odd symbolic segment pads and the pad is not part of the name" {
    var buf: [32]u8 = undefined;
    var b = Builder.init(&buf);
    try b.symbol("SCADA");
    try testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x91, 0x05, 'S', 'C', 'A', 'D', 'A', 0x00 },
        b.bytes(),
    );
    try testing.expectEqual(@as(u8, 4), try b.words());
    try testing.expectEqualStrings("SCADA", (try findSymbol(b.bytes())).?);
}

test "an even symbolic segment does not pad" {
    var buf: [32]u8 = undefined;
    var b = Builder.init(&buf);
    try b.symbol("ShortStr");
    try testing.expectEqual(@as(usize, 10), b.bytes().len);
    try testing.expectEqualStrings("ShortStr", (try findSymbol(b.bytes())).?);
}

test "an array element is a member segment, not an attribute" {
    var buf: [32]u8 = undefined;
    var b = Builder.init(&buf);
    try b.symbol("MyArray");
    try b.member(3);
    try testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x91, 0x07, 'M', 'y', 'A', 'r', 'r', 'a', 'y', 0x00, 0x28, 0x03 },
        b.bytes(),
    );
    try testing.expectEqual(@as(u8, 6), try b.words());
}

test "16- and 32-bit logical segments carry a pad when the path is padded" {
    var buf: [32]u8 = undefined;
    var b = Builder.init(&buf);
    try b.instance(0x1234);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x25, 0x00, 0x34, 0x12 }, b.bytes());

    var b32 = Builder.init(&buf);
    try b32.member(0x00112233);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x2A, 0x00, 0x33, 0x22, 0x11, 0x00 }, b32.bytes());

    // Packed: no pad octet, and therefore an odd path.
    var pk: [32]u8 = undefined;
    var bp = Builder.initPacked(&pk);
    try bp.instance(0x1234);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x25, 0x34, 0x12 }, bp.bytes());
    try testing.expectError(error.OddPathLength, bp.words());
}

test "a padded 16-bit logical segment with a dirty pad octet is refused" {
    const wire = [_]u8{ 0x25, 0xFF, 0x34, 0x12 };
    var it = Iterator.init(&wire);
    try testing.expectError(error.BadPad, it.next());
    // The packed reading of the same octets is a different, legal path.
    var pk = Iterator.initPacked(&wire);
    const seg = (try pk.next()).?;
    try testing.expectEqual(@as(u32, 0x34FF), seg.logical.value);
}

test "the backplane route path Logix clients send" {
    var buf: [16]u8 = undefined;
    var b = Builder.init(&buf);
    try b.port(1, &[_]u8{0});
    try testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x00 }, b.bytes());
    var it = Iterator.init(b.bytes());
    const seg = (try it.next()).?;
    try testing.expectEqual(@as(u16, 1), seg.port.port);
    try testing.expectEqualSlices(u8, &[_]u8{0}, seg.port.link);
}

test "an extended link address carries its own size and pads" {
    var buf: [32]u8 = undefined;
    var b = Builder.init(&buf);
    try b.port(2, "10.0.0.5");
    // 0x12 = extended size + port 2, then the length octet, then the address:
    // 1 + 1 + 8 is already even, so no pad is added.
    try testing.expectEqual(@as(u8, 0x12), b.bytes()[0]);
    try testing.expectEqual(@as(u8, 8), b.bytes()[1]);
    try testing.expectEqual(@as(usize, 10), b.bytes().len);
    var round: [32]u8 = undefined;
    try testing.expectEqualSlices(u8, b.bytes(), try reencode(b.bytes(), &round));
}

test "an extended port number uses the 0x0F escape" {
    var buf: [32]u8 = undefined;
    var b = Builder.init(&buf);
    try b.port(0x1234, &[_]u8{7});
    try testing.expectEqualSlices(u8, &[_]u8{ 0x0F, 0x34, 0x12, 0x07 }, b.bytes());
    var it = Iterator.init(b.bytes());
    const seg = (try it.next()).?;
    try testing.expectEqual(@as(u16, 0x1234), seg.port.port);
}

test "a segment whose size runs past the path is a typed error" {
    // ANSI symbol claiming 40 characters with 3 present.
    var it = Iterator.init(&[_]u8{ 0x91, 0x28, 'a', 'b', 'c' });
    try testing.expectError(error.SegmentOverruns, it.next());
    // 16-bit class segment cut short.
    var it2 = Iterator.init(&[_]u8{ 0x21, 0x00, 0x34 });
    try testing.expectError(error.SegmentOverruns, it2.next());
    // Simple data claiming 10 words with 2 octets present.
    var it3 = Iterator.init(&[_]u8{ 0x80, 0x0A, 0x01, 0x02 });
    try testing.expectError(error.SegmentOverruns, it3.next());
    // Port segment with an extended size that overruns.
    var it4 = Iterator.init(&[_]u8{ 0x11, 0x20, 0x01 });
    try testing.expectError(error.SegmentOverruns, it4.next());
}

test "a symbolic segment with a zero length names nothing" {
    var it = Iterator.init(&[_]u8{ 0x91, 0x00 });
    try testing.expectError(error.EmptySymbol, it.next());
    var it2 = Iterator.init(&[_]u8{0x60});
    try testing.expectError(error.EmptySymbol, it2.next());
    var buf: [8]u8 = undefined;
    var b = Builder.init(&buf);
    try testing.expectError(error.EmptySymbol, b.symbol(""));
}

test "an odd symbolic segment missing its pad runs into the next segment" {
    // `91 05 SCADA` with no pad, then what should be an element segment.
    // The walk consumes the 0x28 as the pad and then finds a bare 0x00.
    const wire = [_]u8{ 0x91, 0x05, 'S', 'C', 'A', 'D', 'A', 0x28, 0x00 };
    var it = Iterator.init(&wire);
    const first = (try it.next()).?;
    try testing.expectEqualStrings("SCADA", first.ansi_symbol);
    // 0x00 is a port segment whose link octet is missing.
    try testing.expectError(error.SegmentOverruns, it.next());
}

test "reserved logical types and formats are refused" {
    var it = Iterator.init(&[_]u8{ 0x3C, 0x01 }); // type 7 (reserved)
    try testing.expectError(error.ReservedFormat, it.next());
    var it2 = Iterator.init(&[_]u8{ 0x23, 0x01 }); // format 3 (reserved)
    try testing.expectError(error.ReservedFormat, it2.next());
}

test "unsupported segment types are refused, not skipped" {
    var it = Iterator.init(&[_]u8{ 0xC1, 0x00 }); // elementary data type segment
    try testing.expectError(error.UnsupportedSegment, it.next());
    var it2 = Iterator.init(&[_]u8{ 0x82, 0x00 }); // an unmodelled data segment
    try testing.expectError(error.UnsupportedSegment, it2.next());
}

test "electronic key decodes and re-encodes" {
    const key = ElectronicKey{
        .vendor_id = 1,
        .device_type = 14,
        .product_code = 54,
        .major_revision = 0x80 | 20,
        .minor_revision = 11,
    };
    var buf: [16]u8 = undefined;
    var b = Builder.init(&buf);
    try b.electronicKey(key);
    const back = try decodeElectronicKey(b.bytes());
    try testing.expectEqual(key.vendor_id, back.vendor_id);
    try testing.expect(back.compatibilityMode());
    try testing.expectEqual(@as(u8, 11), back.minor_revision);
    try testing.expectError(error.Truncated, decodeElectronicKey(b.bytes()[0..5]));
}

test "network segments decode in both their shapes" {
    var it = Iterator.init(&[_]u8{ 0x43, 0x0A }); // production inhibit time = 10ms
    const seg = (try it.next()).?;
    try testing.expectEqual(@as(u5, 3), seg.network.subtype);
    try testing.expectEqualSlices(u8, &[_]u8{0x0A}, seg.network.data);
    var it2 = Iterator.init(&[_]u8{ 0x50, 0x02, 1, 2, 3, 4 }); // 32-bit inhibit time
    const seg2 = (try it2.next()).?;
    try testing.expectEqual(@as(usize, 4), seg2.network.data.len);
    var round: [16]u8 = undefined;
    try testing.expectEqualSlices(u8, &[_]u8{ 0x50, 0x02, 1, 2, 3, 4 }, try reencode(&[_]u8{ 0x50, 0x02, 1, 2, 3, 4 }, &round));
}

test "a full Logix tag path with a program scope round trips" {
    var buf: [64]u8 = undefined;
    var b = Builder.init(&buf);
    try b.symbol("Program:MainProgram");
    try b.symbol("MyUDT");
    try b.symbol("Member");
    try b.member(3);
    try testing.expectEqual(@as(u8, 20), try b.words());
    var round: [64]u8 = undefined;
    try testing.expectEqualSlices(u8, b.bytes(), try reencode(b.bytes(), &round));
    try testing.expectEqual(@as(usize, 4), try countSegments(b.bytes()));
    try testing.expectEqualStrings("Program:MainProgram", (try findSymbol(b.bytes())).?);
}

test "path size is words and an odd path is refused" {
    var buf: [64]u8 = undefined;
    var b = Builder.initPacked(&buf);
    try b.class(6);
    try b.logical(.{ .what = .instance, .value = 0x1234, .format = .bits_16 });
    try testing.expectError(error.OddPathLength, b.words());
}

test "fuzz: epath iteration never panics and re-encodes exactly" {
    try std.testing.fuzz({}, fuzzPath, .{});
}

fn fuzzPath(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    var round: [512]u8 = undefined;
    if (reencode(buf[0..len], &round)) |again| {
        try testing.expectEqualSlices(u8, buf[0..len], again);
    } else |_| {}
    // The accessors must be equally unflappable.
    _ = findLogical(buf[0..len], .class) catch {};
    _ = findSymbol(buf[0..len]) catch {};
    _ = countSegments(buf[0..len]) catch {};
    var it = Iterator.initPacked(buf[0..len]);
    var guard: usize = 0;
    while (true) {
        guard += 1;
        try testing.expect(guard < 1024);
        const seg = it.next() catch break;
        if (seg == null) break;
    }
}
