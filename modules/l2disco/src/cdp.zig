// SPDX-License-Identifier: MIT

//! CDP (Cisco Discovery Protocol) frame codec.
//!
//! Covers the CDP payload as carried over 802.2 LLC/SNAP (the LLC/SNAP
//! encapsulation itself is the capture layer's business, not this codec's):
//! a 4-byte header — version, holdtime ("TTL"), checksum — followed by a
//! list of TLVs with 2-byte type + 2-byte length (length includes the
//! 4-byte TLV header).
//!
//! - `Frame.parse` — typed model for the common TLVs: Device ID,
//!   Addresses, Port ID, Capabilities, Software Version, Platform, VTP
//!   Management Domain, Native VLAN, Duplex. Unknown TLVs pass through
//!   via `tlvIterator`. All slices point into the caller's buffer.
//! - `AddressIterator` — walks the Addresses TLV block (count-prefixed
//!   list of protocol + address pairs) and decodes IPv4 (NLPID 0xCC) and
//!   IPv6 (802.2 SNAP with EtherType 0x86DD) into `netaddr.Ip`.
//! - `Builder` — emits a frame into a caller buffer and computes the
//!   checksum in `finish`.
//!
//! The checksum is the standard RFC 1071 ones'-complement sum over the
//! whole payload. Note: for *odd-length* frames, real Cisco IOS is known
//! to deviate from RFC 1071 padding; frames built here use the standard
//! form, and `ParseOptions.verify_checksum = false` lets a caller accept
//! odd-length frames from devices regardless.
//!
//! Provenance: clean-room from the publicly documented CDP frame format
//! (Cisco documentation; CDP is a Cisco-proprietary but publicly described
//! protocol). Behavior reference only — no third-party dissector source
//! consulted or copied.

const std = @import("std");
const netaddr = @import("netaddr");

pub const ParseError = error{
    /// Shorter than the 4-byte CDP header.
    Truncated,
    /// A TLV header or its declared length overruns the buffer.
    TruncatedTlv,
    /// A TLV declares a length smaller than its own 4-byte header.
    BadTlvLength,
    /// The ones'-complement checksum over the payload does not verify.
    BadChecksum,
    /// A known fixed-layout TLV carries an impossible length.
    BadTlvValue,
    /// An entry inside the Addresses TLV block overruns the block.
    TruncatedAddress,
};

pub const BuildError = error{
    BufferTooSmall,
    /// TLV value longer than 65531 (0xffff - 4) bytes.
    ValueTooLong,
};

pub const header_len = 4;

/// CDP TLV types (the publicly documented set this codec types out).
pub const TlvType = enum(u16) {
    device_id = 0x0001,
    addresses = 0x0002,
    port_id = 0x0003,
    capabilities = 0x0004,
    software_version = 0x0005,
    platform = 0x0006,
    vtp_domain = 0x0009,
    native_vlan = 0x000a,
    duplex = 0x000b,
    _,
};

/// Capability bits (32-bit big-endian flag word), LSB first.
pub const Capabilities = packed struct(u32) {
    router: bool = false,
    tb_bridge: bool = false,
    sr_bridge: bool = false,
    l2_switch: bool = false,
    host: bool = false,
    igmp_capable: bool = false,
    repeater: bool = false,
    _reserved: u25 = 0,

    pub fn fromWire(word: u32) Capabilities {
        return @bitCast(word);
    }

    pub fn toWire(c: Capabilities) u32 {
        return @bitCast(c);
    }
};

pub const Duplex = enum(u8) {
    half = 0,
    full = 1,
    _,
};

/// One raw TLV: wire type + value bytes (without the 4-byte TLV header).
pub const RawTlv = struct {
    type: u16,
    value: []const u8,
};

/// Bounds-checked walk over the TLV region (after the 4-byte header).
pub const TlvIterator = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(tlv_region: []const u8) TlvIterator {
        return .{ .buf = tlv_region };
    }

    pub fn next(it: *TlvIterator) ParseError!?RawTlv {
        if (it.pos == it.buf.len) return null;
        if (it.pos + 4 > it.buf.len) return ParseError.TruncatedTlv;
        const t = std.mem.readInt(u16, it.buf[it.pos..][0..2], .big);
        const total: usize = std.mem.readInt(u16, it.buf[it.pos + 2 ..][0..2], .big);
        if (total < 4) return ParseError.BadTlvLength;
        if (it.pos + total > it.buf.len) return ParseError.TruncatedTlv;
        const value = it.buf[it.pos + 4 ..][0 .. total - 4];
        it.pos += total;
        return .{ .type = t, .value = value };
    }
};

/// One entry of the Addresses TLV block.
pub const Address = struct {
    /// 1 = NLPID, 2 = 802.2 SNAP.
    protocol_type: u8,
    /// Protocol discriminator bytes (e.g. `0xCC` NLPID for IPv4).
    protocol: []const u8,
    /// The address bytes themselves.
    address: []const u8,

    /// Decodes IPv4 (NLPID 0xCC) and IPv6 (802.2 with EtherType 0x86DD);
    /// anything else is null (still available raw).
    pub fn ip(a: *const Address) ?netaddr.Ip {
        if (a.protocol_type == 1 and a.protocol.len == 1 and a.protocol[0] == 0xcc and
            a.address.len == 4)
            return .{ .v4 = a.address[0..4].* };
        if (a.protocol_type == 2 and a.protocol.len >= 2 and a.address.len == 16 and
            std.mem.readInt(u16, a.protocol[a.protocol.len - 2 ..][0..2], .big) == 0x86dd)
            return .{ .v6 = a.address[0..16].* };
        return null;
    }
};

/// Walks the value block of an Addresses TLV: a 4-byte entry count, then
/// per entry protocol type/length/bytes + 2-byte address length + bytes.
pub const AddressIterator = struct {
    buf: []const u8,
    pos: usize,
    remaining: u32,

    pub fn init(addresses_tlv_value: []const u8) ParseError!AddressIterator {
        if (addresses_tlv_value.len < 4) return ParseError.TruncatedAddress;
        return .{
            .buf = addresses_tlv_value,
            .pos = 4,
            .remaining = std.mem.readInt(u32, addresses_tlv_value[0..4], .big),
        };
    }

    pub fn next(it: *AddressIterator) ParseError!?Address {
        if (it.remaining == 0) return null;
        if (it.pos + 2 > it.buf.len) return ParseError.TruncatedAddress;
        const ptype = it.buf[it.pos];
        const plen: usize = it.buf[it.pos + 1];
        it.pos += 2;
        if (it.pos + plen + 2 > it.buf.len) return ParseError.TruncatedAddress;
        const protocol = it.buf[it.pos..][0..plen];
        it.pos += plen;
        const alen: usize = std.mem.readInt(u16, it.buf[it.pos..][0..2], .big);
        it.pos += 2;
        if (it.pos + alen > it.buf.len) return ParseError.TruncatedAddress;
        const address = it.buf[it.pos..][0..alen];
        it.pos += alen;
        it.remaining -= 1;
        return .{ .protocol_type = ptype, .protocol = protocol, .address = address };
    }
};

pub const ParseOptions = struct {
    /// Verify the RFC 1071 checksum (see the module note on odd-length
    /// frames from real devices).
    verify_checksum: bool = true,
};

/// A parsed CDP frame. All slices point into the parsed buffer.
pub const Frame = struct {
    version: u8,
    /// Holdtime in seconds.
    ttl_s: u8,
    checksum: u16,
    /// The whole TLV region, for `tlvIterator`.
    tlvs_raw: []const u8,

    device_id: ?[]const u8 = null,
    port_id: ?[]const u8 = null,
    software_version: ?[]const u8 = null,
    platform: ?[]const u8 = null,
    vtp_domain: ?[]const u8 = null,
    capabilities: ?Capabilities = null,
    native_vlan: ?u16 = null,
    duplex: ?Duplex = null,
    /// Raw value block of the Addresses TLV (walk with `addressIterator`).
    addresses_raw: ?[]const u8 = null,

    pub fn parse(bytes: []const u8, opts: ParseOptions) ParseError!Frame {
        if (bytes.len < header_len) return ParseError.Truncated;
        if (opts.verify_checksum and !verify(bytes)) return ParseError.BadChecksum;

        var f: Frame = .{
            .version = bytes[0],
            .ttl_s = bytes[1],
            .checksum = std.mem.readInt(u16, bytes[2..4], .big),
            .tlvs_raw = bytes[header_len..],
        };

        var it = TlvIterator.init(f.tlvs_raw);
        while (try it.next()) |tlv| {
            switch (@as(TlvType, @enumFromInt(tlv.type))) {
                .device_id => f.device_id = tlv.value,
                .port_id => f.port_id = tlv.value,
                .software_version => f.software_version = tlv.value,
                .platform => f.platform = tlv.value,
                .vtp_domain => f.vtp_domain = tlv.value,
                .capabilities => {
                    if (tlv.value.len != 4) return ParseError.BadTlvValue;
                    f.capabilities = .fromWire(std.mem.readInt(u32, tlv.value[0..4], .big));
                },
                .native_vlan => {
                    if (tlv.value.len != 2) return ParseError.BadTlvValue;
                    f.native_vlan = std.mem.readInt(u16, tlv.value[0..2], .big);
                },
                .duplex => {
                    if (tlv.value.len != 1) return ParseError.BadTlvValue;
                    f.duplex = @enumFromInt(tlv.value[0]);
                },
                .addresses => f.addresses_raw = tlv.value,
                _ => {}, // unknown: reachable via tlvIterator()
            }
        }
        return f;
    }

    /// Re-iterate every TLV (unknown types included).
    pub fn tlvIterator(f: *const Frame) TlvIterator {
        return TlvIterator.init(f.tlvs_raw);
    }

    /// Iterator over the Addresses TLV, or null when the frame has none.
    pub fn addressIterator(f: *const Frame) ParseError!?AddressIterator {
        const raw = f.addresses_raw orelse return null;
        return try AddressIterator.init(raw);
    }
};

/// RFC 1071 ones'-complement checksum over `bytes` (odd length padded
/// with a zero byte). The checksum field must be zeroed by the caller.
pub fn compute(bytes: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 2 <= bytes.len) : (i += 2) {
        sum += std.mem.readInt(u16, bytes[i..][0..2], .big);
    }
    if (i < bytes.len) sum += @as(u32, bytes[i]) << 8;
    while (sum > 0xffff) sum = (sum & 0xffff) + (sum >> 16);
    return @intCast(~sum & 0xffff);
}

/// True when the ones'-complement sum over the whole frame (checksum
/// field included) folds to 0xffff.
pub fn verify(frame_bytes: []const u8) bool {
    if (frame_bytes.len < header_len) return false;
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 2 <= frame_bytes.len) : (i += 2) {
        sum += std.mem.readInt(u16, frame_bytes[i..][0..2], .big);
    }
    if (i < frame_bytes.len) sum += @as(u32, frame_bytes[i]) << 8;
    while (sum > 0xffff) sum = (sum & 0xffff) + (sum >> 16);
    return sum == 0xffff;
}

/// Builds a CDP frame into a caller buffer; `finish` fills the checksum.
pub const Builder = struct {
    buf: []u8,
    pos: usize,

    pub const InitOptions = struct {
        version: u8 = 2,
        /// Holdtime in seconds.
        ttl_s: u8 = 180,
    };

    pub fn init(buf: []u8, opts: InitOptions) BuildError!Builder {
        if (buf.len < header_len) return BuildError.BufferTooSmall;
        buf[0] = opts.version;
        buf[1] = opts.ttl_s;
        buf[2] = 0; // checksum patched in finish()
        buf[3] = 0;
        return .{ .buf = buf, .pos = header_len };
    }

    /// Appends a raw TLV (any type).
    pub fn addTlv(b: *Builder, tlv_type: u16, value: []const u8) BuildError!void {
        if (value.len > 0xffff - 4) return BuildError.ValueTooLong;
        if (b.pos + 4 + value.len > b.buf.len) return BuildError.BufferTooSmall;
        std.mem.writeInt(u16, b.buf[b.pos..][0..2], tlv_type, .big);
        std.mem.writeInt(u16, b.buf[b.pos + 2 ..][0..2], @intCast(4 + value.len), .big);
        @memcpy(b.buf[b.pos + 4 ..][0..value.len], value);
        b.pos += 4 + value.len;
    }

    pub fn addDeviceId(b: *Builder, id: []const u8) BuildError!void {
        try b.addTlv(@intFromEnum(TlvType.device_id), id);
    }

    pub fn addPortId(b: *Builder, id: []const u8) BuildError!void {
        try b.addTlv(@intFromEnum(TlvType.port_id), id);
    }

    pub fn addSoftwareVersion(b: *Builder, v: []const u8) BuildError!void {
        try b.addTlv(@intFromEnum(TlvType.software_version), v);
    }

    pub fn addPlatform(b: *Builder, p: []const u8) BuildError!void {
        try b.addTlv(@intFromEnum(TlvType.platform), p);
    }

    pub fn addVtpDomain(b: *Builder, d: []const u8) BuildError!void {
        try b.addTlv(@intFromEnum(TlvType.vtp_domain), d);
    }

    pub fn addCapabilities(b: *Builder, caps: Capabilities) BuildError!void {
        var word: [4]u8 = undefined;
        std.mem.writeInt(u32, &word, caps.toWire(), .big);
        try b.addTlv(@intFromEnum(TlvType.capabilities), &word);
    }

    pub fn addNativeVlan(b: *Builder, vlan: u16) BuildError!void {
        var be: [2]u8 = undefined;
        std.mem.writeInt(u16, &be, vlan, .big);
        try b.addTlv(@intFromEnum(TlvType.native_vlan), &be);
    }

    pub fn addDuplex(b: *Builder, d: Duplex) BuildError!void {
        try b.addTlv(@intFromEnum(TlvType.duplex), &.{@intFromEnum(d)});
    }

    /// An Addresses TLV holding IPv4 addresses (NLPID 0xCC entries).
    pub fn addAddressesIpv4(b: *Builder, addrs: []const [4]u8) BuildError!void {
        const entry_len = 2 + 1 + 2 + 4; // ptype, plen, 0xCC, alen, addr
        const total = 4 + addrs.len * entry_len;
        if (total > 0xffff - 4) return BuildError.ValueTooLong;
        if (b.pos + 4 + total > b.buf.len) return BuildError.BufferTooSmall;
        std.mem.writeInt(u16, b.buf[b.pos..][0..2], @intFromEnum(TlvType.addresses), .big);
        std.mem.writeInt(u16, b.buf[b.pos + 2 ..][0..2], @intCast(4 + total), .big);
        var pos = b.pos + 4;
        std.mem.writeInt(u32, b.buf[pos..][0..4], @intCast(addrs.len), .big);
        pos += 4;
        for (addrs) |a| {
            b.buf[pos] = 1; // NLPID
            b.buf[pos + 1] = 1; // protocol length
            b.buf[pos + 2] = 0xcc; // IPv4
            std.mem.writeInt(u16, b.buf[pos + 3 ..][0..2], 4, .big);
            b.buf[pos + 5 ..][0..4].* = a;
            pos += entry_len;
        }
        b.pos = pos;
    }

    /// Computes + patches the checksum; returns the finished frame bytes.
    pub fn finish(b: *Builder) []const u8 {
        const frame = b.buf[0..b.pos];
        frame[2] = 0;
        frame[3] = 0;
        std.mem.writeInt(u16, frame[2..4], compute(frame), .big);
        return frame;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

// Golden CDPv2 frame, transcribed TLV-by-TLV from the documented format;
// checksum 0x103f is the RFC 1071 sum over the payload.
const kat_frame = [_]u8{ 0x02, 0xb4, 0x10, 0x3f } // version 2, holdtime 180, checksum
    ++ [_]u8{ 0x00, 0x01, 0x00, 0x0b } ++ "lab-sw1".* // Device ID
    ++ [_]u8{ 0x00, 0x05, 0x00, 0x12 } ++ "Cisco IOS 15.0".* // Software Version
    ++ [_]u8{ 0x00, 0x06, 0x00, 0x12 } ++ "cisco WS-C2960".* // Platform
    ++ [_]u8{ 0x00, 0x03, 0x00, 0x16 } ++ "GigabitEthernet0/1".* // Port ID
    ++ [_]u8{ 0x00, 0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 0x28 } // Capabilities: switch+IGMP
    ++ [_]u8{ 0x00, 0x02, 0x00, 0x11 } // Addresses TLV, 1 entry
    ++ [_]u8{ 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0xcc, 0x00, 0x04, 0xc0, 0xa8, 0x0a, 0x02 } ++ [_]u8{ 0x00, 0x0a, 0x00, 0x06, 0x00, 0x0a } // Native VLAN 10
    ++ [_]u8{ 0x00, 0x0b, 0x00, 0x05, 0x01 } // Duplex: full
    ++ [_]u8{ 0x00, 0x09, 0x00, 0x07 } ++ "LAB".*; // VTP domain

test "CDP KAT: checksum verifies and parse yields the typed model" {
    try testing.expect(verify(&kat_frame));

    const f = try Frame.parse(&kat_frame, .{});
    try testing.expectEqual(@as(u8, 2), f.version);
    try testing.expectEqual(@as(u8, 180), f.ttl_s);
    try testing.expectEqual(@as(u16, 0x103f), f.checksum);
    try testing.expectEqualStrings("lab-sw1", f.device_id.?);
    try testing.expectEqualStrings("GigabitEthernet0/1", f.port_id.?);
    try testing.expectEqualStrings("Cisco IOS 15.0", f.software_version.?);
    try testing.expectEqualStrings("cisco WS-C2960", f.platform.?);
    try testing.expectEqualStrings("LAB", f.vtp_domain.?);
    try testing.expectEqual(@as(u16, 10), f.native_vlan.?);
    try testing.expectEqual(Duplex.full, f.duplex.?);

    const caps = f.capabilities.?;
    try testing.expect(caps.l2_switch);
    try testing.expect(caps.igmp_capable);
    try testing.expect(!caps.router);
    try testing.expectEqual(@as(u32, 0x28), caps.toWire());

    // Addresses: one IPv4.
    var it = (try f.addressIterator()).?;
    const a = (try it.next()).?;
    var buf: [netaddr.max_ip_text_len]u8 = undefined;
    try testing.expectEqualStrings("192.168.10.2", netaddr.formatIp(a.ip().?, &buf));
    try testing.expectEqual(@as(?Address, null), try it.next());
}

test "CDP round-trip: builder reproduces the golden bytes" {
    var buf: [256]u8 = undefined;
    var b = try Builder.init(&buf, .{ .version = 2, .ttl_s = 180 });
    try b.addDeviceId("lab-sw1");
    try b.addSoftwareVersion("Cisco IOS 15.0");
    try b.addPlatform("cisco WS-C2960");
    try b.addPortId("GigabitEthernet0/1");
    try b.addCapabilities(.{ .l2_switch = true, .igmp_capable = true });
    try b.addAddressesIpv4(&.{.{ 192, 168, 10, 2 }});
    try b.addNativeVlan(10);
    try b.addDuplex(.full);
    try b.addVtpDomain("LAB");
    const bytes = b.finish();
    try testing.expectEqualSlices(u8, &kat_frame, bytes);

    // build → parse agrees.
    const f = try Frame.parse(bytes, .{});
    try testing.expectEqualStrings("lab-sw1", f.device_id.?);
}

test "CDP: unknown TLV passes through; odd-length frame checksums" {
    var buf: [128]u8 = undefined;
    var b = try Builder.init(&buf, .{});
    try b.addDeviceId("r1");
    try b.addTlv(0x1234, &.{ 0xaa, 0xbb, 0xcc }); // unknown, odd value
    const bytes = b.finish();
    try testing.expect(verify(bytes)); // odd total length: standard padding

    const f = try Frame.parse(bytes, .{});
    try testing.expectEqualStrings("r1", f.device_id.?);
    var it = f.tlvIterator();
    var saw = false;
    while (try it.next()) |tlv| {
        if (tlv.type == 0x1234) {
            try testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb, 0xcc }, tlv.value);
            saw = true;
        }
    }
    try testing.expect(saw);
}

test "CDP malformed: typed errors, no panic" {
    try testing.expectError(ParseError.Truncated, Frame.parse(&.{}, .{}));
    try testing.expectError(ParseError.Truncated, Frame.parse(&.{ 2, 180 }, .{}));

    // Flipped checksum bit.
    var bad = kat_frame;
    bad[3] ^= 1;
    try testing.expectError(ParseError.BadChecksum, Frame.parse(&bad, .{}));
    // ... which parses fine with verification off.
    _ = try Frame.parse(&bad, .{ .verify_checksum = false });

    // TLV length overrun.
    var overrun = kat_frame;
    overrun[7] = 0xff; // Device ID TLV claims a huge length
    try testing.expectError(ParseError.TruncatedTlv, Frame.parse(&overrun, .{ .verify_checksum = false }));

    // TLV length below its own header size.
    var short = kat_frame;
    short[7] = 3;
    try testing.expectError(ParseError.BadTlvLength, Frame.parse(&short, .{ .verify_checksum = false }));

    // Truncated frame mid-TLV.
    try testing.expectError(
        ParseError.TruncatedTlv,
        Frame.parse(kat_frame[0..10], .{ .verify_checksum = false }),
    );

    // Addresses block whose entry overruns the TLV value.
    const badaddr = [_]u8{ 0x02, 0xb4, 0x00, 0x00 } ++
        [_]u8{ 0x00, 0x02, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x02, 0x01, 0x01 };
    const f = try Frame.parse(&badaddr, .{ .verify_checksum = false });
    var it = (try f.addressIterator()).?;
    try testing.expectError(ParseError.TruncatedAddress, it.next());
}

test "CDP garbage sweep: no panics on random input" {
    var prng = std.Random.DefaultPrng.init(0x43445021); // "CDP!"
    const random = prng.random();
    var buf: [256]u8 = undefined;
    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        const len = random.uintAtMost(usize, buf.len);
        random.bytes(buf[0..len]);
        // Checksum verification off so the TLV walker is exercised.
        if (Frame.parse(buf[0..len], .{ .verify_checksum = false })) |f| {
            if (f.addressIterator() catch null) |it_opt| {
                var it = it_opt;
                while (it.next() catch null) |_| {}
            }
        } else |_| {}
        _ = Frame.parse(buf[0..len], .{}) catch {};
    }
}
