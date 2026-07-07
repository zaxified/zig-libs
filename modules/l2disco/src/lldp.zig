// SPDX-License-Identifier: MIT

//! LLDP (IEEE 802.1AB) LLDPDU codec.
//!
//! The LLDPDU is a stream of TLVs, each opening with a 16-bit header split
//! 7 bits of type + 9 bits of length; the value follows. The stream ends
//! at an End-of-LLDPDU TLV (type 0, length 0).
//!
//! - `TlvIterator` — bounds-checked raw walk yielding `{type, value}`
//!   until the End TLV; never allocates, never panics.
//! - `Lldpdu.parse` — a typed model. The three mandatory TLVs (Chassis ID,
//!   Port ID, Time To Live) are required first, in order; the optional
//!   TLVs (Port Description, System Name, System Description, System
//!   Capabilities, Management Address) are extracted as they appear.
//!   Organizationally-specific TLVs (type 127) and any unrecognized
//!   optional TLVs are reachable through `tlvIterator` / `orgIterator`.
//! - Chassis ID / Port ID expose their subtype and helpers (`mac`, `ip`,
//!   `text`); System Capabilities is a typed bit set; Management Address
//!   and Organizationally-specific TLVs decode into typed sub-models
//!   (IEEE 802.1 port VLAN / VLAN name, IEEE 802.3 MAC/PHY / max frame
//!   size), always keeping the raw bytes.
//! - `Builder` — appends TLVs into a caller buffer; `finish` writes the
//!   End-of-LLDPDU TLV and returns a valid LLDPDU.
//!
//! Provenance: clean-room from IEEE 802.1AB (LLDP) and the IEEE 802.1 /
//! 802.3 organizationally-specific TLV definitions. No third-party
//! dissector source (Wireshark, lldpd, net-snmp, tcpdump) consulted.

const std = @import("std");
const netaddr = @import("netaddr");
const Mac = @import("mac.zig").Mac;

pub const ParseError = error{
    /// A TLV header (2 bytes) does not fit in the remaining buffer.
    Truncated,
    /// A TLV's declared length overruns the buffer.
    TruncatedTlv,
    /// The three mandatory TLVs are absent or out of order.
    MissingMandatory,
    /// A fixed-layout TLV (TTL, capabilities, …) has an impossible length.
    BadTlvLength,
    /// A Management Address TLV's internal lengths are inconsistent.
    BadManagementAddress,
};

pub const BuildError = error{
    BufferTooSmall,
    /// TLV value longer than the 9-bit length field allows (511 bytes).
    ValueTooLong,
};

/// Maximum value length representable in the 9-bit length field.
pub const max_tlv_len = 511;

pub const TlvType = enum(u7) {
    end = 0,
    chassis_id = 1,
    port_id = 2,
    ttl = 3,
    port_description = 4,
    system_name = 5,
    system_description = 6,
    system_capabilities = 7,
    management_address = 8,
    org_specific = 127,
    _,
};

pub const ChassisIdSubtype = enum(u8) {
    chassis_component = 1,
    interface_alias = 2,
    port_component = 3,
    mac_address = 4,
    network_address = 5,
    interface_name = 6,
    local = 7,
    _,
};

pub const PortIdSubtype = enum(u8) {
    interface_alias = 1,
    port_component = 2,
    mac_address = 3,
    network_address = 4,
    interface_name = 5,
    agent_circuit_id = 6,
    local = 7,
    _,
};

/// IANA address-family numbers used by the network-address subtype and the
/// Management Address TLV.
pub const addr_family_ipv4: u8 = 1;
pub const addr_family_ipv6: u8 = 2;

/// Decodes an IANA-family-prefixed network address (`family || addr`).
fn networkAddressIp(bytes: []const u8) ?netaddr.Ip {
    if (bytes.len < 1) return null;
    return switch (bytes[0]) {
        addr_family_ipv4 => if (bytes.len == 5) netaddr.Ip{ .v4 = bytes[1..5].* } else null,
        addr_family_ipv6 => if (bytes.len == 17) netaddr.Ip{ .v6 = bytes[1..17].* } else null,
        else => null,
    };
}

pub const ChassisId = struct {
    subtype: ChassisIdSubtype,
    value: []const u8,

    /// The value as a MAC when the subtype is `mac_address`.
    pub fn mac(c: ChassisId) ?Mac {
        if (c.subtype != .mac_address or c.value.len != 6) return null;
        return .{ .octets = c.value[0..6].* };
    }

    /// The value as an IP when the subtype is `network_address`.
    pub fn ip(c: ChassisId) ?netaddr.Ip {
        if (c.subtype != .network_address) return null;
        return networkAddressIp(c.value);
    }

    /// The value as text for the string-bearing subtypes (alias / name /
    /// local); null otherwise.
    pub fn text(c: ChassisId) ?[]const u8 {
        return switch (c.subtype) {
            .interface_alias, .interface_name, .local, .chassis_component => c.value,
            else => null,
        };
    }
};

pub const PortId = struct {
    subtype: PortIdSubtype,
    value: []const u8,

    pub fn mac(p: PortId) ?Mac {
        if (p.subtype != .mac_address or p.value.len != 6) return null;
        return .{ .octets = p.value[0..6].* };
    }

    pub fn ip(p: PortId) ?netaddr.Ip {
        if (p.subtype != .network_address) return null;
        return networkAddressIp(p.value);
    }

    pub fn text(p: PortId) ?[]const u8 {
        return switch (p.subtype) {
            .interface_alias, .interface_name, .local, .agent_circuit_id => p.value,
            else => null,
        };
    }
};

/// The System Capabilities bit map (IEEE 802.1AB), read big-endian.
pub const SystemCapabilities = packed struct(u16) {
    other: bool = false,
    repeater: bool = false,
    bridge: bool = false,
    wlan_ap: bool = false,
    router: bool = false,
    telephone: bool = false,
    docsis: bool = false,
    station_only: bool = false,
    c_vlan: bool = false,
    s_vlan: bool = false,
    tpmr: bool = false,
    _reserved: u5 = 0,

    pub fn fromWire(word: u16) SystemCapabilities {
        return @bitCast(word);
    }

    pub fn toWire(c: SystemCapabilities) u16 {
        return @bitCast(c);
    }
};

pub const SystemCapabilitiesTlv = struct {
    capabilities: SystemCapabilities,
    enabled: SystemCapabilities,
};

/// Interface-numbering subtype of a Management Address TLV.
pub const InterfaceNumberingSubtype = enum(u8) {
    unknown = 1,
    if_index = 2,
    system_port = 3,
    _,
};

pub const ManagementAddress = struct {
    /// IANA address family of `address` (1 = IPv4, 2 = IPv6, …).
    address_subtype: u8,
    address: []const u8,
    interface_subtype: InterfaceNumberingSubtype,
    interface_number: u32,
    /// The object identifier for the interface (may be empty).
    oid: []const u8,

    pub fn ip(m: ManagementAddress) ?netaddr.Ip {
        return switch (m.address_subtype) {
            addr_family_ipv4 => if (m.address.len == 4) netaddr.Ip{ .v4 = m.address[0..4].* } else null,
            addr_family_ipv6 => if (m.address.len == 16) netaddr.Ip{ .v6 = m.address[0..16].* } else null,
            else => null,
        };
    }

    pub fn parse(value: []const u8) ParseError!ManagementAddress {
        // addr-string-len covers the address subtype byte + the address.
        if (value.len < 1) return ParseError.BadManagementAddress;
        const addr_str_len: usize = value[0];
        if (addr_str_len < 1) return ParseError.BadManagementAddress;
        if (1 + addr_str_len > value.len) return ParseError.BadManagementAddress;
        const address_subtype = value[1];
        const address = value[2 .. 1 + addr_str_len];
        var pos: usize = 1 + addr_str_len;
        // interface subtype (1) + interface number (4) + oid length (1).
        if (pos + 6 > value.len) return ParseError.BadManagementAddress;
        const iface_subtype: InterfaceNumberingSubtype = @enumFromInt(value[pos]);
        const iface_num = std.mem.readInt(u32, value[pos + 1 ..][0..4], .big);
        const oid_len: usize = value[pos + 5];
        pos += 6;
        if (pos + oid_len > value.len) return ParseError.BadManagementAddress;
        return .{
            .address_subtype = address_subtype,
            .address = address,
            .interface_subtype = iface_subtype,
            .interface_number = iface_num,
            .oid = value[pos..][0..oid_len],
        };
    }
};

// ── organizationally-specific (type 127) ────────────────────────────────────

pub const oui_ieee_8021 = [3]u8{ 0x00, 0x80, 0xc2 };
pub const oui_ieee_8023 = [3]u8{ 0x00, 0x12, 0x0f };

/// A raw organizationally-specific TLV: OUI + subtype + the vendor value.
pub const OrgSpecific = struct {
    oui: [3]u8,
    subtype: u8,
    info: []const u8,

    pub fn parse(value: []const u8) ParseError!OrgSpecific {
        if (value.len < 4) return ParseError.BadTlvLength;
        return .{
            .oui = value[0..3].*,
            .subtype = value[3],
            .info = value[4..],
        };
    }

    /// Typed view when the OUI+subtype is one this codec recognizes.
    pub fn decode(o: OrgSpecific) ?OrgValue {
        if (std.mem.eql(u8, &o.oui, &oui_ieee_8021)) {
            switch (o.subtype) {
                1 => { // Port VLAN ID
                    if (o.info.len < 2) return null;
                    return .{ .port_vlan_id = std.mem.readInt(u16, o.info[0..2], .big) };
                },
                3 => { // VLAN Name: vlan id (2) + name len (1) + name
                    if (o.info.len < 3) return null;
                    const name_len: usize = o.info[2];
                    if (3 + name_len > o.info.len) return null;
                    return .{ .vlan_name = .{
                        .vlan_id = std.mem.readInt(u16, o.info[0..2], .big),
                        .name = o.info[3 .. 3 + name_len],
                    } };
                },
                else => return null,
            }
        } else if (std.mem.eql(u8, &o.oui, &oui_ieee_8023)) {
            switch (o.subtype) {
                1 => { // MAC/PHY Config/Status
                    if (o.info.len < 5) return null;
                    return .{ .mac_phy = .{
                        .autoneg = o.info[0],
                        .pmd_advertised = std.mem.readInt(u16, o.info[1..3], .big),
                        .operational_mau = std.mem.readInt(u16, o.info[3..5], .big),
                    } };
                },
                4 => { // Maximum Frame Size
                    if (o.info.len < 2) return null;
                    return .{ .max_frame_size = std.mem.readInt(u16, o.info[0..2], .big) };
                },
                else => return null,
            }
        }
        return null;
    }
};

pub const VlanName = struct { vlan_id: u16, name: []const u8 };

pub const MacPhy = struct {
    /// Auto-negotiation support/status bits.
    autoneg: u8,
    /// PMD auto-negotiation advertised capability.
    pmd_advertised: u16,
    /// Operational MAU type.
    operational_mau: u16,
};

pub const OrgValue = union(enum) {
    port_vlan_id: u16, // IEEE 802.1 subtype 1
    vlan_name: VlanName, // IEEE 802.1 subtype 3
    mac_phy: MacPhy, // IEEE 802.3 subtype 1
    max_frame_size: u16, // IEEE 802.3 subtype 4
};

// ── raw TLV iterator ────────────────────────────────────────────────────────

pub const RawTlv = struct {
    type: TlvType,
    value: []const u8,
};

/// Walks the LLDPDU TLV stream. Stops at (and consumes) the End TLV.
pub const TlvIterator = struct {
    buf: []const u8,
    pos: usize = 0,
    done: bool = false,

    pub fn init(bytes: []const u8) TlvIterator {
        return .{ .buf = bytes };
    }

    pub fn next(it: *TlvIterator) ParseError!?RawTlv {
        if (it.done or it.pos == it.buf.len) return null;
        if (it.pos + 2 > it.buf.len) return ParseError.Truncated;
        const header = std.mem.readInt(u16, it.buf[it.pos..][0..2], .big);
        const t: TlvType = @enumFromInt(@as(u7, @intCast(header >> 9)));
        const len: usize = header & 0x1ff;
        if (it.pos + 2 + len > it.buf.len) return ParseError.TruncatedTlv;
        const value = it.buf[it.pos + 2 ..][0..len];
        it.pos += 2 + len;
        if (t == .end) {
            it.done = true;
            return .{ .type = .end, .value = value };
        }
        return .{ .type = t, .value = value };
    }
};

/// Iterator over just the organizationally-specific (type 127) TLVs.
pub const OrgIterator = struct {
    inner: TlvIterator,

    pub fn next(it: *OrgIterator) ParseError!?OrgSpecific {
        while (try it.inner.next()) |tlv| {
            if (tlv.type == .org_specific) return try OrgSpecific.parse(tlv.value);
        }
        return null;
    }
};

/// Iterator over every Management Address TLV.
pub const ManagementAddressIterator = struct {
    inner: TlvIterator,

    pub fn next(it: *ManagementAddressIterator) ParseError!?ManagementAddress {
        while (try it.inner.next()) |tlv| {
            if (tlv.type == .management_address) return try ManagementAddress.parse(tlv.value);
        }
        return null;
    }
};

// ── typed model ─────────────────────────────────────────────────────────────

pub const Lldpdu = struct {
    // Mandatory.
    chassis_id: ChassisId,
    port_id: PortId,
    ttl_s: u16,

    // Optional (first occurrence).
    port_description: ?[]const u8 = null,
    system_name: ?[]const u8 = null,
    system_description: ?[]const u8 = null,
    capabilities: ?SystemCapabilitiesTlv = null,
    management_address: ?ManagementAddress = null,

    /// The whole TLV stream, for re-iteration (org-specific, extra
    /// management addresses, unknown TLVs).
    raw: []const u8,

    pub fn parse(bytes: []const u8) ParseError!Lldpdu {
        var it = TlvIterator.init(bytes);

        // The three mandatory TLVs, in order.
        const c = (try it.next()) orelse return ParseError.MissingMandatory;
        if (c.type != .chassis_id or c.value.len < 2) return ParseError.MissingMandatory;
        const p = (try it.next()) orelse return ParseError.MissingMandatory;
        if (p.type != .port_id or p.value.len < 2) return ParseError.MissingMandatory;
        const t = (try it.next()) orelse return ParseError.MissingMandatory;
        if (t.type != .ttl or t.value.len != 2) return ParseError.MissingMandatory;

        var du: Lldpdu = .{
            .chassis_id = .{ .subtype = @enumFromInt(c.value[0]), .value = c.value[1..] },
            .port_id = .{ .subtype = @enumFromInt(p.value[0]), .value = p.value[1..] },
            .ttl_s = std.mem.readInt(u16, t.value[0..2], .big),
            .raw = bytes,
        };

        while (try it.next()) |tlv| {
            switch (tlv.type) {
                .end => break,
                .port_description => if (du.port_description == null) {
                    du.port_description = tlv.value;
                },
                .system_name => if (du.system_name == null) {
                    du.system_name = tlv.value;
                },
                .system_description => if (du.system_description == null) {
                    du.system_description = tlv.value;
                },
                .system_capabilities => {
                    if (tlv.value.len != 4) return ParseError.BadTlvLength;
                    if (du.capabilities == null) du.capabilities = .{
                        .capabilities = .fromWire(std.mem.readInt(u16, tlv.value[0..2], .big)),
                        .enabled = .fromWire(std.mem.readInt(u16, tlv.value[2..4], .big)),
                    };
                },
                .management_address => if (du.management_address == null) {
                    du.management_address = try ManagementAddress.parse(tlv.value);
                },
                else => {}, // org-specific / unknown: via iterators below
            }
        }
        return du;
    }

    /// Fresh iterator over the whole TLV stream.
    pub fn tlvIterator(du: *const Lldpdu) TlvIterator {
        return TlvIterator.init(du.raw);
    }

    /// Iterator over the organizationally-specific (type 127) TLVs.
    pub fn orgIterator(du: *const Lldpdu) OrgIterator {
        return .{ .inner = TlvIterator.init(du.raw) };
    }

    /// Iterator over every Management Address TLV (the typed field holds
    /// only the first).
    pub fn managementAddressIterator(du: *const Lldpdu) ManagementAddressIterator {
        return .{ .inner = TlvIterator.init(du.raw) };
    }
};

// ── builder ─────────────────────────────────────────────────────────────────

/// Appends LLDPDU TLVs into a caller buffer. Call the mandatory adders
/// (Chassis ID, Port ID, TTL) first, then optionals, then `finish`.
pub const Builder = struct {
    buf: []u8,
    pos: usize = 0,

    pub fn init(buf: []u8) Builder {
        return .{ .buf = buf };
    }

    /// Appends a raw TLV.
    pub fn addTlv(b: *Builder, tlv_type: TlvType, value: []const u8) BuildError!void {
        if (value.len > max_tlv_len) return BuildError.ValueTooLong;
        if (b.pos + 2 + value.len > b.buf.len) return BuildError.BufferTooSmall;
        const header: u16 = (@as(u16, @intFromEnum(tlv_type)) << 9) | @as(u16, @intCast(value.len));
        std.mem.writeInt(u16, b.buf[b.pos..][0..2], header, .big);
        @memcpy(b.buf[b.pos + 2 ..][0..value.len], value);
        b.pos += 2 + value.len;
    }

    /// Chassis ID with an explicit subtype + value.
    pub fn addChassisId(b: *Builder, subtype: ChassisIdSubtype, value: []const u8) BuildError!void {
        try b.addSubtyped(.chassis_id, @intFromEnum(subtype), value);
    }

    pub fn addChassisIdMac(b: *Builder, mac: Mac) BuildError!void {
        try b.addChassisId(.mac_address, &mac.octets);
    }

    pub fn addPortId(b: *Builder, subtype: PortIdSubtype, value: []const u8) BuildError!void {
        try b.addSubtyped(.port_id, @intFromEnum(subtype), value);
    }

    pub fn addPortIdIfName(b: *Builder, name: []const u8) BuildError!void {
        try b.addPortId(.interface_name, name);
    }

    pub fn addTtl(b: *Builder, seconds: u16) BuildError!void {
        var be: [2]u8 = undefined;
        std.mem.writeInt(u16, &be, seconds, .big);
        try b.addTlv(.ttl, &be);
    }

    pub fn addPortDescription(b: *Builder, text: []const u8) BuildError!void {
        try b.addTlv(.port_description, text);
    }

    pub fn addSystemName(b: *Builder, name: []const u8) BuildError!void {
        try b.addTlv(.system_name, name);
    }

    pub fn addSystemDescription(b: *Builder, desc: []const u8) BuildError!void {
        try b.addTlv(.system_description, desc);
    }

    pub fn addSystemCapabilities(b: *Builder, caps: SystemCapabilities, enabled: SystemCapabilities) BuildError!void {
        var v: [4]u8 = undefined;
        std.mem.writeInt(u16, v[0..2], caps.toWire(), .big);
        std.mem.writeInt(u16, v[2..4], enabled.toWire(), .big);
        try b.addTlv(.system_capabilities, &v);
    }

    pub const ManagementAddressOptions = struct {
        ip: netaddr.Ip,
        interface_subtype: InterfaceNumberingSubtype = .if_index,
        interface_number: u32 = 0,
        oid: []const u8 = &.{},
    };

    pub fn addManagementAddress(b: *Builder, opts: ManagementAddressOptions) BuildError!void {
        var scratch: [64]u8 = undefined;
        var n: usize = 0;
        const addr: []const u8, const family: u8 = switch (opts.ip) {
            .v4 => |q| .{ &q, addr_family_ipv4 },
            .v6 => |q| .{ &q, addr_family_ipv6 },
        };
        scratch[n] = @intCast(1 + addr.len); // addr string length
        scratch[n + 1] = family;
        @memcpy(scratch[n + 2 ..][0..addr.len], addr);
        n += 2 + addr.len;
        scratch[n] = @intFromEnum(opts.interface_subtype);
        std.mem.writeInt(u32, scratch[n + 1 ..][0..4], opts.interface_number, .big);
        scratch[n + 5] = @intCast(opts.oid.len);
        n += 6;
        if (opts.oid.len > 0) {
            @memcpy(scratch[n..][0..opts.oid.len], opts.oid);
            n += opts.oid.len;
        }
        try b.addTlv(.management_address, scratch[0..n]);
    }

    /// A raw organizationally-specific TLV (OUI + subtype + info).
    pub fn addOrgSpecific(b: *Builder, oui: [3]u8, subtype: u8, info: []const u8) BuildError!void {
        var scratch: [max_tlv_len]u8 = undefined;
        if (4 + info.len > scratch.len) return BuildError.ValueTooLong;
        scratch[0..3].* = oui;
        scratch[3] = subtype;
        @memcpy(scratch[4..][0..info.len], info);
        try b.addTlv(.org_specific, scratch[0 .. 4 + info.len]);
    }

    /// IEEE 802.1 Port VLAN ID (subtype 1).
    pub fn addPortVlanId(b: *Builder, vlan: u16) BuildError!void {
        var be: [2]u8 = undefined;
        std.mem.writeInt(u16, &be, vlan, .big);
        try b.addOrgSpecific(oui_ieee_8021, 1, &be);
    }

    /// IEEE 802.3 Maximum Frame Size (subtype 4).
    pub fn addMaxFrameSize(b: *Builder, size: u16) BuildError!void {
        var be: [2]u8 = undefined;
        std.mem.writeInt(u16, &be, size, .big);
        try b.addOrgSpecific(oui_ieee_8023, 4, &be);
    }

    /// Appends the End-of-LLDPDU TLV and returns the finished LLDPDU.
    pub fn finish(b: *Builder) BuildError![]const u8 {
        try b.addTlv(.end, &.{});
        return b.buf[0..b.pos];
    }

    fn addSubtyped(b: *Builder, tlv_type: TlvType, subtype: u8, value: []const u8) BuildError!void {
        if (value.len + 1 > max_tlv_len) return BuildError.ValueTooLong;
        if (b.pos + 2 + 1 + value.len > b.buf.len) return BuildError.BufferTooSmall;
        const header: u16 = (@as(u16, @intFromEnum(tlv_type)) << 9) | @as(u16, @intCast(1 + value.len));
        std.mem.writeInt(u16, b.buf[b.pos..][0..2], header, .big);
        b.buf[b.pos + 2] = subtype;
        @memcpy(b.buf[b.pos + 3 ..][0..value.len], value);
        b.pos += 3 + value.len;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

const kat_mac = Mac{ .octets = .{ 0x00, 0x1b, 0x21, 0x3c, 0x9d, 0xf8 } };

// Golden LLDPDU, transcribed TLV-by-TLV from IEEE 802.1AB (7-bit type +
// 9-bit length headers computed by hand):
//   Chassis ID (MAC) · Port ID (ifname) · TTL · System Name ·
//   System Capabilities · Management Address (IPv4) · 802.1 Port-VLAN · End.
const kat = [_]u8{ 0x02, 0x07, 0x04 } ++ kat_mac.octets // Chassis ID: (1<<9)|7
++ [_]u8{ 0x04, 0x06, 0x05 } ++ "Gi0/1".* // Port ID: (2<<9)|6, ifname
++ [_]u8{ 0x06, 0x02, 0x00, 0x78 } // TTL: (3<<9)|2 = 120 s
++ [_]u8{ 0x0a, 0x07 } ++ "lab-sw1".* // System Name: (5<<9)|7
++ [_]u8{ 0x0e, 0x04, 0x00, 0x14, 0x00, 0x04 } // System Caps: (7<<9)|4
++ [_]u8{ 0x10, 0x0c } // Management Address: (8<<9)|12
++ [_]u8{ 0x05, 0x01, 0xc0, 0xa8, 0x0a, 0x02, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00 } ++ [_]u8{ 0xfe, 0x06, 0x00, 0x80, 0xc2, 0x01, 0x00, 0x0a } // 802.1 Port VLAN: (127<<9)|6
++ [_]u8{ 0x00, 0x00 }; // End-of-LLDPDU

test "LLDP KAT: parse the full LLDPDU" {
    const du = try Lldpdu.parse(&kat);

    // Chassis ID: MAC.
    try testing.expectEqual(ChassisIdSubtype.mac_address, du.chassis_id.subtype);
    try testing.expect(du.chassis_id.mac().?.eql(kat_mac));

    // Port ID: interface name.
    try testing.expectEqual(PortIdSubtype.interface_name, du.port_id.subtype);
    try testing.expectEqualStrings("Gi0/1", du.port_id.text().?);

    // TTL.
    try testing.expectEqual(@as(u16, 120), du.ttl_s);

    // System Name.
    try testing.expectEqualStrings("lab-sw1", du.system_name.?);

    // System Capabilities: bridge + router capable, bridge enabled.
    const caps = du.capabilities.?;
    try testing.expect(caps.capabilities.bridge);
    try testing.expect(caps.capabilities.router);
    try testing.expect(caps.enabled.bridge);
    try testing.expect(!caps.enabled.router);

    // Management Address: IPv4 192.168.10.2, ifIndex 1.
    const ma = du.management_address.?;
    try testing.expectEqual(InterfaceNumberingSubtype.if_index, ma.interface_subtype);
    try testing.expectEqual(@as(u32, 1), ma.interface_number);
    var ipbuf: [netaddr.max_ip_text_len]u8 = undefined;
    try testing.expectEqualStrings("192.168.10.2", netaddr.formatIp(ma.ip().?, &ipbuf));

    // Org-specific: IEEE 802.1 Port VLAN 10.
    var org = du.orgIterator();
    const o = (try org.next()).?;
    try testing.expectEqualSlices(u8, &oui_ieee_8021, &o.oui);
    switch (o.decode().?) {
        .port_vlan_id => |v| try testing.expectEqual(@as(u16, 10), v),
        else => return error.WrongOrgValue,
    }
    try testing.expectEqual(@as(?OrgSpecific, null), try org.next());
}

test "LLDP round-trip: builder reproduces the golden bytes" {
    var buf: [256]u8 = undefined;
    var b = Builder.init(&buf);
    try b.addChassisIdMac(kat_mac);
    try b.addPortIdIfName("Gi0/1");
    try b.addTtl(120);
    try b.addSystemName("lab-sw1");
    try b.addSystemCapabilities(
        .{ .bridge = true, .router = true },
        .{ .bridge = true },
    );
    try b.addManagementAddress(.{
        .ip = .{ .v4 = .{ 192, 168, 10, 2 } },
        .interface_subtype = .if_index,
        .interface_number = 1,
    });
    try b.addPortVlanId(10);
    const bytes = try b.finish();
    try testing.expectEqualSlices(u8, &kat, bytes);

    // build → parse agrees with the model.
    const du = try Lldpdu.parse(bytes);
    try testing.expect(du.chassis_id.mac().?.eql(kat_mac));
    try testing.expectEqual(@as(u16, 120), du.ttl_s);
}

test "LLDP: network-address chassis id + IPv6 management address" {
    var buf: [128]u8 = undefined;
    var b = Builder.init(&buf);
    // Chassis ID network-address: family(1=IPv4) || 10.0.0.1
    try b.addChassisId(.network_address, &.{ 1, 10, 0, 0, 1 });
    try b.addPortId(.mac_address, &kat_mac.octets);
    try b.addTtl(30);
    try b.addManagementAddress(.{ .ip = .{ .v6 = [_]u8{0} ** 15 ++ [_]u8{1} } });
    try b.addMaxFrameSize(1522);
    const bytes = try b.finish();

    const du = try Lldpdu.parse(bytes);
    var ipbuf: [netaddr.max_ip_text_len]u8 = undefined;
    try testing.expectEqualStrings("10.0.0.1", netaddr.formatIp(du.chassis_id.ip().?, &ipbuf));
    try testing.expect(du.port_id.mac().?.eql(kat_mac));
    try testing.expectEqualStrings("::1", netaddr.formatIp(du.management_address.?.ip().?, &ipbuf));

    // 802.3 max-frame-size org TLV decodes.
    var org = du.orgIterator();
    const o = (try org.next()).?;
    switch (o.decode().?) {
        .max_frame_size => |s| try testing.expectEqual(@as(u16, 1522), s),
        else => return error.WrongOrgValue,
    }
}

test "LLDP: unknown optional TLV passes through, never fails parse" {
    var buf: [128]u8 = undefined;
    var b = Builder.init(&buf);
    try b.addChassisIdMac(kat_mac);
    try b.addPortIdIfName("e0");
    try b.addTtl(60);
    try b.addTlv(@enumFromInt(100), &.{ 0xde, 0xad, 0xbe, 0xef }); // reserved/unknown type
    const bytes = try b.finish();

    const du = try Lldpdu.parse(bytes); // must not error
    var it = du.tlvIterator();
    var saw_unknown = false;
    while (try it.next()) |tlv| {
        if (@intFromEnum(tlv.type) == 100) {
            try testing.expectEqualSlices(u8, &.{ 0xde, 0xad, 0xbe, 0xef }, tlv.value);
            saw_unknown = true;
        }
    }
    try testing.expect(saw_unknown);
}

test "LLDP: VLAN name org TLV" {
    const info = [_]u8{ 0x00, 0x0a, 0x04 } ++ "VLAN".*; // vlan 10, name "VLAN"
    const o = try OrgSpecific.parse(&(oui_ieee_8021 ++ [_]u8{3} ++ info));
    switch (o.decode().?) {
        .vlan_name => |v| {
            try testing.expectEqual(@as(u16, 10), v.vlan_id);
            try testing.expectEqualStrings("VLAN", v.name);
        },
        else => return error.WrongOrgValue,
    }
}

test "LLDP malformed: typed errors, no panic" {
    // Missing mandatory: an LLDPDU that starts with System Name.
    var buf: [64]u8 = undefined;
    var b = Builder.init(&buf);
    try b.addSystemName("x");
    try testing.expectError(ParseError.MissingMandatory, Lldpdu.parse(try b.finish()));

    // TLV length overruns the buffer.
    try testing.expectError(ParseError.TruncatedTlv, Lldpdu.parse(&.{ 0x02, 0x07, 0x04 }));

    // Truncated header (one byte).
    try testing.expectError(ParseError.Truncated, Lldpdu.parse(&.{0x02}));

    // TTL with the wrong length.
    const bad_ttl = [_]u8{ 0x02, 0x07, 0x04 } ++ kat_mac.octets ++
        [_]u8{ 0x04, 0x03, 0x05 } ++ "e0".* ++
        [_]u8{ 0x06, 0x01, 0x78 } ++ // TTL length 1 (illegal)
        [_]u8{ 0x00, 0x00 };
    try testing.expectError(ParseError.MissingMandatory, Lldpdu.parse(&bad_ttl));

    // Management Address with an inconsistent internal length.
    var mbuf: [64]u8 = undefined;
    var mb = Builder.init(&mbuf);
    try mb.addChassisIdMac(kat_mac);
    try mb.addPortIdIfName("e0");
    try mb.addTtl(1);
    try mb.addTlv(.management_address, &.{ 0xff, 0x01, 0xc0 }); // addr-str-len 255
    try testing.expectError(ParseError.BadManagementAddress, Lldpdu.parse(try mb.finish()));
}

test "LLDP garbage sweep: no panics on random input" {
    var prng = std.Random.DefaultPrng.init(0x4c4c4450); // "LLDP"
    const random = prng.random();
    var buf: [256]u8 = undefined;
    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        const len = random.uintAtMost(usize, buf.len);
        random.bytes(buf[0..len]);
        if (Lldpdu.parse(buf[0..len])) |du| {
            var it = du.tlvIterator();
            while (it.next() catch null) |_| {}
            var org = du.orgIterator();
            while (org.next() catch null) |o| _ = o.decode();
            var ma = du.managementAddressIterator();
            while (ma.next() catch null) |_| {}
        } else |_| {}
    }
}
