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
//!   Port ID, Time To Live) are required first, in order, and a malformed
//!   one always aborts the parse; the optional TLVs (Port Description,
//!   System Name, System Description, System Capabilities, Management
//!   Address) are extracted as they appear. A malformed optional TLV also
//!   aborts the parse by default, but `ParseOptions.tolerant_optionals` (see
//!   its doc comment) opts into skipping it and keeping the rest.
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
// Test-only (`build.zig`'s `test_deps`, never `deps`): the fuzz corpus seed
// helpers, in the format `std.testing.Smith` actually reads.
const testkit = @import("testkit");
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
    /// A field the typed builders write is outside what its encoding can
    /// carry: an ELIN that is not 10 to 25 octets, a civic address whose
    /// `what` is above 2, whose country code is not two capital letters or
    /// whose LCI is over 255 octets, a known coordinate beyond +-90 / +-180
    /// degrees, an ETS traffic-class count above 8.
    InvalidValue,
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

    /// The value as text for the string-bearing subtypes (component /
    /// alias / name / local); null otherwise. Both component subtypes are
    /// an entPhysicalAlias, a string (IEEE 802.1AB 9.5.2.2).
    pub fn text(c: ChassisId) ?[]const u8 {
        return switch (c.subtype) {
            .interface_alias, .interface_name, .local, .chassis_component, .port_component => c.value,
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

    /// The value as text for the string-bearing subtypes; null otherwise.
    /// `port_component` is an entPhysicalAlias, a string (IEEE 802.1AB
    /// 9.5.3.2) -- it returned null until 2026-10-06, so a neighbour that
    /// names its port that way showed no port at all (tcpdump oracle).
    pub fn text(p: PortId) ?[]const u8 {
        return switch (p.subtype) {
            .interface_alias, .port_component, .interface_name, .local, .agent_circuit_id => p.value,
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
        const iface_subtype: InterfaceNumberingSubtype = @fromBackingInt(@intCast(value[pos]));
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
/// TIA (ANSI/TIA-1057, LLDP-MED) — what VoIP phones and PoE switches send.
pub const oui_tia = [3]u8{ 0x00, 0x12, 0xbb };
/// The OUI the 802.1Qbg draft's EVB TLV used (what gopacket decodes).
pub const oui_ieee_8021qbg = [3]u8{ 0x00, 0x13, 0xbf };
/// Cisco's second OUI: its PoE (spare pair) TLV.
pub const oui_cisco = [3]u8{ 0x00, 0x01, 0x42 };
/// PROFINET (PI), the industrial-Ethernet TLVs.
pub const oui_profinet = [3]u8{ 0x00, 0x0e, 0xcf };

/// LLDP-MED capability bits (TIA-1057 §10.2.2.2), for `MedCapabilities.capabilities`.
pub const MED_CAP = struct {
    pub const capabilities: u16 = 0x0001;
    pub const network_policy: u16 = 0x0002;
    pub const location: u16 = 0x0004;
    pub const ext_power_pse: u16 = 0x0008;
    pub const ext_power_pd: u16 = 0x0010;
    pub const inventory: u16 = 0x0020;
};

/// LLDP-MED device type (TIA-1057 §10.2.2.3).
pub const MedDeviceType = enum(u8) {
    not_defined = 0,
    endpoint_class_1 = 1,
    endpoint_class_2 = 2,
    endpoint_class_3 = 3,
    network_connectivity = 4,
    _,
};

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
                2 => { // Port And Protocol VLAN ID: flags (1) + PPVID (2)
                    if (o.info.len < 3) return null;
                    return .{ .port_protocol_vlan = .{
                        .flags = o.info[0],
                        .ppvid = std.mem.readInt(u16, o.info[1..3], .big),
                    } };
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
                4 => { // Protocol Identity: length (1) + identity octets
                    if (o.info.len < 1 or 1 + @as(usize, o.info[0]) > o.info.len) return null;
                    return .{ .protocol_identity = o.info[1 .. 1 + o.info[0]] };
                },
                5 => { // VID Usage Digest
                    if (o.info.len < 4) return null;
                    return .{ .vid_usage_digest = std.mem.readInt(u32, o.info[0..4], .big) };
                },
                6 => { // Management VID
                    if (o.info.len < 2) return null;
                    return .{ .management_vid = std.mem.readInt(u16, o.info[0..2], .big) };
                },
                7 => return linkAggregation(o.info),
                9 => return if (EtsConfig.parse(o.info)) |e| .{ .ets_config = e } else null,
                10 => return if (EtsRecommendation.parse(o.info)) |e| .{ .ets_recommendation = e } else null,
                11 => { // IEEE 802.1Qaz PFC Configuration: flags (1) + enable bitmap (1)
                    if (o.info.len < 2) return null;
                    return .{ .pfc = .{
                        .willing = o.info[0] & 0x80 != 0,
                        .mbc = o.info[0] & 0x40 != 0,
                        .capability = @intCast(o.info[0] & 0x0f),
                        .enable = o.info[1],
                    } };
                },
                12 => { // IEEE 802.1Qaz Application Priority: reserved (1) + 3-octet entries
                    if (o.info.len < 1 or (o.info.len - 1) % 3 != 0) return null;
                    return .{ .app_priority = .{ .entries = o.info[1..] } };
                },
                else => return null,
            }
        } else if (std.mem.eql(u8, &o.oui, &oui_ieee_8023)) {
            switch (o.subtype) {
                3 => return linkAggregation(o.info),
                1 => { // MAC/PHY Config/Status
                    if (o.info.len < 5) return null;
                    return .{ .mac_phy = .{
                        .autoneg = o.info[0],
                        .pmd_advertised = std.mem.readInt(u16, o.info[1..3], .big),
                        .operational_mau = std.mem.readInt(u16, o.info[3..5], .big),
                    } };
                },
                2 => { // Power Via MDI: support (1), PSE pair (1), class (1) [+ 802.3at]
                    if (o.info.len < 3) return null;
                    var pv: PowerViaMdi = .{
                        .mdi_support = o.info[0],
                        .pse_power_pair = o.info[1],
                        .power_class = o.info[2],
                    };
                    // IEEE 802.3at-2009 extension: type/source/priority (1),
                    // PD requested power (2), PSE allocated power (2), both in
                    // units of 0.1 W. Anything shorter is the 802.3ab form.
                    if (o.info.len >= 8) pv.dot3at = .{
                        .type_source_priority = o.info[3],
                        .pd_requested_dw = std.mem.readInt(u16, o.info[4..6], .big),
                        .pse_allocated_dw = std.mem.readInt(u16, o.info[6..8], .big),
                    };
                    return .{ .power_via_mdi = pv };
                },
                4 => { // Maximum Frame Size
                    if (o.info.len < 2) return null;
                    return .{ .max_frame_size = std.mem.readInt(u16, o.info[0..2], .big) };
                },
                else => return null,
            }
        } else if (std.mem.eql(u8, &o.oui, &oui_ieee_8021qbg)) {
            if (o.subtype == 0) return if (Evb.parse(o.info)) |e| .{ .evb = e } else null;
        } else if (std.mem.eql(u8, &o.oui, &oui_cisco)) {
            if (o.subtype == 1 and o.info.len >= 1) return .{ .cisco_poe = .{
                .pse_four_wire = o.info[0] & 0x01 != 0,
                .pd_spare_pair_shared = o.info[0] & 0x02 != 0,
                .pd_request_spare_pair = o.info[0] & 0x04 != 0,
                .pse_spare_pair_on = o.info[0] & 0x08 != 0,
            } };
        } else if (std.mem.eql(u8, &o.oui, &oui_profinet)) {
            return profinetDecode(o);
        } else if (std.mem.eql(u8, &o.oui, &oui_tia)) {
            switch (o.subtype) {
                1 => { // LLDP-MED Capabilities: capabilities (2) + device type (1)
                    if (o.info.len < 3) return null;
                    return .{ .med_capabilities = .{
                        .capabilities = std.mem.readInt(u16, o.info[0..2], .big),
                        .device_type = @fromBackingInt(@intCast(o.info[2])),
                    } };
                },
                2 => { // Network Policy: app type (1) + U T X VLAN(12) prio(3) DSCP(6)
                    if (o.info.len < 4) return null;
                    const v: u24 = std.mem.readInt(u24, o.info[1..4], .big);
                    return .{ .med_network_policy = .{
                        .application = o.info[0],
                        .unknown_policy = v & (1 << 23) != 0,
                        .tagged = v & (1 << 22) != 0,
                        .vlan_id = @intCast((v >> 9) & 0x0fff),
                        .l2_priority = @intCast((v >> 6) & 0x7),
                        .dscp = @intCast(v & 0x3f),
                    } };
                },
                3 => { // Location Identification: format (1) + data
                    if (o.info.len < 1) return null;
                    return .{ .med_location = .{ .format = o.info[0], .data = o.info[1..] } };
                },
                4 => { // Extended Power-via-MDI: type/source/priority (1) + power (2)
                    if (o.info.len < 3) return null;
                    const b = o.info[0];
                    return .{ .med_ext_power = .{
                        .power_type = @intCast(b >> 6),
                        .power_source = @intCast((b >> 4) & 0x3),
                        .priority = @intCast(b & 0x0f),
                        .power_dw = std.mem.readInt(u16, o.info[1..3], .big),
                    } };
                },
                5...11 => return .{ .med_inventory = .{
                    .field = @fromBackingInt(@intCast(o.subtype)),
                    .text = o.info,
                } },
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

/// IEEE 802.1 Port And Protocol VLAN ID. `flags`: bit 1 = supported,
/// bit 2 = enabled.
pub const PortProtocolVlan = struct { flags: u8, ppvid: u16 };

/// IEEE 802.3 Power Via MDI (802.3ab), with the 802.3at extension when sent.
pub const PowerViaMdi = struct {
    /// Bit 0 port class PSE, 1 PSE MDI power supported, 2 enabled,
    /// 3 pair control ability.
    mdi_support: u8,
    /// 1 = signal pairs, 2 = spare pairs.
    pse_power_pair: u8,
    /// Power class + 1 (1 = class 0 … 5 = class 4).
    power_class: u8,
    dot3at: ?struct {
        /// Bits 7-6 power type, 5-4 power source, 1-0 priority.
        type_source_priority: u8,
        /// Units of 0.1 W.
        pd_requested_dw: u16,
        pse_allocated_dw: u16,
    } = null,
};

pub const MedCapabilities = struct {
    /// `MED_CAP` bits.
    capabilities: u16,
    device_type: MedDeviceType,
};

/// LLDP-MED Network Policy — the voice VLAN a phone is told to use.
pub const MedNetworkPolicy = struct {
    /// 1 voice, 2 voice signaling, 3 guest voice, 4 guest voice signaling,
    /// 5 softphone voice, 6 video conferencing, 7 streaming video,
    /// 8 video signaling (TIA-1057 Table 12).
    application: u8,
    /// U: the device needs a policy and has none.
    unknown_policy: bool,
    /// T: 802.1Q tagged (false = untagged, priority still applies).
    tagged: bool,
    vlan_id: u12,
    l2_priority: u3,
    dscp: u6,
};

/// Why a location LCI could not be decoded. `null` from the decoders below
/// means "this LCI is in another format"; these mean "it is this format and
/// wrong".
pub const LocationError = error{
    /// The LCI is not the length its format requires.
    BadLength,
    /// A civic LCI whose `what` is above 2 or whose country code is not two capital ASCII letters (RFC 4776 §3.1).
    Reserved,
    /// Latitude beyond 90 or longitude beyond 180 degrees (RFC 6225 §2.3: invalid, consumers MUST ignore).
    OutOfRange,
};

pub const MedLocation = struct {
    /// 1 coordinate-based LCI, 2 civic address LCI, 3 ECS ELIN.
    format: u8,
    data: []const u8,

    /// The coordinate-based LCI (format 1, RFC 3825 §2.1): exactly 16 octets.
    /// `null`: another format. `error.BadLength`: not 16 octets. `error.OutOfRange`:
    /// a latitude beyond +-90 or a longitude beyond +-180 degrees whose resolution says it is
    /// known (RFC 6225 §2.3: such values "MUST be considered invalid"; they apply to datums 1-3).
    /// Everything else is decided PER FIELD and never rejects the LCI: a resolution of 0 means
    /// "unknown" (RFC 6225 §2.3.2), above 34 (altitude 30) is "undefined and reserved" (RFC 3825
    /// §2.1), altitude type 0 is "no altitude" (RFC 6225 §2.4.1) and above 2 is undefined; such a
    /// field is not range-checked and its accessor returns null (`latitudeKnown` and friends),
    /// the raw field stays readable and the other fields are kept. The datum is not checked
    /// either: RFC 6225 §2.5 tells a client that does not know a datum to assume WGS 84
    /// (`Coordinate.datumKnown`).
    pub fn coordinate(l: MedLocation) LocationError!?Coordinate {
        if (l.format != 1) return null;
        if (l.data.len != 16) return error.BadLength;
        const v = std.mem.readInt(u128, l.data[0..16], .big);
        const m34: u128 = (1 << 34) - 1;
        const m30: u128 = (1 << 30) - 1;
        const lat: u34 = @intCast((v >> 88) & m34);
        const lon: u34 = @intCast((v >> 48) & m34);
        const alt: u30 = @intCast((v >> 8) & m30);
        const c: Coordinate = .{
            .lat_resolution = @intCast(v >> 122),
            .lat = @as(i34, @bitCast(lat)),
            .lon_resolution = @intCast((v >> 82) & 0x3f),
            .lon = @as(i34, @bitCast(lon)),
            .altitude_type = @intCast((v >> 44) & 0xf),
            .alt_resolution = @intCast((v >> 38) & 0x3f),
            .alt = @as(i30, @bitCast(alt)),
            .datum = @intCast(v & 0xff),
        };
        // Per field (a field whose resolution is 0 or reserved is "unknown" and is not range-checked;
        // a reserved altitude never rejects latitude and longitude).
        if (c.latitudeKnown() and (c.lat > lat_limit or c.lat < -lat_limit)) return error.OutOfRange;
        if (c.longitudeKnown() and (c.lon > lon_limit or c.lon < -lon_limit)) return error.OutOfRange;
        return c;
    }

    const lat_limit: i34 = 90 << 25;
    const lon_limit: i34 = 180 << 25;

    /// The civic address LCI (format 2, RFC 4776 §3.1 as TIA-1057 carries
    /// it). `null`: another format. `error.BadLength`: the LCI length byte is
    /// below 3 (what + country code) or disagrees with the TLV.
    pub fn civic(l: MedLocation) LocationError!?Civic {
        if (l.format != 2) return null;
        if (l.data.len < 4) return error.BadLength;
        const lci_len: usize = l.data[0];
        if (lci_len < 3 or l.data.len != 1 + lci_len) return error.BadLength;
        // RFC 4776 §3.1: `what` is 0, 1 or 2; the country code is two capital ASCII letters.
        if (l.data[1] > 2) return error.Reserved;
        for (l.data[2..4]) |ch| if (ch < 'A' or ch > 'Z') return error.Reserved;
        return .{ .what = l.data[1], .country = l.data[2..4].*, .elements = l.data[4..] };
    }

    /// The ECS ELIN (format 3): the emergency number as text, 10 to 25
    /// octets (TIA-1057). `null`: another format.
    pub fn elin(l: MedLocation) LocationError!?[]const u8 {
        if (l.format != 3) return null;
        if (l.data.len < 10 or l.data.len > 25) return error.BadLength;
        return l.data;
    }
};

/// A decoded coordinate LCI. The raw fixed-point values are kept; the
/// accessors convert (RFC 3825: latitude and longitude are 9.25 two's-complement
/// fixed point, altitude 22.8) and return null where the sender said "unknown".
pub const Coordinate = struct {
    /// Number of valid high-order bits of `lat` / `lon` / `alt` (0 = unknown).
    lat_resolution: u6,
    lat: i34,
    lon_resolution: u6,
    lon: i34,
    /// 0 none, 1 metres, 2 floors.
    altitude_type: u4,
    alt_resolution: u6,
    alt: i30,
    /// 1 WGS 84, 2 NAD83 / NAVD88, 3 NAD83 / MLLW.
    datum: u8,

    /// A field is known when its resolution is 1..34 (altitude 1..30); 0 means unknown
    /// and above that is reserved (RFC 3825 §2.1, RFC 6225 §2.3.1), which read as unknown here.
    pub fn latitudeKnown(c: Coordinate) bool {
        return c.lat_resolution >= 1 and c.lat_resolution <= 34;
    }
    pub fn longitudeKnown(c: Coordinate) bool {
        return c.lon_resolution >= 1 and c.lon_resolution <= 34;
    }
    /// Altitude type 1 (meters) or 2 (floors) with a resolution of 1..30. Type 0 is "no altitude" (RFC 6225 §2.4.1).
    pub fn altitudeKnown(c: Coordinate) bool {
        return (c.altitude_type == 1 or c.altitude_type == 2) and c.alt_resolution >= 1 and c.alt_resolution <= 30;
    }

    /// Null when the latitude is not known.
    pub fn latitudeDegrees(c: Coordinate) ?f64 {
        if (!c.latitudeKnown()) return null;
        return @as(f64, @floatFromInt(c.lat)) / 33554432.0;
    }
    pub fn longitudeDegrees(c: Coordinate) ?f64 {
        if (!c.longitudeKnown()) return null;
        return @as(f64, @floatFromInt(c.lon)) / 33554432.0;
    }
    /// Metres or floors, per `altitude_type`; null when the altitude is not known.
    pub fn altitudeUnits(c: Coordinate) ?f64 {
        if (!c.altitudeKnown()) return null;
        return @as(f64, @floatFromInt(c.alt)) / 256.0;
    }
    /// Datums 1 to 3 are the registered ones (RFC 6225 §2.5); any other is to be read as WGS 84.
    pub fn datumKnown(c: Coordinate) bool {
        return c.datum >= 1 and c.datum <= 3;
    }
};

/// A decoded civic address LCI: the "what" (0 the DHCP server's location, 1
/// the network element, 2 the client), the ISO 3166 country code and the
/// `{type, length, value}` elements behind them.
pub const Civic = struct {
    what: u8,
    country: [2]u8,
    elements: []const u8,

    pub fn iterator(c: Civic) CivicIterator {
        return .{ .buf = c.elements };
    }
};

pub const CivicElement = struct {
    /// RFC 4776 CAtype: 1 A1 (state) … 3 A3 (city), 6 street, 19 house number, 24 postal code, …
    ca_type: u8,
    value: []const u8,
};

pub const CivicIterator = struct {
    buf: []const u8,
    pos: usize = 0,
    failed: bool = false,

    /// An element whose length overruns the LCI is `error.Malformed`, once;
    /// then the iterator is terminal.
    pub fn next(it: *CivicIterator) error{Malformed}!?CivicElement {
        if (it.failed or it.pos == it.buf.len) return null;
        if (it.buf.len - it.pos < 2 or it.buf.len - it.pos - 2 < it.buf[it.pos + 1]) {
            it.failed = true;
            return error.Malformed;
        }
        const len = it.buf[it.pos + 1];
        const e: CivicElement = .{ .ca_type = it.buf[it.pos], .value = it.buf[it.pos + 2 ..][0..len] };
        it.pos += 2 + len;
        return e;
    }
};

pub const MedExtPower = struct {
    /// 0 PSE, 1 PD (the two "type" encodings TIA-1057 §10.2.5.1 defines).
    power_type: u2,
    /// Meaning depends on the type: for a PD, 1 = PSE, 2 = local, 3 = both.
    power_source: u2,
    /// 1 critical, 2 high, 3 low (0 unknown).
    priority: u4,
    /// Units of 0.1 W (6.5 W = 65).
    power_dw: u16,
};

pub const MedInventoryField = enum(u8) {
    hardware_revision = 5,
    firmware_revision = 6,
    software_revision = 7,
    serial_number = 8,
    manufacturer = 9,
    model = 10,
    asset_id = 11,
};

pub const MedInventory = struct { field: MedInventoryField, text: []const u8 };

/// DCBX Priority Flow Control Configuration (IEEE 802.1Qaz §38.4.3).
pub const PfcConfig = struct {
    /// The sender is willing to accept the peer's configuration.
    willing: bool,
    /// MACsec bypass capability.
    mbc: bool,
    /// Number of traffic classes that can do PFC at once.
    capability: u4,
    /// Bit n set: PFC enabled for priority n.
    enable: u8,
};

/// DCBX Application Priority table (IEEE 802.1Qaz §38.4.4): after a reserved
/// octet, entries of priority (3 bits), reserved (2), selector (3), protocol id (2 octets).
pub const AppPriorityTable = struct {
    entries: []const u8,

    pub const Entry = struct { priority: u3, selector: u3, protocol: u16 };

    pub fn count(t: AppPriorityTable) usize {
        return t.entries.len / 3;
    }

    pub fn at(t: AppPriorityTable, i: usize) ?Entry {
        if (i >= t.count()) return null;
        const e = t.entries[i * 3 ..][0..3];
        return .{ .priority = @intCast(e[0] >> 5), .selector = @intCast(e[0] & 7), .protocol = std.mem.readInt(u16, e[1..3], .big) };
    }
};

fn linkAggregation(info: []const u8) ?OrgValue {
    if (info.len < 5) return null;
    return .{ .link_aggregation = .{
        .capable = info[0] & 1 != 0,
        .aggregated = info[0] & 2 != 0,
        .port_id = std.mem.readInt(u32, info[1..5], .big),
    } };
}

/// Link Aggregation TLV (IEEE 802.1AB-2009 Annex E.7; the same layout as the
/// deprecated IEEE 802.3 subtype 3): status octet, then the aggregated port id.
pub const LinkAggregation = struct {
    /// Status bit 0: the link is capable of being aggregated.
    capable: bool,
    /// Status bit 1: it is currently in an aggregation.
    aggregated: bool,
    /// 0 when not aggregated.
    port_id: u32,
};

/// A 4-octet table of 8 priority nibbles (IEEE 802.1Qaz §38.4.1): priority 0
/// in the high nibble of the first octet.
fn priorityTable(b: []const u8) [8]u4 {
    var t: [8]u4 = undefined;
    for (&t, 0..) |*e, i| e.* = @intCast(if (i % 2 == 0) b[i / 2] >> 4 else b[i / 2] & 0x0f);
    return t;
}

fn writePriorityTable(out: []u8, t: [8]u4) void {
    for (0..4) |i| out[i] = (@as(u8, t[2 * i]) << 4) | t[2 * i + 1];
}

/// DCBX ETS Configuration (IEEE 802.1Qaz §38.4.1, subtype 9): the sender's
/// own enhanced transmission selection settings. `tsa` per traffic class:
/// 0 strict priority, 1 credit-based shaper, 2 ETS, 255 vendor specific.
pub const EtsConfig = struct {
    willing: bool,
    /// Credit-based shaper support.
    cbs: bool,
    /// The raw "max TCs" field: 0 means 8 (`trafficClasses`).
    max_tcs: u3,
    /// Traffic class of priority 0..7.
    priority_to_tc: [8]u4,
    /// Percent of the bandwidth of traffic class 0..7.
    tc_bandwidth: [8]u8,
    tsa: [8]u8,

    pub fn trafficClasses(e: EtsConfig) u4 {
        return if (e.max_tcs == 0) 8 else e.max_tcs;
    }

    /// `null` when the info is under 21 octets.
    pub fn parse(info: []const u8) ?EtsConfig {
        if (info.len < 21) return null;
        return .{
            .willing = info[0] & 0x80 != 0,
            .cbs = info[0] & 0x40 != 0,
            .max_tcs = @intCast(info[0] & 0x07),
            .priority_to_tc = priorityTable(info[1..5]),
            .tc_bandwidth = info[5..13].*,
            .tsa = info[13..21].*,
        };
    }

    fn write(e: EtsConfig, out: *[21]u8) void {
        out[0] = (@as(u8, @intFromBool(e.willing)) << 7) | (@as(u8, @intFromBool(e.cbs)) << 6) | e.max_tcs;
        writePriorityTable(out[1..5], e.priority_to_tc);
        out[5..13].* = e.tc_bandwidth;
        out[13..21].* = e.tsa;
    }
};

/// DCBX ETS Recommendation (IEEE 802.1Qaz §38.4.2, subtype 10): what the
/// sender recommends its peer to configure; the same tables as `EtsConfig`
/// behind a reserved octet.
pub const EtsRecommendation = struct {
    priority_to_tc: [8]u4,
    tc_bandwidth: [8]u8,
    tsa: [8]u8,

    pub fn parse(info: []const u8) ?EtsRecommendation {
        if (info.len < 21) return null;
        return .{
            .priority_to_tc = priorityTable(info[1..5]),
            .tc_bandwidth = info[5..13].*,
            .tsa = info[13..21].*,
        };
    }

    fn write(e: EtsRecommendation, out: *[21]u8) void {
        out[0] = 0;
        writePriorityTable(out[1..5], e.priority_to_tc);
        out[5..13].* = e.tc_bandwidth;
        out[13..21].* = e.tsa;
    }
};

/// `Evb.supported` / `enabled` capability bits.
pub const EVB_CAP = struct {
    pub const standard_bridging: u16 = 1 << 7;
    pub const reflective_relay: u16 = 1 << 6;
    pub const retransmission_timer_exponent: u16 = 1 << 2;
    pub const edge_control_protocol: u16 = 1 << 1;
    pub const vsi_discovery_protocol: u16 = 1 << 0;
};

/// The 802.1Qbg (draft) Edge Virtual Bridging TLV, OUI 00-13-BF subtype 0,
/// as gopacket reads it: capabilities supported and enabled, the number of
/// VSIs supported and configured, the retransmission timer exponent.
pub const Evb = struct {
    supported: u16,
    enabled: u16,
    supported_vsis: u16,
    configured_vsis: u16,
    rte_exponent: u8,

    /// `null` when the info is under 9 octets.
    pub fn parse(info: []const u8) ?Evb {
        if (info.len < 9) return null;
        return .{
            .supported = std.mem.readInt(u16, info[0..2], .big),
            .enabled = std.mem.readInt(u16, info[2..4], .big),
            .supported_vsis = std.mem.readInt(u16, info[4..6], .big),
            .configured_vsis = std.mem.readInt(u16, info[6..8], .big),
            .rte_exponent = info[8],
        };
    }
};

/// Cisco's PoE spare-pair TLV (OUI 00-01-42 subtype 1): one flag octet.
pub const CiscoPoe = struct {
    /// Bit 0: the PSE supports four-wire PoE.
    pse_four_wire: bool,
    /// Bit 1: the PD's spare pair architecture is shared.
    pd_spare_pair_shared: bool,
    /// Bit 2: the PD requests spare pair PoE on.
    pd_request_spare_pair: bool,
    /// Bit 3: the PSE's spare pair PoE is on.
    pse_spare_pair_on: bool,

    fn toOctet(c: CiscoPoe) u8 {
        return @as(u8, @intFromBool(c.pse_four_wire)) | (@as(u8, @intFromBool(c.pd_spare_pair_shared)) << 1) |
            (@as(u8, @intFromBool(c.pd_request_spare_pair)) << 2) | (@as(u8, @intFromBool(c.pse_spare_pair_on)) << 3);
    }
};

/// PROFINET PNIO_DELAY (subtype 1): delays in nanoseconds.
pub const ProfinetDelay = struct { rx_local: u32, rx_remote: u32, tx_local: u32, tx_remote: u32, cable_local: u32 };
/// PROFINET PNIO_PORTSTATUS (subtype 2): RT class 2 and class 3 port status.
pub const ProfinetPortStatus = struct { class2: u16, class3: u16 };
/// PROFINET PNIO_MRPPORTSTATUS (subtype 4): MRP domain UUID and port status.
pub const ProfinetMrpPortStatus = struct { uuid: [16]u8, status: u16 };
/// PROFINET PNIO_PTCPSTATUS (subtype 6): the PTCP master and the IRT periods;
/// each period is a valid flag with a 31-bit length or start.
pub const ProfinetPtcpStatus = struct {
    master_address: [6]u8,
    subdomain_uuid: [16]u8,
    ir_data_uuid: [16]u8,
    period_valid: bool,
    period_length: u31,
    red_period_valid: bool,
    red_period_begin: u31,
    orange_period_valid: bool,
    orange_period_begin: u31,
    green_period_valid: bool,
    green_period_begin: u31,
};

fn profinetDecode(o: OrgSpecific) ?OrgValue {
    const i = o.info;
    switch (o.subtype) {
        1 => {
            if (i.len < 20) return null;
            return .{ .profinet_delay = .{
                .rx_local = std.mem.readInt(u32, i[0..4], .big),
                .rx_remote = std.mem.readInt(u32, i[4..8], .big),
                .tx_local = std.mem.readInt(u32, i[8..12], .big),
                .tx_remote = std.mem.readInt(u32, i[12..16], .big),
                .cable_local = std.mem.readInt(u32, i[16..20], .big),
            } };
        },
        2 => {
            if (i.len < 4) return null;
            return .{ .profinet_port_status = .{
                .class2 = std.mem.readInt(u16, i[0..2], .big),
                .class3 = std.mem.readInt(u16, i[2..4], .big),
            } };
        },
        4 => {
            if (i.len < 18) return null;
            return .{ .profinet_mrp_port_status = .{ .uuid = i[0..16].*, .status = std.mem.readInt(u16, i[16..18], .big) } };
        },
        5 => {
            if (i.len < 6) return null;
            return .{ .profinet_chassis_mac = i[0..6].* };
        },
        6 => {
            if (i.len < 54) return null;
            const p = [4]u32{
                std.mem.readInt(u32, i[38..42], .big),
                std.mem.readInt(u32, i[42..46], .big),
                std.mem.readInt(u32, i[46..50], .big),
                std.mem.readInt(u32, i[50..54], .big),
            };
            return .{ .profinet_ptcp_status = .{
                .master_address = i[0..6].*,
                .subdomain_uuid = i[6..22].*,
                .ir_data_uuid = i[22..38].*,
                .period_valid = p[0] >> 31 != 0,
                .period_length = @intCast(p[0] & 0x7fffffff),
                .red_period_valid = p[1] >> 31 != 0,
                .red_period_begin = @intCast(p[1] & 0x7fffffff),
                .orange_period_valid = p[2] >> 31 != 0,
                .orange_period_begin = @intCast(p[2] & 0x7fffffff),
                .green_period_valid = p[3] >> 31 != 0,
                .green_period_begin = @intCast(p[3] & 0x7fffffff),
            } };
        },
        else => return null,
    }
}

pub const OrgValue = union(enum) {
    port_vlan_id: u16, // IEEE 802.1 subtype 1
    port_protocol_vlan: PortProtocolVlan, // IEEE 802.1 subtype 2
    vlan_name: VlanName, // IEEE 802.1 subtype 3
    protocol_identity: []const u8, // IEEE 802.1 subtype 4 (the identity octets)
    vid_usage_digest: u32, // IEEE 802.1 subtype 5
    management_vid: u16, // IEEE 802.1 subtype 6
    link_aggregation: LinkAggregation, // IEEE 802.1 subtype 7 and the deprecated 802.3 subtype 3
    pfc: PfcConfig, // IEEE 802.1Qaz subtype 11 (DCBX priority flow control)
    ets_config: EtsConfig, // IEEE 802.1Qaz subtype 9 (DCBX ETS configuration)
    ets_recommendation: EtsRecommendation, // IEEE 802.1Qaz subtype 10 (DCBX ETS recommendation)
    app_priority: AppPriorityTable, // IEEE 802.1Qaz subtype 12 (DCBX application priority)
    evb: Evb, // 802.1Qbg draft OUI 00-13-BF subtype 0
    cisco_poe: CiscoPoe, // OUI 00-01-42 subtype 1
    profinet_delay: ProfinetDelay, // OUI 00-0e-cf subtype 1
    profinet_port_status: ProfinetPortStatus, // subtype 2
    profinet_mrp_port_status: ProfinetMrpPortStatus, // subtype 4
    profinet_chassis_mac: [6]u8, // subtype 5
    profinet_ptcp_status: ProfinetPtcpStatus, // subtype 6
    mac_phy: MacPhy, // IEEE 802.3 subtype 1
    power_via_mdi: PowerViaMdi, // IEEE 802.3 subtype 2
    max_frame_size: u16, // IEEE 802.3 subtype 4
    med_capabilities: MedCapabilities, // TIA subtype 1
    med_network_policy: MedNetworkPolicy, // TIA subtype 2
    med_location: MedLocation, // TIA subtype 3
    med_ext_power: MedExtPower, // TIA subtype 4
    med_inventory: MedInventory, // TIA subtypes 5-11
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
    /// Set by the first error; see `next`.
    failed: bool = false,

    pub fn init(bytes: []const u8) TlvIterator {
        return .{ .buf = bytes };
    }

    /// After the first error the iterator is terminal: `next` returns null
    /// (a consumer loop that does `catch continue` therefore ends).
    pub fn next(it: *TlvIterator) ParseError!?RawTlv {
        if (it.failed) return null;
        return it.nextRaw() catch |err| {
            it.failed = true;
            return err;
        };
    }

    fn nextRaw(it: *TlvIterator) ParseError!?RawTlv {
        if (it.done or it.pos == it.buf.len) return null;
        if (it.pos + 2 > it.buf.len) return ParseError.Truncated;
        const header = std.mem.readInt(u16, it.buf[it.pos..][0..2], .big);
        const t: TlvType = @fromBackingInt(@intCast(@as(u7, @intCast(header >> 9))));
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

pub const ParseOptions = struct {
    /// The three mandatory TLVs (Chassis ID, Port ID, TTL) always have to be
    /// present, in order, and well-formed -- that never changes. This
    /// governs only the *optional* TLVs (System Capabilities, Management
    /// Address) that carry their own internal length/consistency checks.
    ///
    /// `false` (default): a malformed optional TLV aborts the whole parse,
    /// same as a malformed mandatory one. This is correct for anything that
    /// treats a wrong answer as worse than no answer.
    ///
    /// `true`: a malformed optional TLV is skipped -- the LLDPDU is still
    /// returned with every field that *did* parse (including a later,
    /// well-formed repeat of the same optional TLV type). Use this when
    /// losing a neighbour's Chassis ID / Port ID over one cheap switch
    /// botching an unrelated optional TLV is the real loss -- e.g. "which
    /// switch and port am I wired to" topology discovery. `skipped_optionals`
    /// reports how many were dropped, so a caller that cares can tell a
    /// clean neighbour record from a partially-recovered one.
    tolerant_optionals: bool = false,
};

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

    /// Count of optional TLVs skipped under `ParseOptions.tolerant_optionals`
    /// because they were internally malformed. Always 0 in strict mode
    /// (`tolerant_optionals = false`) -- a malformed optional TLV aborts the
    /// parse there instead of being counted. Saturates at 65535 rather than
    /// wrapping past it, so it stays a lower bound even against `raw` input
    /// longer than any real Ethernet frame.
    skipped_optionals: u16 = 0,

    /// The whole TLV stream, for re-iteration (org-specific, extra
    /// management addresses, unknown TLVs).
    raw: []const u8,

    pub fn parse(bytes: []const u8, opts: ParseOptions) ParseError!Lldpdu {
        var it = TlvIterator.init(bytes);

        // The three mandatory TLVs, in order. Never relaxed by `opts` --
        // ordering and presence of these is the whole point of this parser.
        const c = (try it.next()) orelse return ParseError.MissingMandatory;
        if (c.type != .chassis_id or c.value.len < 2) return ParseError.MissingMandatory;
        const p = (try it.next()) orelse return ParseError.MissingMandatory;
        if (p.type != .port_id or p.value.len < 2) return ParseError.MissingMandatory;
        const t = (try it.next()) orelse return ParseError.MissingMandatory;
        if (t.type != .ttl or t.value.len != 2) return ParseError.MissingMandatory;

        var du: Lldpdu = .{
            .chassis_id = .{ .subtype = @fromBackingInt(@intCast(c.value[0])), .value = c.value[1..] },
            .port_id = .{ .subtype = @fromBackingInt(@intCast(p.value[0])), .value = p.value[1..] },
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
                    if (tlv.value.len != 4) {
                        if (opts.tolerant_optionals) {
                            // Saturating, not wrapping: a malformed optional
                            // TLV needs only its 2-byte LLDP header, so
                            // 65536 of them (>=131072 bytes) would wrap a
                            // plain `+= 1` -- a panic in Debug/ReleaseSafe,
                            // a silent wraparound in ReleaseFast, against a
                            // README that promises no unconditional panic.
                            // Not reachable from a real Ethernet frame, but
                            // `raw` is caller-supplied and not bounded by
                            // this parser to frame-sized input.
                            du.skipped_optionals +|= 1;
                            continue;
                        }
                        return ParseError.BadTlvLength;
                    }
                    if (du.capabilities == null) du.capabilities = .{
                        .capabilities = .fromWire(std.mem.readInt(u16, tlv.value[0..2], .big)),
                        .enabled = .fromWire(std.mem.readInt(u16, tlv.value[2..4], .big)),
                    };
                },
                .management_address => if (du.management_address == null) {
                    du.management_address = ManagementAddress.parse(tlv.value) catch |err| {
                        if (opts.tolerant_optionals) {
                            // See the saturating-add note at the
                            // `.system_capabilities` arm above.
                            du.skipped_optionals +|= 1;
                            continue;
                        }
                        return err;
                    };
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
        const header: u16 = (@as(u16, @backingInt(tlv_type)) << 9) | @as(u16, @intCast(value.len));
        std.mem.writeInt(u16, b.buf[b.pos..][0..2], header, .big);
        @memcpy(b.buf[b.pos + 2 ..][0..value.len], value);
        b.pos += 2 + value.len;
    }

    /// Chassis ID with an explicit subtype + value.
    pub fn addChassisId(b: *Builder, subtype: ChassisIdSubtype, value: []const u8) BuildError!void {
        try b.addSubtyped(.chassis_id, @backingInt(subtype), value);
    }

    pub fn addChassisIdMac(b: *Builder, mac: Mac) BuildError!void {
        try b.addChassisId(.mac_address, &mac.octets);
    }

    pub fn addPortId(b: *Builder, subtype: PortIdSubtype, value: []const u8) BuildError!void {
        try b.addSubtyped(.port_id, @backingInt(subtype), value);
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
        // Guard both the OID-length byte (`@intCast` to `u8` below) and the
        // fixed 64-byte scratch buffer itself, matching `addOrgSpecific`'s
        // bounds-check pattern.
        if (opts.oid.len > 255 or 2 + addr.len + 6 + opts.oid.len > scratch.len) return BuildError.ValueTooLong;
        scratch[n] = @intCast(1 + addr.len); // addr string length
        scratch[n + 1] = family;
        @memcpy(scratch[n + 2 ..][0..addr.len], addr);
        n += 2 + addr.len;
        scratch[n] = @backingInt(opts.interface_subtype);
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

    /// LLDP-MED Capabilities (TIA subtype 1) — a MED device sends this first.
    pub fn addMedCapabilities(b: *Builder, capabilities: u16, device_type: MedDeviceType) BuildError!void {
        var v: [3]u8 = undefined;
        std.mem.writeInt(u16, v[0..2], capabilities, .big);
        v[2] = @backingInt(device_type);
        try b.addOrgSpecific(oui_tia, 1, &v);
    }

    /// LLDP-MED Network Policy (TIA subtype 2) — e.g. a switch telling a
    /// phone its voice VLAN.
    pub fn addMedNetworkPolicy(b: *Builder, p: MedNetworkPolicy) BuildError!void {
        const bits: u24 = (@as(u24, @intFromBool(p.unknown_policy)) << 23) |
            (@as(u24, @intFromBool(p.tagged)) << 22) |
            (@as(u24, p.vlan_id) << 9) | (@as(u24, p.l2_priority) << 6) | p.dscp;
        var v: [4]u8 = undefined;
        v[0] = p.application;
        std.mem.writeInt(u24, v[1..4], bits, .big);
        try b.addOrgSpecific(oui_tia, 2, &v);
    }

    /// IEEE 802.3 Power Via MDI (subtype 2); the 802.3at extension is
    /// written when `p.dot3at` is set (the decoder's inverse).
    pub fn addPowerViaMdi(b: *Builder, p: PowerViaMdi) BuildError!void {
        var v: [8]u8 = undefined;
        v[0] = p.mdi_support;
        v[1] = p.pse_power_pair;
        v[2] = p.power_class;
        var n: usize = 3;
        if (p.dot3at) |e| {
            v[3] = e.type_source_priority;
            std.mem.writeInt(u16, v[4..6], e.pd_requested_dw, .big);
            std.mem.writeInt(u16, v[6..8], e.pse_allocated_dw, .big);
            n = 8;
        }
        try b.addOrgSpecific(oui_ieee_8023, 2, v[0..n]);
    }

    /// LLDP-MED Location Identification (TIA subtype 3): format byte plus
    /// the raw LCI (`MedLocation.format` / `.data`).
    pub fn addMedLocation(b: *Builder, format: u8, data: []const u8) BuildError!void {
        var scratch: [max_tlv_len]u8 = undefined;
        if (1 + data.len + 4 > scratch.len) return BuildError.ValueTooLong;
        scratch[0] = format;
        @memcpy(scratch[1..][0..data.len], data);
        try b.addOrgSpecific(oui_tia, 3, scratch[0 .. 1 + data.len]);
    }

    /// LLDP-MED Extended Power-via-MDI (TIA subtype 4).
    pub fn addMedExtPower(b: *Builder, p: MedExtPower) BuildError!void {
        var v: [3]u8 = undefined;
        v[0] = (@as(u8, p.power_type) << 6) | (@as(u8, p.power_source) << 4) | p.priority;
        std.mem.writeInt(u16, v[1..3], p.power_dw, .big);
        try b.addOrgSpecific(oui_tia, 4, &v);
    }

    /// One LLDP-MED inventory string (TIA subtypes 5-11).
    pub fn addMedInventory(b: *Builder, field: MedInventoryField, text: []const u8) BuildError!void {
        try b.addOrgSpecific(oui_tia, @backingInt(field), text);
    }

    /// DCBX ETS Configuration (IEEE 802.1Qaz subtype 9).
    pub fn addEtsConfig(b: *Builder, e: EtsConfig) BuildError!void {
        var v: [21]u8 = undefined;
        e.write(&v);
        try b.addOrgSpecific(oui_ieee_8021, 9, &v);
    }

    /// DCBX ETS Recommendation (IEEE 802.1Qaz subtype 10).
    pub fn addEtsRecommendation(b: *Builder, e: EtsRecommendation) BuildError!void {
        var v: [21]u8 = undefined;
        e.write(&v);
        try b.addOrgSpecific(oui_ieee_8021, 10, &v);
    }

    /// The 802.1Qbg (draft) EVB TLV (`Evb`).
    pub fn addEvb(b: *Builder, e: Evb) BuildError!void {
        var v: [9]u8 = undefined;
        std.mem.writeInt(u16, v[0..2], e.supported, .big);
        std.mem.writeInt(u16, v[2..4], e.enabled, .big);
        std.mem.writeInt(u16, v[4..6], e.supported_vsis, .big);
        std.mem.writeInt(u16, v[6..8], e.configured_vsis, .big);
        v[8] = e.rte_exponent;
        try b.addOrgSpecific(oui_ieee_8021qbg, 0, &v);
    }

    /// Cisco's PoE spare-pair TLV (`CiscoPoe`).
    pub fn addCiscoPoe(b: *Builder, c: CiscoPoe) BuildError!void {
        try b.addOrgSpecific(oui_cisco, 1, &.{c.toOctet()});
    }

    pub fn addProfinetDelay(b: *Builder, d: ProfinetDelay) BuildError!void {
        var v: [20]u8 = undefined;
        inline for (.{ d.rx_local, d.rx_remote, d.tx_local, d.tx_remote, d.cable_local }, 0..) |x, i|
            std.mem.writeInt(u32, v[i * 4 ..][0..4], x, .big);
        try b.addOrgSpecific(oui_profinet, 1, &v);
    }

    pub fn addProfinetPortStatus(b: *Builder, s: ProfinetPortStatus) BuildError!void {
        var v: [4]u8 = undefined;
        std.mem.writeInt(u16, v[0..2], s.class2, .big);
        std.mem.writeInt(u16, v[2..4], s.class3, .big);
        try b.addOrgSpecific(oui_profinet, 2, &v);
    }

    pub fn addProfinetMrpPortStatus(b: *Builder, s: ProfinetMrpPortStatus) BuildError!void {
        var v: [18]u8 = undefined;
        v[0..16].* = s.uuid;
        std.mem.writeInt(u16, v[16..18], s.status, .big);
        try b.addOrgSpecific(oui_profinet, 4, &v);
    }

    pub fn addProfinetChassisMac(b: *Builder, mac: Mac) BuildError!void {
        try b.addOrgSpecific(oui_profinet, 5, &mac.octets);
    }

    pub fn addProfinetPtcpStatus(b: *Builder, s: ProfinetPtcpStatus) BuildError!void {
        var v: [54]u8 = undefined;
        v[0..6].* = s.master_address;
        v[6..22].* = s.subdomain_uuid;
        v[22..38].* = s.ir_data_uuid;
        const word = struct {
            fn f(valid: bool, n: u31) u32 {
                return (@as(u32, @intFromBool(valid)) << 31) | n;
            }
        }.f;
        std.mem.writeInt(u32, v[38..42], word(s.period_valid, s.period_length), .big);
        std.mem.writeInt(u32, v[42..46], word(s.red_period_valid, s.red_period_begin), .big);
        std.mem.writeInt(u32, v[46..50], word(s.orange_period_valid, s.orange_period_begin), .big);
        std.mem.writeInt(u32, v[50..54], word(s.green_period_valid, s.green_period_begin), .big);
        try b.addOrgSpecific(oui_profinet, 6, &v);
    }

    /// LLDP-MED coordinate location (format 1, RFC 3825 / RFC 6225): the
    /// inverse of `MedLocation.coordinate`. A known latitude or longitude
    /// beyond +-90 / +-180 degrees is `error.InvalidValue` (it would decode as
    /// `error.OutOfRange`).
    pub fn addMedCoordinate(b: *Builder, c: Coordinate) BuildError!void {
        if (c.latitudeKnown() and (c.lat > MedLocation.lat_limit or c.lat < -MedLocation.lat_limit)) return BuildError.InvalidValue;
        if (c.longitudeKnown() and (c.lon > MedLocation.lon_limit or c.lon < -MedLocation.lon_limit)) return BuildError.InvalidValue;
        const lat: u34 = @bitCast(c.lat);
        const lon: u34 = @bitCast(c.lon);
        const alt: u30 = @bitCast(c.alt);
        const v: u128 = (@as(u128, c.lat_resolution) << 122) | (@as(u128, lat) << 88) |
            (@as(u128, c.lon_resolution) << 82) | (@as(u128, lon) << 48) |
            (@as(u128, c.altitude_type) << 44) | (@as(u128, c.alt_resolution) << 38) |
            (@as(u128, alt) << 8) | c.datum;
        var data: [16]u8 = undefined;
        std.mem.writeInt(u128, &data, v, .big);
        try b.addMedLocation(1, &data);
    }

    /// LLDP-MED civic address location (format 2, RFC 4776): `what` (0, 1 or
    /// 2), a two-letter capital country code and the elements; an element is
    /// written as CAtype, length, value. The LCI is at most 255 octets.
    pub fn addMedCivic(b: *Builder, what: u8, country: [2]u8, elements: []const CivicElement) BuildError!void {
        if (what > 2) return BuildError.InvalidValue;
        for (country) |ch| if (ch < 'A' or ch > 'Z') return BuildError.InvalidValue;
        var scratch: [max_tlv_len]u8 = undefined;
        scratch[0] = 0; // the LCI length, filled in below
        scratch[1] = what;
        scratch[2..4].* = country;
        var n: usize = 4;
        for (elements) |e| {
            if (e.value.len > 255) return BuildError.InvalidValue;
            if (n + 2 + e.value.len > 256) return BuildError.InvalidValue;
            scratch[n] = e.ca_type;
            scratch[n + 1] = @intCast(e.value.len);
            @memcpy(scratch[n + 2 ..][0..e.value.len], e.value);
            n += 2 + e.value.len;
        }
        scratch[0] = @intCast(n - 1);
        try b.addMedLocation(2, scratch[0..n]);
    }

    /// LLDP-MED ECS ELIN (format 3): the emergency number, 10 to 25 octets.
    pub fn addMedElin(b: *Builder, elin: []const u8) BuildError!void {
        if (elin.len < 10 or elin.len > 25) return BuildError.InvalidValue;
        try b.addMedLocation(3, elin);
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
        const header: u16 = (@as(u16, @backingInt(tlv_type)) << 9) | @as(u16, @intCast(1 + value.len));
        std.mem.writeInt(u16, b.buf[b.pos..][0..2], header, .big);
        b.buf[b.pos + 2] = subtype;
        @memcpy(b.buf[b.pos + 3 ..][0..value.len], value);
        b.pos += 3 + value.len;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const fz = @import("fuzz_test.zig");
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
    const du = try Lldpdu.parse(&kat, .{});

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
    const du = try Lldpdu.parse(bytes, .{});
    try testing.expect(du.chassis_id.mac().?.eql(kat_mac));
    try testing.expectEqual(@as(u16, 120), du.ttl_s);
}

test "LLDP: both component subtypes are text, for chassis and port alike (802.1AB entPhysicalAlias)" {
    // Port ID subtype 2 is reached by the tcpdump oracle; chassis subtype 3
    // is not, so it is pinned here.
    const c: ChassisId = .{ .subtype = .port_component, .value = "slot1" };
    try testing.expectEqualStrings("slot1", c.text().?);
    const p: PortId = .{ .subtype = .port_component, .value = "1/0/5" };
    try testing.expectEqualStrings("1/0/5", p.text().?);
    try testing.expectEqual(@as(?[]const u8, null), (PortId{ .subtype = .mac_address, .value = "abcdef" }).text());
}

test "LLDP: network-address chassis id + IPv6 management address" {
    var buf: [128]u8 = undefined;
    var b = Builder.init(&buf);
    // Chassis ID network-address: family(1=IPv4) || 10.0.0.1
    try b.addChassisId(.network_address, &.{ 1, 10, 0, 0, 1 });
    try b.addPortId(.mac_address, &kat_mac.octets);
    try b.addTtl(30);
    try b.addManagementAddress(.{ .ip = .{ .v6 = @as([15]u8, @splat(0)) ++ [_]u8{1} } });
    try b.addMaxFrameSize(1522);
    const bytes = try b.finish();

    const du = try Lldpdu.parse(bytes, .{});
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

test "LLDP Builder: typed power, location and inventory adders round-trip through the decoder" {
    var buf: [256]u8 = undefined;
    var b = Builder.init(&buf);
    try b.addChassisIdMac(kat_mac);
    try b.addPortIdIfName("e0");
    try b.addTtl(60);
    try b.addPowerViaMdi(.{ .mdi_support = 7, .pse_power_pair = 1, .power_class = 4 });
    try b.addPowerViaMdi(.{ .mdi_support = 7, .pse_power_pair = 2, .power_class = 5, .dot3at = .{
        .type_source_priority = 0x62,
        .pd_requested_dw = 255,
        .pse_allocated_dw = 300,
    } });
    try b.addMedLocation(3, "5551234");
    try b.addMedExtPower(.{ .power_type = 1, .power_source = 1, .priority = 2, .power_dw = 65 });
    try b.addMedInventory(.serial_number, "SN-42");
    const du = try Lldpdu.parse(try b.finish(), .{});
    var it = du.orgIterator();

    const p1 = (try it.next()).?.decode().?.power_via_mdi;
    try testing.expectEqual(@as(u8, 4), p1.power_class);
    try testing.expect(p1.dot3at == null);
    const p2 = (try it.next()).?.decode().?.power_via_mdi;
    try testing.expectEqual(@as(u8, 2), p2.pse_power_pair);
    try testing.expectEqual(@as(u16, 255), p2.dot3at.?.pd_requested_dw);
    try testing.expectEqual(@as(u16, 300), p2.dot3at.?.pse_allocated_dw);
    try testing.expectEqual(@as(u8, 0x62), p2.dot3at.?.type_source_priority);
    const loc = (try it.next()).?.decode().?.med_location;
    try testing.expectEqual(@as(u8, 3), loc.format);
    try testing.expectEqualStrings("5551234", loc.data);
    const ep = (try it.next()).?.decode().?.med_ext_power;
    try testing.expectEqual(@as(u2, 1), ep.power_type);
    try testing.expectEqual(@as(u2, 1), ep.power_source);
    try testing.expectEqual(@as(u4, 2), ep.priority);
    try testing.expectEqual(@as(u16, 65), ep.power_dw);
    const inv = (try it.next()).?.decode().?.med_inventory;
    try testing.expectEqual(MedInventoryField.serial_number, inv.field);
    try testing.expectEqualStrings("SN-42", inv.text);

    // An LCI too long for one TLV is refused, not truncated.
    var big: [max_tlv_len]u8 = undefined;
    try testing.expectError(BuildError.ValueTooLong, b.addMedLocation(3, &big));
}

test "LLDP: an oversized management-address OID is refused, not a scratch-buffer overrun" {
    var buf: [256]u8 = undefined;
    var b = Builder.init(&buf);
    // `scratch` in addManagementAddress is a fixed [64]u8; an IPv6 address
    // consumes 2 + 16 + 6 = 24 of it, leaving 40 for the OID. 41 bytes used
    // to overrun the buffer before the length guard was added.
    const long_oid = @as([41]u8, @splat(7));
    try testing.expectError(BuildError.ValueTooLong, b.addManagementAddress(.{
        .ip = .{ .v6 = @as([15]u8, @splat(0)) ++ [_]u8{1} },
        .oid = &long_oid,
    }));

    // A 40-byte OID (the exact boundary) still fits and round-trips.
    const max_oid = @as([40]u8, @splat(7));
    try b.addManagementAddress(.{
        .ip = .{ .v6 = @as([15]u8, @splat(0)) ++ [_]u8{1} },
        .oid = &max_oid,
    });
}

test "LLDP: unknown optional TLV passes through, never fails parse" {
    var buf: [128]u8 = undefined;
    var b = Builder.init(&buf);
    try b.addChassisIdMac(kat_mac);
    try b.addPortIdIfName("e0");
    try b.addTtl(60);
    try b.addTlv(@fromBackingInt(@intCast(100)), &.{ 0xde, 0xad, 0xbe, 0xef }); // reserved/unknown type
    const bytes = try b.finish();

    const du = try Lldpdu.parse(bytes, .{}); // must not error
    var it = du.tlvIterator();
    var saw_unknown = false;
    while (try it.next()) |tlv| {
        if (@backingInt(tlv.type) == 100) {
            try testing.expectEqualSlices(u8, &.{ 0xde, 0xad, 0xbe, 0xef }, tlv.value);
            saw_unknown = true;
        }
    }
    try testing.expect(saw_unknown);
}

test "LLDP: a repeated optional TLV keeps the FIRST occurrence in the typed field" {
    // The doc comment on `Lldpdu`'s optional fields promises "first
    // occurrence", but nothing exercised a *second* occurrence of any of
    // them — a parser that kept overwriting with the last one instead would
    // decode every KAT/round-trip test above identically (they each carry at
    // most one of each optional TLV) and only misbehave on a device that
    // repeats a TLV, which none of those fixtures do.
    var buf: [256]u8 = undefined;
    var b = Builder.init(&buf);
    try b.addChassisIdMac(kat_mac);
    try b.addPortIdIfName("Gi0/1");
    try b.addTtl(60);
    try b.addPortDescription("first-desc");
    try b.addPortDescription("second-desc");
    try b.addSystemName("first-name");
    try b.addSystemName("second-name");
    try b.addSystemDescription("first-sysdesc");
    try b.addSystemDescription("second-sysdesc");
    try b.addSystemCapabilities(.{ .bridge = true }, .{});
    try b.addSystemCapabilities(.{ .router = true }, .{ .router = true });
    try b.addManagementAddress(.{ .ip = .{ .v4 = .{ 10, 0, 0, 1 } } });
    try b.addManagementAddress(.{ .ip = .{ .v4 = .{ 10, 0, 0, 2 } } });
    const bytes = try b.finish();

    const du = try Lldpdu.parse(bytes, .{});
    try testing.expectEqualStrings("first-desc", du.port_description.?);
    try testing.expectEqualStrings("first-name", du.system_name.?);
    try testing.expectEqualStrings("first-sysdesc", du.system_description.?);
    try testing.expect(du.capabilities.?.capabilities.bridge);
    try testing.expect(!du.capabilities.?.capabilities.router);
    var ipbuf: [netaddr.max_ip_text_len]u8 = undefined;
    try testing.expectEqualStrings("10.0.0.1", netaddr.formatIp(du.management_address.?.ip().?, &ipbuf));

    // Both occurrences are still reachable through the raw/management-address
    // iterators — "first occurrence wins" is a typed-field convenience, not
    // data loss.
    var ma = du.managementAddressIterator();
    const first = (try ma.next()).?;
    const second = (try ma.next()).?;
    try testing.expectEqualStrings("10.0.0.1", netaddr.formatIp(first.ip().?, &ipbuf));
    try testing.expectEqualStrings("10.0.0.2", netaddr.formatIp(second.ip().?, &ipbuf));
    try testing.expectEqual(@as(?ManagementAddress, null), try ma.next());
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
    try testing.expectError(ParseError.MissingMandatory, Lldpdu.parse(try b.finish(), .{}));

    // TLV length overruns the buffer.
    try testing.expectError(ParseError.TruncatedTlv, Lldpdu.parse(&.{ 0x02, 0x07, 0x04 }, .{}));

    // Truncated header (one byte).
    try testing.expectError(ParseError.Truncated, Lldpdu.parse(&.{0x02}, .{}));

    // TTL with the wrong length -- a malformed MANDATORY TLV, so this fails
    // under both settings; `tolerant_optionals` only ever governs optional
    // TLVs, never the mandatory Chassis ID / Port ID / TTL trio or their
    // ordering.
    const bad_ttl = [_]u8{ 0x02, 0x07, 0x04 } ++ kat_mac.octets ++
        [_]u8{ 0x04, 0x03, 0x05 } ++ "e0".* ++
        [_]u8{ 0x06, 0x01, 0x78 } ++ // TTL length 1 (illegal)
        [_]u8{ 0x00, 0x00 };
    try testing.expectError(ParseError.MissingMandatory, Lldpdu.parse(&bad_ttl, .{}));
    try testing.expectError(
        ParseError.MissingMandatory,
        Lldpdu.parse(&bad_ttl, .{ .tolerant_optionals = true }),
    );

    // Management Address with an inconsistent internal length.
    var mbuf: [64]u8 = undefined;
    var mb = Builder.init(&mbuf);
    try mb.addChassisIdMac(kat_mac);
    try mb.addPortIdIfName("e0");
    try mb.addTtl(1);
    try mb.addTlv(.management_address, &.{ 0xff, 0x01, 0xc0 }); // addr-str-len 255
    try testing.expectError(ParseError.BadManagementAddress, Lldpdu.parse(try mb.finish(), .{}));
}

test "LLDP tolerant: a malformed optional System Capabilities TLV is skipped, chassis/port/TTL survive" {
    var buf: [128]u8 = undefined;
    var b = Builder.init(&buf);
    try b.addChassisIdMac(kat_mac);
    try b.addPortIdIfName("Gi0/1");
    try b.addTtl(120);
    // System Capabilities must be exactly 4 bytes; 3 is malformed.
    try b.addTlv(.system_capabilities, &.{ 0x00, 0x14, 0x00 });
    const bytes = try b.finish();

    // Strict (default): the malformed optional aborts the whole parse --
    // this is the finding: a cheap switch botching one optional TLV must
    // not, by default, lose an otherwise-good neighbour record either, so
    // the fix is an opt-in, not a relaxed default.
    try testing.expectError(ParseError.BadTlvLength, Lldpdu.parse(bytes, .{}));

    // Tolerant: the malformed optional is skipped and counted; everything
    // that did parse -- including the mandatory trio -- comes back intact.
    const du = try Lldpdu.parse(bytes, .{ .tolerant_optionals = true });
    try testing.expect(du.chassis_id.mac().?.eql(kat_mac));
    try testing.expectEqualStrings("Gi0/1", du.port_id.text().?);
    try testing.expectEqual(@as(u16, 120), du.ttl_s);
    try testing.expectEqual(@as(?SystemCapabilitiesTlv, null), du.capabilities);
    try testing.expectEqual(@as(u16, 1), du.skipped_optionals);
}

test "LLDP tolerant: an inconsistent Management Address is skipped the same way" {
    var buf: [128]u8 = undefined;
    var b = Builder.init(&buf);
    try b.addChassisIdMac(kat_mac);
    try b.addPortIdIfName("e0");
    try b.addTtl(60);
    try b.addTlv(.management_address, &.{ 0xff, 0x01, 0xc0 }); // addr-str-len 255: BadManagementAddress
    const bytes = try b.finish();

    try testing.expectError(ParseError.BadManagementAddress, Lldpdu.parse(bytes, .{}));

    const du = try Lldpdu.parse(bytes, .{ .tolerant_optionals = true });
    try testing.expect(du.chassis_id.mac().?.eql(kat_mac));
    try testing.expectEqual(@as(?ManagementAddress, null), du.management_address);
    try testing.expectEqual(@as(u16, 1), du.skipped_optionals);
}

test "LLDP tolerant: skipped_optionals saturates at 65535 instead of wrapping" {
    // W5: `skipped_optionals` is a u16 bumped by `+= 1` for every malformed
    // optional TLV skipped. Each such TLV needs only its 2-byte LLDP header
    // (a zero-length System Capabilities TLV), so 65536 of them -- >=131072
    // bytes of `raw` -- wrap a plain `+= 1` past 65535: a reachable panic in
    // Debug/ReleaseSafe, a silent wraparound to near-zero in ReleaseFast.
    // Not reachable from a real 1500-byte Ethernet frame, but `raw` is not
    // bounded to frame size by this parser. `+|= 1` saturates instead: this
    // test pushes 70000 skips (comfortably past the u16 boundary) and
    // requires the exact ceiling, not merely "did not panic" -- a silent
    // wrap to a small number would still make this assertion fail.
    const gpa = testing.allocator;
    const malformed_count: usize = 70_000;
    const buf = try gpa.alloc(u8, 64 + malformed_count * 2);
    defer gpa.free(buf);

    var b = Builder.init(buf);
    try b.addChassisIdMac(kat_mac);
    try b.addPortIdIfName("Gi0/1");
    try b.addTtl(120);
    var i: usize = 0;
    while (i < malformed_count) : (i += 1) {
        // value.len (0) != 4: hits the tolerant-skip path every time.
        try b.addTlv(.system_capabilities, &.{});
    }
    const bytes = try b.finish();

    const du = try Lldpdu.parse(bytes, .{ .tolerant_optionals = true });
    try testing.expectEqual(@as(u16, std.math.maxInt(u16)), du.skipped_optionals);
}

test "LLDP garbage sweep: no panics on random input" {
    var prng = std.Random.DefaultPrng.init(0x4c4c4450); // "LLDP"
    const random = prng.random();
    var buf: [256]u8 = undefined;
    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        const len = random.uintAtMost(usize, buf.len);
        random.bytes(buf[0..len]);
        if (Lldpdu.parse(buf[0..len], .{})) |du| {
            var it = du.tlvIterator();
            while (it.next() catch null) |_| {}
            var org = du.orgIterator();
            while (org.next() catch null) |o| _ = o.decode();
            var ma = du.managementAddressIterator();
            while (ma.next() catch null) |_| {}
        } else |_| {}
    }
}

// ── fuzz: LLDPDU parse off the wire, never panics ───────────────────────────
//
// `Lldpdu.parse` and its three sub-iterators (generic TLV, org-specific,
// management-address) run on raw Ethernet frames from any neighbour on the
// LAN — no authentication at this layer. The manual PRNG sweep above
// predates the `Smith` harness convention this collection standardises on;
// this drives the same boundary through `std.testing.fuzz`.

/// LLDPDUs for `fuzzLldpParse`, in the format `Smith.slice` reads (see
/// `testkit.fuzz`): a little-endian u32 length, then the frame.
///
/// ⭐ Hex (and the golden frame above), not built at run time: an LLDP TLV
/// header is a big-endian 7-bit type and 9-bit length, so these bytes are the
/// same on every host. The `0x02, 0x07` at the start of `kat` is
/// `(1 << 9) | 7` — Chassis ID, 7 octets.
const lldp_seeds = [_][]const u8{
    // The golden LLDPDU: every mandatory TLV, four optionals, one org TLV.
    testkit.fuzz.seed(&kat),
    // The mandatory three and End, nothing else: a legal LLDPDU with every
    // optional null and both iterators empty of anything interesting.
    testkit.fuzz.seedHex("0207" ++ "04001b213c9df8" ++ "0406" ++ "054769302f31" ++ "06020078" ++ "0000"),

    // ⭐ System Capabilities with three octets instead of four. This is the
    // ONE seed on which `tolerant_optionals` changes the answer — strict
    // returns `BadTlvLength`, tolerant returns an LLDPDU with
    // `skipped_optionals == 1`. Without it, passing the option is decoration.
    testkit.fuzz.seedHex("0207" ++ "04001b213c9df8" ++ "0406" ++ "054769302f31" ++ "06020078" ++
        "0e03" ++ "001400" ++ "0a07" ++ "6c61622d737731" ++ "0000"),
    // The same for a Management Address whose internal lengths do not add up.
    testkit.fuzz.seedHex("0207" ++ "04001b213c9df8" ++ "0406" ++ "054769302f31" ++ "06020078" ++
        "1004" ++ "05010203" ++ "0000"),
    // ⭐ `addr_str_len` EQUAL to the value length: the address slice would end
    // one octet past the value. Only the `1 +` in `1 + addr_str_len >
    // value.len` refuses it.
    testkit.fuzz.seedHex("0207" ++ "04001b213c9df8" ++ "0406" ++ "054769302f31" ++ "06020078" ++
        "1005" ++ "0501c0a80a" ++ "0000"),
    // ⭐ The address block is complete but the six octets of interface
    // subtype + number + OID length behind it are not — `pos + 6 > value.len`
    // is the only thing in front of a read past the end.
    testkit.fuzz.seedHex("0207" ++ "04001b213c9df8" ++ "0406" ++ "054769302f31" ++ "06020078" ++
        "1008" ++ "0501c0a80a02" ++ "0200" ++ "0000"),

    // ── the mandatory-TLV gate ─────────────────────────────────────────────
    // Chassis ID and Port ID but no TTL.
    testkit.fuzz.seedHex("0207" ++ "04001b213c9df8" ++ "0406" ++ "054769302f31" ++ "0000"),
    // Port ID first: the ORDER is mandatory, not just the presence.
    testkit.fuzz.seedHex("0406" ++ "054769302f31" ++ "0207" ++ "04001b213c9df8" ++ "06020078" ++ "0000"),
    // A Chassis ID whose value is one octet — subtype and nothing else.
    testkit.fuzz.seedHex("0201" ++ "04" ++ "0406" ++ "054769302f31" ++ "06020078" ++ "0000"),
    // A TTL TLV with three octets instead of two.
    testkit.fuzz.seedHex("0207" ++ "04001b213c9df8" ++ "0406" ++ "054769302f31" ++ "0603000078" ++ "0000"),

    // ── the TLV walker's own bounds ────────────────────────────────────────
    // A TLV declaring 0x1ff octets over a frame that has none of them.
    testkit.fuzz.seedHex("03ff" ++ "04001b21"),
    // One octet where a two-octet TLV header is needed.
    testkit.fuzz.seedHex("02"),

    // ── the iterators, which the typed fields do not reach ─────────────────
    // Two Management Address TLVs (IPv4 then IPv6): the typed field holds
    // only the first, so the iterator is the only way to the second.
    testkit.fuzz.seedHex("0207" ++ "04001b213c9df8" ++ "0406" ++ "054769302f31" ++ "06020078" ++
        "100c" ++ "0501c0a80a02" ++ "0200000001" ++ "00" ++
        "1018" ++ "1102" ++ strRepeat("20", 16) ++ "0200000002" ++ "00" ++ "0000"),
    // Three org-specific TLVs: 802.1 port VLAN, 802.3 MAC/PHY, and an OUI
    // this codec does not know — so `decode()` returns a value, a value and
    // null, in that order.
    testkit.fuzz.seedHex("0207" ++ "04001b213c9df8" ++ "0406" ++ "054769302f31" ++ "06020078" ++
        "fe06" ++ "0080c201000a" ++
        "fe09" ++ "00120f01" ++ "0301000010" ++
        "fe05" ++ "aabbcc01" ++ "ff" ++ "0000"),
    // An org TLV whose value is under the 4-octet OUI+subtype minimum.
    testkit.fuzz.seedHex("0207" ++ "04001b213c9df8" ++ "0406" ++ "054769302f31" ++ "06020078" ++
        "fe03" ++ "0080c2" ++ "0000"),

    // ── LLDP-MED location (2026-11-04): valid, then hostile ───────────────
    // Coordinate LCI (the frame tcpdump read: lat -33.8688, lon 151.2093, 12.5 m).
    testkit.fuzz.seedHex("0207" ++ "04001b213c9df8" ++ "0406" ++ "054769302f31" ++ "06020078" ++
        "fe15" ++ "0012bb0301" ++ "4bbc432ca5492e6b295f1300000c8001" ++ "0000"),
    // Civic LCI: what 2, US, three elements (CA, Pasadena, 380).
    testkit.fuzz.seedHex("0207" ++ "04001b213c9df8" ++ "0406" ++ "054769302f31" ++ "06020078" ++
        "fe1c" ++ "0012bb0302" ++ "1602" ++ "5553" ++ "01024341" ++ "03085061736164656e61" ++ "1303333830" ++ "0000"),
    // ECS ELIN, ten digits.
    testkit.fuzz.seedHex("0207" ++ "04001b213c9df8" ++ "0406" ++ "054769302f31" ++ "06020078" ++
        "fe0f" ++ "0012bb0303" ++ "35353531323334353637" ++ "0000"),
    // Civic whose last element overruns the LCI.
    testkit.fuzz.seedHex("0207" ++ "04001b213c9df8" ++ "0406" ++ "054769302f31" ++ "06020078" ++
        "fe0c" ++ "0012bb0302" ++ "0602" ++ "5553" ++ "010943" ++ "0000"),
    // Civic whose LCI length byte disagrees with the TLV.
    testkit.fuzz.seedHex("0207" ++ "04001b213c9df8" ++ "0406" ++ "054769302f31" ++ "06020078" ++
        "fe09" ++ "0012bb0302" ++ "2002" ++ "5553" ++ "0000"),
    // Coordinate with a reserved latitude resolution (40).
    testkit.fuzz.seedHex("0207" ++ "04001b213c9df8" ++ "0406" ++ "054769302f31" ++ "06020078" ++
        "fe15" ++ "0012bb0301" ++ "a0" ++ strRepeat("00", 15) ++ "0000"),
    // Coordinate with latitude 255.99 degrees (out of range), and one of 15 octets.
    testkit.fuzz.seedHex("0207" ++ "04001b213c9df8" ++ "0406" ++ "054769302f31" ++ "06020078" ++
        "fe15" ++ "0012bb0301" ++ "49ffffffff" ++ strRepeat("00", 11) ++ "0000"),
    testkit.fuzz.seedHex("0207" ++ "04001b213c9df8" ++ "0406" ++ "054769302f31" ++ "06020078" ++
        "fe14" ++ "0012bb0301" ++ strRepeat("00", 15) ++ "0000"),
    // 802.1 link aggregation (capable + aggregated, port 7), VID usage digest, management VID.
    testkit.fuzz.seedHex("0207" ++ "04001b213c9df8" ++ "0406" ++ "054769302f31" ++ "06020078" ++
        "fe09" ++ "0080c207" ++ "0300000007" ++ "fe08" ++ "0080c205" ++ "00000001" ++ "fe06" ++ "0080c2060064" ++ "0000"),

    // DCBX: PFC (willing, capability 8, priority 3), application priority (two entries).
    testkit.fuzz.seedHex("0207" ++ "04001b213c9df8" ++ "0406" ++ "054769302f31" ++ "06020078" ++
        "fe06" ++ "0080c20b" ++ "8808" ++ "fe0b" ++ "0080c20c" ++ "00" ++ "06018d" ++ "230050" ++ "0000"),

    // Nothing at all.
    testkit.fuzz.seed(""),
};

/// What one LLDPDU yielded. Shared by the fuzz target and its corpus guard so
/// the guard drives the SAME walk.
const LldpTally = struct {
    strict: usize = 0,
    tolerant: usize = 0,
    skipped: usize = 0,
    optionals: usize = 0,
    tlvs: usize = 0,
    orgs: usize = 0,
    decoded: usize = 0,
    addresses: usize = 0,
    coordinates: usize = 0,
    civics: usize = 0,
    civic_elements: usize = 0,
    elins: usize = 0,
    location_errors: usize = 0,
    link_aggregations: usize = 0,
    pfcs: usize = 0,
    apps: usize = 0,
};

/// Every location decoder over one (possibly hostile) LCI; counts what got
/// through the decode, so the harness can assert the depth is reached.
fn walkLocation(l: MedLocation, t: *LldpTally) void {
    if (l.coordinate()) |maybe| {
        if (maybe) |c| {
            t.coordinates += 1;
            std.mem.doNotOptimizeAway((c.latitudeDegrees() orelse 0) + (c.longitudeDegrees() orelse 0) + (c.altitudeUnits() orelse 0));
        }
    } else |_| t.location_errors += 1;
    if (l.civic()) |maybe| {
        if (maybe) |cv| {
            t.civics += 1;
            var it = cv.iterator();
            while (it.next() catch null) |e| {
                t.civic_elements += 1;
                std.mem.doNotOptimizeAway(e.value.len);
            }
        }
    } else |_| t.location_errors += 1;
    if (l.elin()) |maybe| {
        if (maybe != null) t.elins += 1;
    } else |_| t.location_errors += 1;
}

fn walkLldp(bytes: []const u8, tolerant: bool) LldpTally {
    var t: LldpTally = .{};
    if (Lldpdu.parse(bytes, .{ .tolerant_optionals = true })) |_| t.tolerant = 1 else |_| {}
    const du = Lldpdu.parse(bytes, .{ .tolerant_optionals = tolerant }) catch return t;
    t.strict = 1;
    t.skipped = du.skipped_optionals;
    inline for (.{
        du.port_description != null,   du.system_name != null,
        du.system_description != null, du.capabilities != null,
        du.management_address != null,
    }) |present| {
        if (present) t.optionals += 1;
    }
    var it = du.tlvIterator();
    while (it.next() catch null) |_| t.tlvs += 1;
    var org = du.orgIterator();
    while (org.next() catch null) |o| {
        t.orgs += 1;
        if (o.decode()) |v| {
            t.decoded += 1;
            if (v == .med_location) walkLocation(v.med_location, &t);
            if (v == .link_aggregation) t.link_aggregations += 1;
            if (v == .pfc) t.pfcs += 1;
            if (v == .app_priority) t.apps += v.app_priority.count();
        }
    }
    var ma = du.managementAddressIterator();
    while (ma.next() catch null) |a| {
        t.addresses += 1;
        std.mem.doNotOptimizeAway(a.ip());
    }
    return t;
}

test "fuzz: LLDPDU parse never panics on arbitrary bytes" {
    try testing.fuzz({}, fz.fuzzScript(fuzzLldpParse, 256), .{ .corpus = &lldp_seeds });
}

fn fuzzLldpParse(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var buf: [256]u8 = undefined;
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
    // length. `bytes` takes `@min(buf.len, in.len)` octets and the ranged draw
    // then finds fewer than the eight it needs and returns the range MINIMUM,
    // so `len` was 0 for every seed and `parse` was handed an EMPTY slice.
    // The empty slice fails at the first mandatory TLV, so the `catch return`
    // one line down took every round and the three iterators — the whole
    // reason this target exists — had NEVER executed.
    //
    // ⛔ Measured 2026-09-07 over the corpus above: **0 of 16 seeds non-empty,
    // 0 LLDPDUs parsed, 0 TLVs walked, 0 org TLVs decoded and 0 management
    // addresses read before; 15 of 16 non-empty (one seed IS the empty
    // frame), 5 parsed strictly, 9 tolerantly (the four that differ are the
    // malformed-optional seeds), 51 TLVs walked, 4 org TLVs of which 3
    // decode, and 3 management addresses, after.**
    const len: usize = src.slice(&buf);
    // ⚠ `tolerant_optionals` travels in the seed's tail. Drawn here it would
    // be `false` forever, and one whole documented branch of this parser —
    // "skip the malformed optional and keep the neighbour record" — would
    // never run. `walkLldp` drives both settings on every seed anyway, so the
    // draw picks which of the two the deeper walk uses.
    const tolerant = src.value(bool);
    tallyLldp(buf[0..len], tolerant);
}

fn tallyLldp(bytes: []const u8, tolerant: bool) void {
    const t = walkLldp(bytes, tolerant);
    std.mem.doNotOptimizeAway(t);
    if (t.strict != 0) fz.mark(.parsed) else fz.mark(.rejected);
    if (t.decoded != 0) fz.mark(.org_decoded);
    if (t.coordinates != 0) fz.mark(.coordinate);
    if (t.civic_elements != 0) fz.mark(.civic_element);
    if (t.elins != 0) fz.mark(.elin);
    if (t.location_errors != 0) fz.mark(.location_error);
    if (t.pfcs != 0) fz.mark(.pfc);
    if (t.apps != 0) fz.mark(.app_priority);
}

test "corpus: every LLDP seed reaches the iterators, and the walked counts are pinned" {
    // ⭐ The measurement, executable rather than written in a comment, over the
    // SAME corpus the harness gets, through the SAME `walkLldp`. `nonempty` is
    // the reach claim and the only check that catches a seed grown past the
    // harness's buffer, which `Smith.slice` reads back as the EMPTY one.
    //
    // ⛔ A parse count is not the guard: an LLDPDU carrying only its three
    // mandatory TLVs parses cleanly with every optional null and every
    // iterator empty, and one seed above is exactly that. `tlvs`, `orgs`,
    // `decoded` and `addresses` count work the empty input cannot do.
    //
    // ⭐ `skipped` is the one that pins the `tolerant_optionals` branch: it can
    // only be non-zero if a seed carried a malformed OPTIONAL TLV *and* the
    // tolerant setting was actually passed. `strict != tolerant` on at least
    // one seed is what makes the option worth drawing at all.
    var nonempty: usize = 0;
    var total: LldpTally = .{};
    for (lldp_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [256]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        const t = walkLldp(buf[0..len], true);
        total.tolerant += t.tolerant;
        total.skipped += t.skipped;
        total.optionals += t.optionals;
        total.tlvs += t.tlvs;
        total.orgs += t.orgs;
        total.decoded += t.decoded;
        total.addresses += t.addresses;
        total.coordinates += t.coordinates;
        total.civics += t.civics;
        total.civic_elements += t.civic_elements;
        total.elins += t.elins;
        total.location_errors += t.location_errors;
        total.link_aggregations += t.link_aggregations;
        total.pfcs += t.pfcs;
        total.apps += t.apps;
        // The same seed under the strict setting, so the two are comparable.
        total.strict += walkLldp(buf[0..len], false).strict;
    }
    try testing.expectEqual(lldp_seeds.len - 1, nonempty); // one seed IS the empty frame
    try testing.expectEqual(@as(usize, 15), total.strict);
    try testing.expectEqual(@as(usize, 19), total.tolerant);
    try testing.expectEqual(@as(usize, 4), total.skipped);
    try testing.expectEqual(@as(usize, 5), total.optionals);
    try testing.expectEqual(@as(usize, 104), total.tlvs);
    try testing.expectEqual(@as(usize, 17), total.orgs);
    try testing.expectEqual(@as(usize, 16), total.decoded);
    try testing.expectEqual(@as(usize, 3), total.addresses);
    // The location decoders: one coordinate, two civics (one with an overrunning element)
    // yielding three elements, one ELIN, four LCIs that are errors (latitude out of range,
    // 15 octets, civic length mismatch), one link aggregation.
    try testing.expectEqual(@as(usize, 2), total.coordinates); // the valid one and the one with a reserved latitude resolution
    try testing.expectEqual(@as(usize, 2), total.civics);
    try testing.expectEqual(@as(usize, 3), total.civic_elements);
    try testing.expectEqual(@as(usize, 1), total.elins);
    try testing.expectEqual(@as(usize, 3), total.location_errors);
    try testing.expectEqual(@as(usize, 1), total.link_aggregations);
    try testing.expectEqual(@as(usize, 1), total.pfcs);
    try testing.expectEqual(@as(usize, 2), total.apps);
}

// ── 2026-10-04: LLDP-MED, 802.3 power, 802.1 PPVID ─────────────────────────

/// An LLDPDU generated for this test (a VoIP phone's advertisement) and
/// decoded by tcpdump 4.99.6 (`tcpdump -vv -r`); every expected value below is
/// what tcpdump printed for it, quoted next to the assertion.
const lldpdu_med = blk: {
    const h = "02070400112233445504090567652d302f302f3706020078fe070080c202060064fe0c00120f020f01045100ff012cfe" ++
        "070012bb01002f03fe080012bb020140c96efe100012bb03020a02435a01055072616861fe070012bb04520041fe0900" ++
        "12bb054857312e30fe090012bb064657322e31fe090012bb075357322e33fe090012bb08534e313233fe080012bb0941" ++
        "636d65fe0a0012bb0a50686f6e6539fe070012bb0b4134320000";
    var out: [h.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, h) catch unreachable;
    break :blk out;
};

test "LLDP-MED, 802.3 power and 802.1 PPVID decode to what tcpdump printed" {
    const du = try Lldpdu.parse(&lldpdu_med, .{});
    var it = du.orgIterator();
    var seen: u32 = 0;
    var inventory: usize = 0;
    while (try it.next()) |o| {
        const v = o.decode() orelse return error.TestUndecodedOrgTlv;
        switch (v) {
            // "port and protocol vlan id (PPVID): 100, flags [supported, enabled] (0x06)"
            .port_protocol_vlan => |p| {
                try testing.expectEqual(@as(u16, 100), p.ppvid);
                try testing.expectEqual(@as(u8, 0x06), p.flags);
                seen |= 1;
            },
            // "MDI power support [PSE, supported, enabled, can be controlled],
            //  power pair signal, power class class3"
            .power_via_mdi => |p| {
                try testing.expectEqual(@as(u8, 0x0f), p.mdi_support);
                try testing.expectEqual(@as(u8, 1), p.pse_power_pair);
                try testing.expectEqual(@as(u8, 4), p.power_class); // class3 = 3 + 1
                // tcpdump does not print the 802.3at extension; the test
                // frame carries 0x51 (type 2 PD / source / priority), 25.5 W
                // requested and 30.0 W allocated (IEEE 802.3at 79.3.2: 0.1 W units).
                const at = p.dot3at.?;
                try testing.expectEqual(@as(u8, 0x51), at.type_source_priority);
                try testing.expectEqual(@as(u16, 255), at.pd_requested_dw);
                try testing.expectEqual(@as(u16, 300), at.pse_allocated_dw);
                seen |= 2;
            },
            // "Media capabilities [LLDP-MED capabilities, network policy,
            //  location identification, extended power via MDI-PSE, Inventory]
            //  (0x002f)", "Device type [endpoint class 3] (0x03)"
            .med_capabilities => |c| {
                try testing.expectEqual(MED_CAP.capabilities | MED_CAP.network_policy | MED_CAP.location |
                    MED_CAP.ext_power_pse | MED_CAP.inventory, c.capabilities);
                try testing.expectEqual(MedDeviceType.endpoint_class_3, c.device_type);
                seen |= 4;
            },
            // "Application type [voice] (0x01), Flags [Tagged]",
            // "Vlan id 100, L2 priority 5, DSCP value 46"
            .med_network_policy => |n| {
                try testing.expectEqual(@as(u8, 1), n.application);
                try testing.expect(n.tagged and !n.unknown_policy);
                try testing.expectEqual(@as(u12, 100), n.vlan_id);
                try testing.expectEqual(@as(u3, 5), n.l2_priority);
                try testing.expectEqual(@as(u6, 46), n.dscp);
                seen |= 8;
            },
            // "Location data format civic address LCI (0x02)"
            .med_location => |l| {
                try testing.expectEqual(@as(u8, 2), l.format);
                try testing.expectEqual(@as(usize, 11), l.data.len);
                seen |= 16;
            },
            // "Power type [PD device], Power source [PSE - primary power
            //  source]", "Power priority [high] (0x02), Power 6.5 Watts"
            .med_ext_power => |e| {
                try testing.expectEqual(@as(u2, 1), e.power_type);
                try testing.expectEqual(@as(u2, 1), e.power_source);
                try testing.expectEqual(@as(u4, 2), e.priority);
                try testing.expectEqual(@as(u16, 65), e.power_dw);
                seen |= 32;
            },
            // "Hardware revision HW1.0" … "Asset ID A42"
            .med_inventory => |inv| {
                const want: []const u8 = switch (inv.field) {
                    .hardware_revision => "HW1.0",
                    .firmware_revision => "FW2.1",
                    .software_revision => "SW2.3",
                    .serial_number => "SN123",
                    .manufacturer => "Acme",
                    .model => "Phone9",
                    .asset_id => "A42",
                };
                try testing.expectEqualStrings(want, inv.text);
                inventory += 1;
            },
            else => return error.TestUnexpectedOrgTlv,
        }
    }
    try testing.expectEqual(@as(u32, 63), seen);
    try testing.expectEqual(@as(usize, 7), inventory);
}

test "LLDP-MED / power TLVs too short to hold their fields stay raw" {
    const short = [_]OrgSpecific{
        .{ .oui = oui_ieee_8021, .subtype = 2, .info = &.{ 6, 0 } },
        .{ .oui = oui_ieee_8023, .subtype = 2, .info = &.{ 0x0f, 1 } },
        .{ .oui = oui_tia, .subtype = 1, .info = &.{ 0, 0x2f } },
        .{ .oui = oui_tia, .subtype = 2, .info = &.{ 1, 0x40, 0xc9 } },
        .{ .oui = oui_tia, .subtype = 3, .info = &.{} },
        .{ .oui = oui_tia, .subtype = 4, .info = &.{ 0x52, 0 } },
        .{ .oui = oui_tia, .subtype = 12, .info = "x" }, // not a MED subtype
    };
    for (short) |o| try testing.expect(o.decode() == null);
    // An 802.3ab power TLV (3 bytes, no 802.3at extension), and one with a
    // partial extension, decode without one.
    const ab = (OrgSpecific{ .oui = oui_ieee_8023, .subtype = 2, .info = &.{ 0x0f, 1, 4 } }).decode().?;
    try testing.expect(ab.power_via_mdi.dot3at == null);
    const partial = (OrgSpecific{ .oui = oui_ieee_8023, .subtype = 2, .info = &.{ 0x0f, 1, 4, 0x51, 0, 255, 1 } }).decode().?;
    try testing.expect(partial.power_via_mdi.dot3at == null);
    // The priority is the whole low nibble (TIA-1057 §10.2.5.2: 4 bits), so a
    // reserved value 15 reads back as 15, not truncated to 3 bits.
    const pr = (OrgSpecific{ .oui = oui_tia, .subtype = 4, .info = &.{ 0x5f, 0, 1 } }).decode().?;
    try testing.expectEqual(@as(u4, 15), pr.med_ext_power.priority);
    // An empty inventory string is a valid (empty) field.
    const inv = (OrgSpecific{ .oui = oui_tia, .subtype = 11, .info = "" }).decode().?;
    try testing.expectEqual(@as(usize, 0), inv.med_inventory.text.len);
}

test "Builder: LLDP-MED capabilities and network policy reproduce the tcpdump-checked bytes" {
    var buf: [64]u8 = undefined;
    var b = Builder.init(&buf);
    try b.addMedCapabilities(0x002f, .endpoint_class_3);
    try b.addMedNetworkPolicy(.{ .application = 1, .unknown_policy = false, .tagged = true, .vlan_id = 100, .l2_priority = 5, .dscp = 46 });
    // The two TLVs as they sit in `lldpdu_med` (offsets 47..56 and 56..66).
    try testing.expectEqualSlices(u8, lldpdu_med[47..66], buf[0..b.pos]);
    // Every policy bit lands where the decoder reads it back.
    var b2 = Builder.init(&buf);
    const p: MedNetworkPolicy = .{ .application = 8, .unknown_policy = true, .tagged = false, .vlan_id = 4095, .l2_priority = 7, .dscp = 63 };
    try b2.addMedNetworkPolicy(p);
    const o = try OrgSpecific.parse(buf[2..b2.pos]);
    try testing.expectEqualDeep(OrgValue{ .med_network_policy = p }, o.decode().?);
}

// ── vendor org TLVs: EVB, Cisco PoE, Profinet (gopacket facts), DCBX ETS, location builders ─

/// The value of the one org TLV a fresh builder wrote.
fn onlyOrg(buf: []const u8, end: usize) !OrgSpecific {
    return OrgSpecific.parse(buf[2..end]);
}

fn hexBytes(comptime h: []const u8) [h.len / 2]u8 {
    var out: [h.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, h) catch unreachable;
    return out;
}

test "EVB, Cisco PoE and Profinet decode to what gopacket v1.7.5 reads (tools/go_orgtlv)" {
    var buf: [128]u8 = undefined;
    // evb {Supported:{STD RR ECP VDP} Enabled:{STD ECP VDP} SupportedVSIs:32 ConfiguredVSIs:16 RTEExponent:17}
    var b = Builder.init(&buf);
    try b.addOrgSpecific(oui_ieee_8021qbg, 0, &hexBytes("00c3008300200010" ++ "11"));
    const evb = (try onlyOrg(&buf, b.pos)).decode().?.evb;
    try testing.expectEqual(EVB_CAP.standard_bridging | EVB_CAP.reflective_relay | EVB_CAP.edge_control_protocol | EVB_CAP.vsi_discovery_protocol, evb.supported);
    try testing.expectEqual(EVB_CAP.standard_bridging | EVB_CAP.edge_control_protocol | EVB_CAP.vsi_discovery_protocol, evb.enabled);
    try testing.expectEqual(@as(u16, 32), evb.supported_vsis);
    try testing.expectEqual(@as(u16, 16), evb.configured_vsis);
    try testing.expectEqual(@as(u8, 17), evb.rte_exponent);
    var b2 = Builder.init(&buf);
    try b2.addEvb(evb);
    try testing.expectEqualDeep(OrgValue{ .evb = evb }, (try onlyOrg(&buf, b2.pos)).decode().?);
    // Under 9 octets gopacket errors; here the TLV stays raw.
    const short = OrgSpecific{ .oui = oui_ieee_8021qbg, .subtype = 0, .info = &hexBytes("00c30083002000") };
    try testing.expectEqual(@as(?OrgValue, null), short.decode());

    // cisco 05 {PSEFourWire PDRequestSparePair}, 0a {PDShared PSESparePair}, 0f all, 00 none.
    const expect = [_]struct { octet: u8, v: CiscoPoe }{
        .{ .octet = 0x05, .v = .{ .pse_four_wire = true, .pd_spare_pair_shared = false, .pd_request_spare_pair = true, .pse_spare_pair_on = false } },
        .{ .octet = 0x0a, .v = .{ .pse_four_wire = false, .pd_spare_pair_shared = true, .pd_request_spare_pair = false, .pse_spare_pair_on = true } },
        .{ .octet = 0x0f, .v = .{ .pse_four_wire = true, .pd_spare_pair_shared = true, .pd_request_spare_pair = true, .pse_spare_pair_on = true } },
        .{ .octet = 0x00, .v = .{ .pse_four_wire = false, .pd_spare_pair_shared = false, .pd_request_spare_pair = false, .pse_spare_pair_on = false } },
    };
    for (expect) |e| {
        var cb = Builder.init(&buf);
        try cb.addOrgSpecific(oui_cisco, 1, &.{e.octet});
        try testing.expectEqualDeep(OrgValue{ .cisco_poe = e.v }, (try onlyOrg(&buf, cb.pos)).decode().?);
        var rb = Builder.init(&buf);
        try rb.addCiscoPoe(e.v);
        try testing.expectEqual(e.octet, buf[2 + 4]); // after the OUI and subtype
    }
    // The high bits of the flag octet are not ours to read.
    const hi = (OrgSpecific{ .oui = oui_cisco, .subtype = 1, .info = &.{0xf1} }).decode().?.cisco_poe;
    try testing.expect(hi.pse_four_wire and !hi.pd_spare_pair_shared and !hi.pd_request_spare_pair and !hi.pse_spare_pair_on);

    // Profinet, the facts of the oracle run.
    const pn = [_]struct { sub: u8, info: []const u8 }{
        .{ .sub = 1, .info = &hexBytes("0000000a0000000b0000000c0000000d0000000e") },
        .{ .sub = 2, .info = &hexBytes("00010002") },
        .{ .sub = 4, .info = &hexBytes("000102030405060708090a0b0c0d0e0f" ++ "8001") },
        .{ .sub = 5, .info = &hexBytes("0a0b0c0d0e0f") },
        .{ .sub = 6, .info = &hexBytes("0a0b0c0d0e0f" ++ "00112233445566778899aabbccddeeff" ++ "ffeeddccbbaa99887766554433221100" ++ "80000064" ++ "00000000" ++ "80000032" ++ "c8000000") },
    };
    for (pn) |e| {
        const v = (OrgSpecific{ .oui = oui_profinet, .subtype = e.sub, .info = e.info }).decode().?;
        // Decode, build with the typed builder, and the TLV is the same bytes.
        var pb = Builder.init(&buf);
        switch (v) {
            .profinet_delay => |d| {
                try testing.expectEqual(ProfinetDelay{ .rx_local = 10, .rx_remote = 11, .tx_local = 12, .tx_remote = 13, .cable_local = 14 }, d);
                try pb.addProfinetDelay(d);
            },
            .profinet_port_status => |d| {
                try testing.expectEqual(ProfinetPortStatus{ .class2 = 1, .class3 = 2 }, d);
                try pb.addProfinetPortStatus(d);
            },
            .profinet_mrp_port_status => |d| {
                try testing.expectEqual(@as(u16, 0x8001), d.status);
                try testing.expectEqualSlices(u8, &hexBytes("000102030405060708090a0b0c0d0e0f"), &d.uuid);
                try pb.addProfinetMrpPortStatus(d);
            },
            .profinet_chassis_mac => |m| {
                try testing.expectEqualSlices(u8, &hexBytes("0a0b0c0d0e0f"), &m);
                try pb.addProfinetChassisMac(.{ .octets = m });
            },
            .profinet_ptcp_status => |d| {
                // period=true/100 red=false/0 orange=true/50 green=true/1207959552
                try testing.expect(d.period_valid and d.period_length == 100);
                try testing.expect(!d.red_period_valid and d.red_period_begin == 0);
                try testing.expect(d.orange_period_valid and d.orange_period_begin == 50);
                try testing.expect(d.green_period_valid and d.green_period_begin == 1207959552);
                try testing.expectEqualSlices(u8, &hexBytes("0a0b0c0d0e0f"), &d.master_address);
                try testing.expectEqualSlices(u8, &hexBytes("ffeeddccbbaa99887766554433221100"), &d.ir_data_uuid);
                try pb.addProfinetPtcpStatus(d);
            },
            else => return error.TestUnexpectedVariant,
        }
        const back = try onlyOrg(&buf, pb.pos);
        try testing.expectEqualSlices(u8, &oui_profinet, &back.oui);
        try testing.expectEqual(e.sub, back.subtype);
        try testing.expectEqualSlices(u8, e.info, back.info);
    }
    // Too short for their subtype: gopacket errors, here the TLV stays raw.
    const zeros: [64]u8 = @splat(0);
    for ([_]struct { u8, usize }{ .{ 1, 19 }, .{ 2, 3 }, .{ 4, 17 }, .{ 5, 5 }, .{ 6, 53 } }) |c| {
        const o = OrgSpecific{ .oui = oui_profinet, .subtype = c[0], .info = zeros[0..c[1]] };
        try testing.expectEqual(@as(?OrgValue, null), o.decode());
    }
    try testing.expectEqual(@as(?OrgValue, null), (OrgSpecific{ .oui = oui_profinet, .subtype = 3, .info = zeros[0..20] }).decode());
}

test "DCBX ETS configuration and recommendation: layout, round trip, short TLVs stay raw (self-derived)" {
    const cfg: EtsConfig = .{
        .willing = true,
        .cbs = false,
        .max_tcs = 3,
        .priority_to_tc = .{ 0, 0, 1, 1, 2, 2, 7, 15 },
        .tc_bandwidth = .{ 50, 30, 20, 0, 0, 0, 0, 0 },
        .tsa = .{ 2, 2, 2, 0, 0, 0, 0, 255 },
    };
    var buf: [64]u8 = undefined;
    var b = Builder.init(&buf);
    try b.addEtsConfig(cfg);
    // header, OUI 00-80-C2, subtype 9; then W|CBS|max TCs, the 4 nibble octets, 8 bandwidths, 8 TSAs.
    const want = hexBytes("fe19" ++ "0080c2" ++ "09" ++ "83" ++ "0011227f" ++ "321e140000000000" ++ "02020200000000ff");
    try testing.expectEqualSlices(u8, want[0..2], buf[0..2]);
    try testing.expectEqualSlices(u8, want[2..], buf[2..b.pos]);
    const back = (try onlyOrg(&buf, b.pos)).decode().?.ets_config;
    try testing.expectEqualDeep(cfg, back);
    try testing.expectEqual(@as(u4, 3), back.trafficClasses());
    // A max TCs field of 0 means 8.
    var eight = cfg;
    eight.max_tcs = 0;
    try testing.expectEqual(@as(u4, 8), eight.trafficClasses());

    const rec: EtsRecommendation = .{ .priority_to_tc = cfg.priority_to_tc, .tc_bandwidth = cfg.tc_bandwidth, .tsa = cfg.tsa };
    var b2 = Builder.init(&buf);
    try b2.addEtsRecommendation(rec);
    const o = try onlyOrg(&buf, b2.pos);
    try testing.expectEqual(@as(u8, 10), o.subtype);
    try testing.expectEqual(@as(u8, 0), o.info[0]); // reserved
    try testing.expectEqualDeep(OrgValue{ .ets_recommendation = rec }, o.decode().?);
    // One octet short of the 21: raw.
    for ([_]u8{ 9, 10 }) |sub| {
        const short = OrgSpecific{ .oui = oui_ieee_8021, .subtype = sub, .info = o.info[0..20] };
        try testing.expectEqual(@as(?OrgValue, null), short.decode());
    }
}

test "Builder: typed location TLVs are the inverse of the decoders" {
    var buf: [128]u8 = undefined;
    // 34.5 N, 118.25 W, 12.5 m, datum 1, resolutions 25/25/16.
    const c: Coordinate = .{
        .lat_resolution = 25,
        .lat = @as(i34, 34) * (1 << 25) + (1 << 24),
        .lon_resolution = 25,
        .lon = -(@as(i34, 118) * (1 << 25) + (1 << 23)),
        .altitude_type = 1,
        .alt_resolution = 16,
        .alt = 12 * 256 + 128,
        .datum = 1,
    };
    var b = Builder.init(&buf);
    try b.addMedCoordinate(c);
    const loc = (try onlyOrg(&buf, b.pos)).decode().?.med_location;
    try testing.expectEqual(@as(u8, 1), loc.format);
    const back = (try loc.coordinate()).?;
    try testing.expectEqualDeep(c, back);
    try testing.expectApproxEqAbs(@as(f64, 34.5), back.latitudeDegrees().?, 1e-9);
    try testing.expectApproxEqAbs(@as(f64, -118.25), back.longitudeDegrees().?, 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 12.5), back.altitudeUnits().?, 1e-9);

    // Civic: what 2 (the client), US, A1 = CA, A3 = Los Angeles.
    var b2 = Builder.init(&buf);
    try b2.addMedCivic(2, "US".*, &.{ .{ .ca_type = 1, .value = "CA" }, .{ .ca_type = 3, .value = "Los Angeles" } });
    const civ = (try (try onlyOrg(&buf, b2.pos)).decode().?.med_location.civic()).?;
    try testing.expectEqual(@as(u8, 2), civ.what);
    try testing.expectEqualStrings("US", &civ.country);
    var it = civ.iterator();
    const e1 = (try it.next()).?;
    try testing.expect(e1.ca_type == 1 and std.mem.eql(u8, e1.value, "CA"));
    const e2 = (try it.next()).?;
    try testing.expect(e2.ca_type == 3 and std.mem.eql(u8, e2.value, "Los Angeles"));
    try testing.expectEqual(@as(?CivicElement, null), try it.next());

    var b3 = Builder.init(&buf);
    try b3.addMedElin("12125551212");
    try testing.expectEqualStrings("12125551212", (try (try onlyOrg(&buf, b3.pos)).decode().?.med_location.elin()).?);

    // What the decoders would refuse is refused here.
    var b4 = Builder.init(&buf);
    var bad = c;
    bad.lat = 91 * (1 << 25);
    try testing.expectError(BuildError.InvalidValue, b4.addMedCoordinate(bad));
    bad = c;
    bad.lon = -181 * (1 << 25);
    try testing.expectError(BuildError.InvalidValue, b4.addMedCoordinate(bad));
    // An unknown (resolution 0) latitude is not range-checked, as on decode.
    bad = c;
    bad.lat_resolution = 0;
    bad.lat = 91 * (1 << 25);
    try b4.addMedCoordinate(bad);
    try testing.expectError(BuildError.InvalidValue, b4.addMedCivic(3, "US".*, &.{}));
    try testing.expectError(BuildError.InvalidValue, b4.addMedCivic(1, "us".*, &.{}));
    const long_value: [256]u8 = @splat('x');
    try testing.expectError(BuildError.InvalidValue, b4.addMedCivic(1, "US".*, &.{.{ .ca_type = 1, .value = &long_value }}));
    try testing.expectError(BuildError.InvalidValue, b4.addMedElin("123456789"));
    try testing.expectError(BuildError.InvalidValue, b4.addMedElin("12345678901234567890123456"));
}

// ── deterministic fuzz driver (2026-10-09) ───────────────────────────────────
// Shared plumbing and the notes on `L2DISCO_FUZZ` are in `fuzz_test.zig`.

fn fuzzLldpMutated(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;

    var buf: [256]u8 = undefined;
    const tolerant = src.value(bool);
    tallyLldp(fz.damaged(S, src, &lldp_seeds, &buf), tolerant);
}

test "fuzz: lldp parse, damaged corpus entries" {
    try testing.fuzz({}, fz.fuzzScript(fuzzLldpMutated, 64), .{});
}

test "fuzz driver: L2DISCO_FUZZ (lldp)" {
    try fz.fuzz_driver.runAll(.{
        .{ fuzzLldpParse, .{ .prefix = "L2DISCO_FUZZ", .name = "l2disco-lldp" } },
        .{ fuzzLldpMutated, .{ .prefix = "L2DISCO_FUZZ", .name = "l2disco-lldp-mutated" } },
    });
}

test "fuzz harness: 400 seeds in every test run, and they get everywhere (lldp)" {
    // The damaged corpus entries must reach the org decoder and every
    // location decoder; the random-bytes run is only required to parse and reject.
    try fz.checkReachEach("l2disco lldp", .{ fuzzLldpParse, fuzzLldpMutated }, .{
        &[_]fz.Label{.rejected},
        &[_]fz.Label{ .rejected, .parsed, .org_decoded, .coordinate, .civic_element, .elin, .location_error, .pfc, .app_priority },
    }, 4000);
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    // One @splat + @bitCast, not a loop: a comptime loop writing into an
    // array var costs O(n^2) in Sema (40 000 bytes: 8.7 s; http's test
    // binary spent ~5 min in Sema on these, 2026-10-24).
    const rep_result = comptime blk: {
        const unit: [s.len]u8 = s[0..s.len].*;
        const grid: [n][s.len]u8 = @splat(unit);
        const flat: [s.len * n]u8 = @bitCast(grid);
        break :blk (flat ++ [_:0]u8{})[0 .. s.len * n :0].*;
    };
    return &rep_result;
}
