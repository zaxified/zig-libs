// SPDX-License-Identifier: MIT

//! l2disco — a Layer-2 / neighbor-discovery codec: parse + build for the
//! wire formats a device uses to announce and discover its neighbours.
//! Pure codec — it operates on frame-payload byte buffers only; capture
//! (AF_PACKET, BPF) is a separate concern and never opened here.
//!
//! Four protocols, one MAC helper, all allocation-free on the parse hot
//! path (iterators slice the input buffer; the builders write into a
//! caller buffer):
//!
//! - `lldp` — IEEE 802.1AB LLDPDU: the 7-bit-type / 9-bit-length TLV
//!   stream. Mandatory Chassis ID (MAC / network-address / interface-name
//!   subtypes), Port ID, Time To Live, End-of-LLDPDU; optional Port
//!   Description, System Name/Description, System Capabilities (+ enabled),
//!   Management Address; organizationally-specific (type 127) with IEEE
//!   802.1 (port VLAN, VLAN name) and 802.3 (MAC/PHY, max frame size)
//!   decoding. Unknown optional TLVs pass through raw and never fail parse.
//! - `cdp` — Cisco Discovery Protocol: version/holdtime/checksum header +
//!   type/length TLVs (Device ID, Addresses, Port ID, Capabilities,
//!   Software Version, Platform, VTP domain, Native VLAN, Duplex), with
//!   RFC 1071 checksum compute/verify.
//! - `arp` — RFC 826 ARP: the generic packet plus the typed Ethernet+IPv4
//!   request/reply/gratuitous case.
//! - `dhcp` — RFC 2131 message + RFC 2132 options (message type, requested
//!   IP, server id, lease time, subnet mask, routers, DNS, domain/host
//!   name, parameter request list, client id, End/Pad), magic-cookie
//!   validated.
//! - `mac` — a small 48-bit EUI-48 helper (`aa:bb:cc:dd:ee:ff` parse/format
//!   + broadcast/multicast/local predicates) shared by the codecs.
//!
//! Every length is bounds-checked against the buffer; malformed or
//! truncated input is a typed error, never a panic.
//!
//! Provenance: clean-room from IEEE 802.1AB (LLDP), the publicly documented
//! Cisco CDP frame format (behaviour reference only), RFC 826 (ARP), and
//! RFC 2131 / RFC 2132 (DHCP). No third-party dissector source (Wireshark,
//! lldpd, net-snmp, tcpdump) consulted or copied.

const std = @import("std");

pub const meta = .{
    .platform = .any, // pure codec — no syscalls, no sockets
    .role = .codec, // parse/build frame payloads only
    .concurrency = .reentrant, // no shared state; safe if not shared
    .model_after = "IEEE 802.1AB (LLDP), Cisco CDP, RFC 826 (ARP), RFC 2131/2132 (DHCP)",
    .deps = .{"netaddr"}, // Ip parse/format for management/ARP/DHCP addresses
};

/// LLDP (IEEE 802.1AB) LLDPDU codec.
pub const lldp = @import("lldp.zig");

/// CDP (Cisco Discovery Protocol) frame codec.
pub const cdp = @import("cdp.zig");

/// ARP (RFC 826) packet codec.
pub const arp = @import("arp.zig");

/// DHCP (RFC 2131 / 2132) message + options codec.
pub const dhcp = @import("dhcp.zig");

/// 48-bit MAC (EUI-48) address helper.
pub const mac = @import("mac.zig");

// Convenience re-exports of the most-used surface types.
pub const Mac = mac.Mac;
pub const Lldpdu = lldp.Lldpdu;
pub const CdpFrame = cdp.Frame;
pub const ArpPacket = arp.Packet;
pub const ArpEthIpv4 = arp.EthIpv4;
pub const DhcpMessage = dhcp.Message;

test {
    _ = @import("lldp.zig");
    _ = @import("cdp.zig");
    _ = @import("arp.zig");
    _ = @import("dhcp.zig");
    _ = @import("mac.zig");
}

test "meta is well-formed" {
    try std.testing.expectEqual(.any, meta.platform);
    try std.testing.expectEqual(.codec, meta.role);
    try std.testing.expectEqual(.reentrant, meta.concurrency);
}
