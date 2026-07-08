// SPDX-License-Identifier: MIT

//! snmp — pure-Zig SNMP v1 + v2c manager: BER codec, OID handling, message
//! model, and a transport-agnostic client. Fits the network-device
//! management line-up next to `netlink`, `nftables`, and `icmp`.
//!
//! Four layers, all allocation-free:
//!
//! - **BER codec** (`ber`): the ITU-T X.690 subset SNMP needs —
//!   definite-length TLV (short + long form), INTEGER, OCTET STRING, NULL,
//!   OBJECT IDENTIFIER, SEQUENCE, the RFC 2578 application types
//!   (IpAddress, Counter32, Gauge32/Unsigned32, TimeTicks, Opaque,
//!   Counter64) and the v2c varbind exceptions (noSuchObject,
//!   noSuchInstance, endOfMibView). Encoding writes backwards into a caller
//!   buffer, which makes nested definite lengths one-pass.
//! - **OID** (`oid`): bounded-arc OBJECT IDENTIFIER value type —
//!   dotted-decimal parse/format, compare / `startsWith` / `append`; the
//!   wire form (40*x+y first octet, base-128 subidentifiers) lives in the
//!   codec.
//! - **Message model** (`message`): `SEQUENCE { version, community, PDU }`
//!   with every v1 + v2c PDU — GetRequest [0], GetNextRequest [1],
//!   Response [2], SetRequest [3], v1 Trap [4] (decode), GetBulkRequest [5],
//!   InformRequest [6], SNMPv2-Trap [7]. Varbind lists decode lazily
//!   through a typed iterator.
//! - **Client** (`Client`): a manager behind a caller-provided `Transport`
//!   seam (one "send request bytes, receive reply bytes" round-trip), so it
//!   is fully offline-testable: `get` / `getNext` / `getBulk` / `set`,
//!   request-id allocation + matching, error-status surfacing, and a
//!   GetNext `walker` with subtree and loop guards. `UdpTransport` is an
//!   optional `std.Io.net` adapter for the real UDP/161 path — tests never
//!   send.
//!
//! Malformed or hostile agent bytes never panic: all lengths, OID arc
//! counts, and integer widths are bounded, and every decode failure is a
//! typed error.
//!
//! Provenance: clean-room from RFC 1157 (SNMPv1), RFC 1905/3416 (SNMPv2c
//! protocol operations), RFC 2578 (SMI types) and ITU-T X.690 (BER);
//! net-snmp (BSD-like) referenced for behavior only, no source consulted
//! or copied.

const std = @import("std");

pub const meta = .{
    .status = .gap, // no mature pure-Zig SNMP implementation exists
    .platform = .any, // codec + client are portable; UdpTransport uses std.Io.net
    .role = .client, // manager + reusable wire codec
    .concurrency = .single_owner, // Client owns request-id counter + buffers
    .model_after = "SNMP v1 RFC 1157 + v2c RFC 3416/1905; net-snmp behavior",
    .deps = .{}, // std only
};

/// BER (ITU-T X.690) codec — the subset SNMP uses.
pub const ber = @import("ber.zig");

/// OBJECT IDENTIFIER value type.
pub const oid = @import("oid.zig");

/// SNMP message + PDU model (v1 + v2c).
pub const message = @import("message.zig");

/// Trap / notification receiver (manager side): decode + normalize v1 Trap,
/// v2c SNMPv2-Trap and InformRequest datagrams into a `TrapEvent`.
pub const receiver = @import("receiver.zig");

/// SNMPv3 message framing (RFC 3412): the message envelope + ScopedPDU at the
/// plaintext / noAuthNoPriv level. USM security (RFC 3414) builds on top.
pub const v3 = @import("v3.zig");

const client_mod = @import("client.zig");

// Convenience re-exports of the surface types.
pub const Oid = oid.Oid;
pub const Value = ber.Value;
pub const VarBind = message.VarBind;
pub const VarBindList = message.VarBindList;
pub const Version = message.Version;
pub const PduType = message.PduType;
pub const ErrorStatus = message.ErrorStatus;
pub const GenericTrap = message.GenericTrap;
pub const Message = message.Message;
pub const Pdu = message.Pdu;

pub const TrapEvent = receiver.TrapEvent;
pub const TrapKind = receiver.TrapKind;
pub const Dispatcher = receiver.Dispatcher;
pub const parseTrap = receiver.parseTrap;
pub const ackInform = receiver.ackInform;

pub const V3Message = v3.V3Message;
pub const ScopedPdu = v3.ScopedPdu;
pub const MsgFlags = v3.MsgFlags;

pub const Client = client_mod.Client;
pub const Transport = client_mod.Transport;
pub const TransportError = client_mod.TransportError;
pub const UdpTransport = client_mod.UdpTransport;
pub const Walker = client_mod.Walker;

test {
    _ = ber;
    _ = oid;
    _ = message;
    _ = client_mod;
    _ = receiver;
    _ = v3;
}

test "meta is well-formed" {
    try std.testing.expectEqual(.gap, meta.status);
    try std.testing.expectEqual(.any, meta.platform);
    try std.testing.expectEqual(.client, meta.role);
    try std.testing.expectEqual(.single_owner, meta.concurrency);
}
