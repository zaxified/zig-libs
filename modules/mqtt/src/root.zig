// SPDX-License-Identifier: MIT

//! mqtt — pure-Zig MQTT 3.1.1 client: control-packet codec + client state
//! machine. Pairs with `modbus` for the IoT / industrial (SCADA-sim) work.
//!
//! Three layers, all allocation-free:
//!
//! - **Codec** (`packet`): encode + decode for all 14 control-packet types
//!   (CONNECT, CONNACK, PUBLISH, PUBACK, PUBREC, PUBREL, PUBCOMP,
//!   SUBSCRIBE, SUBACK, UNSUBSCRIBE, UNSUBACK, PINGREQ, PINGRESP,
//!   DISCONNECT) — fixed header, the remaining-length varint (1–4 bytes
//!   with malformed/overlong guards), 2-byte-length-prefixed UTF-8 strings
//!   (validated, U+0000 rejected), CONNECT options (clean session,
//!   keep-alive, will, credentials), PUBLISH DUP/QoS/RETAIN flags, typed
//!   CONNACK return codes. Decoding is zero-copy and stream-friendly
//!   (`null` = need more bytes); malformed or hostile bytes yield typed
//!   errors, never a panic.
//! - **Topics** (`topic`): `matches` implements the `+` / `#` wildcard
//!   rules including the `$`-topic exclusion; `validateName` /
//!   `validateFilter` enforce the spec's syntax rules.
//! - **Client** (`Client`): a 3.1.1 client behind a caller-provided
//!   `Transport` write seam; incoming bytes go to `feed`, `poll` decodes
//!   packets, drives the QoS 1 (PUBLISH→PUBACK) and QoS 2
//!   (PUBLISH→PUBREC→PUBREL→PUBCOMP) state machines on both send and
//!   receive sides (auto-acks, exactly-once dedup), tracks a bounded
//!   packet-id pool (wrap + in-use guard) and surfaces typed events.
//!   The caller drives the clock: every call takes `now` (ms); `tick`
//!   handles keep-alive PINGREQ and ping timeouts. `TcpTransport` is an
//!   optional `std.Io.net` adapter — tests never dial.
//!
//! Provenance: clean-room from the OASIS MQTT 3.1.1 specification;
//! mosquitto/Paho referenced for behavior only, no source consulted or
//! copied.

const std = @import("std");

pub const meta = .{
    .platform = .any, // codec + client are portable; TcpTransport uses std.Io.net
    .role = .client, // client + reusable wire codec
    .concurrency = .single_owner, // one owner drives feed/poll/tick
    .model_after = "MQTT 3.1.1 (OASIS) / mosquitto+paho behavior",
    .deps = .{}, // std only
};

/// Control-packet codec (pure wire logic, no I/O).
pub const packet = @import("packet.zig");

/// Topic-name / topic-filter validation and wildcard matching.
pub const topic = @import("topic.zig");

const client_mod = @import("client.zig");

pub const Client = client_mod.Client;
pub const Transport = client_mod.Transport;
pub const TransportError = client_mod.TransportError;
pub const TcpTransport = client_mod.TcpTransport;
pub const Event = client_mod.Event;
pub const Message = client_mod.Message;
pub const ConnectionState = client_mod.ConnectionState;
pub const max_in_flight = client_mod.max_in_flight;

/// MQTT 3.1.1 broker (server): connection registry + subscription fan-out +
/// retained store, QoS 0/1, clean session. Caller-driven and socket-free like
/// `Client` (reversed direction); `broker.TcpServer` is an optional accept
/// loop over `std.Io.net`. See `broker.zig` for scope + deferred features.
pub const broker = @import("broker.zig");

pub const Broker = broker.Broker;
pub const Connection = broker.Connection;
pub const BrokerConfig = broker.Config;
pub const BrokerTransport = broker.Transport;
pub const TcpServer = broker.TcpServer;

// Convenience re-exports of the codec types used at the client surface.
pub const QoS = packet.QoS;
pub const ConnectOptions = packet.Connect;
pub const Will = packet.Will;
pub const Subscription = packet.Subscription;
pub const ConnectReturnCode = packet.ConnectReturnCode;

/// Shorthand for `topic.matches`.
pub const topicMatches = topic.matches;

test {
    _ = packet;
    _ = topic;
    _ = client_mod;
    _ = broker;
}
