// SPDX-License-Identifier: MIT

//! mqtt — pure-Zig MQTT 3.1.1 and 5.0: control-packet codec, client state
//! machine and broker. Pairs with `modbus` for the IoT / industrial
//! (SCADA-sim) work. 5.0 (properties, reason codes, AUTH, session and message
//! expiry, topic aliases, subscription options, shared subscriptions) is per
//! connection — the CONNECT's version — in the codec, the client and the
//! broker alike; see SPEC.md "MQTT 5.0".
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
//! Provenance: clean-room from the OASIS MQTT 3.1.1 and 5.0 specifications;
//! mosquitto/Paho referenced for behavior only, no source consulted or
//! copied.

const std = @import("std");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "MQTT 3.1.1 + 5.0 client and broker — all control packets incl. AUTH and properties, QoS 0/1/2 both ways, sessions with expiry, shared subscriptions, transport-agnostic seam",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    // ⭐ `.linux32` declared 2026-09-11, and it is a claim that was measured,
    // not assumed. The first consumer to cross-compile this module for a
    // 32-bit machine (a store-and-forward proxy, ARMv7 in a router container)
    // found the broker did not build there **at all**: four counters were
    // `std.atomic.Value(u64)`, and a 32-bit target has no 64-bit atomic
    // read-modify-write without libatomic, so `@atomicRmw` on one is a compile
    // error. Every gate in this repo builds native x86-64, so nothing here
    // could have seen it. Declaring the target is what puts
    // `portable-mqtt-linux32` — the module's tests *and* the forcing root that
    // references every non-generic public declaration — between that class of
    // defect and the next consumer.
    .targets = .{ .linux64, .linux32 },
    .platform = .any, // codec + client are portable; TcpTransport uses std.Io.net
    .role = .client, // client + reusable wire codec
    .concurrency = .single_owner, // one owner drives feed/poll/tick
    .model_after = "MQTT 3.1.1 + 5.0 (OASIS) / mosquitto+paho behavior",
    .deps = .{}, // std only
};

/// Control-packet codec (pure wire logic, no I/O).
pub const packet = @import("packet.zig");

/// Topic-name / topic-filter validation and wildcard matching.
pub const topic = @import("topic.zig");

const client_mod = @import("client.zig");
const external_goldens = @import("external_goldens.zig");
const v5_replay = @import("v5_replay.zig");

pub const Client = client_mod.Client;
pub const Transport = client_mod.Transport;
pub const TransportError = client_mod.TransportError;
pub const TcpTransport = client_mod.TcpTransport;
pub const Event = client_mod.Event;
pub const Message = client_mod.Message;
pub const ConnectionState = client_mod.ConnectionState;
pub const max_in_flight = client_mod.max_in_flight;
pub const AliasSlot = client_mod.AliasSlot;
pub const ServerLimits = client_mod.ServerLimits;

/// MQTT 3.1.1 + 5.0 broker (server): connection registry + subscription
/// fan-out + retained store, QoS 0/1/2, clean and persistent sessions. Caller-driven and socket-free like
/// `Client` (reversed direction); `broker.TcpServer` is an optional accept
/// loop over `std.Io.net`. See `broker.zig` for scope + deferred features.
pub const broker = @import("broker.zig");

pub const Broker = broker.Broker;
pub const Connection = broker.Connection;
pub const BrokerConfig = broker.Config;
pub const BrokerTransport = broker.Transport;
pub const BrokerTransportError = broker.TransportError;
pub const TcpServer = broker.TcpServer;

// Optional authentication / ACL seam for the broker (default allow-all).
pub const AuthDecision = broker.AuthDecision;
pub const AuthRequest = broker.AuthRequest;
pub const AclRequest = broker.AclRequest;
pub const Operation = broker.Operation;
pub const PublishVerdict = broker.PublishVerdict;

// Convenience re-exports of the codec types used at the client surface.
pub const Version = packet.Version;
pub const ReasonCode = packet.ReasonCode;
pub const Properties = packet.Properties;
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
    _ = external_goldens;
    _ = v5_replay;
    _ = @import("topic_oracle_test.zig");
}
