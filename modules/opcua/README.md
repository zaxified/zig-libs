# opcua

OPC-UA (IEC 62541 / OPC 10000) **binary client *and* server** — the
industrial-automation data-access protocol: the OPC UA Binary codec
(`encoding`, OPC 10000-6 §5.2), the opc.tcp transport framing (`transport`,
OPC 10000-6 §7), the secure channel (`security`, layered on the sibling `rsa`
module), and the Part-4 services on both sides of the wire — a client that
drives a real server, and a server (device) a real client can drive.

**Status: implemented, both roles.** Client: codec, transport, secure channel
(incl. `Basic256Sha256` Sign/SignAndEncrypt), session lifecycle,
attribute/method services and subscriptions. Server: the opc.tcp connection
state machine with explicit chunk limits, sessions with anonymous/username
identity, a caller-owned address space (`nodestore`) seeded with the standard
namespace-0 skeleton, Read/Write/Browse/BrowseNext/TranslateBrowsePaths/Call,
and the full subscription + Publish-queue engine. Every layer of both halves
was validated live against `open62541`: our client against their server, and
**their stock client binaries against our server**.

```zig
const opcua = @import("opcua");

// ── client ────────────────────────────────────────────────────────────────
// Transport-agnostic: wire Encoder/Decoder/Connection to any std.Io.Reader/
// std.Io.Writer pair — a real TCP connection's buffered stream, or `.fixed`
// over a byte buffer for offline tests.
var conn = opcua.transport.Connection.init(&reader, &writer);
_ = try conn.hello(.{ .protocol_version = 0, .endpoint_url = "opc.tcp://host:4840", ... });
var channel = try opcua.SecureChannel.open(&conn, gpa, .{});
var session = try opcua.Session.create(&channel, gpa, .{ .endpoint_url = url, ... });
try session.activate(null);
const value = try session.readAttribute(node_id, opcua.services.attribute_id.value);

// ── server ────────────────────────────────────────────────────────────────
// A byte-in/byte-out state machine: no threads, no timers, no sockets.
var store = opcua.nodestore.NodeStore.init(gpa);
defer store.deinit();
try store.addStandardNodes(.{ .start_time = now_datetime });

var srv = opcua.server.Server.init(gpa, &store, .{ .endpoints = &endpoints }, prng.random());
defer srv.deinit();
var conn2 = try opcua.server.Connection.init(&srv, &recv_buf, &msg_buf);

try conn2.feed(bytes_from_the_socket, &out_writer, now_ms); // requests in, responses out
try conn2.tick(&out_writer, now_ms);                        // the clock: publishes, timeouts
```

- **Role:** both (client + server/device). **Platform:** any (pure codec +
  caller-supplied streams; no socket, no timer, no thread of its own).
  **Deps:** `rsa` (Basic256Sha256 secure-channel crypto in `security.zig`,
  client-side only). **Concurrency:** single-owner — one loop owns a `Server`
  and its `Connection`s; nothing is internally synchronized and nothing is
  shared implicitly.

Provenance: clean-room from OPC 10000-6 (OPC UA Binary + opc.tcp),
OPC 10000-4 (Services) and OPC 10000-3 (Address Space Model); structure
references open62541 (MPL-2.0) and node-opcua (MIT) — behavioral/API-shape
only, no source copied. See `NOTICE`.

## Built-in type codec (`opcua.encoding`)

`Encoder`/`Decoder` wrap a `std.Io.Writer`/`std.Io.Reader` (§5.2.1 — every
integer/float is little-endian, unlike this repo's `snmp`/`coap` modules).
Types + codec:

- Scalars: Boolean, SByte/Byte, Int16/UInt16/Int32/UInt32/Int64/UInt64,
  Float/Double, `DateTime` (`i64`, 100ns ticks since 1601-01-01), `StatusCode`
  (`u32`).
- `String`/`ByteString`/`XmlElement` — Int32-length-prefixed, modeled as
  `?[]const u8` (`null` = the wire's length-`-1` null, `&.{}` = present but
  empty).
- `Guid` — the Data1/Data2/Data3/Data4 struct.
- `NodeId` — a real tagged union (`numeric`/`string`/`guid`/`byte_string`);
  the wire's two-byte/four-byte/numeric forms are all the `.numeric` variant
  at different compact sizes. `ExpandedNodeId` adds the optional
  namespace-URI/server-index.
- `QualifiedName`, `LocalizedText`, `ExtensionObject` (type-tagged opaque
  body), `Variant` (a real tagged union — `VariantScalar` scalars plus
  arrays of built-in types), `DataValue`,
  `DiagnosticInfo` (recursive via `?*DiagnosticInfo`).

## opc.tcp transport (`opcua.transport`)

Transport-agnostic: `Connection` takes an already-connected
`std.Io.Reader`/`std.Io.Writer` pair — this module never opens a socket.

- `MessageHeader` (8 bytes: 3-byte type code + chunk-type byte + u32 size),
  `MessageType` (HEL/ACK/ERR/MSG/OPN/CLO), `ChunkType` (F/C/A).
- `Hello`/`Acknowledge`/`Error` — the §7.1.2-7.1.4 handshake bodies.
- `SecureConversationMessageHeader`/`SequenceHeader` — the extended framing
  on MSG/OPN/CLO chunks (§6.7.2/§6.7.3), and `MessageChunkAssembler` to
  reassemble a chunk run into one logical message.
- `Connection.hello`/`.sendChunk`/`.recvChunk`, and the `connect(reader,
  writer, endpoint_url)` convenience wrapper.

## Client service layer (`root.zig`)

`SecureChannel` (OpenSecureChannel/CloseSecureChannel — at
`SecurityPolicy#None` or `Basic256Sha256` via `security.zig`), `Session`
(CreateSession/ActivateSession/CloseSession), the service functions
`read`/`write`/`browse`/`browseNext`/`call`, and `Subscription`
(CreateSubscription / MonitoredItems / Publish with typed `Notification`
decoding) — all over the transport's chunk assembler.

## Server: the address space (`opcua.nodestore`)

A caller-owned node store (OPC 10000-3): `Node`s of every standard node class
(Object, Variable, Method, ObjectType, VariableType, ReferenceType, DataType,
View) with their attributes, and references stored on **both** endpoints so
`Browse` works forward and inverse.

- `addStandardNodes(.{})` seeds the browsable namespace-0 skeleton: the
  Root/Objects/Types/Views folders, the type folders, the whole ReferenceType
  tree (`References`→`HierarchicalReferences`→`HasChild`→`Aggregates`→
  `HasComponent`/`HasProperty`, plus `Organizes`/`HasSubtype`/
  `HasTypeDefinition`), the base Object/Variable types, the built-in
  DataTypes, and the `Server` object with ServerArray/NamespaceArray/
  ServerStatus (+ StartTime/CurrentTime/State/BuildInfo).
- `addFolder`/`addObject`/`addVariable`/`addMethod` build the user half;
  `setValue` is the "the sensor moved" entry point; `refreshServerStatus`
  re-stamps the server's own time-bearing nodes from the caller's clock.
- **Ownership: the store deep-copies everything it is given** (allocated
  exactly the way `encoding.Decoder` allocates, so `encoding.free*` frees it),
  so callers may build an address space out of `comptime` literals.
  `readAttribute` borrows (no allocation, valid until the next mutation);
  `dupDataValue` is there when something must outlive a mutation.
- A Method node carries a `MethodFn` the `Call` service invokes, with the
  server's per-request arena as its allocator.

## Server: the protocol (`opcua.server`)

```zig
try conn.feed(input_bytes, out, now_ms); // whatever arrived on the socket
try conn.tick(out, now_ms);              // whatever the clock made due
```

Two entry points, both pure: **time is a parameter, not a dependency**, and
the module owns no socket, timer or thread. That is what lets the same code
serve one real TCP client, an in-memory test pipe, or a simulated fleet of
devices sharing one event loop.

- **Connection layer:** HEL/ACK with real limit negotiation (buffer sizes,
  message size, chunk count — the negotiated values then bound everything),
  OPN/CLO, and multi-chunk send/receive with `C`/`F`/`A` chunk types. Every
  limit violation (oversize chunk, too many chunks, oversize reassembly,
  wrong message type, unknown channel/token) writes an `ERR` (§7.1.4) and
  closes; an abort chunk discards the partial message and the connection
  carries on.
- **Sessions:** CreateSession/ActivateSession/CloseSession with random
  32-byte AuthenticationTokens, anonymous **and** username identity tokens
  (constant-time password comparison), session timeouts driven by the
  injected clock, and GetEndpoints/FindServers answered from the configured
  endpoint list.
- **Services:** Read, Write (with StatusCode/SourceTimestamp/ServerTimestamp
  handling and the right `BadNodeIdUnknown`/`BadAttributeIdInvalid`/
  `BadNotWritable`/`BadTypeMismatch` failures), Browse + BrowseNext with
  session-scoped continuation points, TranslateBrowsePathsToNodeIds, and Call.
- **Subscriptions:** CreateSubscription/ModifySubscription/SetPublishingMode/
  DeleteSubscriptions, CreateMonitoredItems/ModifyMonitoredItems/
  SetMonitoringMode/DeleteMonitoredItems, and the **publish request queue** —
  requests park until a data change or the keep-alive count expires, with
  sequence numbers, piggy-backed acknowledgements and Republish, all as a
  time-injected state machine the caller drives.
- **Config** (`server.Config`) is where the DoS bounds live: sessions,
  subscriptions per session, monitored items, queued publish requests,
  continuation points, operations per request, and the fastest sampling /
  publishing intervals a client may be granted.

**Security: the server side is `SecurityPolicy#None` only.** The client half
also speaks `Basic256Sha256` Sign/SignAndEncrypt; the server half implements
no asymmetric handshake, no certificate validation and no message
signing/encryption, and answers `BadSecurityPolicyRejected` to any OPN asking
for one. Said plainly rather than half-implemented — see SPEC.md.

## Verification

`zig build test-opcua` — 139 tests, green in Debug and ReleaseFast:

- Offline: codec round-trips, transport framing, secure-channel crypto
  vectors, service-message goldens, address-space unit tests, and the whole
  server driven **by this module's own client half** over an in-memory pipe.
- Hostile input + `std.testing.fuzz` on the server: oversize chunks, chunk
  counts over the negotiated maximum, abort chunks mid-message, malformed
  NodeIds/ExtensionObjects, foreign continuation points, publish
  acknowledgements for unknown sequence numbers — all typed errors or
  ServiceFaults, never a crash or a hang.
- Live (skips loudly if `podman`/the image/the port is unavailable):
  **open62541's stock `tutorial_client_firststeps`, `client_subscription_loop`
  and `client` binaries driving this server** (browse, read, write, subscribe,
  call, username login), this module's client driving a real open62541 server,
  and this module's client driving this server over a loopback socket.
- Goldens captured from that live traffic, each decoding *and* re-encoding
  byte-identically, with the self-derived ones labelled as such.
