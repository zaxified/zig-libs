# opcua — spec

OPC-UA (IEC 62541 / OPC 10000) binary client **and** server. Usage: see
./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants

- **Layered, each layer independently testable:** `encoding` (OPC 10000-6
  §5.2) — the built-in type codec over a `std.Io.Writer`/`std.Io.Reader`;
  `transport` (OPC 10000-6 §7) — the opc.tcp handshake and MSG/OPN/CLO chunk
  framing over a caller-supplied stream; `services` (OPC 10000-4) — the
  request/response structures and the client-side `Channel`; `security`
  (OPC 10000-7) — the Basic256Sha256 secure channel; `nodestore`
  (OPC 10000-3) — the server's address space; `server` — the server-side
  connection/session/subscription state machine; `root` — the client's
  `SecureChannel`/`Session`/`Subscription`.
- **Every structure is bidirectional.** Each Part-4 message has both an
  `encode…` and a `decode…`, which is what let the server side be built
  without duplicating a single line of codec: the server decodes exactly the
  structures the client encodes and vice versa.
- **Transport-agnostic, no socket ownership, no timer ownership.** The client
  takes a reader/writer pair. The server takes *bytes* and *a timestamp*:
  `Connection.feed(input, out, now_ms)` and `Connection.tick(out, now_ms)`.
  There is no thread, no `std.time`, no socket anywhere in the module — the
  Linux poll loop that drives it lives in the test file
  (`server_interop.zig`) as an example, not in the library.
- **Little-endian, unlike this repo's other binary protocol codecs**
  (`snmp`'s BER and `coap`'s options are big-endian): OPC 10000-6 §5.2.1
  mandates little-endian for every multi-byte scalar. A deliberate
  divergence, not an inconsistency to "fix".
- **Address-space ownership: the store owns every byte it holds.**
  `nodestore.addNode`/`setValue`/`writeAttribute` deep-copy their arguments
  with the store's allocator, allocated exactly the way `encoding.Decoder`
  allocates so `encoding.free*` frees them. `readAttribute` borrows, and is
  documented as valid only until the next mutation; anything that must
  outlive one (a monitored item's last-reported value) deep-copies via
  `dupDataValue`.
- **Per-request arena on the server.** Every inbound message is decoded, and
  its response built, in an arena that dies with the message; only long-lived
  state (sessions, subscriptions, retransmission queues, continuation points)
  uses the server allocator with explicit frees. A malformed request
  therefore cannot leak: the arena is released either way.
- **Error policy:** malformed wire input becomes a typed
  `EncodeError`/`DecodeError`/`TransportError`, never a panic. On the server,
  a malformed *service body* becomes a `ServiceFault` (the connection
  survives), while a malformed *framing/limit* violation becomes an `ERR`
  message and a closed connection — the split OPC 10000-6 §7.1.4 describes.

## Threat model

**Server side: `SecurityMode=None` / `SecurityPolicy#None` only.** The client
half of this module speaks `Basic256Sha256` at Sign and SignAndEncrypt
(`security.zig`, over the `rsa` module). The server half deliberately does
**not**: it implements no asymmetric handshake, no certificate chain
validation, no message signing or encryption, and answers
`BadSecurityPolicyRejected` to any OPN that asks for one. That is stated
plainly rather than half-implemented, because a server that *advertises*
security it cannot enforce is worse than one that advertises none.
Consequences a deployment must accept:

- the wire is exactly as unauthenticated and unencrypted as CoAP-over-plain-
  UDP or SNMPv1/v2c — appropriate on an already-trusted OT/industrial LAN
  segment, never over an untrusted network;
- a `UserNameIdentityToken` therefore travels **in the clear**. `Config.users`
  is empty by default; passwords are compared in constant time so a wrong one
  cannot be found byte-by-byte from response timing, but that only removes
  the timing oracle, not the eavesdropper;
- `AuthenticationToken`s are 32 random bytes from the caller-supplied
  `std.Random` (pass a real CSPRNG — it is a bearer credential) and are
  compared in constant time, but anyone who can read the wire has them.

**Resource bounds are the other half of the threat model.** A server is
reachable by definition, so every unbounded thing is a DoS surface. Bounded
explicitly, each with a test:

| Bound | Where | Violation |
|---|---|---|
| chunk size | negotiated `receive_buffer_size` | `ERR BadTcpMessageTooLarge`, close |
| chunks per message | negotiated `max_chunk_count` | `ERR BadTcpMessageTooLarge`, close |
| reassembled size | negotiated `max_message_size` + the caller's buffer | `ERR BadTcpMessageTooLarge`, close |
| response size | `max_chunk_count` | `ServiceFault BadEncodingLimitsExceeded` |
| sessions / subscriptions / monitored items | `Config` | `BadTooManySessions` / `…Subscriptions` / `…MonitoredItems` |
| queued Publish requests | `Config.max_publish_requests` | `BadTooManyPublishRequests` |
| retained notifications (Republish) | `Config.max_retransmission_queue` | oldest dropped |
| continuation points per session | `Config.max_continuation_points` | `BadNoContinuationPoints` |
| operations per request | `Config.max_operations_per_request` | `BadTooManyOperations` |
| publishing / sampling interval | `Config.min_*_interval_ms` | revised up |
| publishing cycles per `tick` | `max_cycles_per_tick` | deadline resynchronised |
| type-hierarchy walk depth | `nodestore.max_subtype_depth` | walk stops |

Continuation points are **session-scoped**: a handle from another session (or
a guessed one) is `BadContinuationPointInvalid`, never someone else's cursor.
Sessions are **channel-bound**: a request replaying a valid AuthenticationToken
on a different SecureChannel is `BadSecureChannelIdInvalid` (session transfer
between channels is not implemented, which closes that door rather than
opening it half-way).

## Codec-only vs driven

Everything in `encoding` and `services` is a codec; what makes it *driven* is
whether a state machine in `root` (client) or `server` (server) uses it.

- **Driven, both directions:** OpenSecureChannel/CloseSecureChannel,
  GetEndpoints, FindServers, CreateSession, ActivateSession, CloseSession,
  Read, Write, Browse, BrowseNext, Call, CreateSubscription, ModifySubscription,
  SetPublishingMode, DeleteSubscriptions, CreateMonitoredItems,
  DeleteMonitoredItems, Publish, Republish.
- **Driven server-side only** (the client half has no call for them yet):
  TranslateBrowsePathsToNodeIds, ModifyMonitoredItems, SetMonitoringMode.
- **Codec-only** (structures encode/decode, nothing drives them):
  `EventNotificationList`/`EventFieldList` (no server-side event model),
  `StatusChangeNotification` on the client side, `DiagnosticInfo` trees
  (always encoded empty), `SignedSoftwareCertificate`, `X509IdentityToken`
  and `IssuedIdentityToken` type ids.

## Verification

`zig build test-opcua` — 139 tests, Debug and ReleaseFast.

- **Offline:** RFC/spec-shaped round-trips for every built-in type, transport
  framing, secure-channel KATs, address-space unit tests, and an end-to-end
  suite that drives the *server* with the module's own *client* encoder over
  an in-memory pipe (both halves must agree on bytes, not just on structs).
- **Hostile input:** oversize chunk, chunk count over the negotiated maximum,
  abort chunk mid-message, message-size/type violations, reserved NodeId
  encoding byte, ExtensionObject body length overrun, continuation point from
  another session, publish acknowledgement for an unknown sequence number,
  MSG before OPN, wrong TokenId, rejected security policy — each asserted to
  produce a typed error/fault, never a crash or a hang. Plus
  `std.testing.fuzz` feeding arbitrary bytes into `feed`/`tick`.
- **Live (the real oracle), skipping loudly when unavailable:**
  - *their client → our server*: open62541 1.0.5's stock
    `tutorial_client_firststeps` (connect + Read i=2258),
    `client_subscription_loop` (subscription + repeated DataChange
    notifications) and `client` (GetEndpoints on its own connection, username
    login, Browse of the Objects folder, Read/Write of a String NodeId,
    subscription, method Call) run from `docker.io/open62541/open62541` with
    `--network host`; their stdout is the assertion;
  - *our client → their server*: the pre-existing live tests against a real
    `server_ctt`, including Basic256Sha256 Sign and SignAndEncrypt;
  - *our client → our server*: over a real loopback socket, with the server
    driven from a second thread.
- **Goldens** cut from that live traffic (`OPCUA_CAPTURE_DIR=… zig build
  test-opcua` dumps the raw streams): Hello, OpenSecureChannel, GetEndpoints,
  CreateSession, ActivateSession, Read, Browse, CreateSubscription,
  CreateMonitoredItems and an acknowledging Publish request are **captured**
  open62541 bytes; the ACK, OPN response, GetEndpoints/Read/Publish responses
  are **self-derived** (this server's encoder) and labelled as such in the
  source. Each one decodes *and* re-encodes byte-identically. All of them are
  anonymised: loopback addresses only, no certificates, no device identities.
- **Wireshark cross-check.** `tshark` is unavailable here but `rawshark`
  (Wireshark 4.6.4, same dissectors) is: each captured message was framed as
  a pcap-style record and fed through
  `rawshark -r /dev/stdin -d proto:opcua -F <field>`. Result: 198/198 messages
  across the six streams dissected, **0 `_ws.malformed`**, and the dissector
  reads this server's own fields correctly — `opcua.EndpointUrl =
  "opc.tcp://localhost:4840"`, `opcua.ApplicationUri =
  "urn:zig-libs:opcua:interop-server"`, three `opcua.SecurityPolicyUri =
  "…#None"` out of one GetEndpointsResponse, and `opcua.SubscriptionId=1`,
  `opcua.MonitoredItemId=1`, `opcua.ClientHandle=1` plus a real wall-clock
  `opcua.DateTime` out of a PublishResponse.

## Deferred / not implemented

Server side, deliberately out of scope for this part — each is a Bad status,
never a silent partial answer:

- **Security:** no server-side `SecurityPolicy#Basic256Sha256` (or any signed/
  encrypted policy), no certificate validation, no trust list, no
  `X509IdentityToken`/`IssuedIdentityToken`. `BadSecurityPolicyRejected`.
- **NumericRange (index ranges)** on Read/Write: `BadIndexRangeInvalid`.
- **Filters:** no deadband or event filters on monitored items
  (`BadMonitoredItemFilterUnsupported`), and therefore no events, no
  `EventNotificationList` production, no alarms & conditions.
- **Node management:** no AddNodes/AddReferences/DeleteNodes/DeleteReferences
  (`BadServiceUnsupported`) — the address space is built by the host program,
  not over the wire.
- **Other service sets:** no Query, no HistoryRead/HistoryUpdate, no
  RegisterNodes/UnregisterNodes, no RegisterServer, no session transfer
  between channels, no `TransferSubscriptions`, no Views (a non-null ViewId is
  `BadViewIdUnknown`), no `DataEncoding` other than Default Binary, no
  reverse-connect, no discovery server registration, no multi-server
  namespaces (`ExpandedNodeId.server_index` is decoded, never resolved).
- **Address space:** the seeded namespace 0 is the browsable *skeleton*, not
  the full ~2000-node standard nodeset (a generated NodeSet2 artifact); no
  ModellingRules, no `Argument` metadata on Method nodes (a Call's arguments
  are validated by the method implementation itself), no
  `DataTypeDefinition`/`RolePermissions`/`AccessRestrictions` attributes.
- **Interleaving:** one message at a time per connection (a second chunk run
  interleaved with an unfinished one is `BadTcpMessageTypeInvalid`); a
  response is never sent in chunks smaller than the negotiated buffer minus
  its own framing.
- Client side, unchanged from before: no `Variant` `ArrayDimensions`
  reshaping (multi-dimensional arrays stay flat), no channel *renewal* from
  the client (the server answers `RequestType.renew`, the client never sends
  it), no `TranslateBrowsePathsToNodeIds`/`ModifyMonitoredItems`/
  `SetMonitoringMode` helpers.

## Status

`gap · any · both(client + server) · single_owner` + deps: `rsa` — canonical
source is `pub const meta` in src/root.zig.
