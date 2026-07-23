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

**Both halves speak `SecurityPolicy#Basic256Sha256` at Sign and
SignAndEncrypt** (`security.zig`, over the `rsa` module). The server side is
opt-in: `Config.security = null` (the default) keeps it `#None`-only, with
every byte on the wire identical to the pre-security server; setting it to a
`SecurityConfig` (an RSA key pair + application certificate, plus a trust
policy) turns on the whole thing — asymmetric OpenSecureChannel, P-SHA256 key
derivation, per-chunk symmetric sign/encrypt, SecurityToken renewal with an
overlap window, the CreateSession/ActivateSession signature exchange and
RSA-OAEP-encrypted `UserNameIdentityToken`s.

**What security is enforced.**

| Property | Mechanism | Failure |
|---|---|---|
| the peer holds the key it presents | RSA-PKCS1v1.5/SHA-256 signature over the whole OPN message | `BadSecurityChecksFailed` |
| the OPN was meant for *us* | `ReceiverCertificateThumbprint` == SHA-1 of our certificate, constant-time | `BadCertificateInvalid` |
| the peer certificate is well-formed and in date | `std.crypto.Certificate` behind a bounds-checked DER pre-walk + `notBefore`/`notAfter` vs the injected wall clock | `BadCertificateInvalid` / `BadCertificateTimeInvalid` |
| the peer certificate is *trusted* | caller-supplied `CertificatePolicy.check` | whatever the policy returns |
| only advertised modes are usable | the (policy, mode) pair must appear in `Config.endpoints` | `BadSecurityModeRejected` |
| the nonce carries full entropy | `ClientNonce.len == 32` (the policy's key length) | `BadNonceInvalid` |
| every chunk is authentic | HMAC-SHA256 over the plaintext incl. the MessageHeader; AES-256-CBC under it at SignAndEncrypt | `BadSecurityChecksFailed` |
| a token cannot outlive its lease | `now_ms - created > RevisedLifetime` | `BadSecureChannelTokenUnknown` |
| a renewal does not cut off in-flight messages | the previous token stays valid for `token_renewal_overlap_ms`, capped at its own expiry | `BadSecureChannelTokenUnknown` past the window |
| the channel and the session belong together | `ClientSignature` over serverCertificate ‖ serverNonce, verified against the session's `ClientCertificate` | `BadApplicationSignatureInvalid` |
| the session cannot move channels | session is channel-bound; no transfer is implemented | `BadSecureChannelIdInvalid` |
| the client can authenticate *us* | `ServerSignature` over clientCertificate ‖ clientNonce | client-side check |
| a password is not readable or replayable | RSA-OAEP over `UInt32 len ‖ password ‖ serverNonce`, nonce compared constant-time | `BadIdentityTokenInvalid` |
| a policy cannot be downgraded | a plaintext password against a non-`#None` `UserTokenPolicy` is refused | `BadIdentityTokenInvalid` |

Every secret-dependent comparison — thumbprints, nonces, passwords,
authentication tokens, HMAC tags — goes through
`std.crypto.timing_safe` (`security.constantTimeEql`, built on
`timing_safe.compare`, or `timing_safe.eql` for fixed-size arrays). There is
no `std.mem.eql` on a secret anywhere in the security path.

**What is *not* enforced, and must be understood before deploying.**

- **No trust store, no chain walk, no revocation.** The module validates a
  certificate's structure and validity period and then asks
  `SecurityConfig.certificate_policy`; with `certificate_policy = null` it
  accepts any structurally valid, in-date certificate, self-signed included.
  That authenticates the *channel* (the peer proved possession of the key it
  showed) but authenticates no *identity*. A real deployment wires the policy
  to its trust list — e.g. the sibling `x509` module's `verifyChain` against
  the DER files in the server's PKI directory. CRL/OCSP is likewise the
  policy's business. This is a deliberate seam, not an oversight: an OPC UA
  trust list is a deployment artifact, and a library that invented one would
  be wrong everywhere.
- **No `ApplicationUri`-vs-SAN check** (OPC 10000-6 §6.2.3). open62541's
  server does this and answers `BadCertificateUriInvalid`; this one does not.
- **Certificate-time checks are skipped when `Server.wall_clock_epoch == 0`**
  — the caller injected no wall clock, so the server's time base is
  1601-01-01 and there is nothing honest to compare `notBefore`/`notAfter`
  against. Inject a real epoch in production.
- **`SecurityPolicy#None` is still offered** by any endpoint list that
  includes a None endpoint, and at `#None` everything below is true instead:

  - the wire is exactly as unauthenticated and unencrypted as CoAP-over-plain-
    UDP or SNMPv1/v2c — appropriate on an already-trusted OT/industrial LAN
    segment, never over an untrusted network;
  - a `UserNameIdentityToken` travels **in the clear** unless the endpoint
    offers the encrypted policy (`noneEndpointWithEncryptedUserTokens`).
    `Config.users` is empty by default; passwords are compared in constant
    time so a wrong one cannot be found byte-by-byte from response timing, but
    that only removes the timing oracle, not the eavesdropper;
  - `AuthenticationToken`s are 32 random bytes from the caller-supplied
    `std.Random` (pass a real CSPRNG — it is a bearer credential) and are
    compared in constant time, but anyone who can read the wire has them.

- **`Connection.deinit` must be called** on a secured connection: it frees the
  peer certificate copy and `secureZero`s both key sets. It is a no-op on a
  `#None` connection, which is why the callers that predate the security layer
  are still correct.

**Hostile DER is a first-class input.** `std.crypto.Certificate`'s reader
indexes without bounds checks and computes element ends without clamping, so
`security.certificatePublicKey`/`certificateValidity` put a recursive DER
well-formedness walk plus a zero-padded scratch copy in front of it. A
truncated, mutated or entirely fabricated certificate is
`error.InvalidCertificate`; the tests sweep every prefix and every
single-byte mutation of a real certificate and fuzz arbitrary bytes through
both entry points.

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

- **Driven, both directions, at `#None` *and* `Basic256Sha256`
  Sign/SignAndEncrypt:** OpenSecureChannel/CloseSecureChannel,
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
  and `IssuedIdentityToken` type ids, `ActivateSessionRequest.
  UserTokenSignature` (decoded, never required — it only matters for the
  X509/Issued tokens, which are not implemented), and
  `SecurityPolicy.aes256_sha256_rsapss` (an enum value + `uri()` only).

## Verification

`zig build test-opcua` — 164 tests, Debug and ReleaseFast.

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
- **Hostile security input** (all asserted to produce a specific `Bad…`
  status, and to close the channel rather than answer politely): a flipped bit
  in the chunk-type byte / SecureChannelId / ciphertext, a chunk sealed with
  the wrong keys, a correctly-MAC'd chunk with a `PaddingSize` pointing past
  the message, an expired SecurityToken, the previous token used past its
  renewal overlap, an OPN addressed to another server's certificate, an OPN
  with a wrong-length nonce, an unadvertised SecurityMode, a certificate the
  trust policy rejects, a certificate outside its validity window, an absent /
  stale-nonce / foreign-key `ClientSignature`, a `CreateSession` presenting a
  certificate other than the channel's, a session replayed on a second
  channel, a replayed encrypted password, and a plaintext password against an
  encrypted `UserTokenPolicy`. Certificate parsing additionally gets every
  prefix of a real certificate, every single-byte mutation of one, hand-built
  malformed DER, and `std.testing.fuzz`.
- **Live (the real oracle), skipping loudly when unavailable:**
  - *their client → our server*: open62541 1.0.5's stock
    `tutorial_client_firststeps` (connect + Read i=2258),
    `client_subscription_loop` (subscription + repeated DataChange
    notifications) and `client` (GetEndpoints on its own connection, username
    login, Browse of the Objects folder, Read/Write of a String NodeId,
    subscription, method Call) run from `docker.io/open62541/open62541` with
    `--network host`; their stdout is the assertion;
  - *their client → our server, secured*: Python **`asyncua` 2.0.1** (LGPL-3.0,
    used as a black box — a stock interpreter running a driver script, its
    stdout is the assertion) generates its own throwaway RSA-2048 certificate
    and connects at **Basic256Sha256 / SignAndEncrypt**, then browses the
    Objects folder, reads and writes `ns=1;s=the.answer`, calls a method and
    receives subscription notifications; it reconnects at **Sign** with a
    Basic256Sha256-encrypted `UserNameIdentityToken`; and it runs a third
    connection with a 4 s SecurityToken while reading every 500 ms for 10 s,
    which forces real mid-stream renewals across the overlap window. Plus
    open62541's stock `client_encryption`, which picks our SignAndEncrypt
    endpoint out of `GetEndpoints` on its own;
  - *our client → their server*: the pre-existing live tests against a real
    `server_ctt`, including Basic256Sha256 Sign and SignAndEncrypt;
  - *our client → our server*: over a real loopback socket, with the server
    driven from a second thread.
- **Basic256Sha256 goldens** — all **self-derived** and labelled so, because
  no published OPC UA vector exists for a secured chunk and a captured one
  would have to embed a real peer's certificate: a full asymmetric
  `OpenSecureChannel` message (791 bytes, from a fixed key seed and a fixed
  OAEP seed, so the whole stack under it — `rsa.generate`,
  `rsa.selfSignedCert`, RSA-OAEP, RSA-PKCS1v1.5 — is pinned byte-for-byte) and
  one MSG chunk at each of Sign and SignAndEncrypt. Each is re-encoded and
  re-opened identically. **Key derivation KAT:** `deriveKeys` over two fixed
  32-byte nonces against expected bytes computed by an *independent* Python
  implementation of RFC 5246 §5's P_hash with SHA-256 (OPC 10000-6 §6.7.5's
  construction); `pSha256` itself is separately anchored by the published
  TLS-1.2 PRF/SHA-256 vector, and the *layout* (which slice is which key, and
  which nonce is secret vs seed per direction) is cross-checked by the live
  interop — a real asyncua/open62541 client cannot exchange one signed chunk
  with this server if any of the six outputs is wrong or swapped.
- **`#None` goldens** cut from live traffic (`OPCUA_CAPTURE_DIR=… zig build
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

- **Security policies other than `#None` and `Basic256Sha256`:** no
  `Basic128Rsa15`, no `Basic256` (both deprecated), no `Aes128Sha256RsaOaep`,
  no `Aes256Sha256RsaPss` (an enum value + URI only). Any OPN naming one is
  `BadSecurityPolicyRejected`.
- **Identity tokens:** no `X509IdentityToken`, no `IssuedIdentityToken`
  (`BadIdentityTokenInvalid`) — and therefore no `UserTokenSignature`
  verification, which is what those tokens need.
- **PKI:** no trust store, no chain building, no CRL/OCSP, no
  `ApplicationUri`-vs-SAN matching — see the threat model; the accept/reject
  verdict is the caller's `CertificatePolicy`.
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
