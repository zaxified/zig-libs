# opcua — spec

OPC-UA (IEC 62541 / OPC 10000) binary client, `SecurityPolicy#None`. Usage: see
./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants

- **Layered like `coap`/`snmp`, each independently testable:** `encoding`
  (OPC 10000-6 §5.2) — the built-in type codec, `Encoder`/`Decoder` over a
  `std.Io.Writer`/`std.Io.Reader`. `transport` (OPC 10000-6 §7) — the opc.tcp
  Hello/Acknowledge handshake and MSG/OPN/CLO chunk framing, over a
  caller-supplied stream. `root` reserves the service layer (`SecureChannel`,
  `Session`, `read`/`write`/`browse`/`call`) for later parts.
- **Transport-agnostic, no socket ownership:** `transport.Connection` takes an
  already-connected `std.Io.Reader`/`std.Io.Writer` pair in its constructor.
  Wire it to a real TCP connection, a `.fixed` buffer pair for offline tests,
  or a TLS-terminated stream — this module never calls `std.Io.net` itself.
- **Little-endian, unlike this repo's other binary protocol codecs**
  (`snmp`'s BER and `coap`'s options are big-endian/network order):
  OPC 10000-6 §5.2.1 mandates little-endian for every multi-byte scalar. This
  is a deliberate divergence from those modules' convention, not an
  inconsistency to "fix".
- **`NodeId`/`Variant` are real tagged unions, not placeholders.** Everything
  else in `encoding.zig` (Guid, QualifiedName, LocalizedText, ExtensionObject,
  DataValue, DiagnosticInfo) is likewise a real Zig type; only the
  `Encoder`/`Decoder` *methods* that move bytes are stubbed
  (`@panic("TODO(agent): ...")`), so the implementing agent fills in
  bit-twiddling, not type design.
- **Error policy (once implemented):** malformed wire input must become a
  typed `EncodeError`/`DecodeError`/`TransportError`, never a panic — matching
  every other codec module in this repo (`coap`, `snmp`). The current
  `@panic` stub bodies are the one sanctioned exception, and only until the
  implementing agent replaces them.

## Threat model / out of scope

**No crypto in this module — `SecurityMode=None` only.** OPC UA's real-world
security (`SecurityPolicy#Basic256Sha256` and friends: asymmetric handshake,
message signing, encryption) is entirely out of scope here and belongs to a
separate later module (F9) that will depend on the `rsa` module already in
this repo. Running this module's eventual implementation against a
`SecurityMode=None` endpoint means the wire is exactly as unauthenticated and
unencrypted as CoAP-over-plain-UDP or SNMPv1/v2c — appropriate only on an
already-trusted network (a private OT/industrial LAN segment), never over an
untrusted one. This mirrors the `coap` module's DTLS-seam framing: the
security layer is a swap-in, not a bolt-on retrofit, once F9 exists.

Also out of scope for F1: the discovery services (FindServers/
GetEndpoints), the subscription/monitored-item model (Publish/
CreateMonitoredItems — OPC UA's pub-style data-change notification, a
substantial service family of its own), and the address-space/type-system
browsing helpers beyond the raw `Browse` service stub.

## Verification

`zig build test-opcua` — currently only the placeholder/smoke tests (type
constructibility, no encode/decode/I-O path exists yet to exercise). Once
implemented, expect the same verification shape as `coap`/`snmp`: RFC/spec
known-answer byte vectors where OPC 10000-6 publishes them, round-trip tests
(`encode` then `decode` reproduces the original value) for every built-in
type, and a golden-chunk test against a captured Hello/Acknowledge exchange
from a real OPC UA server if one becomes available as a test fixture.

## Backlog / deferred

- `Variant` array support (`ValueIsArray`/`ArrayDimensions` encoding-byte
  bits) — scalar-only for F1; see the TODO in `encoding.zig`.
- The full service layer: F1-b (SecureChannel), F1-c (Session), F1-d
  (Read/Write/Browse/Call) are reserved signatures only.
- F9: `SecurityPolicy#Basic256Sha256`-class secure channel crypto, depending
  on the `rsa` module.
- Subscriptions/MonitoredItems (Publish service family) — not scoped into F1
  at all yet.

## Status

`gap · any · client(codec+transport reserved; services stubbed) · reentrant`
+ deps: none (std only) — canonical source is `pub const meta` in
src/root.zig.
