# opcua

OPC-UA (IEC 62541 / OPC 10000) **binary client** — the industrial-automation
data-access protocol: the OPC UA Binary codec (`encoding`, OPC 10000-6 §5.2),
the opc.tcp transport framing (`transport`, OPC 10000-6 §7), the secure
channel at `SecurityPolicy#None` or `Basic256Sha256` Sign/SignAndEncrypt
(`security`, layered on the sibling `rsa` module), sessions, and the
Read/Write/Browse/Call + subscription services.

**Status: implemented** — codec, transport, secure channel (incl. the
Basic256Sha256 policy), session lifecycle, attribute/method services and
subscriptions (CreateSubscription / MonitoredItems / Publish) are real; each
layer was live-validated against an open62541 server as it was built.

```zig
const opcua = @import("opcua");

// Transport-agnostic: wire Encoder/Decoder/Connection to any std.Io.Reader/
// std.Io.Writer pair — a real TCP connection's buffered stream, or `.fixed`
// over a byte buffer for offline tests.
var w: std.Io.Writer = .fixed(&out_buf);
var enc = opcua.encoding.Encoder.init(&w);
try enc.encodeString("hello");

var conn = opcua.transport.Connection.init(&reader, &writer);
try conn.hello(.{ .protocol_version = 0, .endpoint_url = "opc.tcp://host:4840" });
```

- **Role:** client. **Platform:** any (pure codec + a caller-supplied stream;
  no socket of its own). **Deps:** `rsa` (Basic256Sha256 secure-channel
  crypto in `security.zig`). **Concurrency:**
  reentrant — `Connection`/`Encoder`/`Decoder` are caller-owned, no shared
  state.

Provenance: clean-room from OPC 10000-6 (OPC UA Binary + opc.tcp) and
OPC 10000-4 (Services); structure references open62541 (MPL-2.0) and
node-opcua (MIT) — behavioral/API-shape only, no source copied. See `NOTICE`.

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

## Service layer (`root.zig`)

`SecureChannel` (OpenSecureChannel/CloseSecureChannel — at
`SecurityPolicy#None` or `Basic256Sha256` via `security.zig`), `Session`
(CreateSession/ActivateSession/CloseSession), the service functions
`read`/`write`/`browse`/`call`, and `Subscription` (CreateSubscription /
MonitoredItems / Publish with typed `Notification` decoding) — all
implemented over the transport's chunk assembler.

## Verification

`zig build test-opcua` — the offline suite (codec round-trips, transport
framing, secure-channel crypto vectors cross-checked against open62541's
implementation, service-message goldens). During development every layer was
additionally validated live against a local open62541 server.
