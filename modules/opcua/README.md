# opcua

OPC-UA (IEC 62541 / OPC 10000) **binary client** — the industrial-automation
data-access protocol. Scope: `opc.tcp` transport, `SecurityPolicy#None` only
(no signing/encryption in this module — see "Non-goals" below).

This is F1 "core", currently a **pre-scaffold skeleton**: the built-in type
codec (`encoding`, OPC 10000-6 §5.2) and the opc.tcp transport framing
(`transport`, OPC 10000-6 §7) are real types with every codec/I-O body
stubbed `@panic("TODO(agent): ...")`. The service layer on top —
OpenSecureChannel/CloseSecureChannel, CreateSession/ActivateSession/
CloseSession, and Read/Write/Browse/Call — is reserved in `root.zig` as
one-line stubs for a later implementing agent to fill in.

```zig
const opcua = @import("opcua");

// Transport-agnostic: wire Encoder/Decoder/Connection to any std.Io.Reader/
// std.Io.Writer pair — a real TCP connection's buffered stream, or `.fixed`
// over a byte buffer for offline tests.
var w: std.Io.Writer = .fixed(&out_buf);
var enc = opcua.encoding.Encoder.init(&w);
// enc.encodeString("hello"); // currently @panics — not yet implemented

var conn = opcua.transport.Connection.init(&reader, &writer);
// conn.hello(.{ .protocol_version = 0, ..., .endpoint_url = "opc.tcp://host:4840" });
```

- **Role:** client. **Platform:** any (pure codec + a caller-supplied stream;
  no socket of its own). **Deps:** none (std only). **Concurrency:**
  reentrant — `Connection`/`Encoder`/`Decoder` are caller-owned, no shared
  state.

Provenance: clean-room from OPC 10000-6 (OPC UA Binary + opc.tcp) and
OPC 10000-4 (Services); structure references open62541 (MPL-2.0) and
node-opcua (MIT) — behavioral/API-shape only, no source copied. See `NOTICE`.

## Built-in type codec (`opcua.encoding`)

`Encoder`/`Decoder` wrap a `std.Io.Writer`/`std.Io.Reader` (§5.2.1 — every
integer/float is little-endian, unlike this repo's `snmp`/`coap` modules).
Real types, stubbed codec methods:

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
  body), `Variant` (a real tagged union over `VariantScalar`, no array
  support yet — see the TODO in `encoding.zig`), `DataValue`,
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

## Reserved for later parts (`root.zig`)

`SecureChannel` (OpenSecureChannel/CloseSecureChannel, F1-b),
`Session` (CreateSession/ActivateSession/CloseSession, F1-c), and the service
functions `read`/`write`/`browse`/`call` (F1-d) are declared with placeholder
signatures and one-line `@panic` bodies — not yet implemented.

## Non-goals

**No crypto in this module.** `SecurityMode=None` is this module's entire
scope; `SecurityPolicy#Basic256Sha256`-class signing/encryption for the
secure channel is a separate later module (F9), layered on the `rsa` module
already in this repo.

## Scope

Pre-scaffold only: module structure, the full built-in-type + transport API
surface, and reserved later-part signatures. No decode/encode logic, no
socket I/O, no secure channel, no session, no services — every body is
`@panic("TODO(agent): ...")`.

## Verification

`zig build test-opcua` — compiles and runs the placeholder/smoke tests only
(no codec/transport logic exists yet to exercise).
