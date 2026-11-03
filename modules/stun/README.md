# stun

Pure-Zig **STUN client** (Session Traversal Utilities for NAT, RFC 8489, née
RFC 5389): a transport-agnostic codec that builds/parses/verifies STUN Binding
messages so a host behind a NAT can learn its public "reflexive" transport
address. Sits alongside the rest of the `netaddr`-based network family.

- No mature pure-Zig STUN library to adopt.
- **Platform:** any (the core is pure computation over caller buffers; only the
  optional `query` helper touches `std.Io.net`).
- **Role:** codec (no I/O in the core).
- **Model after:** RFC 8489 STUN; attribute TLV (de)serialization structure
  modelled after Corendos/ztun (MIT); RFC 5769 test vectors as the oracle.
- **Depends on:** `netaddr` (XOR-MAPPED-ADDRESS decodes to a `netaddr.Ip` + port).

## Scope

- **Header** — 16-bit type (2-bit class + 12-bit method interleaved per §5),
  16-bit length, the magic cookie `0x2112A442`, the 96-bit transaction id.
  `encodeType` / `decodeClass` / `decodeMethod`; Binding is method `0x001`.
- **`Builder`** — writes a message into a caller buffer: `init`, `addAttribute`
  (generic TLV with 4-byte padding), `addSoftware`, `addMappedAddress`
  (plain **or** XOR), `addMessageIntegrity`, `addFingerprint`, `finish`.
  `bindingRequest(txid, out)` is the one-liner for a bare Binding request.
  Also `addErrorCode`, `addUnknownAttributes`, `addUsername`/`addRealm`/
  `addNonce`; `Builder.pad` picks the padding byte (RFC 5769's samples use 0x20).
- **`Message` / `decode`** — validates the header, cookie, and 4-byte length
  alignment, then exposes an `AttributeIterator`, `find`, and decoders:
  - **XOR-MAPPED-ADDRESS** (`0x0020`) and plain **MAPPED-ADDRESS** (`0x0001`)
    → `AddressPort` (`netaddr.Ip` + port); `mappedAddress` prefers the XOR form.
  - **FINGERPRINT** (`0x8028`) — CRC-32 ⊕ `0x5354554E`, `verifyFingerprint`.
  - **MESSAGE-INTEGRITY** (`0x0008`) — HMAC-SHA1-20 over the message with the
    length field adjusted to include the attribute, `verifyMessageIntegrity`
    (constant-time compare via `std.crypto.timing_safe.eql`).
  - **ERROR-CODE** (`0x0009`) → `{ code = class*100 + number, reason }`.
- **`bindingResponse(request, from, out, opts)`** — the server side (RFC 8489
  §6.3): a success response with XOR-MAPPED-ADDRESS = `from` (optionally
  SOFTWARE, short-term MESSAGE-INTEGRITY, FINGERPRINT), or the error response
  the request earns: 420 + UNKNOWN-ATTRIBUTES for comprehension-required
  attributes it does not understand (declare ICE's with `known_attributes`),
  400/401 for missing/failing credentials. It reproduces RFC 5769 §2.2/§2.3
  byte for byte from the §2.1 request.
- **`longTermKey(out, user, realm, password)`** — the RFC 8489 §9.2 MD5 key (into `out: *[16]u8`) for
  long-term credentials (inputs already OpaqueString-prepared; ASCII needs
  nothing). Verifies RFC 5769 §2.4's sample request.
- **`parseUri`** — `stun:`/`stuns:` (RFC 7064) and `turn:`/`turns:` with
  `?transport=` (RFC 7065), default ports 3478/5349.
- **RFC 5780 / ICE / TURN attributes** — `AttributeType` names them; `Builder.addAddress` /
  `Message.address` (any address-valued type, XOR for exactly the three XOR types),
  `otherAddress` / `responseOrigin` / `alternateServer`, `addUint32` / `uint32`,
  `addChangeRequest` / `changeRequest`.
- **MESSAGE-INTEGRITY-SHA256** (RFC 8489 §14.6) — `Builder.addMessageIntegritySha256(key, tag_len)`
  (16..32 bytes, multiple of 4) and `Message.verifyMessageIntegritySha256(key)`; `bindingResponse`
  takes `integrity_key_sha256` (alone or with the SHA-1 key). Also `longTermKeySha256`, `userhash`
  / `Builder.addUserhash` / `Message.userhash`, and `PASSWORD-ALGORITHM(S)`
  (`addPasswordAlgorithm(s)`, `passwordAlgorithm`, `passwordAlgorithms` iterator).
- **`looksLikeStun`** (RFC 7983 demultiplexing) and **`randomTransactionId(io)`**
  (`std.Io.randomSecure`, fails closed).
- **`query`** (optional) — sends a Binding request over `std.Io.net` UDP and
  returns the reflexive address; a convenience only, the pure codec is the real
  interface. Retransmits per RFC 8489 §6.2.1 (`QueryOptions.rto_ms` 500 ms
  doubling, `max_requests` 7, then `last_wait_factor` × RTO — `Schedule`
  reproduces the RFC's 0…31500 ms / 39500 ms example); `timeout_ms` caps the
  whole exchange. A datagram for another transaction or not STUN at all is
  discarded and the wait continues; if only such strays came, the give-up error
  says so (`error.TransactionMismatch`, …) instead of `error.Timeout`; an error
  response ends it with `error.ErrorResponse`.

## Tests

The RFC 5769 test vectors are the oracle — the exact sample byte sequences from
§2.1 (request), §2.2 (IPv4 response), §2.3 (IPv6 response) are used as fixtures
(not invented ones): the sample request decodes and its MESSAGE-INTEGRITY (with
the §2.1 password) and FINGERPRINT verify; the responses decode to
`192.0.2.1:32853` and `2001:db8:1234:5678:11:2233:4455:6677:32853`; tamper tests
flip a covered byte and assert both checks fail. `zig build test-stun` passes in
Debug and `-Doptimize=ReleaseFast`.

## Not here (decided, with reasons in SPEC.md)

OpaqueString/SASLprep (Unicode tables; callers pass prepared strings) · the nonce/realm challenge
flow of a long-term *server* · ICE · TURN · TCP/TLS/DTLS transport · a multiplexing client agent ·
the RFC 5780 NAT-behaviour procedure (the attributes are here) · automatic 300 redirects.

## Which accessor after verifying a MAC

`find`, `address`, `uint32`, `mappedAddress`, `otherAddress`, ... see every attribute in the
datagram, including ones an on-path attacker **appended behind MESSAGE-INTEGRITY** (or behind
FINGERPRINT with a recomputed CRC): the MAC still verifies. After `verifyMessageIntegrity` or
`verifyMessageIntegritySha256`, read the values you act on with `findCovered`, `addressCovered`,
`mappedAddressCovered`, `uint32Covered` (RFC 8489 §14.5: only what precedes the MAC counts).
Without a MAC nothing is authenticated; the covered forms then see the whole message.

Provenance: clean-room from RFC 8489 (STUN), verified against the RFC 5769
test vectors — original work of the zig-libs authors (MIT); the attribute-TLV
(de)serialization *design* is modeled after Corendos/ztun (MIT) — design
reference only, no source copied. HMAC-SHA1 and CRC-32 come from Zig
`std.crypto` / `std.hash`.

Bench oracle (not shipped code): `tools/go_bench/` uses `github.com/pion/stun/v3` v3.1.6 (MIT) and
`tools/go_bench_gortc/` `gortc.io/stun` v1.23.0 (BSD-3-Clause) from the Go module cache; their
`go.mod`/`go.sum` were produced by `go mod tidy` against the Go module proxy on 2026-11-03
(pinned versions, hashes verified by the Go checksum database). Run `zig build bench-stun`.
