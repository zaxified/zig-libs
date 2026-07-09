# stun

Pure-Zig **STUN client** (Session Traversal Utilities for NAT, RFC 8489, née
RFC 5389): a transport-agnostic codec that builds/parses/verifies STUN Binding
messages so a host behind a NAT can learn its public "reflexive" transport
address. Sits alongside the rest of the `netaddr`-based network family.

- **Status:** gap — no mature pure-Zig STUN library to adopt.
- **Platform:** any (the core is pure computation over caller buffers; only the
  optional `query` helper touches `std.Io.net`).
- **Role:** codec (no I/O in the core).
- **Model after:** RFC 8489 STUN; attribute TLV (de)serialization structure
  modelled after Corendos/ztun (MIT); RFC 5769 test vectors as the oracle.
- **Depends on:** `netaddr` (XOR-MAPPED-ADDRESS decodes to a `netaddr.Ip` + port).

## Scope (v1)

- **Header** — 16-bit type (2-bit class + 12-bit method interleaved per §5),
  16-bit length, the magic cookie `0x2112A442`, the 96-bit transaction id.
  `encodeType` / `decodeClass` / `decodeMethod`; Binding is method `0x001`.
- **`Builder`** — writes a message into a caller buffer: `init`, `addAttribute`
  (generic TLV with 4-byte padding), `addSoftware`, `addMappedAddress`
  (plain **or** XOR), `addMessageIntegrity`, `addFingerprint`, `finish`.
  `bindingRequest(txid, out)` is the one-liner for a bare Binding request.
- **`Message` / `decode`** — validates the header, cookie, and 4-byte length
  alignment, then exposes an `AttributeIterator`, `find`, and decoders:
  - **XOR-MAPPED-ADDRESS** (`0x0020`) and plain **MAPPED-ADDRESS** (`0x0001`)
    → `AddressPort` (`netaddr.Ip` + port); `mappedAddress` prefers the XOR form.
  - **FINGERPRINT** (`0x8028`) — CRC-32 ⊕ `0x5354554E`, `verifyFingerprint`.
  - **MESSAGE-INTEGRITY** (`0x0008`) — HMAC-SHA1-20 over the message with the
    length field adjusted to include the attribute, `verifyMessageIntegrity`
    (constant-time compare via `std.crypto.timing_safe.eql`).
  - **ERROR-CODE** (`0x0009`) → `{ code = class*100 + number, reason }`.
- **`query`** (optional) — sends one Binding request over `std.Io.net` UDP and
  returns the reflexive address; a convenience only, the pure codec is the real
  interface. Its unit test skips (needs a reachable server).

## Tests

The RFC 5769 test vectors are the oracle — the exact sample byte sequences from
§2.1 (request), §2.2 (IPv4 response), §2.3 (IPv6 response) are used as fixtures
(not invented ones): the sample request decodes and its MESSAGE-INTEGRITY (with
the §2.1 password) and FINGERPRINT verify; the responses decode to
`192.0.2.1:32853` and `2001:db8:1234:5678:11:2233:4455:6677:32853`; tamper tests
flip a covered byte and assert both checks fail. `zig build test-stun` passes in
Debug and `-Doptimize=ReleaseFast`.

## Deferred (not in v1)

Server side · long-term credential mechanism (RFC 8489 §9.2: SASLprep
username/realm/nonce, MD5 + SHA-256 PASSWORD-ALGORITHMS, USERHASH) ·
UNKNOWN-ATTRIBUTES generation · ICE integration · TURN · TCP/TLS transport.

Provenance: clean-room from RFC 8489 (STUN) and the RFC 5769 test vectors; the
attribute TLV (de)serialization structure is modelled after Corendos/ztun (MIT)
— design reference only, no source copied. HMAC-SHA1 and CRC-32 come from
Zig `std.crypto` / `std.hash`. Owner note: add a `NOTICE` entry for RFC
8489/5769 and the ztun design reference.
