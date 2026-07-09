# stun — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
Pure codec (RFC 8489 client side): header is a 16-bit type (2-bit class + 12-bit method interleaved
per §5), 16-bit length, the magic cookie `0x2112A442`, a 96-bit transaction id. `Builder` writes a
message into a caller buffer (`init`, `addAttribute` — generic TLV with 4-byte padding —,
`addSoftware`, `addMappedAddress` plain or XOR, `addMessageIntegrity`, `addFingerprint`, `finish`;
`bindingRequest(txid, out)` is the one-liner). `Message`/`decode` validates the header, cookie, and
4-byte length alignment, then exposes an `AttributeIterator`, `find`, and typed decoders:
XOR-MAPPED-ADDRESS/MAPPED-ADDRESS → `AddressPort` (`netaddr.Ip` + port; XOR form preferred),
FINGERPRINT (CRC-32 ⊕ `0x5354554E`, `verifyFingerprint`), MESSAGE-INTEGRITY (HMAC-SHA1-20 over the
message with the length field adjusted to include the attribute, `verifyMessageIntegrity` via
constant-time compare), ERROR-CODE → `{ code, reason }`. No allocation in the core — everything is
over caller buffers. `query` (optional) sends one Binding request over `std.Io.net` UDP; a
convenience only, not the interface. Reentrant — no shared state; every call is over caller buffers.
Clean-room from RFC 8489; attribute TLV (de)serialization structure modeled after Corendos/ztun
(design reference only, no source copied) — see NOTICE.

## Threat model / out of scope
This is a client-side codec/utility, not a security boundary by itself: it does not authenticate a
STUN server, and NAT-mapping discovery is inherently informational (a malicious/compromised STUN
server can report a false reflexive address). What it does defend: MESSAGE-INTEGRITY verification
uses `std.crypto.timing_safe.eql` (constant-time), not a byte-wise compare, so a MITM can't use
timing to forge a valid MAC; FINGERPRINT lets a caller distinguish STUN traffic from other protocols
sharing a port. Explicitly out of scope (deferred, not a gap in what's built): server side, the
long-term credential mechanism (RFC 8489 §9.2 — SASLprep username/realm/nonce, PASSWORD-ALGORITHMS,
USERHASH), UNKNOWN-ATTRIBUTES generation, ICE integration, TURN, TCP/TLS transport.

## Verification
The RFC 5769 test vectors are the oracle — the exact sample byte sequences from §2.1 (request), §2.2
(IPv4 response), §2.3 (IPv6 response) are used as fixtures (not invented ones): the sample request
decodes and its MESSAGE-INTEGRITY (with the §2.1 password) and FINGERPRINT verify; the responses
decode to `192.0.2.1:32853` and the IPv6 equivalent; tamper tests flip a covered byte and assert both
checks fail. 12 tests. Run: `zig build test-stun` (Debug and `-Doptimize=ReleaseFast`).

## Backlog / deferred
Server side; long-term credential mechanism (RFC 8489 §9.2); UNKNOWN-ATTRIBUTES generation; ICE
integration; TURN; TCP/TLS transport. (README "Deferred (not in v1)".)

## Status
`gap · any (core pure; optional query helper does I/O) · codec · reentrant` + deps: `netaddr` —
canonical source is `pub const meta` in src/root.zig.
