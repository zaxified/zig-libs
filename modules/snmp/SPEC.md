# snmp — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
Layered: `ber` (X.690 subset — definite-length TLV, SNMP application types incl. Counter64 + v2c
exceptions) → `oid` (dotted parse/format, wire packing, prefix/order) → `message` (v1+v2c
SEQUENCE{version,community,PDU}, all 8 PDUs, shared encode/decode) → `client` (manager behind a
`Transport` seam: get/next/bulk/set + walker) → `receiver` (datagram → normalized `TrapEvent` +
`Dispatcher` + `ackInform`, covering v1 Trap / v2c Trap / Inform) → `v3` (RFC 3412 envelope +
ScopedPDU) → `usm` (RFC 3414 security parameters + auth + privacy). Zero-allocation,
transport-agnostic: codecs fill caller buffers; client/receiver take the transport via a seam
(optional `std.Io` UDP adapter), fully offline-testable. Never-panic: every length, OID arc count,
and integer width is bounded; malformed agent bytes are typed errors. `v3` framing captures
`msgSecurityParameters` as an opaque blob (parsed by `usm`) and surfaces an encrypted ScopedPDU
verbatim as `.encrypted`; `decodeScopedPdu` is public for post-decrypt use. Clean-room from RFC 1157
(v1), 1905/3416 (v2c), 3412 (v3 message processing), 3414 (USM), 3826 (AES priv), 2578 (SMI types),
X.690 (BER) — see NOTICE.

## Threat model / out of scope
USM is the security-sensitive part.
- **Authentication (RFC 3414):** HMAC-MD5-96 / HMAC-SHA-1-96 with the password→key 1 MB expansion
  (§A.2) + engine localization (`Kul = H(Ku ++ engineID ++ Ku)`). `verify` recomputes the digest with
  the auth field zero-filled and compares in **constant time** (`std.crypto.timing_safe.eql`, never
  `mem.eql`). Verified against RFC 3414 A.3 KATs.
- **Privacy (RFC 3826/T-G, landed):** DES-CBC and AES-128-CFB decrypt of the ScopedPDU.
- **Anti-replay window (T-H, landed):** engineBoots/engineTime window check (§3.2).
- **v1/v2c is unauthenticated** — the community string is not a credential; the trap receiver must
  treat input as untrusted (never panics; caller decides trust).
- MD5/SHA-1 are the RFC-3414 originals (weak by modern standards; RFC 7860 SHA-2 not implemented).
  No MIB compiler/SMI parsing; no agent (server) role.
- **Pre-public security-review flag:** `snmp.usm` const-time compare + auth/privacy algorithm
  confusion (MD5 vs SHA-1, DES vs AES selection) is on the pre-public security-review list
  (see /docs/pre-public-review.md) — verify the algorithm-selection path can't be tricked into a
  weaker/wrong primitive by a malicious agent reply.

## Verification
BER + message golden-byte KATs, length-boundary + garbage sweeps, scripted-agent round-trips
(offline `Transport`); trap receiver v1/v2c/inform decode + `NotATrap` + ack round-trip; v3
encode/decode round-trips incl. the encrypted-branch capture; USM RFC 3414 A.3 known-answer vectors
(MD5 + SHA-1, Ku and localized Kul) + sign/verify with adversarial tamper (message byte / digest byte
/ wrong key → `AuthenticationFailed`); privacy KATs (DES-CBC + AES-128-CFB against NIST/RFC vectors)
and time-window accept/reject. 71+ tests (grew with T-G/T-H). Run: `zig build test-snmp`.

## Backlog / deferred
RFC 7860 SHA-2 auth protocols; MIB compiler/SMI parsing; agent (server) role. Pre-public: the
security-review pass on `snmp.usm` const-time/alg-confusion (see Threat model above) is still open
(see /docs/pre-public-review.md).

## Status
`gap · any · codec+client · single_owner` + deps: none (std only) — canonical source is
`pub const meta` in src/root.zig.
