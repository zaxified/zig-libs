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
verbatim as `.encrypted`; `decodeScopedPdu` is public for post-decrypt use, and the send side is
`encodeScopedPdu` (the plaintext TLV to encrypt) + `encodeEncrypted` (envelope with
msgData = encryptedPDU). Clean-room from RFC 1157
(v1), 1905/3416 (v2c), 3412 (v3 message processing), 3414 (USM), 3826 (AES priv), 2578 (SMI types),
X.690 (BER) — see NOTICE.

## Threat model / out of scope
USM is the security-sensitive part.
- **Authentication (RFC 3414):** HMAC-MD5-96 / HMAC-SHA-1-96 with the password→key 1 MB expansion
  (§A.2) + engine localization (`Kul = H(Ku ++ engineID ++ Ku)`). `verify` recomputes the digest with
  the auth field zero-filled and compares in **constant time** (`std.crypto.timing_safe.eql`, never
  `mem.eql`). Verified against RFC 3414 A.3 KATs.
- **Privacy (RFC 3414 §8 + RFC 3826, landed):** DES-CBC and AES-128-CFB encrypt + decrypt of the
  ScopedPDU, wired into the message path both ways (`encodeScopedPdu`/`encodeEncrypted` on send,
  `.encrypted` + `decryptScopedPdu` on receive). AES-192/256 (the draft-blumenthal / Cisco
  variants) and SNMPv3 over TLS/DTLS (RFC 6353) are out of scope.
- **Anti-replay window (T-H, landed):** engineBoots/engineTime window check (§3.2).
- **v1/v2c is unauthenticated** — the community string is not a credential; the trap receiver must
  treat input as untrusted (never panics; caller decides trust).
- MD5/SHA-1 are the RFC-3414 originals (weak by modern standards; RFC 7860 SHA-2 not implemented).
  No MIB compiler/SMI parsing; no agent (server) role.
- **Salt uniqueness is a caller obligation, not enforced here:** the privacy layer (DES-CBC /
  AES-128-CFB) requires the CALLER to supply a UNIQUE `msgPrivacyParameters` salt per message under
  a given key/engineTime — this module neither generates the salt nor enforces/tracks its
  uniqueness. Reusing a salt (e.g. a constant, or a counter that resets within the same
  engineTime second) reuses the AES-CFB keystream or the DES-CBC IV under the same key, which leaks
  plaintext via `C1 XOR C2 = P1 XOR P2`. Callers must use a strictly-increasing (or
  cryptographically random, never repeated) salt for every encrypted message.
- **Reviewed 2026-07-10 (adversarial security pass):** `snmp.usm` const-time compare and
  auth/privacy algorithm confusion (MD5 vs SHA-1, DES vs AES selection) confirmed clean — the
  algorithm-selection path can't be tricked into a weaker/wrong primitive by a malicious agent
  reply; an empty-password panic found in the pass was fixed.

## Verification
BER + message golden-byte KATs, length-boundary + garbage sweeps, scripted-agent round-trips
(offline `Transport`); trap receiver v1/v2c/inform decode + `NotATrap` + ack round-trip; v3
encode/decode round-trips incl. the encrypted-branch capture; USM RFC 3414 A.3 known-answer vectors
(MD5 + SHA-1, Ku and localized Kul) + sign/verify with adversarial tamper (message byte / digest byte
/ wrong key → `AuthenticationFailed`); privacy KATs (DES-CBC + AES-128-CFB against NIST/RFC vectors)
plus a full authPriv datagram round-trip (encodeScopedPdu → encrypt → encodeEncrypted → sign, then
decode → verify → decrypt) and time-window accept/reject. 95 tests. Run: `zig build test-snmp`.

## Backlog / deferred
RFC 7860 SHA-2 auth protocols; MIB compiler/SMI parsing; agent (server) role. The security-review
pass on `snmp.usm` const-time/alg-confusion (see Threat model above) is done — clean, 2026-07-10.

## Status
`gap · any · codec+client · single_owner` + deps: none (std only) — canonical source is
`pub const meta` in src/root.zig.
