# SPEC — `snmp`

**Purpose** — SNMP for network-device management + monitoring: a BER/ASN.1 codec, OID handling, the
v1/v2c message model with a manager client, a **trap/notification receiver** (v1 Trap / v2c Trap /
Inform), and the **SNMPv3 / USM** security layer (message framing + user-based auth). Fits the
device line-up next to `netlink`/`nftables`/`modbus`/`mqtt`.

**Model after / Seed** — clean-room from RFC 1157 (v1), 1905/3416 (v2c), 3412 (v3 message
processing / ScopedPDU), 3414 (USM), 3826 (AES priv — planned), 2578 (SMI types), ITU-T X.690 (BER);
net-snmp behavior only. Greenfield, no seed. See NOTICE.

**Design & invariants**
- **Layered:** `ber` (X.690 subset — definite-length TLV, SNMP application types incl. Counter64 +
  v2c exceptions) · `oid` (dotted parse/format, wire packing, prefix/order) · `message` (v1+v2c
  SEQUENCE{version,community,PDU}, all 8 PDUs, `encodePdu`/`decodePdu` shared building blocks) ·
  `client` (manager behind a `Transport` seam: get/next/bulk/set + walker) · `receiver`
  (datagram → normalized `TrapEvent` + `Dispatcher` + `ackInform`) · `v3` (RFC 3412 envelope +
  ScopedPDU) · `usm` (RFC 3414 security params + auth).
- **Zero-allocation, transport-agnostic:** codecs fill caller buffers; the client/receiver take the
  transport via a seam (optional `std.Io` UDP adapter) — fully offline-testable.
- **Never-panic:** every length, OID arc count, and integer width is bounded; malformed agent bytes
  are typed errors.
- **v3 framing** captures `msgSecurityParameters` as an opaque blob (parsed by `usm`) and surfaces
  an encrypted ScopedPDU verbatim as `.encrypted` for the privacy layer; `decodeScopedPdu` is public
  for post-decrypt use.

**Threat model / out of scope** — USM is the security-sensitive part:
- **Authentication (RFC 3414):** HMAC-MD5-96 / HMAC-SHA-1-96 with the password→key 1 MB expansion
  (§A.2) + engine localization (`Kul = H(Ku ++ engineID ++ Ku)`). `verify` recomputes the digest
  over the whole message with the auth field zero-filled and compares in **constant time**
  (`std.crypto.timing_safe.eql`, never `mem.eql` on a MAC). Verified against the RFC 3414 A.3 KATs.
- **v1/v2c is unauthenticated** — the community string is not a credential; a v2c trap receiver must
  treat input as untrusted (the receiver never panics and the caller decides trust).
- **Out of scope / not yet done:** USM **privacy** (DES-CBC + AES-128-CFB decrypt, T-G) and the
  engineBoots/engineTime **time-window anti-replay** (§3.2, T-H) are pending — so v3 today is
  authNoPriv/noAuthNoPriv only, and replayed authenticated messages inside the (unchecked) time
  window are not yet rejected. MD5/SHA-1 are the RFC-3414 originals (weak by modern standards; RFC
  7860 SHA-2 is a future add). No MIB compiler / SMI parsing; no agent (server) role.

**Verification** — BER + message golden-byte KATs, length-boundary + garbage sweeps,
scripted-agent round-trips (offline `Transport`); trap receiver v1/v2c/inform decode + `NotATrap`
+ ack round-trip; v3 encode/decode round-trips incl. the encrypted-branch capture; USM RFC 3414 A.3
known-answer vectors (MD5 + SHA-1, Ku and localized Kul) + sign/verify with adversarial tamper
(message byte / digest byte / wrong key → AuthenticationFailed). 71 tests.

**Status** — `gap · any · codec+client · single_owner` · deps: none (std only).
