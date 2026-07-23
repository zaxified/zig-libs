# snmp

Pure-Zig **SNMP v1 / v2c / v3 manager**: a BER/ASN.1 codec, OID handling, the
SNMP message/PDU model, a transport-agnostic client, and a complete SNMPv3 USM
stack (authentication, privacy, discovery, anti-replay). Feeds the
network-device management work (alongside `netlink`, `nftables`, `icmp`).

- No mature pure-Zig SNMP implementation exists.
- **Platform:** any (codec, OID, message model and clients are pure
  computation; only the optional `UdpTransport` adapter touches
  `std.Io.net`).
- **Model after:** SNMP v1 RFC 1157 + v2c RFC 3416/1905 + v3 RFC 3412/3414/3826
  + RFC 7860; net-snmp behavior.
- **Scope:**
  - **BER codec** (`ber`): the ITU-T X.690 subset SNMP needs — definite
    lengths only (short + long form, indefinite rejected), single-byte tags,
    INTEGER, OCTET STRING, NULL, OBJECT IDENTIFIER, SEQUENCE, the RFC 2578
    application types (IpAddress [APPLICATION 0], Counter32 [1],
    Gauge32/Unsigned32 [2], TimeTicks [3], Opaque [4], Counter64 [6]) and
    the v2c varbind exceptions (noSuchObject / noSuchInstance /
    endOfMibView as context tags). One-pass backwards encoder; fully
    bounds-checked decoder — malformed input is a typed error, never a
    panic.
  - **OID** (`oid.Oid`): bounded arc count (64), dotted-decimal
    parse/format, `eql` / `startsWith` / `order` / `append`; BER wire form
    (40*x+y first octet, base-128 subidentifiers, overlong-padding
    rejection) in the codec.
  - **Messages** (`message`): `SEQUENCE { version, community, PDU }` with
    all v1 + v2c PDUs — GetRequest [0], GetNextRequest [1], Response [2],
    SetRequest [3], v1 Trap [4] (decode-only), GetBulkRequest [5],
    InformRequest [6], SNMPv2-Trap [7], Report [8]. Lazy typed varbind
    iteration; GetBulk's non-repeaters/max-repetitions handled per RFC 3416
    (negatives clamp to 0).
  - **Client** (`Client`): manager behind a `Transport` seam ("send request
    bytes, receive reply bytes"), so everything is offline-testable —
    `get`, `getNext`, `getBulk` (v2c), `set`, request-id allocation and
    matching, error-status surfacing, and a GetNext `walker` with subtree,
    endOfMibView/noSuchName, and OID-not-increasing guards. `UdpTransport`
    is an optional real `std.Io.net` adapter (UDP/161); tests never send.
  - **SNMPv3 framing** (`v3`): the RFC 3412 message envelope
    (`msgID` / `msgMaxSize` / `msgFlags` / `msgSecurityModel`), the opaque
    `msgSecurityParameters` OCTET STRING, and the ScopedPDU
    (`contextEngineID`, `contextName`, PDU) in both the plaintext and the
    encrypted branch of the `ScopedPduData` CHOICE.
  - **USM** (`usm`): the `UsmSecurityParameters` (de)serializer — a BER
    SEQUENCE **nested inside** the envelope's OCTET STRING; the RFC 3414 §A.2
    password→`Ku`→`Kul` derivation (1 MB expansion + `H(Ku ‖ engineID ‖ Ku)`);
    and authentication for **six** protocols: HMAC-MD5-96 and HMAC-SHA-1-96
    (RFC 3414 §6/§7) plus HMAC-SHA-224/256/384/512 (RFC 7860) with their
    differing truncation lengths (12/12/16/24/32/48). The digest is computed
    over the whole datagram with `msgAuthenticationParameters` **zero-filled to
    its final length** and written back in place, and verification compares in
    **constant time** (`std.crypto.timing_safe`).
  - **Privacy** (`priv`, `des`): CBC-DES (RFC 3414 §8, on a from-scratch FIPS
    46-3 DES — see the note below) and AES-128-CFB128 (RFC 3826), with the
    correct key/pre-IV/salt derivation and the boots‖time‖salt IV.
  - **Anti-replay** (`timewin`): the RFC 3414 §3.2 ±150 s window with
    per-engine boots/time state, in both the authoritative and
    non-authoritative roles.
  - **Reports** (`report`): the Report-PDU is the engine's error channel, not
    data. Every RFC 3414 §5 `usmStats*` counter and RFC 3412 §5.2
    `snmpUnknown*` counter is classified into a typed `Reason`/error
    (`UnknownEngineId`, `NotInTimeWindow`, `WrongDigest`, `UnknownUserName`,
    `UnsupportedSecLevel`, `DecryptionError`, …), with `unknown` for anything
    outside the modelled set.
  - **v3 client** (`V3Client`): over the *same* `Transport` seam as `Client`.
    `noAuthNoPriv` / `authNoPriv` / `authPriv`; the RFC 3414 §4 **engine
    discovery** handshake exposed as a public `discover` (plus `seedEngine` for
    a caller-driven or cached identity); one RFC-sanctioned retry after a
    recoverable Report; downgrade rejection; `get`/`getNext`/`getBulk`/`set`
    and a v3 `walker`. Makes no time-of-day calls — a stale clock self-corrects
    from the engine's authenticated `notInTimeWindows` Report.
  - **DES note.** Zig's `std.crypto` has no DES, so this module carries its own
    (`des.zig`, from FIPS 46-3). It is provided **for interop with legacy
    agents only and is not a recommendation** — single DES has a 56-bit key.
    Prefer AES-128-CFB (RFC 3826), and prefer the RFC 7860 SHA-2 auth
    protocols over MD5/SHA-1.
  - Out of scope for now: the **agent/engine (server) side**; trap listening
    beyond `receiver`; MIB/SMI parsing; the AES-192/256 privacy drafts
    (draft-blumenthal / Cisco variants); SNMPv3 over TLS/DTLS (RFC 6353);
    RFC 3826's `usmDHKickstart`/key-change (`KeyChange`) machinery; and
    context-engine-ID *proxy* forwarding.

**Verified against a real agent.** The v3 stack is checked three ways: the
RFC 3414 Appendix A.3 key-derivation KATs; byte-exact goldens captured from
net-snmp 5.9.4's own `snmpget -v3 -d` (whose digests we both *verify* and
*regenerate bit-for-bit*); and a gated live test that runs discovery + an
authPriv GET + a walk against a real `snmpd`. See `SPEC.md` for the exact
matrix and how to re-run it.

Provenance: clean-room from RFC 1157 (SNMPv1), RFC 1905/3416 (SNMPv2c
protocol operations), RFC 2578 (SMI types), ITU-T X.690 (BER), RFC 3412/3414
(SNMPv3 + USM), RFC 3826 (AES-CFB privacy), RFC 7860 (SHA-2 auth), FIPS 46-3
(DES) and NIST SP 800-38A (CFB mode) — original work of the zig-libs authors
(MIT); net-snmp (BSD-like license) used only as a **black-box interop oracle**
(run it, capture its packets, compare) — no source consulted or copied, so no
NOTICE change is required — see NOTICE.
