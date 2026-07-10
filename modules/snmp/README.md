# snmp

Pure-Zig **SNMP v1 + v2c manager**: a BER/ASN.1 codec, OID handling, the SNMP
message/PDU model, and a transport-agnostic client. Feeds the network-device
management work (alongside `netlink`, `nftables`, `icmp`).

- No mature pure-Zig SNMP implementation exists.
- **Platform:** any (codec, OID, message model and client are pure
  computation; only the optional `UdpTransport` adapter touches
  `std.Io.net`).
- **Model after:** SNMP v1 RFC 1157 + v2c RFC 3416/1905; net-snmp behavior.
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
    InformRequest [6], SNMPv2-Trap [7]. Lazy typed varbind iteration;
    GetBulk's non-repeaters/max-repetitions handled per RFC 3416
    (negatives clamp to 0).
  - **Client** (`Client`): manager behind a `Transport` seam ("send request
    bytes, receive reply bytes"), so everything is offline-testable —
    `get`, `getNext`, `getBulk` (v2c), `set`, request-id allocation and
    matching, error-status surfacing, and a GetNext `walker` with subtree,
    endOfMibView/noSuchName, and OID-not-increasing guards. `UdpTransport`
    is an optional real `std.Io.net` adapter (UDP/161); tests never send.
  - **SNMPv3** (`v3`, `usm`, `des`, `priv`, `timewin`): the RFC 3412 message
    envelope + ScopedPDU; the RFC 3414 USM security parameters, password→key
    derivation, key localization and HMAC-MD5/SHA-1-96 authentication
    (sign/verify, constant-time compare); scoped-PDU **privacy** — CBC-DES
    (RFC 3414 §8, from-scratch FIPS 46-3 DES) and AES-128-CFB128 (RFC 3826),
    with the correct key/IV/salt derivation; and the RFC 3414 §3.2 **time-window
    anti-replay** logic (engine boots/time bookkeeping, ±150 s window, both the
    authoritative and non-authoritative roles). All KAT-verified: FIPS 46-3 DES
    vector, NIST SP 800-38A CFB128-AES128 vectors, RFC 3414 A.3 key-derivation
    vectors. Manager side only — no agent, no engine-ID discovery orchestration.
  - Out of scope for now: agent side, trap listening beyond `receiver`, MIB
    parsing, and the RFC 7860 SHA-2 auth variants.

Provenance: clean-room from RFC 1157 (SNMPv1), RFC 1905/3416 (SNMPv2c
protocol operations), RFC 2578 (SMI types), ITU-T X.690 (BER), RFC 3412/3414
(SNMPv3 + USM), RFC 3826 (AES-CFB privacy), FIPS 46-3 (DES) and NIST SP
800-38A (CFB mode) — original work of the zig-libs authors (MIT); net-snmp
(BSD-like license) referenced for behavior only, no source consulted or
copied — see NOTICE.
