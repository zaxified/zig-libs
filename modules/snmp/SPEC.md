# snmp — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
Layered: `ber` (X.690 subset — definite-length TLV, SNMP application types incl. Counter64 + v2c
exceptions) → `oid` (dotted parse/format, wire packing, prefix/order) → `message` (v1+v2c
SEQUENCE{version,community,PDU}, all 8 request/response PDUs **plus Report [8]**, shared
encode/decode) → `client` (v1/v2c manager behind a `Transport` seam: get/next/bulk/set + walker) →
`receiver` (datagram → normalized `TrapEvent` + `Dispatcher` + `ackInform`, covering v1 Trap /
v2c Trap / Inform) → `v3` (RFC 3412 envelope + ScopedPDU) → `usm` (RFC 3414 + RFC 7860 security
parameters + auth) → `priv`/`des` (RFC 3414 §8 + RFC 3826 privacy) → `timewin` (RFC 3414 §3.2
window) → `report` (Report-PDU classification) → `v3client` (`V3Client`: the USM manager over the
same `Transport` seam). Zero-allocation, transport-agnostic: codecs fill caller buffers;
clients/receiver take the transport via a seam (optional `std.Io` UDP adapter), fully
offline-testable. Never-panic: every length, OID arc count, and integer width is bounded; malformed
agent bytes are typed errors.

Two layering traps are modelled explicitly, because they are what implementations get wrong:
- **`msgSecurityParameters` is a nested encoding** — a BER SEQUENCE serialised *into* an OCTET
  STRING. `v3` captures it as an opaque blob and `usm` parses/builds it separately; a golden test
  re-encodes the parsed fields of every captured datagram and requires byte-identical output.
- **The auth digest covers the whole datagram with `msgAuthenticationParameters` zero-filled to its
  FINAL length**, then overwritten in place. The client therefore serialises a zero placeholder of
  exactly `proto.digestLen()` bytes before signing — encoding a shorter field and patching later
  would shift every following byte and silently invalidate the digest.

`v3` surfaces an encrypted ScopedPDU verbatim as `.encrypted`; `decodeScopedPdu` is public for
post-decrypt use, and the send side is `encodeScopedPdu` (the plaintext TLV to encrypt) +
`encodeEncrypted` (envelope with msgData = encryptedPDU). Clean-room from RFC 1157 (v1), 1905/3416
(v2c), 3412 (v3 message processing), 3414 (USM), 3826 (AES priv), 7860 (SHA-2 auth), 2578 (SMI
types), X.690 (BER) — see NOTICE.

## Threat model / out of scope
USM is the security-sensitive part.

- **Authentication — six protocols.** RFC 3414 §6/§7 HMAC-MD5-96 and HMAC-SHA-1-96, plus RFC 7860
  HMAC-SHA-224/256/384/512. Key lengths 16/20/28/32/48/64; **truncation lengths 12/12/16/24/32/48**
  — `AuthProtocol.digestLen()` is the single source of truth, and an auth field of the wrong length
  for the selected protocol is `error.BadAuthParams`, never a short compare. The password→key path
  is the RFC 3414 §A.2 1 MB expansion + `Kul = H(Ku ‖ engineID ‖ Ku)` with the protocol's hash.
  `verify` recomputes the digest with the auth field zero-filled and compares in **constant time**
  (`std.crypto.timing_safe.eql`, never `mem.eql`).
- **Privacy.** DES-CBC (RFC 3414 §8) and AES-128-CFB128 (RFC 3826), encrypt + decrypt, wired into
  the message path both ways. **DES is legacy and is provided for interop only, not as a
  recommendation** (56-bit key); Zig's std has no DES, so `des.zig` is a from-scratch FIPS 46-3
  implementation. AES-192/256 (draft-blumenthal / Cisco variants) and SNMPv3 over TLS/DTLS
  (RFC 6353) remain out of scope.
- **Salt uniqueness — the library owns it, not the caller.** `msgPrivacyParameters` is the only
  thing standing between an authPriv session and keystream/IV reuse, so it is not an API parameter.
  `priv.encrypt` takes a `priv.SaltSource` and *returns* the salt it drew (`Encrypted.salt`) for the
  USM header; there is no call shape that accepts a salt for live traffic. The default source,
  `SaltSource.counter(seed)`, is a monotonic 64-bit counter shaped per protocol (AES: the counter
  big-endian, RFC 3826 §3.3.1; DES: `snmpEngineBoots ‖ counter[31:0]`, RFC 3414 §8.1.1.1).
  - **What that guarantees:** within one source's lifetime every salt — hence every IV — is
    distinct, for *all* pairs of messages, because it is generated rather than checked.
  - **Escape hatch, deliberately conspicuous:** `SaltSource.fixedForInterop(salt)` pins the salt so
    a published KAT or a captured net-snmp datagram reproduces byte-for-byte. Every message from
    such a source carries the same salt; it is a test/interop construct and never belongs on live
    traffic. It is the only way to get a repeated salt through this API.
  - **Detection is a tripwire, not the mechanism.** A source remembers the IV of the *immediately
    preceding* encryption and returns `error.SaltReuse` if the next one matches. That catches an
    adjacent repeat only — an `A, B, A` sequence is **not** caught, and the tests say so explicitly.
    Full history would need unbounded per-key state, which this zero-allocation module does not
    carry, and would still not survive a process restart; the counter, not this check, is what the
    design rests on.
  - **`error.SaltExhausted`:** RFC 3414 §8.1.1.1 gives DES only a 32-bit local integer, so a DES
    counter source has 2^32 salts per `snmpEngineBoots` epoch — reachable in weeks at a few thousand
    messages/second. It refuses rather than wrapping into a repeat. AES-CFB has the full 64 bits.
  - **DES-CBC is the sharper edge, and the asymmetry is intentional in the RFC, not here.** The
    AES-CFB IV is `boots‖time‖salt`, so the engine clock varies it even if a salt repeats; the
    DES-CBC IV is `pre_iv XOR salt`, with **no** boots/time input at all, so the salt is the only
    thing separating two IVs. DES is therefore fully dependent on this layer.
  - **Cross-restart.** No in-process state can see a previous run. `V3Client` therefore seeds its
    counter from the engine's discovered `engineBoots‖engineTime` before the first encrypted message
    (RFC 3414 §8.1.1.1 asks for a pseudo-random boot-time value; this module owns no clock and no RNG
    by design, and the engine clock is the varying value it already has). That separates two runs
    starting more than one engine-second apart. It does **not** separate two runs that reach their
    first authPriv message inside the same second — pass `Options.initial_salt` with a random value
    if that matters. Consequence of getting it wrong: AES-CFB reuses the keystream outright
    (`C1 XOR C2 = P1 XOR P2`); DES-CBC reuses the IV, which leaks equality of ScopedPDU block
    prefixes — and SNMP ScopedPDU prefixes are highly structured.
- **Anti-replay window.** engineBoots/engineTime ±150 s check (§3.2), per-engine state, both roles.
- **Report handling and trust.** A Report-PDU is never returned as data — it becomes a typed error.
  Trust rules in `V3Client.processReply`, in order: (1) a reply claiming `authFlag` must verify
  before *anything* in it is read; (2) a Report may legitimately arrive **unauthenticated** — real
  agents (net-snmp included, see the `report_wrong_digest` golden) send `usmStatsWrongDigests` with
  `msgFlags = 0x00` — so Reports are exempt from the downgrade rule, but an unauthenticated Report
  may **not** move state we already trust: `unknownEngineIDs` re-seeds only while undiscovered or
  when authenticated, and `notInTimeWindows` moves the clock only when authenticated (otherwise an
  off-path attacker could park the replay window anywhere); (3) only then is DATA held to the
  security level — an `authNoPriv`/`authPriv` request answered unauthenticated or unencrypted is
  `error.SecurityLevelDowngrade`; (4) the engine ID must match the one our keys are localized to.
  A Report we could not act on is terminal immediately; only an acted-on Report earns the single
  retry, so a hostile peer cannot spin the client.
- **Discovery bootstrap.** The RFC 3414 §4 probe is unauthenticated by construction, so the engine
  ID *and clock* it yields are unverified. That is inherent to the handshake; the self-correction is
  that a spoofed clock makes the next authenticated request fall outside the engine's real window,
  and the engine's **authenticated** `notInTimeWindows` Report then supplies the truth. This is why
  the module needs no clock of its own and makes no time-of-day calls.
- **v1/v2c is unauthenticated** — the community string is not a credential; the trap receiver must
  treat input as untrusted (never panics; caller decides trust).
- MD5/SHA-1 are the RFC 3414 originals and are weak by modern standards; prefer the RFC 7860 SHA-2
  protocols. No MIB compiler/SMI parsing; no agent (server) role.
- **Reviewed 2026-07-10 (adversarial security pass):** `snmp.usm` const-time compare and
  auth/privacy algorithm confusion (MD5 vs SHA-1, DES vs AES selection) confirmed clean — the
  algorithm-selection path can't be tricked into a weaker/wrong primitive by a malicious agent
  reply; an empty-password panic found in the pass was fixed.

## Verification
BER + message golden-byte KATs, length-boundary + garbage sweeps, scripted-agent round-trips
(offline `Transport`); trap receiver v1/v2c/inform decode + `NotATrap` + ack round-trip; v3
encode/decode round-trips incl. the encrypted-branch capture; privacy KATs (FIPS 46-3 DES, NIST
SP 800-38A CFB128-AES128) plus full authPriv datagram round-trips; time-window accept/reject.
Salt behaviour is tested for the property, not the round-trip: two successive encryptions of the
*same* plaintext under the same key/boots/time must produce different salts and different
ciphertext (a keystream-reuse detector, since a repeat would make `C1 XOR C2` all-zero); the
`fixedForInterop` reuse tripwire fires for AES and — because its IV has no clock input — for DES
even when `engineTime` moves; the adjacent-only limit of that tripwire is pinned by an `A, B, A`
test that asserts the repeat is *not* caught; the DES 2^32-per-boots budget refuses to wrap; and
two `V3Client`s against engines with different clocks start their counters at different values.
**151 tests** (150 + 1 gated live). Run: `zig build test-snmp`.

The v3 stack is anchored three independent ways:

1. **RFC KATs.** RFC 3414 Appendix A.3.1/A.3.2: MD5 `Ku` = `9f af 32 …`, MD5 `Kul` =
   `52 6f 5e ed …`, SHA-1 `Ku` = `9f b5 cc 03 …`, SHA-1 `Kul` = `66 95 fe bc …` — all byte-exact.
   RFC 7860 publishes no vectors, so its six localized keys are pinned against an independent
   recomputation of the §A.2 formula *and* against net-snmp's own stored `usmUser` rows.

2. **Byte-exact net-snmp goldens** (`src/interop.zig`). Fifteen complete datagrams captured from
   `snmpget -v3 -d` against a stock net-snmp 5.9.4 `snmpd` — discovery probe, discovery Report,
   authNoPriv MD5, authPriv SHA-1+DES, SHA-1+AES, SHA-256+AES, SHA-512+AES (request *and*
   response for each), and three error Reports (`wrongDigests`, `unknownUserNames`,
   `unsupportedSecLevels`). For every one the tests parse and **re-encode the nested
   `msgSecurityParameters` byte-identically**; verify **net-snmp's own HMAC** under a key we derive
   from the password; zero the auth field and **regenerate the whole datagram bit-for-bit**;
   decrypt the authPriv ScopedPDUs and check the PDU inside. Nothing here comes from a real device —
   the engine ID is the literal text `rfc3414-example`, and the password is the public RFC 3414 A.3
   example `maplesyrup`.

3. **Live interop.** `SNMP_TEST_AGENT=host:port` runs discovery + a GET + a walk against a real
   agent (`SNMP_TEST_USER`, `SNMP_TEST_AUTH_PROTO`, `SNMP_TEST_PRIV_PROTO`, `SNMP_TEST_LEVEL`,
   `SNMP_TEST_*_PASSWORD` select the rest). Without the variable it prints `SKIPPED:` and passes,
   like the live tests in `netconf` and `tc`. Executed 2026-07-23 against an unprivileged net-snmp
   5.9.4 `snmpd` on `udp:127.0.0.1:11161` — all green:

   | user | level | auth | priv | result |
   |---|---|---|---|---|
   | md5User | authNoPriv | HMAC-MD5-96 | — | sysName.0 read |
   | shaDesUser | authPriv | HMAC-SHA-1-96 | DES-CBC | sysName.0 read |
   | shaAesUser | authPriv | HMAC-SHA-1-96 | AES-128-CFB | sysName.0 read |
   | sha224User | authPriv | HMAC-128-SHA-224 | AES-128-CFB | sysName.0 read |
   | sha256User | authPriv | HMAC-192-SHA-256 | AES-128-CFB | sysName.0 read |
   | sha384User | authPriv | HMAC-256-SHA-384 | AES-128-CFB | sysName.0 read |
   | sha512User | authPriv | HMAC-384-SHA-512 | AES-128-CFB | sysName.0 read |
   | shaAesUser | noAuthNoPriv | — | — | exchange OK, agent VACM returns `authorizationError` |

   The `snmpd.conf` that produces this matrix is reproduced at the top of `src/interop.zig`.

Hostile-input coverage for v3: truncated/oversized/garbage security parameters; an auth field whose
length is not the protocol's truncation length (both too short and too long, in a real envelope);
the wrong auth protocol applied to a real datagram; a ScopedPDU that fails to decrypt (wrong salt,
non-multiple-of-8 DES ciphertext, wrong-length salt); a Report with an unknown OID, no varbind, a
non-Counter32 value, or extra varbinds; an out-of-window timestamp; msgID and request-id mismatch;
a reply from a different engine; security-level downgrade; and full truncation + bit-flip sweeps
over both the captured net-snmp datagrams and a live authPriv reply. Every one is a typed error.

## Backlog / deferred
Agent (engine/server) role; MIB compiler / SMI parsing; AES-192/256 privacy (draft-blumenthal /
Cisco variants); SNMPv3 over TLS/DTLS (RFC 6353); RFC 3826 `usmDHKickstart` and the `KeyChange`
(key-update) TC; context-engine-ID proxy forwarding; v3 **notifications** (authenticated Trap/Inform
send + receive — `receiver` is still v1/v2c only). The security-review pass on `snmp.usm`
const-time/alg-confusion (see Threat model above) is done — clean, 2026-07-10.

## Status
`gap · any · codec+client · single_owner` + deps: none (std only) — canonical source is
`pub const meta` in src/root.zig.
