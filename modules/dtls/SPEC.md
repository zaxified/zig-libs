# dtls — spec

Design + fill-in notes for the next (crypto-implementing) agent. Usage: see
`./README.md`. Attribution/provenance: see `./NOTICE` (module-local for now —
see that file's placement note).

## Design & invariants

**STATUS UPDATE (crypto core landed):** the crypto-core layer
(`keyschedule.zig`, `aead.zig`) is now REAL and KAT-validated — the 15
functions below are implemented (see each file's tests + `root.zig`'s module
doc for the oracles). What remains deferred is the handshake FLIGHT ENGINE
(`Connection.startHandshake` returns `error.HandshakeEngineNotImplemented`).
The rest of this SPEC is the original design/recon notes; the itemized
15-function checklist below is retained as an implementation record.

**Layered, like this repo's other DTLS/TLS-family scaffolds
(`opcua`/`noise`/`x509`):** the wire-framing layer (`record.zig`,
`handshake.zig`, `flight.zig`, `messages.zig`) is real, pure, allocation-free
where practical, and operates only on caller-supplied byte slices — no I/O,
no wall-clock calls (`flight.zig`'s timer takes `now_ms` from the caller),
no key material. The crypto-core layer (`keyschedule.zig`, `aead.zig`) is now
real. `Connection.zig` wires the two together: `Config.validate`,
`clientInit`/`serverInit`, and the application-data record path
(`installApplicationKeys` + `send`/`recv`) are real and tested;
`startHandshake` (the flight engine) is the one deferred piece.

**Key correction to the recon below:** items reference DTLS reusing the TLS
1.3 key schedule "unchanged" and treating `hkdfExpandLabel` as a std
pass-through. That was WRONG — RFC 9147 §5.9 changes the label prefix to
`"dtls13"` (no trailing space); the implementation uses its own
`expandLabel` with that prefix. Also: "AES-CCM is NOT a std gap" holds only
for a 13-byte nonce; the TLS/DTLS 1.3 profile needs a 12-byte nonce, which
std's CCM presets don't offer, so CCM is left unwired.

## RFC 9147 recon vs. Zig 0.16 `std.crypto`

Recorded in detail in `root.zig`'s module doc comment (single source of
truth per CONVENTIONS.md §5) — summary: `std.crypto.tls.hkdfExpandLabel` is
genuinely `pub` and reusable (RFC 9147 §5.8 says DTLS 1.3's key schedule is
identical to TLS 1.3's), so `keyschedule.hkdfExpandLabel` calls it directly
rather than being stubbed. AES-CCM (incl. CCM_8, RFC 7925's IoT default) is
present in std (`std.crypto.aead.aes_ccm`) — NOT a gap, contrary to this
repo's earlier finding for a different AEAD need in `dnp3`. A real,
callable single-block AES-ECB primitive exists for the RFC 9147 §4.2.3
sequence-number mask (`std.crypto.core.aes.Aes128/Aes256.initEnc(key)
.encrypt(...)`). Nothing else in `std.crypto.tls` is reusable — transcript
hashing and HelloRetryRequest/cookie handling are inline in
`tls.Client.init`'s private ~1670-line state machine, not separate types.

## THE FABLE CORE — every function the next agent must implement

All in `src/keyschedule.zig` unless noted. Each stub's doc comment already
names the exact RFC section; this is the itemized checklist:

1. `keyschedule.earlySecret` — RFC 8446 §7.1, `HKDF-Extract(salt=0, IKM=PSK)`.
2. `keyschedule.binderKey` — RFC 8446 §7.1, `Derive-Secret(early_secret,
   "ext binder", "")`.
3. `keyschedule.pskBinder` — RFC 8446 §4.2.11.2, the PSK binder itself
   (HMAC over the truncated ClientHello1 transcript with a
   `"finished"`-labeled key derived from `binder_key`). **Most
   security-critical stub in this module** — a wrong/skipped check lets an
   attacker splice a PSK identity across connections.
4. `keyschedule.deriveHandshakeSecret` — RFC 8446 §7.1, handles both
   `psk_ke` (zero IKM) and `psk_dhe_ke` (real (EC)DHE shared secret) modes.
5. `keyschedule.deriveHandshakeTrafficSecrets` — RFC 8446 §7.1, `"c hs
   traffic"`/`"s hs traffic"` labels.
6. `keyschedule.deriveMasterSecret` — RFC 8446 §7.1.
7. `keyschedule.deriveApplicationTrafficSecrets` — RFC 8446 §7.1, `"c ap
   traffic"`/`"s ap traffic"` labels, transcript through server Finished.
8. `keyschedule.deriveFinishedKey` — RFC 8446 §7.1, `"finished"` label.
9. `keyschedule.computeFinishedVerifyData` — RFC 8446 §4.4.4, `HMAC
   (finished_key, transcript_hash)`; verifier side MUST compare in constant
   time (`std.crypto.timing_safe.eql`), never `std.mem.eql`.
10. `keyschedule.deriveTrafficKeyIv` — RFC 8446 §7.3, `"key"`/`"iv"` labels
    (the AEAD key + RFC 9147 §4.2.1's static IV).
11. `keyschedule.deriveSequenceNumberKey` — RFC 9147 §4.2.3, `"sn"` label
    (DTLS-specific, no TLS 1.3 equivalent).
12. `aead.Protection(Aead).nonce` — RFC 9147 §4.2.1, `static_iv XOR
    (epoch, sequence_number)` bit-packing — confirm exact byte placement
    against the RFC text.
13. `aead.Protection(Aead).protect` / `.unprotect` — RFC 9147 §4.2, AEAD
    seal/open of the DTLSInnerPlaintext (RFC 8446 §5.2 shape, reused
    unchanged) with the unified header as additional data.
14. `aead.encryptSequenceNumberAes` / `decryptSequenceNumberAes` — RFC 9147
    §4.2.3, AES-ECB-derived keystream mask over the on-wire sequence-number
    bytes.
15. `aead.encryptSequenceNumberChaCha20` / `decryptSequenceNumberChaCha20`
    — RFC 9147 §4.2.3's ChaCha20-suite equivalent (confirm it is NOT simply
    the AES path with the cipher swapped before assuming so).

Once (1)-(15) are real, `Connection.startHandshake`/`send`/`recv` need their
`@panic` calls replaced with the actual sequencing (each documents exactly
which real framing calls surround the panic today).

## Crypto-heaviness, honestly assessed vs. this repo's other scaffolds

**Confirmed, not refuted:** this module is genuinely more crypto-heavy than
`x509`. x509's gap (`chain.zig`) is a POLICY/decision algorithm over
already-correct primitives (`std.crypto.Certificate.Parsed.verify` does the
actual signature math); getting RFC 5280 §6 wrong yields a wrong
accept/reject decision on an otherwise-intact crypto operation. DTLS 1.3's
gap is deriving FRESH key material (HKDF label sequencing) and constructing
FRESH nonces (epoch/sequence-number bit-packing) — a labeling or bit-packing
mistake here doesn't just misapply correct crypto, it silently produces
DIFFERENT (still "successfully" computed) keys/nonces with no compile-time
or obvious-runtime signal, only an interop failure or, worse, a nonce reuse.

## Certificate mode (RFC 8446 §4.4, ADDITIVE — landed after the PSK core)

**STATUS UPDATE:** `Connection.zig` now also implements certificate-mode
Certificate/CertificateVerify/CertificateRequest (`messages.zig` framing +
`certverify.zig` sign/verify, reused unchanged, + the new `certauth.zig`
DER/std-Certificate bridge), layered on top of the unchanged PSK key
exchange — see `root.zig`'s module doc "Certificate mode" section and
`Connection.zig`'s own "certificate mode" section (right before
`handleFlightServer`) for the full design rationale. Summary of what
changed vs. the "Out of scope" list below (now stale on this one point —
left in place rather than silently deleted, corrected here):

- **Implemented:** Certificate/CertificateVerify/CertificateRequest wire
  framing; server always presents its cert when `Config.cert` is set;
  optional mutual auth via `Config.request_client_cert` +
  `Config.require_peer_cert`; peer-chain trust via `Config.peer_verify`
  (`.none` / `.trust_anchor` — a real one-hop `std.crypto.Certificate
  .Parsed.verify` check via `certauth.verifyLeafAgainstAnchor` — /
  `.verify_fn` escape hatch); real ECDSA-P256/P384, RSA-PSS, Ed25519
  signatures over the LIVE running transcript (not a fixed KAT string) via
  `certverify.sign`/`.verify`, unmodified. Proven by a real client↔server
  self-interop suite in `Connection.zig` (server-cert-only, mutual auth,
  wrong-key rejection, untrusted-anchor rejection, required-but-absent-cert
  rejection) — same in-memory-oracle style as the PSK suite, no external
  peer.
- **Still deferred (now explicit, not silently absent):** a genuine
  (EC)DHE-based, PSK-LESS certificate-only key exchange (this engine has no
  `key_share` extension/ECDH machinery at all — real new crypto, out of
  this pass's "plumbing over certverify" scope; certificates here
  AUTHENTICATE on top of the PSK exchange, they don't replace it);
  `signature_algorithms` extension negotiation; full RFC 5280 §6
  certification-path building (multi-hop chains, name constraints,
  `basicConstraints`/`keyUsage` policy checks, revocation) — `.trust_anchor`
  is a minimal one-hop check only; `CertificateEntry` extensions (OCSP
  stapling/SCT) — framed empty on send, length-validated-but-discarded on
  receive.
- **KNOWN GAP, not this module's to fix:** `std.crypto.Certificate.parse`
  (Zig 0.16) is confirmed (by fuzzing, during this work) NOT panic-safe
  against malformed/adversarial DER — even trivial few-byte or random
  ~30-60-byte inputs reliably crash the process via an unguarded array
  index deep in std's ASN.1 walker, rather than returning a typed error.
  `certauth.zig`'s own error handling cannot intercept a panic (Zig has no
  exception mechanism). A live deployment that feeds a PEER-supplied
  Certificate message's bytes into `certauth.parseLeafPublicKey`/
  `.verifyLeafAgainstAnchor` is exposed to a process-crash DoS from a
  malformed certificate until std fixes this (or a from-scratch hardened
  DER parser replaces this bridge — a real, substantial undertaking, out of
  a "no new crypto" Sonnet-tier pass). See `certauth.zig`'s module doc
  "KNOWN GAP" section for the full writeup + the fuzz evidence retained in
  that file's own test suite (`test "parseLeafPublicKey: ..."` intentionally
  does NOT test adversarial input for exactly this reason — see its
  comment).

## Threat model / out of scope

- **Out of scope, by design (not silently skipped):** session resumption /
  `NewSessionTicket` (no `"res binder"`/resumption-PSK path — only `"ext
  binder"`/externally-configured PSK), 0-RTT/early data, connection
  migration beyond the connection-ID field already framed in `record.zig`.
  (X.509/certificate auth was in this list originally — see "Certificate
  mode" above for what landed and what of it is still genuinely deferred.)
- Once `keyschedule.pskBinder` is implemented, it MUST be checked (server
  side) before trusting the offered PSK identity — a missing check is the
  single highest-impact bug this module could ship with.
- `aead.Protection.unprotect` must return the typed
  `error.DecryptionFailed` on any tag mismatch, never panic, never leak
  timing differences between "bad tag" and "bad padding"/other failure
  modes — attacker-controlled ciphertext must never reach a panic path.

## Verification once the crypto core lands

Recommended interop/verification oracles for PSK-mode DTLS 1.3, ranked by
how realistic they are to stand up given PSK-ONLY (no cert infrastructure
needed):

1. **OpenSSL `s_server`/`s_client -dtls1_3 -psk ... -cipher PSK-AES128-CCM8`
   (or the TLS 1.3 PSK cipher-suite equivalent) — most realistic.** OpenSSL
   3.2+ has DTLS 1.3 support and PSK mode needs zero certificate setup —
   just a shared hex key on both sides. This is the natural first oracle:
   run `openssl s_server -dtls -psk <hex> ... ` and have this module's
   client complete a real handshake against it (and vice versa, this
   module's `serverInit` against `openssl s_client -dtls1_3 -psk <hex>`).
2. **GnuTLS `gnutls-cli`/`gnutls-serv --dtls --pskusername/--pskkey`** — a
   second, independent implementation for cross-checking once OpenSSL
   interop works, catching bugs that happen to agree with OpenSSL's (or this
   module's) own misreading of the spec.
3. **mbedTLS/tinydtls test vectors or a built binary** — both are
   constrained-device-oriented DTLS stacks that default to PSK + CCM_8,
   closest in spirit to this module's target profile (RFC 7925 CoAP), but
   more work to stand up as a live oracle than OpenSSL/GnuTLS CLIs.
4. **RFC 8448-style traces adapted for DTLS 1.3** — RFC 8448 publishes full
   TLS 1.3 byte-exact handshake traces (including a PSK-resumption one) that
   are extremely convenient as KATs, but RFC 8448 has no direct DTLS 1.3
   counterpart yet; adapting one (re-deriving DTLS's different record/
   handshake headers around the same key-schedule secrets) is possible but
   is transcription work, not a drop-in vector source — treat this as a
   secondary/cross-check tool once (1)/(2) already pass, not the first oracle
   to reach for.
