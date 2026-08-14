# dtls — spec

Design + fill-in notes for the next (crypto-implementing) agent. Usage: see
`./README.md`. Attribution/provenance: see `./NOTICE` (module-local for now —
see that file's placement note).

## Design & invariants

**STATUS UPDATE (crypto core AND flight engine landed):** the crypto-core
layer (`keyschedule.zig`, `aead.zig`) is REAL and KAT-validated — the 15
functions below are implemented (see each file's tests + `root.zig`'s module
doc for the oracles). The handshake FLIGHT ENGINE (`Connection.startHandshake`
/ `.handleFlight` / `.poll`) is now ALSO implemented — a real RFC 9147 §5
PSK-only (and, additively, `.cert_dhe` certificate-only) client+server
handshake, proven by an in-memory client↔server interop suite (see
`Connection.zig`'s tests and `root.zig`'s module doc for the full list of
what is exercised). The `error.HandshakeEngineNotImplemented` this section
used to describe no longer exists in the code. PSK-mode third-party interop
is also proven — a live wolfSSL 5.9.1 handshake in both roles, see "Live
third-party interop" below, which lists the four wire defects that only a
third-party peer could surface. 0-RTT/resumption/key update/CCM stay
explicitly out of scope, not stubbed; HelloRetryRequest is now IMPLEMENTED
(both roles, both key-exchange modes, including RFC 8446 §4.1.4's group
change). Certificate mode is
**no longer self-interop only** — a live wolfSSL certificate server is now
part of the suite (see "Live third-party interop"), including one run at a
256-byte peer MTU that forces wolfSSL to fragment its Certificate across
datagrams, a wolfSSL server that REQUIRES and verifies our client
certificate, and a wolfSSL certificate CLIENT that verifies the chain our
server presents. The rest of this SPEC
is the original design/recon notes; the itemized 15-function checklist below
is retained as an implementation record (all 15 are done).

**Layered, like this repo's other DTLS/TLS-family scaffolds
(`opcua`/`noise`/`x509`):** the wire-framing layer (`record.zig`,
`handshake.zig`, `flight.zig`, `messages.zig`) is real, pure, allocation-free
where practical, and operates only on caller-supplied byte slices — no I/O,
no wall-clock calls (`flight.zig`'s timer takes `now_ms` from the caller),
no key material. The crypto-core layer (`keyschedule.zig`, `aead.zig`) is now
real. `Connection.zig` wires the two together: `Config.validate`,
`clientInit`/`serverInit`, the application-data record path
(`installApplicationKeys` + `send`/`recv`), and `startHandshake` /
`handleFlight` / `poll` (the flight engine) are all real and tested — see
the "STATUS UPDATE" above.

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

(Historical note: this "once (1)-(15) are real" instruction has since been
carried out — `Connection.startHandshake`/`handleFlight`/`send`/`recv` no
longer have `@panic` placeholders; see the "STATUS UPDATE" at the top of this
file. Retained here as the original implementation record, not current
guidance.)

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
- **`signature_algorithms` extension negotiation (RFC 8446 §4.2.3) — LANDED
  (was listed as deferred here; corrected):** the ClientHello (both `.psk`
  and `.cert_dhe` modes) and a server's `CertificateRequest` now advertise
  `Config.signature_algorithms` (defaults to every scheme `certverify.zig`
  implements) for real; `Connection.zig`'s `selectSignatureScheme` picks the
  scheme a CertificateVerify signs with from the intersection of the peer's
  advertised list, `Config.signature_algorithms`, and
  `certverify.candidateSchemes(cc.private_key)` (what the configured key's
  FAMILY can actually sign under — RSA keys offer all three
  `rsa_pss_rsae_sha*` schemes, EC/Ed25519 keys exactly one each), failing
  with `error.NoSignatureSchemeOverlap` rather than a silent default when
  there is no overlap. `verifyPeerCert` additionally rejects (`error
  .SignatureSchemeNotAdvertised`) a peer's CertificateVerify that used a
  scheme THIS side never put in its own `signature_algorithms` — a downgrade
  guard, checked before the signature itself. `CertConfig` no longer carries
  a fixed `signature_scheme` field.
- **Still deferred (now explicit, not silently absent):** full RFC 5280 §6
  certification-path building (multi-hop chains, name constraints,
  `basicConstraints`/`keyUsage` policy checks, revocation) — `.trust_anchor`
  is a minimal one-hop check only; `CertificateEntry` extensions (OCSP
  stapling/SCT) — framed empty on send, length-validated-but-discarded on
  receive.
- **CLOSED GAP (corrected from an earlier draft of this SPEC):**
  `std.crypto.Certificate.parse` (Zig 0.16) was confirmed by fuzzing to be
  NOT panic-safe against malformed/adversarial DER — even trivial few-byte
  or random ~30-60-byte inputs reliably crashed the process via an
  unguarded array index deep in std's ASN.1 walker, rather than returning a
  typed error, and `certauth.zig` could not intercept a panic (Zig has no
  exception mechanism). This is no longer live: both `certauth.zig` entry
  points (`parseLeafPublicKey`, `verifyLeafAgainstAnchor`) now route
  PEER-supplied Certificate bytes through this collection's `x509` module's
  bounds-checked `spkiOf`/`safeCertificate` bridge first and never call
  `std.crypto.Certificate.parse` directly, so the same hardened parser
  `iec62351` and `opcua` already use closes this module's copy of the gap
  too. See `certauth.zig`'s module doc "CLOSED GAP" note for the full
  writeup, and its `test "parseLeafPublicKey: adversarial DER returns a
  typed error instead of panicking"` for the fuzz-style regression coverage
  (empty/truncated/malformed DER and a full truncation sweep of a real
  certificate, all typed-error, no crash).

## Cert-only (EC)DHE mode (RFC 8446 §4.2.8 key_share + X25519, LANDED)

**STATUS UPDATE:** the "genuine (EC)DHE-based, PSK-LESS certificate-only key
exchange" listed as deferred above is now IMPLEMENTED as a distinct handshake
mode, selected by `Config.key_exchange = .cert_dhe` (default stays `.psk`, so
every PSK / cert-over-PSK path and its RFC 8448 KATs are byte-for-byte
unaffected — proven by the untouched existing suite). Summary:

- **`messages.zig`:** `key_share` (RFC 8446 §4.2.8, ClientHello list +
  ServerHello single-entry forms), `supported_groups` (§4.2.7),
  `signature_algorithms` (§4.2.3) encode/decode, plus the `NamedGroup` enum.
  Both **X25519** (`0x001d`) and **secp256r1** (`0x0017`) are wired end to
  end; a fresh ClientHello offers an X25519 share and secp256r1 is used when
  a server names it in a HelloRetryRequest (RFC 8446 §4.1.4). `key_share`
  has a THIRD wire form for that message — a bare two-byte `selected_group`
  (`encode`/`decodeKeyShareHelloRetryRequest`), not interchangeable with the
  ServerHello form.
- **`Connection.zig`:** in `.cert_dhe` mode the ClientHello offers
  `{supported_groups, signature_algorithms, key_share}` with a fresh
  ephemeral X25519 keypair (`std.crypto.dh.X25519`, seeded from the
  caller-supplied `Entropy`) and **no `pre_shared_key`, no binder**; the
  ServerHello returns its own X25519 share. The ECDHE shared secret is fed
  into the **existing, unmodified** `keyschedule.deriveHandshakeSecret` (the
  early secret's IKM is the zero PSK, RFC 8446 §7.1 — the schedule was
  already DHE-capable, this only supplies the secret; the function was NOT
  forked). Server-only auth and mutual auth (`request_client_cert`) both work,
  reusing the same `certverify`/`certauth`/cert-message plumbing as
  cert-over-PSK mode. The ephemeral private key **and** the shared secret are
  `std.crypto.secureZero`-wiped as soon as the handshake secret is derived
  (forward-secrecy hygiene), and again in `deinit`.

**Validation / honesty:**
- **External-vector KAT (RFC 8448 §3):** the X25519 key_share computation
  (`recoverPublicKey` + `scalarmult`, both directions) and its feed into the
  key schedule reproduce RFC 8448 §3's published client/server X25519
  private+public keys, the `8bd4054f…` shared secret, and the derived
  early+handshake secrets byte-for-byte. §3 is a psk_dhe_ke trace, but its
  ECDHE math is identical and its early secret is over an all-zero PSK —
  exactly this mode's construction.
- **Live third-party peer (no external BYTE vector):** the full cert-only
  wire FLOW (ClientHello→ServerHello→{EE,[CertReq],Cert,CertVerify,
  Finished}→…). **No public DTLS 1.3 cert-only byte-trace exists**, so there
  is no KAT for the flow itself; instead it is driven end to end against a
  live wolfSSL 5.9.1 certificate server (PSK-less X25519 (EC)DHE + an ECDSA
  P-256 chain that must verify against this repo's own trust anchor), and
  additionally at a 256-byte peer MTU so the Certificate arrives fragmented.
  The in-memory client↔server suite remains for the paths a single live peer
  cannot drive — mutual auth and the reject-teeth (tampered ServerHello
  key_share, wrong CertificateVerify key, untrusted anchor, missing
  key_share). Going live immediately found a defect of exactly the class
  self-interop cannot find: the `.cert_dhe` ClientHello carried no
  `supported_versions`, so a real server negotiated DTLS 1.2.

  The two remaining certificate-mode gaps an earlier version of this section
  listed are now closed, both live: a wolfSSL server with
  `VERIFY_PEER | FAIL_IF_NO_PEER_CERT` and the fixture anchor as its only CA
  verifies OUR client's Certificate + CertificateVerify (mutual auth), and a
  real wolfSSL certificate CLIENT verifies the chain our server presents
  (`wolfSSL_get_verify_result` asserted inside the peer). The first found a
  sixth defect of the same family: the client decoded a CertificateRequest's
  `signature_algorithms` into a fixed `[8]u16`, so a real peer's list
  (wolfSSL sends 16) came back `TooManyExtensions` → `Malformed` — the same
  mistake the ClientHello path had already been fixed for, surviving here
  because only our own server had ever sent a CertificateRequest.

- **secp256r1 ECDH KAT (Python `cryptography` / OpenSSL 3.5.5):** two fixed
  scalars, their SEC1 uncompressed points, and the ECDH output — which for
  the NIST curves is the shared point's X COORDINATE only (RFC 8446 §7.4.2),
  not the point encoding. An independent oracle, since the RFC 8448 vector
  covers only the X25519 half.

**Untrusted-DER hazard (unchanged, inherited):** `.cert_dhe` mode parses the
same PEER-supplied X.509 via the same `certauth` path, so it inherits the
`std.crypto.Certificate.parse` non-panic-safety gap documented below /  in
`certauth.zig` verbatim — this pass adds no new cert-parse call sites beyond
that path and does not worsen it; hardened DER parsing remains the tracked
follow-up.

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

## Live third-party interop — done, and what it cost

`src/wolfssl_interop.zig` runs a real DTLS 1.3 PSK handshake over a loopback
UDP socket against **wolfSSL 5.9.1**, in both roles, each followed by an
application-data round trip.

**The oracle ranking this section used to carry was wrong, and the error was
not a detail.** It ranked OpenSSL first on the claim that "OpenSSL 3.2+ has
DTLS 1.3 support". OpenSSL has no DTLS 1.3 at all as of 3.5.5 — `s_server`
offers only `-dtls1`/`-dtls1_2` — and GnuTLS 3.8.12, ranked second, stops at
`VERS-DTLS1.2` (`+VERS-DTLS1.3` is not even a recognised token). Both
"recommendations" were untested assumptions, and acting on them produced a
backlog entry that read "blocked: no DTLS 1.3 peer exists" for as long as
nobody checked what could be *installed*. wolfSSL was packaged the whole
time (`libwolfssl-dev`, built with `WOLFSSL_DTLS13`).

The peer is a ~170-line C program (`src/testdata/wolfssl_peer.c`) embedded
into the test and compiled with `cc` at test time, so the test carries its
own oracle; it skips loudly when `cc` or wolfSSL is absent.

### What it found

Four wire defects, none of which self-interop could ever have caught — a
self-interop suite has both sides make the same mistake in lockstep:

1. **The ClientHello had no `legacy_cookie` field at all** (RFC 9147 §5.3).
   DTLS 1.3 moved the cookie into a HelloRetryRequest extension but keeps
   the legacy field, present and empty. Omitting it shifts every following
   byte, so the peer read the compression-methods length as half of
   `cipher_suites`' — `alert(fatal, decode_error)`.
2. **The PSK binder covered two bytes too many.** RFC 8446 §4.2.11.2 hashes
   the ClientHello "up to and including the `identities` field", i.e. with
   the whole binders **list** removed — and a list, being a vector, starts
   at its own 2-byte length prefix. Both sides here truncated 1 byte later,
   agreed with each other, and disagreed with everyone else:
   `alert(illegal_parameter)`, "binder does not verify".
3. **Neither Hello carried `supported_versions`.** Every version field on
   the wire reads DTLS 1.2 by design (RFC 9147 §5.3), so this extension is
   the only place the negotiated version appears. Without it a peer cannot
   tell 1.3 was meant. The client now sends it and *requires* it in the
   ServerHello (`error.VersionNotNegotiated` / `error.UnsupportedVersion`) —
   a downgrade guard, not just a compatibility fix.
4. **The server never ACKed the client's final flight** (RFC 9147 §7.1).
   The spec's list of implicitly-acknowledged flights is "handshake flights
   *other than* the client's final flight of the main handshake"; all others
   "MUST be ACKed". Nothing follows that flight to carry an implicit ack, so
   a silent server leaves a conforming client blocked in `connect` forever.

A fifth was a robustness bug rather than a wire bug: the server decoded a
peer's `signature_algorithms` into a fixed `[8]u16` and returned
`error.Malformed` when it overflowed. wolfSSL advertises 18 schemes and
OpenSSL a similar number, so any real client was rejected as malformed. The
list is now filtered against the schemes this module can actually select,
which bounds the buffer by OUR list instead of the peer's.

A **sixth** was the identical bug on the OTHER side of the same extension:
the CLIENT decoded a `CertificateRequest`'s `signature_algorithms` with
`decodeU16ListExtension` into a fixed `[8]u16`, so a real peer's list
(wolfSSL 5.9.1 sends 16) became `TooManyExtensions` → `Malformed` and mutual
auth against a third party could not complete at all. Only our own server
had ever sent a `CertificateRequest`, and its list is short — so the fix
applied to the ClientHello path never reached this one. Found the day the
live mutual-auth test was written; same `filterU16ListExtension` fix.

### Mutation testing: cert-mode HelloRetryRequest + secp256r1

Every central invariant of the §4.1.4 work was deliberately broken and the
suite re-run. What each mutation cost:

| mutation | caught by |
|---|---|
| keep ClientHello1's `key_share` instead of regenerating in the named group | the group-change unit tests (`ecdhe_group` assertions) |
| ALWAYS regenerate, even for a cookie-only retry (a §4.1.2 violation) | the cookie-only unit test's byte-identical `key_share` assertion — nothing else, wolfSSL accepts it |
| draw a fresh ClientHello2 `random` | the §4.1.2 conformance comparator |
| accept a retry naming a group already offered | its reject test (the retry-loop guard) |
| accept a retry naming a group never advertised | its reject test |
| secp256r1 shared secret = the Y coordinate instead of X | the OpenSSL-derived ECDH KAT |
| drop the "ServerHello share must be in the group we offered" check | its reject test — **but only after the test was fixed.** The original version sent a 65-byte P-256 point, which the length check inside `ecdheSharedSecret` also rejects, so both the correct and the mutated code returned `MissingKeyShare` and the test passed either way. It now sends a 32-byte value labelled secp256r1, where only the GROUP is wrong |
| RFC 8446 §4.4.1's synthetic `message_hash` type changed 254 → 253 (both sides share the constant) | **only** the live wolfSSL tests. All 18 local HelloRetryRequest tests stay green — the two sides simply agree on a transcript nobody else computes |
| revert the `CertificateRequest` `signature_algorithms` fix above | **only** the live mutual-auth test (230 other tests passed) |

Two of those are worth keeping in mind. The second — a gratuitously
regenerated share — is a real protocol violation that **no live peer
objected to**, so a live oracle is necessary but not sufficient. The
seventh is the "it comes out the same either way" trap: a reject test whose
expected error is also produced by a *different* check downstream proves
nothing, and only mutation showed it.

Note that fully REMOVING `resetToMessageHash`'s body (rather than changing
the constant) is NOT a consistent mutation here and self-interop does catch
it: our server is stateless, so it rebuilds the transcript on a brand-new
`Connection` whose hasher starts empty, while the client's would still carry
ClientHello1 — the two diverge. Only a mutation that keeps both sides doing
the same wrong thing hides from self-interop.

### Proven against wolfSSL: the HelloRetryRequest cookie exchange, both roles

RFC 9147 §5.1's return-routability check runs in both directions against a
real peer: our client against a default-configured wolfSSL server
(`server-hrr` peer mode), and our server — with `Config.hello_retry` set —
against a stock wolfSSL client. Both live tests assert the retry ACTUALLY
happened (`Connection.sawHelloRetryRequest`), so neither can silently decay
into a duplicate of the no-retry test if the exchange stops taking effect.

Three mutations were run against the server side to check the tests have
teeth:

| mutation | caught by |
|---|---|
| `peer_binding` dropped from the cookie MAC | the cross-binding replay test + the cookie unit test — nothing else, and the handshake still completes |
| RFC 8446 §4.4.1's `message_hash` rewrite skipped when rebuilding the transcript | self-interop AND the live test (wolfSSL: binder does not verify) |
| `message_seq` not restored on the connection that handles ClientHello2 | **only** the live test — our own client ignores a ServerHello's `message_seq`, so every self-interop test stays green |

The last one is the argument for the live oracle in one line: a defect that
two `Connection`s written from the same reading of the RFC cannot see.

### Still not proven / not implemented

- **A cookie-rotation overlap window.** RFC 9147 §5.1 RECOMMENDS a server be
  able to accept the previous `cookie_secret` for a period, so clients
  handshaking across a rotation are not dropped. `HelloRetryConfig` takes one
  secret; a caller wanting the overlap must retry ClientHello2 under a second
  `Connection` configured with the older secret. Workable, but it is caller
  policy rather than something the module does.
- **A server-side cookie expiry.** Deliberate, not missing: RFC 9147 §5.1
  offers timestamps as an ALTERNATIVE to secret rotation, and rotation is
  what the API exposes. A clock would also be the first one this module
  reads.
- **A SERVER-initiated group change.** The client half of RFC 8446 §4.1.4's
  `key_share` path is implemented (a retry naming another advertised group
  is answered with a fresh share in it, live-anchored against wolfSSL); the
  server half is not. This server takes whichever offered share it can use
  and answers a ClientHello with nothing usable with
  `error.MissingKeyShare`, never a group-change retry — deciding a group
  before the cookie verifies would mean holding more state for an unverified
  peer, which is what `sendHelloRetryRequest` exists not to do.
- **`psk_dhe_ke`.** `.psk` mode stays PSK-only, so a retry carrying a
  `key_share` there is `error.HelloRetryRequestUnsupported` rather than a
  silent upgrade to an exchange this engine does not run.
- **Send-side fragmentation.** This engine reassembles what it RECEIVES but
  never splits what it SENDS, so it needs a peer MTU large enough for its
  own largest message (`max_cert_message_body` and friends). A peer that
  advertises a tiny MTU can be talked to, but cannot be talked to with a
  large certificate chain.
- **A whole flight RETRANSMITTED verbatim into an incomplete
  accumulation.** Fragmentation is handled; a peer resending an entire
  flight it already sent, mid-reassembly, is rejected and the caller must
  restart. Redundant fragments of the message being reassembled, and
  retransmitted copies of messages already consumed, are both absorbed. See
  `handleFlight`'s "KNOWN LIMIT".
- **More than ONE in-progress inbound message.** A fragment of a later
  handshake message arriving while an earlier one is incomplete is
  `error.InterleavedFragments` rather than buffered — the deliberate cap on
  attacker-driven memory (see `max_flight_bytes`). No conforming sender
  produces that ordering.
- **Certificate mode: MUTUAL auth against a third party.** The live cert
  test verifies wolfSSL's chain; our own client certificate has still only
  ever been checked by our own server.
- **A second independent stack.** wolfSSL agreeing with us rules out the
  four defects above, but a bug the two happen to share would still pass.
  mbedTLS or picotls would be the natural cross-check.
- **CCM suites** — unwired (Zig 0.16 std ships only a 13-byte-nonce CCM; the
  DTLS profile needs 12), so the RFC 7925 CoAP default suite is untested
  against any peer.

## Anchoring

**Anchor grade:** class A · oracle EXTERNAL

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle EXTERNAL** — published vectors, goldens captured from a foreign implementation, or a test run against a live foreign peer.

**What the tests actually contain.** live interop vs real wolfSSL 5.9.1 peer, both roles, multiple flows
