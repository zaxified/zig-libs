# `tlsserver` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-21** — M3 step 3, the per-connection wipe. `Outbound.wipe` zeroed the whole output
  buffer with `std.crypto.secureZero` (a byte at a time: ~16 µs for qap's 48 KiB, on every
  connection); it now zeroes up to the high-water mark of what was written (`Outbound.dirty`,
  `Outbound.touch`), with volatile 32-byte stores (`src/zeroize.zig`, copied from `http`). The
  joiner reset and the ticket/PSK scratch use the same store. New `Server.abandonWrite(n)`
  (`Connection.deinit` calls it for a half-written record). Tests: every path that writes the
  output is zero after `wipe`; a slot written and never committed is zero after `deinit`.
- **2026-10-21** — SPEC backlog only: the client leaf's cap (`clientauth.max_leaf_len`, 4096) as
  a caller-supplied buffer, asked for by qap's tlsserver branch (`Tls.max_client_cert_bytes`
  goes up to 16384). No code change.
- **2026-10-21** — M3 step 2, qap's zero-copy seams. **BREAKING** `Connection.init(config,
  input, output, joiner_buf)`: no output buffer of its own — records are sealed in the
  transport writer's buffer (size it with `minOutputLen`; it must be stream-shaped, `flush`
  emptying it in place), so a connection holds one send buffer instead of two and nothing is
  copied. New `Connection.reader()` / `writer()`: a `std.Io.Reader` over the record just opened
  where it lies in the input, a `std.Io.Writer` whose buffer is the next record's content in the
  output (sealed in place; a short write topped up, not sent alone); cross-record contiguity is
  `error.RecordBoundary` (qap's `RecordReader`/`RecordWriter` contract, without their stepping
  aside for KeyUpdates — the server handles those). `Connection.flush`, `Connection.err`. New
  `Server.writeSlot()` / `commitWrite(n)`; `Server.write` is built on them. Evidence: the 49
  recorded sessions replay byte-exact through `reader()`/`writer()` too; record layout, ordering
  across a read, KeyUpdate precedence and drain's splat pinned by new tests; 10/10 mutants of
  the new code killed (4 survived the first test set); BoGo 339/0, tlsfuzzer 0 worse (both over
  sockets through the new `Connection`); fuzz server + keyupdate 60k each clean. Sonnet review: no
  HIGH; fixed: no reader/writer alias survives `deinit`, `writeAll` into an output that never
  takes a record is `OutputFull` (was a loop), an unsealed slot is wiped when sealing fails, a
  one-octet splat is a memset; documented: end of transport without close_notify is
  `error.EndOfStream` in `err` (a truncation, as the fork's `TlsConnectionTruncated`).
- **2026-10-21** — M3 step 1: `tls13`'s key exchange and ECDSA now run on `ct25519`/`p256`/
  `p384`; server-side handshakes per second (P-256 certificate, X25519,
  TLS_AES_256_GCM_SHA384) 2,012 → 6,705, P-384 506 → 1,832 (SPEC *Backlog*). New opt-in
  bench in `interop_replay_test.zig` (`TLSSERVER_BENCH=1|<case>`, an optimized test binary):
  replays recorded sessions, server work only; the recorded keys are parsed once (an RSA key's
  CRT set-up cost more than a handshake). Interop vectors recaptured (P-384 signatures are RFC
  6979's now): OpenSSL 3.5.5 and Go 1.26.8, 49/49; BoGo 339/0 and tlsfuzzer unchanged.
- **2026-10-21** — tlsfuzzer gate (M2 exit gate). `interop-tlsserver -- --tlsfuzzer DIR` runs
  50 TLS 1.3 tlsfuzzer scripts (new `tools/tlsfuzzer.zig`: three loopback listeners — plain,
  optional client certificates, echo — a key per client scheme list through the new
  `server.firstUsableKey`, tickets, the `GET /keyupdate` convention) and holds their counts
  in `tools/tlsfuzzer/baseline.tsv` (`--tlsfuzzer-update` rewrites them, notes kept). Against
  qap's fork none of its 17 scripts is worse but two deliberate divergences, three are better.
  Found and fixed: a `legacy_version` below 0x0301 beside 0x0304 is now `protocol_version`
  (legacy-version 2/8 → 10/0); a key_share for a group not in `supported_groups`, or for an
  obsolete one, is `illegal_parameter`; `Server.write` no longer cuts a record short to fit
  behind pending output (`OutputFull` until it is sent; new `full_record_output_len`) — the
  echo script saw a 14,000-octet write leave as two records. Tried and reverted, with tests
  pinning the choice: refusing obsolete groups in `supported_groups` (BoGo `Server-JDK11-*`: JDK
  11 lists them beside TLS 1.3) and `decode_error` for a Finished of the wrong length (BoGo
  `TrailingMessageData-TLS13-ClientFinished-TLS`, owed to rustls). BoGo 339 / 0 unchanged,
  rustls parity unchanged; 10/10 planted mutants caught; fuzz `tlsserver-server`,
  `-keyupdate`, `-hello`, `-clientauth` 60k each, clean.
- **2026-10-20** — rustls parity gate (M2 step 6). New `tools/bogo/rustls_parity.py`: the BoGo
  server tests at TLS 1.3 that rustls 0.23.43 (aws-lc-rs) passes, reconstructed from its
  `bogo/config.json.in` and its shim's option table, each test's flags captured from the pinned
  runner → `tools/bogo/rustls-owed.txt` (436); `interop-tlsserver -- --bogo` reports the gate
  (`GAP` lines): 247 pass, 140 disabled with a reason (121 TLS 1.2, 19 divergences), 49 gaps
  (0-RTT, certificate compression, P-521 / ML-DSA keys, ML-KEM-1024). New API:
  `Config.server_order` (suite and group in the server's order), `Config.max_fragment_len`
  (records sent split at it, clamped to [512, 2^14]; `outbound.Outbound.max_fragment`,
  `outbound.min_fragment`; `minOutputLen` counts the extra records),
  `CertifiedKey.signature_schemes` (restrict and order the CertificateVerify schemes),
  `Server.usedHelloRetryRequest`, `Server.ticketAgeSkew`. BoGo 339 pass / 0 fail (was 286;
  shim `-expect-hrr`/`-expect-no-hrr`, `-signing-prefs`, `-server-preference`,
  `-max-send-fragment`, `-no-ticket`, `-resumption-delay`, `-expect-ticket-age-skew`, ALPN
  decline / reject / `-expect-advertised-alpn`, `-expect-peer-verify-pref`,
  `-expect-early-data-reason disabled`); `Basic-Server-*` (TLS 1.2 without a version in the name)
  and the TLS ≤ 1.2 tests the new flags unhid disabled precisely. 14/14 planted mutants caught (3
  survived the first tests: short messages and a roomy buffer hid the fragment size; a 64 KiB
  chain and a full-slot commit added). Fuzz `tlsserver-server`, `-keyupdate`, `-hello` 60k each,
  clean. Independent review (Sonnet): no HIGH or MEDIUM; LOW fixed (`server_order` could choose
  an unknown suite enabled in the configuration → `unreachable`).
- **2026-10-20** — OCSP and SCT stapling (M2 step 5). New `CertifiedKey.sct_list` (a
  `SignedCertificateTimestampList`, RFC 6962 §3.3) sent on the leaf when the ClientHello carries
  `signed_certificate_timestamp` (`hello.ClientHello.sct_requested`; a non-empty body is
  `decode_error`); `messages.CertificateEntry.sct_list`. New `CertifiedKey.check()`
  (`CheckError`: chain length 1..`max_chain_len` (16), certificate lengths, the whole
  Certificate message within 2^24-1, a well-formed SCT list, the leaf's extensions within
  2^16-1), also run on every selected key (failure: `internal_error`). **BEHAVIOURAL:** an empty `ocsp_response` (or `sct_list`) now counts as none,
  as in rustls (it used to fail the handshake with `internal_error`). BoGo 286 pass / 0 fail (was
  274; shim `-ocsp-response`, `-signed-cert-timestamps`; `OCSPStapling-Server-TLS13-*`,
  `SignedCertificateTimestampList-Server-TLS-TLS13`, `SignedCertificateTimestampListInvalid-Server`,
  `UnsolicitedCertificateExtensions-TLS-TLS13`, `SendNoExtensionsOnIntermediate-TLS13`); interop
  49/49 (OpenSSL `-status` with and without, Go checks the staple and both SCTs octet for octet;
  recaptured); fuzz `tlsserver-hello` 1.2M (SCT in the model), `tlsserver-server` and
  `tlsserver-keyupdate` 80k each, clean; 10/10 planted mutants caught (one after a new test).
  Independent review (Sonnet): no HIGH; MEDIUM fixed (`check` did not bound the whole chain);
  LOW fixed (the BoGo shim sized its output without the staple); two LOWs documented in SPEC.
- **2026-10-20** — Client certificates (M2 step 4). New `Config.client_auth` (`ClientAuth`: a
  `ClientCertVerifier`, `mandatory` (default), `schemes` (rustls's list), `authorities`, a
  `Clock`), `clientauth` (Certificate / CertificateVerify decoders, `leafPublicKey`,
  `checkLeafKeyUsage`, `X509Verifier` = `x509.verifyChain` with clientAuth),
  `Server.peerCertificate` / `peerSignatureScheme`. A full handshake sends a CertificateRequest;
  an empty Certificate is `certificate_required` when mandatory; the leaf must have a key the
  server verifies and, with a keyUsage, `digitalSignature`; the verifier's refusal names its
  alert; the CertificateVerify must use a requested TLS 1.3 scheme suiting the key
  (`illegal_parameter`) and verify (`decrypt_error`). **BREAKING:** `minOutputLen(config, key)`
  (was `minOutputLen(key)`): it now also sizes the CertificateRequest and the tickets.
  **BEHAVIOURAL:** the ticket format is 2 (it carries the client's leaf and signature scheme;
  format-1 tickets are not resumed); with a mandatory certificate a ticket without one is not
  resumed (stricter than rustls); `burn.handshake_burn` is 32 KiB. KAT: RFC 8448 §6 (the client's
  RSA Certificate, RSA-PSS CertificateVerify and Finished verified on the server's side; the
  CertificateRequest byte-exact). Interop 46/46 (11 new mTLS sessions with OpenSSL and Go,
  recaptured); BoGo 274 pass / 0 fail (was 166; the run found the missing keyUsage check);
  fuzz: new harness `tlsserver-clientauth` (6M runs clean), `tlsserver-server` (client-flight
  reseal, 240k clean) and `tlsserver-keyupdate` (80k clean) on the mTLS recordings; 17/17
  planted mutants caught (two after new tests), 18/18 with the review fix. New test fixtures
  `test_client_fixtures` (`tools/client_certs.py`). Independent review (Sonnet): no HIGH; MEDIUM
  fixed — re-issued tickets kept a client certificate alive indefinitely; a ticket now carries
  when the certificate was proved and is not resumed past the lifetime from then (stricter than
  rustls). LOWs fixed: unknown revocation status → `certificate_unknown`, the shim's drain
  bounded in time, a failed handshake clears `peerCertificate`.
- **2026-10-20** — Session tickets and PSK resumption (M2 step 3). New `Config.tickets`
  (`Tickets`: a `Ticketer` — `StekTicketer` over a `tlsresume.StekRing` — a `Clock`, `count` 2,
  `lifetime_s` 12 h, capped at 7 days); `Server.isResumed`. After the client's Finished the
  server sends the tickets packed into one record, each with a GREASE extension, none when the
  client does not offer `psk_dhe_ke`. **BEHAVIOURAL** (with `tickets` set): a `pre_shared_key`
  offer is resumed through `tlsresume.select.selectPsk` when a ticket opens and matches suite,
  SNI and lifetime (rustls `can_resume`); its binder not verifying is `decrypt_error`. Without
  `tickets` nothing changes (offer ignored). Interop: OpenSSL `-sess_out/-sess_in` and Go
  (file session cache) save and resume, also after a HelloRetryRequest (35/35, recaptured);
  BoGo 166/0; fuzz `tlsserver-server` gains ticket/binder flips, `tlsserver-keyupdate` opens the
  tickets; 14/14 planted mutants caught. Found on the way: `TicketFields.parse` overflowed `u8`
  on a 255-octet ALPN (fixed before commit). Independent review (Sonnet): no HIGH/MEDIUM; fixed:
  the master secret is wiped once the tickets are out, `lifetime_s = 0` issues no tickets; documented:
  `StekTicketer` lifetime, one ring = one trust domain, an overdue key seals unopenable tickets.
  New dep `tlsresume`.
- **2026-10-20** — KeyUpdate both ways (M2 step 2). **BEHAVIOURAL:** a client's KeyUpdate turns
  the receive key over (was `unexpected_message`); `update_requested` is answered with one
  KeyUpdate of the server's, before its next record (one, however many requests come before it
  goes out — rustls); more than `max_key_updates` (32) KeyUpdates between two application-data
  records is `unexpected_message` (`TooManyKeyUpdates`), an invalid request octet
  `illegal_parameter`, a KeyUpdate not ending its record `unexpected_message`. At
  `max_records_per_key` the server rekeys with `update_requested` instead of closing
  (`KeyLimitReached` is gone). New `Server.keyUpdate` / `Connection.keyUpdate`. The output
  buffer now always keeps room for one alert (`outbound.alert_reserve`, 24 octets): a fatal
  alert or close_notify used to be dropped silently when the application had filled the output
  (found by the new fuzz harness). Interop: three sessions where the server asks for a KeyUpdate
  (two OpenSSL, one Go; captured, replayed), `tlsclient` both ways under every suite; BoGo 142
  pass / 0 fail (`KeyUpdate-ToServer`, `KeyUpdate-FromServer` back); new fuzz harness
  `tlsserver-keyupdate` (a model client following every key; 48,000 runs clean, seven planted
  mutants caught). Independent review: no HIGH or MEDIUM; LOWs fixed — `Connection.keyUpdate`
  reports `OutputFull` instead of leaving a KeyUpdate due behind a too-small buffer,
  `keyUpdate(.update_requested)` upgrades a queued unrequested one, `minOutputLen` counts the
  alert reserve, `close` wipes the dead send secret.
- **2026-10-20** — HelloRetryRequest (M2 step 1). **BEHAVIOURAL:** a client without a share for
  the chosen group gets a HelloRetryRequest naming it (was `handshake_failure`); the second
  ClientHello must keep the HelloRetryRequest's suite and group (stricter than rustls, which
  re-chooses), the same SNI and no `early_data`, else `illegal_parameter`; the transcript restarts with `message_hash`, and early
  data announced by the first ClientHello is skipped in the clear (up to 2^14 octets of
  ciphertext). `minOutputLen` now also holds the HelloRetryRequest. Interop: two OpenSSL and two
  Go HelloRetryRequest sessions (captured, replayed), six `tlsclient` ones; BoGo 140 pass / 0
  fail (was 130; one rustls-parity divergence disabled with its reason); fuzz `tlsserver-server`
  60,000 and `tlsserver-inbound` 1.2M runs clean.
- **2026-10-20** — The BoGo shim (`tools/bogo_shim.zig`, `zig build interop-tlsserver -- --bogo`):
  BoringSSL's runner at 784fcafc, reviewed in full and pinned by `tools/bogo/MANIFEST`, 130 tests
  pass, none fail (`tools/bogo/passing.txt` ratchets them). **BEHAVIOURAL**, from its first run:
  the version is checked before anything else the ClientHello lacks (`protocol_version`, was
  `handshake_failure` for an old client without `signature_algorithms`); no `supported_groups`
  or no `key_share` is `missing_extension` (was `handshake_failure`; RFC 8446 §9.2); a
  signature scheme the key cannot produce is not chosen (`tls13.certverify.canSign`: a 1024-bit
  RSA key and `rsa_pss_rsae_sha512` now refuse with `handshake_failure`, were `internal_error`).
- **2026-10-20** — Fuzz harness `tlsserver-server`: the whole `Server` on the recorded OpenSSL and
  Go client streams — genuine in random chunks and octet by octet, truncated, bit-flipped in
  bodies and headers, spliced, and (white box) the client's Finished resealed damaged or padded;
  alert and failed-state invariants on every run. 160,000 runs clean, five planted mutants
  caught. The interop replay test is renamed for the Go sessions it now covers.
- **2026-10-20** — `Server.negotiatedGroup` and `Server.alpnProtocol`. Interop with Go 1.26's
  crypto/tls client (`tools/go_client/main.go`, ten sessions in `tools/interop.zig`, captured and
  replayed byte-exact with the OpenSSL ones: Go's defaults, every suite, secp256r1/secp384r1,
  P-384/Ed25519/RSA-PSS certificates, ALPN, no SNI, X25519 without the hybrid) and in-process
  handshakes against the collection's `tlsclient` (every certificate kind, every group × suite,
  ALPN; new test dependency).
- **2026-10-20** — `keys.CertKeyPair`: the certificate chain and private key from PEM (SEC1
  `EC PRIVATE KEY`, PKCS#8 `PRIVATE KEY` for EC P-256/P-384, Ed25519 and RSA, PKCS#1 `RSA PRIVATE
  KEY`), the key checked against the leaf (`KeyMismatch`), its PEM body decoded in constant time
  (`b64ct`) under a 64 KiB burn. Anchored on keys the OpenSSL 3.5.5 command line wrote
  (`tools/key_vectors.py`); fuzz harness `tlsserver-keys` (120,000 runs clean, five mutants
  caught; an independent review's MEDIUM — an EC scalar ≥ the order accepted — and LOWs
  fixed before the first commit). New dependencies: `x509`, `rsa` (was test-only), `b64ct`.
- **2026-10-20** — secp384r1 key exchange (through `tls13.kex`) and ECDSA P-384 certificates.
  **BEHAVIOURAL:** `default_groups` gains secp384r1 (last), as qap's fork serves it. Interop with
  OpenSSL `s_client` grows to ten sessions (P-256 over secp384r1, a P-384 certificate over
  secp384r1), recaptured with freshly generated test certificates (`tools/test_certs.py` adds
  P-384).
- **2026-10-20** — `Connection`, the blocking wrapper over `std.Io.Reader`/`Writer` (in-place
  records in the reader's buffer). Interop with OpenSSL 3.5 `s_client` (`tools/interop.zig`:
  P-256, Ed25519 and RSA-PSS certificates, all suites, X25519MLKEM768/X25519/secp256r1, ALPN, no
  SNI), its sessions replayed byte-exact in the tests. **BEHAVIOURAL, not breaking:** a failure
  wipes every key and secret at once; `close` keeps the connection readable;
  `max_records_per_key` (2^23) ends a connection that has not rekeyed (no KeyUpdate yet); two
  compatibility CCS records are no longer accepted with one ClientHello; `test_fixtures`
  exports the test certificates.
- **2026-10-20** — The server: `Server` (sans-I/O full TLS 1.3 handshake with a certificate,
  then application data and close_notify), `Config` (fixed certificate or a `CertificateSelector`
  by SNI, enabled suites and groups, ALPN, the CSPRNG), `CertifiedKey`, `minOutputLen`. Negotiation
  and alerts follow rustls 0.23; no HelloRetryRequest, resumption, client certificates or
  KeyUpdate yet. `outbound` (records framed, fragmented at 2^14 and sealed in place);
  `inbound.Inbound.skip_early` skips rejected 0-RTT records (trial decryption);
  `messages.CertificateEntry.ocsp_response` replaces `ocspStatusData`. Verified by whole
  handshakes against Zig std's TLS client (three suites; X25519MLKEM768, X25519, secp256r1) and
  by every refusal's alert.
- **2026-10-20** — The server's handshake message encoders: `messages` (ServerHello,
  HelloRetryRequest, EncryptedExtensions, Certificate with per-entry extensions, CertificateVerify,
  Finished; ALPN and OCSP extension bodies), each rebuilt byte-exact from its fields against RFC
  8448 §3/§4/§5. The RFC extraction tool is now `tools/rfc8448_messages.py` (ClientHellos and the
  server's messages, `src/message_kat_vectors.zig`).
- **2026-10-20** — The ClientHello decoder: `hello.parseClientHello` (zero-copy, iterators over
  the wire lists; the extensions a TLS 1.3 server reads checked for form; duplicate extensions,
  `pre_shared_key` not last and mismatched PSK identity/binder counts refused; SNI classified
  as rustls does — DNS name, IP literal ignored, invalid). New dependency `netaddr` (IP literals
  in SNI). Anchored on RFC 8448 §3/§4/§5 ClientHellos (§4's binder hash reproduced); fuzz
  harness `tlsserver-hello` (4,000,000-run verdict clean, six planted mutants caught).
- **2026-10-20** — The receive side of the record layer: `inbound.Inbound` (records cut from a
  byte stream, plaintext or protected, into whole handshake messages, alerts and application
  data; joining across records and splitting within one, interleaving and key-change alignment,
  compatibility-mode CCS, plaintext alerts before the first protected record, application data
  only after the client's Finished) and `alert` (the message, what a received alert does,
  error → alert). Receive rules follow rustls 0.23. Fuzz harness `tlsserver-inbound`
  (1,200,000-run verdict clean, five planted mutants caught).
- **2026-10-20** — New module: a TLS 1.3 server, under construction; first piece the record
  layer (`record`: header, per-direction in-place `Protection.seal` / `open` for the AES-128-GCM,
  AES-256-GCM and ChaCha20-Poly1305 suites). Verified against the seven protected records of RFC
  8448 §3 and OpenSSL-sealed AES-256-GCM / ChaCha20-Poly1305 records; fuzz harness
  `tlsserver-record` (12,000,000-run verdict clean, five planted mutants caught) and a ReleaseFast
  stack probe.
