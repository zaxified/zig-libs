# `tlsserver` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
