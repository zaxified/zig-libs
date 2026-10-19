# `tlsclient` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-19** — **Fix:** (std bug, remote server; panic in safe builds, write past `read_buffer` in ReleaseFast) the application read path decrypts each record in place after the plaintext the caller still has buffered, and std only *asserted* there was room for the whole ciphertext. A `peek`/`fill` of more than is buffered (e.g. a delimiter search) with over `min_buffer_len - record` octets still buffered, met by a full-size record (a legal 2^14-octet one is enough on a `min_buffer_len` buffer with 261 octets buffered), now fails the read with `TlsRecordOverflow` instead. Regression test in `src/fuzz_test.zig` ("a full record with the caller's plaintext still buffered …"), negative control checked (fix reverted: the assert fires).

- **2026-10-19** — **NO CONSUMER-VISIBLE CHANGE:** Deprecated std names replaced by their Zig 0.17 spellings (`mem.indexOf*` -> `mem.find*`, `fmt.bufPrint` -> `mem.print`, `fmt.allocPrint(a, …)` -> `a.print(…)`, `bufPrintSentinel` -> `mem.printSentinel`, `@intFromEnum` -> `@backingInt`); the old names are aliases, so behaviour is identical.

- **2026-10-18** — **NO CONSUMER-VISIBLE CHANGE:** Docs: README/SPEC statements about std's unchecked DER reader (`Certificate.parse`) re-read against the 0.17.0 std (unchanged); 0.16-only measurements are labelled as such.

- **2026-10-18** — FIX (std bugs, remote, authenticated peer; panic in safe builds, UB in ReleaseFast): malformed post-handshake messages now end the read with an alert error instead of panicking. A KeyUpdate whose body is not exactly one octet is `TlsDecodeError` (decode_error; checked before the traffic key and `read_seq` are switched; std 0.17 added the same check), a KeyUpdate on a TLS 1.2 connection is `TlsUnexpectedMessage` (it read the inactive `tls_1_3` union field), and an empty or shorter-than-4-octet handshake fragment is `TlsDecodeError` (std indexed past the record). Regression tests in `src/fuzz_test.zig`, each with a documented negative control.
- **2026-10-18** — Ported to Zig 0.17.0. `Client.zig` stays the 0.16.0 copy (the std 0.17 diff is renames plus length checks this copy already has); `root.zig`'s version tripwire now accepts 0.16 and 0.17. Record nonces: `@bitCast(big(seq))` -> `@bitCast(@byteSwap(seq))` at six sites (0.17 `[8]u8` bitcast is little-endian on every target, so the wire-order swap must be unconditional; identical bytes on LE, now also right on BE; AEAD calls unchanged). `X25519` `generateDeterministic`/`recoverPublicKey` are infallible (`try` dropped); `logSecrets` uses `field_names`; two tests build the signed content from comptime-known parts.
- **2026-10-13** — `example/main.zig`: a consumer of the published API (system CA bundle, TCP dial, `initInto` with `ConnectionInfo` + `SessionCache`, one HEAD request, exporter, `end`), required by CONVENTIONS §7.2 since the S2 work took the module to 39 `pub fn` — its absence turned CI 38409490822 red (`check-example-rule`). `secret-api-ok` notes on `ClientAuth.PrivateKey.fits` (reads the tag only) and `SessionCache.find`/`reserve` (public cache key only); `ct-compare` pin 4 → 6 plain compares (the reserved-exporter-label check and one test, both public bytes).
- **2026-10-13** — FIX (std bugs, remote): ServerHello session-id echo 253..255 overflowed a u8 sum (panic in safe modes); TLS 1.3 records shorter than the AEAD tag and TLS 1.2 records shorter than IV+MAC underflowed; an all-zero TLS 1.3 plaintext indexed msg[-1] / underflowed the handshake fragment end (now unexpected_message, RFC 8446 §5.4); `tls_version` was read undefined before the ServerHello. Host names: SAN-only matching via `x509.hostname` (no commonName fallback — BEHAVIOUR CHANGE, as Go), IP hosts against iPAddress SANs and without SNI. Fuzz harness: real-world options on (session view, certificate selector) and a cookie-HRR genuine flight; 200,000 flight runs clean after the fixes.
- **2026-10-13** — S2 step 4: TLS 1.3 session resumption — `Options.session_cache`, `SessionCache`/`ClientSession` (`src/session.zig`), NewSessionTicket kept (PSK via `tlsresume`, new dep), PSK offered with binder (re-bound after HRR, dropped on a suite-hash change), resumed sessions skip the certificate messages and show the kept chain (`ConnectionInfo.did_resume`, `Client.did_resume`); the hook still runs. Not offered past the ticket lifetime or the leaf's notAfter. Interop vs openssl: resumption with and without HRR, expired ticket → full handshake; a broken binder fails the test.
- **2026-10-13** — S2 step 3 (client authentication): `ClientAuth.PrivateKey.rsa` (TLS 1.3 RSA-PSS, TLS 1.2 PKCS#1 v1.5/PSS), scheme choice from the server's list (`PrivateKey.fits`), `Options.client_auth_select` + `CertificateRequestInfo` (schemes, CA names), TLS 1.2 client certificates (Certificate / CertificateVerify over running SHA-2 hashes). `Client.rsa` re-exported, `max_signature_len`. BREAKING: `signCertificateVerify(out, key, scheme, input, random)` (was `(out, key, msg)`; `out` is `[max_signature_len]u8`). New error `TlsCertificateRequestTooLarge`. Interop vs openssl: TLS 1.2 P-256/P-384 (incl. P-256 with ECDSA+SHA384), RSA 2048 in 1.3 (PSS-SHA256/512) and 1.2 (PKCS#1, PSS-SHA384), selection callback with CA names in 1.3 and 1.2.
- **2026-10-13** — FIX (std bug): on a server's KeyUpdate with update_requested, std switched the client's write key without sending its own KeyUpdate, so the server refused the next record (bad_record_mac). The client now sends KeyUpdate(update_not_requested) before its next record, then switches (RFC 8446 §4.6.3), and updates on its own after `key_update_after` = 2^23 records. `Client.key_update_pending`. Interop: s_server `K` and `k`; the std behaviour fails the test.
- **2026-10-13** — S2 step 2: `Options.connection_info` → `ConnectionInfo` (peer certificates, stapled OCSP, SCTs, version/suite/group/ALPN/HRR/EMS; copies in caller storage), `Options.verify_connection` hook (`TlsConnectionRejected`), OCSP + SCT requested by default (TLS 1.2 CertificateStatus handled), TLS 1.2 extended master secret + renegotiation_info offered by default, `Client.exportKeyingMaterial` (RFC 8446 §7.5 / RFC 5705 with EMS; equals openssl `-keymatexport`), `Client.cipher_suite`. Fixed: Ed25519 server certificates were refused (std's scheme→key map lacked ed25519). New errors: `ConnectionInfoTooSmall`, `ConnectionInfoRequired`, `TlsConnectionRejected`.
- **2026-10-13** — S2 step 1, BEHAVIOUR CHANGE (owner: Go's defaults): the ClientHello is built at run time (`src/hello.zig`) and follows Go — groups X25519MLKEM768, X25519, P-256, P-384, P-521 (new, via `p521`), key shares for X25519MLKEM768 and X25519 only. New: `Options.min_version`/`max_version`, `groups`, `key_share_groups` (`std_groups` restores std's 4-share hello), HelloRetryRequest (group and cookie; refusals per RFC 8446 §4.1.4), TLS 1.2 ECDHE_ECDSA suites (suite ↔ certificate key type checked), `Client.negotiated_group`, `Client.hello_retry_request`, errors `VersionsInvalid`/`GroupsInvalid`. Fixed: TLS 1.3 waited for the server's ChangeCipherSpec before decrypting (broke after an HRR); a max-1.2 client refused the TLS 1.3 server's DOWNGRD..01 sentinel; a TLS 1.2-only hello no longer sends key_share. Interop vs openssl: HRR to P-256/P-384/P-521, empty key_share, TLS 1.2 with each group, version bounds; offline HRR cookie + refusals.
- **2026-10-13** — perf: the ClientHello (and a TLS 1.2 ClientKeyExchange) no longer re-encode the P-256/P-384 key shares; `KeyShare` keeps their SEC1 bytes from generation (`keygen.keyPairP256` hands back the encoding p256 already made). Re-encoding std's P-256 point was a field inversion on std's `divstep`, ~4 % of the client CPU. Handshake 1.08–1.11× → 1.01–1.05× Go (card P3 → P2). ctgrind contexts unchanged (39 call chains, diffed).
- **2026-10-13** — P-384 onto the new `p384` module (new dep): the key share's public key (`keygen.keyPairP384` returns a `p384` key pair, still std's secret byte for byte, so the ClientHello is unchanged), ECDHE on secp384r1 (`p384.ecdhInto`), the client's P-384 CertificateVerify signature (bytes change: RFC 6979 nonces), and the server's P-384 signature (decoded by std, verified by `p384`; new test incl. a damaged signature, negative control red). Removed: `src/p384_base_table.zig`, `tools/gen_p384_base_table.py` and the `addMixed` copy. Handshake 1.27–1.37× → 1.08–1.11× Go client CPU. ctgrind kex 19 → 18, cv 32 → 18.
- **2026-10-11** — perf: **handshake 2.86–3.59× → 1.27–1.37× Go** client CPU (card measured, P3). The ClientHello's P-256 and P-384 key shares (std's ClientHello byte for byte, unchanged) no longer use std's `basePoint.mul` (~1.36 ms of ~2.5): new `src/keygen.zig` derives std's key pairs byte for byte (differential tests) with the public points from fixed-base combs — `p256.P256.combMulBase`, and for P-384 a comb over std's `P384` with a generated table (`tools/gen_p384_base_table.py`, 78×16 affine points) and a copy of std's mixed addition without its `isZero` select, which ctgrind showed as secret-dependent loads. ctgrind `kex` 21 → 19 in-file (pattern now includes `keygen.zig`; positive control red); 8 negative controls killed. A real `p384` module is a Backlog item.
- **2026-10-11** — perf: the server's CertificateVerify (TLS 1.3) / ServerKeyExchange (TLS 1.2) signature goes through `p256` (ECDSA P-256) and `rsa.VerifyKey` (PKCS#1 v1.5, PSS) instead of std (new deps `p256`, `rsa`); signature and key decoding stay std's, so malformed input fails as before. With x509's faster chain verify: handshake **5.22–5.87× → 2.86–3.59× Go (two runs)** client CPU. An RSA signature that is not exactly the modulus length now fails verification (std zero-padded a short one and indexed past its buffer on a long one). What is left is ECDHE key generation: std's ClientHello carries P-256 and P-384 shares and std's portable P-384 base multiply is ~half the handshake (Backlog).
- **2026-10-10** — Comparative benchmark `tools/bench.zig` (`zig build bench-tlsclient`): **5.22–5.87× Go crypto/tls client handshake** — over 2×, P4. Card stays `not measured` with the numbers in *Backlog* until the module is sped up (owner 2026-10-10: a consumed module must grade 3 or better). Tooling only, no code change.

- **2026-10-10** — tests: deterministic fuzz driver `TLSCLIENT_FUZZ` (`src/fuzz_test.zig`, `verify.zig`). `tlsclient-flight`: `Client.initInto` reads a genuine TLS 1.3 server flight (x25519, AES-128-GCM, real key schedule, signed CertificateVerify, Finished, then application data across a KeyUpdate and close_notify) that is accepted undamaged, and a plaintext TLS 1.2 flight (real ServerKeyExchange signature) taken up to the server Finished; 0-3 damaged octets / truncation must never be accepted (only the ignored legacy_version octets of the two cleartext records may differ). `tlsclient-chain`: honest, forged, client-only and stray-root chains damaged through the well-formedness guard and `verifyAgainstBundle`. 200,000-run verdicts clean (flight at `.scale` 10). No code change.
- **2026-10-10** — Constant time: new `src/ctgrind_harness.zig` (targets `kex`, `cv`, ReleaseFast). `kex` drives `Client.initInto` over a canned ServerHello with the key-share secrets in `Options.entropy` tainted (key generation, X25519 exchange, handshake key schedule); `cv` taints the client private key through `signCertificateVerify` for P-256, P-384 and Ed25519. No context is a branch of `Client.zig`'s own on a secret: the 21 / 32 in-file contexts are std's ML-KEM matrix rejection sampling (public rho, an artefact of tainting the seed), identity/range verdicts in key generation and ECDSA internals (itemised in `scripts/checks/ctgrind-expected.tsv`). The encrypted server flight is not measured: decrypted public server messages are parsed as by any TLS client. No code change.
- **2026-10-10** — **Security hardening:** `checkWellFormed` (every server certificate, before std's
  parser sees it) now runs `x509.safe.validateForStdParse` instead of `validateCertificate` alone: it
  also requires a constructed element at every position std's `Certificate.parse` descends into, and
  a well-formed RSAPublicKey inside an RSA key's BIT STRING, which std's verify reads unchecked. Both
  are documented out-of-bounds paths in std (x509 2026-10-10, found by x509's chain fuzz driver).

- **2026-10-09** — **HIGH: the established session's application secrets
  were left on the dead stack by `Client.init`'s by-value return.** New
  `Client.initInto(out: *Client, input, output, options)` writes the session to
  `out` inside the burned call tree; `init` keeps std's shape (doc comment points
  to `initInto`). The stack probe now drives a full server flight
  (EncryptedExtensions, Certificate, CertificateVerify, Finished) per group and
  suite: through `init` 640 needle windows over the 8 sets (client/server
  application traffic secrets and keys, in the wrapper's and the caller's
  frames) → 0 through `initInto`. The full flight reaches 296 KiB below the body,
  so `burn.init_burn` 320 → 384 KiB. Additive API, no wire change.

- **2026-10-09** — **HIGH: the ECDHE key shares and the handshake key schedule
  left their secrets on the dead stack after `Client.init`.** ReleaseFast stack
  probe (`stackprobe_test.zig`) drives `init` with a canned ServerHello per group
  and suite (reach checked via `ssl_key_log`); 16-byte needle windows found in 5
  calls, before → after: `x25519_ml_kem768` 2380 / 2460 (SHA-256 / SHA-384
  suite) → 0, `x25519` 2860 / 2965 → 0, `secp256r1` 2830 / 2930 → 0,
  `secp384r1` 2535 / 2630 → 0 (all four key pairs' seeds and scalars, the
  ML-KEM secret vector, the shared secrets, handshake/master secrets, handshake
  traffic secrets and keys, HMAC pads). `init` runs its body one frame down and
  zeroes 320 KiB afterwards (`burn.zig`; the body's frame is 181 KiB, dirty depth
  up to 237 KiB). No API or wire change. Not covered yet: the application
  traffic secrets and the rest of a full handshake (SPEC "Backlog / deferred").

- **2026-10-09** — **BREAKING, HIGH: the client-certificate signature left the
  key and the nonce on the dead stack; the P-256/P-384 ECDHE secret was
  multiplied in variable time.** New ReleaseFast stack probe
  (`stackprobe_test.zig`), 5 calls each, before → after: P-256 `d` 45, `k` 20,
  `k⁻¹` 20, `r·d`/`e+r·d` 10 each; P-384 `d` 60, `k` 30, `k⁻¹` 25, `r·d` 15,
  `e+r·d` 10; Ed25519 seed 10, scalar 15, prefix 15, nonce 60 — all now 0
  (they sat in std's signer frames, below the locals we already wiped).
  `signCertificateVerify` runs its body one frame down and zeroes 16 KiB after
  it (`burn.zig`; bodies dirtied ≤ 7.3 KiB). `ClientAuth.key` is now
  `*const ClientAuth.PrivateKey` (BREAKING: `.key = &key`), so `Options` copies
  never carry the key. The P-256/P-384 key share used std's `mulPublic` on our
  ephemeral scalar — documented "IN VARIABLE TIME", for public scalars; an
  inherited std bug — now `mul`. Not covered yet: the key shares' own secrets
  in std's frames (SPEC "Backlog / deferred").

- **2026-10-04** — **mvp → core.** Two opt-in additions to std's client, every
  edit marked `zig-libs tlsclient`; with default options the handshake is std's
  byte for byte (tested against std's own ClientHello). **ALPN** (RFC 7301):
  `Options.alpn_protocols`, `Client.alpn_protocol`; the answer must be exactly
  one offered name (`TlsIllegalParameter` otherwise). **TLS 1.3 client
  certificates** (RFC 8446 §4.4.2-4.4.3): `Options.client_auth` (`ClientAuth`:
  DER chain + ECDSA P-256/P-384 or Ed25519 key); a request that excludes our
  scheme gets an empty Certificate (§4.4.2.3); key copies wiped after signing.
  New `InitError` members `AlpnProtocolsInvalid`, `ClientCertificateTooLarge`,
  `ClientKeyInvalid` (reachable only through the new options). openssl
  `s_server` interop for both (loopback, throwaway fixtures); mutation 23
  mutants, 1 surviving with a reason (SPEC). Session resumption, TLS 1.2 client
  auth and RSA client keys stay deferred.
- **2026-09-25** — Test fix: the chain fuzzer's corpus seeds are now wrapped
  by `testkit.fuzz.seedInto`. `Smith.slice` reads a 4-byte length first, so
  the raw seeds lost their first bytes and never reached the verifier. The
  corpus test now reads the seeds back through `Smith`, as the fuzzer does
  (raw seeds fail it). Reported by qap.
- **2026-09-25** — New module: Zig 0.16's `std.crypto.tls.Client` with the
  server chain verified by `x509.verifyChain` (RFC 5280: basicConstraints,
  keyUsage, pathLen, nameConstraints, extKeyUsage serverAuth) and every peer
  certificate guarded by `x509.safe` -- closes ziglang/zig #35877, where any
  certificate holder could impersonate any host. Anchored against
  `openssl s_server` (honest chain accepted, forged chain refused, std's own
  client still accepting it as the retirement tripwire). Found by qap's
  M6.2 security review.
