# `tlsclient` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-28** — Card: `Downstream consumer: yes` — qap imports it (it has since the TLS move of 2026-10-19; the card was not updated).

- **2026-10-26** — **Fix (security, Go's rule):** a TLS 1.3 session made without certificate verification (`ca = .no_verification` or `.self_signed`) was resumed by a later connection verifying with a bundle through a shared `SessionCache` -- a resumption skips the Certificate, so a man in the middle of the first connection could impersonate the server on the second. A session is now resumed only under the verification it was made with, or with none (Go: a session without verified chains is not resumed by a verifying config). A cache shared between different bundles is still one trust domain (documented). Test "resumableUnder: …". Found by the audit's review (F2).

- **2026-10-26** — **Fix:** two connections resuming from the same cache entry at once (a shared cache under load) could store the earlier one's NewSessionTicket with a PSK derived from the later one's resumption secret; the next resumption offered a wrong binder and the server ended it (`TlsAlert`, decrypt_error), until a full handshake. A resumed connection now takes a new generation of the entry, so only the last one's tickets are stored. Regression check in `tools/interop.zig` (`resume-13-interleaved`, against Go's concurrent server); negative control: the inverse mutant fails it. Found by the review (F3).

- **2026-10-26** — **Behaviour change (Go's, RFC 8446 §4.2.3 / RFC 9155):** a server's handshake signature with PKCS#1 v1.5 is refused in TLS 1.3 and with SHA-1 in both versions (`TlsBadSignatureScheme`), and rsa_pkcs1_sha1 is no longer offered in signature_algorithms (certificate signatures are `x509`'s, unchanged). std accepted both. Found by the review (F1).

- **2026-10-26** — **Fix:** a ServerHello choosing X25519 when only the X25519MLKEM768 share was sent was accepted (the X25519 key pair exists for the hybrid); RFC 8446 §4.2.8 wants illegal_parameter, which it is now. Test in `fuzz_test.zig`. Found by the review (F4).

- **2026-10-26** — **Fix:** a host name over 255 bytes reached `catch unreachable` (a panic) or an `@intCast` while the ClientHello was built; it is now `error.HostNameInvalid` (new `InitError` member) before anything is written. Found by the review (F5).

- **2026-10-26** — **NO CONSUMER-VISIBLE CHANGE:** audit (review + 77 mutants): tests for the server-message checks no test reached -- a TLS 1.3 server Finished with wrong verify_data, a CertificateRequest after the Certificate, an HRR naming a TLS 1.2 suite, an unsolicited pre_shared_key, a PSK accepted under another hash, both TLS 1.2 downgrade sentinels, a TLS 1.2 ServerHello to a TLS 1.3-only client, a ServerKeyExchange group not listed, ALPN twice, an unsolicited CertificateStatus, a TLS 1.2 CertificateRequest without a credential (`fuzz_test.zig`), and unit tests in `session.zig`, `verify.zig`, `Client.zig`.

- **2026-10-26** — **Fix:** (std bug, remote server; handshake failure) a TLS 1.2 server whose certificate key is on P-384 or P-521 could not be reached: its ServerKeyExchange signature (Go signs with ecdsa_secp256r1_sha256, which in TLS 1.2 names only the hash, RFC 5246 §7.4.1.4.1) was decoded as a P-256 one, `InvalidEncoding`. The curve is now the key's in TLS 1.2; TLS 1.3 still requires the scheme's own curve (`TlsBadSignatureScheme` otherwise). Found by the new `tools/interop.zig`; regression test "server signature: TLS 1.2 ECDSA schemes name the hash…", negative control: the interop rows `leafkey-p384-12`/`leafkey-p521-12` failed before the fix.

- **2026-10-26** — **Fix:** (handshake failure) a TLS 1.3 server with a P-521 certificate key could not be reached: the offered signature_algorithms (std's list) lacked ecdsa_secp521r1_sha512 and the verifier had no P-521. The scheme is offered (one more entry in the ClientHello) and verified through `p521`. Found by `tools/interop.zig` (row `leafkey-p521-13`).

- **2026-10-26** — **Behaviour change (Go's):** a CertificateRequest when no `client_auth`/`client_auth_select` is configured is answered with an empty Certificate (TLS 1.3 and 1.2) and the server decides, as Go's client does; it failed the handshake with `TlsUnexpectedMessage` as in std, so a server that only *requests* a client certificate was unreachable. A server that *requires* one now ends the handshake with its alert (`TlsAlert`, e.g. certificate_required) instead. Test "interop: a CertificateRequest without client_auth gets an empty Certificate…" (replaces "defaults are std's — … fails as in std").

- **2026-10-26** — `tools/interop.zig` (`zig build interop-tlsclient`): a live oracle -- 90 cases against Go's crypto/tls server, judged by Go's client (`tools/go_oracle`). Card E2 → E1; S parity → ahead (two chains Go accepts that RFC 5280 refuses, `x509`'s rules at the TLS layer).

- **2026-10-26** — **Performance:** the X25519 key share (the public key and the shared secret, alone and inside X25519MLKEM768) runs on `ct25519.X25519` instead of std's: same bytes, the public key from a fixed-base comb and the shared secret on a MULX/ADX ladder. Client CPU per handshake 0.68–0.70× → 0.60–0.67× Go 1.26.8, and 1.11–1.23× → 1.03–1.09× rustls 0.23.43 + aws-lc-rs 1.18.0, now measured by `bench-tlsclient` (`tools/rust_fast_bench`). New dependency: `ct25519`. ctgrind `kex` 17 → 15 contexts (std's ladder identity checks gone).

- **2026-10-24** — **NO CONSUMER-VISIBLE CHANGE:** the `strRepeat` helper (the Zig 0.17 stand-in for `**`) builds its string with one `@splat` + `@bitCast` instead of a comptime loop, which Sema evaluated in O(n²) (http's test binary: 323 s → 13 s). Same bytes, faster compile.

- **2026-10-23** — **Fix:** (std bug, remote server) an alert under the handshake key — a server refusing after its ServerHello, e.g. `internal_error` when its signer fails — ended `init` with `TlsUnexpectedMessage` and the description was lost. It is `TlsAlert` now, with `Options.alert` filled; only that record's octets are read as the alert. Found by `tlsserver`'s mutation run; regression test there (`connection.zig`, "an offloaded key signs through Connection.signer…"), negative control checked (without the fix: `TlsUnexpectedMessage`).

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
