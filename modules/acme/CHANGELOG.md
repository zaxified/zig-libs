# acme — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-16** — wave W3: the **order-level API** (instant-acme / lego style): `Client.newOrder` and `fetchOrder(url)` return an `Order` handle (owns its memory; `url`, `status`, `identifiers`, `authorizations`, `finalize`, `certificate`, `expires`), `waitOrder(order, .ready | .valid)`, `finalize(order, csr_der)`, `downloadChain(order, preferred_chain)`; `fetchAuthorization` returns an `Authorization` (every offered `Challenge`, `challenge(kind)`), `keyAuthorization`, `acceptChallenge`, `waitAuthorization`, `deactivateAuthorization` (RFC 8555 §7.5.2), `solveAuthorization`. **Custom challenge solvers:** `Solver` (`present` / `cleanup` over a `ChallengeRequest` with `dnsRecordName`, `dnsTxtValue`, `tlsAlpnIdentifier`, `tlsAlpnSni`), `Options.solvers` replaces the built-in of a type (HTTP-01, TLS-ALPN-01 and DNS-01 are solvers internally). `obtain*` are rebuilt on these calls. `jws.dns01TxtValueFromKeyAuthorization`.
  - **API:** `Error` gains `SolverFailed`; `Status` and `max_reverse_name_len` are public; `OrderOptions`, `OrderTarget`, `SolverError` are new. DNS-01 needs a publisher OR a DNS-01 solver (`DnsPublisherMissing` otherwise).
  - Tests: mock CA — the steps one by one, a caller's DNS-01 solver for a wildcard (no publisher), a refusing solver (no cleanup), deactivation; **Pebble:** new `steps` scenario (newOrder, fetchOrder, authorization with its five challenges, a caller's HTTP-01 solver, finalize, download, deactivation) 8/8 live and replayed offline. Interop tool: chains are checked against the time of the check, not the start of `lifecycle` (`CertificateNotYetValid` on a slow run).

- **2026-10-16** — certificate **reads** moved onto the `x509` module (new dep): `x509.certNotAfter`, `x509.ariCertId` and `x509.issuerCommonName` keep their signatures but read through `x509.chain.certValidity` / `certSerialAndIssuer` / `certAuthorityKeyId` and `x509.names.nameAttribute` (bounded walks, fuzzed there) instead of this module's own DER walkers and std's `Certificate.parse`; the mock CA reads a revoking certificate's key with `x509.spkiOf`. `acme/src/x509.zig` keeps construction only (CSR, TLS-ALPN-01 certificate, key PEM). Behaviour: a certificate whose public-key algorithm `x509` does not know (neither RSA, EC P-256/384/521, Ed25519, ML-DSA nor SLH-DSA) is now `MalformedCertificate` / no issuer CN.

- **2026-10-16** — wave W2: **RSA** account and certificate keys (RS256, PKCS#1 v1.5 + SHA-256, via the `rsa` module; 2048–4096 bits): `jws.Alg.rs256`, `AnyKeyPair.rs256` is a **pointer** to a caller-owned `rsa.KeyPair` (tens of KiB — never held by value; `Client` borrows it, the caller keeps it alive and wipes it), `AnyPublicKey.rs256: rsa.VerifyKey`, `jws.generateRsaKeyPair`, RSA JWK/thumbprint, CSR (`sha256WithRSAEncryption`), `x509.rsaPrivateKeyToPem` (PKCS#1) / `rsaPrivateKeyFromPem` (PKCS#1 or PKCS#8); `Options.cert_key_alg = .rs256` + `cert_rsa_bits` (the certificate key lives on the heap during `obtain`, wiped and freed after export). **IP identifiers** (RFC 8738): an IPv4/IPv6 literal in RFC 5952 form is ordered as `type: "ip"`, written as an iPAddress SAN in the CSR and the TLS-ALPN-01 certificate, served under the reverse-DNS SNI (`in-addr.arpa` / `ip6.arpa`); never over DNS-01; `x509.ParsedCsrAny.ip_sans`; `obtainWithCsr` orders a CSR's IP SANs too. New deps `rsa`, `netaddr`.
  - **API:** `Error` gains `UnsupportedKeySize`; `jws.Alg`/`AnyKeyPair`/`AnyPublicKey` gain `.rs256` (`Alg.crv`/`coordLen`/`sigLen` are EC-only — `Alg.isEc()`); `generateAnyKeyPair` stays EC-only; `privateKeyFromPem(*AnyKeyPair)` stays EC-only (no storage for an RSA pair). `x509.csrDer`'s names may be IP literals (formerly refused as `InvalidDomain`). `ParsedCsrAny` gains `ip_sans` (`deinit` frees it).
  - Tests: RS256 signature byte-identical to `openssl dgst -sha256 -sign`, RSA CSR byte-identical to `openssl req`, PKCS#1/PKCS#8 PEM byte-identical to openssl, JWK thumbprint against python; IP SAN GeneralNames byte-identical to openssl's, openssl's IP CSR parses; RFC 3596 §2.5 reverse-name example; mock CA: RSA account + RSA certificate end to end, an IPv6 identifier over HTTP-01. **Pebble:** new scenarios `rsa`, `ip-http01`, `ip-tlsalpn01` (the material is stored only under the reverse name, so Pebble's SNI proved it) — 9/9 + lifecycle 12/12, replayed offline.
  - Known gap (filed in `rsa`'s Backlog): `rsa`'s private-key PEM codec base64s through std's tables, not constant time like the EC paths' `b64ct`.

- **2026-10-16** — competitor-scope wave W1 (survey `~/CML` § CW: x/crypto/acme + autocert, lego, certmagic, instant-acme, certbot): **profiles** (`Client.profiles`, `ObtainOptions.profile` / `profile_mode`, draft-ietf-acme-profiles); **order validity** (`ObtainOptions.not_before` / `not_after`); **alternate chains** (`ObtainOptions.preferred_chain`, `Link: rel="alternate"`, `x509.issuerCommonName` over the bounded DER reader); **CSR input** (`Client.obtainWithCsr` → `IssuedChain`); **extra CSR extensions** (`x509.Extension`, `x509.must_staple`, `x509.csrDerWith`, `ObtainOptions.csr_extensions`); **rate limits** (`error.RateLimited`, `Client.retryAfter`, `Retry-After` as seconds or HTTP-date) and **503 resend** (`Options.max_unavailable_retries`); **ES512** (P-521 via `p521`) account and certificate keys, CSR, SEC1/PKCS#8 PEM; CA presets `zerossl`, `google_trust_services`, `google_trust_services_staging`. New dep `p521`.
  - **API:** `Error` gains `RateLimited` and `InvalidCsr`; `x509.CsrError` gains `DuplicateExtension`; `jws.Alg`/`AnyKeyPair`/`AnyPublicKey` gain `.es512` (`AnyPublicKey.max_sec1_len` 133) — an exhaustive switch over any of them needs the new arm.
  - Tests: mock CA (profiles required/preferred, validity members, alternate chain chosen and default kept, 503 resent / given up, `rateLimited` not resent, openssl CSR with a subject and a critical keyUsage issued through `obtainWithCsr`, ES512 end to end); must-staple bytes equal openssl's; ES512 JWK/thumbprint, CSR and PEM against openssl + python. **Pebble:** EAB now required, new `lifecycle` scenario (shortlived profile with the leaf lifetime checked, ARI, renewal with `replaces`, revoke by account and by certificate key, contact update, rollover ES256 → ES384, alternate chain to Pebble's second root, deactivation refused afterwards), 12/12 live and replayed offline from the new transcript.

- **2026-10-13** — scope parity with `golang.org/x/crypto/acme` (grade 3 → 2 work): **external account binding** (`Options.eab`, RFC 8555 §7.3.4); **account lifecycle** (`Client.updateContact`, `rolloverKey` RFC 8555 §7.3.5, `deactivate` §7.3.6); **revocation** (`Client.revoke` by account, `revokeWithCertKey` by certificate key, `Reason`; §7.6); **ARI** (RFC 9773: `Client.renewalInfo` / `renewalInfoPem`, `RenewalInfo.pickTime`, `x509.ariCertId`, `obtainWith(.{ .replaces })`; `error.NotSupported` for a CA without the endpoint); **ES384** (P-384 via the `p384` module) account and certificate keys (`jws.Alg`, `AnyKeyPair`, `AnyPublicKey`, `generateAnyKeyPair`, `verifyFlattenedAny`, `parseCsrAny`, `Options.cert_key_alg`); **PKCS#8** `PRIVATE KEY` read/write for both curves (`x509.pkcs8PrivateKeyToPem/FromPem`, `privateKeyFromPem`). New dep `p384`.
  - **API, source-compatible:** `Client.init`'s `account_key`, `jws.sign`'s `key_pair`, `x509.csrDer`/`tlsAlpnCertDer`/`ecPrivateKeyToPem`/`ecPrivateKeyFromPem`'s key and `jws.canonicalJwk`/`thumbprint*`/`keyAuthorization`/`acmeIdentifier`/`dns01TxtValue`'s public key are now `anytype` (a pointer to / value of the P-256 type as before, or the P-384 type, or the `Any*` union); `jws.Header.nonce` is `?[]const u8` (null omits the member; a string coerces). `jws.sign` and the other signing entry points are generic functions now, so a stack probe needs a concrete wrapper (`stackprobe2_test.zig`). `jws.verifyFlattened`/`x509.parseCsr` stay ES256-only (they refuse ES384 by name; `...Any` variants take both). `ecPrivateKeyFromPem` now checks the PEM's curve OID against the target (it ignored it before: a secp256k1 key loaded as P-256). `jws.canonical_jwk_len` stays the P-256 size; P-384 needs `max_canonical_jwk_len`.
  - Tests: mock-CA lifecycle (EAB MAC checked against std HMAC-SHA256; both rollover JWS layers, old key refused; revocation by both keys; ARI against the RFC 9773 §4.1 CertID `aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE`; ES384 flow), ES384 JWK/thumbprint (openssl + python), openssl P-384 CSR and PKCS#8 fixtures byte-exact both ways.
- **2026-10-13** — SECURITY (local key files): `ecPrivateKeyToPem`/`ecPrivateKeyFromPem` base64-coded the private key through std's alphabet tables (key-dependent load addresses, found by the new ctgrind harness) and left the key's base64 / DER in freed heap blocks (`pemEncode`'s scratch, `pemDecode`'s `realloc`). Now constant-time `b64ct.zig` over wiped stack buffers; `ecPrivateKeyFromPem`'s `gpa` is unused. ctgrind harness (`jws`, `csr`, `pem`).
- **2026-10-10** — Card Performance `n/a` with the reason (no timeable reference implementation). Docs only.

- **2026-10-09** — tests: deterministic fuzz driver `ACME_FUZZ` over the existing harnesses (parseOrder, parseAuthz, parseCsr also build a genuine response / signed CSR from the drawn octets: it must parse back to its fields; truncations, a trailing octet and any flipped CSR bit must be refused).
- **2026-10-09** — **NO CONSUMER-VISIBLE CHANGE:** dead-stack pass (`check-secret-api`). `jws.sign`, `x509.csrDer` and `x509.tlsAlpnCertDer` (all already took the key pair by pointer) now run under a 32 KiB burn (`burn.sign_burn`); `Client.init` carries a `secret-api-ok` marker (the `Client` holds the account key by design and is built in place). New `src/stackprobe2_test.zig` (testkit.stackprobe, ReleaseFast) probes the three signing entry points.

- **2026-10-08** — **BREAKING + FIX (secrets on the dead stack, HIGH):** ES256 moved off
  `std.crypto.sign.ecdsa.EcdsaP256Sha256` onto `p256.EcdsaP256Sha256` (burned wrapper); every secret key
  pair / seed / secret key is taken by pointer and every secret result goes into an out-param. Measured
  BEFORE with the new `src/stackprobe_test.zig` (ReleaseFast, per 5 calls): `jws.sign` left `d` 55×, `k` 10×,
  `k⁻¹` 20×, `r·d` 10×, `e+r·d` 10× on the dead stack (down to 2.8 KiB below the call); `x509.csrDer` and
  `x509.tlsAlpnCertDer` the same (`d` 55×, `k` 10×, `k⁻¹` 20×, `r·d` 10×, `e+r·d` 10×, to 3.9 / 4.5 KiB);
  `jws.generateKeyPair` `d` 60× and the seed 20×; `x509.ecPrivateKeyToPem` `d` 20×;
  `x509.ecPrivateKeyFromPem` `d` 50× — `k` next to a published signature is the private key. After: 0 residues
  in all six, negative control 0, positive control found.
  - **API:** `jws.generateKeyPair(out: *KeyPair, io)` (was `generateKeyPair(io) KeyPair`);
    `jws.sign(gpa, key_pair: *const KeyPair, …)`; `x509.csrDer`, `x509.tlsAlpnCertDer`,
    `x509.ecPrivateKeyToPem` take `*const Es256.KeyPair`; `x509.ecPrivateKeyFromPem(out: *KeyPair, gpa, text)`
    (was returning the pair; `out` is zeroed on error); `Client.init(…, account_key: *const jws.KeyPair, …)`
    copies the pair into the client (the field is wiped in `deinit`, as before). `jws.KeyPair` / `Es256` are
    p256's types (same fields as std's). Library code builds pairs with `generateDeterministicInto` /
    `fromSecretKeyInto`.
  - Key mint and the RFC 5915 codec run their bodies one frame down and burn it (`src/burn.zig`, 8 KiB; the
    ECDSA signer burns its own frames inside p256). `ecPrivateKeyToPem` now builds the DER (it holds the
    scalar) in a wiped stack buffer instead of a heap arena; `ecPrivateKeyFromPem` wipes the decoded DER.

- **2026-10-06** — **Anchoring: Pebble** (`tools/pebble.sh`, `tools/interop.zig`, `tools/pebble_helper`,
  `src/pebble_replay_test.zig`): the client against Let's Encrypt's ACME test CA in `-strict` mode —
  HTTP-01 (one and two names), DNS-01 wildcard, TLS-ALPN-01, an unreachable name and a blocked one,
  6/6, every chain verified to Pebble's root; Pebble's answers replayed in the module's lane.
  - **BEHAVIOURAL (diagnostics):** after `error.AuthorizationFailed`, `lastProblem` is the failed
    challenge's `error` problem (`urn:ietf:params:acme:error:connection: …`), as RFC 8555 §8 places it;
    it was the first bytes of the authorization JSON.
  Evidence MIXED → EXTERNAL.

- **2026-10-04** — Tests: mutation schemata run (47 mutants, 43 killed, 3 equivalent, 1 alive
  by design). Nine new tests: validly signed JWS whose header breaks RFC 8555 §6.2 / RFC 7518
  (alg, jwk+kid, kty, short coordinate, 65-octet signature, an embedded jwk against the account
  key), RFC 1035 domain limits, DER indefinite/truncated lengths and the nesting bound, CSR
  fields refused by name plus a critical SAN and a non-dNSName entry, PEM label/body errors,
  RFC 5915 key version/length, and the challenge responder never serving a slash-bearing name.
  No behaviour change.
- **2026-09-30** — **DNS-01 challenge and wildcard certificates.** `ChallengeType.dns_01`,
  `Options.dns_publisher` (`DnsPublisher`: `present`/`cleanup` callbacks — provider code stays the
  caller's), `jws.dns01TxtValue`, `Client.dns01RecordName`, `x509.isValidWildcardDomain`. `obtain`
  accepts `*.name` with `dns_01` only; `csrDer` now accepts a wildcard dNSName. New errors
  `DnsPublishFailed`, `DnsPublisherMissing` (⚠ an exhaustive `switch` over `Client.Error` or
  `ChallengeType` needs the new arms). Mock-CA integration test for a wildcard order over DNS-01; TXT
  value KAT against openssl and Python.

- **2026-09-07** — **All three fuzz harnesses were replaying an EMPTY input; each now
  has a corpus and a measured reach guard.**

  `fuzzParseOrder`, `fuzzParseAuthz` and `fuzzParseCsr` opened with
  `smith.bytes(&buf)` followed by `smith.valueRangeAtMost(u16, 0, buf.len)`. `bytes`
  consumes `min(buf.len, in.len)` octets and a ranged draw then reads eight *more* as
  a little-endian u64, returning the range minimum when fewer remain — so the drawn
  length was 0 for every input a seed can carry, and `parseOrder`, `parseAuthz` and
  `parseCsr` were each handed a zero-length slice while the response sat unread in
  `buf`. All three now take the bytes in one `smith.slice(&buf)` draw.

  ⛔ The two JSON harnesses are the case where `accepted > 0` would have been a
  worthless guard: **every member of `OrderJson` and `AuthzJson` has a default**, so
  `parseOrder("{}")` and `parseAuthz("{}")` both succeed. A corpus of empty objects
  would have read 100% accepted while never reaching a URL, a status word, the
  authorization list or a challenge. Each guard therefore pins numbers an empty or
  defaulted body cannot produce: 10 of 15 order seeds accepted carrying 3
  authorizations, 48 finalize octets and 7 typed statuses; 9 of 14 authz seeds
  accepted yielding 5 http-01 challenges, 2 tls-alpn-01 challenges and 47 identifier
  octets. Non-empty seeds went 0 → 15 and 0 → 14.

  The CSR corpus is built at run time from `csrDer` — this module owns no captured
  CSR, and a pasted one would freeze a copy of the encoder instead of tracking it —
  so the harness and its guard build from the same place. 12 seeds, 2 accepted, 3
  SANs recovered (0/0/0 before). `fuzzParseCsr`'s buffer went 512 → 1024: the two
  real CSRs measure 232 and 248 octets, which 512 held, but only by about four domain
  names, and a seed over the buffer reads back empty rather than large.

- **2026-08-22** — **Breaking:** `pemBlockCount` now returns
  `error{LabelTooLong}!usize` instead of `usize`. It carried the same
  `std.debug.assert` precondition `pemDecode` shed on 2026-08-21, and asserts
  compile out of `ReleaseFast`/`ReleaseSmall`, so an over-long label reached the
  `bufPrint(...) catch unreachable` below it. Callers add `try` (or, where the
  label is a literal, `catch 0` — a count of zero is already the failure path).

- **2026-08-21** — **Breaking:** `pemDecode` gained `error.LabelTooLong`, and
  `PemDecodeError`/`KeyPemError`/`CertError` name it. The caller-supplied label length was
  an `std.debug.assert` guarding two `bufPrint(...) catch unreachable` calls, so in
  `ReleaseFast`/`ReleaseSmall` an over-long label reached the `unreachable` instead of
  being rejected. `pemBlockCount` had the same precondition; it was fixed the next
  day (see the 2026-08-22 entry above).

- **2026-08-13** — Test-only, neither BREAKING nor BEHAVIOURAL: `jws.zig` gained a
  seam test proving `generateKeyPair`'s `entropy.fill` draw is actually read
  (two keys from the same `io` must differ) and that the production
  sign/verify path still round-trips with a freshly drawn key. Before this,
  the account/certificate key draw could be replaced by a constant and the
  suite stayed green — confirmed by mutating the draw (`@memset(&seed,
  0x42)`) and watching the new test fail (34 pass, 1 fail), then reverting
  to green (35/35). Does not distinguish real entropy from a varying-but-
  weak PRNG; see the test's own comment.
- **2026-08-13** — New `jws.generateKeyPair(io)`, and both certificate-key draws
  (`Client.obtain`'s issuance key and `publishTlsAlpn01`'s TLS-ALPN-01
  validation key) now use it. It is
  `std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.generate` verbatim with
  the seed taken from `entropy.fill` (`std.Io.randomSecure`) rather than
  `io.random`, whose contract permits a silent fallback to a weaker seed
  (`std/Io.zig:2462`). **Not breaking:** no signature changed and
  `jws.KeyPair` is still the same std type. New dep: `entropy`.

  Callers should mint the **account key** with `jws.generateKeyPair(io)`
  too — the doc comments on `Client.init` and the module example now say
  so. The account key authenticates every request to the CA for the life
  of the account and a certificate key is what a publicly-trusted
  certificate attests to; neither is recoverable after the fact.
- **2026-07-18** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified against RFC
  8555 §6.2.
