# acme — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-28** — **Fix (no-panic sweep):** an order whose `authorizations` or `identifiers` list is longer than the identifiers ordered is `MalformedResponse` (`newOrder`, `waitOrder`/`finalize` refreshes; `fetchOrder` accepts at most 100) instead of one signed POST per URL a CA cares to list (A-1); `downloadChain` looks at no more than `max_alternate_chains` (8) `Link rel="alternate"` targets and fetches each into a short-lived arena, so a non-chosen alternate body is freed at once (A-2); `RenewalInfo.pickTime` is total on any i64 window, an inverted one gives its start (A-4); `Manager` clock/window arithmetic saturates (`+|`, `-|`) so a clock near the i64 limits cannot overflow (A-5); `max_backoff_s = 0` and `lock_poll_s = 0` are floored to 1 s instead of a busy loop against the CA or the storage (A-6); every pub-helper precondition that ended in `unreachable` (`canonicalJwk`, `keyAuthorization` and `base64UrlEncode` with a short buffer, `.rs256` in `Alg.crv/coordLen/sigLen`, `uncompressedSec1`, `generateAnyKeyPair`, `curveOid`) is now a checked `@panic("acme: ...")` in every mode, with the precondition in the doc comment (A-7); a new on-demand name in `certificate()` first drops the failed on-demand names whose back-off is over, so a server that never calls `maintain` keeps the set bounded (A-9); a chain of more than `max_chain_certs` (10) certificates is `MalformedResponse` in `downloadChain` and `MalformedChain` in `checkPair` (A-10). Docs: `Client` is not movable once a responder is wired (A-8); on-demand issuance runs on the handshake thread, give it 128 KiB of stack (an estimate, not measured; A-11). Not fixed: the typed directory `meta` (A-3, backlog). Tests `no-panic A-1/2/4/5/6/9/10` each fail without their fix. Report: `~/CML/20261028-panic-sweep/acme-sweep.report.md`.

- **2026-10-24** — **NO CONSUMER-VISIBLE CHANGE:** the all-module `strRepeat` rewrite (`571bf09e`) is reverted here: this module's calls are small (seconds of Sema at most), and the change would have made its fresh audit's `src` hash stale for nothing.

- **2026-10-23** — Re-audit (two independent reviews of the current source + mutation) and grade-1 lead. **Fixes, Client:** `lastProblem`/`retryAfter` are cleared by every request, so a later transport failure no longer carries an old `rateLimited`'s `Retry-After` (the `Manager` turned it into a day-long back-off); signed POSTs no longer follow redirects (a 3xx comes back as `AcmeProblem` — RFC 8555 §6.2 makes a redirected POST unanswerable, and a 307 sent the signed body to a host of the CA's choosing); **added** `Options.body_timeout_ms` (default 30 s; a CA that sent its head and stalled mid-body parked the caller and the `Manager`'s issuer for good — `http`'s `total_timeout_ms` ends with the head); certificate downloads send `Accept: application/pem-certificate-chain` (§7.4.2) and a failing alternate chain keeps the default one; an `invalid` order reports its `error` member; `fetchAuthorization`/`loadOrder` no longer leak an arena node allocated after the arena was copied into the result; a CA's HTTP-01 identifier must be a host name before a custom `Solver` sees it; a missing/unparsable `finalize` URL is `MalformedResponse`; a directory with `meta: null` or a non-string profile description loads; `dns01RecordName` panics (all modes) on a domain over 253 bytes instead of `unreachable`; integer `Retry-After` poll pacing reads like `retryAfterHeader` (tabs, u64, saturating). Docs: an RSA account key is held by pointer (`init`, `rolloverKey`); what to do after a rollover whose answer was lost. **Fixes, Manager:** in a certificate's last hour and after it expired, failures kept retrying every minute — the exponential back-off (capped at 10 min there) and a CA `Retry-After` (capped at a day there) hold again; `AcmeIssuer` reports the client's problem/`Retry-After` only for a CA refusal; **added** `OnDemand.wait_ms` (default 30 s; handshakes waiting for an issuance in flight were unbounded); a name twice in one `manage` list (case aside) is `error.InvalidName` (it tripped a hash-map assertion); an IP-literal SNI never reaches the on-demand policy; an `unmanage`d entry reports nothing more; a failed ARI poll waits like a successful one (≥ 60 s, the CA's `Retry-After` up to a week); `checkPair` refuses a certificate valid only from more than a day ahead; the retry time counts from the end of the attempt; `unmanage` takes a trailing dot and a 255-byte wildcard. **storage:** `DirStorage` fsyncs the parent directory after the rename/link. **Ahead** (`tools/autocert_lead`, autocert v0.58.0 against Pebble): two autocert nodes on one cache issue two certificates for one name, a fixed `RenewBefore` longer than the lifetime re-issues in a loop (9 certificates in 10 s); here one issuance under the storage lock and a renewal at a share of the lifetime (tests "fleet: two nodes on one storage due at once issue one certificate", "schedule: ten days or less renews at half the lifetime"). **Mutation** over the final source: 351 schemata mutants, 331 killed, 20 equivalent; the 71 test gaps of the first pass closed with new tests (`MockCa` knobs for existing-account / missing `Location` / scripted order and authorization states / directory status / `Accept` recording / failing alternates, `storage` contract refuses traversal keys on `delete`, DER length-form bounds, RSA SPKI tails, PEM label bounds, a zero-length serial in `ariCertId`, on-demand `AlreadyManaged`, rate-limit ring cap, `max_backoff_s`, redirect Host checks). Card: grade 1 (S1 E1 A1 H1 P–).

- **2026-10-19** — **Fix:** a 503 whose `Retry-After` is a huge number of seconds (any u64) overflowed `secs * 1000` in `Client.postSigned` (panic in safe builds); now saturating, and the no-header doubling shift is clamped. Test: the 503 `Retry-After` test gains a `99999999999999999` case (crashed without the fix). Also a test pinning `DirStorage.load` at exactly `max_value_len` bytes.

- **2026-10-19** — **NO CONSUMER-VISIBLE CHANGE:** Deprecated std names replaced by their Zig 0.17 spellings (`mem.indexOf*` -> `mem.find*`, `fmt.bufPrint` -> `mem.print`, `fmt.allocPrint(a, …)` -> `a.print(…)`, `bufPrintSentinel` -> `mem.printSentinel`, `@intFromEnum` -> `@backingInt`); the old names are aliases, so behaviour is identical.

- **2026-10-18** — Ported to Zig 0.17.0. Non-mechanical: `manager_test.zig` fixes the codemod's `@splat` element type (`[16]FakeIssuer.Step`). The mock CA's `allocRemaining(.limited(64 KiB))` request-body cap (test-only) now accepts exactly 64 KiB (0.17 semantics), no test depends on the boundary.
- **2026-10-18** — **Constant time (finding, fixed):** the PEM HEADER searches over text that may hold a private key of another label — `privateKeyFromPem` on a PKCS#8 key (its `EC PRIVATE KEY` search misses), `rsaPrivateKeyFromPem`, the Manager's stored key+chain blob and `checkKey` — were `std.mem.indexOf` (Boyer-Moore-Horspool) across the key's base64, all of it when the label was absent. New `x509.pemBlockStart` walks the blocks and skips each body by a scan for its END line's first `-`. ctgrind target `anykey` (5 contexts, no `findPos`); mutation 9/10 + 1 equivalent.
- **2026-10-18** — tests: mutation audit of the Manager, storage and the 2026-10 `x509`/`Client` additions (191/217 killed, 26 equivalent after the follow-up below). New `manager_test.zig` tests for schedule/back-off/ARI/on-demand/HTTP-01/distributed-challenge rules, storage limit and owner tests, PEM/PKCS#8 reader tests, `pickTime`/`parseRenewalInfo`/bad-nonce/`AcmeIssuer` rate-limit tests; `Lab.stop` closes the client connections before the server drains (each mock-CA test no longer waits ~10 s). Follow-up: the 15 open survivors closed with `MockCa` knobs (503 `Retry-After`, refused `replaces`, recorded `contact`, failing deactivation, `renewalInfo` trailing slash / non-200, order-poll `Retry-After`) and tests for the 503 loop, `register` contact, `deactivate`, `renewalInfo`, `AcmeIssuer` retry, `ratioRenewAt` at ten days, `rsaPublicEql` and the RSA PEM bounds/order (14 killed, 1 equivalent).
- **2026-10-18** — **Constant time (finding, fixed):** `ecPrivateKeyFromPem` / `pkcs8PrivateKeyFromPem` / `privateKeyFromPem` found the END line with `std.mem.indexOfPos`, a Boyer-Moore-Horspool search forward over the key's base64 — its skip table is indexed by each character and its skip length depends on whether the character is a letter of the END line (ctgrind `mem.zig` findPos; the 2026-10-13 audit had read that context as a layout decision). The END line is now found by the first `-` after the body (base64 has none, so the compare is false on every key character and the scan ends at the body's public length) and must start there. Same accepted inputs as before: the first block of the label is used; a key between other blocks (the Manager's key-then-chain file, a chain before the key) loads (test). **ctgrind:** new targets `pem384` (SEC1 P-384 round trip, 18 in-file) and `pkcs8` (PKCS#8, P-256 + P-384, 17); `pem` stays 18 (the table-indexed search out, one `findScalarPos` compare in); every context attributed in `ctgrind-expected.tsv`.
- **2026-10-18** — **Fleet storage races closed (audit L6, L7).** `DirStorage`: every lock operation (read, decide, create, extend, take over, release) runs under an exclusive `flock` of `locks/.guard` — a stale lock is now taken over by exactly one node, and `unlock` no longer deletes a lock another node took between its read and its delete; without `flock` support the old unguarded behaviour stays. **Added:** `Storage.create` / `VTable.create` (store only if absent; optional field, defaults to null → load-then-store, so existing backends compile unchanged; `DirStorage` = exclusive link, `MemStorage` = one locked check). `loadOrCreateAccountKey` stores a fresh key through it and, when another node stored first, uses that one — two nodes starting at once no longer create two ACME accounts. L10 (expired certificate stays served) kept by decision, SPEC. Tests: racing nodes on one stale lock, held guard blocks `tryLock`, raced account-key creation, `create` in the backend contract; each failed with its fix removed.
- **2026-10-17** — Interop (`tools/interop.zig`, manager scenario) made deterministic: the issuer asks for Pebble's `default` profile (Pebble picks a random profile for an order naming none, so the renewal was a six-day certificate half the time, expired at the shifted clock); the renewal is detected by a changed chain, not `not_after` (same-second issuance repeats it); the restart runs at the real clock (the fresh renewal could already be due there, and the issuer-less manager's failure leaked into later steps). 6/6 runs green. Tooling only.

- **2026-10-17** — The private `src/b64ct.zig` is gone: the EC key PEM uses the new `b64ct` module (`standard.encode`; `decodeIgnoring` with `pem_whitespace` on the raw body, so the branching whitespace strip and its stack copy are gone too). ctgrind `pem` 20 -> 18 in-file. No API change.
- **2026-10-17** — internal: the CSR / TLS-ALPN certificate / key PEM DER is built with `rsa.der_writer` (already a dependency) instead of this module's own copy; output byte-identical. `DerEncodeError`, `CsrError` and `TlsAlpnError` keep `ValueTooLarge`, but it is no longer returned (the shared encoder takes any length; a CSR over 64 KiB is now built).
- **2026-10-17** — ARI `suggestedWindow` times are parsed by `datefmt.parseRfc3339` (new dep `datefmt`, already in the closure via `http`) instead of this module's own RFC 3339 parser and civil-date helpers. **Behaviour change:** a leap second (`23:59:60`) is now refused as `MalformedResponse` (it was read as `:59`), as Go's `time.Parse` does; every other accepted and refused form is unchanged (the existing `parseRfc3339` test table passes as is, plus a `:60` row).
- **2026-10-16** — Manager review fixes (independent review, see SPEC Backlog): one issuer is never called from two threads at once (a `Client` behind it is not thread-safe); an ARI window in the past no longer renews a fresh certificate every round (floor at a tenth of the lifetime); failed on-demand names are forgotten after their back-off and go through the policy and rate limit again; `run()` starts a round within a second of `manage`/`addIssuer`; a handshake no longer waits for a managed name's first issuance; `Retry-After` never parks a valid certificate past `notAfter` − 1 h; stored certificates adopted by `notBefore`; malformed SNI, non-base64url tokens and CTLs in the redirect target refused; an RSA key in PKCS#8 accepted by `checkPair`. **Storage layout:** key and chain are one value, `certificates/<name>.pem` (was `.crt` + `.key` — written by no release). **API:** `addIssuer` returns `error.TooManyIssuers` past `max_issuers` (16); an invalid `Options.node_id` panics in `init`.

- **2026-10-16** — wave W5: **`Manager`**, certificates that obtain and renew themselves (the `autocert` / CertMagic layer; scope core → **parity**). `manage(names)`, `maintain()` (one upkeep step, returns the next due time) / `run()`; renewal at a random time in the CA's ARI window (`Issuer.renewal_window`, re-polled at its `Retry-After`) or `renewal_window_pct` of the lifetime remaining (default a third, half for ≤ 10-day certificates), the renewal naming its predecessor (`replaces`); back-off 1 min doubling to `max_backoff_s`, `Retry-After` honoured; issuers (`Issuer`, `AcmeIssuer` over a `Client`, `issuer_policy` in order / random) with fallback; every issued chain checked before it is stored or served (`checkPair`: `x509.verifyChain` to `trust_anchors`, every name in the SAN, the key matches); `certificate(sni)` (exact, one-label wildcard, `default_server_name`), `tlsAlpnMaterial(sni)`, `httpMiddleware()` (HTTP-01 + autocert's redirect), `challengeSolvers()` for the client; **on-demand** issuance (`OnDemand`: required `allow` policy, ring-buffer rate limit, failure back-off, concurrent handshakes share one issuance); **fleet**: storage locks around issuance, `distributed_challenges`; events `installed` / `failed` / `storage_failed`; `loadOrCreateAccountKey`, `issuerName`. New **`storage`**: `Storage` (load / atomic store / delete / lease `tryLock` / `unlock`), `DirStorage` (0700 dirs, 0600 files, fsync + rename, exclusive-link lock files), `MemStorage`. `Client.tlsAlpnValidation` (the RFC 8737 validation certificate for a caller's own solver; the built-in TLS-ALPN-01 solver uses it).
  - Tests: `manager_test.zig` over openssl fixtures with fixed validity windows (`tools/gen_manager_fixtures.sh`) and an injected clock — every schedule to the second (renewal, back-off, ARI, ten-day rule), restart from storage, fleet lock, issuer fallback past a wrong-key chain, on-demand incl. four concurrent handshakes, HTTP-01 / TLS-ALPN-01 shared through storage, failing storage; the storage contract against both backends; an `AcmeIssuer` through the mock CA with the manager's solver. **Pebble:** new `manager` scenario (DirStorage, real keys, Pebble's root as anchor: issue, ARI window, renewal at the window, restart from storage, TLS-ALPN-01, on-demand) 12/12 live.

- **2026-10-16** — Docs: DNS-01 helpers and the generic publishers (wave W4) live in the new sibling module
  `acmedns` (`Dns01Solver` for `Options.solvers`); README and SPEC point there. No code change here.

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
