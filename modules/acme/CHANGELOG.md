# acme — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
