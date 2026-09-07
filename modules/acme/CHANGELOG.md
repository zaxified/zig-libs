# acme — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
