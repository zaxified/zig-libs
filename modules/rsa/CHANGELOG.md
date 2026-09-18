# rsa — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-16** — documentation only: `PublicKey.fromDer` re-measured at
  453 µs (was recorded ~500 µs on 2026-09-08). It still decides `x509`'s
  PKCS#1 v1.5 dispatch, whose threshold is 352 µs.

- **2026-09-16** — **additive API:** `rsadpPtr`, `rsadpCrtPtr`,
  `rsadpCrtBlindedPtr` and `rsasp1Ptr` take the secret key as
  `*const SecretKey`. Every existing signature is untouched, so no consumer
  changes (DECISIONS.md P3). Why they exist: passing a `SecretKey` by value
  makes an ABI copy at the CALL SITE, in the caller's frame, which no zeroing
  on either side can reach. `blindrsa`'s dead-stack probe measured it — `p`
  and `q` readable after `blindSign`, 2 hits each, unaffected by a 512 KiB
  stack burn because the copy lives above the callee's frames — and 0 through
  the pointer form. Internally `privateOp`/`privateOpCrt` now forward to
  pointer-taking twins, and `makeBlinding` takes the key by pointer too, so
  the key crosses no by-value boundary on the CRT path.

- **2026-09-11** — **Additive: new `decryptOaepHNoFail`** (A1 fix campaign
  round 2, `QUESTIONS-ROUND-2.md` Q4, cross-module with `xmlenc` F3's OAEP
  arm — one commit, both modules). Every existing OAEP entry point
  (`decryptOaep`, `decryptOaepBlinded`, `decryptOaepH`, `decryptOaepHBlinded`)
  keeps its exact current signature and behavior; this is a new function
  alongside them, not a change to any of the 13 in-repo consumers. It shares
  `decryptOaepHBlinded`'s RSADP + branch-free MGF1/lHash/separator-scan
  decode, folds the caller's expected message length into the SAME
  branch-free validity mask (rather than leaving it a post-hoc check, which
  would reopen a length-based oracle — the same reasoning `rsaPkcs1v15Unwrap`
  already documents for its own `want` fold), and reports a padding failure
  as `{.ok = false, .raw = <the RSADP output>}` instead of an early `error`,
  so a caller building a Bleichenbacher-style decoy-CEK countermeasure (RFC
  8017 §7.2.2's classic construction, until now only expressible for PKCS#1
  v1.5 in this module) can do so for OAEP without re-implementing OAEP's
  padding-decode cryptography itself. ⏸ **ODLOŽENO NA KONEC KAMPANĚ —
  vyžaduje re-pin ctgrind řádku** (`scripts/checks/ctgrind-expected.tsv` rows `rsa
  ReleaseFast crt`/`noncrt`): this edit touches `src/root.zig`, one of the
  files the digest covers, so the pin goes red until the coordinator
  re-measures and re-pins at campaign end — not a defect, the digest doing
  its job. `scripts/modtest rsa`: 85/86 (Debug/ReleaseSafe, 1 unrelated
  skip), 85/86 (ReleaseFast).

- **2026-09-09** — **NO CONSUMER-VISIBLE CHANGE:** `src/ctgrind_harness.zig` is added, tainting the CRT private parameters (`p`, `q`, `dp`, `dq`, `qinv` and their Montgomery params) through `rsadpCrt`, and `d` through `rsadp`. Measured ReleaseFast: **213 in-file contexts for `crt`, 2 for `noncrt`**, untainted control 0 and no-`-fvalgrind` trap 0 in every row. ⭐ About 104 of the 213 are not this module's arithmetic at all but `std.crypto.ff` — `Modulus.reduce`'s length-dependent `memcpy` (86) and `Fe.shrink`'s leading-zero strip (29) — reached from `reduceWide` and `Fe.fromBytes`. `SPEC.md:64` says "never branches on secret data", under "Threat model / out of scope", while `SPEC.md:59` already speaks of "a residual leak in the constant-time claim" that blinding exists to decorrelate; this row is the first instrument for either sentence, not a refutation of them. ⚠ Four contexts (`montPowSecret`, `if (s == mp.L)`) are likely a granularity artifact — `L` is a limb count fixed by key SIZE, not by `p`/`q`'s value — and were left tainted and written down rather than carved out.

- **2026-09-08** — **Docs: the "no per-operation setup cost is paid" claim now
  says whose precondition that is.** It holds for a caller that reuses a key and
  not for one that builds a fresh key per operation, which is exactly what
  certificate path validation does — measured, ~500 us to build a 2048-bit
  public key against 36 us to verify with it. `SPEC.md` gains a "Performance
  posture" section with the split (~185 us of `std.crypto.ff` Montgomery
  constants the hot path never uses, ~315 us of `montint` setup), the OpenSSL
  comparison (this module's verify is 2.1x OpenSSL and needs no work; std's is
  22.3x), and why neither remaining optimisation was taken.
  NO CONSUMER-VISIBLE CHANGE (documentation only).

- **2026-09-07** — Test-only, neither BREAKING nor BEHAVIOURAL. All six key-parsing
  fuzz targets (`PublicKey.fromDer`/`fromPem`, `SecretKey.fromDer`/`fromPem`,
  `fromPkcs8`, `fromOpenSSH`) drew their input with `smith.bytes(&buf)` followed by
  `smith.valueRangeAtMost(u16, 0, buf.len)`. `bytes` consumes `@min(buf.len, in.len)`
  octets, so the ranged draw found fewer than the eight it reads as a little-endian
  `u64` and returned the range minimum — **zero on every input** — and none of the six
  had a corpus, so each ran exactly one input for ever: `fromDer("")`, `fromPem("")`,
  `fromOpenSSH("", "")`. Not one octet of a key had ever been through them here.
  Replaced each draw with a single `smith.slice(&buf)` and gave each target a corpus of
  8–9 seeds built from the module's own `kat2048_der`/`kat2048_pem`/`openssh_fixture_*`
  fixtures, roughly half of them a real encoding one octet off (arbitrary bytes cannot
  produce a DER `RSAPrivateKey` whose primes multiply back to the modulus). Three
  buffers were also too small for the module's own fixtures — 1024 against a 1191-octet
  PKCS#1 key, a 1217-octet PKCS#8 one and 1824–1877-octet OpenSSH ones — and a seed
  longer than the buffer reads back EMPTY, so those three could never have carried a
  real private key; raised to 2048/2048/2560. `fromOpenSSH`'s passphrase was hardcoded
  to `""`, which stops at the bcrypt KDF for every encrypted key and left the
  aes256-ctr/aes256-cbc halves unreachable; it now travels in the seed as a second
  length-prefixed field. Each target has a `corpus:` guard pinning the measured
  non-empty count, the accepted count and the number of DISTINCT moduli that came back
  out — the last is the number a collapsed corpus cannot hold up, since it only moves
  when a seed's own octets reach the key. Measured 0 non-empty / 0 accepted / 0 distinct
  before on every target; after: fromDer(pub) 8/3/2, fromDer(sec) 8/3/2, fromPkcs8
  6/2/2, fromPem(pub) 7/3/2, fromPem(sec) 7/2/1, fromOpenSSH 8 non-empty / 3 with a
  passphrase / 5 accepted. ⭐ The corpus reaches two guards that had never executed: the
  `qInv·q ≡ 1 (mod p)` self-check in `fromPrimes`, whose comment says "catches a
  non-prime p sneaking past" and which nothing had ever handed a non-prime p, and
  `parsePrivateSection`'s `n == p*q` cross-check. Verified: `zig build test-rsa
  --summary all` 81 pass, 1 skip; `check-fuzz-reach` rsa 6 collapsed → 0.
- **2026-08-18** — Portability fix (`check-portable`): `eksBlowfishSetup`'s
  `const n = @as(usize, 1) << cost;` (`cost: u6`, the bcrypt_pbkdf expensive-schedule
  round count) failed to compile on a 32-bit target, where `Log2Int(usize)` is `u5` and
  can't hold every value the public `cost: u6` parameter allows. `n` is an iteration
  count, not a memory-sized quantity, so retyped it (and the loop counter `i`) as fixed-
  width `u64` — the direction that keeps `cost`'s full advertised 0..63 range on every
  target, rather than narrowing the type derived from `usize` and silently capping
  `cost` at 31 on 32-bit hosts. Compile-only for every `cost` value already in use here
  (`bcryptHash` always calls it with the hardcoded `cost = 6`); no behavioural test
  added since no exercised input changes result. Verified: `zig build portable-rsa`
  still reports unrelated wasi-surface failures (`os.linux.VDSO`,
  `process.Environ.GlobalBlock.view`) — out of scope for this fix — but the `u5`/`u6`
  diagnostic this fix targeted is gone; `zig build test-rsa --summary all` still 75/76
  (1 pre-existing skip).
- **2026-08-13** — Test-only, neither BREAKING nor BEHAVIOURAL. Removed `test "rsa
  module compiles"`, whose body was `try testing.expect(true)`. It forced nothing —
  this file is already the test root and carries 76 other tests — so all it did was
  make the module's test count larger than its coverage. The fourth and last copy of
  a tautology that came from `modules/_template`, which no longer ships one.

- **2026-07-18** — Security audit: four findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Verified: Byte-exact vs OpenSSL.
  `signPkcs1v15` matches OpenSSL SHA-256/384/512 known answers (`root.zig:2171`).
- **2026-07-10** — New module: Pure-Zig RSA (PKCS#1 v2.2, RFC 8017) over
  `std.crypto.ff`.
