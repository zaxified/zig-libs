# rsa — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-18** — tests: mutation run over the 2026-10 additions (87 mutants of `marshal.zig`, the PBES2 walk, the F1 wire-field check, `pemDecodeBody`, the `HashId`/PSS-salt entry points and `der_writer.zig`: 80 killed, 7 equivalent) and 12 tests added for its 49 first-run survivors: PBES2 structure and limit faults (generated `EncryptedPrivateKeyInfo`), wire `d` ≥ n, INTEGER minimality over many exponents, tail wipe and error zeroing of every writer, inclusive option caps, wrong digest lengths, the smallest PSS key, PEM label cap and same-label blocks. No library change from the run itself.
- **2026-10-18** — **Constant time:** the PEM reader (`pemDecodeBody`, behind every `fromPem`) finds the END line with a scan for the first `-` after the body (base64 has none, so the compare is false on every key character) and then requires the END marker there, instead of std's forward Boyer-Moore-Horspool over the key's base64 (skip table indexed by key characters; found by acme's ctgrind, same code shape). The first block of a label is used, as documented; a `-` inside the body that does not start the END line is `InvalidPem`. ctgrind rows unchanged in count (the `crt`/`noncrt`/`keygen` targets do not read PEM), source digests re-pinned.
- **2026-10-18** — Backlog: the 2026-10-14 `rsa-pbes2` "4 damaged inputs accepted" item closed as not reproduced (0 of 18 473 damaged inputs over 22 000 driver seeds, and an exhaustive one-octet / truncation probe of the three PBES2 fixtures: 0 accepted). No code change.
- **2026-10-17** — **Added: first consumer build option** (CONVENTIONS §4.2): `-Drsa-max-modulus-bits=4096..8192` or `-Dprofile=small` (→ 4096) lowers `max_modulus_bits`; default stays 8192 (graded). Buys code size: HTTPS sizeprobe on a native (ADX/BMI2) CPU `.text` 8.27 → 4.63 MB. Keys above the cap are refused, never truncated; an out-of-range value is a `@compileError`. Tests: the 8192-bit KAT asserts the refusal under a lower cap; the cap test checks one byte over and exactly at the cap. SPEC § Build options.
- **2026-10-17** — Wycheproof test silent on success (the lane treats stderr from a passing test as a failure); it now asserts the vector file yielded valid and invalid cases instead of printing the counts. Test only.

- **2026-10-17** — Constant time: PEM base64 of keys (`marshal.zig` encoding, `pemDecodeBody` decoding) goes through the new `b64ct` module instead of std's alphabet tables, which a private key's DER indexed (SPEC backlog item, base64 half). Decoding follows libsodium's ignore rules with `pem_whitespace`; same accepted PEM. New dep `b64ct`.
- **2026-10-17** — **Added:** `der_writer` (`src/der_writer.zig`), the arena-backed DER encoder `selfSignedCert` builds with, now public and shared: `acme` (CSR, TLS-ALPN certificate, key PEM) and `ocsp` (request builder, test fixtures) use it instead of their own copies. `Builder`: `tlv`, `cat`, `seq`, `set`, `oid`, `bitString`, `octetString`, `boolean`, `null`, `integer` (minimal two's complement), `integerU64`, `integerRaw`, `enumerated`, `utcTime`, `generalizedTime`, `utf8String`, `explicit`, `implicitPrimitive`. Lengths are encoded in any definite form (the old private builder refused content ≥ 64 KiB with `ValueTooLarge`; that error stays in `SelfSignedCertError` but is no longer returned). `selfSignedCert` output byte-identical. Tests: every length-form boundary (0 … 2^24, framing checked by std's DER reader), INTEGER/ENUMERATED minimality, each tag.
- **2026-10-14** — **BREAKING (sizes) / Added:** `max_modulus_bits` 4096 → **8192** (owner decision; 16384 not followed): 8192-bit keys parse, sign, verify, encrypt, decrypt and generate. Sizes up to 4096 run as before (the montint slot follows the key), but every capacity-sized thing doubles: `max_modulus_len` 512 → 1024 (and the `max_*_der_len`/`pem_len` constants), a `SecretKey` (~2×), the stack of a private op — `burn.private_op_burn` 200 → 384 KiB (`fromPrimes` dirtied 325 KiB at the new capacity; STACKPROBE caught residue 232–277 KiB deep and is clean at 384). Consumers with `[rsa.max_modulus_len]u8` buffers compile unchanged; `blindrsa.Context.r_inv` widened with it (tests adapted). Doubling the capacity first cost 2048-bit speed (bench: blinded sign 1.08 → 1.12×, verify 0.83 → 0.91× OpenSSL — capacity-wide zeroing through Zig 0.16's byte-wise `compiler_rt.memset`, 1 KiB compares and wipes); verify now works on exactly k octets, blinding wipes only the slot limbs and takes `e` as a `u32`, with montint's slot-bound fixes → back to 0.85× / 1.08–1.09×. Evidence: an OpenSSL 3.5.5 8192-bit key round-trips byte-exact (PKCS#1, SPKI), PKCS#1 v1.5 sign byte-exact, OAEP-SHA256 ciphertext decrypts, PSS both ways, blinded = unblinded; a 1025-byte modulus is refused.
- **2026-10-14** — **Added (S2 scope, survey R3–R6):** run-time hash `HashId` (SHA-1, SHA-2 incl. 512/224 and 512/256, SHA-3; `digestLen`, `hashMessage`, `max_digest_len`) with `signPkcs1v15Digest`/`verifyPkcs1v15Digest`/`signPssDigest`/`verifyPssDigest`; prehashed verify `verifyPkcs1v15Prehashed`/`verifyPssPrehashed` (and on `VerifyKey`); PKCS#1 v1.5 DigestInfo for SHA-512/224, SHA-512/256, SHA3-224…512; PSS salt recovery `verifyPssAuto`/`verifyPssAutoPrehashed` (and `salt_len = null` in the `Digest`/`H` forms), `maxPssSaltLen`, decoupled MGF1 `signPssH`/`verifyPssH`; encrypted PKCS#8 (PBES2 + PBKDF2 HMAC-SHA1…512, AES-128/192/256-CBC): `fromPkcs8Encrypted`, `SecretKey.fromPemEncrypted` (also takes the cleartext labels), `SecretKey.toPkcs8Encrypted`/`toPemEncrypted` (`Pbes2Options` defaults = OpenSSL 3's shape), `max_pbkdf2_iterations` = 2^20 cap; scrypt, PBES1 and legacy `DEK-Info` PEM refused (`error.UnsupportedEncryption`, owner decision). `generate` enforces FIPS 186-5's `d > 2^(nlen/2)` (retry). New deps `aescbc`, `aes192`. Evidence: OpenSSL 3.5.5 KATs for every new hash (byte-exact v1.5 and salt-0 PSS incl. MGF1-SHA1), salt lengths 0/20/32/max recovered from OpenSSL signatures, OpenSSL's encrypted files (3 cipher/PRF pairs) decrypted and our output equal to theirs outside salt/IV/ciphertext; new fuzz harness `rsa-pbes2` (2000 runs clean). Internal: `safegcd` now lives in `montint` (`montint.safegcd`).
- **2026-10-14** — **Added:** key serialisation (`src/marshal.zig`): `PublicKey.toPkcs1Der`/`toSpkiDer`/`toPem(.spki|.pkcs1)` (also on `VerifyKey`), `SecretKey.toPkcs1Der`/`toPkcs8Der`/`toPem(.pkcs1|.pkcs8)`, `SecretKey.publicKey()`, `PublicKey.equal`/`bits`/`size`, buffer constants `max_*_der_len`/`max_*_pem_len`. Allocation-free, secrets written by position straight into `out` (zeroed on error); output byte-identical to OpenSSL 3 for all eight kat2048 fixtures. **SECURITY (audit F1) / behaviour change:** `SecretKey.fromDer`/`fromPem`/`fromPkcs8` now check the on-disk `n`, `dP`, `dQ`, `qInv` against the key derived from `p`, `q`, `e` and require `d ≡ e⁻¹` mod p−1 and q−1 (`error.InvalidPrivateKey` otherwise) — until now they were never read, so a file with a wrong `n` (e.g. a corrupted `q`, deriving another key) or `d` loaded silently. A valid `d` is kept as given (φ- or λ-reduced), so parse → write round-trips. Fuzz corpus counts re-pinned with that cause (secder 3 → 1 accepted, pkcs8 2 → 1).
- **2026-10-14** — perf (no API change): base blinding moved into the CRT domain — `r` (still drawn mod the public `n`) is reduced mod p and mod q, both halves inverted together by the new lockstep `safegcd.Inverter.invert2` (divsteps of the two problems on one 2×64-bit vector), and the blind (`(c mod p)·r^e`) / unblind (`m1·(r mod p)⁻¹`) are half-size; the redraw verdict is one branch. With montint's block kernels and chunked reducer, `bench-rsa` vs OpenSSL 3.5.5: 1.15–1.61× → 0.82–1.08× (worst `signbl_2048`). ctgrind `crt` 2 → 1 (the doubled F3 verdict context gone); a blinded op adds the one redraw verdict (jwt `rsa` 2 → 3, re-pinned with the cause).
- **2026-10-14** — tests: Wycheproof RSA vectors (`src/wycheproof_test.zig`, recipe `tools/wycheproof.py`, data in `src/testdata/`): 1553 PKCS#1 v1.5 verify, 241 PSS verify, 418 OAEP decrypt incl. digest≠MGF1 — no mismatch. NOTICE records the Apache-2.0 test data.

- **2026-10-13** — `signPkcs1v15Prehashed` and `signPssPrehashed`: sign a digest the caller already has (a TLS 1.2 CertificateVerify's running hash). Byte-identical to signing the message (OpenSSL KATs from the digest; PSS salt 0 agrees, salted verifies). Internals: the EMSA encoders take the digest; no output change for the existing entry points.
- **2026-10-13** — `PublicKey.verifyKey()`: the verify-only `VerifyKey` of a held public key (for `jwt`'s RS*/PS* signing keys).
- **2026-10-11** — New `VerifyKey` (`fromBytes`, `fromDer`, `verifyPkcs1v15`, `verifyPss`, `bits`): a verify-only public key for keys used once (certificate links, handshakes). It keeps the montint modulus and a `u32` exponent and skips `std.crypto.ff.Modulus.fromBytes`, whose Montgomery constants the verify path never reads; same acceptance as `PublicKey.fromBytes` (seeded differential, both verdicts ≥ 100 times). `verifyPkcs1v15`/`verifyPss` now share one body for both key types and take the `s < n` check from montint (boundary test `s = n−1, n, n+2` against the `ff` path). With montint's new public-modulus constructor (also used now by `PublicKey.fromBytes` for `n`), a cold 2048-bit key + verify costs a fraction of std's `Certificate` RSA path — x509 now routes PKCS#1 v1.5 here.
- **2026-10-10** — perf (no API change): the blinded private ops build `r⁻¹ mod n` with a new constant-time batched safegcd (`src/safegcd.zig`, verified `r·r⁻¹ ≡ 1` before use) instead of the variable-time `std.math.big` Euclid, and draw `r` as a montint element (no `std.crypto.ff` round trip); together with montint's new fixed-`L` kernels, `bench-rsa` vs OpenSSL 3.5.5 went from 1.44–2.84× to 1.15–1.61× (worst `decbl_2048`). The private-op `invModN` helper is gone; `bigModInverse` stays for `blindrsa`. ctgrind `crt` 2 / `noncrt` 0 / `keygen` 173 in-file, unchanged (digests re-pinned); STACKPROBE green.
- **2026-10-10** — tools: comparative benchmark `tools/bench.zig` + `tools/c_bench/foreign_bench.c` (`zig build bench-rsa`) against OpenSSL 3.5.5 at 2048/3072/4096 bits (PKCS#1 v1.5 sign/verify, OAEP decrypt, blinded and not); card Performance filled (1.44–2.84×), SPEC "Performance — bench-rsa" section and the levers in Backlog.
- **2026-10-09** — **Added:** `opensshDecryptSection` (+ `OpensshSection`, `OpensshCipher` now
  public): the openssh-key-v1 cipher/KDF half of `fromOpenSSH` (bcrypt rounds cap, aes256-ctr/-cbc),
  shared with the `ssh` module for non-RSA key types. `fromOpenSSH` itself unchanged in behaviour.
- **2026-10-09** — **BREAKING (error set) / SECURITY:** `fromOpenSSH` refuses a bcrypt round
  count above `max_openssh_kdf_rounds` (2048) with the new `error.KdfRoundsTooLarge`; the count
  comes from the key file and bcrypt_pbkdf is linear in it, so `rounds = 2^32-1` pinned the
  caller's CPU indefinitely. Same cap as Go's x/crypto/ssh. Found by `RSA_FUZZ`.
- **2026-10-09** — tests: deterministic fuzz driver `RSA_FUZZ` over the existing harnesses (the six key-parser harnesses also run a "mutated" overlay: a genuine fixture damaged in 0-3 octets / truncated; an undamaged one must be accepted as the 2048-bit key).
- **2026-10-09** — **BREAKING:** `selfSignedCert` takes the secret key by pointer (`sk: *const SecretKey`; call sites in x509, opcua, ocsp, saml, iec62351 migrated). `openssh.bcryptPbkdf` and `openssh.Blowfish.init` now run under a burn (`burn.kdf_burn`); `Blowfish.expandState` / `expand0State` and `eksBlowfishSetup` are no longer `pub` (nothing outside `openssh.zig` used them; `bcryptPbkdf` / `bcryptHash` / `init` are the entry points). Probe: `src/stackprobe2_test.zig`.
- **2026-10-08** — **BREAKING + FIX (secrets on the dead stack, HIGH):** the new ReleaseFast stack
  probe (`src/stackprobe_test.zig`) found `p`, `q`, `d`, `dP`, `dQ`, `qInv` and the CRT halves of
  the operation in dead frames after every `signPkcs1v15`, `signPss` and `decryptOaep` — dozens of
  copies, because `std.crypto.ff` passes its 4096-bit-capacity `Modulus` by value into every
  operation — and the whole 11.8 KiB `SecretKey` in the CALLER's frame on every call (by-value
  argument) and after every key load (error-union return). Every secret entry point now burns its
  stack (`burn.zig`, 200 KiB, ~2 µs against a ~1 ms private operation), every one that uses a key
  takes `sk: *const SecretKey` (`signPkcs1v15*`, `signPss`, `decryptOaep*`, `rsadp`, `rsadpCrt*`,
  `rsasp1`; the 2026-09-16 `*Ptr` forms are folded in and removed), and every constructor writes
  into an out-param zeroed on error: `SecretKey.fromPrimes/fromDer/fromPem(out, …)`,
  `fromPkcs8(out, …)`, `fromOpenSSH(out, …)`, `generate(out: *KeyPair, …)`. 0 residues after,
  caller's frame included.
- **2026-10-04** — Tests: mutation schemata run (59 mutants, 55 killed, 4 equivalent).
  Ten new negative tests, each breaking exactly one property of an otherwise valid
  input: over-long signatures (both verifiers), the PKCS#1 v1.5 PS ≥ 8 bound, a
  nonzero PSS PS/separator octet, a nonzero octet in front of a PSS EM on a 521-bit
  key, a stray OAEP PS octet / missing separator / Y ≠ 0 through `decryptOaepHNoFail`,
  the OAEP buffer preconditions, DER trailing bytes / extra fields / BIT STRING unused
  bits / PKCS#8 v2, an empty PEM body, and one-field-off OpenSSH containers. No
  behaviour change (the test helper `OpensshTestBuilder` grew to 2 KiB).
- **2026-10-03** — **Key derivation and Miller-Rabin are constant-time in the
  primes.** `SecretKey.fromPrimes` computes `n`, `λ = lcm(p−1, q−1)`
  (`montint.nt.lcm`), `d`/`dP`/`dQ` (`DynModint.inverseOfModulus`, inverses
  modulo even secrets) and `qInv` (Fermat on montint) on montint limbs instead
  of `std.math.big.int`'s gcd/divFloor/extended Euclid and `std.crypto.ff`'s
  pow; the values are unchanged (the OpenSSL KAT pins all four). `generate`'s
  Miller-Rabin runs on `DynModint.isProbablePrime`. New ctgrind target
  `keygen`. Remaining: `ff` `Modulus` carriers of `p`, `q` (Backlog). Key import
  costs a few milliseconds more (gcd/lcm at the full 4096-bit capacity).

- **2026-10-02** — **The whole private-key path is off `std.crypto.ff`.**
  The CRT op's reduction of `c` mod p/q, the Garner recombination, the base
  blinding/unblinding and the F3 re-encryption ran in `std.crypto.ff`, whose
  `reduce` and `montgomeryMul` branch on the secret primes in ReleaseFast. They
  run on `montint.DynModint` now (which also replaces this module's private
  `MontParams`/slot copy); `dP`/`dQ`/`qInv`/`d` are read from their `Fe`s by a
  positional limb repack. ctgrind: `crt` 213 → 1 in-file (the F3 verdict),
  `noncrt` 2 → 0. API unchanged.

- **2026-10-02** — **Comments and SPEC no longer call key construction
  constant-time.** `qInv` and Miller-Rabin use `std.crypto.ff`'s pow, which
  branches on the exponent in ReleaseFast, and `d` comes from `std.math.big.int`;
  Backlog entry "constant-time key generation and import". No code change.

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
