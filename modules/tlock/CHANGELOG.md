# tlock — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-27** — **NO CONSUMER-VISIBLE CHANGE:** killing tests and stack probes of `encryptStream` / `decryptStream` from the 2026-11-25 delta mutation run.
- **2026-11-26** — **NO CONSUMER-VISIBLE CHANGE:** dead-stack coverage sweep, wave 3: a `testkit.stackprobe` probe of the public secret entry points no probe called — `age.PayloadStream.sealChunk` / `openChunk` (`src/stackprobe2_test.zig`). Clean. Test only.
- **2026-11-24** — New: the **G2-signature scheme** (drand `"pedersen-bls-unchained"`, kyber `EncryptCCAonG1`): `CiphertextSigG2` (80 bytes, `U ∈ G1`), `encryptSigG2`/`decryptSigG2`, `ciphersuite.h1SigG2` (identity hashed onto `G2`), and the age layer's `encryptSigG2`/`decryptSigG2`/`encryptAllocSigG2`/`decryptAllocSigG2`/`encryptStreamSigG2`/`decryptStreamSigG2`/`encryptedLenSigG2`, with `age.Scheme`. **Source-breaking:** `age.Recipient.ciphertext` is now the union `age.StanzaCiphertext` (`.sig_g1` is the former `Ciphertext`; the stanza body length picks the arm, 128 or 80 bytes), so code that read `recipient.ciphertext` directly adds `.sig_g1`; a stanza of the scheme the called function is not for is `error.InvalidCiphertext`. Verified against the retired testnet `testnet-unchained-3s`: a Go-`tle`-produced file decrypts and re-encrypts byte for byte. ctgrind rows `fp12pow_g2` and `decrypt_g2`; stack probe over the new entry points.
- **2026-11-23** — **NO CONSUMER-VISIBLE CHANGE:** the dead-stack probe (`src/stackprobe_test.zig`) also applies the residue rule (`testkit.stackprobe.residueOf`) to its snapshots: a non-zero byte below a measured call's burn now fails it, whatever secret the needle model names or misses. Clean. Test only.
- **2026-11-21** — New streaming ASCII armor: `age.ArmorWriter` (a `std.Io.Writer` that armors into another writer; `finish` writes the last line and END) and `age.ArmorReader` (a `std.Io.Reader` of the binary bytes of an armored stream; malformed armor is `ReadFailed` with `err = error.MalformedArmor`), as age's `armor.NewWriter`/`armor.NewReader`; composed with `encryptStream`/`decryptStream` they armor/de-armor files of any size. Byte-identical to `armor`, as strict as `dearmor`. Additive.
- **2026-11-20** — **NO CONSUMER-VISIBLE CHANGE:** `encrypt`'s `Gid^r` is `bls12_381`'s new `Fp12.pow` (the same construction, moved upstream); the private `fp12Pow`/`fp12CtSelect` copy and its tests are gone (the tests live in `bls12_381`). Same ciphertexts.
- **2026-11-17** — streaming encrypt/decrypt: `age.encryptStream` and `age.decryptStream` over `std.Io.Reader`/`std.Io.Writer`, the binary age file one 64 KiB STREAM chunk at a time (one allocation of about 128 KiB), after drand/tlock's `Encrypt(dst io.Writer, src io.Reader, round)` / `Decrypt(dst, src)`. Output is byte-equal to `encrypt` for the same `Randomness`; the Go-`tle` fixture decrypts through it. Additive; the private header writer was split out of `encryptBody` with no change in output. Plaintext of chunks before a failing chunk has already reached the writer (each chunk is authenticated first). Armor stays whole-buffer. Delta mutation: 32 mutants, 30 killed, 2 equivalent; card counts cumulative (44/48, 4 eq).
- **2026-10-24** — **NO CONSUMER-VISIBLE CHANGE:** the `strRepeat` helper (the Zig 0.17 stand-in for `**`) builds its string with one `@splat` + `@bitCast` instead of a comptime loop, which Sema evaluated in O(n²) (http's test binary: 323 s → 13 s). Same bytes, faster compile.


- **2026-10-18** — Ported to Zig 0.17.0. `strRepeat` is now `inline fn`: a runtime call made `headerText`'s `++` result a dangling stack temporary (Header.parse tests failed). New regression test pins the header bytes.
- **2026-10-10** — tests: deterministic fuzz driver `TLOCK_FUZZ` (`tlock-age-decoders`, `tlock-age-file`, `tlock-ciphertext`). New oracles: a payload this module sealed opens and one flipped octet refuses; a genuine age file (real quicknet round-1000 key and signature) decrypts while a flipped octet, a truncation and an appended octet are refused (all 10,000 flips refused, header MAC included); the pristine ciphertext decrypts and no damaged one does. No change in `src/` outside tests.
- **2026-10-09** — **BREAKING, HIGH: the BF-IBE core and the age layer left their secrets on the
  dead stack.** New ReleaseFast stack probe (`stackprobe_test.zig`; the round signature is public
  and not a needle), 5 calls each, before → after: `encrypt` the message 10, sigma 10, the FO
  scalar r 20, the pairing value 630 (+540 in drand's cubed form) and both masks; `decrypt` the
  same, recovered (r 20, pairing value 420 + 180); `age.encrypt` the file key 30 and the BF-IBE
  core's r and pairing value; `age.decrypt` the file key and the pairing value; `Randomness.draw`
  the file key/sigma 30 — all now 0 (the payload layer was already clean). Secrets in by pointer,
  out through an out-param, bodies one frame down and burned (`burn.zig`):
  - `encrypt(p_pub, round, message: *const [16]u8, sigma: *const [16]u8)`;
    `decrypt(out: *[16]u8, round_signature, ct) DecryptError!void` (`out` zeroed on error);
    `ciphersuite.randomSigma(out, io)`;
  - `age.Randomness.draw(out, io)` (+ `wipe`), `age.encrypt`/`encryptAlloc(…, rnd: *const
    Randomness, …)`, `age.PayloadStream.init(out, key: *const [32]u8)`,
    `age.sealPayload(out, key: *const [32]u8, pt)`, `age.openPayload(out, key: *const [32]u8, …)`.
  - Fixed: `age.sealedLen` failed at comptime (`@max` narrowed the chunk count to `u1`).
- **2026-10-06** — **API ADDED, NO BEHAVIOURAL CHANGE:** `age.PayloadStream` — the age STREAM
  one chunk at a time (`init(key)`, `sealChunk(out, plaintext, last)`, `openChunk(out, sealed,
  last)` refusing chunk-shape violations with `MalformedPayload`, `wipe`), for callers that
  stream (`timelock_envelope`'s version 2). `age.sealPayload` / `age.openPayload` (whole-buffer)
  are now public and are loops over it, so the Go-`tle` whole-file KAT covers the chunk code.

- **2026-10-06** — ADDED: `tlock.age`, the age v1 envelope drand/tlock's `tle` writes —
  the `tlock` stanza, the HKDF/HMAC-SHA-256 header MAC, the ChaCha20-Poly1305 STREAM payload
  in 64 KiB chunks and ASCII armor — so files of any length can be timelocked and opened:
  `encrypt`/`encryptAlloc`, `decrypt`/`decryptAlloc`, `inspectAlloc`, `Header.parse`,
  `armor`/`dearmor`, `Randomness.draw`, with exact-size helpers. New dependency: `chachapoly`
  (this repo). The stanza body is byte-exact against the genuine `tle` fixture; the MAC,
  STREAM and armor are spec-derived and round-trip-tested, not yet checked against a whole
  Go-produced file. Fuzz harness on the header, armor and payload decoders. Not breaking.
- **2026-10-05** — Mutation run: 14 of 16 killed, 2 equivalent; 0 tests added (the
  `fp12Pow` lookup's `<=` twin and the reject-path wipe of `message`, see SPEC).
  No code change.
- **2026-10-03** — `Ciphertext.fromBytes` refuses a `U` outside `G2` (`bls12_381`'s
  checked decoder, `error.NotInSubgroup`), so `decrypt`'s pairing never sees a torsion point.

- **2026-09-09** — LICENSE ELECTION stated: MIT. The drand upstreams this module models are
  dual-licensed Apache-2.0 OR MIT and the NOTICE named the dual licensing without ever saying
  which branch this repository takes — so the module formally stood under BOTH, and the
  Apache branch's §4(a)/§4(b) conditions were unmet. The same election `rescue` and `lnwire`
  already make, for the same reason.

- **2026-09-07** — `fuzzDecrypt` is a damage harness that applied no damage. Its flip count
  came from `smith.valueRangeAtMost(u8, 0, 6)`, a ranged draw, which reads eight octets as a
  little-endian `u64` and returns the range MINIMUM unless that whole word lands inside the
  range — so it was 0 on every replay, the corruption loop never executed once, and
  `Ciphertext.fromBytes`/`decrypt` were handed the PRISTINE ciphertext every time. The damage
  script now comes out of one `smith.slice` call as the first draw and is read with
  `testkit.fuzz.Cursor` (`NN` flips, then position/value pairs), with an eleven-script corpus
  aimed at the G2 compression flag byte, the far end of `U`, and each of `V` and `W`.
  Measured: **0 flips and exactly 1 distinct ciphertext across the corpus before; 16 flips, 11
  distinct ciphertexts, 8 decoded and 1 decrypted after.**
- **2026-08-14** — Test-only: `kat_test.zig` gained a `testing.fuzz` harness on
  `Ciphertext.fromBytes`/`decrypt` (corrupted ciphertext bytes against a
  fixed, self-consistent beacon-shaped keypair) — `zig build check-fuzz` no
  longer names this module. No panic/OOB found; **neither breaking nor
  behavioural**.
- **2026-08-13** — Test-only: `kat_test.zig` gained "entropy seam: randomSigma
  really draws, and two encryptions of one message differ". **Neither
  BREAKING nor BEHAVIOURAL** — no production code changed; this adds the
  coverage that was missing for the draw the entry below made fail-closed.
  Every other test here feeds `encrypt` a FIXED `sigma` on purpose (that is
  what makes the drand interop vector reproducible), so nothing ever looked
  at a drawn one: hardcoding `randomSigma`'s buffer to a constant left all
  33 tests green. The new test asserts two draws differ AND that two
  encryptions of one message to one round differ in `U`/`V`/`W` and still
  open under the genuine round-1000 signature — verified by planting
  `@memset(&buf, 0x5a)` after the draw: 33/34, exactly this test red. Its
  stated limit: it catches a constant and an ignored `io`, not a
  weak-but-varying PRNG; which vtable slot the bytes come from is pinned in
  `entropy`'s own suite.
- **2026-08-12** — `ciphersuite.randomSigma` draws through the new `entropy` module
  (`entropy.fill`, i.e. `std.Io.randomSecure`) instead of `io.random`. Not
  breaking: `fill` returns `void`, so the signature is unchanged and still
  returns a plain `[block_bytes]u8`. `std.Io.random` is a CSPRNG whose
  contract permits a silent fallback to a weaker seed (`std/Io.zig:2462`)
  and the default `Io.Threaded` takes it, seeding from pid + wall clock +
  an ASLR pointer. A guessable `sigma` opens a timelock ciphertext before
  its round, which is the single property the construction sells, so the
  draw now fails closed. The KAT path is untouched — `encrypt` still takes
  `sigma` as an explicit parameter, and every fixture supplies its own.
- **2026-07-18** — Security audit: two findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Verified: byte-exact bidirectional
  interop against a genuine `drand/tlock` Go `tle` ciphertext.
