# falcon — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-10** — tests: deterministic fuzz driver `FALCON_FUZZ` for Falcon-512 and -1024 (`falcon-{512,1024}-{verify,open,pubkey,seckey}`, new `src/fuzz_test.zig`): the genuine NIST-KAT signature field / signed-message envelope is accepted and every other octet string (real encoding with 0-3 octets damaged or truncated, wild bytes behind the right header) refused; a flipped message or nonce octet is refused; a decoded public key re-encodes to the same octets; a decoded secret key never panics in `publicKey()` and the pristine one reproduces the KAT public key. No change in `src/` outside tests.
- **2026-10-09** — **Fix: the small dead-stack burns left up to 63 bytes unzeroed.** With 32-byte
  vector stores LLVM realigned the frame of a burn of 2 KiB or less (`and $-32, %rsp`), and the 32..63
  bytes between the zeroed buffer and the saved frame pointer kept whatever a callee had left there
  (a 32-byte scalar survived in `voprf`'s probe). Here that was `shake_burn` (2 KiB). Every burn now uses 16-byte
  stores, which need no realignment. No API change.

- **2026-10-09** — **BREAKING, HIGH: key generation, secret-key decode/encode and signing left the secret basis, the seed-derived state and the sampled short vector on the dead stack.**
  New ReleaseFast stack probe (`stackprobe_test.zig`; Falcon-512 and Falcon-1024; 5 calls each; needles = seed,
  SHAKE256 stream, encoded secret key, f/g/F/G as small ints, lifted polynomials, NTT forms, FFT doubles, the
  sampler's Gram matrix, the per-signature RNG seed, the ChaCha seed/state, the accepted s1/s2), hits before → after:
  `generateKeyPair` f 930 / g 930 / F 420 / G 960 / sk bytes 540 / NTT(g) 320 at 512 (1770 / 1740 / 960 / 1920 / 960 / 640 at 1024) — the
  `SigningKey` was returned BY VALUE through `Keygen.generate`, `Ntru.generate` (`Basis`) and `buildTree` (`Tree`), a
  copy per frame; `SigningKey.toSecretKeyBytes` returned the encoded key by value (650 hits at 512, 1060 at 1024) and left the
  trim-encoder's accumulators; `SecretKey.fromBytes` returned f/g/F by value (85 / 155 / 155 / 75 at 512, 155 / 295 / 290 / 165 at 1024);
  `SecretKey.publicKey` / `poly.computePublic` left NTT(g) (320 / 640); `signRandomized` left the per-signature seed (15), the ChaCha
  seed (30) and state (180) and the candidate s1/s2 (960 + 960 at 512, 1920 + 1920 at 1024). Totals 7835 (512) and 15040 (1024) → 0.
  The FFT/Gram scratch inside `sampleSignature` was already wiped by its `defer`s; what survived was the candidate copies and the RNG.
  - `generateKeyPair(rng, sk_out: *SigningKey, pk_out: *PublicKey)` (was: returns `{ signing_key, public_key }`); `sk_out` is
    zeroed on error. Same for `generateKeyPair1024`. `keygen.Keygen.generate(rng, sk, h)`, `ntru.Ntru.generate(rng, out: *Basis)`.
  - `SecretKey.fromBytes(out: *SecretKey, bytes)` (was: returns the key; `out` zeroed on error), same for `SecretKey1024`.
  - `SigningKey.toSecretKeyBytes(sk, out: *[encoded_length]u8)` (was: returns the array).
  - `sign.ShakePrng.init(self: *ShakePrng, seed)` seeds in place (was: returns the state by value); new `deinit` wipes it.
  - `poly.Ring.fromSmall(out: *Poly, src)`; `ffsampling.buildTree(Ring, out: *Tree, f, g, F, G)`;
    `ffsampling.sampleSignature(Ring, tree, c, rng, out: *SignatureCandidate)`.
  - Key generation, signing, secret-key decode/encode, `computePublic` and the SHAKE256 absorb/squeeze run one frame down and zero
    what they dirtied (`burn.zig`; measured depths 55.3 / 104.4 KiB keygen, 71.5 / 138.3 KiB sign at 512 / 1024, burns 80 / 144 and
    96 / 176 KiB). `signWithRng` wipes each attempt's candidate.
  - No heap is involved (the module does not allocate). `check-fp-freedom.sh` and the KATs are unchanged. The ctgrind harness
    (`ctgrind_harness.zig`) only changed its keygen call; the source digests of the falcon row need the coordinator's re-pin.

- **2026-09-09** — **NO CONSUMER-VISIBLE CHANGE:** `src/ctgrind_harness.zig` is added, tainting the NTRU trapdoor `sk.tree.{f,g,big_f,big_g}` through `signRandomized`. ⛔⛔ This reverses `SPEC.md`'s standing decision that the module should NOT have such a row, and the measurement is what reversed it. That argument was entirely about the sampler — `berExp`'s early break and the reject loop's value-dependent trip count, both deliberate reference design — so a row would be "a permanent red that measures the reference design rather than a defect". Measured ReleaseFast: **133 in-file contexts, of which the sampler is 16** (`gaussian.zig:208`, `:228`). The other **112 are `fpr.zig`** — `pack` 62, `half` 42, `add` 8 — which the same SPEC.md describes as a "branchless integer emulation of binary64" with "no data-dependent branch". ⚠ Not claimed: that those 112 are a real leak; claimed: the sentence finally has an instrument, and `check-fp-freedom.sh` could never have seen it (it objdumps for hardware FP instructions, and nothing here executes one). The row is pinned as a bound (`<=133`), since only the direction is load-bearing.

- **2026-09-07** — Fuzz reach: `fuzzVerify`'s corruption was one fixed octet. The flip
  loop opened `smith.valueRangeAtMost(u8, 1, 6)` as the harness's FIRST draw and the
  target had no corpus, so outside `--fuzz` it ran exactly one input and every draw in it
  collapsed to a minimum: one flip, at `smith.index(len)` = position 0, to
  `smith.value(u8)` = 0. The whole harness was "zero the first octet of a real NIST
  signature field", once, for ever. ⚠ A previous audit had already raised that lower
  bound from 0 to 1 and left a TEETH test pinning `n_flips >= 1` — a correct fix to the
  wrong half, because `1` is no better than `0` when the position and the value are
  minima too. The flip loop and its TEETH test are gone. A compressed signature field is
  a byte string off the wire, so it is drawn with one `smith.slice`, and the corpus is
  built at run time from the vector-0 field (the module owns no captured signature): the
  pristine field, its first octet zeroed (the old harness's only input, kept), its last
  octet flipped, a one-octet truncation, a same-length all-zero stream, and the empty
  field. A corpus guard builds from the SAME place the harness does and pins 5 non-empty
  seeds, `5 * sig_len - 1` octets reaching `verify`, and exactly 1 verification.

- **2026-09-03** — Drift re-audit (717 lines since the last one). ⚠ **BREAKING:**
  `Signer.SignError` gained `TooManyRetries`. `signWithRng`'s rejection-sampling
  loop was `while (true)` with `sig_out.len == 0` as its only length check —
  every other undersized buffer made `compEncode` fail, `catch continue` swallow
  it, and the next draw fail identically. **The call never returned**: an
  unkillable, non-allocating spin, not an error. The first audit recorded
  "`sig_out` too small → `error.NoSpaceLeft`" as a PASS in the same sentence that
  named the `catch continue` two lines above it; the halves contradict and
  neither was executed. Now capped at `max_attempts = 64` draws, reporting
  `NoSpaceLeft` when every rejection was for want of room and `TooManyRetries`
  otherwise.
- **2026-09-03** — The constant-time fix from the first audit — `src/fpr.zig`'s
  integer emulation, raised as a HIGH — had **no guard of any kind**. Replacing
  `fpr.div`'s body with a native `/` leaves the whole suite green and the KATs
  byte-exact, because the emulation is bit-identical to IEEE-754 and no value
  test can see the difference; `falcon` is on neither `scripts/checks/ctgrind.sh` nor
  `ctgrind-expected.tsv`. The property was held in place by a SPEC.md paragraph.
  New gate **`scripts/checks/check-fp-freedom.sh`**, wired into every `scripts/test.sh`
  lane: disassembles a ReleaseFast build and fails if a variable-latency FP
  mnemonic reached a non-test symbol. Verified red under that mutation, naming
  `vdivsd` in `fft.polyLdlFft` (the secret Gram matrix), `fft.polyDivAutoadjFft`
  and `fft.polyInvnorm2Fft`.
- **2026-09-03** — The `PublicKey.verify` fuzz harness ran **exactly one input
  with zero bytes flipped**. Outside `--fuzz`, `std.testing.fuzz` with an empty
  corpus runs one input, and `valueRangeAtMost` falls back to the range's LOWER
  bound on exhausted input — so `valueRangeAtMost(u8, 0, 6)` gave 0 flips and the
  harness verified the pristine, valid KAT signature on every ordinary test run,
  while the changelog recorded "no panic/OOB found". Lower bound is now 1, with a
  test pinning it.
- **2026-09-03** — Docs: `example/main.zig` warned that the seeded PRNG was a
  keygen hazard and said nothing about passing the SAME `rng` to
  `signRandomized`, which emits a byte-identical 40-byte salt on every run —
  precisely what `signDeterministic` was deleted for. `SigningKey.secureZero`'s
  doc named double-call as the hazard; the real one is that a wiped key stays
  callable. SPEC.md's `objdump` evidence claimed the FP hits were confined to
  "exactly two functions"; re-running its own grep finds four (all tests, so the
  substantive claim survives — the reproducible count did not, and was already
  wrong when written).

- **2026-08-14** — Test-only: `kat_test.zig` gained a `testing.fuzz` harness on
  `PublicKey.verify` (corrupted compressed-signature bytes against the fixed
  NIST-KAT public key/message/nonce) — `zig build check-fuzz` no longer names
  this module. No panic/OOB found; **neither breaking nor behavioural**.
- **2026-07-18** — Security audit: two findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Byte-exact against NIST Round-3 KAT's
  published test vectors.
- **2026-07-11** — New module: Full FN-DSA — Falcon-512 and Falcon-1024 (the NIST PQ
  lattice signature): verification + signing + key generation + all key/signature
  codecs, byte-exact vs the NIST Round-3 KATs for both parameter.
