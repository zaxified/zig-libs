# musig2 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-09** — **BREAKING:** `nonceGen(out: *NonceGenResult, sk: ?*const [32]u8, …, rand_prime: *const [32]u8, io) NonceGenError!void` — the result goes through `out` (zeroed secnonce on error), `sk` and `rand_prime` by pointer (were by value: the caller frame kept copies); migrate with `var r: NonceGenResult = undefined; try nonceGen(&r, &sk, …, &rand_prime, io)`. `nonceGen` now runs under a 32 KiB dead-stack burn (`burn.zig`); new `stackprobe2_test.zig` on `testkit.stackprobe`. `sign` unchanged.

- **2026-10-08** — **BREAKING + FIX (secrets in the caller's frame):** the dead-stack probe (`src/stackprobe_test.zig`) moved to the direct-region
  engine (p256's, 2026-10-08): the call runs under a `PAD`-deep shim, the region is painted and read
  through a pointer, callee-saved registers are scrubbed first. The old "claim an uninitialised
  buffer" engine could not see the top ~250–450 B of the call — the caller's and the wrappers'
  frames. It found `d'` in the
  caller's frame after `sign` (by-value argument). `sign(secnonce, sk: *const bip340.SecretKey,
  ctx)`. 0 residues after.
- **2026-10-08** — **FIX (secrets on the dead stack):** the dead-stack burn's buffer is now
  16-aligned instead of the vector type's natural 32. At 32 the burn's frame was realigned, and
  the up to 56 bytes between its saved frame pointer and the buffer — the top of the frame the
  burned body had used — stayed unzeroed (found by `threshold_ecdsa`'s stack probe: half of a
  secret survived there). No API change.
- **2026-10-08** — **NO CONSUMER-VISIBLE CHANGE (speed):** the dead-stack burn zeroes with
  volatile 32-byte vector stores instead of `std.crypto.secureZero` (a volatile byte memset,
  ~3 B/ns without libc): ~30× faster per KiB burned. Same size, same depth; the ReleaseFast stack
  probe still reads 0.
- **2026-10-08** — Security (HIGH, no API change): `sign` left the secret key and both secret
  nonces on the dead stack — measured with the new `src/stackprobe_test.zig` (ReleaseFast): `d'`
  once and `k1'`/`k2'` four times each per partial signature. The work now runs one `noinline`
  frame down (the key passed by pointer) and 32 KiB of stack are burned after it returns.
- **2026-10-08** — **BREAKING:** `sign(secnonce: *SecNonce, sk, ctx)` takes the secret nonce by
  pointer and zeroes it on entry, on every call, failed ones included — BIP327's `Sign`
  overwrites `secnonce[0:64]` and libsecp256k1's `musig_partial_sign` clears it the same way. Before,
  `sign` took a copy and the caller's value survived every call, so a retry with another message
  signed twice over one nonce (the key-recovery case). A second `sign` with a consumed secnonce is
  now `error.InvalidSecNonce`. Migration: pass `&secnonce` (a `var`). Also: `partialSigVerify`
  returns `error.InvalidPublicKey` / `error.InvalidPubNonce` for a `signer_index` outside
  `pubkeys` / `pubnonces` instead of indexing out of bounds. Audit 2026-10-08 (`SPEC.md`).

- **2026-10-05** — Tests: first dated mutation run (54 mutants, 45 killed, 9 equivalent or
  unobservable; `SPEC.md` § "Mutation run 2026-10-05"). No defect; 4 new tests close the 6 test
  gaps it found — the aggnonce infinity encoding is exactly 33 zero bytes, secnonce scalars `n`
  and `n + 1` are refused, `keyAgg`/`nonceAgg`/`partialSigAgg` refuse an empty input, `sign`
  refuses a session listing the signer's x with the other parity. No source change.

- **2026-09-09** — **NO CONSUMER-VISIBLE CHANGE:** `src/ctgrind_harness.zig` is added (A1 audit finding R2; the tier-A ctgrind queue, 28 modules). Measured ReleaseFast under valgrind, in-file contexts: **sign 101**. Every target has an untainted control row and a no-`-fvalgrind` trap row, both 0, so the numbers are real taint propagation rather than a silent no-op. ⭐ 81 of the 103 total contexts are the mandatory self-verify (`partialSigVerifyInternal`) re-running k256's deliberately variable-time GLV/wNAF machinery on the partial signature about to be returned — the same shape `bip340` (63/80) and `adaptor` (74/90) show, at a near-identical ratio. That is a property of this signing family, not of this module, which is why the row is pinned as a bound. The pre-self-verify body is 17, all accepted classes. `root.zig:887`'s masked parity select re-canonicalises the selected bytes (2 contexts) — the mask is one uniform byte so the outcome never varies, reported rather than hidden.

- **2026-09-07** — Test-only, no production change: `fuzzPartialSigVerify`, the harness
  named "never panics on **corrupted** partial-signature bytes", had never corrupted a byte.
  Its first draw was `smith.valueRangeAtMost(u8, 0, 4)` and it had no corpus, so `n_flips`
  was the range MINIMUM - **0** - on every input the ordinary lane ever ran: it verified
  BIP327's own published valid partial signature, unmodified, every round. The perturbation
  script now comes out of one `smith.slice` read through `testkit.fuzz.Cursor`, so the byte
  draw is first and a seed is a readable `[flip count][position, value]...` script. And the
  flip budget was wrong independently of the draw: the harness's comment says the mutation
  lands "near the `s < n` boundary", but secp256k1's `n` has **fifteen leading 0xFF octets**,
  so no edit of four octets can raise a 32-octet scalar above it -
  `PartialSignature.fromBytes`'s range check was unreachable from here at any flip count it
  could draw. The cap is now 32 and one seed spends sixteen flips on exactly that refusal.
  Measured by the new `corpus:` guard: 6 non-empty scripts, **26 flips applied** (0 before),
  6 scalars parsed, 2 verified. A note for the next author: that sixteen-flip script is 33
  octets and was first written against a 16-octet `smith.slice` buffer, where it read back
  EMPTY rather than truncated; the guard's `nonempty` count is what caught it.

- **2026-08-14** — Test-only: `kat_test.zig` gained a `testing.fuzz` harness on
  `partialSigVerify` (corrupted partial-signature bytes against a fixed valid
  BIP327 session) — `zig build check-fuzz` no longer names this module. No
  panic/OOB found; **neither breaking nor behavioural**.
- **2026-07-18** — Security audit: no findings. Byte-exact against BIP327's published
  test vectors.
- **2026-07-12** — New module: MuSig2 multi-signature (BIP327) producing BIP340
  signatures.
