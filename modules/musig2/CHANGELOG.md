# musig2 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
