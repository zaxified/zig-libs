# lms — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-03** — **NO CONSUMER-VISIBLE CHANGE:** first audit (review + schemata mutation run,
  67 mutants: 60 killed, 7 equivalent; 7 survived the first pass and are now killed). Eight tests
  added: the persist hook runs before any signature byte exists, an allocation failure while
  building a lower tree burns no leaf, a lower tree is built once per parent leaf and differs
  per parent, an exhausted position restores as exhausted, mutual exclusion of `SigningKey` (spin
  and `Io` guards), `cacheHeight`, exact-size output, `L` outside 1..8. No source change.

- **2026-10-01** — `Persist.io`: the `Io` the persist hook blocks in. With it, `SigningKey.sign`
  guards with an `std.Io.Mutex`, so a second signer parks instead of spinning on one suspended
  in the hook — required when the `Io` runs several tasks on one thread. Without it, unchanged.
  Found by the spinlock audit that followed the simio kv pilot.
- **2026-09-30** — New module: LMS and HSS (RFC 8554), the stateful hash-based
  signature scheme of NIST SP 800-208 and CNSA 2.0. SHA-256, n = 32 sets:
  LMS H5 / H10 / H15 / H20 / H25 and LM-OTS W1 / W2 / W4 / W8, any mix per HSS
  level, HSS with L = 1..8. Verification (`hssVerify`, `lmsVerify`, allocation
  free, `false` on every malformed input, every length and typecode checked
  before it indexes), key generation from a caller-supplied `(SEED, I)` per
  Appendix A, and stateful signing (`SecretKey`, `LmsSecretKey`, the hardened
  `SigningKey` with a durable-position hook and a copy guard). Verified against
  RFC 8554 Appendix F: both HSS signatures verify, and Test Case 2's two public
  keys and both LMS signatures are reproduced byte for byte from the RFC's SEED,
  I and randomizer. Maturity task B4.
