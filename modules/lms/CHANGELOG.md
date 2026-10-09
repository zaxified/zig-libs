# lms — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-09** — **Fix: the small dead-stack burns left up to 63 bytes unzeroed.** With 32-byte
  vector stores LLVM realigned the frame of a burn of 2 KiB or less (`and $-32, %rsp`), and the 32..63
  bytes between the zeroed buffer and the saved frame pointer kept whatever a callee had left there
  (a 32-byte scalar survived in `voprf`'s probe). Here that was `sign_burn` (2 KiB). Every burn now uses 16-byte
  stores, which need no realignment. No API change.

- **2026-10-09** — **BREAKING + FIX (HIGH: seeds and OTS secrets on the dead stack):** the first
  `stackprobe_test.zig` (ReleaseFast) found the SEED left in the dead stack after `Tree.init`
  (30 hits in 5 calls, 111..375 B deep) and, for HSS `SecretKey.init` + first `sign`, the SEED
  (40) and the derived child SEED (30), 239..2703 B deep, all from by-value seeds in the
  caller's and the module's frames. Now 0 hits in every probed call (LMS and 2-level HSS keygen
  and signing, freed heap included, NEG = 0, POS >= 1); without the new burns the probe finds
  `x_q[i]` and OTS chain values up to 1503 B deep. API: the seed is passed by pointer and every
  key is built through an out-parameter, with the seed zeroed on error —
  `Tree.init(out: *Tree, gpa, lms, ots, id, seed: *const [32]u8)`, `Tree.initCached(out, …, seed, c)`,
  `LmsSecretKey.init(out: *LmsSecretKey, …, seed: *const [32]u8)`,
  `SecretKey.init(out: *SecretKey, gpa, levels, seed: *const [32]u8, id, restore_at)` (all return
  `!void`), `SigningKey.init(dst, sk: *SecretKey, persist)` (moves the key and wipes the source),
  `core.deriveX(out: *[32]u8, id, q, i, seed)`. The tree build, `Tree.sign` /
  `signWithRandomizer` and the HSS child-tree builder run one frame down (new `burn.zig`) and
  zero what they dirtied (4 / 2 / 4 KiB, measured 2.2 / 1.5 / 3.1 KiB). Migrate: declare
  `var sk: lms.SecretKey = undefined;` and call `try lms.SecretKey.init(&sk, gpa, levels, &seed, id, null)`.
- **2026-10-08** — **FIX (secrets on the dead stack):** the dead-stack burn's buffer is now
  16-aligned instead of the vector type's natural 32. At 32 the burn's frame was realigned, and
  the up to 56 bytes between its saved frame pointer and the buffer — the top of the frame the
  burned body had used — stayed unzeroed (found by `threshold_ecdsa`'s stack probe: half of a
  secret survived there). No API change.
- **2026-10-08** — **NO CONSUMER-VISIBLE CHANGE (speed):** the dead-stack burn zeroes with
  volatile 32-byte vector stores instead of `std.crypto.secureZero` (a volatile byte memset,
  ~3 B/ns without libc): ~30× faster per KiB burned. Same size, same depth; the ReleaseFast stack
  probe still reads 0.
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
