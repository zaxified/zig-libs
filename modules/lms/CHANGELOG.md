# lms — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-24** — **New (opt-in):** parallel key generation. `Parallel{ .io, .threads }` with `Tree.initParallel` / `initCachedParallel`, `SecretKey.initParallel` (lower trees built at signing time use it too) and `SigningKey.initInPlaceParallel`: the independent height-`c` subtrees are taken from an atomic counter by the caller and up to `threads - 1` `std.Io.Group.concurrent` tasks (0 = the CPU count); keys and signatures are byte-identical to the serial build, and each worker wipes its stack like `Tree.init`. Default behaviour unchanged. H15/W4 in ReleaseFast: 10.0 s serial, 3.1 s on 4 tasks, 2.7 s on 8.
- **2026-11-23** — **NEW + BREAKING:** RFC 9858's additional parameter sets (NIST SP 800-208): SHA-256/192, SHAKE256/256 and SHAKE256/192 — LM-OTS typecodes 5..16 and LMS 10..24 in `OtsParamSet` / `ParamSet` (with `hashFn()`, `nLen()` / `mLen()`, `matches()`), byte-exact against RFC 9858 Appendix A (Test Cases 1–3 regenerated and reproduced, Test Case 4 verified with its LM-OTS part reproduced). Values stay `[32]u8` (`n`); a 24-byte set uses the first 24 bytes, its SEED is `seed[0..24]`. One hash per LMS key: a mismatched pair is `UnsupportedOtsType` at parse and `InvalidLevels` at `SecretKey.init`. Breaking: `LmsPublicKey.toBytes` / `HssPublicKey.toBytes` and `encoded_len` are replaced by `encode(out: *[max_encoded_len]u8) []u8`, `encodedLen()`, `encodedLenFor(lms)` and `max_encoded_len` (the length now depends on `m`); `core.chainHash` / `leafHash` / `intrHash` / `messageHash` / `deriveX` / `deriveRandomizer` take a leading `HashFn`. The hash is chosen per family at compile time inside each call, so `hssVerify` keeps its 4 KiB stack bound; `init_burn` and `hss_burn` grow to 8 KiB (measured 4.7 / 5.9 KiB). ctgrind: new rows `shake` / `n24` (4 in-file each, the same chain-loop class), `hss` 6 → 4 (one code location instead of two inlined copies of that loop). The sign/verify fuzz harness covers one set per new hash.
- **2026-11-23** — **NO CONSUMER-VISIBLE CHANGE:** the hand-written dead-stack probe (`src/stackprobe_test.zig`) also applies the residue rule (`testkit.stackprobe.residueOf`) to its snapshots: a non-zero byte below a measured call's burn now fails it, whatever secret the needle model names or misses. Clean. Test only.
- **2026-11-21** — **NO CONSUMER-VISIBLE CHANGE:** test vectors from cisco/hash-sigs (H5/W1 and H5/W2 key and signature, `kat_vectors.zig` test data) and the oracle recipe `tools/hashsigs_oracle.sh` + `tools/emit.zig`; LM-OTS W1/W2 now have external anchors.
- **2026-11-21** — **New:** `SigningKey.initInPlace(dst, gpa, levels, seed, id, restore_at, persist)`: `SecretKey.init` straight into the handle, so no source copy of the key exists (`init` from a `*SecretKey` stays). Verification-only footprint measured and documented: a verify-only program links nothing from `sign.zig`, and `hssVerify` stays under 4 KiB of stack (new ReleaseFast probe).
- **2026-11-20** — **BREAKING (source):** `Tree.sign` and `Tree.signWithRandomizer` check their arguments and return `TreeSignError![]u8` (new `TreeSignError{ LeafOutOfRange, OutputTooSmall }`, the signature slice `out[0..lmsSignatureLength]`) instead of `void` with `std.debug.assert` preconditions (a panic in ReleaseSafe, undefined behaviour in ReleaseFast for `q >= 2^h` or a wrong `out` length). A longer `out` is now accepted. One checked form, as cisco/hash-sigs' signing functions return `false`. Callers add `try`. `LmsSecretKey` / HSS signing are unchanged.
- **2026-10-18** — Ported to Zig 0.17.0: comptime `arrRepeat` branch quota scaled with length.
- **2026-10-10** — tests: deterministic fuzz driver `LMS_FUZZ` (`lms-verify`, `lms-parse`, `lms-sign-verify`, `hss-sign-verify`, new `src/fuzz_test.zig`; the Smith harnesses in `root.zig` are unchanged): RFC 8554 Test Case 1 (HSS and its LMS-only form) with key, message and signature each intact or damaged -- only the intact triple verifies, wild triples never; parsers re-encode what they accept; signatures from `Tree.sign` (H5, W1/W2/W4/W8) and a 2-level HSS `SecretKey` verify, and a flipped octet, a truncation, another message or another root do not. No change in `src/` outside tests.
- **2026-10-10** — Constant time: new `src/ctgrind_harness.zig` (targets `lms`, `hss`, ReleaseFast): the seed is tainted through LMS (H5/W4) and two-level HSS key generation and signing. The 4 / 6 in-file contexts are the LM-OTS chain loop, whose count is a digit of the message hash over the randomizer C. C is derived from the seed but published in the signature, so this is a tainting artefact, not a leak. No code change.
- **2026-10-09** — `core.deriveX` and `core.deriveRandomizer` (public building blocks) now run under their own burn (`derive_burn`, 2 KiB; negligible next to the hash chains they start). `LmsSecretKey.init` / `LmsSecretKey.sign` / `SecretKey.init` are marked thin wrappers of already-burned `Tree` entry points for the dead-stack lint. No signature changed. Probe: `src/stackprobe2_test.zig`.
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
