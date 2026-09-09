# dkg — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-09** — **NO CONSUMER-VISIBLE CHANGE:** `src/ctgrind_harness.zig` is added (A1 audit finding R2; the tier-A ctgrind queue, 28 modules). Measured ReleaseFast under valgrind, in-file contexts: **coeffs 98 / combine 5**. Every target has an untainted control row and a no-`-fvalgrind` trap row, both 0, so the numbers are real taint propagation rather than a silent no-op. No constant-time claim exists in `SPEC.md` or `README.md`; none was added — this is evidence looking for a sentence to attach to. ⭐ `combineKeyShare`'s own summation over the accepted shares measures **zero**, which is the concrete answer to the question this was built for. ⚠⚠ **45% of `coeffs`' 98 contexts are an over-taint artifact of simulating every party in one process**: `evalCommitmentAt` and `deriveGroupPublicKey` re-decode commitments that this process built moments earlier from tainted coefficients, whereas in the real protocol those bytes arrive over the wire at a party that never held the secret. That limit applies to every multi-party harness in this campaign and none of their numbers were adjusted for it. ⭐ The author also self-corrected before reporting: a first version tainted a whole `[3]?Scalar` and three of eight contexts turned out to be the OPTIONAL'S PRESENCE DISCRIMINANT, not the payload; narrowing the taint took it 8→5. Taint the payload, not the wrapper.

- **2026-09-07** — Test-only, no production change: both broadcast fuzz targets replayed a
  single input. `fuzzPedersenBroadcastDecode` and `fuzzFeldmanBroadcastDecode` each opened
  `smith.bytes(&buf)` and then drew `smith.valueRangeAtMost(u16, 0, 512)`; a ranged `Smith`
  draw reads eight octets as a little-endian `u64` and returns the range MINIMUM when fewer
  than eight remain, and `bytes` had already eaten them — so `len` was **0** every round
  the ordinary lane ran, and `fromBytesAlloc` returned `InvalidEncoding` off its
  `bytes.len < 8` check with the broadcast sitting unread in `buf`. Neither had a corpus
  either, so outside `--fuzz` the one input was the zero-length slice. Both now draw with
  one `smith.slice(&buf)`. The corpus is built from the module's own `toBytesAlloc` (a
  `secp256k1` point in the form `Element.fromBytes` accepts is not reachable from arbitrary
  bytes) and includes the attack this decoder's own comment is about: a frame whose `t`
  claims `2^32-1` commitments over 107 octets, which must be refused before the `alloc`.
  Measured by the new `corpus:` guard: 8 non-empty seeds of 9, 3 accepted, **11 commitments
  decoded off the wire**. The commitment count is pinned rather than `accepted > 0` because
  the header-only `t = 0` frame is accepted while decoding no point at all.

- **2026-07-18** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this).
- **2026-07-17** — New module: Secure Distributed Key Generation (GJKR) for
  `threshold_ecdsa` over secp256k1.
