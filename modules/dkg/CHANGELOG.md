# dkg — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
