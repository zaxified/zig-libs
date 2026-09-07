# bip340 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — Fuzz reach: `fuzzVerify` never corrupted a signature. Its flip loop
  opened `smith.valueRangeAtMost(u8, 0, 6)` as the harness's FIRST draw; a `Smith` ranged
  draw reads eight octets as a little-endian `u64` and returns the range MINIMUM when
  fewer remain, and the target had no corpus, so outside `--fuzz` the one input it ever
  ran was empty and the flip count was **zero every time**. Every ordinary `zig build
  test` verified the pristine vector-0 signature — which the KAT tests above already
  assert — and no corrupted octet ever reached the `r < p` / `s < n` range checks or the
  curve-equation check the harness's own comment says the budget is spent near. Measured
  2026-09-07: 1 round, 0 octets flipped, 0 refusals from `Signature.fromBytes`. The flip
  loop is gone: a signature is 64 octets off the wire, so it is drawn with one
  `smith.slice`, and 12 written seeds carry the near-misses — vector 1's signature over
  the wrong message, r = p and r = p−1, s = n and s = n−1, r = s = 0, all-ones, two
  single-octet corruptions of the real signature, and a 63-octet short read.
  ⚠ A corpus guard pins **refusals**, not acceptances: `Signature.fromBytes` on 64 zero
  octets SUCCEEDS (0 is a canonical `Fe` and a canonical `Scalar`), so an "accepted > 0"
  guard would have read 100% over an empty corpus. Pinned: 11 non-empty, 3 refused,
  9 accepted, 1 verification.

- **2026-08-14** — Test-only: `kat_test.zig` gained a `testing.fuzz` harness on
  `verify` (corrupted signature bytes against a fixed valid pubkey/message) —
  `zig build check-fuzz` no longer names this module. No panic/OOB found;
  **neither breaking nor behavioural**.
- **2026-08-13** — `verifyBatch`'s randomizers `a_2..a_u` are now drawn from
  `io.randomSecure` instead of `Secp256k1.scalar.Scalar.random`, which
  draws from `io.random`. **Not breaking:** the signature is unchanged and
  so is the accepted set for any batch that verifies.

  This one is soundness, not secrecy, and it is the reason the module does
  not simply reuse the `entropy` module: an attacker who can predict the
  `a_i` can pick a batch of individually-invalid signatures whose errors
  cancel in the linear combination, so `io.random`'s documented degrade
  (`std/Io.zig:2462` — a pid-and-clock seed) is a forgery oracle here.

  On an entropy failure the batch is reported **unverified** (`false`)
  rather than aborting the process as `entropy.fill` would. `false` is
  already this function's answer on every failure path, nothing
  irreversible is minted, and single-signature `verify` needs no
  randomness at all — so a caller who gets `false` can re-check the items
  one at a time and lose only the batching speedup. That is the test
  `entropy.fill`'s own doc sets for when not to use it.

- **2026-07-28** — New `taggedHashRuntime`/`taggedHasherRuntime` — the BIP-340 tagged hash
  with a **runtime** tag assembled from parts, for callers whose tag is
  not comptime-known (BOLT#12's nonce leaf, BIP-341 leaf hashes). The
  comptime `taggedHash`/`taggedHasher` remain the fast path. New
  `xonlyBytesOf` (33-byte compressed → 32-byte x-only), also moved out of
  the sibling `lninvoice` module.
- **2026-07-18** — Security audit: no findings. Byte-exact against BIP340's published
  test vectors.
