# bip340 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
