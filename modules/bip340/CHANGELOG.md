# bip340 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- New `taggedHashRuntime`/`taggedHasherRuntime` — the BIP-340 tagged hash
  with a **runtime** tag assembled from parts, for callers whose tag is
  not comptime-known (BOLT#12's nonce leaf, BIP-341 leaf hashes). The
  comptime `taggedHash`/`taggedHasher` remain the fast path. New
  `xonlyBytesOf` (33-byte compressed → 32-byte x-only), also moved out of
  the sibling `lninvoice` module.
