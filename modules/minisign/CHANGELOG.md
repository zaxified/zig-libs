# minisign — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- New module: sign/verify in the minisign file format over Ed25519, both
  legacy (`Ed`) and prehashed-BLAKE2b (`ED`), including scrypt-encrypted
  secret keys and the trusted-comment global signature. Byte-exact
  against artifacts produced by the reference `minisign` binary.
