# musig2 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-14** — Test-only: `kat_test.zig` gained a `testing.fuzz` harness on
  `partialSigVerify` (corrupted partial-signature bytes against a fixed valid
  BIP327 session) — `zig build check-fuzz` no longer names this module. No
  panic/OOB found; **neither breaking nor behavioural**.
- **2026-07-18** — Security audit: no findings. Byte-exact against BIP327's published
  test vectors.
- **2026-07-12** — New module: MuSig2 multi-signature (BIP327) producing BIP340
  signatures.
