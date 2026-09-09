# taproot — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-09** — **NO CONSUMER-VISIBLE CHANGE:** `src/ctgrind_harness.zig` is added (A1 audit finding R2; the tier-A ctgrind queue, 28 modules). Measured ReleaseFast under valgrind, in-file contexts: **secret 10**. Every target has an untainted control row and a no-`-fvalgrind` trap row, both 0, so the numbers are real taint propagation rather than a silent no-op. ⭐ **This module has ZERO branches of its own on a secret.** `d.add(t).toBytes()` — the line `SPEC.md:85-93`'s constant-time claim is actually about — contributed nothing, and `tweakPublicKey` is public-data-only by its own doc comment. All ten contexts belong to the delegated `bip340.KeyPair.fromSecretKey` and `k256`. One of them (`bip340/root.zig:165`) is the disputed even-Y `if`/`else`; the experimental control that makes it disputable was taken here — a second secret whose point has even Y drops the count 12→11. See `bip340`'s entry and `CTGRIND-OPEN-QUESTIONS.md`.

- **2026-07-18** — Security audit: no findings. Byte-exact against BIP341's published
  test vectors.
- **2026-07-12** — New module: BIP341 Taproot key-path output-key tweaking.
