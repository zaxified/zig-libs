# bolt8 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-21** — `noise`'s cipher calls gained `error.BufferTooSmall`; this module maps
  it to the `BufferWrongSize` it already publishes, so its own error sets are unchanged. It
  validates every buffer length itself before calling, so the mapped error is not reachable
  through this API — the mapping exists so that stays true by construction rather than by
  an `unreachable`.

- **2026-07-18** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Verified: `kat_test.zig`
  verifies BOLT#8 Appendix A byte-exact (act1→act2→ act3, five crypto-level negative
  vectors, transport round-trip).
- **2026-07-12** — New module: Lightning BOLT#8 encrypted transport
  (`Noise_XK_secp256k1_ChaChaPoly_SHA256`).
