# geoindex — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-06** — Security audit: no findings. Modeled on Flatbush (mourner/flatbush,
  design reference) (design reference, not a test anchor).
- **2026-07-24** — New module: Static spatial index for bbox + nearest-neighbour queries
  over a large fixed geo-point set — DoS-bounded, frozen zero-copy.
