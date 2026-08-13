# nftables — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-11** — Security audit: three findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Byte-exact JSON
  goldens for three rule shapes, plus a live check that the generated ruleset is
  accepted by a real `nft -c -j -f -`.
- **2026-07-07** — New module: Typed firewall-ruleset builder → libnftables JSON for
  `nft -j -f -` (families/chains/rules/sets, match + verdict statements).
