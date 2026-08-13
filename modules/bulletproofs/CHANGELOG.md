# bulletproofs — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-18** — Security audit: three findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on
  dalek-cryptography/bulletproofs (Rust) / libsecp256k1-zkp (design reference, not a
  test anchor).
- **2026-07-16** — New module: Bulletproofs — zero-knowledge range proofs over
  Ristretto255 (Bünz/Bootle/Boneh/Poelstra/Wuille/Maxwell, IEEE S&P 2018, eprint
  2017/1066) — prove a Pedersen-committed value.
