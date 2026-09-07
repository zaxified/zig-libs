# bulletproofs — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — **Test-only: both proof decoders were only ever handed the
  empty slice.** `ipa.fuzzFromBytesAlloc` and `rangeproof.fuzzFromBytesAlloc`
  opened with `smith.bytes(&buf)` and then drew
  `smith.valueRangeAtMost(u16, 0, buf.len)`; `bytes` consumes
  `@min(buf.len, in.len)` octets, so the ranged draw found fewer than the
  eight it reads as a little-endian `u64` and returned the range MINIMUM.
  `len` was 0 for every input the ordinary test lane can carry, and both
  decoders refused it on their length guard (`bytes.len < 4`,
  `bytes.len < 32*7`) without reading an octet — **`Ristretto255.fromBytes`
  had never been called from either target, nor had the attacker-declared
  `rounds` field ever been read.** Both now draw with one `smith.slice(&buf)`
  over hand-written corpora built around that field. Measured 2026-09-07:
  **IPA 0 of 13 seeds non-empty and 0 proofs decoded before, 12 and 4 after,
  over 17 decoded rounds; range proof 0 of 12 and 0 before, 11 and 3 after,
  over 7 nested IPA rounds.** ⭐ `accepted > 0` would have been a weak guard
  in both: a `rounds = 0` inner-product proof is legal and carries no points
  at all, so the guards pin the rounds decoded — the attacker-declared work
  the decoder actually performed — beside the accepted count. The corpora
  include `rounds = 0xffffffff`, whose `expected_len` is 274 GB and which must
  be refused before any allocation.

- **2026-07-18** — Security audit: three findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on
  dalek-cryptography/bulletproofs (Rust) / libsecp256k1-zkp (design reference, not a
  test anchor).
- **2026-07-16** — New module: Bulletproofs — zero-knowledge range proofs over
  Ristretto255 (Bünz/Bootle/Boneh/Poelstra/Wuille/Maxwell, IEEE S&P 2018, eprint
  2017/1066) — prove a Pedersen-committed value.
