# psbt — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-06** — **`finalize` builds the per-transaction sighash cache once, before its loop
  over the inputs, and hands it to every input's `TxContext`.** Each input built its own
  context with `precomputed = null`, so `bitcoinscript.verifyScript` recomputed BIP143's three
  and BIP341's five commitment hashes for every CHECKSIG — quadratic in the number of inputs,
  which is the consensus DoS those BIPs exist to remove. Measured (A1 P1, 2026-09-06): a 614 kB
  transaction of 8 192 inputs cost 25.9 s of sighashing on this path where the cache costs
  10 ms; `withPrecomputed`, the seam the 2026-08-11 audit added, had no production caller at
  all. The BIP341 half is built only when every spent output resolved (the placeholder for an
  unresolved input must not be baked into a cache); otherwise the BIP143 half alone, and
  taproot inputs — refused without all outputs anyway — take the uncached, byte-exact path.
  `FinalizeSetupError` gains `bitcointx.precomputed.PrecomputedError`. The regtest P2WPKH and
  P2WSH KAT tests now pin the commitment-hash count at 8 per `finalize` via
  `bitcointx.instrument` (it was 3 per signature).

- **2026-08-06** — Security audit: six findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Byte-exact against
  BIP174's published test vectors.
- **2026-07-21** — New module: BIP174 Partially Signed Bitcoin Transaction (PSBT) v0.
