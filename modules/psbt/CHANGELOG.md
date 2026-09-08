# psbt — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-09** — Licensing correction, no code change. `NOTICE` named BSD-2-Clause for
  the BIP174 worked-example data and reproduced none of it: no clauses, no disclaimer, no
  copyright line. All three are now present. Recorded rather than papered over: BIP174
  publishes no copyright line of its own and `bitcoin/bips` carries no `LICENSE` file
  (HTTP 404, verified 2026-09-09), so the rightsholder is named as the BIP's author and
  the absence is stated instead of an attribution being invented. The Bitcoin Core
  section's MIT text was likewise cited by copyright line only; MIT asks for the
  permission notice too, and it is now reproduced.
- **2026-09-07** — ⛔ `fuzzParse` never got past its own `parse` call. Every choice its
  generator made came from `smith` directly — the input/output counts, the record counts, the
  keytypes, the keydata and value lengths, `finalize_them`, the witness-stack bytes — and all
  of them collapse outside `--fuzz`, because a ranged `Smith` draw reads eight octets as a
  little-endian `u64` and returns the range MINIMUM when fewer remain, and `bool` is a 1-bit
  range. So the harness built exactly ONE PSBT for its whole existence: magic, an `UNSIGNED_TX`
  over a **0-input, 0-output** transaction, and a map terminator. ⛔⛔ And that document does
  not parse — a legacy-serialized transaction with zero inputs reads back as a BIP144 witness
  marker, so `parse` returned `error.InvalidWitnessFlag` and the `catch return` on the next
  line took the rest of the harness with it: `decodeWitnessStack`, `finalize`, `extract`, and
  all four invariant assertions (`FinalizeResultCountMismatch`, `ExtractChangedInputCount`,
  `ExtractChangedOutputCount`, `WitnessCountMismatch`) had never executed once. That includes
  the `finalize`/`extract` coverage the W2 A3 (F4) note in this file says was added — the
  obstacle was not the generator's keytype list, it was the first call. The generator now
  reads its choices from a `testkit.fuzz.Cursor` over one `smith.slice` draw, with an
  eleven-script corpus. Measured: **1 distinct PSBT, 0 input maps, 0 output maps, 0 records
  parsed and 0 finalizations before; 10 distinct PSBTs, 17 input maps, 13 output maps, 3
  records parsed and 2 finalizations after** — and the corpus reaches
  `InvalidPubkeyLength`, `UnexpectedKeyData` and `DuplicateKey`, three per-keytype validators
  that had no fuzz coverage at all.

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
