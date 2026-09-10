# psbt — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-10** — A1 fix campaign, 8 of 11 open findings closed (F1, F2, F3, F5, F8, F9,
  F10, F11; F4, F6, F7 remain open -- see the audit record's disposition for why).
  - ⛔⛔ **F1 (HIGH):** `finalize` never checked the spent output's amount at all -- a
    `PSBT_IN_WITNESS_UTXO` (which carries no link to the real previous transaction) could
    claim any `i64`, including negative and multi-quadrillion-satoshi values, and `extract`
    would still hand back a "network-ready" transaction. Fixed per the user's named decision
    (A1 `DECISIONS.md` §2): amount range `0 <= v <= MAX_MONEY` is now checked
    unconditionally (`error.AmountOutOfRange`), and a new opt-in
    `FinalizeOptions.require_non_witness_utxo` (default off, so legitimate P2WPKH-only
    signing flows are unaffected) rejects any input resolved from `WITNESS_UTXO` alone
    (`error.MissingNonWitnessUtxo`). `finalize`'s signature gained a third `FinalizeOptions`
    parameter; every in-module call site updated to `.{}`.
  - ⛔⛔ **F2 (HIGH):** an input already carrying `FINAL_SCRIPTSIG`/`FINAL_SCRIPTWITNESS` was
    treated as "already verified" and returned success without looking at the bytes at all --
    an attacker who supplied those fields directly (no signature anywhere) sailed through.
    `finalizeOneInput` now runs the SAME `verifyScript` gate a freshly-assembled candidate
    goes through before accepting an already-present final field; idempotent success is
    preserved only for an input that still genuinely verifies.
  - F3 (MED): `decodeWitnessUtxoValue`'s two bounds checks (value shorter than 8 bytes;
    script-length claim exceeding the buffer) had no test -- removing either panicked
    (index-out-of-bounds / integer overflow) on attacker bytes rather than returning a typed
    error. Two hostile tests added; no code change (the checks were already correct).
  - F5 (MED): `combine`'s "different transactions" rejection had only one test that differed
    in BOTH txid and map count at once, so either of its two guards alone could be deleted
    and stay 49/49 green. Two isolated tests added (same map count/different txid; same
    txid/different map count); no code change.
  - F8 (MED): `requireFixedValueLen`/`requireBip32ValueShape` (SIGHASH_TYPE/VERSION/
    BIP32_DERIVATION value-shape guards, wired into `parse` since before this module was
    audited) had no test -- removing either was silent OR panicked (an untested
    `PSBT_GLOBAL_VERSION` of the wrong length reads 4 bytes out of a 2-byte value). Three
    hostile tests added; no code change.
  - F9 (LOW): `decodeWitnessStack`'s count-vs-remaining-bytes guard's existing test could not
    tell "rejected before any per-item allocation" (the documented promise) from "rejected by
    the per-item decode running out of bytes anyway" -- both produce `error.Truncated`. A
    `FailingAllocator`-based test added that fails on the very first allocation attempt,
    making the difference observable; no code change.
  - F10 (LOW): BIP174's own vector 19 ("invalid value data due to its size being not the
    stated size") does not actually exercise a value-length check -- measured, it dies on
    the same rule as vector 18. Pinned as such (was previously excluded from the
    per-vector-error test) and cross-referenced to F8's tests, which are the real coverage
    for this class.
  - F11 (LOW): no throughput numbers were published anywhere in `SPEC.md`. Added, from the
    A1 audit's own `ReleaseFast` measurements: 0.78-1.10 ns/byte sparse, 10.8-34.5 ns/byte
    dense (~n^1.15 over a 2000x range), peak/wire allocation amplification up to 15.91x.
  - Open: **F4** (legacy `SIGHASH_SINGLE` bug reproduction passes finalization silently --
    correct behavior for a consensus-following *verifier*, but whether this "verify-on-
    finalize" layer should flag or deviate from it is a policy call, not a bug fix).
    **F6** (the module's one fuzz harness barely gets past its own `parse` call under the
    default corpus-less draw -- a real fix needs either an explicit seed corpus or a
    hand-built skeleton input, out of scope for this pass). **F7** (`findMatchingPartialSig`
    takes the first sighash-matching `PARTIAL_SIG` and gives up if it doesn't verify, even
    when a later record in the same map would -- a naive "try every candidate" fix is
    correct but turns a hostile `combine`-merged PSBT with many decoy `PARTIAL_SIG` records
    into an unbounded number of `verifyScript` calls per input, which is a new amplification
    concern the audit didn't specify a bound for).
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
