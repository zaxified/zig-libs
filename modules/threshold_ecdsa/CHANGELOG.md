# threshold_ecdsa — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-10** — **Fixed:** `MtaProofWc.fromBytesAlloc` accepted trailing octets after the final point
  (`bytes.len < offset + Ne`), so one proof had many encodings; it now requires the exact length, as
  `PdlProof` does. Regression test in the round-trip test.
- **2026-10-10** — **NO CONSUMER-VISIBLE CHANGE:** deterministic fuzz driver (`TECDSA_FUZZ`, `src/fuzz_test.zig`) over every wire decoder: Feldman commitments, public keys, aux params, key share, `Element`, the four EC proofs (honest proof accepted, damaged one refused), range / MtA / MtAwc / PDL / Πmod / Πprm / Πfac proofs, `Presignature`, and `combine` (shares nobody signed never combine). Harness bodies are generic over their choice source, so existing `--fuzz` corpora replay unchanged. 200,000 runs per harness clean in ReleaseSafe; the Πmod/Πprm harnesses now hold a full 67 KB frame (the old 4096-octet buffer could never reach `accepted`). Note: `MtaProofWc.fromBytesAlloc` ignores octets after the final point (only a lower bound is checked), unlike `PdlProof`.

- **2026-10-09** — **BREAKING:** dead-stack rule (CONVENTIONS §2.1.1). `messagePublicKey(seed: *const [32]u8)` takes the Ed25519 message-signing seed by pointer (was by value; it was already burned). `aux_proofs.deriveModChallenge` / `derivePrmChallengeBits` carry `secret-api-ok` markers: their `seed` is the public Fiat-Shamir digest, not a secret. Call sites in `aux_info`, `presign`, `tsslib_interop`, the old stack probe and `dkg` migrated.

- **2026-10-08** — **NO CONSUMER-VISIBLE CHANGE:** the dead-stack probe (`src/stackprobe_test.zig`) moved to the direct-region
  engine (p256's, 2026-10-08): the call runs under a `PAD`-deep shim, the region is painted and read
  through a pointer, callee-saved registers are scrubbed first. The old "claim an uninitialised
  buffer" engine could not see the top ~250–450 B of the call — the caller's and the wrappers'
  frames. 0 residues, caller's frame included.
- **2026-10-08** — **BREAKING + FIX (secrets on the dead stack, HIGH):** measured with the new
  ReleaseFast stack probe (`src/stackprobe_test.zig`), every entry point that touches a secret
  left it in dead stack frames although each named buffer was wiped: the presigning rounds
  (nonces `k`, `γ`, `σ`, `δ`, `ℓ`, `r_k`; round 3 the whole Paillier secret key, 21-23 copies per
  party), `finish`/`signShare` (`k`, `σ`, message seed), the MtA (`α`, `β`, `β'`, `r_a`, `r_b`, the
  Paillier key), the ZK and Sigma provers (witnesses), key generation and the codecs (`x_i`, the
  Paillier factors, `λ`, `μ`, the CRT block, the ring-Pedersen trapdoor) — 141 copies on the
  signing path and 354 over 28 building blocks before the fix, 0 after (61 calls, three tests).
  Fix as in `bip32`: each public entry point runs its body one frame down and burns the stack
  at that depth (`burn.zig`, sized from the measured depth), and secrets no longer cross an API
  by value — secret parameters are pointers, secret results go to an out-parameter:
  `Party.init(…, share: *const KeyShare, …, out: *Party)`, `Party.finish(inbox, out)`,
  `Presignature.fromBytesAlloc(…, out)`, `PresignaturePool.take(…, out) !bool`,
  `mta.*` (`a`/`b`/`alice_sk` by pointer; `mtaAliceInitChecked`, `mtaBobResponse*`,
  `mtaAliceFinalize*`, `decryptWithRandomness` write `out`), `zkproofs.prove*` and
  `ecproofs.prove*`/`pedersenCommit` (scalars and Paillier randomness by pointer),
  `splitSecretKey`/`keygenTrustedDealer` (`secret_key` by pointer), `reconstructSecret(…, out)`,
  `generatePaillierBlum`/`paillierBlumFromPrimes(…, out)`, `auxLogInverse(…, x: *const, out)`,
  `generateAuxParamsWithTrapdoor`/`auxParamsWithTrapdoorFromSafePrimes(…, out)`,
  `KeyShare.fromBytesAlloc(…, out)`, `aux_proofs` provers (`trapdoor` by pointer),
  `aux_info.LocalAux.generate(…, out)`, `LocalAux.fromParts` (moves: wipes its sources) and
  `assembleKeyShare(…, secret_share: *const, …, out)`. Callers: `dkg` (migrated).
  The burn's buffer is 16-aligned: 32-aligned, the frame realigned and up to 56 bytes between the
  saved frame pointer and the buffer stayed unzeroed — half of `α` survived there.
- **2026-10-04** — **BREAKING (API): review 2026-10-03 F5, F11, F13, F15.** The §4.3
  opening gains an echo round: `openAbort` → `echoOpenings(openings)` (returns the round-9 echo)
  → `identify(echoes)`; an opening shown two ways names its signer (`equivocation`).
  `Presignature.toBytesAlloc` now takes `*Presignature` and consumes it (marked used, `k`/`σ`
  wiped). New `Party.abandon` (wipe a pending opening now). `aux_info.Verified` can no longer be
  written by hand (its seal is a private address; `assembleKeyShare` refuses another). New
  `aux_info.reusesMaterial` (used by `dkg.EcdsaRefresh`).
- **2026-10-03** — Mutation audit of the 2026-10-03 additions (two rounds, schemata): tests
  only — Bob's non-unit MtA proof, lies in the last signer's opening section, opening-parser
  prefixes, wrong-kind signed messages, the session id's key-table hash, aux_info refusals.
  SPEC § Audit 2026-10-03.
- **2026-10-03** — **Review of the 2026-10-03 additions (BREAKING: fault set, session id).**
  F1/F2: see the §4.3 entry below. `Party.collect` and `PresignaturePublic.combine` check the
  signature first and drop what proves nothing about its claimed sender (garbage, forged headers,
  bad signatures, replays, other rounds, sessions or recipients); an identical copy is skipped,
  a second signed version is `duplicate_message`. Fault `bad_signature` is gone — such a sender
  ends up `missing_message`. `Presignature.fromBytesAlloc` checks the relations of a finished
  session (`r = R.x`, `ΣR̄ = G`, `ΣS = X`, `k·R = R̄_i`, `σ·R = S_i`). The presigning session id
  (`session/v2`) also hashes the public-key table. New `root.decodeMessageKey` refuses
  small-order message keys (codecs, `Party.init`); message signatures are checked with
  `verifyStrict`.
- **2026-10-03** — Key refresh: `dkg.EcdsaRefresh` gives every party a new share of the same
  key with new Paillier, ring-Pedersen and message keys (see `dkg`'s changelog).
- **2026-10-03** — Presignatures can outlive their process: `Presignature.toBytesAlloc`/
  `fromBytesAlloc` (secret bytes, a used presignature refused), `PresignatureStore` (whose
  `take` hands a record out at most once), `PresignaturePool` (`put` wipes the in-memory
  original, `take` restores once) and `MemoryPresignatureStore`.
- **2026-10-03** — **Identifiable abort for types 5 and 7 (GG20 §4.3).** A `r_bar_sum` or
  `s_sum` abort keeps the session's nonce material; `Party.openAbort` broadcasts the
  signer's opening and `Party.identify` checks everyone's and names the culprit. New:
  `ecproofs.DleqProof` (Chaum–Pedersen), `mta.decryptWithRandomness` (a decryption with its
  Paillier randomness, constant-time in λ). Tests: the δ and σ cheaters are named, and so is
  a signer lying in its opening (wrong γ, a round-2 message its sender never signed, a
  decryption lifted by `N`). A type-7 opening never contains a signer's Bob masks `ν'`
  (review 2026-10-03 F1: the first draft of this entry opened them, and with `k_j` and `μ'`
  public that revealed every honest key share; never released).
- **2026-10-03** — **BREAKING (wire v2, codecs, API): signed presigning messages, the
  equivocator is named.** `PartyPublicKeys.message_key` / `KeyShare.message_seed`
  (Ed25519); `keygenTrustedDealer` takes `message_seeds`, `aux_info.LocalAux` generates
  one and `Announcement` carries its public key (`findDuplicate` refuses a shared one).
  Every `presign` message is signed (`bad_signature`), and the running broadcast
  transcript is replaced by signed per-signer attestations: `equivocation` now names
  the signer who signed two versions of a broadcast, or the one who misquoted it.
  `PresignaturePublic` holds the Phase-6 attestations and message keys (`combine`
  checks shares the same way).
- **2026-10-03** — Constant-time key setup, the last two pieces: the ring-Pedersen
  derivation (`Ñ`, `ord`, `λ`) runs on montint limbs instead of `std.math.big.int`, and
  the prime searches' trial-division sieve multiplies by reciprocals instead of
  dividing (`sieveRejects`) and tests candidates from bytes (`isProbablePrimeBE`). New
  `auxParamsWithTrapdoorFromSafePrimes` (import a ring-Pedersen key from its safe
  primes). ctgrind: new target `auxgen`, `prime` now measures the search's path.
- **2026-10-03** — **BREAKING (wire + API): relation-audit and review LOWs closed.**
  Range/MtA/MtAwc proofs are bound to a caller `context` (new parameter on every
  prove/verify and on `mta.mtaAliceFinalizeChecked`; transcript domains `v3`). Bob's
  MtA proofs must have unit `c_B`/`s`. `mta.mtaAliceFinalizeVerified` (used by
  `presign` and the checked finalize) lifts the plaintext to its centered
  representative, so a negative `β'` cannot wrap and leak a bit through an abort.
  Πprm/Πmod run 128 rounds (was 80), Πmod refuses non-unit challenges and non-canonical
  roots, and their codecs accept exactly one encoding. `aux_info.assembleKeyShare`
  takes an `AnnouncementSet.verified()` instead of a plain slice; `verifyAnnouncement`
  requires a 2048-bit `Ñ`.
- **2026-10-03** — **NO CONSUMER-VISIBLE CHANGE:** the range proof's unit check (entry
  below) is now one constant-time inversion of `c_A·s mod N` (montint divsteps; `u` is
  a unit by equation 2 once `c_A` and `s` are) instead of three big-int gcds. The
  inputs are public, but the single-process ctgrind harness taints ciphertexts derived
  from `k_i`, and the variable-time gcd hit the 1000-context cap on the `nonce` row;
  now it is +1 (the verdict), pinned at `<=479`.

- **2026-10-03** — **⛔ Security fix: the range proof accepted non-unit `u`/`s`.** The
  verifier uses the inversion-free form `u·c^e == Γ^s1·s^N (mod N²)`; the paper's
  `u = Γ^s1·s^N·c^-e` presumes units, the rewrite dropped that. Alice, who knows
  `N = P·Q`, sends `u ≡ 0 (mod P²)` and `s ≡ 0 (mod P)` (multiply an honest `u` by
  `(P²)^N` and `s` by `P²`): equation 2 reads `0 = 0` mod `P²`, so only the `Q²` side
  still binds the plaintext. She encrypts `a = k·Q ≈ 2^1300` (zero mod `Q`, huge mod
  `P`), proves "plaintext 0", and Bob's MtA reply `a·b + β'` (no wrap, `β' < a`) gives
  her `b = ⌊Dec(c_B)/a⌋` — his `γ_i` or `w_i` in one session. `verifyAliceRange` and
  the PDL proof built on it now require `gcd(c_A, N) = gcd(u, N) = gcd(s, N) = 1`.
  Regression test runs the attack end to end (including recovering `b`); with the check
  removed it fails. Found by the 2026-10-03 relation audit.

- **2026-10-03** — **⛔ Security fix: Πprm proved the wrong direction.**
  Aux generation drew `h1` and set `h2 = h1^λ`, and Πprm proved that, i.e.
  `h2 ∈ ⟨h1⟩`. The commitment `h1^x·h2^ρ` hides `x` only if `h1 ∈ ⟨h2⟩`;
  a dishonest tuple owner could pick `h2 = h1^M` (smooth `M`, Blum primes
  pass Πmod) and read `x mod M` out of every commitment the other parties
  made under its tuple — their MtA witnesses, key shares included. Now
  `h2 = r²`, `h1 = h2^λ`, and Πprm proves `h1 = h2^λ` (CGGMP21 Fig.17's
  `s = t^λ`). **Breaking:** `AuxTrapdoor.lambda` is `log_{h2} h1`; Πprm
  proofs made before do not verify. Wire format unchanged. Also: `Pimod`
  verification refuses `Ñ` below 5 bits — `Ñ = 3` looped forever in the
  Miller-Rabin witness draw (both found by an independent review).

- **2026-10-03** — **Πprm's prover is constant-time in `p̃`, `q̃`, `λ`;
  Miller-Rabin lives in `montint`.** `φ` is a limb product, the responses
  `a_i + e_i·λ mod φ` one masked subtraction and the nonce draw's `a_i < φ`
  a borrow (was big-int `divFloor` and a byte compare); new ctgrind target
  `piprm` (3). `isProbablePrime` is now a wrapper over
  `montint.DynModint.isProbablePrime`, the recipe this module introduced
  (`prime` 4 → 3). Proofs and their wire format unchanged.

- **2026-10-03** — **Πmod's exponent `d = Ñ⁻¹ mod φ` is constant-time.**
  `φ = (p−1)(q−1)` is a limb product of the secret primes (`p − 1` = `p` with
  bit 0 cleared) and `d` comes from `montint`'s `inverseOfModulus` (an even
  modulus); the big-int copies of `p`, `q`, `φ` and the extended-Euclid
  `modInverse` are gone. ctgrind `pimod` 540 → 4 (two length verdicts, two
  blends on the published `a_i`/`b_i`). Proofs unchanged.

- **2026-10-03** — **Πmod's rounds and Miller-Rabin are constant-time in the
  secret factor.** The Πmod prover's Legendre symbols (Euler's criterion),
  4th roots (`v^((r+1)/4)`, the QR one of `±s` by a CT select), CRT and
  `q⁻¹ mod p` (Fermat) run on `montint.DynModint` modulo the secret primes
  (was big-int Jacobi/division and `std.crypto.ff` pow modulo the factor);
  `(a_i, b_i)` are picked with bit operations. `root.isProbablePrime(m,
  n_bits, random)` — now taking the candidate's known length — runs its ladder
  modulo the secret candidate with no length scan, no witness rejection and
  one combined round verdict. New ctgrind targets `pimod` (rounds: 0;
  `d = Ñ⁻¹ mod φ` by extended Euclid and the big-int setup remain, backlog)
  and `prime` (4, all verdicts). Proofs and keys unchanged.

- **2026-10-02** — **Πprm/Πmod over `Ñ` can be bound to the prover's
  context.** `Piprm.proveBound`/`verifyBound`, `Pimod.proveBound`/
  `verifyBound` and `proveWellFormedBound`/`verifyWellFormedBound` put the
  caller's `session id || index` into the Fiat-Shamir seed under domains of
  their own (`pi-prm-bound`/`pi-mod-bound`), so a bound proof never passes as
  an unbound one or under another context. `aux_info`'s announcement uses
  them: a party that copies another's `Ñ` with its proofs now fails
  `verifyAnnouncement` (`InvalidAuxParams`) instead of being caught only by
  `findDuplicate`. The unbound functions are unchanged. ⚠ Announcement wire
  compatibility: an announcement from an older build no longer verifies.

- **2026-10-02** — **Prover-side products and conversions of secrets are off
  `std.crypto.ff`.** `zkproofs`' private montint slot copy is replaced by
  `montint.DynModint`; new helpers `pedersenCt`/`mulCt`/`rebase`/
  `feFromSecretBytes` carry the ring-Pedersen commitments, the
  `c_A^α·Enc(γ)`/`r^e·β` products and every secret moved between moduli
  (range/MtA/Πfac provers, `mta`'s `b`, `β'` and encryption randomness), where
  `ff`'s `mul` (extra-reduction bit) and `fromBytes`/`toBytes` branched on the
  value. Together with paillier's move (decrypt's L-function and Garner,
  `addCiphertexts`) ctgrind falls `share` 394 → 244, `nonce` 669 → 478,
  `betaprime` 462 → 285, `fac` 17 → 5 in-file. Proof bytes unchanged.

- **2026-10-02** — **ADDITIVE:** the Paillier half of dealer-free keygen.
  - `fac_proof` — Πfac (CGGMP21 Fig.28, "no small factor"), one proof per verifier under its
    ring-Pedersen tuple; non-negative variant, `ℓ = 256`, `ε = 512`. A modulus `3·X` passes all
    three equations and is refused by the range check alone (test).
  - `aux_proofs.Pimod.provePaillier`/`verifyPaillier` — Πmod over a Paillier `N`, bound to the
    caller's `session id || index` in a domain of its own; the aux-bound Πmod is unchanged.
  - `root.generatePaillierBlum`, `paillierBlumFromPrimes`, `PaillierBlumKey`,
    `paillierModulusAsAux` — Paillier-Blum keys that keep their factors for the proofs.
  - `aux_info` — `LocalAux`, `Announcement` (codec), `verifyAnnouncement`, `verifyFactors`,
    `findDuplicate`, `assembleKeyShare`. The protocol run is `dkg.EcdsaKeygen`.
  - `zkproofs.Transcript.appendContext`, `zkproofs.powSecret`.
  - ⛔ **Fixed: secret exponents through `std.crypto.ff`'s pow.** ctgrind (new target `fac`)
    found its table select compiled to a branch in ReleaseFast; Πprm's commitments, Πmod's
    `y^d` and `generateAuxParams`' `h1^λ` (all pre-existing) now go through `powSecret`
    (montint) like Πfac. Πmod's 4th roots and the prime searches stay variable-time (backlog).

- **2026-10-02** — **ADDITIVE:** `presign` — GG20 signing as one state machine per signer.
  `presign.Party.init(allocator, share, signers, sid)` then six `advance(inbox, random)` calls
  (byte messages in, `Outbox` of broadcast/p2p byte messages out) and `finish(inbox)` give a
  `Presignature`; `Presignature.signShare(message)` is the one online round (used once, wipes
  `k_i`/`σ_i`), `PresignaturePublic.combine(message, shares, &abort)` checks every share with
  `s_j·R == m·R̄_j + r·S_j`, sums, normalises to low-S and verifies under the group key.
  `Message` takes raw bytes or a prehashed digest. Every check of GG20 §3.2 is made: the Phase 3
  Pedersen proof of `(σ_i, ℓ_i)`, the Phase 5 proof that `R̄_i = k_i·R` matches `Enc(k_i)`
  (`zkproofs.PdlProof`, new: the A.1 range proof plus `alpha·R`) and `Σ R̄_j = G`, the Phase 6
  proof that `S_i` and `T_i` share `σ_i` and `Σ S_j = X`. A failed check returns
  `error.ProtocolAbort` with `Party.abort = { culprit, fault }`; the culprit is named for every
  proof failure and every malformed, misaddressed, duplicate or missing message, and in combine
  for a wrong share — `null` only for the paper's types 5 and 7 (`r_bar_sum`, `s_sum`) and for
  `equivocation`: every message after round 1 carries the sender's running hash of all broadcasts,
  so a signer who shows different broadcasts to different peers stops the session before honest
  signers can blame each other. Every message and every new proof is bound to a session id derived
  from the caller's `sid`, the group key, `t` and the signing set. New `ecproofs`
  (`PedersenProof`, `StProof`, `SchnorrProof`, the NUMS generator `pedersenH`).
- **2026-10-02** — **BREAKING:** `root.PartyPublicKeys` gains `verifying_share` (`X_j`, which every
  signer needs for the MtAwc check against `W_j = λ_j·X_j`); `PublicKeys`' wire encoding appends it
  to every entry, and `KeyShare.fromBytesAlloc` refuses a share whose own entry carries a different
  `X_i`. `keygenTrustedDealer` fills it. Old encodings no longer decode. Both decoders now refuse
  trailing bytes, and every length-prefixed reader bounds lengths by subtraction (an `offset + len`
  could wrap on 32-bit targets). The range-proof verifiers cap the length of `s1`/`t1` (work bound).
- **2026-10-02** — **BREAKING:** `signing.signWithShares` is now a driver over `presign.Party` (one
  per share, messages routed by a loop) instead of its own implementation of the protocol — which
  made neither GG20 Phase 5/6 check. Same signature; `SignError` is now `OutOfMemory |
  InvalidParameters | SigningAborted`. `SignOptions` is `{ .threads }` (was `{ .pair_threads,
  .pair_scratch_bytes }`): per-party work per round on threads, per-party CSPRNGs seeded up front,
  worker allocations from per-party arenas over `page_allocator`. The round-message types
  `GammaCommitment`, `SchnorrProof`, `GammaReveal`, `DeltaShare`, `SigShare` and the
  `gamma_*_domain` constants are removed (the state machine has its own, session-bound ones).
  No in-repo consumer.
- **2026-10-02** — **NO CONSUMER-VISIBLE CHANGE:** the ctgrind harness drives `presign.Party`
  state machines with one wrapped PRNG per party (`signWithShares` now seeds per-party CSPRNGs, so
  a wrapper around its `random` would taint only the seeds), and `nonce` taints every 48-byte
  secret-scalar draw (16, was 6). `ctgrind-expected.tsv`: share `<=394`, nonce `<=669`, betaprime
  `<=462` in-file, controls and traps 0; every new context classified (verifier-side over-taint,
  `paillier.decrypt`, std `rejectIdentity`, the draws' own reduction) — none on a prover-side branch.
  New oracle: `tools/tsslib` (tss-lib v3.0.0, both directions) → `src/tsslib_vectors.zig`,
  tested by `src/tsslib_interop.zig`.
- **2026-09-30** — **BREAKING:** `signing.identifyAbortCulprit` is removed. It was a public
  `noreturn` function whose only behaviour was `@panic` (GG20 identifiable abort is not
  implemented), so a caller compiled and then crashed at run time. Identifiable abort stays a
  backlog item (SPEC.md); `signWithShares` is unchanged — it never returns an invalid signature
  and reports `error.SigningAborted` without naming a culprit. No in-repo consumer.
- **2026-09-15** — **NO CONSUMER-VISIBLE CHANGE:** A1 R2. `zkproofs.mulAddBytes` (private,
  the `e*x + addend` Sigma-protocol response arithmetic behind s1/s2/t1/t2) had a
  carry-propagation tail that exited as soon as `carry != 0` went false — a real branch on
  secret-derived partial sums (`cmp $0x100`/`jb`), contradicting its own doc comment. Now the
  tail always walks every remaining byte; the only branch left is on the public loop position.
  Bit-exact with the old shape (differential test, 200 random trials + boundary cases; ctgrind
  harness out_sha unchanged). `ctgrind-expected.tsv`: `share` `<=273`→`<=267`, `nonce`
  `<=400`→`<=378`, `betaprime` `<=313` now holds for real (was the intentionally-red R2 marker).
- **2026-09-15** — **NO CONSUMER-VISIBLE CHANGE:** A1 R1. The ctgrind harness
  (`src/ctgrind_harness.zig`, never part of the library build) gains a `betaprime` target that
  taints Bob's 160-byte MtA blind `β'`, and `scripts/checks/ctgrind-expected.tsv` gains its row. No
  library source changed. The row is RED on purpose: `zkproofs.mulAddBytes`'s carry tail
  branches on secret-derived sums (A1 R2).
- **2026-09-15** — **ADDITIVE:** audit F6. `signing.signWithSharesOptions(allocator, shares, message,
  random, options)` with `SignOptions{ .pair_threads, .pair_scratch_bytes }` runs Phase 3's
  `t(t−1)` ordered-pair MtA/MtAwc conversions on OS threads. Each pair gets its own ChaCha seed
  drawn from `random` up front, each thread owns a disjoint scratch slice and writes only its own
  result slot, and `δ_i`/`σ_i` are summed on the caller's thread after the join — no shared mutable
  state between threads. `signWithShares` is unchanged (it calls the new function with defaults:
  sequential, same randomness order). Measured, ReleaseFast, 5 interleaved reps, median sequential
  → 8 threads: `t=2` 1109 → 570 ms, `t=3` 3275 → 865 ms, `t=4` 6683 → 1612 ms.

- **2026-09-15** — **NO CONSUMER-VISIBLE CHANGE:** audit F4(b)/(c). Two input guards could be
  deleted with the suite green, because every existing reject test also broke a per-round equation.
  New tests build proofs whose every round holds: Πmod over the non-Blum `Ñ = 187 = 11·17` with a
  non-unit `w` (0 and 17), refused only by `Pimod.verify`'s `(w/Ñ) = −1` check; Πprm over the
  degenerate tuples `(h1, h2) = (4, 1)` and `(1, 1)` with the honest `λ = 0` proof, refused only by
  `Piprm.verify`'s `h ∉ {0, 1}` check.

- **2026-09-15** — **SECURITY + BREAKING (signature) + BEHAVIOURAL:** audit F5. MtA drew Bob's
  blind `β'` from `Zq`, so the integer Alice decrypts, `α' = a·b + β'`, was `a·b` plus a blind
  `q` times too small to hide it: Alice (who knows `a`) recovered Bob's `b` from `α'/a` in 4/4
  semi-honest and 3/4 checked-path trials. In `signWithShares` `b` is `γ_j` and the
  Lagrange-weighted key share `w_j`, so every signer learned every other signer's `w_j`.
  `mtaBobResponse` now draws `β' ← Z_N` (GG18 §3); `mtaBobResponseChecked` draws `β' ← Z_{q⁵}`
  (tss-lib `BobMid`), returns it as the new field `BobResponseChecked.beta_prime`, and refuses
  `N <= q⁷` with the new `MtaError.PaillierModulusBelowFloor`. `zkproofs.proveBobMta`/
  `proveBobMtaWc` take `beta_prime: *const [beta_prime_bytes]u8` instead of a `Scalar`; new public
  `zkproofs.beta_prime_bytes` and `zkproofs.q5_bytes`. Signatures produced are unchanged in kind
  (MtA randomness never reaches `r`/`s`). Two checked-path tests moved from 1024- to 2048-bit keys.

- **2026-09-14** — **NO CONSUMER-VISIBLE CHANGE:** `paillier.PublicKey.fromBytes` and
  `SecretKey.fromBytes` now refuse an `n` below 512 bits (paillier audit F8). `PartyPublicKeys` and
  the keygen-output loader inherit that refusal for a toy key on the wire. The audit F3 (a) test
  built its 8-bit key through `fromBytes`; it now takes it from `fromPrimes` and swaps `Γ` in by
  hand. Nothing else here loads a key that small.

- **2026-09-14** — **BREAKING (signature):** audit F10, round-2 decision Q7. `aux_proofs.verifyWellFormed`
  verified Πprm and Πmod only and left `AuxParams.validate` — the structural floor, including
  `Ñ > q⁷` — to the caller by doc comment, although it is the function that makes a received tuple
  trustworthy and both proofs hold over a toy modulus. It is now `verifyWellFormed(aux, proof,
  random)`: `validate(random)` first, then both proofs; `VerifyError` gains `InvalidAuxParams`.
  No caller outside this module's tests. New tests: an honest 128-bit tuple with its honest proof is
  refused (`InvalidAuxParams`) although both proofs hold; a real 2048-bit safe-prime tuple (fixed
  primes, generated once with OpenSSL and checked) is accepted, and a tampered proof for it refused.

- **2026-09-10** — **NO CONSUMER-VISIBLE CHANGE:** adds fuzz harnesses for
  the last 5 of the 12 originally-unfuzzed public `fromBytes*` entry points
  (audit F8, closed): `RangeProof`/`MtaProof`/`MtaProofWc`.`fromBytesAlloc`
  (`zkproofs.zig`) and `ModProof`/`PrmProof`.`fromBytesAlloc`
  (`aux_proofs.zig`). Same shape as the 7 already covered (a fixed, cheap,
  one-time fixture built outside the fuzz loop — a toy 8-bit `n_tilde` and
  a `min_generate_bits`/512-bit Paillier key, not the 2048-bit fixture this
  module's security-relevant tests need — then arbitrary bytes into the
  decoder). 12 of 12 now covered. No production code changed.

- **2026-09-10** — **DOC ONLY, no behavior changed:** this file's
  2026-07-15 entry below (and, independently, `paillier.decrypt`'s own doc
  comment) both described the variable-time Paillier `L`-function division
  as accepted because the value it divides is "masked by a fresh uniform
  `β'` and is therefore independent of the secret nonce." That is wrong as
  this module actually calls it: `mta.zig`'s `beta_prime` is drawn by
  `randomScalar`, uniform over `Zq` (the curve's ~256-bit scalar field),
  not over `Z_N` (this module's Paillier modulus, ~2048 bits) — a `Zq`-
  sized mask over a `Z_N`-sized value is not the independence case either
  sentence described. `SPEC.md`'s own "A5" section already had the correct
  accounting; nobody had checked the CHANGELOG/`paillier` comment against
  it. See `SPEC.md` A5 (this pass's addendum) for the measurement — an ad
  hoc `zig build-exe -fvalgrind` run over `paillier`'s own gated ctgrind
  harness confirms the L-function division IS reached by taint from the
  secret key (333/143 contexts, `crt`/`noncrt`, vs 0/0 untainted) — and for
  what remains genuinely open (whether it is *exploitable*, which no
  measurement in this pass answers). Not re-litigating the older entry's
  history below; recording the correction here instead.

- **2026-09-10** — **BEHAVIOURAL, not breaking:** `signWithShares` now builds
  Alice's Paillier encryption of her secret and its range proof ONCE per
  ordered `(i,j)` pair and shares it between the pair's γ- and w-conversions,
  instead of rebuilding an independent copy for each (audit F7, MED — the
  duplicate cost every existing consumer already paid silently). Output
  signatures are unchanged (still verify under standard ECDSA); what changes
  is that Alice now sends Bob one Paillier ciphertext + range proof per
  ordered pair instead of two, and per-pair wall time drops accordingly.
  Measured (ReleaseFast, `t=2`, mean of 3 reps): **1242 ms → 1024 ms, -17.6%**.
  Internal-only signature change (`runCheckedMtA`/`runCheckedMtAwc`, both
  file-private) — no public API touched.

- **2026-09-10** — **NO CONSUMER-VISIBLE CHANGE:** adds fuzz harnesses for
  the five fixed-size wire-message codecs `signing.zig` decodes from a
  counterparty during signing (audit F8 continued — `GammaCommitment`,
  `SchnorrProof`, `GammaReveal`, `DeltaShare`, `SigShare`.`fromBytes`). With
  `KeyShare.fromBytesAlloc` (closed earlier this campaign), 6 of the 12
  originally-unfuzzed public `fromBytes*` entry points now have coverage;
  `RangeProof`/`MtaProof`/`MtaProofWc`.`fromBytesAlloc` and
  `ModProof`/`PrmProof`.`fromBytesAlloc` remain open. No production code
  changed.

- **2026-09-10** — **NO CONSUMER-VISIBLE CHANGE:** adds a fuzz harness for
  `KeyShare.fromBytesAlloc` (audit F8, MED — 12 of 15 public `fromBytes*`
  entry points had zero fuzz coverage; this closes the highest-severity
  one, the decoder whose missing validation was audit F2's HIGH). Corpus
  seeds a real accepted `KeyShare`, the F2 "own index missing from
  `public_keys`" shape as a corpus entry (not just the standalone
  regression test), an index tampered to an absent value, a truncation,
  and a header-only/empty input; a companion test pins that only the real
  seed is accepted (1 of 5 non-empty seeds). No production code changed.

- **2026-09-10** — **NO CONSUMER-VISIBLE CHANGE:** adds a test isolating
  `verifyBobMtaWc`'s equation 6 (audit F4(a), MED) — the existing "wrong
  B" test tampers `b_point` only at verify time against a proof whose
  challenge was bound to a different point, so it fails equations 3-5
  (Fiat-Shamir mismatch) before equation 6 is ever reached; the new test
  keeps `b_point` consistent between prove and verify (so the transcript
  matches and equations 3-5, which do not reference `b_point`/`u1_point`
  in their own arithmetic, pass on their own terms) while that `b_point`
  is not the Paillier witness `b`'s actual `·G` — isolating the rejection
  to equation 6 alone. No production code changed. Also corrects a
  `Pimod.verify` comment (audit F9, LOW) that claimed its Miller-Rabin
  witnesses are outside the modulus-crafter's control; `SHA256(n_tilde)`
  is a public deterministic function a crafter can evaluate offline, so
  the real argument is cost (~2^-128 per grind attempt at 64 rounds), not
  unpredictability — the underlying conclusion (per-round equations, not
  MR, carry the check) is unchanged.

- **2026-09-10** — **BEHAVIOURAL, not breaking:** `AuxParams.validate` now
  rejects an `h1`/`h2` of order 2 (audit F1, HIGH — an order-2 `h2` let a
  malicious counterparty defeat the Pedersen commitment's hiding via
  `z² = h1^(2m)`, independent of the blinding); this is the cheap
  always-enforced floor the user decided on (Πprm/Πmod stay a deferred,
  separate task). `KeyShare.fromBytesAlloc` now rejects a tuple whose own
  `index` is missing from `public_keys` (`error.InvalidEncoding`), and
  `signWithShares` fails closed with `error.InvalidParameters` on the same
  condition instead of panicking (ReleaseSafe) or hitting undefined
  behaviour (ReleaseFast) on a null-optional unwrap (audit F2, HIGH — a
  real caller, `dkg`, assembles `KeyShare`s from DKG output). Any genuinely
  well-formed tuple/share is accepted exactly as before; only the two
  malformed/degenerate shapes above are now rejected instead of silently
  accepted or crashing. Also fixes the Γ commit-reveal check inside
  `signWithShares`, which compared a value against itself and so could
  never reject anything (audit F3, MED) — internal-only, no observable
  signature-shape or API change for a well-behaved caller.

- **2026-09-09** — **NO CONSUMER-VISIBLE CHANGE:** `src/ctgrind_harness.zig` is added (A1 audit finding R2; the tier-A ctgrind queue, 28 modules). Measured ReleaseFast under valgrind, in-file contexts: **share 127 / nonce 400**. Every target has an untainted control row and a no-`-fvalgrind` trap row, both 0, so the numbers are real taint propagation rather than a silent no-op. Settles a disputed audit claim by measurement: `signing.zig:267`'s `Secp256k1.basePoint.mul(nonce) catch continue` does fire, but `k256`'s own `mul`/`combMulBase` end in `try q.rejectIdentity()` identically (`k256/src/group.zig:278`, `:347`), so routing through `k256` would remove nothing — the class was never fixed for secp256k1, only for Edwards/Ristretto, and it fires at p≈2⁻²⁵⁶. ⭐ Two things nobody was looking for: `paillier.decrypt`'s L-function does a variable-time big-integer division on `k_i`-derived data on EVERY run (audit item A5 had only theorised it), and `zkproofs.zig:345`'s `mulAddBytes` ripple-carry loop has a trip count that depends on the RAW secret witness, before the blinding that makes the published response safe — no document in this module mentions it. ⚠ These numbers are NOT adjusted for single-process over-taint (see `dkg`'s entry); a share of them is public commitment data that only looks secret because one process built it.

- **2026-09-07** — **NO CONSUMER-VISIBLE CHANGE:** this module is out of
  `zig build check-testonly` again, and its fuzz corpus uses a nine-line local
  copy of `testkit.fuzz`'s seed helper rather than the shared one. Enrolling it
  via `test_deps` puts it in that gate, whose probe imports the *published*
  module and references every declaration three levels deep — and this module
  deliberately guards a test-only function with a `@compileError` that fires
  outside a test build, so the probe touches a decl that exists to refuse being
  touched. The two gates contradict each other for any module shaped this way.
  ⛔ A local copy is the thing `testkit.fuzz` was created to abolish (33 of them
  across 12 modules). What stops this one drifting is its anchor test, which
  drives the real `std.testing.Smith` over what the helper produces — the same
  shape as testkit's own tests, so a future Zig that changes `slice`'s framing
  fails here loudly instead of leaving the corpus quietly seeding nothing.

- **2026-09-07** — ⛔⛔ The harness written to guard the fixed ~29 TB over-allocation bug had
  never once produced the input that caused it. All three counted/length-prefixed fuzz
  targets ASSEMBLED their frame out of ranged draws, and a ranged draw returns the range
  minimum when fewer than eight input octets remain. With no corpus the lane runs one round
  on `in = ""`, so every draw took its minimum and each target ran exactly one input for
  ever: `FeldmanCommitments.fromBytesAlloc("\x00\x00\x00\x00")` (count 0, **accepted**, zero
  elements), the same for `PublicKeys`, and twelve zero octets for `AuxParams`. The
  `count = 0xFFFFFFFF` arm sits behind `valueRangeAtMost(u8, 0, 2)`, whose minimum selects
  the small-count arm instead. ⛔ The assembly buffers were also far too small for this
  module's own frames: a real two-party `PublicKeys` encoding is 1150 octets (each entry
  carries a `paillier.modulus_sq_bytes`-wide `g`) against 4 + 256, and a full
  `aux_modulus_bits` `AuxParams` is 780 against three fields of 64. All three targets now
  draw the message itself with one `smith.slice` into a buffer sized for the module's own
  frames (512 / 4096 / 1024), and carry a corpus: real frames from `splitSecretKey`,
  `keygenTrustedDealer` and `generateAuxParamsWithTrapdoor`, plus the hostile counts and
  lying length prefixes written out as bytes — reproducible where a draw is not. Measured:
  7/8, 6/7 and 7/8 non-empty seeds reach the decoder where 0 did; 3, 2 and 2 accepted,
  carrying **5** commitments, **2** party entries and **2** distinct Ñ bit-widths. Those
  second numbers are pinned because `00 00 00 00` is a *legal* frame for the first two
  decoders — an accepted count would have looked healthy on the collapsed harness.

- **2026-09-03** — Drift re-audit. **`mtaAliceFinalize` reduced only the LOW
  64 BYTES of the decrypted Paillier plaintext**, on the strength of a comment
  reading "α' = a·b + β' < q² + q < 2^512, so only its low 64 bytes are
  nonzero". That is true of an HONEST Bob, whose `β'` is a `Scalar`; it is not
  a fact about the protocol. `verifyBobMta`'s range check on `β'` is
  `t1 <= q⁷` — GG18 Appendix A.3's slack, ≈ 2^1792 — so a malicious Bob can
  prove a `β'` of `2^512 - X`, and whenever `a·b >= X` the plaintext crosses
  2^512, the high bytes were dropped, and the module's own invariant
  **α + β ≡ a·b (mod q) silently broke while every proof check passed**.
  Reproduced with `a·b = 1000`: at `X = 2000` the identity holds, at `X = 500`
  it does not — so Bob picks the outcome, and the resulting abort is one
  adaptively-chosen bit of `a·b`. `mtaAliceFinalizeChecked`'s doc named this
  exact attack class ("the Alpha-Rays/TSSHOCK failure class … is rejected
  here"). The reduction is now full-width (`zkproofs.scalarFromWide`, made
  public for it), which removes the precondition rather than asserting it:
  `q⁷ + q² < N` for any `N` meeting the module's key-size floor, so the
  identity holds for every `β'` the proof can accept.
- **2026-09-03** — **`s2`/`t2` are length-capped before they are used as
  exponents.** Both verifiers feed them straight to `powPub`, and nothing
  bounded them — the work is linear in a length the attacker picks. Measured
  against an honest `s2` of 352 bytes, on a proof the verifier then rejects
  anyway: 1 KiB → 44 ms, 64 KiB → 1.1 s, **1 MiB → 19 s**. One message, one
  core, nineteen seconds. The honest bound is `96 + |Ñ| + 1` bytes
  (`e·ρ + γ` with `e < q`, `ρ < q·Ñ`, `γ < q³·Ñ`), so the cap rejects nothing
  an honest prover can produce — asserted from both sides, and the 1 MiB case
  is now a test that runs in 0 ms.
- **2026-07-29** — The GG18 Appendix-A Fiat-Shamir transcripts now bind the Paillier
  **generator** `Γ`, not only the modulus `N` (audit F3 — an unbound
  public value in the verification equation is a value a prover can
  still vary after the challenge is fixed). A companion fail-closed
  check, `root.paillierGeneratorIsStandard`, rejects any received
  Paillier key whose `Γ != N+1` at every prove and verify entry point,
  alongside the existing F1/F2 gates. **BREAKING (wire):** absorbing a
  new value changes every challenge, so proofs minted before this change
  do not verify after it; the three Fiat-Shamir domain tags were bumped
  `…/v1` → `…/v2` so the break surfaces as a plain verification failure.
  No interop is affected — these proofs were never byte-compatible with
  any other implementation.
- **2026-07-28** — Fuzz harnesses over the three length-prefixed deserializers —
  `FeldmanCommitments.fromBytesAlloc`, `PublicKeys.fromBytesAlloc` and
  `AuxParams.fromBytesAlloc` — which had none, under the collection's "never panic and
  never over-allocate on arbitrary input" threat model. Tests only.
- **2026-07-21** — Security audit: `signWithShares` now `secureZero`s its `Ephemeral[]`
  scratch — every party's ephemeral nonce `k`, blinding `gamma`, weighted key share `w`,
  `delta` and `sigma` — before returning it to the allocator, instead of leaving that
  residue in freed heap. The ZK proofs' internal masks were already zeroed; this driver
  array was the one gap.
- **2026-07-18** — The ZK proofs' modular-exponentiation path was rewired onto `montint`:
  about **2.8× faster signing**, and it closed the audit's performance finding — the
  Paillier/ZK hot path had measured ~7–8× slower than an OpenSSL-class bignum on
  `std.crypto.ff`'s schoolbook Montgomery multiply, and after the rewire the 4096-bit
  modexp measures ~1.78×, below the finding bar. No API change.
- **2026-07-16** — Πprm/Πmod proofs of correct generation for the ring-Pedersen auxiliary
  parameters, so a receiver can check that a peer's aux params were honestly generated and
  not merely well-shaped. Closes the audit finding the structural validation below opened;
  the proofs are an out-of-band setup artifact, not auto-exchanged in the online flow, so
  the always-on floor is still what guards the signing path.
- **2026-07-15** — **BEHAVIOURAL, not breaking** — received ring-Pedersen auxiliary
  parameters are now validated, and a key-size floor is enforced, at **every** prove and
  verify entry point: `Ñ` must be composite, `1 < h1, h2 < Ñ`, the Jacobi symbol `(h/Ñ)`
  must be `+1`, and both `Ñ` and the Paillier `N` must exceed `q⁷` (≈2¹⁷⁹²). Without the
  floor the `t1 ≤ q⁷` / `s1 ≤ q³` range bounds inside the proofs were vacuous. Aux params
  and keys that previously went through are now rejected fail-closed with
  `error.InvalidAuxParams`. This is the first pair of findings from the module's Fable-tier
  security audit, which raised **six findings, all fixed** — these two, the perf rewire,
  the `Ephemeral[]` zeroization, the Paillier-generator transcript binding, and the
  variable-time Paillier `L`-function division, which was closed in the `paillier` module
  where the division actually lives (documented as accepted, since the value it divides is
  masked by a fresh uniform `β'` and is therefore independent of the secret nonce). A
  seventh — that the security-critical ZK reject tests were skipped in the default build —
  was **withdrawn**: measured rather than read, this module is `heavy`, so the default lane
  compiles it at ReleaseSafe and runs all fifteen of them.
