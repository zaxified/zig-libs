# threshold_ecdsa — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
