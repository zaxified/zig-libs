# threshold_ecdsa — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
