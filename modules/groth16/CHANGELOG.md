# groth16 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-03** — Drift re-audit (last audited `b199192` — a *Sonnet light confirmation
  pass*, while the ledger records the module's own tier call as Opus, so the previous
  ground was thin). Six mutations, six red.
  - ⛔⛔ **A constraint system larger than the evaluation domain was SILENTLY TRUNCATED.**
    Every walk over the constraints stops at the domain size — `columnEvalAtTau` `break`s at
    `j >= n`, `prove` and `qap.checkDivisible` fill `for (0..n) |j| if (j < constraints.len)`
    — and the only thing in the way was `std.debug.assert(constraints.len <= n)`, compiled
    out in the very mode README.md and SPEC.md tell you to run. The CRS is then built from
    the truncated circuit, so the dropped constraints are not merely unproven: **they are
    absent from the statement the verifier checks**, and nothing at any layer reports it.
    `r1cs.zig`'s own module doc says `isSatisfied` here and the divisibility test there
    "must always agree"; above the domain size they could not.
    Measured on a 3-constraint circuit at `n = 2` whose third constraint the witness
    violates: `r1cs.isSatisfied` correctly answers `false`, Debug panicked, and ReleaseFast
    ran on into undefined behaviour — observed here as SIGSEGV inside `checkDivisible`, and
    on another run of the same code as the QAP oracle answering `true` with
    `bn254.groth16Verify` ACCEPTING the proof. Undefined is undefined; the missing check is
    the same. `n` is a plain comptime constant a caller picks once, so the ordinary way in
    is a circuit that grew past it. Now `error.DomainTooSmall` from `setup`, `prove` AND
    `checkDivisible` — three places because the truncation was in three, and because `prove`
    takes the `System` separately from the `ProvingKey`, so a caller can hand it a circuit
    that grew since the key was made. **Source-breaking:** `prove` and `checkDivisible` now
    return error unions, and `SetupError` has a new variant.
    ⚠ Worth keeping: a first version of the regression test reached only `setup`'s refusal,
    and deleting `prove`'s left the suite green.
  - ⛔ **`poly.divByVanishing`'s size cap was a debug-only assert** in front of an
    `@memcpy` into a fixed 917 KB stack array: a measured SIGSEGV in ReleaseFast at
    `p.len = 20480`. The in-module route is real — `prove(comptime n, …)` builds a `p` of
    length `2n − 1`, so any `n >= 8193` crosses it — and the constant's own doc invites
    exactly that ("bump if a larger circuit needs it") without saying the check evaporates.
    Now `error.PolynomialTooLarge`.
  - ⛔ **`snarkjs_export.decimalBytes` documented "any length"** while copying into a private
    32-byte buffer behind two `std.debug.assert`s: a 48-byte input was a measured SIGSEGV in
    ReleaseFast. Both bounds are typed refusals now, and SPEC's **fuzz exemption** — argued
    from every byte-accepting `pub fn` only ever seeing "field elements THIS module just
    computed" — now says out loud that such an argument holds only while the published
    signature agrees with the call graph.
  - `writeG2`'s point-at-infinity branch had **no test**: replacing its literal with garbage
    left the whole suite green, while `writeG1` has both a generator and an infinity case.
    The frozen snarkjs KAT carries only finite points, so a valid-output corpus could not
    reach it.
- **2026-09-03** — SPEC.md gained the **threat model** its own first line has promised since
  the file was written. Three things a Groth16 consumer must be told and none of which was
  anywhere in SPEC or README: proofs are **malleable** (measured — `πA ← [k]πA`,
  `πB ← [k⁻¹]πB` with `k = 1234567` produces different bytes that also verify, so proof
  bytes must never be a nullifier or replay key); `verify` **does not validate the verifying
  key** (it validates the untrusted proof, including a real G2 subgroup check — the classic
  Groth16 bug is not present — but the `vk` is trusted verbatim, a boundary `bn254` states
  and this module's re-export repeated none of); and the evaluation domain is part of the
  statement.
- **2026-09-03** — Docs. `prover.zig`'s header still said both `setup` and `prove` "`@panic`
  until the core lands" and that `brokenProof` was what was real "before `prove` exists";
  `harness_test.zig` still said its core tests SKIP until the gate flips. The commit that
  stopped 25 modules describing finished work as unimplemented fixed `root.zig`, `gate.zig`,
  README and SPEC, and missed these two. And `example/main.zig`'s headline — "what a
  consumer of this module alone cannot do: check its own output" — was falsified by the very
  next commit, which added `groth16.verify` (whose own doc says "Found by writing
  `example/main.zig`"); the example now verifies its own proof before serialising it. Its
  "no private wire leaked" check was `indexOf(public_json, "13")`, which cannot fire on
  `["91"]` and would have fired FALSELY on a public input of 130 or 913; it now asserts the
  published inputs structurally.
- **2026-08-02** — ⏪ *Backfilled 2026-09-03; this entry was missing.* **BREAKING:**
  `pub const prover` was demoted to a private `const prover` in `root.zig`, removing
  `groth16.prover.*` (`brokenProof`, `bogusVerifyingKey`, `SetupError`) from the public
  surface. Added in the same commit: the whole `snarkjs_export` namespace
  (`max_decimal_digits`, `decimalBytes`, `fpDecimal`, `frDecimal`, `writeG1`, `writeG2`,
  `verifyingKeyJson`, `proofJson`, `publicJson`) plus its frozen snarkjs KAT — a foreign
  verifier accepting a proof this module produced.
- **2026-07-21** — ⏪ *Backfilled 2026-09-03; this entry was missing.* Added the public
  `ToxicWaste.deinit()` and secret zeroization in `setup` and `prove`.

- **2026-08-23** — Added `Groth16Error`, the error set `verify` returns. The
  2026-08-22 entry below re-exported the function and left its error set
  behind, so a caller that wanted to handle `error.WrongPublicInputCount` by
  name still had to reach through `groth16.bn254.Groth16Error` — half a
  publication. Same omission `bn254`'s own root fixed one commit earlier
  (`a2bdcb33`). Pinned by a test that names the set through this root, from a
  file outside it.

- **2026-08-22** — Added `verify`, an alias for `bn254.groth16Verify`. It was already
  reachable as `groth16.bn254.groth16Verify` (the namespace is re-exported), so this is
  symmetry rather than a fix: the module published `Proof` and `VerifyingKey` but not the
  one function that judges them, which sent a first-time consumer looking. Found by writing
  `example/main.zig`.

- **2026-08-14** — Docs-only: `SPEC.md` gained a `**Fuzz exemption:** EMIT-ONLY`
  entry — this module is the Groth16 PROVER (the verifier, and its fuzz
  coverage, live in the sibling `bn254` module); its own only byte-accepting
  functions (`snarkjs_export.zig`) convert proofs/keys THIS module just
  computed into decimal-ASCII JSON, never parse foreign bytes. No production
  or test code changed; **neither breaking nor behavioural**.
- **2026-07-18** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on `snarkjs`
  (JS) / `libsnark` (C++) / `bellman` (Rust); anchored by sibling `bn254.groth16Verify`
  (design reference, not a test anchor).
- **2026-07-17** — New module: Groth16 zk-SNARK PROVER over BN254 (Groth 2016, "On the
  Size of Pairing-based Non-interactive Arguments").
