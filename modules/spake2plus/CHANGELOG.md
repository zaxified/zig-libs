# spake2plus — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-01** — Security audit. `verifierConfirm`'s documented gate did not hold:
  `VerifierConfirmResult` withheld the `k_shared` FIELD while returning `tt` and `k_main`,
  and each of those is a one-call pre-image of `K_shared` through this module's own public
  `deriveKeys`/`kdf` — measured, at the moment the Verifier has never seen a `confirmP`,
  which is exactly the "silently-unauthenticated key" SPEC.md named as the worse defect.
  The struct now carries `confirm_v` and nothing else and frees its own transcript; the
  byte-exact coverage the removed fields carried is unchanged, since `verifierFinish`
  recomputes and returns the same values after the confirmation check. Scoped honestly in
  the docs: this stops a caller's accident, not a hostile Verifier, which holds every input
  needed to recompute the schedule anyway.
  Guards that held nothing, now pinned: `verifierConfirm`'s two RFC 9383 §6
  group-membership checks (added as a third wire-facing entry point in `7386e724` and never
  added to the §6 test set — both could be deleted with the suite green in Debug and
  ReleaseFast), and all twelve `rejectNonCanonical` call sites (the group operation reduces
  mod `n` silently, so `basePoint.mul(n+1) == basePoint.mul(1)` — without the guard a
  non-canonical encoding aliases onto a canonical one). Added the mismatched-password run
  the suite never had, and a source-text gate on the constant-time claim, after
  `computeL`'s multiply over the secret `w1` was swapped for the variable-time `mulPublic`
  with all 29 tests green. ⚠ That gate pins the CALL SITE, not timing: `p256` has no
  `ctgrind_harness.zig`, so neither module is in the `ct` set covering `k256`/`montint`.
  `fuzzShareDecode` rebuilt: it drew a random length in [0, 96] and reached a parsing point
  0.008% of the time, **never once in the 65-byte uncompressed form that is the only
  encoding this module accepts** (0 of 20,000,000 draws) — it was fuzzing the compressed
  path no caller can reach. Now fixed at `share_length`, half the draws perturbing a real
  encoding, driven through the public entry point: 10.0% reach the parse, all uncompressed.
  Docs: `NOTICE` still declared the module a scaffold of `@panic` stubs and carried no
  BoringSSL provenance entry; SPEC.md called `computeW0W1` unanchored in four places and
  omitted the BoringSSL goldens from its anchor evidence; both named `std.crypto.ecc.P256`
  as the group. SPEC.md gained the two obligations it was missing for a PAKE — the
  fail-closed entropy source `x`/`y` must come from (CONVENTIONS.md §2.2; a predictable `y`
  makes `w0*N = shareV - y*P` recoverable and collapses this to an OFFLINE dictionary
  attack) and failed-attempt rate limiting, which RFC 9383 §6 does not require and an
  implementer reading it as a checklist will therefore omit.
- **2026-08-23** — False-anchor fix: the documented "Protocol flow" (README.md) could not
  actually run. `proverFinish` requires the Verifier's `confirmV` as an input and
  `verifierFinish` requires the Prover's `confirmP` as an input, so two genuinely blind
  parties deadlocked — neither could produce a value the other needed first. This went
  unnoticed because `kat_test.zig`'s end-to-end test fed the Verifier's probe call the RFC
  9383 Appendix C vector's already-published `confirmP`, and `example/main.zig` worked
  around it by reconstructing `verifierFinish`'s internals from lower-level primitives.
  Fixed additively: a new `verifierConfirm` function computes the Verifier's `Z`/`V`/`TT`/
  key schedule and emits `confirmV` with no `confirmP` input required (matching RFC 9383
  Appendix A.5's actual message order, where the Verifier transmits `confirmV` before ever
  seeing `confirmP`) — deliberately does NOT return `K_shared`, since RFC 9383 §3.3
  requires validating the peer's confirmation before either party may consider the
  protocol complete. `proverFinish`/`verifierFinish` are unchanged. README.md, SPEC.md,
  and `example/main.zig` updated to the real, runnable, blind two-party flow; `kat_test.zig`
  gained a byte-exact KAT for `verifierConfirm` and a property test that drives both parties
  with no foreknowledge of either confirmation value (proven, via temporary removal of
  `verifierConfirm`, to fail to compile against the prior API).
- **2026-07-18** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Byte-exact against RFC 9383
  Appendix C's published test vectors.
- **2026-07-12** — New module: SPAKE2+ — an augmented (asymmetric) PAKE (RFC 9383),
  P-256/SHA-256/HKDF/HMAC ciphersuite (the Matter/Thread commissioning PAKE) —
  `proverStart`/`verifierStart`.
