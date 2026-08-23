# spake2plus — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
