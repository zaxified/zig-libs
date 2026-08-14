# groth16 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
