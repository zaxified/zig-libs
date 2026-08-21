# bn254 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-22** — Re-export `EcPairingError` at the module root. `ecPairing` and
  `ecPairingCheck` return it, but only `PrecompileError` — a strict subset, missing
  `error.OutOfMemory` — was aliased there, so a caller naming either function's error
  set from outside got a set that does not compile. Found by the module's first
  outside consumer (`example/main.zig`), not by any test in here.
- **2026-07-18** — Security audit: five findings fixed, four documented as accepted (not
  defects) — part of the collection-wide audit. Modeled on gnark-crypto (Go+asm) /
  arkworks (Rust) / libff (C++); py_ecc = correctness oracle only (design reference, not
  a test anchor).
- **2026-07-15** — New module: BN254 / alt-bn128 curve — Parts 1-6 COMPLETE: field tower
  + G1/G2 + optimal-ate pairing + EIP-196/197 precompiles + Groth16 verifier.
