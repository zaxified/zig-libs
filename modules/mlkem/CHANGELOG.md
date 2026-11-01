# `mlkem` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-01** — Fix: on aarch64 `SecretKey.fromBytes` accepted every
  decapsulation key that fails the FIPS 203 §7.3 checks — the caller of an
  error union whose payload holds a 32-byte vector and whose size is not a
  multiple of 32 read the payload instead of the error (Zig 0.17.0 aarch64
  layout disagreement, Zig aligns the vector to 16, LLVM to 32). `Poly`'s
  vectors are now explicitly `align(32)`; arm64 tests green (full CI
  41308222960 had 4 failures there).
- **2026-11-01** — New module: ML-KEM-512/768/1024 (FIPS 203) in
  `std.crypto.kem.ml_kem`'s API shape — 16-lane `i16` NTT with a deinterleaved
  NTT-domain layout, 4-way Keccak for the matrix and noise samplers, branch-free
  rejection sampling. FIPS 203 §7.2/§7.3 key checks, seed-form private key
  (`seedBytes`), `tryGenerate` / `tryEncaps` (entropy failure as an error) and an
  optional FIPS 140-3 pairwise consistency test. 0.48–0.76× aws-lc-rs 1.18.0 and
  0.18–0.29× OpenSSL 3.5.5 on keygen/encaps/decaps (`zig build bench-mlkem`);
  anchored on NIST ACVP-Server, Wycheproof and CCTV vectors and a live OpenSSL
  oracle (`zig build interop-mlkem`); fuzz harness and ctgrind harness.
