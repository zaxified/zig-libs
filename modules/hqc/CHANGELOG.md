# hqc — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-14** — Test-only: `kem_kat_test.zig` gained a `testing.fuzz` harness
  on `Hqc128.decaps` (arbitrary ciphertext bytes against a fixed keypair,
  driving the Reed-Muller/Reed-Solomon decode path) — `zig build check-fuzz`
  no longer names this module. No panic/OOB found; **neither breaking nor
  behavioural**.
- **2026-07-18** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified: Byte-exact
  vs official NIST v5.0.0 `.rsp` (`kat_vectors_kem.zig`, curl-fetched from `pqc-hqc/hqc`
  tag v5.0.0, first 3 counts/set), pk/sk/ct/ss all asserted + decaps.
- **2026-07-16** — New module: HQC (Hamming Quasi-Cyclic) — the code-based KEM NIST
  selected March 2025 as a structurally-independent backup to lattice-based ML-KEM.
