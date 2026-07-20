# Changelog

Per-release changes, grouped by module. One semver for the whole collection
(policy: `CONVENTIONS.md` §8 — pre-1.0, a minor bump may break any module's
API; breaking changes are flagged **BREAKING**). Routine internal refactors
are not listed.

## Unreleased

The collection grew 77 → 148 modules since v0.1.0. Highlights, by area:

- **Pairing / elliptic-curve crypto:** the complete BLS12-381 arc (field tower,
  pairing, RFC 9380 hash-to-curve, BLS signatures, KZG/EIP-4844, threshold) +
  `bn254`, `bbs`, `coconut`, `tlock`, `ibe`; native `k256`/`p256` cores;
  `ed448`/`decaf448`; `montint` big-integer Montgomery arithmetic.
- **Bitcoin / Lightning:** `bip340` Schnorr, `taproot`, `musig2`, `frost`,
  `adaptor`, `sphinx` (BOLT#4), `bolt3`, `bolt8` (Noise_XK) — byte-exact
  against the BIP/BOLT vectors.
- **Post-quantum:** `slhdsa` (FIPS 205), `falcon` (FN-DSA), `hqc`, `xmss`.
- **FHE / ZK / MPC:** `bfv`, `tfhe`, `groth16`, `bulletproofs`, `paillier`,
  `threshold_ecdsa`, `dkg`, `fss`, `vdf`, `ecvrf`.
- **Protocol security:** `rsa`, `x509` path validation, `dnssec`, `ssh`
  (client + server transport), `opcua` (full client incl. SecureChannel),
  `dtls` 1.3 PSK, `quic-crypto` (RFC 9001), `tlsresume`, the `noise`
  framework, `hpke`, `mls`, `signal`, `opaque`/`voprf`, `spake2plus`,
  `ctap2pin`, `oscore`, `jwe`, `sealedbox`, `blindrsa`, `otp`.
- **Fabric / distributed:** `netsim` (deterministic DES + VOPR harness),
  `raft` (model-checked against the five safety properties), `spf-ect`,
  `loopfree-reconv`, `df-elect`, `liveness-hyst`, `loopix`, `lockfree`
  (MPMC queue + epoch reclamation), `ethfrag`, `kvtree` (COW B-tree).
- **Kernel / networking:** `ebpf` + `xdp-classifier`, `tc` (netem),
  `genetlink`, `wireguard`, `rawsock`, `stun`, `pping`, `sntp`, `dnp3`,
  `snmp` (v3/USM auth), `coap`, `mqtt`, `modbus`.
- **Performance campaign:** SIMD `chachapoly` (beats OpenSSL AVX2 keystream on
  the reference host), asm/Montgomery cores under `k256`/`p256`/`montint`;
  audited hot paths within ~≤3× of C peers; several constant-time leaks fixed.
- **Security audit (collection-wide):** all CRIT/HIGH findings fixed — memory
  safety in `dnssec`/`opcua`/`x509`/`stun`/`dnp3`, HTTP request-smuggling and
  `validate` O(n²)-DoS hardening, `dtls` anti-replay window, `zipstream`/
  `json5`/`mcp`/`csvsafe` fixes.
- **Tooling/docs:** `zig build check-catalog` consistency gate (found + fixed
  6 modules missing README catalog rows); versioning + spin-off policy
  (`CONVENTIONS.md` §8); this changelog.

## v0.1.0 — 2026-07-10

Initial public release: 77 modules, 1844 tests, CI green in Debug +
ReleaseFast, MIT (fping-lineage attribution preserved in `NOTICE` §1).
