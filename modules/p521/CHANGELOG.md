# `p521` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-10** — **Speed:** fixed-base comb for s·G (`combMulBaseCt`: 106 signed 5-bit digits,
  one mixed addition each, masked 16-entry scans behind a `blackBox` barrier as in p256) over a
  generated affine table (`src/base_table.zig`, `tools/gen_base_table.py` — independent Python
  arithmetic; a comptime build cost ~1 min / ~2 GB per compile). Used by key derivation and the
  ECDSA nonce commitment. keygen 615 → 122 µs, sign 741 → 237 µs (2.17× → 0.68× OpenSSL 3.5.5);
  worst ratio now ECDH 1.70×, P4 → P3. Tests: differential comb = `mulCt(G, s)` on edges and 400
  random 66-byte scalars, a corrupted-table positive control, table spot checks vs `mulPublic`.
  ctgrind keygen/sign: 0 in-file (counts unchanged, digests re-pinned).
- **2026-10-10** — Audit (review + mutation schemata). Review: field (inversion chain to p − 2,
  sqrt exponent 2^519, canonical decode, 4p headroom in `sub`, carry bounds), scalar (CIOS bound
  a < 2^528 · b < n, R² reduction, rejection sampling), group (RCB formulas, masked lookups,
  comb), ECDSA (RFC 6979 bits2int/bits2octets, DRBG tags, verify ranges), ECDH — clean. Mutation
  34/38 after 4 new refusals in `kat_test.zig` (zero secret key — `fromSecretKey` returned the
  identity as the public key with the check removed —, zero r / s at `Verifier.init`, a negative
  DER INTEGER, a SEQUENCE length that disagrees with its content); 4 equivalent (recoding `>` vs
  `>=` at x = 16, the comb's keep mask — `addMixed` already returns p for (0, 0) —, ECDH's peer
  identity check — the result check returns the same error —, `random`'s top-byte mask).
  Card: audit A4 → A1.

- **2026-10-10** — **BEHAVIOURAL, not breaking:** `signPrehashedWithNonceForTesting` is `void` outside a test
  build (was a function whose body was a `@compileError`), so `check-testonly`'s probe of the published module
  compiles. Tests call it exactly as before.
- **2026-10-10** — Scope survey (OpenSSL reference, Go `crypto/ecdh`/`ecdsa` measured with Go's
  own benchmarks, RustCrypto `p521`, aws-lc, Zig std): `parity`; `## Compared with` table added;
  Performance `fastest ?` (aws-lc unmeasured); grade 4 (no longer provisional). Docs only.
- **2026-10-10** — New module: NIST P-521 (secp521r1) — Mersenne field,
  Montgomery scalars, complete-formula group, constant-time ECDH and
  ECDSA-P521 with RFC 6979 nonces, std `P384`/`Ecdsa`-shaped API. Anchored to
  NIST CAVP (186-4 ECDSA SigVer/SigGen/KeyPair/PKV, ECC CDH), Wycheproof
  (ECDH, ECDSA DER + P1363), RFC 6979 A.2.7 and an OpenSSL 3.5.5 oracle.
