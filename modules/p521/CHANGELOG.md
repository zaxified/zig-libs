# `p521` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-30** — **CONSUMER-VISIBLE (fixes only):** no-panic sweep + blind review (§ GT). `Signature.der_encoded_length_max` 139 → 141: `fromBytes` accepts any 132 bytes, and `toDer` on an r/s with top byte ≥ 0x80 wrote 141 bytes into a 139-byte buffer (panic in safe builds, 2-byte stack overflow in ReleaseFast); valid signatures encode byte-identically. Tests: `src/sweep_test.zig` (also pins DER parse, SEC1 and ECDH edge cases).
- **2026-10-18** — **NO CONSUMER-VISIBLE CHANGE:** Docs: README/SPEC brought up to Zig 0.17.0 (version statements, snippets, measurement labels).
- **2026-10-18** — Test fix (big-endian only): the `fromBytesReduce(.little)` differential test built its bytes as `@bitCast(nativeToLittle(w))`; Zig 0.17's int -> array `@bitCast` is already little-endian on every target, so the swap reversed them on big-endian. Now `writeInt(.little)`. s390x (qemu) passes.
- **2026-10-13** — Fix: the variable-time base-table walk indexed the table with a `u64` window digit, which does not compile on 32-bit targets (`check-portable` linux32 via dns → http → tlsclient); now `@intCast` (the digit is < 2^w).
- **2026-10-11** — **Speed (P3 → P2):** scalar multiplication in Jacobian coordinates. Secret
  scalar (`mul`, ECDH): reduced mod n, folded to min(s, n − s), 106 signed 5-bit digits over a
  16-entry affine table (one batch inversion), masked scans and blends; the incomplete formulas'
  exceptional cases are ruled out by the fold (proof in `mulCt`), only the identity cases remain
  and are blended. Public scalars: width-5 NAF, and the comb table for G in
  `mulDoubleBasePublic`. Field `mul`/`sq` forced inline into the point formulas (`mulI`/`sqI`).
  Paired against OpenSSL 3.5.5: ECDH 1.70× → 0.97×, verify 1.23× → 0.84×, sign 0.74×.
  `mul_burn` 16 → 24 KiB (ecdhInto dirtied 19.2 KiB). Tests: `mulCt`, `mulPublic` and
  `mulDoubleBasePublic` against the old RCB ladder (kept as `mulRcbReference`) on 14 edge scalars
  (0, n − 1, n, n + 1, 2n − 1, 2^528 − 1, …) and random ones with leading zero windows, compared
  by SEC1 bytes; doubling and cancelling sums; the wNAF shape. Fuzz 20,000 runs clean.
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
