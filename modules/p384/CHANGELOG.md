# `p384` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-30** — **NO CONSUMER-VISIBLE CHANGE:** no-panic sweep + blind review (§ GT) found nothing to fix (`der_encoded_length_max` = 104 already covers 48×0xff); pin tests for DER parse, SEC1 decode and ECDH edges in `src/sweep_test.zig`.
- **2026-10-21** — **Added:** `Ecdsa(Hash).signWithSecretKey(out, secret_key, msg, noise)`: the
  RFC 6979 signature from the secret scalar alone (no `d·G`), equal to `KeyPair.sign`'s on the
  RFC 6979 A.2.6 vectors; `error.NonCanonical` / `error.IdentityElement` as `fromSecretKey`.
  Burned and stack-probed.

- **2026-10-13** — Fix: the variable-time base-table walk indexed the table with a `u64` window digit, which does not compile on 32-bit targets (`check-portable` linux32 via dns → http → tlsclient); now `@intCast` (the digit is < 2^w).
- **2026-10-13** — **New module.** NIST P-384: Montgomery field in std's `P384.Fe` representation
  (portable `mont.zig`, shared with the scalar field; amd64 `MULX`/`ADCX`/`ADOX` CIOS core in
  `fast_core.zig`, asm text generated at comptime), `p521`'s group algorithms (Jacobian loops,
  min(s, n − s) fold, signed 5-bit digits, generated fixed-base comb, width-5 NAF for public
  scalars), ECDH, ECDSA over any digest ≤ 64 bytes with RFC 6979 nonces and strict DER, std's API
  shape with `*Into` twins and dead-stack burns. Anchors: CAVP 186-4 (SigVer/SigGen/KeyPair/PKV,
  CDH), Wycheproof (ECDSA SHA-384 and SHA-512, DER and P1363; ECDH), RFC 6979 A.2.6, OpenSSL 3.5.5
  oracle (24 keys), std as a second implementation. ctgrind mul/keygen/sign/ecdh 0 in-file (the
  first run caught the comb's `addMixed` identity select lowered to a branch on the secret table
  point — the comb now uses `addMixedComplete`); fuzz 200,000 runs clean; stack probe green.
  Audit: review (field chains against square-and-multiply, Montgomery bounds T < m·R and the
  2^449 accumulator that needs an eighth asm register, the asm's CF/OF chain closes, comb CT,
  RFC 6979 bits2int for > 48-byte digests, strict DER) + mutation schemata, 120 mutants incl. six
  asm variants: first pass 80 killed; 12 tests added (`audit_test.zig`, `mont.zig`, `scalar.zig`)
  → 99/120 (one a hang), 21 equivalent: identity/zero refusals that the product's identity check repeats with
  the same error (40, 42, 48, 50), digit recoding at x = 16 and NAF parity (65, 66, 80, 82), the
  flip at exact limb ties (64), identity shortcuts that end at the same Z = 0 (73, 75, 90, 91),
  the comb fast path for G (85), DER length-byte checks the remaining checks repeat (120, 126),
  RFC 6979 retry paths of probability ≤ 2^−190 (109, 110, 111, 132), r = 0 (needs a discrete
  log, 113). Speed vs OpenSSL 3.5.5: ECDH 0.95–1.00×,
  sign 0.61×, verify 0.83×.
