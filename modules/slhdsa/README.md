# slhdsa

SLH-DSA (FIPS 205 — the standardized SPHINCS+): stateless hash-based digital
signatures, pure Zig over `std.crypto`'s SHA-2 and SHAKE256. Post-quantum,
conservative security (hash functions only, no lattices), large signatures.

**Status: all twelve FIPS 205 parameter sets implemented end-to-end, each
NIST-KAT-verified** — SLH-DSA-SHA2-{128,192,256}{s,f} and
SLH-DSA-SHAKE-{128,192,256}{s,f}. Every FIPS 205 layer is real: both §11
hash instantiations — SHAKE256 (§11.1: F/H/T_l/PRF/H_msg/PRF_msg all
SHAKE256, full 32-byte ADRS) and SHA-2 (§11.2: compressed 22-byte ADRS,
shared midstate; categories 3/5 keep SHA-256 for F/PRF but use SHA-512 for
H/T_l, MGF1-SHA-512 for H_msg and HMAC-SHA-512 for PRF_msg) — WOTS+ (§5),
XMSS Merkle trees (§6), the hypertree (§7), FORS (§8),
`slh_keygen/sign/verify_internal` (§9/§10.1) and the **pure** external
interface with context strings (§10.2). Byte-exact against the official
**NIST ACVP FIPS 205 vectors**: one keyGen and one deterministic-internal
sigGen case per parameter set, plus hedged-internal and pure-with-context
cases for SHA2-128f — provenance per test case in `src/kat_vectors.zig`.

| Set (SHA2 / SHAKE) | Category | pk | sk | signature |
|--------------------|----------|-----|-----|-----------|
| 128s | 1 | 32 B | 64 B | 7 856 B |
| 128f | 1 | 32 B | 64 B | 17 088 B |
| 192s | 3 | 48 B | 96 B | 16 224 B |
| 192f | 3 | 48 B | 96 B | 35 664 B |
| 256s | 5 | 64 B | 128 B | 29 792 B |
| 256f | 5 | 64 B | 128 B | 49 856 B |

**Not implemented:** the HashSLH-DSA pre-hash variants (§10.2.2). Signing is
not constant-time hardened. Key generation takes caller-supplied seed
bytes — bring your own CSPRNG.

- **Model after:** FIPS 205 (August 2024), clean-room from the standard;
  NIST ACVP `SLH-DSA-{keyGen,sigGen}-FIPS205` JSON vectors as the KAT
  oracle. Fills a real std gap: Zig 0.16 `std.crypto` ships ML-DSA and
  ML-KEM but no SLH-DSA.
- **Deps:** none (std only — `std.crypto.hash.sha2.{Sha256,Sha512}`,
  `std.crypto.auth.hmac.sha2.{HmacSha256,HmacSha512}`,
  `std.crypto.hash.sha3.Shake256`).

## Layout

| File | Role | Status |
|------|------|--------|
| `src/params.zig` | `Params` struct + all twelve FIPS 205 Table 2 rows | real, tested |
| `src/address.zig` | §4.2 ADRS (32-byte hash addresses) + SHA2 compressed form | real, tested |
| `src/engine.zig` | generic `SlhDsa(Params)`: §11.1 SHAKE + §11.2 SHA2 hashes, WOTS+, XMSS, hypertree, FORS, keygen/sign/verify | real, KAT-verified |
| `src/root.zig` | `meta`, re-exports, the twelve ready-to-use instantiations | real, tested |
| `src/kat_vectors.zig` / `src/kat_test.zig` | NIST ACVP vectors (all 12 sets) + the KAT/tamper battery | test-only |

## Usage

```zig
const slhdsa = @import("slhdsa");
// Pick any of the twelve: SlhDsaSha2_{128,192,256}{s,f},
// SlhDsaShake_{128,192,256}{s,f} — or SlhDsa(params.<set>) generically.
const Scheme = slhdsa.SlhDsaSha2_128f;

// Key generation — supply 3n fresh CSPRNG bytes (SK.seed‖SK.prf‖PK.seed):
var seed: [3 * Scheme.n]u8 = undefined;
my_csprng.bytes(&seed);
const kp = Scheme.keyGen(seed);

// Sign (pure variant, empty context, deterministic). Pass n fresh random
// bytes instead of `null` for FIPS 205's recommended hedged signing:
var sig: [Scheme.signature_length]u8 = undefined;
try Scheme.sign(&sig, message, kp.sk, "", null);

// Verify — returns bool; malformed input is false, never a panic:
const ok = Scheme.verify(&sig, message, kp.pk, "");

// Serialization (FIPS 205 §9.1 byte layouts):
const pk_bytes = kp.pk.toBytes(); // [2n]u8
const pk = Scheme.PublicKey.fromBytes(pk_bytes);
const sk = Scheme.SecretKey.fromBytes(kp.sk.toBytes());

// Raw-message internal interface (what ACVP calls "internal") — for
// protocol plumbing that does its own domain separation:
Scheme.signInternal(&sig, message, kp.sk, null);
_ = Scheme.verifyInternal(&sig, message, kp.pk);
```

Verify: `zig build test-slhdsa` (Debug and `-Doptimize=ReleaseFast`).

## Provenance

Clean-room implementation from FIPS 205, a public NIST standard — no
third-party source ported and no third-party implementation studied, so no
`NOTICE` entry (see the NOTICE policy); the spec citation lives in
[SPEC.md](./SPEC.md). The NIST ACVP JSON files are used purely as a
known-answer test oracle.
