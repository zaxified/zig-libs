# slhdsa

SLH-DSA (FIPS 205 — the standardized SPHINCS+): stateless hash-based digital
signatures, pure Zig over `std.crypto`'s SHA-256. Post-quantum, conservative
security (hash functions only, no lattices), large signatures.

**Status: SLH-DSA-SHA2-128f implemented end-to-end + NIST-KAT-verified.**
Exactly ONE parameter set is wired: **SLH-DSA-SHA2-128f** (security
category 1, "fast" — pk 32 B, sk 64 B, signature 17 088 B). Every FIPS 205
layer is real: the §11.2 SHA2 tweakable hashes/PRFs (F/H/T_l/PRF via a
shared SHA-256 midstate, H_msg via MGF1-SHA-256, PRF_msg via
HMAC-SHA-256, compressed ADRS), WOTS+ (§5), XMSS Merkle trees (§6), the
22-layer hypertree (§7), FORS (§8), `slh_keygen/sign/verify_internal`
(§9/§10.1) and the **pure** external interface with context strings
(§10.2). Byte-exact against the official **NIST ACVP FIPS 205 vectors**
(keyGen; deterministic-internal, hedged-internal, and pure-with-context
sigGen) — provenance per test case in `src/kat_vectors.zig`.

**Not implemented:** the other eleven parameter sets (128s, 192s/f, 256s/f
and all SHAKE variants — `params.Params` carries every FIPS 205 knob, so
adding one is a table row + the missing hash instantiation in
`engine.zig`, which today compile-errors on anything but SHA2/n=16) and
the HashSLH-DSA pre-hash variants (§10.2.2). Signing is not constant-time
hardened. Key generation takes caller-supplied seed bytes — bring your own
CSPRNG.

- **Model after:** FIPS 205 (August 2024), clean-room from the standard;
  NIST ACVP `SLH-DSA-{keyGen,sigGen}-FIPS205` JSON vectors as the KAT
  oracle. Fills a real std gap: Zig 0.16 `std.crypto` ships ML-DSA and
  ML-KEM but no SLH-DSA.
- **Deps:** none (std only — `std.crypto.hash.sha2.Sha256`,
  `std.crypto.auth.hmac.sha2.HmacSha256`).

## Layout

| File | Role | Status |
|------|------|--------|
| `src/params.zig` | `Params` struct (all FIPS 205 Table 2 knobs + derived lengths) + `sha2_128f` | real, tested |
| `src/address.zig` | §4.2 ADRS (32-byte hash addresses) + SHA2 compressed form | real, tested |
| `src/engine.zig` | generic `SlhDsa(Params)`: SHA2 hashes, WOTS+, XMSS, hypertree, FORS, keygen/sign/verify | real, KAT-verified |
| `src/root.zig` | `meta`, re-exports, `SlhDsaSha2_128f` instantiation | real, tested |
| `src/kat_vectors.zig` / `src/kat_test.zig` | NIST ACVP vectors + the KAT/tamper battery | test-only |

## Usage

```zig
const slhdsa = @import("slhdsa");
const Scheme = slhdsa.SlhDsaSha2_128f;

// Key generation — supply 48 fresh CSPRNG bytes (SK.seed‖SK.prf‖PK.seed):
var seed: [48]u8 = undefined;
my_csprng.bytes(&seed);
const kp = Scheme.keyGen(seed);

// Sign (pure variant, empty context, deterministic). Pass 16 fresh random
// bytes instead of `null` for FIPS 205's recommended hedged signing:
var sig: [Scheme.signature_length]u8 = undefined;
try Scheme.sign(&sig, message, kp.sk, "", null);

// Verify — returns bool; malformed input is false, never a panic:
const ok = Scheme.verify(&sig, message, kp.pk, "");

// Serialization (FIPS 205 §9.1 byte layouts):
const pk_bytes: [32]u8 = kp.pk.toBytes();
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
