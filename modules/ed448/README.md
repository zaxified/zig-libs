# ed448

Ed448 (EdDSA over edwards448, RFC 8032 §5.2) and X448 (the curve448
Montgomery Diffie-Hellman function, RFC 7748 §4.2/§5) — the "Goldilocks"
448-bit curve family. `std.crypto` ships `Edwards25519`/`Curve25519` (the
25519 family) and the NIST P-curves/secp256k1, but no 448-bit curve at
all — this module is genuine greenfield field + curve arithmetic, not an
extension of anything std already has.

Consumers: applications, CAs, or TLS stacks that want the ~224-bit
security level RFC 8032/RFC 7748 both standardize as Ed25519/X25519's
sibling one level up.

**Status: implemented.** Both the byte-level/wire layer (field/scalar/
point/signature encoding, RFC-mandated scalar clamping, the SHAKE256
`dom4` domain-separation framing, the sign/verify step structure) and
the full number-theory core (`Fp448` field arithmetic with its
Goldilocks/Solinas reduction, the RFC 7748 Montgomery ladder, edwards448
point addition/doubling/scalar multiplication, mod-`L` scalar
arithmetic) are real, constant-time on every secret-input path, and
validated byte-exact against the official RFC test vectors. See
[SPEC.md](SPEC.md) for the design and constant-time posture.

| File | Contents |
|---|---|
| `field.zig` | `Fp448` (`p = 2^448 - 2^224 - 1`), 8×56-bit-limb representation with the Goldilocks/Solinas reduction (`2^448 ≡ 2^224 + 1`) |
| `x448.zig` | RFC 7748 X448: scalar clamping + the constant-time Montgomery ladder |
| `ed448.zig` | RFC 8032 Ed448/Ed448ph: `dom4` framing, wire codecs, `Point` curve arithmetic (complete Edwards formulas), sign/verify |
| `scalar.zig` | Arithmetic mod `L` (the edwards448 subgroup order) for Ed448 signing — constant-time binary reduction |
| `kat_vectors.zig` | Official RFC 7748 §5.2/§6.2 (X448) and RFC 8032 §7.4/§7.5 (Ed448/Ed448ph) test vectors |
| `kat_test.zig` | Byte-exact KAT assertions against `kat_vectors.zig` through the public API |

## Import

```zig
const ed448 = @import("ed448");
```

## X448 (Diffie-Hellman)

```zig
const x448 = ed448.x448;

const kp = x448.KeyPair.generate(io);
const shared = try x448.scalarmult(kp.secret_key, peer_public_key);
```

## Ed448 (signatures)

```zig
const kp = ed448.ed448.KeyPair.create(seed); // 57-byte seed
const sig = try ed448.ed448.sign(kp, msg, ctx); // ctx: []const u8, up to 255 bytes
try ed448.ed448.verify(sig, msg, ctx, kp.public_key);

// Ed448ph (prehashed) variant:
const sig_ph = try ed448.ed448.signPh(kp, msg, ctx);
try ed448.ed448.verifyPh(sig_ph, msg, ctx, kp.public_key);
```

## Import graph

```
ed448 → field (Fp448) → std.crypto.sha3 (Shake256, via ed448.zig)
      → x448 (RFC 7748) → field
      → ed448 (RFC 8032) → field, scalar
      → scalar (mod L)   → std only
```

No sibling zig-libs module dependencies; pure `std` (`std.crypto.hash.
sha3.Shake256`, `std.Io` for randomness).

## Verify

```
zig build test-ed448                          # Debug — all green
zig build -Doptimize=ReleaseFast test-ed448   # ReleaseFast — all green
zig fmt --check modules/ed448/
```

All 48 tests pass in both modes. `kat_test.zig` asserts byte-exact
output against the official RFC 7748 §5.2/§6.2 (X448: both single-vector
tests, the 1-iteration test, and the full Alice/Bob Diffie-Hellman
example) and RFC 8032 §7.4/§7.5 (Ed448: the empty-message, 1-octet,
1-octet-with-context, and 11-octet vectors; Ed448ph: the "TEST abc"
vector) test vectors, plus context-binding, tamper-reject, and
Ed448-vs-Ed448ph cross-rejection property tests; the per-file suites add
field/scalar/point self-checks (inverse, sqrt, encode/decode
round-trips, non-canonical rejects).

Provenance: see [NOTICE](NOTICE).
