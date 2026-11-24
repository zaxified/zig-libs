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
| `scalar.zig` | Arithmetic mod `L` (the edwards448 subgroup order) for Ed448 signing — constant-time folding reduction |
| `kat_vectors.zig` | Official RFC 7748 §5.2/§6.2 (X448) and RFC 8032 §7.4/§7.5 (Ed448/Ed448ph) test vectors |
| `rfc8032_vectors.zig`, `wycheproof_vectors.zig` | Every RFC 8032 §7.4/§7.5 vector, and the Wycheproof `ed448_test.json` cases, as data |
| `kat_test.zig` | Byte-exact KAT assertions against the vector files through the public API |

## Import

```zig
const ed448 = @import("ed448");
```

## X448 (Diffie-Hellman)

```zig
const x448 = ed448.x448;

var kp: x448.KeyPair = undefined;
x448.KeyPair.generate(&kp, io); // secret half lands in `kp`, no temporary
var shared: [x448.shared_length]u8 = undefined;
try x448.scalarmult(&shared, &kp.secret_key, peer_public_key);
```

An Ed448 key converts to an X448 one (RFC 7748 §4.2's 4-isogeny, libdecaf's `convert_private_key_to_x448`):

```zig
var xkp: x448.KeyPair = undefined;
try x448.KeyPair.fromEd448(&xkp, &ed_kp); // ed_kp: ed448.ed448.KeyPair; error.IdentityElement for x = 0
const xpub = try x448.publicKeyFromEd448(ed_kp.public_key.bytes);
```

## Ed448 (signatures)

```zig
const kp = ed448.ed448.KeyPair.create(&seed); // *const [57]u8 seed
const sig = try ed448.ed448.sign(&kp, msg, ctx); // ctx: []const u8, up to 255 bytes
try ed448.ed448.verify(sig, msg, ctx, kp.public_key);

// Ed448ph (prehashed) variant:
const sig_ph = try ed448.ed448.signPh(&kp, msg, ctx);
try ed448.ed448.verifyPh(sig_ph, msg, ctx, kp.public_key);
```

## Import graph

```
ed448 → field (Fp448) → std.crypto.sha3 (Shake256, via ed448.zig)
      → x448 (RFC 7748) → field
      → ed448 (RFC 8032) → field, scalar
      → scalar (mod L)   → std only
```

Sole sibling zig-libs dependency: `entropy` (the fail-closed seed draw behind
the two `KeyPair.generate` functions); otherwise pure `std` (`std.crypto.hash.
sha3.Shake256`, `std.Io`).

## Verify

```
zig build test-ed448                          # Debug — all green
zig build -Doptimize=ReleaseFast test-ed448   # ReleaseFast — all green
zig fmt --check modules/ed448/
```

`kat_test.zig` asserts byte-exact output against the official RFC 7748
§5.2/§6.2 (X448: both single-vector tests, the 1-iteration test, and the
full Alice/Bob Diffie-Hellman example) and every RFC 8032 §7.4 Ed448 and
§7.5 Ed448ph vector, plus context-binding, tamper-reject, and
Ed448-vs-Ed448ph cross-rejection property tests, and holds `verify` to the
Wycheproof `ed448_test.json` cases; the per-file suites add
field/scalar/point self-checks (inverse, sqrt, encode/decode
round-trips, non-canonical rejects).

## Hash to curve

`ed448.h2c.hashToCurve(msg, dst)` / `encodeToCurve(msg, dst)`: RFC 9380's `edwards448_XOF:SHAKE256_ELL2_RO_` /
`_NU_`, a `Point` (the stages `hashToField`, `mapToCurve`, `expandMessageXof` are public too). Anchored by RFC 9380
Appendix J.7.

## Not provided

Batch verification and key blinding, a cofactorless `verify`, and the all-zero
shared-secret check in `x448.scalarmult` (the caller's). See SPEC *What is deliberately not done* and
*Backlog / deferred*.

Provenance: see [NOTICE](NOTICE).
