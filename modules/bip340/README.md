# bip340

BIP340 Schnorr signatures over secp256k1 — the signature scheme behind
Bitcoin Taproot, and the foundational primitive a future Taproot-tweak /
Musig2 / adaptor-signature stack in this collection would build on.

**Status: complete — sign, verify, and batch verification implemented and
KAT-validated against all 19 official BIP340 test vectors** (the 8
secret-key vectors sign to the exact published signature bytes; all 10
deliberately-invalid verification vectors are rejected). See `SPEC.md` for
the design and threat model.

| File | Contents |
|---|---|
| `hash.zig` | `taggedHash`/`taggedHasher` (BIP340's `SHA256(SHA256(tag)‖SHA256(tag)‖msg)`, all three domain tags, comptime-midstate-optimized) |
| `root.zig` | `XOnlyPublicKey` (parse + `lift_x`), `SecretKey`/`PublicKey`/`KeyPair` (even-y normalization + derivation), `Signature` (parse/serialize + canonical range checks), `sign`, `verify`, `verifyBatch` |
| `kat_vectors.zig` | The 19 official BIP340 test vectors, embedded |
| `kat_test.zig` | Full KAT assertions (codecs, derivation, sign round-trip, verify accept/reject) + batch-verification correctness tests |

## Import

```zig
const bip340 = @import("bip340");
```

## API surface

**Keys:**

```zig
const sk = try bip340.SecretKey.fromBytes(sk_bytes); // rejects 0 and >= n
const kp = try bip340.KeyPair.fromSecretKey(sk); // even-y-normalized secret + x-only pubkey
const pk = try bip340.PublicKey.fromSecretKey(sk); // just the x-only pubkey half
```

**x-only public keys** (32 bytes, e.g. parsed off the wire):

```zig
const xonly = try bip340.XOnlyPublicKey.fromBytes(pubkey_bytes); // rejects non-canonical x / off-curve x
const point = try xonly.lift(); // BIP340 lift_x: the even-y secp256k1 point
```

**Signatures** (64 bytes, `r ‖ s`):

```zig
const sig = try bip340.Signature.fromBytes(sig_bytes); // rejects r >= p, s >= n
const bytes = sig.toBytes();
```

**Signing / verifying:**

```zig
const sig_bytes = try bip340.sign(sk, msg, aux_rand, io); // includes the spec-mandated self-verify
const ok = bip340.verify(xonly, msg, sig); // never panics/errors: false on every failure path
const batch_ok = bip340.verifyBatch(&.{.{ .pubkey = xonly, .msg = msg, .sig = sig }}, io);
```

`aux_rand` is BIP340's auxiliary randomness — fresh CSPRNG bytes in
production (defense-in-depth against side-channel/fault attacks; the
signature stays valid and deterministic for any fixed value, which is what
the KAT vectors rely on). `verifyBatch` draws its random blinding scalars
from `io`.

**Tagged hashing** (exposed directly — useful standalone for anything else
building on the same domain-separation convention):

```zig
const e = bip340.taggedHash(bip340.hash.challenge_tag, r_x ++ p_x ++ msg);
```

## Verify

```
zig build test-bip340                       # Debug
zig build test-bip340 -Doptimize=ReleaseFast # ReleaseFast
zig fmt --check modules/bip340/
```

All 19 official BIP340 test vectors (`src/kat_vectors.zig`) pass: x-only
pubkey parse/lift on all 19 pubkeys, signature range-check parsing on all
19 signatures, key derivation on the 8 secret-key vectors, byte-exact sign
round-trip on those same 8, and the full verify accept/reject matrix (1
verify-only TRUE + 10 FALSE vectors). Batch verification is cross-checked
against single verification (no official batch vectors exist).

Provenance: see [NOTICE](NOTICE).
