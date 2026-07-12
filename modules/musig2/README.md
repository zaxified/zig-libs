# musig2

MuSig2 multi-signature scheme over secp256k1 (BIP327): an n-of-n
multi-signature protocol whose two-round signing produces an ordinary
BIP340 Schnorr signature — any BIP340 verifier (including the sibling
`bip340` module's own `verify`) accepts the aggregate signature with no
idea it was produced by more than one signer. Builds directly on `bip340`
for tagged hashing, x-only public-key handling, and the final challenge
hash.

**Status: complete (v1, untweaked).** The full BIP327 core signing flow is
implemented and byte-exact against the official BIP327 test vectors: key
aggregation (with the rogue-key-resistant coefficient rule), nonce
generation/aggregation (including the legal point-at-infinity encoding),
the session challenge/nonce values (with the substitute-`G`-for-infinity
rule), partial signing (with the spec's mandatory self-verify), partial
verification, and final aggregation — whose 64-byte result verifies under
plain `bip340.verify`. Tweaking (`ApplyTweak`) and `DeterministicSign` are
out of v1 scope. See `SPEC.md` for the design, threat model (the
parity/`g`/`gacc` sign-flip chain), and the implementation done-record.

| File | Contents |
|---|---|
| `root.zig` | Every public type (`PlainPublicKey`, `PubNonce`, `AggNonce`, `SecNonce`, `PartialSignature`, `KeyAggContext`, `SessionContext`/`SessionValues`) + the full API surface (`keySort`, `nonceGen`, `keyAgg`, `nonceAgg`, `getSessionValues`, `sign`, `partialSigVerify`, `partialSigAgg`) |
| `kat_vectors.zig` | Six of the eight official BIP327 vector files, embedded |
| `kat_test.zig` | KAT assertions (every embedded official vector) + a 3-signer end-to-end protocol test ending in `bip340.verify` |

## Import

```zig
const musig2 = @import("musig2");
const bip340 = @import("bip340");
```

## API surface

**Individual public keys** (33-byte SEC1-compressed — NOT the same shape
as `bip340.XOnlyPublicKey`):

```zig
const pk = try musig2.PlainPublicKey.fromBytes(pk_bytes); // rejects bad prefix / x >= p / off-curve x
const point = try pk.point(); // the real secp256k1 point (parity per the prefix byte)
```

**Key sorting** (`KeySort`):

```zig
musig2.keySort(pubkey_slice); // sorts in place, lexicographic
```

**Key aggregation** (`KeyAgg` — validates every pubkey, rejects an
infinite aggregate):

```zig
const ctx = try musig2.keyAgg(pubkeys); // KeyAggContext{ q, gacc, tacc }
const aggpk_xonly = ctx.getXonlyPubkey(); // [32]u8, verifiable by bip340.verify
```

**Nonce generation** (`NonceGen`):

```zig
const result = try musig2.nonceGen(sk, pk_bytes, aggpk_xonly, msg, extra_in, rand_prime, io);
// result.secnonce: musig2.SecNonce  (LOCAL — never send over the wire; single-use, see SPEC.md)
// result.pubnonce: musig2.PubNonce  (send to co-signers)
```

**Nonce aggregation** (`NonceAgg` — validates every pubnonce; a cancelled
sum is legally encoded as the point at infinity, not rejected):

```zig
const aggnonce = try musig2.nonceAgg(pubnonces); // musig2.AggNonce
```

**Signing** (`Sign` — secnonce range + signer-pubkey membership checks,
then the partial-signature formula with the spec's mandatory self-verify):

```zig
const ctx = musig2.SessionContext{ .aggnonce = aggnonce, .pubkeys = pubkeys, .msg = msg };
const psig = try musig2.sign(result.secnonce, sk, ctx); // musig2.PartialSignature
```

**Partial signature verification** (`PartialSigVerify` — per-pubnonce/
per-pubkey validation + the `s·G == Re* + e·a·g'·P` equation check):

```zig
try musig2.partialSigVerify(psig, pubnonces, pubkeys, msg, signer_index);
```

**Partial signature aggregation** (`PartialSigAgg` — per-psig range check,
then the final aggregation):

```zig
const sig64 = try musig2.partialSigAgg(psigs, ctx); // [64]u8 — a plain BIP340 signature
const ok = bip340.verify(xonly_aggpk, msg, try bip340.Signature.fromBytes(sig64));
```

## Import graph

```
musig2 → bip340 → std.crypto.ecc.Secp256k1 / std.crypto.hash.sha2.Sha256
```

## Verify

```
zig build test-musig2                       # Debug
zig build test-musig2 -Doptimize=ReleaseFast # ReleaseFast
zig fmt --check modules/musig2/
```

21 pass / 0 skip (21 total) — every embedded official vector asserts
byte-exact (valid AND "invalid contribution" cases across all six
embedded vector files; the only unasserted vectors are `sig_agg`'s two
TWEAKED cases, out of v1 scope), plus a 3-signer end-to-end protocol
test ending in a plain `bip340.verify` accept.

Provenance: see [NOTICE](NOTICE).
