# taproot

BIP341 Taproot key-path output-key tweaking — the small, security-critical
step that turns an internal BIP340 key into the key a Taproot output
actually pays to. Depends on the sibling [`bip340`](../bip340/) module for
`XOnlyPublicKey`/`SecretKey` and the tagged-hash machinery.

**Status: complete.** The `"TapTweak"` tagged hash, the `TweakedPublicKey`
codec, AND both crypto cores — `tweakPublicKey`/`tweakSecretKey` — are real
and pass against all 7 rows of the official BIP341
`wallet-test-vectors.json` (tweak hash, tweaked pubkey + parity, tweaked
privkey, each byte-exact), plus a sign→verify round-trip through `bip340`
with the tweaked key pair. See `SPEC.md` for the design and threat model.

| File | Contents |
|---|---|
| `root.zig` | `tapTweakHash` (BIP341's `"TapTweak"` tagged hash), `TweakedPublicKey` (x-only output key + parity, codec), `TweakError`/`TweakResult`, and the crypto cores `tweakPublicKey`/`tweakSecretKey` |
| `kat_vectors.zig` | 7 rows from the official BIP341 wallet test vectors (public-key tweak + secret-key tweak paired by `internalPubkey`) |
| `kat_test.zig` | KAT assertions against all 7 rows: `tapTweakHash`, `tweakPublicKey` (pubkey + parity + tweak), `tweakSecretKey` (privkey), and a tweaked-key `bip340.sign`→`verify` round-trip |

## Import

```zig
const taproot = @import("taproot");
const bip340 = @import("bip340");
```

## API surface

**The tagged hash** (usable standalone — e.g. for an independent
control-block/tweak verifier that doesn't need the full point arithmetic):

```zig
const t_hash = taproot.tapTweakHash(internal_pubkey_x, merkle_root); // merkle_root: ?[32]u8
```

`merkle_root = null` means "key-path-only, no script tree at all" — distinct
from a script tree whose root happens to be all-zero (which would append 32
zero bytes instead of nothing).

**Tweaked public key** (produced by `tweakPublicKey`):

```zig
pub const TweakedPublicKey = struct {
    x: [32]u8,
    parity: u1, // 0 = even y, 1 = odd y
};
```

**The two crypto cores** (see `root.zig`'s doc comments for the exact
BIP341 algorithm each implements):

```zig
const result = try taproot.tweakPublicKey(internal_xonly, merkle_root); // -> TweakResult{ .output, .tweak }
const q_bytes = try taproot.tweakSecretKey(internal_sk, merkle_root); // -> [32]u8, the tweaked signing scalar
```

A caller signs the output key's messages with `q_bytes` via
`bip340.sign`/`bip340.verify` against `result.output.asXOnly()` — this
module owns the tweak only, not signing.

## Verify

```
zig build test-taproot                       # Debug
zig build test-taproot -Doptimize=ReleaseFast # ReleaseFast
zig fmt --check modules/taproot/
```

All 7 rows of the official BIP341 `wallet-test-vectors.json` pass end to
end — `tapTweakHash`, `tweakPublicKey` (tweaked pubkey + parity + tweak),
and `tweakSecretKey` (tweaked privkey) each byte-exact (both the one
key-path-only row and the six script-tree rows), plus a per-row
`bip340.sign`→`verify` round-trip with the tweaked key pair. 13/13 tests,
zero skips, Debug and ReleaseFast.

Provenance: see [NOTICE](NOTICE).
