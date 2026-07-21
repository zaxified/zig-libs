# psbt

BIP174 Partially Signed Bitcoin Transaction (PSBT) v0 — binary (de)serialization plus the
Combiner role, built on `bitcointx` for the embedded unsigned transaction / UTXO tx bodies. Parses
untrusted PSBT bytes fail-closed. See `SPEC.md` for the full design, threat model, and what's
deliberately deferred (Signer/Finalizer/Extractor — they need a Bitcoin Script interpreter this
repo doesn't have yet).

Provenance: clean-room from the published BIP174 spec (`bitcoin/bips`), no third-party source
ported — see `NOTICE`'s doc-ownership rule (`CONVENTIONS.md` §5) for why that means no NOTICE entry.

## Import

```zig
const psbt = @import("psbt");
```

## Parse, inspect, serialize

```zig
var p = try psbt.parse(allocator, raw_psbt_bytes); // fail-closed on any malformed/hostile input
defer p.deinit(allocator);

var utx = try p.unsignedTx(allocator); // bitcointx.Transaction, caller-owned
defer utx.deinit(allocator);

for (p.inputs, 0..) |input, i| {
    if (try psbt.inputWitnessUtxo(input)) |utxo| {
        std.debug.print("input {d}: {d} sats\n", .{ i, utxo.value });
    }
    for (input.records) |r| {
        if (r.keytype == psbt.input_key.PARTIAL_SIG) {
            // r.keydata = pubkey, r.value = signature
        }
    }
}

const reser = try psbt.serialize(allocator, p); // byte-exact round-trip of a parsed PSBT
defer allocator.free(reser);
```

## Typed accessors for the known field types

| Field | Accessor |
|---|---|
| `PSBT_GLOBAL_UNSIGNED_TX` | `Psbt.unsignedTx(allocator) -> bitcointx.Transaction` (owned) |
| `PSBT_GLOBAL_VERSION` | `Psbt.version() -> ?u32` |
| `PSBT_GLOBAL_XPUB` | `globalXpubDerivation(map, xpub) -> ?Bip32Path` |
| `PSBT_IN_NON_WITNESS_UTXO` | `inputNonWitnessUtxo(map, allocator) -> !?bitcointx.Transaction` (owned) |
| `PSBT_IN_WITNESS_UTXO` | `inputWitnessUtxo(map) -> !?bitcointx.TxOut` |
| `PSBT_IN_SIGHASH_TYPE` | `inputSighashType(map) -> ?u32` |
| `PSBT_IN_BIP32_DERIVATION` | `inputBip32Derivation(map, pubkey) -> ?Bip32Path` |
| `PSBT_OUT_BIP32_DERIVATION` | `outputBip32Derivation(map, pubkey) -> ?Bip32Path` |

Every other known field (`PARTIAL_SIG`, `REDEEM_SCRIPT`, `WITNESS_SCRIPT`, `FINAL_SCRIPTSIG`,
`FINAL_SCRIPTWITNESS`) and every unrecognized/proprietary key type is available directly via
`Map.records` (`Record{ keytype, keydata, value }`, all borrowed slices) — `Map.find(keytype)` for
"no key data" singleton fields, `Map.findKeyed(keytype, keydata)` for pubkey/xpub-keyed fields.

## Combine two PSBTs for the same transaction

```zig
var combined = try psbt.combine(allocator, psbt_a, psbt_b); // error.DifferentTransactions if they don't match
defer combined.deinit(allocator);
```

## Verify

```
zig build test-psbt --summary all
```

Byte-exact against BIP174's own published test vectors: all 20 official invalid PSBTs (rejected,
19 with a specific pinned error), 8 of 10 official valid PSBTs (round-trip), and the BIP's own
worked Combiner example — see `SPEC.md` "Verification" for the full story, including the 2 valid
vectors this module can't accept (a `bitcointx`-inherited wire-format ambiguity, not a psbt bug).
