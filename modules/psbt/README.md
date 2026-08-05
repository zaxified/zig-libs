# psbt

BIP174 Partially Signed Bitcoin Transaction (PSBT) v0 — binary (de)serialization, the Combiner
role, and (via the sibling `bitcoinscript` Script interpreter) the Input Finalizer and Transaction
Extractor roles, built on `bitcointx` for the embedded unsigned transaction / UTXO tx bodies. Parses
untrusted PSBT bytes fail-closed. See `SPEC.md` for the full design, threat model, and what's still
deliberately deferred — corrected here from an earlier version of this line that said Finalizer/
Extractor were also deferred: only the **Signer** role remains unimplemented (it needs private-key
custody and signing policy this module has no opinion about).

Provenance: the wire-format codec (`parse`/`serialize`/`combine`/`finalize`/`extract`) is clean-room
from the published BIP174 spec (`bitcoin/bips`), no third-party source ported. The official BIP174
test-vector BYTES this module vendors (`kat_vectors.zig`) are a separate matter — BIP174 itself is
BSD-2-Clause, which requires attribution on redistribution of its content, including its own worked
examples — see `NOTICE` for that attribution (corrected here: an earlier version of this line said
no `NOTICE` entry was needed at all, which conflated "clean-room codec" with "vendored spec-author
test data"). This module ALSO vendors conformance vectors from Bitcoin Core's `test/functional/data/
rpc_psbt.json` (`core_kat_vectors.zig`, MIT) — a second, independent source; `NOTICE` covers both.

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

## Finalize inputs, then extract the network-ready transaction

```zig
// Mutates ps.inputs in place; one ?InputFinalizeError per input, null = finalized (or already was).
const results = try psbt.finalize(allocator, ps);

// Requires every input finalized (error.InputNotFinalized otherwise).
var tx = try psbt.extract(allocator, ps);
defer tx.deinit(allocator);
const raw = try bitcointx.serialize(allocator, tx);
```

`finalize` handles P2PKH, native/P2SH-wrapped P2WPKH, bare/P2SH/P2WSH/P2SH-P2WSH multisig, and P2TR
key-path — see `finalize.zig`'s module doc comment for the exact scope cut (non-standard/timelocked/
tapscript spends are `error.NonStandardScript`, never silently mis-assembled) and for the
allocator/ownership contract (an arena is assumed). The **Signer** role — producing the
`PARTIAL_SIG`/`TAP_KEY_SIG` records `finalize` consumes — is not implemented; that needs private-key
custody and signing policy this module has no opinion about.

## Verify

```
zig build test-psbt --summary all
```

Byte-exact against BIP174's own published test vectors: all 20 official invalid PSBTs (rejected,
19 with a specific pinned error), 8 of 10 official valid PSBTs (round-trip), the BIP's own worked
Combiner example, and the BIP's own worked Finalizer/Extractor example (a bare P2SH 2-of-2 multisig
input plus a P2SH-P2WSH 2-of-2 multisig input: `finalize` on the pre-finalize PSBT and `extract` on
the finalized PSBT both reproduce the BIP's own published bytes exactly) — see `SPEC.md`
"Verification" for the full story, including the 2 valid vectors this module can't accept (a
`bitcointx`-inherited wire-format ambiguity, not a psbt bug).

Also checked against Bitcoin Core's own `test/functional/data/rpc_psbt.json` (a separate external
oracle, `core_kat_vectors.zig`/`core_kat_test.zig`) — this is where a real gap was found and fixed:
a present `PSBT_GLOBAL_VERSION` is now required to be `0` (BIP174 §"Version 0"), which `parse`
previously didn't check. Core's own `finalizer`/`extractor` vectors turned out to be byte-identical
to BIP174's worked example above (no new spend shape), so neither BIP174 nor Core's JSON reaches
native P2WPKH or native P2WSH multisig — see `SPEC.md` for the full accounting, including which of
Core's vectors are BIP370/BIP371/MuSig2 content this module deliberately doesn't validate.

Both of those two remaining shapes are now closed too, by capturing against a real Bitcoin Core
regtest node instead (`regtest_kat_vectors.zig`/`regtest_kat_test.zig`, `zig build test-psbt`):
native P2WPKH (captured 2026-08-02) and native P2WSH 2-of-3 multisig (captured 2026-08-05, the LAST
spend shape in this module that had no outside oracle at all — `finalize`/`extract` on the pre-
finalize PSBT reproduce Core's own finalized-PSBT and extracted-transaction bytes exactly, and the
extracted transaction was independently confirmed acceptable by `testmempoolaccept` on the node
that produced it). Every spend shape `finalize`/`extract` supports is now anchored against an
outside oracle, not just this module's own round-trip.
