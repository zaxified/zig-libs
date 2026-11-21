# psbt

BIP174 Partially Signed Bitcoin Transaction (PSBT) v0 and BIP370 v2 — binary (de)serialization, the Creator and
Updater roles (`fromUnsignedTx`, typed `set*` functions), the v2 Constructor (`psbt.v2`), BIP371 taproot fields, Base64 I/O, the Combiner
role, and (via the sibling `bitcoinscript` Script interpreter) the Input Finalizer and Transaction
Extractor roles, built on `bitcointx` for the embedded unsigned transaction / UTXO tx bodies. Parses
untrusted PSBT bytes fail-closed. See `SPEC.md` for the full design, threat model, and what is not
provided: only the **Signer** role is unimplemented (it needs private-key custody and signing policy
this module has no opinion about).

Provenance: the wire-format codec (`parse`/`serialize`/`combine`/`finalize`/`extract`) is clean-room
from the published BIP174 spec (`bitcoin/bips`), no third-party source ported. The official BIP174
test-vector BYTES this module vendors (`kat_vectors.zig`) are a separate matter — BIP174 itself is
BSD-2-Clause, which requires attribution on redistribution of its content, including its own worked
examples — see `NOTICE` for that attribution. This module ALSO vendors conformance vectors from Bitcoin Core's `test/functional/data/
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

## Create and update a PSBT (Creator / Updater)

```zig
var arena = std.heap.ArenaAllocator.init(gpa); // the setters assume an arena-like allocator, like `finalize`
defer arena.deinit();
const a = arena.allocator();

var p = try psbt.fromUnsignedTx(a, unsigned_tx); // empty input/output maps
try psbt.setInputNonWitnessUtxo(a, &p, 0, prev_tx); // checked against the input's txid and vout
try psbt.setInputWitnessUtxo(a, &p, 1, prev_out);
try psbt.setInputRedeemScript(a, &p, 0, redeem_script);
try psbt.setInputBip32Derivation(a, &p, 0, pubkey33, master_fingerprint, &.{ 0x80000000 + 44, 0x80000000, 0 });
try psbt.bip371.setInputTapInternalKey(a, &p, 1, internal_xonly_key); // BIP371: also addInputTapLeafScript, ...

const text = try psbt.toBase64(a, p); // what wallets exchange
var back = try psbt.fromBase64(gpa, text); // OwnedPsbt: .psbt plus the buffer it borrows from
defer back.deinit(gpa);
```

BIP371 fields have typed readers (`psbt.bip371.inputTapInternalKey`, `inputTapLeafScripts`,
`outputTapTree`, ...), and the hash-preimage fields `psbt.inputPreimage` / `setInputPreimage`.
`parse` validates all of them structurally.

## Combine two PSBTs for the same transaction

```zig
var combined = try psbt.combine(allocator, psbt_a, psbt_b); // error.DifferentTransactions if they don't match
defer combined.deinit(allocator);
```

## Finalize inputs, then extract the network-ready transaction

```zig
// Mutates ps.inputs in place; one ?InputFinalizeError per input, null = finalized (or already was).
const results = try psbt.finalize(allocator, ps, .{});

// Requires every input finalized (error.InputNotFinalized otherwise).
var tx = try psbt.extract(allocator, ps);
defer tx.deinit(allocator);
const raw = try bitcointx.serialize(allocator, tx);
```

`finalize` handles P2PKH, native/P2SH-wrapped P2WPKH, bare/P2SH/P2WSH/P2SH-P2WSH multisig, and P2TR
key-path and script-path (`<key> OP_CHECKSIG` and `multi_a` leaves, from `TAP_LEAF_SCRIPT` + `TAP_SCRIPT_SIG`) — see `finalize.zig`'s module doc comment for the exact scope cut (non-standard/timelocked/
other tapscript spends are `error.NonStandardScript`, never silently mis-assembled) and for the
allocator/ownership contract (an arena is assumed). The **Signer** role — producing the
`PARTIAL_SIG`/`TAP_KEY_SIG` records `finalize` consumes — is not implemented; that needs private-key
custody and signing policy this module has no opinion about.

## Verify

```
zig build test-psbt --summary all
```

Byte-exact against BIP174's own published test vectors: every official invalid PSBT (rejected, each with
a specific pinned error), every official valid PSBT that does not hit the 0-input ambiguity (round-trip),
the BIP's own worked Combiner example, and the BIP's own worked Finalizer/Extractor example (a bare P2SH
2-of-2 multisig input plus a P2SH-P2WSH 2-of-2 multisig input: `finalize` on the pre-finalize PSBT and
`extract` on the finalized PSBT both reproduce the BIP's own published bytes exactly). The 2 valid vectors
this module cannot accept (a `bitcointx`-inherited wire-format ambiguity, not a psbt bug) and the rest of the
accounting are in `SPEC.md` "Verification".

Also checked against Bitcoin Core's own `test/functional/data/rpc_psbt.json` (a separate external oracle,
`core_kat_vectors.zig`/`core_kat_test.zig`): `PSBT_GLOBAL_VERSION` must be 0 or 2, Core's BIP371 taproot-field and BIP373 MuSig2 defects are rejected, the BIP370
field mixes are refused, and Core's pure-PSBTv2 valid vectors parse. The BIP's own BIP370 vectors are in
`bip370_test.zig`.

The two spend shapes neither BIP174 nor Core's JSON reach, native P2WPKH and native P2WSH 2-of-3
multisig, are anchored by captures from a real Bitcoin Core regtest node
(`regtest_kat_vectors.zig`/`regtest_kat_test.zig`): `finalize`/`extract` on the pre-finalize PSBT reproduce
Core's own finalized-PSBT and extracted-transaction bytes exactly, and the extracted P2WSH transaction was
independently confirmed acceptable by `testmempoolaccept` on the node that produced it. Every spend shape
`finalize`/`extract` supports is anchored against an outside oracle, not just this module's own round-trip.
