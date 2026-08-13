# bitcointx

Pure-Zig **Bitcoin transaction serialization + signature hashing**: CompactSize varints, legacy
AND BIP144 segwit transaction (de)serialization, `txid`/`wtxid`, and all three deployed sighash
algorithms (legacy, BIP143 segwit-v0, BIP341 taproot key-path).

- No mature pure-Zig Bitcoin transaction/sighash library exists; this is the transaction-layer
  complement to the repo's existing `bip340`/`taproot`/`k256`/`ripemd160`/`bech32`/`bip32`
  Bitcoin/Lightning modules (none of which parse a transaction or compute a sighash).
- **Platform:** any — every function is a pure transform over caller-owned byte slices/values, no
  I/O, no allocation beyond the caller's `Allocator`.
- **Model after:** BIP141 (segwit), BIP143 (segwit-v0 sighash), BIP144 (segwit wire format), BIP340
  (Schnorr, via the sibling `bip340` module), BIP341 (taproot key-path sighash); the legacy
  algorithm predates the BIP process and is modeled on Bitcoin Core's reference behavior
  (`SignatureHash()`, `src/script/interpreter.cpp`).

Provenance: BIP141/143/144/340/341 are public specifications (merger doctrine —
see [`CONVENTIONS.md`](../../CONVENTIONS.md) §5), so those sighash paths are
clean-room. The **legacy** sighash predates the BIP process and was never
specified: its behavior — including the `SIGHASH_SINGLE` bug, which is consensus
and must be reproduced bit-for-bit — is modeled on Bitcoin Core's reference
implementation (**MIT**), `SignatureHash()` in `src/script/interpreter.cpp`, as
a **design reference** for behavior only; no source ported or copied. The
reproduced Bitcoin Core `sighash.json` conformance rows are a separate matter
and are answered in [`NOTICE`](NOTICE) beside this file.

## Scope

Implemented — see `SPEC.md` for the full design/threat-model writeup:

- **CompactSize** (`encodeCompactSize`/`decodeCompactSize`) — Bitcoin's varint, fail-closed on
  truncation and non-minimal encodings.
- **Transaction (de)serialization**, legacy AND BIP144 segwit — `deserialize`/`deserializePartial`
  (untrusted bytes → typed errors, zero-copy: script/witness bytes are borrowed slices into the
  caller's buffer) and `serialize`/`serializeLegacy`/`serializeSegwit`. `Transaction.txid()`/
  `.wtxid()` per BIP141.
- **Legacy sighash** (`sighash_legacy.zig`) — scriptCode substitution, ALL/NONE/SINGLE ×
  ANYONECANPAY, the historical SIGHASH_SINGLE `uint256(1)` bug, and Core's
  `SerializeScriptCode` (`OP_CODESEPARATOR` opcodes omitted, push payloads left alone).
- **BIP143 segwit-v0 sighash** (`sighash_bip143.zig`) — the three reusable midstates
  (`hashPrevouts`/`hashSequence`/`hashOutputs`) plus the amount-committing preimage.
- **BIP341 taproot key-path sighash** (`sighash_bip341.zig`) — `SigMsg` over prevout/amount/
  scriptPubKey/sequence/output commitments via `bip340.taggedHash("TapSighash", …)`, all 7
  hashType combinations (`DEFAULT`/`ALL`/`NONE`/`SINGLE` × plain/`ANYONECANPAY`). `commonSigMsg`
  exposes the same layout with a caller-chosen `spend_type` and optional annex commitment, so
  `bitcoinscript`'s BIP342 script-path message appends its extension to this one rather than
  reproducing a consensus-critical byte order a second time.
- **`PrecomputedTransactionData`** (`precomputed.zig`) — the per-transaction commitment hashes
  (BIP143's three midstates, BIP341's five) computed **once per transaction** and reused for every
  input and every `CHECKSIG`, matching Bitcoin Core's struct of the same name. "Reusable" above is
  only true if the caller actually holds them: the plain `sighash` entry points recompute on every
  call, which is `O(n²)` in transaction size on input an attacker chooses — the exact cost BIP143
  was written to eliminate. A validator wants `precompute` + `bip143.sighashWith` /
  `bip341.sighashWith`, which are byte-identical to the uncached forms.
  ⚠ **Precondition: `pre` is invalidated by any mutation of the transaction or its spent outputs;
  the fingerprint detects substitution only.** The `*With` entry points refuse a `pre` built from a
  *different* transaction (`error.PrecomputedMismatch`), but that check is an O(1) pointer/length
  fingerprint: an in-place edit — filling in a `script_sig`, bumping an output value — leaves the
  pointers identical and silently yields the pre-edit digest. Rebuild `pre` after every change.
  Bitcoin Core's `PrecomputedTransactionData` behaves the same way; detecting mutation would mean
  re-hashing the transaction on every call, i.e. paying back exactly what the cache saves.

Deliberately deferred (structurally noted, not half-built — SPEC.md has the full rationale): BIP342
tapscript signature hashing itself (the message layout is shared, the tapscript semantics live in
`bitcoinscript`), and annex support in the *key-path* sighash (the plumbing exists via
`CommonOptions.annex_hash`; only the key-path caller does not use it).

## Use

```zig
const bitcointx = @import("bitcointx");

// -- parse an untrusted raw transaction --
var tx = try bitcointx.deserialize(allocator, raw_tx_bytes);
defer tx.deinit(allocator); // frees only the vin/vout/witness arrays -- raw_tx_bytes must
                             // outlive `tx` (scriptSig/scriptPubKey/witness items borrow it)

const the_txid = try tx.txid(allocator); // sha256d of the non-witness serialization
const the_wtxid = try tx.wtxid(allocator); // sha256d of the full segwit serialization

// -- re-serialize (dispatches on tx.has_witness) --
const wire_bytes = try bitcointx.serialize(allocator, tx);
defer allocator.free(wire_bytes);

// -- legacy sighash (P2PKH/P2PK/bare-multisig/P2SH) --
const legacy_sighash = try bitcointx.legacy.sighash(
    allocator, tx, input_index, script_pubkey_of_spent_output, bitcointx.legacy.ALL,
);

// -- BIP143 segwit-v0 sighash (P2WPKH/P2WSH) -- needs the spent output's amount --
const segwit_sighash = try bitcointx.bip143.sighash(
    allocator, tx, input_index, script_code, spent_amount_sats, bitcointx.bip143.ALL,
);

// -- BIP341 taproot key-path sighash -- needs every input's spent output --
const taproot_sighash = try bitcointx.bip341.sighash(
    allocator, tx, input_index, bitcointx.bip341.SIGHASH_DEFAULT, spent_outputs,
);
```

## Verify

```
zig build test-bitcointx           # Debug
zig build test-bitcointx -Doptimize=ReleaseFast
zig fmt --check modules/bitcointx
```

Byte-exact against: a real mainnet block-170 legacy transaction (txid), BIP143's own published
Native-P2WPKH signed example (round-trip + txid + wtxid), Bitcoin Core's `sighash.json` reference
fixture (**all 500** of its rows, including the 210 that carry an `OP_CODESEPARATOR`), every
transaction in Core's `tx_valid.json` + `tx_invalid.json` (213 real serializations, round-tripped
and cross-checked against Core's own prevout table),
python-bitcoinlib's `RawSignatureHash` for the **SIGHASH_SINGLE boundary** (a corner `sighash.json`
does not reach: 17 of its rows use SINGLE, none with `input_index >= len(vout)`), BIP143's own two
worked examples (intermediates + preimage + sighash), and the
official `bip-0341/wallet-test-vectors.json` `keyPathSpending` vectors (SigMsg + sighash, all 7
hashType cases) — plus hostile-input teeth (truncated/oversized-count/non-minimal-CompactSize, all
typed errors, never a panic or unbounded allocation). See `SPEC.md` for exactly what was verified
against what, and two real transcription pitfalls an independent-implementation cross-check caught
before they reached a Zig test.
