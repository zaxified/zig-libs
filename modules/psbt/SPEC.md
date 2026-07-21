# psbt — spec

Design + threat notes for auditors. Usage: see ./README.md.

## Design & invariants

Format: BIP174's `<magic> <global-map> <input-map>* <output-map>*`, where each `<map>` is a
sequence of `<keylen><keytype+keydata><valuelen><valuedata>` records terminated by a `0x00` byte.
The input/output map counts are not carried by any explicit field — they are exactly the unsigned
transaction's `vin.len`/`vout.len` (BIP174's only source of truth for this), so `parse` decodes the
global map first, decodes `PSBT_GLOBAL_UNSIGNED_TX` via `bitcointx.deserialize`, and only then knows
how many input/output maps to expect.

`Record{ keytype, keydata, value }` is the atomic unit; `Map{ records }` holds them **in original
wire order** (not canonicalized). This is a deliberate choice, not an oversight: BIP174's own
worked examples are *not* uniformly key-sorted (a real multisig-workflow PSBT in the BIP's own Test
Vectors section has two `PSBT_IN_PARTIAL_SIG` records in non-lexicographic order — verified against
the source document), so a "canonicalize on parse, re-sort on serialize" design would NOT reproduce
several of the official vectors byte-exact. Preserving original order and reserializing it makes
`parse` → `serialize` round-trip byte-exact for *any* validly-shaped PSBT, whatever order its
encoder chose. `combine` is the one place that re-sorts (ascending by raw key bytes) — that
matches BIP174's own worked Combiner example, which is explicitly captioned "A combiner which
orders keys lexicographically must produce the following PSBT."

Known key types (`global_key`/`input_key`/`output_key`) get structural validation at parse time —
this is the security core, see "Threat model" below — plus a handful of typed decode helpers
(`Psbt.unsignedTx`, `Psbt.version`, `inputWitnessUtxo`, `inputNonWitnessUtxo`, `inputSighashType`,
`inputBip32Derivation`/`outputBip32Derivation`/`globalXpubDerivation`). Every other key type,
including `PROPRIETARY = 0xFC` at every scope, is untouched opaque passthrough sitting in
`Map.records` — BIP174: "If the signer encounters key-value pairs that it does not understand, it
must pass those key-value pairs through when re-serializing."

Ownership mirrors `bitcointx.tx`'s zero-copy model: every `Record.keydata`/`.value` is a **borrowed**
slice into the buffer `parse` was called with — `bytes` must outlive the returned `Psbt`.
`unsignedTx`/`inputNonWitnessUtxo` decode a nested `bitcointx.Transaction` on demand and return it
**owned** (caller `.deinit()`s it); its own byte content still borrows from the original buffer.

Concurrency: `.reentrant` — no shared/global state, every call is over caller-owned values.

## Verification

**Invalid vectors** (`kat_vectors.zig: invalid`, 20 cases, machine-extracted by regex from BIP174's
own "Test Vectors" section — see that file's doc comment for the exact source and why regex
extraction rather than hand-typing): every one is asserted rejected (`kat_test.zig`'s first test),
and 19 of the 20 are asserted to fail with the *specific* error `parse` gives for that case (traced
by hand against the raw bytes — e.g. "invalid redeemscript typed key" decodes to keytype `0x04`
with one extra keydata byte beyond the type, i.e. `error.UnexpectedKeyData`; "invalid pubkey length
for input partial signature typed key" decodes to a 32-byte keydata on a `PARTIAL_SIG` record, i.e.
`error.InvalidPubkeyLength`). The 20th ("invalid value data due to its size being not the stated
size") is deliberately fuzzed garbage with no single well-defined rejection reason and is only
asserted to fail somehow.

**Valid vectors** (`kat_vectors.zig: valid`, 10 cases): 8 of the 10 are asserted byte-exact on
`parse` → `serialize` round-trip. The remaining 2 ("...0 inputs and 0 outputs" / "...0 inputs")
encode a legacy transaction with a 0-input `vin` count — which is byte-for-byte indistinguishable
from the BIP144 segwit marker byte, a wire-format ambiguity `bitcointx.tx` documents as a real,
permanent restriction of the underlying transaction codec (not something this module can route
around without changing `bitcointx`'s own wire disambiguation rule). These two are asserted to fail
with `error.InvalidWitnessFlag` — a documented, tested limitation, not a silent gap.

**Combiner vector**: BIP174's own worked example ("Given these two PSBTs with unknown key-value
pairs... A combiner which orders keys lexicographically must produce the following PSBT") is pinned
byte-exact: `combine(a, b)` → `serialize` equals the BIP's own expected result bytes.

**Hostile teeth beyond the BIP set** (`root.zig`'s own test block): truncated map (keylen with no
key bytes following), `valuelen` claiming far more bytes than remain (both a 1-byte and a
CompactSize-wide-form declared length), empty global map (no unsigned tx) — every one a typed
error, never a panic or OOB read. `parseMap`'s `ArrayList` only grows one successfully-decoded
record at a time (no upfront-count-driven allocation to game — there is no count field in the map
format to begin with, it's `0x00`-terminated), so there is no large-allocation-from-a-hostile-count
vector the way `bitcointx.tx`'s `vin`/`vout`/witness counts have; duplicate-key detection uses a
`StringHashMapUnmanaged` over borrowed raw key slices (O(n) per map), not an O(n²) pairwise scan, so
a legitimately-large PSBT can't be turned into a duplicate-key-check DoS.

## Threat model / out of scope

`parse` treats every byte as untrusted and fails closed on the first structural or per-field
violation — see `ParseError`'s doc comments for the complete error catalogue. No path panics or
reads out of bounds on malformed/truncated/adversarial input.

**Deferred: Signer, Input Finalizer, Transaction Extractor.** All three roles require interpreting
Bitcoin Script — the Signer to know what it's signing (matching a scriptPubKey/redeemScript/
witnessScript against a spend policy), the Input Finalizer to assemble a final scriptSig/
scriptWitness that actually satisfies the input's script, the Transaction Extractor to (optionally)
validate the result. This repository has no Script interpreter yet — that would be its own future
`bitcoinscript` module. A finalizer/extractor that can't validate what it's building would be a
false sense of completeness worse than not having one; structurally deferred, not half-built. This
module implements exactly the roles that don't need Script: Creator/Updater's wire codec
(`parse`/`serialize`) and the Combiner (`combine`), which BIP174 itself notes "does not need to know
how to interpret scripts in order to combine PSBTs."

**Out of scope: BIP370 (PSBTv2).** BIP174 v0 is what this module implements (the field list in
`global_key`/`input_key`/`output_key` is the complete BIP174 v0 set); BIP370's PSBTv2 extensions
(explicit input/output counts, per-input `PSBT_IN_PREVIOUS_TXID`/`PSBT_IN_OUTPUT_INDEX` replacing
the implicit unsigned-tx-derived shape, etc.) are a distinct, larger wire format and a separate future
task, not attempted here.

**`PSBT_IN_RIPEMD160`/`SHA256`/`HASH160`/`HASH256` (`0x0a`-`0x0d`) and `PROPRIETARY` (`0xFC`
everywhere) are not given typed accessors** — they fall to the generic opaque-passthrough path like
any other unrecognized key type. They round-trip correctly (preserved byte-for-byte) but have no
convenience decoder; not exercised by any official BIP174 vector, and add no security-relevant
validation surface (unlike the mandatory/common fields this module does validate structurally).
