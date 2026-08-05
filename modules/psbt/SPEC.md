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

**Finalizer/Extractor vectors** (`kat_vectors.zig`'s `finalize_combined_hex`/`finalize_finalized_hex`/
`finalize_extracted_tx_hex`, driven by `finalize_test.zig`'s "BIP174 official Finalizer/Extractor
worked example" tests): the same "Test Vectors" section's main multisig-workflow narrative also
carries a genuine pre-finalize/post-finalize/post-extract triple — a bare P2SH 2-of-2 multisig input
plus a P2SH-P2WSH 2-of-2 multisig input. `finalize` on the pre-finalize PSBT reproduces the BIP's own
finalized PSBT byte-exact (with the field-clearing rule checked explicitly per input, not just
implied by the byte compare), and `extract` on the BIP's own finalized PSBT reproduces its published
raw transaction byte-exact. P2WPKH finalization and native (non-P2SH) P2WSH multisig are NOT covered
by BIP174's vectors — see "Regtest vectors" below for how those two are anchored instead.

**Bitcoin Core vectors** (`core_kat_vectors.zig`/`core_kat_test.zig`, `test/functional/data/
rpc_psbt.json`, a SEPARATE external oracle from BIP174): Core's own `finalizer`/`extractor` entries
were checked first and turned out to be byte-identical to the BIP174 Finalizer/Extractor worked
example just above — Core's functional test reuses BIP174's own example verbatim, so the P2WPKH/
native-P2WSH gap noted above is NOT closed by this JSON. What Core's JSON DOES give this module: 45
new (non-BIP174-duplicate) `invalid` vectors plus all 23 `invalid_with_msg` vectors, individually
decoded to determine why each is invalid
rather than just pattern-matching Core's message. That surfaced one genuine BIP174 gap — a present
`PSBT_GLOBAL_VERSION` was checked for shape but never for value, though BIP174 §"Version 0" requires
it be 0 if present — now fixed (`error.UnsupportedPsbtVersion`; `core_kat_vectors.invalid_v0_scope`'s
`core_index = 19`/`42` are the external oracle for it). Every other vector this module still accepts
is BIP370(PSBTv2)/BIP371(Taproot)/MuSig2 content, or a BIP174 §"Signer" TXID-cross-check (Signer role
is deferred, see "Threat model" below) — explicitly out of scope, not a bug; asserted as an accept,
not silently skipped (`core_kat_vectors.invalid_out_of_scope`). Of Core's 42 new `valid` vectors, 27
round-trip byte-exact, 14 are pure-PSBTv2 PSBTs this module correctly refuses (out of scope), and one
(`valid[5]`) hits the SAME 0-vin/BIP144-marker ambiguity as the two BIP174 valid vectors above, just
surfacing as `error.TooManyItems` instead of `error.InvalidWitnessFlag` — same root cause, new facet,
not a new bug. See `core_kat_test.zig`'s doc comment for the full per-index account.

**Regtest vectors** (`regtest_kat_vectors.zig`/`regtest_kat_test.zig`, `zig build test-psbt`): the
two spend shapes neither BIP174's vectors nor Core's `rpc_psbt.json` reach — native P2WPKH and
native (non-P2SH) P2WSH multisig — are anchored by capturing them from a real Bitcoin Core v28.0.0
regtest node instead, once, with the resulting bytes frozen as literals (no network access at test
time; see each vector file's doc comment for the exact `bitcoin-cli` sequence to re-derive them).
Native P2WPKH (captured 2026-08-02): `walletcreatefundedpsbt` → `walletprocesspsbt … false` →
`finalizepsbt`. Native P2WSH 2-of-3 multisig (captured 2026-08-05) needed a longer chain — a
watch-only wallet holding an imported `wsh(multi(2,pk1,pk2,pk3))` descriptor funded via
`sendtoaddress` (not mined directly, to sidestep coinbase maturity), two independent signer wallets
each running `walletprocesspsbt … false`, then `combinepsbt` — because it is the ONE spend shape in
this module that had no outside oracle at all before this capture: an encoder/decoder pair sharing a
misreading would otherwise satisfy its own test. For both shapes, `finalize` on the pre-finalize
PSBT reproduces Core's own finalized-PSBT bytes exactly, `extract` on Core's finalized PSBT
reproduces Core's own extracted-transaction bytes exactly, and (P2WSH multisig only, as the harder
case) the extracted transaction was independently confirmed acceptable by `testmempoolaccept` on the
node that produced it — not just something this module's own code would accept. Every spend shape
`finalize`/`extract` supports is now anchored against an outside oracle.

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

**Input Finalizer and Transaction Extractor are now implemented** (`finalize.zig`'s `finalize`/
`extract`, exported from `root.zig`) — corrected here because this section used to say all three
non-Script roles were deferred pending a Script interpreter; `bitcoinscript` now exists, so that
blocker is gone for these two. `finalize` assembles `FINAL_SCRIPTSIG`/`FINAL_SCRIPTWITNESS` for the
standard spend types (P2PKH, P2WPKH, P2SH-P2WPKH, bare/P2SH/P2WSH/P2SH-P2WSH multisig, P2TR
key-path), verifying every candidate through `bitcoinscript.verifyScript` before accepting it and
clearing the now-consumed input fields per BIP174 §"Input Finalizer"; `extract` splices finalized
inputs into a network-ready `bitcointx.Transaction`. See `finalize.zig`'s own module doc comment for
the full scope cut (non-standard/timelocked/tapscript spends are `error.NonStandardScript`, never
silently mis-assembled) and "Verification" below for the anchor.

**Still deferred: Signer.** It needs private-key custody and signing policy this module has no
opinion about (matching a scriptPubKey/redeemScript/witnessScript against a spend policy, then
producing a signature) — `PARTIAL_SIG`/`TAP_KEY_SIG` records are expected to already be present by
the time `finalize` runs. This module implements Creator/Updater's wire codec (`parse`/`serialize`),
the Combiner (`combine`, which BIP174 itself notes "does not need to know how to interpret scripts
in order to combine PSBTs"), and now the Input Finalizer/Transaction Extractor above.

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
