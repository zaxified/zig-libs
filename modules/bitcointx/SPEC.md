# bitcointx — spec

Design + threat notes for auditors. Usage: see ./README.md.

## Design & invariants

Pure codec + pure computation, no I/O, no allocation beyond what the caller's `Allocator`
provides. Five files:

- `tx.zig` — CompactSize (Bitcoin's varint) encode/decode, and `Transaction`/`TxIn`/`TxOut`/
  `Witness` (de)serialization for both the legacy and BIP144 segwit wire forms. **Zero-copy**:
  every `scriptSig`/`scriptPubKey`/witness-item byte slice returned by `deserialize` is a
  *borrowed* view into the caller's input buffer, never duplicated — only the dynamic-length
  *arrays* (`vin`, `vout`, `witness`, each witness's `items`) are heap-allocated. This means the
  input buffer must outlive the `Transaction`, and `Transaction.deinit` frees only the arrays it
  allocated. `txid`/`wtxid` are `sha256d` of the non-witness / full serialization respectively
  (BIP141), returned in internal/wire byte order (reverse for the conventional display form).
- `hashtype.zig` — the shared `ALL`/`NONE`/`SINGLE`/`ANYONECANPAY` bit layout the legacy and
  BIP143 algorithms both use (a raw `u32`, low 5 bits = base type, bit `0x80` = ANYONECANPAY,
  matching Bitcoin Core's `(nHashType & 0x1f)` / `(nHashType & 0x80)` classification exactly,
  including the fact that any low-5-bit value other than 2/3 — not just 1 — is "ALL-like").
- `sighash_legacy.zig` — the pre-segwit `SignatureHash()` algorithm (predates the BIP process;
  described from Bitcoin Core's reference behavior, `src/script/interpreter.cpp`).
- `sighash_bip143.zig` — BIP143 segwit-v0 sighash: three reusable per-transaction midstates
  (`hashPrevouts`/`hashSequence`/`hashOutputs`) plus the amount-committing preimage.
- `sighash_bip341.zig` — BIP341 taproot key-path sighash: `SigMsg` over prevout/amount/
  scriptPubKey/sequence commitments (single SHA-256, not `sha256d` — see `hash256.zig`'s doc
  comment) plus `bip340.taggedHash("TapSighash", …)`.
- `precomputed.zig` — `PrecomputedTransactionData` (Bitcoin Core's struct of the same name): the
  BIP143 and BIP341 per-transaction commitment hashes computed once per transaction, plus the
  `*With` sighash entry points that consume it. Byte-identical to the uncached entry points by
  construction — the `hash_type`-dependent selection over the commitment hashes lives in one place
  per algorithm and both routes share it — and pinned as such by a test over every hash type and
  every input. Complexity is guarded by a deterministic counter of commitment-hash computations
  (`instrument.zig`), not a stopwatch. **Caller precondition: `pre` is invalidated by any mutation
  of the transaction or its spent outputs; the fingerprint detects substitution only.** The `*With`
  entry points carry an O(1) identity fingerprint (`vin`/`vout`/`spent_outputs` pointers and
  lengths) that refuses a `pre` paired with a different transaction, but an in-place edit through
  those same slices is invisible to it and yields the pre-edit digest with no error — parity with
  Bitcoin Core's struct, which carries no check at all. A content hash would catch it and would
  cost per call exactly the `O(n)` this cache exists to remove, so the limit is documented and
  asserted (the F12 test) rather than engineered away.
- `instrument.zig` — that counter. `builtin.is_test`-gated, so it is `void` and compiles away
  entirely outside a test build.

Concurrency: `.reentrant` — every function is a pure transform over caller-owned values, no
shared/global state. (`instrument.zig`'s counter is the sole mutable global and exists only in a
test binary, where these tests are single-threaded.)

## Threat model / out of scope

`tx.zig`'s `deserialize`/`deserializePartial` parse **untrusted** wire bytes (e.g. a transaction
received from a peer or extracted from a block) and are fail-closed throughout: every malformed,
truncated, or adversarial input returns a typed error, never panics, and a hostile `vin`/`vout`/
witness count can never by itself force a large allocation — see `tx.zig`'s module doc comment
("Hostile-input handling") for the exact mechanism (a cheap remaining-bytes bound check plus the
structural fact that the parse loop only grows its array one successfully-parsed item at a time).
`sighash_*.zig` operate on an already-parsed, already-typed `Transaction` — not raw bytes — so
their error surface is narrower (out-of-range `input_index`, a `spent_outputs` length mismatch,
and BIP341's stricter `hash_type` validity set), documented per function.

**No Bitcoin Script interpretation anywhere in this module.** `scriptSig`/`scriptPubKey`/witness
items are opaque byte slices throughout; `sighash_legacy`/`sighash_bip143`'s `script_code`
parameter is caller-supplied (typically the spent output's `scriptPubKey`, or a P2SH
`redeemScript`) rather than derived by walking a script. Two concrete consequences:

- **`OP_CODESEPARATOR` removal IS implemented** (as of the wave-2 burn-down; this section used to
  record it as a scope cut). `sighash_legacy.zig`'s `appendScriptCode` reproduces Core's
  `CTransactionSignatureSerializer::SerializeScriptCode`: an opcode-aware walk that omits every
  literal `OP_CODESEPARATOR` (`0xab`) *opcode* while leaving a `0xab` *byte* inside a push payload
  alone, with Core's `scriptCode.size() - nCodeSeparators` length prefix and Core's truncation of
  an undecodable tail. This needs push-length rules only — no opcode semantics, no stack — so the
  "no Script interpretation" position above still holds. `legacy_kat_vectors.zig` is consequently
  UNFILTERED: all 500 rows of `sighash.json`, including the 210 the old filter dropped.
- BIP143 explicitly drops this step too (BIP143 "No FindAndDelete"), so `sighash_bip143.zig` has
  **no** scope cut relative to its spec — `script_code` is hashed exactly as given, matching
  BIP143 precisely.

## Deferred: BIP342 tapscript and the annex (structural note, not half-built)

`sighash_bip341.zig` implements **only** taproot key-path spending (`ext_flag = 0`, `spend_type`
always `0x00` — never signals an annex). Deliberately out of scope, not attempted:

- **BIP342 tapscript signature hashing** — a distinct signing mode (`ext_flag = 1`) that
  additionally commits to the tapleaf hash, `key_version`, and `codeseparator_position`. This is
  not "the same function with one more field": it requires the tapscript leaf-hash machinery
  (`TapLeaf` tagged hashing over a script + leaf version) this module does not build.
- **The annex** — BIP341's optional witness-stack trailer (present when the witness has ≥2 items
  and the last one starts with `0x50`), which commits `sha_annex` into `SigMsg` and sets
  `spend_type`'s low bit. Detecting and hashing it is a small, self-contained extension; it is
  omitted because (a) it is meaningless without a companion Fable pass encompassing tapscript (an
  annex-carrying key-path spend is valid but rare, and testing it properly needs a real vector),
  and (b) the official `bip-0341/wallet-test-vectors.json` `keyPathSpending` fixture this module's
  KATs are pinned against contains **no** annex case (confirmed: zero occurrences of `"annex"` in
  the source JSON) — so there is no official byte-exact vector to build or verify it against in
  this pass.

Both are real, independent follow-on units of work, not corners cut inside what's already built.

## Verification

`legacy_kat_vectors.zig`/`bip143_kat_vectors.zig`/`bip341_kat_vectors.zig`/`tx_kat_vectors.zig` are
machine-transcribed (never hand-typed) directly from fetched official sources — see each file's
doc comment for the exact source URL and, where applicable, an independent from-scratch
cross-check (a second implementation, in Python, run once at generation time) that caught a real
transcription/byte-order pitfall before it ever reached this module's Zig tests (see "Pitfalls
this caught" below).

- **Legacy sighash** — `bitcoin/bitcoin`'s own `src/test/data/sighash.json` (the reference-oracle
  fixture `SignatureHash()` is checked against upstream): **all 500 data rows, no filter** (the
  file has 501 array entries, one of which is the header comment). 210 of them carry a raw `0xab`
  byte in the `script` column and were excluded until `SerializeScriptCode` was implemented;
  measured, all 210 are real `OP_CODESEPARATOR` opcodes rather than push payload. Covering all
  3 named base types (`ALL`/`NONE`/`SINGLE`) × both `ANYONECANPAY` states plus many rows whose
  low-5-bit hashType isn't 1/2/3 at all (the "falls back to ALL-like" classification). See
  `modules/bitcointx/NOTICE` for the required Bitcoin Core attribution this data carries.
- **BIP143** — `bip-0143.mediawiki`'s own two published "Example" cases (Native P2WPKH,
  P2SH-P2WPKH): `hashPrevouts`/`hashSequence`/`hashOutputs` AND the full preimage AND the final
  sighash, all four asserted byte-exact per case.
- **BIP341** — `bip-0341/wallet-test-vectors.json`'s `keyPathSpending` section: one shared
  9-prevout transaction, 7 `inputSpending` sub-cases covering every hashType BIP341 defines
  (`DEFAULT`, `ALL`, `NONE`, `SINGLE`, and each with `ANYONECANPAY`), `SigMsg` and sighash both
  asserted byte-exact per case.
- **Real transactions** — `tx.deserialize` → `tx.serialize` round-trip plus `txid`/`wtxid`, against
  (1) mainnet block 170's second transaction (the earliest known peer-to-peer Bitcoin transaction),
  fetched live by block height from a block explorer and keyed by that explorer's own reported
  txid, and (2) BIP143's own published Native-P2WPKH *signed* example (an officially-published
  canonical interop reference), with `txid`/`wtxid` independently derived in Python at generation
  time.
- **Hostile input** — `tx.zig`'s own tests: truncated at every stage (before the version field,
  mid-input), a `vin`/`vout` count claiming far more items than remain (`error.TooManyItems`, no
  allocation-by-hostile-count), a non-minimally-encoded CompactSize, an unrecognized segwit flag
  byte, and trailing bytes after a complete transaction — every one a typed error.

### Pitfalls this caught

Both of the following were caught by the independent-implementation cross-check *before* being
committed to a Zig test, i.e. this is what that process is for, not a hypothetical:

- `sighash.json`'s `signature_hash` column turned out to be in **display** (reversed) byte order,
  like a txid string — not this module's internal/wire order. `legacy_kat_vectors.zig` stores the
  already-reversed (internal-order) value, documented at the point of storage.
- `wallet-test-vectors.json`'s `sigMsg` field name is a false friend: despite the name, its first
  byte IS the BIP341 sighash epoch (`0x00`), i.e. the field actually holds `0x00 || SigMsg` (what
  BIP341's prose calls "Message"), not `SigMsg` alone. `sighash_bip341.zig`'s `sigMsg()` follows
  the vector's actual content (returns the epoch-prefixed bytes) rather than the prose's
  potentially-misleading field name.

Run: `zig build test-bitcointx` (Debug and `-Doptimize=ReleaseFast`).

## Status

`gap · any (pure codec + pure computation, no I/O) · codec · reentrant` + deps: `bip340` —
canonical source is `pub const meta` in src/root.zig.
