# bitcoinscript — spec

Design + threat notes for auditors. Usage: see ./README.md.

## Design & invariants

A stack machine executing UNTRUSTED, attacker-supplied bytes, layered bottom-up:

- `opcodes.zig` — the opcode byte/mnemonic table (matches Bitcoin Core's `opcodetype` enum
  exactly) + the disabled-opcode / reserved-conditional sets.
- `number.zig` — `CScriptNum`, Script's little-endian sign-magnitude integer encoding. Minimal-
  encoding enforcement is a caller-supplied `require_minimal` bool, not baked in — Bitcoin Core
  derives this from a single `MINIMALDATA` flag that gates BOTH push-opcode minimality AND every
  arithmetic/CLTV/CSV operand's `CScriptNum` minimality; `interpreter.zig` passes `flags.minimaldata`
  to both call sites.
- `limits.zig` — the consensus DoS bounds (`MAX_SCRIPT_SIZE`=10000, `MAX_SCRIPT_ELEMENT_SIZE`=520,
  `MAX_OPS_PER_SCRIPT`=201, `MAX_STACK_SIZE`=1000, `MAX_PUBKEYS_PER_MULTISIG`=20) plus one
  module-added bound (`max_stack_items_in_witness`, see "Defensive bounds beyond consensus" below).
- `flags.zig` — `ScriptFlags`, the `SCRIPT_VERIFY_*` set. Each field is documented with exactly
  what it gates; `.none`/`.standard` are convenience presets.
- `txctx.zig` — `SigVersion` (`.base`/`.witness_v0`, selects legacy vs. BIP143 sighash) and
  `TxContext` (the spending tx + input index + every input's spent output — BIP341 needs all of
  them, not just the one being signed).
- `sigcheck.zig` — BIP62/66/146 signature/pubkey encoding checks, and the actual ECDSA
  verification. **Does NOT use `k256.sign.ecdsaVerify`** — that function hashes its `msg`
  parameter with SHA-256 internally (matching `std.crypto.sign.ecdsa`'s "verify over SHA-256 of
  an unhashed message" convention), but `bitcointx.legacy.sighash`/`bip143.sighash` already
  return the FINAL digest (`sha256d(preimage)`) that Bitcoin's ECDSA math consumes directly, with
  no further hashing. Calling `ecdsaVerify(pk, &sighash, sig)` would hash that digest a *third*
  time and silently verify against the wrong value. `sigcheck.zig`'s `ecdsaVerifyDigest` is
  `k256.sign.ecdsaVerify`'s exact arithmetic (built from `k256.Secp256k1`/`k256.Scalar` directly)
  with that extra hash removed — this was caught by the module's own signed-vs-verified
  round-trip test (`e2e_test.zig`), which is exactly the failure mode a "sign it myself, verify it
  myself" test is supposed to catch.
- `interpreter.zig` — `eval` (legacy/segwit-v0) + `evalTapscript` (BIP342): the opcode-dispatch
  loop, `IF`/`NOTIF`/`ELSE`/`ENDIF` structuring, `OP_CODESEPARATOR`-aware scriptCode, and the
  tapscript deltas (Schnorr `OP_CHECKSIG`/`OP_CHECKSIGADD`, the `OP_SUCCESSx` pre-scan, the
  validation-weight budget, mandatory MINIMALIF, removed op-count/script-size limits). Owns every
  DoS bound.
- `tapscript.zig` — BIP341/342 script-path primitives: control-block/tapleaf/Merkle-root/tweak
  commitment (`verifyCommitment`), the `ext_flag=1` sighash extension, and BIP340 Schnorr signature
  checking (`checkSchnorrSig`).
- `verify.zig` — `verifyScript`: legacy → BIP16 P2SH → BIP141 segwit-v0
  (P2WPKH/P2WSH) → BIP341 taproot-key-path → BIP341/342 taproot-script-path orchestration on top of
  `interpreter.eval`/`evalTapscript`.

Concurrency: `.reentrant` — no shared/global state; every call is over caller-owned values.
Allocator contract: `interpreter.eval`/`verifyScript` assume an arena-like allocator (bulk-freed
by the caller after the whole `verifyScript` call) — intermediate buffers (scriptCode copies, hash
results, `OP_DUP`-style aliases of an existing stack slice) are never freed individually. This is
documented in `interpreter.zig`'s module doc comment and is a deliberate simplification, sound
because every value flowing through the stack machine is already bounded by `limits.zig`.

## Threat model / DoS bounds

Every consensus bound is enforced BEFORE the resource it bounds is consumed: script size checked
before any opcode reads; push size checked before the push is executed; op-count checked for
every non-push opcode (including `IF`/`NOTIF`/`ELSE`/`ENDIF` themselves) REGARDLESS of whether the
enclosing branch is currently executing (Bitcoin Core counts this before ever consulting the
`fExec` flag — a script cannot hide unbounded opcodes inside a never-taken `IF` branch); stack
size checked after every instruction. `interpreter.zig`'s tests exercise each of these; `dos_test.zig`
adds `verifyScript`-level teeth (below).

**Defensive bounds beyond consensus**: `verify.zig`'s `verifyWitnessProgram` caps witness item
count (`limits.max_stack_items_in_witness`) and, for P2WSH's non-final stack-seed items and
P2WPKH's `[sig, pubkey]`, each item's size (`limits.max_script_element_size`) — `error.PushSize`.
True Bitcoin Core consensus does **not** bound raw witness-stack item bytes at this exact layer
(it bounds them only indirectly, via the block *weight* limit, an orchestration-layer concern this
standalone script-verifier library has no visibility into). Without this module-added bound, a
caller handing `verifyScript` attacker-supplied witness data directly (fuzzing; a mempool-admission
path with no separate weight check yet) has no memory bound at all. A production full node
embedding this module for **block-validated** spends (where the weight limit is already enforced
upstream) will never observe this bound trigger on a real, weight-valid block.

## BIP342 tapscript

Taproot **key-path** spending (a witness stack of exactly one element, optionally an annex) is a
BIP340 Schnorr signature verified directly against the witness-program bytes over the BIP341
key-path sighash — no script execution at all, per spec.

Taproot **script-path** spending (BIP341/342, a witness stack of ≥2 elements after annex-stripping)
is now implemented end to end:

- **Commitment (BIP341 "Script validation rules", `tapscript.verifyCommitment`)** — the last
  witness item is the control block (`33 + 32m` bytes, `m ≤ 128`), the second-to-last is the leaf
  `script`, and the rest seed the initial stack. The leaf version is `c[0] & 0xfe`; the internal
  key is `c[1:33]`. We recompute the tapleaf hash (`hash_TapLeaf(v || compact_size(script) ||
  script)`), fold the Merkle path (`hash_TapBranch`, lexicographically ordered), tweak the internal
  key (`t = hash_TapTweak(p || merkle_root)`, failing if `t ≥ n`), and check that
  `Q = lift_x(p) + t·G` matches the witness program's x-coordinate AND parity bit. Validated
  byte-exactly against the BIP341 `wallet-test-vectors.json` single-leaf cases (`tapscript.zig`).
  A leaf version other than `0xc0` is anyone-can-spend (upgrade hook) unless
  `discourage_upgradable_taproot_version` is set.
- **`OP_SUCCESSx` (BIP342)** — the exact set `{80, 98, 126-129, 131-134, 137-138, 141-142,
  149-153, 187-254}` (which is precisely the legacy disabled/reserved set ∪ the undefined
  `0xbb..0xfe` tail). A separate pre-scan (`interpreter.scanOpSuccess`, matching Core's
  `ExecuteWitnessScript` first pass) walks the whole leaf before execution; any `OP_SUCCESSx`
  anywhere (even in an unexecuted branch, even before an otherwise-undecodable tail) makes the
  spend succeed unconditionally — unless `discourage_op_success` is set. A decode failure reached
  *before* any `OP_SUCCESSx` is a real `BadOpcode`.
- **`OP_CHECKSIG`/`OP_CHECKSIGVERIFY`/`OP_CHECKSIGADD` (BIP342, `interpreter.evalChecksigTapscript`
  + `tapscript.checkSchnorrSig`)** — a 32-byte public key is BIP340; an empty signature makes
  CHECKSIG push false / CHECKSIGADD leave `n` unchanged / CHECKSIGVERIFY fail; a **non-empty**
  signature that fails to verify (or has an invalid 64/65-byte shape, or a 65-byte form carrying
  `SIGHASH_DEFAULT`) is an immediate, hard script failure (no NULLFAIL leniency). An empty public
  key fails immediately; an unknown (non-32-byte) public key is treated as an always-successful
  upgrade hook unless `discourage_upgradable_pubkeytype` is set. `OP_CHECKMULTISIG(VERIFY)` are
  disabled in tapscript and fail immediately when executed (ignored in an unexecuted branch).
- **Validation-weight budget (BIP342)** — the per-input budget starts at
  `50 + serialized_witness_size` and is decremented by `50` for each executed signature opcode with
  a **non-empty** signature (both known and unknown pubkey types); dropping below zero fails the
  script (`TapscriptValidationWeight`). This replaces the (removed-for-tapscript) 201-op and
  10000-byte-script limits. The 520-byte-per-element and 1000-element stack limits remain, extended
  to the initial stack.
- **Sighash extension (BIP342, `tapscript.sigMsg`)** — the BIP341 Common Signature Message with
  `spend_type = 2` (`ext_flag = 1`, `+1` with an annex), the `sha_annex` commitment when an annex
  is present, and the appended `tapleaf_hash || key_version(0x00) || codesep_pos`. `codesep_pos` is
  the opcode position of the last executed `OP_CODESEPARATOR` (or `0xffffffff`), counting every
  parsed opcode (executed or not). Because `bitcointx.bip341.sigMsg` is key-path-only (hard-coded
  `spend_type = 0x00`, no extension), this module rebuilds the common message; its `ext_flag = 0`
  prefix is cross-checked byte-for-byte against that KAT-backed function (`tapscript.zig`). A future
  DRY refactor lifting a shared `commonSigMsg` into `bitcointx` is left for the interop backlog.

**Verification honesty**: the taproot *commitment* math and the SigMsg *common prefix* are backed by
external BIP341 vectors / `bitcointx`'s KAT-backed key-path sigMsg respectively. The end-to-end
tapscript *spends* (`tapscript_test.zig`) are **constructed round-trips** (build output → sign the
tapscript sighash → verify, each with a positive control), not byte-exact against an external
consensus transaction vector — **but this gap is now separately closed** by
`consensus_kat_test.zig`/`consensus_kat_vectors.zig` (2026-07-28): 5 real transactions
machine-extracted, byte-for-byte, from Bitcoin Core's own
`bitcoin-core/qa-assets:unit_test_data/script_assets_test.json` fuzz/unit corpus (the same corpus
`src/test/script_tests.cpp`'s `script_assets_test` runs), each with a `success` witness that MUST
verify and a `failure` witness (same tx/prevouts/flags) that MUST fail, run through the real
`verifyScript` entry point (full tx deserialization + all inputs' spent outputs, not a stand-in).
Covers: plain key-path spend, a script-path spend with an annex, an `OP_SUCCESSx` short-circuit, a
control-block length-validation failure, and the unknown-leaf-version anyone-can-spend path. This
is a representative slice, not exhaustive coverage of the corpus (2244 entries total) — widening it
is left for the interop backlog.

`FindAndDelete(vchSig)` (the historical per-signature literal-byte-removal quirk in `SignatureHash`,
distinct from `FindAndDelete(OP_CODESEPARATOR)`, which IS implemented) is also out of scope — see
`bitcointx`'s own `sighash_legacy.zig` module doc comment for the same cut and its rationale; no
standard script template ever needs it, and the `script_tests.json` subset pinned below excludes
every vector that would.

## Verification

### script_tests.json coverage

`script_tests_vectors.zig` pins 296 rows machine-filtered (not hand-picked) from Bitcoin Core's
official `src/test/data/script_tests.json` (fetched 2026-07 from the `bitcoin/bitcoin` `master`
branch), then machine-transcribed verbatim via a one-off Python script — never hand-typed. The
filter: keep only rows (a) with no witness field (this module's segwit/taproot coverage is
verified separately, by `e2e_test.zig`'s real spends, rather than transcribing the witness-bearing
subset of the JSON, which is small and largely tapscript-flavored); (b) whose `scriptSig`/
`scriptPubKey` asm text uses only mnemonics this module's opcode table implements (a plain
substring/token check — this mechanically excludes every BIP342 tapscript-only vector); (c)
without `OP_CODESEPARATOR` (sidesteps `FindAndDelete(vchSig)`, out of scope — see above); (d)
without the `CONST_SCRIPTCODE` flag (not modeled, same reason). From the ~1108 rows surviving
that filter, every row is kept for buckets with ≤20 members (every distinct error class Bitcoin
Core's test suite exercises that this module can reach), and a fixed-seed random sample of 70 `OK`
rows / 20 rows for buckets larger than 20 (`EVAL_FALSE`/`BAD_OPCODE`/`INVALID_STACK_OPERATION`/
`DISABLED_OPCODE`/`SCRIPTNUM`/`MINIMALDATA`/`SIG_DER`).

`script_tests_test.zig` assembles each row's asm text (`asmparser.zig`, a transcription of
Bitcoin Core's own `ParseScript`) into script bytes, reproduces Bitcoin Core's EXACT synthetic
crediting/spending transaction pair (`script_tests.cpp`'s `BuildCreditingTransaction`/
`BuildSpendingTransaction` — this is what makes the CHECKSIG-bearing vectors meaningful: their
signatures were computed against precisely this pair), runs `verifyScript`, and asserts the
result's CLASS matches (`OK` vs. the JSON's named error, mapped 1:1 to this module's error names
— e.g. `SCRIPTNUM` → `UnknownError`, the class Bitcoin Core itself folds arithmetic-`CScriptNum`
overflow/non-minimality into via its generic exception catch, distinct from the dedicated
`MinimalData` class which is push-opcode minimality only).

Three real bugs were caught and fixed by getting these 296 rows green (not merely by unit tests of
each function in isolation) — each is exactly the kind of subtle cross-cutting mistake a
"synthesize opcodes independently, believe the docs, never run the official corpus" approach would
have missed:

1. **`isValidSignatureEncoding`'s length arithmetic** (BIP66's exact byte-count check) is written
   against the FULL popped stack element (DER bytes + trailing sighash-type byte) — Bitcoin Core's
   own `IsValidSignatureEncoding` takes `vchSig` exactly as popped, hashtype included. Calling it
   with DER-only bytes (excluding the hashtype byte) undercounts by one and rejects every
   otherwise-valid signature the instant `DERSIG`/`LOW_S`/`STRICTENC` is set (i.e. on almost every
   vector in the corpus).
2. **`OP_CHECKMULTISIG`'s pubkey/signature walk order was reversed.** Bitcoin Core walks both
   blocks starting from the TOP of their stack region (the LAST-pushed pubkey/signature first),
   not push (script-reading) order — `stacktop(-ikey)` with `ikey` initialized just past the
   popped count and incrementing toward the bottom. A 1-of-2 multisig with an invalid second
   pubkey exposed this: with the (wrong) forward order the valid first pubkey matches immediately
   and the loop exits before ever examining the invalid second key, silently passing; Core (and,
   after the fix, this module) tries the invalid key FIRST and fails closed with `Pubkeytype`.
3. **`OP_CHECKMULTISIG`'s early-bail condition must run every loop iteration, not only after a
   signature match.** The condition ("remaining required signatures now exceed remaining
   available keys → can never succeed → stop") is what keeps the loop's key index in bounds when
   NO signature ever matches (e.g. every supplied "signature" is the empty string) — gating it on
   "only check after a match" leaves nothing to terminate that case, walking the key index past
   the end of the pubkey array. Caught by a real BIP66/NULLFAIL-compliance vector in the corpus
   whose scriptSig supplies only empty elements.
4. `OP_IF`/`OP_NOTIF`'s `MINIMALIF` check is gated on `sigversion == WITNESS_V0` in Bitcoin Core,
   not on the flag alone — a base/legacy-context script with the `MINIMALIF` flag set and a
   non-minimal boolean must reach `EVAL_FALSE`, not fail closed with `MinimalIf` at the `IF`
   itself. Caught by a corpus vector combining `P2SH,WITNESS,MINIMALIF` with a base-context (not
   witness-program-shaped) `scriptPubKey`.
5. `OP_CHECKSIG`'s encoding checks (signature DER/hashtype, pubkey compressed/uncompressed shape)
   must run even when the signature is the empty string — Bitcoin Core's
   `CheckSignatureEncoding(vchSig,...) && CheckPubKeyEncoding(vchPubKey,...)` are two independent,
   unconditionally-evaluated checks ANDed together, not a short-circuit on the signature alone (an
   empty signature trivially PASSES `CheckSignatureEncoding` — it's `CheckPubKeyEncoding` that can
   still fail on a malformed pubkey next to it). Caught by a P2PK vector with a truncated
   uncompressed pubkey and a deliberately-empty scriptSig, expecting `Pubkeytype`.

### End-to-end real spends (`e2e_test.zig`)

Three real, self-signed spends, each verified through the SAME code path a production caller
would use (`bitcointx` sighash → `sigcheck`/`bip340.verify` curve check), with a positive control
(a one-byte-tampered signature must fail):

- **P2PKH** — `std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256` keypair, legacy sighash, DER signature
  (BIP62-low-S-normalized, since the raw signer doesn't do this automatically and `ScriptFlags.standard`
  enforces `LOW_S`), `OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG`.
- **P2WPKH** — same keypair shape, BIP143 sighash (with the correct implicit P2PKH-shaped
  scriptCode), 2-item witness stack.
- **P2TR key-path** — `bip340` keypair, BIP341 sighash (`SIGHASH_DEFAULT`), BIP340 Schnorr
  signature, single-item witness stack. Uses the internal key directly as the taproot output key
  (no BIP341 tweak) — legitimate for consensus purposes (BIP341 does not require a script-tree
  tweak), and orthogonal to what this test checks (sighash + Schnorr correctness, not the tweak
  procedure, which is a spender/wallet-side construction concern).

### DoS teeth (`interpreter.zig` + `dos_test.zig`)

`interpreter.zig`'s own tests: script size, op count (including the "hidden inside a never-taken
`IF` branch" case), single-push size, and aggregate stack size, each proven to fail closed with
the specific typed error, no OOM/panic. `dos_test.zig` adds `verifyScript`-level teeth: witness
item count, an oversized P2WSH stack-seed item, an oversized P2WPKH witness item, and confirms a
P2SH redeem script (bounded to `MAX_SCRIPT_ELEMENT_SIZE` as a *push*, independent of its own
`MAX_SCRIPT_SIZE` ceiling once *executed*) round-trips correctly at the boundary.

## Flags

`ScriptFlags` mirrors Bitcoin Core's `SCRIPT_VERIFY_*` set field-for-field; every field's doc
comment in `flags.zig` states exactly what it gates. This now includes the three tapscript
standardness/policy flags — `discourage_op_success`, `discourage_upgradable_pubkeytype`,
`discourage_upgradable_taproot_version` — which reject (as non-standard) the consensus-valid BIP342
upgrade hooks (`OP_SUCCESSx`, unknown CHECKSIG pubkey types, unknown leaf versions). All three are
`false` in `.none` and `true` in `.standard`.
