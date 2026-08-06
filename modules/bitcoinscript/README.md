# bitcoinscript

Pure-Zig **Bitcoin Script interpreter / consensus VM**: a stack machine covering push/flow-control/
stack/arithmetic/crypto opcodes, `OP_CHECKSIG`/`CHECKMULTISIG`/`CHECKSIGADD`/`CHECKLOCKTIMEVERIFY`/
`CHECKSEQUENCEVERIFY`, and a top-level `verifyScript` orchestrating legacy, BIP16 P2SH, BIP141
segwit v0 (P2WPKH/P2WSH), and BIP341/342 taproot **key-path and script-path (tapscript)** spends.

- Published consensus rules with an official byte-exact test-vector corpus (Bitcoin Core's
  `script_tests.json`) and this repo's own `bitcointx`/`k256`/`bip340`/`ripemd160` siblings
  supplying transaction parsing, sighash algorithms, and curve arithmetic — no reason to invent
  anything from scratch. See `SPEC.md` for the full design/threat-model writeup and scope cuts.
- **Executes UNTRUSTED scripts.** Every consensus DoS bound (script/push/stack size, op count,
  pubkey count) is enforced before the resource it bounds is consumed; every malformed or
  adversarial input is a typed error, never a panic. See `SPEC.md` "Threat model / DoS bounds".
- **Platform:** any — pure computation over caller-owned bytes, no I/O.
- **Model after:** Bitcoin Core `script/interpreter.cpp` (and `script_tests.json` as its own
  conformance corpus); BIP16/62/65/66/112/141/142/143/144/146/340/341/342.

## Scope

Implemented:

- **Full opcode set** except the disabled splice/bitwise/wide-arithmetic opcodes (`CAT`/`SUBSTR`/
  `LEFT`/`RIGHT`/`INVERT`/`AND`/`OR`/`XOR`/`2MUL`/`2DIV`/`MUL`/`DIV`/`MOD`/`LSHIFT`/`RSHIFT`),
  which Bitcoin Core itself disables — attempting one is `error.DisabledOpcode`, not a silent skip
  (in a **tapscript** leaf these same bytes are `OP_SUCCESSx` instead — see below).
- **Templates**: bare P2PK/P2PKH/multisig, BIP16 P2SH (including a P2SH-wrapped segwit v0
  program), BIP141 P2WPKH/P2WSH, BIP341 P2TR **key-path**, and BIP341/342 P2TR **script-path
  (tapscript)** — control-block/tapleaf/Merkle-root/tweak commitment check + leaf execution with
  BIP340-Schnorr `OP_CHECKSIG`/`OP_CHECKSIGADD`, the `OP_SUCCESSx` short-circuit, the
  validation-weight budget, and mandatory MINIMALIF (`SPEC.md` "BIP342 tapscript").
- **`ScriptFlags`** mirrors Bitcoin Core's `SCRIPT_VERIFY_*` set: `p2sh`, `dersig`, `low_s`,
  `strictenc`, `nulldummy`, `discourage_upgradable_nops`, `cleanstack`, `checklocktimeverify`,
  `checksequenceverify`, `witness`, `discourage_upgradable_witness_program`, `minimalif`,
  `witness_pubkeytype`, `nullfail`, `minimaldata`, `taproot`, `sigpushonly`,
  `const_scriptcode`, `discourage_op_success`, `discourage_upgradable_pubkeytype`,
  `discourage_upgradable_taproot_version`.

## Use

```zig
const bitcoinscript = @import("bitcoinscript");
const bitcointx = @import("bitcointx");

// The spending transaction, the input being verified, and every input's
// spent output (BIP341 taproot sighashing needs all of them, not just the
// one being signed).
const ctx: bitcoinscript.TxContext = .{
    .tx = spending_tx,
    .input_index = 0,
    .spent_outputs = spent_outputs, // []const bitcointx.TxOut, one per spending_tx.vin entry
};

// witness: the input's witness stack (&.{} if the spend has none).
bitcoinscript.verifyScript(
    allocator, // arena recommended -- see SPEC.md "Allocator contract"
    script_sig,
    script_pubkey,
    witness,
    bitcoinscript.ScriptFlags.standard, // or build a specific combination -- see flags.zig
    ctx,
) catch |err| {
    // err is a typed ScriptError/VerifyError variant (EvalFalse, SigDer,
    // CleanStack, WitnessProgramMismatch, ScriptSize, ...) -- never a panic.
    return err;
};
// returns normally: the spend is valid under the given flags.
```

Calling the interpreter directly (rare — `verifyScript` is the normal entry point) for e.g.
tooling that wants to run one script segment in isolation:

```zig
const bitcoinscript = @import("bitcoinscript");
var stack: std.ArrayList([]const u8) = .empty;
try bitcoinscript.interpreter.eval(allocator, &stack, script_bytes, ctx, .base, flags);
```

### Public API surface

- `verifyScript(allocator, script_sig, script_pubkey, witness, flags, ctx) VerifyError!void`
- `ScriptFlags` (`flags.zig`) — `.none`, `.standard` presets; every field individually documented.
- `TxContext` / `SigVersion` (`txctx.zig`).
- `Opcode` (`opcodes.zig`) — the byte/mnemonic table, for tooling that wants to name a byte.
- `EvalError` / `VerifyError` — typed error sets; every failure mode Bitcoin Core's
  `script_tests.json` names has a corresponding variant (see `SPEC.md` "script_tests.json
  coverage" for the exact name mapping).
- `interpreter`/`sigcheck`/`number`/`limits` submodules, for callers that need a lower layer
  directly (a custom template dispatcher, a fuzzer targeting `eval` alone, …).

## Verify

```sh
zig build test-bitcoinscript --summary all
```

296 pinned rows from Bitcoin Core's official `script_tests.json`, real end-to-end spends
(P2PKH/P2WPKH/P2TR key-path plus BIP342 tapscript script-path: `OP_CHECKSIG`, `OP_CHECKSIGADD`
threshold, `OP_SUCCESSx`, empty-sig, and validation-weight exhaustion — `tapscript_test.zig`),
BIP341 wallet-test-vector KATs for the taproot commitment (`tapscript.zig`), and DoS-bound teeth —
see `SPEC.md` "Verification" for what's pinned and why, including three real cross-cutting bugs the
official corpus caught that isolated unit tests did not.

Provenance: the interpreter is clean-room from the published consensus rules and
the BIPs — no Bitcoin Core source is ported. ⚠ But `script_tests_vectors.zig`'s
rows are machine-transcribed (not hand-typed) from `bitcoin/bitcoin`'s
`src/test/data/script_tests.json`, so this module **reproduces third-party test
data** and carries its own [`NOTICE`](NOTICE) beside it (MIT; the same shape as
`decimal`'s decTest corpus — a preserve-the-notice requirement, no condition
beyond MIT's own). See that vectors file's doc comment and `SPEC.md` for the
exact filter/sampling method.
