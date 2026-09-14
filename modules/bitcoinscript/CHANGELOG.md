# bitcoinscript — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-15** — **Internal only, no behaviour change:** `sigcheck.zig`'s private
  `reduceToScalar` + `ecdsaVerifyDigest` (a byte-for-byte copy of
  `k256.sign.ecdsaVerify`'s arithmetic, minus the internal SHA-256, because
  Bitcoin's OP_CHECKSIG digest is already-hashed) are gone. `checkEcdsaSig`
  now calls the new `k256.sign.ecdsaVerifyPrehashed` (A1 `k256` G4, perf
  pass, round-2 decision Q4, both sides one commit) instead of carrying its
  own copy of the verify core — a future fix to that arithmetic (e.g. a
  Wycheproof-anchored `r`/`s ≥ n` guard, `k256` G3) now only has to be made
  once. `scripts/modtest bitcoinscript`: 91/91 before and after, Debug and
  ReleaseFast.

- **2026-09-09** — Docs: `NOTICE` named ONE vendored corpus; the module has **five**, and one
  of them comes from a repository the file had never heard of. Added:
  `src/script_tests_witness_vectors.zig` (the 107 witness-bearing rows of Core's
  `script_tests.json`), `src/tx_findanddelete_vectors.zig` and `src/tx_locktime_vectors.zig`
  (the `FindAndDelete`/`OP_CODESEPARATOR` and BIP65/BIP112 rows of `tx_valid.json` +
  `tx_invalid.json`), and `src/consensus_kat_vectors.zig` — which is from
  **`bitcoin-core/qa-assets`**, a separate MIT repository, not from `bitcoin/bitcoin`. Its
  upstream copyright line is literally `Copyright (c) 2018 ` with no holder after the year;
  the attribution names the project rather than inventing a person, and the absence is
  recorded. Two pins were branch names and are now the `v29.0` tag the generated files
  actually record. The MIT text is now reproduced. No code or data changed.
- **2026-09-07** — **Test-only, two harnesses, and two recorded audit fixes
  that had never executed.** (a) `verify.fuzzVerifyScript` had NO corpus, so
  the ordinary test lane ran exactly one round of `in = ""` and every `Smith`
  draw returned its minimum: `head_len` 0, `total` 0, `n_witness` 0, and all
  twenty `ScriptFlags` booleans `false` —
  `verifyScript(a, "", "", &.{}, .{}, ctx)`, one input, for ever. **Both fixes
  the comments there record — the `inline for` over the flag struct "so a flag
  added later is drawn without anyone remembering to come back here", and the
  long-script builder that walks the 201-opcode / 1000-element / 10 000-octet
  limits from both sides — sat behind draws that had already collapsed, and
  neither had ever run.** Measured 2026-09-07: 1 input, 0 script octets, 0
  witness items, 0 flags set. (b) `tapscript_test.fuzzTapscriptLeaf` had a
  corpus, built by `tapscriptSeed(bits, 512)` writing one little-endian `u64`
  per draw with every word masked to `& 0x0F`. That kept each word inside its
  range so the harness did run — but it capped **every** choice at 15: the
  leaf script was never longer than 15 octets against a 256-octet buffer, and
  any range later widened past 15 would collapse silently with the suite
  green. Both now read their choices from one `smith.slice` through
  `testkit.fuzz.Cursor`, so a seed is a reviewable octet script.
  Measured after: **verifyScript — 13 of 14 seeds non-empty, 39 141 script
  octets, 18 witness items, 102 flag booleans set, 8 seeds over 200 opcodes, 3
  at the 10 000-octet limit and 1 witness element past the 520-octet push
  bound, every one of which was 0 before. Tapscript — longest leaf 15 → 255
  octets, 404 leaf octets, 7 stack items, and 11 of 15 seeds on which the
  harness's own `TaprootCommitmentMismatch` assertion is armed.**

- **2026-09-02** — **Audit (drift campaign): 1 HIGH fixed, 2 LOW recorded.**
  **HIGH — the condition stack was scanned on every instruction, so a tapscript leaf was
  quadratic in its own length.** `allExecuting` walked a `bool` list end to end for each opcode,
  where Bitcoin Core's `ConditionStack::all_true()` is a single comparison. BIP342 removes both
  `MAX_OPS_PER_SCRIPT` and `MAX_SCRIPT_SIZE` for a leaf, so the nesting depth is whatever the
  spender wrote, and the work is spent before any verdict is reached. Measured in ReleaseFast on
  a leaf of `OP_1 OP_IF` repeated: 100 KB → 0.91 s, 200 KB → 3.68 s, 400 KB → 14.5 s, 800 KB →
  57.2 s, **1.6 MB → 237 s of one core** — ×4 per doubling. Isolated by a control that keeps
  length, opcode count and stack depth identical and only changes the condition VALUES
  (`OP_0 OP_IF`): 16.87 s vs 9.2 ms, a 1835× gap, so the cost is the scan and not the
  allocation. Replaced with Core's shape — depth plus the position of the first `false` — which
  makes `allTrue`, `push`, `pop` and `toggleTop` all O(1). Pinned by a differential against the
  naive scan over 20 000 random operations, and by a wall-clock ceiling on a 200 000-level leaf
  with three orders of magnitude of headroom (the mutation that restores the scan takes **282
  seconds** and fails it). ⚠ Not in the drift window: the shape is as old as the file, and the
  previous audit's B1 result ("no accidental quadratic in the dispatch itself") did not reach it.
  **Recorded, NOT fixed — two error-class divergences from Core**, both of which reject the same
  scripts and differ only in which error they name: a `CHECKMULTISIG` with a missing dummy
  element raises `SIG_FINDANDDELETE` here where Core is believed to raise
  `INVALID_STACK_OPERATION`, and `OP_VERIF`/`OP_VERNOTIF` are rejected before the op-count meter
  rather than after. ⛔ Left alone deliberately: both rest on Core's ordering as remembered
  rather than on `interpreter.cpp` (no network on the audit host), and changing the error
  ordering of a consensus interpreter on an unverified premise is worse than the divergence.
  Ledger: `~/CML/20260931-zig-libs-audit/bitcoinscript.md`.

- **2026-08-06** — Security audit: the interpreter appeared to omit Bitcoin Core's
  legacy `FindAndDelete` sighash step for a class of legacy scripts, which looked like
  it could yield a different validity verdict than Core; investigation found the
  mechanism could not actually diverge in practice, but the code was still changed to
  mirror Core's exact behaviour, and 9 further findings were fixed.
- **2026-07-21** — New module: Bitcoin Script consensus interpreter (VM).
