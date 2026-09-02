# bitcoinscript — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
