# xmss — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-11** — **BREAKING:** `chain`'s `x` parameter is now `*const [n]u8`
  instead of `[n]u8` by value (A1 audit F3 partial mitigation — removes one of
  `chain`'s two stack copies of the WOTS+ chain value; measured RED->RED, the
  finding stays open since `wotsSkGen`/`wotsSign`'s own whole-array copies
  dominate the residue, not this one). Any external caller passing `chain` a
  value directly now needs `&value` instead.
- **2026-09-07** — Test-only, no production change: `fuzzVerify` had never looked at a
  signature's content. It opened `smith.bytes(&sig_buf)` and then drew
  `smith.valueRangeAtMost(u16, 0, signature_length)`; a ranged `Smith` draw returns the
  range MINIMUM when fewer than eight octets remain, and `bytes` had already eaten them - so
  `len` was **0** on every input the ordinary lane ever ran and `verify` returned false off
  its `sig.len != signature_length` guard every round. The `idx`/`r`/`sig_ots`/`auth` parse
  the harness's own comment is entirely about had never run. Now one
  `smith.slice(&sig_buf)`, seeded from the module's own `keyGen` + `sign` (an XMSS
  signature that verifies is not reachable from arbitrary bytes) plus corruptions of the
  leaf index, the randomizer `r`, the top authentication-path node, the message and the
  public root. Measured by the new `corpus:` guard: **6 seeds at exactly
  `signature_length`** and so past the guard and into the WOTS+/authentication-path
  reconstruction (0 before), 1 accepted.

- **2026-09-03** — Drift re-audit (window `b199192..HEAD`, +1237/-37, `src/root.zig` +620). ⚠ **This
  changelog had no entry for the drift at all** — the BDS rewrite, the `SigningKey` handle,
  `zeroize()` and both fuzz harnesses were absent, including `SecretKey`'s layout going from the
  132-byte RFC private key to 1424 B at h=10, which is an ABI and persistence break for any
  existing caller. Recorded now, late. **BREAKING (minor):** `BdsState.covered_idx` now defaults to
  a not-synchronised sentinel rather than 0; `treeHash` is no longer `pub`; the supported height
  range is stated as 2..30.

  ⭐ The drift itself is a correctness and performance success, independently confirmed. All 16
  committed KATs were re-derived from the RFC text by an implementation written from scratch in
  Python (no reference code), byte-exactly — including the h=10 external interop triple. Sign cost
  at h=10 went from 1733.7 ms to **2.55 ms**, level with the wolfSSL C peer's ~2.75 ms. The BDS
  traversal is byte-exact against `buildAuth` over full lifetime sweeps at every height 2..9 and
  the complete 1024-leaf h=10 walk, and resync is byte-exact from a dirty state in both directions.

  - **HIGH, a key restored at index 0 signed garbage and burned the leaf.** `BdsState` has
    all-default fields, so `SecretKey{ …, .bds = .{} }` compiles — and that is exactly what a
    caller restoring a key writes, because SPEC.md described the private key as "4 seeds + a 4-byte
    index". With `covered_idx` defaulting to 0, a key restored **at index 0** — a new key persisted
    before its first signature, the most likely restore point of all — matched `idx`, so the resync
    did not fire: `sign` emitted the all-zero auth path, returned success, and consumed the leaf for
    a signature that does not verify. It never recovered, because `covered_idx` then tracks `idx` in
    lockstep. Every *other* index self-healed, and the existing jump test uses 1/5/11/15/32 — never
    0. Not index reuse and not forgery, but a signing primitive silently producing invalid output
    while irreversibly spending one-time keys. The sentinel makes "not synchronised" unrepresentable
    as "synchronised".

  - **MEDIUM, concurrent bare `sign` is now memory-unsafe, and the doc still described the milder
    hazard.** `sign` mutates `bds.stackoffset`/`stacklevels` as well as `idx`; two racing signers
    drive `stackoffset` to 0 while `stackusage > 0` and `stackoffset - 1` underflows a `u32` —
    integer-overflow panic in Debug, **SIGSEGV in ReleaseFast**. The pre-drift hazard was index
    reuse, which is what the module doc says. `SigningKey` closes it and its interlock has teeth;
    bare `sign` remains the documented default path, so the documentation is the fix.

  - **MEDIUM, `zeroize()` does not reach the last signature's WOTS+ one-time private key.** `chain`
    takes its input by value, so copies live in callee frames. Measured after `zeroize()`: 0 of 67
    recoverable in Debug, **55 of 67 in ReleaseFast**. Possession of leaf *k*'s WOTS+ private key
    permits forging an arbitrary message at index *k*, so a spent index is not harmless. Closing it
    needs a stack scrub at frame recycling — the same unsolved problem `std.crypto` has with its own
    key schedules — so it is stated in the doc and SPEC rather than mitigated.

  - **LOW, `treeHash` was `pub` with an assert-only `t <= h` bound** over a fixed `[h+1]` stack:
    `unreachable` in Debug and, in ReleaseFast, an out-of-bounds write that corrupted the loop state
    and never returned (killed at 600 s). Not attacker-reachable — no internal caller can pass a bad
    `t` — so it is now private rather than guarded.

  - **LOW, `XmssSha2(1, …)` was documented as supported and did not compile.** At h=1 the BDS
    `keep` array is empty and `keep[(tau - 1) >> 1]` fails as soon as `sign` is instantiated. The
    comptime floor is now 2.

  Doc: SPEC's "the private key is therefore 4 seeds + a 4-byte index" is the direct cause of the
  HIGH and now distinguishes secret material from `SecretKey`'s layout, with measured sizes; the
  resync is O(target·h), not O(2^h) as README and SPEC said — measured at h=10, a jump to the last
  leaf costs **4.9x a full keyGen**; and `BdsState` is now the largest fixed buffer, not the WOTS+
  arrays. **Provenance corrected:** README and NOTICE said "no source was read or ported" while
  `root.zig` and SPEC.md both say the BDS traversal *is* ported from the reference
  `xmss_core_fast.c` — two files in one directory making opposite claims about the same ~200 lines.
  Corrected to the code's own statement; xmss-reference is CC0, so the port carries no licence
  condition and what was wrong was the record.


- **2026-08-22** — SPEC.md records the CNSA 2.0 posture: NSA approves LMS and
  XMSS but excludes HSS and XMSS^MT, so this module's single-tree scope is the
  approved one and its omission is the excluded one. Also records what a
  software implementation cannot supply — CNSA requires signature *generation*
  and state management in validated hardware; only verification is servable
  from software.
- **2026-07-18** — Security audit: two findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Modeled on `XMSS/xmss-reference` (C,
  Huelsing et al.) (design reference, not a test anchor).
- **2026-07-12** — New module: XMSS — eXtended Merkle Signature Scheme (RFC 8391),
  single-tree, SHA-256 suite (`XmssSha2_10/16/20_256`) — a stateful hash-based
  signature: WOTS+ one-time sigs (chain/base-w/checksum), the L-tree.
