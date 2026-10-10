# xmss — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-10** — tests: deterministic fuzz driver `XMSS_FUZZ` (`xmss-verify`, `xmss-pubkey`, `xmss-sign-verify`, new `src/fuzz_test.zig`; the Smith harnesses in `root.zig` are unchanged), XMSS-SHA2_10_256: key / message / signature each intact or damaged -- only the intact triple verifies, wild triples never; `PublicKey.fromBytes` re-encodes what it accepts; signatures from a stateful key verify, and a flipped octet, a truncation, an extension, another message, another root or seed do not. No change in `src/` outside tests.
- **2026-10-10** — Constant time: new `src/ctgrind_harness.zig` (target `sign`, ReleaseFast): `SK_SEED` and `SK_PRF` are tainted through `keyGen` and five `sign`s, including the BDS updates, at tree height 4. The 2 in-file contexts are the WOTS chain loop, whose count comes from `H_msg` over `r = PRF(SK_PRF, idx)`. `r` is published in the signature, so this is a tainting artefact, not a leak. No code change.
- **2026-10-09** — the public WOTS+ building blocks `prfKeygen`, `wotsSkGen`, `wotsPkGen`, `wotsSign` and `genLeaf` now run under their own burns (`prf_burn` 2 KiB for the per-chain ones, `burn_size` for the one-shot ones; nested inside `keyGen` / `sign` they only add zeroing). `hashF` / `hashH` / `prf` (KEY is the public SEED), `rootFromSig` (verify path) and `SigningKey.sign` (thin guard) are marked for the dead-stack lint. No signature changed. Probe: `src/stackprobe2_test.zig`.
- **2026-10-09** — **BREAKING + FIX (HIGH, secrets on the dead stack, dead-stack sweep wave 5):**
  no secret travels by value any more. `keyGen` took `sk_seed` / `sk_prf` BY VALUE and returned
  the whole `KeyPair` (private key included) by value; `prfKeygen`, `wotsSkGen` (the ≈ 2 KiB WOTS+
  private key), `chain` and `chainStep` took or returned chain values by value, and
  `SigningKey.init` took the `SecretKey` by value. New stack probe (`stackprobe_test.zig`, 5 calls,
  16-byte windows of `SK_SEED`, `SK_PRF` and every chain value of every leaf of an h = 4 key,
  NEG/POS controls), ReleaseFast: **before** — `keyGen` left 10 windows of `SK_SEED` and 10 of
  `SK_PRF` over 5 calls, 231..279 B below the call (the by-value argument and return copies
  in the caller's side of the frame); `sign` at leaf 0 / leaf 5 and `buildAuth` 0 (the A1 F3 burn
  already covered the callee frames). **After** — 0 for all four, NEG = 0, POS ≥ 1.
  API (out-param first, `*const` for secret inputs):
  `keyGen(kp: *KeyPair, sk_seed, sk_prf, pub_seed: *const [n]u8) void`;
  `prfKeygen(out: *[n]u8, sk_seed, pub_seed, adrs)`;
  `wotsSkGen(sk: *[wots_len][n]u8, sk_seed, pub_seed, adrs)`;
  `chain(x: *[n]u8, start, steps, pub_seed, adrs) void` and `chainStep(x: *[n]u8, …) void`, both IN
  PLACE (a chain value is secret below the chain's public end); `SigningKey.init(dst, sk: *const
  SecretKey, persist)`; `wotsPkGen`, `wotsSign`, `genLeaf` keep value returns (their results are
  the public key, the public signature and a public leaf). `sign` and `buildAuth` already took
  pointers. The burn moved to `burn.zig` (`run`/`stack`, `keyGen`/`sign`/`buildAuth` run their
  body one frame down); real depth at h = 4 in ReleaseFast: `keyGen` 5.9 KiB, `sign` 8.2 KiB
  (8.4 KiB with a traversal rebuild), `buildAuth` 5.9 KiB; burn 16 KiB (was 32 KiB). The old
  in-`root.zig` F3 test is replaced by the probe. Migrate: `var kp: X.KeyPair = undefined;
  X.keyGen(&kp, &sk_seed, &sk_prf, &pub_seed);` and `SigningKey.init(&h, &kp.sk, …)` then
  `kp.sk.zeroize()`.
- **2026-10-08** — **FIX (secrets on the dead stack):** the dead-stack burn's buffer is now
  16-aligned instead of the vector type's natural 32. At 32 the burn's frame was realigned, and
  the up to 56 bytes between its saved frame pointer and the buffer — the top of the frame the
  burned body had used — stayed unzeroed (found by `threshold_ecdsa`'s stack probe: half of a
  secret survived there). No API change.
- **2026-10-08** — **NO CONSUMER-VISIBLE CHANGE (speed):** the dead-stack burn zeroes with
  volatile 32-byte vector stores instead of `std.crypto.secureZero` (a volatile byte memset,
  ~3 B/ns without libc): ~30× faster per KiB burned. Same size, same depth; the ReleaseFast stack
  probe still reads 0.
- **2026-10-06** — **NO CONSUMER-VISIBLE CHANGE:** SPEC consistency: Compared with no longer says no LMS/HSS module exists — it points to the sibling `lms` module (grade 2).
- **2026-10-05** — Mutation run: 23 of 24 killed, 1 equivalent; 1 test extended
  (the external-vector KAT rejects 2048 tampered randomizers, so `verify`'s
  root comparison must cover every byte). No code change.

- **2026-10-01** — `SigningKey.Persist.io`: the `Io` the persist hook blocks in. With it, `SigningKey.sign`
  guards with an `std.Io.Mutex`, so a second signer parks instead of spinning on one suspended
  in the hook — required when the `Io` runs several tasks on one thread. Without it, unchanged.
  Found by the spinlock audit that followed the simio kv pilot.
- **2026-09-15** — A1 F3. Security fix, no API change: WOTS+ chain values
  survived on the dead stack after `keyGen` and `sign` — measured at
  ReleaseFast, `keyGen` left 49, `sign` 47 per call at leaf 0 and 49 after a
  jump to leaf 5 (identical on the audited tree), and a leaf's chain values
  forge a message at that leaf's index. The 2026-09-11 `chain` pointer change
  alone changed none of it. `keyGen`, `sign` and `buildAuth` now run their
  computation one frame down and zero 32 KiB of stack below it before
  returning (`burnStack`; the call trees reach ~10 KiB at h=4 and h=10). The
  dead-stack test used to print one count for leaf 0's chain starts; it now
  asserts zero residue for every chain value of every leaf and both secret
  seeds, beside a negative and a positive control, after `keyGen`, after
  `sign` at leaf 0 and after `sign` with a traversal rebuild to leaf 5. The raw
  WOTS+ primitives (`wotsSkGen`, `wotsSign`, `wotsPkGen`, `genLeaf`, `chain`)
  do not burn.

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
