# bip340 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-10** — **NO CONSUMER-VISIBLE CHANGE:** A1 audit F1/F2 (HIGH). F1:
  added a regression test that crafts a cancelling forged pair (two
  individually-invalid signatures, `s1+delta`/`s2-delta`) and asserts
  `verifyBatch` rejects it — previously no test could tell the shipped random
  linear-combination coefficients from a mutant that hard-codes `a_i = 1`
  (measured: reverting to the mutant turns the new test RED, 28/29, while the
  rest of the suite stays green; the shipped code is 29/29). F2: two 32-byte
  copies of secret-scalar candidates inside `KeyPair.fromSecretKey`
  (`effective`, the chosen value, and `negated = n-d`, the unchosen one) are
  now explicitly `secureZero`d before return, closing the "return-slot" gap
  the audit named — free, and no observable behaviour changes. Also added
  `src/stackprobe_test.zig` (ReleaseFast-only, diagnostic print, not an
  assertion) porting the audit's stack-residue probe into the module per
  `CONVENTIONS.md` §9; see the F2 disposition in `A1/bip340.md` for why it
  stays open despite the fix (today's harness measures 0 copies of `d` both
  before and after, so no RED->GREEN transition was demonstrated).

- **2026-09-09** — **BEHAVIOURAL, not breaking:** `KeyPair.fromSecretKey`'s BIP340 step-3 even-y normalization (`d = d'` if `has_even_y(P)` else `n − d'`) is now a **constant-time masked byte select**, the same shape `sign`'s step-7 nonce normalization has used all along. It was a plain `if` on `xy.y.isOdd()`, so one bit — whether the stored secret is `d` or `n − d` — was observable in timing, while the structurally identical nonce-parity bit 140 lines below was carefully hardened. ⚠ **That bit is worthless to an attacker** (both representations sign identically, so it narrows a search from 2^256 to 2^255); it is hardened for consistency and because it is free, not because a leak was dangerous. Measured: ctgrind in-file contexts **80 → 79**, the signature `out_sha` unchanged, and 3+3 timing runs of `fromSecretKey` whose **spreads overlap** (38.7–39.5 µs vs 39.3–39.5 µs) — no cost this machine can resolve. ⭐ Also switched `scalar.neg(sk.bytes, .big) catch unreachable` to the non-failing `d.neg()`: the byte-slice form's `catch` is itself a branch memcheck reports, even though the input was validated a line earlier and it can never be taken. ⭐ For the record, the reference implementation branches here (`secp256k1_schnorrsig_sign_internal`) and its constant-time CI passes only because `secp256k1_keypair_load` declassifies the pubkey — a defence that does not transfer, since libsecp256k1's keypair exposes the full 33-byte pubkey while this module's is x-only.

- **2026-09-09** — **NO CONSUMER-VISIBLE CHANGE:** `src/ctgrind_harness.zig` is added (A1 audit finding R2; the tier-A ctgrind queue, 28 modules). Measured ReleaseFast under valgrind, in-file contexts: **sign 80**. Every target has an untainted control row and a no-`-fvalgrind` trap row, both 0, so the numbers are real taint propagation rather than a silent no-op. ⭐ 63 of the 80 come from the MANDATORY step-10 self-verify re-running the deliberately variable-time `verify` on the signature about to be returned; the real secret path (steps 1–9) is 15, none of it a class-1 leak. **The step-7 masked parity select measured ZERO contexts**, confirming SPEC.md's "no branch on `R.y`'s parity" for the first time. ⚠ One line is disputed and left open: `root.zig:165`'s even-Y normalisation in `KeyPair.fromSecretKey` is a plain `if`/`else`, not a masked select. This module's harness classified it as branching on the public key's parity; `taproot`'s agent classified it as a real leak and brought an experimental control (a second secret with an even-Y point dropped its count 12→11, because `neg` and its canonicality check appear only on the negating branch). BIP-340 public keys are x-only, so the parity is not published and `d`/`n−d` give the same `P` — "it's public" is false as stated. Recorded in `~/CML/20260901-zig-libs-audit/CTGRIND-OPEN-QUESTIONS.md`, not decided.

- **2026-09-07** — Fuzz reach: `fuzzVerify` never corrupted a signature. Its flip loop
  opened `smith.valueRangeAtMost(u8, 0, 6)` as the harness's FIRST draw; a `Smith` ranged
  draw reads eight octets as a little-endian `u64` and returns the range MINIMUM when
  fewer remain, and the target had no corpus, so outside `--fuzz` the one input it ever
  ran was empty and the flip count was **zero every time**. Every ordinary `zig build
  test` verified the pristine vector-0 signature — which the KAT tests above already
  assert — and no corrupted octet ever reached the `r < p` / `s < n` range checks or the
  curve-equation check the harness's own comment says the budget is spent near. Measured
  2026-09-07: 1 round, 0 octets flipped, 0 refusals from `Signature.fromBytes`. The flip
  loop is gone: a signature is 64 octets off the wire, so it is drawn with one
  `smith.slice`, and 12 written seeds carry the near-misses — vector 1's signature over
  the wrong message, r = p and r = p−1, s = n and s = n−1, r = s = 0, all-ones, two
  single-octet corruptions of the real signature, and a 63-octet short read.
  ⚠ A corpus guard pins **refusals**, not acceptances: `Signature.fromBytes` on 64 zero
  octets SUCCEEDS (0 is a canonical `Fe` and a canonical `Scalar`), so an "accepted > 0"
  guard would have read 100% over an empty corpus. Pinned: 11 non-empty, 3 refused,
  9 accepted, 1 verification.

- **2026-08-14** — Test-only: `kat_test.zig` gained a `testing.fuzz` harness on
  `verify` (corrupted signature bytes against a fixed valid pubkey/message) —
  `zig build check-fuzz` no longer names this module. No panic/OOB found;
  **neither breaking nor behavioural**.
- **2026-08-13** — `verifyBatch`'s randomizers `a_2..a_u` are now drawn from
  `io.randomSecure` instead of `Secp256k1.scalar.Scalar.random`, which
  draws from `io.random`. **Not breaking:** the signature is unchanged and
  so is the accepted set for any batch that verifies.

  This one is soundness, not secrecy, and it is the reason the module does
  not simply reuse the `entropy` module: an attacker who can predict the
  `a_i` can pick a batch of individually-invalid signatures whose errors
  cancel in the linear combination, so `io.random`'s documented degrade
  (`std/Io.zig:2462` — a pid-and-clock seed) is a forgery oracle here.

  On an entropy failure the batch is reported **unverified** (`false`)
  rather than aborting the process as `entropy.fill` would. `false` is
  already this function's answer on every failure path, nothing
  irreversible is minted, and single-signature `verify` needs no
  randomness at all — so a caller who gets `false` can re-check the items
  one at a time and lose only the batching speedup. That is the test
  `entropy.fill`'s own doc sets for when not to use it.

- **2026-07-28** — New `taggedHashRuntime`/`taggedHasherRuntime` — the BIP-340 tagged hash
  with a **runtime** tag assembled from parts, for callers whose tag is
  not comptime-known (BOLT#12's nonce leaf, BIP-341 leaf hashes). The
  comptime `taggedHash`/`taggedHasher` remain the fast path. New
  `xonlyBytesOf` (33-byte compressed → 32-byte x-only), also moved out of
  the sibling `lninvoice` module.
- **2026-07-18** — Security audit: no findings. Byte-exact against BIP340's published
  test vectors.
