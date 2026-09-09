# adaptor — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-09** — **NO CONSUMER-VISIBLE CHANGE:** `src/ctgrind_harness.zig` is added (A1 audit finding R2; the tier-A ctgrind queue, 28 modules). Measured ReleaseFast under valgrind, in-file contexts: **presign 90 / adapt 2 / extract 3**. Every target has an untainted control row and a no-`-fvalgrind` trap row, both 0, so the numbers are real taint propagation rather than a silent no-op. 74 of `presign`'s 90 are the mandatory step-9 self-check calling `preVerify`, which `SPEC.md` itself documents as appropriate variable-time on public data — the same self-verify shape as `bip340` and `musig2`. The 16 direct contexts are accepted classes (`isZero` nonce rejection, `rejectIdentity`, scalar canonicality). ⚠ ONE CONTEXT IS DELIBERATELY LEFT UNRESOLVED: `root.zig:338`, the masked-select loop SPEC calls constant-time, produced one "Use of uninitialised value of size 8" (not "Conditional jump"). The source has no branch there, so the likely explanation is LLVM vectorising the byte loop and memcheck checking the 8-byte load conservatively — but that is a guess, no disassembly was run, and this claim is not closed until someone does one.

- **2026-09-07** — **Test-only: the "corrupted pre-signature" fuzz target had
  never corrupted anything.** `fuzzPreVerify` opened with
  `n_flips = smith.valueRangeAtMost(u8, 0, 6)`, and a ranged `Smith` draw reads
  eight octets as a little-endian `u64` and returns the range MINIMUM unless
  that whole word already lies inside the range. With no corpus, the ordinary
  test lane runs exactly one round of `in = ""`, so `n_flips` was 0 and the
  harness verified vector 0's **pristine** pre-signature, unmodified, on every
  run it ever made. Measured 2026-09-07: 1 input, 0 flips, 0 `fromBytes`
  refusals, 0 rejections. The flips now come out of one `smith.slice` read as
  a script, with a 13-seed corpus naming which of the three wire fields it
  damages — `r` at 0..32, `s_prime` at 32..64, and the negation flag at 64,
  including the flag set to a value that is neither 0 nor 1. Measured after:
  **11 of 13 seeds produce an encoding that differs from the pristine one, 2
  are refused by `fromBytes`, 2 verify and 9 are rejected.** ⭐ An
  `accepted > 0` guard would have scored the OLD harness at 100%, since its one
  input was the untouched vector and it verifies; the guard pins the decode
  refusals and the rejections instead, neither of which the pristine encoding
  can produce.

- **2026-08-14** — Test-only: `kat_test.zig` gained a `testing.fuzz` harness on
  `preVerify` (corrupted `PreSignature` bytes against a fixed valid pubkey/
  message/adaptor point) — `zig build check-fuzz` no longer names this module.
  No panic/OOB found; **neither breaking nor behavioural**.
- **2026-07-18** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on
  `secp256kfun schnorr_fun::adaptor` (Rust, named design ref) (design reference, not a
  test anchor).
- **2026-07-12** — New module: Schnorr adaptor signatures (scriptless scripts / the
  crypto behind Lightning PTLCs + atomic swaps) over BIP340.
