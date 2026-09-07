# adaptor — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
