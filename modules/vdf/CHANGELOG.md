# vdf — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-06** — **BREAKING: the VDF now works in the quotient group
  Z_N*/{±1}, as Wesolowski over an RSA group must** (A1 audit F1, with F2
  and a test for F3). `-1 = N-1` has order 2 in Z_N* and the Fiat-Shamir
  prime `l` is always odd, so `(N-π)^l · x^r = N - y`: for every honest
  `(y, π)` the pair `(N-y, N-π)` verified too, and a prover could publish
  whichever of the two "outputs" it preferred — 38 of 38 such forgeries were
  accepted, at the cost of one `eval` plus two `prove`s and no knowledge of
  `N`'s factorization. A beacon publishing `H(y)` handed the prover one
  adaptively chosen bit per round. Boneh–Bünz–Fisch §6 (and every shipped
  RSA-group VDF) quotient `-1` away; this module did not.

  Now: `eval` returns `min(y, N-y)` (`group.canonicalize`), `prove` returns
  `min(π, N-π)`, and `verify` (a) refuses a `y` or `π` that is not the
  representative of its class rather than folding it — a folding verifier
  would hand a caller hashing the raw bytes the two-valued output straight
  back — and (b) compares `π^l · x^r` with `y` in the quotient. `prove`
  refuses a non-canonical `y` with `error.InvalidElement`. New in `group`:
  `negate`, `canonicalize`, `isCanonical`, `isIdentityClass`.

  **What changes on the wire.** An `eval` output or a proof whose raw value
  lay above `N/2` is now its negation; a proof produced before this entry
  verifies iff both its `y` and `π` happened to be below `N/2` (1 in 4).
  The module has no in-tree consumer. The three RSA-2048 `eval` KAT vectors
  are unchanged (all three values lie below `N/2`); the toy-modulus vector
  in `kat_test.zig` now pins the fold explicitly (raw `833421283368` →
  `166564716581`).

  **Also refused (F2):** an input `x ∈ {1, N-1}` — the quotient's identity,
  on which `eval` is constant in `T` and "a proof of 10^18 sequential
  squarings" was accepted in 6.3 ms. `verify` returns `false`, `prove`
  `error.InvalidElement`. `T = 0` is still the identity map and is not
  refused; a caller who needs a minimum delay enforces it on `T`.

  **F3, partially:** `isProbablePrime` now has a test that the 16 strong
  pseudoprimes to base 2 below 10^5 are rejected under the production
  witness stream (a fixed base-2 witness would pass them all), and the
  round count is pinned to the repo-wide 64 by name — a tripwire, since no
  value test can observe the difference between 64 and 32 random witnesses.

  Regression: the negation forgery in every sign combination (`vdf.zig`),
  a counted check that at least one raw `π`/`y` above `N/2` was folded and
  still verifies, the identity-class refusal, and a separate pin that
  `verify` rejects rather than folds. The `Proof.fromBytes` fuzz harness
  uses `smith.slice` and carries three boundary seeds (it saw one empty
  input before).

- **2026-07-18** — Security audit: two findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Verified: `eval` is byte-exact vs an
  independent Python `pow(5,2T,N)` oracle at T=1/5/1000 over the real RSA-2048 challenge
  modulus (`kat_test.zig:60-123`).
- **2026-07-16** — New module: Wesolowski Verifiable Delay Function over an RSA
  hidden-order group `Z_N*` (Wesolowski, IACR ePrint 2018/623).
