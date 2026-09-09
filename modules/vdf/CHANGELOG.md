# vdf — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-10** — A1 fix campaign, non-breaking (F6/F7/F8/F5/F10; F3/F4 left open):
  - **F8 (LOW):** `group.montPowPublic` no longer underflows on an empty
    exponent — a `usize` `exp_be.len - 1` that panicked in Debug/ReleaseSafe
    and, measured, reads out of bounds and crashes with SEGV in ReleaseFast
    (worse than the audit's originally observed "silently returns 1"; see
    `A1/vdf.md` disposition). Unreachable from this module's own two call
    sites (`l`/`r` are always 32 bytes) but the function is `pub` and
    re-exported via `vdf.group`. Now returns `base^0 = 1` in every mode.
  - **F7 (LOW):** `Proof.fromBytes` added a test for a too-long buffer —
    the existing suite only ever exercised a too-SHORT one, so a weakening
    of the `!=` length check to `<` (silently truncate a longer buffer)
    passed every test green.
  - **F6 (LOW):** fixed three factual documentation errors: `README.md`
    claimed `meta.deps = .{}` (it has been `.{"montint"}` since the
    montint rewire); `group.zig` claimed `montint`'s Montgomery multiply
    is non-constant-time (it IS constant-time — its own module doc comment
    and three `scripts/ctgrind.sh` harnesses say so; the actual reason
    `vdf` uses it is throughput from full 2^64-bit limbs + an amd64 asm
    core, not a dropped CT requirement); `root.zig`'s Caveats section
    still said the choice "keeps `deps = .{}`" sixty lines above the
    `.deps = .{"montint"}` that contradicts it.
  - **F5/F10 (MED/LOW), documentation only:** added a "`T` calibration and
    trust" section to `SPEC.md` and `README.md` — `eval` undershoots an
    OpenSSL-class adversary by ~1.57× and a Debug build undershoots
    ReleaseFast by ~15.8× (measured), ~25× combined if `T` is calibrated
    from `zig build test-vdf`'s own default (Debug) lane; and `T` is an
    unbounded, uncapped input that a caller accepting it from an untrusted
    party must bound itself.
  - **Left open:** F3 (Miller-Rabin round-count strength has no behavioral
    test — the original auditor could not construct an exploit and neither
    could this pass; a 256-bit composite that fools a reduced round count
    needs a targeted Arnault-style construction, out of scope for this
    pass) and F4 (a small-prime presieve in `hashToPrime` would cut
    `verify`'s cost ~2.5× but is a new code path in the one place
    soundness rests on primality — needs its own differential test and
    exceeds this pass's scope; see `A1/vdf.md`).

  Tests: 45 → 47 (both new). `scripts/modtest vdf`: 47/47 in Debug,
  ReleaseSafe, and ReleaseFast. `zig fmt --check modules/vdf/`: clean.

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
