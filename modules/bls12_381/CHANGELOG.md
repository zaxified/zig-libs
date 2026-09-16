# bls12_381 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-16** — **NO API CHANGE, NO BEHAVIOURAL CHANGE + ⚠ large performance change:** A1 `drand` F4. The Miller loop kept its accumulator `T` in AFFINE coordinates and computed the slope `λ` explicitly, paying one `Fp2.inv` per step per pair — and `Fp.inv` is Fermat's `a^(p-2)`, a full 381-bit exponentiation. Measured on `drand`'s 2-pair beacon check (ReleaseFast, process CPU time): **136 inversions at 42.8 µs = 5.82 ms of a 10.01 ms verification**, 78 % of the Miller loop. `T` is now `g2.Jacobian` — this module's own audited, complete group law, reused rather than a second copy — and each step multiplies its line through by the factor that clears the denominators (`2YZ³` doubling, `Z·h` addition), so no step inverts. That is free for the same reason the twisted-image evaluation's `w^3` factor always was, in a stronger form: the final exponentiation's easy part raises to `p^6−1` and `Frobenius^6` fixes `Fp6` — hence `Fp2` — elementwise, so `c^(p^6−1) = 1` for every `c ∈ Fp6*`. A new test pins that lemma, with a control (squaring the raw Miller value DOES change the pairing) so it cannot pass by the final exponentiation collapsing everything. ⚠ A `w`-component factor is NOT a valid control — it is killed too, because `p^2+1` is even. **7 interleaved paired reps, both arms in one binary: `multiMillerLoop` (2 pairs) 6.92 → 1.94 ms (3.6×), `drand.verifyRoundPoints` 9.27 → 4.28 ms (2.17×)**, new faster in 7/7 with non-overlapping ranges. The pairing VALUES are unchanged: the byte-exact `e(G1, G2)` KAT did not move, and a new randomized differential runs 12 random point pairs through both the retained affine reference (`millerLoopAffineRef`, test-only — the same role `subgroupCheckByOrder` plays for the subgroup checks) and the new steps. Raw Miller values DO differ, by the `Fp2` scale factor, by design. 220/220 tests in ReleaseFast and ReleaseSafe (was 218/218), consumers green: `drand` 61/61, `tlock` 36/36, `poseidon` 65/65, `coconut` 26/26, `ibe` 45/45, `bbs` 45/46 (1 unrelated skip). No ctgrind re-pin this time — the rows pin `fp.zig`/`fp2.zig`/`g1.zig`/`g2.zig`/`scalar.zig`, and this change is confined to `pairing.zig`.

- **2026-09-15** — **BEHAVIOURAL (stricter only on invalid input) + ⚠ large performance change:** A1 `drand` F4. `g1.Jacobian.subgroupCheck` and `g2.Jacobian.subgroupCheck` no longer compute `[r]P == O`; they check the curve equation and then the endomorphism membership tests `φ(P) == [−x²]P` (`G1`) and `ψ(P) == [x]P` (`G2`, untwist-Frobenius-twist) — Scott, ePrint 2021/1130 §6/§4; proof and conditions from El Housni–Guillevic–Piellard, ePrint 2022/352 §4.3 Propositions 4/5, whose gcd conditions the new "F4 subgroup" tests re-derive for this curve. ReleaseFast, 7 interleaved reps: `G1` **0.774 → 0.123 ms**, `G2` **2.41 → 0.175 ms**; `drand.verifyRoundPoints` 10.34 → 9.72 ms median. Verdicts are unchanged for every point ON the curve (differential tests against the kept reference `[r]P == O` over members, random non-members, `[r]R` torsion, points of order 3/11/13/23, RFC 9380's pre-`clear_cofactor` `Q0/Q1`, and 60 live drand signatures); the one difference is deliberate: an OFF-curve point of order `r` — e.g. the image `(a²x, a³y)` of a member on an isomorphic curve — used to pass and is now refused. Every decoder already required `isOnCurve`, so only a caller that builds a raw `Affine` sees it. `kzg`'s trusted-setup loader now uses `subgroupCheck` for `G1` (faster than its own variable-time `[r]P`, which stays as a test reference). `scalarMulBytes`/`scalarMul` (the secret-scalar engine) are untouched; `g1.zig`/`g2.zig` digests changed, so the ctgrind rows `g1_scalarmul`/`g2_scalarmul` need a re-pin.

- **2026-09-09** — **NO CONSUMER-VISIBLE CHANGE:** `src/ctgrind_harness.zig` is added (A1 audit finding R2; the tier-A ctgrind queue, 28 modules). Measured ReleaseFast under valgrind, in-file contexts: **field 1 / g1_scalarmul 5 / g2_scalarmul 8**. Every target has an untainted control row and a no-`-fvalgrind` trap row, both 0, so the numbers are real taint propagation rather than a silent no-op. ⛔⛔ `SPEC.md:387` and `bls_sig.zig:48` both claim "no secret-dependent branches"; the measurement disagrees. The heaviest item is `Fp.ctSelect` (`fp.zig:597`), which this module's own prose calls "a byte-mask merge … branch-free and index-free" — **two independent agents disassembled it inside `g1.Jacobian.scalarMulBytes` and found `bt %esi,%edx; jae`**, a real conditional jump on a bit of the secret scalar. ⭐ The repair pattern is already in this tree: `p256/src/group.zig:502-508` names this exact LLVM lowering ("a plain `cMov` here was observed to lower to a secret-dependent branch", the montint `b199192` class) and launders its mask through `blackBox`. Also measured: every `scalarMul` converts the secret scalar to bytes through `std.crypto.ff`, whose `Uint.toBytes` branches at `ff.zig:150`, and `Fp2.isZero` is `c0.isZero() and c1.isZero()` — Zig's `and` SHORT-CIRCUITS, so it is a real branch sitting upstream of `g2.zig`'s otherwise branchless point addition. Scope: every consumer (`ibe`, `bbs`, `coconut`, `groth16`, `tlock`).

- **2026-09-09** — `NOTICE` becomes a third-party attribution instead of a provenance note,
  for the 807 177-byte `data/trusted_setup.txt` and the KZG vectors reproduced from
  `ethereum/c-kzg-4844` (Apache-2.0). The existing argument that ceremony output is
  public-domain data is not withdrawn and may well be right — but the file arrives from an
  Apache-2.0 repository whose LICENSE is what a recipient finds, and one copy of a permissive
  licence is cheaper than the argument. Apache-2.0 reproduced in full per §4(a); §4(b) records
  that the setup file is byte-identical to upstream and unmodified.

- **2026-08-18** — Portability fix (`check-portable`), three sites:
  - `computeRootsOfUnity`'s `std.debug.assert(order <= (@as(usize, 1) << 32))` failed to
    compile on a 32-bit target: the `32` shift doesn't fit `Log2Int(usize)` (`u5`) there.
    The `2^32` bound is a property of BLS12-381's `Fr` group order (its largest
    power-of-two root of unity), not of the host pointer width, so compared in fixed-width
    `u64` instead of `usize`. Compile-only, identical semantics — the assert is a debug
    invariant check, and on a 32-bit target `order: usize` can never exceed `2^32 - 1`
    anyway, so the comparison stays trivially true there exactly as it always was.
  - `scalarWindowDigit`'s `digit |= bit << @as(u6, @intCast(i))` and `g1Msm`'s
    `n_buckets = (@as(usize, 1) << @as(u6, @intCast(c))) - 1` both hardcoded the
    shift-amount cast to `u6` while shifting a genuine `usize` (`digit`, a window value;
    `n_buckets`, a bucket-array length). Retyped both casts to
    `std.math.Log2Int(usize)` — the values actually shifted are memory-sized quantities,
    so the shift type should track the target rather than hardcode 64-bit width; `i` and
    `c` here are both small (`c = msmWindowBits(...)` tops out at 8), well inside `u5`.
    Compile-only, identical semantics on every target that already builds.
  Verified: `zig build portable-bls12_381` — the `u5`/`u6` diagnostics these fixes
  targeted are gone; one unrelated wasi-surface failure remains (`std.Thread.spawn`
  under single-threaded wasm32, reached via `loadTrustedSetup`) — out of scope for this
  fix. `zig build test-bls12_381 --summary all` still 209/209 (ReleaseSafe, heavy
  module).
- **2026-08-12** — `scalar.Fr.random` draws through the new `entropy` module
  (`entropy.fill`, i.e. `std.Io.randomSecure`) instead of `io.random`. Not
  breaking: `fill` returns `void`, so the signature still reads
  `random(io: std.Io) Fr` and no caller changed. `std.Io.random` is a
  CSPRNG whose contract permits a silent fallback to a weaker seed
  (`std/Io.zig:2462`) and the default `Io.Threaded` takes it, seeding from
  pid + wall clock + an ASLR pointer. This is not an abstract concern for a
  field element: `ibe.Scheme.setup` mints its **master secret key** from
  this exact call, so a degraded seed forfeits every identity key that
  authority will ever issue. The rejection-sampling loop is unchanged; only
  the source of each candidate is.
  ⚠ Not covered: the sibling `fp.Fp.random` and the other generic field /
  group primitives still use `io.random`. They were left deliberately —
  they are general-purpose arithmetic helpers with no secret-bearing caller
  in this repo, and `Fr.random` was migrated because it has one.
- **2026-07-18** — Security audit: five findings fixed, four documented as accepted (not
  defects) — part of the collection-wide audit. Byte-exact against RFC 9380's published
  test vectors.
