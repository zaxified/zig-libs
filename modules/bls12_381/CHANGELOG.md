# bls12_381 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
