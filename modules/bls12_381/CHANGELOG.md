# bls12_381 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
