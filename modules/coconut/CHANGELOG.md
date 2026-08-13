# coconut — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-12** — **BREAKING:** `keygen` and `proveCredential` take `io: std.Io` instead of
  `random: std.Random`, and draw from `std.Io.random` — contractually a
  CSPRNG. The old shape did not merely permit the mistake, it *taught* it:
  `keygen`'s doc comment said "seed it for deterministic tests" with nothing
  saying "and never in production". A consumer who followed that advice
  shipped an authority master secret `(x, y₁…y_q)` that is a pure function of
  the seed — anyone who recovers the seed issues arbitrary valid credentials
  for the whole system, and the `t`-of-`n` threshold split becomes decoration
  because the dealer's secret never had to be reassembled from shares. On the
  show side, witness nonces that repeat across two proofs let a verifier who
  sees both extract the HIDDEN attributes and the blinding `r` by the standard
  two-transcript Sigma-protocol argument, i.e. exactly the privacy selective
  disclosure exists to provide.

  The guarantee is now at the type: a `std.Random.DefaultPrng` is not
  expressible at a `std.Io` parameter. This is the `bbs`/`ibe`/`tlock` shape.

  **Migration:** obtain an `Io` (`std.Io.Threaded.init(gpa, .{})` then
  `.io()`) and pass it where the `std.Random` used to go. Coconut has no
  published byte-exact test vector (`SPEC.md` §3), so no consumer needs a
  deterministic issuance; test suites that do can call the new
  `keygenSeededForTest` / `proveCredentialSeededForTest`, whose names are the
  signal. New public `Entropy` union backs both paths.
