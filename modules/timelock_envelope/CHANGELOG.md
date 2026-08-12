# timelock_envelope — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- `SealRandomness.generate` draws all three values — `s_time`,
  `tlock_sigma` and `kem_coins` — through the new `entropy` module
  (`entropy.fill`, i.e. `std.Io.randomSecure`) instead of `io.random`. Not
  breaking: `fill` returns `void`, so the signature still returns a plain
  `SealRandomness`. `std.Io.random` is a CSPRNG whose contract permits a
  silent fallback to a weaker seed (`std/Io.zig:2462`) and the default
  `Io.Threaded` takes it, seeding from pid + wall clock + an ASLR pointer.
  This type's own doc comment already spells out the consequence: `(key,
  nonce)` is a deterministic function of `(s_time, s_pq, suite_id, round)`
  and neither secret is transmitted, so a repeat across two `seal` calls to
  one recipient/round is a full ChaCha20-Poly1305 break — plaintext-XOR
  recovery and forgeable tags. A degraded seed is exactly that repeat, so
  `generate` now aborts instead of producing one silently. `seal` still
  takes `SealRandomness` as an explicit parameter; the KAT path is
  unaffected.
