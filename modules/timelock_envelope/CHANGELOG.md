# timelock_envelope — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-13** — Test-only: `security_test.zig` gained "entropy seam: generate
  draws all three fields afresh, and two seals differ". **Neither BREAKING
  nor BEHAVIOURAL** — no production code changed; this adds the coverage
  that was missing for the draws the entry below made fail-closed. Every
  other test here seals with the fixed `fixedRandomness()` on purpose, so
  nothing ever looked at a drawn value: hardcoding all three fields to a
  constant left all 22 tests green. The new test asserts each of `s_time`,
  `tlock_sigma` and `kem_coins` separately — a whole-envelope diff would
  stay green with any ONE of them frozen, since the other two still vary —
  and then seals twice and opens both. Verified by planting
  `@memset(..., 0x5a)` after each draw INDEPENDENTLY: three runs, 22/23
  each, exactly this test red every time. Its stated limit: it catches a
  constant and an ignored `io`, not a weak-but-varying PRNG; which vtable
  slot the bytes come from is pinned in `entropy`'s own suite.
- **2026-08-12** — `SealRandomness.generate` draws all three values — `s_time`,
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
- **2026-08-06** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified against
  genuine League-of-Entropy quicknet data, inherited from `tlock`/`drand`.
