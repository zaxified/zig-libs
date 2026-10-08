# timelock_envelope — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-09** — **BREAKING, HIGH: the envelope left its secrets in its callers' frames.**
  New ReleaseFast stack probe (`stackprobe_test.zig`), 5 calls each, before → after: `seal`
  the KEM message / s_time 15 and the AEAD key 10; `open` the AEAD key 10; `sealStream` s_time
  / KEM message 15; `deriveKeys` the AEAD key 10; `deriveStreamKey` s_time 5, s_pq 10 and the
  stream key 10; `SealRandomness.generate` the drawn secrets 40 — all now 0. Secrets in by
  pointer, out through an out-param, bodies one frame down and burned (`burn.zig`); tlock and
  hqc burn their own frames below (both swept 2026-10-09):
  - `seal`/`sealStream(…, recipient_ek: *const EncapsKey, …, rnd: *const SealRandomness)`;
    `open`/`openStream(…, recipient_dk: *const DecapsKey, …)`;
  - `SealRandomness.generate(out, io)` (+ `wipe`);
  - `deriveKeys(out: *DerivedKeys, s_time: *const, s_pq: *const, suite_id, round)`;
    `deriveStreamKey(out: *[32]u8, s_time: *const, s_pq: *const, suite_id, round,
    transcript_hash: *const [32]u8)`.
  - Follows tlock's and hqc's pointer/out-param APIs.
- **2026-10-06** — **ADDED (new wire version, version 1 unchanged):** a streaming format for
  payloads of any size in bounded memory: `Envelope(Kem).sealStream(gpa, writer, reader, ek,
  p_pub, round, rnd)` / `.openStream(gpa, writer, reader, dk, round_signature)` over
  `std.Io.Writer`/`Reader`, `streamSealedLen`, module `stream` (`StreamSealError`,
  `StreamOpenError`, `deriveStreamKey`). Wire version 2: the same header without `pt_len`, the
  same two locks, then an age STREAM (64 KiB ChaCha20-Poly1305 chunks via
  `tlock.age.PayloadStream`) under a key that binds both lock secrets and a SHA-256 of the header
  and locks. ⚠ `openStream` writes each verified chunk as it goes — discard the output on an
  error. Version 1's `parse`/`open` refuse version 2 (`UnsupportedVersion`) and vice versa.
  Anchored: the payload is byte-exactly `tlock.age.sealPayload`'s (Go-`tle`-proven). Mutation
  run 10/10 killed. Scope mvp -> core.
- **2026-10-06** — **NO CONSUMER-VISIBLE CHANGE:** SPEC consistency: streaming and multiple recipients in "Deliberately deferred" now point to their Backlog items ("not yet").
- **2026-10-05** — Mutation run: 19 of 19 killed, 0 equivalent; 4 tests added
  (`deriveKeys` against a Python HKDF recomputation, trailing bytes refused by
  `parse`, an undecodable time-lock point is `MalformedTimeLock`,
  `PlaintextTooLarge`). No code change.
- **2026-09-07** — Test-only, no production change: `fuzzOpen`'s mutation arm - the only one
  that ever hands `Env.open` a real envelope, and therefore the only one that can reach
  `open`'s body at all - had never executed. Its first draw was `smith.value(u8) & 1`, a
  bounded draw that returns its range minimum unless a whole eight-octet word lands inside
  the range, and the target had no corpus; so `mode` was 0 on every input the ordinary lane
  ever ran, its own length draw was 0 too, and the single call the harness ever made was
  `Env.open("")`. The harness's own oracle - "a successful open is only possible for a
  byte-identical copy of the base envelope; assert it really is the original plaintext" -
  had never been evaluated. The byte draw now comes first and the flip script is read out of
  it through `testkit.fuzz.Cursor`. Measured by the new `corpus:` guard: 3 raw-arm and **5
  mutation-arm** runs, **11 flips applied**, and **1 successful open** which is what makes
  that plaintext assertion a live one - all three were 0 before.

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
