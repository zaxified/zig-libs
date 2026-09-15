# sealedbox — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-16** — **BREAKING:** the secret-key text codecs that measured a
  leak write into caller buffers (audit A1 L8, a measured defect on a module
  with no consumer — the QUESTIONS-ROUND-2 Q3 rule).
  `encodeSecretKeyBase64(out: *[44]u8, sk: *const [32]u8) void`,
  `parseSecretKeyBase64(out: *[32]u8, text) !void` and
  `parseSecretKeyHex(out: *[32]u8, text) !void`; a parser zeroes `out` on any
  error. Measured at ReleaseFast with every result wiped the moment it was
  available: the value-in/value-out encoder left the raw key on the dead stack
  twice per call and the base64 text once (one key copy was the caller's
  argument copy), and the parsers left the decoded key once and three times per
  call in the module's full test binary — not in a filtered or a stand-alone
  one, because it depended on inlining. So the pattern `wipe` documents erased
  none of it. Writing through the pointer is what removed it; each codec also
  runs `noinline` and is followed by a 1 KiB stack burn, as guards — removing
  either left the probe at zero in the measured binary. `encodeSecretKeyHex` and
  `keyPairFromSecretKey` measured clean and are unchanged.
  `stackprobe_test.zig` gains a test asserting that every secret-key codec
  leaves neither the text nor the key behind.

- **2026-09-16** — **NO CONSUMER-VISIBLE CHANGE (test-only):** audit finding
  L4. The property `wipe` exists for — that the optimiser cannot remove its
  zeroing — had no test that could see it: `wipe: the encoded secret really is
  gone` reads the buffer right after wiping it, which keeps even a plain
  `@memset` alive, and the audit's mutant swapping `secureZero` for `@memset`
  passed every test. New `stackprobe_test.zig` forces a buffer into memory by
  volatile writes, wipes it, never reads it again and scans the dead stack
  after return, beside a negative and a positive control. Measured at
  ReleaseFast in the full test binary: `secureZero` 0/5, `@memset` 5/5, a no-op
  5/5. Imported from `kat_test.zig`, so `root.zig` and its ctgrind digest do not
  move.

- **2026-09-11** — **NO CONSUMER-VISIBLE CHANGE (doc-only):** `SPEC.md`
  gains a "Known limitations" section documenting audit findings H2 and
  M4 by exact location instead of leaving them open. Both point into the
  Zig standard library this module calls (`std.crypto.nacl.SealedBox`'s
  dependencies for H2's dead-stack secret copies; `lib/std/crypto/25519/
  curve25519.zig`'s single `IdentityElement` check, shared by 19 modules
  in this repository, for M4), not into `modules/sealedbox/`. Resolution
  follows the precedent the user set for the identical class of finding
  on `ecvrf` E4 (variant (b): document with the exact location, no
  upstream report, no vendored copy — vendoring would reintroduce the
  "no bespoke crypto" risk `SPEC.md`'s own design section rules out and
  turn a small `std` file into a fork this repository would have to
  track against every Zig release). Neither finding's underlying
  behaviour changed; `grep -c "curve25519.zig\|H2 —\|M4 —\|Known limitations"
  SPEC.md` is 0 before this entry, 4 after.

- **2026-09-10** — A1 fix campaign, audit findings H1/M2/L2/L5/L6/L7 (0 consumers in the repo, `DECISIONS.md` P1/P4). ⏸ Root-cause note: every edit below that touches `src/root.zig` (L2, L6) invalidates the `scripts/ctgrind-expected.tsv` source-digest pin for this module (the digest is a hash over `root.zig` alone, since `src_digest` only hashes files that are both named by `PATTERN` and present in `src/`) and is **deferred for `--update-digests` re-pin at the end of the campaign**; the test-only and doc-only changes (H1, M2, L5, L3, L7, M5) touch `kat_test.zig`/`example/`/`SPEC.md` and do NOT move that digest.
  - **H1 (HIGH):** the AEAD tag check this module relies on (`std.crypto.timing_safe.eql` in std) had no test distinguishing a full 16-byte comparison from a weakened prefix comparison — measured 2026-09-09, every truncation from 1 to 15 bytes survived the suite (20/20 forgeries accepted under a 1-byte check). `kat_test.zig` gains a deterministic ladder test (N = 1/2/4/8): a tag built to match a real one in its first N bytes and provably differ at byte N is asserted to still be rejected. **NO CONSUMER-VISIBLE CHANGE** (test-only); does not touch `root.zig`.
  - **M2 (MEDIUM), second half:** `seal` had no fuzz harness at all (the first half — `fuzzOpen` drawing a zero length via a ranged `Smith` call — was already fixed 2026-09-07, before this audit's finding was written down). `kat_test.zig` gains `fuzzSeal`, fuzzing plaintext content/length through `seal` -> `open` round-trip. **NO CONSUMER-VISIBLE CHANGE**; does not touch `root.zig`.
  - **L2 (LOW): BEHAVIOURAL, not breaking.** `seal`/`open` return named `SealError`/`OpenError` instead of an inferred error union. Same members as before (verified: suite unchanged, 22 -> 26 tests, all green in Debug/ReleaseSafe/ReleaseFast); a caller doing an exhaustive `switch` now sees all four `open` errors instead of the two the old doc-comment named. Touches `root.zig`.
  - **L5 (LOW):** small-order/non-canonical X25519 points (libsodium's own blacklist) were checked against libsodium during the audit (0/13 divergences) but had no committed test. `kat_test.zig` gains two tests pinning `IdentityElement` rejection for six of them, on both `seal` (degenerate recipient key) and `open` (degenerate ephemeral-key prefix). **NO CONSUMER-VISIBLE CHANGE**; does not touch `root.zig`.
  - **L6 (LOW):** `open`'s doc comment now states that `out`'s contents are unspecified on any error (std's failure-path `@memset(m, undefined)` is a no-op in ReleaseFast). Doc-only, touches `root.zig`.
  - **L7 (LOW):** `SPEC.md` documents that `openAlloc` allocates its output buffer before the tag is verified (bounded 1x amplification, freed via `errdefer`, not a finding on its own).
  - **M5:** `SPEC.md` gains a measured Performance section (seal/open vs libsodium at 32B/1kB/64kB) replacing a stale citation from a different module's measurement. Doc-only.
  - **L3:** a stale example comment describing `seal`'s buffer-size check as `std.debug.assert` (the code moved to a real error on 2026-08-23, the comment didn't) is corrected.

- **2026-09-09** — **NO CONSUMER-VISIBLE CHANGE:** a KAT vector whose base64 contains both `+` and `/` (audit finding L1). Mutation M13 — the decoder switched to the URL-safe alphabet — was caught only **by luck**: both fixed KAT strings in this module contain neither character, so the only test that could see the swap encoded a freshly generated key and its verdict rode on entropy (P ≈ 0.255 per key, two keys, measured RED 11 / GREEN 1 of 12). The new vector puts indices 62 and 63 in three different 6-bit positions and drives BOTH paths — the still-`std`-backed public codec that M13 mutated, and this module's own constant-time secret codec, which must agree character for character. It also asserts that the URL-safe spelling of the same key is **rejected** by both, which is what makes it a test of the alphabet rather than of a string. Verified by deploying M13: the new test fails on every run, by construction rather than by chance.

- **2026-09-09** — **BEHAVIOURAL, not breaking: the four SECRET-key text codecs are now constant-time.** `encodeSecretKeyBase64`, `parseSecretKeyBase64`, `encodeSecretKeyHex` and `parseSecretKeyHex` no longer route key material through `std.base64` / `std.fmt`, which are table-driven. ⛔⛔ Measured before the change (`scripts/ctgrind.sh sealedbox`): **8 / 7 / 43 / 47** memcheck contexts, 95 of them on a LOAD, and the disassembly showed `movzbl 0x…(%rax),%eax` over a secret character (std's 256-byte `char_to_index`) and `movzbl 0x…(%r8),%esi` over a secret 6-bit group (std's 64-byte alphabet) — **secret-indexed table lookups, the cache-timing class of T-table AES**. After: **encoders exact 0, parsers exact 1**, and the 1 is `if (invalid != 0)`, the accept/reject the parser returns anyway (a 0 there would be the wrong pin — the decode loops contribute 0, so there is no early exit revealing WHICH character was bad). ⭐⭐ The `out_sha` pins did not move by a single bit: the branch changed, the result did not. Behaviour a caller can observe is unchanged except that the base64 parser now also rejects a **non-canonical final group** (the last 6-bit value's spare 2 bits must be zero, RFC 4648 §3.5) — `std`'s decoder rejected that too, so this is preserved, not new. ⚠ **The public-key codecs still use `std`, deliberately:** their input discloses nothing, so a table lookup there is not a leak and hand-rolling them would be a worse trade. ⚠ The claim is held by optimisation barriers (`blackBox`, the montint `b199192` idiom), not by how the code reads — with the barrier on the *input* instead of the result mask, LLVM still turned `ctEq(c,'+') & 62` into a `test`/`je`; **deleting `blackBox` as dead weight silently reverts the property** and no value test can see it. SPEC.md gains a "Constant-time scope" statement and names the anchor. Value equivalence is proved exhaustively (all 64 indices, all 256 characters through both parsers, all 16 nibbles, and 512 random keys cross-checked against the std-backed public-key codecs in the same binary); ⭐ a KAT caught a real bug in the first draft, where a mask was sixteen bits wide instead of one.

- **2026-09-09** — **NO CONSUMER-VISIBLE CHANGE:** `src/ctgrind_harness.zig` is added, which also puts this module in the `ct` class and therefore in `scripts/ctgrind.sh`. It settles a contradiction the 2026-09-09 ctgrind coverage pass left standing: the pass filed `sealedbox` as a thin wrapper over `std` with nothing of its own to measure, while this module's audit record said the secret-key codecs light up immediately. ⭐ Both were right, about different functions — `seal`/`open` ARE pure `std.crypto.nacl.SealedBox` and are deliberately NOT targets, but `encodeSecretKeyBase64`/`parseSecretKeyBase64`/`encodeSecretKeyHex`/`parseSecretKeyHex` hand 32 bytes that grant full decryption capability to `std.base64` and `std.fmt`, neither of which claims to be constant-time. Measured ReleaseFast with the secret (or, for the parsers, the secret-derived TEXT) marked undefined: **43 / 47 / 8 / 7 in-file contexts**, each with an untainted control row and a no-`-fvalgrind` trap row at 0. ⛔⛔ **These are not artefacts and not merely branches:** 95 of them are reported on a LOAD, and the disassembly shows `movzbl 0x100fde8(%rax),%eax` over a secret byte (the 256-byte `char_to_index`) and `shr $0x34 / and $0x3f / movzbl 0x100ff2e(%r8)` over a secret 6-bit group (the 64-byte alphabet) — secret-indexed table lookups, the cache-timing class of T-table AES. ⚠ Sharpness follows table size, so the 256-byte decode table is the worst of the four and the 16-byte hex table the mildest; the counts are unrolled iterations, not severity. The rows are pinned **as a DEFECT**: the module is not fixed by this entry, and constant-time secret-key codecs remain owed.

- **2026-09-07** — `fuzzOpen` had only ever opened a zero-length ciphertext. It drew the
  length FIRST with `smith.valueRangeAtMost(u16, 0, 256)` and read the bytes into
  `sealed_buf[0..sealed_len]` afterwards; a ranged `Smith` draw reads eight octets as a
  little-endian `u64` and returns the range MINIMUM unless that whole word lands inside the
  range, so `sealed_len` was 0 and the `bytes` call that followed copied nothing. `open`
  refused on its `sealed.len < overhead` line, and no other line of the module ever ran from
  the fuzzer. Now one `smith.slice(&sealed_buf)` call, plus an eight-ciphertext corpus (the
  module's own KAT sealed box, three one-bit mutants of it in the ephemeral key / tag /
  message, `overhead` and `overhead - 1` octets of zeros, a full buffer, and the empty input)
  and a corpus guard. Measured: **0 of 8 seeds non-empty, 0 boxes opened and 0 plaintext
  octets before; 7 of 8 non-empty, 1 opened and 46 plaintext octets after.** The file comment
  argued that random input already reaches the authentication-failure path — true, but it
  reaches only that path: nothing random opens, so `open`'s success branch was unreachable
  from this target by construction.
- **2026-08-23** — **Behavioural:** `seal` returns `error.InvalidBufferSize`
  for an `out` buffer that is not exactly `msg.len + overhead`, where it
  previously used `std.debug.assert`. An assert is compiled out in
  ReleaseFast, so a caller who miscomputed the size got memory corruption in
  the build that matters most and a clean panic only in Debug. `open`, five
  lines below, had always returned an error for the same class of mistake.
  Found by writing this module's first example.

- **2026-08-14** — Test-only: `kat_test.zig` gained a `testing.fuzz` harness on
  `open` (arbitrary-length, arbitrary-content ciphertext against the fixed KAT
  keypair) — `zig build check-fuzz` no longer names this module. No panic/OOB
  found; **neither breaking nor behavioural**.
- **2026-07-18** — Security audit: no findings. Modeled on libsodium `crypto_box_seal` /
  Go `nacl/box` (design reference, not a test anchor).
- **2026-07-07** — New module: NaCl `crypto_box_seal` — anonymous-sender X25519
  public-key encryption (thin over `std.crypto`) + base64/hex key serialization.
