# oscore — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-13** — **Documentation only.** A1 finding F16: `README.md` and `SPEC.md` described
  the `coap` → `oscore` integration as the intended wiring "already in this repository". No
  module depends on `oscore` and no such seam exists; both now say so and leave the wiring to
  the consumer.

- **2026-09-11** — **API CHANGE:** `buildAad` takes a caller-supplied
  `dst: []u8` buffer instead of an `allocator`, and returns
  `error.BufferTooSmall` rather than an `Allocator.Error` (audit finding
  F13). The old version composed two allocator-based sub-encoders
  (`encodeAadArray`, `encodeEncStructure`, each doing its own growable
  `ArrayList` plus a `toOwnedSlice`) for an AAD that, in every real RFC
  8613 Appendix C vector, is under 40 bytes — measured at +150% over the
  bare AEAD for a 16-byte payload, almost entirely allocator overhead.
  `buildAad` now writes CBOR bytes directly into `dst`; a new
  `buildAadLen(params)` reports the exact size needed. `protect`/
  `unprotect` gain a new error, `AadTooLarge`, and use a fixed-size stack
  buffer (`max_aad_len`, 192 bytes — covers `id_piv_field_width`-bounded
  (7 B) kid/piv plus up to 128 B of Class I CoAP options; every Appendix
  C vector has none) instead of allocating one. `encodeAadArray`/
  `encodeEncStructure` themselves are UNCHANGED (still allocator-based,
  still `kat_test.zig`'s own direct byte-exact KAT target) — `buildAad`
  encodes the same bytes by a different, allocation-free route, checked
  against the same Appendix C.4-C.8 vectors independently.
  `QUESTIONS-ROUND-2.md` Q3: a signature change forced by a measured
  cost, free on a module with zero consumers in this repository
  (confirmed: `rg -n '"oscore"' build.zig` names only the module's own
  entry). Measured: a counting-allocator test shows `protect`/
  `unprotect` now make exactly 1 allocation per message (the ciphertext/
  plaintext buffer) instead of 5; a CPU-time A/B against the bare AEAD
  (16-byte payload, 3 rounds, `CLOCK_PROCESS_CPUTIME_ID`) shows `protect`
  dropping from ~563-613 ns/op (the module's own earlier F13 measurement)
  to ~250-290 ns/op — roughly half, consistent with "4 of 5 allocations
  removed, each contributing comparable cost" — though the *percentage*
  overhead over the bare AEAD stays in a similar 110-160% range, because
  that baseline is itself only ~110 ns for 16 bytes, small enough that
  even the one remaining allocation is a comparable fraction of it.

- **2026-09-08** — `SPEC.md`'s constant-time sentence has an instrument behind it now:
  `src/ctgrind_harness.zig`, driven by `scripts/ctgrind.sh`. The module was outside that
  table while making an explicit constant-time claim (audit F8). ReleaseFast: `derive` 0
  in-file contexts of 4, `protect` 0 of 2, `unprotect` 1 of 3 — std's `if (!valid)` at
  `aes_ccm.zig:152`, after the constant-time compare that produced it. ⚠ The two zeros are
  zeros WITH A WITNESS: the earlier probe reported 0 in-file out of a total of 0, which is
  what a harness that never calls the module reports too, so this one prints the derived
  keys and the ciphertext. Teeth: an OR-fold over the Sender Key at the top of `protect`
  moves that row to 1 and fails the gate.

- **2026-09-07** — **NO CONSUMER-VISIBLE CHANGE:** the local `fuzzSeed` /
  `fuzzSeedInto` copies in this module's fuzz files are now `testkit.fuzz`. The
  helper existed **33 times across 12 modules in three shapes**, each carrying its
  own note about the same trap (the returned array has to be container-level or
  the slice dangles with the right length and garbage behind it). Proved
  byte-identical to the copies it replaces before they were deleted, and the
  comparison test was itself broken on purpose first to show it was not vacuous.
  `testkit` added to this module's `test_deps`; test-only, nothing a consumer
  imports changed.

- **2026-09-06** — A1 security audit, the HIGH findings fixed. **Consumer-visible:**
  three new error values. `protect` returns `error.MessageTooLong` for a plaintext
  over `max_plaintext_len` (65 535 B — AES-CCM-16-64-128's 2-byte length field);
  `unprotect` returns it for a payload over `max_ciphertext_len` (that plus the
  tag) BEFORE the AEAD runs — previously an oversized payload panicked in
  Debug/ReleaseSafe ahead of the tag check (a keyless remote crash) and
  `protect` in ReleaseFast emitted a non-CCM length field. `computeNonce` (and
  `unprotect`, via `request_nonce_source.partial_iv`) returns
  `error.PartialIvTooLarge` instead of truncating a Partial IV `>= 2^40` to the
  nonce of `partial_iv mod 2^40`. New API for RFC 8613 §7.5 / Appendix B.1
  restart recovery: `SenderContext.needsCheckpoint`/`resumeAfterRestart`
  (SSN2 = SSN1 + K + F) and `ReplayWindow.resumeAtLowerLimit`; SPEC.md gains a
  "Persistence" section — re-deriving a used context was a two-time pad and a
  500/500 replay, and nothing in the module said so. `deriveContext` wipes its
  derived-key locals and scrubs the stack its HKDF callees vacated. Tests: a
  request delivered twice through `unprotect`, the default window width at its
  edge, a response opened with a nonce-source id that differs from the
  recipient id, non-empty Class I `options`, both `kid` fields non-empty, the
  three previously untested fail-closed guards, and every new guard above —
  each pinned by a mutation that turns the suite red. The fuzz harness draws
  one `smith.slice` and carries a ten-seed corpus (it had decoded the empty
  option once per run). NOTICE no longer describes the cores as stubs.
- **2026-08-23** — Added `OscoreOption.encodePartialIv`, the minimal-length
  big-endian Partial IV encoding `encode()` already used internally, now
  public. Found writing the consumer example: `AadParams.request_piv` (§5.4)
  must carry a request's own Partial IV in this exact wire form, but a
  caller protecting its own request has no `Protected.option.partial_iv`
  bstr to read it back from before calling `protect` — this module's own
  README usage sample worked around the gap with `&.{@intCast(seq)}`, which
  truncates (and panics in Debug/ReleaseSafe) for any sequence number
  `>= 256`. `encode()` now calls the same helper instead of duplicating the
  logic inline; README fixed to use it.
- **2026-07-18** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Byte-exact against RFC 8613
  Appendix C's published test vectors.
- **2026-07-12** — New module: OSCORE — Object Security for Constrained RESTful
  Environments (RFC 8613) — end-to-end object security for CoAP: §3.2.1 HKDF-SHA-256
  security-context derivation.
