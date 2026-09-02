# chachapoly — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-02** — **Audit (drift campaign): 2 MEDIUM, 3 LOW.** ⭐ No forgery, no wrong
  ciphertext or tag, no out-of-bounds: byte-exact against `std` at every shape the auditor could
  construct — 400 randomised chunked MAC streams per lane width, a 32×32 AEAD grid to 2 999 B,
  in-place AEAD at every length ≡ 0 mod 7, AD-only for **every** AD length 0..5 000, and the
  counter-space edges. The defects are in the anchoring and in a guard that was inert in the
  mode this module tells you to ship.
  **MEDIUM — the 32-bit counter anti-wrap rule was `std.debug.assert`**, i.e. absent in
  ReleaseFast. Reproduced there: `ChaCha20.stream(128 B, counter = 0xFFFF_FFFF)` returns bytes
  64..128 **byte-identical to `keystream(counter = 0)`** — a silent two-time pad; with a comptime
  counter the violated `unreachable` became UB and the run SEGV'd. It is a `@panic` in every
  build now, and the arithmetic behind it is a `pub` predicate (`counterWouldWrap`) pinned by
  tests, since the panic itself cannot be caught from one.
  **MEDIUM — three of the four RFC 8439 vectors in this file executed `std`'s code, not ours.**
  §2.3.2 (64 B) and §2.8.2 (114 + 12 B) are inside `delegate_max_bytes`/`aead_delegate_max`, so
  the AEAD had **no external vector exercising a single line of its own**, and the length-sweep
  differential against `std` — a real oracle above the thresholds — is vacuous below them, where
  oracle and implementation are the same code. The prior audit's `A1 external-anchor: PASS`
  predates the thresholds (`d1635787`) and was never re-checked. Fixed with a test-only
  `force_wide` switch (`void` outside a test build, like the existing path witness): §2.3.2 and
  §2.8.2 now run through **both** engines and must agree with the RFC bytes on each.
  **LOW — the AEAD's constant-time tag comparison had no enforcement.** `ctgrind-expected.tsv`
  listed this module with the `poly1305` target alone and the harness never touched `root.zig`,
  so replacing `timing_safe.eql` with `std.mem.eql` left the suite at exit 0. There is an `aead`
  target now, covering `root.zig` **and** the `std` files short calls are delegated to, with the
  four expected ReleaseFast contexts named one by one — they are the branch on the comparison's
  ANSWER, which is the API, not the comparison itself.
  **LOW — the test named for the F1 counter fix was vacuous**: its 64-byte `stream` call is
  inside `delegate_max_bytes`, so it compared `StdChaCha` with `StdChaCha`. It runs through this
  module's engine now, at three counters that end exactly at the top of the space.
  **LOW, recorded not changed** — an in-place `decrypt` that fails zeroes the caller's
  ciphertext (documented, deliberate, and asserted by a test, but a divergence from the `std`
  oracle this module claims drop-in parity with); and **AVX-512 (`lanes = 8`) has no external
  vector at all** — no such hardware here, and no RFC 8439 §A.5 (m = 265) vector exists in the
  repo to reach it. Ledger: `~/CML/20260931-zig-libs-audit/chachapoly.md`.

- **2026-08-11** — Security audit: eleven findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Byte-exact against RFC
  8439's published test vectors.
- **2026-07-19** — Performance: a SIMD implementation now beats OpenSSL's AVX2 keystream
  throughput on the reference host (part of a collection-wide
  performance campaign; the root changelog records no further detail
  than this).
