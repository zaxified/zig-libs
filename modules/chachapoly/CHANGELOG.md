# chachapoly — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-08** — The three `Debug` rows are gone from the constant-time table in
  `SPEC.md` and from `scripts/ctgrind-expected.tsv`. They were a second copy of the
  `ReleaseSafe` positive control (281 in-file contexts against its 210, the same checked
  operators for the same reason), and they were not a measurement: Zig 0.16 compiles Debug
  with the self-hosted x86_64 backend, whose `.debug_line` valgrind's DWARF reader cannot
  parse. Measured on this harness, frames carrying `(file:line)`: `ReleaseFast` 36/36,
  `ReleaseSafe` 2054/2054, **`Debug` 904/2130**, and 51 of 60 resolved Debug frames carry
  the wrong line number (checked against `llvm-symbolizer`; the file is right 60 of 60). A
  context whose pattern-bearing frames all lost their line info is unattributable by any
  pattern, so the `aead` Debug row stood recorded as KNOWN RED from 2026-09-02 and then
  passed unchanged on 2026-09-08 — the verdict was moving with the build, not with this
  module. Nothing consumes this module in Debug and no claim in `SPEC.md` rested on those
  rows. The repo-wide rule is now in `CONVENTIONS.md` §7.1 and `scripts/README.md`.

- **2026-09-07** — Both fuzz targets ran one fixed input for their whole existence.
  `poly1305.fuzzAgainstStd` drew the key, then the message, then a ranged length; a ranged
  `Smith` draw reads eight octets as a little-endian `u64` and returns the range MINIMUM when
  fewer remain, and the two `bytes` calls had already consumed them — so the differential
  compared the MAC of the **empty message under an all-zero key** against std, once, for ever,
  which is the shortest input the carry chain has and the one that exercises no lane at all.
  `root.fuzzDecrypt` was the same shape across five arguments: zero-length ciphertext, zero-
  length AAD, all-zero key, nonce and tag. The key and nonce are drawn from a single
  `smith.slice` now, packed as `nonce ‖ key ‖ tag ‖ ad_len ‖ ad ‖ ciphertext`, and the corpus
  carries a genuine sealed message — the module's comment is right that random bytes reach the
  authentication-failure path, and wrong that this suffices, because they reach ONLY it and
  the success branch of `decrypt` was unreachable by construction. Measured: **Poly1305 1
  distinct (key, message) pair and 0 message octets → 11 pairs and 947 octets; AEAD 1 distinct
  tuple, 0 ciphertext octets and 0 successful opens → 7 tuples, 230 ciphertext octets, 60 AAD
  octets and 1 open.**

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
