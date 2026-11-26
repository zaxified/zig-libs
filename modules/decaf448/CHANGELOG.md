# decaf448 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-26** — **NO CONSUMER-VISIBLE CHANGE:** killing tests from the 2026-11-25 whole-module mutation run (`modinv` updateDE / divsteps edges, scalar inversion).
- **2026-11-24** — **Faster, same results:** `scalar.invert` is the constant-time safegcd inverse of the new `modinv.zig` (Bernstein–Yang divsteps) instead of a Fermat chain over the bit-serial `ed448.scalar.mul`: ≈ 9.6 ms → ≈ 4.3 µs (in-process A/B, ReleaseFast). Every 56-byte input is still accepted and a multiple of `l` still inverts to 0. The dead-stack burn grew 4 → 6 KiB (`burn.scalar_burn`, shared with `scalarMul` and `random`). New ctgrind row `invert` (0 in-file); `scalarmul` digest re-pinned.
- **2026-11-23** — **NO CONSUMER-VISIBLE CHANGE:** the dead-stack probe (`src/stackprobe_test.zig`) also applies the residue rule (`testkit.stackprobe.residueOf`) to its snapshots: a non-zero byte below a measured call's burn now fails it, whatever secret the needle model names or misses. Clean. Test only.
- **2026-11-16** — **BEHAVIOUR CHANGE:** a DST over 255 bytes is no longer refused with `DstTooLong`; `expandMessageXof`
  (and so `hashToElement` / `hashToScalar`) reduces it as RFC 9380 §5.3.3 requires, `SHAKE256("H2C-OVERSIZE-DST-" || DST, 56)`
  (k = 224). New `hash.reduceOversizeDst`. `DstTooLong` stays in `HashError` but is no longer returned.

- **2026-10-10** — tests: deterministic fuzz driver `DECAF448_FUZZ` (testkit) over `Element.decode` (accepted encodings re-encode canonically, a damaged one names another element), the group law on random scalars, and hashToElement/hashToScalar DST bounds. No change to the library code.
- **2026-10-08** — **BREAKING + FIX (secrets on the dead stack, MEDIUM):** the new ReleaseFast stack
  probe (`src/stackprobe_test.zig`) found the scalar and its inverse in dead frames after
  `scalar.invert`, and the result after `scalar.random`; both now burn their stack (`burn.zig`).
  `Element.scalarMul(a, s: *const CompressedScalar)` takes the scalar by pointer and
  `scalar.random(out, io) !void` writes into `out` (zeroed on error) — by value, the caller's frame
  kept a copy. 0 residues after, caller's frame included.
- **2026-10-06** — ADDED: the scalar field — `scalar.sub`, `negate`, `invert`
  (Fermat, constant-time), `reduce(n, bytes)`/`fromWide` (wide reduction mod `l`),
  `random(io)` (`io.randomSecure`, fail-closed) and `scalar.one`; and hashing —
  `hash.expandMessageXof` (RFC 9380, SHAKE256), `hashToElement`
  (`hash_to_decaf448`) and `hashToScalar` (RFC 9497 decaf448-SHAKE256), re-exported
  at the root. Anchored byte-exact to RFC 9380 Appendix K.6 and RFC 9497 Appendix
  A.2. Scope mvp -> core.
- **2026-10-05** — Mutation run: 24 of 24 killed, 0 equivalent; 1 test added
  (MAP's mod-p reduction of an input `>= p`, which no RFC 9496 B.3 vector
  reaches). No code change.

- **2026-09-09** — Licensing: added `NOTICE` (kind `third-party attribution`). No code
  changed. `src/kat_vectors.zig` reproduces RFC 9496 Appendix B's test vectors, which the
  module's `Provenance:` statement never mentioned — it answers for the code. The record
  rests on the IETF Trust's written grant, TLP 5.0 §4.c Revised BSD, reproduced in the new
  file, rather than on the merger doctrine.
- **2026-07-18** — Security audit: no findings. Byte-exact against RFC 9496 Appendix B's
  published test vectors.
- **2026-07-16** — New module: decaf448 prime-order group (RFC 9496, "The ristretto255
  and decaf448 Groups", §5) over `ed448`'s edwards448 curve.
