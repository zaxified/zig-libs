# bolt8 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — The three `act.zig` fuzz targets had never parsed an act. Each drew
  `smith.bytes(&buf)` and then a ranged length, which returns the range minimum when
  fewer than eight input octets remain — so the length was 0 on every input, and with no
  corpus the lane ran exactly one round each: `Act1/2/3.fromBytes("")`, `error.ShortRead`
  before a field is read. The draw is now one `smith.slice(&buf)`, each target carries a
  corpus built from the Appendix A vectors in `kat_vectors.zig` (the published act, the
  bad-MAC/bad-ciphertext/bad-rs vectors, the bad-version and short-read vectors, a full
  act with trailing octets, an all-zero act, and the empty seed), and the harness now
  asserts the fixed-layout round-trip `fromBytes(x).toBytes() == x[0..act_len]` that it
  previously discarded. Measured: 7/7, 7/7 and 8/8 non-empty seeds reach the parser
  where 0 did; 5, 5 and 6 accepted, carrying 3, 3 and 4 **distinct** `e_pub`/`c` values —
  the second number is pinned because an accepted count cannot tell a corpus that
  collapsed to one frame from one that did not.

- **2026-08-21** — `noise`'s cipher calls gained `error.BufferTooSmall`; this module maps
  it to the `BufferWrongSize` it already publishes, so its own error sets are unchanged. It
  validates every buffer length itself before calling, so the mapped error is not reachable
  through this API — the mapping exists so that stays true by construction rather than by
  an `unreachable`.

- **2026-07-18** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Verified: `kat_test.zig`
  verifies BOLT#8 Appendix A byte-exact (act1→act2→ act3, five crypto-level negative
  vectors, transport round-trip).
- **2026-07-12** — New module: Lightning BOLT#8 encrypted transport
  (`Noise_XK_secp256k1_ChaChaPoly_SHA256`).
