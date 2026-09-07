# tenantkex — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — **Test-only: both handshake fuzz harnesses handed their
  reader the EMPTY message on every run.** `fuzzReadMessage1` and
  `fuzzReadMessage2` opened with `smith.bytes(&msg)` and then drew
  `smith.valueRangeAtMost(u16, 0, msg.len)`; `bytes` consumes
  `@min(buf.len, in.len)` octets, so the ranged draw found fewer than the
  eight it reads as a little-endian `u64` and returned the range MINIMUM.
  `len` was 0 for every input the ordinary test lane can carry. Both now draw
  with one `smith.slice(&msg)`. ⭐ A corpus of hand-written byte strings is
  worth nothing against a Noise IK reader — every such seed fails the tag —
  so each corpus carries a seed built at run time from this module's OWN
  writer, driven by the same deterministic `testRandom` the harness uses, plus
  that message with one octet of its tag flipped. Measured 2026-09-07:
  **msg1 target 0 of 9 seeds non-empty and 0 messages read before, 8 and 1
  after; msg2 target 0 of 8 and 0 before, 7 and 1 after.** The guards pin the
  accepted count at exactly 1 in each direction, which is the assertion a
  refusals-only corpus cannot make.

- **2026-08-06** — Security audit: four findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this).
- **2026-07-24** — New module: Per-tenant key exchange — a Noise_IK handshake (via
  `noise`) between two provider edges with the I-SID bound into the prologue, deriving
  the two directional channel keys that feed `aeadframe`; pure.
