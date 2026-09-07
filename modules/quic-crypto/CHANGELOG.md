# quic-crypto — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — **Test-only: `fuzzRemove` called `remove` with an EMPTY
  packet, a zero offset and an all-zero mask on every run, and so never got
  past its first line.** The harness drew `smith.bytes(&packet)` and then four
  more values: a ranged `len`, `smith.value(bool)` for the header form, a
  ranged `pn_offset`, and `smith.bytes(&mask)`. `bytes` consumes
  `@min(buf.len, in.len)` octets, so every draw after it found an exhausted
  input and returned its minimum — `len` 0, form `.short`, `pn_offset` 0, mask
  all zeroes. `remove` then returned `error.PacketTooShort` from its
  `packet.len == 0` guard. **`firstByteMask` was never evaluated and the
  §5.4.1 pn_len recovery this module exists to model had never executed
  once**, so the harness's own claim that `pn_offset` was "fuzzed too so
  short/zero-length PN windows and windows that hang off the end of `packet`
  are both hit deliberately" was false when it was written. The four arguments
  now come out of ONE `smith.slice` — a 7-octet script prefix (`form`,
  `pn_offset`, the five mask octets) followed by the packet — with a 14-seed
  corpus carrying the RFC 9001 Appendix A.2/A.3/A.5 protected headers at their
  real masks and offsets. Measured 2026-09-07: **0 of 14 seeds arrived
  non-empty and 0 calls got past the first guard before; 13 of 14 seeds, 9
  successful removals over 20 recovered PN octets, and all four on-wire
  `pn_len` values, after; the long-header branch went from 0 rounds to 6.**

- **2026-07-18** — Security audit: no findings. Byte-exact against RFC 9001 Appendix A's
  published test vectors.
- **2026-07-11** — New module: RFC 9001 (Using TLS to Secure QUIC) crypto seam.
