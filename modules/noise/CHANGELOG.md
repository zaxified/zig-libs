# noise — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — Fuzz reach: `fuzzReadMessage` never read a handshake message. It
  opened `smith.bytes(&msg)` and then drew the length with `smith.valueRangeAtMost`;
  `bytes` consumes `@min(msg.len, in.len)` octets and a ranged draw reads EIGHT more as a
  little-endian `u64`, returning the range MINIMUM when fewer remain, so the length was 0
  — and with no corpus the one input it ever ran was empty. `readMessage("")` fails on
  the `e` token's length check before a single octet of transcript is mixed. Measured
  2026-09-07: 1 round, 0 messages accepted, 0 payload octets recovered. The draw is now
  one `smith.slice` and the corpus is built at run time from this module's own
  `writeMessage` — a genuine NN message 1 (`e || payload`, no AEAD yet, which is why the
  responder accepts it without knowing the initiator), the same ephemeral with an empty
  payload (`DHLEN` octets, the shortest accepted message), one octet short of `DHLEN`,
  the all-zero ephemeral, the all-ones ephemeral, and a 256-octet message that fills the
  buffer and `out` exactly. ⚠ The corpus guard pins payload octets, not acceptances: a
  `DHLEN`-octet message is accepted with a ZERO-length payload, so "accepted > 0" would
  say nothing about whether any payload crossed the boundary. Pinned: 6 non-empty,
  5 accepted, 257 payload octets.

- **2026-08-21** — **Breaking:** `CipherState.encryptWithAd`/`decryptWithAd` and
  `SymmetricState.encryptAndHash`/`decryptAndHash` gained `error.BufferTooSmall`. The
  output-buffer preconditions were `std.debug.assert`, which compiles out in `ReleaseFast`
  and `ReleaseSmall` — the modes this ships in — leaving a caller-supplied `out` slice to
  be written past in exactly the builds where it matters. The module already published
  `BufferTooSmall` and used a runtime check for the same class elsewhere; these four sites
  were the inconsistency. Callers that only `try` are unaffected; an exhaustive `switch`
  over the error set needs the new tag.

- **2026-07-18** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Byte-exact against RFC 5869's
  published test vectors.
- **2026-07-10** — New module: The generic Noise Protocol Framework (noiseprotocol.org,
  spec rev 34).
