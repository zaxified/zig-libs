# pbb — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-06** — Security audit: four findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified: Verified,
  not assumed. Both Wireshark goldens were re-executed against sharkd 4.6.4 today, and
  the *dissector reached* was checked via `frame.protocols`, not the exit.
- **2026-07-24** — New module: IEEE 802.1ah Provider Backbone Bridge (MAC-in-MAC) codec.
