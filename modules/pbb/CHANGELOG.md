# pbb — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — **`fuzzDecode` handed `decode` an EMPTY frame on every input, and
  the EtherType bias it needed to get anywhere had never executed.**

  It opened with `smith.bytes(buf[0..fuzz_drawn])` and then drew a size class with
  `smith.valueRangeAtMost`. `bytes` consumes `min(out.len, in.len)` octets and every
  ranged draw after it reads eight *more* as a little-endian u64, returning the range
  minimum when fewer remain — so the size class was 0, the length inside it was 0,
  and the `smith.value(bool)` gating the tag-planting block was false. That block is
  the only thing that makes this decoder reachable: uniform octets spell 0x88E7 at
  offset 12 (or 0x88A8 there and 0x88E7 at 16) with probability ~2^-16.

  One `smith.slice` draw, the size class and the bias read from a
  `testkit.fuzz.Cursor` over the seed's own octets, and an eight-entry hex corpus of
  the module's own goldens — the B-Tagged frame, the untagged one that sits exactly
  on `min_frame_len`, and the Wireshark-anchored capture with its customer C-VLAN and
  IPv4 payload — plus a B-Tag with nothing behind it, a 0x8100 C-VLAN where a B-Tag
  belongs, and a one-octet truncation.

  Measured 2026-09-07, before → after: **0 of 8 seeds non-empty → 7 of 8**, 0 decoded
  → 3, and **0 B-Tagged frames → 2**. The B-Tag count is the discriminating one: the
  B-Tag is optional, so a corpus of untagged frames decodes perfectly while never
  entering the branch that has to tell 0x88A8 from 0x88E7 at the same offset.

- **2026-08-06** — Security audit: four findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified: Verified,
  not assumed. Both Wireshark goldens were re-executed against sharkd 4.6.4 today, and
  the *dissector reached* was checked via `frame.protocols`, not the exit.
- **2026-07-24** — New module: IEEE 802.1ah Provider Backbone Bridge (MAC-in-MAC) codec.
