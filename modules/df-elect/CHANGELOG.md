# df-elect — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-11** — Consumer-side follow-up to the `netsim` A1 fix campaign
  (F6): `BrokenAlwaysDf` fires from its own BUM-flooding traffic alone,
  with no injected fault (the "positive control" test already proves it
  trips on a completely empty trace), so `netsim`'s shrinker now correctly
  reduces its counterexample to the EMPTY fault set instead of a pre-fix
  floor of `>= 1` — the "shrink" test's assertion updated from
  `try testing.expect(res.after >= 1);` to
  `try testing.expectEqual(@as(usize, 0), res.after);`. No behavioural
  change to `df-elect` itself. `scripts/modtest df-elect`: 37/37.

- **2026-09-07** — Fuzz reach: neither `fuzzTagOf` nor `fuzzFrames` ever reached its
  decoder. Both opened `smith.bytes(&buf)` and then drew the length with
  `smith.valueRangeAtMost`; `bytes` consumes `@min(buf.len, in.len)` octets and a ranged
  draw reads EIGHT more as a little-endian `u64`, returning the range MINIMUM when fewer
  remain — so the length was 0 for every input a corpus can carry. Neither target had a
  corpus, so the single input each ever executed was empty and both decoders answered
  `error.Truncated` on their first line, with the drawn frame sitting unread in `buf`.
  Measured 2026-09-07: 1 round, 0 non-empty inputs, 0 tags resolved, 0 frames decoded.
  Both draws are now one `smith.slice(&buf)`, `fuzzTagOf`'s buffer was raised from 8 to
  `Hello.wire_len` so a whole frame fits (the shape every dispatch site passes it), and
  each target carries a written corpus: 7 tag octets including the undefined-tag path the
  decoder exists to keep out of `@enumFromInt`, and 9 frames including both 13-octet
  encodings, the cross-decode refusal, a 26-octet two-frame buffer and a truncation.
  Corpus guards draw exactly as the harnesses do and pin 2 hellos / 2 bums / 2 invalid
  tags, and 3 hellos / 2 bums with a pinned sum over `BumFrame.id()`.

- **2026-07-19** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this).
- **2026-07-15** — New module: Partition-correct Designated-Forwarder election (static
  link-state total order, forced by a duplicate-freedom argument — RFC 7432 §8.5 analog)
  + split-horizon; bounded-badness model-checked in netsim.
