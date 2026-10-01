# df-elect — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-01** — **Core isolation; lost frames are now checked.** Review
  found a black hole the checks could not see: a member whose inbound link
  died heard nobody, so it named itself DF for every tag, and its peers (which
  still heard it) deferred to that view — the segment received no frame for
  as long as the cut lasted (16 of 16 lost in a directed test; the sweep had
  drawn it, seed 66, and passed). Now every fabric node floods Hellos
  (non-members with `no_segment`), and a member that has heard none for
  `stale_after` is isolated: its view is empty, it holds nothing, and its
  peers stop counting it. New post-run `firstUnexplainedLoss` (`Origination`,
  `Loss`) checks traffic rather than roles; `worstZeroDfWindow` takes the
  links and counts only members some live node reaches. ⚠ `maxZeroDfWindow`
  grows by one `hello_period` (420 → 470: the isolation path), and
  `worstZeroDfWindow` gains a `links` parameter. Known limit, pinned by a
  test: a one-way failure deeper in the core can still black-hole a segment
  (SPEC Backlog: directed fabric graph). Sweep measurements moved off stderr.
  Mutation run: 33 of 37 killed, 4 equivalent; four tests added for guards
  nothing had pinned (timer start epoch, view mask, foreign-segment Hello,
  the `df_wait == hello_period` edge).
- **2026-09-30** — ⚠ **Breaking: N-member segments, RFC DF algorithms and
  failover.** `EdgeSegment` is now `{ id, esi, members: []Member{node, addr},
  tags }` (members sorted by address, `validate`); the DF is per
  `<segment, Ethernet tag>`: RFC 7432 §8.5 mod N (`moduloDf`), RFC 8584 §3.2
  HRW (`hrwDf`, `hrwWeight`) or preference-based (`preferenceDf`,
  `Member.pref`, what FRRouting runs), selected by `ElectConfig.algorithm`. Roles fail
  over: `stepRole` gives a role up at once and takes one after `df_wait`
  (default 150; `DfElect.init` refuses `df_wait <= hello_period`). `Hello`
  gains `view` and `BumFrame` gains `tag`; both are 17 octets. A member is
  named DF only when its own view and every live peer's advertised view name
  it — the fuzzer found a one-way link cut (`link_down` is directional) that
  duplicated without it. The old static single-owner election (zero duplicates,
  no failover) is gone, and with it `decide`/`SegmentView`/`Decision`/
  `maxBadDfWindow`/`worstBadDfWindow`: split-horizon stays zero-tolerance,
  duplicates are now allowed only within `maxDuplicateWindow` after a heal
  (`firstUnexplainedDuplicate`), and zero-DF is bounded by `maxZeroDfWindow`
  from the last disruption (`worstZeroDfWindow`). Fuzz sweep over both
  algorithms: worst duplicate 50 ticks after a heal (bound 100), worst zero-DF
  377 (bound 420). New REDERIVED vectors from `tools/rederive.py` and an
  EXTERNAL check of the preference choice against 12 phases observed from
  FRRouting 10.7.1 in rootless podman (`tools/frr/`); oracle n/a (class D) ->
  MIXED (class B), scope poc -> mvp; a failing
  sweep now prints its fault schedule. Scenario topology: a 3-member and a
  2-member segment sharing two tags.

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
