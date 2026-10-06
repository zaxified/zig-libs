# spbfib — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-06** — **NO CONSUMER-VISIBLE CHANGE:** SPEC consistency: the per-B-VID / ECT-set entry in "Deliberately deferred" now reads "not yet — see Backlog", matching the 2026-09-30 survey.
- **2026-10-05** — Mutation run: 25 of 26 killed, 1 equivalent; 1 test added (only
  metric 0 is a local route). No code change.
- **2026-09-30** — Anchored on RFC 6329 §5 (Figures 2-4): new `src/rfc6329_example_test.zig` asserts Figure 3 and Figure 4's 12 unicast rows and the 5 group DAs (7300-0x00-0001) against the module; anchor oracle SELF -> EXTERNAL. No code change.
- **2026-09-03** — **NO CONSUMER-VISIBLE CHANGE**, but a precondition every caller must now
  meet: build the `RouteTable` with `isis_spf.computeWith(..., .{ .reject_asymmetric = true })`.
  `isis-spf` became a directed engine on 2026-08-07, and plain `compute` hard-codes
  `reject_asymmetric = false`, so on an asymmetric-metric database the forward and reverse
  B-MAC paths need not be congruent, which SPB's reverse-path forwarding check assumes. This
  module's code did not change; the guarantee underneath it did. Stated in the module doc
  comment since `4a84c760`; this entry was missing until 2026-09-18.
- **2026-08-06** — Security audit: no findings. Modeled on IEEE 802.1aq SPBM FIB
  (conceptual; no C implementation to benchmark against) (design reference, not a test
  anchor).
- **2026-07-24** — New module: SPB (802.1aq) forwarding addressing — unicast B-MAC FIB
  from an `isis-spf` route table re-keyed by backbone MAC + SPBM group multicast-DA
  construction (SPSourceID + I-SID); one congruent ECT path.
