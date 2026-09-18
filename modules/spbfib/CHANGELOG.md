# spbfib — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
