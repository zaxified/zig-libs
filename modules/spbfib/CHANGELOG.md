# spbfib — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-06** — Security audit: no findings. Modeled on IEEE 802.1aq SPBM FIB
  (conceptual; no C implementation to benchmark against) (design reference, not a test
  anchor).
- **2026-07-24** — New module: SPB (802.1aq) forwarding addressing — unicast B-MAC FIB
  from an `isis-spf` route table re-keyed by backbone MAC + SPBM group multicast-DA
  construction (SPSourceID + I-SID); one congruent ECT path.
