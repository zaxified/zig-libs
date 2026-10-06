# tcplan — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-05** — Mutation run: 28 of 30 killed, 2 equivalent; 5 tests added (`cpu ==
  queue_count`, ceil-0 child vs parent ceil, `htb_defcls`, prio not spent by a match-less
  leaf, `mq` child ordering).
- **2026-08-06** — Security audit: no findings. Modeled on LibreQoS (design reference;
  no C binary to benchmark against) (design reference, not a test anchor).
- **2026-07-24** — New module: Compile a hierarchical shaping topology
  (site→AP→subscriber, committed/ceil rates) into a deterministic ordered plan of `tc`
  ops.
