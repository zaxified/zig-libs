# tcplan — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-06** — ADDED: several classifiers per subscriber and HTB class knobs. **BREAKING:**
  `Node.match` is now `[]const Match` (was `?Match`): write `.match = &.{m}` for one entry,
  `&.{v4, v6}` for a dual-stack circuit; each entry becomes one `flower` filter into the
  subscriber's single class, prios consecutive in slice order. ADDED: `Node.htb`
  (`HtbKnobs`: `burst`/`cburst`/`prio`/`quantum`, defaults unchanged), `htb_max_prio`,
  `Match.overlaps`/`prefixValid`, errors `OverlappingMatch`, `HtbPrioOutOfRange`.
  **BEHAVIOURAL:** a prefix length past its family (IPv4 > 32, IPv6 > 128), which `tc`
  clamped silently, is now `error.InvalidPrefix`; two subscribers with overlapping prefixes
  (same family and direction), previously compiled with the lower prio silently winning, are
  now `error.OverlappingMatch`. New iproute2 oracle test (`tools/capture_dualstack.sh` →
  `src/testdata/dualstack_iproute2.txt`). Scope mvp → core.

- **2026-10-05** — Mutation run: 28 of 30 killed, 2 equivalent; 5 tests added (`cpu ==
  queue_count`, ceil-0 child vs parent ceil, `htb_defcls`, prio not spent by a match-less
  leaf, `mq` child ordering).
- **2026-08-06** — Security audit: no findings. Modeled on LibreQoS (design reference;
  no C binary to benchmark against) (design reference, not a test anchor).
- **2026-07-24** — New module: Compile a hierarchical shaping topology
  (site→AP→subscriber, committed/ceil rates) into a deterministic ordered plan of `tc`
  ops.
