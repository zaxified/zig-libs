# bumtree — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-05** — Mutation run: 24 of 24 killed, 0 equivalent; 1 test added (source id
  == `node_count`, `deliversLocally` of a reachable non-member, `prune = false` past an
  unreachable node). No code change.
- **2026-09-30** — Anchored on RFC 6329 §5/§6 (Figures 2-7): new `src/rfc6329_example_test.zig` asserts the IN/IF and OUT/IF rows of Figures 3, 4, 6, 7 and the source-:1 SPT against the module; anchor oracle SELF -> EXTERNAL. No code change.
- **2026-08-06** — Security audit: three findings fixed, two documented as accepted (not
  defects) — part of the collection-wide audit. Modeled on IEEE 802.1aq SPBM per-source
  tree + RPFC (conceptual; no C lib) (design reference, not a test anchor).
- **2026-07-24** — New module: SPB per-source loop-free BUM distribution tree + RPF
  check over `spf-ect`.
