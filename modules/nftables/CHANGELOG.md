# nftables — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-18** — **BEHAVIOURAL, not breaking:** two API gaps closed after a
  consumer (AXP) adopted the native read path and hit both. (1) `Socket.listTables`/
  `listChains`/`listSets`/`listRules`, and `wire.buildDumpRequest`/`buildRuleDumpRequest`,
  now take `family: ?Family` instead of `Family` — `null` sends `nfgen_family =
  NFPROTO_UNSPEC` (0), the same framing `nft list ruleset` uses to sweep every family in
  one request, instead of a caller walking all six itself (18 round trips down to 3 for a
  full table+chain+rule dump). Source-compatible: a concrete `Family` still coerces to the
  new optional at every existing call site, so no caller changes. Verified live in a netns:
  one `listTables(null)` call returns tables from two different families in a single dump
  (`socket.zig`'s new "unspec-family dump" test). Deliberately **not** widened to a plain
  `.unspec` member on `Family` itself — the enum is also the value type of every
  mutation-building call (`TableSpec.family`, `Batch.deleteTable`, `expr.Program.init`,
  `Hook.num`, …), where an unspecified family is meaningless or wrong, so adding it there
  would have made every one of those call sites accept a value that cannot be encoded
  correctly. `listSetElems` was left untouched: it already names one specific,
  already-resolved table/set, not a family-wide sweep. (2) `NFPROTO`, `NF` and `NFT` — the
  kernel constant structs `TableInfo.family`/`ChainInfo.family`/`RuleInfo.family`/
  `SetInfo.family` (raw `u8`) and `ChainInfo.policy` (raw `?i32`) are expressed in — are now
  re-exported from the module root, so a consumer decoding a dump no longer has to name
  `nftables.types` to interpret what `nftables.Socket` handed it back. Also added
  `Family.fromNfproto(u8) ?Family` and `Policy.fromVerdict(i32) ?Policy`, the exact reverse
  of `.nfproto()`/`.verdict()`, so a consumer can recover the typed enum (and its JSON
  schema token via `@tagName`) directly from a decoded byte. Did **not** add a general
  `familyName(u8)`/`verdictName(i32)` string-returning helper as the consumer suggested:
  `Family`'s tag names already are the canonical JSON schema tokens, so `fromNfproto` +
  `@tagName` covers that case with one source of truth rather than a second string table
  that could drift from it; `Policy.fromVerdict` covers the one verdict site
  (`ChainInfo.policy`) that is provably total (a base chain's policy is only ever
  accept/drop). A blanket verdict-code-to-string mapping across all of `NF`/`NFT` was
  rejected because it has no established canonical spelling in this module — e.g.
  `NFT.BREAK` names no JSON/schema token anywhere here (no `Stmt` variant corresponds to
  it), so any string chosen for it would be this module inventing a convention, not
  re-exposing an existing one; a consumer decoding the handful of verdict codes it actually
  sees is better placed to name them than a helper guessing at codes it may never encounter.
- **2026-08-11** — Security audit: three findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Byte-exact JSON
  goldens for three rule shapes, plus a live check that the generated ruleset is
  accepted by a real `nft -c -j -f -`.
- **2026-07-07** — New module: Typed firewall-ruleset builder → libnftables JSON for
  `nft -j -f -` (families/chains/rules/sets, match + verdict statements).
