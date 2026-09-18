# nftables — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — Both fuzz targets walked an empty attribute list. Each opened with
  `smith.bytes(&raw)` and then drew its length with `valueRangeAtMost`, which reads eight input
  octets as a little-endian u64 and returns the range minimum when fewer remain — so the length
  was 0 on every seed and the walkers were handed `""`. In `expr.fuzzExprWalk` that read as
  perfect health: an empty `NFTA_RULE_EXPRESSIONS` nest is a legal rule body, so the walk
  "completed" every round while the loop it is made of never executed once, and the
  `steps <= buf.len / 4 + 1` bound the target is built around was never evaluated.
  `wire.fuzzDecoders` was refused at `payload.len < nfgenmsg_len`, so neither the expression
  iterator nor the set-element iterator ran. Both now draw with one `smith.slice(&buf)` at 2048
  octets (a rule with real expressions and a set-element reply both run past the old 512, so a
  corpus of them would have read back EMPTY), carry corpora built by this module's own `Program`,
  `appendExpr` and attribute writers, and are pinned by guards counting expressions walked, inner
  attributes read, verdicts decoded, objects named, handles read and set elements yielded — a
  bare `nfgenmsg` is a legal reply that ALL FIVE decoders accept while returning structs of
  defaults, so an acceptance count is silent about whether anything was walked. Verified by
  mutation: `parseNfgenmsg`'s length gate and `ExprIterator`'s "not an expression element" skip
  are both caught.

- **2026-09-04** — **Four consistency tests and three live socket tests
  reported PASS where they meant SKIP.** `zig test` counts a bare `return;` as a
  pass, so a host that cannot open a `NETLINK_NETFILTER` socket saw
  `2/2 tests passed` while the run printed "SKIPPED". `liveSocket` now returns
  an error union instead of `?Socket`, so `orelse return;` — which swallowed the
  skip in a different function from the one that announced it — is `try`.
  Measured: the module went from 94 passing to **90 pass, 4 skip**. Found by the
  first audit of `testkit`; `scripts/checks/check-skip-as-pass.py` now refuses the
  shape.

- **2026-09-02** — **Audit (drift campaign): 1 CRITICAL (in `netlink`, reached from here), 2
  MEDIUM, 2 LOW, 2 doc.** The CRITICAL is `codec.nestEnd`'s silent nest-length truncation — see
  `netlink`'s entry; from here it meant `addSetElems` with ~4096 elements, or `addRule` with
  ~3277 expressions, **committed a partially-installed ruleset and reported success**. Refused
  now (`error.AttrTooLong`), with a regression test at 6000 elements.
  **MEDIUM — `ifnameCmp` trimmed an over-long interface name** into a `cmp` against its first 16
  bytes: since no Linux interface can be named that, a `drop` built this way never fired.
  `nft(8)` refuses the same input ("String exceeds maximum length of 16"); so does
  `ifnameBytes` now (`InterfaceNameTooLong`).
  **MEDIUM — `ipv4MaskBytes` accepted prefix lengths 33..63** and returned a mask anyway: `/33`
  came out as `80000000` in ReleaseFast, the mask of a `/1`. `InvalidPrefixLength` now;
  `ipPrefix` had always guarded it, the public helper beside it had not.
  **LOW — `payloadLookup` was missing the `max_value_len` bound** its two `cmp` siblings got when
  2026-08-11's F3 was fixed: the fix set was incomplete.
  **LOW — a `limit` rate wrapped when scaled by its unit**, producing a limit far TIGHTER than
  asked for (1 MiB/s for `(1 << 44) + 1` mbytes/s) with no error in ReleaseFast.
  **Docs:** `NF_NAT_RANGE_MAP_IPS`'s comment described behaviour this module does not have, and
  SPEC's "unanchored header offsets" backlog bullet had outlived its defect — a stale bullet
  makes a future auditor skip a check that now works. Every fix carries a test that goes red when
  the fix is reverted. Ledger: `~/CML/20260931-zig-libs-audit/nftables.md`.

- **2026-08-18** — **BEHAVIOURAL, not breaking:** two API gaps closed after a
  consumer adopted the native read path and hit both. (1) `Socket.listTables`/
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
