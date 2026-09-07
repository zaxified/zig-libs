# uci — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — Fuzz reach: both harnesses ran one empty input. `fuzzParse` opened
  `smith.bytes(&buf)` then drew the length with `smith.valueRangeAtMost`, which returns
  the range MINIMUM once `bytes` has eaten the input, so the target was `parse("")`.
  `fuzzRoundTrip` opened `smith.value(bool)`, so every choice after it was a minimum too:
  no package name, `n_sections` = 0 — an EMPTY `Package` serialized to an empty string
  and re-parsed, which round-trips perfectly and proves nothing. The serializer's
  bare-vs-quoted decision and its quote-escaping path, named in the harness's own comment
  as the whole reason the second target exists, were never entered. Measured 2026-09-07:
  1 round each, 0 sections, 0 options, 0 values. `fuzzParse` now draws byte-first with
  one `smith.slice` over 15 written config seeds (random bytes reject at the first
  keyword check essentially always, so a corpus is the only way this parser is reached at
  all). `fuzzRoundTrip` draws a SHAPE rather than a byte string, so it now reads every
  choice out of one byte-first `smith.slice` through `testkit.fuzz.Cursor` — the draw is
  honest and a seed is a readable script — with six scripts including the empty one,
  which reproduces the collapsed harness exactly. ⚠ The round-trip guard pins values
  built, not successful round trips: the empty package round-trips successfully, which is
  what the collapsed harness was doing. Pinned: 10 accepted / 48 sections / 47 values for
  `parse`, and 13 sections / 25 values for the generator.

- **2026-08-18** — New: `Package.sectionByName(name)` (resolves `pkg.<name>.<opt>` key-path
  addressing by name alone, across section types — matching libuci's own name lookup) and
  `Package.nth(type, index)` (resolves `@type[N]` positional addressing, including libuci's
  negative-index-from-the-end form; verified against libuci's `list.c` source, see SPEC.md).
  Both were previously hand-rolled by consumers over `iterate`, the negative-index case
  needing a counting pass first. Purely additive; no existing behavior changed. Also:
  SPEC.md's out-of-scope section now says explicitly that a file-only reader loses
  staged-but-uncommitted state (`uci set` without `commit`) and that `uci revert` truncates
  its delta file rather than deleting it — both previously implied only by "state files".
- **2026-07-19** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on libuci
  (LGPL-2.1; format-only reference, no source consulted) (design reference, not a test
  anchor).
- **2026-07-07** — New module: OpenWRT UCI config parser + serializer + typed model
  (stable round-trip).
