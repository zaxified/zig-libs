# uci — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
