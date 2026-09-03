# pagecache — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-03** — Drift re-audit. **The per-handle "pages ever touched" side
  table is gone**; `vClose` now sweeps the resident set by key prefix
  (`ramcache.removeMatching`). The table had two structural defects. It grew
  with the **store** rather than the cache — measured ~12 B live / ~18 B peak
  per distinct page touched, so a 4-page (16 KiB) budget over 200 000 pages
  held 2.4 MB, 145x the cache's own ceiling, while every `resident_pages <=
  max_pages` assertion held: the cap was real and bounded the wrong quantity.
  And it was filled best-effort, so a page whose tracking allocation failed
  outlived the close and was served for the **next file** on the recycled
  handle number — a `pread` of an empty file returning another file's page as
  a hit. The sweep is bounded by `max_pages` by construction and cannot fail
  to allocate.
- **2026-09-03** — **A failed write no longer leaves the cache holding bytes
  media does not have.** `writeAll` returned the inner error with the cache
  "unchanged, still the last correct copy" — which assumes the write was
  all-or-nothing. The real `FsStorage` shape is a looping `pwrite` whose
  second chunk can fail after the first landed, and the resident page is then
  OLDER than media: the cache masked the torn page from every reader in the
  process while a raw reader saw it. After a failed write the media state is
  unknown, so the page is dropped (whole cache for a sub-page write). The
  suite had no backend that could make an inner write fail at all, so this
  entire error path was unexercised and the write-through ordering guard was
  deletable with the suite green.
- **2026-09-03** — `Options` are refused by name instead of by
  `std.debug.assert`. `max_pages` has no default, so a caller computing it
  (`cache_bytes / page_size` with `cache_bytes < page_size`) gets 0, and in
  ReleaseFast the assert is `unreachable`: measured as a SIGSEGV inside `init`
  before it returned.
- **2026-09-03** — Test teeth: `vPread`'s "never cache a partially-present
  page" gate was deletable in both modes. Without it a 100-byte page reads
  back as a full page whose tail is the previous caller's buffer — in
  kvtree's `lookup` that is `var page: [page_size]u8 = undefined`, i.e.
  uninitialised stack presented as a tree page. Now pinned, along with the
  failed-write and recycled-handle behaviours above. SPEC records the
  one-handle-per-path precondition (two handles on one file are two key
  spaces) and stops claiming `ramcache` has no single-key removal.
- **2026-08-06** — Security audit: six findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on LMDB mmap'd
  pages / Postgres `shared_buffers` (design reference, not a test anchor).
- **2026-07-22** — New module: bounded write-through page cache between `kvtree`'s pager
  and its `Storage`.
