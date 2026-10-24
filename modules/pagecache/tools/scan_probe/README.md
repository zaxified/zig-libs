# scan_probe — scan resistance, pagecache vs SQLite

Measures the one lead pagecache claims over SQLite's page cache (pcache1, LRU):
**one full sequential scan does not push the hot working set out.**

Workload, identical on both sides: a file of N 4096-byte pages, a cache of C
pages (C << N), a hot set of H < C pages read `passes` times, then ONE
sequential scan of all N pages, then the hot set once more. The number printed
is how many reads reached the backing store in each phase; `hot-again` is the
one that matters (every read there is a hot page the scan evicted).

- `probe.zig` — pagecache side: `PageCache(.max_pages = C)` over a counting
  `Storage` wrapping `kvtree.SimStorage`.
- `sqlite_side.py` — SQLite side (python3 `sqlite3`, 3.46): one row per leaf
  page, `PRAGMA cache_size = C` (pages), `PRAGMA mmap_size = 0`. Backend reads are
  counted from outside with `strace -f -e trace=pread64,getppid`; phases are
  marked by `getppid()` calls. Only 4096-byte preads are page reads; the
  16-byte file-change-counter read SQLite makes once per statement is listed
  separately and excluded.
- `run.sh` — builds the Zig side (no build.zig step; plain `zig build-exe` with
  `-M` modules) and runs both sides over three configurations.

Run: `hw run --slots 1 --name pc-probe -- bash modules/pagecache/tools/scan_probe/run.sh`
(needs `strace` and `python3`). Output: one `pagecache ...` line per
configuration, then per configuration a `sqlite ...` line.

Caveat: the pagecache side uses an in-memory backend, so only the read COUNT
is comparable, never time. SQLite's counts include its interior B-tree pages
(a handful per phase).
