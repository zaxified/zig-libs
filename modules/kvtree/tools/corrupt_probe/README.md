# corrupt_probe — damaged database file, kvtree vs bbolt vs LMDB

Backs the dated `**Ahead:**` claim on kvtree's maturity card: on a store file
with 1..8 random bytes flipped, kvtree never crashes, hangs or panics, while
bbolt v1.5.0 and LMDB 0.9.31 do in a few percent of trials.

Method: one pristine store per side (2000 keys `k%08d`, 100-byte values), then
per trial a deterministic damage (pure function of the seed
`w9-<side>-<mode>-<i>`) and `<probe> check` in a fresh process: open, point-get
all keys, ordered scan, close. Modes: `page` = flips inside one random used
page >= 2; `file` = flips anywhere. Classes: CLEAN (all answers right), WRONG-value
(only a value differs), WRONG-struct (key missing/added/changed/out of order or wrong
count), ERROR (typed error, exit 11), PANIC (crash by signal, Go panic, any
other exit, or a hang past 5 s).

- `kvtree/corrupt.zig` — kvtree probe (`FsStorage`, no page cache).
- `bbolt/` — Go probe; `go.mod`/`go.sum` pin the same `go.etcd.io/bbolt v1.5.0`
  / `x/sys v0.45.0` as `../go_bench`.
- `lmdb/main.c` — LMDB probe against the host `liblmdb.so.0` (hand-written
  prototypes, no headers).
- `run.py` — driver (4 worker threads), prints the summary table.
- `run.sh` — builds all three (no build.zig step), makes the pristine stores,
  runs the driver. Scratch under `.zig-cache/corrupt-probe/`.

Run: `hw run --slots 1 --mem 6G --name kvtree-corrupt --quiet 600 -- bash modules/kvtree/tools/corrupt_probe/run.sh [M]`
(M defaults to 3000; the cited run took ~150 s). Needs zig 0.17, go with an
offline module cache, gcc, liblmdb.so.0.

Caveats: none of the three stores checksums node pages, so a flipped value byte
is undetectable by design and lands in WRONG everywhere; the PANIC and ERROR
columns are the comparison. This is NOT a damage-detection claim. Only random
byte flips (no truncation, zero-fill, page swaps), read side only, RW open, no
mmap storage for kvtree. Trial directories are deleted as they finish; a
single trial is reproducible from its seed.
