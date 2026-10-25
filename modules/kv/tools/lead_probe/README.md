# lead_probe — kv beside rosedb, bitcask, nutsdb

Backs the dated `**Ahead:**` claims on kv's maturity card: a read-only open
beside a live writer (P1) and recovery after a torn tail (P2). P3 (a flipped
byte in a sealed file) is NOT a lead: all four stores detect it.

Stores: kv (`FsStorage` plain and `initMmap`), rosedb v2.4.0, prologic/bitcask
v1.0.2 (default, index removed, `WithAutoRecovery`), nutsdb v1.1.0
(`HintKeyAndRAMIdxMode`). Input: 1000 keys `k%08d`, 100-byte values, no fsync,
clean close; every trial runs each store in its own OS process.

- P1: process A (RW) holds the store, B opens beside it (kv: `read_only`;
  the foreign stores have no read-only option, so a plain open) and reads; A
  writes 10 more; B reads before and after `refresh`; B tries a put.
- P2: truncate the active file by k bytes / append k random bytes (20 seeds) /
  zero the tail (nutsdb); per trial check -> putnew -> getnew -> check.
- P3: flip one byte (xor 0x40) in a value of a sealed file (small segments),
  reopen and read all; P3b flips it under an already open store.

Files:
- `zig/probe.zig` — kv side; `common.go` — Go driver shared by all Go probes;
  `go/<store>/{adapter.go,go.mod,go.sum}` — one small module per store. Three
  modules because the stores pin different dependency sets (go.mod/go.sum are
  identical to `../go_bench`, `../bitcask_bench`, `../nutsdb_bench`); `run.sh`
  copies `common.go` next to each adapter in a staging dir, so it is kept once.
- `drive.py` — scenario driver and summary printer.
- `repro/rosedb_garbage_panic.sh [K [SEED]]` — single repro of the rosedb panic
  in `Open` after k random trailing bytes (needs the binaries from `run.sh`).
- `run.sh` — builds everything (no build.zig step) and runs all scenarios.

Run: `hw run --slots 1 --mem 6G --name kv-lead --quiet 600 -- bash modules/kv/tools/lead_probe/run.sh`
Scratch and results: `.zig-cache/kv-lead-probe/` (`results/*.json`).

Caveats: tampering happens after a clean close, not a real crash (bitcask with
its index removed is the closer crash analog); only tail truncation/garbage, no
holes in the middle; no kill -9 or power loss; no reader across a kv merge.
The nutsdb P3b error text sometimes names a different key than the flipped one
(not investigated).
