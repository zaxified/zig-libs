# SPEC — `kv`

**Purpose** — A crash-consistent embedded key-value store — the pure-Zig local database that
doesn't exist in the ecosystem. Bitcask-style append-only log with an in-memory index; the flagship
"worth-owning" module whose bar is **reliability, proven** (not features).

**Model after / Seed** — Bitcask (Basho; the log-structured KV design) / LMDB / xitdb; reliability
methodology = TigerBeetle's VOPR (Viewstamped Operation Replicator simulator). Greenfield. All I/O
through a `Storage` seam over `std.Io`. See NOTICE (Bitcask design ref).

**Design & invariants**
- **Append-only log + in-memory keydir:** writes append a record (crc + key + value) and update an
  in-memory `key → {file offset, size}` index; reads are one seek+read; recovery replays the log to
  rebuild the index. Deletes are tombstones.
- **Crash consistency:** a torn/partial trailing record is detected (CRC + length bounds) and
  discarded on recovery — a crash mid-write never corrupts previously-committed data. Durability
  invariants are model-checked (below).
- **Storage seam:** all disk I/O goes through an injectable `Storage` interface, so the whole engine
  runs against an in-memory fault-injecting fake — no real filesystem needed to test recovery.
- Threadsafe for the operations it exposes; single log owner.

**Threat model / out of scope** — Reliability, not adversarial security:
- **Fault model:** torn writes, partial/short reads, garbage tails, and crash-at-any-point are the
  threats; the VOPR fuzzes these across randomized workload+fault schedules and asserts 6 durability
  invariants after each crash+recovery, with a **sabotage self-test** (a recovery that loses
  committed data MUST be caught → `error.InvariantViolation`). Reproducible from a seed
  (splitmix64, no clock/OS-rng).
- **Out of scope (deferred):** MVCC / multi-version reads, HAMT on-disk index, ordered scans /
  range queries, transactions, secondary indexes, and a cross-process lock — the randomized VOPR is
  done; these on-disk/txn features are future work. Not a networked/served DB (embedded, in-process).
  No encryption-at-rest, no untrusted-input hardening on the log file (assumes the file is the
  engine's own, not attacker-supplied).

**Verification** — Unit tests + the **randomized deterministic VOPR** (`vopr.zig`): seeded fuzz of
recovery across torn/partial writes, short reads, garbage tails, and crash points ×3 modes over
chained epochs; min-fault-count asserts + the sabotage self-test (≥10/12 seeds catch a data-losing
recovery). 32 tests.

**Status** — `gap · any · both · threadsafe` · deps: none (std only, I/O via `Storage`/`std.Io`).
