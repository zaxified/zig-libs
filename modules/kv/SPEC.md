# kv — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants

- **Append-only log + in-memory keydir:** writes append a record (crc + key + value) and update an
  in-memory `key → {file offset, size}` index; reads are one seek+read; recovery replays the log to
  rebuild the index. Deletes are tombstones. Modeled after Bitcask (Basho) / LMDB / xitdb; see
  NOTICE.
- **Crash consistency:** a torn/partial trailing record is detected (CRC + length bounds) and
  discarded on recovery — a crash mid-write never corrupts previously-committed data. Durability
  invariants are model-checked (see Verification).
- **Storage seam:** all disk I/O goes through an injectable `Storage` interface, so the whole engine
  runs against an in-memory fault-injecting fake — no real filesystem needed to test recovery.
- Threadsafe for the operations it exposes; single log owner.

## Threat model / out of scope

Reliability, not adversarial security:
- **Fault model:** torn writes, partial/short reads, garbage tails, and crash-at-any-point are the
  threats; the VOPR fuzzes these across randomized workload+fault schedules and asserts 6
  durability invariants after each crash+recovery, with a **sabotage self-test** (a recovery that
  loses committed data MUST be caught → `error.InvariantViolation`). Reproducible from a seed
  (splitmix64, no clock/OS-rng).
- **Out of scope (deferred):** MVCC / multi-version reads, HAMT on-disk index, ordered scans /
  range queries, transactions, secondary indexes, and a cross-process lock — the randomized VOPR is
  done; these on-disk/txn features are future work. Not a networked/served DB (embedded,
  in-process). No encryption-at-rest, no untrusted-input hardening on the log file (assumes the
  file is the engine's own, not attacker-supplied).

## Verification

Unit tests + the randomized deterministic **VOPR** (`vopr.zig`): seeded fuzz of recovery across
torn/partial writes, short reads, garbage tails, and crash points ×3 modes over chained epochs;
min-fault-count asserts + the sabotage self-test (≥10/12 seeds catch a data-losing recovery). 32
tests. Run: `zig build test-kv`.

## Backlog / deferred

- **On-disk/MVCC/txn/ordered-scans → DON'T-BUILD-YET** (ecosystem-scanned): multi-week+
  build (B-tree + WAL + MVCC + crash-proof + VOPR sweep) with zero current consumers demanding
  scans/txn. When greenlit: steal-patterns from `xitdb` (HAMT/B-tree + immutable-snapshot-as-MVCC
  over kv's existing atomic-swap seam) + TigerBeetle's VOPR methodology (not code); phased
  ordered-scan B-tree → atomic batches → MVCC snapshot reads → secondary indexes. Bitcask kv is
  enough until then.
- Pending repo-wide **security/similarity review pass** (see /docs/pre-public-review.md): `kv`
  fault-sweep re-audit before any release.

## Status

`gap · any · both · threadsafe` + deps: none (std only, I/O via `Storage`/`std.Io`) — canonical
source is `pub const meta` in src/root.zig.
