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
  loses committed data MUST be caught → `error.InvariantViolation`). Reproducible from a fixed
  PRNG value (splitmix64, no clock/OS-rng).
- **Out of scope (deferred):** MVCC / multi-version reads, HAMT on-disk index, ordered scans /
  range queries, transactions, secondary indexes, and a cross-process lock — the randomized VOPR is
  done; these on-disk/txn features are future work. Not a networked/served DB (embedded,
  in-process). No encryption-at-rest, no untrusted-input hardening on the log file (assumes the
  file is the engine's own, not attacker-supplied).

## Verification

Unit tests + the randomized deterministic **VOPR** (`vopr.zig`): PRNG-driven fuzz of recovery across
torn/partial writes, short reads, garbage tails, and crash points ×4 modes (incl. non-contiguous /
out-of-order durability, see below) over chained epochs; min-fault-count asserts + the sabotage
self-test (≥10/12 runs catch a data-losing recovery). 36 tests. Run: `zig build test-kv`.

## Backlog / deferred

- **On-disk/MVCC/txn/ordered-scans → DON'T-BUILD-YET** (ecosystem-scanned): multi-week+
  build (B-tree + WAL + MVCC + crash-proof + VOPR sweep) with zero current consumers demanding
  scans/txn. When greenlit: steal-patterns from `xitdb` (HAMT/B-tree + immutable-snapshot-as-MVCC
  over kv's existing atomic-swap seam) + TigerBeetle's VOPR methodology (not code); phased
  ordered-scan B-tree → atomic batches → MVCC snapshot reads → secondary indexes. Bitcask kv is
  enough until then.
- **VOPR fault-sweep DONE (2026-07-10):** green at 10× the shipped
  run count (20k runs, 0 failures); crash-anywhere + torn/partial + byte-arbitrary-tear faults are
  covered, CRC-gated fail-stop replay is sound (torn/corrupt tail truncated, never replayed as valid).
- **Out-of-order / non-contiguous durability — COVERED 2026-07-10.** The former gap (`SimStorage`
  could only collapse an un-synced window to a *contiguous prefix*) is closed: a new
  `CrashMode.reorder_unsynced` tracks every `writeAll` since the last durability barrier as a
  byte-range and, on crash, keeps a seed-driven **subset** of them — dropping an earlier range while
  keeping a later one leaves a zero-filled *hole* between persisted regions (splitmix64,
  deterministic, no clock/OS-rng). It is exercised generally in the VOPR (a 4th crash mode) and
  targeted at `compact()`'s write-loop-then-single-`sync` temp-file window (root.zig ~632–648) by a
  dedicated exhaustive sweep in `fault_test.zig` (every crash point × several seeds; a teeth assert
  requires real holes to be punched). **Outcome: no defect — recovery is correct under
  non-contiguous persistence.** Two structural reasons, now proven by the harness: (1) the CRC32
  fail-stop replay truncates at the first hole, so a persisted-but-orphaned later record is *never*
  resurrected, and committed records *before* a hole are never over-truncated (a hole can only sit
  in the append-only tail, above every fsync'd record — direct replay-level test in `root.zig`);
  (2) the only multi-write-before-`sync` window in the engine is `compact()`'s *temp* file, and the
  temp is either discarded on reopen (crash before the rename) or adopted only *after* a full
  `sync` (crash at/after the rename has no un-synced window), so recovery never depends on intra-file
  write ordering. No product-code change was required — the temp-then-atomic-rename discipline was
  already sound; the deliverable is the harness coverage that proves it.

## Status

`gap · any · both · threadsafe` + deps: none (std only, I/O via `Storage`/`std.Io`) — canonical
source is `pub const meta` in src/root.zig.
