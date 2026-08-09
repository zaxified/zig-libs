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
- **Single writer, enforced across processes:** `open` takes an exclusive advisory `flock(2)` on a
  sidecar `<path>.lock` (non-blocking → `error.Locked`) and holds it until `close`, so the lock
  spans every write *and* its fsync, and the whole of recovery (replay + tail truncation happen
  after acquisition — a refused open does not touch the data file). `flock` over
  `fcntl(F_SETLK)`: description-scoped rather than process-scoped, so an unrelated `close` of the
  same path elsewhere in the program cannot silently release it, and `fork` yields one shared
  holder rather than a child with no lock that can then re-lock. Kernel release on process death
  means no stale locks and no PID-file heuristics. The lock is a sidecar, not the data file,
  because `compact()`'s `rename(2)` would otherwise strand it on an unlinked inode. Opt out:
  `Options.lock = .none`. See README for what is *not* promised (advisory only; NFS/SMB/9p/FUSE).

## Optional borrow methods on `Storage`

`preadRef` / `releaseRef` are `?*const fn` vtable slots defaulting to `null`.
`null` means "this backend cannot lend", which is the truthful answer for a
descriptor-backed backend: the bytes only exist once the kernel has copied them
somewhere. `FsStorage`, `SimStorage` and the VOPR backend therefore leave them
alone and `Storage.canLend()` answers `false` for them — the defaults exist
precisely so no implementer is pushed into writing a stub that quietly copies.

`preadRef` returns `Error!?Ref`; `null` is never an error and never a partial or
stale success, it is "use `pread`". There is deliberately no internal fall-back
to a copying read, because a fall-back that looks like a success makes "did the
fast path engage?" unanswerable at the call site. A non-null `Ref` must go back
to `releaseRef` exactly once; between the two, the backend guarantees the bytes
neither move nor change nor are freed. `pagecache` is the implementor today
(it holds page bytes in its own memory); `kvtree`'s read descent is the caller.

## Threat model / out of scope

Reliability, not adversarial security:
- **Fault model:** torn writes, partial/short reads, garbage tails, and crash-at-any-point are the
  threats; the VOPR fuzzes these across randomized workload+fault schedules and asserts 6
  durability invariants after each crash+recovery, with a **sabotage self-test** (a recovery that
  loses committed data MUST be caught → `error.InvariantViolation`). Reproducible from a fixed
  PRNG value (splitmix64, no clock/OS-rng).
- **Out of scope (deferred):** MVCC / multi-version reads, HAMT on-disk index, ordered scans /
  range queries, transactions, secondary indexes, and shared/reader locks — the randomized VOPR is
  done; these on-disk/txn features are future work. (The **cross-process lock** was on this list
  until 2026-08-06 and is now built — see Design & invariants; only the *shared* mode remains
  deferred, the store being single-writer.) Not a networked/served DB (embedded,
  in-process). No encryption-at-rest, no untrusted-input hardening on the log file (assumes the
  file is the engine's own, not attacker-supplied).

## Verification

Unit tests + the randomized deterministic **VOPR** (`vopr.zig`): PRNG-driven fuzz of recovery across
torn/partial writes, short reads, garbage tails, and crash points ×4 modes (incl. non-contiguous /
out-of-order durability, see below) over chained epochs; min-fault-count asserts + the sabotage
self-test (≥10/12 runs catch a data-losing recovery). Run: `zig build test-kv`.

- **Cross-process lock — modeled, not just implemented** (2026-08-06): `tryLockExclusive` is a
  `Storage` vtable op and an injection point, so the fixed sweep crashes on the acquisition like
  any other side effect (57 points × 3 modes). `SimStorage` models a lock as belonging to an open
  file *description* (a second `Handle` on the same name contends), released by `close` and by our
  own crash but **not** by a `holdForeignLock` holder — which is what lets a sweep assert that a
  post-crash recovery contended by another process is refused with `error.Locked` and leaves the
  torn file byte-identical, then succeeds with full invariants once that process is gone.
  `lock_unsupported` models a filesystem with no `flock` (`error.LockUnsupported`, never a silent
  downgrade). The guarantee callers actually buy is proved by two **forked child processes**
  (bounded: `alarm(2)` self-destruct + a deadline-and-`SIGKILL` reaper): a real second process is
  refused, and a `SIGKILL`ed holder — no destructor, no unlock, nothing — leaves the store
  immediately openable with its durable write intact.

- **Fault-scheduling policy is a seam** (`scheduler.zig`, 2026-07-15): the epoch-planning
  decision (which fault, how soon) that used to be inline in `Vopr.runSeed` is a pluggable
  `FaultScheduler` (`Config.scheduler`). `uniformScheduler` is behaviorally identical to the old
  inline logic (same PRNG draw order — no VOPR determinism/stats change). A `Coverage` tally
  (fault-class × early/late-timing cells) is threaded through and recorded on every draw.
- **Coverage-guided fault scheduling — implemented** (`scheduler.zig`, 2026-07-15):
  `coverageGuidedScheduler(&state)` biases the (class × timing) draw toward the least-exercised
  cells via a bandit-style epsilon-greedy rule (exploit = coldest reachable cell w/ random
  tie-break; explore = 1-in-`explore_den` uniform draw). Its `CoverageGuided.session` tally
  PERSISTS across seeds (the piece that made the difference — a per-seed tally degenerates to
  uniform), so a session converges on all 13 reachable cells in ~13 exploit draws instead of
  waiting for uniform sampling to stumble onto the ~1-in-24 rare cells. Fully seeded/deterministic;
  a test asserts it leaves strictly fewer (class × bucket) cells uncovered than `uniformScheduler`
  over an identical draw budget.
- **Failing-seed search + delta-debugging shrinker** (`shrink.zig` + `vopr.zig`, 2026-07-15):
  `findFailingSeed` sweeps a seed range through the VOPR and returns the first captured failure;
  `run` is the CLI-style driver (`--seed`/`--search`/`--shrink`). `shrink` minimizes a failing run
  to a small reproducer. The blocker — kv's VOPR derives its whole workload+fault schedule live
  from the seed's `Prng`, so the captured `Event` trace is an observation, not a re-runnable
  program — is resolved by a **trace-replay mode** in `vopr.zig`: `generateTrace` re-captures a
  seed as a `RecordedTrace` (concrete op list with actual value bytes, crash mode/timing/reorder
  seed, garbage bytes, sabotage), and `replayTrace` executes any subset deterministically without
  a live `Prng`. `shrink` runs ddmin over that trace (drop ops → drop epochs → neutralize faults),
  re-replaying after each cut and keeping the reduction only when the SAME invariant violation
  still reproduces; a test shows it cuts a failing sabotage trace to a strictly smaller reproducer.

## Backlog / deferred
- **On-disk/MVCC/txn/ordered-scans → DON'T-BUILD-YET** (ecosystem-scanned): multi-week+
  build (B-tree + WAL + MVCC + crash-proof + VOPR sweep) with zero current consumers demanding
  scans/txn. When greenlit: steal-patterns from `xitdb` (HAMT/B-tree + immutable-snapshot-as-MVCC
  over kv's existing atomic-swap seam) + TigerBeetle's VOPR methodology (not code); phased
  ordered-scan B-tree → atomic batches → MVCC snapshot reads → secondary indexes. Bitcask kv is
  enough until then.
- **VOPR fault-sweep DONE (2026-07-10):** green at 10× the shipped
  run count (20k runs, no failures); crash-anywhere + torn/partial + byte-arbitrary-tear faults are
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
