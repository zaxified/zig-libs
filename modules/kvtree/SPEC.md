# kvtree — spec

Embedded ordered transactional key-value store: a copy-on-write B-tree with
MVCC snapshot isolation, multi-key ACID transactions, ordered range scans, and
VOPR-checked crash-safety. Usage: see ./README.md. Provenance (clean-room from
the LMDB/BoltDB design + the TigerBeetle VOPR method — design references, no
source ported): see /NOTICE.

## Status: core IMPLEMENTED (gate flipped)

The three irreducible correctness functions in `core.zig` are implemented and
`gate.fable_core_implemented` is `true`: the formerly-gated property tests now
drive the real `Db` — a snapshot-isolation + serializability schedule with a
multi-level-tree phase (~850 commits under pinned snapshots), and a
crash-point sweep over every storage side effect of an open+commit across all
four `kv.SimStorage` crash modes, including a destroy-the-in-flight-meta
probe for the double-buffer invariant. Everything is green in Debug and
ReleaseFast, `zig fmt` clean, no leaks. The section below is kept as the
specification the implementation was written against.

## The architecture decision: (A) copy-on-write B-tree, not (B) B-tree + WAL

Two designs give ordered + transactional + MVCC over a single file:

- **(A) COW B-tree (LMDB / BoltDB).** A write transaction copies every node on
  its root-to-leaf path instead of mutating in place, then swaps a single
  durable pointer — the meta page — from the old root to the new one. MVCC,
  atomic commit and crash-safety are *emergent* from this one mechanism.
- **(B) B-tree + WAL (SQLite).** Durability and atomicity come from a
  write-ahead log replayed on recovery; MVCC readers read through WAL frames.

**Chosen: (A).** The decisive reason is that (A) has **no second state machine
to get wrong**. In (B), correctness lives in the WAL protocol — frame framing,
checkpoint/truncation ordering, the salt/counter scheme, reader marks, the
recovery replay — a large surface that must itself be crash-consistent *in
addition to* the B-tree. In (A) the entire durability story is "write the new
pages, fsync, write one of two meta pages, fsync": snapshot isolation is a
reader pinning an old root, atomic commit is the single meta-pointer swap, and
crash-recovery is "pick the newest of two meta pages that still validates."
Fewer moving parts, and every one of them maps onto a primitive `kv` v0 already
proves out (append + fsync + a validating recovery scan). The concrete
disqualifier-check for our access pattern came up empty: our consumers are
embedded, single-writer, low-contention (`jobqueue`-shaped), so COW's two costs
— write amplification (a whole root-to-leaf path rewritten per commit) and
single-writer serialization — are irrelevant here, while its simpler crash story
is exactly what we want to be able to VOPR-prove. (B)'s WAL only pays off under
high write concurrency we do not have.

## New module, coexisting with `kv` v0 (not a supersede)

`kvtree` is a **new module** alongside `kv`, not a replacement. `kv` v0 is a
stable, VOPR-proven Bitcask point store with a live consumer (`jobqueue`) that
needs only get/put — no ordered scan, no transactions. Superseding it would
force B-tree write-amplification and complexity onto a workload that does not
want them, and churn a shipped module. The split is the repo's standard
client/server-style split by deliverable: reach for `kv` for a minimal
append-only point store; reach for `kvtree` when you need `scan(a..b)` in key
order, atomic multi-key commit/rollback, or lockless MVCC readers.

Reuse, not duplication: `kvtree` depends on `kv` purely to reuse its
`Storage` seam — the injectable page/offset I/O interface **and** its
deterministic crash/fault simulator `SimStorage` (torn writes, out-of-order
durability, I/O-error injection). A page store is an offset-addressed blob
store, which is exactly what that seam is, so the whole VOPR fault machinery
comes for free.

## On-disk layout

Single 4 KiB page unit (`format.zig`):

- **page 0, page 1** — the two META pages, double-buffered. A commit writes the
  meta slot it is *not* currently rooted at, then fsyncs, so a torn meta write
  never destroys the last good one.
- **page 2…** — tree nodes and freelist pages, handed out by the `Pager`. The
  freelist is a page CHAIN — each freelist page carries a `next` pointer
  (0 = end) alongside its entries, so a commit that frees more pages than one
  page holds simply chains another instead of losing ids. The chain is followed
  by those pointers, so its pages need not be adjacent, and they are RECYCLED
  from the freelist like tree pages are. The order matters and is the commit's
  to enforce: the chain's storage is reserved *before* this commit's own freed
  pages are parked, so it can only ever be handed pages an earlier txn freed —
  which copy-on-write guarantees the still-durable base meta does not reference.
  Reserving after would let a commit overwrite a page its own base tree needs,
  a hole that only a crash between the two fsyncs would reveal.

A **node** is a slotted page: an 8-byte header (kind, count, and — for a branch
— the leftmost child), a `count`-entry directory of 2-byte cell offsets kept in
ascending key order, then variable-length cells packed from the end of the page
toward the front. A **leaf** cell is `(key_len, val_len, key, val)`; a **branch**
cell is `(sep_len, right_child, sep)`, with `count` separators routing between
`count + 1` children. A **meta** page carries `txn_id` (monotonic commit
sequence), `root`, the freelist head + count, `high_water` (next never-used
page id), and a CRC32 over its fields.

## The Fable core (`core.zig`) — exactly what it is, and why it is irreducible

Two correctness kernels, three functions (now implemented). Each is the kind of bug a
human review rubber-stamps and only a model-checker catches — which is why the
harness, not a diff read, is the acceptance gate.

1. **`commit` — the atomic-commit invariant (crash-safety kernel).** Apply a
   transaction's buffered changes to the tree copy-on-write and make the result
   durable atomically w.r.t. a crash at any point. The irreducible rule: every
   newly-written data/freelist page must reach stable storage (fsync) *before*
   the meta page that references it is written, and that meta must be durable
   before the commit is acknowledged. Get the ordering wrong — meta before its
   pages, wrong meta slot, a missing fsync — and a crash yields a meta pointing
   at pages that do not exist: a torn tree, unrecoverable, invisible without the
   VOPR. COW makes atomicity *possible* (the old tree is never mutated, so it
   survives until the one pointer swap); the ordering and the double-buffer slot
   choice are `commit`'s to get right.

2. **`recover` — the crash-recovery meta-selection invariant.** On open, adopt
   the meta page with the highest `txn_id` that is both structurally valid
   (CRC/magic/version/geometry) and semantically in-bounds (root/freelist and
   everything they reference `< high_water ≤ file length`). The subtlety: after
   a crash the *newer* slot may be torn — then its CRC fails and the older slot
   is correct — but a torn write can also leave a structurally-valid stale page,
   so `txn_id` order, not slot position, decides. This is the exact dual of
   `commit`'s ordering; the two are correct only together.

3. **`reclaimGate` — the MVCC page-lifecycle / reader-snapshot-GC invariant.** A
   COW reader holds a whole immutable version by pinning a root and never
   locks; that is safe only if a page still reachable from any version a reader
   can see is never overwritten. A page freed by commit `t` was live in every
   version `< t`, so it may be recycled only once no open reader is pinned below
   `t`. The predicate reads as a one-liner, and honesty demands saying so — its
   irreducibility is not the comparison but the *interplay*: `commit` must park
   each freed page tagged with the right freeing-txn and feed the gate the right
   oldest-reader, and an off-by-one (reusing a page an equal-txn reader still
   needs) is a torn read no single-threaded test provokes. It lives in the gated
   core rather than as a plausible inline one-liner precisely because a
   plausible-looking wrong version is the trap.

**Honest tiering.** The bulk of the genuine Fable difficulty is in `commit` +
`recover` (the crash-atomicity kernel `kv` v0's VOPR exists to stress, made
harder by a tree + concurrent snapshots instead of a log). `reclaimGate` is the
smallest of the three and its substance really lives inside `commit`'s freelist
accounting; it is named separately because the MVCC-safety property is
genuinely distinct from crash-atomicity (LMDB implements them in separate
places), not to pad the tier. Everything else — page/node codecs, in-node
binary search, B-tree node **split** (textbook, unit-tested directly; deletes
are in-place with no merge/rebalance yet — see backlog), the
`Pager`, the freelist container, the read/descend/cursor path, and fresh-store
init — is mechanical scaffold, written and green today. If a future reviewer
finds `reclaimGate` collapses cleanly into `commit`, folding it in is fair; the
two-kernel framing is the honest maximum, not a floor.

## Verification (`harness.zig`) — the teeth

Mirrors `kv`'s VOPR + `df-elect`'s positive-control pattern:

- a reference `Model` (a sorted map with independent, deep-cloned MVCC
  snapshots) defining the correct answer;
- pure invariant checkers: **sorted scans**, **snapshot isolation** (a pinned
  read never sees a later/uncommitted write), **serializability** (committed
  txns applied in order == observed state), **crash-recovery to a committed
  prefix** (recovered state == some committed version, never a torn mix);
- a generic property engine (`runProperty`) driving a store and its reference
  `Model` in lockstep across randomized transaction/snapshot schedules;
- **`RefStore`** — a correct in-memory MVCC oracle the engine runs green across
  a 200-seed sweep today;
- **`BrokenRefStore`** — the positive control: one planted bug (snapshot reads
  ignore the pin) that the engine MUST catch. It reuses the *exact* checkers the
  real store will face, so a violation it trips is provably the same check —
  and the teeth test asserts it is caught on the vast majority of seeds (a
  checker with no teeth would catch zero). This proves the harness works
  independent of whether the B-tree core is filled in.

Formerly gated, now LIVE (`gate.fable_core_implemented` is `true`): the real
`Db` driven through the same checkers — a snapshot-isolation +
serializability commit schedule (including a multi-level-tree phase that
forces leaf splits, branch splits and recursive root growth under pinned
snapshots), and a crash-recovery sweep that crashes at EVERY storage side
effect of an open+commit, across all four `kv.SimStorage` crash modes, with
`.reorder_unsynced` swept under multiple seeds (one keep/drop pattern would
be a systematic blind spot for a missing data-before-meta fsync) and an
explicit destroy-the-in-flight-meta probe (this sim's torn write keeps the
first half of a write, which always covers the whole 48-byte meta record, so
meta corruption has to be injected to give the double-buffer invariant
teeth). Still future work: a full randomized VOPR (fuzzed op/crash schedules
chained across epochs) the way `kv/vopr.zig` is, plus a sabotage self-test
and a delta-debugging shrinker. The sim modeling caveat that used to sit
here — an un-synced in-place OVERWRITE below the durable watermark surviving most
crash modes — **is fixed**: `kv.SimStorage` now keeps an undo log when
`allow_overwrite` is set, so `.lose_unsynced` rolls the whole un-synced window
back (overwrites included) and `.reorder_unsynced` restores a dropped range's
pre-write bytes instead of zero-filling it. Overlapping writes within one sync
window are consequently allowed too. `.torn_tail` is unchanged on purpose: its
"first half of the write survives" rule is what the meta-corruption reasoning
above depends on. ⚠ Note the caveat's stated CONSEQUENCE did not hold even
before that fix: deleting commit's final `pager.sync()` was checked by fault
injection against the pre-fix tree and the gated crash sweep already failed with
`RecoveredStateNotCommitted`. The optimism was real; "a missing final meta fsync
is not provable by this harness" was not.

## Threat model / out of scope

Not a security boundary; the "adversary" is timing, crash points and I/O faults
(`kv.SimStorage`'s injectors). Guarantees, once the core is implemented and the
gate flips: ordered scans, atomic multi-key commit/rollback, snapshot isolation
for lockless readers, and crash-recovery to a committed prefix — under the same
`fsync`-honesty caveat `kv` documents (a lying drive/hypervisor is below this
library). Cross-*process* exclusion is not provided (one `Db` per store).

## Backlog / deferred (mechanical, orthogonal to the Fable core)

- **Overflow pages** for keys/values larger than a page fits (today: rejected
  with `error.EntryTooLarge`), mirroring `kv`'s large-value handling.
- **Node merge / rebalance-by-borrow** on underflow (today: deletes remove the
  key in place — underflowed and empty leaves persist until overwritten, which
  wastes space but never corrupts; merging and borrowing from a fuller sibling
  are mechanical additions).
- **Automatic freelist/space reclamation thresholds** and an in-memory page
  cache (compose with `ramcache`).

## Status line

`any · both · single_owner` + dep `kv`, model_after "LMDB / BoltDB (COW B-tree,
meta double-buffer); VOPR = TigerBeetle" — canonical source is `pub const meta`
in src/root.zig.

## Anchoring

**Anchor grade:** class C · oracle n/a

- **Class C** — internal algorithm or data structure — no outside exists, so correctness is defined by invariants or a brute-force reference. Not anchor debt.
- **Oracle n/a** — class C/D carries no anchor debt, so there is no oracle grade to give.

**What the tests actually contain.** embedded COW B-tree; LMDB/BoltDB design inspiration only, own format
