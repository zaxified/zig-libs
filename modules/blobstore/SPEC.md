# blobstore — spec

Content-addressed blob store (git-object/restic style) + a name-addressed raw layer and opaque
named records. Usage: see ./README.md. Attribution/provenance: see this module's README "Provenance" note — clean-room, so there is deliberately no root `/NOTICE` entry to point at (root `NOTICE` §0).

## Design & invariants
- **Layout:** `<base>/cas/<hh...>/<hex>` (content-addressed, dedup, `hh...` = `Options.fanout`
  levels of hex[0..2] fan-out, default 1 level = the historical layout) plus a `<hex>.rc` refcount
  sidecar next to each blob (unless `Options.refcount = false`, see below), `<base>/raw/<ns>/<key>`
  (name-addressed, caller-owned key), `<base>/named/<ns>/<key>` (opaque byte records), `<base>/tmp/`
  (scratch + in-flight ingest temps + the `tmp/.ingest.lock` cross-process lock file). Each of these
  four subdirectories is created lazily, on that layer's first write, not at `Store.init` time — a
  store that never uses a layer (e.g. never calls `putNamed`) never creates its directory.
- **Crash safety:** every write lands in a hidden temp and is made visible by a single `rename(2)`,
  including the `.rc` refcount sidecars since 2026-09-01 — a crash mid-write leaves only an orphaned
  temp; a live blob or sidecar is never torn or partial. **`fsync` is not part of that invariant and
  this line used to claim it was:** the module contains one `sync` call, in `put`. `putNamed` and the
  raw `commit` path rename an unsynced temp, so they are atomic but not durable across power loss.
- **Dedup:** `put` hashes while streaming (single pass, bounded memory); `casCommit` skips the
  rename if the content already exists — one copy on disk regardless of put count — but still bumps
  that blob's refcount, since a dedup hit is a real reference.
- **Reference counting + GC:** `put`/`casCommit` increment a blob's `.rc` sidecar (creating it at 1
  if new); `delete`/`casDelete` only decrement it (floored at 0) and never unlink the blob
  themselves. `gc(keep)` is the sole physical-reclaim path: it sweeps every CAS blob whose refcount
  is zero and is not named in the caller-supplied `keep` allow-list, plus stale abandoned ingest
  temps. Chosen over pure mark-sweep because `put`/`delete` already touch every blob's refcount at
  the exact moment a reference is established/dropped, so `gc` needs no knowledge of `named`
  manifests or any other caller-defined reference format; `keep` remains available as an
  additive escape hatch for callers who want to double-check against their own root set. A blob
  with no `.rc` sidecar at all (written before this feature, never `delete`d since) is treated as
  still-referenced and left alone.
- **`Options.refcount = false` — opting out of sidecars entirely:** for a store that never deletes
  and never calls `gc` (a frozen append-only CAS layout, e.g. a consumer with its own pre-refcount
  test harness asserting an exact file count), `casCommit` becomes rename-only: no `.rc` sidecar is
  ever read or written, so the CAS directory holds exactly one file per blob. This is
  contract-compatible with the rule directly above, not a special case: a sidecar-less blob is
  already, unconditionally, "still-referenced and left alone" from `gc`'s point of view, and
  `refcount = false` just keeps every blob in that state permanently instead of only until the first
  `put`/`delete` touches it. Concretely: `gc`'s CAS sweep is skipped outright (it would find nothing
  to collect — every blob is sidecar-less — so skipping it is an optimization, not a behavior
  change) and reports `GcStats{ .blobs_removed = 0, .bytes_reclaimed = 0 }` truthfully rather than
  silently pretending nothing was asked; `reapStaleIngestTemps` still runs, since ingest-temp reap is
  unrelated to refcounting. `casDelete`/`delete` return `error.RefcountDisabled` instead of
  fabricating a sidecar on demand — a caller that opted into "never delete" should never reach this
  path, and one that does is told so loudly rather than getting a half-bookkept blob that
  contradicts the option it set.
  **Toggling `refcount` on a store with history is a documented footgun, not a supported migration.**
  A store that ran with `refcount = true` may already carry `.rc` sidecars, some possibly at zero
  and already collectible by `gc`. Reopening the same `base` with `refcount = false` does not remove
  or ignore those sidecars selectively — it makes `gc`'s CAS sweep skip the entire store (the
  `if (!self.refcount) return stats;` short-circuit in `gc`, before any directory walk), so every
  pre-existing sidecar, including ones at zero, is never swept again. The direction is fail-safe:
  nothing is deleted that `refcount = true` semantics would have kept, so this cannot corrupt data or
  drop something live — but it silently converts what would have been reclaimable disk space into
  permanent retention, for as long as the store stays open with `refcount = false`. This was
  undocumented before 2026-08-18; it is now stated on `Options.refcount`'s doc comment (source of
  truth) and in README, next to the option itself, per §5's doc-ownership rule. `false` is meant for
  a store created that way from the start — "never deletes, never calls `gc`" is the option's stated
  precondition, not a runtime switch to flip on an established store.
  **Why this got a check (`Store.hasOrphanedRcSidecars`) instead of only a warning, and why that
  check is opt-in rather than automatic at `init`/`gc` time.** A pure prose warning is easy to miss
  at the moment it matters (reopening an existing `base` with different `Options`, months after the
  store was created), so an opt-in existence probe gives a caller a concrete way to check before
  trusting a toggle is safe. It is deliberately **not** run automatically: `Store.init`/`initOptions`
  do zero CAS-tree I/O today (every layer directory is created lazily, per the module doc comment),
  and folding a directory walk into construction would tax every caller's "opening a store is cheap"
  assumption, not only the ones toggling `refcount`. Running it inside `gc` instead would tax exactly
  the callers `refcount = false` is meant to exempt — since "never calls `gc`" is the flag's own
  precondition, a store using it as intended mostly never reaches `gc` at all, and `gc`'s existing
  `refcount = false` path is a *true*, zero-cost no-op specifically so a caller that does call it
  anyway is not surprised by hidden work. Given the failure mode is already fail-safe in direction
  (permanent retention, never a wrong delete), there is no correctness argument for forcing the cost
  onto a path every consumer pays for — only a discoverability one, which the doc-comment pointer and
  the opt-in function both address without the cost.
- **Configurable fan-out:** `Options.fanout` (`1..=32`, default 1) sets how many 2-hex-char
  directory levels the CAS uses before the blob file. Only affects newly-created stores/paths at
  the depth chosen at `Store.initOptions` time — an existing store's on-disk fan-out is not migrated
  by changing the option.
- **Cross-process ingest locking:** an advisory `flock` (`std.Io.File.Lock`) on `tmp/.ingest.lock`
  serializes the commit-and-refcount-mutate section of `casCommit`/`casDelete`/`gc` across
  processes — the has-check+rename+refcount-bump in `casCommit`, the refcount decrement in
  `casDelete`, and the whole sweep in `gc` each hold it for their duration, released on every path
  (including error returns). It does **not** cover `put`'s streaming/hashing phase before commit —
  only the section touching shared on-disk state needs mutual exclusion, so concurrent ingests still
  stream into their own temps in parallel. Temp *names* additionally fold in the PID (not just a
  process-local counter), closing the historical same-name collision risk across processes even for
  the pre-commit phase the lock doesn't cover.
- **Path safety:** `ns`/`key` must be single safe segments (`segmentSafe`: `[A-Za-z0-9._-]`, no
  leading dot, no `.`/`..`), checked on every public entry point — a request can never traverse out
  of `base`. **The sentence that used to follow — "CAS hex keys are generated internally and always
  safe" — was false, and the escape clause it granted was the bug.** `casPath`, `casHas`, `casOpen`,
  `casCommit` and `casDelete` are all public and take `hex` verbatim from the caller; with the
  fan-out slicing added in `3ac5fee9`, a leading `..` became a real directory climb, and
  `casDelete("../victim")` WROTE a `.rc` sidecar outside the store. Since 2026-09-01 every CAS path
  is built through `requireCasHex` (exactly 64 lowercase-hex characters), which also supplies the
  length precondition the fan-out loop never had — a short `hex` used to panic in Debug and, in
  ReleaseFast, read adjacent stack bytes into a directory name. `scratchCreate` was the other
  unguarded entry point and now runs `segmentSafe` like its siblings.
- **Verification primitive:** `verify` re-reads stored bytes to EOF (via `hashdigest.sha256File`,
  which does not trust `stat().size`) and compares to the address, catching silent bit-rot/tampering.
- Reentrant — shared state (refcounts, gc) is coordinated via the advisory ingest flock, not
  in-process synchronization. Posix (atomic-rename visibility, flock; filesystem via `std.Io`).
- Design choices: `put` owns hash-while-write (a single streaming pass, callers never hash
  externally); `verify`, `Digest`, and per-entry-point segment validation guard every path; the raw
  layer is `raw/<ns>/<key>` and opaque records are `named/<ns>/<key>` (any bytes, not just JSON) — no
  JSON/Outcome wrapping, this is pure storage.

## Threat model / out of scope
Not a security boundary against a co-resident attacker with filesystem access to `<base>` — no
encryption, no access control (that's the caller's filesystem permissions). `verify` detects bit-rot
and integrity mismatch but does not defend against a hostile writer supplying colliding content
(SHA-256 collision is out of scope by assumption). `casCommit`'s check-then-rename has a benign
TOCTOU outside the ingest lock's reach only in the sense that two processes committing identical
content just double-rename to the same bytes; the refcount bump itself is inside the lock, so it
does not double-count. `.rc` sidecar writes are not crash-atomic (no temp+rename, unlike blob/named
writes) — a torn write is read back as "no sidecar" (untracked/still-referenced), which is always
the safe direction for reclaim bookkeeping. `gc`'s stale-temp reap is age-gated
(`GcOptions.stale_after_ns`, default 10 min) specifically so it cannot race a slow-but-live `put`
still streaming into its own temp. Cross-process locking covers only blobstore's own ingest/refcount
path — it is not a general-purpose file lock for caller-defined concurrent access patterns.

## Verification
`zig build test-blobstore` (+ `-Doptimize=ReleaseFast`; `zig fmt --check modules/blobstore`). 20
tests covering CAS put/dedup/has/open/verify(intact + bit-rot)/delete, `Digest.fromHex` round-trip,
the raw createTemp→commit→openBlob→list crash-safe path, named put/read/list, `segmentSafe`
rejecting `..`/leading-dot/traversal attempts on every public entry point, `gc` sweeping a
zero-refcount orphan while keeping both a live-refcount blob and an explicitly-`keep`'d
zero-refcount blob (positive control on both), refcount surviving repeated dedup'd puts and only
becoming collectible at zero, configurable fan-out (1/2/3) round-tripping bytes and landing at the
expected nested path, `Store.init` still opening a plain (no-`Options`) store at the default
fan-out, a single writer doing repeated put/delete/gc/reopen cycles never deadlocking on the
ingest flock, `Options.refcount = false` producing exactly one CAS file with no `.rc` sidecar and a
still-readable blob, the no-`Options` default still writing a sidecar (regression guard for the
consumers that pin the historical layout), `gc`'s CAS sweep being a truthful (zero-stats) no-op
under `refcount = false` while `casDelete` refuses with `error.RefcountDisabled`, lazy layer
creation leaving `cas/`/`named/`/`tmp/` absent from a store that only ever wrote to `raw/`, and
(2026-08-18) `hasOrphanedRcSidecars` returning `false` on a fresh store and under normal
`refcount = true` use, plus the refcount-toggle footgun end to end: a store run with
`refcount = true`, a blob deleted down to a zero sidecar `gc` has not yet swept, the same `base`
reopened with `refcount = false`, `hasOrphanedRcSidecars` finding the stale sidecar, and `gc`
confirming it is truthfully untouched (`blobs_removed == 0`).

## Backlog / deferred
None outstanding from the original four-item backlog (garbage collection, reference counting,
configurable fan-out depth, cross-process ingest locking/isolation) — all implemented, see
"Design & invariants" above. Possible future work, not currently planned: `gc` does not sweep
`raw/`/`named/` temp debris (only `cas/.ingest-*.part`, since those are the only ones this module's
own `put` creates unprompted — `raw`/`named` temps are tied to a caller-driven create→commit
sequence with no equivalent "ambient" ingest); Windows/non-POSIX `flock` support (module is POSIX
by design, `meta.platform = .posix`).

## Status
`extract · posix · util · reentrant` + deps: `hashdigest` (SHA-256) — canonical source is
`pub const meta` in src/root.zig.

## Anchoring

**Anchor grade:** class C · oracle n/a

- **Class C** — internal algorithm or data structure — no outside exists, so correctness is defined by invariants or a brute-force reference. Not anchor debt.
- **Oracle n/a** — class C/D carries no anchor debt, so there is no oracle grade to give.

**What the tests actually contain.** local content-addressed store; git/restic modeled behavior only, no external reader
