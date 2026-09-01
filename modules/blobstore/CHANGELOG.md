# blobstore — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-01** — **Security audit: two live references could become one, and
  five public functions wrote outside the store.**

  **CRITICAL, data loss.** `casCommit` and `casDelete` disagreed about what a
  missing `.rc` sidecar means. `casDelete` and `gc` both read it as the one
  implicit reference the docs promise; `casCommit`'s dedup branch read it as
  zero. So when a second referrer `put` content whose blob had no sidecar —
  any blob written before refcounting existed, or any store reopened after an
  `Options.refcount = false` phase — the store recorded `1` for two live
  references, the first referrer's `delete` took it to `0`, and `gc` unlinked
  the blob under the second. No crash was required. The dedup branch now reads
  the same implicit `1`, and both increments saturate: a tampered sidecar at
  `maxInt(u64)` used to wrap to zero in ReleaseFast, which is exactly the
  collectible state.

  **HIGH, path traversal.** `casPath`, `casHas`, `casOpen`, `casCommit` and
  `casDelete` are public and took `hex` verbatim, on the strength of a doc
  line reading "CAS hex keys are generated internally and always safe". They
  are not: `casDelete("../victim")` wrote a `.rc` sidecar outside the store,
  and the fan-out slicing added with configurable fan-out is what turned a
  leading `..` into a real directory climb. Every CAS path is now built
  through `requireCasHex`, which also supplies the length precondition the
  fan-out loop never had — a short `hex` panicked in Debug and, in ReleaseFast
  where the bounds check is gone, read adjacent stack bytes into a directory
  name. `scratchCreate` was the other unguarded entry point and now runs
  `segmentSafe`.

  **HIGH, the ingest lock could be dropped.** An advisory lock is held on an
  inode; unlink `tmp/.ingest.lock` while a holder has it and the next locker
  creates a new inode and walks into the critical section beside the first —
  measured at 0 ms against a 1500 ms control. Nothing said that file had to
  survive, and `tmp/` is documented as scratch. `lockIngest` now re-checks
  that the descriptor it locked is still what the path names, retrying a
  bounded number of times before `error.IngestLockUnstable`, and
  `scratchCreate` refuses the lock's own name.

  **The refcount sidecar is now crash-atomic.** It was a bare `writeFile`, on
  the argument that a torn write "falls back to `default_if_missing`, which is
  the safe direction — never worse than untracked". That holds only for `gc`'s
  reader. The increment path reads the same file with a default of one, so a
  torn sidecar on a blob with five referrers came back as one and three
  references vanished. Untracked is not a neutral state; it means something
  different to every reader. Temp-plus-rename removes the question.

- **2026-09-01** — **Tests for the guards that were holding nothing.** Six
  mutations survived the whole suite in both optimisation modes before this:
  the flagship "a blob with no sidecar is always referenced" fail-safe in
  `gcWalk` could be flipped fully fail-open, the refcount underflow floor could
  be made to wrap, `casDelete`'s implicit-reference default could be changed,
  and the `Options.fanout` bounds check could be deleted. All are pinned now,
  each verified by a mutation that produces a real test failure.

- **2026-09-01** — **Changelog gap closed, and one entry that was owed.**
  `3ac5fee9` added refcounted `gc`, `Options.fanout`/`initOptions` and the
  cross-process ingest lock without a single entry here. The one that matters
  to an upgrading consumer: **`casDelete`/`delete` stopped unlinking the
  blob.** They used to free the file; they now only decrement a sidecar, and
  disk is reclaimed exclusively by `gc`. A consumer who upgraded and never
  called `gc` got silent unbounded disk growth with nothing to read about it.

  Also corrected: README, SPEC and the module doc claimed every write is
  `fsync`'d — the module has one `sync` call, in `put`, so `putNamed` and the
  raw `commit` path are atomic but not durable. `meta.doc`, the source of the
  generated catalog row, still described a pre-GC, pre-lock module. `SPEC`'s
  "three-item backlog" listed four. `README` ended with a stray code fence.


- **2026-08-18** — **BREAKING:** `scratchCreate` now returns `Scratch` (fields `file`,
  `path`) instead of `Temp` (fields `file`, `tmp`). A scratch file is never staged for
  `commit`/`casCommit` — it is read back or streamed out in place, not renamed elsewhere
  — and naming its return type `Temp` with a `.tmp` field told the reader the opposite.
  `Temp` itself is unchanged and keeps meaning what it always meant for `createTemp` /
  `casCreateTemp`, both of which genuinely do rename their result into place. Migration:
  replace `.tmp` with `.path` on `scratchCreate`'s return value (`store.discardTemp(s.tmp)`
  → `store.discardTemp(s.path)`); no other call site changes.
- **2026-08-18** — **BEHAVIOURAL, not breaking:** `init`/`initOptions` no longer eagerly
  create the `cas/`/`raw/`/`named/`/`tmp/` subdirectories; each is now created lazily on
  that layer's first write, so a store that never uses a layer never creates its
  directory. Every existing read path already tolerated a missing layer directory, so
  this is not a breaking change, but a consumer whose own test harness asserted the
  full four-directory tree right after `Store.init` will now see fewer directories until
  it actually writes to each layer.
- **2026-08-18** — Added `Options.refcount: bool = true`. Set `false` for a store that
  never deletes and never calls `gc`: `casCommit` becomes rename-only (no `<hex>.rc`
  sidecar ever written), matching this module's pre-refcount on-disk layout. `gc`'s CAS
  sweep is a truthful no-op on such a store (sidecar-less blobs were already always
  treated as still-referenced — see SPEC.md); `casDelete`/`delete` return the new
  `error.RefcountDisabled` rather than fabricating a sidecar on demand. Default
  (`refcount = true`) is unchanged from every prior release — not a breaking change.
  Security audit, same day: documented (on `Options.refcount`'s doc comment, README and
  SPEC.md) that flipping this to `false` on a store that has ever run with
  `refcount = true` is a footgun, not a migration — existing `.rc` sidecars, some
  possibly already at zero, are then permanently invisible to `gc`'s CAS sweep (fail-safe
  direction: nothing wrongly deleted, but nothing reclaimed either). Added the new,
  opt-in `Store.hasOrphanedRcSidecars()` for a caller to check before trusting such a
  toggle; deliberately not automatic at `init`/`gc` time — see SPEC.md for why.

- **2026-08-14** — Provenance record completed: the git object store (GPL-2.0)
  and restic (BSD-2-Clause) were already named as design references, without
  their licences, which `/NOTICE` §0 requires the record to carry. Nothing is
  owed either way — a design reference imposes no condition. Documentation only.

- **2026-07-18** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Modeled on git-objects /
  restic (Go) (design reference, not a test anchor).
- **2026-07-09** — New module: Content-addressed blob store (git-object/restic style) +
  name-addressed + small named-record layers, crash-safe.
