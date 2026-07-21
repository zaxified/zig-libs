# blobstore — spec

Content-addressed blob store (git-object/restic style) + a name-addressed raw layer and opaque
named records. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
- **Layout:** `<base>/cas/<hh...>/<hex>` (content-addressed, dedup, `hh...` = `Options.fanout`
  levels of hex[0..2] fan-out, default 1 level = the historical layout) plus a `<hex>.rc` refcount
  sidecar next to each blob, `<base>/raw/<ns>/<key>` (name-addressed, caller-owned key),
  `<base>/named/<ns>/<key>` (opaque byte records), `<base>/tmp/` (scratch + in-flight ingest temps +
  the `tmp/.ingest.lock` cross-process lock file).
- **Crash safety:** every write lands in a hidden `.part` temp, is fsync'd, made visible by a single
  `rename(2)`. A crash mid-write leaves only an orphaned temp; a live blob is never torn or partial.
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
  of `base`. CAS hex keys are generated internally and always safe.
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
`zig build test-blobstore` (+ `-Doptimize=ReleaseFast`; `zig fmt --check modules/blobstore`). 13
tests covering CAS put/dedup/has/open/verify(intact + bit-rot)/delete, `Digest.fromHex` round-trip,
the raw createTemp→commit→openBlob→list crash-safe path, named put/read/list, `segmentSafe`
rejecting `..`/leading-dot/traversal attempts on every public entry point, `gc` sweeping a
zero-refcount orphan while keeping both a live-refcount blob and an explicitly-`keep`'d
zero-refcount blob (positive control on both), refcount surviving repeated dedup'd puts and only
becoming collectible at zero, configurable fan-out (1/2/3) round-tripping bytes and landing at the
expected nested path, `Store.init` still opening a plain (no-`Options`) store at the default
fan-out, and a single writer doing repeated put/delete/gc/reopen cycles never deadlocking on the
ingest flock.

## Backlog / deferred
None outstanding from the original three-item backlog (garbage collection, reference counting,
configurable fan-out depth, cross-process ingest locking/isolation) — all implemented, see
"Design & invariants" above. Possible future work, not currently planned: `gc` does not sweep
`raw/`/`named/` temp debris (only `cas/.ingest-*.part`, since those are the only ones this module's
own `put` creates unprompted — `raw`/`named` temps are tied to a caller-driven create→commit
sequence with no equivalent "ambient" ingest); Windows/non-POSIX `flock` support (module is POSIX
by design, `meta.platform = .posix`).

## Status
`extract · posix · util · reentrant` + deps: `hashdigest` (SHA-256) — canonical source is
`pub const meta` in src/root.zig.
