# blobstore — spec

Content-addressed blob store (git-object/restic style) + a name-addressed raw layer and opaque
named records. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
- **Layout:** `<base>/cas/<hh>/<hex>` (content-addressed, dedup, `hh` = hex[0..2] fan-out),
  `<base>/raw/<ns>/<key>` (name-addressed, caller-owned key), `<base>/named/<ns>/<key>` (opaque byte
  records), `<base>/tmp/` (scratch + in-flight ingest temps).
- **Crash safety:** every write lands in a hidden `.part` temp, is fsync'd, made visible by a single
  `rename(2)`. A crash mid-write leaves only an orphaned temp; a live blob is never torn or partial.
- **Dedup:** `put` hashes while streaming (single pass, bounded memory); `casCommit` skips the
  rename if the content already exists — one copy on disk regardless of put count.
- **Path safety:** `ns`/`key` must be single safe segments (`segmentSafe`: `[A-Za-z0-9._-]`, no
  leading dot, no `.`/`..`), checked on every public entry point — a request can never traverse out
  of `base`. CAS hex keys are generated internally and always safe.
- **Verification primitive:** `verify` re-reads stored bytes to EOF (via `hashdigest.sha256File`,
  which does not trust `stat().size`) and compares to the address, catching silent bit-rot/tampering.
- Reentrant — no shared state beyond a process-local atomic ingest-temp-name counter. Posix
  (atomic-rename visibility; filesystem via `std.Io`).
- Design choices: `put` owns hash-while-write (a single streaming pass, callers never hash
  externally); `verify`, `Digest`, and per-entry-point segment validation guard every path; the raw
  layer is `raw/<ns>/<key>` and opaque records are `named/<ns>/<key>` (any bytes, not just JSON) — no
  JSON/Outcome wrapping, this is pure storage.

## Threat model / out of scope
Not a security boundary against a co-resident attacker with filesystem access to `<base>` — no
encryption, no access control (that's the caller's filesystem permissions). `verify` detects bit-rot
and integrity mismatch but does not defend against a hostile writer supplying colliding content
(SHA-256 collision is out of scope by assumption). `delete`/`casDelete` remove a blob
unconditionally — no reference counting, so a blind delete of a deduped blob can dangle references
from other manifests (documented caveat, not a bug). `casCommit`'s check-then-rename has a benign
TOCTOU: two processes committing identical content just double-rename to the same bytes, so
"a committed blob's bytes always match its name" still holds.

## Verification
`zig build test-blobstore` (+ `-Doptimize=ReleaseFast`; `zig fmt --check modules/blobstore`). 8
tests covering CAS put/dedup/has/open/verify(intact + bit-rot)/delete, `Digest.fromHex` round-trip,
the raw createTemp→commit→openBlob→list crash-safe path, named put/read/list, and `segmentSafe`
rejecting `..`/leading-dot/traversal attempts on every public entry point.

## Backlog / deferred
From README "Backlog (deferred, not implemented)": **garbage collection** (`gc(keep)` reachability
sweep to reclaim unreferenced CAS blobs + stale `.part` temps, needs a root set typically the
`named` manifests); **reference counting** for safe individual delete of a deduped blob;
**configurable fan-out depth** (fixed 2-char/256-way; tens-of-millions-of-objects stores
want deeper/tunable fan-out); **cross-process ingest isolation / advisory locking** (ingest temp
names are unique only within a process).

## Status
`extract · posix · util · reentrant` + deps: `hashdigest` (SHA-256) — canonical source is
`pub const meta` in src/root.zig.
