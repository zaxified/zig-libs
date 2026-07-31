# filestore — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see this module's README "Provenance" note — clean-room, so there is deliberately no root `/NOTICE` entry to point at (root `NOTICE` §0).

## Design & invariants
DB-less durable keyed document store: one flat file per record under `<base>/<kind>/<key>`, plus a
thin typed-JSON convenience layer (`put`/`get`/`listTyped`) over the same raw-bytes files
(`putBytes`/`getBytes`/`list`/`delete`) — no forced file extension, no separate directory tree for
the typed API. Crash safety: every write lands in a hidden `.<key>-<n>.part` temp (`n` a
process-local atomic counter, so two writers in the same process never collide) and is made visible
by a single `rename(2)` — a crash mid-write leaves only an orphaned temp, never listed (hidden files
skipped), never read (its name is not a valid key), never a torn live record. Path safety: `kind`
and `key` must each pass `segmentSafe` (`[A-Za-z0-9._-]`, no leading dot, no `.`/`..`) on every
public entry point, so a request can never traverse out of `base`. `listTyped` tolerance:
unparseable files are skipped rather than failing the whole listing, but the `skipped` count is
returned so callers can detect/alert on drift. Platform: posix (visibility relies on atomic
`rename(2)`; filesystem via `std.Io`). Role: util. Concurrency: reentrant — no shared state except
the process-local ingest counter. Original work of the zig-libs authors (MIT): atomic
temp-then-rename writes, `segmentSafe` path validation, and the `listTyped` skip-count are
first-class — no JSON is ever written in place, no path is built without a traversal guard, and no
unparseable record is silently dropped. No third-party source — no NOTICE entry.

### TTL, CAS and cross-process locking (sidecars, not headers)
Three optional layers sit beside the raw-bytes/typed-JSON layer, all keyed off the same `kind`/`key`:

- **TTL/expiry** (`putWithTTL`/`sweep`) — the deadline lives in a hidden sidecar
  `<base>/<kind>/.<key>.expiry` (decimal ns-since-epoch, wall-clock via `Store.clock`), *not* a
  header in the record file — `getBytes` on a live TTL'd record returns exactly the caller's bytes.
  `get`/`getBytes` treat an expired record as absent but never delete it (read-only check); `sweep`
  is the only thing that reclaims expired records. Visibility split, by design: `list` is a raw
  directory scan and still reports an expired-but-unswept key; `get`/`getBytes`/`listTyped` (which
  is built on `getBytes`) do not. `putBytes`/`casPutBytes` do not clear a prior `.expiry` sidecar —
  mixing plain `putBytes` and `putWithTTL` on the same key inherits the old deadline for the new
  bytes; `delete` does clear it (a deleted record leaves no trace).
- **ETag/version CAS** (`casPutBytes`/`getBytesVersioned`/`putBytesVersioned`) — `Version` is a
  `Wyhash` fingerprint of the record's own bytes (fixed seed, stable across restarts), computed on
  read — no sidecar, nothing to keep in sync. `casPutBytes(expected)` writes only if the current
  version matches: `null` means "must not exist" (create), a value means "must exist with exactly
  that version" (update) — anything else is `error.VersionMismatch`.
- **Cross-process advisory locking** (`lockKey`) — an exclusive `flock` on a hidden sidecar
  `<base>/<kind>/.<key>.lock`, held for the duration of a read-check-write. `casPutBytes` and
  `putWithTTL`/`sweep` acquire it internally around their own read-modify-write; a caller doing its
  own multi-step sequence across processes (e.g. `getBytes` then `putBytes`) can wrap it too via
  `lockKey`/`KeyLock.unlock`. Plain `putBytes`/`getBytes`/`delete` remain lock-free and unchanged —
  last-write-wins on the bare `rename(2)` (never a torn file), exactly as before; no locking cost
  for callers who never touch TTL/CAS. The lock file itself is never deleted (an empty per-key file
  persists once ever locked) — harmless, hidden from `list`, cheaper than a racy cleanup.

## Threat model / out of scope
Path traversal via `kind`/`key` is the primary threat modeled: `segmentSafe` rejects any segment
containing `/`, a leading dot, or `.`/`..`, checked on every public entry point, so a hostile/buggy
key cannot escape `base`. Cross-process ingest locking is now modeled for the CAS/TTL write path
specifically (`lockKey`, an advisory `flock` — see above); plain `putBytes`/`getBytes` are still
*not* locked by design (last-write-wins on `rename(2)`, never a torn file, just a benign overwrite
race — unchanged from v1). Not modeled/out of scope: encryption/at-rest confidentiality (files are
plain bytes on disk, permissions are the caller's/filesystem's concern); mandatory (non-advisory)
locking — `flock` is advisory, a process that ignores the API can still read/write past it, same
caveat the option's own doc comment states; TTL/CAS interaction with each other (`casPutBytes` does
not consult or clear the `.expiry` sidecar — they are independent, orthogonal sidecars, see above).

## Verification
Tests cover: the original set (put/get/delete/list round-trip, atomic temp+rename visibility,
`segmentSafe` traversal rejection, typed-JSON round-trip, `listTyped` skipped-count) plus additions
from this backlog batch — TTL present-then-expired-then-still-`list`-visible (deterministic via an
injectable `Store.clock`/`ManualClock`, no real-time sleeps), `sweep` reaping only expired keys and
leaving live-TTL/no-TTL keys + returning the exact count, CAS create/update/mismatch semantics
end-to-end, a **positive control** proving a lost update silently happens with plain `putBytes` and
is instead caught (`error.VersionMismatch`) with `casPutBytes` on the identical scenario, `lockKey`
contention proven with an independent second file descriptor on the same lock path (flock is scoped
to the open-file-description, so this genuinely exercises the same kernel behavior a second process
would hit), and `casPutBytes` proven to actually *block* on a lock held by another thread (timed
against a background holder — a dropped `lockKey` call would make this test go from
waits-~150ms to returns-in-microseconds). Run: `zig build test-filestore`.

## Backlog / deferred
None open from the original v1 backlog — TTL/expiry, ETag/version CAS, and cross-process ingest
locking are all implemented (see "TTL, CAS and cross-process locking" above). Possible future work,
not currently planned: a `sweep`-all-kinds convenience (today `sweep` takes one `kind` at a time,
matching `list`'s per-kind scoping); mandatory (non-advisory) locking; encryption at rest.

## Status
`extract · posix · util · reentrant` · deps: none — canonical source is `pub const meta` in
src/root.zig.
