# filestore — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

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

## Threat model / out of scope
Path traversal via `kind`/`key` is the primary threat modeled: `segmentSafe` rejects any segment
containing `/`, a leading dot, or `.`/`..`, checked on every public entry point, so a hostile/buggy
key cannot escape `base`. Not modeled/out of scope: cross-process ingest locking (the atomic
counter only guarantees temp-name uniqueness *within* a process; cross-process writers to the same
`kind`/`key` can race on the final rename — last-write-wins, never a torn file, just a benign
overwrite); optimistic concurrency (no ETag/version field, every `put` is an unconditional
overwrite); TTL/expiry (no `putWithTTL`/`sweep` — records live until explicitly deleted); and
encryption/at-rest confidentiality (files are plain bytes on disk, permissions are the caller's/
filesystem's concern).

## Verification
6 tests: put/get/delete/list round-trip on the raw-bytes layer, atomic temp+rename visibility (no
partial file ever observed), `segmentSafe` rejecting traversal/hidden/empty segments, typed-JSON
put/get/listTyped round-trip, and `listTyped`'s skipped-count reporting on an injected unparseable
file. Run: `zig build test-filestore`.

## Backlog / deferred
Deferred from v1, per the module README's own Backlog: TTL/expiry (`putWithTTL`/`sweep`,
needs a place to store the expiry and a decision on expired-but-unswept visibility); cross-process
ingest locking (`blobstore`-style, same last-write-wins caveat); reference/version metadata (ETag/
version field for compare-and-swap writes).

## Status
`extract · posix · util · reentrant` · deps: none — canonical source is `pub const meta` in
src/root.zig.
