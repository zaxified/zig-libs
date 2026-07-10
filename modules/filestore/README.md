# filestore

DB-less durable keyed document store: one flat file per record under
`<base>/<kind>/<key>`, written atomically (temp-then-rename), with a thin
typed-JSON convenience layer over the same raw-bytes files.

- Spec-completed: atomic writes, path validation,
  listTyped skip-count.
- **Model after:** flat-file document store.
- **Platform:** posix (visibility relies on atomic `rename(2)`; filesystem via
  `std.Io`). **Role:** util. **Concurrency:** reentrant — no shared state
  except a process-local atomic counter for ingest temp names.
- **Deps:** none — std only.

Provenance: original work of the zig-libs authors (MIT). Atomic
temp-then-rename writes and `segmentSafe` path validation (no JSON is ever
written in place, and no path is built without a traversal guard) mirror the
sibling `blobstore` module's approach. The `listTyped` skipped-count report
surfaces unparseable files instead of swallowing them via a silent
`catch continue`. No third-party source involved — no NOTICE entry.

## Layout

```
<base>/<kind>/<key>   one file per record (opaque bytes or JSON — caller's choice)
```

There is no forced file extension and no separate directory tree for the
typed-JSON convenience API — `put`/`get`/`listTyped` are just
`putBytes`/`getBytes`/`list` with JSON encode/decode on top of the exact same
files.

## API

```zig
const filestore = @import("filestore");

var store = try filestore.Store.init(io, "/var/lib/mystore");

// raw bytes layer (atomic: temp + rename)
try store.putBytes("devices", "dev-1", bytes);
const got = try store.getBytes(arena, "devices", "dev-1");   // ?[]u8
_ = try store.delete("devices", "dev-1");                    // bool
const keys = try store.list(arena, "devices");               // [][]const u8

// typed JSON convenience (same files, JSON-encoded)
try store.put(gpa, MyRecord, "devices", "dev-1", value);
const rec = try store.get(MyRecord, arena, "devices", "dev-1");         // ?MyRecord
const all = try store.listTyped(MyRecord, arena, "devices");            // struct{ items: []MyRecord, skipped: usize }
```

## Design notes

- **Crash safety.** Every write lands in a hidden `.<key>-<n>.part` temp
  (`n` = a process-local atomic counter, so two writers in the same process
  never collide on the same temp path) and is made visible by a single
  `rename(2)`. A crash mid-write leaves only an orphaned temp — never listed
  (hidden files are skipped), never read (its name is not a valid key), never
  a torn live record.
- **Path safety.** `kind` and `key` must each be a safe single segment
  (`segmentSafe`: `[A-Za-z0-9._-]`, no leading dot, no `.`/`..`), checked on
  *every* public entry point, so a request can never traverse out of `base`.
- **Typed JSON is a thin layer, not a second store.** `put`/`get`/`listTyped`
  serialize/parse JSON and call straight through to the raw-bytes layer — same
  atomicity, same path safety, same files. Mixing raw and typed access to the
  same `kind` is the caller's own responsibility.
- **`listTyped` tolerance.** A kind directory may accumulate records from
  different code versions or a half-written record from a concurrent `put`
  racing a `list` snapshot. Rather than fail the whole listing, unparseable
  files are skipped — but the count is returned (`skipped`) so callers can
  detect and alert on drift, rather than silently dropping them.
- **Crash safety by construction.** Records never land in place: every write
  goes to a temp then a single `rename(2)` (a crash mid-write leaves only an
  orphaned temp, never a torn file), and every path is built through
  `segmentSafe` (a hostile/buggy `id` containing `../` can never escape
  `base`). Per-resource one-liner wrappers and domain-specific queries are
  consumer glue, not part of this generic module.

## Backlog (deferred, not implemented)

- **TTL / expiry** — `putWithTTL(kind, key, bytes, ttl)` to tag a record with
  an expiry, plus `sweep(now)` to reap expired records. Needs a place to store
  the expiry (sidecar file or a small header) and a decision on whether
  expired-but-unswept records should still be visible to `get`/`list`.
- **Cross-process ingest locking** — like `blobstore`, the ingest counter only
  guarantees temp-name uniqueness *within* a process; cross-process writers to
  the same `kind`/`key` can race on the final rename (last write wins, which
  is at least never a torn file, just a benign overwrite race).
- **Reference/version metadata** — no ETag/version field on records, so
  optimistic-concurrency writes (compare-and-swap on a stored version) are not
  supported; every `put` is an unconditional overwrite.
