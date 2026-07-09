# filestore

DB-less durable keyed document store: one flat file per record under
`<base>/<kind>/<key>`, written atomically (temp-then-rename), with a thin
typed-JSON convenience layer over the same raw-bytes files.

- **Status:** `extract` — carved out of the authors' axp project
  (`axp-central/src/store.zig`), then spec-completed (atomic writes, path
  validation, listTyped skip-count — the seed had none of these).
- **Model after:** flat-file document store (the axp resource store this was
  seeded from).
- **Platform:** posix (visibility relies on atomic `rename(2)`; filesystem via
  `std.Io`). **Role:** util. **Concurrency:** reentrant — no shared state
  except a process-local atomic counter for ingest temp names.
- **Deps:** none — std only.

Provenance: extracted from the authors' own axp project
(`axp-central/src/store.zig`; axp is the authors' code, MIT). The
`kind/id.json` layout and the read/list/delete shape are the seed's; atomic
temp-then-rename writes and `segmentSafe` path validation (the seed had
*neither* — it wrote JSON directly with `writeFile` and built paths with no
traversal guard) are written for this module, mirroring the sibling
`blobstore` module's approach. The `listTyped` skipped-count report is also
new — the seed's `listRecords` swallowed unparseable files via a silent
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
  same `kind` is the caller's own responsibility (as in the seed).
- **`listTyped` tolerance.** A kind directory may accumulate records from
  different code versions or a half-written record from a concurrent `put`
  racing a `list` snapshot. Rather than fail the whole listing, unparseable
  files are skipped — but the count is returned (`skipped`) so callers can
  detect and alert on drift, instead of the seed's silent `catch continue`.
- **Deltas vs the seed.** `axp-central/src/store.zig` wrote records directly
  with `Dir.writeFile` (no temp, no rename — a crash mid-write could leave a
  torn `.json` file) and built every path with plain `bufPrint` (no segment
  validation — a hostile/buggy `id` containing `../` could escape `base`).
  Both are fixed here. The per-resource one-liner wrappers (`putDevice`,
  `putIdentity`, `putTask`, ...) and the `nextPendingTask` query are consumer
  glue specific to axp's resource types and are not part of this generic
  module.

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
