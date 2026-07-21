# filestore

DB-less durable keyed document store: one flat file per record under
`<base>/<kind>/<key>`, written atomically (temp-then-rename), with a thin
typed-JSON convenience layer over the same raw-bytes files. TTL/expiry,
ETag/version CAS and cross-process advisory locking sit alongside as
opt-in sidecar layers — see "TTL, CAS and locking" below.

- Spec-completed: atomic writes, path validation, listTyped skip-count,
  TTL/expiry (`putWithTTL`/`sweep`), ETag/version CAS (`casPutBytes`),
  cross-process advisory locking (`lockKey`).
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

// TTL / expiry — wall-clock via store.clock (injectable in tests)
try store.putWithTTL("sessions", "s1", bytes, 3600 * std.time.ns_per_s); // 1h
_ = try store.getBytes(arena, "sessions", "s1");   // null once expired (read-only check)
const swept = try store.sweep(arena, "sessions");  // actually deletes expired records

// ETag / version CAS — Version is a content fingerprint, no sidecar needed
const v1 = try store.casPutBytes(arena, "accounts", "a1", "v1", null); // null = must not exist
const v2 = try store.casPutBytes(arena, "accounts", "a1", "v2", v1);   // must match current version
// store.casPutBytes(arena, "accounts", "a1", "v3", v1) now => error.VersionMismatch (stale)
const cur = try store.getBytesVersioned(arena, "accounts", "a1"); // ?struct{ bytes, version }

// cross-process advisory locking — used internally by casPutBytes/putWithTTL/
// sweep; expose it for your own multi-step read-modify-write sequences too
var kl = try store.lockKey("accounts", "a1");
defer kl.unlock();
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

## TTL, CAS and locking

- **TTL / expiry.** `putWithTTL(kind, key, bytes, ttl_ns)` records a deadline
  in a hidden sidecar `.<key>.expiry` next to the record (decimal
  ns-since-epoch, wall-clock via `Store.clock` — injectable for tests, real
  `clock_gettime(REALTIME)` by default). `getBytes`/`get`/`listTyped` treat an
  expired record as absent — a read-only check, they never delete. `sweep(kind)`
  is what actually reaps expired records, returning the count removed. `list`
  is a raw directory scan and does *not* filter by TTL, so an
  expired-but-unswept key still shows up there — that split is intentional
  (`list` is cheap-by-design, one syscall per entry; TTL-filtering it would
  mean a stat/read per key). Plain `putBytes`/`casPutBytes` do not clear a
  prior `.expiry` sidecar (mixing them with `putWithTTL` on the same key
  inherits the old deadline) — `delete` does clear it.
- **ETag / version CAS.** `Version` is a `Wyhash` fingerprint of the record's
  own bytes (fixed seed, so it is stable across process restarts) — computed
  on read, not stored anywhere, so there is no sidecar to keep in sync.
  `getBytesVersioned`/`putBytesVersioned` report it; `casPutBytes(kind, key,
  bytes, expected)` writes only if the current version matches `expected`
  (`null` = must not exist, a value = must exist with exactly that version) —
  otherwise `error.VersionMismatch`, and the caller should re-`get` and retry
  rather than blindly overwrite.
- **Cross-process advisory locking.** `lockKey(kind, key)` takes an exclusive
  `flock` on a hidden sidecar `.<key>.lock`, released via `KeyLock.unlock()`.
  `casPutBytes` and `putWithTTL`/`sweep` acquire it internally around their
  own read-check-write, which is what makes CAS actually trustworthy across
  processes — the atomic `rename(2)` in `putBytes` alone only prevents a torn
  *read* of one write, it does nothing to stop two processes' multi-step
  CAS/TTL sequences from interleaving. A caller doing its own multi-step
  read-modify-write across processes can wrap it with `lockKey` too. Plain
  `putBytes`/`getBytes`/`delete` stay lock-free and unchanged — no locking
  cost unless you touch TTL/CAS, and last-write-wins on the bare `rename(2)`
  (never a torn file) remains the documented behavior for them.

## Backlog (deferred, not implemented)

None from the original v1 backlog — TTL/expiry, ETag/version CAS and
cross-process locking (above) close it out. Not currently planned: a
`sweep`-all-kinds convenience (today one `kind` at a time, like `list`);
mandatory (non-advisory) locking; encryption at rest.
