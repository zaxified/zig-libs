# blobstore

Content-addressed blob store (git-object / restic style): stream a blob in,
get back its SHA-256 address; identical content is stored **once**. Plus a
name-addressed raw layer and small opaque **named** records — all made
crash-safe by temp-then-atomic-rename.

- Spec-completed: single-pass `put`, `verify`,
  segment validation, `Digest`, `named` generalization.
- **Model after:** git object store / restic (256-way hex fan-out, dedup).
- **Platform:** posix (visibility relies on atomic `rename(2)`; filesystem via
  `std.Io`). **Role:** util. **Concurrency:** reentrant — no shared state except
  a process-local atomic counter for ingest temp names.
- **Deps:** `hashdigest` (SHA-256; nothing cryptographic is reimplemented here).

Provenance: original work of the zig-libs authors (MIT); modeled after the git
object store / restic content-addressing design (256-way hex fan-out, dedup —
behavior only, no source consulted or copied). SHA-256 comes from the sibling
`hashdigest` module. No third-party source involved — no NOTICE entry.

## Layout

```
<base>/cas/<hh>/<hex>     content-addressed blobs (dedup); hh = hex[0..2]
<base>/raw/<ns>/<key>     name-addressed blobs (caller owns the key)
<base>/named/<ns>/<key>   small opaque byte records (manifests, indexes)
<base>/tmp/               scratch space + in-flight ingest temps
```

## API

```zig
const blobstore = @import("blobstore");

var store = try blobstore.Store.init(io, "/var/lib/mystore");

// content-addressed: stream in, get the digest back; dedup is automatic
var reader: std.Io.Reader = ...;         // any *std.Io.Reader
const d = try store.put(&reader);        // -> Digest (SHA-256 hex)
const d2 = try store.putBytes(slice);    // convenience for in-memory bytes

_ = store.has(d);                        // bool
var f = (try store.open(d)).?;           // ?std.Io.File (caller closes)
_ = try store.verify(d);                 // re-hash on disk: true=intact, false=bit-rot
_ = try store.delete(d);                 // bool (see refcount caveat below)

// digests round-trip through hex text
const parsed = try blobstore.Digest.fromHex(hex64);

// raw name-addressed layer (temp-then-commit for crash safety)
var buf: [768]u8 = undefined;
const w = try store.createTemp("dev1", "backup.bin", &buf); // stream into w.file
try store.commit("dev1", "backup.bin", w.tmp);              // atomic rename
_ = try store.openBlob("dev1", "backup.bin");               // ?File
const items = try store.list(arena, "dev1");                // []Entry{key,bytes}

// named opaque records
try store.putNamed("hostA", "snapshot-1", manifest_bytes);
const rec = try store.readNamed(arena, "hostA", "snapshot-1"); // ?[]u8
const keys = try store.listNamed(arena, "hostA");              // [][]const u8
```

## Design notes

- **Crash safety.** Every write lands in a hidden `.part` temp, is `fsync`'d,
  and is made visible by a single `rename(2)`. A crash mid-write leaves only a
  temp (garbage, never referenced); a live blob is never torn or partial.
- **Dedup.** `put` hashes while streaming (single pass, bounded memory) and
  `casCommit` skips the rename if the content already exists — one copy on disk
  regardless of how many times it is put.
- **Path safety.** `ns`/`key` must be single safe segments (`segmentSafe`:
  `[A-Za-z0-9._-]`, no leading dot, no `.`/`..`), checked on *every* public
  entry point, so a request can never traverse out of `base`. CAS hex keys are
  generated internally and always safe.
- **Verification.** `verify` re-reads the stored bytes to EOF (via
  `hashdigest.sha256File`, which does not trust `stat().size`) and compares the
  hash to the address — catching silent bit-rot or tampering.
- **Design choices.** `put` owns the hash-while-write (a single streaming
  pass), so callers never hash externally. `verify` re-reads to detect
  bit-rot; `Digest` and per-entry-point segment validation guard every path.
  The raw layer is `raw/<ns>/<key>` and opaque records are `named/<ns>/<key>`
  (any bytes, not just JSON) — no JSON/Outcome wrapping, this is pure storage.

## Backlog (deferred, not implemented)

- **Garbage collection** — `gc(keep: []Digest)` reachability sweep to reclaim
  unreferenced CAS blobs (and stale `.part` temps from crashed ingests). Needs a
  root set (typically the `named` manifests) to walk.
- **Reference counting** — `delete`/`casDelete` remove a blob unconditionally;
  with dedup, a blob may back several manifests, so a blind delete can dangle
  references. A safe individual delete needs refcounts or GC-only reclamation.
- **Configurable fan-out depth** — the CAS uses a fixed 2-char (256-way) fan-out.
  Tens-of-millions-of-objects stores want deeper/tunable fan-out
  (`<hh>/<hh>/<hex>`) to bound directory sizes.
- **Cross-process locking / commit TOCTOU** — `casCommit` does a check-then-rename
  (`casHas` then `rename`). Two processes committing the *same* content can race:
  the later rename simply overwrites an identical blob, so the invariant
  "a committed blob's bytes always match its name" holds and the race is
  harmless. Ingest temp names are only unique *within* a process (an atomic
  counter); cross-process ingest isolation and any advisory locking are left to
  the caller.
```
