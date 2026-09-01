# blobstore

Content-addressed blob store (git-object / restic style): stream a blob in,
get back its SHA-256 address; identical content is stored **once**. Plus a
name-addressed raw layer and small opaque **named** records — all made
crash-safe by temp-then-atomic-rename.

- Spec-completed: single-pass `put`, `verify`,
  segment validation, `Digest`, `named` generalization, refcounted `gc`,
  configurable fan-out, cross-process ingest locking.
- **Model after:** git object store / restic (256-way hex fan-out, dedup).
- **Platform:** posix (visibility relies on atomic `rename(2)` + advisory
  `flock`; filesystem via `std.Io`). **Role:** util. **Concurrency:**
  reentrant — shared state (refcounts, gc) is coordinated via an advisory
  cross-process flock, not in-process synchronization.
- **Deps:** `hashdigest` (SHA-256; nothing cryptographic is reimplemented here).

Provenance: original work of the zig-libs authors (MIT); modeled after the git
object store (GPL-2.0) and restic's (BSD-2-Clause) content-addressing design
(256-way hex fan-out, dedup — behavior only, no source consulted or copied).
SHA-256 comes from the sibling `hashdigest` module. No third-party source
involved — no NOTICE entry; a design reference carries no condition, and the
licences are named because `/NOTICE` §0 requires the record to name them.

## Layout

Each subdirectory below is created **lazily**, on that layer's first write — a store
that never uses a layer (e.g. never calls `putNamed`) never creates its directory.

```
<base>/cas/<hh...>/<hex>  content-addressed blobs (dedup); hh... = Options.fanout
                          levels of hex[0..2] (default 1 level, i.e. hex[0..2])
<base>/cas/<hh...>/<hex>.rc  refcount sidecar for that blob (omitted entirely when
                          the store is opened with Options.refcount = false)
<base>/raw/<ns>/<key>     name-addressed blobs (caller owns the key)
<base>/named/<ns>/<key>   small opaque byte records (manifests, indexes)
<base>/tmp/               scratch space + in-flight ingest temps +
                          tmp/.ingest.lock (cross-process advisory flock)
```

## API

```zig
const blobstore = @import("blobstore");

var store = try blobstore.Store.init(io, "/var/lib/mystore");
// or, with a deeper CAS fan-out for a store expecting tens of millions of
// objects (default fanout=1 matches every store created before this option
// existed — pick fanout once, at creation time, it is not migrated later):
var store2 = try blobstore.Store.initOptions(io, "/var/lib/bigstore", .{ .fanout = 2 });
// or, for a store that never deletes and never calls gc, opt out of the
// refcount sidecar entirely (rename-only casCommit, matching this module's
// pre-refcount on-disk layout — see "Reference counting + GC" below):
var store3 = try blobstore.Store.initOptions(io, "/var/lib/frozenstore", .{ .refcount = false });

// content-addressed: stream in, get the digest back; dedup is automatic
var reader: std.Io.Reader = ...;         // any *std.Io.Reader
const d = try store.put(&reader);        // -> Digest (SHA-256 hex); bumps refcount
const d2 = try store.putBytes(slice);    // convenience for in-memory bytes

_ = store.has(d);                        // bool
var f = (try store.open(d)).?;           // ?std.Io.File (caller closes)
_ = try store.verify(d);                 // re-hash on disk: true=intact, false=bit-rot
_ = try store.delete(d);                 // bool; decrements refcount, does NOT unlink —
                                          // see "Reference counting + GC" below

// reclaim every zero-refcount blob not in `keep`, plus stale ingest temps
const stats = try store.gc(arena, &.{}, .{}); // -> GcStats{blobs_removed,bytes_reclaimed,temps_removed}

// opt-in check before trusting a `refcount` toggle on an existing store — see
// "Opting out of refcounting" below
_ = try store.hasOrphanedRcSidecars();   // bool

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

- **Crash safety.** Every write lands in a hidden temp and is made visible by a
  single `rename(2)`, so a crash mid-write leaves only a temp (garbage, never
  referenced) and a live blob is never torn or partial. **`fsync` is narrower
  than the rename discipline and this bullet used to conflate them:** only
  `put` fsyncs its temp before committing. `putNamed` and the raw `commit`
  path rename an unsynced temp, so a power loss can leave a correctly-shaped
  store missing the last named write — atomic, not durable. `put` is the
  durable one.
- **Dedup.** `put` hashes while streaming (single pass, bounded memory) and
  `casCommit` skips the rename if the content already exists — one copy on disk
  regardless of how many times it is put.
- **Path safety.** `ns`/`key` must be single safe segments (`segmentSafe`:
  `[A-Za-z0-9._-]`, no leading dot, no `.`/`..`), checked on *every* public
  entry point, so a request can never traverse out of `base`. This used to
  carve out "CAS hex keys are generated internally and always safe" — but five
  public functions take `hex` from the caller, and `casDelete("../victim")`
  wrote outside the store. Every CAS path now goes through `requireCasHex`, and
  `scratchCreate` validates its name too.
- **Verification.** `verify` re-reads the stored bytes to EOF (via
  `hashdigest.sha256File`, which does not trust `stat().size`) and compares the
  hash to the address — catching silent bit-rot or tampering.
- **Design choices.** `put` owns the hash-while-write (a single streaming
  pass), so callers never hash externally. `verify` re-reads to detect
  bit-rot; `Digest` and per-entry-point segment validation guard every path.
  The raw layer is `raw/<ns>/<key>` and opaque records are `named/<ns>/<key>`
  (any bytes, not just JSON) — no JSON/Outcome wrapping, this is pure storage.
- **Reference counting + GC.** `put`/`casCommit` bump a `<hex>.rc` sidecar
  every time a reference is established — including a dedup hit, which is a
  real second reference to the same bytes. `delete`/`casDelete` only
  decrement it (floored at 0); they never unlink the blob. `gc(keep)` is the
  only function that actually reclaims disk space: it removes every CAS blob
  whose refcount has reached zero and is not named in `keep`, plus abandoned
  `cas/.ingest-*.part` temps older than `GcOptions.stale_after_ns` (default
  10 min). Refcounting was chosen over pure mark-sweep because `put`/`delete`
  already see every reference change as it happens, so `gc` doesn't need to
  understand `named` manifests or any other caller-defined pointer format;
  `keep` stays available as an explicit, additive allow-list for callers who
  want to cross-check against their own root set instead of trusting
  bookkeeping alone. A blob with no `.rc` sidecar at all (from a store
  written before this feature, never `delete`d since) is left untouched by
  `gc` — refcount tracking only starts once `put`/`delete` first touches that
  digest.
- **Opting out of refcounting (`Options.refcount = false`).** For a store
  that never deletes and never calls `gc`, `casCommit` becomes rename-only:
  no `.rc` sidecar is ever read or written, so the CAS directory holds
  exactly one file per blob — the pre-refcount on-disk layout this module
  shipped before refcounting existed. This is contract-compatible with the
  no-sidecar rule above, not a special case: `gc` already treats a
  sidecar-less blob as permanently still-referenced, and `refcount = false`
  simply keeps every blob in that state forever instead of only until the
  first `put`/`delete`. `gc`'s CAS sweep is therefore skipped outright on
  such a store (it truthfully reports zero blobs/bytes reclaimed rather than
  silently doing nothing), and `casDelete`/`delete` return
  `error.RefcountDisabled` instead of creating a sidecar on demand.
  **Do not flip `refcount` to `false` on a store that has ever run with
  `refcount = true`.** It may already have `.rc` sidecars on disk, some
  possibly at zero and already collectible; reopening with `refcount = false`
  makes `gc`'s CAS sweep skip the whole store, so those sidecars are never
  collected again — fail-safe (nothing is deleted that shouldn't be), but
  permanent. `false` is for a store created that way from the start, not a
  runtime switch on an established one. `Store.hasOrphanedRcSidecars()` is an
  opt-in check for exactly this situation — see its doc comment for why it
  is opt-in rather than automatic.
- **Configurable fan-out.** `Options.fanout` (`Store.initOptions`, `1..=32`,
  default `1`) sets how many 2-hex-char CAS directory levels precede the
  blob file — `cas/<hh>/<hex>` at the default, `cas/<hh>/<hh>/<hex>` at
  `fanout = 2`, and so on, for stores with tens of millions of objects that
  want to bound per-directory size. `Store.init` is unchanged and always
  uses the default, so every store written before this option existed still
  opens correctly; changing `fanout` does not migrate an existing store's
  on-disk layout.
- **Cross-process ingest locking.** An advisory `flock` on
  `tmp/.ingest.lock` serializes the commit-and-refcount-mutate section of
  `casCommit`/`casDelete`/`gc` across processes, so concurrent writers can't
  corrupt a refcount sidecar or have `gc` race a live `delete`. It does not
  cover `put`'s streaming/hashing phase — only the shared-state mutation at
  the end needs mutual exclusion, so concurrent ingests still stream into
  their own temps in parallel. Temp names additionally fold in the PID (not
  only a process-local counter), closing the old same-name-clash-across-
  processes risk for the pre-lock streaming phase too. `casCommit`'s
  has-check+rename+refcount-bump happens as one lock-held unit, so two
  processes committing the *same* content no longer race the refcount bump
  itself (the earlier benign rename-only TOCTOU note still applies to the
  rename call in isolation).
